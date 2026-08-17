"""Shared transport for the v2 stub adapters (cmdb, identity, change-mgmt,
threat-intel, ticket).

All five stubs are auth-less FastAPI services on the compose network, reached by
shelling out to `docker --context soc-playground exec <bastion> curl ...` — the same
transport elastic_adapter.py uses for Kibana detection-rule installs. Host-state has
a different shape (docker exec → command output, no HTTP) and keeps its own transport
in host_state_adapter.py.

Two rules the whole family obeys:

  - **A transport RAISES, it never exits.** `SystemExit` is a `BaseException`, so it
    unwinds straight out of `agent.iter()` and takes the run with it, writing no row
    for the very failure the taxonomy exists to record. The fault classes in
    `faults.py` carry the exit code AND the upstream diagnosis instead.
  - **The tree and the env are PARAMETERS** (a `VerbContext`), never module constants
    read at import. An import-time `DEFENDER_DIR` freezes to whatever env the driver
    was started with, so a run anchored on a worktree or an eval's tmp tree would read
    the MAIN checkout's `config.env`; and a child forked with no `env=` inherits the
    driver's `os.environ`, provider keys included.

House conventions (transport, auth posture, config keys, exit codes) are in
`README.md` in this directory.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters.confinement import guard_outbound
from defender.scripts.adapters.faults import (
    USAGE_EXIT_CODE,
    ConfigFault,
    TransportFault,
    UpstreamFault,
)


REQUIRED_CONFIG_KEYS_TEMPLATE = ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC")

DEFAULT_DOCKER_CONTEXT = "soc-playground"

__all__ = [
    "AdapterArgumentParser",
    "DEFAULT_DOCKER_CONTEXT",
    "REQUIRED_CONFIG_KEYS_TEMPLATE",
    "USAGE_EXIT_CODE",
    "docker_context",
    "docker_exec_curl",
    "docker_exec_raw",
    "docker_inspect_raw",
    "health_check",
    "http_get",
    "http_get_obj",
    "http_post",
    "load_config",
    "split_status",
]


class AdapterArgumentParser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors exit ``USAGE_EXIT_CODE`` (64) instead of
    argparse's default 2.

    A bad flag / unknown subcommand is then *structurally* distinct from a connectivity
    failure (exit 2), so the circuit breaker keys on the exit code alone — no fragile
    stderr-phrase sniffing. Subparsers built via ``add_subparsers()`` inherit this class
    automatically (``parser_class=type(self)``), so subcommand usage errors and explicit
    ``parser.error(...)`` calls exit 64 too.

    Only `ticket_cli` still has a CLI; its two subprocess callers (``ticket_seeds``,
    ``verify_forward``) pin these exit codes.
    """

    def error(self, message: str):  # noqa: D102 — overrides argparse's exit(2)
        self.print_usage(sys.stderr)
        self.exit(USAGE_EXIT_CODE, f"{self.prog}: error: {message}\n")


def docker_context(ctx: VerbContext) -> str:
    """The docker context every adapter's transport runs against, read from the RUN's env.

    Single source of truth across the family, so overriding it points the whole stack —
    not half of it — at another environment. Read from `ctx.env`, not at import: the
    module object outlives any one run.
    """
    return ctx.env.get("SOC_PLAYGROUND_DOCKER_CONTEXT", DEFAULT_DOCKER_CONTEXT)


def _child_env(ctx: VerbContext) -> dict[str, str]:
    """The environment a transport hands the child it forks: the RUN's SCRUBBED env, never
    the driver's `os.environ` (which holds the provider API keys)."""
    return dict(ctx.env)


def _config_path(ctx: VerbContext, system: str) -> Path:
    return ctx.defender_dir / "knowledge" / "environment" / "systems" / system / "config.env"


def _parse_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def load_config(
    ctx: VerbContext, system: str, prefix: str,
    required: tuple[str, ...] = REQUIRED_CONFIG_KEYS_TEMPLATE,
) -> dict[str, str]:
    """Load `{ctx.defender_dir}/knowledge/environment/systems/{system}/config.env`.

    The tree comes from the RUN (`ctx.defender_dir`), not a module constant: a run anchored
    on a worktree or an eval's tmp tree must read THAT tree's config.

    The prefix namespaces the env-file keys (e.g. CMDB_URL_BASE, IDENTITY_BASTION_HOST);
    caller-friendly stripped keys come back as URL_BASE / BASTION_HOST / TIMEOUT_SEC. A
    missing file or a missing key is a `ConfigFault` — infra (exit 2), because a system with
    no config is definitionally down, and only exit 2 trips the breaker.

    `required` is the key set THIS system needs — the three-key transport template by
    default, which is what the five docker-exec-curl stubs declare. A system needing more
    passes its own tuple (`ticket_adapter.REQUIRED_CONFIG_KEYS` adds KEY_PATTERN, its key
    grammar). There is deliberately no optional-with-default lane: every value read here is
    required, absent means down, and a caller wanting a fallback must say so in its own
    code rather than have a missing environment fact resolve silently.
    """
    path = _config_path(ctx, system)
    if not path.exists():
        raise ConfigFault(
            f"config file not found: {path} — this file should ship with the "
            f"defender-v2-env branch; if missing, restore from git."
        )

    raw = _parse_env_file(path)
    cfg: dict[str, str] = {}
    for key in required:
        prefixed = f"{prefix}_{key}"
        # The RUN's env overrides the file for ops convenience (CI, per-run overrides).
        val = ctx.env.get(prefixed) or raw.get(prefixed)
        if val:
            cfg[key] = val

    missing = [k for k in required if not cfg.get(k)]
    if missing:
        raise ConfigFault(
            f"missing required config keys in {path}: "
            f"{', '.join(f'{prefix}_{k}' for k in missing)}"
        )
    return cfg


def docker_exec_curl(  # noqa: PLR0913 — one curl request's per-call state
    ctx: VerbContext,
    container: str,
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | None = None,
    timeout_sec: int = 10,
    insecure: bool = False,
    auth: str | None = None,
) -> tuple[int, str, str]:
    """Run curl inside `container` over the run's docker context.

    Returns (returncode, stdout, stderr); stdout carries the response body
    followed by ``\\n<http_code>`` (recover with `split_status`). Raises
    `TransportFault` when the docker exec itself fails (CLI missing / timeout),
    so a reachable-but-erroring service still returns its status + body.

    `auth` (e.g. ``"elastic:${ELASTIC_PASSWORD}"``) runs curl inside the
    container's shell so the ``${VAR}`` secret expands *there*, against the
    container's own env, never on this host; None = no ``-u`` (the auth-less
    stubs). `insecure` adds ``-k`` for the stack's self-signed TLS.
    """
    flags = ["-sS"] + (["-k"] if insecure else [])
    args = ["-X", method, "--max-time", str(timeout_sec), "-H", "Accept: application/json"]
    for key, val in (headers or {}).items():
        args += ["-H", f"{key}: {val}"]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    # Status on its own trailing line so `split_status` can recover it from stdout.
    args += ["-w", "\n%{http_code}", url]

    context = docker_context(ctx)
    if auth:
        # Static flags live in the in-container shell so ${VAR} expands there;
        # everything dynamic is forwarded as argv after `--` (so a JSON body with
        # spaces/quotes survives intact — no shell re-parsing). `--` lands in $0.
        inner = f'exec curl {" ".join(flags)} -u "{auth}" "$@"'
        cmd = ["docker", "--context", context, "exec", "-i", container,
               "sh", "-c", inner, "--", *args]
    else:
        cmd = ["docker", "--context", context, "exec", container, "curl", *flags, *args]
    try:
        # utf-8 and LOSSY: the far side is vendor data (indexed log lines), so a stray
        # non-UTF-8 byte must cost one character, not raise a UnicodeDecodeError that sails
        # past the guards below (it is a ValueError) and out of the adapter.
        # `timeout` is MANDATORY on every fork: it is the only kill left, there being no
        # outer wall-clock budget.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec + 10,
                              encoding="utf-8", errors="replace", env=_child_env(ctx))
    except FileNotFoundError as e:
        raise TransportFault("docker CLI not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise TransportFault(
            f"docker exec curl timed out after {timeout_sec + 10}s (target: {url})"
        ) from e
    return proc.returncode, proc.stdout, proc.stderr


def split_status(stdout: str) -> tuple[str, str]:
    """Recover (body, http_status) from curl -w '\\n%{http_code}' output.

    Returns ('', '') when stdout is empty (e.g. curl failed before any
    request — caller decides via returncode).
    """
    if not stdout:
        return "", ""
    sep = stdout.rfind("\n")
    if sep == -1:
        return "", stdout.strip()
    return stdout[:sep], stdout[sep + 1:].strip()


def http_get(
    ctx: VerbContext, config: dict[str, str], path: str, *, system: str,
    params: dict | None = None,
) -> dict | list:
    """GET <URL_BASE><path>?<params>, return parsed JSON.

    Raises `TransportFault` (infra) on docker/unreachable/5xx and `UpstreamFault` (a query
    error, carrying the vendor's own `detail`) on a 4xx — a 404 included.

    `system` is REQUIRED, not defaulted: it keys the confinement allowlist
    (`confine_read_endpoint`), and every system funnels through this one function — a
    caller that forgot to name itself would silently confine against the wrong allowlist.
    """
    qs = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = f"{config['URL_BASE'].rstrip('/')}{path}{qs}"
    return _request(ctx, config, url, system=system, method="GET")


def http_post(
    ctx: VerbContext, config: dict[str, str], path: str, body: dict, *, system: str,
) -> dict | list:
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    return _request(ctx, config, url, system=system, method="POST", body=body)


def http_get_obj(
    ctx: VerbContext, config: dict[str, str], path: str, *, system: str,
    params: dict | None = None,
) -> dict[str, Any]:
    """`http_get` for endpoints whose contract is a JSON *object*. Narrows the
    `dict | list` parse to `dict[str, Any]` so callers get typed `.get()`/indexing, and
    fails fast on a non-object rather than crashing later on `list.get`. List endpoints
    keep raw `http_get` + their own `isinstance(payload, list)` guard."""
    payload = http_get(ctx, config, path, system=system, params=params)
    if not isinstance(payload, dict):
        raise TransportFault(
            f"expected a JSON object from {path}, got {type(payload).__name__}"
        )
    return payload


def _raise_on_transport_failure(
    ctx: VerbContext, bastion: str, rc: int, stderr: str
) -> None:
    """curl never completed a request → transport-level failure. `TransportFault` (exit 2) so
    the queries row and the circuit breaker both see a down system, not a query error. No-op
    when curl exited clean. Covers both a missing/stopped bastion (`docker exec` fails before
    curl runs) and curl's own failures.

    THE RETURN CODE ALONE DECIDES, and `stdout` is deliberately not a parameter: because
    `docker_exec_curl` appends `-w "\\n%{http_code}"`, curl writes a status line on EVERY exit,
    so stdout is `"\\n000"` — never empty — when no request completed. Any guard conditioned on
    empty stdout is unsatisfiable, and lets a DNS failure / refused connection / `--max-time`
    timeout parse as HTTP 0, match neither arm of `_raise_on_http_error`, and return `{}` from
    `_request` as a SUCCESS — an outage reaching the lead as "the system holds nothing", with
    exit 0 counting nothing towards the breaker."""
    if rc == 0:
        return
    hint = stderr.strip() or "no stderr"
    if "No such container" in hint or "is not running" in hint:
        raise TransportFault(
            f"bastion container {bastion!r} unreachable: {hint} — confirm "
            f"`docker --context {docker_context(ctx)} ps` lists {bastion} as running."
        )
    raise TransportFault(f"docker exec failed (rc={rc}): {hint}")


def _parse_status_code(stdout: str, stderr: str, url: str, rc: int) -> tuple[str, int]:
    """Split curl's body/status and parse the HTTP status to an int. A malformed (no status),
    non-numeric, or `000` response is a `TransportFault`: curl never completed a request, so
    there is no upstream verdict to file as a query error. Returns (body_text, code).

    `000` is curl's own "no response" status, and is checked separately from the rc rather
    than folded into it: the two are independent readings of the same fault, and a curl that
    reported `000` while exiting 0 would otherwise parse to `0`, match neither arm of
    `_raise_on_http_error`, and be filed as a system that answered."""
    body_text, status = split_status(stdout)
    if not status:
        # Reached only with rc == 0 (`_raise_on_transport_failure` owns every non-zero exit):
        # curl claims success while emitting no `-w` status line. Show the bytes it did emit —
        # the shape of that stdout is the whole diagnosis.
        raise TransportFault(
            f"malformed curl response from {url}: "
            f"stdout={stdout!r} stderr={stderr.strip()!r}"
        )
    try:
        code = int(status)
    except ValueError as e:
        raise TransportFault(f"non-numeric http status from curl: {status!r}") from e
    if code == 0:
        detail = stderr.strip() or "no stderr"
        raise TransportFault(
            f"curl reported HTTP 000 from {url} (no response; rc={rc}): {detail}"
        )
    return body_text, code


def _raise_on_http_error(code: int, body_text: str, url: str) -> None:
    """Map a >=400 HTTP status onto the fault taxonomy: 5xx → `TransportFault` (the system is
    down), 4xx → `UpstreamFault` carrying the vendor's OWN `detail` verbatim. That detail is
    the row's payload_digest and the sole input to the pitfalls-curation lane, so a generic
    message here silently dries that lane up. No-op on a success code."""
    if code >= 500:
        raise TransportFault(f"upstream {url} returned HTTP {code}: {body_text}")
    if code >= 400:
        # 4xx is a query error (bad arg, 404): the agent's own to fix.
        try:
            payload = json.loads(body_text) if body_text else {}
        except json.JSONDecodeError:
            payload = {"detail": body_text}
        detail = payload.get("detail", payload) if isinstance(payload, dict) else payload
        raise UpstreamFault(f"HTTP {code} from {url}: {detail}")


def _request(
    ctx: VerbContext, config: dict[str, str], url: str, *, system: str, method: str,
    body: dict | None = None,
) -> dict | list:
    # Target-fidelity confinement, BEFORE any transport is attempted. Every HTTP stub system
    # funnels through this one function, so wiring the read-endpoint allowlist here rather
    # than in each adapter is what makes the seam cover all of them.
    guard_outbound(ctx, system, url, method=method)

    bastion = config["BASTION_HOST"]
    timeout = int(config.get("TIMEOUT_SEC", "10"))
    rc, stdout, stderr = docker_exec_curl(
        ctx, bastion, url, method=method, body=body, timeout_sec=timeout
    )

    _raise_on_transport_failure(ctx, bastion, rc, stderr)
    body_text, code = _parse_status_code(stdout, stderr, url, rc)
    _raise_on_http_error(code, body_text, url)

    if not body_text:
        return {}
    try:
        return json.loads(body_text)
    except json.JSONDecodeError as e:
        raise TransportFault(f"non-JSON response from {url}: {e} (body: {body_text!r})") from e


def health_check(ctx: VerbContext, config: dict[str, str], system_label: str) -> dict[str, Any]:
    """Standard health-check: GET <URL_BASE>/health and RETURN the payload.

    Returns data rather than printing: prose on stdout would leave the queries table
    recording an empty payload for the one call whose point is to say the system is up."""
    payload = http_get_obj(ctx, config, "/health", system=system_label)
    return {"system": system_label, "connected": True, **payload}


def docker_exec_raw(
    ctx: VerbContext,
    bastion: str,
    argv: list[str],
    *,
    timeout_sec: int = 10,
) -> tuple[int, str, str]:
    """Run `docker --context <ctx's context> exec <bastion> <argv...>`.

    Exposed for host_state_adapter.py — same docker context as the HTTP
    stubs, but the command isn't curl. Returns (rc, stdout, stderr); raises
    `TransportFault` when the exec itself never ran (CLI missing / timeout).
    """
    cmd = ["docker", "--context", docker_context(ctx), "exec", bastion, *argv]
    try:
        # utf-8 and LOSSY: this runs arbitrary host verbs (`ps`, `ls`, file reads) inside the
        # bastion, so stdout carries filenames and process cmdlines — a strict decode would turn
        # one odd byte into a UnicodeDecodeError that escapes every guard downstream (a
        # ValueError is neither a rc check nor a fault) and takes the run with it.
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec + 5,
            encoding="utf-8", errors="replace", env=_child_env(ctx),
        )
    except FileNotFoundError as e:
        raise TransportFault("docker CLI not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise TransportFault(
            f"docker exec timed out after {timeout_sec + 5}s "
            f"(bastion: {bastion}, argv: {shlex.join(argv)})"
        ) from e
    return proc.returncode, proc.stdout, proc.stderr


def docker_inspect_raw(
    ctx: VerbContext,
    target: str,
    *,
    fmt: str | None = None,
    timeout_sec: int = 10,
) -> tuple[int, str, str]:
    """Run `docker --context <ctx's context> inspect [--format <fmt>] <target>`.

    Daemon-level container/image inspection — distinct from docker_exec_raw,
    which runs a command *inside* a container. Exposed for host_state_adapter.py's
    container-inspect verb (Falco alerts carry a runtime container id, not a
    host name). Returns (rc, stdout, stderr).
    """
    cmd = ["docker", "--context", docker_context(ctx), "inspect"]
    if fmt is not None:
        cmd += ["--format", fmt]
    cmd.append(target)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec + 5,
            encoding="utf-8", errors="replace",  # container labels/env are foreign bytes too
            env=_child_env(ctx),
        )
    except FileNotFoundError as e:
        raise TransportFault("docker CLI not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise TransportFault(
            f"docker inspect timed out after {timeout_sec + 5}s (target: {target})"
        ) from e
    return proc.returncode, proc.stdout, proc.stderr
