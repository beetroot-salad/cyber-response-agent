"""Shared transport for the v2 stub adapters (cmdb, identity, change-mgmt,
threat-intel, ticket).

All five stubs are auth-less FastAPI services on the compose network, reached by
shelling out to `docker --context <the system's own context> exec <bastion> curl ...` — the same
transport elastic_adapter.py uses for Kibana detection-rule installs. Host-state has
a different shape (docker exec → command output, no HTTP) and keeps its own transport
in host_state_adapter.py.

Two rules the whole family obeys:

  - **A transport RAISES, it never exits.** `SystemExit` is a `BaseException`, so it
    unwinds straight out of `agent.iter()` and takes the run with it, writing no row
    for the very failure the taxonomy exists to record. The fault classes in
    `faults.py` carry the exit code AND the upstream diagnosis instead.
  - **The record and the env are PARAMETERS** (a `VerbContext`), never module constants
    read at import, and nothing is looked up in the env. Settings come from the run's
    tenant record (#1107), built once when the run began; a child forked with no `env=`
    inherits the driver's `os.environ`, provider keys included, so every child is handed
    the run's scrubbed env explicitly.

House conventions (transport, auth posture, config keys, exit codes) are in
`README.md` in this directory.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from defender.runtime.tenant_settings import (
    DOCKER_EXEC,
    NOT_CONFIGURED,
    SystemConfig,
    is_blank,
    system_prefix,
)
from defender.runtime.verbs import VerbContext
from defender.scripts.adapters.confinement import guard_outbound
from defender.scripts.adapters.faults import (
    USAGE_EXIT_CODE,
    ConfigFault,
    TransportFault,
    UpstreamFault,
)


REQUIRED_CONFIG_KEYS_TEMPLATE = ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC")

#: The system that owns the two raw lanes (`docker_exec_raw`, `docker_inspect_raw`): host-state
#: is the only adapter that runs a command rather than an HTTP request.
HOST_STATE = "host-state"

#: What replaces a secret value found in text the transport returns (O4, MF-5 i).
SECRET_MARKER = "[secret redacted]"

#: A secret reaches its one child under `DEFENDER_SECRET_<i>`, `i` its position in the call's
#: `secrets` tuple — never under the tenant's declared name (a declared `PATH` or `DOCKER_HOST`
#: must set nothing of that name). `docker exec -e <name>` forwards it BY NAME, so only the name
#: is ever on argv.
SECRET_ENV_PREFIX = "DEFENDER_SECRET_"

__all__ = [
    "HOST_STATE",
    "REQUIRED_CONFIG_KEYS_TEMPLATE",
    "SECRET_ENV_PREFIX",
    "SECRET_MARKER",
    "USAGE_EXIT_CODE",
    "access_context",
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
    "system_entry",
]


def system_entry(ctx: VerbContext, system: str) -> SystemConfig:
    """`system`'s `config.env` as the RUN's record holds it (parsed once at resolve), or the
    `ConfigFault` for why there is none: a folder with no usable file keeps its own fault, and a
    system with no folder gets "this tenant's settings do not configure this system". A fresh
    instance each call, so a stored fault is never handed a second traceback."""
    tenant = ctx.tenant
    entry = tenant.systems.get(system)
    if entry is None:
        path = Path(tenant.settings) / "systems" / system / "config.env"
        raise ConfigFault(f"config file not found: {path} — {NOT_CONFIGURED}")
    if isinstance(entry, ConfigFault):
        raise ConfigFault(str(entry))
    return entry


def access_context(ctx: VerbContext, system: str, prefix: str | None = None) -> str:
    """The docker context `system` is reached on — its `<PREFIX>_DOCKER_CONTEXT` — or
    `ConfigFault` (that system down, the run goes on). THE ONE CHECK of how a system is reached
    (D2): `<PREFIX>_TRANSPORT` must be `docker-exec` exactly, and the context must be named and
    not blank. There is NO default for either: an absent or empty context would be handed to
    docker as `--context ''`, which docker defers to its own `DOCKER_CONTEXT` or current context,
    re-opening the very steering this record removed (MF-3).

    Called first by every adapter's `load_config` and by every transport entry, so a system that
    is down for its access method faults naming that key before any URL is confined or any
    timeout parsed."""
    entry = system_entry(ctx, system)
    prefix = prefix or system_prefix(system)
    method = entry.get(f"{prefix}_TRANSPORT")
    if method is None or is_blank(method):
        raise ConfigFault(
            f"{prefix}_TRANSPORT is not set — name this system's access method "
            f"({DOCKER_EXEC!r}) in its config.env; there is no default")
    if method != DOCKER_EXEC:
        raise ConfigFault(
            f"{prefix}_TRANSPORT={method!r} names an access method that is not implemented — "
            f"only {DOCKER_EXEC!r} is")
    context = entry.get(f"{prefix}_DOCKER_CONTEXT")
    if context is None or is_blank(context):
        raise ConfigFault(
            f"{prefix}_DOCKER_CONTEXT is not set — name the docker context this system is "
            "reached on in its config.env; there is no default")
    return context


def docker_context(ctx: VerbContext, system: str) -> str:
    """The docker context `system`'s transport runs against, from the run's record (D2)."""
    return access_context(ctx, system)


def _child_env(ctx: VerbContext) -> dict[str, str]:
    """The environment a transport hands the child it forks: the RUN's SCRUBBED env passed
    through whole (docker needs PATH, HOME, its own config), never the driver's `os.environ`
    (which holds the provider API keys). Nothing is LOOKED UP in it (N4)."""
    return dict(ctx.env)


def load_config(
    ctx: VerbContext, system: str, prefix: str,
    required: tuple[str, ...] = REQUIRED_CONFIG_KEYS_TEMPLATE,
) -> dict[str, str]:
    """`system`'s settings from the run's record: its `config.env`, prefix stripped.

    The record is the one resolved when the run began (`run_tenant.resolve_run_tenant`), not the
    file as it is now and not the process environment: an edit mid-run and an exported variable
    change nothing a run addresses (O1, O2). The prefix namespaces the file's keys
    (CMDB_URL_BASE, IDENTITY_BASTION_HOST); caller-friendly stripped keys come back as URL_BASE /
    BASTION_HOST / TIMEOUT_SEC. A system with no usable config, an unimplemented access method, or
    a missing, blank or malformed required key is a `ConfigFault` — infra (exit 2), because a
    system with no config is definitionally down, and only exit 2 trips the breaker.

    The access method is checked FIRST (`access_context`), ahead of the required keys and the
    timeout: a system whose method is not `docker-exec` is down for that reason, whatever else
    its file says.

    `required` is the key set THIS system needs — the three-key transport template by default,
    which is what the five docker-exec-curl stubs declare. A system needing more passes its own
    tuple (`ticket_adapter.REQUIRED_CONFIG_KEYS` adds KEY_PATTERN, its key grammar). There is
    deliberately no optional-with-default lane: every value read here is required, absent or
    blank means down, and a caller wanting a fallback must say so in its own code rather than
    have a missing environment fact resolve silently.
    """
    entry = system_entry(ctx, system)
    access_context(ctx, system, prefix)
    cfg: dict[str, str] = {}
    for key in required:
        val = entry.get(f"{prefix}_{key}")
        if val is not None and not is_blank(val):
            cfg[key] = val

    missing = [k for k in required if k not in cfg]
    if missing:
        path = Path(ctx.tenant.settings) / "systems" / system / "config.env"
        raise ConfigFault(
            f"missing required config keys in {path}: "
            f"{', '.join(f'{prefix}_{k}' for k in missing)}"
        )
    timeout = cfg.get("TIMEOUT_SEC")
    if timeout is not None and not (timeout.isascii() and timeout.isdigit() and int(timeout) > 0):
        raise ConfigFault(
            f"{prefix}_TIMEOUT_SEC must be a whole number of seconds above zero, got {timeout!r}")
    return cfg


def _destination_owner(ctx: VerbContext, container: str, url: str) -> str:
    """The ONE system whose config declares this call's destination — its URL base the URL starts
    with, its bastion or Elastic container the call execs into — for a caller that did not name
    its system. Several systems may share a bastion, so the URL decides first and the container
    only breaks a tie or stands alone. `ConfigFault` when the destination is nobody's or
    several systems' (name `system=` then): a docker context is a per-system fact and is never
    guessed."""
    by_url: set[str] = set()
    by_container: set[str] = set()
    for name, entry in ctx.tenant.systems.items():
        if not isinstance(entry, SystemConfig):
            continue
        for key, value in entry.items():
            if is_blank(value):
                continue
            if key.endswith(("_URL_BASE", "ELASTICSEARCH_URL", "KIBANA_URL")) and url.startswith(
                    value.rstrip("/")):
                by_url.add(name)
            if key.endswith(("_BASTION_HOST", "_ES_CONTAINER", "_KIBANA_CONTAINER")) and (
                    value == container):
                by_container.add(name)
    owners = by_url & by_container or by_url or by_container
    if len(owners) != 1:
        raise ConfigFault(
            f"cannot tell which of this tenant's systems the call to {url} (container "
            f"{container!r}) belongs to — name system= so its docker context can be chosen")
    return next(iter(owners))


def _scrubbed(text: str, secrets: Sequence[str]) -> str:
    """`text` with every placed secret value replaced by `SECRET_MARKER`. Literal values only:
    an encoded or cut echo is a known limit."""
    for value in secrets:
        if value:
            text = text.replace(value, SECRET_MARKER)
    return text


def _place_secrets(ctx: VerbContext, names: Sequence[str]) -> tuple[list[str], dict[str, str], list[str]]:
    """Resolve each declared secret NAME through the run's record (`ConfigFault` for an
    undeclared or unreadable one, before any child is forked) and place it for ONE child: the
    `docker exec` flags that forward it by name, the child-environment additions, and the values
    (for scrubbing returned text). The value goes into that child's environment and nowhere
    else — never argv, never `ctx.env`, never the process environment (O4)."""
    flags: list[str] = []
    extra: dict[str, str] = {}
    values: list[str] = []
    for i, name in enumerate(names):
        value = ctx.tenant.secrets.get(name)
        var = f"{SECRET_ENV_PREFIX}{i}"
        flags += ["-e", var]
        extra[var] = value
        values.append(value)
    return flags, extra, values


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
    system: str | None = None,
    secrets: Sequence[str] = (),
) -> tuple[int, str, str]:
    """Run curl inside `container` over `system`'s docker context.

    Returns (returncode, stdout, stderr); stdout carries the response body
    followed by ``\\n<http_code>`` (recover with `split_status`). Raises
    `TransportFault` when the docker exec itself fails (CLI missing / timeout),
    so a reachable-but-erroring service still returns its status + body.

    `system` names the tenant system the call is for, so its OWN docker context is used; a
    caller that omits it gets the one system whose config declares this destination
    (`_destination_owner`). `secrets` are DECLARED secret names (`*_SECRET_REF` in the tenant's
    systems): each is resolved through the record and set in the environment of this one child
    only, forwarded into the container by name (`-e NAME`), and replaced by `SECRET_MARKER` in the
    text this returns (O4).

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

    context = docker_context(ctx, system or _destination_owner(ctx, container, url))
    secret_flags, secret_env, placed = _place_secrets(ctx, secrets)
    if auth:
        # Static flags live in the in-container shell so ${VAR} expands there;
        # everything dynamic is forwarded as argv after `--` (so a JSON body with
        # spaces/quotes survives intact — no shell re-parsing). `--` lands in $0.
        inner = f'exec curl {" ".join(flags)} -u "{auth}" "$@"'
        cmd = ["docker", "--context", context, "exec", "-i", *secret_flags, container,
               "sh", "-c", inner, "--", *args]
    else:
        cmd = ["docker", "--context", context, "exec", *secret_flags, container, "curl",
               *flags, *args]
    try:
        # utf-8 and LOSSY: the far side is vendor data (indexed log lines), so a stray
        # non-UTF-8 byte must cost one character, not raise a UnicodeDecodeError that sails
        # past the guards below (it is a ValueError) and out of the adapter.
        # `timeout` is MANDATORY on every fork: it is the only kill left, there being no
        # outer wall-clock budget.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec + 10,
                              encoding="utf-8", errors="replace",
                              env={**_child_env(ctx), **secret_env})
    except FileNotFoundError as e:
        raise TransportFault("docker CLI not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise TransportFault(
            f"docker exec curl timed out after {timeout_sec + 10}s (target: {url})"
        ) from e
    return proc.returncode, _scrubbed(proc.stdout, placed), _scrubbed(proc.stderr, placed)


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
    ctx: VerbContext, bastion: str, rc: int, stderr: str, system: str,
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
            f"`docker --context {docker_context(ctx, system)} ps` lists {bastion} as running."
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
        ctx, bastion, url, method=method, body=body, timeout_sec=timeout, system=system
    )

    _raise_on_transport_failure(ctx, bastion, rc, stderr, system)
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
    system: str = HOST_STATE,
) -> tuple[int, str, str]:
    """Run `docker --context <system's context> exec <bastion> <argv...>`.

    Exposed for host_state_adapter.py — which runs a command rather than curl, and so owns this
    lane (`system` defaults to it). Returns (rc, stdout, stderr); raises `TransportFault` when
    the exec itself never ran (CLI missing / timeout).
    """
    cmd = ["docker", "--context", docker_context(ctx, system), "exec", bastion, *argv]
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
    system: str = HOST_STATE,
) -> tuple[int, str, str]:
    """Run `docker --context <system's context> inspect [--format <fmt>] <target>`.

    Daemon-level container/image inspection — distinct from docker_exec_raw,
    which runs a command *inside* a container. Exposed for host_state_adapter.py's
    container-inspect verb (Falco alerts carry a runtime container id, not a
    host name). Returns (rc, stdout, stderr).
    """
    cmd = ["docker", "--context", docker_context(ctx, system), "inspect"]
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
