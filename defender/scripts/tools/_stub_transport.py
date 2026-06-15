"""Shared transport for the v2 stub adapters (cmdb, identity, change-mgmt,
threat-intel, ticket).

All five stubs are auth-less FastAPI services on the compose network. The
defender reaches them by shelling out to `docker --context soc-playground
exec <bastion> curl ...` — same transport elastic_cli.py uses for Kibana
detection-rule installs. One transport here for all five keeps the
adapters thin (just verb-to-endpoint mapping + output formatting).

Host-state has a different shape (docker exec → command output, no HTTP)
and uses host_state_cli.py's own transport, not this module.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import urllib.parse
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFENDER_DIR = Path(os.environ.get("DEFENDER_DIR", SCRIPT_DIR.parent.parent))

REQUIRED_CONFIG_KEYS_TEMPLATE = ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC")
DOCKER_CONTEXT = "soc-playground"


def _config_path(system: str) -> Path:
    return DEFENDER_DIR / "knowledge" / "environment" / "systems" / system / "config.env"


def _parse_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def load_config(system: str, prefix: str) -> dict[str, str]:
    """Load `defender/knowledge/environment/systems/{system}/config.env`.

    The prefix namespaces the env-file keys (e.g. CMDB_URL_BASE,
    IDENTITY_BASTION_HOST). Caller-friendly stripped keys come back as
    URL_BASE / BASTION_HOST / TIMEOUT_SEC.
    """
    path = _config_path(system)
    if not path.exists():
        sys.exit(
            f"error: config file not found: {path}\n"
            f"hint: this file should ship with the defender-v2-env branch — "
            f"if missing, restore from git."
        )

    raw = _parse_env_file(path)
    cfg: dict[str, str] = {}
    for key in REQUIRED_CONFIG_KEYS_TEMPLATE:
        prefixed = f"{prefix}_{key}"
        # Env vars override the file for ops convenience (CI, per-run overrides).
        val = os.environ.get(prefixed) or raw.get(prefixed)
        if val:
            cfg[key] = val

    missing = [k for k in REQUIRED_CONFIG_KEYS_TEMPLATE if not cfg.get(k)]
    if missing:
        sys.exit(
            f"error: missing required config keys in {path}: "
            f"{', '.join(f'{prefix}_{k}' for k in missing)}"
        )
    return cfg


def _docker_exec_curl(
    bastion: str,
    url: str,
    *,
    method: str = "GET",
    body: dict | None = None,
    timeout_sec: int = 10,
) -> tuple[int, str, str]:
    """Run `docker --context soc-playground exec <bastion> curl ...`.

    Returns (returncode, stdout, stderr). curl runs with -sS and -w to
    suffix the HTTP status code on its own line — we split that off
    before returning the JSON body.
    """
    curl_argv = [
        "curl", "-sS",
        "--max-time", str(timeout_sec),
        "-X", method,
        "-H", "Accept: application/json",
    ]
    if body is not None:
        curl_argv += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    # Write HTTP status on its own trailing line so we can recover it from stdout.
    curl_argv += ["-w", "\n%{http_code}", url]

    cmd = [
        "docker", "--context", DOCKER_CONTEXT, "exec", bastion,
        *curl_argv,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec + 5,
        )
    except FileNotFoundError:
        print("error: docker CLI not found on PATH", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print(f"error: docker exec curl timed out after {timeout_sec + 5}s (target: {url})", file=sys.stderr)
        sys.exit(2)
    return proc.returncode, proc.stdout, proc.stderr


def _split_status(stdout: str) -> tuple[str, str]:
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


def http_get(config: dict[str, str], path: str, *, params: dict | None = None) -> dict | list:
    """GET <URL_BASE><path>?<params>, return parsed JSON.

    Exits 1 on HTTP error (4xx/5xx other than the explicit handlings noted
    below), 2 on connectivity / docker / unreachable. 404 propagates as
    an exit-1 with the upstream detail.
    """
    qs = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = f"{config['URL_BASE'].rstrip('/')}{path}{qs}"
    return _request(config, url, method="GET")


def http_post(config: dict[str, str], path: str, body: dict) -> dict | list:
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    return _request(config, url, method="POST", body=body)


def _request(config: dict[str, str], url: str, *, method: str, body: dict | None = None) -> dict | list:
    bastion = config["BASTION_HOST"]
    timeout = int(config.get("TIMEOUT_SEC", "10"))
    rc, stdout, stderr = _docker_exec_curl(bastion, url, method=method, body=body, timeout_sec=timeout)

    if rc != 0 and not stdout:
        # curl never produced output → transport-level failure. Exit 2 (the
        # connectivity/docker/unreachable code in every stub's exit contract) so
        # the gather exit-code protocol and the circuit breaker both see it as a
        # down system, not a query error.
        hint = stderr.strip() or "no stderr"
        if "No such container" in hint or "is not running" in hint:
            print(
                f"error: bastion container {bastion!r} unreachable: {hint}\n"
                f"hint: confirm `docker --context {DOCKER_CONTEXT} ps` lists {bastion} as running.",
                file=sys.stderr,
            )
            sys.exit(2)
        print(f"error: docker exec failed (rc={rc}): {hint}", file=sys.stderr)
        sys.exit(2)

    body_text, status = _split_status(stdout)
    if not status:
        # curl exited non-zero but emitted partial output — show what we got.
        sys.exit(
            f"error: malformed curl response from {url}\n"
            f"stdout: {stdout!r}\nstderr: {stderr.strip()!r}"
        )

    try:
        code = int(status)
    except ValueError:
        sys.exit(f"error: non-numeric http status from curl: {status!r}")

    if code >= 500:
        print(f"error: upstream {url} returned HTTP {code}: {body_text}", file=sys.stderr)
        sys.exit(2)
    if code >= 400:
        # 4xx is a query error (bad arg, 404). Surface upstream message.
        try:
            payload = json.loads(body_text) if body_text else {}
        except json.JSONDecodeError:
            payload = {"detail": body_text}
        detail = payload.get("detail", payload) if isinstance(payload, dict) else payload
        print(f"error: HTTP {code} from {url}: {detail}", file=sys.stderr)
        sys.exit(1)

    if not body_text:
        return {}
    try:
        return json.loads(body_text)
    except json.JSONDecodeError as e:
        sys.exit(f"error: non-JSON response from {url}: {e}\nbody: {body_text!r}")


def health_check(config: dict[str, str], system_label: str) -> None:
    """Standard health-check: GET <URL_BASE>/health and print summary."""
    payload = http_get(config, "/health")
    print("connected")
    print(f"{system_label}: {payload.get('status', 'unknown')}")
    for key in sorted(k for k in payload if k != "status"):
        print(f"{key}: {payload[key]}")


def docker_exec_raw(
    bastion: str,
    argv: list[str],
    *,
    timeout_sec: int = 10,
) -> tuple[int, str, str]:
    """Run `docker --context soc-playground exec <bastion> <argv...>`.

    Exposed for host_state_cli.py — same docker context as the HTTP
    stubs, but the command isn't curl. Returns (rc, stdout, stderr).
    """
    cmd = ["docker", "--context", DOCKER_CONTEXT, "exec", bastion, *argv]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec + 5,
        )
    except FileNotFoundError:
        print("error: docker CLI not found on PATH", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print(
            f"error: docker exec timed out after {timeout_sec + 5}s "
            f"(bastion: {bastion}, argv: {shlex.join(argv)})",
            file=sys.stderr,
        )
        sys.exit(2)
    return proc.returncode, proc.stdout, proc.stderr


def docker_inspect_raw(
    target: str,
    *,
    fmt: str | None = None,
    timeout_sec: int = 10,
) -> tuple[int, str, str]:
    """Run `docker --context soc-playground inspect [--format <fmt>] <target>`.

    Daemon-level container/image inspection — distinct from docker_exec_raw,
    which runs a command *inside* a container. Exposed for host_state_cli.py's
    container-inspect verb (Falco alerts carry a runtime container id, not a
    host name). Returns (rc, stdout, stderr).
    """
    cmd = ["docker", "--context", DOCKER_CONTEXT, "inspect"]
    if fmt is not None:
        cmd += ["--format", fmt]
    cmd.append(target)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec + 5,
        )
    except FileNotFoundError:
        print("error: docker CLI not found on PATH", file=sys.stderr)
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print(
            f"error: docker inspect timed out after {timeout_sec + 5}s "
            f"(target: {target})",
            file=sys.stderr,
        )
        sys.exit(2)
    return proc.returncode, proc.stdout, proc.stderr
