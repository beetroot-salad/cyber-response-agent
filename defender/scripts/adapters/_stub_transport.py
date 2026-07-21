
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

    def error(self, message: str):  # noqa: D102 — overrides argparse's exit(2)
        self.print_usage(sys.stderr)
        self.exit(USAGE_EXIT_CODE, f"{self.prog}: error: {message}\n")


def docker_context(ctx: VerbContext) -> str:
    return ctx.env.get("SOC_PLAYGROUND_DOCKER_CONTEXT", DEFAULT_DOCKER_CONTEXT)


def _child_env(ctx: VerbContext) -> dict[str, str]:
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


def docker_exec_curl(  # noqa: PLR0913 — one curl request's per-call state; the ctx is the 9th because the tree/env stopped being module constants
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
    flags = ["-sS"] + (["-k"] if insecure else [])
    args = ["-X", method, "--max-time", str(timeout_sec), "-H", "Accept: application/json"]
    for key, val in (headers or {}).items():
        args += ["-H", f"{key}: {val}"]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    args += ["-w", "\n%{http_code}", url]

    context = docker_context(ctx)
    if auth:
        inner = f'exec curl {" ".join(flags)} -u "{auth}" "$@"'
        cmd = ["docker", "--context", context, "exec", "-i", container,
               "sh", "-c", inner, "--", *args]
    else:
        cmd = ["docker", "--context", context, "exec", container, "curl", *flags, *args]
    try:
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
    if not stdout:
        return "", ""
    sep = stdout.rfind("\n")
    if sep == -1:
        return "", stdout.strip()
    return stdout[:sep], stdout[sep + 1:].strip()


def http_get(
    ctx: VerbContext, config: dict[str, str], path: str, *, params: dict | None = None
) -> dict | list:
    qs = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = f"{config['URL_BASE'].rstrip('/')}{path}{qs}"
    return _request(ctx, config, url, method="GET")


def http_post(ctx: VerbContext, config: dict[str, str], path: str, body: dict) -> dict | list:
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    return _request(ctx, config, url, method="POST", body=body)


def http_get_obj(
    ctx: VerbContext, config: dict[str, str], path: str, *, params: dict | None = None
) -> dict[str, Any]:
    payload = http_get(ctx, config, path, params=params)
    if not isinstance(payload, dict):
        raise TransportFault(
            f"expected a JSON object from {path}, got {type(payload).__name__}"
        )
    return payload


def _raise_on_transport_failure(
    ctx: VerbContext, bastion: str, rc: int, stdout: str, stderr: str
) -> None:
    if not (rc != 0 and not stdout):
        return
    hint = stderr.strip() or "no stderr"
    if "No such container" in hint or "is not running" in hint:
        raise TransportFault(
            f"bastion container {bastion!r} unreachable: {hint} — confirm "
            f"`docker --context {docker_context(ctx)} ps` lists {bastion} as running."
        )
    raise TransportFault(f"docker exec failed (rc={rc}): {hint}")


def _parse_status_code(stdout: str, stderr: str, url: str) -> tuple[str, int]:
    body_text, status = split_status(stdout)
    if not status:
        raise TransportFault(
            f"malformed curl response from {url}: "
            f"stdout={stdout!r} stderr={stderr.strip()!r}"
        )
    try:
        code = int(status)
    except ValueError as e:
        raise TransportFault(f"non-numeric http status from curl: {status!r}") from e
    return body_text, code


def _raise_on_http_error(code: int, body_text: str, url: str) -> None:
    if code >= 500:
        raise TransportFault(f"upstream {url} returned HTTP {code}: {body_text}")
    if code >= 400:
        try:
            payload = json.loads(body_text) if body_text else {}
        except json.JSONDecodeError:
            payload = {"detail": body_text}
        detail = payload.get("detail", payload) if isinstance(payload, dict) else payload
        raise UpstreamFault(f"HTTP {code} from {url}: {detail}")


def _request(
    ctx: VerbContext, config: dict[str, str], url: str, *, method: str, body: dict | None = None
) -> dict | list:
    bastion = config["BASTION_HOST"]
    timeout = int(config.get("TIMEOUT_SEC", "10"))
    rc, stdout, stderr = docker_exec_curl(
        ctx, bastion, url, method=method, body=body, timeout_sec=timeout
    )

    _raise_on_transport_failure(ctx, bastion, rc, stdout, stderr)
    body_text, code = _parse_status_code(stdout, stderr, url)
    _raise_on_http_error(code, body_text, url)

    if not body_text:
        return {}
    try:
        return json.loads(body_text)
    except json.JSONDecodeError as e:
        raise TransportFault(f"non-JSON response from {url}: {e} (body: {body_text!r})") from e


def health_check(ctx: VerbContext, config: dict[str, str], system_label: str) -> dict[str, Any]:
    payload = http_get_obj(ctx, config, "/health")
    return {"system": system_label, "connected": True, **payload}


def docker_exec_raw(
    ctx: VerbContext,
    bastion: str,
    argv: list[str],
    *,
    timeout_sec: int = 10,
) -> tuple[int, str, str]:
    cmd = ["docker", "--context", docker_context(ctx), "exec", bastion, *argv]
    try:
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
    cmd = ["docker", "--context", docker_context(ctx), "inspect"]
    if fmt is not None:
        cmd += ["--format", fmt]
    cmd.append(target)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec + 5,
            encoding="utf-8", errors="replace",
            env=_child_env(ctx),
        )
    except FileNotFoundError as e:
        raise TransportFault("docker CLI not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise TransportFault(
            f"docker inspect timed out after {timeout_sec + 5}s (target: {target})"
        ) from e
    return proc.returncode, proc.stdout, proc.stderr
