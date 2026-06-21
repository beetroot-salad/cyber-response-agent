"""Shared support for defender data-source adapter CLIs.

`/connect` copies this file to `defender/scripts/adapters/_adapter.py` the
first time it onboards a system, and every generated `{system}_cli.py`
imports it. It owns the three things every adapter does identically —
argument parsing, non-secret config loading, and the exit codes — and
the one thing a generated adapter must never improvise: credential
resolution.

Transport (HTTP, SSH, `docker exec`, an existing CLI) is deliberately
NOT here. Transport is what varies between environments, so it lives in
the adapter. What lives here is everything an adapter should not reinvent.

Credential boundary
-------------------
Secrets are read from environment variables and nowhere else. `config.env`
holds non-secret values only: endpoints, timeouts, and the *names* of the
environment variables that hold secrets. Nothing in this module reads a
secret from `config.env`, returns one in a structure that gets logged, or
prints one. This is the single most important property of the adapter
layer — keep it that way.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any, NoReturn

# Exit codes — the adapter contract. Identical across every adapter so the
# gather subagent (and validate_scaffold.py) can rely on them.
EXIT_OK = 0           # success, including a connected-but-empty result
EXIT_QUERY_ERROR = 1  # the query/lookup reached the system but was rejected
EXIT_CONN_ERROR = 2   # could not reach or authenticate to the system, or
                      #   the adapter is misconfigured (missing config/secret)
EXIT_USAGE = 64       # bad invocation: unknown flag/subcommand, missing arg


class AdapterArgumentParser(argparse.ArgumentParser):
    """argparse that exits EXIT_USAGE (64) on a usage error instead of the
    default 2, so a malformed invocation is distinguishable from a real
    connectivity failure (which owns exit 2)."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def die(code: int, message: str) -> NoReturn:
    """Print an error to stderr and exit. Use for the hint paths — missing
    config, missing secret, unreachable system — so the failure carries an
    actionable message and the right exit code."""
    print(message, file=sys.stderr)
    raise SystemExit(code)


def _defender_dir() -> Path:
    """Resolve the defender root. `run.py` exports DEFENDER_DIR; outside
    that, fall back to this file's location
    (`<defender>/scripts/adapters/_adapter.py`)."""
    env = os.environ.get("DEFENDER_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2]


def load_config(system: str) -> dict[str, str]:
    """Read non-secret config from
    `{DEFENDER_DIR}/knowledge/environment/systems/{system}/config.env`.

    Shell-style `KEY=value` lines; `#` comments and blank lines ignored;
    surrounding quotes stripped. An environment variable named
    `{SYSTEM}_{KEY}` (e.g. `ASSETDB_URL_BASE` for system `assetdb`, key
    `URL_BASE`) overrides the file value — that's how CI and per-run
    overrides work. The `{SYSTEM}_` prefix is deliberate: a bare `URL_BASE`
    in the environment must not silently bleed across every adapter, so
    overrides are scoped per system. A key absent from the file is not
    introduced from the environment here.

    This file never holds secrets (see the module docstring); it holds the
    *names* of the env vars that do.
    """
    path = (
        _defender_dir()
        / "knowledge" / "environment" / "systems" / system / "config.env"
    )
    config: dict[str, str] = {}
    if path.exists():
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            config[key.strip()] = val.strip().strip('"').strip("'")
    prefix = system.upper().replace("-", "_") + "_"
    for key in list(config):
        override = os.environ.get(prefix + key)
        if override is not None:
            config[key] = override
    return config


def _cfg(config: dict[str, str], key: str, system: str) -> str:
    """Fetch a required non-secret config value; fail loud if missing."""
    val = config.get(key)
    if not val:
        die(
            EXIT_CONN_ERROR,
            f"{system}: config key {key!r} is required for "
            f"AUTH_TYPE={config.get('AUTH_TYPE', 'none')!r} but is missing "
            f"from config.env.",
        )
    return val


def _require_secret(var_name: str, system: str) -> str:
    """Fetch a secret from the environment by *name*; fail loud if unset.
    The name comes from config.env (non-secret); the value only ever comes
    from the environment."""
    val = os.environ.get(var_name)
    if not val:
        die(
            EXIT_CONN_ERROR,
            f"{system}: secret env var {var_name!r} is not set. Export it "
            f"(or add it to your .env / vault integration) and retry. "
            f"config.env holds only the variable name, never the value.",
        )
    return val


def resolve_auth(system: str, config: dict[str, str]) -> dict[str, str]:
    """Return the HTTP headers that authenticate a request, from the
    non-secret `AUTH_TYPE` declared in `config.env`. Secrets are pulled
    from the environment by the variable names config names — never from
    `config.env` itself.

    Supported `AUTH_TYPE` values and the config keys each needs:

        none    (default) — no auth.                         {}
        bearer  TOKEN_ENV                  — Authorization: Bearer <token>
        basic   USERNAME, PASSWORD_ENV     — Authorization: Basic <b64>
        header  AUTH_HEADER, AUTH_KEY_ENV  — <AUTH_HEADER>: <key>

    `*_ENV` keys name the environment variable holding the secret;
    `USERNAME` and `AUTH_HEADER` are non-secret and live in config.env
    directly. Anything else (mTLS, SigV4, OAuth client-credentials) is too
    vendor-specific to standardize — implement it in the adapter and note
    why in `execution.md`.
    """
    auth_type = config.get("AUTH_TYPE", "none").lower()
    if auth_type == "none":
        return {}
    if auth_type == "bearer":
        token = _require_secret(_cfg(config, "TOKEN_ENV", system), system)
        return {"Authorization": f"Bearer {token}"}
    if auth_type == "basic":
        user = _cfg(config, "USERNAME", system)
        password = _require_secret(_cfg(config, "PASSWORD_ENV", system), system)
        encoded = base64.b64encode(f"{user}:{password}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}
    if auth_type == "header":
        header = _cfg(config, "AUTH_HEADER", system)
        key = _require_secret(_cfg(config, "AUTH_KEY_ENV", system), system)
        return {header: key}
    die(
        EXIT_CONN_ERROR,
        f"{system}: unsupported AUTH_TYPE {auth_type!r}. Built in: none, "
        f"bearer, basic, header. For anything else, implement it in the "
        f"adapter and document it in execution.md.",
    )


def die_for_http_status(system: str, status: int, body: str = "") -> None:
    """Map an HTTP status onto the adapter exit-code contract: exit on
    failure, return on success (2xx/3xx).

    The urllib example gets this mapping for free from
    `urllib.error.HTTPError.code`. A transport that does NOT raise a
    status-bearing exception — `docker exec … curl`, an SSH command, a
    wrapped vendor CLI — should reconstruct the status (e.g. curl's
    `-w '%{http_code}'`) and call this, so the 0/1/2 contract matches the
    example instead of being reinvented per adapter.

        status == 0   no HTTP response reached us (refused / DNS / timeout)
                      → EXIT_CONN_ERROR
        401 / 403     auth failure → EXIT_CONN_ERROR
        >= 400        reached but rejected (404, 400, 5xx) → EXIT_QUERY_ERROR
        otherwise     success → return
    """
    if status == 0:
        die(EXIT_CONN_ERROR,
            f"{system}: no HTTP response (connection refused, DNS, or "
            f"timeout). A data-source outage, not a query problem — do not "
            f"retry-probe.")
    if status in (401, 403):
        die(EXIT_CONN_ERROR,
            f"{system}: authentication failed (HTTP {status}). Check "
            f"AUTH_TYPE and the secret env var it names.")
    if status >= 400:
        detail = body.strip()
        die(EXIT_QUERY_ERROR,
            f"{system}: query rejected (HTTP {status})"
            + (f": {detail}" if detail else "."))


def print_raw(system: str, endpoint: str, args: dict[str, Any], result: Any) -> None:
    """Emit the stable `--raw` envelope the gather capture persists by-ref
    to `gather_raw/`. Keep this shape stable across adapters — drift breaks
    replay and the offline learning loop."""
    print(json.dumps(
        {"system": system, "endpoint": endpoint, "args": args, "result": result}
    ))
