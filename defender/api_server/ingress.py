"""The ingress launcher (#1161 S5, B9): `python -m defender.api_server.ingress`.

One entry point for dev, CI's browser check and the deployment. It reads four inputs, all required and none defaulted,
refuses (non-zero exit, naming the setting) before Caddy starts when one is unset or misshapen, then replaces itself
with Caddy (exec), so signals reach Caddy and nothing of ours stands between. The Caddyfile, `defender/frontend/Caddyfile`,
reads the same four names from the environment."""

from __future__ import annotations

import os
import re
import shutil
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from defender._log import configure_from_env

from ._settings import StartRefused, _port, artifact_domain, origin

CADDYFILE = Path(__file__).resolve().parent.parent / "frontend" / "Caddyfile"

_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\]", re.ASCII)


def _upstream(value: str) -> str:
    host, separator, port = value.rpartition(":")
    if not separator or not _HOST.fullmatch(host):
        raise ValueError("must be host:port")
    _port(port)
    return value


#: What a folder path may hold. The Caddyfile reads it by text substitution before parsing, so whitespace, braces,
#: quotes or `#` would change the Caddyfile itself.
_DIRECTORY = re.compile(r"[A-Za-z0-9._/@+=~-]+", re.ASCII)


def _directory(value: str) -> str:
    if not _DIRECTORY.fullmatch(value):
        raise ValueError("may hold only letters, digits and . _ / @ + = ~ - (no spaces, braces, quotes or #)")
    if not Path(value).is_dir():
        raise ValueError("is not a directory")
    return value


#: Every input, with its parser. A launcher-only setting is named here and nowhere else.
INPUTS: dict[str, Callable[[str], str]] = {
    "DEFENDER_API_FRONTEND_ORIGIN": origin,
    "DEFENDER_ARTIFACT_DOMAIN": artifact_domain,
    "DEFENDER_INGRESS_API_UPSTREAM": _upstream,
    "DEFENDER_INGRESS_FRONTEND_DIR": _directory,
}


def checked(environ: Mapping[str, str]) -> dict[str, str]:
    """Each input parsed, or `StartRefused` naming the first that is unset, empty or misshapen."""
    values = {}
    for name, parse in INPUTS.items():
        if not environ.get(name):
            raise StartRefused(f"{name} is not set" if name not in environ else f"{name} is empty")
        try:
            values[name] = parse(environ[name])
        except ValueError as why:
            raise StartRefused(f"{name}: {why}") from None
    return values


def main() -> None:
    try:
        checked(os.environ)  # Caddy reads the same names from the environment, unchanged
    except StartRefused as why:
        sys.exit(f"ingress: {why}")
    caddy = shutil.which("caddy")
    if caddy is None:
        sys.exit("ingress: `caddy` is not on PATH")
    os.execve(caddy, [caddy, "run", "--config", str(CADDYFILE), "--adapter", "caddyfile"], os.environ)


if __name__ == "__main__":
    configure_from_env()
    main()
