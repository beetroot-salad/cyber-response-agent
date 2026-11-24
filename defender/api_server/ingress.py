"""The ingress launcher (#1161 S5, B9): `python -m defender.api_server.ingress`.

One entry point for dev, CI's browser check and the deployment. It reads six inputs, all required and none defaulted,
refuses (non-zero exit, naming the setting) before Caddy starts when one is unset or misshapen, then replaces itself
with Caddy (exec), so signals reach Caddy and nothing of ours stands between. The Caddyfile, `defender/frontend/Caddyfile`,
reads them from the environment, the listen address split into its host and port (`caddy_environment`).

The ingress always serves plain HTTP on `DEFENDER_INGRESS_LISTEN`: TLS, when there is any, ends in front of it. It never
learns the public origin, so Caddy's automatic HTTPS has nothing to act on (and is off besides).

Two of the inputs are the Forgejo site's (#1592 OD-1, OD-3): `DEFENDER_FORGE_DOMAIN`, the host it answers on (parsed as the
artifact domain is), and `DEFENDER_INGRESS_FORGE_UPSTREAM`, Forgejo's private `host:port`. On that
host the Caddyfile forwards only its allowlist; on any other host the app is served as before."""

from __future__ import annotations

import os
import re
import shutil
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from defender._log import configure_from_env

from ._settings import StartRefused, _port, artifact_domain

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
    "DEFENDER_INGRESS_LISTEN": _upstream,
    "DEFENDER_ARTIFACT_DOMAIN": artifact_domain,
    "DEFENDER_INGRESS_API_UPSTREAM": _upstream,
    "DEFENDER_INGRESS_FRONTEND_DIR": _directory,
    "DEFENDER_FORGE_DOMAIN": artifact_domain,
    "DEFENDER_INGRESS_FORGE_UPSTREAM": _upstream,
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


def caddy_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """What Caddy runs with: `environ` as given, plus the listen address's host and port apart (the Caddyfile binds the
    host and listens on the port for every Host a client sends). `environ` must have passed `checked`."""
    host, _, port = environ["DEFENDER_INGRESS_LISTEN"].rpartition(":")
    return {**environ, "DEFENDER_INGRESS_LISTEN_HOST": host.removeprefix("[").removesuffix("]"),
            "DEFENDER_INGRESS_LISTEN_PORT": port}


def main() -> None:
    try:
        checked(os.environ)
    except StartRefused as why:
        sys.exit(f"ingress: {why}")
    caddy = shutil.which("caddy")
    if caddy is None:
        sys.exit("ingress: `caddy` is not on PATH")
    os.execve(caddy, [caddy, "run", "--config", str(CADDYFILE), "--adapter", "caddyfile"], caddy_environment(os.environ))


if __name__ == "__main__":
    configure_from_env()
    main()
