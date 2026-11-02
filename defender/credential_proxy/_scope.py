"""Where a request may go and what it may do (#1163 O2, O3, A2, A9, A14): the URL against the
one declared base, the route against the declared reads and writes and the token's grant.

A URL is judged as written, never normalised: another scheme, host or port, a login part, or a
path outside the base is `ConfigFault` (a correct adapter builds its URL from the same base); a
`.` or `..` segment, spelled out or percent-encoded, is `ConfinementFault` wherever it is.
Routes are paths relative to the base; `*` stands for exactly one non-empty segment."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from defender.kit.access import AccessDeclaration, Route
from defender.credential_proxy._refusal import CONFIG, CONFINEMENT, Refused
from defender.credential_proxy._tokens import READ_WRITE

#: Methods that are reads under any base (O3).
READ_METHODS = ("GET", "HEAD")
_METHOD = re.compile(r"[A-Z]{1,16}")
_DEFAULT_PORT = {"http": 80, "https": 443}
#: What a segment is split on once decoded: a server may read either as a separator.
_SEPARATOR = re.compile(r"[/\\]")


@dataclass(frozen=True)
class Target:
    """Where a request is sent (`url`: the base's origin, the path and query as written) and its
    path relative to the base (`path`, what routes match and the audit records)."""

    url: str
    path: str


def locate(declaration: AccessDeclaration, url: str) -> Target:
    """`url` as a destination under `declaration`'s base, or `Refused`."""
    if any(ch <= " " or ch == "\x7f" for ch in url):
        raise Refused(CONFIG, "the URL holds whitespace or a control character")
    base = urlsplit(declaration.base)
    try:
        asked = urlsplit(url)
        asked_port = asked.port
    except ValueError:
        raise Refused(CONFIG, "the URL does not parse") from None
    if asked.username is not None or asked.password is not None or "@" in asked.netloc:
        raise Refused(CONFIG, "the URL carries a login part; the proxy applies the credential")
    if asked.fragment:
        raise Refused(CONFIG, "the URL carries a fragment")
    scheme = asked.scheme.lower()
    if (scheme, asked.hostname, asked_port or _DEFAULT_PORT.get(scheme)) != (
            base.scheme.lower(), base.hostname, base.port or _DEFAULT_PORT.get(base.scheme.lower())):
        raise Refused(CONFIG, "the URL's scheme, host or port is not the declared base's")
    path = asked.path or "/"
    decoded = unquote(path)
    if any(part in (".", "..") for part in _SEPARATOR.split(decoded)):
        raise Refused(CONFINEMENT, "the URL path holds a `.` or `..` segment")
    if ";" in decoded:
        # Some servers read `;` as starting a path parameter and resolve `/..;/` as `/../`.
        raise Refused(CONFINEMENT, "the URL path holds a `;` (a path parameter)")
    base_path = base.path.rstrip("/")
    if not (path == base_path or path.startswith(base_path + "/")):
        raise Refused(CONFIG, "the URL path is not under the declared base")
    sent = f"{base.scheme}://{base.netloc}{path}" + (f"?{asked.query}" if asked.query else "")
    return Target(url=sent, path=path[len(base_path):] or "/")


def check_route(declaration: AccessDeclaration, system: str, method: str, path: str,
                mode: str) -> None:
    """`Refused` unless `method` on `path` (relative to the base) is a read, or a declared write
    and `mode` (the token's grant on `system`) is read-write. GET and HEAD are reads; another
    method is a read only if a read route lists it (O3, A14)."""
    if not _METHOD.fullmatch(method):
        raise Refused(CONFIG, f"{method[:20]!r} is not an upper-case HTTP method")
    if method in READ_METHODS or _route_listed(declaration.reads, method, path):
        return
    if not _route_listed(declaration.writes, method, path):
        raise Refused(CONFINEMENT, f"{method} {path} is not a declared route of {system}")
    if mode != READ_WRITE:
        raise Refused(CONFINEMENT, f"{method} {path} is a write and the token grants {system} "
                                   "read only")


def _route_listed(routes: tuple[Route, ...], method: str, path: str) -> bool:
    return any(route.method == method and _route_pattern_matches(route.path, path) for route in routes)


def _route_pattern_matches(pattern: str, path: str) -> bool:
    wanted, asked = pattern.split("/"), path.split("/")
    if len(wanted) != len(asked):
        return False
    for want, got in zip(wanted, asked, strict=True):
        if want == "*":
            if not got or _SEPARATOR.search(unquote(got)):
                return False
        elif want != got:
            return False
    return True


__all__ = ["READ_METHODS", "Target", "check_route", "locate"]
