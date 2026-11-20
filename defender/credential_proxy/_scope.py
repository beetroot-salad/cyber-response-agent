"""Where a request may go and what it may do (#1163 O2, O3, A2, A9, A14): the URL against the
one declared base, the route against the declared reads and writes and the token's grant.

A URL is judged as written, never normalised: another scheme, host or port, a login part, or a
path outside the base is `ConfigFault` (a correct adapter builds its URL from the same base); a
`.` or `..` segment, spelled out or percent-encoded, or a segment that decodes to hold a `/` or
`\\` (`kit.paths`, #1391 r5 O-T5), is `ConfinementFault` wherever it is.
Routes are paths relative to the base; `*` stands for exactly one non-empty segment."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from defender.kit.access import AccessDeclaration, Route, ticket_write_fault
from defender.kit.paths import holds_separator, url_form_fault, url_path_fault
from defender.credential_proxy._refusal import CONFIG, CONFINEMENT, Refused
from defender.kit.faults import ORIGIN_REQUEST, ORIGIN_SETUP
from defender.credential_proxy._tokens import READ_WRITE

#: Methods that are reads under any base (O3).
READ_METHODS = ("GET", "HEAD")
_METHOD = re.compile(r"[A-Z]{1,16}")


def is_read_method(method: str) -> bool:
    """True for a method the proxy admits as a read with no declared route (GET, HEAD, O3): the one question of which
    methods need a declaration, which the record judgement asks too (#1504 O3)."""
    return method in READ_METHODS

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
    """`url` as a destination under `declaration`'s base, or `Refused`. The rules for a URL as a
    whole are `kit.paths`' (`url_form_fault`, `url_path_fault`), the ones the access
    declaration's parser judges a base by (#1366 R15)."""
    form = url_form_fault(url)
    if form is not None:
        raise Refused(CONFIG, form.reason, origin=ORIGIN_REQUEST)
    asked = urlsplit(url)
    try:
        base = urlsplit(declaration.base)
        base_port = base.port
    except ValueError:
        # The parser refuses such a base; a declaration that reached here anyway is the
        # system's configuration fault, not a transport one.
        raise Refused(CONFIG, "the system's declared base does not parse", origin=ORIGIN_SETUP) from None
    scheme = asked.scheme.lower()
    if (scheme, asked.hostname, asked.port or _DEFAULT_PORT.get(scheme)) != (
            base.scheme.lower(), base.hostname, base_port or _DEFAULT_PORT.get(base.scheme.lower())):
        raise Refused(CONFIG, "the URL's scheme, host or port is not the declared base's", origin=ORIGIN_REQUEST)
    path = asked.path or "/"
    confined = url_path_fault(path)
    if confined is not None:
        raise Refused(CONFINEMENT if confined.confinement else CONFIG, confined.reason, origin=ORIGIN_REQUEST)
    base_path = base.path.rstrip("/")
    if not (path == base_path or path.startswith(base_path + "/")):
        raise Refused(CONFIG, "the URL path is not under the declared base", origin=ORIGIN_REQUEST)
    if any(holds_separator(unquote(segment)) for segment in path[len(base_path):].split("/")):
        # A server that decodes the path before routing would split it there (#1391 r5 O-T5).
        # Only the part under the base: the tenant's own base may name an escaped `/`.
        raise Refused(CONFINEMENT, "a URL path segment holds an encoded `/` or `\\`", origin=ORIGIN_REQUEST)
    sent = f"{base.scheme}://{base.netloc}{path}" + (f"?{asked.query}" if asked.query else "")
    return Target(url=sent, path=path[len(base_path):] or "/")


def check_route(declaration: AccessDeclaration, system: str, method: str, path: str,
                mode: str, ticket: str | None = None) -> None:
    """`Refused` unless `method` on `path` (relative to the base) is a read, or the one write a
    write pass names. GET and HEAD are reads; another method is a read only if a read route lists
    it (O3, A14). A read-write grant always names its ticket (X1, `_tokens`), and under it every
    other method is judged by `_ticket_write` alone: there is no write without a ticket."""
    if not _METHOD.fullmatch(method):
        raise Refused(CONFIG, f"{method[:20]!r} is not an upper-case HTTP method", origin=ORIGIN_REQUEST)
    if is_read_method(method):
        return
    if mode == READ_WRITE:
        if ticket is None:
            raise Refused(CONFINEMENT, f"the token's write pass on {system} names no ticket", origin=ORIGIN_REQUEST)
        return _ticket_write(declaration, system, method, path, ticket)
    if _route_listed(declaration.reads, method, path):
        return
    if _route_listed(declaration.writes, method, path):
        raise Refused(CONFINEMENT, f"{method} {path} is a write and the token grants {system} "
                                   "read only", origin=ORIGIN_REQUEST)
    raise Refused(CONFINEMENT, f"{method} {path} is not a declared route of {system}", origin=ORIGIN_REQUEST)


def _ticket_write(declaration: AccessDeclaration, system: str, method: str, path: str,
                  ticket: str) -> None:
    """X1: under a write pass naming `ticket`, a non-read method is allowed only when the system
    declares exactly one write route with exactly one wildcard segment and only GET reads (X2,
    enforced here, not trusted from the store), and `method` on `path` is that route with the
    wildcard segment decoding to `ticket`."""
    reason = ticket_write_fault(declaration)
    if reason is not None:
        raise Refused(CONFINEMENT, f"{system} cannot be written under a ticket pass: {reason}",
                      origin=ORIGIN_REQUEST)
    (route,) = declaration.writes
    if route.method != method or not _route_pattern_matches(route.path, path):
        raise Refused(CONFINEMENT, f"{method} {path} is not the one write route of {system}",
                      origin=ORIGIN_REQUEST)
    wanted = route.path.split("/")
    segment = path.split("/")[wanted.index("*")]
    if unquote(segment) != ticket:
        raise Refused(CONFINEMENT, f"{method} {path} is not on the ticket the token names",
                      origin=ORIGIN_REQUEST)


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


__all__ = ["READ_METHODS", "is_read_method", "Target", "check_route", "locate"]
