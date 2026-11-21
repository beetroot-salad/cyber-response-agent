"""The access declaration of one `http-proxy` system (#1163): where its credential may go, how
it is applied, and which requests are reads or writes. Values only: it holds no credential. The
parser that reads it from a tenant's settings stays in `tenancy`."""
from __future__ import annotations

import contextlib
import re
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass

from defender.kit.faults import ORIGIN_ACCESS, ORIGIN_SETUP, AdapterFault, TransportFault

#: The operator's variable naming the credential proxy's address. Read by the launching process
#: alone: the address reaches a verb call on its context, never through a run's environment.
PROXY_URL_ENV = "DEFENDER_CREDENTIAL_PROXY_URL"

#: Seconds the credential proxy allows for its own calls (token check, credential read) on top of
#: a request's timeout, and the seconds a caller waits past the proxy's deadline (r7 A21, #1364
#: O1): the proxy answers by its deadline, so it has given up before its caller does.
PROXY_OVERHEAD_SEC = 20
CALLER_GRACE_SEC = 5


def caller_wait_sec(timeout_sec: float) -> float:
    """How long a caller waits for each stretch of the proxy's reply to a request with
    `timeout_sec`: the proxy's deadline (`timeout_sec` + `PROXY_OVERHEAD_SEC`), which it answers
    by, and `CALLER_GRACE_SEC`. A wait per read, not for the whole reply (#1412)."""
    return timeout_sec + PROXY_OVERHEAD_SEC + CALLER_GRACE_SEC

#: The access method (D2) of a system reached through the credential proxy.
HTTP_PROXY = "http-proxy"

BEARER = "bearer"
BASIC = "basic"
HEADER = "header"
OAUTH_CLIENT_CREDENTIALS = "oauth-client-credentials"
SCHEMES = (BEARER, BASIC, HEADER, OAUTH_CLIENT_CREDENTIALS)

#: The kinds a credential set can have (A4): a static key set, or an OAuth client.
STATIC = "static"
CREDENTIAL_KINDS = (STATIC, OAUTH_CLIENT_CREDENTIALS)

#: The fixed field names a scheme reads from its set (r7 A19): a declaration does not rename them.
USERNAME, PASSWORD = "username", "password"
CLIENT_ID, CLIENT_SECRET = "client_id", "client_secret"

@dataclass(frozen=True)
class Auth:
    """The declared scheme and how it is applied. Only the parts the scheme uses are set; a
    `basic` or OAuth scheme reads its set's fixed field names (r7 A19), a `bearer` or `header`
    scheme the one `field` it names."""

    scheme: str
    field: str | None = None
    header: str | None = None
    token_url: str | None = None
    scopes: tuple[str, ...] = ()

    @property
    def kind(self) -> str:
        """The credential-set kind this scheme needs."""
        return OAUTH_CLIENT_CREDENTIALS if self.scheme == OAUTH_CLIENT_CREDENTIALS else STATIC


# --- the credential schema (#1470 O7, P6): what a scheme's set holds and every value rule the proxy refuses at use ----

#: The least length of a secret field's value (#1163 A4).
SECRET_MIN_LENGTH = 16

#: The schemes whose set has fixed field names (r7 A19): each field and whether it is secret.
_FIXED_FIELDS: Mapping[str, Mapping[str, bool]] = {
    BASIC: {USERNAME: False, PASSWORD: True},
    OAUTH_CLIENT_CREDENTIALS: {CLIENT_ID: False, CLIENT_SECRET: True},
}

#: The field names the schema holds public: a scheme that names its own secret field (bearer, header) may not name one
#: of these (the access parser's rule, r7 A19).
PUBLIC_FIELD_NAMES = frozenset(name for fields in _FIXED_FIELDS.values() for name, secret in fields.items() if not secret)


def credential_fields(auth: Auth) -> Mapping[str, bool]:
    """Exactly the fields `auth`'s credential set holds, each mapped to whether it is secret: bearer and header the one
    field they name (secret); basic `username` (public) and `password`; OAuth `client_id` (public) and
    `client_secret`."""
    if auth.scheme in (BEARER, HEADER):
        return {str(auth.field): True}
    return dict(_FIXED_FIELDS[auth.scheme])


def _sent_in_a_header(auth: Auth) -> bool:
    """Is the set's value sent as a header as it is (bearer, header), so it must be ASCII?"""
    return auth.scheme in (BEARER, HEADER)


def _value_faults(auth: Auth, name: str, value: object, secret: bool) -> list[str]:
    """Why `value` cannot stand in field `name` of `auth`'s set: the rules the proxy refuses at use, and the secret
    length. Never shows the value."""
    shown = f"the credential field {name!r}"
    if not isinstance(value, str):
        return [f"{shown} must be text"]
    if not value:
        return [f"{shown} is empty"]
    faults: list[str] = []
    if not value.isprintable():
        faults.append(f"{shown} holds a control character")
    if _sent_in_a_header(auth) and not value.isascii():
        faults.append(f"{shown} is not ASCII, so it cannot be sent in a header")
    if auth.scheme == BASIC and name == USERNAME and ":" in value:
        faults.append(f"{shown} holds a `:`, which a basic-auth username may not")
    if secret and len(value) < SECRET_MIN_LENGTH:
        faults.append(f"{shown} is secret and shorter than {SECRET_MIN_LENGTH} characters")
    return faults


def credential_faults(auth: Auth, fields: Mapping[str, str]) -> list[str]:
    """Every reason `fields` is not a credential set `auth`'s scheme can use, each a sentence naming the field (never a
    value); `[]` when it fits. Exactly the scheme's fields (`credential_fields`), each holding a value the proxy would
    send: non-empty and printable, ASCII where it is sent in a header, no `:` in a basic username, and a secret one at
    least `SECRET_MIN_LENGTH` long."""
    expected = credential_fields(auth)
    faults = [f"the {auth.scheme} credential set lacks the field {name!r}" for name in sorted(expected)
              if name not in fields]
    for name in sorted(fields, key=repr):
        if name not in expected:
            faults.append(f"the field {name!r} is not one the {auth.scheme} scheme reads")
        else:
            faults += _value_faults(auth, name, fields[name], expected[name])
    return faults


class CredentialRefused(Exception):
    """A credential set the schema refuses for its scheme: `faults` is every reason (`credential_faults`)."""

    def __init__(self, faults: list[str]) -> None:
        self.faults = list(faults)
        super().__init__("; ".join(self.faults))


def check_credentials(auth: Auth, fields: Mapping[str, str]) -> None:
    """`CredentialRefused` with every fault unless `fields` is a set `auth`'s scheme can use."""
    faults = credential_faults(auth, fields)
    if faults:
        raise CredentialRefused(faults)


#: Seconds a request token lives from when it is signed (r7 A20), and the life a held read token
#: must have left to be handed out again (#1363 O1).
TOKEN_SEC = 600
TOKEN_REUSE_MARGIN_SEC = 60


class _Held:
    """A signed token and when it expires; the token is a bearer value, out of every repr."""

    __slots__ = ("expires_at", "token")

    def __init__(self, token: str, expires_at: float) -> None:
        self.token = token
        self.expires_at = expires_at

    def __repr__(self) -> str:
        return f"{type(self).__name__}(expires_at={self.expires_at})"


class RequestAccess:
    """One process's access to the credential proxy (#1363 O1, O5, B1): its address and the one
    holder of its read token, shared by a run, a sibling run and a pre-flight pass.

    It signs when first asked, reuses the token while more than `TOKEN_REUSE_MARGIN_SEC` of its
    `TOKEN_SEC` remain, and otherwise signs a fresh one, under one lock, so concurrent first
    requests make one sign. A failed sign is latched (D8, Principle 3): the asker gets the fault,
    and every later ask raises a fresh fault with the same detail and signs nothing. The client
    tells it of each `setup` or `access` fault it raises (`report`); the first `access` fault
    marks access **lost** and latches it the same way, and a `setup` fault of configuration kind is
    recorded against its system. A `setup` fault of transport kind is one failed call, as a run
    treats it (#1363 O7, #1256 DP2: only what cannot change marks a system), and is not recorded.
    The holder says whether access was lost because a sign failed (`sign_failed`). Its owner is called, outside the lock, with each of those faults (`on_fault`) and may
    `shut` it. Signing is the injected `mint(expires_at)`, which raises its fault; the clock is the
    holder's own. The token is a bearer value, out of every repr."""

    def __init__(self, proxy_url: str, mint: Callable[[float], str], *,
                 clock: Callable[[], float] = time.time,
                 on_fault: Callable[[AdapterFault], None] | None = None) -> None:
        self.proxy_url = proxy_url
        self._mint = mint
        self._clock = clock
        self._on_fault = on_fault
        self._lock = threading.RLock()
        self._held: _Held | None = None
        #: Why access is lost, once it is: the first `access` fault's detail, or why a sign failed.
        self._lost: str | None = None
        self._sign_failed = False
        self._shut = False
        self._setup: dict[str, str] = {}

    def __repr__(self) -> str:
        return f"{type(self).__name__}(proxy_url={self.proxy_url!r})"

    __str__ = __repr__

    def token(self) -> str:
        """The run's read token: the held one while it has life left, else a new one. Raises the
        fault of a sign that failed, or a fresh one with the latched detail once access is lost
        or the holder is shut."""
        failed: AdapterFault | None = None
        with self._lock:
            if self._shut:
                raise self._unavailable("this process closed its access to the credential proxy")
            if self._lost is not None:
                raise self._unavailable(self._lost)
            now = self._clock()
            if self._held is not None and self._held.expires_at - TOKEN_REUSE_MARGIN_SEC > now:
                return self._held.token
            try:
                expires_at = now + TOKEN_SEC
                self._held = _Held(self._mint(expires_at), expires_at)
                return self._held.token
            except AdapterFault as fault:
                self._held, self._lost, failed = None, fault.detail, fault
                self._sign_failed = True
        # Reached only by a failed sign: its owner learns of it, then the asker.
        failed.origin = failed.origin or ORIGIN_ACCESS
        self._tell(failed)
        raise failed

    def report(self, fault: AdapterFault) -> None:
        """The client's report of a fault it raised. Only a `setup` or `access` one concerns the
        holder; any other, a fault with no origin, and a `setup` fault of transport kind are
        ignored."""
        if fault.origin not in (ORIGIN_SETUP, ORIGIN_ACCESS):
            return
        if fault.origin == ORIGIN_SETUP and isinstance(fault, TransportFault):
            return
        with self._lock:
            if fault.origin == ORIGIN_ACCESS:
                if self._lost is not None:
                    return
                self._lost = fault.detail
            else:
                self._setup.setdefault(fault.system or "", fault.detail)
        self._tell(fault)

    def shut(self) -> None:
        """Close the holder: every later ask raises and signs nothing."""
        with self._lock:
            self._shut = True

    @property
    def lost(self) -> str | None:
        """Why access is lost (the latched detail), or None while it is not."""
        with self._lock:
            return self._lost

    @property
    def sign_failed(self) -> bool:
        """Whether access was lost because a sign failed, not because the proxy refused us."""
        with self._lock:
            return self._sign_failed

    @property
    def setup_faults(self) -> dict[str, str]:
        """The configuration-kind `setup` faults reported so far, by the system each names
        (detail of the first)."""
        with self._lock:
            return dict(self._setup)

    @contextlib.contextmanager
    def deciding(self) -> Iterator[RequestAccess]:
        """Hold the holder's lock while its owner decides what it saw, and shut it as the
        decision is made: a token request still running on a thread the owner abandoned is
        counted by that lock, and nothing signs afterwards (#1363 O6)."""
        with self._lock:
            try:
                yield self
            finally:
                self._shut = True

    def _unavailable(self, detail: str) -> TransportFault:
        fault = TransportFault(detail, maybe_delivered=False)
        fault.origin = ORIGIN_ACCESS
        return fault

    def _tell(self, fault: AdapterFault) -> None:
        if self._on_fault is not None:
            self._on_fault(fault)


@dataclass(frozen=True)
class Route:
    """A method and a path relative to the declared base; `*` matches within one segment."""

    method: str
    path: str


# --- the one route rule (#1504 A6.1): its readers take it from here and keep no copy --------------------------------

#: The methods the credential proxy admits as reads with no declared route (#1163 O3): a record declares none of them,
#: an adapter's `READ_ROUTES` lists none of them, and the in-process read-endpoint confinement judges exactly them.
READ_METHODS = ("GET", "HEAD")
#: A declared route's method: upper-case letters, 3 to 10 of them.
_ROUTE_METHOD = re.compile(r"[A-Z]{3,10}")


def is_read_method(method: str) -> bool:
    """True for a method the proxy admits as a read with no declared route (`READ_METHODS`): the one question of which
    methods need a declaration, which the record judgement asks too (#1504 O3)."""
    return method in READ_METHODS


def route_shape_fault(method: object, path: object) -> str | None:
    """Why `(method, path)` is not a well-formed declared route, as a clause naming each bad part, or None when it is:
    the method is upper-case letters, 3 to 10; the path is text starting with `/` and holding no `?` or `#`. THE shape:
    the access declaration's parser, the catalog reader and the catalog declarations lint all ask it."""
    faults = []
    if not (isinstance(method, str) and _ROUTE_METHOD.fullmatch(method)):
        faults.append(f"its method {method!r} is not 3 to 10 upper-case letters")
    if not (isinstance(path, str) and path.startswith("/") and "?" not in path and "#" not in path):
        faults.append(f"its path {path!r} does not start with `/`, or holds `?` or `#`")
    return "; ".join(faults) or None


def read_routes_fault(value: object) -> str | None:
    """Why `value`, an adapter's `READ_ROUTES` as read cold, is not a usable list, as one line naming each offending entry
    (or the value), or None when it is usable: a tuple of `(method, path)` pairs, each of the declared route shape
    (`route_shape_fault`), none of a method in `READ_METHODS` (those need no declaration), none repeated. THE rule: the
    catalog reader and the catalog declarations lint both judge a list with it (#1504 A6.1)."""
    if not isinstance(value, tuple):
        return f"is {value!r}, not a tuple of (method, path) routes"
    faults: list[str] = []
    seen: list[object] = []  # a list, not a set: an entry read cold may be unhashable (a dict)
    for route in value:
        if not (isinstance(route, tuple) and len(route) == 2):
            faults.append(f"holds {route!r}, which is not a (method, path) pair")
            continue
        method, path = route
        why = route_shape_fault(method, path)
        if why is None and method in READ_METHODS:
            why = f"the proxy admits a {method} with no declared route, so the list names none"
        if why is not None:
            faults.append(f"holds {route!r}: {why}")
        elif route in seen:
            faults.append(f"holds {route!r} more than once")
        seen.append(route)
    faults = list(dict.fromkeys(faults))  # each offending entry named once, however often it recurs
    return "; ".join(faults) or None


@dataclass(frozen=True)
class AccessDeclaration:
    """One system's merged declaration: its single base URL (A2), its auth, the non-GET reads
    and the writes (default none), and optionally the private CA its system is verified under."""

    base: str
    auth: Auth
    reads: tuple[Route, ...] = ()
    writes: tuple[Route, ...] = ()
    #: PEM certificates that are the only trust for every leg of this declaration, its base and
    #: its OAuth token URL alike (#1391 O4, P4); None: the public bundle.
    ca: str | None = None


def ticket_write_fault(declaration: AccessDeclaration) -> str | None:
    """Why `declaration` cannot be written under a write pass naming a ticket (#1471 X2), as a clause, or None: it must
    declare exactly one write route with exactly one `*` segment (where the ticket goes), and only GET reads. THE rule:
    the credential proxy enforces it on every ticket write, and the case system's cover rule (`system_rules.cover_fault`)
    asks it last, so a declaration the store accepts is one the proxy writes under."""
    if len(declaration.writes) != 1 or declaration.writes[0].path.split("/").count("*") != 1:
        return "it must declare exactly one write route with exactly one `*` segment"
    if any(route.method != "GET" for route in declaration.reads):
        return "it declares a read route that is not a GET"
    return None


__all__ = [
    "TOKEN_REUSE_MARGIN_SEC", "TOKEN_SEC", "BASIC", "BEARER", "CALLER_GRACE_SEC", "caller_wait_sec", "CLIENT_ID", "CLIENT_SECRET", "CREDENTIAL_KINDS", "HEADER", "HTTP_PROXY",
    "OAUTH_CLIENT_CREDENTIALS", "PASSWORD", "PROXY_OVERHEAD_SEC", "PROXY_URL_ENV", "PUBLIC_FIELD_NAMES", "SCHEMES",
    "READ_METHODS", "SECRET_MIN_LENGTH", "STATIC", "USERNAME", "AccessDeclaration", "Auth", "CredentialRefused", "RequestAccess", "Route",
    "check_credentials", "credential_faults", "credential_fields", "is_read_method", "read_routes_fault",
    "route_shape_fault", "ticket_write_fault",
]
