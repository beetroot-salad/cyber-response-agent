"""The access declaration of one `http-proxy` system (#1163): where its credential may go, how
it is applied, and which requests are reads or writes. Values only: it holds no credential. The
parser that reads it from a tenant's settings stays in `tenancy`."""
from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable, Iterable, Iterator
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
#: The one field of each kind that is not secret; every other field of a set is.
PUBLIC_FIELD = {STATIC: USERNAME, OAUTH_CLIENT_CREDENTIALS: CLIENT_ID}


def secret_fields(kind: str, names: Iterable[str]) -> tuple[str, ...]:
    """Which of a `kind` set's field `names` are secret (r7 A19): all but the kind's public
    field. The write API's minimum length asks this."""
    return tuple(n for n in names if n != PUBLIC_FIELD.get(kind))


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


__all__ = [
    "TOKEN_REUSE_MARGIN_SEC", "TOKEN_SEC", "BASIC", "BEARER", "CALLER_GRACE_SEC", "caller_wait_sec", "CLIENT_ID", "CLIENT_SECRET", "CREDENTIAL_KINDS", "HEADER", "HTTP_PROXY",
    "OAUTH_CLIENT_CREDENTIALS", "PASSWORD", "PROXY_OVERHEAD_SEC", "PROXY_URL_ENV", "PUBLIC_FIELD", "SCHEMES", "STATIC",
    "USERNAME", "AccessDeclaration", "Auth", "RequestAccess", "Route", "secret_fields",
]
