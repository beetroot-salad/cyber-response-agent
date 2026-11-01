"""The access declaration of one `http-proxy` system (#1163): where its credential may go, how
it is applied, and which requests are reads or writes. Values only: it holds no credential. The
parser that reads it from a tenant's settings stays in `tenancy`."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

#: The operator's variable naming the credential proxy's address. Read by the launching process
#: alone: the address reaches a verb call on its context, never through a run's environment.
PROXY_URL_ENV = "DEFENDER_CREDENTIAL_PROXY_URL"

#: Seconds the credential proxy allows for its own calls (token check, credential read) on top of
#: a request's timeout, and the seconds a caller waits past that whole deadline (r7 A21): the
#: proxy has given up before its caller does.
PROXY_OVERHEAD_SEC = 20
CALLER_GRACE_SEC = 5

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
    field. The write API's minimum length and the proxy's scrub both ask this, so they agree."""
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


@dataclass(frozen=True)
class RequestAccess:
    """What a run's callers present to the credential proxy: its address and the read token the
    run signed at its start. The token is a bearer value, out of every repr."""

    proxy_url: str
    token: str = field(repr=False)


@dataclass(frozen=True)
class Route:
    """A method and a path relative to the declared base; `*` matches within one segment."""

    method: str
    path: str


@dataclass(frozen=True)
class AccessDeclaration:
    """One system's merged declaration: its single base URL (A2), its auth, the non-GET reads
    and the writes (default none)."""

    base: str
    auth: Auth
    reads: tuple[Route, ...] = ()
    writes: tuple[Route, ...] = ()


__all__ = [
    "BASIC", "BEARER", "CALLER_GRACE_SEC", "CLIENT_ID", "CLIENT_SECRET", "CREDENTIAL_KINDS", "HEADER", "HTTP_PROXY",
    "OAUTH_CLIENT_CREDENTIALS", "PASSWORD", "PROXY_OVERHEAD_SEC", "PROXY_URL_ENV", "PUBLIC_FIELD", "SCHEMES", "STATIC",
    "USERNAME", "AccessDeclaration", "Auth", "RequestAccess", "Route", "secret_fields",
]
