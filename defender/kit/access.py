"""The access declaration of one `http-proxy` system (#1163): where its credential may go, how
it is applied, and which requests are reads or writes. Values only: it holds no credential. The
parser that reads it from a tenant's settings stays in `tenancy`."""
from __future__ import annotations

from dataclasses import dataclass, field

#: The operator's variable naming the credential proxy's address. Read by the launching process
#: alone: the address reaches a verb call on its context, never through a run's environment.
PROXY_URL_ENV = "DEFENDER_CREDENTIAL_PROXY_URL"

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


@dataclass(frozen=True)
class Auth:
    """The declared scheme and the credential-set fields it names. Only the parts the scheme
    uses are set."""

    scheme: str
    field: str | None = None
    header: str | None = None
    username_field: str | None = None
    password_field: str | None = None
    token_url: str | None = None
    scopes: tuple[str, ...] = ()
    client_id_field: str | None = None
    client_secret_field: str | None = None

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
    "BASIC", "BEARER", "CREDENTIAL_KINDS", "HEADER", "HTTP_PROXY", "OAUTH_CLIENT_CREDENTIALS",
    "PROXY_URL_ENV", "SCHEMES", "STATIC", "AccessDeclaration", "Auth", "RequestAccess", "Route",
]
