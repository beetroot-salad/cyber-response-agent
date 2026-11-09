"""The Keycloak sign-in adapter (#1306 DC-8): the browser sign-in and the admin API, as one class.

Keycloak is reached over HTTP only, through an injectable `httpx` transport. Its access and refresh
tokens never leave this module: a sign-in yields the verified ID token's account id, name and
`amr`, nothing else. Diagnostics carry statuses and reasons, never tokens or secrets.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import hmac
import json
import logging
import urllib.parse
from collections.abc import Callable
from typing import Any

import httpx
import jwt

from defender.identity import SignInRefused, SignInUnavailable, VerifiedProgramToken, VerifiedSignIn
from defender.records.formats import CredentialId, IdRefused

_log = logging.getLogger(__name__)

#: Our names for what an account must still do, and Keycloak's for the same.
_REQUIRED_ACTIONS = {"set_password": "UPDATE_PASSWORD", "set_up_otp": "CONFIGURE_TOTP"}
_TIMEOUT_SECONDS = 10.0
_ALGORITHM = "RS256"
#: An admin token is dropped this long before its stated expiry, so a call never carries a dead one.
_ADMIN_TOKEN_MARGIN = _dt.timedelta(seconds=30)


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _split_url(setting: str, value: str) -> urllib.parse.SplitResult:
    """An absolute http(s) URL with a host, a valid port if any, and no credentials, query, fragment
    or whitespace; else a ValueError naming the setting."""
    def refuse(why: str) -> ValueError:
        return ValueError(f"keycloak {setting} {value!r} {why}")

    if any(c.isspace() or not c.isprintable() for c in value):
        raise refuse("contains whitespace or a control character")
    try:
        parts = urllib.parse.urlsplit(value)
        parts.port  # noqa: B018 — reading it is the check: a non-numeric or out-of-range port raises
    except ValueError as e:
        raise refuse(f"is not a URL: {e}") from None
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.query or parts.fragment \
            or value.endswith(("?", "#")):
        raise refuse("is not an absolute http(s) URL without query or fragment")
    if parts.username is not None:
        raise refuse("carries credentials")
    return parts


def _realm_url(issuer: str) -> tuple[str, str, str]:
    """The issuer as (itself without a trailing slash, the server base before `/realms/`, the realm)."""
    parts = _split_url("issuer", issuer)
    base, sep, realm = parts.path.rstrip("/").rpartition("/realms/")
    if not realm or "/" in realm:  # without `/realms/`, `realm` is the whole path, which has a slash
        raise ValueError(f"keycloak issuer {issuer!r} is not <server>/realms/<realm>")
    issuer = issuer.rstrip("/")
    return issuer, issuer[: len(issuer) - len(sep + realm)], realm


def _server_base(server_url: str) -> str:
    """A URL as `_split_url` takes it; a path prefix is kept, but not one reaching into `/realms`
    (that is the issuer)."""
    if "realms" in _split_url("server_url", server_url).path.split("/"):
        raise ValueError(f"keycloak server_url {server_url!r} names a realm path; give the server's base, not the issuer")
    return server_url.rstrip("/")


def _rsa_keys(published: Any) -> dict[str, Any]:
    """The usable RS256 signing keys of a published key set, by key id; others are skipped."""
    keys: dict[str, Any] = {}
    for jwk in published:
        if not isinstance(jwk, dict) or jwk.get("kty") != "RSA" or not isinstance(jwk.get("kid"), str):
            continue
        if jwk.get("use", "sig") != "sig" or jwk.get("alg", _ALGORITHM) != _ALGORITHM:
            continue
        try:
            keys[jwk["kid"]] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        except (jwt.PyJWTError, ValueError):
            _log.warning("skipping an unreadable signing key")
    return keys


#: The programs realm's key set is fetched at most this often, so random key ids in bearer tokens never become
#: Keycloak traffic.
KEY_REFETCH_WINDOW = _dt.timedelta(seconds=60)
#: Keys fetched this long ago are fetched again before use, so a key Keycloak stopped publishing stops verifying.
KEY_MAX_AGE = _dt.timedelta(minutes=10)


class _KeySet:
    """One realm's published signing keys, shared by both realms' token checks. An unknown key id, or keys older
    than `KEY_MAX_AGE`, fetch the set again, at most once per `refetch_window` (a failed fetch counts). One
    fetch runs at a time and requests arriving meanwhile wait for its result. Only a successful fetch replaces
    the keys: an outage keeps the held keys verifying, and an unknown key id during one is `SignInUnavailable`,
    never `SignInRefused`, because the key may well exist."""

    def __init__(
        self, http: httpx.AsyncClient, url: str, clock: Callable[[], _dt.datetime], *, token: str, realm: str,
        refetch_window: _dt.timedelta,
    ) -> None:
        self._http, self._url, self._clock = http, url, clock
        self._window = refetch_window
        self._token, self._realm = token, realm  # for the refusal and the log line
        self._keys: dict[str, Any] = {}
        self._fetched_at: _dt.datetime | None = None  # the last successful fetch
        self._tried_at: _dt.datetime | None = None  # the last fetch, successful or not
        self._lock = asyncio.Lock()

    def _fresh(self, now: _dt.datetime) -> bool:
        return self._fetched_at is not None and now - self._fetched_at < KEY_MAX_AGE

    async def key_for(self, kid: object) -> Any:
        if not isinstance(kid, str) or not kid:
            raise SignInRefused(f"{self._token} names no signing key")
        held = self._keys.get(kid)
        if held is not None and (self._fresh(self._clock()) or self._lock.locked()):
            return held  # a key we hold never waits behind a fetch
        async with self._lock:
            now = self._clock()
            held = self._keys.get(kid)
            if held is not None and self._fresh(now):
                return held  # a fetch that finished while this request waited
            if self._tried_at is None or now - self._tried_at >= self._window:
                self._tried_at = now
                try:
                    self._keys, self._fetched_at = await self._fetch(), now
                except SignInUnavailable:
                    if held is None:
                        raise
                    _log.warning("keycloak %s key set is past its age and cannot be fetched; held keys serve",
                                 self._realm)
                    return held
            elif held is not None:
                return held  # past its age, but the next fetch is not due yet
            elif self._fetched_at != self._tried_at:  # the last fetch failed: the key may well exist
                raise SignInUnavailable("keycloak's signing keys cannot be fetched")
        key = self._keys.get(kid)
        if key is None:
            raise SignInRefused(f"{self._token} names an unknown signing key")
        return key

    async def _fetch(self) -> dict[str, Any]:
        try:
            response = await self._http.get(self._url)
            response.raise_for_status()
            published = response.json()["keys"]
        except httpx.HTTPError as error:
            _log.warning("keycloak %s key set request failed: %s", self._realm, type(error).__name__)
            raise SignInUnavailable("keycloak's signing keys cannot be fetched") from error
        except (ValueError, KeyError, TypeError) as error:
            raise SignInUnavailable("keycloak's signing keys are unreadable") from error
        return _rsa_keys(published)


class _RealmAdmin:
    """A realm's admin API as one confidential client reaches it: a client-credentials token, reused until shortly
    before it expires, and calls that treat any failure as `SignInUnavailable`. The subclass sets `_http`, `_oidc`
    (the realm's `protocol/openid-connect` URL), `_admin_client` and `_clock`."""

    _http: httpx.AsyncClient
    _oidc: str
    _admin_client: tuple[str, str]
    _clock: Callable[[], _dt.datetime]
    _admin_token_held: tuple[str, _dt.datetime] | None

    async def _admin_token(self) -> str:
        """A client-credentials token, reused until shortly before Keycloak says it expires."""
        held = self._admin_token_held
        if held is not None and self._clock() < held[1]:
            return held[0]
        try:
            response = await self._http.post(f"{self._oidc}/token", auth=self._admin_client,
                                       data={"grant_type": "client_credentials"})
            response.raise_for_status()
            body = response.json()
            token, lifetime = body["access_token"], body.get("expires_in")
        except httpx.HTTPError as error:
            _log.warning("keycloak admin token request failed: %s", type(error).__name__)
            raise SignInUnavailable("keycloak refused the admin token request") from error
        except (ValueError, KeyError, TypeError) as error:
            raise SignInUnavailable("keycloak's admin token response is unreadable") from error
        if not isinstance(token, str) or not token:
            raise SignInUnavailable("keycloak's admin token response is unreadable")
        if isinstance(lifetime, (int, float)) and lifetime > _ADMIN_TOKEN_MARGIN.total_seconds():
            self._admin_token_held = (token, self._clock() + _dt.timedelta(seconds=lifetime) - _ADMIN_TOKEN_MARGIN)
        return token

    async def _admin(self, method: str, url: str, *, accept: tuple[int, ...] = (), **kwargs: Any) -> httpx.Response:
        """One admin API call; any non-2xx (other than the `accept`ed statuses) or transport error is unavailable."""
        try:
            response = await self._http.request(
                method, url, headers={"Authorization": f"Bearer {await self._admin_token()}"}, **kwargs)
        except httpx.HTTPError as error:
            _log.warning("keycloak admin %s failed: %s", method, type(error).__name__)
            raise SignInUnavailable("keycloak's admin API is unreachable") from error
        if not response.is_success and response.status_code not in accept:
            _log.warning("keycloak admin %s answered %s", method, response.status_code)
            raise SignInUnavailable(f"keycloak's admin API answered {response.status_code}")
        return response


class KeycloakSignIn(_RealmAdmin):
    """Sign-in and account administration against one Keycloak realm."""

    def __init__(  # noqa: PLR0913 — the pinned interface: two clients' credentials plus the seams, one keyword each
        self,
        *,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        admin_client_id: str,
        admin_client_secret: str,
        server_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], _dt.datetime] = _utc_now,
    ) -> None:
        self._issuer, base, realm = _realm_url(issuer)
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._admin_client = (admin_client_id, admin_client_secret)
        self._clock = clock
        self._http = httpx.AsyncClient(transport=transport, timeout=_TIMEOUT_SECONDS)
        # Keycloak serves every realm under <base>/realms/<name>; the admin API sits beside it. The
        # admin client's `manage-users` role reaches only its own realm, which is the sign-in realm.
        # `server_url`, when the API reaches Keycloak at another address than the browser does
        # (#1349), replaces that base for every request the API sends itself; the browser's
        # sign-in URL and the token's `iss` stay the issuer.
        server = base if server_url is None else _server_base(server_url)
        self._signin_url = f"{self._issuer}/protocol/openid-connect/auth"
        self._oidc = f"{server}/realms/{realm}/protocol/openid-connect"
        self._admin_users_url = f"{server}/admin/realms/{realm}/users"
        # No refetch window: an ID token comes from Keycloak's own token endpoint, never from an outsider, so an
        # unknown key id there is a rotation to follow at once, not traffic to hold back.
        self._keys = _KeySet(self._http, f"{self._oidc}/certs", clock, token="the ID token", realm="sign-in",
                             refetch_window=_dt.timedelta(0))
        self._admin_token_held: tuple[str, _dt.datetime] | None = None

    async def close(self) -> None:
        await self._http.aclose()

    # --- browser sign-in ---------------------------------------------------------------------

    async def begin_signin(self, *, state: str, nonce: str, code_challenge: str) -> str:
        """The URL to send the browser to: password prompt forced, PKCE S256."""
        query = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": "openid profile",
            "state": state,
            "nonce": nonce,
            "prompt": "login",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        })
        return f"{self._signin_url}?{query}"

    async def finish_signin(self, *, code: str, code_verifier: str, nonce: str) -> VerifiedSignIn:
        """Exchange the code, verify the ID token, and return who signed in and how."""
        id_token = await self._exchange_code(code, code_verifier)
        claims = await self._verify(id_token, nonce)
        # Only the name the person gave: `preferred_username` is the id our own code chose.
        name = claims.get("name") or ""
        amr = claims.get("amr")
        methods = tuple(m for m in amr if isinstance(m, str)) if isinstance(amr, list) else ()
        return VerifiedSignIn(account_id=claims["sub"], name=str(name), amr=methods)

    async def _exchange_code(self, code: str, code_verifier: str) -> str:
        try:
            response = await self._http.post(
                f"{self._oidc}/token",
                auth=(self._client_id, self._client_secret),
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "code_verifier": code_verifier,
                    "redirect_uri": self._redirect_uri,
                },
            )
        except httpx.HTTPError as error:
            _log.warning("keycloak token request failed: %s", type(error).__name__)
            raise SignInUnavailable("keycloak is unreachable") from error
        if response.status_code >= httpx.codes.INTERNAL_SERVER_ERROR:
            _log.warning("keycloak token endpoint answered %s", response.status_code)
            raise SignInUnavailable("keycloak failed the code exchange")
        if response.status_code != httpx.codes.OK:
            raise SignInRefused("keycloak rejected the code exchange")
        try:
            id_token = response.json()["id_token"]
        except (ValueError, KeyError, TypeError) as error:
            raise SignInRefused("the token response carries no ID token") from error
        if not isinstance(id_token, str) or not id_token:
            raise SignInRefused("the token response carries no ID token")
        return id_token

    async def _verify(self, id_token: str, nonce: str) -> dict[str, Any]:
        """The ID token's claims once signature, algorithm, issuer, audience, expiry and nonce hold."""
        try:
            header = jwt.get_unverified_header(id_token)
            if header.get("alg") != _ALGORITHM:
                raise SignInRefused("the ID token is not signed with RS256")
            key = await self._keys.key_for(header.get("kid"))
            claims = jwt.decode(
                id_token,
                key,
                algorithms=[_ALGORITHM],
                audience=self._client_id,
                issuer=self._issuer,
                # Expiry is checked below against the injected clock, not the process clock.
                options={"require": ["exp", "iss", "aud", "sub"], "verify_exp": False,
                         "verify_iat": False, "verify_nbf": False},
            )
        except jwt.PyJWTError as error:
            raise SignInRefused(f"the ID token failed verification: {type(error).__name__}") from error
        if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= self._clock().timestamp():
            raise SignInRefused("the ID token has expired")
        if not isinstance(claims["sub"], str) or not claims["sub"]:
            raise SignInRefused("the ID token has no subject")
        token_nonce = claims.get("nonce")
        if not isinstance(token_nonce, str) or not hmac.compare_digest(
            token_nonce.encode(), nonce.encode()
        ):
            raise SignInRefused("the ID token's nonce does not match")
        return claims

    # --- the admin API -----------------------------------------------------------------------

    async def create_account(self, *, username: str, email: str, required_actions: frozenset[str]) -> str:
        """Create a verified, enabled account and return its id; an existing one is found, not duplicated."""
        try:
            actions = sorted(_REQUIRED_ACTIONS[name] for name in required_actions)
        except KeyError as error:
            raise ValueError(f"unknown required action {error.args[0]!r}") from error
        body = {"username": username, "email": email, "emailVerified": True, "enabled": True,
                "requiredActions": actions}
        response = await self._admin("POST", self._admin_users_url, json=body, accept=(201, 409))
        if response.status_code == httpx.codes.CONFLICT:  # the username or email exists
            return await self._find_by_username(username)
        account_id = response.headers.get("location", "").rstrip("/").rsplit("/", 1)[-1]
        if not account_id:
            raise SignInUnavailable("keycloak created the account but named no id")
        return urllib.parse.unquote(account_id)

    async def _find_by_username(self, username: str) -> str:
        response = await self._admin("GET", self._admin_users_url, params={"username": username, "exact": "true"})
        try:
            hits = [u for u in response.json()
                    if isinstance(u.get("username"), str) and u["username"].casefold() == username.casefold()]
            return str(hits[0]["id"])
        except (ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
            # The conflict came from something else (an email another account holds): no wrong id.
            raise SignInUnavailable("keycloak reports a conflict but has no such account") from error

    async def send_set_password_email(self, account_id: str, *, lifespan: _dt.timedelta) -> None:
        """Have Keycloak email the account an action link to set its password."""
        await self._admin(
            "PUT", f"{self._user_url(account_id)}/execute-actions-email",
            params={"lifespan": int(lifespan.total_seconds())}, json=["UPDATE_PASSWORD"],
        )

    async def has_otp(self, account_id: str) -> bool:
        """Whether the account holds a one-time-code credential."""
        response = await self._admin("GET", f"{self._user_url(account_id)}/credentials")
        try:
            return any(isinstance(c, dict) and c.get("type") == "otp" for c in response.json())
        except (ValueError, TypeError) as error:
            raise SignInUnavailable("keycloak's credential list is unreadable") from error

    async def require_otp_setup(self, account_id: str) -> None:
        """Make the account set up a one-time code at its next sign-in, keeping its other pending actions."""
        url = self._user_url(account_id)
        try:
            user = (await self._admin("GET", url)).json()
            existing = user.get("requiredActions") or []
            user["requiredActions"] = [*existing, *(a for a in ("CONFIGURE_TOTP",) if a not in existing)]
        except (ValueError, AttributeError, TypeError) as error:
            raise SignInUnavailable("keycloak's account record is unreadable") from error
        await self._admin("PUT", url, json=user)

    def _user_url(self, account_id: str) -> str:
        return f"{self._admin_users_url}/{urllib.parse.quote(account_id, safe='')}"


#: A program client's access tokens live this long (seconds).
PROGRAM_TOKEN_LIFESPAN = 300
_CLIENT_PAGE = 100


class KeycloakPrograms(_RealmAdmin):
    """The programs realm (`defender-programs`, #1307): OAuth clients for program credentials, and the check of
    the access tokens they get. Holds the admin client of that realm alone, with client management only. Every
    failure of an admin call or of a key-set fetch is `SignInUnavailable`; a token that does not verify is
    `SignInRefused`. It deletes only what it is told to, never on its own."""

    def __init__(  # noqa: PLR0913 — settings and seams, one keyword each
        self,
        *,
        issuer: str,
        audience: str,
        admin_client_id: str,
        admin_client_secret: str,
        server_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], _dt.datetime] = _utc_now,
    ) -> None:
        self._issuer, base, realm = _realm_url(issuer)
        self._audience = audience
        self._admin_client = (admin_client_id, admin_client_secret)
        self._clock = clock
        self._http = httpx.AsyncClient(transport=transport, timeout=_TIMEOUT_SECONDS)
        server = base if server_url is None else _server_base(server_url)
        self._oidc = f"{server}/realms/{realm}/protocol/openid-connect"
        self._clients_url = f"{server}/admin/realms/{realm}/clients"
        self._keys = _KeySet(self._http, f"{self._oidc}/certs", clock, token="the token", realm="programs",
                             refetch_window=KEY_REFETCH_WINDOW)
        self._admin_token_held = None

    async def close(self) -> None:
        await self._http.aclose()

    # --- tokens ------------------------------------------------------------------------------

    async def verify_token(self, token: str) -> VerifiedProgramToken:
        """The token's client and subject once signature, RS256, issuer, audience, `typ`, expiry and the
        presence of `azp` and `sub` hold; else `SignInRefused`. Keycloak unreachable for a key we lack: unavailable."""
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != _ALGORITHM:
                raise SignInRefused("the token is not signed with RS256")
            key = await self._keys.key_for(header.get("kid"))
            claims = jwt.decode(
                token, key, algorithms=[_ALGORITHM], audience=self._audience, issuer=self._issuer,
                options={"require": ["exp", "iss", "aud", "sub"], "verify_exp": False,
                         "verify_iat": False, "verify_nbf": False})
        except (jwt.PyJWTError, ValueError, TypeError) as error:
            raise SignInRefused(f"the token failed verification: {type(error).__name__}") from error
        expires = claims.get("exp")
        if not isinstance(expires, (int, float)) or expires <= self._clock().timestamp():
            raise SignInRefused("the token has expired")
        if claims.get("typ") != "Bearer":
            raise SignInRefused("the token is not an access token")
        client, subject = claims.get("azp"), claims["sub"]
        if not isinstance(client, str) or not client or not isinstance(subject, str) or not subject:
            raise SignInRefused("the token names no client or subject")
        return VerifiedProgramToken(
            client_id=client, subject=subject, expires_at=_dt.datetime.fromtimestamp(expires, _dt.UTC))

    # --- clients -----------------------------------------------------------------------------

    async def create_client(self, credential_id: str) -> tuple[str, str]:
        """Create the confidential, service-account-only client whose client id and internal id are the
        credential's id; then read back its service-account user id and its secret. Nothing is undone on a
        failure: the reconciliation deletes what no credential claims."""
        body = {
            "id": credential_id, "clientId": credential_id, "enabled": True, "protocol": "openid-connect",
            "publicClient": False, "clientAuthenticatorType": "client-secret", "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
            "fullScopeAllowed": False,
            "attributes": {"access.token.lifespan": str(PROGRAM_TOKEN_LIFESPAN)},
            "protocolMappers": [{
                "name": "programs-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": self._audience, "access.token.claim": "true",
                           "id.token.claim": "false", "introspection.token.claim": "false"},
            }],
        }
        await self._admin("POST", self._clients_url, json=body)
        client_url = f"{self._clients_url}/{urllib.parse.quote(credential_id, safe='')}"
        try:
            account = (await self._admin("GET", f"{client_url}/service-account-user")).json()["id"]
            secret = (await self._admin("GET", f"{client_url}/client-secret")).json()["value"]
        except (ValueError, KeyError, TypeError) as error:
            raise SignInUnavailable("keycloak's client record is unreadable") from error
        if not isinstance(account, str) or not account or not isinstance(secret, str) or not secret:
            raise SignInUnavailable("keycloak's client record is unreadable")
        return account, secret

    async def client_ids(self) -> set[str]:
        """The program clients: those whose client id and internal id are one credential id (UUID), as
        `create_client` makes them, so that `delete_client` addresses what was listed. Built-in clients and the
        API's own have plain names, and a client made by hand has an internal id of Keycloak's own: none is listed."""
        found: set[str] = set()
        first = 0
        while True:
            response = await self._admin("GET", self._clients_url, params={"first": first, "max": _CLIENT_PAGE})
            try:
                page = [(str(c["id"]), str(c["clientId"])) for c in response.json()]
            except (ValueError, KeyError, TypeError) as error:
                raise SignInUnavailable("keycloak's client list is unreadable") from error
            for internal_id, client_id in page:
                if internal_id != client_id:
                    continue
                try:
                    found.add(str(CredentialId(client_id)))
                except IdRefused:
                    continue
            if len(page) < _CLIENT_PAGE:
                return found
            first += _CLIENT_PAGE

    async def delete_client(self, client_id: str) -> bool:
        """Delete the client with this internal id (our credential id): whether it was there to delete; one already
        gone is no error."""
        response = await self._admin(
            "DELETE", f"{self._clients_url}/{urllib.parse.quote(client_id, safe='')}", accept=(404,))
        return response.status_code != 404
