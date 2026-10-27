"""The Keycloak sign-in adapter (#1306 DC-8): the browser sign-in and the admin API, as one class.

Keycloak is reached over HTTP only, through an injectable `httpx` transport. Its access and refresh
tokens never leave this module: a sign-in yields the verified ID token's account id, name and
`amr`, nothing else. Diagnostics carry statuses and reasons, never tokens or secrets.
"""

from __future__ import annotations

import datetime as _dt
import hmac
import json
import logging
import urllib.parse
from collections.abc import Callable
from typing import Any

import httpx
import jwt

from defender.identity import SignInRefused, SignInUnavailable, VerifiedSignIn

_log = logging.getLogger(__name__)

#: Our names for what an account must still do, and Keycloak's for the same.
_REQUIRED_ACTIONS = {"set_password": "UPDATE_PASSWORD", "set_up_otp": "CONFIGURE_TOTP"}
_TIMEOUT_SECONDS = 10.0
_ALGORITHM = "RS256"
#: An admin token is dropped this long before its stated expiry, so a call never carries a dead one.
_ADMIN_TOKEN_MARGIN = _dt.timedelta(seconds=30)


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


class KeycloakSignIn:
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
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], _dt.datetime] = _utc_now,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._admin_client = (admin_client_id, admin_client_secret)
        self._clock = clock
        self._http = httpx.Client(transport=transport, timeout=_TIMEOUT_SECONDS)
        # Keycloak serves every realm under <base>/realms/<name>; the admin API sits beside it. The
        # admin client's `manage-users` role reaches only its own realm, which is the sign-in realm.
        base, realm = self._issuer.rsplit("/realms/", 1)
        self._oidc = f"{self._issuer}/protocol/openid-connect"
        self._admin_users_url = f"{base}/admin/realms/{realm}/users"
        self._keys: dict[str, Any] = {}
        self._admin_token_held: tuple[str, _dt.datetime] | None = None

    def close(self) -> None:
        self._http.close()

    # --- browser sign-in ---------------------------------------------------------------------

    def begin_signin(self, *, state: str, nonce: str, code_challenge: str) -> str:
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
        return f"{self._oidc}/auth?{query}"

    def finish_signin(self, *, code: str, code_verifier: str, nonce: str) -> VerifiedSignIn:
        """Exchange the code, verify the ID token, and return who signed in and how."""
        id_token = self._exchange_code(code, code_verifier)
        claims = self._verify(id_token, nonce)
        # Only the name the person gave: `preferred_username` is the id our own code chose.
        name = claims.get("name") or ""
        amr = claims.get("amr")
        methods = tuple(m for m in amr if isinstance(m, str)) if isinstance(amr, list) else ()
        return VerifiedSignIn(account_id=claims["sub"], name=str(name), amr=methods)

    def _exchange_code(self, code: str, code_verifier: str) -> str:
        try:
            response = self._http.post(
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

    def _verify(self, id_token: str, nonce: str) -> dict[str, Any]:
        """The ID token's claims once signature, algorithm, issuer, audience, expiry and nonce hold."""
        try:
            header = jwt.get_unverified_header(id_token)
            if header.get("alg") != _ALGORITHM:
                raise SignInRefused("the ID token is not signed with RS256")
            key = self._key_for(header.get("kid"))
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

    def _key_for(self, kid: object) -> Any:
        """The signing key published under `kid`; one refetch of the key set on an unknown id."""
        if not isinstance(kid, str) or not kid:
            raise SignInRefused("the ID token names no signing key")
        if kid not in self._keys:
            self._keys = self._fetch_keys()
        if kid not in self._keys:
            raise SignInRefused("the ID token names an unknown signing key")
        return self._keys[kid]

    def _fetch_keys(self) -> dict[str, Any]:
        try:
            response = self._http.get(f"{self._oidc}/certs")
            response.raise_for_status()
            published = response.json()["keys"]
        except httpx.HTTPError as error:
            _log.warning("keycloak key set request failed: %s", type(error).__name__)
            raise SignInUnavailable("keycloak's signing keys cannot be fetched") from error
        except (ValueError, KeyError, TypeError) as error:
            raise SignInUnavailable("keycloak's signing keys are unreadable") from error
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

    # --- the admin API -----------------------------------------------------------------------

    def create_account(self, *, username: str, email: str, required_actions: frozenset[str]) -> str:
        """Create a verified, enabled account and return its id; an existing one is found, not duplicated."""
        try:
            actions = sorted(_REQUIRED_ACTIONS[name] for name in required_actions)
        except KeyError as error:
            raise ValueError(f"unknown required action {error.args[0]!r}") from error
        body = {"username": username, "email": email, "emailVerified": True, "enabled": True,
                "requiredActions": actions}
        response = self._admin("POST", self._admin_users_url, json=body, accept=(201, 409))
        if response.status_code == httpx.codes.CONFLICT:  # the username or email exists
            return self._find_by_username(username)
        account_id = response.headers.get("location", "").rstrip("/").rsplit("/", 1)[-1]
        if not account_id:
            raise SignInUnavailable("keycloak created the account but named no id")
        return urllib.parse.unquote(account_id)

    def _find_by_username(self, username: str) -> str:
        response = self._admin("GET", self._admin_users_url, params={"username": username, "exact": "true"})
        try:
            hits = [u for u in response.json()
                    if isinstance(u.get("username"), str) and u["username"].casefold() == username.casefold()]
            return str(hits[0]["id"])
        except (ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
            # The conflict came from something else (an email another account holds): no wrong id.
            raise SignInUnavailable("keycloak reports a conflict but has no such account") from error

    def send_set_password_email(self, account_id: str, *, lifespan: _dt.timedelta) -> None:
        """Have Keycloak email the account an action link to set its password."""
        self._admin(
            "PUT", f"{self._user_url(account_id)}/execute-actions-email",
            params={"lifespan": int(lifespan.total_seconds())}, json=["UPDATE_PASSWORD"],
        )

    def has_otp(self, account_id: str) -> bool:
        """Whether the account holds a one-time-code credential."""
        response = self._admin("GET", f"{self._user_url(account_id)}/credentials")
        try:
            return any(isinstance(c, dict) and c.get("type") == "otp" for c in response.json())
        except (ValueError, TypeError) as error:
            raise SignInUnavailable("keycloak's credential list is unreadable") from error

    def require_otp_setup(self, account_id: str) -> None:
        """Make the account set up a one-time code at its next sign-in, keeping its other pending actions."""
        url = self._user_url(account_id)
        try:
            user = self._admin("GET", url).json()
            existing = user.get("requiredActions") or []
            user["requiredActions"] = [*existing, *(a for a in ("CONFIGURE_TOTP",) if a not in existing)]
        except (ValueError, AttributeError, TypeError) as error:
            raise SignInUnavailable("keycloak's account record is unreadable") from error
        self._admin("PUT", url, json=user)

    def _user_url(self, account_id: str) -> str:
        return f"{self._admin_users_url}/{urllib.parse.quote(account_id, safe='')}"

    def _admin_token(self) -> str:
        """A client-credentials token, reused until shortly before Keycloak says it expires."""
        held = self._admin_token_held
        if held is not None and self._clock() < held[1]:
            return held[0]
        try:
            response = self._http.post(f"{self._oidc}/token", auth=self._admin_client,
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

    def _admin(self, method: str, url: str, *, accept: tuple[int, ...] = (), **kwargs: Any) -> httpx.Response:
        """One admin API call; any non-2xx (other than the `accept`ed statuses) or transport error is unavailable."""
        try:
            response = self._http.request(
                method, url, headers={"Authorization": f"Bearer {self._admin_token()}"}, **kwargs)
        except httpx.HTTPError as error:
            _log.warning("keycloak admin %s failed: %s", method, type(error).__name__)
            raise SignInUnavailable("keycloak's admin API is unreachable") from error
        if not response.is_success and response.status_code not in accept:
            _log.warning("keycloak admin %s answered %s", method, response.status_code)
            raise SignInUnavailable(f"keycloak's admin API answered {response.status_code}")
        return response
