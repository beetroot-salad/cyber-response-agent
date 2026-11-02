"""Applying a credential set by its declared scheme (#1163 A4, A8, A12, O4, O6).

A set's kind must fit the scheme (`bearer`/`basic`/`header` need `static`, OAuth needs
`oauth-client-credentials`) and every field the scheme reads must be present, or nothing is
sent. `secret_values` names the values the answer is scrubbed of (every field but the kind's
public one, r7 A19; the pipeline adds the access token). OAuth access tokens live only in this
process, keyed by (tenant, system, set version,
digest of the auth block); a token is reused only while it is unexpired by a margin."""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import quote_plus

import httpx

from defender.kit.access import (
    BASIC,
    BEARER,
    CLIENT_ID,
    CLIENT_SECRET,
    CREDENTIAL_KINDS,
    HEADER,
    PASSWORD,
    USERNAME,
    Auth,
    secret_fields,
)
from defender.kit.faults import ConfigFault
from defender.credential_proxy._deadline import Deadline
from defender.credential_proxy._refusal import CONFIG, TRANSPORT, Refused

#: What replaces a secret value the upstream echoed (N6: literal echoes only).
MARKER = "[credential removed]"
#: A cached access token is not reused within this many seconds of its stated expiry.
REFRESH_MARGIN_SEC = 30
#: The most a token endpoint's answer may hold.
TOKEN_REPLY_CAP = 65536


@dataclass(frozen=True)
class CredentialSet:
    """One (tenant, system)'s credentials: their `kind` (A4), the field values (never shown in
    a repr) and the store's version of the set, which a rotation moves on."""

    kind: str
    fields: Mapping[str, str] = field(repr=False)
    version: int

    def __post_init__(self) -> None:
        if self.kind not in CREDENTIAL_KINDS:
            raise ConfigFault(f"a credential set's kind must be one of {list(CREDENTIAL_KINDS)}")
        if not isinstance(self.fields, Mapping) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in self.fields.items()):
            raise ConfigFault("a credential set's fields must map names to text")
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise ConfigFault("a credential set's version must be a whole number")


def _needed(creds: CredentialSet, name: str | None, system: str) -> str:
    value = creds.fields.get(name or "")
    if not value:
        raise Refused(CONFIG, f"the credential set of {system} lacks the field {name!r} its "
                              "declared scheme needs")
    if not value.isprintable():
        raise Refused(CONFIG, f"the credential field {name!r} of {system} holds a control "
                              "character")
    return value


def secret_values(creds: CredentialSet) -> tuple[str, ...]:
    """The secret values of `creds`, by the rule the write API checks too (r7 A19)."""
    return tuple(v for k in secret_fields(creds.kind, creds.fields) if (v := creds.fields[k]))


def check_fit(auth: Auth, creds: CredentialSet, system: str) -> None:
    """`Refused` unless `creds` is the kind `auth` needs (A4)."""
    if creds.kind != auth.kind:
        raise Refused(CONFIG, f"the credential set of {system} is {creds.kind!r}; its declared "
                              f"scheme {auth.scheme!r} needs {auth.kind!r}")


def _ascii(value: str, name: str | None, system: str) -> str:
    if not value.isascii():
        raise Refused(CONFIG, f"the credential field {name!r} of {system} is not ASCII, so it cannot be a header")
    return value


def static_headers(auth: Auth, creds: CredentialSet, system: str) -> dict[str, str]:
    """The header a static scheme adds. A value sent as is must be ASCII (a header is bytes)."""
    if auth.scheme == BEARER:
        return {"Authorization": f"Bearer {_ascii(_needed(creds, auth.field, system), auth.field, system)}"}
    if auth.scheme == HEADER:
        return {str(auth.header): _ascii(_needed(creds, auth.field, system), auth.field, system)}
    if auth.scheme == BASIC:
        user = _needed(creds, USERNAME, system)
        if ":" in user:
            raise Refused(CONFIG, f"the basic-auth username of {system} holds a `:`")
        packed = f"{user}:{_needed(creds, PASSWORD, system)}".encode()
        return {"Authorization": f"Basic {base64.b64encode(packed).decode('ascii')}"}
    raise AssertionError(f"not a static scheme: {auth.scheme}")


def scrub_secrets(text: str, secrets: tuple[str, ...]) -> str:
    """`text` with every literal occurrence of each secret replaced by `MARKER`, longest
    first so a secret holding another is removed whole."""
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, MARKER)
    return text


def scrub_secret_bytes(data: bytes, secrets: tuple[str, ...]) -> bytes:
    """`scrub_secrets` over bytes, each secret as its UTF-8 bytes."""
    for secret in sorted(secrets, key=len, reverse=True):
        data = data.replace(secret.encode("utf-8"), MARKER.encode("utf-8"))
    return data


@dataclass
class _Held:
    version: int
    digest: str
    token: str = field(repr=False)
    good_until: float


def _auth_digest(auth: Auth) -> str:
    block = [auth.token_url, list(auth.scopes)]
    return hashlib.sha256(json.dumps(block).encode("utf-8")).hexdigest()


class AccessTokens:
    """OAuth access tokens held in memory per (tenant, system), each under the set version and
    the auth block it was issued for (A8). A changed version or block, or a token within
    `REFRESH_MARGIN_SEC` of expiry, means a fresh exchange; one at a time per system."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._gates: dict[tuple[str, str], threading.Lock] = {}
        self._held: dict[tuple[str, str], _Held] = {}

    def __repr__(self) -> str:
        return f"{type(self).__name__}({len(self._held)} held)"

    def _gate(self, key: tuple[str, str]) -> threading.Lock:
        with self._lock:
            return self._gates.setdefault(key, threading.Lock())

    def token(self, client: httpx.Client, tenant_id: str, system: str, auth: Auth,  # noqa: PLR0913 — one exchange's inputs
              creds: CredentialSet, deadline: Deadline) -> str:
        """An access token for `creds` under `auth`: the held one if still good, else a new
        exchange (whose failure is `Refused`, never retried)."""
        key, digest = (tenant_id, system), _auth_digest(auth)
        with self._gate(key):
            held = self._held.get(key)
            if (held is not None and (held.version, held.digest) == (creds.version, digest)
                    and time.monotonic() < held.good_until):
                return held.token
            self._held.pop(key, None)
            asked_at = time.monotonic()
            token, lifetime = _token_exchange(client, auth, creds, system, deadline)
            if lifetime is not None and lifetime > REFRESH_MARGIN_SEC:
                self._held[key] = _Held(creds.version, digest, token,
                                        asked_at + lifetime - REFRESH_MARGIN_SEC)
            return token

    def evict(self, tenant_id: str, system: str, token: str) -> None:
        """Drop the held token for (tenant, system) if it is `token` (the upstream refused it)."""
        key = (tenant_id, system)
        with self._gate(key):
            held = self._held.get(key)
            if held is not None and held.token == token:
                del self._held[key]


def _token_exchange(client: httpx.Client, auth: Auth, creds: CredentialSet,
                    system: str, deadline: Deadline) -> tuple[str, int | None]:
    """One client-credentials exchange at the declared token URL (A12): the access token and
    its stated lifetime in seconds (None: not stated, so it is not reused). The client secret
    goes in Basic auth (RFC 6749 2.3.1) and only here."""
    client_id = _needed(creds, CLIENT_ID, system)
    secret = _needed(creds, CLIENT_SECRET, system)
    packed = f"{quote_plus(client_id)}:{quote_plus(secret)}".encode()
    form = {"grant_type": "client_credentials"}
    if auth.scopes:
        form["scope"] = " ".join(auth.scopes)
    headers = {"Authorization": f"Basic {base64.b64encode(packed).decode('ascii')}",
               "Accept": "application/json"}
    what = f"the token exchange of {system}"
    try:
        with client.stream("POST", str(auth.token_url), data=form, headers=headers,
                           timeout=deadline.wait(what)) as reply:
            status = reply.status_code
            body = bytearray()
            for chunk in reply.iter_bytes():
                deadline.left(what)
                body += chunk
                if len(body) > TOKEN_REPLY_CAP:
                    raise Refused(CONFIG, f"the token endpoint of {system} answered more than "
                                          f"{TOKEN_REPLY_CAP} bytes")
    except httpx.TransportError as e:
        raise Refused(TRANSPORT, f"the token endpoint of {system} is unreachable "
                                 f"({type(e).__name__})") from None
    except httpx.DecodingError:
        raise Refused(CONFIG, f"the token endpoint of {system} answered an undecodable "
                              "body") from None
    if status >= 500:
        raise Refused(TRANSPORT, f"the token endpoint of {system} answered {status}")
    if status != 200:
        raise Refused(CONFIG, f"the token endpoint of {system} refused the exchange ({status})")
    return _issued(bytes(body), system)


def _issued(body: bytes, system: str) -> tuple[str, int | None]:
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        doc = None
    if not isinstance(doc, dict):
        raise Refused(CONFIG, f"the token endpoint of {system} answered 200 without a JSON "
                              "object")
    token, kind, lifetime = doc.get("access_token"), doc.get("token_type"), doc.get("expires_in")
    if not isinstance(token, str) or not token or not token.isprintable() or " " in token:
        raise Refused(CONFIG, f"the token endpoint of {system} answered 200 without a usable "
                              "access_token")
    if kind is not None and (not isinstance(kind, str) or kind.lower() != "bearer"):
        raise Refused(CONFIG, f"the token endpoint of {system} issued a token that is not a "
                              "bearer token")
    return token, _lifetime(lifetime)


def _lifetime(stated: object) -> int | None:
    """`expires_in` in seconds: a non-negative integer, or its decimal text (some providers send
    "3599"). Anything else is no stated lifetime, so the token is not reused."""
    if isinstance(stated, str) and stated.isascii() and stated.isdigit():
        return int(stated)
    if isinstance(stated, int) and not isinstance(stated, bool) and stated >= 0:
        return stated
    return None


__all__ = ["MARKER", "AccessTokens", "CredentialSet", "check_fit", "scrub_secrets",
           "scrub_secret_bytes", "secret_values", "static_headers"]
