"""Request tokens (#1163 O8, A11): who may use which systems' credentials, until when.

Wire form: `<payload>.<signature>`, where `<payload>` is base64url (no padding) of a JSON object
with exactly `tenant` (tenant id), `investigation` (the run id, #1081), `grant` (a list of
`[system, "r" | "rw"]`, sorted) and `exp` (expiry, Unix seconds). The signer signs the payload's
ASCII bytes, and the verifier is handed those same bytes: the claims are read only once the
signature over them is valid, and with the key of the tenant they name (A11). The token names no
commit: the proxy always applies `current` (P-2)."""
from __future__ import annotations

import base64
import binascii
import json
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from defender import tenancy
from defender.kit.access import RequestAccess
from defender.kit.faults import AdapterFault, ConfigFault
from defender.kit.verbs import is_system_name

READ = "r"
READ_WRITE = "rw"
MODES = (READ, READ_WRITE)
_CLAIM_KEYS = frozenset({"tenant", "investigation", "grant", "exp"})
_PAYLOAD = re.compile(r"[A-Za-z0-9_-]+")
#: A token longer than this is not one the minter writes: refused before any decoding.
MAX_TOKEN_CHARS = 16384
_MAX_INVESTIGATION_CHARS = 128


class TokenSigner(Protocol):
    """The launcher's transit-sign port: the signature over `payload`."""

    def sign(self, payload: bytes) -> str: ...


class TokenVerifier(Protocol):
    """The proxy's transit-verify port: is `signature` valid over `payload` under the key of
    `tenant_id`? A store it cannot reach is `ConfigFault`, never a verdict."""

    def verify(self, payload: bytes, signature: str, *, tenant_id: str) -> bool: ...


@dataclass(frozen=True)
class Claims:
    """A token's claims: `grant` maps each granted system to its mode."""

    tenant: str
    investigation: str
    grant: Mapping[str, str]
    exp: int


def mint_request_token(signer: TokenSigner, *, tenant_id: str, investigation: str,
                       grant: Iterable[tuple[str, str]], expires_at: datetime) -> str:
    """A token for `tenant_id`'s run `investigation`, granting each `(system, "r" | "rw")` of
    `grant` until `expires_at` (aware), signed by `signer`. Any claim out of shape (a system
    name outside the grammar included, or a system granted twice) is `ConfigFault` and nothing
    is signed."""
    if not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
        raise ConfigFault("a request token's expiry must be an aware datetime")
    doc: dict[str, Any] = {"tenant": tenant_id, "investigation": investigation,
           "grant": [list(entry) for entry in grant], "exp": int(expires_at.timestamp())}
    _claims_of(doc)
    doc["grant"] = sorted(doc["grant"])
    payload = base64.urlsafe_b64encode(
        json.dumps(doc, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"{payload}.{signer.sign(payload.encode('ascii'))}"


def run_token_mint(signer: TokenSigner, *, tenant_id: str,
                   investigation: str) -> Callable[[Iterable[tuple[str, str]], float], str]:
    """The one way a process signs its run's tokens, read and write-back alike: `mint(grant,
    expires_at)` signs `grant` for `tenant_id`'s run `investigation` until `expires_at`, in
    seconds of the caller's clock."""

    def mint(grant: Iterable[tuple[str, str]], expires_at: float) -> str:
        return mint_request_token(signer, tenant_id=tenant_id, investigation=investigation,
                                  grant=grant, expires_at=datetime.fromtimestamp(expires_at, UTC))

    return mint


def request_access(signer: TokenSigner, proxy_url: str, *, tenant_id: str, investigation: str,
                reads: Iterable[str], clock: Callable[[], float] = time.time,
                on_fault: Callable[[AdapterFault], None] | None = None) -> RequestAccess:
    """The one holder of a process's read token (#1363 O1, B1), built the same way by a run, a
    sibling run and a pre-flight pass: `r` on each system of `reads`, for `investigation`, signed
    by `signer` (`run_token_mint`) when first needed and re-signed by the holder's one rule.
    Building it signs nothing. `on_fault` is its owner's callback (see `RequestAccess`)."""
    grant = {(system, "r") for system in reads}
    mint = run_token_mint(signer, tenant_id=tenant_id, investigation=investigation)
    return RequestAccess(proxy_url, lambda expires_at: mint(grant, expires_at), clock=clock,
                         on_fault=on_fault)


def split_token(token: str) -> tuple[bytes, str, Claims]:
    """`(signed payload, signature, unverified claims)` of a token in the wire form, or
    `ConfigFault`. The claims are not to be trusted until the signature is verified over the
    payload with the claimed tenant's key."""
    if len(token) > MAX_TOKEN_CHARS:
        raise ConfigFault("the request token is too long to be one")
    payload, dot, signature = token.partition(".")
    if not dot or not signature or not _PAYLOAD.fullmatch(payload):
        raise ConfigFault("the request token is not in the token wire form")
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        doc = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise ConfigFault("the request token's claims do not decode") from None
    if not isinstance(doc, dict):
        raise ConfigFault("the request token's claims are not an object")
    return payload.encode("ascii"), signature, _claims_of(doc)


def _claims_of(doc: Any) -> Claims:  # noqa: C901 — one flat shape check
    if not isinstance(doc, dict) or set(doc) != _CLAIM_KEYS:
        raise ConfigFault(f"request token claims must be exactly {sorted(_CLAIM_KEYS)}")
    tenant, investigation, grant, exp = (doc["tenant"], doc["investigation"], doc["grant"],
                                         doc["exp"])
    if not isinstance(tenant, str) or not tenancy.is_valid_tenant_id(tenant):
        raise ConfigFault("a request token must name one tenant id")
    if (not isinstance(investigation, str) or not investigation
            or len(investigation) > _MAX_INVESTIGATION_CHARS):
        raise ConfigFault("a request token must name one investigation")
    if isinstance(exp, bool) or not isinstance(exp, int):
        raise ConfigFault("a request token's expiry must be whole Unix seconds")
    if not isinstance(grant, list):
        raise ConfigFault("a request token's grant must be a list of [system, mode]")
    granted: dict[str, str] = {}
    for entry in grant:
        if not (isinstance(entry, list) and len(entry) == 2
                and all(isinstance(part, str) for part in entry)):
            raise ConfigFault("a request token's grant must be a list of [system, mode]")
        system, mode = entry
        if not is_system_name(system):
            raise ConfigFault(f"a request token may not grant {system!r}: not a system name")
        if mode not in MODES:
            raise ConfigFault(f"a request token grants {system} with mode {mode!r}, not one of "
                              f"{list(MODES)}")
        if system in granted:
            raise ConfigFault(f"a request token grants {system} twice")
        granted[system] = mode
    return Claims(tenant=tenant, investigation=investigation, grant=granted, exp=exp)


__all__ = ["MODES", "READ", "READ_WRITE", "Claims", "TokenSigner", "TokenVerifier",
           "mint_request_token", "run_token_mint", "split_token"]
