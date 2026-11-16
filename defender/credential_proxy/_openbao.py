"""OpenBao as the credential store and the token verifier (#1163 H11, O5, A4, A11, A25).

- Store: KV v2, one secret per (tenant, system, credential generation) at `<kv mount>/data/<tenant>/<system>/g<N>`, holding
  `{"kind": ..., "fields": {...}}`; a write replaces the whole set and moves the version on.
  The writer (`OpenBaoSecrets`, the API's) may create, update and read metadata only; the
  proxy (`OpenBaoStore`) may read data only (`store_policies`).
- Tokens: transit on the deployment's fixed mount (`configuration.issuer.TRANSIT_MOUNT`), one key
  per tenant (`transit_key_for`). The proxy may verify with any tenant's key and sign with none
  (`TransitVerifier`); each tenant's sign login signs with its own key only, under the deployment's
  templated `defender-tenant-sign` policy (operator-provisioned, A24'), and its signer is
  `credential_proxy.request_signer`.

A server that cannot be reached or answers 5xx is `TransportFault`; any other refusal is
`ConfigFault` (r7 A18). No message or repr holds a token or a credential value. The server's own
audit device records each credential write (A4)."""
from __future__ import annotations

import base64
import functools
import re
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from typing import Any, TypeVar

import httpx

from defender import tenancy
from defender.kit.internal_http import internal_async_client, internal_client, tls_trust
from defender.configuration.issuer import DEPLOYMENT_ISSUER, TRANSIT_MOUNT
from defender.kit.access import CREDENTIAL_KINDS
from defender.kit.faults import ORIGIN_ACCESS, ORIGIN_SETUP, AdapterFault, ConfigFault, TransportFault
from defender.kit.verbs import is_system_name
from defender.credential_proxy._credentials import CredentialSet
from defender.credential_proxy._deadline import current as current_deadline
from defender.credential_proxy._refusal import labelled

#: How long one call to OpenBao may take, in seconds.
OPENBAO_TIMEOUT_SEC = 10.0
#: The writer's pooled client holds at most this many connections: a systems page (up to 200 rows) asks about its rows
#: at once, and the rest wait for a free connection rather than each opening its own.
_POOL_LIMITS = httpx.Limits(max_connections=16, max_keepalive_connections=16)
#: A mount path: what may stand inside a policy's path string.
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})*")
#: Every tenant's transit key name starts so; the tenant id follows.
_KEY_PREFIX = "request-token-"


def transit_key_for(tenant_id: str) -> str:
    """The name of `tenant_id`'s transit key (A11): the one naming rule. A tenant id that is not a
    canonical tenant UUID is `ConfigFault`, so no key path is built from it (A26)."""
    _check_tenant(tenant_id)
    return f"{_KEY_PREFIX}{tenant_id}"


def _check_tenant(tenant_id: object) -> str:
    if not isinstance(tenant_id, str) or not tenancy.is_valid_tenant_id(tenant_id):
        raise ConfigFault("not a tenant id")
    return tenant_id


def _check_name(value: object, what: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise ConfigFault(f"{what} {value!r} is not a mount path or key name")
    return value


def _secret_path(tenant_id: object, system: object, generation: object) -> str:
    _check_tenant(tenant_id)
    if not isinstance(system, str) or not is_system_name(system):
        raise ConfigFault(f"{system!r} is not a system name")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise ConfigFault(f"{generation!r} is not a credential generation")
    return f"{tenant_id}/{system}/g{generation}"


#: The token's own lookup (`GET`): what a token of the API's may ask of OpenBao about itself (#1532 K1).
LOOKUP_SELF = "auth/token/lookup-self"


def store_policies(*, kv_mount: str) -> dict[str, str]:
    """The policy text for each of the product's two roles: `writer` (set a whole credential set,
    read metadata, look its own token up: the API's start check, #1532 K4) and `proxy` (read credential
    sets, verify with any tenant's key on the transit mount). Nothing grants list, delete, sign, key
    read or export; signing is the tenant sign login's templated policy (A25)."""
    kv = _check_name(kv_mount, "the KV mount")
    writer = (f'path "{kv}/data/*" {{\n  capabilities = ["create", "update"]\n}}\n'
              f'path "{kv}/metadata/*" {{\n  capabilities = ["read"]\n}}\n'
              f'path "{LOOKUP_SELF}" {{\n  capabilities = ["read"]\n}}\n')
    proxy = (f'path "{kv}/data/*" {{\n  capabilities = ["read"]\n}}\n'
             f'path "{TRANSIT_MOUNT}/verify/{_KEY_PREFIX}*" {{\n  capabilities = ["update"]\n}}\n')
    return {"writer": writer, "proxy": proxy}


def openbao_fault(status: int, detail: str) -> AdapterFault:
    """The fault for an OpenBao answer that is not the one asked for (r7 A18): a 5xx (sealed,
    standby, failing) may pass, so it is `TransportFault`; anything else is the operator's to
    fix, `ConfigFault`."""
    fault = TransportFault if status >= 500 else ConfigFault
    return fault(detail)


class SecretStoreFault(AdapterFault):
    """A write-only secret port call (`OpenBaoSecrets`) that did not get the answer it asked for (#1470). The writer
    states the write's outcome itself (r8 Am-1), so no caller re-derives it: `stored` is False when OpenBao certainly
    did nothing (it refused, answered sealed, or the request never left), None when it may have (the request went out
    and no answer came, or a 5xx that is not the sealed one). `status` is the HTTP status OpenBao answered (None: no
    answer), kept for the message. Raised as one of its two kinds, so a caller keyed on the fault class reads it as
    before."""

    def __init__(self, detail: str, *, status: int | None, stored: bool | None) -> None:
        super().__init__(detail)
        self.status = status
        self.stored = stored


class SecretStoreUnavailable(SecretStoreFault, TransportFault):
    """No usable answer: none, a 5xx one (sealed, standby, failing), or one that cannot be read. It may pass."""

    def __init__(self, detail: str, *, status: int | None, stored: bool | None) -> None:
        SecretStoreFault.__init__(self, detail, status=status, stored=stored)
        self.maybe_delivered = stored is None


class SecretStoreRefused(SecretStoreFault, ConfigFault):
    """A 4xx answer (a policy refusal, a bad request): the operator's to fix. OpenBao refuses before it writes, so
    nothing was stored. `forbidden` is the 403: this token, under its policy, may not make this call at this address;
    the token, its policy, the mount and the address can each be why (#1532 P1)."""

    def __init__(self, detail: str, *, status: int) -> None:
        super().__init__(detail, status=status, stored=False)

    @property
    def forbidden(self) -> bool:
        return self.status == 403  # noqa: PLR2004 — HTTP Forbidden


_R = TypeVar("_R")


def _our_access(call: Callable[..., _R]) -> Callable[..., _R]:
    """A proxy-only OpenBao call: a fault it raises with no label of its own is OpenBao being
    unreachable or refusing the proxy, our access as a whole (#1363 B3: labelled here, at the
    proxy's step, since `openbao_fault` is shared with the launcher and the API's secret writer)."""
    @functools.wraps(call)
    def labelled_call(*args: Any, **kwargs: Any) -> _R:
        try:
            return call(*args, **kwargs)
        except AdapterFault as fault:
            fault.origin = fault.origin or ORIGIN_ACCESS
            raise
    return labelled_call


class _Login:
    """One login to one OpenBao server: its address, mount and token (never shown), and the trust of the calls made on
    the event loop, built once here since building it blocks the loop (#1375 O1). It opens no connection: each kind of
    caller below opens its own."""

    def __init__(self, *, addr: str, token: str, mount: str) -> None:
        if not isinstance(addr, str) or not addr.startswith(("http://", "https://")):
            raise ConfigFault("the OpenBao address must be an http(s) URL")
        if not isinstance(token, str) or not token or not token.isprintable():
            raise ConfigFault("the OpenBao token must be non-empty text")
        self.addr = addr.rstrip("/")
        self.mount = _check_name(mount, "the mount")
        self._token = token
        self._loop_trust = tls_trust(DEPLOYMENT_ISSUER.ca_cert)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(addr={self.addr!r}, mount={self.mount!r})"

    __str__ = __repr__

    def _url(self, rest: str) -> str:
        return f"{self.addr}/v1/{self.mount}/{rest}"

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self._token}


class _OpenBao(_Login):
    """The proxy's calls to OpenBao: synchronous ones over one pooled connection, and those made inside a proxied
    request on the event loop, each on its own short-lived client. `transport` is a test's `httpx.MockTransport` (none:
    the network): it serves both."""

    def __init__(self, *, addr: str, token: str, mount: str,
                 transport: httpx.MockTransport | None = None) -> None:
        super().__init__(addr=addr, token=token, mount=mount)
        self._transport = transport
        #: One pooled connection for this login's calls made outside a proxied request.
        self._client = internal_client(trust=tls_trust(DEPLOYMENT_ISSUER.ca_cert),
                                       transport=transport, timeout=OPENBAO_TIMEOUT_SEC)

    def _call(self, method: str, rest: str, what: str, json: Any = None) -> httpx.Response:
        """One synchronous call; inside a proxied request, it runs under that request's deadline
        (#1364 O1), so a slow OpenBao cannot hold the proxy past it."""
        deadline = current_deadline()
        try:
            if deadline is None:
                return self._client.request(method, self._url(rest), json=json,
                                            headers=self._headers())
            return deadline.run(what, lambda: self._acall(method, rest, what, json))
        except httpx.HTTPError as e:
            raise TransportFault(f"OpenBao at {self.addr} is unreachable for {what} "
                                 f"({type(e).__name__})") from None

    async def _acall(self, method: str, rest: str, what: str, json: Any = None) -> httpx.Response:
        try:
            async with internal_async_client(trust=self._loop_trust, transport=self._transport,
                                             timeout=OPENBAO_TIMEOUT_SEC) as client:
                return await client.request(method, self._url(rest), json=json,
                                            headers=self._headers())
        except httpx.HTTPError as e:
            raise TransportFault(f"OpenBao at {self.addr} is unreachable for {what} "
                                 f"({type(e).__name__})") from None

    def _refused(self, reply: httpx.Response, what: str) -> AdapterFault:
        return openbao_fault(reply.status_code,
                             f"OpenBao at {self.addr} refused {what} ({reply.status_code})")


def _data_of(reply: httpx.Response) -> Mapping[str, Any]:
    try:
        doc = reply.json()
    except ValueError:
        doc = None
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, dict):
        raise ConfigFault(f"OpenBao answered {reply.status_code} without a data object")
    return data


class OpenBaoStore(_OpenBao):
    """The proxy's read of credential sets."""

    @_our_access
    def read(self, tenant_id: str, system: str, generation: int) -> CredentialSet | None:
        """`(tenant_id, system)`'s current set at `generation`, or None when there is none. A set
        missing its data or not in the store's shape is that system's setup (`setup`); the store
        failing to answer, or refusing the proxy, is its access."""
        path = _secret_path(tenant_id, system, generation)
        what = f"the credential read of {system}"
        reply = self._call("GET", f"data/{path}", what)
        if reply.status_code == 404:
            return None
        if reply.status_code != 200:
            raise self._refused(reply, what)
        try:
            data = _data_of(reply)
        except ConfigFault as fault:
            # `_data_of` is shared with the API's secret writer, so the label is set here, at the
            # proxy's step: a reply with no data object is this system's stored set unreadable.
            raise labelled(fault, ORIGIN_SETUP) from None
        body, meta = data.get("data"), data.get("metadata")
        if body is None:  # the current version is deleted
            return None
        if not (isinstance(body, dict) and set(body) == {"kind", "fields"}
                and body["kind"] in CREDENTIAL_KINDS and isinstance(body["fields"], dict)
                and isinstance(meta, dict) and isinstance(meta.get("version"), int)):
            raise labelled(ConfigFault(f"the stored credential set of {system} is not in the "
                                       "store's shape {kind, fields}"), ORIGIN_SETUP)
        return CredentialSet(kind=body["kind"], fields=dict(body["fields"]),
                             version=meta["version"])


class OpenBaoSecrets(_Login):
    """The write-only secret port (the API's, #1470 D-E; `tenant check`'s existence read): set a whole credential set
    with its kind at a credential generation, and ask whether one exists there. It cannot read a value back. A call
    that does not get its answer raises `SecretStoreFault` (`SecretStoreUnavailable` or `SecretStoreRefused`), stating
    whether anything was stored.

    Its calls are asynchronous. Inside `async with pooled():`, opened by the holder that owns the event loop (the API's
    `serving`, `tenant check`'s one run), they share that block's pooled client, which closes when the block ends; any
    other call opens a client of its own for that call. `transport` is any asynchronous transport (a test's scripted
    one, or none: the network)."""

    def __init__(self, *, addr: str, token: str, mount: str,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        super().__init__(addr=addr, token=token, mount=mount)
        self._transport = transport
        self._pool: httpx.AsyncClient | None = None

    def _opened(self, **limits: Any) -> httpx.AsyncClient:
        return internal_async_client(trust=self._loop_trust, transport=self._transport, timeout=OPENBAO_TIMEOUT_SEC,
                                     **limits)

    @asynccontextmanager
    async def pooled(self) -> AsyncIterator[None]:
        """Share one pooled client between this block's calls, all on the block's event loop; it closes as the block
        ends. Not reentrant: one holder opens it."""
        if self._pool is not None:
            raise RuntimeError("the secret writer's pooled client is already open")
        async with self._opened(limits=_POOL_LIMITS) as pool:
            self._pool = pool
            try:
                yield
            finally:
                self._pool = None

    async def _secret_call(self, method: str, rest: str, what: str, json: Any = None, *,
                           url: str | None = None) -> httpx.Response:
        """One call under the mount (`rest`), or at `url` when given."""
        url = url or self._url(rest)
        try:
            if self._pool is not None:
                return await self._pool.request(method, url, json=json, headers=self._headers())
            async with self._opened() as client:
                return await client.request(method, url, json=json, headers=self._headers())
        except httpx.HTTPError as e:
            # Never sent: no connection was made, or none came free in time (a pool timeout fires before sending).
            never_sent = isinstance(e, httpx.ConnectError | httpx.ConnectTimeout | httpx.PoolTimeout)
            raise SecretStoreUnavailable(f"OpenBao at {self.addr} is unreachable for {what} ({type(e).__name__})",
                                         status=None, stored=False if never_sent else None) from None

    def _secret_refused(self, reply: httpx.Response, what: str) -> SecretStoreFault:
        status = reply.status_code
        if status == 503 and _answers_sealed(reply):  # noqa: PLR2004 — a sealed OpenBao did nothing
            return SecretStoreUnavailable(f"OpenBao at {self.addr} is sealed ({what})", status=status, stored=False)
        detail = f"OpenBao at {self.addr} refused {what} ({status})"
        if status >= 500:  # noqa: PLR2004 — 5xx may pass (`openbao_fault`)
            return SecretStoreUnavailable(detail, status=status, stored=None)
        return SecretStoreRefused(detail, status=status)

    async def put_credentials(self, tenant_id: str, system_id: str, kind: str,
                              credentials: Mapping[str, str], *, generation: int) -> None:
        """Replace `(tenant_id, system_id)`'s whole set at `generation` with `credentials` of `kind`."""
        path = _secret_path(tenant_id, system_id, generation)
        if kind not in CREDENTIAL_KINDS:
            raise ConfigFault(f"a credential set's kind must be one of {list(CREDENTIAL_KINDS)}")
        if not credentials or not all(isinstance(k, str) and isinstance(v, str) and v
                                      for k, v in credentials.items()):
            raise ConfigFault("a credential set must map one or more names to non-empty text")
        what = f"the credential write of {system_id}"
        reply = await self._secret_call("POST", f"data/{path}", what,
                                        json={"data": {"kind": kind, "fields": dict(credentials)}})
        if reply.status_code not in (200, 204):
            raise self._secret_refused(reply, what)

    async def look_up_self(self) -> None:
        """OpenBao accepts this token at this address (lookup-self answered with its token's data). Its answer is not
        otherwise read. A 403 is `SecretStoreRefused`; no usable answer (none, a 5xx, sealed, or a 200 without a data
        object) is `SecretStoreUnavailable`. (#1532 K1, K3)"""
        what = "the token's lookup"
        reply = await self._secret_call("GET", "", what, url=f"{self.addr}/v1/{LOOKUP_SELF}")
        if reply.status_code != 200:
            raise self._secret_refused(reply, what)
        try:
            _data_of(reply)
        except ConfigFault:
            raise SecretStoreUnavailable(f"OpenBao at {self.addr} answered {what} without a data object",
                                         status=reply.status_code, stored=False) from None

    async def has_credentials(self, tenant_id: str, system_id: str, *, generation: int) -> bool:
        """Does `(tenant_id, system_id)` have a current set at `generation`? Asked of the metadata only. A 200 that is
        not KV metadata is no usable answer (`SecretStoreUnavailable`), like a 5xx."""
        path = _secret_path(tenant_id, system_id, generation)
        what = f"the credential existence check of {system_id}"
        reply = await self._secret_call("GET", f"metadata/{path}", what)
        if reply.status_code == 404:
            return False
        if reply.status_code != 200:
            raise self._secret_refused(reply, what)
        try:
            data = _data_of(reply)
        except ConfigFault:
            raise SecretStoreUnavailable(f"OpenBao at {self.addr} answered {what} without KV metadata",
                                         status=reply.status_code, stored=False) from None
        current = data.get("current_version")
        version = (data.get("versions") or {}).get(str(current))
        return (isinstance(current, int) and current > 0 and isinstance(version, dict)
                and not version.get("deletion_time") and not version.get("destroyed"))


def _answers_sealed(reply: httpx.Response) -> bool:
    """Is `reply` a sealed OpenBao's answer (`errors` naming "Vault is sealed")?"""
    try:
        doc = reply.json()
    except ValueError:
        return False
    errors = doc.get("errors") if isinstance(doc, dict) else None
    return isinstance(errors, list) and any(isinstance(e, str) and "Vault is sealed" in e for e in errors)


class TransitVerifier(_OpenBao):
    """The proxy's verifier: checks a token with the key of the tenant it names (A11), on the
    deployment's transit mount. It keeps no tenant list (A26): a tenant whose key is missing or
    destroyed (offboarded) is refused by OpenBao, `ConfigFault`."""

    def __init__(self, *, addr: str, token: str,
                 transport: httpx.MockTransport | None = None) -> None:
        super().__init__(addr=addr, token=token, mount=TRANSIT_MOUNT, transport=transport)

    @_our_access
    def verify(self, payload: bytes, signature: str, *, tenant_id: str) -> bool:
        key = transit_key_for(tenant_id)
        what = f"verifying with {key}"
        reply = self._call("POST", f"verify/{key}", what, json={
            "input": base64.b64encode(payload).decode("ascii"), "signature": signature})
        if reply.status_code != 200:
            raise self._refused(reply, what)
        valid = _data_of(reply).get("valid")
        if not isinstance(valid, bool):
            raise ConfigFault(f"OpenBao answered {what} without a verdict")
        return valid


__all__ = ["OpenBaoSecrets", "openbao_fault", "OpenBaoStore", "SecretStoreFault", "SecretStoreRefused",
           "SecretStoreUnavailable", "TransitVerifier", "store_policies", "transit_key_for"]
