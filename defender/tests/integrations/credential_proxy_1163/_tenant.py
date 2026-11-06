"""#1163: a published tenant whose `identity` system is reached through the proxy, and the
proxy's dependencies over it. Built on #1108 P4's real publish; plants data only."""
from __future__ import annotations

import base64
import contextlib
import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163._target import proxy
from defender.tests.tenancy.tenant_1108_p4._support import (
    OTHER_TENANT_ID,
    PublishedTenant,
    export_dir,
    published_tenant,
)

#: The investigation (run id, #1081) every sketch token names.
RUN_ID = "0b8f6a52-1163-4c1e-9d0e-6f2b3a4c5d6e"


@contextlib.contextmanager
def identity_via_proxy(scratch: Path, root: Path, decl: str,
                       **kw: Any) -> Iterator[PublishedTenant]:
    """The fixture tenant with `identity` on `http-proxy`, declared by `decl`, published once."""
    files = H.access_files("identity", decl, env=H.HTTP_PROXY_IDENTITY_ENV)
    with published_tenant(scratch, root=root, files=files, **kw) as t:
        yield t


def exports_of(t: PublishedTenant) -> Path:
    """`<T>/exports/`: what the proxy is told it reads for this tenant."""
    return export_dir(t.tenant, t.commit).parent


def run_record(t: PublishedTenant) -> Any:
    """The run's record over the first export's settings, as run start resolves it."""
    from defender.systems.run_tenant import run_tenant_for

    return run_tenant_for(t.tenant, dispatches_lead_zero=False,
                          settings_root=export_dir(t.tenant, t.commit) / "settings")


def static_set(key: str = H.CANARY_KEY, version: int = 1) -> Any:
    return proxy().CredentialSet(kind="static", fields={"api_key": key}, version=version)


def custom_set(fields: Mapping[str, str], version: int = 1) -> Any:
    return proxy().CredentialSet(kind="static", fields=dict(fields), version=version)


def basic_set(user: str = "svc-reader", password: str = H.CANARY_KEY, version: int = 1) -> Any:
    return proxy().CredentialSet(kind="static", fields={"username": user, "password": password},
                                 version=version)


def oauth_set(secret: str = H.CANARY_SECRET, version: int = 1) -> Any:
    return proxy().CredentialSet(
        kind="oauth-client-credentials",
        fields={"client_id": H.CLIENT_ID, "client_secret": secret}, version=version)


def data_root_of(tenants: Mapping[str, Path]) -> Path:
    """The one data root the exports folders in `tenants` ({tenant id: `<root>/<id>/exports`})
    sit under. The proxy keeps no tenant list (A26), so a caller's mapping only says which
    root; a folder anywhere else, or two roots, is a broken fixture."""
    roots = {Path(folder).parent.parent for folder in tenants.values()}
    assert len(roots) == 1, tenants
    root = roots.pop()
    assert all(Path(folder) == root / tid / "exports" for tid, folder in tenants.items()), tenants
    return root


def deps(tenants: Mapping[str, Path] | Path, store: Any, *, verifier: Any = None,
         audit: Any = None, **extra: Any) -> Any:
    """`ProxyDeps` over a data root: `tenants` is the root itself or the `{id: exports}` mapping
    of tenants under it; `extra` keywords (e.g. `max_response_bytes`) pass through."""
    root = tenants if isinstance(tenants, Path) else data_root_of(tenants)
    return proxy().ProxyDeps(data_root=root, store=store,
                             verifier=verifier if verifier is not None else H.FakeVerifier(),
                             audit=audit if audit is not None else H.AuditRecorder(), **extra)


def forged_token(signer: Any, base_token: str, tenant_id: str) -> str:
    """`base_token` with its tenant claim replaced by `tenant_id` and the new payload signed by
    `signer`: the token a launcher would never mint (minting refuses a bad id), for a proxy that
    must not trust the claim. Wire form `<base64url(JSON claims)>.<signature>` (a sketch gap)."""
    claims = H.claims_of(base_token) | {"tenant": tenant_id}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{payload}.{signer.sign(payload.encode('ascii'))}"


def token(tenant_id: str, grant: set[tuple[str, str]], *, signer: Any = None,
          expires_in: timedelta = timedelta(hours=1), investigation: str = RUN_ID) -> str:
    return proxy().mint_request_token(
        signer if signer is not None else H.FakeSigner(), tenant_id=tenant_id,
        investigation=investigation, grant=grant, expires_at=datetime.now(UTC) + expires_in)


def post(client: Any, tok: str, system: str, method: str, url: str,
         body: Any = None, headers: Mapping[str, str] | None = None,
         timeout_sec: float | None = None) -> Any:
    """One request to the proxy as the http-proxy transport makes it; the HTTP response.
    `body` is the request body text (or None); `timeout_sec` the system's own timeout (r7 A21),
    left out when None."""
    from defender.tests.integrations.credential_proxy_1163._target import PROXY_PATH

    response = client.post(PROXY_PATH, headers={"Authorization": f"Bearer {tok}"},
                           json={"system": system, "method": method, "url": url,
                                 "headers": dict(headers or {}), "body": body}
                           | ({} if timeout_sec is None else {"timeout_sec": timeout_sec}))
    assert response.status_code == 200, response.text
    return response


FINAL_FIELDS = ("status", "headers", "fault", "detail", "system_side", "sent", "body_whole", "reader_fault")


def fields_of(final: Any) -> dict[str, Any]:
    """A `FinalRecord`'s fields, read by attribute as the design says."""
    return {name: getattr(final, name) for name in FINAL_FIELDS}


def answer_of(raw: bytes) -> dict[str, Any]:
    """The final record of the proxy's framed reply `raw` as a dict, with `body` added as the run
    reads it: the body frames' text when the record says the body counts, else empty (#1412)."""
    from defender._proxy_client import decode_reply

    reply = decode_reply(raw)
    final = fields_of(reply.final)
    whole = final["body_whole"] is True
    return {**final, "body": b"".join(reply.chunks).decode("utf-8", "replace") if whole else ""}


def ask(client: Any, tok: str, system: str, method: str, url: str,
        body: Any = None, headers: Mapping[str, str] | None = None,
        timeout_sec: float | None = None) -> dict[str, Any]:
    """`post`, read as `answer_of`."""
    return answer_of(post(client, tok, system, method, url, body, headers, timeout_sec).content)


GRANT_R = {("identity", "r")}
#: The path every rig declaration puts its base at: a non-root base (r5 A2).
BASE_PATH = "/api/v2"


@dataclass
class Rig:
    """One published tenant (`identity` on the proxy), a recording upstream, and the proxy over
    a fake store, audit sink and a verifier that accepts only what `signer` signed."""

    t: PublishedTenant
    up: H.Upstream
    store: H.FakeStore
    audit: Any
    signer: H.FakeSigner
    verifier: Any
    client: Any
    data_root: Path
    ghosts: dict[str, Path] = field(default_factory=dict)

    def tok(self, grant: set[tuple[str, str]] | None = None, **kw: Any) -> str:
        return token(self.t.tenant_id, GRANT_R if grant is None else grant,
                     signer=self.signer, **kw)

    def post(self, method: str = "GET", path: str = "/users/x", *, system: str = "identity",  # noqa: PLR0913 — one request's parts
             grant: set[tuple[str, str]] | None = None, tok: str | None = None,
             url: str | None = None, body: str | None = None,
             headers: Mapping[str, str] | None = None,
             timeout_sec: float | None = None) -> Any:
        """`method` on `path` relative to the declared base (or the absolute `url`), with a
        token granting `grant` (read on identity unless given) unless `tok` is given; the HTTP
        response."""
        return post(self.client, self.tok(grant) if tok is None else tok, system, method,
                    url if url is not None else f"{self.up.url}{BASE_PATH}{path}", body, headers,
                    timeout_sec)

    def ask(self, *args: Any, **kw: Any) -> dict[str, Any]:
        """`post`, read as `answer_of`."""
        return answer_of(self.post(*args, **kw).content)

    def rebuild(self, **deps_kw: Any) -> None:
        """A new proxy app over the same fakes with other `ProxyDeps` options."""
        self.client = client_of(deps(self.data_root, self.store, verifier=self.verifier,
                                     audit=self.audit, **deps_kw))


def client_of(d: Any) -> Any:
    from fastapi.testclient import TestClient

    return TestClient(proxy().create_app(d))


@contextlib.contextmanager
def rig(scratch: Path, root: Path, decl: Callable[[str], str] | None = None, *,
        creds: Any = "static", ghosts: Mapping[str, Path] | None = None,
        audit: Any = None, store: Any = None, **deps_kw: Any) -> Iterator[Rig]:
    """A `Rig`. `decl(upstream_url)` is the merged declaration text (default: a bearer key on
    the upstream's `BASE_PATH`); `creds` is the credential set stored for `identity` (default a
    static key; None stores none); `ghosts` names tenant ids that get an (empty) `exports/` folder
    under the data root, whatever path is given (A26: the proxy is told no tenant list); `store`
    replaces the store port outright."""
    with H.upstream() as up:
        text = decl(up.url) if decl is not None else H.declaration(up.url + BASE_PATH)
        with identity_via_proxy(scratch, root, text) as t:
            if store is None:
                store = H.FakeStore({(t.tenant_id, "identity"): static_set() if creds == "static"
                                     else creds} if creds is not None else {})
            signer = H.FakeSigner()
            verifier = H.PairedVerifier(signer)
            sink = H.AuditRecorder() if audit is None else audit
            for ghost in ghosts or {}:
                (root / ghost / "exports").mkdir(parents=True)
            client = client_of(deps(root, store, verifier=verifier, audit=sink, **deps_kw))
            yield Rig(t, up, store, sink, signer, verifier, client, root, dict(ghosts or {}))


def crm_files(base: str) -> dict[str, str]:
    """Repo files making `crm` an http-proxy system with a bearer-key declaration at `base`."""
    return H.access_files("crm", H.declaration(base), env=H.http_proxy_env("crm"))


@contextlib.contextmanager
def crm_pair(scratch: Path, root: Path, base_a: str, base_b: str) -> Iterator[tuple[Any, Any]]:
    """Two tenants under one data root, each declaring `crm` (A at `base_a`, B at `base_b`)."""
    with published_tenant(scratch / "a", root=root, repo_name="a",
                          files=crm_files(base_a)) as a, \
            published_tenant(scratch / "b", root=root, tenant_id=OTHER_TENANT_ID,
                             repo_name="b", files=crm_files(base_b)) as b:
        yield a, b
