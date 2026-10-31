"""#1163: a published tenant whose `identity` system is reached through the proxy, and the
proxy's dependencies over it. Built on #1108 P4's real publish; plants data only."""
from __future__ import annotations

import contextlib
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163._target import proxy
from defender.tests.tenancy.tenant_1108_p4._support import (
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


def deps(tenants: Mapping[str, Path], store: Any, *, verifier: Any = None,
         audit: Any = None) -> Any:
    return proxy().ProxyDeps(tenant_exports=dict(tenants), store=store,
                             verifier=verifier if verifier is not None else H.FakeVerifier(),
                             audit=audit if audit is not None else H.AuditRecorder())


def token(tenant_id: str, grant: set[tuple[str, str]], *, signer: Any = None,
          expires_in: timedelta = timedelta(hours=1), investigation: str = RUN_ID) -> str:
    return proxy().mint_request_token(
        signer if signer is not None else H.FakeSigner(), tenant_id=tenant_id,
        investigation=investigation, grant=grant, expires_at=datetime.now(UTC) + expires_in)


def ask(client: Any, tok: str, system: str, method: str, url: str,
        body: Any = None) -> dict[str, Any]:
    """One request to the proxy as the http-proxy transport makes it; the proxy's JSON answer."""
    from defender.tests.integrations.credential_proxy_1163._target import PROXY_PATH

    response = client.post(PROXY_PATH, headers={"Authorization": f"Bearer {tok}"},
                           json={"system": system, "method": method, "url": url,
                                 "headers": {}, "body": body})
    assert response.status_code == 200, response.text
    return response.json()
