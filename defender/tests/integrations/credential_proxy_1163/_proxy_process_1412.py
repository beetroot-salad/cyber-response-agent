"""#1412 O1: the real proxy under uvicorn in its own process over fake ports, so its memory can be
read apart from the test's. A gauge route reports allocations and how many requests overlapped."""
from __future__ import annotations

import json
import sys
import tracemalloc
from pathlib import Path
from typing import Any

import uvicorn

from defender.credential_proxy import CredentialSet, ProxyDeps, create_app
from defender.tests.integrations.credential_proxy_1163 import _harness as H

GAUGE_PATH = "/__gauge"


class _Gauged:
    """Forwards to the proxy unchanged. `GET /__gauge` answers the gauge's readings; `?reset`
    first restarts the allocation peak."""

    def __init__(self, app: Any, audit: H.AuditRecorder) -> None:
        self.app, self.audit = app, audit
        self.live = self.live_peak = 0

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["path"] == GAUGE_PATH:
            return await self._answer(scope, send)
        self.live += 1
        self.live_peak = max(self.live_peak, self.live)
        try:
            await self.app(scope, receive, send)
        finally:
            self.live -= 1

    async def _answer(self, scope: Any, send: Any) -> None:
        if scope["query_string"] == b"reset" and tracemalloc.is_tracing():
            tracemalloc.reset_peak()
        now, peak = tracemalloc.get_traced_memory()
        body = json.dumps({"traced_now": now, "traced_peak": peak, "live_peak": self.live_peak,
                           "audited": len(self.audit.records)}).encode()
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})


def main(data_root: str, tenant: str, port: str, trace: str) -> None:
    audit = H.AuditRecorder()
    store = H.FakeStore({(tenant, "identity"): CredentialSet(
        kind="static", fields={"api_key": H.CANARY_KEY}, version=1)})
    app = create_app(ProxyDeps(data_root=Path(data_root), store=store, verifier=H.FakeVerifier(),
                               audit=audit))
    if trace == "trace":
        tracemalloc.start()
    uvicorn.run(_Gauged(app, audit), host="127.0.0.1", port=int(port), log_level="warning")


if __name__ == "__main__":
    main(*sys.argv[1:])
