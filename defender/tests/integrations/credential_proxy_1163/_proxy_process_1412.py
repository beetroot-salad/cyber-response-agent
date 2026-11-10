"""#1412 O1: the real proxy under uvicorn in its own process over fake ports, so its memory can be
read apart from the test's. A gauge route reports allocations and how many requests overlapped."""
from __future__ import annotations

import asyncio
import sys
import tracemalloc
from pathlib import Path
from typing import Any

import uvicorn

from defender.credential_proxy import CredentialSet, ProxyDeps, create_app
from defender.credential_proxy._connections import DeliveryLimited
from defender.tests.integrations.credential_proxy_1163 import _harness as H

GAUGE_PATH = H.GAUGE_PATH


class _Gauged:
    """Forwards to the proxy unchanged. `GET /__gauge` answers allocations, overlap and worker
    threads lent out (now, and the peak a 5 ms sampler saw); `?reset` restarts the allocation peak."""

    def __init__(self, app: Any, audit: H.AuditRecorder) -> None:
        self.app, self.audit = app, audit
        self.live = self.live_peak = self.borrowed_peak = 0
        self.sampler: asyncio.Task[None] | None = None

    async def _sample(self) -> None:
        while True:
            self.borrowed_peak = max(self.borrowed_peak, H.borrowed_threads())
            await asyncio.sleep(0.005)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["path"] == GAUGE_PATH:
            return await self._answer(scope, send)
        if self.sampler is None:
            self.sampler = asyncio.create_task(self._sample())
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
        await H.answer_gauge(send, {
            "traced_now": now, "traced_peak": peak, "live_peak": self.live_peak,
            "borrowed": H.borrowed_threads(), "total_tokens": H.thread_limit(),
            "borrowed_peak": self.borrowed_peak,
            "audited": len(self.audit.records)})


def main(data_root: str, tenant: str, port: str, trace: str) -> None:
    audit = H.AuditRecorder()
    store = H.FakeStore({(tenant, "identity"): CredentialSet(
        kind="static", fields={"api_key": H.CANARY_KEY}, version=1)})
    from defender.tests.support.tenancy import _systems1366 as R

    app = create_app(ProxyDeps(records=R.ExportRecords(Path(data_root)), store=R.GenerationBlind(store),
                               verifier=H.FakeVerifier(),
                               audit=audit))
    if trace == "trace":
        tracemalloc.start()
    uvicorn.run(_Gauged(app, audit), host="127.0.0.1", port=int(port), log_level="warning",
                http=DeliveryLimited)


if __name__ == "__main__":
    main(*sys.argv[1:])
