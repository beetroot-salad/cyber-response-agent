"""Helpers for the learning-state cutover job's cases (#1278) — NO test functions, no policy.

Slice G's own world: the p4 published tenant (real clone, origin and forge fake) registered active in a migrated
database, the production `PostgresTenantRepository` over it, and a `HostActor` from `LifecycleWorld`'s fakes with the
cutover job's seam injected. It does not touch the shared lifecycle world's fixtures.

Interface requests the cases use (the code stage supplies them):
- `TenantRepository.request_learning_cutover(tenant_id)`: like `request_rotate`; an active tenant with nothing pending
  gets `pending_action="learning_cutover"`, step `import`, actor host; `Conflict`/`NotFound` otherwise.
- Steps (host actor), `NEXT["learning_cutover"]`: `import` -> `cutover` -> end. `import` takes the tenant's host lock
  exclusive and runs `import_learning_state`; `cutover` runs `cut_over_learning_state`. A refusal or fault fails the
  tenant's job at that step with the reason in `record.failure`; `request_resume` restarts at that step.
- `HostActor(..., open_delivery=<callable(tenant_id) -> TenantDelivery>)`: how the host reaches the tenant's forge and
  clone; the store is opened from `DEFENDER_DATABASE_DSN`.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld, lifecycle_config

ACTION = "learning_cutover"
DSN_ENV = "DEFENDER_DATABASE_DSN"


def learning_folder(t: Any) -> Path:
    return Path(location_path(t.tenant.tenant_root)) / "learning"


class CutoverWorld:
    """`.add(published)` registers a published tenant; `.request(tid)`, `.run()`, `.record(tid)`, `.resume(tid)`."""

    def __init__(self, tmp_path: Path, data_root: Path, dsn: str, monkeypatch: Any, **config: Any) -> None:
        from defender.tenancy.postgres import PostgresTenantRepository

        monkeypatch.setenv(DSN_ENV, dsn)
        self.dsn = dsn
        self.data_root = data_root
        self.lifecycle = LifecycleWorld(tmp_path / "lc", data_root)
        self.lifecycle.config = lifecycle_config(tmp_path / "lc", data_root, **config)
        self.repo = PostgresTenantRepository(dsn)
        self.tenants: dict[str, Any] = {}
        self.host = self.lifecycle.new_host(self.repo, open_delivery=lambda tid: self.tenants[str(tid)].open_delivery())

    def add(self, published: Any) -> SimpleNamespace:
        register_tenant(self.dsn, published.tenant_id)
        folder = learning_folder(published)
        folder.mkdir(parents=True, exist_ok=True)
        self.tenants[published.tenant_id] = published
        return SimpleNamespace(t=published, tid=published.tenant_id, root=folder, dsn=self.dsn)

    def request(self, tid: str) -> Any:
        return self.lifecycle.call(self.repo.request_learning_cutover, tid)

    def resume(self, tid: str) -> Any:
        return self.lifecycle.call(self.repo.request_resume, tid)

    def run(self) -> int:
        """One host pass: the number of steps run."""
        return int(self.lifecycle.call(self.host.work))

    def record(self, tid: str) -> Any:
        return self.lifecycle.call(self.repo.tenant, tid)

    def close(self) -> None:
        self.lifecycle.call(self.repo.close)
        self.lifecycle.close()
