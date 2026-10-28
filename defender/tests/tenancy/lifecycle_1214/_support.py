"""#1214 sketch world — NO test functions. The API (over #1306's identity world) and the two lifecycle
actors over ONE in-memory tenant repository, the boundary fakes of `_fakes`, one clock and a data root.

Production names #1214 must supply are imported in the one block below, so a missing name is one
ImportError (the expected red before implementation). Pinned shapes (sketch report, "Pinned interface"):
- `defender.tenancy.InMemoryTenantRepository()`; `defender.tenancy.postgres.PostgresTenantRepository(dsn)`;
  reads `await tenant(T)` (detached record: state, pending_action, step, step_actor, failure, repo_url,
  offboarded_at, repo_delete_after), `await generations(T)`, `await forge_wiring(T)`; `await close()`.
- `defender.tenancy.TenantDirectory(open_repository)`: sync; `.state(T) -> str | None`.
- `InMemoryIdentityRepository(tenants=<InMemoryTenantRepository>)` (the twins share one tenant store);
  `Bootstrap(administrators=...)` (no tenants section, Q3); `ApiDeps(..., tenants=<repository>)`.
- `defender.lifecycle.ManagementService(tenants, *, identity, forge, openbao, integration, git, clock)`
  and `HostActor(tenants, *, data_root, openbao, git, publish, clock)`; each `await work() -> int`:
  for every tenant it may take up, it runs steps while the current step is its own (until handed
  over, failed or done), and returns the count of steps run.
- Step names (Flow 1): provider, repo, bot, integration, template, install, sweep, prepare, activate.
- Generation fields: salt, status, bot_login, oidc_role, approle, entity, audience,
  host_secret_file (Path), secret_accessor.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import uuid
from pathlib import Path
from typing import Any

from defender.api.app import create_app
from defender.api.fakes import InMemorySecrets, StubArtifactLinks, StubSystemChecker
from defender.api.ports import ApiDeps
from defender.tests.support.api._identity1306 import FRONTEND_ORIGIN, NEW, OPS, World, items
from defender.tests.tenancy.lifecycle_1214._fakes import (
    FakeForge,
    FakeIntegrationCommand,
    FakeOpenBao,
    RecordingPublish,
    RoutedGit,
)

# Production names #1214 must supply. Kept in this one block so a missing package is one ImportError.
from defender.identity import Bootstrap, IdentityService, InMemoryIdentityRepository  # noqa: E402
from defender.lifecycle import HostActor, ManagementService  # noqa: E402
from defender.tenancy import InMemoryTenantRepository, TenantDirectory  # noqa: E402,F401

#: Offboarding keeps the archived repo this long (Q5).
REPO_WINDOW = _dt.timedelta(days=30)
#: Audit actions #1214 adds on `defender.identity.audit` (K11).
CREATE, RESUME, OFFBOARD, ROTATE, REPO_DELETE = (
    "tenant.create", "tenant.resume", "tenant.offboard", "tenant.rotate", "tenant.repo.delete")


class LifecycleWorld(World):
    """#1306's world with the tenant repository wired into the API, the identity repository sharing
    its tenant store, `ops` as administrator, and both lifecycle actors over the fakes."""

    def __init__(self, tmp_path: Path, data_root: Path) -> None:
        self.tenants: Any = InMemoryTenantRepository()
        self.data_root = data_root
        self.forge = FakeForge(tmp_path / "forge")
        self.integration = FakeIntegrationCommand(self.forge)
        self.openbao = FakeOpenBao()
        self.git = RoutedGit(self.forge)
        self.publish = RecordingPublish()
        super().__init__(administrators=[OPS], start=False)
        self.call(self.service.start)
        self.send_pending()
        self.ops = self.sign_in_admin()
        self.service_actor = ManagementService(
            self.tenants, identity=self.service, forge=self.forge.client(), openbao=self.openbao.client(),
            integration=self.integration, git=self.git, clock=self.clock)
        self.host_actor = HostActor(
            self.tenants, data_root=data_root, openbao=self.openbao.client("host-token"), git=self.git,
            publish=self.publish, clock=self.clock)

    def build(self, *, administrators: Any, tenants: Any) -> None:
        assert not tenants, "#1214 Q3: the bootstrap file names no tenants"
        if not getattr(self, "_shared", False):
            self.repo = InMemoryIdentityRepository(tenants=self.tenants)
            self._shared = True
        self.service = IdentityService(self.repo, signin=self.signin, mail=self.mail, clock=self.clock,
                                       bootstrap=Bootstrap(administrators=tuple(administrators)))
        self.app = create_app(ApiDeps(
            alerts=self.store, investigations=self.store, learning_jobs=self.store,
            lessons=self.store, systems=self.store, writes=self.store,
            secrets=InMemorySecrets(), checker=StubSystemChecker(), artifact_links=StubArtifactLinks(),
            identity=self.service, frontend_origin=FRONTEND_ORIGIN, tenants=self.tenants,
        ))

    # --- the job --------------------------------------------------------------------------

    def drive(self, *, limit: int = 60) -> int:
        """Alternate the two actors until neither has a step to take; the number of steps run."""
        total = 0
        for _ in range(limit):
            ran = self.call(self.service_actor.work) + self.call(self.host_actor.work)
            if ran == 0:
                return total
            total += ran
        raise AssertionError(f"the job did not settle within {limit} rounds")

    def create(self) -> str:
        """`POST /admin/tenants` as `ops`; the minted id (asserted 202)."""
        made = self.ops.post("/admin/tenants", json={})
        assert made.status_code == 202, made.text
        return made.json()["tenant_id"]

    def active_tenant(self) -> str:
        tenant = self.create()
        self.drive()
        assert self.item(tenant)["state"] == "active", self.item(tenant)
        return tenant

    def item(self, tenant: str) -> dict[str, Any]:
        got = self.ops.get(f"/admin/tenants/{tenant}")
        assert got.status_code == 200, got.text
        return got.json()

    def record(self, tenant: str) -> Any:
        return self.call(self.tenants.tenant, tenant)

    def generations(self, tenant: str) -> list[Any]:
        return self.call(self.tenants.generations, tenant)

    def live(self, tenant: str) -> Any:
        [live] = [g for g in self.generations(tenant) if g.status == "live"]
        return live

    def member_of(self, tenant: str, email: str = NEW) -> Any:
        """`email` invited by `ops`, sent, signed in and accepted: an active member's browser."""
        invited = self.ops.post(f"/admin/tenants/{tenant}/invitations", json={"email": email})
        assert invited.status_code == 202, invited.text
        self.send_pending()
        browser = self.sign_in(email)
        accepted = browser.post(f"/invitations/{invited.json()['id']}/accept")
        assert accepted.status_code == 200, accepted.text
        return browser

    def directory(self) -> Any:
        """The host's synchronous view of this world's tenant repository."""
        return TenantDirectory(lambda: self.tenants)


def tenant_ids(response: Any) -> list[str]:
    return [i["tenant_id"] for i in items(response)]


def is_uuid4(text: str) -> bool:
    try:
        return uuid.UUID(text).version == 4 and str(uuid.UUID(text)) == text
    except ValueError:
        return False


def as_dict(row: Any) -> dict[str, Any]:
    return dataclasses.asdict(row) if dataclasses.is_dataclass(row) else dict(vars(row))
