"""#1214 lifecycle world (r9) — NO test functions. The API (over #1306's identity world) and the two
lifecycle actors over ONE in-memory tenant repository, the boundary fakes of `_fakes`, one clock and a data root.

Production names #1214 must supply are imported in the one block below, so a missing name is one
ImportError (the expected red before implementation). Pinned shapes (amendment r9, "Pinned interface"):
- `defender.tenancy.InMemoryTenantRepository()` (+ seeder `add_tenant`); reads `tenant(T)`, `tenants()`,
  `generations(T)`, `forge_wiring(T)`; `defender.tenancy.TenantDirectory(open_repository)`.
- `InMemoryIdentityRepository(tenants=<twin>)`, `Bootstrap(administrators=...)`, `ApiDeps(..., tenants=)`.
- `defender.lifecycle.ManagementService(tenants, *, identity, forge, openbao, integration, git, config, clock)`
  and `HostActor(tenants, *, openbao_login, git, publish, config, clock)`; the host has NO management client
  (DC-12): `openbao_login` is `openbao.client(None)` (no management token), and it gets the AppRole `role_id`
  from the generation. Each `await work() -> int` is one pass (DC-14).
- `LifecycleConfig(...)`: NOT pinned field by field (GAP-0-2). Built in ONE place, `lifecycle_config`, with the
  DC-13 items under the keyword names used there; if the implementer names them differently, fix that one function.
- Step names (DC-3): create `names provider repo bot integration template wrap install sweep prepare activate`;
  rotate `names provider bot integration wrap install sweep retire remove_old_file`; offboard `offboard teardown
  finish`; `delete_repo`.

Interface for the cases (all on `LifecycleWorld(tmp_path, data_root)`):
`.create() -> T`, `.active_tenant() -> T`, `.item(T)`, `.record(T)`, `.generations(T)`, `.live(T)`,
`.member_of(T, email)`, `.directory()`, `.tenants` (twin), `.fakes` and its aliases `.forge .integration .openbao
.git .publish`, `.config`, `.service_actor`, `.host_actor`, `.ops` (administrator browser),
`.service_pass()` / `.host_pass()` (one `work()` each, the step count), `.drive(limit=, stop=)`
(alternate service pass, host pass until neither ran a step or `stop()` is true between passes),
`.new_service(tenants=None, identity=None, **fakes)` / `.new_host(...)` (another actor over the same fakes, e.g. over a
second repository), `lifecycle_config(tmp_path, data_root, **overrides)`, `tenant_ids`, `is_uuid4`, `as_dict`.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender.tests.support.api._identity1306 import NEW, OPS, World, items
from defender.tests.tenancy.lifecycle_1214._fakes import FORGE_URL, OPENBAO_URL, Fakes

# Production names #1214 must supply. Kept in this one block so a missing package is one ImportError.
from defender.lifecycle import HostActor, LifecycleConfig, ManagementService  # noqa: E402
from defender.tenancy import InMemoryTenantRepository, TenantDirectory, template_dir  # noqa: E402,F401

#: Offboarding keeps the archived repo this long (Q5).
REPO_WINDOW = _dt.timedelta(days=30)
#: Audit actions #1214 adds on `defender.identity.audit` (K11).
CREATE, RESUME, OFFBOARD, ROTATE, REPO_DELETE = (
    "tenant.create", "tenant.resume", "tenant.offboard", "tenant.rotate", "tenant.repo.delete")


REPO_ROOT = Path(__file__).resolve().parents[4]


def lifecycle_config(tmp_path: Path, data_root: Path, **overrides: Any) -> Any:
    """The one `LifecycleConfig` of the tests (DC-13): https issuer, forge and OpenBao addresses of the fakes,
    the real template directory, a per-test secrets directory OUTSIDE `<data root>/<T>/`, a short poll."""
    fields: dict[str, Any] = {
        "issuer_url": "https://openbao.test:8200/v1/identity/oidc",
        "forge_url": FORGE_URL, "forge_admin_token": "forge-admin-token",
        "openbao_url": OPENBAO_URL, "openbao_login": "bao-management-token",
        "integration_command": "forgejo-test", "template_dir": template_dir(REPO_ROOT),
        "secrets_dir": tmp_path / "secrets", "data_root": data_root, "poll_interval": 0.01,
    }
    return LifecycleConfig(**{**fields, **overrides})


class LifecycleWorld(World):
    """#1306's world with the tenant repository wired into the API, the identity repository sharing
    its tenant store, `ops` as administrator, and both lifecycle actors over the fakes."""

    def __init__(self, tmp_path: Path, data_root: Path) -> None:
        self.data_root = data_root
        self.tmp_path = tmp_path
        self.fakes = Fakes(tmp_path)
        self.forge, self.integration, self.openbao = self.fakes.forge, self.fakes.integration, self.fakes.openbao
        self.git, self.publish = self.fakes.git, self.fakes.publish
        self.config = lifecycle_config(tmp_path, data_root)
        super().__init__(administrators=[OPS], start=False)
        self.call(self.service.start)
        self.send_pending()
        self.ops = self.sign_in_admin()
        self.service_actor = self.new_service(self.tenants, identity=self.service)
        self.host_actor = self.new_host(self.tenants)

    def new_service(self, tenants: Any, *, identity: Any, **overrides: Any) -> Any:
        """A management service over `tenants` and this world's fakes; `overrides` replace a fake or `config`/`clock`."""
        parts: dict[str, Any] = {
            "forge": self.forge.client(), "openbao": self.openbao.client(), "integration": self.integration,
            "git": self.git, "config": self.config, "clock": self.clock, **overrides}
        return ManagementService(tenants, identity=identity, **parts)

    def new_host(self, tenants: Any, **overrides: Any) -> Any:
        """A host actor over `tenants`: NO management client, only the login client (DC-12)."""
        parts: dict[str, Any] = {
            "openbao_login": self.openbao.client(None), "git": self.git, "publish": self.publish,
            "config": self.config, "clock": self.clock, **overrides}
        return HostActor(tenants, **parts)

    # --- the job --------------------------------------------------------------------------

    def service_pass(self) -> int:
        return int(self.call(self.service_actor.work))

    def host_pass(self) -> int:
        return int(self.call(self.host_actor.work))

    def drive(self, *, limit: int = 60, stop: Callable[[], bool] | None = None) -> int:
        """Alternate service and host passes until neither ran a step (or `stop()` is true between passes);
        the number of steps run."""
        total = 0
        for _ in range(limit):
            ran = 0
            for run_pass in (self.service_pass, self.host_pass):
                ran += run_pass()
                if stop is not None and stop():
                    return total + ran
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
