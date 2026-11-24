"""#1214 lifecycle world (r9) — NO test functions. The API (over #1306's identity world) and the two
lifecycle actors over ONE in-memory tenant repository, the boundary fakes of `_fakes`, one clock and a data root.

Production names #1214 must supply are imported in the one block below, so a missing name is one
ImportError (the expected red before implementation). Pinned shapes (amendment r9, "Pinned interface"):
- `defender.tenancy.InMemoryTenantRepository()` (+ seeder `add_tenant`); reads `tenant(T)`, `tenants()`,
  `generations(T)`, `forge_wiring(T)`; `defender.tenancy.TenantDirectory(open_repository)`.
- `InMemoryIdentityRepository(tenants=<twin>)`, `Bootstrap(administrators=...)`, `ApiDeps(..., tenants=)`.
- `defender.lifecycle.ManagementService(tenants, *, identity, forge, openbao, integration, git, config, clock)`
  and `HostActor(tenants, *, forge, openbao_login, git, fetch, config, clock)` (#1618: `fetch=` replaced `publish=`); `forge` has no credential (F-1); the host has NO management client
  (DC-12): `openbao_login` is `openbao.client(None)` (no management token), and it gets the AppRole `role_id`
  from the generation. Each `await work() -> int` is one pass (DC-14).
- `LifecycleConfig(...)`: NOT pinned field by field (GAP-0-2). Built in ONE place, `lifecycle_config`, with the
  DC-13 items under the keyword names used there; if the implementer names them differently, fix that one function.
- Step names (DC-3): create `names provider repo bot integration template wrap install sweep prepare activate`;
  rotate `names provider bot protect integration wrap install sweep retire remove_old_file` (r8.3); offboard `offboard teardown
  finish`; `delete_repo`.

Interface for the cases (all on `LifecycleWorld(tmp_path, data_root)`):
`.create() -> T`, `.active_tenant() -> T`, `.item(T)`, `.record(T)`, `.generations(T)`, `.live(T)`,
`.member_of(T, email)`, `.directory()`, `.tenants` (twin), `.fakes` and its aliases `.forge .integration .openbao
.git`, `.fetch` (the host actor's fetch seam), `.config`, `.service_actor`, `.host_actor`, `.ops` (administrator browser),
`.forge.bearer_calls()` / `.admin_token_calls()` (who presented what), `.service_pass()` / `.host_pass()` (one `work()` each, the step count), `.drive(limit=, stop=)`
(alternate service pass, host pass until neither ran a step or `stop()` is true between passes),
`.new_service(tenants=None, identity=None, **fakes)` / `.new_host(...)` (another actor over the same fakes, e.g. over a
second repository), `lifecycle_config(tmp_path, data_root, **overrides)`, `tenant_ids`, `is_uuid4`, `as_dict`.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import uuid
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from defender.tests.support.api._mount1161 import API
from defender.tests.support.api._identity1306 import NEW, OPS, World, items, tenants_of
from defender.tests.tenancy.lifecycle_1214._fakes import FORGE_URL, ISSUER_URL, OPENBAO_URL, Fakes

# Production names #1214 must supply. Kept in this one block so a missing package is one ImportError.
from defender.lifecycle import HostActor, LifecycleConfig, ManagementService  # noqa: E402
from defender.tenancy import InMemoryTenantRepository, TenantDirectory, template_dir  # noqa: E402,F401

#: Offboarding keeps the archived repo this long (Q5).
REPO_WINDOW = _dt.timedelta(days=30)
#: Audit actions #1214 adds on `defender.identity.audit` (K11).
CREATE, RESUME, OFFBOARD, ROTATE, REPO_DELETE = (
    "tenant.create", "tenant.resume", "tenant.offboard", "tenant.rotate", "tenant.repo.delete")


REPO_ROOT = Path(__file__).resolve().parents[4]


KEYCLOAK_SOURCE_ID = 7
FORGE_SESSIONS_DSN = "postgresql://fs_lifecycle_login@sessions.test:5432/forgejo_sessions"
#: The forge as a browser reaches it (required since the #1592 finalize): the fakes' forge, as the tests' browser has it.
FORGE_PUBLIC_URL = FORGE_URL


def people_settings(settings: Any, sessions_dsn: str = FORGE_SESSIONS_DSN) -> list[tuple[str, str]]:
    """The settings #1592 makes required (r15 Settings: `keycloak_source_id`, `forge_sessions_dsn`; finalize:
    `forge_public_url`), as the environment variables a process-entry case sets. The default DSN is unreachable: a case
    that starts the real `_serve` and never reaches the sessions database needs no more."""
    return [(settings.KEYCLOAK_SOURCE_ID_ENV, str(KEYCLOAK_SOURCE_ID)), (settings.FORGE_SESSIONS_DSN_ENV, sessions_dsn),
            (settings.FORGE_PUBLIC_URL_ENV, FORGE_PUBLIC_URL)]


def lifecycle_config(tmp_path: Path, data_root: Path, **overrides: Any) -> Any:
    """The one `LifecycleConfig` of the tests (DC-13): https issuer, forge and OpenBao addresses of the fakes,
    the real template directory, a per-test secrets directory OUTSIDE `<data root>/<T>/`, a short poll, and the two
    r9-pinned defaults spelled out (`lock_keepalive` seconds, `teardown_wait` seconds before SIGKILL, F-11)."""
    fields: dict[str, Any] = {
        "issuer_url": ISSUER_URL,
        "forge_url": FORGE_URL, "forge_admin_token": "forge-admin-token",
        "openbao_url": OPENBAO_URL, "openbao_login": "bao-management-token",
        "integration_command": "forgejo-test", "template_dir": template_dir(REPO_ROOT),
        "secrets_dir": tmp_path / "secrets", "data_root": data_root, "poll_interval": 0.01, "lock_keepalive": 30, "teardown_wait": 5.0,
        # #1592: the two required fields of the people worker (OD-4, OD-12): the Keycloak login source's id and the
        # login of a member of `fs_lifecycle` on the sessions database (no test reaches it unless it says so).
        "keycloak_source_id": KEYCLOAK_SOURCE_ID, "forge_sessions_dsn": FORGE_SESSIONS_DSN,
        "forge_public_url": FORGE_PUBLIC_URL,
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
        self.git = self.fakes.git  # #1618: no `publish` seam (prepare fetches: `self.fetch`, made with the host actor)
        self.config = lifecycle_config(tmp_path, data_root)
        super().__init__(administrators=[OPS], start=False, database=True)  # #1496: offboarding is the real store's
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
        """A host actor over `tenants`: NO management client, only the login client (DC-12), and a forge client
        with NO credential (F-1: install presents the bot's own Bearer per request)."""
        from defender.tests.tenancy.lifecycle_1214._fetch_1618 import fetch_seam_of

        # #1618 (flow 5, FORCED `HostActor(..., fetch=)` in place of `publish=`): prepare reads through the REAL fetch child
        # over the forge fake's bare repositories (`_fetch_1618`), for every lifecycle world.
        parts: dict[str, Any] = {
            "forge": self.forge.client(None), "openbao_login": self.openbao.client(None), "git": self.git,
            "fetch": fetch_seam_of(self), "config": self.config, "clock": self.clock, **overrides}
        return HostActor(tenants, **parts)

    def close(self) -> None:
        listener = getattr(self, "git_listener", None)
        if listener is not None:
            listener.close()
            self.git_listener = None
        super().close()

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
        made = self.ops.post(API + "/admin/tenants", json={})
        assert made.status_code == 202, made.text
        return made.json()["tenant_id"]

    def active_tenant(self) -> str:
        tenant = self.create()
        self.drive()
        assert self.item(tenant)["state"] == "active", self.item(tenant)
        return tenant

    def item(self, tenant: str) -> dict[str, Any]:
        got = self.ops.get(f"{API}/admin/tenants/{tenant}")
        assert got.status_code == 200, got.text
        return got.json()

    def record(self, tenant: str) -> Any:
        return self.call(self.tenants.tenant, tenant)

    def generations(self, tenant: str) -> list[Any]:
        return self.call(self.tenants.generations, tenant)

    def set_generation(self, tenant: str, status: str, **fields: Any) -> None:
        """Overwrite columns of the tenant's `status` generation row in place, as a damaged or older row would read
        (test support, by SQL: no repository writes a generation's fields after the fact)."""
        from defender.tests.support.shared._postgres1339 import execute

        assert self.dsn is not None
        assert fields
        names = ", ".join(f"{name} = %s" for name in fields)
        values = tuple(str(v) if isinstance(v, Path) else v for v in fields.values())
        execute(self.dsn, f"UPDATE tenancy.generations SET {names} WHERE tenant_id = %s AND status = %s",  # noqa: S608 — test-owned names
                (*values, tenant, status))

    def live(self, tenant: str) -> Any:
        [live] = [g for g in self.generations(tenant) if g.status == "live"]
        return live

    def member_of(self, tenant: str, email: str = NEW) -> Any:
        """`email` invited by `ops`, sent and signed in (the first sign-in accepts, #1306): an active
        member's browser."""
        invited = self.ops.post(f"{API}/admin/tenants/{tenant}/invitations", json={"email": email})
        assert invited.status_code == 202, invited.text
        self.send_pending()
        browser = self.sign_in(email)
        assert tenant in tenants_of(browser), "the first sign-in did not make an active member"
        return browser

    def directory(self) -> Any:
        """The host's synchronous view of this world's tenant repository."""
        return TenantDirectory(lambda: self.tenants)


class _NoStore:
    """Where no test server is configured: offboarding's store call, which has nothing to purge."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    async def offboard(self, tenant: str, *, wait: float) -> None:
        return None

    async def close(self) -> None:
        return None


@contextmanager
def learning_database(monkeypatch: Any) -> Iterator[None]:
    """The lifecycle world's learning database (#1278 O6): offboarding purges the tenant's learning rows and refuses where
    `DEFENDER_DATABASE_DSN` is unset. A migrated database of its own where the test server is configured, else a store
    stand-in that purges nothing. A case that tests the unset refusal deletes the variable itself."""
    from defender.tests.support.shared import _postgres1339 as pg

    if os.environ.get(pg.DSN_ENV):
        with pg.database(migrated=True) as dsn:
            monkeypatch.setenv("DEFENDER_DATABASE_DSN", dsn)
            yield
        return
    import defender.learning_store as store

    monkeypatch.setattr(store, "LearningStore", _NoStore)  # lint-monkeypatch: ok — the host actor imports the store inside its offboarding step; no seam carries one in
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", "postgresql://stand-in/none")
    yield


def tenant_ids(response: Any) -> list[str]:
    return [i["tenant_id"] for i in items(response)]


def is_uuid4(text: str) -> bool:
    try:
        return uuid.UUID(text).version == 4 and str(uuid.UUID(text)) == text
    except ValueError:
        return False


def as_dict(row: Any) -> dict[str, Any]:
    return dataclasses.asdict(row) if dataclasses.is_dataclass(row) else dict(vars(row))
