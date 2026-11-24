"""The tenant fixture helper: the ONE place a test gets a data root and a tenant."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import contextlib
import importlib
import os
import shutil
from pathlib import Path
from typing import Any

#: The data-root knob. Spelled here rather than imported from `_tenant`, which exports no public
#: string constant (`lint_run_records` refuses importing one as a "record name").
DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"

#: The tenant this helper sets up by default.
D9_TENANT_ID = fixture_uuid("tenant:playground")

#: The committed fixture tenant — the knowledge every test tenant is set up from.
FIXTURE = Path(__file__).resolve().parents[5] / "defender" / "tests" / "fixtures" / "tenant-fixture"
DEFENDER = Path(__file__).resolve().parents[4]


def _tenant_owner():
    """`defender/tenancy/_tenant.py`, imported at CALL time so a missing name is one test's failure."""
    return importlib.import_module("defender.tenancy._tenant")


def current_data_root() -> Path:
    """The data root the autouse fixture pointed this test at — read off the environment the
    same way a production process is handed it, never recomputed."""
    raw = os.environ.get(DATA_ROOT_ENV)
    assert raw, (
        f"{DATA_ROOT_ENV} is not set in this test — the autouse `data_root` fixture in "
        "tests/conftest.py was removed or overridden; every test must run against its own root")
    return Path(raw)


def tenant_directory(root: Path, tenant_id: str, **keywords: Any) -> Any:
    """A `TenantDirectory` holding `tenant_id` ACTIVE with its forge wiring (#1214 Flow 4: host entry points
    take the tenant from the directory, not from `tenant.json`). Imported at CALL time -- the production
    names it needs exist only after #1214. `keywords` are `_active1214.active_directory`'s (`origin`, `repo`,
    `state`, `wiring`, `generations`: a minting call site seeds a generation, see `_active1214`); the origin defaults to the tenant clone's own `origin` remote when `<root>/<id>` is a
    clone, else `http://forge.test/tenants/<id>.git`."""
    from defender.tests.support.tenancy._active1214 import active_directory
    from defender.tests.support.tenancy._proxied1391 import sign_generation

    if keywords.get("wiring", True) and "generations" not in keywords:
        # A fixture tenant's elastic is proxied (#1391 P1/D12): run start needs a sign login.
        keywords["generations"] = [sign_generation(str(tenant_id))]
    return active_directory(Path(location_path(root)), str(tenant_id), **keywords)


class LazyDirectory:
    """`t.directory` on an object that cannot carry a real property (a frozen production `Tenant`): forwards
    every attribute to the `TenantDirectory` built on first use, so nothing imports #1214 code until a
    migrated call site reads `state(T)` / `forge_wiring(T)` off it. (Not an `isinstance` TenantDirectory.)"""

    def __init__(self, make: Any) -> None:
        self._make = make
        self._real: Any = None

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") or name in ("_make", "_real"):
            raise AttributeError(name)
        if self._real is None:
            self._real = self._make()
        return getattr(self._real, name)


class D9Tenant(str):
    """The id a test hands to `--tenant` (a `str`), with `.directory`: the current test's data root's
    directory holding it active (see `tenant_directory`). Built lazily, on each read."""

    @property
    def directory(self) -> Any:
        return tenant_directory(current_data_root(), str(self))


class KnowledgeFolder(type(Path())):  # type: ignore[misc]
    """`<root>/<id>/knowledge` as `place_tenant` returns it, with `.directory` for the tenant it belongs to."""

    @property
    def directory(self) -> Any:
        mapping = {"alert_mapping": self.alert_mapping} if hasattr(self, "alert_mapping") else {}  # #1345 (place_tenant)
        return tenant_directory(self.parent.parent, self.parent.name, **mapping)


def ensure_d9_tenant(tenant_id: str = D9_TENANT_ID) -> str:
    """Set `tenant_id` up in the current test's data root (`set_up_tenant`). Returns the id (a `D9Tenant`, a
    `str`), ready to hand to `--tenant`; a host entry call also passes `directory=<that id>.directory`
    (O6: the folder is on disk, the tenant only in `.directory`)."""
    set_up_tenant(current_data_root(), tenant_id)
    return D9Tenant(tenant_id)


def set_up_tenant(root: Path, tenant_id: str = D9_TENANT_ID, *, published: bool = False) -> Any:
    """`tenant_id` set up under the data root `root` the way an operator does and accepted: the
    committed fixture tenant copied to `<root>/<id>/knowledge` with its `agent/.tenant-id`
    (O6: no row is written; the tenant exists in `.directory`). Each step is skipped when already
    done. Returns the `Tenant` the real `accept_tenant` hands back.

    `published=True` (opt-in for branch-launch scenes): the placed content is also committed on `main` of the tenant's
    Forgejo repository, the data root's served remote (#1618: knowledge lives only there;
    `_fetch_standin_1618.seed_placed`), so a source stamped through `_triplet_947.provenance_record` names a commit
    Forgejo serves, which a fetch can copy and pin.

    `.directory` on the returned `Tenant` (#1214): a `LazyDirectory` over `tenant_directory(root, id)`, the
    tenant active with its forge wiring; a migrated call site passes `directory=t.directory`."""
    owner = _tenant_owner()
    root = Path(location_path(root))
    knowledge = root / tenant_id / "knowledge"
    on_its_remote = False
    if not knowledge.exists():
        from defender.tests.support.tenancy._fetch_standin_1618 import served_remote

        # Already set up with its knowledge on its Forgejo repository only (`_spec1224.Estate.place`, a published
        # scene): placing the fixture here would be committed over that `main` by the next fetch's seeding.
        on_its_remote = (served_remote(root, tenant_id) / "HEAD").exists()
    if not knowledge.exists() and not on_its_remote:
        shutil.copytree(FIXTURE, knowledge, symlinks=True)
        (knowledge / "agent" / ".tenant-id").write_text(f"{tenant_id}\n", encoding="utf-8")
    if published:
        from defender.tests.support.tenancy._fetch_standin_1618 import seed_placed

        seed_placed(root, tenant_id)
    accepted = owner.accept_tenant(fixture_data_root(root), tenant_id, defender_dir=DEFENDER)
    # a frozen dataclass without slots still takes an instance attribute; eq and hash use the fields only
    with contextlib.suppress(AttributeError, TypeError):
        object.__setattr__(accepted, "directory", LazyDirectory(lambda: tenant_directory(root, tenant_id)))
    return accepted
