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
FIXTURE = Path(__file__).resolve().parents[5] / "knowledge" / "tenant-fixture"
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
        return tenant_directory(self.parent.parent, self.parent.name)


def ensure_d9_tenant(tenant_id: str = D9_TENANT_ID) -> str:
    """Set `tenant_id` up in the current test's data root (`set_up_tenant`). Returns the id (a `D9Tenant`, a
    `str`), ready to hand to `--tenant`; a host entry call also passes `directory=<that id>.directory`
    (O6: the folder is on disk, the tenant only in `.directory`)."""
    set_up_tenant(current_data_root(), tenant_id)
    return D9Tenant(tenant_id)


#: `tenant_id` -> a published fixture tenant's folder, built once per process (`_published_copy`).
_PUBLISHED: dict[str, Path] = {}
_PUBLISHED_HOME: list[Any] = []


def _published_copy(tenant_id: str) -> Path:
    """`<process scratch>/<n>/root/<tenant_id>`: the committed fixture tenant set up as
    `tenant_id` and published for real ONCE per process through
    `tenant_1108_p4._support.published_tenant` (a git clone, a real export, `exports/current`),
    its origin server closed after: reading a published tenant needs no network. Callers copy
    the folder in; nothing in it names its root."""
    if tenant_id in _PUBLISHED:
        return _PUBLISHED[tenant_id]
    import tempfile

    from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

    if not _PUBLISHED_HOME:
        _PUBLISHED_HOME.append(tempfile.TemporaryDirectory(prefix="d9-published-tenants-"))
    home = Path(_PUBLISHED_HOME[0].name) / str(len(_PUBLISHED))
    with published_tenant(home / "forge", root=home / "root", tenant_id=tenant_id):
        pass
    _PUBLISHED[tenant_id] = home / "root" / tenant_id
    return _PUBLISHED[tenant_id]


def set_up_tenant(root: Path, tenant_id: str = D9_TENANT_ID, *, published: bool = False) -> Any:
    """`tenant_id` set up under the data root `root` the way an operator does and accepted: the
    committed fixture tenant copied to `<root>/<id>/knowledge` with its `agent/.tenant-id`
    (O6: no row is written; the tenant exists in `.directory`). Each step is skipped when already
    done. Returns the `Tenant` the real `accept_tenant` hands back.

    `published=True` (opt-in for branch-launch scenes): the same content as a REAL published
    tenant (clone, export, `exports/current`), so a source stamped through
    `_triplet_947.provenance_record` names a commit its clone holds and can be materialised and
    pinned. Asking for it over a tenant already set up unpublished is a fixture bug, refused.

    `.directory` on the returned `Tenant` (#1214): a `LazyDirectory` over `tenant_directory(root, id)`, the
    tenant active with its forge wiring; a migrated call site passes `directory=t.directory`."""
    owner = _tenant_owner()
    root = Path(location_path(root))
    if published:
        folder = root / tenant_id
        if not folder.exists():
            shutil.copytree(_published_copy(tenant_id), folder, symlinks=True)
        assert (folder / "exports" / "current").is_file(), (
            f"fixture bug: tenant {tenant_id} under {root} was already set up UNPUBLISHED; ask "
            "for `published=True` at its first set-up")
    knowledge = root / tenant_id / "knowledge"
    if not knowledge.exists():
        shutil.copytree(FIXTURE, knowledge, symlinks=True)
        (knowledge / "agent" / ".tenant-id").write_text(f"{tenant_id}\n", encoding="utf-8")
    accepted = owner.accept_tenant(fixture_data_root(root), tenant_id, defender_dir=DEFENDER)
    # a frozen dataclass without slots still takes an instance attribute; eq and hash use the fields only
    with contextlib.suppress(AttributeError, TypeError):
        object.__setattr__(accepted, "directory", LazyDirectory(lambda: tenant_directory(root, tenant_id)))
    return accepted
