"""D9's tenant fixture helper (#1078 pass A) — the ONE place a test gets a data root and a tenant."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import importlib
import os
import shutil
from pathlib import Path
from typing import Any

#: The data-root knob #1078 adds (D2). Spelled here rather than imported from `_tenant`: the
#: design deliberately exports no public string constant from the owner module (J05 — a public
#: `str` there is an import-refused "record name" under `lint_run_records`' import arm).
DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"

#: The one tenant D9's helper creates (no test uses two tenants — D9, N12).
D9_TENANT_ID = fixture_uuid("tenant:playground")

#: The committed fixture tenant (#1120 H2) — the knowledge every test tenant is set up from.
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


def ensure_d9_tenant(tenant_id: str = D9_TENANT_ID) -> str:
    """Set `tenant_id` up in the current test's data root (`set_up_tenant`), unless its row is
    already there. Returns the id, ready to hand to `--tenant`."""
    set_up_tenant(current_data_root(), tenant_id)
    return tenant_id


#: `tenant_id` -> a published fixture tenant's folder, built once per process (`_published_copy`).
_PUBLISHED: dict[str, Path] = {}
_PUBLISHED_HOME: list[Any] = []


def _published_copy(tenant_id: str) -> Path:
    """`<process scratch>/<n>/root/<tenant_id>`: the committed fixture tenant set up as
    `tenant_id` and published for real ONCE per process through S0's one helper
    (`tenant_1108_p4._support.published_tenant`: a git clone, a real export, `exports/current`),
    its origin server closed after — reading or materialising a published tenant needs no
    network. Callers copy the folder in; nothing in it names its root."""
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
    """`tenant_id` set up under the data root `root` the way an operator does (#1120 DC2) and
    accepted: the committed fixture tenant (`knowledge/tenant-fixture/`) copied to
    `<root>/<id>/knowledge` with its `agent/.tenant-id`, then the row minted by the REAL
    `create_tenant` (D10: "evals and fixtures call `create_tenant` directly, each against a
    fresh tmp root"). Each step is skipped when already done, so a second call is the first
    one's tenant. Returns the `Tenant` the real `accept_tenant` hands back.

    `published=True` (#1108 P4, opt-in for branch-launch scenes): the tenant is instead the
    same fixture content as a REAL published tenant — clone, export, `exports/current` — so a
    source stamped through `_triplet_947.provenance_record` names a commit its clone holds and
    flow 7 can materialise and pin it. Asking for it over a tenant already set up unpublished
    is a fixture bug, refused."""
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
    if not (root / tenant_id / "tenant.json").is_file():
        owner.create_tenant(fixture_data_root(root), tenant_id)
    return owner.accept_tenant(fixture_data_root(root), tenant_id, defender_dir=DEFENDER)
