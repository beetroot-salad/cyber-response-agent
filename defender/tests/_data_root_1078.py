"""D9's tenant fixture helper (#1078 pass A) — the ONE place a test gets a data root and a tenant.

#1078 moves every run under `<data root>/<tenant>/runs/` and makes the tenant a required,
pre-existing thing: `DEFENDER_DATA_ROOT` has NO default (§7 J01, "NO DEFAULT DATA ROOT" — an
unset variable is refused, naming it), a fresh run needs `--tenant <id>`, and the tenant exists
only once `create_tenant` has written its row. So a test that drives a run needs two things it
never needed before: a data root it owns, and a tenant created in it.

* THE DATA ROOT is the autouse `data_root` fixture in `tests/conftest.py` (§7 J57(b): an autouse
  fixture, overriding D9's "a fixture helper… not an autouse one"). Every test, whether it asks
  or not, runs with `DEFENDER_DATA_ROOT` pointed at its own fresh tmp directory, so no test can
  reach a host data root and none shares one with another test or another xdist worker (J58).
  It only SETS THE VARIABLE — it calls nothing new, so it is inert against code that does not
  read the variable yet.
* THE TENANT is created ON REQUEST, by `ensure_d9_tenant()` here (or the `d9_tenant` fixture in
  conftest, which calls it). Never autouse: `create_tenant` is the implementation under test,
  and an autouse call to it would turn every test in the repo into one failure about it.

`D9_TENANT_ID` is a TEST value. Production code holds no tenant literal (O1's census scans
`defender/**/*.py` minus the tests); the docs name `playground` as the operator's first tenant,
and the tests use the same id so a fixture tenant reads like the documented one.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import importlib
import os
from pathlib import Path

#: The data-root knob #1078 adds (D2). Spelled here rather than imported from `_tenant`: the
#: design deliberately exports no public string constant from the owner module (J05 — a public
#: `str` there is an import-refused "record name" under `lint_run_records`' import arm).
DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"

#: The one tenant D9's helper creates (no test uses two tenants — D9, N12).
D9_TENANT_ID = "playground"


def _tenant_owner():
    """`defender/_tenant.py`, imported at CALL time so a missing name is one test's failure."""
    return importlib.import_module("defender._tenant")


def current_data_root() -> Path:
    """The data root the autouse fixture pointed this test at — read off the environment the
    same way a production process is handed it, never recomputed."""
    raw = os.environ.get(DATA_ROOT_ENV)
    assert raw, (
        f"{DATA_ROOT_ENV} is not set in this test — the autouse `data_root` fixture in "
        "tests/conftest.py was removed or overridden; every test must run against its own root")
    return Path(raw)


def ensure_d9_tenant(tenant_id: str = D9_TENANT_ID) -> str:
    """Create `tenant_id` in the current test's data root through the REAL `create_tenant`
    (D10: "evals and fixtures call `create_tenant` directly, each against a fresh tmp root"),
    unless its row is already there. Returns the id, ready to hand to `--tenant`."""
    owner = _tenant_owner()
    root = current_data_root()
    if not (root / tenant_id / "tenant.json").is_file():
        owner.create_tenant(root, tenant_id)
    return tenant_id
