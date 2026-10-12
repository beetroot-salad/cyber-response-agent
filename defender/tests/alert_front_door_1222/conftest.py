"""#1222 suite fixtures: the configured roots a scenario must never share with the host.

`tests/conftest.py` already gives every test its own `DEFENDER_DATA_ROOT` (the tenant, its runs
base and its knowledge live there; `_spec1222.plant_tenant` places tenants under it). Two more
roots are read from configuration by surfaces this suite drives:

* the learning-state root (`DEFENDER_LEARNING_STATE_DIR`) — the judge's enqueue, the curation
  enqueue and the lesson author's queue read and write under it, by default inside the checkout;
* the launcher's episodes root (`DEFENDER_EPISODES_BASE`, no default: `cli.episodes_root` refuses
  an unset one).

Both are pointed under the test's own `tmp_path` for every test in this directory (the
`live_oracle_1224/conftest.py` shape), so no scenario passes or fails on the ambient
environment and none writes outside its tmp dir. `monkeypatch.setenv` only — never `setattr`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests import _triplet_947 as T


@pytest.fixture(autouse=True)
def _configured_roots_1222(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "episodes-root"
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(root))
    T.isolate_learning_state(tmp_path, monkeypatch)
    return root
