"""Fixtures for the chaos control-plane spec (issue #401).

Nothing here touches the live stack or docker. Every fixture is either a real
file already committed in this repo (hosts/inventory.yaml, detection-rules/*.json,
cmdb/app.py) or a tmp dir. Everything that would otherwise need
`docker --context soc-playground exec` goes through the injected exec seam in
`_fakes.FakeExecSeam`.

The CMDB-stub fixtures import the real FastAPI app, whose deps the devcontainer's
bare python3 does not carry. Run the suite with:

    flock /tmp/defender-pytest.lock uv run --no-project --python 3.12 \
        --with 'fastapi==0.115.*' --with pyyaml --with httpx --with pytest \
        -m pytest playground-v2/chaos/tests

(fastapi is pinned to the version cmdb/Dockerfile installs. The flock is the
machine-wide pytest lock every pytest invocation on this box goes through —
ad-hoc subsets included — so this suite never runs alongside another
session's xdist fleet.)
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest
import yaml

# playground-v2/chaos/tests/conftest.py -> playground-v2/
PLAYGROUND_ROOT = Path(__file__).resolve().parents[2]

# `chaos` is the package under test; it lives at playground-v2/chaos/. pytest's
# prepend importmode only puts this tests/ dir on sys.path, not its grandparent.
if str(PLAYGROUND_ROOT) not in sys.path:
    sys.path.insert(0, str(PLAYGROUND_ROOT))

UV_HINT = (
    "needs the CMDB stub's runtime deps; run: flock /tmp/defender-pytest.lock "
    "uv run --no-project --python 3.12 "
    "--with 'fastapi==0.115.*' --with pyyaml --with httpx --with pytest "
    "-m pytest playground-v2/chaos/tests"
)


@pytest.fixture(scope="session")
def playground_root() -> Path:
    return PLAYGROUND_ROOT


@pytest.fixture(scope="session")
def rules_dir(playground_root: Path) -> Path:
    """The real detection-rules dir the O4 guard (M3) reads at activate time."""
    d = playground_root / "detection-rules"
    assert d.is_dir(), f"missing {d}"
    return d


@pytest.fixture(scope="session")
def inventory_path(playground_root: Path) -> Path:
    """The real CMDB source of truth — baked into the container at build time."""
    p = playground_root / "hosts" / "inventory.yaml"
    assert p.is_file(), f"missing {p}"
    return p


@pytest.fixture(scope="session")
def inventory_text(inventory_path: Path) -> str:
    return inventory_path.read_text()


@pytest.fixture(scope="session")
def inventory(inventory_text: str) -> dict:
    return yaml.safe_load(inventory_text)


@pytest.fixture(scope="session")
def inventory_host_names(inventory: dict) -> list[str]:
    return [h["name"] for h in inventory["hosts"]]


@pytest.fixture
def profiles_dir(tmp_path: Path) -> Path:
    """Where `chaos/profiles/*.yaml` live. Tests write their own — the three
    day-one profiles are implementation, not spec."""
    d = tmp_path / "profiles"
    d.mkdir()
    return d


@pytest.fixture
def ledger_dir(tmp_path: Path) -> Path:
    """Stand-in for the gitignored `chaos/ledger/` the scorer reads (O5)."""
    d = tmp_path / "ledger"
    d.mkdir()
    return d


@pytest.fixture
def cmdb_app(inventory_path: Path):
    """The real playground-v2/cmdb/app.py module, inventory pointed at the repo copy.

    INVENTORY_PATH is resolved from the environment at import time, so the env var
    is set before the module is executed and the module is loaded off-path (never
    registered in sys.modules) so each test gets a clean BASE/OVERLAY.
    """
    pytest.importorskip("fastapi", reason=UV_HINT)
    app_path = inventory_path.parent.parent / "cmdb" / "app.py"
    assert app_path.is_file(), f"missing {app_path}"

    previous = os.environ.get("CMDB_INVENTORY_PATH")
    os.environ["CMDB_INVENTORY_PATH"] = str(inventory_path)
    try:
        spec = importlib.util.spec_from_file_location("playground_cmdb_app", app_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.OVERLAY.clear()
        module._load_inventory()
        yield module
    finally:
        if previous is None:
            os.environ.pop("CMDB_INVENTORY_PATH", None)
        else:
            os.environ["CMDB_INVENTORY_PATH"] = previous


@pytest.fixture
def cmdb_client(cmdb_app):
    """TestClient against the real stub. Entered as a context manager so the
    lifespan (_load_inventory) actually runs."""
    pytest.importorskip("httpx", reason=UV_HINT)
    from fastapi.testclient import TestClient

    with TestClient(cmdb_app.app) as client:
        yield client
