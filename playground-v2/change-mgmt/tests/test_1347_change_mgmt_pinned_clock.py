"""#1347 r6.4 O3 (re-covered per A10): the change-mgmt stub answers with its clock pinned at the
freeze moment T and its wall-clock refresh off.

Seams bound by this contract (within the app's conventions: env vars read when `app.py` loads,
like `STANDING_REFRESH_SECONDS`):

* `V2_STUB_AS_OF` (ISO instant, = T): the app's clock is that instant for every use of "now" - standing
  CR materialization, `/changes/active` without `at`, and the `created`/`updated` stamps (`_now()`).
* `STANDING_REFRESH_SECONDS=0`: no refresh loop is started (today 0 would spin).

Run: defender-pytest uv run --no-project --python 3.12 --with 'fastapi==0.115.*'
--with pyyaml --with httpx --with pytest -m pytest playground-v2/change-mgmt/tests
"""
from __future__ import annotations

import importlib.util
import re
import sys
import time
from datetime import datetime, timedelta, UTC
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

APP = Path(__file__).resolve().parents[1] / "app.py"
SEED = APP.parent / "seed"
AS_OF = datetime(2026, 10, 20, 2, 30, tzinfo=UTC)  # a Tuesday, inside the web patch window


@pytest.fixture
def load(monkeypatch):
    def _load(**env):
        monkeypatch.setenv("CHANGE_SEED_PATH", str(SEED / "changes.yaml"))
        monkeypatch.setenv("CHANGE_STANDING_PATH", str(SEED / "standing.yaml"))
        monkeypatch.delenv("V2_STUB_AS_OF", raising=False)
        monkeypatch.delenv("STANDING_REFRESH_SECONDS", raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        spec = importlib.util.spec_from_file_location("change_mgmt_1347", APP)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, "change_mgmt_1347", module)  # pydantic resolves annotations here
        spec.loader.exec_module(module)
        return module
    return _load


def _standing_days(client) -> set[datetime]:
    ids = [c["id"] for c in client.get("/changes").json()["changes"]
           if c["id"].startswith(("CHG-DB-BACKUP-", "CHG-WEB-PATCH-"))]
    return {datetime.strptime(re.search(r"(\d{8})T", i).group(1), "%Y%m%d").replace(tzinfo=UTC)
            for i in ids}


def test_standing_crs_are_materialized_around_the_pinned_clock(load):
    """O3: occurrences span as_of-7d..as_of+1d and none comes from the wall clock."""
    app = load(V2_STUB_AS_OF="2026-10-20T02:30:00Z", STANDING_REFRESH_SECONDS="0")
    with TestClient(app.app) as client:
        days = _standing_days(client)
        assert datetime(2026, 10, 20, tzinfo=UTC) in days
        assert days and all(AS_OF - timedelta(days=8) <= d <= AS_OF + timedelta(days=1) for d in days)
        ids = {c["id"] for c in client.get("/changes").json()["changes"]}
        assert "CHG-WEB-PATCH-20261020T0200Z" in ids and "CHG-DB-BACKUP-20261019T0200Z" in ids


def test_active_changes_without_at_use_the_pinned_clock(load):
    """O3: `/changes/active?host=` with no `at` answers for as_of, not the wall clock."""
    app = load(V2_STUB_AS_OF="2026-10-20T02:30:00Z", STANDING_REFRESH_SECONDS="0")
    with TestClient(app.app) as client:
        got = client.get("/changes/active", params={"host": "web-1"}).json()
    assert "CHG-WEB-PATCH-20261020T0200Z" in [c["id"] for c in got]


def test_writes_are_stamped_with_the_pinned_clock(load):
    """O3: `_now()` is as_of, so created/updated stamps are the pinned instant."""
    app = load(V2_STUB_AS_OF="2026-10-20T02:30:00Z", STANDING_REFRESH_SECONDS="0")
    assert datetime.fromisoformat(app._now().replace("Z", "+00:00")) == AS_OF
    time.sleep(0.01)
    assert datetime.fromisoformat(app._now().replace("Z", "+00:00")) == AS_OF


def test_admin_reset_rematerializes_around_the_pinned_clock(load):
    """O3: `POST /admin/reset` re-derives the standing CRs from T, not from the wall clock."""
    app = load(V2_STUB_AS_OF="2026-10-20T02:30:00Z", STANDING_REFRESH_SECONDS="0")
    with TestClient(app.app) as client:
        assert client.post("/admin/reset").status_code == 200
        days = _standing_days(client)
    assert datetime(2026, 10, 20, tzinfo=UTC) in days
    assert all(AS_OF - timedelta(days=8) <= d <= AS_OF + timedelta(days=1) for d in days)


def test_a_transition_is_stamped_with_the_pinned_clock(load):
    """O3: a status transition's `updated` is T, whatever the wall clock says."""
    app = load(V2_STUB_AS_OF="2026-10-20T02:30:00Z", STANDING_REFRESH_SECONDS="0")
    with TestClient(app.app) as client:
        resp = client.post("/changes/CHG-WEB-PATCH-20261020T0200Z/transitions",
                           json={"status": "implemented"})
    assert resp.status_code == 200
    assert datetime.fromisoformat(resp.json()["updated"].replace("Z", "+00:00")) == AS_OF


def test_zero_refresh_seconds_starts_no_refresh_loop(load):
    """O3: a standing CR removed after startup is not re-added: no loop is running."""
    app = load(V2_STUB_AS_OF="2026-10-20T02:30:00Z", STANDING_REFRESH_SECONDS="0")
    with TestClient(app.app) as client:
        app.STORE.pop("CHG-WEB-PATCH-20261020T0200Z")
        time.sleep(0.3)
        assert client.get("/changes/CHG-WEB-PATCH-20261020T0200Z").status_code == 404


def test_without_the_pin_the_stub_still_follows_the_wall_clock(load):
    """O3 control: unpinned, today's standing CR is materialized and the clock moves."""
    app = load(STANDING_REFRESH_SECONDS="0")
    today = datetime.now(UTC)
    with TestClient(app.app) as client:
        days = _standing_days(client)
    assert any(d.date() == today.date() for d in days)
    assert abs(datetime.fromisoformat(app._now()) - today) < timedelta(minutes=1)
