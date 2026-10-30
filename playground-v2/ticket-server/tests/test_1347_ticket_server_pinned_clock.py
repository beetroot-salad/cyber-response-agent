"""#1347 O3 (FR4): the ticket stub's clock is pinned at as_of.

Seam bound by this contract: env var `STUB_AS_OF` (ISO instant) read when `app.py` loads, like
`TICKET_SEED_PATH`; `app._now()` then returns that instant, every time, and records stamped with
it (created/updated) carry it.

Run: flock /tmp/defender-pytest.lock uv run --no-project --python 3.12 --with 'fastapi==0.115.*'
--with httpx --with pytest -m pytest playground-v2/ticket-server/tests
"""
from __future__ import annotations

import importlib.util
import sys
import time
from datetime import datetime, timedelta, UTC
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

APP = Path(__file__).resolve().parents[1] / "app.py"
AS_OF = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)


@pytest.fixture
def load(monkeypatch):
    def _load(**env):
        monkeypatch.setenv("TICKET_SEED_PATH", str(APP.parent / "seed" / "tickets.json"))
        monkeypatch.delenv("STUB_AS_OF", raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        spec = importlib.util.spec_from_file_location("ticket_server_1347", APP)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, "ticket_server_1347", module)  # pydantic resolves annotations here
        spec.loader.exec_module(module)
        return module
    return _load


def _at(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def test_now_returns_the_pinned_instant_every_time(load):
    """O3: `_now()` is as_of however long the stub has been up."""
    app = load(STUB_AS_OF="2026-10-20T09:00:00Z")
    first = _at(app._now())
    time.sleep(0.01)
    assert first == AS_OF and _at(app._now()) == AS_OF


def test_a_new_ticket_is_stamped_with_the_pinned_instant(load):
    """O3: created/updated on a record written through the API carry as_of."""
    app = load(STUB_AS_OF="2026-10-20T09:00:00Z")
    with TestClient(app.app) as client:
        resp = client.post("/tickets", json={"key": "FRZ-1", "summary": "s"})
    assert resp.status_code in (200, 201)
    body = resp.json()
    assert _at(body["created"]) == AS_OF and _at(body["updated"]) == AS_OF


def test_without_the_pin_the_clock_is_the_wall_clock(load):
    """O3 control: unpinned, `_now()` is current time."""
    app = load()
    assert abs(_at(app._now()) - datetime.now(UTC)) < timedelta(minutes=1)
