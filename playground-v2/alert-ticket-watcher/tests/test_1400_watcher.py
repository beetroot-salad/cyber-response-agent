"""#1400 — the alert-ticket-watcher sends every new alert to the ticket-server, once its page lands.

Elasticsearch is faked (`FakeAlerts` answers the watcher's search bodies); the ticket-server is
the real FastAPI app. Run with:

    uv run --no-project --python 3.12 \
        --with 'fastapi==0.115.*' --with httpx --with pytest \
        -m pytest playground-v2/alert-ticket-watcher/tests
"""
from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PLAYGROUND = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 11, 3, 17, 0, tzinfo=timezone.utc)
OVERLAP = timedelta(minutes=2)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


watcher = _load("alert_ticket_watcher_1400", PLAYGROUND / "alert-ticket-watcher" / "watcher.py")


def hit(n: int, at: datetime) -> dict:
    """A search hit the way Elasticsearch returns a security alert: flat dotted _source."""
    uuid = f"{n:064x}"
    ts = at.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {"_id": uuid, "sort": [int(at.timestamp() * 1000), uuid], "_source": {
        "@timestamp": ts,
        "kibana.alert.uuid": uuid,
        "kibana.alert.rule.rule_id": "v2-off-hours-sudo",
        "kibana.alert.rule.description": "Three or more sudo executions",
    }}


class FakeAlerts:
    """Answers search bodies the way Elasticsearch would: range, sort, size, search_after."""

    def __init__(self, hits):
        self.hits = sorted(hits, key=lambda h: h["sort"])
        self.bodies = []

    def __call__(self, body):
        self.bodies.append(body)
        since = watcher._parse(body["query"]["range"]["@timestamp"]["gte"])
        out = [h for h in self.hits if watcher._parse(h["_source"]["@timestamp"]) >= since]
        if "search_after" in body:
            out = [h for h in out if h["sort"] > body["search_after"]]
        return out[: body["size"]]


def test_alerts_since_the_cursor_are_posted_and_the_cursor_moves_to_the_newest():
    alerts = FakeAlerts([hit(1, T0 - timedelta(hours=1)), hit(2, T0 + timedelta(seconds=5)),
                         hit(3, T0 + timedelta(seconds=9))])
    posted = []
    cursor = watcher.poll_once(T0, OVERLAP, alerts, posted.append)

    assert [[a["_id"] for a in batch] for batch in posted] == [[f"{2:064x}", f"{3:064x}"]]
    assert posted[0][0]["kibana.alert.uuid"] == f"{2:064x}"
    assert cursor == T0 + timedelta(seconds=9)
    # the query reaches back by the overlap, so an alert indexed late is not missed
    assert alerts.bodies[0]["query"]["range"]["@timestamp"]["gte"] == "2026-11-03T16:58:00.000Z"


def test_nothing_new_leaves_the_cursor_and_posts_nothing():
    posted = []
    assert watcher.poll_once(T0, OVERLAP, FakeAlerts([]), posted.append) == T0
    assert posted == []


def test_more_than_a_page_is_read_page_by_page(monkeypatch):
    monkeypatch.setattr(watcher, "PAGE_SIZE", 2)
    alerts = FakeAlerts([hit(n, T0 + timedelta(seconds=n)) for n in range(1, 6)])
    posted = []
    cursor = watcher.poll_once(T0, OVERLAP, alerts, posted.append)

    assert [len(b) for b in posted] == [2, 2, 1]
    assert {a["_id"] for b in posted for a in b} == {f"{n:064x}" for n in range(1, 6)}
    assert cursor == T0 + timedelta(seconds=5)
    assert alerts.bodies[1]["search_after"] == alerts.hits[1]["sort"]


def test_a_refused_post_keeps_the_cursor_so_the_next_poll_resends(monkeypatch):
    monkeypatch.setattr(watcher, "PAGE_SIZE", 2)
    alerts = FakeAlerts([hit(n, T0 + timedelta(seconds=n)) for n in range(1, 5)])
    calls = []

    def post(batch):
        calls.append(batch)
        if len(calls) == 2:
            raise OSError("ticket-server down")

    with pytest.raises(OSError):
        watcher.poll_once(T0, OVERLAP, alerts, post)
    # the first page landed; the caller keeps its own cursor (T0), so the retry re-reads
    # from T0 - overlap and resends both pages
    resent = []
    watcher.poll_once(T0, OVERLAP, alerts, resent.extend)
    assert {a["_id"] for a in resent} == {f"{n:064x}" for n in range(1, 5)}


def test_end_to_end_each_alert_opens_one_ticket_in_the_real_ticket_server(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    monkeypatch.setenv("TICKET_SEED_PATH", str(tmp_path / "no-seed.json"))
    app = _load("ticket_server_app_1400w", PLAYGROUND / "ticket-server" / "app.py").app
    alerts = FakeAlerts([hit(1, T0 + timedelta(seconds=1)), hit(2, T0 + timedelta(seconds=2))])

    with TestClient(app) as client:
        def post(batch):
            r = client.post("/hooks/kibana-alerts", json={"alerts": batch})
            r.raise_for_status()

        cursor = watcher.poll_once(T0, OVERLAP, alerts, post)
        watcher.poll_once(cursor, OVERLAP, alerts, post)  # the overlap re-sends both: no-ops

        tickets = client.get("/tickets").json()["tickets"]
        assert sorted(t["key"] for t in tickets) == [f"{1:064x}", f"{2:064x}"]
        t = client.get(f"/tickets/{1:064x}").json()
        assert t["labels"] == ["sig:v2-off-hours-sudo", "evt:2026-11-03T17:00:01.000Z"]
        assert t["summary"] == "Three or more sudo executions"


def test_the_container_command_is_not_one_shuffles_reaper_kills():
    lines = (PLAYGROUND / "alert-ticket-watcher" / "Dockerfile").read_text().splitlines()
    (cmd,) = [ln for ln in lines if ln.startswith("CMD")]
    assert "app.py" not in cmd and "watcher.py" in cmd
