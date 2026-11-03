"""#1400 — when an alert fires, the playground opens its ticket, keyed by the alert's id.

Kibana's preconfigured webhook connector (kibana/kibana.yml) posts each rule execution's new
alerts to the ticket-server's hook; the detection-rule installer attaches that action to every
rule. These tests drive the real FastAPI app and read the real committed config files; nothing
touches the live stack. Run with the stub's runtime deps:

    uv run --no-project --python 3.12 \
        --with 'fastapi==0.115.*' --with httpx --with pyyaml --with pytest \
        -m pytest playground-v2/ticket-server/tests
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

PLAYGROUND = Path(__file__).resolve().parents[2]
UUID = "43d6d7042a1400be4fcbba4359ee80d3bcc860844a7c6a433b6b61bb850643f4"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def client(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    # SEED_PATH is read at import: an absent seed gives an empty store.
    monkeypatch.setenv("TICKET_SEED_PATH", str(tmp_path / "no-seed.json"))
    app_mod = _load("ticket_server_app_1400", PLAYGROUND / "ticket-server" / "app.py")
    with TestClient(app_mod.app) as c:
        yield c


def flat_alert(uuid: str = UUID, rule_id: str = "v2-cross-tier-ssh-pivot") -> dict:
    """An alert as it sits in the alert index: flat dotted keys."""
    return {
        "_id": uuid,
        "kibana.alert.uuid": uuid,
        "@timestamp": "2026-05-25T13:53:35.193Z",
        "kibana.alert.rule.rule_id": rule_id,
        "kibana.alert.rule.uuid": "internal-rule-saved-object-id",
        "kibana.alert.rule.name": "v2 cross-tier SSH pivot",
        "kibana.alert.rule.description": "Successful sshd login on a workstation host",
    }


def nested_alert(uuid: str = UUID) -> dict:
    """The same alert with its dotted keys expanded into objects."""
    return {
        "_id": uuid,
        "@timestamp": "2026-05-25T13:53:35.193Z",
        "kibana": {"alert": {
            "uuid": uuid,
            "rule": {
                "rule_id": "v2-cross-tier-ssh-pivot",
                "uuid": "internal-rule-saved-object-id",
                "name": "v2 cross-tier SSH pivot",
                "description": "Successful sshd login on a workstation host",
            },
        }},
    }


def _hook(client, body):
    return client.post("/hooks/kibana-alerts", json=body)


@pytest.mark.parametrize("alert", [flat_alert(), nested_alert()], ids=["flat", "nested"])
def test_a_fired_alert_opens_its_ticket_under_the_alerts_id(client, alert):
    assert client.get(f"/tickets/{UUID}").status_code == 404

    r = _hook(client, {"alerts": [alert]})
    assert r.status_code == 200, r.text
    assert r.json() == {"created": [UUID], "existing": [], "skipped": 0}

    t = client.get(f"/tickets/{UUID}").json()
    assert t["status"] == "open"
    assert t["summary"] == "Successful sshd login on a workstation host"
    # the human rule id, not the rule's saved-object uuid
    assert t["labels"] == ["sig:v2-cross-tier-ssh-pivot", "evt:2026-05-25T13:53:35.193Z"]
    assert t["comments"] == []


def test_the_run_can_comment_on_it_and_correlation_finds_it(client):
    _hook(client, {"alerts": [flat_alert()]})
    r = client.post(f"/tickets/{UUID}/comments", json={"author": "defender", "body": "x"})
    assert r.status_code == 201
    found = client.get("/tickets", params={"label": "sig:v2-cross-tier-ssh-pivot"}).json()
    assert [t["key"] for t in found["tickets"]] == [UUID]


def test_a_repeated_delivery_changes_nothing(client):
    _hook(client, {"alerts": [flat_alert()]})
    client.post(f"/tickets/{UUID}/comments", json={"author": "defender", "body": "x"})
    before = client.get(f"/tickets/{UUID}").json()

    r = _hook(client, {"alerts": [flat_alert()]})
    assert r.json() == {"created": [], "existing": [UUID], "skipped": 0}
    assert client.get(f"/tickets/{UUID}").json() == before


def test_each_alert_in_a_delivery_gets_its_own_ticket_and_a_bare_list_is_accepted(client):
    r = _hook(client, [flat_alert("a" * 64), flat_alert("b" * 64, rule_id="v2-off-hours-sudo")])
    assert r.json()["created"] == ["a" * 64, "b" * 64]
    assert client.get(f"/tickets/{'b' * 64}").json()["labels"][0] == "sig:v2-off-hours-sudo"


def test_an_alert_with_no_id_is_skipped_not_keyed_by_something_else(client):
    alert = flat_alert()
    del alert["kibana.alert.uuid"], alert["_id"]
    r = _hook(client, {"alerts": [alert, "not-an-alert"]})
    assert r.json() == {"created": [], "existing": [], "skipped": 2}
    assert client.get("/tickets").json()["total"] == 0


def test_a_body_without_alerts_is_refused(client):
    assert _hook(client, {"alerts": "nope"}).status_code == 422


# --- the wiring: Kibana's connector and the rule action point at this route ---

def _connector() -> tuple[str, dict]:
    yaml = pytest.importorskip("yaml")
    cfg = yaml.safe_load((PLAYGROUND / "kibana" / "kibana.yml").read_text())
    (cid, connector), = cfg["xpack.actions.preconfigured"].items()
    return cid, connector


def test_kibanas_connector_posts_to_the_hook_on_the_ticket_server():
    _, connector = _connector()
    assert connector["actionTypeId"] == ".webhook"
    url = urlparse(connector["config"]["url"])
    assert (url.hostname, url.port, url.path) == ("ticket-server", 8080, "/hooks/kibana-alerts")
    assert connector["config"]["method"] == "post"


def test_every_installed_rule_carries_the_hook_once_under_the_connectors_id():
    cid, _ = _connector()
    installer = _load("install_detection_rules_1400",
                      PLAYGROUND / "scripts" / "install_detection_rules.py")
    assert installer.ALERT_TICKET_CONNECTOR_ID == cid

    rule_files = sorted((PLAYGROUND / "detection-rules").glob("*.json"))
    assert rule_files
    for path in rule_files:
        installed = installer.with_ticket_action(json.loads(path.read_text()))
        hooks = [a for a in installed["actions"] if a["id"] == cid]
        assert len(hooks) == 1, path.name
        assert installer.with_ticket_action(installed)["actions"] == installed["actions"]

    body = installer.ALERT_TICKET_ACTION["params"]["body"]
    # Kibana renders {{{context.alerts}}} as raw JSON; stand in a list and the body must parse.
    assert json.loads(body.replace("{{{context.alerts}}}", json.dumps([flat_alert()]))) == {
        "alerts": [flat_alert()]
    }
