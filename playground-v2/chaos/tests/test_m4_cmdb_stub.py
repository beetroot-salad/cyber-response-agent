"""M4 — the one CMDB-stub change, driven through the real FastAPI app.

Two obligations ride on it:

  * O6 leak fix — `GET /health` today returns `overlay_count`, which rises the
    moment a stale-CMDB profile activates. That is an agent-reachable payload
    that counts the harness's edits, so it goes. No non-harness consumer needs it.
  * missing-host — the common real-world "silent gap" needs a way to say a host
    is absent. An overlay sentinel makes `_effective` return None and drops the
    host from `list_hosts`, with no marker field left visible anywhere.

Nothing here is mocked: it is the committed cmdb/app.py over the committed
hosts/inventory.yaml.
"""
from __future__ import annotations

TOMBSTONE = {"__absent__": True}


def test_health_no_longer_counts_the_overlay(cmdb_client):
    body = cmdb_client.get("/health").json()
    assert body["status"] == "ok"
    assert body["host_count"] > 0
    assert "overlay_count" not in body, "the overlay count is an agent-reachable harness tell (O6)"


def test_health_does_not_grow_a_tell_when_an_overlay_is_set(cmdb_client):
    before = cmdb_client.get("/health").json()
    assert cmdb_client.post("/admin/overlay/web-1", json={"owner": "team.sre"}).status_code == 200
    after = cmdb_client.get("/health").json()
    assert after == before, f"/health changed under an overlay: {before} -> {after}"


def test_tombstone_makes_effective_return_none(cmdb_app):
    assert cmdb_app._effective("web-1") is not None
    cmdb_app.OVERLAY["web-1"] = dict(TOMBSTONE)
    assert cmdb_app._effective("web-1") is None
    # positive control: an unrelated base host is untouched
    assert cmdb_app._effective("web-2")["owner"] == "team.web"


def test_tombstoned_host_disappears_from_list_hosts(cmdb_client):
    before = {h["name"] for h in cmdb_client.get("/hosts").json()["hosts"]}
    assert {"web-1", "web-2"} <= before

    assert cmdb_client.post("/admin/overlay/web-1", json=TOMBSTONE).status_code == 200

    listing = cmdb_client.get("/hosts").json()
    names = {h["name"] for h in listing["hosts"]}
    assert "web-1" not in names, "tombstoned host still listed"
    assert "web-2" in names, "an unrelated host was collaterally hidden"
    assert listing["total"] == len(listing["hosts"]) == len(before) - 1


def test_tombstoned_host_is_a_plain_404_with_no_marker(cmdb_client):
    assert cmdb_client.get("/hosts/web-1").status_code == 200
    cmdb_client.post("/admin/overlay/web-1", json=TOMBSTONE)

    response = cmdb_client.get("/hosts/web-1")
    assert response.status_code == 404
    # The 404 must look exactly like any other unknown host — no sentinel echoed.
    assert "__absent__" not in response.text
    unknown = cmdb_client.get("/hosts/no-such-host-1")
    assert unknown.status_code == 404
    assert set(response.json()) == set(unknown.json())
    assert response.json()["detail"] == unknown.json()["detail"].replace("no-such-host-1", "web-1")


def test_tombstone_is_reverted_by_the_existing_overlay_delete(cmdb_client):
    cmdb_client.post("/admin/overlay/web-1", json=TOMBSTONE)
    assert cmdb_client.get("/hosts/web-1").status_code == 404

    assert cmdb_client.delete("/admin/overlay/web-1").json()["cleared"] is True
    restored = cmdb_client.get("/hosts/web-1")
    assert restored.status_code == 200
    assert restored.json()["owner"] == "team.web"


def test_a_tombstoned_host_never_leaks_through_a_filtered_listing(cmdb_client):
    cmdb_client.post("/admin/overlay/db-1", json=TOMBSTONE)
    prod = cmdb_client.get("/hosts", params={"criticality": "prod"}).json()["hosts"]
    assert "db-1" not in {h["name"] for h in prod}
    assert "web-1" in {h["name"] for h in prod}
