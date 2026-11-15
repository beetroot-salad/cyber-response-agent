"""#1083 piece 1: the API's real server, end to end over the real stores (PostgreSQL, the job store, the identity store).

The app is composed by `defender.api_server.serving` over a fresh migrated database, Keycloak played by a transport that
answers as the dev Keycloak was observed to. People and programs are seeded in the identity store; nothing here signs in
through Keycloak (O4 is the dev walk-through's)."""
from __future__ import annotations

import collections
import dataclasses
import datetime as dt
import json
import logging
import re
import urllib.parse
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest

from defender.tests.support.api._server1083 import (
    A,
    ANN,
    B,
    ORIGIN,
    BOB,
    OPS,
    PROGRAMS_REALM,
    SESSION_COOKIE,
    SIGNIN_REALM,
    Child,
    FakeKeycloak,
    Seeded,
    TokenCredential,
    environment,
    free_port,
    person,
    program,
    program_token,
    seed_identity,
    seed_token_credential,
)
from defender.tests.support.api._signin1161 import authorize, deleted, link_account, set_cookies
from defender.tests.support.api._mount1161 import route_paths
from defender.tests.support.jobs._jobs1342 import (
    ALERT_BYTES,
    DESCRIPTION,
    TITLE,
    job_store,
    register_tenant,
    row,
)
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING

pytestmark = pytest.mark.anyio

WORK_ACTIONS = ("investigation.start", "investigation.cancel", "investigation.delete", "learning_job.start",
                "alert_mapping.update")
MAPPING_ENTRIES = ("signature", "event_time", "summary", "case_key", "title", "description")
C = "0b6f1c1e-3c55-4a4e-9a51-1083000000cc"
NOON = dt.datetime(2026, 11, 1, 12, tzinfo=dt.UTC)


class Served:
    """The running app, a client on it, and what the test seeded."""

    def __init__(self, client: httpx.AsyncClient, app: Any, dsn: str, tmp_path: Path, keycloak: FakeKeycloak,
                 seeded: Seeded) -> None:
        self.client, self.app, self.dsn, self.tmp_path, self.keycloak, self.seeded = (
            client, app, dsn, tmp_path, keycloak, seeded)

    def ann(self, *, write: bool = True) -> dict[str, str]:
        return person(self.seeded.ann_session, write=write)

    def bob(self, *, write: bool = True) -> dict[str, str]:
        return person(self.seeded.bob_session, write=write)

    def ops(self) -> dict[str, str]:
        return person(self.seeded.ops_session, write=True)

    def program(self) -> dict[str, str]:
        return program(self.seeded.program_key)

    def bearer(self, token: str) -> dict[str, str]:
        return program(token)

    def user_id(self, email: str) -> str:
        [(found,)] = execute(self.dsn, "SELECT id FROM identity.users WHERE email = %s", (email,))
        return str(found)


@pytest.fixture
def tenants(migrated_database: str) -> str:
    """A and B active, each with the fixture's alert mapping saved."""
    register_tenant(migrated_database, A)
    register_tenant(migrated_database, B)
    return migrated_database


@pytest.fixture
async def served(tenants: str, tmp_path: Path) -> AsyncIterator[Served]:
    """The app as the real server composes it, its lifespan run by `serving`, on this test's loop."""
    from defender.api_server import Settings, serving

    seeded = await seed_identity(tenants)
    keycloak = FakeKeycloak()
    async with serving(Settings.from_environ(environment(tmp_path, dsn=tenants)), transport=keycloak) as running, \
            httpx.AsyncClient(transport=httpx.ASGITransport(app=running.app), base_url=ORIGIN) as client:
        yield Served(client, running.app, tenants, tmp_path, keycloak, seeded)
    assert keycloak.unmodelled == []


@pytest.fixture
async def token_credential(served: Served) -> TokenCredential:
    """A live OAuth credential of the seeded program, so the programs realm's tokens can be minted for it."""
    return await seed_token_credential(served.dsn, served.seeded)


async def _alerts(dsn: str, tenant: str, *fired: dt.datetime) -> list[str]:
    """One stored alert per `fired`, through the store's trusted insert (no product command creates alerts, N9)."""
    async with job_store(dsn) as store:
        stored = [await store.insert_alert(tenant, vendor="elastic", vendor_ticket_id=f"T-{tenant[-2:]}-{at.isoformat()}",
                                           fired_at=at, changed_at=at, received_at=at, raw=ALERT_BYTES)
                  for at in fired]
    return [str(s.alert_id) for s in stored]


async def _completed(dsn: str, tenant: str, alert_id: str) -> str:
    """An investigation of `alert_id` brought to `completed` by the store's own claim and finish."""
    async with job_store(dsn) as store:
        inv, _ = await store.create_investigation(tenant, alert_id, "seed", actor="seed")
        claim = await store.claim()
        assert claim.record.investigation_id == inv.investigation_id, "premise: nothing else was queued"
        await store.finish(tenant, inv.investigation_id, stage="completed", disposition="malicious", cost_usd=0.0)
    return str(inv.investigation_id)


async def _start(served: Served, alert_id: str, key: str, headers: dict[str, str] | None = None) -> httpx.Response:
    return await served.client.post(f"/api/tenants/{A}/investigations", headers=headers or served.ann(),
                                    json={"alert_id": alert_id, "client_request_id": key})


# --- alerts -----------------------------------------------------------------------------------------

@pytest.mark.postgres
async def test_o6_alerts_list_newest_first_by_window_with_a_cursor_and_read_one(served):
    """Alerts page newest first with a cursor, narrow by window, and read one with its raw text. (O6)"""
    early, middle, late = (NOON + dt.timedelta(hours=h) for h in (-5, -3, -1))
    a_early, a_middle, a_late = await _alerts(served.dsn, A, early, middle, late)
    await _alerts(served.dsn, B, late)  # another tenant's alert never lists here

    first = (await served.client.get(f"/api/tenants/{A}/alerts", params={"limit": 2}, headers=served.ann(write=False))).json()
    assert [a["alert_id"] for a in first["items"]] == [a_late, a_middle]
    assert first["next_cursor"] is not None
    second = (await served.client.get(f"/api/tenants/{A}/alerts", params={"limit": 2, "cursor": first["next_cursor"]},
                                      headers=served.ann(write=False))).json()
    assert ([a["alert_id"] for a in second["items"]], second["next_cursor"]) == ([a_early], None)

    window = await served.client.get(f"/api/tenants/{A}/alerts", headers=served.ann(write=False),
                                     params={"fired_after": (middle - dt.timedelta(hours=1)).isoformat()})
    assert [a["alert_id"] for a in window.json()["items"]] == [a_late, a_middle]

    one = await served.client.get(f"/api/tenants/{A}/alerts/{a_late}", headers=served.ann(write=False))
    assert one.status_code == 200
    assert (one.json()["raw"], one.json()["title"], one.json()["description"]) == (ALERT_BYTES.decode(), TITLE, DESCRIPTION)


# --- investigations ---------------------------------------------------------------------------------

@pytest.mark.postgres
async def test_o6_a_member_starts_lists_reads_and_cancels_an_investigation_on_the_job_store(served):
    """Start, list, read and cancel answer what the job store holds; cancel of a queued one aborts it. (O6)"""
    [alert_id] = await _alerts(served.dsn, A, NOON)
    started = await _start(served, alert_id, "req-1")
    assert started.status_code == 201
    investigation = started.json()
    assert (investigation["alert_id"], investigation["status"], investigation["attempt"]) == (alert_id, "queued", 1)
    assert investigation["artifacts"] == []
    assert row(served.dsn, investigation["investigation_id"])["stage"] == "queued"

    listed = await served.client.get(f"/api/tenants/{A}/investigations", params={"alert_id": alert_id},
                                     headers=served.ann(write=False))
    assert [i["investigation_id"] for i in listed.json()["items"]] == [investigation["investigation_id"]]
    read = await served.client.get(f"/api/tenants/{A}/investigations/{investigation['investigation_id']}",
                                   headers=served.ann(write=False))
    assert read.json() == investigation

    cancelled = await served.client.post(
        f"/api/tenants/{A}/investigations/{investigation['investigation_id']}/cancel", headers=served.ann())
    assert cancelled.status_code == 200
    assert (cancelled.json()["status"], cancelled.json()["failure_reason"]) == ("aborted", "cancelled")
    assert row(served.dsn, investigation["investigation_id"])["stage"] == "aborted"


@pytest.mark.postgres
async def test_o6_repeating_a_start_with_its_request_id_answers_the_same_investigation(served):
    """A start repeated with its `client_request_id` answers 200 with the investigation the first one made. (O6)"""
    [alert_id] = await _alerts(served.dsn, A, NOON)
    first = await _start(served, alert_id, "req-1")
    again = await _start(served, alert_id, "req-1")
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json() == first.json()
    assert execute(served.dsn, "SELECT count(*) FROM jobs.investigations WHERE alert_id = %s", (alert_id,)) == [(1,)]

    other = await _start(served, alert_id, "req-2")  # another request while one is live: the live one answers
    assert (other.status_code, other.json()["investigation_id"]) == (200, first.json()["investigation_id"])


@pytest.mark.postgres
async def test_o6_cancel_and_delete_refuse_what_they_must_and_a_deleted_investigation_reads_absent(served):
    """Cancelling an ended investigation and deleting a live one conflict; a deleted one reads 404. (O6)"""
    [alert_id] = await _alerts(served.dsn, A, NOON)
    inv = (await _start(served, alert_id, "req-1")).json()["investigation_id"]
    path = f"/api/tenants/{A}/investigations/{inv}"

    assert (await served.client.delete(path, headers=served.ann())).status_code == 409  # live
    assert (await served.client.post(f"{path}/cancel", headers=served.ann())).status_code == 200
    assert (await served.client.post(f"{path}/cancel", headers=served.ann())).status_code == 409  # ended

    assert (await served.client.get(path, headers=served.ann(write=False))).status_code == 200  # control
    assert (await served.client.delete(path, headers=served.ann())).status_code == 204
    assert (await served.client.get(path, headers=served.ann(write=False))).status_code == 404
    listed = await served.client.get(f"/api/tenants/{A}/investigations", headers=served.ann(write=False))
    assert listed.json()["items"] == []
    assert row(served.dsn, inv) is None


# --- learning jobs ----------------------------------------------------------------------------------

@pytest.mark.postgres
async def test_o6_learning_jobs_start_replay_list_by_investigation_and_read(served):
    """A learning job starts once per request id, lists by investigation and reads what the store holds. (O6)"""
    first_alert, second_alert = await _alerts(served.dsn, A, NOON, NOON + dt.timedelta(hours=1))
    inv, other = await _completed(served.dsn, A, first_alert), await _completed(served.dsn, A, second_alert)
    ann = served.ann()

    started = await served.client.post(f"/api/tenants/{A}/learning-jobs", headers=ann,
                                       json={"investigation_id": inv, "client_request_id": "relearn-1"})
    assert started.status_code == 201
    job = started.json()
    assert (job["investigation_id"], job["alert_id"], job["trigger"], job["status"]) == (inv, first_alert, "explicit", "queued")
    again = await served.client.post(f"/api/tenants/{A}/learning-jobs", headers=ann,
                                     json={"investigation_id": inv, "client_request_id": "relearn-1"})
    assert (again.status_code, again.json()) == (200, job)

    read = await served.client.get(f"/api/tenants/{A}/learning-jobs/{job['learning_job_id']}", headers=served.ann(write=False))
    assert read.json() == job
    listed = await served.client.get(f"/api/tenants/{A}/learning-jobs", params={"investigation_id": inv},
                                     headers=served.ann(write=False))
    held = execute(served.dsn, "SELECT id FROM jobs.learning_jobs WHERE investigation_id = %s", (inv,))
    assert {j["learning_job_id"] for j in listed.json()["items"]} == {str(i) for (i,) in held}
    assert job["learning_job_id"] in {j["learning_job_id"] for j in listed.json()["items"]}
    everything = await served.client.get(f"/api/tenants/{A}/learning-jobs", headers=served.ann(write=False))
    assert {j["investigation_id"] for j in everything.json()["items"]} == {inv, other}  # control: the filter narrowed it


@pytest.mark.postgres
async def test_o6_a_learning_job_of_an_investigation_that_did_not_complete_conflicts(served):
    """A re-learn of a queued investigation answers 409; of a completed one, 201. (O6)"""
    queued_alert, done_alert = await _alerts(served.dsn, A, NOON, NOON + dt.timedelta(hours=1))
    queued = (await _start(served, queued_alert, "req-1")).json()["investigation_id"]
    done = await _completed(served.dsn, A, done_alert)
    body = {"client_request_id": "relearn-1"}
    refused = await served.client.post(f"/api/tenants/{A}/learning-jobs", headers=served.ann(),
                                       json={"investigation_id": queued, **body})
    accepted = await served.client.post(f"/api/tenants/{A}/learning-jobs", headers=served.ann(),
                                        json={"investigation_id": done, **body})
    assert (refused.status_code, accepted.status_code) == (409, 201)


# --- alert mapping ----------------------------------------------------------------------------------

@pytest.mark.postgres
async def test_the_alert_mapping_reads_through_its_own_port_while_systems_refuse(served):
    """The alert mapping answers the tenant's saved mapping although the systems port refuses whole. (G2, O6)"""
    from defender.api.models import AlertMapping

    got = await served.client.get(f"/api/tenants/{A}/alert-mapping", headers=served.ann(write=False))
    assert got.status_code == 200
    assert got.json() == {entry: FIXTURE_ALERT_MAPPING.get(entry) for entry in AlertMapping.model_fields}
    assert (await served.client.get(f"/api/tenants/{A}/systems", headers=served.ann(write=False))).status_code == 501


@pytest.mark.postgres
async def test_o6_a_mapping_replace_answers_what_the_store_holds(served):
    """A replace answers the mapping the store now holds, and a read after it answers the same. (O6, Am-8)"""
    replacement = {entry: f"vendor.{entry}" for entry in MAPPING_ENTRIES} | {"summary": None}
    put = await served.client.put(f"/api/tenants/{A}/alert-mapping", headers=served.ann(), json=replacement)
    assert put.status_code == 200  # the tenant had one: a replace, not a creation
    assert put.json() == replacement
    assert put.json() == await _held_async(served.dsn, A)
    got = await served.client.get(f"/api/tenants/{A}/alert-mapping", headers=served.ann(write=False))
    assert got.json() == put.json()
    assert await _held_async(served.dsn, B) == {e: FIXTURE_ALERT_MAPPING.get(e) for e in MAPPING_ENTRIES}  # B untouched


@pytest.mark.postgres
async def test_o6_every_subset_of_the_entries_mapped_is_replaced_and_read_back_as_exactly_that_mapping(served):
    """For each subset of the six entries (none included), a replace and a read both answer 200 with exactly it. (O6, #1345 M2)"""
    import itertools

    from defender.records.formats import MAPPING_KEYS

    assert set(MAPPING_KEYS) == set(MAPPING_ENTRIES)
    subsets = [s for r in range(len(MAPPING_KEYS) + 1) for s in itertools.combinations(MAPPING_KEYS, r)]
    assert len(subsets) == 2 ** len(MAPPING_KEYS)
    url = f"/api/tenants/{A}/alert-mapping"
    for mapped in [(), *subsets]:  # the empty one first: straight after the fixture's full mapping
        body = {entry: f"vendor.{entry}" if entry in mapped else None for entry in MAPPING_KEYS}
        put = await served.client.put(url, headers=served.ann(), json=body)
        assert (put.status_code, put.json()) == (200, body), mapped
        got = await served.client.get(url, headers=served.ann(write=False))
        assert (got.status_code, got.json()) == (200, body), mapped


async def _held_async(dsn: str, tenant: str) -> dict[str, str | None]:
    async with job_store(dsn) as store:
        stored = await store.get_alert_mapping(tenant)
    return {entry: stored.path_of(entry) for entry in MAPPING_ENTRIES}


# --- tenant keying through the wire -----------------------------------------------------------------

@pytest.mark.postgres
async def test_another_tenants_member_reads_every_work_record_of_a_tenant_as_absent(served):
    """Bob's session on A's tenant path answers 404 for every work read and write that answers Ann. (O6, O10)"""
    [alert_id] = await _alerts(served.dsn, A, NOON)
    inv = (await _start(served, alert_id, "req-1")).json()["investigation_id"]
    done = await _completed(served.dsn, A, (await _alerts(served.dsn, A, NOON + dt.timedelta(hours=1)))[0])
    job = (await served.client.post(f"/api/tenants/{A}/learning-jobs", headers=served.ann(),
                                    json={"investigation_id": done, "client_request_id": "r"})).json()["learning_job_id"]
    reads = ["/alerts", f"/alerts/{alert_id}", "/investigations", f"/investigations/{inv}", "/learning-jobs",
             f"/learning-jobs/{job}", "/alert-mapping"]
    for path in reads:
        assert (await served.client.get(f"/api/tenants/{A}{path}", headers=served.ann(write=False))).status_code == 200, path
        assert (await served.client.get(f"/api/tenants/{A}{path}", headers=served.bob(write=False))).status_code == 404, path
    assert (await served.client.post(f"/api/tenants/{A}/investigations/{inv}/cancel", headers=served.bob())).status_code == 404
    assert (await served.client.delete(f"/api/tenants/{A}/investigations/{inv}", headers=served.bob())).status_code == 404
    assert (await _start(served, alert_id, "req-2", served.bob())).status_code == 404
    assert row(served.dsn, inv)["stage"] == "queued"  # control: nothing of Bob's reached it

    # Bob's own tenant does not hold A's ids: the same id, read by its own member on its own path, is absent.
    assert (await served.client.get(f"/api/tenants/{B}/investigations/{inv}", headers=served.bob(write=False))).status_code == 404
    assert (await served.client.get(f"/api/tenants/{B}/alerts/{alert_id}", headers=served.bob(write=False))).status_code == 404
    assert (await served.client.get(f"/api/tenants/{B}/alerts", headers=served.bob(write=False))).json()["items"] == []


# --- #1485 O4: learning work, read through the learning store the server composed --------------------------------

@pytest.mark.postgres
async def test_1485_o4_held_dead_items_and_parked_batches_are_served_from_the_learning_store_not_501(served):
    """Rows the learning store's verbs made are what both learning routes answer on the real server (200, never 501), as
    the store holds them (`item_id` too) and only for their tenant; `status=dead` narrows; another tenant's member is 404
    there. (O4, O1, O2, O3)"""
    from defender.tests.support.api._learning1485 import dead_alone, held_together, parked_revert
    from defender.tests.support.learning.core._store1278 import learning_store

    async with learning_store(served.dsn) as store:
        batch = await held_together(store, A, [("finding", "h1")], pr=7)
        dead = await dead_alone(store, A, "d1")
        await held_together(store, B, [("finding", "b-only")])
        parked = await parked_revert(store, A)
        await parked_revert(store, B)
        stored = {i.key: i for i in await store.work(A, statuses=["held", "dead"])}
    ann = served.ann(write=False)

    items = await served.client.get(f"/tenants/{A}/learning/items", headers=ann)
    assert items.status_code == 200, items.text
    assert [(i["item_id"], i["key"], i["status"], i["reason"], i["batch_id"], i["pr_number"]) for i in items.json()["items"]] == [
        (str(i.id), i.key, i.status, i.reason, str(i.batch_id), i.pr_number)
        for i in sorted(stored.values(), key=lambda i: (i.updated_at, str(i.id)), reverse=True)]
    assert {stored["h1"].batch_id, stored["d1"].batch_id} == {batch, dead}
    narrowed = await served.client.get(f"/tenants/{A}/learning/items", params={"status": "dead"}, headers=ann)
    assert [i["key"] for i in narrowed.json()["items"]] == ["d1"]
    listed = await served.client.get(f"/tenants/{A}/learning/parked-batches", headers=ann)
    assert listed.status_code == 200, listed.text
    assert [(b["batch_id"], b["batch_kind"], b["blocks_lane"]) for b in listed.json()["items"]] == [
        (str(parked), "revert", False)]
    for route in ("learning/items", "learning/parked-batches"):
        assert (await served.client.get(f"/tenants/{A}/{route}", headers=served.bob(write=False))).status_code == 404


# --- tenant administration --------------------------------------------------------------------------

@pytest.mark.postgres
async def test_o7_an_administrator_creates_a_tenant_row_the_lifecycle_will_work(served):
    """`POST /admin/tenants` writes a `creating` tenant row with `create` pending, which reads back through the admin routes. (O7)"""
    created = await served.client.post("/api/admin/tenants", headers=served.ops())
    assert created.status_code == 202
    tenant_id = created.json()["tenant_id"]
    assert execute(served.dsn, "SELECT state, pending_action FROM tenancy.tenants WHERE id = %s",
                   (tenant_id,)) == [("creating", "create")]
    read = await served.client.get(f"/api/admin/tenants/{tenant_id}", headers=served.ops())
    assert read.status_code == 200
    assert tenant_id in {t["tenant_id"] for t in (await served.client.get("/api/admin/tenants", headers=served.ops())).json()["items"]}
    # The caller is judged by the identity store: a member who is no platform administrator is refused, and no row is made.
    before = execute(served.dsn, "SELECT count(*) FROM tenancy.tenants")
    assert before == [(3,)]  # A, B and the one just created
    refused = await served.client.post("/api/admin/tenants", headers=served.ann())
    assert refused.status_code == 403
    assert execute(served.dsn, "SELECT count(*) FROM tenancy.tenants") == before


@pytest.mark.postgres
async def test_o7_an_administrator_invites_an_existing_user_into_an_empty_tenant_by_rows_and_a_logged_notice(
        served, caplog):
    """The invitation writes an invited membership and a notice request, logs the notice, and writes nothing to Keycloak. (O7, N10)"""
    register_tenant(served.dsn, C)
    caplog.set_level(logging.INFO)
    invited = await served.client.post(f"/api/admin/tenants/{C}/invitations", headers=served.ops(), json={"email": BOB})
    assert invited.status_code == 202
    invitation_id = invited.json()["id"]
    held = execute(served.dsn, "SELECT m.status, u.email, m.invited_by FROM identity.memberships m "
                   "JOIN identity.users u ON u.id = m.user_id WHERE m.tenant_id = %s", (C,))
    assert [(status, email, str(by)) for status, email, by in held] == [("invited", BOB, served.user_id(OPS))]
    # The sender is the identity loop's, on its own interval: the notice reaches the log, naming who, where and which.
    with anyio.fail_after(60):
        while not any(invitation_id in r.getMessage() and BOB in r.getMessage() and C in r.getMessage()
                      for r in caplog.records):
            await anyio.sleep(0.5)
    assert [m for m in served.keycloak.seen if m[0] != "GET" and "/admin/realms/" in m[1]] == []
    # Control: the same route refuses a tenant that has members.
    assert (await served.client.post(f"/api/admin/tenants/{A}/invitations", headers=served.ops(),
                                     json={"email": BOB})).status_code == 409


@pytest.mark.postgres
async def test_o7_an_administrator_offboards_a_tenant_and_its_queued_investigation_is_aborted(served):
    """Offboarding moves the tenant to `offboarding`, aborts its queued investigation and ends its members' access. (O7)"""
    [alert_id], [other_alert] = await _alerts(served.dsn, A, NOON), await _alerts(served.dsn, B, NOON)
    queued = (await _start(served, alert_id, "req-1")).json()["investigation_id"]
    other = (await served.client.post(f"/api/tenants/{B}/investigations", headers=served.bob(),
                                      json={"alert_id": other_alert, "client_request_id": "req-1"})).json()["investigation_id"]
    assert row(served.dsn, queued)["stage"] == "queued"  # premise

    refused = await served.client.post(f"/api/admin/tenants/{A}/offboard", headers=served.ann())
    assert refused.status_code == 403
    assert execute(served.dsn, "SELECT state FROM tenancy.tenants WHERE id = %s", (A,)) == [("active",)]

    done = await served.client.post(f"/api/admin/tenants/{A}/offboard", headers=served.ops())
    assert done.status_code == 202
    assert (done.json()["state"], done.json()["pending_action"]) == ("offboarding", "offboard")
    assert execute(served.dsn, "SELECT state, pending_action FROM tenancy.tenants WHERE id = %s", (A,)) == [
        ("offboarding", "offboard")]
    assert execute(served.dsn, "SELECT stage, failure_reason FROM jobs.investigations WHERE id = %s", (queued,)) == [
        ("aborted", "tenant_offboarded")]
    assert (await served.client.get(f"/api/tenants/{A}/alerts", headers=served.ann(write=False))).status_code == 404
    # Control: another tenant's queued investigation and access are untouched.
    assert row(served.dsn, other)["stage"] == "queued"
    assert (await served.client.get(f"/api/tenants/{B}/alerts", headers=served.bob(write=False))).status_code == 200


# --- unbacked families ------------------------------------------------------------------------------

def _unbacked(document: dict[str, Any]) -> list[tuple[str, str]]:
    """Every operation of the documented routes on systems and lessons: (path, method)."""
    return [(path, method) for path, item in document["paths"].items() for method in item
            if ("/systems" in path or "/lessons" in path) and method in ("get", "put", "post", "delete")]


@pytest.mark.postgres
async def test_o8_systems_and_lessons_refuse_501_naming_their_issue_after_membership(served):
    """A member gets 501 naming the backing issue on every systems and lessons route; a non-member gets 404. (O8, P1)"""
    body = {"kind": "ticket", "display_name": "Tickets", "enabled": True, "settings": {}}
    credentials = {"kind": "static", "credentials": {"api_token": "a-secret-of-sixteen-or-more"}}
    cases = [("get", "/systems", None, "#1470"), ("put", "/systems/tix", body, "#1470"),
             ("put", "/systems/tix/credentials", credentials, "#1470"), ("post", "/systems/tix/check", None, "#1470"),
             ("get", "/lessons", None, "#1082")]
    assert (await served.client.get(f"/api/tenants/{A}/alerts", headers=served.ann(write=False))).status_code == 200  # control
    for method, path, payload, issue in cases:
        refused = await served.client.request(method, f"/api/tenants/{A}{path}", headers=served.ann(), json=payload)
        assert refused.status_code == 501, path
        assert refused.headers["content-type"].startswith("application/problem+json")
        # FORCED CHOICE FC-8: the problem's `type` stays unpinned; the detail names the issue by its number.
        assert (refused.json()["title"], refused.json()["status"]) == ("Not Implemented", 501)
        assert issue in refused.json()["detail"], path
        outsider = await served.client.request(method, f"/api/tenants/{A}{path}", headers=served.bob(), json=payload)
        assert outsider.status_code == 404, path


@pytest.mark.postgres
async def test_o8_the_real_servers_openapi_declares_the_501_on_every_systems_and_lessons_route(served):
    """On the real server, the operations declaring 501 are exactly those on systems and lessons. (O8, Am-2)"""
    document = (await served.client.get("/api/openapi.json")).json()
    unbacked = set(_unbacked(document))
    assert len(unbacked) >= 5
    declaring = {(path, method) for path, item in document["paths"].items() for method, op in item.items()
                 if "501" in op["responses"]}
    assert declaring == unbacked, declaring ^ unbacked
    assert "not yet real" not in document["info"].get("summary", "")


@pytest.mark.postgres
async def test_o8_a_real_process_serves_the_same_openapi_document_as_the_app(served):
    """A started program answers `/openapi.json` declaring the 501s, equal to the in-process app's document. (O8, Am-2)"""
    child = Child.faked(environment(served.tmp_path, dsn=served.dsn, port=free_port()))
    try:
        assert child.ready(), "the program should come up on the migrated database"
        over_the_wire = httpx.get(f"{child.base_url}/api/openapi.json", timeout=10).json()
    finally:
        ended = child.stop()
        child.kill()
    assert ended.returncode == 0, ended.stderr
    assert all("501" in over_the_wire["paths"][path][method]["responses"] for path, method in _unbacked(over_the_wire))
    assert over_the_wire == json.loads(json.dumps(served.app.openapi()))


# --- audit: one announcer per action ----------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Event:
    logger: str
    message: str
    action: str | None
    actor: str | None
    credential_id: str | None
    tenant_id: str | None
    target: str | None
    detail: str | None


def _announced(caplog: Any) -> list[Event]:
    """Every record, on any logger, that announces a work action: by its `action` attribute or by naming the action."""
    return [Event(r.name, r.getMessage(), *(getattr(r, field, None) for field in (
        "action", "actor", "credential_id", "tenant_id", "target", "detail")))
            for r in caplog.records
            if getattr(r, "action", None) in WORK_ACTIONS or any(a in r.getMessage() for a in WORK_ACTIONS)]


@pytest.mark.postgres
async def test_o9_each_work_action_is_announced_once_naming_its_caller(served, caplog):
    """On the real wiring each start, cancel, delete, learning-job start and mapping replace logs one event. (O9, P2)"""
    first_alert, second_alert, third_alert = await _alerts(served.dsn, A, NOON, NOON + dt.timedelta(hours=1),
                                                          NOON + dt.timedelta(hours=2))
    done = await _completed(served.dsn, A, third_alert)
    caplog.set_level(logging.DEBUG)
    caplog.clear()
    ann = served.ann()

    by_program = (await _start(served, first_alert, "ci-1", served.program())).json()["investigation_id"]
    by_person = (await _start(served, second_alert, "ann-1", ann)).json()["investigation_id"]
    assert (await served.client.post(f"/api/tenants/{A}/investigations/{by_program}/cancel", headers=ann)).status_code == 200
    assert (await served.client.delete(f"/api/tenants/{A}/investigations/{by_program}", headers=ann)).status_code == 204
    job = (await served.client.post(f"/api/tenants/{A}/learning-jobs", headers=ann,
                                    json={"investigation_id": done, "client_request_id": "relearn-1"})).json()["learning_job_id"]
    mapping = {entry: FIXTURE_ALERT_MAPPING.get(entry) for entry in MAPPING_ENTRIES} | {"summary": None}
    assert (await served.client.put(f"/api/tenants/{A}/alert-mapping", headers=ann, json=mapping)).status_code == 200
    # Reads and a refused write announce nothing.
    assert (await served.client.get(f"/api/tenants/{A}/investigations/{by_person}", headers=ann)).status_code == 200
    assert (await served.client.post(f"/api/tenants/{A}/investigations/{by_program}/cancel", headers=ann)).status_code == 404

    events = _announced(caplog)
    assert collections.Counter(e.action for e in events) == {
        "investigation.start": 2, "investigation.cancel": 1, "investigation.delete": 1, "learning_job.start": 1,
        "alert_mapping.update": 1}, [(e.logger, e.message) for e in events]
    named = {(e.action, e.target): e for e in events}
    ann_id = served.user_id(ANN)
    started_by_program, started_by_person = named["investigation.start", by_program], named["investigation.start", by_person]
    # FORCED CHOICE FC-9: the event's record attribute for the credential is `credential_id` (beside `actor`).
    assert (started_by_program.actor, started_by_program.credential_id, started_by_program.detail) == (
        served.seeded.program_id, served.seeded.credential_id, f"alert {first_alert}")
    assert (started_by_person.actor, started_by_person.credential_id, started_by_person.detail) == (
        ann_id, None, f"alert {second_alert}")
    for action, target in (("investigation.cancel", by_program), ("investigation.delete", by_program),
                           ("learning_job.start", job), ("alert_mapping.update", A)):
        event = named[action, target]
        assert (event.actor, event.credential_id, event.tenant_id) == (ann_id, None, A), action
    assert named["learning_job.start", job].detail == f"investigation {done}; trigger=explicit"


@pytest.mark.postgres
async def test_o9_a_start_through_a_client_credentials_token_names_that_credential(served, token_credential, caplog):
    """A start by a program's access token is announced with the token credential, not the key's. (O9)"""
    [alert_id] = await _alerts(served.dsn, A, NOON)
    caplog.set_level(logging.DEBUG)
    caplog.clear()
    token = program_token(served.keycloak, token_credential)
    started = await _start(served, alert_id, "ci-token-1", served.bearer(token))
    assert started.status_code == 201
    [event] = [e for e in _announced(caplog) if e.action == "investigation.start"]
    assert (event.actor, event.credential_id, event.target) == (
        served.seeded.program_id, token_credential.credential_id, started.json()["investigation_id"])
    assert token_credential.credential_id != served.seeded.credential_id


# --- callers by routes ------------------------------------------------------------------------------

@pytest.mark.postgres
async def test_o5_the_programs_realm_token_is_admitted_for_its_audience_signer_and_lifetime_only(served, token_credential):
    """A token with the right audience passes; a wrong audience, signer or lifetime is refused 401, as is a stranger's bearer. (O5)"""
    path = f"/api/tenants/{A}/alerts"
    right = program_token(served.keycloak, token_credential)
    assert (await served.client.get(path, headers=served.bearer(right))).status_code == 200
    wrong = {
        "audience": program_token(served.keycloak, token_credential, audience="defender-api"),
        "issued by the sign-in realm": program_token(served.keycloak, token_credential, realm=SIGNIN_REALM),
        "expired": program_token(served.keycloak, token_credential, lifetime=-dt.timedelta(minutes=1)),
        "not a token": "not.a.token",
    }
    for why, token in wrong.items():
        refused = await served.client.get(path, headers=served.bearer(token))
        assert refused.status_code == 401, why
        assert refused.headers["www-authenticate"].startswith("Bearer"), why
    assert PROGRAMS_REALM != SIGNIN_REALM  # the control's premise: two realms, two keys


def _declarations(dependant: Any) -> set[str]:
    found = {sub.call.declares for sub in dependant.dependencies if getattr(sub.call, "declares", None)}
    for sub in dependant.dependencies:
        found |= _declarations(sub)
    return found


def _route_table(app: Any) -> list[tuple[str, str, str]]:
    """Every served operation as (method, path, declaration): the permission it names, else `platform`, else its category."""
    from defender.api.app import _served_routes
    from defender.identity.roles import ROLE_PERMISSIONS

    permissions = set(ROLE_PERMISSIONS["admin"])
    table = set()
    for route in _served_routes(app.routes):
        found = _declarations(route.dependant)
        [declared] = (found & {"platform"}) or (found & permissions) or (found - {"person"} or {"person"})
        table |= {(method, route.path, declared) for method in route.methods if method not in {"HEAD", "OPTIONS"}}
    return sorted(table)


UNKNOWN = "0b6f1c1e-3c55-4a4e-9a51-1083000000ff"


def _concrete(path: str, tenant: str) -> str:
    """`path` with the tenant the caller acts in (on a tenant's routes), a system named `tix`, any other id one nothing holds."""
    def fill(found: re.Match[str]) -> str:
        name = found.group(1)
        return "tix" if name == "system_id" else tenant if name == "tenant_id" and path.startswith("/api/tenants/") else UNKNOWN
    return re.sub(r"\{(\w+)(?::\w+)?\}", fill, path)


SYSTEM = {"kind": "ticket", "display_name": "Tickets", "enabled": True, "settings": {}}
CREDENTIALS = {"kind": "static", "credentials": {"api_token": "a-secret-of-sixteen-or-more"}}


def _body(method: str, path: str) -> dict[str, Any]:
    """A body that gets past validation where a route's answer would otherwise be its 422: the systems' bodies."""
    if method not in {"POST", "PUT", "PATCH"}:
        return {}
    return {"json": CREDENTIALS if path.endswith("/credentials") and "/systems" in path
            else SYSTEM if "/systems/" in path else {}}


# Copied literally from tests/api/test_programs_1307_roles.py (PERMISSION_OF, AUTOMATION): the oracle for a program
# caller is this table, never production's `grants` or `ROLE_PERMISSIONS`.
TENANT = "/api/tenants/{}"
PERMISSION_OF = {
    ("GET", f"{TENANT}/alerts"): "work.read",
    ("GET", f"{TENANT}/alerts/{{}}"): "work.read",
    ("POST", f"{TENANT}/investigations"): "investigations.run",
    ("GET", f"{TENANT}/investigations"): "work.read",
    ("GET", f"{TENANT}/investigations/{{}}"): "work.read",
    ("POST", f"{TENANT}/investigations/{{}}/cancel"): "investigations.run",
    ("DELETE", f"{TENANT}/investigations/{{}}"): "investigations.delete",
    ("GET", f"{TENANT}/investigations/{{}}/artifacts/{{}}"): "work.read",
    ("POST", f"{TENANT}/learning-jobs"): "learning.run",
    ("GET", f"{TENANT}/learning-jobs"): "work.read",
    ("GET", f"{TENANT}/learning-jobs/{{}}"): "work.read",
    ("GET", f"{TENANT}/lessons"): "work.read",
    ("GET", f"{TENANT}/systems"): "config.read",
    ("PUT", f"{TENANT}/systems/{{}}"): "config.write",
    ("PUT", f"{TENANT}/systems/{{}}/credentials"): "config.write",
    ("POST", f"{TENANT}/systems/{{}}/check"): "config.write",
    ("GET", f"{TENANT}/alert-mapping"): "config.read",
    ("PUT", f"{TENANT}/alert-mapping"): "config.write",
    ("GET", f"{TENANT}/learning/items"): "work.read",  # #1485 O3
    ("GET", f"{TENANT}/learning/parked-batches"): "work.read",  # #1485 O3
    ("GET", f"{TENANT}/members"): "people.manage",
    ("DELETE", f"{TENANT}/members/{{}}"): "people.manage",
    ("GET", f"{TENANT}/invitations"): "people.manage",
    ("POST", f"{TENANT}/invitations"): "people.manage",
    ("DELETE", f"{TENANT}/invitations/{{}}"): "people.manage",
    ("POST", f"{TENANT}/programs"): "people.manage",
    ("GET", f"{TENANT}/programs"): "people.manage",
    ("DELETE", f"{TENANT}/programs/{{}}"): "people.manage",
    ("POST", f"{TENANT}/programs/{{}}/credentials"): "people.manage",
    ("GET", f"{TENANT}/programs/{{}}/credentials"): "people.manage",
    ("DELETE", f"{TENANT}/programs/{{}}/credentials/{{}}"): "people.manage",
}
AUTOMATION = {"work.read", "investigations.run"}


def _refusal(method: str, path: str, declared: str, outsider: bool, is_person: bool, is_admin: bool) -> int | None:
    """The status a refused caller must get from the permission table (#1307 D4), None for one the route lets in."""
    if outsider:
        return 404  # a non-member, an administrator included, and a program of another tenant
    if declared == "platform":
        return None if is_admin else 403
    if declared == "person":
        return None if is_person else 403
    if declared in {"any", "public"}:
        return None
    if path.startswith("/api/tenants/"):
        key = (method, re.sub(r"\{\w+(?::\w+)?\}", "{}", path))
        assert declared == PERMISSION_OF[key], (key, declared)  # the served declaration is the literal table's
        return None if is_person or PERMISSION_OF[key] in AUTOMATION else 403
    return None if is_person else 403


@pytest.mark.postgres
async def test_o5_every_route_answers_every_caller_as_the_permission_table_says(served, token_credential):
    """Each route, by each caller: refusals are the table's exact status, nothing is 500, only systems and lessons are 501. (O5, O8, O3)"""
    table = _route_table(served.app)
    kinds = {declared for _, _, declared in table}
    assert set(PERMISSION_OF.values()) | {"platform"} <= kinds, kinds  # the table covers every permission and the administrator
    token = program_token(served.keycloak, token_credential)
    tenant_a, tenant_b = A, B
    callers = {  # name -> (headers, is a person, tenant it is a member of, platform administrator)
        "ann": (served.ann(), True, tenant_a, False), "ops": (served.ops(), True, None, True),
        "bob": (served.bob(), True, tenant_b, False), "key": (served.program(), False, tenant_a, False),
        "token": (served.bearer(token), False, tenant_a, False)}
    seen: collections.Counter[tuple[str, str]] = collections.Counter()
    for method, path, declared in table:
        if declared == "public" or path == "/api/auth/logout":  # sign-in redirects reach the identity provider; logout ends the session the matrix uses
            continue
        tenant_route = path.startswith("/api/tenants/")
        for name, (headers, is_person, member_of, is_admin) in callers.items():
            for acts_in in ((A, B) if tenant_route else (None,)):
                url = _concrete(path, acts_in or A)
                got = (await served.client.request(method, url, headers=headers, **_body(method, path))).status_code
                who = f"{name} {method} {url} ({declared})"
                assert got != 500, who
                expected = _refusal(method, path, declared, tenant_route and member_of != acts_in, is_person, is_admin)
                if expected is not None:
                    assert got == expected, who
                    seen[name, "refused"] += 1
                    seen[name, str(expected)] += 1
                    continue
                seen[name, "passed"] += 1
                assert got not in (401, 403), who
                unbacked = "/systems" in path or "/lessons" in path
                assert (got == 501) == unbacked, who
    # Anonymous, from the frontend's origin (so the origin layer lets a state change through to sign-in): 401 everywhere.
    rows = [(m, p) for m, p, d in table if d not in {"public"} and p != "/api/auth/logout"]
    anonymous = {(m, p): (await served.client.request(m, _concrete(p, A), headers={"Origin": ORIGIN},
                                                      **_body(m, p))).status_code for m, p in rows}
    assert set(anonymous.values()) == {401}, {k: v for k, v in anonymous.items() if v != 401}
    # Without the origin, the origin layer answers a state change 403 before sign-in is looked at (#1307 O9).
    foreign = {(m, p): (await served.client.request(m, _concrete(p, A), **_body(m, p))).status_code for m, p in rows}
    assert foreign == {(m, p): 401 if m in {"GET", "HEAD", "OPTIONS"} else 403 for m, p in rows}, foreign
    # Every caller has been both let in and refused somewhere, so none of the table was vacuous.
    assert all(seen[name, outcome] for name in callers for outcome in ("passed", "refused")), seen
    # A program is refused for want of permission (403) as well as for being an outsider (404): the automation row is not everything.
    assert all(seen[name, "403"] for name in ("key", "token")), seen


# --- paging every list, filtered, over more than a page ---------------------------------------------------------------

def _clone(dsn: str, table: str, template: str, count: int, **overrides: str) -> None:
    """`count` copies of row `template` of `jobs.<table>` in one statement: each column as the template's, unless
    `overrides` gives it as an SQL expression of `n` (1..count)."""
    columns = [c for (c,) in execute(dsn, "SELECT column_name FROM information_schema.columns WHERE table_schema = 'jobs' "
                                          "AND table_name = %s ORDER BY ordinal_position", (table,))]
    chosen = ", ".join(overrides.get(c, c) for c in columns)
    execute(dsn, f"INSERT INTO jobs.{table} ({', '.join(columns)}) SELECT {chosen} FROM jobs.{table}, "
                 f"generate_series(1, %s) AS n WHERE id = %s", (count, template))


def _tied(at: dt.datetime, *, step: int = 1) -> str:
    """Times from `at`, three rows to each second (ties), moving by `step` seconds."""
    return f"timestamptz '{at.isoformat()}' + (n / 3) * {step} * interval '1 second'"


async def _walk(served: Served, path: str, params: dict[str, str], limit: int) -> list[dict[str, Any]]:
    """Every page of a list, following each `next_cursor` with the same query, until a page has none."""
    pages: list[dict[str, Any]] = []
    cursor = None
    while len(pages) < 1000:
        query = {**params, "limit": str(limit)} | ({"cursor": cursor} if cursor else {})
        answer = await served.client.get(path, params=query, headers=served.ann(write=False))
        assert answer.status_code == 200, answer.text
        pages.append(answer.json())
        cursor = pages[-1]["next_cursor"]
        if cursor is None:
            return pages
    raise AssertionError(f"{path} {params}: the cursor never ended")


@pytest.mark.postgres
async def test_o6_o10_each_list_walked_by_its_cursors_is_the_filtered_rows_newest_first_each_once(served):
    """Each list, under each filter, at limit 1 and MAX_PAGE, over more than a page with tied times and rows the filter
    leaves out: walking the cursors gives the filtered rows newest first, each once, short only at the end. (O6, O10)"""
    from defender.api.app import MAX_PAGE

    dsn, extra = served.dsn, MAX_PAGE + 4  # more than a page and one beyond it, with ties at every page edge
    [template] = await _alerts(dsn, A, NOON)
    _clone(dsn, "alerts", template, extra, id="gen_random_uuid()", vendor_ticket_id="'bulk-' || n", fired_at=_tied(NOON))
    _clone(dsn, "alerts", template, 6, id="gen_random_uuid()", vendor_ticket_id="'before-' || n",
           fired_at=_tied(NOON - dt.timedelta(hours=1)))
    [kept_alert, other_alert] = await _alerts(dsn, A, NOON - dt.timedelta(days=1), NOON - dt.timedelta(days=2))
    kept, other = await _completed(dsn, A, kept_alert), await _completed(dsn, A, other_alert)
    for investigation, count in ((kept, extra), (other, 5)):
        _clone(dsn, "investigations", investigation, count, id="gen_random_uuid()", request_key="'bulk-' || n",
               created_at=_tied(NOON))
        [(auto_job,)] = execute(dsn, "SELECT id FROM jobs.learning_jobs WHERE investigation_id = %s", (investigation,))
        _clone(dsn, "learning_jobs", auto_job, count, id="gen_random_uuid()", request_key="'bulk-' || n",
               created_at=_tied(NOON))

    def newest_first(rows: list[tuple[Any, ...]], keep: Callable[[tuple[Any, ...]], bool]) -> list[str]:
        return [str(i) for i, at, *_ in sorted((r for r in rows if keep(r)), key=lambda r: (r[1], str(r[0])), reverse=True)]

    alerts = execute(dsn, "SELECT id, fired_at FROM jobs.alerts WHERE tenant_id = %s", (A,))
    investigations = execute(dsn, "SELECT id, created_at, alert_id FROM jobs.investigations WHERE tenant_id = %s", (A,))
    learning = execute(dsn, "SELECT id, created_at, investigation_id FROM jobs.learning_jobs WHERE tenant_id = %s", (A,))
    lists = [  # (path, id field, query, the rows it must answer, the limits walked)
        ("alerts", "alert_id", {"fired_after": NOON.isoformat()}, newest_first(alerts, lambda r: r[1] >= NOON), (1, MAX_PAGE)),
        ("investigations", "investigation_id", {"alert_id": kept_alert},
         newest_first(investigations, lambda r: str(r[2]) == kept_alert), (1, MAX_PAGE)),
        ("learning-jobs", "learning_job_id", {"investigation_id": kept},
         newest_first(learning, lambda r: str(r[2]) == kept), (1, MAX_PAGE))]
    lists += [(path, field, {}, newest_first(rows, lambda r: True), (MAX_PAGE,))  # unfiltered: one page edge suffices
              for path, field, rows in (("alerts", "alert_id", alerts), ("investigations", "investigation_id", investigations),
                                        ("learning-jobs", "learning_job_id", learning))]
    for path, field, query, expected, limits in lists:
        assert len(expected) > MAX_PAGE + 1, (path, query)  # premise: more than a page and its probe row
        for limit in limits:
            pages = await _walk(served, f"/api/tenants/{A}/{path}", query, limit)
            case = (path, query, limit)
            assert [item[field] for page in pages for item in page["items"]] == expected, case
            assert [len(p["items"]) for p in pages[:-1]] == [limit] * (len(pages) - 1), case
            assert 0 < len(pages[-1]["items"]) <= limit, case


# --- #1161 piece 1: sign-in carries a return path; the API under /api ----------------------------------------
# The real app (`serving`) over real stores, Keycloak's back channel the transport and its front channel the pure
# `authorize`. The in-process matrix of outcomes is in `test_signin_1161.py`; here the wiring is the real server's.

#: The callback as the provider is told it (B3: derived from the frontend origin, never set).
_CALLBACK = f"{ORIGIN}/api/auth/callback"
INV = "0b6f1c1e-3c55-4a4e-9a51-116100000001"
TICKET_PATH = f"/t/{A}/investigations/{INV}"
OTHER_PATH = f"/t/{A}/investigations/0b6f1c1e-3c55-4a4e-9a51-116100000002"


async def _login(served: Served, back: str | None, *, status: int = 302) -> tuple[str, dict[str, Any]]:
    """Sign-in start with `back` as its return path (None: no parameter): the authorize URL and the cookies it sets."""
    r = await served.client.get("/api/auth/login", params={} if back is None else {"return": back})
    assert r.status_code == status, (r.status_code, r.text)
    return r.headers["location"], set_cookies(r)


def _prelogin(cookies: dict[str, Any]) -> tuple[str, Any]:
    """The one pre-login cookie a sign-in start set (every cookie but the session's)."""
    [(name, morsel)] = [(n, m) for n, m in cookies.items() if n != SESSION_COOKIE]
    return name, morsel


async def _callback(served: Served, url: str, sent: dict[str, str]) -> httpx.Response:
    """The browser arriving at the callback URL `url` (the front channel's answer) with the cookies `sent`."""
    split = urllib.parse.urlsplit(url)
    assert f"{split.scheme}://{split.netloc}{split.path}" == _CALLBACK, url
    headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in sent.items())} if sent else {}
    return await served.client.get(f"{split.path}?{split.query}", headers=headers)


def _landing(r: httpx.Response) -> str:
    """A 303's `Location`, after checking it is a path (never an absolute URL, B3) outside the API."""
    assert r.status_code == 303, (r.status_code, r.text)
    target = r.headers["location"]
    split = urllib.parse.urlsplit(target)
    assert (split.scheme, split.netloc) == ("", ""), target
    assert split.path != "/api", target
    assert not split.path.startswith("/api/"), target
    return target


async def _signed_in(served: Served, back: str | None) -> httpx.Response:
    """Ann signs in from start to callback with return path `back`; the callback's answer."""
    account = await link_account(served.dsn, ANN)
    url, cookies = await _login(served, back)
    name, morsel = _prelogin(cookies)
    return await _callback(served, authorize(url, account), {name: morsel.value})


def _failed(r: httpx.Response) -> tuple[str, dict[str, str]]:
    """The sign-in-failed screen a callback 303'd to: its reason and the rest of its query; no session was opened."""
    landed = urllib.parse.urlsplit(_landing(r))
    assert landed.path == "/sign-in-failed", landed
    assert SESSION_COOKIE not in set_cookies(r), r.headers.get_list("set-cookie")
    query = dict(urllib.parse.parse_qsl(landed.query, strict_parsing=True))
    return query.pop("reason"), query


@pytest.mark.postgres
@pytest.mark.parametrize("back", [TICKET_PATH, "/", None], ids=["investigation", "root", "absent"])
async def test_1161_p2_sign_in_lands_on_its_return_path_byte_for_byte_and_opens_a_session(served, back):
    """The callback 303s to exactly the judged return path (the root when absent) and opens a working session. (P2, B4)"""
    r = await _signed_in(served, back)
    assert _landing(r) == (back or "/")
    session = set_cookies(r)[SESSION_COOKIE]
    me = await served.client.get("/api/me", headers=person(session.value))
    assert me.status_code == 200, me.text
    assert me.json()["user"]["email"] == ANN, me.text


@pytest.mark.postgres
@pytest.mark.parametrize("back", [
    "", "t/a", "//evil.example/x", "/\\evil.example/x", "https://evil.example/x", "/t/\x01x", "/api", "/api/me",
    TICKET_PATH + "?from=ticket", TICKET_PATH + "/", TICKET_PATH.upper(), "/sign-in-failed",
], ids=["empty", "relative", "scheme-relative", "backslash", "absolute", "control", "api", "api-route", "query",
        "trailing-slash", "case", "failed-screen"])
async def test_1161_b2_a_refused_return_path_is_a_bad_request_and_starts_nothing(served, back):
    """A present `return` P2 refuses: 303 to `/sign-in-failed?reason=bad-request`, no cookie, no provider redirect. (B2, B4)"""
    r = await served.client.get("/api/auth/login", params={"return": back})
    assert r.status_code == 303, (r.status_code, r.text)
    assert r.headers["location"] == "/sign-in-failed?reason=bad-request"
    assert not r.headers.get_list("set-cookie")
    assert (await _login(served, TICKET_PATH))[0]  # control: a member starts


@pytest.mark.postgres
async def test_1161_b3_the_redirect_uri_is_derived_from_the_origin_and_the_setting_is_gone(served, tmp_path):
    """The authorize URL names `<origin>/api/auth/callback` whatever the request's `Host`, and a stale `DEFENDER_KEYCLOAK_REDIRECT_URI` changes nothing. (B3)"""
    from defender.api_server import Settings

    url, _ = await _login(served, None)
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["redirect_uri"] == [_CALLBACK]
    # Not the request's: a start that arrives under another `Host` (or a forwarded one) still names the configured origin.
    foreign = await served.client.get("/api/auth/login", headers={
        "Host": "attacker.example", "X-Forwarded-Host": "attacker.example", "X-Forwarded-Proto": "https"})
    assert foreign.status_code == 302, (foreign.status_code, foreign.text)
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(foreign.headers["location"]).query)["redirect_uri"] == [_CALLBACK]
    environ = environment(tmp_path, dsn=served.dsn)
    assert "DEFENDER_KEYCLOAK_REDIRECT_URI" not in environ
    Settings.from_environ({**environ, "DEFENDER_KEYCLOAK_REDIRECT_URI": "not a url"})  # unread: no refusal
    assert (await _signed_in(served, None)).status_code == 303  # the exchange used that URI: the fake binds it


@pytest.mark.postgres
async def test_1161_d6_two_sign_ins_in_flight_each_complete_to_their_own_return_path(served):
    """Each attempt sets its own `__Host-` cookie; each callback reads and clears only its own. (D6, B1)"""
    account = await link_account(served.dsn, ANN)
    first, second = TICKET_PATH, OTHER_PATH
    (url1, c1), (url2, c2) = await _login(served, first), await _login(served, second)
    (name1, m1), (name2, m2) = _prelogin(c1), _prelogin(c2)
    assert name1 != name2, "one pre-login cookie name for both attempts: the second overwrites the first"
    for name, m in ((name1, m1), (name2, m2)):
        assert name.startswith("__Host-"), name
        assert m["path"] == "/", m.OutputString()
        assert not m["domain"], m.OutputString()
        assert m["httponly"], m.OutputString()
        assert m["secure"], m.OutputString()
        assert m["samesite"].lower() == "lax", m.OutputString()
        assert m["max-age"] == "600", m.OutputString()
    jar = {name1: m1.value, name2: m2.value}
    done2 = await _callback(served, authorize(url2, account), jar)
    assert _landing(done2) == second
    cleared = set_cookies(done2)
    assert deleted(cleared[name2]), done2.headers.get_list("set-cookie")
    assert name1 not in cleared, done2.headers.get_list("set-cookie")
    done1 = await _callback(served, authorize(url1, account), {name1: m1.value})
    assert _landing(done1) == first


@pytest.mark.postgres
async def test_1161_d6_b4_a_callback_without_its_own_cookie_never_uses_another_attempts_return_path(served):
    """Missing, another attempt's or an unprefixed twin: `prelogin-missing`, no `return`, only its own cookie cleared. (D6, B4)"""
    account = await link_account(served.dsn, ANN)
    (url1, c1), (_url2, c2) = await _login(served, TICKET_PATH), await _login(served, OTHER_PATH)
    name1, m1 = _prelogin(c1)
    name2, m2 = _prelogin(c2)
    unprefixed = {name1.removeprefix("__Host-"): m1.value}
    for sent in ({name2: m2.value}, {}, unprefixed):
        r = await _callback(served, authorize(url1, account), sent)
        assert _failed(r) == ("prelogin-missing", {})
        # The callback clears its own attempt's cookie on every answer, held or not; nothing else is touched.
        cleared = set_cookies(r)
        assert list(cleared) == [name1], r.headers.get_list("set-cookie")
        assert deleted(cleared[name1]), r.headers.get_list("set-cookie")
    assert _landing(await _callback(served, authorize(url1, account), {name1: m1.value})) == TICKET_PATH  # control


def _token_answer(status: int, body: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _request: httpx.Response(status, json=body)


@pytest.mark.postgres
@pytest.mark.parametrize(("reason", "linked", "token"), [
    ("login-attempt-invalid", True, (400, {"error": "invalid_grant", "error_description": "Code not valid"})),
    ("unknown-account", False, None),
    ("unavailable", True, (503, {})),
])
async def test_1161_b4_every_failed_callback_is_a_303_to_the_failed_screen_with_its_reason_and_return(
        served, reason, linked, token):
    """A refused or unavailable callback: 303 to a frontend path with the reason and the attempt's `return`; its cookie is cleared. (B4, S1)"""
    account = await link_account(served.dsn, ANN) if linked else "kc-nobody"
    if token is not None:
        served.keycloak.answers[(SIGNIN_REALM, "token")] = _token_answer(*token)
    url, cookies = await _login(served, TICKET_PATH)
    name, morsel = _prelogin(cookies)
    r = await _callback(served, authorize(url, account), {name: morsel.value})
    assert _failed(r) == (reason, {"return": TICKET_PATH})
    assert deleted(set_cookies(r)[name]), r.headers.get_list("set-cookie")


@pytest.mark.postgres
async def test_1161_b4_an_internal_fault_on_the_callback_is_logged_as_an_error_and_answers_error(served, caplog):
    """The identity store breaks after the token step (a real fault: its table is gone): 303 `error`, no `return`, cookie cleared, error logged. (B4, S1)"""
    account = await link_account(served.dsn, ANN)
    url, cookies = await _login(served, TICKET_PATH)
    name, morsel = _prelogin(cookies)
    healthy = await _signed_in(served, None)  # control: the same path signs in while the store is whole
    assert healthy.status_code == 303
    caplog.clear()
    execute(served.dsn, "ALTER TABLE identity.users RENAME TO users_moved")
    r = await _callback(served, authorize(url, account), {name: morsel.value})
    assert _failed(r) == ("error", {})
    assert deleted(set_cookies(r)[name]), r.headers.get_list("set-cookie")
    # The callback's own record (logger `defender.api.app`, its exception the store's fault), not the identity loop's
    # `a sender pass failed`, which also logs ERROR while the table is gone.
    own = [x for x in caplog.records if x.name == "defender.api.app" and x.levelno >= logging.ERROR
           and x.exc_info is not None and "users" in str(x.exc_info[1])]
    assert own, [(x.name, x.getMessage()) for x in caplog.records if x.levelno >= logging.ERROR]


@pytest.mark.postgres
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD"])
@pytest.mark.parametrize("path", ["/api/auth/login", "/api/auth/callback"])
async def test_1161_s1_the_sign_in_routes_answer_code_to_any_method_but_get(served, path, method):
    """On the real app a non-GET is 403 or 405 and sets no cookie; GET is the control. (B4, S1)"""
    r = await served.client.request(method, path, headers={"Origin": ORIGIN})
    assert r.status_code in (403, 405), r.status_code
    assert not r.headers.get_list("set-cookie")
    assert (await served.client.get("/api/auth/login")).status_code == 302


@pytest.mark.postgres
async def test_1161_b3_every_create_answers_a_location_path_under_api_that_reads_back(served):
    """Investigation, learning job and tenant creates answer a `Location` that is a path under `/api` and reads the new record. (B3, C36)"""
    [alert_id] = await _alerts(served.dsn, A, NOON)
    started = await _start(served, alert_id, "loc-1")
    assert started.status_code == 201, started.text
    inv = started.json()["investigation_id"]
    admin = await served.client.post("/api/admin/tenants", headers=served.ops())
    assert admin.status_code == 202, admin.text
    for response, path in ((started, f"/api/tenants/{A}/investigations/{inv}"),
                           (admin, f"/api/admin/tenants/{admin.json()['tenant_id']}")):
        location = response.headers["location"]
        assert location == path, location  # a path: no scheme, no host
        read = await served.client.get(location, headers=served.ops() if "/admin/" in location else served.ann(write=False))
        assert read.status_code == 200, read.text


@pytest.mark.postgres
async def test_1161_b3_a_learning_job_create_answers_a_location_path(served):
    """The learning-job create's `Location` is a path under `/api`. (B3, C36)"""
    [alert_id] = await _alerts(served.dsn, A, NOON)
    inv = await _completed(served.dsn, A, alert_id)
    r = await served.client.post(f"/api/tenants/{A}/learning-jobs", headers=served.ann(),
                                 json={"investigation_id": inv, "client_request_id": "loc-2"})
    assert r.status_code == 201, r.text
    assert r.headers["location"] == f"/api/tenants/{A}/learning-jobs/{r.json()['learning_job_id']}"


@pytest.mark.postgres
async def test_1161_b3_an_alert_mapping_create_answers_a_location_path_and_a_replace_answers_none(served):
    """The first save of a tenant's mapping is a 201 whose `Location` is the mapping's path; a replace is a 200 with none. (B3, C36)"""
    execute(served.dsn, "DELETE FROM tenancy.alert_mappings WHERE tenant_id = %s", (A,))  # a tenant that has none yet
    mapping = {entry: f"vendor.{entry}" for entry in MAPPING_ENTRIES}
    assert (await served.client.get(f"/api/tenants/{A}/alert-mapping", headers=served.ann(write=False))).status_code == 404
    created = await served.client.put(f"/api/tenants/{A}/alert-mapping", headers=served.ann(), json=mapping)
    assert created.status_code == 201, created.text
    assert created.headers["location"] == f"/api/tenants/{A}/alert-mapping"
    assert (await served.client.get(created.headers["location"], headers=served.ann(write=False))).json() == mapping
    replaced = await served.client.put(f"/api/tenants/{A}/alert-mapping", headers=served.ann(), json=mapping)
    assert replaced.status_code == 200  # control: a replace creates nothing
    assert "location" not in replaced.headers


@pytest.mark.postgres
async def test_1161_b3_a_cookie_alone_reads_the_api_and_no_origin_is_granted_cors(served):
    """The session cookie alone is enough; no response grants another origin access, preflight included. (B5)"""
    elsewhere = "https://evil.example"
    me = await served.client.get("/api/me", headers={**served.ann(write=False), "Origin": elsewhere})
    assert me.status_code == 200, me.text
    assert me.json()["user"]["email"] == ANN, me.text
    preflight = await served.client.options("/api/me", headers={
        "Origin": elsewhere, "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})
    for r in (me, preflight):
        assert not [h for h in r.headers if h.lower().startswith("access-control-")], (r.status_code, dict(r.headers))


@pytest.mark.postgres
@pytest.mark.parametrize(("value", "served_docs"), [("true", True), (None, False), ("false", False), ("1", False),
                                                    ("TRUE", False), ("", False), ("True", False), ("yes", False),
                                                    ("on", False), ("y", False), (" true", False), ("true ", False),
                                                    ("true\n", False), ("enabled", False)])
async def test_1161_b10_the_docs_pages_are_served_only_when_the_dev_setting_is_true(
        tenants, tmp_path, value, served_docs):
    """`DEFENDER_API_DOCS=true` serves `/api/docs` and `/api/redoc`; anything else, or unset, serves neither; the document always ships. (B10)"""
    from defender.api_server import Settings, serving

    extra = {} if value is None else {"DEFENDER_API_DOCS": value}
    settings = Settings.from_environ({**environment(tmp_path, dsn=tenants), **extra})
    async with serving(settings, transport=FakeKeycloak()) as running, \
            httpx.AsyncClient(transport=httpx.ASGITransport(app=running.app), base_url=ORIGIN) as client:
        got = [(await client.get(p)).status_code for p in ("/api/docs", "/api/redoc")]
        assert got == ([200, 200] if served_docs else [404, 404]), got
        assert (await client.get("/api/openapi.json")).status_code == 200
        # B3: with the docs on, every route (their redirect page included) is still under `/api`, and none answers at the root.
        assert [p for p in route_paths(running.app.routes) if not p.startswith("/api/")] == []
        assert (await client.get("/api/docs/oauth2-redirect")).status_code == (200 if served_docs else 404)
        assert [(await client.get(p)).status_code for p in ("/docs", "/redoc", "/docs/oauth2-redirect", "/openapi.json")] == [404] * 4
