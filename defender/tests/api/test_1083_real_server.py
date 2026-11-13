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
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from defender.tests.support.api._server1083 import (
    A,
    ANN,
    B,
    ORIGIN,
    Child,
    FakeKeycloak,
    Seeded,
    environment,
    free_port,
    person,
    program,
    seed_identity,
)
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
    return await served.client.post(f"/tenants/{A}/investigations", headers=headers or served.ann(),
                                    json={"alert_id": alert_id, "client_request_id": key})


# --- alerts -----------------------------------------------------------------------------------------

@pytest.mark.postgres
async def test_o6_alerts_list_newest_first_by_window_with_a_cursor_and_read_one(served):
    """Alerts page newest first with a cursor, narrow by window, and read one with its raw text. (O6)"""
    early, middle, late = (NOON + dt.timedelta(hours=h) for h in (-5, -3, -1))
    a_early, a_middle, a_late = await _alerts(served.dsn, A, early, middle, late)
    await _alerts(served.dsn, B, late)  # another tenant's alert never lists here

    first = (await served.client.get(f"/tenants/{A}/alerts", params={"limit": 2}, headers=served.ann(write=False))).json()
    assert [a["alert_id"] for a in first["items"]] == [a_late, a_middle]
    assert first["next_cursor"] is not None
    second = (await served.client.get(f"/tenants/{A}/alerts", params={"limit": 2, "cursor": first["next_cursor"]},
                                      headers=served.ann(write=False))).json()
    assert ([a["alert_id"] for a in second["items"]], second["next_cursor"]) == ([a_early], None)

    window = await served.client.get(f"/tenants/{A}/alerts", headers=served.ann(write=False),
                                     params={"fired_after": (middle - dt.timedelta(hours=1)).isoformat()})
    assert [a["alert_id"] for a in window.json()["items"]] == [a_late, a_middle]

    one = await served.client.get(f"/tenants/{A}/alerts/{a_late}", headers=served.ann(write=False))
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

    listed = await served.client.get(f"/tenants/{A}/investigations", params={"alert_id": alert_id},
                                     headers=served.ann(write=False))
    assert [i["investigation_id"] for i in listed.json()["items"]] == [investigation["investigation_id"]]
    read = await served.client.get(f"/tenants/{A}/investigations/{investigation['investigation_id']}",
                                   headers=served.ann(write=False))
    assert read.json() == investigation

    cancelled = await served.client.post(
        f"/tenants/{A}/investigations/{investigation['investigation_id']}/cancel", headers=served.ann())
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
    path = f"/tenants/{A}/investigations/{inv}"

    assert (await served.client.delete(path, headers=served.ann())).status_code == 409  # live
    assert (await served.client.post(f"{path}/cancel", headers=served.ann())).status_code == 200
    assert (await served.client.post(f"{path}/cancel", headers=served.ann())).status_code == 409  # ended

    assert (await served.client.get(path, headers=served.ann(write=False))).status_code == 200  # control
    assert (await served.client.delete(path, headers=served.ann())).status_code == 204
    assert (await served.client.get(path, headers=served.ann(write=False))).status_code == 404
    listed = await served.client.get(f"/tenants/{A}/investigations", headers=served.ann(write=False))
    assert listed.json()["items"] == []
    assert row(served.dsn, inv) is None


# --- learning jobs ----------------------------------------------------------------------------------

@pytest.mark.postgres
async def test_o6_learning_jobs_start_replay_list_by_investigation_and_read(served):
    """A learning job starts once per request id, lists by investigation and reads what the store holds. (O6)"""
    first_alert, second_alert = await _alerts(served.dsn, A, NOON, NOON + dt.timedelta(hours=1))
    inv, other = await _completed(served.dsn, A, first_alert), await _completed(served.dsn, A, second_alert)
    ann = served.ann()

    started = await served.client.post(f"/tenants/{A}/learning-jobs", headers=ann,
                                       json={"investigation_id": inv, "client_request_id": "relearn-1"})
    assert started.status_code == 201
    job = started.json()
    assert (job["investigation_id"], job["alert_id"], job["trigger"], job["status"]) == (inv, first_alert, "explicit", "queued")
    again = await served.client.post(f"/tenants/{A}/learning-jobs", headers=ann,
                                     json={"investigation_id": inv, "client_request_id": "relearn-1"})
    assert (again.status_code, again.json()) == (200, job)

    read = await served.client.get(f"/tenants/{A}/learning-jobs/{job['learning_job_id']}", headers=served.ann(write=False))
    assert read.json() == job
    listed = await served.client.get(f"/tenants/{A}/learning-jobs", params={"investigation_id": inv},
                                     headers=served.ann(write=False))
    held = execute(served.dsn, "SELECT id FROM jobs.learning_jobs WHERE investigation_id = %s", (inv,))
    assert {j["learning_job_id"] for j in listed.json()["items"]} == {str(i) for (i,) in held}
    assert job["learning_job_id"] in {j["learning_job_id"] for j in listed.json()["items"]}
    everything = await served.client.get(f"/tenants/{A}/learning-jobs", headers=served.ann(write=False))
    assert {j["investigation_id"] for j in everything.json()["items"]} == {inv, other}  # control: the filter narrowed it


@pytest.mark.postgres
async def test_o6_a_learning_job_of_an_investigation_that_did_not_complete_conflicts(served):
    """A re-learn of a queued investigation answers 409; of a completed one, 201. (O6)"""
    queued_alert, done_alert = await _alerts(served.dsn, A, NOON, NOON + dt.timedelta(hours=1))
    queued = (await _start(served, queued_alert, "req-1")).json()["investigation_id"]
    done = await _completed(served.dsn, A, done_alert)
    body = {"client_request_id": "relearn-1"}
    refused = await served.client.post(f"/tenants/{A}/learning-jobs", headers=served.ann(),
                                       json={"investigation_id": queued, **body})
    accepted = await served.client.post(f"/tenants/{A}/learning-jobs", headers=served.ann(),
                                        json={"investigation_id": done, **body})
    assert (refused.status_code, accepted.status_code) == (409, 201)


# --- alert mapping ----------------------------------------------------------------------------------

@pytest.mark.postgres
async def test_the_alert_mapping_reads_through_its_own_port_while_systems_refuse(served):
    """The alert mapping answers the tenant's saved mapping although the systems port refuses whole. (G2, O6)"""
    from defender.api.models import AlertMapping

    got = await served.client.get(f"/tenants/{A}/alert-mapping", headers=served.ann(write=False))
    assert got.status_code == 200
    assert got.json() == {entry: FIXTURE_ALERT_MAPPING.get(entry) for entry in AlertMapping.model_fields}
    assert (await served.client.get(f"/tenants/{A}/systems", headers=served.ann(write=False))).status_code == 501


@pytest.mark.postgres
async def test_o6_a_mapping_replace_answers_what_the_store_holds(served):
    """A replace answers the mapping the store now holds, and a read after it answers the same. (O6, Am-8)"""
    replacement = {entry: f"vendor.{entry}" for entry in MAPPING_ENTRIES} | {"summary": None}
    put = await served.client.put(f"/tenants/{A}/alert-mapping", headers=served.ann(), json=replacement)
    assert put.status_code == 200  # the tenant had one: a replace, not a creation
    assert put.json() == replacement
    assert put.json() == await _held_async(served.dsn, A)
    got = await served.client.get(f"/tenants/{A}/alert-mapping", headers=served.ann(write=False))
    assert got.json() == put.json()
    assert await _held_async(served.dsn, B) == {e: FIXTURE_ALERT_MAPPING.get(e) for e in MAPPING_ENTRIES}  # B untouched


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
    job = (await served.client.post(f"/tenants/{A}/learning-jobs", headers=served.ann(),
                                    json={"investigation_id": done, "client_request_id": "r"})).json()["learning_job_id"]
    reads = ["/alerts", f"/alerts/{alert_id}", "/investigations", f"/investigations/{inv}", "/learning-jobs",
             f"/learning-jobs/{job}", "/alert-mapping"]
    for path in reads:
        assert (await served.client.get(f"/tenants/{A}{path}", headers=served.ann(write=False))).status_code == 200, path
        assert (await served.client.get(f"/tenants/{A}{path}", headers=served.bob(write=False))).status_code == 404, path
    assert (await served.client.post(f"/tenants/{A}/investigations/{inv}/cancel", headers=served.bob())).status_code == 404
    assert (await served.client.delete(f"/tenants/{A}/investigations/{inv}", headers=served.bob())).status_code == 404
    assert (await _start(served, alert_id, "req-2", served.bob())).status_code == 404
    assert row(served.dsn, inv)["stage"] == "queued"  # control: nothing of Bob's reached it

    # Bob's own tenant does not hold A's ids: the same id, read by its own member on its own path, is absent.
    assert (await served.client.get(f"/tenants/{B}/investigations/{inv}", headers=served.bob(write=False))).status_code == 404
    assert (await served.client.get(f"/tenants/{B}/alerts/{alert_id}", headers=served.bob(write=False))).status_code == 404
    assert (await served.client.get(f"/tenants/{B}/alerts", headers=served.bob(write=False))).json()["items"] == []


# --- tenant administration --------------------------------------------------------------------------

@pytest.mark.postgres
async def test_o7_an_administrator_creates_a_tenant_row_the_lifecycle_will_work(served):
    """`POST /admin/tenants` writes a `creating` tenant row with `create` pending, which reads back through the admin routes. (O7)"""
    created = await served.client.post("/admin/tenants", headers=served.ops())
    assert created.status_code == 202
    tenant_id = created.json()["tenant_id"]
    assert execute(served.dsn, "SELECT state, pending_action FROM tenancy.tenants WHERE id = %s",
                   (tenant_id,)) == [("creating", "create")]
    read = await served.client.get(f"/admin/tenants/{tenant_id}", headers=served.ops())
    assert read.status_code == 200
    assert tenant_id in {t["tenant_id"] for t in (await served.client.get("/admin/tenants", headers=served.ops())).json()["items"]}
    # The caller is judged by the identity store: a member who is no platform administrator is refused.
    assert (await served.client.post("/admin/tenants", headers=served.ann())).status_code in (403, 404)
    assert len(execute(served.dsn, "SELECT id FROM tenancy.tenants WHERE id = %s", (tenant_id,))) == 1


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
    assert (await served.client.get(f"/tenants/{A}/alerts", headers=served.ann(write=False))).status_code == 200  # control
    for method, path, payload, issue in cases:
        refused = await served.client.request(method, f"/tenants/{A}{path}", headers=served.ann(), json=payload)
        assert refused.status_code == 501, path
        assert refused.headers["content-type"].startswith("application/problem+json")
        # FORCED CHOICE FC-8: the problem's `type` stays unpinned; the detail names the issue by its number.
        assert (refused.json()["title"], refused.json()["status"]) == ("Not Implemented", 501)
        assert issue in refused.json()["detail"], path
        outsider = await served.client.request(method, f"/tenants/{A}{path}", headers=served.bob(), json=payload)
        assert outsider.status_code == 404, path


@pytest.mark.postgres
async def test_o8_the_real_servers_openapi_declares_the_501_on_every_systems_and_lessons_route(served):
    """Every documented operation on systems and lessons declares 501; the work routes do not. (O8, Am-2)"""
    document = (await served.client.get("/openapi.json")).json()
    unbacked = _unbacked(document)
    assert len(unbacked) >= 5
    for path, method in unbacked:
        assert "501" in document["paths"][path][method]["responses"], (path, method)
    for path, item in document["paths"].items():
        if "/alerts" in path or "/investigations" in path:
            assert all("501" not in op["responses"] for op in item.values()), path
    assert "not yet real" not in document["info"].get("summary", "")


@pytest.mark.postgres
async def test_o8_a_real_process_serves_the_same_openapi_document_as_the_app(served):
    """A started program answers `/openapi.json` declaring the 501s, equal to the in-process app's document. (O8, Am-2)"""
    child = Child.faked(environment(served.tmp_path, dsn=served.dsn, port=free_port()))
    try:
        assert child.ready(), "the program should come up on the migrated database"
        over_the_wire = httpx.get(f"{child.base_url}/openapi.json", timeout=10).json()
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
    assert (await served.client.post(f"/tenants/{A}/investigations/{by_program}/cancel", headers=ann)).status_code == 200
    assert (await served.client.delete(f"/tenants/{A}/investigations/{by_program}", headers=ann)).status_code == 204
    job = (await served.client.post(f"/tenants/{A}/learning-jobs", headers=ann,
                                    json={"investigation_id": done, "client_request_id": "relearn-1"})).json()["learning_job_id"]
    mapping = {entry: FIXTURE_ALERT_MAPPING.get(entry) for entry in MAPPING_ENTRIES} | {"summary": None}
    assert (await served.client.put(f"/tenants/{A}/alert-mapping", headers=ann, json=mapping)).status_code == 200
    # Reads and a refused write announce nothing.
    assert (await served.client.get(f"/tenants/{A}/investigations/{by_person}", headers=ann)).status_code == 200
    assert (await served.client.post(f"/tenants/{A}/investigations/{by_program}/cancel", headers=ann)).status_code == 404

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
