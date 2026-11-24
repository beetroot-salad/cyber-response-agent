"""#1471 slice A, the API: start and poll of readiness and adoption over the real server, the real job store and the real
record store (R1, A1, R2, A2, R13-2, B1, C7, C8). Tenant A's admin is Ann, tenant B's is Bob, `ops` the platform
administrator, `program` a program of A (no config permission). Names are `test-surface.md` §1-§2. Postgres-gated."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
import pytest

from defender.tests.support.api._config1470 import TICKET, TOKEN, ScriptedOpenBao, problem_text, served_config
from defender.tests.support.api._server1083 import ORIGIN, A, B, person
from defender.tests.support.jobs._host_requests1471 import (
    ADOPTION,
    FRESH,
    KNOWLEDGE,
    NO_BASE_FILES,
    READINESS,
    READY_RESULT,
    SHIPS_BASE_FILES,
    adopted,
    host_child,
    host_row,
    host_rows,
    host_worker,
    plant,
    planted_checkout,  # noqa: F401 (fixture)
    refused,
)
from defender.tests.support.jobs._jobs1342 import JobsAudit, job_store, register_tenant
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

@pytest.fixture
async def scripted(request, migrated_database: str, tmp_path):
    """The real server started over a planted checkout (`$DEFENDER_DIR`), so which adapter ships base files is the test's."""
    request.getfixturevalue("planted_checkout")  # before the server builds its catalog
    async with served_config(migrated_database, tmp_path, scripted=ScriptedOpenBao()) as configured:
        record_repo_page(configured.dsn, A, REPO_PAGE_A)
        yield configured


#: Tenant A's repository page as the lifecycle records it (`tenancy.tenants.repo_url`, `<forge public URL>/<repo>`): a
#: dev-shaped one, plain http with a port, so a link built from a hostname alone would miss it.
REPO_PAGE_A = f"http://forge.defender.test:8000/t-{A}/knowledge"


def record_repo_page(dsn: str, tenant: str, page: str | None) -> None:
    execute(dsn, "UPDATE tenancy.tenants SET repo_url = %s WHERE id = %s", (page, tenant))


C = fixture_uuid("1471:tenant-c")
UNKNOWN = "00000000-0000-4000-8000-0000000014a1"
KEYS = {"status", "created_at", "started_at", "finished_at", "result", "failure_reason", "failure_message"}


def ops(s) -> dict[str, str]:
    return person(s.seeded.ops_session, write=True)


async def start_readiness(s, headers: Mapping[str, str] | None = None, tenant: str = A) -> httpx.Response:
    return await s.client.post(f"/api/tenants/{tenant}/readiness", headers=headers or s.ann())


async def start_adoption(s, system: str, headers: Mapping[str, str] | None = None, tenant: str = A) -> httpx.Response:
    return await s.client.post(f"/api/tenants/{tenant}/systems/{system}/adoptions", headers=headers or s.ann())


async def admin_start(s, kind: str, tenant: str = A, system: str = TICKET) -> httpx.Response:
    path = f"/api/admin/tenants/{tenant}/" + ("readiness" if kind == "readiness" else f"systems/{system}/adoptions")
    return await s.client.post(path, headers=ops(s))


def poll_path(kind: str, request_id: str, tenant: str = A, *, admin: bool = False) -> str:
    base = f"/api/admin/tenants/{tenant}" if admin else f"/api/tenants/{tenant}"
    return f"{base}/{'readiness' if kind == 'readiness' else 'adoptions'}/{request_id}"


async def poll(s, kind: str, request_id: str, tenant: str = A, *, admin: bool = False) -> httpx.Response:
    headers = ops(s) if admin else (s.ann(write=False) if tenant == A else s.bob(write=False))
    return await s.client.get(poll_path(kind, request_id, tenant, admin=admin), headers=headers)


def id_of(kind: str, body: Mapping[str, Any]) -> str:
    return body["readiness_id" if kind == "readiness" else "adoption_id"]


def carried_with_base_files() -> str:
    return SHIPS_BASE_FILES


def carried_without_base_files() -> str:
    return NO_BASE_FILES


def forge_origin(dsn: str, tenant: str) -> str:
    return execute(dsn, "SELECT origin FROM tenancy.forge_wiring WHERE tenant_id = %s", (tenant,))[0][0]


def pr_page(tenant: str, number: int) -> str:
    """#1592 (amends #1471 A3; finalize, #1623 review): the pull request's page is the tenant's recorded repository page
    (the one the Knowledge repo link opens) plus `/pulls/<n>`, never the wiring's private origin."""
    assert tenant == A, "only tenant A has a recorded repository page"
    return f"{REPO_PAGE_A}/pulls/{number}"


# --- R1: start ------------------------------------------------------------------------------------------------------

async def test_r1_a_config_writer_starts_a_readiness_check_201_with_a_location_that_reads_it_and_it_is_audited(scripted, caplog):
    """201, `Location` naming the poll route, the request object queued with null live fields; the row records Ann and
    `readiness.start` is announced. (R1, R2)"""
    audit = JobsAudit(caplog)
    r = await start_readiness(scripted)
    assert r.status_code == 201, r.text
    body = r.json()
    assert KEYS | {"readiness_id", "systems_without_credentials"} <= set(body)
    assert (body["status"], body["result"], body["started_at"], body["finished_at"], body["failure_reason"],
            body["systems_without_credentials"]) == ("queued", None, None, None, None, None)
    rid = body["readiness_id"]
    assert r.headers["Location"] == poll_path("readiness", rid)
    again = await scripted.client.get(r.headers["Location"], headers=scripted.ann(write=False))
    assert again.status_code == 200
    assert again.json() == body
    [row] = host_rows(scripted.dsn)
    assert (row["id"], row["tenant_id"], row["kind"], row["stage"], row["requester"]) == (
        rid, A, "readiness", "queued", scripted.user_id("ann@a.example"))
    assert [(e.action, e.actor, e.tenant_id, e.target) for e in audit.events()] == [
        ("readiness.start", scripted.user_id("ann@a.example"), A, rid)]


async def test_r1_a_start_while_one_is_queued_answers_200_with_that_one_no_location_no_row_no_event(scripted, caplog):
    """Two requests while queued give one id; the replay is 200 with no `Location` and announces nothing. (R1)"""
    audit = JobsAudit(caplog)
    first = await start_readiness(scripted)
    assert [e.action for e in audit.events()] == ["readiness.start"], "control: the first start is announced"
    caplog.clear()  # repair 5: the replay's events alone
    second = await start_readiness(scripted)
    assert (first.status_code, second.status_code) == (201, 200)
    assert second.json()["readiness_id"] == first.json()["readiness_id"]
    assert "Location" not in second.headers
    assert len(host_rows(scripted.dsn)) == 1
    assert audit.events() == []


async def test_r1_a_request_while_one_runs_is_a_new_queued_one(scripted):
    """A running check does not dedupe: asking again after a fix queues a new one. (R1)"""
    running = plant(scripted.dsn, A, "readiness", stage="running")
    r = await start_readiness(scripted)
    assert r.status_code == 201
    assert r.json()["readiness_id"] != running
    assert [x["stage"] for x in host_rows(scripted.dsn)] == ["running", "queued"]


@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_r1_c8_permissions_membership_comes_first_and_a_refusal_makes_no_row(scripted, kind, caplog):
    """A program of A (no `config.write`) is 403, another tenant's admin 404 (membership first), an anonymous caller 401,
    each with no row and no event; Ann is served. (R1, A1, C8)"""
    system = carried_without_base_files()
    path = f"/api/tenants/{A}/" + ("readiness" if kind == "readiness" else f"systems/{system}/adoptions")
    audit = JobsAudit(caplog)
    assert (await scripted.client.post(path, headers=scripted.program())).status_code == 403
    assert (await scripted.client.post(path, headers=scripted.bob())).status_code == 404
    # from the frontend, so the origin guard (a 403 before authentication) lets it reach the session check (repair 5)
    assert (await scripted.client.post(path, headers={"Origin": ORIGIN})).status_code == 401
    assert (await scripted.client.post(path, headers=ops(scripted))).status_code == 404, "a platform admin is no member"
    assert host_rows(scripted.dsn) == []
    assert audit.events() == []
    assert (await scripted.client.post(path, headers=scripted.ann())).status_code != 403  # control


@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_c8_the_admin_route_starts_a_request_for_any_tenant_and_only_for_a_platform_admin(scripted, kind, caplog):
    """The platform admin starts one for A with no membership: 201, `Location` on the admin poll route, the admin as
    requester and actor. A tenant admin and a program are 403 there. (C8, R1, A1)"""
    system = carried_with_base_files() if kind == "adoption" else TICKET
    if kind == "adoption":
        scripted.plant_version(system, 1, adapter=system)
    path = f"/api/admin/tenants/{A}/" + ("readiness" if kind == "readiness" else f"systems/{system}/adoptions")
    for headers in (scripted.ann(), scripted.bob(), scripted.program()):
        assert (await scripted.client.post(path, headers=headers)).status_code == 403
    assert host_rows(scripted.dsn) == []
    audit = JobsAudit(caplog)
    r = await admin_start(scripted, kind, system=system)
    assert r.status_code == 201, r.text
    rid = id_of(kind, r.json())
    assert r.headers["Location"] == poll_path(kind, rid, admin=True)
    admin_id = scripted.user_id("ops@platform.example")
    assert host_row(scripted.dsn, rid)["requester"] == admin_id
    assert [(e.action.split(".")[1], e.actor, e.tenant_id) for e in audit.events()] == [("start", admin_id, A)]
    assert (await poll(scripted, kind, rid, admin=True)).json() == r.json()


@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_r1_a_tenant_being_offboarded_takes_no_request_409_while_its_live_rows_are_kept_failed(scripted, kind):
    """Driven through the admin route: after the offboard a start is 409 and makes no row; the live rows the offboard ended
    stay, `failed`/`tenant_offboarded`, none deleted. (R1, A1, B1)"""
    system = carried_with_base_files() if kind == "adoption" else TICKET
    if kind == "adoption":
        scripted.plant_version(system, 1, adapter=system)
    queued = await admin_start(scripted, kind, system=system)
    running = plant(scripted.dsn, A, "adoption" if kind == "readiness" else "readiness", system=system if kind == "readiness" else None,
                    stage="running")
    assert (await scripted.client.post(f"/api/admin/tenants/{A}/offboard", headers=ops(scripted))).status_code == 202
    before = host_rows(scripted.dsn)
    assert {r["id"] for r in before} == {id_of(kind, queued.json()), running}
    assert {(r["stage"], r["failure_reason"]) for r in before} == {("failed", "tenant_offboarded")}
    assert (await admin_start(scripted, kind, system=system)).status_code == 409
    assert host_rows(scripted.dsn) == before


@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_r1_a_tenant_still_creating_has_its_request_accepted_and_queued(scripted, kind):
    """§9 addendum: only offboarding refuses a start; a `creating` tenant's request is queued (201). (R1, A1)"""
    register_tenant(scripted.dsn, C, state="creating", records=None, wiring=False)
    system = carried_with_base_files() if kind == "adoption" else TICKET
    if kind == "adoption":
        scripted.plant_version(system, 1, adapter=system, tenant=C)
    r = await admin_start(scripted, kind, tenant=C, system=system)
    assert r.status_code == 201, r.text
    assert host_row(scripted.dsn, id_of(kind, r.json()))["stage"] == "queued"


# --- A1: adoption start -----------------------------------------------------------------------------------------------

async def test_a1_a_system_the_tenant_has_no_record_of_is_404_and_a_system_that_ships_no_base_files_is_409_no_base_files(scripted):
    """404 for an unrecorded system (also one only another tenant records), 409 naming `no_base_files` for a recorded system
    whose adapter ships none; neither makes a row; permission still comes first. (A1)"""
    system = carried_without_base_files()
    scripted.plant_version("elastic", 1, adapter="elastic", tenant=B)
    assert (await start_adoption(scripted, system)).status_code == 404
    assert (await start_adoption(scripted, "elastic")).status_code == 404
    scripted.plant_version(system, 1, adapter=system)
    refusal = await start_adoption(scripted, system)
    assert refusal.status_code == 409
    assert "no_base_files" in problem_text(refusal)
    assert host_rows(scripted.dsn) == []
    assert (await start_adoption(scripted, "no-such", headers=scripted.program())).status_code == 403


async def test_a1_an_adoption_of_a_system_that_ships_base_files_is_201_dedupes_while_queued_and_not_while_running(scripted, caplog):
    """201 with `Location`, then 200 for the same system; a disabled system is adoptable; a running one does not dedupe; the
    event names the system. (A1)"""
    system = carried_with_base_files()
    scripted.plant_version(system, 1, adapter=system, enabled=False)
    audit = JobsAudit(caplog)
    first = await start_adoption(scripted, system)
    assert first.status_code == 201, first.text
    assert first.headers["Location"] == poll_path("adoption", first.json()["adoption_id"])
    assert first.json()["system_id"] == system
    assert first.json()["pr_url"] is None
    again = await start_adoption(scripted, system)
    assert (again.status_code, again.json()["adoption_id"]) == (200, first.json()["adoption_id"])
    assert [(e.action, e.detail) for e in audit.events()] == [("adoption.start", f"system {system}")]
    execute(scripted.dsn, "UPDATE jobs.host_requests SET stage = 'running', started_at = now(), "
                          "lease_expires_at = now() + interval '5 minutes' WHERE id = %s", (first.json()["adoption_id"],))
    third = await start_adoption(scripted, system)
    assert third.status_code == 201
    assert third.json()["adoption_id"] != first.json()["adoption_id"]


# --- R2, A2: poll -----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_r2_a_poll_for_another_tenants_other_kinds_or_unknown_id_is_404(scripted, kind):
    """404 for an unknown id, for the other kind's id, and for another tenant's id (under its own path and under A's); 422 for
    a malformed id; the right id is 200. (R2, A2)"""
    other = "adoption" if kind == "readiness" else "readiness"
    mine = plant(scripted.dsn, A, kind, system=TICKET if kind == "adoption" else None, stage="completed")
    theirs = plant(scripted.dsn, B, kind, system=TICKET if kind == "adoption" else None)
    assert (await poll(scripted, kind, mine)).status_code == 200
    assert (await poll(scripted, kind, UNKNOWN)).status_code == 404
    assert (await poll(scripted, other, mine)).status_code == 404
    assert (await poll(scripted, kind, theirs)).status_code == 404
    assert (await poll(scripted, kind, mine, tenant=B)).status_code == 404
    assert (await poll(scripted, kind, theirs, tenant=B)).status_code == 200
    assert (await scripted.client.get(poll_path(kind, "not-an-id"), headers=scripted.ann(write=False))).status_code == 422
    assert (await scripted.client.get(poll_path(kind, mine), headers=scripted.program())).status_code == 403
    assert (await poll(scripted, other, mine, admin=True)).status_code == 404


async def test_r2_each_stage_is_served_with_the_fields_it_has(scripted):
    """queued, running, completed and failed rows read with `status`, times, `result` iff completed and the failure pair iff
    failed. (R2)"""
    result = {"outcome": "refused", "step": "tenant", "sentence": "the tenant is not active", "knowledge": None}
    ids = {
        "queued": plant(scripted.dsn, A, "readiness"),
        "running": plant(scripted.dsn, A, "readiness", stage="running"),
        "completed": plant(scripted.dsn, A, "readiness", stage="completed", result=result),
        "failed": plant(scripted.dsn, A, "readiness", stage="failed", reason="worker_error", message="the helper failed"),
    }
    served = {k: (await poll(scripted, "readiness", i)).json() for k, i in ids.items()}
    assert {k: v["status"] for k, v in served.items()} == {k: k for k in ids}
    assert served["queued"]["started_at"] is None
    assert served["running"]["started_at"] is not None
    assert served["completed"]["result"] == result
    assert served["completed"]["finished_at"] is not None
    for stage in ("queued", "running", "failed"):
        assert served[stage]["result"] is None, stage
    assert (served["failed"]["failure_reason"], served["failed"]["failure_message"]) == ("worker_error", "the helper failed")
    for stage in ("queued", "running", "completed"):
        assert (served[stage]["failure_reason"], served[stage]["failure_message"]) == (None, None), stage


async def test_d7_a_sentence_holding_markup_is_served_byte_for_byte(scripted):
    """A stored sentence with `<`, `&` and `"` is served unchanged: no escaping, stripping or rewriting; escaping is the page's. (D7, P-2)"""
    sentence = 'system "a<b>&c" is not a well-formed name'
    result = {"outcome": "refused", "step": "tenant", "sentence": sentence, "knowledge": None}
    rid = plant(scripted.dsn, A, "readiness", stage="completed", result=result)
    resp = await poll(scripted, "readiness", rid)
    assert resp.json()["result"]["sentence"] == sentence


# --- R13-2: live fields -----------------------------------------------------------------------------------------------

async def test_r13_2_credential_presence_is_asked_on_completed_polls_only_and_lists_systems_without_a_set(scripted):
    """A completed poll of an active tenant lists the ids of every recorded system, disabled included, with no credential at
    its current generation, sorted; queued, running and failed polls are null and ask the store nothing. (R3, R13-2, D10)"""
    from defender.tests.support.api._config1470 import ELASTIC, ELASTIC_ACCESS, ELASTIC_SETTINGS

    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    assert (await scripted.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS, enabled=False)).status_code == 201
    done = plant(scripted.dsn, A, "readiness", stage="completed")
    others = [plant(scripted.dsn, A, "readiness"), plant(scripted.dsn, A, "readiness", stage="running"),
              plant(scripted.dsn, A, "readiness", stage="failed", reason="no_record", message="m")]
    scripted.scripted.calls.clear()
    for rid in others:
        assert (await poll(scripted, "readiness", rid)).json()["systems_without_credentials"] is None
    assert scripted.scripted.calls == [], "a queued, running or failed poll asked the secret store"
    assert (await poll(scripted, "readiness", done)).json()["systems_without_credentials"] == sorted([TICKET, ELASTIC])
    assert (await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204
    assert (await poll(scripted, "readiness", done)).json()["systems_without_credentials"] == [ELASTIC]


async def test_r13_2_a_completed_poll_when_the_secret_store_cannot_answer_is_503_and_other_polls_still_answer(scripted):
    """Sealed: a completed poll is 503 naming the secret store; a queued, running or failed one is 200. Unsealed, 200. (R2, C7)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    done = plant(scripted.dsn, A, "readiness", stage="completed")
    queued = plant(scripted.dsn, A, "readiness")
    scripted.scripted.sealed = True
    refused_poll = await poll(scripted, "readiness", done)
    assert refused_poll.status_code == 503
    assert "secret store" in problem_text(refused_poll).lower()
    assert (await poll(scripted, "readiness", queued)).status_code == 200
    scripted.scripted.sealed = False
    assert (await poll(scripted, "readiness", done)).status_code == 200


async def test_r13_2_a_secret_store_that_refuses_the_apis_login_is_500_naming_it_not_503(scripted):
    """A 403 from the store on a completed poll is the API's 500 naming the refusal, as on `GET /systems`. (R2, C7)"""
    import httpx as _httpx

    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    done = plant(scripted.dsn, A, "readiness", stage="completed")
    scripted.scripted.answer("GET", "metadata", _httpx.Response(403, json={"errors": ["permission denied"]}), times=1)
    lenient = await scripted.lenient().get(poll_path("readiness", done), headers=scripted.ann(write=False))
    assert lenient.status_code == 500
    assert "secret store" in problem_text(lenient).lower()


async def test_r13_2_once_the_tenant_is_not_active_a_completed_poll_serves_the_kept_row_with_null_presence_and_no_store_call(scripted):
    """After the offboard (admin route): the kept completed row is served, `systems_without_credentials` null, and the secret
    store is not asked, sealed or not. (R13-2, B1)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    done = plant(scripted.dsn, A, "readiness", stage="completed")
    assert (await poll(scripted, "readiness", done)).json()["systems_without_credentials"] == [TICKET]
    assert (await scripted.client.post(f"/api/admin/tenants/{A}/offboard", headers=ops(scripted))).status_code == 202
    scripted.scripted.calls.clear()
    scripted.scripted.sealed = True
    kept = await poll(scripted, "readiness", done, admin=True)
    assert kept.status_code == 200, kept.text
    assert (kept.json()["status"], kept.json()["result"], kept.json()["systems_without_credentials"]) == (
        "completed", READY_RESULT, None)
    assert scripted.scripted.calls == []


async def test_a2_an_adoption_poll_never_asks_the_secret_store_and_builds_pr_url_from_the_wiring_and_the_number(scripted):
    """`pr_url` is the tenant's recorded repository page plus `/pulls/<n>` for an outcome with a number, null for
    `nothing_to_adopt`; the sealed store changes nothing. (A2, A3, R13-2, #1592)"""
    origin = forge_origin(scripted.dsn, A).removesuffix(".git")
    opened = plant(scripted.dsn, A, "adoption", system=TICKET, stage="completed", result={"outcome": "opened", "pr_number": 17})
    nothing = plant(scripted.dsn, A, "adoption", system="elastic", stage="completed",
                    result={"outcome": "nothing_to_adopt", "pr_number": None})
    scripted.scripted.sealed = True
    scripted.scripted.calls.clear()
    got = (await poll(scripted, "adoption", opened)).json()
    assert (got["result"], got["pr_url"], got["system_id"]) == ({"outcome": "opened", "pr_number": 17},
                                                               pr_page(A, 17), TICKET)
    assert origin not in got["pr_url"], "the address was built from the wiring's private origin"
    none = (await poll(scripted, "adoption", nothing)).json()
    assert (none["result"]["outcome"], none["pr_url"]) == ("nothing_to_adopt", None)
    assert scripted.scripted.calls == []
    for outcome in ("already_open", "rejected"):
        rid = plant(scripted.dsn, A, "adoption", system=f"s-{outcome}".replace("_", "-"), stage="completed",
                    result={"outcome": outcome, "pr_number": 5})
        assert (await poll(scripted, "adoption", rid)).json()["pr_url"] == pr_page(A, 5)


async def test_r13_2_an_adoption_poll_for_a_tenant_with_no_forge_wiring_serves_pr_url_null_and_never_fails(scripted):
    """No wiring, and so no repository page, recorded: the read is 200 with `pr_url` null, number or not. (R13-2)"""
    register_tenant(scripted.dsn, C, records=None, wiring=False)
    rid = plant(scripted.dsn, C, "adoption", system=TICKET, stage="completed", result={"outcome": "opened", "pr_number": 9})
    served = await poll(scripted, "adoption", rid, tenant=C, admin=True)
    assert served.status_code == 200, served.text
    assert (served.json()["pr_url"], served.json()["result"]["pr_number"]) == (None, 9)


async def test_a3_the_pr_address_comes_from_wiring_never_from_the_job_record(scripted):
    """A stored result carrying its own `pr_url` is not served as the address. (A3)"""
    rid = plant(scripted.dsn, A, "adoption", system=TICKET, stage="completed",
                result={"outcome": "opened", "pr_number": 3, "pr_url": "https://evil.example/pulls/3"})
    assert (await poll(scripted, "adoption", rid)).json()["pr_url"] == pr_page(A, 3)


# --- the worker's result, served on poll ------------------------------------------------------------------------------

async def test_the_result_a_worker_stores_is_what_the_poll_serves_for_both_kinds(scripted, tmp_path):
    """A request made through the API, run by a worker whose helper leaves records, polls `completed` with the composed
    result: readiness with the knowledge status and credential presence, adoption with `pr_url`. (R2, R13-1.5, A2)"""
    root = tmp_path / "data"
    (root / A / "runs").mkdir(parents=True)
    (root / A / "sessions").mkdir()
    world = {"tmp": tmp_path, "root": root, "runs": root / A / "runs", "dsn": scripted.dsn}
    system = carried_with_base_files()
    scripted.plant_version(system, 1, adapter=system)
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    r = (await start_readiness(scripted)).json()["readiness_id"]
    a = (await start_adoption(scripted, system)).json()["adoption_id"]
    child = host_child(world, files={READINESS: refused("systems", "no usable system"), KNOWLEDGE: FRESH,
                                     ADOPTION: adopted("opened", 12)})
    async with job_store(scripted.dsn) as store:
        await host_worker(world, store, child).drain()
    got_r = (await poll(scripted, "readiness", r)).json()
    assert got_r["status"] == "completed"
    assert got_r["result"] == {"outcome": "refused", "step": "systems", "sentence": "no usable system",
                               "knowledge": {"status": "current", "commit": "c" * 40, "stale_kind": None}}
    # the adoption's system is planted as a version with no credential, so it is listed too (repair 5): the presence is
    # served on a `refused` result as on `ready` (R13-2)
    assert got_r["systems_without_credentials"] == sorted([TICKET, system])
    got_a = (await poll(scripted, "adoption", a)).json()
    assert (got_a["status"], got_a["result"], got_a["pr_url"]) == (
        "completed", {"outcome": "opened", "pr_number": 12}, pr_page(A, 12))


async def test_b1_the_admin_reads_the_rows_an_offboard_ended_and_a_tenant_member_no_longer_can(scripted):
    """The ended rows are readable through the admin route with their reason; the offboarded tenant's member is 404. (B1, R2)"""
    rid = (await start_readiness(scripted)).json()["readiness_id"]
    assert (await scripted.client.post(f"/api/admin/tenants/{A}/offboard", headers=ops(scripted))).status_code == 202
    ended = (await poll(scripted, "readiness", rid, admin=True)).json()
    assert (ended["status"], ended["failure_reason"]) == ("failed", "tenant_offboarded")
    assert ended["systems_without_credentials"] is None
    assert (await poll(scripted, "readiness", rid)).status_code == 404
    assert len(host_rows(scripted.dsn)) == 1


@pytest.mark.parametrize("page", [None, f"{ORIGIN}/t/x/knowledge", "javascript:alert(1)", "forgejo:3000/t/knowledge"])
async def test_a_recorded_repository_page_a_browser_may_not_open_serves_pr_url_null(scripted, page):
    """finalize (#1623 review): the link follows the Knowledge repo link's rule for the recorded page: none, one on the
    app's own origin, or one that is not an absolute http(s) URL gives `pr_url` null, and the read still succeeds."""
    record_repo_page(scripted.dsn, A, page)
    rid = plant(scripted.dsn, A, "adoption", system=TICKET, stage="completed", result={"outcome": "opened", "pr_number": 9})
    served = await poll(scripted, "adoption", rid)
    assert served.status_code == 200, served.text
    assert (served.json()["pr_url"], served.json()["result"]["pr_number"]) == (None, 9)
