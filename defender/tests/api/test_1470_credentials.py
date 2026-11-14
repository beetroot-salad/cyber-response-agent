"""#1470: a tenant admin sets a system's credentials through the API, and every stored write is announced (O7, O9).

Real server over a migrated database; the secret store is the real `OpenBaoSecrets` over `ScriptedOpenBao` (faults a real
server cannot be made to give, the post-write race) and, in the `real` runs of `configured`, a real OpenBao holding the
writer policy. Postgres-gated; the `openbao`-marked tests need the test OpenBao."""
from __future__ import annotations

import logging

import anyio
import httpx
import pytest
from defender.tests.support.api._config1470 import (
    BASE_MOVED,
    ELASTIC,
    ELASTIC_ACCESS,
    ELASTIC_SETTINGS,
    PASSWORD,
    TICKET,
    TICKET_ACCESS,
    TICKET_SETTINGS,
    TOKEN,
    Configured,
    audit_events,
    problem_text,
    told,
)
from defender.tests.support.api._openbao1470 import (
    KV_MOUNT,
    WRITER_TOKEN,
    ScriptedOpenBao,
)
from defender.tests.support.api._server1083 import ANN, A
from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING

ELASTIC_SET = {"username": "defender-reader", "password": PASSWORD}
MARKER_UNUSED = "stored for an unused generation"
MARKER_POSSIBLY = "possibly stored"

postgres = pytest.mark.postgres
anyio_mark = pytest.mark.anyio


async def _ticket(configured: Configured, *, with_set: bool = False) -> None:
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    if with_set:
        assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204


def _faults(response: httpx.Response) -> list[str]:
    body = response.json()
    assert response.status_code == 422, response.text
    assert "errors" not in body, body
    assert body["faults"]
    assert all(isinstance(f, str) for f in body["faults"]), body
    return body["faults"]


# --- O7 / P3: the generation, not the version ------------------------------------------------------------------------

@anyio_mark
@postgres
async def test_o7_p3_credentials_follow_the_generation_not_the_version(configured):
    """Set for v1 → 204 at g1; v2 changes a setting (same generation): for v1 still 204; v3 moves the base: for v2 is
    409 naming 3 and `has_credentials` is false until a set for v3 (at g2). (O7, P3, D-D)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    first = await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert first.status_code == 204, first.text
    assert configured.stored_set(TICKET, 1) == {"kind": "static", "fields": {"api_key": TOKEN}}

    timeout = TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"}
    assert (await configured.put_system(TICKET, 1, settings=timeout)).status_code == 200
    assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN + "-2"})).status_code == 204
    assert configured.stored_set(TICKET, 1)["fields"] == {"api_key": TOKEN + "-2"}  # a set is replaced whole

    moved = TICKET_ACCESS.replace(*BASE_MOVED)
    assert moved != TICKET_ACCESS, "premise: the base is in the fixture's access text"
    assert (await configured.put_system(TICKET, 2, settings=timeout, access=moved)).status_code == 200
    refused = await configured.put_credentials(TICKET, 2, {"api_key": TOKEN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["current_version"] == 3
    assert "faults" not in refused.json()
    assert configured.stored_generations(TICKET) == [1]
    assert (await configured.put_credentials(TICKET, 3, {"api_key": TOKEN})).status_code == 204
    assert configured.stored_generations(TICKET) == [1, 2]
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is True


@anyio_mark
@postgres
async def test_o7_a_disabled_current_version_counts_and_an_unknown_or_future_version_is_409(configured):
    """v2 disables the system (same generation): for v1 and for v2 are 204; for 0, 3, 99: 409 naming 2. (O7, P3)"""
    await _ticket(configured)
    assert (await configured.put_system(TICKET, 1, enabled=False)).status_code == 200
    assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204
    assert (await configured.put_credentials(TICKET, 2, {"api_key": TOKEN})).status_code == 204
    for for_version in (0, 3, 99):
        refused = await configured.put_credentials(TICKET, for_version, {"api_key": TOKEN + "-x"})
        assert refused.status_code == 409
        assert refused.json()["current_version"] == 2, (for_version, refused.text)
    assert configured.stored_set(TICKET, 1)["fields"] == {"api_key": TOKEN}


@anyio_mark
@postgres
async def test_o7_a_deleted_system_has_no_current_record_and_its_version_is_not_a_generation_to_write_to(configured):
    """No record (never written, or deleted): 404 for any set, however wrong, and nothing stored. (O7)"""
    bad = {"nonsense": "x"}
    assert (await configured.put_credentials(TICKET, 1, bad)).status_code == 404
    await _ticket(configured)
    assert (await configured.delete_system(TICKET, 1)).status_code == 204
    assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 404
    assert (await configured.put_credentials(TICKET, 7, bad)).status_code == 404
    assert configured.stored_generations(TICKET) == []


@anyio_mark
@postgres
async def test_o7_the_version_check_comes_before_the_schema_check(configured):
    """A stale `for_version` with an invalid set is 409 (not 422), and nothing is stored. (O7)"""
    await _ticket(configured)
    stale = await configured.put_credentials(TICKET, 5, {"nonsense": "x"})
    assert stale.status_code == 409
    assert stale.json()["current_version"] == 1, stale.text
    assert configured.stored_generations(TICKET) == []


# --- O7: the credential schema ---------------------------------------------------------------------------------------

_BAD_SETS = [
    (TICKET, "a missing field", {}, ("api_key",)),
    (TICKET, "a field the scheme does not have", {"api_key": TOKEN, "password": TOKEN}, ("password",)),
    (TICKET, "the wrong field", {"api_token": TOKEN}, ("api_key", "api_token")),
    (TICKET, "a secret shorter than the minimum", {"api_key": "short"}, ("api_key",)),
    (TICKET, "an empty value", {"api_key": ""}, ("api_key",)),
    (TICKET, "a non-ASCII character in a bearer token", {"api_key": "tøken-of-sixteen-or-more"}, ("api_key",)),
    (TICKET, "a line break in a token", {"api_key": TOKEN + "\nX-Evil: 1"}, ("api_key",)),
    (ELASTIC, "a username holding a colon", {**ELASTIC_SET, "username": "defender:reader"}, ("username",)),
    (ELASTIC, "a short password", {**ELASTIC_SET, "password": "short"}, ("password",)),
    (ELASTIC, "a missing username", {"password": PASSWORD}, ("username",)),
    (ELASTIC, "an empty username", {**ELASTIC_SET, "username": ""}, ("username",)),
]


@anyio_mark
@postgres
@pytest.mark.parametrize(("system", "label", "bad", "names"), _BAD_SETS, ids=[f"{s}-{label}" for s, label, _, _ in _BAD_SETS])
async def test_o7_a_set_that_breaks_the_schemes_credential_schema_is_422_naming_the_fields(configured, system, label, bad, names):
    """A set not exactly the scheme's fields, or with a value the proxy would refuse at use: 422 `faults` naming the
    field, at the write; a good set on the same system is taken (control) and the bad one never replaces it. (O7)"""
    if system == TICKET:
        await _ticket(configured)
        good = {"api_key": TOKEN}
    else:
        assert (await configured.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)).status_code == 201
        good = ELASTIC_SET
    assert (await configured.put_credentials(system, 1, good)).status_code == 204
    faults = _faults(await configured.put_credentials(system, 1, bad))
    for name in names:
        assert any(name in f for f in faults), (name, faults)
    assert configured.stored_set(system, 1) == {"kind": "static", "fields": good}


@anyio_mark
@postgres
async def test_o7_every_fault_of_one_set_is_listed_in_one_answer(configured):
    """A basic set with a colon username and a short password: both named in one 422. (O7)"""
    assert (await configured.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)).status_code == 201
    faults = _faults(await configured.put_credentials(ELASTIC, 1, {"username": "a:b", "password": "short"}))
    assert any("username" in f for f in faults)
    assert any("password" in f for f in faults), faults
    assert configured.stored_generations(ELASTIC) == []


@anyio_mark
@postgres
async def test_o7_a_stored_access_that_no_longer_parses_is_422_naming_its_fault_and_stores_nothing(scripted):
    """A current record whose access an earlier release stored and today's parser refuses: 422, nothing stored. (O7)"""
    scripted.plant_version(TICKET, 1, access="base: [unclosed")
    faults = _faults(await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN}))
    assert faults
    assert scripted.stored_generations(TICKET) == []
    assert scripted.scripted.calls == []


@anyio_mark
@postgres
@pytest.mark.parametrize("body", [
    {"credentials": {"api_key": TOKEN}},
    {"for_version": 1},
    {"for_version": 1, "credentials": {"api_key": 12345678901234567890}},
    {"for_version": 1, "credentials": {"api_key": TOKEN}, "kind": "static"},
    {"for_version": "one", "credentials": {"api_key": TOKEN}},
], ids=["no for_version", "no credentials", "a number for a value", "a kind (P4)", "version not a number"])
async def test_o7_a_malformed_credential_body_is_a_validation_422_with_errors(configured, body):
    """Wire shape: `for_version` and `credentials` (field → text), nothing else. (O7, P4)"""
    await _ticket(configured)
    refused = await configured.put_raw(f"/tenants/{A}/systems/{TICKET}/credentials", body)
    assert refused.status_code == 422, refused.text
    assert refused.json()["errors"]
    assert "faults" not in refused.json()
    assert configured.stored_generations(TICKET) == []


@anyio_mark
@postgres
async def test_o7_no_route_returns_a_value_and_no_answer_or_log_line_holds_one(configured, caplog):
    """After setting credentials and reading everything back: no answer or log line holds the token or password, the
    credentials path answers only the write, and the writer never read a value. (O7, C10)"""
    caplog.set_level(logging.DEBUG)
    await _ticket(configured, with_set=True)
    assert (await configured.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)).status_code == 201
    seen = [await configured.put_credentials(ELASTIC, 1, ELASTIC_SET), await configured.get_system(TICKET),
            await configured.list_systems(), await configured.put_credentials(TICKET, 1, {"api_key": TOKEN + "!"}),
            await configured.put_credentials(TICKET, 1, {"api_key": "short"}),
            await configured.put_credentials(TICKET, 9, {"api_key": TOKEN})]
    for method in ("get", "post", "delete", "patch"):
        seen.append(await configured.client.request(method.upper(), f"/tenants/{A}/systems/{TICKET}/credentials",
                                                    headers=configured.ann()))
    assert [r.status_code for r in seen[-4:]] == [405] * 4
    everything = " ".join([r.text for r in seen] + [r.getMessage() + str(getattr(r, "detail", "")) for r in caplog.records])
    assert TOKEN not in everything
    assert PASSWORD not in everything
    if configured.scripted is not None:
        assert configured.scripted.value_reads == []


# --- O7: the secret store failing ------------------------------------------------------------------------------------

_FAILS = [
    ("sealed", None, 503, "not stored", False),
    ("a refused connection", httpx.ConnectError("refused"), 503, "not stored", False),
    ("a timeout", httpx.ReadTimeout("slow"), 503, MARKER_POSSIBLY, True),
    ("a 500", httpx.Response(500, json={"errors": ["internal error"]}), 503, MARKER_POSSIBLY, True),
    ("a refused login", httpx.Response(403, json={"errors": ["permission denied"]}), 500, "refus", False),
]


@anyio_mark
@postgres
@pytest.mark.parametrize(("label", "fault", "status", "says", "announced"), _FAILS, ids=[f[0] for f in _FAILS])
async def test_o7_o9_a_secret_store_fault_on_the_write_is_503_not_stored_or_possibly_stored_or_500_for_a_refused_login(
        scripted, caplog, label, fault, status, says, announced):
    """Sealed or a refused connection: 503 'not stored', nothing announced. A timeout or any other fault: 503 'possibly
    stored', announced with that marker. A login refused after start: 500 naming the refusal, nothing announced. (O7, O9)"""
    caplog.set_level(logging.DEBUG)
    await _ticket(scripted)
    caplog.clear()
    bao = scripted.scripted
    if fault is None:
        bao.sealed = True
    else:
        bao.answer("POST", "/data/", fault, times=1)
    refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert refused.status_code == status, refused.text
    said = problem_text(refused).lower()
    assert says in said, said
    if says == "not stored":
        assert "possibly" not in said, said
    events = audit_events(caplog, "system.credentials")
    if announced:
        [event] = events
        assert MARKER_POSSIBLY in told(event)
        assert event.target == TICKET
        assert TOKEN not in told(event)
    else:
        assert events == []
    bao.sealed = False
    control = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert control.status_code == 204, control.text  # the same request succeeds once the fault is gone


@anyio_mark
@postgres
async def test_o7_o9_a_re_read_that_cannot_answer_is_503_possibly_stored_and_announced_so(scripted, caplog):
    """The record store fails between the write and its re-read (the table is gone): 503 'possibly stored', announced
    `possibly stored`. (O7, O9)"""
    from defender.tests.support.shared._postgres1339 import execute

    caplog.set_level(logging.DEBUG)
    await _ticket(scripted)
    caplog.clear()

    async def break_the_records(path: str) -> None:
        with anyio.fail_after(30):  # off the loop, and failing rather than hanging on a lock the app holds
            await anyio.to_thread.run_sync(
                execute, scripted.dsn, "SET lock_timeout = '5s'; ALTER TABLE tenancy.system_versions RENAME TO sv_away")

    scripted.scripted.on_write = break_the_records
    try:
        refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    finally:
        execute(scripted.dsn, "ALTER TABLE tenancy.sv_away RENAME TO system_versions")
    assert refused.status_code == 503, refused.text
    assert MARKER_POSSIBLY in problem_text(refused).lower()
    [event] = audit_events(caplog, "system.credentials")
    assert MARKER_POSSIBLY in told(event)
    assert scripted.stored_set(TICKET, 1) == {"kind": "static", "fields": {"api_key": TOKEN}}


@anyio_mark
@postgres
async def test_o7_the_kind_stored_is_the_schemes_not_a_constant(scripted):
    """An oauth-scheme system stores its set as kind `oauth-client-credentials` with `client_id`/`client_secret`; a bearer
    one stays `static`. (O7, P4)"""
    from defender.tests.support.tenancy import _systems1366 as R

    access = R.declaration("http://soc-playground:8004", scheme=R.OAUTH, token_url="https://soc-playground:8004/token",
                           writes=(("POST", "/tickets/*/comments"),))
    assert (await scripted.put_system(TICKET, 0, access=access)).status_code == 201
    pair = {"client_id": "client-1", "client_secret": TOKEN}
    assert (await scripted.put_credentials(TICKET, 1, pair)).status_code == 204
    assert scripted.stored_set(TICKET, 1) == {"kind": "oauth-client-credentials", "fields": pair}
    refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})  # the bearer shape no longer fits
    assert refused.status_code == 422, refused.text


# --- O7 / O9: the post-write re-read ---------------------------------------------------------------------------------

@anyio_mark
@postgres
async def test_o7_o9_a_set_stored_for_a_generation_that_moved_meanwhile_is_409_and_announced_as_unused(scripted, caplog):
    """Another admin saves v2 with a new base while the set is being written: the re-read sees a new generation → 409
    naming 2, the set stays at g1, announced `stored for an unused generation`. (O7, O9, scenario)"""
    caplog.set_level(logging.DEBUG)
    await _ticket(scripted)
    caplog.clear()

    async def other_admin_moves_the_base(path: str) -> None:
        with anyio.fail_after(30):  # a stuck second request fails the test rather than hanging it
            saved = await scripted.put_system(TICKET, 1, access=TICKET_ACCESS.replace(*BASE_MOVED))
        assert saved.status_code == 200, saved.text

    scripted.scripted.on_write = other_admin_moves_the_base
    refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["current_version"] == 2
    assert "faults" not in refused.json()
    assert scripted.stored_generations(TICKET) == [1]
    assert (await scripted.get_system(TICKET)).json()["has_credentials"] is False
    [event] = audit_events(caplog, "system.credentials")
    assert MARKER_UNUSED in told(event)
    assert event.target == TICKET
    assert TOKEN not in told(event)
    scripted.scripted.on_write = None
    assert (await scripted.put_credentials(TICKET, 2, {"api_key": TOKEN})).status_code == 204  # control


@anyio_mark
@postgres
async def test_o7_o9_a_save_that_keeps_the_generation_meanwhile_leaves_the_write_a_204_with_no_marker(scripted, caplog):
    """v2 changes only an index key (same generation) during the write: 204, announced plainly. (O7, O9, scenario)"""
    caplog.set_level(logging.DEBUG)
    await _ticket(scripted)
    caplog.clear()

    async def other_admin_changes_a_setting(path: str) -> None:
        with anyio.fail_after(30):
            saved = await scripted.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})
        assert saved.status_code == 200, saved.text

    scripted.scripted.on_write = other_admin_changes_a_setting
    done = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert done.status_code == 204, done.text
    [event] = audit_events(caplog, "system.credentials")
    assert MARKER_UNUSED not in told(event)
    assert MARKER_POSSIBLY not in told(event)
    assert (await scripted.get_system(TICKET)).json()["has_credentials"] is True


@anyio_mark
@postgres
async def test_o7_o9_a_system_deleted_during_the_write_is_409_naming_0_and_announced_as_unused(scripted, caplog):
    """Deleted while the set is being written: 409 with `current_version` 0, announced as unused. (O7, O9)"""
    caplog.set_level(logging.DEBUG)
    await _ticket(scripted)
    caplog.clear()

    async def other_admin_deletes(path: str) -> None:
        with anyio.fail_after(30):
            deleted = await scripted.delete_system(TICKET, 1)
        assert deleted.status_code == 204

    scripted.scripted.on_write = other_admin_deletes
    refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert refused.status_code == 409
    assert refused.json()["current_version"] == 0, refused.text
    [event] = audit_events(caplog, "system.credentials")
    assert MARKER_UNUSED in told(event)
    assert (await scripted.get_system(TICKET)).status_code == 404


# --- O9: one event per stored write ----------------------------------------------------------------------------------

MAPPING_ENTRIES = ("signature", "event_time", "summary", "case_key", "title", "description")
AUDITED = ("system.update", "system.delete", "case_record.update", "case_record.delete", "system.credentials",
           "alert_mapping.update")


@anyio_mark
@postgres
async def test_o9_each_stored_write_announces_one_event_naming_the_member_and_the_target_and_refused_writes_none(configured, caplog):
    """System put x2, case put/delete, credentials, system delete, mapping: one event each by Ann in A, targets the
    system (system and credential events) or the tenant (case and mapping events); a stale put, a judged put, a stale
    delete, a refused credential set and a request for another tenant announce nothing; the credential event names
    fields, never values. (O9)"""
    caplog.set_level(logging.DEBUG)
    caplog.clear()
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.put_system(TICKET, 1)).status_code == 200
    assert (await configured.put_system(TICKET, 1)).status_code == 409
    assert (await configured.put_system(TICKET, 2, settings={})).status_code == 422
    assert (await configured.put_case(0)).status_code == 201
    assert (await configured.put_case(0)).status_code == 409
    assert (await configured.delete_case(1)).status_code == 204
    assert (await configured.delete_case(1)).status_code == 404
    assert (await configured.put_credentials(TICKET, 2, {"api_key": TOKEN})).status_code == 204
    assert (await configured.put_credentials(TICKET, 9, {"api_key": TOKEN})).status_code == 409
    assert (await configured.put_credentials(TICKET, 2, {"api_key": "x"})).status_code == 422
    assert (await configured.delete_system(TICKET, 1)).status_code == 409
    assert (await configured.delete_system(TICKET, 2)).status_code == 204
    assert (await configured.delete_system(TICKET, 3)).status_code == 404
    mapping = await configured.put_raw(f"/tenants/{A}/alert-mapping", {e: FIXTURE_ALERT_MAPPING.get(e) for e in MAPPING_ENTRIES})
    assert mapping.status_code == 200, mapping.text

    events = audit_events(caplog, *AUDITED)
    assert [e.action for e in events] == ["system.update", "system.update", "case_record.update", "case_record.delete",
                                          "system.credentials", "system.delete", "alert_mapping.update"], \
        [(e.action, e.target) for e in events]
    assert {(e.actor, e.tenant_id) for e in events} == {(configured.user_id(ANN), A)}
    assert {e.target for e in events if e.action.startswith("system.")} == {TICKET}
    assert {e.target for e in events if not e.action.startswith("system.")} == {A}
    [credentials] = [e for e in events if e.action == "system.credentials"]
    assert "api_key" in told(credentials)
    assert MARKER_UNUSED not in told(credentials)
    assert MARKER_POSSIBLY not in told(credentials)
    assert TOKEN not in " ".join(told(e) for e in events)


# --- C10: the writer policy ------------------------------------------------------------------------------------------

def _writer_calls(transport: httpx.BaseTransport | None, addr: str, token: str, mount: str) -> list[int]:
    """The statuses of: a write, a metadata read of it, a metadata read of a path never written, a value read, a delete,
    a list, and a read with another token: the answers `ScriptedOpenBao` was written from."""
    with httpx.Client(transport=transport, base_url=addr, headers={"X-Vault-Token": token}) as client:
        data, metadata = f"/v1/{mount}/data/t/s/g1", f"/v1/{mount}/metadata/t/s/g1"
        statuses = [client.post(data, json={"data": {"kind": "static", "fields": {"api_key": TOKEN}}}).status_code,
                    client.get(metadata).status_code, client.get(f"/v1/{mount}/metadata/t/s/g2").status_code,
                    client.get(data).status_code, client.delete(data).status_code,
                    client.request("LIST", f"/v1/{mount}/metadata/t").status_code]
        statuses.append(client.get(metadata, headers={"X-Vault-Token": "not-a-token"}).status_code)
    return statuses


#: write 200, metadata of it 200, of nothing 404, a value read 403, delete 403, list 403, an unknown token 403.
WRITER_STATUSES = [200, 200, 404, 403, 403, 403, 403]


def test_c10_the_scripted_stand_in_answers_as_the_writer_policy_was_observed_to():
    """The stand-in's answers to the calls the API makes and the ones the writer must not: the same list the real server
    gives in the next test. (C10, stand-in fidelity)"""
    bao = ScriptedOpenBao()
    assert _writer_calls(bao, "http://openbao.test", WRITER_TOKEN, KV_MOUNT) == WRITER_STATUSES
    assert bao.value_reads == ["t/s/g1"]


@pytest.mark.openbao
def test_c10_the_writer_policy_creates_and_updates_a_set_and_reads_metadata_but_cannot_read_a_value_back(openbao):
    """With the API's role (`store_policies` writer): a set is written, its metadata read, and a value read, delete and
    list are refused, as is another token. (C10)"""
    from defender.credential_proxy._openbao import store_policies

    writer = openbao.token_for(openbao.apply_policy("api-writer-c10", store_policies(kv_mount=openbao.kv_mount)["writer"]))
    tenant = openbao.tenant()
    data = f"{openbao.kv_mount}/data/{tenant}/s/g1"
    with httpx.Client(base_url=openbao.addr, headers={"X-Vault-Token": writer}) as client:
        write = client.post(f"/v1/{data}", json={"data": {"kind": "static", "fields": {"api_key": TOKEN}}})
        again = client.post(f"/v1/{data}", json={"data": {"kind": "static", "fields": {"api_key": TOKEN + "-2"}}})
        got = [client.get(f"/v1/{openbao.kv_mount}/metadata/{tenant}/s/g1").status_code,
               client.get(f"/v1/{openbao.kv_mount}/metadata/{tenant}/s/g2").status_code,
               client.get(f"/v1/{data}").status_code, client.delete(f"/v1/{data}").status_code,
               client.request("LIST", f"/v1/{openbao.kv_mount}/metadata/{tenant}").status_code]
    assert (write.status_code, again.status_code) == (200, 200)
    assert got == [200, 404, 403, 403, 403]
    stored = openbao.call("GET", data)
    assert stored.json()["data"]["data"]["fields"] == {"api_key": TOKEN + "-2"}  # read as root: the set is there, replaced whole
    assert stored.json()["data"]["metadata"]["version"] == 2
