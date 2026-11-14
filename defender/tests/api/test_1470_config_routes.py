"""#1470: a tenant admin reads and writes the tenant's catalog view, systems and case record through the API.

The app is the real server (`defender.api_server.serving`) over a migrated database and the real record store; the secret
store is the real `OpenBaoSecrets` over a scripted transport (and over a real OpenBao, in the `real` runs of `configured`).
Credentials and audit are `test_1470_credentials`; start rules `test_1470_start`. Postgres-gated."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from defender.tests.support.api._config1470 import (
    BASE_MOVED,
    BODY,
    ELASTIC,
    ELASTIC_ACCESS,
    ELASTIC_SETTINGS,
    TICKET,
    TICKET_ACCESS,
    TICKET_NAME,
    TICKET_SETTINGS,
    TOKEN,
    edited_cursor,
    problem_text,
)
from defender.tests.support.api._server1083 import ANN, ORIGIN, A, B
from defender.tests.support.tenancy import _systems1366 as R

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

LAB = {"ticket", "cmdb", "change-mgmt", "identity", "threat-intel", "host-state"}
REAL = {"jira", "servicenow", "elastic"}


def _served(version: int, *, has_credentials: bool = False, settings: dict[str, str] | None = None,
            access: str | None = None, enabled: bool = True, system: str = TICKET, name: str | None = TICKET_NAME) -> dict:
    return {"system_id": system, "version": version, "display_name": name, "enabled": enabled,
            "settings": TICKET_SETTINGS if settings is None else settings,
            "access": TICKET_ACCESS if access is None else access, "has_credentials": has_credentials}


def _stale(response: httpx.Response, shown: int) -> None:
    body = response.json()
    assert response.status_code == 409, response.text
    assert body["current_version"] == shown, body
    assert "faults" not in body
    assert "errors" not in body, body


def _judged(response: httpx.Response) -> list[str]:
    body = response.json()
    assert response.status_code == 422, response.text
    assert "errors" not in body, body  # a 422 carries `faults` or `errors`, never both
    assert isinstance(body["faults"], list)
    assert body["faults"], body
    assert all(isinstance(f, str) for f in body["faults"])
    assert "current_version" not in body
    return body["faults"]


# --- O2: the catalog -------------------------------------------------------------------------------------------------

async def test_o2_the_catalog_lists_every_adapter_with_what_a_record_of_it_stores(scripted):
    """`GET /adapters`: every catalog adapter with display name, settings keys, sample settings and the lab flag. (O2)"""
    got = await scripted.get("/adapters")
    assert got.status_code == 200, got.text
    items = {i["adapter_id"]: i for i in got.json()["items"]}
    assert set(items) == LAB | REAL
    assert {a for a, i in items.items() if i["lab_example"]} == LAB
    assert all(set(i) == {"adapter_id", "display_name", "settings_keys", "sample_settings", "lab_example"}
               for i in items.values())
    assert items[TICKET]["display_name"] == TICKET_NAME
    assert sorted(items[TICKET]["settings_keys"]) == sorted(TICKET_SETTINGS)
    assert items["host-state"]["settings_keys"] == []
    assert items["host-state"]["sample_settings"] == {}
    for adapter, item in items.items():
        assert sorted(item["sample_settings"]) == sorted(item["settings_keys"]), adapter
        assert all(isinstance(v, str) and v and "CHANGE-ME" not in v and "playground" not in v
                   for v in item["sample_settings"].values()), (adapter, item["sample_settings"])
    assert scripted.scripted.calls == []  # the catalog read asks no secret store


@pytest.mark.parametrize("adapter", sorted(R.FIXTURE_FOLDERS))
async def test_o2_each_adapters_own_check_accepts_the_sample_settings_the_catalog_serves(scripted, adapter):
    """A record of each adapter that has an access folder in the fixture (seven of the nine; jira and servicenow need an
    access declaration the fixture lacks) carrying exactly its served sample settings is stored (201). (O2)"""
    sample = {i["adapter_id"]: i["sample_settings"] for i in (await scripted.get("/adapters")).json()["items"]}[adapter]
    saved = await scripted.put_system(adapter, 0, settings=sample, access=R.FIXTURE_FOLDERS[adapter][1])
    assert saved.status_code == 201, saved.text
    assert saved.json()["settings"] == sample


# --- O3 / O4: save and read a system ---------------------------------------------------------------------------------

async def test_o3_o4_a_system_is_created_201_replaced_200_and_read_back_as_stored(configured):
    """`replaces: 0` is 201 at version 1; one naming 1 is 200 at version 2; reads answer the record. (O3, O4)"""
    assert (await configured.get_system(TICKET)).status_code == 404  # never written: absent
    assert (await configured.list_systems()).json()["items"] == []
    created = await configured.put_system(TICKET, 0)
    assert created.status_code == 201, created.text
    assert created.headers["Location"] == f"{ORIGIN}/tenants/{A}/systems/{TICKET}"  # as every create names its resource
    assert created.json() == _served(1)
    assert (await configured.get_system(TICKET)).json() == _served(1)

    edited = TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"}
    replaced = await configured.put_system(TICKET, 1, settings=edited, enabled=False)
    assert replaced.status_code == 200, replaced.text
    assert "Location" not in replaced.headers
    assert replaced.json() == _served(2, settings=edited, enabled=False)
    other = await configured.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)
    assert other.status_code == 201, other.text
    listed = (await configured.list_systems()).json()["items"]
    assert {i["system_id"]: i["version"] for i in listed} == {TICKET: 2, ELASTIC: 1}
    assert [(v.version, v.settings, v.enabled) for v in configured.versions(TICKET)] == [
        (1, TICKET_SETTINGS, True), (2, edited, False)]
    assert {v.author for v in configured.versions(TICKET)} == {configured.user_id(ANN)}


async def test_o3_a_current_record_whose_adapter_the_catalog_lacks_reads_with_no_display_name_and_can_be_deleted(scripted):
    """A record an upgrade left naming a removed adapter: display name null on read; its delete is 204. (O3, O5)"""
    scripted.plant_version("retired", 1, adapter="retired")
    read = await scripted.get_system("retired")
    assert read.status_code == 200, read.text
    assert read.json()["display_name"] is None
    assert (await scripted.delete_system("retired", 1)).status_code == 204
    assert (await scripted.get_system("retired")).status_code == 404


@pytest.mark.parametrize("replaces", [0, 3, 99])
async def test_p2_a_save_naming_a_version_a_read_does_not_show_is_409_naming_what_it_shows(configured, replaces):
    """With v2 current, any other `replaces` is stale: 409 with `current_version` 2 and nothing written. (P2, O4)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.put_system(TICKET, 1)).status_code == 200
    if replaces == 0:
        stale = await configured.put_system(TICKET, replaces)
    else:
        stale = await configured.put_system(TICKET, replaces, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "30"})
    _stale(stale, 2)
    assert [v.version for v in configured.versions(TICKET)] == [1, 2]
    assert (await configured.put_system(TICKET, 2)).status_code == 200  # control: naming the shown version works


async def test_p2_a_save_over_nothing_names_version_0_and_a_stale_one_is_409_naming_0(configured):
    """Never written: `replaces: 4` is 409 naming 0; after a delete the tombstone shows as none (0). (P2)"""
    _stale(await configured.put_system(TICKET, 4), 0)
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.delete_system(TICKET, 1)).status_code == 204
    _stale(await configured.put_system(TICKET, 1), 0)
    assert [v.version for v in configured.versions(TICKET)] == [1, 2]


_BAD_RECORDS = [
    ("no settings", {"settings": {}}, ("TICKET_TIMEOUT_SEC", "TICKET_KEY_PATTERN")),
    ("a key the adapter does not read", {"settings": TICKET_SETTINGS | {"TICKET_BOGUS": "1"}}, ("TICKET_BOGUS",)),
    ("a placeholder value", {"settings": TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "CHANGE-ME"}}, ("TICKET_TIMEOUT_SEC",)),
    ("a blank value", {"settings": TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": ""}}, ("TICKET_TIMEOUT_SEC",)),
    ("access that is not YAML", {"access": "base: [unclosed"}, ()),
    ("access that is empty", {"access": ""}, ()),
    ("access with a placeholder", {"access": TICKET_ACCESS.replace("soc-playground", "CHANGE-ME")}, ()),
]


@pytest.mark.parametrize(("label", "change", "names"), _BAD_RECORDS, ids=[c[0] for c in _BAD_RECORDS])
async def test_o4_p6_a_record_the_judgement_refuses_is_422_with_every_fault_naming_the_system(configured, label, change, names):
    """Each refusal class: 422, a `faults` list (no `errors`), every fault a sentence naming `ticket`, the keys named,
    nothing stored; the same route stored the good record first (control). (O4, P6)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    body = {"settings": TICKET_SETTINGS, "access": TICKET_ACCESS} | change
    refused = await configured.put_system(TICKET, 1, **body)
    faults = _judged(refused)
    assert all(TICKET in f for f in faults), faults
    for name in names:
        assert any(name in f for f in faults), (name, faults)
    assert [v.version for v in configured.versions(TICKET)] == [1]


async def test_o4_every_fault_of_one_record_is_listed_in_one_answer(configured):
    """Two bad settings in one record: each key named in the one 422, not the first only. (O4)"""
    refused = await configured.put_system(TICKET, 0, settings={"TICKET_BOGUS": "1", "TICKET_TIMEOUT_SEC": "CHANGE-ME"})
    faults = _judged(refused)
    text = " ".join(faults)
    assert "TICKET_BOGUS" in text, faults
    assert "TICKET_TIMEOUT_SEC" in text, faults
    assert len(faults) >= 2


async def test_o5_o6_a_case_system_must_stay_an_enabled_system_so_disabling_it_or_naming_a_disabled_one_is_422(configured):
    """The case record's system is one of the tenant's current enabled systems: disabling it is refused (naming it) and
    so is a case record naming a disabled system; re-enabling restores both. (O5, O6, cover rule)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.put_case(0)).status_code == 201
    faults = _judged(await configured.put_system(TICKET, 1, enabled=False))
    assert any(TICKET in f for f in faults), faults
    assert (await configured.delete_case(1)).status_code == 204
    assert (await configured.put_system(TICKET, 1, enabled=False)).status_code == 200
    _judged(await configured.put_case(0))
    assert (await configured.put_system(TICKET, 2, enabled=True)).status_code == 200
    assert (await configured.put_case(0)).status_code == 201


async def test_o4_p4_an_id_that_is_not_a_catalog_adapter_is_the_judgements_422_and_nothing_is_stored(configured):
    """`tix` names no adapter: 422 naming it; the same body at `ticket` is stored (control). (O4, P4)"""
    faults = _judged(await configured.put_system("tix", 0))
    assert any("tix" in f for f in faults), faults
    assert configured.versions("tix") == []
    assert (await configured.put_system(TICKET, 0)).status_code == 201


@pytest.mark.parametrize("drop", ["replaces", "enabled", "settings", "access"])
async def test_o4_every_field_of_a_system_write_is_required_and_a_missing_one_is_a_validation_422(configured, drop):
    """No field defaults: a body missing `drop` is 422 with `errors` naming it (and no `faults`). (O4, G2)"""
    body = {"replaces": 0, "enabled": True, "settings": TICKET_SETTINGS, "access": TICKET_ACCESS}
    del body[drop]
    refused = await configured.put_raw(f"/tenants/{A}/systems/{TICKET}", body)
    assert refused.status_code == 422, refused.text
    assert "faults" not in refused.json()
    assert refused.json()["errors"], refused.json()
    assert drop in str(refused.json()["errors"])
    extra = await configured.put_raw(f"/tenants/{A}/systems/{TICKET}",
                                     {"replaces": 0, "enabled": True, "settings": TICKET_SETTINGS,
                                      "access": TICKET_ACCESS, "adapter": TICKET})
    assert extra.status_code == 422, extra.text  # P4: the adapter is not a write field
    assert configured.versions(TICKET) == []


# --- the systems list: a `Page` over the real store (re-homed from the stub's sweep of lists) ---------------------------

def _three_systems() -> list[str]:
    return sorted(R.FIXTURE_FOLDERS)[:3]


async def _save_three(served) -> list[str]:
    ids = _three_systems()
    for adapter in ids:
        settings, access = R.FIXTURE_FOLDERS[adapter]
        assert (await served.put_system(adapter, 0, settings=dict(settings), access=access)).status_code == 201
    return ids


async def test_o3_the_systems_list_pages_by_cursor_serving_every_system_once_in_id_order(configured):
    """`limit=1` walks three saved systems in id order, each once, the last page's cursor null; the page is the `Page`
    envelope (`items`, `next_cursor`). (O3, lists keep the Page envelope)"""
    ids = await _save_three(configured)
    seen: list[str] = []
    params: dict[str, object] = {"limit": 1}
    for _ in range(len(ids) + 1):
        page = (await configured.client.get(f"/tenants/{A}/systems", params=params,
                                            headers=configured.ann(write=False))).json()
        assert set(page) == {"items", "next_cursor"}, page
        assert len(page["items"]) == 1
        seen += [i["system_id"] for i in page["items"]]
        if page["next_cursor"] is None:
            break
        params = {"limit": 1, "cursor": page["next_cursor"]}
    assert seen == ids


async def test_o3_the_systems_list_asks_the_secret_store_only_for_the_rows_on_the_page(scripted):
    """Three systems, `limit=1`: the page serves the first, and every secret-store ask that names a system names that
    one, never another; the store was asked something (the page's `has_credentials` is the secret store's answer). (O3)"""
    first, *others = await _save_three(scripted)
    scripted.scripted.calls.clear()
    page = (await scripted.client.get(f"/tenants/{A}/systems", params={"limit": 1}, headers=scripted.ann(write=False))).json()
    assert [i["system_id"] for i in page["items"]] == [first]
    paths = [p for _, p in scripted.scripted.calls if f"/{A}/" in p]
    assert paths, scripted.scripted.calls
    assert all(f"/{A}/{first}/" in p for p in paths), paths
    assert not [p for p in paths for other in others if f"/{other}/" in p], paths


@pytest.mark.parametrize("bad_id", ["a b/é", "' OR 1=1 --", "", "\u0000", "x" * 1363])
async def test_o3_an_edited_cursor_naming_an_id_outside_the_grammar_is_refused_before_the_secret_store(scripted, bad_id):
    """A cursor whose id was edited to something no system id can be is 422, and the secret store is asked nothing. (O3)"""
    await _save_three(scripted)
    first = (await scripted.client.get(f"/tenants/{A}/systems", params={"limit": 1}, headers=scripted.ann(write=False))).json()
    scripted.scripted.calls.clear()
    refused = await scripted.client.get(f"/tenants/{A}/systems", headers=scripted.ann(write=False),
                                        params={"limit": 1, "cursor": edited_cursor(first["next_cursor"], id=bad_id)})
    assert refused.status_code == 422, refused.text
    assert scripted.scripted.calls == []


async def test_o3_a_systems_cursor_is_bound_to_its_tenant_even_for_a_member_of_both(scripted):
    """Ann, made a member of B too, cannot carry A's cursor to B's list (422); the same cursor works in A (control). (O3)"""
    import datetime as dt

    from defender.identity.postgres import PostgresIdentityRepository
    from defender.records.formats import TenantId, UserId

    await _save_three(scripted)
    now = dt.datetime.now(dt.UTC)
    repo = PostgresIdentityRepository(scripted.dsn)
    try:
        await repo.add_membership(UserId(scripted.user_id(ANN)), TenantId(B), status="active", invited_by=None, created_at=now, accepted_at=now)
    finally:
        await repo.close()
    headers = scripted.ann(write=False)
    cursor = (await scripted.client.get(f"/tenants/{A}/systems", params={"limit": 1}, headers=headers)).json()["next_cursor"]
    assert (await scripted.client.get(f"/tenants/{A}/systems", params={"limit": 1, "cursor": cursor}, headers=headers)).status_code == 200
    assert (await scripted.client.get(f"/tenants/{B}/systems", params={"cursor": cursor}, headers=headers)).status_code == 422


# --- P2 / O5: delete and re-create -----------------------------------------------------------------------------------

async def test_p2_o5_a_deleted_system_reads_absent_and_is_re_created_with_replaces_0_as_201(configured):
    """Delete v1 (tombstone v2) → 204, absent; re-create `replaces: 0` → 201 at v3; again → 409 naming 3. (P2, O4, O5)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    deleted = await configured.delete_system(TICKET, 1)
    assert deleted.status_code == 204, deleted.text
    assert (await configured.get_system(TICKET)).status_code == 404
    assert (await configured.list_systems()).json()["items"] == []
    recreated = await configured.put_system(TICKET, 0)
    assert recreated.status_code == 201, recreated.text
    assert recreated.headers["Location"] == f"{ORIGIN}/tenants/{A}/systems/{TICKET}"
    assert recreated.json() == _served(3)
    _stale(await configured.put_system(TICKET, 0), 3)


async def test_o5_deleting_with_no_current_record_is_404_before_any_version_check_and_a_stale_delete_409(configured):
    """No current record (never written, or deleted): 404 whatever `replaces` says; with v1 current, `replaces: 0`
    is 409 naming 1 and writes no tombstone. (O5, P2)"""
    assert (await configured.delete_system(TICKET, 7)).status_code == 404
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    _stale(await configured.delete_system(TICKET, 0), 1)
    assert [v.deleted for v in configured.versions(TICKET)] == [False]
    assert (await configured.delete_system(TICKET, 1)).status_code == 204
    assert (await configured.delete_system(TICKET, 1)).status_code == 404
    assert (await configured.delete_system(TICKET, 99)).status_code == 404


async def test_o5_a_delete_names_the_version_it_replaces(configured):
    """`replaces` is required on a delete: without it, a validation 422 and the record stays. (O5)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    refused = await configured.client.delete(f"/tenants/{A}/systems/{TICKET}", headers=configured.ann())
    assert refused.status_code == 422
    assert refused.json()["errors"], refused.text
    assert (await configured.get_system(TICKET)).status_code == 200


async def test_o5_deleting_the_case_records_system_is_refused_by_the_cover_rule(configured):
    """The case record names ticket: deleting it is 422 naming it; after the case record goes it is 204. (O5, O6)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.put_case(0)).status_code == 201
    faults = _judged(await configured.delete_system(TICKET, 1))
    assert any(TICKET in f for f in faults), faults
    assert (await configured.get_system(TICKET)).status_code == 200
    assert (await configured.delete_case(1)).status_code == 204
    assert (await configured.delete_system(TICKET, 1)).status_code == 204


# --- O6: the case record ---------------------------------------------------------------------------------------------

async def test_o6_the_case_record_is_created_replaced_read_stale_refused_deleted_and_re_created(configured):
    """PUT 201 v1, GET; PUT naming 1 is 200 v2; a stale PUT 409 naming 2; DELETE 204; GET 404; PUT `replaces: 0` 201 v4. (O6, P2)"""
    path = f"/tenants/{A}/case-record"
    assert (await configured.get("/case-record")).status_code == 404
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    created = await configured.put_case(0)
    assert created.status_code == 201, created.text
    assert created.headers["Location"] == f"{ORIGIN}{path}"
    record = {"version": 1, "system_id": TICKET, "comment_body": BODY}
    assert created.json() == record
    assert (await configured.get("/case-record")).json() == record
    edited = await configured.put_case(1, comment_body="{disposition}")
    assert edited.status_code == 200, edited.text
    assert "Location" not in edited.headers
    assert edited.json() == record | {"version": 2, "comment_body": "{disposition}"}
    _stale(await configured.put_case(1), 2)
    _stale(await configured.delete_case(1), 2)
    assert (await configured.delete_case(2)).status_code == 204
    assert (await configured.get("/case-record")).status_code == 404
    again = await configured.put_case(0)
    assert again.status_code == 201
    assert again.headers["Location"] == f"{ORIGIN}{path}"
    assert again.json()["version"] == 4, again.text
    assert {v.author for v in R.case_versions(configured.dsn, A)} == {configured.user_id(ANN)}
    assert (await configured.client.get(path, headers=configured.ann(write=False))).json()["version"] == 4


async def test_o6_deleting_a_case_record_that_is_absent_is_404_whatever_it_replaces(configured):
    """No case record (never written, or deleted): 404 before any version comparison. (O6, P2)"""
    assert (await configured.delete_case(5)).status_code == 404
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.put_case(0)).status_code == 201
    assert (await configured.delete_case(1)).status_code == 204
    assert (await configured.delete_case(1)).status_code == 404


@pytest.mark.parametrize(("label", "write"), [
    ("a system with no record", {"system_id": ELASTIC}),
    ("a template that cannot render", {"comment_body": "{0}"}),
    ("an empty template", {"comment_body": "   "}),
])
async def test_o6_a_case_record_the_judgement_refuses_is_422_and_stores_nothing(configured, label, write):
    """The case system must be a configured system and the body a renderable template: 422 `faults` (O6, P6)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    refused = await configured.put_case(0, **write)
    assert refused.status_code == 422, (label, refused.text)
    assert _judged(refused)
    assert R.case_versions(configured.dsn, A) == []
    assert (await configured.put_case(0)).status_code == 201  # control: the good record is taken


# --- G2: refusal bodies ----------------------------------------------------------------------------------------------

async def test_g2_the_problem_document_declares_faults_and_current_version(scripted):
    """The served OpenAPI's Problem names `faults` (a list of text) and `current_version` (an integer). (G2, D10)"""
    document = (await scripted.client.get("/openapi.json")).json()
    properties = document["components"]["schemas"]["Problem"]["properties"]
    assert properties["faults"]["type"] == "array" or "array" in str(properties["faults"])
    assert "integer" in str(properties["current_version"])
    put = document["paths"]["/tenants/{tenant_id}/systems/{system_id}"]["put"]["responses"]
    assert {"201", "200", "409", "422"} <= set(put), set(put)


# --- reads and writes with the secret store sealed or failing --------------------------------------------------------

async def test_o3_o4_while_the_secret_store_is_sealed_system_reads_and_replacing_writes_are_503_and_each_request_asks_again(scripted):
    """Sealed: reading a system and replacing one are 503 naming the sealed secret store, writing nothing and reading no
    value; a request that needs no answer from it (create, catalog, case record) makes no call; unsealed, the same app
    answers (no seal state is kept). (O3, O4, C20)"""
    bao = scripted.scripted
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    bao.sealed = True
    for refused in (await scripted.get_system(TICKET), await scripted.list_systems(),
                    await scripted.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})):
        assert refused.status_code == 503, refused.text
        assert "sealed" in problem_text(refused).lower(), refused.text
    assert [v.version for v in scripted.versions(TICKET)] == [1]
    bao.calls.clear()
    created = await scripted.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)
    assert created.status_code == 201, created.text  # no read: no set can exist at a new generation
    assert (await scripted.get("/adapters")).status_code == 200
    assert (await scripted.get("/case-record")).status_code == 404  # records, not the secret store
    assert bao.calls == []
    assert bao.paths() == []  # nothing written
    assert bao.value_reads == []  # no value read
    bao.sealed = False
    assert (await scripted.get_system(TICKET)).status_code == 200
    assert (await scripted.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})).status_code == 200
    assert bao.value_reads == []


async def test_o3_o4_o6_while_the_secret_store_is_sealed_an_empty_list_is_200_and_deletes_and_case_writes_succeed(scripted):
    """Sealed, the requests that need no secret-store answer succeed: listing a tenant with no systems (200, empty), a
    create, a case-record create and delete, a system delete. (O3, O4, O5, O6, C20)"""
    bao = scripted.scripted
    bao.sealed = True
    listed = await scripted.list_systems()
    assert listed.status_code == 200, listed.text
    assert listed.json()["items"] == []
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    assert (await scripted.put_case(0)).status_code == 201
    assert (await scripted.delete_case(1)).status_code == 204
    assert (await scripted.delete_system(TICKET, 1)).status_code == 204
    assert [(v.version, v.deleted) for v in scripted.versions(TICKET)] == [(1, False), (2, True)]
    assert bao.paths() == []
    assert bao.value_reads == []


async def test_o3_o4_a_secret_store_that_refuses_the_apis_login_after_start_is_500_on_reads_and_the_replace_pre_read(scripted):
    """A 403 once the API is running: a read, a list and a replacing save (its pre-read) are 500 naming the secret
    store's refusal, not 503; the save stores nothing; a create, needing no answer, still succeeds. (O3, O4, O7)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    scripted.scripted.token = "no-longer-the-apis"  # the stand-in now refuses the token the API sends
    for refused in (await scripted.get_system(TICKET), await scripted.list_systems(),
                    await scripted.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})):
        assert refused.status_code == 500, refused.text
        assert "secret store" in problem_text(refused).lower(), refused.text
    assert [v.version for v in scripted.versions(TICKET)] == [1]
    assert (await scripted.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)).status_code == 201


async def test_o4_a_create_or_re_create_asks_the_secret_store_nothing(scripted):
    """Create, delete, re-create: no call reaches the secret store, and the answers say `has_credentials` false. (O4)"""
    assert (await scripted.put_system(TICKET, 0)).json()["has_credentials"] is False
    assert (await scripted.delete_system(TICKET, 1)).status_code == 204
    assert (await scripted.put_system(TICKET, 0)).json()["has_credentials"] is False
    assert scripted.scripted.calls == []


async def test_o3_o4_a_secret_store_that_cannot_answer_fails_the_read_and_refuses_the_write_before_it_commits(scripted):
    """A 500 to the existence read: reads 503, the replacing write 503 with no new version; healthy again, 200. (O3, O4)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    scripted.scripted.answer("GET", "metadata", httpx.Response(500, json={"errors": ["boom"]}), times=3)
    for refused in (await scripted.get_system(TICKET), await scripted.list_systems(),
                    await scripted.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})):
        assert refused.status_code == 503, refused.text
        assert "secret store" in problem_text(refused).lower()
    assert [v.version for v in scripted.versions(TICKET)] == [1]
    assert (await scripted.get_system(TICKET)).status_code == 200


async def test_o4_has_credentials_is_true_exactly_while_a_set_exists_at_the_current_generation(configured):
    """A set stored for v1: reads and a same-generation save answer true; a save that moves the base answers false and
    a read agrees; a save that restores nothing changes the answer only by the generation it raised. (O3, O4, D-D)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is False
    assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is True
    same = await configured.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})
    assert same.json()["has_credentials"] is True  # as of before the write, same generation
    moved = await configured.put_system(TICKET, 2, access=TICKET_ACCESS.replace(*BASE_MOVED))
    assert moved.status_code == 200
    assert moved.json()["has_credentials"] is False
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is False
    assert [v.credential_generation for v in configured.versions(TICKET)] == [1, 1, 2]


# --- membership ------------------------------------------------------------------------------------------------------

async def test_o4_another_tenants_admin_writes_nothing_of_this_tenant_and_asks_no_secret_store(scripted):
    """Ann, admin of A only, naming tenant B: 404 on each config route, nothing written, no secret-store call. (O4, O7)"""
    assert (await scripted.get("/systems", tenant=B)).status_code == 404
    assert (await scripted.put_system(TICKET, 0, tenant=B)).status_code == 404
    assert (await scripted.delete_system(TICKET, 1, tenant=B)).status_code == 404
    assert (await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN}, tenant=B)).status_code == 404
    assert scripted.versions(TICKET, tenant=B) == []
    assert scripted.scripted.calls == []
    assert (await scripted.put_system(TICKET, 0)).status_code == 201  # control: her own tenant


# --- O15: what still refuses names its real owner --------------------------------------------------------------------

async def test_o15_the_connection_check_still_refuses_501_naming_its_owner_not_this_piece(scripted):
    """A saved system's check is 501 naming #1460, never #1470; a stranger gets 404. (O15, D-C)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    refused = await scripted.client.post(f"/tenants/{A}/systems/{TICKET}/check", headers=scripted.ann())
    assert refused.status_code == 501, refused.text
    assert "#1460" in refused.json()["detail"]
    assert "#1470" not in refused.json()["detail"]
    lessons = await scripted.client.get(f"/tenants/{A}/lessons", headers=scripted.ann(write=False))
    assert lessons.status_code == 501
    assert "#1082" in lessons.json()["detail"]
    assert "#1470" not in lessons.json()["detail"]
    stranger = await scripted.client.post(f"/tenants/{B}/systems/{TICKET}/check", headers=scripted.ann())
    assert stranger.status_code == 404


def test_o15_no_refusal_the_api_serves_names_this_piece_and_the_blob_stores_names_1082():
    """The program's refusal texts: none names #1470; the artifact links' and the audit's name #1082. (O15)

    The artifact read is unreachable over HTTP on the real server (its list is empty: no blob store), so the text is read."""
    import re

    import defender.api_server

    served = Path(defender.api_server.__file__).parent
    literals = [m for p in sorted(served.glob("*.py")) for m in re.findall(r"\"[^\"\n]*#\d+[^\"\n]*\"", p.read_text())]
    assert [lit for lit in literals if "#1470" in lit] == []
    assert any("#1082" in lit for lit in literals), literals


@pytest.mark.parametrize("drop", ["replaces", "system_id", "comment_body"])
async def test_o6_every_field_of_a_case_record_write_is_required_and_none_is_extra(configured, drop):
    """No field defaults: a case-record body missing `drop`, or carrying one more, is a validation 422 with `errors`. (O6, G2)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    body = {"replaces": 0, "system_id": TICKET, "comment_body": BODY}
    del body[drop]
    refused = await configured.put_raw(f"/tenants/{A}/case-record", body)
    assert refused.status_code == 422, refused.text
    assert refused.json()["errors"]
    assert "faults" not in refused.json()
    extra = await configured.put_raw(f"/tenants/{A}/case-record",
                                     {"replaces": 0, "system_id": TICKET, "comment_body": BODY, "enabled": True})
    assert extra.status_code == 422, extra.text
    assert R.case_versions(configured.dsn, A) == []


async def test_r7_2_an_undeclared_query_parameter_on_a_system_write_is_refused_and_changes_nothing(configured):
    """`PUT /systems/ticket?x=1` is a 422 `extra_forbidden` at `["query", "x"]`; nothing is stored. (R7-2, O4)"""
    body = {"replaces": 0, "enabled": True, "settings": TICKET_SETTINGS, "access": TICKET_ACCESS}
    refused = await configured.put_raw(f"/tenants/{A}/systems/{TICKET}", body, params={"x": "1"})
    assert refused.status_code == 422, refused.text
    assert [(e["type"], e["loc"]) for e in refused.json()["errors"]] == [("extra_forbidden", ["query", "x"])]
    assert configured.versions(TICKET) == []
