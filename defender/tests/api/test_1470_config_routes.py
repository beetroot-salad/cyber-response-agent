"""#1470: a tenant admin reads and writes the tenant's catalog view, systems and case record through the API.

The app is the real server (`defender.api_server.serving`) over a migrated database and the real record store; the secret
store is the real `OpenBaoSecrets` over a scripted transport (and over a real OpenBao, in the `real` runs of `configured`).
Credentials and audit are `test_1470_credentials`; start rules `test_1470_start`. Postgres-gated."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any

import anyio

import httpx
import pytest
from defender.tests.support.api._config1470 import (
    remove_tenant,
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
    served_config,
)
from defender.tests.support.api._openbao1470 import ScriptedOpenBao
from defender.tests.support.api._server1083 import ANN, REPO, A, B
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.systems._rules1470 import write_broken_adapter

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

LAB = {"ticket", "cmdb", "change-mgmt", "identity", "threat-intel", "host-state"}
REAL = {"jira", "servicenow", "elastic"}


def _served(version: int, *, has_credentials: bool = False, settings: dict[str, str] | None = None,
            access: str | None = None, enabled: bool = True, system: str = TICKET, name: str | None = TICKET_NAME) -> dict:
    return {"system_id": system, "version": version, "display_name": name, "enabled": enabled,
            "settings": TICKET_SETTINGS if settings is None else settings,
            "access": TICKET_ACCESS if access is None else access, "has_credentials": has_credentials}


def _saved(version: int, **kw: Any) -> dict:
    """A save's answer: the record as stored, with no `has_credentials` (r8 Am-2: a save asks no secret store)."""
    return {k: v for k, v in _served(version, **kw).items() if k != "has_credentials"}


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


#: adapter id -> its settings keys as stored: the checkout's nine adapters (base `CATALOG_KEYS`, #1366 O2).
CATALOG_KEYS = {
    "elastic": ("ELASTIC_EVENTS_INDEX", "ELASTIC_ALERTS_INDEX"),
    "jira": ("JIRA_TIMEOUT_SEC", "JIRA_SERVICE_DESK"),
    "servicenow": ("SERVICENOW_TIMEOUT_SEC", "SERVICENOW_TABLE"),
    "change-mgmt": ("CHANGE_MGMT_TIMEOUT_SEC",),
    "cmdb": ("CMDB_TIMEOUT_SEC",),
    "host-state": (),
    "identity": ("IDENTITY_TIMEOUT_SEC",),
    "threat-intel": ("THREAT_INTEL_TIMEOUT_SEC",),
    "ticket": ("TICKET_TIMEOUT_SEC", "TICKET_KEY_PATTERN"),
}


def _declared(adapter: str):
    """The adapter's module: its `PREFIX`, `REQUIRED_CONFIG_KEYS`, `DISPLAY_NAME` and `EXAMPLE` are the cold-readable
    constants the catalog is read from, so the served entry is judged against them, not a second copy."""
    import importlib

    return importlib.import_module(f"defender.integrations.{adapter.replace('-', '_')}_adapter")


async def test_o2_the_served_catalog_is_exactly_the_checkouts_adapters(scripted):
    """Premise of the per-adapter rows: the nine adapters on disk are the table's, and the catalog serves each. (O2)"""
    on_disk = {p.stem.removesuffix("_adapter").replace("_", "-")
               for p in (REPO / "defender/integrations").glob("*_adapter.py")}
    assert on_disk == set(CATALOG_KEYS) == LAB | REAL
    assert {i["adapter_id"] for i in (await scripted.get("/adapters")).json()["items"]} == set(CATALOG_KEYS)


@pytest.mark.parametrize("adapter", sorted(CATALOG_KEYS))
async def test_o2_each_adapters_served_entry_is_what_its_module_declares(scripted, adapter):
    """Per adapter: `display_name` is its module's `DISPLAY_NAME`, `settings_keys` exactly the keys its module requires
    (`<PREFIX>_<key>`, none missing, none extra), `lab_example` its `EXAMPLE` flag. (O2; base
    `test_1366_o2_the_catalog_lists_every_adapter_with_its_display_name_exact_required_keys_and_example_mark`)"""
    module = _declared(adapter)
    declared = {f"{module.PREFIX}_{k}" for k in module.REQUIRED_CONFIG_KEYS}
    assert declared == set(CATALOG_KEYS[adapter]), f"premise: {adapter}'s declared constants are the design's keys"
    [item] = [i for i in (await scripted.get("/adapters")).json()["items"] if i["adapter_id"] == adapter]
    assert item["display_name"] == module.DISPLAY_NAME, (adapter, item)
    assert set(item["settings_keys"]) == declared, (adapter, item)
    assert len(item["settings_keys"]) == len(declared), (adapter, item)
    assert item["lab_example"] is bool(module.EXAMPLE), (adapter, item)


#: Every adapter module the checkout carries (the catalog's members, by what is on disk).
_ON_DISK = sorted(p.stem.removesuffix("_adapter").replace("_", "-") for p in (REPO / "defender/integrations").glob("*_adapter.py"))


def _sample_read_cold(adapter: str) -> object:
    """The module's `SAMPLE_SETTINGS` as written in its source (a literal, read without importing the module)."""
    import ast

    source = (REPO / "defender/integrations" / f"{adapter.replace('-', '_')}_adapter.py").read_text("utf-8")
    found = [node.value for node in ast.parse(source).body
             if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None
             and any(isinstance(t, ast.Name) and t.id == "SAMPLE_SETTINGS"
                     for t in (node.targets if isinstance(node, ast.Assign) else [node.target]))]
    assert len(found) == 1, f"{adapter} declares SAMPLE_SETTINGS once"
    return ast.literal_eval(found[0])


def _access_for(adapter: str, sample: dict[str, str]) -> str:
    """The fixture's access folder where it has one; jira and servicenow, which it lacks, get one built here, covering
    the comment route their sample settings name."""
    if adapter in R.FIXTURE_FOLDERS:
        return R.FIXTURE_FOLDERS[adapter][1]
    routes = {"jira": ("POST", "/rest/api/3/issue/*/comment"),
              "servicenow": ("PATCH", f"/api/now/table/{sample.get('SERVICENOW_TABLE')}/*")}
    return R.declaration(f"https://{adapter}.example", writes=(routes[adapter],))


@pytest.mark.parametrize("adapter", _ON_DISK)
async def test_o2_each_adapters_own_check_accepts_the_sample_settings_the_catalog_serves(scripted, adapter):
    """For every adapter in the catalog: the served `sample_settings` is its module's `SAMPLE_SETTINGS` read cold, and a
    record of it carrying exactly those settings is stored (201): its own check accepts them. (O2, D11)"""
    sample = {i["adapter_id"]: i["sample_settings"] for i in (await scripted.get("/adapters")).json()["items"]}[adapter]
    assert sample == _sample_read_cold(adapter), adapter
    saved = await scripted.put_system(adapter, 0, settings=sample, access=_access_for(adapter, sample))
    assert saved.status_code == 201, saved.text
    assert saved.json()["settings"] == sample


# --- each version row's author ----------------------------------------------------------------------------------------

def _version_row_writes(app) -> list[tuple[str, str]]:
    """Every config write route the app serves that writes a record version: its systems and case-record PUT and DELETE
    (the credentials route writes the secret store, not a version row)."""
    from defender.tests.support.api._config1470 import served_config_routes

    return sorted(r for r in served_config_routes(app) if r[0] in ("PUT", "DELETE") and not r[1].endswith("/credentials"))


async def test_1470_each_version_row_a_config_write_inserts_names_the_acting_member_as_its_author(scripted):
    """Over every config write route that inserts a version row (read from the app's own table), with the version it
    replaces planted by another author: the route adds one row, and its author is the acting member's id (Ann), neither
    the tenant's id nor the replaced row's author. (Design: each version row's author is the acting member's id; O4-O6)"""
    from defender.tests.support.shared._postgres1339 import execute

    ann = scripted.user_id(ANN)
    assert ann != A, "premise: the acting member's id is not the tenant's"
    routes = _version_row_writes(scripted.app)
    assert {m for m, _ in routes} == {"PUT", "DELETE"}, routes
    assert len(routes) >= 4, routes  # noqa: PLR2004 — premise: the systems and case-record writes are found
    scripted.plant_version(TICKET, 1)  # the case record's system, for its cover
    authors: dict[tuple[str, str], tuple[int, str]] = {}
    for method, template in routes:
        case = template.endswith("/case-record")
        rows = (lambda: [(c.version, c.author) for c in R.case_versions(scripted.dsn, A)]) if case else (
            lambda: [(v.version, v.author) for v in scripted.versions(ELASTIC)])
        version = (rows()[-1][0] if rows() else 0) + 1
        if case:
            execute(scripted.dsn, "INSERT INTO tenancy.case_versions (tenant_id, version, system_id, comment_body, deleted, "
                                  "author, written_at) VALUES (%s, %s, %s, %s, false, 'planted', now())",
                    (A, version, TICKET, BODY))
            body = {"replaces": version, "system_id": TICKET, "comment_body": BODY}
        else:
            scripted.plant_version(ELASTIC, version, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)
            body = {"replaces": version, "enabled": True, "settings": ELASTIC_SETTINGS, "access": ELASTIC_ACCESS}
        path = template.replace("{}", A, 1).replace("{}", ELASTIC, 1)
        kw = {"json": body} if method == "PUT" else {"params": {"replaces": version}}
        answered = await scripted.client.request(method, path, headers=scripted.ann(), **kw)
        assert answered.status_code < 300, (method, template, answered.text)  # noqa: PLR2004
        after = rows()
        assert [n for n, _ in after][-2:] == [version, version + 1], ((method, template), "one row added", after)
        authors[(method, template)] = after[-1]
    assert {route: author for route, (_, author) in authors.items()} == dict.fromkeys(routes, ann), authors


# --- O3 / O4: save and read a system ---------------------------------------------------------------------------------

async def test_o3_o4_a_system_is_created_201_replaced_200_and_read_back_as_stored(configured):
    """`replaces: 0` is 201 at version 1; one naming 1 is 200 at version 2; reads answer the record. (O3, O4)"""
    assert (await configured.get_system(TICKET)).status_code == 404  # never written: absent
    assert (await configured.list_systems()).json()["items"] == []
    created = await configured.put_system(TICKET, 0)
    assert created.status_code == 201, created.text
    assert created.headers["Location"] == f"/api/tenants/{A}/systems/{TICKET}"  # as every create names its resource
    assert created.json() == _saved(1)
    assert (await configured.get_system(TICKET)).json() == _served(1)

    edited = TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"}
    replaced = await configured.put_system(TICKET, 1, settings=edited, enabled=False)
    assert replaced.status_code == 200, replaced.text
    assert "Location" not in replaced.headers
    assert replaced.json() == _saved(2, settings=edited, enabled=False)
    other = await configured.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)
    assert other.status_code == 201, other.text
    listed = (await configured.list_systems()).json()["items"]
    assert {i["system_id"]: i["version"] for i in listed} == {TICKET: 2, ELASTIC: 1}
    assert [(v.version, v.settings, v.enabled) for v in configured.versions(TICKET)] == [
        (1, TICKET_SETTINGS, True), (2, edited, False)]
    assert {v.author for v in configured.versions(TICKET)} == {configured.user_id(ANN)}


async def test_o3_the_systems_list_serves_each_systems_enabled_flag_and_whether_it_holds_credentials(scripted):
    """Each listed row answers its own `enabled` and `has_credentials`: ticket enabled with a set, elastic disabled
    without; after ticket's base moves, ticket is enabled with no set at the new generation. (O3, P3)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    assert (await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204
    other = await scripted.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS, enabled=False)
    assert other.status_code == 201, other.text

    listed = (await scripted.list_systems()).json()["items"]

    assert {i["system_id"]: (i["enabled"], i["has_credentials"]) for i in listed} == {
        TICKET: (True, True), ELASTIC: (False, False)}

    moved = await scripted.put_system(TICKET, 1, access=TICKET_ACCESS.replace(*BASE_MOVED))
    assert moved.status_code == 200, moved.text
    listed = (await scripted.list_systems()).json()["items"]

    assert {i["system_id"]: (i["enabled"], i["has_credentials"]) for i in listed} == {
        TICKET: (True, False), ELASTIC: (False, False)}, "a new base raises the generation: no set at it yet"


async def test_o3_a_current_record_whose_adapter_the_catalog_lacks_reads_with_no_display_name_and_can_be_deleted(scripted):
    """A record an upgrade left naming a removed adapter: display name null on read; its delete is 204. (O3, O5)"""
    scripted.plant_version("retired", 1, adapter="retired")
    read = await scripted.get_system("retired")
    assert read.status_code == 200, read.text
    assert read.json()["display_name"] is None
    assert (await scripted.delete_system("retired", 1)).status_code == 204
    assert (await scripted.get_system("retired")).status_code == 404


#: Each write beside a record an upgrade left naming a removed adapter: what it plants first, the write, its status.
_BESIDE_RETIRED = {
    "a-put-of-another-system": ((), lambda served: served.put_system(TICKET, 0), 201),
    "a-case-record-put": ((TICKET,), lambda served: served.put_case(0), 201),
    "a-delete-of-another-system": ((ELASTIC,), lambda served: served.delete_system(ELASTIC, 1), 204),
}


@pytest.mark.parametrize("write", list(_BESIDE_RETIRED))
async def test_o4_o5_a_current_record_whose_adapter_the_catalog_lacks_blocks_no_write_of_another_record(scripted, write):
    """A record naming a removed adapter is not judged by a write that leaves it unchanged: the write stands and the
    record stays current; replacing that record itself is still 422 naming it (control). (O4, O5, #1366 C4)"""
    planted, call, status = _BESIDE_RETIRED[write]
    scripted.plant_version("retired", 1, adapter="retired")
    for system in planted:
        scripted.plant_version(system, 1, settings=ELASTIC_SETTINGS if system == ELASTIC else None,
                               access=ELASTIC_ACCESS if system == ELASTIC else None)
    answer = await call(scripted)
    assert answer.status_code == status, answer.text
    assert [(v.version, v.deleted) for v in scripted.versions("retired")] == [(1, False)]
    faults = _judged(await scripted.put_system("retired", 1, settings={"RETIRED_TIMEOUT_SEC": "10"}))
    assert any("retired" in f for f in faults), faults


async def test_d8_a_write_is_judged_over_the_catalog_built_at_start_reading_no_adapter_file(migrated_database, tmp_path,
                                                                                            monkeypatch):
    """The checkout's adapters are read once, at start: an adapter whose import fails was imported once and each write
    naming it is 422 with its load fault, and once the adapters directory is gone writes are still judged. (D8, #1470)"""
    checkout, counter = tmp_path / "checkout", tmp_path / "imports"
    folder = checkout / "integrations"
    write_broken_adapter(folder, counter)
    shutil.copy(REPO / "defender/integrations/ticket_adapter.py", folder / "ticket_adapter.py")
    monkeypatch.setenv("DEFENDER_DIR", str(checkout))
    saved_path = list(sys.path)  # the copied adapter puts its checkout's parent on sys.path when imported
    try:
        async with served_config(migrated_database, tmp_path, scripted=ScriptedOpenBao()) as served:
            listed = (await served.get("/adapters")).json()["items"]
            assert {i["adapter_id"] for i in listed} == {"broken", TICKET}, "premise: the catalog is the tmp checkout's"
            assert counter.read_text() == "x", "premise: start imported the broken adapter"
            for _ in range(3):
                faults = _judged(await served.put_system("broken", 0, settings={"BROKEN_TIMEOUT_SEC": "10"}))
                assert any("broken" in f and "could not be loaded" in f for f in faults), faults
            assert counter.read_text() == "x", "a write imported the broken adapter again"
            shutil.rmtree(folder)
            assert (await served.put_system(TICKET, 0)).status_code == 201
            faults = _judged(await served.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_BOGUS": "1"}))
            assert any("TICKET_BOGUS" in f for f in faults), faults
            faults = _judged(await served.put_system("broken", 0, settings={"BROKEN_TIMEOUT_SEC": "10"}))
            assert any("broken" in f and "could not be loaded" in f for f in faults), faults
            assert [v.version for v in served.versions(TICKET)] == [1]
    finally:
        sys.path[:] = saved_path


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
    refused = await configured.put_raw(f"/api/tenants/{A}/systems/{TICKET}", body)
    assert refused.status_code == 422, refused.text
    assert "faults" not in refused.json()
    assert refused.json()["errors"], refused.json()
    assert drop in str(refused.json()["errors"])
    extra = await configured.put_raw(f"/api/tenants/{A}/systems/{TICKET}",
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


async def test_o3_a_page_whose_row_fails_answers_that_failure_at_once_and_asks_no_more_for_the_rest():
    """The list asks about its rows at once; when one fails, the page answers that failure itself (its own type, so its
    handler answers it; not a group of failures), without waiting for the rows still asking, which are cancelled and
    hold no pooled connection. (O3; #1526 review)"""
    from defender.api.app import _all_or_first_failure
    from defender.api.ports import SecretStoreUnavailable

    still_asking: list[str] = []

    async def fails() -> bool:
        await anyio.sleep(0.05)
        raise SecretStoreUnavailable("the secret store cannot say")

    async def hangs() -> bool:
        try:
            await anyio.sleep_forever()
        finally:
            still_asking.append("cancelled")
        return True

    async def answers() -> bool:
        return True

    assert await _all_or_first_failure([answers(), answers()]) == [True, True]  # control: every answer, in order
    with anyio.fail_after(5), pytest.raises(SecretStoreUnavailable):
        await _all_or_first_failure([hangs(), fails(), hangs()])
    assert still_asking == ["cancelled", "cancelled"]


async def test_o3_the_systems_list_pages_by_cursor_serving_every_system_once_in_id_order(configured):
    """`limit=1` walks three saved systems in id order, each once, the last page's cursor null; the page is the `Page`
    envelope (`items`, `next_cursor`). (O3, lists keep the Page envelope)"""
    ids = await _save_three(configured)
    seen: list[str] = []
    params: dict[str, object] = {"limit": 1}
    for _ in range(len(ids) + 1):
        page = (await configured.client.get(f"/api/tenants/{A}/systems", params=params,
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
    page = (await scripted.client.get(f"/api/tenants/{A}/systems", params={"limit": 1}, headers=scripted.ann(write=False))).json()
    assert [i["system_id"] for i in page["items"]] == [first]
    paths = [p for _, p in scripted.scripted.calls if f"/{A}/" in p]
    assert paths, scripted.scripted.calls
    assert all(f"/{A}/{first}/" in p for p in paths), paths
    assert not [p for p in paths for other in others if f"/{other}/" in p], paths


@pytest.mark.parametrize("bad_id", ["a b/é", "' OR 1=1 --", "", "\u0000", "x" * 1363])
async def test_o3_an_edited_cursor_naming_an_id_outside_the_grammar_is_refused_before_the_secret_store(scripted, bad_id):
    """A cursor whose id was edited to something no system id can be is 422, and the secret store is asked nothing. (O3)"""
    await _save_three(scripted)
    first = (await scripted.client.get(f"/api/tenants/{A}/systems", params={"limit": 1}, headers=scripted.ann(write=False))).json()
    scripted.scripted.calls.clear()
    refused = await scripted.client.get(f"/api/tenants/{A}/systems", headers=scripted.ann(write=False),
                                        params={"limit": 1, "cursor": edited_cursor(first["next_cursor"], id=bad_id)})
    assert refused.status_code == 422, refused.text
    assert scripted.scripted.calls == []


async def test_o3_a_systems_cursor_is_bound_to_its_tenant_even_for_a_member_of_both(scripted):
    """Ann, made a member of B too, cannot carry A's cursor to B's list (422); the same cursor works in A (control). (O3)"""
    import datetime as dt

    from defender.identity.postgres import PostgresIdentityRepository
    from defender.records.formats import TenantId, UserId
    from defender.tests.support.identity._seed1496 import seed_membership

    await _save_three(scripted)
    now = dt.datetime.now(dt.UTC)
    repo = PostgresIdentityRepository(scripted.dsn)
    try:
        await seed_membership(repo, UserId(scripted.user_id(ANN)), TenantId(B), status="active", invited_by=None, created_at=now, accepted_at=now)
    finally:
        await repo.close()
    headers = scripted.ann(write=False)
    cursor = (await scripted.client.get(f"/api/tenants/{A}/systems", params={"limit": 1}, headers=headers)).json()["next_cursor"]
    assert (await scripted.client.get(f"/api/tenants/{A}/systems", params={"limit": 1, "cursor": cursor}, headers=headers)).status_code == 200
    calls = len(scripted.scripted.calls)
    assert (await scripted.client.get(f"/api/tenants/{B}/systems", params={"cursor": cursor}, headers=headers)).status_code == 422
    assert len(scripted.scripted.calls) == calls


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
    assert recreated.headers["Location"] == f"/api/tenants/{A}/systems/{TICKET}"
    assert recreated.json() == _saved(3)
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
    refused = await configured.client.delete(f"/api/tenants/{A}/systems/{TICKET}", headers=configured.ann())
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
    path = f"/api/tenants/{A}/case-record"
    assert (await configured.get("/case-record")).status_code == 404
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    created = await configured.put_case(0)
    assert created.status_code == 201, created.text
    assert created.headers["Location"] == path  # a path, never an absolute URL (#1161 B3)
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
    assert again.headers["Location"] == path
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
    document = (await scripted.client.get("/api/openapi.json")).json()
    properties = document["components"]["schemas"]["Problem"]["properties"]
    assert properties["faults"]["type"] == "array" or "array" in str(properties["faults"])
    assert "integer" in str(properties["current_version"])
    put = document["paths"]["/api/tenants/{tenant_id}/systems/{system_id}"]["put"]["responses"]
    assert {"201", "200", "409", "422"} <= set(put), set(put)


# --- D13: the served system models hold the id to the grammar -------------------------------------------------------

SYSTEM_ROUTE = "/api/tenants/{tenant_id}/systems/{system_id}"


def _response_model(app, method: str, template: str):
    """The model the app declares for the answer of `method template`, from the app's own route table (the design names
    no class, so none is imported)."""
    from defender.tests.support.api._routes1307a import _served

    [route] = [r for r in _served(app.routes) if r.path == template and method in r.methods]
    model = getattr(route, "response_model", None)
    assert model is not None, f"{method} {template} declares no response model"
    return model


@pytest.mark.parametrize("bad", ["a/b", "a b", "a?b#c", "é", ""])
async def test_d13_an_id_outside_the_grammar_cannot_be_served_as_a_system(scripted, bad):
    """The served system models (a single read's and a list's item) refuse to be built from an id outside the grammar
    (a hand-edited row): base `test_an_id_outside_the_grammar_cannot_be_served`'s own `bad` ids, with its own
    `pytest.raises(ValueError, match="pattern")`. The unedited answer builds (control). (D13)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    served = (await scripted.get_system(TICKET)).json()
    listed = (await scripted.list_systems()).json()
    one, many = _response_model(scripted.app, "GET", SYSTEM_ROUTE), _response_model(scripted.app, "GET", "/api/tenants/{tenant_id}/systems")
    one.model_validate(served)
    many.model_validate(listed)
    with pytest.raises(ValueError, match="pattern"):
        one.model_validate({**served, "system_id": bad})
    with pytest.raises(ValueError, match="pattern"):
        many.model_validate({**listed, "items": [{**listed["items"][0], "system_id": bad}]})


async def test_d13_the_published_schema_of_a_served_system_carries_the_id_pattern(scripted):
    """The OpenAPI document's system answer holds `system_id` to a pattern. (D13)"""
    document = (await scripted.client.get("/api/openapi.json")).json()
    ref = document["paths"][SYSTEM_ROUTE]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    schema = document["components"]["schemas"][ref.rsplit("/", 1)[1]]
    assert "pattern" in schema["properties"]["system_id"], schema["properties"]["system_id"]


# --- a record-store fault on a system write --------------------------------------------------------------------------

async def test_o4_a_database_fault_on_a_system_write_is_500_and_announces_nothing(scripted, caplog):
    """The version table gone while a replacing save runs (a fault the store cannot answer): 500, no event announced; once
    it is back the same save is 200 at version 2 (control). Base: a failing write port is a 500 that announces nothing.
    (Am-2, P2; the generic 500 handler)"""
    import logging

    from defender.tests.support.shared._postgres1339 import execute

    caplog.set_level(logging.DEBUG)
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    caplog.clear()
    body = {"replaces": 1, "enabled": True, "settings": TICKET_SETTINGS, "access": TICKET_ACCESS}
    execute(scripted.dsn, "ALTER TABLE tenancy.system_versions RENAME TO sv_away")
    try:
        async with scripted.lenient() as client:
            refused = await client.put(f"/api/tenants/{A}/systems/{TICKET}", headers=scripted.ann(), json=body)
    finally:
        execute(scripted.dsn, "ALTER TABLE tenancy.sv_away RENAME TO system_versions")
    assert refused.status_code == 500, refused.text
    assert [r for r in caplog.records if getattr(r, "action", None) == "system.update"] == []
    assert [v.version for v in scripted.versions(TICKET)] == [1]
    assert (await scripted.put_raw(f"/api/tenants/{A}/systems/{TICKET}", body)).status_code == 200


# --- reads and writes with the secret store sealed or failing --------------------------------------------------------

async def test_o3_o4_while_the_secret_store_is_sealed_system_reads_are_503_saves_succeed_and_each_request_asks_again(scripted):
    """Sealed: reading a system and listing are 503 naming the sealed secret store, reading no value; a save (create
    or replace), the catalog and the case record need no answer from it and make no call; unsealed, the same app
    answers (no seal state is kept). (O3, O4, C20; r8 Am-2: a save asks no secret store)"""
    bao = scripted.scripted
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    bao.sealed = True
    for refused in (await scripted.get_system(TICKET), await scripted.list_systems()):
        assert refused.status_code == 503, refused.text
        assert "sealed" in problem_text(refused).lower(), refused.text
    bao.calls.clear()
    replaced = await scripted.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})
    assert replaced.status_code == 200, replaced.text
    created = await scripted.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)
    assert created.status_code == 201, created.text
    assert (await scripted.get("/adapters")).status_code == 200
    assert (await scripted.get("/case-record")).status_code == 404  # records, not the secret store
    assert [v.version for v in scripted.versions(TICKET)] == [1, 2]
    assert bao.calls == []
    assert bao.paths() == []  # nothing written
    assert bao.value_reads == []  # no value read
    bao.sealed = False
    assert (await scripted.get_system(TICKET)).status_code == 200
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


async def test_o3_a_secret_store_that_refuses_the_apis_login_after_start_is_500_on_reads_and_a_save_still_succeeds(scripted):
    """A 403 once the API is running: a read and a list are 500 naming the secret store's refusal, not 503; a save
    (create or replace), needing no answer, still succeeds. (O3, O7; r8 Am-2)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    scripted.scripted.token = "no-longer-the-apis"  # the stand-in now refuses the token the API sends
    for refused in (await scripted.get_system(TICKET), await scripted.list_systems()):
        assert refused.status_code == 500, refused.text
        assert "secret store" in problem_text(refused).lower(), refused.text
    replaced = await scripted.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})
    assert replaced.status_code == 200, replaced.text
    assert (await scripted.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)).status_code == 201
    assert [v.version for v in scripted.versions(TICKET)] == [1, 2]


async def test_o4_a_save_asks_the_secret_store_nothing_and_its_answer_carries_no_has_credentials(scripted):
    """Create, replace, delete, re-create: no call reaches the secret store, and no save's answer names
    `has_credentials` (a client reads the system for it). (O4; r8 Am-2)"""
    answers = [await scripted.put_system(TICKET, 0),
               await scripted.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})]
    assert (await scripted.delete_system(TICKET, 2)).status_code == 204
    answers.append(await scripted.put_system(TICKET, 0))
    assert [a.status_code for a in answers] == [201, 200, 201], [a.text for a in answers]
    assert all("has_credentials" not in a.json() for a in answers), [a.json() for a in answers]
    assert scripted.scripted.calls == []


async def test_o4_the_published_schema_of_a_save_answer_carries_no_has_credentials_and_a_read_does(scripted):
    """The OpenAPI document: `PUT /systems/{id}` answers (200 and 201) a model with no `has_credentials`; `GET` answers
    one with it. (O3, O4; r8 Am-2)"""
    doc = (await scripted.client.get("/api/openapi.json")).json()
    path = doc["paths"]["/api/tenants/{tenant_id}/systems/{system_id}"]

    def props(answer: dict) -> set[str]:
        ref = answer["content"]["application/json"]["schema"]["$ref"].rsplit("/", 1)[-1]
        return set(doc["components"]["schemas"][ref]["properties"])

    assert "has_credentials" in props(path["get"]["responses"]["200"])
    for code in ("200", "201"):
        assert "has_credentials" not in props(path["put"]["responses"][code]), code
        assert {"system_id", "version", "enabled", "settings", "access"} <= props(path["put"]["responses"][code])


async def test_o3_a_secret_store_that_cannot_answer_fails_the_read_and_a_save_still_commits(scripted):
    """A 500 to the existence read: reads 503 naming the secret store; a replacing save commits (it asks nothing);
    healthy again, 200. (O3, O4; r8 Am-2)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    scripted.scripted.answer("GET", "metadata", httpx.Response(500, json={"errors": ["boom"]}), times=2)
    for refused in (await scripted.get_system(TICKET), await scripted.list_systems()):
        assert refused.status_code == 503, refused.text
        assert "secret store" in problem_text(refused).lower()
    saved = await scripted.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})
    assert saved.status_code == 200, saved.text
    assert [v.version for v in scripted.versions(TICKET)] == [1, 2]
    assert (await scripted.get_system(TICKET)).status_code == 200


_UNREADABLE_METADATA = [
    ("not JSON", httpx.Response(200, content=b"<html>proxy error</html>")),
    ("no data object", httpx.Response(200, json={"request_id": "x"})),
    ("data not an object", httpx.Response(200, json={"data": []})),
]


@pytest.mark.parametrize(("label", "answer"), _UNREADABLE_METADATA, ids=[u[0] for u in _UNREADABLE_METADATA])
async def test_o3_an_existence_answer_that_cannot_be_read_is_503_naming_the_secret_store(scripted, label, answer):
    """A 200 to the existence read that is not KV metadata: a read and a list are 503 naming the secret store (no
    usable answer), never 500; healthy again, 200. (O3; r8 Am-1)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    scripted.scripted.answer("GET", "metadata", answer, times=2)
    for refused in (await scripted.get_system(TICKET), await scripted.list_systems()):
        assert refused.status_code == 503, (label, refused.text)
        assert "secret store" in problem_text(refused).lower(), refused.text
    assert (await scripted.get_system(TICKET)).status_code == 200


async def test_o4_has_credentials_is_true_exactly_while_a_set_exists_at_the_current_generation(configured):
    """A set stored for v1: a read answers true, also after a same-generation save; after a save that moves the base
    a read answers false. (O3, O4, D-D)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is False
    assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is True
    same = await configured.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})
    assert same.status_code == 200, same.text
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is True
    moved = await configured.put_system(TICKET, 2, access=TICKET_ACCESS.replace(*BASE_MOVED))
    assert moved.status_code == 200
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is False
    assert [v.credential_generation for v in configured.versions(TICKET)] == [1, 1, 2]


async def test_o4_a_save_naming_0_after_another_admin_deleted_is_201_at_the_next_version(scripted):
    """v1 holds a set; another admin deletes the system; a save naming 0 (the caller's view had none) is 201 with
    `Location` at version 3, as the store's created flag says; a read then answers `has_credentials` false (a new
    generation). A plain replace after is 200 with no `Location`. (O4: created decided by the store under the lock; D12)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    assert (await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204
    assert (await scripted.delete_system(TICKET, 1)).status_code == 204
    saved = await scripted.put_system(TICKET, 0)
    assert [(v.version, v.deleted) for v in scripted.versions(TICKET)] == [(1, False), (2, True), (3, False)]
    assert saved.status_code == 201, saved.text
    assert saved.headers.get("location", "").endswith(f"/api/tenants/{A}/systems/{TICKET}"), saved.headers
    assert saved.json()["version"] == 3
    assert (await scripted.get_system(TICKET)).json()["has_credentials"] is False

    replaced = await scripted.put_system(TICKET, 3, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})
    assert (replaced.status_code, "location" in replaced.headers) == (200, False), replaced.text


_INACTIVE = ["offboarding", "offboarded", "gone"]


@pytest.mark.parametrize("state", _INACTIVE)
async def test_o8_a_config_read_of_a_tenant_that_left_active_is_the_refusal_a_write_gets(scripted, state):
    """Admission refuses a tenant that is not active (404), so a config read meets one only when the tenant leaves
    `active` after admission. The read is then refused by the one tenant rule with the type a write gets
    (`TenantNotActive`, `NoSuchTenant`), which the app answers 409 / 404 by type; never an unmapped one, a 500.
    Asked of the systems port the program builds, after the state change. (O8; r9)"""
    from defender.api.config_records import ConfigRecords
    from defender.credential_proxy import OpenBaoSecrets
    from defender.system_records import NoSuchTenant, TenantNotActive
    from defender.system_rules import Catalog
    from defender.tests.support.jobs._jobs1342 import fixed_clock, move_tenant
    from defender.api_server import record_store
    from defender.tenancy.postgres import PostgresTenantRepository

    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    assert (await scripted.put_case(0)).status_code == 201
    catalog = Catalog.of_checkout()
    store = record_store(scripted.dsn, catalog, clock=fixed_clock)
    tenants = PostgresTenantRepository(scripted.dsn)
    port = ConfigRecords(store, tenants, catalog, OpenBaoSecrets(addr="http://openbao.test:8200", token="t",
                                                                 mount="secret", transport=scripted.scripted))
    try:
        assert [r.system_id for r in await port.list_systems(A, after=None, limit=10)] == [TICKET]  # control
        if state == "gone":
            await remove_tenant(scripted.dsn, A)
        else:
            await anyio.to_thread.run_sync(lambda: move_tenant(scripted.dsn, A, state=state))
        refusal = NoSuchTenant if state == "gone" else TenantNotActive
        for read in (lambda: port.list_systems(A, after=None, limit=10), lambda: port.get_system(A, TICKET),
                     lambda: port.get_case_record(A)):
            with pytest.raises(refusal):
                await read()
    finally:
        await store.close()
        await tenants.close()


# --- membership ------------------------------------------------------------------------------------------------------

async def test_o4_another_tenants_admin_writes_nothing_of_this_tenant_and_asks_no_secret_store(scripted):
    """Ann, admin of A only, naming tenant B, which holds a system, its credentials and a case record (put there by
    Bob, B's admin): 404 on each config route, nothing written, no secret-store call. B holds records so that a skipped
    membership check would answer 200/204/409, not 404. (O4, O7)"""
    body = {"replaces": 0, "enabled": True, "settings": TICKET_SETTINGS, "access": TICKET_ACCESS}
    assert (await scripted.put_raw(f"/api/tenants/{B}/systems/{TICKET}", body, headers=scripted.bob())).status_code == 201
    case = {"replaces": 0, "system_id": TICKET, "comment_body": BODY}
    assert (await scripted.put_raw(f"/api/tenants/{B}/case-record", case, headers=scripted.bob())).status_code == 201
    creds = {"for_version": 1, "credentials": {"api_key": TOKEN}}
    assert (await scripted.put_raw(f"/api/tenants/{B}/systems/{TICKET}/credentials", creds,
                                   headers=scripted.bob())).status_code == 204
    held = scripted.stored_generations(TICKET, tenant=B)
    assert held, "B's credentials are held"
    scripted.scripted.calls.clear()

    assert (await scripted.get("/systems", tenant=B)).status_code == 404
    assert (await scripted.get(f"/systems/{TICKET}", tenant=B)).status_code == 404
    assert (await scripted.put_system(TICKET, 0, tenant=B)).status_code == 404
    assert (await scripted.put_system(TICKET, 1, tenant=B)).status_code == 404
    assert (await scripted.delete_system(TICKET, 1, tenant=B)).status_code == 404
    assert (await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN}, tenant=B)).status_code == 404
    assert (await scripted.get("/case-record", tenant=B)).status_code == 404
    assert (await scripted.put_raw(f"/api/tenants/{B}/case-record", case)).status_code == 404
    assert (await scripted.client.delete(f"/api/tenants/{B}/case-record", params={"replaces": 1},
                                         headers=scripted.ann())).status_code == 404
    assert [v.version for v in scripted.versions(TICKET, tenant=B)] == [1]
    assert [v.version for v in R.case_versions(scripted.dsn, B)] == [1]
    assert scripted.stored_generations(TICKET, tenant=B) == held
    assert scripted.scripted.calls == []
    assert (await scripted.put_system(TICKET, 0)).status_code == 201  # control: her own tenant


# --- O15: what still refuses names its real owner --------------------------------------------------------------------

async def test_o15_the_connection_check_still_refuses_501_naming_its_owner_not_this_piece(scripted):
    """A saved system's check is 501 naming #1460, never #1470; a stranger gets 404. (O15, D-C)"""
    assert (await scripted.put_system(TICKET, 0)).status_code == 201
    refused = await scripted.client.post(f"/api/tenants/{A}/systems/{TICKET}/check", headers=scripted.ann())
    assert refused.status_code == 501, refused.text
    assert "#1460" in refused.json()["detail"]
    assert "#1470" not in refused.json()["detail"]
    lessons = await scripted.client.get(f"/api/tenants/{A}/lessons", headers=scripted.ann(write=False))
    assert lessons.status_code == 501
    assert "#1082" in lessons.json()["detail"]
    assert "#1470" not in lessons.json()["detail"]
    stranger = await scripted.client.post(f"/api/tenants/{B}/systems/{TICKET}/check", headers=scripted.ann())
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
    refused = await configured.put_raw(f"/api/tenants/{A}/case-record", body)
    assert refused.status_code == 422, refused.text
    assert refused.json()["errors"]
    assert "faults" not in refused.json()
    extra = await configured.put_raw(f"/api/tenants/{A}/case-record",
                                     {"replaces": 0, "system_id": TICKET, "comment_body": BODY, "enabled": True})
    assert extra.status_code == 422, extra.text
    assert R.case_versions(configured.dsn, A) == []


async def test_r7_2_an_undeclared_query_parameter_on_a_system_write_is_refused_and_changes_nothing(configured):
    """`PUT /systems/ticket?x=1` is a 422 `extra_forbidden` at `["query", "x"]`; nothing is stored. (R7-2, O4)"""
    body = {"replaces": 0, "enabled": True, "settings": TICKET_SETTINGS, "access": TICKET_ACCESS}
    refused = await configured.put_raw(f"/api/tenants/{A}/systems/{TICKET}", body, params={"x": "1"})
    assert refused.status_code == 422, refused.text
    assert [(e["type"], e["loc"]) for e in refused.json()["errors"]] == [("extra_forbidden", ["query", "x"])]
    assert configured.versions(TICKET) == []
