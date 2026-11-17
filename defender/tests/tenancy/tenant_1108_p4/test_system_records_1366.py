"""#1366 slice W (write side), kept after #1470 over the store: the judgement and the store's rules for a tenant's system and
case records (O3-O5, P5, C2-C4, DC8, R7, G4), driven through `R.Admin` (the store with the real judgement, as the API
writes). Retired with #1470: the import (D-F), the operator's folder, file and printing surface (O10), and the credential
command (the credentials route's tests). Postgres-gated; the tenant is the published fixture, registered active with the
fixture's records."""
from __future__ import annotations

import asyncio
import dataclasses
import json
import random
import itertools
import re
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from defender.tests.support.jobs._jobs1342 import fixed_clock, register_tenant
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant, second_tenant

REPO = Path(__file__).resolve().parents[4]
CMDB_CONFIG, CMDB_ACCESS = R.FIXTURE_FOLDERS["cmdb"]  # the imported version 1: rewrites differ in one thing only
CMDB_NEW = {"CMDB_TIMEOUT_SEC": "20"}
TICKET_CONFIG, TICKET_ACCESS = R.FIXTURE_FOLDERS["ticket"]
TICKET_BASE = "http://soc-playground:8004"
IDENTITY = {"IDENTITY_TIMEOUT_SEC": "10"}
IDENTITY_BASE = "http://soc-playground:8005"
JIRA_BASE = "https://acme.atlassian.net"
JIRA_API, JIRA_DESK = ("POST", "/rest/api/3/issue/*/comment"), ("POST", "/rest/servicedeskapi/request/*/comment")
JIRA_CONFIG = {"JIRA_TIMEOUT_SEC": "10", "JIRA_SERVICE_DESK": "no"}
SN_CONFIG = {"SERVICENOW_TIMEOUT_SEC": "10", "SERVICENOW_TABLE": "incident"}
SN_ROUTE = ("PATCH", "/api/now/table/incident/*")
#: Words a fault names a FILE by (DC6: a fault names the record, "system <s> settings" / "system <s> access").
FILE_WORDS = ("config.env", "access.yaml", "settings/systems")
RETIRED, RETIRED_CASE = "legacy-widget", "legacy-ticket"  # records naming an adapter an upgrade removed (O3, design "Flows")
ALL_SYSTEMS = tuple(sorted({*R.FIXTURE_SYSTEMS, *R.REAL, "frobnicator", "tacit-knowledge", RETIRED, RETIRED_CASE}))


def _operator(tenant: Any, dsn: str, tmp_path: Path, capsys: Any, monkeypatch: Any, **kw: Any) -> R.Admin:
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", dsn)
    register_tenant(dsn, tenant.tenant_id, data_root=tenant.data_root)  # the fixture's records
    return R.Admin(tenant.tenant_id, dsn, tmp_path / "op", capsys, **kw)


@pytest.fixture
def fixture_tenant(tmp_path, data_root):
    """The fixture tenant under this test's data root, publishing the retired folders `R.import_files()` plants."""
    with published_tenant(tmp_path / "forge", root=data_root, files=R.import_files()) as published:
        yield published


@pytest.fixture
def op(fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch):  # noqa: F811 — the imported fixture
    """The fixture tenant, registered with its records."""
    return _operator(fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch)


@pytest.fixture
def imported_op(op):
    return op


def _jira_access(*writes: tuple[str, str], reads: tuple = ()) -> str:
    return R.declaration(JIRA_BASE, writes=writes, reads=reads)


def _case_versions(op: R.Admin) -> list[tuple[int, str, bool]]:
    return [(c.version, c.system_id, c.deleted) for c in R.case_versions(op.dsn, op.tid)]


def _state(op: R.Admin) -> tuple[dict[str, list[tuple[int, int, bool]]], list[tuple[int, str, bool]]]:
    """Everything the records tables hold for the tenant, as (numbers per system, case versions)."""
    return {s: op.numbers(s) for s in ALL_SYSTEMS}, _case_versions(op)


def _refused(op: R.Admin, before: Any, rc: int, said: str, needles: tuple[tuple[str, ...], ...], *,
             file_ok: bool = False) -> None:
    """A refusal: non-zero, each needle (words sharing one line) present, no file named unless `file_ok`, no
    traceback, and the tables exactly as `before`."""
    assert rc != 0, said
    for words in needles:
        assert R.lines_naming(said, *words), (words, said)
    assert "Traceback" not in said, said
    if not file_ok:
        assert not [w for w in (*FILE_WORDS, str(op.tmp)) if w in said], said
    assert _state(op) == before






def _numbered(text: str, system: str, number: int) -> bool:
    """Some line names `system` and carries `number` as a number of its own (bare, or as `v<N>` / `g<N>`), not as a
    digit inside a path, an id or a timestamp."""
    pattern = re.compile(rf"(?<![\w.\-/])[vg]?{number}(?![\w.\-/])")
    return any(system in line and pattern.search(line) for line in text.splitlines())


# --- O3 / O4: the judgement refuses an unusable system record -------------------------------------------------

class Refusal(NamedTuple):
    id: str
    system: str
    config: Mapping[str, str] | None
    access: str | None
    needles: tuple[tuple[str, ...], ...]
    replaces: int = 1
    good: tuple[Mapping[str, str], str] | None = None
    file_ok: bool = False
    #: The control's system when the refusal is about the system's NAME (the good variant is a catalog id instead).
    good_system: str | None = None


_GOOD_CMDB = (CMDB_NEW, CMDB_ACCESS)
_ELASTIC_CONFIG, _ELASTIC_ACCESS = R.FIXTURE_FOLDERS["elastic"]
_rng = random.Random(1366)
#: undeclared keys by membership: another adapter's declared key, the unprefixed declared name, one past the declared
#: name, and seeded random names; none is a key cmdb declares.
UNDECLARED = ["CMDB_COLOUR", "IDENTITY_TIMEOUT_SEC", "TIMEOUT_SEC", "CMDB_TIMEOUT_SEC_EXTRA",
              *("K" + "".join(_rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789_") for _ in range(9)) for _ in range(3))]
_BAD_ACCESS = {
    "access-unparseable": "access: [unclosed\n",
    "access-not-a-mapping": "just some text\n",
    "access-wrong-kind": json.dumps({"access": "ssh", "base": "http://soc-playground:8001", "auth": {"scheme": "basic"}}),
    "access-base-not-a-url": R.declaration("soc-playground"),
    "access-unknown-key": json.dumps({"access": "http-proxy", "base": "http://soc-playground:8001", "auth": {"scheme": "basic"},
                                     "colour": "red"}),
    "access-duplicate-key": '{"access": "http-proxy", "access": "http-proxy", "base": "http://soc-playground:8001", "auth": {"scheme": "basic"}}',
    "access-placeholder": R.declaration("http://CHANGE-ME:8001"),
}
REFUSALS = [
    Refusal("unknown-catalog-id", "frobnicator", {}, CMDB_ACCESS, (("frobnicator",),), replaces=0,
            good=(JIRA_CONFIG, _jira_access(JIRA_API)), good_system="jira"),
    Refusal("platform-served-name", "tacit-knowledge", {}, CMDB_ACCESS, (("tacit-knowledge", "platform"),), replaces=0,
            good=(JIRA_CONFIG, _jira_access(JIRA_API)), good_system="jira"),
    *(Refusal(f"undeclared-key-{n}", "cmdb", {**CMDB_CONFIG, key: "x"}, CMDB_ACCESS, (("cmdb", key),), good=_GOOD_CMDB)
      for n, key in enumerate(UNDECLARED)),
    Refusal("undeclared-key-on-an-adapter-with-none", "host-state", {"HOST_STATE_COLOUR": "x"},
            R.FIXTURE_FOLDERS["host-state"][1], (("host-state", "HOST_STATE_COLOUR"),),
            good=({}, R.FIXTURE_FOLDERS["host-state"][1])),
    Refusal("missing-required-key", "cmdb", {}, CMDB_ACCESS, (("cmdb", "CMDB_TIMEOUT_SEC"),), good=_GOOD_CMDB),
    Refusal("no-settings-at-all", "cmdb", None, CMDB_ACCESS, (("cmdb", "CMDB_TIMEOUT_SEC"),), good=_GOOD_CMDB, file_ok=True),
    Refusal("blank-value", "cmdb", {"CMDB_TIMEOUT_SEC": ""}, CMDB_ACCESS, (("cmdb", "CMDB_TIMEOUT_SEC"),), good=_GOOD_CMDB),
    Refusal("change-me-value", "cmdb", {"CMDB_TIMEOUT_SEC": "CHANGE-ME"}, CMDB_ACCESS, (("cmdb", "CMDB_TIMEOUT_SEC"),), good=_GOOD_CMDB),
    *(Refusal(f"timeout-{n}", "cmdb", {"CMDB_TIMEOUT_SEC": v}, CMDB_ACCESS, (("cmdb", "TIMEOUT_SEC"),), good=_GOOD_CMDB)
      for n, v in (("zero", "0"), ("negative", "-5"), ("word", "ten"), ("fraction", "1.5"))),
    Refusal("jira-service-desk-maybe", "jira", {**JIRA_CONFIG, "JIRA_SERVICE_DESK": "maybe"}, _jira_access(JIRA_API),
            (("jira", "SERVICE_DESK"),), replaces=0, good=(JIRA_CONFIG, _jira_access(JIRA_API))),
    *(Refusal(f"servicenow-table-{n}", "servicenow", {**SN_CONFIG, "SERVICENOW_TABLE": v},
              R.declaration(JIRA_BASE, writes=(SN_ROUTE,)), (("servicenow", "TABLE"),), replaces=0,
              good=(SN_CONFIG, R.declaration(JIRA_BASE, writes=(SN_ROUTE,))))
      for n, v in (("space", "bad table"), ("slash", "a/b"), ("blank", ""))),
    *(Refusal(f"elastic-path-key-{n}", "elastic", {**_ELASTIC_CONFIG, "ELASTIC_EVENTS_INDEX": v}, _ELASTIC_ACCESS,
              (("elastic", "ELASTIC_EVENTS_INDEX"),), good=({**_ELASTIC_CONFIG, "ELASTIC_EVENTS_INDEX": "logs-2"}, _ELASTIC_ACCESS))
      for n, v in (("slash", "a/b"), ("dotdot", "../x"), ("backslash", "a\\b"))),
    # The base import-failure members whose adapter or text differs from the rows above (each with its own needles).
    Refusal("change-me-on-identity", "identity", {"IDENTITY_TIMEOUT_SEC": "CHANGE-ME"}, R.FIXTURE_FOLDERS["identity"][1],
            (("identity", "IDENTITY_TIMEOUT_SEC"),), good=(IDENTITY, R.FIXTURE_FOLDERS["identity"][1])),
    Refusal("missing-required-on-threat-intel", "threat-intel", {}, R.FIXTURE_FOLDERS["threat-intel"][1],
            (("threat-intel", "THREAT_INTEL_TIMEOUT_SEC"),), good=R.FIXTURE_FOLDERS["threat-intel"]),
    Refusal("zero-timeout-on-change-mgmt", "change-mgmt", {"CHANGE_MGMT_TIMEOUT_SEC": "0"}, R.FIXTURE_FOLDERS["change-mgmt"][1],
            (("change-mgmt", "CHANGE_MGMT_TIMEOUT_SEC"),), good=R.FIXTURE_FOLDERS["change-mgmt"]),
    Refusal("access-unparseable-on-change-mgmt", "change-mgmt", R.FIXTURE_FOLDERS["change-mgmt"][0], "access: [\n",
            (("change-mgmt", "access"),), good=R.FIXTURE_FOLDERS["change-mgmt"]),
    Refusal("access-empty-on-host-state", "host-state", R.FIXTURE_FOLDERS["host-state"][0], "",
            (("host-state", "access"),), good=R.FIXTURE_FOLDERS["host-state"]),
    Refusal("access-missing", "cmdb", CMDB_CONFIG, None, (("cmdb", "access"),), good=_GOOD_CMDB, file_ok=True),
    *(Refusal(name, "cmdb", CMDB_CONFIG, text, (("cmdb", "access"),), good=_GOOD_CMDB) for name, text in _BAD_ACCESS.items()),
]


@pytest.mark.postgres
@pytest.mark.parametrize("row", REFUSALS, ids=[r.id for r in REFUSALS])
def test_1366_o4_an_unusable_system_record_is_refused_naming_system_and_key_not_a_file_and_writes_nothing(imported_op, row):
    """Each unusable input is refused naming the system and the key or part, no file, and stores nothing; the good
    variant on the same channel is then stored as the next version. (#1366 O3, O4, P2, DC6)"""
    before = _state(imported_op)

    rc, said = imported_op.set_system(row.system, replaces=row.replaces, config=row.config, access=row.access)

    _refused(imported_op, before, rc, said, row.needles, file_ok=row.file_ok)
    if row.good is not None:
        control = row.good_system or row.system
        rc, said = imported_op.set_system(control, replaces=row.replaces, config=row.good[0], access=row.good[1])
        assert rc == 0, said
        assert imported_op.current()[control].version == row.replaces + 1


@pytest.mark.postgres
def test_keys_are_case_sensitive_so_a_lower_case_spelling_is_not_the_setting(imported_op):
    """A key in lower case is not the upper-case key the adapter reads: the record is refused naming the system and the
    spelling (it cannot satisfy the required key and is not a declared one), and stores nothing. (The reader half, that
    it reads the key as written, is pinned in `test_folder_reader_w_1366`; P2: what cannot be used cannot be stored.)"""
    op = imported_op
    before = _state(op)

    rc, said = op.set_system("change-mgmt", replaces=1, config={"change_mgmt_timeout_sec": "10"},
                             access=R.FIXTURE_FOLDERS["change-mgmt"][1])

    assert rc != 0, said
    assert "change-mgmt" in said, said
    assert "CHANGE_MGMT_TIMEOUT_SEC" in said or "change_mgmt_timeout_sec" in said, said
    assert "Traceback" not in said, said
    assert _state(op) == before


def _undeclared_keys() -> list[str]:
    """Keys a `config.env` line can spell that cmdb does not declare (it declares `CMDB_TIMEOUT_SEC`): spellings of the
    declared key, lower case, hyphen, dot, non-ASCII and mixed, and seeded random text over those alphabets."""
    rng = random.Random(13662)
    fixed = ["cmdb_timeout_sec", "Cmdb_Timeout_Sec", "CMDB-TIMEOUT-SEC", "CMDB.TIMEOUT.SEC", "cmdb_api_token", "cmdb-key",
             "token", "timeout_sec", "CMDB_TIMEOUT_SÉC", "ключ", "日本語", "k.e.y", "a-b", "_leading", "9digit"]
    alphabets = ["abcdefghijklmnopqrstuvwxyz_", "abcdefghijklmnopqrstuvwxyz-.", "abcdefgABCDEFG0123456789_-.", "éßжя日本_a-z"]
    generated = ["".join(rng.choice(rng.choice(alphabets)) for _ in range(rng.randint(2, 12))) for _ in range(12)]
    return [key for key in dict.fromkeys([*fixed, *generated]) if key != "CMDB_TIMEOUT_SEC" and "=" not in key]


UNDECLARED_KEYS = _undeclared_keys()


@pytest.mark.postgres
@pytest.mark.parametrize("key", UNDECLARED_KEYS, ids=[f"key-{i}" for i in range(len(UNDECLARED_KEYS))])
def test_1366_o4_a_settings_key_the_adapter_does_not_declare_is_refused_whatever_its_spelling_and_never_stored(imported_op, key):
    """cmdb's declared key beside one more `KEY="..."` setting is refused when the key is not one cmdb declares, whatever
    it is spelt like (a case variant of the declared key, lower case, hyphens, dots, non-ASCII): the refusal names the
    system and the key, no traceback, and no version is stored nor a secret value left in a record. Control: the declared
    key alone is stored. (#1366 O4, P1, P2, H2)"""
    op = imported_op
    before = _state(op)

    rc, said = op.set_system("cmdb", replaces=1, config={"CMDB_TIMEOUT_SEC": "10", key: "s3cr3t-1366"}, access=CMDB_ACCESS)

    assert rc != 0, said
    assert R.lines_naming(said, "cmdb", key), (key, said)
    assert "Traceback" not in said, said
    assert _state(op) == before, "a refused key changed the records"
    assert "s3cr3t-1366" not in repr([op.versions(s) for s in R.FIXTURE_SYSTEMS]), "a value of the refused line was stored"
    rc, said = op.set_system("cmdb", replaces=1, config=CMDB_NEW, access=CMDB_ACCESS)
    assert rc == 0, said  # control: the declared key alone is stored as the next version


async def _door(op: R.Admin, call: Any) -> Any:
    store = R.api_record_store(op.dsn)
    try:
        return await call(store)
    finally:
        await store.close()


def _at_the_door(op: R.Admin, call: Any) -> Any:
    return asyncio.run(_door(op, call))


@pytest.mark.postgres
@pytest.mark.parametrize(("name", "system", "adapter", "needles"), [
    ("adapter-differs-from-system-id", "cmdb", "identity", ("cmdb", "identity")),
    ("unknown-catalog-id", "cmdb", "frobnicator", ("cmdb", "frobnicator")),
    ("custom-reference", "cmdb", ("adapters/my_adapter.py", "0123abc"), ("cmdb", "custom")),
    ("platform-served-name", "tacit-knowledge", "tacit-knowledge", ("tacit-knowledge", "platform"))])
def test_1366_o3_the_write_door_refuses_what_the_command_line_cannot_express(imported_op, name, system, adapter, needles):
    """Adapter id differing from the system id, an unknown id, a custom (path, revision) reference and a platform-served
    name raise `RecordRefused` naming the system and write no row; the matching catalog record is accepted. (#1366 O3, O4, R3)"""
    from defender.system_records import RecordRefused

    before = _state(imported_op)
    replaces = 0 if system == "tacit-knowledge" else 1

    async def put(store: Any, adapter: Any = adapter) -> None:
        await store.put_system(imported_op.tid, system, replaces=replaces, adapter=adapter, enabled=True,
                               settings=dict(CMDB_CONFIG), access=CMDB_ACCESS, author="test door")

    with pytest.raises(RecordRefused) as refused:
        _at_the_door(imported_op, put)

    text = str(refused.value)
    assert all(word in text for word in needles), text
    assert not [w for w in FILE_WORDS if w in text], text
    assert _state(imported_op) == before
    if system == "cmdb":  # control: the same call with the catalog id equal to the system id
        _at_the_door(imported_op, lambda store: put(store, "cmdb"))
        assert imported_op.current()["cmdb"].version == 2


# --- O4 case record, O5 delete/disable of the case system -------------------------------------------------------------

@pytest.mark.postgres
@pytest.mark.parametrize("system", sorted(R.FIXTURE_SYSTEMS - {"ticket"}))
def test_1366_o4_a_case_system_whose_adapter_offers_no_comment_action_is_refused(imported_op, system):
    """Every current system but ticket has no comment route: `set-case` naming it is refused naming it and changes
    nothing. (#1366 O4, C1)"""
    before = _state(imported_op)

    rc, said = imported_op.set_case(replaces=1, system=system)

    _refused(imported_op, before, rc, said, ((system, "case"),), file_ok=True)


@pytest.mark.postgres
@pytest.mark.parametrize("how", ["absent", "disabled", "deleted"])
def test_1366_o4_a_case_system_that_is_not_a_current_enabled_record_is_refused(imported_op, how):
    """A case system jira that has no record, a disabled one or a deleted one is refused naming jira; the enabled
    covering one is accepted. (#1366 O4)"""
    op = imported_op
    if how != "absent":
        assert op.set_system("jira", replaces=0, config=JIRA_CONFIG, access=_jira_access(JIRA_API), disabled=how == "disabled")[0] == 0
    if how == "deleted":
        assert op.delete_system("jira", replaces=1)[0] == 0
    before = _state(op)

    rc, said = op.set_case(replaces=1, system="jira")

    _refused(op, before, rc, said, (("jira", "case"),), file_ok=True)
    version = {"absent": 0, "disabled": 1, "deleted": 0}[how]  # #1470 P2: a tombstone shows as none
    assert op.set_system("jira", replaces=version, config=JIRA_CONFIG, access=_jira_access(JIRA_API), disabled=False)[0] == 0
    assert op.set_case(replaces=1, system="jira")[0] == 0
    assert op.current()["jira"].enabled






@pytest.mark.postgres
@pytest.mark.parametrize("how", ["delete", "disable"])
def test_1366_o4_the_case_system_cannot_be_deleted_or_disabled_until_the_case_record_is_deleted(imported_op, how):
    """ticket is the case system: deleting or disabling it is refused naming ticket and the case record; once
    `delete-case` has run the same call is accepted. (#1366 O4, O5)"""
    op = imported_op
    act = (lambda: op.delete_system("ticket", replaces=1)) if how == "delete" else (
        lambda: op.set_system("ticket", replaces=1, config=TICKET_CONFIG, access=TICKET_ACCESS, disabled=True))
    before = _state(op)

    rc, said = act()

    _refused(op, before, rc, said, (("ticket", "case"),))
    assert op.delete_case(replaces=1)[0] == 0
    rc, said = act()
    assert rc == 0, said
    assert op.numbers("ticket")[-1][0] == 2


# --- an upgrade removed a record's adapter from the catalog --------------------------------------------------------------

@pytest.fixture
def retired_op(fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch):  # noqa: F811
    """An imported tenant (the retired fixture's systems) that also holds two records naming adapters the catalog lacks,
    as after an upgrade dropped them (planted through the seeder's accept-all judge: records are data, the catalog is the
    checkout's). `legacy-ticket` is the tenant's case system."""
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    seeded = R.fixture_records()
    spec = dataclasses.replace(
        seeded, systems={**seeded.systems,
                         RETIRED: R.SysSpec({}, R.declaration("http://soc-playground:8010"), adapter=RETIRED),
                         RETIRED_CASE: R.SysSpec({}, R.declaration("http://soc-playground:8011",
                                                                   writes=(("POST", "/tickets/*/comments"),)),
                                                 adapter=RETIRED_CASE)},
        case=R.CaseSpec(system_id=RETIRED_CASE))
    register_tenant(migrated_database, fixture_tenant.tenant_id, data_root=fixture_tenant.data_root, records=spec)
    return R.Admin(fixture_tenant.tenant_id, migrated_database, tmp_path / "op", capsys)


@pytest.mark.postgres
@pytest.mark.parametrize("how", ["rewrite", "disable", "door-same-adapter", "door-another-adapter"])
def test_1366_o3_a_record_whose_adapter_an_upgrade_removed_takes_no_write_but_a_delete(retired_op, how):
    """A current record naming an adapter the catalog no longer has refuses every write (a rewrite, a disable, the write
    door with the same or another adapter), each naming the system and changing nothing; a delete is accepted (a version,
    the record gone). (#1366 O3, design Flows: upgrade drops a catalog adapter)"""
    from defender.system_records import RecordRefused

    op, before = retired_op, _state(retired_op)
    assert op.current()[RETIRED].adapter_id == RETIRED, "premise: the stored record names the removed adapter"
    access = R.declaration("http://soc-playground:8010")

    if how in ("rewrite", "disable"):
        rc, said = op.set_system(RETIRED, replaces=1, config={}, access=access, disabled=how == "disable")
        _refused(op, before, rc, said, ((RETIRED,),))
    else:
        adapter = RETIRED if how == "door-same-adapter" else "cmdb"

        async def put(store: Any) -> None:
            await store.put_system(op.tid, RETIRED, replaces=1, adapter=adapter, enabled=True, settings={},
                                   access=access, author="test door")

        with pytest.raises(RecordRefused) as refused:
            _at_the_door(op, put)
        assert RETIRED in str(refused.value), str(refused.value)
        assert _state(op) == before

    rc, said = op.delete_system(RETIRED, replaces=1)
    assert rc == 0, said
    assert op.numbers(RETIRED)[-1] == (2, 1, True)
    assert RETIRED not in op.current()


@pytest.mark.postgres
@pytest.mark.parametrize("how", ["delete-case", "repoint-case"])
def test_1366_o3_a_case_system_whose_adapter_an_upgrade_removed_is_deleted_only_after_the_case_record_stops_naming_it(
        retired_op, how):
    """The case system's adapter is gone: deleting it is refused naming it and the case record, as is a disable, and
    nothing changes; once the case record is deleted (`delete-case`) or repointed to a system that can comment (`set-case`
    naming ticket) the same delete is accepted. (#1366 O3, O4, design Flows)"""
    op = retired_op
    before = _state(op)

    rc, said = op.delete_system(RETIRED_CASE, replaces=1)
    _refused(op, before, rc, said, ((RETIRED_CASE, "case"),))
    rc, said = op.set_system(RETIRED_CASE, replaces=1, config={}, access=R.declaration("http://soc-playground:8011"),
                             disabled=True)
    _refused(op, before, rc, said, ((RETIRED_CASE,),))

    freed = op.delete_case(replaces=1) if how == "delete-case" else op.set_case(replaces=1, system="ticket")
    assert freed[0] == 0, freed
    rc, said = op.delete_system(RETIRED_CASE, replaces=1)

    assert rc == 0, said
    assert op.numbers(RETIRED_CASE)[-1] == (2, 1, True)


# --- C2 / C3 / C4: the cover rule at write ------------------------------------------------------------------------------

#: (id, writes, reads, covers) for ticket's comment route `POST /tickets/*/comments` at base `TICKET_BASE`. X2: the case
#: system's declared writes are exactly that route and its declared reads are all GET.
TICKET_COVER = [
    ("exact", (("POST", "/tickets/*/comments"),), (), True),
    ("exact-with-get-reads", (("POST", "/tickets/*/comments"),),
     (("GET", "/tickets/*/comments"), ("GET", "/tickets/*"), ("GET", "/search")), True),
    ("beside-another-write", (("POST", "/tickets/*/transitions"), ("POST", "/tickets/*/comments")), (), False),
    ("beside-another-method-write", (("POST", "/tickets/*/comments"), ("PUT", "/tickets/*")), (), False),
    ("beside-the-key-spelled-out", (("POST", "/tickets/*/comments"), ("POST", "/tickets/ABC-1/comments")), (), False),
    ("wildcard-for-a-literal-segment", (("POST", "/*/*/comments"),), (), False),
    ("every-segment-a-wildcard", (("POST", "/*/*/*"),), (), False),
    ("a-non-get-read-elsewhere", (("POST", "/tickets/*/comments"),), (("POST", "/search"),), False),
    ("a-mutating-read-elsewhere", (("POST", "/tickets/*/comments"),), (("PATCH", "/tickets/*"),), False),
    ("no-writes", (), (), False),
    ("other-route-only", (("POST", "/tickets/*/transitions"),), (), False),
    ("other-method", (("PUT", "/tickets/*/comments"),), (), False),
    ("literal-where-the-pattern-has-a-star", (("POST", "/tickets/ABC-1/comments"),), (), False),
    ("one-segment-too-many", (("POST", "/tickets/*/comments/extra"),), (), False),
    ("one-segment-too-few", (("POST", "/tickets/*"),), (), False),
    ("literal-compared-raw", (("POST", "/tickets/*/Comments"),), (), False),
    ("other-prefix", (("POST", "/ticket/*/comments"),), (), False),
    ("only-a-read-route", (), (("POST", "/tickets/*/comments"),), False),
    ("read-route-with-a-literal-matches-the-comment-route", (("POST", "/tickets/*/comments"),),
     (("POST", "/tickets/ABC-1/comments"),), False),
    ("read-route-with-a-star-matches-the-comment-route", (("POST", "/tickets/*/comments"),),
     (("POST", "/tickets/*/comments"),), False),
    ("read-route-with-a-star-for-a-literal-matches", (("POST", "/tickets/*/comments"),),
     (("POST", "/*/ABC-1/comments"),), False),
    ("read-routes-that-do-not-match-but-are-not-get", (("POST", "/tickets/*/comments"),),
     (("GET", "/tickets/*/comments"), ("POST", "/tickets/*/other"), ("POST", "/tickets/*")), False),
]
#: What the refusal's cause names, by row: the route that breaks X2 (rows not listed carry the existing causes).
COVER_CAUSE = {"beside-another-write": "/tickets/*/transitions", "beside-another-method-write": "PUT",
               "beside-the-key-spelled-out": "/tickets/ABC-1/comments", "wildcard-for-a-literal-segment": "/*/*/comments",
               "every-segment-a-wildcard": "/*/*/*", "a-non-get-read-elsewhere": "/search",
               "a-mutating-read-elsewhere": "PATCH",
               "read-routes-that-do-not-match-but-are-not-get": "/tickets/*/other"}


@pytest.mark.postgres
@pytest.mark.parametrize("row", TICKET_COVER, ids=[r[0] for r in TICKET_COVER])
def test_1366_c2_a_write_to_the_case_system_is_stored_only_if_a_write_route_covers_the_comment_route(imported_op, row):
    """ticket (the case system) is stored only with exactly the comment route as its declared writes and no read route
    that is not a GET; else refused naming ticket's access and the route that breaks the rule. (#1366 C2, C4, X2)"""
    name, writes, reads, covers = row
    access = R.declaration(TICKET_BASE, writes=writes, reads=reads)
    before = _state(imported_op)

    rc, said = imported_op.set_system("ticket", replaces=1, config=TICKET_CONFIG, access=access)

    if covers:
        assert rc == 0, said
        assert imported_op.current()["ticket"].version == 2
    else:
        _refused(imported_op, before, rc, said, (("system ticket access",),))
        assert not R.lines_naming(said, "system ticket settings"), said
        if name in COVER_CAUSE:
            assert R.lines_naming(said, "system ticket access", COVER_CAUSE[name]), said


@pytest.mark.postgres
def test_1366_c4_a_case_record_write_that_finds_no_cover_is_refused_naming_the_case_record(imported_op):
    """With the case record deleted, ticket is rewritten without cover (allowed); `set-case` naming it is refused
    naming the case record, and succeeds once ticket covers again. (#1366 C4)"""
    op = imported_op
    assert op.delete_case(replaces=1)[0] == 0
    assert op.set_system("ticket", replaces=1, config=TICKET_CONFIG,
                         access=R.bearer_access(TICKET_BASE, writes=(("POST", "/tickets/*/transitions"),)))[0] == 0
    before = _state(op)

    rc, said = op.set_case(replaces=0)  # #1470 P2: the deleted case record shows as none

    _refused(op, before, rc, said, (("case record",),), file_ok=True)
    assert op.set_system("ticket", replaces=2, config=TICKET_CONFIG, access=TICKET_ACCESS)[0] == 0
    assert op.set_case(replaces=0)[0] == 0


@pytest.fixture
def jira_case(imported_op):
    """jira (SERVICE_DESK no, covering `POST /rest/api/3/issue/*/comment`) is the case system."""
    op = imported_op
    assert op.set_system("jira", replaces=0, config=JIRA_CONFIG, access=_jira_access(JIRA_API))[0] == 0
    assert op.set_case(replaces=1, system="jira")[0] == 0
    return op


#: (id, new settings, new access, parts the refusal names, or None when stored): the part named is the one whose
#: change alone breaks cover (recompute with old settings + new access, and the reverse).
JIRA_NAMING = [
    ("settings-only", {**JIRA_CONFIG, "JIRA_SERVICE_DESK": "yes"}, _jira_access(JIRA_API), {"settings"}),
    ("access-only", JIRA_CONFIG, _jira_access(JIRA_DESK), {"access"}),
    ("both-alone-break", {**JIRA_CONFIG, "JIRA_SERVICE_DESK": "yes"},
     _jira_access(("POST", "/rest/api/3/issue/*/transitions")), {"settings", "access"}),
    ("both-change-and-cover-holds", {**JIRA_CONFIG, "JIRA_SERVICE_DESK": "yes"}, _jira_access(JIRA_DESK), None),
]


@pytest.mark.postgres
@pytest.mark.parametrize("row", JIRA_NAMING, ids=[r[0] for r in JIRA_NAMING])
def test_1366_c4_the_refusal_names_the_part_of_the_case_system_whose_change_broke_cover(jira_case, row):
    """A write to the case system that stops covering its comment route names its settings, its access or both, by
    which change alone breaks cover; a change of both that still covers is stored. (#1366 C4, C1)"""
    _, settings, access, parts = row
    before = _state(jira_case)

    rc, said = jira_case.set_system("jira", replaces=1, config=settings, access=access)

    if parts is None:
        assert rc == 0, said
        assert jira_case.current()["jira"].version == 2
        return
    _refused(jira_case, before, rc, said, tuple((f"system jira {p}",) for p in sorted(parts)))
    for other in {"settings", "access"} - parts:
        assert not R.lines_naming(said, f"system jira {other}"), said


@pytest.mark.postgres
def test_1366_c4_a_servicenow_table_change_that_leaves_the_route_uncovered_names_the_settings(imported_op):
    """servicenow as case system covers `PATCH /api/now/table/incident/*`; moving TABLE to `problem` under the same
    access is refused naming its settings; with a covering route for `problem` it is stored. (#1366 C4, C1)"""
    op = imported_op
    access = R.declaration(JIRA_BASE, writes=(SN_ROUTE,))
    assert op.set_system("servicenow", replaces=0, config=SN_CONFIG, access=access)[0] == 0
    assert op.set_case(replaces=1, system="servicenow")[0] == 0
    before = _state(op)

    rc, said = op.set_system("servicenow", replaces=1, config={**SN_CONFIG, "SERVICENOW_TABLE": "problem"}, access=access)

    _refused(op, before, rc, said, (("system servicenow settings",),))
    assert not R.lines_naming(said, "system servicenow access")
    rc, said = op.set_system("servicenow", replaces=1, config={**SN_CONFIG, "SERVICENOW_TABLE": "problem"},
                             access=R.declaration(JIRA_BASE, writes=(("PATCH", "/api/now/table/problem/*"),)))
    assert rc == 0, said


@pytest.mark.postgres
def test_1366_c4_a_write_to_a_system_that_is_not_the_case_system_needs_no_cover(jira_case):
    """With jira the case system, ticket (no longer one) is stored with no write route at all. (#1366 C4)"""
    rc, said = jira_case.set_system("ticket", replaces=1, config=TICKET_CONFIG, access=R.bearer_access(TICKET_BASE))
    assert rc == 0, said


# --- O5: versions, staleness, deletes, numbering ------------------------------------------------------------------------

@pytest.mark.postgres
def test_1366_o5_versions_rise_by_one_per_system_and_a_delete_counts_as_the_version_to_replace(imported_op):
    """cmdb: edit (2), delete (3); then naming 2, the delete (3) or 9 is refused and naming 0 (#1470 P2: a tombstone shows
    as none) stores version 4; identity stays at 1. Each version carries its writer as author. (#1366 O5, R9)"""
    op = imported_op
    assert op.set_system("cmdb", replaces=1, config=CMDB_NEW, access=CMDB_ACCESS)[0] == 0
    assert op.delete_system("cmdb", replaces=2)[0] == 0
    before = _state(op)

    for stale in (2, 3, 9):
        rc, said = op.set_system("cmdb", replaces=stale, config=CMDB_NEW, access=CMDB_ACCESS)
        _refused(op, before, rc, said, (("cmdb",),), file_ok=True)
        assert not stale or _numbered(said, "cmdb", stale), said

    assert op.set_system("cmdb", replaces=0, config=CMDB_NEW, access=CMDB_ACCESS)[0] == 0
    assert [(n, d) for n, _, d in op.numbers("cmdb")] == [(1, False), (2, False), (3, True), (4, False)]
    assert [v.author for v in op.versions("cmdb")] == [R.SEED_AUTHOR, *[R.ADMIN_AUTHOR] * 3]  # each version's author is the acting member
    times = [v.written_at for v in op.versions("cmdb")]
    assert None not in times
    assert times == sorted(times)
    assert op.numbers("identity") == [(1, 1, False)]


@pytest.mark.postgres
def test_1366_o5_a_rewrite_identical_to_the_current_version_is_still_a_new_version(imported_op):
    """cmdb rewritten with exactly its version-1 settings and access is version 2, same content, same generation.
    (#1366 O5)"""
    assert imported_op.set_system("cmdb", replaces=1, config=CMDB_CONFIG, access=CMDB_ACCESS)[0] == 0
    first, second = imported_op.versions("cmdb")
    assert (second.version, second.settings, second.access, second.credential_generation) == (
        2, first.settings, first.access, first.credential_generation)


@pytest.mark.postgres
def test_1366_o5_deleting_a_deleted_or_never_recorded_system_is_refused(imported_op):
    """delete-system on a system never recorded (jira) or already deleted (cmdb) is refused and writes nothing; the
    first delete of cmdb is accepted. (#1366 O5)"""
    op = imported_op
    assert op.delete_system("cmdb", replaces=1)[0] == 0
    before = _state(op)
    for system, replaces in (("jira", 0), ("cmdb", 2), ("cmdb", 1)):
        rc, said = op.delete_system(system, replaces=replaces)
        _refused(op, before, rc, said, ((system,),), file_ok=True)


@pytest.mark.postgres
def test_1366_o5_a_write_naming_a_version_no_longer_current_is_refused_naming_the_system_and_version(imported_op):
    """Two operators edit cmdb from version 1: the first is stored as 2, the second (naming 1) is refused naming cmdb
    and version 1 and changes nothing. (#1366 O5)"""
    assert imported_op.set_system("cmdb", replaces=1, config=CMDB_NEW, access=CMDB_ACCESS)[0] == 0
    before = _state(imported_op)

    rc, said = imported_op.set_system("cmdb", replaces=1, config={"CMDB_TIMEOUT_SEC": "30"}, access=CMDB_ACCESS)

    _refused(imported_op, before, rc, said, (("system cmdb",),), file_ok=True)
    assert _numbered(said, "cmdb", 1), said
    assert [(v.version, v.settings) for v in imported_op.versions("cmdb")] == [(1, CMDB_CONFIG), (2, CMDB_NEW)]


@pytest.mark.postgres
def test_1366_o5_a_delete_is_a_version_and_check_then_reports_the_grants_on_it_as_orphaned(imported_op):
    """Deleting cmdb adds version 2 marked deleted; cmdb is no longer a current system and `check` reports its grant
    rows as orphaned, which it did not before. (#1366 O5, O1)"""
    _, before = imported_op.check()
    assert not R.lines_naming(before, "cmdb", "orphan"), before

    rc, said = imported_op.delete_system("cmdb", replaces=1)

    assert rc == 0, said
    assert [(v.version, v.deleted, v.author) for v in imported_op.versions("cmdb")] == [
        (1, False, R.SEED_AUTHOR), (2, True, R.ADMIN_AUTHOR)]
    assert "cmdb" not in imported_op.current()
    _, after = imported_op.check()
    assert R.lines_naming(after, "cmdb", "orphan"), after


@pytest.mark.postgres
def test_1366_o5_case_versions_number_per_tenant_and_follow_the_same_rules(imported_op):
    """Case: set (2), delete (3); then deleting again, naming 2 or the delete (3) is refused; naming 0 (#1470 P2: a
    tombstone shows as none) stores 4. Authors are `set-case` and `delete-case`. (#1366 O5, R9)"""
    op = imported_op
    assert op.set_case(replaces=1)[0] == 0
    assert op.delete_case(replaces=2)[0] == 0
    before = _state(op)

    for rc, said in (op.delete_case(replaces=3), op.set_case(replaces=2), op.set_case(replaces=3)):
        _refused(op, before, rc, said, (), file_ok=True)

    assert op.set_case(replaces=0)[0] == 0
    assert _case_versions(op) == [(1, "ticket", False), (2, "ticket", False), (3, "ticket", True), (4, "ticket", False)]
    assert [c.author for c in R.case_versions(op.dsn, op.tid)] == [
        R.SEED_AUTHOR, *[R.ADMIN_AUTHOR] * 3]
    current = R.current_records(op.dsn, op.tid).case
    assert (current.version, current.system_id) == (4, "ticket")  # W7: the case record holds no comment body


def _threaded(dsn: str, judge: Any, call: Any, failed: list) -> threading.Thread:
    """Run `call(store)` on a fresh `RecordStore(dsn, judge=judge)` in its own thread and event loop."""
    def target() -> None:
        async def go() -> None:
            from defender.system_records import RecordStore

            store = RecordStore(dsn, clock=fixed_clock, judge=judge)
            try:
                await call(store)
            finally:
                await store.close()
        try:
            asyncio.run(go())
        except BaseException as e:  # noqa: BLE001 — surfaced to the test thread
            failed.append(e)
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread


@pytest.mark.postgres
def test_1366_o5_one_tenants_writes_are_serialized_across_the_system_and_case_tables(imported_op):
    """Two store instances: a system write is held inside its judgement; a case write started meanwhile does not reach
    its own judgement until the first is released, and then sees the first's write. (#1366 O5, A1)"""
    op = imported_op
    in_a, release, in_b, failed, seen_b = threading.Event(), threading.Event(), threading.Event(), [], []

    def judge_a(after: Any, before: Any) -> list[str]:
        in_a.set()
        assert release.wait(60), "test left A held"
        return []

    def judge_b(after: Any, before: Any) -> list[str]:
        seen_b.append(after)
        in_b.set()
        return []

    async def delete_identity(store: Any) -> None:
        await store.delete_system(op.tid, "identity", replaces=1, author="test a")

    async def put_case(store: Any) -> None:
        await store.put_case(op.tid, replaces=1, system_id="ticket", author="test b")  # W7: no comment body

    a = _threaded(op.dsn, judge_a, delete_identity, failed)
    try:
        assert in_a.wait(30), failed
        b = _threaded(op.dsn, judge_b, put_case, failed)
        assert not in_b.wait(3), "the case write was judged while the system write held the tenant's lock"
    finally:
        release.set()
    a.join(60)
    b.join(60)

    assert not failed, failed
    assert in_b.is_set()
    assert "identity" not in seen_b[0].systems
    assert "cmdb" in seen_b[0].systems
    assert op.numbers("identity") == [(1, 1, False), (2, 1, True)]
    assert _case_versions(op) == [(1, "ticket", False), (2, "ticket", False)]


@pytest.mark.postgres
def test_1366_o5_two_store_instances_writing_the_same_version_store_one_and_refuse_the_other(imported_op):
    """Two stores race `put_system(cmdb, replaces=1)` repeatedly from one version: exactly one wins each round, the
    other is refused as stale, and versions stay consecutive. (#1366 O5)"""
    from defender.system_records import RecordRefused

    op = imported_op

    async def race(round_: int) -> list[Any]:
        async def one(tag: str) -> None:
            async def call(store: Any) -> None:
                await store.put_system(op.tid, "cmdb", replaces=round_, adapter="cmdb", enabled=True,
                                       settings={"CMDB_TIMEOUT_SEC": str(10 + round_)}, access=CMDB_ACCESS, author=tag)
            await _door(op, call)
        return await asyncio.gather(one("a"), one("b"), return_exceptions=True)

    for round_ in (1, 2, 3):
        results = asyncio.run(race(round_))
        assert [r for r in results if r is None] != [], results
        assert len([r for r in results if isinstance(r, RecordRefused)]) == 1, results
        assert len(results) == 2
    assert [v for v, _, _ in op.numbers("cmdb")] == [1, 2, 3, 4]


# --- P5 / R4: credential generations -----------------------------------------------------------------------------------

_HTTPS = "https://identity.internal:8005"
_BEARER = {"scheme": "bearer", "field": "api_key"}
_HEADER = {"scheme": "header", "header": "X-Api-Key", "field": "api_key"}
_OAUTH = {"scheme": "oauth-client-credentials", "token_url": "https://idp.internal/token", "scopes": ["read"]}


def _ca(which: str) -> str:
    from defender.tests.support.shared._tls_server import chain

    pki = chain()
    return {"root": pki.root.cert, "chain": pki.root.cert + pki.intermediate.cert}[which].decode()


#: (changed Auth field or part, access before, access after, generation rise). One pair per field of `kit.access.Auth`,
#: plus base, ca (added, changed, removed), and the changes that must NOT raise it.
GENERATION_PAIRS = [
    ("base", R.declaration(_HTTPS), R.declaration("https://identity.internal:9005"), 1),
    ("scheme", R.declaration(_HTTPS, auth={"scheme": "basic"}), R.declaration(_HTTPS, auth=_BEARER), 1),
    ("field", R.declaration(_HTTPS), R.declaration(_HTTPS, auth={**_BEARER, "field": "token"}), 1),
    ("header", R.declaration(_HTTPS, auth=_HEADER), R.declaration(_HTTPS, auth={**_HEADER, "header": "X-Other-Key"}), 1),
    ("token_url", R.declaration(_HTTPS, auth=_OAUTH), R.declaration(_HTTPS, auth={**_OAUTH, "token_url": "https://idp.internal/oauth"}), 1),
    ("scopes", R.declaration(_HTTPS, auth=_OAUTH), R.declaration(_HTTPS, auth={**_OAUTH, "scopes": ["read", "write"]}), 1),
    ("ca-added", R.declaration(_HTTPS), R.declaration(_HTTPS, ca=_ca("root")), 1),
    ("ca-changed", R.declaration(_HTTPS, ca=_ca("root")), R.declaration(_HTTPS, ca=_ca("chain")), 1),
    ("ca-removed", R.declaration(_HTTPS, ca=_ca("root")), R.declaration(_HTTPS), 1),
    ("routes-only", R.declaration(_HTTPS), R.declaration(_HTTPS, reads=(("GET", "/users"),), writes=(("POST", "/users/*"),)), 0),
    ("reserialized", R.declaration(_HTTPS),
     '# the same declaration, laid out another way\nreads: []\nwrites: []\nauth: {field: api_key, scheme: bearer}\n'
     f'base: "{_HTTPS}"\naccess: http-proxy\n', 0),
]


def test_1366_p5_every_auth_field_has_a_generation_pair():
    """The pairs below drive one change per field of the auth block; a field added to `Auth` fails here until it
    gets a pair. (#1366 P5, R4)"""
    from defender.kit.access import Auth

    assert {f.name for f in dataclasses.fields(Auth)} <= {pair[0] for pair in GENERATION_PAIRS}


@pytest.mark.postgres
@pytest.mark.parametrize("row", GENERATION_PAIRS, ids=[r[0] for r in GENERATION_PAIRS])
def test_1366_p5_the_generation_rises_on_a_change_of_base_ca_or_any_auth_field_and_not_otherwise(imported_op, row):
    """identity written with `before` then `after`: the generation rises by one when base, ca or an auth field differs
    as parsed values, and stays when only routes or the text layout differ. (#1366 P5, R4)"""
    _, before, after, rise = row
    op = imported_op
    assert op.set_system("identity", replaces=1, config=IDENTITY, access=before)[0] == 0
    rc, said = op.set_system("identity", replaces=2, config=IDENTITY, access=after)
    assert rc == 0, said
    (_, g2, _), (_, g3, _) = op.numbers("identity")[1:]
    assert g3 - g2 == rise, op.numbers("identity")


@pytest.mark.postgres
def test_1366_p5_a_stored_access_that_no_longer_parses_gives_the_next_write_a_new_generation(imported_op):
    """identity's stored access stops parsing (as a later, stricter rule would leave it); a write naming another base
    cannot be shown to reach the same upstream, so it takes generation 2, and the set stored at g1 is not offered to the
    new base. (#1366 P5, R4, K4)"""
    from defender.tests.support.shared._postgres1339 import execute

    op = imported_op
    execute(op.dsn, "UPDATE tenancy.system_versions SET access = %s WHERE tenant_id = %s AND system_id = 'identity'",
            ("access: no-longer-valid\n", op.tid))
    rc, said = op.set_system("identity", replaces=1, config=IDENTITY, access=R.bearer_access("http://elsewhere:9005"))
    assert rc == 0, said
    assert op.numbers("identity") == [(1, 1, False), (2, 2, False)]


@pytest.mark.postgres
def test_1366_p5_a_settings_change_alone_keeps_the_generation(imported_op):
    """A new timeout keeps identity at generation 1. (#1366 P5)"""
    assert imported_op.set_system("identity", replaces=1, config={"IDENTITY_TIMEOUT_SEC": "20"},
                                  access=R.FIXTURE_FOLDERS["identity"][1])[0] == 0
    assert imported_op.numbers("identity") == [(1, 1, False), (2, 1, False)]


@pytest.mark.postgres
def test_1366_p5_a_delete_carries_the_generation_and_a_re_create_takes_the_next_never_a_reused_one(imported_op):
    """identity at generations 1, 2, 3, deleted (carrying 3), re-created with its first declaration (4), deleted and
    re-created with the same declaration again (5); credentials set at generation 1 are not at the current one.
    (#1366 P5, R4, K3)"""
    op = imported_op
    first = R.FIXTURE_FOLDERS["identity"][1]
    assert op.set_credentials("identity", {"api_key": "k1"}, for_version=1)[0] == 0
    for replaces, base in ((1, "http://soc-playground:9005"), (2, "http://soc-playground:9105")):
        assert op.set_system("identity", replaces=replaces, config=IDENTITY, access=R.bearer_access(base))[0] == 0
    assert op.delete_system("identity", replaces=3)[0] == 0
    assert op.set_system("identity", replaces=0, config=IDENTITY, access=first)[0] == 0  # #1470 P2: deleted shows as 0
    assert op.delete_system("identity", replaces=5)[0] == 0
    assert op.set_system("identity", replaces=0, config=IDENTITY, access=first)[0] == 0

    assert op.numbers("identity") == [(1, 1, False), (2, 2, False), (3, 3, False), (4, 3, True), (5, 4, False),
                                      (6, 4, True), (7, 5, False)]
    assert op.kv.written() == [f"{op.tid}/identity/g1"]
    assert R.lines_naming(op.check()[1], "identity", "no credentials")


# --- DC8: disable and set-case via the store ---------------------------------------------------------------------------







@pytest.mark.postgres
def test_1366_dc8_disabling_and_re_enabling_is_a_version_that_keeps_the_record(imported_op):
    """Writing a system disabled stores version 2 with enabled false (settings and access judged all the same); writing it
    enabled again is version 3. Each is a version that keeps the record. (#1366 DC8, O1)"""
    op = imported_op
    rc, said = op.set_system("cmdb", replaces=1, config={**CMDB_CONFIG, "CMDB_COLOUR": "x"}, access=CMDB_ACCESS, disabled=True)
    assert rc != 0, said
    assert R.lines_naming(said, "CMDB_COLOUR"), said
    assert op.set_system("cmdb", replaces=1, config=CMDB_CONFIG, access=CMDB_ACCESS, disabled=True)[0] == 0
    assert op.current()["cmdb"].enabled is False
    assert op.set_system("cmdb", replaces=2, config=CMDB_CONFIG, access=CMDB_ACCESS, disabled=False)[0] == 0
    assert [(v.version, v.enabled) for v in op.versions("cmdb")] == [(1, True), (2, False), (3, True)]


@pytest.mark.postgres
def test_1366_dc8_set_case_stores_the_system_and_delete_case_removes_the_record(imported_op):
    """Writing the case record stores its system as given (version 2; W7: it holds no template); deleting it makes the
    case record not exist. (#1366 DC8, O5, H7)"""
    op = imported_op
    assert op.set_case(replaces=1)[0] == 0
    case = R.current_records(op.dsn, op.tid).case
    assert (case.version, case.system_id) == (2, "ticket")
    assert not hasattr(case, "comment_body"), "W7: the stored case record still carries a comment body"
    assert op.delete_case(replaces=2)[0] == 0
    assert R.current_records(op.dsn, op.tid).case is None


@pytest.mark.postgres
def test_1366_r7_two_tenants_may_point_at_one_base_each_keeping_its_own_record_and_credentials(
        fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch):  # noqa: F811
    """Two tenants set cmdb to one base: both accepted, each with its own history and credential path. (#1366 R7)"""
    shared = R.bearer_access("http://shared-cmdb.internal:8001")
    kv = R.KvStandIn()
    with second_tenant(fixture_tenant, files=R.import_files()) as other:
        a = _operator(fixture_tenant, migrated_database, tmp_path / "a", capsys, monkeypatch, kv=kv)
        b = _operator(other, migrated_database, tmp_path / "b", capsys, monkeypatch, kv=kv)
        assert a.tid != b.tid
        for op in (a, b):
            rc, said = op.set_system("cmdb", replaces=1, config=CMDB_CONFIG, access=shared)
            assert rc == 0, said
        assert a.current()["cmdb"].access == b.current()["cmdb"].access == shared
        assert a.numbers("cmdb") == b.numbers("cmdb"), "one tenant's write moved the other's history"
        assert [n[0] for n in a.numbers("cmdb")] == [1, 2]
        for op, key in ((a, "key-of-a"), (b, "key-of-b")):
            rc, said = op.set_credentials("cmdb", {"api_key": key}, for_version=2)
            assert rc == 0, said
    generation = a.current()["cmdb"].credential_generation
    assert kv.written() == [f"{a.tid}/cmdb/g{generation}", f"{b.tid}/cmdb/g{generation}"]
    assert kv.held == {f"{a.tid}/cmdb/g{generation}": [R.credential_set({"api_key": "key-of-a"})],
                       f"{b.tid}/cmdb/g{generation}": [R.credential_set({"api_key": "key-of-b"})]}


# --- round 9 (G4): the cover judgement is the proxy's own, over declared routes spelled any way ----------------------------

#: The comment ticket's adapter sends and its declared route (K5 pins the first against the second at the proxy).
COMMENT = ("POST", "/tickets/ABC-1/comments")
COMMENT_ROUTE = ("POST", "/tickets/*/comments")


def _spellings(segment: str) -> list[str]:
    """One declared path segment, spelled other ways: a star, the literal, case changes, percent-encodings of one and of
    every character, partial stars, empty, another literal, an encoded star."""
    encoded = "".join(f"%{ord(c):02X}" for c in segment)
    return [segment, "*", "**", "", "x", segment.upper(), segment.swapcase(), f"%{ord(segment[0]):02x}{segment[1:]}" if segment else "%2e",
            encoded, encoded.lower(), segment[:1] + "*", "*" + segment[1:], segment + "*", "%2A", segment + "%20"]


def _mutated_paths() -> list[str]:
    """Declared paths built from the adapter's comment pattern by segment mutations: each segment alone, two segments
    together, a trailing `/`, doubled separators."""
    segments = COMMENT_ROUTE[1].split("/")
    paths = {"/".join(segments)}
    for i, segment in enumerate(segments):
        paths |= {"/".join([*segments[:i], s, *segments[i + 1:]]) for s in _spellings(segment)}
    for i, j in ((1, 2), (1, 3), (2, 3)):
        for a in _spellings(segments[i])[:9]:
            for b in _spellings(segments[j])[:9]:
                mutated = list(segments)
                mutated[i], mutated[j] = a, b
                paths.add("/".join(mutated))
    paths |= {"/".join(segments) + "/", "/".join(segments) + "//", COMMENT_ROUTE[1].replace("/", "//", 1)}
    return sorted(paths)


def _admitted_as(access: Any, mode: str) -> bool:
    from defender.credential_proxy._refusal import Refused
    from defender.credential_proxy._scope import check_route

    try:  # a write pass always names its ticket (X1): the one the comment goes to
        check_route(access, "ticket", *COMMENT, mode, "ABC-1" if mode == "rw" else None)
    except Refused:
        return False
    return True


def _proxy_admits(access: str) -> tuple[bool, bool]:
    """What the proxy's own matcher does with the comment the adapter sends, under the declaration `access`: (admitted as
    a write that a read-only token does not get, admitted through a read route). A declaration the access parser refuses
    admits nothing."""
    from defender.credential_proxy._tokens import READ, READ_WRITE
    from defender.kit.faults import ConfigFault
    from defender.tenancy import parse_access

    try:
        parsed = parse_access(access, system="ticket")
    except ConfigFault:
        return False, False
    as_read = _admitted_as(parsed, READ)
    return _admitted_as(parsed, READ_WRITE) and not as_read, as_read


@pytest.mark.postgres
def test_1366_g4_the_cover_judgement_stores_only_the_exact_comment_route_and_only_where_the_proxy_admits_it(
        imported_op):
    """Declared write routes built from the adapter's comment pattern by segment mutations (a star, another literal,
    case changes, percent-encodings, partial stars, empty segments, a trailing `/`): the ticket system, the case system,
    is stored with a route exactly when it is the comment route itself (X2: no wider route, however the proxy's matcher
    admits it), which the proxy admits as a write. Beside it, the same spellings declared as POST read routes are never
    stored, and as GET read routes are stored whenever the access parser takes them. (#1366 C2, K4; X2)"""
    from defender.kit.faults import ConfigFault
    from defender.system_records import RecordRefused
    from defender.tenancy import parse_access

    op = imported_op
    base = "http://soc-playground:8004"
    wrong: list[str] = []
    version = [op.current()["ticket"].version]

    def parses(access: str) -> bool:
        try:
            parse_access(access, system="ticket")
        except ConfigFault:
            return False
        return True

    async def run_through_the_door(store: Any) -> None:
        async def stored(access: str) -> bool:
            try:
                await store.put_system(op.tid, "ticket", replaces=version[0], adapter="ticket", enabled=True,
                                       settings=dict(TICKET_CONFIG), access=access, author="test door")
            except RecordRefused:
                return False
            version[0] += 1
            return True

        for path in _mutated_paths():
            access = R.declaration(base, writes=(("POST", path),))
            exact = path == COMMENT_ROUTE[1]
            if await stored(access) is not exact:
                wrong.append(f"write {path!r}: stored only when it is the exact comment route ({exact})")
        assert await stored(R.declaration(base, writes=(COMMENT_ROUTE,))), "control: the exact route is stored"
        assert _proxy_admits(R.declaration(base, writes=(COMMENT_ROUTE,)))[0], "control: the proxy admits it as a write"
        for path, method in itertools.product(_mutated_paths(), ("POST", "GET")):
            access = R.declaration(base, writes=(COMMENT_ROUTE,), reads=((method, path),))
            if parses(access) and await stored(access) is (method == "POST"):
                wrong.append(f"read {method} {path!r}: stored only when the read is a GET")

    _at_the_door(op, run_through_the_door)
    assert not wrong, wrong
