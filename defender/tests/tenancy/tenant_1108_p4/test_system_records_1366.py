"""#1366 slice W (write side): the operator command writes a tenant's system and case records (O2, O4, O5, O8, O9,
P5, C2-C4, O11, DC8; R13 import copies no secret).

Entry: `cli.tenant.main(argv)` with no `directory=`, as a production process: host acceptance and the record store
both come from `DEFENDER_DATABASE_DSN` over a migrated database (Postgres-gated). The tenant is the published fixture
(its retired `settings/` folders planted by `R.import_files()`), registered `active` and NOT imported
(`register_tenant(records=None)`). State is read back through the R10 read (`R.current_records`) and, for history,
`R.system_versions` / `R.case_versions`; credentials through the KV stand-in's recorded paths. Refusals the CLI cannot
express (adapter mismatch, custom reference, serialization) go to `open_store` / `RecordStore`. Every invented name is
in `support/tenancy/_systems1366.py` and `.contract-first/shared-interface.md`.
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import importlib
import inspect
import json
import os
import random
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from defender.tests.support.jobs._jobs1342 import fixed_clock, register_tenant
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _handoff1366 as H
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1108_p4._support import FIXTURE_SETTINGS, published_tenant, second_tenant

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


def _operator(tenant: Any, dsn: str, tmp_path: Path, capsys: Any, monkeypatch: Any, **kw: Any) -> R.Operator:
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", dsn)
    register_tenant(dsn, tenant.tenant_id, data_root=tenant.data_root, records=None)  # R8: not imported
    return R.Operator(tenant.tenant_id, dsn, tmp_path / "op", capsys, **kw)


@pytest.fixture
def fixture_tenant(tmp_path, data_root):
    """The fixture tenant under this test's data root, publishing the retired folders `R.import_files()` plants."""
    with published_tenant(tmp_path / "forge", root=data_root, files=R.import_files()) as published:
        yield published


@pytest.fixture
def op(fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch):  # noqa: F811 — the imported fixture
    """The fixture tenant, registered, not yet imported."""
    return _operator(fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch)


@pytest.fixture
def imported_op(op):
    rc, said = op.import_()
    assert rc == 0, said
    return op


@contextlib.contextmanager
def _planted(tmp_path: Path, data_root: Path, dsn: str, capsys: Any, monkeypatch: Any,
             files: Mapping[str, str | None] | None = None, **overrides: str | None) -> Iterator[R.Operator]:
    """A registered, not-imported tenant publishing `R.import_files(**overrides)` (or exactly `files`)."""
    with published_tenant(tmp_path / "forge", root=data_root,
                          files=R.import_files(**overrides) if files is None else dict(files)) as t:
        yield _operator(t, dsn, tmp_path, capsys, monkeypatch)


def _jira_access(*writes: tuple[str, str], reads: tuple = ()) -> str:
    return R.declaration(JIRA_BASE, writes=writes, reads=reads)


def _case_versions(op: R.Operator) -> list[tuple[int, str, bool]]:
    return [(c.version, c.system_id, c.deleted) for c in R.case_versions(op.dsn, op.tid)]


def _state(op: R.Operator) -> tuple[dict[str, list[tuple[int, int, bool]]], list[tuple[int, str, bool]]]:
    """Everything the records tables hold for the tenant, as (numbers per system, case versions)."""
    return {s: op.numbers(s) for s in ALL_SYSTEMS}, _case_versions(op)


def _refused(op: R.Operator, before: Any, rc: int, said: str, needles: tuple[tuple[str, ...], ...], *,
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


def _block(out: str, adapter: str, others: tuple[str, ...]) -> str:
    """The listing lines from the first naming `adapter` up to the next line naming another adapter."""
    lines, taken = out.splitlines(), []
    for line in lines:
        if taken and any(o in line for o in others):
            break
        if taken or adapter in line:
            taken.append(line)
    return "\n".join(taken)


# --- O2 -------------------------------------------------------------------------------------------------------------

#: adapter id -> (declared settings keys as stored, a tool it offers or None); the checkout's nine adapters (O2).
CATALOG_KEYS: Mapping[str, tuple[tuple[str, ...], str | None]] = {
    "elastic": (("ELASTIC_EVENTS_INDEX", "ELASTIC_ALERTS_INDEX"), None),
    "jira": (("JIRA_TIMEOUT_SEC", "JIRA_SERVICE_DESK"), None),
    "servicenow": (("SERVICENOW_TIMEOUT_SEC", "SERVICENOW_TABLE"), None),
    "change-mgmt": (("CHANGE_MGMT_TIMEOUT_SEC",), None),
    "cmdb": (("CMDB_TIMEOUT_SEC",), "list-hosts"),
    "host-state": ((), None),
    "identity": (("IDENTITY_TIMEOUT_SEC",), "get-user"),
    "threat-intel": (("THREAT_INTEL_TIMEOUT_SEC",), None),
    "ticket": (("TICKET_TIMEOUT_SEC", "TICKET_KEY_PATTERN"), None),
}


_UPPER_KEY = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")  # a settings key as stored: PREFIX_NAME


def _declared(adapter: str) -> Any:
    """The adapter's module: its `PREFIX`, `REQUIRED_CONFIG_KEYS`, `DISPLAY_NAME` and `EXAMPLE` are the cold-readable
    constants the K2 lint guarantees (O2), so the listing is judged against them, not against a second copy."""
    return importlib.import_module(f"defender.integrations.{adapter.replace('-', '_')}_adapter")


def test_1366_o2_the_catalog_lists_every_adapter_with_its_display_name_exact_required_keys_and_example_mark(capsys):
    """`catalog` lists each adapter with its display name, exact required keys and example mark (all from its K2
    constants); tacit-knowledge is no entry. (#1366 O2, K2)"""
    from defender.cli import tenant

    on_disk = {p.stem.removesuffix("_adapter").replace("_", "-") for p in (REPO / "defender/integrations").glob("*_adapter.py")}
    assert on_disk == set(CATALOG_KEYS) == {*R.REAL, *R.EXAMPLES}, "premise: the table is the checkout's adapter set"
    capsys.readouterr()
    rc = tenant.main([R.CATALOG])
    out = capsys.readouterr().out
    assert rc == 0, out
    for adapter, (keys, tool) in CATALOG_KEYS.items():
        module = _declared(adapter)
        declared = tuple(f"{module.PREFIX}_{k}" for k in module.REQUIRED_CONFIG_KEYS)
        assert set(declared) == set(keys), f"premise: {adapter}'s declared constants are the design's keys"
        assert bool(module.EXAMPLE) == (adapter in R.EXAMPLES), f"premise: {adapter}'s EXAMPLE flag"
        block = _block(out, adapter, tuple(a for a in CATALOG_KEYS if a != adapter))
        assert block, (adapter, out)
        assert module.DISPLAY_NAME in block, (adapter, module.DISPLAY_NAME, block)
        assert tool is None or tool in block, (adapter, tool, block)
        assert ("example" in block) == bool(module.EXAMPLE), (adapter, block)
        # exactly the declared keys: none missing, none extra (any KEY_LIKE token in the block is declared)
        assert set(_UPPER_KEY.findall(block)) == set(declared), (adapter, declared, block)
        for key in declared:  # each is marked required, on the line that names it
            assert [ln for ln in block.splitlines() if key in ln and "required" in ln.lower()], (adapter, key, block)
    assert "tacit-knowledge" not in out


# --- O9 / R13 -------------------------------------------------------------------------------------------------------

@pytest.mark.postgres
def test_1366_o9_the_import_turns_each_folder_into_a_first_version_at_generation_one_and_marks_the_tenant(
        fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch):  # noqa: F811
    """Every `settings/systems/<s>/` becomes version 1 at generation 1, settings and access as the folder held them,
    and the case record its version 1, all by `tenant.py import`; the tenant is marked. (#1366 O9, R8, R9, K4)"""
    tid = fixture_tenant.tenant_id
    op = _operator(fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch)
    assert not R.imported(migrated_database, tid), "premise: not imported"

    rc, said = op.import_()

    assert rc == 0, said
    current = op.current()
    assert set(current) == R.FIXTURE_SYSTEMS
    for system, (config, access) in R.FIXTURE_FOLDERS.items():
        got = current[system]
        assert (got.version, got.credential_generation, got.enabled, got.adapter_id) == (1, 1, True, system), system
        assert (dict(got.settings), got.access) == (dict(config), access), system
    assert {(s, op.versions(s)[-1].author, op.versions(s)[-1].deleted) for s in R.FIXTURE_SYSTEMS} == {
        (s, R.AUTHOR[R.IMPORT], False) for s in R.FIXTURE_SYSTEMS}
    assert all(op.versions(s)[-1].written_at is not None for s in R.FIXTURE_SYSTEMS)
    case = R.current_records(migrated_database, tid).case
    assert (case.version, case.system_id, case.comment_body) == (1, "ticket", R.FIXTURE_CASE_BODY)
    assert [(c.version, c.author) for c in R.case_versions(migrated_database, tid)] == [(1, R.AUTHOR[R.IMPORT])]
    assert R.imported(migrated_database, tid)


@pytest.mark.postgres
def test_1366_r13_the_import_copies_no_secret_and_reads_none(
        fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch):  # noqa: F811
    """A credential set stored at the pre-generation path stays where it is and is neither read nor copied to `g1`: the
    import's OpenBao (handed to it as `secrets=`) sees no request. After it `systems` lists elastic without credentials
    at its current generation until `set-credentials` writes `g1`. (#1366 R13, O8)"""
    tid = fixture_tenant.tenant_id
    kv = R.KvStandIn({f"{tid}/elastic": R.credential_set({"username": "svc", "password": "pw"})})
    op = _operator(fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch, kv=kv)

    rc, said = op.import_()

    assert rc == 0, said
    assert kv.requests == [], kv.requests
    assert list(kv.held) == [f"{tid}/elastic"]
    rc, listing = op.systems()
    assert rc == 0, listing
    assert R.lines_naming(listing, "elastic", "no credentials"), listing

    assert op.set_credentials("elastic", {"username": "svc", "password": "pw"}, for_version=1)[0] == 0
    assert kv.written() == [f"{tid}/elastic/g1"]
    assert not R.lines_naming(op.systems()[1], "elastic", "no credentials")


#: (id, planted overrides, files the dry run must name (any of), folder the import refusal must name (any of), key).
_CASE_FILE, _TICKET_ACCESS_FILE = "settings/case-record.yaml", "settings/systems/ticket/access.yaml"
_CFG = "settings/systems/{}/config.env".format
_ACC = "settings/systems/{}/access.yaml".format
IMPORT_FAILURES = [
    ("undeclared-key", {_CFG("cmdb"): 'CMDB_TIMEOUT_SEC="10"\nCMDB_COLOUR="red"\n'}, (_CFG("cmdb"),), ("settings/systems/cmdb",), "CMDB_COLOUR"),
    ("change-me", {_CFG("identity"): 'IDENTITY_TIMEOUT_SEC="CHANGE-ME"\n'}, (_CFG("identity"),), ("settings/systems/identity",), "IDENTITY_TIMEOUT_SEC"),
    ("missing-required", {_CFG("threat-intel"): "# nothing\n"}, (_CFG("threat-intel"),), ("settings/systems/threat-intel",), "THREAT_INTEL_TIMEOUT_SEC"),
    ("zero-timeout", {_CFG("change-mgmt"): 'CHANGE_MGMT_TIMEOUT_SEC="0"\n'}, (_CFG("change-mgmt"),), ("settings/systems/change-mgmt",), "CHANGE_MGMT_TIMEOUT_SEC"),
    ("path-key", {_CFG("elastic"): 'ELASTIC_EVENTS_INDEX="a/b"\nELASTIC_ALERTS_INDEX="alerts-*"\n'}, (_CFG("elastic"),), ("settings/systems/elastic",), "ELASTIC_EVENTS_INDEX"),
    ("access-unparseable", {_ACC("change-mgmt"): "access: [\n"}, (_ACC("change-mgmt"),), ("settings/systems/change-mgmt",), None),
    ("access-empty", {_ACC("host-state"): ""}, (_ACC("host-state"),), ("settings/systems/host-state",), None),
    ("platform-served", {_ACC("tacit-knowledge"): R.declaration("http://soc-playground:8009")}, ("settings/systems/tacit-knowledge",), ("settings/systems/tacit-knowledge",), None),
    ("unknown-adapter", {_ACC("frobnicator"): R.declaration("http://soc-playground:8009")}, ("settings/systems/frobnicator",), ("settings/systems/frobnicator",), None),
    ("case-system-without-folder", {_CASE_FILE: R.case_record_text("jira")}, (_CASE_FILE,), (_CASE_FILE,), "jira"),
    ("case-system-cannot-comment", {_CASE_FILE: R.case_record_text("cmdb")}, (_CASE_FILE,), (_CASE_FILE,), "cmdb"),
    ("case-template", {_CASE_FILE: R.case_record_text(body="{nosuch}")}, (_CASE_FILE,), (_CASE_FILE,), None),
    ("cover-broken", {_ACC("ticket"): R.bearer_access(TICKET_BASE, writes=(("POST", "/tickets/*/transitions"),))},
     (_TICKET_ACCESS_FILE, _CASE_FILE), ("settings/systems/ticket", _CASE_FILE), None),
    # r5: a READ route that matches the comment route is refused even beside a covering write (C2's read-route rule).
    ("cover-read-route-matches", {_ACC("ticket"): R.declaration(TICKET_BASE, reads=(("POST", "/tickets/*/comments"),),
                                                                   writes=(("POST", "/tickets/*/comments"),))},
     (_TICKET_ACCESS_FILE, _CASE_FILE), ("settings/systems/ticket", _CASE_FILE), None),
    ("cover-read-route-literal-matches", {_ACC("ticket"): R.declaration(TICKET_BASE, reads=(("POST", "/tickets/ABC-1/comments"),),
                                                                           writes=(("POST", "/tickets/*/comments"),))},
     (_TICKET_ACCESS_FILE, _CASE_FILE), ("settings/systems/ticket", _CASE_FILE), None),
]


@pytest.mark.postgres
@pytest.mark.parametrize("row", IMPORT_FAILURES, ids=[r[0] for r in IMPORT_FAILURES])
def test_1366_o9_one_failing_folder_refuses_the_whole_import_naming_it_and_the_dry_run_names_the_file(
        row, tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811
    """Any one folder or case record failing the store's judgement refuses the whole import naming it, writing no
    version, no mark and touching no secret; the dry run names the file to fix. (#1366 O9, C6)"""
    _, overrides, dry_files, folders, key = row
    with _planted(tmp_path, data_root, migrated_database, capsys, monkeypatch, **overrides) as op:
        dry_rc, listed = op.import_(dry_run=True)
        rc, said = op.import_()

        assert dry_rc != 0, listed
        assert any(R.lines_naming(listed, f) for f in dry_files), listed
        assert key is None or R.lines_naming(listed, key), listed
        assert rc != 0, said
        assert any(R.lines_naming(said, f) for f in folders), said
        assert "Traceback" not in said + listed
        assert op.current() == {}
        assert R.current_records(migrated_database, op.tid).case is None
        assert not R.imported(migrated_database, op.tid)
        assert op.kv.requests == []


@pytest.mark.postgres
def test_1366_o9_the_dry_run_lists_every_failure_across_folders_and_the_case_record(
        tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811
    """Five failures of different kinds in five places: the dry run names all five files, the import writes none.
    (#1366 O9)"""
    bad = {_CFG("cmdb"): 'CMDB_TIMEOUT_SEC="10"\nCMDB_COLOUR="red"\n', _ACC("identity"): "access: [\n",
           _CFG("elastic"): 'ELASTIC_EVENTS_INDEX="a/b"\nELASTIC_ALERTS_INDEX="x"\n',
           _ACC("tacit-knowledge"): R.declaration("http://soc-playground:8009"),
           _CASE_FILE: R.case_record_text(body="{nosuch}")}
    with _planted(tmp_path, data_root, migrated_database, capsys, monkeypatch, **bad) as op:
        rc, listed = op.import_(dry_run=True)

        assert rc != 0
        for file in bad:
            assert R.lines_naming(listed, file.removesuffix("/access.yaml") if "tacit" in file else file), (file, listed)
        assert op.import_()[0] != 0
        assert op.current() == {}
        assert not R.imported(migrated_database, op.tid)


@pytest.mark.postgres
def test_1366_o9_a_clean_dry_run_writes_nothing_and_leaves_the_import_to_run(
        op, migrated_database):  # noqa: F811
    """A dry run over a good tenant is clean, leaves no row and no mark and touches no secret; the import after it
    still runs. (#1366 O9)"""
    rc, listed = op.import_(dry_run=True)

    assert rc == 0, listed
    assert op.current() == {}
    assert R.case_versions(migrated_database, op.tid) == []
    assert not R.imported(migrated_database, op.tid)
    assert op.kv.requests == []
    assert op.import_()[0] == 0
    assert set(op.current()) == R.FIXTURE_SYSTEMS


@pytest.mark.postgres
def test_1366_o9_the_import_reads_the_published_export_not_the_clone(fixture_tenant, op):
    """After publishing, the clone's working tree is edited (a changed cmdb timeout, a removed elastic folder, a bad
    new folder): the import stores the published values. (#1366 O9, DC8)"""
    settings = fixture_tenant.clone / "settings"
    assert (settings / "systems/elastic").is_dir(), "premise: the clone holds the planted folders"
    (settings / "systems/cmdb").mkdir(parents=True, exist_ok=True)
    (settings / "systems/cmdb/config.env").write_text('CMDB_TIMEOUT_SEC="77"\nCMDB_COLOUR="red"\n', encoding="utf-8")
    shutil.rmtree(settings / "systems/elastic")
    (settings / "systems/frobnicator").mkdir(parents=True, exist_ok=True)
    (settings / "systems/frobnicator/access.yaml").write_text("access: [\n", encoding="utf-8")

    published = R.settings_of(fixture_tenant.data_root, fixture_tenant.tenant_id)
    assert (published / "systems/elastic").is_dir(), "premise: the published export still holds the original folders"
    assert "77" not in (published / "systems/cmdb/config.env").read_text("utf-8"), "premise: published cmdb is unedited"

    rc, said = op.import_()

    assert rc == 0, said
    assert set(op.current()) == R.FIXTURE_SYSTEMS
    assert dict(op.current()["cmdb"].settings) == CMDB_CONFIG


@pytest.mark.postgres
def test_1366_o9_a_tenant_with_no_systems_is_still_marked_imported_and_then_takes_writes(
        tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811
    """Importing a tenant whose export holds no system folder and no case record writes no version, sets the mark, and
    a first `set-system` then lands as version 1. (#1366 O9, R8)"""
    retired = {f"settings/{p.relative_to(FIXTURE_SETTINGS)}": None for p in FIXTURE_SETTINGS.rglob("*")
               if p.is_file() and (p.relative_to(FIXTURE_SETTINGS).parts[0] == "systems"
                                   or p.name == "case-record.yaml")}
    with _planted(tmp_path, data_root, migrated_database, capsys, monkeypatch, files=retired) as op:
        assert not R.imported(migrated_database, op.tid)

        rc, said = op.import_()

        assert rc == 0, said
        assert R.imported(migrated_database, op.tid)
        assert op.current() == {}
        assert R.current_records(migrated_database, op.tid).case is None
        assert op.set_system("cmdb", replaces=0, config=CMDB_CONFIG, access=CMDB_ACCESS)[0] == 0
        assert op.numbers("cmdb") == [(1, 1, False)]


@pytest.mark.postgres
def test_1366_o9_an_already_imported_tenant_is_refused_naming_the_import_and_nothing_changes(imported_op):
    """A second import (also after an edit) is refused naming the import and rewrites no version. (#1366 O9, R8)"""
    assert imported_op.set_system("cmdb", replaces=1, config=CMDB_NEW, access=CMDB_ACCESS)[0] == 0
    before = _state(imported_op)

    rc, said = imported_op.import_()

    assert rc != 0, said
    assert R.lines_naming(said, R.AUTHOR[R.IMPORT]), said
    assert _state(imported_op) == before
    assert dict(imported_op.current()["cmdb"].settings) == CMDB_NEW


@pytest.mark.postgres
@pytest.mark.parametrize("command", ["set_system", "delete_system", "set_case", "delete_case"])
def test_1366_r8_a_write_to_a_tenant_not_imported_is_refused_naming_the_import(op, command):
    """All four write commands on a not-imported tenant are refused naming the import before any staleness; after the
    import the same call lands. (#1366 R8, DC8)"""
    call = {"set_system": lambda: op.set_system("cmdb", replaces=1, config=CMDB_NEW, access=CMDB_ACCESS),
            "delete_system": lambda: op.delete_system("cmdb", replaces=1),
            "set_case": lambda: op.set_case(replaces=1, body="{disposition}"),
            "delete_case": lambda: op.delete_case(replaces=1)}[command]

    rc, said = call()

    assert rc != 0, said
    assert R.lines_naming(said, R.AUTHOR[R.IMPORT]), said
    assert not R.imported(op.dsn, op.tid)
    assert op.numbers("cmdb") == []
    assert _case_versions(op) == []
    assert op.import_()[0] == 0
    rc, said = call()
    assert rc == 0, said


# --- O3 / O4: the operator command refuses an unusable system record -------------------------------------------------

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


async def _door(op: R.Operator, call: Any) -> Any:
    from defender.system_records import open_store

    store = open_store(op.dsn, clock=fixed_clock)
    if inspect.isawaitable(store):
        store = await store
    try:
        return await call(store)
    finally:
        await store.close()


def _at_the_door(op: R.Operator, call: Any) -> Any:
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
    version = {"absent": 0, "disabled": 1, "deleted": 2}[how]
    assert op.set_system("jira", replaces=version, config=JIRA_CONFIG, access=_jira_access(JIRA_API))[0] == 0
    assert op.set_case(replaces=1, system="jira")[0] == 0
    assert op.current()["jira"].enabled


@pytest.mark.postgres
@pytest.mark.parametrize("body", ["{nosuch}", "{0}", "{unclosed", "   "])
def test_1366_o4_a_case_template_failing_the_case_record_rules_is_refused(imported_op, body):
    """A template naming an unknown render key, a positional one, an unclosed brace or blank text is refused and
    stored nowhere; a good one is version 2. (#1366 O4, #1359)"""
    before = _state(imported_op)

    rc, said = imported_op.set_case(replaces=1, body=body)

    _refused(imported_op, before, rc, said, (("comment.body",),), file_ok=True)  # #1359's judgement names the field
    assert imported_op.set_case(replaces=1, body="{disposition}: {cause}")[0] == 0
    assert _case_versions(imported_op) == [(1, "ticket", False), (2, "ticket", False)]


@pytest.mark.postgres
def test_1366_o4_a_case_record_naming_a_file_that_is_not_a_record_is_refused(imported_op, tmp_path):
    """A case-record file that is not a mapping with a `system` and a `comment.body` is refused and stored nowhere.
    (#1366 O4, DC8)"""
    before = _state(imported_op)
    shapes = ["- just\n- a list\n", "system: ticket\n", "comment: {body: x}\n", "system: [\n",
              "system: 42\ncomment: {body: x}\n", "system: ''\ncomment: {body: x}\n",
              "system: ticket\ncomment: [x]\n", "system: ticket\ncomment: {}\n", "system: ticket\ncomment:\n  body: 7\n"]
    for n, text in enumerate(shapes):
        file = tmp_path / f"bad-case-{n}.yaml"
        file.write_text(text, encoding="utf-8")
        rc, said = imported_op.run(R.SET_CASE, imported_op.tid, str(file), R.REPLACES, "1")
        assert rc != 0, (text, said)
        assert "Traceback" not in said, (text, said)
        assert _state(imported_op) == before, text


@pytest.mark.postgres
def test_1366_p2_a_handoff_folder_whose_files_are_not_text_is_refused_and_stored_nowhere(imported_op, tmp_path):
    """A `config.env` or `access.yaml` that is not UTF-8 text never becomes a record: `set-system` refuses naming the
    system, with no traceback, and stores nothing. Moved from the startup tests that planted a non-UTF-8 `config.env`
    (a file that cannot reach a run any more). (#1366 P2, O9, DC8)"""
    before = _state(imported_op)
    for n, name in enumerate(("config.env", "access.yaml")):
        folder = R.system_folder(tmp_path / f"bytes-{n}", "cmdb", config=CMDB_CONFIG, access=CMDB_ACCESS)
        (folder / name).write_bytes(b"\xff\xfe not text \x80\n")
        rc, said = imported_op.run(R.SET_SYSTEM, imported_op.tid, "cmdb", str(folder), R.REPLACES, "1")
        _refused(imported_op, before, rc, said, (("cmdb",),), file_ok=True)


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
    return R.Operator(fixture_tenant.tenant_id, migrated_database, tmp_path / "op", capsys)


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

#: (id, writes, reads, covers) for ticket's comment route `POST /tickets/*/comments` at base `TICKET_BASE`.
TICKET_COVER = [
    ("exact", (("POST", "/tickets/*/comments"),), (), True),
    ("beside-another-write", (("POST", "/tickets/*/transitions"), ("POST", "/tickets/*/comments")), (), True),
    ("wildcard-for-a-literal-segment", (("POST", "/*/*/comments"),), (), True),
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
    ("read-routes-that-do-not-match", (("POST", "/tickets/*/comments"),),
     (("GET", "/tickets/*/comments"), ("POST", "/tickets/*/other"), ("POST", "/tickets/*")), True),
]


@pytest.mark.postgres
@pytest.mark.parametrize("row", TICKET_COVER, ids=[r[0] for r in TICKET_COVER])
def test_1366_c2_a_write_to_the_case_system_is_stored_only_if_a_write_route_covers_the_comment_route(imported_op, row):
    """ticket (the case system) is stored only with a same-method, same-length write route whose segments are `*` or
    the raw literal, and no read route matching the comment route; else refused naming ticket's access. (#1366 C2, C4)"""
    _, writes, reads, covers = row
    access = R.declaration(TICKET_BASE, writes=writes, reads=reads)
    before = _state(imported_op)

    rc, said = imported_op.set_system("ticket", replaces=1, config=TICKET_CONFIG, access=access)

    if covers:
        assert rc == 0, said
        assert imported_op.current()["ticket"].version == 2
    else:
        _refused(imported_op, before, rc, said, (("system ticket access",),))
        assert not R.lines_naming(said, "system ticket settings"), said


@pytest.mark.postgres
def test_1366_c4_a_case_record_write_that_finds_no_cover_is_refused_naming_the_case_record(imported_op):
    """With the case record deleted, ticket is rewritten without cover (allowed); `set-case` naming it is refused
    naming the case record, and succeeds once ticket covers again. (#1366 C4)"""
    op = imported_op
    assert op.delete_case(replaces=1)[0] == 0
    assert op.set_system("ticket", replaces=1, config=TICKET_CONFIG,
                         access=R.bearer_access(TICKET_BASE, writes=(("POST", "/tickets/*/transitions"),)))[0] == 0
    before = _state(op)

    rc, said = op.set_case(replaces=2)

    _refused(op, before, rc, said, (("case record",),), file_ok=True)
    assert op.set_system("ticket", replaces=2, config=TICKET_CONFIG, access=TICKET_ACCESS)[0] == 0
    assert op.set_case(replaces=2)[0] == 0


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
    """cmdb: edit (2), delete (3); then naming 2, 0 or 9 is refused and naming the delete (3) stores version 4; identity
    stays at 1. Each version carries its command's name as author and a time. (#1366 O5, R9)"""
    op = imported_op
    assert op.set_system("cmdb", replaces=1, config=CMDB_NEW, access=CMDB_ACCESS)[0] == 0
    assert op.delete_system("cmdb", replaces=2)[0] == 0
    before = _state(op)

    for stale in (2, 0, 9):
        rc, said = op.set_system("cmdb", replaces=stale, config=CMDB_NEW, access=CMDB_ACCESS)
        _refused(op, before, rc, said, (("cmdb",),), file_ok=True)
        assert not stale or _numbered(said, "cmdb", stale), said

    assert op.set_system("cmdb", replaces=3, config=CMDB_NEW, access=CMDB_ACCESS)[0] == 0
    assert [(n, d) for n, _, d in op.numbers("cmdb")] == [(1, False), (2, False), (3, True), (4, False)]
    assert [v.author for v in op.versions("cmdb")] == [R.AUTHOR[R.IMPORT], R.AUTHOR[R.SET_SYSTEM],
                                                      R.AUTHOR[R.DELETE_SYSTEM], R.AUTHOR[R.SET_SYSTEM]]
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
        (1, False, R.AUTHOR[R.IMPORT]), (2, True, R.AUTHOR[R.DELETE_SYSTEM])]
    assert "cmdb" not in imported_op.current()
    _, after = imported_op.check()
    assert R.lines_naming(after, "cmdb", "orphan"), after


@pytest.mark.postgres
def test_1366_o5_case_versions_number_per_tenant_and_follow_the_same_rules(imported_op):
    """Case: set (2), delete (3); then deleting again, naming 2 or 0 is refused; naming the delete stores 4. Authors
    are `set-case` and `delete-case`. (#1366 O5, R9)"""
    op = imported_op
    assert op.set_case(replaces=1, body="{disposition}")[0] == 0
    assert op.delete_case(replaces=2)[0] == 0
    before = _state(op)

    for rc, said in (op.delete_case(replaces=3), op.set_case(replaces=2), op.set_case(replaces=0)):
        _refused(op, before, rc, said, (), file_ok=True)

    assert op.set_case(replaces=3, body="{cause}")[0] == 0
    assert _case_versions(op) == [(1, "ticket", False), (2, "ticket", False), (3, "ticket", True), (4, "ticket", False)]
    assert [c.author for c in R.case_versions(op.dsn, op.tid)] == [
        R.AUTHOR[R.IMPORT], R.AUTHOR[R.SET_CASE], R.AUTHOR[R.DELETE_CASE], R.AUTHOR[R.SET_CASE]]
    assert R.current_records(op.dsn, op.tid).case.comment_body == "{cause}"


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
        await store.put_case(op.tid, replaces=1, system_id="ticket", comment_body="{disposition}", author="test b")

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
    assert op.set_system("identity", replaces=4, config=IDENTITY, access=first)[0] == 0
    assert op.delete_system("identity", replaces=5)[0] == 0
    assert op.set_system("identity", replaces=6, config=IDENTITY, access=first)[0] == 0

    assert op.numbers("identity") == [(1, 1, False), (2, 2, False), (3, 3, False), (4, 3, True), (5, 4, False),
                                      (6, 4, True), (7, 5, False)]
    assert op.kv.written() == [f"{op.tid}/identity/g1"]
    assert R.lines_naming(op.systems()[1], "identity", "no credentials")


# --- O8: set-credentials -----------------------------------------------------------------------------------------------


class _BaoDown(R.KvStandIn):
    """OpenBao unreachable: every request fails to connect."""

    def _handle(self, request):
        import httpx

        raise httpx.ConnectError("connection refused", request=request)


class _WrittenMeanwhile(R.KvStandIn):
    """OpenBao that, as the credential set arrives, lets another writer store the system's next version first: the
    same record with its credential generation raised by `raise_by` (0: a change that keeps the generation, such as a
    reads route)."""

    def __init__(self, dsn: str, tenant_id: str, system: str, raise_by: int) -> None:
        super().__init__()
        self._meanwhile = (dsn, tenant_id, system, raise_by)

    def _handle(self, request):
        from defender.tests.support.shared._postgres1339 import execute

        if request.method in ("POST", "PUT") and self._meanwhile is not None:
            dsn, tenant_id, system, raise_by = self._meanwhile
            self._meanwhile = None
            execute(dsn, "INSERT INTO tenancy.system_versions (tenant_id, system_id, version, adapter_id, enabled, settings, "
                         "access, credential_generation, deleted, author, written_at) "
                         "SELECT tenant_id, system_id, version + 1, adapter_id, enabled, settings, access, "
                         "credential_generation + %s, deleted, author, written_at FROM tenancy.system_versions "
                         "WHERE tenant_id = %s AND system_id = %s ORDER BY version DESC LIMIT 1",
                    (raise_by, tenant_id, system))
        return super()._handle(request)


@pytest.mark.parametrize(("raise_by", "served"), [(0, True), (1, False)], ids=["same-generation", "new-generation"])
@pytest.mark.postgres
def test_1366_o8_a_version_written_meanwhile_is_served_when_it_keeps_the_generation(imported_op, raise_by, served):
    """identity moves to version 2 while its version-1 credentials are being stored. The set at `g1` serves version 2
    when that version kept generation 1, so the command succeeds; when it took generation 2 the set serves nothing
    current, and the command says so and fails. (#1366 O8, P5)"""
    op = imported_op
    op.kv = _WrittenMeanwhile(op.dsn, op.tid, "identity", raise_by)

    rc, said = op.set_credentials("identity", {"api_key": "k-1366"}, for_version=1)

    assert op.versions("identity")[-1].version == 2, "premise: a version was written meanwhile"
    assert (rc == 0) is served, said
    assert bool(R.lines_naming(said, "identity", "does not serve")) is not served, said


@pytest.mark.postgres
def test_1366_o8_an_unreachable_secret_store_is_a_printed_refusal_not_a_traceback(imported_op):
    """set-credentials while OpenBao is down: exit 1 and one `[tenant.py]` line naming the system, nothing written."""
    op = imported_op
    op.kv = _BaoDown()
    rc, said = op.set_credentials("identity", {"api_key": "k-1366"}, for_version=1)
    assert rc == 1, said
    assert R.lines_naming(said, "[tenant.py]", "identity", "not written"), said
    assert "Traceback" not in said


@pytest.mark.postgres
def test_1366_o8_a_bad_kv_mount_is_a_printed_refusal_not_a_traceback(imported_op):
    """`--kv-mount` that is not a mount name: exit 1 and one `[tenant.py]` line naming the mount."""
    op = imported_op
    op.tmp.mkdir(parents=True, exist_ok=True)
    token = op.tmp / "token"
    token.write_text("operator-token\n", encoding="utf-8")
    from defender.cli import tenant

    op.capsys.readouterr()
    rc = tenant.main(["systems", op.tid, "--token-file", str(token), "--kv-mount", "bad mount"])
    said = op.capsys.readouterr()
    assert rc == 1, said
    assert R.lines_naming(said.err, "[tenant.py]", "mount"), said

@pytest.mark.postgres
def test_1366_o8_credentials_prepared_for_a_stale_version_are_refused_and_current_ones_land_at_its_generation(imported_op):
    """identity moves (version 2, generation 2): credentials naming version 1 are refused naming identity and the
    version and nothing is written; naming 2 they are written, exactly as given, at `<tenant>/identity/g2` only.
    (#1366 O8, P5)"""
    op = imported_op
    assert op.set_system("identity", replaces=1, config=IDENTITY, access=R.bearer_access("http://identity.internal:8005"))[0] == 0
    rc, said = op.set_credentials("identity", {"api_key": "k-1366"}, for_version=1)
    assert rc != 0, said
    assert _numbered(said, "identity", 1), said
    assert op.kv.written() == []
    assert op.kv.held == {}

    rc, said = op.set_credentials("identity", {"api_key": "k-1366"}, for_version=2)
    assert rc == 0, said
    assert op.kv.written() == [f"{op.tid}/identity/g2"]
    assert op.kv.held == {f"{op.tid}/identity/g2": [R.credential_set({"api_key": "k-1366"})]}


@pytest.mark.postgres
def test_1366_o8_credentials_are_only_for_an_existing_current_system(imported_op):
    """A system with no record or a deleted one is refused and nothing is written; a disabled one takes credentials at
    its generation path. (#1366 O8)"""
    op = imported_op
    assert op.delete_system("cmdb", replaces=1)[0] == 0
    for system, version in (("jira", 1), ("cmdb", 2), ("cmdb", 1)):
        rc, said = op.set_credentials(system, {"api_key": "k"}, for_version=version)
        assert rc != 0, said
        assert R.lines_naming(said, system), said
    assert op.kv.written() == []

    assert op.set_system("identity", replaces=1, config=IDENTITY, access=R.FIXTURE_FOLDERS["identity"][1], disabled=True)[0] == 0
    assert op.set_credentials("identity", {"api_key": "k"}, for_version=2)[0] == 0
    assert op.kv.written() == [f"{op.tid}/identity/g1"]


class _MovingKv(R.KvStandIn):
    """A KV stand-in that runs `move` once, during the first write it is sent (another operator moving the system)."""

    def __init__(self, move: Any) -> None:
        super().__init__()
        self._move, self._moved = move, False

    def _handle(self, request: Any) -> Any:
        if request.method in ("POST", "PUT") and not self._moved:
            self._moved = True
            self._move()
        return super()._handle(request)


@pytest.mark.postgres
def test_1366_o8_credentials_typed_while_another_operator_moves_the_system_are_reported_refused(
        fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch):  # noqa: F811
    """identity is moved to a new base during the credential write: the command re-reads, finds the version no longer
    current and reports a refusal; the set it wrote sits at the version's own generation path. (#1366 O8)"""
    def move() -> None:
        async def put(store: Any) -> None:
            await store.put_system(fixture_tenant.tenant_id, "identity", replaces=2, adapter="identity", enabled=True,
                                   settings=IDENTITY, access=R.bearer_access("http://identity.moved:8005"), author="other operator")
        thread = threading.Thread(target=lambda: asyncio.run(_door(op, put)))
        thread.start()
        thread.join(60)

    kv = _MovingKv(move)
    op = _operator(fixture_tenant, migrated_database, tmp_path, capsys, monkeypatch, kv=kv)
    assert op.import_()[0] == 0
    assert op.set_system("identity", replaces=1, config=IDENTITY, access=R.bearer_access("http://identity.internal:8005"))[0] == 0

    rc, said = op.set_credentials("identity", {"api_key": "k"}, for_version=2)

    assert op.numbers("identity") == [(1, 1, False), (2, 2, False), (3, 3, False)], "premise: the move landed"
    assert rc != 0, said
    assert R.lines_naming(said, "identity"), said
    assert kv.written() == [f"{op.tid}/identity/g2"]


# --- DC8: systems, export, disable, set-case ---------------------------------------------------------------------------

@pytest.mark.postgres
def test_1366_dc8_systems_lists_each_current_system_with_version_generation_enabled_and_credentials(imported_op):
    """With identity at version 3, generation 2, cmdb disabled and threat-intel deleted: one line per current system
    naming version and generation, disabled ones say so, the deleted one is gone, `no credentials` follows the current
    generation. (#1366 DC8, O8)"""
    op = imported_op
    assert op.set_system("identity", replaces=1, config=IDENTITY, access=R.bearer_access("http://soc-playground:9005"))[0] == 0
    assert op.set_system("identity", replaces=2, config={"IDENTITY_TIMEOUT_SEC": "20"}, access=R.bearer_access("http://soc-playground:9005"))[0] == 0
    assert op.set_system("cmdb", replaces=1, config=CMDB_CONFIG, access=CMDB_ACCESS, disabled=True)[0] == 0
    assert op.delete_system("threat-intel", replaces=1)[0] == 0
    assert op.set_credentials("identity", {"api_key": "k"}, for_version=3)[0] == 0

    rc, listing = op.systems()

    assert rc == 0, listing
    (identity,) = R.lines_naming(listing, "identity")
    assert _numbered(identity, "identity", 3), identity
    assert _numbered(identity, "identity", 2), identity
    assert "no credentials" not in identity
    assert "disabled" not in identity
    (cmdb,) = R.lines_naming(listing, "cmdb")
    assert "disabled" in cmdb, cmdb
    assert "no credentials" in cmdb, cmdb
    assert not R.lines_naming(listing, "threat-intel"), listing
    for system in R.FIXTURE_SYSTEMS - {"identity", "cmdb", "threat-intel"}:
        (line,) = R.lines_naming(listing, system)
        assert "no credentials" in line, line
        assert "disabled" not in line, line
    assert op.set_system("identity", replaces=3, config={"IDENTITY_TIMEOUT_SEC": "20"},
                         access=R.bearer_access("http://soc-playground:9999"))[0] == 0
    assert "no credentials" in R.lines_naming(op.systems()[1], "identity")[0]


@pytest.mark.postgres
def test_1366_dc8_a_system_exported_by_systems_is_taken_back_by_set_system_unchanged(imported_op, tmp_path):
    """`systems --export <dir>` writes each current system as the folder `set-system` takes; writing cmdb back from it
    is a new version with the same settings, access and generation. (#1366 DC8, O11)"""
    op = imported_op
    assert op.set_system("cmdb", replaces=1, config=CMDB_NEW, access=CMDB_ACCESS)[0] == 0
    out = tmp_path / "exported"

    rc, said = op.systems(R.EXPORT, str(out))

    assert rc == 0, said
    for system, (config, _access_text) in R.FIXTURE_FOLDERS.items():
        folder = out / system
        assert (folder / "access.yaml").is_file(), (system, sorted(p.name for p in out.rglob("*")))
        config_file = folder / "config.env"
        assert (R.parse_config_env(config_file.read_text("utf-8")) if config_file.is_file() else {}) == (
            CMDB_NEW if system == "cmdb" else dict(config)), system
    rc, said = op.run(R.SET_SYSTEM, op.tid, "cmdb", str(out / "cmdb"), R.REPLACES, "2")
    assert rc == 0, said
    before, again = op.versions("cmdb")[1:]
    assert (again.version, again.settings, again.access, again.credential_generation) == (
        3, before.settings, before.access, before.credential_generation)
    assert op.run(R.SET_SYSTEM, op.tid, "host-state", str(out / "host-state"), R.REPLACES, "1")[0] == 0


@pytest.mark.postgres
def test_1366_dc8_an_export_refuses_a_directory_already_holding_a_system_folder(imported_op, tmp_path):
    """host-state has no settings, so its export writes no config.env: a stale one an earlier folder left would be read
    back by set-system. `--export` into a directory holding any system's folder is refused, naming it, and writes
    nothing. (#1366 DC8)"""
    op = imported_op
    out = tmp_path / "exported"
    stale = out / "host-state" / "config.env"
    stale.parent.mkdir(parents=True)
    stale.write_text("HOST_STATE_LEFTOVER=1\n", encoding="utf-8")

    rc, said = op.systems(R.EXPORT, str(out))

    assert rc == 1, said
    assert R.lines_naming(said, "[tenant.py]", "host-state"), said
    assert sorted(p.relative_to(out).as_posix() for p in out.rglob("*")) == ["host-state", "host-state/config.env"]


@pytest.mark.postgres
def test_1366_dc8_disabling_and_re_enabling_is_a_version_that_keeps_the_record(imported_op):
    """`--disabled` stores version 2 with enabled false (settings and access judged all the same); a write with no flag
    keeps it disabled (version 3: the folder does not say on or off, so an exported folder written back cannot switch it
    on); `--enabled` is version 4, enabled again. (#1366 DC8, O1)"""
    op = imported_op
    rc, said = op.set_system("cmdb", replaces=1, config={**CMDB_CONFIG, "CMDB_COLOUR": "x"}, access=CMDB_ACCESS, disabled=True)
    assert rc != 0, said
    assert R.lines_naming(said, "CMDB_COLOUR"), said
    assert op.set_system("cmdb", replaces=1, config=CMDB_CONFIG, access=CMDB_ACCESS, disabled=True)[0] == 0
    assert op.current()["cmdb"].enabled is False
    assert op.set_system("cmdb", replaces=2, config=CMDB_CONFIG, access=CMDB_ACCESS)[0] == 0
    assert op.set_system("cmdb", replaces=3, config=CMDB_CONFIG, access=CMDB_ACCESS, disabled=False)[0] == 0
    assert [(v.version, v.enabled) for v in op.versions("cmdb")] == [(1, True), (2, False), (3, False), (4, True)]


@pytest.mark.postgres
def test_1366_dc8_set_case_stores_the_body_exactly_and_delete_case_removes_the_record(imported_op):
    """`set-case` stores the file's system and template text as given (version 2); `delete-case` makes the case record
    not exist. (#1366 DC8, O5, H7)"""
    op = imported_op
    body = "{disposition} — {cause}\n\n{narrative}\nsee {case_id}"
    assert op.set_case(replaces=1, body=body)[0] == 0
    case = R.current_records(op.dsn, op.tid).case
    assert (case.version, case.system_id, case.comment_body) == (2, "ticket", body)
    assert op.delete_case(replaces=2)[0] == 0
    assert R.current_records(op.dsn, op.tid).case is None


# --- O11 ------------------------------------------------------------------------------------------------------------

@pytest.mark.postgres
@pytest.mark.parametrize("part", ["settings", "access"])
def test_1366_o11_connects_handoff_is_judged_with_the_stores_own_sentence_located_by_the_file(imported_op, tmp_path, part):
    """The store and connect's validator give the same fault sentence, located by record and by file. (#1366 O11, DC6)"""
    key = "CMDB_COLOUR" if part == "settings" else "colour"
    config = {**CMDB_CONFIG, "CMDB_COLOUR": "red"} if part == "settings" else CMDB_CONFIG
    access = CMDB_ACCESS if part == "settings" else CMDB_ACCESS.rstrip("\n") + "\ncolour: red\n"  # an unknown top-level key
    rc, said = imported_op.set_system("cmdb", replaces=1, config=config, access=access)
    assert rc != 0, said
    (fault,) = [line.removeprefix("[tenant.py] ").strip() for line in R.lines_naming(said, key)]
    sentence = H.store_sentence(fault, "cmdb", part)

    def validated(config: dict[str, str], access: str, label: str) -> str:
        folder = R.system_folder(tmp_path / f"handoff-{label}", "cmdb", config=config, access=access)
        env = {**os.environ, "PYTHONPATH": str(REPO)}
        done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", "cmdb",
                               "--handoff", str(folder)], cwd=REPO, env=env, capture_output=True, text=True,
                              timeout=120, check=False)
        return done.stdout + done.stderr

    report = validated(config, access, "bad")
    assert any(sentence in line for line in H.handoff_lines(report, key, "cmdb", part)), (sentence, report)
    clean = validated(CMDB_CONFIG, CMDB_ACCESS, "clean")  # control: same channel, a folder the store accepts
    assert "validate_scaffold: cmdb" in clean, clean  # printed only once the arguments were accepted
    assert key not in clean


#: (id, extra config.env text, the secret value it carries): lines a config parser may ignore or override.
IGNORED_LINE_SECRETS = [
    ("export-line", 'export CMDB_API_TOKEN="sk-live-9f8e7d6c5b4a3f2e1d0c"\n', "sk-live-9f8e7d6c5b4a3f2e1d0c"),
    ("overridden-duplicate", 'CMDB_PASSWORD="hunter2-live"\nCMDB_PASSWORD=""\n', "hunter2-live"),
    ("overridden-reference", 'CMDB_TOKEN_SECRET_REF="ghp-AbC!d3f@xyz"\nCMDB_TOKEN_SECRET_REF=""\n', "ghp-AbC!d3f@xyz"),
]


@pytest.mark.postgres
@pytest.mark.parametrize("row", IGNORED_LINE_SECRETS, ids=[r[0] for r in IGNORED_LINE_SECRETS])
def test_1366_h2_a_secret_on_a_line_a_parser_ignores_never_enters_a_stored_record(imported_op, tmp_path, row):
    """Guard: a secret on an ignored `export`/duplicate line is refused or left out, never stored (successor of the
    retired `test_validator_finds_secrets_on_lines_the_run_ignores`). (#1366 H2, P2)"""
    _, extra, secret = row
    folder = tmp_path / "raw" / "cmdb"
    folder.mkdir(parents=True)
    (folder / "access.yaml").write_text(CMDB_ACCESS, encoding="utf-8")
    base = 'CMDB_TIMEOUT_SEC="20"\n'
    (folder / "config.env").write_text(base, encoding="utf-8")
    rc, said = imported_op.run(R.SET_SYSTEM, imported_op.tid, "cmdb", str(folder), R.REPLACES, "1")
    assert rc == 0, said  # control: the declared key alone is stored as version 2
    (folder / "config.env").write_text(base + extra, encoding="utf-8")

    rc, said = imported_op.run(R.SET_SYSTEM, imported_op.tid, "cmdb", str(folder), R.REPLACES, "2")

    stored = [v for v in imported_op.versions("cmdb")]
    assert secret not in repr(stored), f"a secret value was stored:\n{stored}"
    current = imported_op.current()["cmdb"]
    assert set(current.settings) <= {"CMDB_TIMEOUT_SEC"}, dict(current.settings)
    assert current.version == (2 if rc != 0 else 3), (rc, said)


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
            rc, said = op.import_()
            assert rc == 0, said
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

    try:
        check_route(access, "ticket", *COMMENT, mode)
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
def test_1366_g4_the_cover_judgement_accepts_a_declared_write_exactly_when_the_proxy_admits_the_comment_as_that_write(
        imported_op):
    """Declared write routes built from the adapter's comment pattern by segment mutations (a star, another literal,
    case changes, percent-encodings, partial stars, empty segments, a trailing `/`): the ticket system, the case system,
    is stored with a route exactly when the proxy's own matcher (`check_route`) admits the request the adapter sends as
    a write that read-only tokens do not get; and a route the access parser refuses is not stored. Beside the exact
    covering write, the same spellings declared as READ routes: whenever the proxy admits the comment through the read
    route the write is refused (a comment is allowed only as a declared write). (#1366 C2, K4; the judgement is not a
    second matcher)"""
    from defender.system_records import RecordRefused

    op = imported_op
    base = "http://soc-playground:8004"
    wrong: list[str] = []
    version = [op.current()["ticket"].version]

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
            if await stored(access) is not _proxy_admits(access)[0]:
                wrong.append(f"write {path!r}: the judgement and the proxy differ on the comment as a write")
        assert await stored(R.declaration(base, writes=(COMMENT_ROUTE,))), "control: the exact route is stored"
        for path in _mutated_paths():
            access = R.declaration(base, writes=(COMMENT_ROUTE,), reads=(("POST", path),))
            if _proxy_admits(access)[1] and await stored(access):
                wrong.append(f"read {path!r}: the proxy admits the comment through the read route, and it was stored")

    _at_the_door(op, run_through_the_door)
    assert not wrong, wrong
