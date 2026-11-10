"""#1366 slice R (read side): `tenant check` judges the tenant's records (R8, R12, O1, C5).

Entry: `cli.tenant.main(["check", id])` as a production process (database from `DEFENDER_DATABASE_DSN`, Postgres-gated),
tenants registered over the committed fixture (every system granted) with the records each case seeds (`records=`, no
judgement: a record an upgrade made unusable is stored as it was); credentials in the operator's KV stand-in. A finding
is read as the lines `check` prints for the case that the same tenant with sound records does not (the control), with
tenant ids normalised, so wording is pinned only where the design words it.
"""
from __future__ import annotations

import contextlib

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant, second_tenant

pytestmark = pytest.mark.postgres


@pytest.fixture
def op(tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811 — the imported fixture
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    with published_tenant(tmp_path / "forge", root=data_root, files=R.import_files()) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=t.data_root, records=None)
        yield R.Operator(t.tenant_id, migrated_database, tmp_path / "op", capsys)


@pytest.fixture
def tenants(tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811 — the imported fixture
    """`make(records, files=None)` -> an `Operator` for a new registered tenant (at most two per test), seeded with
    `records` (a `RecordsSpec`, default the fixture's); the tenant's repo is the committed fixture plus `files`."""
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    stack, made = contextlib.ExitStack(), []

    def make(records=None, files=None):
        records = R.fixture_records() if records is None else records
        n = len(made)
        t = (stack.enter_context(published_tenant(tmp_path / "forge", root=data_root, files=files)) if not made
             else stack.enter_context(second_tenant(made[0], files=files if files is not None else {})))
        register_tenant(migrated_database, t.tenant_id, data_root=t.data_root, records=records)
        made.append(t)
        return R.Operator(t.tenant_id, migrated_database, tmp_path / f"op{n}", capsys)

    with stack:
        yield make


def _findings(op) -> list[str]:
    """`check`'s lines with the tenant's id masked, so two tenants' outputs compare."""
    _, out = op.check()
    return [line.replace(op.tid, "<tenant>") for line in out.splitlines()]


def _only_in(found: list[str], control: list[str], *words: str) -> list[str]:
    return [line for line in found if line not in control and all(w in line for w in words)]


def test_1366_r8_check_refuses_a_tenant_not_yet_imported_naming_the_import(op):
    """`check` before the import names `tenant.py import`; after it, that finding is gone. (#1366 R8)"""
    _, before = op.check()
    assert R.lines_naming(before, R.AUTHOR[R.IMPORT]), before

    assert op.import_()[0] == 0
    _, after = op.check()
    assert not R.lines_naming(after, R.AUTHOR[R.IMPORT]), after


def test_1366_r8_a_not_imported_tenant_has_that_one_finding_and_no_findings_from_its_folders(op):
    """The not-imported tenant's report is the import finding alone: nothing is judged from the retired folders
    (they stand for a full set of systems and a case). (#1366 R8, R12 row 'tenant not imported')"""
    rc, out = op.check()

    assert rc != 0, out
    assert R.lines_naming(out, R.AUTHOR[R.IMPORT]), out
    assert not R.lines_naming(out, "orphan") + R.lines_naming(out, "no credentials"), out


def test_1366_r12_a_grant_on_a_system_that_was_never_recorded_is_reported_as_orphaned(tenants):
    """cmdb is granted (the fixture grants every system) but the tenant never had a record for it: `check` reports an
    orphaned grant naming cmdb that the sound tenant does not get. (#1366 R12, O1)"""
    sound = _findings(tenants())

    found = _findings(tenants(R.without(R.fixture_records(), "cmdb")))

    assert _only_in(found, sound, "cmdb", "orphan"), found


def test_1366_r12_a_deleted_system_the_grants_still_name_is_orphaned_after_the_operator_deleted_it(tenants):
    """The operator's `delete-system cmdb` leaves the grants naming it: `check` then reports the orphaned grant, and did
    not before. (#1366 R12, O5)"""
    op = tenants()
    before = _findings(op)
    assert op.delete_system("cmdb", replaces=1)[0] == 0

    assert _only_in(_findings(op), before, "cmdb", "orphan")


def test_1366_r12_a_disabled_system_that_is_granted_is_reported_as_granted_but_disabled(tenants):
    """cmdb disabled by the operator while granted: `check` reports it as granted but disabled (not as orphaned); the
    tenant with it enabled does not get that line. (#1366 R12, O4 disabled)"""
    op = tenants()
    before = _findings(op)
    config, access = R.FIXTURE_FOLDERS["cmdb"]
    assert op.set_system("cmdb", replaces=1, config=config, access=access, disabled=True)[0] == 0

    found = _findings(op)

    assert _only_in(found, before, "cmdb", "disabled"), found
    assert not _only_in(found, before, "cmdb", "orphan"), found


def test_1366_o1_check_judges_only_the_systems_the_tenant_has_records_for(tenants):
    """The census of `check` covers the tenant's own systems: with a grants table that omits host-state, a tenant that
    records host-state is told its verbs have no disposition, and one that does not record it is told nothing of it. (#1366 O1, R12 row 'ungranted, unrecorded')"""
    from defender.tests.support.tenancy import _tenants1106 as T

    table = {"settings/verb-grants.yaml": T.TABLE_A}
    recorded = _findings(tenants(files=table))
    unrecorded = _findings(tenants(R.without(R.fixture_records(), "host-state", "threat-intel", "change-mgmt", "ticket"),
                                   files=table))

    assert R.lines_naming("\n".join(recorded), "host-state"), recorded
    assert not R.lines_naming("\n".join(unrecorded), "host-state"), unrecorded
    assert not R.lines_naming("\n".join(unrecorded), "orphan", "threat-intel"), "ungranted and unrecorded is silent"


def test_1366_r12_check_reports_a_record_an_upgrade_made_unusable(tenants):
    """cmdb's stored settings carry CHANGE-ME (a rule an upgrade added): `check` reports cmdb, as it does a bad folder
    today; the sound tenant gets no such line. (#1366 R12 row 'invalidated by an upgrade', P2)"""
    sound = _findings(tenants())
    spec = R.edited(R.fixture_records(), "cmdb", settings={"CMDB_TIMEOUT_SEC": "CHANGE-ME"})

    assert _only_in(_findings(tenants(spec)), sound, "cmdb")


def test_1366_r12_check_reports_each_system_without_credentials_at_its_current_generation(tenants):
    """No credentials yet: every system is reported. After credentials for cmdb at its version only cmdb stops being
    reported; after the operator moves cmdb (generation 2) it is reported again. (#1366 R12, O8, P5, A4)"""
    op = tenants()
    config, access = R.FIXTURE_FOLDERS["cmdb"]
    words = ("no credentials at the current generation",)

    first = _findings(op)
    assert {s for s in R.FIXTURE_SYSTEMS if R.lines_naming("\n".join(first), s, *words)} == R.FIXTURE_SYSTEMS

    assert op.set_credentials("cmdb", {"api_key": "k1"}, for_version=1)[0] == 0
    second = _findings(op)
    assert not R.lines_naming("\n".join(second), "cmdb", *words), second
    assert R.lines_naming("\n".join(second), "identity", *words), second

    assert op.set_system("cmdb", replaces=1, config=config, access=R.declaration("http://moved.test"))[0] == 0
    assert R.lines_naming("\n".join(_findings(op)), "cmdb", *words)


def test_1366_o9_check_reports_a_tenant_repos_leftover_system_folders_and_case_file_as_retired_and_ignored(tenants):
    """A repo that still holds `settings/systems/` and `settings/case-record.yaml` is told they are retired and ignored; a
    repo without them is not (the control relies on O9 dropping them from the committed fixture). (#1366 DC8)"""
    clean = "\n".join(_findings(tenants()))
    left = "\n".join(_findings(tenants(files=R.import_files())))

    assert R.lines_naming(left, "retired", "settings/systems"), left
    assert R.lines_naming(left, "retired", "case-record"), left
    assert not R.lines_naming(clean, "retired"), clean


def test_1366_c5_check_reports_a_case_record_whose_system_no_longer_covers_its_comment_route(tenants):
    """The ticket system's stored declaration writes only `POST /tickets/*/transitions`, not the comment route the
    adapter now declares: `check` reports the case record's lost cover naming ticket; the tenant whose declaration covers
    it gets no such line. (#1366 C5, C2)"""
    sound = _findings(tenants())
    lost = R.edited(R.fixture_records(), "ticket",
                    access=R.declaration("http://soc-playground:8004", writes=(("POST", "/tickets/*/transitions"),)))

    found = _only_in(_findings(tenants(lost)), sound, "ticket")

    assert found, "the case system's lost cover was not reported"


def test_1366_o1_the_case_systems_lookup_uses_the_tenants_records_not_the_checkouts_adapters(tenants):
    """The case record names ticket but ticket has no record: `check` reports the case system as not among the tenant's
    systems, though the checkout carries a ticket adapter. (#1366 O1 case-system lookup, O4)"""
    sound = _findings(tenants())

    found = _only_in(_findings(tenants(R.without(R.fixture_records(), "ticket"))), sound, "ticket")

    assert any("case" in line.lower() for line in found), found


def test_1366_check_with_no_database_is_a_fault_naming_the_variable_and_never_a_look_at_the_folders(
        tmp_path, data_root, monkeypatch, capsys):
    """Without `DEFENDER_DATABASE_DSN` `check` fails naming it and prints no finding derived from the tenant's folders
    (which stand for a full set of systems). (#1366 DC8 'check with no database')"""
    from defender.cli import tenant

    monkeypatch.delenv("DEFENDER_DATABASE_DSN", raising=False)
    with published_tenant(tmp_path / "forge", root=data_root, files=R.import_files()) as t:
        rc = tenant.main(["check", t.tenant_id])
    said = capsys.readouterr()

    assert rc != 0
    assert "DEFENDER_DATABASE_DSN" in said.out + said.err
    assert not R.lines_naming(said.out + said.err, "no credentials")
    assert not R.lines_naming(said.out + said.err, "orphan")
