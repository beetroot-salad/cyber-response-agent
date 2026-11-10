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
import yaml

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1108_p4._support import FIXTURE, published_tenant, second_tenant

pytestmark = pytest.mark.postgres

#: A catalog adapter an upgrade removed (a record can still name it: the accept-all seeder stores what it is given).
RETIRED = "legacy-widget"
COMMENT_ROUTE = ("POST", "/tickets/*/comments")
#: A grants table whose gather grant is on the platform-served registry alone (nothing for a record to be missing).
TABLE_TACIT_ONLY = "dispositions:\n  tacit-knowledge:\n    health-check: {roles: [gather]}\n    lookup: {roles: [gather]}\n"


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


class _Lines(list):
    """`check`'s lines with the tenant's id masked (so two tenants' outputs compare); `.rc` is its exit status."""

    rc: int = 0


def _fields_for(access: str) -> dict[str, str]:
    """A credential set shaped for the declaration's scheme (basic: username and password; the rest: an api key).
    The access text is YAML (the fixture's files are commented YAML, not JSON); an empty or unreadable text takes the
    default shape."""
    try:
        scheme = ((yaml.safe_load(access) or {}).get("auth") or {}).get("scheme")
    except yaml.YAMLError:
        scheme = None
    return {"username": "u", "password": "p"} if scheme == "basic" else {"api_key": "k"}


def _credentialed(op) -> None:
    """Credentials at the current generation (1) for every fixture system, through the operator's own door."""
    for system, (_, access) in R.FIXTURE_FOLDERS.items():
        assert op.set_credentials(system, _fields_for(access), for_version=1)[0] == 0, system


def _stocked(op) -> None:
    """A credential set at the CURRENT generation of every system the tenant has a record for (disabled ones too), put
    in the operator's KV stand-in under the path the design names (`<tenant>/<system>/g<N>`), so that "no credentials at
    the current generation" cannot be the reason a `check` exits nonzero. A seeding step, like the records: it does not
    go through `set-credentials`, whose own refusals are not this file's subject."""
    for system, record in op.current().items():
        path = f"{op.tid}/{system}/g{record.credential_generation}"
        if path not in op.kv.held:
            op.kv.held[path] = [R.credential_set(_fields_for(record.access))]


def _findings(op, *, credentials: bool = True) -> _Lines:
    """`check`'s lines. Credentials are stocked first (`_stocked`) unless `credentials=False`: a test about another
    finding must not owe its nonzero exit to the credentials finding (`_exits_for_its_own_finding` asserts it did not)."""
    if credentials:
        _stocked(op)
    rc, out = op.check()
    lines = _Lines(line.replace(op.tid, "<tenant>") for line in out.splitlines())
    lines.rc = rc
    return lines


def _exits_for_its_own_finding(found: _Lines) -> None:
    """The exit is nonzero and the credentials finding is not the cause (each test asserts its own finding's words)."""
    assert found.rc != 0, "any finding exits nonzero"
    assert not R.lines_naming("\n".join(found), "no credentials"), found


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
    _exits_for_its_own_finding(found)


def test_1366_r12_a_deleted_system_the_grants_still_name_is_orphaned_after_the_operator_deleted_it(tenants):
    """The operator's `delete-system cmdb` leaves the grants naming it: `check` then reports the orphaned grant, and did
    not before. (#1366 R12, O5)"""
    op = tenants()
    before = _findings(op)
    assert op.delete_system("cmdb", replaces=1)[0] == 0

    found = _findings(op)
    assert _only_in(found, before, "cmdb", "orphan")
    _exits_for_its_own_finding(found)


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
    _exits_for_its_own_finding(found)


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

    found = _findings(tenants(spec))
    assert _only_in(found, sound, "cmdb")
    _exits_for_its_own_finding(found)


def test_1366_r12_check_reports_each_system_without_credentials_at_its_current_generation(tenants):
    """No credentials yet: every system is reported. After credentials for cmdb at its version only cmdb stops being
    reported; after the operator moves cmdb (generation 2) it is reported again. (#1366 R12, O8, P5, A4)"""
    op = tenants()
    config, access = R.FIXTURE_FOLDERS["cmdb"]
    words = ("no credentials at the current generation",)

    first = _findings(op, credentials=False)
    assert first.rc != 0, "no credentials at the current generation is a finding, and any finding exits nonzero"
    assert {s for s in R.FIXTURE_SYSTEMS if R.lines_naming("\n".join(first), s, *words)} == R.FIXTURE_SYSTEMS

    assert op.set_credentials("cmdb", {"api_key": "k1"}, for_version=1)[0] == 0
    second = _findings(op, credentials=False)
    assert not R.lines_naming("\n".join(second), "cmdb", *words), second
    assert R.lines_naming("\n".join(second), "identity", *words), second

    assert op.set_system("cmdb", replaces=1, config=config, access=R.declaration("http://moved.test"))[0] == 0
    assert R.lines_naming("\n".join(_findings(op, credentials=False)), "cmdb", *words)


def test_1366_b6_no_credentials_at_the_current_generation_is_the_only_finding_that_fails_a_sound_tenant(tenants):
    """The one test where "no credentials" is the whole reason for the exit: the sound tenant exits nonzero with a
    "no credentials at the current generation" line for each system and no other kind of finding; the same tenant with
    a set at each system's generation exits zero. (#1366 B6, R12 'no credentials', orchestrator bullet)"""
    op = tenants()
    bare = _findings(op, credentials=False)

    assert bare.rc != 0, bare
    assert {s for s in R.FIXTURE_SYSTEMS if R.lines_naming("\n".join(bare), s, "no credentials at the current generation")} \
        == R.FIXTURE_SYSTEMS, bare
    others = ("orphan", "disabled", "retired", "not among", "cover")
    assert not [line for line in bare if any(w in line for w in others)], bare

    assert _findings(op).rc == 0


def test_1366_o9_check_reports_a_tenant_repos_leftover_system_folders_and_case_file_as_retired_and_ignored(tenants):
    """A repo that still holds `settings/systems/` and `settings/case-record.yaml` is told they are retired and ignored,
    and `check` exits nonzero until they are removed (design: a leftover reported by `check`, either form, is a
    finding); a repo without them is told nothing of it and, with credentials, exits zero (the control relies on O9
    dropping them from the committed fixture). (#1366 DC8, P1, X5)"""
    clean = _findings(tenants())
    left = _findings(tenants(files=R.import_files()))

    assert R.lines_naming("\n".join(left), "retired", "settings/systems"), left
    assert R.lines_naming("\n".join(left), "retired", "case-record"), left
    assert not R.lines_naming("\n".join(clean), "retired"), clean
    _exits_for_its_own_finding(left)
    assert clean.rc == 0, clean


@pytest.mark.parametrize(("reads", "writes"), [
    pytest.param((), (("POST", "/tickets/*/transitions"),), id="write-route-missing"),
    pytest.param((COMMENT_ROUTE,), (COMMENT_ROUTE,), id="read-route-matches-the-comment-route"),
    pytest.param((("POST", "/tickets/ABC-1/comments"),), (COMMENT_ROUTE,), id="read-route-literal-matches-the-comment-route"),
])
def test_1366_c5_check_reports_a_case_record_whose_system_no_longer_covers_its_comment_route(tenants, reads, writes):
    """The ticket system's stored declaration writes only `POST /tickets/*/transitions`, or lists a read route that
    matches the comment route (the r5 ruling: refused even with a covering write): `check` reports the case record's lost
    cover naming ticket and exits nonzero; the tenant whose declaration covers it gets no such line. (#1366 C5, C2, B2)"""
    sound = _findings(tenants())
    lost = R.edited(R.fixture_records(), "ticket",
                    access=R.declaration("http://soc-playground:8004", reads=reads, writes=writes))

    found = _findings(tenants(lost))

    assert _only_in(found, sound, "ticket"), "the case system's lost cover was not reported"
    _exits_for_its_own_finding(found)


def test_1366_o1_the_case_systems_lookup_uses_the_tenants_records_not_the_checkouts_adapters(tenants):
    """The case record names ticket but ticket has no record: `check` reports the case system as not among the tenant's
    systems, though the checkout carries a ticket adapter. (#1366 O1 case-system lookup, O4)"""
    sound = _findings(tenants())

    report = _findings(tenants(R.without(R.fixture_records(), "ticket")))
    found = _only_in(report, sound, "ticket")

    assert any("case" in line.lower() for line in found), found
    _exits_for_its_own_finding(report)


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


def test_1366_r12_check_reports_a_record_naming_an_adapter_an_upgrade_removed(tenants):
    """The tenant holds a record for `legacy-widget`, a catalog-backed record (system id == adapter id) for an adapter the
    catalog no longer has (stored as it was): `check` reports it naming `legacy-widget`, exits nonzero, and the sound
    tenant gets no such line; no pruned checkout is needed. (#1366 R12 row 'adapter removed by an upgrade', B3)"""
    sound = _findings(tenants())

    found = _findings(tenants(R.added(R.fixture_records(), RETIRED)))

    assert _only_in(found, sound, RETIRED), found
    _exits_for_its_own_finding(found)


def test_1366_r8_a_tenant_imported_with_no_records_is_not_told_to_import(tenants):
    """Imported with zero records is not `not imported`: `check` never names the import for it. Granting the catalog
    systems it has no record for, it reports each orphaned grant (proof the records were read, not skipped); granting the
    platform-served registry alone it reports no orphan at all. (#1366 R8 second half, R11, R12)"""
    granted = _findings(tenants(R.RecordsSpec()))
    tacit = _findings(tenants(R.RecordsSpec(), files={"settings/verb-grants.yaml": TABLE_TACIT_ONLY}))

    for report in (granted, tacit):
        assert not R.lines_naming("\n".join(report), R.AUTHOR[R.IMPORT]), report
    assert {s for s in ("cmdb", "elastic") if R.lines_naming("\n".join(granted), s, "orphan")} == {"cmdb", "elastic"}, granted
    _exits_for_its_own_finding(granted)
    assert not R.lines_naming("\n".join(tacit), "orphan"), tacit


def test_1366_r13_a_fresh_import_fails_check_for_want_of_credentials_until_each_system_has_them(op):
    """After `import` (which touches no secret) every system has no credentials at the current generation: `check`
    reports each and exits nonzero; once every system has its credentials at that generation the line is gone. (This
    tenant's repo still holds the retired folders, so its exit stays nonzero for that reason; the zero exit is the next
    test's.) (#1366 R13, R12, B6)"""
    assert op.import_()[0] == 0
    rc, out = op.check()

    assert rc != 0, out
    assert {s for s in R.FIXTURE_SYSTEMS if R.lines_naming(out, s, "no credentials at the current generation")} == R.FIXTURE_SYSTEMS, out

    _credentialed(op)
    _, out = op.check()
    assert not R.lines_naming(out, "no credentials"), out


def test_1366_b6_check_exits_zero_over_a_sound_tenant_with_credentials_and_nonzero_once_a_finding_exists(tenants):
    """The sound tenant (every system recorded and credentialed at its generation) exits zero; the operator's
    `delete-system cmdb` (the grants then name an orphan) turns the same tenant's exit nonzero. (#1366 B6, R12)"""
    op = tenants()
    _credentialed(op)

    assert _findings(op).rc == 0

    assert op.delete_system("cmdb", replaces=1)[0] == 0
    assert _findings(op).rc != 0


def _grants_without_ticket_held() -> str:
    """The fixture's grants table with every `ticket` verb granted to nobody (the case system is then held by no role)."""
    doc = yaml.safe_load((FIXTURE / "settings" / "verb-grants.yaml").read_text(encoding="utf-8"))
    doc["dispositions"]["ticket"] = {
        verb: {"roles": [], "reason": "a case system; no agent reads it"} for verb in doc["dispositions"]["ticket"]}
    return yaml.safe_dump(doc, sort_keys=False)


def test_1366_r1_an_ungranted_case_system_with_unusable_settings_is_a_finding_naming_its_settings(tenants):
    """The settings judgement runs on the case system though no role holds it: ticket (the case system, granted to
    nobody) with empty stored settings is reported naming `system ticket settings`, not a file; the same tenant with
    sound settings gets no such line. Moved from `case_comment_1359/test_case_comment_tenant_check.py::test_r1_an_ungranted_
    case_system_with_bad_settings` (#1366 O9: a bad `config.env` file cannot reach a check; DC6: the record is the locator)."""
    files = {"settings/verb-grants.yaml": _grants_without_ticket_held()}
    sound = _findings(tenants(files=files))

    found = _findings(tenants(R.edited(R.fixture_records(), "ticket", settings={}), files=files))

    assert _only_in(found, sound, "system ticket settings"), found
    _exits_for_its_own_finding(found)
    assert not R.lines_naming("\n".join(found), "config.env"), found


def test_1366_c5_check_reports_a_case_record_naming_a_system_whose_adapter_offers_no_comment_action(tenants):
    """A stored case record naming cmdb (whose adapter has no comment route; an upgrade can remove one): `check` reports
    it naming the case record and cmdb, exits nonzero; the tenant whose case system is ticket gets no such line. Moved
    from `test_case_comment_tenant_check.py::test_r1_a_case_system_that_exports_no_comment_action...` (#1366 O4, C5, O9)."""
    sound = _findings(tenants())

    found = _findings(tenants(R.RecordsSpec(R.fixture_records().systems, R.CaseSpec("cmdb"))))

    assert [line for line in found if line not in sound and "cmdb" in line and "case" in line.lower()], found
    _exits_for_its_own_finding(found)


def test_1366_r1_a_settings_fault_that_tells_the_operator_the_base_is_in_the_access_is_located_at_the_settings(tenants):
    """ticket's stored settings carry a `TICKET_URL_BASE` key (its text says the base lives in the access declaration):
    the finding is located `system ticket settings`, never `system ticket access`. Moved from
    `test_case_comment_tenant_check.py::test_r1_a_config_env_fault_that_mentions_access_yaml_names_config_env`
    (#1366 DC6)."""
    sound = _findings(tenants())
    settings = {**R.FIXTURE_FOLDERS["ticket"][0], "TICKET_URL_BASE": "https://cases.example.test"}

    found = _findings(tenants(R.edited(R.fixture_records(), "ticket", settings=settings)))

    mine = _only_in(found, sound, "system ticket settings", "TICKET_URL_BASE")
    assert mine, found
    # the sentence may mention the access declaration in its body; its LOCATOR (what comes first) is the settings
    for line in mine:
        access = line.find("system ticket access")
        assert access == -1 or line.index("system ticket settings") < access, line
    _exits_for_its_own_finding(found)


def test_1366_o2_a_tenant_with_no_case_record_passes_check(tenants):
    """No case record (the case record is optional, #1359 O2): the tenant whose systems are all recorded and credentialed
    exits zero and `check` names no case finding. Moved from the `check <id>` half of
    `case_comment_1359/test_case_comment_tenant_check.py::test_o2_a_tenant_with_no_case_file_passes_check`. (#1366 O2, R10)"""
    found = _findings(tenants(R.RecordsSpec(R.fixture_records().systems, None)))

    assert found.rc == 0, found
    assert not R.lines_naming("\n".join(found), "case"), found
