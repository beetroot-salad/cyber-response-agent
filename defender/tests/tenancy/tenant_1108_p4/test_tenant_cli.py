"""#1108 P4 O-SEE: the operator can see a stalled publish. `tenant.py update <id>` publishes
(fetch, fast-forward, export, swap `current`); `tenant.py check <id>` also reports how far
`current` trails `origin/main` and the last publish refusal, whichever trigger met it (`update`,
the launch-time child, a drain's start).

Entry: `defender/cli/tenant.py`'s own `update` (injected forge `client` and `identity`, standing in
for the AppRole login) and `check_tenant` (local state only), whose output is captured, over
`p4_tenant`.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Any

import pytest

from defender.tests.support.jobs._jobs1342 import (
    an_alert,
    job_store,
    register_tenant,
    restate_tenant,
    seed_alert_mapping,
)
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING
from defender.tests.support.tenancy._tenants1106 import ALERT_MAPPING_TEXT
from defender.tests.tenancy.tenant_1108_delivery._identity import VaultHTTP
from defender.tests.tenancy.tenant_1108_p4._support import (
    bind_forge,
    current_commit,
    export_dir,
    git,
    index_entry,
    push_to_remote,
)

LINK_PATH = "agent/lessons/evil.md"


def _cli() -> Any:
    from defender.cli import tenant

    return tenant


def _update(p4: Any, capsys, *, identity: Any = None) -> tuple[int, list[str]]:
    capsys.readouterr()
    with p4.admitted() as admitted:
        rc = _cli().update(admitted, client=p4.forge.client,
                           identity=identity if identity is not None else p4.identity)
    return rc, _said(capsys)


def _check(p4: Any, capsys) -> list[str]:
    capsys.readouterr()
    with p4.admitted() as admitted:
        _cli().check_tenant(admitted)
    return _said(capsys)


def _said(capsys) -> list[str]:
    captured = capsys.readouterr()
    return [line for line in (captured.err + captured.out).splitlines() if line.strip()]


def _new(after: list[str], before: list[str]) -> list[str]:
    return [line for line in after if line not in before]


def _trails_by(lines: list[str], n: int) -> list[str]:
    """Lines reporting a trail of `n` commits: the count as a whole number beside `commit`."""
    return [line for line in lines
            if re.search(rf"(?<![\w.]){n}(?![\w.])", line) and "commit" in line.lower()]


def _sealed_identity(p4: Any) -> Any:
    vault = VaultHTTP(p4.tenant_id)
    vault.status = 503
    vault.body = {"errors": ["Vault is sealed"]}
    return vault.identity()


def test_o_see_tenant_py_has_an_update_command():
    with pytest.raises(SystemExit) as done:
        _cli().main(["update", "--help"])
    assert done.value.code == 0, "tenant.py has no `update` command"


def test_o_see_tenant_py_update_publishes_the_merged_main(p4_tenant, capsys):
    """After a merge on the origin, `current` names the merged commit and its export exists."""
    bind_forge(p4_tenant)
    before = p4_tenant.commit
    merged = p4_tenant.merge({"agent/lessons/merged-by-a-human.md":
                              "---\nname: merged-by-a-human\n---\n\nA reviewed lesson.\n"})
    assert current_commit(p4_tenant.tenant) == before, "positive control: nothing published yet"

    rc, said = _update(p4_tenant, capsys)
    assert rc == 0, said
    assert current_commit(p4_tenant.tenant) == merged, (
        "`tenant.py update` did not publish the merged `main`")
    assert (export_dir(p4_tenant.tenant, merged) / "agent" / "lessons"
            / "merged-by-a-human.md").is_file()


def test_o_see_check_reports_the_trail_and_a_content_refusal_until_a_publish_catches_up(
        p4_tenant, capsys):
    """After two merges whose tip holds a link, `update` refuses visibly and `check` reports
    `current` trailing `origin/main` by 2 commits, naming the refused path. Once a fix is merged
    and published, `check` reports no trail and no longer names the old refusal."""
    bind_forge(p4_tenant)
    published = p4_tenant.commit
    clean = _check(p4_tenant, capsys)
    assert _trails_by(clean, 2) == [], f"positive control: no trail reported yet: {clean}"
    assert not any(LINK_PATH in line for line in clean), f"positive control: {clean}"

    p4_tenant.merge({"agent/lessons/fine.md": "---\nname: fine\n---\n\nFine.\n"})
    push_to_remote(p4_tenant.p3, p4_tenant.scratch,
                   lambda w: index_entry(w, "120000", LINK_PATH, data=b"/etc/passwd"),
                   "a link merged by a human", stage=False)

    rc, said = _update(p4_tenant, capsys)
    assert rc != 0, f"`tenant.py update` published a commit holding a link: {said}"
    assert any(LINK_PATH in line for line in said), (
        f"`tenant.py update`'s refusal does not name the refused path: {said}")
    assert current_commit(p4_tenant.tenant) == published, "the refused publish moved `current`"
    assert git(p4_tenant.clone, "rev-list", "--count",
               f"{published}..refs/remotes/origin/main") == "2", "fixture: the fetch landed"

    stalled = _new(_check(p4_tenant, capsys), clean)
    assert _trails_by(stalled, 2), (
        f"`check` does not report `current` trailing `origin/main` by 2 commits: {stalled}")
    assert any(LINK_PATH in line for line in stalled), (
        f"`check` does not report the last publish refusal (the refused link): {stalled}")

    fixed = p4_tenant.merge({LINK_PATH: None}, "remove the link")
    rc, said = _update(p4_tenant, capsys)
    assert rc == 0, said
    assert current_commit(p4_tenant.tenant) == fixed, said
    caught_up = _check(p4_tenant, capsys)
    for n in (1, 2, 3):
        assert _trails_by(caught_up, n) == [], (
            f"`check` still reports a trail after the publish caught up: {caught_up}")
    assert not any(LINK_PATH in line for line in caught_up), (
        f"`check` still reports the old link refusal after a later publish succeeded: {caught_up}")


def test_o_see_check_reports_an_unprotected_main_refusal(p4_tenant, capsys):
    """The refusal `update` meets is visible in `check` afterwards, as a line `check` did not
    print before it."""
    bind_forge(p4_tenant)
    before = _check(p4_tenant, capsys)

    p4_tenant.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    rc, said = _update(p4_tenant, capsys)
    assert rc != 0, f"`tenant.py update` published with `main` unprotected: {said}"

    after = _new(_check(p4_tenant, capsys), before)
    assert any("protect" in line.lower() for line in after), (
        f"`check` does not report the unprotected-`main` publish refusal: {after}")


def test_o_see_check_reports_a_sealed_issuer_refusal(p4_tenant, capsys):
    """Publishing stops while the issuer is sealed, and `check` makes it visible: after `update`
    meets the sealed issuer, `check` reports the refusal naming the issuer, as a new line."""
    bind_forge(p4_tenant)
    before = _check(p4_tenant, capsys)
    words = ("issuer", "identity", "vault", "openbao", "sealed")

    rc, said = _update(p4_tenant, capsys, identity=_sealed_identity(p4_tenant))
    assert rc != 0, f"`tenant.py update` published with the issuer sealed: {said}"
    assert current_commit(p4_tenant.tenant) == p4_tenant.commit

    after = _new(_check(p4_tenant, capsys), before)
    assert any(w in line.lower() for line in after for w in words), (
        f"`check` does not report the sealed-issuer publish refusal: {after}")


# ---------------------------------------------------------------------------------------------
# Every publish trigger feeds `check`: the launch-time child and the drain start, not only
# `tenant.py update`.
# ---------------------------------------------------------------------------------------------

def test_o_see_check_names_an_unprotected_main_met_by_the_launch_time_child(
        p4_tenant, tmp_path, capsys):
    """A launch-time publish (the child's in-process entry) that meets an unprotected `main`
    reports `stale:operator`, and `check` afterwards names the refusal."""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    bind_forge(p4_tenant)
    before = _check(p4_tenant, capsys)

    p4_tenant.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    line = B.run_child(p4_tenant)
    assert B.outcome_class(line) == "stale:operator", line

    after = _new(_check(p4_tenant, capsys), before)
    assert any("protect" in entry.lower() for entry in after), (
        f"`check` does not name the refusal the launch-time publish met: {after}")


def test_o_see_check_names_a_merged_link_refused_by_the_launch_time_child(
        p4_tenant, tmp_path, capsys):
    """A launch-time publish refused on content (a merged link) leaves `check` reporting
    the trail of 1 commit and the refused path."""
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    bind_forge(p4_tenant)
    before = _check(p4_tenant, capsys)
    assert _trails_by(before, 1) == [], f"positive control: {before}"

    push_to_remote(p4_tenant.p3, p4_tenant.scratch,
                   lambda w: index_entry(w, "120000", LINK_PATH, data=b"/etc/passwd"),
                   "a link merged by a human", stage=False)
    line = B.run_child(p4_tenant)
    assert B.outcome_class(line) == "stale:operator", line
    assert current_commit(p4_tenant.tenant) == p4_tenant.commit

    after = _new(_check(p4_tenant, capsys), before)
    assert _trails_by(after, 1), f"`check` reports no trail of 1 commit: {after}"
    assert any(LINK_PATH in entry for entry in after), (
        f"`check` does not name the link the launch-time publish refused: {after}")


def test_o_see_check_names_an_unprotected_main_met_at_drain_start(
        p4_tenant, tmp_path, capsys, monkeypatch):
    """A drain whose start-of-tick publish meets an unprotected `main` refuses, and `check`
    afterwards names that refusal."""
    from defender.tests.support.learning.curation import _spec773 as S
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        LESSON_NAME,
        BoxSpy,
        CuratorTrigger,
        author_drain,
        drain_paths,
        product_repo,
        queue,
    )

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    bind_forge(p4_tenant)
    before = _check(p4_tenant, capsys)

    p4_tenant.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    paths = drain_paths(p4_tenant, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    trigger = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")}))
    rc = author_drain(p4_tenant, paths, trigger=trigger, box=BoxSpy())
    assert rc == 2, f"the drain did not refuse an unprotected `main` (rc={rc})"

    after = _new(_check(p4_tenant, capsys), before)
    assert any("protect" in entry.lower() for entry in after), (
        f"`check` does not name the refusal the drain-start publish met: {after}")


# --- #1345 O6: `tenant.py set-alert-mapping <id> <file>` writes the database's mapping (D3) -----------------
#
# Entry: the CLI's own `main(argv)` with no `directory=`, as a production process: host acceptance and the store
# both come from `DEFENDER_DATABASE_DSN` over a migrated database (Postgres-gated). The tenant is the published
# fixture, registered `active` in the database; it starts with NO mapping unless a case seeds one.

OTHER = str(uuid.UUID(int=0x1345A6))
#: Over `ALERT_BYTES`: `rule.description` is "sketch", `rule.id` "r-1342", `a` "\u00e9".
SIX_FILE = ("signature: rule.id\nevent_time: alert_timestamp\nsummary: rule.description\ncase_key: alert_id\n"
            "title: rule.description\ndescription: rule.id\n")


class _Verb:
    """The fixture tenant on a migrated database, and the verb run against it."""

    def __init__(self, p4: Any, dsn: str, tmp_path: Any, capsys: Any) -> None:
        self.p4, self.dsn, self.tmp, self.capsys = p4, dsn, tmp_path, capsys
        self.tid = p4.tenant_id
        self.written = 0

    def run(self, content: str | bytes, tid: str | None = None) -> tuple[int, str, str]:
        self.written += 1
        file = self.tmp / f"mapping-{self.written}.yaml"
        file.write_bytes(content if isinstance(content, bytes) else content.encode())
        return self.run_file(file, tid)

    def run_file(self, file: Any, tid: str | None = None) -> tuple[int, str, str]:
        self.capsys.readouterr()
        rc = _cli().main(["set-alert-mapping", tid or self.tid, str(file)])
        said = self.capsys.readouterr()
        return rc, said.out, said.err

    def stored(self, tid: str | None = None) -> dict[str, str] | None:
        async def read() -> dict[str, str] | None:
            async with job_store(self.dsn) as store:
                found = await store.get_alert_mapping(tid or self.tid)
            return None if found is None else dict(found.paths)

        return asyncio.run(read())

    def alert(self, ticket: str, tid: str | None = None) -> str:
        async def insert() -> str:
            async with job_store(self.dsn) as store:
                return (await an_alert(store, tid or self.tid, ticket=ticket)).alert_id

        return asyncio.run(insert())

    def display(self, tid: str | None = None) -> list[tuple[Any, Any]]:
        return [tuple(r) for r in execute(self.dsn, "SELECT title, description FROM jobs.alerts WHERE tenant_id = %s "
                                          "ORDER BY vendor_ticket_id", (tid or self.tid,))]

    def mapping_rows(self) -> int:
        return execute(self.dsn, "SELECT count(*) FROM tenancy.alert_mappings")[0][0]


@pytest.fixture
def verb(p4_tenant, migrated_database, tmp_path, capsys, monkeypatch):  # noqa: F811 — the imported fixture
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    register_tenant(migrated_database, p4_tenant.tenant_id, data_root=p4_tenant.data_root, alert_mapping=None)
    return _Verb(p4_tenant, migrated_database, tmp_path, capsys)


def _lines(err: str) -> list[str]:
    return [line for line in err.splitlines() if line.strip()]


@pytest.mark.postgres
def test_1345_o6_the_verb_stores_a_six_entry_file_prints_it_and_re_derives_the_tenants_titles(verb):
    """A valid file becomes the tenant's mapping (created), the stored mapping is printed, and the tenant's alerts
    now read through it. (#1345 O6, D3, O2)"""
    verb.alert("T-1")
    assert verb.display() == [(None, None)], "premise: no mapping, no display"

    rc, out, err = verb.run(SIX_FILE)

    assert (rc, err) == (0, "")
    assert verb.stored() == {k: v for k, v in FIXTURE_ALERT_MAPPING.items()}
    assert verb.display() == [("sketch", "r-1342")]
    # "prints the stored mapping": each entry's name and path on one line (the layout is the code stage's).
    for entry, path in FIXTURE_ALERT_MAPPING.items():
        assert any(entry in line and path in line for line in out.splitlines()), (entry, out)


@pytest.mark.postgres
def test_1345_o6_a_four_entry_file_loads_with_title_and_description_unmapped(verb):
    """Today's four-entry file loads: what the file leaves out is unmapped and the titles go null. (#1345 O6, D3)
    D4's counterpart (the same four entries as an API PUT body are 422) is pinned in the API suite:
    `test_api_stub.py::test_1345_the_mapping_body_names_exactly_the_records_entries_all_required` and the over-the-fake `missing-entry` case (round 1 repair 12; the API half left this test)."""
    seed_alert_mapping(verb.dsn, verb.tid, FIXTURE_ALERT_MAPPING)
    verb.alert("T-1")
    assert verb.display() == [("sketch", "r-1342")], "control: the six-entry mapping derived a title"

    rc, _, err = verb.run(ALERT_MAPPING_TEXT)

    assert (rc, err) == (0, "")
    assert verb.stored() == {"signature": "rule.id", "event_time": "timestamp", "summary": "rule.description",
                             "case_key": "alert_id"}
    assert verb.display() == [(None, None)]


@pytest.mark.postgres
def test_1345_o6_an_empty_mapping_file_is_a_valid_choice_that_unmaps_everything(verb):
    """`{}` is saved as the tenant's mapping (M2), not refused as missing. (#1345 O6, M2)"""
    seed_alert_mapping(verb.dsn, verb.tid, FIXTURE_ALERT_MAPPING)
    verb.alert("T-1")

    rc, _, err = verb.run("{}\n")

    assert (rc, err) == (0, "")
    assert (verb.stored(), verb.display()) == ({}, [(None, None)])


@pytest.mark.postgres
@pytest.mark.parametrize(("content", "names"), [
    ("signature: [unclosed\n", None),                  # not YAML
    ("- signature\n- title\n", None),                  # not a mapping of entries
    ("signature: rule.id\nseverity: rule.level\n", "severity"),  # an entry that is not one of the six: named, as the API does (r5.1 O6)
    ("", None),                                         # empty file: not a YAML mapping (r5.1 O6 file syntax)
    ("  \n\t\n  ", None),                               # whitespace only: likewise
    ("rule.id\n", None),                                # a scalar: likewise
    ("title: rule..description\n", "title"),            # an empty segment
    ("case_key: ' alert_id'\n", "case_key"),            # surrounding whitespace
    ("description: 42\n", "description"),               # not a path
    ("summary: ''\n", "summary"),                       # an empty path
    (b"\xff\xfe\x00 not utf-8", None),
], ids=["not-yaml", "not-a-mapping", "unknown-entry", "empty-file", "whitespace-only-file", "scalar-file", "empty-segment", "whitespace", "not-a-path", "empty-path", "not-utf8"])
def test_1345_o6_a_malformed_file_or_invalid_entry_is_refused_and_writes_nothing(verb, content, names):
    """The refusal is `[tenant.py] ...` on stderr, exit 1, nothing printed as stored; the mapping and the display
    stay as they were (the valid file in the first case is the control). (#1345 O6, M2)"""
    seed_alert_mapping(verb.dsn, verb.tid, FIXTURE_ALERT_MAPPING)
    verb.alert("T-1")
    before = (verb.stored(), verb.display())
    assert before == (dict(FIXTURE_ALERT_MAPPING), [("sketch", "r-1342")])

    rc, out, err = verb.run(content)

    assert (rc, out) == (1, "")
    assert _lines(err), err
    assert all(line.startswith("[tenant.py] ") for line in _lines(err)), err  # no traceback
    if names:
        assert names in err
    assert (verb.stored(), verb.display()) == before


@pytest.mark.postgres
def test_1345_o6_an_entry_given_as_null_in_the_file_is_unmapped_like_one_left_out(verb):
    """`description: null` is stored as unmapped (absent from the stored paths) and the display is re-derived with no
    description, while the mapped `title` still derives; with a path in its place the description derives (control, the six-entry
    test above). (r5.1 O6 file syntax)"""
    seed_alert_mapping(verb.dsn, verb.tid, FIXTURE_ALERT_MAPPING)
    verb.alert("T-1")
    assert verb.display() == [("sketch", "r-1342")], "control: with a path the description derives"

    rc, _, err = verb.run("signature: rule.id\ntitle: rule.description\ndescription: null\ncase_key: ~\n")

    assert (rc, err) == (0, "")
    assert verb.stored() == {"signature": "rule.id", "title": "rule.description"}
    assert verb.display() == [("sketch", None)]


@pytest.mark.postgres
def test_1345_o6_a_missing_file_is_refused_and_writes_nothing(verb):
    """A path that names no file: `[tenant.py] ...`, exit 1, no mapping created. (#1345 O6)"""
    rc, out, err = verb.run_file(verb.tmp / "nowhere.yaml")

    assert (rc, out) == (1, "")
    assert _lines(err), err
    assert all(line.startswith("[tenant.py] ") for line in _lines(err)), err
    assert (verb.stored(), verb.mapping_rows()) == (None, 0)


@pytest.mark.postgres
def test_1345_o6_a_second_run_replaces_whole_like_a_put_and_touches_no_other_tenant(verb):
    """The same outcome as a PUT: the file replaces the mapping whole (an entry it leaves out is gone), every alert of the
    tenant is re-derived, another tenant's mapping and display are untouched. (#1345 O6, M1, O2)"""
    register_tenant(verb.dsn, OTHER, alert_mapping={"title": "a"})
    verb.alert("T-1")
    verb.alert("T-2")
    verb.alert("T-1", OTHER)

    rc, _, err = verb.run("signature: rule.id\ntitle: rule.description\ndescription: rule.id\n")
    assert (rc, err) == (0, "")
    assert verb.display() == [("sketch", "r-1342")] * 2

    rc, _, err = verb.run("title: a\n")

    assert (rc, err) == (0, "")
    assert verb.stored() == {"title": "a"}, "a replace is whole: the earlier entries are gone"
    assert verb.display() == [("\u00e9", None)] * 2
    assert (verb.stored(OTHER), verb.display(OTHER)) == ({"title": "a"}, [("\u00e9", None)])


@pytest.mark.postgres
@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
def test_1345_o6_a_tenant_that_is_not_active_is_refused_by_host_acceptance_and_writes_nothing(verb, state):
    """As `update` and `propose` are: a non-`active` tenant is refused `[tenant.py] ...` naming its state, exit 1; the same tenant active takes the file (control). (#1345 O6, D3)"""
    restate_tenant(verb.dsn, verb.tid, state=state, data_root=verb.p4.data_root)

    rc, out, err = verb.run(SIX_FILE)

    assert (rc, out) == (1, "")
    assert all(line.startswith("[tenant.py] ") for line in _lines(err)), err
    assert state in err, err
    assert verb.mapping_rows() == 0

    restate_tenant(verb.dsn, verb.tid, state="active", data_root=verb.p4.data_root)
    rc, _, err = verb.run(SIX_FILE)
    assert (rc, err) == (0, "")
    assert verb.stored() == dict(FIXTURE_ALERT_MAPPING)


@pytest.mark.postgres
def test_1345_o6_an_unknown_tenant_is_refused_and_writes_nothing(verb):
    """A tenant id the database does not hold: refused at acceptance, no mapping row of any tenant. (#1345 O6, D3)"""
    rc, out, err = verb.run(SIX_FILE, tid=str(uuid.UUID(int=0x1345EE)))

    assert (rc, out) == (1, "")
    assert _lines(err), err
    assert all(line.startswith("[tenant.py] ") for line in _lines(err)), err
    assert verb.mapping_rows() == 0


def test_1345_o6_without_a_database_address_the_verb_is_refused_not_crashed(p4_tenant, tmp_path, capsys, monkeypatch):
    """No `DEFENDER_DATABASE_DSN`: `[tenant.py] ...`, exit 1, no traceback (the verb has no other store). (#1345 O6)"""
    monkeypatch.delenv("DEFENDER_DATABASE_DSN", raising=False)
    file = tmp_path / "m.yaml"
    file.write_text(SIX_FILE, encoding="utf-8")
    capsys.readouterr()

    rc = _cli().main(["set-alert-mapping", p4_tenant.tenant_id, str(file)])

    said = capsys.readouterr()
    assert rc == 1
    assert _lines(said.err), said.err
    assert all(line.startswith("[tenant.py] ") for line in _lines(said.err)), said.err


@pytest.mark.postgres
def test_1345_o6_the_verb_emits_no_alert_mapping_audit_event(verb, caplog):
    """The API's `alert_mapping.update` event is the API's: a verb run emits no audit record (a record carrying an `action`,
    or from an audit logger); the run did store. (#1345 O6, O1; narrowed in round 1 repair 9)"""
    with caplog.at_level(logging.DEBUG):
        rc, _, err = verb.run(SIX_FILE)

    # Control: the replace happened. stderr is not pinned empty: at DEBUG, acceptance's own alembic and asyncio log lines
    # reach it; a refusal would be a `[tenant.py]` line and a non-zero exit.
    assert rc == 0, err
    assert "[tenant.py]" not in err, err
    assert verb.stored() == dict(FIXTURE_ALERT_MAPPING), "control: the replace happened"
    audit = [r for r in caplog.records if hasattr(r, "action") or r.name.rsplit(".", 1)[-1] == "audit"]
    assert [r for r in audit if "alert_mapping" in str(getattr(r, "action", "")) + r.getMessage()] == []
