"""#1108 P4 O-SEE: the operator can see a stalled publish. `tenant.py update <id>` publishes
(fetch, fast-forward, export, swap `current`); `tenant.py check <id>` also reports how far
`current` trails `origin/main` and the last publish refusal, whichever trigger met it (`update`,
the launch-time child, a drain's start).

Entry: `defender/cli/tenant.py`'s own `update` (injected forge `client` and `identity`, standing in
for the AppRole login) and `check_tenant` (local state only), whose output is captured, over
`p4_tenant`.
"""
from __future__ import annotations

import re
import uuid
from typing import Any

import pytest

from defender.tests.support.jobs._jobs1342 import (
    register_tenant,
    seed_alert_mapping,
)
from defender.tests.support.learning.core._store1278 import world  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _records1470 as K
from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING
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


@pytest.mark.postgres
def test_o_see_check_names_an_unprotected_main_met_at_drain_start(world, capsys):  # noqa: F811 — the imported fixture
    """A drain whose start-of-tick publish meets an unprotected `main` refuses, and `check`
    afterwards names that refusal."""
    from defender.tests.support.learning.core._store1278 import LessonWriter, call, finding, lesson_citing
    from defender.tests.tenancy.tenant_1108_p4._drain_support import LESSON_NAME, BoxSpy, author_drain

    t = world.t
    before = _check(t, capsys)

    t.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    call(world.dsn, "publish_findings", t.tenant_id, "run-1", [finding("f1")], kind="finding")  # waiting in the store: one claim
    rc = author_drain(t, world.paths, trigger=LessonWriter({LESSON_NAME: lesson_citing("f1")}), box=BoxSpy())
    assert rc == 2, f"the drain did not refuse an unprotected `main` (rc={rc})"

    after = _new(_check(t, capsys), before)
    assert any("protect" in entry.lower() for entry in after), (
        f"`check` does not name the refusal the drain-start publish met: {after}")


# --- #1345 O4: the readiness check reports a tenant with no alert mapping ------------------------------------------
# (#1470 O1/O10: `set-alert-mapping` is removed; the mapping is written by `PUT /alert-mapping`, tested in
# api/test_1083_port_contract.py. The check's finding is kept, seeding the mapping through the store.)


@pytest.fixture
def unmapped(p4_tenant, migrated_database, monkeypatch):  # noqa: F811 — the imported fixture
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    register_tenant(migrated_database, p4_tenant.tenant_id, data_root=p4_tenant.data_root, alert_mapping=None)
    return p4_tenant.tenant_id, migrated_database


@pytest.mark.postgres
def test_1345_o4_check_reports_a_tenant_with_no_mapping_until_one_is_saved(unmapped, capsys):
    """A tenant with no mapping is refused at every run, so `check` says so in the refusal's own words; a saved mapping
    clears the finding. (#1345 O4)"""
    from defender.records.formats import ALERT_MAPPING_MISSING

    tid, dsn = unmapped
    capsys.readouterr()
    rc = _cli().main(["check", tid])
    said = capsys.readouterr()
    assert rc == 1
    assert ALERT_MAPPING_MISSING in said.out + said.err

    seed_alert_mapping(dsn, tid, FIXTURE_ALERT_MAPPING)
    capsys.readouterr()
    _cli().main(["check", tid])
    said = capsys.readouterr()
    assert ALERT_MAPPING_MISSING not in said.out + said.err


# --- #1470 O10 / O11: the operator's record commands are removed, and nothing shipped names them ---------------------

#: O10's list, shared with the notes test (`_records1470`): the oracle for both tests below.
REMOVED_1470 = K.REMOVED_COMMANDS
KEPT_1470 = frozenset({"check", "update", "propose"})
_HYPHENATED = sorted(c for c in REMOVED_1470 if "-" in c)
#: A removed hyphenated command named anywhere, or a plain-word one named as `tenant.py <word>`.
_NAMES_A_REMOVED_COMMAND = re.compile(
    rf"(?<![\w-])(?:{'|'.join(map(re.escape, _HYPHENATED))})(?![\w-])"
    rf"|tenant\.py[`'\"]?\s+(?:{'|'.join(map(re.escape, sorted(REMOVED_1470 - set(_HYPHENATED))))})(?![\w-])")


def test_1470_o11_the_census_pattern_finds_each_way_a_removed_command_is_named_and_not_the_kept_ones():
    """Control for the census below: it finds each removed command in the forms shipped text names it, and none of the
    kept commands or plain words. (O11)"""
    for command in REMOVED_1470:
        named = [f"run `python3 defender/cli/tenant.py {command} <id>`", f"tenant.py {command}", f"`tenant.py` {command} x"]
        assert all(_NAMES_A_REMOVED_COMMAND.search(line) for line in named[:2]), command
    for command in _HYPHENATED:
        assert _NAMES_A_REMOVED_COMMAND.search(f"use `{command}` then"), command
    for innocent in ("tenant.py check <id>", "tenant.py update", "tenant.py propose x", "the systems list", "set-systems-up",
                     "an import statement", "the catalog of adapters", "tenant.py"):
        assert not _NAMES_A_REMOVED_COMMAND.search(innocent), innocent


def test_1470_o10_each_removed_record_command_is_an_invalid_choice_and_only_the_kept_ones_are_offered(capsys):
    """Each of O10's nine subcommands is refused by argparse as an invalid choice (exit 2, no pointer shim) and is not
    offered in `--help`; `check`, `update` and `propose` still are. (O10, principle 3)"""
    with pytest.raises(SystemExit) as helped:
        _cli().main(["--help"])
    assert helped.value.code == 0
    offered = set(re.search(r"\{([\w,-]+)\}", capsys.readouterr().out).group(1).split(","))  # argparse's choices
    assert offered == KEPT_1470
    for command in sorted(REMOVED_1470):
        with pytest.raises(SystemExit) as refused:
            _cli().main([command, str(uuid.uuid4())])
        assert refused.value.code == 2, command  # noqa: PLR2004 — argparse's usage error
        assert "invalid choice" in capsys.readouterr().err, command


@pytest.mark.parametrize("argv", [["--help"], *([c, "--help"] for c in sorted(KEPT_1470))], ids=lambda a: " ".join(a))
def test_1470_o11_the_commands_help_text_names_no_removed_command(argv, capsys):
    """`tenant.py --help` and each kept command's help name no removed command. (O11)"""
    with pytest.raises(SystemExit) as helped:
        _cli().main(argv)
    assert helped.value.code == 0
    shown = capsys.readouterr().out
    assert len(shown) > 100, "premise: help was printed"  # noqa: PLR2004
    assert [line for line in shown.splitlines() if _NAMES_A_REMOVED_COMMAND.search(line)] == []


_DEFENDER = __import__("pathlib").Path(__file__).resolve().parents[3]
_SHIPPED_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".txt", ".sh", ".toml", ".json"}
_UPGRADE_NOTES = "## Upgrade from before"


def _shipped_lines() -> list[tuple[str, int, str]]:
    """Every line of shipped text under `defender/` (all but the tests, `docs/archive` and dependencies), less the sections an
    `## Upgrade from before` heading opens (to the next `## `): the one place a removed command may be named."""
    found = []
    for path in sorted(_DEFENDER.rglob("*")):
        rel = path.relative_to(_DEFENDER).as_posix()
        if (not path.is_file() or path.is_symlink() or path.suffix not in _SHIPPED_SUFFIXES or rel.startswith("tests/")
                or rel.startswith("docs/archive/")
                or any(part in {".venv", "__pycache__", "node_modules"} for part in path.parts)):
            continue
        in_upgrade_notes = False
        for number, line in enumerate(path.read_text("utf-8", errors="replace").splitlines(), 1):
            if line.startswith("## "):
                in_upgrade_notes = line.startswith(_UPGRADE_NOTES)
            if not in_upgrade_notes:
                found.append((rel, number, line))
    return found


def test_1470_o11_no_shipped_text_outside_the_upgrade_notes_names_a_removed_command():
    """No refusal, skill, doc, help or code text under `defender/` names a removed subcommand, except in an
    `## Upgrade from before` section. (O11)"""
    lines = _shipped_lines()
    assert len({rel for rel, _, _ in lines}) > 200, "premise: the scan reads the shipped tree"  # noqa: PLR2004
    assert {"skills", "docs", "cli", "systems"} <= {rel.split("/")[0] for rel, _, _ in lines}, "premise: skills and docs too"
    naming = [f"{rel}:{n}: {line.strip()[:120]}" for rel, n, line in lines if _NAMES_A_REMOVED_COMMAND.search(line)]
    assert naming == []


def _joined(node: Any) -> str:
    """A string constant as a reader of the code sees it: implicit concatenation is already one constant in the tree; an
    f-string's text parts are joined with `{}` where a value goes."""
    import ast

    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "{}" for v in node.values)
    return node.value


def _read_as_a_reader(rel: str, lines: list[str]) -> list[str]:
    """The texts of one shipped file as a reader sees them, whitespace runs (line breaks included) collapsed: for Python
    each string constant (implicit concatenation joined) and its comments run together; for anything else its prose,
    the lines `_shipped_lines` keeps run together."""
    import ast
    import io
    import tokenize

    def collapse(text: str) -> str:
        return " ".join(text.split())

    source = "\n".join(lines)
    if not rel.endswith(".py"):
        return [collapse(source)]
    tree = ast.parse(source)
    inner = {id(v) for node in ast.walk(tree) if isinstance(node, ast.JoinedStr) for v in node.values}
    texts = [collapse(_joined(node)) for node in ast.walk(tree) if id(node) not in inner and (
        isinstance(node, ast.JoinedStr) or (isinstance(node, ast.Constant) and isinstance(node.value, str)))]
    comments = [t.string.lstrip("#") for t in tokenize.generate_tokens(io.StringIO(source).readline)
                if t.type == tokenize.COMMENT]
    return [*texts, collapse(" ".join(comments))]


def test_1470_o11_no_shipped_text_names_a_removed_command_across_a_wrapped_line_or_a_joined_string():
    """Read as a reader sees it (a string's implicit concatenation joined, prose and comments with line breaks collapsed),
    no shipped text outside the upgrade notes names a removed subcommand. (O11)"""
    wrapped = ["run `python3 defender/cli/tenant.py", "catalog <id>`"]
    joined = ['ERROR = ("the operator runs `tenant.py "', '        "delete-" "system`")']
    assert [_NAMES_A_REMOVED_COMMAND.search(t) is not None for t in _read_as_a_reader("x.md", wrapped)] == [True], "premise"
    assert any(_NAMES_A_REMOVED_COMMAND.search(t) for t in _read_as_a_reader("x.py", joined)), "premise: the join"
    by_file: dict[str, list[str]] = {}
    for rel, _, line in _shipped_lines():
        by_file.setdefault(rel, []).append(line)
    naming = [f"{rel}: ...{found.group(0)}..." for rel, lines in sorted(by_file.items())
              for text in _read_as_a_reader(rel, lines) for found in _NAMES_A_REMOVED_COMMAND.finditer(text)]
    assert naming == []


def test_1470_o11_the_scan_skips_historical_docs_and_reads_the_rest_of_docs():
    """`docs/archive` (historical, not shipped) is not scanned; the rest of `docs/` is. (O11)"""
    files = {rel for rel, _, _ in _shipped_lines()}
    assert not [rel for rel in files if rel.startswith("docs/archive/")]
    assert any(rel.startswith("docs/") for rel in files)


def test_1470_o11_connects_handoff_is_restated_as_the_admins_put_of_each_system():
    """The connect skill's hand-off step names `PUT /systems/{id}` as how a tenant admin enters the folder's settings and
    access, and no operator command. (O11)"""
    text = (_DEFENDER / "skills" / "connect" / "SKILL.md").read_text("utf-8")
    assert re.search(r"PUT\s+/systems/", text), "the hand-off does not name PUT /systems"
