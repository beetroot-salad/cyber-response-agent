"""#1108 P4 O7: every corpus write goes through `TenantDelivery`. One row per writer, each observed
where it lands: a commit-maker branch and PR on the tenant forge, never the product repo, plus its
rows in the delivery record `<T>/learning/commit-maker.jsonl` (O7-PATH).

The two lesson authors and the curators' corpus repair run through the real `author_drain`, the
lead author, draft synthesis and pitfalls through the real `lead_author_drain`, each with only the
model spawn (and a run's extraction) faked by `_drain_support`. A composed case drives drain ->
human merge -> `revert_lesson.main`; a census shows no production module keeps the legacy commit
and delivery machinery; and `evaluations/harness.py` is tested from here. Revert itself is
`test_revert_cli.py`, connect's tenant half `test_connect_propose.py`.
"""
from __future__ import annotations

import ast
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender._git import REPO_ROOT
from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._support import forge_pulls, merge_on_remote
from defender.tests.tenancy.tenant_1108_p4._support import (
    DEFENDER,
    bind_forge,
    current_commit,
    export_dir,
    git,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LEAD_PREFIX,
    BoxSpy,
    LeadStep,
    PitfallsStep,
    executed_lead,
    lead_author_drain,
    queued_run,
    CuratorTrigger,
    author_drain,
    critical_text,
    drafts_dir,
    drain_paths,
    product_repo,
    product_state,
    queue,
    remote_branches,
    touched,
)

EVALUATIONS = REPO_ROOT / "evaluations"


# ---------------------------------------------------------------------------------------------
# Observations shared by the rows
# ---------------------------------------------------------------------------------------------


def _record_rows(t: Any) -> list[dict]:
    """The commit-maker's delivery record, `<T>/learning/commit-maker.jsonl`, read as plain JSON
    lines: P3 writes one row per commit it made, `{commit, batch:
    {branch, base, start}, lanes, changes: [{path, before, after}]}`. `[]` when absent."""
    record = Path(location_path(t.tenant.learning)) / "commit-maker.jsonl"
    if not record.is_file():
        return []
    return [json.loads(line) for line in record.read_text(encoding="utf-8").splitlines() if line]


def _assert_recorded(t: Any, before: list[dict], branch: str, tip: str, paths: list[str]) -> None:
    """Every commit the tick made on `branch` is a new row of the tenant's delivery
    record (rows recorded before the tick are `before`), its tip among them, and the rows name
    exactly `paths` — the same paths the branch carries."""
    rows = _record_rows(t)
    assert rows[:len(before)] == before, "the delivery record was rewritten, not appended"
    new = rows[len(before):]
    assert new, "the tick's commit is not in the tenant's delivery record"
    assert {r["batch"]["branch"] for r in new} == {branch}, new
    assert tip in {r["commit"] for r in new}, (tip, new)
    assert sorted({c["path"] for r in new for c in r["changes"]}) == sorted(paths), new


def _queue_dir(paths: Any) -> Path:
    """The lead lane's curation queue (`enqueue_curation`'s rows): top level is queued,
    `inflight/` is claimed and not yet consumed."""
    return Path(location_path(paths.state_root)) / "author-queue"


def _queued(paths: Any, case_id: str) -> tuple[bool, bool]:
    """`(at the queue's top, in flight)` for `case_id`'s row."""
    q = _queue_dir(paths)
    return (q / f"{case_id}.json").is_file(), (q / "inflight" / f"{case_id}.json").is_file()


def _shared_inodes(root: Path, other: Path) -> list[str]:
    """Every regular file under `root` whose rel path under `other` names the SAME file (same
    device and inode, a hard link) — `[]` when every pair is a separate file."""
    shared = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        twin = other / path.relative_to(root)
        if twin.is_symlink() or not twin.is_file():
            continue
        a, b = path.lstat(), twin.lstat()
        if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
            shared.append(path.relative_to(root).as_posix())
    return shared


def _paired(root: Path, other: Path) -> list[str]:
    """Rel paths of regular files present under both roots (what `_shared_inodes` compared)."""
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*")
                  if p.is_file() and not p.is_symlink() and (other / p.relative_to(root)).is_file())


# ---------------------------------------------------------------------------------------------
# Behavioural rows: the two corpus authors of the author lane
# ---------------------------------------------------------------------------------------------

_ROWS = {
    # writer: (curator module the drain triggers, queue channel, row, corpus under agent/)
    "lessons-author": ("author", "findings", S.finding_row("f1", run_id="f1"), "lessons"),
    "questioner-author": ("questioner_curator", "questioner_findings",
                          S.world_row("w1", systems=["cmdb"]), "lessons-questioner"),
}


@pytest.mark.parametrize("writer", sorted(_ROWS))
def test_o7_each_author_lane_writer_lands_in_the_tenant_repo_and_nowhere_in_the_product_repo(
        p4_tenant, tmp_path, monkeypatch, caplog, writer):
    """The lesson is one commit on a tenant `lessons/` branch touching only its corpus, with a
    PR; the product checkout is unchanged (positive control: test_drains' flow-4 case)."""
    from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    module, channel, row, corpus = _ROWS[writer]
    t = p4_tenant
    bind_forge(t)
    product = product_repo(tmp_path)
    paths = drain_paths(t, product)
    queue(paths, [row], channel={"findings": FINDINGS, "questioner_findings": QUESTIONER_FINDINGS}[channel])
    before = product_state(product)
    curator = S.FakeCurator(writes={"p4-writer.md": S.lesson(row["finding_id"])})
    trigger, box = CuratorTrigger(**{module: curator}), BoxSpy()
    main = t.origin_main()
    recorded = _record_rows(t)

    rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 0, critical_text(caplog)
    assert curator.calls, f"{writer}'s model step never ran"
    (branch, tip), = remote_branches(t.remote).items()
    assert touched(t.remote, main, tip) == [f"agent/{corpus}/p4-writer.md"]
    assert [c["head"] for c in t.forge.creates] == [branch]
    _assert_recorded(t, recorded, branch, tip, [f"agent/{corpus}/p4-writer.md"])
    assert product_state(product) == before


# ---------------------------------------------------------------------------------------------
# Corpus repair (author lane): an unapproved edit is put back, never committed
# ---------------------------------------------------------------------------------------------

FIXTURE_LESSON = "fixture-owner-before-close.md"


def test_o7_corpus_repair_restores_an_unapproved_edit_from_the_batch_base_and_commits_none_of_it(
        p4_tenant, tmp_path, monkeypatch, caplog):
    """The model writes an approved lesson (citing the queued row) and also rewrites a
    human-written fixture lesson citing nothing from the batch: only the approved lesson is
    committed, and the fixture keeps its base bytes at the branch tip."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    t = p4_tenant
    bind_forge(t)
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    curator = S.FakeCurator(writes={"p4-approved.md": S.lesson("f1"),
                                    FIXTURE_LESSON: "tampered by the model\n"})
    main = t.origin_main()
    recorded = _record_rows(t)

    rc = author_drain(t, paths, trigger=CuratorTrigger(author=curator), box=BoxSpy())

    assert rc == 0, critical_text(caplog)
    (branch, tip), = remote_branches(t.remote).items()
    assert touched(t.remote, main, tip) == ["agent/lessons/p4-approved.md"]
    assert git(t.remote, "rev-parse", f"{tip}:agent/lessons/{FIXTURE_LESSON}") == git(
        t.remote, "rev-parse", f"{main}:agent/lessons/{FIXTURE_LESSON}")
    assert [c["head"] for c in t.forge.creates] == [branch]
    # The repaired fixture is in no recorded change: the record names the approved lesson only.
    _assert_recorded(t, recorded, branch, tip, ["agent/lessons/p4-approved.md"])


# ---------------------------------------------------------------------------------------------
# The lead-author lane over a draft: lead author, draft synthesis, pitfalls, per-claim reset
# ---------------------------------------------------------------------------------------------

TEMPLATE = "gather/queries/cmdb/host-owner.md"
EXECUTION = "cmdb/execution.md"
PITFALLS_ADDON = "agent/skills/gather/defender-sql.pitfalls.md"


@pytest.fixture
def lead_lane(monkeypatch):
    """The lead lane's knobs at their smallest: the pitfalls lane opens at one mistake, the
    system-skill lift never fires."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")


def _lead_paths(t, tmp_path):
    return drain_paths(t, product_repo(tmp_path, adapters=("cmdb",)))


def _commits(remote, base, tip):
    """`[(commit, [paths it touched])]` oldest first, base exclusive."""
    shas = git(remote, "rev-list", "--reverse", f"{base}..{tip}").split()
    return [(sha, sorted(p for p in git(remote, "show", "--no-renames", "--name-only",
                                        "--format=", sha).splitlines() if p)) for sha in shas]


def test_o7_flead_the_lead_author_and_draft_synthesis_land_on_a_lead_author_branch_of_the_tenant(
        p4_tenant, tmp_path, lead_lane, caplog):
    """Serving one queued run, the real lead author mints a catalog draft for its uncatalogued
    query and commits it with the model's template edit on a tenant `lead-author/` branch with
    its PR; the product checkout is unchanged."""
    t = p4_tenant
    bind_forge(t)
    paths = _lead_paths(t, tmp_path)
    product = paths.repo_root
    before = product_state(product)
    run_dir = queued_run(t, paths, "p4-lead-one")
    run = run_dir.name
    step = LeadStep(executed={run: [executed_lead("cmdb.owner-by-tag")]},
                    edits={run: {TEMPLATE: "\nAlso check the asset tag.\n"}})
    main = t.origin_main()
    recorded = _record_rows(t)
    assert _queued(paths, "case-p4-lead-one") == (True, False), "control: the row is seen queued"

    rc = lead_author_drain(t, paths, box=BoxSpy(), run_lead_author=step,
                           run_pitfalls=lambda *_a, **_k: 0)

    assert rc == 0, critical_text(caplog)
    assert step.served == [run]
    (branch, tip), = remote_branches(t.remote, LEAD_PREFIX).items()
    assert remote_branches(t.remote) == {}, "the lead lane used the lessons prefix"
    paths_touched = touched(t.remote, main, tip)
    assert f"agent/skills/{TEMPLATE}" in paths_touched, paths_touched
    drafts = [p for p in paths_touched if p.startswith("agent/skills/gather/queries/cmdb/_draft/")]
    assert len(drafts) == 1, paths_touched
    assert sorted(paths_touched) == sorted([f"agent/skills/{TEMPLATE}", *drafts])
    assert "Also check the asset tag." in git(t.remote, "show", f"{tip}:agent/skills/{TEMPLATE}")
    assert [c["head"] for c in t.forge.creates] == [branch]
    _assert_recorded(t, recorded, branch, tip, paths_touched)
    # The claim is consumed once its commit is real (#952): the row is neither queued nor in
    # flight, and the run is recorded done at that commit.
    assert _queued(paths, "case-p4-lead-one") == (False, False)
    done = run_dir / "lead_author" / "done"
    assert done.is_file(), "the served run was not recorded done"
    assert f"commit: {tip}\n" in done.read_text(encoding="utf-8"), done.read_text(encoding="utf-8")
    assert product_state(product) == before


def test_o7_flead_a_lead_batch_whose_pr_failed_after_its_commit_is_delivered_next_tick_once(
        p4_tenant, tmp_path, lead_lane, caplog):
    """The claim's commit is pushed but the forge refuses the PR: the failure is logged and the
    claim is consumed with its commit (#952). The next tick delivers the retained batch as one
    PR for the same branch and tip, without re-serving the run or committing twice."""
    t = p4_tenant
    bind_forge(t)
    paths = _lead_paths(t, tmp_path)
    run = queued_run(t, paths, "p4-lead-retained").name
    step = LeadStep(executed={run: [executed_lead("cmdb.owner-by-tag")]},
                    edits={run: {TEMPLATE: "\nRetained, then delivered.\n"}})
    main = t.origin_main()
    recorded = _record_rows(t)
    t.forge.fail_create = True

    with caplog.at_level(logging.INFO):
        lead_author_drain(t, paths, box=BoxSpy(), run_lead_author=step,
                          run_pitfalls=lambda *_a, **_k: 0)

    assert step.served == [run], "control: tick 1 served the run"
    assert [r for r in caplog.records if r.levelno >= logging.ERROR], "a failed PR was silent"
    (branch, tip), = remote_branches(t.remote, LEAD_PREFIX).items()
    assert [c["head"] for c in t.forge.creates] == [branch], "control: the create was refused"
    assert t.forge.prs == []
    assert len(_commits(t.remote, main, tip)) == 1
    assert _queued(paths, "case-p4-lead-retained") == (False, False)

    t.forge.fail_create = False
    caplog.clear()
    with caplog.at_level(logging.INFO):
        rc = lead_author_drain(t, paths, box=BoxSpy(), run_lead_author=step,
                               run_pitfalls=lambda *_a, **_k: 0)

    assert rc == 0, critical_text(caplog)
    assert step.served == [run], "the retained run was served again"
    assert remote_branches(t.remote, LEAD_PREFIX) == {branch: tip}, "committed or branched again"
    assert [c["head"] for c in t.forge.creates] == [branch, branch]
    assert [row["head"]["ref"] for row in t.forge.prs if row["state"] == "open"] == [branch]
    _assert_recorded(t, recorded, branch, tip, [p for _sha, f in _commits(t.remote, main, tip)
                                               for p in f])
    assert len(_record_rows(t)) == len(recorded) + 1, "the commit-maker committed twice"
    assert _queued(paths, "case-p4-lead-retained") == (False, False)


def test_o7_flead_a_failed_claim_is_reset_out_of_the_draft_and_never_reaches_a_commit(
        p4_tenant, tmp_path, lead_lane, caplog):
    """Two runs in one tick: the first claim's edit is one commit; the second claim's model
    writes and then fails, so its write is reset out of the draft and the system skill at the
    tip is `main`'s."""
    t = p4_tenant
    bind_forge(t)
    paths = _lead_paths(t, tmp_path)
    good = queued_run(t, paths, "p4-lead-a").name
    bad = queued_run(t, paths, "p4-lead-b").name
    step = LeadStep(executed={good: [executed_lead("cmdb.host-owner")],
                              bad: [executed_lead("cmdb.host-owner", lead_id="l-002")]},
                    edits={good: {TEMPLATE: "\nFirst claim's note.\n"},
                           bad: {EXECUTION: "\nA failed claim's stray write.\n"}},
                    rc={bad: 2})
    main = t.origin_main()

    lead_author_drain(t, paths, box=BoxSpy(), run_lead_author=step,
                      run_pitfalls=lambda *_a, **_k: 0)

    assert sorted(step.served) == sorted([good, bad])
    (branch, tip), = remote_branches(t.remote, LEAD_PREFIX).items()
    commits = _commits(t.remote, main, tip)
    assert [files for _sha, files in commits] == [[f"agent/skills/{TEMPLATE}"]], commits
    assert git(t.remote, "rev-parse", f"{tip}:agent/skills/{EXECUTION}") == git(
        t.remote, "rev-parse", f"{main}:agent/skills/{EXECUTION}")
    assert [c["head"] for c in t.forge.creates] == [branch]


def test_o7_flead_pitfalls_curation_lands_on_the_tenant_add_on_page_only(
        p4_tenant, tmp_path, lead_lane, caplog):
    """A pitfalls-only tick curates the queued reducer mistake into the tenant's add-on page as
    one commit on a `lead-author/` branch with its PR, and never touches the product checkout."""
    from defender.learning.core.state import PITFALLS
    from defender.tests.support.learning.core._declared870 import shim_row

    t = p4_tenant
    bind_forge(t)
    paths = _lead_paths(t, tmp_path)
    product = paths.repo_root
    before = product_state(product)
    queue(paths, [shim_row("p4-run:1")], channel=PITFALLS)
    bullet = "- **Name the unnested column.** An anonymous unnest cannot be grouped."
    step = PitfallsStep(bullet)
    main = t.origin_main()
    recorded = _record_rows(t)

    rc = lead_author_drain(t, paths, box=BoxSpy(), run_pitfalls=step,
                           run_lead_author=lambda *_a, **_k: None)

    assert rc == 0, critical_text(caplog)
    assert [h["path"] for batch in step.handoffs for h in batch] == [PITFALLS_ADDON]
    (branch, tip), = remote_branches(t.remote, LEAD_PREFIX).items()
    assert touched(t.remote, main, tip) == [PITFALLS_ADDON]
    assert bullet in git(t.remote, "show", f"{tip}:{PITFALLS_ADDON}")
    assert [c["head"] for c in t.forge.creates] == [branch]
    _assert_recorded(t, recorded, branch, tip, [PITFALLS_ADDON])
    assert product_state(product) == before


# ---------------------------------------------------------------------------------------------
# O7-PATH composed: drain -> human merge -> revert, on the record the drain wrote
# ---------------------------------------------------------------------------------------------


def test_o7_path_a_drained_lesson_a_human_merged_is_reverted_by_the_cli_on_the_tenant(
        p4_tenant, tmp_path, monkeypatch, caplog, capsys):
    """`revert_lesson.main` reverts the drain's recorded commit once a human merged it: one new
    branch off the merged `main` deleting only the lesson, with its PR. The revert reads the
    delivery record the drain left, so this is the path a writer's record row must serve.
    Control: before the merge the same revert refuses."""
    import importlib

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    t = p4_tenant
    bind_forge(t)
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    lesson_path = "agent/lessons/p4-composed.md"
    curator = S.FakeCurator(writes={"p4-composed.md": S.lesson("f1")})
    recorded = _record_rows(t)
    revert = importlib.import_module("defender.cli.learning.revert_lesson")

    def cli() -> int:
        return revert.main(["--tenant", t.tenant_id, "p4-composed"], client=t.forge.client,
                           identity=t.vault.identity(), directory=t.directory)

    assert author_drain(t, paths, trigger=CuratorTrigger(author=curator), box=BoxSpy()) == 0, \
        critical_text(caplog)
    (branch, tip), = remote_branches(t.remote).items()
    _assert_recorded(t, recorded, branch, tip, [lesson_path])
    assert cli() != 0, "control: an unmerged lesson was reverted"
    merged = merge_on_remote(t.p3, t.scratch, branch)
    before = set(remote_branches(t.remote, prefix=""))
    caplog.clear()

    with caplog.at_level(logging.INFO):
        rc = cli()

    assert rc == 0, critical_text(caplog)
    new = {b: tip for b, tip in remote_branches(t.remote, prefix="").items() if b not in before}
    (revert_branch, revert_tip), = new.items()
    assert touched(t.remote, merged, revert_tip) == [lesson_path]
    assert git(t.remote, "ls-tree", "--name-only", revert_tip, "--", lesson_path) == ""
    assert [row["head"]["ref"] for row in t.forge.prs
            if row["state"] == "open" and row["head"]["ref"] == revert_branch] == [revert_branch]


# ---------------------------------------------------------------------------------------------
# A draft shares no inode with the export it was made from
# ---------------------------------------------------------------------------------------------


def test_f_hardlink_the_comparison_sees_a_hard_linked_pair_and_not_a_copy(tmp_path):
    """Positive control for the next case's observation: a hard link is reported, a copy is
    not, and the pair is compared at all."""
    a, b = tmp_path / "a" / "agent", tmp_path / "b" / "agent"
    (a / "lessons").mkdir(parents=True)
    (b / "lessons").mkdir(parents=True)
    (a / "lessons" / "linked.md").write_text("x\n", encoding="utf-8")
    os.link(a / "lessons" / "linked.md", b / "lessons" / "linked.md")
    (a / "lessons" / "copied.md").write_text("y\n", encoding="utf-8")
    (b / "lessons" / "copied.md").write_text("y\n", encoding="utf-8")
    assert _paired(a, b) == ["lessons/copied.md", "lessons/linked.md"]
    assert _shared_inodes(a, b) == ["lessons/linked.md"]


def test_f_hardlink_a_drafts_files_share_no_inode_with_the_export_while_the_box_runs(
        p4_tenant, tmp_path, monkeypatch, caplog):
    """While the model step runs (the draft mounted writable), no file under the draft's
    `agent/` is the export's own file (device and inode), so a write through the box never
    reaches the export the next run copies. At least one pair is compared."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    t = p4_tenant
    bind_forge(t)
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    seen: list[tuple[str, list[str], list[str]]] = []

    def during_run(*_a: Any) -> None:
        export = export_dir(t.tenant, current_commit(t.tenant)) / "agent"
        for agent in sorted(p for p in drafts_dir(t).rglob("agent")
                            if p.is_dir() and not p.is_symlink()):
            seen.append((str(agent), _paired(agent, export), _shared_inodes(agent, export)))

    curator = S.FakeCurator(writes={"p4-inode.md": S.lesson("f1")}, also=during_run)

    rc = author_drain(t, paths, trigger=CuratorTrigger(author=curator), box=BoxSpy())

    assert rc == 0, critical_text(caplog)
    assert seen, "no draft agent/ was found while the model step ran"
    assert any(paired for _agent, paired, _shared in seen), seen
    assert [(agent, shared) for agent, _paired_, shared in seen if shared] == []


# ---------------------------------------------------------------------------------------------
# Census: no production module keeps the legacy commit/delivery machinery
# ---------------------------------------------------------------------------------------------

#: Names whose any reference in production code is a writer committing or delivering outside
#: P3's commit-maker: the legacy product-repo delivery (`AuthorBranch`, `GhForge`,
#: its revert, the worktree batch) and the per-claim worktree commits (`ClaimGit`, the corpus
#: commit helpers, worktree creation).
LEGACY_REFERENCES = frozenset({
    "AuthorBranch", "GhForge", "ClaimGit", "revert_lesson_pr",
    "_run_worktree_batch", "finish_batch", "commit_corpus", "commit_corpus_paths",
    "git_commit_paths", "git_worktree_add",
})
#: Of those, the classes and the batch whose very definition must be gone.
LEGACY_DEFINITIONS = frozenset({"AuthorBranch", "GhForge", "ClaimGit", "_run_worktree_batch"})


def legacy_hits(source: str, filename: str = "<src>") -> list[tuple[int, str, str]]:
    """`(line, name, how)` for every reference to a `LEGACY_REFERENCES` name (a bare name, an
    attribute, an import) and every definition of a `LEGACY_DEFINITIONS` name in `source`."""
    hits = []
    for node in ast.walk(ast.parse(source, filename)):
        if isinstance(node, ast.Name) and node.id in LEGACY_REFERENCES:
            hits.append((node.lineno, node.id, "ref"))
        elif isinstance(node, ast.Attribute) and node.attr in LEGACY_REFERENCES:
            hits.append((node.lineno, node.attr, "ref"))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            hits += [(node.lineno, a.name.rsplit(".", 1)[-1], "import") for a in node.names
                     if a.name.rsplit(".", 1)[-1] in LEGACY_REFERENCES]
        elif (isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
              and node.name in LEGACY_DEFINITIONS):
            hits.append((node.lineno, node.name, "def"))
    return hits


def _production_sources() -> list[Path]:
    tests = DEFENDER / "tests"
    return sorted([p for p in DEFENDER.rglob("*.py")
                   if not p.is_relative_to(tests) and ".venv" not in p.parts
                   and "__pycache__" not in p.parts]
                  + [p for p in EVALUATIONS.rglob("*.py") if "_tmp" not in p.parts])


def test_o7_census_scanner_finds_each_kind_of_legacy_spelling():
    """Positive control for the census below: an import, a call through `_git`, an attribute
    call and a class definition are each found; the P3 commit-maker's names are not."""
    src = (
        "from defender.learning.author.branch import AuthorBranch\n"   # 1
        "from defender import _git\n"
        "_git.git_commit_paths(root, [], [], 'm')\n"                    # 3
        "branch.finish_batch(batch_id, wt)\n"                           # 4
        "class GhForge:\n    pass\n"                                    # 5
        "batch.commit(change_set, 'm'); delivery.finish(batch)\n"
    )
    assert sorted(legacy_hits(src)) == [(1, "AuthorBranch", "import"),
                                        (3, "git_commit_paths", "ref"),
                                        (4, "finish_batch", "ref"), (5, "GhForge", "def")]


def test_o7_no_production_writer_commits_or_delivers_outside_the_tenant_commit_maker():
    """No definition, import or reference of the legacy machinery remains in production code
    (`defender/` outside `tests/`, and `evaluations/`), so every writer reaches git only
    through P3's `TenantDelivery`."""
    hits = []
    for path in _production_sources():
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        hits += [f"{path.relative_to(REPO_ROOT)}:{line}: {name} ({how})"
                 for line, name, how in legacy_hits(source, str(path))]
    assert hits == [], "legacy commit/delivery machinery remains:\n" + "\n".join(hits)


# ---------------------------------------------------------------------------------------------
# The evals harness: the author against a draft, a fake forge, no issuer, no network
# ---------------------------------------------------------------------------------------------

_HARNESS_RUN = """
import json, socket, sys
from pathlib import Path
evals, scenario, scratch = (Path(a) for a in sys.argv[1:4])
connects = []
def _audit(event, args):
    if event == "socket.connect":
        connects.append(repr(args[1]))
sys.addaudithook(_audit)
# Control: the audit sees a connect (a loopback listener of our own).
probe = socket.socket(); probe.bind(("127.0.0.1", 0)); probe.listen(1)
c = socket.create_connection(probe.getsockname()); c.close(); probe.close()
control = list(connects); connects.clear()
sys.path.insert(0, str(evals))
import harness
from defender.tests.support.learning.curation._spec773 import FakeCurator, lesson
curator = FakeCurator(writes={"harness-lesson.md": lesson("f1")})
harness.materialize(scenario, scratch)
run, _wall = harness.run_author(scratch, invoke_agent=curator)
print(json.dumps({"rc": run.returncode, "stderr": run.stderr, "spawned": len(curator.calls),
                  "control": control, "connects": connects}))
"""


def _repositories(root: Path) -> list[Path]:
    """Every git repository under `root`: a work tree's `.git` and a bare repo's directory."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        if ".git" in dirnames or ".git" in filenames:
            found.append(here)
        elif {"HEAD", "objects", "refs"} <= set(filenames) | set(dirnames):
            found.append(here)
            dirnames.clear()
    return found


def test_o7_the_evals_harness_authors_into_a_tenant_draft_with_a_fake_forge_and_no_issuer(tmp_path):
    """The harness drives the real lessons author against a draft (only the model spawn faked):
    its commit lands on a tenant-shaped repo with exactly one PR on the fake forge, no issuer is
    configured or contacted, and nothing is written under `defender/lessons/` or `.worktrees/`."""
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "findings.jsonl").write_text(
        json.dumps(S.finding_row("f1", run_id="f1")) + "\n", encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "HOME")}
    env.update(PYTHONPATH=str(REPO_ROOT), PYTHONDONTWRITEBYTECODE="1",
               GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="evals", GIT_AUTHOR_EMAIL="e@test.invalid",
               GIT_COMMITTER_NAME="evals", GIT_COMMITTER_EMAIL="e@test.invalid")

    proc = subprocess.run([sys.executable, "-c", _HARNESS_RUN, str(EVALUATIONS), str(scenario),
                           str(scratch)], env=env, capture_output=True, text=True, timeout=300,
                          check=False)

    assert proc.returncode == 0, proc.stderr[-4000:]
    run = json.loads(proc.stdout.strip().splitlines()[-1])
    assert run["rc"] == 0, run
    assert run["spawned"] == 1, run
    # No issuer contacted: the harness process opened no socket at all (its forge is a fake
    # transport, its origin a local repository); control: the same audit saw our own connect.
    assert run["control"], "control: the audit hook saw no connect"
    assert run["connects"] == [], run["connects"]
    # No issuer configured: no issuer client config anywhere the harness wrote, and no
    # issuer/OpenBao variable handed to it.
    assert not [p for p in scratch.rglob("*issuer*")], sorted(scratch.rglob("*issuer*"))
    assert not [k for k in env if "ISSUER" in k or k.startswith(("BAO_", "VAULT_"))]
    # Exactly one PR on the fake forge (P3's remote-backed `ForgeHTTP`, whose PR rows live
    # with the bare remote), for the branch that carries the lesson.
    prs = [row for repo in _repositories(scratch) for row in forge_pulls(repo)]
    assert len(prs) == 1, prs
    head = prs[0]["head"]["ref"]
    landed = [repo for repo in _repositories(scratch)
              if git(repo, "for-each-ref", "--format=%(refname)", f"refs/heads/{head}")]
    assert landed, f"the PR's branch {head} is on no repository"
    assert "agent/lessons/harness-lesson.md" in git(
        landed[0], "show", "--name-only", "--format=", f"refs/heads/{head}").splitlines()
    touched_paths = set()
    for repo in _repositories(scratch):
        if not git(repo, "for-each-ref", "--format=%(refname)"):
            continue  # a repository with no commit yet holds no landing
        log = git(repo, "log", "--all", "--no-renames", "--name-only", "--format=")
        touched_paths |= {line for line in log.splitlines() if line}
    assert "agent/lessons/harness-lesson.md" in touched_paths, sorted(touched_paths)
    assert not [p for p in touched_paths if p.startswith("defender/lessons")], sorted(touched_paths)
    assert not list(scratch.rglob(".worktrees")), "a product-repo worktree was cut"
    assert not (scratch / "defender" / "lessons").exists()
