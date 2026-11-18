"""#1537 PR1 (design r3.1, "Data" backfill): a row the code writes carries the cause the migration's frozen backfill gives its own
text, never `unrecorded`, for every transition the code writes with a text of its own.

Each case drives the real transition (the tick for the loop's, the store's verbs for the store's), reads the stored cause and text, then plants
that very text at the revision before the migration, upgrades, and reads what the backfill made of it. The migration's table
is not importable before it exists, so the census of transitions is the case table here. Curator- and gate-written texts are
not pinned (model-written text can never be matched); `unrecorded` is for those and for no transition below.
"""
from __future__ import annotations

from typing import Any

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.migrations.test_1537_causes_migration import _after_ticket_write, _batch, _item, _tenant
from defender.tests.support.learning.core._feedback1278 import FeedbackCurator, make_scene, opened, reviewer_removes_citation, tick
from defender.tests.support.learning.core._store1278 import ONE, call, lapse_lease, lesson_citing, store_mod
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._postgres1339 import empty_database, execute, migrated_database  # noqa: F401 — fixtures
from defender.tests.tenancy.tenant_1108_delivery._support import close_on_remote, merge_on_remote, pr_row
from defender.tests.tenancy.tenant_1108_p4._drain_support import LESSON_NAME, drafts_dir, remote_branches
from defender.tests.tenancy.tenant_1108_p4._support import git

pytestmark = pytest.mark.postgres

AUTHOR = "author"


def _files(*ids: str) -> dict[str, str]:
    return {f"lessons/{LESSON_NAME}": lesson_citing(*ids)}


# --- the loop's transitions (a real tick) -----------------------------------------------------------------------------


def _closed_without_feedback(w, caplog, tmp_path):
    w.seed("f1")
    _id, branch, _n = opened(w, FeedbackCurator(_files("f1")), caplog)
    close_on_remote(w.t.p3, branch)
    tick(w, FeedbackCurator())
    return "item", "f1", "held"


def _cut_from_merge(w, caplog, tmp_path):
    w.seed("f1", "f2")
    _id, branch, _n = opened(w, FeedbackCurator(_files("f1", "f2")), caplog)
    merge_on_remote(w.t.p3, w.scratch, branch, edit=reviewer_removes_citation(LESSON_NAME, lesson_citing("f1")))
    tick(w, FeedbackCurator())
    return "item", "f2", "held"


def _foreign_pr(w, caplog, tmp_path):
    w.seed("f1")
    w.t.forge.add_pr(pr_row(77, "lessons/hand-made"))
    tick(w, FeedbackCurator(_files("f1")))
    return "batch", None, "needs_person"


def _stranded(w) -> tuple[Any, str]:
    """A tick whose push succeeded and whose PR open failed: the batch working, its branch on the forge."""
    w.seed("f1")
    w.t.forge.fail_create = True
    writer = FeedbackCurator(_files("f1"))
    tick(w, writer)
    w.t.forge.fail_create = False
    [(branch, _tip)] = remote_branches(w.t.remote).items()
    [batch_id] = w.batch_rows()
    lapse_lease(w.dsn, batch_id)
    return writer, branch


def _foreign_commits_remote(w, caplog, tmp_path):
    from defender.tests.support.learning.core._store1278 import foreign_commit_on, forget_local_branch

    writer, branch = _stranded(w)
    foreign_commit_on(w.t.remote, branch, w.scratch)
    forget_local_branch(w.t.clone, branch, drafts=drafts_dir(w.t))
    tick(w, writer)
    return "batch", None, "needs_person"


def _foreign_commits_local(w, caplog, tmp_path):
    writer, branch = _stranded(w)
    git(w.t.remote, "branch", "-D", branch)
    # a commit on the local branch that the commit-maker did not make, made with plumbing so no worktree is needed
    foreign = git(w.t.clone, "-c", "user.name=x", "-c", "user.email=x@y.z", "commit-tree", f"{branch}^{{tree}}", "-p", branch, "-m", "by hand")
    git(w.t.clone, "update-ref", f"refs/heads/{branch}", foreign.strip())
    tick(w, writer)
    return "batch", None, "needs_person"


# --- the store's transitions (its own verbs) --------------------------------------------------------------------------


def _publish(w) -> None:
    from defender.tests.support.learning.core._store1278 import finding

    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", [finding("f1")], kind="finding")


def _claim(w):
    return call(w.dsn, "claim", w.t.tenant_id, AUTHOR, owner="host-a", thresholds=ONE)


def _ended_by_count(w, outcome_name: str) -> tuple[str, str, str]:
    """`f1` offered and declined (or deferred) until the store retires it."""
    _publish(w)
    for _ in range(30):
        held = _claim(w)
        if held is None:
            break
        call(w.dsn, "end_no_commits", held, {("finding", "f1"): getattr(store_mod().Outcome, outcome_name)()})
    return "item", "f1", "dead"


def _declined_ceiling(w, caplog, tmp_path):
    return _ended_by_count(w, "declined")


def _deferral_ceiling(w, caplog, tmp_path):
    return _ended_by_count(w, "deferred")


def _replacements(w, *, then_nothing: bool = False) -> None:
    _publish(w)
    held = _claim(w)
    call(w.dsn, "in_review", held, 7, {})
    for generation in range(10):
        assert call(w.dsn, "end_review", w.t.tenant_id, held.batch_id, expect_phase="in_review", outcome="closed", published=[], held=[])
        held = _claim(w)
        if held is None:
            return
        if then_nothing:
            call(w.dsn, "end_no_commits", held, {})
            return
        call(w.dsn, "in_review", held, 8 + generation, {})


def _replacement_ceiling(w, caplog, tmp_path):
    _replacements(w)
    return "item", "f1", "held"


def _replacement_committed_nothing(w, caplog, tmp_path):
    _replacements(w, then_nothing=True)
    return "item", "f1", "held"


#: (the transition, how to drive it, the cause the code must write): the cause is the design's own name for it.
CASES = {
    "foreign_pr": (_foreign_pr, "foreign_pr"),
    "foreign_commits_remote": (_foreign_commits_remote, "foreign_commits_remote"),
    "foreign_commits_local": (_foreign_commits_local, "foreign_commits_local"),
    "closed_without_feedback": (_closed_without_feedback, "closed_without_feedback"),
    "cut_from_merge": (_cut_from_merge, "cut_from_merge"),
    "replacement_ceiling": (_replacement_ceiling, "replacement_ceiling"),
    "replacement_committed_nothing": (_replacement_committed_nothing, "replacement_committed_nothing"),
    "declined_ceiling": (_declined_ceiling, "declined_ceiling"),
    "deferral_ceiling": (_deferral_ceiling, "deferral_ceiling"),
}


@pytest.mark.parametrize("name", list(CASES))
def test_pr1_a_row_the_code_writes_has_the_cause_the_backfill_gives_its_own_text_and_never_unrecorded(
        name, p4_tenant, migrated_database, empty_database, monkeypatch, tmp_path, caplog):  # noqa: F811 — fixtures
    """Each transition's row carries a cause equal to what the frozen backfill makes of the very text the code stored with it, and not `unrecorded`. (PR1, Data backfill)"""
    w = make_scene(p4_tenant, migrated_database, tmp_path, monkeypatch)
    w.t.forge.scopes = {"write:repository", "write:issue", "read:issue"}  # a closed PR's comments are readable
    drive, cause = CASES[name]
    table, key, state = drive(w, caplog, tmp_path)
    if table == "item":
        [(status, got, reason)] = execute(w.dsn, "SELECT status, cause, reason FROM learning.work_items WHERE tenant_id = %s AND item_key = %s",
                                          (w.t.tenant_id, key))
    else:
        [(status, got, reason)] = execute(w.dsn, "SELECT phase, cause, reason FROM learning.batches WHERE tenant_id = %s", (w.t.tenant_id,))
    assert (status, got) == (state, cause), (reason,)
    assert reason, "the transition stored a text"

    old = empty_database
    _upgrade_to(old, revisions.down_of(_after_ticket_write()))
    _tenant(old)
    if table == "item":
        _item(old, "planted", status, reason)
    batch = _batch(old, kind="revert", lane="author", phase="needs_person", reason=reason) if table == "batch" else None
    _upgrade_to(old, _after_ticket_write())
    if table == "item":
        [(backfilled,)] = execute(old, "SELECT cause FROM learning.work_items WHERE item_key = 'planted'")
    else:
        [(backfilled,)] = execute(old, "SELECT cause FROM learning.batches WHERE id = %s", (batch,))
    assert backfilled == got, f"the backfill of {reason!r} is {backfilled!r}, the code wrote {got!r}"
    assert backfilled != "unrecorded"


@pytest.mark.parametrize("name", ["foreign_pr", "foreign_commits_remote", "foreign_commits_local"])
def test_o5_a_batch_the_loop_parks_for_a_foreign_cause_records_when_not_before_it_was_created(
        name, p4_tenant, migrated_database, monkeypatch, tmp_path, caplog):  # noqa: F811 — fixtures
    """The real tick's park (the store's `needs_person`) for a foreign PR, foreign commits on the remote or foreign commits on the local branch sets `parked_at`, and not earlier than the batch's `created_at`. (O5)"""
    w = make_scene(p4_tenant, migrated_database, tmp_path, monkeypatch)
    drive, cause = CASES[name]
    drive(w, caplog, tmp_path)
    [(phase, got, parked_at, created_at)] = execute(
        w.dsn, "SELECT phase, cause, parked_at, created_at FROM learning.batches WHERE tenant_id = %s", (w.t.tenant_id,))
    assert (phase, got) == ("needs_person", cause)
    assert parked_at is not None, "a batch parked by the loop shows no time"
    assert parked_at >= created_at
