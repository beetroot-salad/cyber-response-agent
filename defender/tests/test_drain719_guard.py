"""Issue #719, part 2/5 — the ENUMERATED retire set (decision 8) and what reaches it.

Executable spec, pre-implementation. Rewritten at §7 round 2: decision 8 reversed judge
recommendation A12 ("the ceiling is total"). There is no bare `except Exception` and no
re-raise carve-out. Retirement is reachable only from an enumerated set — `AuthorError`,
`GitError`, `ModelRetry` — and any class outside it stays uncaught, leaving the row queued:
stuck but recoverable and loud, as today.

**Why, because it is the property these tests exist to protect.** A widened guard plus a total
ceiling plus terminal retirement into a graveyard nothing reads composed into a path where any
unnamed exception class permanently deleted a batch of real work every three ticks, with the
only durable record in a file that has no production reader. The accepted trade is that a novel
class returns to unbounded retry instead of silent permanent loss.

**The trap inverted, and this module is where it is caught.** Under decision 6 the hazard was
re-raising `GitError` by reaching for `faults.SYSTEMIC_FAULTS`. Under an allow-list the hazard
is the mirror image and likelier: an implementer writes the obvious `except AuthorError`,
silently drops `GitError` and `ModelRetry`, and reverts decision 1 paths 3 and 4 — with a suite
that only checks *something* retires still green. So membership is asserted PER MEMBER, each
driven through the real primitive: a real `GitError` out of `commit_corpus` with git's own index
lock held, and the `ModelRetry` class PJ1c observed. The `AuthorError` case is invisible here —
it passes under every wrong spelling.

Decision 5 survives as stated (all four channels) but is now a property of the retire SET.
Decision 6's extent half survives and is CONFIRMATORY rather than load-bearing: A11, B5 and D5
are carried by non-membership now, not by where a line sits.

**Scope of the set, because a reader meeting only this file would over-read it.** It governs the
four AUTHOR channels. The pitfalls and lead-author legs keep `run_or_dead_letter`'s own re-raise
set, which this change does not touch and which contains `GitError` — so a commit-time `GitError`
retires here and kills the drain there. One class, two classifications, by channel: deliberate,
carried as the waiver `retirement_classification_differs_across_the_pitfalls_boundary`, and both
halves asserted rather than merely permitted.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from pydantic_ai.exceptions import ModelRetry

import _drain719 as h
from _drain719 import drain  # the not-yet-written target, via the suite's own shim
from defender.learning.author import shared as author_shared  # type: ignore[import-not-found]
from defender.learning.core import faults  # type: ignore[import-not-found]
from defender.learning.core.config import FatalConfigError, StageAbort  # type: ignore[import-not-found]
from defender.runtime.box import BoxFault  # type: ignore[import-not-found]
from defender._git import GitError  # type: ignore[import-not-found]

#: Decision 8's retire set, spelled out here so a test can name a member and a non-member
#: without reading them back off the implementation it is meant to constrain.
#:
#: SCOPE, because a reader meeting only this file would over-read it: the set governs the FOUR
#: AUTHOR CHANNELS. The pitfalls and lead-author legs keep their own mechanism — the re-raise
#: set inside `run_or_dead_letter`, which this change does not touch and which CONTAINS
#: `GitError`. So a commit-time `GitError` retires here and kills the drain there: one class,
#: two classifications, by channel. That asymmetry is deliberate, is carried as the waiver
#: `retirement_classification_differs_across_the_pitfalls_boundary`, and both halves are
#: asserted — the author half below, the pitfalls half in
#: `test_systemic_faults_propagate_without_bumping_attempts`.
MEMBERS = (author_shared.AuthorError, GitError, ModelRetry)
NON_MEMBERS = (StageAbort, FatalConfigError, BoxFault, OSError, RuntimeError, LookupError)


def _instance(cls: type[BaseException], note: str) -> BaseException:
    """Build `cls` the way production raises it.

    `GitError`'s constructor is `(args, returncode, stderr)`, not `(message)` — a
    single-argument call raises `TypeError` in the test's own setup, which silently truncates
    any loop that builds instances lazily and leaves the assertions after it unexecuted. That
    is invisible to reading and to a null-stub pass: the test still collects, still fails
    against a missing target, and looks like every other red. Every caller here therefore goes
    through this factory, and the callers build their instances UP FRONT so a wrong shape is
    one loud failure rather than a quietly shortened loop."""
    if cls is GitError:
        return GitError(["commit", "-m", note], 1, "fatal: unable to write new index file")
    return cls(note)


def _raising_gate(exc: BaseException):
    """A gate that fails. The gate runs outside the clauses that name the retire set, so it is
    the injection point for "raised where nothing is watching for a member"."""

    def gate(batch, cfg):
        raise exc

    return gate


def _wedge_git(repo: Path) -> None:
    """Occupy git's index lock, so the next real `git add`/`git commit` in `repo` fails with a
    real `GitError` — the transient git failure D1/P01 is about, induced through git itself
    rather than imagined."""
    (repo / ".git" / "index.lock").write_text("held by this test\n")


def _unwedge_git(repo: Path) -> None:
    (repo / ".git" / "index.lock").unlink()


def _git_log(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "log", "--oneline"],
        capture_output=True, text=True, check=True,
    ).stdout


# =======================================================================================
# Decision 8 — the trigger is an enumerated set, and A12 is reversed
# =======================================================================================


def test_only_a_named_fault_class_reaches_the_retire_seam(tmp_path: Path):
    """Decision 8 as one property: retirement is reachable from a named class and from nothing
    else. Every member is driven and must retire; every non-member is driven and must leave the
    row queued with no attempt written.

    This REVERSES what stood here before §7 round 2. A green run on the previous body — a plain
    `RuntimeError` reaching the seam — would now be evidence against the resolved design, which
    is why the demand was renamed rather than edited in place: an id whose content is the
    opposite of what it says is a trap for a later reader.

    Both fault lists are constructed BEFORE the first drive. Built lazily inside the loops, a
    constructor whose real shape differs from `cls(message)` — `GitError` takes
    `(args, returncode, stderr)` — raises `TypeError` in setup, and the "and from nothing else"
    half never executes at all while the test still reports as an ordinary pre-implementation
    red. That defect shipped in this file once."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")

    members = [_instance(cls, "member") for cls in MEMBERS]
    non_members = [_instance(cls, "not a member") for cls in NON_MEMBERS]
    assert len(members) == len(MEMBERS)
    assert len(non_members) == len(NON_MEMBERS)

    for i, exc in enumerate(members):
        rid = f"m/{i}"
        h.seed(ch, [h.row_for("actor_observations", rid)])
        cfg = h.cfg_for(
            paths, "actor_observations", max_attempts=1, invoke_agent=h.raising(exc)
        )
        assert drain.run_batch(cfg=cfg) == 2, f"{type(exc).__name__} did not fault the batch"
        assert h.pending(ch) == [], f"{type(exc).__name__} is a member and must retire"
        assert [r["observation_id"] for r in h.graveyard(ch)][-1] == rid

    for i, exc in enumerate(non_members):
        rid = f"n/{i}"
        rows = [h.row_for("actor_observations", rid)]
        h.seed(ch, rows)
        before = len(h.graveyard(ch))
        cfg = h.cfg_for(
            paths, "actor_observations", max_attempts=1, invoke_agent=h.raising(exc)
        )
        with pytest.raises(type(exc)):
            drain.run_batch(cfg=cfg)
        assert h.pending(ch) == rows, f"{type(exc).__name__} must leave the row untouched"
        assert len(h.graveyard(ch)) == before, f"{type(exc).__name__} retired something"


def test_a_failure_in_no_named_class_leaves_the_row_queued_with_its_count_untouched(
    tmp_path: Path,
):
    """A12 REVERSED. The judge's recommendation was that anything not explicitly systemic
    retires — "the ceiling is total". Decision 8 says the opposite, because total plus terminal
    plus a reader-less graveyard deletes real work on a fault class nobody anticipated.

    A `FileNotFoundError` from inside the authoring call is in no named class. It escapes
    uncaught across repeated ticks, the row keeps the count it arrived with, and the queue is
    byte-identical afterwards — unbounded retry, which is the accepted cost of removing the
    permanent-loss path. Stuck but recoverable and loud, as today."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "environment_observations")
    rows = [h.row_for("environment_observations", "b/0", attempts=2)]
    h.seed(ch, rows)
    before = ch.file.read_bytes()
    cfg = h.cfg_for(
        paths,
        "environment_observations",
        max_attempts=3,
        invoke_agent=h.raising(FileNotFoundError("no such prompt file")),
    )

    for _ in range(3):
        with pytest.raises(FileNotFoundError):
            drain.run_batch(cfg=cfg)

    assert ch.file.read_bytes() == before, "an unnamed class must not touch the queue at all"
    assert h.attempts_of(ch, "b/0") == 2, "the count is untouched — not bumped, not reset"
    assert h.graveyard(ch) == []
    assert h.consumed(ch) == []


def test_a_repeatedly_failing_row_that_never_retires_surfaces_a_named_operator_signal(
    tmp_path: Path,
):
    """Decision 10 — the "loud" half of decision 8's trade. Reversing A12 was argued as "stuck
    but recoverable AND LOUD"; the suite pins recoverable, and loud lived only in the rationale.
    A failure mode deliberately chosen OVER permanent loss is the worse of the two if nobody
    notices it, so the row that stays queued has to be visible from outside the process.

    THE ORACLE MUST FAIL WHEN THE SIGNAL IS ABSENT, which is what shapes every assertion here.
    The drain already logs generically on failure, so "a log line was emitted" passes today,
    passes under an implementation with no stuck-row signal at all, and proves nothing. Four
    things are therefore asserted that generic logging cannot satisfy:

    the record names the fault CLASS by name, so an operator can tell a decode error from a
    missing file without reading a traceback; it names the stalled row ids; it CARRIES A COUNT
    that rises tick over tick, which is what turns "this failed" into "this has been stuck for
    three ticks"; and it lands on an observation channel, which has no `held_report` — the
    lessons-local operator report D7 deliberately did not generalise — so the signal cannot be
    satisfied by reusing that surface for one direction only.

    The paired control is the discriminating half in the other direction: a MEMBER fault on the
    same channel retires, and must write NOTHING here. Without it an implementation could emit a
    stuck record on every failure and pass, which would make the signal noise rather than a
    stuck-row signal."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    rows = [h.row_for("actor_observations", "a/0"), h.row_for("actor_observations", "a/1")]
    h.seed(ch, rows)
    cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=3,
        invoke_agent=h.raising(FileNotFoundError("no such prompt file")),
    )

    for tick in (1, 2, 3):
        with pytest.raises(FileNotFoundError):
            drain.run_batch(cfg=cfg)
        records = h.stuck_records(ch)
        assert len(records) == tick, f"tick {tick} produced no stuck-row record"

        latest = records[-1]
        assert latest["fault_class"] == "FileNotFoundError", (
            "the record does not name the fault class, so an operator cannot tell this failure "
            "from any other — a generic 'batch failed' line would satisfy a weaker assertion"
        )
        assert sorted(latest["row_ids"]) == ["a/0", "a/1"], "the stalled rows are not named"
        assert latest["consecutive_ticks"] == tick, (
            "the record carries no rising count, so a row stuck for three ticks is "
            "indistinguishable from one that failed once"
        )

    assert h.pending_by_id(ch).keys() == {"a/0", "a/1"}, "the rows are stuck, as decision 8 wants"
    assert h.graveyard(ch) == []
    assert not (paths.pending_dir / "held_report.log").exists(), (
        "the signal must exist on a channel that has no held_report — D7 keeps that one "
        "lessons-local, so it cannot be the stuck-row surface"
    )

    member = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("a member — this one retires")),
    )
    before = len(h.stuck_records(ch))
    assert drain.run_batch(cfg=member) == 2
    assert len(h.graveyard(ch)) == 2, "the member fault retired the rows"
    assert len(h.stuck_records(ch)) == before, (
        "a fault that RETIRED wrote a stuck-row record — the signal is firing on every failure "
        "rather than on the non-retiring ones, which makes it noise"
    )


def test_the_retire_set_names_author_error_git_error_and_model_retry_and_nothing_else(
    tmp_path: Path,
):
    """The membership oracle, and the one place the inverted trap is caught. An implementer
    reaching for the obvious `except AuthorError` drops `GitError` and `ModelRetry` and quietly
    reverts decision 1 paths 3 and 4 — while every test that only checks "something retires"
    stays green, because the `AuthorError` case passes under the wrong spelling too.

    So each member is driven separately and asserted to retire, with the two droppable ones
    driven through the real dependency: git's own index lock held so `commit_corpus` raises a
    genuine `GitError`, and the `ModelRetry` class PJ1c observed on a killed boxed command. The
    declared set is then checked to hold exactly those three, so a fourth member smuggled in
    fails too."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")

    h.seed(ch, [h.row_for("actor_observations", "a/git")])
    git_cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.committing("member", also=lambda r, b, c: _wedge_git(c.repo_root)),
    )
    assert drain.run_batch(cfg=git_cfg) == 2
    assert [r["observation_id"] for r in h.graveyard(ch)] == ["a/git"], "GitError is a member"
    _unwedge_git(paths.repo_root)

    h.seed(ch, [h.row_for("actor_observations", "a/retry")])
    retry_cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(ModelRetry("command timed out after 120s")),
    )
    assert drain.run_batch(cfg=retry_cfg) == 2
    assert "a/retry" in {r["observation_id"] for r in h.graveyard(ch)}, "ModelRetry is a member"

    h.seed(ch, [h.row_for("actor_observations", "a/auth")])
    auth_cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(author_shared.AuthorError("member")),
    )
    assert drain.run_batch(cfg=auth_cfg) == 2
    assert "a/auth" in {r["observation_id"] for r in h.graveyard(ch)}

    assert set(drain.RETIRE_SET) == set(MEMBERS), "the declared set is not the three members"
    assert not set(drain.RETIRE_SET) & set(NON_MEMBERS)
    assert set(drain.RETIRE_SET) != set(faults.SYSTEMIC_FAULTS)


def test_the_retire_set_is_the_same_on_findings_as_on_the_observation_channels(tmp_path: Path):
    """Decision 5 survives decision 8 unchanged in scope and changed in mechanism: the set is
    the same on all four drained channels, so a channel naming fewer classes fails here.

    Driven per channel with one member an `except AuthorError` spelling would drop
    (`ModelRetry`) and one non-member (`StageAbort`), because a parity test that only drives
    `AuthorError` cannot see either half. No existing findings-channel test discriminates any of
    this — they all fault with an explicit `AuthorError` — so this demand, not the legacy suite,
    is what carries decision 5."""
    paths = h.make_paths(tmp_path)
    h.write_source_refs(paths, "run-W")
    member_seen, non_member_seen = {}, {}

    for name in h.AUTHOR_CHANNELS:
        ch = h.channel_of(paths, name)
        rid = "run-W/0" if name == "findings" else "w/0"

        h.seed(ch, [h.row_for(name, rid)])
        member = h.cfg_for(
            paths, name, max_attempts=1, invoke_agent=h.raising(ModelRetry("killed"))
        )
        assert drain.run_batch(cfg=member) == 2, f"{name}: a member did not fault the batch"
        # `pending == []` rather than the pending list itself: the observable is "the queue
        # was emptied", and a list of dicts cannot go in the set this compares across
        # channels. As first written it raised TypeError before asserting anything.
        member_seen[name] = (h.pending(ch) == [], tuple(r["attempts"] for r in h.graveyard(ch)))

        rows = [h.row_for(name, rid)]
        h.seed(ch, rows)
        non_member = h.cfg_for(
            paths, name, max_attempts=1, invoke_agent=h.raising(StageAbort("abort"))
        )
        with pytest.raises(StageAbort):
            drain.run_batch(cfg=non_member)
        non_member_seen[name] = h.pending(ch) == rows

    assert set(member_seen.values()) == {(True, (1,))}, member_seen
    assert set(non_member_seen.values()) == {True}, non_member_seen


def test_non_member_systemic_faults_skip_retirement_and_git_error_does_not(tmp_path: Path):
    """RE-DERIVED, not patched — this demand has been written three times under opposite
    pressures. Its content: on the author channels `StageAbort`, `FatalConfigError` and
    `BoxFault` are exempt from retirement BECAUSE THEY ARE NOT MEMBERS of the retire set. That
    observable coincides with the pre-fold "the except clause never named them", but the reason
    is stated rather than accidental, and it survives a refactor that moves a line.

    One member did not come back: `GitError` is permanently OUT of the exempt set (decision 1
    path 3). The original demand asserted all four were exempt; asserting that again would
    silently revert the decision, so the `GitError` half is the discriminating one here.

    Exemption is also total OUTSIDE the clauses that name the set: injected at the pre-author
    gate, an `AuthorError` is as exempt as a `StageAbort` — the control showing this is about
    reach as well as class."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    rows = [h.row_for("actor_observations", "a/0")]

    for exc in (StageAbort("abort"), FatalConfigError("bad config"), BoxFault("box gone")):
        h.seed(ch, rows)
        cfg = h.cfg_for(
            paths, "actor_observations", max_attempts=1, invoke_agent=h.raising(exc)
        )
        with pytest.raises(type(exc)):
            drain.run_batch(cfg=cfg)
        assert h.pending(ch) == rows, f"{type(exc).__name__}: exempt by non-membership"
        assert h.graveyard(ch) == []

    h.seed(ch, rows)
    git_cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.committing("notexempt", also=lambda r, b, c: _wedge_git(c.repo_root)),
    )
    assert drain.run_batch(cfg=git_cfg) == 2, "GitError is NOT exempt — decision 1 path 3"
    assert [r["observation_id"] for r in h.graveyard(ch)] == ["a/0"]
    _unwedge_git(paths.repo_root)

    h.seed(ch, rows)
    # Against the count this channel already carries, not against zero: the GitError probe
    # above deliberately retired a row into this same graveyard, so the empty-graveyard
    # spelling asserted that the earlier half of the test had not happened.
    before = len(h.graveyard(ch))
    outside = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        gate=_raising_gate(author_shared.AuthorError("a member, but out of reach")),
        invoke_agent=h.raising(AssertionError("the gate failed first")),
    )
    with pytest.raises(author_shared.AuthorError):
        drain.run_batch(cfg=outside)
    assert h.pending(ch) == rows
    assert len(h.graveyard(ch)) == before, "a member raised out of reach retired something"


def test_the_retire_set_clauses_span_the_agent_call_through_the_corpus_commit_and_no_further(
    tmp_path: Path,
):
    """Decision 6's extent half: which calls sit inside the try whose except clauses name the
    retire set. Confirmatory rather than load-bearing since decision 8 — A11, B5 and D5 are
    carried by non-membership now — but a real property, because a call raising a MEMBER moved
    across either edge changes what happens to the row.

    REBUILT so it actually discriminates. The previous four probes were a member from the agent
    call, a member from the corpus commit, an `OSError` from a lock acquisition and an `OSError`
    from the queue rewrite. The last two outcomes follow from NON-MEMBERSHIP alone, so an
    implementation with the clauses drawn at any other extent passed them: extent was never
    observed, membership was observed twice.

    Every probe below raises a MEMBER, holding membership constant so PLACEMENT is the only
    variable. Each fails on one specific misplacement:

    * a member from the pre-author gate must PROPAGATE — fails if the clauses open too early;
    * a member from the agent call must RETIRE — fails if they open too late;
    * a member from the corpus commit must RETIRE — fails if they close before the commit;
    * a member from the post-rotate hook must PROPAGATE with the rotation already landed —
      fails if they close too late. That is the edge decision 9 leans on to carry the
      post-commit no-bump, and nothing else in the suite can see it.
    """
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")

    h.seed(ch, [h.row_for("actor_observations", "a/0")])
    queued = h.pending(ch)
    before_gate = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        gate=_raising_gate(_instance(author_shared.AuthorError, "member, before they open")),
        invoke_agent=h.raising(AssertionError("the gate failed first")),
    )
    with pytest.raises(author_shared.AuthorError):
        drain.run_batch(cfg=before_gate)
    assert h.pending(ch) == queued, "a member from the gate retired — the clauses open too early"
    assert h.graveyard(ch) == []

    inside_agent = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(_instance(author_shared.AuthorError, "member, inside")),
    )
    assert drain.run_batch(cfg=inside_agent) == 2
    assert [r["observation_id"] for r in h.graveyard(ch)] == ["a/0"], "the clauses open too late"

    h.seed(ch, [h.row_for("actor_observations", "a/1")])
    inside_commit = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.committing("g", also=lambda r, b, c: _wedge_git(c.repo_root)),
    )
    assert drain.run_batch(cfg=inside_commit) == 2
    assert sorted(r["observation_id"] for r in h.graveyard(ch)) == ["a/0", "a/1"], (
        "a member from the corpus commit did not retire — the clauses close too early"
    )
    _unwedge_git(paths.repo_root)

    h.seed(ch, [h.row_for("actor_observations", "a/2")])
    after_rotate = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.committing("post"),
        post_rotate=_raising_gate(_instance(author_shared.AuthorError, "member, after they close")),
    )
    with pytest.raises(author_shared.AuthorError):
        drain.run_batch(cfg=after_rotate)
    assert "a/2" not in {r["observation_id"] for r in h.graveyard(ch)}, (
        "a member raised after the rotation retired — the clauses close too late, which is the "
        "edge decision 9 relies on to carry the post-commit no-bump"
    )
    assert "a/2" in {r["observation_id"] for r in h.consumed(ch)}, (
        "the rotation had not landed, so this was not the post-close probe it claims to be"
    )


# =======================================================================================
# Decision 1's four paths — each is a named member, which is why each still retires
# =======================================================================================


def test_post_agent_failure_with_a_succeeding_agent_bumps_and_retires(tmp_path: Path):
    """Decision 1 path 2 — the strongest single finding in the routed set, and unaffected in
    OUTCOME by decision 8 because `verify_agent_state` and `validate_agent_result_partition`
    both raise `AuthorError`, a member. What changed is the wiring statement: this retires
    because the class is named, not because a bare `except Exception` swept it up.

    The agent call SUCCEEDS; the failure is in the step after it and before the commit lands —
    the result partition names an id that was never in the batch, so the real validator rejects
    it. An oracle that faults the AGENT passes vacuously here, which is why the recorded call is
    asserted to have happened."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "environment_observations")
    h.seed(ch, [h.row_for("environment_observations", "b/0")])

    def over_claim(rows, batch_id, cfg):
        (cfg.corpus_dir / f"lesson-{batch_id}.md").write_text("---\nx: 1\n---\nbody\n")
        return {
            "committed": [rows[0]["observation_id"], "b/999-never-queued"],
            "consumed_skip": [],
            "held_forward_bad": [],
            "commit_message": "author env lessons batch",
        }

    agent = h.recording(over_claim)
    cfg = h.cfg_for(paths, "environment_observations", max_attempts=2, invoke_agent=agent)

    assert drain.run_batch(cfg=cfg) == 2
    assert len(agent.calls) == 1, "the agent must have succeeded for this to discriminate"
    assert h.attempts_of(ch, "b/0") == 1

    assert drain.run_batch(cfg=cfg) == 2
    assert h.pending(ch) == []
    assert [r["attempts"] for r in h.graveyard(ch)] == [2]


def test_corpus_commit_git_error_bumps_the_row_and_leaves_the_corpus_dir_usable(tmp_path: Path):
    """Decision 1 path 3, STRENGTHENED at §7 round 2: `GitError`'s membership is asserted
    explicitly rather than inferred from the row having retired. Under an allow-list the natural
    wrong spelling drops this member silently, and a test that only observes the graveyard
    cannot say which class put the row there.

    The agent succeeds and writes its lesson; git itself then fails for real, its index lock
    held. Both halves are needed: the row bumps and retires, AND the corpus directory is left
    clean enough for the next tick to reach its gate at all — a stray uncommitted file aborts
    every subsequent batch (F5/P03), which is how this path wedges the channel today."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_environment_observations")
    h.seed(ch, [h.row_for("actor_environment_observations", "e/0")])
    cfg = h.cfg_for(
        paths,
        "actor_environment_observations",
        max_attempts=1,
        invoke_agent=h.committing("wedge", also=lambda r, b, c: _wedge_git(c.repo_root)),
    )

    assert GitError in tuple(drain.RETIRE_SET), "GitError was dropped from the retire set"
    assert drain.run_batch(cfg=cfg) == 2
    assert h.pending(ch) == []
    assert [r["attempts"] for r in h.graveyard(ch)] == [1]

    _unwedge_git(paths.repo_root)
    author_shared.assert_clean_corpus_dir(paths.repo_root, cfg.corpus_dir, cfg.corpus_dir_rel)

    h.seed(ch, [h.row_for("actor_environment_observations", "e/1")])
    nxt = h.cfg_for(
        paths, "actor_environment_observations", max_attempts=1, invoke_agent=h.committing("ok")
    )
    assert drain.run_batch(cfg=nxt) == 0, "the channel is not wedged for the next batch"


def test_externally_killed_box_command_is_not_reported_as_a_successful_batch(tmp_path: Path):
    """Decision 1 path 4, and the second member an `except AuthorError` spelling drops. PJ1c
    (executed) found that a boxed bash command stopped from OUTSIDE the process is absorbed by
    `runtime/tools.py::_tool_bash` into a pydantic-ai `ModelRetry` and reaches neither the
    per-item nor the systemic path — the batch reports success, nothing is counted, the item
    never retires.

    Scoped to the drain's own seam: the absorption happens below `cfg.invoke_agent`, so the class
    PJ1c observed is raised at the injection seam above it. `ModelRetry`'s membership is asserted
    directly, because the retirement it causes is indistinguishable from an `AuthorError`'s once
    the row is in the graveyard. The paired control is a genuinely successful batch, which
    rotates and counts nothing."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")

    h.seed(ch, [h.row_for("actor_observations", "a/0")])
    ok = h.cfg_for(paths, "actor_observations", max_attempts=2, invoke_agent=h.committing("live"))
    assert drain.run_batch(cfg=ok) == 0
    assert h.pending(ch) == []
    assert h.graveyard(ch) == []

    assert ModelRetry in tuple(drain.RETIRE_SET), "ModelRetry was dropped from the retire set"
    h.seed(ch, [h.row_for("actor_observations", "a/1")])
    # The control batch above authored a/0 and consumed it, so the ledger is not empty here
    # and never was: what this asserts is that the KILLED batch adds nothing to it.
    consumed_before = len(h.consumed(ch))
    killed = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=2,
        invoke_agent=h.raising(ModelRetry("command timed out after 120s")),
    )
    assert drain.run_batch(cfg=killed) != 0, "an absorbed kill is not a successful batch"
    assert h.attempts_of(ch, "a/1") == 1
    assert len(h.consumed(ch)) == consumed_before, (
        "nothing was consumed by a batch that did not author"
    )


# =======================================================================================
# Non-membership carries what placement used to
# =======================================================================================


def test_a_plain_oserror_from_a_lock_acquisition_is_classified_systemic(tmp_path: Path):
    """D5/P13, SIMPLIFIED by decision 8. §7's derivation — that "classify explicitly" meant the
    lock layer must name its own fault type — was load-bearing only while a type-based re-raise
    set could over-capture a missing-file `OSError`. Under an allow-list an `OSError` is simply
    not a member, so this spec no longer requires a named lock fault: a plain `OSError` escaping
    is the contract.

    Induced for real — the lock path is a directory, so opening it fails at the primitive. The
    acquisition failure escapes uncaught, nothing is counted, and the queue is untouched."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    rows = [h.row_for("actor_observations", "a/0")]
    h.seed(ch, rows)

    ch.drain_lock.mkdir(parents=True)
    cfg = h.cfg_for(
        paths,
        "actor_observations",
        max_attempts=1,
        invoke_agent=h.raising(AssertionError("never reached")),
    )
    with pytest.raises(OSError):  # noqa: PT011 - the lock-acquisition OSError's exact subclass (IsADirectoryError etc.) is platform-dependent; the point is that it escapes uncaught and uncounted
        drain.run_batch(cfg=cfg)
    assert h.pending(ch) == rows
    assert h.graveyard(ch) == []
    assert h.attempts_of(ch, "a/0") is None


def test_mid_batch_author_timeout_bumps_the_row_and_is_ceiling_eligible(tmp_path: Path):
    """PJ1b, executed: when the whole-batch wall-clock deadline finally fires it lands as a
    per-item `AuthorError` through the `TimeoutError` -> `RunUnprocessable` -> `AuthorError`
    chain. Under decision 8 that chain is exactly what makes it retire — it arrives AS a member,
    where a bare `TimeoutError` would not, which the second half asserts.

    PJ1a is carried as a constraint, not re-tested: the deadline is SOFT and cannot preempt a
    blocking boxed call, so nothing here treats the configured timeout as the bound on the stall
    and no assertion below is about elapsed time."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0")])
    late = author_shared.AuthorError(
        "curator (batch1) did not complete: curator (curator:batch1) did not complete: TimeoutError()"
    )
    cfg = h.cfg_for(paths, "actor_observations", max_attempts=2, invoke_agent=h.raising(late))

    assert drain.run_batch(cfg=cfg) == 2
    assert h.attempts_of(ch, "a/0") == 1
    assert drain.run_batch(cfg=cfg) == 2
    assert "TimeoutError" in h.graveyard(ch)[0]["deadletter_reason"]

    h.seed(ch, [h.row_for("actor_observations", "a/1")])
    bare = h.cfg_for(
        paths, "actor_observations", max_attempts=2, invoke_agent=h.raising(TimeoutError("bare"))
    )
    with pytest.raises(TimeoutError):
        drain.run_batch(cfg=bare)
    assert h.attempts_of(ch, "a/1") is None, "a bare TimeoutError is not a member"


def test_systemic_faults_propagate_without_bumping_attempts(tmp_path: Path):
    """The marker-channel half keeps its own mechanism: the pitfalls and lead-author legs exempt
    by RE-RAISING through `run_or_dead_letter`, where the author channels exempt by
    non-membership (C32). Driven through the real pitfalls drain leg, the four named systemic
    classes propagate out of the tick with no attempt written to any queued row.

    `GitError` is in that re-raise set and this change does not touch it, so a commit-time
    `GitError` retires on the four author channels and kills the drain here. Both halves are
    pinned by tests; the asymmetry is recorded as intended in the artifact's waivers rather than
    left for a cold reader to find.

    Positive control: the converted pitfalls fault is deliberately NOT in that re-raise set, so
    an `AuthorError` on the same path is dead-lettered into the retire seam and DOES bump."""
    from defender.learning.core import drains  # type: ignore[import-not-found]

    paths = h.make_paths(tmp_path)
    rows = [h.row_for("pitfalls", f"r:l-{i:03d}:0") for i in range(2)]

    for exc in (
        StageAbort("abort"),
        FatalConfigError("bad config"),
        GitError(["git", "commit"], 1, "boom"),
        BoxFault("box gone"),
    ):
        h.seed(paths.pitfalls, rows)

        def leg(_paths, box=None, _exc=exc):
            raise _exc

        with pytest.raises(type(exc)):
            drains._drain_pitfalls(paths, leg)
        assert h.pending(paths.pitfalls) == rows, f"{type(exc).__name__}: no row was touched"
        assert h.graveyard(paths.pitfalls) == []

    h.seed(paths.pitfalls, rows)

    def failing_author(_paths, box=None):
        raise author_shared.AuthorError("converted pitfalls rc")

    drains._drain_pitfalls(paths, failing_author)
    assert [r.get("attempts") for r in h.pending(paths.pitfalls)] == [1, 1], (
        "the non-exempt AuthorError did not bump both rows"
    )


# =======================================================================================
# Decision 9 — the reconciling tick, which is what this test actually earns
# =======================================================================================


def test_a_fault_after_a_successful_corpus_commit_leaves_the_attempt_count_alone(tmp_path: Path):
    """The tick FOLLOWING a corpus commit that landed while its rotation never ran must
    reconcile the stranded row without re-authoring it: the pre-author idempotency gate finds
    the already-authored id in the corpus, marks the row consumed and rotates it out, so the
    committed work is not authored a second time and the queue converges.

    Decision 9 re-minted this from decision 7's demand, which was dropped by an editing accident
    and ratified on its merits afterwards. What it no longer claims is a SUPPRESSION step: the
    post-commit no-bump falls out of decision 8 instead, because the failing rotation raises
    `OSError` and `OSError` is not a member of the retire set. The no-bump assertion below is
    kept as a companion observation and is CONFIRMATORY only — it would also pass on an
    implementation that never suppressed anything, and there is no injection seam between
    `commit_corpus` and the rotation through which a member could be raised to make it
    discriminating. The reconciling half is what discharges this demand.

    Standing cost, recorded rather than discovered: nothing here pins the post-commit path free
    of retire-set members. If a future change raises one of the three from a post-commit step,
    the bump returns and no test in this suite fails.

    #771 §7 D1 retired the old technique (pre-occupying the rotation-rewrite's deterministic
    `.tmp` sibling with a directory) — the rewrite now stages under an unpredictable name, so
    nothing can be pre-planted at it. This is the primitive's OWN refusal instead:
    `channel.file` is swapped for a symlink aliasing a sibling copy of the same bytes, so both
    reads that need it (`run_batch`'s row selection and `_rewrite_queue`'s re-read, both via
    `read_jsonl_rows`, which follows symlinks) still find `b/0`, and the commit (which writes
    into the git worktree, not the queue directory) is unaffected — but `write_guarded`'s
    `_refuse_unless_plain` lstat's `channel.file` itself and refuses on the symlink before ever
    computing a staged name. The exact planted-alias shape #771 exists to catch, and — an lstat
    type check rather than a permission bit — it fails the same way whether or not the process
    holds root."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "environment_observations")
    h.seed(ch, [h.row_for("environment_observations", "b/0")])

    before = ch.file.read_bytes()
    aliased_target = ch.file.with_name(ch.file.name + ".aliased")
    aliased_target.write_bytes(before)
    ch.file.unlink()
    ch.file.symlink_to(aliased_target)
    cfg = h.cfg_for(
        paths, "environment_observations", max_attempts=1, invoke_agent=h.committing("landed")
    )
    with pytest.raises(OSError):  # noqa: PT011 - the OS-level rotation-rewrite failure's exact subclass is platform-dependent; the point is that the commit lands before it propagates
        drain.run_batch(cfg=cfg)

    assert "author landed batch" in _git_log(paths.repo_root), "the commit must have landed"
    assert h.attempts_of(ch, "b/0") is None, "no bump once the commit has landed"
    assert h.graveyard(ch) == []

    ch.file.unlink()
    aliased_target.unlink()
    ch.file.write_bytes(before)
    must_not_author = h.recording(h.raising(AssertionError("re-authored already-corpus work")))
    nxt = h.cfg_for(
        paths, "environment_observations", max_attempts=1, invoke_agent=must_not_author
    )
    assert drain.run_batch(cfg=nxt) == 0
    assert must_not_author.calls == [], "the reconciling tick re-invoked the agent"
    assert h.pending(ch) == [], "the stranded row was reconciled out of the queue"
    assert "b/0" in {r["observation_id"] for r in h.consumed(ch)}
