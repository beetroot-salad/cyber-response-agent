"""#852 — the drain treats its queue as best-effort, in five places, without saying so.

The through-line the register names: **a marker leaves the queue only when work provably
happened for it, and a write to the corpus is attributable to the finding that justified
it.** Each test below names the register ref it pins.

Two of the five are pinned where their siblings already live rather than here, because the
property is shared and a lone copy would be the one that rots:

* **F-18** (a marker whose `run_dir` is not a string) joins the dead-letter tables in
  `tests/learning/test_loop.py` — both queues run the one `claim_markers` protocol, so both
  tables carry the case.
* **F-21** (`_SAFE_ID_SEGMENT`'s `$` anchor) joins `tests/test_lead_author_synth.py`, beside
  the traversal case it is the same guard as.

Fakes enter through the shipped injection seams — `dataclasses.replace(cfg, invoke_agent=)`
for the corpus author, `run_lead_author=` / `branch=` / the box lifecycle for the drain — so
no `monkeypatch.setattr` is needed to drive any of this. The one real resource a test takes
is the lead-author QUEUE LOCK, held with a plain `flock` exactly as a second lead-author
process would hold it: F-03 is a fact about that lock, and injecting the skip would assert
the shipped `rc` contract nowhere.
"""
from __future__ import annotations

import fcntl
import json
from pathlib import Path

import pytest

import _drain719 as h
from _drain719 import drain
from defender.learning.core import drains, markers
from defender.learning.leads import lead_author
from defender.tests._spec791 import (
    SpecBranch,
    author_markers,
    loop_paths,
    marker_body,
    noop_scrub,
    noop_start_box,
    noop_stop_box,
)


# --------------------------------------------------------------------------------------
# F-02 — the corpus commit is pathspec-wide; attribution is what bounds it
# --------------------------------------------------------------------------------------


def _write_corpus_file(corpus_dir: Path, stem: str, field: str, cited: list[str]) -> Path:
    """One curator-written corpus file, citing `cited` under `field` (or nothing at all).

    `field` is the caller's, not derived, because the point of two of these tests is that
    the citation is read under the CHANNEL's own provenance key."""
    provenance = f"{field}:\n" + "".join(f"  - {c}\n" for c in cited) if cited else ""
    path = corpus_dir / f"{stem}.md"
    path.write_text(
        f"---\nname: {stem}\ndescription: a teachable pitfall\n{provenance}---\n\nbody\n",
        encoding="utf-8",
    )
    return path


def _head_files(repo: Path) -> list[str]:
    return h.git(repo, "show", "--name-only", "--pretty=format:", "HEAD").stdout.split()


def _commits(repo: Path) -> int:
    """Commit count — how "nothing was committed" is asserted, since HEAD on a faulted tick
    is the fixture's own init commit and carries the whole tree."""
    return int(h.git(repo, "rev-list", "--count", "HEAD").stdout.strip())


def test_852_f02_a_forward_bad_lesson_is_not_swept_into_a_mixed_batch_commit(tmp_path: Path):
    """F-02. A lesson the curator wrote and then reported `held_forward_bad` must not reach
    the corpus on the back of its batch-mates.

    MIXED is the whole finding. The homogeneous case was already caught: with `committed`
    empty and a file left behind, `verify_agent_state`'s aggregate check fires, the corpus is
    restored and the rows are re-queued. But that check is one bit for the whole batch — and
    a batch is >= LEARNING_AUTHOR_THRESHOLD (5) rows, so mixed GOOD/BAD is the NORMAL shape.
    One legitimately committed lesson satisfies the aggregate bit, and the pathspec-wide
    `git add -- defender/lessons` then commits the rejected lesson beside it. The forward
    check said that lesson would flip a correctly-resolved case; nothing downstream reads its
    verdict back, so the corpus was the last place it could be stopped.

    The disposition is the one the aggregate check already established: `AuthorError` ->
    the corpus is restored (both files gone, nothing committed) -> the batch is bumped and
    stays queued for the next tick."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    for run_id in ("run-G", "run-B"):
        h.write_source_refs(paths, run_id)
    h.seed(ch, [h.row_for("findings", "run-G/0"), h.row_for("findings", "run-B/0")])

    def curate(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "vouched", "source_finding_ids", ["run-G/0"])
        # The BAD lesson the curator was told to `rm` and did not (prompt.md, "Per-lesson
        # forward-check gate"). Nothing cites it, because the finding that would have is the
        # one the forward check just rejected.
        _write_corpus_file(cfg.corpus_dir, "forward-bad", "source_finding_ids", [])
        return {
            "committed": ["run-G/0"],
            "consumed_skip": [],
            "held_forward_bad": [{"finding_id": "run-B/0", "reason": "flips a green case"}],
            "commit_message": "defender: lesson vouched",
        }

    cfg = h.cfg_for(paths, "findings", invoke_agent=curate)
    assert drain.run_batch(cfg=cfg) == 2, "the unattributable file did not fault the tick"

    assert not (cfg.corpus_dir / "forward-bad.md").exists(), \
        "the rejected lesson survived in the corpus"
    assert not (cfg.corpus_dir / "vouched.md").exists(), \
        "the tick faulted but its batch-mate's edit was not restored away with it"
    assert _commits(paths.repo_root) == 1, "a commit landed on a faulted tick"
    assert sorted(h.pending_by_id(ch)) == ["run-B/0", "run-G/0"], \
        "the batch left the queue on a tick that committed nothing"
    assert h.attempts_of(ch, "run-G/0") == 1


def test_852_f02_an_attributable_mixed_batch_still_commits_and_reports_the_hold(
    tmp_path: Path,
):
    """F-02's control, and its second half.

    The control: a curator that DOES delete the rejected lesson commits normally — one file,
    the one its committed finding vouches for — and the held row stays queued carrying its
    `forward_bad:` reason. A gate that also blocked this would have replaced a durability
    bug with a wedge.

    The second half: the held report is written even though the batch committed. It used to
    return early on `commit_sha is not None`, which silenced the report on exactly the batch
    shape a forward-check hold is most interesting in — the mixed one, where the held
    lesson's file sat in a corpus being committed for its batch-mates. What a tick held does
    not depend on how its other rows went."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    for run_id in ("run-G", "run-B"):
        h.write_source_refs(paths, run_id)
    h.seed(ch, [h.row_for("findings", "run-G/0"), h.row_for("findings", "run-B/0")])

    def curate(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "vouched", "source_finding_ids", ["run-G/0"])
        return {
            "committed": ["run-G/0"],
            "consumed_skip": [],
            "held_forward_bad": [{"finding_id": "run-B/0", "reason": "flips a green case"}],
            "commit_message": "defender: lesson vouched",
        }

    cfg = h.cfg_for(paths, "findings", invoke_agent=curate)
    assert drain.run_batch(cfg=cfg) == 0

    assert _head_files(paths.repo_root) == ["defender/lessons/vouched.md"]
    assert list(h.pending_by_id(ch)) == ["run-B/0"]
    assert h.pending_by_id(ch)["run-B/0"]["held_reason"].startswith("forward_bad: ")
    report = cfg.held_report.read_text(encoding="utf-8")
    assert "run-B/0" in report, (
        "the batch committed, so the forward-check hold went unreported — the operator's one "
        "written trace of a BAD verdict is missing on the batch shape it matters most in"
    )


def test_852_f02_attribution_reads_the_channels_own_provenance_key(tmp_path: Path):
    """F-02, on an observation channel: the citation must be under the key that channel's
    idempotency gate reads back.

    The four author channels share one drain body and two provenance spellings —
    `source_finding_ids` on the lessons corpus, `source_observation_ids` on the actor and
    environment corpora. Accepting either would let an actor lesson citing `source_finding_ids`
    pass this gate and stay invisible to `existing_observation_ids`, i.e. be authored again
    on every following tick. Keying on `channel.id_key` is what keeps "attributable" and
    "recognised as already authored" the same question."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/0")])

    def curate_under_the_wrong_key(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "mis-cited", "source_finding_ids", ["a/0"])
        return {
            "committed": ["a/0"],
            "consumed_skip": [],
            "held_forward_bad": [],
            "commit_message": "author actor lesson",
        }

    cfg = h.cfg_for(paths, "actor_observations", invoke_agent=curate_under_the_wrong_key)
    assert drain.run_batch(cfg=cfg) == 2
    assert not (cfg.corpus_dir / "mis-cited.md").exists()
    assert _commits(paths.repo_root) == 1

    def curate(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "cited", "source_observation_ids", ["a/0"])
        return {
            "committed": ["a/0"],
            "consumed_skip": [],
            "held_forward_bad": [],
            "commit_message": "author actor lesson",
        }

    cfg = h.cfg_for(paths, "actor_observations", invoke_agent=curate)
    assert drain.run_batch(cfg=cfg) == 0
    assert _head_files(paths.repo_root) == ["defender/lessons-actor/cited.md"]


def test_852_f02_a_supersede_flip_is_not_read_as_an_unattributed_file(tmp_path: Path):
    """F-02's other control: the gate must not fault ORDINARY curation.

    `Supersede` is a documented step on both observation curators — "author the new lesson,
    flip the old one to `status: stale, superseded_by: {new-name}`". The flipped file is a
    MODIFICATION of a lesson already in history, and it does not gain a `source_observation_
    ids` entry from this batch, because the batch's observation is what the REPLACEMENT
    cites. Demanding a voucher from it faults the tick, restores the corpus — deleting the
    legitimate replacement with it — and bumps the batch toward the ceiling that retires it
    into the graveyard, i.e. turns a routine supersede into permanent data loss.

    The exemption is narrow on purpose: it is the file's provenance list being byte-identical
    to HEAD's, not "modifications are fine". A file the agent CREATED never qualifies (F-02's
    own case cites nothing), and a fold that appends an id the forward check rejected has
    changed its provenance and still fails."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "actor_observations")
    h.seed(ch, [h.row_for("actor_observations", "a/1")])

    seeded = h.cfg_for(paths, "actor_observations")
    old = _write_corpus_file(seeded.corpus_dir, "old-fact", "source_observation_ids", ["a/0"])
    h.git(paths.repo_root, "add", "-A")
    h.git(paths.repo_root, "commit", "-q", "-m", "an earlier batch's lesson")

    def curate(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "new-fact", "source_observation_ids", ["a/1"])
        old.write_text(
            old.read_text(encoding="utf-8").replace(
                "description:", "status: stale\nsuperseded_by: new-fact\ndescription:"
            ),
            encoding="utf-8",
        )
        return {
            "committed": ["a/1"],
            "consumed_skip": [],
            "held_forward_bad": [],
            "commit_message": "author actor lesson, supersede the contradicted one",
        }

    cfg = h.cfg_for(paths, "actor_observations", invoke_agent=curate)
    assert drain.run_batch(cfg=cfg) == 0, "the supersede flip faulted the tick"
    assert sorted(_head_files(paths.repo_root)) == [
        "defender/lessons-actor/new-fact.md",
        "defender/lessons-actor/old-fact.md",
    ]
    assert "status: stale" in old.read_text(encoding="utf-8")
    assert h.pending_by_id(ch) == {}, "the batch was re-queued by a tick that committed"


def test_852_f02_a_modified_file_that_claims_a_new_source_still_needs_a_voucher(
    tmp_path: Path,
):
    """The exemption's edge. A fold that APPENDS an id — the one the forward check then
    rejected — has claimed new provenance, so "unchanged since HEAD" does not cover it and
    the file must still be vouched for by the committed set. Without this the exemption
    would reopen F-02 for every fold onto an existing lesson.

    Driven on the FINDINGS channel, not an observation one, so that the attribution gate is
    the only thing that can fault this tick: `held_forward_bad` is a bucket only this channel
    declares, and a result naming it on an observation channel is rejected by the partition
    validator two steps earlier — which returns the same rc=2 and restores the same corpus,
    for a reason that has nothing to do with attribution. Checked by deletion: with the gate
    call removed, this test fails."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of(paths, "findings")
    for run_id in ("run-G", "run-B"):
        h.write_source_refs(paths, run_id)
    h.seed(ch, [h.row_for("findings", "run-G/0"), h.row_for("findings", "run-B/0")])

    seeded = h.cfg_for(paths, "findings")
    old = _write_corpus_file(seeded.corpus_dir, "old-fact", "source_finding_ids", ["run-A/0"])
    h.git(paths.repo_root, "add", "-A")
    h.git(paths.repo_root, "commit", "-q", "-m", "an earlier batch's lesson")

    def curate(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "vouched", "source_finding_ids", ["run-G/0"])
        # The forward check said run-B/0's fold flips a green case; the curator was told to
        # re-edit the target back and did not.
        _write_corpus_file(
            cfg.corpus_dir, "old-fact", "source_finding_ids", ["run-A/0", "run-B/0"]
        )
        return {
            "committed": ["run-G/0"],
            "consumed_skip": [],
            "held_forward_bad": [{"finding_id": "run-B/0", "reason": "flips a green case"}],
            "commit_message": "defender: lesson vouched",
        }

    cfg = h.cfg_for(paths, "findings", invoke_agent=curate)
    assert drain.run_batch(cfg=cfg) == 2, "the rejected fold rode in on its batch-mate"
    assert _commits(paths.repo_root) == 2
    assert "run-B/0" not in old.read_text(encoding="utf-8"), "the rejected fold survived"
    assert sorted(h.pending_by_id(ch)) == ["run-B/0", "run-G/0"]


# --------------------------------------------------------------------------------------
# F-03 — a skip is not a serve
# --------------------------------------------------------------------------------------


def _queued_run(tmp_path: Path, case_id: str, name: str, paths) -> Path:
    run_dir = tmp_path / "runs" / name
    run_dir.mkdir(parents=True, exist_ok=True)
    markers.enqueue_case_for_curation(case_id, run_dir, paths)
    return run_dir


def _drain(paths, tmp_path: Path, **overrides):
    return drains.lead_author_drain(
        paths,
        run_pitfalls=lambda *_a, **_kw: 0,
        branch=SpecBranch(tmp_path / "worktrees"),
        start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
        **overrides,
    )


def test_852_f03_a_held_queue_lock_leaves_the_whole_batch_queued(tmp_path: Path):
    """F-03. A lead-author tick that never ran because another one holds the per-author
    queue lock must not read as a completed serve.

    `lead_author.run` used to return 0 for that skip — the same value a finished curation
    returns — so the drain unlinked every marker it had claimed in the pass. The whole
    queued batch deleted: no work done, no dead letter in `failed/`, no retry, and
    `_has_lead_author_work` false afterwards. The window is the full agent spawn
    (LEAD_AUTHOR_TIMEOUT_SECONDS, default 1800s), and the documented trigger is an operator
    running `lead_author.py <run_dir>` by hand — which the CLI's own help calls a precondition
    violation, not something the queue may punish by discarding requests.

    Driven through the REAL chain: the real `_invoke_lead_author`, the real module `run`, and
    a real `flock` on the real queue-lock file — held here the way a second lead-author
    process holds it. Nothing about the skip is faked, so the `rc` contract between the two
    modules is what the assertions rest on.

    The batch costs nothing: no `attempts` bump (a skip is not a failed attempt, and three
    ticks under a 30-minute manual hold would otherwise dead-letter healthy requests) and the
    marker that WAS claimed is put straight back in the slot the claim freed."""
    paths = loop_paths(tmp_path)
    _queued_run(tmp_path, "case-1", "run-1", paths)
    _queued_run(tmp_path, "case-2", "run-2", paths)

    lead_author.QUEUE_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    holder = lead_author.QUEUE_LOCK_FILE.open("a+")
    try:
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        rc = _drain(paths, tmp_path)
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()

    assert rc == 0
    assert author_markers(paths) == ["case-1.json", "case-2.json"], \
        "a request nothing served was deleted from the queue"
    assert list((paths.author_queue_dir / "inflight").glob("*.json")) == [], \
        "a claimed request was left stranded in inflight/ by a pass that served nothing"
    assert not (paths.author_queue_dir / "failed").exists(), \
        "a skip was dead-lettered — it is not a failure of the request"
    for name in ("case-1.json", "case-2.json"):
        assert "attempts" not in marker_body(paths.author_queue_dir / name), \
            "a skip spent one of the request's three retries"
    assert drains._has_lead_author_work(paths) is True, \
        "the queue went quiet on work that is still queued"


def test_852_f03_the_skip_rc_is_distinct_from_a_completed_serve(tmp_path: Path):
    """F-03's seam, stated directly: the value `run` returns for "another tick holds the
    queue lock" is not the value it returns for a finished curation, and not the value it
    returns for a fault (rc=2, which the drain quarantines on).

    Bound here rather than left implicit in the test above because it is the whole
    mechanism: `_invoke_lead_author` cannot tell a skip from a serve by any other means —
    it sees an integer and nothing else."""
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)

    lead_author.QUEUE_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    holder = lead_author.QUEUE_LOCK_FILE.open("a+")
    try:
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        rc = lead_author.run(run_dir, paths=loop_paths(tmp_path))
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()

    assert rc == lead_author.QUEUE_LOCK_SKIP_RC
    assert rc not in (0, 2), "the skip is indistinguishable from a serve or from a fault"


# --------------------------------------------------------------------------------------
# F-04 — a re-queue must not overwrite a fresher request for the same case
# --------------------------------------------------------------------------------------


def test_852_f04_a_transient_retry_does_not_clobber_a_fresher_request(tmp_path: Path):
    """F-04. The claim frees the top-level slot so a re-ask that lands mid-serve has
    somewhere to go (#791 P2). A retry that re-queues by atomic REPLACE destroys exactly
    that request.

    Both halves are ordinary operation, and each is already treated as real on its own: the
    mid-drain re-ask is `test_791_a_curation_re_ask_issued_mid_drain_is_not_destroyed`
    ("the operator re-investigates the case while the lane is curating it"), and the
    swallowed transient is a first-class designed path (`_run_curator_module` catching the
    spawn's OSError, `attempts`, LEAD_AUTHOR_MAX_RETRIES). Composed, the older run's spec
    lands on top of the newer one and the case is re-served off the STALE run dir — the newer
    investigation's leads, drafts and pitfalls never curated, with nothing recording it.

    Create-if-absent instead, and the queue's documented contract decides the collision: the
    later run always wins, so the retry is dropped rather than written over the re-ask."""
    paths = loop_paths(tmp_path)
    first = _queued_run(tmp_path, "case-A", "run-1", paths)
    second = tmp_path / "runs" / "run-2"
    second.mkdir(parents=True)

    served: list[Path] = []

    def serve(_paths, run_dir, *, box=None):
        served.append(run_dir)
        if len(served) == 1:
            # The operator re-investigates the case while the lane is curating it...
            markers.enqueue_case_for_curation("case-A", second, paths)
            # ...and the agent spawn then hits the transient the drain retries on.
            raise drains._LeadAuthorRetry("lead-author hit a swallowed transient (rc=None)")

    _drain(paths, tmp_path, run_lead_author=serve)

    assert author_markers(paths) == ["case-A.json"]
    body = marker_body(paths.author_queue_dir / "case-A.json")
    assert Path(body["run_dir"]).resolve() == second.resolve(), (
        "the retry replaced the fresher curation request with the stale run dir — the case "
        "will be re-served off the run the operator already superseded"
    )
    assert "attempts" not in body, \
        "the superseding request inherited the retried run's attempt count"

    _drain(paths, tmp_path, run_lead_author=serve)
    assert served == [first.resolve(), second.resolve()], \
        "the second pass did not serve the newer investigation"
    assert author_markers(paths) == []


def test_852_f04_requeue_is_create_if_absent_and_leaves_no_staging_file(tmp_path: Path):
    """F-04's primitive. `rewrite_marker` (the replace) stays for the callers that mean it;
    the re-queue path needs the other answer, and it needs to REPORT which one it got so the
    caller can drop its stale spec rather than silently lose the fresh one.

    The staging half is not decoration: the re-queue writes through a temp file so the slot
    goes from absent to fully-written in one step, and a temp file left behind in a directory
    the drain globs is a marker-shaped object nothing owns."""
    queue_dir = tmp_path / "author-queue"
    queue_dir.mkdir()
    slot = queue_dir / "case-A.json"

    assert markers.requeue_marker(slot, {"case_id": "case-A", "run_dir": "/runs/run-1"}) is True
    assert markers.requeue_marker(slot, {"case_id": "case-A", "run_dir": "/runs/stale"}) is False
    assert json.loads(slot.read_text())["run_dir"] == "/runs/run-1", \
        "the refused re-queue wrote itself in anyway"
    assert [p.name for p in queue_dir.iterdir()] == ["case-A.json"], \
        "the re-queue left its staging file in the queue directory"


@pytest.mark.parametrize("spec", [{"case_id": "c"}, {"run_id": "r", "attempts": 2}])
def test_852_f04_a_free_slot_still_takes_the_re_queue(tmp_path: Path, spec: dict):
    """The ordinary case, under both row shapes the queue carries: nothing else landed, so
    the request goes back exactly as it was handed over."""
    slot = tmp_path / "queue" / "row.json"
    assert markers.requeue_marker(slot, spec) is True
    assert json.loads(slot.read_text()) == spec
