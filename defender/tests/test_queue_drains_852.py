"""Queue drains are best-effort only where proven: markers leave the queue only after work happened; lock-held skip; requeue never clobbers."""
from __future__ import annotations

import fcntl
import json
from pathlib import Path

import pytest

import _drain719 as h
from _drain719 import drain
from defender.learning.core import drains
from defender.learning.core.state import LEAD_QUEUE_LOCK, Claimed
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
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests import _state1135


# F-02 — the corpus commit is pathspec-wide; attribution is what bounds it


def _write_corpus_file(corpus_dir: Path, stem: str, field: str, cited: list[str]) -> Path:
    """One curator-written corpus file, citing `cited` under `field` (or nothing at all)."""
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
    """F-02."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "run-G/0"), h.row_for("findings", "run-B/0")])

    def curate(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "vouched", "source_finding_ids", ["run-G/0"])
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
    assert sorted(h.pending_by_id(paths, ch)) == ["run-B/0", "run-G/0"], \
        "the batch left the queue on a tick that committed nothing"
    assert h.attempts_of(paths, ch, "run-G/0") == 1


def test_852_f02_an_attributable_mixed_batch_still_commits_and_reports_the_hold(
    tmp_path: Path,
):
    """F-02's control, and its second half."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "run-G/0"), h.row_for("findings", "run-B/0")])

    def curate(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "vouched", "source_finding_ids", ["run-G/0"])
        return {
            "committed": ["run-G/0"],
            "consumed_skip": [],
            "commit_message": "defender: lesson vouched",
        }

    cfg = h.cfg_for(paths, "findings", invoke_agent=curate)
    assert drain.run_batch(cfg=cfg) == 0

    assert _head_files(paths.repo_root) == ["defender/lessons/vouched.md"]
    assert list(h.pending_by_id(paths, ch)) == ["run-B/0"]
    assert "attempts" not in h.pending_by_id(paths, ch)["run-B/0"]
    assert "held_reason" not in h.pending_by_id(paths, ch)["run-B/0"], (
        "a row this tick never mentioned was stamped with a hold reason it was never given"
    )


def test_852_f02_a_modified_file_that_claims_a_new_source_still_needs_a_voucher(
    tmp_path: Path,
):
    """The exemption's edge."""
    paths = h.make_paths(tmp_path)
    ch = h.channel_of("findings")
    h.seed(paths, ch, [h.row_for("findings", "run-G/0"), h.row_for("findings", "run-B/0")])

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
    assert sorted(h.pending_by_id(paths, ch)) == ["run-B/0", "run-G/0"]


# F-03 — a skip is not a serve


def _enqueue(paths, case_id: str, run_dir: Path) -> None:
    """The curation request the investigation's tail files (`run_common.enqueue_curation`'s own
    body: the run's address, #1105 PR 2), through the handle."""
    _state1135.state_for_paths(paths).enqueue_curation(
        case_id, _state1135.curation_row(case_id, run_dir))


def _queued_run(case_id: str, name: str, paths) -> Path:
    """A natural run `name` planted where the drain rehydrates a row (`curation_run_dir`),
    with the curation request for `case_id` naming it."""
    run_dir = _state1135.curation_run_dir(name)
    _enqueue(paths, case_id, run_dir)
    return run_dir


def _address(row: dict) -> tuple[str, str]:
    """The run a curation row names: its `(tenant_id, run_id)` (#1105 PR 2 declared change 8)."""
    return row["tenant_id"], row["run_id"]


def _drain(paths, tmp_path: Path, **overrides):
    return drains.lead_author_drain(
        paths,
        run_pitfalls=lambda *_a, **_kw: 0,
        branch=SpecBranch(tmp_path / "worktrees"),
        start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
        **overrides,
    )


def test_852_f03_a_held_queue_lock_leaves_the_whole_batch_queued(tmp_path: Path):
    """F-03."""
    paths = loop_paths(tmp_path)
    _queued_run("case-1", "run-1", paths)
    _queued_run("case-2", "run-2", paths)

    queue_lock = (paths.state_root / LEAD_QUEUE_LOCK.file).parent / ".lock"
    queue_lock.parent.mkdir(parents=True, exist_ok=True)
    holder = queue_lock.open("a+")
    try:
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        rc = _drain(paths, tmp_path)
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()

    assert rc == 0
    assert author_markers(paths) == ["case-1.json", "case-2.json"], \
        "a request nothing served was deleted from the queue"
    assert list((paths.state_root / "author-queue" / "inflight").glob("*.json")) == [], \
        "a claimed request was left stranded in inflight/ by a pass that served nothing"
    assert not (paths.state_root / "author-queue" / "failed").exists(), \
        "a skip was dead-lettered — it is not a failure of the request"
    for name in ("case-1.json", "case-2.json"):
        assert "attempts" not in marker_body(paths.state_root / "author-queue" / name), \
            "a skip spent one of the request's three retries"
    assert drains._has_lead_author_work(_state1135.state_for_paths(paths)) is True, \
        "the queue went quiet on work that is still queued"


def test_852_f03_the_skip_rc_is_distinct_from_a_completed_serve(tmp_path: Path):
    """F-03's seam, stated directly: the value `run` returns for "another tick holds the"""
    run_dir = _state1135.curation_run_dir("run-1")
    paths = loop_paths(tmp_path)

    queue_lock = (paths.state_root / LEAD_QUEUE_LOCK.file).parent / ".lock"
    queue_lock.parent.mkdir(parents=True, exist_ok=True)
    holder = queue_lock.open("a+")
    try:
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        rc = lead_author.run(_state1135.run_of(run_dir), label=LEAD_AUTHOR_DRAIN_LABEL,
                             paths=paths)
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()

    assert rc == lead_author.QUEUE_LOCK_SKIP_RC
    assert rc not in (0, 2), "the skip is indistinguishable from a serve or from a fault"


# F-04 — a re-queue must not overwrite a fresher request for the same case


def test_852_f04_a_transient_retry_does_not_clobber_a_fresher_request(tmp_path: Path):
    """F-04."""
    paths = loop_paths(tmp_path)
    first = _queued_run("case-A", "run-1", paths)
    second = _state1135.curation_run_dir("run-2")

    served: list[Path] = []

    def serve(_paths, _state, run, *, box=None, **_kw):
        served.append(run.run_dir)
        if len(served) == 1:
            # The operator re-investigates the case while the lane is curating it...
            _enqueue(paths, "case-A", second)
            # ...and the agent spawn then hits the transient the drain retries on.
            raise drains._LeadAuthorRetry("lead-author hit a swallowed transient (rc=None)")

    _drain(paths, tmp_path, run_lead_author=serve)

    assert author_markers(paths) == ["case-A.json"]
    body = marker_body(paths.state_root / "author-queue" / "case-A.json")
    assert _address(body) == _address(_state1135.curation_row("case-A", second)), (
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
    """F-04's primitive."""
    state = _state1135.state_over(tmp_path / "state")
    run_dir = _state1135.curation_run_dir("run-1")
    state.enqueue_curation("case-A", _state1135.curation_row("case-A", run_dir))
    [claim] = list(state.claim("case_id"))
    queue_dir = tmp_path / "state" / "author-queue"
    slot = queue_dir / "case-A.json"
    assert not slot.exists(), "the claim left the slot occupied"

    assert state.requeue(claim) is True
    stale = Claimed(key="case-A", name="case-A.json",
                    spec=_state1135.curation_row("case-A", run_dir.parent / "stale"))
    assert state.requeue(stale) is False
    assert _address(json.loads(slot.read_text())) == \
        _address(_state1135.curation_row("case-A", run_dir)), \
        "the refused re-queue wrote itself in anyway"
    assert {p.name for p in queue_dir.iterdir()} == {"case-A.json", "inflight"}, \
        "the re-queue left its staging file in the queue directory"


@pytest.mark.parametrize("spec", [{"case_id": "c"}, {"run_id": "r", "attempts": 2}])
def test_852_f04_a_free_slot_still_takes_the_re_queue(tmp_path: Path, spec: dict):
    """The ordinary case, under both row shapes the queue carries: nothing else landed, so
    the request goes back exactly as it was handed over."""
    state = _state1135.state_over(tmp_path / "state")
    slot = tmp_path / "state" / "author-queue" / "row.json"
    assert state.requeue(Claimed(key="row", name="row.json", spec=spec)) is True
    assert json.loads(slot.read_text()) == spec
