"""#952 — consumption follows durability in the lead-author lane."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import contextlib
import fcntl
import json
import re
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from defender import _git
from defender._git import GitError
from defender._io import append_jsonl
from defender.learning.author.branch import BranchError
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead
from defender.learning.leads.pitfalls_curator import PitfallsDisposition
from defender import box as box_mod
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.core._declared870 import (
    Spawn,
    commit_all,
    consumed_by_id,
    curate_execution_md,
    graveyard_by_id,
    pitfall_row,
    queue_ids,
    seed_tree,
    shim_row,
    write_reducer_surface,
)
from defender.tests.support.shared.contracts._repo import query_template, seed_skills_repo
from defender.tests.support.sandbox._spec791 import (
    SpecBranch,
    author_markers,
    loop_paths,
    marker_body,
    noop_scrub,
    noop_start_box,
    noop_stop_box,
)
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests.support.learning.curation._lead_author_1134 import lead_deps, lead_trees
from defender.learning.core.state import FINDINGS, LEAD_QUEUE_LOCK, PITFALLS


# --- substrate -------------------------------------------------------------------------------

#: The commit a served lead-author run hands the drain in place of writing the sentinel
#: itself; the sentinel the drain then writes names it.
SHA = "abc123"

COMMITTED_ID = "p:committed:0"
HELD_ID = "p:held:0"

RETAINED = (
    "1 served marker(s) left in inflight/, 1 committed pitfall row(s) left queued, "
    "1 held row(s) not bumped"
)

_SENTINEL_RE = re.compile(r"\Acommit: (?P<sha>\S+)\nat: \S+\ncommit_made: (?P<made>True|False)\n\Z")


class _Branch(SpecBranch):
    """`SpecBranch` plus what this spec needs"""

    def __init__(
        self, base: Path, *, prefix: str = "lead-author/",
        fail: BaseException | None = None, commits: int = 1,
        deliver_fail: BaseException | None = None, deliver_result: str | None = "delivered",
    ) -> None:
        super().__init__(base)
        self.branch_prefix = prefix
        self._fail = fail
        self._commits = commits
        self._deliver_fail = deliver_fail
        self._deliver_result = deliver_result
        self.batch_ids: list[str] = []
        self.delivered: list[str] = []

    @property
    def quarantine_dir(self) -> Path:
        return self._base / "quarantine"

    @property
    def batch_id(self) -> str:
        assert len(self.batch_ids) == 1, f"expected one batch, saw {self.batch_ids}"
        return self.batch_ids[0]

    def start_batch(self, batch_id: str) -> Path:
        self.batch_ids.append(batch_id)
        return super().start_batch(batch_id)

    def finish_batch(self, batch_id: str, wt: Path):
        self.events.append("finish")
        if self._fail is not None:
            raise self._fail
        return f"PR/{batch_id}" if self._commits else None

    def deliver(self, batch_id: str):
        self.events.append("deliver")
        self.delivered.append(batch_id)
        if self._deliver_fail is not None:
            raise self._deliver_fail
        return f"PR/{batch_id}" if self._deliver_result is not None else None


def _queued_run(case_id: str, name: str, paths: LoopPaths) -> Path:
    """A natural run `name` planted where the drain rehydrates a row (`curation_run_dir`, under
    the test's data root, #1105 PR 2), with the curation request for `case_id` naming it."""
    run_dir = _state1135.curation_run_dir(name)
    _state1135.enqueue_case(_state1135.state_for_paths(paths), case_id, run_dir)
    return run_dir


def _address(run_dir: Path) -> tuple[str, str]:
    """The `(tenant_id, run_id)` a curation row names for the run at `run_dir` (#1105 PR 2
    declared change 8: the row is the run's address, where it named its folder)."""
    row = _state1135.curation_row("", run_dir)
    return row["tenant_id"], row["run_id"]


def _seed_pitfalls(paths: LoopPaths) -> bytes:
    """One committable system row and one held reducer row that has ALREADY been declined
    once — so "`offers_declined` not bumped" compares against a real value, and the green
    tick's bump has somewhere to go. Returns the queue file's bytes as seeded."""
    persist.append_pitfalls(
        [
            pitfall_row(COMMITTED_ID, "elastic"),
            shim_row(HELD_ID, **{pitfalls_curator.OFFERS_DECLINED_KEY: 1}),
        ],
        state=_state1135.state_for_paths(paths),
    )
    return (location_path(paths.state_root) / PITFALLS.queue).read_bytes()


def _disposition(sha: str | None = SHA) -> PitfallsDisposition:
    return PitfallsDisposition(committed_ids=(COMMITTED_ID,), sha=sha, held_ids=(HELD_ID,))


def _serving(served: list[Path], *, done: bool = True, before=None):
    """A `run_lead_author` fake that simulates a served run"""

    def serve(_paths, _state, run, *, box=None, on_done):
        served.append(run.run_dir)
        if before is not None:
            before()
        if done:
            on_done(SHA)

    return serve


def _curating(curated: list[PitfallsDisposition], disposition: PitfallsDisposition):
    """A `run_pitfalls` fake that simulates a curation: it hands its partition to the drain
    through `on_curated` and returns 0, exactly as the real curator does in deferred mode."""

    def curate(_paths, _state, *, box=None, on_curated):
        curated.append(disposition)
        on_curated(disposition)
        return 0

    return curate


def _no_curation(*_a, **_kw) -> int:
    return 0


def _tick(paths: LoopPaths, *, branch, run_lead_author, run_pitfalls, scrub=noop_scrub) -> int:
    return drains.lead_author_drain(
        paths, run_lead_author=run_lead_author, run_pitfalls=run_pitfalls, branch=branch,
        start_box=noop_start_box, stop_box=noop_stop_box, scrub=scrub,
    )


def _tainting(_tree, **_kw):
    raise box_mod.RunTainted("planted link")


def _rows_by_id(paths: LoopPaths) -> dict[str, dict]:
    return {str(r["pitfall_id"]): r for r in persist.read_pitfalls(_state1135.state_for_paths(paths))}


def _done(run_dir: Path) -> Path:
    return run_dir / "lead_author" / "done"


def _done_sha(run_dir: Path) -> str:
    """The commit the run's sentinel records — through the sentinel's own shape, so a
    look-alike file is a failure here rather than a match."""
    text = _done(run_dir).read_text(encoding="utf-8")
    m = _SENTINEL_RE.match(text)
    assert m, f"not a sentinel: {text!r}"
    return m["sha"]


def _inflight(paths: LoopPaths) -> list[str]:
    d = location_path(paths.state_root) / "author-queue" / "inflight"
    return sorted(p.name for p in d.glob("*.json")) if d.is_dir() else []


def _inflight_attempts(paths: LoopPaths, case: str) -> int:
    return int(marker_body(location_path(paths.state_root) / "author-queue" / "inflight" / f"{case}.json").get("attempts", 0))


def _pending_deliveries(paths: LoopPaths) -> list[dict]:
    d = location_path(paths.state_root) / "_pending_delivery"
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))] \
        if d.is_dir() else []


@contextlib.contextmanager
def _held(path: Path):
    """Hold `path` under an exclusive `flock`, the way a second process holds it. A separate
    open-file description, so production's own `open`+`flock` on the same path contends."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = path.open("a+", encoding="utf-8")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        yield fh
    finally:
        _release(fh)


def _release(fh) -> None:
    with contextlib.suppress(OSError, ValueError):
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    with contextlib.suppress(OSError):
        fh.close()


def _bounded(fn, *, holder, seconds: float = 15.0):
    """Call `fn` and refuse to wait forever on it."""
    out: dict[str, object] = {}

    def go() -> None:
        try:
            out["value"] = fn()
        except BaseException as e:  # noqa: BLE001 — re-raised on the test's own thread below
            out["error"] = e

    worker = threading.Thread(target=go, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        _release(holder)
        worker.join(seconds)
        pytest.fail(
            f"blocked for >{seconds}s on the held append lock — the rotation reached "
            "`queue_lock` with no deadline (the drain must pass one)"
        )
    if "error" in out:
        raise out["error"]  # type: ignore[misc]
    return out.get("value")


def _assert_nothing_consumed(
    paths: LoopPaths, run_dir: Path, case: str, queue_before: bytes,
) -> None:
    """O1's shared-state clause, in one place so every pre-apply exit asserts the same thing"""
    assert _inflight(paths) == [f"{case}.json"], "the served marker left inflight/"
    claimed = marker_body(location_path(paths.state_root) / "author-queue" / "inflight" / f"{case}.json")
    assert (claimed["tenant_id"], claimed["run_id"]) == _address(run_dir)
    assert author_markers(paths) == [], "the claim was handed back to the top level"
    assert not (location_path(paths.state_root) / "author-queue" / "failed").exists(), "the served run was dead-lettered"
    assert (location_path(paths.state_root) / PITFALLS.queue).read_bytes() == queue_before, (
        "the pitfalls queue changed on a tick that consumed nothing (a rotation, or a bumped "
        f"`{pitfalls_curator.OFFERS_DECLINED_KEY}`)"
    )
    assert _rows_by_id(paths)[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 1
    assert not (location_path(paths.state_root) / PITFALLS.consumed).exists(), "a row reached the consumed ledger"
    assert not _done(run_dir).exists(), (
        "the done sentinel was written under the shared run dir — the reclaimed marker will "
        "be served as 'already processed' next tick and unlinked anyway"
    )
    assert drains._has_lead_author_work(_state1135.state_for_paths(paths)) is True, "the queue went quiet on retained work"


def _assert_consumed(paths: LoopPaths, run_dir: Path, *, done: bool = True) -> None:
    """O3's census, in one place"""
    assert author_markers(paths) == [], "the served marker is back at the top level"
    assert _inflight(paths) == [], "the served marker is still claimed"
    if done:
        assert _done_sha(run_dir) == SHA
    else:
        assert not _done(run_dir).exists(), \
            "a sentinel was written for a run whose curator handed over none"
    consumed = consumed_by_id(paths)
    assert consumed[COMMITTED_ID]["consumed_category"] == "consumed_committed"
    assert consumed[COMMITTED_ID]["consumed_commit"] == SHA
    assert HELD_ID not in consumed
    rows = _rows_by_id(paths)
    assert list(rows) == [HELD_ID], "the committed row is still queued after its batch consumed"
    assert rows[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 2, \
        "the declined offer was not counted"
    assert graveyard_by_id(paths) == {}


# --- O1 — nothing is consumed before the tree passes the scrub --------------------------------


@pytest.mark.parametrize("fault", ["run_tainted_from_scrub", "box_fault_from_teardown"])
def test_952_o1_a_batch_whose_tree_never_passes_the_scrub_consumes_nothing(
    tmp_path: Path, capsys, fault: str,
):
    """O1, the exits BEFORE the apply."""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    queue_before = _seed_pitfalls(paths)
    served: list[Path] = []
    curated: list[PitfallsDisposition] = []
    branch = _Branch(tmp_path / "worktrees")
    scrub, stop_box = noop_scrub, noop_stop_box
    if fault == "run_tainted_from_scrub":
        expected_type: type[BaseException] = box_mod.RunTainted
        scrub = _tainting
    else:
        expected_type = box_mod.BoxFault

        def stop_box(_box, **_kw):
            raise box_mod.BoxFault("docker stop hung")

    with pytest.raises(expected_type):
        drains.lead_author_drain(
            paths, run_lead_author=_serving(served),
            run_pitfalls=_curating(curated, _disposition()), branch=branch,
            start_box=noop_start_box, stop_box=stop_box, scrub=scrub,
        )

    assert served == [run_dir.resolve()]
    assert curated == [_disposition()]
    assert "finish" not in branch.events, "finish_batch ran on a tree the scrub never cleared"
    assert "cleanup" in branch.events
    _assert_nothing_consumed(paths, run_dir, "case-1", queue_before)
    assert _inflight_attempts(paths, "case-1") == 1, "the serve was not counted as an attempt"
    assert _pending_deliveries(paths) == [], "an unsound batch was recorded for delivery"

    err = capsys.readouterr().err
    summary = (
        f"lead_author_drain: batch not consumed — left for the next tick's reclaim, up to: "
        f"{RETAINED}"
    )
    assert sum(line.endswith(summary) for line in err.splitlines()) == 1, (
        f"the retained summary must be logged exactly once on a pre-apply exit:\n{err}"
    )
    assert "finish_batch failed" not in err
    assert "work stays queued" not in err


# --- O3 — a batch whose tree passed the scrub consumes exactly what it served ----------------


@pytest.mark.parametrize(
    ("commits", "done"),
    [(1, True), (0, True), (1, False)],
    ids=["pr-opened", "zero-commits-finish-returns-none", "clean-path-no-sentinel"],
)
def test_952_o3_a_batch_that_passes_the_scrub_consumes_what_it_served(
    tmp_path: Path, commits: int, done: bool,
):
    """O3, the positive control for every O1 negative."""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    _seed_pitfalls(paths)
    served: list[Path] = []
    curated: list[PitfallsDisposition] = []
    branch = _Branch(tmp_path / "worktrees", commits=commits)

    rc = _tick(
        paths, branch=branch,
        run_lead_author=_serving(served, done=done),
        run_pitfalls=_curating(curated, _disposition()),
    )

    assert rc == 0
    assert served == [run_dir.resolve()]
    assert curated == [_disposition()]
    assert branch.events == ["lease-check", "start", "finish", "cleanup"]
    _assert_consumed(paths, run_dir, done=done)
    assert _pending_deliveries(paths) == [], "a landed batch left a delivery record"


def test_952_o1_consumption_happens_before_the_push_and_is_not_undone_by_its_failure(
    tmp_path: Path, capsys,
):
    """O1 + O2 + O7, the `BranchError` arm."""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    _seed_pitfalls(paths)
    served: list[Path] = []
    curated: list[PitfallsDisposition] = []
    branch = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))

    rc = _tick(
        paths, branch=branch,
        run_lead_author=_serving(served), run_pitfalls=_curating(curated, _disposition()),
    )

    assert rc == 0
    assert served == [run_dir.resolve()], "the serve never ran — every clause below is vacuous"
    assert curated == [_disposition()]
    assert branch.events == ["lease-check", "start", "finish", "cleanup"]
    _assert_consumed(paths, run_dir)
    assert drains._has_lead_author_work(_state1135.state_for_paths(paths)) is False, "consumed work still wakes the lane"
    records = _pending_deliveries(paths)
    assert [r["branch"] for r in records] == [f"lead-author/{branch.batch_id}"]
    assert records[0]["batch_id"] == branch.batch_id
    assert records[0]["reason"] == "push rejected"
    assert records[0]["label"] == "lead_author_drain", "the record names the wrong lane"

    err = capsys.readouterr().err
    expected = (
        f"lead_author_drain: finish_batch failed: push rejected — commit retained on local "
        f"branch lead-author/{branch.batch_id}; delivery is retried next tick, before "
        "anything new is served"
    )
    assert any(line.endswith(expected) for line in err.splitlines()), \
        f"the failure line does not say what was retained and what happens next:\n{err}"
    assert "work stays queued" not in err, "the old line claims a re-queue that never happens"
    assert "nothing consumed" not in err, "the line denies a consumption that happened"
    assert "batch produced no commits" not in err, \
        "a tick with a retained commit reported itself as commit-less"
    assert "opened PR" not in err


def test_952_o1_a_git_fault_from_finish_batch_propagates_after_the_consumption(
    tmp_path: Path, capsys,
):
    """O1 is about the scrub, not the push"""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    _seed_pitfalls(paths)
    branch = _Branch(tmp_path / "worktrees", fail=GitError(["push"], 128, "the remote hung up"))

    with pytest.raises(GitError):
        _tick(
            paths, branch=branch,
            run_lead_author=_serving([]), run_pitfalls=_curating([], _disposition()),
        )

    assert branch.events == ["lease-check", "start", "finish", "cleanup"]
    _assert_consumed(paths, run_dir)
    err = capsys.readouterr().err
    assert "batch not consumed" not in err
    assert "inflight" not in err


def test_952_m1_the_disposition_applies_sentinels_and_unlinks_before_the_pitfalls_rotation(
    tmp_path: Path, monkeypatch,
):
    """M1's apply order — sentinels, then unlinks, then the pitfalls rotation, then the decline bumps — observed through a REAL fault at the third step"""
    monkeypatch.setenv("LEARNING_REPO_LOCK_WAIT_SECONDS", "0")
    paths = loop_paths(tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    queue_before = _seed_pitfalls(paths)
    served: list[Path] = []
    curated: list[PitfallsDisposition] = []
    branch = _Branch(tmp_path / "worktrees")

    with _held(location_path(paths.state_root) / PITFALLS.append_lock) as holder, pytest.raises(TimeoutError):
        _bounded(
            lambda: _tick(
                paths, branch=branch,
                run_lead_author=_serving(served),
                run_pitfalls=_curating(curated, _disposition()),
            ),
            holder=holder,
        )

    assert branch.events == ["lease-check", "start", "cleanup"], \
        "the push ran ahead of, or despite, an apply that did not complete"
    # Before the rotation: applied.
    assert _done_sha(run_dir) == SHA
    assert author_markers(paths) == []
    assert _inflight(paths) == []
    # From the rotation on: not applied.
    assert (location_path(paths.state_root) / PITFALLS.queue).read_bytes() == queue_before
    assert not (location_path(paths.state_root) / PITFALLS.consumed).exists()
    assert _rows_by_id(paths)[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 1, \
        "the decline bump ran ahead of the rotation it is ordered behind"


def test_952_m1_a_malformed_lock_wait_refuses_the_tick_before_any_work(
    tmp_path: Path, monkeypatch,
):
    from defender.learning.core.config import FatalConfigError

    monkeypatch.setenv("LEARNING_REPO_LOCK_WAIT_SECONDS", "soon")
    paths = loop_paths(tmp_path)
    _queued_run("case-1", "run-1", paths)
    served: list[Path] = []
    branch = _Branch(tmp_path / "worktrees")

    with pytest.raises(FatalConfigError):
        _tick(paths, branch=branch, run_lead_author=_serving(served), run_pitfalls=_no_curation)

    assert served == []
    assert branch.events == []
    assert author_markers(paths) == ["case-1.json"]


# --- O7 — delivery is the drain's own retry ---------------------------------------------------


def test_952_o7_the_next_tick_delivers_the_retained_branch_before_serving(
    tmp_path: Path, capsys,
):
    paths = loop_paths(tmp_path)
    _queued_run("case-1", "run-1", paths)
    served: list[Path] = []
    failing = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))
    assert _tick(
        paths, branch=failing, run_lead_author=_serving(served), run_pitfalls=_no_curation,
    ) == 0
    assert len(_pending_deliveries(paths)) == 1
    retained = failing.batch_id
    capsys.readouterr()

    second = _queued_run("case-2", "run-2", paths)
    landing = _Branch(tmp_path / "worktrees")
    assert _tick(
        paths, branch=landing, run_lead_author=_serving(served), run_pitfalls=_no_curation,
    ) == 0

    assert landing.events == ["deliver", "lease-check", "start", "finish", "cleanup"], \
        "delivery must come first, and must not replace the serve"
    assert landing.delivered == [retained]
    assert served[-1] == second.resolve(), "the second tick did not go on to serve new work"
    assert _pending_deliveries(paths) == []
    err = capsys.readouterr().err
    assert (
        f"lead_author_drain: delivered retained branch lead-author/{retained}: opened PR "
        f"PR/{retained}"
    ) in err
    assert served.count(served[0]) == 1, "the retained batch's run was served again"


def test_952_o7_a_delivery_that_keeps_failing_holds_the_writer_lease(tmp_path: Path, capsys):
    """O7's ceiling. While the retained branch cannot be delivered, the lane is PARKED"""
    paths = loop_paths(tmp_path)
    _queued_run("case-1", "run-1", paths)
    served: list[Path] = []
    failing = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))
    assert _tick(
        paths, branch=failing, run_lead_author=_serving(served), run_pitfalls=_no_curation,
    ) == 0
    retained = failing.batch_id
    _queued_run("case-2", "run-2", paths)
    capsys.readouterr()

    for _ in range(3):
        parked = _Branch(tmp_path / "worktrees", deliver_fail=BranchError("token expired"))
        assert _tick(
            paths, branch=parked, run_lead_author=_serving(served), run_pitfalls=_no_curation,
        ) == 0
        assert parked.events == ["deliver"], "a parked tick minted a batch or checked the lease"
        assert parked.delivered == [retained]
    assert len(served) == 1, "an agent ran while delivery was failing"
    assert author_markers(paths) == ["case-2.json"]
    assert len(_pending_deliveries(paths)) == 1
    err = capsys.readouterr().err
    assert err.count(
        f"lead_author_drain: delivery of retained branch lead-author/{retained} failed again: "
        "token expired — it holds the writer lease; nothing served this tick"
    ) == 3

    landing = _Branch(tmp_path / "worktrees")
    assert _tick(
        paths, branch=landing, run_lead_author=_serving(served), run_pitfalls=_no_curation,
    ) == 0
    assert landing.events == ["deliver", "lease-check", "start", "finish", "cleanup"]
    assert len(served) == 2
    assert _pending_deliveries(paths) == []


def test_952_o7_a_retained_branch_with_nothing_to_deliver_is_forgotten(tmp_path: Path, capsys):
    """`deliver` answering `None` — the branch is gone, or has nothing ahead of `origin/main`
    any more — is not a failure: the record is dropped, the log says so, and the tick goes on."""
    paths = loop_paths(tmp_path)
    _queued_run("case-1", "run-1", paths)
    failing = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))
    assert _tick(paths, branch=failing, run_lead_author=_serving([]), run_pitfalls=_no_curation) == 0
    retained = failing.batch_id

    branch = _Branch(tmp_path / "worktrees", deliver_result=None)
    assert _tick(paths, branch=branch, run_lead_author=_serving([]), run_pitfalls=_no_curation) == 0

    assert branch.events == ["deliver"], "with nothing queued the tick stops at the wake gate"
    assert _pending_deliveries(paths) == []
    err = capsys.readouterr().err
    assert (
        f"lead_author_drain: retained branch lead-author/{retained} has nothing left to "
        "deliver — record dropped"
    ) in err


def test_952_o7_each_lane_delivers_only_its_own_records(tmp_path: Path):
    paths = loop_paths(tmp_path)
    _queued_run("case-1", "run-1", paths)
    failing = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))
    assert _tick(paths, branch=failing, run_lead_author=_serving([]), run_pitfalls=_no_curation) == 0
    assert len(_pending_deliveries(paths)) == 1

    append_jsonl(location_path(paths.state_root) / FINDINGS.queue, [{"finding_id": f"f{i}"} for i in range(5)])
    lessons = _Branch(tmp_path / "worktrees", prefix="lessons/", deliver_fail=BranchError("no"))
    rc = drains.author_drain(
        paths, trigger_author=lambda *_a, **_kw: None, branch=lessons,
        start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
    )
    assert rc == 0
    assert lessons.events == ["lease-check", "start", "finish", "cleanup"], \
        "the lessons lane touched the lead-author lane's record"
    assert len(_pending_deliveries(paths)) == 1


# --- O8 — every serve is an attempt -----------------------------------------------------------


def test_952_o8_a_batch_that_never_passes_the_scrub_is_quarantined_at_the_ceiling(
    tmp_path: Path, monkeypatch,
):
    """O8. A run whose curation taints every tree is reclaimed from `inflight/` one tick after another — and each reclaim is one more attempt on the..."""
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "3")
    paths = loop_paths(tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    served: list[Path] = []

    for expected in (1, 2, 3):
        with pytest.raises(box_mod.RunTainted):
            _tick(
                paths, branch=_Branch(tmp_path / "worktrees"), scrub=_tainting,
                run_lead_author=_serving(served), run_pitfalls=_no_curation,
            )
        assert len(served) == expected
        assert _inflight(paths) == ["case-1.json"]
        assert _inflight_attempts(paths, "case-1") == expected

    # The fourth reclaim quarantines at the claim, before the serve seam is reached: the
    # scrub is the ordinary one here, so a serve would have been consumed and would show.
    assert _tick(
        paths, branch=_Branch(tmp_path / "worktrees"),
        run_lead_author=_serving(served), run_pitfalls=_no_curation,
    ) == 0
    assert len(served) == 3, "the run was served past the ceiling"
    assert _inflight(paths) == []
    assert not _done(run_dir).exists()
    failed = marker_body(location_path(paths.state_root) / "author-queue" / "failed" / "case-1.json")
    assert failed["failed"] == "served 3 time(s) without being recorded done"
    assert (failed["tenant_id"], failed["run_id"]) == _address(run_dir)
    assert drains._has_lead_author_work(_state1135.state_for_paths(paths)) is False


# --- O6 — a fresher same-case request survives a failed push --------------------------------


def test_952_o6_a_failed_push_neither_destroys_nor_supersedes_a_fresher_request(
    tmp_path: Path,
):
    """O6 + M2. The claim frees the top-level slot so a re-ask landing mid-serve has somewhere to go."""
    paths = loop_paths(tmp_path)
    first = _queued_run("case-A", "run-1", paths)
    second = _state1135.curation_run_dir("run-2")
    served: list[Path] = []

    def re_ask() -> None:
        # The operator re-investigates the case while the lane is curating it...
        _state1135.enqueue_case(_state1135.state_for_paths(paths), "case-A", second)

    failing = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))
    assert _tick(
        paths, branch=failing, run_pitfalls=_no_curation,
        run_lead_author=_serving(served, before=re_ask),
    ) == 0
    assert served == [first.resolve()]

    assert author_markers(paths) == ["case-A.json"]
    fresher = marker_body(location_path(paths.state_root) / "author-queue" / "case-A.json")
    assert (fresher["tenant_id"], fresher["run_id"]) == _address(second), (
        "the failed push replaced the fresher curation request with the stale run dir"
    )
    assert "attempts" not in fresher
    assert _inflight(paths) == [], "the consumed claim was left in inflight/"
    assert _done_sha(first) == SHA
    assert not (location_path(paths.state_root) / "author-queue" / "failed").exists()

    landing = _Branch(tmp_path / "worktrees")
    assert _tick(
        paths, branch=landing, run_pitfalls=_no_curation, run_lead_author=_serving(served),
    ) == 0
    assert served == [first.resolve(), second.resolve()], \
        "the second tick must serve the fresher request, and the stale run only once"
    assert landing.events == ["deliver", "lease-check", "start", "finish", "cleanup"]
    assert author_markers(paths) == []
    assert _inflight(paths) == []
    assert drains._has_lead_author_work(_state1135.state_for_paths(paths)) is False


# --- O2 — the lessons lane's failure line makes no claim about markers or pitfalls ------------


# --- O5 / M4 — the curators' switch: consume now, or hand the consumption back ---------------


def _lead(**kw) -> ExecutedLead:
    base = dict(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id="wazuh.newthing", system="wazuh", verb="newthing", params={}, raw_command="cli",
        goal_text="", what_to_summarize=(), raw_ref=None,
        payload_status="ok", payload_digest="", error_class=None,
    )
    base.update(kw)
    return ExecutedLead(**base)


def _curator_deps(repo: Path, state: Path, **overrides):
    """Production lead-author deps over a seeded, committed skills tree, with the two tables
    bypassed (their own suite)."""
    deps = lead_deps(LoopPaths(repo_root=repo, state_dir=state))
    seams = dict(
        extract=lambda _rd: ([], [_lead()]),
        synthesize=lambda executed, skills=None, where=None, catalog=None, systems=None: [],
        discover_system_drafts=lambda: [],
    )
    seams.update(overrides)
    return replace(deps, **seams)


_CATALOG = "defender/skills/gather/queries"


def _promoting_agent(repo: Path):
    def agent(_rd, _handoffs, _pending, *, box=None) -> int:
        (repo / _CATALOG / "wazuh" / "newthing.md").write_text(
            query_template("wazuh.newthing", "established"), encoding="utf-8",
        )
        (repo / _CATALOG / "wazuh" / "_draft" / "newthing.md").unlink()
        return 0

    return agent


def _agent_must_not_run(*_a, **_kw) -> int:
    raise AssertionError("the agent was spawned on a path that resolves no handoff")


def _without_at(text: str) -> str:
    """The sentinel minus its timestamp line, so two renderings of one sha compare."""
    return "\n".join(ln for ln in text.splitlines() if not ln.startswith("at: "))


@pytest.mark.parametrize("deferred", [False, True], ids=["default-writes", "on_done-defers"])
def test_952_m4_the_post_commit_sentinel_is_written_or_handed_over(
    tmp_path: Path, deferred: bool,
):
    """O5 + M4, the `_run_locked` write site (after the commit)."""
    repo = seed_skills_repo(tmp_path / "repo")
    run_dir = _state1135.curation_run_dir("lead-run")
    deps = _curator_deps(
        repo, tmp_path / "state",
        invoke_agent=_promoting_agent(repo),
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
    )
    head_before = _git.git_head_sha(repo)
    captured: list[str | None] = []

    run = _state1135.run_of(run_dir)
    rc = lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps,
                         on_done=captured.append) if deferred \
        else lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)

    assert rc == 0
    sha = _git.git_head_sha(repo)
    assert sha != head_before, "the commit is not deferred — only the sentinel is"
    if deferred:
        assert not _done(run_dir).exists(), "deferred mode still wrote the sentinel"
        assert captured == [sha]
    else:
        assert captured == []
        assert _done_sha(run_dir) == sha
        assert _done(run_dir).read_text(encoding="utf-8").endswith("commit_made: True\n")
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file(), \
        "the pitfalls_collected marker is NOT deferred (O4)"


@pytest.mark.parametrize("deferred", [False, True], ids=["default-writes", "on_done-defers"])
def test_952_m4_the_none_resolved_sentinel_is_written_or_handed_over(
    tmp_path: Path, deferred: bool,
):
    repo = seed_skills_repo(tmp_path / "repo")
    run_dir = _state1135.curation_run_dir("lead-run")
    deps = _curator_deps(
        repo, tmp_path / "state",
        invoke_agent=_agent_must_not_run,
        build_handoff=lambda rd, ex, jl=None, **_: [],
    )
    head_before = _git.git_head_sha(repo)
    captured: list[str | None] = []

    run = _state1135.run_of(run_dir)
    rc = lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps,
                         on_done=captured.append) if deferred \
        else lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)

    assert rc == 0
    assert _git.git_head_sha(repo) == head_before, "a none-resolved run made a commit"
    if deferred:
        assert not _done(run_dir).exists()
        assert captured == [None]
    else:
        assert captured == []
        assert _done_sha(run_dir) == "none"
        assert _done(run_dir).read_text(encoding="utf-8").endswith("commit_made: False\n")


# --- O5 / M4 — the pitfalls curator hands its partition back, or consumes as today -----------


@pytest.fixture
def pitfalls_repo(tmp_path: Path, monkeypatch) -> Path:
    """A committed worktree carrying the reducer surface (as `test_870_partition.scene`), with
    the threshold at 1 so the tick is about the PARTITION rather than the gate."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=("elastic", "cmdb"), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")
    return repo


def _three_way_batch(paths: LoopPaths) -> None:
    """One row per partition: a declared-system row the curator teaches (committed), a reducer
    row the curator is offered and declines (held), and an undeclared-system row nothing can
    ever teach (unattributable)."""
    persist.append_pitfalls(
        [
            pitfall_row("c:l-000:0", "elastic"),
            shim_row("h:l-003:0"),
            pitfall_row("u:l-001:0", "newsys"),
        ],
        state=_state1135.state_for_paths(paths),
    )


def test_952_m4_run_pitfalls_hands_its_partition_to_on_curated_and_consumes_nothing_committed(
    pitfalls_repo: Path, tmp_path: Path,
):
    """O5 + M4 + O4 at the pitfalls curator."""
    paths = LoopPaths(repo_root=pitfalls_repo, state_dir=tmp_path / "state")
    _three_way_batch(paths)
    head_before = _git.git_head_sha(pitfalls_repo)
    spawn = Spawn(curate_execution_md("elastic"))
    captured: list[PitfallsDisposition] = []

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn, on_curated=captured.append,
                                         trees=lead_trees(paths)) == 0

    sha = _git.git_head_sha(pitfalls_repo)
    assert sha != head_before, "the commit is not deferred — only the consumption is"
    assert [h.get("surface") for h in spawn.handoffs] == ["system", "reducer"], \
        "the reducer offer was never made, so the held arm is vacuous"
    assert captured == [
        PitfallsDisposition(committed_ids=("c:l-000:0",), sha=sha, held_ids=("h:l-003:0",)),
    ]

    assert sorted(queue_ids(paths)) == ["c:l-000:0", "h:l-003:0"], \
        "a deferred tick rotated the committed row, or dropped the held one"
    rows = _rows_by_id(paths)
    assert pitfalls_curator.OFFERS_DECLINED_KEY not in rows["h:l-003:0"], \
        "the decline was counted on a tick whose consumption was handed back"
    consumed = consumed_by_id(paths)
    assert set(consumed) == {"u:l-001:0"}, "the committed row reached the ledger, or the unattributable one did not"
    assert consumed["u:l-001:0"]["consumed_category"] == "consumed_unattributable"
    assert graveyard_by_id(paths)["u:l-001:0"]["deadletter_reason"] == "undeclared-system:newsys"

    assert captured[0].apply(_state1135.state_for_paths(paths), timeout_seconds=5) == 0
    consumed = consumed_by_id(paths)
    assert consumed["c:l-000:0"]["consumed_category"] == "consumed_committed"
    assert consumed["c:l-000:0"]["consumed_commit"] == sha
    assert queue_ids(paths) == ["h:l-003:0"]
    assert _rows_by_id(paths)["h:l-003:0"][pitfalls_curator.OFFERS_DECLINED_KEY] == 1


# --- the rotation deadline ------------------------------------------------------------------


def test_952_m1_the_deferred_rotation_reaches_the_queue_lock_with_a_deadline(tmp_path: Path):
    """M1: the drain must pass a deadline into the rotation (`persist.queue_lock`"""
    paths = loop_paths(tmp_path)
    queue_before = _seed_pitfalls(paths)
    disposition = _disposition()

    with _held(location_path(paths.state_root) / PITFALLS.append_lock) as holder:
        with pytest.raises(TimeoutError):
            _bounded(lambda: disposition.apply(_state1135.state_for_paths(paths), timeout_seconds=0), holder=holder)
        assert (location_path(paths.state_root) / PITFALLS.queue).read_bytes() == queue_before
        assert not (location_path(paths.state_root) / PITFALLS.consumed).exists()

        with pytest.raises(TimeoutError):
            _bounded(
                lambda: persist.rotate_pitfalls(
                    [COMMITTED_ID], SHA, state=_state1135.state_for_paths(paths), timeout_seconds=0,
                ),
                holder=holder,
            )
        assert (location_path(paths.state_root) / PITFALLS.queue).read_bytes() == queue_before

    assert disposition.apply(_state1135.state_for_paths(paths), timeout_seconds=0) == 0
    consumed = consumed_by_id(paths)
    assert consumed[COMMITTED_ID]["consumed_category"] == "consumed_committed"
    assert consumed[COMMITTED_ID]["consumed_commit"] == SHA
    rows = _rows_by_id(paths)
    assert list(rows) == [HELD_ID]
    assert rows[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 2


def test_952_m1_the_immediate_rotation_is_bounded_under_the_drain_and_unbounded_by_hand(
    pitfalls_repo: Path, tmp_path: Path,
):
    """The deadline covers the rotations the curator makes AT ONCE too — the `consumed_unattributable` rotation runs inside the drain's `do_work`, under..."""
    paths = LoopPaths(repo_root=pitfalls_repo, state_dir=tmp_path / "state")
    persist.append_pitfalls([pitfall_row("u:l-001:0", "newsys")], state=_state1135.state_for_paths(paths))
    queue_before = (location_path(paths.state_root) / PITFALLS.queue).read_bytes()

    with _held(location_path(paths.state_root) / PITFALLS.append_lock) as holder, pytest.raises(TimeoutError):
        _bounded(
            lambda: pitfalls_curator.run_pitfalls(
                paths=paths, invoke=_agent_must_not_run, lock_wait_seconds=0,
                trees=lead_trees(paths),
            ),
            holder=holder,
        )
    assert (location_path(paths.state_root) / PITFALLS.queue).read_bytes() == queue_before

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_agent_must_not_run,
                                         trees=lead_trees(paths)) == 0
    assert queue_ids(paths) == []
    assert consumed_by_id(paths)["u:l-001:0"]["consumed_category"] == "consumed_unattributable"


# --- O5 / M5 — the drain holds the per-author queue lock for the whole tick ------------------


def test_952_m5_the_drain_holds_the_queue_lock_across_the_serve(tmp_path: Path):
    """O5 + M5. Deferring the sentinel to the drain opens a gap — the remaining serves, the pitfalls curation, box teardown — in which a by-hand..."""
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _queued_run("case-1", "run-1", paths)
    by_hand = _state1135.curation_run_dir("by-hand")
    (by_hand / "gather_raw").mkdir()
    served: list[Path] = []
    mid_serve: list[int] = []

    def probe() -> None:
        mid_serve.append(lead_author.run(_state1135.run_of(by_hand), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths))

    assert _tick(
        paths, branch=_Branch(tmp_path / "worktrees"), run_pitfalls=_no_curation,
        run_lead_author=_serving(served, before=probe),
    ) == 0
    assert served == [run_dir.resolve()]
    assert mid_serve == [lead_author.QUEUE_LOCK_SKIP_RC], \
        "a by-hand run started during a drain tick did not skip on the queue lock"
    assert author_markers(paths) == [], "the tick must still serve under the lock it holds"
    assert _inflight(paths) == [], "the tick must still consume under the lock it holds"

    # Positive control: the lock the tick held IS the file a by-hand run locks. Held here the
    # way a second process would hold it, the same call skips; released, it does not.
    with _held((location_path(paths.state_root) / LEAD_QUEUE_LOCK.file).parent / ".lock"):
        assert lead_author.run(_state1135.run_of(by_hand), label=LEAD_AUTHOR_DRAIN_LABEL,
                               paths=paths) == lead_author.QUEUE_LOCK_SKIP_RC
        assert not (by_hand / "lead_author").exists(), "a skipped by-hand run wrote state"
    assert lead_author.run(_state1135.run_of(by_hand), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths) == 0
    assert (by_hand / "lead_author" / "pitfalls_collected").is_file(), \
        "outside a tick the by-hand run must serve, not skip"


def test_952_m5_a_tick_started_under_a_held_queue_lock_claims_nothing(tmp_path: Path, capsys):
    """M5's other direction"""
    paths = loop_paths(tmp_path)
    _queued_run("case-1", "run-1", paths)
    _queued_run("case-2", "run-2", paths)
    served: list[Path] = []
    branch = _Branch(tmp_path / "worktrees")

    with _held((location_path(paths.state_root) / LEAD_QUEUE_LOCK.file).parent / ".lock"):
        rc = _tick(
            paths, branch=branch, run_pitfalls=_no_curation,
            run_lead_author=_serving(served),
        )

    assert rc == 0
    assert served == [], "the tick served under a lock another run holds"
    assert author_markers(paths) == ["case-1.json", "case-2.json"]
    assert _inflight(paths) == [], "a skipped tick claimed a marker"
    for name in ("case-1.json", "case-2.json"):
        assert "attempts" not in marker_body(location_path(paths.state_root) / "author-queue" / name), \
            "a skip spent one of the request's attempts"
    assert "start" not in branch.events, "a skipped tick minted a batch"
    err = capsys.readouterr().err
    assert "lead_author_drain: another lead-author run holds the queue lock — skipping" in err

    # Positive control: released, the same tick serves.
    assert _tick(
        paths, branch=_Branch(tmp_path / "worktrees"), run_pitfalls=_no_curation,
        run_lead_author=_serving(served),
    ) == 0
    assert len(served) == 2
    assert author_markers(paths) == []


def test_952_m5_the_drain_enters_the_curator_past_its_own_lock(tmp_path: Path):
    """M5's wiring: `_invoke_lead_author` — the drain's production `run_lead_author` — enters the curator through `run_under_held_queue_lock`, past the..."""
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    drained = _state1135.curation_run_dir("drained")
    by_hand = _state1135.curation_run_dir("by-hand")
    for d in (drained, by_hand):
        (d / "gather_raw").mkdir()
    captured: list[str | None] = []

    with _held((location_path(paths.state_root) / LEAD_QUEUE_LOCK.file).parent / ".lock"):
        drains._invoke_lead_author(paths, _state1135.state_for_paths(paths),
                                   _state1135.run_of(drained), on_done=captured.append,
                                   label=LEAD_AUTHOR_DRAIN_LABEL)
        assert (drained / "lead_author" / "pitfalls_collected").is_file(), \
            "the curator never ran past the lock the drain is supposed to have exempted it from"
        assert captured == [], "an empty run dir is the clean path: no sentinel to hand over"
        assert not _done(drained).exists()

        assert lead_author.run(_state1135.run_of(by_hand), label=LEAD_AUTHOR_DRAIN_LABEL,
                               paths=paths) == lead_author.QUEUE_LOCK_SKIP_RC
        assert not (by_hand / "lead_author").exists(), "a skipped by-hand run wrote state"


# --- the adversary round: ways the suite above was greened while betraying intent -----------


class _ProbingBranch(_Branch):
    """`_Branch` whose `finish_batch` first records what a by-hand run answers at that
    moment — after the consumption, but still inside the tick M5's lock spans."""

    def __init__(self, base: Path, *, probe, **kw) -> None:
        super().__init__(base, **kw)
        self._probe = probe
        self.probed: list[int] = []

    def finish_batch(self, batch_id: str, wt: Path):
        self.probed.append(self._probe())
        return super().finish_batch(batch_id, wt)


def test_952_c_the_queue_lock_is_held_through_curation_and_finish_batch(tmp_path: Path):
    """Kills C. A lock released right after `do_work` greened the M5 test, which only probes from inside the serve."""
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _queued_run("case-1", "run-1", paths)
    by_hand = _state1135.curation_run_dir("by-hand")
    (by_hand / "gather_raw").mkdir()
    served: list[Path] = []
    in_curation: list[int] = []

    def probe() -> int:
        return lead_author.run(_state1135.run_of(by_hand), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths)

    def curate(_paths, _state, *, box=None, on_curated):
        in_curation.append(probe())
        return 0

    branch = _ProbingBranch(tmp_path / "worktrees", probe=probe)
    assert _tick(paths, branch=branch, run_lead_author=_serving(served), run_pitfalls=curate) == 0

    assert served == [run_dir.resolve()]
    assert in_curation == [lead_author.QUEUE_LOCK_SKIP_RC], \
        "a by-hand run during the pitfalls curation did not skip on the queue lock"
    assert branch.probed == [lead_author.QUEUE_LOCK_SKIP_RC], \
        "a by-hand run during finish_batch did not skip on the queue lock"
    assert not (by_hand / "lead_author").exists(), "a skipped by-hand run wrote state"
    assert author_markers(paths) == []
    assert _inflight(paths) == []
    assert _done_sha(run_dir) == SHA

    assert lead_author.run(_state1135.run_of(by_hand), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths) == 0
    assert (by_hand / "lead_author" / "pitfalls_collected").is_file()


def test_952_d_a_failed_sentinel_write_leaves_the_claim_in_inflight(tmp_path: Path):
    """Kills D. Unlinking the claims BEFORE writing the sentinels greened the ordering test, which faults at the rotation and so only ever sees steps 1–2..."""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    queue_before = _seed_pitfalls(paths)
    (run_dir / "lead_author").write_text("not a directory\n", encoding="utf-8")
    served: list[Path] = []
    curated: list[PitfallsDisposition] = []
    branch = _Branch(tmp_path / "worktrees")

    with pytest.raises(OSError, match="lead_author"):
        _tick(
            paths, branch=branch,
            run_lead_author=_serving(served), run_pitfalls=_curating(curated, _disposition()),
        )

    assert served == [run_dir.resolve()]
    assert branch.events == ["lease-check", "start", "cleanup"], \
        "the push ran on a batch whose apply did not complete"
    assert (run_dir / "lead_author").is_file(), "the blocking file was clobbered"
    assert _inflight(paths) == ["case-1.json"], \
        "the claim was unlinked ahead of a sentinel write that then failed"
    assert author_markers(paths) == []
    assert (location_path(paths.state_root) / PITFALLS.queue).read_bytes() == queue_before
    assert not (location_path(paths.state_root) / PITFALLS.consumed).exists()
    assert _rows_by_id(paths)[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 1
