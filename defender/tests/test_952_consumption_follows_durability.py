"""#952 — consumption follows durability in the lead-author lane.

The lane's three consumption points — the served marker's unlink, the pitfalls rows'
`consumed_committed` rotation (with the held rows' `offers_declined` bump riding behind it),
and the per-run `done` sentinel under the SHARED run dir — all happened inside `do_work`,
before the scrub had judged the tree and before `finish_batch` pushed anything. A rejected
push then logged "work stays queued" over a queue that had already been emptied, and the
commit sat orphaned on a local branch nothing named.

The durability event is the LOCAL COMMIT, not the push: once the tree has passed the scrub
the curators' commits sit on a local branch on the same disk as the queues — as durable as
the state being consumed. Every test here is one obligation of that contract, named in its
docstring:

  O1  shared state is consumed once the batch's tree has passed the scrub — never before it
      (a taint, a box fault), and never contingent on the push;
  O2  a push or PR that fails is RECORDED and the log says so truthfully, per lane — the commit
      is retained, delivery is retried, nothing is re-served;
  O3  a tick that lands consumes exactly what it served — today's success-path census;
  O4  failure dispositions stay immediate (the `consumed_unattributable` rotation and its
      graveyard, the `pitfalls_collected` marker);
  O5  a by-hand `lead_author` run still consumes at once, and cannot re-serve a run the drain
      has committed but not yet recorded (the drain holds the per-author queue lock for the tick);
  O6  a fresher same-case request that lands mid-tick is never destroyed by a stale one;
  O7  delivery is the drain's own retry: the next tick of the lane delivers a retained branch
      before it serves anything, an undelivered branch holds the writer lease while delivery
      keeps failing, and no agent runs for it;
  O8  every serve is an attempt: a batch that never reaches the apply is reclaimed a bounded
      number of times, then quarantined.

Every fake enters through a shipped seam — the drain's `run_lead_author=` / `run_pitfalls=` /
`branch=` / `scrub=` kwargs, `lead_author.run(deps=..., on_done=...)`,
`run_pitfalls(invoke=..., on_curated=...)` — and every fault is a REAL one through the real
primitive: a `BranchError` / `GitError` / `RunTainted` raised where production raises them, a
lock held with `fcntl.flock` the way a second process holds it. Nothing is `setattr`-patched.

Every negative here (a marker still present, a row unchanged, a counter not bumped, a
sentinel absent) is paired with a positive control on the same address under the
complementary condition — the green tick, the released lock, the default mode.
"""
from __future__ import annotations

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
from defender.learning.core import drains, markers, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead
from defender.learning.leads.pitfalls_curator import PitfallsDisposition
from defender.runtime import box as box_mod
from defender.tests._declared869 import seed_executed_query
from defender.tests._declared870 import (
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
from defender.tests._repo import query_template, seed_skills_repo
from defender.tests._spec791 import (
    SpecBranch,
    author_markers,
    loop_paths,
    marker_body,
    noop_scrub,
    noop_start_box,
    noop_stop_box,
)


# --- substrate -------------------------------------------------------------------------------

#: The commit a served lead-author run hands the drain in place of writing the sentinel
#: itself; the sentinel the drain then writes names it.
SHA = "abc123"

COMMITTED_ID = "p:committed:0"
HELD_ID = "p:held:0"

#: The not-consumed log's retained-counts clause for the one-marker, one-committed, one-held
#: tick every drain-level test here seeds — spelled as a LITERAL, never read off the
#: disposition, so a summary that miscounts cannot agree with the test that checks it.
RETAINED = (
    "1 served marker(s) left in inflight/, 1 committed pitfall row(s) left queued, "
    "1 held row(s) not bumped"
)

_SENTINEL_RE = re.compile(r"\Acommit: (?P<sha>\S+)\nat: \S+\ncommit_made: (?P<made>True|False)\n\Z")


class _Branch(SpecBranch):
    """`SpecBranch` plus what this spec needs: the batch id the tick minted (the failure log
    names `lead-author/<batch_id>`, so the assertion needs the real one), a `finish_batch`
    that raises the configured fault or returns `None` for a zero-commit batch, a `deliver`
    that records the retry and raises its own configured fault, and the `quarantine_dir` the
    taint path preserves into."""

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


def _queued_run(tmp_path: Path, case_id: str, name: str, paths: LoopPaths) -> Path:
    run_dir = tmp_path / "runs" / name
    run_dir.mkdir(parents=True, exist_ok=True)
    markers.enqueue_case_for_curation(case_id, run_dir, paths)
    return run_dir


def _seed_pitfalls(paths: LoopPaths) -> bytes:
    """One committable system row and one held reducer row that has ALREADY been declined
    once — so "`offers_declined` not bumped" compares against a real value, and the green
    tick's bump has somewhere to go. Returns the queue file's bytes as seeded."""
    persist.append_pitfalls(
        [
            pitfall_row(COMMITTED_ID, "elastic"),
            shim_row(HELD_ID, **{pitfalls_curator.OFFERS_DECLINED_KEY: 1}),
        ],
        paths=paths,
    )
    return paths.pitfalls.file.read_bytes()


def _disposition(sha: str | None = SHA) -> PitfallsDisposition:
    return PitfallsDisposition(committed_ids=(COMMITTED_ID,), sha=sha, held_ids=(HELD_ID,))


def _serving(served: list[Path], *, done: bool = True, before=None):
    """A `run_lead_author` fake that simulates a served run: it hands the drain the commit
    (or nothing, on the clean path that records no sentinel today) through the `on_done`
    seam. `on_done` is keyword-REQUIRED so a drain that stopped passing it fails here, at the
    seam, rather than silently serving without one."""

    def serve(_paths, run_dir, *, box=None, on_done):
        served.append(run_dir)
        if before is not None:
            before()
        if done:
            on_done(SHA)

    return serve


def _curating(curated: list[PitfallsDisposition], disposition: PitfallsDisposition):
    """A `run_pitfalls` fake that simulates a curation: it hands its partition to the drain
    through `on_curated` and returns 0, exactly as the real curator does in deferred mode."""

    def curate(_paths, *, box=None, on_curated):
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
    return {str(r["pitfall_id"]): r for r in persist.read_pitfalls(paths)}


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
    d = paths.author_queue_dir / "inflight"
    return sorted(p.name for p in d.glob("*.json")) if d.is_dir() else []


def _inflight_attempts(paths: LoopPaths, case: str) -> int:
    return int(marker_body(paths.author_queue_dir / "inflight" / f"{case}.json").get("attempts", 0))


def _pending_deliveries(paths: LoopPaths) -> list[dict]:
    d = paths.pending_delivery_dir
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
    """Call `fn` and refuse to wait forever on it.

    The lock this test holds is what `fn` contends on, and a call that reaches the flock with
    NO deadline blocks until that lock is released — which nothing in the test does until `fn`
    returns, so the hang IS the failure this guard turns into a red test. Run on a thread; a
    call still running after `seconds` has the lock released for it (so the worker can finish
    and the process can exit) and fails the test naming the missing deadline."""
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
    """O1's shared-state clause, in one place so every pre-apply exit asserts the same thing:
    the served marker is still claimed (in `inflight/`, not back at the top level, not
    dead-lettered), the pitfalls queue is byte-identical (rows AND counters), nothing reached
    the consumed ledger, no `done` sentinel exists for the run, and the wake gate still sees
    the work."""
    assert _inflight(paths) == [f"{case}.json"], "the served marker left inflight/"
    assert Path(marker_body(paths.author_queue_dir / "inflight" / f"{case}.json")["run_dir"]) \
        == run_dir.resolve()
    assert author_markers(paths) == [], "the claim was handed back to the top level"
    assert not (paths.author_queue_dir / "failed").exists(), "the served run was dead-lettered"
    assert paths.pitfalls.file.read_bytes() == queue_before, (
        "the pitfalls queue changed on a tick that consumed nothing (a rotation, or a bumped "
        f"`{pitfalls_curator.OFFERS_DECLINED_KEY}`)"
    )
    assert _rows_by_id(paths)[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 1
    assert not paths.pitfalls.consumed.exists(), "a row reached the consumed ledger"
    assert not _done(run_dir).exists(), (
        "the done sentinel was written under the shared run dir — the reclaimed marker will "
        "be served as 'already processed' next tick and unlinked anyway"
    )
    assert drains._has_lead_author_work(paths) is True, "the queue went quiet on retained work"


def _assert_consumed(paths: LoopPaths, run_dir: Path, *, done: bool = True) -> None:
    """O3's census, in one place: the marker is gone from the top level and from `inflight/`;
    the sentinel under the shared run dir names the commit the curator handed over (or, on
    the clean path that records none today, no sentinel at all); the committed row is in the
    consumed ledger as `consumed_committed` under the curation's sha; and the held row's
    `offers_declined` moved from 1 to 2 while the row stayed queued."""
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
    tmp_path: Path, said, fault: str,
):
    """O1, the exits BEFORE the apply. The scrub's `RunTainted` and a box fault from the
    teardown both mean the curators' commits are not sound to deliver — so a tick that served
    a marker and curated the pitfalls queue leaves every piece of shared state exactly as it
    found it, propagates the fault (the signal is load-bearing), and logs what stays for the
    next tick's reclaim exactly once — and the reclaim is one attempt older (O8).

    Both fakes RECORD that they ran, so the negatives below are about a tick that did the
    work, not one that skipped it. The green tick beside this test is the positive control on
    every address."""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run(tmp_path, "case-1", "run-1", paths)
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

    err = said.readouterr().err
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
    """O3, the positive control for every O1 negative. The identical tick whose scrub passes
    consumes exactly today's census (`_assert_consumed`), and then pushes.

    `finish_batch` returning `None` — `commits_ahead == 0`, nothing to push — changes nothing
    about the consumption: it happened before the push was attempted, and the sentinel
    records the run as done."""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run(tmp_path, "case-1", "run-1", paths)
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
    tmp_path: Path, said,
):
    """O1 + O2 + O7, the `BranchError` arm. A tick whose tree passed the scrub consumes what
    it served BEFORE `finish_batch` runs, and a push that is then rejected undoes none of it:
    the work is done, its commit is on a local branch, and the only thing outstanding is
    delivery — recorded for the next tick, and logged as exactly that. No `inflight/` claim,
    no re-serve, none of the old "work stays queued" wording."""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run(tmp_path, "case-1", "run-1", paths)
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
    assert drains._has_lead_author_work(paths) is False, "consumed work still wakes the lane"
    records = _pending_deliveries(paths)
    assert [r["branch"] for r in records] == [f"lead-author/{branch.batch_id}"]
    assert records[0]["batch_id"] == branch.batch_id
    assert records[0]["reason"] == "push rejected"

    err = said.readouterr().err
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
    tmp_path: Path, said,
):
    """O1 is about the scrub, not the push: a `GitError` raised by `finish_batch` itself
    (`commits_ahead` runs outside its own `try`) propagates as the systemic fault it is —
    but the consumption it interrupts has already happened, because the tree had passed the
    scrub. Nothing is logged as retained, because nothing is."""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run(tmp_path, "case-1", "run-1", paths)
    _seed_pitfalls(paths)
    branch = _Branch(tmp_path / "worktrees", fail=GitError(["push"], 128, "the remote hung up"))

    with pytest.raises(GitError):
        _tick(
            paths, branch=branch,
            run_lead_author=_serving([]), run_pitfalls=_curating([], _disposition()),
        )

    assert branch.events == ["lease-check", "start", "finish", "cleanup"]
    _assert_consumed(paths, run_dir)
    err = said.readouterr().err
    assert "batch not consumed" not in err
    assert "inflight" not in err


def test_952_m1_the_disposition_applies_sentinels_and_unlinks_before_the_pitfalls_rotation(
    tmp_path: Path, monkeypatch,
):
    """M1's apply order — sentinels, then unlinks, then the pitfalls rotation, then the decline
    bumps — observed through a REAL fault at the third step: the pitfalls append lock is held
    by this test and the drain's configured lock wait is zero, so the rotation's deadline
    expires. Everything before it is on disk; everything from it on is not — and the push
    never runs, because the apply sits ahead of it.

    That order is what makes a partial apply safe (design: "a partial apply on the lead-author
    half is a no-op re-serve, and on the pitfalls half a re-curation"). The expiry propagates
    rather than being swallowed. The tick beside this one, with the lock free, is the positive
    control: the same disposition rotates and bumps."""
    monkeypatch.setenv("LEARNING_REPO_LOCK_WAIT_SECONDS", "0")
    paths = loop_paths(tmp_path)
    run_dir = _queued_run(tmp_path, "case-1", "run-1", paths)
    queue_before = _seed_pitfalls(paths)
    served: list[Path] = []
    curated: list[PitfallsDisposition] = []
    branch = _Branch(tmp_path / "worktrees")

    with _held(paths.pitfalls.append_lock) as holder, pytest.raises(TimeoutError):
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
    assert paths.pitfalls.file.read_bytes() == queue_before
    assert not paths.pitfalls.consumed.exists()
    assert _rows_by_id(paths)[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 1, \
        "the decline bump ran ahead of the rotation it is ordered behind"


def test_952_m1_a_malformed_lock_wait_refuses_the_tick_before_any_work(
    tmp_path: Path, monkeypatch,
):
    """The wait the apply passes into the rotation is configuration, and configuration is
    read at the tick's entry — never after an agent has run and a commit exists. Malformed,
    it refuses the tick before a worktree is minted or a marker claimed."""
    from defender.learning.core.config import FatalConfigError

    monkeypatch.setenv("LEARNING_REPO_LOCK_WAIT_SECONDS", "soon")
    paths = loop_paths(tmp_path)
    _queued_run(tmp_path, "case-1", "run-1", paths)
    served: list[Path] = []
    branch = _Branch(tmp_path / "worktrees")

    with pytest.raises(FatalConfigError):
        _tick(paths, branch=branch, run_lead_author=_serving(served), run_pitfalls=_no_curation)

    assert served == []
    assert branch.events == []
    assert author_markers(paths) == ["case-1.json"]


# --- O7 — delivery is the drain's own retry ---------------------------------------------------


def test_952_o7_the_next_tick_delivers_the_retained_branch_before_serving(
    tmp_path: Path, said,
):
    """O7. The tick after a rejected push delivers the retained branch FIRST — push and PR
    from the branch alone, no agent — then goes on to serve whatever is queued. The record
    is removed once delivered, and the log names the PR."""
    paths = loop_paths(tmp_path)
    _queued_run(tmp_path, "case-1", "run-1", paths)
    served: list[Path] = []
    failing = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))
    assert _tick(
        paths, branch=failing, run_lead_author=_serving(served), run_pitfalls=_no_curation,
    ) == 0
    assert len(_pending_deliveries(paths)) == 1
    retained = failing.batch_id
    said.readouterr()

    second = _queued_run(tmp_path, "case-2", "run-2", paths)
    landing = _Branch(tmp_path / "worktrees")
    assert _tick(
        paths, branch=landing, run_lead_author=_serving(served), run_pitfalls=_no_curation,
    ) == 0

    assert landing.events == ["deliver", "lease-check", "start", "finish", "cleanup"], \
        "delivery must come first, and must not replace the serve"
    assert landing.delivered == [retained]
    assert served[-1] == second.resolve(), "the second tick did not go on to serve new work"
    assert _pending_deliveries(paths) == []
    err = said.readouterr().err
    assert (
        f"lead_author_drain: delivered retained branch lead-author/{retained}: opened PR "
        f"PR/{retained}"
    ) in err
    assert served.count(served[0]) == 1, "the retained batch's run was served again"


def test_952_o7_a_delivery_that_keeps_failing_holds_the_writer_lease(tmp_path: Path, said):
    """O7's ceiling. While the retained branch cannot be delivered, the lane is PARKED: no
    lease check, no worktree, no box, no agent, the queued marker untouched — exactly as an
    open PR parks it. The record stays. Released (the delivery succeeds), the same tick
    serves. Nothing here re-runs an agent for the retained batch, however many ticks pass."""
    paths = loop_paths(tmp_path)
    _queued_run(tmp_path, "case-1", "run-1", paths)
    served: list[Path] = []
    failing = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))
    assert _tick(
        paths, branch=failing, run_lead_author=_serving(served), run_pitfalls=_no_curation,
    ) == 0
    retained = failing.batch_id
    _queued_run(tmp_path, "case-2", "run-2", paths)
    said.readouterr()

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
    err = said.readouterr().err
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


def test_952_o7_a_retained_branch_with_nothing_to_deliver_is_forgotten(tmp_path: Path, said):
    """`deliver` answering `None` — the branch is gone, or has nothing ahead of `origin/main`
    any more — is not a failure: the record is dropped, the log says so, and the tick goes on."""
    paths = loop_paths(tmp_path)
    _queued_run(tmp_path, "case-1", "run-1", paths)
    failing = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))
    assert _tick(paths, branch=failing, run_lead_author=_serving([]), run_pitfalls=_no_curation) == 0
    retained = failing.batch_id

    branch = _Branch(tmp_path / "worktrees", deliver_result=None)
    assert _tick(paths, branch=branch, run_lead_author=_serving([]), run_pitfalls=_no_curation) == 0

    assert branch.events == ["deliver"], "with nothing queued the tick stops at the wake gate"
    assert _pending_deliveries(paths) == []
    err = said.readouterr().err
    assert (
        f"lead_author_drain: retained branch lead-author/{retained} has nothing left to "
        "deliver — record dropped"
    ) in err


def test_952_o7_each_lane_delivers_only_its_own_records(tmp_path: Path):
    """The two lanes share one record dir and one `_run_worktree_batch`, and each runs under
    its own drain lock — so the lessons lane must neither deliver nor be parked by a
    `lead-author/` record, and vice versa."""
    paths = loop_paths(tmp_path)
    _queued_run(tmp_path, "case-1", "run-1", paths)
    failing = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))
    assert _tick(paths, branch=failing, run_lead_author=_serving([]), run_pitfalls=_no_curation) == 0
    assert len(_pending_deliveries(paths)) == 1

    append_jsonl(paths.pending_file, [{"finding_id": f"f{i}"} for i in range(5)])
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
    """O8. A run whose curation taints every tree is reclaimed from `inflight/` one tick
    after another — and each reclaim is one more attempt on the claim, so at
    `LEAD_AUTHOR_MAX_RETRIES` serves it is quarantined rather than served a fourth time. The
    dead letter names what happened; the agent never runs for it again."""
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "3")
    paths = loop_paths(tmp_path)
    run_dir = _queued_run(tmp_path, "case-1", "run-1", paths)
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
    failed = marker_body(paths.author_queue_dir / "failed" / "case-1.json")
    assert failed["failed"] == "served 3 time(s) without being recorded done"
    assert Path(failed["run_dir"]) == run_dir.resolve()
    assert drains._has_lead_author_work(paths) is False


# --- O6 — a fresher same-case request survives a failed push --------------------------------


def test_952_o6_a_failed_push_neither_destroys_nor_supersedes_a_fresher_request(
    tmp_path: Path,
):
    """O6 + M2. The claim frees the top-level slot so a re-ask landing mid-serve has somewhere
    to go. The served claim is consumed once the tree passes the scrub — a failed push does
    not touch it — and the fresher request keeps its slot, untouched by the stale run's
    `attempts`. The second tick delivers the retained branch, then serves the fresher request
    alone: the stale run is never served twice."""
    paths = loop_paths(tmp_path)
    first = _queued_run(tmp_path, "case-A", "run-1", paths)
    second = tmp_path / "runs" / "run-2"
    second.mkdir(parents=True)
    served: list[Path] = []

    def re_ask() -> None:
        # The operator re-investigates the case while the lane is curating it...
        markers.enqueue_case_for_curation("case-A", second, paths)

    failing = _Branch(tmp_path / "worktrees", fail=BranchError("push rejected"))
    assert _tick(
        paths, branch=failing, run_pitfalls=_no_curation,
        run_lead_author=_serving(served, before=re_ask),
    ) == 0
    assert served == [first.resolve()]

    assert author_markers(paths) == ["case-A.json"]
    fresher = marker_body(paths.author_queue_dir / "case-A.json")
    assert Path(fresher["run_dir"]) == second.resolve(), (
        "the failed push replaced the fresher curation request with the stale run dir"
    )
    assert "attempts" not in fresher
    assert _inflight(paths) == [], "the consumed claim was left in inflight/"
    assert _done_sha(first) == SHA
    assert not (paths.author_queue_dir / "failed").exists()

    landing = _Branch(tmp_path / "worktrees")
    assert _tick(
        paths, branch=landing, run_pitfalls=_no_curation, run_lead_author=_serving(served),
    ) == 0
    assert served == [first.resolve(), second.resolve()], \
        "the second tick must serve the fresher request, and the stale run only once"
    assert landing.events == ["deliver", "lease-check", "start", "finish", "cleanup"]
    assert author_markers(paths) == []
    assert _inflight(paths) == []
    assert drains._has_lead_author_work(paths) is False


# --- O2 — the lessons lane's failure line makes no claim about markers or pitfalls ------------


def test_952_o2_the_lessons_lane_failure_line_is_lane_neutral_and_records_delivery(
    tmp_path: Path, said,
):
    """O2 + O7 on the lane that does NOT collect a disposition. `_run_worktree_batch` is
    shared, so the lessons lane's `finish_batch` failure is logged by the same line and
    recorded the same way: it must name the retained `lessons/<batch_id>` branch and what
    happens next, and nothing else — no `inflight/`, no pitfall counts, no claim about what
    was or was not consumed (this lane consumes its rows inside the serve, so any such claim
    would be false here), and none of the old "work stays queued" wording."""
    paths = loop_paths(tmp_path)
    append_jsonl(paths.pending_file, [{"finding_id": f"f{i}"} for i in range(5)])
    branch = _Branch(tmp_path / "worktrees", prefix="lessons/", fail=BranchError("push rejected"))
    triggered: list[str] = []

    rc = drains.author_drain(
        paths,
        trigger_author=lambda _p, _f, _env, module, *_a, **_kw: triggered.append(module),
        branch=branch,
        start_box=noop_start_box, stop_box=noop_stop_box, scrub=noop_scrub,
    )

    assert rc == 0
    assert "author" in triggered, "the tick never ran a curator, so the line below is vacuous"
    assert branch.events == ["lease-check", "start", "finish", "cleanup"]
    assert [r["branch"] for r in _pending_deliveries(paths)] == [f"lessons/{branch.batch_id}"]
    err = said.readouterr().err
    expected = (
        "author_drain: finish_batch failed: push rejected — commit retained on local branch "
        f"lessons/{branch.batch_id}; delivery is retried next tick, before anything new is "
        "served"
    )
    assert any(line.endswith(expected) for line in err.splitlines()), \
        f"the lessons lane's line must be the lane-neutral sentence ALONE:\n{err}"
    assert "inflight" not in err, "the lessons lane claimed something about markers"
    assert "pitfall" not in err, "the lessons lane claimed something about pitfall rows"
    assert "consumed" not in err, "the lessons lane made a claim about consumption"
    assert "work stays queued" not in err
    assert "batch produced no commits" not in err


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
    bypassed (their own suite) and the queue lock stubbed (the drain's, under M5)."""
    deps = lead_author.build_lead_author_deps(LoopPaths(repo_root=repo, state_dir=state))
    seams = dict(
        extract=lambda _rd: ([], [_lead()]),
        synthesize=lambda executed, catalog_dir=None, catalog=None, systems=None: [],
        discover_system_drafts=lambda: [],
        acquire_queue_lock=lambda: object(),
        release_queue_lock=lambda _fh: None,
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
    """O5 + M4, the `_run_locked` write site (after the commit). By default — the CLI `main`,
    every existing caller — `run` writes `<run_dir>/lead_author/done` exactly as today. Given
    `on_done`, the commit that WOULD have been recorded is handed to it instead and NOTHING
    lands under the run dir; the commit itself is not deferred (HEAD moves in both modes)."""
    repo = seed_skills_repo(tmp_path / "repo")
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()
    deps = _curator_deps(
        repo, tmp_path / "state",
        invoke_agent=_promoting_agent(repo),
        build_handoff=lambda rd, ex, jl=None, **_: [{"query_id": "wazuh.newthing"}],
    )
    head_before = _git.git_head_sha(repo)
    captured: list[str | None] = []

    rc = lead_author.run(run_dir, deps=deps, on_done=captured.append) if deferred \
        else lead_author.run(run_dir, deps=deps)

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
    """O5 + M4, the `_prepare_handoffs` write site: executed leads that resolve to no catalog
    template, and no pending drafts — the agent is never spawned and the run is recorded done
    with `commit: none`. Both modes, same record; only where it goes differs."""
    repo = seed_skills_repo(tmp_path / "repo")
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()
    deps = _curator_deps(
        repo, tmp_path / "state",
        invoke_agent=_agent_must_not_run,
        build_handoff=lambda rd, ex, jl=None, **_: [],
    )
    head_before = _git.git_head_sha(repo)
    captured: list[str | None] = []

    rc = lead_author.run(run_dir, deps=deps, on_done=captured.append) if deferred \
        else lead_author.run(run_dir, deps=deps)

    assert rc == 0
    assert _git.git_head_sha(repo) == head_before, "a none-resolved run made a commit"
    if deferred:
        assert not _done(run_dir).exists()
        assert captured == [None]
    else:
        assert captured == []
        assert _done_sha(run_dir) == "none"
        assert _done(run_dir).read_text(encoding="utf-8").endswith("commit_made: False\n")


@pytest.mark.parametrize("deferred", [False, True], ids=["default", "on_done"])
def test_952_m4_the_clean_path_writes_nothing_and_calls_nothing(tmp_path: Path, deferred: bool):
    """The third clean exit — no executed leads, no pending drafts — writes no sentinel today
    and hands over none under `on_done` either: `rc == 0`, no `done`, `on_done` never called.
    The `pitfalls_collected` marker is still written in both modes (O4)."""
    repo = seed_skills_repo(tmp_path / "repo")
    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()
    deps = _curator_deps(
        repo, tmp_path / "state",
        extract=lambda _rd: ([], []),
        invoke_agent=_agent_must_not_run,
    )
    captured: list[str | None] = []

    rc = lead_author.run(run_dir, deps=deps, on_done=captured.append) if deferred \
        else lead_author.run(run_dir, deps=deps)

    assert rc == 0
    assert captured == []
    assert not _done(run_dir).exists()
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()


def test_952_m4_done_sentinel_text_is_the_one_producer_and_write_done_sentinel_the_one_writer(
    tmp_path: Path,
):
    """M4's two named seams, pinned on their own: `done_sentinel_text(sha)` renders the body
    (`commit: <sha|none>`, `at: <iso>`, `commit_made: <True|False>`), and
    `write_done_sentinel(run_dir, sha)` renders it AT WRITE TIME — so `at:` is when the run
    was recorded done, not when it was served — and puts it at `<run_dir>/lead_author/done`,
    the file `_run_locked` then honours as "already processed", which is the positive control
    that the writer wrote the sentinel and not a look-alike."""
    made = lead_author.done_sentinel_text("abc123")
    none = lead_author.done_sentinel_text(None)
    assert _SENTINEL_RE.match(made), f"not a sentinel: {made!r}"
    assert _SENTINEL_RE.match(none), f"not a sentinel: {none!r}"
    assert made.startswith("commit: abc123\n")
    assert made.endswith("commit_made: True\n")
    assert none.startswith("commit: none\n")
    assert none.endswith("commit_made: False\n")

    run_dir = tmp_path / "lead-run"
    run_dir.mkdir()
    lead_author.write_done_sentinel(run_dir, "abc123")
    written = _done(run_dir).read_text(encoding="utf-8")
    assert _without_at(written) == _without_at(made)
    assert _SENTINEL_RE.match(written)

    repo = seed_skills_repo(tmp_path / "repo")
    deps = _curator_deps(repo, tmp_path / "state", invoke_agent=_agent_must_not_run)
    assert lead_author.run(run_dir, deps=deps) == 0
    assert _done(run_dir).read_text(encoding="utf-8") == written, "the short-circuit rewrote it"


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
        paths=paths,
    )


def test_952_m4_run_pitfalls_hands_its_partition_to_on_curated_and_consumes_nothing_committed(
    pitfalls_repo: Path, tmp_path: Path,
):
    """O5 + M4 + O4 at the pitfalls curator. Given `on_curated`, `run_pitfalls` commits as
    today and then hands its partition — the committed ids, the commit sha, the held ids — to
    the callable ONCE, applying none of it: the committed row is STILL queued and the held
    row's `offers_declined` untouched. The `consumed_unattributable` rotation and its graveyard
    entry are NOT deferred (O4's positive control, in the same tick): the undeclared row is
    gone from the queue and filed.

    Then the disposition is applied through its own `apply` — with the lock free — and the
    queue reaches exactly the state the default mode reaches on the same seed (the test
    below), which is what makes the hand-over sufficient rather than merely descriptive."""
    paths = LoopPaths(repo_root=pitfalls_repo, state_dir=tmp_path / "state")
    _three_way_batch(paths)
    head_before = _git.git_head_sha(pitfalls_repo)
    spawn = Spawn(curate_execution_md("elastic"))
    captured: list[PitfallsDisposition] = []

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn, on_curated=captured.append) == 0

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

    assert captured[0].apply(paths, timeout_seconds=5) == 0
    consumed = consumed_by_id(paths)
    assert consumed["c:l-000:0"]["consumed_category"] == "consumed_committed"
    assert consumed["c:l-000:0"]["consumed_commit"] == sha
    assert queue_ids(paths) == ["h:l-003:0"]
    assert _rows_by_id(paths)["h:l-003:0"][pitfalls_curator.OFFERS_DECLINED_KEY] == 1


def test_952_o5_run_pitfalls_default_consumes_exactly_as_today(pitfalls_repo: Path, tmp_path: Path):
    """O5, the pitfalls half: with no `on_curated` the curator consumes immediately — the
    committed row rotates as `consumed_committed` under the commit's sha, the unattributable
    row as `consumed_unattributable` with its graveyard entry, and the held row stays queued
    with one decline counted. The mirror of `test_870_partition`'s mixed-batch assertions on
    the same three-way seed as the deferred test above, so the two modes are compared on one
    address."""
    paths = LoopPaths(repo_root=pitfalls_repo, state_dir=tmp_path / "state")
    _three_way_batch(paths)
    head_before = _git.git_head_sha(pitfalls_repo)

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(curate_execution_md("elastic"))) == 0

    sha = _git.git_head_sha(pitfalls_repo)
    assert sha != head_before
    consumed = consumed_by_id(paths)
    assert consumed["c:l-000:0"]["consumed_category"] == "consumed_committed"
    assert consumed["c:l-000:0"]["consumed_commit"] == sha
    assert consumed["u:l-001:0"]["consumed_category"] == "consumed_unattributable"
    assert "h:l-003:0" not in consumed
    assert queue_ids(paths) == ["h:l-003:0"]
    assert _rows_by_id(paths)["h:l-003:0"][pitfalls_curator.OFFERS_DECLINED_KEY] == 1
    assert set(graveyard_by_id(paths)) == {"u:l-001:0"}


def test_952_o5_run_pitfalls_by_hand_reads_no_drain_configuration(
    pitfalls_repo: Path, tmp_path: Path, monkeypatch,
):
    """O5, byte-for-byte: the by-hand curator does not read the drain's lock wait — a
    malformed `LEARNING_REPO_LOCK_WAIT_SECONDS` is the drain's problem (refused at ITS entry,
    before any work) and must not surface after a by-hand commit as a `FatalConfigError`
    with the rows left queued."""
    monkeypatch.setenv("LEARNING_REPO_LOCK_WAIT_SECONDS", "soon")
    paths = LoopPaths(repo_root=pitfalls_repo, state_dir=tmp_path / "state")
    _three_way_batch(paths)

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=Spawn(curate_execution_md("elastic"))) == 0

    assert consumed_by_id(paths)["c:l-000:0"]["consumed_category"] == "consumed_committed"
    assert queue_ids(paths) == ["h:l-003:0"]


# --- the rotation deadline ------------------------------------------------------------------


def test_952_m1_the_deferred_rotation_reaches_the_queue_lock_with_a_deadline(tmp_path: Path):
    """M1: the drain must pass a deadline into the rotation (`persist.queue_lock`: "THE DRAIN
    must pass one"), and today's `rotate_pitfalls` passes none. Observed for real: with the
    pitfalls append lock held by this test, `PitfallsDisposition.apply(..., timeout_seconds=0)`
    raises `TimeoutError` at once and leaves the queue and the ledger untouched; with the lock
    released the same call applies. `rotate_pitfalls(..., timeout_seconds=0)` is pinned the
    same way, since it is the seam the deadline threads through.

    `committed_ids` is non-empty on purpose: the rotation is the FIRST step of `apply`, so a
    build that reordered the decline bump ahead of it would block on `drain.retire`'s
    unbounded lock — which `_bounded` turns into a red test rather than a hung one."""
    paths = loop_paths(tmp_path)
    queue_before = _seed_pitfalls(paths)
    disposition = _disposition()

    with _held(paths.pitfalls.append_lock) as holder:
        with pytest.raises(TimeoutError):
            _bounded(lambda: disposition.apply(paths, timeout_seconds=0), holder=holder)
        assert paths.pitfalls.file.read_bytes() == queue_before
        assert not paths.pitfalls.consumed.exists()

        with pytest.raises(TimeoutError):
            _bounded(
                lambda: persist.rotate_pitfalls(
                    [COMMITTED_ID], SHA, paths=paths, timeout_seconds=0,
                ),
                holder=holder,
            )
        assert paths.pitfalls.file.read_bytes() == queue_before

    assert disposition.apply(paths, timeout_seconds=0) == 0
    consumed = consumed_by_id(paths)
    assert consumed[COMMITTED_ID]["consumed_category"] == "consumed_committed"
    assert consumed[COMMITTED_ID]["consumed_commit"] == SHA
    rows = _rows_by_id(paths)
    assert list(rows) == [HELD_ID]
    assert rows[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 2


def test_952_m1_the_immediate_rotation_is_bounded_under_the_drain_and_unbounded_by_hand(
    pitfalls_repo: Path, tmp_path: Path,
):
    """The deadline covers the rotations the curator makes AT ONCE too — the
    `consumed_unattributable` rotation runs inside the drain's `do_work`, under every lock
    the tick holds, and a wedged appender must not hold the tick open there any more than
    at the apply. `run_pitfalls(lock_wait_seconds=0)` against a held append lock raises
    `TimeoutError`; the same call with no wait — the by-hand default — is the unbounded wait
    it always was, so it is driven with the lock FREE as the positive control."""
    paths = LoopPaths(repo_root=pitfalls_repo, state_dir=tmp_path / "state")
    persist.append_pitfalls([pitfall_row("u:l-001:0", "newsys")], paths=paths)
    queue_before = paths.pitfalls.file.read_bytes()

    with _held(paths.pitfalls.append_lock) as holder, pytest.raises(TimeoutError):
        _bounded(
            lambda: pitfalls_curator.run_pitfalls(
                paths=paths, invoke=_agent_must_not_run, lock_wait_seconds=0,
            ),
            holder=holder,
        )
    assert paths.pitfalls.file.read_bytes() == queue_before

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=_agent_must_not_run) == 0
    assert queue_ids(paths) == []
    assert consumed_by_id(paths)["u:l-001:0"]["consumed_category"] == "consumed_unattributable"


# --- O5 / M5 — the drain holds the per-author queue lock for the whole tick ------------------


def test_952_m5_the_drain_holds_the_queue_lock_across_the_serve(tmp_path: Path):
    """O5 + M5. Deferring the sentinel to the drain opens a gap — the remaining serves, the
    pitfalls curation, box teardown — in which a by-hand `lead_author.py <run_dir>` would
    take the per-author queue lock, see no sentinel, and re-serve the run. So the drain takes
    that lock once, around the whole tick. Observed through the REAL by-hand entry point
    called from inside the serve: `lead_author.run(run_dir, paths=paths)` — no `deps`, the
    CLI's own path — answers `QUEUE_LOCK_SKIP_RC` while the tick is running.

    The positive control is the same call, the same `paths`, outside any tick: it does not
    skip. Both halves are the same file — `paths.lead_pending_dir / ".lock"` — which is the
    contract's deviation (b): the lock is resolved off `paths`, so the drain and a by-hand run
    over the same state contend on one file rather than on `DEFAULT_PATHS`' constant.

    The by-hand run dir is empty, so outside a tick the real `run` takes the lock, resolves
    membership over the seeded tree, and exits on the clean path — rc 0, a value the skip rc
    is defined to be distinct from."""
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _queued_run(tmp_path, "case-1", "run-1", paths)
    by_hand = tmp_path / "runs" / "by-hand"
    (by_hand / "gather_raw").mkdir(parents=True)
    served: list[Path] = []
    mid_serve: list[int] = []

    def probe() -> None:
        mid_serve.append(lead_author.run(by_hand, paths=paths))

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
    with _held(paths.lead_pending_dir / ".lock"):
        assert lead_author.run(by_hand, paths=paths) == lead_author.QUEUE_LOCK_SKIP_RC
        assert not (by_hand / "lead_author").exists(), "a skipped by-hand run wrote state"
    assert lead_author.run(by_hand, paths=paths) == 0
    assert (by_hand / "lead_author" / "pitfalls_collected").is_file(), \
        "outside a tick the by-hand run must serve, not skip"


def test_952_m5_a_tick_started_under_a_held_queue_lock_claims_nothing(tmp_path: Path, said):
    """M5's other direction: a tick that finds the per-author queue lock held — a by-hand run
    in progress — skips BEFORE claiming, and says so. The markers stay at the top level
    (nothing in `inflight/`, no `attempts` spent), the serve seam is never reached, and the
    tick returns 0."""
    paths = loop_paths(tmp_path)
    _queued_run(tmp_path, "case-1", "run-1", paths)
    _queued_run(tmp_path, "case-2", "run-2", paths)
    served: list[Path] = []
    branch = _Branch(tmp_path / "worktrees")

    with _held(paths.lead_pending_dir / ".lock"):
        rc = _tick(
            paths, branch=branch, run_pitfalls=_no_curation,
            run_lead_author=_serving(served),
        )

    assert rc == 0
    assert served == [], "the tick served under a lock another run holds"
    assert author_markers(paths) == ["case-1.json", "case-2.json"]
    assert _inflight(paths) == [], "a skipped tick claimed a marker"
    for name in ("case-1.json", "case-2.json"):
        assert "attempts" not in marker_body(paths.author_queue_dir / name), \
            "a skip spent one of the request's attempts"
    assert "start" not in branch.events, "a skipped tick minted a batch"
    err = said.readouterr().err
    assert "lead_author_drain: another lead-author run holds the queue lock — skipping" in err

    # Positive control: released, the same tick serves.
    assert _tick(
        paths, branch=_Branch(tmp_path / "worktrees"), run_pitfalls=_no_curation,
        run_lead_author=_serving(served),
    ) == 0
    assert len(served) == 2
    assert author_markers(paths) == []


def test_952_m5_the_drain_enters_the_curator_past_its_own_lock(tmp_path: Path):
    """M5's wiring: `_invoke_lead_author` — the drain's production `run_lead_author` — enters
    the curator through `run_under_held_queue_lock`, past the acquisition `run` makes,
    because the drain already holds that lock. Driven with the lock held by this test
    (standing in for the drain's own hold): the invocation must serve — it runs `_run_locked`
    for real over an empty run dir, which the `pitfalls_collected` marker it leaves proves —
    and must not skip or contend.

    The positive control is the same held lock against the by-hand entry point over a second
    run dir: THAT skips, and leaves no marker — so the file this test holds is the one both
    callers resolve, and only the drain's wiring is exempt from it."""
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    drained = tmp_path / "runs" / "drained"
    by_hand = tmp_path / "runs" / "by-hand"
    for d in (drained, by_hand):
        (d / "gather_raw").mkdir(parents=True)
    captured: list[str | None] = []

    with _held(paths.lead_pending_dir / ".lock"):
        drains._invoke_lead_author(paths, drained, on_done=captured.append)
        assert (drained / "lead_author" / "pitfalls_collected").is_file(), \
            "the curator never ran past the lock the drain is supposed to have exempted it from"
        assert captured == [], "an empty run dir is the clean path: no sentinel to hand over"
        assert not _done(drained).exists()

        assert lead_author.run(by_hand, paths=paths) == lead_author.QUEUE_LOCK_SKIP_RC
        assert not (by_hand / "lead_author").exists(), "a skipped by-hand run wrote state"


# --- the adversary round: ways the suite above was greened while betraying intent -----------


def test_952_a_the_production_adapter_forwards_on_done_to_the_curator(tmp_path: Path):
    """Kills A. `_invoke_lead_author` accepting `on_done` and never forwarding it to the
    curator greened every test above: the drain-level tests fake the serve, and the wiring
    test drives a run dir that reaches the clean path, which writes no sentinel in either
    mode. So this drives the PRODUCTION adapter over a run dir that reaches a sentinel write
    without a model — one executed lead whose `query_id` names an undeclared system, so no
    draft is minted and `build_handoff` resolves it to no template (`_prepare_handoffs`'
    "none resolved" exit, `commit: none`). The record must reach `on_done` and NOTHING may
    land under the run dir.

    Positive control: the by-hand entry point over the same run dir writes that sentinel."""
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = tmp_path / "runs" / "run-1"
    seed_executed_query(run_dir, query_id="nosuch.verb", system="nosuch", verb="verb")
    captured: list[str | None] = []

    drains._invoke_lead_author(paths, run_dir, on_done=captured.append)

    assert captured == [None], "the production adapter did not hand the record to on_done"
    assert not _done(run_dir).exists(), \
        "the production adapter let the curator write the sentinel inside do_work"
    assert (run_dir / "lead_author" / "pitfalls_collected").is_file()

    assert lead_author.run(run_dir, paths=paths) == 0
    assert _done_sha(run_dir) == "none"


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
    """Kills C. A lock released right after `do_work` greened the M5 test, which only probes
    from inside the serve. The gap M5 names is the whole of it — pitfalls curation, box
    teardown, the apply — so the by-hand entry point is probed from inside the pitfalls
    curation AND from inside `finish_batch`: both must answer `QUEUE_LOCK_SKIP_RC`, and the
    tick must still consume. Outside a tick the same call serves (rc 0)."""
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",),
                     skills=("elastic",), catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    run_dir = _queued_run(tmp_path, "case-1", "run-1", paths)
    by_hand = tmp_path / "runs" / "by-hand"
    (by_hand / "gather_raw").mkdir(parents=True)
    served: list[Path] = []
    in_curation: list[int] = []

    def probe() -> int:
        return lead_author.run(by_hand, paths=paths)

    def curate(_paths, *, box=None, on_curated):
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

    assert lead_author.run(by_hand, paths=paths) == 0
    assert (by_hand / "lead_author" / "pitfalls_collected").is_file()


def test_952_d_a_failed_sentinel_write_leaves_the_claim_in_inflight(tmp_path: Path):
    """Kills D. Unlinking the claims BEFORE writing the sentinels greened the ordering test,
    which faults at the rotation and so only ever sees steps 1–2 both done. Here the sentinel
    write itself fails for real — a regular FILE sits where `<run_dir>/lead_author/` must be,
    so the writer's mkdir raises. The fault propagates, the push never runs, and the served
    marker is still claimed in `inflight/`: a partial apply on the lead-author half must be
    a no-op re-serve, never a run consumed without its sentinel. Nothing behind the sentinel
    step ran either. The green tick is the positive control on every address."""
    paths = loop_paths(tmp_path)
    run_dir = _queued_run(tmp_path, "case-1", "run-1", paths)
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
    assert paths.pitfalls.file.read_bytes() == queue_before
    assert not paths.pitfalls.consumed.exists()
    assert _rows_by_id(paths)[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 1


@pytest.mark.parametrize("fault", ["git_error_from_finish_batch", "run_tainted_from_scrub"])
def test_952_e_the_lessons_lane_logs_no_retained_summary_on_a_systemic_fault(
    tmp_path: Path, said, fault: str,
):
    """Kills E. Rendering a `None` disposition as zeros put "batch not consumed — …; 0 served
    marker(s) left in inflight/, 0 committed pitfall row(s) …" on the LESSONS lane's systemic
    exits, which the O2 test — `BranchError` only — never drives. O2 is about every exit: a
    lane that collected no disposition says nothing about markers or pitfall rows on any of
    them. The fault propagates as on the lead-author lane."""
    paths = loop_paths(tmp_path)
    append_jsonl(paths.pending_file, [{"finding_id": f"f{i}"} for i in range(5)])
    triggered: list[str] = []
    if fault == "git_error_from_finish_batch":
        expected_type: type[BaseException] = GitError
        branch = _Branch(
            tmp_path / "worktrees", prefix="lessons/",
            fail=GitError(["push"], 128, "the remote hung up"),
        )
        scrub = noop_scrub
    else:
        expected_type = box_mod.RunTainted
        branch = _Branch(tmp_path / "worktrees", prefix="lessons/")
        scrub = _tainting

    with pytest.raises(expected_type):
        drains.author_drain(
            paths,
            trigger_author=lambda _p, _f, _env, module, *_a, **_kw: triggered.append(module),
            branch=branch, start_box=noop_start_box, stop_box=noop_stop_box, scrub=scrub,
        )

    assert "author" in triggered, "the tick never ran a curator, so the negatives are vacuous"
    assert "cleanup" in branch.events
    err = said.readouterr().err
    assert "batch not consumed" not in err, "the lessons lane logged a summary it never collected"
    assert "inflight" not in err
    assert "pitfall" not in err
    assert "work stays queued" not in err


def test_952_f_the_retained_summary_counts_each_kind_at_asymmetric_counts(
    tmp_path: Path, said,
):
    """Kills F. Every pre-apply exit above seeds one served marker, one committed id and one
    held id (or zeros), so a summary that counted recorded-done markers as served markers,
    or swapped the committed and held counts, agreed with the literal. Two served markers of
    which one hands over no record, three committed ids, one held id — each count is its own
    number, and the state assertions are honest against a queue seeded to match."""
    paths = loop_paths(tmp_path)
    run_1 = _queued_run(tmp_path, "case-1", "run-1", paths)
    run_2 = _queued_run(tmp_path, "case-2", "run-2", paths)
    committed = ("p:committed:0", "p:committed:1", "p:committed:2")
    persist.append_pitfalls(
        [*(pitfall_row(pid, "elastic") for pid in committed),
         shim_row(HELD_ID, **{pitfalls_curator.OFFERS_DECLINED_KEY: 1})],
        paths=paths,
    )
    queue_before = paths.pitfalls.file.read_bytes()
    served: list[Path] = []

    def serve(_paths, run_dir, *, box=None, on_done):
        served.append(run_dir)
        if run_dir.name == "run-1":
            on_done(SHA)  # run-2 is the clean path that hands over no record

    disposition = PitfallsDisposition(committed_ids=committed, sha=SHA, held_ids=(HELD_ID,))
    curated: list[PitfallsDisposition] = []
    branch = _Branch(tmp_path / "worktrees")

    with pytest.raises(box_mod.RunTainted):
        _tick(
            paths, branch=branch, scrub=_tainting,
            run_lead_author=serve, run_pitfalls=_curating(curated, disposition),
        )

    assert served == [run_1.resolve(), run_2.resolve()]
    assert curated == [disposition]
    assert _inflight(paths) == ["case-1.json", "case-2.json"]
    assert paths.pitfalls.file.read_bytes() == queue_before
    assert not _done(run_1).exists()
    assert not _done(run_2).exists()
    err = said.readouterr().err
    expected = (
        "lead_author_drain: batch not consumed — left for the next tick's reclaim, up to: "
        "2 served marker(s) left in inflight/, 3 committed pitfall row(s) left queued, "
        "1 held row(s) not bumped"
    )
    assert any(line.endswith(expected) for line in err.splitlines()), \
        f"the retained counts are not the served/committed/held counts:\n{err}"


def test_952_g_a_held_only_deferred_tick_defers_the_decline_bump(pitfalls_repo: Path, tmp_path: Path):
    """Kills G. Honouring `on_curated` only when there was something committed greened the
    M4 curator test, whose three-way seed always has a committed row. A tick that offered
    the reducer surface and was declined has NOTHING committed and one held row — and its
    decline bump is the scrub-dependent write C13 named: bumped inside `do_work`, N tainted
    batches retire the row with its lesson never taught. So the held-only disposition is
    handed over with the bump unapplied; applying it is what counts the decline."""
    paths = LoopPaths(repo_root=pitfalls_repo, state_dir=tmp_path / "state")
    persist.append_pitfalls([shim_row("h:l-003:0")], paths=paths)
    head_before = _git.git_head_sha(pitfalls_repo)
    spawn = Spawn(None)
    captured: list[PitfallsDisposition] = []

    assert pitfalls_curator.run_pitfalls(paths=paths, invoke=spawn, on_curated=captured.append) == 0

    assert [h.get("surface") for h in spawn.handoffs] == ["reducer"], "the offer was never made"
    assert _git.git_head_sha(pitfalls_repo) == head_before
    assert captured == [PitfallsDisposition(committed_ids=(), sha=None, held_ids=("h:l-003:0",))]
    assert queue_ids(paths) == ["h:l-003:0"]
    assert pitfalls_curator.OFFERS_DECLINED_KEY not in _rows_by_id(paths)["h:l-003:0"], \
        "the decline was counted on a tick whose consumption was handed back"
    assert consumed_by_id(paths) == {}
    assert graveyard_by_id(paths) == {}

    assert captured[0].apply(paths, timeout_seconds=5) == 0
    assert _rows_by_id(paths)["h:l-003:0"][pitfalls_curator.OFFERS_DECLINED_KEY] == 1
    assert queue_ids(paths) == ["h:l-003:0"]


def test_952_m1_the_deferred_decline_bump_is_bounded_too(tmp_path: Path):
    """The deadline covers BOTH steps of `apply`: the decline bump's own locked rotation
    (`drain.retire`) waits on the same append lock as the committed rotation, and a
    held-only disposition never reaches the first step — so a deadline threaded into the
    rotation alone would let a held-only apply wait forever. Held lock: `TimeoutError`, row
    untouched; released: bumped."""
    paths = loop_paths(tmp_path)
    queue_before = _seed_pitfalls(paths)
    held_only = PitfallsDisposition(committed_ids=(), sha=None, held_ids=(HELD_ID,))

    with _held(paths.pitfalls.append_lock) as holder, pytest.raises(TimeoutError):
        _bounded(lambda: held_only.apply(paths, timeout_seconds=0), holder=holder)
    assert paths.pitfalls.file.read_bytes() == queue_before
    assert _rows_by_id(paths)[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 1

    assert held_only.apply(paths, timeout_seconds=0) == 0
    assert _rows_by_id(paths)[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 2
    assert COMMITTED_ID in _rows_by_id(paths), "a held-only apply rotated the committed row"
