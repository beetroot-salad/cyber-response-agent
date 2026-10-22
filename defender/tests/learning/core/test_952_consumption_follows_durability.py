"""#952 — consumption follows durability in the lead-author lane."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import contextlib
import fcntl
import re
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from defender import _git
from defender import box as box_mod
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import ExecutedLead
from defender.learning.leads.pitfalls_curator import PitfallsDisposition
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
    author_markers,
    loop_paths,
    marker_body,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LEAD_PREFIX,
    BoxSpy,
    draft_entries,
    drain_paths,
    product_repo,
    remote_branches,
)
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.tests.support.learning.curation._lead_author_1134 import lead_deps, lead_trees
from defender.learning.core.state import LEAD_QUEUE_LOCK, PITFALLS


# --- substrate -------------------------------------------------------------------------------

#: The commit a served lead-author run hands the drain in place of writing the sentinel
#: itself; the sentinel the drain then writes names it.
SHA = "abc123"

COMMITTED_ID = "p:committed:0"
HELD_ID = "p:held:0"

_SENTINEL_RE = re.compile(r"\Acommit: (?P<sha>\S+)\nat: \S+\ncommit_made: (?P<made>True|False)\n\Z")


def _queued_run(case_id: str, name: str, paths: LoopPaths) -> Path:
    """A natural run `name` planted where the drain rehydrates a row (`curation_run_dir`, under
    the test's data root, #1105 PR 2), with the curation request for `case_id` naming it."""
    run_dir = _state1135.curation_run_dir(name)
    _state1135.enqueue_case(_state1135.state_for_paths(paths), case_id, run_dir)
    return run_dir


def _address(run_dir: Path) -> tuple[str, str]:
    """The `(tenant_id, run_id)` a curation row names for the run at `run_dir`."""
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

    def serve(_paths, _state, run, *, box=None, on_done, **_kw):
        served.append(run.run_dir)
        if before is not None:
            before()
        if done:
            on_done(SHA)

    return serve


def _curating(curated: list[PitfallsDisposition], disposition: PitfallsDisposition):
    """A `run_pitfalls` fake that simulates a curation: it hands its partition to the drain
    through `on_curated` and returns 0, exactly as the real curator does in deferred mode."""

    def curate(_paths, _state, *, box=None, on_curated, **_kw):
        curated.append(disposition)
        on_curated(disposition)
        return 0

    return curate


def _no_curation(*_a, **_kw) -> int:
    return 0


@pytest.fixture
def tenant(tmp_path: Path, data_root: Path):
    """#1108 P4: the lane drains into the fixture tenant's repo, published for real and bound
    to its forge (`tenant_1108_p4/_support.py`). Its id is D9's, so the runs the curation rows
    name (`_state1135.curation_run_dir`) are this tenant's."""
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        yield t


def _tenant_paths(t, tmp_path: Path) -> LoopPaths:
    """The tenant's learning paths over a scratch product checkout (`drain_paths`)."""
    return drain_paths(t, product_repo(tmp_path))


def _tick(t, paths: LoopPaths, *, run_lead_author, run_pitfalls, box: BoxSpy | None = None) -> int:
    """One lead-author tick through the P4 drain seams (`client=`/`identity=` over the tenant's
    forge and issuer fakes, the batch's box via `BoxSpy`): the `branch=`/`scrub=` seams are
    gone with the product-repo delivery."""
    spy = box if box is not None else BoxSpy()
    return drains.lead_author_drain(
        paths, run_lead_author=run_lead_author, run_pitfalls=run_pitfalls,
        client=t.forge.client, identity=t.vault.identity(), start_box=spy.start,
        stop_box=spy.stop,
    )


def _nothing_delivered(t) -> None:
    """No `lead-author/` branch reached the tenant origin and no PR was asked for."""
    assert remote_branches(t.remote, LEAD_PREFIX) == {}, "a batch reached the tenant origin"
    assert t.forge.creates == [], "a PR was opened"


def _inflight_attempts(paths: LoopPaths, case: str) -> int:
    return int(marker_body(location_path(paths.state_root) / "author-queue" / "inflight"
                           / f"{case}.json").get("attempts", 0))


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


# --- O3 — a batch whose tree passed the scrub consumes exactly what it served ----------------


@pytest.mark.parametrize("done", [True, False],
                         ids=["sentinel-handed-over", "clean-path-no-sentinel"])
def test_952_o3_a_batch_that_passes_the_scrub_consumes_what_it_served(
    tmp_path: Path, tenant, done: bool,
):
    """O3, the positive control for every O1 negative — over the P4 lane (#1108): the batch is a
    draft of the tenant's repo; a tick whose serve and curation leave the draft unchanged has
    nothing to deliver (no `lead-author/` branch, no PR), discards its draft, and consumes
    exactly what it served. (The batch-with-commits row is P4's: `tenant_1108_p4/test_writers.py`
    lead-lane rows.)"""
    paths = _tenant_paths(tenant, tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    _seed_pitfalls(paths)
    served: list[Path] = []
    curated: list[PitfallsDisposition] = []
    box = BoxSpy()

    rc = _tick(
        tenant, paths, box=box,
        run_lead_author=_serving(served, done=done),
        run_pitfalls=_curating(curated, _disposition()),
    )

    assert rc == 0
    assert served == [run_dir.resolve()]
    assert curated == [_disposition()]
    assert len(box.requests) == 1, "the batch's box was not started once"
    assert draft_entries(tenant) == [], "the batch's draft was not discarded"
    _nothing_delivered(tenant)
    _assert_consumed(paths, run_dir, done=done)


def test_952_m1_the_disposition_applies_sentinels_and_unlinks_before_the_pitfalls_rotation(
    tmp_path: Path, monkeypatch, tenant,
):
    """M1's apply order — sentinels, then unlinks, then the pitfalls rotation, then the decline bumps — observed through a REAL fault at the third step"""
    monkeypatch.setenv("LEARNING_REPO_LOCK_WAIT_SECONDS", "0")
    paths = _tenant_paths(tenant, tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    queue_before = _seed_pitfalls(paths)
    served: list[Path] = []
    curated: list[PitfallsDisposition] = []

    with _held(location_path(paths.state_root) / PITFALLS.append_lock) as holder, pytest.raises(TimeoutError):
        _bounded(
            lambda: _tick(
                tenant, paths,
                run_lead_author=_serving(served),
                run_pitfalls=_curating(curated, _disposition()),
            ),
            holder=holder,
        )

    # The push never ran ahead of, or despite, an apply that did not complete.
    _nothing_delivered(tenant)
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
    tmp_path: Path, monkeypatch, tenant,
):
    from defender.learning.core.config import FatalConfigError

    monkeypatch.setenv("LEARNING_REPO_LOCK_WAIT_SECONDS", "soon")
    paths = _tenant_paths(tenant, tmp_path)
    _queued_run("case-1", "run-1", paths)
    served: list[Path] = []
    box = BoxSpy()

    with pytest.raises(FatalConfigError):
        _tick(tenant, paths, box=box, run_lead_author=_serving(served),
              run_pitfalls=_no_curation)

    assert served == []
    assert box.requests == [], "a box started for a refused tick"
    assert draft_entries(tenant) == [], "a draft was built for a refused tick"
    _nothing_delivered(tenant)
    assert author_markers(paths) == ["case-1.json"]


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


def test_952_m5_the_drain_holds_the_queue_lock_across_the_serve(tmp_path: Path, tenant):
    """O5 + M5. Deferring the sentinel to the drain opens a gap — the remaining serves, the pitfalls curation, box teardown — in which a by-hand run would re-serve; the drain holds the per-author queue lock for its whole tick (over the P4 tenant lane, #1108)."""
    paths = _tenant_paths(tenant, tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    by_hand = _state1135.curation_run_dir("by-hand")
    (by_hand / "gather_raw").mkdir()
    served: list[Path] = []
    mid_serve: list[int] = []

    def probe() -> None:
        mid_serve.append(lead_author.run(_state1135.run_of(by_hand), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths))

    assert _tick(
        tenant, paths, run_pitfalls=_no_curation,
        run_lead_author=_serving(served, before=probe),
    ) == 0
    assert served == [run_dir.resolve()]
    assert mid_serve == [lead_author.QUEUE_LOCK_SKIP_RC], \
        "a by-hand run started during a drain tick did not skip on the queue lock"
    assert not (by_hand / "lead_author").exists(), "a skipped by-hand run wrote state"
    assert author_markers(paths) == [], "the tick must still serve under the lock it holds"
    assert _inflight(paths) == [], "the tick must still consume under the lock it holds"

    # Positive control: the lock the tick held IS the file a by-hand run locks. Held here the
    # way a second process would hold it, the same call skips; and once the tick is over the
    # file is free (a non-blocking exclusive lock on it succeeds).
    with _held((location_path(paths.state_root) / LEAD_QUEUE_LOCK.file).parent / ".lock"):
        assert lead_author.run(_state1135.run_of(by_hand), label=LEAD_AUTHOR_DRAIN_LABEL,
                               paths=paths) == lead_author.QUEUE_LOCK_SKIP_RC
        assert not (by_hand / "lead_author").exists(), "a skipped by-hand run wrote state"


def test_952_m5_a_tick_started_under_a_held_queue_lock_claims_nothing(tmp_path: Path, capsys, tenant):
    """M5's other direction (over the P4 tenant lane, #1108): a tick that finds the queue lock held claims nothing, builds no draft and starts no box."""
    paths = _tenant_paths(tenant, tmp_path)
    _queued_run("case-1", "run-1", paths)
    _queued_run("case-2", "run-2", paths)
    served: list[Path] = []
    box = BoxSpy()

    with _held((location_path(paths.state_root) / LEAD_QUEUE_LOCK.file).parent / ".lock"):
        rc = _tick(tenant, paths, box=box, run_pitfalls=_no_curation,
                   run_lead_author=_serving(served))

    assert rc == 0
    assert served == [], "the tick served under a lock another run holds"
    assert author_markers(paths) == ["case-1.json", "case-2.json"]
    assert _inflight(paths) == [], "a skipped tick claimed a marker"
    for name in ("case-1.json", "case-2.json"):
        assert "attempts" not in marker_body(location_path(paths.state_root) / "author-queue" / name), \
            "a skip spent one of the request's attempts"
    assert box.requests == [], "a skipped tick started a batch box"
    assert draft_entries(tenant) == [], "a skipped tick built a draft"
    _nothing_delivered(tenant)
    err = capsys.readouterr().err
    assert "lead_author_drain: another lead-author run holds the queue lock — skipping" in err

    # Positive control: released, the same tick serves.
    assert _tick(tenant, paths, run_pitfalls=_no_curation, run_lead_author=_serving(served)) == 0
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


class _ProbingBox(BoxSpy):
    """`BoxSpy` whose batch-end stop first records what a by-hand run answers at that moment —
    after the serves and the curation, still inside the tick M5's lock spans."""

    def __init__(self, probe) -> None:
        super().__init__()
        self._probe = probe
        self.probed: list[int] = []

    def stop(self, box, **kw) -> None:
        self.probed.append(self._probe())
        super().stop(box, **kw)


def test_952_c_the_queue_lock_is_held_through_curation_and_finish_batch(tmp_path: Path, tenant):
    """Kills C. A lock released right after `do_work` greened the M5 test, which only probes from inside the serve. Over the P4 tenant lane (#1108) the lock is probed during the pitfalls curation, at the batch box's stop, and at every forge request the tick makes after its serve (delivery): a by-hand run skips at each."""
    paths = _tenant_paths(tenant, tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    by_hand = _state1135.curation_run_dir("by-hand")
    (by_hand / "gather_raw").mkdir()
    served: list[Path] = []
    in_curation: list[int] = []
    at_forge: list[int] = []

    def probe() -> int:
        return lead_author.run(_state1135.run_of(by_hand), label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths)

    def curate(_paths, _state, *, box=None, on_curated, **_kw):
        in_curation.append(probe())
        return 0

    box = _ProbingBox(probe)
    tenant.forge.on_request = lambda _req: at_forge.append(probe()) if served else None
    assert _tick(tenant, paths, box=box, run_lead_author=_serving(served), run_pitfalls=curate) == 0
    tenant.forge.on_request = None

    assert served == [run_dir.resolve()]
    assert in_curation == [lead_author.QUEUE_LOCK_SKIP_RC], \
        "a by-hand run during the pitfalls curation did not skip on the queue lock"
    assert box.probed, "the batch's box was never stopped"
    assert set(box.probed) == {lead_author.QUEUE_LOCK_SKIP_RC}, \
        "a by-hand run at the batch's end did not skip on the queue lock"
    assert set(at_forge) <= {lead_author.QUEUE_LOCK_SKIP_RC}, \
        "a by-hand run during the batch's delivery did not skip on the queue lock"
    assert not (by_hand / "lead_author").exists(), "a skipped by-hand run wrote state"
    assert author_markers(paths) == []
    assert _inflight(paths) == []
    assert _done_sha(run_dir) == SHA

    # Positive control: after the tick the lock is free (held here, the probe skips; the
    # non-blocking hold itself would raise were the tick still holding it).
    with _held((location_path(paths.state_root) / LEAD_QUEUE_LOCK.file).parent / ".lock"):
        assert probe() == lead_author.QUEUE_LOCK_SKIP_RC


def test_952_d_a_failed_sentinel_write_leaves_the_claim_in_inflight(tmp_path: Path, tenant):
    """Kills D. Unlinking the claims BEFORE writing the sentinels greened the ordering test, which faults at the rotation and so only ever sees steps 1–2. Over the P4 tenant lane (#1108): nothing is delivered for a batch whose apply did not complete."""
    paths = _tenant_paths(tenant, tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    queue_before = _seed_pitfalls(paths)
    (run_dir / "lead_author").write_text("not a directory\n", encoding="utf-8")
    served: list[Path] = []
    curated: list[PitfallsDisposition] = []

    with pytest.raises(OSError, match="lead_author"):
        _tick(
            tenant, paths,
            run_lead_author=_serving(served), run_pitfalls=_curating(curated, _disposition()),
        )

    assert served == [run_dir.resolve()]
    _nothing_delivered(tenant)
    assert (run_dir / "lead_author").is_file(), "the blocking file was clobbered"
    assert _inflight(paths) == ["case-1.json"], \
        "the claim was unlinked ahead of a sentinel write that then failed"
    assert author_markers(paths) == []
    assert (location_path(paths.state_root) / PITFALLS.queue).read_bytes() == queue_before
    assert not (location_path(paths.state_root) / PITFALLS.consumed).exists()
    assert _rows_by_id(paths)[HELD_ID][pitfalls_curator.OFFERS_DECLINED_KEY] == 1


# --- O8 / O6 — restored over the P4 tenant lane (#1108), with a fault that is neither a scrub
#     nor a push ------------------------------------------------------------------------------


class _StopFaulting(BoxSpy):
    """The batch box's stop fails (a `BoxFault`, as a box that will not stop raises, #1195): the
    tick halts after its serves and before the apply, so nothing it served is consumed."""

    def stop(self, box, **kw) -> None:
        super().stop(box, **kw)
        raise box_mod.BoxFault("could not stop the box (injected)")


def test_952_o8_every_serve_is_an_attempt_and_the_run_is_quarantined_at_the_ceiling(
    tmp_path: Path, monkeypatch, tenant,
):
    """O8. A run whose batch never reaches the apply (here its box never stops) is reclaimed from `inflight/` one tick after another, and each reclaim is one more attempt on the request: at `LEAD_AUTHOR_MAX_RETRIES` serves the next tick quarantines it at the claim, before the serve seam, rather than serving it forever."""
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "3")
    paths = _tenant_paths(tenant, tmp_path)
    run_dir = _queued_run("case-1", "run-1", paths)
    served: list[Path] = []

    for expected in (1, 2, 3):
        with pytest.raises(box_mod.BoxFault):
            _tick(tenant, paths, box=_StopFaulting(), run_lead_author=_serving(served),
                  run_pitfalls=_no_curation)
        assert len(served) == expected
        assert _inflight(paths) == ["case-1.json"]
        assert _inflight_attempts(paths, "case-1") == expected
        _nothing_delivered(tenant)

    # The fourth reclaim quarantines at the claim, before the serve seam is reached: the box
    # stops cleanly here, so a serve would have been consumed and would show.
    assert _tick(tenant, paths, run_lead_author=_serving(served), run_pitfalls=_no_curation) == 0
    assert len(served) == 3, "the run was served past the ceiling"
    assert _inflight(paths) == []
    assert not _done(run_dir).exists()
    failed = marker_body(location_path(paths.state_root) / "author-queue" / "failed" / "case-1.json")
    assert failed["failed"] == "served 3 time(s) without being recorded done"
    assert (failed["tenant_id"], failed["run_id"]) == _address(run_dir)
    assert drains._has_lead_author_work(_state1135.state_for_paths(paths)) is False


def test_952_o6_a_transient_serve_failure_neither_destroys_nor_supersedes_a_fresher_request(
    tmp_path: Path, tenant,
):
    """O6 + M2. The claim frees the top-level slot so a re-ask landing mid-serve has somewhere to go. The serve then fails transiently (the lead-author step's retry signal, not a scrub or a push): the stale claim is not re-queued over the fresher request, which survives with no attempt spent, and the next tick serves it, and the stale run never again."""
    paths = _tenant_paths(tenant, tmp_path)
    first = _queued_run("case-A", "run-1", paths)
    second = _state1135.curation_run_dir("run-2")
    served: list[Path] = []

    def failing_serve(_paths, _state, run, *, box=None, on_done, **_kw):
        served.append(run.run_dir)
        # The operator re-investigates the case while the lane is curating it...
        _state1135.enqueue_case(_state1135.state_for_paths(paths), "case-A", second)
        raise drains._LeadAuthorRetry("lead-author hit a transient (injected)")

    assert _tick(tenant, paths, run_pitfalls=_no_curation, run_lead_author=failing_serve) == 0
    assert served == [first.resolve()]

    assert author_markers(paths) == ["case-A.json"]
    fresher = marker_body(location_path(paths.state_root) / "author-queue" / "case-A.json")
    assert (fresher["tenant_id"], fresher["run_id"]) == _address(second), (
        "the failed serve replaced the fresher curation request with the stale run")
    assert "attempts" not in fresher
    assert _inflight(paths) == [], "the failed claim was left in inflight/"
    assert not _done(first).exists()
    assert not (location_path(paths.state_root) / "author-queue" / "failed").exists()

    assert _tick(tenant, paths, run_pitfalls=_no_curation, run_lead_author=_serving(served)) == 0
    assert served == [first.resolve(), second.resolve()], \
        "the second tick must serve the fresher request, and the stale run only once"
    assert author_markers(paths) == []
    assert _inflight(paths) == []
    assert drains._has_lead_author_work(_state1135.state_for_paths(paths)) is False
