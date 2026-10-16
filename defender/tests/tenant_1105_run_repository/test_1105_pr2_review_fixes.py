"""#1105 PR 2 — the code review's findings the owner approved (PR #1236), each driven through
its real entry point.

* A — opening a run answers ONE refusal family. `runs.open`, `runs.resolve` and an episode
  view's `open` refuse only with `RunRefused`: `RunAbsent` when the run is gone (its container
  included), `RunUnreachable` (raised from the container's `TenantRefused`) when the container
  cannot be trusted or read right now, a plain `RunRefused` for a refused entry. So the
  launcher's VERIFY step, which catches `RunRefused`, records every finished world whose
  container went bad after the siblings ran as `not archived` and goes on to the judge.
* B — the curation drain: a row whose run is GONE is `artifact-missing` at once; any other
  refusal (the tenant's acceptance, an unreachable container, a refused entry) is a counted
  transient attempt, re-queued until `LEAD_AUTHOR_MAX_RETRIES`, then `transient-exhausted`.
* C — a pitfalls-only tick needs no `DEFENDER_DATA_ROOT`; a tick with rows queued and no data
  root refuses before any box exists, every row still queued.
* D — one opener for a command line's `--tenant T <run_id>`: the refusal is printed on stderr,
  never only logged.
* E — the tracer's run listing holds the runs folder once and hands out every run.

RED before the fixes, each for its stated reason; every negative is paired with a positive
control in the same test.

#1187 (design rev 2, R1): no container holds or is judged by a `_tenant.json`, so the faults
that spoiled one are retired; a link or an absent folder is the container fault left. The
tests that changed say so in their docstrings ("#1187 declared change N").
`test_a_a_container_spoiled_after_the_siblings_ran_is_recorded_and_judged` is retired: its
fault was the record, and the judge door's record check goes with it (VERIFY's per-world
refusal stays pinned by `test_a_verify_opens_every_finished_arm_or_hands_back_its_refusal`;
the door's recordless open by
`ids_1187/test_1187_roster_consumers.py::test_the_judge_door_opens_an_episode_whose_arm_container_has_no_record`).
Its launcher-level half — the container goes bad after the siblings ran, VERIFY records each
world `not archived`, the launch returns a status and the judge step is reached — is kept by
`test_a_a_container_linked_after_the_siblings_ran_is_recorded_and_judged`, with the fault #1187
leaves: `<ep>/runs` swapped for a link (review round 2, F24).
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender import _tenant
from defender.tests._fixture_uuid import fixture_uuid
from defender.tests.tenant_1105_run_repository import _spec1105 as H
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _rid(text: str):
    from defender.run_repository import RunId

    return RunId.parse(text)


#: A natural run's id in the drain scenes (#1187, declared change 1: a run id is a canonical
#: UUID — a row naming an old `r1` is off grammar and quarantined before the tick's own refusal
#: or the drain's rehydration is reached).
RID_R1 = fixture_uuid("pr2-rf-r1")


def _good(tmp_path: Path, *run_ids: str, tenant_id: str = H.T_ID):
    """A tenant under the configured data root, its natural runs folder as run setup leaves it
    (#1187 R1: no `_tenant.json`) and a real run folder per id."""
    t = H.tenant(P.data_root(), tenant_id)
    H.runs_folder(t)
    for rid in run_ids:
        H.make_run(t.runs, rid)
    return t


def _uuid_tenant(*run_ids: str, tenant_id: str = H.T_ID):
    """#1187's natural container (declared changes 1 and 6): a tenant under the configured data
    root, its `<T>/runs` a real folder with NO `_tenant.json`, and a run folder per (UUID) id."""
    t = H.tenant(P.data_root(), tenant_id)
    Path(t.runs).mkdir(parents=True, exist_ok=True)
    for rid in run_ids:
        H.make_run(t.runs, rid)
    return t


def _post_runs_episode(tenant_id: str, labels: tuple[str, ...]) -> tuple[Path, str, dict]:
    """#1187's episode after RUNS: `<T>/episodes/<uuid>/` with its arm roster naming `labels`
    and a real arm folder at each roster id (no record anywhere). Returns
    `(folder, episode id, roster)`."""
    from defender.tests.ids_1187 import _spec1187 as S

    episode_id = S.new_id()
    roster = {label: S.new_id() for label in labels}
    ep = S.make_episode(P.data_root(), tenant_id, episode_id, labels=labels, roster=roster,
                        arms=True)
    return ep, episode_id, roster


# ==========================================================================================
# A — one refusal family from opening a run.
# ==========================================================================================

def test_a_natural_open_refuses_only_with_run_refused_and_absent_only_when_gone(tmp_path):
    """`runs.open` over a container that cannot be read — a link at `<T>/runs` — refuses with
    `RunUnreachable`, a `RunRefused`, raised from the container's `TenantRefused`. An absent
    container is `RunAbsent`: the run is gone with it. `resolve` answers the same family; an
    address naming another tenant stays `TenantRefused` (a caller's bug). Positive control: the
    same open over the good container hands out the run. RED before the fix: the container
    faults are a bare `TenantRefused`, which an `except RunRefused` misses.

    #1187 declared changes 1 and 6 (R1): the record faults (a corrupt `_tenant.json`, none,
    another tenant's) are retired — no record is judged, and a container holding none is the
    good one. Ids are UUIDs. Declared change 8 (S-iso): the link is refused by the walk from
    `<T>`; the open still answers the one `RunRefused` family naming the level, but whether as
    `RunUnreachable` raised from a `TenantRefused` or as a `RunRefused` of the walk's own is not
    pinned (the design allows either at a link below `<T>`). (Name kept.)"""
    import uuid

    from defender.run_repository import RunAbsent, RunAddress, RunRefused

    r1 = str(uuid.uuid4())
    t = _uuid_tenant(r1)
    runs = t.runs_repository()
    assert not (Path(t.runs) / "_tenant.json").exists()
    assert Path(runs.open(_rid(r1)).run_dir) == Path(t.runs) / r1, "positive control"
    assert Path(runs.resolve(RunAddress(H.T_ID, r1)).run_dir) == Path(t.runs) / r1

    moved = tmp_path / "runs-elsewhere"
    Path(t.runs).rename(moved)
    os.symlink(moved, t.runs)
    for door, call in (("open", lambda: runs.open(_rid(r1))),
                       ("resolve", lambda: runs.resolve(RunAddress(H.T_ID, r1)))):
        err = H.raised(call)
        assert isinstance(err, RunRefused), f"{door} under a linked runs folder raised {err!r}"
        assert not isinstance(err, RunAbsent), door
        assert str(t.runs) in H.message(err), f"{door}: the refusal names the level: {err!r}"
    os.unlink(t.runs)
    err = H.raised(runs.open, _rid(r1))
    assert isinstance(err, RunAbsent), f"open over an absent container raised {err!r}"
    moved.rename(t.runs)
    assert Path(runs.open(_rid(r1)).run_dir) == Path(t.runs) / r1, "the folder put back"

    foreign = H.raised(runs.resolve, RunAddress(H.U_ID, r1))
    assert isinstance(foreign, _tenant.TenantRefused), (
        f"resolve of another tenant's address must stay the caller's TenantRefused: {foreign!r}")


def test_a_an_arm_whose_container_goes_bad_after_the_view_opened_is_run_refused(tmp_path):
    """An episode view's `open` answers the same family: a container removed outright after
    the view opened is `RunAbsent`. Positive control: the arm opens before the fault.

    #1187 declared changes 2, 6 and 15 (R1, R2): the record halves (a `_tenant.json` removed or
    corrupted after the view opened) are retired — no arm container holds a record. The episode
    is `<T>/episodes/<uuid>/` and the arm is at its roster id. (A link at the arm container is
    pinned by
    `ids_1187/test_1187_layout_isolation.py::test_a_link_at_an_arm_container_is_refused_and_the_real_folder_opens`.)
    (Name kept.)"""
    from defender.run_repository import RunAbsent

    t = _uuid_tenant()
    ep, episode_id, roster = _post_runs_episode(H.T_ID, ("a", "b"))
    view = t.runs_repository().episode(episode_id)
    arm = view.arm_id("a")
    assert str(arm) == roster["a"]
    assert Path(view.open(arm).run_dir) == ep / "runs" / roster["a"], "positive control"

    (ep / "runs").rename(tmp_path / "container-gone")
    err = H.raised(view.open, arm)
    assert isinstance(err, RunAbsent), f"a removed container raised {err!r}"
    view.close()


def test_a_verify_opens_every_finished_arm_or_hands_back_its_refusal(tmp_path):
    """The launcher's VERIFY step opens each finished arm through `_finished_arms`, which keeps
    a `RunRefused` as that world's own fault. With the container gone after the siblings ran,
    every arm comes back as a `RunRefused` (none raises). Positive control: with the container
    in place every arm is a `Run`. RED before the fix: the container's `TenantRefused` escapes
    `_finished_arms`.

    #1187 declared changes 6 and 15 (R1, R2): the fault is no longer a removed `_tenant.json`
    (no record is judged); it is the arm container itself moved away. The arms are opened by
    the ids the episode's roster holds. (Name kept.)"""
    from defender.learning.branch import cli
    from defender.run_repository import Run, RunRefused

    t = _uuid_tenant()
    labels = ("a", "b", "c")
    ep, episode_id, roster = _post_runs_episode(H.T_ID, labels)
    with t.runs_repository().episode(episode_id) as view:
        arms = cli._finished_arms(view, labels)
        assert all(isinstance(arms[label], Run) for label in labels), f"control: {arms}"
        assert {label: Path(arms[label].run_dir).name for label in labels} == roster
        (ep / "runs").rename(tmp_path / "container-gone")
        arms = cli._finished_arms(view, labels)
    assert sorted(arms) == sorted(labels)
    assert all(isinstance(arms[label], RunRefused) for label in labels), arms


class _ContainerLinkingSibling(P.J.FakeSibling):
    """`J.FakeSibling`, then — once EVERY started sibling has returned — the episode's arm
    container `<ep>/runs` moved outside the episode and a link left at its name: a container
    fault that appears between RUNS and VERIFY (#1187: the record it used to be is retired; a
    link is the fault left, S-iso). Counted under a lock, so the move happens after the last
    sibling finished writing, never under one still running."""

    def __init__(self, *, outside: Path, siblings: int) -> None:
        super().__init__()
        self.outside = outside
        self.siblings = siblings
        self._done = 0
        self._lock = threading.Lock()
        self.linked: Path | None = None

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None, **kw: Any) -> int:
        rc = super().__call__(argv, env=env, **kw)
        with self._lock:
            self._done += 1
            ep = self.episode_of(list(argv))
            if self._done == self.siblings and ep is not None and self.linked is None:
                moved = self.outside / "runs-moved"
                (ep / "runs").rename(moved)
                os.symlink(moved, ep / "runs")
                self.linked = ep / "runs"
        return rc


def _world_reasons(episode_dir: Path) -> dict[str, str]:
    from defender import _yaml

    records = episode_dir / "world_records"
    if not records.is_dir():
        return {}
    return {p.stem: (_yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("reason")
            for p in sorted(records.glob("*.yaml"))}


def _steps(episode_dir: Path) -> list[str]:
    """The launcher's stage timing record's steps (`learning.branch.timing`, #1025 O7): a step
    is on it once its boundary was crossed, the judge's included when the grade failed."""
    from defender import _io
    from defender.learning.branch import timing

    with _io.bind(episode_dir) as bound:
        return [row["step"] for row in timing.read_stage_timings(bound) or []]


def test_a_a_container_linked_after_the_siblings_ran_is_recorded_and_judged(
        tmp_path, monkeypatch):
    """Driven through the launcher (`learning/branch/cli.main`): the siblings ran, then their
    container `<ep>/runs` was swapped for a link to a real folder holding every finished arm.
    VERIFY opens each arm through the episode view, which never follows the link: every world
    is recorded `not archived` (its arm refused — `RunRefused`, or the container's
    `TenantRefused`, which VERIFY must hold too), the launch returns a status rather than
    raising, and the judge step is still reached (its row is on the stage timing record).
    Nothing is archived from the link's target. Positive control: a clean launch under fresh
    roots archives the worlds, records none `not archived` and grades.

    Review round 2, F24: the launcher-level half of the retired
    `test_a_a_container_spoiled_after_the_siblings_ran_is_recorded_and_judged`, whose fault (a
    spoiled `_tenant.json`) #1187 R1 retires; S-iso lets the open raise either class here, and
    `_finished_arms` catching only `RunRefused` would crash the launch on the other."""
    est, src = P.launch_source(tmp_path)
    outside = tmp_path / "outside-the-episode"
    outside.mkdir()
    spawn = _ContainerLinkingSibling(outside=outside, siblings=len(P.T.WORLDS))
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src), spawn=spawn)
    assert got.questioner.calls > 0, f"the launch never ran: {got.message!r}"
    assert spawn.faults == [], spawn.faults
    unplanted = "the double never linked the container: the fault this test is about was not planted"
    assert spawn.linked is not None, unplanted
    assert spawn.linked.is_symlink(), unplanted
    assert got.raised is None, f"a container fault escaped the launch: {got.raised!r}"
    assert isinstance(got.rc, int)
    (ep,) = P.launched_episodes()
    reasons = _world_reasons(ep)
    assert sorted(reasons) == sorted(P.T.WORLDS), reasons
    assert set(reasons.values()) == {"not archived"}, reasons
    assert "judge" in _steps(ep), f"the judge step was not reached after VERIFY: {_steps(ep)}"
    archived = [q for q in (ep / "worlds").rglob("report.md")] if (ep / "worlds").is_dir() else []
    assert archived == [], f"a world was archived through the linked container: {archived}"

    control_root = tmp_path / "control"
    control_root.mkdir()
    monkeypatch.setenv(P.DATA_ROOT_ENV, str(tmp_path / "control-data"))
    P.roots(control_root, monkeypatch)
    est2, src2 = P.launch_source(control_root)
    clean = P.drive_launch(est2, P.launch_argv(P.LAUNCH_TENANT, src2))
    assert clean.raised is None, f"the control did not launch: {clean!r}"
    assert clean.rc == 0, f"the control did not launch: {clean!r}"
    (ep2,) = P.launched_episodes()
    assert "not archived" not in _world_reasons(ep2).values()
    assert (ep2 / "worlds" / "b" / "report.md").is_file()
    assert (ep2 / "judge.yaml").is_file()
    assert clean.judge.prompts


# ==========================================================================================
# B — the curation drain: gone is artifact-missing; any other refusal is transient.
# ==========================================================================================

def _queued(paths: Any, case_id: str) -> dict | None:
    row = Path(paths.state_root) / "author-queue" / f"{case_id}.json"
    return json.loads(row.read_text(encoding="utf-8")) if row.is_file() else None


def test_b_a_row_that_cannot_be_reached_right_now_is_a_counted_transient_attempt(
        tmp_path, monkeypatch):
    """A row whose tenant cannot be accepted (no such tenant), whose run's name holds a link
    (a refused entry), or whose container cannot be trusted (its `_tenant.json` removed) is
    re-queued with `attempts: 1` — not dead-lettered, not served — and at
    `LEAD_AUTHOR_MAX_RETRIES` quarantined `transient-exhausted`. Positive control in the same
    ticks: a row whose run folder is GONE is `artifact-missing` at once, and a good row is
    served. RED before the fix: every such row is `artifact-missing` on the first tick.

    #1187 declared changes 1 and 6 (R1): the container that cannot be trusted is no longer one
    whose `_tenant.json` was removed (no record is judged; such a container serves) — it is one
    whose `<U>/runs` is a link. Run ids are UUIDs, and neither container holds a record.
    (Name kept.)"""
    import uuid

    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "2")
    r1, linked, nope = (str(uuid.uuid4()) for _ in range(3))
    t = _uuid_tenant(r1)
    u = _uuid_tenant(r1, tenant_id=H.U_ID)
    os.symlink(Path(t.runs) / r1, Path(t.runs) / linked)
    paths = P.loop_paths(tmp_path)
    transient = {
        "ghost": {"case_id": "ghost", "tenant_id": "ghost", "run_id": r1},
        "linked": {"case_id": "linked", "tenant_id": H.T_ID, "run_id": linked},
        "unreachable": {"case_id": "unreachable", "tenant_id": H.U_ID, "run_id": r1},
    }
    for case_id, body in transient.items():
        P.queue_row(paths, case_id, body)
    P.queue_row(paths, "gone", {"case_id": "gone", "tenant_id": H.T_ID, "run_id": nope})
    P.queue_row(paths, "own", {"case_id": "own", "tenant_id": H.T_ID, "run_id": r1})
    moved = tmp_path / "u-runs-elsewhere"
    Path(u.runs).rename(moved)
    os.symlink(moved, u.runs)

    lane = P.Lane()
    P.drain(paths, lane)
    assert lane.run_dirs == [Path(t.runs) / r1], f"served {lane.run_dirs}"
    gone = P.dead_letter(paths, "gone")
    assert gone is not None
    assert gone.get("failed") == "artifact-missing", gone
    for case_id in transient:
        assert P.dead_letter(paths, case_id) is None, (
            f"{case_id} was dead-lettered at once: {P.dead_letter(paths, case_id)!r}")
        row = _queued(paths, case_id)
        assert row is not None, f"{case_id} was not re-queued"
        assert row.get("attempts") == 1, f"{case_id}: {row!r}"

    P.drain(paths, P.Lane())
    for case_id in transient:
        letter = P.dead_letter(paths, case_id)
        assert letter is not None, f"{case_id} was not quarantined at the retry ceiling"
        assert str(letter.get("failed", "")).startswith("transient-exhausted"), (
            f"{case_id}: {letter!r}")
        assert not P.still_queued(paths, case_id)


# ==========================================================================================
# C — the data root is read only when a curation row is to be served.
# ==========================================================================================

class _Branch:
    """`AuthorBranch`'s seam for one tick, its worktree the given real git tree."""

    branch_prefix = "lead-author/"

    def __init__(self, worktree: Path) -> None:
        self.worktree = worktree
        self.events: list[str] = []

    def branch_name(self, batch_id: str) -> str:
        return f"{self.branch_prefix}{batch_id}"

    def open_pr_exists(self) -> bool:
        return False

    def start_batch(self, _batch_id: str) -> Path:
        self.events.append("start")
        return self.worktree

    def finish_batch(self, _batch_id: str, _wt: Path) -> None:
        self.events.append("finish")

    def cleanup(self, _wt: Path) -> None:
        self.events.append("cleanup")


class _Box:
    def __init__(self) -> None:
        self.started: list[str] = []

    def start(self, request: Any, **_kw: Any) -> Any:
        self.started.append(request.name)
        return SimpleNamespace(name=request.name, sandboxed=False)


def _tick(paths: Any, *, lane: Any, pitfalls: list[str], box: _Box) -> int:
    from defender.learning.core import drains

    def run_pitfalls(_wt_paths: Any, _state: Any, **_kw: Any) -> int:
        pitfalls.append("pitfalls")
        return 0

    return drains.lead_author_drain(
        paths, run_lead_author=lane, run_pitfalls=run_pitfalls,
        branch=_Branch(Path(paths.repo_root)), start_box=box.start,
        stop_box=lambda *_a, **_k: None, scrub=lambda *_a, **_k: None)


def test_c_a_pitfalls_only_tick_needs_no_data_root(tmp_path, monkeypatch):
    """With `DEFENDER_DATA_ROOT` unset and only pitfalls at threshold (no curation row), the
    lead-author tick starts its box and reaches the pitfalls step. RED before the fix: the
    marker step resolves the data root unconditionally inside the batch and refuses it."""
    from defender.learning.core import persist
    from defender.tests._state1135 import state_for_paths

    paths = P.loop_paths(tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls([{"pitfall_id": "r:0", "system": "elastic"}],
                            state=state_for_paths(paths))
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    pitfalls: list[str] = []
    box = _Box()
    lane = P.Lane()
    rc = _tick(paths, lane=lane, pitfalls=pitfalls, box=box)
    assert rc == 0
    assert box.started, "the tick never started its box"
    assert pitfalls == ["pitfalls"], "the pitfalls step was not reached"
    assert lane.handed == []


def test_c_a_tick_with_rows_and_no_data_root_refuses_before_any_box(tmp_path, monkeypatch):
    """With a curation row queued and `DEFENDER_DATA_ROOT` unset, the tick refuses before its
    box is started — the row still queued, not claimed. The refusal is the stage's
    configuration refusal (`FatalConfigError`, raised from the data root's `TenantRefused`:
    PR #1236's second review round). Positive control: the root restored, the same tick starts
    the box and serves the row. RED before the fix: the box is started first and the refusal
    comes from inside the batch."""
    from defender.learning.core.config import FatalConfigError

    t = _good(tmp_path, RID_R1)
    root = os.environ[P.DATA_ROOT_ENV]
    paths = P.loop_paths(tmp_path)
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": H.T_ID, "run_id": RID_R1})
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    box = _Box()
    lane = P.Lane()
    err = H.raised(_tick, paths, lane=lane, pitfalls=[], box=box)
    assert isinstance(err, FatalConfigError), f"the tick did not refuse: {err!r}"
    assert isinstance(err.__cause__, _tenant.TenantRefused), err.__cause__
    assert box.started == [], "a box was started for a tick that could not serve its rows"
    assert _queued(paths, "case-t") is not None, "the row left the queue"
    assert lane.handed == []

    monkeypatch.setenv(P.DATA_ROOT_ENV, root)
    assert _tick(paths, lane=lane, pitfalls=[], box=box) == 0
    assert box.started, "the control never started its box"
    assert lane.run_dirs == [Path(t.runs) / RID_R1]


# ==========================================================================================
# D — one opener for `--tenant T <run_id>`; its refusal is printed, not logged.
# ==========================================================================================

@contextmanager
def _no_logging():
    """Every log record dropped, so only what a command PRINTS reaches stderr."""
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(logging.NOTSET)


def _lead_author_main():
    from defender.learning.leads import lead_author

    return lead_author.main


def _workspace_map_main():
    from defender.scripts import workspace_map

    return workspace_map.main


@pytest.mark.parametrize("cli", ["lead_author", "visualize_run", "workspace_map",
                                 "visualize_run --episode"])
def test_d_each_run_id_command_prints_its_refusal_on_stderr(tmp_path, d9_tenant, cli):
    """Each command line that takes `--tenant T <run_id>` — the lead author, the run page, the
    workspace map (and the run page with `--episode`) — with a run id that names nothing, and
    every log record disabled: it exits with its own refusal status and the refusal, naming the
    run, is on stderr. RED before the fix: the lead author and the run page only LOG it (a log
    level hides it); the workspace map already printed it (green: it moved onto the shared
    opener unchanged in this respect)."""
    from defender.tests._state1135 import curation_run_dir

    curation_run_dir("r-real", tenant_id=d9_tenant)
    argv, main, status = {
        "lead_author": (["--tenant", d9_tenant, "nope-run"], _lead_author_main(), 2),
        "visualize_run": (P.new_run_page_argv(d9_tenant, "nope-run"), P.run_page_main(), 1),
        "workspace_map": (["workspace_map.py", "--tenant", d9_tenant, "nope-run"],
                          _workspace_map_main(), 2),
        "visualize_run --episode": (
            P.new_run_page_argv(d9_tenant, "nope-run", episode_id="no-such-episode"),
            P.run_page_main(), 1),
    }[cli]
    with _no_logging():
        got = P.drive_cli(main, argv)
    assert got.rc == status, f"{cli}: {got.rc} {got.said!r}"
    assert "nope-run" in got.err, f"{cli} did not print its refusal on stderr: {got.err!r}"
    assert got.out == ""


def test_d_the_shared_opener_opens_a_natural_run_and_an_arm_or_returns_the_refusal(
        tmp_path, d9_tenant):
    """`open_requested_run(data_root, tenant, run_id, episode_id=None)`: the natural run, or
    with an episode id the arm, opened through the tenant's repository — or the refusal as one
    line of text naming the request. RED before the fix: no such function.

    #1187 declared changes 1, 2, 5 and 15: the arm is opened under `<T>/episodes/<uuid>/` by
    the id its roster holds (never `<episode>-<label>`), and every id is a UUID — the absent
    run and the absent episode are UUIDs that name nothing. (Name kept.)"""
    import uuid

    from defender.run_repository import Run, open_requested_run

    real = str(uuid.uuid4())
    run_dir = H.make_run(P.data_root() / d9_tenant / "runs", real)
    ep, episode_id, roster = _post_runs_episode(d9_tenant, ("a",))
    root = _tenant.resolve_data_root()

    run = open_requested_run(root, d9_tenant, real)
    assert isinstance(run, Run), run
    assert Path(run.run_dir) == run_dir
    arm = open_requested_run(root, d9_tenant, roster["a"], episode_id=episode_id)
    assert isinstance(arm, Run), arm
    assert Path(arm.run_dir) == ep / "runs" / roster["a"]

    for raw_tenant, raw_run, episode_id in ((d9_tenant, str(uuid.uuid4()), None),
                                           ("no-such-tenant", real, None),
                                           (d9_tenant, real, str(uuid.uuid4())),
                                           (d9_tenant, f"../{real}", None)):
        refused = open_requested_run(root, raw_tenant, raw_run, episode_id=episode_id)
        assert isinstance(refused, str), f"{raw_tenant}/{raw_run}/{episode_id}: {refused!r}"
        assert "cannot be opened" in refused, refused
        assert "\n" not in refused, refused


# ==========================================================================================
# E — the tracer's listing: one hold, every run.
# ==========================================================================================

def test_e_the_tenants_runs_come_from_one_hold_of_the_runs_folder(tmp_path):
    """`RunsRepository.all_runs()` holds the runs folder ONCE and hands out a `Run` for every listed run, in id order, each reading its own records;
    `trace_lesson.tenant_runs` answers the same runs. An absent runs folder holds none.
    Positive control on the cost: opening the same runs one by one holds the folder once per
    run. RED before the fix: no `all_runs`, and the tracer lists then opens each run."""
    from defender.learning.ops import trace_lesson
    from defender.run_repository import Run, RunsRepository

    # #1187 declared change 1: uuid run ids (sorted: the listing hands them out in id order).
    from defender.tests._fixture_uuid import fixture_uuid

    ids = sorted(fixture_uuid(f"rf-e-r{i}") for i in (1, 2, 3))
    t = _good(tmp_path, *ids)
    rec = H.RecordingIO()
    got = RunsRepository(t, io=rec).all_runs()
    assert [str(r.id) for r in got] == ids
    assert all(isinstance(r, Run) for r in got)
    assert [Path(r.run_dir) for r in got] == [Path(t.runs) / i for i in ids]
    assert all("seed" in (r.facts.alert.read() or "") for r in got)
    assert len(rec.named("hold")) == 1, f"the listing held the folder {rec.named('hold')!r}"

    one_by_one = H.RecordingIO()
    repo = RunsRepository(t, io=one_by_one)
    for run_id in repo.list():
        repo.open(run_id)
    assert len(one_by_one.named("hold")) == len(ids) + 1, "control: per-id opens hold each"

    assert [str(r.id) for r in trace_lesson.tenant_runs(H.T_ID)] == ids

    empty = _good(tmp_path, tenant_id=H.U_ID)
    shutil.rmtree(empty.runs)
    assert empty.runs_repository().all_runs() == []
