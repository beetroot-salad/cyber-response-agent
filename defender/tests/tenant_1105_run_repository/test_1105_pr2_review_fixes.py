"""Review-finding regressions: natural open refusals, container spoiled after view, transient drain attempts, CLI stderr refusals."""
from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender import _tenant
from defender.tests import _judge_921 as J
from defender.tests.tenant_1105_run_repository import _spec1105 as H
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P

EP = "20260728t161845z-src-n59"


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _episodes() -> Path:
    return Path(os.environ[P.EPISODES_BASE_ENV])


def _rid(text: str):
    from defender.run_repository import RunId

    return RunId.parse(text)


def _good(tmp_path: Path, *run_ids: str, tenant_id: str = H.T_ID):
    """A tenant under the configured data root, its natural runs folder as run setup leaves it
    (`_tenant.json` naming it) and a real run folder per id."""
    t = H.tenant(P.data_root(), tenant_id)
    H.runs_folder(t)
    for rid in run_ids:
        H.make_run(t.runs, rid)
    return t


def _episode(*, container: str | None, arms: tuple[str, ...] = (),
             episode_id: str = EP) -> Path:
    """`<episodes>/<episode_id>/` with a manifest-shaped file and, when `container` names a
    tenant, its `runs/` with that tenant's record (the real writer) and a real folder per arm."""
    ep = _episodes() / episode_id
    ep.mkdir(parents=True)
    (ep / "family.yaml").write_text("episode_id: x\n", encoding="utf-8")
    if container is not None:
        (ep / "runs").mkdir()
        _tenant.ensure_runs_base_record(ep / "runs", container)
    for label in arms:
        H.make_run(ep / "runs", f"{episode_id}-{label}", alert=f'{{"arm": "{label}"}}\n')
    return ep


# ==========================================================================================
# A — one refusal family from opening a run.
# ==========================================================================================

def test_a_natural_open_refuses_only_with_run_refused_and_absent_only_when_gone(tmp_path):
    """`runs.open` over a container that cannot be trusted or read — a corrupt `_tenant.json`,
    none, another tenant's, a link at `<T>/runs` — refuses with `RunUnreachable`, a
    `RunRefused`, raised from the container's `TenantRefused` (whose text it carries). An
    absent container is `RunAbsent`: the run is gone with it. `resolve` answers the same
    family; an address naming another tenant stays `TenantRefused` (a caller's bug). Positive
    control: the same open over the good container hands out the run. RED before the fix: the
    container faults are a bare `TenantRefused`, which an `except RunRefused` misses."""
    from defender.run_repository import RunAbsent, RunAddress, RunRefused, RunUnreachable

    t = _good(tmp_path, "r1")
    runs = t.runs_repository()
    record = Path(t.runs) / "_tenant.json"
    good = record.read_bytes()
    assert Path(runs.open(_rid("r1")).run_dir) == Path(t.runs) / "r1", "positive control"

    faults = {
        "a corrupt record": lambda: record.write_text("{not json", encoding="utf-8"),
        "no record": record.unlink,
        "another tenant's record": lambda: record.write_bytes(
            H.tenant_record_text(H.U_ID).encode("utf-8")),
    }
    for what, plant in faults.items():
        plant()
        for door, call in (("open", lambda: runs.open(_rid("r1"))),
                           ("resolve", lambda: runs.resolve(RunAddress(H.T_ID, "r1")))):
            err = H.raised(call)
            assert isinstance(err, RunUnreachable), f"{door} over {what} raised {err!r}"
            assert isinstance(err, RunRefused), what
            assert not isinstance(err, RunAbsent), what
            assert isinstance(err.__cause__, _tenant.TenantRefused), (
                f"{door} over {what}: not raised from the container's refusal: {err!r}")
            assert "_tenant.json" in str(err), f"{door} over {what} lost the reason: {err}"
        record.write_bytes(good)
        assert Path(runs.open(_rid("r1")).run_dir) == Path(t.runs) / "r1", f"after {what}"

    moved = tmp_path / "runs-elsewhere"
    Path(t.runs).rename(moved)
    os.symlink(moved, t.runs)
    err = H.raised(runs.open, _rid("r1"))
    assert isinstance(err, RunUnreachable), f"open under a linked runs folder raised {err!r}"
    os.unlink(t.runs)
    err = H.raised(runs.open, _rid("r1"))
    assert isinstance(err, RunAbsent), f"open over an absent container raised {err!r}"
    moved.rename(t.runs)
    assert Path(runs.open(_rid("r1")).run_dir) == Path(t.runs) / "r1", "the folder put back"

    foreign = H.raised(runs.resolve, RunAddress(H.U_ID, "r1"))
    assert isinstance(foreign, _tenant.TenantRefused), (
        f"resolve of another tenant's address must stay the caller's TenantRefused: {foreign!r}")


def test_a_an_arm_whose_container_goes_bad_after_the_view_opened_is_run_refused(tmp_path):
    """An episode view's `open` answers the same family: a container whose `_tenant.json` is
    removed or corrupted after the view opened is `RunUnreachable`; a container removed
    outright is `RunAbsent`. Positive control: the arm opens before the fault. RED before the
    fix: `TenantRefused`."""
    from defender.run_repository import RunAbsent, RunUnreachable

    t = _good(tmp_path)
    ep = _episode(container=H.T_ID, arms=("a",))
    view = t.runs_repository().episode(EP)
    arm = view.arm_id("a")
    assert Path(view.open(arm).run_dir) == ep / "runs" / f"{EP}-a", "positive control"

    (ep / "runs" / "_tenant.json").unlink()
    err = H.raised(view.open, arm)
    assert isinstance(err, RunUnreachable), f"a removed record raised {err!r}"
    (ep / "runs" / "_tenant.json").write_text("{torn", encoding="utf-8")
    err = H.raised(view.open, arm)
    assert isinstance(err, RunUnreachable), f"a corrupt record raised {err!r}"
    (ep / "runs").rename(tmp_path / "container-gone")
    err = H.raised(view.open, arm)
    assert isinstance(err, RunAbsent), f"a removed container raised {err!r}"
    view.close()


def test_a_verify_opens_every_finished_arm_or_hands_back_its_refusal(tmp_path):
    """The launcher's VERIFY step opens each finished arm through `_finished_arms`, which keeps
    a `RunRefused` as that world's own fault. With the container's record removed after the
    siblings ran, every arm comes back as a `RunRefused` (none raises). Positive control: with
    the record in place every arm is a `Run`. RED before the fix: the container's
    `TenantRefused` escapes `_finished_arms`."""
    from defender.learning.branch import cli
    from defender.run_repository import Run, RunRefused

    t = _good(tmp_path)
    labels = ("a", "b", "c")
    ep = _episode(container=H.T_ID, arms=labels)
    with t.runs_repository().episode(EP) as view:
        arms = cli._finished_arms(view, labels)
        assert all(isinstance(arms[label], Run) for label in labels), f"control: {arms}"
        (ep / "runs" / "_tenant.json").unlink()
        arms = cli._finished_arms(view, labels)
    assert sorted(arms) == sorted(labels)
    assert all(isinstance(arms[label], RunRefused) for label in labels), arms


class _ContainerSpoilingSibling:
    """`J.FakeSibling`, then the siblings' container record overwritten with garbage after
    each sibling ran — a container fault that appears between RUNS and VERIFY."""

    def __init__(self, episode_dir: Path) -> None:
        self.inner = J.FakeSibling(episode_dir)
        self.record = Path(episode_dir) / "runs" / "_tenant.json"

    def __call__(self, argv: list[str], **kw: Any) -> int:
        rc = self.inner(argv, **kw)
        self.record.write_text("{spoiled", encoding="utf-8")
        return rc

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)


def _world_reasons(episode_dir: Path) -> dict[str, str]:
    from defender import _yaml

    records = episode_dir / "world_records"
    if not records.is_dir():
        return {}
    return {p.stem: (_yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("reason")
            for p in sorted(records.glob("*.yaml"))}


def test_a_a_container_spoiled_after_the_siblings_ran_is_recorded_and_judged(
        tmp_path, monkeypatch, caplog):
    """Driven through the launcher (`learning/branch/cli.main`): the siblings ran, then their
    container's `_tenant.json` was spoiled. VERIFY records each finished world as `not
    archived` (its run folder refused), the launch returns a status rather than raising, and
    the judge step is still reached — and, since PR #1236's second review round, its door
    judges the container's record as the episode view does, so it refuses the spoiled record
    (logged by the launcher, non-fatal) and writes no `judge.yaml`. The page then refuses the
    spoiled container on its own, non-fatal to the launch, so it is not asserted. Positive
    control: a clean launch under fresh roots archives the worlds, records none `not
    archived` and grades. RED before the fix: the container's `TenantRefused` escapes VERIFY,
    the launch raises, and neither the records nor the judge step are reached."""
    est, src = P.launch_source(tmp_path)
    ep = _episodes() / P.EPISODE_ID
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src),
                         spawn=_ContainerSpoilingSibling(ep))
    assert got.questioner.calls > 0, f"the launch never ran: {got.message!r}"
    assert got.raised is None, f"a container fault escaped the launch: {got.raised!r}"
    assert isinstance(got.rc, int)
    reasons = _world_reasons(ep)
    assert set(reasons.values()) == {"not archived"}, reasons
    assert sorted(reasons) == ["a", "b", "c"], reasons
    judged = [r.getMessage() for r in caplog.records if "the judge pass failed" in r.getMessage()]
    assert judged, "the judge step was not reached after VERIFY"
    assert "_tenant.json" in judged[0], f"the judge refused something else: {judged}"
    assert not (ep / "judge.yaml").exists(), "the judge graded a spoiled container"

    control_root = tmp_path / "control"
    control_root.mkdir()
    monkeypatch.setenv(P.DATA_ROOT_ENV, str(tmp_path / "control-data"))
    P.roots(control_root, monkeypatch)
    est2, src2 = P.launch_source(control_root)
    clean = P.drive_launch(est2, P.launch_argv(P.LAUNCH_TENANT, src2))
    assert clean.raised is None, f"the control did not launch: {clean!r}"
    assert clean.rc == 0, f"the control did not launch: {clean!r}"
    ep2 = _episodes() / P.EPISODE_ID
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
    served. RED before the fix: every such row is `artifact-missing` on the first tick."""
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "2")
    t = _good(tmp_path, "r1")
    u = _good(tmp_path, "r1", tenant_id=H.U_ID)
    os.symlink(Path(t.runs) / "r1", Path(t.runs) / "linked")
    paths = P.loop_paths(tmp_path)
    transient = {
        "ghost": {"case_id": "ghost", "tenant_id": "ghost", "run_id": "r1"},
        "linked": {"case_id": "linked", "tenant_id": H.T_ID, "run_id": "linked"},
        "unreachable": {"case_id": "unreachable", "tenant_id": H.U_ID, "run_id": "r1"},
    }
    for case_id, body in transient.items():
        P.queue_row(paths, case_id, body)
    P.queue_row(paths, "gone", {"case_id": "gone", "tenant_id": H.T_ID, "run_id": "nope"})
    P.queue_row(paths, "own", {"case_id": "own", "tenant_id": H.T_ID, "run_id": "r1"})
    (Path(u.runs) / "_tenant.json").unlink()

    lane = P.Lane()
    P.drain(paths, lane)
    assert lane.run_dirs == [Path(t.runs) / "r1"], f"served {lane.run_dirs}"
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

    t = _good(tmp_path, "r1")
    root = os.environ[P.DATA_ROOT_ENV]
    paths = P.loop_paths(tmp_path)
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": H.T_ID, "run_id": "r1"})
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
    assert lane.run_dirs == [Path(t.runs) / "r1"]


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



# ==========================================================================================
# E — the tracer's listing: one hold, every run.
# ==========================================================================================

