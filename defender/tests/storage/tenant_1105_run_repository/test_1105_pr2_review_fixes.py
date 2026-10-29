"""Review-finding regressions: natural open refusals, container spoiled after view, transient drain attempts, CLI stderr refusals."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import uuid
import threading

import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.records._tenant_id import TenantRefused


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _rid(text: str):
    from defender.records import RunId

    return RunId.parse(text)


#: A natural run's id in the drain scenes: a UUID, since a row naming anything else is
#: quarantined before rehydration is reached.
RID_R1 = fixture_uuid("pr2-rf-r1")


def _uuid_tenant(*run_ids: str, tenant_id: str = H.T_ID):
    """A tenant under the configured data root, its `<T>/runs` a real folder (no `_tenant.json`)
    and a run folder per id."""
    t = H.tenant(location_path(P.data_root)(), tenant_id)
    Path(location_path(t.runs)).mkdir(parents=True, exist_ok=True)
    for rid in run_ids:
        H.make_run(location_path(t.runs), rid)
    return t


def _post_runs_episode(tenant_id: str, labels: tuple[str, ...]) -> tuple[Path, str, dict]:
    """An episode after RUNS: `<T>/episodes/<uuid>/` with its arm roster naming `labels` and a
    real arm folder at each roster id. Returns `(folder, episode id, roster)`."""
    from defender.tests.storage.ids_1187 import _spec1187 as S

    episode_id = S.new_id()
    ep = S.make_episode(location_path(P.data_root)(), tenant_id, episode_id, labels=labels, roster=True,
                        arms=True)
    return ep, episode_id, S.read_roster(ep)


def test_a_natural_open_refuses_only_with_run_refused_and_absent_only_when_gone(tmp_path):
    """A link at `<T>/runs` makes `open` and `resolve` refuse with a `RunRefused` (a bare
    `TenantRefused` would slip past `except RunRefused`); an absent container is `RunAbsent`; an
    address naming another tenant stays `TenantRefused` (a caller's bug)."""
    import uuid

    from defender.records import RunAbsent, RunAddress, RunRefused

    r1 = str(uuid.uuid4())
    t = _uuid_tenant(r1)
    runs = t.runs_repository()
    assert not (Path(location_path(t.runs)) / "_tenant.json").exists()
    assert Path(runs.open(_rid(r1)).run_dir) == Path(location_path(t.runs)) / r1, "positive control"
    assert Path(runs.resolve(RunAddress(H.T_ID, r1)).run_dir) == Path(location_path(t.runs)) / r1

    moved = tmp_path / "runs-elsewhere"
    Path(location_path(t.runs)).rename(moved)
    os.symlink(moved, location_path(t.runs))
    for door, call in (("open", lambda: runs.open(_rid(r1))),
                       ("resolve", lambda: runs.resolve(RunAddress(H.T_ID, r1)))):
        err = H.raised(call)
        assert isinstance(err, RunRefused), f"{door} under a linked runs folder raised {err!r}"
        assert not isinstance(err, RunAbsent), door
        assert str(location_path(t.runs)) in H.message(err), f"{door}: the refusal names the level: {err!r}"
    os.unlink(location_path(t.runs))
    err = H.raised(runs.open, _rid(r1))
    assert isinstance(err, RunAbsent), f"open over an absent container raised {err!r}"
    moved.rename(location_path(t.runs))
    assert Path(runs.open(_rid(r1)).run_dir) == Path(location_path(t.runs)) / r1, "the folder put back"

    foreign = H.raised(runs.resolve, RunAddress(H.U_ID, r1))
    assert isinstance(foreign, TenantRefused), (
        f"resolve of another tenant's address must stay the caller's TenantRefused: {foreign!r}")


def test_a_an_arm_whose_container_goes_bad_after_the_view_opened_is_run_refused(tmp_path):
    """An arm container removed after the episode view opened makes the view's `open` answer
    `RunAbsent`. (A linked arm container: `test_1187_layout_isolation.py`'s
    `test_linked_repository_levels_refuse_and_restore[arms]`.)"""
    from defender.records import RunAbsent

    t = _uuid_tenant()
    ep, episode_id, roster = _post_runs_episode(H.T_ID, ("a", "b"))
    view = t.runs_repository().episode(episode_id)
    arm = view.arm_id(P.T.world_id(ep, "a"))
    assert str(arm) == roster[P.T.world_id(ep, "a")]
    assert Path(view.open(arm).run_dir) == ep / "runs" / roster[P.T.world_id(ep, "a")], "positive control"

    (ep / "runs").rename(tmp_path / "container-gone")
    err = H.raised(view.open, arm)
    assert isinstance(err, RunAbsent), f"a removed container raised {err!r}"
    view.close()


def test_a_verify_opens_every_finished_arm_or_hands_back_its_refusal(tmp_path):
    from defender.learning.branch import cli
    from defender.records import Run, RunRefused

    t = _uuid_tenant()
    labels = ("a", "b", "c")
    ep, episode_id, roster = _post_runs_episode(H.T_ID, labels)
    with t.runs_repository().episode(episode_id) as view:
        arms = cli._finished_arms(view, [P.T.world_id(ep, label) for label in labels])
        assert all(isinstance(arms[P.T.world_id(ep, label)], Run) for label in labels), f"control: {arms}"
        assert {P.T.world_id(ep, label): Path(arms[P.T.world_id(ep, label)].run_dir).name for label in labels} == roster
        (ep / "runs").rename(tmp_path / "container-gone")
        arms = cli._finished_arms(view, [P.T.world_id(ep, label) for label in labels])
    assert sorted(arms) == sorted(P.T.world_id(ep, label) for label in labels)
    assert all(isinstance(arms[P.T.world_id(ep, label)], RunRefused) for label in labels), arms


class _ContainerLinkingSibling(P.J.FakeSibling):
    """`J.FakeSibling`, then, once EVERY started sibling has returned, the arm container
    `<ep>/runs` moved outside the episode and a link left at its name: a container fault
    between RUNS and VERIFY. Counted under a lock, so the move never runs under a live sibling."""

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
    """The launcher's stage timing record's steps: a step is on it once its boundary was
    crossed, the judge's included when the grade failed."""
    from defender import _io
    from defender.learning.branch import timing

    with _io.bind(episode_dir) as bound:
        return [row["step"] for row in timing.read_stage_timings(bound) or []]


def test_a_a_container_linked_after_the_siblings_ran_is_recorded_and_judged(
        tmp_path, monkeypatch):
    """Through the launcher: after the siblings ran, `<ep>/runs` became a link to a folder
    holding every finished arm. VERIFY never follows it: every world is `not archived` (its
    `RunRefused`, or the container's `TenantRefused`, caught too), the launch returns a status
    and the judge step is still reached. Control: a clean launch archives and grades."""
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
    assert sorted(reasons) == sorted(P.T.world_id(ep, label) for label in P.T.WORLDS), reasons
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
    assert (ep2 / "worlds" / P.T.world_id(ep2, "b") / "report.md").is_file()
    assert (ep2 / "judge.yaml").is_file()
    assert clean.judge.prompts


def _queued(paths: Any, case_id: str) -> dict | None:
    row = Path(location_path(paths.state_root)) / "author-queue" / f"{case_id}.json"
    return json.loads(row.read_text(encoding="utf-8")) if row.is_file() else None


def test_b_a_row_that_cannot_be_reached_right_now_is_a_counted_transient_attempt(
        tmp_path, monkeypatch):
    monkeypatch.setenv("LEAD_AUTHOR_MAX_RETRIES", "2")
    r1, linked, nope, only_in_u = (str(uuid.uuid4()) for _ in range(4))
    t = _uuid_tenant(r1)
    u = _uuid_tenant(r1, only_in_u, tenant_id=H.U_ID)
    os.symlink(Path(location_path(t.runs)) / r1, Path(location_path(t.runs)) / linked)
    paths = P.loop_paths(tmp_path)
    transient = {
        "ghost": {"case_id": "ghost", "tenant_id": fixture_uuid("tenant:ghost"), "run_id": r1},
        "linked": {"case_id": "linked", "tenant_id": H.T_ID, "run_id": linked},
        "unreachable": {"case_id": "unreachable", "tenant_id": H.U_ID, "run_id": r1},
    }
    for case_id, body in transient.items():
        P.queue_row(paths, case_id, body)
    gone = {
        "gone": {"case_id": "gone", "tenant_id": H.T_ID, "run_id": nope},
        "crossed": {"case_id": "crossed", "tenant_id": H.T_ID, "run_id": only_in_u},
    }
    for case_id, body in gone.items():
        P.queue_row(paths, case_id, body)
    P.queue_row(paths, "own", {"case_id": "own", "tenant_id": H.T_ID, "run_id": r1})
    moved = tmp_path / "u-runs-elsewhere"
    Path(location_path(u.runs)).rename(moved)
    os.symlink(moved, location_path(u.runs))

    lane = P.Lane()
    P.drain(paths, lane)
    assert lane.run_dirs == [Path(location_path(t.runs)) / r1], f"served {lane.run_dirs}"
    for case_id in gone:
        letter = P.dead_letter(paths, case_id)
        assert letter is not None, f"{case_id}: {letter!r}"
        assert letter.get("failed") == "artifact-missing", f"{case_id}: {letter!r}"
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


class _Box:
    def __init__(self) -> None:
        self.started: list[str] = []

    def start(self, request: Any, **_kw: Any) -> Any:
        self.started.append(request.name)
        return SimpleNamespace(name=request.name, sandboxed=False)


@pytest.fixture
def published(tmp_path, data_root):
    """The fixture tenant published for real, its forge bound: the lead-author drain batches
    into the tenant repo, so its ticks run tenant-selected over it."""
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        yield t


def _tenant_paths(t: Any, tmp_path: Path) -> Any:
    from defender.tests.tenancy.tenant_1108_p4._drain_support import drain_paths, product_repo

    paths = drain_paths(t, product_repo(tmp_path))
    Path(location_path(paths.state_root)).mkdir(parents=True, exist_ok=True)
    return paths


def _tick(t: Any, paths: Any, *, lane: Any, pitfalls: list[str], box: _Box) -> int:
    """One REAL `lead_author_drain` tick over the tenant path, with the tenant forge fake's
    client and an issuer-fake identity."""
    from defender.learning.core import drains

    def run_pitfalls(_wt_paths: Any, _state: Any, **_kw: Any) -> int:
        pitfalls.append("pitfalls")
        return 0

    return drains.lead_author_drain(
        paths, run_lead_author=lane, run_pitfalls=run_pitfalls,
        client=t.forge.client, identity=t.vault.identity(), directory=t.directory, start_box=box.start,
        stop_box=lambda *_a, **_k: None)


def test_c_a_pitfalls_only_tick_needs_no_data_root(published, tmp_path, monkeypatch):
    """With `DEFENDER_DATA_ROOT` unset, a tick with only pitfalls work still starts its box and
    reaches pitfalls."""
    from defender.learning.core import persist
    from defender.tests.support.learning.core._state1135 import state_for_paths

    paths = _tenant_paths(published, tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls([{"pitfall_id": "r:0", "system": "elastic"}],
                            state=state_for_paths(paths))
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    pitfalls: list[str] = []
    box = _Box()
    lane = P.Lane()
    rc = _tick(published, paths, lane=lane, pitfalls=pitfalls, box=box)
    assert rc == 0
    assert box.started, "the tick never started its box"
    assert pitfalls == ["pitfalls"], "the pitfalls step was not reached"
    assert lane.handed == []


def test_c_a_tenant_tick_serves_its_rows_from_its_own_root_without_the_env(
        published, tmp_path, monkeypatch):
    """A drain is tenant-selected, so a queued row's run is rehydrated under that tenant's own
    data root: with `DEFENDER_DATA_ROOT` unset, the row is still served."""
    t = published
    H.make_run(H.runs_folder(t.tenant), RID_R1)
    paths = _tenant_paths(t, tmp_path)
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": t.tenant_id, "run_id": RID_R1})
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    box = _Box()
    lane = P.Lane()
    assert _tick(t, paths, lane=lane, pitfalls=[], box=box) == 0
    assert box.started, "the tick never started its box"
    assert lane.run_dirs == [Path(location_path(t.tenant.runs)) / RID_R1]
    assert _queued(paths, "case-t") is None, "the served row was left on the queue"


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
    from defender.cli import workspace_map

    return workspace_map.main


@pytest.mark.parametrize("cli", ["lead_author", "visualize_run", "workspace_map",
                                 "visualize_run --episode"])
def test_d_each_run_id_command_prints_its_refusal_on_stderr(tmp_path, d9_tenant, cli):
    from defender.tests.support.learning.core._state1135 import curation_run_dir

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
