"""#1195 design amendment 3 (2026-10-06), the lessons drain: one box per batch, stopped between
agent runs; the stop fault wins, the box carries its docker, and the lanes get a run handle.

`author_drain` (the lessons and lessons-questioner channels, which share one tick) creates and
checks its box at batch start, as on main, wraps it in a `runtime.box.BoxRuns` handle and stops
it at once. The `box` threaded down to each curator, and so `CorpusAuthorConfig.box`, is that
handle; each box-using spawn runs inside `box_for_run(handle)`, which starts the box for the
spawn, hands the spawn the executor, and stops the box after:

- `_author_batch`: `with box_mod.box_for_run(cfg.box) as run_box: result =
  cfg.invoke_agent(to_author, batch_id, replace(cfg, box=run_box))`;
- `_spawn_repair`: the same for `cfg.invoke_repair`.

So no host step of the lane (capture, settle, agent-report check, judge, restore, commit,
rotation, the undo, the next curator's gate) runs while the box is running, except inside a
spawn's window (O2''); a host step sees the handle, a spawn the executor (O6); nothing a spawn
leaves running outlives its run (O3', O1); a box that won't start or stop halts the batch with
`BoxFault` (O4, D3: `_drain_one_curator` re-raises it; D3a: it outranks the undo's own fault),
and a stop fault outranks the spawn's own failure, which becomes its `__context__` (F1, O5); a
stop fault some layer swallows is still caught by the next run's check before its start (E3').

Every curator scene is `_spec773`'s: a real repo, queue, gate, settle, judge, restore, commit
and rotation; only the spawns, the verifier and the key source are fakes, entering through the
config. The box is a sandboxed executor carrying a fake daemon (`_box1195.FakeDaemon`) as its
docker, which the spawn sites' `box_for_run` and the drain's own stop and removal reach through
it; through `author_drain`, only `start_box=` brings that docker (`X.HeldStart`, or the real
`start_box` with `docker=`). A `Tripwire` is the `docker` first on `PATH`, except in the one
row that runs production's own default docker. The lane's host steps log into a
`_box1195.Journal`, which notes what was running at each. Never `monkeypatch.setattr`.

Tests -> obligations:

- O2''/E5', O6, wiring: `test_each_spawn_runs_in_its_own_window_and_no_host_step_beside_a_running_box`
  (both channels, judged clean and repaired; each spawn handed the executor, the gate and the
  post-rotation hook the handle), `test_one_tick_runs_one_window_per_spawn_across_both_curators`
  (each curator handed the handle), `test_the_pre_state_is_captured_before_the_run_starts`,
  `test_a_failing_spawns_box_is_stopped_before_the_undo_runs`.
- E1'/E4', F2, through the production drain (one create, a stop before the first curator, one
  window per spawn, `rm -f` before the scan; the executor carrying the docker it was created
  with, or production's default): `test_the_production_drain_runs_one_box_stopped_between_its_agent_runs`.
- F1 (O5): `test_a_stop_fault_under_a_failing_spawn_halts_author_drain_with_the_failure_as_context`
  (`RuntimeError`, `AuthorError`, `ModelRetry` x a stop refused, without effect, unproven, the
  seam raising x the questioner following or nothing following; the `holds` control handles
  each as before), and through the DEFAULT curator step,
  `test_a_stop_fault_under_a_failing_default_spawn_halts_the_drain` (the batch box's whole
  docker sequence: nothing after the failed stop but the removal).
- E3' (N11''): `test_a_swallowed_stop_fault_makes_the_next_curators_run_refuse` (a trigger that
  swallows the `BoxFault`; with its `holds` control).
- O4, batch start: `test_a_batch_start_fault_charges_no_curator_row_and_writes_no_stuck_record`
  (create, sentinel, link ban; main's pointer, or `AliasBanNotInForce` as itself).
- O4 (D3): `test_a_box_fault_from_the_first_curators_step_halts_the_drain` (+ its control),
  `test_a_box_fault_in_the_first_curator_halts_the_tick_before_the_second` (the spawn, a start
  refused or unproven, a stop refused or unproven; each also in the repair's run),
  `test_a_seam_fault_at_the_runs_stop_halts_the_lessons_drain` (the carried docker raising at
  the stop is a `BoxFault`, never contained as a curator's crash; with its control),
  `test_a_box_fault_in_the_second_curator_halts_the_drain`,
  `test_control_a_non_box_fault_in_the_first_curator_is_contained_and_the_second_runs` (N4; a
  `SystemExit` among them, its run's box still stopped),
  `test_a_run_start_fault_through_the_default_curator_step_halts_the_drain`
  (`trigger_author=None`; the batch box's docker calls are exactly `X.REFUSED_FIRST_RUN`),
  `test_a_box_fault_escapes_author_drain_with_nothing_delivered` (+ its control, where each
  curator is handed the handle).
- D3a: `test_a_box_fault_outranks_an_undo_fault_and_the_second_curator_never_runs`, with
  `test_control_an_undo_fault_still_replaces_a_non_box_fault`.
- O1/O3': `test_a_process_left_in_the_box_cannot_change_a_judged_lesson` (rewrite, symlink),
  `test_control_a_process_that_outlived_its_run_would_race_the_commit`,
  `test_what_the_box_writes_during_its_own_run_is_what_is_judged`; the same for a process the
  repair leaves, after judge 2: `test_a_process_the_repair_left_cannot_change_the_lesson_judged_after_it`
  (a repair's stop that does not take; `holds` control), with
  `test_control_a_process_the_repair_left_that_outlived_its_run_would_race_the_commit`.
- The settle lists the tree after the stop:
  `test_a_path_the_box_first_writes_as_its_run_stops_is_settled_and_judged` (a new stray is
  refused; the control, a new lesson, is judged and committed).
"""
from __future__ import annotations

import dataclasses
import errno
import logging
import os
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from pydantic_ai.exceptions import ModelRetry

from defender import _git, _io
from defender._git import GitError
from defender._io import NotPlainEntry
from defender.learning.core import config as author_config
from defender.learning.core import drains
from defender.learning.core.config import FatalConfigError, LoopPaths, StageAbort
from defender.runtime import box as box_mod
from defender.runtime import providers
from defender.runtime.box import BoxFault
from defender.runtime.verbs import RegistryError
from defender.tests import _box1195 as X
from defender.tests import _spec773 as S
from defender.tests._curator1134 import (
    JournalHeld,
    move_out_and_link,
    plant_link,
    put,
    questioner_cfg,
)
from defender.tests._spec791 import loop_paths
from defender.tests.e2e.test_922_spine import RepoBranch

CHANNELS = ["lessons", "questioner"]

#: The spawns: each must run inside a window of its own, and nothing else may.
SPAWN_KINDS = ("agent", "repair")

#: The repair's rewrite of `a.md`: new bytes, so the judge's memo re-judges it on pass 2.
REPAIRED = S.lesson("f1", body="the lesson, repaired")

#: The container the direct drives' box names (the drain's is `defender-drain-<batch id>`).
NAME = "defender-drain-l1195"


# ---------------------------------------------------------------------------------------
# The shared log, and the seams that write to it
# ---------------------------------------------------------------------------------------


def _kinds(log: list) -> list[str]:
    return [e[0] for e in log]


def _host(log: list, kind: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    """A host seam of the tick (`cfg.gate`, `cfg.post_rotate`, `cfg.source_key`), logging
    `(kind,)` each time it is called."""

    def call(*a: Any, **k: Any) -> Any:
        log.append((kind,))
        return fn(*a, **k)

    return call


def _placing(log: list, tree_for: Callable[..., Any],
             before: Callable[[], object] | None = None) -> Callable[..., Any]:
    """The lane's real `tree_for`, logging `("tree_for", path)` for each path asked of it: the
    settle's put-back of a non-`.md` stray, and the commit's placement of every path it stages.
    `before` runs first on each call (a process's turn, in the O1 rows)."""

    def placed(path: Any) -> Any:
        log.append(("tree_for", str(path)))
        if before is not None:
            before()
        return tree_for(path)

    return placed


class Report(dict):
    """A spawn's AUTHOR_RESULT as the drain receives it: every `get` is logged as
    `("report", key)`, so the agent-report check, the partition check, the commit message and
    the projection all show where they ran."""

    def __init__(self, log: list, data: dict) -> None:
        super().__init__(data)
        self._log = log

    def get(self, key: Any, default: Any = None) -> Any:
        self._log.append(("report", key))
        return super().get(key, default)


class Spawn:
    """A spawn seam (`cfg.invoke_agent`, `cfg.invoke_repair`): logs `(kind,)`, runs its inner
    fake (which records its own calls, the config it was handed among them), and hands back the
    inner fake's report as a `Report`."""

    def __init__(self, log: list, kind: str, inner: Callable[..., Any]) -> None:
        self.log, self.kind, self.inner = log, kind, inner

    def __call__(self, *a: Any, **k: Any) -> Any:
        self.log.append((self.kind,))
        return Report(self.log, self.inner(*a, **k))


def _queue_files(paths: LoopPaths) -> tuple[Path, ...]:
    return (paths.findings.file, paths.questioner_findings.file)


def _queued(paths: LoopPaths) -> tuple[bytes | None, ...]:
    return tuple(q.read_bytes() if q.exists() else None for q in _queue_files(paths))


def _after_each_spawn(log: list) -> list[list[tuple]]:
    """The log split at its spawns: before the first, between each pair, after the last."""
    cuts = [i for i, e in enumerate(log) if e[0] in SPAWN_KINDS]
    bounds = [-1, *cuts, len(log)]
    return [list(log[bounds[i] + 1:bounds[i + 1]]) for i in range(len(bounds) - 1)]


# ---------------------------------------------------------------------------------------
# Scenes
# ---------------------------------------------------------------------------------------


def _rows(channel: str, *ids: str) -> list[dict]:
    if channel == "lessons":
        return [S.finding_row(i, run_id=i) for i in ids]
    # A world row carries no `run_id` in production; one is given here so the injected forward
    # check reaches the verifier rather than refusing the pair before the call.
    return [S.world_row(i, run_id=i) for i in ids]


def _channel_scene(tmp_path: Path, channel: str, *, rows: list[dict], curator: S.FakeCurator,
                   seed_corpus: dict[str, str] | None = None) -> S.Scene:
    if channel == "lessons":
        return S.build_scene(tmp_path, rows=rows, curator=curator, seed_corpus=seed_corpus)
    return S.build_questioner_scene(tmp_path, rows=rows, curator=curator,
                                    seed_corpus=seed_corpus)


def _rel(sc: S.Scene, name: str) -> str:
    return (sc.corpus / name).relative_to(sc.repo).as_posix()


def _verifier(log: list, verdicts: dict | None = None) -> S.FakeVerifier:
    """The verifier, logging `("judge", file name)` for each pair it is asked."""
    return S.FakeVerifier(verdicts=dict(verdicts or {}),
                          on_call=lambda ctx: log.append(("judge", ctx.lesson_path.name)))


def _wire(  # noqa: PLR0913 — one config, every seam a row varies
        cfg: Any, log: list, *, curator: Callable[..., Any], verifier: S.FakeVerifier | None = None,
        repair: Callable[..., Any] | None = None, journal: bool = True,
        on_place: Callable[[], object] | None = None,
) -> Any:
    """`cfg` (a real builder's) with its spawns logging into `log` (`Spawn`), `verifier` as its
    forward check (none: every pair EXEMPT), and a key source that sources nothing. `journal`:
    the gate, the post-rotation hook, every placement (`tree_for`) and every corpus read, write
    and unlink (`JournalHeld`) log too. `on_place` runs at each placement."""
    fields: dict[str, Any] = {
        "invoke_agent": Spawn(log, "agent", curator),
        "invoke_repair": Spawn(log, "repair", repair if repair is not None else S.FakeRepair()),
        "forward_check": verifier.as_check() if verifier is not None else None,
        "exempt": lambda row: False,
        "source_key": _host(log, "key", lambda *_a, **_k: object()),
    }
    if journal:
        fields |= {
            "gate": _host(log, "gate", cfg.gate),
            "post_rotate": _host(log, "post_rotate", cfg.post_rotate),
            "tree_for": _placing(log, cfg.tree_for),
            "corpus": JournalHeld(cfg.corpus_dir, log),
        }
    if on_place is not None:
        fields["tree_for"] = _placing(log, cfg.tree_for, before=on_place)
    return dataclasses.replace(cfg, **fields)


@dataclasses.dataclass
class Tick:
    """One author-drain tick's worktree: the lessons scene's repo, with a questioner queue
    beside the findings one, and each curator's config (`cfgs`, by module name). `trigger` is
    the drain's `trigger_author` seam: it logs `("trigger", module)`, marks the daemon's log
    `trigger:<module>` when given one, and runs that curator the way
    `drains._maybe_trigger_author` does, handing it the box the drain handed down (the batch's
    handle). `start_box`: the `start_box=` an `author_drain` over the tick is given."""

    sc: S.Scene
    log: list
    cfgs: dict[str, Any]
    triggered: list[tuple[str, Any]] = dataclasses.field(default_factory=list)
    daemon: X.FakeDaemon | None = None
    start_box: Any = None

    @property
    def paths(self) -> LoopPaths:
        return self.sc.paths

    def trigger(self, _paths: LoopPaths, _pending_file: Path, _threshold_env: str,
                module_name: str, _pending_label: str, *, box: Any = None) -> None:
        self.log.append(("trigger", module_name))
        self.triggered.append((module_name, box))
        if self.daemon is not None:
            self.daemon.mark(f"trigger:{module_name}")
        cfg = self.cfgs[module_name]
        drains._run_curator_module(
            module_name, lambda mod: mod.run_batch(hold_committed=True, cfg=cfg, box=box))

    def modules(self) -> list[str]:
        return [m for m, _ in self.triggered]


def _tick(  # noqa: PLR0913 — one tick's two curators, every seam a row varies
        tmp_path: Path, log: list, *, curator: S.FakeCurator, q_curator: S.FakeCurator,
        verifier: S.FakeVerifier | None = None, repair: Callable[..., Any] | None = None,
        seed_corpus: dict[str, str] | None = None, q_rows: tuple[str, ...] = ("w1",),
        journal: bool = False, on_place: Callable[[], object] | None = None,
) -> Tick:
    """The lessons curator over `f1` (`curator`, `verifier`, `repair`) and the questioner curator
    over `q_rows` (`q_curator`, no forward check), in one worktree."""
    sc = S.build_scene(tmp_path, curator=curator, seed_corpus=seed_corpus)
    S.seed(sc.paths.questioner_findings, [S.world_row(i) for i in q_rows])
    lessons = _wire(sc.cfg, log, curator=curator, verifier=verifier, repair=repair,
                    journal=journal, on_place=on_place)
    questioner = _wire(questioner_cfg(sc.paths), log, curator=q_curator, journal=journal)
    return Tick(sc=sc, log=log, cfgs={"author": lessons, "questioner_curator": questioner})


def _questioner_rel(t: Tick, name: str) -> str:
    return (t.paths.lessons_questioner_dir / name).relative_to(t.sc.repo).as_posix()


def _stuck_classes(paths: LoopPaths, channel: str) -> list[str]:
    return [r.get("fault_class") for r in S.stuck_records(getattr(paths, channel))]


def _seeing_box(fn: Callable[..., Any], seen: list) -> Callable[..., Any]:
    """A host seam handed the tick's config last (`cfg.gate(keyed, cfg)`,
    `cfg.post_rotate(outcome, cfg)`), noting the `box` that config holds each time."""

    def call(*a: Any, **k: Any) -> Any:
        seen.append(a[-1].box)
        return fn(*a, **k)

    return call


# ---------------------------------------------------------------------------------------
# Wiring: each spawn in a window of its own; no host step beside a running box
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("repair", [False, True], ids=["judged-clean", "repaired"])
@pytest.mark.parametrize("channel", CHANNELS)
def test_each_spawn_runs_in_its_own_window_and_no_host_step_beside_a_running_box(
        tmp_path: Path, monkeypatch, channel: str, repair: bool):
    """Through the channel's `run_batch(cfg=..., box=<the batch's stopped box>)`: the curator
    leaves `a.md` (citing f1), `b.md` (citing f2) and a non-`.md` stray, and skips f3. With every
    verdict GOOD, one window (a `docker start` to the next `docker stop`) holds the curator spawn
    and nothing else. With `a.md` BAD then GOOD and `b.md` BAD throughout, a second window holds
    the repair spawn (which rewrites `a.md` and leaves a stray of its own) and nothing else.

    Each spawn saw the box running and was handed, as its config's `box`, the batch's executor,
    never the handle the tick was handed; the gate and the post-rotation hook, host steps, were
    handed the handle (O6). Every host step saw nothing running: the gate and the key source before the
    first spawn; the settle's put-back of each spawn's stray, the report reads, the corpus reads
    and the judge after each; the restore of the unapproved `b.md`, the commit's placements and
    the post-rotation hook after the last. The box is stopped at the end."""
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    log = X.Journal(daemon)
    curator = S.FakeCurator(
        writes={"a.md": S.lesson("f1"), "b.md": S.lesson("f2"), "stray.txt": "not a lesson\n"},
        committed=["f1", "f2"], consumed_skip=[{"finding_id": "f3", "reason": "dup"}],
    )
    sc = _channel_scene(tmp_path, channel, rows=_rows(channel, "f1", "f2", "f3"), curator=curator)
    fixer = S.FakeRepair(writes={"a.md": REPAIRED, "repair-stray.txt": "not a lesson\n"})
    verdicts = {"a.md": ["BAD", "GOOD"], "b.md": "BAD"} if repair else {}
    sc.cfg = _wire(sc.cfg, log, curator=curator, verifier=_verifier(log, verdicts), repair=fixer)
    seen: list[Any] = []
    sc.cfg = dataclasses.replace(sc.cfg, gate=_seeing_box(sc.cfg.gate, seen),
                                 post_rotate=_seeing_box(sc.cfg.post_rotate, seen))
    queued_before = _queued(sc.paths)

    assert sc.run(box=runs) == 0

    spawns = ["agent", "repair"] if repair else ["agent"]
    log.assert_runs_hold_exactly(spawns, SPAWN_KINDS)
    assert curator.calls[-1]["cfg"].box is box, "the curator was not handed the executor"
    if repair:
        assert fixer.calls[-1]["cfg"].box is box, "the repair was not handed the executor"
    assert len(seen) == 2, "the gate or the post-rotation hook never ran, so the row is vacuous"
    assert all(b is runs for b in seen), f"a host step was handed {seen}, not the handle"
    assert fixer.spawned == (1 if repair else 0)
    assert daemon.status(NAME) == "exited", "the box was left running"
    segments = _after_each_spawn(log)
    before, after_spawn, after_last = segments[0], segments[1], segments[-1]
    assert {"gate", "key"} <= set(_kinds(before)), _kinds(before)
    stray = ("tree_for", str(sc.corpus / "stray.txt"))
    assert stray in after_spawn, "the settle after the curator spawn was not seen"
    assert {"report", "read", "judge"} <= set(_kinds(after_spawn)), _kinds(after_spawn)
    assert ("tree_for", str(sc.corpus / "a.md")) in after_last, "the commit was not seen"
    assert "post_rotate" in _kinds(after_last)
    if repair:
        assert ("tree_for", str(sc.corpus / "repair-stray.txt")) in after_last
        assert "judge" in _kinds(after_last)
        assert ("unlink", "b.md") in after_last, "the restore of b.md was not seen"
        assert sc.head_text(_rel(sc, "a.md")) == REPAIRED
        assert sc.head_text(_rel(sc, "b.md")) is None
    else:
        assert sc.head_text(_rel(sc, "a.md")) == S.lesson("f1")
        assert sc.head_text(_rel(sc, "b.md")) == S.lesson("f2")
    assert sc.head_sha() != sc.base_sha
    assert _queued(sc.paths) != queued_before


def test_one_tick_runs_one_window_per_spawn_across_both_curators(tmp_path: Path, monkeypatch):
    """The design's key flow, through `_drain_curators(..., box=<the handle on the batch's
    stopped box>)` and both real curators: each curator is handed the handle (nothing running
    when either is triggered), and exactly three windows follow — the lessons curator, its
    repair, the questioner curator — each holding its spawn alone, each handed the batch's
    executor. Nothing runs between them or after the last. HEAD holds both curators'
    lessons."""
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    log = X.Journal(daemon)
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")})
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, log, curator=curator, q_curator=q_curator,
              verifier=_verifier(log, {"a.md": ["BAD", "GOOD"]}),
              repair=S.FakeRepair(writes={"a.md": REPAIRED}), journal=True)

    drains._drain_curators(t.paths, t.trigger, box=runs)

    assert t.modules() == ["author", "questioner_curator"]
    assert all(b is runs for _, b in t.triggered), "a curator was handed something but the handle"
    log.assert_runs_hold_exactly(["agent", "repair", "agent"], SPAWN_KINDS)
    assert q_curator.calls[-1]["cfg"].box is box
    assert daemon.status(NAME) == "exited"
    assert t.sc.head_text(_rel(t.sc, "a.md")) == REPAIRED
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


#: A committed file outside both corpora: the box's write there once started is a stray only if
#: the tick took its baseline of strays before the start.
STRAY_REL = "defender/notes/stray1195.md"
STRAY_EDIT = "rewritten by the box\n"


@pytest.mark.parametrize("when", ["once-started", "before-the-run"])
@pytest.mark.parametrize("channel", CHANNELS)
def test_the_pre_state_is_captured_before_the_run_starts(tmp_path: Path, monkeypatch,
                                                         channel: str, when: str):
    """The box rewrites a committed file outside the corpus as soon as its run starts: the
    settle refuses the tick (an `AuthorError` naming it, which retires: rc 2, f1 bumped, a stuck
    record naming the stray), HEAD unchanged, the stray put back. The baseline of strays was
    captured before the start, so the rewrite is new. Control: the same rewrite already standing
    before the run is in the baseline, and the tick commits."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")})
    sc = _channel_scene(tmp_path, channel, rows=_rows(channel, "f1"), curator=curator)
    stray = sc.repo / STRAY_REL
    put(stray, "committed\n")
    S.git(sc.repo, "add", "--", STRAY_REL)
    S.git(sc.repo, "commit", "-q", "-m", "a file outside both corpora")
    sc.base_sha = sc.head_sha()
    if when == "before-the-run":
        put(stray, STRAY_EDIT)
    else:
        daemon.on_start(stray, STRAY_EDIT, at=1)
    sc.cfg = _wire(sc.cfg, [], curator=curator, journal=False)

    rc = sc.run(box=runs)

    assert curator.calls, "the curator never ran, so the baseline was never compared"
    if when == "before-the-run":
        assert rc == 0
        assert sc.head_text(_rel(sc, "a.md")) == S.lesson("f1")
        assert sc.head_text(STRAY_REL) == "committed\n"
        return
    assert rc == 2
    assert sc.head_files() == []
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert any(STRAY_REL in str(r.get("reason")) for r in S.stuck_records(sc.channel))
    assert stray.read_text() == "committed\n"


def test_a_failing_spawns_box_is_stopped_before_the_undo_runs(tmp_path: Path, monkeypatch):
    """The lessons spawn leaves `a.md` and raises `RuntimeError`: its run still stops the box on
    that way out (its window holds the spawn alone), and the undo's removal of `a.md` through
    the corpus mount runs after, with nothing running. The contained fault lets the questioner
    curator run, in a window of its own."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    log = X.Journal(daemon)

    def boom(*_a: Any) -> None:
        raise RuntimeError("the agent crashed")

    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=boom)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, log, curator=curator, q_curator=q_curator, journal=True)

    drains._drain_curators(t.paths, t.trigger, box=runs)

    log.assert_runs_hold_exactly(["agent", "agent"], SPAWN_KINDS)
    undo = [i for i, e in enumerate(log) if e == ("unlink", "a.md")]
    spawns = [i for i, e in enumerate(log) if e[0] == "agent"]
    assert undo, "the undo never removed the failed spawn's lesson through the corpus mount"
    assert all(spawns[0] < i < spawns[1] for i in undo), "the undo was not between the runs"
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


# ---------------------------------------------------------------------------------------
# The production drain: the real start, stop and removal over the fake daemon
# ---------------------------------------------------------------------------------------


def _production_tick(tmp_path: Path, monkeypatch, daemon: X.FakeDaemon, *,  # noqa: PLR0913 — one tick, every fake a row varies
                     curator: S.FakeCurator, q_curator: S.FakeCurator,
                     verifier: S.FakeVerifier | None = None,
                     repair: S.FakeRepair | None = None, log: list | None = None,
                     path_default: bool = False) -> Tick:
    """A tick `author_drain` serves as production wires it: both thresholds at 1, the image
    inputs committed under the repo's `defender/`, and the trigger marking the daemon's log as
    each curator is triggered. The real `start_box` creates the box over the daemon, given as
    its `docker=` (`t.start_box`), with a `Tripwire` the `docker` on `PATH`; with
    `path_default`, production's own default docker reaches the daemon installed on `PATH`.
    Either way the drain's post-create stop, each spawn's run and the batch-end removal reach
    the daemon through the executor."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    X.clear_opt_out(monkeypatch)
    t = _tick(tmp_path, log if log is not None else [], curator=curator, q_curator=q_curator,
              verifier=verifier, repair=repair)
    X.plant_image_inputs(t.sc.repo)
    S.git(t.sc.repo, "add", "-A", "--", "defender")
    S.git(t.sc.repo, "commit", "-q", "-m", "the box image inputs")
    t.sc.base_sha = t.sc.head_sha()
    if path_default:
        daemon.install(monkeypatch)
    else:
        daemon.tripwire = X.Tripwire(tmp_path).install(monkeypatch)
        t.start_box = partial(box_mod.start_box, docker=daemon)
    t.daemon = daemon
    return t


def _author_drain(t: Tick, events: list[str], **seams: Any) -> int:
    branch = RepoBranch(t.sc.repo, events=events)
    seams.setdefault("scrub", lambda tree, *_a, **_k: events.append(f"scrub:{tree}"))
    if t.start_box is not None:
        seams.setdefault("start_box", t.start_box)
    return drains.author_drain(t.paths, trigger_author=t.trigger, branch=branch, **seams)


@pytest.mark.parametrize("docker", ["carried", "path-default"])
def test_the_production_drain_runs_one_box_stopped_between_its_agent_runs(
        tmp_path: Path, monkeypatch, docker: str):
    """`author_drain` with the real `start_box` and its own `stop_box`: the daemon creates one
    container, at batch start, under the batch's name, and it is stopped before the first
    curator is triggered. For each spawn (the lessons curator, its repair, the questioner
    curator) one window starts it, holds the spawn alone, and stops it. After the last window
    the batch-end `docker rm -f` removes it, then the tree is scanned. Both curators committed
    and the batch was delivered; each curator was handed the handle, each spawn the drain's own
    executor.

    `carried`: only `start_box=` brings the docker (the real start over the in-process daemon),
    and every call reaches the daemon through the executor, none the `docker` on `PATH` (F2).
    `path-default`: production's own default docker, the daemon installed on `PATH`."""
    daemon = X.FakeDaemon(tmp_path)
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")},
                            also=lambda *_a: daemon.mark("curator"))
    repair = S.FakeRepair(writes={"a.md": REPAIRED}, also=lambda *_a: daemon.mark("repair"))
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")},
                              also=lambda *_a: daemon.mark("questioner"))
    t = _production_tick(tmp_path, monkeypatch, daemon, curator=curator, q_curator=q_curator,
                         verifier=S.FakeVerifier(verdicts={"a.md": ["BAD", "GOOD"]}),
                         repair=repair, path_default=docker == "path-default")
    events: list[str] = []
    watch = X.ScanWatch(daemon, events)

    assert _author_drain(t, events, scrub=watch) == 0

    batch_id = next(e.split(":", 1)[1] for e in events if e.startswith("start_batch:"))
    name = f"defender-drain-{batch_id}"
    assert daemon.created() == [name], "the batch did not create exactly its one box"
    kept = [s for s in daemon.steps() if s in ("create", "start", "stop", "rm", "scan") or ":" in s
            or s in ("curator", "repair", "questioner")]
    assert kept == ["create", "stop", "trigger:author", "start", "curator", "stop", "start",
                    "repair", "stop", "trigger:questioner_curator", "start", "questioner",
                    "stop", "rm", "scan"], kept
    assert daemon.windows() == [["curator"], ["repair"], ["questioner"]], daemon.steps()
    watch.assert_scanned_once_the_box_was_gone()
    handed = curator.calls[-1]["cfg"].box
    assert handed.sandboxed, handed
    assert handed.name == name, handed
    assert repair.calls[-1]["cfg"].box is handed
    assert q_curator.calls[-1]["cfg"].box is handed
    assert all(isinstance(b, X.box_runs_type()) for _, b in t.triggered), t.triggered
    assert any(e.startswith("finish_batch:") for e in events), events
    assert t.sc.head_text(_rel(t.sc, "a.md")) == REPAIRED
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")
    if docker == "carried":
        assert handed.docker is daemon, "the executor does not carry the docker it was created with"
        X.no_path_docker(daemon)


# ---------------------------------------------------------------------------------------
# F1 (O5): a run's stop fault halts the drain, outranking the spawn's own failure
# ---------------------------------------------------------------------------------------

#: What the lessons spawn raises after leaving its lesson: a crash, contained to its channel,
#: and the two retiring faults, which `_handle_retire` bumps f1 for.
F1_FAILURES = [
    pytest.param(lambda: RuntimeError("the agent crashed"), id="RuntimeError"),
    pytest.param(lambda: S.author_error("the agent's report was refused"), id="AuthorError"),
    pytest.param(lambda: ModelRetry("the model gave up retrying"), id="ModelRetry"),
]


def _assert_handled_as_before(t: Tick, raised: BaseException, got: BaseException | None,
                              events: list[str], *, follows: bool) -> None:
    """The F1 control: the run's stop held, so the spawn's failure is handled as without a box
    (a crash contained and recorded stuck; a retiring fault bumping f1), the questioner curator
    is served when it has a row, and the batch is delivered."""
    assert got is None, got
    retiring = not isinstance(raised, RuntimeError)
    assert t.sc.pending_by_id()["f1"].get("attempts") == (1 if retiring else None)
    assert _stuck_classes(t.paths, "findings") == [type(raised).__name__]
    assert t.modules() == ["author", "questioner_curator"]
    if follows:
        assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")
    assert any(e.startswith("finish_batch:") for e in events), events


@pytest.mark.parametrize("follows", [True, False], ids=["questioner-follows", "nothing-follows"])
@pytest.mark.parametrize("stop", [*X.STOP_FAULTS, "holds"])
@pytest.mark.parametrize("failure", F1_FAILURES)
def test_a_stop_fault_under_a_failing_spawn_halts_author_drain_with_the_failure_as_context(
        tmp_path: Path, monkeypatch, failure: Any, stop: str, follows: bool):
    """`author_drain` over the tick (only `start_box=` bringing the docker): the lessons spawn
    leaves `a.md` and raises X (a crash, `AuthorError`, `ModelRetry`), and its run's stop fails
    (refused, without effect, unproven, the seam raising). A `BoxFault` escapes `author_drain`
    at once, never X, with X as its `__context__` (behind the seam's own exception when the
    seam raised): the stop fault wins. So X is never handled as X: f1 is not bumped by
    `_handle_retire`, the findings channel's stuck record names `BoxFault`, the lesson is undone
    and nothing commits; the questioner curator is never triggered, whether it has a row to run
    (`questioner-follows`, whose run would refuse beside the box) or none (`nothing-follows`,
    where no later run would catch a box left running); nothing is delivered; the box is
    removed, then the tree scanned. Control (`holds`): X is handled as before."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    daemon = X.FakeDaemon(tmp_path)
    daemon.tripwire = X.Tripwire(tmp_path).install(monkeypatch)
    if stop != "holds":
        # 1: the post-create stop; 2: the lessons run's. The status asks: 1 proves the
        # post-create stop; the run asks 2 before its start, 3 after it, 4 after its stop.
        X.fail_stop(daemon, stop, at=2, inspect_at=4)
    raised = failure()

    def crash(*_a: Any) -> None:
        raise raised

    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=crash)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, [], curator=curator, q_curator=q_curator,
              q_rows=("w1",) if follows else ())
    run, events, watch = _lane(t, daemon)

    got = X.caught(run)

    assert len(curator.calls) == 1, "the spawn never ran, so the row is vacuous"
    assert not (t.sc.corpus / "a.md").exists(), "the spawn's lesson was not undone"
    watch.assert_scanned_once_the_box_was_gone()
    X.no_path_docker(daemon)
    if stop == "holds":
        _assert_handled_as_before(t, raised, got, events, follows=follows)
        return
    assert isinstance(got, BoxFault), f"the spawn's failure outranked its stop fault: {got!r}"
    assert got is not raised
    if stop.startswith("seam-"):
        assert daemon.seam_raised == ["stop"], daemon.seam_raised
        assert raised in X.chain(got), f"the spawn's failure was lost: {X.chain(got)}"
    else:
        assert got.__context__ is raised, f"the spawn's failure is not the context: {X.chain(got)}"
    assert X.POINTER not in str(got), f"a mid-batch box fault got a build pointer: {got}"
    assert t.sc.pending_by_id()["f1"].get("attempts") is None, "f1 was bumped for a box fault"
    assert _stuck_classes(t.paths, "findings") == ["BoxFault"]
    assert t.modules() == ["author"], "the drain went on past a box that would not stop"
    assert q_curator.calls == []
    assert _stuck_classes(t.paths, "questioner_findings") == []
    assert daemon.steps().count("start") == 1, daemon.steps()
    assert t.sc.head_files() == [], "a commit landed beside a box that would not stop"
    assert not any(e.startswith("finish_batch:") for e in events), events


# ---------------------------------------------------------------------------------------
# E3': a stop fault some layer swallows is caught at the next run's start
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("stop", ["refused", "holds"])
def test_a_swallowed_stop_fault_makes_the_next_curators_run_refuse(tmp_path: Path, monkeypatch,
                                                                   stop: str):
    """`author_drain` over the tick, with a trigger that swallows the lessons curator's
    `BoxFault`, as a layer above a spawn may (N11''). With `refused`, the lessons run's stop is
    refused with nothing in flight: its `BoxFault` is swallowed and the box keeps running. The
    questioner curator's run then finds the box not `exited` and refuses before its spawn,
    naming the status, with a best-effort stop: that `BoxFault` halts `author_drain`. The
    questioner never runs, its channel records `BoxFault`, nothing is committed or delivered;
    the box is removed, then the tree scanned. Control (`holds`): both curators commit and the
    batch is delivered."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    daemon = X.FakeDaemon(tmp_path)
    daemon.tripwire = X.Tripwire(tmp_path).install(monkeypatch)
    if stop == "refused":
        daemon.refuse_stop(at=[2])  # 1: the post-create stop; 2: the lessons run's
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")})
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, [], curator=curator, q_curator=q_curator)
    masked: list[BoxFault] = []

    def swallowing(paths: LoopPaths, file: Path, env: str, module_name: str, label: str, *,
                   box: Any = None) -> None:
        try:
            t.trigger(paths, file, env, module_name, label, box=box)
        except BoxFault as e:
            if module_name != "author":
                raise
            masked.append(e)

    run, events, watch = _lane(t, daemon, trigger=swallowing)

    got = X.caught(run)

    watch.assert_scanned_once_the_box_was_gone()
    X.no_path_docker(daemon)
    if stop == "holds":
        assert got is None, got
        assert masked == []
        assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")
        assert any(e.startswith("finish_batch:") for e in events), events
        return
    assert len(masked) == 1, "the lessons run's stop did not fail, so the row is vacuous"
    assert isinstance(got, BoxFault), f"the batch did not halt on a box left running: {got!r}"
    assert got is not masked[0]
    assert "running" in str(got), got
    assert q_curator.calls == [], "the questioner ran beside the box the first run left running"
    assert _stuck_classes(t.paths, "questioner_findings") == ["BoxFault"]
    assert t.sc.head_files() == [], "a commit landed beside a running box"
    assert not any(e.startswith("finish_batch:") for e in events), events
    steps = daemon.steps()
    tail = steps[steps.index("trigger:questioner_curator"):]
    assert "start" not in tail, f"the questioner's run started a running box: {tail}"
    assert "stop" in tail[:tail.index("rm")], f"no best-effort stop on the refusal: {tail}"


# ---------------------------------------------------------------------------------------
# O4 at batch start: a fault creating or checking the box charges no curator row
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize(("knob", "kind", "pointed"), X.BATCH_START_FAULTS)
def test_a_batch_start_fault_charges_no_curator_row_and_writes_no_stuck_record(
        tmp_path: Path, monkeypatch, knob: str, kind: type, pointed: bool):
    """`author_drain` as production wires it; the batch's box cannot be created, or a check at
    its creation fails: the fault escapes before any curator (as on main: a `BoxFault` naming
    `origin/main @ <cut commit>`, a link ban as `AliasBanNotInForce`). No curator is triggered,
    neither channel gets a stuck record, neither queue moves, f1 is not bumped, and nothing is
    committed or delivered."""
    daemon = X.FakeDaemon(tmp_path)
    t = _production_tick(tmp_path, monkeypatch, daemon,
                         curator=S.FakeCurator(writes={"a.md": S.lesson("f1")}),
                         q_curator=S.FakeCurator(writes={"q.md": S.lesson("w1")}))
    getattr(daemon, knob)()
    queued = _queued(t.paths)
    events: list[str] = []

    got = X.caught(lambda: _author_drain(t, events))

    assert isinstance(got, kind), got
    assert (f"{X.POINTER}{t.sc.base_sha}" in str(got)) is pointed, got
    assert t.modules() == [], "a curator was triggered though the box never came up"
    assert _stuck_classes(t.paths, "findings") == []
    assert _stuck_classes(t.paths, "questioner_findings") == []
    assert _queued(t.paths) == queued, "a queue moved for a box that never came up"
    assert t.sc.pending_by_id()["f1"].get("attempts") is None
    assert t.sc.head_sha() == t.sc.base_sha
    assert not any(e.startswith("finish_batch:") for e in events), events
    X.no_path_docker(daemon)


# ---------------------------------------------------------------------------------------
# O4 through the lane's DEFAULT work step (`trigger_author=None`)
# ---------------------------------------------------------------------------------------


def _ambient_verifier_key(monkeypatch: Any) -> None:
    """The findings channel's own forward check sources the verifier key before its first spawn
    (`_verifier_key_preflight`); an ambient key answers it, so the default step goes on to its
    run's start. Sourcing is all it does: no model is called before the box is up."""
    var = providers.provider_for(author_config.verifier_model()).api_key_var
    monkeypatch.setenv(var, "sk-test-1195")


def _default_scene(tmp_path: Path, monkeypatch: Any, *, findings: bool
                   ) -> tuple[S.Scene, X.FakeDaemon]:
    """The lessons drain's DEFAULT world: both thresholds at 1, f1 queued on the findings
    channel (`findings`) and w1 on the questioner channel, the image inputs committed, the
    opt-out unset, the verifier key ambient, and the fake daemon, which `_default_drain` gives
    the real `start_box` as its `docker=`; a `Tripwire` is the `docker` on `PATH`."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    X.clear_opt_out(monkeypatch)
    _ambient_verifier_key(monkeypatch)
    sc = S.build_scene(tmp_path, rows=[S.finding_row("f1", run_id="f1")] if findings else [])
    S.seed(sc.paths.questioner_findings, [S.world_row("w1")])
    X.plant_image_inputs(sc.repo)
    S.git(sc.repo, "add", "-A", "--", "defender")
    S.git(sc.repo, "commit", "-q", "-m", "the box image inputs")
    sc.base_sha = sc.head_sha()
    daemon = X.FakeDaemon(tmp_path)
    daemon.tripwire = X.Tripwire(tmp_path).install(monkeypatch)
    return sc, daemon


def _default_drain(sc: S.Scene, daemon: X.FakeDaemon, events: list[str],
                   watch: X.ScanWatch) -> BaseException | None:
    """`author_drain` with every default but the docker the real `start_box` creates the box
    with: what it raised, or `None`."""
    return X.caught(lambda: drains.author_drain(
        sc.paths, branch=RepoBranch(sc.repo, events=events), scrub=watch,
        start_box=partial(box_mod.start_box, docker=daemon)))


def _batch_calls(daemon: X.FakeDaemon) -> list[str]:
    [name] = daemon.created()
    return daemon.calls_from_the_first_stop(name)


@pytest.mark.parametrize("queued", ["both", "questioner-only"])
def test_a_run_start_fault_through_the_default_curator_step_halts_the_drain(
        tmp_path: Path, monkeypatch, queued: str):
    """`author_drain` with every default (`_maybe_trigger_author` driving each channel's real
    `run_batch` over its real config, the real `start_box`/`stop_box`) over the fake daemon (the
    docker the real `start_box` is given, and so the docker its executor carries),
    whose first `docker start` is refused: with both queues at threshold, the findings curator's
    run cannot start, and the `BoxFault` escapes `author_drain`. Only one start was ever asked
    for: the questioner curator is not served, its queue is as it was, and nothing is recorded
    against its rows; f1 is not bumped; nothing is committed or delivered; the box is removed.

    Control (`questioner-only`): the findings queue empty, so the questioner curator is served
    first: its default step reaches its run's start too (one start), and halts the same way. So
    one start in the row above means the questioner never got that far.

    Either way the batch box's docker calls are exactly `X.REFUSED_FIRST_RUN`: no default step
    asks the daemon anything outside its run."""
    sc, daemon = _default_scene(tmp_path, monkeypatch, findings=queued == "both")
    daemon.refuse_start(at=[1])
    q_before = sc.paths.questioner_findings.file.read_bytes()
    events: list[str] = []
    watch = X.ScanWatch(daemon, events)

    got = _default_drain(sc, daemon, events, watch)

    assert isinstance(got, BoxFault), got
    X.no_path_docker(daemon)
    assert daemon.steps().count("start") == 1, f"a start was asked after a box fault: {daemon.steps()}"
    assert _batch_calls(daemon) == X.REFUSED_FIRST_RUN, "a default step called docker outside its run"
    assert not any(e.startswith("finish_batch:") for e in events), events
    assert sc.head_sha() == sc.base_sha, "a commit landed after a box fault"
    watch.assert_scanned_once_the_box_was_gone()
    if queued == "questioner-only":
        assert _stuck_classes(sc.paths, "questioner_findings") == ["BoxFault"]
        return
    assert _stuck_classes(sc.paths, "findings") == ["BoxFault"], (
        "the box fault was not the findings curator's own")
    assert sc.paths.questioner_findings.file.read_bytes() == q_before, (
        "the questioner's queue moved after the findings curator's box fault")
    assert _stuck_classes(sc.paths, "questioner_findings") == [], (
        "the questioner curator was served after the findings curator's box fault")
    assert sc.pending_by_id()["f1"].get("attempts") is None, "f1 was bumped for a box fault"


@pytest.mark.parametrize("stop", ["refused", "holds"])
def test_a_stop_fault_under_a_failing_default_spawn_halts_the_drain(tmp_path: Path, monkeypatch,
                                                                     stop: str):
    """F1 through `_maybe_trigger_author`: `author_drain` with every default but the docker,
    both queues at threshold, and an unroutable curator model, so each real spawn raises
    `FatalConfigError` at its key lookup, inside its run's window (a non-box fault, contained to
    its channel). With `refused`, the findings curator's run's stop is refused under that fault:
    a `BoxFault` escapes `author_drain` at once, with the `FatalConfigError` as its context. The
    findings channel records `BoxFault`; the questioner curator is never served (one `docker
    start`, its queue as it was, nothing recorded against it); nothing is delivered. The batch
    box's docker calls end at the failed stop's proof and the batch-end removal: nothing asks
    the daemon after the failed stop.

    Control (`holds`): the stop takes; the findings channel records the `FatalConfigError`, the
    questioner's run starts (two starts) and its spawn fails the same contained way, so
    `author_drain` returns."""
    sc, daemon = _default_scene(tmp_path, monkeypatch, findings=True)
    monkeypatch.setenv("LEARNING_AUTHOR_MODEL", "no-such-model-1195")
    if stop == "refused":
        daemon.refuse_stop(at=[2])  # 1: the post-create stop; 2: the findings curator's run
    q_before = sc.paths.questioner_findings.file.read_bytes()
    events: list[str] = []
    watch = X.ScanWatch(daemon, events)

    got = _default_drain(sc, daemon, events, watch)

    assert sc.head_sha() == sc.base_sha
    watch.assert_scanned_once_the_box_was_gone()
    X.no_path_docker(daemon)
    calls = _batch_calls(daemon)
    first_run = ["stop", "status", "status", "start", "status", "stop", "status"]
    if stop == "holds":
        assert got is None, got
        assert _stuck_classes(sc.paths, "findings") == ["FatalConfigError"], (
            "the findings curator's spawn never ran in its window")
        assert calls == [*first_run, "status", "start", "status", "stop", "status", "rm"], calls
        return
    assert isinstance(got, BoxFault), f"the spawn's fault outranked its stop fault: {got!r}"
    assert isinstance(got.__context__, FatalConfigError), X.chain(got)
    assert _stuck_classes(sc.paths, "findings") == ["BoxFault"]
    assert calls == [*first_run, "rm"], f"the daemon was asked after the failed stop: {calls}"
    assert sc.paths.questioner_findings.file.read_bytes() == q_before
    assert _stuck_classes(sc.paths, "questioner_findings") == []
    assert not any(e.startswith("finish_batch:") for e in events), events


# ---------------------------------------------------------------------------------------
# O4 (D3): a box fault in either curator halts the tick
# ---------------------------------------------------------------------------------------


def _raising_trigger(calls: list[str], fault: BaseException) -> Callable[..., None]:
    def trigger(_paths: LoopPaths, _file: Path, _env: str, module_name: str, _label: str, *,
                box: Any = None) -> None:
        calls.append(module_name)
        if module_name == "author":
            raise fault

    return trigger


@pytest.mark.parametrize("fault", ["BoxFault", "RuntimeError"])
def test_a_box_fault_from_the_first_curators_step_halts_the_drain(tmp_path: Path, fault: str):
    """The first curator's step raises `BoxFault`: it propagates out of `_drain_curators` (the
    same object) and the second curator is never triggered. Control: a `RuntimeError` there is
    contained, recorded on the findings channel's stuck report, and the second curator runs."""
    paths = loop_paths(tmp_path)
    exc: BaseException = BoxFault("the box did not start") if fault == "BoxFault" else RuntimeError("x")
    calls: list[str] = []
    trigger = _raising_trigger(calls, exc)
    if fault == "RuntimeError":
        drains._drain_curators(paths, trigger, box=None)
        assert calls == ["author", "questioner_curator"]
        assert _stuck_classes(paths, "findings") == ["RuntimeError"]
        return
    with pytest.raises(BoxFault) as got:
        drains._drain_curators(paths, trigger, box=None)
    assert got.value is exc
    assert calls == ["author"], "the second curator ran after a box fault"


#: Where a `BoxFault` comes from, in the curator that faults:
#: - `spawn`: the spawn itself raises it, after leaving its lesson;
#: - `start`: its run's `docker start` is refused, before the spawn;
#: - `start-unproven`: the start answers 0 and the box stays stopped;
#: - `stop`: its run's stop is refused after the spawn returned;
#: - `stop-unproven`: the stop answers 0 and the box keeps running;
#: - `repair-…`: the same in the repair's run (the lessons verdict BAD on pass 1, so the repair
#:   runs; its run is the second). Its start and stop are proven by the status too: a verb that
#:   answers 0 and does not take is a fault there as in the curator's own run.
FIRST_CURATOR_SOURCES = ["spawn", "start", "start-unproven", "stop", "stop-unproven",
                         "repair-spawn", "repair-start", "repair-start-unproven", "repair-stop",
                         "repair-stop-unproven"]
SECOND_CURATOR_SOURCES = ["spawn", "start", "start-unproven", "stop", "stop-unproven"]


@dataclasses.dataclass
class Faulted:
    """A tick one of whose curators meets a box fault, its fakes, the daemon, the handle on its
    box, and the exception injected (`None` for a fault the daemon makes)."""

    t: Tick
    curator: S.FakeCurator
    q_curator: S.FakeCurator
    verifier: S.FakeVerifier
    repair: S.FakeRepair
    daemon: X.FakeDaemon
    runs: Any
    fault: BaseException | None


def _set_daemon_fault(daemon: X.FakeDaemon, kind: str, nth: int) -> None:
    """The `nth` start or stop (from 1) faults as `kind` says."""
    if kind == "start":
        daemon.refuse_start(at=[nth])
    elif kind == "start-unproven":
        daemon.start_takes_no_effect(at=[nth])
    elif kind == "stop":
        daemon.refuse_stop(at=[nth])
    elif kind == "stop-unproven":
        daemon.stop_takes_no_effect(at=[nth])


def _box_fault_scene(  # noqa: PLR0913 — one tick, every fault a row varies
        tmp_path: Path, monkeypatch: Any, source: str, *, in_curator: str = "author",
        seed_corpus: dict[str, str] | None = None, plant: Callable[..., None] | None = None,
        log: list | None = None, stops_before: int = 0,
) -> Faulted:
    """A tick whose lessons curator leaves `a.md` (citing f1) and whose questioner curator leaves
    `q.md` (citing w1), each committing it unless something faults. The curator `in_curator`
    meets a box fault from `source` (`FIRST_CURATOR_SOURCES`), after running `plant` (the box's
    own act) in its spawn. `stops_before`: the stops the daemon answers before the first run's
    (the drain's post-create stop, through `author_drain`, which starts a box of its own: then
    the daemon holds nothing to begin with, and `runs` is `None`). A `Tripwire` is the `docker`
    on `PATH` either way."""
    if stops_before:
        daemon, runs = X.FakeDaemon(tmp_path), None
        daemon.tripwire = X.Tripwire(tmp_path).install(monkeypatch)
    else:
        daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    log = log if log is not None else []
    fault: BaseException | None = BoxFault(f"the box failed ({source})") if source.endswith("spawn") else None

    def act(rows: Any, batch_id: str, cfg: Any) -> None:
        if plant is not None:
            plant(rows, batch_id, cfg)
        if source == "spawn":
            assert fault is not None
            raise fault

    first = in_curator == "author"
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=act if first else None)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")}, also=None if first else act)
    repairing = source.startswith("repair-")
    verifier = S.FakeVerifier(verdicts={"a.md": ["BAD", "GOOD"]} if repairing else {})
    repair = S.FakeRepair(writes={"a.md": REPAIRED}, raise_after_writes=True,
                          raises=fault if source == "repair-spawn" else None)
    t = _tick(tmp_path, log, curator=curator, q_curator=q_curator, verifier=verifier,
              repair=repair, seed_corpus=seed_corpus)
    # The faulting run's ordinal: the lessons curator's is 1, its repair's 2; the questioner's
    # follows the lessons curator's single run.
    nth = 2 if (repairing or not first) else 1
    kind = source.removeprefix("repair-")
    _set_daemon_fault(daemon, kind, nth + (stops_before if kind.startswith("stop") else 0))
    return Faulted(t=t, curator=curator, q_curator=q_curator, verifier=verifier, repair=repair,
                   daemon=daemon, runs=runs, fault=fault)


def _assert_is_the_box_fault(got: BaseException | None, f: Faulted) -> None:
    """The drain's `BoxFault` is the injected one, or one the daemon's fault made."""
    assert isinstance(got, BoxFault), got
    if f.fault is not None:
        assert got is f.fault, (got, X.chain(got))
    assert X.POINTER not in str(got), f"a mid-batch box fault got a build pointer: {got}"


def _assert_halted_after_the_first_curator(t: Tick, q_curator: S.FakeCurator,
                                           q_queued: bytes | None) -> None:
    assert t.modules() == ["author"], "the second curator was triggered after a box fault"
    assert q_curator.calls == [], "the second curator's spawn ran after a box fault"
    assert t.sc.head_files() == [], "a commit landed after a box fault"
    assert t.sc.pending_by_id()["f1"].get("attempts") is None, "a box fault bumped the row"
    assert _queued(t.paths)[1] == q_queued, "the second curator's queue was touched"
    assert _stuck_classes(t.paths, "findings") == ["BoxFault"]
    assert _stuck_classes(t.paths, "questioner_findings") == []


def _assert_halted_in_the_second_curator(t: Tick) -> None:
    """The first curator committed (the control inside the row); the second's box fault left no
    commit, no bumped row and its own stuck record, and its lesson undone."""
    assert t.modules() == ["author", "questioner_curator"]
    assert t.sc.head_text(_rel(t.sc, "a.md")) == S.lesson("f1"), "the first curator never committed"
    assert t.sc.head_text(_questioner_rel(t, "q.md")) is None, "a commit landed after a box fault"
    assert not (t.paths.lessons_questioner_dir / "q.md").exists(), "the lesson was not undone"
    assert S.pending_by_id(t.paths.questioner_findings)["w1"].get("attempts") is None
    assert _stuck_classes(t.paths, "questioner_findings") == ["BoxFault"]
    assert _stuck_classes(t.paths, "findings") == []


@pytest.mark.parametrize("source", FIRST_CURATOR_SOURCES)
def test_a_box_fault_in_the_first_curator_halts_the_tick_before_the_second(
        tmp_path: Path, monkeypatch, source: str):
    """Through `_drain_curators` and both real curators: a box fault in the lessons curator —
    from its spawn, its run's start (refused, or not taking) or its run's stop (refused, or not
    taking), or the same in the repair's run — escapes the drain as a `BoxFault`. The questioner
    curator is never triggered, nothing is committed, f1 is not bumped and its stuck record names
    `BoxFault`; the curator's lesson is undone. A start fault runs no spawn; after a fault in the
    repair's run, nothing is judged again; every start was followed by a stop."""
    f = _box_fault_scene(tmp_path, monkeypatch, source)
    t = f.t
    q_queued = _queued(t.paths)[1]

    got = X.caught(lambda: drains._drain_curators(t.paths, t.trigger, box=f.runs))

    _assert_is_the_box_fault(got, f)
    _assert_halted_after_the_first_curator(t, f.q_curator, q_queued)
    kind = source.removeprefix("repair-")
    assert len(f.curator.calls) == (0 if source.startswith("start") else 1)
    assert not (t.sc.corpus / "a.md").exists(), "the curator's lesson was not undone"
    if source.startswith("repair-"):
        assert len(f.repair.calls) == (0 if kind.startswith("start") else 1)
        assert f.verifier.texts_for("a.md") == [S.lesson("f1")], (
            "the tree was judged again after the repair's box fault")
    else:
        assert f.repair.calls == []
    steps = f.daemon.steps()
    assert steps.count("stop") >= steps.count("start"), f"a start was never stopped: {steps}"


@pytest.mark.parametrize("source", SECOND_CURATOR_SOURCES)
def test_a_box_fault_in_the_second_curator_halts_the_drain(tmp_path: Path, monkeypatch,
                                                           source: str):
    """The same faults in the questioner curator, which runs second: its `BoxFault` escapes
    `_drain_curators` too, so `finish_batch` is never reached. The lessons curator's commit
    stands; the questioner's lesson is undone, w1 is not bumped and its stuck record names
    `BoxFault`."""
    f = _box_fault_scene(tmp_path, monkeypatch, source, in_curator="questioner_curator")

    got = X.caught(lambda: drains._drain_curators(f.t.paths, f.t.trigger, box=f.runs))

    _assert_is_the_box_fault(got, f)
    _assert_halted_in_the_second_curator(f.t)
    assert len(f.q_curator.calls) == (0 if source.startswith("start") else 1)


#: Faults that are not box faults, raised by the lessons spawn after it leaves its lesson. All but
#: `GitError` are non-retiring, contained by `_drain_one_curator` (N4: `StageAbort`,
#: `FatalConfigError`, `RegistryError` keep their behaviour); `GitError` retires inside its own
#: tick (f1 bumped). Either way the second curator runs. `SystemExit` (a spawn calling
#: `sys.exit`) is neither an `Exception` nor an interrupt, and `_drain_one_curator` contains it
#: too (as on main): its run's box must still be stopped before the second curator's run starts.
CONTAINED_FAULTS = [RuntimeError, StageAbort, FatalConfigError, RegistryError, GitError,
                    SystemExit]


def _not_a_box_fault(cls: type[BaseException], message: str) -> BaseException:
    return S.git_error(message) if cls is GitError else cls(message)


@pytest.mark.parametrize("fault", CONTAINED_FAULTS, ids=lambda c: c.__name__)
def test_control_a_non_box_fault_in_the_first_curator_is_contained_and_the_second_runs(
        tmp_path: Path, monkeypatch, fault: type[BaseException]):
    """The lessons spawn leaves `a.md` and raises a fault that is not a box fault: handled as
    before, its run's box stopped whatever the class. `_drain_curators` returns, the questioner
    curator runs (in a window of its own) and commits, and the findings channel's stuck record
    names the fault (f1 bumped only by the retiring `GitError`)."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)

    def boom(*_a: Any) -> None:
        raise _not_a_box_fault(fault, "not a box fault")

    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=boom)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, [], curator=curator, q_curator=q_curator)

    drains._drain_curators(t.paths, t.trigger, box=runs)

    assert t.modules() == ["author", "questioner_curator"]
    assert len(q_curator.calls) == 1
    assert daemon.steps().count("start") == 2, daemon.steps()
    assert daemon.status(NAME) == "exited", "a run left the box running"
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")
    assert t.sc.head_text(_rel(t.sc, "a.md")) is None
    assert _stuck_classes(t.paths, "findings") == [fault.__name__]
    assert t.sc.pending_by_id()["f1"].get("attempts") == (1 if fault is GitError else None)


# ---------------------------------------------------------------------------------------
# D3a: the box fault outranks the undo's own fault
# ---------------------------------------------------------------------------------------

#: The holding folder the box swaps for a link before its run ends: the undo's write-back of
#: `sub/lesson.md` then meets a linked holding folder, a plain `OSError(ELOOP)`.
SEEDED_SUB = {"sub/lesson.md": S.lesson("f0")}


def _swap_sub_for_a_link(moved: Path) -> Callable[..., None]:
    def plant(_rows: Any, _batch_id: str, cfg: Any) -> None:
        move_out_and_link(cfg.corpus_dir / "sub", moved)

    return plant


def _undo_fault_logged(caplog: Any) -> bool:
    """A WARNING-or-worse record carries the undo's own fault, the core's plain `OSError(ELOOP)`
    for a linked holding folder: as the record's exception, or in its text (the core's
    refusal, or `ELOOP`'s own words). The leaf refusal (`NotPlainEntry`) the undo passes over
    for the link itself is not it."""
    said = (_io._LINKED_FOLDER, os.strerror(errno.ELOOP))
    for r in caplog.records:
        if r.levelno < logging.WARNING:
            continue
        exc = r.exc_info[1] if r.exc_info else None
        if isinstance(exc, OSError) and type(exc) is not NotPlainEntry and exc.errno == errno.ELOOP:
            return True
        if any(text in r.getMessage() for text in said):
            return True
    return False


@pytest.mark.parametrize("source", ["spawn", "stop"])
def test_a_box_fault_outranks_an_undo_fault_and_the_second_curator_never_runs(
        tmp_path: Path, monkeypatch, caplog, source: str):
    """The box swaps the corpus folder `sub/` (holding a committed lesson) for a link, then a box
    fault follows (the spawn raises `BoxFault`, or its run's stop is refused with nothing else in
    flight). The undo's write-back of `sub/lesson.md` raises `OSError(ELOOP)`; with a `BoxFault`
    in flight that is logged and suppressed, so the `BoxFault` escapes `_drain_curators` rather
    than an `OSError` that `_run_curator_module` would swallow. The questioner curator never runs,
    nothing commits, f1 is not bumped, and its stuck record names `BoxFault`. Control: the next
    row."""
    caplog.set_level(logging.WARNING)
    f = _box_fault_scene(tmp_path, monkeypatch, source, seed_corpus=SEEDED_SUB,
                         plant=_swap_sub_for_a_link(tmp_path / "outside" / "moved-sub"))
    q_queued = _queued(f.t.paths)[1]

    got = X.caught(lambda: drains._drain_curators(f.t.paths, f.t.trigger, box=f.runs))

    _assert_is_the_box_fault(got, f)
    _assert_halted_after_the_first_curator(f.t, f.q_curator, q_queued)
    assert _undo_fault_logged(caplog), "the undo's own fault was swallowed without a trace"


#: In-flight faults that are not box faults, over the same undo fault: the retiring
#: `AuthorError` and `GitError`, and the non-retiring rest, the systemic ones among them.
UNDO_CONTROL_FAULTS = [S.author_error, RuntimeError, GitError, StageAbort, FatalConfigError,
                       RegistryError]


@pytest.mark.parametrize("in_flight", UNDO_CONTROL_FAULTS,
                         ids=lambda c: "AuthorError" if c is S.author_error else c.__name__)
def test_control_an_undo_fault_still_replaces_a_non_box_fault(
        tmp_path: Path, monkeypatch, in_flight: Callable[[str], Exception]):
    """The same swap, with the curator raising a fault that is not a box fault (retiring or not,
    systemic or not): the undo's `OSError(ELOOP)` still replaces it (#1134 O5.3), is recorded
    stuck as `OSError` with f1 not bumped, and `_run_curator_module` contains it, so
    `_drain_curators` returns and the questioner curator runs and commits."""
    _daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)

    def plant_then_fail(rows: Any, batch_id: str, cfg: Any) -> None:
        _swap_sub_for_a_link(tmp_path / "outside" / "moved-sub")(rows, batch_id, cfg)
        if in_flight is S.author_error:
            raise S.author_error("refused after the swap")
        raise _not_a_box_fault(in_flight, "failed after the swap")

    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=plant_then_fail)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, [], curator=curator, q_curator=q_curator, seed_corpus=SEEDED_SUB)

    drains._drain_curators(t.paths, t.trigger, box=runs)

    assert _stuck_classes(t.paths, "findings") == ["OSError"]
    assert t.sc.pending_by_id()["f1"].get("attempts") is None
    assert t.modules() == ["author", "questioner_curator"]
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


# ---------------------------------------------------------------------------------------
# O4 through the lane: the box fault escapes `author_drain`, so nothing is delivered
# ---------------------------------------------------------------------------------------

#: `(source, the curator it faults in)`: the first curator's spawn, start and stop, the
#: repair's stop, a stop fault over an undo that faults too, and the second curator's stop.
LANE_FAULTS = [
    pytest.param("spawn", "author", id="spawn"),
    pytest.param("start", "author", id="start"),
    pytest.param("stop", "author", id="stop"),
    pytest.param("repair-stop", "author", id="repair-stop"),
    pytest.param("stop-over-an-undo-fault", "author", id="stop-over-an-undo-fault"),
    pytest.param("stop", "questioner_curator", id="second-curator-stop"),
]


def _lane(t: Tick, daemon: X.FakeDaemon, *, trigger: Callable[..., None] | None = None
          ) -> tuple[Callable[[], int], list[str], X.ScanWatch]:
    """`author_drain` over the tick's worktree (`trigger`, else the tick's own), only its
    `start_box=` injected: `HeldStart` over `daemon`, whose executor carries the daemon, so the
    post-create stop, the runs and the default removal reach it through that executor."""
    events: list[str] = []
    branch = RepoBranch(t.sc.repo, events=events)
    watch = X.ScanWatch(daemon, events)
    t.daemon = daemon

    def run() -> int:
        return drains.author_drain(t.paths, trigger_author=trigger or t.trigger, branch=branch,
                                   start_box=X.HeldStart(daemon), scrub=watch)

    return run, events, watch


def test_control_author_drain_delivers_a_batch_with_no_box_fault(tmp_path: Path, monkeypatch):
    """The lane rows' control: the same tick, nothing faults. The box is created at batch start
    and stopped before the first curator is triggered; each curator's spawn gets a window of its
    own; both curators commit, the box is removed before the scan, and `finish_batch` delivers
    the batch. Each curator is handed the handle (F3), and nothing reaches the `docker` on
    `PATH` (F2)."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    daemon = X.FakeDaemon(tmp_path)
    daemon.tripwire = X.Tripwire(tmp_path).install(monkeypatch)
    log = X.Journal(daemon)
    t = _tick(tmp_path, log, curator=S.FakeCurator(writes={"a.md": S.lesson("f1")}),
              q_curator=S.FakeCurator(writes={"q.md": S.lesson("w1")}))
    run, events, watch = _lane(t, daemon)

    assert run() == 0
    steps = daemon.steps()
    assert steps.index("start_box") < steps.index("stop") < steps.index("trigger:author"), steps
    log.assert_runs_hold_exactly(["agent", "agent"], SPAWN_KINDS)
    watch.assert_scanned_once_the_box_was_gone()
    assert t.modules() == ["author", "questioner_curator"]
    assert all(isinstance(b, X.box_runs_type()) for _, b in t.triggered), t.triggered
    assert any(e.startswith("finish_batch:") for e in events), events
    assert t.sc.head_text(_rel(t.sc, "a.md")) == S.lesson("f1")
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")
    X.no_path_docker(daemon)


@pytest.mark.parametrize(("source", "in_curator"), LANE_FAULTS)
def test_a_box_fault_escapes_author_drain_with_nothing_delivered(
        tmp_path: Path, monkeypatch, source: str, in_curator: str):
    """`author_drain` over the real worktree (the trigger, the branch, the batch start and the
    scan injected): a box fault in either curator escapes `author_drain` as a `BoxFault`, with no
    build pointer. The box is removed, then the tree is scanned, and the worktree cleaned up,
    but `finish_batch` (push and PR) never runs. In the first curator: the second is never
    triggered, nothing is committed, f1 is not bumped. In the second: its lesson is undone and
    w1 not bumped. Control: the row above."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    undo_fault = source == "stop-over-an-undo-fault"
    f = _box_fault_scene(
        tmp_path, monkeypatch, "stop" if undo_fault else source, in_curator=in_curator,
        seed_corpus=SEEDED_SUB if undo_fault else None,
        plant=_swap_sub_for_a_link(tmp_path / "outside" / "moved-sub") if undo_fault else None,
        stops_before=1)
    q_queued = _queued(f.t.paths)[1]
    run, events, watch = _lane(f.t, f.daemon)

    got = X.caught(run)

    _assert_is_the_box_fault(got, f)
    assert not any(e.startswith("finish_batch:") for e in events), events
    watch.assert_scanned_once_the_box_was_gone()
    assert "cleanup" in events, events
    X.no_path_docker(f.daemon)
    if in_curator == "author":
        _assert_halted_after_the_first_curator(f.t, f.q_curator, q_queued)
    else:
        _assert_halted_in_the_second_curator(f.t)


# ---------------------------------------------------------------------------------------
# O1 / O3': a process the spawn left in its box dies with its run
# ---------------------------------------------------------------------------------------


class LeftProcess:
    """A process the spawn leaves in the box, simulated over the fake daemon: it lives while the
    container keeps running in the boot it was started in, and dies with the run's stop (a
    later start is a fresh boot, as a stopped container's processes do not come back). With
    `outlives_its_run` it acts regardless (the control: what a process that survived would do).

    It gets its turn whenever the host asks a placement (`cfg.tree_for`), which the tick first
    does for the commit, after the judge: the schedule on which a live process beats the
    commit. `turns` counts the turns it was given; `acts` what it did."""

    def __init__(self, daemon: X.FakeDaemon, *, outlives_its_run: bool = False) -> None:
        self.daemon, self.outlives = daemon, outlives_its_run
        self.boot: int | None = None
        self.act: Callable[[], None] | None = None
        self.acts: list[str] = []
        self.turns = 0

    def leave(self, act: Callable[[], None]) -> None:
        """Started by the spawn: in the box's current boot, which must be running."""
        assert self.daemon.status(NAME) == "running", "the spawn ran with no box running"
        self.boot = self.daemon.boots()
        self.act = act

    def alive(self) -> bool:
        if self.act is None:
            return False
        if self.outlives:
            return True
        return self.daemon.status(NAME) == "running" and self.daemon.boots() == self.boot

    def turn(self) -> None:
        if self.act is None or self.acts:
            return
        self.turns += 1
        if self.alive():
            self.act()


#: What the spawn leaves at `a.md`, and what the verifier judges.
SPAWNED = S.lesson("f1", body="the lesson the verifier judged")
#: What the process left in the box writes there: it cites f1 too, so it would pass every rule
#: the commit applies without a verifier.
EVIL = S.lesson("f1", body="rewritten by a process the spawn left behind")
#: What the box writes while its run's box is still up: judged like anything else.
VARIANT = S.lesson("f1", body="rewritten while the box was still up")


def _leave_a_writer(process: LeftProcess, writes: str, outside: Path) -> Callable[..., None]:
    """The spawn's last act: leave a process in the box that, once, replaces `a.md` with `EVIL`
    (`rewrite`), or with a symlink to an outside file holding it (`symlink`)."""

    def leave(_rows: Any, _batch_id: str, cfg: Any) -> None:
        at = cfg.corpus_dir / "a.md"

        def act() -> None:
            if writes == "symlink":
                target = outside / "evil.md"
                put(target, EVIL)
                plant_link(at, target)
            else:
                put(at, EVIL)
            process.acts.append(writes)

        process.leave(act)

    return leave


def _o1_tick(tmp_path: Path, process: LeftProcess, writes: str | None
             ) -> tuple[Tick, S.FakeVerifier]:
    leave = _leave_a_writer(process, writes, tmp_path / "outside") if writes else None
    curator = S.FakeCurator(writes={"a.md": SPAWNED}, also=leave)
    verifier = S.FakeVerifier()
    t = _tick(tmp_path, [], curator=curator, q_curator=S.FakeCurator(), verifier=verifier,
              q_rows=(), on_place=process.turn)
    return t, verifier


@pytest.mark.parametrize("writes", ["rewrite", "symlink"])
def test_a_process_left_in_the_box_cannot_change_a_judged_lesson(tmp_path: Path, monkeypatch,
                                                                 writes: str):
    """`_drain_curators(..., box=<the batch's stopped box>)`: the spawn leaves `a.md` and a
    process that would replace it (new bytes, or a symlink) at the commit's placement, after the
    judge. The spawn's run stopped the box, and the process with it, so the process never acts
    and HEAD holds the bytes the verifier judged, as a plain file. Control: the next row, where
    the same process acts if it outlives its run."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    process = LeftProcess(daemon)
    t, verifier = _o1_tick(tmp_path, process, writes)

    drains._drain_curators(t.paths, t.trigger, box=runs)

    assert verifier.texts_for("a.md") == [SPAWNED]
    assert process.act is not None, "no process was left in the box, so the row is vacuous"
    assert process.turns >= 1, "the process never had a turn after its run, so the row is vacuous"
    assert process.acts == [], "a process outlived its run's stop"
    assert t.sc.head_text(_rel(t.sc, "a.md")) == SPAWNED
    assert _git.git(["ls-tree", "HEAD", "--", _rel(t.sc, "a.md")],  # lint-oracle: ok — reads HEAD as a git user would
                    cwd=t.sc.repo).split(" ", 1)[0] == "100644"


@pytest.mark.parametrize("writes", ["rewrite", "symlink"])
def test_control_a_process_that_outlived_its_run_would_race_the_commit(
        tmp_path: Path, monkeypatch, writes: str):
    """The same tick with a process that survives its run: it acts at the commit's placement,
    after the judge, and HEAD holds what it wrote (a symlink commits as one), which the verifier
    never saw. The race the run's stop closes is real against this machinery."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    process = LeftProcess(daemon, outlives_its_run=True)
    t, verifier = _o1_tick(tmp_path, process, writes)

    drains._drain_curators(t.paths, t.trigger, box=runs)

    assert verifier.texts_for("a.md") == [SPAWNED]
    assert process.acts == [writes]
    mode = _git.git(["ls-tree", "HEAD", "--", _rel(t.sc, "a.md")],  # lint-oracle: ok — reads HEAD as a git user would
                    cwd=t.sc.repo).split(" ", 1)[0]
    if writes == "symlink":
        assert mode == "120000"
    else:
        assert t.sc.head_text(_rel(t.sc, "a.md")) == EVIL


def test_what_the_box_writes_during_its_own_run_is_what_is_judged(tmp_path: Path, monkeypatch):
    """The box rewrites `a.md` on its run's way out, while it is still up: the settle and the
    judge come after the stop, so the verifier judges what it wrote, and that is what HEAD
    holds."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    process = LeftProcess(daemon)
    t, verifier = _o1_tick(tmp_path, process, None)
    daemon.on_stop(t.sc.corpus / "a.md", VARIANT, at=1)

    drains._drain_curators(t.paths, t.trigger, box=runs)

    assert verifier.texts_for("a.md") == [VARIANT]
    assert t.sc.head_text(_rel(t.sc, "a.md")) == VARIANT


def _repair_o1_tick(tmp_path: Path, process: LeftProcess
                    ) -> tuple[Tick, S.FakeVerifier, S.FakeRepair]:
    """The O1 tick with the process left by the REPAIR: the curator leaves `a.md` (judged BAD),
    the repair rewrites it (judged GOOD on pass 2) and leaves a process that, once, replaces it
    with `EVIL`, at the commit's placement after judge 2."""

    def leave(_bad: Any, _batch_id: str, cfg: Any) -> None:
        at = cfg.corpus_dir / "a.md"

        def act() -> None:
            put(at, EVIL)
            process.acts.append("rewrite")

        process.leave(act)

    repair = S.FakeRepair(writes={"a.md": REPAIRED}, also=leave)
    verifier = S.FakeVerifier(verdicts={"a.md": ["BAD", "GOOD"]})
    t = _tick(tmp_path, [], curator=S.FakeCurator(writes={"a.md": S.lesson("f1")}),
              q_curator=S.FakeCurator(), verifier=verifier, repair=repair, q_rows=(),
              on_place=process.turn)
    return t, verifier, repair


@pytest.mark.parametrize("stop", ["takes-no-effect", "holds"])
def test_a_process_the_repair_left_cannot_change_the_lesson_judged_after_it(
        tmp_path: Path, monkeypatch, stop: str):
    """`_drain_curators`: the repair rewrites `a.md` and leaves a process that would replace it
    after judge 2. With `takes-no-effect`, the repair's run's stop answers 0 and the box keeps
    running: the run proves its stop by the status, so it raises `BoxFault` before judge 2, the
    process never acts, and nothing is committed (no settle, judge, restore or commit beside the
    repair's leftovers). Control (`holds`): the stop takes, the process dies with the run though
    it is given its turn, and HEAD holds what judge 2 approved. The next row shows the same
    process, outliving its run, does reach HEAD."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    if stop == "takes-no-effect":
        daemon.stop_takes_no_effect(at=[2])  # 1: the curator's run's stop; 2: the repair's
    process = LeftProcess(daemon)
    t, verifier, repair = _repair_o1_tick(tmp_path, process)

    got = X.caught(lambda: drains._drain_curators(t.paths, t.trigger, box=runs))

    assert len(repair.calls) == 1, "the repair never ran, so the row is vacuous"
    assert process.act is not None, "no process was left in the box, so the row is vacuous"
    assert process.acts == [], "a process the repair left acted after the judge"
    if stop == "holds":
        assert got is None, got
        assert process.turns >= 1, "the process never had a turn after its run (vacuous)"
        assert verifier.texts_for("a.md") == [S.lesson("f1"), REPAIRED]
        assert t.sc.head_text(_rel(t.sc, "a.md")) == REPAIRED
        return
    assert isinstance(got, BoxFault), f"a repair's stop that did not take went unnoticed: {got!r}"
    assert verifier.texts_for("a.md") == [S.lesson("f1")], "judged beside the repair's box"
    assert t.sc.head_files() == [], "a commit landed beside the repair's running box"


def test_control_a_process_the_repair_left_that_outlived_its_run_would_race_the_commit(
        tmp_path: Path, monkeypatch):
    """The same tick with the repair's process surviving its run: it acts at the commit's
    placement, after judge 2, and HEAD holds `EVIL`, which no verifier saw."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    process = LeftProcess(daemon, outlives_its_run=True)
    t, verifier, _repair = _repair_o1_tick(tmp_path, process)

    drains._drain_curators(t.paths, t.trigger, box=runs)

    assert verifier.texts_for("a.md") == [S.lesson("f1"), REPAIRED]
    assert process.acts == ["rewrite"]
    assert t.sc.head_text(_rel(t.sc, "a.md")) == EVIL


# ---------------------------------------------------------------------------------------
# A path the box first writes as its run stops is settled and judged after the stop
# ---------------------------------------------------------------------------------------

#: A new file outside both corpora: a stray only a settle that lists the tree after the stop
#: sees.
NEW_STRAY = "defender/notes/new1195.md"
#: A new lesson the box leaves in the corpus as it stops, citing the batch's own finding.
NEW_LESSON = S.lesson("f1", body="a second lesson, written as the box stopped")


@pytest.mark.parametrize("what", ["new-stray", "new-lesson"])
@pytest.mark.parametrize("channel", CHANNELS)
def test_a_path_the_box_first_writes_as_its_run_stops_is_settled_and_judged(
        tmp_path: Path, monkeypatch, channel: str, what: str):
    """The spawn leaves `a.md`; the box, on its run's way out while still up, first writes a
    path the spawn never touched. A new file outside both corpora (`new-stray`) is refused by
    the settle (an `AuthorError` naming it: rc 2, a stuck record naming it, nothing committed).
    Control (`new-lesson`): a new lesson in the corpus is settled, judged (lessons channel) and
    committed beside `a.md`. A settle, or a listing of its, taken inside the run would miss
    both."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")})
    sc = _channel_scene(tmp_path, channel, rows=_rows(channel, "f1"), curator=curator)
    verifier = S.FakeVerifier() if channel == "lessons" else None
    sc.cfg = _wire(sc.cfg, [], curator=curator, verifier=verifier, journal=False)
    if what == "new-stray":
        daemon.on_stop(sc.repo / NEW_STRAY, "left by the box as it stopped\n", at=1)
    else:
        daemon.on_stop(sc.corpus / "b.md", NEW_LESSON, at=1)

    rc = sc.run(box=runs)

    assert curator.calls, "the spawn never ran"
    if what == "new-lesson":
        assert rc == 0, rc
        assert sc.head_text(_rel(sc, "b.md")) == NEW_LESSON, "the stop-time lesson was missed"
        assert sc.head_text(_rel(sc, "a.md")) == S.lesson("f1")
        if verifier is not None:
            assert verifier.texts_for("b.md") == [NEW_LESSON], "the stop-time lesson was not judged"
        return
    assert rc == 2, rc
    assert sc.head_files() == [], "a commit landed beside a stray the box left as it stopped"
    assert any(NEW_STRAY in str(r.get("reason")) for r in S.stuck_records(sc.channel)), (
        S.stuck_records(sc.channel))


# ---------------------------------------------------------------------------------------
# A seam fault at the run's stop halts the drain, never contained as a curator's crash
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("docker", ["seam-OSError", "seam-TimeoutExpired", "holds"])
def test_a_seam_fault_at_the_runs_stop_halts_the_lessons_drain(tmp_path: Path, monkeypatch,
                                                                docker: str):
    """Through `_drain_curators` and both real curators: the docker the box carries raises at
    the lessons run's stop (no binary; a daemon that never answered), with nothing in flight.
    That is a `BoxFault`: the drain halts with it, the questioner curator is never triggered,
    the findings channel records `BoxFault`, and nothing is committed. An `OSError` escaping
    raw would be contained by `_run_curator_module` as a curator's crash and the drain would go
    on. Control (`holds`): both curators commit and the box is stopped."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    if docker != "holds":
        daemon.seam_raises(docker.removeprefix("seam-"), step="stop", at=[1])
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")})
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, [], curator=curator, q_curator=q_curator)

    got = X.caught(lambda: drains._drain_curators(t.paths, t.trigger, box=runs))

    assert len(curator.calls) == 1, "the spawn never ran, so the row is vacuous"
    X.no_path_docker(daemon)
    if docker == "holds":
        assert got is None, got
        assert t.modules() == ["author", "questioner_curator"]
        assert t.sc.head_text(_rel(t.sc, "a.md")) == S.lesson("f1")
        assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")
        assert daemon.status(NAME) == "exited"
        return
    assert daemon.seam_raised == ["stop"], "the seam never raised at the stop (vacuous)"
    assert isinstance(got, BoxFault), f"a box whose stop faulted did not halt the drain: {got!r}"
    assert t.modules() == ["author"], "the stop's seam fault was contained as a curator's crash"
    assert q_curator.calls == []
    assert _stuck_classes(t.paths, "findings") == ["BoxFault"]
    assert t.sc.head_files() == []
