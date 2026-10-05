"""#1195 amendment (2026-10-06), the lessons drain: one box per agent run.

`author_drain` (the lessons and lessons-questioner channels, which share one tick) no longer
starts a box for the batch, nor freezes one. The `box` threaded down to each curator is the
batch's `BoxSource`; each box-using spawn runs inside a box of its own:

- `_author_batch`: `with box_mod.box_for_run(cfg.box) as box: result = cfg.invoke_agent(
  to_author, batch_id, replace(cfg, box=box))`;
- `_spawn_repair`: the same for `cfg.invoke_repair`.

So no capture, settle, agent-report check, judge, restore, commit or rotation runs while a box
of the batch is up (O2'), and nothing a spawn leaves running outlives its run (O3'). A box that
won't start or won't come down halts the batch with `BoxFault` (O4, E5: `_drain_one_curator`
re-raises it; D3a: it outranks the undo's own fault). One container name serves the whole batch,
so a box a failed teardown left alive refuses the next run's start (E2).

Every curator scene is `_spec773`'s: a real repo, queue, gate, settle, judge, restore, commit
and rotation; only the spawns, the verifier and the key source are fakes, entering through the
config. Box starts and stops enter through a `BoxSource`'s seams (`_box1195.Runs`, a recorded
pair; `SimBox`, a simulated box with processes), or, for the production rows, through the real
`start_box`/`stop_box` over a fake daemon on `PATH` (`_box1195.FakeDaemon`). Never
`monkeypatch.setattr`.

Tests -> obligations:

- Wiring, O2'/E4: `test_each_spawn_runs_in_a_box_of_its_own_and_no_host_step_runs_beside_one`
  (both channels, judged clean and repaired), `test_one_tick_runs_one_box_per_agent_run_across_both_curators`,
  `test_the_pre_state_is_captured_before_the_box_starts`,
  `test_a_failing_spawns_box_is_removed_before_the_undo_runs`.
- Wiring through the production drain (no box at batch start, one real box per run, none
  after the last, E3's batch-end probe): `test_the_production_drain_runs_one_real_box_per_agent_run_and_leaves_none`.
- E2: `test_a_box_a_failed_teardown_left_alive_refuses_the_next_curators_run`, with
  `test_control_a_teardown_that_holds_lets_the_next_curator_run_and_deliver`.
- O4 (E5): `test_a_box_fault_from_the_first_curators_step_halts_the_drain` (+ its control),
  `test_a_box_fault_in_the_first_curator_halts_the_tick_before_the_second` (the spawn, a start
  fault, a link-ban failure at a start, a teardown fault; each also in the repair's run),
  `test_a_box_fault_in_the_second_curator_halts_the_drain`,
  `test_control_a_non_box_fault_in_the_first_curator_is_contained_and_the_second_runs` (N4),
  `test_a_box_fault_escapes_author_drain_with_nothing_delivered` (+ its control),
  `test_the_escaping_box_fault_names_the_cut_commit_not_the_first_curators_commit` (E6).
- D3a: `test_a_box_fault_outranks_an_undo_fault_and_the_second_curator_never_runs`, with
  `test_control_an_undo_fault_still_replaces_a_non_box_fault`.
- O1/O3': `test_a_process_left_in_the_box_cannot_change_a_judged_lesson` (rewrite, symlink),
  `test_control_with_one_box_for_the_batch_the_process_races_the_commit`,
  `test_what_the_box_writes_during_its_own_run_is_what_is_judged`.
"""
from __future__ import annotations

import dataclasses
import errno
import logging
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _git, _io
from defender._git import GitError
from defender._io import NotPlainEntry
from defender.learning.core import drains
from defender.learning.core.config import FatalConfigError, LoopPaths, StageAbort
from defender.runtime.box import AliasBanNotInForce, BoxFault
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
from defender.tests.e2e import _box665 as B
from defender.tests.e2e.test_922_spine import RepoBranch

CHANNELS = ["lessons", "questioner"]

#: The spawns: each must run inside a box of its own, and nothing else may.
SPAWN_KINDS = ("agent", "repair")

#: The repair's rewrite of `a.md`: new bytes, so the judge's memo re-judges it on pass 2.
REPAIRED = S.lesson("f1", body="the lesson, repaired")

#: The container name the recorded sources ask for (the drain's is `defender-drain-<batch id>`).
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
    `before` runs first on each call (the simulated box's turn, in the O1 rows)."""

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


def _state(repo: Path, paths: LoopPaths) -> Callable[[], tuple]:
    """What a run's `enter`/`exit` carry: HEAD and both queues' bytes."""
    return lambda: (_git.git_head_sha(repo), _queued(paths))


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
    the drain's `trigger_author` seam: it logs `("trigger", module)`, runs `on_trigger(module)`,
    and runs that curator the way `drains._maybe_trigger_author` does, handing it the box the
    drain handed down."""

    sc: S.Scene
    log: list
    cfgs: dict[str, Any]
    triggered: list[tuple[str, Any]] = dataclasses.field(default_factory=list)
    on_trigger: Callable[[str], object] | None = None

    @property
    def paths(self) -> LoopPaths:
        return self.sc.paths

    def trigger(self, _paths: LoopPaths, _pending_file: Path, _threshold_env: str,
                module_name: str, _pending_label: str, *, box: Any = None) -> None:
        self.log.append(("trigger", module_name))
        self.triggered.append((module_name, box))
        if self.on_trigger is not None:
            self.on_trigger(module_name)
        cfg = self.cfgs[module_name]
        drains._run_curator_module(
            module_name, lambda mod: mod.run_batch(hold_committed=True, cfg=cfg, box=box))

    def modules(self) -> list[str]:
        return [m for m, _ in self.triggered]

    def state(self) -> Callable[[], tuple]:
        return _state(self.sc.repo, self.paths)


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


def _segments(log: list, wins: list[tuple[int, int]]) -> list[list[tuple]]:
    """The log split around the runs: before the first, between each pair, after the last."""
    bounds = [-1, *[i for w in wins for i in w], len(log)]
    return [log[bounds[i] + 1:bounds[i + 1]] for i in range(0, len(bounds), 2)]


# ---------------------------------------------------------------------------------------
# Wiring: each spawn in a box of its own; no host step beside a live box
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("repair", [False, True], ids=["judged-clean", "repaired"])
@pytest.mark.parametrize("channel", CHANNELS)
def test_each_spawn_runs_in_a_box_of_its_own_and_no_host_step_runs_beside_one(
        tmp_path: Path, channel: str, repair: bool):
    """Through the channel's `run_batch(cfg=..., box=<a source>)`: the curator leaves `a.md`
    (citing f1), `b.md` (citing f2) and a non-`.md` stray, and skips f3. With every verdict GOOD,
    one run holds the curator spawn and nothing else. With `a.md` BAD then GOOD and `b.md` BAD
    throughout, a second run holds the repair spawn (which rewrites `a.md` and leaves a stray of
    its own) and nothing else.

    Each spawn is handed, as its config's `box`, the box its own run started (a fresh one per
    run, each from the source's request), and every box is removed by the end. Every host step
    is seen with no box up: the gate and the key source before the first run; the settle's
    put-back of each spawn's stray, the report reads, the corpus reads and the judge after each;
    the restore of the unapproved `b.md`, the commit's placements and the post-rotation hook
    after the last. HEAD and both queues are unchanged across each run, and both moved by the
    end of the tick."""
    log: list = []
    curator = S.FakeCurator(
        writes={"a.md": S.lesson("f1"), "b.md": S.lesson("f2"), "stray.txt": "not a lesson\n"},
        committed=["f1", "f2"], consumed_skip=[{"finding_id": "f3", "reason": "dup"}],
    )
    sc = _channel_scene(tmp_path, channel, rows=_rows(channel, "f1", "f2", "f3"), curator=curator)
    fixer = S.FakeRepair(writes={"a.md": REPAIRED, "repair-stray.txt": "not a lesson\n"})
    verdicts = {"a.md": ["BAD", "GOOD"], "b.md": "BAD"} if repair else {}
    runs = X.Runs(log, state=_state(sc.repo, sc.paths))
    sc.cfg = _wire(sc.cfg, log, curator=curator, verifier=_verifier(log, verdicts), repair=fixer)
    queued_before = _queued(sc.paths)
    source = runs.source(NAME)

    assert sc.run(box=source) == 0

    spawns = ["agent", "repair"] if repair else ["agent"]
    wins = X.assert_each_run_holds_exactly(log, spawns, SPAWN_KINDS)
    assert len(runs.boxes) == len(spawns), runs.boxes
    assert curator.calls[-1]["cfg"].box is runs.boxes[0], (
        "the curator was not handed the box its own run started")
    if repair:
        assert fixer.calls[-1]["cfg"].box is runs.boxes[1], (
            "the repair was not handed the box its own run started")
    assert [r.name for r in runs.requests] == [NAME] * len(spawns)
    assert runs.alive == [], "a box outlived its run"
    assert fixer.spawned == (1 if repair else 0)
    segments = _segments(log, wins)
    before, after_spawn, after_last = segments[0], segments[1], segments[-1]
    assert {"gate", "key"} <= set(_kinds(before)), _kinds(before)
    stray = ("tree_for", str(sc.corpus / "stray.txt"))
    assert stray in after_spawn, "the settle after the curator spawn ran beside a live box"
    assert {"report", "read", "judge"} <= set(_kinds(after_spawn)), _kinds(after_spawn)
    assert ("tree_for", str(sc.corpus / "a.md")) in after_last, "the commit ran beside a box"
    assert "post_rotate" in _kinds(after_last)
    if repair:
        assert ("tree_for", str(sc.corpus / "repair-stray.txt")) in after_last
        assert "judge" in _kinds(after_last)
        assert ("unlink", "b.md") in after_last, "the restore of b.md ran beside a box"
        assert sc.head_text(_rel(sc, "a.md")) == REPAIRED
        assert sc.head_text(_rel(sc, "b.md")) is None
    else:
        assert sc.head_text(_rel(sc, "a.md")) == S.lesson("f1")
        assert sc.head_text(_rel(sc, "b.md")) == S.lesson("f2")
    assert sc.head_sha() != sc.base_sha
    assert _queued(sc.paths) != queued_before


def test_one_tick_runs_one_box_per_agent_run_across_both_curators(tmp_path: Path):
    """The design's key flow, through `_drain_curators(..., box=<the batch's source>)` and both
    real curators: each curator is handed the source itself (no box is up when either is
    triggered), and exactly three runs follow — the lessons curator, its repair, the questioner
    curator — each holding its spawn alone, each a fresh box from the one request (one container
    name per batch). No box is up between them or after the last. HEAD holds both curators'
    lessons."""
    log: list = []
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")})
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, log, curator=curator, q_curator=q_curator,
              verifier=_verifier(log, {"a.md": ["BAD", "GOOD"]}),
              repair=S.FakeRepair(writes={"a.md": REPAIRED}), journal=True)
    runs = X.Runs(log, state=t.state())
    source = runs.source(NAME)

    drains._drain_curators(t.paths, t.trigger, box=source)

    assert t.modules() == ["author", "questioner_curator"]
    assert all(b is source for _, b in t.triggered), "a curator was handed something but the source"
    X.assert_each_run_holds_exactly(log, ["agent", "repair", "agent"], SPAWN_KINDS)
    assert len({id(b) for b in runs.boxes}) == 3
    assert [r.name for r in runs.requests] == [NAME] * 3
    assert q_curator.calls[-1]["cfg"].box is runs.boxes[2]
    assert runs.alive == []
    assert t.sc.head_text(_rel(t.sc, "a.md")) == REPAIRED
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


#: A committed file outside both corpora: the box's write there once started is a stray only if
#: the tick took its baseline of strays before the start.
STRAY_REL = "defender/notes/stray1195.md"
STRAY_EDIT = "rewritten by the box\n"


@pytest.mark.parametrize("when", ["once-started", "before-the-run"])
@pytest.mark.parametrize("channel", CHANNELS)
def test_the_pre_state_is_captured_before_the_box_starts(tmp_path: Path, channel: str, when: str):
    """The box rewrites a committed file outside the corpus as soon as it is up: the settle
    refuses the tick (an `AuthorError` naming it, which retires: rc 2, f1 bumped, a stuck record
    naming the stray), HEAD unchanged, the stray put back. The baseline of strays was captured
    before the box started, so the rewrite is new. Control: the same rewrite already standing
    before the run is in the baseline, and the tick commits."""
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")})
    sc = _channel_scene(tmp_path, channel, rows=_rows(channel, "f1"), curator=curator)
    stray = sc.repo / STRAY_REL
    put(stray, "committed\n")
    S.git(sc.repo, "add", "--", STRAY_REL)
    S.git(sc.repo, "commit", "-q", "-m", "a file outside both corpora")
    sc.base_sha = sc.head_sha()
    if when == "before-the-run":
        put(stray, STRAY_EDIT)
    log: list = []
    runs = X.Runs(log, on_start=(lambda _b: put(stray, STRAY_EDIT))
                  if when == "once-started" else None)
    sc.cfg = _wire(sc.cfg, log, curator=curator, journal=False)

    rc = sc.run(box=runs.source(NAME))

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


def test_a_failing_spawns_box_is_removed_before_the_undo_runs(tmp_path: Path):
    """The lessons spawn leaves `a.md` and raises `RuntimeError`: its run still removes the box on
    that way out (the run holds the spawn alone), and the undo's removal of `a.md` through the
    corpus mount runs after, with no box up. The contained fault lets the questioner curator run,
    in a box of its own."""
    log: list = []

    def boom(*_a: Any) -> None:
        raise RuntimeError("the agent crashed")

    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=boom)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, log, curator=curator, q_curator=q_curator, journal=True)
    runs = X.Runs(log, state=t.state())

    drains._drain_curators(t.paths, t.trigger, box=runs.source(NAME))

    wins = X.assert_each_run_holds_exactly(log, ["agent", "agent"], SPAWN_KINDS)
    first_exit, second_enter = wins[0][1], wins[1][0]
    undo = [i for i, e in enumerate(log) if e == ("unlink", "a.md")]
    assert undo, "the undo never removed the failed spawn's lesson through the corpus mount"
    assert all(first_exit < i < second_enter for i in undo), "the undo ran beside a live box"
    assert runs.alive == []
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


# ---------------------------------------------------------------------------------------
# The production drain: real start/stop over a fake daemon
# ---------------------------------------------------------------------------------------


def _production_tick(tmp_path: Path, monkeypatch, daemon: X.FakeDaemon, *,  # noqa: PLR0913 — one tick, every fake a row varies
                     curator: S.FakeCurator, q_curator: S.FakeCurator,
                     verifier: S.FakeVerifier | None = None,
                     repair: S.FakeRepair | None = None) -> Tick:
    """A tick `author_drain` serves as production wires it: both thresholds at 1, the image
    inputs committed under the repo's `defender/`, the fake daemon first on `PATH` (so the
    drain's own `start_box`/`stop_box` and its source's status probe all reach it), and the
    trigger marking the daemon's log as each curator is triggered."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    X.clear_opt_out(monkeypatch)
    t = _tick(tmp_path, [], curator=curator, q_curator=q_curator, verifier=verifier,
              repair=repair)
    X.plant_image_inputs(t.sc.repo)
    S.git(t.sc.repo, "add", "-A", "--", "defender")
    S.git(t.sc.repo, "commit", "-q", "-m", "the box image inputs")
    t.sc.base_sha = t.sc.head_sha()
    daemon.install(monkeypatch)
    t.on_trigger = lambda module: daemon.mark(f"trigger:{module}")
    return t


def _author_drain(t: Tick, events: list[str], **seams: Any) -> int:
    branch = RepoBranch(t.sc.repo, events=events)
    return drains.author_drain(t.paths, trigger_author=t.trigger, branch=branch,
                               scrub=lambda tree, *_a, **_k: events.append(f"scrub:{tree}"),
                               **seams)


def test_the_production_drain_runs_one_real_box_per_agent_run_and_leaves_none(
        tmp_path: Path, monkeypatch):
    """`author_drain` with its own `start_box`/`stop_box`: the daemon creates no container
    before the first curator is triggered; for each spawn (the lessons curator, its repair, the
    questioner curator) exactly one container is created, under the batch's one name, the spawn
    runs, and it is removed; after the last removal the batch-end teardown asks the name's
    status, and no container is left. Both curators committed and the batch was delivered."""
    daemon = X.FakeDaemon(tmp_path)
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")},
                            also=lambda *_a: daemon.mark("curator"))
    repair = S.FakeRepair(writes={"a.md": REPAIRED}, also=lambda *_a: daemon.mark("repair"))
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")},
                              also=lambda *_a: daemon.mark("questioner"))
    t = _production_tick(tmp_path, monkeypatch, daemon, curator=curator, q_curator=q_curator,
                         verifier=S.FakeVerifier(verdicts={"a.md": ["BAD", "GOOD"]}),
                         repair=repair)
    events: list[str] = []

    assert _author_drain(t, events) == 0

    batch_id = next(e.split(":", 1)[1] for e in events if e.startswith("start_batch:"))
    name = f"defender-drain-{batch_id}"
    kept = [s for s in daemon.steps() if s in ("create", "rm") or ":" in s
            or s in ("curator", "repair", "questioner")]
    assert kept == ["trigger:author", "create", "curator", "rm", "create", "repair", "rm",
                    "trigger:questioner_curator", "create", "questioner", "rm"], kept
    assert daemon.created() == [name] * 3
    steps = daemon.steps(of=name)
    last_rm = len(steps) - 1 - steps[::-1].index("rm")
    assert "status" in steps[last_rm + 1:], f"no batch-end teardown asked the status: {steps}"
    assert daemon.names() == [], "a box outlived the batch"
    handed = curator.calls[-1]["cfg"].box
    assert handed.sandboxed, handed
    assert handed.name == name, handed
    assert any(e.startswith("finish_batch:") for e in events), events
    assert t.sc.head_text(_rel(t.sc, "a.md")) == REPAIRED
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


# ---------------------------------------------------------------------------------------
# E2: a box a failed teardown left alive refuses the next run's start
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("teardown", ["refused", "holds"])
def test_a_box_a_failed_teardown_left_alive_refuses_the_next_curators_run(
        tmp_path: Path, monkeypatch, caplog, teardown: str):
    """`author_drain` as production wires it, over the fake daemon. The lessons curator's spawn
    leaves `a.md` and crashes (`RuntimeError`, contained to its channel); with `refused`, the
    removal of its box fails on the way out, so that teardown fault is only logged under the
    crash, and the box stays running. The questioner curator's start then meets the batch's name
    still running and raises `BoxFault` before its spawn: the questioner never runs, nothing is
    committed, nothing is delivered, and the fault escapes `author_drain`.

    Control (`holds`): the same crash with the removal taking; the questioner gets a fresh box,
    commits, and the batch is delivered."""
    caplog.set_level(logging.WARNING)
    daemon = X.FakeDaemon(tmp_path)

    def crash(*_a: Any) -> None:
        if teardown == "refused":
            daemon.refuse_rm(1)
        raise RuntimeError("the agent crashed")

    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=crash)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _production_tick(tmp_path, monkeypatch, daemon, curator=curator, q_curator=q_curator)
    events: list[str] = []
    got = X.caught(lambda: _author_drain(t, events))

    assert len(curator.calls) == 1
    assert _stuck_classes(t.paths, "findings") == ["RuntimeError"]
    if teardown == "holds":
        assert got is None, got
        assert len(q_curator.calls) == 1
        assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")
        assert any(e.startswith("finish_batch:") for e in events), events
        return
    assert isinstance(got, BoxFault), got
    assert q_curator.calls == [], "the questioner ran beside the box the first run left alive"
    assert t.sc.head_sha() == t.sc.base_sha, "a commit landed beside a live box"
    assert not any(e.startswith("finish_batch:") for e in events), events
    assert _stuck_classes(t.paths, "questioner_findings") == ["BoxFault"]
    assert len(daemon.created()) == 1, "a second box was created beside the live one"


# ---------------------------------------------------------------------------------------
# O4 (E5): a box fault in either curator halts the tick
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
#: - `start`: its run's start (the box would not come up), before the spawn;
#: - `alias-ban`: its run's start finds the link ban not in force (`AliasBanNotInForce`, which the
#:   source surfaces as a `BoxFault` chained to it);
#: - `stop`: its run's teardown, after the spawn returned;
#: - `repair-spawn` / `repair-start` / `repair-stop`: the same in the repair's run (the lessons
#:   verdict BAD on pass 1, so the repair runs; its run is the second).
FIRST_CURATOR_SOURCES = ["spawn", "start", "alias-ban", "stop", "repair-spawn", "repair-start",
                         "repair-stop"]
SECOND_CURATOR_SOURCES = ["spawn", "start", "alias-ban", "stop"]


@dataclasses.dataclass
class Faulted:
    """A tick one of whose curators meets a box fault, its fakes, its recorded box seams, and
    the exception injected."""

    t: Tick
    curator: S.FakeCurator
    q_curator: S.FakeCurator
    verifier: S.FakeVerifier
    repair: S.FakeRepair
    runs: X.Runs
    fault: BaseException


def _box_fault_scene(  # noqa: PLR0913 — one tick, every fault a row varies
        tmp_path: Path, source: str, *, in_curator: str = "author",
        seed_corpus: dict[str, str] | None = None, plant: Callable[..., None] | None = None,
        log: list | None = None,
) -> Faulted:
    """A tick whose lessons curator leaves `a.md` (citing f1) and whose questioner curator leaves
    `q.md` (citing w1), each committing it unless something faults. The curator `in_curator`
    meets a box fault from `source` (`FIRST_CURATOR_SOURCES`), after running `plant` (the box's
    own act) in its spawn."""
    log = log if log is not None else []
    fault: BaseException = (AliasBanNotInForce("the alias ban is not in force under runsc")
                            if source == "alias-ban"
                            else BoxFault(f"the box failed ({source})"))

    def act(rows: Any, batch_id: str, cfg: Any) -> None:
        if plant is not None:
            plant(rows, batch_id, cfg)
        if source == "spawn":
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
    runs = X.Runs(log, start_faults={nth: fault} if kind in ("start", "alias-ban") else None,
                  stop_faults={nth: fault} if kind == "stop" else None)
    return Faulted(t=t, curator=curator, q_curator=q_curator, verifier=verifier, repair=repair,
                   runs=runs, fault=fault)


def _assert_is_the_box_fault(got: BaseException, f: Faulted) -> None:
    """The drain's `BoxFault` is the injected one, or — for a link-ban failure — a `BoxFault`
    chained to it; either may come re-raised with the cut commit appended (E6)."""
    if isinstance(f.fault, BoxFault):
        assert X.carries(got, f.fault), (got, X.chain(got))
        return
    assert isinstance(got, BoxFault), got
    assert f.fault in X.chain(got), (got, X.chain(got))


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
        tmp_path: Path, source: str):
    """Through `_drain_curators` and both real curators: a box fault in the lessons curator —
    from its spawn, its run's start (a box that won't come up, or a link ban not in force), its
    run's teardown, or the same in the repair's run — escapes the drain as a `BoxFault`. The
    questioner curator is never triggered, nothing is committed, f1 is not bumped and its stuck
    record names `BoxFault`; the curator's lesson is undone. A start fault runs no spawn; after a
    fault in the repair's run, nothing is judged again; every box that started was stopped."""
    f = _box_fault_scene(tmp_path, source)
    t = f.t
    q_queued = _queued(t.paths)[1]

    got = X.caught(lambda: drains._drain_curators(t.paths, t.trigger, box=f.runs.source(NAME)))

    _assert_is_the_box_fault(got, f)
    _assert_halted_after_the_first_curator(t, f.q_curator, q_queued)
    kind = source.removeprefix("repair-")
    assert len(f.curator.calls) == (0 if source in ("start", "alias-ban") else 1)
    assert not (t.sc.corpus / "a.md").exists(), "the curator's lesson was not undone"
    if source.startswith("repair-"):
        assert len(f.repair.calls) == (0 if kind == "start" else 1)
        assert f.verifier.texts_for("a.md") == [S.lesson("f1")], (
            "the tree was judged again after the repair's box fault")
    else:
        assert f.repair.calls == []
    assert len(f.runs.stopped) == len(f.runs.boxes), "a box that started was never stopped"


@pytest.mark.parametrize("source", SECOND_CURATOR_SOURCES)
def test_a_box_fault_in_the_second_curator_halts_the_drain(tmp_path: Path, source: str):
    """The same faults in the questioner curator, which runs second: its `BoxFault` escapes
    `_drain_curators` too, so `finish_batch` is never reached. The lessons curator's commit
    stands; the questioner's lesson is undone, w1 is not bumped and its stuck record names
    `BoxFault`."""
    f = _box_fault_scene(tmp_path, source, in_curator="questioner_curator")

    got = X.caught(lambda: drains._drain_curators(f.t.paths, f.t.trigger,
                                                  box=f.runs.source(NAME)))

    _assert_is_the_box_fault(got, f)
    _assert_halted_in_the_second_curator(f.t)
    assert len(f.q_curator.calls) == (0 if source in ("start", "alias-ban") else 1)


#: Faults that are not box faults, raised by the lessons spawn after it leaves its lesson. All but
#: `GitError` are non-retiring, contained by `_drain_one_curator` (N4: `StageAbort`,
#: `FatalConfigError`, `RegistryError` keep their behaviour); `GitError` retires inside its own
#: tick (f1 bumped). Either way the second curator runs.
CONTAINED_FAULTS = [RuntimeError, StageAbort, FatalConfigError, RegistryError, GitError]


def _not_a_box_fault(cls: type[Exception], message: str) -> Exception:
    return S.git_error(message) if cls is GitError else cls(message)


@pytest.mark.parametrize("fault", CONTAINED_FAULTS, ids=lambda c: c.__name__)
def test_control_a_non_box_fault_in_the_first_curator_is_contained_and_the_second_runs(
        tmp_path: Path, fault: type[Exception]):
    """The lessons spawn leaves `a.md` and raises a fault that is not a box fault: handled as
    before. `_drain_curators` returns, the questioner curator runs (in a box of its own) and
    commits, and the findings channel's stuck record names the fault (f1 bumped only by the
    retiring `GitError`)."""
    log: list = []

    def boom(*_a: Any) -> None:
        raise _not_a_box_fault(fault, "not a box fault")

    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=boom)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, log, curator=curator, q_curator=q_curator)
    runs = X.Runs(log)

    drains._drain_curators(t.paths, t.trigger, box=runs.source(NAME))

    assert t.modules() == ["author", "questioner_curator"]
    assert len(q_curator.calls) == 1
    assert len(runs.boxes) == 2, runs.boxes
    assert runs.alive == []
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
        tmp_path: Path, caplog, source: str):
    """The box swaps the corpus folder `sub/` (holding a committed lesson) for a link, then a box
    fault follows (the spawn raises `BoxFault`, or its run's teardown does with nothing else in
    flight). The undo's write-back of `sub/lesson.md` raises `OSError(ELOOP)`; with a `BoxFault`
    in flight that is logged and suppressed, so the `BoxFault` escapes `_drain_curators` rather
    than an `OSError` that `_run_curator_module` would swallow. The questioner curator never runs,
    nothing commits, f1 is not bumped, and its stuck record names `BoxFault`. Control: the next
    row."""
    caplog.set_level(logging.WARNING)
    f = _box_fault_scene(tmp_path, source, seed_corpus=SEEDED_SUB,
                         plant=_swap_sub_for_a_link(tmp_path / "outside" / "moved-sub"))
    q_queued = _queued(f.t.paths)[1]

    got = X.caught(lambda: drains._drain_curators(f.t.paths, f.t.trigger,
                                                  box=f.runs.source(NAME)))

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
        tmp_path: Path, in_flight: Callable[[str], Exception]):
    """The same swap, with the curator raising a fault that is not a box fault (retiring or not,
    systemic or not): the undo's `OSError(ELOOP)` still replaces it (#1134 O5.3), is recorded
    stuck as `OSError` with f1 not bumped, and `_run_curator_module` contains it, so
    `_drain_curators` returns and the questioner curator runs and commits."""

    def plant_then_fail(rows: Any, batch_id: str, cfg: Any) -> None:
        _swap_sub_for_a_link(tmp_path / "outside" / "moved-sub")(rows, batch_id, cfg)
        if in_flight is S.author_error:
            raise S.author_error("refused after the swap")
        raise _not_a_box_fault(in_flight, "failed after the swap")

    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=plant_then_fail)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, [], curator=curator, q_curator=q_curator, seed_corpus=SEEDED_SUB)

    drains._drain_curators(t.paths, t.trigger, box=X.Runs().source(NAME))

    assert _stuck_classes(t.paths, "findings") == ["OSError"]
    assert t.sc.pending_by_id()["f1"].get("attempts") is None
    assert t.modules() == ["author", "questioner_curator"]
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


# ---------------------------------------------------------------------------------------
# O4 through the lane: the box fault escapes `author_drain`, so nothing is delivered
# ---------------------------------------------------------------------------------------

#: `(source, the curator it faults in)`: the first curator's spawn, start, link ban and
#: teardown, the repair's teardown, a teardown fault over an undo that faults too, and the
#: second curator's teardown.
LANE_FAULTS = [
    pytest.param("spawn", "author", id="spawn"),
    pytest.param("start", "author", id="start"),
    pytest.param("alias-ban", "author", id="alias-ban"),
    pytest.param("stop", "author", id="stop"),
    pytest.param("repair-stop", "author", id="repair-stop"),
    pytest.param("stop-over-an-undo-fault", "author", id="stop-over-an-undo-fault"),
    pytest.param("stop", "questioner_curator", id="second-curator-stop"),
]


def _lane(t: Tick, runs: X.Runs) -> tuple[Callable[[], int], list[str]]:
    rec = B.BoxLifecycleRecorder()
    branch = RepoBranch(t.sc.repo, events=rec.events)

    def run() -> int:
        return drains.author_drain(t.paths, trigger_author=t.trigger, branch=branch,
                                   start_box=runs.start, stop_box=runs.stop, scrub=rec.scrub)

    return run, rec.events


def test_control_author_drain_delivers_a_batch_with_no_box_fault(tmp_path: Path, monkeypatch):
    """The lane rows' control: the same tick, nothing faults. No box is started before the
    first curator is triggered; each curator's spawn gets a box of its own; both curators commit
    and `finish_batch` delivers the batch."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    log: list = []
    t = _tick(tmp_path, log, curator=S.FakeCurator(writes={"a.md": S.lesson("f1")}),
              q_curator=S.FakeCurator(writes={"q.md": S.lesson("w1")}))
    run, events = _lane(t, X.Runs(log))

    assert run() == 0
    kinds = _kinds(log)
    assert kinds.index("trigger") < kinds.index("enter"), f"a box started before any curator: {kinds}"
    X.assert_each_run_holds_exactly(log, ["agent", "agent"], SPAWN_KINDS)
    assert t.modules() == ["author", "questioner_curator"]
    assert any(e.startswith("finish_batch:") for e in events), events
    assert t.sc.head_text(_rel(t.sc, "a.md")) == S.lesson("f1")
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


@pytest.mark.parametrize(("source", "in_curator"), LANE_FAULTS)
def test_a_box_fault_escapes_author_drain_with_nothing_delivered(
        tmp_path: Path, monkeypatch, source: str, in_curator: str):
    """`author_drain` over the real worktree (the trigger, the branch and the box seams
    injected): a box fault in either curator escapes `author_drain` as a `BoxFault` carrying the
    injected one. The tree is scanned and the worktree cleaned up, but `finish_batch` (push and
    PR) never runs. In the first curator: the second is never triggered, nothing is committed,
    f1 is not bumped. In the second: its lesson is undone and w1 not bumped. Control: the row
    above."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    undo_fault = source == "stop-over-an-undo-fault"
    f = _box_fault_scene(
        tmp_path, "stop" if undo_fault else source, in_curator=in_curator,
        seed_corpus=SEEDED_SUB if undo_fault else None,
        plant=_swap_sub_for_a_link(tmp_path / "outside" / "moved-sub") if undo_fault else None)
    q_queued = _queued(f.t.paths)[1]
    run, events = _lane(f.t, f.runs)

    got = X.caught(run)

    _assert_is_the_box_fault(got, f)
    assert not any(e.startswith("finish_batch:") for e in events), events
    assert any(e.startswith("scrub:") for e in events), events
    assert "cleanup" in events, events
    if in_curator == "author":
        _assert_halted_after_the_first_curator(f.t, f.q_curator, q_queued)
    else:
        _assert_halted_in_the_second_curator(f.t)


def test_the_escaping_box_fault_names_the_cut_commit_not_the_first_curators_commit(
        tmp_path: Path, monkeypatch):
    """The lessons curator commits (HEAD moves past the commit the worktree was cut from); the
    questioner curator's start then faults. The `BoxFault` escaping `author_drain` names
    `origin/main @ <the cut commit>`, never the lessons commit."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    f = _box_fault_scene(tmp_path, "start", in_curator="questioner_curator")
    cut = f.t.sc.base_sha
    run, events = _lane(f.t, f.runs)

    got = X.caught(run)

    assert isinstance(got, BoxFault), got
    assert got.__cause__ is f.fault, X.chain(got)
    head = f.t.sc.head_sha()
    assert head != cut, "the lessons curator never committed, so the row is vacuous"
    pointer = re.search(r"origin/main @ ([0-9a-f]{7,40})", str(got))
    assert pointer, str(got)
    assert cut.startswith(pointer.group(1)), (pointer.group(1), cut)
    assert not head.startswith(pointer.group(1)), "the pointer names the lessons commit"
    assert not any(e.startswith("finish_batch:") for e in events), events


# ---------------------------------------------------------------------------------------
# O1 / O3': a process the spawn left in its box dies with the box
# ---------------------------------------------------------------------------------------


class SimBox:
    """A box as the lane drives it, simulated as a `BoxSource`'s start/stop pair, with the
    processes a spawn leaves in it. Each start is a fresh box; each stop removes the box and every
    process in it, as the design does. With `per_batch`, a stop removes nothing: one box for the
    whole batch, the design this replaced (the race control).

    A process gets its turn whenever the host asks a placement (`cfg.tree_for`), which the tick
    first does for the commit, after the judge: the schedule on which a live process beats the
    commit. `turns_after_removal` counts the turns that came after a removal took a process
    with it. With `act_at_stop`, the processes also get a turn on the run's way out, while the
    box is still up."""

    def __init__(self, *, per_batch: bool = False, act_at_stop: bool = False) -> None:
        self.per_batch, self.act_at_stop = per_batch, act_at_stop
        self.up = False
        self.processes: list[Callable[[], None]] = []
        self.acts: list[str] = []
        self.removed_with_processes = 0
        self.turns_after_removal = 0
        self.starts = 0

    def start(self, request: Any, *_a: Any, **_kw: Any) -> X.RunBox:
        self.starts += 1
        self.up = True
        return X.RunBox(name=request.name, n=self.starts)

    def stop(self, _box: Any, *_a: Any, **_kw: Any) -> None:
        if self.act_at_stop:
            self.turn()
        if self.per_batch:
            return
        if self.processes:
            self.removed_with_processes += 1
        self.processes.clear()
        self.up = False

    def turn(self) -> None:
        if self.removed_with_processes:
            self.turns_after_removal += 1
        for process in list(self.processes):
            process()

    def source(self) -> Any:
        return X.box_source(X.request(NAME), start_box=self.start, stop_box=self.stop)


#: What the spawn leaves at `a.md`, and what the verifier judges.
SPAWNED = S.lesson("f1", body="the lesson the verifier judged")
#: What the process left in the box writes there: it cites f1 too, so it would pass every rule
#: the commit applies without a verifier.
EVIL = S.lesson("f1", body="rewritten by a process the spawn left behind")
#: What the process writes while its run's box is still up: judged like anything else.
VARIANT = S.lesson("f1", body="rewritten while the box was still up")


def _leave_a_writer(box: SimBox, writes: str, outside: Path) -> Callable[..., None]:
    """The spawn's last act: leave a process in the box that, once, replaces `a.md` with
    `EVIL` (`rewrite`), or with a symlink to an outside file holding it (`symlink`), or rewrites
    it to `VARIANT` (`variant`)."""

    def leave(_rows: Any, _batch_id: str, cfg: Any) -> None:
        at = cfg.corpus_dir / "a.md"

        def writer() -> None:
            if box.acts:
                return
            if writes == "symlink":
                target = outside / "evil.md"
                put(target, EVIL)
                plant_link(at, target)
            else:
                put(at, VARIANT if writes == "variant" else EVIL)
            box.acts.append(writes)

        assert box.up, "the spawn ran with no box up"
        box.processes.append(writer)

    return leave


def _o1_tick(tmp_path: Path, box: SimBox, writes: str) -> tuple[Tick, S.FakeVerifier]:
    curator = S.FakeCurator(writes={"a.md": SPAWNED},
                            also=_leave_a_writer(box, writes, tmp_path / "outside"))
    verifier = S.FakeVerifier()
    t = _tick(tmp_path, [], curator=curator, q_curator=S.FakeCurator(), verifier=verifier,
              q_rows=(), on_place=box.turn)
    return t, verifier


@pytest.mark.parametrize("writes", ["rewrite", "symlink"])
def test_a_process_left_in_the_box_cannot_change_a_judged_lesson(tmp_path: Path, writes: str):
    """`_drain_curators(..., box=<a source over the simulated box>)`: the spawn leaves `a.md` and
    a process that would replace it (new bytes, or a symlink) at the commit's placement, after
    the judge. The spawn's run removed its box, and the process with it, so the process never
    acts and HEAD holds the bytes the verifier judged, as a plain file. Control: the next row,
    where the same process wins with one box for the batch."""
    box = SimBox()
    t, verifier = _o1_tick(tmp_path, box, writes)

    drains._drain_curators(t.paths, t.trigger, box=box.source())

    assert verifier.texts_for("a.md") == [SPAWNED]
    assert box.removed_with_processes == 1, "no process was left in the box, so the row is vacuous"
    assert box.turns_after_removal >= 1, "the process never had a turn after its run, so the row is vacuous"
    assert box.acts == [], "a process outlived its run's box"
    assert t.sc.head_text(_rel(t.sc, "a.md")) == SPAWNED
    assert X.head_mode(t.sc.repo, _rel(t.sc, "a.md")) == "100644"


@pytest.mark.parametrize("writes", ["rewrite", "symlink"])
def test_control_with_one_box_for_the_batch_the_process_races_the_commit(
        tmp_path: Path, writes: str):
    """The same tick with one box for the batch (a stop removes nothing): the process acts at the
    commit's placement, after the judge, and HEAD holds what it wrote (a symlink commits as one),
    which the verifier never saw. The race per-run removal closes is real against this
    machinery."""
    box = SimBox(per_batch=True)
    t, verifier = _o1_tick(tmp_path, box, writes)

    drains._drain_curators(t.paths, t.trigger, box=box.source())

    assert verifier.texts_for("a.md") == [SPAWNED]
    assert box.acts == [writes]
    if writes == "symlink":
        assert X.head_mode(t.sc.repo, _rel(t.sc, "a.md")) == "120000"
    else:
        assert t.sc.head_text(_rel(t.sc, "a.md")) == EVIL


def test_what_the_box_writes_during_its_own_run_is_what_is_judged(tmp_path: Path):
    """The process acts on its run's way out, while the box is still up: the settle and the judge
    come after the box is removed, so the verifier judges what it wrote, and that is what HEAD
    holds."""
    box = SimBox(act_at_stop=True)
    t, verifier = _o1_tick(tmp_path, box, "variant")

    drains._drain_curators(t.paths, t.trigger, box=box.source())

    assert box.acts == ["variant"]
    assert verifier.texts_for("a.md") == [VARIANT]
    assert t.sc.head_text(_rel(t.sc, "a.md")) == VARIANT
