"""#1195: the lessons drain's box is frozen unless an agent is running.

#1178 amendment 2 / PR #1194's remedy, applied to `author_drain` (the lessons and
lessons-questioner channels, which share one box per tick), plus one new part: the per-curator
fault isolation stops swallowing a box fault. The seams, each driven by injection, never
`monkeypatch.setattr`:

- `drains._drain_curators(paths, trigger_author, *, box=None, pause=box_mod.pause_box)` calls
  `pause(box)` before the first curator (D1); `author_drain` keeps the default.
- `CorpusAuthorConfig.thaw`, defaulting to `box_mod.thawed`: `_author_batch` runs
  `cfg.invoke_agent(...)`, and `_spawn_repair` runs `cfg.invoke_repair(...)`, each inside
  `with cfg.thaw(cfg.box):`, and nothing else (D2, N6).
- `drains._drain_one_curator` re-raises `box_mod.BoxFault`, so the sibling curator never runs
  (D3); any other non-retiring fault is still contained (N4).
- `drain._author_and_rotate`: with a `BoxFault` in flight, an exception from
  `_undo_agent_edits` is logged and suppressed and the `BoxFault` propagates; with any other
  fault in flight, today's behaviour stands (D3a).

Every curator scene is `_spec773`'s: a real repo, queue, gate, settle, judge, restore, commit
and rotation; only the spawns, the verifier and the key source are fakes, entering through the
config. A curator is triggered the way `drains._maybe_trigger_author` triggers one, through
`drains._run_curator_module` (whose `(SubprocessError, OSError)` swallow is the hazard D3a
closes), with the channel's own `run_batch(cfg=...)`. The questioner channel ships with no
forward check; where a row needs its repair spawn, one is injected (the thaw sits at
`drain.py`'s call site, which both channels share).

Tests -> obligations:

- D1 / O3, the drain's freeze:
  `test_the_drain_freezes_its_box_before_the_first_curator`,
  `test_a_pause_that_cannot_be_proven_halts_the_drain_before_either_curator`,
  `test_the_drains_default_pause_is_runtime_box_pause_box`,
  `test_the_drains_default_pause_halts_a_box_it_cannot_show_frozen`,
  `test_author_drain_freezes_the_box_it_started_before_either_curator`.
- D2 / O3, each spawn thawed exactly, every host step frozen (pre-state capture, gate, settle,
  the agent-report check, judge, restore, commit, rotation):
  `test_each_spawn_is_thawed_exactly_and_no_host_step_runs_thawed`,
  `test_one_tick_freezes_once_then_thaws_exactly_around_each_spawn_of_both_curators`,
  `test_the_pre_state_is_captured_frozen_before_the_thaw`,
  `test_nothing_but_the_thaw_touches_the_box`.
- D1 + D2 defaults: `test_both_curator_configs_default_their_thaw_to_runtime_box_thawed`,
  `test_the_default_thaw_runs_no_curator_in_a_box_it_cannot_show_running`,
  `test_the_default_seams_hold_the_box_frozen_except_around_each_spawn`.
- D3 / O2: `test_a_box_fault_from_the_first_curators_step_halts_the_drain` (+ its control),
  `test_a_box_fault_in_the_first_curator_halts_the_tick_before_the_second` (spawn, re-freeze
  after a spawn that returned or raised, unproven thaw, and each in the repair window),
  `test_a_box_fault_in_the_second_curator_halts_the_drain`, and
  `test_control_a_non_box_fault_in_the_first_curator_is_contained_and_the_second_runs` (N4).
- D2 / O3 on the fault path: `test_a_failing_spawn_is_refrozen_before_the_undo_runs`.
- D3a / O2: `test_a_box_fault_outranks_an_undo_fault_and_the_second_curator_never_runs`, with
  `test_control_an_undo_fault_still_replaces_a_non_box_fault` (every other in-flight class,
  the systemic ones included).
- O2 through the lane: `test_a_box_fault_escapes_author_drain_with_nothing_delivered` (either
  curator), with `test_control_author_drain_delivers_a_batch_with_no_box_fault`.
- O1: `test_a_process_left_in_the_box_cannot_change_a_judged_lesson`,
  `test_control_with_no_freeze_the_process_races_the_commit` (the race is real),
  `test_what_the_box_writes_before_the_refreeze_is_what_is_judged`.

`pause_box`/`thawed` themselves are in `test_1178_box_pause.py`; the real-box row in
`test_1178_frozen_box.py`.
"""
from __future__ import annotations

import contextlib
import dataclasses
import errno
import inspect
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _git, _io
from defender._io import NotPlainEntry
from defender.learning.author import _config as author_config
from defender.learning.core import drains
from defender._git import GitError
from defender.learning.core.config import FatalConfigError, LoopPaths, StageAbort
from defender.runtime.verbs import RegistryError
from defender.runtime import box as box_mod
from defender.runtime.box import BoxFault
from defender.tests import _spec773 as S
from defender.tests._curator1134 import (
    JournalHeld,
    author_cfg,
    move_out_and_link,
    plant_link,
    put,
    questioner_cfg,
    world,
)
from defender.tests._spec791 import loop_paths, noop_scrub, noop_stop_box
from defender.tests.e2e import _box665 as B
from defender.tests.e2e.test_922_spine import RepoBranch
from defender.tests.test_1178_box_pause import PAUSED, THAWED, DockerShim
from defender.tests.test_1178_thaw_gate import _absent_box, _head_mode
from defender.tests.test_1178_thaw_gate import docker_on_path  # noqa: F401 — a fixture, used by name

CHANNELS = ["lessons", "questioner"]

#: The spawns: each must run inside a thaw, and nothing else may.
SPAWN_KINDS = ("agent", "repair")

#: The repair's rewrite of `a.md`: new bytes, so the judge's memo re-judges it on pass 2.
REPAIRED = S.lesson("f1", body="the lesson, repaired")


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
    fake (which records its own calls), and hands back the inner fake's report as a `Report`."""

    def __init__(self, log: list, kind: str, inner: Callable[..., Any]) -> None:
        self.log, self.kind, self.inner = log, kind, inner

    def __call__(self, *a: Any, **k: Any) -> Any:
        self.log.append((self.kind,))
        return Report(self.log, self.inner(*a, **k))


class Thaw:
    """The injected `cfg.thaw` seam: `thaw(box)` returns a context manager. It records each box
    it is handed and logs `("enter", HEAD, queues)` and `("exit", HEAD, queues)` (queues: the
    bytes of both channels' queue files), so a commit or a rotation made while thawed shows as a
    change between the two. `enter_fault` is raised on the way in (the box could not be shown
    running); `on_enter` runs once in (the box's first writes); `on_exit` runs on the way out,
    still thawed (the box's last writes); `refreeze_fault` is raised after the body, whether it
    returned or raised, as the re-freeze failing does. With `nth`, the two faults are raised by
    the `nth` thaw this seam hands out (from 1) and no other: the repair's is the second."""

    def __init__(self, log: list, repo: Path, queues: tuple[Path, ...] = (), *,  # noqa: PLR0913 — one seam, every fault a row varies
                 on_enter: Callable[[], object] | None = None,
                 on_exit: Callable[[], object] | None = None,
                 enter_fault: BaseException | None = None,
                 refreeze_fault: BaseException | None = None,
                 nth: int | None = None) -> None:
        self.log, self.repo, self.queues = log, repo, queues
        self.on_enter, self.on_exit = on_enter, on_exit
        self.enter_fault, self.refreeze_fault = enter_fault, refreeze_fault
        self.nth = nth
        self.boxes: list[Any] = []

    def __call__(self, box: Any) -> contextlib.AbstractContextManager[None]:
        self.boxes.append(box)
        return self._held(self.nth is None or len(self.boxes) == self.nth)

    def _state(self) -> tuple[str, tuple[bytes | None, ...]]:
        return (_git.git_head_sha(self.repo),
                tuple(q.read_bytes() if q.exists() else None for q in self.queues))

    @contextlib.contextmanager
    def _held(self, faults: bool):
        self.log.append(("enter", *self._state()))
        if faults and self.enter_fault is not None:
            raise self.enter_fault
        if self.on_enter is not None:
            self.on_enter()
        try:
            yield
        finally:
            if self.on_exit is not None:
                self.on_exit()
            self.log.append(("exit", *self._state()))
            if faults and self.refreeze_fault is not None:
                raise self.refreeze_fault


def _windows(log: list) -> list[tuple[int, int]]:
    """Each thaw's `(enter, exit)` indices in `log`, in order."""
    out: list[tuple[int, int]] = []
    start: int | None = None
    for i, entry in enumerate(log):
        if entry[0] == "enter":
            assert start is None, f"a thaw was entered inside another: {_kinds(log)}"
            start = i
        elif entry[0] == "exit":
            assert start is not None, f"a thaw exited that was never entered: {_kinds(log)}"
            out.append((start, i))
            start = None
    assert start is None, f"a thaw never re-froze: {_kinds(log)}"
    return out


def _assert_each_thaw_holds_exactly_its_spawn(log: list, spawns: list[str]) -> list[tuple[int, int]]:
    """One thaw per spawn, in order, each holding its spawn and nothing else; no spawn outside a
    thaw; HEAD and both queues the same at each thaw's exit as at its entry (no commit and no
    rotation ran while the box was thawed). Returns the windows."""
    kinds = _kinds(log)
    windows = _windows(log)
    assert [kinds[a + 1:b] for a, b in windows] == [[s] for s in spawns], (
        f"each thaw must hold exactly its spawn: {kinds}")
    assert sum(k in SPAWN_KINDS for k in kinds) == len(spawns), f"a spawn ran frozen: {kinds}"
    for a, b in windows:
        assert log[b][1] == log[a][1], "HEAD moved while thawed: a commit ran beside a live box"
        assert log[b][2] == log[a][2], (
            "a queue was rewritten while thawed: a rotation ran beside a live box")
    return windows


def _queue_files(paths: LoopPaths) -> tuple[Path, ...]:
    return (paths.findings.file, paths.questioner_findings.file)


def _queued(paths: LoopPaths) -> tuple[bytes | None, ...]:
    return tuple(q.read_bytes() if q.exists() else None for q in _queue_files(paths))


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
        repair: Callable[..., Any] | None = None, thaw: Any = None, journal: bool = True,
        on_place: Callable[[], object] | None = None,
) -> Any:
    """`cfg` (a real builder's) with its spawns logging into `log` (`Spawn`), `verifier` as its
    forward check (none: every pair EXEMPT), and a key source that sources nothing. `journal`:
    the gate, the post-rotation hook, every placement (`tree_for`) and every corpus read, write
    and unlink (`JournalHeld`) log too. `on_place` runs at each placement. `thaw`, when given,
    is injected as `cfg.thaw`."""
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
    if thaw is not None:
        fields["thaw"] = thaw
    return dataclasses.replace(cfg, **fields)


@dataclasses.dataclass
class Tick:
    """One author-drain tick's worktree: the lessons scene's repo, with a questioner queue
    beside the findings one, and each curator's config (`cfgs`, by module name). `trigger` is
    the drain's `trigger_author` seam: it logs `("trigger", module)` and runs that curator the
    way `drains._maybe_trigger_author` does."""

    sc: S.Scene
    log: list
    cfgs: dict[str, Any]
    triggered: list[tuple[str, Any]] = dataclasses.field(default_factory=list)

    @property
    def paths(self) -> LoopPaths:
        return self.sc.paths

    def trigger(self, _paths: LoopPaths, _pending_file: Path, _threshold_env: str,
                module_name: str, _pending_label: str, *, box: Any = None) -> None:
        self.log.append(("trigger", module_name))
        self.triggered.append((module_name, box))
        cfg = self.cfgs[module_name]
        drains._run_curator_module(
            module_name, lambda mod: mod.run_batch(hold_committed=True, cfg=cfg, box=box))

    def modules(self) -> list[str]:
        return [m for m, _ in self.triggered]

    def with_thaws(self, lessons: Any, questioner: Any) -> None:
        """Inject `lessons` as the lessons curator's `cfg.thaw`, `questioner` as the
        questioner's."""
        self.cfgs = {
            "author": dataclasses.replace(self.cfgs["author"], thaw=lessons),
            "questioner_curator": dataclasses.replace(self.cfgs["questioner_curator"],
                                                      thaw=questioner),
        }


def _tick(  # noqa: PLR0913 — one tick's two curators, every seam a row varies
        tmp_path: Path, log: list, *, curator: S.FakeCurator, q_curator: S.FakeCurator,
        verifier: S.FakeVerifier | None = None, repair: Callable[..., Any] | None = None,
        thaw: Any = None, q_thaw: Any = None, seed_corpus: dict[str, str] | None = None,
        q_rows: tuple[str, ...] = ("w1",), journal: bool = False,
        on_place: Callable[[], object] | None = None,
) -> Tick:
    """The lessons curator over `f1` (`curator`, `verifier`, `repair`, `thaw`) and the
    questioner curator over `q_rows` (`q_curator`, no forward check, `q_thaw`), in one
    worktree."""
    sc = S.build_scene(tmp_path, curator=curator, seed_corpus=seed_corpus)
    S.seed(sc.paths.questioner_findings, [S.world_row(i) for i in q_rows])
    lessons = _wire(sc.cfg, log, curator=curator, verifier=verifier, repair=repair, thaw=thaw,
                    journal=journal, on_place=on_place)
    questioner = _wire(questioner_cfg(sc.paths), log, curator=q_curator, thaw=q_thaw,
                       journal=journal)
    return Tick(sc=sc, log=log, cfgs={"author": lessons, "questioner_curator": questioner})


def _questioner_rel(t: Tick, name: str) -> str:
    return (t.paths.lessons_questioner_dir / name).relative_to(t.sc.repo).as_posix()


def _stuck_classes(paths: LoopPaths, channel: str) -> list[str]:
    return [r.get("fault_class") for r in S.stuck_records(getattr(paths, channel))]


# ---------------------------------------------------------------------------------------
# D1: `_drain_curators(..., pause=)` freezes the box before either curator
# ---------------------------------------------------------------------------------------


class Curators:
    """The drain's injected steps, logging into one list: `pause(box)` as `("pause", box)`, each
    curator's trigger as `("trigger", module, box)`. `pause_fault` is raised by the pause after
    it is logged."""

    def __init__(self, *, pause_fault: BaseException | None = None) -> None:
        self.log: list[tuple] = []
        self.pause_fault = pause_fault

    def pause(self, box: Any) -> None:
        self.log.append(("pause", box))
        if self.pause_fault is not None:
            raise self.pause_fault

    def trigger(self, _paths: LoopPaths, _pending_file: Path, _threshold_env: str,
                module_name: str, _pending_label: str, *, box: Any = None) -> None:
        self.log.append(("trigger", module_name, box))


def test_the_drain_freezes_its_box_before_the_first_curator(tmp_path: Path):
    """The first thing the drain does with the box is `pause(box)`, with the very box it was
    handed, once, before either curator; both curators then run with that box."""
    paths = loop_paths(tmp_path)
    steps, box = Curators(), object()
    drains._drain_curators(paths, steps.trigger, box=box, pause=steps.pause)
    assert steps.log == [
        ("pause", box),
        ("trigger", "author", box),
        ("trigger", "questioner_curator", box),
    ]


def test_a_pause_that_cannot_be_proven_halts_the_drain_before_either_curator(tmp_path: Path):
    """`pause` raises `BoxFault`: it propagates out of the drain (the same object), neither
    curator runs, and neither channel records a stuck tick. Control: the row above."""
    paths = loop_paths(tmp_path)
    fault = BoxFault("the box did not report paused")
    steps = Curators(pause_fault=fault)
    with pytest.raises(BoxFault) as got:
        drains._drain_curators(paths, steps.trigger, box=object(), pause=steps.pause)
    assert got.value is fault
    assert [e[0] for e in steps.log] == ["pause"], steps.log
    assert _stuck_classes(paths, "findings") == []
    assert _stuck_classes(paths, "questioner_findings") == []


def test_the_drains_default_pause_is_runtime_box_pause_box():
    default = inspect.signature(drains._drain_curators).parameters["pause"].default
    assert default is box_mod.pause_box


@pytest.mark.usefixtures("docker_on_path")
def test_the_drains_default_pause_halts_a_box_it_cannot_show_frozen(tmp_path: Path):
    """`_drain_curators` with its own `pause`, handed a sandboxed box naming no container: the
    real `pause_box` cannot prove it frozen, so `BoxFault`, and no curator is triggered."""
    paths = loop_paths(tmp_path)
    steps = Curators()
    with pytest.raises(BoxFault):
        drains._drain_curators(paths, steps.trigger, box=_absent_box())
    assert steps.log == [], "a curator ran beside a box never shown frozen"


def test_author_drain_freezes_the_box_it_started_before_either_curator(
        tmp_path: Path, monkeypatch):
    """`author_drain` as production wires it (its own `_drain_curators` call; the trigger, the
    branch and the box lifecycle injected), its box the shim's running container: the shim logs
    one proven freeze before either curator is triggered, and nothing else; the box ends
    paused."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    paths = loop_paths(tmp_path)
    S.seed(paths.findings, [S.finding_row("f1", run_id="f1")])
    shim = DockerShim(tmp_path, monkeypatch)
    box = shim.box()
    started: list[Any] = []

    def start_box(request: Any, *_a: Any, **_kw: Any) -> Any:
        started.append(request)
        return box

    def trigger(_paths: LoopPaths, _file: Path, _env: str, module_name: str, _label: str, *,
                box: Any = None) -> None:
        shim.mark(module_name)

    rc = drains.author_drain(
        paths, trigger_author=trigger, branch=B.RecordingBranch(tmp_path / "worktrees"),
        start_box=start_box, stop_box=noop_stop_box, scrub=noop_scrub,
    )
    assert rc == 0
    assert len(started) == 1, "the drain never started its box"
    assert shim.steps() == [*PAUSED, "author", "questioner_curator"]
    assert shim.state() == "paused"


# ---------------------------------------------------------------------------------------
# D2 / O3: each spawn is thawed exactly; no host step runs thawed
# ---------------------------------------------------------------------------------------


def _segments(log: list, windows: list[tuple[int, int]]) -> list[list[tuple]]:
    """The log split around the thaws: before the first, between each pair, after the last."""
    bounds = [-1, *[i for w in windows for i in w], len(log)]
    return [log[bounds[i] + 1:bounds[i + 1]] for i in range(0, len(bounds), 2)]


@pytest.mark.parametrize("repair", [False, True], ids=["judged-clean", "repaired"])
@pytest.mark.parametrize("channel", CHANNELS)
def test_each_spawn_is_thawed_exactly_and_no_host_step_runs_thawed(
        tmp_path: Path, channel: str, repair: bool):
    """Through the channel's `run_batch(cfg=<thaw injected>, box=<sentinel>)`: the curator
    leaves `a.md` (citing f1), `b.md` (citing f2) and a non-`.md` stray, and skips f3. With
    every verdict GOOD, one thaw holds the curator spawn and nothing else. With `a.md` BAD then
    GOOD and `b.md` BAD throughout, a second thaw holds the repair spawn (which rewrites `a.md`
    and leaves a stray of its own) and nothing else. Each thaw is handed the sentinel box.

    Every host step is seen outside a thaw: the gate and the key source before the first; the
    settle's put-back of each spawn's stray, the report reads, the corpus reads and the judge
    after each; the restore of the unapproved `b.md`, the commit's placements and the
    post-rotation hook after the last. HEAD and both queues are unchanged across each thaw, and
    both moved by the end of the tick."""
    log: list = []
    curator = S.FakeCurator(
        writes={"a.md": S.lesson("f1"), "b.md": S.lesson("f2"), "stray.txt": "not a lesson\n"},
        committed=["f1", "f2"], consumed_skip=[{"finding_id": "f3", "reason": "dup"}],
    )
    sc = _channel_scene(tmp_path, channel, rows=_rows(channel, "f1", "f2", "f3"), curator=curator)
    fixer = S.FakeRepair(writes={"a.md": REPAIRED, "repair-stray.txt": "not a lesson\n"})
    verdicts = {"a.md": ["BAD", "GOOD"], "b.md": "BAD"} if repair else {}
    thaw = Thaw(log, sc.repo, _queue_files(sc.paths))
    sc.cfg = _wire(sc.cfg, log, curator=curator, verifier=_verifier(log, verdicts), repair=fixer,
                   thaw=thaw)
    queued_before = _queued(sc.paths)
    box = object()

    assert sc.run(box=box) == 0

    spawns = ["agent", "repair"] if repair else ["agent"]
    windows = _assert_each_thaw_holds_exactly_its_spawn(log, spawns)
    assert thaw.boxes == [box] * len(spawns), thaw.boxes
    assert fixer.spawned == (1 if repair else 0)
    segments = _segments(log, windows)
    before, after_spawn, after_last = segments[0], segments[1], segments[-1]
    assert {"gate", "key"} <= set(_kinds(before)), _kinds(before)
    stray = ("tree_for", str(sc.corpus / "stray.txt"))
    assert stray in after_spawn, "the settle after the curator spawn was not seen frozen"
    assert {"report", "read", "judge"} <= set(_kinds(after_spawn)), _kinds(after_spawn)
    assert ("tree_for", str(sc.corpus / "a.md")) in after_last, "the commit was not seen frozen"
    assert "post_rotate" in _kinds(after_last)
    if repair:
        assert ("tree_for", str(sc.corpus / "repair-stray.txt")) in after_last
        assert "judge" in _kinds(after_last)
        assert ("unlink", "b.md") in after_last, "the restore of b.md was not seen frozen"
        assert sc.head_text(_rel(sc, "a.md")) == REPAIRED
        assert sc.head_text(_rel(sc, "b.md")) is None
    else:
        assert sc.head_text(_rel(sc, "a.md")) == S.lesson("f1")
        assert sc.head_text(_rel(sc, "b.md")) == S.lesson("f2")
    assert sc.head_sha() != sc.base_sha
    assert _queued(sc.paths) != queued_before


def test_one_tick_freezes_once_then_thaws_exactly_around_each_spawn_of_both_curators(
        tmp_path: Path):
    """The design's key flow, through `_drain_curators(..., pause=<recording>)` and both real
    curators sharing one injected thaw: one pause, with the drain's box, before the first
    trigger and every host step of either curator; then exactly three thaws, each handed that
    box: the lessons curator, its repair, the questioner curator. HEAD holds both curators'
    lessons."""
    log: list = []
    box = object()
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")})
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})

    def pause(b: Any) -> None:
        log.append(("pause", b))

    t = _tick(tmp_path, log, curator=curator, q_curator=q_curator,
              verifier=_verifier(log, {"a.md": ["BAD", "GOOD"]}),
              repair=S.FakeRepair(writes={"a.md": REPAIRED}), journal=True)
    thaw = Thaw(log, t.sc.repo, _queue_files(t.paths))
    t.with_thaws(thaw, thaw)

    drains._drain_curators(t.paths, t.trigger, box=box, pause=pause)

    kinds = _kinds(log)
    assert kinds.count("pause") == 1, kinds
    assert log[0] == ("pause", box), kinds[:3]
    assert t.modules() == ["author", "questioner_curator"]
    _assert_each_thaw_holds_exactly_its_spawn(log, ["agent", "repair", "agent"])
    assert thaw.boxes == [box, box, box], thaw.boxes
    assert t.sc.head_text(_rel(t.sc, "a.md")) == REPAIRED
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


#: A committed file outside both corpora: the box's write there once thawed is a stray only if
#: the tick took its baseline of strays before the thaw.
STRAY_REL = "defender/notes/stray1195.md"
STRAY_EDIT = "rewritten by the box\n"


@pytest.mark.parametrize("when", ["once-thawed", "before-the-run"])
@pytest.mark.parametrize("channel", CHANNELS)
def test_the_pre_state_is_captured_frozen_before_the_thaw(
        tmp_path: Path, channel: str, when: str):
    """The box rewrites a committed file outside the corpus as soon as it is thawed: the settle
    refuses the tick (an `AuthorError` naming it, which retires: rc 2, f1 bumped, a stuck record
    naming the stray), HEAD unchanged, the stray put back. The baseline of strays was captured
    while the box was frozen, before the thaw, so the rewrite is new. Control: the same rewrite
    already standing before the run is in the baseline, and the tick commits."""
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
    thaw = Thaw(log, sc.repo,
                on_enter=(lambda: put(stray, STRAY_EDIT)) if when == "once-thawed" else None)
    sc.cfg = _wire(sc.cfg, log, curator=curator, thaw=thaw, journal=False)

    rc = sc.run(box=object())

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


@pytest.mark.parametrize("channel", CHANNELS)
def test_nothing_but_the_thaw_touches_the_box(tmp_path: Path, channel: str):
    """The thaw injected (it does nothing), the box a sandboxed one naming no container: the
    tick commits. Anything else in the tick that asked docker about the box (a freeze around the
    judge, a pause before the commit) would raise `BoxFault` here."""
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")})
    sc = _channel_scene(tmp_path, channel, rows=_rows(channel, "f1"), curator=curator)
    log: list = []
    thaw = Thaw(log, sc.repo)
    sc.cfg = _wire(sc.cfg, log, curator=curator, thaw=thaw, journal=False)
    box = _absent_box()

    assert sc.run(box=box) == 0
    assert thaw.boxes == [box]
    assert sc.head_text(_rel(sc, "a.md")) == S.lesson("f1")


# ---------------------------------------------------------------------------------------
# D1 + D2: the default seams are the real `pause_box` / `thawed`
# ---------------------------------------------------------------------------------------


def test_both_curator_configs_default_their_thaw_to_runtime_box_thawed(tmp_path: Path):
    """The base config's `thaw` defaults to `runtime.box.thawed`, and both builders leave it
    there."""
    fields = {f.name: f for f in dataclasses.fields(author_config.CorpusAuthorConfig)}
    assert fields["thaw"].default is box_mod.thawed
    w = world(tmp_path)
    assert author_cfg(w.paths, trees=w.trees).thaw is box_mod.thawed
    assert questioner_cfg(w.paths, trees=w.trees).thaw is box_mod.thawed


@pytest.mark.usefixtures("docker_on_path")
@pytest.mark.parametrize("channel", CHANNELS)
def test_the_default_thaw_runs_no_curator_in_a_box_it_cannot_show_running(
        tmp_path: Path, channel: str):
    """The channel's `run_batch(box=<sandboxed, no such container>)` with the builder's own
    thaw: the real `thawed` cannot prove the box running, so `BoxFault` before the curator is
    called; HEAD unchanged, f1 not bumped."""
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")})
    sc = _channel_scene(tmp_path, channel, rows=_rows(channel, "f1"), curator=curator)
    with pytest.raises(BoxFault):
        sc.run(box=_absent_box())
    assert curator.calls == [], "the curator ran in a box never shown running"
    assert sc.head_files() == []
    assert sc.pending_by_id()["f1"].get("attempts") is None


def test_the_default_seams_hold_the_box_frozen_except_around_each_spawn(
        tmp_path: Path, monkeypatch):
    """`_drain_curators` with its own `pause`, both curators with their builders' own thaw, over
    the shim's running container: the shim logs one proven freeze, then for each spawn (the
    lessons curator, its repair, the questioner curator) one proven thaw, the spawn and one
    proven freeze, and nothing else; the box ends paused, and both curators committed."""
    shim = DockerShim(tmp_path, monkeypatch)
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")},
                            also=lambda *_a: shim.mark("curator"))
    repair = S.FakeRepair(writes={"a.md": REPAIRED}, also=lambda *_a: shim.mark("repair"))
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")},
                              also=lambda *_a: shim.mark("questioner"))
    t = _tick(tmp_path, [], curator=curator, q_curator=q_curator,
              verifier=S.FakeVerifier(verdicts={"a.md": ["BAD", "GOOD"]}), repair=repair)

    drains._drain_curators(t.paths, t.trigger, box=shim.box())

    assert curator.calls, "the lessons curator never ran"
    assert repair.calls, "the repair never ran"
    assert q_curator.calls, "the questioner curator never ran"
    assert shim.steps() == [*PAUSED, *THAWED, "curator", *PAUSED, *THAWED, "repair", *PAUSED,
                            *THAWED, "questioner", *PAUSED]
    assert shim.state() == "paused"
    assert t.sc.head_text(_rel(t.sc, "a.md")) == REPAIRED
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


# ---------------------------------------------------------------------------------------
# D3 / O2: a box fault in the first curator halts the tick
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
    exc: BaseException = BoxFault("re-freeze failed") if fault == "BoxFault" else RuntimeError("x")
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
#: - `spawn`: the curator spawn itself raises it, after leaving its lesson;
#: - `refreeze`: the thaw's re-freeze, after the spawn returned;
#: - `thaw-unproven`: the thaw's way in, before the spawn;
#: - `refreeze-over-a-failing-spawn`: the spawn raises `RuntimeError` and the re-freeze on that way
#:   out fails too (a thaw that re-freezes only on success loses this one);
#: - `repair-spawn` / `repair-refreeze` / `repair-unproven`: the same three in the repair window
#:   (the lessons verdict BAD on pass 1, so the repair runs; its thaw is the second).
FIRST_CURATOR_SOURCES = ["spawn", "refreeze", "thaw-unproven", "refreeze-over-a-failing-spawn",
                         "repair-spawn", "repair-refreeze", "repair-unproven"]
SECOND_CURATOR_SOURCES = ["spawn", "refreeze", "thaw-unproven", "refreeze-over-a-failing-spawn"]


@dataclasses.dataclass
class Faulted:
    """A tick one of whose curators meets a `BoxFault`, and its fakes. `thaw` is the faulting
    curator's (`None` when the fault is the spawn's own and no thaw is injected)."""

    t: Tick
    curator: S.FakeCurator
    q_curator: S.FakeCurator
    verifier: S.FakeVerifier
    repair: S.FakeRepair
    thaw: Thaw | None


def _box_fault_scene(  # noqa: PLR0913 — one tick, every fault a row varies
        tmp_path: Path, source: str, fault: BoxFault, *, in_curator: str = "author",
        seed_corpus: dict[str, str] | None = None, plant: Callable[..., None] | None = None,
) -> Faulted:
    """A tick whose lessons curator leaves `a.md` (citing f1) and whose questioner curator leaves
    `q.md` (citing w1), each committing it unless something faults. The curator `in_curator`
    meets `fault` from `source` (`FIRST_CURATOR_SOURCES`), after running `plant` (the box's own
    act) in its spawn. The other curator's thaw, when one is injected, holds."""
    log: list = []
    spawn_fault = {"spawn": fault,
                   "refreeze-over-a-failing-spawn": RuntimeError("the agent crashed")}.get(source)

    def act(rows: Any, batch_id: str, cfg: Any) -> None:
        if plant is not None:
            plant(rows, batch_id, cfg)
        if spawn_fault is not None:
            raise spawn_fault

    first = in_curator == "author"
    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=act if first else None)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")}, also=None if first else act)
    repairing = source.startswith("repair-")
    verifier = S.FakeVerifier(verdicts={"a.md": ["BAD", "GOOD"]} if repairing else {})
    repair = S.FakeRepair(writes={"a.md": REPAIRED}, raise_after_writes=True,
                          raises=fault if source == "repair-spawn" else None)
    t = _tick(tmp_path, log, curator=curator, q_curator=q_curator, verifier=verifier,
              repair=repair, seed_corpus=seed_corpus)
    thaw = None
    if source not in ("spawn", "repair-spawn"):
        unproven = source.endswith("unproven")
        thaw = Thaw(log, t.sc.repo, enter_fault=fault if unproven else None,
                    refreeze_fault=None if unproven else fault, nth=2 if repairing else None)
        holding = Thaw(log, t.sc.repo)
        t.with_thaws(*((thaw, holding) if first else (holding, thaw)))
    return Faulted(t=t, curator=curator, q_curator=q_curator, verifier=verifier, repair=repair,
                   thaw=thaw)


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
    """Through `_drain_curators` and both real curators: a `BoxFault` in the lessons curator, from
    its spawn, its thaw's re-freeze (after a spawn that returned or one that raised), a thaw that
    cannot be proven before the spawn, or the same three in the repair window, escapes the drain
    (the same object). The questioner curator is never triggered, nothing is committed, f1 is
    not bumped and its stuck record names `BoxFault`; the curator's lesson is undone. With a
    thaw unproven, its spawn is never called; after a repair-window fault, nothing is judged
    again."""
    fault = BoxFault("the box did not report paused after the spawn")
    f = _box_fault_scene(tmp_path, source, fault)
    t = f.t
    q_queued = _queued(t.paths)[1]
    box = B.FakeBox(name="box-1195")

    with pytest.raises(BoxFault) as got:
        drains._drain_curators(t.paths, t.trigger, box=box)

    assert got.value is fault
    _assert_halted_after_the_first_curator(t, f.q_curator, q_queued)
    assert len(f.curator.calls) == (0 if source == "thaw-unproven" else 1)
    assert not (t.sc.corpus / "a.md").exists(), "the curator's lesson was not undone"
    if source.startswith("repair-"):
        assert len(f.repair.calls) == (0 if source == "repair-unproven" else 1)
        assert f.verifier.texts_for("a.md") == [S.lesson("f1")], (
            "the tree was judged again after the repair's box fault")
    else:
        assert f.repair.calls == []
    if f.thaw is not None:
        assert f.thaw.boxes == [box] * (2 if source.startswith("repair-") else 1)


@pytest.mark.parametrize("source", SECOND_CURATOR_SOURCES)
def test_a_box_fault_in_the_second_curator_halts_the_drain(tmp_path: Path, source: str):
    """The same faults in the questioner curator, which runs second: its `BoxFault` escapes
    `_drain_curators` too (the same object), so `finish_batch` is never reached. The lessons
    curator's commit stands; the questioner's lesson is undone, w1 is not bumped and its stuck
    record names `BoxFault`."""
    fault = BoxFault("the box did not report paused after the questioner's spawn")
    f = _box_fault_scene(tmp_path, source, fault, in_curator="questioner_curator")

    with pytest.raises(BoxFault) as got:
        drains._drain_curators(f.t.paths, f.t.trigger, box=B.FakeBox(name="box-1195"))

    assert got.value is fault
    _assert_halted_in_the_second_curator(f.t)
    assert len(f.q_curator.calls) == (0 if source == "thaw-unproven" else 1)


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
    before. `_drain_curators` returns, the questioner curator runs and commits, and the findings
    channel's stuck record names the fault (f1 bumped only by the retiring `GitError`)."""
    log: list = []

    def boom(*_a: Any) -> None:
        raise _not_a_box_fault(fault, "not a box fault")

    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=boom)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, log, curator=curator, q_curator=q_curator)

    drains._drain_curators(t.paths, t.trigger, box=B.FakeBox(name="box-1195"))

    assert t.modules() == ["author", "questioner_curator"]
    assert len(q_curator.calls) == 1
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")
    assert t.sc.head_text(_rel(t.sc, "a.md")) is None
    assert _stuck_classes(t.paths, "findings") == [fault.__name__]
    assert t.sc.pending_by_id()["f1"].get("attempts") == (1 if fault is GitError else None)


def test_a_failing_spawn_is_refrozen_before_the_undo_runs(tmp_path: Path):
    """The lessons spawn leaves `a.md` and raises `RuntimeError`: its thaw still exits on that
    way out (the window holds the spawn alone), and the undo's removal of `a.md` through the
    corpus mount runs after the exit, frozen. The contained fault lets the questioner curator
    run, in a window of its own."""
    log: list = []

    def boom(*_a: Any) -> None:
        raise RuntimeError("the agent crashed")

    curator = S.FakeCurator(writes={"a.md": S.lesson("f1")}, also=boom)
    q_curator = S.FakeCurator(writes={"q.md": S.lesson("w1")})
    t = _tick(tmp_path, log, curator=curator, q_curator=q_curator, journal=True)
    thaw = Thaw(log, t.sc.repo)
    t.with_thaws(thaw, thaw)

    drains._drain_curators(t.paths, t.trigger, box=B.FakeBox(name="box-1195"))

    windows = _assert_each_thaw_holds_exactly_its_spawn(log, ["agent", "agent"])
    first_exit, second_enter = windows[0][1], windows[1][0]
    undo = [i for i, e in enumerate(log) if e == ("unlink", "a.md")]
    assert undo, "the undo never removed the failed spawn's lesson through the corpus mount"
    assert all(first_exit < i < second_enter for i in undo), (
        "the undo ran beside a thawed box")
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


# ---------------------------------------------------------------------------------------
# D3a / O2: the box fault outranks the undo's own fault
# ---------------------------------------------------------------------------------------

#: The holding folder the box swaps for a link on its way out: the undo's write-back of
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


@pytest.mark.parametrize("source", ["spawn", "refreeze"])
def test_a_box_fault_outranks_an_undo_fault_and_the_second_curator_never_runs(
        tmp_path: Path, caplog, source: str):
    """The box swaps the corpus folder `sub/` (holding a committed lesson) for a link, then the
    box faults (the spawn raises `BoxFault`, or the thaw's re-freeze does). The undo's write-back
    of `sub/lesson.md` raises `OSError(ELOOP)`; with a `BoxFault` in flight that is logged and
    suppressed, so the `BoxFault` (the same object) escapes `_drain_curators` rather than an
    `OSError` that `_run_curator_module` would swallow. The questioner curator never runs,
    nothing commits, f1 is not bumped, and its stuck record names `BoxFault`. Control: the next
    row."""
    caplog.set_level(logging.WARNING)
    fault = BoxFault("the box did not report paused after the spawn")
    f = _box_fault_scene(tmp_path, source, fault, seed_corpus=SEEDED_SUB,
                         plant=_swap_sub_for_a_link(tmp_path / "outside" / "moved-sub"))
    q_queued = _queued(f.t.paths)[1]

    with pytest.raises(BoxFault) as got:
        drains._drain_curators(f.t.paths, f.t.trigger, box=B.FakeBox(name="box-1195"))

    assert got.value is fault
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

    drains._drain_curators(t.paths, t.trigger, box=B.FakeBox(name="box-1195"))

    assert _stuck_classes(t.paths, "findings") == ["OSError"]
    assert t.sc.pending_by_id()["f1"].get("attempts") is None
    assert t.modules() == ["author", "questioner_curator"]
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


# ---------------------------------------------------------------------------------------
# O2 through the lane: the box fault escapes `do_work`, so nothing is delivered
# ---------------------------------------------------------------------------------------

#: `(source, the curator it faults in)`: each first-curator source, the repair window's
#: re-freeze, a re-freeze over an undo that faults too, and the second curator's re-freeze.
LANE_FAULTS = [
    pytest.param("spawn", "author", id="spawn"),
    pytest.param("refreeze", "author", id="refreeze"),
    pytest.param("refreeze-over-a-failing-spawn", "author", id="refreeze-over-a-failing-spawn"),
    pytest.param("repair-refreeze", "author", id="repair-refreeze"),
    pytest.param("refreeze-over-an-undo-fault", "author", id="refreeze-over-an-undo-fault"),
    pytest.param("refreeze", "questioner_curator", id="second-curator-refreeze"),
]


def _run_author_drain(t: Tick) -> tuple[Callable[[], int], list[str]]:
    rec = B.BoxLifecycleRecorder()
    branch = RepoBranch(t.sc.repo, events=rec.events)

    def run() -> int:
        return drains.author_drain(t.paths, trigger_author=t.trigger, branch=branch,
                                   start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub)

    return run, rec.events


def test_control_author_drain_delivers_a_batch_with_no_box_fault(tmp_path: Path, monkeypatch):
    """The lane rows' control: the same tick, nothing faults, both injected thaws hold. Both
    curators commit and `finish_batch` delivers the batch."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    log: list = []
    t = _tick(tmp_path, log, curator=S.FakeCurator(writes={"a.md": S.lesson("f1")}),
              q_curator=S.FakeCurator(writes={"q.md": S.lesson("w1")}))
    t.with_thaws(Thaw(log, t.sc.repo), Thaw(log, t.sc.repo))
    run, events = _run_author_drain(t)

    assert run() == 0
    assert t.modules() == ["author", "questioner_curator"]
    assert any(e.startswith("finish_batch:") for e in events), events
    assert t.sc.head_text(_rel(t.sc, "a.md")) == S.lesson("f1")
    assert t.sc.head_text(_questioner_rel(t, "q.md")) == S.lesson("w1")


@pytest.mark.parametrize(("source", "in_curator"), LANE_FAULTS)
def test_a_box_fault_escapes_author_drain_with_nothing_delivered(
        tmp_path: Path, monkeypatch, source: str, in_curator: str):
    """`author_drain` over the real worktree (the trigger, the branch and the box lifecycle
    injected): a `BoxFault` in either curator escapes `author_drain` (the same object). The box
    is torn down and the tree scrubbed, the worktree cleaned up, but `finish_batch` (push and PR)
    never runs. In the first curator: the second is never triggered, nothing is committed, f1 is
    not bumped. In the second: its lesson is undone and w1 not bumped. Control: the row above."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    fault = BoxFault("the box did not report paused after the spawn")
    undo_fault = source == "refreeze-over-an-undo-fault"
    f = _box_fault_scene(
        tmp_path, "refreeze" if undo_fault else source, fault, in_curator=in_curator,
        seed_corpus=SEEDED_SUB if undo_fault else None,
        plant=_swap_sub_for_a_link(tmp_path / "outside" / "moved-sub") if undo_fault else None)
    q_queued = _queued(f.t.paths)[1]
    run, events = _run_author_drain(f.t)

    with pytest.raises(BoxFault) as got:
        run()

    assert got.value is fault
    assert not any(e.startswith("finish_batch:") for e in events), events
    assert any(e.startswith("stop:") for e in events), events
    assert any(e.startswith("scrub:") for e in events), events
    assert "cleanup" in events, events
    if in_curator == "author":
        _assert_halted_after_the_first_curator(f.t, f.q_curator, q_queued)
    else:
        _assert_halted_in_the_second_curator(f.t)


# ---------------------------------------------------------------------------------------
# O1: a process left in the box cannot change a judged lesson
# ---------------------------------------------------------------------------------------


class SimBox:
    """A box as the lane drives it, simulated: running (as `start_box` hands it back) or
    frozen, and the processes the spawns left in it. `pause`/`thaw` are its injected freeze;
    `sandboxed` is false, so the real `pause_box`/`thawed` leave it alone (the race control).

    A process gets its turn whenever the host asks a placement (`cfg.tree_for`), which the tick
    first does for the commit, after the judge: the schedule on which a live process beats the
    commit. A frozen box's processes do not run; `blocked` counts the turns they lost. With
    `act_at_refreeze`, they also get a turn on the thaw's way out, while still thawed."""

    sandboxed = False
    name = "sim-box-1195"

    def __init__(self, *, act_at_refreeze: bool = False) -> None:
        self.running = True
        self.processes: list[Callable[[], None]] = []
        self.acts: list[str] = []
        self.blocked = 0
        self.act_at_refreeze = act_at_refreeze

    def pause(self, box: Any) -> None:
        assert box is self, "the drain froze some other box"
        self.running = False

    def thaw(self, box: Any) -> contextlib.AbstractContextManager[None]:
        assert box is self, "a spawn thawed some other box"
        return self._window()

    @contextlib.contextmanager
    def _window(self):
        self.running = True
        try:
            yield
        finally:
            if self.act_at_refreeze:
                self.turn()
            self.running = False

    def turn(self) -> None:
        if not self.processes:
            return
        if not self.running:
            self.blocked += 1
            return
        for process in list(self.processes):
            process()


#: What the spawn leaves at `a.md`, and what the verifier judges.
SPAWNED = S.lesson("f1", body="the lesson the verifier judged")
#: What the process left in the box writes there: it cites f1 too, so it would pass every rule
#: the commit applies without a verifier.
EVIL = S.lesson("f1", body="rewritten by a process the spawn left behind")
#: What the process writes while the box is still thawed: judged like anything else.
VARIANT = S.lesson("f1", body="rewritten while the box was still thawed")


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

        box.processes.append(writer)

    return leave


def _o1_tick(tmp_path: Path, box: SimBox, writes: str, *, frozen: bool) -> tuple[Tick, S.FakeVerifier]:
    curator = S.FakeCurator(writes={"a.md": SPAWNED},
                            also=_leave_a_writer(box, writes, tmp_path / "outside"))
    verifier = S.FakeVerifier()
    t = _tick(tmp_path, [], curator=curator, q_curator=S.FakeCurator(), verifier=verifier,
              thaw=box.thaw if frozen else None, q_thaw=box.thaw if frozen else None,
              q_rows=(), on_place=box.turn)
    return t, verifier


@pytest.mark.parametrize("writes", ["rewrite", "symlink"])
def test_a_process_left_in_the_box_cannot_change_a_judged_lesson(tmp_path: Path, writes: str):
    """`_drain_curators(..., pause=<the box's freeze>)`, the lessons curator thawed by the box's
    own thaw: the spawn leaves `a.md` and a process that would replace it (new bytes, or a
    symlink) at the commit's placement, after the judge. The box is frozen then, so the process
    loses its turn and HEAD holds the bytes the verifier judged, as a plain file. Control: the
    next row, where the same process wins with no freeze."""
    box = SimBox()
    t, verifier = _o1_tick(tmp_path, box, writes, frozen=True)

    drains._drain_curators(t.paths, t.trigger, box=box, pause=box.pause)

    assert verifier.texts_for("a.md") == [SPAWNED]
    assert box.blocked >= 1, "the process never had a turn after the judge, so the freeze is untested"
    assert box.acts == [], "a process ran in a box that should have been frozen"
    assert t.sc.head_text(_rel(t.sc, "a.md")) == SPAWNED
    assert _head_mode(t.sc.repo, _rel(t.sc, "a.md")) == "100644"


@pytest.mark.parametrize("writes", ["rewrite", "symlink"])
def test_control_with_no_freeze_the_process_races_the_commit(tmp_path: Path, writes: str):
    """The same tick with no freeze (the default seams leave this unsandboxed box alone, so it
    runs throughout): the process acts at the commit's placement, after the judge, and HEAD holds
    what it wrote (a symlink commits as one), which the verifier never saw. The race the freeze
    closes is real against this machinery."""
    box = SimBox()
    t, verifier = _o1_tick(tmp_path, box, writes, frozen=False)

    drains._drain_curators(t.paths, t.trigger, box=box)

    assert verifier.texts_for("a.md") == [SPAWNED]
    assert box.acts == [writes]
    if writes == "symlink":
        assert _head_mode(t.sc.repo, _rel(t.sc, "a.md")) == "120000"
    else:
        assert t.sc.head_text(_rel(t.sc, "a.md")) == EVIL


def test_what_the_box_writes_before_the_refreeze_is_what_is_judged(tmp_path: Path):
    """The process acts on the thaw's way out, while the box still runs: the settle and the judge
    come after the re-freeze, so the verifier judges what it wrote, and that is what HEAD holds."""
    box = SimBox(act_at_refreeze=True)
    t, verifier = _o1_tick(tmp_path, box, "variant", frozen=True)

    drains._drain_curators(t.paths, t.trigger, box=box, pause=box.pause)

    assert box.acts == ["variant"]
    assert verifier.texts_for("a.md") == [VARIANT]
    assert t.sc.head_text(_rel(t.sc, "a.md")) == VARIANT
