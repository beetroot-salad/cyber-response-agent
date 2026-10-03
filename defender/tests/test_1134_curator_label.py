"""#1134 v2 curator step: the drain label is consumed where the author lane's trees open, the open
`DrainTrees` flows below that, and the trees live exactly as long as one curator's batch.

The shape (the v2 contract's "Shape", mirroring the lead-author step; owner decisions of
2026-09-29: the label is required all the way to where it is read, spelled once as
`config.AUTHOR_DRAIN_LABEL`):

- `author_drain`'s DEFAULT work-step seam is `functools.partial(drains._maybe_trigger_author,
  label=AUTHOR_DRAIN_LABEL)`; an injected `trigger_author` keeps its call shape.
- `_maybe_trigger_author(paths, pending_file, threshold_env, module_name, pending_label, *,
  label, box=None)` requires the label; past the threshold check it opens `open_drain_trees(paths,
  label)` AROUND `_run_curator_module` (so a hold fault propagates to `_drain_one_curator`'s stuck
  record, never rc=None) and hands the curator `run_batch(..., trees=trees, ...)`. Each curator
  opens its own trees (both corpora, the label's whole mount list); closed when its batch returns
  or raises. Below the threshold nothing is held.
- `build_author_config` / `build_questioner_config(paths, *, trees, ...)` require the trees and set
  `corpus = shared.lane_corpus(trees, <corpus dir>)` (`trees.mount(...)`, its `ValueError` ->
  `FatalConfigError`; never a handle of its own) and `tree_for = trees.tree_for`. The channel
  `run_batch(*, ..., trees=None, cfg=None, ...)` takes exactly one of the two (`TypeError`
  otherwise). Nothing below the open takes a label.
- Both channel `main()`s and the eval harness's `run_author` open the trees themselves, with the
  constant. Nothing else in the curator modules holds or binds a tree (H5/H7).

The trees' lifetime is observed from inside the curator's batch: a `LoopPaths` subclass handed to
the seam records what this process holds under the repo (`descriptors_under`) when the builder
reads `author_lock_file`, which it does only after the open. Faults enter as exceptions raised
from that same property; nothing is monkeypatched but the environment (the thresholds).

Red before the step: `_maybe_trigger_author` takes no `label`, the builders and `run_batch` take
no `trees`, `shared.lane_corpus` is missing, the default seam is the bare function, and the
channel `main()`s / the harness open nothing.
"""
from __future__ import annotations

import ast
import inspect
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender import _corpus, _io
from defender.learning.author import drain
from defender.learning.author import _config as author_config
from defender.learning.author import shared as author_shared
from defender.learning.author.lessons import run as lessons_run
from defender.learning.author.questioner import run as questioner_run
from defender.learning.core import drains, lane_trees
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL,
    LEAD_AUTHOR_DRAIN_LABEL,
    FatalConfigError,
    LoopPaths,
)
from defender._tree_listing import entry_kind
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees
from defender.tests._by_path import import_lint_lib
from defender.tests._curator1134 import (
    is_link_to,
    leaf_refusal,
    plant_link,
    put,
    world,
)
from defender.tests._drain719 import finding_row, make_repo, pending, seed, stuck_records
from defender.tests.e2e import _box665 as B
from defender.tests.e2e.test_922_spine import RepoBranch
from defender.tests._tree_listing_1134 import descriptors_under

BUILDERS = {
    "lessons": (lessons_run.build_author_config, "lessons_dir"),
    "questioner": (questioner_run.build_questioner_config, "lessons_questioner_dir"),
}
RUNNERS = {"lessons": lessons_run.run_batch, "questioner": questioner_run.run_batch}
CHANNEL_MODULES = {"lessons": lessons_run, "questioner": questioner_run}
astlib = import_lint_lib("_astlib")


# ---------------------------------------------------------------------------------------
# The trees are required below the open; exactly one of trees / cfg reaches run_batch
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_the_builders_require_the_trees_and_take_their_mounts(tmp_path, channel):
    """`build_author_config` / `build_questioner_config` refuse a call without `trees`
    (`TypeError`, no default). With them, `cfg.corpus` IS `trees.mount(cfg.corpus_dir)` (the held
    mount itself, no second hold), `cfg.corpus_dir` is the corpus's spelling, and `cfg.tree_for`
    is the trees' own bound lookup."""
    w = world(tmp_path)
    build, attr = BUILDERS[channel]

    with pytest.raises(TypeError):
        build(w.paths)

    cfg = build(w.paths, trees=w.trees)
    assert cfg.corpus_dir == getattr(w.paths, attr)
    assert cfg.corpus is w.trees.mount(cfg.corpus_dir)
    assert cfg.tree_for == w.trees.tree_for


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_run_batch_takes_exactly_one_of_trees_and_cfg(tmp_path, channel):
    """The channel `run_batch` takes exactly one of `trees` (it builds its config from them) and
    `cfg` (used as is: it carries the `Held` and `tree_for`): neither, or both, is a `TypeError`
    (always over the test's own paths, never `DEFAULT_PATHS`). The positive controls: each one
    alone serves an empty queue (rc 0)."""
    w = world(tmp_path)
    build, _attr = BUILDERS[channel]
    run = RUNNERS[channel]
    cfg = build(w.paths, trees=w.trees)

    with pytest.raises(TypeError):
        run(paths=w.paths)
    with pytest.raises(TypeError):
        run(paths=w.paths, trees=w.trees, cfg=cfg)

    assert run(paths=w.paths, trees=w.trees) == 0
    assert run(cfg=cfg) == 0


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_nothing_below_the_open_takes_a_label(channel):
    """H8: the label is consumed where the trees open. The builders, the channel `run_batch`es and
    `drain.run_batch` have no `label` parameter (passing one further would be required-but-unread,
    v1's H5); the builders' `trees` is keyword-only with no default."""
    build, _attr = BUILDERS[channel]
    for fn in (build, RUNNERS[channel], drain.run_batch):
        assert "label" not in inspect.signature(fn).parameters, fn
    trees = inspect.signature(build).parameters["trees"]
    assert trees.kind is inspect.Parameter.KEYWORD_ONLY
    assert trees.default is inspect.Parameter.empty


# ---------------------------------------------------------------------------------------
# lane_corpus: the corpus mount comes from the trees, or the lane refuses
# ---------------------------------------------------------------------------------------


def _refusing_trees(w) -> dict[str, Any]:
    """Each way the trees a curator is handed can fail to hold its corpus exactly, as `(paths,
    open trees)`: opened for the lead member, or trees whose mounts omit the corpora (only
    `skills/`), move them elsewhere, hold only a folder above them (`defender/`), or only a
    folder below each corpus. Since #1179's amendment a member answers its own trees, so the
    wrong mount sets are opened directly (`DrainTrees.open`) rather than through a paths double
    that lies about a member's list."""
    moved = (w.repo / "moved" / "lessons", w.repo / "moved" / "lessons-questioner")
    for tree in moved:
        tree.mkdir(parents=True, exist_ok=True)
    (w.corpus_dir / "below").mkdir()
    (w.sibling_dir / "below").mkdir()
    return {
        "lead_label": lambda: (w.paths, open_drain_trees(w.paths, LEAD_AUTHOR_DRAIN_LABEL)),
        "omits_the_corpora": lambda: (w.paths, DrainTrees.open((w.paths.skills_dir,))),
        "moves_the_corpora": lambda: (w.paths, DrainTrees.open(moved)),
        "mount_above": lambda: (w.paths, DrainTrees.open((w.paths.defender_dir,))),
        "mount_below": lambda: (w.paths, DrainTrees.open(
            (w.corpus_dir / "below", w.sibling_dir / "below"))),
    }


REFUSALS = ("lead_label", "omits_the_corpora", "moves_the_corpora", "mount_above",
            "mount_below")


@pytest.mark.parametrize("how", REFUSALS)
@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_trees_that_do_not_hold_the_corpus_exactly_are_fatal_config(tmp_path, channel, how):
    """`shared.lane_corpus(trees, corpus_dir)` is `trees.mount(corpus_dir)`, its `ValueError`
    turned into `FatalConfigError` naming the corpus and the mounts the trees hold: never a handle
    rooted elsewhere (above or below), never a fallback to the plain path. The builder, and
    `run_batch` building its own config, refuse the same way.

    Catches: `hold(corpus_dir)` beside the trees, and a lookup that takes the mount ABOVE the
    corpus (`tree_for(corpus_dir)` answering a non-`"."` name)."""
    w = world(tmp_path)
    build, attr = BUILDERS[channel]
    paths, trees = _refusing_trees(w)[how]()
    corpus_dir = getattr(paths, attr)

    with trees:
        with pytest.raises(FatalConfigError) as got:
            author_shared.lane_corpus(trees, corpus_dir)
        said = str(got.value)
        assert str(corpus_dir) in said, said
        for mount in trees.mounts:
            assert str(mount) in said, (mount, said)
        with pytest.raises(FatalConfigError):
            build(paths, trees=trees)
        with pytest.raises(FatalConfigError):
            RUNNERS[channel](paths=paths, trees=trees)


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_lane_corpus_is_the_trees_own_mount_whatever_opened_them(tmp_path, channel):
    """The control for the refusals: trees holding exactly the two corpora, opened directly
    (`DrainTrees.open`, not through the author member) give the very `Held` the trees hold, and
    the builder takes it; its `tree_for` maps the sibling corpus to the sibling's mount of the
    same trees."""
    w = world(tmp_path)
    build, attr = BUILDERS[channel]
    paths = LoopPaths(repo_root=w.repo, state_dir=tmp_path / "state")

    with DrainTrees.open((paths.lessons_dir, paths.lessons_questioner_dir)) as trees:
        corpus_dir = getattr(paths, attr)
        assert author_shared.lane_corpus(trees, corpus_dir) is trees.mount(corpus_dir)
        cfg = build(paths, trees=trees)
        assert cfg.corpus is trees.mount(corpus_dir)
        hit = cfg.tree_for(paths.lessons_questioner_dir / "y.md")
        assert hit is not None
        assert hit[0] is trees.mount(paths.lessons_questioner_dir)
        assert hit[1] == "y.md"


# ---------------------------------------------------------------------------------------
# cfg.corpus and cfg.tree_for, behaviourally
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_cfg_corpus_is_the_held_mount_and_never_follows_a_link(tmp_path, channel):
    """`cfg.corpus` is the held corpus mount: a symlink at a name below it is refused by the
    view's read, by `write` and by `unlink` (`NotPlainEntry`), the link left and its target
    untouched. The positive control: a plain file at the same name is read and rewritten."""
    w = world(tmp_path)
    build, attr = BUILDERS[channel]
    cfg = build(w.paths, trees=w.trees)
    root = getattr(w.paths, attr)

    target = w.target("secret.md")
    body = target.read_bytes()
    plant_link(root / "linked.md", target)
    assert cfg.corpus.view().read("linked.md").text is None
    with pytest.raises(OSError) as wrote:  # noqa: PT011 — the exact class is the assertion below
        cfg.corpus.write("linked.md", b"rewritten\n", mode="replace")
    assert leaf_refusal(wrote.value), repr(wrote.value)
    with pytest.raises(OSError) as unlinked:  # noqa: PT011 — the exact class is the assertion below
        cfg.corpus.unlink("linked.md")
    assert leaf_refusal(unlinked.value), repr(unlinked.value)
    assert is_link_to(root / "linked.md", target)
    assert target.read_bytes() == body

    put(root / "plain.md", body)
    assert cfg.corpus.view().read("plain.md").text == body.decode()
    cfg.corpus.write("plain.md", b"rewritten\n", mode="replace")
    assert (root / "plain.md").read_bytes() == b"rewritten\n"


def test_cfg_tree_for_maps_both_corpora_to_their_own_mounts_and_nothing_else(tmp_path):
    """`cfg.tree_for` is the trees' lookup: a path in the curator's own corpus maps to `cfg.corpus`
    itself, a path in the SIBLING corpus to the sibling's mount (the `Held` `_put_back` uses for a
    git-status name there), anything else (skills, the rest of the repo) to `None`, and a relative
    path is refused (callers join it to the working copy first). The sibling's view refuses a
    link at the name."""
    w = world(tmp_path)
    cfg = w.cfg()

    own = cfg.tree_for(w.corpus_dir / "a.md")
    assert own is not None
    assert own[0] is cfg.corpus
    assert own[1] == "a.md"
    sib = cfg.tree_for(w.sibling_dir / "sub" / "b.md")
    assert sib is not None
    assert sib[0] is w.trees.mount(w.sibling_dir)
    assert sib[1] == "sub/b.md"
    assert cfg.tree_for(w.paths.skills_dir / "elastic" / "SKILL.md") is None
    assert cfg.tree_for(w.repo / "defender" / "notes.txt") is None
    with pytest.raises(ValueError):  # noqa: PT011 — DrainTrees.tree_for's refusal of a relative path
        cfg.tree_for("defender/lessons/a.md")

    plant_link(w.sibling_dir / "b.md", w.target("secret.md"))
    held, name = cfg.tree_for(w.sibling_dir / "b.md")
    assert held.view().read(name).text is None
    assert entry_kind(held.view(), name).kind == "other"


# ---------------------------------------------------------------------------------------
# The seam consumes the label: _maybe_trigger_author, and author_drain's real default seam
# ---------------------------------------------------------------------------------------


def _held_queue(paths: LoopPaths) -> None:
    """One adversarial finding with no ground truth written: the pre-author gate holds it, so a
    tick serves it without spawning any agent."""
    seed(paths.findings, [finding_row("f1", run_id="no-ground-truth")])


def _trigger_args(paths: LoopPaths) -> tuple:
    return (paths, paths.findings.file, "LEARNING_AUTHOR_THRESHOLD", "author", "pending")


def test_the_trigger_requires_the_label_and_runs_the_batch_under_its_trees(tmp_path, monkeypatch):
    """`drains._maybe_trigger_author` refuses a call without `label` (`TypeError`); with it, the
    channel's `run_batch` runs over the trees the label opens: the gate holds the row (written back
    with its `held_reason`) and nothing is recorded stuck."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    w = world(tmp_path)
    _held_queue(w.paths)

    with pytest.raises(TypeError):
        drains._maybe_trigger_author(*_trigger_args(w.paths))
    assert "held_reason" not in pending(w.paths.findings)[0]

    drains._maybe_trigger_author(*_trigger_args(w.paths), label=AUTHOR_DRAIN_LABEL)

    [row] = pending(w.paths.findings)
    assert "held_reason" in row, row
    assert stuck_records(w.paths.findings) == []


def test_the_trigger_opens_the_trees_of_the_label_it_is_handed_and_no_other(tmp_path, monkeypatch):
    """H8: `_maybe_trigger_author` opens the trees of the label IT was handed. The lead member
    opens `skills/` alone, and the builder refuses it (`FatalConfigError` out of the trigger;
    the row is not served). A non-member (the author lane's value or name as a string, an
    unknown string) raises at its first use (#1179 O1', `AttributeError`), with nothing held
    and the row not served. The author member serves the queue: the gate holds the row, nothing
    is stuck.

    Catches: a trigger that shadows its `label` with the author label (the lead member would
    serve the queue), and one that coerces a string into a member."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    w = world(tmp_path)
    _held_queue(w.paths)
    w.trees.close()

    with pytest.raises(FatalConfigError):
        drains._maybe_trigger_author(*_trigger_args(w.paths), label=LEAD_AUTHOR_DRAIN_LABEL)
    assert "held_reason" not in pending(w.paths.findings)[0]
    for non_member in ("no_such_drain", "author_drain", "AUTHOR"):
        with pytest.raises(AttributeError):
            drains._maybe_trigger_author(*_trigger_args(w.paths), label=non_member)
        assert "held_reason" not in pending(w.paths.findings)[0]
        assert descriptors_under(w.repo) == []

    drains._maybe_trigger_author(*_trigger_args(w.paths), label=AUTHOR_DRAIN_LABEL)

    [row] = pending(w.paths.findings)
    assert "held_reason" in row, row
    assert stuck_records(w.paths.findings) == []


def _drive_author_drain(paths: LoopPaths, repo: Path) -> int:
    """`drains.author_drain` with its PRODUCTION `trigger_author` (not injected) over `repo` as
    the batch worktree, the box lifecycle recorded."""
    rec = B.BoxLifecycleRecorder()
    return drains.author_drain(
        paths, branch=RepoBranch(repo, events=rec.events),
        start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub,
    )


def test_author_drains_real_default_seam_carries_the_label_to_the_open(tmp_path, monkeypatch):
    """`drains.author_drain` with its production `trigger_author`: the label it binds into that
    default reaches the trees' open, and the batch runs over them. A queue the gate holds entirely
    means no agent is spawned; the held row is written back, nothing is recorded stuck on either
    channel, and nothing is held once the drain returns. A default seam that bound no label (a
    `TypeError`) or a label that mounts no corpus would take the curator out of the tick
    (`_drain_one_curator` records a stuck row) instead."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    w = world(tmp_path)
    _held_queue(w.paths)
    w.trees.close()  # the drain's own trees are the only ones under the repo now

    rc = _drive_author_drain(w.paths, w.repo)

    assert rc == 0
    [row] = pending(w.paths.findings)
    assert "held_reason" in row, row
    assert stuck_records(w.paths.findings) == []
    assert stuck_records(w.paths.questioner_findings) == []
    assert descriptors_under(w.repo) == []


def test_a_missing_corpus_mount_is_a_hold_fault_each_curator_records_stuck(tmp_path, monkeypatch):
    """The drain working copy lacks `lessons-questioner/` (one of the author label's mounts).
    Through `author_drain` with its REAL default seam: each curator's `open_drain_trees` fails to
    hold it (`FileNotFoundError` from `hold`), and that fault propagates out of the seam (it is
    not folded into `_run_curator_module`'s rc=None), so `_drain_one_curator` writes that
    channel's stuck record naming it. The sibling curator still runs — it opens its own trees, and
    records its own. Nothing is created, no row is bumped or held, and nothing is held after.

    Catches: the open placed inside `_run_curator_module` (an `OSError` there is swallowed into a
    `(continuing)` log line, recorded nowhere), and a "make the mount point" fallback."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    repo = make_repo(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    assert not paths.lessons_questioner_dir.exists()
    _held_queue(paths)
    seed(paths.questioner_findings, [{"schema_version": 1, "finding_id": "w1",
                                      "subject": "world", "type": "lead-set",
                                      "finding": "a world finding"}])

    rc = _drive_author_drain(paths, repo)

    assert rc == 0
    assert [r["fault_class"] for r in stuck_records(paths.findings)] == ["FileNotFoundError"]
    assert [r["fault_class"] for r in stuck_records(paths.questioner_findings)] == [
        "FileNotFoundError"]
    assert not os.path.lexists(paths.lessons_questioner_dir), "a missing mount point was made"
    [row] = pending(paths.findings)
    assert "held_reason" not in row, row
    assert row.get("attempts") is None, row
    assert descriptors_under(repo) == []


def test_a_hold_fault_at_the_open_propagates_out_of_the_seam(tmp_path, monkeypatch):
    """The unit half: over a working copy with no `lessons-questioner/`, `_maybe_trigger_author`
    raises the `FileNotFoundError` its open met (not swallowed into rc=None), serves nothing,
    creates nothing, and holds nothing after (the mount it did hold is released)."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    repo = make_repo(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    _held_queue(paths)

    with pytest.raises(FileNotFoundError):
        drains._maybe_trigger_author(*_trigger_args(paths), label=AUTHOR_DRAIN_LABEL)

    assert "held_reason" not in pending(paths.findings)[0]
    assert not os.path.lexists(paths.lessons_questioner_dir)
    assert descriptors_under(repo) == []


# ---------------------------------------------------------------------------------------
# Lifetime (A3): one DrainTrees per curator batch, open while it runs, closed after
# ---------------------------------------------------------------------------------------


def _spy_paths(repo: Path, state: Path, seen: list[list[str]], *,
               fault: BaseException | None = None) -> LoopPaths:
    """A `LoopPaths` (the seam's `paths`) that records, each time `author_lock_file` is asked for
    (the builders read it after the open), what this process holds under the repo; with `fault`,
    raises it after recording. A class per call."""

    class Spy(LoopPaths):
        @property
        def author_lock_file(self) -> Path:  # type: ignore[override]
            seen.append(sorted(descriptors_under(self.repo_root)))
            if fault is not None:
                raise fault
            return super().author_lock_file

    return Spy(repo_root=repo, state_dir=state)


def _held_roots(paths: LoopPaths) -> list[str]:
    return sorted(os.path.realpath(p) for p in AUTHOR_DRAIN_LABEL.writable_trees(paths))


def test_the_trigger_holds_the_labels_mounts_only_while_the_batch_runs(
    tmp_path, monkeypatch, caplog,
):
    """`_maybe_trigger_author(..., label=AUTHOR)` over a queue the gate holds: while the curator's
    batch runs (seen from inside its config build) this process holds exactly the roots of
    `AUTHOR_DRAIN_LABEL.writable_trees(paths)` of the paths it was HANDED; once the seam returns it holds nothing under the repo; and no handle
    was used after a close (no `Bad file descriptor` in the log of a batch whose gate read the
    corpus through it).

    Catches: trees opened from a fresh `LoopPaths` (or the default list), trees opened outside
    the seam or left open after it, and a lazy reader iterated past the close."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    caplog.set_level(logging.DEBUG)
    w = world(tmp_path)
    put(w.corpus_dir / "seeded.md", "---\nsource_finding_ids:\n- f0\n---\nbody\n")
    w.commit()
    seen: list[list[str]] = []
    paths = _spy_paths(w.repo, tmp_path / "state", seen)
    _held_queue(paths)
    w.trees.close()
    assert descriptors_under(w.repo) == []

    drains._maybe_trigger_author(*_trigger_args(paths), label=AUTHOR_DRAIN_LABEL)

    assert seen, "the curator's batch never built its config"
    assert all(held == _held_roots(paths) for held in seen), (seen, _held_roots(paths))
    assert len(_held_roots(paths)) == 2
    assert descriptors_under(w.repo) == [], "a held root outlived the seam"
    assert "held_reason" in pending(paths.findings)[0]
    bad = [r.getMessage() for r in caplog.records if "Bad file descriptor" in r.getMessage()]
    assert bad == [], bad


@pytest.mark.parametrize("fault", ["RuntimeError", "OSError"])
def test_the_trigger_releases_the_trees_when_the_batch_raises(tmp_path, monkeypatch, fault):
    """The curator's batch raises inside the seam (from its config build): a `RuntimeError`
    propagates out of the seam as itself; an `OSError` is `_run_curator_module`'s swallowed
    crash (rc=None, the seam returns). Either way the trees were held while it ran and are closed
    after."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    w = world(tmp_path)
    seen: list[list[str]] = []
    exc = RuntimeError("the batch blew up") if fault == "RuntimeError" else OSError(5, "io fault")
    paths = _spy_paths(w.repo, tmp_path / "state", seen, fault=exc)
    _held_queue(paths)
    w.trees.close()

    if fault == "RuntimeError":
        with pytest.raises(RuntimeError, match="the batch blew up"):
            drains._maybe_trigger_author(*_trigger_args(paths), label=AUTHOR_DRAIN_LABEL)
    else:
        assert drains._maybe_trigger_author(*_trigger_args(paths), label=AUTHOR_DRAIN_LABEL) is None

    assert seen == [_held_roots(paths)], seen
    assert descriptors_under(w.repo) == [], "a held root outlived the raising seam"


def test_below_the_threshold_nothing_is_held(tmp_path, monkeypatch):
    """Under the threshold the seam returns before the open: neither corpus attribute is read
    after the queue is seeded (the label's trees are never asked for), no batch runs, and
    nothing is held."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "5")
    w = world(tmp_path)
    asked: list[str] = []
    seen: list[list[str]] = []

    class CountsTheAsk(LoopPaths):
        @property
        def lessons_dir(self) -> Path:  # type: ignore[override]
            asked.append("lessons_dir")
            return super().lessons_dir

        @property
        def lessons_questioner_dir(self) -> Path:  # type: ignore[override]
            asked.append("lessons_questioner_dir")
            return super().lessons_questioner_dir

    paths = CountsTheAsk(repo_root=w.repo, state_dir=tmp_path / "state")
    _held_queue(paths)
    w.trees.close()
    asked.clear()

    drains._maybe_trigger_author(*_trigger_args(paths), label=AUTHOR_DRAIN_LABEL)

    assert asked == []
    assert seen == []
    assert "held_reason" not in pending(paths.findings)[0]
    assert descriptors_under(w.repo) == []


# ---------------------------------------------------------------------------------------
# Source checks: where the label is spelled, and that nothing else opens a tree (H5/H7, H8)
# ---------------------------------------------------------------------------------------


def _tree(module: Any) -> ast.Module:
    return ast.parse(inspect.getsource(module))


def _function(tree: ast.AST, name: str) -> ast.FunctionDef:
    [fn] = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
    return fn


def _callee(call: ast.Call) -> str | None:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _is_name(node: ast.AST | None, name: str) -> bool:
    return (isinstance(node, ast.Name) and node.id == name) or (
        isinstance(node, ast.Attribute) and node.attr == name)


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _calls(node: ast.AST, name: str) -> list[ast.Call]:
    return [c for c in ast.walk(node) if isinstance(c, ast.Call) and _callee(c) == name]


def _open_withs(node: ast.AST) -> list[tuple[ast.With, ast.Call, str | None]]:
    """Each `with open_drain_trees(...) as <name>:` under `node`: the statement, the call, and the
    bound name."""
    out = []
    for w in ast.walk(node):
        if isinstance(w, ast.With):
            for item in w.items:
                ctx = item.context_expr
                if isinstance(ctx, ast.Call) and _callee(ctx) == "open_drain_trees":
                    bound = item.optional_vars.id if isinstance(item.optional_vars,
                                                                ast.Name) else None
                    out.append((w, ctx, bound))
    return out


def _label_arg(call: ast.Call) -> ast.expr | None:
    return call.args[1] if len(call.args) > 1 else _kw(call, "label")


def test_author_drains_default_seam_is_the_trigger_partial_with_the_constant():
    """H8: in `author_drain`, the default `trigger_author` is `functools.partial(
    _maybe_trigger_author, label=AUTHOR_DRAIN_LABEL)` — the constant by name, never a string —
    and the lead label is not named there. (Step 3's pins over `_run_worktree_batch(label=...)`
    stay as they are.)

    Catches: the bare function as the default (no label reaches the open), and a partial over
    the lead label or a literal."""
    fn = _function(_tree(drains), "author_drain")
    partials = [c for c in _calls(fn, "partial")
                if c.args and _is_name(c.args[0], "_maybe_trigger_author")]
    assert len(partials) == 1, [ast.dump(c) for c in partials]
    assert _is_name(_kw(partials[0], "label"), "AUTHOR_DRAIN_LABEL"), ast.dump(partials[0])
    assert not [n for n in ast.walk(fn) if _is_name(n, "LEAD_AUTHOR_DRAIN_LABEL")]


def test_the_trigger_opens_the_trees_with_its_own_label_around_the_curator_call():
    """`_maybe_trigger_author` takes `label` keyword-only with no default, never rebinds it, and
    opens `open_drain_trees(paths, label)` — its own parameter, not a constant — in a `with`
    whose body holds the `_run_curator_module` call (so a hold fault is outside the module call's
    catch); the curator's `run_batch` gets `trees=<the with's name>` and no `label`."""
    params = inspect.signature(drains._maybe_trigger_author).parameters
    assert params["label"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["label"].default is inspect.Parameter.empty
    fn = _function(_tree(drains), "_maybe_trigger_author")
    rebinds = [n for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id == "label"
               and isinstance(n.ctx, ast.Store)]
    assert rebinds == [], "the trigger rebinds its label parameter"

    [(with_, call, bound)] = _open_withs(fn)
    assert _is_name(call.args[0] if call.args else _kw(call, "wt_paths"), "paths"), ast.dump(call)
    assert _is_name(_label_arg(call), "label"), ast.dump(call)
    assert _calls(with_, "_run_curator_module"), "the curator call is not inside the open"
    [run] = _calls(fn, "run_batch")
    assert _kw(run, "label") is None, ast.dump(run)
    assert bound is not None
    assert _is_name(_kw(run, "trees"), bound), ast.dump(run)


@pytest.mark.parametrize("channel", sorted(CHANNEL_MODULES))
def test_each_channel_main_opens_its_trees_with_the_author_label(channel):
    """`main()` (the manual CLI) opens `open_drain_trees(DEFAULT_PATHS, AUTHOR_DRAIN_LABEL)` — the
    constant by name — and runs `run_batch(trees=<those trees>)` inside it. Not driven: `main`
    runs against `DEFAULT_PATHS`, this checkout's own state."""
    fn = _function(_tree(CHANNEL_MODULES[channel]), "main")
    [(with_, call, bound)] = _open_withs(fn)
    assert _is_name(call.args[0] if call.args else None, "DEFAULT_PATHS"), ast.dump(call)
    assert _is_name(_label_arg(call), "AUTHOR_DRAIN_LABEL"), ast.dump(call)
    runs = _calls(fn, "run_batch")
    assert len(runs) == 1, [ast.dump(c) for c in runs]
    assert runs[0] in list(ast.walk(with_)), "run_batch runs outside the trees' with"
    assert bound is not None
    assert _is_name(_kw(runs[0], "trees"), bound), ast.dump(runs[0])


def _harness() -> Path:
    return Path(drains.__file__).resolve().parents[2] / "evals" / "harness.py"


def test_the_eval_harness_opens_the_author_trees_around_its_config_and_batch():
    """`evals/harness.py`'s `run_author(tmp)` opens `open_drain_trees(paths, AUTHOR_DRAIN_LABEL)`
    (the constant by name) and, inside that `with`, builds its config over those trees
    (`build_author_config(paths, trees=<them>, ...)`) and runs its batch with that config
    (`run_batch(paths=paths, cfg=...)`). All three name one local, `paths`, bound in
    `run_author` exactly once, to `LoopPaths(repo_root=<its first parameter>)`: the scratch repo
    it was handed, never `DEFAULT_PATHS` or any other import. Parsed from the file, not imported.

    Catches (E05b): trees opened and the config built over the live checkout
    (`DEFAULT_PATHS`) while the batch is told the scratch repo's paths."""
    tree = ast.parse(_harness().read_text(encoding="utf-8"))
    env = astlib.module_env(tree)
    fn = _function(tree, "run_author")
    [(with_, call, bound)] = _open_withs(fn)
    assert _is_name(_label_arg(call), "AUTHOR_DRAIN_LABEL"), ast.dump(call)
    inside = list(ast.walk(with_))
    [build] = _calls(fn, "build_author_config")
    [run] = _calls(fn, "run_batch")
    assert build in inside, "the config is built outside the open"
    assert run in inside, "the batch runs outside the open"
    assert bound is not None
    assert _is_name(_kw(build, "trees"), bound), ast.dump(build)
    assert _kw(run, "cfg") is not None, ast.dump(run)
    assert _kw(run, "trees") is None, ast.dump(run)

    over = [call.args[0] if call.args else _kw(call, "wt_paths"),
            build.args[0] if build.args else _kw(build, "paths"), _kw(run, "paths")]
    assert all(isinstance(a, ast.Name) and a.id == "paths" for a in over), \
        [ast.unparse(a) if a is not None else None for a in over]
    binds = [n for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id == "paths"
             and isinstance(n.ctx, ast.Store)]
    assert len(binds) == 1, [ast.unparse(b) for b in binds]
    [assign] = [n for n in ast.walk(fn) if isinstance(n, ast.Assign) and binds[0] in n.targets]
    made = assign.value
    assert isinstance(made, ast.Call), ast.unparse(assign)
    assert astlib.callee(made, env) == f"{LoopPaths.__module__}.LoopPaths", ast.unparse(made)
    root = made.args[0] if made.args else _kw(made, "repo_root")
    assert isinstance(root, ast.Name), ast.unparse(made)
    assert root.id == fn.args.args[0].arg, ast.unparse(made)


#: Run in a fresh interpreter, as the harness runs: materialize the scenario into the scratch
#: repo, commit it (`init_git`), then `run_author` over it; print what it reported.
_HARNESS_RUN = """
import json, sys
from pathlib import Path
evals, scenario, scratch = (Path(a) for a in sys.argv[1:4])
sys.path.insert(0, str(evals))
import harness
from _harness_util import init_git
harness.materialize(scenario, scratch)
init_git(scratch)
run, _wall = harness.run_author(scratch)
print(json.dumps({"rc": run.returncode, "stdout": run.stdout, "stderr": run.stderr}))
"""


def test_the_eval_harness_runs_an_empty_queue_scenario_in_its_scratch_repo(tmp_path):
    """E05/E05b, driven: the harness's own `materialize` over a scenario whose queue is empty
    (no model is ever called), `init_git`, then `run_author` — in a subprocess, the way the
    harness runs (its `_harness_util` import needs `evals/` on the path), under a deadline. It
    reports rc 0 and raises nothing; the batch ran in the scratch repo (its author lock is
    there); and nothing landed in the decoy state folder `DEFAULT_PATHS` is pointed at
    (`DEFENDER_LEARNING_STATE_DIR`), so the run never reached the live checkout's paths.

    Catches (E05): a harness that opens trees its scratch repo cannot hold (a mount point it
    never made: `FileNotFoundError` out of `open_drain_trees`, before the reporting `try`); and
    (E05b) one whose config is built over `DEFAULT_PATHS`, which takes its locks in the decoy."""
    evals = _harness().parent
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "findings.jsonl").write_text("", encoding="utf-8")
    scratch = tmp_path / "scratch-repo"
    scratch.mkdir()
    decoy = tmp_path / "decoy-state"
    decoy.mkdir()
    env = {**os.environ, "PYTHONPATH": str(evals.parents[1]),
           "DEFENDER_LEARNING_STATE_DIR": str(decoy)}

    proc = subprocess.run(
        [sys.executable, "-c", _HARNESS_RUN, str(evals), str(scenario), str(scratch)],
        env=env, capture_output=True, text=True, timeout=120, check=False)

    assert proc.returncode == 0, proc.stderr[-4000:]
    run = json.loads(proc.stdout.strip().splitlines()[-1])
    assert run["rc"] == 0, run
    assert (scratch / "defender" / "learning" / "_author.lock").exists()
    assert sorted(p.name for p in decoy.iterdir()) == []


#: The calls that make a held tree or a bound reader of a path, by dotted origin (resolved
#: through `_astlib`, so an alias, a module-qualified call or `DrainTrees.open` is the same call).
_OPENERS = frozenset({
    f"{_io.__name__}.hold", f"{_io.__name__}.bind", f"{_io.__name__}.hold_new",
    f"{_corpus.__name__}._viewed",
    f"{lane_trees.__name__}.open_drain_trees", f"{lane_trees.__name__}.DrainTrees.open",
})
#: A relative import resolves to a leading-dot origin (`..core.lane_trees.open_drain_trees`);
#: it is the same call when its tail is an opener's.
_OPENER_TAILS = ("hold", "bind", "hold_new", "_viewed", "open_drain_trees", "DrainTrees.open")


def _is_opener(call: ast.Call, env: Any) -> bool:
    origin = astlib.callee(call, env)
    if origin is None:
        return False
    if origin.startswith("."):
        return any(origin == f".{t}" or origin.endswith(f".{t}") for t in _OPENER_TAILS)
    return origin in _OPENERS


_CURATOR_MODULES = {"drain": drain, "shared": author_shared, "lessons": lessons_run,
                    "questioner": questioner_run, "_config": author_config}


@pytest.mark.parametrize("name", sorted(_CURATOR_MODULES))
def test_no_curator_module_holds_or_binds_a_tree_but_the_channel_mains(name):
    """H5/H7: below the open, the trees flow; nothing in `drain.py`, `shared.py`, the two channel
    modules or `_config.py` calls `hold(`, `bind(`, `hold_new(`, `_corpus._viewed(`,
    `DrainTrees.open(` or `open_drain_trees(` — except each channel's `main()`, which opens the
    lane's trees itself. (`lane_corpus` takes `trees.mount(...)`; the readers' Path form binds
    inside `_corpus`.)

    Catches: a handle rebuilt from `corpus_dir` at the snapshot, the judge, the attribution or
    the undo; a second label table that opens its own trees; and (E07) a prompt manifest read
    through `_corpus._viewed(cfg.corpus_dir)`."""
    tree = _tree(_CURATOR_MODULES[name])
    env = astlib.module_env(tree)
    mains = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "main"]
    allowed = {id(c) for m in mains for c in ast.walk(m)} if name in ("lessons", "questioner") \
        else set()
    openers = [
        (c.lineno, ast.unparse(c)) for c in ast.walk(tree)
        if isinstance(c, ast.Call) and id(c) not in allowed and _is_opener(c, env)
    ]
    assert openers == [], openers
    if name in ("lessons", "questioner"):
        # Positive control: the resolver sees the open the exemption is for.
        assert [c for m in mains for c in ast.walk(m) if isinstance(c, ast.Call)
                and _is_opener(c, env)], "main() opens nothing the check can see"


#: The shared readers that take a corpus first (or as `corpus=`): a `Bound` in the drain, a `Path`
#: only for callers outside it (N-h).
_READERS = frozenset({
    f"{_corpus.__name__}.iter_lessons", f"{_corpus.__name__}.iter_lesson_paths",
    f"{author_shared.__name__}.build_corpus_manifest",
    f"{author_shared.__name__}.build_curator_user_prompt",
})


def _owners(tree: ast.AST) -> dict[ast.AST, ast.AST | None]:
    """Each node of `tree` to its innermost enclosing function (None at module level)."""
    owner: dict[ast.AST, ast.AST | None] = {}

    def visit(node: ast.AST, fn: ast.AST | None) -> None:
        for child in ast.iter_child_nodes(node):
            owner[child] = fn
            visit(child, child if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
                  else fn)

    visit(tree, None)
    return owner


def _is_view(arg: ast.expr, fn: Any) -> bool:
    """`arg` is a `Bound`: a `.view()` / `.under(...)` call, or a name `fn` binds to one — a
    parameter annotated with `Bound`, or a plain assignment from such a call."""
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
        return arg.func.attr in ("view", "under")
    if not isinstance(arg, ast.Name) or fn is None:
        return False
    params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    if any(a.arg == arg.id and a.annotation is not None and "Bound" in ast.unparse(a.annotation)
           for a in params):
        return True
    return any(isinstance(n, ast.Assign) and _is_view(n.value, None)
               and any(isinstance(t, ast.Name) and t.id == arg.id for t in n.targets)
               for n in ast.walk(fn))


@pytest.mark.parametrize("name", sorted(_CURATOR_MODULES))
def test_no_curator_module_hands_a_reader_the_corpus_by_its_spelling(name):
    """E03/E07: in the curator modules every shared reader (`iter_lessons`, `iter_lesson_paths`,
    `build_corpus_manifest`, `build_curator_user_prompt`'s `corpus=`) gets a VIEW as its corpus —
    `cfg.corpus.view()`, or a name bound to a `Bound` — never a `Path` (`cfg.corpus_dir`,
    `corpus_dir`, `Path(...)`), whose reader form opens the folder by its spelling. Callees
    resolve through `_astlib`; a call to the module's own top-level def (which `_astlib`
    answers None for: a local binding, not an import) is that def. Positive control: in
    `shared.py` and both channel modules the check sees reader calls to judge.

    Catches: an idempotency read or a prompt manifest that checks `cfg.corpus` and then reads
    `iter_lessons(cfg.corpus_dir, ...)`."""
    module = _CURATOR_MODULES[name]
    tree = _tree(module)
    env = astlib.module_env(tree)
    owner = _owners(tree)
    local_defs = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    seen, by_spelling = [], []
    for c in ast.walk(tree):
        if not isinstance(c, ast.Call):
            continue
        origin = astlib.callee(c, env)
        if origin is None and isinstance(c.func, ast.Name) and c.func.id in local_defs:
            origin = f"{module.__name__}.{c.func.id}"
        if origin not in _READERS:
            continue
        corpus = c.args[0] if c.args and not origin.endswith("build_curator_user_prompt") \
            else _kw(c, "corpus")
        if corpus is None:
            continue
        seen.append(c.lineno)
        if not _is_view(corpus, owner.get(c)):
            by_spelling.append((c.lineno, ast.unparse(c)))
    assert by_spelling == [], by_spelling
    if name in ("shared", "lessons", "questioner"):
        assert seen, f"no reader call seen in {name}: the check judged nothing"


def test_the_trigger_holds_nothing_for_an_injected_seam(tmp_path, monkeypatch):
    """An injected `trigger_author` keeps its call shape (no `label`) and the lane opens nothing
    around it: the default seam is the only place the author label is consumed."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    w = world(tmp_path)
    _held_queue(w.paths)
    w.trees.close()
    calls: list[tuple[tuple, dict, list[str]]] = []

    def injected(*a, **kw):
        calls.append((a, kw, sorted(descriptors_under(w.repo))))

    rec = B.BoxLifecycleRecorder()
    rc = drains.author_drain(w.paths, trigger_author=injected,
                             branch=RepoBranch(w.repo, events=rec.events),
                             start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub)

    assert rc == 0
    assert [c[0][3] for c in calls] == ["author", "questioner_curator"]
    assert all("label" not in c[1] for c in calls), calls
    assert all(c[2] == [] for c in calls), "the lane held trees around an injected seam"
