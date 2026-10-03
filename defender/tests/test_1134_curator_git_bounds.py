"""#1134 (curator step): the curator's git calls cannot hang the tick.

While the agent runs, its box has the lessons corpus mounted read-write; the curator drain
(`drain.run_batch`) runs git over that corpus afterwards, before any scrub. A FIFO the agent leaves
at `<corpus>/.gitignore` blocks every git walk that reads ignore rules (`git status
--untracked-files=all`, `ls-files --others --exclude-standard`); one at `<corpus>/.gitattributes`
blocks every git call that reads attributes for a file it must hash or write (`status` re-hashing a
stat-dirty file, `checkout`, `reset`, `add`, `commit -- <paths>`). Today the settle's first `git
status` blocks for good, holding the repo lock.

The contract pinned here:

1. `CorpusAuthorConfig.git_timeout` (seconds; one module default, 60) bounds every git read the
   tick runs: `_capture_pre_state`, the settle, the report cross-checks, and the fault undo
   (`_commit_landed`, `_restore_corpus`'s reset / status / ls-files / compare, `_revert_strays`).
   Set here through `S.build_scene(..., git_timeout=...)`. The `git commit` itself is not bounded.
2. A read that does not answer in time is a git failure, and fails closed. In the tick it is
   `drain.GitProbeError` (never retired: recorded stuck under that class, the row's `attempts` not
   bumped, nothing committed), its message saying git "did not answer within" the bound. In the
   fault undo it is handled like a failed step (status -> `git_worktree_files`; both -> "nothing
   swept"; compare -> every before-state file written back), so the original fault keeps
   propagating: a `TimeoutExpired` never replaces it.
3. Every curator git call (the reads, and the commit's add / rm / commit) runs with
   `GIT_ATTR_SOURCE=HEAD`, so a `.gitattributes` the agent plants, FIFO or regular, is never
   opened. A regular one is still a non-`.md` stray, reverted before the commit.
4. `_git.git_tree_blobs`, `git_unchanged_since` and `git_worktree_files` take `timeout=`, which
   bounds every git process each runs; expiry raises `subprocess.TimeoutExpired`, unconverted.
   `git_tree_blobs` and `git_unchanged_since` ignore replace objects (`GIT_NO_REPLACE_OBJECTS`):
   the before-state and the comparison are the real commit's.

Every scene with a FIFO, and every call against a sleeping git, runs under `_within`'s deadline,
so a regression costs one failed test, not a wedged worker: past the deadline each FIFO is opened
from its other end (the blocked git returns) and replaced by a plain file (the tick's next git
call does not block again), and the test fails.

Red on the current code (39d8a2f8): a scene that sets `git_timeout`, and a `_git` call passing
`timeout=`, fails on the missing field or keyword (pydantic's "Unexpected keyword argument", a
`TypeError`); the `.gitattributes` scenes set no bound and miss the deadline (the settle's first
`git status` blocks); the replace-object units read the replacement's bytes; `_git_read` lets a
`TimeoutExpired` through unconverted. The regular-file controls pass today: they pin behaviour the
change must keep.
"""
from __future__ import annotations

import logging
import os
import shutil
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender._git import GitError
from defender.learning.author import drain
from defender.tests import _spec773 as S
from defender.tests._curator1134 import lesson_text, plant_fifo, put, world
from defender.tests.test_1134_curator_drain import PLANTED, SEEDED, _scene

#: The bound a scene sets (`git_timeout`) or a `_git` call passes (`timeout=`) when a git call is
#: meant to time out: small, so a scene with three or four timed-out reads stays a few seconds.
BOUND = 2.0
#: How long a scene or a call may take before the test fails, generous for a loaded box: a
#: scene here answers in a few seconds once nothing blocks.
DEADLINE = 40.0
#: How long the shim git sleeps on its subcommand: past `DEADLINE`, so an unbounded call fails the
#: test at the deadline rather than answering late.
SHIM_SLEEP = 60
#: How soon a `_git` call given `timeout=BOUND` must have raised: ten times the bound, far short
#: of the shim's sleep, so a helper that bounds the process by anything but the caller's
#: `timeout` (a fixed value of its own) fails here even when it does raise.
PROMPTLY = 10 * BOUND
#: The corpus folder's spelling, the pathspec the curator hands git.
LESSONS = "defender/lessons"
#: A second seeded lesson, which the agent leaves stat-dirty with its bytes unchanged, so the
#: index cannot vouch for it and `git status` / `reset` must re-hash it (reading its attributes).
TOUCHED = "touched-lesson.md"


# ---------------------------------------------------------------------------------------
# The deadline, the shim git, and small observers
# ---------------------------------------------------------------------------------------


def _release(fifo: Path) -> None:
    """Free a git blocked opening `fifo`, and keep the next one from blocking: open the FIFO's
    other end (the blocked open returns), put a plain empty file at the name (later opens meet
    that), then close the end (a reader sees end-of-file)."""
    try:
        end = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    except OSError:
        return
    try:
        spare = fifo.with_name(f"{fifo.name}.released")
        spare.write_bytes(b"")
        os.replace(spare, fifo)
    finally:
        os.close(end)


def _within(fn: Callable[[], Any], *, fifos: Sequence[Path] = ()) -> tuple[str, Any]:
    """`("value", v)` or `("raised", exc)` for `fn()`, run on a worker thread. The test fails
    when `fn` has not returned within `DEADLINE`; each of `fifos` is first released (`_release`)
    and the worker given one more `DEADLINE` to unwind, so no git is left blocked behind it."""
    outcome: dict[str, Any] = {}

    def body() -> None:
        try:
            outcome["value"] = fn()
        except BaseException as e:  # noqa: BLE001 — handed back to the test's thread
            outcome["raised"] = e

    worker = threading.Thread(target=body, daemon=True)
    worker.start()
    worker.join(DEADLINE)
    if worker.is_alive():
        for fifo in fifos:
            _release(fifo)
        worker.join(DEADLINE)
        pytest.fail(f"no answer within {DEADLINE}s: a git call blocked (on "
                    f"{[f.name for f in fifos] or 'a sleeping git'}) and nothing bounded it")
    if "raised" in outcome:
        return ("raised", outcome["raised"])
    return ("value", outcome.get("value"))


def _tick(sc: Any, *, fifos: Sequence[Path] = ()) -> tuple[str, Any]:
    """`drain.run_batch(cfg=sc.cfg)` under the deadline: `("rc", n)` or `("raised", exc)`."""
    result, got = _within(lambda: drain.run_batch(cfg=sc.cfg), fifos=fifos)
    return ("rc", got) if result == "value" else ("raised", got)


def _raised(fn: Callable[[], Any]) -> BaseException | None:
    try:
        fn()
    except Exception as e:  # noqa: BLE001 — the outcome under test, whatever its type
        return e
    return None


def _slow_git(tmp_path: Path, patch: pytest.MonkeyPatch, subcommand: str, *,
              seconds: int) -> Path:
    """Put a `git` first on `PATH` that logs each invocation's arguments, one line each, to the
    returned file; then, when `seconds` is set and one argument is exactly `subcommand`, sleeps
    that long in its own process (`exec sleep`, so a timeout's kill ends it), and otherwise runs
    the real git. `seconds=0` is a pass-through that still logs: the control showing the call
    reached `subcommand` through the shim."""
    real = shutil.which("git")
    assert real is not None
    bin_dir = tmp_path / "slow-git-bin"
    bin_dir.mkdir()
    log = tmp_path / "slow-git.log"
    lines = ["#!/bin/sh", f"printf '%s\\n' \"$*\" >> '{log}'"]
    if seconds:
        lines += ['for a in "$@"; do',
                  f'  if [ "$a" = "{subcommand}" ]; then exec sleep {seconds}; fi',
                  "done"]
    lines.append(f'exec "{real}" "$@"')
    shim = bin_dir / "git"
    shim.write_text("\n".join(lines) + "\n", encoding="utf-8")
    shim.chmod(0o755)
    patch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return log


def _ran(log: Path, subcommand: str) -> bool:
    """Whether the shim logged a git invocation carrying `subcommand` as an argument."""
    if not log.is_file():
        return False
    return any(subcommand in line.split() for line in log.read_text(encoding="utf-8").splitlines())


def _stuck_classes(sc: Any) -> list[str | None]:
    return [r.get("fault_class") for r in S.stuck_records(sc.channel)]


def _warnings(caplog: Any) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


def _is_fifo(at: Path) -> bool:
    return os.path.lexists(at) and stat.S_ISFIFO(os.lstat(at).st_mode)


def _committed_blob(sc: Any, name: str) -> str | None:
    """`name`'s blob in HEAD, raw (`cat-file blob`: no attribute, filter or textconv read)."""
    proc = S.git(sc.repo, "cat-file", "blob", f"HEAD:{LESSONS}/{name}", check=False)
    return proc.stdout if proc.returncode == 0 else None


def _stat_dirty(at: Path) -> None:
    """`at` keeps its bytes but its mtime moves, so the index's stat data no longer vouches for
    it and git must re-hash it."""
    st = os.stat(at)
    os.utime(at, (st.st_atime, st.st_mtime + 100))


# ---------------------------------------------------------------------------------------
# A: a `.gitignore` FIFO makes the tick's git reads time out; the tick is a stuck probe
# ---------------------------------------------------------------------------------------


def _gitignore_scene(tmp_path: Path, plant: Callable[[Path], None]) -> Any:
    """The curator writes an attributable lesson `PLANTED`, rewrites seeded `SEEDED` (still
    citing the batch, so the compare has work and a normal tick would commit it), and leaves
    `plant` at `<corpus>/.gitignore`. The bound is `BOUND`."""
    def agent(rows, batch_id, cfg):
        put(cfg.corpus_dir / SEEDED, lesson_text("f0", "f1", mark="edited"))
        plant(cfg.corpus_dir / ".gitignore")

    return _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}, also=agent),
                  git_timeout=BOUND)


def test_a_gitignore_fifo_the_agent_leaves_is_a_stuck_git_probe_not_a_hung_tick(tmp_path, caplog):
    """The agent leaves a FIFO at `<corpus>/.gitignore`. The settle's first `git status` would
    block opening it; bounded, it does not answer within `BOUND`, which is the tick's
    `GitProbeError` (exact type, its message naming the bound): recorded stuck under that class,
    `f1` not bumped, nothing committed. The fault undo's own `git status` and its `git ls-files`
    fallback time out the same way (one WARNING naming both: nothing swept), its compare (`git
    diff`, which reads no `.gitignore`) answers, so `SEEDED` is written back to its committed
    bytes; `_revert_strays`' status times out silently; the `GitProbeError` still comes out.

    Declared outcome: `PLANTED` still stands (git cannot say what the agent made, so nothing is
    swept), and so does the FIFO, both left for the scrub.

    Catches: an unbounded status (the tick hangs, holding the repo lock); a `TimeoutExpired`
    leaking out of the settle unrouted, or out of the undo in place of the probe error."""
    caplog.set_level(logging.WARNING)
    sc = _gitignore_scene(tmp_path, plant_fifo)
    fifo = sc.corpus / ".gitignore"

    result, got = _tick(sc, fifos=[fifo])

    assert result == "raised", got
    assert type(got) is drain.GitProbeError, repr(got)
    assert "did not answer within" in str(got), str(got)
    assert _is_fifo(fifo)
    fifo.unlink()  # the plant observed; the test's own git calls below must not meet it
    assert _stuck_classes(sc) == ["GitProbeError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert sc.head_files() == []
    assert (sc.corpus / SEEDED).read_text(encoding="utf-8") == lesson_text("f0")
    swept = [m for m in _warnings(caplog) if "nothing swept" in m]
    assert len(swept) == 1, _warnings(caplog)
    assert "git status" in swept[0], swept[0]
    assert "git ls-files" in swept[0], swept[0]
    # Declared: nothing named the agent's new lesson, so nothing removed it.
    assert (sc.corpus / PLANTED).read_text(encoding="utf-8") == lesson_text("f1")


def test_control_a_plain_gitignore_is_a_stray_and_the_tick_commits(tmp_path):
    """The positive control at the same address under the same bound: a plain `.gitignore` is a
    non-`.md` stray, reverted by the settle; the tick commits `PLANTED` and `SEEDED`'s rewrite
    (rc 0), nothing stuck."""
    sc = _gitignore_scene(tmp_path, lambda at: put(at, "*.tmp\n"))

    got = _tick(sc)

    assert got == ("rc", 0), got
    assert not os.path.lexists(sc.corpus / ".gitignore")
    assert sc.head_files() == [f"{LESSONS}/{PLANTED}", f"{LESSONS}/{SEEDED}"]
    assert _committed_blob(sc, SEEDED) == lesson_text("f0", "f1", mark="edited")
    assert sc.category_of("f1") == "consumed_committed"
    assert _stuck_classes(sc) == []


# ---------------------------------------------------------------------------------------
# B: a `.gitattributes` FIFO is never opened; the tick commits
# ---------------------------------------------------------------------------------------

_SEEDS = {SEEDED: lesson_text("f0"), TOUCHED: lesson_text("f0", mark="touched")}


def _gitattributes_scene(tmp_path: Path, plant: Callable[[Path], None], *, lesson: str,
                         fault: BaseException | None = None) -> Any:
    """The curator writes `lesson` at `PLANTED`, leaves `TOUCHED` stat-dirty (so `git status`
    and `git reset` must re-hash it), chmods `SEEDED` +x (a mode-only change, which the settle
    puts back with `git checkout`), leaves `plant` at `<corpus>/.gitattributes`, then raises
    `fault` if one is given. No `git_timeout`: the default bound, which the deadline undercuts, so
    any git call that opens the plant fails the test."""
    def agent(rows, batch_id, cfg):
        _stat_dirty(cfg.corpus_dir / TOUCHED)
        os.chmod(cfg.corpus_dir / SEEDED, 0o755)
        plant(cfg.corpus_dir / ".gitattributes")
        if fault is not None:
            raise fault

    return _scene(tmp_path, seed_corpus=dict(_SEEDS),
                  curator=S.FakeCurator(writes={PLANTED: lesson}, also=agent))


def _assert_committed_cleanly(sc: Any) -> None:
    assert sc.head_files() == [f"{LESSONS}/{PLANTED}"]
    assert _committed_blob(sc, PLANTED) == lesson_text("f1")
    assert sc.category_of("f1") == "consumed_committed"
    assert _stuck_classes(sc) == []
    assert (sc.corpus / SEEDED).read_text(encoding="utf-8") == _SEEDS[SEEDED]
    assert os.stat(sc.corpus / SEEDED).st_mode & 0o111 == 0, "the settle's checkout did not run"
    assert (sc.corpus / TOUCHED).read_text(encoding="utf-8") == _SEEDS[TOUCHED]


def test_a_gitattributes_fifo_the_agent_leaves_is_never_opened_and_the_tick_commits(tmp_path):
    """The agent leaves a FIFO at `<corpus>/.gitattributes` and an index that cannot vouch for
    `TOUCHED` (stat-dirty) or `SEEDED` (mode-only change). Every curator git call reads
    attributes from HEAD's tree (`GIT_ATTR_SOURCE=HEAD`), so the settle's re-hashing `git status`,
    its `git checkout` of `SEEDED`, and the commit's `git add` / `git commit -- <paths>` never
    open the FIFO: the tick completes normally (rc 0), `PLANTED` committed, `SEEDED` back to
    its committed bytes and mode, nothing stuck. The FIFO still stands (git lists no untracked
    FIFO, so nothing removed it: the tick got through with it in place).

    Catches: any of those git calls reading the worktree's attributes (the tick hangs; here, the
    deadline), and a fix that gets through by removing the plant instead."""
    sc = _gitattributes_scene(tmp_path, plant_fifo, lesson=lesson_text("f1"))
    fifo = sc.corpus / ".gitattributes"

    got = _tick(sc, fifos=[fifo])

    assert got == ("rc", 0), got
    assert _is_fifo(fifo)
    fifo.unlink()  # the plant observed; the test's own git calls below must not meet it
    _assert_committed_cleanly(sc)


def test_control_a_plain_gitattributes_is_a_stray_reverted_before_the_commit(tmp_path):
    """The positive control at the same address: a plain `.gitattributes` is a non-`.md` stray,
    reverted by the settle before anything is committed; the tick otherwise runs as above."""
    sc = _gitattributes_scene(tmp_path, lambda at: put(at, "*.md -text\n"),
                              lesson=lesson_text("f1"))

    got = _tick(sc)

    assert got == ("rc", 0), got
    assert not os.path.lexists(sc.corpus / ".gitattributes")
    _assert_committed_cleanly(sc)


# ---------------------------------------------------------------------------------------
# C: the same plant on the fault path; the undo asks git and the fault keeps its routing
# ---------------------------------------------------------------------------------------

#: The two fault routes into `_undo_agent_edits`: the agent raising right after its edits (so the
#: undo is the first host code to meet the plant and the stat-dirty index), and an unattributable
#: lesson the settle passes and the vouching gate refuses.
_ROUTES = {
    "the agent raises": (lesson_text("f1"), True),
    "an unattributable lesson": (lesson_text("not-this-batch"), False),
}


def _fault_scene(tmp_path: Path, plant: Callable[[Path], None], route: str) -> Any:
    """`_gitattributes_scene` on a fault route, with `SEEDED` rewritten (not only chmodded), so
    the undo's compare finds it changed and writes it back."""
    lesson, agent_raises = _ROUTES[route]
    fault = drain.AuthorError("injected after the plant") if agent_raises else None

    def plant_and_rewrite(at: Path) -> None:
        put(at.parent / SEEDED, lesson_text("f0", mark="edited"))
        plant(at)

    return _gitattributes_scene(tmp_path, plant_and_rewrite, lesson=lesson, fault=fault)


def _assert_fault_undone(sc: Any, caplog: Any) -> None:
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert _stuck_classes(sc) == ["AuthorError"]
    assert sc.head_files() == []
    assert (sc.corpus / SEEDED).read_text(encoding="utf-8") == _SEEDS[SEEDED]
    assert (sc.corpus / TOUCHED).read_text(encoding="utf-8") == _SEEDS[TOUCHED]
    assert not os.path.lexists(sc.corpus / PLANTED)
    # The undo's git status and compare answered: no fallback, no warning at all.
    assert _warnings(caplog) == []


@pytest.mark.parametrize("route", sorted(_ROUTES))
def test_a_gitattributes_fifo_on_the_fault_path_is_never_opened_and_the_fault_retires(
    tmp_path, caplog, route,
):
    """The `.gitattributes` FIFO and the stat-dirty index again, with `SEEDED` rewritten, on a
    fault route (`AuthorError`). The undo's `git reset`, `git status` and compare read attributes
    from HEAD's tree, so none opens the FIFO and each answers: the fault retires as ever (rc 2,
    `f1` bumped, recorded stuck under `AuthorError`), `SEEDED` holds its committed bytes again,
    the agent's lesson is swept, no restore fallback is logged, and the FIFO stands.

    Catches: an undo whose reset or status reads the worktree's attributes (the deadline, under
    the default bound), or one that times out and falls back (the WARNING)."""
    caplog.set_level(logging.WARNING)
    sc = _fault_scene(tmp_path, plant_fifo, route)
    fifo = sc.corpus / ".gitattributes"

    got = _tick(sc, fifos=[fifo])

    assert got == ("rc", 2), got
    assert _is_fifo(fifo)
    fifo.unlink()  # the plant observed; the test's own git calls below must not meet it
    _assert_fault_undone(sc, caplog)


@pytest.mark.parametrize("route", sorted(_ROUTES))
def test_control_a_plain_gitattributes_on_the_fault_path_is_swept_and_the_fault_retires(
    tmp_path, caplog, route,
):
    """The positive control at the same address: a plain `.gitattributes` on the same fault
    routes is swept with the agent's lesson; the fault retires and the undo runs as above."""
    caplog.set_level(logging.WARNING)
    sc = _fault_scene(tmp_path, lambda at: put(at, "*.md -text\n"), route)

    got = _tick(sc)

    assert got == ("rc", 2), got
    assert not os.path.lexists(sc.corpus / ".gitattributes")
    _assert_fault_undone(sc, caplog)


# ---------------------------------------------------------------------------------------
# A comparison that does not answer: the settle's probe error, the undo's write-back fallback
# ---------------------------------------------------------------------------------------


def test_a_comparison_that_does_not_answer_is_the_ticks_probe_and_the_undo_writes_back(
    tmp_path, monkeypatch, caplog,
):
    """Every `git diff` sleeps past the bound (a shim git). The curator chmods `SEEDED`, so the
    settle compares it (`_byte_identical_to_head`); unanswered, that is the tick's
    `GitProbeError` ("did not answer within"), recorded stuck, `f1` not bumped, nothing
    committed. The undo's own compare times out too: it is handled like a failed one (a WARNING
    naming `git diff`; every before-state file written back), so `SEEDED` holds its committed
    bytes, the agent's lesson is swept (its status answered), and the probe error still comes out.

    Catches: a comparison left unbounded, a timed-out one read as an answer, or a
    `TimeoutExpired` from the undo's compare replacing the fault."""
    caplog.set_level(logging.WARNING)

    def chmod_seeded(rows, batch_id, cfg):
        os.chmod(cfg.corpus_dir / SEEDED, 0o755)

    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")},
                                                also=chmod_seeded), git_timeout=BOUND)
    with monkeypatch.context() as patch:
        log = _slow_git(tmp_path, patch, "diff", seconds=SHIM_SLEEP)
        result, got = _tick(sc)

    assert result == "raised", got
    assert type(got) is drain.GitProbeError, repr(got)
    assert "did not answer within" in str(got), str(got)
    assert _ran(log, "diff")
    assert _stuck_classes(sc) == ["GitProbeError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert sc.head_files() == []
    assert (sc.corpus / SEEDED).read_text(encoding="utf-8") == lesson_text("f0")
    assert not os.path.lexists(sc.corpus / PLANTED)
    written_back = [m for m in _warnings(caplog) if "writes every one back" in m]
    assert len(written_back) == 1, _warnings(caplog)
    assert "git diff" in written_back[0], written_back[0]


# ---------------------------------------------------------------------------------------
# D: the `_git` helpers bound every git process they run
# ---------------------------------------------------------------------------------------

KEPT = lesson_text("f0", mark="kept")
ORIGINAL = lesson_text("f0", mark="original")
REWRITTEN = lesson_text("f0", mark="rewritten by the agent")
NEW = lesson_text("f1", mark="new")


def _corpus_repo(tmp_path: Path) -> Any:
    """A committed corpus holding `kept.md` and `rewritten.md` (and the fixture's `.gitkeep`);
    then `rewritten.md` is rewritten and an untracked `new.md` added."""
    w = world(tmp_path)
    put(w.corpus_dir / "kept.md", KEPT)
    put(w.corpus_dir / "rewritten.md", ORIGINAL)
    w.commit()
    put(w.corpus_dir / "rewritten.md", REWRITTEN)
    put(w.corpus_dir / "new.md", NEW)
    return w


#: Each helper as the curator calls it over the corpus (an answer made comparable).
_HELPERS: dict[str, Callable[..., Any]] = {
    "git_tree_blobs": lambda repo, **kw: _git.git_tree_blobs(repo, "HEAD", LESSONS, **kw),
    "git_unchanged_since": lambda repo, **kw: _git.git_unchanged_since(repo, "HEAD", LESSONS, **kw),
    "git_worktree_files": lambda repo, **kw: sorted(_git.git_worktree_files(repo, LESSONS, **kw)),
}

#: Each helper's answer over `_corpus_repo`.
_ANSWERS: dict[str, Any] = {
    "git_tree_blobs": {f"{LESSONS}/.gitkeep": b"", f"{LESSONS}/kept.md": KEPT.encode(),
                       f"{LESSONS}/rewritten.md": ORIGINAL.encode()},
    "git_unchanged_since": frozenset({f"{LESSONS}/.gitkeep", f"{LESSONS}/kept.md"}),
    "git_worktree_files": [f"{LESSONS}/{n}" for n in (".gitkeep", "kept.md", "new.md",
                                                       "rewritten.md")],
}

#: Every git process each helper runs, by its subcommand.
_PROCESSES = [
    ("git_tree_blobs", "ls-tree"),
    ("git_tree_blobs", "cat-file"),
    ("git_unchanged_since", "ls-tree"),
    ("git_unchanged_since", "diff"),
    ("git_worktree_files", "rev-parse"),
    ("git_worktree_files", "ls-files"),
]


@pytest.mark.parametrize(("helper", "subcommand"), _PROCESSES)
def test_each_git_process_a_helper_runs_is_bounded_by_its_timeout(
    tmp_path, monkeypatch, helper, subcommand,
):
    """A shim git sleeps on one subcommand the helper runs and answers every other at once: the
    helper, given `timeout=BOUND`, raises `subprocess.TimeoutExpired` (exact type, unconverted:
    `scripts/tenant.py` catches that type) within `PROMPTLY`.

    Catches: a helper that bounds some of its git processes but not this one, or bounds it by a
    value of its own rather than the caller's `timeout`."""
    w = _corpus_repo(tmp_path)
    with monkeypatch.context() as patch:
        log = _slow_git(tmp_path, patch, subcommand, seconds=SHIM_SLEEP)
        started = time.monotonic()
        result, got = _within(lambda: _HELPERS[helper](w.repo, timeout=BOUND))
        took = time.monotonic() - started

    assert result == "raised", got
    assert type(got) is subprocess.TimeoutExpired, repr(got)
    assert took < PROMPTLY, f"raised after {took:.1f}s: not bounded by timeout={BOUND}"
    assert _ran(log, subcommand)


@pytest.mark.parametrize(("helper", "subcommand"), _PROCESSES)
def test_control_through_a_git_that_answers_each_helper_answers_under_its_timeout(
    tmp_path, monkeypatch, helper, subcommand,
):
    """The positive control at the same address: the shim on `PATH` but sleeping on nothing.
    The helper, given the same `timeout=`, answers what it always has, and the shim saw the
    subcommand (the negative's sleep is what timed out, not the shim)."""
    w = _corpus_repo(tmp_path)
    with monkeypatch.context() as patch:
        log = _slow_git(tmp_path, patch, subcommand, seconds=0)
        result, got = _within(lambda: _HELPERS[helper](w.repo, timeout=BOUND))

    assert result == "value", got
    assert got == _ANSWERS[helper]
    assert _ran(log, subcommand)


def test_git_worktree_files_over_a_gitignore_fifo_times_out(tmp_path):
    """No shim: a real FIFO at `<corpus>/.gitignore`. `git ls-files --exclude-standard` blocks
    opening it; bounded, `git_worktree_files(..., timeout=BOUND)` raises
    `subprocess.TimeoutExpired` within `PROMPTLY`, and the FIFO is left as it was."""
    w = _corpus_repo(tmp_path)
    fifo = w.corpus_dir / ".gitignore"
    plant_fifo(fifo)

    started = time.monotonic()
    result, got = _within(lambda: _git.git_worktree_files(w.repo, LESSONS, timeout=BOUND),
                          fifos=[fifo])
    took = time.monotonic() - started

    assert result == "raised", got
    assert type(got) is subprocess.TimeoutExpired, repr(got)
    assert took < PROMPTLY, f"raised after {took:.1f}s: not bounded by timeout={BOUND}"
    assert _is_fifo(fifo)


def test_control_git_worktree_files_honours_a_plain_gitignore_under_its_timeout(tmp_path):
    """The positive control at the same address: a plain `.gitignore` naming `ignored.md`. The
    helper answers every other worktree file, `.gitignore` itself included, and not
    `ignored.md`."""
    w = _corpus_repo(tmp_path)
    put(w.corpus_dir / ".gitignore", "ignored.md\n")
    put(w.corpus_dir / "ignored.md", NEW)

    result, got = _within(
        lambda: sorted(_git.git_worktree_files(w.repo, LESSONS, timeout=BOUND)))

    assert result == "value", got
    assert got == [f"{LESSONS}/{n}" for n in (".gitignore", ".gitkeep", "kept.md", "new.md",
                                               "rewritten.md")]


# ---------------------------------------------------------------------------------------
# E: replace objects never stand in for the commit's own blobs
# ---------------------------------------------------------------------------------------

REPLACEMENT = lesson_text("f0", mark="the replacement object's bytes")
_REPLACED = f"{LESSONS}/replaced.md"


def _replaced_repo(tmp_path: Path) -> Any:
    """A committed corpus file `replaced.md` holding `ORIGINAL`, and a replace ref standing the
    blob `REPLACEMENT` in for its blob. The positive control (plain `git cat-file -p
    HEAD:<path>`, which honours replace refs) shows the replacement: the plant took."""
    w = world(tmp_path)
    put(w.corpus_dir / "replaced.md", ORIGINAL)
    w.commit()
    original = w.git("rev-parse", f"HEAD:{_REPLACED}").stdout.strip()
    spare = tmp_path / "replacement-bytes"
    put(spare, REPLACEMENT)
    replacement = w.git("hash-object", "-w", str(spare)).stdout.strip()
    w.git("replace", original, replacement)
    assert w.head_text(_REPLACED) == REPLACEMENT
    return w


def test_git_tree_blobs_reads_the_commits_own_blob_not_its_replacement(tmp_path):
    """`git_tree_blobs` answers the bytes the commit stores (`ORIGINAL`), not the replace
    object's: the before-state is the real commit's.

    Catches: a `cat-file --batch` run with replace refs honoured (today's)."""
    w = _replaced_repo(tmp_path)

    assert _git.git_tree_blobs(w.repo, "HEAD", LESSONS)[_REPLACED] == ORIGINAL.encode()


def test_git_unchanged_since_compares_with_the_commits_own_blob_not_its_replacement(tmp_path):
    """`git_unchanged_since` compares against the blob the commit stores. The worktree holding
    `ORIGINAL` (rewritten, stat-dirty, so git hashes it) is unchanged; holding the replacement's
    bytes it is changed.

    Catches: a `git diff` run with replace refs honoured (today's), which calls the
    replacement's bytes unchanged."""
    w = _replaced_repo(tmp_path)
    at = w.corpus_dir / "replaced.md"
    put(at, ORIGINAL)
    _stat_dirty(at)

    assert _REPLACED in _git.git_unchanged_since(w.repo, "HEAD", LESSONS)
    put(at, REPLACEMENT)
    assert _REPLACED not in _git.git_unchanged_since(w.repo, "HEAD", LESSONS)


# ---------------------------------------------------------------------------------------
# F: the probe wrapper routes a timed-out read
# ---------------------------------------------------------------------------------------


def test_a_git_read_that_does_not_answer_in_time_is_a_git_probe_error():
    """`drain._git_read` turns a step's `subprocess.TimeoutExpired` into `GitProbeError` (exact
    type), its message saying git did not answer within the bound.

    Catches: a timed-out read escaping the wrapper as `TimeoutExpired`, a class the tick neither
    retires nor names as a git failure."""
    def unanswered():
        raise subprocess.TimeoutExpired(["git", "status"], BOUND)

    got = _raised(lambda: drain._git_read("x", unanswered))

    assert type(got) is drain.GitProbeError, repr(got)
    assert "did not answer within" in str(got), str(got)


def test_control_git_read_routes_a_git_failure_and_passes_an_answer_through():
    """The positive control on the same wrapper: a step's `GitError` is `GitProbeError` as
    ever, and a step that answers hands its answer back."""
    def failing():
        raise GitError(["status"], 128, "fatal: Unable to create index.lock")

    got = _raised(lambda: drain._git_read("x", failing))

    assert type(got) is drain.GitProbeError, repr(got)
    assert drain._git_read("x", lambda: "the answer") == "the answer"
