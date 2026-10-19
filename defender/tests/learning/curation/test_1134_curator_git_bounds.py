from __future__ import annotations

import contextlib
import dataclasses
import logging
import os
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender.learning.author import drain
from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.support.learning.curation._curator1134 import lesson_text, plant_fifo, put, world
from defender.tests.learning.curation.test_1134_curator_drain import PLANTED, SEEDED, _scene

BOUND = 1.5
#: How long a scene or a call may take before the test fails, generous for a loaded box: a
#: scene here answers in a few seconds once nothing blocks.
DEADLINE = 40.0
#: How long the shim git sleeps on its subcommand: past `DEADLINE`, so an unbounded call fails the
#: test at the deadline rather than answering late.
SHIM_SLEEP = 60
PROMPTLY = 10 * BOUND
#: The corpus folder's spelling, the pathspec the curator hands git.
LESSONS = "defender/lessons"
#: A second seeded lesson, which the agent leaves stat-dirty with its bytes unchanged, so the
#: index cannot vouch for it and `git status` / `reset` must re-hash it (reading its attributes).
TOUCHED = "touched-lesson.md"


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


def _within(fn: Callable[[], Any], *, fifos: Sequence[Path] = (), shim: _Shim | None = None,
            what: str = "") -> tuple[str, Any]:
    """`("value", v)` or `("raised", exc)` for `fn()`, run on a worker thread. The test fails
    when `fn` has not returned within `DEADLINE`; each of `fifos` is first released (`_release`),
    each stall of `shim` killed, and the worker given one more `DEADLINE` to unwind, so no git is
    left blocked behind it. `what` names the call in the failure."""
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
        if shim is not None:
            shim.kill_stalls()
        worker.join(DEADLINE)
        pytest.fail(f"no answer within {DEADLINE}s: a git call blocked (on "
                    f"{[f.name for f in fifos] or 'a sleeping git'}{' at ' + what if what else ''})"
                    " and nothing bounded it")
    if "raised" in outcome:
        return ("raised", outcome["raised"])
    return ("value", outcome.get("value"))


def _tick(sc: Any, *, fifos: Sequence[Path] = (), shim: _Shim | None = None,
          what: str = "") -> tuple[str, Any]:
    """`drain.run_batch(cfg=sc.cfg)` under the deadline: `("rc", n)` or `("raised", exc)`."""
    result, got = _within(lambda: drain.run_batch(cfg=sc.cfg), fifos=fifos, shim=shim, what=what)
    return ("rc", got) if result == "value" else ("raised", got)


def _raised(fn: Callable[[], Any]) -> BaseException | None:
    try:
        fn()
    except Exception as e:  # noqa: BLE001 — the outcome under test, whatever its type
        return e
    return None


@dataclasses.dataclass(frozen=True)
class _Shim:
    """A `git` first on `PATH` (`_shim_git`): the log of every invocation, and the pids of the
    ones it stalled."""

    log: Path
    pids: Path

    def calls(self) -> list[tuple[int, bool, list[str]]]:
        """Each invocation in order: its ordinal (from 1, counted by this shim), whether the agent
        had run by then (the flag file existed), and its arguments."""
        if not self.log.is_file():
            return []
        calls = []
        for line in self.log.read_text(encoding="utf-8").splitlines():
            n, ran, *args = line.split(" ")
            calls.append((int(n), ran == "1", args))
        return calls

    def ran(self, *tokens: str) -> bool:
        """Whether one invocation carried every one of `tokens` as an argument."""
        return any(all(t in args for t in tokens) for _n, _ran, args in self.calls())

    def kill_stalls(self) -> None:
        """Kill every invocation the shim stalled (git then answers rc -9, and the caller
        unwinds)."""
        if not self.pids.is_file():
            return
        for pid in self.pids.read_text(encoding="utf-8").split():
            with contextlib.suppress(ProcessLookupError, ValueError):
                os.kill(int(pid), signal.SIGKILL)


def _shim_git(at: Path, patch: pytest.MonkeyPatch, *, stall_every: str = "", stall_at: int = 0,
              stall_after: str = "", flag: Path | None = None,
              delay_first: tuple[str, int] = ("", 0)) -> _Shim:
    """Put a `git` (living in `at`) first on `PATH` that logs every invocation (`_Shim.calls`)
    and runs the real git, except that it stalls (`exec sleep SHIM_SLEEP` in its own process, so
    a timeout's kill ends it; its pid recorded for `_Shim.kill_stalls`): every invocation carrying
    `stall_every` as an argument; the `stall_at`-th invocation; and, once `flag` exists (the fake
    agent writes it), every invocation carrying `stall_after`. The first invocation carrying
    `delay_first[0]` sleeps `delay_first[1]` seconds, then runs the real git. With nothing set it
    is a pass-through that only logs."""
    real = shutil.which("git")
    assert real is not None
    bin_dir = at / "bin"
    bin_dir.mkdir(parents=True)
    log, pids, count, delayed = (at / "calls.log", at / "stalls.pids", at / "count",
                                 at / "delayed")
    ran_flag = flag if flag is not None else at / "no-flag"
    delay_sub, delay_seconds = delay_first
    script = f"""#!/bin/sh
n=$(( $(cat '{count}' 2>/dev/null || echo 0) + 1 ))
echo "$n" > '{count}'
ran=0; [ -e '{ran_flag}' ] && ran=1
printf '%s %s %s\\n' "$n" "$ran" "$*" >> '{log}'
stall() {{ echo "$$" >> '{pids}'; exec sleep {SHIM_SLEEP}; }}
[ "$n" = "{stall_at}" ] && stall
for a in "$@"; do
  [ -n "{stall_every}" ] && [ "$a" = "{stall_every}" ] && stall
  [ "$ran" = 1 ] && [ -n "{stall_after}" ] && [ "$a" = "{stall_after}" ] && stall
  if [ -n "{delay_sub}" ] && [ "$a" = "{delay_sub}" ] && [ ! -e '{delayed}' ]; then
    : > '{delayed}'; sleep {delay_seconds}
  fi
done
exec "{real}" "$@"
"""
    shim = bin_dir / "git"
    shim.write_text(script, encoding="utf-8")
    shim.chmod(0o755)
    patch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return _Shim(log=log, pids=pids)


def _subcommand(args: Sequence[str]) -> str:
    """The git subcommand in an invocation's arguments: the first that is no option (`-c` takes
    the next as its value)."""
    rest = iter(args)
    for arg in rest:
        if arg == "-c":
            next(rest, None)
        elif not arg.startswith("-"):
            return arg
    return ""


def _stuck_classes(sc: Any) -> list[str | None]:
    return [r.get("fault_class") for r in S.stuck_records(sc.paths, sc.channel)]


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


def _gitignore_scene(tmp_path: Path, plant: Callable[[Path], None]) -> Any:
    """The curator writes an attributable lesson `PLANTED`, rewrites seeded `SEEDED` (still
    citing the batch, so the compare has work and a normal tick would commit it), and leaves
    `plant` at `<corpus>/.gitignore`. The bound is `BOUND`."""
    def agent(rows, batch_id, cfg):
        put(cfg.corpus_dir / SEEDED, lesson_text("f0", "f1", mark="edited"))
        plant(cfg.corpus_dir / ".gitignore")

    return _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}, also=agent),
                  git_timeout=BOUND)


def test_a_gitignore_fifo_the_agent_leaves_is_a_stuck_git_probe_not_a_hung_tick(
    tmp_path, monkeypatch, caplog,
):
    caplog.set_level(logging.WARNING)
    sc = _gitignore_scene(tmp_path, plant_fifo)
    fifo = sc.corpus / ".gitignore"

    with monkeypatch.context() as patch:
        shim = _shim_git(tmp_path / "git-shim", patch)
        result, got = _tick(sc, fifos=[fifo], shim=shim)

    assert result == "raised", got
    assert type(got) is drain.GitProbeError, repr(got)
    assert "did not answer within" in str(got), str(got)
    assert str(BOUND) in str(got), str(got)
    assert shim.ran("ls-files", "--others"), "the undo never asked git ls-files"
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
    sc = _gitignore_scene(tmp_path, lambda at: put(at, "*.tmp\n"))

    got = _tick(sc)

    assert got == ("rc", 0), got
    assert not os.path.lexists(sc.corpus / ".gitignore")
    assert sc.head_files() == [f"{LESSONS}/{PLANTED}", f"{LESSONS}/{SEEDED}"]
    assert _committed_blob(sc, SEEDED) == lesson_text("f0", "f1", mark="edited")
    assert sc.category_of("f1") == "consumed_committed"
    assert _stuck_classes(sc) == []


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


def test_a_comparison_that_does_not_answer_is_the_ticks_probe_and_the_undo_writes_back(
    tmp_path, monkeypatch, caplog,
):
    caplog.set_level(logging.WARNING)

    def chmod_seeded(rows, batch_id, cfg):
        os.chmod(cfg.corpus_dir / SEEDED, 0o755)

    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")},
                                                also=chmod_seeded), git_timeout=BOUND)
    with monkeypatch.context() as patch:
        shim = _shim_git(tmp_path / "git-shim", patch, stall_every="diff")
        result, got = _tick(sc, shim=shim)

    assert result == "raised", got
    assert type(got) is drain.GitProbeError, repr(got)
    assert "did not answer within" in str(got), str(got)
    assert str(BOUND) in str(got), str(got)
    assert shim.ran("diff")
    assert _stuck_classes(sc) == ["GitProbeError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert sc.head_files() == []
    assert (sc.corpus / SEEDED).read_text(encoding="utf-8") == lesson_text("f0")
    assert not os.path.lexists(sc.corpus / PLANTED)
    written_back = [m for m in _warnings(caplog) if "writes every one back" in m]
    assert len(written_back) == 1, _warnings(caplog)
    assert "git diff" in written_back[0], written_back[0]


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


@pytest.fixture(scope="module")
def helper_stalls(dispatch_shim, tmp_path_factory):
    """Each `_PROCESSES` case run against a git sleeping on its subcommand, all at once (each
    waits out its own `BOUND`): `{(helper, subcommand): (result, got, took, shim)}`."""
    root = tmp_path_factory.mktemp("helper-stalls")

    def one(i_case):
        i, (helper, subcommand) = i_case
        at = root / f"case-{i}"
        w = _corpus_repo(at)
        shim = _dispatch_cfg(at, stall_every=subcommand)
        started = time.monotonic()
        result, got = _within(lambda: _HELPERS[helper](w.repo, timeout=BOUND), shim=shim)
        return (helper, subcommand), (result, got, time.monotonic() - started, shim)

    with ThreadPoolExecutor(max_workers=len(_PROCESSES)) as pool:
        return dict(pool.map(one, enumerate(_PROCESSES)))


@pytest.mark.parametrize(("helper", "subcommand"), _PROCESSES)
def test_each_git_process_a_helper_runs_is_bounded_by_its_timeout(
    helper_stalls, helper, subcommand,
):
    result, got, took, shim = helper_stalls[(helper, subcommand)]

    assert result == "raised", got
    assert type(got) is subprocess.TimeoutExpired, repr(got)
    assert took < PROMPTLY, f"raised after {took:.1f}s: not bounded by timeout={BOUND}"
    assert shim.ran(subcommand)


@pytest.mark.parametrize(("helper", "subcommand"), _PROCESSES)
def test_control_through_a_git_that_answers_each_helper_answers_under_its_timeout(
    tmp_path, monkeypatch, helper, subcommand,
):
    w = _corpus_repo(tmp_path)
    with monkeypatch.context() as patch:
        shim = _shim_git(tmp_path / "git-shim", patch)
        result, got = _within(lambda: _HELPERS[helper](w.repo, timeout=BOUND), shim=shim)

    assert result == "value", got
    assert got == _ANSWERS[helper]
    assert shim.ran(subcommand)


def test_git_worktree_files_over_a_gitignore_fifo_times_out(tmp_path):
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
    w = _corpus_repo(tmp_path)
    put(w.corpus_dir / ".gitignore", "ignored.md\n")
    put(w.corpus_dir / "ignored.md", NEW)

    result, got = _within(
        lambda: sorted(_git.git_worktree_files(w.repo, LESSONS, timeout=BOUND)))

    assert result == "value", got
    assert got == [f"{LESSONS}/{n}" for n in (".gitignore", ".gitkeep", "kept.md", "new.md",
                                               "rewritten.md")]


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
    w = _replaced_repo(tmp_path)

    assert _git.git_tree_blobs(w.repo, "HEAD", LESSONS)[_REPLACED] == ORIGINAL.encode()


def test_git_unchanged_since_compares_with_the_commits_own_blob_not_its_replacement(tmp_path):
    w = _replaced_repo(tmp_path)
    at = w.corpus_dir / "replaced.md"
    put(at, ORIGINAL)
    _stat_dirty(at)

    assert _REPLACED in _git.git_unchanged_since(w.repo, "HEAD", LESSONS)
    put(at, REPLACEMENT)
    assert _REPLACED not in _git.git_unchanged_since(w.repo, "HEAD", LESSONS)


def test_a_git_read_that_does_not_answer_in_time_is_a_git_probe_error():
    def unanswered():
        raise subprocess.TimeoutExpired(["git", "status"], BOUND)

    got = _raised(lambda: drain._git_read("x", unanswered))

    assert type(got) is drain.GitProbeError, repr(got)
    assert "did not answer within" in str(got), str(got)
    assert str(BOUND) in str(got), str(got)


#: The bound the census scenes and the other stall scenes set: short, since a census stalls each
#: of its calls in turn. Not a whole number, so the message naming it is checked however spelled.
STALL_BOUND = 1.5
#: A non-lesson file outside the corpus the undo census's agent leaves (`_revert_strays`' work).
OUTSIDE_STRAY = "defender/skills/elastic/stray.txt"
_CENSUS_SEEDS = {SEEDED: lesson_text("f0"), TOUCHED: lesson_text("f0", mark="touched")}


def _census_scene(at: Path, *, undo: bool) -> Any:
    """A tick that reaches every kind of git call the curator makes, its repo under `at` and its
    flag at `at / "agent-ran"` (outside the repo, so no status lists it). The agent writes the
    attributable `PLANTED`; rewrites `SEEDED` to cite the batch (committed with it); chmods `TOUCHED` +x (a mode-only change, which the settle compares and checks
    out); leaves a non-lesson `notes.txt` in the corpus (reverted through `_put_back`); then writes
    the flag. With `undo` it also leaves a stray outside the corpus and raises `AuthorError`, so
    every git call after the flag is the fault undo's (`_commit_landed`, `_restore_corpus`,
    `_revert_strays`). The bound is `STALL_BOUND`."""
    def agent(rows, batch_id, cfg):
        put(cfg.corpus_dir / SEEDED, lesson_text("f0", "f1", mark="edited"))
        os.chmod(cfg.corpus_dir / TOUCHED, 0o755)
        put(cfg.corpus_dir / "notes.txt", "not a lesson\n")
        if undo:
            put(cfg.repo_root / OUTSIDE_STRAY, "outside the corpus\n")
        put(at / "agent-ran", "")
        if undo:
            raise drain.AuthorError("injected after the agent's edits")

    return _scene(at, seed_corpus=dict(_CENSUS_SEEDS),
                  curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}, also=agent),
                  git_timeout=STALL_BOUND)


_DISPATCH_SHIM = """#!/bin/sh
d=$(pwd -P); cfg=
while :; do
  [ -f "$d/git-shim-cfg" ] && { cfg="$d/git-shim-cfg"; break; }
  [ "$d" = / ] && break
  d=$(dirname "$d")
done
[ -z "$cfg" ] && exec "{real}" "$@"
. "$cfg"
n=$(( $(cat "$state/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$state/count"
ran=0; [ -e "$flag" ] && ran=1
printf '%s %s %s\\n' "$n" "$ran" "$*" >> "$state/calls.log"
stall() {{ echo "$$" >> "$state/stalls.pids"; exec sleep {sleep}; }}
[ "$n" = "$stall_at" ] && stall
for a in "$@"; do [ -n "$stall_every" ] && [ "$a" = "$stall_every" ] && stall; done
exec "{real}" "$@"
"""


@pytest.fixture(scope="module")
def dispatch_shim(tmp_path_factory):
    """The census scenes' shared sleeping `git`, first on `PATH` for this module's census tests."""
    real = shutil.which("git")
    assert real is not None
    bin_dir = tmp_path_factory.mktemp("dispatch-bin")
    shim = bin_dir / "git"
    shim.write_text(_DISPATCH_SHIM.replace("{{", "{").replace("}}", "}")
                    .replace("{real}", real).replace("{sleep}", str(SHIM_SLEEP)), encoding="utf-8")
    shim.chmod(0o755)
    patch = pytest.MonkeyPatch()
    patch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    yield
    patch.undo()


def _dispatch_cfg(at: Path, *, stall_at: int = 0, stall_every: str = "", flag: Path | None = None
                  ) -> _Shim:
    """Configure the shared dispatch shim for the scene under `at`: it stalls the `stall_at`-th
    git call, and every call carrying `stall_every` as an argument (`0` / `""`: none)."""
    state = at / "git-shim"
    state.mkdir()
    (at / "git-shim-cfg").write_text(
        f"state='{state}'\nstall_at={stall_at}\nstall_every='{stall_every}'\n"
        f"flag='{flag or at / 'no-flag'}'\n", encoding="utf-8")
    return _Shim(log=state / "calls.log", pids=state / "stalls.pids")


def _census_run(at: Path, *, undo: bool, stall_at: int = 0) -> tuple[Any, tuple[str, Any], _Shim]:
    """One `_census_scene` tick under `_tick`'s deadline, through the shared dispatch shim
    configured to stall this scene's `stall_at`-th git call (`0`: none)."""
    sc = _census_scene(at, undo=undo)
    shim = _dispatch_cfg(at, stall_at=stall_at, flag=at / "agent-ran")
    got = _tick(sc, shim=shim, what=f"git call #{stall_at}" if stall_at else "the census")
    return sc, got, shim


@pytest.fixture(scope="module")
def tick_census(dispatch_shim, tmp_path_factory):
    """The unstalled census tick, run once: its log is every parametrized case's window."""
    return _census_run(tmp_path_factory.mktemp("tick-census"), undo=False)


@pytest.fixture(scope="module")
def undo_census(dispatch_shim, tmp_path_factory):
    """The unstalled fault-undo census tick, run once."""
    return _census_run(tmp_path_factory.mktemp("undo-census"), undo=True)


_TICK_SUBCOMMANDS = ["rev-parse", "ls-tree", "cat-file", "status", "diff", "checkout", "ls-files"]
_UNDO_SUBCOMMANDS = ["rev-parse", "reset", "status", "ls-tree", "diff", "checkout", "ls-files"]


def _stall_every_call(root: Path, census: Any, subcommands: list[str], *, undo: bool) -> dict:
    """For each of `subcommands`, each call in the census's window running it, a fresh census
    scene whose shim stalls exactly that call: `{subcommand: [(where, ran, sc, got), ...]}`, or the
    exception a scene raised in place of its tuple. Every scene waits out its own bound, so they
    run side by side on threads (one after another the bounds would add up, and under `--dist
    loadfile` this file is one worker's serial time). Each stalled run's own log must show the
    same subcommand at that ordinal (the calls did not diverge from the census, so the stall is
    where the census says)."""
    calls = census[2].calls()
    if undo:
        window = [call for call in calls if call[1]]
    else:
        window = calls[1:[_subcommand(args) for _n, _ran, args in calls].index("add")]
    jobs = [(sub, call) for sub in subcommands for call in window if _subcommand(call[2]) == sub]

    def one(job):
        sub, (n, ran, args) = job
        where = f"git call #{n} ({' '.join(args)[:120]})"
        try:
            sc, got, shim = _census_run(root / f"stall-{n}", undo=undo, stall_at=n)
            seen = shim.calls()
            assert len(seen) >= n, f"{where}: the stalled run made only {len(seen)} calls"
            assert _subcommand(seen[n - 1][2]) == sub, f"{where}: diverged, {seen[n - 1]}"
            return sub, (where, ran, sc, got)
        except BaseException as e:  # noqa: BLE001 — re-raised in the test that owns `sub`
            return sub, e

    out: dict = {sub: [] for sub in subcommands}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for sub, result in pool.map(one, jobs):
            out[sub].append(result)
    return out


@pytest.fixture(scope="module")
def tick_stalls(tick_census, tmp_path_factory):
    """Every pre-commit call of the census tick stalled alone, all run together once."""
    return _stall_every_call(tmp_path_factory.mktemp("tick-stalls"), tick_census,
                             _TICK_SUBCOMMANDS, undo=False)


@pytest.fixture(scope="module")
def undo_stalls(undo_census, tmp_path_factory):
    """Every call of the fault-undo census stalled alone, all run together once."""
    return _stall_every_call(tmp_path_factory.mktemp("undo-stalls"), undo_census,
                             _UNDO_SUBCOMMANDS, undo=True)


def _stalled_calls(stalls: dict, subcommand: str, census_log: list) -> list:
    """The `(where, ran, sc, got)` of each stalled call running `subcommand`; an exception a
    scene raised is raised here, in the test that owns the subcommand."""
    results = stalls[subcommand]
    assert results, f"the scene never reached a git {subcommand}: {census_log}"
    for result in results:
        if isinstance(result, BaseException):
            raise result
    return results


@pytest.mark.parametrize("subcommand", _TICK_SUBCOMMANDS)
def test_every_git_call_the_tick_makes_before_its_commit_is_bounded(
    tick_census, tick_stalls, subcommand,
):
    sc, got, shim = tick_census
    assert got == ("rc", 0), got
    assert sc.head_files() == sorted([f"{LESSONS}/{PLANTED}", f"{LESSONS}/{SEEDED}"])
    census = shim.calls()
    subcommands = [_subcommand(args) for _n, _ran, args in census]
    assert subcommands[0] == "status", census[0]  # the clean gate, unbounded by design
    assert "add" in subcommands, census

    window = census[1:subcommands.index("add")]
    for where, ran, stalled, outcome in _stalled_calls(tick_stalls, subcommand, window):
        result, exc = outcome
        assert result == "raised", f"{where}: {outcome}"
        assert type(exc) is drain.GitProbeError, f"{where}: {exc!r}"
        assert str(STALL_BOUND) in str(exc), f"{where}: {exc}"
        assert _stuck_classes(stalled) == ["GitProbeError"], where
        assert stalled.pending_by_id()["f1"].get("attempts") is None, where
        assert stalled.head_files() == [], where
        if not ran:
            assert stalled.curator.calls == [], f"{where}: the agent ran past a failed read"


@pytest.mark.parametrize("subcommand", _UNDO_SUBCOMMANDS)
def test_every_git_call_the_fault_undo_makes_is_bounded_and_the_fault_keeps_its_routing(
    undo_census, undo_stalls, subcommand,
):
    sc, got, shim = undo_census
    assert got == ("rc", 2), got
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert _stuck_classes(sc) == ["AuthorError"]

    window = [call for call in shim.calls() if call[1]]
    for where, _ran, stalled, outcome in _stalled_calls(undo_stalls, subcommand, window):
        assert outcome == ("rc", 2), f"{where}: {outcome}"
        assert stalled.pending_by_id()["f1"].get("attempts") == 1, where
        assert _stuck_classes(stalled) == ["AuthorError"], where
        assert stalled.head_files() == [], where


def _undo_scene(tmp_path: Path) -> Any:
    """The agent writes `PLANTED`, rewrites `SEEDED`, writes the flag `tmp_path / "agent-ran"`,
    and raises `AuthorError`: every git call after the flag is the fault undo's. The bound is
    `STALL_BOUND`."""
    def agent(rows, batch_id, cfg):
        put(cfg.corpus_dir / SEEDED, lesson_text("f0", mark="edited"))
        put(tmp_path / "agent-ran", "")
        raise drain.AuthorError("injected after the agent's edits")

    return _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}, also=agent),
                  git_timeout=STALL_BOUND)


def _undo_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
              stall_after: str = "") -> tuple[Any, tuple[str, Any], _Shim]:
    """`_undo_scene`'s tick, through a shim git that stalls every `stall_after` call once the
    agent has run (`""`: none)."""
    sc = _undo_scene(tmp_path)
    with monkeypatch.context() as patch:
        shim = _shim_git(tmp_path / "git-shim", patch, stall_after=stall_after,
                         flag=tmp_path / "agent-ran")
        got = _tick(sc, shim=shim)
    return sc, got, shim


def _assert_fault_kept(sc: Any, got: tuple[str, Any]) -> None:
    assert got == ("rc", 2), got
    assert sc.pending_by_id()["f1"].get("attempts") == 1
    assert _stuck_classes(sc) == ["AuthorError"]
    assert sc.head_files() == []


def _reached_after_agent(shim: _Shim, subcommand: str) -> bool:
    return any(ran and _subcommand(args) == subcommand for _n, ran, args in shim.calls())


def test_a_fault_undo_whose_rev_parse_does_not_answer_keeps_the_fault_and_deletes_nothing(
    tmp_path, monkeypatch,
):
    sc, got, shim = _undo_run(tmp_path, monkeypatch, stall_after="rev-parse")

    assert _reached_after_agent(shim, "rev-parse")
    _assert_fault_kept(sc, got)
    assert (sc.corpus / PLANTED).read_text(encoding="utf-8") == lesson_text("f1")


def test_a_fault_undo_whose_reset_does_not_answer_keeps_the_fault_and_still_restores(
    tmp_path, monkeypatch,
):
    sc, got, shim = _undo_run(tmp_path, monkeypatch, stall_after="reset")

    assert _reached_after_agent(shim, "reset")
    _assert_fault_kept(sc, got)
    assert not os.path.lexists(sc.corpus / PLANTED)
    assert (sc.corpus / SEEDED).read_text(encoding="utf-8") == lesson_text("f0")


def test_a_fault_undo_whose_status_does_not_answer_sweeps_what_git_ls_files_names(
    tmp_path, monkeypatch, caplog,
):
    caplog.set_level(logging.WARNING)
    sc, got, shim = _undo_run(tmp_path, monkeypatch, stall_after="status")

    assert _reached_after_agent(shim, "status")
    _assert_fault_kept(sc, got)
    assert shim.ran("ls-files", "--others")
    assert not os.path.lexists(sc.corpus / PLANTED)
    assert (sc.corpus / SEEDED).read_text(encoding="utf-8") == lesson_text("f0")
    fallback = [m for m in _warnings(caplog)
                if "swept the worktree files git ls-files names instead" in m]
    assert len(fallback) == 1, _warnings(caplog)


def test_control_a_fault_undo_whose_git_answers_sweeps_and_restores_without_a_fallback(
    tmp_path, monkeypatch, caplog,
):
    caplog.set_level(logging.WARNING)
    sc, got, shim = _undo_run(tmp_path, monkeypatch)

    _assert_fault_kept(sc, got)
    assert not shim.ran("ls-files", "--others")
    assert not os.path.lexists(sc.corpus / PLANTED)
    assert (sc.corpus / SEEDED).read_text(encoding="utf-8") == lesson_text("f0")
    assert _warnings(caplog) == []


def _gitkeep_scene(tmp_path: Path, plant: Callable[[Path], None]) -> Any:
    """The agent writes the attributable `PLANTED`, rewrites the corpus's tracked non-lesson
    `.gitkeep` (a stray the settle puts back with `_put_back`'s `git checkout`) and leaves
    `plant` at `<corpus>/.gitattributes`. No `git_timeout`: the deadline undercuts the default."""
    def agent(rows, batch_id, cfg):
        put(cfg.corpus_dir / ".gitkeep", "the agent was here\n")
        plant(cfg.corpus_dir / ".gitattributes")

    return _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}, also=agent))


def test_a_gitattributes_fifo_beside_a_rewritten_gitkeep_is_never_opened_by_its_checkout(
    tmp_path,
):
    sc = _gitkeep_scene(tmp_path, plant_fifo)
    fifo = sc.corpus / ".gitattributes"

    got = _tick(sc, fifos=[fifo])

    assert got == ("rc", 0), got
    assert _is_fifo(fifo)
    fifo.unlink()  # the plant observed; the test's own git calls below must not meet it
    assert sc.head_files() == [f"{LESSONS}/{PLANTED}"]
    assert (sc.corpus / ".gitkeep").read_text(encoding="utf-8") == ""
    assert _stuck_classes(sc) == []


def test_control_a_plain_gitattributes_beside_a_rewritten_gitkeep_is_reverted_with_it(tmp_path):
    """The positive control at the same address: a plain `.gitattributes` is reverted with the
    rewritten `.gitkeep`; the tick commits `PLANTED`."""
    sc = _gitkeep_scene(tmp_path, lambda at: put(at, "*.md -text\n"))

    got = _tick(sc)

    assert got == ("rc", 0), got
    assert not os.path.lexists(sc.corpus / ".gitattributes")
    assert sc.head_files() == [f"{LESSONS}/{PLANTED}"]
    assert (sc.corpus / ".gitkeep").read_text(encoding="utf-8") == ""


#: How long the shim holds the tick's first `git rev-parse` (the pre-agent HEAD read) before
#: answering: past `STALL_BOUND` and past any bound under 3 s, well short of `_LONG_BOUND`.
SLOW_READ = 4
_LONG_BOUND = 20.0


def _slow_head_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                   git_timeout: float) -> tuple[Any, tuple[str, Any], _Shim]:
    """A tick whose curator writes the attributable `PLANTED`, under `git_timeout`, through a
    shim git that holds the first `git rev-parse` `SLOW_READ` seconds before answering."""
    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}),
                git_timeout=git_timeout)
    with monkeypatch.context() as patch:
        shim = _shim_git(tmp_path / "git-shim", patch, delay_first=("rev-parse", SLOW_READ))
        got = _tick(sc, shim=shim)
    return sc, got, shim


def test_a_read_slower_than_a_short_git_timeout_is_a_probe_error_naming_it(tmp_path, monkeypatch):
    sc, got, _shim = _slow_head_run(tmp_path, monkeypatch, STALL_BOUND)

    result, exc = got
    assert result == "raised", got
    assert type(exc) is drain.GitProbeError, repr(exc)
    assert str(STALL_BOUND) in str(exc), str(exc)
    assert sc.curator.calls == []
    assert _stuck_classes(sc) == ["GitProbeError"]


def test_control_the_same_slow_read_answers_under_a_long_git_timeout(tmp_path, monkeypatch):
    sc, got, shim = _slow_head_run(tmp_path, monkeypatch, _LONG_BOUND)

    assert got == ("rc", 0), got
    assert shim.ran("rev-parse")
    assert sc.head_files() == [f"{LESSONS}/{PLANTED}"]


#: How long the scene's pre-commit hook takes: well past `STALL_BOUND`.
SLOW_HOOK = 4


def test_the_commit_is_not_bounded_a_pre_commit_hook_slower_than_git_timeout_still_commits(
    tmp_path,
):
    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")}),
                git_timeout=STALL_BOUND)
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    finished = tmp_path / "hook-finished"
    hook = hooks / "pre-commit"
    hook.write_text(f"#!/bin/sh\nsleep {SLOW_HOOK}\n: > '{finished}'\n", encoding="utf-8")
    hook.chmod(0o755)
    S.git(sc.repo, "config", "core.hooksPath", str(hooks))

    got = _tick(sc)

    assert got == ("rc", 0), got
    assert finished.exists(), "the pre-commit hook did not run to its end"
    assert sc.head_files() == [f"{LESSONS}/{PLANTED}"]
    assert _committed_blob(sc, PLANTED) == lesson_text("f1")


FORGED = lesson_text("f0", mark="the forged commit's bytes")


def _forged_head_repo(tmp_path: Path) -> Any:
    """A committed corpus holding `kept.md` and `replaced.md` (`ORIGINAL`), and a replace ref
    standing a forged sibling commit in for HEAD: its tree drops `kept.md` and carries `FORGED`
    for `replaced.md`. The worktree holds the real commit. The positive control (plain `git
    ls-tree HEAD`, which honours replace refs) lists the forged tree: the plant took."""
    w = world(tmp_path)
    put(w.corpus_dir / "kept.md", KEPT)
    put(w.corpus_dir / "replaced.md", ORIGINAL)
    w.commit()
    real = w.head()
    (w.corpus_dir / "kept.md").unlink()
    put(w.corpus_dir / "replaced.md", FORGED)
    w.commit("forged")
    forged = w.head()
    w.git("reset", "-q", "--hard", real)
    w.git("replace", "-f", real, forged)
    listed = w.git("ls-tree", "-r", "--name-only", "HEAD", "--", LESSONS).stdout.split()
    assert listed == [f"{LESSONS}/.gitkeep", _REPLACED], listed
    return w


def test_git_tree_blobs_reads_the_real_commits_tree_not_a_replacement_commit(tmp_path):
    w = _forged_head_repo(tmp_path)

    assert _git.git_tree_blobs(w.repo, "HEAD", LESSONS) == {
        f"{LESSONS}/.gitkeep": b"", f"{LESSONS}/kept.md": KEPT.encode(),
        _REPLACED: ORIGINAL.encode()}


def test_git_unchanged_since_compares_with_the_real_commits_tree_not_a_replacement_commit(
    tmp_path,
):
    w = _forged_head_repo(tmp_path)

    assert _git.git_unchanged_since(w.repo, "HEAD", LESSONS) == frozenset(
        {f"{LESSONS}/.gitkeep", f"{LESSONS}/kept.md", _REPLACED})
