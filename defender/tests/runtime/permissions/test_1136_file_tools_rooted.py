from __future__ import annotations

import contextlib
import os
import signal
import stat
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest


pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender._io import ALIAS_READ_REFUSAL  # noqa: E402
from defender.agents import MAIN_DEF  # noqa: E402
from defender.learning.author.curator_engine import CuratorDeps  # noqa: E402
from defender.investigation.tools.lesson_read import _tool_lesson_read  # noqa: E402
from defender.investigation import permission  # noqa: E402
from defender.investigation.agent_definition import bind  # noqa: E402
from defender.investigation.tools import (  # noqa: E402
    _tool_append_block,
    _tool_edit_file,
    _tool_fix_row,
    _tool_read_file,
    _tool_write_file,
    read_companion,
)
from defender.tests.support.learning.curation._curator_691_harness import make_worktree, pending_run_dir  # noqa: E402


#: The host file's bytes. Distinctive, so "the message carries no host bytes" is checkable.
HOST = "HOST-SECRET-1136 do not disclose\n"
HOST_MARK = "HOST-SECRET-1136"


# ---------------------------------------------------------------------------------------------
# fixtures


def _host_file(tmp_path: Path) -> Path:
    """A file outside every root the tools are bound to."""
    d = tmp_path / "outside"
    d.mkdir(exist_ok=True)
    f = d / "secret.txt"
    f.write_text(HOST, encoding="utf-8")
    return f


def _snapshot(path: Path) -> tuple[bytes, int, int, int, tuple[str, ...]]:
    """What a refused write must leave alone: the target's bytes, inode, link count and mode,
    and the listing of the folder holding it (no new entry beside it either)."""
    st = os.lstat(path)
    return (
        path.read_bytes(), st.st_ino, st.st_nlink, st.st_mode,
        tuple(sorted(os.listdir(path.parent))),
    )


def _main(tmp_path: Path, *, run: Path | None = None):
    """MAIN deps through the real `bind`, as `test_append_only_write_lane_810` builds them."""
    if run is None:
        run = tmp_path / "run"
        run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    return bind(MAIN_DEF, run, defender_dir=dfn), run


def _curator(tmp_path: Path, *, repo_root: Path | None = None) -> tuple[CuratorDeps, Path]:
    """A curator on a worktree tree through the production `CuratorDeps.for_run` (its read
    confine is stored resolved, its `cwd_anchor`/`defender_dir` raw). Returns the deps and the
    corpus folder as the test spells it."""
    wt = make_worktree(tmp_path) if repo_root is None else repo_root
    corpus = wt / "defender" / "lessons"
    deps = CuratorDeps.for_run(pending_run_dir(tmp_path), wt, corpus, box=None)
    return deps, corpus


@contextlib.contextmanager
def _within(seconds: int = 5) -> Iterator[None]:
    """Fail, rather than wedge CI, when a tool blocks on a planted FIFO."""

    def _late(signum, frame):
        raise AssertionError("a file tool blocked on a FIFO planted at the name")

    previous = signal.signal(signal.SIGALRM, _late)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _refused(call: Callable[[], object]) -> str:
    """The call's `ModelRetry` text. Anything else — a return, an `OSError`, a `ValueError` —
    fails the test with what actually happened."""
    try:
        out = call()
    except ModelRetry as e:
        return str(e)
    except Exception as e:  # noqa: BLE001 — the point is to name what escaped
        pytest.fail(f"expected a ModelRetry, got {type(e).__name__}: {e}")
    pytest.fail(f"expected a ModelRetry, the call returned: {out!r}")


# ---------------------------------------------------------------------------------------------
# hard link at the name


def test_read_file_refuses_a_hard_link_to_a_host_file(tmp_path):
    deps, run = _main(tmp_path)
    host = _host_file(tmp_path)
    notes = run / "notes.txt"

    notes.write_text("plain notes\n", encoding="utf-8")
    assert "plain notes" in _tool_read_file(deps, "notes.txt")

    notes.unlink()
    os.link(host, notes)
    message = _refused(lambda: _tool_read_file(deps, "notes.txt"))
    assert HOST_MARK not in message


def test_lesson_read_refuses_a_hard_link_to_a_host_file(tmp_path):
    """The same leak through the curator's `lesson_read`, on a lesson inside its confine."""
    deps, corpus = _curator(tmp_path)
    host = _host_file(tmp_path)
    lesson = corpus / "x.md"

    lesson.write_text("plain lesson\n", encoding="utf-8")
    assert "plain lesson" in _tool_lesson_read(deps, "defender/lessons/x.md", part="full")

    lesson.unlink()
    os.link(host, lesson)
    message = _refused(lambda: _tool_lesson_read(deps, "defender/lessons/x.md", part="full"))
    assert HOST_MARK not in message


@pytest.mark.parametrize("tool", ["write_file", "edit_file"])
def test_a_write_over_a_hard_link_is_a_retry_and_the_host_file_is_unchanged(tool, tmp_path):
    deps, corpus = _curator(tmp_path)
    host = _host_file(tmp_path)
    lesson = corpus / "x.md"
    name = "defender/lessons/x.md"

    def write(old: str) -> str:
        if tool == "write_file":
            return _tool_write_file(deps, name, "OVERWRITTEN\n")
        return _tool_edit_file(deps, name, old, "OVERWRITTEN")

    lesson.write_text("plain body\n", encoding="utf-8")
    write("plain body")
    assert lesson.read_text(encoding="utf-8").startswith("OVERWRITTEN")

    lesson.unlink()
    os.link(host, lesson)
    before = _snapshot(host)
    message = _refused(lambda: write(HOST_MARK))
    assert HOST_MARK not in message
    assert _snapshot(host) == before, "the refused write reached the host file"


# ---------------------------------------------------------------------------------------------
# a symlink at the name, pointing INSIDE the allowed tree


def test_read_file_refuses_a_symlink_at_the_name(tmp_path):
    """`run/link.txt -> run/notes.txt`: the gate resolves the link to a run-dir file and admits
    it, so only the read can refuse following it. The file under its own name reads as today."""
    deps, run = _main(tmp_path)
    (run / "notes.txt").write_text("plain notes\n", encoding="utf-8")
    os.symlink(run / "notes.txt", run / "link.txt")

    assert "plain notes" in _tool_read_file(deps, "notes.txt")
    _refused(lambda: _tool_read_file(deps, "link.txt"))


def test_write_file_over_a_symlink_at_the_name_is_a_retry_and_leaves_both(tmp_path):
    deps, corpus = _curator(tmp_path)
    real = corpus / "real.md"
    real.write_text("ORIGINAL lesson\n", encoding="utf-8")  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant
    link = corpus / "link.md"
    os.symlink(real, link)
    before = _snapshot(real)

    _refused(lambda: _tool_write_file(deps, "defender/lessons/link.md", "REDIRECTED\n"))
    assert _snapshot(real) == before, "the refused write reached the linked lesson"
    assert os.path.islink(link), "the refusal replaced the planted link"

    _tool_write_file(deps, "defender/lessons/real.md", "REWRITTEN\n")  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant
    assert real.read_text(encoding="utf-8") == "REWRITTEN\n"  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant


# ---------------------------------------------------------------------------------------------
# a symlinked holding folder that points INSIDE the allowed tree


def test_read_file_refuses_a_symlinked_holding_folder_inside_the_run_dir(tmp_path):
    deps, run = _main(tmp_path)
    (run / "gather_summaries").mkdir()
    (run / "gather_summaries" / "l-001.md").write_text("INSIDE\n", encoding="utf-8")
    os.symlink(run / "gather_summaries", run / "alias", target_is_directory=True)

    assert "INSIDE" in _tool_read_file(deps, "gather_summaries/l-001.md")
    _refused(lambda: _tool_read_file(deps, "alias/l-001.md"))


def test_a_curator_refuses_a_symlinked_holding_folder_inside_its_tree(tmp_path):
    deps, corpus = _curator(tmp_path)
    lesson = corpus / "a.md"
    lesson.write_text("ORIGINAL lesson\n", encoding="utf-8")  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant
    os.symlink(corpus, corpus.parent / "lessons-alias", target_is_directory=True)

    assert "ORIGINAL lesson" in _tool_lesson_read(deps, "defender/lessons/a.md", part="full")  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant
    _refused(lambda: _tool_lesson_read(deps, "defender/lessons-alias/a.md", part="full"))

    before = _snapshot(lesson)
    _refused(lambda: _tool_write_file(deps, "defender/lessons-alias/a.md", "REDIRECTED\n"))
    assert _snapshot(lesson) == before, "the refused write landed through the linked folder"

    _tool_write_file(deps, "defender/lessons/a.md", "REWRITTEN\n")  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant
    assert lesson.read_text(encoding="utf-8") == "REWRITTEN\n"  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant


# ---------------------------------------------------------------------------------------------
# a FIFO at the name


def _fifo_read_main(tmp_path: Path) -> Callable[[], object]:
    deps, run = _main(tmp_path)
    os.mkfifo(run / "pipe.txt")
    return lambda: _tool_read_file(deps, "pipe.txt")


def _fifo_lesson_read(tmp_path: Path) -> Callable[[], object]:
    deps, corpus = _curator(tmp_path)
    os.mkfifo(corpus / "pipe.md")
    return lambda: _tool_lesson_read(deps, "defender/lessons/pipe.md", part="full")


def _fifo_edit_preread(tmp_path: Path) -> Callable[[], object]:
    deps, corpus = _curator(tmp_path)
    os.mkfifo(corpus / "pipe.md")
    return lambda: _tool_edit_file(deps, "defender/lessons/pipe.md", "anything", "else")


@pytest.mark.parametrize(
    "arm", [_fifo_read_main, _fifo_lesson_read, _fifo_edit_preread],
    ids=["read_file", "lesson_read", "edit_file-preread"],
)
def test_a_fifo_at_the_name_never_blocks_a_read(arm, tmp_path):
    """A reader-less FIFO at the name: every reading tool answers at once, as a retry. An open
    that blocks on it would wedge the run, so the arm enforces its own bound."""
    call = arm(tmp_path)
    with _within():
        _refused(call)


@pytest.mark.parametrize("tool", ["write_file", "edit_file-create"])
def test_a_fifo_at_the_name_refuses_a_write_as_a_retry(tool, tmp_path):
    deps, corpus = _curator(tmp_path)
    pipe = corpus / "pipe.md"
    os.mkfifo(pipe)
    name = "defender/lessons/pipe.md"

    with _within():
        if tool == "write_file":
            _refused(lambda: _tool_write_file(deps, name, "NEW\n"))
        else:
            _refused(lambda: _tool_edit_file(deps, name, "", "NEW\n"))
    assert stat.S_ISFIFO(os.lstat(pipe).st_mode), "the refusal replaced the planted entry"


# ---------------------------------------------------------------------------------------------
# a `..` component


def test_read_file_refuses_a_dotdot_component(tmp_path):
    deps, run = _main(tmp_path)
    (run / "sub").mkdir()
    (run / "notes.txt").write_text("plain notes\n", encoding="utf-8")

    assert "plain notes" in _tool_read_file(deps, "notes.txt")
    _refused(lambda: _tool_read_file(deps, "sub/../notes.txt"))


def test_write_file_refuses_a_dotdot_component(tmp_path):
    """A `..` that stays inside the corpus: today the write lands. It must be refused and land
    nothing; without the `..` the same lesson lands as today."""
    deps, corpus = _curator(tmp_path)

    _refused(lambda: _tool_write_file(deps, "defender/lessons/../lessons/new.md", "NEW\n"))
    assert not (corpus / "new.md").exists(), "the refused write landed"

    _tool_write_file(deps, "defender/lessons/new.md", "NEW\n")
    assert (corpus / "new.md").read_text(encoding="utf-8") == "NEW\n"


# ---------------------------------------------------------------------------------------------
# plain trees spelled through a symlinked root keep working


def _spellings(link_root: Path, real_root: Path, rel: str) -> dict[str, str]:
    return {
        "relative": rel,
        "absolute-through-link": str(link_root / rel),
        "absolute-resolved": str(real_root / rel),
    }


@pytest.mark.parametrize("spelling", ["relative", "absolute-through-link", "absolute-resolved"])
def test_a_curator_on_a_symlinked_repo_root_reads_and_writes_as_today(spelling, tmp_path):
    real = make_worktree(tmp_path)
    link = tmp_path / "wt-link"
    os.symlink(real, link, target_is_directory=True)
    deps, _corpus = _curator(tmp_path, repo_root=link)
    real_corpus = real / "defender" / "lessons"
    (real_corpus / "a.md").write_text("plain lesson\n", encoding="utf-8")

    read_path = _spellings(link, real, "defender/lessons/a.md")[spelling]
    if spelling != "relative":
        read_path = deps.view.to_model(Path(read_path))
    assert "plain lesson" in _tool_lesson_read(deps, read_path, part="full")

    write_path = _spellings(link, real, "defender/lessons/new.md")[spelling]
    if spelling != "relative":
        write_path = deps.view.to_model(Path(write_path))
    _tool_write_file(deps, write_path, "first line\n")
    assert (real_corpus / "new.md").read_text(encoding="utf-8") == "first line\n"

    _tool_edit_file(deps, write_path, "first line", "edited line")
    assert (real_corpus / "new.md").read_text(encoding="utf-8") == "edited line\n"


@pytest.mark.parametrize("spelling", ["relative", "model-absolute"])
def test_main_on_a_run_dir_under_a_symlinked_ancestor_reads_and_appends_as_today(
    spelling, tmp_path
):
    real_base = tmp_path / "real"
    real_base.mkdir()
    link_base = tmp_path / "linked"
    os.symlink(real_base, link_base, target_is_directory=True)
    (real_base / "run").mkdir()
    deps, _run = _main(tmp_path, run=link_base / "run")
    (real_base / "run" / "notes.txt").write_text("plain notes\n", encoding="utf-8")

    read_path = {"relative": "notes.txt", "model-absolute": "/runs/current/notes.txt"}[spelling]
    assert "plain notes" in _tool_read_file(deps, read_path)
    for host in (str(link_base / "run" / "notes.txt"), str(real_base / "run" / "notes.txt")):
        refusal = _refused(lambda host=host: _tool_read_file(deps, host))
        assert "plain notes" not in refusal, f"a host spelling was read: {host}"

    _tool_append_block(deps, "+ first\n")
    _tool_append_block(deps, "+ second\n")
    inv = real_base / "run" / "investigation.md"
    assert inv.read_text(encoding="utf-8") == "+ first\n+ second\n"


# ---------------------------------------------------------------------------------------------
# investigation.md: the companion read and MAIN's writes


def test_the_companion_keeps_its_three_way_split_over_a_hard_link(tmp_path):
    deps, run = _main(tmp_path)
    inv = run / "investigation.md"

    absent = read_companion(deps)
    assert (absent.text, absent.refusal) == ("", None)

    inv.write_text("+ plain\n", encoding="utf-8")
    assert read_companion(deps).text == "+ plain\n"

    inv.unlink()
    os.link(_host_file(tmp_path), inv)
    planted = read_companion(deps)
    assert planted.text is None
    assert planted.retryable is False, "a planted entry is not a passing fault"
    assert ALIAS_READ_REFUSAL in (planted.refusal or "")
    assert HOST_MARK not in (planted.refusal or "")


@pytest.mark.parametrize("tool", ["append_block", "fix_row"])
def test_main_writes_over_a_hard_link_are_retries_and_leave_the_host_file(tool, tmp_path):
    deps, run = _main(tmp_path)
    host = _host_file(tmp_path)
    os.link(host, run / "investigation.md")
    before = _snapshot(host)

    if tool == "append_block":
        message = _refused(lambda: _tool_append_block(deps, "+ appended\n"))
    else:
        message = _refused(lambda: _tool_fix_row(deps, HOST.strip(), "+ repaired"))
    assert HOST_MARK not in message
    assert _snapshot(host) == before, "the refused write reached the host file"


def test_the_write_gate_does_not_take_its_baseline_through_a_hard_link(tmp_path):
    deps, run = _main(tmp_path)
    inv = run / "investigation.md"
    baseline = "+ first\n"
    proposal = baseline + "+ second\n"

    def decide():
        return permission.decide_write(
            inv, proposal, run_dir=deps.run_dir, defender_dir=deps.defender_dir,
            policy=deps.policy,
        )

    inv.write_text(baseline, encoding="utf-8")
    assert decide().allow, "the plain-file control: an extending append is allowed today"

    inv.unlink()
    host = tmp_path / "outside" / "inv.md"
    host.parent.mkdir()
    host.write_text(baseline, encoding="utf-8")
    os.link(host, inv)
    assert not decide().allow, "the gate took its baseline through a hard link"


# ---------------------------------------------------------------------------------------------
# the static guard: the touched sites call no path seam


def test_a_folder_link_two_levels_above_the_name_is_refused_for_reads(tmp_path):
    deps, run = _main(tmp_path)
    (run / "gather_summaries").mkdir()
    (run / "gather_summaries" / "l-001.md").write_text("INSIDE\n", encoding="utf-8")
    os.symlink(run, run / "g", target_is_directory=True)

    assert "INSIDE" in _tool_read_file(deps, "gather_summaries/l-001.md")
    message = _refused(lambda: _tool_read_file(deps, "g/gather_summaries/l-001.md"))
    assert "INSIDE" not in message


def test_lesson_read_and_edit_file_refuse_a_symlink_at_the_name(tmp_path):
    deps, corpus = _curator(tmp_path)
    real = corpus / "a.md"
    real.write_text("ORIGINAL lesson\n", encoding="utf-8")  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant
    link = corpus / "b.md"
    os.symlink(real, link)

    message = _refused(lambda: _tool_lesson_read(deps, "defender/lessons/b.md", part="full"))
    assert "ORIGINAL" not in message  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant
    before = _snapshot(real)
    _refused(lambda: _tool_edit_file(deps, "defender/lessons/b.md", "ORIGINAL", "REDIRECTED"))  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant
    assert _snapshot(real) == before, "edit_file wrote through the link"
    assert os.path.islink(link), "the refusal replaced the planted link"

    _tool_edit_file(deps, "defender/lessons/a.md", "ORIGINAL", "EDITED")  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant
    assert real.read_text(encoding="utf-8") == "EDITED lesson\n"


def test_the_write_gate_over_a_fifo_at_investigation_md_denies_without_blocking(tmp_path):
    deps, run = _main(tmp_path)
    inv = run / "investigation.md"
    proposal = "+ first\n+ second\n"

    def decide():
        return permission.decide_write(
            inv, proposal, run_dir=deps.run_dir, defender_dir=deps.defender_dir,
            policy=deps.policy,
        )

    inv.write_text("+ first\n", encoding="utf-8")
    assert decide().allow
    inv.unlink()
    os.mkfifo(inv)
    with _within():
        assert not decide().allow, "the gate took a FIFO as the baseline"


# ---------------------------------------------------------------------------------------------
# review round (#1208): a plain folder is "file not found", and no refusal names a host path


@pytest.mark.parametrize("tool", ["read_file", "write_file"])
def test_a_refusal_names_no_host_path(tool, tmp_path):
    """The refusal a planted hard link earns names the model's own path, never the host's
    spelling of the root (agents are not told where their run dir is)."""
    if tool == "read_file":
        deps, run = _main(tmp_path)
        os.link(_host_file(tmp_path), run / "notes.txt")
        message = _refused(lambda: _tool_read_file(deps, "notes.txt"))
        root = run
    else:
        deps, corpus = _curator(tmp_path)
        os.link(_host_file(tmp_path), corpus / "x.md")
        message = _refused(lambda: _tool_write_file(deps, "defender/lessons/x.md", "NEW\n"))
        root = corpus
    assert str(tmp_path) not in message, message
    assert str(root.resolve()) not in message, message


# ---------------------------------------------------------------------------------------------
# second review round (#1208): a confine is never a trust root; `//`; the refusal kind
