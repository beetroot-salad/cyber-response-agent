"""#1136 — the model's file tools reach the host through the rooted core, not the path seams.

The tools keep taking paths exactly as the agent sees them (absolute, or relative to
`deps.cwd_anchor`); only the host I/O below them moves onto `defender/_io.py`'s rooted core
(`bind(root).read(name)`, `rooted_mkdir` + `rooted_write`). That is a refactor, so plain trees
must look exactly as they do today — the existing tool tests guard that, and the positive
controls here re-pin the shapes the move could break (a symlinked repo root for a curator, a run
dir spelled through a symlinked ancestor).

What comes with the core, accepted rather than sought, and pinned by a few tests rather than a
matrix:

  * a hard link, a link at the name, a FIFO or a symlinked holding folder on the path is
    refused as a `ModelRetry` instead of followed — never a raw `OSError`/`ValueError`
    traceback, never a hang — and a refused write leaves the planted target byte-for-byte as
    it was;
  * so the hard-link read leak closes: today `read_file` as MAIN returns the bytes of a hard
    link in the run dir to a file outside every read root;
  * a `..` component in a model path is refused with a `ModelRetry`;
  * `read_companion` keeps its three-way split (never written → `""`; planted or undecodable
    → `None`, not retryable; I/O fault → retryable).

The symlinked holding folders here point INSIDE the allowed tree on purpose: the permission
gate resolves the path and admits it, so only the I/O layer can refuse.

Every plant is a real one (`os.link`, `os.symlink`, `os.mkfifo`); no `monkeypatch.setattr`.
"""
from __future__ import annotations

import ast
import contextlib
import os
import signal
import stat
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender._io import ALIAS_READ_REFUSAL  # noqa: E402
from defender.agents import MAIN_DEF  # noqa: E402
from defender.learning.author.curator_engine import CuratorDeps  # noqa: E402
from defender.learning.author.lesson_read import _tool_lesson_read  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.tools import (  # noqa: E402
    _tool_append_block,
    _tool_edit_file,
    _tool_fix_row,
    _tool_read_file,
    _tool_write_file,
    read_companion,
)
from defender.tests._curator_691_harness import make_worktree, pending_run_dir  # noqa: E402

_DEFENDER = Path(__file__).resolve().parents[1]

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
    """The C1 leak: a hard link in the run dir to a file outside every read root. `resolve()`
    does not see through a hard link, so the gate admits it; the read must refuse it, and the
    retry must carry no host bytes. Same address, plain file first: it reads as today."""
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
    """A writer over a hard link at the name: today the guarded write refuses it by raising an
    `OSError` straight out of the tool. It must reach the model as a retry, and the host file
    the link shares an inode with must be byte-for-byte unchanged.

    `edit_file`'s `old_string` is text the HOST file holds, so its pre-read is what decides: a
    `old_string` absent from it would be refused as "not found" on any code and prove nothing.
    Same address, plain file first: the write lands as today."""
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
    """`lessons/link.md -> lessons/real.md`: a writable lesson name the gate admits. Today the
    guarded write refuses the link by raising out of the tool. It must be a retry; the lesson
    the link points at is unchanged and the link itself still stands."""
    deps, corpus = _curator(tmp_path)
    real = corpus / "real.md"
    real.write_text("ORIGINAL lesson\n", encoding="utf-8")
    link = corpus / "link.md"
    os.symlink(real, link)
    before = _snapshot(real)

    _refused(lambda: _tool_write_file(deps, "defender/lessons/link.md", "REDIRECTED\n"))
    assert _snapshot(real) == before, "the refused write reached the linked lesson"
    assert os.path.islink(link), "the refusal replaced the planted link"

    _tool_write_file(deps, "defender/lessons/real.md", "REWRITTEN\n")
    assert real.read_text(encoding="utf-8") == "REWRITTEN\n"


# ---------------------------------------------------------------------------------------------
# a symlinked holding folder that points INSIDE the allowed tree


def test_read_file_refuses_a_symlinked_holding_folder_inside_the_run_dir(tmp_path):
    """`run/alias -> run/gather_summaries`: the gate resolves `alias/l-001.md` to a gather
    summary, a shape MAIN may read, and admits it. Only the read can refuse following the link.
    The same file through the real folder reads as today."""
    deps, run = _main(tmp_path)
    (run / "gather_summaries").mkdir()
    (run / "gather_summaries" / "l-001.md").write_text("INSIDE\n", encoding="utf-8")
    os.symlink(run / "gather_summaries", run / "alias", target_is_directory=True)

    assert "INSIDE" in _tool_read_file(deps, "gather_summaries/l-001.md")
    _refused(lambda: _tool_read_file(deps, "alias/l-001.md"))


def test_a_curator_refuses_a_symlinked_holding_folder_inside_its_tree(tmp_path):
    """`defender/lessons-alias -> defender/lessons`: the resolved path is a lesson inside the
    confine and a name the curator's write allowlist admits, so the gate passes both the read
    and the write. Both must be refused, and the lesson the link points at must be unchanged
    (today the write's folder walk raises `OSError` out of the tool). The same lesson through the
    real folder reads and writes as today."""
    deps, corpus = _curator(tmp_path)
    lesson = corpus / "a.md"
    lesson.write_text("ORIGINAL lesson\n", encoding="utf-8")
    os.symlink(corpus, corpus.parent / "lessons-alias", target_is_directory=True)

    assert "ORIGINAL lesson" in _tool_lesson_read(deps, "defender/lessons/a.md", part="full")
    _refused(lambda: _tool_lesson_read(deps, "defender/lessons-alias/a.md", part="full"))

    before = _snapshot(lesson)
    _refused(lambda: _tool_write_file(deps, "defender/lessons-alias/a.md", "REDIRECTED\n"))
    assert _snapshot(lesson) == before, "the refused write landed through the linked folder"

    _tool_write_file(deps, "defender/lessons/a.md", "REWRITTEN\n")
    assert lesson.read_text(encoding="utf-8") == "REWRITTEN\n"


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
    """A writer over a FIFO at the name: today the guarded write raises `OSError` out of the
    tool (`edit_file` with an empty `old_string` reads the FIFO as "no file" and tries to
    create). It must be a retry, and the FIFO must still stand where it was."""
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
    """`sub/../notes.txt` resolves to a file the gate admits; the path is refused anyway. `sub`
    exists, so the refusal cannot be today's "file not found" for a missing folder. Without the
    `..` the same file reads as today."""
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
    """The operator's repo root is a symlink. The curator's read confine is stored resolved
    while its `cwd_anchor` and `defender_dir` keep the operator's spelling, so a plain relative
    path never sits lexically under a confine member — turning the path into (root, name) must
    still find its root. Every spelling the agent may use reads, writes and edits a plain
    lesson exactly as today."""
    real = make_worktree(tmp_path)
    link = tmp_path / "wt-link"
    os.symlink(real, link, target_is_directory=True)
    deps, _corpus = _curator(tmp_path, repo_root=link)
    real_corpus = real / "defender" / "lessons"
    (real_corpus / "a.md").write_text("plain lesson\n", encoding="utf-8")

    read_path = _spellings(link, real, "defender/lessons/a.md")[spelling]
    assert "plain lesson" in _tool_lesson_read(deps, read_path, part="full")

    write_path = _spellings(link, real, "defender/lessons/new.md")[spelling]
    _tool_write_file(deps, write_path, "first line\n")
    assert (real_corpus / "new.md").read_text(encoding="utf-8") == "first line\n"

    _tool_edit_file(deps, write_path, "first line", "edited line")
    assert (real_corpus / "new.md").read_text(encoding="utf-8") == "edited line\n"


@pytest.mark.parametrize("spelling", ["relative", "absolute-through-link", "absolute-resolved"])
def test_main_on_a_run_dir_under_a_symlinked_ancestor_reads_and_appends_as_today(
    spelling, tmp_path
):
    """The run dir sits under a symlinked ancestor (the macOS `/tmp` shape): the root is the
    host's spelling and is followed. Every spelling reads a plain file, and `append_block` lands
    in `investigation.md`, exactly as today."""
    real_base = tmp_path / "real"
    real_base.mkdir()
    link_base = tmp_path / "linked"
    os.symlink(real_base, link_base, target_is_directory=True)
    (real_base / "run").mkdir()
    deps, _run = _main(tmp_path, run=link_base / "run")
    (real_base / "run" / "notes.txt").write_text("plain notes\n", encoding="utf-8")

    read_path = _spellings(link_base / "run", real_base / "run", "notes.txt")[spelling]
    assert "plain notes" in _tool_read_file(deps, read_path)

    _tool_append_block(deps, "+ first\n")
    _tool_append_block(deps, "+ second\n")
    inv = real_base / "run" / "investigation.md"
    assert inv.read_text(encoding="utf-8") == "+ first\n+ second\n"


# ---------------------------------------------------------------------------------------------
# investigation.md: the companion read and MAIN's writes


def test_the_companion_keeps_its_three_way_split_over_a_hard_link(tmp_path):
    """`read_companion` through the move: never written is `""`; a plain document is its text;
    a hard link at `investigation.md` is a planted entry — no text, and NOT retryable (no retry
    changes the document's state; the host closes the case)."""
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
    """MAIN's two writes of `investigation.md` over a hard link to a host file: a retry, never an
    `OSError`, and the host file is byte-for-byte unchanged. (Today the companion read refuses
    the plant before the bare write is reached, so this holds already; it guards the move.)"""
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
    """The write gate reads `investigation.md`'s current text as the append-only baseline. Over
    a hard link to a host file, that baseline is the host's bytes: today a proposal extending
    them is ALLOWED. The baseline read goes through the core, so the plant is a read refusal and
    the gate fails closed. The same bytes in a plain file are a baseline, and allow as today."""
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


#: The path seams the file tools leave: each follows the caller's path spelling.
_SEAMS = frozenset({
    "write_guarded", "read_guarded", "read_plain", "read_plain_bytes", "read_bytes_guarded",
    "read_text_utf8", "read_text_soft", "guarded_mkdir", "locked_for_rewrite",
    "locked_for_read", "open_guarded", "write_atomic", "append_jsonl",
})

#: Path-following probes and I/O no file tool may call on a model path.
_PATH_IO = frozenset({
    "is_file", "read_text", "read_bytes", "write_text", "write_bytes", "open", "mkdir",
    "makedirs",
})


def _offences(nodes: Sequence[ast.AST]) -> list[str]:
    """Every seam reference and path-following call under `nodes`, by resolved name rather than
    spelling: an imported seam is flagged whatever alias binds it, an attribute access is flagged
    whatever object it is taken off, and a seam named as a string (`getattr`) is flagged too."""
    found: list[str] = []
    for top in nodes:
        for node in ast.walk(top):
            if isinstance(node, ast.ImportFrom):
                found += [f"imports {a.name}" for a in node.names if a.name in _SEAMS]
            elif isinstance(node, ast.Attribute) and node.attr in _SEAMS:
                found.append(f"references .{node.attr}")
            elif isinstance(node, ast.Name) and node.id in _SEAMS:
                found.append(f"uses {node.id}")
            elif isinstance(node, ast.Constant) and node.value in _SEAMS:
                found.append(f"names {node.value!r}")
            elif isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Attribute) and fn.attr in _PATH_IO:
                    found.append(f"calls .{fn.attr}()")
                elif isinstance(fn, ast.Name) and fn.id == "open":
                    found.append("calls open()")
    return found


def _module(rel: str) -> ast.Module:
    return ast.parse((_DEFENDER / rel).read_text(encoding="utf-8"))


def _decide_write_and_its_helpers() -> list[ast.AST]:
    """`decide_write` and every module-level function of `permission/files.py` it reaches by
    name, so a baseline read moved into a helper is still in scope. (Its unused twin
    `_decide_investigation_write` was deleted.)"""
    tree = _module("runtime/permission/files.py")
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    seen: dict[str, ast.AST] = {}
    todo = ["decide_write"]
    while todo:
        name = todo.pop()
        if name in seen or name not in funcs:
            continue
        seen[name] = funcs[name]
        todo += [
            c.func.id for c in ast.walk(funcs[name])
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
        ]
    assert "decide_write" in seen, "permission/files.py no longer defines decide_write"
    return list(seen.values())


@pytest.mark.parametrize("site", [
    "runtime/tools/_files.py",
    "runtime/tools/_document.py",
    "runtime/tools/_bash.py",
    "permission.decide_write",
])
def test_the_file_tools_call_no_path_seam(site):
    """The census half of the refactor: the file tools' modules (`_files.py`, `_document.py`,
    `_bash.py`, home of the folder-making helper) and the write gate's baseline read reference
    none of the path seams, and call no path-following probe or open on a path. Their host I/O
    goes through the rooted core instead. This feeds #1105's ratchet."""
    nodes = (
        _decide_write_and_its_helpers() if site == "permission.decide_write" else [_module(site)]
    )
    assert _offences(nodes) == [], f"{site} still reaches the host through a path seam"


# ---------------------------------------------------------------------------------------------
# adversary round (#1136): plants deeper than the immediate parent, a link at the name for the
# remaining tools, the gate's baseline over a FIFO, a census by object, and today's messages


def test_a_folder_link_two_levels_above_the_name_is_refused_for_reads(tmp_path):
    """`run/g -> run`: `g/gather_summaries/l-001.md` resolves to a summary MAIN may read, so the
    gate admits it. A link anywhere on the path is refused, not only at the immediate parent.
    The real path reads as today."""
    deps, run = _main(tmp_path)
    (run / "gather_summaries").mkdir()
    (run / "gather_summaries" / "l-001.md").write_text("INSIDE\n", encoding="utf-8")
    os.symlink(run, run / "g", target_is_directory=True)

    assert "INSIDE" in _tool_read_file(deps, "gather_summaries/l-001.md")
    message = _refused(lambda: _tool_read_file(deps, "g/gather_summaries/l-001.md"))
    assert "INSIDE" not in message


def test_a_folder_link_two_levels_above_the_name_is_refused_for_curator_io(tmp_path):
    """`defender/alias -> defender`: `defender/alias/lessons/a.md` resolves to a lesson the
    curator may read and write. Both are refused and the lesson is unchanged; the real path
    reads and writes as today."""
    deps, corpus = _curator(tmp_path)
    lesson = corpus / "a.md"
    lesson.write_text("ORIGINAL lesson\n", encoding="utf-8")
    os.symlink(corpus.parent, corpus.parent / "alias", target_is_directory=True)
    deep = "defender/alias/lessons/a.md"

    _refused(lambda: _tool_lesson_read(deps, deep, part="full"))
    before = _snapshot(lesson)
    _refused(lambda: _tool_write_file(deps, deep, "REDIRECTED\n"))
    _refused(lambda: _tool_edit_file(deps, deep, "ORIGINAL", "REDIRECTED"))
    assert _snapshot(lesson) == before, "a write landed through the linked folder"

    assert "ORIGINAL lesson" in _tool_lesson_read(deps, "defender/lessons/a.md", part="full")
    _tool_write_file(deps, "defender/lessons/a.md", "REWRITTEN\n")
    assert lesson.read_text(encoding="utf-8") == "REWRITTEN\n"


def test_lesson_read_and_edit_file_refuse_a_symlink_at_the_name(tmp_path):
    """`lessons/b.md -> lessons/a.md`, a name the gate admits for both tools: `lesson_read`
    returns none of `a.md`'s bytes, `edit_file` leaves `a.md` unchanged and the link standing.
    `a.md` itself reads and edits as today."""
    deps, corpus = _curator(tmp_path)
    real = corpus / "a.md"
    real.write_text("ORIGINAL lesson\n", encoding="utf-8")
    link = corpus / "b.md"
    os.symlink(real, link)

    message = _refused(lambda: _tool_lesson_read(deps, "defender/lessons/b.md", part="full"))
    assert "ORIGINAL" not in message
    before = _snapshot(real)
    _refused(lambda: _tool_edit_file(deps, "defender/lessons/b.md", "ORIGINAL", "REDIRECTED"))
    assert _snapshot(real) == before, "edit_file wrote through the link"
    assert os.path.islink(link), "the refusal replaced the planted link"

    _tool_edit_file(deps, "defender/lessons/a.md", "ORIGINAL", "EDITED")
    assert real.read_text(encoding="utf-8") == "EDITED lesson\n"


def test_the_write_gate_over_a_fifo_at_investigation_md_denies_without_blocking(tmp_path):
    """The gate's append-only baseline over a reader-less FIFO at `investigation.md`: it answers
    at once and denies (the baseline could not be read), never blocks the run. A plain file is
    a baseline, and an extending append is allowed."""
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


def test_the_file_tools_hold_no_path_seam_by_object():
    """The census by object, not spelling: no module-level name of the file tools' modules (the
    whole `runtime/tools` package's tool modules, `lesson_read` and `permission/files.py`) is
    bound to a path-seam function, whatever it is called and wherever it was re-exported from.
    `_deps.py` is excluded: its `lessons_loaded` append is a run record (#1165)."""
    import importlib

    import defender._io as io_mod

    seams = {getattr(io_mod, n) for n in _SEAMS if hasattr(io_mod, n)}
    assert seams, "no seam resolved — the census would pass vacuously"
    offences = []
    for modname in (
        "defender.runtime.tools._files", "defender.runtime.tools._document",
        "defender.runtime.tools._bash", "defender.runtime.tools",
        "defender.learning.author.lesson_read", "defender.runtime.permission.files",
    ):
        mod = importlib.import_module(modname)
        offences += [f"{modname}.{k}" for k, v in vars(mod).items() if any(v is s for s in seams)]
    assert offences == [], offences


def test_read_file_keeps_todays_messages(tmp_path):
    """Plain-tree messages are unchanged: a missing file is `file not found: <path>`, and
    undecodable bytes are `<path> is not valid UTF-8 text (binary or corrupt)`."""
    deps, run = _main(tmp_path)
    assert _refused(lambda: _tool_read_file(deps, "nope.txt")) == "file not found: nope.txt"
    (run / "bin.txt").write_bytes(b"\xff\xfe\x00bad")
    assert _refused(lambda: _tool_read_file(deps, "bin.txt")) == (
        "bin.txt is not valid UTF-8 text (binary or corrupt)"
    )


# ---------------------------------------------------------------------------------------------
# review round (#1208): a plain folder is "file not found", and no refusal names a host path


def test_read_file_on_a_plain_folder_is_file_not_found_as_today(tmp_path):
    """An ordinary folder at the name is not a plant: `read_file` says `file not found`, as
    `is_file()` answered before the move, not the alias refusal."""
    deps, run = _main(tmp_path)
    (run / "sub").mkdir()
    assert _refused(lambda: _tool_read_file(deps, "sub")) == "file not found: sub"


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
