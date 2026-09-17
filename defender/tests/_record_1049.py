"""Shared machinery for #1049's episode-tree reader spec — NO test scripts.

The change (`spec-flow/specs/spec_graph_1049.yaml`, 70-resolutions.md "Resolved shape of demand
#0"): an episode-tree reader never holds an absolute path it could format. The primitive is
`defender._io.bind(root, *, os_=os)` — the ONLY operation that takes a path — and the reader it
answers walks a relative name component by component from the root's own handle
(`os.open(component, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC, dir_fd=<previous handle>)`, the
handle `fstat`-classified), answering a frozen `RecordRead` in exactly one of three states:
present (`text` is a `str`), absent (`absent=True`, ENOENT at any component) or refused
(`refusal == f"{name}: {reason}"`). `bound.read_jsonl(name)` is the JSONL twin
(`errors="replace"` fixed); `bound.under(name)` is a reader bound at a directory named relative
to it, DERIVED from the parent's handle by the same no-follow components (never path-opened). A name is a
sequence of plain components — `''`, `'.'`, `'..'`, a NUL and an absolute spelling cannot be
constructed (`ValueError` naming no path, before any open).

NONE of it exists at base 085b76e0; every import goes through `mod()` PER TEST (the
`_triplet_947` idiom) so the missing primitive is one failure per test, never a collection
error hiding the other assertions.

EVERY FAULT HERE IS A REAL INPUT THROUGH THE REAL PRIMITIVE — the shapes are planted on the
filesystem by `plant_shape` and re-probed on every run; the only fake is `RecordingOs`, a
pass-through RECORDER over the real `os` that injects nothing and records what the walk asks of
it (which opens, with which flags and `dir_fd`, which `fstat`s, which closes). It enters through
`bind`'s `os_=` seam, never `monkeypatch.setattr` (`scripts/lint/lint_monkeypatch.py`). Fault
content cites the claims that observed it on the real filesystem: the leaf shapes are g1/c-15
(hard link → EMLINK, both names refused), the permission arms g2/v2-1 (executed as uid 65534
via `setpriv`), the parent-component shapes v2-1 (a symlinked or dangling parent is the
kernel's own ELOOP under `O_NOFOLLOW` without `O_DIRECTORY`; a file or fifo squatting a parent
is "Not a directory" off the handle's `fstat`), the over-long name rg1, the JSONL policy rg3.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import ast
import contextlib
import errno
import inspect
import os
import textwrap
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _triplet_947 as T

mod = T.mod

NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")

#: `_io.ALIAS_READ_REFUSAL` — spelled here too so the assertions do not import the module under
#: test at collection time; `test_1049_..._refused_with_the_relative_name` checks the two agree.
ALIAS = "refusing to read through a non-plain or aliased entry"

#: A directory name no fixture content ever spells, so "the root's spelling is absent from the
#: sentence" cannot pass by accident of a short tmp path.
SECRET = "operator-secret-location"

UNDECODABLE = b"\xff\xfe\x00 not text"


def io():
    return mod("_io")


def bind(root: Path, **kw: Any) -> Any:
    """`_io.bind(root, **kw)` — the primitive's one path-taking operation."""
    return io().bind(root, **kw)


def family():
    return mod("learning.judge.family")


def judge():
    return mod("learning.judge")


def refused_class():
    return T.sym("learning.judge", "JudgeRefused")


def strerror(code: int) -> str:
    """The reason the primitive spells for an errno — `os.strerror`, so the assertion holds in
    whatever locale CI runs (D-J6: locale invariance is not demanded, byte identity is)."""
    return os.strerror(code)


# --------------------------------------------------------------------------------------
# The three states.
# --------------------------------------------------------------------------------------


def state(read: Any) -> str:
    """Which of the three states a `RecordRead` is in — and that it is in EXACTLY one:
    present (`text` a str, `absent` False, `refusal` None), absent (`absent` True, the other
    two None) or refused (`refusal` a str, `text` None, `absent` False). `absent` is read as
    a bool of its own, never inferred from `text is None`."""
    assert read is not None, "the reader answered None — the three states are a value"
    text, absent, refusal = read.text, read.absent, read.refusal
    assert isinstance(absent, bool), f"absent is {absent!r}, not a bool"
    if isinstance(text, str):
        assert absent is False, f'present with absent={absent!r}, refusal={refusal!r}'
        assert refusal is None, f'present with absent={absent!r}, refusal={refusal!r}'
        return "present"
    assert text is None, f"text is {text!r}"
    if absent:
        assert refusal is None, f"absent with a refusal {refusal!r}"
        return "absent"
    assert isinstance(refusal, str), f"neither present nor absent, and refusal is {refusal!r}"
    return "refused"


def refusal(read: Any, name: str) -> str:
    """The refused state's sentence, checked against the formula: `f"{name}: {reason}"` — the
    WHOLE relative name as given, said exactly once, and a non-empty reason after it."""
    assert state(read) == "refused", f"{name!r} was not refused: {read!r}"
    sentence = read.refusal
    assert sentence.startswith(f"{name}: "), f"{sentence!r} does not start with {name!r}: "
    assert sentence.count(name) == 1, f"the name is said {sentence.count(name)} times in {sentence!r}"
    reason = sentence[len(name) + 2:]
    assert reason, f"empty or 'None' reason in {sentence!r}"
    assert reason != 'None', f"empty or 'None' reason in {sentence!r}"
    return reason


# --------------------------------------------------------------------------------------
# The recording os seam — a pass-through recorder, never a fault injector.
# --------------------------------------------------------------------------------------


#: Names the walk must never ask of the seam: every one is a question about a name ahead of
#: (or instead of) its open.
FORBIDDEN_OS_NAMES = frozenset({
    "lstat", "stat", "access", "readlink", "listdir", "scandir", "path", "exists", "realpath",
})


class RecordingOs:
    """Every call the primitive makes through `bind(..., os_=)`: delegated to the real `os`
    and recorded — `opens` as `(path, flags, dir_fd, fd-or-exception)`, `fstats` and `closes`
    as the fd, `fdopens` as `(fd, file)`, and `asked` as every OTHER attribute the walk touched
    (so a `lstat`/`stat`/`path.exists` reaches the test as a name, not a silent success)."""

    def __init__(self) -> None:
        self.opens: list[tuple[Any, int, int | None, Any]] = []
        self.fstats: list[int] = []
        self.closes: list[int] = []
        self.fdopens: list[tuple[int, Any]] = []
        self.asked: list[str] = []

    def open(self, path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        try:
            fd = os.open(path, flags, mode, dir_fd=dir_fd)
        except OSError as e:
            self.opens.append((path, flags, dir_fd, e))
            raise
        self.opens.append((path, flags, dir_fd, fd))
        return fd

    def fstat(self, fd: int) -> os.stat_result:
        self.fstats.append(fd)
        return os.fstat(fd)

    def close(self, fd: int) -> None:
        self.closes.append(fd)
        os.close(fd)

    def fdopen(self, fd: int, *a: Any, **kw: Any) -> Any:
        fh = os.fdopen(fd, *a, **kw)
        self.fdopens.append((fd, fh))
        return fh

    def __getattr__(self, name: str) -> Any:
        self.asked.append(name)
        return getattr(os, name)

    # -- projections the assertions read --

    @property
    def component_opens(self) -> list[tuple[Any, int, int | None, Any]]:
        """The opens made relative to a handle — the walk's own steps; the root's own open
        (no `dir_fd`) is not one of them."""
        return [o for o in self.opens if o[2] is not None]

    def all_closed(self) -> bool:
        """Every fd the walk opened relative to a handle was closed — by `close` or by the
        file `fdopen` handed back having been closed."""
        via_fdopen = {fd for fd, fh in self.fdopens if fh.closed}
        component_fds = [o[3] for o in self.component_opens if isinstance(o[3], int)]
        return all(fd in self.closes or fd in via_fdopen for fd in component_fds)


#: The flag set every component — intermediate and leaf alike — is opened with (D-V3, v2-1).
WALK_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def surface(bound: Any) -> dict[str, str]:
    """Every spelling a bound reader's own surface offers a reader body (D-V2, F-3): each
    non-dunder, non-callable attribute of `dir(bound)` — `_root` and a property included, a
    single underscore is no privacy — whose value is a `str`, `bytes` or `os.PathLike`, spelled
    as text, plus `repr(bound)` and `str(bound)` under the keys `repr` and `str`. A bound reader
    that exposes its root here passes the readers' parameter census and lets any reader format
    the root; the census is the readers' half, this is the bind's."""
    out: dict[str, str] = {"repr": repr(bound), "str": str(bound)}
    for name in dir(bound):
        if name.startswith("__") and name.endswith("__"):
            continue
        try:
            value = getattr(bound, name)
        except Exception:  # noqa: BLE001 — a property that raises offers no spelling
            continue
        if callable(value):
            continue
        if isinstance(value, os.PathLike):
            value = os.fspath(value)
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            out[name] = value
    return out


# --------------------------------------------------------------------------------------
# Planting every shape of `entry_shape` — real entries, re-made on every run.
# --------------------------------------------------------------------------------------


def write_bytes(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return path


def plant_link(path: Path, target: Path | str) -> Path:
    if path.is_symlink() or path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
    return path


def plant_hard_link(path: Path, scratch: Path) -> Path:
    """A hard link at `path` to a SCRATCH file (never a live record — a hard link makes BOTH
    names refused, g1/g13/RF-J5)."""
    write_bytes(scratch, "scratch target\n")
    if path.exists() or path.is_symlink():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.link(scratch, path)
    return path


def plant_fifo(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        path.unlink()
    os.mkfifo(path)
    return path


#: The shapes the primitive's per-shape tests walk, keyed by `entry_shape`'s member name, each
#: with the relative NAME the walk is asked and the planter that makes the entry under a root.
#: Parent shapes plant the parent; the leaf under it is what the name asks for.
LONG_COMPONENT = "x" * 256 + ".md"


def _closed(path: Path, content: bytes | str = "closed\n") -> Path:
    """A mode-000 regular file — re-opened first when it is already there, so a shape planted
    twice under one root (d-05 walks the table under two spellings) works as non-root."""
    if path.exists():
        path.chmod(0o644)
    write_bytes(path, content).chmod(0)
    return path


def _closed_dir(root: Path, mode: int) -> None:
    """A directory holding `leaf.md`, then chmod'ed to `mode` — re-opened first, so planting
    it twice under one root (the present-leaf and the absent-leaf names) works as non-root."""
    if root.is_dir():
        root.chmod(0o755)
    write_bytes(root / "leaf.md", "under a closed parent\n")
    root.chmod(mode)


#: Every shape of `entry_shape`, keyed by the member name: the planter makes the entry under a
#: root and answers the relative NAME the walk is asked. Parent shapes plant the parent; the
#: leaf under it is what the name asks for. A table, not a match — so a shape is one row.
_PLANTERS: dict[str, Callable[[Path], str]] = {
    "plain": lambda root: "plain.md",
    "deep": lambda root: "realdir/leaf.md",
    "empty_file": lambda root: write_bytes(root / "empty.md", b"") and "empty.md",
    "absent": lambda root: "absent.md",
    "absent_parent": lambda root: "nowhere/leaf.md",
    "symlink": lambda root: plant_link(root / "link.md", root / "plain.md") and "link.md",
    "dangling_link": lambda root: plant_link(root / "dangling.md", root / "nowhere-at-all.md") and "dangling.md",
    "symlink_to_unreadable": lambda root: plant_link(
        root / "link-to-closed.md", _closed(root / "scratch" / "closed-target.md")) and "link-to-closed.md",
    "hard_link": lambda root: plant_hard_link(root / "hard.md", root / "scratch" / "hard-target.md") and "hard.md",
    "directory": lambda root: (root / "dir.md").mkdir(parents=True, exist_ok=True) or "dir.md",
    "fifo": lambda root: plant_fifo(root / "fifo.md") and "fifo.md",
    "undecodable": lambda root: write_bytes(root / "bad.md", UNDECODABLE) and "bad.md",
    "parent_is_file": lambda root: write_bytes(root / "afile", "a file, not a directory\n") and "afile/leaf.md",
    "parent_is_fifo": lambda root: plant_fifo(root / "afifo") and "afifo/leaf.md",
    "symlinked_parent": lambda root: plant_link(root / "linkdir", root / "realdir") and "linkdir/leaf.md",
    "dangling_parent": lambda root: plant_link(root / "dangledir", root / "nowhere-dir") and "dangledir/leaf.md",
    "name_too_long": lambda root: LONG_COMPONENT,
    "mode_000_file": lambda root: _closed(root / "closed.md") and "closed.md",
    "mode_000_parent": lambda root: _closed_dir(root / "closed", 0) or "closed/leaf.md",
    "mode_000_parent_absent_leaf": lambda root: _closed_dir(root / "closed", 0) or "closed/absent.md",
    "search_only_parent": lambda root: _closed_dir(root / "searchonly", 0o111) or "searchonly/leaf.md",
}


def plant_shape(root: Path, shape: str) -> str:
    """Plant `shape` under `root` (beside the plain file and the real directory every root
    carries) and return the relative name that reaches it."""
    write_bytes(root / "realdir" / "leaf.md", "deep text\n")
    write_bytes(root / "plain.md", "plain text\n")
    return _PLANTERS[shape](root)


#: The refused shapes any uid observes, with the reason each is refused for (d-02).
REFUSED_SHAPES: dict[str, str] = {
    "symlink": ALIAS,
    "hard_link": ALIAS,
    "directory": ALIAS,
    "fifo": ALIAS,
    "dangling_link": ALIAS,
    "symlink_to_unreadable": ALIAS,
    "symlinked_parent": ALIAS,
    "dangling_parent": ALIAS,
    "parent_is_file": os.strerror(errno.ENOTDIR),
    "parent_is_fifo": os.strerror(errno.ENOTDIR),
    "name_too_long": os.strerror(errno.ENAMETOOLONG),
}

#: The refused shapes only a non-root uid observes (d-03, g2/v2-1).
PERMISSION_SHAPES: tuple[str, ...] = (
    "mode_000_file", "mode_000_parent", "mode_000_parent_absent_leaf", "search_only_parent")


@contextlib.contextmanager
def restoring_modes(*paths: Path) -> Iterator[None]:
    """Give every path back a removable mode on the way out, so a failing assertion never
    leaves a mode-000 tree the tmp-dir cleanup cannot delete."""
    try:
        yield
    finally:
        for p in paths:
            with contextlib.suppress(OSError):
                p.chmod(0o755 if p.is_dir() else 0o644)


def restore_tree(root: Path) -> None:
    """Every mode-000 / search-only entry `plant_shape` leaves under `root`, made removable."""
    for name in ("closed.md", "closed", "searchonly", "scratch/closed-target.md"):
        p = root / name
        with contextlib.suppress(OSError):
            p.chmod(0o755 if p.is_dir() else 0o644)


# --------------------------------------------------------------------------------------
# AST censuses — over the SOURCE of the target, resolved by symbol.
# --------------------------------------------------------------------------------------


def parsed(obj: Any) -> ast.AST:
    """The AST of a function's or class's own source (dedented, so a method parses)."""
    return ast.parse(textwrap.dedent(inspect.getsource(obj)))


def called_names(tree: ast.AST) -> set[str]:
    """Every `f(...)` / `x.f(...)` callee name in `tree`."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def attribute_names(tree: ast.AST) -> set[str]:
    return {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}


def path_typed_parameters(fn: ast.FunctionDef) -> list[str]:
    """The parameters of `fn` annotated as a path (`Path`, `PurePath`, `PathLike`, a `str |
    PurePath` union naming one) OR named like a root (`path`, `root`, `episode_dir`,
    `world_dir`, `run_dir`, `*_path`)."""
    rooty = {"path", "root", "episode_dir", "world_dir", "run_dir"}
    out = []
    a = fn.args
    for p in (*a.posonlyargs, *a.args, *a.kwonlyargs):
        names = {n.id for n in ast.walk(p.annotation) if isinstance(n, ast.Name)} if p.annotation else set()
        attrs = {n.attr for n in ast.walk(p.annotation) if isinstance(n, ast.Attribute)} if p.annotation else set()
        typed = bool({"Path", "PurePath", "PathLike"} & (names | attrs))
        if typed or p.arg in rooty or p.arg.endswith("_path"):
            out.append(p.arg)
    return out


def function_def(tree: ast.AST, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"no function {name!r} in the parsed source")


def module_tree(module: Any) -> ast.AST:
    return ast.parse(Path(module.__file__).read_text(encoding="utf-8"))


def calls_by_function(tree: ast.AST, callees: frozenset[str]) -> dict[str, dict[str, int]]:
    """For every top-level function in `tree`, how many times it calls each of `callees`
    (`{fn: {callee: n}}`, functions with zero calls omitted); module-level calls under the
    key `<module>`."""
    out: dict[str, dict[str, int]] = {}

    def count(owner: str, node: ast.AST) -> None:
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                f = n.func
                callee = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
                if callee in callees:
                    out.setdefault(owner, {})
                    out[owner][callee] = out[owner].get(callee, 0) + 1

    assert isinstance(tree, ast.Module)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            count(node.name, node)
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    count(f"{node.name}.{item.name}", item)
        else:
            count("<module>", node)
    return out


def defined_functions(tree: ast.AST) -> set[str]:
    return {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
