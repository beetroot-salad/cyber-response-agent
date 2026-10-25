"""One loader for the programs this tree runs but cannot import."""
from __future__ import annotations

import contextlib
import importlib
import importlib.util
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import ModuleType

WORKTREE = Path(__file__).resolve().parents[5]
DEFENDER = WORKTREE / "defender"
LINT_DIR = WORKTREE / "tooling" / "lint"


@contextlib.contextmanager
def on_sys_path(*dirs: Path) -> Iterator[None]:
    """``dirs`` on ``sys.path`` for the duration of the block.

    Removes only what this call added, so a directory another caller is relying on
    survives — the hand-rolled version of this (insert, then ``finally: sys.path.remove``)
    removes unconditionally and will happily take away an entry it did not put there.

    Use this only where the entry must NOT outlive the load. Where a loaded script's own
    imports need the directory at call time as well as at exec time, pass ``sys_path=``
    to `load_module` instead and let it stay.
    """
    added = [str(d) for d in dirs if str(d) not in sys.path]
    for entry in added:
        sys.path.insert(0, entry)
    try:
        yield
    finally:
        for entry in added:
            with contextlib.suppress(ValueError):
                sys.path.remove(entry)


def load_module(
    path: Path,
    *,
    name: str | None = None,
    sys_path: Sequence[Path] = (),
    register: bool = True,
) -> ModuleType:
    """The program at ``path``, executed fresh and returned as a module."""
    name = name or path.stem
    for entry in sys_path:
        if str(entry) not in sys.path:
            sys.path.insert(0, str(entry))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None, f"nothing loadable at {path}"
    assert spec.loader is not None, f"{path} has no loader"
    module = importlib.util.module_from_spec(spec)
    if register:
        sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_trace_lesson(name: str) -> ModuleType:
    """``cli/learning/trace_lesson.py`` — one path, five suites, five module objects.

    ``name`` is required and deliberately not defaulted. The suites that load this CLI
    want *separate* module objects, because each rebinds or exercises module state the
    others must not see; ``test_corpus_fold_584`` documents the rejected alternative
    (rebinding ``mod.LESSONS_DIR`` on a shared module) at length. What they did not want,
    and had, was three different derivations of where the file is.
    """
    return load_module(DEFENDER / "cli" / "learning" / "trace_lesson.py", name=name)


def import_lint_lib(name: str) -> ModuleType:
    """A library the gates share (``_astlib``, ``_baseline``) — IMPORTED, never path-loaded."""
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    return importlib.import_module(name)


def load_lint_gate(stem: str, *, name: str | None = None) -> ModuleType:
    """The lint gate ``tooling/lint/<stem>.py``, reached the way CI reaches it.

    The gates are standalone programs that import each other by bare name
    (``from _baseline import gate``, ``from _astlib import read_and_parse``), so their
    own directory has to be on ``sys.path`` and has to stay there for as long as the
    loaded gate is used — this is the case `on_sys_path` is wrong for.
    """
    return load_module(LINT_DIR / f"{stem}.py", name=name or stem, sys_path=(LINT_DIR,))


