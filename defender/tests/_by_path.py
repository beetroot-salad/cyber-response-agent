"""One loader for the programs this tree runs but cannot import.

`scripts/`, `scripts/lint/` and the repo-root tools are directories of standalone
programs, not importable packages, so a test that needs one reaches it by path — the way
CI reaches it. That part is unavoidable. What was avoidable is that the same
`spec_from_file_location` dance had been written thirty-odd times under fourteen names,
each copy free to differ on the two details that actually decide whether a load works:
whether the module is registered in ``sys.modules`` before it executes, and what goes on
``sys.path`` first. Nothing recorded which of those differences was a decision and which
was a copy that stopped short, so three copies carry a comment explaining the
registration and the rest simply omit it.

Loading a program by path is not the same as importing it. Two consequences are worth
knowing before adding a caller:

- **The module executes on every call.** There is no import cache here. A helper that
  loads a script per test hands each test a genuinely fresh module — which is what
  ``test_frontmatter_fold_591`` relies on for a fresh ``lru_cache``, and what
  ``test_lessons_fm`` relies on when it rebinds module constants at a tmp path.
- **``__name__`` is not ``"__main__"``.** A script's ``if __name__ == "__main__":`` tail
  does not run, which is the whole reason these tests can reach a CLI's internals.
"""
from __future__ import annotations

import contextlib
import importlib
import importlib.util
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import ModuleType

WORKTREE = Path(__file__).resolve().parents[2]
DEFENDER = WORKTREE / "defender"
LINT_DIR = WORKTREE / "scripts" / "lint"


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
    """The program at ``path``, executed fresh and returned as a module.

    ``name`` defaults to the file's stem. Pass one where two tests load the same file and
    must not share a ``sys.modules`` entry, or where the stem would collide with a real
    module.

    ``register`` puts the module into ``sys.modules`` *before* it executes, and it is not
    cosmetic: ``@dataclass`` resolves a class's postponed annotations through
    ``sys.modules[cls.__module__]``, which is absent for a path-loaded module, so a script
    that defines a dataclass raises on load without it. It defaults on because that is the
    answer which cannot silently break a caller. Pass ``register=False`` where leaving the
    name unclaimed is the point.

    Registering does claim the name, so do not point this at a module something also
    reaches by bare ``import`` — you get two module objects under one key and two copies of
    every class in it. `import_lint_lib` exists because that had already happened.

    ``sys_path`` entries are inserted if absent and left in place, because a script whose
    own imports need a directory needs it for as long as the module is used, not just for
    the exec.
    """
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
    """``learning/ops/trace_lesson.py`` — one path, five suites, five module objects.

    ``name`` is required and deliberately not defaulted. The suites that load this CLI
    want *separate* module objects, because each rebinds or exercises module state the
    others must not see; ``test_corpus_fold_584`` documents the rejected alternative
    (rebinding ``mod.LESSONS_DIR`` on a shared module) at length. What they did not want,
    and had, was three different derivations of where the file is.
    """
    return load_module(DEFENDER / "learning" / "ops" / "trace_lesson.py", name=name)


def import_lint_lib(name: str) -> ModuleType:
    """A library the gates share (``_astlib``, ``_baseline``) — IMPORTED, never path-loaded.

    The distinction matters and used to be got wrong. A gate reaches these by bare name
    (``from _astlib import ScanBlind``), so there is exactly one module object and one
    ``ScanBlind`` class as long as everyone imports it. Path-loading it mints a *second*
    module under the same ``sys.modules`` key, and any gate loaded before that point goes
    on raising the first copy's ``ScanBlind`` while a test that path-loaded the second
    catches a class that can never match. That was live: three suites assert
    ``pytest.raises(_astlib.ScanBlind)`` and passed only because every gate happened to be
    re-executed after the clobber, in file order.
    """
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    return importlib.import_module(name)


def load_lint_gate(stem: str, *, name: str | None = None) -> ModuleType:
    """The lint gate ``scripts/lint/<stem>.py``, reached the way CI reaches it.

    The gates are standalone programs that import each other by bare name
    (``from _baseline import gate``, ``from _astlib import read_and_parse``), so their
    own directory has to be on ``sys.path`` and has to stay there for as long as the
    loaded gate is used — this is the case `on_sys_path` is wrong for.
    """
    return load_module(LINT_DIR / f"{stem}.py", name=name or stem, sys_path=(LINT_DIR,))
