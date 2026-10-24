"""Loaders for the lint programs this suite tests.

The lints are standalone programs that import each other by bare name (`from _astlib import ...`),
so their own directory has to be on `sys.path` for as long as a loaded lint is used."""
from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

LINT_DIR = Path(__file__).resolve().parents[1]


def import_lint_lib(name: str) -> ModuleType:
    """A library the lints share (`_astlib`, `_baseline`) — IMPORTED, never path-loaded."""
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    return importlib.import_module(name)


def load_lint_gate(stem: str, *, name: str | None = None) -> ModuleType:
    """The lint `tooling/lint/<stem>.py`, executed fresh the way CI reaches it."""
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    name = name or stem
    spec = importlib.util.spec_from_file_location(name, LINT_DIR / f"{stem}.py")
    assert spec is not None and spec.loader is not None, f"nothing loadable at {stem}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
