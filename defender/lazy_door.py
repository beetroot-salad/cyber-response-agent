"""A package's door, served lazily (#1315): the public names other areas take from the package's
private modules, imported on first use.

A door module declares a literal `_HOMES` dict (each served name -> the submodule of its package
that defines it), imports every served name under `if TYPE_CHECKING:` (so the type checker and the
re-export-resolving gates see the real origin), and binds `__getattr__ = lazy_door(globals(),
_HOMES)`. `tooling/lint/lint_private_imports.py` checks the three agree.

Lazy, not eager: an eager door makes importing any module of the package import everything the
door serves; `records`' measured 0.04 s -> 4 s. Standard library only, and at the bottom of the
import order, so the lowest packages (and the venv guard's) can have a door.
"""
from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from typing import Any


def lazy_door(namespace: dict[str, Any], homes: Mapping[str, str]) -> Callable[[str], Any]:
    """The PEP 562 `__getattr__` for the door module whose globals are `namespace`: a served
    name is read off its home submodule on every access; anything else is an AttributeError, as
    for any module.

    Never cached in the door: a caller that read `home.name` at call time before the door
    existed still sees what the home holds now, a test's patch on the home included. A cached
    copy would keep the first value it read, a patched one included, for the process."""
    module = namespace["__name__"]
    package = namespace["__package__"]

    def __getattr__(name: str) -> Any:
        home = homes.get(name)
        if home is None:
            raise AttributeError(f"module {module!r} has no attribute {name!r}")
        return getattr(importlib.import_module(f"{package}.{home}"), name)

    return __getattr__
