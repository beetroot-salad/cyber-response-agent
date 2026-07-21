
from __future__ import annotations

import importlib.util
import inspect
import re
import types
import typing
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union, get_args, get_origin

_SYSTEM_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")

ADAPTER_SUFFIX = "_adapter.py"


@dataclass(frozen=True)
class VerbContext:

    defender_dir: Path
    run_dir: Path
    env: Mapping[str, str]


Verb = Callable[..., Any]



_ENGINE_ATTR = "__verb_engine__"
_BODY_PARAM_ATTR = "__verb_body_param__"

_ENGINE_DECL: dict[tuple[str, str], tuple[str, str]] = {
    ("elastic", "esql"): ("esql", "query"),          # lint-shippable: ok — real queries-table `system` value
    ("elastic", "query"): ("lucene", "native_query"),   # lint-shippable: ok — real queries-table `system` value
    ("elastic", "alerts"): ("lucene", "native_query"),  # lint-shippable: ok — real queries-table `system` value
}


def verb(*, engine: str = "none", body_param: str | None = None) -> Callable[[Verb], Verb]:

    def decorate(fn: Verb) -> Verb:
        setattr(fn, _ENGINE_ATTR, engine)
        setattr(fn, _BODY_PARAM_ATTR, body_param)
        return fn

    return decorate


def engine_of(fn: Verb) -> str:
    return getattr(fn, _ENGINE_ATTR, "none")


def body_param_of(fn: Verb) -> str | None:
    return getattr(fn, _BODY_PARAM_ATTR, None)


def engine_for(system: str, verb_name: str) -> str:
    decl = _ENGINE_DECL.get((system, verb_name))
    return decl[0] if decl else "none"


def body_param_for(system: str, verb_name: str) -> str | None:
    decl = _ENGINE_DECL.get((system, verb_name))
    return decl[1] if decl else None


def declared_params(fn: Verb) -> dict[str, inspect.Parameter]:
    return {
        p.name: p
        for p in inspect.signature(fn).parameters.values()
        if p.kind is inspect.Parameter.KEYWORD_ONLY
    }


_NONE_TYPE = type(None)


def _resolved_hints(fn: Verb) -> dict[str, Any]:
    try:
        return typing.get_type_hints(fn)
    except Exception:  # noqa: BLE001 — an unresolvable hint must not deny a well-formed call
        return {}


def _matches(value: Any, ann: Any) -> bool:
    if ann is inspect.Parameter.empty or ann is Any:
        return True
    origin = get_origin(ann)
    if origin is Union or origin is types.UnionType:
        return any(_matches(value, arg) for arg in get_args(ann))
    if ann is _NONE_TYPE:
        return value is None
    if origin is not None:
        return isinstance(value, origin)
    if ann is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if ann is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if isinstance(ann, type):
        return isinstance(value, ann)
    return True


def _ann_name(ann: Any) -> str:
    return getattr(ann, "__name__", None) or str(ann).replace("typing.", "")


def validate_params(fn: Verb, params: Mapping[str, Any]) -> str | None:
    declared = declared_params(fn)
    unknown = sorted(set(params) - set(declared))
    if unknown:
        return (
            f"unknown param(s) {unknown} — this verb declares "
            f"{sorted(declared)} and nothing else."
        )
    missing = sorted(
        name for name, p in declared.items()
        if p.default is inspect.Parameter.empty and name not in params
    )
    if missing:
        return f"missing required param(s) {missing} (declared params: {sorted(declared)})."

    hints = _resolved_hints(fn)
    mistyped = sorted(
        f"{name!r} takes {_ann_name(hints[name])}, got "
        f"{type(params[name]).__name__} ({params[name]!r})"
        for name in params
        if name in hints and not _matches(params[name], hints[name])
    )
    if mistyped:
        return (
            f"wrong param type(s): {'; '.join(mistyped)}. Pass JSON values of the declared "
            "type — a number is a number, not a quoted string, and a boolean is true/false."
        )
    return None



def _system_of(path: Path) -> str:
    return path.name[: -len(ADAPTER_SUFFIX)].replace("_", "-")


_MODULES: dict[str, Any] = {}


def _load_adapter_module(path: Path) -> Any:
    resolved = path.resolve()
    key = str(resolved)
    if key not in _MODULES:
        spec = importlib.util.spec_from_file_location(f"_defender_adapter_{abs(hash(key))}", resolved)
        if spec is None or spec.loader is None:
            raise ImportError(f"could not load adapter module {resolved}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULES[key] = module
    return _MODULES[key]


class ModuleVerbRegistry:

    def __init__(self, adapters_dir: Path):
        self.adapters_dir = Path(adapters_dir)

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(_system_of(p) for p in self.adapters_dir.glob("*" + ADAPTER_SUFFIX)))

    def verbs(self, system: str) -> Mapping[str, Verb]:
        if not _SYSTEM_RE.match(system):
            raise KeyError(system)
        root = self.adapters_dir.resolve()
        path = (self.adapters_dir / (system.replace("-", "_") + ADAPTER_SUFFIX)).resolve()
        if root not in path.parents:
            raise KeyError(system)
        if not path.is_file():
            raise KeyError(system)
        verbs = getattr(_load_adapter_module(path), "VERBS", None)
        if not isinstance(verbs, Mapping):
            return {}
        return dict(verbs)


__all__ = [
    "ADAPTER_SUFFIX",
    "ModuleVerbRegistry",
    "Verb",
    "VerbContext",
    "body_param_for",
    "body_param_of",
    "declared_params",
    "engine_for",
    "engine_of",
    "validate_params",
    "verb",
]
