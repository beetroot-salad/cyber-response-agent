
from __future__ import annotations

import ast
import importlib.util
import inspect
import re
import types
import typing
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union, get_args, get_origin

from .verb_grant import GrantError, VerbGrant

_SYSTEM_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")

ADAPTER_SUFFIX = "_adapter.py"


@dataclass(frozen=True)
class VerbContext:

    defender_dir: Path
    run_dir: Path
    env: Mapping[str, str]
    capture: Any = None


Verb = Callable[..., Any]



_ENGINE_ATTR = "__verb_engine__"
_BODY_PARAM_ATTR = "__verb_body_param__"
_VERB_CLASS_ATTR = "__verb_class__"
_WRAPPER_ONLY_ATTR = "__verb_wrapper_only__"

_ENGINE_DECL: dict[tuple[str, str], tuple[str, str]] = {
    ("elastic", "esql"): ("esql", "query"),          # lint-shippable: ok — real queries-table `system` value
    ("elastic", "query"): ("lucene", "native_query"),   # lint-shippable: ok — real queries-table `system` value
    ("elastic", "alerts"): ("lucene", "native_query"),  # lint-shippable: ok — real queries-table `system` value
}


def verb(
    *, engine: str = "none", body_param: str | None = None, verb_class: str = "r",
    wrapper_only: tuple[str, ...] = (),
) -> Callable[[Verb], Verb]:
    """`wrapper_only` names params a first-party WRAPPER binds and no model may (#900).

    The case it exists for is `ticket`'s `require_closed`: the benign judge's closed-ticket
    tool hard-codes it on the wire (`closed_ticket_tool.py:490,532`) and deliberately keeps it
    off its own model-facing schema, while gather — which shares the verb — has no business
    setting it at all. It only ever NARROWS (it pins `status=closed`), so this is not a
    privilege boundary; it is a correctness one. A gather lead that bound it would silently
    drop the open and in-progress siblings it was dispatched to correlate, and could then
    report "no open work touching this host" from a read it had quietly narrowed itself.

    A marked param is refused by `validate_params` and omitted from `model_facing_params`, so
    the surface a model is shown and the surface the boundary accepts stay the same set. The
    wrapper is unaffected: it calls `fn(ctx, **params)` directly and never crosses this check.
    """
    # CHECKED AT DECORATION, because both ways of getting it wrong are SILENT and both undo
    # the one property this feature buys. A bare string iterates into its characters
    # (`frozenset("require_closed")` reserves 13 letters and no param), and a misspelt name
    # reserves nothing at all — after either, `list_verbs` publishes the param and
    # `validate_params` accepts it, which is exactly the publication/enforcement disagreement
    # `model_facing_params` exists to make impossible.
    if isinstance(wrapper_only, str):
        raise TypeError(
            f"@verb(wrapper_only={wrapper_only!r}) is a bare string — it would iterate into "
            "characters and reserve no param. Pass a tuple: (\"<param>\",)"
        )
    reserved = frozenset(wrapper_only)

    def decorate(fn: Verb) -> Verb:
        declared = declared_params(fn)
        undeclared = sorted(reserved - set(declared))
        if undeclared:
            raise ValueError(
                f"@verb(wrapper_only=…) on {getattr(fn, '__name__', fn)!r} reserves "
                f"{undeclared}, which the signature does not declare as keyword-only param(s) "
                f"— a reserved name that matches nothing is silently no reservation at all"
            )
        # AND it must carry a DEFAULT, checked here for the same reason the two above are:
        # the failure is silent and lands at the wrong layer. `validate_params` computes its
        # required set from `model_facing_params`, which a reserved param is by definition not
        # in — so a default-less one is never reported missing, and a model call that omits it
        # (the only call it can make) reaches `fn(vctx, **params)` and raises TypeError inside
        # the query tool: an infra-class row and a circuit-breaker contribution for what is
        # really a declaration defect.
        undefaulted = sorted(
            n for n in reserved if declared[n].default is inspect.Parameter.empty
        )
        if undefaulted:
            raise ValueError(
                f"@verb(wrapper_only=…) on {getattr(fn, '__name__', fn)!r} reserves "
                f"{undefaulted}, which the signature declares WITHOUT a default — a reserved "
                f"param is dropped from the required set the boundary checks, so no model call "
                f"can ever supply it and every one of them would fault inside the verb body. "
                f"Give it the default the wrapper overrides"
            )
        setattr(fn, _ENGINE_ATTR, engine)
        setattr(fn, _BODY_PARAM_ATTR, body_param)
        setattr(fn, _VERB_CLASS_ATTR, verb_class)
        setattr(fn, _WRAPPER_ONLY_ATTR, reserved)
        return fn

    return decorate


def engine_of(fn: Verb) -> str:
    return getattr(fn, _ENGINE_ATTR, "none")


def body_param_of(fn: Verb) -> str | None:
    return getattr(fn, _BODY_PARAM_ATTR, None)


def verb_class_of(fn: Verb) -> str:
    """The verb_class a verb body declares via `@verb(verb_class=…)`, defaulting to the
    read-only class for an undecorated body — every shipped verb today is `r`."""
    return getattr(fn, _VERB_CLASS_ATTR, "r")


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


def wrapper_only_params(fn: Verb) -> frozenset[str]:
    """The params `@verb(wrapper_only=…)` reserves to a first-party wrapper."""
    return getattr(fn, _WRAPPER_ONLY_ATTR, frozenset())


def model_facing_params(fn: Verb) -> dict[str, inspect.Parameter]:
    """The declared params a MODEL may bind — `declared_params` minus the wrapper-only set.

    THE surface for anything model-facing: what `validate_params` accepts and what
    `list_verbs` publishes are both this, so the two cannot disagree. `declared_params` stays
    the raw signature read, which is what a binding call and the scaffold's placeholder
    invariant want.
    """
    hidden = wrapper_only_params(fn)
    return {n: p for n, p in declared_params(fn).items() if n not in hidden}


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
    declared = model_facing_params(fn)
    # BEFORE the unknown check, which would otherwise absorb these: a wrapper-only param is
    # declared on the signature, so "unknown param" would be a lie about why it was refused
    # and would send the model looking for a typo it did not make.
    reserved = sorted(set(params) & wrapper_only_params(fn))
    if reserved:
        return (
            f"param(s) {reserved} are set by the first-party tool that owns this read, never "
            f"by you — this verb's caller-settable params are {sorted(declared)}."
        )
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


def _adapter_path(adapters_dir: Path, system: str) -> Path | None:
    if not _SYSTEM_RE.match(system):
        return None
    root = Path(adapters_dir).resolve()
    path = (Path(adapters_dir) / (system.replace("-", "_") + ADAPTER_SUFFIX)).resolve()
    if root not in path.parents or not path.is_file():
        return None
    return path


def declared_verb_names(adapters_dir: Path, system: str) -> frozenset[str]:
    """Every verb name a system's adapter declares, read COLD off its `VERBS = {...}` literal
    — no import, so a system whose module cannot even be imported still declares what it
    declares. Only string-literal keys of a top-level dict LITERAL assignment are seen; a
    table assembled any other way (a loop, a comprehension) declares nothing to this reader,
    which is deliberate — the load check that consumes this must fail rather than treat an
    unreadable table as a blank cheque (§7 R10)."""
    path = _adapter_path(adapters_dir, system)
    if path is None:
        return frozenset()
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError):
        return frozenset()
    names: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "VERBS" for t in node.targets):
            continue
        for key in node.value.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                names.add(key.value)
    return frozenset(names)


GRANTED = "GRANTED"
DENIED = "DENIED"
UNDECLARED = "UNDECLARED"


@dataclass(frozen=True)
class VerbDecision:

    outcome: str
    fn: Verb | None
    refusal: str | None


class VerbRegistry:
    """The nominally-typed verb-registry seam (§7 R15): every construction route requires a
    real `VerbGrant`, so an unscoped registry is unconstructable rather than merely un-passed,
    and every entry point that takes a registry checks the TYPE — a registry-shaped stand-in
    that never went through this constructor is refused, because a structural check ("does it
    answer verbs()/decide()?") cannot tell a real grant apart from a duck-typed one that
    answers GRANTED to everything."""

    def __init__(self, grant: VerbGrant):
        if not isinstance(grant, VerbGrant):
            raise GrantError(
                f"a verb registry requires a real VerbGrant, got {type(grant).__name__}"
            )
        self.grant = grant

    def systems(self) -> tuple[str, ...]:
        raise NotImplementedError

    def verbs(self, system: str) -> Mapping[str, Verb]:
        raise NotImplementedError

    def _cold_verb_names(self, system: str) -> frozenset[str] | None:
        """Verb names `system` REALLY declares, resolved without importing when a subclass
        can (`ModuleVerbRegistry` overrides this with the cold AST reader). `None` tells
        `decide` no cold source exists, so it falls back to `self.verbs(system)` — cheap for
        an in-memory fake, the reason a real-adapter subclass must override rather than
        inherit this default."""
        return None

    def decide(self, system: str, verb: str) -> VerbDecision:
        """THE grant decision point. Decided from the grant ALONE first — no adapter is
        resolved (no import) unless the grant admits the call — so a denial or an
        unresolvable verdict on a system whose adapter cannot even be imported is still
        reached, and reached without importing it (§7 R11's UNDECLARED/DENIED split, read
        literally). A verb name outside what the system REALLY declares (a case or whitespace
        near-miss) is UNDECLARED even when the grant otherwise reaches the system — DENIED is
        reserved for a real, withheld verb."""
        if not self.grant.allows(system, verb):
            if system in self.grant.systems:
                cold = self._cold_verb_names(system)
                if cold is not None:
                    real = verb in cold
                else:
                    try:
                        real = verb in self.verbs(system)
                    except KeyError:
                        real = False
                if real:
                    return VerbDecision(
                        DENIED, None,
                        f"{system}.{verb} is not granted to role {self.grant.role!r}.",
                    )
            return VerbDecision(
                UNDECLARED, None,
                f"unresolvable: {system}.{verb} (unknown, or role {self.grant.role!r} holds "
                "no grant reaching it).",
            )
        try:
            verbs = self.verbs(system)
        except KeyError:
            return VerbDecision(UNDECLARED, None, f"unknown system {system!r}.")
        fn = verbs.get(verb)
        if fn is None:
            return VerbDecision(UNDECLARED, None, f"unknown verb {verb!r} for {system}.")
        declared_class = verb_class_of(fn)
        expected_class = self.grant.class_of(system, verb)
        if expected_class is not None and declared_class != expected_class:
            raise GrantError(
                f"{system}.{verb} is declared class {declared_class!r} but the grant for role "
                f"{self.grant.role!r} expects {expected_class!r} — grant/declaration disagreement"
            )
        return VerbDecision(GRANTED, fn, None)


class ModuleVerbRegistry(VerbRegistry):

    def __init__(self, adapters_dir: Path, grant: VerbGrant):
        super().__init__(grant)
        self.adapters_dir = Path(adapters_dir)
        # One cold read+parse per SYSTEM, not per grant entry: `declared_verb_names` re-reads
        # and re-parses the adapter every call, and the shipped gather grant names 28 entries
        # across 7 systems.
        declared = {s: declared_verb_names(self.adapters_dir, s) for s, _, _ in grant.entries}
        offenders = [(s, v) for s, v, _ in grant.entries if v not in declared[s]]
        if offenders:
            named = ", ".join(f"{s}.{v}" for s, v in offenders)
            raise GrantError(
                f"verb_grant for role {grant.role!r} names verb(s) the adapters under "
                f"{self.adapters_dir} do not declare: {named}"
            )

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(_system_of(p) for p in self.adapters_dir.glob("*" + ADAPTER_SUFFIX)))

    def _cold_verb_names(self, system: str) -> frozenset[str] | None:
        return declared_verb_names(self.adapters_dir, system)

    def verbs(self, system: str) -> Mapping[str, Verb]:
        path = _adapter_path(self.adapters_dir, system)
        if path is None:
            raise KeyError(system)
        verbs = getattr(_load_adapter_module(path), "VERBS", None)
        if not isinstance(verbs, Mapping):
            return {}
        return dict(verbs)


__all__ = [
    "ADAPTER_SUFFIX",
    "DENIED",
    "GRANTED",
    "UNDECLARED",
    "ModuleVerbRegistry",
    "Verb",
    "VerbContext",
    "VerbDecision",
    "VerbRegistry",
    "body_param_for",
    "body_param_of",
    "declared_params",
    "declared_verb_names",
    "engine_for",
    "engine_of",
    "model_facing_params",
    "validate_params",
    "verb",
    "verb_class_of",
    "wrapper_only_params",
]
