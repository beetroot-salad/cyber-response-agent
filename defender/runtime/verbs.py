"""The verb registry: an adapter's `VERBS` mapping is its whole model-facing surface.

Before #611 a data-source call was a bash STRING the model authored — `defender-<system>
<verb> '<query body>' --query-id <id>` — so the model could name a program, and the adapter's
affordance was `--help`. A verb is the typed replacement: a plain annotated
function whose KEYWORD-ONLY params ARE its param contract. Three things fall out of that
one choice, and each is load-bearing:

  - **The signature is the allowlist.** `declared_params` is the ONE reader of it, and the
    query tool's validator asks it — so "what may the model pass" has a single answer that
    cannot drift from what the verb actually accepts. (Enforcement is a runtime validator,
    not the JSON schema: `params` is per-verb, and a per-verb-dependent object cannot be one
    schema. The model sees no per-verb affordance in the tool schema at all; it learns the
    roster from the injected catalog.)
  - **No verb can name a program, a command, or a path in the driver's namespace.** There is
    no argv left to smuggle one into.
  - **The tree is a PARAMETER, not an import-time constant.** A verb takes a `VerbContext`
    carrying the RUN's `defender_dir` and its scrubbed env. The adapters used to read
    `DEFENDER_DIR` at module import; in-process that constant would freeze to the driver's
    ambient env at first import, and a run whose tree is a worktree or an eval's tmp tree
    would silently read the MAIN checkout's `config.env` (the #551 bug class, one layer down).

This module imports nothing from `pydantic_ai` and nothing from `runtime/` — the descriptor
catalog (a `hooks/` module) reads the roster from it at prompt-build time.
"""

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

#: The shape a system NAME may take: lowercase kebab, no separators, no dots. `system` is
#: MODEL-supplied (the `query` tool passes it straight here), and it is joined into a filesystem
#: path that is then IMPORTED — so a name carrying `/` or `..` (`../../../tmp/evil/pwned`) would,
#: with a matching `*_adapter.py` on disk, execute an arbitrary module. The shape reject is the first
#: gate; the resolved-containment check in `verbs()` is the belt behind it (the invariant is
#: "resolve(adapters_dir/<file>) stays under resolve(adapters_dir)", which holds even if a future
#: edit loosens this pattern). Neither alone: a bare shape check trusts `.replace('-','_')` not to
#: reintroduce a separator, and a bare containment check would still import a same-dir module the
#: roster never listed.
_SYSTEM_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")

#: The structural marker for a data-source adapter. It is load-bearing well beyond this
#: glob — `_cmd_segments.ADAPTER_RE` (the security regex that denies the main loop direct
#: adapter execution), `record_query._ADAPTER_RE` (the queries-table system join key), and
#: `workspace_map` all key on it. Those regexes fail OPEN on a mismatch: they simply stop
#: matching, and the gate keeps passing while gating nothing. Any change to this constant
#: must land in the same commit as all of them.
ADAPTER_SUFFIX = "_adapter.py"


@dataclass(frozen=True)
class VerbContext:
    """What the harness hands every verb: the RUN's tree, the RUN's dir, and the RUN's env.

    `defender_dir` is the tree this run is anchored on (a worktree in a learning drain, a tmp
    tree in an eval) — a verb resolves its `config.env` from HERE, never from an import-time
    module constant.

    `env` is the SCRUBBED environment (`run_common.run_env`) a transport must hand to any
    child it forks. It is the thing that keeps the provider keys out of the `docker` child:
    the scrub used to ride on the capture subprocess's `env=`, and a transport that forks with
    no `env=` at all inherits the driver's `os.environ`, keys included. #550 closes that
    properly by taking the key out of the driver; until then this is the belt.
    """

    defender_dir: Path
    run_dir: Path
    env: Mapping[str, str]


Verb = Callable[..., Any]


# --- the verb ENGINE declaration (#620) -------------------------------------
#
# A verb's body is EITHER a query LANGUAGE (an ES|QL pipe, a Lucene/KQL string — the whole query
# lives in ONE param) OR a set of scalar params (the majority). Which it is, and which param
# carries the language body, is a property of the VERB, not the system: the SIEM's `esql` speaks
# ES|QL in `query`, its `query`/`alerts` speak Lucene in `native_query`, and every other verb is
# param-only. The pre-#620 consumer keyed this on the SYSTEM (`_is_esql`), which could not tell
# the SIEM's `query` (Lucene) from its `esql` (ES|QL) — the exact bug this declaration ends.
#
# The declaration has two faces, and they are TWINS that must agree:
#   * `@verb(engine=…, body_param=…)` STAMPS the live registry function; `engine_of` /
#     `body_param_of` read it back. This is the in-process path (the query tool, the validator).
#   * `_ENGINE_DECL` is the OFFLINE twin, keyed on the recorded `(system, verb)` strings, read by
#     the frozen-row consumers (`draft_synthesis`, `lead_extraction`) via `engine_for` /
#     `body_param_for`. They resolve a persisted row's engine WITHOUT importing an adapter module:
#     importing a per-tree adapter to read a decorator attribute would re-open the #551 freeze one
#     layer up (the reader would bind whichever tree imported the module first). An offline reader
#     therefore cannot go through the stamped function — it has no function, only the row's strings.

_ENGINE_ATTR = "__verb_engine__"
_BODY_PARAM_ATTR = "__verb_body_param__"

#: (system, verb) -> (engine, body_param) for every verb whose body is a query language. Absent
#: => engine "none", the param-only majority. The @verb decorations on the adapters carry the same
#: facts for the live path; keep the two in step when a verb's engine changes.
_ENGINE_DECL: dict[tuple[str, str], tuple[str, str]] = {
    ("elastic", "esql"): ("esql", "query"),          # lint-shippable: ok — real queries-table `system` value
    ("elastic", "query"): ("lucene", "native_query"),   # lint-shippable: ok — real queries-table `system` value
    ("elastic", "alerts"): ("lucene", "native_query"),  # lint-shippable: ok — real queries-table `system` value
}


def verb(*, engine: str = "none", body_param: str | None = None) -> Callable[[Verb], Verb]:
    """Declare a verb's ENGINE and native-query-body param — a per-VERB property, not per-system.

    A verb whose body is a query language carries `engine=` + `body_param=` (the SIEM's esql →
    `esql`/`query`; query/alerts → `lucene`/`native_query`); a param-only verb carries neither and
    reads as engine `"none"`. The decorator only STAMPS two attributes and returns the function
    UNCHANGED, so `declared_params` / `validate_params` keep reading the signature — the marker
    never blinds the validator to the body param (it is an attribute, not an annotation, so there
    is nothing for `_resolved_hints` to strip the way an `Annotated[str, QueryBody]` would be).
    """

    def decorate(fn: Verb) -> Verb:
        setattr(fn, _ENGINE_ATTR, engine)
        setattr(fn, _BODY_PARAM_ATTR, body_param)
        return fn

    return decorate


def engine_of(fn: Verb) -> str:
    """The verb's declared engine, or `"none"` for an undecorated (param-only) verb."""
    return getattr(fn, _ENGINE_ATTR, "none")


def body_param_of(fn: Verb) -> str | None:
    """The keyword-only param carrying the verb's native query body, or None (param-only)."""
    return getattr(fn, _BODY_PARAM_ATTR, None)


def engine_for(system: str, verb_name: str) -> str:
    """The engine a frozen row's `(system, verb)` speaks, resolved OFFLINE (no adapter import) —
    `"none"` for the param-only majority. Keyed per-VERB: the SIEM's `query` is `lucene` while its
    `esql` is `esql`, the distinction the old system-keyed `_is_esql` could not draw."""
    decl = _ENGINE_DECL.get((system, verb_name))
    return decl[0] if decl else "none"


def body_param_for(system: str, verb_name: str) -> str | None:
    """The keyword-only param carrying `(system, verb)`'s native query body, resolved offline —
    None for a param-only verb."""
    decl = _ENGINE_DECL.get((system, verb_name))
    return decl[1] if decl else None


def declared_params(fn: Verb) -> dict[str, inspect.Parameter]:
    """A verb's param surface: the KEYWORD-ONLY params of its annotated signature.

    Keyword-only is the discriminator, not "everything but the first arg": the `VerbContext`
    is harness carriage and arrives positionally, so a verb author cannot accidentally expose
    it to the model, and a model cannot bind it. Everything the model may supply is spelled
    `*, name: type` — which also means a verb's params are unordered by construction, killing
    the `arg0`/`arg1` positional flattening the learning loop had to reverse-engineer.
    """
    return {
        p.name: p
        for p in inspect.signature(fn).parameters.values()
        if p.kind is inspect.Parameter.KEYWORD_ONLY
    }


_NONE_TYPE = type(None)


def _resolved_hints(fn: Verb) -> dict[str, Any]:
    """The verb's annotations as TYPES, not strings. Adapters carry `from __future__ import
    annotations`, so `inspect.signature` hands back `'int'`/`'str | None'` as text; only
    `get_type_hints` (which evaluates against the module's own globals) yields something a
    check can be written against. An annotation that will not resolve is not a rejection —
    the checker treats it as unconstrained, so a verb author's typo widens nothing."""
    try:
        return typing.get_type_hints(fn)
    except Exception:  # noqa: BLE001 — an unresolvable hint must not deny a well-formed call
        return {}


def _matches(value: Any, ann: Any) -> bool:
    """Does `value` satisfy the annotation `ann`? Structural and deliberately shallow: the
    container is checked, its element types are not (`dict[str, str]` asks only for a dict).
    A deep check would be a schema validator, and the param surface is not a schema — what
    this has to catch is the WRONG KIND of thing, not a badly-typed leaf."""
    if ann is inspect.Parameter.empty or ann is Any:
        return True
    origin = get_origin(ann)
    if origin is Union or origin is types.UnionType:      # `str | None`, `dict | list`
        return any(_matches(value, arg) for arg in get_args(ann))
    if ann is _NONE_TYPE:
        return value is None
    if origin is not None:                                # `dict[str, str]` → check `dict`
        return isinstance(value, origin)
    # `bool` is a subclass of `int`, so an unguarded isinstance would let `limit=True` through
    # as an integer — and a bool that reaches an arithmetic clamp is exactly the silent-wrong
    # class this check exists to stop.
    if ann is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if ann is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if isinstance(ann, type):
        return isinstance(value, ann)
    return True                                           # uninterpretable → unconstrained


def _ann_name(ann: Any) -> str:
    return getattr(ann, "__name__", None) or str(ann).replace("typing.", "")


def validate_params(fn: Verb, params: Mapping[str, Any]) -> str | None:
    """`None` if `params` satisfies `fn`'s declared surface, else the model-facing reason.

    Rejects an unknown key, a missing required one (a kw-only param with no default), and a
    value of the wrong TYPE. The reason NAMES the declared roster — the model has no `--help`
    any more, so a rejection that only says "invalid" leaves it guessing at a surface it cannot
    see.

    The type check is not a nicety, and it is the half that is easy to leave out: the signature
    is only "the allowlist" if its ANNOTATIONS bind too. `params` arrives as `dict[str, Any]`
    from the model with no per-key JSON schema behind it (a per-verb `params` cannot be one
    schema), so nothing upstream constrains a value's kind. Unchecked, a `limit="20"` reaches an
    arithmetic clamp (`min(limit, cap)`) and raises `TypeError` INSIDE the verb — where the query
    tool's catch-all maps an unmapped fault to exit 2, the code that means "the system is down".
    Two of those and `circuit_breaker` trips a perfectly healthy system for the rest of the run;
    five and the run aborts. The exit-64 usage class exists precisely so the agent's own mistakes
    can never hide a working system (`circuit_breaker.INFRA_EXIT_CODES`), and before #611
    argparse's `type=`/`store_true` enforced it — in-process, this is the only thing left that
    does. The quieter half is the same mistake without the crash: a truthy `enabled="false"`
    reaching a `bool` param queries the ENABLED users and answers a question nobody asked.
    """
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


# --- the production registry ------------------------------------------------

def _system_of(path: Path) -> str:
    """`scripts/adapters/host_state_adapter.py` → `host-state`. The filename uses `_` where the
    canonical system name uses `-`; normalizing here keeps the registry's roster and the
    queries table's `system` column spelling the same thing."""
    return path.name[: -len(ADAPTER_SUFFIX)].replace("_", "-")


# Loaded adapter modules, keyed by the RESOLVED file path. Keyed on the path and not on the
# module name because the module NAME collides across trees (`probe_cli` in tree A and tree B
# are the same name), and a name-keyed cache — `sys.modules`, or an `@cache` on the system
# string — would hand tree B the module object tree A executed. That is exactly the freeze the
# `defender_dir`-as-a-parameter rule exists to prevent, and it would arrive through the roster
# rather than through the verb.
_MODULES: dict[str, Any] = {}


def _load_adapter_module(path: Path) -> Any:
    resolved = path.resolve()
    key = str(resolved)
    if key not in _MODULES:
        # A synthetic, path-derived module name, and NOT registered in `sys.modules`: two trees'
        # `probe_cli` must be two module objects, and registering either under a shared dotted
        # name would make the second import silently return the first.
        spec = importlib.util.spec_from_file_location(f"_defender_adapter_{abs(hash(key))}", resolved)
        if spec is None or spec.loader is None:
            raise ImportError(f"could not load adapter module {resolved}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULES[key] = module
    return _MODULES[key]


class ModuleVerbRegistry:
    """The production registry, resolved PER TREE: `{system: {verb: fn}}` read from each
    adapter module's `VERBS` mapping under `adapters_dir`.

    `systems()` is the roster ON DISK — every `*_adapter.py`, including one that declares no verbs.
    That system is then *unreachable* (its `verbs()` is empty and the tool rejects it) rather
    than *unfiltered*: an empty declaration must not read as "no filter". This tree already
    fails OPEN in exactly that shape (`descriptor_catalog`'s `or None` degrades an empty roster
    to no-catalog), which is why the emptiness is carried honestly here and decided by the
    caller instead of being smoothed away into an absence. (It used to fail open TWICE — the
    retired main-loop shim regex went `None` on an empty adapter roster too; #667 deleted that
    hook, so `descriptor_catalog` is the surviving instance, not the second of a pair.)
    """

    def __init__(self, adapters_dir: Path):
        self.adapters_dir = Path(adapters_dir)

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(_system_of(p) for p in self.adapters_dir.glob("*" + ADAPTER_SUFFIX)))

    def verbs(self, system: str) -> Mapping[str, Verb]:
        """`system`'s declared verbs. `KeyError` for an unknown OR malformed system — the tool
        turns that into the model-facing "unknown system" rejection; the registry itself makes no
        admission decision beyond containment.

        The name is MODEL-supplied and is joined into a path that gets IMPORTED, so it is guarded
        twice before that: the shape reject (`_SYSTEM_RE`) and the post-join containment check
        (`resolve(path)` must stay under `resolve(adapters_dir)`). Without them,
        `query(system="../../../../tmp/x/pwned")` would exec an arbitrary `pwned_adapter.py` — a code
        path opened by attacker-influenced alert data steering the model."""
        if not _SYSTEM_RE.match(system):
            raise KeyError(system)
        root = self.adapters_dir.resolve()
        path = (self.adapters_dir / (system.replace("-", "_") + ADAPTER_SUFFIX)).resolve()
        if root not in path.parents:
            raise KeyError(system)  # belt: a name that resolved outside the adapters dir
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
