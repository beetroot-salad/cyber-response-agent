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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The shape a system NAME may take: lowercase kebab, no separators, no dots. `system` is
#: MODEL-supplied (the `query` tool passes it straight here), and it is joined into a filesystem
#: path that is then IMPORTED — so a name carrying `/` or `..` (`../../../tmp/evil/pwned`) would,
#: with a matching `*_cli.py` on disk, execute an arbitrary module. The shape reject is the first
#: gate; the resolved-containment check in `verbs()` is the belt behind it (the invariant is
#: "resolve(adapters_dir/<file>) stays under resolve(adapters_dir)", which holds even if a future
#: edit loosens this pattern). Neither alone: a bare shape check trusts `.replace('-','_')` not to
#: reintroduce a separator, and a bare containment check would still import a same-dir module the
#: roster never listed.
_SYSTEM_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")

#: A `<system>_cli.py` module keeps its filename even though it is no longer a CLI: the
#: suffix is load-bearing in four independent places (this glob, `ADAPTER_CLI_RE`, jscpd's
#: `--ignore` under a hard `--threshold 3`, and `lint_duplicate_helpers.EXCLUDED_SUFFIXES`),
#: so renaming seven near-identical registries would turn them into a CI-red duplication
#: finding. Honest naming is a follow-up, not a rider on this change.
ADAPTER_SUFFIX = "_cli.py"


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


def validate_params(fn: Verb, params: Mapping[str, Any]) -> str | None:
    """`None` if `params` satisfies `fn`'s declared surface, else the model-facing reason.

    Rejects an unknown key and a missing required one (a kw-only param with no default). The
    reason NAMES the declared roster — the model has no `--help` any more, so a rejection that
    only says "invalid" leaves it guessing at a surface it cannot see.
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
    return None


# --- the production registry ------------------------------------------------

def _system_of(path: Path) -> str:
    """`scripts/adapters/host_state_cli.py` → `host-state`. The filename uses `_` where the
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

    `systems()` is the roster ON DISK — every `*_cli.py`, including one that declares no verbs.
    That system is then *unreachable* (its `verbs()` is empty and the tool rejects it) rather
    than *unfiltered*: an empty declaration must not read as "no filter". This tree already
    fails OPEN twice in exactly that shape (`adapter_shims()` returning the empty set makes the
    shim regex `None`; `descriptor_catalog`'s `or None` degrades an empty roster to no-catalog),
    which is why the emptiness is carried honestly here and decided by the caller instead of
    being smoothed away into an absence.
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
        `query(system="../../../../tmp/x/pwned")` would exec an arbitrary `pwned_cli.py` — a code
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
    "declared_params",
    "validate_params",
]
