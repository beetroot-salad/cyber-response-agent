
from __future__ import annotations

import ast
import contextvars
import importlib.util
import inspect
import os
import re
import threading
import types
import typing
from collections.abc import Callable, Mapping
from defender._model import model
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Union, get_args, get_origin

from pydantic import SkipValidation, field_validator

from .verb_grant import GrantError, VerbGrant
from defender._io import read_bytes_capped

if TYPE_CHECKING:
    from defender.runtime.run_tenant import RunTenant as _RunTenant
else:
    # `run_tenant` imports `verb_dispositions`, which imports this module: the real class cannot
    # be named here at runtime. Static checking sees `RunTenant`; pydantic sees `Any` (and the
    # field is `SkipValidation` regardless — the record is never rebuilt or copied by a context).
    _RunTenant = Any


class RegistryError(Exception):
    """The adapters directory cannot be read (absent, a regular file, unreadable, not
    searchable, or holding an unopenable adapter file).

    Raised by `read_roster` at process start so an unreadable tree fails before any model call
    instead of becoming an empty roster. Not a `GrantError`, which points at the disposition
    table."""


class CallDelivery:
    """Whether the caller of a served verb is still waiting for its answer.

    The query tool runs a verb on a worker thread; when the awaiting lead is cancelled (a
    sibling lead's budget kill) the worker still runs the call to its end. A registry that
    records delivered calls reads `abandoned` before writing a row for one (#1224, N12)."""

    def __init__(self) -> None:
        self.abandoned = False


#: The current served call's delivery, set by the query tool around the worker thread.
CALL_DELIVERY: contextvars.ContextVar[CallDelivery | None] = contextvars.ContextVar(
    "verb_call_delivery", default=None)


class ServingAbort(Exception):
    """A served verb that will not answer at all: the registry serving it has given up on the
    world it serves (#1224: `estate.oracle.OracleUnservable`). The query tool re-raises it as
    control flow, so it is never filed as a fault row or charged to the circuit breaker; the
    process it ends records why."""

#: The alphabet of a system name, unanchored, for scanners that find a name inside text. A
#: fragment rather than a compiled pattern so nobody matches with it and skips the length bound
#: `is_system_name` applies. Verb names share this alphabet.
SYSTEM_PATTERN = r"[a-z0-9][a-z0-9-]*"
#: Private so callers use `is_system_name`, which also applies the bound. Anchored at both ends
#: so `.search` cannot match a well-formed suffix of a bad name.
_SYSTEM_RE = re.compile(rf"\A{SYSTEM_PATTERN}\Z")
#: Ceiling on a system name, which arrives as unbounded model text at several readers (the
#: prompt-cache key, the `query` tool's echo, the gather tool's retry message).
SYSTEM_MAX_LEN = 64


def is_system_name(name: str) -> bool:
    """Is `name` a well-formed system name (lowercase letters, digits and hyphens, bounded)?

    The single check for every channel a system name arrives on; a looser second spelling
    would admit names the dispatch seam later rejects. Shape only, never membership.
    """
    # Length first so an arbitrarily long model-supplied blob is refused without a regex scan.
    return len(name) <= SYSTEM_MAX_LEN and bool(_SYSTEM_RE.match(name))


ADAPTER_SUFFIX = "_adapter.py"

#: How model-facing text names a tenant's host-only `settings/` folder: by what it is, never by
#: its host path. The table pointers and the query tool's fault redaction build on it.
SETTINGS_POINTER = "the tenant's settings/"

#: A refusal's pointer at the verb-disposition table when no run supplied its tenant's pointer.
TABLE_POINTER = f"{SETTINGS_POINTER}verb-grants.yaml"


def redact_settings_path(text: str, settings: Path) -> str:
    """`text` with the tenant's host settings folder — as given and as resolved — named by
    `SETTINGS_POINTER` instead. THE ONE REDACTION every model- or run-dir-facing channel that can
    carry an adapter's or the resolver's fault text goes through (the query tool's two fault
    channels, lead-zero's "unavailable" note, the ticket writer's receipt reason): a fault worded
    with the path it read would otherwise put the host's layout in front of the model, and the run
    dir is the box's writable mount. @owns settings redaction"""
    for spelling in {str(Path(settings)), str(Path(settings).resolve())}:
        text = text.replace(spelling.rstrip("/") + "/", SETTINGS_POINTER).replace(
            spelling, SETTINGS_POINTER.rstrip("/"))
    return text


@model(frozen=True)
class VerbContext:

    defender_dir: Path
    run_dir: Path
    #: `SkipValidation`: pydantic would copy an abstract `Mapping` into a writable `dict`,
    #: replacing a read-only proxy or the live `os.environ` with a snapshot on every call.
    env: Annotated[Mapping[str, str], SkipValidation]
    #: The run's tenant record (#1107): its settings folder, grants and everything resolved from
    #: the folder once (each system's `config.env`, the corpus-engine view, the ticket mapping),
    #: in place of the folder and the process environment. No default, so no site can silently
    #: read another tenant's or the checkout's. `defender_dir` is the code tree; the folder path
    #: stays reachable as `tenant.settings`. `SkipValidation` because the real class cannot be
    #: imported here (see the import note above); `_tenant_given` still refuses `None`.
    tenant: Annotated[_RunTenant, SkipValidation]
    capture: Any = None
    #: The moment a branched-world call is served as of; `None` for the ordinary run, which
    #: uses the wall clock. Every world of a family, the base included, carries the branch
    #: point's moment, so no branch arm reads the wall clock (that would make it unreplayable).
    #:
    #: Set by the estate registry on every call. A `datetime` rather than a string
    #: because systems format timestamps differently; not a callable because a function as a
    #: dataclass default would bind `ctx` as its first argument when called.
    as_of: datetime | None = None

    @field_validator("tenant")
    @classmethod
    def _tenant_given(cls, value: Any) -> Any:
        # The guard `settings_dir: Path` gave for free: a verb over no record would fail later,
        # inside the adapter, as an AttributeError the breaker files as an infra fault.
        if value is None:
            raise ValueError("a verb context needs the run's tenant record; got None")
        return value


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
    """`wrapper_only` names params a first-party wrapper binds and no model may.

    E.g. `ticket`'s `require_closed`: the closed-ticket tool pins it, while a gather lead that
    set it would silently drop the open siblings it was dispatched to correlate. A marked param
    is refused by `validate_params` and omitted from `model_facing_params`; the wrapper calls
    `fn(ctx, **params)` directly and never crosses that check.
    """
    # Checked at decoration because both mistakes are silent: a bare string reserves its
    # characters, and a misspelt name reserves nothing, leaving the param model-settable.
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
        # A reserved param needs a default: it is outside the required set `validate_params`
        # checks, so without one every model call would raise TypeError inside the verb body
        # and be filed as an infra fault.
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
    """The verb_class a verb body declares via `@verb(verb_class=…)`; `r` when undecorated."""
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
    """The declared params a model may bind: `declared_params` minus the wrapper-only set.

    Both `validate_params` and `list_verbs` use this, so what is accepted and what is published
    cannot disagree."""
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
    """Every param problem in one model-facing message, or `None` if the call is valid.

    Reporting all problems at once saves the model a retry per problem. A param already
    reported as reserved or unknown is not also reported as mistyped."""
    declared = model_facing_params(fn)
    problems: list[str] = []
    # Before the unknown check: a wrapper-only param is declared, so "unknown" would send the
    # model looking for a typo it did not make.
    reserved = sorted(set(params) & wrapper_only_params(fn))
    if reserved:
        problems.append(
            f"param(s) {reserved} are set by the first-party tool that owns this read, never "
            f"by you — this verb's caller-settable params are {sorted(declared)}."
        )
    unknown = sorted(set(params) - set(declared) - set(reserved))
    if unknown:
        problems.append(
            f"unknown param(s) {unknown} — this verb declares "
            f"{sorted(declared)} and nothing else."
        )
    missing = sorted(
        name for name, p in declared.items()
        if p.default is inspect.Parameter.empty and name not in params
    )
    if missing:
        problems.append(
            f"missing required param(s) {missing} (declared params: {sorted(declared)}).")

    hints = _resolved_hints(fn)
    already_named = set(reserved) | set(unknown)
    mistyped = sorted(
        f"{name!r} takes {_ann_name(hints[name])}, got "
        f"{type(params[name]).__name__} ({params[name]!r})"
        for name in params
        if name in hints and name not in already_named and not _matches(params[name], hints[name])
    )
    if mistyped:
        problems.append(
            f"wrong param type(s): {'; '.join(mistyped)}. Pass JSON values of the declared "
            "type — a number is a number, not a quoted string, and a boolean is true/false."
        )
    if not problems:
        return None
    return " ".join(problems)



def _system_of(path: Path) -> str:
    return path.name[: -len(ADAPTER_SUFFIX)].replace("_", "-")


_MODULES: dict[str, Any] = {}

#: Serializes the check-then-exec below: parallel gather leads resolve adapters on worker
#: threads, and a double `exec_module` would run side effects twice and split verb identity.
#: `RLock` because an adapter whose import reaches back into the registry would deadlock a `Lock`.
_MODULES_LOCK = threading.RLock()


def _load_adapter_module(path: Path) -> Any:
    resolved = path.resolve()
    key = str(resolved)
    with _MODULES_LOCK:
        if key not in _MODULES:
            spec = importlib.util.spec_from_file_location(
                f"_defender_adapter_{abs(hash(key))}", resolved,
            )
            if spec is None or spec.loader is None:
                raise ImportError(f"could not load adapter module {resolved}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _MODULES[key] = module
        return _MODULES[key]


def _adapter_path_under(root: Path, system: str) -> Path | None:
    """The adapter file `system` dispatches from under the already-resolved `root`, or `None`.

    Touches the disk, so it is called only inside `read_roster`'s error wrap."""
    if not is_system_name(system):
        return None
    path = (root / (system.replace("-", "_") + ADAPTER_SUFFIX)).resolve()
    if root not in path.parents or not path.is_file():
        return None
    return path


def _verb_names_in(source: bytes, path: Path) -> tuple[frozenset[str], str | None]:
    """Cold read of one adapter's `VERBS = {...}` literal from its source bytes, without disk I/O.

    Returns `(names, None)`, or `(frozenset(), why)` when the source does not parse. Parses
    bytes rather than decoded text so it accepts exactly what the import accepts (a `# coding:`
    line, a non-UTF-8 byte in a comment). Only string keys of a dict-literal assignment count;
    a table built any other way declares nothing, so the grant's load check fails rather than
    treating an unreadable table as a blank cheque."""
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, RecursionError) as e:
        return frozenset(), f"{type(e).__name__}: {e}"
    names: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "VERBS" for t in node.targets):
            continue
        for key in node.value.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                names.add(key.value)
    return frozenset(names), None


GRANTED = "GRANTED"
DENIED = "DENIED"
UNDECLARED = "UNDECLARED"


@model(frozen=True, eq=False)
class RosterRead:
    """One complete read of an adapters directory, shared as a value by every consumer.

    `accepted` maps each system to the adapter file that dispatches it; `verbs` maps it to the
    verb names its adapter declares (read cold); `unparsed` maps systems whose source did not
    parse to the parser's reason (their `verbs` entry is empty); `refused` lists, sorted and
    deduplicated, derived names the dispatch seam would not resolve. The maps are read-only
    views so no consumer can mutate the registry's roster."""

    root: Path
    # The concrete view class, not `Mapping`: pydantic would copy a `Mapping` into a writable dict.
    accepted: types.MappingProxyType[str, Path]
    verbs: types.MappingProxyType[str, frozenset[str]]
    unparsed: types.MappingProxyType[str, str]
    refused: tuple[str, ...]

    def declared_verbs(self, system: str) -> frozenset[str]:
        """The verb names `system`'s adapter declares; empty if not accepted or unparsed."""
        return self.verbs.get(system, frozenset())


def _cannot_read(adapters_dir: Path, e: BaseException, *, blame_entry: bool = True) -> str:
    """`RegistryError`'s text: always the directory, plus the file when the fault was one entry's.

    `blame_entry=False` omits the entry for faults the OS reports against an entry but which
    are the directory's (the `lstat` pass's `EACCES`)."""
    fault = getattr(e, "strerror", None) or str(e)
    text = f"adapters directory {adapters_dir} cannot be read ({fault})"
    filename = getattr(e, "filename", None) if blame_entry else None
    if filename and Path(filename) != Path(adapters_dir):
        text += f" at {filename}"
    return text


def read_roster(adapters_dir: Path) -> RosterRead:
    """The one read of an adapters directory; raises `RegistryError` if it cannot be read.

    Read once at process start and handed down as a value, so every consumer (registry,
    dispatch catalogs, workspace map, gate, audit) sees the same set.

    @owns accepted — derived here and nowhere else.
    @owns refused — derived here and nowhere else.
    @owns verbs — the cold verb read, per accepted system, here and nowhere else.
    @owns unparsed — the parser's reason per adapter whose source it refused.

    All disk I/O happens in one `try` pass, so its `except` fully covers "the host could not
    read the tree"; parsing happens afterwards on bytes in memory and is recorded per file in
    `unparsed`. `os.scandir` is used because it raises for an absent, non-directory or
    unreadable path, where `Path.glob` silently yields `[]`.

    Every entry is `lstat`ed: a directory with the read bit but not the search bit lists fine,
    then fails every resolve (on 3.14+ `is_file` swallows `EACCES`, giving a silent empty
    roster). `follow_symlinks=False` so a dangling symlink is dropped, not treated as that fault.

    Names are filtered through `_adapter_path_under`, not `is_system_name` alone, because
    `_system_of`'s `_`->`-` mapping is not invertible (e.g. `change-mgmt_adapter.py` derives a
    name the seam looks for at `change_mgmt_adapter.py`), and a directory can end in the suffix.

    `RuntimeError` covers `Path.resolve` on a symlink loop (3.11/3.12); `PermissionError` can
    come from `is_file` (3.11-3.13) or `read_bytes`. All are the same "cannot read" fault."""
    adapters_dir = Path(adapters_dir)
    try:
        with os.scandir(adapters_dir) as it:
            entries = [e for e in it if e.name.endswith(ADAPTER_SUFFIX)]
        for entry in entries:
            try:
                entry.stat(follow_symlinks=False)
            except PermissionError as e:
                # `EACCES` here is the directory's missing search bit, though the OS names
                # the entry; don't blame the entry.
                raise RegistryError(_cannot_read(adapters_dir, e, blame_entry=False)) from e
        resolved = adapters_dir.resolve()
        accepted: dict[str, Path] = {}
        sources: dict[str, bytes] = {}
        refused: list[str] = []
        for name in sorted({_system_of(Path(entry.name)) for entry in entries}):
            path = _adapter_path_under(resolved, name)
            if path is None:
                refused.append(name)
            else:
                accepted[name] = path
                sources[name] = read_bytes_capped(path)
    except (OSError, RuntimeError) as e:
        raise RegistryError(_cannot_read(adapters_dir, e)) from e
    declared: dict[str, frozenset[str]] = {}
    unparsed: dict[str, str] = {}
    for name, source in sources.items():
        declared[name], why = _verb_names_in(source, accepted[name])
        if why is not None:
            unparsed[name] = why
    return RosterRead(
        root=adapters_dir,
        accepted=types.MappingProxyType(accepted),
        verbs=types.MappingProxyType(declared),
        unparsed=types.MappingProxyType(unparsed),
        refused=tuple(refused),
    )

@model(frozen=True)
class VerbDecision:

    outcome: str
    fn: Verb | None
    refusal: str | None


class VerbRegistry:
    """The nominally typed verb-registry seam.

    Construction requires a real `VerbGrant`, and entry points check the type, since a
    structural check cannot tell a real grant from a stand-in that grants everything."""

    #: Where this registry's grant is authored, named in `decide`'s refusals; `None` for a code
    #: literal, since pointing at a file that cannot widen the grant would mislead. Builders of
    #: a run's registry pass the model-facing `run_tenant.table_pointer`, never the host path.
    grant_home: str | None = None

    def __init__(self, grant: VerbGrant):
        if not isinstance(grant, VerbGrant):
            raise GrantError(
                f"a verb registry requires a real VerbGrant, got {type(grant).__name__}"
            )
        self.grant = grant

    def systems(self) -> tuple[str, ...]:
        """The systems this registry declares. Must not raise or do I/O: a registry that cannot
        learn its roster fails at construction. The query tool relies on this to classify a
        rejected `system` as declared or unknown, with no third answer."""
        raise NotImplementedError

    def verbs(self, system: str) -> Mapping[str, Verb]:
        raise NotImplementedError

    def _cold_verb_names(self, system: str) -> frozenset[str] | None:
        """Verb names `system` declares, without importing; `None` if there is no cold source,
        in which case `decide` falls back to `self.verbs(system)`. Real-adapter subclasses
        must override this so a refusal never imports an adapter."""
        return None

    def decide(self, system: str, verb: str) -> VerbDecision:
        """The grant decision point.

        Decided from the grant first; no adapter is imported unless the grant admits the call.
        A verb the system does not declare (including near-misses) is UNDECLARED; DENIED is
        only for a real, withheld verb. A wholly ungranted system is also UNDECLARED, which
        carries agent-visible retry semantics (no denial record, agent-fixable).

        The UNDECLARED message distinguishes a typo from a declared verb on an ungranted
        system, so a freshly connected system is not mistaken for a spelling error. A refusal
        never names a verb the caller did not already name.
        """
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
                    # A withheld verb is a table row without this role; point at the table.
                    withheld = (
                        f" Withheld in the verb-disposition table ({self.grant_home})."
                    ) if self.grant_home is not None else ""
                    return VerbDecision(
                        DENIED, None,
                        f"{system}.{verb} is not granted to role {self.grant.role!r}."
                        f"{withheld}",
                    )
                return VerbDecision(
                    UNDECLARED, None,
                    f"unresolvable: {system}.{verb} — role {self.grant.role!r} reaches "
                    f"{system!r}, but no verb of that name is declared there.",
                )
            # The grant reaches this system nowhere. A cold read (never an import) tells a
            # typo from an ungranted real verb; an ungranted adapter must not be executed.
            cold = self._cold_verb_names(system)
            declared_here = cold is not None and verb in cold
            if not declared_here:
                return VerbDecision(
                    UNDECLARED, None,
                    f"unresolvable: {system}.{verb} (unknown, or role "
                    f"{self.grant.role!r} holds no grant reaching it).",
                )
            # No pointer when `grant_home` is `None`: the table cannot widen a code-literal grant.
            fix = (
                f" If {system!r} was just connected, it needs rows in the verb-disposition "
                f"table ({self.grant_home})."
            ) if self.grant_home is not None else ""
            return VerbDecision(
                UNDECLARED, None,
                f"unresolvable: {system}.{verb} — the verb is declared, but role "
                f"{self.grant.role!r} holds no grant reaching the {system!r} system at "
                f"all.{fix}",
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

    def decide_call(self, system: str, verb: str, params: Mapping[str, Any]) -> VerbDecision:
        """`decide` for a call the model is actually making, as opposed to verb discovery.

        Separate so a registry that records served calls (`estate.registry.WorldRegistry`) does
        not record listings. `params` is for that record; the decision is `decide`'s alone."""
        return self.decide(system, verb)


class ModuleVerbRegistry(VerbRegistry):

    def __init__(self, roster: RosterRead, grant: VerbGrant, *, grant_home: str = TABLE_POINTER):
        super().__init__(grant)
        # Takes the roster value `read_roster` produced at process start, never a directory:
        # an unreadable tree then fails there as `RegistryError`, not here as a grant mismatch.
        # All later questions are answered from the snapshot; the adapters tree is assumed not
        # to change under a live registry.
        if not isinstance(roster, RosterRead):
            raise TypeError(
                f"a ModuleVerbRegistry takes the RosterRead `read_roster` produced, got "
                f"{type(roster).__name__} — read the adapters directory once where the "
                "process starts and hand the value down"
            )
        self.roster = roster
        self._systems: tuple[str, ...] = tuple(sorted(roster.accepted))
        # The run's tenant's table pointer when supplied, else the generic one; every grant
        # this class serves a model is a table projection.
        self.grant_home = grant_home
        offenders = [
            (s, v) for s, v, _ in grant.entries if v not in self._cold_verb_names(s)
        ]
        if offenders:
            named = ", ".join(f"{s}.{v}" for s, v in offenders)
            raise GrantError(
                f"verb_grant for role {grant.role!r} names verb(s) the adapters under "
                f"{roster.root} do not declare: {named}"
            )

    def systems(self) -> tuple[str, ...]:
        """The accepted systems of the roster this registry was built over."""
        return self._systems

    def _cold_verb_names(self, system: str) -> frozenset[str]:
        # Answered from the roster, so no per-question state accumulates: `system` can be
        # unbounded model text on `decide`'s refusal path.
        return self.roster.declared_verbs(system)

    def verbs(self, system: str) -> Mapping[str, Verb]:
        # From the roster, so `verbs()` and `systems()` cannot disagree. A tree removed under a
        # live registry surfaces here as the import's `OSError` (a host fault), never as
        # "unknown system".
        path = self.roster.accepted.get(system)
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
    "SYSTEM_MAX_LEN",
    "SYSTEM_PATTERN",
    "UNDECLARED",
    "ModuleVerbRegistry",
    "RegistryError",
    "CALL_DELIVERY",
    "CallDelivery",
    "RosterRead",
    "ServingAbort",
    "Verb",
    "VerbContext",
    "VerbDecision",
    "VerbRegistry",
    "body_param_for",
    "body_param_of",
    "declared_params",
    "engine_for",
    "engine_of",
    "is_system_name",
    "model_facing_params",
    "read_roster",
    "validate_params",
    "verb",
    "verb_class_of",
    "wrapper_only_params",
]
