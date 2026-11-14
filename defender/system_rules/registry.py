"""The one read of an adapters directory (#1035) and what is read of it without running an adapter: the roster
(`RosterRead`, `read_roster`, `RegistryError`), the platform-served system names (#1390), and the loader that executes an
adapter file afresh (`fresh_adapter_module`). Moved below `systems` (#1470 D-E) so the record judgement the API loads
reads the catalog with no run code; `systems.verbs` re-exports these names, so they are the same objects there."""
from __future__ import annotations

import ast
import importlib.util
import os
import types
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from defender._io import read_bytes_capped
from defender._model import model
from defender.kit.verbs import HOST_ACTIONS, is_system_name

ADAPTER_SUFFIX = "_adapter.py"

#: The platform-served systems (#1390) and the verb names each serves: product code the platform runs itself, never an
#: adapter file. Their names are reserved; every roster holds them, whatever the adapters folder says. The one statement of
#: these names: `systems.tacit_registry` builds its verb table from them.
TACIT_KNOWLEDGE = "tacit-knowledge"
PLATFORM_SERVED_NAMES: Mapping[str, frozenset[str]] = types.MappingProxyType({
    TACIT_KNOWLEDGE: frozenset({"health-check", "lookup"}),
})

RESERVED_REASON = "reserved for the platform-served system of that name (an adapter may not use it)"
ANOMALOUS_REASON = "anomalous adapter name: not a name the dispatch seam resolves"


class RegistryError(Exception):
    """The adapters directory cannot be read (absent, a regular file, unreadable, not
    searchable, or holding an unopenable adapter file).

    Raised by `read_roster` at process start so an unreadable tree fails before any model call
    instead of becoming an empty roster. Not a `GrantError`, which points at the disposition
    table."""


def is_platform_served(system: str) -> bool:
    """Whether `system` is served by the platform itself (reserved name, in every roster)."""
    return system in PLATFORM_SERVED_NAMES


def system_of(path: Path) -> str:
    """The system an adapter file dispatches as: its stem without the suffix, `_` read as `-`."""
    return path.name[: -len(ADAPTER_SUFFIX)].replace("_", "-")


def exec_adapter_module(resolved: Path, name: str) -> Any:
    """Execute the adapter file at `resolved` as a new module object named `name` (never put
    in `sys.modules`)."""
    spec = importlib.util.spec_from_file_location(name, resolved)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load adapter module {resolved}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fresh_adapter_module(roster: RosterRead, system: str) -> Any:
    """`system`'s adapter module imported afresh from the file `roster` accepted for it, for
    its settings check at run start (`system_status.judge_run`, #1256) and the catalog. Never
    cached here: the call-time load (`systems.verbs.ModuleVerbRegistry.verbs`) keeps its own
    semantics, and this read neither primes nor consults it. `KeyError` for a system the roster
    does not accept; an import that fails raises its own exception."""
    path = roster.adapter_files.get(system)
    if path is None:
        raise KeyError(system)
    resolved = path.resolve()
    return exec_adapter_module(resolved, f"_defender_adapter_check_{abs(hash(str(resolved)))}")


def adapter_path_under(root: Path, system: str) -> Path | None:
    """The adapter file `system` dispatches from under the already-resolved `root`, or `None`.

    Touches the disk, so it is called only inside `read_roster`'s error wrap."""
    if not is_system_name(system):
        return None
    path = (root / (system.replace("-", "_") + ADAPTER_SUFFIX)).resolve()
    if root not in path.parents or not path.is_file():
        return None
    return path


_ACTION_SPELLINGS = {spelling: action for action in HOST_ACTIONS
                     for spelling in (action, action.replace("_", "-"))}


def _exposed_host_action(table: ast.Dict) -> str | None:
    """The host-only action this `VERBS` literal hands to the agent (#1359 O4, #1374), or None. A
    key spelling one either way, or a value that is its bare name."""
    for key, value in zip(table.keys, table.values, strict=True):
        if isinstance(key, ast.Constant) and key.value in _ACTION_SPELLINGS:
            return _ACTION_SPELLINGS[key.value]
        if isinstance(value, ast.Name) and value.id in HOST_ACTIONS:
            return value.id
    return None


def _verb_names_in(source: bytes, path: Path) -> tuple[frozenset[str], str | None, bool]:
    """Cold read of one adapter's `VERBS = {...}` literal from its source bytes, without disk I/O.

    Returns `(names, None, empty)`, or `(frozenset(), why, False)` when the source does not parse
    or its `VERBS` exposes the host-only comment action (the adapter is then refused whole: none
    of its verbs is granted). `empty` is true when a `VERBS` dict literal exists and holds nothing:
    an adapter with no agent actions, valid, as against one with no readable `VERBS`. Parses bytes
    rather than decoded text so it accepts exactly what the import accepts (a `# coding:` line, a
    non-UTF-8 byte in a comment). Only string keys of a dict-literal assignment count; a table
    built any other way declares nothing, so the grant's load check fails rather than treating an
    unreadable table as a blank cheque."""
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, RecursionError) as e:
        return frozenset(), f"{type(e).__name__}: {e}", False
    names: set[str] = set()
    literal = False
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "VERBS" for t in node.targets):
            continue
        literal = True
        exposed = _exposed_host_action(node.value)
        if exposed is not None:
            return frozenset(), (
                f"its VERBS exposes the host-only action `{exposed}`: that function is the "
                "host's own call to the case and is never a verb an agent may be granted"
            ), False
        for key in node.value.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                names.add(key.value)
    return frozenset(names), None, literal and not names


class GrantSystems(Protocol):
    """What `RosterRead.systems_shown_to` reads of a verb grant (`systems.verb_grant.VerbGrant`): the systems it reaches.
    Structural, so this package names no `systems` type."""

    @property
    def systems(self) -> frozenset[str]: ...


@model(frozen=True, eq=False)
class RosterRead:
    """One complete read of an adapters directory, shared as a value by every consumer.

    A roster's *systems* are the keys of `verbs`: the adapter files plus the platform-served
    systems (#1390), whose verbs are product code. `adapter_files` maps each system dispatched
    from a file to that file, and nothing else: a consumer that reads a file uses it, a consumer
    that reads a name uses the systems. `verbs` maps each system to the verb names it declares
    (an adapter's read cold); `unparsed` maps systems whose source did not parse to the parser's
    reason (their `verbs` entry is empty); `refused` maps, sorted, each derived name the dispatch
    seam would not resolve to why. The maps are read-only views so no consumer can mutate the
    registry's roster."""

    root: Path
    # The concrete view class, not `Mapping`: pydantic would copy a `Mapping` into a writable dict.
    adapter_files: types.MappingProxyType[str, Path]
    verbs: types.MappingProxyType[str, frozenset[str]]
    unparsed: types.MappingProxyType[str, str]
    refused: types.MappingProxyType[str, str]
    #: Systems whose `VERBS` is an empty dict literal: adapters with no agent actions (#1359 R1),
    #: valid, as against one whose `VERBS` cannot be read.
    no_verbs: frozenset[str] = frozenset()
    #: Whether this is a whole read of its adapters directory (a catalog), or one tenant's systems
    #: drawn from one (`systems.catalog.TenantSystems`, #1366 DC7). The surfaces with no tenant (the
    #: invlang ceiling gate among them) key on this, never on `root`, which a tenant's roster
    #: shares with the catalog it was drawn from.
    whole: bool = True

    def declared_verbs(self, system: str) -> frozenset[str]:
        """The verb names `system` declares; empty if not in the roster or unparsed."""
        return self.verbs.get(system, frozenset())

    @property
    def systems(self) -> tuple[str, ...]:
        """Every system of the roster, sorted: adapter files and platform-served systems."""
        return tuple(sorted(self.verbs))

    def systems_shown_to(self, grant: GrantSystems) -> tuple[str, ...]:
        """The systems a run holding `grant` is told about: every adapter's, and a
        platform-served one only where the grant holds a verb of it. A platform-served system is
        in every tenant's roster, so listing it regardless would invite calls that can only be
        denied (#1390 A3)."""
        return tuple(s for s in self.systems if not is_platform_served(s) or s in grant.systems)


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


def _sorted_adapter_names(resolved: Path, names: list[str]) -> tuple[dict[str, Path], dict[str, str]]:
    """`names` split into the adapter files the dispatch seam resolves, and why it refuses each
    of the others."""
    accepted: dict[str, Path] = {}
    refused: dict[str, str] = {}
    for name in names:
        path = adapter_path_under(resolved, name)
        if is_platform_served(name):
            refused[name] = RESERVED_REASON
        elif path is None:
            refused[name] = ANOMALOUS_REASON
        else:
            accepted[name] = path
    return accepted, refused


def read_roster(adapters_dir: Path) -> RosterRead:
    """The one read of an adapters directory; raises `RegistryError` if it cannot be read."""
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
        accepted, refused = _sorted_adapter_names(
            resolved, sorted({system_of(Path(entry.name)) for entry in entries}))
        sources = {name: read_bytes_capped(path) for name, path in accepted.items()}
    except (OSError, RuntimeError) as e:
        raise RegistryError(_cannot_read(adapters_dir, e)) from e
    declared: dict[str, frozenset[str]] = {}
    unparsed: dict[str, str] = {}
    empty: set[str] = set()
    for name, source in sources.items():
        declared[name], why, none_declared = _verb_names_in(source, accepted[name])
        if why is not None:
            unparsed[name] = why
        elif none_declared:
            empty.add(name)
    declared.update(PLATFORM_SERVED_NAMES)
    return RosterRead(
        root=adapters_dir,
        adapter_files=types.MappingProxyType(accepted),
        verbs=types.MappingProxyType(dict(sorted(declared.items()))),
        unparsed=types.MappingProxyType(unparsed),
        refused=types.MappingProxyType(refused),
        no_verbs=frozenset(empty),
    )


__all__ = ["ADAPTER_SUFFIX", "ANOMALOUS_REASON", "PLATFORM_SERVED_NAMES", "RESERVED_REASON", "GrantSystems",
           "RegistryError", "RosterRead", "TACIT_KNOWLEDGE", "adapter_path_under", "exec_adapter_module", "fresh_adapter_module",
           "is_platform_served", "read_roster", "system_of"]
