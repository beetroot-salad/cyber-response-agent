"""The catalog of adapters and a tenant's systems (#1366 DC7): two types, so a surface says which it reads.

`Catalog` is the whole checkout: every `*_adapter.py` under `integrations/`, with the declarations each makes as
module constants (`DISPLAY_NAME`, `EXAMPLE`, `PREFIX`, `REQUIRED_CONFIG_KEYS`, `PATH_KEYS`, read cold, K2) and its
`comment_route` (read by loading the module, C1). The surfaces with no tenant read it: the product CI census lint,
the invlang ceiling gate, connect, `check --folder`, the operator's `catalog` listing and the record judgement.

`TenantSystems` is what one tenant has: its current enabled records whose adapter the catalog carries, plus the
platform-served systems, built once from the tenant's current-records read (`TenantRecords`) and handed to every
tenant surface (O1). Its `roster` is the `RosterRead` those surfaces consume; a catalog adapter no record names is not
in it. A record whose adapter the catalog lacks (an upgrade removed it) and a disabled record are kept apart, so run
start and `tenant check` can say what became of them (R12)."""
from __future__ import annotations

import ast
import dataclasses
import threading
import types
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from defender._io import read_bytes_capped
from defender._paths import adapters_under, process_defender_dir
from defender.kit.transport import REQUIRED_CONFIG_KEYS_TEMPLATE
from defender.kit.verbs import COMMENT_ACTION
from defender.systems.verbs import PLATFORM_SERVED, RosterRead, fresh_adapter_module, is_platform_served, read_roster
from defender.tenancy.models import SystemRecord, TenantRecords

#: The module constants every catalog adapter declares, read cold (K2).
DECLARATIONS = ("PREFIX", "REQUIRED_CONFIG_KEYS", "PATH_KEYS", "DISPLAY_NAME", "EXAMPLE")
#: The adapter function that declares the comment route (C1).
COMMENT_ROUTE = "comment_route"
#: The shared keys template an adapter's keys may splat (`*transport.REQUIRED_CONFIG_KEYS_TEMPLATE`).
_TEMPLATE_NAME = "REQUIRED_CONFIG_KEYS_TEMPLATE"


@dataclasses.dataclass(frozen=True)
class CatalogEntry:
    """One catalog adapter as its module declares it, read without running it. A declaration the module lacks, or does
    not spell as a literal, is None (`PATH_KEYS` defaults to none); `unparsed` is the roster's reason when its source
    could not be read."""

    adapter_id: str
    path: Path
    display_name: str | None
    example: bool
    prefix: str | None
    required_keys: tuple[str, ...] | None
    path_keys: tuple[str, ...]
    tools: frozenset[str]
    unparsed: str | None = None

    @property
    def stored_keys(self) -> tuple[str, ...]:
        """The settings keys a record of this adapter holds: each required key with the prefix, as stored."""
        if self.prefix is None or self.required_keys is None:
            return ()
        return tuple(f"{self.prefix}_{key}" for key in self.required_keys)


class Catalog:
    """The whole checkout's adapters (DC7), over one roster read of `integrations/`. Entries are read cold and lazily,
    modules loaded on demand and held for this catalog's life (the judgement asks one module several questions)."""

    def __init__(self, roster: RosterRead) -> None:
        self._roster = roster
        self._entries: dict[str, CatalogEntry] = {}
        self._modules: dict[str, Any] = {}
        self._lock = threading.Lock()

    @classmethod
    def of_checkout(cls, defender_dir: Path | None = None) -> Catalog:
        """The catalog of the checkout at `defender_dir` (the running process's tree when None). Raises the roster's
        `RegistryError` when the adapters directory cannot be read."""
        return cls(read_roster(adapters_under(Path(defender_dir) if defender_dir else process_defender_dir())))

    @property
    def roster(self) -> RosterRead:
        """The whole catalog's roster: every adapter of the checkout plus the platform-served systems."""
        return self._roster

    @property
    def adapter_ids(self) -> tuple[str, ...]:
        """Every adapter the catalog carries, sorted (platform-served systems are none)."""
        return tuple(sorted(self._roster.adapter_files))

    def __contains__(self, adapter_id: object) -> bool:
        return adapter_id in self._roster.adapter_files

    def entry(self, adapter_id: str) -> CatalogEntry:
        """`adapter_id`'s declarations, read cold; `KeyError` when the catalog has no such adapter."""
        with self._lock:
            found = self._entries.get(adapter_id)
        if found is not None:
            return found
        path = self._roster.adapter_files[adapter_id]
        unparsed = self._roster.unparsed.get(adapter_id)
        values = {} if unparsed is not None else _cold_declarations(path)
        made = CatalogEntry(
            adapter_id=adapter_id, path=path,
            display_name=_nonblank(values.get("DISPLAY_NAME")), example=values.get("EXAMPLE") is True,
            prefix=_nonblank(values.get("PREFIX")), required_keys=_keys(values.get("REQUIRED_CONFIG_KEYS")),
            path_keys=_keys(values.get("PATH_KEYS")) or (), tools=self._roster.declared_verbs(adapter_id),
            unparsed=unparsed)
        with self._lock:
            self._entries[adapter_id] = made
        return made

    def entries(self) -> tuple[CatalogEntry, ...]:
        """Every adapter's entry, by id."""
        return tuple(self.entry(a) for a in self.adapter_ids)

    def module(self, adapter_id: str) -> Any:
        """`adapter_id`'s module, loaded afresh from the checkout once per catalog; `KeyError` for an adapter the catalog
        lacks; an import that fails raises its own exception (and is retried on the next ask)."""
        with self._lock:
            if adapter_id in self._modules:
                return self._modules[adapter_id]
        loaded = fresh_adapter_module(self._roster, adapter_id)
        with self._lock:
            return self._modules.setdefault(adapter_id, loaded)

    def comment_route(self, adapter_id: str, settings: Mapping[str, str]) -> tuple[str, str] | None:
        """The route `adapter_id`'s comment action sends for a record holding `settings` (prefixed), or None when it
        offers no comment action (C1: no `comment_route`, or one that returns None). The adapter's `ConfigFault` for
        settings its route cannot be built from propagates."""
        return route_of(self.module(adapter_id), settings)


def route_of(module: Any, settings: Mapping[str, str]) -> tuple[str, str] | None:
    """`module`'s comment route for `settings`, or None when it declares none or no comment action. "Offers a comment
    action" is exactly "has a route" (C1); a module with `add_case_comment` and no route offers none."""
    if not callable(getattr(module, COMMENT_ACTION, None)):
        return None
    declare = getattr(module, COMMENT_ROUTE, None)
    if not callable(declare):
        return None
    route = declare(settings)
    if route is None:
        return None
    method, pattern = route
    return str(method), str(pattern)


@dataclasses.dataclass(frozen=True, eq=False)
class TenantSystems:
    """One tenant's systems (DC7, O1): its current enabled records whose adapter the catalog carries, plus the
    platform-served systems. Built once (`of`) from the tenant's current records and handed to every tenant surface;
    `roster` is the roster those surfaces read. `disabled` and `adapter_missing` keep the records that are not systems
    of the tenant's run, for the surfaces that report them (R12)."""

    catalog: Catalog
    records: TenantRecords
    roster: RosterRead
    #: Enabled records whose adapter the catalog carries: the tenant's systems besides the platform-served ones.
    enabled: Mapping[str, SystemRecord]
    #: Current records the operator disabled: not in the roster.
    disabled: Mapping[str, SystemRecord]
    #: Enabled records naming an adapter the catalog does not carry (an upgrade removed it, or a custom reference):
    #: not in the roster; run start refuses the tenant naming each.
    adapter_missing: Mapping[str, SystemRecord]

    @classmethod
    def of(cls, records: TenantRecords, catalog: Catalog) -> TenantSystems:
        """The tenant's systems over `catalog` from its current `records`. A tenant not imported has only the
        platform-served systems here; refusing its run (R8) is its caller's."""
        whole = catalog.roster
        enabled: dict[str, SystemRecord] = {}
        disabled: dict[str, SystemRecord] = {}
        missing: dict[str, SystemRecord] = {}
        for system, record in sorted(records.systems.items()):
            if is_platform_served(system):
                continue  # never a record (R3); the store refuses one
            if not record.enabled:
                disabled[system] = record
            elif record.custom_ref is not None or record.adapter_id not in catalog:
                missing[system] = record
            else:
                enabled[system] = record
        files = {s: whole.adapter_files[r.adapter_id] for s, r in enabled.items()}
        verbs = {s: whole.verbs.get(r.adapter_id, frozenset()) for s, r in enabled.items()}
        verbs.update({name: whole.verbs[name] for name in PLATFORM_SERVED if name in whole.verbs})
        roster = RosterRead(
            root=whole.root,
            adapter_files=types.MappingProxyType(files),
            verbs=types.MappingProxyType(dict(sorted(verbs.items()))),
            unparsed=types.MappingProxyType({s: whole.unparsed[r.adapter_id] for s, r in enabled.items()
                                             if r.adapter_id in whole.unparsed}),
            refused=types.MappingProxyType({}),
            no_verbs=frozenset(s for s, r in enabled.items() if r.adapter_id in whole.no_verbs),
            whole=False,
        )
        return cls(catalog=catalog, records=records, roster=roster,
                   enabled=types.MappingProxyType(enabled), disabled=types.MappingProxyType(disabled),
                   adapter_missing=types.MappingProxyType(missing))

    @property
    def imported(self) -> bool:
        """Whether the tenant's systems come from records at all (R8, R11)."""
        return self.records.imported

    @property
    def systems(self) -> tuple[str, ...]:
        """Every system of the tenant, sorted: its enabled catalog-backed records and the platform-served systems."""
        return self.roster.systems


# --- the cold read ------------------------------------------------------------------------------------------------

def _cold_declarations(path: Path) -> dict[str, object]:
    """The module-level declarations of the adapter at `path`, each as its literal value, without running it. A name
    assigned a value that is not a literal (a call, an expression) or not at module level is absent."""
    try:
        tree = ast.parse(read_bytes_capped(path))
    except (OSError, SyntaxError, ValueError):
        return {}
    assigned: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            assigned[node.target.id] = node.value
    out: dict[str, object] = {}
    for name in DECLARATIONS:
        if name in assigned:
            value = _literal(assigned[name], assigned, depth=0)
            if value is not _UNREAD:
                out[name] = value
    return out


_UNREAD = object()


def _literal(node: ast.expr, assigned: Mapping[str, ast.expr], *, depth: int) -> object:
    """`node`'s value when it is a literal, a tuple of literals and splats of the shared keys template or of another
    module-level tuple, or an alias of another module-level name; else `_UNREAD`."""
    if depth > 8:
        return _UNREAD
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return _literal(assigned[node.id], assigned, depth=depth + 1) if node.id in assigned else _UNREAD
    if isinstance(node, ast.Tuple | ast.List):
        items: list[object] = []
        for element in node.elts:
            if isinstance(element, ast.Starred):
                inner = element.value
                if isinstance(inner, ast.Attribute) and inner.attr == _TEMPLATE_NAME:
                    items.extend(REQUIRED_CONFIG_KEYS_TEMPLATE)
                    continue
                value = _literal(inner, assigned, depth=depth + 1)
                if not isinstance(value, tuple):
                    return _UNREAD
                items.extend(value)
            else:
                value = _literal(element, assigned, depth=depth + 1)
                if value is _UNREAD:
                    return _UNREAD
                items.append(value)
        return tuple(items)
    return _UNREAD


def _nonblank(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _keys(value: object) -> tuple[str, ...] | None:
    if isinstance(value, tuple) and all(isinstance(v, str) for v in value):
        return value
    return None


__all__ = ["COMMENT_ROUTE", "DECLARATIONS", "Catalog", "CatalogEntry", "TenantSystems", "route_of"]
