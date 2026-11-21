"""The catalog of adapters (#1366 DC7): every `*_adapter.py` under the checkout's `integrations/`, with the declarations
each makes as module constants (`DISPLAY_NAME`, `EXAMPLE`, `PREFIX`, `REQUIRED_CONFIG_KEYS`, `PATH_KEYS`,
`SAMPLE_SETTINGS`, `BASE_FILES`, read cold, K2) and its `comment_route` (read by loading the module, C1). The surfaces with no tenant
read it: the product CI census lint, the invlang ceiling gate, connect, `check --folder`, the API's catalog read and the
record judgement. A tenant's systems (`systems.catalog.TenantSystems`) are drawn from it.

An adapter module is loaded at most once per catalog: the module, or the exception its import raised, is kept and
answered again on each ask, never retried (#1470 D8). `load_all` loads every entry and module up front, so a caller that
judges under a lock (the API, built once at start) reads no file afterwards."""
from __future__ import annotations

import ast
import dataclasses
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from defender._io import read_bytes_capped
from defender._paths import adapters_under, process_defender_dir
from defender.kit.transport import REQUIRED_CONFIG_KEYS_TEMPLATE
from defender.kit.verbs import COMMENT_ACTION
from defender.system_rules.registry import RosterRead, fresh_adapter_module, read_roster

#: The module constants every catalog adapter declares, read cold (K2).
DECLARATIONS = ("PREFIX", "REQUIRED_CONFIG_KEYS", "PATH_KEYS", "DISPLAY_NAME", "EXAMPLE", "SAMPLE_SETTINGS", "BASE_FILES")
#: The adapter function that declares the comment route (C1).
COMMENT_ROUTE = "comment_route"
#: The shared keys template an adapter's keys may splat (`*transport.REQUIRED_CONFIG_KEYS_TEMPLATE`).
_TEMPLATE_NAME = "REQUIRED_CONFIG_KEYS_TEMPLATE"


@dataclasses.dataclass(frozen=True)
class CatalogEntry:
    """One catalog adapter as its module declares it, read without running it. A declaration the module lacks, or does
    not spell as a literal, is None (`PATH_KEYS` defaults to none); `unparsed` is the roster's reason when its source
    could not be read. `sample_settings` is its `SAMPLE_SETTINGS` (stored key -> an example value, #1470 D11).
    `base_files` is the folder of its `BASE_FILES` (a literal path relative to `integrations/`, #1471 P-8), None when it
    declares none, or one that is not a path below `integrations/`; `system_rules.base_files` renders it."""

    adapter_id: str
    path: Path
    display_name: str | None
    example: bool
    prefix: str | None
    required_keys: tuple[str, ...] | None
    path_keys: tuple[str, ...]
    tools: frozenset[str]
    unparsed: str | None = None
    sample_settings: Mapping[str, str] | None = None
    base_files: Path | None = None

    @property
    def stored_keys(self) -> tuple[str, ...]:
        """The settings keys a record of this adapter holds: each required key with the prefix, as stored."""
        if self.prefix is None or self.required_keys is None:
            return ()
        return tuple(f"{self.prefix}_{key}" for key in self.required_keys)


@dataclasses.dataclass(frozen=True)
class _Failed:
    """An adapter module whose import raised: the exception, raised again on each ask (D8)."""

    error: BaseException


class Catalog:
    """The whole checkout's adapters (DC7), over one roster read of `integrations/`. Entries are read cold and held;
    each module is loaded once, its failure kept as data (D8), for this catalog's life."""

    def __init__(self, roster: RosterRead) -> None:
        self._roster = roster
        self._entries: dict[str, CatalogEntry] = {}
        self._modules: dict[str, Any] = {}
        self._lock = threading.RLock()

    @classmethod
    def of_checkout(cls, defender_dir: Path | None = None) -> Catalog:
        """The catalog of the checkout at `defender_dir` (the running process's tree when None). Raises the roster's
        `RegistryError` when the adapters directory cannot be read."""
        return cls(read_roster(adapters_under(Path(defender_dir) if defender_dir else process_defender_dir())))

    def load_all(self) -> Catalog:
        """Read every entry and load every adapter module now (a failed load is kept, not raised): the catalog whole, so
        no later ask reads a file. This catalog."""
        for adapter in self.adapter_ids:
            self.entry(adapter)
            self._load(adapter)
        return self

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
                unparsed=unparsed, sample_settings=_text_map(values.get("SAMPLE_SETTINGS")),
                base_files=_folder_below(path.parent, values.get("BASE_FILES")))
            self._entries[adapter_id] = made
            return made

    def entries(self) -> tuple[CatalogEntry, ...]:
        """Every adapter's entry, by id."""
        return tuple(self.entry(a) for a in self.adapter_ids)

    def _load(self, adapter_id: str) -> Any:
        """The module, or `_Failed` holding its import's exception; loaded at most once."""
        if adapter_id not in self._roster.adapter_files:
            raise KeyError(adapter_id)
        with self._lock:
            if adapter_id not in self._modules:
                try:
                    self._modules[adapter_id] = fresh_adapter_module(self._roster, adapter_id)
                except Exception as e:  # noqa: BLE001 — kept as data and raised again on each ask (D8)
                    self._modules[adapter_id] = _Failed(e)
            return self._modules[adapter_id]

    def module(self, adapter_id: str) -> Any:
        """`adapter_id`'s module, loaded from the checkout once per catalog; `KeyError` for an adapter the catalog
        lacks. An import that failed raises that same exception on this and every later ask (D8)."""
        loaded = self._load(adapter_id)
        if isinstance(loaded, _Failed):
            raise loaded.error
        return loaded

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
    module-level tuple, a dict of literals, or an alias of another module-level name; else `_UNREAD`."""
    if depth > 8:
        return _UNREAD
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return _literal(assigned[node.id], assigned, depth=depth + 1) if node.id in assigned else _UNREAD
    if isinstance(node, ast.Dict):
        return _dict_literal(node)
    if isinstance(node, ast.Tuple | ast.List):
        return _tuple_literal(node, assigned, depth=depth)
    return _UNREAD


def _dict_literal(node: ast.Dict) -> object:
    """A dict whose keys and values are all constants, else `_UNREAD`."""
    pairs: dict[object, object] = {}
    for key, value in zip(node.keys, node.values, strict=True):
        if not (isinstance(key, ast.Constant) and isinstance(value, ast.Constant)):
            return _UNREAD
        pairs[key.value] = value.value
    return pairs


def _tuple_literal(node: ast.Tuple | ast.List, assigned: Mapping[str, ast.expr], *, depth: int) -> object:
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


def _nonblank(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _folder_below(integrations: Path, value: object) -> Path | None:
    """`value`, a relative path literal, as a folder below `integrations`; None for anything else (absent, not text,
    absolute, or climbing out)."""
    text = _nonblank(value)
    if text is None or Path(text).is_absolute() or ".." in Path(text).parts:
        return None
    return integrations / text


def _keys(value: object) -> tuple[str, ...] | None:
    if isinstance(value, tuple) and all(isinstance(v, str) for v in value):
        return value
    return None


def _text_map(value: object) -> Mapping[str, str] | None:
    if isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        return dict(value)
    return None


__all__ = ["COMMENT_ROUTE", "DECLARATIONS", "Catalog", "CatalogEntry", "route_of"]
