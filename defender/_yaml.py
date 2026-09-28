from __future__ import annotations

import contextlib
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, NamedTuple

import yaml

from defender._io import TEXT_READ_ERRORS


def duplicate_key_paths(text: str) -> tuple[str, ...]:
    """Every mapping key that appears more than once under the same parent, as `a.b.c` paths.

    PyYAML silently keeps the last of a repeated key, so a reviewer reads two lines and the
    loader honours one. The collapse happens at construction, so this walks the `compose` node
    tree. A `<<:` merge counts as writing its keys, since an explicit key shadowing a merged one
    is the same last-wins collapse.

    Returns paths rather than raising, so each caller decides whether a repeat is fatal.
    """
    try:
        root = compose(text)
    except (yaml.YAMLError, RecursionError):
        # Not this function's verdict: the caller's own `safe_load` reports it properly.
        return ()

    found: list[str] = []
    # Iterative with an identity-keyed visited set: documents can be deeply nested, and a
    # self-referencing anchor (`a: &x {b: *x}`) composes into a cyclic node graph.
    stack: list[tuple[Any, str]] = [(root, "")]
    seen_nodes: set[int] = set()
    # One constructor for the whole walk, keeping PyYAML's memo table across keys.
    constructor = yaml.constructor.SafeConstructor()
    while stack:
        node, path = stack.pop()
        if id(node) in seen_nodes:
            continue
        seen_nodes.add(id(node))
        if isinstance(node, yaml.MappingNode):
            # Expand `<<:` first so merged keys are visible to the scan. An unmergeable `<<`
            # is left for the caller's own `safe_load` to report.
            with contextlib.suppress(yaml.YAMLError, RecursionError):
                constructor.flatten_mapping(node)
            keys: set[Any] = set()
            for key_node, value_node in node.value:
                label = key_node.value if isinstance(key_node, yaml.ScalarNode) else "?"
                here = f"{path}.{label}" if path else str(label)
                key = _resolved_key(key_node, constructor)
                if key in keys:
                    found.append(here)
                keys.add(key)
                stack.append((value_node, here))
        elif isinstance(node, yaml.SequenceNode):
            for i, child in enumerate(node.value):
                stack.append((child, f"{path}[{i}]"))
    # The loop appends once per surplus occurrence; report each path once, in first-seen order.
    return tuple(dict.fromkeys(found))


def duplicate_top_level_key(text: str) -> bool:
    """True iff `text`'s TOP-LEVEL mapping declares the same key twice.

    Shares `duplicate_key_paths`' key identity and merge handling so the frontmatter gate and
    the permission table agree on what `safe_load` would collapse. Top-level only: a nested
    repeat is not a repeat of `_artifact_schema`'s top-level `disposition:`. Returns False on
    parse trouble, which the caller's own parse reports.
    """
    try:
        root = compose(text)
    except (yaml.YAMLError, RecursionError):
        return False
    if not isinstance(root, yaml.MappingNode):
        return False
    constructor = yaml.constructor.SafeConstructor()
    with contextlib.suppress(yaml.YAMLError, RecursionError):
        constructor.flatten_mapping(root)  # `<<:` merges become real top-level pairs
    seen: set[Any] = set()
    for key_node, _value_node in root.value:
        key = _resolved_key(key_node, constructor)
        if key in seen:
            return True
        seen.add(key)
    return False


def _resolved_key(key_node: Any, constructor: Any) -> Any:
    """A mapping key's identity after tag resolution — the constructed value, as `safe_load`
    uses. Raw text is wrong both ways: `yes:` and `true:` (and `1:`/`true:`, which hash
    together) are one key, while `1:` and `"1":` are two.
    """
    if not isinstance(key_node, yaml.ScalarNode):
        # A collection key is unhashable once constructed; use an identity no scalar shares.
        return (key_node.tag, id(key_node))
    try:
        value = constructor.construct_object(key_node)
        hash(value)
    except Exception:  # noqa: BLE001 — an unconstructable key falls back to its raw text
        return (key_node.tag, key_node.value)
    return value


def safe_load(text: str) -> Any:
    with _construction_errors_as_yaml_errors():
        return yaml.safe_load(text)


class AliasRefused(yaml.YAMLError):
    """A document that must be a tree reused a node by alias."""


class _TreeLoader(yaml.SafeLoader):
    def compose_node(self, parent: Any, index: Any) -> Any:
        # Refused as the alias is met, before anything is expanded: an alias graph of a few
        # hundred bytes can stand for billions of values, and an alias can close a cycle.
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise AliasRefused(
                f"line {event.start_mark.line + 1}: the document reuses a node by alias "
                f"(*{event.anchor}); write the value out in full")
        return super().compose_node(parent, index)


def safe_load_tree(text: str) -> Any:
    """`safe_load` for a model-authored document, which must be a tree: any alias (including a
    `<<` merge) is `AliasRefused`, a `YAMLError`. Everything that walks the result can then
    assume no shared or cyclic values."""
    with _construction_errors_as_yaml_errors():
        return yaml.load(text, Loader=_TreeLoader)  # noqa: S506 — a SafeLoader subclass


class Readings(NamedTuple):
    """One document, read twice from one node tree (`safe_load_typed_and_spelled`)."""

    typed: Any    #: what `safe_load` gives
    spelled: Any  #: the same shape exactly; every VALUE scalar the text it was written as


def safe_load_typed_and_spelled(text: str) -> Readings:
    """`safe_load`'s document and its spelling, constructed from one composed tree.

    @owns spelled — the text reading of a YAML document, produced here and nowhere else.
    Construction re-spells scalars (`2026-07-25T07:48:37.065Z` becomes a `datetime`, `0755`
    becomes `493`, `yes` becomes `True`), so text-containment checks must scan the spelling or
    their result depends on whether the model quoted a value.

    `spelled` has the same shape as `typed` (containers, keys, aliases, cycles) and differs
    only where a scalar is a value (a mapping's value or a sequence's item): there it is the
    source text, with nulls as their spelling (`~` is `"~"`, empty is `""`). Keys stay typed,
    since text keys would merge `1:` with `'1':`; a bare scalar document stays typed too. One
    tree guarantees the checked values are the values of the structure shown, and building
    the typed half first means whatever `safe_load` refuses is refused here.

    Edges: `!!omap`/`!!pairs`/`!!set` members stay typed, and a scalar aliased from a mapping
    key is constructed once, as the key.
    """
    with _construction_errors_as_yaml_errors():
        # This module's `compose`, which pins the safe loader.
        root = compose(text)
        if root is None:
            return Readings(None, None)
        return Readings(
            yaml.constructor.SafeConstructor().construct_document(root),
            _SpelledValuesConstructor().construct_document(root),
        )


class _SpelledValuesConstructor(yaml.constructor.SafeConstructor):
    """`SafeConstructor` whose value scalars construct to their own text.

    Mapping values and sequence items are noted as they pass; unnoted scalars (keys, the root)
    are typed as usual. Only methods are overridden — no class-level tables, which are shared
    with `yaml.safe_load` — so nothing leaks into other loads.
    """

    def __init__(self) -> None:
        super().__init__()
        self._value_nodes: set[int] = set()

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        self.flatten_mapping(node)
        self._value_nodes.update(id(value) for _, value in node.value)
        return super().construct_mapping(node, deep)

    def construct_sequence(self, node: Any, deep: bool = False) -> Any:
        self._value_nodes.update(id(item) for item in node.value)
        return super().construct_sequence(node, deep)

    def construct_object(self, node: Any, deep: bool = False) -> Any:
        if isinstance(node, yaml.ScalarNode) and id(node) in self._value_nodes:
            return node.value
        return super().construct_object(node, deep)


@contextlib.contextmanager
def _construction_errors_as_yaml_errors() -> Iterator[None]:
    """The two non-`YAMLError`s a load can raise, translated so a caller that catches
    `YAMLError` for malformed input never gets an interpreter error instead."""
    try:
        yield
    except RecursionError as e:
        raise yaml.YAMLError("YAML is nested too deeply to parse") from e
    except ValueError as e:
        # A constructor rejecting a resolver-matched scalar (an out-of-range
        # implicit timestamp). `yaml.YAMLError` is not a `ValueError`, so this
        # cannot swallow PyYAML's own typed errors.
        raise yaml.YAMLError(f"YAML value could not be constructed: {e}") from e


def compose(text: str) -> Any:
    """`text`'s node tree under the safe loader — the last representation where repeated keys
    still exist.

    `SafeLoader` explicitly (`yaml.compose` defaults to the full `Loader`): untrusted text only
    ever meets the safe loader. Raises what `yaml.compose` raises, `RecursionError` included.
    """
    return yaml.compose(text, Loader=yaml.SafeLoader)


def reject_unread_keys(
    where: str, mapping: Mapping[object, object], known: tuple[str, ...],
    *, error: type[Exception],
) -> None:
    """Refuse a mapping carrying a key nothing reads, as `error` naming `where` and the key.

    An ignored key is a statement a reviewer reads and the runtime does not honour — e.g. a
    planted `residue: settled` muting a census, or a misspelled `resaon:` that looks explained.
    """
    unknown = sorted(str(k) for k in mapping if k not in known)
    if unknown:
        raise error(
            f"{where} carries key(s) {unknown} that nothing reads — the key(s) read here are "
            f"{list(known)}"
        )


def load_reviewed_mapping(
    path: Path, *, what: str, known: tuple[str, ...], error: type[Exception],
) -> Mapping[object, object]:
    """Read a hand-authored, reviewed per-deployment file (`verb-grants.yaml`,
    `lead-zero.yaml`) as one top-level mapping carrying only `known` keys, or raise `error`.

    Refuses absent, unreadable, repeated keys (checked before the load, which would hide them),
    unparseable, non-mapping, and unread keys, naming `what` and `path`. Values are the
    caller's to interpret.
    """
    where = f"{what} at {path}"
    if not path.is_file():
        raise error(f"{what} not found at {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except TEXT_READ_ERRORS as e:
        raise error(f"{where} is unreadable ({e})") from e

    duplicates = duplicate_key_paths(text)
    if duplicates:
        raise error(
            f"{where} repeats key(s) {list(duplicates)} — YAML would silently honour the last "
            "of each; write each key once"
        )
    try:
        data = safe_load(text)
    except yaml.YAMLError as e:
        raise error(f"{where} does not parse ({e})") from e

    if not isinstance(data, Mapping):
        raise error(f"{where} must be a mapping carrying the key(s) {list(known)}")
    # Before the caller's shape checks: an unread key is the more actionable diagnosis.
    reject_unread_keys(where, data, known, error=error)
    return data
