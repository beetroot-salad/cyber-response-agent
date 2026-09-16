from __future__ import annotations

import contextlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from defender._io import TEXT_READ_ERRORS


def duplicate_key_paths(text: str) -> tuple[str, ...]:
    """Every mapping key that appears more than once under the same parent, as `a.b.c` paths.

    PyYAML does not report a repeated key — the LAST one wins, silently. For a document whose
    whole job is to be reviewed by a human that is a hole, not a quirk: two lines sit in the
    file, a reviewer reads both, and the loader honours one. `safe_load` cannot see it because
    the collapse happens while the node tree is being constructed, so this walks the node tree
    from `compose`, which is the last representation where both keys still exist.

    A `<<:` MERGE counts as writing its keys here, because `safe_load` expands one into the
    mapping before building it: a merged key that an explicit key shadows is a real last-wins
    collapse, and the merged half leaves no trace in the loaded document. Reporting it is the
    same rule, not an extra one — two statements in the file, one honoured.

    Returns paths rather than raising, so each caller decides whether a repeat is fatal (a
    permission table) or a warning (a corpus document).
    """
    try:
        root = compose(text)
    except (yaml.YAMLError, RecursionError):
        # Unparseable is not this function's verdict to give — the caller's own `safe_load`
        # raises on it with the parser's message, which says far more than "duplicates: none".
        # `RecursionError` for the same reason: `safe_load` below translates it into a
        # `YAMLError`, and a document too deep to compose must reach the caller as that, not as
        # an interpreter error escaping a helper that promises never to raise.
        return ()

    found: list[str] = []
    # Iterative, with an identity-keyed visited set. Recursion here has two ways to blow the
    # stack that `compose` itself survives: a deeply nested document, and an anchor that
    # contains its own alias (`a: &x {b: *x}`), which PyYAML composes into a CYCLIC node graph
    # because it registers the anchor before filling the node in. `safe_load` handles both;
    # this must too, or it turns a caller's typed refusal into a `RecursionError`.
    stack: list[tuple[Any, str]] = [(root, "")]
    seen_nodes: set[int] = set()
    # ONE constructor for the whole walk. `_resolved_key` needs a `SafeConstructor` to answer
    # what `safe_load` would build for a key, and minting a fresh one per key both allocates
    # per key and throws away the memo table PyYAML keeps on it.
    constructor = yaml.constructor.SafeConstructor()
    while stack:
        node, path = stack.pop()
        if id(node) in seen_nodes:
            continue
        seen_nodes.add(id(node))
        if isinstance(node, yaml.MappingNode):
            # `<<:` EXPANDED FIRST, for the reason the docstring gives: while a merge is still
            # a `<<` pair of its own, the keys it contributes are invisible to the scan below,
            # so an explicit key silently shadowing a merged one reads as no repeat at all.
            # `duplicate_top_level_key` below flattens for the same reason, and
            # `_artifact_schema._has_duplicate_top_level_key` delegates to it rather than
            # deciding again — the two answers to "what would `safe_load` collapse here" must
            # not diverge, so there is only one.
            # Failure is not this function's verdict to give: an unmergeable `<<` reaches the
            # caller through its own `safe_load`, with the parser's message.
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
    # DEDUPLICATED, because the contract in the docstring is a key SET — "every mapping key
    # that appears more than once" — and the loop above appends once per surplus occurrence,
    # so `a:` written three times reported `('a', 'a')` and the caller's refusal listed one
    # path twice. `dict.fromkeys` keeps first-seen order.
    return tuple(dict.fromkeys(found))


def duplicate_top_level_key(text: str) -> bool:
    """True iff `text`'s TOP-LEVEL mapping declares the same key twice.

    The same question as `duplicate_key_paths` asked of one level only, and it shares that
    function's key identity (`_resolved_key`) and its merge handling rather than re-deciding
    either: the frontmatter gate and the permission table must not end up with two answers to
    "what would `safe_load` collapse here" (defender/CLAUDE.md — one home for a helper).

    Top-level ONLY, deliberately: `_artifact_schema` reads a top-level `disposition:` and a
    nested one is "missing" there rather than a repeat, so widening this to the nested scan
    would deny a document the gate is supposed to admit.

    Returns False on any parse trouble, for `duplicate_key_paths`' reason: the caller has
    already parsed this text once, so trouble here means no reliable signal rather than a
    verdict.
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
    """A mapping key's identity AFTER tag resolution, which is the identity `safe_load` uses.

    Comparing the raw scalar text is wrong in both directions, and this function's whole job
    is the direction that loses data: `yes:` and `true:` are different text and the SAME key
    (PyYAML 1.1 booleans, and `1:`/`true:` collapse too because Python dicts hash them
    together), so a document carrying both silently keeps one row — precisely the collapse
    this module exists to report. The other direction is a false alarm: `1:` and `"1":` are
    the same text under different tags and are two real, distinct keys.

    The identity is therefore the CONSTRUCTED value and nothing else, because a Python dict is
    what `safe_load` builds and its key identity is the one that decides which row survives.
    """
    if not isinstance(key_node, yaml.ScalarNode):
        # A collection key: unhashable once constructed, and no document this is used on has
        # one. An identity that at least never collides with a scalar's.
        return (key_node.tag, id(key_node))
    try:
        value = constructor.construct_object(key_node)
        hash(value)
    except Exception:  # noqa: BLE001 — an unconstructable key falls back to its raw text
        return (key_node.tag, key_node.value)
    return value


def safe_load(text: str) -> Any:
    return _load_with(text, yaml.SafeLoader)


def safe_load_text_scalars(text: str) -> Any:
    """`safe_load`, except that every scalar is the TEXT it was written as.

    @owns the spelled reading of a document. `safe_load` is compose-then-construct, and
    construction is the one step that re-spells a scalar: a plain `2026-07-25T07:48:37.065Z`
    becomes a `datetime` whose `str()` is `2026-07-25 07:48:37.065000+00:00`, `0755` becomes
    `493`, `yes` becomes `True`, and an explicitly tagged `!!timestamp …` goes the same way.
    The oracle-golden containment checks — is this `must_not_emit` literal a whole value or
    a token of what the projection emitted — ran over a document already typed that way, so
    whether a forbidden instant was caught depended on whether the model quoted it (#951).

    Everything ELSE is `safe_load`, from the same loader with only scalar construction
    overridden: a `<<:` merge still merges, an alias still resolves, a repeated key still
    collapses to its last value, and a tag the safe loader refuses on a collection is still
    refused. That is the point of it being one reading rather than a second walk beside the
    typed one — a document has exactly one set of values here, and there is no second
    navigation to disagree with about which nodes those are. A `!!python/…` tag on a scalar
    is inert: nothing is constructed from it, and the scalar's text is what comes back.

    Mapping keys are text too (`1:` and `"1":` are one key here, two under `safe_load`), and
    a null is its spelling — `~` is `"~"`, an empty value is `""`. Only a document whose
    readers want structure and strings and never a typed value should be read this way; the
    manifests and calibration files are not (a `defective: false` must stay a boolean).
    """
    return _load_with(text, _TextScalarLoader)


class _TextScalarLoader(yaml.SafeLoader):
    """`SafeLoader` whose scalars construct to their own text. No class-level table is
    touched (the resolver table in particular — it is shared with `SafeLoader` until first
    write), so nothing here can leak into `yaml.safe_load` for the rest of the process."""

    def construct_object(self, node: Any, deep: bool = False) -> Any:
        if isinstance(node, yaml.ScalarNode):
            return node.value
        return super().construct_object(node, deep)


def _load_with(text: str, loader: type[yaml.SafeLoader]) -> Any:
    try:
        return yaml.load(text, Loader=loader)  # noqa: S506 — a SafeLoader, or a subclass of it
    except RecursionError as e:
        raise yaml.YAMLError("YAML is nested too deeply to parse") from e
    except ValueError as e:
        # A constructor rejecting a resolver-matched scalar (an out-of-range
        # implicit timestamp). `yaml.YAMLError` is not a `ValueError`, so this
        # cannot swallow PyYAML's own typed errors.
        raise yaml.YAMLError(f"YAML value could not be constructed: {e}") from e


def compose(text: str) -> Any:
    """`text`'s node tree under the safe loader — the LAST representation in which every
    mapping key is still there, which is what `duplicate_key_paths` and
    `duplicate_top_level_key` read: construction is where a repeated key collapses to its
    last value. (A reader that wants the document's SPELLING does not need the tree —
    `safe_load_text_scalars` is a full load that keeps it.)

    `SafeLoader` explicitly: `yaml.compose` defaults to the full `Loader`, and while composing
    constructs nothing, this module's whole contract with its callers is that untrusted text
    only ever meets the safe loader — a default that has to be argued about is one a later
    edit gets wrong. Raises what `yaml.compose` raises, `RecursionError` included; both
    callers here catch that themselves, because neither is the reader whose verdict a parse
    failure is.
    """
    return yaml.compose(text, Loader=yaml.SafeLoader)


def reject_unread_keys(
    where: str, mapping: Mapping[object, object], known: tuple[str, ...],
    *, error: type[Exception],
) -> None:
    """Refuse a mapping carrying a key nothing reads, as `error` naming `where` and the key.

    A key the loader ignores is a statement a reviewer WILL read and the runtime will not
    honour — the same two-statements-one-honoured defect as a duplicate key, one level up. An
    adversarial implementer of #995 hid a `residue: settled` top-level key in the shipped table
    to mute the census; a `class: rw` on a row, or a misspelled `resaon:` leaving a withholding
    unexplained while looking explained, are the same shape inside a row; a misspelled
    `correlation_tempalte:` in `lead-zero.yaml` is the same shape in a one-key file.
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
    `lead-zero.yaml`) as ONE top-level mapping carrying only `known` keys, or raise `error`.

    Everything about the FILE being trustworthy at all, in one place — absent, unreadable or
    undecodable, a repeated key (refused BEFORE the load, because the load is where the
    duplicate disappears and YAML silently honours the last), unparseable, not a mapping, a
    key nothing reads. Every refusal names `what` and `path`: the failure is read at startup by
    someone who has just edited the file. What the KEYS mean is the caller's — this returns the
    mapping and decides nothing about its values.
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
    # BEFORE any shape check the caller makes: an unread top-level key is the more actionable
    # diagnosis. A table carrying both (`residue: settled` beside an empty `dispositions:`)
    # reported only "declares no dispositions", which sends the author looking for missing
    # rows rather than at the key that does nothing.
    reject_unread_keys(where, data, known, error=error)
    return data
