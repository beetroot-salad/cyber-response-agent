from __future__ import annotations

import contextlib
from typing import Any

import yaml


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
        # `SafeLoader` explicitly: `compose` defaults to the full `Loader`, and while composing
        # constructs nothing, this module's whole contract with its callers is that untrusted
        # text only ever meets the safe loader — a default that has to be argued about is one
        # a later edit gets wrong.
        root = yaml.compose(text, Loader=yaml.SafeLoader)
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
        root = yaml.compose(text, Loader=yaml.SafeLoader)
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
    try:
        return yaml.safe_load(text)
    except RecursionError as e:
        raise yaml.YAMLError("YAML is nested too deeply to parse") from e
    except ValueError as e:
        # A constructor rejecting a resolver-matched scalar (an out-of-range
        # implicit timestamp). `yaml.YAMLError` is not a `ValueError`, so this
        # cannot swallow PyYAML's own typed errors.
        raise yaml.YAMLError(f"YAML value could not be constructed: {e}") from e
