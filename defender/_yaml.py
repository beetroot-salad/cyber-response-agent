from __future__ import annotations

from typing import Any

import yaml


def duplicate_key_paths(text: str) -> tuple[str, ...]:
    """Every mapping key that appears more than once under the same parent, as `a.b.c` paths.

    PyYAML does not report a repeated key — the LAST one wins, silently. For a document whose
    whole job is to be reviewed by a human that is a hole, not a quirk: two lines sit in the
    file, a reviewer reads both, and the loader honours one. `safe_load` cannot see it because
    the collapse happens while the node tree is being constructed, so this walks the node tree
    from `compose`, which is the last representation where both keys still exist.

    Returns paths rather than raising, so each caller decides whether a repeat is fatal (a
    permission table) or a warning (a corpus document).
    """
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        # Unparseable is not this function's verdict to give — the caller's own `safe_load`
        # raises on it with the parser's message, which says far more than "duplicates: none".
        return ()

    found: list[str] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, yaml.MappingNode):
            seen: set[str] = set()
            for key_node, value_node in node.value:
                key = getattr(key_node, "value", None)
                if not isinstance(key, str):
                    continue
                here = f"{path}.{key}" if path else key
                if key in seen:
                    found.append(here)
                seen.add(key)
                walk(value_node, here)
        elif isinstance(node, yaml.SequenceNode):
            for i, child in enumerate(node.value):
                walk(child, f"{path}[{i}]")

    walk(root, "")
    return tuple(found)


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
