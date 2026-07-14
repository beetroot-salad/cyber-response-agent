"""``yaml.safe_load`` with the #609 fold, as one seam (#613).

PyYAML raises bare ``RecursionError`` — not a ``YAMLError`` — on deeply nested
input (flow or block), so one flooded LLM-authored file escapes every
``except yaml.YAMLError`` degrade path built around a raw ``safe_load``. Fold
it here into ``yaml.YAMLError`` so a caller's existing posture (dead-letter,
skip, warn, re-raise typed) covers the whole malformed class, and a future
call site gets the guard by using this instead of remembering to widen its
``except`` by hand. Fixed message: the offending YAML is multi-KB by
construction and the message lands in stderr warns and dead-letter records.
"""
from __future__ import annotations

from typing import Any

import yaml


def safe_load(text: str) -> Any:
    """Drop-in ``yaml.safe_load`` whose failures are all ``yaml.YAMLError``."""
    try:
        return yaml.safe_load(text)
    except RecursionError as e:
        raise yaml.YAMLError("YAML is nested too deeply to parse") from e
