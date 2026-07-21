"""``yaml.safe_load`` with the #609 fold, as one seam (#613).

PyYAML raises bare ``RecursionError`` — not a ``YAMLError`` — on deeply nested
input (flow or block), so one flooded LLM-authored file escapes every
``except yaml.YAMLError`` degrade path built around a raw ``safe_load``. Fold
it here into ``yaml.YAMLError`` so a caller's existing posture (dead-letter,
skip, warn, re-raise typed) covers the whole malformed class, and a future
call site gets the guard by using this instead of remembering to widen its
``except`` by hand. Fixed message: the offending YAML is multi-KB by
construction and the message lands in stderr warns and dead-letter records.

``ValueError`` is the second member of that class. PyYAML's implicit
``timestamp`` resolver matches on SHAPE (``\\d{4}-\\d\\d-\\d\\d``, ``HH:MM:SS``)
and only then hands the fields to ``datetime``, so a shape-valid but
calendar-invalid scalar — ``2001-02-30:``, ``25:59:43`` — comes back out of
``construct_yaml_timestamp`` as a bare ``ValueError`` past every
``except yaml.YAMLError``. That is one LLM-authored line away from any
frontmatter reader, including ``permission.decide_write``'s report.md gate,
whose contract is to RETURN a decision and never propagate. Its message is
short and specific (unlike a flood's), so it rides along.
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
    except ValueError as e:
        # A constructor rejecting a resolver-matched scalar (an out-of-range
        # implicit timestamp). `yaml.YAMLError` is not a `ValueError`, so this
        # cannot swallow PyYAML's own typed errors.
        raise yaml.YAMLError(f"YAML value could not be constructed: {e}") from e
