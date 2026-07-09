"""Small prompt-assembly helpers shared across the pipeline stages.

``_section`` wraps a labeled body in an XML-ish tag block; the actor/judge stage
drivers compose their user prompts out of these blocks so the stages don't drift on
tag shape. (``verify_forward/shared.py::data_section`` is its sibling on the
author-side forward-check.)
"""
from __future__ import annotations


def _section(tag: str, body: str, comment: str | None = None) -> str:
    inner = f"<!-- {comment} -->\n" if comment else ""
    return f"<{tag}>\n{inner}{body.rstrip()}\n</{tag}>\n"
