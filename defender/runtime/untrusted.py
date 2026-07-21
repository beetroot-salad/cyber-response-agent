
from __future__ import annotations


def wrap(content: str, tag: str, salt: str) -> str:
    return f"<run-{salt}-{tag}>\n{content}\n</run-{salt}-{tag}>"
