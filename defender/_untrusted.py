from __future__ import annotations


def wrap(content: str, tag: str, salt: str) -> str:
    """Place untrusted text inside one invocation-scoped prompt frame."""
    for name, value in (("content", content), ("tag", tag), ("salt", salt)):
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
    if not tag:
        raise ValueError("tag must not be empty")
    if not salt:
        raise ValueError("salt must not be empty")
    return f"<run-{salt}-{tag}>\n{content}\n</run-{salt}-{tag}>"
