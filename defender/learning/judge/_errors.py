"""The judge's refusal class, in its own module to avoid a package-`__init__` import cycle."""

from __future__ import annotations


class JudgeRefused(Exception):
    """A judge pass that cannot honestly run: a malformed archived input, a manifest failing the
    judge's load-time validation (a predating or unreadable manifest, duplicate or colliding
    labels), or a reply failing `JudgeReply` validation. An absent per-world input is not a refusal: that world is
    marked `ungradable` instead.

    A bare `Exception`, not a `ValueError`: pydantic wraps a `ValueError` raised in a `@model`
    validator into `ValidationError`, which every `except JudgeRefused` would then miss.
    """
