#!/usr/bin/env python3
from __future__ import annotations


class VerdictError(RuntimeError):
    """The verifier replied, but its text carries no single readable verdict: no VERDICT
    line, an unrecognized token, or conflicting VERDICT lines.

    An ordinary `Exception` so the drain's per-pair handler can catch it. A call that never
    completes (timeout, transport error) raises a different class."""


def _verdict_lines(text: str) -> list[str]:
    lines: list[str] = []
    for line in text.strip().splitlines():
        s = line.strip().strip("*`# ").strip()
        if s.upper().startswith("VERDICT:"):
            lines.append(s.split(":", 1)[1].strip().strip("*`. ").upper())
    return lines


def parse_verdict(text: str, *, error_prefix: str) -> str:
    lines = _verdict_lines(text)
    if not lines:
        raise VerdictError(
            f"{error_prefix}: no VERDICT line found in verifier output:\n" + text[-1000:]
        )
    distinct = sorted(set(lines))
    if len(distinct) > 1:
        raise VerdictError(f"{error_prefix}: conflicting VERDICT lines found: {distinct}")
    verdict = lines[-1]
    if verdict not in ("GOOD", "BAD"):
        raise VerdictError(f"{error_prefix}: unrecognized verdict {verdict!r}")
    return verdict


def reasoning_text(text: str) -> str:
    """The model's prose with its VERDICT line(s) stripped — the reasoning half of
    `ForwardCheck.run`'s `(verdict, reasoning)` pair."""
    kept = [
        line for line in text.strip().splitlines()
        if not line.strip().strip("*`# ").strip().upper().startswith("VERDICT:")
    ]
    return "\n".join(kept).strip()

