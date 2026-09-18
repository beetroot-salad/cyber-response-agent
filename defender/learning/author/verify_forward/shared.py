#!/usr/bin/env python3
from __future__ import annotations


class VerdictError(RuntimeError):
    """The verifier replied, but its text carries no single readable verdict.

    Replaces `parse_verdict`'s old `SystemExit` (a `BaseException`, which the drain's
    per-pair handler could never catch): no VERDICT line at all, an unrecognized token, or
    more than one distinct VERDICT line (§7 FK-11). A call that never COMPLETES — a
    timeout, a transport error — is a different exception class entirely and is never this
    one (§7 FK-9)."""


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
    """The model's prose, with its trailing VERDICT line(s) stripped — the second half of
    `ForwardCheck.run`'s `(verdict, reasoning)` pair, kept alongside the verdict rather than
    discarded (the loss this delta exists to stop, C2)."""
    kept = [
        line for line in text.strip().splitlines()
        if not line.strip().strip("*`# ").strip().upper().startswith("VERDICT:")
    ]
    return "\n".join(kept).strip()

