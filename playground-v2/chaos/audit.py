"""M7's pure half — the decision that a sampled payload leaks the harness (O6).

Two ways a fault becomes distinguishable from ordinary environmental decay:

  * a harness-shaped word sitting anywhere in a payload (a key or a value —
    a marker buried in a compound key like `defender_eval` is just as much a
    tell as one in a sentence), and
  * a document the managed ingest pipeline's `on_failure` stamped —
    `event.kind: pipeline_error` and/or a bare `error.*` field — because a
    controller processor caused it and it lands in the agent-visible index.

The scanner must also be discriminating: real inventory vocabulary
(`canary-1`, `event.outcome: failure`, an ordinary `Accepted publickey` line)
must never trip it, or every audit becomes noise. `ctl.py audit`'s live half
(sampling the documents/payloads themselves) is not exercised here — see
`chaos/tests/test_o6_audit.py` for what is.
"""
from __future__ import annotations

from typing import Any, Iterable

HARNESS_MARKERS = ("chaos", "fault", "inject", "harness", "defender", "eval")


def _walk_strings(node: Any) -> Iterable[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _walk_strings(value)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk_strings(item)


def _has_pipeline_error_kind(node: Any) -> bool:
    if isinstance(node, dict):
        if node.get("kind") == "pipeline_error":
            return True
        return any(_has_pipeline_error_kind(v) for v in node.values())
    if isinstance(node, (list, tuple)):
        return any(_has_pipeline_error_kind(v) for v in node)
    return False


def _has_error_key(node: Any) -> bool:
    if isinstance(node, dict):
        if "error" in node:
            return True
        return any(_has_error_key(v) for v in node.values())
    if isinstance(node, (list, tuple)):
        return any(_has_error_key(v) for v in node)
    return False


def audit_payloads(payloads: list[dict[str, Any]]) -> list[str]:
    """Return one finding string per payload that leaks the harness, else []."""
    findings: list[str] = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        if _has_pipeline_error_kind(payload):
            findings.append(f"event.kind=pipeline_error in agent-reachable payload: {payload!r}")
        if _has_error_key(payload):
            findings.append(f"controller-caused error field in agent-reachable payload: {payload!r}")
        for text in _walk_strings(payload):
            lowered = text.lower()
            hit = next((marker for marker in HARNESS_MARKERS if marker in lowered), None)
            if hit is not None:
                findings.append(f"harness marker {hit!r} in agent-reachable payload: {payload!r}")
                break
    return findings
