"""M7's pure half — deciding that an agent-reachable payload leaks the harness (O6).

The ledger knows exactly what the controller wrote, so the audit checks for
*that*, not for words:

  * a controller processor body appearing verbatim in a payload (the agent
    got at pipeline definitions), and
  * a document the managed ingest pipeline's `on_failure` stamped —
    `event.kind: pipeline_error` / `error.message` — whose message names a
    field a controller processor touches. The system integration's own grok
    failures stamp the same shape on malformed lines and are not ours.

Those are `findings`; they gate the exit code. The harness-marker word scan
(`scan_markers`) is kept as an *advisory*: useful for a human reading the
report, but a token like `fault` or `eval` is ordinary syslog vocabulary
(`general protection fault`, `/usr/bin/eval`), so it cannot decide a pass.
`ctl.py audit`'s live half (sampling the payloads themselves, and the
positive control) is not exercised here — see `chaos/tests/test_o6_audit.py`
for what is.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

HARNESS_MARKERS = frozenset({"chaos", "fault", "injected", "harness", "defender", "eval"})
# Underscore-separated compound keys (defender_eval) are the whole reason this
# isn't a plain substring/`\b` check: `\b` treats `_` as a word character, so
# it would never fire inside "defender_eval". Splitting into letter-only
# tokens and requiring an EXACT match against a marker is what lets a
# compound key still count while "default" (contains "fault") and
# "evaluate"/"failure" (contain "eval"/no relation to "fault") do not.
_TOKEN_RE = re.compile(r"[a-z]+")


def _tokens(text: str) -> Iterable[str]:
    return _TOKEN_RE.findall(text.lower())


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


def _walk_dicts(node: Any) -> Iterable[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk_dicts(item)


def _get_path(doc: dict[str, Any], path: str) -> Any:
    """`event.kind` from either a nested `{"event": {"kind": ..}}` or a
    flattened `{"event.kind": ..}` document."""
    if path in doc:
        return doc[path]
    node: Any = doc
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def controller_footprint(records: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], set[str]]:
    """(processor bodies, fields touched) across the given ledger records."""
    processors: list[dict[str, Any]] = []
    fields: set[str] = set()
    for record in records:
        for m in record.get("resolved_mutations") or []:
            if "processor" in m:
                processors.append(m["processor"])
            fields.update(m.get("fields") or [])
    return processors, fields


def audit_payloads(payloads: list[dict[str, Any]], *, records: Iterable[dict[str, Any]]) -> list[str]:
    """One finding per payload that carries something the controller wrote."""
    processors, fields = controller_footprint(records)
    findings: list[str] = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        if processors and any(d in processors for d in _walk_dicts(payload)):
            findings.append(f"controller processor body in agent-reachable payload: {payload!r}")
            continue
        message = _get_path(payload, "error.message")
        kind = _get_path(payload, "event.kind")
        if fields and (kind == "pipeline_error" or message is not None):
            text = str(message or "")
            named = sorted(f for f in fields if f in text)
            if named:
                findings.append(
                    f"ingest error naming controller field(s) {named} in agent-reachable payload: {payload!r}"
                )
    return findings


def scan_markers(payloads: list[dict[str, Any]]) -> list[str]:
    """Advisory: one line per payload carrying a harness-shaped token."""
    advisories: list[str] = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        for text in _walk_strings(payload):
            hit = next((tok for tok in _tokens(text) if tok in HARNESS_MARKERS), None)
            if hit is not None:
                advisories.append(f"harness-shaped token {hit!r} in agent-reachable payload: {payload!r}")
                break
    return advisories
