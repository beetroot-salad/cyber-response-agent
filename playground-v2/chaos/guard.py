"""O4 — a chaos profile cannot silence the alert it degrades.

Reads the real `detection-rules/*.json` at activate time and builds two sets:

  * rule-key fields — the fields any rule's threshold or query keys on. Two
    sources feed this, and missing either one reopens the exact near-miss the
    design flagged: `threshold.field` (a JSON array — this is where
    `source.ip` and several `host.name` values live, nowhere in the query
    text) *and* the parsed query/EQL string (where `process.name`,
    `event.outcome`, `falco.rule` live).
  * rule-read streams — each rule's `index` array.

`check_profile` refuses a schema-drift profile whose target field is in the
first set, and a data-drop profile whose target stream is in the second.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Every field name in these rules is written dotted (process.name, source.ip,
# falco.output_fields.container.name, ...); nothing else in the query/EQL
# text happens to be. A plain dotted-identifier scan is therefore precise
# enough without a real lucene/EQL/kuery parser.
_FIELD_RE = re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\b")


class GuardRefused(Exception):
    """Raised when a profile would silence, or risk silencing, a detection rule."""


def _load_rules(rules_dir: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text()) for p in sorted(Path(rules_dir).glob("*.json"))]


def rule_key_fields(rules_dir: Path) -> set[str]:
    """Every field any rule's threshold or query/EQL text keys on."""
    fields: set[str] = set()
    for rule in _load_rules(rules_dir):
        threshold = rule.get("threshold") or {}
        for field in threshold.get("field") or []:
            fields.add(field)
        fields.update(_FIELD_RE.findall(rule.get("query") or ""))
    return fields


def rule_read_streams(rules_dir: Path) -> set[str]:
    """Every data stream any rule's `index` reads."""
    streams: set[str] = set()
    for rule in _load_rules(rules_dir):
        for index in rule.get("index") or []:
            streams.add(index)
    return streams


def check_profile(profile: Any, *, rules_dir: Path) -> None:
    """Raise GuardRefused if `profile` would touch a rule-protected field or stream.

    Must run before any mutation reaches the stack — a refused profile is a
    precondition failure, not a report written after the fact.
    """
    if profile.mode == "schema-drift":
        rename = profile.params.get("rename")
        target = rename["from"] if rename else profile.params.get("remove")
        if target in rule_key_fields(rules_dir):
            raise GuardRefused(
                f"schema-drift target {target!r} keys a detection rule (O4) — "
                "renaming or removing it can silence that rule's alert"
            )
    elif profile.mode == "data-drop":
        target = profile.params.get("target_stream")
        if target in rule_read_streams(rules_dir):
            raise GuardRefused(
                f"data-drop target stream {target!r} is read by a detection rule (O4) — "
                "any drop rate on it can break a sequence rule's evidence chain"
            )
    # cmdb-stale carries no O4 exposure: no detection rule reads CMDB fields.
