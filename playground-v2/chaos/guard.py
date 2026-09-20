"""O4 — a chaos profile cannot silence the alert it degrades.

Reads the real `detection-rules/*.json` at activate time and builds two sets:

  * rule-key fields — the fields any rule's threshold or query keys on. Two
    sources feed this, and missing either one reopens the exact near-miss the
    design flagged: `threshold.field` (a JSON array — this is where
    `source.ip` and several `host.name` values live, nowhere in the query
    text) *and* the parsed query/EQL string (where `process.name`,
    `event.outcome`, `falco.rule` live).
  * rule-read streams — each rule's `index` array.

The checks reason about what a mutation would *touch*, not about the literal
string in the profile:

  * a field target covers itself and every field under it — removing `event`
    removes `event.outcome`;
  * a stream target is a glob matched against the rules' index globs in both
    directions — `logs-*` reaches `logs-system.auth-*`;
  * a drop processor's resolved pipeline is refused when it is one of the
    parent `@custom` pipelines every Fleet-managed pipeline calls, since a
    drop there runs for every stream regardless of the target glob.

`check_profile` applies these to a profile's parameters (cheap, before any
resolution); `check_mutations` applies the same tests to the resolved
mutations the controller is about to push. Both share one set of predicates,
so they cannot disagree.
"""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from typing import Any, Iterable

from chaos.mutations import pipeline_for_stream

# Every field name in these rules is written dotted (process.name, source.ip,
# falco.output_fields.container.name, ...); nothing else in the query/EQL
# text happens to be. A plain dotted-identifier scan is therefore precise
# enough without a real lucene/EQL/kuery parser.
_FIELD_RE = re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\b")

# Fleet-managed ingest pipelines call these on every document, whatever the
# dataset; a processor installed here is not scoped to any stream.
FLEET_PARENT_PIPELINES = frozenset({"global@custom", "logs@custom"})


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


# -- predicates ---------------------------------------------------------------


def field_reaches(target: str, fields: Iterable[str]) -> set[str]:
    """The rule-key fields a rename/remove of `target` would take with it:
    the field itself and every field nested under it."""
    return {f for f in fields if f == target or f.startswith(target + ".")}


def stream_reaches(target: str, streams: Iterable[str]) -> set[str]:
    """The rule-read stream globs that overlap the target glob, in either
    direction (`logs-*` covers `logs-system.auth-*`; the exact pattern
    matches itself)."""
    return {s for s in streams if fnmatch.fnmatchcase(s, target) or fnmatch.fnmatchcase(target, s)}


def pipeline_is_unscoped(pipeline: str) -> bool:
    """A `@custom` pipeline Fleet invokes for more than one dataset."""
    return pipeline in FLEET_PARENT_PIPELINES or pipeline.endswith(".integration@custom")


# -- checks -------------------------------------------------------------------


def _check_field(target: str, rules_dir: Path) -> None:
    hit = field_reaches(target, rule_key_fields(rules_dir))
    if hit:
        raise GuardRefused(
            f"schema-drift target {target!r} keys a detection rule via {sorted(hit)} (O4) — "
            "renaming or removing it can silence that rule's alert"
        )


def _check_stream(target: str, pipeline: str, rules_dir: Path) -> None:
    if pipeline_is_unscoped(pipeline):
        raise GuardRefused(
            f"data-drop target {target!r} resolves to {pipeline!r}, which Fleet runs for every "
            "dataset (O4) — a drop there is not scoped to the target stream"
        )
    hit = stream_reaches(target, rule_read_streams(rules_dir))
    if hit:
        raise GuardRefused(
            f"data-drop target stream {target!r} reaches rule-read stream(s) {sorted(hit)} (O4) — "
            "any drop rate on it can break a sequence rule's evidence chain"
        )


def check_profile(profile: Any, *, rules_dir: Path) -> None:
    """Raise GuardRefused if `profile` would touch a rule-protected field or stream.

    Runs on the profile's own parameters, before any resolution or any read
    of the stack. `check_mutations` repeats the same tests on what was
    actually resolved.
    """
    if profile.mode == "schema-drift":
        rename = profile.params.get("rename")
        target = rename["from"] if rename else profile.params.get("remove")
        if target:
            _check_field(target, rules_dir)
    elif profile.mode == "data-drop":
        target = profile.params.get("target_stream")
        if target:
            _check_stream(target, pipeline_for_stream(target), rules_dir)
    # cmdb-stale carries no O4 exposure: no detection rule reads CMDB fields.


def check_mutations(mutations: list[dict[str, Any]], *, rules_dir: Path) -> None:
    """Raise GuardRefused if any resolved mutation would touch a rule-protected
    field, stream or pipeline. This is the check that gates the push."""
    for m in mutations:
        if m["kind"] == "schema-drift":
            processor = m["processor"]
            body = processor.get("rename") or processor.get("remove") or {}
            _check_field(body["field"], rules_dir)
            if pipeline_is_unscoped(m["pipeline"]):
                raise GuardRefused(f"schema-drift pipeline {m['pipeline']!r} is not scoped to one dataset")
        elif m["kind"] == "data-drop":
            _check_stream(m["target_stream"], m["pipeline"], rules_dir)
