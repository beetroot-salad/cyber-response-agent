"""O4 — a chaos profile cannot silence the alert it degrades.

Reads the real `detection-rules/*.json` at activate time and builds two sets:

  * rule-key fields — the fields any rule's threshold or query keys on. Two
    sources feed this, and missing either one reopens the exact near-miss the
    design flagged: `threshold.field` (a JSON array — this is where
    `source.ip` and several `host.name` values live, nowhere in the query
    text) *and* the parsed query/EQL string (where `process.name`,
    `event.outcome`, `falco.rule` live).
  * rule-read datasets — the dataset behind each rule's `index` pattern
    (`logs-system.auth-*` -> `system.auth`).

Both sides speak the stack's vocabulary, so every check is exact set
membership:

  * a mutation's `fields` (everything its processor reads, writes or
    removes) may not include a rule-key field or an ancestor of one —
    removing `event` removes `event.outcome`;
  * a mutation's `dataset` may not be one a rule reads. A dataset names
    exactly one pipeline, so there is no glob to widen and no parent
    pipeline to reach — a profile that tries to name one is refused as
    malformed before it gets here (chaos.mutations).

A rule whose index pattern does not pin down one dataset (`logs-*`) reads
every dataset, and every data-drop is refused while it exists.

`check_profile` applies these to a profile's parameters (cheap, before any
resolution); `check_mutations` applies the same tests to the resolved
mutations the controller is about to push. Both share one set of predicates,
so they cannot disagree.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from chaos.mutations import dataset_of_stream

# Every field name in these rules is written dotted (process.name, source.ip,
# falco.output_fields.container.name, ...); nothing else in the query/EQL
# text happens to be. A plain dotted-identifier scan is therefore precise
# enough without a real lucene/EQL/kuery parser.
_FIELD_RE = re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\b")

READS_EVERY_DATASET = "*"


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


def rule_read_datasets(rules_dir: Path) -> set[str]:
    """Every dataset any rule's `index` reads; `*` if any pattern is too
    wide to name one dataset."""
    datasets: set[str] = set()
    for rule in _load_rules(rules_dir):
        for index in rule.get("index") or []:
            datasets.add(dataset_of_stream(index) or READS_EVERY_DATASET)
    return datasets


# -- predicates ---------------------------------------------------------------


def field_reaches(target: str, fields: Iterable[str]) -> set[str]:
    """The rule-key fields a processor touching `target` would take with it:
    the field itself and every field nested under it."""
    return {f for f in fields if f == target or f.startswith(target + ".")}


def dataset_is_rule_read(dataset: str, datasets: Iterable[str]) -> bool:
    datasets = set(datasets)
    return dataset in datasets or READS_EVERY_DATASET in datasets


# -- checks -------------------------------------------------------------------


def _check_fields(fields: Iterable[str], rules_dir: Path) -> None:
    key_fields = rule_key_fields(rules_dir)
    for target in fields:
        hit = field_reaches(target, key_fields)
        if hit:
            raise GuardRefused(
                f"schema-drift touches {target!r}, which keys a detection rule via {sorted(hit)} (O4) — "
                "renaming, removing or writing it can silence or pollute that rule's alert"
            )


def _check_dataset(dataset: str, rules_dir: Path) -> None:
    if dataset_is_rule_read(dataset, rule_read_datasets(rules_dir)):
        raise GuardRefused(
            f"data-drop dataset {dataset!r} is read by a detection rule (O4) — "
            "any drop rate on it can break a sequence rule's evidence chain"
        )


def check_profile(profile: Any, *, rules_dir: Path) -> None:
    """Raise GuardRefused if `profile` would touch a rule-protected field or dataset.

    Runs on the profile's own parameters, before any resolution or any read
    of the stack. `check_mutations` repeats the same tests on what was
    actually resolved.
    """
    if profile.mode == "schema-drift":
        rename = profile.params.get("rename")
        fields = [rename["from"], rename["to"]] if rename else [profile.params.get("remove")]
        # The processor lives in the auth dataset's pipeline by design (that
        # is where the investigation-read fields are); only its fields are
        # guarded, never the pipeline itself.
        _check_fields([f for f in fields if f], rules_dir)
    elif profile.mode == "data-drop":
        dataset = profile.params.get("dataset")
        if isinstance(dataset, str):
            _check_dataset(dataset, rules_dir)
    # cmdb-stale carries no O4 exposure: no detection rule reads CMDB fields.


def check_mutations(mutations: list[dict[str, Any]], *, rules_dir: Path) -> None:
    """Raise GuardRefused if any resolved mutation would touch a rule-protected
    field or dataset. This is the check that gates the push."""
    for m in mutations:
        if m["kind"] == "schema-drift":
            _check_fields(m["fields"], rules_dir)
        elif m["kind"] == "data-drop":
            _check_dataset(m["dataset"], rules_dir)
