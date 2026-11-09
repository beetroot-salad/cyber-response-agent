"""A chaos profile cannot silence the alert it degrades.

Reads the real `detection-rules/*.json` at activate time and builds two sets:

  * rule-key fields — from both `threshold.field` (where `source.ip` and some
    `host.name` keys live) and the parsed query/EQL text; either alone misses some.
  * rule-read datasets — the dataset behind each rule's `index` pattern
    (`logs-system.auth-*` -> `system.auth`), or behind each source an ES|QL
    rule's query reads, taken from the product's one reader
    (`defender.integrations.esql_text.sources`).

A mutation's `fields` may not include a rule-key field or an ancestor of one
(removing `event` removes `event.outcome`), and its `dataset` may not be one a
rule reads. A rule whose index pattern is too wide to name one dataset
(`logs-*`) blocks every data-drop. So does an ES|QL rule whose sources are
empty or unreadable: the guard fails closed and reads `*` for it.

`check_profile` runs on a profile's parameters (cheap, before resolution);
`check_mutations` runs the same predicates on the resolved mutations.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

# The ES|QL source reader is the product's; the repo root has to be importable (run as a script,
# only this directory and playground-v2/ are).
_REPO_ROOT = str(Path(__file__).resolve().parents[2])
if _REPO_ROOT not in sys.path:
    sys.path.append(_REPO_ROOT)

from chaos.mutations import dataset_of_stream  # noqa: E402
from defender.integrations.esql_text import sources as esql_sources  # noqa: E402

# Field names in these rules are dotted and nothing else in the query text is,
# so a dotted-identifier scan suffices without a real query parser.
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


def _is_esql(rule: dict[str, Any]) -> bool:
    return "esql" in (rule.get("type"), rule.get("language"))


def _rule_indices(rule: dict[str, Any]) -> list[str]:
    """What a rule reads: its `index` patterns, and for an ES|QL rule the sources of its query.
    Sources that are empty (`ROW`) or unreadable (`None`) read everything."""
    indices = list(rule.get("index") or [])
    if _is_esql(rule):
        found = esql_sources(rule.get("query") or "")
        indices += found if found else [READS_EVERY_DATASET]
    return indices


def rule_read_datasets(rules_dir: Path) -> set[str]:
    """Every dataset any rule reads; `*` if any pattern is too wide to name one dataset."""
    return {dataset_of_stream(index) or READS_EVERY_DATASET
            for rule in _load_rules(rules_dir) for index in _rule_indices(rule)}


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
        # Only the processor's fields are guarded; its pipeline (auth) is
        # rule-read by design.
        _check_fields([f for f in fields if f], rules_dir)
    elif profile.mode == "data-drop":
        dataset = profile.params.get("dataset")
        if isinstance(dataset, str):
            _check_dataset(dataset, rules_dir)
    # cmdb-stale is safe: no detection rule reads CMDB fields.



def check_mutations(mutations: list[dict[str, Any]], *, rules_dir: Path) -> None:
    """Raise GuardRefused if any resolved mutation would touch a rule-protected
    field or dataset. This is the check that gates the push."""
    for m in mutations:
        if m["kind"] == "schema-drift":
            _check_fields(m["fields"], rules_dir)
        elif m["kind"] == "data-drop":
            _check_dataset(m["dataset"], rules_dir)
