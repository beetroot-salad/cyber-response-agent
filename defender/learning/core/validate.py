from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from defender._yaml import safe_load
from defender._report import ReportRead, read_report
from defender._text import is_content_less, strip_zero_width
from defender.learning.core.config import (
    ACTOR_OBSERVATION_TYPES,
    ALL_FINDING_TYPES,
    BENIGN_ALL_FINDING_TYPES,
    BENIGN_OUTCOME_ENUM,
    RunUnprocessable,
    OUTCOME_ENUM,
)




def normalize_disposition(report_path: Path) -> str:
    """The run's disposition, or `RunUnprocessable`.

    What the value MEANS is `_report.read_report`'s single decision. What stays here is the
    loop's REACTION: a case whose headline it cannot read is refused with a typed error the
    drain can dead-letter, never guessed at. The head-of-file dump accompanies every refusal —
    it is the operator's only view of what the model actually wrote.
    """
    read = read_report(report_path)
    if read.disposition is None:
        raise RunUnprocessable(_unprocessable_reason(read, report_path))
    return read.disposition


def _unprocessable_reason(read: ReportRead, report_path: Path) -> str:
    if not read.text:
        return str(read.reason)
    head = "\n".join(read.text.splitlines()[:30])
    return f"{read.reason}\n--- {report_path} (head) ---\n{head}"




def strip_yaml_fence(text: str) -> str:
    s = text.strip()
    m = re.search(r"</[a-zA-Z_][\w-]*?think[a-zA-Z_]*>\s*\n", s) or re.search(
        r"</think(?:ing)?>\s*\n", s
    )
    if m:
        s = s[m.end():].strip()
    m = re.match(r"\A```(?:yaml|yml)?\s*\n(.*?)\n```\s*\Z", s, re.DOTALL)
    if m:
        s = m.group(1).strip()
    m = re.search(r"^```(?:yaml|yml)?\s*\n(.*?)\n```", s, re.DOTALL | re.MULTILINE)
    if m and not s.startswith("```"):
        s = m.group(1).strip()
    m = re.match(r"\A<([a-zA-Z_][\w-]*)\s*>\s*\n(.*?)\n\s*</\1>\s*\Z", s, re.DOTALL)
    if m:
        s = m.group(2).strip()
    s = re.sub(r"\n\s*</[a-zA-Z_][\w-]*>\s*\Z", "", s)
    s = re.sub(r"\n\s*```\s*\Z", "", s)
    return s


def strip_yaml_preamble(text: str) -> str:
    lines = text.split("\n")
    for i in range(len(lines)):
        candidate = text if i == 0 else "\n".join(lines[i:])
        try:
            doc = safe_load(candidate)
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict):
            if not i:
                return text
            suffix = lines[i:]
            while suffix and not suffix[0].strip():
                del suffix[0]
            return "\n".join(suffix)
    return text


def normalize_judge_yaml(text: str) -> str:
    return strip_yaml_preamble(strip_yaml_fence(text))




def _outcome_keyword_in(outcome_value: Any, enum: set[str]) -> str:
    if not isinstance(outcome_value, str):
        raise RunUnprocessable(f"judge `outcome` is not a string: {type(outcome_value)}")
    # strip_zero_width before the split, not after: `.strip()` cannot see those characters,
    # and one clinging to `caught` must not turn a judged case unprocessable. Whitespace
    # survives it, so the split still cuts the keyword off the rationale that follows.
    first = re.split(r"[\s.,;:]", strip_zero_width(outcome_value).strip(), maxsplit=1)[0]
    if first not in enum:
        raise RunUnprocessable(f"judge outcome keyword {first!r} not in {sorted(enum)}")
    return first


def _outcome_keyword(outcome_value: Any) -> str:
    return _outcome_keyword_in(outcome_value, OUTCOME_ENUM)


def _benign_outcome_keyword(outcome_value: Any) -> str:
    return _outcome_keyword_in(outcome_value, BENIGN_OUTCOME_ENUM)




class _NoAliasOracleDumper(yaml.SafeDumper):

    def ignore_aliases(self, data: Any) -> bool:
        return True


def dump_oracle_doc(doc: dict) -> str:
    return yaml.dump(
        doc, Dumper=_NoAliasOracleDumper, sort_keys=False,
        default_flow_style=False, allow_unicode=True,
    )




def _validate_judge_optional_keys(doc: dict[str, Any], keys: frozenset[str]) -> None:
    """Validate the optional top-level keys THIS doc's direction may carry — a key outside
    `keys` is left alone rather than rejected.

    The declared set is the one home for "which optional keys does this direction's judge
    emit": the transcript view reads the same sets off `Direction.judge_optional_keys` to
    decide which sections to render, so a new optional key cannot be accepted here and stay
    invisible on the page."""
    for key in sorted(keys):
        _JUDGE_OPTIONAL_VALIDATORS[key](doc)


def _validate_judge_actor_observations(doc: dict[str, Any]) -> None:
    if "actor_observations" not in doc:
        return
    observations = doc["actor_observations"]
    if not isinstance(observations, list):
        raise RunUnprocessable("judge `actor_observations` is not a list")
    for i, o in enumerate(observations):
        _validate_actor_observation(i, o)


def _validate_judge_environment_observations(doc: dict[str, Any]) -> None:
    if "environment_observations" not in doc:
        return
    obs = doc["environment_observations"]
    if not isinstance(obs, list):
        raise RunUnprocessable("judge `environment_observations` is not a list")
    for i, o in enumerate(obs):
        _validate_environment_observation(i, o)


def _validate_judge_resolution_method(doc: dict[str, Any]) -> None:
    if "resolution_method" not in doc:
        return
    rm = doc["resolution_method"]
    if not isinstance(rm, str) or is_content_less(rm):
        raise RunUnprocessable("judge `resolution_method` must be a non-empty string")


_JUDGE_OPTIONAL_VALIDATORS = {
    "actor_observations": _validate_judge_actor_observations,
    "environment_observations": _validate_judge_environment_observations,
    "resolution_method": _validate_judge_resolution_method,
}

# The optional top-level keys each direction's judge doc may carry. Enforced by the
# validators above and read by the transcript view through `Direction.judge_optional_keys`
# — ONE declaration, so accepted-but-unrendered cannot happen.
ADVERSARIAL_JUDGE_OPTIONAL_KEYS = frozenset(_JUDGE_OPTIONAL_VALIDATORS)
BENIGN_JUDGE_OPTIONAL_KEYS = frozenset({"environment_observations"})


def validate_judge_doc(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise RunUnprocessable("judge YAML did not parse to a mapping")
    _require_judge_keys(doc, _outcome_keyword)
    findings = doc["defender_findings"]
    if not isinstance(findings, list):
        raise RunUnprocessable("judge `defender_findings` is not a list")
    for i, f in enumerate(findings):
        _validate_finding(i, f, ALL_FINDING_TYPES)
    _validate_judge_optional_keys(doc, ADVERSARIAL_JUDGE_OPTIONAL_KEYS)
    return doc


def _require_judge_keys(doc: dict, outcome_keyword) -> None:
    for key in ("outcome", "defender_findings"):
        if key not in doc:
            raise RunUnprocessable(f"judge YAML missing required key: {key}")
    outcome_keyword(doc["outcome"])


def _validate_finding(i: int, f: Any, allowed_types: set[str]) -> None:
    if not isinstance(f, dict):
        raise RunUnprocessable(f"finding[{i}] is not a mapping")
    for k in ("type", "subject_anchor", "subject_topic", "finding", "citations"):
        if k not in f:
            raise RunUnprocessable(f"finding[{i}] missing key: {k}")
    for k in ("subject_anchor", "subject_topic"):
        v = f[k]
        if not isinstance(v, str) or is_content_less(v):
            raise RunUnprocessable(f"finding[{i}].{k} must be a non-empty string")
    # `isinstance` first — `allowed_types` is a set, so a non-string `type` raises an
    # unhashable-TypeError past `RunUnprocessable` and out of `_validate_judge_yaml`
    # BEFORE the `*.raw.txt` audit companion is written, losing the only record of what
    # the judge replied. The two keys checked directly above already guard this way.
    if not isinstance(f["type"], str) or f["type"] not in allowed_types:
        raise RunUnprocessable(
            f"finding[{i}].type={f['type']!r} not in {sorted(allowed_types)}"
        )
    if not isinstance(f["citations"], list):
        raise RunUnprocessable(f"finding[{i}].citations is not a list")


def _validate_actor_observation(i: int, o: Any) -> None:
    if not isinstance(o, dict):
        raise RunUnprocessable(f"actor_observations[{i}] is not a mapping")
    for k in ("type", "subject_anchor", "subject_topic", "observation"):
        if k not in o:
            raise RunUnprocessable(f"actor_observations[{i}] missing key: {k}")
        v = o[k]
        if not isinstance(v, str) or is_content_less(v):
            raise RunUnprocessable(f"actor_observations[{i}].{k} must be a non-empty string")
    if o["type"] not in ACTOR_OBSERVATION_TYPES:
        raise RunUnprocessable(
            f"actor_observations[{i}].type={o['type']!r} not in "
            f"{sorted(ACTOR_OBSERVATION_TYPES)}"
        )




def validate_judge_benign_doc(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise RunUnprocessable("benign judge YAML did not parse to a mapping")
    _require_judge_keys(doc, _benign_outcome_keyword)
    findings = doc["defender_findings"]
    if not isinstance(findings, list):
        raise RunUnprocessable("benign judge `defender_findings` is not a list")
    for i, f in enumerate(findings):
        _validate_finding(i, f, BENIGN_ALL_FINDING_TYPES)
    _validate_judge_optional_keys(doc, BENIGN_JUDGE_OPTIONAL_KEYS)
    return doc


def _validate_environment_observation(i: int, o: Any) -> None:
    if not isinstance(o, dict):
        raise RunUnprocessable(f"environment_observations[{i}] is not a mapping")
    for k in ("alert_rule_ids", "relevance_criteria", "fact"):
        if k not in o:
            raise RunUnprocessable(f"environment_observations[{i}] missing key: {k}")
    rule_ids = o["alert_rule_ids"]
    if not isinstance(rule_ids, list) or not rule_ids:
        raise RunUnprocessable(
            f"environment_observations[{i}].alert_rule_ids must be a non-empty "
            "list (the retrieval anchor)"
        )
    # A list of ids that render as nothing is as anchorless as an empty list, and
    # `persist.py` stores these as THE retrieval anchor for the fact.
    if any(not isinstance(r, str) or is_content_less(r) for r in rule_ids):
        raise RunUnprocessable(
            f"environment_observations[{i}].alert_rule_ids entries must be "
            "non-empty strings (the retrieval anchor)"
        )
    for k in ("relevance_criteria", "fact"):
        if not isinstance(o[k], str) or is_content_less(o[k]):
            raise RunUnprocessable(
                f"environment_observations[{i}].{k} must be a non-empty string"
            )
    _validate_entity_selectors(i, o.get("entities") or [])


def _validate_entity_selectors(i: int, entities: Any) -> None:
    """The optional `entities` list of an environment observation.

    `isinstance` BEFORE the loop, the same guard and the same reason as `_validate_finding`'s
    `type` check: a scalar here raises `TypeError: 'int' object is not iterable` past the
    declared `RunUnprocessable` and out of `_validate_judge_yaml` — which catches only
    `(yaml.YAMLError, RunUnprocessable)` and writes the `*.raw.txt` audit companion INSIDE that
    handler, so the crash takes the only record of what the judge replied with it.
    """
    if not isinstance(entities, list):
        raise RunUnprocessable(
            f"environment_observations[{i}].entities must be a list of "
            "{type, class} selector mappings"
        )
    for sel in entities:
        if not isinstance(sel, dict) or "type" not in sel or "class" not in sel:
            raise RunUnprocessable(
                f"environment_observations[{i}].entities selectors must be "
                "{type, class} mappings"
            )


@dataclass(frozen=True)
class Verdict:
    """One judge verdict, reduced to the fields a comparison can be made on.

    Kept here rather than in an eval harness: the two production-judge suites
    (`test_judge_pydantic_engine.py`, `test_judge_yaml_preamble.py`) assert on it as the
    end-to-end shape a raw model return normalizes into.
    """

    case_id: str
    direction: str
    outcome: str | None
    finding_keys: frozenset
    parsed_ok: bool


def parse_judge_verdict(text: str, *, case_id: str, direction: str) -> Verdict:
    """A raw judge return parsed into a `Verdict`, never raising.

    An unparseable or schema-invalid verdict is a DATA POINT — `parsed_ok=False` — rather
    than a crash: this is the one judge-YAML entry point whose caller is measuring how often
    the model produces something unusable, so a refusal here would destroy the measurement.
    The live loop's own path (`run_cycle._validate_judge_yaml`) makes the opposite choice on
    purpose.
    """
    benign = direction == "benign"
    try:
        # `_yaml.safe_load`, not `yaml.safe_load`: the hardened wrapper turns a recursion bomb
        # and an unconstructable scalar into `YAMLError` instead of their own types.
        doc = safe_load(normalize_judge_yaml(text))
        validated = (validate_judge_benign_doc if benign else validate_judge_doc)(doc)
    except Exception:  # noqa: BLE001 — an unparseable/invalid verdict is a data point, not a crash
        return Verdict(case_id, direction, None, frozenset(), False)
    keys = frozenset(
        (f.get("type"), f.get("subject_anchor"))
        for f in validated.get("defender_findings", [])
        if isinstance(f, dict)
    )
    return Verdict(case_id, direction, validated.get("outcome"), keys, True)
