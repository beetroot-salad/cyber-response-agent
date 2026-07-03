"""Pure validators and text-normalizers for loop artifacts — no I/O, no globals.

Disposition normalization, model-output fence/envelope stripping, outcome-keyword
parsing, and the oracle/judge/benign-judge schema gates. Everything here is a pure
function of its arguments, so it is unit-tested directly with no injection.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from defender._frontmatter import FrontmatterError, parse_frontmatter
from defender.learning.core.config import (
    ACTOR_OBSERVATION_TYPES,
    ALL_FINDING_TYPES,
    BENIGN_ALL_FINDING_TYPES,
    BENIGN_OUTCOME_ENUM,
    DISPOSITION_ENUM,
    RunUnprocessable,
    OUTCOME_ENUM,
)


# ---------------------------------------------------------------------------
# Disposition normalization
# ---------------------------------------------------------------------------


def normalize_disposition(report_path: Path) -> str:
    if not report_path.is_file():
        raise RunUnprocessable(f"report.md not found: {report_path}")
    text = report_path.read_text()
    try:
        fm, _ = parse_frontmatter(text)
    except FrontmatterError as e:
        head = "\n".join(text.splitlines()[:30])
        raise RunUnprocessable(f"report.md {e}\n--- {report_path} (head) ---\n{head}") from e
    disp = fm.get("disposition")
    if disp not in DISPOSITION_ENUM:
        raise RunUnprocessable(
            f"report.md disposition={disp!r} not in {sorted(DISPOSITION_ENUM)}"
        )
    return disp


# ---------------------------------------------------------------------------
# Model-output envelope stripping
# ---------------------------------------------------------------------------


def strip_yaml_fence(text: str) -> str:
    """Strip a leading code fence and/or a stray opening/closing XML tag.

    Models routinely wrap structured output in a code fence or a phantom
    `<content>...</content>` envelope even when the prompt forbids it; the loop
    accepts these tics rather than fail on them. Stripping is shallow: only one
    fence/tag layer is removed, and only if it surrounds the entire payload.
    """
    s = text.strip()
    # Drop everything up to and including a closing </thinking> / </think> tag —
    # reasoning-model output convention sometimes leaks through, with the actual
    # answer following the closing tag.
    m = re.search(r"</[a-zA-Z_][\w-]*?think[a-zA-Z_]*>\s*\n", s) or re.search(
        r"</think(?:ing)?>\s*\n", s
    )
    if m:
        s = s[m.end():].strip()
    m = re.match(r"\A```(?:yaml|yml)?\s*\n(.*?)\n```\s*\Z", s, re.DOTALL)
    if m:
        s = m.group(1).strip()
    # Drop a leading preamble before a fenced YAML block ("Let me construct...").
    m = re.search(r"^```(?:yaml|yml)?\s*\n(.*?)\n```", s, re.DOTALL | re.MULTILINE)
    if m and not s.startswith("```"):
        s = m.group(1).strip()
    # Strip a wrapping <tag>...</tag> envelope (e.g. <content>, <output>).
    m = re.match(r"\A<([a-zA-Z_][\w-]*)\s*>\s*\n(.*?)\n\s*</\1>\s*\Z", s, re.DOTALL)
    if m:
        s = m.group(2).strip()
    # Strip a dangling trailing close tag / close fence with no matching opener.
    s = re.sub(r"\n\s*</[a-zA-Z_][\w-]*>\s*\Z", "", s)
    s = re.sub(r"\n\s*```\s*\Z", "", s)
    return s


def strip_yaml_preamble(text: str) -> str:
    """Trim a leading prose preamble that sits before an embedded YAML mapping.

    A reasoning model sometimes prepends analysis prose ("Let me analyze...\\n\\n") above
    the YAML document it was asked to emit; unfenced, that prose makes ``yaml.safe_load``
    fail on the whole blob. This drops leading lines until the remainder parses to a YAML
    **mapping** (a ``dict``), and returns that suffix. Schema-agnostic on purpose — it
    anchors on "the rest is a mapping", NOT on any particular first key — so it works for
    any single-mapping document, not just the judge verdict's ``outcome:``.

    Robust by construction: at column 0 a preamble and the real document either merge into
    one mapping (YAML duplicate-key last-wins keeps the real, later value) or the preamble's
    suffix fails to parse and the walk falls through to the real document; a multi-document
    ``---`` stream raises (``safe_load`` is single-document) and is likewise walked past.
    Fail-closed: when no suffix parses to a mapping (a genuinely malformed output), the text
    is returned unchanged, so it fails validation downstream exactly as it should.
    """
    lines = text.split("\n")
    for i in range(len(lines)):
        candidate = text if i == 0 else "\n".join(lines[i:])
        try:
            doc = yaml.safe_load(candidate)
        except (yaml.YAMLError, RecursionError):
            # RecursionError (a deeply nested flow collection) is not a YAMLError, so it
            # would otherwise escape and crash the caller; treat it like any unparseable
            # candidate and keep the walk fail-closed.
            continue
        if isinstance(doc, dict):
            if not i:
                return text  # already clean — return verbatim (no whitespace perturbation)
            # A preamble was dropped. Drop only the blank boundary line(s) the split left,
            # preserving the verified suffix's own indentation — a plain ``.strip()`` would
            # dedent just the first line and desync a uniformly-indented mapping into
            # invalid YAML (the function had already proven this candidate parses).
            suffix = lines[i:]
            while suffix and not suffix[0].strip():
                del suffix[0]
            return "\n".join(suffix)
    return text


def normalize_judge_yaml(text: str) -> str:
    """The shared judge-output normalizer: strip a code-fence/envelope, then a prose
    preamble. Both judge consumers — the live loop (``orchestrate._validate_judge_yaml``)
    and the eval A/B harness (``judge_equivalence.parse_judge_verdict``) — funnel through
    this ONE function so their preamble handling can never drift apart (the drift #492
    fixed). Composed of two general primitives; the oracle path deliberately calls only
    ``strip_yaml_fence`` (its assembled doc has no prose preamble to trim)."""
    return strip_yaml_preamble(strip_yaml_fence(text))


# ---------------------------------------------------------------------------
# Outcome-keyword parsing
# ---------------------------------------------------------------------------


def _outcome_keyword_in(outcome_value: Any, enum: set[str]) -> str:
    if not isinstance(outcome_value, str):
        raise RunUnprocessable(f"judge `outcome` is not a string: {type(outcome_value)}")
    # Tolerate the model fusing the keyword with a rationale clause
    # ("survived. The defender's investigation…"): take the head token.
    first = re.split(r"[\s.,;:]", outcome_value.strip(), maxsplit=1)[0]
    if first not in enum:
        raise RunUnprocessable(f"judge outcome keyword {first!r} not in {sorted(enum)}")
    return first


def _outcome_keyword(outcome_value: Any) -> str:
    return _outcome_keyword_in(outcome_value, OUTCOME_ENUM)


def _benign_outcome_keyword(outcome_value: Any) -> str:
    return _outcome_keyword_in(outcome_value, BENIGN_OUTCOME_ENUM)


# ---------------------------------------------------------------------------
# Oracle doc serialization
# ---------------------------------------------------------------------------
#
# The oracle doc is assembled by our own code (``_loop_oracle.assemble_oracle_doc``:
# one ``{lead_id, events}`` per lead, lead_ids taken from the join), so its structure
# is guaranteed by construction — there is nothing model-controlled to validate at the
# doc level. The only model-authored content is each lead's ``events`` list, which
# ``parse_lead_events`` already guarantees is a list; its items are read solely by the
# LLM judge as text, so no structural gate is imposed on them here.


class _NoAliasOracleDumper(yaml.SafeDumper):
    """SafeDumper that never emits YAML anchors/aliases.

    The judge is an LLM reading the raw YAML text — it cannot resolve a ``*alias``
    back-reference, so two shape-identical projected events must each be written out in
    full rather than the second collapsing to an alias of the first. Forcing inline
    emission keeps every projection self-contained.
    """

    def ignore_aliases(self, data: Any) -> bool:
        return True


def dump_oracle_doc(doc: dict) -> str:
    """Serialize the assembled oracle doc to YAML, every event inlined (no aliases).

    The judge reads this as text, so repeated events are written out in full under each
    lead, never as ``*alias`` back-references (see ``_NoAliasOracleDumper``).
    ``allow_unicode=True`` keeps non-ASCII event values (e.g. a username ``Bjørn``) literal
    rather than ``\\xNN``-escaped, so the LLM judge compares the same text the defender's
    actuals carry. Mirrors the dumper in ``_loop_oracle.build_lead_user_prompt``.
    """
    return yaml.dump(
        doc, Dumper=_NoAliasOracleDumper, sort_keys=False,
        default_flow_style=False, allow_unicode=True,
    )


# ---------------------------------------------------------------------------
# Judge schema (adversarial)
# ---------------------------------------------------------------------------


def _validate_judge_actor_observations(doc: dict[str, Any]) -> None:
    """Optional `actor_observations` list (adversarial-only)."""
    if "actor_observations" not in doc:
        return
    observations = doc["actor_observations"]
    if not isinstance(observations, list):
        raise RunUnprocessable("judge `actor_observations` is not a list")
    for i, o in enumerate(observations):
        _validate_actor_observation(i, o)


def _validate_judge_environment_observations(doc: dict[str, Any]) -> None:
    """Optional `environment_observations` list. The adversarial judge also emits
    positive-polarity env facts from grounded mispredictions, into the SHARED
    lessons-environment/ corpus (issue #298). Same schema as the benign env
    stream — reuse the gate."""
    if "environment_observations" not in doc:
        return
    obs = doc["environment_observations"]
    if not isinstance(obs, list):
        raise RunUnprocessable("judge `environment_observations` is not a list")
    for i, o in enumerate(obs):
        _validate_environment_observation(i, o)


def _validate_judge_resolution_method(doc: dict[str, Any]) -> None:
    """Optional `resolution_method`: the grounded form offline enrichment stamps
    inside the case-history ticket's `resolution` (issue #338) — emitted only on
    a benign disposition, so optional here; when present it must be a non-empty
    scalar line."""
    if "resolution_method" not in doc:
        return
    rm = doc["resolution_method"]
    if not isinstance(rm, str) or not rm.strip():
        raise RunUnprocessable("judge `resolution_method` must be a non-empty string")


def validate_judge_doc(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise RunUnprocessable("judge YAML did not parse to a mapping")
    _require_judge_keys(doc, _outcome_keyword)
    findings = doc["defender_findings"]
    if not isinstance(findings, list):
        raise RunUnprocessable("judge `defender_findings` is not a list")
    for i, f in enumerate(findings):
        _validate_finding(i, f, ALL_FINDING_TYPES)
    _validate_judge_actor_observations(doc)
    _validate_judge_environment_observations(doc)
    _validate_judge_resolution_method(doc)
    return doc


def _require_judge_keys(doc: dict, outcome_keyword) -> None:
    # `outcome_rationale`, `encounter_analysis`, `confidence` are thinking
    # scaffolding the prompt walks the model through but no longer requires it to
    # emit — the loop never parsed them. Required output is the machine-consumed core.
    for key in ("outcome", "defender_findings"):
        if key not in doc:
            raise RunUnprocessable(f"judge YAML missing required key: {key}")
    outcome_keyword(doc["outcome"])  # raises on an unknown keyword


def _validate_finding(i: int, f: Any, allowed_types: set[str]) -> None:
    if not isinstance(f, dict):
        raise RunUnprocessable(f"finding[{i}] is not a mapping")
    for k in ("type", "subject_anchor", "subject_topic", "finding", "citations"):
        if k not in f:
            raise RunUnprocessable(f"finding[{i}] missing key: {k}")
    for k in ("subject_anchor", "subject_topic"):
        v = f[k]
        if not isinstance(v, str) or not v.strip():
            raise RunUnprocessable(f"finding[{i}].{k} must be a non-empty string")
    if f["type"] not in allowed_types:
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
        if not isinstance(v, str) or not v.strip():
            raise RunUnprocessable(f"actor_observations[{i}].{k} must be a non-empty string")
    if o["type"] not in ACTOR_OBSERVATION_TYPES:
        raise RunUnprocessable(
            f"actor_observations[{i}].type={o['type']!r} not in "
            f"{sorted(ACTOR_OBSERVATION_TYPES)}"
        )


# ---------------------------------------------------------------------------
# Judge schema (benign / FP direction)
# ---------------------------------------------------------------------------


def validate_judge_benign_doc(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise RunUnprocessable("benign judge YAML did not parse to a mapping")
    _require_judge_keys(doc, _benign_outcome_keyword)
    findings = doc["defender_findings"]
    if not isinstance(findings, list):
        raise RunUnprocessable("benign judge `defender_findings` is not a list")
    for i, f in enumerate(findings):
        _validate_finding(i, f, BENIGN_ALL_FINDING_TYPES)
    if "environment_observations" in doc:
        obs = doc["environment_observations"]
        if not isinstance(obs, list):
            raise RunUnprocessable("benign judge `environment_observations` is not a list")
        for i, o in enumerate(obs):
            _validate_environment_observation(i, o)
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
    for k in ("relevance_criteria", "fact"):
        if not isinstance(o[k], str) or not o[k].strip():
            raise RunUnprocessable(
                f"environment_observations[{i}].{k} must be a non-empty string"
            )
    # ``entities`` is optional, but each selector must carry type + class. The
    # no-identity discipline is the curator's + forward-check's job, not this gate.
    for sel in o.get("entities") or []:
        if not isinstance(sel, dict) or "type" not in sel or "class" not in sel:
            raise RunUnprocessable(
                f"environment_observations[{i}].entities selectors must be "
                "{type, class} mappings"
            )
