"""Executable spec for issue #492 — the shared judge-verdict preamble normalizer.

A reasoning-model judge sometimes prepends prose ("Let me analyze...\\n\\n") before its
YAML verdict. Trimming it at only one parse site leaves the others dead-lettering an
otherwise-valid verdict. The fix moves the trim into a SHARED, schema-agnostic primitive
both convergence points — the in-process engine's return boundary (`_extract_yaml_doc`)
and the eval harness — call:

  * E1  `validate.strip_yaml_preamble(text) -> str`  — drop leading lines until the
        remainder parses to a YAML MAPPING; fail-closed (return input unchanged) when
        none do. NOT anchored on the literal `outcome:` keyword — general to any schema.
        Composed as `strip_yaml_preamble(strip_yaml_fence(x))`.
  * E2  `run_cycle._validate_judge_yaml`   — the live loop (both engines feed it).
  * E3  `validate.parse_judge_verdict` — the non-raising verdict parser (it lived in the
        engine-equivalence A/B harness until that harness was retired).

These tests drive the REAL entry points and assert only observable outcomes (return
value, parsed outcome, `.raw.txt` side effect, raised errors). They are written before
the implementation: `strip_yaml_preamble` does not exist yet, so this file is RED (import
error) until the fix lands — that is the intended pre-implementation signal.

Resolved design forks (see the #492 discussion):
  * return shape of E1 = `str` (both callers re-parse);
  * probe predicate = first suffix that parses to a mapping (schema-agnostic, no `outcome`
    requirement — provably equivalent to the outcome-keyed anchor on reachable inputs);
  * no-parse fallback = return the strip_yaml_fence result unchanged (fail-closed).
"""
from __future__ import annotations

import yaml
import pytest

from defender.learning.core.config import RunUnprocessable
from defender.learning.core.run_cycle import _validate_judge_yaml
from defender.learning.core.validate import (
    parse_judge_verdict,
    strip_yaml_fence,
    strip_yaml_preamble,
    validate_judge_doc,
)

_CLEAN_ADV = "outcome: caught\ndefender_findings: []"
_CLEAN_BENIGN = "outcome: refuted\ndefender_findings: []"



# --- E1: what the walk TRIMS ------------------------------------------------
# Every case feeds one raw model return and asserts the trimmed text parses to the intended
# verdict. Only the preamble shape varies; the primitive under test never does.
@pytest.mark.parametrize(("case", "raw", "outcome"), [
    # The headline bug: plain prose before the verdict is dropped.
    ("unfenced-prose-preamble", "Let me analyze the findings.\n\n" + _CLEAN_ADV, "caught"),

    # A multi-paragraph preamble (several bare-scalar lines, no blank before the last) is
    # dropped in full, not just down to the last blank line.
    ("multiline-prose-preamble",
     "Paragraph one.\nStill paragraph one.\n\nSecond paragraph.\n\n"
     "outcome: survived\ndefender_findings: []", "survived"),

    # #492 core, mechanism A: a PREAMBLE line begins `outcome:` at col 0, then parse-breaking
    # prose, then the real verdict. The preamble anchor's suffix fails to parse, so the walk
    # falls through to the real verdict — NOT the preamble's 'survived'. The incumbent
    # `_extract_yaml_doc` (first col-0 anchor) got exactly this wrong.
    ("preamble-outcome-line-then-parsebreak-then-real-verdict",
     "outcome: this looks survived-ish to me\n"
     "Let me write the real verdict now.\n\n"
     "outcome: caught\ndefender_findings: []", "caught"),

    # #492 core, mechanism B: when the preamble `outcome:` line and the real verdict merge
    # into ONE mapping (no parse-breaking prose between them), YAML duplicate-key last-wins
    # makes the real (later) outcome win regardless of anchor.
    ("preamble-outcome-line-merges-last-wins",
     "outcome: survived\nnote: on second thought\n\n"
     "outcome: caught\ndefender_findings: []", "caught"),

    # A doc whose ONLY top-level mapping is the verdict, with an indented `outcome:` inside a
    # citation quote, already parses whole — the indented one is data, never anchored on.
    ("indented-citation-outcome-is-not-anchored",
     "outcome: survived\n"
     "defender_findings:\n"
     "  - type: disposition-confirmed\n"
     "    subject_anchor: l-001\n"
     "    citations:\n"
     "      - source: comparison\n"
     "        quote: 'inner outcome: success'\n", "survived"),

    # Regression: when the verdict the walk accepts is uniformly INDENTED (the model emitted
    # it inside a list/quote context), the trimmed result must STILL parse to the same
    # mapping. A plain `.strip()` on the accepted suffix would dedent only the first line and
    # desync the block into invalid YAML — corrupting a verdict the walk had proven parses.
    ("indented-verdict-after-preamble-survives-the-trim",
     "Let me analyze.\n\n  outcome: caught\n  defender_findings: []", "caught"),

    # Duplicate top-level `outcome:` keys are a plain YAML last-wins parse; the primitive does
    # not intercede.
    ("duplicate-outcome-keys-last-wins-not-special-cased",
     "outcome: caught\noutcome: survived\ndefender_findings: []", "survived"),

    # Edge: two `---`-separated verdicts. `yaml.safe_load` RAISES on a multi-doc stream (it is
    # single-doc), so every prefix containing the separator fails and the walk stops at the
    # trailing single doc. Pathological input, pinned so the behavior is defined rather than
    # accidental.
    ("multidoc-separator-yields-the-trailing-doc",
     "outcome: caught\ndefender_findings: []\n---\n"
     "outcome: survived\ndefender_findings: []", "survived"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 60 and "\n" not in v else "")
def test_the_walk_trims_a_preamble_down_to_the_real_verdict(case, raw, outcome):
    """E1: whatever the model wrote before the verdict, the trimmed text parses to the
    verdict the model actually reached — and when two candidate anchors compete, the one
    that PARSES wins rather than the one that comes first."""
    assert yaml.safe_load(strip_yaml_preamble(raw))["outcome"] == outcome


# --- E1: what the walk must LEAVE ALONE -------------------------------------
# Fail-closed. Nothing here is a best-effort truncated slice: the input comes back
# byte-identical so downstream validation dead-letters it exactly as it does today.
@pytest.mark.parametrize(("case", "raw"), [
    # The common case must not be perturbed: input that already parses to a mapping.
    ("clean-mapping-is-a-passthrough-noop", _CLEAN_ADV),
    # No parseable mapping anywhere.
    ("no-mapping-anywhere", "just prose, no verdict here at all"),
    # FORK-B: a col-0 mapping-looking line whose suffix NEVER parses to a mapping (a tab in
    # the indentation makes every suffix invalid YAML).
    ("col0-key-present-but-no-suffix-parses", "outcome:\n\tbroken\ttab\tindent"),
    # A deeply nested flow collection makes `yaml.safe_load` raise `RecursionError` — NOT a
    # `yaml.YAMLError` — on every suffix. The walk must swallow it like any other parse
    # failure rather than letting it escape and crash the caller.
    ("recursion-bomb-is-swallowed-not-raised", "outcome: " + "[" * 6000),
], ids=lambda v: v if isinstance(v, str) and len(v) < 60 and "\n" not in v else "")
def test_the_walk_returns_the_input_unchanged_when_it_cannot_find_a_verdict(case, raw):
    """E1 (fail-closed): with no parseable mapping to trim down to, the primitive returns its
    input byte-for-byte — never a partial slice it could not prove parses."""
    assert strip_yaml_preamble(raw) == raw


def test_is_idempotent():
    """E1: strip_yaml_preamble(strip_yaml_preamble(x)) == strip_yaml_preamble(x) — a
    normalized doc is not re-trimmed on a second pass."""
    raw = "Prose.\n\n" + _CLEAN_ADV
    once = strip_yaml_preamble(raw)
    assert strip_yaml_preamble(once) == once


def test_generalizes_to_non_outcome_schema():
    """E1 (the generality contract): the primitive is NOT anchored on `outcome:`. A
    preamble before a mapping whose first key is something else is trimmed just the same
    -> the remainder parses to the intended mapping."""
    raw = "Some narration first.\n\nleads:\n  - id: l-001\nsummary: done"
    out = strip_yaml_preamble(raw)
    assert yaml.safe_load(out) == {"leads": [{"id": "l-001"}], "summary": "done"}


def test_composes_after_strip_yaml_fence_for_preamble_plus_fence():
    """E1 composition: the call-site order is strip_yaml_fence THEN strip_yaml_preamble.
    strip_yaml_fence already handles 'preamble + fenced block'; the composed pipeline
    yields the clean verdict for a prose-preamble'd, fenced doc."""
    raw = "Let me construct the verdict.\n\n```yaml\noutcome: caught\ndefender_findings: []\n```"
    out = strip_yaml_preamble(strip_yaml_fence(raw))
    assert yaml.safe_load(out)["outcome"] == "caught"



def test_e2_parses_preambled_verdict(tmp_path):
    """E2: a prose-preamble'd adversarial verdict now normalizes + validates -> returns
    (doc, stripped) with doc['outcome']=='caught' and stripped starting at 'outcome:'.
    Pre-fix this dead-lettered (strip_yaml_fence left the prose in place)."""
    raw = "Reasoning about the case.\n\n" + _CLEAN_ADV
    doc, stripped = _validate_judge_yaml(raw, validate_judge_doc, tmp_path / "judge.raw.txt")
    assert doc["outcome"] == "caught"
    assert stripped.startswith("outcome:")


def test_e2_clean_input_writes_no_raw_companion(tmp_path):
    """E2: when normalization is a no-op (already-clean verdict), no `.raw.txt` companion
    is written; the return carries the validated doc."""
    raw_path = tmp_path / "judge.raw.txt"
    doc, stripped = _validate_judge_yaml(_CLEAN_ADV, validate_judge_doc, raw_path)
    assert doc["outcome"] == "caught"
    assert not raw_path.exists()


def test_e2_mutation_writes_raw_companion(tmp_path):
    """E2: when normalization trims a preamble (stripped != raw), the ORIGINAL raw is
    persisted to the `.raw.txt` companion as the audit trail."""
    raw = "Prose preamble.\n\n" + _CLEAN_ADV
    raw_path = tmp_path / "judge.raw.txt"
    _validate_judge_yaml(raw, validate_judge_doc, raw_path)
    assert raw_path.read_text() == raw


def test_e2_unparseable_raises_and_writes_raw(tmp_path):
    """E2: a doc that is still unparseable after normalization raises RunUnprocessable and
    writes the raw companion (fail-closed fallback returned it unchanged; safe_load raised)."""
    raw = "not yaml: ["
    raw_path = tmp_path / "judge.raw.txt"
    with pytest.raises(RunUnprocessable):
        _validate_judge_yaml(raw, validate_judge_doc, raw_path)
    assert raw_path.read_text() == raw


def test_e2_recursion_bomb_dead_letters_not_crashes(tmp_path):
    """E2 (regression): a deeply nested flow collection makes yaml.safe_load raise
    RecursionError — NOT a YAMLError — at BOTH the normalize step and the caller's re-parse.
    _validate_judge_yaml must dead-letter it (RunUnprocessable + raw companion), never let
    the RecursionError escape and crash the learning worker. Mirrors parse_judge_verdict's
    graceful degradation so the two consumers stay converged (#492)."""
    raw = "outcome: " + "[" * 6000
    raw_path = tmp_path / "judge.raw.txt"
    with pytest.raises(RunUnprocessable):
        _validate_judge_yaml(raw, validate_judge_doc, raw_path)
    assert raw_path.read_text() == raw


def test_e2_schema_invalid_raises_and_writes_raw(tmp_path):
    """E2: a doc that parses but fails the schema gate (missing defender_findings) raises
    RunUnprocessable and writes the raw companion — normalization does not paper over a
    validation failure."""
    raw = "outcome: caught"
    raw_path = tmp_path / "judge.raw.txt"
    with pytest.raises(RunUnprocessable):
        _validate_judge_yaml(raw, validate_judge_doc, raw_path)
    assert raw_path.read_text() == raw



def test_e3_parses_preambled_adversarial_verdict():
    """E3: the eval harness now trims a prose preamble too (it was the third consumer the
    fix must cover) -> Verdict(outcome='caught', parsed_ok=True)."""
    raw = "Here is my analysis.\n\n" + _CLEAN_ADV
    v = parse_judge_verdict(raw, case_id="c1", direction="adversarial")
    assert v.parsed_ok
    assert v.outcome == "caught"


def test_e3_parses_preambled_benign_verdict():
    """E3: same fix on the benign leg (equally unprotected before) -> Verdict(outcome=
    'refuted', parsed_ok=True) for a prose-preamble'd benign verdict."""
    raw = "Weighing the false-positive case.\n\n" + _CLEAN_BENIGN
    v = parse_judge_verdict(raw, case_id="c1", direction="benign")
    assert v.parsed_ok
    assert v.outcome == "refuted"


def test_e3_malformed_returns_parsed_ok_false_without_raising():
    """E3: a genuinely malformed doc scores parsed_ok=False (a regression data point) and
    never raises — the A/B must not crash."""
    v = parse_judge_verdict("not yaml: [", case_id="c1", direction="adversarial")
    assert not v.parsed_ok
    assert v.outcome is None



def test_e2_and_e3_agree_on_same_preambled_input(tmp_path):
    """PARITY (the whole point of #492): the SAME preamble'd input yields the SAME outcome
    through the live loop (E2) and the eval harness (E3). They must never diverge again."""
    raw = "Analysis prose.\n\n" + _CLEAN_ADV
    doc, _ = _validate_judge_yaml(raw, validate_judge_doc, tmp_path / "judge.raw.txt")
    v = parse_judge_verdict(raw, case_id="c1", direction="adversarial")
    assert doc["outcome"] == v.outcome == "caught"


def test_strip_yaml_fence_unchanged_for_oracle_style_doc():
    """LAYERING: strip_yaml_fence is NOT modified — the prose-trim lives only in
    strip_yaml_preamble, which the oracle path never calls. An oracle-style doc (a mapping
    with no top-level `outcome:`) run through strip_yaml_fence is unchanged."""
    oracle = "leads:\n  - lead_id: l-001\n    events: []"
    assert strip_yaml_fence(oracle) == oracle
