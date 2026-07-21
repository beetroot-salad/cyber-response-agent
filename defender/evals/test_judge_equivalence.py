from __future__ import annotations

import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender.evals.judge_equivalence import (  # noqa: E402
    Verdict,
    compare,
    findings_agreement,
    outcome_match_rate,
    parse_failure_rate,
    parse_judge_verdict,
    punt_rate,
    render_report,
    systematic_flips,
)


def _v(case, direction, outcome, keys=()):
    return Verdict(case, direction, outcome, frozenset(keys), outcome is not None)



def test_parse_verdict_valid_empty_findings():
    v = parse_judge_verdict("outcome: caught\ndefender_findings: []\n", case_id="c1", direction="adversarial")
    assert v.parsed_ok
    assert v.outcome == "caught"
    assert v.finding_keys == frozenset()


def test_parse_verdict_strips_fence():
    v = parse_judge_verdict("```yaml\noutcome: survived\ndefender_findings: []\n```\n",
                      case_id="c1", direction="adversarial")
    assert v.parsed_ok
    assert v.outcome == "survived"


def test_parse_verdict_invalid_is_not_a_crash():
    for bad in ("not yaml: [", "outcome: bogus-keyword\ndefender_findings: []\n", "just prose"):
        v = parse_judge_verdict(bad, case_id="c1", direction="adversarial")
        assert not v.parsed_ok
        assert v.outcome is None



def test_outcome_match_rate():
    ref = [_v("a", "adversarial", "caught"), _v("b", "adversarial", "survived")]
    cand = [_v("a", "adversarial", "caught"), _v("b", "adversarial", "undecidable")]
    assert outcome_match_rate(ref, cand) == 0.5
    assert outcome_match_rate([], []) == 1.0


def test_systematic_flips_only_counts_the_load_bearing_axis():
    ref = [
        _v("a", "adversarial", "caught"),
        _v("b", "adversarial", "caught"),
        _v("c", "benign", "refuted"),
    ]
    cand = [
        _v("a", "adversarial", "survived"),
        _v("b", "adversarial", "undecidable"),
        _v("c", "benign", "survived"),
    ]
    assert systematic_flips(ref, cand) == ["a", "c"]


def test_findings_agreement_jaccard():
    ref = [_v("a", "adversarial", "caught", keys={("missed-lead", "x"), ("gap", "y")})]
    cand = [_v("a", "adversarial", "caught", keys={("missed-lead", "x")})]
    assert findings_agreement(ref, cand) == 0.5
    assert findings_agreement([_v("a", "adversarial", "caught")],
                              [_v("a", "adversarial", "caught")]) == 1.0


def test_punt_and_parse_failure_rates():
    vs = [_v("a", "adversarial", "caught"), _v("b", "adversarial", "undecidable"),
          _v("c", "adversarial", "incoherent"), _v("d", "adversarial", None)]
    assert punt_rate(vs) == 0.5
    assert parse_failure_rate(vs) == 0.25


def test_compare_and_report():
    ref = [_v("a", "adversarial", "caught"), _v("b", "benign", "refuted")]
    cand = [_v("a", "adversarial", "caught"), _v("b", "benign", "survived")]
    cmp = compare(ref, cand)
    assert cmp.n == 2
    assert cmp.outcome_match == 0.5
    assert cmp.flips == ["b"]
    txt = render_report("Step 1", cmp, self_consistency=0.9)
    assert "flips: 1" in txt
    assert "NOT yet equivalent" in txt


def test_compare_mismatched_lengths_raises():
    import pytest
    with pytest.raises(ValueError, match="differ in length"):
        compare([_v("a", "adversarial", "caught")], [])
