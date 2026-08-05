"""The spec_graph ratchet — the gate that makes the checkers bind after authoring time.

The checkers ran only inside write-tests, so a graph merged with its findings intact and
the mechanical no evaporated the moment it became durable. This gate runs them over the
committed corpus; the tests here pin its four arms, because the arm that matters most is the
one that is easy to get backwards: paying debt down must never fail a build.

Findings are injected rather than derived from real graphs — the ratchet's logic is
(findings, baseline) → exit code, and coupling these to the corpus would make them a
re-assertion of today's finding counts instead of a test of the rule.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

LINT_DIR = Path(__file__).resolve().parents[2] / "scripts" / "lint"


@pytest.fixture
def lint():
    if str(LINT_DIR) not in sys.path:
        sys.path.insert(0, str(LINT_DIR))
    import lint_spec_graph

    return lint_spec_graph


def _baseline(tmp_path: Path, entries: dict[str, str]) -> Path:
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps({"//": "test", "entries": entries}), encoding="utf-8")
    return p


def test_a_graph_not_in_the_baseline_must_be_clean(lint, tmp_path):
    """The point of the whole gate: every graph write-tests produces from here on passes
    all four checkers, whatever the corpus behind it looks like."""
    rc = lint.main(
        [], results={"new.yaml": ["claims: mistyped C1"]},
        baseline_path=_baseline(tmp_path, {}),
    )
    assert rc == 1


def test_a_new_clean_graph_passes(lint, tmp_path):
    rc = lint.main([], results={"new.yaml": []}, baseline_path=_baseline(tmp_path, {}))
    assert rc == 0


def test_a_baselined_graph_at_its_ceiling_passes(lint, tmp_path):
    rc = lint.main(
        [], results={"old.yaml": ["a", "b", "c"]},
        baseline_path=_baseline(tmp_path, {"old.yaml": "3 — pre-#674"}),
    )
    assert rc == 0


def test_a_baselined_graph_that_gains_a_finding_fails(lint, tmp_path):
    rc = lint.main(
        [], results={"old.yaml": ["a", "b", "c", "d"]},
        baseline_path=_baseline(tmp_path, {"old.yaml": "3 — pre-#674"}),
    )
    assert rc == 1


def test_paying_debt_down_is_not_a_failure(lint, tmp_path):
    """The arm a fingerprint-membership ratchet gets wrong: fixing findings changes the
    graph's identity under a (path, count) key, and a naive 'absent from baseline' rule
    would fail the build for an improvement."""
    rc = lint.main(
        [], results={"old.yaml": ["a"]},
        baseline_path=_baseline(tmp_path, {"old.yaml": "3 — pre-#674"}),
    )
    assert rc == 0


def test_an_unparseable_ceiling_tightens_rather_than_loosens(lint, tmp_path):
    """A malformed baseline entry must not read as 'anything goes' — the direction a
    corrupted config fails in is itself a decision."""
    rc = lint.main(
        [], results={"old.yaml": ["a"]},
        baseline_path=_baseline(tmp_path, {"old.yaml": "no number here"}),
    )
    assert rc == 1


def test_a_gate_that_cannot_look_exits_2(lint, tmp_path, monkeypatch):
    """#652's rule, applied to this gate: blindness is never clean. A checker that cannot
    load, or a graph that cannot be read, must not certify the corpus."""
    def _blind():
        raise lint.GateBlind("checkers unavailable")

    monkeypatch.setattr(lint, "_scan", _blind)
    assert lint.main([], baseline_path=_baseline(tmp_path, {})) == 2


def test_the_committed_corpus_is_at_or_under_its_recorded_ceilings(lint):
    """The real corpus against the real baseline — the assertion CI makes on every push."""
    assert lint.main([]) == 0
