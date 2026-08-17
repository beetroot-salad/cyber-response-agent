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


# The ratchet, one row per arm. `results` is what the checkers reported this run; the baseline
# entry is the ceiling recorded for that graph; `rc` is the gate's verdict.
@pytest.mark.parametrize(("case", "results", "entries", "rc"), [
    # The point of the whole gate: a graph ABSENT from the baseline must be clean, whatever
    # the corpus behind it looks like — every graph write-tests produces from here on.
    ("new-graph-with-a-finding-fails", {"new.yaml": ["claims: mistyped C1"]}, {}, 1),
    ("new-graph-clean-passes", {"new.yaml": []}, {}, 0),

    # A baselined graph may sit AT its ceiling ...
    ("baselined-graph-at-its-ceiling-passes",
     {"old.yaml": ["a", "b", "c"]}, {"old.yaml": "3 — pre-#674"}, 0),
    # ... and may not exceed it.
    ("baselined-graph-that-gains-a-finding-fails",
     {"old.yaml": ["a", "b", "c", "d"]}, {"old.yaml": "3 — pre-#674"}, 1),

    # The arm a fingerprint-MEMBERSHIP ratchet gets wrong: fixing findings changes the graph's
    # identity under a (path, count) key, and a naive "absent from baseline" rule would fail
    # the build for an improvement.
    ("paying-debt-down-is-not-a-failure",
     {"old.yaml": ["a"]}, {"old.yaml": "3 — pre-#674"}, 0),

    # A malformed baseline entry must not read as "anything goes" — the direction a corrupted
    # config fails in is itself a decision.
    ("unparseable-ceiling-tightens-rather-than-loosens",
     {"old.yaml": ["a"]}, {"old.yaml": "no number here"}, 1),
], ids=lambda v: v if isinstance(v, str) and len(v) < 60 and " " not in v else "")
def test_the_ratchet_blocks_growth_without_blocking_repair(
    lint, tmp_path, case, results, entries, rc
):
    """The gate blocks a graph that is newly dirty or that gained findings, and stays out of
    the way of one that paid debt down — with a corrupted ceiling failing CLOSED."""
    assert lint.main([], results=results, baseline_path=_baseline(tmp_path, entries)) == rc


def test_a_gate_that_cannot_look_exits_2(lint, tmp_path):
    """#652's rule, applied to this gate: blindness is never clean. A checker that cannot
    load, or a graph that cannot be read, must not certify the corpus.

    Blindness arrives through the `scan` seam rather than by replacing the module's own
    function: the fake injects the fault, it does not reach inside the target."""
    def _blind():
        raise lint.GateBlind("checkers unavailable")

    assert lint.main([], scan=_blind, baseline_path=_baseline(tmp_path, {})) == 2


@pytest.mark.gate  # covered by code-smells' "spec_graph gate (checkers over the committed corpus)"
def test_the_committed_corpus_is_at_or_under_its_recorded_ceilings(lint):
    """The real corpus against the real baseline — the assertion CI makes on every push.

    `gate`-marked, so the `test` job does not make it a SECOND time: the code-smells step
    runs this exact entry point over this exact corpus and blocks on its exit code. At 19.5s
    it was the second-largest test in the suite, and the duplicate bought no coverage."""
    assert lint.main([]) == 0
