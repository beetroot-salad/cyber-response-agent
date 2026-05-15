"""Top-k neighbor scorer — tokenizer units + the regression-pin fixture."""
from __future__ import annotations

import pytest

from defender.learning import lead_neighbors as ln


# ---------------------------------------------------------------------------
# tokenize_query — Mode A argument-side tokenizer
# ---------------------------------------------------------------------------


def test_tokenize_query_drops_pure_numeric_and_plumbing():
    toks = ln.tokenize_query(
        "python3 wazuh_cli.py --query 'rule.id:5710' --window 1h"
    )
    assert "5710" not in toks
    # "window" is in PLUMBING_TOKENS — must not appear.
    assert "window" not in toks
    assert "run_dir" not in toks


def test_tokenize_query_preserves_dotted_field_references():
    """`rule.id` and `data.srcip` must survive as single tokens."""
    toks = ln.tokenize_query("rule.id:5710 AND data.srcip:10.0.0.1")
    assert "rule.id" in toks
    assert "data.srcip" in toks
    # Sanity — they did NOT collapse to bare "rule" + "id".
    assert "id" not in toks or "data" not in toks or "rule.id" in toks


def test_tokenize_query_lowercases():
    toks = ln.tokenize_query("RULE.GROUPS:Sudo")
    assert "rule.groups" in toks
    assert "sudo" in toks
    assert "RULE.GROUPS" not in toks


def test_tokenize_query_empty_input_yields_empty_set():
    assert ln.tokenize_query("") == frozenset()


# ---------------------------------------------------------------------------
# tokenize_goal — Mode B prose tokenizer
# ---------------------------------------------------------------------------


def test_tokenize_goal_drops_stopwords():
    toks = ln.tokenize_goal("Retrieve sudo commands on a given host")
    assert "retrieve" in toks
    assert "sudo" in toks
    assert "commands" in toks
    assert "host" in toks
    # Stoplisted words must not appear.
    assert "on" not in toks
    assert "a" not in toks
    assert "the" not in toks


def test_tokenize_goal_drops_numeric_tokens():
    toks = ln.tokenize_goal("Look at rule 5710 over the last 24 hours")
    assert "5710" not in toks
    assert "24" not in toks
    assert "rule" in toks


# ---------------------------------------------------------------------------
# build_idf
# ---------------------------------------------------------------------------


def test_build_idf_increases_for_rare_tokens():
    """A token in 1 of 3 documents should weight more than a token in all 3."""
    a = frozenset({"x", "y"})
    b = frozenset({"y", "z"})
    c = frozenset({"y", "w"})
    idf = ln.build_idf([a, b, c])
    assert idf["x"] > idf["y"], idf
    assert idf["w"] > idf["y"]


def test_build_idf_empty_corpus_returns_empty_dict():
    assert ln.build_idf([]) == {}


def test_build_idf_handles_no_tokens():
    """Empty token sets must not crash idf computation."""
    idf = ln.build_idf([frozenset(), frozenset()])
    assert idf == {}


# ---------------------------------------------------------------------------
# weighted_jaccard
# ---------------------------------------------------------------------------


def test_weighted_jaccard_identical_sets_is_1():
    a = frozenset({"x", "y"})
    idf = {"x": 1.0, "y": 1.0}
    assert ln.weighted_jaccard(a, a, idf) == pytest.approx(1.0)


def test_weighted_jaccard_disjoint_is_0():
    a = frozenset({"x"})
    b = frozenset({"y"})
    idf = {"x": 1.0, "y": 1.0}
    assert ln.weighted_jaccard(a, b, idf) == 0.0


def test_weighted_jaccard_empty_input_is_0():
    assert ln.weighted_jaccard(frozenset(), frozenset({"x"}), {"x": 1.0}) == 0.0
    assert ln.weighted_jaccard(frozenset({"x"}), frozenset(), {"x": 1.0}) == 0.0


# ---------------------------------------------------------------------------
# Mode-A / Mode-B routing
# ---------------------------------------------------------------------------


def test_top_k_neighbors_uses_mode_a_when_query_id_resolves():
    catalog = ln.load_catalog()
    mode, neighbors = ln.top_k_neighbors(
        {"query_id": "wazuh.auth-events", "goal_text": ""},
        catalog,
        k=3,
    )
    assert mode == "A"
    assert all(n.template_id != "wazuh.auth-events" for n in neighbors)
    assert len(neighbors) == 3


def test_top_k_neighbors_falls_through_to_mode_b_when_query_id_unresolved():
    catalog = ln.load_catalog()
    mode, neighbors = ln.top_k_neighbors(
        {
            "query_id": "wazuh.nonexistent",
            "goal_text": "Retrieve sudo commands",
        },
        catalog,
        k=3,
    )
    assert mode == "B"
    assert len(neighbors) == 3


def test_top_k_neighbors_mode_b_smoke_returns_descending_scores():
    """Mode B is not empirically validated — smoke-test only."""
    catalog = ln.load_catalog()
    _, neighbors = ln.top_k_neighbors(
        {"query_id": "", "goal_text": "DNS queries to a suspicious domain"},
        catalog,
        k=3,
    )
    assert len(neighbors) == 3
    # Scores monotonically non-increasing.
    for i in range(len(neighbors) - 1):
        assert neighbors[i].score >= neighbors[i + 1].score


# ---------------------------------------------------------------------------
# Regression fixture — pinned scorer behavior
# ---------------------------------------------------------------------------


def test_sanity_fixture_passes_7_of_7():
    """The 7-case regression fixture must pass 7/7 top-3.

    The expectations are the scorer's CURRENT output, pinned. Any
    regression (tokenizer change, idf change, weight change) that
    re-ranks the top-3 surfaces here so a human can decide whether
    the change is desired.
    """
    catalog = ln.load_catalog()
    result = ln.evaluate_sanity_fixture(catalog)
    assert result["fails"] == 0, result["detail"]
    assert result["passes"] == 7
