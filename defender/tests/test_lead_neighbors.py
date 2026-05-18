"""Top-k neighbor scorer — tokenizer units + regression-pin fixture.

The fixture pins the scorer's current top-3 output for each bundled
catalog template. A tokenizer / IDF / weighting change that re-ranks
any case shows up as a test failure — the human author decides
whether the change is desired.
"""
from __future__ import annotations

import pytest

import lead_neighbors as ln  # type: ignore[import-not-found]


# ---------------------------------------------------------------------------
# tokenize_query — Mode A argument-side tokenizer
# ---------------------------------------------------------------------------


def test_tokenize_query_drops_pure_numeric_and_plumbing():
    toks = ln.tokenize_query(
        "python3 wazuh_cli.py --query 'rule.id:5710' --window 1h"
    )
    assert "5710" not in toks
    assert "window" not in toks  # PLUMBING
    assert "run_dir" not in toks


def test_tokenize_query_preserves_dotted_field_references():
    toks = ln.tokenize_query("rule.id:5710 AND data.srcip:10.0.0.1")
    assert "rule.id" in toks
    assert "data.srcip" in toks


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
    assert "the" not in toks
    assert "a" not in toks
    assert "on" not in toks
    assert "sudo" in toks
    assert "host" in toks


def test_tokenize_goal_preserves_dotted_field_references():
    toks = ln.tokenize_goal("Find high data.srcip diversity per agent")
    assert "data.srcip" in toks


# ---------------------------------------------------------------------------
# Regression-pin fixture — exact-order top-3 per case
# ---------------------------------------------------------------------------


REGRESSION_FIXTURE: tuple[dict, ...] = (
    {
        "case_id": "auth-events",
        "query_id": "wazuh.auth-events",
        "expected_top3": (
            "wazuh.sudo-commands",
            "wazuh.file-integrity-changes",
            "wazuh.recent-rule-fires",
        ),
    },
    {
        "case_id": "sudo-commands",
        "query_id": "wazuh.sudo-commands",
        "expected_top3": (
            "wazuh.file-integrity-changes",
            "wazuh.auth-events",
            "wazuh.recent-rule-fires",
        ),
    },
    {
        "case_id": "file-integrity-changes",
        "query_id": "wazuh.file-integrity-changes",
        "expected_top3": (
            "wazuh.sudo-commands",
            "wazuh.recent-rule-fires",
            "wazuh.agent-alerts-in-window",
        ),
    },
    {
        "case_id": "recent-rule-fires",
        "query_id": "wazuh.recent-rule-fires",
        "expected_top3": (
            "wazuh.dns-query-history",
            "wazuh.file-integrity-changes",
            "wazuh.agent-alerts-in-window",
        ),
    },
    {
        "case_id": "agent-alerts-in-window",
        "query_id": "wazuh.agent-alerts-in-window",
        "expected_top3": (
            "wazuh.falco-rules-by-container",
            "wazuh.recent-rule-fires",
            "wazuh.file-integrity-changes",
        ),
    },
    {
        "case_id": "dns-query-history",
        "query_id": "wazuh.dns-query-history",
        "expected_top3": (
            "wazuh.recent-rule-fires",
            "wazuh.file-integrity-changes",
            "wazuh.agent-alerts-in-window",
        ),
    },
    {
        "case_id": "mode-b-novel-goal",
        "query_id": "wazuh.nonexistent",
        "goal_text": (
            "Retrieve sudo and privileged command executions on a given host"
        ),
        "expected_top3": (
            "wazuh.sudo-commands",
            "wazuh.auth-events",
            "wazuh.dns-query-history",
        ),
    },
)


@pytest.fixture(scope="module")
def catalog():
    cat = ln.load_catalog()
    if not cat:
        pytest.skip("catalog not present in this checkout")
    return cat


@pytest.fixture(scope="module")
def idfs(catalog):
    return (
        ln.build_idf(ln._all_query_variants(catalog)),
        ln.build_idf([ln.tokenize_goal(t.goal_text) for t in catalog]),
    )


@pytest.mark.parametrize("case", REGRESSION_FIXTURE,
                         ids=[c["case_id"] for c in REGRESSION_FIXTURE])
def test_top3_pinned(catalog, idfs, case):
    idf_query, idf_goal = idfs
    _, neighbors = ln.top_k_neighbors(
        case, catalog, idf_query=idf_query, idf_goal=idf_goal, k=3
    )
    actual = tuple(n.template_id for n in neighbors[:3])
    expected = tuple(case["expected_top3"])
    assert actual == expected, (
        f"top-3 changed for {case['case_id']}:\n"
        f"  expected: {expected}\n"
        f"  actual:   {actual}"
    )


def test_mode_a_cli_firewall(catalog):
    """A wazuh template's neighbors must all be wazuh (CLI firewall)."""
    _, neighbors = ln.top_k_neighbors(
        {"query_id": "wazuh.auth-events"}, catalog, k=10
    )
    for n in neighbors:
        assert n.template_id.startswith("wazuh."), (
            f"CLI firewall leaked: {n.template_id} returned for wazuh source"
        )


def test_mode_b_returns_results_for_unknown_query_id(catalog):
    """Unresolved query_id falls back to Mode B against goal_text."""
    mode, neighbors = ln.top_k_neighbors(
        {"query_id": "nonexistent.lookup", "goal_text": "list sudo commands"},
        catalog,
        k=3,
    )
    assert mode == "B"
    assert len(neighbors) > 0
