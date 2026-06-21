"""Top-k neighbor scorer — tokenizer units + regression-pin fixture.

The fixture pins the scorer's current top-3 output for each bundled
catalog template. A tokenizer / IDF / weighting change that re-ranks
any case shows up as a test failure — the human author decides
whether the change is desired.
"""
from __future__ import annotations

import pytest

from defender.learning import lead_neighbors as ln  # type: ignore[import-not-found]


# ---------------------------------------------------------------------------
# tokenize_query — argument-side tokenizer
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


def test_tokenize_query_preserves_hyphenated_index_name():
    """ES|QL data-stream names survive as one token (the strongest 'same data'
    signal); trailing glob/hyphen punctuation is normalized off."""
    toks = ln.tokenize_query('FROM logs-system.auth-* | STATS c = COUNT(*)')
    assert "logs-system.auth" in toks
    assert "logs" not in toks  # not shattered onto the common bare token
    assert "count" in toks


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
)


@pytest.fixture(scope="module")
def catalog():
    cat = ln.load_catalog()
    if not cat:
        pytest.skip("catalog not present in this checkout")
    return cat


@pytest.fixture(scope="module")
def idf(catalog):
    return ln.build_idf(ln._all_query_variants(catalog))


# The regression fixture below and test_cli_firewall pin scorer behavior over
# a populated wazuh catalog. defender-v2-env stripped that catalog in the
# v1-strip and its v2 replacements aren't authored yet, so the pinned ids don't
# resolve. Skip until the v2 gather catalog is populated, then regenerate the
# fixture against real v2 templates (don't hand-invent rankings).
_V2_CATALOG_PENDING = pytest.mark.skip(
    reason="regression baseline pinned against the v1 wazuh catalog (stripped on "
    "defender-v2-env); regenerate against v2 templates once the catalog is populated"
)


@_V2_CATALOG_PENDING
@pytest.mark.parametrize("case", REGRESSION_FIXTURE,
                         ids=[c["case_id"] for c in REGRESSION_FIXTURE])
def test_top3_pinned(catalog, idf, case):
    neighbors = ln.top_k_neighbors(case["query_id"], catalog, idf=idf, k=3)
    actual = tuple(n.template_id for n in neighbors[:3])
    expected = tuple(case["expected_top3"])
    assert actual == expected, (
        f"top-3 changed for {case['case_id']}:\n"
        f"  expected: {expected}\n"
        f"  actual:   {actual}"
    )


@_V2_CATALOG_PENDING
def test_cli_firewall(catalog):
    """A wazuh template's neighbors must all be wazuh (CLI firewall)."""
    neighbors = ln.top_k_neighbors("wazuh.auth-events", catalog, k=10)
    for n in neighbors:
        assert n.template_id.startswith("wazuh."), (
            f"CLI firewall leaked: {n.template_id} returned for wazuh source"
        )


def test_unresolved_query_id_raises(catalog):
    """Caller must filter unresolvable ids; an unfiltered call is a hard error."""
    with pytest.raises(KeyError):
        ln.top_k_neighbors("nonexistent.lookup", catalog, k=3)


# ---------------------------------------------------------------------------
# Catalog walk — _draft/ + status tagging
# ---------------------------------------------------------------------------


def test_load_catalog_walks_draft_subdir(tmp_path):
    catalog_dir = tmp_path / "queries"
    (catalog_dir / "wazuh" / "_draft").mkdir(parents=True)
    (catalog_dir / "wazuh" / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\nstatus: established\n---\n\n## Goal\n\nx\n\n## Query\n\n```\nq\n```\n"
    )
    (catalog_dir / "wazuh" / "_draft" / "novel-thing.md").write_text(
        "---\nid: wazuh.novel-thing\nstatus: draft\n---\n\n## Goal\n\ny\n\n## Query\n\n```\nq2\n```\n"
    )
    cat = ln.load_catalog(catalog_dir)
    by_id = {t.id: t for t in cat}
    assert "wazuh.auth-events" in by_id
    assert "wazuh.novel-thing" in by_id
    assert by_id["wazuh.auth-events"].status == "established"
    assert by_id["wazuh.novel-thing"].status == "draft"
    # System derivation: draft entry's system is still "wazuh", not "_draft".
    assert by_id["wazuh.novel-thing"].system == "wazuh"


def test_load_catalog_defaults_missing_status_to_established(tmp_path):
    """Templates with no `status:` field default to established."""
    catalog_dir = tmp_path / "queries"
    (catalog_dir / "wazuh").mkdir(parents=True)
    (catalog_dir / "wazuh" / "x.md").write_text(
        "---\nid: wazuh.x\n---\n\n## Goal\n\nx\n\n## Query\n\n```\nq\n```\n"
    )
    cat = ln.load_catalog(catalog_dir)
    assert len(cat) == 1
    assert cat[0].status == "established"


# ---------------------------------------------------------------------------
# ES|QL fence extraction (#340 / #343 migration)
# ---------------------------------------------------------------------------


_ESQL_SECTION = """\
ES|QL. Server-side aggregation — zzzproseword the result rows ARE the answer.

```esql
FROM logs-system.auth-*
| WHERE event.outcome IS NOT NULL AND user.name == "${user}"
| STATS accepted = COUNT(*) BY source.ip
```

**Narrowing examples** (each is the query above with axes removed):

- *User baseline*: keep user.name, drop the otherprosenarrowing predicate.
"""


def test_query_variants_extracts_esql_fence_not_prose():
    """An ```esql fence must be tokenized, not the surrounding prose.

    Before the fix, ``_query_variants`` only recognized bash/json/unlabeled
    fences, so an ES|QL section fell through to tokenizing the whole body —
    pulling in prose ("zzzproseword") and the narrowing-example commentary,
    which swamps the actual query tokens.
    """
    variants = ln._query_variants(_ESQL_SECTION)
    toks = set().union(*variants)
    # Query-body tokens are present...
    assert "user.name" in toks
    assert "source.ip" in toks
    assert "event.outcome" in toks
    # ...and prose / narrowing-example tokens outside the fence are not.
    assert "zzzproseword" not in toks
    assert "otherprosenarrowing" not in toks


def _esql_template(tid: str, query: str, goal: str = "auth history") -> str:
    return (
        f"---\nid: {tid}\nstatus: established\nengine: esql\n---\n\n"
        f"## Goal\n\n{goal}\n\n## Query\n\n```esql\n{query}\n```\n"
    )


def test_esql_narrowing_scores_above_unrelated_measurement(tmp_path):
    """A coined narrowing of a wide ES|QL template must rank that template
    as its top neighbor, well above an unrelated measurement.

    This is the underfolding-detection substrate: the curator decides
    'discard/widen vs promote' from these scores, so a narrowing has to be
    legible as a near-duplicate of its wide parent.
    """
    catalog_dir = tmp_path / "queries"
    (catalog_dir / "elastic" / "_draft").mkdir(parents=True)
    # Wide capability template: every auth-history filter axis + broad stats.
    (catalog_dir / "elastic" / "sshd-auth-history.md").write_text(_esql_template(
        "elastic.sshd-auth-history",
        'FROM logs-system.auth-*\n'
        '| WHERE @timestamp >= "${start}" AND user.name == "${user}"\n'
        '        AND source.ip == "${src}" AND host.name == "${dst}"\n'
        '        AND event.outcome IS NOT NULL\n'
        '| STATS accepted = COUNT(*) WHERE event.outcome == "success",\n'
        '        failed = COUNT(*) WHERE event.outcome == "failure"\n'
        '        BY source.ip, host.name',
    ))
    # Unrelated measurement: outbound network connections (different fields).
    (catalog_dir / "elastic" / "zeek-outbound-by-source.md").write_text(_esql_template(
        "elastic.zeek-outbound-by-source",
        'FROM logs-zeek.conn-*\n'
        '| WHERE source.ip == "${src}"\n'
        '| STATS bytes = SUM(network.bytes) BY destination.ip, destination.port',
        goal="outbound network connections",
    ))
    # Coined narrowing of the wide template: a strict subset of its axes.
    (catalog_dir / "elastic" / "_draft" / "sshd-failed-by-srcip.md").write_text(_esql_template(
        "elastic.sshd-failed-by-srcip",
        'FROM logs-system.auth-*\n'
        '| WHERE host.name == "${dst}" AND event.outcome == "failure"\n'
        '| STATS failed = COUNT(*) BY source.ip',
        goal="failed ssh by source ip",
    ))

    catalog = ln.load_catalog(catalog_dir)
    neighbors = ln.top_k_neighbors("elastic.sshd-failed-by-srcip", catalog, k=2)
    by_id = {n.template_id: n.score for n in neighbors}
    assert neighbors[0].template_id == "elastic.sshd-auth-history", (
        f"narrowing should rank its wide parent first, got {neighbors}"
    )
    assert by_id["elastic.sshd-auth-history"] > by_id.get(
        "elastic.zeek-outbound-by-source", 0.0
    )
