"""Top-k neighbor scorer — tokenizer units, catalog loading and the query-variant extractor."""
from __future__ import annotations

import pytest

from defender.learning.leads import lead_neighbors as ln  # type: ignore[import-not-found]




def test_tokenize_query_drops_pure_numeric_and_plumbing():
    toks = ln.tokenize_query(
        "python3 wazuh_adapter.py --query 'rule.id:5710' --window 1h"
    )
    assert "5710" not in toks
    assert "window" not in toks
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
    assert "logs" not in toks
    assert "count" in toks




@pytest.fixture(scope="module")
def catalog():
    cat = ln.load_catalog()
    if not cat:
        pytest.skip("catalog not present in this checkout")
    return cat


def test_unresolved_query_id_raises(catalog):
    """Caller must filter unresolvable ids; an unfiltered call is a hard error."""
    with pytest.raises(KeyError):
        ln.top_k_neighbors("nonexistent.lookup", catalog, k=3)




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
    assert by_id["wazuh.novel-thing"].system == "wazuh"


def test_load_catalog_does_not_promote_a_missing_status_to_established(tmp_path):
    """A template with no `status:` field is NOT established — its status is unknown.

    This test pinned the opposite until #585: `load_catalog` resolved the field with
    `fm.get("status") or "established"`, an `or` mis-fire on a valid-falsy value (the shape
    `defender/CLAUDE.md`'s anchor-a-default rule bans). That default was survivable while the walk
    only ran in an offline drain. The fold puts it on the gather dispatch's hot path and feeds it
    to the injected template index, where it becomes a promotion: a `draft_synthesis` skeleton that
    lost its frontmatter key — a body auto-drafted from attacker-influenced alert data — would be
    served to gather as a curated, established template. The template is still WALKED (the row is
    not dropped); it is the established/draft split that fails closed, so the index's positive
    `status == "established"` filter simply does not admit it.
    """
    catalog_dir = tmp_path / "queries"
    (catalog_dir / "wazuh").mkdir(parents=True)
    (catalog_dir / "wazuh" / "x.md").write_text(
        "---\nid: wazuh.x\n---\n\n## Goal\n\nx\n\n## Query\n\n```\nq\n```\n"
    )
    cat = ln.load_catalog(catalog_dir)
    assert len(cat) == 1
    assert cat[0].status != "established"




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
    assert "user.name" in toks
    assert "source.ip" in toks
    assert "event.outcome" in toks
    assert "zzzproseword" not in toks
    assert "otherprosenarrowing" not in toks
