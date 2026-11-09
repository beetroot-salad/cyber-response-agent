"""#1347 A5/A6: `esql_text.sources(query)` is the one reader of what an ES|QL query reads (verb and lab
guard): index expressions, `[]` if none, `None` if unreadable so callers fail closed."""
from __future__ import annotations

import pytest

from defender.integrations import esql_text


@pytest.mark.parametrize(("query", "expected"), [
    pytest.param("FROM logs-* | LIMIT 1", ["logs-*"], id="from"),
    pytest.param("from logs-* | limit 1", ["logs-*"], id="lowercase"),
    pytest.param("FROM logs-*|LIMIT 1", ["logs-*"], id="no-space-before-the-separator"),
    pytest.param("FROM logs-a,logs-b", ["logs-a", "logs-b"], id="list"),
    pytest.param("FROM logs-a ,\t logs-b\n, alerts-*", ["logs-a", "logs-b", "alerts-*"], id="list-spaced"),
    pytest.param('FROM "logs-a", "alerts-*" | LIMIT 1', ["logs-a", "alerts-*"], id="quoted"),
    pytest.param("FROM logs-* METADATA _id, _index | LIMIT 1", ["logs-*"], id="metadata-is-not-a-source"),
    pytest.param("FROM\n  logs-*\n| LIMIT 1", ["logs-*"], id="source-on-the-next-line"),
    pytest.param("TS metrics-* | LIMIT 1", ["metrics-*"], id="ts"),
    pytest.param("FROM logs-* | LOOKUP JOIN hosts ON host.name", ["logs-*", "hosts"], id="lookup-join"),
    pytest.param("from logs-*\n| keep a\n| lookup   join hosts on a | lookup join owners on b",
                 ["logs-*", "hosts", "owners"], id="lookup-joins-lowercase-and-spaced"),
    pytest.param('FROM logs-* | WHERE m RLIKE "a|FROM .security-7" | LIMIT 1', ["logs-*"],
                 id="a-string-literal-is-data"),
    pytest.param('FROM logs-* | WHERE m == "LOOKUP JOIN .security-7"', ["logs-*"],
                 id="a-string-literal-holding-a-join-is-data"),
    pytest.param("ROW a = 1 | EVAL b = a + 1", [], id="row-reads-nothing"),
    pytest.param("SHOW INFO", [], id="show-reads-nothing"),
])
def test_sources_lists_every_index_expression_the_query_reads(query, expected):
    """A5/A6: FROM, TS and LOOKUP JOIN name sources (quotes and METADATA dropped, string literals
    ignored); ROW and SHOW read none."""
    assert esql_text.sources(query) == expected


@pytest.mark.parametrize("query", [
    pytest.param("", id="empty"),
    pytest.param("   ", id="blank"),
    pytest.param("FROM", id="from-without-a-source"),
    pytest.param("FROM | LIMIT 1", id="from-with-an-empty-source"),
    pytest.param("FROM logs-a,, logs-b", id="empty-source-in-a-list"),
    pytest.param("LIMIT 1", id="no-source-command"),
    pytest.param("SELECT * FROM logs-*", id="not-esql"),
    pytest.param("FROM logs-* | LOOKUP JOIN", id="join-without-an-index"),
    pytest.param("FROM logs-* | FORK (WHERE a > 1) (WHERE a < 1)", id="fork"),
    pytest.param("FROM (FROM logs-*) | LIMIT 1", id="subquery"),
    pytest.param("FROM logs-a, (FROM logs-b) | LIMIT 1", id="subquery-beside-a-source"),
    pytest.param("FROM logs-* | ENRICH hosts ON host.name", id="enrich"),
    pytest.param("FROM remote:logs-* | LIMIT 1", id="remote-cluster"),
    pytest.param("FROM *:logs-* | LIMIT 1", id="every-remote-cluster"),
    pytest.param("FROM logs-*, remote:logs-* | LIMIT 1", id="remote-among-sources"),
])
def test_sources_is_none_when_the_query_cannot_be_read_with_confidence(query):
    """A5/A6: unparsable text, a subquery, FORK, ENRICH and a remote `cluster:index` are `None`
    (not an empty list, which means "reads no index"), so every caller fails closed."""
    assert esql_text.sources(query) is None


@pytest.mark.parametrize("query", [
    pytest.param("FROM logs-*, /* x */ .security-7", id="comment-between-sources"),
    pytest.param("FROM logs-* | LOOKUP JOIN /* x */ .security-7 ON a", id="comment-before-a-join-index"),
    pytest.param("FROM logs-*\n// x\n, .security-7", id="line-comment-between-sources"),
    pytest.param("FROM logs-*,\n.security-7", id="source-on-the-next-line"),
    pytest.param("FROM logs-*,\t.security-7", id="tab"),
    pytest.param("FrOm logs-*, .security-7", id="mixed-case"),
    pytest.param("FROM logs-* METADATA _id | LOOKUP JOIN\n .security-7 ON a", id="join-index-on-the-next-line"),
    pytest.param('FROM logs-*, ".security-7"', id="quoted"),
    pytest.param("FROM logs-*|LOOKUP JOIN .security-7 ON a", id="no-space-before-the-separator"),
    pytest.param("ROW a = 1 | LOOKUP JOIN .security-7 ON a", id="join-after-a-row"),
    pytest.param("FROM logs-* | EVAL a = 1 | LOOKUP JOIN .security-7 ON a | LIMIT 1", id="join-after-other-commands"),
])
def test_a_source_is_never_hidden_from_the_reader(query):
    """A5/A6: however the text is spelled, a query that reads `.security-7` is read as naming it
    or as unreadable (`None`), never as reading only what is around it."""
    got = esql_text.sources(query)

    assert got is None or any(".security-7" in s for s in got), got
