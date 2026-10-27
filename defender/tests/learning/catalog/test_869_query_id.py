"""#869 M3/O2/U3 — the queries-table row names the system the call was dispatched to."""
from __future__ import annotations

from defender.learning.leads.draft_synthesis import (
    _draft_basename,
    _draft_candidate_segments,
)
from defender.investigation.query_tool import resolve_query_id


def test_resolve_query_id_refuses_a_foreign_prefix():
    assert resolve_query_id("elastic", "esql", "fakesys.hunt-creds") == "elastic.esql"
    # The two shapes that are already refused, so the new rule joins a screen rather than
    # replacing one: a reserved sentinel prefix and a traversal-bearing id.
    assert resolve_query_id("elastic", "esql", "∅.bash-shim") == "elastic.esql"
    assert resolve_query_id("elastic", "esql", "../x") == "elastic.esql"


def test_resolve_query_id_keeps_a_matching_prefix():
    assert resolve_query_id("elastic", "esql", "elastic.hunt-creds") == "elastic.hunt-creds"
    assert resolve_query_id("cmdb", "get-host", "cmdb.crown-jewels") == "cmdb.crown-jewels"


def test_resolve_query_id_enforces_the_whole_schema_shape():
    assert resolve_query_id("elastic", "esql", "elastic") == "elastic.esql"
    assert resolve_query_id("elastic", "esql", "elastic.") == "elastic.esql"
    assert resolve_query_id("elastic", "esql", "elastic.foo.bar") == "elastic.esql"

    system, basename = _draft_candidate_segments(
        "elastic.foo.bar", "esql", set(), row_system="elastic")
    assert system == "elastic"
    assert basename == _draft_basename("elastic.foo.bar")
    assert "foo" not in basename
    assert "." not in basename
    assert _draft_candidate_segments(
        resolve_query_id("elastic", "esql", "elastic.foo.bar"), "esql", set(),
        row_system="elastic",
    ) is None

    # The control on the same address: a well-formed coined id still survives.
    assert resolve_query_id("elastic", "esql", "elastic.hunt-creds") == "elastic.hunt-creds"
