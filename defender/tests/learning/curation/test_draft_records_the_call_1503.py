"""#1503: a draft records the call as it was made, its tool and every param.

No product table says which param of which system's tool carries a query language's text, and
the draft writer reads no adapter. So an ES|QL call is recorded like any other call: its verb
and params, the query text one param value among them. The learning model lifts the text into
the template's `## Query` when it promotes the draft (owner, #1503).
"""
from __future__ import annotations

from pathlib import Path

import yaml

from defender.learning.leads.draft_synthesis import (
    _draft_basename, _executed_query, synthesize_drafts,
)
from defender.learning.leads.lead_extraction import ExecutedLead
from defender.tests.support.learning.curation._lead_author_1134 import drafts_under

PIPE = "FROM logs-* | WHERE user.name == \"alice\" | STATS c = COUNT(*)"


def _lead(system: str, verb: str, params: dict) -> ExecutedLead:
    return ExecutedLead(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id=f"{system}.failed-logins", system=system, verb=verb, params=params,
        raw_command="", goal_text="failed logins for alice", what_to_summarize=(),
        raw_ref=Path("gather_raw/l-001/0.json"), payload_status="ok",
        payload_digest="2 bytes", error_class=None,
    )


def _draft(tmp_path: Path, lead: ExecutedLead) -> tuple[dict, str]:
    cat = tmp_path / "skills" / "gather" / "queries"
    (cat / lead.system).mkdir(parents=True)
    [draft] = synthesize_drafts(
        [lead], **drafts_under(cat), catalog=[], systems=frozenset({lead.system}))
    assert draft == cat / lead.system / "_draft" / f"{_draft_basename(lead.query_id)}.md"
    text = draft.read_text()
    return yaml.safe_load(text.split("---")[1]), text


def test_a_query_language_call_is_recorded_as_its_call(tmp_path):
    lead = _lead("elastic", "esql", {"query": PIPE, "limit": 10})
    front, text = _draft(tmp_path, lead)
    assert yaml.safe_load(_executed_query(lead)) == {
        "verb": "esql", "params": {"query": PIPE, "limit": 10}}
    assert front["params"] == ["limit", "query"]
    assert "engine" not in front
    assert "```query\n" in text
    assert PIPE in text


def test_every_system_is_recorded_the_same_way(tmp_path):
    """The draft writer names no system: a tenant's own adapter records like the product's."""
    elastic = _executed_query(_lead("elastic", "esql", {"query": PIPE}))
    tenants = _executed_query(_lead("acme-siem", "esql", {"query": PIPE}))
    assert elastic == tenants


def test_a_long_query_text_is_not_wrapped():
    """The learning model lifts the text out of the params: a line wrap would split the pipe."""
    long_pipe = "FROM logs-* | " + " | ".join(f"EVAL f{i} = field_{i}" for i in range(20))
    record = _executed_query(_lead("elastic", "esql", {"query": long_pipe}))
    assert long_pipe in record.splitlines()[-1]
