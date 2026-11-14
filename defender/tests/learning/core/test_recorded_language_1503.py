"""#1503: a query's language is recorded when it runs, from the adapter's own declaration.

The learning loop's draft writer and lead author read it back off the row, so a tenant's own
adapter that speaks a query language is recorded like the product's, and no product table names
a vendor. Rows are box-writable: the reader keeps a recorded language only in the shape a
declaration can take, and a query-text param only when the call bound it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from defender.investigation.record_query import QUERY_ROW_COLUMNS
from defender.kit.verbs import VerbContext, verb
from defender.learning.lead_repository import load_queries
from defender.learning.leads.draft_synthesis import _draft_basename, synthesize_drafts
from defender.learning.leads.lead_extraction import ExecutedLead
from defender.records import RunPaths
from defender.tests.support.learning.curation._lead_author_1134 import drafts_under

LEAD = "l-001"


def _lead(*, engine: str, body_param: str | None, params: dict[str, Any]) -> ExecutedLead:
    return ExecutedLead(
        lead_id=LEAD, query_index=0, is_multi_query=False, entry_index=0,
        query_id="acme.failed-logins", system="acme", verb="search", params=params,
        raw_command="", goal_text="failed logins for the user", what_to_summarize=(),
        raw_ref=Path(f"gather_raw/{LEAD}/0.json"), payload_status="ok",
        payload_digest="2 bytes", error_class=None, engine=engine, body_param=body_param,
    )


def _draft(tmp_path: Path, lead: ExecutedLead) -> str:
    cat = tmp_path / "skills" / "gather" / "queries"
    (cat / "acme").mkdir(parents=True)
    created = synthesize_drafts(
        [lead], **drafts_under(cat), catalog=[], systems=frozenset({"acme"}))
    assert created == [cat / "acme" / "_draft" / f"{_draft_basename('acme.failed-logins')}.md"]
    return created[0].read_text()


# --- the writer's columns -----------------------------------------------------------------------

def test_the_row_carries_the_language_and_its_query_param():
    assert QUERY_ROW_COLUMNS[-2:] == ("engine", "body_param")


def test_the_writer_records_what_the_adapter_declares():
    from defender.investigation.record_query import declared_language

    @verb(engine="spl", body_param="search")
    def language(ctx: VerbContext, *, search: str) -> None: ...

    @verb()
    def plain(ctx: VerbContext, *, user: str) -> None: ...

    assert declared_language(language) == ("spl", "search")
    assert declared_language(plain) == ("none", None)
    assert declared_language(None) == ("none", None)


@pytest.mark.parametrize(("engine", "body_param"), [
    # Not a name the reader keeps: it would be recorded as a plain call.
    ("ES|QL", "search"),
    # A language with nowhere for its text.
    ("spl", None),
    # A body param the signature does not declare.
    ("spl", "query"),
], ids=["off-shape-engine", "no-body-param", "undeclared-body-param"])
def test_a_language_declaration_the_row_could_not_record_is_refused(engine, body_param):
    """Refused where the adapter is written, so a declared language is never recorded as
    nothing and its query learned as a plain call (#1503)."""
    with pytest.raises(ValueError, match="engine"):
        @verb(engine=engine, body_param=body_param)
        def fn(ctx: VerbContext, *, search: str) -> None: ...


def test_the_writer_drops_a_mark_set_around_the_decorator():
    """Defence in depth: a function carrying an off-shape mark by hand records a plain call."""
    from defender.investigation.record_query import declared_language

    def fn(ctx: VerbContext, *, query: str) -> None: ...

    fn.__verb_engine__ = "ES|QL"  # type: ignore[attr-defined]
    fn.__verb_body_param__ = "query"  # type: ignore[attr-defined]
    assert declared_language(fn) == ("none", None)


def test_the_executed_record_carries_the_rows_language(tmp_path):
    from defender.learning.lead_repository import JoinedLead
    from defender.learning.leads.lead_extraction import extract_from_joined

    payload = tmp_path / "run" / "gather_raw" / LEAD / "0.json"
    payload.parent.mkdir(parents=True)
    payload.write_text("{}")
    read = _read(tmp_path, _row())
    assert read.raw_ref == payload
    [lead] = extract_from_joined([JoinedLead(
        lead_id=LEAD, goal="g", what_to_summarize=[], queries=[read])])
    assert (lead.engine, lead.body_param) == ("spl", "search")


# --- the draft writer reads the row's language, for any system ------------------------------------

def test_a_tenant_adapters_language_query_is_recorded_as_its_text(tmp_path):
    text = _draft(tmp_path, _lead(
        engine="spl", body_param="search",
        params={"search": "index=auth action=failure user=alice", "earliest": "-24h"}))
    assert "```spl\nindex=auth action=failure user=alice\n```" in text
    assert "engine: spl" in text
    # The query text became the recording, so it is not a fill-in param; the other one is.
    front = yaml.safe_load(text.split("---")[1])
    assert front["params"] == ["earliest"]


def test_a_plain_call_is_recorded_as_the_call(tmp_path):
    text = _draft(tmp_path, _lead(
        engine="none", body_param=None, params={"search": "index=auth"}))
    assert "verb: search" in text
    assert "engine:" not in text


# --- the reader: what a row may claim ----------------------------------------------------------

def _row(**overrides: Any) -> dict:
    row = {
        "lead_id": LEAD, "seq": 0, "system": "acme", "verb": "search",
        "query_id": "acme.ad-hoc", "params": {"search": "index=auth"},
        "raw_command": "acme search", "payload_path": f"gather_raw/{LEAD}/0.json",
        "exit_code": 0, "error_class": None, "payload_status": "ok",
        "payload_digest": "2 bytes", "payload_sha256": "", "system_key": "",
        "received_at": "", "engine": "spl", "body_param": "search",
    }
    row.update(overrides)
    return row


def _read(tmp_path: Path, row: dict):
    run = tmp_path / "run"
    paths = RunPaths(run)
    paths.executed_queries.parent.mkdir(parents=True, exist_ok=True)
    paths.executed_queries.write_text(json.dumps(row) + "\n")
    [read] = load_queries(run)
    return read


def test_the_reader_keeps_a_declared_language(tmp_path):
    read = _read(tmp_path, _row())
    assert (read.engine, read.body_param) == ("spl", "search")


@pytest.mark.parametrize("overrides", [
    # A table written before the columns existed.
    {"engine": None, "body_param": None},
    # Not a name a declaration could carry (it lands in a fence and in front matter).
    {"engine": "spl\n## Goal"},
    {"engine": ["spl"]},
    # A query param the call never bound.
    {"body_param": "query"},
    {"body_param": 7},
], ids=["absent", "not-a-name", "not-a-string", "unbound-param", "param-not-a-string"])
def test_the_reader_drops_what_a_declaration_could_not_say(tmp_path, overrides):
    row = _row(**overrides)
    for key in [k for k, v in overrides.items() if v is None]:
        del row[key]
    read = _read(tmp_path, row)
    assert (read.engine, read.body_param) == ("none", None)


# --- the query tool records the adapter's declaration ------------------------------------------

def test_the_query_tool_records_the_adapters_declaration(tmp_path):
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e._replay_harness import VerbRecorder
    from defender.tests.support.learning.curation._verb_authorization_632 import (
        DONE, PAYLOAD, ScopedFakeVerbs, grant_of, q, run_gather,
    )

    rec = VerbRecorder()

    @verb(engine="spl", body_param="search")
    def search(ctx: VerbContext, *, search: str) -> Any:
        rec.record("search", ctx, {"search": search})
        return PAYLOAD

    def lookup(ctx: VerbContext, *, user: str) -> Any:
        rec.record("lookup", ctx, {"user": user})
        return PAYLOAD

    registry = ScopedFakeVerbs(
        {"elastic": {"search": search, "lookup": lookup}},
        grant_of("gather", (("elastic", "search"), ("elastic", "lookup"))))
    r = run_gather(tmp_path, verbs=registry, run_id="lang1503", turns=[
        q("elastic", "search", {"search": "index=auth"}),
        q("elastic", "lookup", {"user": "alice"}),
        DONE,
    ])
    by_verb = {row["verb"]: row for row in r.own_evidence}
    assert (by_verb["search"]["engine"], by_verb["search"]["body_param"]) == ("spl", "search")
    assert (by_verb["lookup"]["engine"], by_verb["lookup"]["body_param"]) == ("none", None)
