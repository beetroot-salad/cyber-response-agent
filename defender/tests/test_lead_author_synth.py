"""Tests for lead_author.synthesize_drafts — the WARN-and-draft fix.

An executed query whose coined `{system}.{suffix}` id matches no catalog template must
be minted as a `{system}/_draft/{suffix}.md` skeleton (so the lead-author curates it)
rather than dropped. Ad-hoc leads (id with no `{system}.` prefix) and untagged calls
(id suffix == the row's recorded verb) are not catalog candidates and are skipped.

#620: re-pinned off the dead `params['arg0']` positional (the query tool never writes it)
onto the named-params row shape — the canonical record is the verb's declared body param
verbatim (an engine verb) or a structured `{verb, params}` call (a param-only verb), and
candidacy keys on the row's own recorded `verb`, not a hardcoded reserved-verb set.
"""
from __future__ import annotations

from pathlib import Path

from defender.learning.leads import lead_author


def _lead(
    query_id: str, params: dict | None = None, raw_command: str = "",
    system: str | None = None, verb: str = "get",
) -> lead_author.ExecutedLead:
    # The queries table records ``system`` + ``verb`` independently; default ``system`` to the
    # query_id's namespace (how record_query builds the id) so callers only set it explicitly
    # when exercising a system/id-prefix mismatch. ``verb`` is the honest registry verb the row
    # freezes; it defaults to a value that is NOT the id suffix (so the id reads as coined).
    if system is None:
        system = query_id.split(".", 1)[0] if "." in query_id else ""
    return lead_author.ExecutedLead(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, system=system, verb=verb, params=params or {},
        raw_command=raw_command, goal_text="probe the thing",
        what_to_summarize=(), raw_ref=Path("gather_raw/l-001/0.json"),
        payload_status="ok", payload_digest="2 bytes, 1 line(s)", error_class=None,
    )


def _catalog(tmp_path) -> Path:
    """Build an isolated tmp catalog and return its dir.

    Pass the returned dir as ``synthesize_drafts(..., catalog_dir=cat)``: that
    threads the read root through to ``load_catalog`` (it both reads the template
    index from and writes drafts under the same dir), so no module-global patch is
    needed to keep the call off the real on-disk catalog."""
    cat = tmp_path / "queries"
    (cat / "host-query").mkdir(parents=True)
    (cat / "host-query" / "proc-tree.md").write_text(
        "---\nid: host-query.proc-tree\nstatus: established\n---\n\n## Goal\nx\n"
    )
    return cat


def test_unresolved_verb_is_drafted(tmp_path):
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")], catalog_dir=cat)
    draft = cat / "stub-cmdb" / "_draft" / "network-map.md"
    assert created == [draft]
    text = draft.read_text()
    assert "id: stub-cmdb.network-map" in text
    assert "status: draft" in text


def test_resolved_verb_not_drafted(tmp_path):
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts([_lead("host-query.proc-tree")], catalog_dir=cat) == []


def test_adhoc_query_id_skipped(tmp_path):
    cat = _catalog(tmp_path)
    # `ad-hoc` has no `{system}.` prefix — not a catalog candidate.
    assert lead_author.synthesize_drafts([_lead("ad-hoc")], catalog_dir=cat) == []
    assert not (cat / "ad-hoc").exists()


def test_idempotent(tmp_path):
    cat = _catalog(tmp_path)
    first = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")], catalog_dir=cat)
    assert first
    second = lead_author.synthesize_drafts(
        [_lead("stub-cmdb.network-map", {"name": "web-1"}, verb="map")], catalog_dir=cat)
    assert second == []


# ---------------------------------------------------------------------------
# Canonical-record skeleton shape (#340 / #343 / #620 migration)
# ---------------------------------------------------------------------------

_ESQL_PIPE = (
    'FROM logs-system.auth-*\n'
    '| WHERE host.name == "db-1" AND event.outcome == "failure"\n'
    '| STATS failed = COUNT(*) BY source.ip'
)


def test_esql_draft_carries_literal_query_not_placeholder(tmp_path):
    """An elastic esql draft's ## Query is the exact pipe that ran (the verbatim `query` body
    param), engine-tagged — no KQL 'fill in the invocation' placeholder, no ## What to
    summarize."""
    cat = _catalog(tmp_path)
    lead_author.synthesize_drafts([
        _lead("elastic.sshd-failed-by-srcip", {"query": _ESQL_PIPE}, verb="esql",
              system="elastic"),
    ], catalog_dir=cat)
    text = (cat / "elastic" / "_draft" / "sshd-failed-by-srcip.md").read_text()
    assert "engine: esql" in text
    assert "```esql" in text
    assert "STATS failed = COUNT(*) BY source.ip" in text   # the literal pipe
    assert "Fill in the real" not in text                   # old placeholder gone
    assert "## What to summarize" not in text
    assert "## Pitfalls" in text


def test_executed_query_is_the_declared_body_or_structured_call(tmp_path):
    """_executed_query returns the verbatim declared body param for an engine verb (esql →
    `query`) and a structured `{verb, params}` call for a param-only verb — never raw_command,
    never a dead `params['arg0']` read."""
    lead = _lead("elastic.x", {"query": _ESQL_PIPE}, verb="esql", system="elastic")
    assert lead_author._executed_query(lead) == _ESQL_PIPE
    # A param-only verb → the structured call, carrying the verb + every bound param, never the
    # shlex audit string.
    param_lead = _lead("cmdb.host-lookup", {"host": "db-1"}, verb="get-host", system="cmdb",
                       raw_command="cmdb get-host host=db-1")
    record = lead_author._executed_query(param_lead)
    assert "get-host" in record
    assert "db-1" in record
    assert record != param_lead.raw_command


def test_executed_query_keys_on_recorded_verb_not_id_prefix(tmp_path):
    """The engine decision reads the queries-table `(system, verb)`, not the query_id prefix — a
    tagged query whose id namespace differs from the verb that actually ran is still classified
    by the real per-verb engine."""
    pipe = "FROM logs-system.auth-* | STATS c = COUNT(*)"
    # An esql verb (system=elastic) even though the tagged id namespace differs.
    el = _lead("custom.tagged", {"query": pipe}, verb="esql", system="elastic")
    assert lead_author._executed_query(el) == pipe
    # A param-only verb even though the id prefix says elastic → the structured call.
    non = _lead("elastic.weird", {"host": "10.0.0.5"}, verb="get-host", system="cmdb")
    record = lead_author._executed_query(non)
    assert "get-host" in record
    assert "10.0.0.5" in record


def test_malformed_query_id_does_not_mint_off_surface_draft(tmp_path):
    """A query_id with an empty system (`.verb`) or empty verb (`system.`) must
    not mint a draft off the `{system}/_draft/{kebab}` surface (the empty-system
    case would land at the catalog root `_draft/` and brick the post-flight)."""
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts([
        _lead(".verb", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
        _lead("elastic.", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], catalog_dir=cat)
    assert created == []
    assert not (cat / "_draft").exists()              # no catalog-root draft dir
    assert not (cat / "elastic" / "_draft" / ".md").exists()


def test_grok_braces_in_query_do_not_crash_skeleton(tmp_path):
    """A query body with ES|QL GROK braces (%{WORD:f}) must not break rendering."""
    cat = _catalog(tmp_path)
    grok_pipe = 'FROM logs-* | GROK message "%{IP:src} %{WORD:action}" | STATS c = COUNT(*) BY action'
    created = lead_author.synthesize_drafts([
        _lead("elastic.grok-probe", {"query": grok_pipe}, verb="esql", system="elastic"),
    ], catalog_dir=cat)
    assert created
    assert "%{IP:src}" in (cat / "elastic" / "_draft" / "grok-probe.md").read_text()


def test_traversal_query_id_does_not_escape_catalog(tmp_path):
    """A query_id whose segments contain `/`, `..`, or a backslash must not write
    a draft outside the `{system}/_draft/` surface. Defense-in-depth at the sink:
    record_query rejects these at the boundary, but synthesize_drafts holds the
    line on its own for any already-persisted/foreign row."""
    cat = _catalog(tmp_path)
    created = lead_author.synthesize_drafts([
        # `/` + `..` in the suffix → would resolve outside the catalog.
        _lead("elastic.../../../../PWNED", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
        # traversal in the system segment.
        _lead("../../etc.passwd", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], catalog_dir=cat)
    assert created == []
    # No file escaped the catalog (or landed anywhere under the temp tree).
    assert not (tmp_path / "PWNED.md").exists()
    assert list(tmp_path.rglob("PWNED.md")) == []


def test_untagged_verb_not_drafted(tmp_path):
    """A bare `{system}.{verb}` id whose suffix IS the recorded verb (no coined --query-id) is a
    non-candidate — an untagged call must not mint a junk catch-all draft."""
    cat = _catalog(tmp_path)
    assert lead_author.synthesize_drafts([
        _lead("elastic.esql", {"query": _ESQL_PIPE}, verb="esql", system="elastic"),
    ], catalog_dir=cat) == []
    assert not (cat / "elastic" / "_draft" / "esql.md").exists()
