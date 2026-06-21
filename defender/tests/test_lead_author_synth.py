"""Tests for lead_author.synthesize_drafts — the WARN-and-draft fix.

An executed query whose `{system}.{verb}` id matches no catalog template must
be minted as a `{system}/_draft/{verb}.md` skeleton (so the lead-author curates
it) rather than dropped. Ad-hoc leads (id with no `{system}.` prefix) are not
catalog candidates and are skipped.
"""
from __future__ import annotations

from pathlib import Path

from defender.learning import lead_author
from defender.learning import lead_neighbors


def _lead(
    query_id: str, params: dict | None = None, raw_command: str = "",
) -> "lead_author.ExecutedLead":
    return lead_author.ExecutedLead(
        lead_id="l-001", query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, params=params or {}, raw_command=raw_command,
        goal_text="probe the thing",
        what_to_summarize=(), raw_ref=Path("gather_raw/l-001/0.json"),
        payload_status="ok", payload_digest="2 bytes, 1 line(s)",
    )


def _catalog(tmp_path, monkeypatch) -> Path:
    cat = tmp_path / "queries"
    (cat / "host-query").mkdir(parents=True)
    (cat / "host-query" / "proc-tree.md").write_text(
        "---\nid: host-query.proc-tree\nstatus: established\n---\n\n## Goal\nx\n"
    )
    monkeypatch.setattr(lead_neighbors, "CATALOG_ROOT", cat)
    # synthesize_drafts calls load_catalog() through lead_author's own
    # lead_neighbors reference, which may be a distinct module object from the
    # one imported here — patch that one too so the catalog redirect actually
    # takes (otherwise load_catalog reads the real on-disk catalog).
    monkeypatch.setattr(lead_author.lead_neighbors, "CATALOG_ROOT", cat)
    monkeypatch.setattr(lead_author, "CATALOG_DIR", cat)
    return cat


def test_unresolved_verb_is_drafted(tmp_path, monkeypatch):
    cat = _catalog(tmp_path, monkeypatch)
    created = lead_author.synthesize_drafts([_lead("stub-cmdb.network-map", {"name": "web-1"})])
    draft = cat / "stub-cmdb" / "_draft" / "network-map.md"
    assert created == [draft]
    text = draft.read_text()
    assert "id: stub-cmdb.network-map" in text
    assert "status: draft" in text


def test_resolved_verb_not_drafted(tmp_path, monkeypatch):
    _catalog(tmp_path, monkeypatch)
    assert lead_author.synthesize_drafts([_lead("host-query.proc-tree")]) == []


def test_adhoc_query_id_skipped(tmp_path, monkeypatch):
    cat = _catalog(tmp_path, monkeypatch)
    # `ad-hoc` has no `{system}.` prefix — not a catalog candidate.
    assert lead_author.synthesize_drafts([_lead("ad-hoc")]) == []
    assert not (cat / "ad-hoc").exists()


def test_idempotent(tmp_path, monkeypatch):
    _catalog(tmp_path, monkeypatch)
    first = lead_author.synthesize_drafts([_lead("stub-cmdb.network-map", {"name": "web-1"})])
    assert first
    second = lead_author.synthesize_drafts([_lead("stub-cmdb.network-map", {"name": "web-1"})])
    assert second == []


# ---------------------------------------------------------------------------
# Lean / ES|QL skeleton shape (#340 / #343 migration)
# ---------------------------------------------------------------------------

_ESQL_PIPE = (
    'FROM logs-system.auth-*\n'
    '| WHERE host.name == "db-1" AND event.outcome == "failure"\n'
    '| STATS failed = COUNT(*) BY source.ip'
)


def test_esql_draft_carries_literal_query_not_placeholder(tmp_path, monkeypatch):
    """An elastic draft's ## Query is the exact pipe that ran, engine-tagged —
    no KQL 'fill in the invocation' placeholder, no ## What to summarize."""
    cat = _catalog(tmp_path, monkeypatch)
    lead_author.synthesize_drafts([
        _lead("elastic.sshd-failed-by-srcip", {"arg0": _ESQL_PIPE},
              raw_command=f"esql {_ESQL_PIPE!r}"),
    ])
    text = (cat / "elastic" / "_draft" / "sshd-failed-by-srcip.md").read_text()
    assert "engine: esql" in text
    assert "```esql" in text
    assert "STATS failed = COUNT(*) BY source.ip" in text   # the literal pipe
    assert "Fill in the real" not in text                   # old placeholder gone
    assert "## What to summarize" not in text
    assert "## Pitfalls" in text


def test_arg0_preferred_over_raw_command_for_query_body(tmp_path, monkeypatch):
    """_executed_query prefers the bare pipe (arg0) to the full shim invocation
    for elastic (where arg0 IS the ES|QL query), but uses raw_command for other
    systems (where arg0 is a bare positional value, not the query)."""
    lead = _lead("elastic.x", {"arg0": _ESQL_PIPE}, raw_command=f"esql {_ESQL_PIPE!r}")
    assert lead_author._executed_query(lead) == _ESQL_PIPE
    # No arg0 (flag-shaped adapter) → fall back to raw_command.
    flag_lead = _lead("cmdb.host-lookup", {"host": "db-1"}, raw_command="host-lookup --host db-1")
    assert lead_author._executed_query(flag_lead) == "host-lookup --host db-1"
    # Positional NON-elastic adapter (cmdb.hostname-by-ip ${ip}): arg0 is the bare
    # value '10.0.0.5', not a query — the canonical record is the full raw_command.
    pos_lead = _lead("cmdb.hostname-by-ip", {"arg0": "10.0.0.5"},
                     raw_command="hostname-by-ip 10.0.0.5")
    assert lead_author._executed_query(pos_lead) == "hostname-by-ip 10.0.0.5"


def test_malformed_query_id_does_not_mint_off_surface_draft(tmp_path, monkeypatch):
    """A query_id with an empty system (`.verb`) or empty verb (`system.`) must
    not mint a draft off the `{system}/_draft/{kebab}` surface (the empty-system
    case would land at the catalog root `_draft/` and brick the post-flight)."""
    cat = _catalog(tmp_path, monkeypatch)
    created = lead_author.synthesize_drafts([
        _lead(".verb", {"arg0": _ESQL_PIPE}, raw_command=f"esql {_ESQL_PIPE!r}"),
        _lead("elastic.", {"arg0": _ESQL_PIPE}, raw_command=f"esql {_ESQL_PIPE!r}"),
    ])
    assert created == []
    assert not (cat / "_draft").exists()              # no catalog-root draft dir
    assert not (cat / "elastic" / "_draft" / ".md").exists()


def test_grok_braces_in_query_do_not_crash_skeleton(tmp_path, monkeypatch):
    """A query body with ES|QL GROK braces (%{WORD:f}) must not break rendering."""
    cat = _catalog(tmp_path, monkeypatch)
    grok_pipe = 'FROM logs-* | GROK message "%{IP:src} %{WORD:action}" | STATS c = COUNT(*) BY action'
    created = lead_author.synthesize_drafts([
        _lead("elastic.grok-probe", {"arg0": grok_pipe}, raw_command=f"esql {grok_pipe!r}"),
    ])
    assert created
    assert "%{IP:src}" in (cat / "elastic" / "_draft" / "grok-probe.md").read_text()


def test_untagged_esql_verb_not_drafted(tmp_path, monkeypatch):
    """A bare `{system}.esql` id (no --query-id tag) is a non-candidate — an
    untagged ES|QL call must not mint a junk catch-all draft."""
    cat = _catalog(tmp_path, monkeypatch)
    assert lead_author.synthesize_drafts([
        _lead("elastic.esql", {"arg0": _ESQL_PIPE}, raw_command=f"esql {_ESQL_PIPE!r}"),
    ]) == []
    assert not (cat / "elastic" / "_draft" / "esql.md").exists()
