"""Tests for lead_author.synthesize_drafts — the WARN-and-draft fix.

An executed CLI verb that matches no catalog template must be minted as a
`{system}/_draft/{verb}.md` skeleton (so the lead-author curates it) rather
than dropped. Pins the cmdb.get-host bug fix.
"""
from __future__ import annotations

from pathlib import Path

import lead_author
import lead_neighbors


def _lead(query_id: str, params: dict | None = None) -> "lead_author.ExecutedLead":
    return lead_author.ExecutedLead(
        position=0, query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, params=params or {}, goal_text="probe the thing",
        what_to_summarize=(), result_ref=Path("x.json"), sidecar_path=Path("x.observations.json"),
    )


def _catalog(tmp_path, monkeypatch) -> Path:
    cat = tmp_path / "queries"
    (cat / "host-state").mkdir(parents=True)
    (cat / "host-state" / "container-identity-and-uid.md").write_text(
        "---\nid: host-state.container-identity-and-uid\nstatus: established\n---\n\n## Goal\nx\n"
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
    created = lead_author.synthesize_drafts([_lead("cmdb.get-host", {"name": "web-1"})])
    draft = cat / "cmdb" / "_draft" / "get-host.md"
    assert created == [draft]
    text = draft.read_text()
    assert "id: cmdb.get-host" in text
    assert "status: draft" in text


def test_resolved_verb_not_drafted(tmp_path, monkeypatch):
    _catalog(tmp_path, monkeypatch)
    assert lead_author.synthesize_drafts([_lead("host-state.container-identity-and-uid")]) == []


def test_query_body_verb_skipped(tmp_path, monkeypatch):
    cat = _catalog(tmp_path, monkeypatch)
    assert lead_author.synthesize_drafts([_lead("elastic.query")]) == []
    assert not (cat / "elastic" / "_draft" / "query.md").exists()


def test_idempotent(tmp_path, monkeypatch):
    _catalog(tmp_path, monkeypatch)
    first = lead_author.synthesize_drafts([_lead("cmdb.get-host", {"name": "web-1"})])
    assert first
    second = lead_author.synthesize_drafts([_lead("cmdb.get-host", {"name": "web-1"})])
    assert second == []
