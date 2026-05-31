"""Tests for lead_author.synthesize_drafts — the WARN-and-draft fix.

An executed query whose `{system}.{verb}` id matches no catalog template must
be minted as a `{system}/_draft/{verb}.md` skeleton (so the lead-author curates
it) rather than dropped. Ad-hoc leads (id with no `{system}.` prefix) are not
catalog candidates and are skipped.
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
