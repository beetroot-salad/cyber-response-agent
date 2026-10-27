"""investigation/workspace_map.py: the orchestrator-facing map carries no credential signal (#255) and does not name gather_raw (#264)."""
from __future__ import annotations

from pathlib import Path

from defender.tests.support.shared.contracts._by_path import DEFENDER, load_module

wm = load_module(DEFENDER / "investigation" / "workspace_map.py")


def test_no_credential_signal(tmp_path: Path):
    out = wm.workspace_map(tmp_path, systems=()).replace(str(tmp_path), "RUNDIR").lower()
    for token in (".env", "missing", "elastic_password", "elasticsearch_url",
                  "password", "credential", "watched_env", "source it"):
        assert token not in out, f"credential signal leaked into map: {token!r}"


def test_gather_raw_suppressed(tmp_path: Path):
    (tmp_path / "alert.json").write_text("{}")
    gr = tmp_path / "gather_raw"
    gr.mkdir()
    (gr / "l-001.lead.json").write_text("{}")
    out = wm.workspace_map(tmp_path, systems=()).replace(str(tmp_path), "RUNDIR")
    assert "alert.json" in out
    assert "gather_raw" not in out
