"""Lessons-frontend api layer (serialize.build_view) contract guarantees.

#1108 P4 (O1, O-U5, design "Data model and ownership"): the posture page reads a tenant's
knowledge from an export, through `KnowledgePaths(agent_root)` — never the product tree, which
holds no tenant knowledge after P4. The reader is pointed at an agent root (assumed seam:
`build_view(agent_root=...)`, replacing today's `defender_dir=` / `of_defender_dir`). The retired
corpora `lessons-actor`/`lessons-environment` are deleted (U5), so the page has no group for them.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.frontend import serialize  # noqa: E402
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

#: The groups the posture page shows after U5: the defender's corpus and the questioner's.
LIVE_GROUPS = {"defender", "questioner"}

#: The committed fixture tenant's lessons (`knowledge/tenant-fixture/agent/`), by group.
FIXTURE_TITLES = {
    "defender": {"fixture-change-window-is-not-approval", "fixture-owner-before-close"},
    "questioner": {"fixture-questioner-seed"},
}


@pytest.fixture
def export_agent(tmp_path: Path, data_root: Path) -> Path:
    """The fixture tenant's `agent/` inside a real export (O11's one helper: git-init the
    fixture tenant, publish for real) — the root the frontend reads after P4."""
    with published_tenant(tmp_path / "forge", root=data_root) as tenant:
        yield tenant.export.path / "agent"


def test_o_u5_the_posture_page_has_only_the_live_groups(export_agent: Path):
    """O-U5: the posture page names no retired corpus — its groups are exactly the defender's and
    the questioner's, each with a label, blurb and declared metadata fields."""
    groups = serialize.build_view(agent_root=export_agent)["groups"]
    assert set(groups) == LIVE_GROUPS
    for g in groups.values():
        assert g["label"]
        assert g["blurb"]
        assert isinstance(g["fields"], list)
        assert g["fields"], "each group must declare metadata fields for the view"


def test_o1_the_page_shows_the_exports_lessons_not_the_product_trees(export_agent: Path):
    """O1/P-1: built from an export, the page shows exactly that export's lessons — the made-up
    fixture's — in the record shape the page renders."""
    groups = serialize.build_view(agent_root=export_agent)["groups"]
    assert {name: {rec["title"] for rec in g["lessons"]} for name, g in groups.items()} \
        == FIXTURE_TITLES
    for g in groups.values():
        for lesson in g["lessons"]:
            assert set(lesson) >= {
                "group", "title", "description", "status", "source_path", "metadata", "body",
            }
            assert lesson["title"]
            assert lesson["status"] in {"live", "stale", "malformed"}
            assert isinstance(lesson["metadata"], dict)


def test_skipped_lesson_gets_a_degraded_record(tmp_path):
    import json

    agent = tmp_path / "agent"
    for spec in serialize.GROUPS.values():
        (agent / spec["dir"]).mkdir(parents=True)
    (agent / "lessons" / "good.md").write_text("---\nname: good\ndescription: d\n---\nbody\n")
    (agent / "lessons" / "broken.md").write_text("---\ndescription: [unclosed\n---\nbody\n")
    (agent / "lessons" / "_draft.md").write_text("not a lesson\n")

    lessons = serialize.build_view(agent_root=agent)["groups"]["defender"]["lessons"]

    assert [rec["title"] for rec in lessons] == ["broken", "good"]
    broken = lessons[0]
    assert broken["status"] == "malformed"
    assert "frontmatter unavailable" in broken["description"]
    assert broken["metadata"] == {}
    assert broken["body"] == ""
    # The spelling is relative to the tenant repo, never the product tree's `defender/...`; the
    # exact prefix (`agent/`) is the agent root's own spelling, which r3 does not fix.
    assert broken["source_path"].endswith("lessons/broken.md")
    assert not broken["source_path"].startswith(("defender/", "/"))
    json.dumps(lessons)


def test_metadata_is_json_safe(export_agent: Path):
    """YAML-parsed dates etc. must serialize (lessons carry created_at)."""
    import json

    json.dumps(serialize.build_view(agent_root=export_agent))


def test_json_safe_coerces_exotic_types():
    """_json_safe must neutralize non-JSON YAML scalars so a build can't crash
    on an exotic frontmatter value (a !!set, a bare time, ...)."""
    import datetime
    import json

    out = serialize._json_safe({
        "s": {"b", "a"},
        "t": datetime.time(9, 30),
        "d": datetime.date(2026, 6, 2),
    })
    assert out["s"] == ["a", "b"]
    assert out["d"] == "2026-06-02"
    assert isinstance(out["t"], str)
    json.dumps(out)
