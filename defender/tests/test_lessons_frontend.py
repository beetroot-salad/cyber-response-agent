"""Lessons-frontend api layer (serialize.build_view) contract guarantees.

The view contract is what the self-contained HTML renders from, so these
tests pin the shape the template depends on rather than the exact lesson
counts (which grow as the loop authors). Counts are checked against the
live on-disk corpora so the serializer must enumerate exactly those files.
"""
from __future__ import annotations

import sys
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEFENDER / "learning" / "frontend"))

import serialize


CORPUS_DIR = {
    "defender": DEFENDER / "lessons",
    "actor": DEFENDER / "lessons-actor",
    "environment": DEFENDER / "lessons-environment",
}


def _on_disk(corpus: Path) -> set[str]:
    if not corpus.is_dir():
        return set()
    return {p.stem for p in corpus.glob("*.md") if not p.name.startswith("_")}


def test_build_view_is_pure():
    """build_view carries no timestamp — that lives in the CLI layer only."""
    assert "generated_at" not in serialize.build_view()


def test_three_groups_present():
    groups = serialize.build_view()["groups"]
    assert set(groups) == {"defender", "actor", "environment"}
    for g in groups.values():
        assert g["label"] and g["blurb"] and isinstance(g["fields"], list)
        assert g["fields"], "each group must declare metadata fields for the view"


def test_counts_match_on_disk():
    groups = serialize.build_view()["groups"]
    for name, corpus in CORPUS_DIR.items():
        assert len(groups[name]["lessons"]) == len(_on_disk(corpus)), name


def test_lesson_record_shape():
    groups = serialize.build_view()["groups"]
    for g in groups.values():
        for lesson in g["lessons"]:
            assert set(lesson) >= {
                "group", "title", "description", "status", "source_path", "metadata", "body",
            }
            assert lesson["title"]
            assert lesson["status"] in {"live", "stale"}
            assert isinstance(lesson["metadata"], dict)


def test_actor_lesson_field_mapping():
    """The known actor seed maps subject→title, relevance_criteria→description."""
    actor = serialize.build_view()["groups"]["actor"]["lessons"]
    seed = next(l for l in actor if l["title"] == "wazuh-rule-5712-threshold")
    assert seed["description"].startswith("defender uses Wazuh rule 5712")
    assert seed["metadata"]["alert_rule_ids"] == [5712]
    assert seed["body"]  # the lesson body is carried for the expander


def test_metadata_is_json_safe():
    """YAML-parsed dates etc. must serialize (defender lessons carry created_at)."""
    import json

    json.dumps(serialize.build_view())  # raises if any value is non-serializable
