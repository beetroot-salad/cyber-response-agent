"""Lessons-frontend api layer (serialize.build_view) contract guarantees.

The view contract is what the self-contained HTML renders from, so these
tests pin the shape the template depends on rather than the exact lesson
counts (which grow as the loop authors). Counts are checked against the
live on-disk corpora so the serializer must enumerate exactly those files.
"""
from __future__ import annotations

from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[1]

from defender._corpus import iter_lesson_paths  # noqa: E402
from defender.learning.frontend import serialize  # noqa: E402


CORPUS_DIR = {
    "defender": DEFENDER / "lessons",
    "actor": DEFENDER / "lessons-actor",
    "environment": DEFENDER / "lessons-environment",
}


def _on_disk(corpus: Path) -> set[str]:
    """Stems the serializer enumerates: every DISCOVERED lesson — non-underscore ``*.md``.

    UPDATED by #590's rule (review of PR #608): the serializer no longer omits a lesson whose
    frontmatter fails to parse — a warn-skipped lesson gets a degraded marker record instead of
    vanishing from the posture view. The oracle is therefore the DISCOVERY rule
    (``iter_lesson_paths``), not the walk's parse-success subset. Deliberately NOT rebuilt on
    ``build_view``'s own output: an oracle derived from the thing it checks is a tautology."""
    return {path.stem for path in iter_lesson_paths(corpus)}


def test_build_view_is_pure():
    """build_view carries no timestamp — that lives in the CLI layer only."""
    assert "generated_at" not in serialize.build_view()


def test_three_groups_present():
    groups = serialize.build_view()["groups"]
    assert set(groups) == {"defender", "actor", "environment"}
    for g in groups.values():
        assert g["label"]
        assert g["blurb"]
        assert isinstance(g["fields"], list)
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
            assert lesson["status"] in {"live", "stale", "malformed"}
            assert isinstance(lesson["metadata"], dict)


def test_environment_seed_field_mapping():
    """Env-fact seeds surface through build_view with the field mapping the
    template depends on: subject→title, relevance_criteria→description, and the
    body carried for the expander. Validated against the live env corpus
    generically — no single seed is load-bearing, so the test survives the
    corpus churning as the loop authors and prunes env facts (issue #298 moved
    these seeds from the actor corpus to the shared environment corpus). The
    subject→title / relevance_criteria→description direction is pinned by
    test_environment_field_mapping_unit."""
    env = serialize.build_view()["groups"]["environment"]["lessons"]
    assert env, "environment corpus is empty — env-seed retrieval would surface nothing"
    for seed in env:
        assert seed["title"], seed["source_path"]        # subject→title
        assert seed["description"], seed["source_path"]  # relevance_criteria→description
        assert seed["body"], seed["source_path"]         # carried for the expander
        assert isinstance(seed["metadata"], dict), seed["source_path"]


def test_environment_field_mapping_unit():
    """Env mapping (subject→title, relevance_criteria→description) is pinned
    via _normalize directly, since the live env corpus may be empty and the
    build_view-based actor test wouldn't exercise it."""
    spec = serialize.GROUPS["environment"]
    path = DEFENDER / spec["dir"] / "corp-vpn-egress.md"
    fm = {
        "subject": "corp-vpn-egress",
        "relevance_criteria": "egress from the corp VPN range is expected",
        "alert_rule_ids": [5712],
    }
    rec = serialize._normalize(
        path, fm, "body text", group="environment",
        title_keys=spec["title_keys"], desc_key=spec["desc_key"],
    )
    assert rec["title"] == "corp-vpn-egress"
    assert rec["description"] == "egress from the corp VPN range is expected"
    assert rec["metadata"]["alert_rule_ids"] == [5712]
    assert rec["body"] == "body text"


def test_skipped_lesson_gets_a_degraded_record(tmp_path):
    """A DISCOVERED lesson the walk warn-skips must still appear in the view (#590's rule, the
    posture-view half): omitting it hides from ``lessons.html`` exactly the broken lesson a
    human should be looking at. The record is degraded (marker description, ``status:
    malformed``, no metadata) but shape-compatible, so the template renders it unchanged."""
    import json

    fixture = tmp_path / "defender"
    for spec in serialize.GROUPS.values():
        (fixture / spec["dir"]).mkdir(parents=True)
    (fixture / "lessons" / "good.md").write_text("---\nname: good\ndescription: d\n---\nbody\n")
    (fixture / "lessons" / "broken.md").write_text("---\ndescription: [unclosed\n---\nbody\n")
    (fixture / "lessons" / "_draft.md").write_text("not a lesson\n")  # excluded by discovery

    lessons = serialize.build_view(defender_dir=fixture)["groups"]["defender"]["lessons"]

    assert [rec["title"] for rec in lessons] == ["broken", "good"]  # sorted, both present
    broken = lessons[0]
    assert broken["status"] == "malformed"
    assert "frontmatter unavailable" in broken["description"]
    assert broken["metadata"] == {}
    assert broken["body"] == ""
    assert broken["source_path"] == "defender/lessons/broken.md"
    json.dumps(lessons)  # the degraded record is as JSON-safe as a normal one


def test_metadata_is_json_safe():
    """YAML-parsed dates etc. must serialize (defender lessons carry created_at)."""
    import json

    json.dumps(serialize.build_view())  # raises if any value is non-serializable


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
    assert out["s"] == ["a", "b"]        # set → sorted list (deterministic)
    assert out["d"] == "2026-06-02"      # date → iso string
    assert isinstance(out["t"], str)     # time → str fallback
    json.dumps(out)                      # must not raise
