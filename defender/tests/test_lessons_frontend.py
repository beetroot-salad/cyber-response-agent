"""Lessons-frontend api layer (serialize.build_view) contract guarantees.

The view contract is what the self-contained HTML renders from, so these
tests pin the shape the template depends on rather than the exact lesson
counts (which grow as the loop authors). Counts are checked against the
live on-disk corpora so the serializer must enumerate exactly those files.
"""
from __future__ import annotations

from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[1]

from defender.learning.frontend import serialize  # noqa: E402


CORPUS_DIR = {
    "defender": DEFENDER / "lessons",
    "actor": DEFENDER / "lessons-actor",
    "environment": DEFENDER / "lessons-environment",
}


def _on_disk(corpus: Path) -> set[str]:
    """Stems the serializer would enumerate: non-underscore ``*.md`` whose
    frontmatter parses. The serializer warns+skips malformed files, so
    counting raw ``*.md`` would diverge the moment a lesson lands with a
    YAML typo — mirror the skip via the same ``_read_lesson`` primitive."""
    if not corpus.is_dir():
        return set()
    out: set[str] = set()
    for p in corpus.glob("*.md"):
        if p.name.startswith("_"):
            continue
        fm, _ = serialize._read_lesson(p)
        if fm:
            out.add(p.stem)
    return out


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
