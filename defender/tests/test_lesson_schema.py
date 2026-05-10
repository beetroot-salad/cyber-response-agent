"""Lesson frontmatter shape: required keys, parseable as YAML."""
from __future__ import annotations

import re

import yaml


_FM_RE = re.compile(r"\A---\n(.*?)\n---", re.DOTALL)


def test_existing_finding_ids_handles_empty_dir(tmp_repo):
    a = tmp_repo.author
    assert a.existing_finding_ids() == set()


def test_existing_finding_ids_aggregates_across_lessons(tmp_repo):
    a = tmp_repo.author
    (a.LESSONS_DIR / "one.md").write_text(
        "---\nname: one\ndescription: d\nsource_finding_ids:\n  - r/0\n  - r/1\ncreated_at: 2026-05-09T00:00:00+00:00\n---\nbody\n"
    )
    (a.LESSONS_DIR / "two.md").write_text(
        "---\nname: two\ndescription: d\nsource_finding_ids:\n  - r/2\ncreated_at: 2026-05-09T00:00:00+00:00\n---\nbody\n"
    )
    assert a.existing_finding_ids() == {"r/0", "r/1", "r/2"}


def test_lesson_with_no_frontmatter_is_ignored(tmp_repo):
    a = tmp_repo.author
    (a.LESSONS_DIR / "nofm.md").write_text("just a body, no frontmatter\n")
    assert a.existing_finding_ids() == set()


def test_lesson_frontmatter_required_keys_round_trip(tmp_repo):
    """A canonical lesson must round-trip through yaml.safe_load and expose the four required keys."""
    a = tmp_repo.author
    body = (
        "---\n"
        "name: monitoring-username-shortcut\n"
        "description: when source username matches a monitoring service-account, check auth-history first\n"
        "source_finding_ids:\n"
        "  - real-01-low-monitoring-probe/0\n"
        "created_at: 2026-05-09T12:00:00+00:00\n"
        "---\n\n"
        "Body explaining the pitfall.\n"
    )
    p = a.LESSONS_DIR / "monitoring.md"
    p.write_text(body)
    text = p.read_text()
    m = _FM_RE.match(text)
    assert m is not None
    fm = yaml.safe_load(m.group(1))
    for key in ("name", "description", "source_finding_ids", "created_at"):
        assert key in fm, f"missing required key {key}"
    assert isinstance(fm["source_finding_ids"], list)
    assert isinstance(fm["description"], str)
