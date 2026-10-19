"""#984: a draft that CONTRADICTS a claim already shipped in a system's SKILL.md must not wait behind the lift-threshold queue depth."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.leads import lead_author  # type: ignore[import-not-found]
from defender.tests.learning.curation.test_lead_author import _deps
from defender.tests.support.learning.curation._lead_author_1134 import skills_view


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """Mirrors `test_lead_author.run_dir` — kept local rather than imported so the fixture name (used as a..."""
    rd = tmp_path / "test-run-001"
    rd.mkdir()
    (rd / "gather_raw").mkdir()
    return rd


def _write_draft(path: Path, *, contradicts_skill: bool | None = None) -> None:
    lines = ["---", "status: draft"]
    if contradicts_skill is not None:
        lines.append(f"contradicts_skill: {'true' if contradicts_skill else 'false'}")
    lines.append("---")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _one_draft(tmp_path: Path, **kw) -> Path:
    skills = tmp_path / "defender" / "skills"
    draft_dir = skills / "elastic" / "_draft"
    draft_dir.mkdir(parents=True, exist_ok=True)
    draft = draft_dir / "a.md"
    _write_draft(draft, **kw)
    return draft


def test_contradicting_draft_bypasses_threshold_alone(run_dir: Path, monkeypatch, tmp_path):
    """One draft flagged `contradicts_skill: true`, alone, far below threshold=5 — surfaces anyway rather than..."""
    draft = _one_draft(tmp_path, contradicts_skill=True)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert len(pending) == 1
    assert pending[0]["system"] == "elastic"
    assert pending[0]["draft_path"] == "defender/skills/elastic/_draft/a.md"


def test_non_contradicting_draft_stays_silenced_below_threshold(
    run_dir: Path, monkeypatch, tmp_path
):
    """Same queue depth, flag explicitly false — the pre-#984 behavior is unchanged: a merely-incomplete draft..."""
    draft = _one_draft(tmp_path, contradicts_skill=False)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert pending == []


def test_draft_with_no_contradicts_field_stays_silenced(run_dir: Path, monkeypatch, tmp_path):
    """A draft written before this field existed (no `contradicts_skill:` key at all) takes the ORIGINAL..."""
    draft = _one_draft(tmp_path)  # no contradicts_skill key at all
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert pending == []


def test_unparseable_draft_does_not_bypass(run_dir: Path, monkeypatch, tmp_path):
    """A draft with no frontmatter fence (malformed) must not crash the gate and must not silently bypass it — an..."""
    skills = tmp_path / "defender" / "skills"
    draft_dir = skills / "elastic" / "_draft"
    draft_dir.mkdir(parents=True)
    draft = draft_dir / "a.md"
    draft.write_text("not frontmatter at all\n", encoding="utf-8")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert pending == []


def test_one_contradicting_draft_lifts_the_whole_batch(run_dir: Path, monkeypatch, tmp_path):
    """The handoff is all-or-nothing, same as the at/above-threshold path: one contradicting draft among several..."""
    skills = tmp_path / "defender" / "skills"
    draft_dir = skills / "elastic" / "_draft"
    draft_dir.mkdir(parents=True)
    contradicting = draft_dir / "a.md"
    plain = draft_dir / "b.md"
    _write_draft(contradicting, contradicts_skill=True)
    _write_draft(plain)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [contradicting, plain])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert len(pending) == 2


def test_contradicting_draft_at_threshold_uses_ordinary_path(
    run_dir: Path, monkeypatch, tmp_path
):
    """At/above threshold, a contradicting draft surfaces through the SAME path an ordinary draft would — the..."""
    draft = _one_draft(tmp_path, contradicts_skill=True)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert len(pending) == 1


def test_body_text_mentioning_the_flag_does_not_bypass(run_dir: Path, monkeypatch, tmp_path):
    """The flag is a FRONTMATTER key, not a substring anywhere in the file. A draft whose `## Notes` prose..."""
    skills = tmp_path / "defender" / "skills"
    draft_dir = skills / "elastic" / "_draft"
    draft_dir.mkdir(parents=True)
    draft = draft_dir / "a.md"
    draft.write_text(
        "---\nstatus: draft\n---\n\n"
        "## Notes\n\n"
        "See the README: setting `contradicts_skill: true` bypasses the lift threshold.\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert pending == []


def test_frontmatter_string_value_mentioning_the_flag_does_not_bypass(
    run_dir: Path, monkeypatch, tmp_path
):
    """Same idea, one layer closer: the substring appears inside a DIFFERENT frontmatter key's string value,..."""
    skills = tmp_path / "defender" / "skills"
    draft_dir = skills / "elastic" / "_draft"
    draft_dir.mkdir(parents=True)
    draft = draft_dir / "a.md"
    draft.write_text(
        '---\nstatus: draft\nnotes: "contradicts_skill: true is documented in the README"\n---\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert pending == []


def test_quoted_true_string_does_not_bypass(run_dir: Path, monkeypatch, tmp_path):
    """`contradicts_skill: "true"` is a YAML STRING, not the boolean `true` — the schema calls for a real..."""
    skills = tmp_path / "defender" / "skills"
    draft_dir = skills / "elastic" / "_draft"
    draft_dir.mkdir(parents=True)
    draft = draft_dir / "a.md"
    draft.write_text('---\nstatus: draft\ncontradicts_skill: "true"\n---\n', encoding="utf-8")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert pending == []


def test_draft_contradicts_skill_predicate(tmp_path: Path):
    """Unit-level pin on the predicate itself, independent of the threshold plumbing."""
    p = tmp_path / "x.md"

    _write_draft(p, contradicts_skill=True)
    assert lead_author._draft_contradicts_skill(skills_view(tmp_path), p, where=tmp_path) is True

    _write_draft(p, contradicts_skill=False)
    assert lead_author._draft_contradicts_skill(skills_view(tmp_path), p, where=tmp_path) is False

    _write_draft(p)
    assert lead_author._draft_contradicts_skill(skills_view(tmp_path), p, where=tmp_path) is False

    p.write_text("no frontmatter\n", encoding="utf-8")
    assert lead_author._draft_contradicts_skill(skills_view(tmp_path), p, where=tmp_path) is False

    assert lead_author._draft_contradicts_skill(
        skills_view(tmp_path), tmp_path / "missing.md", where=tmp_path) is False
