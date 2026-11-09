"""#984: a draft that CONTRADICTS a claim already shipped in a system's SKILL.md must not wait behind the lift-threshold queue depth.

The drafts sit in a lead lane's batch draft (`test_lead_author._lane`), the deps are built over
that lane (`test_lead_author._deps`), and a draft's handoff path is repo-relative
`agent/skills/...`."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.leads import lead_author  # type: ignore[import-not-found]
from defender.tests.learning.curation.test_lead_author import _deps, _lane
from defender.tests.support.learning.curation._lead_author_1134 import skills_view


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """A plain run dir with `gather_raw/`. Local rather than imported from `test_lead_author`: an
    imported fixture used as a parameter name shadows its import."""
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


def _draft_dir(tmp_path: Path):
    """A lead lane over the seeded tenant and its draft's `elastic/_draft/` folder."""
    lane = _lane(tmp_path)
    draft_dir = lane.skills_dir / "elastic" / "_draft"
    draft_dir.mkdir(parents=True, exist_ok=True)
    return lane, draft_dir


def _one_draft(tmp_path: Path, **kw):
    lane, draft_dir = _draft_dir(tmp_path)
    draft = draft_dir / "a.md"
    _write_draft(draft, **kw)
    return lane, draft


def test_contradicting_draft_bypasses_threshold_alone(run_dir: Path, monkeypatch, tmp_path):
    """One draft flagged `contradicts_skill: true`, alone and far below threshold=5, is handed
    off anyway rather than waiting for the queue to fill."""
    lane, draft = _one_draft(tmp_path, contradicts_skill=True)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(lane, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert len(pending) == 1
    assert pending[0]["system"] == "elastic"
    assert pending[0]["draft_path"] == "agent/skills/elastic/_draft/a.md"


@pytest.mark.parametrize("text", [
    # The flag explicitly false: a merely-incomplete draft still waits for the threshold.
    pytest.param("---\nstatus: draft\ncontradicts_skill: false\n---\n", id="flag-false"),
    # Written before the field existed: no `contradicts_skill:` key at all.
    pytest.param("---\nstatus: draft\n---\n", id="no-field"),
    # No frontmatter fence: the gate must neither crash nor silently bypass.
    pytest.param("not frontmatter at all\n", id="unparseable"),
    # The flag is a FRONTMATTER key, not a substring anywhere in the file.
    pytest.param("---\nstatus: draft\n---\n\n## Notes\n\n"
                 "See the README: setting `contradicts_skill: true` bypasses the lift threshold.\n",
                 id="body-mention"),
    # Nor a substring inside a DIFFERENT frontmatter key's string value.
    pytest.param('---\nstatus: draft\nnotes: "contradicts_skill: true is documented in the README"\n---\n',
                 id="other-key-mention"),
    # `"true"` is a YAML STRING, not the boolean `true` the schema calls for.
    pytest.param('---\nstatus: draft\ncontradicts_skill: "true"\n---\n', id="quoted-true"),
])
def test_non_contradicting_draft_stays_silenced_below_threshold(
    run_dir: Path, monkeypatch, tmp_path, text
):
    """Below threshold=5, a draft without a real boolean `contradicts_skill: true` frontmatter
    key is not handed off."""
    lane, draft_dir = _draft_dir(tmp_path)
    draft = draft_dir / "a.md"
    draft.write_text(text, encoding="utf-8")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(lane, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert pending == []


def test_one_contradicting_draft_lifts_the_whole_batch(run_dir: Path, monkeypatch, tmp_path):
    """The handoff is all-or-nothing, as at/above threshold: one contradicting draft lifts the
    plain draft beside it too."""
    lane, draft_dir = _draft_dir(tmp_path)
    contradicting = draft_dir / "a.md"
    plain = draft_dir / "b.md"
    _write_draft(contradicting, contradicts_skill=True)
    _write_draft(plain)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(lane, discover_system_drafts=lambda: [contradicting, plain])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert len(pending) == 2


def test_contradicting_draft_at_threshold_uses_ordinary_path(
    run_dir: Path, monkeypatch, tmp_path
):
    """At/above threshold, a contradicting draft surfaces through the SAME path an ordinary draft
    would."""
    lane, draft = _one_draft(tmp_path, contradicts_skill=True)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    deps = _deps(lane, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert len(pending) == 1


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
