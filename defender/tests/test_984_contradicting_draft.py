"""#984: a draft that CONTRADICTS a claim already shipped in a system's SKILL.md must not
wait behind the lift-threshold queue depth.

The issue's own case: `defender/skills/elastic/SKILL.md` told the orchestrator to group
Falco alerts on `falco.output_fields.container.name`; a verified draft sitting in
`elastic/_draft/` since 2026-05-27 said that field is `<NA>` on every alert and the
container id is the only field that resolves. The correction sat queued for three months
because `LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD` (default 5) counts the WHOLE pending-draft
queue and this system never had enough unrelated drafts to cross it — so a knowledge
surface that was actively wrong queued behind unrelated, merely-incomplete drafts with no
relation to the defect.

Scope: `_draft_contradicts_skill` (the frontmatter read) and its effect on
`_prepare_handoffs`'s threshold gate. Not the corpus of real elastic drafts — the
contradiction this issue reported is fixed directly in `SKILL.md` and the stale draft
removed as part of the same change (see the diff, not a test here).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning.leads import lead_author  # type: ignore[import-not-found]
from defender.tests.test_lead_author import _deps


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """Mirrors `test_lead_author.run_dir` — kept local rather than imported so the fixture
    name (used as a parameter in every test below) never collides with a module-level import
    binding of the same name (ruff F811: a same-named parameter "redefines" an unused import
    on every occurrence, not just the second)."""
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
    """One draft flagged `contradicts_skill: true`, alone, far below threshold=5 — surfaces
    anyway rather than waiting for four more unrelated drafts to accumulate."""
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
    """Same queue depth, flag explicitly false — the pre-#984 behavior is unchanged: a
    merely-incomplete draft still waits for the queue to fill."""
    draft = _one_draft(tmp_path, contradicts_skill=False)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    # No executed leads either, so a correctly-silenced draft hits the pre-existing
    # "nothing to do" exit (rc=0, `test_prepare_handoffs_both_empty_exits_zero`) — the
    # point under test is `pending == []`, not this shared exit code.
    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert pending == []


def test_draft_with_no_contradicts_field_stays_silenced(run_dir: Path, monkeypatch, tmp_path):
    """A draft written before this field existed (no `contradicts_skill:` key at all) takes
    the ORIGINAL threshold-gated path — the field is opt-in, never inferred."""
    draft = _one_draft(tmp_path)  # no contradicts_skill key at all
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "5")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc == 0
    assert pending == []


def test_unparseable_draft_does_not_bypass(run_dir: Path, monkeypatch, tmp_path):
    """A draft with no frontmatter fence (malformed) must not crash the gate and must not
    silently bypass it — an unreadable flag is not evidence of contradiction."""
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
    """The handoff is all-or-nothing, same as the at/above-threshold path: one contradicting
    draft among several ordinary ones surfaces the WHOLE batch, not just the flagged file —
    `_prepare_handoffs` has never handed out a partial system-draft batch, and the author
    still needs the neighboring drafts' context to fold correctly."""
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
    """At/above threshold, a contradicting draft surfaces through the SAME path an ordinary
    draft would — the flag only matters below threshold; it isn't a second, different way
    to build the handoff once the queue is already big enough."""
    draft = _one_draft(tmp_path, contradicts_skill=True)
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1")
    deps = _deps(tmp_path, discover_system_drafts=lambda: [draft])

    _, pending, rc = lead_author._prepare_handoffs(run_dir, deps)
    assert rc is None
    assert len(pending) == 1


def test_body_text_mentioning_the_flag_does_not_bypass(run_dir: Path, monkeypatch, tmp_path):
    """The flag is a FRONTMATTER key, not a substring anywhere in the file. A draft whose
    `## Notes` prose happens to quote `contradicts_skill: true` (documenting the mechanism,
    say) while its own frontmatter never sets the key must stay on the ordinary path — a
    predicate that just greps the whole file for that string would wrongly bypass here."""
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
    """Same idea, one layer closer: the substring appears inside a DIFFERENT frontmatter
    key's string value, never as the `contradicts_skill:` key itself. Only the real key
    counts."""
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
    """`contradicts_skill: "true"` is a YAML STRING, not the boolean `true` — the schema
    calls for a real boolean, and a predicate that treats any truthy-looking value as a
    bypass is looser than the field is documented to be."""
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
    assert lead_author._draft_contradicts_skill(p) is True

    _write_draft(p, contradicts_skill=False)
    assert lead_author._draft_contradicts_skill(p) is False

    _write_draft(p)
    assert lead_author._draft_contradicts_skill(p) is False

    p.write_text("no frontmatter\n", encoding="utf-8")
    assert lead_author._draft_contradicts_skill(p) is False

    assert lead_author._draft_contradicts_skill(tmp_path / "missing.md") is False
