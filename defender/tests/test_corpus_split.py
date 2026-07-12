"""Real-corpus invariant guarding the env-fact / tradecraft split (issue #298).

After convergence, standing deployment facts live ONLY in lessons-environment/
(shared, read by both actors) and lessons-actor/ is pattern/tradecraft-only.
These checks run over the actual checked-in corpora so a regression — an
env-fact authored back into lessons-actor, or an env lesson that is
unretrievable / keyed on an identity selector — fails CI.
"""
from __future__ import annotations

from pathlib import Path

from defender._corpus import iter_lessons

REPO_ROOT = Path(__file__).resolve().parents[2]
LESSONS_ENV = REPO_ROOT / "defender" / "lessons-environment"
LESSONS_ACTOR = REPO_ROOT / "defender" / "lessons-actor"


def _corpus(d: Path) -> list[tuple[Path, dict]]:
    """Every non-``_`` lesson in ``d`` as ``(path, frontmatter)``, parsed by the shared walk.

    Folded onto ``iter_lessons`` (#584). This helper used to be a SIXTH hand-rolled copy of the
    corpus walk — its own ``\\A---\\n`` regex fence-split plus ``yaml.safe_load`` — which meant the
    CI gate below disagreed with every other reader about what a lesson IS: the un-normalized regex
    reds on a CRLF lesson that ``iter_lessons`` parses fine.

    Its guarantee is kept VERBATIM and that is the load-bearing part of the fold: ``iter_lessons``
    warn-SKIPS a malformed lesson where this walk ASSERTED, so the assertion moves here, to the call
    site. Every non-``_`` ``*.md`` must come back from the iterator — otherwise a malformed lesson
    would newly slip through this real-corpus CI gate in silence, which is the opposite of what it
    is for."""
    lessons = list(iter_lessons(d))
    expected = {p for p in d.glob("*.md") if not p.name.startswith("_")}
    skipped = sorted(p.name for p in expected - {lesson.path for lesson in lessons})
    assert not skipped, f"unparseable frontmatter (warn-skipped by iter_lessons): {skipped}"
    return [(lesson.path, lesson.fm) for lesson in lessons]


def test_env_corpus_has_anchor_and_wellformed_entities() -> None:
    for p, doc in _corpus(LESSONS_ENV):
        anchor = doc.get("alert_rule_ids")
        assert isinstance(anchor, list), (
            f"{p.name}: env lesson alert_rule_ids anchor must be a list"
        )
        assert anchor, (
            f"{p.name}: env lesson needs a non-empty alert_rule_ids anchor"
        )
        for sel in doc.get("entities") or []:
            assert isinstance(sel, dict), (
                f"{p.name}: entity selector must be a {{type, class}} mapping"
            )
            assert "type" in sel, (
                f"{p.name}: entity selector must have a 'type' key"
            )
            assert "class" in sel, (
                f"{p.name}: entity selector must have a 'class' key"
            )
            # No identity selectors — the defender never grounds the identity in
            # the prologue, so it is not a retrievable key (the grounding is body).
            assert sel["type"] != "identity", (
                f"{p.name}: env lessons must not key on an identity selector"
            )


def test_actor_corpus_is_pattern_only() -> None:
    for p, doc in _corpus(LESSONS_ACTOR):
        # A pattern lesson is keyed by techniques. A mutable: true, subject-bearing,
        # techniques-less lesson is an env-fact and no longer belongs here.
        is_env_fact = (
            doc.get("mutable") is True
            and doc.get("subject")
            and not doc.get("techniques")
        )
        assert not is_env_fact, (
            f"{p.name}: looks like an env-fact (mutable+subject, no techniques) — "
            "env-facts belong in lessons-environment/ (issue #298)"
        )
