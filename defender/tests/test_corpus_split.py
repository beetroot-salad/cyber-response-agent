"""Real-corpus invariant guarding the env-fact / tradecraft split (issue #298).

After convergence, standing deployment facts live ONLY in lessons-environment/
(shared, read by both actors) and lessons-actor/ is pattern/tradecraft-only.
These checks run over the actual checked-in corpora so a regression — an
env-fact authored back into lessons-actor, or an env lesson that is
unretrievable / keyed on an identity selector — fails CI.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
LESSONS_ENV = REPO_ROOT / "defender" / "lessons-environment"
LESSONS_ACTOR = REPO_ROOT / "defender" / "lessons-actor"

_FM = re.compile(r"\A---\n(.*?)\n---", re.DOTALL)


def _corpus(d: Path) -> list[tuple[Path, dict]]:
    out: list[tuple[Path, dict]] = []
    for p in sorted(d.glob("*.md")):
        if p.name.startswith("_"):
            continue
        m = _FM.match(p.read_text())
        assert m, f"{p.name}: missing frontmatter"
        doc = yaml.safe_load(m.group(1))
        assert isinstance(doc, dict), f"{p.name}: frontmatter is not a mapping"
        out.append((p, doc))
    return out


def test_env_corpus_has_anchor_and_wellformed_entities() -> None:
    for p, doc in _corpus(LESSONS_ENV):
        anchor = doc.get("alert_rule_ids")
        assert isinstance(anchor, list) and anchor, (
            f"{p.name}: env lesson needs a non-empty alert_rule_ids anchor"
        )
        for sel in doc.get("entities") or []:
            assert isinstance(sel, dict) and "type" in sel and "class" in sel, (
                f"{p.name}: entity selector must be a {{type, class}} mapping"
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
