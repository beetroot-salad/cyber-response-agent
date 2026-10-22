"""The knowledge layout has one owner, rooted at an agent root (#1108 P1 -> P4).

P1 re-rooted the layout on the code checkout (`DefenderPaths(repo_root).knowledge`). P4 moves
the knowledge out of the product tree: `KnowledgePaths` is built from an agent root alone (a
run copy, a draft or an export), and `DefenderPaths` carries no knowledge at all. The
symbol-resolved census of every other reader is `tenant_1108_p4/test_census.py` (O4).
"""
from __future__ import annotations

import importlib
from pathlib import Path

#: Imported by name: the one-argument constructor is the P4 target (expected red before it).
_knowledge = importlib.import_module("defender.knowledge._knowledge")


def test_an_agent_root_carries_its_own_knowledge(tmp_path: Path) -> None:
    """O4: `KnowledgePaths(agent_root)` — built from the agent root alone, as the design
    writes it — places every corpus and skill under that root and nowhere else, so a run
    copy's paths can never reach another root (another tenant's, or the product tree)."""
    agent = tmp_path / "run-knowledge" / "r1" / "agent"
    knowledge = _knowledge.KnowledgePaths(agent)
    assert knowledge.lessons_dir == agent / "lessons"
    assert knowledge.lessons_questioner_dir == agent / "lessons-questioner"
    assert knowledge.system_skill_dir("cmdb") == agent / "skills" / "cmdb"
    assert knowledge.catalog_dir == agent / "skills" / "gather" / "queries"
    other = _knowledge.KnowledgePaths(tmp_path / "other" / "agent")
    assert not other.lessons_dir.is_relative_to(agent)


def test_the_corpus_sets_name_only_live_corpora():
    """O-U5 / O5: the author side touches the runtime corpus and the questioner's; the runtime
    loads only its own; the retired corpora are in neither set."""
    assert frozenset({"lessons", "lessons-questioner"}) == _knowledge.LESSON_CORPORA
    assert frozenset({"lessons"}) == _knowledge.RUNTIME_LESSON_CORPORA


def test_the_code_checkout_carries_no_knowledge(tmp_path: Path) -> None:
    """O1 / O4: a checkout's paths (`DefenderPaths`) no longer lead to any knowledge — the
    accessor P1 re-rooted (`.knowledge`, `.lessons_dir`, ...) is gone, not re-pointed."""
    from defender._paths import DefenderPaths

    paths = DefenderPaths(repo_root=tmp_path)
    assert not hasattr(paths, "knowledge")
    assert not hasattr(paths, "lessons_dir")
