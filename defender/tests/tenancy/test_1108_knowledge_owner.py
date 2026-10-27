"""The knowledge layout has one owner, `KnowledgePaths`, built from an agent root alone (a run
copy, a draft or an export); `DefenderPaths` carries no knowledge (#1108). The symbol-resolved
census of every other reader is `tenant_1108_p4/test_census.py`."""
from __future__ import annotations

from pathlib import Path

from defender.knowledge import _knowledge


def test_an_agent_root_carries_its_own_knowledge(tmp_path: Path) -> None:
    """`KnowledgePaths(agent_root)` places every corpus and skill under that root and nowhere
    else, so a run copy's paths can never reach another root (another tenant's, or the product
    tree)."""
    agent = tmp_path / "run-knowledge" / "r1" / "agent"
    knowledge = _knowledge.KnowledgePaths(agent)
    assert knowledge.lessons_dir == agent / "lessons"
    assert knowledge.lessons_questioner_dir == agent / "lessons-questioner"
    assert knowledge.system_skill_dir("cmdb") == agent / "skills" / "cmdb"
    assert knowledge.catalog_dir == agent / "skills" / "gather" / "queries"
    other = _knowledge.KnowledgePaths(tmp_path / "other" / "agent")
    assert not other.lessons_dir.is_relative_to(agent)


def test_the_corpus_sets_name_only_live_corpora():
    """The author side touches the runtime corpus and the questioner's; the runtime loads only
    its own; the retired corpora are in neither set."""
    assert frozenset({"lessons", "lessons-questioner"}) == _knowledge.LESSON_CORPORA
    assert frozenset({"lessons"}) == _knowledge.RUNTIME_LESSON_CORPORA


def test_the_code_checkout_carries_no_knowledge(tmp_path: Path) -> None:
    """A checkout's paths (`DefenderPaths`) lead to no knowledge: the accessors (`.knowledge`,
    `.lessons_dir`, ...) are gone, not re-pointed."""
    from defender._paths import DefenderPaths

    paths = DefenderPaths(repo_root=tmp_path)
    assert not hasattr(paths, "knowledge")
    assert not hasattr(paths, "lessons_dir")
