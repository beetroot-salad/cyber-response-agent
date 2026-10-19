"""A re-rooted checkout carries its own knowledge paths."""
from __future__ import annotations

from pathlib import Path

from defender._paths import DefenderPaths


def test_a_re_rooted_checkout_carries_its_own_knowledge(tmp_path: Path) -> None:
    """A worktree's paths reach the worktree's knowledge, never the running checkout's."""
    wt = DefenderPaths(repo_root=tmp_path)
    assert wt.knowledge.agent_root == tmp_path / "defender"
    assert wt.lessons_dir == tmp_path / "defender" / "lessons"
    assert wt.knowledge.system_skill_dir("cmdb") == tmp_path / "defender" / "skills" / "cmdb"
