"""`lesson_name`: which opened files count as lesson loads (`lessons_loaded.jsonl`).

#1108 P4 O5: a lesson read from the run copy is recorded, recognised by `KnowledgePaths`' corpus
dirs — not by a `defender/` grandparent (P4-C7), which no tenant lesson has after P4 (O1). The
recogniser is told the agent root it serves (assumed seam: `lesson_name(path, agent_root=...)`).
"""
from __future__ import annotations

from pathlib import Path

from defender.hooks.record_lesson_load import (
    lesson_name,
)

#: A run copy's agent root, shaped as the design places it: `<T>/run-knowledge/<run_id>/agent`.
RUN_AGENT = Path("/data/tenant-a/run-knowledge/run-1/agent")


def test_o5_names_a_lesson_in_the_run_copys_corpus():
    """O5: a direct `.md` child of the run copy's `lessons/` is the lesson its stem names."""
    assert lesson_name(str(RUN_AGENT / "lessons" / "foo.md"), agent_root=RUN_AGENT) == "foo"


def test_o5_ignores_nested_non_md_and_underscore_files():
    assert lesson_name(str(RUN_AGENT / "lessons" / "sub" / "z.md"), agent_root=RUN_AGENT) is None
    assert lesson_name(str(RUN_AGENT / "lessons" / "readme.txt"), agent_root=RUN_AGENT) is None
    assert lesson_name(str(RUN_AGENT / "lessons" / "_TEMPLATE.md"), agent_root=RUN_AGENT) is None
    # control: the same root names a real lesson, so the refusals above are about the shape
    assert lesson_name(str(RUN_AGENT / "lessons" / "z.md"), agent_root=RUN_AGENT) == "z"


def test_o5_a_corpus_dir_under_another_root_is_not_the_corpus():
    """O5/O1: recognition keys on the served agent root's corpus dirs. A `lessons/` dir anywhere
    else — another run's copy, a staged tree, or the old product spelling `defender/lessons/` —
    is not this run's corpus."""
    other = Path("/data/tenant-b/run-knowledge/run-9/agent")
    assert lesson_name(str(other / "lessons" / "foo.md"), agent_root=RUN_AGENT) is None
    assert lesson_name("/repo/defender/lessons/foo.md", agent_root=RUN_AGENT) is None
    assert lesson_name("/repo/elsewhere/lessons/foo.md", agent_root=RUN_AGENT) is None
    # control: the same file name under the served root is a lesson
    assert lesson_name(str(RUN_AGENT / "lessons" / "foo.md"), agent_root=RUN_AGENT) == "foo"
