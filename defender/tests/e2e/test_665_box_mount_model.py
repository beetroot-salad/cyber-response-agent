"""#665 — gate/mount reasoning for the learning-role boxes: the curator gate refuses a ..-traversing rm out of its corpus, and host-side write tools never cross the box transport."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import RunScope, bind, compile_policy_for  # noqa: E402
from defender.runtime.permission.bash import decide_bash  # noqa: E402
from _box665 import ScriptedTransport  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "s665mnt"

def test_curator_relative_operand_rebased_at_cwd_anchor_escapes_corpus(tmp_path):
    """test_curator_relative_operand_rebased_at_cwd_anchor_escapes_corpus (F9 → R4) — containment
    of a curator `rm` operand that traverses `..` out of its corpus but stays in the worktree
    is bound to BOTH layers: the gate's textual anti-traversal AND the mount as the
    authoritative backstop (po63: a `..` ..."""
    from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF, SHIPPED_LESSON_CORPORA

    repo = tmp_path / "repo"
    dtree = repo / "defender"
    for name in SHIPPED_LESSON_CORPORA:
        (dtree / name).mkdir(parents=True, exist_ok=True)
    scope = RunScope(corpus_name="lessons",
                     read_confine=tuple((dtree / n).resolve() for n in SHIPPED_LESSON_CORPORA))
    policy = compile_policy_for(CORPUS_AUTHOR_DEF, tmp_path / "lrd", scope=scope, defender_dir=dtree)
    decision = decide_bash(f"rm {dtree / 'lessons'}/../lessons-environment/x.md",
                           policy=policy, run_dir=tmp_path / "lrd", defender_dir=dtree,
                           cwd_anchor=repo)
    assert not decision.allow, "the gate allowed a `..` traversal out of the curator's corpus scope"
    ok = decide_bash(f"rm {dtree / 'lessons'}/x.md", policy=policy, run_dir=tmp_path / "lrd",
                     defender_dir=dtree, cwd_anchor=repo)
    assert ok.allow, "the in-scope rm was refused (positive control failed)"

# N3 — the host-side write tools never cross the box; the scan (S7)
def test_host_side_write_tools_write_live_tree_in_process(tmp_path):
    """host_tools_do_not_cross_box (negative) — the write/edit tools mutate the live tree
    IN-PROCESS host-side; they never cross the box transport (N3), so no in-box mount exists for
    their output. Negative: the box transport records NO write from a host-side write tool;
    positive control: the file lands on the host tree."""
    from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF, SHIPPED_LESSON_CORPORA

    dtree = tmp_path / "repo" / "defender"
    for name in SHIPPED_LESSON_CORPORA:
        (dtree / name).mkdir(parents=True, exist_ok=True)
    scope = RunScope(corpus_name="lessons",
                     read_confine=tuple((dtree / n).resolve() for n in SHIPPED_LESSON_CORPORA))
    transport = ScriptedTransport()  # any run_parsed would record here
    deps = bind(CORPUS_AUTHOR_DEF, tmp_path / "lrd", scope=scope, defender_dir=dtree,
                box=box_mod.BoxExecutor(transport=transport))
    target = dtree / "lessons" / "spec-new.md"
    runtime_tools._tool_write_file(deps, str(target), "spec content")
    assert transport.calls == [], "a host-side write crossed the box transport"
    assert target.read_text(encoding="utf-8") == "spec content", "the write did not land on the live tree"

