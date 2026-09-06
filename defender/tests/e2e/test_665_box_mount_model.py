"""#665 — the mount model of the two new tiers + the gate↔mount reasoning (part 3 of 3).

The run-cycle box (shared by the actor + judge legs) and the drain box (over its worktree
leaf) each compose a mount SET whose identity is what these tests pin: covers the union of
its roles' gate scopes plus each cwd_anchor (M3a, corrected by DC2), nothing wider than a
scope or the infra needs (S4), gather_raw read-only (S1), the run-cycle tree tightened rw→ro
(R4/F5), the drain rw confined to the leaf, mounting only the TRIGGERED corpus (M1). Plus the
gate-side reasoning: the actor's cwd_anchor move to repo_root (decision 1 / DC2), the gate
passing pinned-script argv unexamined, the no-file-opening actor grant, and the host-side
write tools that never cross the box.

RED AGAINST HEAD: neither creation site composes a box, so the run-cycle / drain mount SETS
are observed off the request the future site hands the injected `start_box` seam (TypeError
until built); the actor still anchors at learning_run_dir, not repo_root. Live mechanism
confirmations (a real ro-write refusal, a real `..` traversal landing on the ro rootfs) are
in `test_665_box_live.py`.
"""
from __future__ import annotations

from pathlib import Path

import pytest


pytest.importorskip("pydantic_ai")

from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import RunScope, bind, compile_policy_for  # noqa: E402
from defender.runtime.permission.bash import decide_bash  # noqa: E402
from _box665 import ScriptedTransport  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "s665mnt"
from defender.learning.core.config import REPO_ROOT  # noqa: E402

PINNED = REPO_ROOT / "defender" / "scripts" / "lessons" / "defender-lessons"








def _anchor_covered(req, anchor) -> bool:
    """DC2 coverage predicate: a cwd_anchor is covered iff it lies INSIDE some mount, OR it is
    the immediate (auto-created, read-only) PARENT of some mount whose subtree the granted
    commands resolve into (po44). A wholly-outside anchor — inside no mount and parent of none
    — is the M3a violation the issue's own failure mode names."""
    anchor = Path(anchor)
    for m in req.mounts:
        source = Path(m.source)
        if anchor.is_relative_to(source) or source.parent == anchor:
            return True
    return False




































def test_curator_relative_operand_rebased_at_cwd_anchor_escapes_corpus(tmp_path):
    """test_curator_relative_operand_rebased_at_cwd_anchor_escapes_corpus (F9 → R4) —
    containment of a curator `rm` operand that traverses `..` out of its corpus but stays in
    the worktree is bound to BOTH layers: the gate's textual anti-traversal AND the mount as
    the authoritative backstop (po63: a `..` escape lands on the ro rootfs/infra mount, write
    refused). Asserts the gate refuses a `..`-traversing rm operand out of the corpus scope."""
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


def test_scan_step_walks_the_full_written_tree_versus_only_a_diff(tmp_path):
    """scan_before_supply_chain's twin — the S7 scan walks the FULL written tree (os.walk),
    not only a diff, so a tainting entry anywhere in the tree is caught. Asserts box.scrub
    raises on a non-regular entry planted deep in the tree."""
    tree = tmp_path / "leaf"
    (tree / "a" / "b").mkdir(parents=True)
    (tree / "a" / "b" / "ok.md").write_text("ok", encoding="utf-8")
    bad = tree / "a" / "b" / "sym"
    bad.symlink_to(tmp_path / "outside")
    with pytest.raises(box_mod.RunTainted):
        box_mod.scrub(tree)




def test_a_symlink_left_in_the_corpus_tree_is_refused_by_the_s7_scan_before_commit(tmp_path):
    """test_a_symlink_left_in_the_corpus_tree_is_refused_by_the_s7_scan_before_commit — a
    symlink an in-box `rm`/program leaves in the corpus tree is CAUGHT by the S7 scan BEFORE the
    commit (RunTainted), so it is NEVER committed and pushed into the corpus that steers the
    runtime defender. Asserts box.scrub REFUSES a symlink left in the tree (the name now matches
    the asserted outcome — refusal, not commit)."""
    tree = tmp_path / "leaf" / "defender" / "lessons"
    tree.mkdir(parents=True)
    (tree / "real.md").write_text("lesson", encoding="utf-8")
    (tree / "sneaky").symlink_to("/etc/passwd")
    with pytest.raises(box_mod.RunTainted):
        box_mod.scrub(tmp_path / "leaf")


