"""#691 — the curator binding seam: bind returns a corpus-scoped CuratorDeps, the retained
roots (M6), the by-name corpus lookup (M1), the named tool-config slot (M4/M5), and for_run as a
thin wrapper over bind (M9). RED against HEAD by design: ``CORPUS_AUTHOR_DEF.bindable`` is ``False``
and ``for_run`` bypasses ``bind`` today, so every ``bind_curator`` call raises the current
not-supported ValueError (or the RunScope/slot field is missing) — each test names the DEMANDED
observable so a green #0 is what turns it, never an incidental import error.

The seam + gate helpers live in ``_curator_691_harness`` (one home, per the duplicate-helpers
ratchet). Provisional target symbols that do not exist at HEAD (the ``tool_config`` slot, a
``ForwardCheckConfig`` split off the five non-corpus fields, the retained ``roots`` field) are
imported / touched INSIDE the test bodies so ``--collect-only`` stays clean; their absence is the
red, at run time, not at collection.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from dataclasses import fields, replace
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from _curator_691_harness import (  # noqa: E402
    bind_curator,
    corpus,
    curator_deps,
    curator_scope,
    forward_check_gate,
    make_worktree,
    pending_run_dir,
    rel,
    write_file,
)
from defender.agents import AGENTS  # noqa: E402
from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF, CuratorDeps  # noqa: E402
from defender.learning.author.verify_forward.checks import FINDINGS_CHECK, ForwardCheck  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.tools import AgentDeps  # noqa: E402


# ===========================================================================
# #0 — the binding seam returns a corpus-scoped curator deps
# ===========================================================================

def test_bind_returns_a_corpus_scoped_curator_deps(tmp_path):
    """Binding the curator BY NAME against its worktree returns a CuratorDeps whose compiled write
    scope roots at ``<worktree>/defender/<corpus>``, NOT at run_dir — the whole point of #0. The
    run_dir .md write DENY is the discriminator: a bind whose write_allow rooted at run_dir would
    admit it (this fails if the write scope roots at run_dir)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")
    write_file(deps, rel("lessons", "m.md"))                       # own corpus → lands
    assert (corpus(wt, "lessons") / "m.md").read_text() == "body\n"
    with pytest.raises(ModelRetry):
        write_file(deps, str(rd / "scratch.md"))                   # run_dir → DENY


def test_the_policy_is_compiled_through_the_lower_level_entry_point(tmp_path):
    """Composing the roots and calling the lower-level compile entry directly yields the SAME
    compiled policy the front-door bind produces for one corpus (RG-3: full AgentPolicy equal) —
    seam parity, so the corpus-name guard the front door adds is not a second policy model."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    scope = curator_scope(wt, "lessons")
    direct = compile_policy_for(CORPUS_AUTHOR_DEF, rd, scope=scope, defender_dir=wt / "defender")
    via_bind = bind_curator(wt, rd, "lessons").policy
    assert direct.write_allow == via_bind.write_allow
    assert direct.read_roots == via_bind.read_roots
    assert direct.read_confine == via_bind.read_confine
    assert [g.program for g in direct.bash_allow] == [g.program for g in via_bind.bash_allow]


def test_a_bound_deps_is_copied_with_one_field_replaced(tmp_path):
    """The per-spawn attach idiom copies a bound deps with one field changed; the copy's retained
    ResolvedRoots (M6) and compiled policy are downstream of the BIND, not of the replace — so they
    are copied through byte-identical (c11's bind-then-replace idiom)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")
    copy = replace(deps, salt="other-salt")
    assert copy.policy == deps.policy
    assert copy.roots == deps.roots            # provisional M6 field — retained, copied through


def test_binding_the_same_spawn_twice(tmp_path):
    """Two binds of the same spawn produce policy-relevant fields identical across both — write
    scope, read confine, corpus_dir, retained roots — because bind is pure construction, not a
    stateful registration (in-process AND, by the same argument, across processes)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    a = bind_curator(wt, rd, "lessons")
    b = bind_curator(wt, rd, "lessons")
    assert a.policy.write_allow  # non-degenerate: the equality below must not be two nothings agreeing
    assert a.policy.write_allow == b.policy.write_allow
    assert a.policy.read_confine == b.policy.read_confine
    assert a.corpus_dir == b.corpus_dir
    assert a.roots == b.roots


def test_bind_is_idempotent_across_a_retried_spawn(tmp_path):
    """A retried spawn calls bind a second time with byte-identical inputs in the same process; the
    second call's write scope / read confine / corpus_dir / retained roots must equal the first,
    with no registry- or module-level residue from the by-name resolution the first call ran."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    first = bind_curator(wt, rd, "lessons")
    second = bind_curator(wt, rd, "lessons")
    third = bind_curator(wt, rd, "lessons")             # a third proves no accumulating residue
    assert first.policy.write_allow  # non-degenerate: below must not be three nothings agreeing
    assert first.policy.write_allow == second.policy.write_allow == third.policy.write_allow
    assert first.corpus_dir == second.corpus_dir == third.corpus_dir
    assert first.roots == second.roots == third.roots


def test_for_run_called_twice_for_the_same_spawn(tmp_path):
    """for_run is called fresh per attempt (M9's thin wrapper over bind); both returned deps are
    policy-equivalent and the first is unaffected by the second — no shared mutable spawn state
    (F88: a retried deps is slot-equivalent to the first)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    d1 = curator_deps(wt, rd, "lessons")
    d2 = curator_deps(wt, rd, "lessons")
    assert d1.policy.write_allow == d2.policy.write_allow
    assert d1.corpus_dir == d2.corpus_dir


def test_bound_curator_anchoring_matches_the_for_run_anchoring(tmp_path):
    """The bound curator's cwd_anchor and tree reproduce today's for_run anchoring exactly (c18/M3:
    the curator anchors on its worktree tree, so bind's cwd_anchor is ``tree.parent`` == for_run's
    repo_root). RED today: CORPUS_AUTHOR_DEF does not yet set anchors_on_tree, so bind anchors on
    run_dir — this fails until #0 lands the anchoring flag."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    via_bind = bind_curator(wt, rd, "lessons")
    via_for_run = curator_deps(wt, rd, "lessons")
    assert via_bind.cwd_anchor == via_for_run.cwd_anchor
    assert via_bind.defender_dir == via_for_run.defender_dir


# ===========================================================================
# M6 / M1 — retained roots + the corpus found by NAME
# ===========================================================================

def test_bound_deps_retain_the_compiled_resolved_roots(tmp_path):
    """M6: the deps retains the ResolvedRoots the bind compiled — the record reproduces the run_dir
    and worktree tree the policy was rooted against (a bound deps is not just a policy; the roots it
    came from ride with it, so forward_check re-reads them rather than re-deriving a second root)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")
    assert deps.roots.run_dir == rd                        # provisional M6 field
    assert deps.roots.defender_dir == wt / "defender"


def test_every_role_this_change_does_not_mention_carries_the_new_record(tmp_path):
    """M6/O5: the retained-roots record lands on the BASE AgentDeps, so every OTHER role acquires it
    too — corpus or no corpus, empty toolset or not. Drive a couple of unrelated roles through bind
    and observe each deps carries its own compiled roots (RED today: the field is unbuilt)."""
    rd = pending_run_dir(tmp_path)
    checked = 0
    for role, defn in AGENTS.items():
        if role is AgentRole.CORPUS_AUTHOR or not defn.bindable:
            continue
        try:
            deps = bind(defn, rd)                           # its own generic scope
        except Exception:
            continue                                        # roles needing special scope (confine/tree)
        assert deps.roots.run_dir == rd                     # provisional M6 field — every role has it
        checked += 1
    assert checked >= 1, "no non-curator role bound — the census picked no subject"


def test_the_spawn_corpus_is_resolved_by_name_not_by_position(tmp_path):
    """M1: the spawn corpus is found BY NAME, never ``corpus_roots[0]``. Bind for lessons-actor and
    the resolved corpus_dir is ``<worktree>/defender/lessons-actor`` — pure by-name path arithmetic
    (RG-PO5), distinct from MAIN/GATHER's positional static list."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons-actor")
    assert deps.corpus_dir == wt / "defender" / "lessons-actor"


def test_the_spawn_record_is_asked_for_the_corpus_the_spawn_names(tmp_path):
    """The consumer gets the by-name-resolved corpus, never another spawn's: a curator named
    lessons-actor authors into lessons-actor (lands) and is denied lessons (a sibling) — the record
    it drives is the corpus it named."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons-actor")
    write_file(deps, rel("lessons-actor", "x.md"))
    assert (corpus(wt, "lessons-actor") / "x.md").read_text() == "body\n"
    with pytest.raises(ModelRetry):
        write_file(deps, rel("lessons", "y.md"))            # a sibling it did not name


def test_corpus_dir_derivation_is_unchanged_for_the_git_commit_consumer(tmp_path):
    """For the three shipped names the by-name lookup hands the git-commit consumer a byte-identical
    corpus_dir (c10/g8): ``lessons`` → ``<worktree>/defender/lessons``, unchanged from today."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")
    assert deps.corpus_dir == wt / "defender" / "lessons"


# ===========================================================================
# M4 / M5 — the named tool-config slot: inert-by-default, loud at first use
# ===========================================================================

def test_agent_deps_carries_a_named_tool_config_slot(tmp_path):
    """M4: the five forward-check fields collapse into ONE named ``tool_config`` slot on the base
    AgentDeps (F51: no corpus in it); forward_check reads its config THROUGH the slot. Drive the
    seam: attach the config into the slot and forward_check admits an in-corpus operand through it.
    RED today (bindable + the ForwardCheckConfig/slot are unbuilt)."""
    from defender.learning.author.curator_engine import ForwardCheckConfig  # provisional (M4)
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    (corpus(wt, "lessons") / "x.md").write_text("x\n", encoding="utf-8")
    deps = bind_curator(wt, rd, "lessons")                  # slot UNSET (M5)
    cfg = ForwardCheckConfig(
        check=FINDINGS_CHECK, runs_dir=wt / "runs",
        pending=wt / "_pending" / "f.jsonl", queued_ids=frozenset(), run_verify=lambda **_: "GOOD",
    )
    bound = replace(deps, tool_config=cfg)                  # provisional slot name
    forward_check_gate(bound, rel("lessons", "x.md"))       # reads config through the slot → admits


def test_importing_runtime_does_not_import_the_learning_stages():
    """M4: the tool-config slot is a RUNTIME-side Protocol with an inert default, so importing the
    runtime deps module must not drag in the learning stages (runtime/ never imports learning/ to
    look a deps subtype up). A fresh interpreter importing ``defender.runtime.tools`` pulls in no
    ``defender.learning.author`` module."""
    code = (
        "import defender.runtime.tools, sys; "
        "leaked = [m for m in sys.modules if m.startswith('defender.learning.author')]; "
        "assert not leaked, leaked"
    )
    # repo root is 2 parents up from this test file (<repo_root>/defender/tests/...) — set
    # PYTHONPATH explicitly for the fresh interpreter rather than relying on the invoker's
    # ambient env (pytest's own `pythonpath = [".."]` ini setting resolves `import defender`
    # for THIS process; a bare subprocess.run([sys.executable, "-c", ...]) does not inherit it).
    repo_root = Path(__file__).resolve().parents[2]
    env = {**os.environ, "PYTHONPATH": str(repo_root)}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr


def test_forward_check_repacks_the_config_slot_into_check_context(tmp_path):
    """The config slot's five fields (check, runs_dir, pending, queued_ids, run_verify) are repacked
    into the CheckContext the forward_check builds — one consumer family (c3/g2), not duplicated. A
    recording check captures the ctx it is HANDED and every field traces back to the deps."""
    from defender.learning.author.verify_forward.tool import Pair, run_forward_check
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    captured: dict = {}

    def _rec(ctx):
        captured["ctx"] = ctx
        return "GOOD"

    rec_check = ForwardCheck(error_prefix="rec", prompt_path=None, run=_rec)
    sid = "row-1"
    deps = CuratorDeps.for_run(
        rd, wt, corpus(wt, "lessons"),
        check=rec_check, runs_dir=wt / "runs",
        pending=wt / "_pending" / "f.jsonl", queued_ids=frozenset({sid}),
    )
    (corpus(wt, "lessons") / "lesson.md").write_text("x\n", encoding="utf-8")
    asyncio.run(run_forward_check(deps, [Pair(lesson_path=rel("lessons", "lesson.md"), source_id=sid)]))
    ctx = captured["ctx"]
    assert ctx.runs_dir == deps.runs_dir
    assert ctx.pending == deps.pending
    assert ctx.corpus_dir == deps.corpus_dir
    assert ctx.run_verify == deps.run_verify


def test_forward_check_repeated_calls_see_the_same_compiled_policy(tmp_path):
    """Every forward_check invocation reads the roots the single bind compiled; nothing re-derives a
    second root — the same in-corpus operand gates identically on repeated calls, and to the same
    resolved path (M6)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    (corpus(wt, "lessons") / "x.md").write_text("x\n", encoding="utf-8")
    p1 = forward_check_gate(deps, rel("lessons", "x.md"))
    p2 = forward_check_gate(deps, rel("lessons", "x.md"))
    assert p1 == p2 == (corpus(wt, "lessons") / "x.md")


def test_spawn_identity_fields_do_not_move_into_the_tool_config_slot(tmp_path):
    """M4 moves ONLY the five forward-check fields into the slot: run_dir / defender_dir / run_id /
    salt / cwd_anchor stay BARE identity fields on the base AgentDeps, read directly off the deps —
    they are spawn identity, not tool configuration (c12)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert deps.run_id == rd.name
    assert deps.run_dir == rd
    assert deps.defender_dir == wt / "defender"
    base_names = {f.name for f in fields(AgentDeps)}
    assert {"run_dir", "defender_dir", "run_id", "salt", "cwd_anchor"} <= base_names


def test_tool_config_slot_survives_two_successive_replace_calls(tmp_path):
    """The config the slot holds survives two successive replace() calls that change other fields
    (dep-PO-2): after attaching the config and replacing identity twice, the slot still names the
    same config object. RED today (the slot is unbuilt)."""
    from defender.learning.author.curator_engine import ForwardCheckConfig  # provisional (M4)
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")
    cfg = ForwardCheckConfig(
        check=FINDINGS_CHECK, runs_dir=wt / "runs",
        pending=wt / "_pending" / "f.jsonl", queued_ids=frozenset(), run_verify=lambda **_: "GOOD",
    )
    b2 = replace(replace(replace(deps, tool_config=cfg), run_id="a"), salt="b")
    assert b2.tool_config is cfg


def test_bind_constructs_a_policy_correct_curator_with_no_tool_config(tmp_path):
    """M5: bind constructs a POLICY-CORRECT curator with the tool-config slot UNSET (inert default,
    mirroring AgentDeps.box) — the compiled write/read policy is complete without any config
    attached. Drive: the slot-unset deps still authors its own corpus."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")                  # slot unset
    write_file(deps, rel("lessons", "m.md"))               # policy is complete without a config
    assert (corpus(wt, "lessons") / "m.md").read_text() == "body\n"


def test_tool_config_slot_unset_across_full_lifecycle(tmp_path):
    """M5: with the slot unset, nothing is observable except at forward_check — write / edit / rm /
    cat / lesson_read all work, the slot never touched (c3/g2: forward_check is the sole consumer
    family). Drive a write and a cat with the slot unset → both succeed."""
    from _curator_691_harness import bash_decision
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")                  # slot unset
    (corpus(wt, "lessons") / "x.md").write_text("x\n", encoding="utf-8")
    write_file(deps, rel("lessons", "m.md"))               # write: slot untouched
    assert bash_decision(deps, "cat defender/lessons/x.md").allow   # cat: slot untouched


def test_forward_check_raises_a_named_error_when_its_config_is_unset(tmp_path):
    """M5 (loud-at-first-use): forward_check with its config slot UNSET raises an error that NAMES
    the missing config/slot — inert until used, then loud (F50 leaves the exception CATEGORY open;
    the recommended reading is a retryable refusal, so assert the message names the slot). Positive
    control: with the config SET, the same in-corpus operand is admitted."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    (corpus(wt, "lessons") / "x.md").write_text("x\n", encoding="utf-8")
    unset = bind_curator(wt, rd, "lessons")                # slot unset
    with pytest.raises(Exception) as exc:  # noqa: PT011 - message asserted below, category deliberately open (F50)
        forward_check_gate(unset, rel("lessons", "x.md"))
    assert "config" in str(exc.value).lower() or "forward" in str(exc.value).lower()
    # positive control: config SET → the same operand admits
    ok = curator_deps(wt, rd, "lessons")
    assert forward_check_gate(ok, rel("lessons", "x.md")) == (corpus(wt, "lessons") / "x.md")
