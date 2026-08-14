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

from _box665 import (  # noqa: E402
    DEFENDER,
    REPO_ROOT,
    BoxLifecycleRecorder,
    RecordingBranch,
    drive_run_one,
    drive_worktree_batch,
    mount_for,
)

pytest.importorskip("pydantic_ai")

from defender.learning.pipeline.actor_engine import ACTOR_DEF  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.runtime.agent_definition import RunScope, bind, compile_policy_for  # noqa: E402
from defender.runtime.permission.bash import decide_bash  # noqa: E402
from _box665 import ScriptedTransport  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "s665mnt"
PINNED = REPO_ROOT / "defender" / "scripts" / "lessons" / "defender-lessons"


# --------------------------------------------------------------------------- #
def _rc_request(tmp_path, monkeypatch, **kw):
    """The run-cycle BoxRequest run_one composes (captured off the injected start_box)."""
    rec = BoxLifecycleRecorder()
    drive_run_one(tmp_path, monkeypatch, rec, **kw)  # TypeError at HEAD → red
    return rec.only_request()


def _drain_request(tmp_path, **kw):
    """The drain BoxRequest _run_worktree_batch composes over its worktree leaf."""
    rec = BoxLifecycleRecorder()
    branch = RecordingBranch(tmp_path / "wt", events=rec.events)
    drive_worktree_batch(tmp_path, rec, do_work=lambda wt, *, box=None: None, branch=branch)
    return rec.only_request()


def _actor_deps(run_dir, *, scripts=()):
    return bind(ACTOR_DEF, run_dir, scope=RunScope(read_confine=(run_dir,), scripts=scripts),
                defender_dir=DEFENDER)


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


# ======================================================================= #
# The run-cycle box mount SET (O3/M3/S1/S4, DC2, R4, R10)
# ======================================================================= #
def test_mount_covers_union_gate_scope_and_cwd_anchor(tmp_path, monkeypatch):
    """mount_covers_scope (DC2) — the run-cycle box's mounts cover the UNION of its roles'
    gate scopes (run_dir, defender_dir, gather_raw) plus each role's cwd_anchor; per DC2 a
    cwd_anchor may be inside a mount OR the auto-created read-only PARENT of one (the actor's
    repo_root is the parent of the defender mount). Asserts every gate-scope root is mounted
    and the anchor is covered."""
    req = _rc_request(tmp_path, monkeypatch)
    run_dir_name = "inv-665"
    assert mount_for(req, run_dir_name) is not None, "learning_run_dir gate root not mounted"
    assert mount_for(req, str(DEFENDER)) is not None, "defender_dir gate root not mounted"
    assert mount_for(req, "gather_raw") is not None, "gather_raw gate root not mounted"
    # DC2: the actor cwd_anchor (repo_root) is covered — it is the parent of the defender mount.
    defender_mount = mount_for(req, str(DEFENDER))
    assert Path(req.workdir) == Path(defender_mount.source).parent, \
        "the actor cwd_anchor is not covered as the parent of a mount (M3a/DC2)"


def test_every_mount_justified_by_scope_or_infra(tmp_path, monkeypatch):
    """no_mount_wider_than_justified — nothing is mounted that neither a gate root nor the
    execution mechanism requires (S4): every mount source is one of the run-cycle box's
    justified trees (learning_run_dir, the defender infra tree, gather_raw). A mount widening
    beyond these is the defect this pins against."""
    req = _rc_request(tmp_path, monkeypatch)
    justified = ("inv-665", str(DEFENDER), "gather_raw")
    for m in req.mounts:
        assert any(j in str(m.source) for j in justified), f"unjustified mount {m.source}"


def test_run_cycle_box_mounts_gather_raw_readonly(tmp_path, monkeypatch):
    """gather_raw_readonly (negative) — the run-cycle box mounts gather_raw READ-ONLY, because
    the judge must not mutate the evidence it grades (S1). Negative on the writability of the
    gather_raw mount; positive control: the mount is present (the judge can READ it)."""
    req = _rc_request(tmp_path, monkeypatch)
    m = mount_for(req, "gather_raw")
    assert m is not None, "gather_raw was not mounted at all (positive control failed)"
    assert m.writable is False, "gather_raw was mounted writable — the judge can mutate evidence"


def test_run_cycle_writable_mount_has_an_in_box_justifier(tmp_path, monkeypatch):
    """test_run_cycle_writable_mount_has_an_in_box_justifier (F5 → R4) — the run-cycle
    learning_run_dir mount is tightened rw→READ-ONLY: no in-box program writes it (the writers
    act host-side, N3), and S4 grants nothing wider than justified — parity with the runtime
    tier is not a justification. Asserts the learning_run_dir mount is read-only."""
    req = _rc_request(tmp_path, monkeypatch)
    m = mount_for(req, "inv-665")
    assert m is not None, "the run-cycle learning_run_dir was not mounted"
    assert m.writable is False, \
        "the run-cycle learning_run_dir mount stayed writable with no in-box justifier"


def test_run_cycle_box_mount_union_leaks_a_sibling_batchs_learning_run_dir(tmp_path, monkeypatch):
    """test_run_cycle_box_mount_union_leaks_a_sibling_batchs_learning_run_dir — the box mounts
    exactly THIS run's learning_run_dir, never a parent directory (which would expose sibling
    runs' learning_run_dirs, the drain tier's M1 blast-radius failure applied to the run-cycle
    tier). Asserts no mount source is a strict parent of learning_run_dir."""
    req = _rc_request(tmp_path, monkeypatch)
    m = mount_for(req, "inv-665")
    assert m is not None, "learning_run_dir was not mounted"
    assert Path(m.source).name == "inv-665", \
        "the mount source is a parent of learning_run_dir — sibling runs leak in"


def test_judge_gate_scope_read_roots_may_include_a_path_not_snapshotted_at_box_creation(
    tmp_path, monkeypatch,
):
    """test_judge_gate_scope_read_roots_may_include_a_path_not_snapshotted_at_box_creation
    (po43 → R10) — the run-cycle box's ro gather_raw mount is decided by an EARLY is_dir()
    check hoisted to run_one's top (from run_dir alone), snapshotted BEFORE box creation —
    docker cannot add mounts to a running container, so a read root known only per-leg later
    would be silently missing. Asserts a gather_raw present at box creation is mounted."""
    req = _rc_request(tmp_path, monkeypatch, gather_raw=True)
    assert mount_for(req, "gather_raw") is not None, \
        "gather_raw present at box creation was not snapshotted into the ro mount"


def test_gather_raw_mount_omitted_when_evidence_dir_legitimately_absent_at_request_time(
    tmp_path, monkeypatch,
):
    """test_gather_raw_mount_omitted_when_evidence_dir_legitimately_absent_at_request_time —
    a gather-less run legitimately has no gather_raw; the conditional is_dir() gate (decision
    9) omits the mount rather than binding an absent source (which docker refuses loudly, DC1).
    Asserts the request omits the gather_raw mount when the evidence dir does not exist."""
    req = _rc_request(tmp_path, monkeypatch, gather_raw=False)
    assert mount_for(req, "gather_raw") is None, \
        "an absent gather_raw was still composed into the mount set"


def test_gather_raw_appears_after_the_run_cycle_box_already_started_without_it(tmp_path, monkeypatch):
    """test_gather_raw_appears_after_the_run_cycle_box_already_started_without_it — the mount
    set is FIXED once at box creation; if gather_raw is created later (after the box already
    started without it), it is never remounted (no remount mechanism, and mounts cannot be
    added to a running container). Asserts one box, composed without gather_raw when absent at
    creation."""
    rec = BoxLifecycleRecorder()
    drive_run_one(tmp_path, monkeypatch, rec, gather_raw=False)  # TypeError at HEAD → red
    assert len(rec.boxes) == 1, "the box was recreated to pick up a late gather_raw"
    assert mount_for(rec.only_request(), "gather_raw") is None


def test_cwd_anchor_wholly_outside_every_declared_mount(tmp_path, monkeypatch):
    """test_cwd_anchor_wholly_outside_every_declared_mount — the issue's OWN failure mode (M3a):
    a role whose cwd_anchor lies WHOLLY OUTSIDE every mount — inside none and the parent of none
    — is UNCOVERED (`python3 defender/...` / `docker exec -w <anchor>` targets a tree the box
    never mounted). Negative: a wholly-outside anchor is uncovered. Positive control (DC2): the
    composed run-cycle actor cwd_anchor (repo_root, the auto-created ro PARENT of the defender
    mount, po44) IS covered — parent-of-a-mount is VALID, wholly-outside is the violation, and
    the two are kept distinct."""
    req = _rc_request(tmp_path, monkeypatch)
    anchor = getattr(req, "workdir", None)
    assert anchor is not None, "the run-cycle request composed no workdir/cwd_anchor"
    # positive control (DC2): the composed actor anchor is the defender mount's parent → covered
    assert _anchor_covered(req, anchor), \
        "the composed actor cwd_anchor (the defender mount's parent) is not covered (DC2 positive control failed)"
    # negative (M3a): an anchor inside no mount and the parent of none is uncovered
    outside = tmp_path / "nowhere-outside-every-mount"
    assert not _anchor_covered(req, outside), \
        "an anchor wholly outside every declared mount was treated as covered (the issue's M3a failure mode)"


def test_role_anchor_that_is_a_mount_parent_not_inside_any_mount(tmp_path, monkeypatch):
    """test_role_anchor_that_is_a_mount_parent_not_inside_any_mount (DC2 / po44) — a role whose
    cwd_anchor is the mount's PARENT (not inside any mount) WORKS: under --read-only dockerd
    auto-creates the ro parent, which is a usable `docker exec -w` workdir into which relative
    `defender/...` resolves (po44 confirmed live). Asserts the composed request uses repo_root
    (the defender mount's parent) as the actor workdir — the working mechanism, not an open
    fork."""
    req = _rc_request(tmp_path, monkeypatch)
    defender_mount = mount_for(req, str(DEFENDER))
    assert defender_mount is not None
    assert Path(req.workdir) == Path(defender_mount.source).parent, \
        "the actor workdir is not the auto-created ro parent of the defender mount (DC2)"


# ======================================================================= #
# The drain box mount SET (M1/S3/S4)
# ======================================================================= #
def test_drain_box_mounts_only_triggered_corpora(tmp_path):
    """drain_mounts_only_triggered — the drain box mounts only the corpora that TRIGGERED this
    batch, not the static SHIPPED_LESSON_CORPORA union (M1: a static union would hand every
    batch write access to two corpora it will not touch). Asserts a corpus is mounted writable
    while the full shipped union is NOT — the untriggered siblings are absent from the writable
    mount set, checked on exact directory basenames (not the never-true single-mount 'source
    contains both sibling names' substring predicate this replaces)."""
    req = _drain_request(tmp_path)
    writable_names = {Path(m.source).name for m in req.mounts if m.writable}
    assert writable_names, "no writable corpus was mounted (positive control failed)"
    shipped = {"lessons", "lessons-actor", "lessons-environment"}
    assert not shipped.issubset(writable_names), \
        "the full SHIPPED_LESSON_CORPORA union was mounted writable, not the triggered subset"


def test_drain_rw_trees_inside_worktree_leaf_only(tmp_path):
    """drain_rw_confined_to_leaf (negative) — every RW mount of the drain box has its source
    inside the throwaway worktree leaf, never repo_root or the shared .worktrees parent
    (mounting one level up silently converts the blast radius to the live checkout, M1).
    Negative on any rw source escaping the leaf; positive control: a leaf-scoped rw mount is
    present."""
    req = _drain_request(tmp_path)
    leaf_base = str(tmp_path / "wt")
    writable = [m for m in req.mounts if m.writable]
    assert writable, "no writable drain mount was composed (positive control failed)"
    for m in writable:
        assert leaf_base in str(m.source), f"a drain rw mount {m.source} escaped the worktree leaf"


def test_drain_box_mount_set_regresses_to_full_corpus_union_instead_of_triggered_subset(tmp_path):
    """test_drain_box_mount_set_regresses_to_full_corpus_union_instead_of_triggered_subset —
    the mount set must always be exactly the triggered corpora, never the full
    SHIPPED_LESSON_CORPORA union (a regression O3/M1 explicitly rejects as unsafe). Asserts
    the drain request never carries all three shipped corpora at once."""
    req = _drain_request(tmp_path)
    sources = " ".join(str(m.source) for m in req.mounts)
    shipped = ("lessons", "lessons-actor", "lessons-environment")
    assert not all(s in sources for s in shipped), "the mount set regressed to the full corpus union"


def test_drain_leaf_mount_source_resolved_at_a_different_time_than_leaf_creation(tmp_path):
    """test_drain_leaf_mount_source_resolved_at_a_different_time_than_leaf_creation — the mount
    source is the EXACT leaf path start_batch returned, never an independently re-derived path
    landing at .worktrees/ or repo_root (M1: mounting one level up silently converts the blast
    radius). Asserts the drain box's rw mount source is under the batch's own leaf, not its
    parent."""
    req = _drain_request(tmp_path)
    parent = str((tmp_path / "wt").resolve())
    for m in req.mounts:
        if m.writable:
            assert str(Path(m.source).parent).startswith(parent), \
                "the drain rw mount source is outside the worktree base"
            assert Path(m.source) != Path(parent), \
                "the drain rw mount source is the .worktrees parent, not the specific leaf"


# ======================================================================= #
# gate ↔ mount reasoning (M3a / O3 / decision 1 / DC2)
# ======================================================================= #
def test_a_gate_approved_operand_resolves_to_a_path_absent_from_every_declared_mount(
    tmp_path, monkeypatch,
):
    """test_a_gate_approved_operand_resolves_to_a_path_absent_from_every_declared_mount — the
    gate-scope root list and the mount-derivation root list must stay in sync (M3a): no
    role/path pairing exists where a command clears the gate and only then hits a tree the box
    never mounted. Asserts every judge cat gate root is covered by a run-cycle mount."""
    req = _rc_request(tmp_path, monkeypatch)
    run_dir = tmp_path / "inv-665"
    for gate_root in (str(run_dir), str(DEFENDER), "gather_raw"):
        assert mount_for(req, gate_root) is not None, \
            f"gate root {gate_root} is approvable but absent from every declared mount"


def test_drain_infra_mount_exposes_non_triggered_corpus_to_gate_approved_read(tmp_path):
    """test_drain_infra_mount_exposes_non_triggered_corpus_to_gate_approved_read (F10 → R4) —
    the whole-worktree ro infra mount makes a sibling non-triggered corpus READABLE via a
    gate-approved cat/grep; this read-reachability is an ACCEPTED cost of the infra mount's
    width (recorded explicitly), while a WRITE to an untriggered sibling stays mechanically
    refused (its source is not among the rw mounts). Asserts the untriggered corpus is NOT a
    writable mount."""
    req = _drain_request(tmp_path)
    for m in req.mounts:
        if "lessons-environment" in str(m.source):
            assert m.writable is False, "an untriggered sibling corpus was mounted writable"


def test_curator_gate_scope_includes_untriggered_sibling_corpora_the_mount_deliberately_excludes(
    tmp_path,
):
    """test_curator_gate_scope_includes_untriggered_sibling_corpora_the_mount_deliberately_excludes
    (SB1 → R4) — the curator's read gate scope spans the three-corpus confine while the drain
    mount set is narrowed to the triggered subset; the doc does not draw gate scope and mount
    derivation from one shared source, so a gate-approved read can reach an unmounted sibling
    (accepted read-reachability) but a WRITE is refused by the absent rw mount. Asserts the
    triggered-only rw mount set."""
    req = _drain_request(tmp_path)
    writable_sources = " ".join(str(m.source) for m in req.mounts if m.writable)
    assert "lessons-environment" not in writable_sources, \
        "an untriggered sibling corpus the gate scope spans became writable"


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


def test_judge_cat_operand_reaches_defender_dir_beyond_its_declared_gate_roots(tmp_path):
    """test_judge_cat_operand_reaches_defender_dir_beyond_its_declared_gate_roots — defender_dir
    is not 'beyond' the judge's gate scope: the judge cat scope is built over exactly
    (run_dir, defender_dir, *read_roots), so a path under defender_dir is WITHIN what the gate
    intends the judge to read — the ro infra mount and the judge gate root coincide by design
    (M3b overlap is ordinary), not by accidental mount width."""
    from dataclasses import replace

    from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF
    from defender.runtime.agent_definition import ToolSet

    run_dir = tmp_path / "lrd"
    run_dir.mkdir()
    # Binds the benign leg's effective ToolSet (#632, §7 R7) — see test_665_box_geography.py's
    # _judge_deps for the same reasoning; this probe is about the cat gate scope, not the
    # verb grant.
    benign = replace(JUDGE_DEF, tools=ToolSet(read=True, bash=True, closed_tickets=True))
    policy = compile_policy_for(benign, run_dir, defender_dir=DEFENDER)
    decision = decide_bash(f"cat {DEFENDER / 'SKILL.md'}", policy=policy, run_dir=run_dir,
                           defender_dir=DEFENDER, cwd_anchor=run_dir)
    assert decision.allow, "defender_dir is one of the judge's declared cat gate roots, not beyond it"


# ======================================================================= #
# The actor anchor move (decision 1) + N3/N4/S6 containment (host-side gate)
# ======================================================================= #
def test_actor_cwd_anchor_is_repo_root(tmp_path):
    """actor_cwd_anchor_repo_root (decision 1) — the actor's cwd_anchor moves to repo_root
    (defender_dir.parent), so a relative `python3 defender/...` operand resolves against the
    repo root inside the box. At HEAD the actor anchors at learning_run_dir — the issue's
    failure mode."""
    deps = _actor_deps(tmp_path / "lrd")
    assert deps.cwd_anchor == REPO_ROOT, \
        f"actor cwd_anchor is {deps.cwd_anchor}, not repo_root (still anchored at learning_run_dir)"


def test_actor_read_file_resolves_relative_against_repo_root(tmp_path):
    """actor_read_file_resolves_repo_root — the actor's read tool rebases a RELATIVE operand
    against the new repo_root anchor, so `defender/SKILL.md` resolves under repo_root, not under
    learning_run_dir."""
    from defender.runtime.tools import _resolve_operand

    deps = _actor_deps(tmp_path / "lrd")
    resolved = _resolve_operand(deps, "defender/SKILL.md")
    assert resolved == (REPO_ROOT / "defender" / "SKILL.md"), \
        f"a relative actor read operand resolved to {resolved}, not against repo_root"


def test_actor_pinned_script_operand_spelling_survives_anchor_move(tmp_path):
    """test_actor_pinned_script_operand_spelling_survives_anchor_move (decision 1) — both the
    relative and the absolute spelling of the actor's pinned script still resolve after the
    anchor move to repo_root: the pins_path grant admits either spelling."""
    deps = _actor_deps(tmp_path / "lrd", scripts=(PINNED,))
    rel = PINNED.relative_to(REPO_ROOT)
    for spelling in (str(PINNED), str(rel)):
        d = decide_bash(f"python3 {spelling}", policy=deps.policy, run_dir=tmp_path / "lrd",
                        defender_dir=DEFENDER, cwd_anchor=deps.cwd_anchor)
        assert d.allow, f"pinned-script spelling {spelling!r} was refused after the anchor move"


def test_actor_read_tool_rebase_stays_within_read_confine(tmp_path):
    """test_actor_read_tool_rebase_stays_within_read_confine (po53) — moving the actor anchor
    cannot widen or narrow read_confine: decide_read's confine check takes (policy, run_dir,
    defender_dir), never cwd_anchor, so the read confinement is bit-for-bit unchanged whether
    the actor anchors at learning_run_dir or repo_root (gate-independence, po53 confirmed)."""
    from defender.learning.pipeline.actor_engine import ACTOR_DEF

    confine = (tmp_path / "lrd",)
    p1 = compile_policy_for(ACTOR_DEF, tmp_path / "lrd",
                            scope=RunScope(read_confine=confine), defender_dir=DEFENDER)
    assert p1.read_confine == tuple(confine), \
        "the actor read_confine changed under the anchor move (decide_read is not anchor-blind)"


def test_actor_bash_grant_has_no_file_opening_verb(tmp_path):
    """actor_no_file_opening_grant (negative) — the actor shares a box whose mount set is the
    union of both roles' needs, but its entire bash grant is `python3 <pinned script>` — no
    `cat`, no `grep`, no file-opening verb (N4), so nothing on the bash lane can open a file
    across the wider shared mount. Negative on any file-opening program; positive control: the
    pinned python3 grant is present."""
    policy = compile_policy_for(
        ACTOR_DEF, tmp_path / "lrd",
        scope=RunScope(read_confine=(tmp_path / "lrd",), scripts=(PINNED,)), defender_dir=DEFENDER)
    programs = {g.program for g in policy.bash_allow}
    assert programs == {"python3"}, f"the actor grant carries a file-opening verb: {programs}"


def test_actor_bash_grant_opens_no_file_over_any_reachable_in_box_tree(tmp_path):
    """test_actor_bash_grant_opens_no_file_over_any_reachable_in_box_tree — driving the actor's
    gate over a `cat`/`grep` of any tree reachable in the shared box (judge evidence, the
    package tree, a sibling leg's writes) is refused: the safety argument is the ABSENCE of a
    file-opening verb, not mount narrowing. Negative over the shared box's reachable trees;
    positive control: the actor's one pinned command still runs."""
    deps = _actor_deps(tmp_path / "lrd", scripts=(PINNED,))
    for target in (DEFENDER / "SKILL.md", tmp_path / "lrd" / "gather_raw" / "x.json"):
        for verb in ("cat", "grep -n x"):
            d = decide_bash(f"{verb} {target}", policy=deps.policy, run_dir=tmp_path / "lrd",
                            defender_dir=DEFENDER, cwd_anchor=deps.cwd_anchor)
            assert not d.allow, f"the actor opened {target} via {verb!r} across the shared box"
    ok = decide_bash(f"python3 {PINNED}", policy=deps.policy, run_dir=tmp_path / "lrd",
                     defender_dir=DEFENDER, cwd_anchor=deps.cwd_anchor)
    assert ok.allow, "the actor's one pinned command was refused (positive control failed)"


def test_cross_leg_shared_writable_surface_is_bounded(tmp_path):
    """test_cross_leg_shared_writable_surface_is_bounded — the actor and judge share one box, so
    the box exposes trees the actor's own read confinement exists to replace; the gate is the
    enforcer (N4/S6): the actor still cannot open any file over the shared writable surface.
    Asserts the actor gate refuses a write/read of a sibling-written path in the shared box."""
    deps = _actor_deps(tmp_path / "lrd", scripts=(PINNED,))
    sibling_written = tmp_path / "lrd" / "actor_benign_story.md"
    d = decide_bash(f"cat {sibling_written}", policy=deps.policy, run_dir=tmp_path / "lrd",
                    defender_dir=DEFENDER, cwd_anchor=deps.cwd_anchor)
    assert not d.allow, "the actor read a sibling leg's write across the shared box surface"


def test_pinned_script_argv_carries_extra_arguments_beyond_the_pinned_path(tmp_path):
    """test_pinned_script_argv_carries_extra_arguments_beyond_the_pinned_path — pins_path=True
    means the gate never resolves the operand, so extra positional args/flags after the pinned
    script path pass the gate UNEXAMINED; containment against a hostile extra argument relies
    entirely on the pinned script's own behavior (the S6 live-owed probe), not on gate-level
    argv restriction. Asserts the gate admits extra argv."""
    deps = _actor_deps(tmp_path / "lrd", scripts=(PINNED,))
    d = decide_bash(f"python3 {PINNED} --hostile /etc/passwd extra",
                    policy=deps.policy, run_dir=tmp_path / "lrd", defender_dir=DEFENDER,
                    cwd_anchor=deps.cwd_anchor)
    assert d.allow, "pins_path unexpectedly examined the extra argv (the reliance is on the script)"


# ======================================================================= #
# N3 — the host-side write tools never cross the box; the scan (S7)
# ======================================================================= #
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


def test_rw_tree_scan_lands_before_commit_push(tmp_path):
    """scan_before_supply_chain — the S7 scan of the written rw tree lands BEFORE finish_batch's
    commit+push+PR (the supply-chain path into the corpus), and AFTER the box is torn down (the
    rw bind released, so the scan reads a static tree): the recorded order is stop → scrub →
    finish_batch. Asserts the scan itself (box_mod.scrub, observed through the injected `scrub=`
    seam) actually RAN and landed strictly between box teardown and finish_batch — not merely
    that teardown precedes finish_batch."""
    log: list[str] = []
    rec = BoxLifecycleRecorder(events=log)
    branch = RecordingBranch(tmp_path / "wt", events=log)
    drive_worktree_batch(tmp_path, rec, do_work=lambda wt, *, box=None: None, branch=branch)
    assert rec.boxes, "no drain box was created"
    assert rec.scrubbed, "the S7 tree scan (scrub) never ran before the supply-chain step"
    assert branch.finished, "no finish_batch was recorded"
    stop_i = log.index(f"stop:{rec.boxes[0].name}")
    scrub_i = next(i for i, e in enumerate(log) if e.startswith("scrub:"))
    finish_i = log.index(f"finish_batch:{branch.finished[0]}")
    assert stop_i < scrub_i < finish_i, \
        "the S7 scan did not land between box teardown and finish_batch (commit saw a tree the scan had not cleared)"


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


def test_run_cycle_in_run_consumer_reads_a_file_a_concurrent_leg_can_still_mutate(tmp_path, monkeypatch):
    """test_run_cycle_in_run_consumer_reads_a_file_a_concurrent_leg_can_still_mutate — a
    dec8-ACCEPTED residual: the per-leg consumers (persist_run/append_findings) run host-side
    while the shared run-cycle box is still alive, so a consumer can read a file a concurrent
    leg can still mutate. The box is torn down once at run end, AFTER both legs — the accepted
    ordering. Asserts a single teardown at run end (not per-leg)."""
    rec = BoxLifecycleRecorder()
    drive_run_one(tmp_path, monkeypatch, rec, disposition="inconclusive")  # TypeError at HEAD → red
    assert len(rec.boxes) == 1, "more than one run-cycle box was created for the invocation"
    assert rec.stopped == rec.boxes, \
        "the shared box was torn down per-leg, not once at run end (dec8 residual)"
