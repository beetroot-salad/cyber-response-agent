"""#691 curator-bindable — the read scope (O6/R4) and the explicit-tree requirement (M3).

RED against HEAD by design. Two mechanisms this file pins:

* **R4 read confine.** The curator declares ``requires_confine=True`` with the confine set to the
  three shipped lesson corpora; ``_resolved_read_roots`` REPLACES the ``defender_dir`` base with the
  confine. Observable matrix (P2d executed): a SIBLING corpus ``lesson_read`` ALLOWs (the confine
  spans all three), ``defender/docs`` and ``defender/SKILL.md`` flip ALLOW→DENY, the spawn's OWN
  run dir stays ALLOW, and the bash ``cat`` scope stays own-corpus (sibling ``cat`` DENY — the
  deliberate divergence from ``lesson_read``). Today ``for_run``'s policy carries ``read_confine=()``
  so a ``docs`` read is ALLOWED through the wide ``defender_dir`` base — that is the RED, each
  read-negative failing on its own assertion (the confine correction is unbuilt).

  REFUTED, not pinned: c17/g10 "M2 narrows read_allow to the corpus shape" (read_allow stays EMPTY,
  the confine carries the narrowing on the roots half); c20's own-corpus-only runtime-safety reading
  (the committed suite pins the CROSS-corpus reads, and R4 KEEPS them).

* **M3 explicit tree.** Binding the curator with no explicit NON-PATHS ``defender_dir`` raises — the
  main-checkout-authoring state is unbuildable. Driven through the binding seam ``bind``; RED today
  (``bindable=False`` raises first — the message assertion pins that the DEMANDED tree refusal is
  what a green #0 must surface, not the incidental unbindable error).

Gate lanes are driven through the shared harness (``read_decision`` → ``decide_read`` roots+shapes,
``bash_decision`` → ``decide_bash`` cat scope, ``forward_check_gate`` → ``decide_write``); the
CuratorDeps under test is the STABLE ``for_run`` deps whose ``.policy`` the refactor re-anchors.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender._paths import PATHS  # noqa: E402
from defender.runtime.agent_definition import RunScope, bind  # noqa: E402
from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF  # noqa: E402

from _curator_691_harness import (  # noqa: E402
    bash_decision,
    confine,
    corpus,
    curator_deps,
    forward_check_gate,
    make_worktree,
    pending_run_dir,
    read_decision,
    rel,
    write_file,
)


def _reads(deps, path: str) -> bool:
    """Whether the lesson-read lane (``decide_read`` — roots + shapes) admits ``path``."""
    return read_decision(deps, path).allow


def _cats(deps, path: str) -> bool:
    """Whether the bash ``cat`` lane admits ``path`` (its grant scope, own-corpus only)."""
    return bash_decision(deps, f"cat {path}").allow


# ===========================================================================
# O6 / R4 — the read confine
# ===========================================================================

def test_the_curator_declares_requires_confine_over_the_three_corpora(tmp_path):
    """The curator's read reach is the three-corpus confine, not the whole tree: a read of a
    sibling corpus lesson ALLOWs while a read of ``defender/docs`` and ``defender/SKILL.md`` — real
    files INSIDE the tree but outside every lesson corpus — DENYs. RED today: ``for_run``'s policy
    carries ``read_confine=()``, so the wide ``defender_dir`` base admits docs/SKILL."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert _reads(deps, rel("lessons-actor", "sib.md"))          # confine spans the three
    assert not _reads(deps, "defender/docs/design.md")           # outside the confine → DENY
    assert not _reads(deps, "defender/SKILL.md")                 # outside the confine → DENY


def test_the_read_view_must_span_three_corpora_while_the_shell_view_stays_at_one(tmp_path):
    """One spawn, two surfaces required to DISAGREE: ``lesson_read`` of a sibling-corpus lesson is
    ALLOW (the confine spans all three corpora), but ``cat`` of that SAME path is DENY (the bash
    scope is own-corpus only). The read view and the shell view are deliberately different reaches."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    sib = rel("lessons-actor", "sib.md")
    assert _reads(deps, sib)          # lesson_read spans the confine
    assert not _cats(deps, sib)       # cat stays at one corpus


def test_a_read_inside_the_spawns_tree_but_outside_every_lesson_corpus(tmp_path):
    """NEGATIVE + control: a read of ``defender/docs/*.md`` and ``defender/SKILL.md`` — inside the
    worktree but outside every lesson corpus — DENYs under the confine; the spawn's OWN run-dir file
    stays ALLOW (the run dir is a read root independent of the confine). RED today: docs/SKILL are
    admitted through the wide ``defender_dir`` base the confine has not yet replaced."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    (rd / "note.md").write_text("x\n", encoding="utf-8")
    deps = curator_deps(wt, rd, "lessons")
    assert not _reads(deps, "defender/docs/design.md")           # negative: docs
    assert not _reads(deps, "defender/SKILL.md")                 # negative: SKILL
    assert _reads(deps, str(rd / "note.md"))                     # positive control: own run dir


def test_two_spawns_in_one_batch_reach_into_each_others_corpora(tmp_path):
    """Cross-corpus READS between same-batch spawns are intended and allowed; cross-corpus WRITES
    stay refused. Spawn-A (corpus ``lessons``) may ``lesson_read`` a ``lessons-actor`` lesson, but a
    ``write_file`` into ``lessons-actor`` is denied (ModelRetry). The read widened, the write did not."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    a = curator_deps(wt, rd, "lessons")
    assert _reads(a, rel("lessons-actor", "peer.md"))            # cross-corpus read ALLOW
    with pytest.raises(ModelRetry):                               # cross-corpus write DENY
        write_file(a, rel("lessons-actor", "evil.md"), "body\n")
    assert not (corpus(wt, "lessons-actor") / "evil.md").exists()  # nothing landed cross-corpus


def test_the_committed_reachability_difference_between_the_read_surface_and_the_shell_surface(tmp_path):
    """The committed #559 property, R6-repaired to be discriminating on a REAL sibling path: the
    lesson-read surface reaches the sibling corpus (ALLOW) while the shell (``cat``) surface does not
    (DENY). Both halves survive R4 — the divergence is the point, not an accident of an empty read."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    (corpus(wt, "lessons-environment") / "real.md").write_text("lesson\n", encoding="utf-8")
    deps = curator_deps(wt, rd, "lessons")
    sib = rel("lessons-environment", "real.md")
    assert _reads(deps, sib)          # read surface: reaches the sibling
    assert not _cats(deps, sib)       # shell surface: does not


def test_a_lesson_corpus_is_added_to_the_tree_after_the_scope_was_written(tmp_path):
    """The confine is a STATIC three-name declaration: a FOURTH lesson-shaped dir added to the tree
    (``defender/lessons-extra``) is DENIED even though it looks like a corpus — the gate (the static
    confine) and the matcher (a new dir on disk) diverge. Positive control: a read inside one of the
    three declared corpora ALLOWs. RED today: the wide ``defender_dir`` base admits the fourth dir."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    (wt / "defender" / "lessons-extra").mkdir(parents=True, exist_ok=True)
    deps = curator_deps(wt, rd, "lessons")
    assert not _reads(deps, "defender/lessons-extra/x.md")       # fourth corpus DENY (static confine)
    assert _reads(deps, rel("lessons-actor", "in.md"))           # control: a declared corpus ALLOW


def test_read_allow_stays_single_corpus_after_r4_and_the_confine_carries_the_narrowing(tmp_path):
    """``read_allow`` (the cat scope) stays SINGLE-corpus and untouched while the CONFINE carries the
    reach-narrowing on the roots half — the two are independent axes, neither re-derived from the
    other. Observable: sibling ``cat`` DENY (the single-corpus cat scope) yet sibling ``lesson_read``
    ALLOW (the three-corpus confine on the roots half). NOT pinned: read_allow gaining the corpus
    shape (c17/g10 refuted)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    sib = rel("lessons-actor", "s.md")
    assert not _cats(deps, sib)       # cat scope: own corpus only (single)
    assert _reads(deps, sib)          # confine (roots half): spans the three


def test_a_spawn_reads_the_queue_it_was_spawned_over(tmp_path):
    """A read of the spawn's OWN run dir is ALLOW, before and after the change — the run dir is a
    read root independent of the confine (P2d). A file dropped in the run dir is readable."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    (rd / "queued.json").write_text("{}\n", encoding="utf-8")
    deps = curator_deps(wt, rd, "lessons")
    assert _reads(deps, str(rd / "queued.json"))


def test_corpus_name_names_no_corpus_among_the_three_shipped_lesson_corpora(tmp_path):
    """The READ reach is the SAME fixed three-corpus confine for EVERY curator spawn regardless of
    its own name (promoted P64): a spawn named ``lessons`` and a spawn named ``lessons-actor`` both
    ALLOW a read of ``lessons-environment`` and both DENY a read of ``defender/docs`` — the confine
    is the same set, not a per-spawn own-corpus reach. RED today for the docs half (wide base)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    for name in ("lessons", "lessons-actor"):
        deps = curator_deps(wt, rd, name)
        assert _reads(deps, rel("lessons-environment", "z.md"))  # same confine for every spawn
        assert not _reads(deps, "defender/docs/x.md")            # and it excludes docs, for every spawn


def test_the_forward_checks_own_lesson_gate_after_the_read_scope_widens(tmp_path):
    """The forward_check tool's own lesson gate (``_gate_lesson_path`` → ``decide_write``) still
    REFUSES a sibling-corpus operand — it rides the write gate, which R4 does not touch. An own-corpus
    operand is admitted (returns a Path); a sibling operand raises ModelRetry. Unchanged by the read
    widening (x4)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert forward_check_gate(deps, rel("lessons", "own.md"))    # own corpus: admitted
    with pytest.raises(ModelRetry):                               # sibling: refused
        forward_check_gate(deps, rel("lessons-actor", "sib.md"))


def test_the_curator_reads_no_longer_reach_defender_docs(tmp_path):
    """The prompt line that named ``defender/docs/…`` is denied after the confine (g13): a read of a
    ``defender/docs`` path DENYs while the curator's own-corpus read still ALLOWs (control). RED
    today: the wide ``defender_dir`` base admits docs; R5 additionally updates the prompt line."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert not _reads(deps, "defender/docs/learning-loop.md")    # the prompt-named docs path: DENY
    assert _reads(deps, rel("lessons", "own.md"))                # control: own corpus still reads


# ===========================================================================
# M3 — the explicit worktree tree (the binding seam raises without one)
# ===========================================================================

_EXPLICIT_TREE = r"explicit NON-PATHS defender_dir"


def _bind_no_tree(wt, rd, defender_dir):
    """Bind the curator through the seam with the given (mis-scoped) tree, no corpus_name field in
    play — isolates the M3 tree check. A bare-confine RunScope avoids the not-yet-built corpus_name
    field so the raise under test is the TREE refusal, not a missing-field error."""
    return bind(CORPUS_AUTHOR_DEF, rd, scope=RunScope(read_confine=confine(wt)), defender_dir=defender_dir)


def test_binding_the_curator_without_an_explicit_tree_raises(tmp_path):
    """The main-checkout-authoring state is UNBUILDABLE: binding the curator with no explicit
    NON-PATHS ``defender_dir`` raises, naming the tree requirement. Positive control: the stable
    ``for_run`` drain path (an explicit worktree tree) authors an in-corpus lesson. RED today: the
    seam raises the incidental ``bindable=False`` message, not the demanded tree refusal."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=_EXPLICIT_TREE):
        _bind_no_tree(wt, rd, None)
    write_file(curator_deps(wt, rd, "lessons"), rel("lessons", "ok.md"), "body\n")  # control: authors
    assert (corpus(wt, "lessons") / "ok.md").read_text() == "body\n"


def test_defender_dir_is_none_for_a_role_that_requires_an_explicit_tree(tmp_path):
    """``defender_dir=None`` for the tree-requiring curator raises "requires an explicit NON-PATHS
    defender_dir" (g16/P10) — a None tree would author the MAIN checkout. RED today (bindable message)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=_EXPLICIT_TREE):
        _bind_no_tree(wt, rd, None)


def test_defender_dir_is_the_main_checkout_paths_value(tmp_path):
    """``defender_dir=PATHS.defender_dir`` (the MAIN checkout) raises IDENTICALLY to the ``None`` case
    — the two collapse to the same refusal, so the curator can never anchor on the main tree (g16/P10)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=_EXPLICIT_TREE):
        _bind_no_tree(wt, rd, PATHS.defender_dir)


def test_an_operator_runs_a_curator_entrypoint_against_the_working_checkout(tmp_path):
    """An operator invoking a curator entrypoint against the working checkout (the MAIN tree) is
    refused at bind — "requires an explicit NON-PATHS defender_dir" — instead of silently proceeding
    into the main checkout (a-P9). Control: the in-worktree drain path authors unchanged."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=_EXPLICIT_TREE):
        _bind_no_tree(wt, rd, PATHS.defender_dir)
    write_file(curator_deps(wt, rd, "lessons-actor"), rel("lessons-actor", "d.md"), "b\n")  # drain OK


def test_the_drain_path_still_authors_after_the_entrypoints_break(tmp_path):
    """SURVIVAL (c5): the drain supplies an explicit worktree tree and keeps authoring unchanged —
    the positive control for R2's accepted entrypoint breakage. The in-worktree ``for_run`` deps
    admits an in-corpus ``.md`` write; a sibling-corpus write is still refused."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons-environment")
    write_file(deps, rel("lessons-environment", "authored.md"), "body\n")     # authors
    assert (corpus(wt, "lessons-environment") / "authored.md").read_text() == "body\n"
    with pytest.raises(ModelRetry):
        write_file(deps, rel("lessons", "x.md"), "body\n")                     # still scoped


def test_every_curator_spawn_reports_the_same_run_identity(tmp_path):
    """All four spawn configs (two of them naming ``lessons-environment``) share ONE run identity:
    ``run_id == "_pending"`` and one run dir, while each authors its own corpus. The per-spawn corpus
    name is NOT a run identifier (P4) — the shared ``_pending`` sink is the R2 shared-sink territory."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    spawn_corpora = ("lessons", "lessons-actor", "lessons-environment", "lessons-environment")
    deps = [curator_deps(wt, rd, name) for name in spawn_corpora]
    assert all(d.run_id == "_pending" for d in deps)             # one run identity for every spawn
    assert len({d.run_dir for d in deps}) == 1                   # one shared run dir
