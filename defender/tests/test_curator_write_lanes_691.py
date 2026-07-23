"""#691 — the curator's WRITE-capable lanes (O2/S1-S4 + MD-1/MD-3/MD-4/MD-5/MD-7).

Executable spec (write-tests phase E), RED against HEAD where it pins a correction. Every test
drives a REAL gate through the shared harness (`_curator_691_harness`): `write_file`/`edit_file`
raise `ModelRetry` on a `decide_write` deny and LAND the file on allow; `bash_decision(...).allow`
is the rm lane; `forward_check_gate` is the fourth write-capable lane. Gate tests build the deps
through the stable `for_run` entry point (M9 keeps it); MD-1 drives the binding seam itself.

Corrections pinned here (NOT the refuted behaviour):
  * MD-1 / D1 (RG-1): a curator whose write scope roots OUTSIDE its read confine is unbuildable —
    bind REFUSES it (R4's "write byte-identical to today" clause was struck).
  * MD-3 (RG-adv4): the rm grant never `resolve()`s, so a symlink out of corpus it DELETES while
    the other three lanes deny — the correction is all FOUR lanes agree (deny).
  * MD-7 / F77 / f7 (D3): the write lane is narrowed to the read segment class, so the write and
    read lanes admit EXACTLY the same lesson filenames (a space/newline name write=True read=False,
    x6, is the pinned bug — the correction is the write REFUSES it).
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from _curator_691_harness import (  # noqa: E402
    bash_decision,
    bind_curator,
    corpus,
    curator_deps,
    edit_file,
    forward_check_gate,
    lesson_read,
    make_worktree,
    pending_run_dir,
    rel,
    write_file,
)


# The both-surfaces pairing lives in the file (not the harness) so the intent — a policy tight on
# write_file but loose on edit_file is the fail-open — stays visible at each call site.
def _denied_on_both_write_surfaces(deps, path: str) -> None:
    with pytest.raises(ModelRetry):
        write_file(deps, path, "body\n")
    with pytest.raises(ModelRetry):
        edit_file(deps, path, "", "body\n")


def _admitted_in_corpus(wt, deps, corpus_name: str, stem: str = "lesson") -> None:
    r = rel(corpus_name, f"{stem}.md")
    landed = corpus(wt, corpus_name) / f"{stem}.md"
    write_file(deps, r, "body\n")               # admitted → lands
    assert landed.read_text() == "body\n"
    edit_file(deps, r, "body\n", "edited\n")     # admitted → real in-place edit
    assert landed.read_text() == "edited\n"


# ===========================================================================
# O2 / S1 / S4 — the write scope roots at the worktree corpus, not run_dir
# ===========================================================================

def test_write_allow_roots_at_the_worktree_corpus_not_run_dir(tmp_path):
    """The compiled write scope roots at <worktree>/defender/<corpus>, NOT run_dir: an in-corpus
    .md write LANDS on both write surfaces, a run_dir .md write is DENIED on both. Fails if the
    scope roots at run_dir (the #691 done-criterion) — a bind-built-at-run_dir policy would ADMIT
    the run_dir write."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    _admitted_in_corpus(wt, deps, "lessons")                  # roots at the worktree corpus
    _denied_on_both_write_surfaces(deps, str(rd / "scratch.md"))  # NOT run-dir-rooted


def test_the_run_directory_and_the_authored_tree_are_the_same_tree(tmp_path):
    """They are NOT the same tree: run_dir is <MAIN>/defender/learning/_pending, the authored tree
    is the worktree (the production shape on every drained batch, P4). A write lands in the worktree
    corpus while a same-named write into run_dir denies — the two trees are distinct."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert corpus(wt, "lessons").resolve() != rd.resolve()
    assert rd.resolve() not in corpus(wt, "lessons").resolve().parents
    _admitted_in_corpus(wt, deps, "lessons")
    _denied_on_both_write_surfaces(deps, str(rd / "lesson.md"))


def test_the_curator_cannot_write_outside_its_own_corpus(tmp_path):
    """A write/edit to a SIBLING corpus, to run_dir, and to the MAIN checkout (defender/skills) is
    DENIED on BOTH write surfaces and nothing lands; the own-corpus .md write succeeds (control).
    Binds every write surface the operand could reach (write_file + edit_file)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    _denied_on_both_write_surfaces(deps, rel("lessons-actor", "x.md"))    # a sibling corpus
    _denied_on_both_write_surfaces(deps, str(rd / "x.md"))                # run_dir
    _denied_on_both_write_surfaces(deps, "defender/skills/x.md")          # MAIN checkout, not the corpus
    assert not (corpus(wt, "lessons-actor") / "x.md").exists()            # nothing landed cross-corpus
    _admitted_in_corpus(wt, deps, "lessons")                             # positive control


def test_the_curator_cannot_write_a_non_md_path(tmp_path):
    """A non-.md write UNDER the corpus (.py, .txt, no extension) is DENIED on both surfaces
    (build_write_allow suffix='.md'); the sibling .md write succeeds (control)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    for bad in ("note.py", "note.txt", "noext"):
        _denied_on_both_write_surfaces(deps, rel("lessons", bad))
    _admitted_in_corpus(wt, deps, "lessons")


def test_a_write_operand_filename_is_the_empty_string(tmp_path):
    """An empty filename (the corpus dir itself, no basename) cannot satisfy the `.md` suffix and is
    refused on both surfaces; a real .md name succeeds (control)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    _denied_on_both_write_surfaces(deps, "defender/lessons/")   # empty basename
    _admitted_in_corpus(wt, deps, "lessons")


def test_a_write_operand_filename_has_no_extension(tmp_path):
    """A write of an extension-less filename under the corpus is refused on both surfaces; the
    sibling .md write succeeds (control)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    _denied_on_both_write_surfaces(deps, rel("lessons", "lessonfile"))
    _admitted_in_corpus(wt, deps, "lessons")


def test_a_write_operand_filename_extension_differs_only_in_letter_case_from_md(tmp_path):
    """`.MD` is refused on both surfaces — the compiled tail is a literal `\\.md` with no case flag
    (g8's observed pattern); the lowercase `.md` write succeeds (control)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    _denied_on_both_write_surfaces(deps, rel("lessons", "LESSON.MD"))
    _admitted_in_corpus(wt, deps, "lessons")


def test_a_write_operand_path_is_given_relative_with_a_leading_dot_slash(tmp_path):
    """`./defender/lessons/x.md` resolves identically to `defender/lessons/x.md` against the same
    cwd_anchor and is ADMITTED — the write lands at the one corpus path either spelling names
    (f14/P11)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    write_file(deps, "./" + rel("lessons", "dot.md"), "body\n")
    assert (corpus(wt, "lessons") / "dot.md").read_text() == "body\n"


# ===========================================================================
# MD-1 (RG-1 / D1) — a mis-scoped curator is unbuildable (refuse at bind)
# ===========================================================================

def test_a_non_shipped_corpus_name_write_is_denied_by_confine_containment(tmp_path):
    """MD-1 / D1: a curator whose write scope roots OUTSIDE its own read confine is UNBUILDABLE —
    bind REFUSES a name (e.g. `skills`) M7 shape-admits but that sits outside the three-corpus
    confine (RG-1: `_resolved_read_roots` replaces the defender_dir base, so decide_write's
    containment half denies every such write). §7 D1 pinned refuse-at-bind (a scope that cannot
    author is unbuildable) and STRUCK R4's 'write byte-identical to today' clause. The raise must
    NAME the scope/confine mismatch, so it is the DEMANDED refusal, not the incidental bindable=False.
    Positive control: an in-confine corpus builds cleanly and authors."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    with pytest.raises(ValueError, match=r"confine|scope|outside|author|contain"):
        bind_curator(wt, rd, "skills")                       # skills ∉ the three-corpus confine
    deps = bind_curator(wt, rd, "lessons")                    # in-confine → buildable (control)
    write_file(deps, rel("lessons", "ok.md"), "body\n")
    assert (corpus(wt, "lessons") / "ok.md").read_text() == "body\n"


def test_a_shipped_corpus_write_is_denied_when_its_read_confine_excludes_it(tmp_path):
    """MD-1 / D1 ISOLATED from MD-6 (the F18 scenario). A SHIPPED corpus name — one MD-6's exact-match
    membership ACCEPTS (`lessons`) — is bound with a read confine that EXCLUDES that very corpus, so the
    compiled write scope roots OUTSIDE its own read confine. bind REFUSES it (§7 D1 pinned refuse-at-bind:
    a scope that cannot author is unbuildable; RG-1: `_resolved_read_roots` REPLACES the defender_dir
    base, so decide_write's containment half would deny every such write). This isolates MD-1 from MD-6:
    the name is membership-ACCEPTED, so only MD-1's confine-containment check can refuse it — an
    implementation that ships MD-6 but omits MD-1 fails HERE, on the confine mismatch, not on membership.
    The raise must NAME the scope/confine mismatch so it is the DEMANDED refusal, not the incidental
    bindable=False. Positive control: the SAME shipped corpus, bound with a confine that INCLUDES it,
    binds cleanly and authors."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    excludes_lessons = (
        corpus(wt, "lessons-actor").resolve(),
        corpus(wt, "lessons-environment").resolve(),
    )                                                              # a confine that omits `lessons`
    with pytest.raises(ValueError, match=r"confine|scope|outside|author|contain"):
        bind_curator(wt, rd, "lessons", read_confine=excludes_lessons)  # write scope ⊄ the confine
    includes_lessons = (corpus(wt, "lessons").resolve(),)        # a confine that CONTAINS `lessons`
    deps = bind_curator(wt, rd, "lessons", read_confine=includes_lessons)  # buildable (control)
    write_file(deps, rel("lessons", "ok.md"), "body\n")
    assert (corpus(wt, "lessons") / "ok.md").read_text() == "body\n"


# ===========================================================================
# S3 / MD-3 / MD-4 / MD-5 — the rm lane and the four-lane parity
# ===========================================================================

def test_the_rm_lane_is_scoped_to_the_same_corpus_as_the_write_lane(tmp_path):
    """Parity: the rm grant admits exactly the spawn's OWN corpus, the same set the write lane
    admits — `rm defender/lessons/x.md` ALLOW, a sibling corpus DENY, a flag or a second path DENY;
    the own-corpus single rm is the control."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert bash_decision(deps, "rm defender/lessons/draft.md").allow          # own corpus (control)
    assert not bash_decision(deps, "rm defender/lessons-actor/draft.md").allow  # sibling
    assert not bash_decision(deps, "rm -rf defender/lessons/draft.md").allow    # a flag
    assert not bash_decision(deps, "rm defender/lessons/a.md defender/lessons/b.md").allow  # two paths


def test_all_four_write_lanes_deny_a_symlink_out_of_corpus(tmp_path):
    """MD-3 (RG-adv4, the standout): one crafted operand — a symlink under the corpus pointing at a
    sibling corpus, so `defender/lessons/escape/secret.md` RESOLVES out of the corpus — presented to
    all FOUR write-capable lanes must be DENIED by every one. RED against HEAD: the rm grant never
    `resolve()`s, so it DELETES the out-of-corpus target (write_file/edit_file/forward_check deny) —
    the correction is the rm lane `resolve()`s + rechecks containment and all four AGREE. Positive
    control: an in-corpus operand is ADMITTED by all four."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    # a symlink inside the corpus pointing at the sibling corpus
    (corpus(wt, "lessons") / "escape").symlink_to(corpus(wt, "lessons-actor"))
    escape = "defender/lessons/escape/secret.md"          # resolves to lessons-actor/secret.md
    # all four lanes must DENY the escaping operand
    with pytest.raises(ModelRetry):
        write_file(deps, escape, "body\n")
    with pytest.raises(ModelRetry):
        edit_file(deps, escape, "", "body\n")
    with pytest.raises(ModelRetry):
        forward_check_gate(deps, escape)
    assert not bash_decision(deps, f"rm {escape}").allow   # RED today: the rm grant deletes it
    assert not (corpus(wt, "lessons-actor") / "secret.md").exists()  # the escape wrote nothing
    # positive control: an in-corpus operand admitted by all four lanes
    (corpus(wt, "lessons") / "real.md").write_text("body\n", encoding="utf-8")
    write_file(deps, rel("lessons", "real.md"), "body\n")
    edit_file(deps, rel("lessons", "real.md"), "body\n", "edited\n")
    # the forward_check lane ADMITS the in-corpus operand: it returns the resolved in-corpus path
    # (a deny would raise ModelRetry instead), so the returned path is a real observable that fails
    # if the gate wrongly denied a legitimate in-corpus write.
    gated = forward_check_gate(deps, rel("lessons", "real.md"))
    assert gated.resolve() == (corpus(wt, "lessons") / "real.md").resolve()
    assert bash_decision(deps, "rm " + rel("lessons", "real.md")).allow


def test_the_rm_grant_matches_the_shell_tokenized_argv(tmp_path):
    """MD-4 (RG-adv3): a `$(...)`/backtick operand DENIES because the shell TOKENIZER splits the
    substitution into separate tokens before the grant matches (NOT because of `_stage_unsafe`,
    which is dead code for this shape), and a `;`-joined command denies on the ungranted second
    stage. Positive control: a plain single-operand in-corpus rm is admitted."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert not bash_decision(deps, "rm defender/lessons/$(whoami).md").allow
    assert not bash_decision(deps, "rm defender/lessons/`whoami`.md").allow
    assert not bash_decision(deps, "rm defender/lessons/x.md; echo hi").allow
    assert bash_decision(deps, "rm defender/lessons/draft.md").allow          # positive control


def test_a_single_operand_in_corpus_rm_is_admitted(tmp_path):
    """MD-5 (RG-ispo4): a single in-corpus `rm defender/lessons/draft.md` is ADMITTED — the curator
    promotes or discards one draft. This is the positive control the degenerate-name negative
    (test_the_rm_grant_under_a_degenerate_empty_or_dot_corpus_name) lacks (RF2)."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert bash_decision(deps, "rm defender/lessons/draft.md").allow


def test_the_rm_grant_under_a_degenerate_empty_or_dot_corpus_name(tmp_path):
    """A degenerate corpus name ("" or ".") is rejected by M7 BEFORE any grant is compiled (K4), so
    no admitting rm grant is ever built — binding such a curator RAISES. Its paired positive control
    is test_a_single_operand_in_corpus_rm_is_admitted (an ACCEPTED name admits an in-corpus rm), so
    this negative is not vacuous (RF2). RED against HEAD: M7's single-segment rule is not built."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    for degenerate in ("", "."):
        # strict ValueError (M7's rejection), NOT a bare TypeError from the not-yet-built
        # corpus_name field — else this negative passes vacuously against HEAD.
        with pytest.raises(ValueError):  # noqa: PT011
            bind_curator(wt, rd, degenerate)


def test_a_single_rm_naming_two_corpora_is_denied(tmp_path):
    """A single `rm` naming two operands in different corpora is DENIED — the compiled grant is a
    single-operand grammar (RG-ispo4), so a two-operand invocation matches no pattern; a same-corpus
    two-file rm is also denied; the single in-corpus rm is the control."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    assert not bash_decision(
        deps, "rm defender/lessons/x.md defender/lessons-actor/y.md"
    ).allow
    assert not bash_decision(deps, "rm defender/lessons/x.md defender/lessons/y.md").allow
    assert bash_decision(deps, "rm defender/lessons/single.md").allow          # positive control


# ===========================================================================
# MD-7 / F77 / f7 — the write lane and the read lane admit the same names
# ===========================================================================

def test_a_lesson_the_curator_can_write_it_can_read_back(tmp_path):
    """MD-7 / D3: every lesson filename the write lane admits, the read lane admits too — the write
    lane is narrowed to the read segment class `[\\w.@=+-]+` via ONE shared derivation, foreclosing
    the `[^\\x00]*` newline frame-injection channel (R6). RED against HEAD: a name with a space
    (`my lesson.md`) is write=True read=False today (x6) — the correction is the write lane REFUSES
    it. Positive control: a plain in-class name is admitted by write AND read back the same content."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, rd, "lessons")
    out_of_class = rel("lessons", "my lesson.md")   # a space — outside the read segment class
    # the read lane (the cat scope's `[\w.@=+-]+` segment class) already refuses the space today;
    # the write lane MUST refuse it too so the two lanes admit the same names (the correction).
    assert not bash_decision(deps, "cat " + out_of_class).allow
    with pytest.raises(ModelRetry):
        write_file(deps, out_of_class, "body\n")     # RED today: the write tail admits the space
    # positive control: an in-class name — write admits AND both read surfaces read it back
    write_file(deps, rel("lessons", "good.md"), "hello\n")
    assert bash_decision(deps, "cat " + rel("lessons", "good.md")).allow
    assert "hello" in lesson_read(deps, rel("lessons", "good.md"))
