"""Executable spec (write-tests step 8) for the curator GLM port's per-spawn CORPUS_AUTHOR
policy + the two gates it drives. Pre-implementation — the target module does NOT exist yet,
so these tests ARE the spec: RED until ``defender.learning.author.curator_engine`` (the new
``AgentRole.CORPUS_AUTHOR`` + ``CuratorDeps`` + ``_corpus_author_policy`` + ``CORPUS_AUTHOR_DEF``)
is written and the four curator prompts are rewritten off Glob/Grep. The module-level import of
``curator_engine`` is the expected collection-time red.

Design (mirror of the lead-author port #543): one ``AgentRole.CORPUS_AUTHOR`` + one
``CORPUS_AUTHOR_DEF`` (``ToolSet(lesson_read=True, bash=True, write=True, forward_check=True)`` —
``bash`` is a plain bool since #575: tool PRESENCE, with the grants built per-spawn below) serves
all four curators; the write_allow / bash_allow are built PER-SPAWN from the worktree ``corpus_dir``
(``CuratorDeps.for_run`` → ``_corpus_author_policy``), NOT via ``compile_policy``/``bind`` (whose
write_allow roots at ``run_dir``). Per curator: A→lessons/, B→lessons-actor/,
C&D→lessons-environment/. Since #558 the forward-check is a bound tool, not a bash grant.

What is driven, and how:
  * every test builds a REAL policy via ``_corpus_author_policy`` / ``CuratorDeps.for_run`` and
    then calls the REAL gate — the ``write_file``/``edit_file`` tool wrappers (``tools._tool_write_file``
    / ``tools._tool_edit_file``, which invoke ``permission.decide_write`` and raise ``ModelRetry`` on
    a deny — so BOTH distinct write surfaces are bound, not just the shared ``decide_write``) and
    ``permission.decide_bash`` for the bash lane. Assertions are on OBSERVABLE decisions only
    (admit + the file lands / ``ModelRetry`` / ``BashDecision.allow``), never on a pattern internal;
  * EVERY deny is PAIRED with its positive control on the SAME surface (the legit in-corpus .md
    write / the sanctioned forward-check / the in-corpus viewer / the single-draft rm ADMITTED);
  * ``..`` and symlink: the bash lane rejects ``..`` TEXTUALLY (no ``resolve()``); the write lane
    rejects a ``..`` / symlink via decide_write's RESOLVED-path fullmatch — tested accordingly.

Gate signatures confirmed from ``permission/files.py`` + ``permission/bash.py``:
  ``decide_write(path, proposed_text="", *, run_dir, defender_dir, policy)`` → ``Decision``
  (both roots REQUIRED since #681 — an omitted ``run_dir`` used to skip the #629 artifact gate);
  ``decide_bash(command, *, policy, run_dir=None, defender_dir=None)`` → ``BashDecision``.

Bash operand spelling ASSUMED repo-relative (``defender/<corpus>/...``): the agent's bash runs at
cwd=worktree (``tools._tool_bash`` cwd=``deps.defender_dir.parent``), and the current in-process
bash grants are repo-relative (``Bash(rm defender/lessons/*.md)``). A correct port must admit that
form (else every in-worktree read is silently denied). Writes are spelling-agnostic — a
repo-relative operand is resolved against the worktree by ``_resolve_operand`` and matched against
the absolute write_allow.

#575 — "one containment model" — folded this lane onto the SAME ``Grant`` model as every other
agent, and three of the bash demands below moved with it (the WRITE demands are untouched — the
write lane never had a private grammar):

  * the curator's private viewer copies (``_CAT_FLAG``/``_LS_FLAG``/``_GREP_FLAG``) are DELETED; it
    compiles the shared ``grant.program_shape``s, so the two lanes can no longer drift — which they
    HAD (its ``_LS_FLAG`` still admitted ``-R`` after #579 dropped it on the runtime lane);
  * ``ls`` is GONE from every lane. The corpus inventory is the #574 manifest, so the demand
    "enumerate the corpus to fold duplicates" is served without a gated program at all;
  * ``grep`` lost its FILE operand everywhere — it is a stdin-only pipe stage now
    (``cat <file> | grep <pattern>``), which is what makes ``cat`` the sole opener. So the
    corpus-anchored *operand* is no longer grep's containment: ``cat``'s ``scope`` is, checked
    against the RESOLVED path.

The properties those demands existed to protect all SURVIVE, re-expressed against the new lane and
asserted below: every corpus read still resolves inside the spawn's OWN corpus, no flag that opens a
file or eats an operand is admitted, and this remains the one denylist-free lane.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

import defender  # noqa: E402
from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import ToolSet  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.tools import _tool_edit_file, _tool_write_file  # noqa: E402

# The port target — missing until implemented (these imports ARE the expected red).
from defender.learning.author.curator_engine import (  # noqa: E402  # type: ignore[import-not-found]
    CORPUS_AUTHOR_DEF,
    CuratorDeps,
    _corpus_author_policy,
)
from defender.agents import AGENTS  # noqa: E402


# ---------------------------------------------------------------------------
# Per-curator wiring (the seam contract's A/B/C/D partition) + worktree harness
# ---------------------------------------------------------------------------

# The corpus subdir each curator writes into (its ONLY per-spawn isolation surface).
_CURATORS: dict[str, dict[str, object]] = {
    "A": {"corpus": "lessons"},
    "B": {"corpus": "lessons-actor"},
    "C": {"corpus": "lessons-environment"},
    "D": {"corpus": "lessons-environment"},
}

def _make_worktree(tmp_path: Path) -> Path:
    """A tmp batch 'worktree': the three lesson corpora exist so real writes land."""
    root = tmp_path / "wt"
    for name in ("lessons", "lessons-actor", "lessons-environment"):
        (root / "defender" / name).mkdir(parents=True, exist_ok=True)
    return root


def _run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "runs" / "run-1"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _corpus(wt: Path, curator: str) -> Path:
    return wt / "defender" / str(_CURATORS[curator]["corpus"])


def _deps(wt: Path, run_dir: Path, curator: str) -> CuratorDeps:
    from defender.learning.author.verify_forward.checks import FINDINGS_CHECK
    return CuratorDeps.for_run(
        run_dir, wt, _corpus(wt, curator),
        check=FINDINGS_CHECK, runs_dir=wt / "runs",
        pending=wt / "_pending" / "findings.jsonl", queued_ids=frozenset(),
    )


def _policy(wt: Path, curator: str):
    return _corpus_author_policy(_corpus(wt, curator))


def _rel(curator: str) -> str:
    """The repo-relative corpus prefix the agent (cwd=worktree) types, e.g. defender/lessons-actor."""
    return f"defender/{_CURATORS[curator]['corpus']}"


def _gate(wt: Path, pol, cmd: str):
    """Drive the REAL bash gate the way production does (``tools._tool_bash`` passes
    ``deps.run_dir``, ``deps.defender_dir`` AND ``deps.cwd_anchor``).

    Threading the anchor is LOAD-BEARING, not ceremony: since #575 a ``cat`` operand is RESOLVED
    before it is scope-checked, and a repo-relative operand (the spelling the curator types,
    cwd=worktree) is rebased on the anchor to resolve it. Omit it and the gate rebases on the
    default — the RUN DIR since #540 — so every corpus read would deny for the wrong reason.

    The curator is TREE-anchored: it edits a throwaway worktree while its ``run_dir`` is the
    pending queue, so its anchor is the worktree root. Production sets exactly this at
    ``CuratorDeps.for_run`` (``cwd_anchor=repo_root``); this helper mirrors it, which is the
    point of the helper."""
    return permission.decide_bash(
        cmd, policy=pol, run_dir=wt / "runs", defender_dir=wt / "defender",
        cwd_anchor=wt,
    )


# --- write-surface drivers: bind write_file AND edit_file (both are decide_write) ---

def _denied_on_both_write_surfaces(deps: CuratorDeps, path: str) -> None:
    """A policy tight on write_file but loose on edit_file (or vice-versa) is the fail-open,
    so a negative must deny on BOTH. write_file denies at decide_write; edit_file (create mode)
    denies at decide_read (path outside the read surface) OR at decide_write (in read surface but
    outside write_allow) — either raises ModelRetry."""
    p = str(path)
    with pytest.raises(ModelRetry):
        _tool_write_file(deps, p, "body\n")
    with pytest.raises(ModelRetry):
        _tool_edit_file(deps, p, "", "body\n")


def _admitted_on_both_write_surfaces(wt: Path, deps: CuratorDeps, corpus_name: str, stem: str = "lesson") -> None:
    """Positive control on both surfaces: write_file authors <corpus>/<stem>.md (it lands), then
    edit_file mutates it in place (a real, non-create edit)."""
    rel = f"defender/{corpus_name}/{stem}.md"
    landed = wt / "defender" / corpus_name / f"{stem}.md"
    _tool_write_file(deps, rel, "body\n")            # admitted → no ModelRetry
    assert landed.read_text() == "body\n"
    _tool_edit_file(deps, rel, "body\n", "edited\n")  # admitted → real edit
    assert landed.read_text() == "edited\n"


# ===========================================================================
# Role + per-spawn policy (seam)
# ===========================================================================

def test_one_corpus_author_role_serves_all_four(tmp_path):
    """one-corpus-author-role: a single AgentRole.CORPUS_AUTHOR + CORPUS_AUTHOR_DEF
    (ToolSet lesson_read+bash+write+forward_check — read=True swapped for the scoped lesson_read
    in #559) registered ONCE in AGENTS serves all four curators; A's held_forward_bad divergence
    lives in the envelope, not a second engine/role.

    (#575: ``ToolSet.bash`` is a plain bool — tool PRESENCE. What the curator may then RUN is its
    per-spawn grant list, built by ``_corpus_author_policy``, and asserted through the gate below.)"""
    assert CORPUS_AUTHOR_DEF.role is AgentRole.CORPUS_AUTHOR
    assert CORPUS_AUTHOR_DEF.tools == ToolSet(
        bash=True, write=True, forward_check=True, lesson_read=True
    )
    assert AGENTS[AgentRole.CORPUS_AUTHOR] is CORPUS_AUTHOR_DEF  # registered once, no duplicate role
    wt, rd = _make_worktree(tmp_path), _run_dir(tmp_path)
    for curator in ("A", "B", "C", "D"):
        assert _deps(wt, rd, curator).role is AgentRole.CORPUS_AUTHOR


def test_per_spawn_policy_not_bind(tmp_path):
    """per-spawn-policy-not-bind: for_run builds a PER-SPAWN corpus-scoped write_allow, NOT
    compile_policy/bind (whose ToolSet(write=True) write_allow roots at run_dir). The run_dir
    DENY is the discriminator — a bind-built policy would ADMIT a run_dir .md write."""
    wt, rd = _make_worktree(tmp_path), _run_dir(tmp_path)
    deps = _deps(wt, rd, "A")
    _denied_on_both_write_surfaces(deps, str(rd / "scratch.md"))  # a bind write_allow would admit this
    _admitted_on_both_write_surfaces(wt, deps, "lessons")         # positive control: own corpus


def test_safe_by_construction_corpus_scope(tmp_path):
    """safe-by-construction-corpus-scope (footgun A regression): a CORPUS_AUTHOR write_allow is
    confined to <corpus>/**.md — never run-dir-rooted nor whole-defender_dir; the factory REQUIRES
    a corpus_dir. Positive control: a deps built for lessons-actor admits an in-corpus .md write."""
    wt, rd = _make_worktree(tmp_path), _run_dir(tmp_path)
    deps = _deps(wt, rd, "B")  # corpus lessons-actor/
    _admitted_on_both_write_surfaces(wt, deps, "lessons-actor")   # positive control
    _denied_on_both_write_surfaces(deps, "defender/skills/x.md")  # NOT whole-defender_dir
    _denied_on_both_write_surfaces(deps, "defender/lessons/x.md")  # NOT a sibling corpus
    _denied_on_both_write_surfaces(deps, str(rd / "x.md"))        # NOT run-dir-rooted
    with pytest.raises(TypeError):  # the factory cannot be built without naming the corpus
        CuratorDeps.for_run(rd, wt)  # missing corpus_dir (and the bound check)


# ===========================================================================
# Write gate — every surface, each negative paired with its positive control
# ===========================================================================

def test_write_in_corpus_admitted(tmp_path):
    """write-in-corpus-admitted: write_file AND edit_file may author a <corpus>/<name>.md under
    the spawn's OWN corpus — the write is admitted and the file lands (for each of A/B/C)."""
    wt, rd = _make_worktree(tmp_path), _run_dir(tmp_path)
    for curator in ("A", "B", "C"):
        deps = _deps(wt, rd, curator)
        _admitted_on_both_write_surfaces(wt, deps, str(_CURATORS[curator]["corpus"]), stem=f"m{curator}")


def test_write_cross_corpus_denied(tmp_path):
    """write-cross-corpus-denied: a write_file OR edit_file to a DIFFERENT corpus than the spawn's
    own is DENIED on both surfaces; the same write into the OWN corpus succeeds (paired control).
    Bidirectional: A→lessons-actor/ + lessons-environment/ denied; B→lessons/ denied."""
    wt, rd = _make_worktree(tmp_path), _run_dir(tmp_path)
    a = _deps(wt, rd, "A")  # corpus lessons/
    _denied_on_both_write_surfaces(a, "defender/lessons-actor/x.md")
    _denied_on_both_write_surfaces(a, "defender/lessons-environment/y.md")
    assert not (wt / "defender" / "lessons-actor" / "x.md").exists()  # nothing landed cross-corpus
    _admitted_on_both_write_surfaces(wt, a, "lessons")               # positive control
    b = _deps(wt, rd, "B")  # corpus lessons-actor/
    _denied_on_both_write_surfaces(b, "defender/lessons/z.md")
    _admitted_on_both_write_surfaces(wt, b, "lessons-actor")         # positive control


def test_write_non_md_denied(tmp_path):
    """write-non-md-denied: a write of a non-.md file (.py, .txt, no extension) UNDER the corpus is
    DENIED on both surfaces (build_write_allow suffix='.md'); the sibling .md write succeeds."""
    wt, rd = _make_worktree(tmp_path), _run_dir(tmp_path)
    deps = _deps(wt, rd, "A")
    for bad in ("defender/lessons/note.py", "defender/lessons/note.txt", "defender/lessons/noext"):
        _denied_on_both_write_surfaces(deps, bad)
    _admitted_on_both_write_surfaces(wt, deps, "lessons")  # positive control: sibling .md


def test_write_outside_worktree_denied(tmp_path):
    """write-outside-worktree-denied: a write to run_dir, or anywhere outside <corpus>/**.md, is
    DENIED on both surfaces — the flat corpus allowlist does NOT grant run_dir (unlike a run-dir
    confine). The in-corpus .md write succeeds (positive control)."""
    wt, rd = _make_worktree(tmp_path), _run_dir(tmp_path)
    deps = _deps(wt, rd, "A")
    _denied_on_both_write_surfaces(deps, str(rd / "x.md"))               # the run dir
    _denied_on_both_write_surfaces(deps, str(tmp_path / "elsewhere" / "z.md"))  # anywhere else
    _admitted_on_both_write_surfaces(wt, deps, "lessons")               # positive control


def test_write_traversal_symlink_denied(tmp_path):
    """write-traversal-symlink-denied: a `..` traversal path and a symlink under the corpus pointing
    outside are both DENIED by decide_write's RESOLVED-path fullmatch, on write_file AND edit_file;
    the direct in-corpus .md write succeeds (positive control)."""
    wt, rd = _make_worktree(tmp_path), _run_dir(tmp_path)
    deps = _deps(wt, rd, "A")  # corpus lessons/
    # `..` escapes the corpus after resolve() → outside write_allow
    _denied_on_both_write_surfaces(deps, "defender/lessons/../lessons-actor/esc.md")
    # a symlink under the corpus pointing outside → resolved path lands outside write_allow
    outside = tmp_path / "outside"
    outside.mkdir()
    (wt / "defender" / "lessons" / "evil").symlink_to(outside)
    _denied_on_both_write_surfaces(deps, "defender/lessons/evil/pwn.md")
    assert not (outside / "pwn.md").exists()               # the escape wrote nothing
    _admitted_on_both_write_surfaces(wt, deps, "lessons")  # positive control


# ===========================================================================
# Bash gate — rm + the corpus-scoped `cat` opener + the stdin-only grep stage
# ===========================================================================

# (#558) The two per-curator verifier-grant cases that lived here — bash-forward-check-admitted
# and bash-wrong-forward-check-denied — are INVERTED by the port: the curator's bash allowlist now
# admits no python interpreter at all, because a regex over argv pins the program token but not the
# operands that program acts on (#565). Their replacements live in test_forward_check_tool.py:
# ::test_d25_no_bash_grant_for_the_verifier (no interpreter admitted, for any curator) and
# ::test_d25b_surviving_bash_lane_still_works (the rm + viewers survive). The per-curator variation
# they asserted is now ::test_d2_check_bound_from_deps_not_operand — it rides on the deps.


def test_bash_rm_scoped_admitted(tmp_path):
    """bash-rm-scoped-admitted: a single-path `rm <corpus>/<name>.md` of the spawn's OWN corpus is
    admitted (promote/discard a draft), for each curator's own corpus.

    Unchanged by #575: `rm` is one of the three `pins_path` grants — `rm` unlinks the LINK, not the
    target, so `resolve()` is the wrong operand model for it and its path stays in the PATTERN."""
    wt = _make_worktree(tmp_path)
    for curator in ("A", "B", "C"):
        pol = _policy(wt, curator)
        assert _gate(wt, pol, f"rm {_rel(curator)}/draft.md").allow


def test_bash_rm_abuse_denied(tmp_path):
    """bash-rm-abuse-denied: rm with flags (-rf, -v), multi-path rm, cross-corpus rm, a literal `..`
    operand, and an absolute path outside the corpus are ALL DENIED (single path, no flags, anti-`..`
    textual, corpus-anchored). The single-draft in-corpus rm succeeds (positive control).

    The `..` case stays a TEXTUAL rejection even after #575 made containment resolve: `rm`'s grant
    is `pins_path`, so nothing resolves its operand and the traversal must be denied literally, in
    the pattern (`curator_engine._SEG`)."""
    wt = _make_worktree(tmp_path)
    pol = _policy(wt, "A")  # corpus lessons/
    rel = _rel("A")
    for cmd in (
        f"rm -rf {rel}/x.md",                 # a flag
        f"rm -v {rel}/x.md",                  # a flag
        f"rm {rel}/a.md {rel}/b.md",          # multi-path
        "rm defender/lessons-actor/x.md",      # cross-corpus
        f"rm {rel}/../lessons-actor/x.md",     # a literal `..` operand (pins_path → no resolve)
        "rm /etc/passwd",                      # absolute path outside the corpus
    ):
        assert not _gate(wt, pol, cmd).allow, cmd
    assert _gate(wt, pol, f"rm {rel}/single.md").allow  # positive control


def test_bash_corpus_read_admitted(tmp_path):
    """bash-nav-viewers-corpus-anchored, RE-EXPRESSED for the one containment model (#575). The
    demand — "the curator can read its own corpus from bash, since there is no Glob/Grep tool
    in-process" — survives; the three programs that served it do not:

      * `ls` is DELETED from every lane. The corpus INVENTORY is the #574 manifest now, so the
        enumeration demand is met with no gated program at all — a strict subtraction of attack
        surface (`ls`'s dir operand was the lane's other path-opening slot, and its arg-eating
        `-I`/`-w`/`-T` flags were the #579 bug class);
      * `grep` lost its FILE operand — it is a stdin-only pipe stage: `cat <file> | grep <pat>`.
        Identical capability, one extra `cat |`;
      * `cat` is the sole opener, and its scope is checked against the RESOLVED path.

    So: the pipe form of every read the curator actually needs is ADMITTED, for each curator's own
    corpus."""
    wt = _make_worktree(tmp_path)
    for curator in ("A", "B", "C"):
        pol = _policy(wt, curator)
        rel = _rel(curator)
        assert _gate(wt, pol, f"cat {rel}/x.md").allow
        assert _gate(wt, pol, f"cat {rel}/x.md | grep needle").allow
        assert _gate(wt, pol, f"cat {rel}/x.md | grep -l 'source_signature:.*rule-id'").allow
        # the two programs the fold deleted are gone from THIS lane too — no private survivor
        assert not _gate(wt, pol, f"ls {rel}").allow
        assert not _gate(wt, pol, f"grep needle {rel}/x.md").allow   # the file-operand form


def test_bash_nav_outside_corpus_denied(tmp_path):
    """bash-nav-outside-corpus-denied: a `cat` of anything OUTSIDE the spawn's corpus — a sibling
    corpus, a `..` traversal, an absolute /etc/passwd, or a symlink pointing out — is DENIED.

    WHAT CHANGED (#575): the containment is no longer the textual corpus-anchored OPERAND (which
    could not see through a symlink, and had to reject `..` by spelling). It is the `cat` grant's
    SCOPE, fullmatched against the path `resolve()` returns. That STRENGTHENS this lane, which is
    the one with no compile_policy and — historically — no secret denylist: `..` collapses and an
    escaping symlink resolves to where it POINTS, so both land outside the scope by the same check.
    The escaping-symlink case could not be written against the old lane at all.

    Positive control on the same lane (own corpus, both the direct read and the pipe form)."""
    wt = _make_worktree(tmp_path)
    pol = _policy(wt, "B")  # corpus lessons-actor/
    rel = _rel("B")
    # a symlink INSIDE the corpus pointing out of it — resolve() collapses it to /etc
    (wt / "defender" / "lessons-actor" / "esc").symlink_to("/etc")
    for cmd in (
        "cat defender/lessons/x.md",           # a sibling corpus
        f"cat {rel}/../lessons/x.md",           # `..` traversal — collapses out of scope
        "cat /etc/passwd",                      # absolute, outside every scope
        f"cat {rel}/esc/passwd",                # an ESCAPING SYMLINK (new: only resolve() sees it)
        f"cat {rel}/x.md | cat /etc/passwd",     # every pipe STAGE is scope-checked, not just the first
    ):
        assert not _gate(wt, pol, cmd).allow, cmd
    # positive controls on the same lane (own corpus)
    assert _gate(wt, pol, f"cat {rel}/x.md").allow
    assert _gate(wt, pol, f"cat {rel}/x.md | grep needle").allow


def test_bash_corpus_symlink_inside_the_corpus_still_reads(tmp_path):
    """The paired positive control for the symlink deny above: containment is WHERE THE PATH
    RESOLVES, not "symlinks are banned". A link inside the corpus pointing at another IN-CORPUS
    file still ALLOWs — otherwise the deny above would be passing for the wrong reason (a blanket
    symlink ban), and a legitimately symlinked corpus would be unreadable."""
    wt = _make_worktree(tmp_path)
    pol = _policy(wt, "B")
    corpus = wt / "defender" / "lessons-actor"
    (corpus / "real.md").write_text("x\n")
    (corpus / "alias.md").symlink_to(corpus / "real.md")
    assert _gate(wt, pol, f"cat {_rel('B')}/alias.md").allow


def test_bash_grep_file_option_exfil_denied(tmp_path):
    """A grep FILE-opening option must not smuggle an out-of-corpus read. `grep --file=<path>` /
    `--exclude-from=<path>` make grep OPEN that path, and `grep -r` walks the worktree cwd with no
    operand at all — on a lane whose `grep` is declared `OPENS_NOTHING`, any of these landing means
    the file grep opens is NEVER scope-checked. The claim is only as good as the SHAPE that earns
    it, so these must deny at the shape.

    #575 makes the claim structural rather than asserted: grep has no file slot left, so the
    surviving grammar admits no `--long` option and no `-`-prefixed positional at all (the shared
    `grant.program_shape("grep")`, pinned globally by test_grant_gate_575::b7/b8). What this test
    still adds is that THIS lane — the denylist-free, `compile_policy`-free one — really did fold
    onto that shared shape and kept no private copy of the old grammar.

    Positive control: the stdin form the curator now uses."""
    wt = _make_worktree(tmp_path)
    pol = _policy(wt, "B")  # corpus lessons-actor/
    rel = _rel("B")
    for cmd in (
        f"grep --file=/etc/passwd {rel}/probe.md",           # grep reads patterns FROM /etc/passwd
        f"grep --exclude-from=/etc/passwd {rel}/probe.md",    # same file-open, different option
        f"cat {rel}/x.md | grep --file=/etc/passwd",           # …and on the stdin form too
        f"cat {rel}/x.md | grep --exclude-from=/etc/passwd",
        f"grep -r -f {rel}/probe.md",                          # -f eats the operand → -r recurses cwd
        f"grep -rf {rel}/probe.md",                            # bundled form of the same
        f"cat {rel}/x.md | grep -r needle",                    # -r recurses the cwd from a pipe stage
    ):
        assert not _gate(wt, pol, cmd).allow, cmd
    assert _gate(wt, pol, f"cat {rel}/x.md | grep needle").allow  # positive control


def test_bash_arg_consuming_flag_denied(tmp_path):
    """An ADMITTED flag that CONSUMES the next token must not eat the operand. This is the #579 bug
    class, and it is the reason a flag class must be a POSITIVE boolean allowlist rather than a
    catch-all minus the known-bad: `-[a-eg-zA-Z]+` ("any letter but `-f`") admitted every shape
    below, and a catch-all fails OPEN the day coreutils grows another arg-taker.

    #575 re-expresses it rather than retiring it. The curator's PRIVATE flag classes
    (`_CAT_FLAG`/`_LS_FLAG`/`_GREP_FLAG`) are DELETED — it compiles the shared `program_shape`s
    now. That deletion is exactly what this test guards: the private copy had ALREADY DRIFTED (its
    `_LS_FLAG` still admitted `-R` after #579 dropped it on the runtime lane), which is the second
    place the next fail-open would have hidden.

    `ls` is gone entirely, so its arg-eaters are moot — but they are kept in the deny list as a
    ratchet: re-granting `ls` to this lane must not silently re-admit `-I`/`-w`/`-T`. Every deny is
    paired with the boolean-flag positive control it must not cost us. (Verified against the runtime
    container's GNU coreutils 9.7 / grep 3.11 — the dev box's `ls`/`ugrep` are not the gate's
    target.)"""
    wt = _make_worktree(tmp_path)
    pol = _policy(wt, "B")  # corpus lessons-actor/
    rel = _rel("B")
    for cmd in (
        # `-e` supplies the PATTERN, so grep demotes the free-text slot to a FILE it OPENS —
        # an arbitrary out-of-corpus read on a lane with no secret denylist.
        f"grep -eNEEDLE /etc/passwd {rel}/x.md",
        f"grep -e NEEDLE /etc/passwd {rel}/x.md",
        f"cat {rel}/x.md | grep -e NEEDLE /etc/passwd",
        # each of these eats the search token, leaving grep with NO pattern — and, on a lane that
        # still had a file slot, shifting the corpus path into the PATTERN slot so grep walked the cwd.
        f"grep -d recurse {rel}/x.md",
        f"grep -D skip {rel}/x.md",
        f"grep -m 1 {rel}/x.md",
        f"grep -A 2 {rel}/x.md",
        f"grep -B 2 {rel}/x.md",
        f"grep -C 2 {rel}/x.md",
        f"cat {rel}/x.md | grep -m 1 needle",
        f"cat {rel}/x.md | grep -A 2 needle",
        # `cat` has no arg-taking flag at all (that is WHY it can be the sole opener), so an
        # unknown dash token must fail closed rather than be absorbed as free text.
        f"cat -z {rel}/x.md",
        f"cat --show-all {rel}/x.md",
        # ls: `-I PATTERN` / `-w COLS` / `-T COLS` swallow the dir operand, so `ls` falls back to
        # listing the cwd — the worktree root. `ls` is now denied outright; kept as the ratchet.
        f"ls -I {rel}",
        f"ls -w {rel}",
        f"ls -T {rel}",
        f"ls -laI {rel}",   # bundled: still contains an arg-taker
        f"ls -R {rel}",     # the flag the curator's PRIVATE `_LS_FLAG` had drifted into admitting
    ):
        assert not _gate(wt, pol, cmd).allow, cmd
    # positive controls — the boolean-flag shapes the curator prompts actually tell it to run
    # (`cat <lesson>`, `cat <file> | grep -l '<key>:.*<val>'`) must survive.
    for cmd in (
        f"cat {rel}/x.md | grep -l 'source_signature:.*rule-id'",
        f"cat {rel}/x.md | grep -n needle",
        f"cat -n {rel}/x.md",
    ):
        assert _gate(wt, pol, cmd).allow, cmd


def test_bash_arbitrary_program_denied(tmp_path):
    """bash-arbitrary-program-denied: any command that is not a granted viewer or the scoped rm
    — git commit, any python, curl, cat of a secret — is DENIED (deny-by-default). The in-corpus
    viewer succeeds (positive control). Also pins survival-agent-no-git: the toolset has no git
    grant. Since #558 there is no interpreter grant either: `python3 <anything>` is denied, so the
    forward-check can only be reached through the bound `forward_check` tool."""
    wt = _make_worktree(tmp_path)
    pol = _policy(wt, "A")
    for cmd in (
        "git commit -m x",                 # no git grant (the loop is the sole committer)
        "python3 -c pass",                 # bare python
        "python3 evil.py",                 # any script — there is no verifier grant left
        "curl http://evil.test",           # arbitrary network
        "cat /etc/passwd",                 # a secret, absolute
    ):
        assert not _gate(wt, pol, cmd).allow, cmd
    assert _gate(wt, pol, "cat defender/lessons/x.md").allow    # positive control
    assert _gate(wt, pol, "rm defender/lessons/x.md").allow     # positive control


def test_bash_lane_names_only_programs_it_grants(tmp_path):
    """The curator's `deny_reason` is PROMPT SURFACE, and #575 deleted two programs it used to
    name. A reason that still advertised `ls` (or grep's file operand) would teach a dead command
    and the curator would burn turns on it. So: every program the deny reason names must be one
    this lane actually grants — derived from the LIVE grant list, never a hardcoded dead-name list,
    so it keeps working after the next deletion. (The global sweep is
    test_grant_gate_575::test_g1; this is its curator-lane instance, because the curator's policy
    never passes through `compile_policy` and so is not reachable from a def-driven sweep.)"""
    wt = _make_worktree(tmp_path)
    pol = _policy(wt, "A")
    granted = {g.program for g in pol.bash_allow}
    assert granted == {"cat", "grep", "rm"}       # ls is gone; no interpreter; no adapter
    named = set(re.findall(r"`?\b(ls|cat|grep|rm|jq|head|tail|wc|python3)\b`?", pol.deny_reason))
    assert named, "the deny reason names no program at all — this check would be vacuous"
    assert named <= granted, f"deny reason names programs this lane denies: {named - granted}"


# ===========================================================================
# Cross-curator isolation (one role → per-spawn scoping is the ONLY boundary)
# ===========================================================================

def test_cross_curator_isolation(tmp_path):
    """One CORPUS_AUTHOR role serves all four, so the ONLY isolation is the per-spawn corpus
    scoping: curator A must DENY a write / rm / READ of B's corpus (lessons-actor/) on every
    surface, while ADMITTING its OWN lessons/. (Since #558 the forward-check is no longer a bash
    grant, so it is not an isolation surface here; the tool's lesson operand is confined to the
    spawn's own corpus — test_forward_check_tool.py::test_d19_lesson_path_confined_to_own_corpus.)

    The READ surface is spelled `cat` now, not `grep <file>` (#575: grep is a stdin-only stage, so
    `cat` is the sole opener and the ONLY program whose operand carries the corpus scope). The
    isolation property is unchanged — only which program can express a cross-corpus read is."""
    wt, rd = _make_worktree(tmp_path), _run_dir(tmp_path)
    a_deps = _deps(wt, rd, "A")
    a_pol = a_deps.policy
    # ADMIT own corpus (positive controls)
    _admitted_on_both_write_surfaces(wt, a_deps, "lessons", stem="own")
    assert _gate(wt, a_pol, "rm defender/lessons/own.md").allow
    assert _gate(wt, a_pol, "cat defender/lessons/own.md | grep needle").allow
    # DENY B's corpus (write + rm + read)
    _denied_on_both_write_surfaces(a_deps, "defender/lessons-actor/x.md")
    assert not _gate(wt, a_pol, "rm defender/lessons-actor/x.md").allow
    assert not _gate(wt, a_pol, "cat defender/lessons-actor/x.md").allow
    assert not _gate(wt, a_pol, "cat defender/lessons-actor/x.md | grep needle").allow


# ===========================================================================
# Prompts (light fold-pass-executable pin)
# ===========================================================================

def test_prompts_drop_absent_tools():
    """prompts-drop-absent-tools (LIGHT — pins the fold-pass-executable demand): the ported curator
    prompts must express corpus enumeration as bash ls/grep, never the absent Glob/Grep TOOLS.
    RED against the current prompts (malicious_actor/benign_actor still say `Glob …`, lessons says
    `Grep the frontmatter`); GREEN once the port rewrites them. A silent Glob death would ship green
    with permanent duplicate lessons, so the mandated whole-corpus fold must be executable in-process.
    (Lowercase `grep`/`ls`/`cat` — the bash programs — stay allowed; only the capitalized tool names
    are flagged.)"""
    # `defender` is a namespace package (no __init__.py), so `defender.__file__` is None; anchor
    # off its package path instead (the robust idiom test_runner_teardown_structural also uses).
    author_dir = Path(defender.__path__[0]).resolve() / "learning" / "author"
    prompts = sorted(author_dir.glob("*/prompt.md"))
    assert prompts, "no curator prompt.md files found under learning/author"
    tool_ref = re.compile(r"\b(?:Glob|Grep)\b")
    offenders = {str(p): tool_ref.findall(p.read_text()) for p in prompts if tool_ref.search(p.read_text())}
    assert not offenders, f"ported curator prompts still name the absent Glob/Grep tools: {offenders}"
