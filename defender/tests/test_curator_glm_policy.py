"""Executable spec (write-tests step 8) for the curator GLM port's per-spawn CORPUS_AUTHOR
policy + the two gates it drives. Pre-implementation — the target module does NOT exist yet,
so these tests ARE the spec: RED until ``defender.learning.author.curator_engine`` (the new
``AgentRole.CORPUS_AUTHOR`` + ``CuratorDeps`` + ``_corpus_author_policy`` + ``CORPUS_AUTHOR_DEF``)
is written and the four curator prompts are rewritten off Glob/Grep. The module-level import of
``curator_engine`` is the expected collection-time red.

Design (mirror of the lead-author port #543): one ``AgentRole.CORPUS_AUTHOR`` + one
``CORPUS_AUTHOR_DEF`` (``ToolSet(read=True, bash=BashGrammar(), write=True)``) serves all four
curators; the write_allow / bash_allow are built PER-SPAWN from the worktree ``corpus_dir``
(``CuratorDeps.for_run`` → ``_corpus_author_policy``), NOT via ``compile_policy``/``bind`` (whose
write_allow roots at ``run_dir``). Per curator: A→lessons/ (verifiers batch.py+forward.py),
B→lessons-actor/ (batch.py+actor.py), C&D→lessons-environment/ (env.py).

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
  ``decide_write(path, proposed_text="", *, run_dir=None, defender_dir=None, policy)`` → ``Decision``;
  ``decide_bash(command, *, policy, run_dir=None, defender_dir=None)`` → ``BashDecision``.

Bash operand spelling ASSUMED repo-relative (``defender/<corpus>/...``): the agent's bash runs at
cwd=worktree (``tools._tool_bash`` cwd=``deps.defender_dir.parent``), the demand examples are
repo-relative (``ls defender/lessons-actor/``), and the current in-process bash grants + forward-check
commands are repo-relative (``Bash(rm defender/lessons/*.md)``; ``… defender/learning/author/
verify_forward/forward.py``). A correct port must admit that form (else every in-worktree
enumeration is silently denied). Writes are spelling-agnostic — a repo-relative operand is
resolved against the worktree by ``_resolve_operand`` and matched against the absolute write_allow.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

import defender  # noqa: E402
from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import BashGrammar, ToolSet  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.tools import _tool_edit_file, _tool_write_file  # noqa: E402

# The port target — missing until implemented (these imports ARE the expected red).
from defender.learning.author.curator_engine import (  # noqa: E402  # type: ignore[import-not-found]
    CORPUS_AUTHOR_DEF,
    CuratorDeps,
    _corpus_author_policy,
)
from defender.runtime.agents import AGENTS  # noqa: E402


# ---------------------------------------------------------------------------
# Per-curator wiring (the seam contract's A/B/C/D partition) + worktree harness
# ---------------------------------------------------------------------------

# corpus subdir + the verifier scripts each curator's bash_allow may run. batch.py is
# SHARED by A and B, so the per-curator discriminator is forward.py (A) vs actor.py (B)
# vs env.py (C/D) — the wrong-forward-check negatives lean on that.
_CURATORS: dict[str, dict[str, object]] = {
    "A": {"corpus": "lessons", "verifiers": ("batch.py", "forward.py")},
    "B": {"corpus": "lessons-actor", "verifiers": ("batch.py", "actor.py")},
    "C": {"corpus": "lessons-environment", "verifiers": ("env.py",)},
    "D": {"corpus": "lessons-environment", "verifiers": ("env.py",)},
}

_VERIFY_REL = "defender/learning/author/verify_forward"


def _make_worktree(tmp_path: Path) -> Path:
    """A tmp batch 'worktree': the three lesson corpora + the verify_forward scripts exist
    so real writes land and (belt-and-suspenders) any ``.is_file()`` verifier check passes."""
    root = tmp_path / "wt"
    for name in ("lessons", "lessons-actor", "lessons-environment"):
        (root / "defender" / name).mkdir(parents=True, exist_ok=True)
    vf = root / "defender" / "learning" / "author" / "verify_forward"
    vf.mkdir(parents=True, exist_ok=True)
    for script in ("batch.py", "forward.py", "actor.py", "env.py"):
        (vf / script).write_text("# verifier\n")
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


def _verify_cmd(script: str, args: str = "--pending q.jsonl --run-dir rd") -> str:
    """A forward-check command in the shape the agent issues (bare python3 + repo-relative script)."""
    return f"python3 {_VERIFY_REL}/{script} {args}"


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
    (ToolSet read+bash+write+forward_check) registered ONCE in AGENTS serves all four curators;
    A's held_forward_bad divergence lives in the envelope, not a second engine/role."""
    assert CORPUS_AUTHOR_DEF.role is AgentRole.CORPUS_AUTHOR
    assert CORPUS_AUTHOR_DEF.tools == ToolSet(
        read=True, bash=BashGrammar(), write=True, forward_check=True
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
# Bash gate — forward-check + rm + corpus-anchored viewers (Q1 option 3)
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
    admitted (promote/discard a draft), for each curator's own corpus."""
    wt = _make_worktree(tmp_path)
    for curator in ("A", "B", "C"):
        pol = _policy(wt, curator)
        assert permission.decide_bash(f"rm {_rel(curator)}/draft.md", policy=pol).allow


def test_bash_rm_abuse_denied(tmp_path):
    """bash-rm-abuse-denied: rm with flags (-rf, -v), multi-path rm, cross-corpus rm, a literal `..`
    operand, and an absolute path outside the corpus are ALL DENIED (single path, no flags, anti-`..`
    textual, corpus-anchored). The single-draft in-corpus rm succeeds (positive control)."""
    wt = _make_worktree(tmp_path)
    pol = _policy(wt, "A")  # corpus lessons/
    rel = _rel("A")
    for cmd in (
        f"rm -rf {rel}/x.md",                 # a flag
        f"rm -v {rel}/x.md",                  # a flag
        f"rm {rel}/a.md {rel}/b.md",          # multi-path
        "rm defender/lessons-actor/x.md",      # cross-corpus
        f"rm {rel}/../lessons-actor/x.md",     # a literal `..` operand (bash lane no resolve)
        "rm /etc/passwd",                      # absolute path outside the corpus
    ):
        assert not permission.decide_bash(cmd, policy=pol).allow, cmd
    assert permission.decide_bash(f"rm {rel}/single.md", policy=pol).allow  # positive control


def test_bash_nav_viewers_corpus_anchored(tmp_path):
    """bash-nav-viewers-corpus-anchored: ls/grep/cat of the spawn's OWN corpus are admitted — the
    agent enumerates existing lessons to fold duplicates via the bash reader lane, since there is
    no Glob/Grep tool in-process."""
    wt = _make_worktree(tmp_path)
    for curator in ("A", "B", "C"):
        pol = _policy(wt, curator)
        rel = _rel(curator)
        assert permission.decide_bash(f"grep needle {rel}/x.md", policy=pol).allow
        assert permission.decide_bash(f"cat {rel}/x.md", policy=pol).allow
        assert permission.decide_bash(f"ls {rel}", policy=pol).allow


def test_bash_nav_outside_corpus_denied(tmp_path):
    """bash-nav-outside-corpus-denied: cat/grep/ls of anything OUTSIDE the spawn's corpus — another
    corpus, a `..` traversal, or an absolute path like /etc/passwd — is DENIED: the hand-built viewer
    pattern carries NO auto secret-denylist, so its corpus-anchored operand (anti-`..`) is the sole
    containment. The in-corpus grep/ls/cat succeeds (positive control on the same lane)."""
    wt = _make_worktree(tmp_path)
    pol = _policy(wt, "B")  # corpus lessons-actor/
    rel = _rel("B")
    assert not permission.decide_bash("grep needle defender/lessons/x.md", policy=pol).allow          # other corpus
    assert not permission.decide_bash("ls defender/lessons-environment", policy=pol).allow             # other corpus
    assert not permission.decide_bash(f"cat {rel}/../lessons/x.md", policy=pol).allow                   # `..` traversal
    assert not permission.decide_bash("cat /etc/passwd", policy=pol).allow                             # absolute, no denylist
    # positive controls on the same lane (own corpus)
    assert permission.decide_bash(f"grep needle {rel}/x.md", policy=pol).allow
    assert permission.decide_bash(f"ls {rel}", policy=pol).allow
    assert permission.decide_bash(f"cat {rel}/x.md", policy=pol).allow


def test_bash_grep_file_option_exfil_denied(tmp_path):
    """A grep FILE-opening option must not smuggle an out-of-corpus read through the free-text
    search slot. `_VIEW_FLAG` excludes short `-f`, but the search token slot would otherwise admit
    any `-`-prefixed token, so `grep --file=<out-of-corpus>` / `--exclude-from=<...>` (grep OPENS
    that file) and `grep -r -f <in-corpus-probe>` (no file operand → `-r` recurses the worktree cwd)
    would exfiltrate arbitrary files this denylist-free lane's operand anchor is the sole guard
    against. All must be DENIED; a plain in-corpus grep is the positive control."""
    wt = _make_worktree(tmp_path)
    pol = _policy(wt, "B")  # corpus lessons-actor/
    rel = _rel("B")
    for cmd in (
        f"grep --file=/etc/passwd {rel}/probe.md",          # grep reads patterns FROM /etc/passwd
        f"grep --exclude-from=/etc/passwd {rel}/probe.md",   # same file-open, different option
        f"grep -r -f {rel}/probe.md",                        # -f eats the operand → -r recurses cwd
        f"grep -rf {rel}/probe.md",                          # bundled form of the same
    ):
        assert not permission.decide_bash(cmd, policy=pol).allow, cmd
    assert permission.decide_bash(f"grep needle {rel}/x.md", policy=pol).allow  # positive control


def test_bash_arbitrary_program_denied(tmp_path):
    """bash-arbitrary-program-denied: any command that is not a whitelisted viewer or the scoped rm
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
        assert not permission.decide_bash(cmd, policy=pol).allow, cmd
    assert permission.decide_bash("cat defender/lessons/x.md", policy=pol).allow    # positive control
    assert permission.decide_bash("rm defender/lessons/x.md", policy=pol).allow     # positive control


# ===========================================================================
# Cross-curator isolation (one role → per-spawn scoping is the ONLY boundary)
# ===========================================================================

def test_cross_curator_isolation(tmp_path):
    """One CORPUS_AUTHOR role serves all four, so the ONLY isolation is the per-spawn corpus
    scoping: curator A must DENY a write / rm / grep of B's corpus (lessons-actor/) on every
    surface, while ADMITTING its OWN lessons/. (Since #558 the forward-check is no longer a bash
    grant, so it is not an isolation surface here; the tool's lesson operand is confined to the
    spawn's own corpus — test_forward_check_tool.py::test_d19_lesson_path_confined_to_own_corpus.)"""
    wt, rd = _make_worktree(tmp_path), _run_dir(tmp_path)
    a_deps = _deps(wt, rd, "A")
    a_pol = a_deps.policy
    # ADMIT own corpus (positive controls)
    _admitted_on_both_write_surfaces(wt, a_deps, "lessons", stem="own")
    assert permission.decide_bash("rm defender/lessons/own.md", policy=a_pol).allow
    assert permission.decide_bash("grep needle defender/lessons/own.md", policy=a_pol).allow
    # DENY B's corpus (write + rm + grep)
    _denied_on_both_write_surfaces(a_deps, "defender/lessons-actor/x.md")
    assert not permission.decide_bash("rm defender/lessons-actor/x.md", policy=a_pol).allow
    assert not permission.decide_bash("grep needle defender/lessons-actor/x.md", policy=a_pol).allow


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
