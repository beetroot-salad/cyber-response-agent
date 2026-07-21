"""Hermetic spec for the in-process PydanticAI lead-author engine (no API key, no network).

The lead author is the FIRST *writer* port onto the shared ``_pydantic_stage`` transport
(after the read-only judge/actor/oracle/verify predictors). These drive the REAL engine
(``_run_author_pydantic`` deps build + write gate + observe trace; ``run_author_stage``
key-sourcing + fault mapping) with a ``FunctionModel`` injected through the ``make_model`` DI
seam, under ``override_allow_model_requests(False)`` so any real provider call raises. Pins the
port's load-bearing decisions:

- write_allow (a flat defender/skills/**.md pattern) confines the corpus writers; the ``rm`` bash
  grant confines draft deletion — cross-surface parity, both lanes now confining ``..`` traversal.
- ``bind(LEAD_AUTHOR_DEF, run, defender_dir=<wt>/defender)`` (the SINGLE seam since #551 — the
  bespoke ``LeadAuthorDeps.for_run`` retired) threads the WORKTREE's defender_dir into both the
  policy anchor + the deps field (never the main checkout — a PATHS tree is unbuildable), and the
  deps cannot be born without a policy (safe-by-construction, #536).
- a repo-relative file op resolves against the WORKTREE repo_root, not the process cwd (F2),
  without leaking the process cwd.
- ``require_output=False`` lets a writer end with empty prose; the default (True) still
  quarantines an empty verdict for the four shipped read-only stages.
- F1: a systemic ``FatalConfigError`` (bad key / unroutable model / cross-provider effort)
  PROPAGATES; only a per-run ``RunUnprocessable`` maps to rc 124.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import (  # noqa: E402
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender.learning.core import config  # noqa: E402
from defender.learning.core.config import (  # noqa: E402
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
)
from defender.learning.leads.lead_author_engine import (  # noqa: E402
    LEAD_AUTHOR_DEF,
    LeadAuthorDeps,
    _run_author_pydantic,
    run_author_stage,
)
from defender.learning.pipeline import _pydantic_stage  # noqa: E402
from defender.learning.pipeline._pydantic_stage import run_stage  # noqa: E402
from defender.runtime import observe, permission, providers  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.permission import AgentPolicy  # noqa: E402
from defender.tests._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.tests._engine_helpers import replay_once as _replay  # noqa: E402

_SKILLS_REL = "defender/skills"


def _lead_deps(run_dir: Path, wt: Path) -> LeadAuthorDeps:
    """The lead-author deps via the SINGLE bind seam (#551 — replaces the retired
    ``LeadAuthorDeps.for_run(run_dir, repo_root)``): bind threads the worktree tree
    ``wt/defender`` into BOTH the policy anchor and the deps ``defender_dir`` field."""
    deps = bind(LEAD_AUTHOR_DEF, run_dir, defender_dir=wt / "defender")
    assert isinstance(deps, LeadAuthorDeps)
    return deps


def _lead_policy(skills_dir: Path) -> AgentPolicy:
    """The lead-author policy anchored on ``skills_dir`` via bind (#551 — replaces the retired
    ``_lead_author_policy(skills_dir)``). ``skills_dir.parent`` is a NON-PATHS worktree defender_dir
    (LEAD_AUTHOR_DEF is ``requires_explicit_tree``, so a main-checkout tree is unbuildable — these
    shape tests use a synthetic worktree; the rm matcher recognizes the repo-relative
    ``defender/skills`` spelling regardless of the worktree location)."""
    return bind(LEAD_AUTHOR_DEF, Path("/tmp/lead-run"), defender_dir=skills_dir.parent).policy


def _tool_then_text(tool_calls, final_text):
    """A two-turn FunctionModel: turn 1 issues the tool calls; once a ToolReturnPart is seen
    (turn 2+), emit the final text. Lets a real write_file execute, then the model 'finishes'."""
    def fn(messages, info):
        seen_return = any(
            isinstance(p, ToolReturnPart)
            for m in messages for p in getattr(m, "parts", [])
        )
        if seen_return:
            return ModelResponse(parts=[TextPart(content=final_text)])
        return ModelResponse(parts=[ToolCallPart(tool_name=n, args=a) for n, a in tool_calls])
    return fn




def _prompt(tmp_path):
    p = tmp_path / "lead_author.md"
    p.write_text("Curate the catalog. Edit skill files under defender/skills. Finish when done.\n")
    return p


def _worktree(tmp_path):
    """A tmp 'batch worktree': <root>/defender/skills/... exists so real writes land somewhere."""
    root = tmp_path / "wt"
    (root / "defender" / "skills" / "gather" / "queries" / "foo").mkdir(parents=True)
    return root


def _run_dir(tmp_path):
    d = tmp_path / "runs" / "run-A"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _spawn(**over):
    """run_author_stage with hermetic defaults (fake key + fake transport); override per case."""
    kw = dict(
        system_prompt_file=Path("/tmp/does-not-matter-lae.md"),
        batch_id="run-A", user_prompt="u", repo_root=Path("/tmp/wt"),
        learning_run_dir=Path("/tmp/rd"), log_label="lead author", log=lambda *a, **k: None,
        source_key=lambda model, label: None, run_author=lambda **kw: "",
    )
    kw.update(over)
    return run_author_stage(**kw)


# ===========================================================================
# bind(LEAD_AUTHOR_DEF, defender_dir=) — worktree binding + safe-by-construction
# ===========================================================================

def test_for_run_binds_worktree_defender_dir_and_write_allow(tmp_path):
    """bind stamps the WORKTREE's defender_dir + write_allow, NOT PATHS.defender_dir (the main
    checkout). Asserted through the real gates: with these deps, a read AND write of the worktree
    skills tree is allowed. Guarded negatives prove the worktree binding is load-bearing — the SAME
    op bound to a DIFFERENT tree is denied, and calling the gate with a mismatched defender_dir (the
    deps/policy split #551 forbids) denies the read (a stale-anchor bug would lock the agent out of
    the very tree it curates)."""
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    deps = _lead_deps(rd, wt)
    assert deps.defender_dir == wt / "defender"
    assert len(deps.policy.write_allow) == 1  # one flat skills-corpus pattern, anchored to the worktree
    assert deps.role is AgentRole.LEAD_AUTHOR
    skill = wt / "defender" / "skills" / "gather" / "queries" / "foo" / "x.md"
    # positive: the worktree binding lets the agent write + read its own corpus
    assert permission.decide_write(
        skill, "body\n", run_dir=rd, defender_dir=deps.defender_dir, policy=deps.policy).allow
    assert permission.decide_read(skill, run_dir=rd, defender_dir=deps.defender_dir, policy=deps.policy).allow
    # guarded negatives: a policy bound to a DIFFERENT worktree tree denies the write …
    other_pol = _lead_deps(rd, tmp_path / "other").policy
    assert not permission.decide_write(
        skill, "body\n", run_dir=rd, defender_dir=deps.defender_dir, policy=other_pol).allow
    # … and calling the gate with a mismatched defender_dir (the split) denies the read.
    assert not permission.decide_read(skill, run_dir=rd, defender_dir=config.REPO_ROOT / "defender", policy=deps.policy).allow


def test_lead_author_deps_cannot_be_born_without_policy(tmp_path):
    """Safe-by-construction (#536 required-policy): a LeadAuthorDeps built WITHOUT a policy is a
    TypeError — a writer subtype can't silently inherit the MAIN policy by omission. Positive
    control: for_run supplies the lead-author policy (write_allow non-empty; no data-source reach).

    #575: the `adapters` / `raw_reads` capability bits are deleted. Their content — "this agent has
    no data-source reach and no payload address" — is now a fact about the GRANT LIST (the adapter
    capability IS a routed Grant; a raw read IS a shape in `read_allow`), so it is asserted through
    the gate, where it is actually decided, rather than as a declared bit that could disagree."""
    with pytest.raises(TypeError):
        LeadAuthorDeps(run_dir=tmp_path, defender_dir=tmp_path / "defender", run_id="x", salt="s")
    deps = _lead_deps(_run_dir(tmp_path), _worktree(tmp_path))
    assert deps.policy.write_allow  # non-empty
    assert not permission.decide_bash("defender-elastic query x", policy=deps.policy).allow
    assert not permission.decide_bash(
        "defender-elastic query x | defender-sql 'SELECT 1'", policy=deps.policy).allow


# ===========================================================================
# the bound lead-author policy — shape + the rm-of-drafts matcher (F3) + asymmetry
# ===========================================================================

def test_lead_author_policy_shape():
    """write_allow = one flat skills/**.md pattern, exactly ONE bash grant (the `rm` of drafts —
    discovery is driver-precomputed, no Glob/Grep), read_confine empty (reads under defender_dir
    stay allowed), and NOTHING else on the bash lane.

    #575 dissolved the four capability BITS this used to enumerate
    (`adapters`/`adapter_sql_pipe`/`raw_reads`/`operand_gated`) into the grant list itself: the
    adapter capability is a routed `Grant`, a raw read is a shape in a `cat` grant's scope, and
    "operand-gated" is just "this grant's program has an extractor". So the single strongest
    statement of the same property is that the lane holds EXACTLY ONE grant and it is the `rm` —
    which subsumes all four bits at once (an agent with one `rm` grant has no adapter route, no
    payload address and no opener) and cannot drift from the lane the way a declared bit could."""
    skills = Path("/wt/defender/skills")
    pol = _lead_policy(skills)
    assert len(pol.write_allow) == 1
    # the one pattern admits a skills .md and denies a non-.md sibling (the corpus-code tightening)
    assert pol.write_allow[0].fullmatch(str(skills / "elastic" / "x.md"))
    assert not pol.write_allow[0].fullmatch(str(skills / "invlang" / "validate.py"))
    assert pol.read_confine == ()
    # exactly one grant, and it is the pins_path `rm` — no adapter, no viewer, no opener
    assert len(pol.bash_allow) == 1
    (rm,) = pol.bash_allow
    assert rm.program == "rm"
    assert rm.pins_path is True          # `rm` unlinks the LINK — resolve() is the wrong model
    assert rm.route is permission.Route.PLAIN
    assert pol.read_allow == ()          # no `cat` grant ⇒ no read shapes (decide_read stays root-only)


def test_rm_repo_relative_draft_allowed_regardless_of_worktree_location(tmp_path):
    """The agent runs with cwd=worktree and issues REPO-RELATIVE rm paths, so the matcher must
    accept ``rm defender/skills/...`` for ANY worktree location — the repo-relative spelling is
    the fixed SKILLS_REL, not skills_dir.relative_to(REPO_ROOT) (a tmp worktree is not under
    REPO_ROOT). The absolute <worktree>/defender/skills/... spelling is accepted too."""
    wt = _worktree(tmp_path)
    pol = _lead_deps(_run_dir(tmp_path), wt).policy
    assert permission.decide_bash("rm defender/skills/elastic/_draft/x.md", policy=pol).allow
    assert permission.decide_bash(f"rm {wt}/defender/skills/elastic/_draft/x.md", policy=pol).allow


def test_rm_outside_skills_denied():
    """rm of a path OUTSIDE defender/skills (lessons, an absolute system file) → denied: the
    skills prefix is baked into the anchored regex (operands are unconfined on the bash lane)."""
    pol = _lead_policy(Path("/tmp/lead-wt/defender/skills"))
    assert not permission.decide_bash("rm defender/lessons/z.md", policy=pol).allow
    assert not permission.decide_bash("rm /etc/passwd", policy=pol).allow


def test_rm_flags_and_multipath_denied():
    """F3: single-path rm only. ``rm -rf <skills>`` (a flag) and ``rm a b`` (multi-path) are
    DENIED — matching the old ``rm defender/skills/:*`` intent (one draft removed at a time)."""
    pol = _lead_policy(Path("/tmp/lead-wt/defender/skills"))
    assert not permission.decide_bash("rm -rf defender/skills/elastic", policy=pol).allow
    assert not permission.decide_bash("rm defender/skills/a.md defender/skills/b.md", policy=pol).allow
    # rejected: allow -f / multi-path because "it's all under skills" — the agent issues one rm
    #           per draft; the git scope gate is containment, the regex is shape (mirrors the actor)


def test_rm_command_substitution_denied():
    """``rm $(...)`` is denied by _stage_unsafe (structural), independent of the operand — the
    gate never expands the substitution."""
    pol = _lead_policy(Path("/tmp/lead-wt/defender/skills"))
    assert not permission.decide_bash("rm $(echo defender/skills/x.md)", policy=pol).allow


def test_cross_surface_parity_out_of_scope_denied_on_both_lanes(tmp_path):
    """Parity: the corpus is mutable via TWO surfaces — the file writers (decide_write +
    write_allow) and rm (bash lane + bash_allow). An out-of-scope mutation is denied on BOTH:
    a write_file to defender/lessons AND ``rm defender/lessons/x`` are each denied. Positive
    controls: the SAME op to defender/skills is ALLOWED on both lanes (the mechanism fires, the
    boundary is real). A constraint on one surface but absent on its sibling is the fail-open."""
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    pol = _lead_deps(rd, wt).policy
    (wt / "defender" / "lessons").mkdir(parents=True)
    skills_ok = wt / "defender" / "skills" / "gather" / "queries" / "foo" / "y.md"
    lessons = wt / "defender" / "lessons" / "z.md"
    # write surface
    assert permission.decide_write(                                               # positive control
        skills_ok, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    assert not permission.decide_write(                                           # negative
        lessons, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    # rm (bash) surface — repo-relative spellings the matcher recognizes
    assert permission.decide_bash("rm defender/skills/gather/queries/foo/_draft/y.md", policy=pol).allow  # positive
    assert not permission.decide_bash("rm defender/lessons/z.md", policy=pol).allow             # negative


def test_both_lanes_deny_dotdot_traversal_escape(tmp_path):
    """Both mutation surfaces confine ``..`` traversal (the review-hardened rm matcher, finding #1).
    An operand that lexically starts defender/skills/ but ``..``-escapes it is denied on BOTH lanes:
    decide_write resolve()s the ``..`` and lands outside write_allow → DENY; the rm matcher rejects a
    ``..`` segment TEXTUALLY (the bash lane does no resolve()) → DENY. This closes the prior
    accepted asymmetry, where ``rm defender/skills/../lessons/x.md`` was allowed and could delete a
    file OUTSIDE the worktree that the loop's git scope gate (worktree ``git status`` only) never
    sees. Positive controls: the in-scope ``_draft`` baseline both surfaces still accept."""
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    pol = _lead_deps(rd, wt).policy
    escape = wt / "defender" / "skills" / ".." / "lessons" / "x.md"
    assert not permission.decide_write(
        escape, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    assert not permission.decide_bash("rm defender/skills/../lessons/x.md", policy=pol).allow
    # a ..-escape via the absolute spelling is denied too
    assert not permission.decide_bash(f"rm {wt}/defender/skills/../../etc/passwd", policy=pol).allow
    ok = wt / "defender" / "skills" / "gather" / "queries" / "foo" / "z.md"
    assert permission.decide_write(
        ok, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    assert permission.decide_bash("rm defender/skills/gather/queries/foo/_draft/z.md", policy=pol).allow


# ===========================================================================
# run_stage — require_output (the new flag) + the writers toolset
# ===========================================================================

def test_run_stage_require_output_matrix(tmp_path):
    """The blast-radius guard for the four shipped read-only stages. With a CONTENT-LESS final text
    (whitespace — the observable proxy for a reasoning model that burned its whole budget in the
    thinking channel and emitted no real prose; a TRULY-empty "" is rejected by pydantic-ai itself
    before this guard, so whitespace is what actually reaches it): require_output OMITTED →
    RunUnprocessable; =True → RunUnprocessable; =False → returns the content-less text as-is. The
    DEFAULT is unchanged, so judge/actor/oracle/verify (which never pass the flag) still quarantine
    a content-less verdict — the new path is opt-in. Positive control: require_output=False with
    NON-empty output returns that text verbatim (the flag suppresses only the content-less guard)."""
    deps = _lead_deps(_run_dir(tmp_path), _worktree(tmp_path))

    def _go(require, text, tag):
        kw = {} if require is None else {"require_output": require}
        return run_stage(
            stage="lead_author", prompt_path=_prompt(tmp_path), model="m", effort=None,
            trace_name=f"ro-{tag}.jsonl", label="la", user="u",
            learning_run_dir=deps.run_dir, deps=deps, request_limit=4,
            make_model=_fake_model(_replay(text)), **kw,
        )

    with override_allow_model_requests(False):
        with pytest.raises(RunUnprocessable):
            _go(None, "  ", "default")            # default unchanged — regression guard
        with pytest.raises(RunUnprocessable):
            _go(True, "  ", "true")
        assert _go(False, "  ", "false") == "  "  # opt-in suppresses the content-less guard
        assert _go(False, "real story", "pc") == "real story"   # positive control


def test_lead_author_registers_file_writers(tmp_path):
    """The lead author is the loop's first writer: build_stage_agent(LeadAuthorDeps) registers the
    file writers (write_file/edit_file) on top of read + bash — the four-tool in-process surface.
    #538: the toolset comes from the agent's AgentDefinition by role (LEAD_AUTHOR_DEF's write=True
    ToolSet), not a `writers` flag. (The read-only predictors registering NOTHING is pinned in
    test_agent_definition.)"""
    logger = observe.RequestLogger(tmp_path / "toolset.jsonl")
    try:
        w = _pydantic_stage.build_stage_agent(
            LeadAuthorDeps, _prompt(tmp_path), "m", None, logger, "la",
            make_model=_fake_model(_replay("")))
    finally:
        logger.close()
    assert list(w._function_toolset.tools) == ["bash", "read_file", "write_file", "edit_file"]


# ===========================================================================
# F2 — a repo-relative file op resolves against the WORKTREE, not the process cwd
# ===========================================================================

def test_relative_write_lands_in_worktree_not_process_cwd(tmp_path, monkeypatch):
    """F2 (the sharpest correctness fault), pinned as the OBSERVABLE (impl-agnostic — chdir or
    resolve-against-deps both pass). Process cwd is chdir'd to a DECOY dir that ITSELF holds a
    defender/skills tree; the model issues write_file('defender/skills/.../new.md', body)
    through the REAL _run_author_pydantic(repo_root=<worktree>). The file must land under the
    WORKTREE (allowed by write_allow) with content==body, and NOTHING is written under the
    decoy — the write resolves against repo_root, never the ambient cwd. (The bash lane already
    runs at the worktree via _tool_bash cwd=deps.defender_dir.parent; the FILE tools must too.)"""
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    decoy = tmp_path / "decoy"
    (decoy / "defender" / "skills" / "gather" / "queries" / "foo").mkdir(parents=True)
    monkeypatch.chdir(decoy)
    rel = "defender/skills/gather/queries/foo/new.md"
    fn = _tool_then_text([("write_file", {"path": rel, "content": "BODY-42"})], "done")
    with override_allow_model_requests(False):
        out = _run_author_pydantic(
            prompt_path=_prompt(tmp_path), model="m", effort=None, trace_name="f2.jsonl",
            label="la", user="u", learning_run_dir=rd, repo_root=wt, request_limit=6,
            make_model=_fake_model(fn))
    assert out == "done"
    landed = wt / "defender" / "skills" / "gather" / "queries" / "foo" / "new.md"
    assert landed.is_file()                                       # positive: real write, in the worktree
    assert landed.read_text() == "BODY-42"
    assert not (decoy / rel).exists()                             # negative: never the ambient cwd


def test_write_into_new_subtree_creates_parents(tmp_path):
    """A promote/lift into a not-yet-existing skills subtree must succeed (the file writers mkdir
    their approved path's parents, mirroring the claude -p Write they replace) — NOT raise an
    uncaught FileNotFoundError that run_stage maps to RunUnprocessable, quarantining the whole tick
    and discarding every valid edit. `newsys/` does not exist in the worktree; the write must create
    it and land the file, and the run must complete (out == 'done')."""
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    rel = "defender/skills/newsys/queries/auth.md"           # newsys/ absent in the worktree
    assert not (wt / "defender" / "skills" / "newsys").exists()
    fn = _tool_then_text([("write_file", {"path": rel, "content": "PROMOTED"})], "done")
    with override_allow_model_requests(False):
        out = _run_author_pydantic(
            prompt_path=_prompt(tmp_path), model="m", effort=None, trace_name="newdir.jsonl",
            label="la", user="u", learning_run_dir=rd, repo_root=wt, request_limit=6,
            make_model=_fake_model(fn))
    assert out == "done"
    landed = wt / "defender" / "skills" / "newsys" / "queries" / "auth.md"
    assert landed.read_text() == "PROMOTED"


def test_engine_run_does_not_leak_process_cwd(tmp_path, monkeypatch):
    """If the port fixes F2 via os.chdir(repo_root), that mutation is PROCESS-GLOBAL and would
    corrupt sibling lead+pitfalls spawns / concurrent stages. Pin the observable: after a full
    _run_author_pydantic run, os.getcwd() is UNCHANGED (absolute-ize AND chdir-with-restore both
    pass; a leaked chdir fails)."""
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    decoy = tmp_path / "decoy2"
    decoy.mkdir()
    monkeypatch.chdir(decoy)
    before = os.getcwd()
    with override_allow_model_requests(False):
        _run_author_pydantic(
            prompt_path=_prompt(tmp_path), model="m", effort=None, trace_name="cwd.jsonl",
            label="la", user="u", learning_run_dir=rd, repo_root=wt, request_limit=4,
            make_model=_fake_model(_replay("done")))
    assert os.getcwd() == before


def test_writer_contentless_final_after_write_is_success(tmp_path):
    """The lead author is a writer: it works via write_file/rm and may end with a CONTENT-LESS
    final (whitespace — a truly-empty "" is rejected by pydantic-ai before the guard, so the
    observable content-less case is whitespace). Through the real transport (LEAD_AUTHOR_DEF's
    write-enabled toolset + require_output=False), a write_file tool call THEN a content-less final
    returns that text (not RunUnprocessable) and the write landed — proving the def registered the
    file writers and a content-less final != a failed run. (Production leans on the prompt to emit a
    one-line summary,
    so the normal final is non-empty; this pins the require_output=False safety valve.)"""
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    rel = "defender/skills/gather/queries/foo/e.md"
    fn = _tool_then_text([("write_file", {"path": rel, "content": "X"})], "  ")
    with override_allow_model_requests(False):
        out = _run_author_pydantic(
            prompt_path=_prompt(tmp_path), model="m", effort=None, trace_name="e.jsonl",
            label="la", user="u", learning_run_dir=rd, repo_root=wt, request_limit=6,
            make_model=_fake_model(fn))
    assert out == "  "
    assert (wt / "defender" / "skills" / "gather" / "queries" / "foo" / "e.md").read_text() == "X"


# ===========================================================================
# run_author_stage — rc mapping (F1) + key ordering + trace key
# ===========================================================================

def test_run_author_stage_success_returns_zero():
    """A run_author that completes (returns text — or "" for a writer) → rc 0."""
    assert _spawn(run_author=lambda **kw: "") == 0


def test_run_author_stage_run_unprocessable_maps_to_124():
    """A per-run fault (timeout / usage-limit / model error / empty verdict → RunUnprocessable
    from run_author) → rc 124 (single-run quarantine). The positive contrast to config faults."""
    def _boom(**kw):
        raise RunUnprocessable("model timed out")
    assert _spawn(run_author=_boom) == 124


def test_run_author_stage_config_fault_propagates_not_124():
    """F1 = PROPAGATE. A FatalConfigError — from key sourcing (bad/absent metered key, unroutable
    model, cross-provider effort) OR from run_author (run_stage's build ValueError→FatalConfigError)
    — must RE-RAISE, NOT be mapped to 124. A deployment-wide misconfig then fails ONCE, loudly
    (systemic exit-2), instead of quarantining every queued marker one-by-one."""
    def _boom_key(model, label):
        raise FatalConfigError("needs FIREWORKS_API_KEY")
    with pytest.raises(FatalConfigError, match="FIREWORKS_API_KEY"):
        _spawn(source_key=_boom_key)

    def _boom_build(**kw):
        raise FatalConfigError("misconfigured effort")
    with pytest.raises(FatalConfigError):
        _spawn(run_author=_boom_build)
    # rejected: catch FatalConfigError → return 124 "to keep the drain alive" — a single misconfig
    #           would then burn the whole queue into quarantine one marker per tick, invisibly


def test_run_author_stage_stage_abort_propagates():
    """StageAbort (a systemic fault) also propagates — only RunUnprocessable is caught→124."""
    def _boom(**kw):
        raise StageAbort("systemic")
    with pytest.raises(StageAbort):
        _spawn(run_author=_boom)


def test_run_author_stage_sources_key_before_run():
    """Ordering: the metered key is sourced BEFORE the transport runs (a run that bills before
    its key is present would 401). Observable via ordered spy recording; the key is sourced for
    the configured model."""
    events = []
    _spawn(
        source_key=lambda model, label: events.append(("key", model)),
        run_author=lambda **kw: events.append(("run", kw.get("model"))) or "",
        model=config.LEAD_AUTHOR_MODEL,
    )
    assert [e[0] for e in events] == ["key", "run"]
    assert events[0][1] == config.LEAD_AUTHOR_MODEL


def test_run_author_stage_trace_name_carries_batch_id_and_pid(tmp_path):
    """The per-spawn trace name is unique on (batch_id, pid): batch_id distinguishes concurrent
    DIFFERENT-run spawns; pid distinguishes concurrent drain PROCESSES sharing one run. Capture
    the trace_name run_author_stage hands the transport for two batch_ids into one run dir."""
    rd = _run_dir(tmp_path)
    seen = []

    def _cap(**kw):
        seen.append(kw["trace_name"])
        return ""

    for bid in ("run-A", "run-B"):
        _spawn(batch_id=bid, learning_run_dir=rd, run_author=_cap)
    assert len(set(seen)) == 2                       # distinct per batch_id
    pid = str(os.getpid())
    assert all(pid in n for n in seen)               # pid in every name
    assert any("run-A" in n for n in seen)
    assert any("run-B" in n for n in seen)


def test_two_distinct_traces_into_one_dir_both_survive(tmp_path):
    """Positive control for the truncate-mode RequestLogger: two spawns with DISTINCT trace names
    into ONE learning_run_dir both leave a non-empty trace — the second open() does not clobber
    the first. Driven in turn (deterministic — a collision would be a same-name truncate, which
    distinct names avoid; no race harness needed)."""
    rd, wt = _run_dir(tmp_path), _worktree(tmp_path)
    with override_allow_model_requests(False):
        for name in ("run-A.7.trace.jsonl", "run-B.7.trace.jsonl"):
            _run_author_pydantic(
                prompt_path=_prompt(tmp_path), model="m", effort=None, trace_name=name,
                label="la", user="u", learning_run_dir=rd, repo_root=wt, request_limit=4,
                make_model=_fake_model(_replay("done")))
    a, b = rd / "run-A.7.trace.jsonl", rd / "run-B.7.trace.jsonl"
    assert a.is_file()
    assert a.read_text().strip()
    assert b.is_file()
    assert b.read_text().strip()


# ===========================================================================
# config cross-product + defaults (FACT-EFFORT / F5) + build-fault → FatalConfigError
# ===========================================================================

def test_lead_author_config_defaults_glm_low():
    """The migration flips the shipped defaults: model glm-5.2, effort low (matching the defender
    MAIN + verifier), plus a generous request limit for a multi-file editor."""
    assert config.LEAD_AUTHOR_MODEL == "glm-5.2"
    assert config.LEAD_AUTHOR_EFFORT == "low"
    assert config.LEAD_AUTHOR_REQUEST_LIMIT >= 50


def test_effort_cross_product_builds(monkeypatch):
    """FACT-EFFORT / F5. The default effort ``low`` is cross-provider-safe, so the documented
    claude-* A/B override (harness_lead pins claude-sonnet-4-6) still BUILDS, and the glm-5.2
    default builds. Guarded negative: claude-* + ``none`` (a Fireworks-only effort) raises
    ValueError — proving that had the default been ``none``, the claude pin would be dead on
    arrival, so ``low`` is the load-bearing reconciled choice. (Fake keys; settings make no
    request.)"""
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    providers.build_for_effort("glm-5.2", config.LEAD_AUTHOR_EFFORT)             # default builds
    providers.build_for_effort("claude-sonnet-4-6", config.LEAD_AUTHOR_EFFORT)   # A/B override builds
    with pytest.raises(ValueError, match="none"):
        providers.build_for_effort("claude-sonnet-4-6", "none")                  # Fireworks-only effort


def test_claude_none_effort_becomes_fatal_config(tmp_path, monkeypatch):
    """FACT-BUILDERR wiring end-to-end: an unsupported cross-provider effort (claude-* + none)
    raises ValueError at build, which run_stage maps to FatalConfigError (systemic, not a per-run
    RunUnprocessable). Fake key; the ValueError fires before any request (real make_model)."""
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    with override_allow_model_requests(False), pytest.raises(FatalConfigError):
        _run_author_pydantic(
            prompt_path=_prompt(tmp_path), model="claude-sonnet-4-6", effort="none",
            trace_name="cfg.jsonl", label="la", user="u",
            learning_run_dir=_run_dir(tmp_path), repo_root=_worktree(tmp_path), request_limit=4)


def test_unroutable_model_source_key_fatal_config(tmp_path):
    """source_first_party_key (the REAL default source_key) raises FatalConfigError on a model
    that routes to no provider — and per F1 that propagates (not 124). run_author is a fake so
    nothing runs; the fault is at key-sourcing time."""
    with pytest.raises(FatalConfigError):
        run_author_stage(
            system_prompt_file=_prompt(tmp_path), batch_id="run-A", user_prompt="u",
            repo_root=_worktree(tmp_path), learning_run_dir=_run_dir(tmp_path),
            log_label="lead author", log=lambda *a, **k: None,
            model="gpt-4-turbo", run_author=lambda **kw: "x")
