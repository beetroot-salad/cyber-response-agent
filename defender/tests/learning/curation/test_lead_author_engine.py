"""In-process PydanticAI lead-author engine (FunctionModel, no network): write_allow/rm confinement, cwd handling, fault mapping."""
from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import (  # noqa: E402
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender.learning.core.config import StageContext, StageWiring  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.learning.core.config import (  # noqa: E402
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
)
from defender.learning.leads.lead_author_engine import (  # noqa: E402
    LEAD_AUTHOR_DEF,
    LeadAuthorDeps,
    _run_lead_author_pydantic,
    run_author_stage,
)
from defender.learning._pydantic_stage import run_stage  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.permission import AgentPolicy  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.tests.support.shared.contracts._repo import seed_adapter_stubs  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import replay_once as _replay  # noqa: E402
from defender.run_repository import WIRE_LOG_DIR  # noqa: E402


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
    ``defender/skills`` spelling regardless of the worktree location).

    ``skills_dir`` must be a REAL path under a tree that declares adapters, not the bare
    ``/wt/defender/skills`` string these shape tests used to pass. Since #772 the policy's write
    lanes and its ``rm`` grant are both compiled per declared system, so the tree is now an input
    to the shape, not just an anchor for it — a policy built against a tree with no adapters
    would be a policy with no lanes, which ``bind`` refuses.
    """
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
    """A tmp 'batch worktree': <root>/defender/skills/... exists so real writes land somewhere.

    It declares `elastic` and `cmdb` as systems because since #772 the write allow compiles one
    lane PER declared system — a worktree with a skills dir and no adapters is a tree in which
    nothing under `skills/` is a system, so the policy has no lane at all and `bind` refuses it.
    That is the tree's fault, not the policy's, which is why the probe paths below moved off the
    old `queries/foo/` (a name no tree ever declared) onto `queries/elastic/`.
    """
    root = tmp_path / "wt"
    (root / "defender" / "skills" / "gather" / "queries" / "elastic" / "_draft").mkdir(
        parents=True
    )
    (root / "defender" / "skills" / "elastic" / "_draft").mkdir(parents=True)
    seed_adapter_stubs(root / "defender", ("elastic", "cmdb"))
    return root


def _run_dir(tmp_path):
    d = tmp_path / "runs" / "run-A"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _spawn(**over):
    """run_author_stage with hermetic defaults (fake key + fake transport); override per case.

    Keeps the flat per-knob override ergonomics the cases rely on and folds them into the
    #713 grouped call shape here, so a case still says `model=...` / `batch_id=...`."""
    kw = dict(
        system_prompt_file=Path("/tmp/does-not-matter-lae.md"),
        batch_id="run-A", user_prompt="u", repo_root=Path("/tmp/wt"),
        learning_run_dir=Path("/tmp/rd"), log_label="lead author", log=logging.getLogger("defender.test"),
        source_key=lambda model, label: None, run_author=lambda *a, **kw: "",
        model=config.lead_author_model(), effort=config.lead_author_effort(),
        timeout=config.lead_author_timeout(), request_limit=config.lead_author_request_limit(),
    )
    kw.update(over)
    log_label = kw.pop("log_label")
    return run_author_stage(
        wiring=StageWiring.for_batch(
            kw.pop("system_prompt_file"), kw.pop("model"), kw.pop("effort"),
            batch_id=kw.pop("batch_id"), label=log_label,
        ),
        ctx=StageContext(
            learning_run_dir=kw.pop("learning_run_dir"),
            user=kw.pop("user_prompt"),
            request_limit=kw.pop("request_limit"),
            wall_clock_timeout=kw.pop("timeout"),
            repo_root=kw.pop("repo_root"),
            box=kw.pop("box", None),
            salt=kw.pop("salt", None),
        ),
        log_label=log_label,
        **kw,
    )


# bind(LEAD_AUTHOR_DEF, defender_dir=) — worktree binding + safe-by-construction

def test_for_run_binds_worktree_defender_dir_and_write_allow(tmp_path):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    deps = _lead_deps(rd, wt)
    assert deps.defender_dir == wt / "defender"
    assert len(deps.policy.write_allow) == 5  # the five named lanes, anchored to the worktree
    assert deps.role is AgentRole.LEAD_AUTHOR
    skill = wt / "defender" / "skills" / "gather" / "queries" / "elastic" / "x.md"
    # positive: the worktree binding lets the agent write + read its own corpus
    assert permission.decide_write(
        skill, "body\n", run_dir=rd, defender_dir=deps.defender_dir, policy=deps.policy).allow
    assert permission.decide_read(skill, run_dir=rd, defender_dir=deps.defender_dir, policy=deps.policy).allow
    # guarded negatives: a policy bound to a DIFFERENT worktree tree denies the write …
    other_pol = _lead_deps(rd, _worktree(tmp_path / "other")).policy
    assert not permission.decide_write(
        skill, "body\n", run_dir=rd, defender_dir=deps.defender_dir, policy=other_pol).allow
    # … and calling the gate with a mismatched defender_dir (the split) denies the read.
    assert not permission.decide_read(skill, run_dir=rd, defender_dir=config.REPO_ROOT / "defender", policy=deps.policy).allow


def test_lead_author_deps_cannot_be_born_without_policy(tmp_path):
    with pytest.raises(ValidationError):  # 1067: a required/kw-only miss is pydantic's ValidationError, never stdlib's TypeError
        LeadAuthorDeps(run_dir=tmp_path, defender_dir=tmp_path / "defender", run_id="x")
    deps = _lead_deps(_run_dir(tmp_path), _worktree(tmp_path))
    assert deps.policy.write_allow  # non-empty
    assert not permission.decide_bash("defender-elastic query x", policy=deps.policy).allow
    assert not permission.decide_bash(
        "defender-elastic query x | defender-sql 'SELECT 1'", policy=deps.policy).allow


# the bound lead-author policy — shape + the rm-of-drafts matcher (F3) + asymmetry


def test_rm_repo_relative_draft_allowed_regardless_of_worktree_location(tmp_path):
    wt = _worktree(tmp_path)
    pol = _lead_deps(_run_dir(tmp_path), wt).policy
    assert permission.decide_bash("rm defender/skills/elastic/_draft/x.md", policy=pol, run_dir=wt, cwd_anchor=wt).allow
    assert permission.decide_bash(f"rm {wt}/defender/skills/elastic/_draft/x.md", policy=pol, run_dir=wt, cwd_anchor=wt).allow


def test_rm_outside_skills_denied(tmp_path):
    """rm of a path OUTSIDE defender/skills (lessons, an absolute system file) → denied: the
    skills prefix and the resolved operand's scope are both checked."""
    wt = _worktree(tmp_path)
    pol = _lead_policy(wt / "defender" / "skills")
    assert not permission.decide_bash("rm defender/lessons/z.md", policy=pol, run_dir=wt, cwd_anchor=wt).allow
    assert not permission.decide_bash("rm /etc/passwd", policy=pol, run_dir=wt, cwd_anchor=wt).allow


def test_rm_flags_and_multipath_denied(tmp_path):
    """F3: single-path rm only. ``rm -rf <skills>`` (a flag) and ``rm a b`` (multi-path) are
    DENIED — matching the old ``rm defender/skills/:*`` intent (one draft removed at a time)."""
    wt = _worktree(tmp_path)
    pol = _lead_policy(wt / "defender" / "skills")
    assert not permission.decide_bash("rm -rf defender/skills/elastic/_draft/x.md", policy=pol, run_dir=wt, cwd_anchor=wt).allow
    assert not permission.decide_bash(
        "rm defender/skills/elastic/_draft/a.md defender/skills/elastic/_draft/b.md",
        policy=pol, run_dir=wt, cwd_anchor=wt,
    ).allow
    # rejected: allow -f / multi-path because "it's all under skills" — the agent issues one rm
    #           per draft; the git scope gate is containment, the regex is shape (mirrors the actor)


def test_rm_command_substitution_denied(tmp_path):
    """``rm $(...)`` is denied by _stage_unsafe (structural), independent of the operand — the
    gate never expands the substitution."""
    wt = _worktree(tmp_path)
    pol = _lead_policy(wt / "defender" / "skills")
    assert not permission.decide_bash(
        "rm $(echo defender/skills/elastic/_draft/x.md)", policy=pol, run_dir=wt, cwd_anchor=wt).allow


def test_cross_surface_parity_out_of_scope_denied_on_both_lanes(tmp_path):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    pol = _lead_deps(rd, wt).policy
    (wt / "defender" / "lessons").mkdir(parents=True)
    skills_ok = wt / "defender" / "skills" / "gather" / "queries" / "elastic" / "y.md"
    lessons = wt / "defender" / "lessons" / "z.md"
    # write surface
    assert permission.decide_write(                                               # positive control
        skills_ok, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    assert not permission.decide_write(                                           # negative
        lessons, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    # rm (bash) surface — repo-relative spellings the matcher recognizes
    assert permission.decide_bash(
        "rm defender/skills/gather/queries/elastic/_draft/y.md", policy=pol, run_dir=wt, cwd_anchor=wt).allow  # positive
    assert not permission.decide_bash("rm defender/lessons/z.md", policy=pol, run_dir=wt, cwd_anchor=wt).allow             # negative


def test_both_lanes_deny_dotdot_traversal_escape(tmp_path):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    pol = _lead_deps(rd, wt).policy
    escape = wt / "defender" / "skills" / ".." / "lessons" / "x.md"
    assert not permission.decide_write(
        escape, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    assert not permission.decide_bash("rm defender/skills/../lessons/x.md", policy=pol, run_dir=wt, cwd_anchor=wt).allow
    # a ..-escape via the absolute spelling is denied too
    assert not permission.decide_bash(f"rm {wt}/defender/skills/../../etc/passwd", policy=pol, run_dir=wt, cwd_anchor=wt).allow
    ok = wt / "defender" / "skills" / "gather" / "queries" / "elastic" / "z.md"
    assert permission.decide_write(
        ok, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    assert permission.decide_bash("rm defender/skills/gather/queries/elastic/_draft/z.md", policy=pol, run_dir=wt, cwd_anchor=wt).allow


# run_stage — require_output (the new flag) + the writers toolset

def test_run_stage_require_output_matrix(tmp_path):
    deps = _lead_deps(_run_dir(tmp_path), _worktree(tmp_path))

    def _go(require, text, tag):
        kw = {} if require is None else {"require_output": require}
        return run_stage(
            stage="lead_author",
            wiring=StageWiring(
                prompt_path=_prompt(tmp_path),
                model="m",
                effort=None,
                trace_name=f"ro-{tag}.jsonl",
                label="la",
            ),
            ctx=StageContext(
                learning_run_dir=deps.run_dir,
                user="u",
                request_limit=4,
                wall_clock_timeout=config.subagent_timeout(),
            ),
            deps=deps,
            make_model=_fake_model(_replay(text)),
            **kw,
        )

    with override_allow_model_requests(False):
        with pytest.raises(RunUnprocessable):
            _go(None, "  ", "default")            # default unchanged — regression guard
        with pytest.raises(RunUnprocessable):
            _go(True, "  ", "true")
        assert _go(False, "  ", "false") == "  "  # opt-in suppresses the content-less guard
        assert _go(False, "real story", "pc") == "real story"   # positive control


# F2 — a repo-relative file op resolves against the WORKTREE, not the process cwd

def test_relative_write_lands_in_worktree_not_process_cwd(tmp_path, monkeypatch):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    decoy = tmp_path / "decoy"
    (decoy / "defender" / "skills" / "gather" / "queries" / "elastic").mkdir(parents=True)
    monkeypatch.chdir(decoy)
    rel = "defender/skills/gather/queries/elastic/new.md"
    fn = _tool_then_text([("write_file", {"path": rel, "content": "BODY-42"})], "done")
    with override_allow_model_requests(False):
        out = _run_lead_author_pydantic(
            StageWiring(
                prompt_path=_prompt(tmp_path), model="m",
                effort=None, trace_name="f2.jsonl",
                label="la",
            ),
            StageContext(
                learning_run_dir=rd,
                user="u",
                request_limit=6,
                wall_clock_timeout=config.lead_author_timeout(),
                repo_root=wt,
            ),
            make_model=_fake_model(fn),
        )
    assert out == "done"
    landed = wt / "defender" / "skills" / "gather" / "queries" / "elastic" / "new.md"
    assert landed.is_file()                                       # positive: real write, in the worktree
    assert landed.read_text() == "BODY-42"
    assert not (decoy / rel).exists()                             # negative: never the ambient cwd


def test_write_into_new_subtree_creates_parents(tmp_path):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    rel = "defender/skills/cmdb/_draft/auth.md"              # cmdb/ absent in the worktree
    assert not (wt / "defender" / "skills" / "cmdb").exists()
    fn = _tool_then_text([("write_file", {"path": rel, "content": "PROMOTED"})], "done")
    with override_allow_model_requests(False):
        out = _run_lead_author_pydantic(
            StageWiring(
                prompt_path=_prompt(tmp_path), model="m",
                effort=None, trace_name="newdir.jsonl",
                label="la",
            ),
            StageContext(
                learning_run_dir=rd,
                user="u",
                request_limit=6,
                wall_clock_timeout=config.lead_author_timeout(),
                repo_root=wt,
            ),
            make_model=_fake_model(fn),
        )
    assert out == "done"
    landed = wt / "defender" / "skills" / "cmdb" / "_draft" / "auth.md"
    assert landed.read_text() == "PROMOTED"


def test_engine_run_does_not_leak_process_cwd(tmp_path, monkeypatch):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    decoy = tmp_path / "decoy2"
    decoy.mkdir()
    monkeypatch.chdir(decoy)
    before = os.getcwd()
    with override_allow_model_requests(False):
        _run_lead_author_pydantic(
            StageWiring(
                prompt_path=_prompt(tmp_path), model="m",
                effort=None, trace_name="cwd.jsonl",
                label="la",
            ),
            StageContext(
                learning_run_dir=rd,
                user="u",
                request_limit=4,
                wall_clock_timeout=config.lead_author_timeout(),
                repo_root=wt,
            ),
            make_model=_fake_model(_replay("done")),
        )
    assert os.getcwd() == before


def test_writer_contentless_final_after_write_is_success(tmp_path):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    rel = "defender/skills/gather/queries/elastic/e.md"
    fn = _tool_then_text([("write_file", {"path": rel, "content": "X"})], "  ")
    with override_allow_model_requests(False):
        out = _run_lead_author_pydantic(
            StageWiring(
                prompt_path=_prompt(tmp_path), model="m",
                effort=None, trace_name="e.jsonl",
                label="la",
            ),
            StageContext(
                learning_run_dir=rd,
                user="u",
                request_limit=6,
                wall_clock_timeout=config.lead_author_timeout(),
                repo_root=wt,
            ),
            make_model=_fake_model(fn),
        )
    assert out == "  "
    assert (wt / "defender" / "skills" / "gather" / "queries" / "elastic" / "e.md").read_text() == "X"


# run_author_stage — rc mapping (F1) + key ordering + trace key

def test_run_author_stage_success_returns_zero():
    """A run_author that completes (returns text — or "" for a writer) → rc 0."""
    assert _spawn(run_author=lambda *a, **kw: "") == 0


def test_run_author_stage_run_unprocessable_maps_to_124():
    """A per-run fault (timeout / usage-limit / model error / empty verdict → RunUnprocessable
    from run_author) → rc 124 (single-run quarantine). The positive contrast to config faults."""
    def _boom(*a, **kw):
        raise RunUnprocessable("model timed out")
    assert _spawn(run_author=_boom) == 124


def test_run_author_stage_config_fault_propagates_not_124():
    def _boom_key(model, label):
        raise FatalConfigError("needs FIREWORKS_API_KEY")
    with pytest.raises(FatalConfigError, match="FIREWORKS_API_KEY"):
        _spawn(source_key=_boom_key)

    def _boom_build(*a, **kw):
        raise FatalConfigError("misconfigured effort")
    with pytest.raises(FatalConfigError):
        _spawn(run_author=_boom_build)
    # rejected: catch FatalConfigError → return 124 "to keep the drain alive" — a single misconfig
    #           would then burn the whole queue into quarantine one marker per tick, invisibly


def test_run_author_stage_stage_abort_propagates():
    """StageAbort (a systemic fault) also propagates — only RunUnprocessable is caught→124."""
    def _boom(*a, **kw):
        raise StageAbort("systemic")
    with pytest.raises(StageAbort):
        _spawn(run_author=_boom)


def test_run_author_stage_sources_key_before_run():
    events = []
    _spawn(
        source_key=lambda model, label: events.append(("key", model)),
        run_author=lambda wiring, ctx, **kw: events.append(("run", wiring.model)) or "",
        model=config.lead_author_model(),
    )
    assert [e[0] for e in events] == ["key", "run"]
    assert events[0][1] == config.lead_author_model()


def test_two_distinct_traces_into_one_dir_both_survive(tmp_path):
    rd, wt = _run_dir(tmp_path), _worktree(tmp_path)
    with override_allow_model_requests(False):
        for name in ("run-A.7.trace.jsonl", "run-B.7.trace.jsonl"):
            _run_lead_author_pydantic(
                StageWiring(
                    prompt_path=_prompt(tmp_path), model="m",
                    effort=None, trace_name=name,
                    label="la",
                ),
                StageContext(
                    learning_run_dir=rd,
                    user="u",
                    request_limit=4,
                    wall_clock_timeout=config.lead_author_timeout(),
                    repo_root=wt,
                ),
                make_model=_fake_model(_replay("done")),
            )
    a, b = (rd / WIRE_LOG_DIR / "run-A.7.trace.jsonl",
            rd / WIRE_LOG_DIR / "run-B.7.trace.jsonl")
    assert a.is_file()
    assert a.read_text().strip()
    assert b.is_file()
    assert b.read_text().strip()


# config cross-product + defaults (FACT-EFFORT / F5) + build-fault → FatalConfigError


def test_claude_none_effort_becomes_fatal_config(tmp_path, monkeypatch):
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    with override_allow_model_requests(False), pytest.raises(FatalConfigError):
        _run_lead_author_pydantic(
            StageWiring(
                prompt_path=_prompt(tmp_path), model="claude-sonnet-4-6",
                effort="none", trace_name="cfg.jsonl",
                label="la",
            ),
            StageContext(
                learning_run_dir=_run_dir(tmp_path),
                user="u",
                request_limit=4,
                wall_clock_timeout=config.lead_author_timeout(),
                repo_root=_worktree(tmp_path),
            ),
        )


def test_unroutable_model_source_key_fatal_config(tmp_path):
    with pytest.raises(FatalConfigError):
        _spawn(
            system_prompt_file=_prompt(tmp_path),
            repo_root=_worktree(tmp_path), learning_run_dir=_run_dir(tmp_path),
            model="gpt-4-turbo",
            source_key=config.source_first_party_key,
            run_author=lambda *a, **kw: "x")


@pytest.mark.parametrize("grouped", [False, True])
def test_box_output_overflow_is_not_an_unprocessable_learning_stage(tmp_path, grouped):
    from defender.box import BoxOutputLimitExceeded
    from defender.runtime.exception_groups import carried

    overflow = BoxOutputLimitExceeded()
    fault = ExceptionGroup("stage", [overflow]) if grouped else overflow
    deps = _lead_deps(_run_dir(tmp_path), _worktree(tmp_path))

    def fail(_messages, _info):
        raise fault

    with pytest.raises(type(fault)) as caught:
        run_stage(
            stage="lead_author",
            wiring=StageWiring(prompt_path=_prompt(tmp_path), model="m", effort=None,
                               trace_name="output-overflow.jsonl", label="la"),
            ctx=StageContext(learning_run_dir=deps.run_dir, user="u", request_limit=4,
                             wall_clock_timeout=config.subagent_timeout()),
            deps=deps, make_model=_fake_model(fail),
        )
    assert carried(caught.value, BoxOutputLimitExceeded) is overflow
