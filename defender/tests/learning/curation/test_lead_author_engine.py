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
from defender.investigation import permission  # noqa: E402
from defender.investigation.agent_definition import RunScope, bind  # noqa: E402
from defender._agent_role import AgentRole  # noqa: E402
from defender.investigation.permission import AgentPolicy  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.tests.support.shared.contracts._repo import seed_adapter_stubs  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import replay_once as _replay  # noqa: E402
from defender.records import WIRE_LOG_DIR  # noqa: E402


#: #1108 P4 (O7, option (a) of the S-H report): the lane writes a batch draft's `agent/skills`;
#: the adapters and the authored product prompts stay in the product checkout. The deps bind the
#: product tree as `defender_dir` and the draft's `agent/` as `RunScope(tenant_agent=...)`
#: (ASSUMED SEAM: the lead author's write lanes compile under that scope); relative paths resolve
#: from the draft's `agent/` (P3 `Batch.box_request`'s workdir).


def _lead_deps(run_dir: Path, wt: Path) -> LeadAuthorDeps:
    """The lead-author deps via the SINGLE bind seam (#551): `wt/defender` (product: adapters)
    as the policy anchor and the deps' `defender_dir`, `wt/draft/agent` as the tenant agent."""
    deps = bind(LEAD_AUTHOR_DEF, run_dir, defender_dir=wt / "defender",
                scope=RunScope(tenant_agent=_agent(wt)))
    assert isinstance(deps, LeadAuthorDeps)
    return deps


def _lead_policy(wt: Path) -> AgentPolicy:
    """The lead-author policy for the lane tree `wt` (product + draft), via bind."""
    return _lead_deps(Path("/tmp/lead-run"), wt).policy


def _agent(wt: Path) -> Path:
    """The batch draft's `agent/` beside the product tree in the lane tree `wt`."""
    return wt / "draft" / "agent"


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
    p.write_text("Curate the catalog. Edit skill files under skills/. Finish when done.\n")
    return p


def _worktree(tmp_path):
    """A tmp lane tree: `<root>/defender` (product: the `elastic` and `cmdb` adapters, since #772
    one lane per declared system) and `<root>/draft/agent/skills/...` (the batch draft the lane
    writes), with the draft folders real writes land in."""
    root = tmp_path / "wt"
    skills = _agent(root) / "skills"
    (skills / "gather" / "queries" / "elastic" / "_draft").mkdir(parents=True)
    (skills / "elastic" / "_draft").mkdir(parents=True)
    (root / "defender" / "skills").mkdir(parents=True)
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
    """One bind anchors the product tree and the draft: the lane writes and reads its own draft,
    and a policy bound to another draft refuses both (#551, O7)."""
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    deps = _lead_deps(rd, wt)
    assert deps.defender_dir == wt / "defender"
    assert len(deps.policy.write_allow) == 5  # the five named lanes, anchored to the draft
    assert deps.role is AgentRole.LEAD_AUTHOR
    skill = _agent(wt) / "skills" / "gather" / "queries" / "elastic" / "x.md"
    # positive: the binding lets the agent write + read its own draft
    assert permission.decide_write(
        skill, "body\n", run_dir=rd, defender_dir=deps.defender_dir, policy=deps.policy).allow
    assert permission.decide_read(skill, run_dir=rd, defender_dir=deps.defender_dir, policy=deps.policy).allow
    # guarded negatives: a policy bound to a DIFFERENT lane tree denies the write and the read
    other_pol = _lead_deps(rd, _worktree(tmp_path / "other")).policy
    assert not permission.decide_write(
        skill, "body\n", run_dir=rd, defender_dir=deps.defender_dir, policy=other_pol).allow
    assert not permission.decide_read(
        skill, run_dir=rd, defender_dir=deps.defender_dir, policy=other_pol).allow
    # … and the product tree's own skills are no lane (O1/O7: tenant writes touch agent/ only)
    product = wt / "defender" / "skills" / "elastic" / "_draft" / "x.md"
    assert not permission.decide_write(
        product, "body\n", run_dir=rd, defender_dir=deps.defender_dir, policy=deps.policy).allow


def test_lead_author_deps_cannot_be_born_without_policy(tmp_path):
    with pytest.raises(ValidationError):  # 1067: a required/kw-only miss is pydantic's ValidationError, never stdlib's TypeError
        LeadAuthorDeps(run_dir=tmp_path, defender_dir=tmp_path / "defender", run_id="x")
    deps = _lead_deps(_run_dir(tmp_path), _worktree(tmp_path))
    assert deps.policy.write_allow  # non-empty
    assert not permission.decide_bash("defender-elastic query x", policy=deps.policy).allow
    assert not permission.decide_bash(
        "defender-elastic query x | defender-sql 'SELECT 1'", policy=deps.policy).allow


# the bound lead-author policy — shape + the rm-of-drafts matcher (F3) + asymmetry
# (#1108 P4: rm runs from the draft's `agent/`, the box's workdir; `skills/...` is relative to it)


def _rm(cmd: str, wt: Path, pol: AgentPolicy) -> bool:
    agent = _agent(wt)
    return permission.decide_bash(cmd, policy=pol, run_dir=agent, cwd_anchor=agent).allow


def test_rm_repo_relative_draft_allowed_regardless_of_worktree_location(tmp_path):
    wt = _worktree(tmp_path)
    pol = _lead_deps(_run_dir(tmp_path), wt).policy
    assert _rm("rm skills/elastic/_draft/x.md", wt, pol)
    assert _rm(f"rm {_agent(wt)}/skills/elastic/_draft/x.md", wt, pol)


def test_rm_outside_skills_denied(tmp_path):
    """rm of a path OUTSIDE the draft's skills (lessons, the product tree, an absolute system
    file) → denied, with the in-skills draft as the positive control (#551, O7)."""
    wt = _worktree(tmp_path)
    pol = _lead_policy(wt)
    assert _rm("rm skills/elastic/_draft/z.md", wt, pol)
    assert not _rm("rm lessons/z.md", wt, pol)
    assert not _rm(f"rm {wt}/defender/skills/elastic/_draft/z.md", wt, pol)
    assert not _rm("rm /etc/passwd", wt, pol)


def test_rm_flags_and_multipath_denied(tmp_path):
    """F3: single-path rm only. ``rm -rf <skills>`` (a flag) and ``rm a b`` (multi-path) are
    DENIED — one draft removed at a time."""
    wt = _worktree(tmp_path)
    pol = _lead_policy(wt)
    assert _rm("rm skills/elastic/_draft/x.md", wt, pol)
    assert not _rm("rm -rf skills/elastic/_draft/x.md", wt, pol)
    assert not _rm("rm skills/elastic/_draft/a.md skills/elastic/_draft/b.md", wt, pol)


def test_rm_command_substitution_denied(tmp_path):
    """``rm $(...)`` is denied by _stage_unsafe (structural), independent of the operand — the
    gate never expands the substitution."""
    wt = _worktree(tmp_path)
    pol = _lead_policy(wt)
    assert _rm("rm skills/elastic/_draft/x.md", wt, pol)
    assert not _rm("rm $(echo skills/elastic/_draft/x.md)", wt, pol)


def test_cross_surface_parity_out_of_scope_denied_on_both_lanes(tmp_path):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    pol = _lead_deps(rd, wt).policy
    agent = _agent(wt)
    (agent / "lessons").mkdir(parents=True)
    skills_ok = agent / "skills" / "gather" / "queries" / "elastic" / "y.md"
    lessons = agent / "lessons" / "z.md"
    # write surface
    assert permission.decide_write(                                               # positive control
        skills_ok, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    assert not permission.decide_write(                                           # negative
        lessons, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    # rm (bash) surface
    assert _rm("rm skills/gather/queries/elastic/_draft/y.md", wt, pol)          # positive
    assert not _rm("rm lessons/z.md", wt, pol)                                    # negative


def test_both_lanes_deny_dotdot_traversal_escape(tmp_path):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    pol = _lead_deps(rd, wt).policy
    agent = _agent(wt)
    escape = agent / "skills" / ".." / "lessons" / "x.md"
    assert not permission.decide_write(
        escape, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    assert not _rm("rm skills/../lessons/x.md", wt, pol)
    # a ..-escape via the absolute spelling is denied too
    assert not _rm(f"rm {agent}/skills/../../../etc/passwd", wt, pol)
    ok = agent / "skills" / "gather" / "queries" / "elastic" / "z.md"
    assert permission.decide_write(
        ok, "b\n", run_dir=rd, defender_dir=wt / "defender", policy=pol).allow
    assert _rm("rm skills/gather/queries/elastic/_draft/z.md", wt, pol)


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
    (decoy / "skills" / "gather" / "queries" / "elastic").mkdir(parents=True)
    monkeypatch.chdir(decoy)
    rel = "skills/gather/queries/elastic/new.md"
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
                repo_root=_agent(wt),
            ),
            make_model=_fake_model(fn),
        )
    assert out == "done"
    landed = _agent(wt) / "skills" / "gather" / "queries" / "elastic" / "new.md"
    assert landed.is_file()                                       # positive: real write, in the worktree
    assert landed.read_text() == "BODY-42"
    assert not (decoy / rel).exists()                             # negative: never the ambient cwd


def test_write_into_new_subtree_creates_parents(tmp_path):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    rel = "skills/cmdb/_draft/auth.md"              # cmdb/ absent in the draft
    assert not (_agent(wt) / "skills" / "cmdb").exists()
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
                repo_root=_agent(wt),
            ),
            make_model=_fake_model(fn),
        )
    assert out == "done"
    landed = _agent(wt) / "skills" / "cmdb" / "_draft" / "auth.md"
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
                repo_root=_agent(wt),
            ),
            make_model=_fake_model(_replay("done")),
        )
    assert os.getcwd() == before


def test_writer_contentless_final_after_write_is_success(tmp_path):
    wt, rd = _worktree(tmp_path), _run_dir(tmp_path)
    rel = "skills/gather/queries/elastic/e.md"
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
                repo_root=_agent(wt),
            ),
            make_model=_fake_model(fn),
        )
    assert out == "  "
    assert (_agent(wt) / "skills" / "gather" / "queries" / "elastic" / "e.md").read_text() == "X"


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
    from defender._exception_groups import carried

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
