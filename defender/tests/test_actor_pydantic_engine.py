"""Hermetic tests for the in-process PydanticAI actor engine (no API key, no network).

Drives the REAL `_run_actor_pydantic` (deps build + policy-driven gate + observe trace) with a
`FunctionModel` injected through the actor's `make_model` DI seam, under
`override_allow_model_requests(False)` so any real provider call raises. Plus the actor's
distinctive tool surface — the two pinned lessons-script matchers and the no-`read_roots`
read scope — and the InProcessSubagents.actor routing.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.exceptions import ModelRetry  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.learning.core import config, subagents  # noqa: E402
from defender.learning.pipeline import _pydantic_stage  # noqa: E402
from defender.learning.pipeline import actor_engine  # noqa: E402
from defender.learning.pipeline.actor_engine import ActorDeps, _ActorScope, _run_actor_pydantic  # noqa: E402
from defender.learning.pipeline.actor_engine import ACTOR_DEF  # noqa: E402
from defender.learning.pipeline.malicious_actor.run import is_skip_story  # noqa: E402
from defender.runtime import observe, permission  # noqa: E402
from defender.runtime.agent_definition import RunScope, compile_policy_for  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402

_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT
_DEFENDER_DIR = config.REPO_ROOT / "defender"
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR
# The malicious leg's read confine (both lesson corpora), as malicious_actor.run wires it.
_MALICIOUS_CONFINE = (_ACTOR_DIR, _ENV_DIR)


def _flatten(messages) -> str:
    out = []
    for msg in messages:
        for part in getattr(msg, "parts", []):
            c = getattr(part, "content", None)
            if isinstance(c, str):
                out.append(c)
    return "\n".join(out)


def _replay(turns, *, seen=None):
    """A FunctionModel fn replaying scripted turns. Each turn is
    {"calls": [(tool, args)...], "text": str}."""
    state = {"i": 0}

    def fn(messages, info):
        if seen is not None:
            seen.append(_flatten(messages))
        turn = turns[min(state["i"], len(turns) - 1)]
        state["i"] += 1
        parts = [ToolCallPart(tool_name=n, args=a) for n, a in turn.get("calls", [])]
        if turn.get("text"):
            parts.append(TextPart(content=turn["text"]))
        return ModelResponse(parts=parts)

    return fn


def _fake_model(fn):
    # settings=None — a FunctionModel needs no provider settings (mirrors _replay_harness).
    return lambda model, effort: BuiltModel(FunctionModel(fn), None)


def _lrd(tmp_path):
    lrd = tmp_path / "learning_run"
    lrd.mkdir()
    return lrd


def _prompt(tmp_path):
    p = tmp_path / "actor.md"
    p.write_text("You are the adversarial actor. Emit a story or a SKIP line.\n")
    return p


_STORY = "0. Techniques used\n\n1. The adversary logged in with stolen creds and pivoted.\n"

_RUN = Path("/tmp/actor-run")   # absolute (bind's root guard rejects a relative anchor)


def _actor_policy(scripts, *, read_confine):
    """The actor's compiled policy through the REAL seam.

    #575 deleted the module-private `_actor_policy(scripts, read_confine=…)` constructor: each def
    now hangs its OWN grant builder (`_actor_bash_shapes`) on itself, and the per-leg inputs (which
    pinned scripts this leg may run, which corpora it may read) ride a `RunScope` that
    `compile_policy_for` folds into `ResolvedRoots`. The leg variation is unchanged — it just
    arrives through the one compile seam production uses instead of a private back door."""
    return compile_policy_for(
        ACTOR_DEF, run_dir=_RUN,
        scope=RunScope(scripts=tuple(scripts), read_confine=tuple(read_confine)),
    )


# --- the engine returns the model's final text verbatim + writes its trace ---

def test_run_actor_pydantic_returns_story_and_writes_trace(tmp_path):
    lrd = _lrd(tmp_path)
    fn = _replay([{"text": _STORY}])
    with override_allow_model_requests(False):
        out = _run_actor_pydantic(
            _prompt(tmp_path), "claude-sonnet-4-6", "low", "actor_trace.jsonl", "actor",
            "write the story", lrd,
            scope=_ActorScope((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE),
            make_model=_fake_model(fn),
        )
    assert out == _STORY
    assert (lrd / "actor_trace.jsonl").is_file()
    assert (lrd / "actor_trace.jsonl").read_text().strip()  # at least one request logged


def test_run_actor_pydantic_returns_skip_verbatim(tmp_path):
    # A SKIP short-circuit flows back verbatim so is_skip_story sees it (even behind a
    # GLM reasoning preamble — the hardened is_skip_story scans the first few lines).
    lrd = _lrd(tmp_path)
    fn = _replay([{"text": "Let me consider the menu.\n\nSKIP: no covering initial-access technique"}])
    with override_allow_model_requests(False):
        out = _run_actor_pydantic(
            _prompt(tmp_path), "claude-sonnet-4-6", "low", "actor_trace.jsonl", "actor",
            "write the story", lrd,
            scope=_ActorScope((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE),
            make_model=_fake_model(fn),
        )
    assert out.startswith("Let me consider the menu.")
    assert is_skip_story(out)


# --- the two pinned lessons-script grants ---------------------------------------

def test_script_grant_accepts_pinned_spellings():
    """#575 renamed `_script_pattern` → `_script_grant`, which wraps the same anchored argv regex in
    a `Grant`. The pattern is one of the three `pins_path` EXEMPTIONS to "no grant pattern embeds a
    path": here the operand IS the program, so resolving it and checking it against a scope buys
    nothing the pinned pattern didn't already have (and per #565 the pinned script's own argv is
    ungated regardless). Pin the exemption flag alongside the shape — it is what tells the a2 audit
    sweep this embedded path is deliberate rather than a leaked anchor."""
    g = actor_engine._script_grant(_ENV_RETRIEVE)
    assert g.pins_path is True
    assert g.scope == ()      # nothing to resolve — the path lives in the pattern
    p = g.pattern
    # repo-relative (what the prompt types), absolute, and a bare `python` interpreter
    assert p.fullmatch("python3 defender/scripts/lessons/lessons_env_retrieve.py --alert-rule-ids 5712 --entities host:web")
    assert p.fullmatch(f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712")
    assert p.fullmatch(f"python {_ENV_RETRIEVE} --alert-rule-ids 5712")


def test_script_grant_rejects_wrong_shape():
    p = actor_engine._script_grant(_ENV_RETRIEVE).pattern
    assert not p.fullmatch(f"python3 {_ACTOR_INDEX} --techniques T1078")  # different pinned script
    assert not p.fullmatch("python3 -c print(1)")                         # arbitrary python
    assert not p.fullmatch("cat /etc/passwd")                             # non-python program


def test_actor_script_pipe_denied_through_gate():
    # a pipe re-opens no reader surface: the `| cat` stage is claimed by no actor grant → denied.
    # (`_decide_readers` requires EVERY stage to be claimed, and the actor grants no viewer at all.)
    pol = _actor_policy((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,))
    assert not permission.decide_bash(
        f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712 | cat", policy=pol).allow


# --- the policy through the full gate -------------------------------------------

def test_actor_policy_allows_pinned_scripts_and_denies_offlist():
    pol = _actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE)
    # both pinned lesson scripts are allowed by the actor's grants
    assert permission.decide_bash(f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712", policy=pol).allow
    assert permission.decide_bash(f"python3 {_ACTOR_INDEX} --techniques T1078", policy=pol).allow
    # arbitrary python, an unpinned script, a data-source adapter, and arbitrary shell are denied
    assert not permission.decide_bash("python3 -c 'print(1)'", policy=pol).allow
    assert not permission.decide_bash("python3 defender/scripts/lessons/other.py", policy=pol).allow
    assert not permission.decide_bash("defender-elastic query x", policy=pol).allow
    assert not permission.decide_bash("rm -rf /tmp/x", policy=pol).allow


def test_actor_has_no_viewer_surface_at_all():
    """The actor's bash lane is JUST its pinned-script grants — no `cat`, so no reader surface and
    (by `read_allow_of`) no read shapes either: `decide_read` stays root-only inside the confine,
    which IS the actor's whole read surface.

    This is the property that keeps the actor gray-box: `cat` is the sole opener in the #575 model,
    so an actor without a `cat` grant cannot address a file from bash AT ALL — not the judge's
    rubric, not another corpus, not its own transcript. Guarded by construction rather than by a
    clamp on a wider grant. (Its per-leg confine, enforced on the read tool, is pinned below.)"""
    pol = _actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE)
    assert {g.program for g in pol.bash_allow} == {"python3"}
    assert all(g.pins_path for g in pol.bash_allow)
    assert pol.read_allow == ()   # no cat grant → no shape filter; the confine bounds the reads
    for cmd in (f"cat {_ACTOR_DIR}/T1078.md", "cat /etc/passwd", "grep -n x /etc/passwd", "ls"):
        assert not permission.decide_bash(cmd, policy=pol).allow, cmd


def test_benign_actor_policy_excludes_tradecraft_index():
    # The benign leg carries only the env-retrieve grant; the tradecraft index stays a
    # malicious-only capability (the actor-settings.json boundary, now enforced by policy).
    benign = _actor_policy((_ENV_RETRIEVE,), read_confine=(_ENV_DIR,))
    assert permission.decide_bash(f"python3 {_ENV_RETRIEVE} --alert-rule-ids 5712", policy=benign).allow
    assert not permission.decide_bash(f"python3 {_ACTOR_INDEX} --techniques T1078", policy=benign).allow


# --- read scope: CONFINED to the lesson corpora (#512) --------------------------

def test_actor_read_scope_is_confined_to_lessons(tmp_path):
    # #512: the actor's read_confine REPLACES the defender_dir base, so a defender_dir
    # file OUTSIDE the confine (SKILL.md, the judge rubric) is no longer readable — the
    # gray-box hole #510 opened. run_dir artifacts and in-confine lessons still are.
    #
    # #575: the `raw_reads` / `adapters` capability BITS this used to assert are DELETED — each was
    # a declared value that could disagree with the lane enforcing it. Both properties are now facts
    # about the grant list, so they are asserted where they are decided: no adapter grant and no
    # gather_raw shape means the actor has no ADDRESS for either, not a clamp over a wider one.
    pol = _actor_policy((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE)
    assert set(pol.read_confine) == set(_MALICIOUS_CONFINE)
    assert pol.read_roots == ()          # confine replaces the corpus base; no widening
    # gray-box, by positive enumeration: no adapter route and no viewer surface at all
    assert not permission.decide_bash("defender-elastic query x", policy=pol).allow
    assert not permission.decide_bash(
        "defender-elastic query x | defender-sql 'SELECT 1'", policy=pol).allow
    # the gather_raw half of the old `raw_reads is False` bit still holds — as enumeration now,
    # not as a bit (see ::test_actor_cannot_read_a_staged_gather_raw_payload below).
    lrd = _lrd(tmp_path)
    # in-confine lesson: allowed
    assert permission.decide_read(
        _ACTOR_DIR / "T1078.md", run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=pol
    ).allow
    # under defender_dir but OUTSIDE the confine (SKILL.md): now DENIED
    assert not permission.decide_read(
        _DEFENDER_DIR / "SKILL.md", run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=pol
    ).allow
    # the actor's own run-dir artifact stays readable (run_dir remains a root)
    assert permission.decide_read(
        lrd / "actor_menu.txt", run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=pol
    ).allow
    # a file outside {run_dir} ∪ confine is refused
    assert not permission.decide_read(
        tmp_path / "elsewhere.txt", run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=pol
    ).allow


def test_actor_cannot_read_a_staged_gather_raw_payload(tmp_path):
    """THE GRAY-BOX PROPERTY, at the seam that now decides it.

    This is what `assert pol.raw_reads is False` used to buy, re-expressed as the observable
    decision (#575 deleted the BIT; the property it stood for survives — as enumeration).

    The actor is gray-box BY DESIGN: `lead_repository.actor_view` projects queries only and hides
    `payload_path` precisely so the actor invents its attack story WITHOUT seeing the raw evidence.
    If it can read the payloads, the whole adversarial signal is contaminated — it is no longer
    writing a candidate story, it is reading the answer.

    THE TRAP THIS PINS. At HEAD a RAW clamp denied a `gather_raw/` path for every agent with
    `raw_reads=False`, wherever it sat. Replacing that with positive enumeration over
    `policy.read_allow` ALMOST reopened it: the actor has no `cat` grant, so its `read_allow` is
    `()` — and an empty `read_allow` means "no shape filter", which falls back to ROOT-ONLY. The
    actor's `run_dir` is a root.

    And its run_dir really does hold payloads — this is reachable, not theoretical. The actor's
    `run_dir` IS the *learning* run dir, and `persist._copy_shared_inputs` →
    `lead_repository.stage_tables` COPIES the investigation's whole `gather_raw/` tree into it. The
    two direction legs SHARE one `learning_run_dir` (`orchestrate.py:433`) and run CONCURRENTLY
    (`ThreadPoolExecutor(max_workers=2)`, `orchestrate.py:450`) as actor → oracle → judge → persist,
    so on an `inconclusive` case leg A's persist stages the payloads while leg B's actor is still
    running. `ops/replay_actor.py` replays the actor over an already-staged bundle outright.

    So `decide_read` makes the attacker-influenced channel OPT-IN for every agent: a `gather_raw`
    read needs a shape that NAMES it (gather's raw shape; the judge's scope over its comparison
    roots), never merely a root that contains it. An empty shape list is a widening default, and
    this is the one path class where a widening default is a security failure.

    Driven through the REAL production tool (`tools._tool_read_file` on real `bind`-built deps),
    not a synthetic policy."""
    lrd = _lrd(tmp_path)
    raw = lrd / "gather_raw" / "l-001" / "0.json"
    raw.parent.mkdir(parents=True)
    raw.write_text('{"payload": "the evidence the gray-box actor must not see"}\n')

    from defender.runtime.agent_definition import bind
    from defender.runtime import tools as runtime_tools

    deps = bind(
        actor_engine.ACTOR_DEF, lrd,
        scope=RunScope(scripts=(_ENV_RETRIEVE,), read_confine=_MALICIOUS_CONFINE),
    )
    assert not permission.decide_read(
        raw, run_dir=lrd, defender_dir=_DEFENDER_DIR, policy=deps.policy
    ).allow, "decide_read admits a gather_raw payload for the gray-box actor"
    with pytest.raises(ModelRetry):          # the real tool must refuse it, not return it
        runtime_tools._tool_read_file(deps, str(raw))


def test_actor_scope_requires_explicit_confine():
    # #512 fail-loud: read_confine is a required keyword-only field — building an actor scope
    # WITHOUT it is a construction-time TypeError, not a silent fall back to the full defender_dir
    # corpus (which would reopen the #510 gray-box hole). There is no unconfined actor.
    with pytest.raises(TypeError):
        _ActorScope((_ENV_RETRIEVE, _ACTOR_INDEX))
    # …and naming the confine builds the confined scope as before.
    scope = _ActorScope((_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=_MALICIOUS_CONFINE)
    assert scope.read_confine == _MALICIOUS_CONFINE


# --- the agent is read-only (no writers) + GLM@low effort plumbing --------------

def test_actor_agent_is_read_only_no_writers():
    logger = observe.RequestLogger(Path("/tmp/does-not-need-to-exist-actor-tools.jsonl"))
    try:
        agent = _pydantic_stage.build_stage_agent(
            ActorDeps, Path(__file__), "any-model", "low", logger, "actor",
            make_model=_fake_model(_replay([{"text": ""}])),
        )
    finally:
        logger.close()
    # read-only: the actor reads lessons + retrieval scripts, never writes
    assert list(agent._function_toolset.tools) == ["bash", "read_file"]


def test_build_actor_agent_applies_glm_low_effort(monkeypatch):
    # The GLM@low lever this migration ships: effort flows model → providers.build_for_effort →
    # Fireworks extra_body.reasoning_effort. build_for_effort constructs a REAL OpenAIChatModel
    # (needs a key at construction; a fake key keeps it hermetic — settings make no request).
    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    logger = observe.RequestLogger(Path("/tmp/does-not-need-to-exist-actor-effort.jsonl"))
    try:
        agent = _pydantic_stage.build_stage_agent(
            ActorDeps, Path(__file__), "glm-5.2", "low", logger, "actor",
        )
    finally:
        logger.close()
    assert agent.model_settings["extra_body"]["reasoning_effort"] == "low"


# --- InProcessSubagents.actor / .actor_benign run the in-process engine -------

def test_subagents_actor_runs_pydantic_engine(monkeypatch, tmp_path):
    captured = {}

    def _spy_actor(alert_path, actor_input_path, learning_run_dir, *, actor_fn=None):
        captured["actor_fn"] = actor_fn
        return _STORY

    def _spy_benign(alert_path, case_entities, alert_rule_key, learning_run_dir, *, actor_fn=None):
        captured["benign_fn"] = actor_fn
        return _STORY

    # render_actor_view_yaml / extract_case_entities read real run artifacts — stub them so the
    # routing decision is all that's exercised.
    monkeypatch.setattr(subagents.lead_repository, "render_actor_view_yaml", lambda _rd: "leads: []\n")  # lint-monkeypatch: ok — stub the actor-view projection
    monkeypatch.setattr(subagents, "extract_case_entities", lambda _p: "host:web")  # lint-monkeypatch: ok — stub the entity extraction
    monkeypatch.setattr(subagents, "invoke_actor", _spy_actor)  # lint-monkeypatch: ok — spy the actor_fn routing decision
    monkeypatch.setattr(subagents, "invoke_actor_benign", _spy_benign)  # lint-monkeypatch: ok — spy the actor_fn routing decision

    sub = subagents.InProcessSubagents()
    sub.actor(tmp_path, tmp_path)
    assert captured["actor_fn"] is _run_actor_pydantic
    sub.actor_benign(tmp_path, tmp_path, "5712")
    assert captured["benign_fn"] is _run_actor_pydantic
