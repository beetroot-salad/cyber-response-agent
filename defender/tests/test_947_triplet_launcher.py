"""#947 — the launcher: what it checks, what it starts, what it refuses (preflight, `Step.RUNS`,
`Step.VERIFY`; M7, M9).

The launcher is a composition, and under D1 everything it composes is a PROCESS: it writes the
manifest, has pre-flight calibrate each world's oracle (#1224, which retired #947's cluster
staging and replay review), starts N `run.py --resume` children together, waits, then verifies
each sibling's scrub and stamp before archiving. It never executes an investigation in its own
process.

Three readings the §7 seam settled and this file pins:

* **An episode pre-flight does not accept ends the EPISODE.** Nothing runs, the record
  archives, and no sibling process starts.
* **A family that fails verification withholds comparability**: per-world archiving with only
  the family stamp and the comparability claim withheld, and the reason returned.
* **The family holds the resolved MODEL constant as well as the commit.** The role preflight
  resolves per process, so three siblings launched into a changed environment can be a
  comparison across two models with a perfectly agreeing stamp.

RED against b8a63e66: none of the seams below exists, the launcher runs siblings in-process via
`asyncio.gather` (C1), and it hoists ONE provenance capture above the whole family (C22).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from defender._episode_handle import Episode
from defender._io import bind
from defender.tests import _triplet_947 as T
from defender.tests.live_oracle_1224 import _spec1224 as S


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots point inside `tmp_path` for every scenario in this file.

    Without it a scenario takes its runs base from `tmp_path` and its episode dir from the
    production resolver, so `episode_dir_for` answers about the developer's and CI's REAL roots:
    the assertions compare two different worlds and hold for every implementation, the archived
    worlds are written outside `tmp_path`, and the three scenarios that share one episode id
    become order-dependent on a directory an earlier test left behind.
    """
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)


def _cli():
    return T.mod("learning.branch.cli")


def _verify_family(ep_dir, run_dirs, **kw):
    """`cli.verify_family` over an `Episode` opened on `ep_dir`: it takes the handle, not the
    episode dir (#1133 rev 2)."""
    with Episode.open(ep_dir) as episode:
        return _cli().verify_family(episode, run_dirs, **kw)


def _tenant_paths():
    """#1078: the tenant `T.runs_base` (or `d9_tenant`) already created."""
    return T.current_tenant()


#: The one answer every captured call of `_launch`'s source run carries, so a single scripted
#: oracle submission (`_PASSING`) serves every call unchanged and every fact world calibrates.
_BASE = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
                   "ts": "2026-07-28T15:00:00Z"}]}


def _calls() -> list:
    """The source run's captured calls: two pre-branch reads over `_spec1224`'s fixture tenant."""
    return [S.Call("idp", "query", S.query_params("user:alice"), _BASE),
            S.Call("edr", "query", S.query_params("host:db-1"), _BASE)]


def _launch(tmp_path, *, spawn=None, argv_extra=(), oracle=None, verifier=None, **seams):
    """Drive one episode through the real launcher over `_spec1224`'s fixture tenant (#1224).

    Pre-flight replays the source run's captured calls (`_calls`) through each fact world's
    oracle: by default an oracle serving every call unchanged and a verifier passing it, so the
    family is accepted and its siblings start. Every other seam defaults to a recording double
    (`S.launch`): the role preflight is neutralised for every scenario not about it, and
    `live_tree` is #976's live-tree capture matching the fixture source's stamp — otherwise the
    suite's own HEAD is what the preflight compares.

    Returns `(rc, spawn, episode_dir, message)`; `message` is a refusal's `sys.exit` text.
    """
    run = S.launch(
        tmp_path, S.estate(tmp_path), calls=_calls(), spawn=spawn, argv_extra=argv_extra,
        oracle=oracle if oracle is not None else S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM)),
        verifier=verifier if verifier is not None else S.passing_verifier(), **seams)
    return run.rc, run.spawn, run.ep, run.message


# ---------------------------------------------------------------------------------------
# preflight — what is checked before anything is spent
# ---------------------------------------------------------------------------------------


def test_947_launcher_returns_episode_dir_and_status(tmp_path):
    """The launcher returns a zero status with a fully archived episode dir, and a non-zero one
    otherwise — leaving the manifest and pre-flight's outcome record on disk either way, so an
    operator reading the exit status and the directory sees the same answer."""
    rc, _spawn, ep, _message = _launch(tmp_path)
    assert rc == 0
    assert (ep / "family.yaml").is_file()
    assert (ep / "outcome.yaml").is_file()
    assert (ep / "worlds").is_dir()


def test_947_un_nameable_episode_token_is_refused_before_the_questioner_runs(tmp_path):
    """An episode whose token cannot be rendered nameable is refused before the questioner is
    called at all: the refusal costs no model call and no primed capture."""
    base, src = T.runs_base(tmp_path, source_run_id="FRESH CASE")
    agent = T.FakeAgent()
    with pytest.raises(SystemExit):
        _cli().main([str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
                    spawn=T.FakeSpawn(), questioner=agent,
                    preflight=S.no_preflight, live_tree=T.source_capture())
    assert agent.calls == 0


def test_947_episode_token_rendering_is_injective_and_nameable(tmp_path):
    """The episode token's rendering is injective and nameable: two distinct episode ids never
    render to one token, and every token it produces composes a world token that names one
    world-ledger file — a plain character replacement is not enough, because the run-id grammar
    admits both delimiters. (#1224 retired the `wv-` view names the token once also had to
    admit; the world ledger's filename is what still carries it.)"""
    fam = T.mod("runtime.branch._family")
    ids = ["a-b_c-n1", "a_b-c-n1", "a-b-c_n1", "A-B-n1", "20260728T161845Z-fresh-case-n59"]
    tokens = [fam.episode_token_for(i) for i in ids]
    assert len(set(tokens)) == len(set(ids))
    for token in tokens:
        world = fam.world_token_for(token, "b")
        assert world == f"{token}.b"
        assert re.fullmatch(r"[a-z0-9][a-z0-9._]*", world), world


def test_947_step_one_preflight_checks_every_precondition_before_spending(tmp_path):
    """Preflight checks every precondition in ONE block before anything is spent, and EACH of them
    refuses before the questioner is called: the branch point out of range for the derived fence
    count, and an absent source alert. (The alert's LINK SCREEN is the same block's third check
    and has its own demand — a screen names which reader applies it, which an ordering
    assertion cannot. #1224 retired the cluster-reachability and sweep arms with staging.)"""
    base, src = T.runs_base(tmp_path)

    def refuses(argv_extra, *, prepare=lambda: None):
        agent = T.FakeAgent()
        prepare()
        with pytest.raises(SystemExit):
            # The role-model preflight is neutralised: each arm has to refuse for the reason it
            # names, and an uncredentialed host would otherwise satisfy every one of them with
            # the preflight's own refusal before the check under test was ever reached.
            _cli().main([str(src), *argv_extra, "--continuation-prompt", "go"],
                        spawn=T.FakeSpawn(), questioner=agent,
                        preflight=S.no_preflight, live_tree=T.source_capture())
        assert agent.calls == 0, "the questioner was paid for before the preflight refused"

    for out_of_range in ("-1", str(10 ** 9)):
        refuses([out_of_range])
    # the alert is PRESENT — the launcher reads it for the questioner's own prompt
    refuses([str(T.BRANCH_MESSAGE_ID)], prepare=lambda: (src / "alert.json").unlink())


def test_947_the_launcher_screens_the_source_alert_before_the_questioner_reads_it(tmp_path):
    """The launcher screens the source run's `alert.json` before it reaches the questioner's
    prompt: the source run dir is a prior box's rw bind, the only screen standing on that read
    today lives inside the frame D1 deletes, and a link planted at that name is refused rather
    than followed into a model-facing prompt — the third reader of this surface, beside the
    resume seed and the questioner's own frontier read."""
    base, src = T.runs_base(tmp_path)
    secret = tmp_path / "root-private-key"
    secret.write_text("ROOT-PRIVATE-KEY", encoding="utf-8")
    (src / "alert.json").unlink()
    (src / "alert.json").symlink_to(secret)
    agent = T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c"))
    with pytest.raises(T.refusals()) as refusal:
        _cli().main([str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
                    spawn=T.FakeSpawn(), questioner=agent,
                    preflight=S.no_preflight, live_tree=T.source_capture())
    assert "alert" in str(refusal.value)
    assert agent.prompts == [], "the planted link reached the questioner's prompt"
    assert "ROOT-PRIVATE-KEY" not in str(refusal.value)


def test_947_the_step_one_command_line_requires_a_continuation_prompt(tmp_path):
    """The step-1 command line requires the operator's continuation prompt: it is part of the
    measured instrument and the design names no other author for it, so a launch without one
    refuses at the parser rather than inventing a string."""
    import contextlib
    import io

    base, src = T.runs_base(tmp_path)
    err = io.StringIO()
    with contextlib.redirect_stderr(err), pytest.raises(SystemExit) as bad:
        _cli().parse_branch_args([str(src), str(T.BRANCH_MESSAGE_ID)])
    assert bad.value.code == 2
    assert "--continuation-prompt" in err.getvalue()
    assert "--episode-id" not in err.getvalue(), (
        "the episode id is still an operator argument; the design derives it")


def test_947_all_siblings_in_one_family_share_one_continuation_prompt(tmp_path):
    """Every sibling in one family is launched with the SAME continuation prompt: the manifest
    carries one string and each child's command line names that one, so a family cannot become
    a comparison across two different instructions."""
    import yaml

    rc, spawn, ep, _message = _launch(tmp_path)
    manifest = yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    assert manifest["continuation_prompt"] == "go"
    assert len(spawn.launches) >= 2
    seen = {la["argv"][la["argv"].index("--resume") + 1] for la in spawn.launches}
    assert len(seen) == 1, "the siblings were launched from different manifests"


# ---------------------------------------------------------------------------------------
# `Step.PREFLIGHT` / `Step.RUNS` — an unaccepted episode, and starting the family
# ---------------------------------------------------------------------------------------


def test_947_accepted_siblings_are_started_together_as_processes(tmp_path):
    """The accepted siblings are started TOGETHER as child processes: each launch is a `run.py
    --resume` command line naming its own world, the launches overlap in time rather than
    running to completion one after another, and each child runs the sibling entry point.

    The fake BLOCKS, and it has to: a child that answers in microseconds of pure Python is never
    preempted mid-call, so N launchers released together would still enter and leave it one at a
    time and `overlap` would read False for an implementation that did start them together. A
    real `run.py` child blocks for the length of an investigation; `Fault(delay=…)` is the
    fake's stand-in for that."""
    slow = T.FakeSpawn(fault=T.Fault(delay=0.25))
    rc, spawn, ep, _message = _launch(tmp_path, spawn=slow)
    assert sorted(spawn.worlds) == ["a", "b", "c"]
    for launch in spawn.launches:
        assert "--resume" in launch["argv"]
        assert any(arg.endswith("run.py") for arg in launch["argv"])
    assert spawn.overlap, "the siblings ran serially; nothing was started together"


def test_947_the_launcher_globs_and_passes_its_own_questioner_lessons(tmp_path):
    """#1007 M8/O7, wired end to end through the REAL launcher, not `author_family` called
    directly: a matching lesson on disk in the questioner corpus reaches call 1's prompt.

    Every M8 test in `test_1007_questioner.py` drives `questioner.author_family` directly,
    which is where the selection/framing/cap logic lives and is correctly tested — but
    `learning/branch/cli.py`'s own `_author` step is what has to GLOB the corpus and hand the
    raw candidate list in, and nothing exercised that wiring: the launcher never passed
    `lessons=` at all until this fix, so O7 was a no-op in production despite every unit test
    passing.

    Observably true: with a lesson file in a `lessons_dir` the launcher is handed (the same
    injection-seam discipline `preflight`/`spawn` already use — never `monkeypatch.setattr` on
    the production corpus path), whose `systems` names one of this episode's served systems
    (#1224: `systems` replaced the lesson's `pattern` / `holding_system`), the lesson's body
    reaches the FIRST prompt the questioner's fake agent records (call 1, the family-authoring
    call).

    What failure looks like: the launcher resolves its own production corpus path but never
    globs it, or globs it and drops the result on the floor instead of passing it through
    `_author` into `author_family`.
    """
    import yaml

    lessons_dir = tmp_path / "lessons-questioner"
    lessons_dir.mkdir(parents=True)
    body = "QUESTIONER-LAUNCHER-LESSON-BODY"
    meta = {"name": "l1", "systems": ["idp"]}
    (lessons_dir / "l1.md").write_text(
        "---\n" + yaml.safe_dump(meta, sort_keys=False) + "---\n" + body + "\n",
        encoding="utf-8")

    questioner = S.questioner_for()
    rc, _spawn, _ep, _message = _launch(tmp_path, questioner=questioner, lessons_dir=lessons_dir)

    assert rc == 0, "the episode did not complete cleanly"
    assert questioner.prompts, "the questioner was never called"
    assert body in questioner.prompts[0], (
        "the lesson never reached call 1's prompt — the launcher's own glob/pass-through is "
        "not wired, even though author_family's own selection logic is correct")


def test_947_launcher_has_no_import_or_await_of_run_investigation(tmp_path):
    """The launcher has no path to the in-process investigation at all: its module names neither
    the driver's entry point nor an await of it, and every sibling it drives is reached through
    the process seam instead."""
    src = (T.DEFENDER / "learning" / "branch" / "cli.py").read_text(encoding="utf-8")
    assert "run_investigation" not in src
    assert "asyncio.gather" not in src
    rc, spawn, ep, _message = _launch(tmp_path)
    assert spawn.launches, "the launcher started no child process"


def test_947_every_injected_seam_has_a_production_value(tmp_path):
    """Every seam the launcher injects has a value it resolves for itself, so the shipped entry
    point can run an episode with nothing hand-supplied (O1).

    THE SEAM STAYS A SEAM — every parameter below still defaults to `None`, which is what lets
    every scenario in this file drive the launcher without a provider — and the launcher answers
    for them at its own boundary, the way it already does for the role preflight.
    Injected-with-no-production-value is not a seam but a hole: it reached
    `author_family(invoke=None)` as a bare `TypeError` with an episode id already burned, and
    refusing instead of crashing left the entry point still unable to launch anything.

    The MODEL seams are asserted structurally and by construction rather than by driving them: a
    real call costs money and needs a provider, and what can go wrong without one is what is
    checked here — that the shipped role prompt exists and the agent builds from it through the
    same builder every other stage uses, and that pre-flight's oracle and verifier resolve from
    their knobs when none is handed in. The ROSTER seam (#1224: pre-flight's grant-decided
    reader, which replaced the review's adapter layer) is read for real, because reading it is
    the check: it is the checkout's adapters directory, parsed."""
    import inspect

    cli = _cli()
    seams = T.mod("learning.branch.seams")
    for name in ("questioner", "oracle", "verifier", "roster"):
        assert inspect.signature(cli.main).parameters[name].default is None, (
            f"{name} is no longer an injectable seam, so every scenario in this file would "
            "need a provider")
    src = (T.DEFENDER / "learning" / "branch" / "cli.py").read_text(encoding="utf-8")
    for builder in ("seams.model_seam", "read_roster(adapters_under(_DEFENDER_DIR))"):
        assert builder in src, f"the launcher never reaches {builder}"
    registry = (T.DEFENDER / "learning" / "branch" / "estate" / "registry.py").read_text(
        encoding="utf-8")
    assert "_LazyModel(" in registry, "pre-flight's model seams have no production value"
    for knob in ("settings.model, settings.effort", "settings.check_model, settings.check_effort"):
        assert knob in registry, f"pre-flight's model seam is not built from {knob}"

    from defender._paths import adapters_under
    from defender.runtime.verbs import read_roster

    ep = T.episode(tmp_path)
    assert read_roster(adapters_under(T.DEFENDER)).accepted, (
        "pre-flight has no production roster to read through")
    assert callable(seams.model_seam(ep)), "the questioner has no production model call"

    # The agent the model seam drives, built the way `run_stage` builds it — the structural half
    # (a role with a registered definition, a readable standing prompt, a deps class the builder
    # accepts) with no provider call made.
    #
    # THE MODEL BUILDER IS INJECTED, and it is not a convenience: `build_agent_core`'s default
    # is `providers.build_for_effort`, which SOURCES A BILLABLE KEY. Left to the ambient
    # environment this test asserts whether the HOST is credentialed — green on a developer's
    # machine, red on CI — which is the same trap `S.no_preflight` exists for one seam over.
    # The seam under test is the wiring, and the provider is what the family-level role
    # preflight is for.
    from pydantic_ai.models.function import FunctionModel

    from defender.learning._pydantic_stage import build_stage_agent
    from defender.learning.branch.questioner import (
        QuestionerDeps,
        questioner_effort,
        questioner_model,
    )
    from defender.learning.core.config import StageWiring
    from defender.runtime import observe
    from defender.runtime.providers import BuiltModel

    role_prompt = T.DEFENDER / "learning" / "branch" / "questioner" / "role.md"
    assert role_prompt.is_file(), "the questioner has no standing system prompt to be built with"
    logger = observe.RequestLogger(tmp_path / "seam_trace.jsonl")
    try:
        assert build_stage_agent(
            QuestionerDeps,
            StageWiring(prompt_path=role_prompt, model=questioner_model(),
                        effort=questioner_effort(), trace_name="t.jsonl", label="questioner"),
            logger,
            make_model=lambda name, effort: BuiltModel(
                FunctionModel(lambda messages, info: None), None),
        ) is not None
    finally:
        logger.close()


def _bare_family() -> dict:
    """A family no world of which carries a fact: pre-flight has nothing to calibrate."""
    return S.family_v2(worlds=[S.control_world("a"), S.world_v2("b", facts=[]),
                               S.world_v2("c", role="C", facts=[])])


@pytest.mark.parametrize("outcome", ["refused", "unusable"])
def test_947_an_unaccepted_episode_starts_no_sibling_and_its_record_archives(
        tmp_path, monkeypatch, outcome):
    """An episode pre-flight does not accept ends the EPISODE: no sibling process starts, the
    status is non-zero, and the manifest and pre-flight's outcome record are archived on disk —
    an examined no, recorded with its reason. Both non-accepting outcomes are driven (#1224,
    which retired the replay review's rejection): `refused` (no world carries a fact, so there
    is nothing to calibrate) and `unusable` (two worlds failed calibration — the oracle never
    submits an answer)."""
    import yaml

    monkeypatch.setenv("ORACLE_RETRY_CAP", "1")
    seams = ({"questioner": S.questioner_for(_bare_family())} if outcome == "refused" else
             {"oracle": S.oracle(then=S.text_only("no served answer fits this world"))})
    rc, spawn, ep, _message = _launch(tmp_path, **seams)
    assert rc != 0
    assert spawn.launches == [], "a sibling started"
    record = yaml.safe_load((ep / "outcome.yaml").read_text(encoding="utf-8"))
    assert record["outcome"] == outcome
    assert record["reason"]
    assert (ep / "family.yaml").read_text(encoding="utf-8").strip()


def test_947_any_failure_in_steps_two_to_four_aborts_the_episode(tmp_path):
    """ONE rule, not a taxonomy: a step that fails before the first sibling starts aborts the
    episode — the launch refuses and no sibling process starts. Driven through a questioner call
    that fails (`Step.QUESTIONER`). (#1224 retired the staging and review arms with their steps;
    a world's own failure in `Step.PREFLIGHT` is a recorded outcome, not an abort.)"""
    spawn = T.FakeSpawn()
    rc, spawn, _ep, message = _launch(
        tmp_path, spawn=spawn,
        questioner=T.FakeAgent(S.family_v2(), fault=T.Fault(raise_after=1)))
    assert rc != 0
    assert message, "the abort was not reported as a refusal"
    assert spawn.launches == [], "a sibling started after the abort"


# ---------------------------------------------------------------------------------------
# `Step.VERIFY` — verification, the family stamp and withheld comparability
# ---------------------------------------------------------------------------------------


def test_947_launcher_verifies_each_siblings_scrub_verdict(tmp_path):
    """The launcher verifies each sibling's scrub verdict after the processes exit, reading the
    verdict at its sidecar path beside the run dir rather than inside the tree it judges."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    for world in T.WORLDS:
        T.sibling_run_dir(base, world)
    report = _verify_family(ep, [base / f"{T.EPISODE_ID}-{w}" for w in T.WORLDS],
                            source=T.provenance_record())
    assert report["scrub_verified"] == list(T.WORLDS)


def test_947_a_sibling_without_a_ran_true_scrub_marks_the_episode_incomplete(tmp_path):
    """A sibling whose scrub verdict is absent, or present but not recording a completed walk,
    withholds the family's comparability with the reason — never archived as comparable."""
    base, src = T.runs_base(tmp_path)
    for scrub_ran, world in ((None, "b"), (False, "c")):
        ep = T.episode(tmp_path)
        dirs = [T.sibling_run_dir(base, w, scrub_ran=True if w != world else scrub_ran)
                for w in T.WORLDS]
        report = _verify_family(ep, dirs, source=T.provenance_record())
        assert report["comparable"] is False
        assert world in report["reason"]


def test_a_finished_sibling_without_a_scrub_verdict_gets_its_own_not_archived_record(tmp_path):
    """A sibling that exited cleanly but has no scrub verdict is never archived, so the judge
    cannot see it — and it carries its own `not archived` record, the only way the judge
    counts a world it cannot see toward O5. A verified sibling beside it gets none."""
    outcome = T.mod("learning.branch.outcome")
    base, _src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, scrub_ran=None if w == "b" else True)
            for w in T.WORLDS]

    report = _verify_family(ep, dirs, source=T.provenance_record())

    assert "b" not in report["archived"]
    with bind(Path(ep)) as bound:
        failed = outcome.failed_worlds(bound, {})
    assert sorted(failed) == ["b"]
    assert failed["b"]["reason"] == outcome.NOT_ARCHIVED


def test_947_agreeing_sibling_stamps_write_the_family_stamp(tmp_path):
    """Sibling stamps that agree write the family stamp: one record for the family, carrying
    the agreed provenance every sibling reported.

    The source is anchored at `cafe1` too (#976 M3): siblings agreeing among themselves at a
    commit the source did not run is exactly the family the anchor refuses, so the positive
    here is agreement with each other AND with the source."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, commit="cafe1") for w in T.WORLDS]
    _verify_family(ep, dirs, source=T.provenance_record(commit="cafe1"))
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["agreed"]["commit"] == "cafe1"


def test_947_family_stamp_carries_agreed_and_override_as_disjoint_roles(tmp_path):
    """The family stamp carries its three roles disjointly: the agreed provenance record, the
    SOURCE's own record it was anchored to (#976 M4/O5), and whether the dirty override was
    given — none sourced from another, so an override cannot be read out of the provenance
    half, and the anchor cannot be mistaken for the siblings' agreement or vice versa."""
    ep = T.episode(tmp_path)
    # The siblings' OWN runs base (`<episode>/runs`, §7 FORK-13), with no tenant record, so
    # the stamp carries exactly its three roles (a seeded base adds `base_world_id`, #1106).
    _verify_family(ep, [T.sibling_run_dir(ep / "runs", w) for w in T.WORLDS],
                   source=T.provenance_record())
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    # #1204: `waived` names the fault kinds the override waived — none, for a clean family.
    assert set(stamp) == {"agreed", "allow_dirty", "source", "waived"}
    assert stamp["waived"] == []
    assert "allow_dirty" not in stamp["agreed"]
    assert "allow_dirty" not in stamp["source"]
    assert stamp["allow_dirty"] is False
    assert stamp["source"]["commit"] == "deadbee"


def test_947_disagreeing_sibling_stamps_mark_the_episode_incomplete_with_a_reason(tmp_path):
    """Sibling stamps recording different commits withhold the family's comparability with the
    reason, and no family stamp is written: the tree moved between the first and last sibling, which is
    exactly the catch per-process stamps exist for."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, commit=("cafe1" if w == "a" else "cafe2"))
            for w in T.WORLDS]
    report = _verify_family(ep, dirs, source=T.provenance_record(commit="cafe1"))
    assert report["comparable"] is False
    assert "commit" in report["reason"]
    assert not (ep / "provenance.json").exists()


def test_947_an_absent_or_unreadable_sibling_stamp_marks_the_episode_incomplete(tmp_path):
    """A sibling stamp that is absent, or present but unreadable, is not an agreeing stamp: the
    family's comparability is withheld with the reason exactly as for a disagreeing one, and no
    family stamp is written."""
    base, src = T.runs_base(tmp_path)
    for mutate in ("absent", "truncated"):
        ep = T.episode(tmp_path)
        dirs = [T.sibling_run_dir(base, w, stamp=(w != "b")) for w in T.WORLDS]
        if mutate == "truncated":
            (dirs[1] / "provenance.json").write_text('{"commit": "cafe', encoding="utf-8")
        report = _verify_family(ep, dirs, source=T.provenance_record())
        assert report["comparable"] is False
        assert not (ep / "provenance.json").exists()


def test_947_the_family_stamp_carries_the_resolved_model_per_sibling(tmp_path):
    """The family stamp compares the resolved MODEL alongside the commit and the scope: each
    sibling's stamp records the model its own process resolved, and the family stamp carries the
    agreed value."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    _verify_family(ep, [T.sibling_run_dir(base, w, model="m-1") for w in T.WORLDS],
                   source=T.provenance_record())
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["agreed"]["model"] == "m-1"


def test_947_a_cross_model_family_refuses_rather_than_agreeing(tmp_path):
    """A family whose siblings resolved DIFFERENT models refuses rather than passing with an
    otherwise agreeing stamp: the model is held constant the way the commit is, so a comparison
    across two models is never archived as comparable."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, model=("m-1" if w == "a" else "m-2")) for w in T.WORLDS]
    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert report["comparable"] is False
    assert "model" in report["reason"]
    assert not (ep / "provenance.json").exists()


def test_947_a_dirty_sibling_tree_is_refused_without_the_override(tmp_path):
    """EVERY non-clean stamp outcome refuses absent the override, and there are three a capture
    can produce: a dirty tree, a git that could not be asked at all (no sha, a reason), and a
    git that named the sha but could not answer for the tree. An unknown is not a clean bill of
    health.

    The override waives DIRT AND ONLY DIRT (#976 O4/M3b). The two shapes that still carry a
    commit — a dirty tree, and a sha whose tree git could not answer for — are compared on the
    fields they carry and complete under `--allow-dirty`. The SILENT shape (no sha at all) is
    never waived: it has no commit to compare against its siblings or the source, and before
    #976 the override dropped it from the agreement and `_agreed_record` published another
    arm's commit as the family's (C11). Observed failing by: an accepted episode under the
    override in which sibling `b` carries no commit."""
    base, src = T.runs_base(tmp_path)
    waivable = {
        "dirty": {"dirty": True},
        "git-failed": {"dirty": None, "unavailable": T.GIT_STATUS_FAILED},
    }
    for name, stamp in waivable.items():
        ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-{name}")
        dirs = [T.sibling_run_dir(base / name, w, **(stamp if w == "b" else {}))
                for w in T.WORLDS]
        report = _verify_family(ep, dirs, source=T.provenance_record())
        assert report["comparable"] is False, name
        assert "b" in report["reason"], (name, report["reason"])
        assert not (ep / "provenance.json").exists(), name
        ok = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-{name}-ok")
        waived = _verify_family(ok, dirs, source=T.provenance_record(), allow_dirty=True)
        assert waived["comparable"] is True, name
        assert (ok / "provenance.json").is_file(), name
    silent = {"commit": None, "dirty": None, "unavailable": T.GIT_UNAVAILABLE}
    dirs = [T.sibling_run_dir(base / "silent", w, **(silent if w == "b" else {}))
            for w in T.WORLDS]
    for allow_dirty in (False, True):
        ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-silent-{allow_dirty}")
        report = _verify_family(ep, dirs, source=T.provenance_record(),
                                allow_dirty=allow_dirty)
        assert report["comparable"] is False, f"allow_dirty={allow_dirty}"
        assert "b" in report["reason"], (allow_dirty, report["reason"])
        assert not (ep / "provenance.json").exists(), (
            f"allow_dirty={allow_dirty}: a family with a silent arm was stamped as comparable")


def test_947_the_dirty_override_is_named_in_the_family_stamp(tmp_path):
    """When the dirty override is given it is NAMED in the family stamp: a reader of the archive
    can tell an agreed clean family from one that was waved through."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, dirty=(w == "b")) for w in T.WORLDS]
    _verify_family(ep, dirs, source=T.provenance_record(), allow_dirty=True)
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["allow_dirty"] is True


def test_947_launcher_no_longer_hoists_one_capture_above_the_family(tmp_path):
    """The launcher does not hoist its own capture of the tree ABOVE the family as the family's
    provenance. Since #976 it does take one (M2: the live-tree check at preflight, through the
    injected `live_tree=` seam), but that record describes the launcher's moment and is not the
    authority (#976 non-obligation): the family stamp's `agreed` record is a conclusion about
    the N per-process sibling stamps, and the workflow a hoisted record once served — knowing
    what the family was made against — completes from those. (The name is kept: the committed
    spec graph's `discharged_by` points at it, and the claim it names still holds.)

    Driven end to end so the capture the launcher DOES take (M2, for the live-tree check) is
    on the record: under `--allow-dirty` the live tree is dirty with one named path, the
    siblings each ran clean at the same commit, and the accepted family stamp's `agreed`
    half carries the siblings' clean answer and their model — not the launcher-moment's dirt,
    not its `model=None`. Observed failing by: `agreed.dirty` True, `agreed.dirty_paths`
    naming the launcher's path, or `agreed.model` None."""
    import yaml

    from defender.tests import _judge_921 as J

    ep = _cli().episode_dir_for(T.EPISODE_ID, tenant=_tenant_paths())
    launcher_moment = T.source_capture(dirty=True, model=None)
    # The judge seam is `_launch`'s scripted default: an ACCEPTED family is graded at the tail
    # of the launch, and its production value is a real model call.
    rc, spawn, ep, _message = _launch(tmp_path, spawn=J.FakeSibling(ep),
                                      live_tree=launcher_moment, argv_extra=("--allow-dirty",))
    assert rc == 0
    assert launcher_moment.calls == 1, "the live tree was captured other than once per launch"
    assert yaml.safe_load((ep / "outcome.yaml").read_text(encoding="utf-8"))["outcome"] == \
        "accepted"
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["agreed"]["dirty"] is False
    assert stamp["agreed"]["dirty_paths"] == []
    assert stamp["agreed"]["dirty_path_count"] == 0
    assert stamp["agreed"]["model"] == "m-1"
    assert stamp["agreed"]["commit"] == "deadbee"
    assert stamp["allow_dirty"] is True


# ---------------------------------------------------------------------------------------
# §7 FORK-1 — a family that fails verification withholds comparability
# ---------------------------------------------------------------------------------------


def test_947_an_incomplete_family_archives_per_world_and_withholds_comparability(tmp_path):
    """A family that fails verification archives each individually clean sibling and withholds
    only the family stamp and the comparability claim: the clean worlds are on disk, the stamp
    is not, and the verification report says why. (#1224 retired `incomplete` as an outcome
    word: the outcome record is pre-flight's, and verification never touches it.)"""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, scrub_ran=(w != "c")) for w in T.WORLDS]
    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert sorted(p.name for p in (ep / "worlds").iterdir()) == ["a", "b"]
    assert not (ep / "provenance.json").exists()
    assert report["comparable"] is False
    assert "c" in report["reason"]
    assert not (ep / "outcome.yaml").exists(), "verification wrote pre-flight's outcome record"


# ---------------------------------------------------------------------------------------
# §7 FORK-2 — relaunching after a death
# ---------------------------------------------------------------------------------------


def test_947_two_launchers_on_one_episode_cannot_both_prime_it(tmp_path):
    """The episode directory's creation is an exclusive create, not a check-then-act: two
    launchers racing on one source and branch point each claim their OWN episode directory
    (N17: a launch never reuses one — the loser moves on to `<id>-r2`), never two captures
    stacked into a single base recording that both callers read as clean."""
    import threading

    base, src = T.runs_base(tmp_path)
    cli = _cli()
    results: list = []
    barrier = threading.Barrier(2)

    def attempt():
        barrier.wait()
        try:
            with cli.prepare_episode(T.EPISODE_ID, src, tenant=_tenant_paths()) as episode:
                results.append(episode)
        except Exception as e:  # noqa: BLE001 — the refusal is the observation
            results.append(e)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not any(isinstance(r, Exception) for r in results), results
    first = cli.episode_dir_for(T.EPISODE_ID, tenant=_tenant_paths())
    assert sorted(r.dir for r in results) == [first, first.parent / f"{T.EPISODE_ID}-r2"]
    for episode in results:
        lines = (episode.dir / "served" / "base.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == len(set(lines)) == 1, (episode.dir, lines)


# ---------------------------------------------------------------------------------------
# the one shared mutable resource D1 newly contends
# ---------------------------------------------------------------------------------------


def test_947_concurrent_sibling_forks_into_one_source_store_all_land(tmp_path):
    """Every concurrent sibling fork into the ONE source session store lands: N forks issued
    together each produce their own session under the source's database, and none is lost to
    the contention D1 newly manufactures."""
    store_mod = T.mod("runtime.session_store")
    import threading

    from defender.tests import _session_store_705 as S

    base, src = T.runs_base(tmp_path)
    handle = store_mod.open_store(case_id="case-947", runs_base=base)
    sid = handle.new_session(agent_id="main")
    # A REAL BRANCH POINT. `fork` walks the prefix at `at_message_id` and refuses one holding an
    # unresolved call, so a fork needs a session with a complete pair in it and the id of that
    # pair's last row — which is exactly the boundary a sibling resumes from.
    at = handle.append(sid, [S.user_request("investigate the alert"), *S.complete_pair()],
                       agent_id="main")[-1]
    made: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(3)

    def fork():
        barrier.wait()
        h = store_mod.open_store(case_id="case-947", runs_base=base)
        child = h.fork(sid, at_message_id=at)
        with lock:
            made.append(child)

    threads = [threading.Thread(target=fork) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(made) == 3
    assert len(set(made)) == 3


def test_947_concurrent_siblings_take_distinct_container_names(tmp_path):
    """Concurrent siblings take distinct container names: each name is derived from that
    sibling's own run id, so no two children of one family can contend for one container."""
    docker = T.mod("runtime.box._docker")
    names = {docker.container_name(f"{T.EPISODE_ID}-{w}") for w in T.WORLDS}
    assert len(names) == len(T.WORLDS)
    assert all(name.startswith("defender-run-") for name in names)

