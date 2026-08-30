"""#947 — the launcher: what it checks, what it starts, what it refuses (steps 1, 5, 6; M7, M9).

The launcher is a composition, and under D1 everything it composes is a PROCESS: it writes the
manifest, stages the corpus, reviews, starts N `run.py --resume` children together, waits, then
verifies each sibling's scrub and stamp before archiving. It never executes an investigation in
its own process.

Three readings the §7 seam settled and this file pins:

* **Any rejected world ends the EPISODE.** Nothing runs, the record archives, and no sibling
  process starts — recorded as an examined no rather than as an unexamined mechanism sentence.
* **`incomplete` is a modelled outcome**, not the absence of a file: an outcome field with a
  reason, a fourth teardown trigger, per-world archiving with only the family stamp and the
  comparability claim withheld.
* **The family holds the resolved MODEL constant as well as the commit.** The role preflight
  resolves per process, so three siblings launched into a changed environment can be a
  comparison across two models with a perfectly agreeing stamp.

RED against b8a63e66: none of the seams below exists, the launcher runs siblings in-process via
`asyncio.gather` (C1), and it hoists ONE provenance capture above the whole family (C22).
"""
from __future__ import annotations

import contextlib
import json

import pytest

from defender.tests import _triplet_947 as T


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


def _cli():
    return T.mod("learning.branch.cli")


def _launch(tmp_path, *, spawn=None, door=None, argv_extra=(), capture=(), **seams):
    """Drive one episode through the real launcher.

    `capture` lands rows in the SOURCE run's queries table before the launch, which is the only
    way to give an episode a primed base: the launcher primes from the source, so a scenario
    that needs the review to have something to replay has to put it there.
    """
    base, src = T.runs_base(tmp_path)
    for row in capture:
        T.capture_call(src, **row)
    if spawn is None:
        spawn = T.FakeSpawn()
    if door is None:
        door = T.FakeDoor()
    seams.setdefault("questioner",
                     T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c")))
    seams.setdefault("adapters", T.FakeAdapters())
    seams.setdefault("invoke", T.FakeAgent(*["same"] * 24))
    # The role-model preflight is injected for every scenario that is not about it: left to the
    # ambient environment it decides these tests on whether the host holds a billable key, and
    # it SATISFIES the ones that assert a refusal without their reaching the check they name.
    # `test_947_role_preflight_runs_once_for_the_family_and_again_in_each_sibling` injects its
    # own recording seam and is what discharges the demand.
    seams.setdefault("preflight", T.no_preflight)
    rc = _cli().main([str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go",
                      *argv_extra],
                     spawn=spawn, door=door, **seams)
    return rc, spawn, _cli().episode_dir_for(T.EPISODE_ID)


# ---------------------------------------------------------------------------------------
# step 1 — what is checked before anything is spent
# ---------------------------------------------------------------------------------------


def test_947_launcher_returns_episode_dir_and_status(tmp_path):
    """The launcher returns a zero status with a fully archived episode dir, and a non-zero one
    otherwise — leaving the manifest, the staging record and the review on disk either way, so
    an operator reading the exit status and the directory sees the same answer."""
    rc, _spawn, ep = _launch(tmp_path)
    assert rc == 0
    assert (ep / "family.yaml").is_file()
    assert (ep / "review.yaml").is_file()
    assert (ep / "worlds").is_dir()


def test_947_un_nameable_episode_token_is_refused_before_the_questioner_runs(tmp_path):
    """An episode whose token cannot be rendered nameable is refused before the questioner is
    called at all: the refusal costs no model call, no staged name and no primed capture."""
    base, src = T.runs_base(tmp_path, source_run_id="FRESH CASE")
    agent = T.FakeAgent()
    with pytest.raises(SystemExit):
        _cli().main([str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
                    spawn=T.FakeSpawn(), door=T.FakeDoor(), questioner=agent,
                    preflight=T.no_preflight)
    assert agent.calls == 0


def test_947_episode_token_rendering_is_injective_and_nameable(tmp_path):
    """The episode token's rendering is injective and nameable: two distinct episode ids never
    render to one token, and every token it produces is one the naming rules admit — a plain
    character replacement is not enough, because the run-id grammar admits both delimiters."""
    fam = T.mod("runtime.branch._family")
    confinement = T.mod("scripts.adapters.confinement")
    ids = ["a-b_c-n1", "a_b-c-n1", "a-b-c_n1", "A-B-n1", "20260728T161845Z-fresh-case-n59"]
    tokens = [fam.episode_token_for(i) for i in ids]
    assert len(set(tokens)) == len(set(ids))
    for token in tokens:
        assert confinement._nameable_world(f"{token}.b")


def test_947_sweep_runs_before_the_questioner_is_called(tmp_path):
    """The launcher's first act is the sweep: leftover names from an earlier death are removed
    before the questioner is called, so an episode never authors worlds into a namespace still
    holding another attempt's aliases."""
    order: list[str] = []

    class Ordered(T.FakeDoor):
        def list_names(self, glob):
            order.append("sweep")
            return super().list_names(glob)

    class Watched(T.FakeAgent):
        def __call__(self, prompt, **kw):
            order.append("questioner")
            return super().__call__(prompt, **kw)

    watched = Watched(T.family_doc(), T.world_doc("b"), T.world_doc("c"))
    _launch(tmp_path, door=Ordered(), questioner=watched)
    assert order[:1] == ["sweep"]
    assert "questioner" in order


def test_947_step_one_preflight_checks_every_precondition_before_spending(tmp_path):
    """Step 1 checks every precondition in ONE block before anything is spent, and EACH of them
    refuses before the questioner is called: the branch point out of range for the derived fence
    count, an absent source alert, a cluster the write door cannot reach, and a sweep that did
    not complete. (The alert's LINK SCREEN is the same block's fifth check and has its own
    demand — a screen names which reader applies it, which an ordering assertion cannot.)"""
    base, src = T.runs_base(tmp_path)

    def refuses(argv_extra, *, door, prepare=lambda: None):
        agent = T.FakeAgent()
        prepare()
        with pytest.raises(SystemExit):
            # The role-model preflight is neutralised: each arm has to refuse for the reason it
            # names, and an uncredentialed host would otherwise satisfy every one of them with
            # the preflight's own refusal before the check under test was ever reached.
            _cli().main([str(src), *argv_extra, "--continuation-prompt", "go"],
                        spawn=T.FakeSpawn(), door=door, questioner=agent,
                        preflight=T.no_preflight)
        assert agent.calls == 0, "the questioner was paid for before the preflight refused"

    for out_of_range in ("-1", str(10 ** 9)):
        refuses([out_of_range], door=T.FakeDoor())
    # the alert is PRESENT — the launcher reads it for the questioner's own prompt
    refuses([str(T.BRANCH_MESSAGE_ID)], door=T.FakeDoor(),
            prepare=lambda: (src / "alert.json").unlink())
    (src / "alert.json").write_text('{"rule": {"id": "r"}}', encoding="utf-8")
    # the cluster / the write door's own environment
    refuses([str(T.BRANCH_MESSAGE_ID)], door=T.FakeDoor(fault=T.Fault(raise_after=0)))
    # the sweep COMPLETED: a leftover name inside this episode's own token that will not delete
    leftover = f"wv-{T.EPISODE_TOKEN}.a-logs-"
    refuses([str(T.BRANCH_MESSAGE_ID)],
            door=T.FakeDoor(existing=(leftover,), fault=T.Fault(fail_on=(f"{T.EPISODE_TOKEN}.a",))))


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
                    spawn=T.FakeSpawn(), door=T.FakeDoor(), questioner=agent,
                    preflight=T.no_preflight)
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

    rc, spawn, ep = _launch(tmp_path)
    manifest = yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    assert manifest["continuation_prompt"] == "go"
    assert len(spawn.launches) >= 2
    seen = {la["argv"][la["argv"].index("--resume") + 1] for la in spawn.launches}
    assert len(seen) == 1, "the siblings were launched from different manifests"


# ---------------------------------------------------------------------------------------
# step 4/5 — rejection, and starting the family
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
    rc, spawn, ep = _launch(tmp_path, spawn=slow)
    assert sorted(spawn.worlds) == ["a", "b", "c"]
    for launch in spawn.launches:
        assert "--resume" in launch["argv"]
        assert any(arg.endswith("run.py") for arg in launch["argv"])
    assert spawn.overlap, "the siblings ran serially; nothing was started together"


def test_947_launcher_has_no_import_or_await_of_run_investigation(tmp_path):
    """The launcher has no path to the in-process investigation at all: its module names neither
    the driver's entry point nor an await of it, and every sibling it drives is reached through
    the process seam instead."""
    src = (T.DEFENDER / "learning" / "branch" / "cli.py").read_text(encoding="utf-8")
    assert "run_investigation" not in src
    assert "asyncio.gather" not in src
    rc, spawn, ep = _launch(tmp_path)
    assert spawn.launches, "the launcher started no child process"


def test_947_every_injected_seam_has_a_production_value(tmp_path):
    """Every seam the launcher injects has a value it resolves for itself, so the shipped entry
    point can run an episode with nothing hand-supplied (O1).

    THE SEAM STAYS A SEAM — all three parameters still default to `None`, which is what lets
    every scenario in this file drive the launcher without a provider — and the launcher answers
    for them at its own boundary, the way it already does for the write door and the role
    preflight. Injected-with-no-production-value is not a seam but a hole: it reached
    `author_family(invoke=None)` as a bare `TypeError` with an episode id already burned, and
    refusing instead of crashing left the entry point still unable to launch anything.

    The MODEL seam is asserted structurally and by construction rather than by driving it: a
    real call costs money and needs a provider, and what can go wrong without one is what is
    checked here — that the shipped role prompt exists and the agent builds from it through the
    same builder every other stage uses. The ADAPTER seam is built for real, because building it
    is the check: the registry reads and parses every system the gather grant names."""
    import inspect

    cli = _cli()
    seams = T.mod("learning.branch.seams")
    for name in ("questioner", "adapters", "invoke"):
        assert inspect.signature(cli.main).parameters[name].default is None, (
            f"{name} is no longer an injectable seam, so every scenario in this file would "
            "need a provider")
    src = (T.DEFENDER / "learning" / "branch" / "cli.py").read_text(encoding="utf-8")
    for builder in ("seams.model_seam", "seams.adapter_seam"):
        assert builder in src, f"the launcher never reaches {builder}"

    ep = T.episode(tmp_path)
    assert callable(seams.adapter_seam(ep)), "the review has no production adapter layer"
    assert callable(seams.model_seam(ep)), "the questioner has no production model call"

    # The agent the model seam drives, built the way `run_stage` builds it — the structural half
    # (a role with a registered definition, a readable standing prompt, a deps class the builder
    # accepts) with no provider call made.
    #
    # THE MODEL BUILDER IS INJECTED, and it is not a convenience: `build_agent_core`'s default
    # is `providers.build_for_effort`, which SOURCES A BILLABLE KEY. Left to the ambient
    # environment this test asserts whether the HOST is credentialed — green on a developer's
    # machine, red on CI — which is the same trap `T.no_preflight` exists for one seam over.
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


def test_947_a_rejected_world_ends_the_episode_and_the_record_archives(tmp_path):
    """Any rejected world ends the EPISODE: no world runs, the manifest, staging record and
    review are archived, and the episode's recorded outcome is rejected — an examined no, not a
    per-world refusal that would leave a two-world family running."""
    adapters = T.FakeAdapters(by_target={T.world_token("b"): {"hits": [{"_id": "planted"}]}})
    rc, spawn, ep = _launch(tmp_path, adapters=adapters,
                            invoke=T.FakeAgent(*["contradiction"] * 24))
    assert rc != 0
    assert spawn.launches == []
    assert T.review_doc(ep)["episode"]["decision"] == "rejected"
    for name in ("family.yaml", "staged.yaml", "review.yaml"):
        assert (ep / name).is_file(), name


def test_947_no_sibling_process_starts_when_any_world_is_rejected(tmp_path):
    """No sibling process starts when ANY world is rejected — not the rejected one and not its
    accepted siblings: the process seam records no launch at all, which is the observable that
    separates "the episode stopped" from "one world was skipped".

    World C is the one rejected, and it is rejected on REACHABILITY rather than on a live read:
    it declares a patch on `web-1`, the discriminating envelope comes back holding a different
    host, so the difference C declares is not visible in the world C would run in. A review does
    not gather evidence — nothing here matches a world token against a call that a patches-only
    overlay never retargets — and the base world, which declares nothing, stays accepted
    throughout."""
    adapters = T.FakeAdapters({("elastic", "esql"): {"hits": [{"host": "other-host"}]}})
    rc, spawn, ep = _launch(tmp_path, adapters=adapters,
                            invoke=T.FakeAgent(*["contradiction"] * 24))
    record = T.review_doc(ep)
    assert record["worlds"]["c"]["decision"] == "rejected"
    assert record["worlds"]["c"]["reachability"]["patched_visible"] is False
    assert record["worlds"]["a"]["decision"] == "accepted"
    assert spawn.launches == []
    assert spawn.worlds == []


def test_947_rejected_episode_archives_manifest_staging_and_review(tmp_path):
    """A rejected episode archives its inputs rather than deleting the directory: the manifest,
    the staging record and the review record are all still readable afterwards, because a
    family that did not run is the second thing the drift obligation is observed by."""
    adapters = T.FakeAdapters(by_target={T.world_token("b"): {"hits": [{"_id": "planted"}]}})
    rc, spawn, ep = _launch(tmp_path, adapters=adapters,
                            invoke=T.FakeAgent(*["contradiction"] * 24))
    for name in ("family.yaml", "staged.yaml", "review.yaml"):
        assert (ep / name).read_text(encoding="utf-8").strip(), name


def test_947_any_failure_in_steps_two_to_four_aborts_the_episode(tmp_path, monkeypatch):
    """ONE rule for all three steps, not a six-way taxonomy: a questioner call that fails
    (step 2), a staging door that fails mid-way (step 3) and a review whose replay cannot reach
    the cluster (step 4) each abort the episode the same way — teardown fires and no sibling
    process starts."""
    cases = {
        # `staged` is whether the abort happens AFTER the first name was created. It is not a
        # softer expectation for the questioner arm: teardown removes exactly what the staging
        # record names, so an abort in step 2 leaves an empty record and a correct teardown makes
        # no delete call at all. What that arm can be held to — and is — is the stronger claim
        # that nothing was created in the first place.
        "questioner": ({"questioner": T.FakeAgent(T.family_doc(),
                                                  fault=T.Fault(raise_after=1))}, False),
        # `raise_after=2` and not 1: step 1's own reachability probe and the sweep each open a
        # connection, so a door that dies on the second one never reaches step 3 at all and this
        # arm would be a second reading of the preflight rather than of staging.
        "staging": ({"door": T.FakeDoor(fault=T.Fault(raise_after=2))}, True),
        # STEP 4 FAILS ON THE COMPARATOR, not on a cluster the review cannot reach: a review
        # replays and does not gather evidence, so its only outbound call is the discriminating
        # envelope and a failing one is a recorded reachability result rather than an abort. What
        # can still end step 4 is the judgment itself — here the model answers `mutation` on the
        # review seat, which admits three verdicts and not that one, and the comparator refuses a
        # wrong-seat answer rather than filing it as a contradiction.
        "review": ({"capture": [{"system": "identity", "verb": "get-user",
                                 "payload": {"hits": [{"host": "web-1", "owner": "soc"}]}}],
                    "invoke": T.FakeAgent(*["mutation"] * 8)}, True),
    }
    for step, (seams, staged) in cases.items():
        # Each arm gets its own episodes root: three aborts sharing one would make the second
        # and third meet a directory the first left behind, and the ordering — not the abort
        # rule — would be what they observed.
        monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / f"episodes-{step}"))
        door = seams.pop("door", None) or T.FakeDoor()
        capture = seams.pop("capture", ())
        spawn = T.FakeSpawn()
        with pytest.raises(SystemExit):
            _launch(tmp_path, spawn=spawn, door=door, capture=capture, **seams)
        assert spawn.launches == [], f"{step}: a sibling started after the abort"
        if staged:
            assert door.deleted(), f"{step}: teardown left the names it recorded on the cluster"
            assert set(door.deleted()) >= set(door.created()), (
                f"{step}: teardown removed fewer names than the abort created")
        else:
            assert door.created() == [], f"{step}: a name was created before the abort"


def test_947_teardown_runs_on_rejection_completion_and_exception(tmp_path, monkeypatch):
    """Teardown runs on every exit the launcher has: on a rejection, on a clean completion, and
    on an exception raised after the first staging append.

    EACH EXIT GETS ITS OWN EPISODE. An episode id is derived from (source run, branch point), so
    three launches from one source share one — and the first leaves a manifest behind, which the
    relaunch rule refuses on purpose. Sharing a root would make the second and third arms observe
    that refusal rather than the exit they are about."""
    rejecting = T.FakeAdapters(by_target={T.world_token("b"): {"hits": [{"_id": "planted"}]}})
    exits = [
        ("clean", {}),
        ("rejection", {"adapters": rejecting, "invoke": T.FakeAgent(*["contradiction"] * 24)}),
    ]
    for name, kwargs in exits:
        monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / f"episodes-{name}"))
        door = T.FakeDoor()
        with contextlib.suppress(SystemExit):
            _launch(tmp_path, door=door, **kwargs)
        assert door.deleted(), f"teardown did not run for the {name} exit"
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-exception"))
    crashing = T.FakeDoor(fault=T.Fault(raise_after=2))
    with pytest.raises(SystemExit):
        _launch(tmp_path, door=crashing)
    assert crashing.deleted()


# ---------------------------------------------------------------------------------------
# step 6 — verification, the family stamp and the incomplete outcome
# ---------------------------------------------------------------------------------------


def test_947_launcher_verifies_each_siblings_scrub_verdict(tmp_path):
    """The launcher verifies each sibling's scrub verdict after the processes exit, reading the
    verdict at its sidecar path beside the run dir rather than inside the tree it judges."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    for world in T.WORLDS:
        T.sibling_run_dir(base, world)
    report = _cli().verify_family(ep, [base / f"{T.EPISODE_ID}-{w}" for w in T.WORLDS])
    assert report["scrub_verified"] == list(T.WORLDS)


def test_947_a_sibling_without_a_ran_true_scrub_marks_the_episode_incomplete(tmp_path):
    """A sibling whose scrub verdict is absent, or present but not recording a completed walk,
    marks the episode incomplete with the reason — never archived as comparable."""
    base, src = T.runs_base(tmp_path)
    for scrub_ran, world in ((None, "b"), (False, "c")):
        ep = T.episode(tmp_path)
        dirs = [T.sibling_run_dir(base, w, scrub_ran=True if w != world else scrub_ran)
                for w in T.WORLDS]
        report = _cli().verify_family(ep, dirs)
        assert report["outcome"] == "incomplete"
        assert world in report["reason"]


def test_947_agreeing_sibling_stamps_write_the_family_stamp(tmp_path):
    """Sibling stamps that agree write the family stamp: one record for the family, carrying
    the agreed provenance every sibling reported."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, commit="cafe1") for w in T.WORLDS]
    _cli().verify_family(ep, dirs)
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["agreed"]["commit"] == "cafe1"


def test_947_family_stamp_carries_agreed_and_override_as_disjoint_roles(tmp_path):
    """The family stamp carries its two roles disjointly: the agreed provenance record, and
    whether the dirty override was given — neither sourced from the other, so an override
    cannot be read out of the provenance half or vice versa."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    _cli().verify_family(ep, [T.sibling_run_dir(base, w) for w in T.WORLDS])
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert set(stamp) == {"agreed", "allow_dirty"}
    assert "allow_dirty" not in stamp["agreed"]
    assert isinstance(stamp["allow_dirty"], bool)


def test_947_disagreeing_sibling_stamps_mark_the_episode_incomplete_with_a_reason(tmp_path):
    """Sibling stamps recording different commits mark the episode incomplete with the reason,
    and no family stamp is written: the tree moved between the first and last sibling, which is
    exactly the catch per-process stamps exist for."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, commit=("cafe1" if w == "a" else "cafe2"))
            for w in T.WORLDS]
    report = _cli().verify_family(ep, dirs)
    assert report["outcome"] == "incomplete"
    assert "commit" in report["reason"]
    assert not (ep / "provenance.json").exists()


def test_947_an_absent_or_unreadable_sibling_stamp_marks_the_episode_incomplete(tmp_path):
    """A sibling stamp that is absent, or present but unreadable, is not an agreeing stamp: the
    episode is marked incomplete with the reason exactly as a disagreeing one is, and no family
    stamp is written."""
    base, src = T.runs_base(tmp_path)
    for mutate in ("absent", "truncated"):
        ep = T.episode(tmp_path)
        dirs = [T.sibling_run_dir(base, w, stamp=(w != "b")) for w in T.WORLDS]
        if mutate == "truncated":
            (dirs[1] / "provenance.json").write_text('{"commit": "cafe', encoding="utf-8")
        report = _cli().verify_family(ep, dirs)
        assert report["outcome"] == "incomplete"
        assert not (ep / "provenance.json").exists()


def test_947_the_family_stamp_carries_the_resolved_model_per_sibling(tmp_path):
    """The family stamp compares the resolved MODEL alongside the commit and the scope: each
    sibling's stamp records the model its own process resolved, and the family stamp carries the
    agreed value."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    _cli().verify_family(ep, [T.sibling_run_dir(base, w, model="m-1") for w in T.WORLDS])
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["agreed"]["model"] == "m-1"


def test_947_a_cross_model_family_refuses_rather_than_agreeing(tmp_path):
    """A family whose siblings resolved DIFFERENT models refuses rather than passing with an
    otherwise agreeing stamp: the model is held constant the way the commit is, so a comparison
    across two models is never archived as comparable."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, model=("m-1" if w == "a" else "m-2")) for w in T.WORLDS]
    report = _cli().verify_family(ep, dirs)
    assert report["outcome"] == "incomplete"
    assert "model" in report["reason"]
    assert not (ep / "provenance.json").exists()


def test_947_a_dirty_sibling_tree_is_refused_without_the_override(tmp_path):
    """EVERY non-clean stamp outcome refuses absent the override, and there are three a capture
    can produce: a dirty tree, a git that could not be asked at all (no sha, a reason), and a
    git that named the sha but could not answer for the tree. An unknown is not a clean bill of
    health. With the override each of the three families completes instead."""
    base, src = T.runs_base(tmp_path)
    arms = {
        "dirty": {"dirty": True},
        "unavailable": {"commit": None, "dirty": None, "unavailable": T.GIT_UNAVAILABLE},
        "git-failed": {"dirty": None, "unavailable": T.GIT_STATUS_FAILED},
    }
    for name, stamp in arms.items():
        ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-{name}")
        dirs = [T.sibling_run_dir(base / name, w, **(stamp if w == "b" else {}))
                for w in T.WORLDS]
        report = _cli().verify_family(ep, dirs)
        assert report["outcome"] == "incomplete", name
        assert "b" in report["reason"], (name, report["reason"])
        ok = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-{name}-ok")
        assert _cli().verify_family(ok, dirs, allow_dirty=True)["outcome"] == "accepted", name


def test_947_the_dirty_override_is_named_in_the_family_stamp(tmp_path):
    """When the dirty override is given it is NAMED in the family stamp: a reader of the archive
    can tell an agreed clean family from one that was waved through."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, dirty=(w == "b")) for w in T.WORLDS]
    _cli().verify_family(ep, dirs, allow_dirty=True)
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["allow_dirty"] is True


def test_947_launcher_no_longer_hoists_one_capture_above_the_family(tmp_path):
    """The launcher no longer captures one provenance record above the family: nothing in it
    reads the tree's provenance for the family as a whole, and the workflow that record served —
    knowing what the family was made against — completes from the per-sibling stamps instead."""
    src_text = (T.DEFENDER / "learning" / "branch" / "cli.py").read_text(encoding="utf-8")
    assert "capture_tree" not in src_text
    base, source = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    _cli().verify_family(ep, [T.sibling_run_dir(base, w) for w in T.WORLDS])
    assert (ep / "provenance.json").is_file()


# ---------------------------------------------------------------------------------------
# §7 FORK-1 — `incomplete` is a modelled outcome
# ---------------------------------------------------------------------------------------


def test_947_the_episode_outcome_is_a_recorded_field_with_a_reason(tmp_path):
    """The episode's outcome is a recorded field carrying accepted, rejected or incomplete plus
    a reason — never the ABSENCE of a file, which is what left every question about a partially
    good family falling through."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, scrub_ran=(w != "c")) for w in T.WORLDS]
    _cli().verify_family(ep, dirs)
    record = T.review_doc(ep)["episode"]
    assert record["outcome"] == "incomplete"
    assert record["reason"]


def test_947_an_incomplete_family_is_a_fourth_teardown_trigger(tmp_path):
    """`incomplete` is a fourth teardown trigger: a family that cannot be stamped still has its
    staged names removed, because the cluster does not care why the episode ended."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    door = T.FakeDoor(existing=(f"wv-{T.world_token('b')}-logs-",))
    (ep / "staged.yaml").write_text(
        json.dumps([{"world": T.world_token("b"), "name": f"wv-{T.world_token('b')}-logs-",
                     "kind": "alias", "derived_from": T.EVENTS_PATTERN,
                     "created_at": T.AS_OF}]), encoding="utf-8")
    dirs = [T.sibling_run_dir(base, w, scrub_ran=(w != "c")) for w in T.WORLDS]
    _cli().verify_family(ep, dirs, door=door)
    assert door.deleted() == [f"wv-{T.world_token('b')}-logs-"]


def test_947_an_incomplete_family_archives_per_world_and_withholds_comparability(tmp_path):
    """An incomplete family archives each individually clean sibling and withholds only the
    family stamp and the comparability claim: the clean worlds are on disk, the stamp is not,
    and the episode's recorded outcome says why."""
    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w, scrub_ran=(w != "c")) for w in T.WORLDS]
    _cli().verify_family(ep, dirs)
    assert sorted(p.name for p in (ep / "worlds").iterdir()) == ["a", "b"]
    assert not (ep / "provenance.json").exists()
    assert T.review_doc(ep)["episode"]["outcome"] == "incomplete"


# ---------------------------------------------------------------------------------------
# §7 FORK-2 — relaunching after a death
# ---------------------------------------------------------------------------------------


def test_947_two_launchers_on_one_episode_cannot_both_prime_it(tmp_path):
    """The episode directory's creation is an exclusive create, not a check-then-act: two
    launchers racing on one source and branch point produce ONE primed episode and one refusal,
    never two captures stacked into a single base recording that both callers read as clean."""
    import threading

    base, src = T.runs_base(tmp_path)
    cli = _cli()
    results: list = []
    barrier = threading.Barrier(2)

    def attempt():
        barrier.wait()
        try:
            results.append(cli.prepare_episode(T.EPISODE_ID, src))
        except Exception as e:  # noqa: BLE001 — the refusal is the observation
            results.append(e)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(isinstance(r, Exception) for r in results) == 1, results
    rows = (cli.episode_dir_for(T.EPISODE_ID) / "served" / "base.jsonl")
    assert not rows.exists() or len(rows.read_text(encoding="utf-8").splitlines()) == \
        len({line for line in rows.read_text(encoding="utf-8").splitlines()})


def test_947_a_relaunch_adopts_an_episode_dir_holding_no_manifest(tmp_path):
    """A relaunch ADOPTS an episode directory that holds no manifest: a mid-prime death would
    otherwise make that source and branch point permanently unbranchable with no documented
    remedy, while a directory that DOES hold a manifest is still refused."""
    base, src = T.runs_base(tmp_path)
    cli = _cli()
    ep = cli.episode_dir_for(T.EPISODE_ID)
    (ep / "served").mkdir(parents=True, exist_ok=True)
    assert cli.prepare_episode(T.EPISODE_ID, src) is not None
    T.write_family(ep)
    with pytest.raises(T.refusals()):
        cli.prepare_episode(T.EPISODE_ID, src)


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
