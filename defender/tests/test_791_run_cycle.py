"""#791 part 1 — the learning cycle after the offline oracle leaves it.

Every test here is one demand of `defender/tests/spec_graph_791-retire-offline-oracle.yaml`,
named by that demand's `discharged_by`. RED against HEAD is the expected state: no
implementation exists, and these pin the demanded correction rather than today's behaviour.

THREE REFUTATIONS SHAPE THIS FILE AND ARE PINNED AS CORRECTIONS, NOT DESCRIBED:

* "The retired modules stay uncalled" is FALSE in production (P5). The evidence column that
  survives the three-to-two cut is produced inside the retired stage's own module and is
  called on every direction leg. R1 moves the producer out; a test seeded from the issue's
  own wording would go red against correct code, so the demand here is about what a learning
  run IMPORTS, not about a package being unexercised.
* An operator CANNOT enqueue a learn marker by hand and never could (H1, refuted). The
  learning CLI's bare run-dir positional drives the run cycle DIRECTLY and never creates the
  queue (H1b), so the surviving hand path is that direct drive — asserting a marker anywhere
  would pin a mechanism that does not exist.
* No reachable disposition selects zero directions (E1, refuted). The two reachable shapes of
  "this run produced nothing worth curating" are an actor SKIP and a leg that raised, so the
  issue's third shape is not written here.

The key-sourcing pair is the sharpest trap in the set (E4): at shipped defaults the oracle,
actor and judge models are all aliases of ONE provider, so "a learning run completes with no
oracle key" is TRUE OF THE UNCHANGED TREE. The demand is observable only in the crossing
column, and its paired control — the default column, which proves nothing — is written next
to it so a reader cannot mistake one for the other.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from defender import run as run_py  # noqa: E402
from defender.learning.core import run_cycle  # noqa: E402
from defender.learning.core.directions import BY_NAME  # noqa: E402
from defender.scripts.visualize import visualize_judge as vj  # noqa: E402
from defender.tests._spec791 import (  # noqa: E402
    DEFENDER,
    CLI_PY,
    LEG_COMPLETED,
    LEG_NEVER_SELECTED,
    LEG_STARTED_AND_DIED,
    LEG_UNRECORDED,
    RETIRED_PACKAGE,
    GroundedJudgeSubagents,
    SpecSubagents,
    SpecTail,
    author_markers,
    call_order,
    drive_tail,
    learn_markers,
    loop_paths,
    make_run_dir,
    noop_start_box,
    noop_stop_box,
    plant_alert,
    satisfy_engine_keys,
    satisfy_entrypoint_keys,
)

ADVERSARIAL, BENIGN = BY_NAME["adversarial"], BY_NAME["benign"]


def _drive(tmp_path, monkeypatch, *, agents, disposition="inconclusive", name="case-791",
           leads=("l-001",), alert_bytes=None):
    """Drive the REAL run cycle over a real run dir with the subagents injected."""
    satisfy_engine_keys(monkeypatch, disposition)
    paths = loop_paths(tmp_path)
    run_dir = make_run_dir(tmp_path, name=name, disposition=disposition, leads=leads,
                           alert_bytes=alert_bytes)
    rc = run_cycle.run_one(
        run_dir, paths=paths, agents=agents,
        start_box=noop_start_box, stop_box=noop_stop_box,
    )
    return rc, paths, run_dir, agents


def _learning_dir(paths, run_dir: Path) -> Path:
    return paths.runs_dir / run_dir.name


def test_791_learning_run_leaves_no_projection_artifact(tmp_path, monkeypatch):
    """run_cycle_result_shape — a learning run leaves NO projected-telemetry file and no
    `.raw.txt` fallback in the learning run dir, and neither direction declares one among the
    artifacts its legs produce: the name LEAVES the declared list rather than staying declared
    with nothing writing it.

    FK1's rejected branch is what this pins against. The leg-ran check asks whether ANY
    declared name exists (E8), so a declared-but-unwritten name cannot make it FAIL — it fails
    OPEN, permanently, rendering an empty section forever; and run dirs already on disk make
    it wrong retroactively, because the old bytes render as this run's projection.

    The positive control is the second half: the story and the judge doc ARE written, so the
    absence asserted above is the retirement and not a run that never happened."""
    rc, paths, run_dir, _agents = _drive(tmp_path, monkeypatch, agents=GroundedJudgeSubagents())
    learn = _learning_dir(paths, run_dir)

    assert rc == 0
    assert sorted(p.name for p in learn.glob("projected_telemetry*")) == [], \
        "the learning run still writes a projected-telemetry artifact"

    for direction in (ADVERSARIAL, BENIGN):
        assert not hasattr(direction, "telemetry_name"), \
            f"{direction.name} still declares a projected-telemetry name on the run record"
        declared = direction.artifact_names()
        assert not [n for n in declared if "projected_telemetry" in n], \
            f"{direction.name} still declares {declared} — the retired name never left the tuple"

    for direction in (ADVERSARIAL, BENIGN):
        assert (learn / direction.story_name).is_file(), "the leg wrote no story"
        assert (learn / direction.judge_name).is_file(), "the leg persisted no judge doc"


def test_791_a_leg_that_died_is_not_reported_as_a_leg_that_ran(tmp_path, monkeypatch):
    """leg_ran_signal_is_positive — each leg records its own terminal status in the run's
    record, and the viewer reads that one place to separate a leg that was never selected from
    one that started and died. Dropping the declared name and giving the viewer a positive
    signal are one decision (R2 + R15), not two.

    Three arms, one per member of the vocabulary the status carries. (1) A leg whose judge
    call raises leaves its story on disk — under the presence inference that IS "this leg ran"
    — and must report `started-and-died`. (2) A direction the disposition never selected
    reports `never-selected`. (3) A learning run dir written BEFORE the field existed carries
    no status at all and must read as `unrecorded` — R15's stated default, and the accepted
    cost of the decision: such a run dir must be reported neither as a leg that ran nor as one
    that was never selected."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    agents = SpecSubagents(judge_fault=RuntimeError("judge call died mid-leg"))
    with pytest.raises(RuntimeError):
        _drive(tmp_path, monkeypatch, agents=agents, disposition="benign", name="case-died")

    paths = loop_paths(tmp_path)
    died = paths.runs_dir / "case-died"
    assert (died / ADVERSARIAL.story_name).is_file(), \
        "the dying leg left no artifact — the presence inference this demand replaces cannot " \
        "even be wrong here, so the assertion below would be vacuous"

    assert vj.leg_status("case-died", ADVERSARIAL) == LEG_STARTED_AND_DIED
    assert vj.leg_status("case-died", ADVERSARIAL) != LEG_COMPLETED
    assert vj.leg_status("case-died", BENIGN) == LEG_NEVER_SELECTED

    stale = paths.runs_dir / "case-pre-change"
    stale.mkdir(parents=True)
    (stale / ADVERSARIAL.story_name).write_text("a story from before the field existed\n",
                                                encoding="utf-8")
    assert vj.leg_status("case-pre-change", ADVERSARIAL) == LEG_UNRECORDED, \
        "a run dir written before the status field existed must read as its stated default"


def test_791_finished_investigation_leaves_the_learn_queue_empty(tmp_path, monkeypatch):
    """investigation_writes_no_learn_marker — a finished investigation writes no marker onto
    the learn queue: the automatic feed the investigation tail carried is unhooked at its call
    site, so the tail's enqueue branch is gone from the entrypoint's composition.

    Bullet 1 removes a CALL SITE, not a function — the refusal predicate the helper owns is
    shared source after R3, and the parity demand over both enqueues is what keeps it from
    drifting. So this asserts on what the tail DOES, by driving the entrypoint through R22's
    seam over a run nothing refuses: a finished investigation leaves the learn queue with
    nothing in it. The paired positive is the curation marker landing on the author queue in
    the same tail — without it "the queue is empty" is also true of a tail that never ran, or
    of a test pointed at the wrong state root."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    paths = loop_paths(tmp_path)

    tail = SpecTail(paths)
    assert drive_tail(run_py.main, plant_alert(tmp_path / "operator"), tail) == 0
    assert tail.run_dirs, "the entrypoint never ran the investigation, so the queues prove nothing"

    assert learn_markers(paths) == [], "a finished investigation left a learn-queue marker"
    assert author_markers(paths), \
        "no curation marker either — the tail wrote nothing, so the emptiness above proves nothing"


def test_791_operator_can_still_learn_a_run_by_hand(tmp_path, monkeypatch):
    """hand_invoked_learning_still_runs — bullet 1 removes the AUTOMATIC path, not every path:
    an operator handing the learning entrypoint a bare run dir still drives the run cycle and
    the run's own learning artifacts appear.

    The mechanism this demand used to name does not exist and never did (H1, refuted): the
    CLI's positional makes ZERO calls to the enqueue helper and never creates the queue
    directory. So the surviving path asserted here is the DIRECT drive — the artifacts a
    hand-invoked LEARN produces — plus the composition claim that the positional branch reaches
    the run cycle and no enqueue at all. Without this demand, bullets 3 and 4 read as edits to
    unreachable code."""
    rc, paths, run_dir, _agents = _drive(tmp_path, monkeypatch, agents=GroundedJudgeSubagents(),
                                          disposition="benign")
    learn = _learning_dir(paths, run_dir)

    assert rc == 0
    assert (learn / ADVERSARIAL.story_name).is_file()
    assert (learn / ADVERSARIAL.judge_name).is_file()
    assert learn_markers(paths) == [], "the hand path must not touch the learn queue"

    cli_calls = call_order(CLI_PY, "main")
    assert "run_one" in cli_calls, "the CLI no longer drives the run cycle; re-site this demand"
    assert not [c for c in cli_calls if c.startswith("enqueue")], \
        "the CLI's dispatch reaches an enqueue — the refuted hand feed is back"


def test_791_run_cycle_leaves_the_author_queue_untouched(tmp_path, monkeypatch):
    """run_cycle_writes_no_author_marker — the run cycle no longer enqueues for authoring: the
    curation trigger moves to the investigation boundary, so the run cycle's own tail writes
    no marker, and curation ends up with exactly one trigger rather than a live one plus a
    dead one.

    Driven over both reachable shapes of "produced nothing worth curating" (E1 refutes the
    third): an ordinary run, an actor SKIP, and a leg that raised — the last two are where the
    old call site's `enqueue regardless` mattered. The positive control is that the cycle
    really ran in each arm: the leg's own artifacts are on disk."""
    for label, agents, expect_raise in (
        ("skip", SpecSubagents(story="SKIP: not ours\n"), False),
        ("ordinary", GroundedJudgeSubagents(), False),
        ("raised", SpecSubagents(judge_fault=RuntimeError("leg died")), True),
    ):
        paths = loop_paths(tmp_path / label)
        satisfy_engine_keys(monkeypatch, "benign")
        run_dir = make_run_dir(tmp_path / label, disposition="benign")
        if expect_raise:
            with pytest.raises(RuntimeError):
                run_cycle.run_one(run_dir, paths=paths, agents=agents,
                                  start_box=noop_start_box, stop_box=noop_stop_box)
        else:
            run_cycle.run_one(run_dir, paths=paths, agents=agents,
                              start_box=noop_start_box, stop_box=noop_stop_box)

        assert (paths.runs_dir / run_dir.name / ADVERSARIAL.story_name).is_file(), \
            f"{label}: the cycle never reached the leg, so the assertion below is vacuous"
        assert author_markers(paths) == [], \
            f"{label}: the run cycle still enqueued the run for authoring"


def test_791_direction_leg_completes_with_two_subagent_calls(tmp_path, monkeypatch):
    """no_oracle_stage_call_in_a_direction_leg — a direction leg drives the actor and the
    judge and NOTHING else: the retired stage is never invoked from the learning cycle.

    The zero call count alone passes vacuously (R12): a scenario that dies early is
    indistinguishable from one that correctly declined to call the stage, and "it is never
    called" is this change's headline demand. So the leg's own COMPLETION is asserted beside
    it — the judge doc persisted, the findings appended, the cycle returning cleanly.

    Scoped to the STAGE INVOCATION, never to "the package is unexercised": P5 refuted that
    reading, and its own demand is the import test next to this one."""
    rec_agents = GroundedJudgeSubagents()
    rc, paths, run_dir, agents = _drive(tmp_path, monkeypatch, agents=rec_agents)
    learn = _learning_dir(paths, run_dir)

    assert rc == 0
    assert agents.rec.count("oracle") == 0, "a direction leg still invoked the retired stage"
    assert sorted(agents.calls) == ["actor", "actor_benign", "judge", "judge_benign"], \
        f"the leg drove {agents.calls}, not the actor and the judge alone"
    for direction in (ADVERSARIAL, BENIGN):
        assert (learn / direction.judge_name).is_file(), \
            f"{direction.name} never completed — the zero call count above proves nothing"


def test_791_a_learning_run_imports_nothing_from_the_retired_package(tmp_path, monkeypatch):
    """learning_run_never_imports_the_retired_package — a learning run imports nothing from the
    retired stage's package, and the evidence column that survives the three-to-two cut is
    produced somewhere else.

    This is the widening R1 accepted and the handoff must state plainly. Today the judge's
    surviving comparison imports and calls the sample producer once per executed lead on every
    direction leg — and that producer lives in the retired stage's own module, beside the
    oracle's prompt builder, reply parser and projection assembler (P5). "Uncalled" is false in
    PRODUCTION, not only in the evals. Moving the producer out is what makes the word mean what
    it says, and what lets the dead-code gate express itself honestly: a file that is PARTLY
    live is the one shape a file-level accept cannot describe.

    Driven in a subprocess because the claim is about a fresh interpreter's import graph: this
    process has already imported half the tree, so `sys.modules` here would answer for the test
    session rather than for a run."""
    script = textwrap.dedent(
        f"""
        import json, sys
        from pathlib import Path
        sys.path.insert(0, {str(DEFENDER.parent)!r})
        from defender.learning.pipeline.judge.compare import build_comparison, real_sample_text
        from defender.learning.core import run_cycle
        from defender.tests._spec791 import (
            GroundedJudgeSubagents, loop_paths, make_run_dir, noop_start_box, noop_stop_box,
        )
        tmp = Path({str(tmp_path / "sub")!r})
        tmp.mkdir(parents=True, exist_ok=True)
        run_dir = make_run_dir(tmp, disposition="benign")
        run_cycle.run_one(run_dir, paths=loop_paths(tmp), agents=GroundedJudgeSubagents(),
                          start_box=noop_start_box, stop_box=noop_stop_box)
        leaked = sorted(m for m in sys.modules if m.startswith({RETIRED_PACKAGE!r}))
        print(json.dumps({{"leaked": leaked, "home": real_sample_text.__module__}}))
        """
    )
    satisfy_engine_keys(monkeypatch, "benign")
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True,
        cwd=str(DEFENDER), env={**dict(__import__("os").environ),
                                "PYTHONPATH": str(DEFENDER.parent)},
    )
    assert proc.returncode == 0, f"the driven run failed:\n{proc.stderr[-3000:]}"
    result = json.loads(proc.stdout.strip().splitlines()[-1])

    assert result["leaked"] == [], \
        f"a learning run pulled in {result['leaked']} from the retired package"
    assert not result["home"].startswith(RETIRED_PACKAGE), \
        f"the surviving evidence column is still produced inside {result['home']}"


def test_791_transcript_renders_a_leg_with_no_projection_section(tmp_path, monkeypatch):
    """projected_telemetry_consumers_survive — the two live dependents of the artifact being
    removed both survive it: the transcript renders a leg that left no projection, with no
    dangling oracle section and no dead link to one, and the surviving eval still writes its
    OWN projection into its own staging dir.

    The persist step already tolerates a null projection — the SKIP path drives that shape
    today (C15) — so what needs a witness is not the write but the READERS. The transcript's
    oracle section is one; the second eval's staging copy is the other, and it keeps its own
    geometry rather than the run cycle's."""
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    learn = tmp_path / "state" / "runs" / "case-t"
    learn.mkdir(parents=True)
    (learn / ADVERSARIAL.story_name).write_text("a story\n", encoding="utf-8")
    (learn / ADVERSARIAL.judge_name).write_text("outcome: caught\n", encoding="utf-8")

    view = vj.ADVERSARIAL_VIEW
    assert vj.render_judge_actor_section("case-t", view), "the leg no longer renders at all"
    assert vj.render_judge_judge_section({"outcome": "caught"}, view)
    assert not hasattr(vj, "render_judge_oracle_section"), \
        "the transcript still renders a section for the artifact nothing writes"

    toc = vj.render_judge_toc([(view, 0)], raw_bundle=False)
    assert "projected telemetry" not in toc.lower(), \
        "the transcript's contents still link a projected-telemetry section"

    from defender.evals import _pipeline

    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "actor_story.md").write_text("not a SKIP\n", encoding="utf-8")
    head = make_run_dir(tmp_path, name="head-run", disposition="benign")

    class _Loop:
        class RunUnprocessable(Exception):
            pass

        ADVERSARIAL_WIRING = object()

        class InProcessSubagents:
            def oracle(self, *_a, **_kw):
                return "projections: []\n"

        @staticmethod
        def is_skip_story(_text):
            return False

        @staticmethod
        def strip_yaml_fence(text):
            return text

        @staticmethod
        def _prepare_engines_for(_directions, **_kw):
            pass

    # The fake declares no `judge`: the judging half of this eval goes dark under R7 (its own
    # demand owns the stated skip), so reaching for one here is an AttributeError, not a pass.
    _pipeline.run_head_oracle_and_judge(head, staging, _Loop)
    assert (staging / "projected_telemetry.yaml").is_file(), \
        "the surviving eval no longer writes its own projection into its staging dir"


def test_791_run_cycle_sources_no_key_for_the_oracle_model(tmp_path, monkeypatch):
    """key_sourcing_no_longer_names_the_oracle_model — the run cycle's key-sourcing step no
    longer names the retired stage's model, so a learning run neither resolves its provider nor
    demands its key.

    Observed by pointing the knob at a name NO provider knows: resolution raises on an unknown
    model (H6), so a run cycle that still names it fails loudly and one that has stopped naming
    it completes. That is the only witness available without a second provider's key, and it is
    exact — it cannot pass because a key happened to be lying around.

    FK4/R13 scopes this to the run cycle's own path: the shared preparation helper's model set
    is untouched and the surviving eval keeps sourcing its own key, because removing it there
    breaks that eval in exactly the non-default configuration that makes the end-to-end demand
    observable at all. Accepted cost, stated: this pins the WIRING, not the outcome."""
    satisfy_engine_keys(monkeypatch, "benign")
    monkeypatch.setenv("ORACLE_MODEL", "spec791-no-such-provider/model")
    paths = loop_paths(tmp_path)
    run_dir = make_run_dir(tmp_path, disposition="benign")

    rc = run_cycle.run_one(run_dir, paths=paths, agents=GroundedJudgeSubagents(),
                           start_box=noop_start_box, stop_box=noop_stop_box)
    assert rc == 0, "the run cycle still resolves the retired stage's model"
    assert (paths.runs_dir / run_dir.name / ADVERSARIAL.judge_name).is_file()


def test_791_learning_run_completes_with_no_oracle_provider_key(tmp_path, monkeypatch):
    """oracle_model_on_another_provider_still_runs — with the retired stage's model pointed at
    the OTHER provider and that provider's key withheld, a learning run still completes.

    This is the crossing column and the only one in which the demand has a witness. Keys are
    sourced PER PROVIDER (E4), and at shipped defaults the oracle, actor and judge models are
    all aliases of one provider — so the human's original wording, "a learning run completes
    with no oracle key", is TRUE OF THE UNCHANGED TREE. Withholding the second provider's key
    is what makes the assertion mean anything; the `.env` search path is neutralised too, or
    the key comes back through a file the test never named."""
    monkeypatch.setenv("FIREWORKS_API_KEY", "spec791-not-used")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(tmp_path / "empty.env"))
    (tmp_path / "empty.env").write_text("# no keys here\n", encoding="utf-8")
    monkeypatch.setenv("ORACLE_MODEL", "claude-sonnet-4-5")

    paths = loop_paths(tmp_path)
    run_dir = make_run_dir(tmp_path, disposition="benign")
    rc = run_cycle.run_one(run_dir, paths=paths, agents=GroundedJudgeSubagents(),
                           start_box=noop_start_box, stop_box=noop_stop_box)
    assert rc == 0, "the run cycle still demands the retired stage's provider key"


def test_791_a_single_provider_learning_run_completes(tmp_path, monkeypatch):
    """single_provider_run_is_the_paired_control — at shipped defaults, with every model on one
    provider and that provider's key present, a learning run completes.

    It completes before the change and after it, and PROVES NOTHING about the key-sourcing set
    — which is precisely why it is written down beside the demand that does. A reader who sees
    only this green column cannot tell the two apart, and would read the retirement as
    witnessed when it is not."""
    monkeypatch.delenv("ORACLE_MODEL", raising=False)
    satisfy_engine_keys(monkeypatch, "benign")
    paths = loop_paths(tmp_path)
    run_dir = make_run_dir(tmp_path, disposition="benign")

    rc = run_cycle.run_one(run_dir, paths=paths, agents=GroundedJudgeSubagents(),
                           start_box=noop_start_box, stop_box=noop_stop_box)
    assert rc == 0
    assert (paths.runs_dir / run_dir.name / ADVERSARIAL.judge_name).is_file()


def test_791_concurrent_direction_legs_write_distinct_artifacts(tmp_path, monkeypatch):
    """concurrent_direction_legs_write_distinct_artifacts — two direction legs running
    concurrently into one shared learning run dir land their per-lead comparison files and
    their judge docs on DISTINCT paths carrying each leg's own content.

    Both sinks have full key coverage on paper and no demand drove two legs to check it — the
    canonical shape of a per-key collision across the two legs of one fan-out. Asserted on real
    content, not on the names alone: two files that exist but hold one leg's bytes is exactly
    the collision, and a name check cannot see it.

    Re-opened by the gate after an earlier drop that rested on a probe citation absent from the
    ledger. An unverifiable citation is not a pass."""
    rc, paths, run_dir, agents = _drive(
        tmp_path, monkeypatch,
        agents=GroundedJudgeSubagents(
            judge_raw="outcome: caught\ndefender_findings: []\n",
            judge_benign_raw="outcome: survived\ndefender_findings: []\n",
        ),
    )
    learn = paths.runs_dir / run_dir.name
    assert rc == 0

    adversarial_cmp = learn / ADVERSARIAL.judge_wiring.comparison_dirname / "l-001.md"
    benign_cmp = learn / BENIGN.judge_wiring.comparison_dirname / "l-001.md"
    assert adversarial_cmp != benign_cmp, "both legs render into ONE comparison path"
    for p in (adversarial_cmp, benign_cmp):
        assert p.is_file(), f"{p} was never written — the collision check would be vacuous"

    judge_docs = {d.name: (learn / d.judge_name).read_text(encoding="utf-8")
                  for d in (ADVERSARIAL, BENIGN)}
    assert len(set(judge_docs.values())) == 2, \
        f"the two legs' judge docs are byte-identical — one leg overwrote the other: {judge_docs}"
    assert len(agents.judge_user_texts) == 2
    assert len(set(agents.judge_user_texts)) == 2, \
        "both legs were sent the same judge turn — the per-direction comparison collided"
