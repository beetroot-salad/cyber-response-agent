"""The run's wire log is not readable by the agents that write into it.

`llm_requests.jsonl` is the run's ONE wire log: MAIN, every gather subagent (`gather:{lead_id}`)
and every review stage (`review:{lens}`) log through the same `RequestLogger`, which is what
makes all three priceable. That sharing is also what makes the file a boundary: it holds, in
full and verbatim, the raw gather payload bytes `decide_read` refuses MAIN one call earlier with
`RAW_DENY_REASON`, and MAIN's transcript that GATHER has never been shown.

At the run ROOT it was readable by both of them. MAIN's and GATHER's run-dir read shape is
`under(run, SEG)` (`permission/policies/_common.read_shapes`, the builder those two share) and
`SEG` spells ONE path segment, so the shape admits every run-root file — the read tool and the
bash `cat` lane alike, since they share the shape OBJECT. `is_untrusted_read` does not fire on
the log either, so neither lane salt-framed the read: the bytes arrived as ordinary text.

The fix is one directory, not one clamp: the log moved to `<run_dir>/wire_logs/llm_requests.jsonl`,
one level down and therefore outside a single-segment shape, for MAIN and GATHER symmetrically
and with no shape edited. `test_the_subdirectory_is_what_denies` is the falsification — it plants
the same filename back at the run root and shows the gate admits it there, so these tests cannot
pass for some reason other than the one they name.

THE OFFLINE LANE IS THE SAME DEFECT AND NOT THE SAME FIX (the second class below). Every
learning stage logs through the same `RequestLogger` into the learning run dir, and that dir is
the gray-box ACTOR's own root — so `judge_trace.jsonl` at its root handed the actor the payload
exemplars `judge/compare.unredacted_exemplar` puts in the judge's prompt UNREDACTED, which is
exactly what `decide_read`'s `gather_raw` deny exists to keep from it. Both legs of an
`inconclusive` case run CONCURRENTLY against one `LegDirs`, and a re-LEARN reopens the dir with
the previous pass's traces still in it, so the actor is alive while those files exist.

A subdirectory alone does NOT close that one, which is why the deny is a component rule rather
than a shape: the ACTOR declares no read shape at all (root containment only admits every
depth) and the JUDGE's `cat` scope is `under(run, TREE)` (a subdirectory fullmatches). So
`wire_logs/` is denied OUTRIGHT by `files.names_wire_log_dir`, on both read surfaces, for every role —
and `test_the_component_is_what_denies_in_the_learning_lane` is that half's falsification.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from defender._run_paths import WIRE_LOG_DIR, WIRE_LOG, RunPaths  # noqa: E402
from defender.agents import ACTOR_DEF, GATHER_DEF, JUDGE_DEF, MAIN_DEF  # noqa: E402
from defender.runtime import observe, permission  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    RunScope,
    compile_policy_for,
    effective_tools_for,
)
from defender.scripts import workspace_map as wsm  # noqa: E402

READERS = ("main", "gather")


@pytest.fixture
def env(tmp_path):
    """A run dir carrying the wire log where a live run puts it, plus the run-root artifacts
    that are the positive controls — a deny that also denied `investigation.md` would prove
    nothing about the subdirectory."""
    run = tmp_path / "run"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    (run / "gather_summaries").mkdir()
    for rel in ("investigation.md", "report.md", "alert.json", "executed_queries.jsonl",
                "tool_trace.jsonl", "gather_summaries/l-001.md", "gather_raw/l-001/0.json"):
        (run / rel).write_text("{}\n", encoding="utf-8")
    dfn = tmp_path / "defender"
    (dfn / "lessons").mkdir(parents=True)
    (dfn / "lessons" / "x.md").write_text("x\n", encoding="utf-8")

    wire = observe.wire_log_path(run)
    wire.write_text('{"agent_id": "gather:l-001", "message": "secret payload bytes"}\n',
                    encoding="utf-8")
    return SimpleNamespace(
        run=run, dfn=dfn, wire=wire,
        main=compile_policy_for(MAIN_DEF, run_dir=run, defender_dir=dfn),
        gather=compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn),
    )


def _read(env, path, which):
    return permission.decide_read(
        Path(path), run_dir=env.run, defender_dir=env.dfn, policy=getattr(env, which)
    )


def _bash(env, cmd, which):
    return permission.decide_bash(
        cmd, policy=getattr(env, which), run_dir=env.run, defender_dir=env.dfn
    )


def test_the_wire_log_lives_one_level_below_the_run_root(tmp_path):
    """The location is the mechanism, so it is pinned as such: `<run>/wire_logs/` — a directory,
    not a run-root name. `wire_log_path` creates the dir (the driver opens the logger on it
    before anything else writes into the run), and agrees with the layout `_run_paths` declares
    for every reader."""
    run = tmp_path / "run"
    run.mkdir()
    path = observe.wire_log_path(run)

    assert path == run / WIRE_LOG_DIR / WIRE_LOG
    assert path == RunPaths(run).wire_log
    assert path.parent.is_dir(), "the driver would fail to open a log in a dir nobody created"
    assert path.parent != run, (
        "the wire log is back at the run root, where a single-segment read shape admits it"
    )


@pytest.mark.parametrize("which", READERS)
def test_the_read_tool_denies_the_wire_log(env, which):
    """MAIN and GATHER symmetrically. MAIN is the reported direction (gather's payload bytes
    reaching the main loop around `RAW_DENY_REASON`); GATHER is the mirror the same shape opened
    — an injected subagent reading MAIN's whole transcript back."""
    assert not _read(env, env.wire, which).allow


@pytest.mark.parametrize("which", READERS)
def test_the_bash_lane_denies_the_wire_log(env, which):
    """The `cat` lane too, and for the same reason rather than by a second rule: the shape tuple
    `decide_read` enforces IS the object the `cat` grant carries as its scope. `cat` was the
    wider half of the leak — the read tool caps a payload read at 8,192 bytes, `cat` at nothing."""
    assert not _bash(env, f"cat {env.wire}", which).allow


@pytest.mark.parametrize("which", READERS)
def test_run_root_artifacts_still_read(env, which):
    """The positive control. The subdirectory must move exactly one file out of scope: MAIN's
    own work log still reads, and so does the summary lane gather is supposed to answer through.
    A deny that swept these up would be a broken shape, not a closed hole."""
    assert _read(env, env.run / "investigation.md", which).allow
    assert _bash(env, f"cat {env.run}/investigation.md", which).allow
    assert _read(env, env.run / "gather_summaries" / "l-001.md", which).allow


@pytest.mark.parametrize("which", READERS)
def test_the_subdirectory_is_what_denies(env, which):
    """FALSIFICATION. Plant the same filename at the run ROOT: the gate ALLOWS it there, for both
    readers, on both lanes. So the deny above is the directory doing the work and not a filename
    the gate happens to know — which is also the standing warning to anyone moving this log back
    up, or adding a second stream that carries wire bodies verbatim beside it."""
    planted = env.run / WIRE_LOG
    planted.write_text("{}\n", encoding="utf-8")

    assert _read(env, planted, which).allow
    assert _bash(env, f"cat {planted}", which).allow


def _run_dir_section(out: str) -> str:
    """Just the map's `## Run dir` listing.

    Asserted on rather than the whole document because the rest of the map is generated from
    the REAL `workspace_map.DEFENDER_DIR` — the skills dirs, the adapter filenames, the query
    systems — and a bare substring test over that would turn red the day someone adds a skill
    whose name happens to contain `wire_logs`, for a reason that has nothing to do with the
    suppression this test is about."""
    body = out.split("## Run dir", 1)[1]
    return body.split("\n## ", 1)[0]


def test_the_workspace_map_does_not_name_the_observe_dir(env):
    """The map is inlined into MAIN's message 0 as "the canonical surfaces", and MAIN has no
    `ls` — so the map is its whole directory view. Naming a dir the gate then refuses only
    teaches the model to ask for it; `gather_raw/` is suppressed on the same ground (#264)."""
    listing = _run_dir_section(wsm.workspace_map(env.run).replace(str(env.run), "RUNDIR"))

    assert WIRE_LOG_DIR not in listing
    assert WIRE_LOG not in listing
    assert "investigation.md" in listing, "the run-dir listing stopped listing anything at all"


# the offline lane: same stream class, same component, a DIFFERENT mechanism

LEARNING_READERS = ("actor", "judge")


@pytest.fixture
def lenv(tmp_path):
    """A learning run dir with the two stage traces where `run_stage` puts them, the staged
    `gather_raw/` tree beside them, and the actor's own artifacts as positive controls.

    `stage_trace_path` is used rather than a hand-joined path for the reason the production
    call site uses it: the location is the thing under test, so a test that spelled it itself
    would keep passing after the writer moved."""
    lrd = tmp_path / "learning-run"
    (lrd / "gather_raw" / "l-001").mkdir(parents=True)
    (lrd / "gather_raw" / "l-001" / "0.json").write_text('{"user": "root"}\n', encoding="utf-8")
    (lrd / "actor_story.md").write_text("the story\n", encoding="utf-8")
    (lrd / "actor_input.yaml").write_text("leads: []\n", encoding="utf-8")
    dfn = tmp_path / "defender"
    (dfn / "lessons-actor").mkdir(parents=True)
    (dfn / "lessons-actor" / "a.md").write_text("x\n", encoding="utf-8")

    traces = {}
    for name in ("judge_trace.jsonl", "oracle_actor_story_l-001.trace.jsonl",
                 "actor_trace.jsonl"):
        p = observe.stage_trace_path(lrd, name)
        p.write_text('{"message": "unredacted payload exemplar"}\n', encoding="utf-8")
        traces[name] = p

    return SimpleNamespace(
        run=lrd, dfn=dfn, traces=traces,
        actor=compile_policy_for(
            ACTOR_DEF, run_dir=lrd, defender_dir=dfn,
            scope=RunScope(scripts=(), read_confine=(dfn / "lessons-actor",)),
        ),
        judge=compile_policy_for(
            JUDGE_DEF, lrd, scope=RunScope(add_dirs=()), defender_dir=dfn,
            tools=effective_tools_for(JUDGE_DEF),
        ),
    )


def test_a_learning_stage_trace_lands_under_observe(lenv):
    """One component for both lanes. `files.names_wire_log_dir` is a single path-component test, so
    a stage trace written anywhere else is a stream the deny cannot see — which is the whole
    reason the offline writer goes through `stage_trace_path` rather than joining a name."""
    for name, path in lenv.traces.items():
        assert path == lenv.run / WIRE_LOG_DIR / name
        assert path.parent.is_dir()


def test_the_gray_box_actor_cannot_read_the_judge_s_trace(lenv):
    """The reported crossing, in the lane it actually lives in.

    The actor must write its story WITHOUT the payloads; `decide_read`'s `gather_raw` branch is
    what enforces that, and the assertion below it is the positive control proving that branch
    is still doing its job here. The judge's prompt carries those same payloads UNREDACTED
    (`compare.unredacted_exemplar`), so its trace at the learning run dir's root was the same
    bytes by another name — and the actor's `read_allow` is EMPTY, so no shape filter ever ran."""
    assert not _read(lenv, lenv.traces["judge_trace.jsonl"], "actor").allow
    assert not _read(lenv, lenv.traces["oracle_actor_story_l-001.trace.jsonl"], "actor").allow
    assert not _read(lenv, lenv.run / "gather_raw" / "l-001" / "0.json", "actor").allow
    assert lenv.actor.read_allow == (), (
        "the actor grew a read shape — this test's premise (no shape filter runs for it) is "
        "the reason its deny has to come from the component rule and not from enumeration"
    )


@pytest.mark.parametrize("which", LEARNING_READERS)
def test_no_learning_role_reads_a_trace(lenv, which):
    """Denied OUTRIGHT on the read tool, unlike `gather_raw` — no role may opt in by declaring
    a shape. Both roles, and `test_the_component_is_what_denies_in_the_learning_lane` below is
    the falsification for both."""
    assert not _read(lenv, lenv.traces["judge_trace.jsonl"], which).allow


def test_the_bash_lane_denies_a_trace_for_the_judge(lenv):
    """The `cat` lane, asserted for the JUDGE and ONLY the judge — because it is the only
    learning role where the assertion measures anything.

    The judge is where a subdirectory could never have excluded the file: its `cat` scope is
    `under(run, TREE)`, which fullmatches at any depth, so here the deny is carried by
    `files.names_wire_log_dir` alone — and the run-root control beneath it is what shows the `cat`
    itself is otherwise well-formed and claimable. The ACTOR is deliberately NOT parametrized
    in: it holds ZERO bash grants, so every command it names is refused by the fallthrough
    before an operand is ever resolved, and a `cat` deny for it would stay green with
    `names_wire_log_dir` deleted. That vacuity is pinned rather than papered over — the last
    assertion fails the day the actor grows a grant, which is the day the case belongs here
    with a falsification of its own."""
    trace = lenv.traces["judge_trace.jsonl"]
    assert not _bash(lenv, f"cat {trace}", "judge").allow
    assert _bash(lenv, f"cat {lenv.run / 'actor_story.md'}", "judge").allow, (
        "positive control: a run-root artifact the judge may read must still `cat`, or the "
        "deny above proves nothing about the component"
    )
    assert lenv.actor.bash_allow == (), (
        "the actor grew a bash grant — its `cat` deny is no longer vacuous, so it belongs in "
        "a parametrized case with a falsification of its own"
    )


def test_the_deny_is_scoped_to_observe_and_nothing_else(lenv):
    """The positive control for the whole class. `wire_logs/` must be the only thing that moved:
    the judge still reads the payloads it is supposed to judge, and the actor still reads its
    own inputs. A deny that swept these up would be a blanket, not a boundary."""
    assert _read(lenv, lenv.run / "gather_raw" / "l-001" / "0.json", "judge").allow
    assert _read(lenv, lenv.run / "actor_story.md", "actor").allow
    assert _read(lenv, lenv.run / "actor_input.yaml", "actor").allow


@pytest.mark.parametrize("which", LEARNING_READERS)
def test_the_component_is_what_denies_in_the_learning_lane(lenv, which):
    """FALSIFICATION, the offline half. The same trace name at the learning run dir ROOT is
    ALLOWED for both roles — which is the pre-fix behaviour, stated as a test so the denies
    above cannot be passing for some unrelated reason, and so the claim "a subdirectory would
    not have been enough here" is measured rather than asserted in a comment."""
    planted = lenv.run / "judge_trace.jsonl"
    planted.write_text("{}\n", encoding="utf-8")

    assert _read(lenv, planted, which).allow


def test_names_wire_log_dir_is_a_component_test_not_a_substring(tmp_path):
    """The discipline `_names_raw` states, held for the new marker too: the test is over path
    PARTS. A substring scan is decided by text the path's owner does not control — a checkout
    under `~/observe-notes/`, a pytest tmp dir named `test_observe_0` — and would deny reads
    across an unrelated tree while a file honestly named `observed.jsonl` slipped through."""
    assert permission.names_wire_log_dir(tmp_path / WIRE_LOG_DIR / "x.jsonl")
    assert permission.names_wire_log_dir(tmp_path / WIRE_LOG_DIR / "deep" / "x.jsonl")
    assert not permission.names_wire_log_dir(tmp_path / "observed" / "x.jsonl")
    assert not permission.names_wire_log_dir(tmp_path / "my-observe-notes" / "x.jsonl")
    assert not permission.names_wire_log_dir(tmp_path / "observe.jsonl")
