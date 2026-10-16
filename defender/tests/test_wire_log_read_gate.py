"""The run's wire log (wire_logs/llm_requests.jsonl, holding raw gather payloads and MAIN's transcript) is unreadable by the agents that write into it: it sits one directory below the run root, outside MAIN's and GATHER's single-segment read shape, for the read tool and the bash cat lane alike, and no learning role can read a stage trace."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from defender.agents import CORPUS_AUTHOR_DEF, MAIN_DEF  # noqa: E402
from defender.tests import _tenants1106  # noqa: E402
from defender.run_repository import WIRE_LOG_DIR, WIRE_LOG, RunPaths  # noqa: E402
from defender.runtime import observe, permission  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    RunScope,
    compile_policy_for,
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
        gather=compile_policy_for(
            _tenants1106.fixture_gather_def(), run_dir=run, defender_dir=dfn),
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
    before anything else writes into the run), and agrees with the layout `run_repository._layout` declares
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
    """Just the map's `## Run dir` listing."""
    body = out.split("## Run dir", 1)[1]
    return body.split("\n## ", 1)[0]


def test_the_workspace_map_does_not_name_the_observe_dir(env):
    """The map is inlined into MAIN's message 0 as "the canonical surfaces", and MAIN has no
    `ls` — so the map is its whole directory view. Naming a dir the gate then refuses only
    teaches the model to ask for it; `gather_raw/` is suppressed on the same ground (#264)."""
    listing = _run_dir_section(wsm.workspace_map(env.run, systems=()).replace(str(env.run), "RUNDIR"))

    assert WIRE_LOG_DIR not in listing
    assert WIRE_LOG not in listing
    assert "investigation.md" in listing, "the run-dir listing stopped listing anything at all"


# the offline lane: same stream class, same component, a DIFFERENT mechanism

@pytest.fixture
def lenv(tmp_path):
    """A learning run dir with a stage trace where `run_stage` puts it, a staged `gather_raw/`
    tree beside it, and a bound learning role to ask the gate about."""
    lrd = tmp_path / "learning-run"
    (lrd / "gather_raw" / "l-001").mkdir(parents=True)
    (lrd / "gather_raw" / "l-001" / "0.json").write_text('{"user": "root"}\n', encoding="utf-8")
    dfn = tmp_path / "defender"
    corpus = dfn / "lessons"
    corpus.mkdir(parents=True)
    (corpus / "a.md").write_text("x\n", encoding="utf-8")

    traces = {}
    for name in ("judge_trace.jsonl", "questioner_trace.jsonl"):
        p = observe.stage_trace_path(lrd, name)
        p.write_text('{"message": "unredacted payload exemplar"}\n', encoding="utf-8")
        traces[name] = p

    return SimpleNamespace(
        run=lrd, dfn=dfn, traces=traces,
        curator=compile_policy_for(
            CORPUS_AUTHOR_DEF, run_dir=lrd, defender_dir=dfn,
            scope=RunScope(corpus_name="lessons", read_confine=(corpus,)),
        ),
    )


#: TWO LEARNING-LANE DEMANDS LEFT WITH #922, recorded because their absence weakens this file.
LEARNING_READERS = ("curator",)




def test_a_learning_stage_trace_lands_under_observe(lenv):
    """One component for both lanes. `files.names_wire_log_dir` is a single path-component test, so
    a stage trace written anywhere else is a stream the deny cannot see — which is the whole
    reason the offline writer goes through `stage_trace_path` rather than joining a name."""
    for name, path in lenv.traces.items():
        assert path == lenv.run / WIRE_LOG_DIR / name
        assert path.parent.is_dir()


def test_a_learning_role_cannot_read_a_stage_trace_or_the_staged_payloads(lenv):
    """The reported crossing, in the lane it actually lives in."""
    assert not _read(lenv, lenv.traces["judge_trace.jsonl"], "curator").allow
    assert not _read(lenv, lenv.traces["questioner_trace.jsonl"], "curator").allow
    assert not _read(lenv, lenv.run / "gather_raw" / "l-001" / "0.json", "curator").allow
    assert lenv.curator.read_allow == (), (
        "the actor grew a read shape — this test's premise (no shape filter runs for it) is "
        "the reason its deny has to come from the component rule and not from enumeration"
    )


@pytest.mark.parametrize("which", LEARNING_READERS)
def test_no_learning_role_reads_a_trace(lenv, which):
    """Denied OUTRIGHT on the read tool, unlike `gather_raw` — no role may opt in by declaring
    a shape. Both roles, and `test_the_component_is_what_denies_in_the_learning_lane` below is
    the falsification for both."""
    assert not _read(lenv, lenv.traces["judge_trace.jsonl"], which).allow






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
