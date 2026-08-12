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

MAIN and GATHER are the whole roster here, and deliberately: they are the two roles that read
THIS run dir. The judge and the actor read the learning run dir, which the wire log never
reaches, and neither would be covered by a subdirectory anyway — the judge's scope is
`under(run, TREE)` and the actor declares no shape at all. `_run_paths.OBSERVE_DIR` records
that limit so the containment argument is not borrowed for a stream it does not cover.

The fix is one directory, not one clamp: the log moved to `<run_dir>/observe/llm_requests.jsonl`,
one level down and therefore outside a single-segment shape, for MAIN and GATHER symmetrically
and with no shape edited. `test_the_subdirectory_is_what_denies` is the falsification — it plants
the same filename back at the run root and shows the gate admits it there, so these tests cannot
pass for some reason other than the one they name.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from defender._run_paths import OBSERVE_DIR, WIRE_LOG, RunPaths  # noqa: E402
from defender.agents import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime import observe, permission  # noqa: E402
from defender.runtime.agent_definition import compile_policy_for  # noqa: E402
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
    """The location is the mechanism, so it is pinned as such: `<run>/observe/` — a directory,
    not a run-root name. `wire_log_path` creates the dir (the driver opens the logger on it
    before anything else writes into the run), and agrees with the layout `_run_paths` declares
    for every reader."""
    run = tmp_path / "run"
    run.mkdir()
    path = observe.wire_log_path(run)

    assert path == run / OBSERVE_DIR / WIRE_LOG
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
    whose name happens to contain `observe`, for a reason that has nothing to do with the
    suppression this test is about."""
    body = out.split("## Run dir", 1)[1]
    return body.split("\n## ", 1)[0]


def test_the_workspace_map_does_not_name_the_observe_dir(env):
    """The map is inlined into MAIN's message 0 as "the canonical surfaces", and MAIN has no
    `ls` — so the map is its whole directory view. Naming a dir the gate then refuses only
    teaches the model to ask for it; `gather_raw/` is suppressed on the same ground (#264)."""
    listing = _run_dir_section(wsm.workspace_map(env.run).replace(str(env.run), "RUNDIR"))

    assert OBSERVE_DIR not in listing
    assert WIRE_LOG not in listing
    assert "investigation.md" in listing, "the run-dir listing stopped listing anything at all"
