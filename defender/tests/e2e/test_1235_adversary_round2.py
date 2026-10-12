"""#1235 round 2 — the holes the second adversary pass found in the round-2 suite.

Each test greens on an honest round-2 implementation and goes red under one cheating
implementation the rest of the suite let through (named in its docstring as "Exploit"): the
correlation lead on a second state, a folder-keyed fallback, a parse-gated legacy refusal,
lead-0's capped call without the state, the store-setup exit without it, a breaker charge
outside the lock. The release obligation's own hole (R4) was fixed in place.

Round 3 moved two of them to the review's fix list: an enforced role with no state now RAISES
(O2), and the state no longer rides the summary — it is injected, and `drive()` hands it back
(O6).
"""
from __future__ import annotations

import contextlib
import json
import sys
import threading
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.hooks import budget_enforcer as be  # noqa: E402
from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import branch, circuit_breaker, session_store  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.scripts.adapters.faults import TransportFault  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    CORRELATION_SUMMARY,
    L3,
    answer_hits,
    answer_raising,
    run,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    drive,
    materialize,
)
from defender.tests.e2e.test_1235_queries_and_pointer import (  # noqa: E402
    OLD_POINTER_NAME,
    _finished_run,
    _pointer,
)
from defender.tests.e2e.test_808_correlation_lead import TWO_ACTORS  # noqa: E402
from defender.tests.test_budget_seams_631 import _run_dir, drive_agent  # noqa: E402

pytestmark = pytest.mark.e2e

LEAD = "l-001"


# ======================================================================================
# the correlation lead (item 3, l-00c) is a gather lead of THIS run: its calls ride the
# run's one RunState, by reference.
# ======================================================================================

def test_the_correlation_leads_calls_ride_the_runs_one_state(tmp_path):
    """Brief: "Gather deps get the parent's object ... Lead-0's capture deps get it too"; pin:
    "Gather deps carry the parent's object BY REFERENCE". Item 3's lead is dispatched by the
    harness (`dispatch_correlation`), not by MAIN's `gather` tool, so `_run_gather`'s
    `run_state=deps.run_state` is not the line that carries it — the driver's call is.

    The correlation lead's two `alerts` calls are counted in the run's ONE pool (a difference
    against the same run whose correlation lead makes no call), its verb contexts carry the very
    object `drive()` returns, and the run's state holds its rows.

    Exploit (greens the committed suite): `dispatch_correlation(..., run_state=RunState(
    run_dir, run_id))` — a second state for item 3. Its calls never reach the run's pool or the
    run's breaker (an elastic outage l-00c sees does not trip elastic for MAIN's leads, and
    RUN_FAIL_KILL_LIMIT is split across two counters), and its clock starts late."""
    corr = [Turn(tool_calls=[("query", {
        "system": "elastic", "verb": "alerts",
        "params": {"native_query": f'user.name:"dev.dana" AND k1:{i}'}})]) for i in range(2)]
    busy = run(tmp_path / "busy", run_id="k1-busy", answer=answer_hits(TWO_ACTORS),
               gather_turns=[*corr, Turn(text=CORRELATION_SUMMARY)])
    idle = run(tmp_path / "idle", run_id="k1-idle", answer=answer_hits(TWO_ACTORS))

    mine = [c for c in busy.rec.calls if "k1:" in str(c.params.get("native_query"))]
    assert len(mine) == 2, "positive control: the correlation lead's calls never ran"
    assert len(busy.rows_for(L3)) == 2, "positive control: the correlation lead wrote no rows"
    assert idle.has_sidecar(L3), "the control run did not dispatch item 3 either"
    assert all(c.ctx.run_state is busy.state for c in mine), (
        "the correlation lead's verb context carried a state other than the run's")
    assert list(busy.state.lead_rows(L3)) == busy.rows_for(L3), (
        "the run's state does not hold the correlation lead's rows")
    delta = busy.budget["tool_calls"] - idle.budget["tool_calls"]
    assert delta == 2, f"the correlation lead's two calls moved the run's pool by {delta}"


# ======================================================================================
# an enforced role whose deps carry no state raises — it never reaches a live run's state.
# ======================================================================================

def test_a_deps_with_no_state_raises_and_never_reaches_a_live_runs_state(tmp_path):
    """Round 3 (O2, the review's finding 2): an enforced role (MAIN, here) whose deps carry no
    run state raises `TypeError` at its first tool call — round 2 let it through, counting and
    refusing nothing, which ran an enforced role with no budget at all. A run's state is live
    and AT its cap for the very folder the hand-bound deps name: the raise neither counts on it
    nor is answered from it.

    Positive control, same folder and script: carried, the same call is refused at that cap.

    Exploit it still catches: `RunState(...)` registers each state in a module table keyed by
    `os.path.abspath(run_dir)` (strong references, never removed), and the budget hooks fall
    back to it when `deps.run_state is None` — round 1's folder-keyed table kept as a fallback:
    the call is then refused (or counted) instead of raising."""
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1, "wall_clock_timeout": 3600,
              "grace_seconds": 600}
    run_dir = _run_dir(tmp_path, "k2")
    live = RunState(run_dir, "k2-live")
    be.account_call(live, "bash", limits=limits, tier="core")
    assert live.budget_snapshot()["tool_calls"] == 1
    script = [[("bash", {"command": "echo k2"})]]

    with pytest.raises(TypeError, match="RunState"):
        drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True, state=None)
    assert live.budget_snapshot()["tool_calls"] == 1, (
        "a deps carrying no state counted its call into the live run's state")

    carried, _ = drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True, state=live)
    assert "BUDGET" in str(carried.all_messages()).upper(), (
        "the control: carried, a call on a state at its cap was not refused")


# ======================================================================================
# a run recorded before #1235 refuses on the old file's PRESENCE, whatever its bytes.
# ======================================================================================

def _plant_old_link(tmp_path: Path, run_dir: Path, variant: str) -> tuple[dict, Path]:
    """Make `run_dir` a pre-#1235 run whose in-folder link is `variant`; returns the link the
    run really had and the old file's path."""
    link = _pointer(run_dir)
    RunPaths(run_dir).session_pointer().unlink()
    old = run_dir / OLD_POINTER_NAME
    if variant == "empty":
        old.write_text("", encoding="utf-8")
    elif variant == "truncated":
        old.write_text(json.dumps(link)[:20], encoding="utf-8")
    elif variant == "no-store-path":
        old.write_text(json.dumps({"case_id": link["case_id"]}), encoding="utf-8")
    else:
        old.symlink_to(tmp_path / "nowhere.json")
    return link, old


def _assert_refused_everywhere(run_dir: Path, link: dict, old: Path) -> None:
    def says_rerun(err: BaseException) -> None:
        assert run_dir.name in str(err)
        assert "re-run" in str(err)
        assert "1235" in str(err)

    store = session_store.open_store_for_read(Path(link["store_path"]))
    try:
        for read in (session_store.resolve_store_path, session_store.resolve_session_id):
            with pytest.raises(session_store.LegacyRunLink) as err:
                read(run_dir)
            says_rerun(err.value)
        for open_store in (branch.open_source_store, branch.source_store_if_any):
            with pytest.raises(branch.BranchError) as err:
                open_store(run_dir)
            says_rerun(err.value)
        with pytest.raises(session_store.LegacyRunLink) as err:
            branch.session_for_run(store, run_dir)
        says_rerun(err.value)

        old.unlink()
        assert branch.source_store_if_any(run_dir) is None, "control: no old file is no session"
    finally:
        store.connection.close()


@pytest.mark.parametrize("variant", ["empty", "truncated", "no-store-path"])
def test_an_old_in_folder_link_refuses_whatever_its_bytes(tmp_path, variant):
    """Brief: "If a run folder still holds `session_store_pointer.json` (the old in-folder link)
    and there is no sidecar, every link reader raises one clear error ... It never reads as 'no
    session'." R5 plants only a well-formed old link. An old link file that is empty, truncated,
    or missing `store_path` is still that file: each of the four readers (and
    `session_for_run`) refuses it with the re-run message.

    Positive control, same folder: with the old file gone it reads as "no session".

    Exploit (greens the committed suite): refuse only when the old file parses as a JSON object
    naming `store_path`; anything else at that name reads as "no session"."""
    run_dir = _finished_run(tmp_path / "a", f"k4-{variant}")
    link, old = _plant_old_link(tmp_path, run_dir, variant)
    _assert_refused_everywhere(run_dir, link, old)


def test_a_dangling_link_at_the_old_name_refuses_too(tmp_path):
    """A link to nothing at `session_store_pointer.json` (no sidecar) — the box can plant one,
    the run folder being its rw bind. "Still holds the file" is read as `os.path.lexists`:
    anything at the old name refuses (fail closed), never reads as "no session".

    Exploit it would catch: the parse-gated refusal of `test_k4_...` above, and an
    `is_file()`-gated one."""
    run_dir = _finished_run(tmp_path / "a", "k4-dangling")
    link, old = _plant_old_link(tmp_path, run_dir, "dangling-link")
    _assert_refused_everywhere(run_dir, link, old)


# ======================================================================================
# lead-0's capped call carries the run's state on its verb context.
# ======================================================================================

def test_lead_zeros_capped_call_carries_the_runs_state(tmp_path):
    """Brief: "`VerbContext.run_state` ... set wherever a VerbContext is built (`query_tool.py
    ~927`, `lead_zero/_capture.py ~102, ~200`)"; pin: "query_tool and lead-0's capture set it to
    the run's state". `_capture.py ~200` is `_CallLedger.call`'s CAPPED path (after item 1's
    one recorded elastic failure, calls bypass `QueryCapture`), the one site no test reaches
    with a context check. Arm A of `test_item_one_stops_at_one_recorded_per_system_failure`:
    the shell fetch fails (recorded, the ledger caps), the ancestor `query` then runs capped.

    Positive control, same run: the first (uncapped) call's context carries the state.

    Exploit (greens the committed suite): build the capped path's `VerbContext` without
    `run_state=` — a world registry serving that call pauses no investigator clock."""
    down = TransportFault("docker exec failed")
    res = run(tmp_path, run_id="k5-capped", shell=down, answer=answer_raising(down))
    assert [c.verb for c in res.rec.calls] == ["alerts", "query"], (
        "the scenario no longer reaches lead-0's capped path")
    assert res.rec.calls[0].ctx.run_state is res.state, (
        "control: the uncapped call's context does not carry the run's state")
    assert res.rec.calls[1].ctx.run_state is res.state, (
        "lead-0's capped call's verb context does not carry the run's state")


# ======================================================================================
# the store-setup failure exit runs on the state drive injected.
# ======================================================================================

def test_the_store_setup_failure_exit_runs_on_the_injected_state(tmp_path):
    """Round 3 (O6): production's summary carries no state on any exit; the state is injected
    (`run_investigation(run_state=…)`) and the harness hands back the one it injected. On the
    store-setup failure exit — the `_run_summary` site no turn reaches — `drive()` returns that
    very object, and the run's id is its own.

    Exploit it catches: the store-setup exit building a state of its own (`RunState(run_dir,
    run_id)` again) instead of resolving the injected one once at the boundary; the summary's
    absence of the key on this exit is `test_1235_round3_e2e`'s."""
    def no_store(case_id: str, run_dir: Path):  # noqa: ARG001
        raise OSError("k6: no store")

    run_dir = materialize(tmp_path, GOLDEN_AB3)
    mine = RunState(run_dir, "k6-store-fault")
    summary = drive(run_dir, run_id="k6-store-fault",
                    main=ReplayFn([Turn(text="Investigation complete.")]), store_factory=no_store,
                    run_state=mine)
    assert summary["truncated_by"] == session_store.TRUNCATED_BY_STORE, summary
    assert summary["run_state"] is mine, "drive did not hand back the state it injected"
    assert mine.run_id == "k6-store-fault"


# ======================================================================================
# a breaker charge is one read-modify-write under the state's lock.
# ======================================================================================

def test_concurrent_breaker_charges_lose_no_failure(tmp_path):
    """Brief: "One lock inside the object serialises every read-modify-write: the cap check plus
    increment, a row append, a breaker charge." The budget (adversary X7c) and the row append
    (`test_concurrent_appends_...`) have preemption tests; the breaker has none. Sixteen threads
    charging under fine-grained preemption lose no failure, in any of eight trials.

    Exploit (greens the committed suite): `record_outcome` mutates `state.breaker` outside
    `state.lock` — under preemption `failures += 1` / `total_failures += 1` lose charges (this
    test caught it 4 runs of 4; the honest lock passes it every time, ~9s)."""
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    per, workers = 2000, 16
    try:
        for trial in range(8):
            state = RunState(tmp_path, f"k7-{trial}")

            def work(w: int, state: RunState = state) -> None:
                for _ in range(per):
                    with contextlib.suppress(circuit_breaker.RunAborted):
                        circuit_breaker.record_outcome(state, f"sys{w % 2}", 2)

            threads = [threading.Thread(target=work, args=(w,)) for w in range(workers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            snap = state.breaker_snapshot()
            assert snap["total_failures"] == per * workers, f"trial {trial} lost a charge"
            assert sum(s["failures"] for s in snap["systems"].values()) == per * workers
    finally:
        sys.setswitchinterval(old)
