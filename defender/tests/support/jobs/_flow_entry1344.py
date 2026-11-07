"""#1344 e2e children, started by the real worker: `python _flow_entry1344.py <mode> <commit> <marks> <args...>`.

- `investigate`: the real job entry (`run.job_main`) over the replay driver. MAIN writes a document, dispatches one
  lead (`gather`) whose query reaches a stand-in elastic, writes the rest and closes: a completed run whose one
  `gather` response is a legal fork point.
- `investigate-no-gather`: the same run with no `gather`, so no fork point exists.
- `family`: the real learning job entry (`job_entry.main`), every paid model a script and the siblings real
  `run.main` processes' in-process equivalent (`_1255_twin.run_main`), continuing MAIN's script after the fork.
  Args: `--job <id> --tenant <T> --source <investigation id> --parent-pid <pid>`.
- `post-step`: the real post-step with a recording drain gate (`<marks>/gate`, holding the queue's size when it ran)."""
from __future__ import annotations

import functools
import os
import sys
from pathlib import Path

# A bare script: the checkout root comes from this file's location, never from the parent's environment.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from defender.tests.e2e import _replay_harness as RH
from defender.tests.e2e._lead_zero_808 import VerbRecorder, answer_hits, elastic_backend, hit
from defender.tests.support.runtime.state import _1255_snapshot as R

mode, commit, marks, argv = sys.argv[1], sys.argv[2], Path(sys.argv[3]), sys.argv[4:]
marks.mkdir(parents=True, exist_ok=True)

LEAD = "l-001"
QUERY = RH.Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                       "params": {"native_query": "user.name:dev.dana"}})])
DOCS = [hit(ts="2026-05-25T15:20:00.000Z")]
DISPOSITION = "malicious"


def main_script(*, gathers: bool = True) -> list:
    """append, dispatch (the only `gather`; `gathers=False`: none), the rest of the document, close."""
    first, second, third = R.chunks(3)
    return [R.append(first), *([R.dispatch(LEAD)] if gathers else []), R.append(second), R.append(third),
            R.close(DISPOSITION), RH.Turn(text="Investigation complete.")]


def after_the_gather() -> list:
    """What a sibling's MAIN says once it has resumed at the `gather` response."""
    return main_script()[2:]


def _unboxed(*_a, start_token=None, **_k):
    from defender import box as box_mod

    return box_mod.unboxed_executor()


def investigate(*, gathers: bool = True) -> int:
    from defender import run as run_py

    gather = R.LeadRouter({R.CORRELATION_LEAD: R.CORRELATION_TURNS, LEAD: (QUERY, RH.Turn(text=f"summary of {LEAD}"))})
    inner = RH.investigate_as_handed(RH.ReplayFn(main_script(gathers=gathers)), gather)

    def investigate_with_a_system(**handed):
        return inner(**{**handed, "verbs": elastic_backend(VerbRecorder(), answer_hits(DOCS))})

    drive = functools.partial(run_py._drive_investigation, investigate=investigate_with_a_system)
    lifecycle = functools.partial(run_py._run_investigation_lifecycle, investigate=drive, start_box=_unboxed)
    return run_py.job_main(argv, lifecycle=lifecycle, preflight=lambda *a, **k: 0, visualize=lambda *a, **k: None,
                           publish=lambda *a, **k: f"fresh {commit}")


def family() -> int:
    from defender.learning.branch import job_entry
    from defender.tests.e2e import _1255_twin as TWIN
    from defender.tests.learning.branch.test_947_triplet_launcher import _BASE
    from defender.tests.learning.oracle.live_contracts import _spec1224 as S
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.support.learning.judge import _judge_921 as J

    tenant = argv[argv.index("--tenant") + 1]
    runs = Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "runs"
    estate = S.estate(marks / "estate")

    def sibling(sibling_argv, *, env=None, **_kw) -> int:
        """A real sibling's `run.py --tenant T --episode E --world W`, in this process, MAIN continuing the script."""
        recording = TWIN.Recording(sibling_argv[sibling_argv.index("--world") + 1])
        TWIN.run_main(sibling_argv[2:], recording, main_turns=after_the_gather(),
                      clock=TWIN.SteppingClock(TWIN.ARM_CLOCK_START))
        (marks / f"sibling-{recording.label}").write_text(str(recording.exit_code), encoding="utf-8")
        return recording.exit_code if isinstance(recording.exit_code, int) else 1

    finding = J.finding_doc(bucket="lead-quality", subject="defender", topic="the lead was never revisited")
    world = J.reply_doc(findings=[finding])
    world.update(bucket="lead-quality", systems=["idp"])
    judge = J.scripted_judge(default=S.as_reply_text(world), family_default=S.as_reply_text(J.family_reply()))
    seams = dict(questioner=S.questioner_for(), preflight=S.no_preflight, live_tree=T.source_capture(),
                 roster=estate.roster(), judge=judge, oracle=S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM)).model,
                 verifier=S.passing_verifier().model, directory=T.launcher_directory(tenant), spawn=sibling)
    (marks / "runs").write_text(str(runs), encoding="utf-8")
    if os.environ.get("FLOW_DAMAGE") == "store-version":
        _store_from_a_newer_format(runs, argv[argv.index("--source") + 1])
    try:
        job_entry.main(argv, **seams)
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else 1
    return 0


def _store_from_a_newer_format(runs: Path, investigation: str) -> None:
    """The source's session database as a store of another format version would leave it (L5)."""
    import json
    import sqlite3

    from defender.tests.support.jobs._jobs1342 import session_db

    case = json.loads((runs / f"{investigation}.session-pointer.json").read_text(encoding="utf-8"))["case_id"]
    path = session_db(runs, case)
    assert path.is_file(), f"premise: the run's session database is at {path}"
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("PRAGMA user_version = 99")


def post_step() -> int:
    from defender.learning.branch import post_step as step
    from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
    from defender.tests.support.learning.core._state1135 import state_over

    tenant = argv[argv.index("--tenant") + 1]

    def gate(*_a, **_k) -> int:
        state = state_over(Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "learning")
        (marks / "gate").write_text(str(len(state.rows(FINDINGS)) + len(state.rows(QUESTIONER_FINDINGS))),
                                    encoding="utf-8")
        return 0

    try:
        step.main(argv, author_tick=gate)
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else 1
    return 0


sys.exit({"investigate": investigate, "investigate-no-gather": functools.partial(investigate, gathers=False),
          "family": family, "post-step": post_step}[mode]())
