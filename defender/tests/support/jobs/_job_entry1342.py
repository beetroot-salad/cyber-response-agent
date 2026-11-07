"""#1342 test entry for the job lane: `python _job_entry1342.py <mode> <commit> <marks> --job <id> --tenant <T> --parent-pid <pid>`.

Calls the real job entry (`run.job_main`) with seams and an unboxed executor handed through the
lifecycle's `start_box` seam (never `DEFENDER_ALLOW_UNSANDBOXED`). Marks go in `<marks>/`.

- `replay` (O16): the real driver over a replay model that writes the golden investigation and
  closes with the golden's disposition.
- `replay-fault-after-close`: the same, but the replay model's request after the close tool committed
  raises `KeyboardInterrupt` (the one exception every broad handler passes through), so the real
  driver raises after the close; it marks `fault-raised` first.
- `hold` (death tie): the investigation blocks in the main thread; `hold-committed` is the same after
  closing the report on the facts holder it is handed (r5 C2). Marks: `pid`, `in-lifecycle`,
  `start-token` (the token the box start was handed), `interrupted` (the exception type that reached the investigation), `stop-box-started`, then
  `stop-box-done` once `go-on` exists (a later signal during teardown would stop the wait).
- `replay-priced` (#1377): MAIN, one gather lead and the live review stages as priced stand-ins;
  `replay-priced-ledger-fault` also refuses ledger inserts during the review; a mode ending `-raises` then raises out of the investigation, so the driver never returns its summary. Both configure logging as run.py's `__main__` does. Marks: `calls-<model>`."""
from __future__ import annotations

import functools
import os
import sys
import time
from pathlib import Path

# The child is a bare script: put the checkout root (the parent of `defender/`) on the path from
# this file's own location, so it never relies on the parent's PYTHONPATH or an installed package.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from defender import box as box_mod
from defender import run as run_py
from defender.tests.e2e import _replay_harness as RH

GOLDEN = Path(RH.__file__).resolve().parents[1] / "fixtures" / "e2e" / "golden-v2sshd"

mode, commit, marks, argv = sys.argv[1], sys.argv[2], Path(sys.argv[3]), sys.argv[4:]
marks.mkdir(parents=True, exist_ok=True)
(marks / "pid").write_text(str(os.getpid()), encoding="utf-8")


def _unboxed(*_a, start_token=None, **_k):
    """The box start of these children; the token the job entry handed it (r5 C1) goes in a mark."""
    if start_token is not None:
        (marks / "start-token").write_text(start_token, encoding="utf-8")
    return box_mod.unboxed_executor()


class _FaultsAfterClose(RH.ReplayFn):
    """The replay model whose request after the scripted turns (the close was the last) raises
    `KeyboardInterrupt`, which no broad handler in the driver swallows, after marking it."""

    __name__ = "FaultsAfterClose"

    def __call__(self, messages, info):
        if self.calls >= len(self._turns):
            (marks / "fault-raised").touch()
            raise KeyboardInterrupt
        return super().__call__(messages, info)


def _replay_lifecycle(*, fault_after_close: bool = False):
    from defender.records.formats import parse_report_text

    disposition = parse_report_text((GOLDEN / "report.md").read_text(encoding="utf-8")).disposition
    turns = [
        RH.Turn(tool_calls=[("append_block", {"text": (GOLDEN / "investigation.md").read_text(encoding="utf-8")})]),
        RH.Turn(tool_calls=[("close_investigation", {"disposition": disposition})]),
    ]
    # The fault mode drops the closing text turn, so the request after the close is the one that raises.
    main = (_FaultsAfterClose(turns) if fault_after_close
            else RH.ReplayFn([*turns, RH.Turn(text="Investigation complete.")]))
    investigate = functools.partial(run_py._drive_investigation, investigate=RH.investigate_as_handed(main))
    return functools.partial(run_py._run_investigation_lifecycle, investigate=investigate, start_box=_unboxed)


def _hold_lifecycle(*, closes: bool):
    def investigate(*, job_facts=None, **_kw):
        if closes:
            from defender.investigation.challenge_gate import ReviewState

            assert job_facts is not None, "the investigation was not handed the job facts holder"
            job_facts.review_state["state"] = ReviewState(closed=True)
        (marks / "in-lifecycle").touch()
        try:
            while True:
                time.sleep(0.05)
        except BaseException as e:
            (marks / "interrupted").write_text(type(e).__name__, encoding="utf-8")
            raise

    def stop_box(*_a, **_k):
        (marks / "stop-box-started").touch()
        deadline = time.monotonic() + 15
        while not (marks / "go-on").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        (marks / "stop-box-done").touch()

    return functools.partial(run_py._run_investigation_lifecycle, investigate=investigate,
                             start_box=_unboxed, stop_box=stop_box, scrub=lambda *a, **k: None)


#: The priced modes' models (#1377): each name its own `in` rate (3.0, 1.0, 0.95 USD a million).
PRICED_MAIN, PRICED_GATHER, PRICED_REVIEW = "claude-sonnet-4-6", "claude-haiku-4-5", "kimi-k2.6"


def _counted(name: str, then=None):
    """Append one line to `<marks>/calls-<name>` per call, then run `then`."""
    def before():
        with (marks / f"calls-{name}").open("a", encoding="utf-8") as fh:
            fh.write("1\n")
        if then is not None:
            then()
    return before


def _session_database() -> Path:
    import json

    job, tenant = argv[argv.index("--job") + 1], argv[argv.index("--tenant") + 1]
    pointer = Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "runs" / f"{job}.session-pointer.json"
    return Path(json.loads(pointer.read_text(encoding="utf-8"))["store_path"])


def _ledger_trigger(sql: str):
    """A real sqlite fault on the run's own ledger table, made from a second connection."""
    import sqlite3
    import threading

    lock = threading.Lock()

    def run() -> None:
        with lock:
            conn = sqlite3.connect(_session_database(), timeout=10)
            try:
                conn.execute(sql)
                conn.commit()
            finally:
                conn.close()
    return run


def _priced_lifecycle(*, ledger_fault: bool, raises: bool = False):
    """`replay-priced`: MAIN (dispatch one elastic lead, append, close, text), the lead (one query,
    then its final summary), the correlation lead (its summary) and the live review stages, each a priced stand-in. `-ledger-fault`
    refuses every ledger insert from the first review call until MAIN's turn after the close."""
    import asyncio

    from pydantic_ai.models import override_allow_model_requests

    from defender.investigation import driver
    from defender.records.formats import parse_report_text
    from defender.tests.e2e._replay_harness import FakeVerbs
    from defender.tests.e2e.test_query_tool_611 import DONE, q

    disposition = parse_report_text((GOLDEN / "report.md").read_text(encoding="utf-8")).disposition
    from defender.tests.support.jobs._jobs1342 import SPEND_LEDGER

    refuse = _ledger_trigger(f"CREATE TRIGGER IF NOT EXISTS refuse_spend BEFORE INSERT ON {SPEND_LEDGER} "
                             "BEGIN SELECT RAISE(ABORT, 'the disk is full'); END") if ledger_fault else None
    allow = _ledger_trigger("DROP TRIGGER IF EXISTS refuse_spend") if ledger_fault else None
    main_calls = {"n": 0}

    def main_before():
        main_calls["n"] += 1
        if allow is not None and main_calls["n"] == 4:  # the text turn after the close
            allow()

    main = RH.ReplayFn([
        RH.Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic", "goal": "measure this lead",
                                        "what_to_summarize": ["auth events"]})]),
        RH.Turn(tool_calls=[("append_block", {"text": (GOLDEN / "investigation.md").read_text(encoding="utf-8")})]),
        RH.Turn(tool_calls=[("close_investigation", {"disposition": disposition})]),
        RH.Turn(text="Investigation complete."),
    ])
    # l-001 runs its query, then its final summary; the correlation lead (l-00c) answers its summary once.
    lead = RH._with_default_correlation(RH.ReplayFn([q("elastic", "query", {"native_query": "user.name:root"}), DONE]), None)
    review = RH.ReplayFn([RH.Turn(text=RH._review_bundle.composer_reply("holds"))] * 3)
    make_model = RH.priced_make_model({
        PRICED_MAIN: RH.Priced(main, before=_counted("main", main_before)),
        PRICED_GATHER: RH.Priced(lead, before=_counted("gather")),
        PRICED_REVIEW: RH.Priced(review, before=_counted("review", refuse)),
    })
    def query(ctx, *, native_query: str, limit: int = 10) -> list[dict]:
        return [{"user": "root"}]

    verbs = FakeVerbs({"elastic": {"query": query}})

    def investigate(**handed):
        # No `review_stages`: the run's own live bundle, built on the run's `make_model` (#1377).
        with override_allow_model_requests(False):
            summary = asyncio.run(driver.run_investigation(
                **{**handed, "verbs": verbs}, make_model=make_model, orient_shim=RH.no_orient_shims))
        if raises:
            raise RuntimeError("the run died after its last response")
        return summary

    drive = functools.partial(run_py._drive_investigation, investigate=investigate)
    return functools.partial(run_py._run_investigation_lifecycle, investigate=drive, start_box=_unboxed)


if mode.startswith("replay-priced"):
    from defender import _log

    _log.configure_from_env()  # the way run.py's __main__ does: the priced modes' stderr is read for the failed-write ERROR line
    lifecycle = _priced_lifecycle(ledger_fault="ledger-fault" in mode, raises=mode.endswith("-raises"))
elif mode.startswith("replay"):
    lifecycle = _replay_lifecycle(fault_after_close=mode == "replay-fault-after-close")
else:
    lifecycle = _hold_lifecycle(closes=mode == "hold-committed")
sys.exit(run_py.job_main(argv, lifecycle=lifecycle, preflight=lambda *a, **k: 0,
                         visualize=lambda *a, **k: None, publish=lambda *a, **k: f"fresh {commit}"))
