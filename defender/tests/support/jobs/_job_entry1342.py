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
  `stop-box-done` once `go-on` exists (a later signal during teardown would stop the wait)."""
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
    main = (_FaultsAfterClose if fault_after_close else RH.ReplayFn)([
        RH.Turn(tool_calls=[("append_block", {"text": (GOLDEN / "investigation.md").read_text(encoding="utf-8")})]),
        RH.Turn(tool_calls=[("close_investigation", {"disposition": disposition})]),
        RH.Turn(text="Investigation complete."),
    ])
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


lifecycle = (_replay_lifecycle(fault_after_close=mode == "replay-fault-after-close")
             if mode.startswith("replay") else _hold_lifecycle(closes=mode == "hold-committed"))
sys.exit(run_py.job_main(argv, lifecycle=lifecycle, preflight=lambda *a, **k: 0,
                         visualize=lambda *a, **k: None, publish=lambda *a, **k: f"fresh {commit}"))
