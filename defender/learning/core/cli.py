from __future__ import annotations

import sys
from collections.abc import Callable

from defender.learning.core.config import RunAlreadyLive, RunUnprocessable
from defender.learning.core.drains import author_drain, lead_author_drain
from defender.learning.core.faults import SYSTEMIC_FAULTS


_HELP_EPILOG = """\
Two authoring stages, one drainer at a time each. Neither takes a run_dir: both read a queue
and open a PR.

  --author-drain       the findings queue -> the lessons corpus
  --lead-author-drain  the queued run dirs -> the gather catalog + system skills

WHERE THE FINDINGS COME FROM (#922). Until the cutover this file also carried the LEARN stage
— `loop.py <run_dir>` and `--learn-drain` — which ran a four-role pipeline over one finished
run and appended its verdicts to the findings queue. That pipeline is deleted. Findings now
come from a BRANCHED EPISODE: `defender/learning/branch/cli.py` forks a finished run at a
chosen message, runs a family of worlds from it, and its judge appends the graded rows to the
same `_pending/findings.jsonl` this drain reads. The queue and both stages below are unchanged;
only the producer moved.

Environment:
  LEARNING_AUTHOR_THRESHOLD          AUTHORABLE queued findings before the lessons curator
                                     runs — rows the gate has already held do not count
                                     toward it (default: 5)
  LEARNING_SUBAGENT_TIMEOUT_SECONDS  per-subagent timeout (default: 450)

Exit codes: 0 success / 0 REFUSED because another drainer holds the lease (the stderr line is
the only signal — blocking would hang the terminal behind a full batch, and a non-zero code
would fail a wrapper over a condition that is nobody's error) / 2 StageAbort (systemic fault —
fix the deployment) / 1 usage.
"""


def _run_stage(stage: Callable[[], int], *, allow_run_error: bool = False) -> int:
    try:
        return stage()
    except SYSTEMIC_FAULTS as e:
        print(f"[loop] FATAL: {e}", file=sys.stderr)
        # A terse exit-2 line costs the traceback an unhandled fault would have printed, and
        # with it the exception this one displaced. That matters for `RunTainted`, which
        # deliberately outranks the work's own failure — `__context__` is the reason the batch
        # was already dying, and nothing else on this path says it.
        if e.__context__ is not None:
            print(f"[loop] FATAL: ...it displaced: {e.__context__!r}", file=sys.stderr)
        return 2
    except RunAlreadyLive as e:
        # Not an error and not a traceback: a caller asking for work another holder already
        # has has made no mistake, and blocking would hang their terminal behind a full batch.
        # The raiser this was written for (`run_one`) left with #922; the arm stays because
        # the lease discipline it answers for is the drains', and #955 F-49's choice — say so,
        # do nothing, exit clean — is the same answer for them.
        print(f"[loop] {e}", file=sys.stderr)
        return 0
    except RunUnprocessable as e:
        if not allow_run_error:
            raise
        print(f"[loop] FATAL: unprocessable run: {e}", file=sys.stderr)
        return 2


def main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="defender/learning/loop.py",
        description=(
            "Defender learning-loop orchestrator: the two authoring stages that drain a "
            "queue into a corpus PR. The stage that PRODUCED the findings queue moved to "
            "the branched-episode judge in #922 — see the epilogue."
        ),
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--author-drain", action="store_true",
        help="LESSONS AUTHOR stage: in a fresh lessons/ worktree, drain the "
             "findings/observation curator queues and open one lessons PR "
             "(takes no run_dir; one drainer at a time).",
    )
    parser.add_argument(
        "--lead-author-drain", action="store_true",
        help="LEAD-AUTHOR stage: in a fresh lead-author/ worktree, curate the gather "
             "catalog + system skills for each queued run dir and open one lead-author "
             "PR (separate from the lessons PR; takes no run_dir; one drainer at a time).",
    )
    ns = parser.parse_args(argv[1:])

    if ns.author_drain and ns.lead_author_drain:
        print("--author-drain and --lead-author-drain are mutually exclusive",
              file=sys.stderr)
        return 1

    if ns.author_drain:
        return _run_stage(author_drain)

    if ns.lead_author_drain:
        return _run_stage(lead_author_drain)

    # No positional to fall through to since #922 removed the LEARN stage: a bare invocation
    # is a usage error, not a request to process something.
    print("one of --author-drain / --lead-author-drain is required", file=sys.stderr)
    return 1
