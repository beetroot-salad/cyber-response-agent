from __future__ import annotations

import sys
from pathlib import Path
from collections.abc import Callable

from defender.learning.core.config import RunAlreadyLive, RunUnprocessable
from defender.learning.core.drains import author_drain, lead_author_drain
from defender.learning.core.faults import SYSTEMIC_FAULTS
from defender.learning.core.run_cycle import learn_drain, run_one


_HELP_EPILOG = """\
Direction dispatch (by the defender's normalized disposition):
  benign          → adversarial direction only (hunt the missed attack / FN)
  malicious       → benign direction only      (hunt the over-escalation / FP)
  inconclusive    → both directions
  false-positive  → neither: a verdict about the RULE, not the entity
A disposition that maps to no direction is skipped.

Inputs (must exist in <run_dir>):
  alert.json                 verbatim alert input
  report.md                  YAML frontmatter with disposition ∈ {benign, false-positive, inconclusive, malicious}
  investigation.md           defender's invlang audit log
  executed_queries.jsonl     the queries table (FK lead_id) — written live by record_query.py
  gather_raw/{lead_id}.lead.json   the leads table — written live by record_lead.py
  gather_raw/{lead_id}/{seq}.json  raw query payloads (by-ref)
  (joined via defender/learning/lead_repository.py)

Outputs:
  defender/learning/runs/<run_id>/
    actor_input.yaml               adversarial actor-facing projection (queries only)
    actor_story.md / *_benign.md   per-direction story (or "SKIP: ...")
    judge_findings[_benign].yaml   judge classification + queueable findings
  defender/learning/_pending/findings.jsonl
    appended queueable defender findings (both directions, tagged `direction`);
    when count >= LEARNING_AUTHOR_THRESHOLD the lessons curator (author.py) runs.
  defender/learning/_pending/actor_observations.jsonl   (adversarial direction)
    when count >= LEARNING_AUTHOR_ACTOR_THRESHOLD, author_actor.py runs.
  defender/learning/_pending/environment_observations.jsonl   (benign/FP direction)
    when count >= LEARNING_AUTHOR_ENV_THRESHOLD, author_actor_benign.py runs.
  defender/learning/_pending/actor_environment_observations.jsonl  (adversarial direction, #298)
    adversarial env facts → the SHARED lessons-environment/ corpus; when count >=
    LEARNING_AUTHOR_ACTOR_ENV_THRESHOLD, author_actor_env.py runs.

Environment:
  ACTOR_MODEL / BENIGN_ACTOR_MODEL     claude model for the adversarial / benign actor
  ORACLE_MODEL                         per-lead telemetry oracle model (default: glm-5.2;
                                       needs FIREWORKS_API_KEY — the oracle runs in-process)
  ORACLE_EFFORT                        oracle reasoning effort (default: none — reasoning
                                       DISABLED; the mechanical per-lead projection needs none)
  ORACLE_MAX_CONCURRENCY               max concurrent per-lead oracle calls (default: 8)
  JUDGE_EFFORT / BENIGN_JUDGE_EFFORT   judge reasoning effort (default: medium)
  JUDGE_MODEL / BENIGN_JUDGE_MODEL     adversarial / benign judge model (default: kimi-k3;
                                       needs FIREWORKS_API_KEY — the judge runs in-process)
  LEARNING_SUBAGENT_TIMEOUT_SECONDS    per-subagent timeout (default: 450)
  LEARNING_AUTHOR_THRESHOLD            pending findings before author runs (default: 5)
  LEARNING_AUTHOR_ACTOR_THRESHOLD      pending actor observations before author_actor runs
  LEARNING_AUTHOR_ENV_THRESHOLD        pending FP env observations before author_actor_benign runs
  LEARNING_AUTHOR_ACTOR_ENV_THRESHOLD  pending adversarial env observations before author_actor_env runs (#298)

Typical use (off-process): `defender/run.py` enqueues a learn-queue marker per finished
run; a SIEM-free worker drains it with `python3 defender/learning/loop.py --learn-drain`
(running this LEARN stage + re-rendering each transcript). `python3
defender/learning/loop.py <run_dir>` runs LEARN directly for a single run (re-processing).

Exit codes: 0 success / 0 skipped (no direction, or actor SKIP) / 0 REFUSED because another
pass already holds this run's lock (`RunAlreadyLive` — nothing ran; the stderr line is the
only signal, because blocking would hang the terminal behind a full learning cycle and a
non-zero code would fail a wrapper over a condition that is nobody's error) / 2 StageAbort
(systemic fault — fix the deployment) / 2 RunUnprocessable on a direct single run (bad run
data) / 1 usage. On a drain, a RunUnprocessable is a bug (the per-item guards should have
caught it), so it propagates uncaught rather than masquerading as a clean exit 2.
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
        # Not an error and not a traceback: a human asking for a run the worker already holds
        # has made no mistake, and blocking would hang their terminal behind a full learning
        # cycle. `run_one` raises this so the DRAIN can keep the queue marker; the CLI's own
        # answer is the one #955 F-49 chose — say so, do nothing, exit clean.
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
            "Defender learning-loop orchestrator. Given a finished defender run dir, "
            "runs actor → oracle → judge, persists artifacts under "
            "defender/learning/runs/<run_id>/, and queues findings for the curators."
        ),
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "run_dir", type=Path, nargs="?",
        help="Defender run dir (LEARN stage: produce findings + enqueue for authoring)",
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
    parser.add_argument(
        "--learn-drain", action="store_true",
        help="LEARN stage (off-process worker): drain the learn-queue, running "
             "actor → oracle → judge per finished run + re-rendering its transcript "
             "(takes no run_dir; SIEM-free, safe to run concurrently).",
    )
    ns = parser.parse_args(argv[1:])

    drain_flags = sum((ns.author_drain, ns.lead_author_drain, ns.learn_drain))
    if drain_flags > 1:
        print("--author-drain, --lead-author-drain, and --learn-drain are mutually "
              "exclusive", file=sys.stderr)
        return 1

    if ns.author_drain:
        if ns.run_dir is not None:
            print("--author-drain takes no run_dir", file=sys.stderr)
            return 1
        return _run_stage(author_drain)

    if ns.lead_author_drain:
        if ns.run_dir is not None:
            print("--lead-author-drain takes no run_dir", file=sys.stderr)
            return 1
        return _run_stage(lead_author_drain)

    if ns.learn_drain:
        if ns.run_dir is not None:
            print("--learn-drain takes no run_dir", file=sys.stderr)
            return 1
        return _run_stage(learn_drain)

    if ns.run_dir is None:
        print("run_dir required (or pass --author-drain / --lead-author-drain)", file=sys.stderr)
        return 1
    run_dir = ns.run_dir.resolve()
    if not run_dir.is_dir():
        print(f"not a directory: {run_dir}", file=sys.stderr)
        return 1
    return _run_stage(lambda: run_one(run_dir), allow_run_error=True)
