#!/usr/bin/env python3
"""Secondary-metric harness — frozen-actor replay catch rate.

Where the primary metric (``held_out.py``) asks "does the
current defender disposition match ground truth on held-out alerts?"
the secondary asks "would the current defender's lead sequence refute
stories an *older* actor writes?"

Divergence between the two (primary plateaus, secondary climbs) is
the diagnostic signal: defender is gaining curriculum-distribution
capability without target-distribution capability. See
``defender/docs/learning-loop-actor-learning.md`` §Secondary.

Pipeline per eligible alert:

  1. Current defender (HEAD) investigates the alert via
     ``defender/run.py --no-learn`` — produces ``report.md`` +
     the two lead/query tables (``executed_queries.jsonl`` + ``gather_raw/``).
  2. Filter eligibility: ground-truth must be benign or
     inconclusive. Malicious held-out is primary-only.
  3. Filter executed: HEAD defender must not have escalated
     (``disposition != malicious``). False escalations drop out of
     the catch-rate denominator and are reported as
     ``not_executed``.
  4. Frozen actor (gen-{N-K} worktree) writes a story via
     ``defender/learning/replay_actor.py``, projecting the HEAD
     defender's tables through ``lead_repository.actor_view``. Model is
     pinned from the gen-{N-K} commit's ``Actor-Model:`` trailer.
  5. Current oracle + judge (HEAD) grade the story against the
     defender's lead sequence.

Catch rate = caught / (caught + survived + incoherent + undecidable)
over the executed set. ``skip-passthrough`` (frozen actor declined
to write a story) is excluded from the denominator and reported
separately as SKIP rate.

Usage:
  python3 defender/evals/secondary.py [--k 3] [--out <dir>]

The harness writes no commits and creates no queue entries.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _reexec_into_venv_if_needed() -> None:
    """Re-exec into defender/.venv when invoked under a non-venv python.

    Two failure modes this guards against:

    1. loop.py has its own top-level os.execv guard. If we let that
       fire during ``importlib.exec_module(loop)`` later in this
       module, it would replace the harness process on the wrong
       argv. Pre-empting at our own top means loop's guard becomes a
       no-op by the time we import it.
    2. The module imports non-stdlib packages (``yaml``) below. A
       system python without PyYAML would fail at our own import
       line *before* this guard had a chance to switch interpreters.
       So the guard must run before the first non-stdlib import.

    At pytest-collection time we must NOT re-exec (the venv's console
    script names its interpreter ``python``, not ``python3``; strict
    equality would replace the collector process with the harness CLI
    and exit 2). The ``sys.prefix == venv`` check is permissive:
    any same-venv interpreter (``python``, ``python3``, ``python3.11``)
    is treated as already valid.
    """
    venv = Path(__file__).resolve().parents[2] / "defender" / ".venv"
    if not venv.is_dir():
        return
    try:
        already_in_venv = Path(sys.prefix).resolve() == venv.resolve()
    except OSError:
        already_in_venv = False
    if already_in_venv:
        return
    venv_py = venv / "bin" / "python3"
    if venv_py.is_file():
        os.execv(str(venv_py), [str(venv_py), __file__, *sys.argv[1:]])


# Must run before any non-stdlib import (yaml below) so a system
# python without PyYAML can still reach the re-exec into the venv.
_reexec_into_venv_if_needed()

import argparse
import importlib.util
import uuid
from dataclasses import dataclass

import yaml

# ---------------------------------------------------------------------------
# Sub-module imports — re-exported so test_secondary.py can access all
# public symbols via the ``sec`` module reference it obtains by loading
# this file directly with importlib.
# ---------------------------------------------------------------------------

from _secondary_config import (  # noqa: E402
    REPO_ROOT,
    LEARNING_DIR,
    EVAL_OUT_DIR,
    FIXTURES_DIR,
    DEFAULT_RUNS_BASE,
    ELIGIBLE_DISPOSITIONS,
    ESCALATED_DISPOSITION,
    SecondaryError,
)
from _generation import (  # noqa: E402, F401  (parse_trailers/list_actor_commits/worktree_path_for/_worktree_head_sha re-exported for test_secondary.py)
    parse_trailers,
    list_actor_commits,
    resolve_target_pin,
    worktree_path_for,
    _worktree_head_sha,
    ensure_worktree,
    worktree_has_replay_script,
)
from _pipeline import (  # noqa: E402
    AlertResult,
    run_head_defender,
    read_head_disposition,
    run_frozen_actor,
    run_head_oracle_and_judge,
)
from _summary import (  # noqa: E402
    SecondarySummary,
    format_summary_md,
    write_summary,
)


# ---------------------------------------------------------------------------
# loop.py shims — load on demand so tests can import this module without
# pulling pyyaml-only loop dependencies into the import path.
# ---------------------------------------------------------------------------

def _load_by_path(modname: str, filename: str):
    """Load a ``learning/`` sibling by path under a private module name. The
    asserts narrow the optional spec/loader for the type gate; ``setdefault``
    keeps a prior import (the shim may be loaded more than once per process)."""
    spec = importlib.util.spec_from_file_location(modname, LEARNING_DIR / filename)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(modname, mod)
    spec.loader.exec_module(mod)
    return mod


def _load_loop():
    return _load_by_path("_defender_learning_loop_secondary", "loop.py")


def _load_shared():
    return _load_by_path("_defender_learning_shared_secondary", "_author_shared.py")


# ---------------------------------------------------------------------------
# Eligibility / fixtures
# ---------------------------------------------------------------------------

@dataclass
class HeldOutAlert:
    slug: str
    alert_path: Path
    ground_truth: dict


def load_held_out_fixtures(fixtures_dir: Path) -> list[HeldOutAlert]:
    out: list[HeldOutAlert] = []
    for child in sorted(fixtures_dir.iterdir()):
        if not child.is_dir():
            continue
        alert = child / "alert.json"
        gt = child / "ground_truth.yaml"
        if not (alert.is_file() and gt.is_file()):
            continue
        gt_doc = yaml.safe_load(gt.read_text()) or {}
        if not isinstance(gt_doc, dict) or gt_doc.get("held_out") is not True:
            continue
        out.append(HeldOutAlert(child.name, alert, gt_doc))
    return out


def eligible_for_secondary(alerts: list[HeldOutAlert]) -> list[HeldOutAlert]:
    return [a for a in alerts if a.ground_truth.get("disposition") in ELIGIBLE_DISPOSITIONS]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_secondary(
    *,
    k: int,
    out_dir: Path,
    runs_base: Path,
    fixtures_dir: Path,
    repo_root: Path,
    worktrees_dir: Path | None = None,
) -> SecondarySummary:
    shared = _load_shared()
    n_next = shared.actor_generation_count(repo_root)  # = 1 + prior committed
    n_committed = n_next - 1                  # latest committed gen
    summary = SecondarySummary(
        current_generation=n_committed,
        pinned_generation=None,
        pinned_sha=None,
        pinned_model=None,
        k=k,
    )

    if n_committed < 1:
        summary.replay_incompatible_reason = (
            f"no actor-author commits in history yet (current gen={n_committed})"
        )
        write_summary(summary, out_dir)
        return summary

    pin = resolve_target_pin(repo_root, k)
    if pin is None:
        summary.replay_incompatible_reason = (
            f"no commit asserts Generation {n_committed - k} "
            f"(need {k} prior actor-author commits, have {n_committed})"
        )
        write_summary(summary, out_dir)
        return summary

    summary.pinned_generation = pin.generation
    summary.pinned_sha = pin.sha
    summary.pinned_model = pin.actor_model

    worktree = ensure_worktree(pin, repo_root, worktrees_dir=worktrees_dir)
    if not worktree_has_replay_script(worktree):
        summary.replay_incompatible_reason = (
            f"gen-{pin.generation} worktree at {worktree} does not ship "
            f"defender/learning/replay_actor.py"
        )
        write_summary(summary, out_dir)
        return summary

    fixtures = load_held_out_fixtures(fixtures_dir)
    eligible = eligible_for_secondary(fixtures)
    summary.eligible = len(eligible)

    # Per-attempt suffix so reruns after an interruption don't collide
    # with prior run dirs (``defender/run.py`` refuses to overwrite an
    # existing one). One suffix per harness invocation so all alerts in
    # a run share the same attempt id and per-alert artifacts cluster
    # together on disk.
    attempt = uuid.uuid4().hex[:8]

    loop_mod = _load_loop()
    for alert in eligible:
        run_id = f"sec-eval-gen{n_committed}-{alert.slug}-{attempt}"
        result = AlertResult(
            slug=alert.slug,
            ground_truth=alert.ground_truth["disposition"],
            status="failed",
        )
        # Stable case_id (no attempt suffix) for actor seeding —
        # decoupled from the per-attempt run dir so reruns of the same
        # (generation, alert) sample the identical menu/archetype.
        case_id = f"sec-eval-gen{n_committed}-{alert.slug}"
        try:
            head_run_dir = run_head_defender(alert, run_id, runs_base)
            result.head_run_dir = str(head_run_dir)
            head_disp = read_head_disposition(head_run_dir)
            result.head_disposition = head_disp
            if head_disp == ESCALATED_DISPOSITION:
                result.status = "not_executed"
                summary.results.append(result)
                continue
            if head_disp not in ELIGIBLE_DISPOSITIONS:
                # Missing report.md / unparseable frontmatter / non-enum
                # disposition. A broken HEAD run mustn't smuggle bogus
                # rows into the metric — record as failed and skip the
                # actor/oracle/judge stages.
                result.error = (
                    f"HEAD defender produced no eligible disposition "
                    f"(got {head_disp!r})"
                )
                summary.results.append(result)
                continue

            staging = runs_base / f"{run_id}-replay"
            run_frozen_actor(head_run_dir, staging, worktree, pin, case_id, loop_mod)
            result.replay_run_dir = str(staging)
            outcome = run_head_oracle_and_judge(head_run_dir, staging, loop_mod)
            result.judge_outcome = outcome
            result.status = "executed"
        except SecondaryError as e:
            result.error = str(e)[:500]
        summary.results.append(result)

    write_summary(summary, out_dir)
    return summary


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--k", type=int, default=3,
                   help="generations back to pin the frozen actor (default 3)")
    p.add_argument("--out", default=str(EVAL_OUT_DIR),
                   help=f"output dir (default: {EVAL_OUT_DIR})")
    p.add_argument("--runs-base", default=str(DEFAULT_RUNS_BASE),
                   help=f"defender runs base (default: {DEFAULT_RUNS_BASE})")
    p.add_argument("--fixtures", default=str(FIXTURES_DIR),
                   help=f"held-out fixtures dir (default: {FIXTURES_DIR})")
    ns = p.parse_args(argv)

    summary = run_secondary(
        k=ns.k,
        out_dir=Path(ns.out),
        runs_base=Path(ns.runs_base),
        fixtures_dir=Path(ns.fixtures),
        repo_root=REPO_ROOT,
    )
    print(format_summary_md(summary))
    return 0


if __name__ == "__main__":
    # _reexec_into_venv_if_needed() ran at import time (before the
    # PyYAML import) so by the time we get here we're already in the
    # venv or there was no venv to re-exec into.
    sys.exit(main(sys.argv[1:]))
