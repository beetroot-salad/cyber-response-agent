#!/usr/bin/env python3
"""Shared run-dir + post-step helpers for the defender runtime.

The entrypoint (`run.py`, the PydanticAI engine) and the gather/orient tools
import these: `materialize_run_dir` (set up the run dir), `run_env` (the bash
tool's subprocess environment), `cross_check_tables` / `enqueue_learning` /
`visualize` (the post-investigation steps). Engine-agnostic and side-effect-free
to import — the heavier learning imports are done lazily inside the functions
that need them.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

DEFENDER_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEFENDER_DIR.parent
# Put the workspace root on sys.path so `defender.*` namespace imports resolve
# (the learning modules are imported lazily below); see tests/conftest.py.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender._run_paths import RunPaths  # noqa: E402

VISUALIZE_SCRIPT = DEFENDER_DIR / "scripts" / "visualize" / "visualize_run.py"

# The single home for the runtime runs-base literal + its env resolution. Every
# other reader (evals/_secondary_config.py, evals/held_out.py) calls
# resolve_runs_base() instead of re-reading DEFENDER_RUNS_BASE with its own copy of
# the DEFAULT_RUNS_BASE default below.
DEFAULT_RUNS_BASE = Path("/tmp/defender-runs")


def resolve_runs_base() -> Path:
    """The runtime runs base from ``$DEFENDER_RUNS_BASE`` (call time), else the
    default. Resolved here so the env var + default literal have one source."""
    return Path(os.environ.get("DEFENDER_RUNS_BASE", str(DEFAULT_RUNS_BASE)))


def materialize_run_dir(alert: Path, run_id: str | None) -> Path:
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    runs_base = resolve_runs_base()
    if run_id is None:
        ts = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{ts}-{alert.stem}"
    run_dir = runs_base / run_id
    if run_dir.exists():
        sys.exit(f"run dir already exists: {run_dir}")
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    shutil.copy(alert, RunPaths(run_dir).alert)
    # Per-run salt consumed by the tag_tool_results tagging to wrap untrusted
    # data-source output in unguessable delimiters. Stable across the run,
    # regenerated per run.
    RunPaths(run_dir).meta.write_text(
        json.dumps({"run_id": run_dir.name, "salt": secrets.token_hex(8)}, indent=2)
        + "\n"
    )
    # Propagate a sibling ground_truth.yaml into the run dir so the learning
    # loop's persist stage can recognise held-out cases and suppress
    # queue appends. Fixture layout: {fixture-dir}/{alert.json,ground_truth.yaml}.
    gt = alert.parent / "ground_truth.yaml"
    if gt.is_file():
        shutil.copy(gt, run_dir / "ground_truth.yaml")
    return run_dir


def run_env(defender_dir: Path, run_dir: Path) -> dict[str, str]:
    """The bash tool's subprocess environment. `bin/` goes first on PATH so the
    `defender-*` shims resolve by a single stable token regardless of cwd, venv
    path, or compound wrapping; the run-dir anchors the budget/tag accounting and
    the invlang corpus root (`DEFENDER_RUNS_BASE == run_dir.parent`).

    Every billable provider key (`providers.api_key_vars()` — `ANTHROPIC_API_KEY`,
    `FIREWORKS_API_KEY`, …) is stripped: the bash tool runs data-source shims, never
    LLM calls, so no billable key has any business in its environment (the PydanticAI
    engine authenticates in-process from `os.environ`, which this copy leaves
    untouched). Returns a fresh dict — never mutates `os.environ`."""
    # Local import keeps this module engine-agnostic to import; providers' heavy
    # backends are lazy, so this pulls in no pydantic-ai.
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    env["DEFENDER_DIR"] = str(defender_dir)
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    env["DEFENDER_RUNS_BASE"] = str(run_dir.parent)
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    return env


def visualize(run_dir: Path) -> None:
    # visualize_run.py renders the judge + runtime pages AND mirrors them into
    # defender/run-visualizations/<run_id>/ (so reviews aren't gated on /tmp
    # surviving). Pre-learn the judge page renders empty (no judge artifacts yet);
    # the off-process learn worker re-renders + re-mirrors the same way once they
    # exist, so the runtime view is the only useful part of this pass.
    proc = subprocess.run(
        [sys.executable, str(VISUALIZE_SCRIPT), str(run_dir)],
        capture_output=True, text=True,
    )
    sys.stderr.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(f"[run.py] visualize_run failed: {proc.stderr}")


def cross_check_tables(run_dir: Path) -> None:
    """Loud structural-integrity check on the two live tables.

    Restores the signal the deleted projection-failure halt used to provide:
    cross-check the leads/queries tables against the `:L` row ids in
    investigation.md. Orphan query rows or a lead the narration forgot are a
    WARN — a structurally degraded run that would otherwise flow silently into
    the oracle/judge; leads with no queries are an informational MONITOR note.
    Never raises — a diagnostic must not abort the post-steps.
    """
    if not RunPaths(run_dir).investigation.is_file():
        return
    try:
        from defender.learning import lead_repository

        xcheck = lead_repository.narration_crosscheck_from_run(run_dir)
    except Exception as e:  # noqa: BLE001 — diagnostics must never break the run
        print(f"[run.py] narration cross-check skipped: {e!r}", file=sys.stderr)
        return
    if not xcheck["ok"]:
        print(
            "[run.py] WARN narration cross-check FAILED — the live tables "
            "disagree with investigation.md's :L rows:",
            file=sys.stderr,
        )
        if xcheck["missing_from_narration"]:
            print(f"[run.py]   table lead_ids with no :L row: {xcheck['missing_from_narration']}", file=sys.stderr)
        if xcheck["queries_without_lead"]:
            print(f"[run.py]   query FKs with no lead sidecar (orphans): {xcheck['queries_without_lead']}", file=sys.stderr)
    if xcheck["leads_without_queries"]:
        print(f"[run.py]   note: leads with no queries (monitor): {xcheck['leads_without_queries']}", file=sys.stderr)


def enqueue_learning(run_dir: Path) -> None:
    """Hand the finished run to the off-process LEARN worker by dropping a
    learn-queue marker. The runtime holds SIEM creds; learning is SIEM-free and
    runs in a separate process (loop.py --learn-drain), so the investigation's
    exit no longer waits on — or is rolled back by — the learning chain."""
    from defender.learning import loop as _loop

    _loop.enqueue_for_learning(run_dir)
