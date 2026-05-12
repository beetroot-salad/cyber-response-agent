#!/usr/bin/env python3
"""Defender entrypoint — investigate one alert end-to-end.

Usage:
    python3 defender/run.py <alert.json> [options]

Options:
    --run-id ID         Override the auto-generated run id.
    --no-learn          Skip the learning-loop step.
    --model MODEL       Override $DEFENDER_MODEL (default: claude-sonnet-4-6).
    --effort EFFORT     Pass --effort to claude.

Pipeline:
    1. Materialize {run_dir}/ with alert.json and an empty gather_raw/.
    2. Spawn `claude -p` against defender/SKILL.md with the prepared
       run_settings.json (permissions + the lead-metadata extraction
       hook). stream-json events go to {run_dir}/tool_trace.jsonl.
    3. Project lead_sequence.yaml from the run.
    4. Render transcript.html.
    5. Unless --no-learn, hand the run to defender.learning.loop.run_one
       (in-process import, not subprocess).

Steps 3–5 used to live in run.sh + the SKILL prompt; consolidating
them here means the agent stops carrying the projection responsibility
and broken runs (where the agent forgot or crashed) still produce
whatever artifacts the agent did manage to write.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Re-exec into defender/.venv if launched against a different interpreter,
# so callers don't have to remember to invoke the venv python. Bootstrap
# instructions live in defender/CLAUDE.md §Python environment.
_DEFENDER_DIR = Path(__file__).resolve().parent
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
# Compare unresolved paths — the venv python is typically a symlink to the
# system interpreter, so .resolve() would collapse both sides and skip the
# re-exec even when site-packages differ.
if _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse
import datetime as _dt
import shutil
import subprocess
import tempfile

DEFENDER_DIR = _DEFENDER_DIR
REPO_ROOT = DEFENDER_DIR.parent
SETTINGS_TEMPLATE = DEFENDER_DIR / "run-settings.json"
PROJECT_SCRIPT = DEFENDER_DIR / "scripts" / "project_lead_sequence.py"
VISUALIZE_SCRIPT = DEFENDER_DIR / "scripts" / "visualize_run.py"

DEFAULT_RUNS_BASE = Path("/tmp/defender-runs")
DEFAULT_MODEL = "claude-sonnet-4-6"


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("alert", type=Path, help="Path to alert.json fixture")
    p.add_argument("--run-id", default=None, help="Override auto-generated run id")
    p.add_argument("--no-learn", action="store_true", help="Skip the learning loop")
    p.add_argument("--model", default=None, help="claude --model (overrides $DEFENDER_MODEL)")
    p.add_argument("--effort", default=None, help="claude --effort (overrides $DEFENDER_EFFORT)")
    return p.parse_args(argv)


def materialize_run_dir(alert: Path, run_id: str | None) -> Path:
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    runs_base = Path(os.environ.get("DEFENDER_RUNS_BASE", str(DEFAULT_RUNS_BASE)))
    if run_id is None:
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{ts}-{alert.stem}"
    run_dir = runs_base / run_id
    if run_dir.exists():
        sys.exit(f"run dir already exists: {run_dir}")
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(alert, run_dir / "alert.json")
    # Propagate a sibling ground_truth.yaml into the run dir so the learning
    # loop's persist stage can recognise held-out cases and suppress
    # queue appends. Fixture layout: {fixture-dir}/{alert.json,ground_truth.yaml}.
    gt = alert.parent / "ground_truth.yaml"
    if gt.is_file():
        shutil.copy(gt, run_dir / "ground_truth.yaml")
    return run_dir


def build_settings_file() -> Path:
    """Materialize a tempfile settings.json with $DEFENDER_DIR substituted.

    Claude Code executes hook `command` strings via shell, so the
    `${DEFENDER_DIR}` placeholder in run-settings.json would expand at
    hook-fire time too — but writing it out resolved removes the
    dependency on the env var being set in the hook subshell, and
    keeps the on-disk template diff-friendly.
    """
    template = SETTINGS_TEMPLATE.read_text()
    resolved = (
        template
        .replace("${DEFENDER_DIR}", str(DEFENDER_DIR))
        .replace("${PYTHON}", sys.executable)
    )
    fh = tempfile.NamedTemporaryFile(
        mode="w", suffix=".settings.json", delete=False, prefix="defender-"
    )
    fh.write(resolved)
    fh.close()
    return Path(fh.name)


def build_prompt(run_id: str, run_dir: Path) -> str:
    return (
        "Read defender/SKILL.md and follow it end-to-end.\n\n"
        "## Run context\n"
        f"case_id: {run_id}\n"
        f"run_dir: {run_dir}\n"
        f"alert: {run_dir / 'alert.json'}\n\n"
        "The run dir already exists with alert.json copied in and an empty\n"
        "gather_raw/ subdirectory. It lives under /tmp — write all run\n"
        "artifacts (investigation.md, report.md, gather_raw/*) there, not\n"
        "under the repo. Work through ORIENT → PLAN → GATHER →\n"
        "ANALYZE → REPORT, dispatching gather subagents per\n"
        "defender/SKILL.md §GATHER. Stop when investigation.md and\n"
        "report.md both exist; lead_sequence.yaml and transcript.html are\n"
        "rendered by the harness after you exit.\n"
    )


def spawn_claude(prompt: str, run_dir: Path, settings_path: Path, model: str, effort: str | None) -> int:
    trace = run_dir / "tool_trace.jsonl"
    args = [
        "claude", "-p",
        "--model", model,
        "--output-format", "stream-json",
        "--include-hook-events",
        "--verbose",
        "--permission-mode", "acceptEdits",
        "--settings", str(settings_path),
        "--add-dir", str(run_dir),
    ]
    if effort:
        args.extend(["--effort", effort])
    print(f"[run.py] run_dir={run_dir} model={model}" + (f" effort={effort}" if effort else ""), file=sys.stderr)
    env = dict(os.environ)
    env["DEFENDER_DIR"] = str(DEFENDER_DIR)
    with trace.open("w") as out:
        proc = subprocess.run(args, input=prompt, text=True, stdout=out, env=env, cwd=str(REPO_ROOT))
    return proc.returncode


def project_lead_sequence(run_dir: Path) -> bool:
    proc = subprocess.run(
        [sys.executable, str(PROJECT_SCRIPT), str(run_dir)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(f"[run.py] project_lead_sequence failed: {proc.stderr}")
        return False
    sys.stderr.write(proc.stdout)
    return True


def visualize(run_dir: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(VISUALIZE_SCRIPT), str(run_dir)],
        capture_output=True, text=True,
    )
    sys.stderr.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(f"[run.py] visualize_run failed: {proc.stderr}")
        return
    # Mirror the rendered transcript into defender/run-visualizations/
    # so reviews aren't gated on /tmp/defender-runs/ surviving.
    transcript = run_dir / "transcript.html"
    if transcript.is_file():
        dest_dir = DEFENDER_DIR / "run-visualizations"
        dest_dir.mkdir(exist_ok=True)
        dest = dest_dir / f"{run_dir.name}.html"
        shutil.copyfile(transcript, dest)
        sys.stderr.write(f"[run.py] copied transcript to {dest.relative_to(REPO_ROOT)}\n")


def run_learning_loop(run_dir: Path) -> int:
    sys.path.insert(0, str(DEFENDER_DIR / "learning"))
    try:
        import loop as _loop  # type: ignore[import-not-found]
    finally:
        sys.path.pop(0)
    try:
        return _loop.run_one(run_dir)
    except _loop.LoopError as e:
        print(f"[run.py] learning loop FATAL: {e}", file=sys.stderr)
        return 2


def main(argv: list[str]) -> int:
    ns = parse_args(argv)
    alert = ns.alert.resolve()
    run_dir = materialize_run_dir(alert, ns.run_id)

    settings_path = build_settings_file()
    model = ns.model or os.environ.get("DEFENDER_MODEL") or DEFAULT_MODEL
    effort = ns.effort or os.environ.get("DEFENDER_EFFORT") or None

    prompt = build_prompt(run_dir.name, run_dir)
    rc = spawn_claude(prompt, run_dir, settings_path, model, effort)
    if rc != 0:
        print(f"[run.py] claude exited rc={rc}; continuing post-steps on whatever artifacts exist", file=sys.stderr)

    projected = project_lead_sequence(run_dir)

    print("[run.py] artifacts:", file=sys.stderr)
    for entry in sorted(run_dir.iterdir()):
        sys.stderr.write(f"  {entry.name}\n")

    if not projected:
        # Projection failure is a harness-level break (no lead_sequence.yaml,
        # the documented learning-loop input). Surface it on every path —
        # the non-zero exit lets CI / loops detect a broken run regardless
        # of whether --no-learn was requested. Render the transcript first
        # so the broken run still has a reviewable artifact.
        visualize(run_dir)
        print("[run.py] lead_sequence.yaml missing; halting after post-steps", file=sys.stderr)
        return rc or 1

    learn_rc = 0
    if ns.no_learn:
        print("[run.py] --no-learn set; skipping learning loop", file=sys.stderr)
    else:
        print("[run.py] handing off to learning loop", file=sys.stderr)
        learn_rc = run_learning_loop(run_dir)

    # Render after the learning loop so transcript.html includes the
    # actor/oracle/judge artifacts and any lesson-corpus commits.
    visualize(run_dir)
    return rc or learn_rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
