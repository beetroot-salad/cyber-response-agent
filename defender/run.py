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
       run_settings.json (permissions + the record_lead hook). The two
       lead/query tables are written live during the run by record_lead.py
       + record_query.py. stream-json events go to {run_dir}/tool_trace.jsonl.
    3. Render transcript.html.
    4. Unless --no-learn, hand the run to defender.learning.loop.run_one
       (in-process import, not subprocess).

Steps 3–4 used to live in run.sh + the SKILL prompt; consolidating
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
import contextlib
import datetime as _dt
import json
import secrets
import shutil
import subprocess
import tempfile

DEFENDER_DIR = _DEFENDER_DIR
REPO_ROOT = DEFENDER_DIR.parent
SETTINGS_TEMPLATE = DEFENDER_DIR / "run-settings.json"
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
        ts = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{ts}-{alert.stem}"
    run_dir = runs_base / run_id
    if run_dir.exists():
        sys.exit(f"run dir already exists: {run_dir}")
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(alert, run_dir / "alert.json")
    # Per-run salt consumed by the tag_tool_results hook to wrap untrusted
    # data-source output in unguessable delimiters. Stable across the run,
    # regenerated per run.
    (run_dir / "meta.json").write_text(
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
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".settings.json", delete=False, prefix="defender-"
    ) as fh:
        fh.write(resolved)
        return Path(fh.name)


def build_prompt(run_id: str, run_dir: Path) -> str:
    # Inline workspace orientation so the agent doesn't burn turns on
    # ls/find/grep across skills, tools, and env files. Failure here is
    # non-fatal — the prompt still works without the map; we just lose
    # the discovery-thrash savings.
    ws_proc = subprocess.run(
        [sys.executable, str(DEFENDER_DIR / "scripts" / "workspace_map.py"), str(run_dir)],
        capture_output=True, text=True,
    )
    ws_map = ws_proc.stdout if ws_proc.returncode == 0 else f"<workspace map unavailable: {ws_proc.stderr.strip()}>\n"
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
        "report.md both exist; the lead/query tables are written live as you\n"
        "dispatch gather, and transcript.html is rendered after you exit.\n\n"
        f"{ws_map}"
    )


def spawn_claude(prompt: str, run_dir: Path, settings_path: Path, model: str, effort: str | None) -> int:
    trace = run_dir / "tool_trace.jsonl"
    # `--add-dir REPO_ROOT` is what lets Task-tool subagents Read paths
    # under DEFENDER_DIR. Subagents land in a Claude-Code-managed
    # worktree whose cwd is *not* under REPO_ROOT, so relative paths
    # resolve into the wrong tree; absolute reads under REPO_ROOT only
    # work if the directory is on the allowlist.
    args = [
        "claude", "-p",
        "--model", model,
        "--output-format", "stream-json",
        "--include-hook-events",
        "--verbose",
        "--permission-mode", "acceptEdits",
        "--settings", str(settings_path),
        "--add-dir", str(run_dir),
        "--add-dir", str(REPO_ROOT),
    ]
    if effort:
        args.extend(["--effort", effort])
    print(f"[run.py] run_dir={run_dir} model={model}" + (f" effort={effort}" if effort else ""), file=sys.stderr)
    env = dict(os.environ)
    env["DEFENDER_DIR"] = str(DEFENDER_DIR)
    # Single run-dir anchor for the budget + tag hooks (one claude -p per
    # run, so no session→run map is needed). Inherited by hook subshells.
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    # Put the invocation shims (defender/bin/defender-*) first on PATH so the
    # agent and its subagents call `defender-invlang` / `defender-elastic` /
    # … by a single stable token — matched by one allowlist rule regardless of
    # cwd, venv path, or compound wrapping. DEFENDER_RUNS_BASE is the invlang
    # corpus root the shim injects (run_dir.parent == the runs base).
    env["PATH"] = f"{DEFENDER_DIR / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    env["DEFENDER_RUNS_BASE"] = str(run_dir.parent)
    with trace.open("w") as out:
        proc = subprocess.run(args, input=prompt, text=True, stdout=out, env=env, cwd=str(REPO_ROOT))
    return proc.returncode


def visualize(run_dir: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(VISUALIZE_SCRIPT), str(run_dir)],
        capture_output=True, text=True,
    )
    sys.stderr.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(f"[run.py] visualize_run failed: {proc.stderr}")
        return
    # Mirror the rendered pages into defender/run-visualizations/<run_id>/
    # so reviews aren't gated on /tmp/defender-runs/ surviving. We mirror
    # into a per-run subdir (not flat files) because the judge/runtime
    # pages cross-link via relative hrefs.
    dest_dir = DEFENDER_DIR / "run-visualizations" / run_dir.name
    copied: list[str] = []
    for fname in ("transcript.html", "runtime.html"):
        src = run_dir / fname
        if not src.is_file():
            continue
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / fname
        shutil.copyfile(src, dest)
        copied.append(str(dest.relative_to(REPO_ROOT)))
    for path in copied:
        sys.stderr.write(f"[run.py] copied {path}\n")


def cross_check_tables(run_dir: Path) -> None:
    """Loud structural-integrity check on the two live tables.

    Restores the signal the deleted projection-failure halt used to provide:
    cross-check the leads/queries tables against the `:L` row ids in
    investigation.md. Orphan query rows or a lead the narration forgot are a
    WARN — a structurally degraded run that would otherwise flow silently into
    the oracle/judge; leads with no queries are an informational MONITOR note.
    Never raises — a diagnostic must not abort the post-steps.
    """
    if not (run_dir / "investigation.md").is_file():
        return
    learning = str(DEFENDER_DIR / "learning")
    sys.path.insert(0, learning)
    try:
        import lead_repository  # type: ignore[import-not-found]

        xcheck = lead_repository.narration_crosscheck_from_run(run_dir)
    except Exception as e:  # noqa: BLE001 — diagnostics must never break the run
        print(f"[run.py] narration cross-check skipped: {e!r}", file=sys.stderr)
        return
    finally:
        with contextlib.suppress(ValueError):
            sys.path.remove(learning)
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

    # The two lead/query tables are written live during the run (record_lead.py
    # + record_query.py), so there is no post-run projection step. A run that
    # produced no queries (no executed_queries.jsonl) is a monitor case, not a
    # harness break — the learning loop reads whatever the join surface yields.
    print("[run.py] artifacts:", file=sys.stderr)
    for entry in sorted(run_dir.iterdir()):
        sys.stderr.write(f"  {entry.name}\n")

    if not (run_dir / "executed_queries.jsonl").is_file():
        print("[run.py] note: no executed_queries.jsonl (the run ran no queries)", file=sys.stderr)

    # Loud structural-integrity signal (replaces the deleted projection halt).
    cross_check_tables(run_dir)

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
