#!/usr/bin/env python3
"""Attack scenario runner.

Dispatches a single attack scenario from the devcontainer against the
remote compose stack via `docker --context soc-playground exec`. Attacks
fire into the live environment with baseline activity left on — the
agent's job is signal-vs-noise discrimination.

Usage:

    ./runner.py list
    ./runner.py run ssh-brute-force-canary --seed 42 --intensity 8
    ./runner.py run living-off-the-land --dry-run

A run writes attacks/runs/<run_id>/meta.json — start/end timestamps,
resolved parameters, per-step exit codes — as an investigation-context
hint, not a hard query window.

Reproducing a specific investigation post-mortem is the audit log's job:
the soc-agent's `audit_tool_calls.py` PostToolUse hook records each
tool_input + tool_response pair under runs/<session>/tool_audit.jsonl,
which is the durable record of what the agent saw. Historical query
reproducibility for arbitrary later replays relies on Elastic ILM
retention. Per-iteration PRNG seeding is kept only for dispatch
debugging stability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
CATALOG_PATH = HERE / "catalog.yaml"
RUNS_DIR = HERE / "runs"
DOCKER_CONTEXT = "soc-playground"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, dict]:
    raw = yaml.safe_load(path.read_text())
    return {s["id"]: s for s in raw["scenarios"]}


def render(template: str, ctx: dict[str, Any]) -> str:
    out = template
    for k, v in ctx.items():
        out = out.replace("${" + k + "}", str(v))
    return out


def seed_for(scenario_id: str, seed: int, step_index: int, iteration: int) -> int:
    key = f"{scenario_id}:{seed}:{step_index}:{iteration}".encode()
    return int(hashlib.sha256(key).hexdigest()[:16], 16)


def docker_exec(
    host: str,
    command: str,
    user: str | None,
    dry_run: bool,
) -> tuple[int, str, str]:
    args = ["docker", "--context", DOCKER_CONTEXT, "exec"]
    if user and user != "root":
        args += ["-u", user]
    args += [host, "bash", "-lc", command]
    if dry_run:
        print("DRY-RUN:", " ".join(args[:5]), "...")
        print(command)
        print()
        return 0, "", ""
    proc = subprocess.run(args, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def run_scenario(
    scenario: dict,
    seed: int,
    overrides: dict[str, Any],
    dry_run: bool,
) -> tuple[str, Path, list[dict]]:
    intensity = int(overrides.get("intensity") or scenario.get("default_intensity", 1))
    source_user = overrides.get("user") or scenario.get("source_user", "root")
    target_host = overrides.get("target") or scenario["target_host"]

    run_id = f"{scenario['id']}-{seed}-{uuid.uuid4().hex[:8]}"
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    step_log: list[dict] = []
    started_at = now_iso()

    for step_index, step in enumerate(scenario["steps"]):
        repeat_raw = step.get("repeat", 1)
        repeats = intensity if repeat_raw == "${intensity}" else int(repeat_raw)
        source_host = step.get("source_host") or scenario.get("source_host")
        step_user = step.get("source_user") or source_user
        allow_fail = bool(step.get("allow_fail", False))
        delay_s_between = float(step.get("delay_s_between", 0))

        for iteration in range(repeats):
            # Per-iteration PRNG is available to downstream fixture-capture
            # uses even if the current cmd doesn't reference it.
            _ = random.Random(seed_for(scenario["id"], seed, step_index, iteration))
            ctx = {
                "host": target_host,
                "target": target_host,
                "user": step_user,
                "iteration": iteration,
                "intensity": intensity,
            }
            cmd = render(step["cmd"], ctx)
            step_started = now_iso()
            t0 = time.monotonic()
            rc, out, err = docker_exec(source_host, cmd, step_user, dry_run)
            step_log.append(
                {
                    "step_index": step_index,
                    "iteration": iteration,
                    "source_host": source_host,
                    "source_user": step_user,
                    "cmd": cmd,
                    "rc": rc,
                    "stdout_tail": out[-500:],
                    "stderr_tail": err[-500:],
                    "started_at": step_started,
                    "ended_at": now_iso(),
                    "duration_s": round(time.monotonic() - t0, 3),
                }
            )
            if rc != 0 and not allow_fail and not dry_run:
                finished_at = now_iso()
                _write_meta(run_dir, scenario, seed, overrides, started_at, finished_at, step_log, aborted=True)
                raise SystemExit(
                    f"step {step_index}.{iteration} failed rc={rc} (allow_fail=false); "
                    f"aborted; meta → {run_dir / 'meta.json'}"
                )
            if delay_s_between and iteration + 1 < repeats and not dry_run:
                time.sleep(delay_s_between)

    finished_at = now_iso()
    _write_meta(run_dir, scenario, seed, overrides, started_at, finished_at, step_log, aborted=False)
    return run_id, run_dir, step_log


def _write_meta(
    run_dir: Path,
    scenario: dict,
    seed: int,
    overrides: dict[str, Any],
    started_at: str,
    finished_at: str,
    step_log: list[dict],
    aborted: bool,
) -> None:
    meta = {
        "run_id": run_dir.name,
        "scenario_id": scenario["id"],
        "category": scenario["category"],
        "description": scenario["description"].strip(),
        "seed": seed,
        "overrides": {k: v for k, v in overrides.items() if v is not None},
        "resolved": {
            "intensity": int(overrides.get("intensity") or scenario.get("default_intensity", 1)),
            "source_user": overrides.get("user") or scenario.get("source_user", "root"),
            "target_host": overrides.get("target") or scenario["target_host"],
        },
        "started_at": started_at,
        "finished_at": finished_at,
        "aborted": aborted,
        "steps": step_log,
    }
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))


def cmd_list(args: argparse.Namespace) -> int:
    catalog = load_catalog()
    for scenario in catalog.values():
        desc = " ".join(scenario["description"].split())
        print(f"{scenario['id']:32s} [{scenario['category']}]")
        print(f"  target={scenario['target_host']} source={scenario.get('source_host','?')} "
              f"as={scenario.get('source_user','root')} intensity={scenario.get('default_intensity',1)}")
        print(f"  {desc[:160]}")
        print()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    catalog = load_catalog()
    if args.scenario not in catalog:
        print(f"unknown scenario: {args.scenario}", file=sys.stderr)
        print(f"available: {', '.join(sorted(catalog))}", file=sys.stderr)
        return 2
    scenario = catalog[args.scenario]
    overrides = {
        "user": args.user,
        "target": args.target,
        "intensity": args.intensity,
    }
    print(f"running {scenario['id']} (seed={args.seed}) ...")
    run_id, run_dir, step_log = run_scenario(scenario, args.seed, overrides, args.dry_run)
    ok = sum(1 for s in step_log if s["rc"] == 0)
    print(f"finished: run_id={run_id} steps={len(step_log)} ok={ok}")
    print(f"meta → {run_dir / 'meta.json'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list scenarios in catalog.yaml")

    prun = sub.add_parser("run", help="run a scenario")
    prun.add_argument("scenario", help="scenario id (see `list`)")
    prun.add_argument("--seed", type=int, default=42, help="PRNG seed (default 42)")
    prun.add_argument("--user", help="override source_user")
    prun.add_argument("--target", help="override target_host")
    prun.add_argument("--intensity", type=int, help="override default_intensity")
    prun.add_argument("--dry-run", action="store_true", help="print dispatches without running")

    args = parser.parse_args()
    if args.command == "list":
        return cmd_list(args)
    if args.command == "run":
        return cmd_run(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
