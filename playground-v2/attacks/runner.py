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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

HERE = Path(__file__).resolve().parent
CATALOG_PATH = HERE / "catalog.yaml"
INVENTORY_PATH = HERE.parent / "hosts" / "inventory.yaml"
RUNS_DIR = HERE / "runs"
DOCKER_CONTEXT = "soc-playground"
CR_MODES = ("none", "valid", "stale", "scope-mismatch")
CHANGE_MGMT_CONTAINER = "change-mgmt"


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


def _load_inventory() -> dict[str, Any]:
    return yaml.safe_load(INVENTORY_PATH.read_text())


def _sibling_host(target_host: str, inv: dict[str, Any]) -> str:
    """Pick a host distinct from target_host for scope-mismatch CRs.

    Prefer a peer in the same inventory role (web-2 if target is web-1); if the
    role has no peers (e.g., db-1 is the sole db), fall back to canary-1 — the
    sandbox host is the safe out-of-tier pick.
    """
    hosts = inv.get("hosts") or []
    target_role = next((h.get("role") for h in hosts if h.get("name") == target_host), None)
    if target_role:
        siblings = [h["name"] for h in hosts if h.get("role") == target_role and h["name"] != target_host]
        if siblings:
            return siblings[0]
    for h in hosts:
        if h.get("name") not in (target_host, None) and h.get("role") == "canary":
            return h["name"]
    others = [h["name"] for h in hosts if h.get("name") != target_host]
    if not others:
        raise SystemExit("inventory has no host distinct from target — cannot synthesize scope-mismatch CR")
    return others[0]


def _build_cr_body(
    cr_mode: str,
    run_id: str,
    target_host: str,
    source_user: str,
    scenario_id: str,
    inv: dict[str, Any],
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    short = run_id.rsplit("-", 1)[-1]
    cr_id = f"CHG-RUNNER-{short}"
    if cr_mode == "valid":
        hosts = [target_host]
        window_start = now - timedelta(minutes=5)
        window_end = now + timedelta(minutes=30)
    elif cr_mode == "stale":
        hosts = [target_host]
        window_start = now - timedelta(hours=3)
        window_end = now - timedelta(hours=1)
    elif cr_mode == "scope-mismatch":
        hosts = [_sibling_host(target_host, inv)]
        window_start = now - timedelta(minutes=5)
        window_end = now + timedelta(minutes=30)
    else:
        raise ValueError(f"unsupported cr_mode {cr_mode!r}")
    return {
        "id": cr_id,
        "summary": f"Synthetic CR for attack run {scenario_id} ({cr_mode})",
        "description": (
            f"Posted by attacks/runner.py with --cr-mode={cr_mode}. "
            "Synthetic — exists to exercise the agent's CR scope-check, not real change governance."
        ),
        "status": "in_progress",
        "requester": source_user,
        "approver": "change-board",
        "hosts": hosts,
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "ticket_ref": f"RUNNER-{short}",
    }


def _post_cr(body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """POST the CR via `docker exec change-mgmt python -c …`.

    Uses the python:3.12-slim base image's stdlib urllib — no Docker network
    plumbing from the devcontainer needed, no SSH tunnel precondition.
    Returns (rc, parsed_response_or_error).
    """
    payload = json.dumps(body)
    script = (
        "import json, sys, urllib.request, urllib.error\n"
        "body = json.loads(sys.stdin.read())\n"
        "req = urllib.request.Request(\n"
        "    'http://127.0.0.1:8080/changes',\n"
        "    data=json.dumps(body).encode(),\n"
        "    headers={'Content-Type': 'application/json'},\n"
        "    method='POST',\n"
        ")\n"
        "try:\n"
        "    with urllib.request.urlopen(req, timeout=5) as resp:\n"
        "        print(resp.read().decode())\n"
        "except urllib.error.HTTPError as e:\n"
        "    sys.stderr.write(e.read().decode())\n"
        "    sys.exit(e.code if e.code < 256 else 1)\n"
    )
    args = [
        "docker", "--context", DOCKER_CONTEXT, "exec", "-i",
        CHANGE_MGMT_CONTAINER, "python", "-c", script,
    ]
    proc = subprocess.run(args, input=payload, capture_output=True, text=True)
    if proc.returncode != 0:
        return proc.returncode, {"error": proc.stderr.strip() or proc.stdout.strip()}
    try:
        return 0, json.loads(proc.stdout)
    except json.JSONDecodeError:
        return 0, {"raw": proc.stdout}


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
    cr_mode: str = "none",
) -> tuple[str, Path, list[dict]]:
    intensity = int(overrides.get("intensity") or scenario.get("default_intensity", 1))
    source_user = overrides.get("user") or scenario.get("source_user", "root")
    target_host = overrides.get("target") or scenario["target_host"]

    run_id = f"{scenario['id']}-{seed}-{uuid.uuid4().hex[:8]}"
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    pre_run: dict[str, Any] = {"cr_mode": cr_mode}
    if cr_mode != "none":
        inv = _load_inventory()
        body = _build_cr_body(cr_mode, run_id, target_host, source_user, scenario["id"], inv)
        pre_run["cr_request"] = body
        if dry_run:
            print(f"DRY-RUN: would POST CR id={body['id']} hosts={body['hosts']} "
                  f"window={body['window_start']}..{body['window_end']}")
            pre_run["cr_post_rc"] = 0
            pre_run["cr_post_response"] = {"dry_run": True}
        else:
            rc, resp = _post_cr(body)
            pre_run["cr_post_rc"] = rc
            pre_run["cr_post_response"] = resp
            if rc != 0:
                raise SystemExit(
                    f"--cr-mode={cr_mode}: POST /changes failed rc={rc} "
                    f"resp={resp}; not firing scenario"
                )
            print(f"posted synthetic CR id={body['id']} hosts={body['hosts']} mode={cr_mode}")

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
                _write_meta(run_dir, scenario, seed, overrides, started_at, finished_at, step_log, pre_run, aborted=True)
                raise SystemExit(
                    f"step {step_index}.{iteration} failed rc={rc} (allow_fail=false); "
                    f"aborted; meta → {run_dir / 'meta.json'}"
                )
            if delay_s_between and iteration + 1 < repeats and not dry_run:
                time.sleep(delay_s_between)

    finished_at = now_iso()
    _write_meta(run_dir, scenario, seed, overrides, started_at, finished_at, step_log, pre_run, aborted=False)
    return run_id, run_dir, step_log


def _write_meta(
    run_dir: Path,
    scenario: dict,
    seed: int,
    overrides: dict[str, Any],
    started_at: str,
    finished_at: str,
    step_log: list[dict],
    pre_run: dict[str, Any],
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
        "pre_run": pre_run,
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
    print(f"running {scenario['id']} (seed={args.seed}, cr_mode={args.cr_mode}) ...")
    run_id, run_dir, step_log = run_scenario(scenario, args.seed, overrides, args.dry_run, args.cr_mode)
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
    prun.add_argument(
        "--cr-mode",
        choices=CR_MODES,
        default="none",
        help=(
            "POST a synthetic CR to change-mgmt before firing. "
            "none (default): no CR. "
            "valid: CR covers target host + current window — authorized-window cover. "
            "stale: CR covers target host but window already closed — tests temporal check. "
            "scope-mismatch: CR covers a sibling host instead — tests host-scope check."
        ),
    )
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
