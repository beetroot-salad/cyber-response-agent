"""Parallel-gather stress test.

Replays the gather phase of run `20260425-123706-rule100001` (control:
gather-composite, 2 leads, 165s wall) as N parallel single-`gather` subagent
dispatches and reports the cost/quality delta.

Usage:
    SOC_AGENT_SIEM_ADAPTER=wazuh \
    soc-agent/.venv/bin/python3 tasks-scratch/parallel-gather-experiment.py

Output:
    /tmp/parallel-gather-exp-<ts>/  (full run dir mirror)
    /tmp/parallel-gather-exp-<ts>/SUMMARY.md  (side-by-side metrics)
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent / "soc-agent"
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers._context_loader import load_lead_definition  # noqa: E402
from scripts.handlers._subagent import invoke_subagent  # noqa: E402
from scripts.handlers.gather import (  # noqa: E402
    Scope,
    _assemble_prompt_single,
    _parse_envelope_response,
)

CONTROL_RUN = Path(
    "/tmp/soc-agent-orchestrate-eval/20260425-123706-rule100001/runs/"
    "8074230b-20ba-4b4f-976e-47002ad59469"
)


# --- minimal Context shim (matches the field set _assemble_prompt_single uses)
@dataclass
class CtxShim:
    run_dir: Path
    signature_id: str


def setup_experiment_dir() -> Path:
    """Create a fresh run dir mirroring the control's pre-GATHER state."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    exp_root = Path(f"/tmp/parallel-gather-exp-{ts}")
    run_dir = exp_root / "runs" / "exp-uuid"
    run_dir.mkdir(parents=True, exist_ok=True)

    # Copy state files the gather subagent / hooks need.
    for fname in ("alert.json", "meta.json"):
        src = CONTROL_RUN / fname
        if src.exists():
            shutil.copy(src, run_dir / fname)

    # Snapshot investigation.md as it stood at GATHER dispatch time —
    # truncate at the GATHER section since that's what the gather subagent's
    # context-loader would have seen mid-run (we want pre-loop-1-GATHER
    # state). Easiest: copy as-is. The gather subagent doesn't actually
    # consume investigation.md at dispatch, so this is a lower bound on
    # fidelity; it matters only if any hook reads it.
    inv = CONTROL_RUN / "investigation.md"
    if inv.exists():
        shutil.copy(inv, run_dir / "investigation.md")

    # Required dirs for hooks.
    (run_dir / "raw_query_outputs").mkdir(exist_ok=True)
    (run_dir / "subagent_outputs").mkdir(exist_ok=True)
    (run_dir / "raw_details").mkdir(exist_ok=True)

    # state.json — mark phase=GATHER so any state-reading hook is content.
    state = {
        "run_id": "exp-uuid",
        "ticket_id": "",
        "signature_id": "wazuh-rule-100001",
        "phase": "GATHER",
        "history": ["CONTEXTUALIZE", "PREDICT"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    (run_dir / "state.json").write_text(json.dumps(state, indent=2))
    return run_dir


def build_lead_scopes() -> tuple[list[Scope], dict[str, str]]:
    """Return the two prescribed leads from PREDICT-loop-1 as Scope objects."""
    # From predict-loop-1.yaml.routing.lead_hints:
    lead_hints = {
        "container-baseline": (
            "Query rule-100001 events for container image "
            "cyber-response-agent_devcontainer-target-endpoint:latest. "
            "Characterize: count of prior events with runc as parent, "
            "cadence, and any variation in cmdline shape across events. "
            "This establishes whether runc-parent shells are a recurring "
            "pattern for this image."
        ),
        "correlated-endpoint-events": (
            "Query Falco rules 100000-100099 from container.id=7bd5857e8d0b "
            "in a ±15-minute window around 2026-04-25T12:36:25Z. Surface "
            "any co-fires of rules 100002 (stdout/stdin redirect), 100006 "
            "(sensitive file read), 100007 (drop-and-exec), or 100008 "
            "(log clearing) — playbook composition rule requires "
            "escalation if any appear in the same container window."
        ),
    }

    # PREDICT scope_override: window_hours=168, anchor=alert (alert ts =
    # 2026-04-25T12:36:25Z).
    incident_end = "2026-04-25T12:36:25Z"
    incident_start = "2026-04-18T12:36:25Z"  # 168h back

    base_bindings = {
        "container": "7bd5857e8d0b",
        "image": "cyber-response-agent_devcontainer-target-endpoint:latest",
        "host": "wazuh.manager",
    }

    scopes = [
        Scope(
            lead_name="container-baseline",
            vendor="wazuh",
            reporting_agent="wazuh.manager",
            incident_start=incident_start,
            incident_end=incident_end,
            entity_bindings=base_bindings,
            template_exists=False,
        ),
        Scope(
            lead_name="correlated-endpoint-events",
            vendor="wazuh",
            reporting_agent="wazuh.manager",
            incident_start="2026-04-25T12:21:25Z",  # ±15 min around alert
            incident_end="2026-04-25T12:51:25Z",
            entity_bindings=base_bindings,
            template_exists=(
                SOC_AGENT_ROOT / "knowledge" / "common-investigation"
                / "leads" / "correlated-endpoint-events"
                / "templates" / "wazuh.md"
            ).exists(),
        ),
    ]
    return scopes, lead_hints


def dispatch_one(
    ctx: CtxShim, scope: Scope, lead_hints: dict[str, str], loop_n: int
) -> dict:
    """Run one gather subagent; return metrics + parsed envelope."""
    prompt = _assemble_prompt_single(
        ctx, scope, loop_n, lead_hint=lead_hints.get(scope.lead_name),
    )
    started = time.monotonic()
    stdout = invoke_subagent("gather", prompt, timeout=450)
    duration_s = time.monotonic() - started
    envelope = _parse_envelope_response(stdout, loop_n=loop_n, mode="single")
    return {
        "lead_name": scope.lead_name,
        "duration_s": round(duration_s, 1),
        "prompt_chars": len(prompt),
        "stdout_chars": len(stdout),
        "envelope": envelope.__dict__ if envelope else None,
        "stdout": stdout,
    }


def main() -> int:
    print("=== parallel-gather stress test ===")
    if not CONTROL_RUN.exists():
        print(f"control run dir missing: {CONTROL_RUN}", file=sys.stderr)
        return 1
    if not os.environ.get("SOC_AGENT_SIEM_ADAPTER"):
        os.environ["SOC_AGENT_SIEM_ADAPTER"] = "wazuh"
    os.environ["SOC_AGENT_SIGNATURE_ID"] = "wazuh-rule-100001"

    run_dir = setup_experiment_dir()
    os.environ["SOC_AGENT_RUN_DIR"] = str(run_dir)
    print(f"experiment run_dir: {run_dir}")

    scopes, lead_hints = build_lead_scopes()
    ctx = CtxShim(run_dir=run_dir, signature_id="wazuh-rule-100001")

    print(
        f"dispatching {len(scopes)} gather subagents in parallel: "
        + ", ".join(s.lead_name for s in scopes)
    )
    wall_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(scopes)) as pool:
        futures = [
            pool.submit(dispatch_one, ctx, s, lead_hints, 1) for s in scopes
        ]
        results = [f.result() for f in futures]
    wall_total = round(time.monotonic() - wall_start, 1)

    # Build a synthesized envelope (concatenate leads).
    synthesized_leads = []
    for r in results:
        env = r.get("envelope") or {}
        synthesized_leads.extend(env.get("leads") or [])
    synthesized = {
        "gather": {
            "loop": 1,
            "leads": synthesized_leads,
        },
    }
    (run_dir / "synthesized_envelope.yaml").write_text(
        yaml.safe_dump(synthesized, sort_keys=False)
    )

    # Pull control metrics from the control run dir.
    audit_lines = (CONTROL_RUN / "subagent_audit.jsonl").read_text().splitlines()
    control_gc = next(
        (
            json.loads(line) for line in audit_lines
            if json.loads(line).get("agent") == "gather-composite"
        ),
        None,
    )

    # Write summary.
    lines = [
        "# parallel-gather stress test — results",
        "",
        f"experiment run dir: `{run_dir}`",
        "",
        "## Control (gather-composite, single dispatch)",
        "",
        f"- agent: `gather-composite` (sonnet)",
    ]
    if control_gc:
        lines += [
            f"- duration: {control_gc['duration_ms']/1000:.1f}s",
            f"- prompt_chars: {control_gc['prompt_chars']}",
            f"- stdout_chars: {control_gc['stdout_chars']}",
            f"- leads emitted: 2 (container-baseline + correlated-endpoint-events)",
        ]
    lines += [
        "",
        "## Experiment (gather x N, parallel)",
        "",
        f"- agent: `gather` (sonnet) × {len(results)}",
        f"- wall (max of parallel dispatches): {wall_total}s",
    ]
    sum_prompt = sum(r["prompt_chars"] for r in results)
    sum_stdout = sum(r["stdout_chars"] for r in results)
    lines += [
        f"- sum(prompt_chars): {sum_prompt}",
        f"- sum(stdout_chars): {sum_stdout}",
        "",
        "### Per-lead breakdown",
        "",
        "| lead | duration | prompt_chars | stdout_chars | leads_in_envelope |",
        "|------|---------:|-------------:|-------------:|------------------:|",
    ]
    for r in results:
        env = r.get("envelope") or {}
        n_leads = len(env.get("leads") or [])
        lines.append(
            f"| {r['lead_name']} | {r['duration_s']}s | "
            f"{r['prompt_chars']} | {r['stdout_chars']} | {n_leads} |"
        )

    if control_gc:
        wall_delta_pct = (
            (wall_total - control_gc["duration_ms"] / 1000)
            / (control_gc["duration_ms"] / 1000) * 100
        )
        prompt_delta_pct = (
            (sum_prompt - control_gc["prompt_chars"])
            / control_gc["prompt_chars"] * 100
        )
        stdout_delta_pct = (
            (sum_stdout - control_gc["stdout_chars"])
            / control_gc["stdout_chars"] * 100
        )
        lines += [
            "",
            "## Headline deltas (experiment vs control)",
            "",
            f"- wall: **{wall_delta_pct:+.0f}%**  "
            f"({wall_total}s vs {control_gc['duration_ms']/1000:.1f}s)",
            f"- prompt_chars: **{prompt_delta_pct:+.0f}%**  "
            f"({sum_prompt} vs {control_gc['prompt_chars']})",
            f"- stdout_chars: **{stdout_delta_pct:+.0f}%**  "
            f"({sum_stdout} vs {control_gc['stdout_chars']})",
        ]

    summary = "\n".join(lines) + "\n"
    summary_path = run_dir.parent.parent / "SUMMARY.md"
    summary_path.write_text(summary)
    print()
    print(summary)
    print(f"summary saved: {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
