"""Parallel-gather stress test #2 — both leads on-disk + wazuh templates.

Fixture: rule 5710 monitoring_probe.sh alert (just triggered).
Leads: authentication-history + network-analysis (both have on-disk
definition.md + wazuh.md template; both can be dispatched as singleton
gather agents under the proposed routing rule).

Runs BOTH:
- Experiment: 2x parallel `gather` (haiku) singletons.
- Control:    1x `gather-composite` (sonnet) on the same 2 leads.

Side-by-side cost/quality comparison written to SUMMARY.md.

Usage:
    SOC_AGENT_SIEM_ADAPTER=wazuh \
    soc-agent/.venv/bin/python3 tasks-scratch/parallel-gather-experiment-2.py
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

from scripts.handlers._subagent import invoke_subagent  # noqa: E402
from scripts.handlers.gather import (  # noqa: E402
    Scope,
    _assemble_prompt_single,
    _assemble_prompt_composite,
    _parse_envelope_response,
)

ALERT_PATH = Path("/tmp/5710-alert.json")


@dataclass
class CtxShim:
    run_dir: Path
    signature_id: str


def setup_run_dir(label: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    root = Path(f"/tmp/parallel-gather-exp2-{ts}-{label}")
    run_dir = root / "runs" / "exp-uuid"
    run_dir.mkdir(parents=True, exist_ok=True)
    if ALERT_PATH.exists():
        shutil.copy(ALERT_PATH, run_dir / "alert.json")
    (run_dir / "raw_query_outputs").mkdir(exist_ok=True)
    (run_dir / "subagent_outputs").mkdir(exist_ok=True)
    (run_dir / "raw_details").mkdir(exist_ok=True)
    (run_dir / "investigation.md").write_text(
        "# Investigation\n\n## CONTEXTUALIZE\n\nfixture for parallel-gather-2.\n"
    )
    (run_dir / "state.json").write_text(json.dumps({
        "run_id": "exp-uuid",
        "ticket_id": "",
        "signature_id": "wazuh-rule-5710",
        "phase": "GATHER",
        "history": ["CONTEXTUALIZE", "PREDICT"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }))
    return run_dir


def build_scopes() -> tuple[list[Scope], dict[str, str], str, str]:
    """Two on-disk-definition leads from rule 5710 scenario A."""
    # Alert is ~13:33Z; use ±5min window for cross-verification.
    incident_end = "2026-04-25T13:38:00Z"
    incident_start = "2026-04-25T12:33:00Z"  # 65min back

    bindings = {
        "ip": "172.22.0.10",
        "user": "nagios",
        "host": "target-endpoint",
        "dst_ip": "172.22.0.13",
        "port": "22",
    }

    auth = Scope(
        lead_name="authentication-history",
        vendor="wazuh",
        reporting_agent="target-endpoint",
        incident_start=incident_start,
        incident_end=incident_end,
        entity_bindings=bindings,
        template_exists=True,
    )
    net = Scope(
        lead_name="network-analysis",
        vendor="wazuh",
        reporting_agent="target-endpoint",
        incident_start="2026-04-25T13:18:00Z",
        incident_end="2026-04-25T13:48:00Z",
        entity_bindings=bindings,
        template_exists=True,
    )

    hints = {
        "authentication-history": (
            "Survey 5710 events from srcip 172.22.0.10 over the past 65 minutes. "
            "Characterize: per-srcuser counts, cadence pattern (regular vs burst), "
            "whether all attempted usernames belong to the monitoring sentinel set "
            "(nagios/zabbix/healthcheck/monitorprobe/sensu) or include non-sentinel "
            "names. Establishes whether the alert sits in a stable monitoring cadence "
            "or is an outlier."
        ),
        "network-analysis": (
            "Survey network telemetry for srcip 172.22.0.10 → dst_ip 172.22.0.13 "
            "port 22 in the ±15min window around the alert. Characterize: connection "
            "rate, distinct srcports, whether traffic shape matches expected "
            "monitoring-probe profile or shows brute-force burst patterns."
        ),
    }
    return [auth, net], hints, incident_start, incident_end


def dispatch_singleton(ctx: CtxShim, scope: Scope, hints: dict[str, str]) -> dict:
    prompt = _assemble_prompt_single(
        ctx, scope, 1, lead_hint=hints.get(scope.lead_name),
    )
    started = time.monotonic()
    stdout = invoke_subagent("gather", prompt, timeout=450)
    duration = time.monotonic() - started
    env = _parse_envelope_response(stdout, loop_n=1, mode="single")
    return {
        "lead": scope.lead_name,
        "duration_s": round(duration, 1),
        "prompt_chars": len(prompt),
        "stdout_chars": len(stdout),
        "envelope": env.__dict__ if env else None,
        "stdout": stdout,
    }


def dispatch_composite_control(
    ctx: CtxShim, scopes: list[Scope], hints: dict[str, str]
) -> dict:
    primary, *secondary = scopes
    prompt = _assemble_prompt_composite(
        ctx, primary, 1, mode="initial",
        lead_hints=hints,
        secondary_scopes=secondary,
    )
    started = time.monotonic()
    stdout = invoke_subagent("gather-composite", prompt, timeout=450)
    duration = time.monotonic() - started
    env = _parse_envelope_response(stdout, loop_n=1, mode="composite")
    return {
        "duration_s": round(duration, 1),
        "prompt_chars": len(prompt),
        "stdout_chars": len(stdout),
        "envelope": env.__dict__ if env else None,
        "stdout": stdout,
    }


def main() -> int:
    print("=== parallel-gather stress test #2 (both leads on-disk) ===")
    if not ALERT_PATH.exists():
        print(f"alert fixture missing: {ALERT_PATH}", file=sys.stderr)
        return 1
    os.environ.setdefault("SOC_AGENT_SIEM_ADAPTER", "wazuh")
    os.environ["SOC_AGENT_SIGNATURE_ID"] = "wazuh-rule-5710"

    scopes, hints, _, _ = build_scopes()

    # ---- Experiment: parallel singletons ----
    exp_run = setup_run_dir("exp")
    os.environ["SOC_AGENT_RUN_DIR"] = str(exp_run)
    exp_ctx = CtxShim(run_dir=exp_run, signature_id="wazuh-rule-5710")
    print(f"\n[experiment] dispatching {len(scopes)} parallel singletons")
    exp_wall_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(scopes)) as pool:
        results = [
            f.result() for f in [
                pool.submit(dispatch_singleton, exp_ctx, s, hints) for s in scopes
            ]
        ]
    exp_wall = round(time.monotonic() - exp_wall_start, 1)

    # ---- Control: serial gather-composite on the same set ----
    ctl_run = setup_run_dir("ctl")
    os.environ["SOC_AGENT_RUN_DIR"] = str(ctl_run)
    ctl_ctx = CtxShim(run_dir=ctl_run, signature_id="wazuh-rule-5710")
    print(f"[control]    dispatching gather-composite ({len(scopes)} leads serial)")
    ctl_wall_start = time.monotonic()
    control = dispatch_composite_control(ctl_ctx, scopes, hints)
    ctl_wall = round(time.monotonic() - ctl_wall_start, 1)

    # ---- Synthesize experiment envelope ----
    syn_leads: list[dict] = []
    for r in results:
        env = r.get("envelope") or {}
        syn_leads.extend(env.get("leads") or [])
    (exp_run / "synthesized_envelope.yaml").write_text(
        yaml.safe_dump({"gather": {"loop": 1, "leads": syn_leads}}, sort_keys=False)
    )

    # ---- Metrics ----
    sum_prompt = sum(r["prompt_chars"] for r in results)
    sum_stdout = sum(r["stdout_chars"] for r in results)
    exp_lead_status = [
        ((r.get("envelope") or {}).get("leads") or [{}])[0].get("status", "?")
        for r in results
    ]
    ctl_envelope = control.get("envelope") or {}
    ctl_lead_status = [lead.get("status", "?") for lead in (ctl_envelope.get("leads") or [])]

    lines = [
        "# parallel-gather stress test #2 — both leads on-disk + wazuh",
        "",
        f"experiment dir: `{exp_run}`",
        f"control dir:    `{ctl_run}`",
        "",
        "Leads: authentication-history + network-analysis",
        "Both have on-disk definition.md + wazuh templates.",
        "",
        "## Headline",
        "",
        "| metric | control (gather-composite) | experiment (gather × 2 parallel) | Δ |",
        "|---|---:|---:|---:|",
    ]

    def pct(a: float, b: float) -> str:
        if b == 0:
            return "n/a"
        return f"{(a - b) / b * 100:+.0f}%"

    lines += [
        f"| wall (s) | {ctl_wall} | {exp_wall} | **{pct(exp_wall, ctl_wall)}** |",
        f"| Σ prompt_chars | {control['prompt_chars']} | {sum_prompt} | "
        f"{pct(sum_prompt, control['prompt_chars'])} |",
        f"| Σ stdout_chars | {control['stdout_chars']} | {sum_stdout} | "
        f"{pct(sum_stdout, control['stdout_chars'])} |",
        f"| lead statuses | {ctl_lead_status} | {exp_lead_status} | — |",
        "",
        "## Per-lead (experiment)",
        "",
        "| lead | duration | prompt | stdout | status |",
        "|---|---:|---:|---:|---|",
    ]
    for r, st in zip(results, exp_lead_status):
        lines.append(
            f"| {r['lead']} | {r['duration_s']}s | {r['prompt_chars']} | "
            f"{r['stdout_chars']} | {st} |"
        )

    summary_path = exp_run.parent.parent / "SUMMARY.md"
    summary = "\n".join(lines) + "\n"
    summary_path.write_text(summary)
    print()
    print(summary)
    print(f"summary saved: {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
