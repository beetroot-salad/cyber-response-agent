#!/usr/bin/env python3
"""Gather-only harness: dispatch ONE gather lead in isolation (no main loop).

Mirrors the live dispatch exactly — same 40-request cap, same adapter-capture
hooks, same descriptor catalog + dispatch prompt — via tools._run_gather, the
seam already factored out "so it's testable without the main model". Used to
A/B the gather SKILL deterministically on a single lead, off the loop-count
nondeterminism of a full run.

    python3 scripts/gather_only.py <run_id> [lead_key]

lead_key selects a canned lead (default: baseline-7d, the one that crashed Haiku).
"""
from __future__ import annotations
import asyncio
import json
import os
import sys
from pathlib import Path

DEFENDER_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(DEFENDER_DIR.parent))

from defender import run as _run  # noqa: E402
from defender.runtime import driver, observe  # noqa: E402
from defender.runtime.tools import RunDeps, _run_gather, _gather_prompt  # noqa: E402
import defender.run_pai as run_pai  # noqa: E402

# Canned leads taken verbatim from the gsplit-haiku-1 crash run's leads table.
LEADS = {
    "baseline-7d": dict(
        system="elastic",
        goal=("Retrieve dev.dana's sshd authentication baseline over the past 7 days "
              "to characterize normal source hosts, destination hosts, auth methods, "
              "and timing patterns — to grade whether the alert-time behavior is a "
              "deviation."),
        what_to_summarize=[
            "distinct source hosts dev.dana authenticates from",
            "distinct destination hosts dev.dana authenticates to",
            "auth methods observed (password vs publickey vs certificate)",
            "typical time-of-day for auth events",
            "any prior cross-tier (workstation to prod) events in the 7d window",
            "frequency of sshd events per day",
            "any failures or novel destinations in the 7d window",
        ],
    ),
    # Elastic, WITH a template — a src_ip -> host pair baseline maps 1:1 to the
    # sshd-baseline-7d template's measurement (${src_ip}, ${host}), so the finder
    # binds the template rather than coining. (The user-scoped baseline-7d lead
    # above does NOT match it — the template is IP->host-pair scoped — so the
    # finder coins there; that is correct behavior, not a template-path test.)
    "ip-host-baseline": dict(
        system="elastic",
        goal=("Establish the 7-day pre-alert sshd authentication baseline for source IP "
              "172.18.0.14 connecting to host db-1 (the prod pivot target), anchored at "
              "the alert timestamp 2026-05-25T13:53:35Z and excluding the alert window, to "
              "judge whether the alert-time auth volume and methods are a departure from normal."),
        what_to_summarize=[
            "count of Accepted vs Failed sshd auth events from 172.18.0.14 to db-1 over the 7d window",
            "auth methods observed historically (password / publickey / gssapi) and relative counts",
            "whether 172.18.0.14 has any prior auth history to db-1 (zero-vs-nonzero baseline)",
        ],
    ),
    # Elastic, NO template — host-level process execution has no catalog
    # template (container-process-ancestry is falco/container-scoped), so the
    # finder must coin the query → Sonnet executor (the ad-hoc path).
    "process-db1": dict(
        system="elastic",
        goal=("Characterize the process-execution events on prod host db-1 during the "
              "15-minute cross-tier pivot window (2026-05-25 13:38:00Z–13:53:35Z) — what "
              "commands and processes ran after dev.dana's sshd login on the target, to "
              "assess hands-on-keyboard activity following the pivot."),
        what_to_summarize=[
            "distinct process names executed on db-1 in the window",
            "parent/child process relationships (what spawned what)",
            "any shell, network, or recon tools (bash, sh, curl, wget, nc, ss, netstat, nmap)",
            "command-line arguments where present",
            "total process-event count and the timing span",
        ],
    ),
    # Non-elastic (cmdb) WITH a template — host-trust-edges via the `get-host`
    # positional verb. Exercises the cross-system executor path (positional
    # verb + injected execution.md), the documented gap.
    "host-posture": dict(
        system="cmdb",
        goal=("Establish the CMDB inventory posture of prod host db-1 — the cross-tier "
              "pivot target — its role, criticality, owner, and declared outbound trust "
              "edges, and whether a dev/office workstation appears among them, to judge "
              "whether dev.dana's cross-tier access path is sanctioned."),
        what_to_summarize=[
            "db-1 role (from CMDB record)",
            "db-1 criticality (sandbox / dev / preprod / prod)",
            "db-1 owner team",
            "db-1 trust_edges_out (full list of declared outbound targets)",
            "whether any dev-ws-* / office-ws-* workstation appears in db-1's trust_edges_out",
        ],
    ),
}


async def main() -> int:
    run_id = sys.argv[1]
    lead = LEADS[sys.argv[2] if len(sys.argv) > 2 else "baseline-7d"]

    key, src = run_pai.resolve_first_party_key(DEFENDER_DIR)
    if not key:
        print("[gather_only] no first-party key", file=sys.stderr)
        return 2
    os.environ["ANTHROPIC_API_KEY"] = key

    alert = DEFENDER_DIR / "fixtures/v2-cross-tier-ssh-pivot/alert.json"
    run_dir = _run.materialize_run_dir(alert, run_id)
    salt = json.loads((run_dir / "meta.json").read_text()).get("salt", "")
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    deps = RunDeps(run_dir=run_dir, defender_dir=DEFENDER_DIR, run_id=run_id,
                   salt=salt, is_main_session=True)

    # DEFENDER_GATHER_LEAN selects the issue #340 lean single-agent path
    # (SKILL.lean.md, one ES|QL aggregation, no finder/executor split) over the
    # split. Same lead dispatch + capture hooks, so the two are A/B-comparable.
    lean = bool(os.environ.get("DEFENDER_GATHER_LEAN"))
    if lean:
        def factory(agent_id: str):
            return driver.build_lean_gather_agent(DEFENDER_DIR, logger, agent_id)
        engine, request_limit, run_kwargs = (
            "LEAN", driver.GATHER_REQUEST_LIMIT,
            dict(role="executor", prompt_fn=_gather_prompt),
        )
    else:
        def factory(agent_id: str):
            return driver.build_finder_agent(DEFENDER_DIR, logger, agent_id)
        engine, request_limit, run_kwargs = (
            "SPLIT", driver.FINDER_REQUEST_LIMIT, {},
        )

    print(f"[gather_only] engine={engine} run_dir={run_dir} "
          f"gather_model={driver._gather_model()} "
          f"finder_model={driver._finder_model()}", file=sys.stderr)
    try:
        out = await _run_gather(deps, factory, request_limit,
                                "l-001", lead["system"], lead["goal"],
                                lead["what_to_summarize"], **run_kwargs)
        print("=== GATHER SUMMARY (unwrapped head) ===")
        print(out[:1200])
        print("[gather_only] OK", run_id)
        return 0
    except Exception as e:  # noqa: BLE001 — surface the crash class loudly
        print(f"[gather_only] CRASHED: {type(e).__name__}: {str(e)[:300]}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
