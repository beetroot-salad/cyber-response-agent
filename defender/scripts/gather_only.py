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
from defender.runtime.tools import RunDeps, _run_gather  # noqa: E402
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

    def factory(agent_id: str):
        return driver.build_finder_agent(DEFENDER_DIR, logger, agent_id)

    print(f"[gather_only] run_dir={run_dir} finder_model={driver._finder_model()} "
          f"executor_model={driver._gather_model()}", file=sys.stderr)
    try:
        out = await _run_gather(deps, factory, driver.FINDER_REQUEST_LIMIT,
                                "l-001", lead["system"], lead["goal"],
                                lead["what_to_summarize"])
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
