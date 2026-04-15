#!/usr/bin/env python3
"""Single Stop-event entrypoint — composes the Stop-stage steps in order.

plugin.json registers exactly one Stop hook entry pointing at this script.
It reads the Stop payload once from stdin, then invokes each step module's
`main(payload)` function in explicit order:

    1. investigation_summary — append outcome row to runs/audit.jsonl
    2. close_ticket_action   — deterministic close-ticket dispatch

Ordering is guaranteed because it's composed in Python, not delegated to
the harness's hook-serialization semantics. Two hooks touching the same
run directory in undefined order would be a race; composing them in one
entrypoint removes the race.

Every step is wrapped in try/except so a failure in one does not prevent
the next from running. The handler always exits 0 — a broken Stop step
must never crash the agent session.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts import close_ticket_action, investigation_summary  # noqa: E402


def _run_step(name: str, func, payload: dict) -> None:
    try:
        func(payload)
    except Exception as exc:  # noqa: BLE001 — must never raise out of the handler
        print(f"stop_handler: {name} raised: {exc!r}", file=sys.stderr)


def main() -> None:
    raw = ""
    try:
        if not sys.stdin.isatty():
            raw = sys.stdin.read()
    except Exception:
        raw = ""

    payload: dict = {}
    if raw.strip():
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {}
        if isinstance(parsed, dict):
            payload = parsed

    _run_step("investigation_summary", investigation_summary.main, payload)
    _run_step("close_ticket_action", close_ticket_action.main, payload)


if __name__ == "__main__":
    main()
    sys.exit(0)
