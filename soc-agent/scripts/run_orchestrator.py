#!/usr/bin/env python3
"""Driver for the Python state-machine orchestrator.

Replaces the `/investigate` skill entry point with a direct call into
`scripts.orchestrate.run()`. Sets up the run directory (identical to
`setup_run.py`), constructs the `Context`, and dispatches
`default_handlers()`.

Usage:
    python3 scripts/run_orchestrator.py <signature_id> <alert_json>

Requires:
    SOC_AGENT_RUNS_DIR — base directory for run dirs (same contract as
                         setup_run.py).

Prints the orchestrator summary (status + phase history) to stdout on
success. Exits non-zero on orchestration errors.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.orchestrate import Context, OrchestrationError, run  # noqa: E402
from scripts.handlers import default_handlers  # noqa: E402
from scripts.setup_run import read_signature_severity, sanitize_alert  # noqa: E402


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <signature_id> <alert_json>",
            file=sys.stderr,
        )
        return 2

    signature_id = sys.argv[1]
    alert_json_str = sys.argv[2]

    severity = read_signature_severity(signature_id)

    try:
        alert = json.loads(alert_json_str)
    except json.JSONDecodeError as exc:
        print(f"error: malformed alert JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(alert, dict):
        print("error: alert must be a JSON object", file=sys.stderr)
        return 1

    runs_base_val = os.environ.get("SOC_AGENT_RUNS_DIR")
    if not runs_base_val:
        print("error: SOC_AGENT_RUNS_DIR is not set", file=sys.stderr)
        return 1
    runs_base = Path(runs_base_val)

    run_id = str(uuid.uuid4())
    run_dir = runs_base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    alert = sanitize_alert(alert)

    (run_dir / "alert.json").write_text(json.dumps(alert, indent=2))
    (run_dir / "meta.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "signature_id": signature_id,
                "severity": severity,
                "salt": secrets.token_hex(8),
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        )
    )

    ticket_id = alert.get("id") or ""
    if not ticket_id:
        print(
            "error: alert missing top-level 'id' field — cannot resolve ticket_id",
            file=sys.stderr,
        )
        return 1

    ctx = Context(
        run_dir=run_dir,
        signature_id=signature_id,
        ticket_id=ticket_id,
        alert=alert,
    )

    print(f"[orchestrator] run_id={run_id}")
    print(f"[orchestrator] run_dir={run_dir}")
    print(f"[orchestrator] signature_id={signature_id}")
    print(f"[orchestrator] ticket_id={ticket_id}")
    print(f"[orchestrator] severity={severity}")
    sys.stdout.flush()

    try:
        summary = run(ctx, default_handlers())
    except OrchestrationError as exc:
        print(f"[orchestrator] FAILED: {exc}", file=sys.stderr)
        return 1

    print()
    print(f"[orchestrator] status: {summary['status']}")
    print(f"[orchestrator] history: {' -> '.join(summary['history'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
