#!/usr/bin/env python3
"""Set up the investigation run directory and save alert data.

Usage: python3 scripts/setup_run.py <signature_id> <alert_json>

Creates:
  {SOC_AGENT_RUNS_DIR:-runs}/{uuid}/alert.json

Prints run metadata to stdout for !command substitution in SKILL.md.

Exit codes:
  0 — success
  1 — invalid arguments or malformed alert JSON
"""

import json
import os
import sys
import uuid
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <signature_id> <alert_json>", file=sys.stderr)
        return 1

    signature_id = sys.argv[1]
    alert_json_str = sys.argv[2]

    # Parse alert JSON
    try:
        alert = json.loads(alert_json_str)
    except json.JSONDecodeError as e:
        print(f"Error: malformed alert JSON: {e}", file=sys.stderr)
        return 1

    if not isinstance(alert, dict):
        print("Error: alert_json must be a JSON object", file=sys.stderr)
        return 1

    # Generate a neutral run ID — decoupled from alert field names
    run_id = str(uuid.uuid4())

    # Build run directory path
    runs_base = Path(
        os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs"))
    )
    run_dir = runs_base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Save alert.json
    alert_file = run_dir / "alert.json"
    alert_file.write_text(json.dumps(alert, indent=2))

    # Output for skill substitution
    print(f"Run directory: {run_dir}")
    print(f"Run ID: {run_id}")
    print(f"Signature: {signature_id}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
