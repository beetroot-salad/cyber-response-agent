#!/usr/bin/env python3
"""Set up the investigation run directory and save alert data.

Usage: python3 scripts/setup_run.py <signature_id> <alert_json>

Creates:
  {SOC_AGENT_RUNS_DIR:-runs}/{uuid}/alert.json
  {SOC_AGENT_RUNS_DIR:-runs}/{uuid}/meta.json  (run_id, signature_id, salt)

Prints run metadata to stdout for !command substitution in SKILL.md.

Exit codes:
  0 — success
  1 — invalid arguments or malformed alert JSON
"""

import json
import os
import re
import secrets
import sys
import uuid
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Static sanitization — protects human reviewers and structural plumbing.
# Does NOT stop semantic injection (LLMs understand language regardless).
# See docs/design-v3-architecture.md §8.2 for rationale.
# ---------------------------------------------------------------------------

# Unicode characters that can hide content from human reviewers or confuse
# delimiter parsing, while being processed by LLM tokenizers.
_DANGEROUS_CODEPOINTS = re.compile(
    "["
    "\u200b-\u200f"  # zero-width space, joiners, direction marks
    "\u2028-\u2029"  # line/paragraph separators
    "\u202a-\u202e"  # bidi embedding/override
    "\u2060-\u2064"  # invisible operators
    "\u2066-\u2069"  # bidi isolates
    "\ufeff"          # BOM / zero-width no-break space
    "\ufff9-\ufffb"  # interlinear annotations
    "\U000e0001"      # language tag
    "\U000e0020-\U000e007f"  # tag characters
    "]"
)

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

MAX_FIELD_LEN = 4096


def sanitize_value(value: str) -> str:
    """Strip dangerous invisible characters and enforce length limits."""
    value = _DANGEROUS_CODEPOINTS.sub("", value)
    value = _ANSI_ESCAPE.sub("", value)
    if len(value) > MAX_FIELD_LEN:
        value = value[:MAX_FIELD_LEN] + " [TRUNCATED]"
    return value


def sanitize_alert(obj: object) -> object:
    """Recursively sanitize string values in alert data."""
    if isinstance(obj, str):
        return sanitize_value(obj)
    if isinstance(obj, dict):
        return {k: sanitize_alert(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_alert(v) for v in obj]
    return obj


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

    # Generate per-run salt for untrusted content delimiters
    salt = secrets.token_hex(8)

    # Sanitize and save alert.json
    alert = sanitize_alert(alert)
    alert_file = run_dir / "alert.json"
    alert_file.write_text(json.dumps(alert, indent=2))

    # Save meta.json (run metadata for hooks)
    meta = {"run_id": run_id, "signature_id": signature_id, "salt": salt}
    meta_file = run_dir / "meta.json"
    meta_file.write_text(json.dumps(meta, indent=2))

    # Write wrapped alert for the investigation agent.
    # The agent reads this instead of raw alert.json — salted delimiters
    # prevent pre-crafted closing tag attacks from alert field values.
    alert_text = json.dumps(alert, indent=2)
    wrapped = (
        f"<run-{salt}-alert-data>\n"
        f"{alert_text}\n"
        f"</run-{salt}-alert-data>"
    )
    (run_dir / "alert_wrapped.md").write_text(wrapped)

    # Output for skill substitution
    print(f"Run directory: {run_dir}")
    print(f"Run ID: {run_id}")
    print(f"Signature: {signature_id}")
    print(f"Salt: {salt}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
