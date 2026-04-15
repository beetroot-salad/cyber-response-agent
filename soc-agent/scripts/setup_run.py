#!/usr/bin/env python3
"""Set up the investigation run directory and save alert data.

Usage: python3 scripts/setup_run.py <signature_id> <alert_json>

Creates:
  {SOC_AGENT_RUNS_DIR:-runs}/{uuid}/alert.json
  {SOC_AGENT_RUNS_DIR:-runs}/{uuid}/meta.json  (run_id, signature_id, severity, salt)

Prints run metadata to stdout for !command substitution in SKILL.md.

Exit codes:
  0 — success
  1 — invalid arguments, malformed alert JSON, or missing/invalid signature severity
"""

import json
import os
import re
import secrets
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.frontmatter import parse_yaml_frontmatter
from schemas.report_frontmatter import MIN_LEADS_BY_SEVERITY

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


def read_signature_severity(signature_id: str) -> str:
    """Read severity from signatures/{id}/context.md frontmatter.

    Fail-fast: raises if the file is missing or the severity field is
    absent or invalid. Severity is a per-signature contract that hooks
    rely on at runtime — silently defaulting hides authoring bugs.
    """
    context_path = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "context.md"
    )
    if not context_path.exists():
        raise SystemExit(
            f"Error: signature '{signature_id}' has no context.md at {context_path}"
        )
    fm = parse_yaml_frontmatter(context_path.read_text())
    severity = fm.get("severity")
    if not severity:
        raise SystemExit(
            f"Error: {context_path} frontmatter is missing 'severity'"
        )
    if severity not in MIN_LEADS_BY_SEVERITY:
        valid = sorted(MIN_LEADS_BY_SEVERITY.keys())
        raise SystemExit(
            f"Error: {context_path} severity={severity!r} is not one of {valid}"
        )
    return severity


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <signature_id> <alert_json>", file=sys.stderr)
        return 1

    signature_id = sys.argv[1]
    alert_json_str = sys.argv[2]

    # Read + validate severity from the signature's context.md before any
    # filesystem mutation, so a misconfigured signature fails loudly without
    # leaving a half-built run directory behind.
    severity = read_signature_severity(signature_id)

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
    meta = {
        "run_id": run_id,
        "signature_id": signature_id,
        "severity": severity,
        "salt": salt,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    meta_file = run_dir / "meta.json"
    meta_file.write_text(json.dumps(meta, indent=2))

    # Eagerly write session→run mapping so Stop-stage hooks can resolve
    # the run directory via the fast path without a racy mtime scan.
    # CLAUDE_SESSION_ID is set by the Claude Code harness in the !command
    # environment; when present this completely eliminates the slow path.
    session_id = os.environ.get("CLAUDE_SESSION_ID", "")
    if session_id:
        from hooks.scripts.run_context import write_session_mapping
        write_session_mapping(session_id, run_dir, signature_id, runs_base)

    # Output for skill substitution
    print(f"Run directory: {run_dir}")
    print(f"Run ID: {run_id}")
    print(f"Signature: {signature_id}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
