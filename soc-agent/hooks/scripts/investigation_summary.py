#!/usr/bin/env python3
"""Stop hook: Append investigation outcome summary to runs/audit.jsonl.

Reads the most recent completed run and appends a JSONL entry with the
investigation verdict (status, disposition, confidence, precedent match).

Exit codes:
    0 - Always (summary logging should never block the agent)
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


def get_runs_dir() -> Path:
    """Get the runs directory. Configurable via SOC_AGENT_RUNS_DIR env var."""
    return Path(os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs")))


def parse_yaml_frontmatter(text: str) -> dict:
    """Parse simple YAML frontmatter from markdown."""
    lines = text.strip().split("\n")
    if not lines or lines[0].strip() != "---":
        return {}

    fields = {}
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()
            if value.lower() in ("null", "~", ""):
                value = None
            elif value.isdigit():
                value = int(value)
            elif value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1]
            fields[key] = value
    return fields


def find_latest_run() -> Path | None:
    """Find the most recent run directory with a report.md."""
    runs_dir = get_runs_dir()
    if not runs_dir.exists():
        return None

    run_dirs = sorted(
        [d for d in runs_dir.iterdir() if d.is_dir() and (d / "report.md").exists()],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    return run_dirs[0] if run_dirs else None


def main():
    try:
        sys.stdin.read()
    except Exception:
        pass

    run_dir = find_latest_run()
    if run_dir is None:
        sys.exit(0)

    report_path = run_dir / "report.md"
    with open(report_path) as f:
        frontmatter = parse_yaml_frontmatter(f.read())

    state = {}
    state_path = run_dir / "state.json"
    if state_path.exists():
        with open(state_path) as f:
            state = json.load(f)

    entry = {
        "run_id": state.get("run_id", run_dir.name),
        "ticket_id": frontmatter.get("ticket_id", ""),
        "signature_id": frontmatter.get("signature_id", ""),
        "status": frontmatter.get("status", ""),
        "disposition": frontmatter.get("disposition", ""),
        "confidence": frontmatter.get("confidence", ""),
        "matched_precedent": frontmatter.get("matched_precedent"),
        "leads_pursued": frontmatter.get("leads_pursued", 0),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    audit_path = get_runs_dir() / "audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_path, "a") as f:
        f.write(json.dumps(entry) + "\n")

    sys.exit(0)


if __name__ == "__main__":
    main()
