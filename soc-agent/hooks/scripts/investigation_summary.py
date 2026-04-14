#!/usr/bin/env python3
"""Stop hook: Append investigation outcome summary to runs/audit.jsonl.

Reads the most recent completed run and appends a JSONL entry with the
investigation verdict (status, disposition, confidence, precedent match,
timestamps, and token usage).

Exit codes:
    0 - Always (summary logging should never block the agent)
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.frontmatter import parse_yaml_frontmatter  # noqa: E402, F401


def get_runs_dir() -> Path:
    """Get the runs directory. Configurable via SOC_AGENT_RUNS_DIR env var."""
    return Path(os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs")))


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


def sum_transcript_tokens(transcript_path: str) -> dict:
    """Sum token usage from Claude Code session transcript JSONL.

    Each assistant message in the transcript carries a usage dict with
    input_tokens, output_tokens, cache_creation_input_tokens, and
    cache_read_input_tokens. Returns zeroed dict on any failure.
    """
    counts = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }
    try:
        with open(transcript_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("type") == "assistant":
                    usage = record.get("message", {}).get("usage", {})
                    for key in counts:
                        counts[key] += usage.get(key, 0)
    except Exception:
        pass
    return counts


def main():
    payload = {}
    try:
        payload = json.loads(sys.stdin.read())
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

    start_timestamp = None
    meta_path = run_dir / "meta.json"
    if meta_path.exists():
        try:
            with open(meta_path) as f:
                meta = json.load(f)
            start_timestamp = meta.get("created_at")
        except Exception:
            pass

    transcript_path = payload.get("transcript_path")
    tokens = sum_transcript_tokens(transcript_path) if transcript_path else {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }

    entry = {
        "run_id": state.get("run_id", run_dir.name),
        "ticket_id": frontmatter.get("ticket_id", ""),
        "signature_id": frontmatter.get("signature_id", ""),
        "status": frontmatter.get("status", ""),
        "disposition": frontmatter.get("disposition", ""),
        "confidence": frontmatter.get("confidence", ""),
        "matched_archetype": frontmatter.get("matched_archetype"),
        "matched_ticket_id": frontmatter.get("matched_ticket_id"),
        "leads_pursued": frontmatter.get("leads_pursued", 0),
        "start_timestamp": start_timestamp,
        "end_timestamp": datetime.now(timezone.utc).isoformat(),
        **tokens,
    }

    audit_path = get_runs_dir() / "audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_path, "a") as f:
        f.write(json.dumps(entry) + "\n")

    sys.exit(0)


if __name__ == "__main__":
    main()
