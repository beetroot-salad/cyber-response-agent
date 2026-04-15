#!/usr/bin/env python3
"""Stop hook: Append investigation outcome summary to runs/audit.jsonl.

Resolves the run directory via session_id from the Stop payload and appends
a JSONL entry with the investigation verdict (status, disposition,
confidence, precedent match, timestamps, and token usage).

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
from hooks.scripts.run_context import get_runs_dir, resolve_run_dir  # noqa: E402


TOKEN_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


def _empty_stats() -> dict:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "models": [],
        "total_cost_usd": None,
    }


def extract_transcript_stats(transcript_path: str) -> dict:
    """Extract tokens, models, and cost from a Claude Code session transcript.

    Two transcript formats handled:

    1. **stream-json** (as tee'd by eval_run.sh with --output-format stream-json):
       ends with a `type: "result"` record that carries the authoritative
       accumulated `usage` dict and `total_cost_usd`. One record, complete
       truth — preferred whenever present.

    2. **Persisted session transcript** (~/.claude/projects/<project>/<uuid>.jsonl):
       no result record. Each assistant message is emitted once per content
       block with the same `message.id`, and every duplicate carries the
       same final `usage` snapshot — so a naive sum across records double-
       counts. Dedupe by `message.id` (last occurrence wins), then sum.

    Models are collected as a sorted distinct list regardless of format —
    single-element in the common case, multi-element if the user ran /model
    mid-session or a subagent used a different model.

    Returns the empty-stats dict on any failure; never raises.
    """
    stats = _empty_stats()
    try:
        result_usage = None
        result_cost = None
        models = set()
        per_msg_usage = {}  # message.id -> latest usage dict seen

        with open(transcript_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                rtype = record.get("type")
                if rtype == "result":
                    usage = record.get("usage")
                    if isinstance(usage, dict):
                        result_usage = usage
                    cost = record.get("total_cost_usd")
                    if isinstance(cost, (int, float)):
                        result_cost = cost
                elif rtype == "assistant":
                    msg = record.get("message", {})
                    model = msg.get("model")
                    if model:
                        models.add(model)
                    msg_id = msg.get("id")
                    usage = msg.get("usage")
                    if msg_id and isinstance(usage, dict):
                        per_msg_usage[msg_id] = usage

        stats["models"] = sorted(models)
        stats["total_cost_usd"] = result_cost

        if result_usage is not None:
            for key in TOKEN_KEYS:
                stats[key] = result_usage.get(key, 0)
        else:
            for usage in per_msg_usage.values():
                for key in TOKEN_KEYS:
                    stats[key] += usage.get(key, 0)
    except Exception:
        pass
    return stats


def main(payload: dict | None = None) -> None:
    """Append an audit entry for the current run. Never raises.

    Accepts the Stop payload dict. When called directly from __main__,
    the payload is read from stdin. Either way, session_id anchors the
    run-directory resolution so concurrent runs don't cross-contaminate.
    """
    if payload is None:
        payload = {}

    session_id = payload.get("session_id") if isinstance(payload, dict) else None
    runs_dir = get_runs_dir()

    run_dir: Path | None = None
    if session_id:
        run_dir, _ = resolve_run_dir(session_id, runs_dir)
    if run_dir is None:
        return

    report_path = run_dir / "report.md"
    if not report_path.exists():
        return
    with open(report_path) as f:
        frontmatter = parse_yaml_frontmatter(f.read())

    state: dict = {}
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

    # SOC_AGENT_TRANSCRIPT_PATH takes precedence so eval_run.sh can point at
    # the tee'd full transcript — under --no-session-persistence, the Stop
    # hook payload's transcript_path is a 1-line ai-title stub.
    transcript_path = os.environ.get("SOC_AGENT_TRANSCRIPT_PATH") or payload.get("transcript_path")
    stats = extract_transcript_stats(transcript_path) if transcript_path else _empty_stats()

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
        **stats,
    }

    audit_path = runs_dir / "audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_path, "a") as f:
        f.write(json.dumps(entry) + "\n")


if __name__ == "__main__":
    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    try:
        cli_payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        cli_payload = {}
    if not isinstance(cli_payload, dict):
        cli_payload = {}
    main(cli_payload)
    sys.exit(0)
