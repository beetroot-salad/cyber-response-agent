#!/usr/bin/env python3
"""Postmortem analyzer for soc-agent eval runs.

Reads the artifacts produced by `playground/scripts/eval_run.sh` (or any
soc-agent run with `--output-format stream-json --include-hook-events`) and
prints a structured postmortem covering wall clock, tool call breakdown,
SIEM queries, subagent spawns, hook events, denials, and final disposition.

Usage:
    analyze_run.py <eval_dir>            # full report
    analyze_run.py <eval_dir> --terse    # high-level metrics only

    # eval_dir is the directory `eval_run.sh` creates, e.g.
    #   /workspace/runs/20260410-141350-rule5710/
    # which contains alert.json, transcript.jsonl, and runs/{uuid}/...

Exit codes:
    0 - report printed
    1 - eval_dir invalid or missing required artifacts
"""

import argparse
import json
import sys
from collections import Counter, OrderedDict
from datetime import datetime
from pathlib import Path

import yaml

DENIED_PHRASES = (
    "requires approval",
    "multiple operations",
    "was blocked",
    "judge timed out",
    "Cancelled: parallel",
    "tool_use_error",
)

# Bash command classifier — used to bucket OK/denied calls in the summary.
def classify_bash(cmd: str) -> str:
    if "wazuh_cli.py" in cmd:
        # Match both long form (--query) and short form (-q) — the agent
        # uses both interchangeably.
        if "--query" in cmd or " -q " in cmd or cmd.endswith(" -q"):
            return "siem-query"
        if " health-check" in cmd:
            return "siem-health"
        return "siem-other"
    if "docker exec" in cmd:
        return "docker-exec"
    if "write_state.py" in cmd:
        return "state-write"
    if "resolve_imports.py" in cmd:
        return "skill-bake"
    if "setup_run.py" in cmd:
        return "skill-bake"
    if "search_precedents.py" in cmd:
        return "precedent-search"
    if cmd.lstrip().startswith(("ls ", "ls\t", "ls\n")) or cmd.strip() == "ls":
        return "fs-ls"
    if cmd.lstrip().startswith("cat "):
        return "fs-cat"
    if cmd.lstrip().startswith("find "):
        return "fs-find"
    if cmd.lstrip().startswith("echo "):
        return "echo"
    return "other"


def load_transcript(eval_dir: Path) -> list[dict]:
    path = eval_dir / "transcript.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def load_run_dir(eval_dir: Path) -> Path | None:
    """Find the single run UUID dir under eval_dir/runs/."""
    runs = eval_dir / "runs"
    if not runs.exists():
        return None
    candidates = [
        d for d in runs.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ]
    if not candidates:
        return None
    # Pick the most recently modified — handles multi-run dirs.
    return max(candidates, key=lambda d: d.stat().st_mtime)


def get_event_timestamp(ev: dict) -> datetime | None:
    ts = ev.get("timestamp")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_tool_result_index(events: list[dict]) -> dict[str, dict]:
    """Index tool_result blocks by tool_use_id for O(1) lookup."""
    index: dict[str, dict] = {}
    for ev in events:
        if ev.get("type") != "user":
            continue
        c = (ev.get("message", {}) or {}).get("content", "")
        if not isinstance(c, list):
            continue
        for b in c:
            if b.get("type") == "tool_result":
                tuid = b.get("tool_use_id")
                if tuid:
                    index[tuid] = b
    return index


def find_tool_result(tool_use_block: dict, result_index: dict[str, dict]) -> dict | None:
    """Look up the tool_result for a given tool_use block by id."""
    tuid = tool_use_block.get("id")
    if not tuid:
        return None
    return result_index.get(tuid)


def tool_result_text(block: dict) -> str:
    cc = block.get("content", "")
    if isinstance(cc, list):
        return " ".join(
            str(x.get("text", "")) for x in cc if isinstance(x, dict)
        )
    return str(cc)


def is_denied(block: dict) -> bool:
    if block.get("is_error"):
        return True
    txt = tool_result_text(block)
    return any(p in txt for p in DENIED_PHRASES)


# ---------------------------------------------------------------------------
# Section: run metadata
# ---------------------------------------------------------------------------

def section_metadata(eval_dir: Path, events: list[dict], run_dir: Path | None) -> None:
    print("=" * 70)
    print(f"RUN METADATA — {eval_dir.name}")
    print("=" * 70)

    alert_path = eval_dir / "alert.json"
    if alert_path.exists():
        try:
            alert = json.loads(alert_path.read_text())
            print(f"  alert ts:    {alert.get('timestamp', '?')}")
            rule = alert.get("rule", {})
            print(f"  rule:        {rule.get('id', '?')} — {rule.get('description', '?')}")
            data = alert.get("data", {})
            print(f"  srcip:       {data.get('srcip', '?')}")
            print(f"  srcuser:     {data.get('srcuser', '?')}")
        except (json.JSONDecodeError, OSError) as e:
            print(f"  alert.json:  unreadable ({e})")

    if events:
        init = next((e for e in events if e.get("type") == "system"
                     and e.get("subtype") == "init"), None)
        if init:
            print(f"  model:       {init.get('model', '?')}")
            print(f"  session_id:  {str(init.get('session_id', '?'))[:8]}")
            mcps = init.get("mcp_servers", [])
            if mcps:
                conn = [m['name'] for m in mcps if m.get('status') == 'connected']
                print(f"  mcp connected: {conn}")

    if run_dir:
        print(f"  run_dir:     {run_dir}")
        state_path = run_dir / "state.json"
        if state_path.exists():
            try:
                state = json.loads(state_path.read_text())
                print(f"  final phase: {state.get('phase', '?')}")
                print(f"  history:     {state.get('history', [])}")
            except json.JSONDecodeError:
                pass
    print()


# ---------------------------------------------------------------------------
# Section: wall clock + cost
# ---------------------------------------------------------------------------

def section_timing(events: list[dict]) -> None:
    print("WALL CLOCK & COST")
    print("-" * 70)
    timestamps = [t for t in (get_event_timestamp(e) for e in events) if t]
    if timestamps:
        elapsed = (timestamps[-1] - timestamps[0]).total_seconds()
        print(f"  wall clock:  {elapsed:.0f}s ({elapsed/60:.1f} min)")
    result = next((e for e in events if e.get("type") == "result"), None)
    if result:
        print(f"  num_turns:   {result.get('num_turns', '?')}")
        cost = result.get("total_cost_usd", 0)
        print(f"  total cost:  ${cost}")
        usage = result.get("usage", {})
        if usage:
            print(f"  input tok:   {usage.get('input_tokens', '?')}")
            print(f"  output tok:  {usage.get('output_tokens', '?')}")
            print(f"  cache read:  {usage.get('cache_read_input_tokens', '?')}")
    print()


# ---------------------------------------------------------------------------
# Section: tool call summary
# ---------------------------------------------------------------------------

def section_tool_calls(events: list[dict]) -> None:
    print("TOOL CALLS")
    print("-" * 70)

    result_index = build_tool_result_index(events)
    counts: Counter = Counter()
    bash_ok: Counter = Counter()
    bash_denied: Counter = Counter()
    bash_unmatched = 0

    for ev in events:
        if ev.get("type") != "assistant":
            continue
        for b in (ev.get("message", {}) or {}).get("content", []) or []:
            if b.get("type") != "tool_use":
                continue
            name = b.get("name", "?")
            counts[name] += 1
            if name == "Bash":
                cmd = (b.get("input") or {}).get("command", "")
                cat = classify_bash(cmd)
                result = find_tool_result(b, result_index)
                if result is None:
                    bash_unmatched += 1
                    continue
                if is_denied(result):
                    bash_denied[cat] += 1
                else:
                    bash_ok[cat] += 1

    total = sum(counts.values())
    print(f"  total tool calls: {total}")
    for name, n in counts.most_common():
        print(f"    {n:4d}  {name}")

    if bash_ok or bash_denied:
        print()
        print("  Bash calls by category:")
        all_cats = sorted(set(bash_ok) | set(bash_denied))
        for cat in all_cats:
            ok = bash_ok.get(cat, 0)
            denied = bash_denied.get(cat, 0)
            print(f"    {cat:20s}  ok={ok:3d}  denied={denied:3d}")
        if bash_unmatched:
            print(f"    (unmatched results: {bash_unmatched})")
    print()


# ---------------------------------------------------------------------------
# Section: SIEM queries
# ---------------------------------------------------------------------------

def section_siem(events: list[dict]) -> None:
    print("SIEM QUERIES (wazuh_cli.py -q / --query)")
    print("-" * 70)
    result_index = build_tool_result_index(events)
    found = False
    for ev in events:
        if ev.get("type") != "assistant":
            continue
        for b in (ev.get("message", {}) or {}).get("content", []) or []:
            if b.get("type") != "tool_use" or b.get("name") != "Bash":
                continue
            cmd = (b.get("input") or {}).get("command", "")
            if "wazuh_cli.py" not in cmd:
                continue
            if "--query" not in cmd and " -q " not in cmd and not cmd.endswith(" -q"):
                continue
            result = find_tool_result(b, result_index)
            status = "OK" if result and not is_denied(result) else "ERR"
            cmd_clean = cmd.replace("\n", " ")
            print(f"  [{status}] {cmd_clean[:200]}")
            found = True
    if not found:
        print("  (no SIEM queries)")
    print()


# ---------------------------------------------------------------------------
# Section: subagent spawns
# ---------------------------------------------------------------------------

def section_subagents(events: list[dict], run_dir: Path | None) -> None:
    print("SUBAGENT SPAWNS")
    print("-" * 70)
    spawns = []
    # Subagent invocations may appear as `Task` (claude code spawning API) or
    # `Agent` (the older / alternate tool name in some stream-json variants).
    for ev in events:
        if ev.get("type") != "assistant":
            continue
        for b in (ev.get("message", {}) or {}).get("content", []) or []:
            if b.get("type") == "tool_use" and b.get("name") in ("Task", "Agent"):
                inp = b.get("input") or {}
                spawns.append({
                    "tool": b.get("name"),
                    "subagent_type": inp.get("subagent_type", "?"),
                    "description": inp.get("description", "?"),
                    "prompt_excerpt": str(inp.get("prompt", ""))[:120],
                })
    print(f"  total subagent calls: {len(spawns)}")
    for s in spawns:
        print(f"    [{s['tool']}/{s['subagent_type']}] {s['description']}")
        if s["prompt_excerpt"]:
            print(f"      prompt: {s['prompt_excerpt']}...")

    # Cross-check budget.json subagent_spawns counter
    if run_dir:
        budget = run_dir / "budget.json"
        if budget.exists():
            try:
                b = json.loads(budget.read_text())
                print(f"  budget.json subagent_spawns: {b.get('subagent_spawns', '?')}")
                print(f"  budget.json tool_calls:      {b.get('tool_calls', '?')}")
            except json.JSONDecodeError:
                pass

    # Check for ticket-context specifically (mirrors validate_report check)
    ticket_ctx_found = any("ticket-context" in (str(s["description"]) + str(s["prompt_excerpt"])).lower()
                           or "ticket_context" in (str(s["description"]) + str(s["prompt_excerpt"])).lower()
                           for s in spawns)
    print(f"  ticket-context spawned: {'YES' if ticket_ctx_found else 'NO'}")
    print()


# ---------------------------------------------------------------------------
# Section: hook events
# ---------------------------------------------------------------------------

def section_hooks(events: list[dict]) -> None:
    print("HOOK EVENTS")
    print("-" * 70)
    hook_counts: Counter = Counter()
    interesting: list[tuple] = []
    for ev in events:
        if ev.get("type") != "system":
            continue
        sub = ev.get("subtype", "")
        if "hook" not in sub:
            continue
        name = ev.get("hook_name", "?")
        hook_counts[(name, sub)] += 1
        if sub == "hook_response":
            ec = ev.get("exit_code", 0)
            out = (ev.get("output") or "").strip()
            err = (ev.get("stderr") or "").strip()
            if ec != 0 or "validate_report" in (out + err) or "Tier" in (out + err) or "Budget" in (out + err):
                msg = (out or err)[:200].replace("\n", " ")
                interesting.append((name, ec, msg))
    print("  hook fire counts:")
    for (name, sub), n in sorted(hook_counts.items()):
        print(f"    {n:4d}  {sub:15s}  {name}")
    if interesting:
        print()
        print("  notable hook outputs (non-zero exit or validation/budget):")
        for name, ec, msg in interesting[:20]:
            print(f"    [{ec}] {name}")
            print(f"         {msg}")
    print()


# ---------------------------------------------------------------------------
# Section: denials & errors
# ---------------------------------------------------------------------------

def section_denials(events: list[dict]) -> None:
    print("DENIED / ERRORED TOOL RESULTS")
    print("-" * 70)
    denials: list[str] = []
    for i, ev in enumerate(events):
        if ev.get("type") != "user":
            continue
        c = (ev.get("message", {}) or {}).get("content", "")
        if not isinstance(c, list):
            continue
        for b in c:
            if b.get("type") != "tool_result":
                continue
            if is_denied(b):
                txt = tool_result_text(b)[:140].replace("\n", " ")
                denials.append(txt)
    print(f"  total denied/errored: {len(denials)}")
    for d in denials[:25]:
        print(f"    - {d}")
    if len(denials) > 25:
        print(f"    ... ({len(denials) - 25} more)")
    print()


# ---------------------------------------------------------------------------
# Section: final disposition
# ---------------------------------------------------------------------------

def section_disposition(run_dir: Path | None) -> None:
    print("FINAL DISPOSITION")
    print("-" * 70)
    if not run_dir:
        print("  (no run_dir found)")
        print()
        return
    report = run_dir / "report.md"
    if not report.exists():
        print("  (no report.md written)")
        print()
        return
    text = report.read_text()
    # Extract and parse YAML frontmatter
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            block = text[3:end]
            try:
                fm = yaml.safe_load(block) or {}
                for k, v in fm.items():
                    print(f"  {k}: {v}")
            except yaml.YAMLError:
                pass
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description="Postmortem analyzer for soc-agent eval runs")
    p.add_argument("eval_dir", help="Path to /workspace/runs/{run_id}/ (eval_run.sh output dir)")
    p.add_argument("--terse", action="store_true",
                   help="Print only metadata, timing, and disposition")
    p.add_argument("--html", action="store_true",
                   help="Also render transcript.html via render_transcript.py")
    args = p.parse_args()

    eval_dir = Path(args.eval_dir).resolve()
    if not eval_dir.is_dir():
        print(f"error: {eval_dir} is not a directory", file=sys.stderr)
        return 1
    if not (eval_dir / "transcript.jsonl").exists():
        print(f"error: {eval_dir}/transcript.jsonl not found — is this an eval_run dir?",
              file=sys.stderr)
        return 1

    events = load_transcript(eval_dir)
    run_dir = load_run_dir(eval_dir)

    sections = OrderedDict([
        ("metadata", lambda: section_metadata(eval_dir, events, run_dir)),
        ("timing", lambda: section_timing(events)),
        ("tools", lambda: section_tool_calls(events)),
        ("siem", lambda: section_siem(events)),
        ("subagents", lambda: section_subagents(events, run_dir)),
        ("hooks", lambda: section_hooks(events)),
        ("denials", lambda: section_denials(events)),
        ("disposition", lambda: section_disposition(run_dir)),
    ])

    if args.terse:
        for name in ("metadata", "timing", "subagents", "disposition"):
            sections[name]()
    else:
        for fn in sections.values():
            fn()

    if args.html:
        import subprocess
        renderer = Path(__file__).parent / "render_transcript.py"
        subprocess.run([sys.executable, str(renderer), str(eval_dir)], check=False)

    return 0


if __name__ == "__main__":
    sys.exit(main())
