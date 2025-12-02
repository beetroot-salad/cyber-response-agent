#!/usr/bin/env python3
"""
Run Log Analyzer

Analyzes execution logs and Claude Code conversation history for investigation
and reproduction runs. Displays thinking transcript, tool usage, and final results.

Usage:
    python analyze_run.py <run_id>
    python analyze_run.py TEST-REPRO-001_20251202_153308_dfe648af
    python analyze_run.py --list                    # List available runs
    python analyze_run.py --recent 5                # Show 5 most recent runs
    python analyze_run.py <run_id> --json           # Output as JSON
    python analyze_run.py <run_id> --tools-only     # Show only tool usage
    python analyze_run.py <run_id> --summary        # Show brief summary
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


# Paths
INVESTIGATION_RUNS_DIR = Path("/workspace/app/agent/investigation/runs")
REPRODUCTION_RUNS_DIR = Path("/workspace/app/agent/reproduction/runs")
CLAUDE_PROJECTS_DIR = Path("/root/.claude/projects")
CLAUDE_DEBUG_DIR = Path("/root/.claude/debug")


@dataclass
class ToolCall:
    """Represents a single tool invocation."""
    name: str
    input: dict[str, Any]
    result: Optional[str] = None
    timestamp: Optional[str] = None
    duration_ms: Optional[int] = None


@dataclass
class Message:
    """Represents a message in the conversation."""
    role: str  # user, assistant, system
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    timestamp: Optional[str] = None
    thinking: Optional[str] = None


@dataclass
class RunAnalysis:
    """Complete analysis of a run."""
    run_id: str
    run_type: str  # investigation or reproduction
    run_dir: Path
    session_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Input context
    ticket_id: Optional[str] = None
    signature_id: Optional[str] = None
    hypothesis: Optional[str] = None
    alert_data: Optional[dict] = None

    # Conversation
    messages: list[Message] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)

    # Output
    result: Optional[dict] = None
    report_body: Optional[str] = None

    # Errors
    errors: list[str] = field(default_factory=list)


def find_run_directory(run_id: str) -> tuple[Optional[Path], str]:
    """Find the run directory for a given run ID."""
    # Check investigation runs
    inv_dir = INVESTIGATION_RUNS_DIR / run_id
    if inv_dir.exists():
        return inv_dir, "investigation"

    # Check reproduction runs
    repro_dir = REPRODUCTION_RUNS_DIR / run_id
    if repro_dir.exists():
        return repro_dir, "reproduction"

    # Check for partial match
    for runs_dir, run_type in [(INVESTIGATION_RUNS_DIR, "investigation"),
                                (REPRODUCTION_RUNS_DIR, "reproduction")]:
        if runs_dir.exists():
            for d in runs_dir.iterdir():
                if d.is_dir() and run_id in d.name:
                    return d, run_type

    return None, ""


def find_session_logs(run_dir: Path) -> list[Path]:
    """Find Claude Code session logs for a run directory."""
    # Convert run directory path to the Claude projects directory format
    # e.g., /workspace/app/agent/.../RUN_ID -> -workspace-app-agent-...-RUN-ID
    # Note: Claude Code converts both / and _ to - in the directory name
    path_str = str(run_dir).replace("/", "-").replace("_", "-")
    project_dir = CLAUDE_PROJECTS_DIR / path_str

    session_logs = []
    if project_dir.exists():
        for f in project_dir.iterdir():
            if f.suffix == ".jsonl" and not f.name.startswith("agent-"):
                session_logs.append(f)

    return sorted(session_logs, key=lambda f: f.stat().st_mtime, reverse=True)


def parse_jsonl_log(log_path: Path) -> list[dict]:
    """Parse a JSONL conversation log file."""
    entries = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries


def extract_text_content(content: Any) -> str:
    """Extract text from message content (handles both string and list formats)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    texts.append(item.get("text", ""))
                elif item.get("type") == "tool_result":
                    result_content = item.get("content", "")
                    if isinstance(result_content, str):
                        texts.append(f"[Tool Result: {result_content[:200]}...]" if len(result_content) > 200 else f"[Tool Result: {result_content}]")
            elif isinstance(item, str):
                texts.append(item)
        return "\n".join(texts)
    return str(content)


def extract_thinking(content: Any) -> Optional[str]:
    """Extract extended thinking content from message."""
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "thinking":
                return item.get("thinking", "")
    return None


def extract_tool_calls(content: Any) -> list[ToolCall]:
    """Extract tool calls from message content."""
    tool_calls = []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "tool_use":
                tool_calls.append(ToolCall(
                    name=item.get("name", "unknown"),
                    input=item.get("input", {}),
                ))
    return tool_calls


def analyze_run(run_id: str) -> RunAnalysis:
    """Analyze a run and extract all relevant information."""
    run_dir, run_type = find_run_directory(run_id)

    analysis = RunAnalysis(
        run_id=run_id,
        run_type=run_type,
        run_dir=run_dir or Path("."),
    )

    if not run_dir:
        analysis.errors.append(f"Run directory not found for: {run_id}")
        return analysis

    # Load input context
    if run_type == "investigation":
        alert_file = run_dir / "alert.json"
        if alert_file.exists():
            with open(alert_file) as f:
                analysis.alert_data = json.load(f)
                analysis.ticket_id = analysis.alert_data.get("ticket_id")
                analysis.signature_id = analysis.alert_data.get("signature_id")
    else:  # reproduction
        hypothesis_file = run_dir / "hypothesis.json"
        if hypothesis_file.exists():
            with open(hypothesis_file) as f:
                data = json.load(f)
                analysis.hypothesis = data.get("hypothesis")
                analysis.ticket_id = data.get("ticket_id")
                analysis.signature_id = data.get("signature_id")

    # Find and parse session logs
    session_logs = find_session_logs(run_dir)

    if not session_logs:
        analysis.errors.append("No session logs found in Claude projects directory")
        return analysis

    # Parse the main session log (most recent)
    log_entries = parse_jsonl_log(session_logs[0])

    # Extract session ID and timestamps
    for entry in log_entries:
        if "sessionId" in entry:
            analysis.session_id = entry["sessionId"]
            break

    # Track timestamps
    timestamps = []
    for entry in log_entries:
        if "timestamp" in entry:
            ts = entry["timestamp"]
            if isinstance(ts, str):
                try:
                    timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                except ValueError:
                    pass

    if timestamps:
        analysis.start_time = min(timestamps)
        analysis.end_time = max(timestamps)
        analysis.duration_seconds = (analysis.end_time - analysis.start_time).total_seconds()

    # Extract messages and tool calls
    tool_use_ids = {}  # Map tool_use_id to ToolCall for result matching

    for entry in log_entries:
        entry_type = entry.get("type")
        timestamp = entry.get("timestamp")

        if entry_type == "user":
            msg_data = entry.get("message", {})
            content = msg_data.get("content", "")

            # Check for tool results
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "tool_result":
                        tool_id = item.get("tool_use_id")
                        result_content = item.get("content", "")
                        if tool_id and tool_id in tool_use_ids:
                            tool_use_ids[tool_id].result = result_content[:1000] if len(str(result_content)) > 1000 else str(result_content)

            text = extract_text_content(content)
            if text and not text.startswith("[Tool Result:"):
                analysis.messages.append(Message(
                    role="user",
                    content=text,
                    timestamp=timestamp,
                ))

        elif entry_type == "assistant":
            msg_data = entry.get("message", {})
            content = msg_data.get("content", [])

            text = extract_text_content(content)
            tool_calls = extract_tool_calls(content)
            thinking = extract_thinking(content)

            # Register tool calls for result matching
            for tc in tool_calls:
                # Find the tool_use_id from the original content
                if isinstance(content, list):
                    for item in content:
                        if (isinstance(item, dict) and
                            item.get("type") == "tool_use" and
                            item.get("name") == tc.name):
                            tool_id = item.get("id")
                            if tool_id:
                                tool_use_ids[tool_id] = tc

            analysis.tool_calls.extend(tool_calls)

            if text or tool_calls or thinking:
                analysis.messages.append(Message(
                    role="assistant",
                    content=text,
                    tool_calls=tool_calls,
                    timestamp=timestamp,
                    thinking=thinking,
                ))

    # Load reproduction report if available
    report_file = run_dir / "output" / "reproduction-report.md"
    if report_file.exists():
        with open(report_file) as f:
            analysis.report_body = f.read()

    return analysis


def format_tool_call(tc: ToolCall, verbose: bool = False) -> str:
    """Format a tool call for display."""
    lines = [f"  📧 {tc.name}"]

    if verbose:
        # Show input parameters
        for key, value in tc.input.items():
            value_str = str(value)
            if len(value_str) > 100:
                value_str = value_str[:100] + "..."
            lines.append(f"      {key}: {value_str}")
    else:
        # Compact format for common tools
        if tc.name == "Bash":
            cmd = tc.input.get("command", "")
            if len(cmd) > 80:
                cmd = cmd[:80] + "..."
            lines[0] = f"  📧 Bash: {cmd}"
        elif tc.name == "Read":
            path = tc.input.get("file_path", "")
            lines[0] = f"  📧 Read: {path}"
        elif tc.name == "Glob":
            pattern = tc.input.get("pattern", "")
            lines[0] = f"  📧 Glob: {pattern}"
        elif tc.name == "Grep":
            pattern = tc.input.get("pattern", "")
            lines[0] = f"  📧 Grep: {pattern}"
        elif tc.name == "Write":
            path = tc.input.get("file_path", "")
            lines[0] = f"  📧 Write: {path}"
        elif tc.name == "Edit":
            path = tc.input.get("file_path", "")
            lines[0] = f"  📧 Edit: {path}"
        elif tc.name == "TodoWrite":
            todos = tc.input.get("todos", [])
            lines[0] = f"  📧 TodoWrite: {len(todos)} items"

    if tc.result and verbose:
        result_preview = tc.result[:200] if len(tc.result) > 200 else tc.result
        result_preview = result_preview.replace("\n", " ")
        lines.append(f"      → {result_preview}")

    return "\n".join(lines)


def print_analysis(analysis: RunAnalysis,
                   tools_only: bool = False,
                   summary: bool = False,
                   verbose: bool = False) -> None:
    """Print the analysis in a readable format."""

    # Header
    print("=" * 80)
    print(f"RUN ANALYSIS: {analysis.run_id}")
    print("=" * 80)
    print()

    # Metadata
    print(f"Type:        {analysis.run_type}")
    print(f"Directory:   {analysis.run_dir}")
    if analysis.session_id:
        print(f"Session ID:  {analysis.session_id}")
    if analysis.ticket_id:
        print(f"Ticket ID:   {analysis.ticket_id}")
    if analysis.signature_id:
        print(f"Signature:   {analysis.signature_id}")
    if analysis.duration_seconds:
        print(f"Duration:    {analysis.duration_seconds:.1f}s")
    if analysis.start_time:
        print(f"Started:     {analysis.start_time.isoformat()}")
    print()

    # Errors
    if analysis.errors:
        print("ERRORS:")
        for err in analysis.errors:
            print(f"  ⚠️  {err}")
        print()
        return

    # Summary mode
    if summary:
        print("TOOL USAGE SUMMARY:")
        tool_counts = {}
        for tc in analysis.tool_calls:
            tool_counts[tc.name] = tool_counts.get(tc.name, 0) + 1
        for name, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
            print(f"  {name}: {count}")
        print()
        print(f"Total messages: {len(analysis.messages)}")
        print(f"Total tool calls: {len(analysis.tool_calls)}")
        return

    # Tools only mode
    if tools_only:
        print("TOOL CALLS:")
        print("-" * 40)
        for i, tc in enumerate(analysis.tool_calls, 1):
            print(f"\n[{i}] {format_tool_call(tc, verbose=verbose)}")
        return

    # Full transcript
    print("CONVERSATION TRANSCRIPT:")
    print("-" * 40)

    for msg in analysis.messages:
        timestamp = ""
        if msg.timestamp:
            try:
                dt = datetime.fromisoformat(msg.timestamp.replace("Z", "+00:00"))
                timestamp = f" [{dt.strftime('%H:%M:%S')}]"
            except ValueError:
                pass

        if msg.role == "user":
            print(f"\n👤 USER{timestamp}:")
            content = msg.content
            if len(content) > 500 and not verbose:
                content = content[:500] + "...[truncated]"
            print(indent_text(content, "  "))

        elif msg.role == "assistant":
            print(f"\n🤖 ASSISTANT{timestamp}:")

            # Print thinking if available
            if msg.thinking:
                print("  💭 THINKING:")
                thinking = msg.thinking
                if len(thinking) > 500 and not verbose:
                    thinking = thinking[:500] + "...[truncated]"
                print(indent_text(thinking, "    "))

            # Print content
            if msg.content:
                content = msg.content
                if len(content) > 1000 and not verbose:
                    content = content[:1000] + "...[truncated]"
                print(indent_text(content, "  "))

            # Print tool calls
            for tc in msg.tool_calls:
                print(format_tool_call(tc, verbose=verbose))

    # Report body
    if analysis.report_body:
        print()
        print("=" * 40)
        print("FINAL REPORT:")
        print("=" * 40)
        report = analysis.report_body
        if len(report) > 2000 and not verbose:
            report = report[:2000] + "\n...[truncated]"
        print(report)


def indent_text(text: str, indent: str) -> str:
    """Indent all lines of text."""
    return "\n".join(indent + line for line in text.split("\n"))


def list_runs(limit: int = 20) -> None:
    """List available runs."""
    runs = []

    # Collect investigation runs
    if INVESTIGATION_RUNS_DIR.exists():
        for d in INVESTIGATION_RUNS_DIR.iterdir():
            if d.is_dir():
                runs.append((d, "investigation", d.stat().st_mtime))

    # Collect reproduction runs
    if REPRODUCTION_RUNS_DIR.exists():
        for d in REPRODUCTION_RUNS_DIR.iterdir():
            if d.is_dir():
                runs.append((d, "reproduction", d.stat().st_mtime))

    # Sort by modification time
    runs.sort(key=lambda x: x[2], reverse=True)

    if not runs:
        print("No runs found.")
        return

    print(f"{'RUN ID':<60} {'TYPE':<15} {'MODIFIED'}")
    print("-" * 95)

    for d, run_type, mtime in runs[:limit]:
        dt = datetime.fromtimestamp(mtime)
        print(f"{d.name:<60} {run_type:<15} {dt.strftime('%Y-%m-%d %H:%M:%S')}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze investigation and reproduction run logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s TEST-REPRO-001_20251202_153308_dfe648af
  %(prog)s --list
  %(prog)s --recent 5
  %(prog)s <run_id> --tools-only
  %(prog)s <run_id> --summary
  %(prog)s <run_id> --json
  %(prog)s <run_id> --verbose
        """
    )

    parser.add_argument("run_id", nargs="?", help="Run ID to analyze")
    parser.add_argument("--list", "-l", action="store_true",
                        help="List available runs")
    parser.add_argument("--recent", "-r", type=int, metavar="N",
                        help="Show N most recent runs")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--tools-only", "-t", action="store_true",
                        help="Show only tool usage")
    parser.add_argument("--summary", "-s", action="store_true",
                        help="Show brief summary")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show full content without truncation")

    args = parser.parse_args()

    if args.list:
        list_runs()
        return

    if args.recent:
        list_runs(limit=args.recent)
        return

    if not args.run_id:
        parser.print_help()
        sys.exit(1)

    analysis = analyze_run(args.run_id)

    if args.json:
        # Convert to JSON-serializable format
        output = {
            "run_id": analysis.run_id,
            "run_type": analysis.run_type,
            "run_dir": str(analysis.run_dir),
            "session_id": analysis.session_id,
            "start_time": analysis.start_time.isoformat() if analysis.start_time else None,
            "end_time": analysis.end_time.isoformat() if analysis.end_time else None,
            "duration_seconds": analysis.duration_seconds,
            "ticket_id": analysis.ticket_id,
            "signature_id": analysis.signature_id,
            "hypothesis": analysis.hypothesis,
            "alert_data": analysis.alert_data,
            "tool_calls": [
                {"name": tc.name, "input": tc.input, "result": tc.result}
                for tc in analysis.tool_calls
            ],
            "message_count": len(analysis.messages),
            "errors": analysis.errors,
        }
        print(json.dumps(output, indent=2))
    else:
        print_analysis(analysis,
                       tools_only=args.tools_only,
                       summary=args.summary,
                       verbose=args.verbose)


if __name__ == "__main__":
    main()
