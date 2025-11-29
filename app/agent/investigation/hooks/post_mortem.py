#!/usr/bin/env python3
"""
Post-Mortem Hook for Investigation Agent

Called after an investigation completes to analyze the session and
potentially update the knowledge base with new utilities or lessons.

This script is invoked by Claude Code as a hook. It:
1. Reads the investigation report from scratchpad
2. Invokes Claude to analyze for novel insights
3. Applies approved updates to knowledge base

Usage (as Claude Code hook):
    Configured in .claude/settings.json under hooks.Stop

Environment:
    INVESTIGATION_RUN_DIR: Path to the investigation run directory
    SIGNATURE_ID: The signature that was investigated
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Paths
APP_DIR = Path("/workspace/app")
KNOWLEDGE_DIR = APP_DIR / "knowledge"
HOOKS_DIR = APP_DIR / "agent" / "investigation" / "hooks"


def read_investigation_report(run_dir: Path) -> str | None:
    """Read the investigation report from the run directory."""
    # Check scratchpad for notes
    scratchpad = run_dir / "scratchpad"
    report_parts = []

    # Read alert.json
    alert_file = run_dir / "alert.json"
    if alert_file.exists():
        with open(alert_file) as f:
            alert = json.load(f)
            report_parts.append(f"## Alert\n```json\n{json.dumps(alert, indent=2)}\n```")

    # Read any markdown files in scratchpad
    if scratchpad.exists():
        for f in scratchpad.glob("*.md"):
            report_parts.append(f"## {f.stem}\n{f.read_text()}")

    # Read any output files
    for pattern in ["output.txt", "report.md", "findings.json"]:
        output_file = run_dir / pattern
        if output_file.exists():
            report_parts.append(f"## {pattern}\n{output_file.read_text()}")

    if not report_parts:
        return None

    return "\n\n".join(report_parts)


def run_analysis(report: str, signature_id: str) -> dict:
    """
    Run Claude to analyze the investigation report.

    Returns parsed JSON with utilities and lessons to add.
    """
    prompt_file = HOOKS_DIR / "post_mortem_prompt.md"
    if not prompt_file.exists():
        return {"utilities": [], "lessons": [], "summary": "Hook prompt not found"}

    prompt = prompt_file.read_text()

    full_prompt = f"""{prompt}

---

## Investigation to Analyze

**Signature**: {signature_id}

{report}

---

Analyze this investigation and output your JSON response.
Remember: empty arrays are the expected common case. Only add genuinely novel, specific, reusable insights.
"""

    # Call Claude CLI
    try:
        result = subprocess.run(
            ["claude", "--print", "-p", full_prompt],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            return {
                "utilities": [],
                "lessons": [],
                "summary": f"Analysis failed: {result.stderr}",
            }

        # Parse JSON from output
        output = result.stdout.strip()

        # Try to extract JSON from response
        import re
        json_match = re.search(r"```json\s*\n(.*?)\n```", output, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))

        # Try parsing entire output as JSON
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return {
                "utilities": [],
                "lessons": [],
                "summary": "Could not parse analysis output",
            }

    except subprocess.TimeoutExpired:
        return {"utilities": [], "lessons": [], "summary": "Analysis timed out"}
    except FileNotFoundError:
        return {"utilities": [], "lessons": [], "summary": "Claude CLI not found"}


def apply_utility(utility: dict, signature_id: str) -> bool:
    """
    Apply a utility update to the knowledge base.

    Returns True if applied successfully.
    """
    placement = utility.get("placement", "signature")
    name = utility.get("name", "unnamed")
    content = utility.get("content", "")
    description = utility.get("description", "")

    if not content:
        return False

    # Determine target file
    if placement == "common":
        target_dir = KNOWLEDGE_DIR / "common" / "utilities"
    else:
        target_dir = KNOWLEDGE_DIR / "signatures" / signature_id / "utilities"

    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / f"{name}.md"

    # Don't overwrite existing
    if target_file.exists():
        return False

    # Write utility
    timestamp = datetime.now(timezone.utc).isoformat()
    utility_content = f"""# {name}

{description}

## Usage

```
{content}
```

---
*Added: {timestamp}*
*Rationale: {utility.get('rationale', 'N/A')}*
"""

    target_file.write_text(utility_content)
    return True


def apply_lesson(lesson: dict, signature_id: str) -> bool:
    """
    Append a lesson to the appropriate lessons.md file.

    Returns True if applied successfully.
    """
    placement = lesson.get("placement", "signature")
    lesson_type = lesson.get("type", "tip")
    content = lesson.get("content", "")
    evidence = lesson.get("evidence", "")

    if not content:
        return False

    # Determine target file
    if placement == "common":
        target_file = KNOWLEDGE_DIR / "common" / "lessons" / "lessons.md"
    else:
        target_file = KNOWLEDGE_DIR / "signatures" / signature_id / "lessons.md"

    if not target_file.exists():
        return False

    # Read existing content to check for duplicates
    existing = target_file.read_text()
    if content in existing:
        return False  # Already exists

    # Append lesson
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    type_emoji = {"pattern": "🔍", "pitfall": "⚠️", "tip": "💡"}.get(lesson_type, "📝")

    lesson_entry = f"""

### {type_emoji} {lesson_type.title()} ({timestamp})

{content}

*Evidence: {evidence}*
"""

    with open(target_file, "a") as f:
        f.write(lesson_entry)

    return True


def main():
    """Main hook entry point."""
    # Get environment
    run_dir = os.environ.get("INVESTIGATION_RUN_DIR")
    signature_id = os.environ.get("SIGNATURE_ID")

    if not run_dir or not signature_id:
        # Try to read from stdin (Claude Code hook format)
        try:
            hook_input = json.load(sys.stdin)
            run_dir = hook_input.get("cwd", run_dir)
            # Try to extract signature from session data
        except (json.JSONDecodeError, EOFError):
            pass

    if not run_dir:
        print(json.dumps({"error": "No run directory specified"}))
        sys.exit(0)  # Exit 0 to not block Claude Code

    run_dir = Path(run_dir)
    if not run_dir.exists():
        print(json.dumps({"error": f"Run directory not found: {run_dir}"}))
        sys.exit(0)

    # Default signature if not provided
    if not signature_id:
        alert_file = run_dir / "alert.json"
        if alert_file.exists():
            with open(alert_file) as f:
                alert = json.load(f)
                signature_id = alert.get("signature_id", "unknown")
        else:
            signature_id = "unknown"

    # Read investigation report
    report = read_investigation_report(run_dir)
    if not report:
        print(json.dumps({"summary": "No investigation report found"}))
        sys.exit(0)

    # Run analysis
    analysis = run_analysis(report, signature_id)

    # Apply updates
    utilities_applied = 0
    lessons_applied = 0

    for utility in analysis.get("utilities", []):
        if apply_utility(utility, signature_id):
            utilities_applied += 1

    for lesson in analysis.get("lessons", []):
        if apply_lesson(lesson, signature_id):
            lessons_applied += 1

    # Output result
    result = {
        "summary": analysis.get("summary", "Analysis complete"),
        "utilities_applied": utilities_applied,
        "lessons_applied": lessons_applied,
    }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
