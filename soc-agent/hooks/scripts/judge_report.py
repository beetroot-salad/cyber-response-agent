#!/usr/bin/env python3
"""Stop hook: Tier 2 semantic judge for investigation reports.

Runs after validate_report.py (Tier 1) passes. Uses claude CLI with Haiku
to validate report consistency, completeness, and precedent match validity.

Reads the investigation artifacts from the run directory, assembles the judge
prompt from judge_prompt.md, and invokes claude CLI.

Exit codes:
    0 - Validation passed (or not applicable — no report, no precedent, etc.)
    2 - Validation failed (FLAG verdict — message fed back to agent)
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Add soc-agent root to path for schema imports
SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.frontmatter import parse_yaml_frontmatter
from schemas.report_frontmatter import parse_frontmatter

JUDGE_PROMPT_PATH = Path(__file__).resolve().parent / "judge_prompt.md"
JUDGE_MODEL = os.environ.get("SOC_AGENT_JUDGE_MODEL", "haiku")


def get_runs_dir() -> Path:
    """Get the runs directory. Configurable via SOC_AGENT_RUNS_DIR env var."""
    return Path(os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs")))


def find_latest_run_dir() -> Path | None:
    """Find the most recent run directory (by mtime of report.md)."""
    runs_dir = get_runs_dir()
    if not runs_dir.exists():
        return None

    reports = sorted(
        runs_dir.glob("*/report.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return reports[0].parent if reports else None


def load_report_frontmatter(report_path: Path) -> dict | None:
    """Parse report frontmatter. Returns None if invalid."""
    content = report_path.read_text()
    fields = parse_yaml_frontmatter(content)
    if not fields:
        return None
    report, errors = parse_frontmatter(fields)
    if errors:
        return None
    return fields


def load_precedent(signature_id: str, matched_precedent: str) -> dict | None:
    """Load the matched precedent JSON."""
    precedent_dir = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "precedents"
    )
    candidate = precedent_dir / matched_precedent
    if candidate.exists():
        return json.loads(candidate.read_text())
    if not matched_precedent.endswith(".json"):
        candidate = precedent_dir / (matched_precedent + ".json")
        if candidate.exists():
            return json.loads(candidate.read_text())
    return None


def read_file_safe(path: Path, label: str) -> str:
    """Read file contents or return a placeholder."""
    if path.exists():
        return path.read_text()
    return f"[{label} not found: {path.name}]"


def assemble_prompt(
    alert_data: str,
    investigation_log: str,
    report: str,
    precedent: str,
) -> str:
    """Assemble the judge prompt from the template and context."""
    template = JUDGE_PROMPT_PATH.read_text()
    prompt = template.replace("{alert_data}", alert_data)
    prompt = prompt.replace("{investigation_log}", investigation_log)
    prompt = prompt.replace("{report}", report)
    prompt = prompt.replace("{precedent}", precedent)
    return prompt


def invoke_judge(prompt: str) -> tuple[str, int]:
    """Invoke claude CLI with the judge prompt.

    Returns (output, returncode).
    """
    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--model", JUDGE_MODEL, "--output-format", "text"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout.strip(), result.returncode
    except FileNotFoundError:
        return "claude CLI not found", 1
    except subprocess.TimeoutExpired:
        return "judge timed out after 30s", 1


def parse_verdict(output: str) -> tuple[str, str]:
    """Parse the VERDICT line from judge output.

    Returns (pass|flag, reason).
    """
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("VERDICT:"):
            rest = line[len("VERDICT:"):].strip()
            match = re.match(r"(PASS|FLAG)\s*[—\-]\s*(.*)", rest, re.IGNORECASE)
            if match:
                return match.group(1).upper(), match.group(2)
            # Fallback: just check for PASS/FLAG
            if "PASS" in rest.upper():
                return "PASS", rest
            return "FLAG", rest
    return "FLAG", "could not parse judge verdict from output"


def main():
    """Main entry point — reads hook event from stdin, runs Tier 2 judge."""
    # Consume stdin (hook protocol)
    try:
        sys.stdin.read()
    except Exception:
        pass

    # Find latest run
    run_dir = find_latest_run_dir()
    if run_dir is None:
        sys.exit(0)

    report_path = run_dir / "report.md"
    if not report_path.exists():
        sys.exit(0)

    # Parse report frontmatter — only judge resolved reports with a precedent
    fm = load_report_frontmatter(report_path)
    if fm is None:
        sys.exit(0)

    status = fm.get("status", "")
    matched_precedent = fm.get("matched_precedent")
    signature_id = fm.get("signature_id", "")

    # Only run judge on resolved reports that claim a precedent match
    if status != "resolved" or not matched_precedent:
        sys.exit(0)

    # Load artifacts
    precedent_data = load_precedent(signature_id, matched_precedent)
    if precedent_data is None:
        # Tier 1 should have caught this, but be safe
        print("Tier 2 judge: matched precedent not found", file=sys.stderr)
        sys.exit(2)

    alert_text = read_file_safe(run_dir / "alert.json", "alert data")
    investigation_text = read_file_safe(run_dir / "investigation.md", "investigation log")
    report_text = report_path.read_text()
    precedent_text = json.dumps(precedent_data, indent=2)

    # Assemble and invoke
    prompt = assemble_prompt(alert_text, investigation_text, report_text, precedent_text)
    output, returncode = invoke_judge(prompt)

    if returncode != 0:
        # Judge invocation failed — fail safe, escalate
        print(
            f"Tier 2 judge: claude CLI error (rc={returncode}): {output}",
            file=sys.stderr,
        )
        sys.exit(2)

    # Parse verdict
    verdict, reason = parse_verdict(output)

    if verdict == "PASS":
        sys.exit(0)
    else:
        print(f"Tier 2 judge flagged report: {reason}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Full judge output:", file=sys.stderr)
        print(output, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
