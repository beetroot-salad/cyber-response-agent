#!/usr/bin/env python3
"""Stop hook: Validate investigation report frontmatter.

Reads the Claude Code hook event from stdin, finds report.md in the run
directory, parses YAML frontmatter, and performs Tier 1 validation checks.

Exit codes:
    0 - Validation passed (or no report found — nothing to validate)
    2 - Validation failed (message fed back to agent)
"""

import json
import os
import sys
from pathlib import Path

# Add soc-agent root to path for schema imports
SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.report_frontmatter import (
    MIN_LEADS_BY_SEVERITY,
    parse_frontmatter,
)


def parse_yaml_frontmatter(text: str) -> dict:
    """Parse YAML frontmatter from a markdown file.

    Expects content between --- delimiters at the start of the file.
    Simple key: value parser — no external YAML library needed.
    """
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


def get_runs_dir() -> Path:
    """Get the runs directory. Configurable via SOC_AGENT_RUNS_DIR env var."""
    return Path(os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs")))


def find_report_in_runs() -> Path | None:
    """Find the most recent report.md in runs/."""
    runs_dir = get_runs_dir()
    if not runs_dir.exists():
        return None

    reports = sorted(
        runs_dir.glob("*/report.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return reports[0] if reports else None


def check_precedent_exists(matched_precedent: str, signature_id: str) -> bool:
    """Check that the referenced precedent file actually exists."""
    if not matched_precedent:
        return False

    precedent_dir = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "precedents"
    )

    # Try exact match, then with .json extension
    candidate = precedent_dir / matched_precedent
    if candidate.exists():
        return True
    if not matched_precedent.endswith(".json"):
        return (precedent_dir / (matched_precedent + ".json")).exists()
    return False


def get_signature_severity(signature_id: str) -> str:
    """Get severity from context.md frontmatter. Default: medium."""
    context_path = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "context.md"
    )
    if not context_path.exists():
        return "medium"

    with open(context_path) as f:
        content = f.read()

    fm = parse_yaml_frontmatter(content)
    return fm.get("severity", "medium")


def validate(report_path: Path) -> tuple[bool, list[str]]:
    """Run all Tier 1 validation checks on a report.

    Returns (passed, errors).
    """
    errors = []

    with open(report_path) as f:
        content = f.read()

    # Parse frontmatter
    fields = parse_yaml_frontmatter(content)
    if not fields:
        return False, ["report.md has no YAML frontmatter (missing --- delimiters)"]

    report, parse_errors = parse_frontmatter(fields)
    if parse_errors:
        errors.extend(parse_errors)

    if report is None:
        return False, errors

    # Check 1: leads_pursued meets minimum for severity
    severity = get_signature_severity(report.signature_id)
    min_leads = MIN_LEADS_BY_SEVERITY.get(severity, 2)
    if report.leads_pursued < min_leads:
        errors.append(
            f"leads_pursued={report.leads_pursued} is below minimum "
            f"for {severity} severity (requires >= {min_leads})"
        )

    # Check 2: resolved requires precedent file exists
    if report.status == "resolved":
        if not report.matched_precedent:
            errors.append("status=resolved requires matched_precedent")
        elif not check_precedent_exists(report.matched_precedent, report.signature_id):
            errors.append(
                f"matched_precedent '{report.matched_precedent}' not found in "
                f"knowledge/signatures/{report.signature_id}/precedents/"
            )

    return len(errors) == 0, errors


def main():
    """Main entry point — reads hook event from stdin."""
    try:
        sys.stdin.read()
    except Exception:
        pass

    report_path = find_report_in_runs()
    if report_path is None:
        sys.exit(0)

    passed, errors = validate(report_path)

    if passed:
        sys.exit(0)
    else:
        print("Report validation failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
