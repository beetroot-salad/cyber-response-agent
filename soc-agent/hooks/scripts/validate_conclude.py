#!/usr/bin/env python3
"""PostToolUse hook: CONCLUDE transition verification gate.

Fires on Write/Edit/Bash events targeting `investigation.md`. When the
file contains a `## CONCLUDE` header, enforces preconditions that the
investigation is ready to close:

1. ticket-context subagent was dispatched during CONTEXTUALIZE.
   Silent backstop — not surfaced in SKILL.md §CONCLUDE because by
   CONCLUDE time the damage is already done. Exists only so a broken
   preload surfaces somewhere.
2. leads pursued meets the signature severity minimum, counted by
   parsing `**Lead:**` / `**Leads:**` lines in `## GATHER` blocks.
3. `conclusion_checks.json` exists in the run directory and covers
   the expected question set for its declared status. Expected IDs
   are parsed from `skills/investigate/conclusion_checks.md` so the
   two stay in sync.
4. Every citation in `conclusion_checks.json` appears as a verbatim
   substring in `investigation.md`. Prevents fabrication; does not
   evaluate answer quality.

Exit codes:
    0 - Passed (or not a CONCLUDE-triggering write)
    2 - Gate failed (message fed back to agent, blocks the write)
"""

import json
import os
import re
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.frontmatter import parse_yaml_frontmatter
from schemas.report_frontmatter import MIN_LEADS_BY_SEVERITY

CONCLUSION_CHECKS_PROMPT = (
    SOC_AGENT_ROOT / "skills" / "investigate" / "conclusion_checks.md"
)

# Regex to extract an investigation.md path from a Bash command string.
# Stops at shell metacharacters and whitespace.
BASH_INV_PATH_RE = re.compile(r"([^\s'\"<>|&;()`$]*investigation\.md)")

# `## CONCLUDE` header, anchored to line start with a trailing word boundary
# so `## CONCLUDED` or other suffixes don't trigger.
CONCLUDE_HEADER_RE = re.compile(r"^## CONCLUDE\b", re.MULTILINE)

# Each `## GATHER ...` block, captured up to the next `## ` header or EOF.
GATHER_SECTION_RE = re.compile(r"^## GATHER\b.*?(?=^## |\Z)", re.MULTILINE | re.DOTALL)

# `**Lead:** name` or `**Leads:** a, b, c` — the value runs to end of line.
LEAD_LINE_RE = re.compile(r"^\*\*Leads?:\*\*\s*(.+)$", re.MULTILINE)

# Question headers in the prompt file: `### \`question_id\``
QUESTION_HEADER_RE = re.compile(r"^### `([a-z_][a-z0-9_]*)`\s*$", re.MULTILINE)

# Per-status question sections in the prompt file.
STATUS_SECTION_RE = re.compile(
    r"^## Questions — status: (\w+)\s*$(.*?)(?=^## Questions — status:|\Z)",
    re.MULTILINE | re.DOTALL,
)


# ---------------------------------------------------------------------------
# Run directory identification (mirrors infer_state.py)
# ---------------------------------------------------------------------------

def get_runs_dir() -> Path:
    return Path(os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs")))


def extract_run_dir(hook_data: dict) -> Path | None:
    """Extract the run directory from a PostToolUse event targeting
    investigation.md. Returns None if the event is unrelated."""
    tool_input = hook_data.get("tool_input", {})
    tool_name = hook_data.get("tool_name", "")

    file_path_str: str | None = None

    if tool_name in ("Write", "Edit"):
        fp = tool_input.get("file_path", "")
        if fp:
            file_path_str = fp
    elif tool_name == "Bash":
        command = tool_input.get("command", "")
        if "investigation.md" not in command:
            return None
        m = BASH_INV_PATH_RE.search(command)
        if m:
            file_path_str = m.group(1)

    if not file_path_str:
        return None

    path = Path(file_path_str)
    if path.name != "investigation.md":
        return None

    runs_dir = get_runs_dir()
    try:
        path.parent.relative_to(runs_dir)
    except ValueError:
        return None

    return path.parent


def read_signature_id(run_dir: Path) -> str:
    meta_path = run_dir / "meta.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            return meta.get("signature_id", "")
        except (json.JSONDecodeError, KeyError):
            pass
    return ""


def get_signature_severity(signature_id: str) -> str:
    """Read severity from `context.md` frontmatter. Default: medium."""
    if not signature_id:
        return "medium"
    context_path = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "context.md"
    )
    if not context_path.exists():
        return "medium"
    fm = parse_yaml_frontmatter(context_path.read_text())
    return fm.get("severity") or "medium"


# ---------------------------------------------------------------------------
# Gate 1: ticket-context dispatched
# ---------------------------------------------------------------------------

def check_ticket_context_spawned(run_dir: Path) -> str | None:
    """Return None on pass, error message on fail. Primary check is the
    preloaded `ticket_context.yaml`; fallback scans the audit log for a
    manual Task/Agent dispatch of the ticket-context subagent."""
    if (run_dir / "ticket_context.yaml").exists():
        return None

    audit_path = run_dir.parent / "tool_audit.jsonl"
    if not audit_path.exists():
        # Audit hook not running — no signal available, don't fail.
        return None

    try:
        lines = audit_path.read_text().splitlines()
    except OSError:
        return None

    for line in lines:
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("tool_name") not in ("Task", "Agent"):
            continue
        blob = json.dumps(ev.get("tool_input", {})).lower()
        if "ticket-context" in blob or "ticket_context" in blob:
            return None

    return (
        "ticket-context subagent was not dispatched. The CONTEXTUALIZE "
        "preload script normally writes ticket_context.yaml to the run "
        "directory; if it failed, dispatch the subagent manually using "
        "skills/investigate/ticket-context.md and re-write the CONCLUDE "
        "header."
    )


# ---------------------------------------------------------------------------
# Gate 2: leads pursued meets severity minimum
# ---------------------------------------------------------------------------

def count_leads_from_investigation(investigation_text: str) -> int:
    """Count distinct named leads across all `## GATHER` blocks.

    Parses each GATHER block for `**Lead:** X` or `**Leads:** a, b, c`
    lines and collects the names into a set. Composite dispatches
    contribute each named lead separately.
    """
    leads_seen: set[str] = set()
    for block_match in GATHER_SECTION_RE.finditer(investigation_text):
        block = block_match.group(0)
        for lead_match in LEAD_LINE_RE.finditer(block):
            names = lead_match.group(1).strip()
            # The skill template has `**Lead:** lead-name` or
            # `**Leads:** a, b, c (for composite)` — strip any trailing
            # parenthetical comment and split on commas.
            if "(" in names:
                names = names.split("(", 1)[0]
            for name in names.split(","):
                name = name.strip().strip("*").strip()
                if name:
                    leads_seen.add(name)
    return len(leads_seen)


def check_leads_minimum(run_dir: Path, investigation_text: str) -> str | None:
    signature_id = read_signature_id(run_dir)
    severity = get_signature_severity(signature_id)
    min_leads = MIN_LEADS_BY_SEVERITY.get(severity, 2)
    count = count_leads_from_investigation(investigation_text)
    if count < min_leads:
        return (
            f"leads pursued count={count} is below minimum for {severity} "
            f"severity (requires >= {min_leads}). Return to HYPOTHESIZE and "
            f"pursue additional diagnostic leads before concluding."
        )
    return None


# ---------------------------------------------------------------------------
# Gates 3 + 4: conclusion_checks.json
# ---------------------------------------------------------------------------

def load_expected_questions() -> dict[str, list[str]]:
    """Parse the agent-facing prompt to discover expected question IDs per
    status. Returns {"resolved": [...], "escalated": [...]}."""
    if not CONCLUSION_CHECKS_PROMPT.exists():
        return {}
    text = CONCLUSION_CHECKS_PROMPT.read_text()
    result: dict[str, list[str]] = {}
    for match in STATUS_SECTION_RE.finditer(text):
        status = match.group(1).strip()
        section = match.group(2)
        ids = QUESTION_HEADER_RE.findall(section)
        result[status] = ids
    return result


def check_conclusion_file(run_dir: Path, investigation_text: str) -> str | None:
    """Validate conclusion_checks.json shape, question set, and citations."""
    checks_path = run_dir / "conclusion_checks.json"
    if not checks_path.exists():
        return (
            "conclusion_checks.json not found in run directory. Read "
            "skills/investigate/conclusion_checks.md and write your answers "
            "to conclusion_checks.json *before* writing the ## CONCLUDE header."
        )

    try:
        data = json.loads(checks_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return f"conclusion_checks.json is not valid JSON: {e}"

    if not isinstance(data, dict):
        return (
            "conclusion_checks.json must be a JSON object with 'status' and "
            "'checks' fields"
        )

    status = data.get("status")
    if status not in ("resolved", "escalated"):
        return (
            f"conclusion_checks.json 'status' must be 'resolved' or "
            f"'escalated', got {status!r}"
        )

    checks = data.get("checks")
    if not isinstance(checks, list):
        return "conclusion_checks.json 'checks' must be a list"

    expected = load_expected_questions()
    if status not in expected:
        return (
            f"conclusion_checks.md does not define a question set for "
            f"status '{status}'"
        )
    expected_ids = set(expected[status])

    actual_ids: list[str] = []
    for i, entry in enumerate(checks):
        if not isinstance(entry, dict):
            return f"conclusion_checks.json checks[{i}] must be an object"
        qid = entry.get("question_id")
        if not qid:
            return f"conclusion_checks.json checks[{i}] is missing 'question_id'"
        actual_ids.append(qid)

    actual_set = set(actual_ids)
    missing = expected_ids - actual_set
    extra = actual_set - expected_ids
    if missing:
        return (
            f"conclusion_checks.json is missing required question(s) for "
            f"status={status}: {sorted(missing)}"
        )
    if extra:
        return (
            f"conclusion_checks.json contains unexpected question(s): "
            f"{sorted(extra)}. Valid for status={status}: {sorted(expected_ids)}"
        )

    # Gate 4: citation resolution
    for entry in checks:
        qid = entry["question_id"]
        answer = entry.get("answer", "")
        if not isinstance(answer, str) or not answer.strip():
            return (
                f"conclusion_checks.json question '{qid}' has empty or "
                f"missing 'answer'"
            )
        citations = entry.get("citations")
        if not isinstance(citations, list) or not citations:
            return (
                f"conclusion_checks.json question '{qid}' must have a "
                f"non-empty 'citations' list"
            )
        for j, citation in enumerate(citations):
            if not isinstance(citation, str) or not citation.strip():
                return (
                    f"conclusion_checks.json question '{qid}' citation[{j}] "
                    f"is empty or whitespace-only"
                )
            if citation not in investigation_text:
                preview = citation[:80] + ("..." if len(citation) > 80 else "")
                return (
                    f"conclusion_checks.json question '{qid}' citation not "
                    f"found in investigation.md: {preview!r}. Citations must "
                    f"be verbatim substrings copied from the investigation log."
                )

    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    run_dir = extract_run_dir(hook_data)
    if run_dir is None:
        sys.exit(0)

    investigation_path = run_dir / "investigation.md"
    if not investigation_path.exists():
        sys.exit(0)

    investigation_text = investigation_path.read_text()
    if not CONCLUDE_HEADER_RE.search(investigation_text):
        sys.exit(0)

    errors: list[str] = []

    err = check_ticket_context_spawned(run_dir)
    if err:
        errors.append(err)

    err = check_leads_minimum(run_dir, investigation_text)
    if err:
        errors.append(err)

    err = check_conclusion_file(run_dir, investigation_text)
    if err:
        errors.append(err)

    if errors:
        print("CONCLUDE gate failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
