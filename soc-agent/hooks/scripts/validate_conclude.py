#!/usr/bin/env python3
"""PostToolUse hook: CONCLUDE transition verification gate.

Fires on Write/Edit of `investigation.md` (narrowed by `if` filters in
plugin.json). When the file contains a `## CONCLUDE` header, enforces
preconditions that the investigation is ready to close:

1. ticket-context subagent was dispatched during CONTEXTUALIZE.
   Silent backstop — not surfaced in SKILL.md §CONCLUDE because by
   CONCLUDE time the damage is already done. Exists only so a broken
   preload surfaces somewhere.
2. leads pursued meets the signature severity minimum, counted by
   parsing `**Lead:**` / `**Leads:**` lines in `## GATHER` blocks.
   Skipped for screen-resolved investigations (no GATHER blocks by
   construction — their safety comes from SCREEN pattern match +
   precedent + judge validation in validate_report.py).
3. `conclusion_checks.json` exists in the run directory and covers
   the expected question set for its declared status. Expected IDs
   are parsed from `skills/investigate/conclusion_checks.md` so the
   two stay in sync. Skipped for screen-resolved investigations.
4. Every citation in `conclusion_checks.json` appears as a verbatim
   substring in `investigation.md`. Prevents fabrication; does not
   evaluate answer quality.

Exit codes:
    0 - Passed (or not a CONCLUDE-triggering write)
    2 - Gate failed (message fed back to agent, blocks the write)
"""

import json
import re
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.investigation_parse import (
    count_distinct_leads,
    has_conclude_header,
    is_screen_resolved,
)
from hooks.scripts.run_context import extract_run_dir
from schemas.report_frontmatter import MIN_LEADS_BY_SEVERITY

CONCLUSION_CHECKS_PROMPT = (
    SOC_AGENT_ROOT / "skills" / "investigate" / "conclusion_checks.md"
)

# Question headers in the prompt file: `### \`question_id\``
QUESTION_HEADER_RE = re.compile(r"^### `([a-z_][a-z0-9_]*)`\s*$", re.MULTILINE)

# Per-status question sections in the prompt file.
STATUS_SECTION_RE = re.compile(
    r"^## Questions — status: (\w+)\s*$(.*?)(?=^## Questions — status:|\Z)",
    re.MULTILINE | re.DOTALL,
)


# ---------------------------------------------------------------------------
# meta.json access
# ---------------------------------------------------------------------------

def read_meta(run_dir: Path) -> dict:
    meta_path = run_dir / "meta.json"
    if not meta_path.exists():
        return {}
    try:
        return json.loads(meta_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


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

def check_leads_minimum(run_dir: Path, investigation_text: str) -> str | None:
    meta = read_meta(run_dir)
    severity = meta.get("severity")
    if not severity:
        # setup_run.py validates severity at run creation, so a missing
        # value here means meta.json predates that validation or was
        # written by a different harness. Don't fail the gate on that —
        # surface it as a soft pass with no enforcement.
        return None
    min_leads = MIN_LEADS_BY_SEVERITY.get(severity)
    if min_leads is None:
        return None
    count = count_distinct_leads(investigation_text)
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
    if not has_conclude_header(investigation_text):
        sys.exit(0)

    errors: list[str] = []

    err = check_ticket_context_spawned(run_dir)
    if err:
        errors.append(err)

    if is_screen_resolved(investigation_text):
        # Screen-resolved runs go straight from SCREEN to CONCLUDE without a
        # GATHER loop. The leads-floor and self-check questions both assume
        # the hypothesis loop ran, so they don't apply. Safety for screen
        # runs comes from SCREEN pattern match + precedent + the report
        # validation Tier 1/2 hooks in validate_report.py.
        pass
    else:
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
