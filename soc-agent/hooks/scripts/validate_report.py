#!/usr/bin/env python3
"""PostToolUse hook: Combined Tier 1 + Tier 2 report validation.

Fires on Write/Edit tool calls. Checks if the written file is a report.md
inside a run directory. If so, runs:
  - Tier 1: deterministic frontmatter validation (fast, no dependencies)
  - Tier 2: semantic judge via claude CLI with Haiku (only for valid reports)

The run directory is extracted deterministically from tool_input.file_path.

Exit codes:
    0 - Validation passed (or not a report.md write — nothing to validate)
    2 - Validation failed (message fed back to agent)
"""

import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

# Add soc-agent root to path for schema imports
SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.frontmatter import parse_yaml_frontmatter
from schemas.precedent import check_recency, DEFAULT_MAX_AGE_DAYS
from schemas.report_frontmatter import (
    MIN_LEADS_BY_SEVERITY,
    parse_frontmatter,
)

JUDGE_PROMPT_PATH = Path(__file__).resolve().parent / "judge_prompt.md"
JUDGE_MODEL = os.environ.get("SOC_AGENT_JUDGE_MODEL", "haiku")


# ---------------------------------------------------------------------------
# Run directory identification (from PostToolUse event)
# ---------------------------------------------------------------------------

def get_runs_dir() -> Path:
    """Get the runs directory. Configurable via SOC_AGENT_RUNS_DIR env var."""
    return Path(os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs")))


def extract_run_dir(hook_data: dict) -> Path | None:
    """Extract the run directory from a PostToolUse event.

    Returns the parent directory if the tool wrote to a report.md
    inside the runs directory. Returns None otherwise.
    """
    tool_input = hook_data.get("tool_input", {})
    file_path = tool_input.get("file_path", "")
    if not file_path:
        return None

    path = Path(file_path)
    if path.name != "report.md":
        return None

    # Verify it's inside the runs directory
    runs_dir = get_runs_dir()
    try:
        path.parent.relative_to(runs_dir)
    except ValueError:
        return None

    return path.parent


# ---------------------------------------------------------------------------
# Tier 1: Deterministic validation
# ---------------------------------------------------------------------------

def get_precedent_max_age(signature_id: str) -> int:
    """Load precedent_max_age_days from permissions.yaml, or use default."""
    perms_path = (
        SOC_AGENT_ROOT / "config" / "signatures" / signature_id / "permissions.yaml"
    )
    if not perms_path.exists():
        return DEFAULT_MAX_AGE_DAYS
    try:
        import yaml
        data = yaml.safe_load(perms_path.read_text()) or {}
    except Exception:
        # yaml not available or parse error — use default
        # Fall back to simple key scanning for stdlib-only envs
        try:
            for line in perms_path.read_text().splitlines():
                line = line.strip()
                if line.startswith("precedent_max_age_days:"):
                    return int(line.split(":", 1)[1].strip())
        except (ValueError, IndexError):
            pass
        return DEFAULT_MAX_AGE_DAYS
    return int(data.get("precedent_max_age_days", DEFAULT_MAX_AGE_DAYS))


def validate_precedent_content(
    matched_precedent: str, signature_id: str
) -> list[str]:
    """Load and validate precedent content: signature_id match + recency."""
    errors = []
    precedent_dir = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "precedents"
    )
    candidate = precedent_dir / matched_precedent
    if not candidate.exists() and not matched_precedent.endswith(".json"):
        candidate = precedent_dir / (matched_precedent + ".json")
    if not candidate.exists():
        return []  # file-existence is checked separately

    try:
        data = json.loads(candidate.read_text())
    except (json.JSONDecodeError, OSError) as e:
        errors.append(f"precedent '{matched_precedent}' is not valid JSON: {e}")
        return errors

    # Check signature_id matches
    prec_sig = data.get("signature_id", "")
    if prec_sig != signature_id:
        errors.append(
            f"precedent signature_id '{prec_sig}' does not match "
            f"report signature_id '{signature_id}'"
        )

    # Check recency
    validated_at = data.get("validated_at")
    if not validated_at:
        errors.append(
            f"precedent '{matched_precedent}' has no validated_at field"
        )
    else:
        max_age = get_precedent_max_age(signature_id)
        fresh, msg = check_recency(validated_at, max_age)
        if not fresh:
            errors.append(f"precedent '{matched_precedent}': {msg}")

    return errors


def check_precedent_exists(matched_precedent: str, signature_id: str) -> bool:
    """Check that the referenced precedent file actually exists."""
    if not matched_precedent:
        return False

    precedent_dir = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "precedents"
    )

    candidate = precedent_dir / matched_precedent
    if candidate.exists():
        return True
    if not matched_precedent.endswith(".json"):
        return (precedent_dir / (matched_precedent + ".json")).exists()
    return False


# ---------------------------------------------------------------------------
# Archetype + trust anchor validation (new model)
# ---------------------------------------------------------------------------

def load_archetype_frontmatter(matched_archetype: str, signature_id: str) -> dict | None:
    """Load and parse the YAML frontmatter of an archetype file.

    Returns None if the file does not exist or has no frontmatter.
    """
    archetype_dir = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "archetypes"
    )
    candidate = archetype_dir / matched_archetype
    if not candidate.exists() and not matched_archetype.endswith(".md"):
        candidate = archetype_dir / (matched_archetype + ".md")
    if not candidate.exists():
        return None
    return parse_yaml_frontmatter(candidate.read_text())


def check_archetype_exists(matched_archetype: str, signature_id: str) -> bool:
    """Check that the referenced archetype file actually exists and parses."""
    if not matched_archetype:
        return False
    return load_archetype_frontmatter(matched_archetype, signature_id) is not None


def validate_archetype_anchors(
    matched_archetype: str,
    signature_id: str,
    anchors_consulted: list,
) -> list[str]:
    """Verify every required anchor on the archetype was consulted and confirmed.

    Called only when status=resolved. An archetype with required_anchors
    cannot resolve to a non-escalation status without all of them confirming.
    """
    fm = load_archetype_frontmatter(matched_archetype, signature_id)
    if fm is None:
        return []  # existence is checked separately

    required = fm.get("required_anchors") or []
    if not isinstance(required, list):
        return [
            f"archetype '{matched_archetype}' has invalid required_anchors "
            f"(must be a list)"
        ]

    consulted_by_name: dict = {}
    for entry in anchors_consulted or []:
        if isinstance(entry, dict) and entry.get("anchor"):
            consulted_by_name[entry["anchor"]] = entry

    errors: list[str] = []
    for anchor_name in required:
        if anchor_name not in consulted_by_name:
            errors.append(
                f"archetype '{matched_archetype}' requires anchor "
                f"'{anchor_name}' but it was not consulted"
            )
            continue
        entry = consulted_by_name[anchor_name]
        result = entry.get("result", "")
        if result != "confirmed":
            errors.append(
                f"archetype '{matched_archetype}' requires anchor "
                f"'{anchor_name}' to be confirmed but result was '{result}'"
            )

    return errors


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


def is_screen_resolved(run_dir: Path) -> bool:
    """Check if this investigation was resolved via the SCREEN phase.

    Reads state.json and checks if SCREEN is in history but HYPOTHESIZE
    is not (i.e., the investigation didn't enter the full loop).
    """
    state_path = run_dir / "state.json"
    if not state_path.exists():
        return False
    try:
        state = json.loads(state_path.read_text())
        history = state.get("history", [])
        return "SCREEN" in history and "HYPOTHESIZE" not in history
    except (json.JSONDecodeError, KeyError):
        return False


def playbook_has_screen_section(signature_id: str) -> bool:
    """Check if the playbook for this signature has a ## Screen section."""
    playbook_path = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "playbook.md"
    )
    if not playbook_path.exists():
        return False
    content = playbook_path.read_text()
    return bool(re.search(r"^## Screen\b", content, re.MULTILINE))


def check_ticket_context_spawned(run_dir: Path) -> str | None:
    """Verify a ticket-context subagent was spawned during this investigation.

    SKILL.md §CONTEXTUALIZE requires spawning a ticket-context subagent (Task
    tool) to handle cross-alert recurrence and prior-investigation checks.
    Without it, recurring-pattern detection is structurally incomplete and the
    main agent ends up doing those queries inline with weaker context.

    Walks the per-run audit log for any Task call whose tool_input references
    the ticket-context prompt path or contains ticket-context as a keyword.
    Returns None on pass, an error message on fail.
    """
    audit_path = run_dir.parent / "tool_audit.jsonl"
    if not audit_path.exists():
        # No audit log means the audit hook hasn't run (or isn't configured).
        # Don't fail validation in that case — the absence is its own signal
        # but not actionable from here.
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
        if ev.get("tool_name") != "Task":
            continue
        # Inspect the tool_input as a serialized blob — the agent may put the
        # ticket-context reference in the prompt, the description, or via the
        # file path. Substring match handles all three.
        blob = json.dumps(ev.get("tool_input", {})).lower()
        if "ticket-context" in blob or "ticket_context" in blob:
            return None

    return (
        "no ticket-context subagent invocation found in tool_audit.jsonl. "
        "SKILL.md §CONTEXTUALIZE requires spawning a ticket-context subagent "
        "via the Task tool (prompt template at "
        "skills/investigate/ticket-context.md) to handle cross-alert "
        "recurrence and prior-investigation checks. Without it, "
        "recurring-pattern detection is structurally incomplete. Spawn it "
        "now with Task(subagent_type=..., description=..., prompt=<contents "
        "of ticket-context.md with {run_dir} substituted>), then re-write "
        "report.md."
    )


def validate_tier1(report_path: Path) -> tuple[bool, list[str], dict | None]:
    """Run Tier 1 validation. Returns (passed, errors, frontmatter_fields)."""
    errors = []

    content = report_path.read_text()
    fields = parse_yaml_frontmatter(content)
    if not fields:
        return False, ["report.md has no YAML frontmatter (missing --- delimiters)"], None

    report, parse_errors = parse_frontmatter(fields)
    if parse_errors:
        errors.extend(parse_errors)

    if report is None:
        return False, errors, None

    # Determine if this is a screen-resolved investigation
    run_dir = report_path.parent
    screen = is_screen_resolved(run_dir)

    # Check: ticket-context subagent must have been spawned during CONTEXTUALIZE.
    # This applies to all investigations regardless of screen-resolution, since
    # CONTEXTUALIZE runs before SCREEN in the phase ordering.
    ticket_ctx_error = check_ticket_context_spawned(run_dir)
    if ticket_ctx_error:
        errors.append(ticket_ctx_error)

    # Check: leads_pursued meets minimum for severity
    # Screen-resolved reports are exempt — their safety comes from
    # precedent match + pattern match + judge validation
    if screen:
        if not playbook_has_screen_section(report.signature_id):
            errors.append(
                f"report is screen-resolved but playbook for "
                f"'{report.signature_id}' has no ## Screen section"
            )
    else:
        severity = get_signature_severity(report.signature_id)
        min_leads = MIN_LEADS_BY_SEVERITY.get(severity, 2)
        if report.leads_pursued < min_leads:
            errors.append(
                f"leads_pursued={report.leads_pursued} is below minimum "
                f"for {severity} severity (requires >= {min_leads})"
            )

    # Check: resolved requires either matched_archetype or matched_precedent
    if report.status == "resolved":
        has_archetype = bool(report.matched_archetype)
        has_precedent = bool(report.matched_precedent)

        if not has_archetype and not has_precedent:
            errors.append(
                "status=resolved requires matched_archetype or matched_precedent"
            )

        if has_archetype:
            if not check_archetype_exists(
                report.matched_archetype, report.signature_id
            ):
                errors.append(
                    f"matched_archetype '{report.matched_archetype}' not found in "
                    f"knowledge/signatures/{report.signature_id}/archetypes/"
                )
            else:
                anchor_errors = validate_archetype_anchors(
                    report.matched_archetype,
                    report.signature_id,
                    report.trust_anchors_consulted,
                )
                errors.extend(anchor_errors)

        if has_precedent:
            if not check_precedent_exists(
                report.matched_precedent, report.signature_id
            ):
                errors.append(
                    f"matched_precedent '{report.matched_precedent}' not found in "
                    f"knowledge/signatures/{report.signature_id}/precedents/"
                )
            else:
                content_errors = validate_precedent_content(
                    report.matched_precedent, report.signature_id
                )
                errors.extend(content_errors)

    return len(errors) == 0, errors, fields


# ---------------------------------------------------------------------------
# Tier 2: Semantic judge
# ---------------------------------------------------------------------------

def load_report_frontmatter(report_path: Path) -> dict | None:
    """Parse report frontmatter. Returns None if invalid or missing."""
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


def get_run_salt(run_dir: Path) -> str:
    """Get the per-run salt from meta.json, or generate a fallback."""
    meta_path = run_dir / "meta.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            return meta.get("salt", "")
        except (json.JSONDecodeError, KeyError):
            pass
    # Fallback: generate a per-invocation salt
    return secrets.token_hex(8)


def wrap_untrusted(content: str, tag: str, salt: str) -> str:
    """Wrap untrusted content in salted delimiters."""
    return f"<run-{salt}-{tag}>\n{content}\n</run-{salt}-{tag}>"


def assemble_prompt(
    alert_data: str,
    investigation_log: str,
    report: str,
    precedent: str | None,
    salt: str,
) -> str:
    """Assemble the judge prompt from the template and context.

    If precedent is None, the prompt runs in no-precedent mode (4 criteria).
    """
    template = JUDGE_PROMPT_PATH.read_text()

    # Wrap untrusted content with salted delimiters
    safe_alert = wrap_untrusted(alert_data, "alert-data", salt)
    safe_log = wrap_untrusted(investigation_log, "investigation-log", salt)

    prompt = template.replace("{alert_data}", safe_alert)
    prompt = prompt.replace("{investigation_log}", safe_log)
    prompt = prompt.replace("{report}", report)

    if precedent is not None:
        safe_precedent = wrap_untrusted(precedent, "precedent", salt)
        prompt = prompt.replace("{precedent}", safe_precedent)
        prompt = prompt.replace("{judge_mode}", "full")
    else:
        prompt = prompt.replace("{precedent}", "[No precedent — this is an escalated report]")
        prompt = prompt.replace("{judge_mode}", "no-precedent")

    return prompt


def invoke_judge(prompt: str) -> tuple[str, int]:
    """Invoke claude CLI with the judge prompt. Returns (output, returncode)."""
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
    """Parse the VERDICT line from judge output. Returns (pass|flag, reason)."""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("VERDICT:"):
            rest = line[len("VERDICT:"):].strip()
            match = re.match(r"(PASS|FLAG)\s*[—\-]\s*(.*)", rest, re.IGNORECASE)
            if match:
                return match.group(1).upper(), match.group(2)
            if "PASS" in rest.upper():
                return "PASS", rest
            return "FLAG", rest
    return "FLAG", "could not parse judge verdict from output"


def run_tier2(run_dir: Path, fields: dict) -> tuple[bool, str]:
    """Run Tier 2 semantic judge. Returns (passed, message)."""
    status = fields.get("status", "")
    matched_precedent = fields.get("matched_precedent")
    signature_id = fields.get("signature_id", "")

    # Load precedent if available (resolved reports always have one after Tier 1)
    precedent_data = None
    if matched_precedent:
        precedent_data = load_precedent(signature_id, matched_precedent)
        if precedent_data is None:
            return False, f"matched precedent '{matched_precedent}' could not be loaded"

    # Load artifacts
    salt = get_run_salt(run_dir)
    alert_text = read_file_safe(run_dir / "alert.json", "alert data")
    investigation_text = read_file_safe(run_dir / "investigation.md", "investigation log")
    report_text = (run_dir / "report.md").read_text()
    precedent_text = json.dumps(precedent_data, indent=2) if precedent_data else None

    # Assemble and invoke
    prompt = assemble_prompt(alert_text, investigation_text, report_text, precedent_text, salt)
    output, returncode = invoke_judge(prompt)

    if returncode != 0:
        return False, f"claude CLI error (rc={returncode}): {output}"

    verdict, reason = parse_verdict(output)

    if verdict == "PASS":
        return True, ""
    else:
        return False, f"Judge flagged report: {reason}\n\nFull judge output:\n{output}"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    """Main entry point — reads PostToolUse event from stdin."""
    try:
        raw = sys.stdin.read()
        hook_data = json.loads(raw)
    except Exception:
        sys.exit(0)

    # Only process report.md writes inside runs/
    run_dir = extract_run_dir(hook_data)
    if run_dir is None:
        sys.exit(0)

    report_path = run_dir / "report.md"
    if not report_path.exists():
        sys.exit(0)

    # --- Tier 1: Deterministic validation ---
    passed, errors, fields = validate_tier1(report_path)

    if not passed:
        print("Report validation failed (Tier 1):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(2)

    if fields is None:
        sys.exit(0)

    # --- Tier 2: Semantic judge ---
    passed, message = run_tier2(run_dir, fields)

    if passed:
        sys.exit(0)
    else:
        print(f"Report validation failed (Tier 2):\n{message}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
