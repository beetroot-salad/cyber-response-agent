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
import re
import sys
from pathlib import Path

# Add soc-agent root to path for schema imports
SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts import permissions as permissions_module
from hooks.scripts.frontmatter import parse_yaml_frontmatter
from hooks.scripts.judge_runner import (
    get_run_salt,
    invoke_judge,
    parse_verdict,
    wrap_untrusted,
)
from hooks.scripts.run_context import get_runs_dir
from schemas.precedent import check_recency
from schemas.report_frontmatter import parse_frontmatter

JUDGE_PROMPT_PATH = Path(__file__).resolve().parent / "judge_prompt.md"


# ---------------------------------------------------------------------------
# Run directory identification (from PostToolUse event)
# ---------------------------------------------------------------------------

def extract_run_dir(hook_data: dict) -> Path | None:
    """Extract the run directory from a PostToolUse event targeting report.md.

    Note: this hook validates report.md, not investigation.md, so it can't
    use the shared run_context.extract_run_dir helper (which is keyed on
    investigation.md).
    """
    tool_input = hook_data.get("tool_input", {})
    file_path = tool_input.get("file_path", "")
    if not file_path:
        return None

    path = Path(file_path)
    if path.name != "report.md":
        return None

    if path.parent.parent != get_runs_dir():
        return None
    return path.parent


# ---------------------------------------------------------------------------
# Tier 1: Deterministic validation
# ---------------------------------------------------------------------------

def get_precedent_max_age(signature_id: str) -> int:
    """Load precedent_max_age_days from permissions.yaml, or use default.

    Delegates to hooks.scripts.permissions, passing our SOC_AGENT_ROOT so
    tests that monkeypatch this module's root still hit the expected file.
    """
    return permissions_module.get_precedent_max_age(signature_id, root=SOC_AGENT_ROOT)


def _precedent_path(
    signature_id: str, matched_archetype: str, matched_ticket_id: str
) -> Path:
    """Resolve the filesystem path to a precedent snapshot under its archetype."""
    archetype_dir = (
        SOC_AGENT_ROOT
        / "knowledge"
        / "signatures"
        / signature_id
        / "archetypes"
        / matched_archetype
    )
    filename = matched_ticket_id
    if not filename.endswith(".json"):
        filename = filename + ".json"
    return archetype_dir / filename


def validate_precedent_content(
    matched_archetype: str,
    matched_ticket_id: str,
    signature_id: str,
) -> list[str]:
    """Load and validate precedent snapshot content: schema + recency +
    archetype-matches-parent-dir cross-check."""
    errors = []
    candidate = _precedent_path(signature_id, matched_archetype, matched_ticket_id)
    if not candidate.exists():
        return []  # file-existence is checked separately

    try:
        data = json.loads(candidate.read_text())
    except (json.JSONDecodeError, OSError) as e:
        errors.append(
            f"precedent '{matched_ticket_id}' is not valid JSON: {e}"
        )
        return errors

    # Cross-check: archetype field must match parent directory name
    prec_archetype = data.get("archetype", "")
    if prec_archetype != matched_archetype:
        errors.append(
            f"precedent '{matched_ticket_id}' archetype field "
            f"'{prec_archetype}' does not match parent directory "
            f"'{matched_archetype}'"
        )

    # Check recency against captured_at
    captured_at = data.get("captured_at")
    if not captured_at:
        errors.append(
            f"precedent '{matched_ticket_id}' has no captured_at field"
        )
    else:
        max_age = get_precedent_max_age(signature_id)
        fresh, msg = check_recency(captured_at, max_age)
        if not fresh:
            errors.append(f"precedent '{matched_ticket_id}': {msg}")

    return errors


def validate_temporal_anchors_reconfirmed(
    matched_archetype: str,
    matched_ticket_id: str,
    signature_id: str,
    anchors_consulted: list,
) -> list[str]:
    """Enforce: every temporal anchor cited by the precedent must be
    re-confirmed in this investigation.

    A precedent's `anchors_at_time` may mark entries with `temporal: true`
    — confirmations that were time-bounded at the moment the past ticket
    closed (business trip, change window, deploy run, on-call shift).
    Temporal confirmations do not transfer forward in time: a later alert
    with the same shape and entities cannot inherit that disposition
    unless the temporal state is re-confirmed now.

    For each `temporal: true` entry in the precedent, the current report's
    `trust_anchors_consulted` must contain a matching entry with
    `result: confirmed`. Otherwise the precedent match is stale and
    grounding fails.
    """
    errors: list[str] = []
    candidate = _precedent_path(signature_id, matched_archetype, matched_ticket_id)
    if not candidate.exists():
        return errors

    try:
        data = json.loads(candidate.read_text())
    except (json.JSONDecodeError, OSError):
        return errors  # shape errors reported by validate_precedent_content

    anchors_at_time = data.get("anchors_at_time") or []
    if not isinstance(anchors_at_time, list):
        return errors

    temporal_anchors = [
        entry for entry in anchors_at_time
        if isinstance(entry, dict) and entry.get("temporal") is True and entry.get("anchor")
    ]
    if not temporal_anchors:
        return errors

    consulted_by_name: dict = {}
    for entry in anchors_consulted or []:
        if isinstance(entry, dict) and entry.get("anchor"):
            consulted_by_name[entry["anchor"]] = entry

    for tanchor in temporal_anchors:
        name = tanchor["anchor"]
        current = consulted_by_name.get(name)
        if current is None:
            errors.append(
                f"precedent '{matched_ticket_id}' cites temporal anchor "
                f"'{name}' (time-bounded confirmation at ticket close) but "
                f"this investigation did not re-consult it; temporal "
                f"confirmations do not transfer forward in time"
            )
            continue
        result = current.get("result", "")
        if result != "confirmed":
            errors.append(
                f"precedent '{matched_ticket_id}' cites temporal anchor "
                f"'{name}' as confirmed at ticket close, but this "
                f"investigation's re-confirmation returned '{result}'; "
                f"temporal grounding is stale"
            )

    return errors


def check_precedent_exists(
    matched_archetype: str,
    matched_ticket_id: str,
    signature_id: str,
) -> bool:
    """Check that the referenced precedent snapshot file actually exists."""
    if not matched_archetype or not matched_ticket_id:
        return False
    return _precedent_path(
        signature_id, matched_archetype, matched_ticket_id
    ).exists()


# ---------------------------------------------------------------------------
# Archetype + trust anchor validation (new model)
# ---------------------------------------------------------------------------

def load_archetype_frontmatter(matched_archetype: str, signature_id: str) -> dict | None:
    """Load and parse the YAML frontmatter of an archetype's trust-anchors.md.

    Archetypes live at
    `knowledge/signatures/{sig}/archetypes/{matched_archetype}/trust-anchors.md`.
    Frontmatter (archetype, signature_id, required_anchors) is duplicated
    in `story.md`; either file is a valid source. We read trust-anchors.md
    because it's the file that declares the grounding contract this
    validator enforces. Returns None if the file does not exist.
    """
    archetype_file = (
        SOC_AGENT_ROOT
        / "knowledge"
        / "signatures"
        / signature_id
        / "archetypes"
        / matched_archetype
        / "trust-anchors.md"
    )
    if not archetype_file.exists():
        return None
    return parse_yaml_frontmatter(archetype_file.read_text())


def check_archetype_exists(matched_archetype: str, signature_id: str) -> bool:
    """Check that the referenced archetype directory + trust-anchors.md exists and parses."""
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


def is_screen_resolved(run_dir: Path) -> bool:
    """Check if this investigation was resolved via the SCREEN phase.

    Reads state.json and checks if SCREEN is in history but PREDICT
    is not (i.e., the investigation didn't enter the full loop).
    """
    state_path = run_dir / "state.json"
    if not state_path.exists():
        return False
    try:
        state = json.loads(state_path.read_text())
        history = state.get("history", [])
        return "SCREEN" in history and "PREDICT" not in history
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

    if screen and not playbook_has_screen_section(report.signature_id):
        errors.append(
            f"report is screen-resolved but playbook for "
            f"'{report.signature_id}' has no ## Screen section"
        )

    # Check: resolved requires
    #   (1) matched_archetype pointing at a real archetype
    #   (2) grounding — at least one of:
    #         (a) archetype.required_anchors all confirmed, OR
    #         (b) matched_ticket_id pointing at a real precedent snapshot
    # When (a) is not available (archetype declares no required_anchors),
    # (b) is mandatory. When (a) is available, (b) is optional extra
    # confidence.
    if report.status == "resolved":
        if not report.matched_archetype:
            errors.append(
                "status=resolved requires matched_archetype"
            )
        else:
            fm = load_archetype_frontmatter(
                report.matched_archetype, report.signature_id
            )
            if fm is None:
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

                # Grounding enforcement: if the archetype declares no
                # required_anchors, the resolution must be grounded by a
                # matched_ticket_id instead.
                required = fm.get("required_anchors") or []
                if not required and not report.matched_ticket_id:
                    errors.append(
                        f"archetype '{report.matched_archetype}' declares no "
                        f"required_anchors, so matched_ticket_id is required "
                        f"as the grounding citation for status=resolved"
                    )

            if report.matched_ticket_id:
                if not check_precedent_exists(
                    report.matched_archetype,
                    report.matched_ticket_id,
                    report.signature_id,
                ):
                    errors.append(
                        f"matched_ticket_id '{report.matched_ticket_id}' not found "
                        f"under knowledge/signatures/{report.signature_id}/"
                        f"archetypes/{report.matched_archetype}/"
                    )
                else:
                    content_errors = validate_precedent_content(
                        report.matched_archetype,
                        report.matched_ticket_id,
                        report.signature_id,
                    )
                    errors.extend(content_errors)

                    temporal_errors = validate_temporal_anchors_reconfirmed(
                        report.matched_archetype,
                        report.matched_ticket_id,
                        report.signature_id,
                        report.trust_anchors_consulted,
                    )
                    errors.extend(temporal_errors)

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


def load_precedent(
    signature_id: str,
    matched_archetype: str,
    matched_ticket_id: str,
) -> dict | None:
    """Load the matched precedent snapshot JSON from inside the archetype dir."""
    if not matched_archetype or not matched_ticket_id:
        return None
    candidate = _precedent_path(
        signature_id, matched_archetype, matched_ticket_id
    )
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
    precedent: str | None,
    salt: str,
    status: str = "resolved",
) -> str:
    """Assemble the slimmed Tier 2 judge prompt.

    The slimmed judge (post-REPORT refactor) only validates the
    report↔log delta plus precedent transfer. Archetype / shape /
    completeness / anchor-leg checks moved to the pre-REPORT judges.

    Two modes:
    - `full`: status=resolved. INTERNAL_CONSISTENCY + EVIDENCE_SUFFICIENCY
       are hard gates; PRECEDENT_TRANSFER fires when matched_ticket_id is
       set, otherwise N/A.
    - `escalation`: status=escalated. INTERNAL_CONSISTENCY +
       EVIDENCE_SUFFICIENCY are hard gates; PRECEDENT_TRANSFER is N/A.
    """
    template = JUDGE_PROMPT_PATH.read_text()

    # Wrap untrusted content with salted delimiters. The report is
    # agent-generated (not external), so it is NOT salted.
    safe_alert = wrap_untrusted(alert_data, "alert-data", salt)
    safe_log = wrap_untrusted(investigation_log, "investigation-log", salt)

    prompt = template.replace("{alert_data}", safe_alert)
    prompt = prompt.replace("{investigation_log}", safe_log)
    prompt = prompt.replace("{report}", report)

    if precedent is not None:
        safe_precedent = wrap_untrusted(precedent, "precedent", salt)
        prompt = prompt.replace("{precedent}", safe_precedent)
    else:
        prompt = prompt.replace(
            "{precedent}",
            "[No matched ticket — PRECEDENT_TRANSFER is N/A]",
        )

    mode = "full" if status == "resolved" else "escalation"
    prompt = prompt.replace("{judge_mode}", mode)

    return prompt


def run_tier2(run_dir: Path, fields: dict) -> tuple[bool, str]:
    """Run Tier 2 semantic judge. Returns (passed, message)."""
    status = fields.get("status", "")
    matched_archetype = fields.get("matched_archetype")
    matched_ticket_id = fields.get("matched_ticket_id")
    signature_id = fields.get("signature_id", "")

    # Load precedent if the report cites a specific ticket under an archetype.
    # matched_ticket_id is optional — many resolved reports match an
    # archetype without a ticket citation, and escalated reports never have one.
    precedent_data = None
    if matched_archetype and matched_ticket_id:
        precedent_data = load_precedent(
            signature_id, matched_archetype, matched_ticket_id
        )
        if precedent_data is None:
            return False, (
                f"matched_ticket_id '{matched_ticket_id}' under archetype "
                f"'{matched_archetype}' could not be loaded"
            )

    # Load artifacts. The slimmed Tier 2 judge no longer reads archetype
    # descriptions — shape/completeness moved to the pre-REPORT judges.
    # Tier 2's only archetype-adjacent check is PRECEDENT_TRANSFER, which
    # uses the precedent snapshot directly.
    salt = get_run_salt(run_dir)
    alert_text = read_file_safe(run_dir / "alert.json", "alert data")
    investigation_text = read_file_safe(run_dir / "investigation.md", "investigation log")
    report_text = (run_dir / "report.md").read_text()
    precedent_text = json.dumps(precedent_data, indent=2) if precedent_data else None

    # Assemble and invoke
    prompt = assemble_prompt(
        alert_text,
        investigation_text,
        report_text,
        precedent_text,
        salt,
        status=status,
    )
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
