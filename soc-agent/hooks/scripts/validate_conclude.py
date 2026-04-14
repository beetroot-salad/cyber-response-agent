#!/usr/bin/env python3
"""PreToolUse hook: CONCLUDE transition verification gate.

Fires on Write/Edit targeting `investigation.md` (narrowed by `if`
filters in plugin.json). Computes the *proposed* post-write text from
the tool input (not the file on disk, which hasn't been updated yet),
checks for a `## CONCLUDE` header, and enforces:

1. ticket-context subagent was dispatched during CONTEXTUALIZE.
   Silent backstop — not surfaced in SKILL.md §CONCLUDE because by
   CONCLUDE time the damage is already done. Exists only so a broken
   preload surfaces somewhere.
2. `conclusion_checks.json` exists in the run directory and covers the
   expected question set for its declared status. Each citation is a
   `{lines: "A-B", contains: "token"}` pair — the hook parses the
   range, slices those lines from the proposed investigation.md text,
   and checks that `contains` is a verbatim substring of that slice.
   Prevents fabrication; cheaper and more paraphrase-tolerant than
   matching a full sentence against the whole file. Expected question
   IDs come from `skills/investigate/conclusion_checks.md` so the two
   stay in sync.

   The self-check (gate 2) only fires when the investigation is
   *struggling* or the signature's scaffolding is thin. Concretely:
   - `loops >= 4` (forced iteration signals the agent is on weak
     ground, regardless of signature maturity), OR
   - `archetype_count < 2` for the signature (a playbook with one or
     zero archetypes gives the agent no discriminative story to fit
     evidence against, so the forced articulation earns its keep).

   Screen-resolved investigations are exempt regardless — their
   safety comes from SCREEN pattern match + precedent +
   validate_report.py Tier 1/2.

Running as PreToolUse means a rejection blocks the write before
`infer_state.py` advances `state.json`. The agent can then fix the
authoring gap and re-issue the write from the same pre-CONCLUDE phase,
without the state machine confusion a rejected PostToolUse would
cause.

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
    has_conclude_header,
    iter_phase_headers,
    is_screen_resolved,
)
from hooks.scripts.run_context import extract_run_dir_from_path

CONCLUSION_CHECKS_PROMPT = (
    SOC_AGENT_ROOT / "skills" / "investigate" / "conclusion_checks.md"
)

# Thresholds for firing the self-check. Raising either makes the check
# stricter (fires more often); lowering makes it more permissive.
MAX_LOOPS_BEFORE_SELF_CHECK = 4
MIN_ARCHETYPES_FOR_MATURE_SCAFFOLDING = 2

# Question headers in the prompt file: `### \`question_id\``
QUESTION_HEADER_RE = re.compile(r"^### `([a-z_][a-z0-9_]*)`\s*$", re.MULTILINE)

# Per-status question sections in the prompt file.
STATUS_SECTION_RE = re.compile(
    r"^## Questions — status: (\w+)\s*$(.*?)(?=^## Questions — status:|\Z)",
    re.MULTILINE | re.DOTALL,
)


# ---------------------------------------------------------------------------
# Proposed-content resolution
# ---------------------------------------------------------------------------

def resolve_proposed_text(hook_data: dict) -> tuple[Path | None, str | None]:
    """Return (run_dir, proposed_text) for a PreToolUse event targeting
    investigation.md, or (None, None) if the event is unrelated.

    For Write: `tool_input.content` is the full proposed file.
    For Edit:  read the current file and apply `old_string → new_string`
               (respecting `replace_all`).
    """
    tool_name = hook_data.get("tool_name", "")
    tool_input = hook_data.get("tool_input", {})
    file_path = tool_input.get("file_path", "")

    run_dir = extract_run_dir_from_path(file_path)
    if run_dir is None:
        return None, None

    if tool_name == "Write":
        content = tool_input.get("content", "")
        return run_dir, content if isinstance(content, str) else ""

    if tool_name == "Edit":
        inv_path = run_dir / "investigation.md"
        if not inv_path.exists():
            return None, None
        try:
            current = inv_path.read_text()
        except OSError:
            return None, None
        old = tool_input.get("old_string", "")
        new = tool_input.get("new_string", "")
        if not isinstance(old, str) or not isinstance(new, str):
            return None, None
        if tool_input.get("replace_all"):
            proposed = current.replace(old, new)
        else:
            proposed = current.replace(old, new, 1)
        return run_dir, proposed

    return None, None


# ---------------------------------------------------------------------------
# Gate 1: ticket-context dispatched
# ---------------------------------------------------------------------------

def check_ticket_context_spawned(run_dir: Path) -> str | None:
    """Return None on pass, error message on fail.

    The ticket-context subagent is dispatched inline by the main agent
    during CONTEXTUALIZE (see SKILL.md §CONTEXTUALIZE step 3). The
    primary detection path is the audit log scan below, which looks for
    a Task/Agent call matching the ticket-context subagent prompt.

    The `ticket_context.yaml` file check is kept as a legacy/test
    convenience — tests can set it as a fast "ticket-context ran" marker
    without building an audit log. Production flow no longer writes the
    file (no preload script).
    """
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
        "ticket-context subagent was not dispatched during CONTEXTUALIZE. "
        "The main agent is expected to spawn it inline via Agent() as "
        "described in SKILL.md §CONTEXTUALIZE step 3; the audit log "
        "has no matching Task/Agent call. Dispatch the subagent using "
        "skills/investigate/ticket-context.md before re-issuing this "
        "CONCLUDE write. Next action: stay in CONCLUDE, run the subagent, "
        "then retry the write."
    )


# ---------------------------------------------------------------------------
# Self-check complexity gate
# ---------------------------------------------------------------------------

def count_hypothesize_loops(text: str) -> int:
    """Number of `## HYPOTHESIZE` phase headers in the proposed text. This
    matches `count_loops` over state.history but works against the proposed
    investigation text directly, which the hook already has in hand."""
    return sum(1 for p in iter_phase_headers(text) if p == "HYPOTHESIZE")


def signature_archetype_count(signature_id: str) -> int:
    """Number of archetype directories under the signature's knowledge tree.

    An archetype is a subdirectory of `knowledge/signatures/{sig}/archetypes/`
    that contains a README.md. Missing tree → 0.
    """
    if not signature_id:
        return 0
    arch_dir = (
        SOC_AGENT_ROOT
        / "knowledge"
        / "signatures"
        / signature_id
        / "archetypes"
    )
    if not arch_dir.exists():
        return 0
    count = 0
    for d in arch_dir.iterdir():
        if d.is_dir() and (d / "README.md").exists():
            count += 1
    return count


def should_run_self_check(run_dir: Path, proposed_text: str) -> bool:
    """TEMPORARILY always True — we want empirical data on the self-check's
    value and cost on every investigation, not just struggling ones. The
    complexity-gated version is preserved below as reference for when we
    turn it back on.

    Previous behavior (loops < MAX AND archetype_count >= MIN → skip) is
    retained in the `_complexity_gate_disabled_fire_always` helper for
    reference and future re-enable.
    """
    return True


def _complexity_gate_disabled_fire_always(run_dir: Path, proposed_text: str) -> bool:
    """Reference implementation of the complexity gate — not wired up.

    Fire the self-check when the investigation is struggling (many
    hypothesis loops) or the signature's scaffolding is thin (few
    archetypes). Kept for when we want to re-enable the skip path.
    """
    loops = count_hypothesize_loops(proposed_text)
    if loops >= MAX_LOOPS_BEFORE_SELF_CHECK:
        return True
    meta_path = run_dir / "meta.json"
    signature_id = ""
    if meta_path.exists():
        try:
            signature_id = json.loads(meta_path.read_text()).get("signature_id", "")
        except (json.JSONDecodeError, OSError):
            pass
    archetype_count = signature_archetype_count(signature_id)
    if archetype_count < MIN_ARCHETYPES_FOR_MATURE_SCAFFOLDING:
        return True
    return False


# ---------------------------------------------------------------------------
# Gates 2 + 3: conclusion_checks.json
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


_NEXT_ACTION_AUTHORING = (
    "Next action: stay in CONCLUDE, fix conclusion_checks.json, retry the write."
)


def parse_line_range(value: str) -> tuple[int, int] | None:
    """Parse a `lines` field from a citation: either `"N"` (single line)
    or `"A-B"` (inclusive range, 1-indexed). Returns (start, end) or None
    on any parse error (non-integer, reversed range, non-positive)."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if "-" in s:
        parts = s.split("-", 1)
        try:
            start = int(parts[0].strip())
            end = int(parts[1].strip())
        except ValueError:
            return None
    else:
        try:
            start = end = int(s)
        except ValueError:
            return None
    if start < 1 or end < start:
        return None
    return (start, end)


def extract_line_slice(text: str, start: int, end: int) -> str | None:
    """Return lines [start..end] of `text` joined with newlines (1-indexed,
    inclusive). Returns None if the range runs off the end of the text."""
    lines = text.split("\n")
    if end > len(lines):
        return None
    return "\n".join(lines[start - 1:end])


def check_conclusion_file(run_dir: Path, investigation_text: str) -> str | None:
    """Validate conclusion_checks.json shape, question set, and citations.

    Every rejection message ends with an explicit next-action line so the
    agent knows where to go. All failures here are authoring issues — the
    agent stays in the current phase and re-issues the write after fixing
    the JSON. No phase change is needed.
    """
    checks_path = run_dir / "conclusion_checks.json"
    if not checks_path.exists():
        return (
            "conclusion_checks.json not found in run directory. Read "
            "skills/investigate/conclusion_checks.md and write your answers "
            "to conclusion_checks.json *before* the ## CONCLUDE write. "
            "Next action: stay in CONCLUDE, author the file, retry the write."
        )

    try:
        data = json.loads(checks_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return (
            f"conclusion_checks.json is not valid JSON: {e}. "
            f"{_NEXT_ACTION_AUTHORING}"
        )

    if not isinstance(data, dict):
        return (
            "conclusion_checks.json must be a JSON object with 'status' and "
            f"'checks' fields. {_NEXT_ACTION_AUTHORING}"
        )

    status = data.get("status")
    if status not in ("resolved", "escalated"):
        return (
            f"conclusion_checks.json 'status' must be 'resolved' or "
            f"'escalated', got {status!r}. {_NEXT_ACTION_AUTHORING}"
        )

    checks = data.get("checks")
    if not isinstance(checks, list):
        return (
            f"conclusion_checks.json 'checks' must be a list. "
            f"{_NEXT_ACTION_AUTHORING}"
        )

    expected = load_expected_questions()
    if status not in expected:
        return (
            f"conclusion_checks.md does not define a question set for "
            f"status '{status}'. This is a skill-configuration bug, not an "
            f"agent issue — escalate to the human operator."
        )
    expected_ids = set(expected[status])

    actual_ids: list[str] = []
    for i, entry in enumerate(checks):
        if not isinstance(entry, dict):
            return (
                f"conclusion_checks.json checks[{i}] must be an object. "
                f"{_NEXT_ACTION_AUTHORING}"
            )
        qid = entry.get("question_id")
        if not qid:
            return (
                f"conclusion_checks.json checks[{i}] is missing 'question_id'. "
                f"{_NEXT_ACTION_AUTHORING}"
            )
        actual_ids.append(qid)

    actual_set = set(actual_ids)
    missing = expected_ids - actual_set
    extra = actual_set - expected_ids
    if missing:
        return (
            f"conclusion_checks.json is missing required question(s) for "
            f"status={status}: {sorted(missing)}. {_NEXT_ACTION_AUTHORING}"
        )
    if extra:
        return (
            f"conclusion_checks.json contains unexpected question(s): "
            f"{sorted(extra)}. Valid for status={status}: {sorted(expected_ids)}. "
            f"{_NEXT_ACTION_AUTHORING}"
        )

    # Gate 3: citation resolution.
    # Each citation is `{"lines": "N" or "A-B", "contains": "verbatim token"}`.
    # The hook checks (a) the range parses and is within file bounds,
    # (b) `contains` is a plain substring of the sliced line range.
    max_line = investigation_text.count("\n") + 1
    for entry in checks:
        qid = entry["question_id"]
        answer = entry.get("answer", "")
        if not isinstance(answer, str) or not answer.strip():
            return (
                f"conclusion_checks.json question '{qid}' has empty or "
                f"missing 'answer'. {_NEXT_ACTION_AUTHORING}"
            )
        citations = entry.get("citations")
        if not isinstance(citations, list) or not citations:
            return (
                f"conclusion_checks.json question '{qid}' must have a "
                f"non-empty 'citations' list. {_NEXT_ACTION_AUTHORING}"
            )
        for j, citation in enumerate(citations):
            if not isinstance(citation, dict):
                return (
                    f"conclusion_checks.json question '{qid}' citation[{j}] "
                    f"must be an object with 'lines' and 'contains' fields. "
                    f"{_NEXT_ACTION_AUTHORING}"
                )
            lines_value = citation.get("lines")
            rng = parse_line_range(lines_value) if isinstance(lines_value, str) else None
            if rng is None:
                return (
                    f"conclusion_checks.json question '{qid}' citation[{j}] "
                    f"'lines' must be a string like \"64\" or \"62-68\" "
                    f"(1-indexed, start <= end). Got {lines_value!r}. "
                    f"{_NEXT_ACTION_AUTHORING}"
                )
            start, end = rng
            slice_text = extract_line_slice(investigation_text, start, end)
            if slice_text is None:
                return (
                    f"conclusion_checks.json question '{qid}' citation[{j}] "
                    f"'lines' range {start}-{end} is out of bounds "
                    f"(investigation.md has {max_line} lines). "
                    f"{_NEXT_ACTION_AUTHORING}"
                )
            contains = citation.get("contains")
            if not isinstance(contains, str) or not contains.strip():
                return (
                    f"conclusion_checks.json question '{qid}' citation[{j}] "
                    f"'contains' must be a non-empty string. "
                    f"{_NEXT_ACTION_AUTHORING}"
                )
            if contains not in slice_text:
                preview = contains[:80] + ("..." if len(contains) > 80 else "")
                return (
                    f"conclusion_checks.json question '{qid}' citation[{j}] "
                    f"'contains' text not found within lines {start}-{end}: "
                    f"{preview!r}. The token must be a VERBATIM substring of "
                    f"the cited line range — copy-paste directly from "
                    f"investigation.md, including backticks and punctuation. "
                    f"{_NEXT_ACTION_AUTHORING}"
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

    run_dir, proposed_text = resolve_proposed_text(hook_data)
    if run_dir is None or proposed_text is None:
        sys.exit(0)

    if not has_conclude_header(proposed_text):
        sys.exit(0)

    errors: list[str] = []

    err = check_ticket_context_spawned(run_dir)
    if err:
        errors.append(err)

    if not is_screen_resolved(proposed_text):
        # Fire the self-check when either (a) complexity says we need it,
        # or (b) the agent authored conclusion_checks.json defensively — in
        # the second case we validate what they wrote even though we would
        # have exempted a missing file.
        run_gate = should_run_self_check(run_dir, proposed_text)
        file_present = (run_dir / "conclusion_checks.json").exists()
        if run_gate or file_present:
            err = check_conclusion_file(run_dir, proposed_text)
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
