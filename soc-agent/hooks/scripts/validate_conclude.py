#!/usr/bin/env python3
"""PreToolUse hook: CONCLUDE transition verification gate.

Fires on Write/Edit targeting `investigation.md` (narrowed by `if`
filters in plugin.json). Computes the *proposed* post-write text from
the tool input (not the file on disk, which hasn't been updated yet).

Fires only when the proposed text contains both a `## CONCLUDE` header
AND a parseable `conclude:` YAML block — the second of the two writes
the agent performs at the conclusion boundary, by which point
`matched_archetype` is declared and Judge B has the context it needs.

Two gates run:

1. **ticket-context dispatched.** Silent backstop — verifies the
   ticket-context subagent fired during CONTEXTUALIZE. Not surfaced in
   SKILL.md because by CONCLUDE time the damage is already done; this
   exists only so a broken preload surfaces somewhere.

2. **Two-judge investigation soundness check.** Two Haiku judges run
   in parallel via the claude CLI:
     - Judge A (log integrity): LEGITIMACY_CHECK,
       PLUS_PLUS_FALSIFICATION, DANGLING_EVIDENCE,
       ESCALATION_RATIONALE.
     - Judge B (archetype/grounding): SHAPE_MATCH, COMPLETENESS,
       GROUNDING_MATCH (anchor leg only).
   Verdicts are ANDed deterministically — any FLAG blocks the write.

SCREEN-resolved investigations are exempt from gate 2 (their safety
comes from SCREEN pattern match + precedent + validate_report.py).

Running as PreToolUse means a rejection blocks the write before
`infer_state.py` advances `state.json`. The agent fixes the issue and
re-issues the write from the same phase, no state-machine confusion.

Exit codes:
    0 - Passed (or not a CONCLUDE-finalising write)
    2 - Gate failed (message fed back to agent, blocks the write)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.investigation_parse import (
    has_conclude_header,
    is_screen_resolved,
    resolve_proposed_text,
)
from hooks.scripts.invlang_validate import _merge_blocks
from hooks.scripts.invlang_walkers import (
    collect_hypothesis_ids,
    compute_final_status,
)
from hooks.scripts.judge_runner import (
    get_run_salt,
    invoke_judges_parallel,
    parse_verdict,
    wrap_untrusted,
)
from hooks.scripts.run_context import extract_run_dir_from_path

JUDGE_A_PROMPT_PATH = Path(__file__).resolve().parent / "conclude_judge_A_prompt.md"
JUDGE_B_PROMPT_PATH = Path(__file__).resolve().parent / "conclude_judge_B_prompt.md"

YAML_BLOCK_RE = re.compile(r"```yaml[ \t]*\r?\n(.*?)\r?\n```", re.DOTALL)
VERDICT_LINE_RE = re.compile(
    r"\*\*Verdict:\*\*\s*(resolved|escalated)\b", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Gate 1: ticket-context dispatched
# ---------------------------------------------------------------------------

def check_ticket_context_spawned(run_dir: Path) -> str | None:
    """Return None on pass, error message on fail.

    Primary signal is the audit log scan for a Task/Agent call mentioning
    ticket-context. The `ticket_context.yaml` file path is a legacy/test
    convenience marker.
    """
    if (run_dir / "ticket_context.yaml").exists():
        return None

    audit_path = run_dir.parent / "tool_audit.jsonl"
    if not audit_path.exists():
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
        "described in SKILL.md §CONTEXTUALIZE step 3; the audit log has no "
        "matching Task/Agent call. Dispatch the subagent using "
        "Agent(subagent_type=\"ticket-context\") before re-issuing this "
        "CONCLUDE write. Next action: stay in CONCLUDE, run the subagent, "
        "then retry the write."
    )


# ---------------------------------------------------------------------------
# Gate 2 fire condition + context extraction
# ---------------------------------------------------------------------------

def extract_conclude_yaml(text: str) -> dict | None:
    """Find the first ```yaml fenced block whose top-level key is `conclude`
    and return the parsed dict. Returns None if no such block is found or
    parsing fails."""
    for raw in YAML_BLOCK_RE.findall(text):
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict) and "conclude" in doc:
            inner = doc["conclude"]
            if isinstance(inner, dict):
                return inner
    return None


def extract_status(text: str) -> str | None:
    """Return 'resolved' or 'escalated' from the `**Verdict:**` line in
    the CONCLUDE section, or None if not present / unparseable."""
    m = VERDICT_LINE_RE.search(text)
    if not m:
        return None
    return m.group(1).lower()


def load_archetype_description(signature_id: str, archetype: str) -> str | None:
    """Load an archetype's full description for Judge B.

    Returns story.md + trust-anchors.md concatenated — story carries the
    observable shape (needed for SHAPE_MATCH), trust-anchors carries the
    grounding contract + precedent pointer (needed for COMPLETENESS /
    GROUNDING_MATCH).
    """
    if not signature_id or not archetype:
        return None
    base = (
        SOC_AGENT_ROOT
        / "knowledge"
        / "signatures"
        / signature_id
        / "archetypes"
        / archetype
    )
    parts: list[str] = []
    for name in ("story.md", "trust-anchors.md"):
        p = base / name
        if p.exists():
            try:
                parts.append(p.read_text())
            except OSError:
                continue
    if not parts:
        return None
    return "\n\n".join(parts)


def load_sibling_archetypes(signature_id: str, matched: str | None) -> str:
    """Return a concatenated text block of sibling archetype descriptions
    (story + trust-anchors per sibling, excluding the matched one). Empty
    string if none / signature unknown."""
    if not signature_id:
        return ""
    arch_dir = (
        SOC_AGENT_ROOT
        / "knowledge"
        / "signatures"
        / signature_id
        / "archetypes"
    )
    if not arch_dir.exists():
        return ""
    parts: list[str] = []
    for d in sorted(arch_dir.iterdir()):
        if not d.is_dir():
            continue
        if d.name == matched:
            continue
        chunks: list[str] = []
        for name in ("story.md", "trust-anchors.md"):
            p = d / name
            if not p.exists():
                continue
            try:
                chunks.append(p.read_text())
            except OSError:
                continue
        if not chunks:
            continue
        parts.append(f"# Sibling archetype: {d.name}\n\n" + "\n\n".join(chunks))
    return "\n\n---\n\n".join(parts)


def get_signature_id(run_dir: Path) -> str:
    meta_path = run_dir / "meta.json"
    if not meta_path.exists():
        return ""
    try:
        return json.loads(meta_path.read_text()).get("signature_id", "")
    except (json.JSONDecodeError, OSError):
        return ""


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------

def assemble_judge_a_prompt(
    *,
    alert_text: str,
    investigation_text: str,
    salt: str,
    status: str,
) -> str:
    template = JUDGE_A_PROMPT_PATH.read_text()
    safe_alert = wrap_untrusted(alert_text, "alert-data", salt)
    safe_log = wrap_untrusted(investigation_text, "investigation-log", salt)
    mode = "full" if status == "resolved" else "escalation"
    prompt = template.replace("{alert_data}", safe_alert)
    prompt = prompt.replace("{investigation_log}", safe_log)
    prompt = prompt.replace("{judge_mode}", mode)
    return prompt


def assemble_judge_b_prompt(
    *,
    alert_text: str,
    investigation_text: str,
    matched_archetype_text: str | None,
    sibling_archetypes_text: str,
    salt: str,
    status: str,
) -> str:
    template = JUDGE_B_PROMPT_PATH.read_text()
    safe_alert = wrap_untrusted(alert_text, "alert-data", salt)
    safe_log = wrap_untrusted(investigation_text, "investigation-log", salt)
    if matched_archetype_text is not None:
        safe_arch = wrap_untrusted(matched_archetype_text, "archetype", salt)
    else:
        safe_arch = "[No matched_archetype declared in the conclude: block]"
    if sibling_archetypes_text:
        safe_siblings = wrap_untrusted(
            sibling_archetypes_text, "sibling-archetypes", salt
        )
    else:
        safe_siblings = "[No sibling archetypes under this signature]"
    mode = "full" if status == "resolved" else "escalation"
    prompt = template.replace("{alert_data}", safe_alert)
    prompt = prompt.replace("{investigation_log}", safe_log)
    prompt = prompt.replace("{matched_archetype}", safe_arch)
    prompt = prompt.replace("{sibling_archetypes}", safe_siblings)
    prompt = prompt.replace("{judge_mode}", mode)
    return prompt


# ---------------------------------------------------------------------------
# Gate 2: parallel judge dispatch
# ---------------------------------------------------------------------------

def run_judges(run_dir: Path, proposed_text: str) -> str | None:
    """Run Judge A and Judge B in parallel. Return None on pass, an
    error message describing the FLAGs on fail."""
    status = extract_status(proposed_text)
    if status is None:
        return (
            "CONCLUDE write is missing a parseable `**Verdict:** resolved|escalated` "
            "line in the ## CONCLUDE section. Add it per the SKILL.md §CONCLUDE "
            "template and retry. Next action: stay in CONCLUDE, fix the verdict "
            "line, retry the write."
        )

    conclude_block = extract_conclude_yaml(proposed_text)
    if conclude_block is None:
        # Pre-YAML write — defer until the conclude: block is added.
        return None

    matched_archetype = conclude_block.get("matched_archetype")
    if isinstance(matched_archetype, str) and not matched_archetype.strip():
        matched_archetype = None
    if matched_archetype is not None and not isinstance(matched_archetype, str):
        matched_archetype = None

    signature_id = get_signature_id(run_dir)
    matched_readme = (
        load_archetype_description(signature_id, matched_archetype)
        if matched_archetype
        else None
    )
    sibling_text = load_sibling_archetypes(signature_id, matched_archetype)

    alert_text = ""
    alert_path = run_dir / "alert.json"
    if alert_path.exists():
        try:
            alert_text = alert_path.read_text()
        except OSError:
            alert_text = ""

    salt = get_run_salt(run_dir)

    prompt_a = assemble_judge_a_prompt(
        alert_text=alert_text,
        investigation_text=proposed_text,
        salt=salt,
        status=status,
    )
    prompt_b = assemble_judge_b_prompt(
        alert_text=alert_text,
        investigation_text=proposed_text,
        matched_archetype_text=matched_readme,
        sibling_archetypes_text=sibling_text,
        salt=salt,
        status=status,
    )

    results = invoke_judges_parallel([("A", prompt_a), ("B", prompt_b)])

    flags: list[str] = []
    for label, output, returncode in results:
        if returncode != 0:
            flags.append(f"Judge {label} CLI error (rc={returncode}): {output}")
            continue
        verdict, reason = parse_verdict(output)
        if verdict != "PASS":
            flags.append(
                f"Judge {label} flagged investigation: {reason}\n\n"
                f"Full Judge {label} output:\n{output}"
            )

    if flags:
        return "\n\n".join(flags) + (
            "\n\nNext action: stay in CONCLUDE, address the FLAG(s) above by "
            "either revising the investigation log (additional ANALYZE, a new "
            "lead, or downgrading a hypothesis grade) or escalating instead of "
            "resolving, then retry the write."
        )
    return None


# ---------------------------------------------------------------------------
# Gate 4: frontier closure
# ---------------------------------------------------------------------------

# Only resolving terminations require every hypothesis to be terminal.
# Escalations (severity-ceiling, exhaustion-escalation) exist precisely because
# live hypotheses can't be tested to completion with available tools — active
# hypotheses in the handoff are the point, not a bug.
_RESOLVING_TERMINATION_CATEGORIES = {"trust-root", "adversarial-refuted"}


def check_frontier_closure(proposed_text: str) -> str | None:
    """Every declared hypothesis must have a terminal status at CONCLUDE —
    but only for resolving investigations.

    A hypothesis is terminal when it's `confirmed` (last resolution `++`
    or explicit `status: confirmed`), `refuted` (last resolution `--` or
    explicit `status: refuted`), or `shelved` (appears in any lead's
    `shelved` list).

    For `termination.category ∈ {trust-root, adversarial-refuted}`, any
    hypothesis still `active` blocks the write — the investigation
    claims closure but hasn't closed its frontier. For `severity-ceiling`
    and `exhaustion-escalation`, active hypotheses are legitimate
    (that's the content of the escalation), so the check passes
    unconditionally. A missing `conclude.termination.category` also
    passes — structural validation of that field is the job of the
    report frontmatter check.

    Returns None on pass; a single error message (possibly aggregating
    multiple active hypotheses) on fail.
    """
    blocks: list = []
    for match in YAML_BLOCK_RE.finditer(proposed_text):
        try:
            doc = yaml.safe_load(match.group(1))
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict):
            blocks.append(doc)
    if not blocks:
        return None
    merged = _merge_blocks(blocks)

    # Read termination category. Only resolving categories gate on closure.
    conclude_block = merged.get("conclude") or {}
    termination = conclude_block.get("termination") or {}
    category = termination.get("category") if isinstance(termination, dict) else None
    if category not in _RESOLVING_TERMINATION_CATEGORIES:
        return None

    active: list[str] = []
    for hid in collect_hypothesis_ids(merged):
        if compute_final_status(merged, hid) == "active":
            active.append(hid)

    if not active:
        return None

    return (
        f"frontier-closure failed: hypothesis id(s) {sorted(active)} are "
        f"still 'active' at CONCLUDE but termination.category is {category!r} "
        f"(a resolving category). Every declared hypothesis must end in "
        f"'confirmed' (++), 'refuted' (--), or 'shelved' (via a lead's shelved "
        f"list) before you can claim {category!r}. If a hypothesis can't be "
        f"tested with available tools, either shelve it explicitly or switch "
        f"termination.category to 'severity-ceiling' (and add ceiling_test) "
        f"or 'exhaustion-escalation'. "
        f"Next action: author the missing resolution/shelving in a new "
        f"gather block, or change the termination category, then retry the "
        f"CONCLUDE write."
    )


ESCALATION_CATEGORIES = {"exhaustion-escalation", "severity-ceiling"}


def check_termination_vs_verdict(proposed_text: str) -> str | None:
    """Block CONCLUDE writes where termination.category contradicts the
    frontmatter's verdict / matched_archetype.

    The ANALYZE subagent picks termination.category as its routing
    decision. An escalation category (exhaustion-escalation,
    severity-ceiling) means the loop cannot produce a resolved
    disposition. When the main agent then writes `**Verdict:** resolved`
    or, for exhaustion-escalation, names a non-null matched_archetype,
    it is contradicting its own routing — the exact self-contradiction
    observed in run #34 where ANALYZE loop 2 said "no matching
    archetype, exhaustion-escalation" but CONCLUDE wrote
    `matched_archetype: monitoring-probe / resolved`.

    Rules enforced:
      - termination.category ∈ {exhaustion-escalation, severity-ceiling}
        ⇒ Verdict must be `escalated`, not `resolved`.
      - termination.category == exhaustion-escalation
        ⇒ matched_archetype must be null (no archetype fits, by
        definition of the category).

    Returns None on pass, an error message on fail.
    """
    conclude_block = extract_conclude_yaml(proposed_text)
    if conclude_block is None:
        return None

    termination = conclude_block.get("termination") or {}
    if not isinstance(termination, dict):
        return None
    category = termination.get("category")
    if category not in ESCALATION_CATEGORIES:
        return None

    verdict = extract_status(proposed_text)
    matched_archetype = conclude_block.get("matched_archetype")

    errors: list[str] = []
    if verdict == "resolved":
        errors.append(
            f"`**Verdict:** resolved` contradicts "
            f"`termination.category: {category}` — escalation categories "
            f"cannot produce a resolved disposition. Change Verdict to "
            f"`escalated` or change termination.category to a resolving "
            f"kind (trust-root, adversarial-refuted) only if the evidence "
            f"actually supports resolution."
        )
    if category == "exhaustion-escalation" and matched_archetype not in (None, "null", ""):
        errors.append(
            f"`matched_archetype: {matched_archetype!r}` contradicts "
            f"`termination.category: exhaustion-escalation` — by definition "
            f"this category means no archetype fits the evidence. Set "
            f"matched_archetype to null, or change termination.category if "
            f"an archetype actually matches the observed shape."
        )

    if not errors:
        return None
    return (
        "termination-vs-verdict contradiction: "
        + " | ".join(errors)
        + " Next action: reconcile the CONCLUDE frontmatter with the "
        "ANALYZE routing, then retry the write."
    )


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
        err = check_termination_vs_verdict(proposed_text)
        if err:
            errors.append(err)

        err = run_judges(run_dir, proposed_text)
        if err:
            errors.append(err)

        err = check_frontier_closure(proposed_text)
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
