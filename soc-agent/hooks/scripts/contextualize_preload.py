#!/usr/bin/env python3
"""UserPromptSubmit hook: preload ticket-context and archetype-scan.

Fires on every UserPromptSubmit. For non-investigation prompts, exits
immediately with no output (~1ms). For investigation prompts (detected by
"Run directory:" in the expanded skill template), spawns two claude
subprocesses in parallel and returns trimmed results via additionalContext.

Full outputs are saved to {run_dir}/ticket_context.yaml and
{run_dir}/archetype_scan.yaml for the main agent to read if it needs
detail beyond the trimmed summary.

Exit codes:
    0 — Always. This hook must never block the agent.
"""

import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_DIR = SOC_AGENT_ROOT / "skills" / "investigate"

TICKET_CONTEXT_PROMPT = SKILLS_DIR / "ticket-context.md"
ARCHETYPE_SCAN_PROMPT = SKILLS_DIR / "archetype-scan.md"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SUBPROCESS_TIMEOUT = int(os.environ.get("SOC_AGENT_PRELOAD_TIMEOUT", "120"))

# Patterns to extract from setup_run.py output in the expanded prompt
RUN_DIR_PATTERN = re.compile(r"Run directory:\s*(.+)")
SIGNATURE_PATTERN = re.compile(r"Signature:\s*(\S+)")


# ---------------------------------------------------------------------------
# Frontmatter parsing (reuse the zero-dep parser from hooks/scripts/)
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parent))
from frontmatter import parse_yaml_frontmatter  # noqa: E402


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def extract_run_metadata(prompt: str) -> tuple[str, str] | None:
    """Extract run_dir and signature_id from expanded SKILL.md prompt.

    Returns (run_dir, signature_id) or None if this isn't an investigation.
    """
    run_dir_match = RUN_DIR_PATTERN.search(prompt)
    sig_match = SIGNATURE_PATTERN.search(prompt)
    if not run_dir_match or not sig_match:
        return None
    return run_dir_match.group(1).strip(), sig_match.group(1).strip()


def build_subagent_prompt(template_path: Path, substitutions: dict[str, str]) -> tuple[str, str]:
    """Read a subagent prompt template and substitute variables.

    Returns (prompt_body, model) where model comes from frontmatter.
    Raises ValueError if the template has no model declared in frontmatter.
    """
    text = template_path.read_text()
    fm = parse_yaml_frontmatter(text)
    model = fm.get("model")
    if model is None:
        raise ValueError(f"{template_path.name}: frontmatter missing required 'model' field")

    # Strip frontmatter from the body — everything after the closing ---
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise ValueError(f"{template_path.name}: missing frontmatter delimiters (expected --- ... ---)")
    body = parts[2]

    for key, value in substitutions.items():
        body = body.replace(f"{{{key}}}", value)

    return body.strip(), str(model)


def invoke_subagent(prompt: str, model: str, label: str) -> tuple[str, str | None]:
    """Invoke claude --print with the given prompt and model.

    Returns (output, error). Error is None on success.
    """
    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--model", model, "--output-format", "text"],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
        if result.returncode != 0:
            return "", f"{label} exited with code {result.returncode}: {result.stderr[:200]}"
        return result.stdout.strip(), None
    except FileNotFoundError:
        return "", f"{label}: claude CLI not found"
    except subprocess.TimeoutExpired:
        return "", f"{label}: timed out after {SUBPROCESS_TIMEOUT}s"


def _count_inline_list(value: str) -> int:
    """Count items in an inline YAML list like '["a", "b", "c"]'."""
    value = value.strip()
    if not value.startswith("[") or not value.endswith("]"):
        return 1
    inner = value[1:-1].strip()
    if not inner:
        return 0
    return len(inner.split(","))


# Lines to drop from definite entries (field name at list-item child indent)
_DEFINITE_DROP = {"reasoning"}
# Lines to drop from prior_investigation blocks
_PRIOR_INV_DROP = {"run_id", "summary"}
# Lines to drop from maybe entries
_MAYBE_DROP = {"reasoning"}


def trim_ticket_context(raw: str) -> str:
    """Trim ticket-context output for additionalContext injection.

    Line-level YAML filter — no external dependencies. Operates on the
    predictable indentation structure of the ticket-context subagent output.

    - situation: kept in full
    - definite[].alert_ids: replaced with count
    - definite[].reasoning: dropped (on disk)
    - definite[].prior_investigation.{run_id,summary}: dropped
    - maybe: capped at 3 entries, reasoning dropped
    - fast_resolve: kept in full
    """
    # Extract YAML block from markdown code fence if present
    text = raw
    fence_match = re.search(r"```ya?ml\s*\n(.*?)```", raw, re.DOTALL)
    if fence_match:
        text = fence_match.group(1)

    lines = text.split("\n")
    out: list[str] = []

    # Track which top-level section we're in (situation, definite, maybe, fast_resolve)
    section = ""
    maybe_item_count = 0
    skip_until_indent = -1  # drop all lines at indent > this value

    for line in lines:
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        # Reset skip if we've dedented past the skip threshold
        if skip_until_indent >= 0 and indent <= skip_until_indent:
            skip_until_indent = -1

        if skip_until_indent >= 0:
            continue

        # Detect top-level section transitions (indent 2 under ticket_context)
        if indent <= 2 and stripped and not stripped.startswith("-"):
            key = stripped.split(":")[0].strip()
            if key in ("situation", "definite", "maybe", "fast_resolve"):
                section = key
                maybe_item_count = 0

        # Extract field name from the line, stripping list-item "- " prefix
        content = stripped[2:] if stripped.startswith("- ") else stripped
        field = content.split(":")[0].strip() if ":" in content else ""

        # Section-specific trimming
        if section == "definite":
            # Replace alert_ids with count
            if field == "alert_ids":
                value = content.split(":", 1)[1].strip()
                count = _count_inline_list(value)
                prefix = line[:indent]
                if stripped.startswith("- "):
                    prefix += "- "
                out.append(f"{prefix}count: {count}")
                continue

            # Drop reasoning
            if field in _DEFINITE_DROP:
                skip_until_indent = indent
                continue

            # Inside prior_investigation: drop run_id, summary
            if field in _PRIOR_INV_DROP:
                skip_until_indent = indent
                continue

        elif section == "maybe":
            # Count list items (lines starting with "- " at the list indent)
            if stripped.startswith("- ") and indent >= 4:
                maybe_item_count += 1
                if maybe_item_count > 3:
                    skip_until_indent = indent - 1
                    continue

            # Replace alert_ids with count (same as definite)
            if field == "alert_ids":
                value = content.split(":", 1)[1].strip()
                count = _count_inline_list(value)
                prefix = line[:indent]
                if stripped.startswith("- "):
                    prefix += "- "
                out.append(f"{prefix}count: {count}")
                continue

            if field in _MAYBE_DROP:
                skip_until_indent = indent
                continue

        out.append(line)

    return "\n".join(out)


def format_additional_context(
    tc_output: str | None,
    tc_error: str | None,
    as_output: str | None,
    as_error: str | None,
    run_dir: str,
) -> str:
    """Format the combined output for additionalContext."""
    sections = []

    sections.append("## Ticket Context")
    sections.append("")
    if tc_error:
        sections.append(f"*Preload error: {tc_error}. Fall back to manual dispatch or read {run_dir}/ticket_context.yaml if it exists.*")
    elif tc_output:
        sections.append(tc_output)
    else:
        sections.append("*No output. Fall back to manual dispatch.*")

    sections.append("")
    sections.append("## Archetype Scan")
    sections.append("")
    if as_error:
        sections.append(f"*Preload error: {as_error}. Fall back to manual dispatch or read {run_dir}/archetype_scan.yaml if it exists.*")
    elif as_output:
        sections.append(as_output)
    else:
        sections.append("*No output. Fall back to manual dispatch.*")

    return "\n".join(sections)


def main() -> int:
    try:
        raw = sys.stdin.read()
        hook_data = json.loads(raw)
    except Exception:
        return 0

    prompt = hook_data.get("prompt", "")

    # Fast-path: not an investigation prompt
    metadata = extract_run_metadata(prompt)
    if metadata is None:
        return 0

    run_dir, signature_id = metadata
    run_path = Path(run_dir)
    runs_dir = str(run_path.parent)

    # Verify run dir exists with alert.json
    if not (run_path / "alert.json").exists():
        print(f"contextualize_preload: alert.json not found at {run_dir}", file=sys.stderr)
        return 0

    # Build subagent prompts
    substitutions = {
        "run_dir": run_dir,
        "signature_id": signature_id,
        "runs_dir": runs_dir,
    }

    tc_prompt = tc_model = tc_build_error = None
    as_prompt = as_model = as_build_error = None

    try:
        tc_prompt, tc_model = build_subagent_prompt(TICKET_CONTEXT_PROMPT, substitutions)
    except Exception as e:
        tc_build_error = str(e)
        print(f"contextualize_preload: failed to build ticket-context prompt: {e}", file=sys.stderr)

    try:
        as_prompt, as_model = build_subagent_prompt(ARCHETYPE_SCAN_PROMPT, substitutions)
    except Exception as e:
        as_build_error = str(e)
        print(f"contextualize_preload: failed to build archetype-scan prompt: {e}", file=sys.stderr)

    if tc_prompt is None and as_prompt is None:
        return 0

    # Spawn subagents in parallel
    tc_output, tc_error = None, tc_build_error
    as_output, as_error = None, as_build_error

    futures = {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        if tc_prompt is not None:
            futures["ticket-context"] = executor.submit(
                invoke_subagent, tc_prompt, tc_model, "ticket-context"
            )
        if as_prompt is not None:
            futures["archetype-scan"] = executor.submit(
                invoke_subagent, as_prompt, as_model, "archetype-scan"
            )

        for label, future in futures.items():
            try:
                output, error = future.result(timeout=SUBPROCESS_TIMEOUT + 10)
                if label == "ticket-context":
                    tc_output, tc_error = output, error
                else:
                    as_output, as_error = output, error
            except Exception as e:
                if label == "ticket-context":
                    tc_error = f"future error: {e}"
                else:
                    as_error = f"future error: {e}"

    # Save full outputs to disk
    if tc_output:
        try:
            (run_path / "ticket_context.yaml").write_text(tc_output)
        except OSError as e:
            print(f"contextualize_preload: failed to save ticket_context.yaml: {e}", file=sys.stderr)

    if as_output:
        try:
            (run_path / "archetype_scan.yaml").write_text(as_output)
        except OSError as e:
            print(f"contextualize_preload: failed to save archetype_scan.yaml: {e}", file=sys.stderr)

    # Trim ticket-context for additionalContext
    trimmed_tc = trim_ticket_context(tc_output) if tc_output else None

    # Archetype scan output is already lean — pass through
    trimmed_as = as_output

    # Format and return
    additional_context = format_additional_context(
        trimmed_tc, tc_error, trimmed_as, as_error, run_dir
    )

    output = {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": additional_context,
        }
    }
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"contextualize_preload: unhandled error: {e}", file=sys.stderr)
        sys.exit(0)
