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


def trim_ticket_context(raw: str) -> str:
    """Trim ticket-context output for additionalContext injection.

    Keeps: situation, definite (count instead of IDs, drops reasoning),
    maybe (max 3, drops reasoning), fast_resolve (full).
    """
    # Try to parse as YAML-in-markdown (the output is a ```yaml block)
    # If parsing fails, return raw — the main agent can still read it
    try:
        import yaml  # noqa: F811
    except ImportError:
        # No PyYAML — return raw output, trimming is best-effort
        return raw

    # Extract YAML block from markdown code fence if present
    yaml_text = raw
    fence_match = re.search(r"```ya?ml\s*\n(.*?)```", raw, re.DOTALL)
    if fence_match:
        yaml_text = fence_match.group(1)

    try:
        data = yaml.safe_load(yaml_text)
    except Exception:
        return raw

    if not isinstance(data, dict):
        return raw

    if "ticket_context" not in data:
        return raw
    tc = data["ticket_context"]
    if not isinstance(tc, dict):
        return raw

    trimmed = {}

    # situation — keep in full
    if "situation" in tc:
        trimmed["situation"] = tc["situation"]

    # definite — count instead of IDs, drop reasoning
    if "definite" in tc and isinstance(tc["definite"], list):
        trimmed_definite = []
        for entry in tc["definite"]:
            if not isinstance(entry, dict):
                continue
            t = {}
            if "alert_ids" in entry:
                ids = entry["alert_ids"]
                t["count"] = len(ids) if isinstance(ids, list) else 1
            if "shared" in entry:
                t["shared"] = entry["shared"]
            if "first_seen" in entry:
                t["first_seen"] = entry["first_seen"]
            if "temporal_pattern" in entry:
                t["temporal_pattern"] = entry["temporal_pattern"]
            # prior_investigation — keep disposition, archetype, ticket_id only
            pi = entry.get("prior_investigation", {})
            if isinstance(pi, dict) and pi.get("exists"):
                t["prior_investigation"] = {
                    "exists": True,
                    "disposition": pi.get("disposition"),
                    "matched_archetype": pi.get("matched_archetype"),
                    "matched_ticket_id": pi.get("matched_ticket_id"),
                }
            # reasoning — disk only (not included)
            trimmed_definite.append(t)
        trimmed["definite"] = trimmed_definite

    # maybe — max 3 entries, drop reasoning
    if "maybe" in tc and isinstance(tc["maybe"], list):
        trimmed_maybe = []
        for entry in tc["maybe"][:3]:
            if not isinstance(entry, dict):
                continue
            t = {}
            if "shared_entities" in entry:
                t["shared_entities"] = entry["shared_entities"]
            if "signature" in entry:
                t["signature"] = entry["signature"]
            # reasoning — disk only
            trimmed_maybe.append(t)
        trimmed["maybe"] = trimmed_maybe

    # fast_resolve — keep in full (safety-critical)
    if "fast_resolve" in tc:
        trimmed["fast_resolve"] = tc["fast_resolve"]

    try:
        return yaml.dump({"ticket_context": trimmed}, default_flow_style=False, sort_keys=False)
    except Exception:
        return raw


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
