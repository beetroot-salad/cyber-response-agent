"""HYPOTHESIZE phase handler.

Replaces the HYPOTHESIZE section of `skills/investigate/SKILL.md` with a
Python orchestration that dispatches the `hypothesize` subagent, parses its
terminal routing YAML, and appends the invlang block to investigation.md.

The `hypothesize` subagent (agents/hypothesize.md, model=sonnet) emits one of:
    - `hypothesize:` YAML block + `Selected lead:` + `Pitfalls:` (fork mode)
    - `gather:` YAML block with lead-level predictions + `Selected lead:` +
      `Pitfalls:` (no-fork mode — when no observable discriminates between
      candidate classifications yet)
    - `error:` block (malformed inputs)
followed by a terminal routing YAML:
    ```yaml
    mode: fork | no-fork
    selected_lead: <lead name>
    loop_n: <integer>
    ```

This handler:
    - computes `loop_n` from ctx.history (count of prior HYPOTHESIZE entries + 1)
    - invokes the subagent via the shared `_subagent.invoke_subagent` wrapper
    - detects and raises on `error:` blocks
    - extracts the terminal routing YAML via `extract_terminal_yaml`
    - validates the proposed append against the invlang validator
      (`validate_companion`) as a library call — catching rules 26/27/28
      (compound claim, evaluation prefix, leanness) + 1-25
    - on validation failure: respawns with `resume_from_checkpoint=true` and
      the validator errors as `remediation_notes`; accepts the second attempt
      only if it validates, else raises
    - appends the invlang sections to investigation.md
    - always routes to Phase.GATHER (the only legal transition)

Block-type inference (`hypothesize:` vs `gather:` vs `error:`) is done on the
raw response text before the trailer is extracted. The trailer's `mode` field
is cross-checked against the inferred block type; mismatch raises.

Not in this cutover:
    - Sibling-pair embedding-distance check for semantic non-discrimination.
      Rationale: 1/28 corpus blocks exhibits the failure; shipping the
      embedding infrastructure does not pay for itself at this rate. Filed as
      a post-cutover enhancement; revisit after ~20 fresh runs accumulate or
      if the failure rate rises.

Input (Context):
    ctx.run_dir, ctx.signature_id, ctx.history, ctx.alert

Output:
    PhaseResult
      - always Phase.GATHER
      - payload: {mode, selected_lead, loop_n, block_type}

Files written:
    {run_dir}/investigation.md — appends the invlang sections (no trailer).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._subagent import (
    extract_terminal_yaml,
    invoke_subagent as _shared_invoke,
)


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_HYPOTHESIZE_TIMEOUT_SECONDS", "300")
)

_VALID_MODES = {"fork", "no-fork"}


# ---------------------------------------------------------------------------
# Subagent invocation (mockable)
# ---------------------------------------------------------------------------


def _invoke_subagent(prompt: str, *, timeout: int = SUBAGENT_TIMEOUT_SECONDS) -> str:
    """Module-level wrapper over the shared subagent dispatcher.

    Kept as a module-level function so tests can monkeypatch it with
    `monkeypatch.setattr(hypothesize_handler, "_invoke_subagent", stub)`.
    """
    return _shared_invoke("hypothesize", prompt, timeout=timeout)


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


def _compute_loop_n(ctx: Context) -> int:
    """Current loop number = count of prior HYPOTHESIZE entries + 1.

    HYPOTHESIZE stamps the loop number on the block it is about to emit
    (ANALYZE counts the prior loops retrospectively).
    """
    prior = sum(1 for p in ctx.history if p == Phase.HYPOTHESIZE.value)
    # History includes the current phase (appended in orchestrate.run() before
    # the handler is called). Subtract 1 for the current entry so the count
    # reflects truly prior loops.
    if ctx.current_phase == Phase.HYPOTHESIZE and prior > 0:
        prior -= 1
    return prior + 1


def _assemble_prompt(ctx: Context, *, remediation_notes: list[str] | None = None) -> str:
    loop_n = _compute_loop_n(ctx)
    lines = [
        f"run_dir={ctx.run_dir}",
        f"signature_id={ctx.signature_id}",
        f"loop_n={loop_n}",
    ]
    if remediation_notes:
        lines.append("resume_from_checkpoint=true")
        lines.append("remediation_notes=" + " | ".join(remediation_notes))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Block-type detection + error-block handling
# ---------------------------------------------------------------------------


# Detect top-level key of the first fenced ```yaml block that carries one of
# the expected keys. Tolerates preamble YAML blocks (unlikely, but defensive).
_FIRST_FENCE_RE = re.compile(
    r"```yaml\s*\n(?P<body>.*?)\n```",
    re.DOTALL,
)


def _detect_block_type(raw: str) -> str:
    """Return the first top-level invlang key present in any yaml fence.

    Returns one of: "hypothesize", "gather", "error", "unknown". The terminal
    routing YAML (whose top-level keys are `mode/selected_lead/loop_n`) is
    distinguishable and not counted.
    """
    for m in _FIRST_FENCE_RE.finditer(raw):
        body = m.group("body")
        try:
            parsed = yaml.safe_load(body)
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        keys = set(parsed.keys())
        if "hypothesize" in keys:
            return "hypothesize"
        if "gather" in keys:
            return "gather"
        if "error" in keys:
            return "error"
        # Skip the terminal routing block (mode/selected_lead/loop_n).
    return "unknown"


def _extract_error_reason(raw: str) -> str:
    for m in _FIRST_FENCE_RE.finditer(raw):
        try:
            parsed = yaml.safe_load(m.group("body"))
        except yaml.YAMLError:
            continue
        if isinstance(parsed, dict) and "error" in parsed:
            err = parsed["error"]
            if isinstance(err, str):
                return err
            if isinstance(err, dict):
                return str(err.get("reason", err))
    return "<no reason provided>"


# ---------------------------------------------------------------------------
# Trailer validation
# ---------------------------------------------------------------------------


def _validate_trailer(trailer: dict, *, block_type: str, expected_loop_n: int) -> dict:
    """Verify the terminal routing YAML conforms to the subagent contract."""
    mode = trailer.get("mode")
    if mode not in _VALID_MODES:
        raise OrchestrationError(
            f"hypothesize subagent: invalid trailer mode {mode!r} "
            f"(expected one of {sorted(_VALID_MODES)})"
        )
    expected_by_type = {"hypothesize": "fork", "gather": "no-fork"}
    if block_type in expected_by_type and mode != expected_by_type[block_type]:
        raise OrchestrationError(
            f"hypothesize subagent: trailer mode {mode!r} does not match "
            f"block type {block_type!r} (expected {expected_by_type[block_type]!r})"
        )
    selected_lead = trailer.get("selected_lead")
    if not isinstance(selected_lead, str) or not selected_lead.strip():
        raise OrchestrationError(
            "hypothesize subagent: trailer missing non-empty selected_lead"
        )
    loop_n = trailer.get("loop_n")
    if not isinstance(loop_n, int):
        raise OrchestrationError(
            f"hypothesize subagent: trailer loop_n must be int, got {loop_n!r}"
        )
    if loop_n != expected_loop_n:
        raise OrchestrationError(
            f"hypothesize subagent: trailer loop_n={loop_n} does not match "
            f"orchestrator-computed loop_n={expected_loop_n}"
        )
    return trailer


# ---------------------------------------------------------------------------
# Section extraction (strip the terminal routing fence)
# ---------------------------------------------------------------------------


def _strip_terminal_routing(raw: str) -> str:
    """Return `raw` with the last ```yaml``` fence removed.

    The terminal routing YAML is consumed out-of-band and must not land in
    investigation.md — invlang validators would reject the `mode/selected_lead/
    loop_n` keys as unknown. Drop the last yaml fence; preserve all preceding
    fences (which carry the invlang `hypothesize:` / `gather:` blocks).
    """
    last_start = raw.rfind("```yaml")
    if last_start == -1:
        return raw.rstrip() + "\n"
    end_marker_start = raw.find("```", last_start + len("```yaml"))
    if end_marker_start == -1:
        return raw[:last_start].rstrip() + "\n"
    after = raw[end_marker_start + len("```"):]
    return (raw[:last_start].rstrip() + "\n" + after.lstrip()).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Validate + append (library invocation of the invlang validator)
# ---------------------------------------------------------------------------


def _validate_companion_proposed(ctx: Context, new_section: str) -> list[str]:
    """Run `validate_companion` against `investigation.md + new_section`.

    Returns the validator's error list. Used both for pre-write gating and for
    producing remediation notes on the retry path.
    """
    hooks_path = str(SOC_AGENT_ROOT / "hooks")
    if hooks_path not in sys.path:
        sys.path.insert(0, hooks_path)
    from scripts.invlang_validate import validate_companion  # type: ignore

    inv_path = ctx.run_dir / "investigation.md"
    current = inv_path.read_text() if inv_path.exists() else ""
    proposed = (
        current
        + ("\n" if current and not current.endswith("\n") else "")
        + new_section
    )
    return validate_companion(proposed, current if current else None)


def _append_to_investigation(ctx: Context, new_section: str) -> None:
    inv_path = ctx.run_dir / "investigation.md"
    current = inv_path.read_text() if inv_path.exists() else ""
    separator = "\n" if current and not current.endswith("\n") else ""
    inv_path.write_text(current + separator + new_section)


# ---------------------------------------------------------------------------
# Single-attempt pipeline
# ---------------------------------------------------------------------------


def _attempt(
    ctx: Context,
    *,
    expected_loop_n: int,
    remediation_notes: list[str] | None,
) -> tuple[str, str, dict, list[str]]:
    """Run one subagent invocation end-to-end.

    Returns `(sections_to_append, block_type, trailer, validator_errors)`.
    Raises OrchestrationError for unrecoverable shapes (error block, malformed
    trailer, unknown block type). Validator errors are *returned* rather than
    raised so the caller can decide whether to retry.
    """
    prompt = _assemble_prompt(ctx, remediation_notes=remediation_notes)
    raw = _invoke_subagent(prompt)

    block_type = _detect_block_type(raw)
    if block_type == "error":
        raise OrchestrationError(
            f"hypothesize subagent returned error block: {_extract_error_reason(raw)}"
        )
    if block_type == "unknown":
        raise OrchestrationError(
            "hypothesize subagent produced no hypothesize:/gather:/error: "
            f"block:\n{raw[:500]}"
        )

    trailer = _validate_trailer(
        extract_terminal_yaml(raw),
        block_type=block_type,
        expected_loop_n=expected_loop_n,
    )

    sections = _strip_terminal_routing(raw)
    errors = _validate_companion_proposed(ctx, sections)
    return sections, block_type, trailer, errors


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def handle(ctx: Context) -> PhaseResult:
    expected_loop_n = _compute_loop_n(ctx)

    sections, block_type, trailer, errors = _attempt(
        ctx, expected_loop_n=expected_loop_n, remediation_notes=None,
    )

    if errors:
        # One retry with the validator errors as remediation. The subagent
        # should read its checkpoint and correct the flagged claims.
        sections, block_type, trailer, errors = _attempt(
            ctx, expected_loop_n=expected_loop_n, remediation_notes=errors,
        )
        if errors:
            raise OrchestrationError(
                "HYPOTHESIZE invlang validation failed on retry:\n"
                + "\n".join(f"  - {e}" for e in errors)
            )

    _append_to_investigation(ctx, sections)

    payload = {
        "mode": trailer["mode"],
        "selected_lead": trailer["selected_lead"],
        "loop_n": trailer["loop_n"],
        "block_type": block_type,
    }
    return PhaseResult(next_phase=Phase.GATHER, payload=payload)
