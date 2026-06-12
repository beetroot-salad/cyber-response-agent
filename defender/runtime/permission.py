"""Single in-process permission/validation gate for the PydanticAI runtime.

This is the simplified port of the four Claude Code PreToolUse hooks
(`approve_shim_invocations`, `block_main_loop_raw_access`,
`block_unwrapped_adapter_calls`, `invlang_validate`). Instead of four
subprocesses reading stdin-JSON and exiting 2, one module exposes pure decision
functions that the driver calls in-process and raises `ModelRetry` on a deny.

**Functionality parity:** the *logic* is the existing logic — we import the same
`hooks/_cmd_segments.py` taxonomy and the same gate predicates, so a newly
onboarded `defender-*` adapter auto-gates here too, exactly as in the `claude -p`
runtime. We do not re-implement the rules; we re-host them.

Decisions are pure (`command`/`text` in, `Decision` out) so they unit-test for
free, with no model call.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

# defender/ (parents[1]) and the repo root (parents[2]); mirror the hooks'
# sys.path bootstrap so `defender.skills.invlang` resolves and the sibling
# hook/taxonomy modules import.
_DEFENDER_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = _DEFENDER_DIR.parent
for _p in (str(_REPO_ROOT), str(_DEFENDER_DIR / "hooks")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _cmd_segments import (  # noqa: E402  (sys.path set above)
    ADAPTER_CLI_RE,
    NON_ADAPTER_SHIMS,
    unwrap,
)
# Reuse the gate predicates verbatim — these are pure (no stdin/exit), so the
# in-process gate and the subprocess hooks can never disagree on the taxonomy.
from approve_shim_invocations import (  # noqa: E402
    READONLY_TOOLS,
    _all_segments_safe,
)
from block_main_loop_raw_access import (  # noqa: E402
    ADAPTER_DENY_REASON,
    RAW_DENY_REASON,
    RAW_MARKER,
    _adapter_shim_re,
)
from block_unwrapped_adapter_calls import (  # noqa: E402
    DENY_REASON as UNWRAPPED_DENY_REASON,
    _has_unwrapped_adapter,
)
from defender.skills.invlang.validate import validate_companion  # noqa: E402

# Fall-through in `claude -p` meant "ask the user"; headless we have no prompt,
# so an unrecognized main-loop command fails closed (deny), matching the net
# effect of the static allowlist (only defender-* shims + jq/ls/cat were ever
# permitted without a prompt).
FALLTHROUGH_DENY_REASON = (
    "Blocked: only the defender-* shims and read-only viewers (jq/ls/cat/…) are "
    "permitted from the main loop. Dispatch gather for data-source access; do not "
    "run arbitrary shell."
)

# The gather-payload tools legitimately name `gather_raw` paths on the command
# line (data-source-debug reads one, record-query writes one) — exempt them from
# the raw clamp. Mirrors block_main_loop_raw_access.main's exemption.
_GATHER_PAYLOAD_TOKENS = (
    "data_source_debug", "defender-data-source-debug",
    "record_query", "defender-record-query",
)


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str = ""


def _names_a_gather_payload_tool(cmd: str) -> bool:
    return any(tok in cmd for tok in _GATHER_PAYLOAD_TOKENS)


def decide_bash(command: str, *, is_main_session: bool) -> Decision:
    """Allow/deny a Bash command, porting the three Bash gate hooks.

    `is_main_session=True` → the orchestrator (slice 1 is always this): no
    adapter calls, no gather_raw reads, only safe shims/viewers.
    `is_main_session=False` → the gather subagent (slice 2): adapters allowed but
    only through the `defender-record-query` capture wrapper.
    """
    cmd = command.strip()
    if not cmd:
        return Decision(True)

    if not is_main_session:
        # Gather subagent: block_unwrapped_adapter_calls owns the rule.
        if _has_unwrapped_adapter(cmd):
            return Decision(False, UNWRAPPED_DENY_REASON)
        return Decision(True)

    # --- main loop (block_main_loop_raw_access + approve_shim_invocations) ---
    if RAW_MARKER in cmd and not _names_a_gather_payload_tool(cmd):
        return Decision(False, RAW_DENY_REASON)

    shim_re = _adapter_shim_re()
    is_adapter = bool(ADAPTER_CLI_RE.search(cmd)) or bool(shim_re and shim_re.search(cmd))
    wrapped = "record_query.py" in cmd or "defender-record-query" in cmd
    if is_adapter and not wrapped:
        return Decision(False, ADAPTER_DENY_REASON)

    # Allow iff composed entirely of safe tokens (readonly viewers + non-adapter
    # shims), after unwrapping a leading `timeout`/`bash -c`. Else fail closed.
    inner = unwrap(cmd)
    if inner is None:
        return Decision(False, FALLTHROUGH_DENY_REASON)
    safe = frozenset(set(READONLY_TOOLS) | set(NON_ADAPTER_SHIMS))
    if not _all_segments_safe(inner, safe):
        return Decision(False, FALLTHROUGH_DENY_REASON)
    return Decision(True)


# Read denylist — mirrors run-settings.json `permissions.deny` (creds, ssh,
# ground truth, the held-out manifest). Matched on any path component / suffix.
_READ_DENY_SUBSTR = (".env", "credentials", "ground_truth", "ground-truth", "cases.json")
_READ_DENY_DIR = ".ssh"


def decide_read(path: Path, *, is_main_session: bool) -> Decision:
    """Allow/deny a file read, porting the Read deny rules + the main-loop
    gather_raw clamp (`block_main_loop_raw_access` on Read)."""
    p = Path(path)
    name = p.name
    parts = set(p.parts)
    if _READ_DENY_DIR in parts or any(s in name for s in _READ_DENY_SUBSTR):
        return Decision(False, f"Blocked: {name} is a denied read (secrets / ground truth).")
    if is_main_session and RAW_MARKER in str(p) and not _names_a_gather_payload_tool(str(p)):
        return Decision(False, RAW_DENY_REASON)
    return Decision(True)


def is_untrusted_read(path: Path) -> bool:
    """True for reads of attacker-influenced data that must be tag-wrapped:
    the alert payload and (slice 2) raw gather payloads."""
    p = Path(path)
    return p.name == "alert.json" or RAW_MARKER in str(p)


def decide_write(path: Path, proposed_text: str, *, run_dir: Path) -> Decision:
    """Allow/deny a write of `proposed_text` to `path`, porting the
    `Write(/tmp/defender-runs/**)` path allow + `invlang_validate`.

    For `investigation.md`, run the structural invlang validator against the
    full proposed text (current on-disk text supplies the append-only baseline);
    any error denies with the validator's messages so the model can fix its
    invlang — the in-process equivalent of the hook's exit-2 feedback.
    """
    path = Path(path)
    run_dir = Path(run_dir).resolve()
    try:
        path.resolve().relative_to(run_dir)
    except ValueError:
        return Decision(
            False,
            f"Blocked: writes must stay inside the run dir ({run_dir}); "
            f"{path} is outside it.",
        )

    if path.name == "investigation.md":
        current = path.read_text() if path.is_file() else None
        errors = validate_companion(proposed_text, current)
        if errors:
            return Decision(
                False,
                "investigation.md failed invlang validation — fix and rewrite:\n"
                + "\n".join(f"  - {e}" for e in errors),
            )
    return Decision(True)
