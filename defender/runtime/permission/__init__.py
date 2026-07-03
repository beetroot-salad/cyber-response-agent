"""Single in-process permission/validation gate for the PydanticAI runtime.

This is the simplified port of the old `claude -p` PreToolUse hooks (the
main-loop raw/adapter clamp, the safe-shim allowlist, and invlang validation).
Instead of subprocesses reading stdin-JSON and exiting 2, this package exposes
pure decision functions that the driver calls in-process and raises `ModelRetry`
on a deny. Decisions are pure (`command`/`path`/`text` in, a `Decision` out) so
they unit-test for free, with no model call.

Three previously-tangled concerns, now one module each:

  - `bash.py` — the Bash gate (`decide_bash`), structured around the no-shell
    executor (#379) and returning a `BashDecision` that carries the gate's single
    parse so dispatch + execution never re-decompose the command (#456).
  - `command_shape.py` — the adapter/non-adapter classifiers over the parsed
    `bash_exec.Pipeline` structure, shared between the gate and tool dispatch.
  - `files.py` — the read deny-by-default allowlist (`decide_read`,
    `is_untrusted_read`) and the write/invlang gate (`decide_write`).

The public surface is re-exported here, so `from defender.runtime import
permission; permission.<name>` resolves unchanged.
"""

from __future__ import annotations

from . import command_shape
from .bash import (
    ADAPTER_STANDALONE_REASON,
    FALLTHROUGH_DENY_REASON,
    GATHER_FALLTHROUGH_DENY_REASON,
    BashDecision,
    decide_bash,
    policy_for,
)
from .decision import Decision
from .files import decide_read, decide_write, is_untrusted_read
from .policy import AgentPolicy

__all__ = [
    "ADAPTER_STANDALONE_REASON",
    "FALLTHROUGH_DENY_REASON",
    "GATHER_FALLTHROUGH_DENY_REASON",
    "AgentPolicy",
    "BashDecision",
    "Decision",
    "command_shape",
    "decide_bash",
    "decide_read",
    "decide_write",
    "is_untrusted_read",
    "policy_for",
]
