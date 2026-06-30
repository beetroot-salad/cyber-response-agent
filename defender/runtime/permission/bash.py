"""The Bash gate: allow/deny a command for a given agent role.

**Structured around the no-shell executor (#379).** The read-only Bash lane runs
`shell=False` (`runtime/bash_exec.py`), so the gate does not parse a shell string
and predict what bash will do — it validates the SAME `Pipeline` decomposition the
executor runs (`bash_exec.parse`). What the gate approves is exactly what executes;
there is no validator/executor parser differential to bypass. The decision is then a
deny-by-default allowlist over each stage's program, sourced from the declarative
`bash_policy.json`:

  - main loop — only the read-only viewers + non-adapter `defender-*` shims; no
    data-source adapters (dispatch gather), no `gather_raw/` reads.
  - gather subagent — the same viewers/shims, plus a data-source adapter run
    either standalone (captured transparently) or as the sanctioned
    `adapter --raw | defender-sql '<SQL>'` aggregation pipe.

**The command is parsed exactly once (#456).** `decide_bash` unwraps + parses, then
returns a `BashDecision` carrying that parse: the verdict, the `Pipeline` list (for
the executor's `run_parsed`), and the adapter/pipe routing the dispatcher consumes —
so neither dispatch nor execution re-decomposes the string. The
adapter/non-adapter classification lives in `command_shape` (shared with dispatch),
the main-loop raw/adapter deny *reasons* in `hooks/block_main_loop_raw_access.py`."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS, unwrap
from defender.hooks.block_main_loop_raw_access import (
    ADAPTER_DENY_REASON,
    RAW_DENY_REASON,
    RAW_MARKER,
)
from defender.runtime import bash_exec, bash_policy
from defender.runtime.agent_role import AgentRole

from . import command_shape
from .decision import Decision

# Fall-through in `claude -p` meant "ask the user"; headless we have no prompt,
# so an unrecognized main-loop command fails closed (deny), matching the net
# effect of the static allowlist (only defender-* shims + jq/ls/cat were ever
# permitted without a prompt).
FALLTHROUGH_DENY_REASON = (
    "Blocked: only the defender-* shims and read-only viewers (jq/ls/cat/…) are "
    "permitted from the main loop. Dispatch gather for data-source access; do not "
    "run arbitrary shell."
)

# The gather subagent IS the data-access layer, so the main-loop "dispatch gather"
# advice is nonsensical here — it would tell gather to dispatch itself. Gather may
# run a data-source adapter (`defender-<system> …`) directly as a standalone
# command (captured automatically) plus read-only viewers; everything else fails
# closed.
GATHER_FALLTHROUGH_DENY_REASON = (
    "Blocked: gather may only run a data-source adapter (`defender-<system> …`) as "
    "a standalone command — it is captured automatically — plus read-only viewers "
    "(jq/grep/ls/cat/…). To read data, run the adapter directly; don't run "
    "arbitrary shell (no curl/rm/python3, no pipes or redirects into writes)."
)

# Gather may run a data-source adapter directly — it's captured transparently —
# but only solo, or as the sanctioned `adapter --raw | defender-sql '<SQL>'`
# aggregation pipe. Any other pipeline/compound makes "the payload" ambiguous.
ADAPTER_STANDALONE_REASON = (
    "Blocked: run the data-source adapter as a standalone command (it is captured "
    "automatically — no wrapper needed), then filter the persisted payload file "
    "with jq/grep/Read. The only adapter pipe allowed is "
    "`defender-<system> … --raw | defender-sql '<SQL>'`. Don't otherwise pipe or "
    "chain the adapter call."
)

# The gather-payload capture wrapper legitimately names `gather_raw` paths on the
# command line (record-query writes one) — exempt it from the raw clamp. Mirrors
# block_main_loop_raw_access.main's exemption.
_GATHER_PAYLOAD_TOKENS = (
    "record_query", "defender-record-query",
)

# A leading `VAR=value` env-assignment prefix (the credential-groping vector) —
# matched against the first token of a stage only.
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass(frozen=True)
class BashDecision(Decision):
    """A Bash verdict that carries the gate's single parse, so dispatch and
    execution don't re-decompose the command (#456):

      - `pipelines` — the parsed `Pipeline` list, handed to `bash_exec.run_parsed`
        (None on a deny; empty tuple for an empty command).
      - `adapter_argv` — the standalone-adapter argv to capture (gather only).
      - `sql_pipe` — the `(adapter_argv, sql_argv)` split for the sanctioned
        `adapter --raw | defender-sql` pipe (gather only).

    `adapter_argv`/`sql_pipe` are mutually exclusive and set only when the verdict
    is allow; both None means the command runs through the plain executor."""

    pipelines: tuple[bash_exec.Pipeline, ...] | None = None
    adapter_argv: list[str] | None = None
    sql_pipe: tuple[list[str], list[str]] | None = None


def _names_a_gather_payload_tool(cmd: str) -> bool:
    return any(tok in cmd for tok in _GATHER_PAYLOAD_TOKENS)


@lru_cache(maxsize=1)
def _allowed_programs() -> frozenset:
    """Programs allowed as a stage head in either lane: the declarative read-only
    viewers (`bash_policy.json`) plus the non-adapter `defender-*` shims (the
    taxonomy's source of truth). Adapters are gated separately (per-agent)."""
    return frozenset(bash_policy.viewers() | set(NON_ADAPTER_SHIMS))


def _stage_unsafe(argv: list[str]) -> bool:
    """A stage carrying a construct we refuse to auto-approve even though the
    no-shell executor renders it inert: a subshell / command substitution
    (`(`/`)`/`$(`/backtick), an `export`, or a leading `VAR=` assignment. With
    shell=False these expand to literal bytes (no security risk), but we keep the
    deny as cheap defense-in-depth — the last line if `shell=True` is ever
    reintroduced anywhere downstream — and so the agent gets a clear deny rather
    than a confusing literal-`$(...)`-as-filename error."""
    for i, t in enumerate(argv):
        if t in ("(", ")"):
            return True
        if "$(" in t or "`" in t:
            return True
        if t == "export":
            return True
        if i == 0 and _ENV_ASSIGN_RE.match(t):
            return True
    return False


def _parse(cmd: str) -> list[bash_exec.Pipeline] | None:
    """Unwrap + parse `cmd` (already stripped) once into the `Pipeline` list, or
    None to fail closed — when `unwrap` rejects the wrapper, or the executor's
    decomposition raises on an operator/redirect it does not model (the shared
    `bash_exec.parse`, the whole point of #379: gate and executor decompose
    identically). This is the single decomposition every branch below routes off."""
    inner = unwrap(cmd)
    if inner is None:
        return None
    try:
        return bash_exec.parse(inner)
    except bash_exec.BashExecError:
        return None


def _decide_bash_gather(cmd: str) -> BashDecision:
    """Gather subagent. A standalone adapter call is allowed directly (the harness
    captures it), as is the `adapter --raw | defender-sql '<SQL>'` aggregation
    pipe. Any other pipeline/compound containing an adapter is ambiguous and
    denied. Non-adapter commands must be read-only viewers / non-adapter shims, so
    arbitrary shell (`rm`, `curl|bash`, `python3 …`) still fails closed."""
    pipelines = _parse(cmd)
    if pipelines is None:
        return BashDecision(False, GATHER_FALLTHROUGH_DENY_REASON)
    if command_shape.has_adapter(pipelines):
        # A standalone adapter is captured transparently; the only sanctioned
        # multi-stage shape is the `adapter --raw | defender-sql '<SQL>'` pipe (a
        # single two-stage pipeline). Any other compound containing an adapter — a
        # different downstream program, or a `;`/`&&`/`||` sequence — is ambiguous
        # and denied. The adapter/sql query payloads are NOT run through the
        # substitution guard (they go straight to subprocess shell=False).
        standalone = command_shape.standalone_adapter_argv(pipelines)
        if standalone is not None:
            return _allow(pipelines, adapter_argv=standalone)
        if bash_policy.adapter_sql_pipe_allowed("gather"):
            split = command_shape.adapter_sql_split(pipelines)
            if split is not None:
                return _allow(pipelines, sql_pipe=split)
        return BashDecision(False, ADAPTER_STANDALONE_REASON)
    # Non-adapter command: read-only viewers / non-adapter shims only. The
    # substitution/assignment guard applies here (these stages execute through the
    # no-shell executor), but not to the adapter/defender-sql payloads above.
    return _decide_viewers(pipelines, GATHER_FALLTHROUGH_DENY_REASON)


def _decide_bash_main(cmd: str) -> BashDecision:
    """Main loop: no adapter calls, no gather_raw reads, only safe shims/viewers.
    A `defender-record-query … -- <adapter> …` wrapper is fine — its stage head is
    the (allowlisted) wrapper, not the adapter, so it is neither flagged as an
    adapter call nor denied."""
    if RAW_MARKER in cmd and not _names_a_gather_payload_tool(cmd):
        return BashDecision(False, RAW_DENY_REASON)

    pipelines = _parse(cmd)
    if pipelines is None:
        return BashDecision(False, FALLTHROUGH_DENY_REASON)
    # A data-source adapter from the main loop is denied with the specific reason
    # (it must be dispatched via gather, and run directly here it escapes the audit
    # trail) rather than the generic fall-through.
    if not bash_policy.adapters_allowed("main") and command_shape.has_adapter(pipelines):
        return BashDecision(False, ADAPTER_DENY_REASON)
    # The main loop runs only the read-only viewers/shims (no adapters past the
    # check above), so the substitution/assignment guard applies to every stage.
    return _decide_viewers(pipelines, FALLTHROUGH_DENY_REASON)


def _decide_viewers(pipelines: list[bash_exec.Pipeline], deny_reason: str) -> BashDecision:
    """The shared non-adapter tail: every stage must be substitution-free and an
    allowlisted read-only viewer / non-adapter shim, else fail closed."""
    stages = command_shape.flat_stages(pipelines)
    if any(_stage_unsafe(s) for s in stages):
        return BashDecision(False, deny_reason)
    if not all(s[0] in _allowed_programs() for s in stages):
        return BashDecision(False, deny_reason)
    return _allow(pipelines)


def _allow(
    pipelines: list[bash_exec.Pipeline],
    *,
    adapter_argv: list[str] | None = None,
    sql_pipe: tuple[list[str], list[str]] | None = None,
) -> BashDecision:
    return BashDecision(
        True, pipelines=tuple(pipelines), adapter_argv=adapter_argv, sql_pipe=sql_pipe,
    )


def decide_bash(command: str, *, role: AgentRole) -> BashDecision:
    """Allow/deny a Bash command, porting the three Bash gate hooks.

    `role=MAIN` → the orchestrator (slice 1): no adapter calls, no gather_raw
    reads, only safe shims/viewers.
    Any non-MAIN role (today `GATHER`, slice 2) → the gather subagent: it may
    run a data-source adapter directly (captured transparently) — standalone or
    piped into defender-sql — plus read-only viewers; arbitrary shell fails
    closed. New subagent roles get their own branch here when their policy
    diverges from gather's.

    Returns a `BashDecision` carrying the single parse (see the class): callers
    read `.allow`/`.reason` as before, and route capture/execution off
    `.adapter_argv`/`.sql_pipe`/`.pipelines` without re-parsing (#456).
    """
    cmd = command.strip()
    if not cmd:
        return BashDecision(True)

    if role is not AgentRole.MAIN:
        return _decide_bash_gather(cmd)
    return _decide_bash_main(cmd)
