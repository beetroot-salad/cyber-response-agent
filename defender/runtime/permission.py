"""Single in-process permission/validation gate for the PydanticAI runtime.

This is the simplified port of the old `claude -p` PreToolUse hooks (the
main-loop raw/adapter clamp, the safe-shim allowlist, and invlang validation).
Instead of subprocesses reading stdin-JSON and exiting 2, one module exposes
pure decision functions that the driver calls in-process and raises `ModelRetry`
on a deny.

**The Bash gate is structured around the no-shell executor (#379).** The
read-only Bash lane runs `shell=False` (`runtime/bash_exec.py`), so the gate no
longer parses a shell string and predicts what bash will do — it validates the
SAME argv-stage decomposition the executor runs (`bash_exec.stage_argvs`). What
the gate approves is exactly what executes; there is no validator/executor
parser differential to bypass. The decision is then a deny-by-default allowlist
over each stage's program, sourced from the declarative `bash_policy.json`:

  - main loop — only the read-only viewers + non-adapter `defender-*` shims; no
    data-source adapters (dispatch gather), no `gather_raw/` reads.
  - gather subagent — the same viewers/shims, plus a data-source adapter run
    either standalone (captured transparently) or as the sanctioned
    `adapter --raw | defender-sql '<SQL>'` aggregation pipe.

The adapter/non-adapter shim taxonomy still comes from `hooks/_cmd_segments.py`
(one source of truth, so a newly onboarded adapter auto-gates), and the
main-loop raw/adapter deny *reasons* from `hooks/block_main_loop_raw_access.py`.

Decisions are pure (`command`/`text` in, `Decision` out) so they unit-test for
free, with no model call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from defender.hooks._cmd_segments import (
    ADAPTER_CLI_RE,
    NON_ADAPTER_SHIMS,
    unwrap,
)
from defender.hooks.block_main_loop_raw_access import (
    ADAPTER_DENY_REASON,
    RAW_DENY_REASON,
    RAW_MARKER,
)
from defender.runtime import bash_exec, bash_policy
from defender.runtime.agent_role import AgentRole
from defender.skills.invlang.validate import validate_companion

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

# The aggregation shim that consumes an adapter's `--raw` payload on stdin. Only
# this program may sit downstream of an adapter in the sanctioned pipe.
_SQL_SHIM = "defender-sql"


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str = ""


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


def _decompose(inner: str) -> list[list[str]] | None:
    """The flat argv stages the executor would run for `inner` (already unwrapped),
    or None to fail closed when the command carries an operator/redirect the no-shell
    executor does not model (`bash_exec` raises). Sharing `bash_exec.stage_argvs` is
    the whole point of #379: the gate and the executor decompose identically. The
    substitution/assignment guard (`_stage_unsafe`) is applied by the caller, and
    ONLY to non-adapter viewer stages — an adapter / defender-sql query payload is
    passed straight to `subprocess` (shell=False), where `$(…)`/backticks are inert
    literal bytes, so guarding those stages only false-denies legitimate queries."""
    try:
        return bash_exec.stage_argvs(inner)
    except bash_exec.BashExecError:
        return None


def _segment_is_adapter(toks: list[str]) -> bool:
    """True iff the stage's COMMAND (first token) is a data-source adapter — a
    `defender-<system>` shim or a `<system>_cli.py` script. Anchored to command
    position: an adapter name appearing as an *argument* (`which defender-<system>`,
    a `defender-record-query … -- defender-<system> …` wrapper) is NOT a query and
    must not be captured/denied as one."""
    if not toks:
        return False
    cmd = toks[0]
    if cmd in ("python", "python3") and len(toks) > 1:
        cmd = toks[1]  # raw `python3 …/<system>_cli.py` form
    if cmd.startswith("defender-"):
        return cmd not in NON_ADAPTER_SHIMS
    return bool(ADAPTER_CLI_RE.search(cmd))


def _adapter_sql_pipe_split(inner: str) -> tuple[list[str], list[str]] | None:
    """If `inner` (already unwrapped) is the sanctioned `defender-<system> … --raw |
    defender-sql '<SQL>'` shape, return `(adapter_argv, sql_argv)`; else None. The
    shape is ONE pipeline of exactly two stages — an adapter producing on the left,
    defender-sql consuming on the right. defender-sql is self-sandboxed (no
    file/network), so aggregating the captured payload through it is a local
    transform, not a second data-source query.

    Uses `bash_exec.pipeline_argvs` (PIPELINE structure), not the flattened stage
    list: a `;`/`&&`/`||` compound (`adapter --raw ; defender-sql …`) is a SEQUENCE
    of separate pipelines, not a pipe, and must NOT be treated as the sanctioned
    pipe — the shell would sequence/short-circuit them (with `||`, run defender-sql
    only on adapter *failure*), whereas `_capture_adapter_sql` unconditionally
    streams the captured payload into defender-sql. Accepting those compounds was a
    validator/executor differential and a hole in the deny-by-default compound rule."""
    try:
        pipelines = bash_exec.pipeline_argvs(inner)
    except bash_exec.BashExecError:
        return None
    if len(pipelines) != 1 or len(pipelines[0]) != 2:
        return None
    adapter, consumer = pipelines[0]
    if _segment_is_adapter(adapter) and consumer and consumer[0] == _SQL_SHIM:
        return adapter, consumer
    return None


def adapter_argv(command: str) -> list[str] | None:
    """If `command` is a STANDALONE adapter invocation (the gather-captured case),
    return its argv; else None. Standalone = a single stage whose command is an
    adapter, after unwrapping a leading `timeout`/`bash -c`. The gather bash tool
    uses this to route the call through the transparent capture path."""
    inner = unwrap(command.strip())
    if inner is None:
        return None
    stages = _decompose(inner)
    if stages is None or len(stages) != 1 or not _segment_is_adapter(stages[0]):
        return None
    return stages[0]  # the stage's argv IS the adapter argv (shlex-resolved)


def adapter_sql_pipe(command: str) -> tuple[list[str], list[str]] | None:
    """If `command` is the sanctioned `adapter --raw | defender-sql '<SQL>'` pipe,
    return `(adapter_argv, sql_argv)`; else None. The gather bash tool uses this to
    capture the adapter payload and then aggregate it through defender-sql."""
    inner = unwrap(command.strip())
    if inner is None:
        return None
    return _adapter_sql_pipe_split(inner)


def _decide_bash_gather(cmd: str) -> Decision:
    """Gather subagent. A standalone adapter call is allowed directly (the harness
    captures it), as is the `adapter --raw | defender-sql '<SQL>'` aggregation
    pipe. Any other pipeline/compound containing an adapter is ambiguous and
    denied. Non-adapter commands must be read-only viewers / non-adapter shims, so
    arbitrary shell (`rm`, `curl|bash`, `python3 …`) still fails closed."""
    inner = unwrap(cmd)
    if inner is None:
        return Decision(False, GATHER_FALLTHROUGH_DENY_REASON)
    stages = _decompose(inner)
    if stages is None:
        return Decision(False, GATHER_FALLTHROUGH_DENY_REASON)
    if any(_segment_is_adapter(s) for s in stages):
        # A standalone adapter is captured transparently; the only sanctioned
        # multi-stage shape is the `adapter --raw | defender-sql '<SQL>'` pipe (a
        # single two-stage pipeline). Any other compound containing an adapter — a
        # different downstream program, or a `;`/`&&`/`||` sequence — is ambiguous
        # and denied. The adapter/sql query payloads are NOT run through the
        # substitution guard (they go straight to subprocess shell=False).
        if len(stages) == 1:
            return Decision(True)
        if bash_policy.adapter_sql_pipe_allowed("gather") and _adapter_sql_pipe_split(inner):
            return Decision(True)
        return Decision(False, ADAPTER_STANDALONE_REASON)
    # Non-adapter command: read-only viewers / non-adapter shims only. The
    # substitution/assignment guard applies here (these stages execute through the
    # no-shell executor), but not to the adapter/defender-sql payloads above.
    if any(_stage_unsafe(s) for s in stages):
        return Decision(False, GATHER_FALLTHROUGH_DENY_REASON)
    if not all(s[0] in _allowed_programs() for s in stages):
        return Decision(False, GATHER_FALLTHROUGH_DENY_REASON)
    return Decision(True)


def _decide_bash_main(cmd: str) -> Decision:
    """Main loop: no adapter calls, no gather_raw reads, only safe shims/viewers.
    A `defender-record-query … -- <adapter> …` wrapper is fine — its stage head is
    the (allowlisted) wrapper, not the adapter, so it is neither flagged as an
    adapter call nor denied."""
    if RAW_MARKER in cmd and not _names_a_gather_payload_tool(cmd):
        return Decision(False, RAW_DENY_REASON)

    inner = unwrap(cmd)
    if inner is None:
        return Decision(False, FALLTHROUGH_DENY_REASON)
    stages = _decompose(inner)
    if stages is None:
        return Decision(False, FALLTHROUGH_DENY_REASON)
    # A data-source adapter from the main loop is denied with the specific reason
    # (it must be dispatched via gather, and run directly here it escapes the audit
    # trail) rather than the generic fall-through.
    if not bash_policy.adapters_allowed("main") and any(_segment_is_adapter(s) for s in stages):
        return Decision(False, ADAPTER_DENY_REASON)
    # The main loop runs only the read-only viewers/shims (no adapters past the
    # check above), so the substitution/assignment guard applies to every stage.
    if any(_stage_unsafe(s) for s in stages):
        return Decision(False, FALLTHROUGH_DENY_REASON)
    if not all(s[0] in _allowed_programs() for s in stages):
        return Decision(False, FALLTHROUGH_DENY_REASON)
    return Decision(True)


def decide_bash(command: str, *, role: AgentRole) -> Decision:
    """Allow/deny a Bash command, porting the three Bash gate hooks.

    `role=MAIN` → the orchestrator (slice 1): no adapter calls, no gather_raw
    reads, only safe shims/viewers.
    Any non-MAIN role (today `GATHER`, slice 2) → the gather subagent: it may
    run a data-source adapter directly (captured transparently) — standalone or
    piped into defender-sql — plus read-only viewers; arbitrary shell fails
    closed. New subagent roles get their own branch here when their policy
    diverges from gather's.
    """
    cmd = command.strip()
    if not cmd:
        return Decision(True)

    if role is not AgentRole.MAIN:
        return _decide_bash_gather(cmd)
    return _decide_bash_main(cmd)


def _is_within(p: Path, root: Path) -> bool:
    """True iff resolved path `p` is `root` or below it."""
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def decide_read(
    path: Path, *, run_dir: Path, defender_dir: Path, role: AgentRole
) -> Decision:
    """Allow/deny a file read — a **deny-by-default allowlist**, matching the shape
    `decide_write` already uses for writes. A read must resolve INSIDE one of two
    roots: the run dir (the agent's own case artifacts + gather payloads) or the
    defender corpus (`defender_dir` — skills / lessons / scripts / SKILL.md). Past
    runs read essentially nothing else (alert.json, SKILLs, lessons, run artifacts);
    everything outside both roots fails closed. `resolve()` collapses `..` and
    symlinks, so an allowed-root prefix can't be escaped (the structural close for
    the `cat …/.env` / basename-only / case-sensitivity gaps a denylist alone left).

    On top of the allowlist, the declarative secret/ground-truth denylist
    (`bash_policy.json`) still denies a sensitive file that lands INSIDE a root — a
    captured `.env` in the run dir, the eval `cases.json` — cheap belt-and-suspenders.

    The main-loop gather_raw clamp is unchanged: the main loop consumes the gather
    summary, never the raw payload; the gather subagent (a non-MAIN role) reads
    its own gather_raw to verify its query result."""
    p = Path(path)
    rp = p.resolve()
    roots = (Path(run_dir).resolve(), Path(defender_dir).resolve())
    if not any(_is_within(rp, root) for root in roots):
        return Decision(
            False,
            "Blocked: reads are limited to the run dir and the defender corpus "
            f"(skills/lessons/scripts); {p} is outside both.",
        )
    # Belt-and-suspenders: a secret / ground-truth file INSIDE an allowed root is
    # still denied (substrings match the filename, dirs match any path component).
    name = rp.name
    parts = set(rp.parts)
    if any(d in parts for d in bash_policy.read_deny_dirs()) or any(
        s in name for s in bash_policy.read_deny_substrings()
    ):
        return Decision(False, f"Blocked: {name} is a denied read (secrets / ground truth).")
    # No gather-payload-tool exemption here: that exemption is about a Bash
    # *command* invoking record-query (which legitimately names a gather_raw
    # path). block_main_loop_raw_access never applies it to a Read
    # (its `cmd` is "" for non-Bash), so a main-loop read of any gather_raw path is
    # unconditionally clamped.
    if RAW_MARKER in str(rp) and role is AgentRole.MAIN:
        return Decision(False, RAW_DENY_REASON)
    return Decision(True)


def is_untrusted_read(path: Path) -> bool:
    """True for reads of attacker-influenced data that must be tag-wrapped:
    the alert payload and (slice 2) raw gather payloads."""
    p = Path(path)
    return p.name == "alert.json" or RAW_MARKER in str(p)


def decide_write(path: Path, proposed_text: str, *, run_dir: Path) -> Decision:
    """Allow/deny a write of `proposed_text` to `path`, porting the
    `Write(<run_dir>/**)` path allow + `invlang_validate`.

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
        # Fail closed on an internal validator error — same as invlang_validate's
        # hook, which exits 2 (block) rather than letting the write through.
        try:
            errors = validate_companion(proposed_text, current)
        except Exception as e:  # noqa: BLE001 — a blocking gate must fail closed
            return Decision(
                False,
                f"investigation.md validation errored — failing closed: {e!r}. "
                "Simplify the invlang and rewrite.",
            )
        if errors:
            return Decision(
                False,
                "investigation.md failed invlang validation — fix and rewrite:\n"
                + "\n".join(f"  - {e}" for e in errors),
            )
    return Decision(True)
