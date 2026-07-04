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
from pathlib import Path

from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS, unwrap
from defender.hooks.block_main_loop_raw_access import (
    ADAPTER_DENY_REASON,
    RAW_DENY_REASON,
    RAW_MARKER,
)
from defender.runtime import bash_exec, bash_policy

from . import command_shape
from .decision import Decision
from .files import read_allowed_path
from .policy import AgentPolicy

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

# jq option grammar for the file-arg path-gate (the judge's `bash_readers=('jq',)`
# lane). jq OPENS a file for: its positional input operands (after the filter
# program) and the argument-taking flags below. The gate validates EVERY such path
# against the policy's read roots — closing the flag-injection escape where a
# `--slurpfile <out-of-roots>` loads a file while the trailing operand looks clean.
#
# Each entry: flag -> (tokens consumed INCLUDING the flag, index of the FILE arg
# within that span or None, supplies-the-filter). `-f`/`--from-file` load the filter
# program FROM a file, so their arg is both a gated file AND fills the filter slot
# (the next bare positional is then an input, not the filter).
_JQ_ARG_FLAGS: dict[str, tuple[int, int | None, bool]] = {
    "-f": (2, 1, True), "--from-file": (2, 1, True),
    "--slurpfile": (3, 2, False), "--rawfile": (3, 2, False), "--argfile": (3, 2, False),
    "--arg": (3, None, False), "--argjson": (3, None, False),       # <name> <value>
    "--indent": (2, None, False), "-L": (2, None, False), "--library-path": (2, None, False),
}
_JQ_ARGS_MODES = frozenset({"--args", "--jsonargs"})  # trailing positionals become strings, not files


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


def policy_for(agent: str) -> AgentPolicy:
    """Build the `AgentPolicy` for a runtime agent ('main' | 'gather') from the
    declarative `bash_policy.json` capability flags. The fall-through deny message
    differs by agent: the main loop is told to dispatch gather for data access,
    while the gather subagent (which IS the data layer) is told to run the adapter
    directly. Learning-loop agents (the judge) construct their own `AgentPolicy` in
    their own module rather than going through this runtime-agent factory."""
    deny_reason = (
        FALLTHROUGH_DENY_REASON if agent == "main" else GATHER_FALLTHROUGH_DENY_REASON
    )
    return AgentPolicy(
        adapters=bash_policy.adapters_allowed(agent),
        adapter_sql_pipe=bash_policy.adapter_sql_pipe_allowed(agent),
        raw_reads=bash_policy.raw_reads_allowed(agent),
        deny_reason=deny_reason,
    )


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


def _decide_adapter(pipelines: list[bash_exec.Pipeline], policy: AgentPolicy) -> BashDecision:
    """Classify a command that contains a data-source adapter. Denied unless the agent
    may run adapters; when allowed, a standalone call is captured transparently and the
    only sanctioned multi-stage shape is `adapter --raw | defender-sql '<SQL>'` (gated on
    `adapter_sql_pipe`). Any other adapter compound is ambiguous. The adapter/sql payloads
    are NOT run through the substitution guard (they go straight to subprocess shell=False)."""
    if not policy.adapters:
        return BashDecision(False, ADAPTER_DENY_REASON)
    standalone = command_shape.standalone_adapter_argv(pipelines)
    if standalone is not None:
        return _allow(pipelines, adapter_argv=standalone)
    if policy.adapter_sql_pipe:
        split = command_shape.adapter_sql_split(pipelines)
        if split is not None:
            return _allow(pipelines, sql_pipe=split)
    return BashDecision(False, ADAPTER_STANDALONE_REASON)


def _jq_flag_step(argv: list[str], i: int) -> tuple[int, list[str], bool] | None:
    """Handle one jq OPTION token at `argv[i]` (a token starting with `-`, never a
    bare `-`). Returns `(next_i, files_loaded, supplies_filter)`, or `None` to FAIL
    CLOSED (a malformed arg-taking flag, or an unrecognized long option that might
    smuggle a file). A short boolean flag / bundle (`-s`, `-nr`, `-c`, …) opens no
    file and consumes only itself."""
    t = argv[i]
    spec = _JQ_ARG_FLAGS.get(t)
    if spec is not None:
        consume, file_off, supplies_filter = spec
        if i + consume > len(argv):
            return None  # arg-taking flag with its argument(s) missing
        loaded = [argv[i + file_off]] if file_off is not None else []
        return i + consume, loaded, supplies_filter
    if t.startswith("--"):
        return None  # unrecognized long option — fail closed (may take a file)
    return i + 1, [], False  # short boolean flag / bundle


def _jq_input_files(argv: list[str]) -> list[str] | None:
    """Every file path a `jq` invocation (`argv[0] == 'jq'`) will OPEN — its
    positional input operands plus the `--slurpfile`/`--rawfile`/`--argfile`/`-f`
    file targets. Returns `[]` for an inert stdin-only `jq '.'` (nothing to gate), or
    `None` when the argv uses a shape we won't reason about (FAIL CLOSED). `-`
    operands (stdin) are skipped; after `--args`/`--jsonargs` the trailing positionals
    are string args, not files."""
    files: list[str] = []
    filter_seen = False
    args_mode = False
    i, n = 1, len(argv)
    while i < n:
        t = argv[i]
        if args_mode:
            i += 1  # post `--args`/`--jsonargs`: positionals are strings, not files
        elif t in _JQ_ARGS_MODES:
            args_mode = True
            i += 1
        elif t.startswith("-") and t != "-":
            step = _jq_flag_step(argv, i)
            if step is None:
                return None
            i, loaded, supplies_filter = step
            files.extend(loaded)
            filter_seen = filter_seen or supplies_filter
        elif not filter_seen:
            filter_seen = True  # the first bare positional is the filter program
            i += 1
        else:
            if t != "-":
                files.append(t)  # a subsequent bare positional is an input file
            i += 1
    return files


def _jq_reads_within_roots(
    argv: list[str], policy: AgentPolicy, *, run_dir: Path | None, defender_dir: Path | None
) -> bool:
    """Whether every file a `jq` stage opens resolves within `policy`'s read roots.
    An inert stdin `jq '.'` (no file operands) passes; an unparseable jq shape fails
    closed."""
    files = _jq_input_files(argv)
    if files is None:
        return False
    return all(
        read_allowed_path(f, run_dir=run_dir, defender_dir=defender_dir, policy=policy)
        for f in files
    )


def _decide_restricted_readers(
    pipelines: list[bash_exec.Pipeline], policy: AgentPolicy,
    *, run_dir: Path | None, defender_dir: Path | None,
) -> BashDecision:
    """A per-policy REDUCED reader set (the judge's jq-only lane). The command must
    be a SINGLE stage (a pipe/compound would re-open the reader surface via a
    downstream head/cat through the global fall-through), substitution-free, and a
    `jq` invocation whose file operands are path-gated to the policy's read roots.
    The only restricted set in play is `('jq',)`; a non-jq program — even one
    nominally listed — carries no file-arg path-gate, so it fails closed rather than
    admit an un-gated reader."""
    argv = command_shape.single_stage_argv(pipelines)  # a single command, never a pipe/compound
    if argv is None or _stage_unsafe(argv):
        return BashDecision(False, policy.deny_reason)
    if argv[0] != "jq" or "jq" not in (policy.bash_readers or ()):
        return BashDecision(False, policy.deny_reason)
    if not _jq_reads_within_roots(argv, policy, run_dir=run_dir, defender_dir=defender_dir):
        return BashDecision(False, policy.deny_reason)
    return _allow(pipelines)


def _decide_readers(
    pipelines: list[bash_exec.Pipeline], policy: AgentPolicy,
    *, run_dir: Path | None, defender_dir: Path | None,
) -> BashDecision:
    """The non-adapter reader tail, narrowed by `policy.bash_readers`:

      - `None` — today's GLOBAL viewer allowlist (main / gather, byte-for-byte).
      - `()` — NO bash reader surface at all (the confined actor: reads go through
        the read tool, never bash). Its pinned scripts still run — they are claimed
        by a custom matcher upstream of this tail.
      - a set (the judge's `('jq',)`) — only those programs, single-stage, with `jq`
        path-gated to the policy's read roots (`_decide_restricted_readers`)."""
    if policy.bash_readers is None:
        return _decide_viewers(pipelines, policy.deny_reason)
    if not policy.bash_readers:
        return BashDecision(False, policy.deny_reason)
    return _decide_restricted_readers(
        pipelines, policy, run_dir=run_dir, defender_dir=defender_dir
    )


def decide_bash(
    command: str, *, policy: AgentPolicy,
    run_dir: Path | None = None, defender_dir: Path | None = None,
) -> BashDecision:
    """Allow/deny a Bash command for an agent, driven entirely by its `AgentPolicy`
    (no per-role method): custom matchers first, then the raw-read clamp, adapter
    capture, and the per-policy reader surface (`bash_readers`).

    `run_dir`/`defender_dir` supply the read roots the judge's `jq` file-arg
    path-gate validates against; they are irrelevant to a policy with the default
    `bash_readers=None` (main/gather) or `()` (the actor), so those callers may omit
    them.

    Returns a `BashDecision` carrying the single parse (see the class): callers read
    `.allow`/`.reason` as before, and route capture/execution off
    `.adapter_argv`/`.sql_pipe`/`.pipelines` without re-parsing (#456).
    """
    cmd = command.strip()
    if not cmd:
        return BashDecision(True)

    # Raw-read clamp (a security invariant, so it runs before any custom matcher): a
    # command naming a gather_raw/ path is denied unless the agent may read raw. The
    # gather-payload-tool exemption keeps the main loop's `defender-record-query …
    # <gather_raw path>` wrapper allowed (it legitimately names a raw path); an agent
    # with raw_reads (gather, judge) skips the clamp entirely.
    if (
        RAW_MARKER in cmd
        and not policy.raw_reads
        and not _names_a_gather_payload_tool(cmd)
    ):
        return BashDecision(False, RAW_DENY_REASON)

    pipelines = _parse(cmd)
    if pipelines is None:
        return BashDecision(False, policy.deny_reason)

    # Custom logic: an agent's matcher may claim a command before the generic
    # adapter/viewer flow — e.g. the judge's pinned closed-ticket read runs as
    # `python3 <ticket_cli> …`, an adapter-shaped path the generic flow would
    # otherwise misclassify and deny.
    for matcher in policy.custom_matchers:
        claimed = matcher(pipelines)
        if claimed is not None:
            return claimed

    # A data-source adapter is classified by its own helper (capture routing / the
    # sanctioned adapter|defender-sql pipe / the adapter deny reasons).
    if command_shape.has_adapter(pipelines):
        return _decide_adapter(pipelines, policy)

    # Non-adapter command: the per-policy reader surface. `bash_readers=None` is
    # today's global viewer allowlist; `()` grants no bash reader; a set narrows to
    # those programs (the judge's path-gated jq). The substitution/assignment guard
    # applies throughout (these stages execute through the no-shell executor).
    return _decide_readers(pipelines, policy, run_dir=run_dir, defender_dir=defender_dir)
