"""Command-shape classification, shared between the Bash gate and tool dispatch.

Pure functions over the parsed `bash_exec.Pipeline` structure — the adapter/
non-adapter taxonomy the gate uses to *decide* and the dispatcher uses to *route*
capture. They do NO parsing: the caller decomposes once (`bash_exec.parse`) and
hands the structure here, so a command is parsed exactly once per tool call
(#456). This is the classification half that used to be tangled into the Bash
gate (`_segment_is_adapter` / `_adapter_sql_pipe_split` / `adapter_argv` /
`adapter_sql_pipe`); pulling it out is what lets the parse flow gate → dispatch.

The adapter taxonomy itself still comes from `hooks/_cmd_segments.py` (one source
of truth, so a newly onboarded adapter auto-gates)."""

from __future__ import annotations

from defender.hooks._cmd_segments import ADAPTER_CLI_RE, NON_ADAPTER_SHIMS
from defender.runtime.bash_exec import Pipeline

# The aggregation shim that consumes an adapter's `--raw` payload on stdin. Only
# this program may sit downstream of an adapter in the sanctioned pipe.
SQL_SHIM = "defender-sql"


def is_adapter_stage(argv: list[str]) -> bool:
    """True iff the stage's COMMAND (first token) is a data-source adapter — a
    `defender-<system>` shim or a `<system>_cli.py` script. Anchored to command
    position: an adapter name appearing as an *argument* (`which defender-<system>`,
    a `defender-record-query … -- defender-<system> …` wrapper) is NOT a query and
    must not be captured/denied as one."""
    if not argv:
        return False
    cmd = argv[0]
    if cmd in ("python", "python3") and len(argv) > 1:
        cmd = argv[1]  # raw `python3 …/<system>_cli.py` form
    if cmd.startswith("defender-"):
        return cmd not in NON_ADAPTER_SHIMS
    return bool(ADAPTER_CLI_RE.search(cmd))


def flat_stages(pipelines: list[Pipeline]) -> list[list[str]]:
    """The flat per-stage argvs (pipeline boundaries flattened, empty stages
    dropped) — the view the gate's allowlist / unsafe-construct checks iterate."""
    return [st.argv for pl in pipelines for st in pl.stages if st.argv]


def has_adapter(pipelines: list[Pipeline]) -> bool:
    """True iff any stage of the command is a data-source adapter."""
    return any(is_adapter_stage(s) for s in flat_stages(pipelines))


def standalone_adapter_argv(pipelines: list[Pipeline]) -> list[str] | None:
    """If the command is a STANDALONE adapter invocation (the gather-captured
    case) — a single stage whose command is an adapter — return its argv; else
    None. The argv IS the shlex-resolved stage, handed straight to the capture
    path."""
    stages = flat_stages(pipelines)
    if len(stages) == 1 and is_adapter_stage(stages[0]):
        return stages[0]
    return None


def adapter_sql_split(pipelines: list[Pipeline]) -> tuple[list[str], list[str]] | None:
    """If the command is the sanctioned `defender-<system> … --raw | defender-sql
    '<SQL>'` shape, return `(adapter_argv, sql_argv)`; else None. The shape is ONE
    pipeline of exactly two stages — an adapter producing on the left, defender-sql
    consuming on the right. defender-sql is self-sandboxed (no file/network), so
    aggregating the captured payload through it is a local transform, not a second
    data-source query.

    A `;`/`&&`/`||` compound (`adapter --raw ; defender-sql …`) is a SEQUENCE of
    SEPARATE pipelines, not a pipe, so it can't match this single-`Pipeline` test —
    the shell would sequence/short-circuit them (with `||`, run defender-sql only on
    adapter *failure*), whereas the capture path unconditionally streams the captured
    payload into defender-sql. Accepting those compounds was a validator/executor
    differential and a hole in the deny-by-default compound rule (#379)."""
    if len(pipelines) != 1:
        return None
    stages = flat_stages(pipelines)
    if len(stages) != 2:
        return None
    adapter, consumer = stages
    if is_adapter_stage(adapter) and consumer and consumer[0] == SQL_SHIM:
        return adapter, consumer
    return None
