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

from defender.hooks._cmd_segments import (
    ADAPTER_CLI_RE,
    NON_ADAPTER_SHIMS,
    OPERATOR_TOOLS,
)
from defender.runtime.bash_exec import Pipeline

# The aggregation shim that consumes an adapter's payload on stdin. Only
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
        return cmd not in NON_ADAPTER_SHIMS and cmd not in OPERATOR_TOOLS
    return bool(ADAPTER_CLI_RE.search(cmd))


def flat_stages(pipelines: list[Pipeline]) -> list[list[str]]:
    """The flat per-stage argvs (pipeline boundaries flattened, empty stages
    dropped) — the view the gate's allowlist / unsafe-construct checks iterate."""
    return [st.argv for pl in pipelines for st in pl.stages if st.argv]


def has_adapter(pipelines: list[Pipeline]) -> bool:
    """True iff any stage of the command is a data-source adapter."""
    return any(is_adapter_stage(s) for s in flat_stages(pipelines))


# `standalone_adapter_argv` / `adapter_sql_split` went with the routes they fed (#611). They
# split an adapter command into the argv the capture layer ran and the `(adapter, defender-sql)`
# pipe it streamed a payload through — and there is no capture-from-bash layer left to hand an
# argv to. `has_adapter` survives because the CLASSIFICATION still earns an adapter-shaped
# command its own deny reason (one that names the `query` tool), which is the whole of what the
# taxonomy is still for on this lane.
