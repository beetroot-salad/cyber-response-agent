
from __future__ import annotations

from defender.hooks._cmd_segments import (
    ADAPTER_RE,
    NON_ADAPTER_SHIMS,
    OPERATOR_TOOLS,
)
from defender.runtime.bash_exec import Pipeline

SQL_SHIM = "defender-sql"


def is_adapter_stage(argv: list[str]) -> bool:
    if not argv:
        return False
    cmd = argv[0]
    if cmd in ("python", "python3") and len(argv) > 1:
        cmd = argv[1]
    if cmd.startswith("defender-"):
        return cmd not in NON_ADAPTER_SHIMS and cmd not in OPERATOR_TOOLS
    return bool(ADAPTER_RE.search(cmd))


def flat_stages(pipelines: list[Pipeline]) -> list[list[str]]:
    return [st.argv for pl in pipelines for st in pl.stages if st.argv]


def is_reducer_stage(argv: list[str]) -> bool:
    """Is this stage the SQL reducer? `bin/` carries exactly one, and it is a NON-adapter
    (`NON_ADAPTER_SHIMS`), so this and `is_adapter_stage` partition rather than overlap. It
    lives beside `SQL_SHIM` rather than at a call site so a second reducer is one edit."""
    return bool(argv) and argv[0] == SQL_SHIM


def terminal_reducer(pipelines: list[Pipeline]) -> bool:
    """Is the reducer the stage whose exit status the executor actually REPORTS?

    `bash_exec` returns `procs[-1].returncode` of the last pipeline it ran, so a reducer that
    is not that final stage never has its own status observed: `… | defender-sql '<bad>' |
    head -40` exits 0 with the reduce broken, and `… | defender-sql '<ok>' | grep zzz` exits 1
    with the reduce fine. Any reader that attributes the reported rc to the reducer is right
    only when the reducer IS that stage, which is what this answers.

    Connectors are refused for the same reason: across `&&`/`||` the reported rc belongs to
    whichever pipeline ran last, and a short-circuit means the reducer may not have run at all.
    """
    if len(pipelines) != 1:
        return False
    stages = flat_stages(pipelines)
    return bool(stages) and is_reducer_stage(stages[-1])


def has_adapter(pipelines: list[Pipeline]) -> bool:
    return any(is_adapter_stage(s) for s in flat_stages(pipelines))


