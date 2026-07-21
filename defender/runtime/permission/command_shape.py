
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


def has_adapter(pipelines: list[Pipeline]) -> bool:
    return any(is_adapter_stage(s) for s in flat_stages(pipelines))


