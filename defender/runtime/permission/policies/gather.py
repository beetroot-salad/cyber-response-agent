"""The GATHER subagent's Bash policy.

Gather IS the data-access layer: it may run a data-source adapter directly
(captured transparently) or as the sanctioned `adapter --raw | defender-sql
'<SQL>'` aggregation pipe, and it may read / `jq` its own `gather_raw/**`. Its
reader surface (`bash_allow`) is the same anchored viewers/shims as main (#535);
the difference is capability bits (adapters + raw_reads), routed structurally
(`bash._decide_adapter`) and via the run-dir anchor (gather's `gather_raw` reads
fall under the run root, and its `raw_reads` bit skips the main-loop raw clamp).
"""

from __future__ import annotations

from pathlib import Path

from defender.runtime import bash_policy

from ..policy import AgentPolicy
from ._common import reader_patterns

# Gather IS the data layer, so the main-loop "dispatch gather" advice is nonsensical
# here — it may run the adapter directly, plus read-only viewers; everything else
# fails closed.
GATHER_FALLTHROUGH_DENY_REASON = (
    "Blocked: gather may only run a data-source adapter (`defender-<system> …`) as "
    "a standalone command — it is captured automatically — plus read-only viewers "
    "(jq/grep/ls/cat/…). To read data, run the adapter directly; don't run "
    "arbitrary shell (no curl/rm/python3, no pipes or redirects into writes)."
)


def gather_policy(run_dir: Path, defender_dir: Path) -> AgentPolicy:
    """The GATHER policy anchored to this run's read roots (#535). Same anchored
    reader lane as main; `raw_reads=True` lets gather read its own `gather_raw/**`
    (under the run root) that the main loop is clamped off."""
    return AgentPolicy(
        bash_allow=reader_patterns(run_dir, defender_dir),
        jq_operand_gated=False,  # jq is stdin-compute-only here — no file operand to gate (#535)
        adapters=bash_policy.adapters_allowed("gather"),
        adapter_sql_pipe=bash_policy.adapter_sql_pipe_allowed("gather"),
        raw_reads=bash_policy.raw_reads_allowed("gather"),
        deny_reason=GATHER_FALLTHROUGH_DENY_REASON,
    )
