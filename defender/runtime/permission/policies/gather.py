"""The GATHER subagent's Bash policy.

Gather IS the data-access layer: it may run a data-source adapter directly
(captured transparently) or as the sanctioned `adapter --raw | defender-sql
'<SQL>'` aggregation pipe, and it may read / `jq` its own `gather_raw/**`. Its
reader surface (`bash_allow`) is the same viewers/shims as main; the adapter
capability rides on the capability bits, routed structurally (`bash._decide_adapter`).
"""

from __future__ import annotations

from defender.runtime import bash_policy

from ..policy import AgentPolicy
from ._common import viewer_patterns

# Gather IS the data layer, so the main-loop "dispatch gather" advice is nonsensical
# here — it may run the adapter directly, plus read-only viewers; everything else
# fails closed.
GATHER_FALLTHROUGH_DENY_REASON = (
    "Blocked: gather may only run a data-source adapter (`defender-<system> …`) as "
    "a standalone command — it is captured automatically — plus read-only viewers "
    "(jq/grep/ls/cat/…). To read data, run the adapter directly; don't run "
    "arbitrary shell (no curl/rm/python3, no pipes or redirects into writes)."
)


def gather_policy() -> AgentPolicy:
    return AgentPolicy(
        bash_allow=viewer_patterns(),
        jq_operand_gated=False,  # deferred (jq dual-use) — see [[read-surface-consolidation-512]]
        adapters=bash_policy.adapters_allowed("gather"),
        adapter_sql_pipe=bash_policy.adapter_sql_pipe_allowed("gather"),
        raw_reads=bash_policy.raw_reads_allowed("gather"),
        deny_reason=GATHER_FALLTHROUGH_DENY_REASON,
    )
