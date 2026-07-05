"""The MAIN loop's Bash policy.

The main loop orchestrates; it does not touch data sources. Its bash surface is
the read-only viewers + non-adapter `defender-*` shims only — no data-source
adapter (it dispatches gather for that) and no `gather_raw/` reads (it consumes
the gather summary). See `..policy.AgentPolicy` for the field contract.
"""

from __future__ import annotations

from defender.runtime import bash_policy

from ..policy import AgentPolicy
from ._common import viewer_patterns

# Fall-through in `claude -p` meant "ask the user"; headless we have no prompt, so
# an unrecognized main-loop command fails closed (deny).
FALLTHROUGH_DENY_REASON = (
    "Blocked: only the defender-* shims and read-only viewers (jq/ls/cat/…) are "
    "permitted from the main loop. Dispatch gather for data-source access; do not "
    "run arbitrary shell."
)


def main_policy() -> AgentPolicy:
    return AgentPolicy(
        bash_allow=viewer_patterns(),
        jq_operand_gated=False,  # deferred (jq dual-use) — see [[read-surface-consolidation-512]]
        adapters=bash_policy.adapters_allowed("main"),
        adapter_sql_pipe=bash_policy.adapter_sql_pipe_allowed("main"),
        raw_reads=bash_policy.raw_reads_allowed("main"),
        deny_reason=FALLTHROUGH_DENY_REASON,
    )
