"""The MAIN loop's Bash-policy deny reason.

The main loop orchestrates; it does not touch data sources. Its bash surface is
the read-only viewers + non-adapter `defender-*` shims only — no data-source
adapter (it dispatches gather for that) and no `gather_raw/` reads (it consumes
the gather summary). Since #535 the reader lane is PER-RUN and ANCHORED, and #551
made `bind`/`compile_policy` the SINGLE policy source; the MAIN policy is compiled
via `compile_policy_for(MAIN_DEF, …)` (the policy-only half of `bind`). This module
now owns only the MAIN fall-through deny reason, which `MAIN_DEF` carries.
"""

from __future__ import annotations

# Fall-through in `claude -p` meant "ask the user"; headless we have no prompt, so
# an unrecognized main-loop command fails closed (deny).
FALLTHROUGH_DENY_REASON = (
    "Blocked: only the defender-* shims and read-only viewers (jq/ls/cat/…) are "
    "permitted from the main loop. Dispatch gather for data-source access; do not "
    "run arbitrary shell."
)
