"""The GATHER subagent's Bash-policy deny reason.

Gather IS the data-access layer, but since #611 it reaches a data source through the typed
`query` TOOL, not through bash: the adapter routes off its bash lane are gone (`_common.
reader_grants` no longer emits them), and what bash keeps is the local-computation half — the
read-only viewers over payloads already on disk, plus its own `gather_raw/**`. #551 made
`bind`/`compile_policy` the SINGLE policy source; the GATHER policy is compiled via
`compile_policy_for(GATHER_DEF, …)` (the policy-only half of `bind`). This module owns only the
GATHER fall-through deny reason, which `GATHER_DEF` carries.
"""

from __future__ import annotations

# PROMPT SURFACE: this text is checked against GATHER's own live grant list, because a reason
# naming a route the agent cannot take teaches a dead command — and after #611 the dead route is
# the one this reason used to teach ("run the data-source adapter as a standalone command — it is
# captured automatically"). The correction a model needs here is the name of the surface that
# DOES work, so the reason leads with it.
#
# The `cat` form is spelled ABSOLUTE on purpose: bash resolves a relative operand against the
# repo root, not the run dir, so the relative spelling of a payload path denies — and the
# `[record_query] raw payload:` note the query result carries is absolute precisely so this pipe
# can be copied straight out of it.
GATHER_FALLTHROUGH_DENY_REASON = (
    "Blocked: reach a data source with the `query` tool, never with bash — "
    "`query(system=…, verb=…, params={…}, query_id=…)`. Bash here is local computation over a "
    "payload already on disk: the read-only viewers (cat/grep/jq/head/tail/wc), of which only "
    "`cat` opens a file — the rest read STDIN, so pipe into them, e.g. "
    "`cat <ABSOLUTE payload path> | jq '<filter>'`, or aggregate with "
    "`cat <ABSOLUTE payload path> | defender-sql '<SQL>'`. Use the absolute path the query "
    "result reports; a relative spelling is denied. Do not run arbitrary shell."
)
