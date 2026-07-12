"""The GATHER subagent's Bash-policy deny reason.

Gather IS the data-access layer: it may run a data-source adapter directly
(captured transparently) or as the sanctioned `adapter | defender-sql
'<SQL>'` aggregation pipe, and it may read / `jq` its own `gather_raw/**`. Its
reader surface (`bash_allow`) is the same anchored viewers/shims as main (#535);
the difference is capability bits (adapters + raw_reads), routed structurally
(`bash._decide_adapter`) and via the run-dir anchor. #551 made `bind`/`compile_policy`
the SINGLE policy source; the GATHER policy is compiled via
`compile_policy_for(GATHER_DEF, …)` (the policy-only half of `bind`). This module now owns
only the GATHER fall-through deny reason, which `GATHER_DEF` carries.
"""

from __future__ import annotations

# Gather IS the data layer, so the main-loop "dispatch gather" advice is nonsensical
# here — it may run the adapter directly, plus read-only viewers; everything else
# fails closed.
# PROMPT SURFACE: the named programs are checked against GATHER's own live grant list. The old
# text named `ls` (deleted) and `curl/rm/python3` (never granted) — the second is the subtler
# fault: listing what an agent CANNOT run in the same slash-group vocabulary it reads to learn
# what it CAN is how a dead program gets learned as a live one.
GATHER_FALLTHROUGH_DENY_REASON = (
    "Blocked: gather may only run a data-source adapter (`defender-<system> …`) as a standalone "
    "command — it is captured automatically — plus the read-only viewers (cat/grep/jq/head/tail/"
    "wc), of which only `cat` opens a file; the rest read STDIN (`cat <payload> | jq '<filter>'`). "
    "To read data, run the adapter directly; do not run arbitrary shell."
)
