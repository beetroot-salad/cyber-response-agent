
from __future__ import annotations

GATHER_FALLTHROUGH_DENY_REASON = (
    "Blocked: reach a data source with the `query` tool, never with bash — "
    "`query(system=…, verb=…, params={…}, query_id=…)`. Bash here is local computation over a "
    "payload already on disk: the read-only viewers (cat/grep/head/tail/wc), of which only "
    "`cat` opens a file — the rest read STDIN, so pipe into them, e.g. "
    "`cat <ABSOLUTE payload path> | grep '<substring>'`, or aggregate with "
    "`cat <payload path> | defender-sql '<SQL>'`. Prefer the absolute path the query result "
    "reports; a relative one resolves against the run dir. Do not run arbitrary shell."
)
