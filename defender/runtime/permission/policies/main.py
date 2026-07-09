"""The MAIN loop's Bash policy — now a thin `bind(MAIN_DEF)` alias (#551).

The main loop orchestrates; it does not touch data sources. Its bash surface is
the read-only viewers + non-adapter `defender-*` shims only — no data-source
adapter (it dispatches gather for that) and no `gather_raw/` reads (it consumes
the gather summary). Since #535 the reader lane is PER-RUN and ANCHORED; #551
finishes the consolidation by making `bind`/`compile_policy` the SINGLE policy
source, so `main_policy` is demoted to a one-line alias delegating to it (NOT a
second builder kept honest by a parity test). This module now owns only the MAIN
fall-through deny reason (which `MAIN_DEF` carries) + that alias.
"""

from __future__ import annotations

from pathlib import Path

from ..policy import AgentPolicy

# Fall-through in `claude -p` meant "ask the user"; headless we have no prompt, so
# an unrecognized main-loop command fails closed (deny).
FALLTHROUGH_DENY_REASON = (
    "Blocked: only the defender-* shims and read-only viewers (jq/ls/cat/…) are "
    "permitted from the main loop. Dispatch gather for data-source access; do not "
    "run arbitrary shell."
)


def main_policy(run_dir: Path, defender_dir: Path) -> AgentPolicy:
    """The MAIN policy anchored to this run's read roots (#535) — a thin `compile_policy_for(MAIN_DEF)`
    alias (#551 — the single policy source): `compile_policy` bakes the anchored reader
    allowlist + the run-dir `write_allow` + the read↔bash filename `read_shapes` filter, so
    the returned policy is exactly what the bound MAIN loop runs (no drift, no parity test).
    Uses `compile_policy_for` (the policy-only half of `bind`) rather than `bind(...).policy`, so
    no deps object / uuid4 salt is minted just to read one field. Imported lazily — `MAIN_DEF`
    lives in `driver`, whose import path funnels back through this package."""
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.driver import MAIN_DEF

    return compile_policy_for(MAIN_DEF, run_dir, defender_dir=defender_dir)
