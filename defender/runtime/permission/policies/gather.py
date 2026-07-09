"""The GATHER subagent's Bash policy — now a thin `bind(GATHER_DEF)` alias (#551).

Gather IS the data-access layer: it may run a data-source adapter directly
(captured transparently) or as the sanctioned `adapter --raw | defender-sql
'<SQL>'` aggregation pipe, and it may read / `jq` its own `gather_raw/**`. Its
reader surface (`bash_allow`) is the same anchored viewers/shims as main (#535);
the difference is capability bits (adapters + raw_reads), routed structurally
(`bash._decide_adapter`) and via the run-dir anchor. #551 makes `bind`/`compile_policy`
the SINGLE policy source, so `gather_policy` is demoted to a one-line alias over it; this
module now owns only the GATHER fall-through deny reason (which `GATHER_DEF` carries).
"""

from __future__ import annotations

from pathlib import Path

from ..policy import AgentPolicy

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
    """The GATHER policy anchored to this run's read roots (#535) — a thin `bind(GATHER_DEF)`
    alias (#551 — the single policy source): `compile_policy` bakes the same anchored reader
    lane as main plus the gather capability bits (adapters + `raw_reads` for its own
    `gather_raw/**`), so the returned policy is exactly what the bound gather subagent runs.
    `bind` is imported lazily — `GATHER_DEF` lives in `driver`."""
    from defender.runtime.agent_definition import bind
    from defender.runtime.driver import GATHER_DEF

    return bind(GATHER_DEF, run_dir, defender_dir=defender_dir).policy
