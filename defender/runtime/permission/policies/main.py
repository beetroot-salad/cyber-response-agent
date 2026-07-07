"""The MAIN loop's Bash policy.

The main loop orchestrates; it does not touch data sources. Its bash surface is
the read-only viewers + non-adapter `defender-*` shims only — no data-source
adapter (it dispatches gather for that) and no `gather_raw/` reads (it consumes
the gather summary). Since #535 the reader lane is PER-RUN and ANCHORED: the
viewer file operands must resolve (textually) under `run_dir` + the defender
corpus, so the bash lane confines reads the same way `files.decide_read` already
does. See `..policy.AgentPolicy` for the field contract and `._common` for the
anchoring grammar.
"""

from __future__ import annotations

from pathlib import Path

from defender.runtime import bash_policy

from ..files import build_write_allow
from ..policy import AgentPolicy
from ._common import reader_patterns

# Fall-through in `claude -p` meant "ask the user"; headless we have no prompt, so
# an unrecognized main-loop command fails closed (deny).
FALLTHROUGH_DENY_REASON = (
    "Blocked: only the defender-* shims and read-only viewers (jq/ls/cat/…) are "
    "permitted from the main loop. Dispatch gather for data-source access; do not "
    "run arbitrary shell."
)


def main_policy(run_dir: Path, defender_dir: Path) -> AgentPolicy:
    """The MAIN policy anchored to this run's read roots (#535). `run_dir` +
    `defender_dir` bake the reader allowlist's operand anchors, so a main policy is
    per-run — there is no unconfined module-level default to inherit.

    `write_allow` declares the one write surface the main loop owns: its run-dir
    subtree (`investigation.md` / `report.md` and any other case artifact it authors).
    A single anchored pattern over the resolved run dir — exact parity with the prior
    run-dir write confinement, now expressed as the flat write allowlist every writer
    uses (`decide_write`)."""
    return AgentPolicy(
        bash_allow=reader_patterns(run_dir, defender_dir),
        jq_operand_gated=False,  # jq is stdin-compute-only here — no file operand to gate (#535)
        adapters=bash_policy.adapters_allowed("main"),
        adapter_sql_pipe=bash_policy.adapter_sql_pipe_allowed("main"),
        raw_reads=bash_policy.raw_reads_allowed("main"),
        write_allow=(build_write_allow(run_dir),),
        deny_reason=FALLTHROUGH_DENY_REASON,
    )
