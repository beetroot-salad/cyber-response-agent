"""`AgentPolicy` — the declarative per-agent permission the gate keys on.

An agent's Bash/Read/Write capability is *data it brings*, not a role branch in the gate.
`decide_bash`/`decide_read`/`decide_write` take an `AgentPolicy` and behave accordingly, so
adding an agent is a new policy value, never a new `_decide_bash_<role>` method.

Since #575 all three surfaces speak ONE containment model (`grant.Grant`): a command is
allowed iff it matches a grant's **shape** (program + flags + arity — no paths) and
everything `PROGRAMS[grant.program]` says it opens **resolves** into that grant's **scope**
(anchored regexes over the RESOLVED path). The per-agent capability BITS are gone: what an
agent may do is the grant list itself — `raw_reads` became "the gather_raw shape is (not) in
this agent's list", `operand_gated` became "this grant's program has an extractor", and
`adapters`/`adapter_sql_pipe` became the two structurally-routed `Route` grants. Positive
enumeration, so "main cannot read gather_raw" is not a clamp bolted onto a wider grant — it
is an address main never had.

The program-table validation is HERE, in `__post_init__`, rather than in `compile_policy`: it
must hold for EVERY policy, including one built directly (the curator's per-spawn corpus
policy) — an untabled program is an UNGATED one, and the denylist-free curator lane is the
worst place for that fail-open to hide."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .grant import PROGRAMS, Grant, PathShapes

_DEFAULT_DENY_REASON = (
    "Blocked: this command is not permitted for this agent (read-only viewers and "
    "the agent's declared capabilities only)."
)


@dataclass(frozen=True)
class AgentPolicy:
    """What an agent may do at the Bash/Read/Write gate.

    - `bash_allow` — the agent's Bash grants. A non-adapter command is allowed iff EVERY
      stage is claimed by a `Route.PLAIN` grant here (shape ∧ scope). Empty (the default) →
      no bash surface at all (a confined stage reads through `read_file`). Data-source
      adapters are claimed by the two structural `Route` grants, which never match a stage.
    - `read_allow` — the read tool's path shapes, `fullmatch`ed against the RESOLVED path.
      This IS the same tuple OBJECT the `cat` grant carries as its `scope` (`compile_policy`
      hands one object to both), which is what makes read↔bash parity structural rather than
      maintained — there is nothing to keep in sync. Empty → no shape filter, so the read
      gate stays root-only (every non-reader agent, whose reads are bounded by its roots).
    - `read_roots` — extra allowed read roots beyond `{run_dir, defender_dir}` (the judge's
      comparison dir under the investigation run dir, which is where its `gather_raw` lives).
    - `read_confine` — when non-empty, REPLACES the `defender_dir` read base: the gate then
      allows only `{run_dir} ∪ read_confine ∪ read_roots`. The gray-box confine (#512): a
      confined actor sees only its lesson corpora, never the judge's grading rubric.
    - `write_allow` — anchored `re.Pattern`s `fullmatch`ed against the RESOLVED write path.
      A flat, deny-by-default list of the specific paths an agent may author, never a coarse
      root prefix. Because the operand is resolved before matching, a `..` escape is collapsed
      away and cannot match — the allowlist is a true path set, not a string prefix. Empty
      (the default) → the agent may write nothing.
    - `deny_reason` — the fall-through deny message shown to the model. PROMPT SURFACE: a
      reason naming a program this agent's own lane denies teaches a dead command, so it is
      checked against the live grant list (g1), never hand-maintained.
    """

    bash_allow: tuple[Grant, ...] = ()
    read_allow: PathShapes = PathShapes()
    read_roots: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = ()
    write_allow: tuple[re.Pattern[str], ...] = ()
    deny_reason: str = _DEFAULT_DENY_REASON
    # The budget-posture bit (#631), carried from the agent DEFINITION through
    # `compile_policy` so the budget hook reads it off `deps.policy` — DATA, never a
    # role branch. False for every learning stage (accounting-only); True for MAIN and
    # GATHER (deny-and-kill). A new agent must STATE its posture rather than inherit one.
    budget_enforced: bool = False

    def __post_init__(self) -> None:
        """Fail LOUD on a grant naming a program absent from `PROGRAMS` — never fail-open at
        the first decide, which is what the old `_OPERAND_GATED_PROGRAMS.get(argv[0]) is None
        → True` pass-through did: an untabled program was silently ungated."""
        untabled = sorted({g.program for g in self.bash_allow if g.program not in PROGRAMS})
        if untabled:
            raise ValueError(
                f"bash grant names untabled program(s) {untabled}: every granted program must "
                "declare what it opens in permission.grant.PROGRAMS (an untabled program is an "
                "ungated one). Add it there — with a real extractor, or OPENS_NOTHING earned by "
                "a shape admitting no file-opening flag."
            )
