"""`AgentPolicy` — the declarative per-agent permission the gate keys on.

An agent's Bash/Read capability is *data it brings*, not a role branch in the
gate. `decide_bash`/`decide_read` take an `AgentPolicy` and behave accordingly,
so adding an agent is a new policy value (+ any custom matchers), never a new
`_decide_bash_<role>` method. Runtime agents (main/gather) get their policy from
`bash_policy.json` via `bash.policy_for(name)`; a learning-loop agent (the judge)
constructs its own `AgentPolicy` in its own module.

The shared security invariants — the read-only viewer allowlist and the
secret/ground-truth read denylist — stay GLOBAL in `bash_policy.json` and are
applied by the gate for every agent regardless of policy; they are not per-agent
config.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from collections.abc import Callable

if TYPE_CHECKING:  # annotations only — importing these here would cycle with bash.py
    from defender.runtime.bash_exec import Pipeline

    from .bash import BashDecision

# A custom matcher is an agent's *custom logic*: given the gate's single parse, it
# claims a command (returns an allow `BashDecision`) or declines (`None`, falling
# through to the generic adapter/viewer flow). It runs before adapter
# classification, so an agent can permit a shape the generic flow would misclassify
# or deny (e.g. the judge's pinned closed-ticket read via `python3 <ticket_cli>`).
Matcher = Callable[["list[Pipeline]"], "BashDecision | None"]

_DEFAULT_DENY_REASON = (
    "Blocked: this command is not permitted for this agent (read-only viewers and "
    "the agent's declared capabilities only)."
)


@dataclass(frozen=True)
class AgentPolicy:
    """What an agent may do at the Bash/Read gate.

    - `adapters` — may invoke a data-source adapter (captured transparently).
    - `adapter_sql_pipe` — may run the `adapter --raw | defender-sql '<SQL>'` pipe.
    - `raw_reads` — may read / `jq` `gather_raw/**` (the MAIN loop may not; the
      gather subagent and the judge may).
    - `read_roots` — extra allowed read roots beyond `{run_dir, defender_dir}`
      (the judge's comparison dir under `learning_run_dir`).
    - `custom_matchers` — the agent's custom logic (see `Matcher`).
    - `deny_reason` — the fall-through deny message shown to the model.
    """

    adapters: bool = False
    adapter_sql_pipe: bool = False
    raw_reads: bool = False
    read_roots: tuple[Path, ...] = ()
    custom_matchers: tuple[Matcher, ...] = ()
    deny_reason: str = _DEFAULT_DENY_REASON
