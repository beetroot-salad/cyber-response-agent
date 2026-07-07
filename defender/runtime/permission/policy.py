"""`AgentPolicy` — the declarative per-agent permission the gate keys on.

An agent's Bash/Read capability is *data it brings*, not a role branch in the
gate. `decide_bash`/`decide_read` take an `AgentPolicy` and behave accordingly,
so adding an agent is a new policy value, never a new `_decide_bash_<role>`
method. Every agent's Bash surface is one flat, anchored **regex allowlist over
the tokenized argv** (`bash_allow`) — "what can this agent run?" is answered by
reading that agent's policy file, not the gate. Matching happens on the parsed
argv (`command_shape.flat_stages`), which is de-quoted and expansion-free, NOT on
the raw command string — so the classic raw-string fail-opens (`jq "$(cmd)"`
matching a quoted-arg pattern and then expanding under a shell) cannot occur, and
`shell=False` execution keeps the args inert (the regex gates program/shape only).

Command **shape** is the allowlist's job, and — since #535 — so is operand
**path-containment** for the runtime agents: main/gather bake the run's read roots
into their `bash_allow` regex (`policies._common.reader_patterns`), so a viewer's
file operand must TEXTUALLY sit under `{run_dir}` or a tight corpus `.md` and a `..`
segment is rejected literally (the bash lane does no `resolve()`, so a symlink target
is closed by the write-side invariant that no allowed tool creates a symlink, not by
the regex; see `_common`). The judge keeps the complementary `resolve()`-based `jq`
file-operand path-gate (`bash._jq_reads_within_roots`, enabled by `jq_operand_gated`),
since its `jq` legitimately opens files; main/gather `jq` is stdin-compute-only, so it
has no file operand to gate. The shared security invariants — the secret/ground-truth
read denylist and the `gather_raw` raw-read clamp — stay global / capability-bit driven
and are applied for every agent regardless of `bash_allow`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_DENY_REASON = (
    "Blocked: this command is not permitted for this agent (read-only viewers and "
    "the agent's declared capabilities only)."
)


@dataclass(frozen=True)
class AgentPolicy:
    """What an agent may do at the Bash/Read gate.

    - `bash_allow` — the agent's Bash allowlist: anchored `re.Pattern`s matched
      per stage against `" ".join(argv)` (the de-quoted, expansion-free tokens
      from `command_shape.flat_stages`). A non-adapter command is allowed iff
      EVERY stage matches some pattern here. Empty (the default) → no bash reader
      surface at all (the confined actor reads through `read_file`). Data-source
      adapters are NOT expressed here — they route structurally (see `adapters`).
    - `jq_operand_gated` — when True, a `jq` stage's file operands must resolve
      within the policy's read roots (the judge's path-gated `jq`; see
      `bash._jq_reads_within_roots`). False for main/gather because their `jq` is
      stdin-compute-only (no file operand to gate — #535); their reader lane instead
      confines the file-OPENING viewers (`cat`/`grep`/…) via the anchored `bash_allow`.
    - `adapters` — may invoke a data-source adapter (captured transparently).
    - `adapter_sql_pipe` — may run the `adapter --raw | defender-sql '<SQL>'` pipe.
    - `raw_reads` — may read / `jq` `gather_raw/**` (the MAIN loop may not; the
      gather subagent and the judge may).
    - `read_roots` — extra allowed read roots beyond `{run_dir, defender_dir}`
      (the judge's comparison dir under `learning_run_dir`).
    - `read_confine` — when non-empty, REPLACES the `defender_dir` read base: the
      read gate then allows only `{run_dir} ∪ read_confine ∪ read_roots`, not the
      whole corpus. The gray-box confine (#512): a confined actor sees only its
      lesson corpora, never the judge's grading rubric. Empty (the default) keeps
      the legacy `{run_dir, defender_dir, *read_roots}` — inert for main/gather.
    - `write_confine` — extra allowed WRITE roots beyond `{run_dir}` (the mirror of
      `read_confine` for the write gate): a writer agent that authors a corpus subtree
      declares it here (the lead author's `defender/skills`). Empty (the default) keeps
      writes run-dir-only — inert for every read-only/predictor agent and the main loop,
      which write only their own run dir.
    - `deny_reason` — the fall-through deny message shown to the model.
    """

    bash_allow: tuple[re.Pattern[str], ...] = ()
    jq_operand_gated: bool = False
    adapters: bool = False
    adapter_sql_pipe: bool = False
    raw_reads: bool = False
    read_roots: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = ()
    write_confine: tuple[Path, ...] = ()
    deny_reason: str = _DEFAULT_DENY_REASON
