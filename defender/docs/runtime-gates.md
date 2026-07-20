# Runtime gates — in-process permission, budget, and integrity hooks

How the runtime driver enforces its gates in-process (the successor to the retired `claude -p` hook wiring). Moved out of `defender/CLAUDE.md` verbatim (2026-07-20); the code is the spec — start at `defender/runtime/permission/` and `defender/agents.py`.

The learning loop has proven its value end-to-end on real cases, so the
earlier "runtime reliability gates are out of scope" stance is **lifted**.
The runtime is the in-process **PydanticAI driver** (`runtime/driver.py`),
so these gates run **in-process** — not as Claude Code PreToolUse/PostToolUse
subprocesses. The legacy `claude -p` runtime and its `run-settings.json` hook
wiring were retired; the gate *logic* lives on, re-hosted in-process (the
`hooks/` modules below are now imported as plain libraries, not wired as
hooks). The gates:

- **`runtime/permission/`** — the single in-process permission/validation
  gate (a package: `bash.py` gate / `command_shape.py` classifiers shared with
  dispatch / `files.py` read+write). It unifies the four old `claude -p`
  PreToolUse hooks, the driver calls it before each tool, raising `ModelRetry`
  on a deny (the in-process twin of the old exit-2). The Bash gate is structured
  around the **no-shell executor** (#379): the read-only lane runs `shell=False`
  (`runtime/bash_exec.py`), so the gate validates the SAME argv-stage
  decomposition the executor runs (`bash_exec.parse`) — what it approves is
  exactly what executes, with no validator/executor parser differential to
  bypass. The gate parses the command once and returns a `BashDecision` carrying
  that parse, so dispatch + execution never re-decompose it (#456). The decision
  is then a **deny-by-default, per-agent list of `Grant`s** (#575): each grant is a
  **shape** (program + flags + arity — no paths) plus a **scope** (anchored regexes
  over the **RESOLVED** path). A stage is allowed iff a grant's shape claims it AND
  everything `PROGRAMS[grant.program]` says it opens resolves into that grant's scope;
  a non-adapter command is allowed iff every stage is. `PROGRAMS`
  (`permission/grant.py`) is the ONE table of what each program opens — **`cat` is the
  sole opener**, and every other granted program is `OPENS_NOTHING`, a claim its shape
  must earn by admitting no file-opening flag (`grep -f`, `wc --files0-from=`,
  `grep -r`; the flag classes are positive boolean allowlists built from `gnu_flags.py`,
  #579). `grep`/`jq`/`head`/`tail`/`wc` are stdin-only pipe stages — `cat X | grep -n s`,
  never `grep -n s X` — and there is no `ls`/`cd` on any lane, which leaves the whole
  bash surface with no recursive-descent primitive and no path-opening program but `cat`.
  Each agent hangs its own grant builder on its own `AgentDefinition.bash_shapes`
  (`compile_policy` composes what the defs bring; `runtime/` enumerates no agents and
  imports no `learning/` private — the registry lives at `defender/agents.py`). Three
  grants are `pins_path` exemptions, where the operand IS the program and the pattern is
  the containment: the actor's pinned `python3 <script>`, the lead author's / curator's
  `rm <path>`, and the judge's ticket CLI — whose **mandatory** `--require-closed`
  lookahead is its entire security property (a boolean-flag allowlist would make it
  optional and drop it silently). Containment is **positive enumeration**: main cannot
  read `gather_raw` because that shape is not in its list — there is no `RAW_MARKER`
  substring clamp over the command text any more — and the read tool enforces the SAME
  tuple OBJECT the `cat` grant carries as its scope (`AgentPolicy.read_allow`), so
  read↔bash parity is identity, not maintenance. `bash_policy.json` still carries the
  secret/ground-truth read denylist, applied at `resolve()` time on both surfaces; the
  deny *reasons* live with the policies (and are checked against the live grant list — a
  reason naming a program the agent cannot run teaches a dead command). `defender-policy
  show|explain` (`scripts/policy_cli.py`) is the audit CLI: a second CONSUMER of the
  gate, never a second implementation — and an OPERATOR tool no agent may run.
  - **Main-loop raw-access + shim gating** — only the `defender-*` shims and
    read-only viewers run from the main loop; data-source adapters and
    `gather_raw/` reads are denied there (the gather subagent is the
    data-access layer).
  - **Query capture is a capability of the typed `query` tool** — since #611 the
    gather subagent calls the in-process `query` tool (`runtime/query_tool.py`)
    with `system`/`verb`/`params`; there is no standalone adapter call on any bash
    lane. The tool's capture capability records the queries-table row + by-ref
    payload in-process — inseparable from the call, so a query that ran cannot
    dodge its row — which retired the old `block_unwrapped_adapter_calls.py`
    wrapper-forcing hook (no `defender-record-query` wrapper to require). The old
    `defender-<sys> … | defender-sql '<SQL>'` adapter-in-a-pipe is gone; a reduce
    is now a separate step over the captured payload
    (`cat <payload> | defender-sql '<SQL>'`). The queries table is still a
    real integrity gate.
  - **invlang validation on `investigation.md` writes** — `permission/files.py`
    runs the structural validator (`skills/invlang/validate.py`'s
    `validate_companion`, the same rules the old `invlang_validate.py` hook
    used) before the write commits and raises `ModelRetry` with the validator
    errors on a violation. Fails closed on an internal validator error. The
    validator library + its `_walkers.py` are also shared with the corpus
    queries and the learning loop.
- **budget + observability** — installed as in-process `Hooks` on the agents
  in `driver.py`: an `after_tool_execute` budget accountant (warning-only
  per-run tool-call / spawn / wall-clock caps, `hooks/budget_enforcer.py`'s
  logic) and a `model_request` wrap that logs every API request to
  `llm_requests.jsonl` (`runtime/observe.py`, which projects `tool_trace.jsonl`).
- **lead claim + descriptor injection + tagging** — `runtime/tools.py`
  imports `record_lead.claim_lead` (writes the leads-table row and claims the
  `lead_id` with an atomic `O_CREAT|O_EXCL` create — a reused id raises
  in-process, bouncing the defender back to PLAN, so it stays a real integrity
  gate), `inject_system_skill_description.descriptor_catalog` (the
  progressive-disclosure descriptor catalog), `runtime/untrusted.wrap` (salted
  untrusted-data tagging of adapter/alert reads + the gather return), and
  `record_lesson_load.lesson_name` (lesson→outcome traceability into
  `lessons_loaded.jsonl`). These anchor on the run dir from `AgentDeps`.

Still out of scope (port later if a case demands it): report-consistency
judges, the phase state machine, class-slot grammar vocab, and sibling-fork
topological uniqueness. Two further invlang spec rules (per-type class-slot
grammar, sibling-fork uniqueness) are *not* yet enforced because the spec's
own examples currently contradict them — see
`docs/decisions/defender-invlang-enforcement-ramp.md`.
