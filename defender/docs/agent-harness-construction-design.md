# The agent-harness seam: one shared capability surface on two engines (Agent SDK + PydanticAI)

**Status:** design — not yet implemented. Supersedes #474 (curator-only runtime
construction); tracked in #480. **Decision:** adopt the Claude Agent SDK
(`claude-agent-sdk`) for the offline learning-loop agents, retiring the three
hand-rolled `claude -p` transports; keep PydanticAI for the in-process runtime.
The two engines read **one shared capability surface** — the same declarative
policy/config, applied through a thin per-engine binding. Builds on #471
(`curator_allowed_tools` / `curator_agent_env` / `RunnerOptions.env`) and mirrors
the runtime's own migration off `claude -p` to PydanticAI
(`docs/runtime-pydanticai-migration.md`, the `[runtime]` extra). Same "primitive
defined once, not N×" shape as the git seam (#460) and the namespace-root hoists
(#447/#448). **Billing gate verified:** Anthropic confirms the Agent SDK and
`claude -p` draw from the *same* subscription usage limits ([support article][bill],
June 2026); switching engines does not change the billing path.

## What this is

The reframe is the whole point: **the engines own the modeling.** The Agent SDK
(offline) and PydanticAI (runtime) own the subprocess/transport, the spawn
lifecycle, the agent loop, built-in tool execution, streaming, and result
handling. With the SDK adopted we stop writing a `claude -p` transport at all —
the select-loop + stdin-pump engine, the command assembly, and the marker-scraping
result extractors all become engine-owned.

What remains ours — and what #474 found scattered — is each agent's **capability
surface**: its **tools**, its **permission policy**, and its **hooks** (plus the
prompt / model / effort / cwd knobs that are already config). Today that surface is
specified **four** ways: three ad-hoc `--allowed-tools` strings on the `claude -p`
side and a fourth, richer in-process definition in the runtime (`tools.py` + the
`permission/` package + budget/observe `Hooks`).

This doc defines the target: **the capability surface is defined once as shared
declarative config + a shared enforcer, and each harness binds it to its engine.**
Two engines, one source of truth.

**Why commit to the SDK now — and why it doesn't foreclose consolidation.** The
offline agents' engine is chosen by workload profile, not convenience: they are
short single-shots (no per-loop compaction to justify owning the message list —
the runtime's whole reason for PydanticAI), they fan out heavily per case, and
the SDK bills the **subscription**. In-process PydanticAI would bill the
*metered* API — the "Phase C billing fan-out" risk that
`runtime-pydanticai-migration.md` raises against itself — so for these agents the
SDK is plausibly the *permanent* choice, not a stepping stone. This **revises
that doc's Phase C**, which floated moving actor/oracle/judge/author/verify
in-process to PydanticAI for the information-asymmetry prize: the shared enforcer
below delivers that same hard-boundary guarantee through the SDK's unbypassable
`PreToolUse` deny, without the metered fan-out. And if we ever consolidate
anyway, the cost is a re-validation pass (parity on the eval fixtures), **not** a
rewrite — *provided no SDK type escapes the adapter* (the port returns
engine-neutral values; `decide()` and `loop.py` never import `claude_agent_sdk`).
That seam hygiene is the same discipline that makes this migration correct, so
banking the reversibility costs nothing extra.

## Design

### The backbone: one policy/config file, one enforcer, two bindings

This is the load-bearing idea and the generalization of today's
`runtime/bash_policy.json` (the declarative deny-by-default allowlist the runtime
already loads):

- **One declarative policy file** — data only: per-role tool grants, per-tool path
  scopes, command-prefix rules, deny rules. The generalization of `bash_policy.json`.
- **One shared enforcer** — a single `decide(role, tool_name, tool_input) ->
  Decision(allow, reason)` that **routes** to the tool-specific gates that already
  exist in the `permission/` package (`decide_bash` / `decide_read` / `decide_write`,
  each returning `Decision`). The router is the new part; the three gates and their
  tests stay. It is **total and deny-by-default** — an unmapped tool returns `deny`,
  exactly the posture we want on the SDK side, where the tool surface is wide — and
  it returns a `Decision` rather than raising, so the *bindings* translate that into
  `ModelRetry` (runtime) or a hook `deny` (SDK).
- **Two thin bindings:**
  - **PydanticAI runtime** — the in-process gate raises `ModelRetry(reason)` on a
    deny (already does this).
  - **SDK offline** — a **`PreToolUse` hook** calls the *same* `decide`:

    ```python
    async def gate(input_data, tool_use_id, context):
        # binding normalizes the SDK's tool_input dict into decide()'s shared vocab
        d = permission.decide(role, input_data["tool_name"],
                              normalize(input_data["tool_input"]))
        if not d.allow:
            return {"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": d.reason,   # shown to the MODEL, so it won't retry
            }}
        return {}   # allow / pass through
    ```

    Registered as `hooks={"PreToolUse": [HookMatcher(hooks=[gate])]}`, with
    `permission_mode="dontAsk"` and `setting_sources=[]`.

Two disciplines keep the router an asset, not a new coupling:

- **Engine-neutral input vocabulary.** The SDK hook hands `tool_input` as a dict
  (`{"file_path": ...}`); PydanticAI hands typed args. Each *binding* normalizes its
  raw input into one shared vocabulary **before** calling `decide` — the router must
  not parse SDK-shaped dicts, or the SDK leaks into the enforcer (and the
  reversibility argued in §What this is breaks).
- **`role` is the load-bearing axis, not the dispatch.** Today `role` matters only to
  `decide_bash` (main vs gather adapter capability); `decide_read` / `decide_write`
  scope by `{run_dir, defender_dir}`. When the offline agents land, `role` becomes the
  *primary* key, because read-scope **is** the blinding invariant — actor gray-box,
  judge blind, `ground_truth.yaml` hard-denied (the `Workspace = {scope, policy, view}`
  model in `runtime-pydanticai-migration.md` §Phase C). That `role -> read-scope`
  table — not the routing — is the real design work, and it is what turns blinding from
  a soft discipline into a gate guarantee. Sequence it: land the router with
  **role-for-bash only** (exact parity with today), then add `role -> read-scope` when
  the **actor** is the first agent that forces its shape.

**Why a `PreToolUse` hook, not `can_use_tool` or `settings.json`** (grounded in the
[permissions][perm] + [hooks][hooks] docs): hooks are evaluated **first** and a hook
`deny` is **unbypassable** (it applies even in `bypassPermissions`), whereas
`can_use_tool` is *skipped for any auto-approved tool* — so scoping placed there is
silently bypassed. The hook receives `tool_input` (file_path, Bash command) so
path/command scoping works. And it needs **no setting-source**, so it does not drag
in the leakage below. `permission_mode="dontAsk"` makes anything not explicitly
allowed a hard deny (never a prompt → never a hang in a headless run).

Scope the sharing honestly: share the **mechanism + `decide()` vocabulary**, not the
runtime's specific policy *data* (the runtime gates the bash no-shell executor,
gather raw-access, invlang-on-write, and the `{run_dir, defender_dir}` allowlist —
all curator-irrelevant). Each agent/role supplies its own policy data over the one
enforcer. The same shape generalizes to **logging/observability**: one shared config
+ emitter, bound via PydanticAI's `Hooks` (`model_request` / `after_tool_execute`)
and the SDK's `PostToolUse` hook.

### Dividing principle: two engines, one capability vocabulary

Two engines, because the load-bearing policies are *opposite*: env/billing is
inverted (SDK → strip `ANTHROPIC_API_KEY`, bill subscription; PydanticAI → keep the
metered key) and loop control differs (autonomous SDK `query()` vs. `agent.iter` +
in-process `ModelRetry`). A forced common engine Protocol would leak. But **one
vocabulary for the part we define** — `(tools, permission policy, hooks, prompt,
model, cwd)` — bound two ways. The SDK does the modeling, so the only thing left to
define is the surface that was always ours.

### Harness A — the Agent SDK adapter behind the Subagents port

The SDK owns transport/loop/result. We implement `AgentSdkSubagents` (the second
adapter on the existing `core/subagents.py` port) and hand it `ClaudeAgentOptions`:

- **Tools** — the enabled tool names per agent (curator: `Read, Glob, Grep, Edit,
  Write, Bash`; the text-only verifier gate: none).
- **Permissions** — the shared `PreToolUse` gate above (`dontAsk`,
  `setting_sources=[]`). This is the single-source binding, not a per-caller string.
- **Hooks** — `PostToolUse` for the observability log (the `llm_requests.jsonl` /
  `tool_trace` analog) + budget/tagging where needed; the offline analog of the
  runtime's in-process `Hooks`.
- **System prompt** — the **custom-string** form (`system_prompt=<author prompt
  text>`), which sends *only* what you provide — matching today's
  `--system-prompt-file` full replacement. **Not** the `claude_code` preset or
  `append` (those inject the coding-assistant persona and change authoring behavior).
- **Result** — `output_format` json-schema → `ResultMessage.structured_output`,
  retiring the `AUTHOR_RESULT:` marker scrape and the verifier `GOOD`/`BAD` print.
- **Env (#4) + retry knobs** — `ClaudeAgentOptions.env` is the one chokepoint: strip
  `ANTHROPIC_API_KEY` (structural close of #4; subscription confirmed) and tune
  retries here (see below).
- **Timeout** — keep our own authoritative bounded deadline (the select-loop
  discipline) via `asyncio.timeout()` + verified child teardown on cancel; the SDK's
  stream idle watchdog (`CLAUDE_STREAM_IDLE_TIMEOUT_MS`) is defense-in-depth, not the
  sole guarantee (see below).

### Harness B — the PydanticAI runtime (the reference binding)

`runtime/driver.py` already binds this surface richly: `tools.py` (tools), the
`permission/` package + `bash_policy.json` (policy), budget/observe `Hooks`. It is
the **reference binding** of the shared vocabulary; the SDK side is the lighter
sibling. Keep the metered key. Light touch — name the construction (`build_driver`)
for symmetry — **not** a rebuild.

### Retries & lifecycle: a net upgrade, mapped to today's abort semantics

Grounded in the [Python reference][py]. Today's contract: any failure (timeout /
`rc != 0` / missing marker / bad JSON) → `RunnerError` → `AuthorError` → **batch
aborts, queue intact**. Map the SDK's outcomes onto it:

| SDK outcome | Meaning | Maps to |
|---|---|---|
| `ResultMessage.subtype == "success"`, `is_error == False` | clean finish | proceed to post-flight |
| `is_error == True` (even on `success`) | final model request failed | `RunnerError` → abort |
| `subtype == "error_during_execution"` | loop error | `RunnerError` → abort |
| `subtype == "error_max_turns"` | bound loop depth hit | `RunnerError` → abort (**partial edits may be in the tree**; the post-flight cross-check catches them) |
| `subtype == "error_max_structured_output_retries"` | model never matched the json-schema | `RunnerError` → abort (**new** failure mode) |
| `subtype == "error_max_budget_usd"` | budget cap hit | `RunnerError` → abort (**new**, if we set a USD cap) |
| `CLINotFoundError` / `ProcessError` / `CLIJSONDecodeError` | transport failure | `RunnerError` → abort |

- **Transient retries are internal and tunable** — the CLI already retries
  429/500/overloaded; `ClaudeAgentOptions.env` exposes `CLAUDE_CODE_MAX_RETRIES`
  (default 10, cap 15), `API_TIMEOUT_MS`, and a **stream idle watchdog**
  (`CLAUDE_STREAM_IDLE_TIMEOUT_MS`). That watchdog catches the same stalled-mid-stream
  child the select-loop's per-second check did — but we **keep the select-loop's
  deadline discipline, not cede it**: our `asyncio.timeout()` at the caller stays the
  authoritative deadline + kill, with the SDK watchdog as a second layer. What the SDK
  *does* subsume is the select-loop's manual **pipe** management (stderr drain, stdin
  pump, line buffering); the **deadline** guarantee we keep and own.
- **No new caller-side retry** — don't let adoption sneak in retry-on-error that
  would double-author. The drain re-runs next tick, as today.
- **Caveat:** *hooks may not fire when `max_turns` is hit* — critical finalization
  (the on-disk log flush, post-flight) must live in the caller after the stream ends,
  not in a `Stop`/`PostToolUse` hook.

### Async execution model: valuable, scoped to the fan-out stages

The SDK is `async` (`async for … in query()`); the loop is synchronous
(`subprocess.run`, `ThreadPoolExecutor`, `flock`). Adopt async **where the loop
already fans out** — the oracle per-lead (`ORACLE_MAX_CONCURRENCY`), the verify-forward
batch (`VERIFY_BATCH_WORKERS`), both directions — as `asyncio.gather` under an
`asyncio.Semaphore(N)` that **preserves the existing concurrency cap** (an unbounded
gather would blow rate limits). This is a genuine behavior upgrade, not sugar: an
`asyncio.timeout()` around the gather **cleanly cancels the whole fan-out and tears
down the SDK's child processes**, structurally fixing the "timeout must kill the
child / orphaned `claude` subprocess" edge case. Leave the **serial author drain**
(flock/repo-lock serialized) synchronous — async there is neutral; convert only the
fan-out call sites, and only after the transport swap lands.

### #4 / #5 under the SDK

- **#4 (billing)** closes at the `ClaudeAgentOptions.env` chokepoint (strip the key;
  subscription confirmed). `curator_agent_env` and `RunnerOptions.env` retire.
- **#5 (data-context) is unchanged by the pivot** — the SDK changes how *we* spawn the
  curator, not how the *curator* reaches its verifier. The forward-check verifier is a
  **grandchild** the curator spawns through its own Bash tool, so the state dir reaches
  it by inheritance today: `actor.py`'s `PENDING_FILE` derives from `DEFAULT_PATHS`,
  which honors the `DEFENDER_LEARNING_STATE_DIR` env var the curator pins via
  `curator_agent_env` (#425). That works — so #5 is not a live break, it is a
  cleanliness/testability choice. **How** we clean it is Open Q C: loop-run passes the
  state dir as a Python object (retiring `PENDING_FILE` + the env-pinning); the
  agent-shelled fallback adds an explicit `--state-root` arg instead.

## Edge cases / behavioral-equivalence checklist

This is "more of a refactor than a behavior change" *only if* these seams are held.
The ⚠️ two are the sharpest:

- ⚠️ **Permission enforcement must be a `PreToolUse` hook, not `can_use_tool`** —
  auto-approved tools skip `can_use_tool`, silently defeating corpus scoping. Hook
  deny is unbypassable.
- ⚠️ **Sync→async boundary** — every call site gains `asyncio.run`; the verify batch's
  `ThreadPoolExecutor` becomes `gather` + `Semaphore`. Biggest structural change.
- **`setting_sources=[]`** or the SDK loads `defender/CLAUDE.md`, `.claude/skills/`,
  and `.claude/settings.json` rules/hooks by default — changing context *and* merging
  in permission grants.
- **System prompt = custom string**, not the `claude_code` preset/append.
- **Restrict the tool surface** — the SDK default-exposes WebSearch/WebFetch/Agent/
  Monitor/AskUserQuestion/MCP; `allowed_tools` + `dontAsk` keep the curator to what it
  had (and AskUserQuestion can't hang under `dontAsk`).
- **Bash prefix-grant fidelity** — re-encode `Bash(rm defender/lessons/*.md)` /
  `Bash(<verifier> forward.py:*)` exactly in the `decide()` policy; over-deny blocks
  the verifier, under-deny allows arbitrary `rm`.
- **Observability log shape** — reconstruct `author_run.jsonl` from a `PostToolUse`
  hook / the message stream so the visualizer + `held_report` tooling keep working.
- **`ResultMessage` subtype mapping** — per the table above; especially `error_max_turns`
  → abort (partial edits), and `error_max_structured_output_retries` (new).
- **Timeout must kill the child** — our `asyncio.timeout` is the authoritative
  deadline (the select-loop discipline); *verify* the SDK tears down its child on
  cancel, don't assume it. Don't leak `claude` processes under the fan-out.
- **Effort mapping** — confirm the SDK expresses the pinned `--effort medium/low` 1:1.
- **Path normalization in the gate** — relative/absolute/symlink, worktree vs state
  dir (same class as #5).

## Kept / dropped

**Dropped (engine-owned now).** The three `claude -p` transports
(`author/runner.py`, `core/runner.py`, `verify_forward/shared.py`) and the idea of
consolidating them by hand; the select-loop + stdin-pump engine; `RunnerOptions` as
a transport spec; the `AUTHOR_RESULT:` / `GOOD`-`BAD` marker conventions; the
per-caller `--allowed-tools` strings.

**In scope.** The shared policy file + `decide()` enforcer + the two bindings (the
backbone); the `AgentSdkSubagents` adapter behind the port; the per-agent capability
surface (tools + `PreToolUse` gate + `PostToolUse` observability + structured
output + custom-string prompt); the env chokepoint (#4); loop-run for the
forward-check so the verifier takes the state dir as a Python object — retiring
`actor.py`'s `PENDING_FILE` + env-pinning, `--state-root` as the fallback (#5, Open Q
C); async fan-out with a semaphore at
the concurrent stages; `claude-agent-sdk` as an optional extra (mirroring
`[runtime]`, core stays `pyyaml`-only); naming `build_driver`; a `lint_raw_claude_spawn`
AST gate (now "no hand-rolled `claude -p` spawn — route through the adapter").

**Out of scope.** A forced common engine Protocol across the two harnesses;
migrating the runtime off PydanticAI to the SDK (the runtime deliberately chose
PydanticAI — metered key, typed outputs, in-process gates); the Agent-SDK →
Managed-Agents hosted path; async-ifying the serial author drain; the per-system
runtime gates and anything under "still out of scope" in `defender/CLAUDE.md`.

## Open questions

- **A — two engines permanently, or eventually one?** Lean: two by design (the
  runtime's PydanticAI choice was deliberate; the Agent SDK is its offline mirror),
  but the shared policy/enforcer keeps a future single-engine world cheap.
- **B — how much runtime policy data to share now?** Resolved in shape (share the
  `decide()` mechanism + policy file, keep per-role data separate); open only on
  sequencing — land the curator on the shared enforcer first, migrate the runtime's
  gate onto it as a fast-follow, not a prerequisite.
- **C — where does the forward-check run?** Three options: keep it agent-shelled (the
  curator's Bash tool spawns `forward.py` as a grandchild), move the verifiers to SDK
  calls, or have the **loop** run the forward-check directly. **Lean: loop-run.** It is
  the only option that lets the state dir travel as a **Python object** (the existing
  `LoopPaths` / a `Path`) instead of crossing a shell boundary — retiring the
  `--state-root` arg, the `DEFENDER_LEARNING_STATE_DIR` env-pinning, *and* `actor.py`'s
  module-level `PENDING_FILE` constant in one move, and making the verifier
  unit-testable with no env manipulation. It is also the cleaner separation of concerns:
  a regression gate belongs to the loop, not to the curator it gates — today the curator
  effectively grades its own homework by shelling the check that decides whether to keep
  its own edit. **Cost:** the keep/revert decision currently lives *inside* the
  curator's author transaction (the per-batch worktree + writer lease in `branch.py`);
  loop-run moves revert-on-`BAD` to the loop — a real reshape of the transaction
  envelope, not a free win. Fallback if that reshape is too entangled for one PR:
  agent-shelled + `--state-root` (the env var already works today, so it is an
  explicitness/testability upgrade, not a fix for breakage).
- **Billing forward-risk.** The paused June-15 Agent-SDK billing change is an equal
  risk to status-quo `claude -p` (same announcement), so not a differentiator — but
  track it. A 5-minute smoke test (unset the key → trivial `query()` → check
  `ResultMessage.usage`) confirms the subscription path before committing.
- **Rollout — two PRs (decided).** *PR 1 (seam + proof):* the shared policy file +
  `decide()` enforcer, the `AgentSdkSubagents` adapter behind the port, the curator
  migrated (the #480 slice), the env chokepoint (#4), the `PreToolUse` gate +
  `dontAsk` + `setting_sources=[]`, structured output, and the `asyncio.timeout`
  deadline — validating subscription billing + behavioral parity on one consumer.
  *PR 2 (generalize + lock):* migrate the pipeline stages + verifiers, the async
  fan-out with a semaphore, loop-run for the forward-check (state dir as a Python
  object; `--state-root` fallback) retiring `PENDING_FILE` + env-pinning (#5),
  and the `lint_raw_claude_spawn` gate. The runtime-gate migration onto the shared
  enforcer (B) rides PR 2 or a fast-follow.
- **Ops caveats to design for.** Transcript disk bloat (`~/.claude/projects`; set a
  `SessionStore` or cleanup); multi-day token expiry on long workers.

[bill]: https://support.claude.com/en/articles/15036540-use-the-claude-agent-sdk-with-your-claude-plan
[perm]: https://code.claude.com/docs/en/agent-sdk/permissions
[hooks]: https://code.claude.com/docs/en/agent-sdk/hooks
[py]: https://code.claude.com/docs/en/agent-sdk/python
