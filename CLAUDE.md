# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**Cyber Response Agent (v3)** — A hypothesis-driven security alert triage system. Reduces SOC analyst workload by investigating alerts through iterative hypothesis elimination, validating findings against precedents, and recommending disposition.

**Key Goal**: Zero false negatives (never auto-close real threats), high precision recommendations, mean time to resolution of 1-3 minutes.

**Approach**: Claude Code plugin with a hypothesis-driven investigation loop. The agent forms hypotheses, gathers evidence from whatever SIEM/query tools are available via MCP, eliminates candidates with structured assessments, and stops when confident. Hooks enforce structural safety. MVP is `recommend`-only. The plugin is **vendor-neutral** — it works with any SIEM that exposes tools via MCP. Wazuh signatures are included as working examples.

## Architecture

### Investigation Loop

The common case is **single-iteration**: CONTEXTUALIZE → [SCREEN] → PREDICT → GATHER → ANALYZE → REPORT. Looping back from ANALYZE into PREDICT is the exception (more evidence required), not the default. ASSESS is a PREDICT-internal gate, not a separate phase: PREDICT first checks whether the next move actually branches on a competing explanation; if not, it scaffolds a single mechanism + legitimacy contracts and proceeds to GATHER.

```
/investigate $signature_id $alert_json
        │
        ├── !command: resolve_imports.py bakes signature knowledge into prompt
        │   (context.md + playbook.md + checklist.md + @import: atoms)
        ├── !command: setup_run.py creates run dir + alert.json
        ├── !command: workspace_map.py emits on-disk orientation
        └── CONTEXTUALIZE → [SCREEN] ──────────────────────────────┐
                │                                                   │
                ▼                                                   │
             PREDICT  ◀─────────────────────┐                       │
                │   (assess → scaffold)     │                       │
                ▼                           │                       │
             GATHER  ────────────────────── │                       │
                │                           │                       │
                ▼                           │                       │
             ANALYZE ──── need more ────────┘                       │
                │                                                   │
                ▼                                                   │
             REPORT  ◀───────────────────────────────────────────── ┘
                │
                ▼
            report.md
```

The optional SCREEN phase spawns a cheap subagent that attempts fast pattern matching against playbook-defined screen patterns; if matched, the full loop is skipped and evidence flows straight to REPORT. Most phase-level reasoning now runs in dedicated plugin subagents (see below); the main investigate skill orchestrates.

### Core Components

| Component | Path | Purpose |
|-----------|------|---------|
| **Investigate Skill** | `soc-agent/skills/investigate/SKILL.md` | Entry point + investigation loop orchestration |
| **Author Skill** | `soc-agent/skills/author/SKILL.md` | Edits `knowledge/` + `config/signatures/` with validator + probe-evidence gates |
| **Connect Skill** | `soc-agent/skills/connect/SKILL.md` | Onboards a new SIEM/EDR/identity/CMDB system — generates adapter CLI + environment knowledge |
| **Handbook Skill** | `soc-agent/skills/handbook/SKILL.md` | On-demand plugin reference docs (architecture, loop, validation, retention) |
| **Screen Subagent** | `soc-agent/agents/screen.md` | Fast pattern matching (SCREEN phase) |
| **Contextualize-prologue Subagent** | `soc-agent/agents/contextualize-prologue.md` | CONTEXTUALIZE prologue authoring (vertices + edges from alert) |
| **Archetype-match Subagent** | `soc-agent/agents/archetype-match.md` | REPORT-time archetype routing (match confirmed picture against archetype catalog) |
| **Ticket-context Subagent** | `soc-agent/agents/ticket-context.md` | CONTEXTUALIZE 4-hour correlation (backed by `scripts/tools/ticket_context.py`) |
| **Predict Subagent** | `soc-agent/agents/predict.md` | Mechanism scaffolding + legitimacy contracts + falsifiable predictions |
| **Gather Subagent** | `soc-agent/agents/gather.md` | Single-lead execution |
| **Gather-composite Subagent** | `soc-agent/agents/gather-composite.md` | Multi-lead composite dispatch |
| **Analyze Subagent** | `soc-agent/agents/analyze.md` | Extraction-contract evidence analysis with shape verification |
| **Report Subagent** | `soc-agent/agents/report.md` | Mechanical-compose handler entry point for REPORT |
| **Report-narrative Subagent** | `soc-agent/agents/report_narrative.md` | Haiku-backed report narrative authoring |
| **Import Resolver** | `soc-agent/scripts/resolve_imports.py` | `!command` preprocessing: bakes signature knowledge into the prompt |
| **Run Setup** | `soc-agent/scripts/setup_run.py` | Creates run dir + alert.json, maps session → run |
| **Preflight** | `soc-agent/scripts/preflight.py` | Binary connectivity check across configured systems |
| **Workspace Map** | `soc-agent/scripts/workspace_map.py` | On-disk orientation emitted into the skill prompt |
| **Invlang CLI** | `soc-agent/scripts/invlang/` | Corpus query tool (invoked via `scripts/invlang/run.sh`) |

### Hook Architecture

All hooks live under `soc-agent/hooks/scripts/` and are registered in `soc-agent/.claude-plugin/plugin.json`. They only fire when the plugin is loaded.

| Event | Matcher | Hook | Purpose |
|-------|---------|------|---------|
| PreToolUse | `Task\|Agent` | `inject_env_context.py` | Inject environment context into subagent prompts |
| PreToolUse | `Write\|Edit` on `*/investigation.md` | `infer_state_pre.py` | Pre-write state transition check |
| PreToolUse | `Write\|Edit` on `*/investigation.md` | `validate_report_precheck.py` | Pre-REPORT self-contradiction guards (parallel Haiku judges) |
| PreToolUse | `Write\|Edit` on `*/investigation.md` | `invlang_validate.py` | Pre-write schema validation (35 rules) — blocks writes on schema errors |
| PostToolUse | `Task\|Agent` | `extract_subagent_yaml.py` | Extract subagent YAML output into the investigation record |
| PostToolUse | `Write\|Edit\|Bash` | `infer_state.py` | Infer state transitions from `## PHASE` headers |
| PostToolUse | `Write\|Edit` | `validate_report.py` | Two-tier report validation (Tier 1 structural + Tier 2 Haiku judge) |
| PostToolUse | `Bash\|mcp__.*` / `Read(*/alert.json)` | `tag_tool_results.py` | Tag tool results with salted delimiters for injection safety |
| PostToolUse | `*` | `audit_tool_calls.py` | Split audit (state-changing) + trace (read-only) JSONL logs |
| PostToolUse | `*` | `budget_enforcer.py` | Enforce per-run budget caps |
| Stop | `*` | `stop_handler.py` | Sequential entrypoint — calls `investigation_summary.py` then `close_ticket_action.py` |

Shared helpers: `run_context.py` (session→run resolution), `permissions.py` (permissions.yaml loader), `frontmatter.py`, `investigation_parse.py`, `invlang_walkers.py`, `judge_runner.py`, `judge_prompt.md`, `report_judge_{A,B}_prompt.md`.

### Safety Architecture

- **Two-tier report validation** — `validate_report.py` (PostToolUse Write|Edit) fires when `report.md` is written. Tier 1 enforces structural constraints deterministically. Tier 2 calls Haiku via the claude CLI to validate report consistency, precedent match validity, and evidence sufficiency (full mode = 5 checks for resolved-with-precedent; no-precedent mode = 4 checks for escalated). Untrusted content is wrapped in per-run salted delimiters to block prompt injection.
- **Invlang schema validation** — `invlang_validate.py` (PreToolUse) blocks any write/edit to `investigation.md` that violates the 35 validator rules (see `docs/investigation-language.md`).
- **Pre-REPORT judges** — `validate_report_precheck.py` runs parallel Haiku judges (prompts A/B) on the proposed `## REPORT` write to catch self-contradictions before the report-time invlang block lands.
- **State machine** (`infer_state.py` PostToolUse + `infer_state_pre.py` PreToolUse) prevents phase skipping — inferred from `## PHASE` headers in `investigation.md`; agent must follow CONTEXTUALIZE→[SCREEN]→(PREDICT↔GATHER↔ANALYZE loop)→REPORT.
- **Two-leg resolution requirement** — `status=resolved` requires `matched_archetype` naming an archetype directory AND grounding: every `required_anchors` entry confirmed OR `matched_ticket_id` citing a valid precedent snapshot inside that archetype directory. Archetypes with no required anchors must be grounded by `matched_ticket_id`.
- **Legitimacy as edge attribute (invlang v2.8)** — hypotheses whose disposition depends on authorization declare a `legitimacy_contract`; resolving leads write `legitimacy_resolutions` on the edge. `disposition: benign` is structurally gated on every contract resolving `authorized` (validator rule #21); `unauthorized`/`indeterminate` force escalation. Mechanism-level adversarial variants (`?adversary-controlled-*`) remain separate hypotheses — classification carries the claim.
- **Budget enforcement** — `budget_enforcer.py` caps per-run tool calls / cost per `schemas/budget.py`.

## Project Structure

```
/workspace/
├── soc-agent/                     # Claude Code plugin (all shippable agent content)
│   ├── .claude-plugin/
│   │   └── plugin.json            # Plugin manifest (hooks + skills + agents registration)
│   ├── agents/                    # Plugin-registered subagents (phase-level workers)
│   │   ├── screen.md              # Fast pattern matching (SCREEN phase)
│   │   ├── contextualize-prologue.md  # Prologue authoring (CONTEXTUALIZE)
│   │   ├── archetype-match.md     # REPORT-time archetype routing
│   │   ├── ticket-context.md      # 4-hour ticket correlation (CONTEXTUALIZE)
│   │   ├── predict.md             # Mechanism scaffold + legitimacy contracts (PREDICT)
│   │   ├── gather.md              # Single-lead GATHER
│   │   ├── gather-composite.md    # Composite-lead GATHER dispatch
│   │   ├── analyze.md             # Extraction-contract ANALYZE
│   │   ├── report.md              # REPORT mechanical-compose entry point
│   │   └── report_narrative.md    # Haiku-backed REPORT narrative
│   ├── skills/
│   │   ├── investigate/           # Main loop orchestrator + past-investigations query
│   │   ├── author/                # Edit knowledge/ + config/signatures/ with validator + probes
│   │   ├── connect/               # Onboard a new security system (adapter CLI + env knowledge)
│   │   └── handbook/              # On-demand plugin reference docs
│   │       └── content/           # act-mode, design, investigation-loop, invlang, knowledge-base,
│   │                              #   phases, retention, run-artifacts, validation
│   ├── scripts/
│   │   ├── resolve_imports.py     # !command resolver: signature knowledge → stdout
│   │   ├── setup_run.py           # Create run dir + alert.json; map session → run
│   │   ├── fetch_alert.py         # Retrieve alerts by id for replay
│   │   ├── preflight.py           # Per-system connectivity health check
│   │   ├── workspace_map.py       # On-disk orientation for investigate prompt
│   │   ├── query.py               # Wrapper over system CLIs for ad-hoc querying
│   │   ├── cleanup_runs.py        # Retention / cleanup for runs/
│   │   ├── init.sh                # One-shot dev bootstrap
│   │   ├── invlang/               # Companion-query CLI (invoked via run.sh)
│   │   │   ├── cli.py
│   │   │   ├── corpus.py
│   │   │   ├── queries.py
│   │   │   └── run.sh
│   │   └── tools/                 # Per-system CLI adapters + utilities
│   │       ├── wazuh_cli.py
│   │       ├── host_query.py
│   │       ├── stub_ticket_cli.py         # Reference ActionContract ticketing adapter
│   │       ├── playground_ticket_cli.py   # FastAPI mock ticketing client
│   │       ├── ticket_context.py          # Backend for the ticket-context subagent
│   │       ├── data_source_health.py      # Abstract health-check helper
│   │       ├── data_source_health_wazuh.py
│   │       └── list_lead_tags.py
│   ├── hooks/
│   │   └── scripts/               # See "Hook Architecture" above
│   ├── knowledge/
│   │   ├── common-investigation/  # Portable investigation methodology
│   │   │   ├── SKILL.md
│   │   │   ├── checklist.md
│   │   │   └── leads/             # Reusable lead defs + per-vendor query templates
│   │   ├── invlang/
│   │   │   └── schema.md          # Schema loaded into the investigate prompt
│   │   ├── environment/           # Org-specific deployment knowledge (see design-v3-tool-execution.md §10)
│   │   │   ├── context/           # Classification heuristics (IP ranges, identity patterns, etc.)
│   │   │   ├── data-sources/      # Abstract data-tag reference docs
│   │   │   ├── operations/        # Per-anchor grounding recipes
│   │   │   └── systems/           # Vendor-specific field knowledge
│   │   │       ├── wazuh/         # Wazuh field quirks, auth queries, config.env
│   │   │       ├── host-query/
│   │   │       ├── stub-ticket/
│   │   │       └── playground-ticket/
│   │   └── signatures/
│   │       ├── _template/         # Skeleton + onboarding guide for new signatures
│   │       ├── wazuh-rule-550/    # Example: file integrity
│   │       ├── wazuh-rule-5710/   # Example: SSH invalid user
│   │       ├── wazuh-rule-100001/ # Example: reference for lean one-hop playbook layering
│   │       └── wazuh-rule-100110/ # Example
│   ├── schemas/                   # Python dataclass validators (system contracts)
│   │   ├── report_frontmatter.py
│   │   ├── state.py
│   │   ├── precedent.py
│   │   ├── adapter_contract.py    # Generic ABC base for system adapters
│   │   ├── budget.py              # Budget enforcement config
│   │   ├── retention.py           # Run retention policy
│   │   └── enums.py
│   ├── config/
│   │   └── signatures/
│   │       ├── _template/permissions.yaml
│   │       ├── wazuh-rule-550/permissions.yaml
│   │       ├── wazuh-rule-5710/permissions.yaml
│   │       ├── wazuh-rule-100001/permissions.yaml
│   │       └── wazuh-rule-100110/permissions.yaml
│   ├── tests/                     # pytest test suite (see "Running Tests" below)
│   └── runs/                      # Investigation run dirs (configurable via SOC_AGENT_RUNS_DIR)
│
├── .claude/
│   ├── settings.json              # (project-local, currently empty)
│   ├── settings.local.json        # Dev permissions
│   └── skills/                    # Personal dev skills (not shipped): analyze-pilot, invlang, ship, testrun
│
├── docs/                          # Design documentation
├── playground/                    # Docker / Wazuh stack / ticket-server for dev + eval
├── tasks/                         # Kanban task files (one .md per task, frontmatter-driven)
│   └── build.py                   # Renders board.html from tasks/*.md
├── board.html                     # Generated kanban board — open in browser, no server
└── .devcontainer/                 # Docker environment
```

## Task Tracking

Open work lives in `tasks/` — one markdown file per task with `title`, `status` (`backlog` / `todo` / `doing` / `done`), and `groups` (comma-separated tags) frontmatter. Body is free-form context. Run `python3 tasks/build.py` to regenerate `board.html`. A task may carry multiple group tags; each renders as its own badge. This replaced the legacy `todo.md` — open issues (state-machine bypass mitigation, validation-hook promotion, SCREEN cost-reduction workstream, Sonnet-migration stages, etc.) all live as task files now.

## Python Environment

All deps are declared as extras in `soc-agent/pyproject.toml` and installed into a single venv at `soc-agent/.venv`. Run `cd soc-agent && uv sync --extra dev` to create or update it; invoke scripts and tests via `soc-agent/.venv/bin/python3` (or activate with `source soc-agent/.venv/bin/activate`).

## Running Tests

```bash
# All unit tests (no LLM required, ~25s — subprocess-heavy state tests)
pytest soc-agent/tests/ -v -m "not llm"

# Common suites
pytest soc-agent/tests/test_validate_report.py -v          # Report validation (Tier 1+2)
pytest soc-agent/tests/test_validate_report_precheck.py -v # Pre-REPORT self-contradiction guards
pytest soc-agent/tests/test_invlang_validate.py -v    # Invlang schema rules
pytest soc-agent/tests/test_invlang_queries.py -v     # Invlang corpus queries
pytest soc-agent/tests/test_state_transitions.py -v   # State machine
pytest soc-agent/tests/test_infer_state.py -v         # State inference
pytest soc-agent/tests/test_kb_schema.py -v           # Knowledge base schema
pytest soc-agent/tests/test_archetype_fixtures.py -v  # Archetype precedent snapshots
pytest soc-agent/tests/test_resolve_imports.py -v     # Import resolver
pytest soc-agent/tests/test_setup_run.py -v           # Run setup
pytest soc-agent/tests/test_audit_hooks.py -v         # Audit hooks
pytest soc-agent/tests/test_budget_enforcer.py -v     # Budget enforcement
pytest soc-agent/tests/test_tag_tool_results.py -v    # Salted-delimiter tagging
pytest soc-agent/tests/test_stop_handler.py -v        # Stop-stage composition
pytest soc-agent/tests/test_close_ticket_action.py -v # Act-mode close dispatch
pytest soc-agent/tests/test_adapter_contract.py -v    # Generic adapter ABC
pytest soc-agent/tests/test_wazuh_cli.py -v           # Wazuh adapter
pytest soc-agent/tests/test_host_query.py -v          # Host adapter
pytest soc-agent/tests/test_ticket_context.py -v      # Ticket-context backend
pytest soc-agent/tests/test_preflight.py -v           # Preflight connectivity

# Integration tests (require LLM)
pytest soc-agent/tests/test_e2e_mock.py -m llm              # Mock SIEM
pytest soc-agent/tests/test_e2e_live.py -m "llm and live"   # Live Wazuh
pytest soc-agent/tests/test_judge_report.py -m llm          # Tier 2 judge
```

## Investigation Flow Language

**Full spec:** `docs/investigation-language.md` (v2.13, implemented). Query CLI: invoke via `bash soc-agent/scripts/invlang/run.sh` (see the canonical invocation note — `python -m invlang` and direct `cli.py` calls fail). Schema loaded into the investigate prompt lives at `soc-agent/knowledge/invlang/schema.md`. Validator runs as a PreToolUse hook on `investigation.md` writes (`hooks/scripts/invlang_validate.py`).

### Purpose

The investigation language is a structured YAML schema for recording security investigations as **graph traversals**. Each investigation produces a companion document — a machine-readable + human-readable audit trail of every hypothesis, lead, observation, and weight update from alert to disposition. Companions are designed to be corpus-queryable: which hypothesis patterns recur, which leads are most discriminating, where investigations stall.

### Philosophy

An investigation maintains two layers: a **confirmed graph** (vertices/edges backed by SIEM events, runtime audit, or authoritative sources — append-only, never mutated) and a **proposed frontier** (one candidate upstream extension per active hypothesis). Leads collapse the frontier: each lead is an edge measurement that either materializes proposed elements into the confirmed graph or refutes them.

Investigations traverse **backward** — from the observed alert toward upstream causes — halting when the frontier is empty or a **trust root** is reached (a vertex with no accessible upstream). The agent is not allowed to pre-commit to deep causal narratives; hypotheses are lean (1–2 predictions, the minimum that discriminates between competing explanations), deepened only when evidence forces it.

Inline vocabulary used in `investigation.md`:
- **Hypotheses** prefixed with `?` — e.g., `?monitoring-probe`, `?brute-force`
- **Leads** — evidence-gathering actions that discriminate between hypotheses
- **Assessments** — `++` (strongly supports), `+` (weakly supports), `-` (weakly refutes), `--` (strongly refutes)
- **Trace** — compressed investigation path: `lead1(result)→lead2(result)→disposition:hypothesis`

### Companion structure (top-level)

```yaml
prologue:       # CONTEXTUALIZE: vertices + edges derived from the alert
  vertices: []
  edges: []

hypothesize:    # PREDICT: initial proposed frontier (omit for SCREEN-matched cases). Block name preserved for corpus backward-compat.
  hypotheses: []

findings:       # GATHER + ANALYZE: ordered lead blocks (same id merges across phases)
  - lead: {...}

conclude:       # REPORT: termination category, disposition, confidence, matched_archetype. Block name preserved for corpus backward-compat.
  termination:
    category: trust-root | adversarial-refuted | severity-ceiling | exhaustion-escalation
  disposition: benign | true_positive | unclear
  confidence: high | medium | low
  matched_archetype: <name> | null
```

The key invariants enforced by the validator (35 rules in total — see spec §Validator rules; rule #23 enforces sibling-hypothesis classification uniqueness so proposed forks are structurally distinct):
- **Edge authority** — `++`/`--` resolutions must cite at least one `siem-event`, `runtime-audit`, or `authoritative-source` edge.
- **Append-only** — no existing record is ever mutated; decomposition adds sub-vertices, attribution adds `identified_as` links.
- **Mechanical leads stay within their data source** — a lead's observations contain only entities the queried system directly names by native identity.

## Key Design Patterns

### Hypothesis-Driven Investigation
- Agent forms candidate explanations, makes predictions, gathers evidence
- Legitimacy-gated disposition — `disposition: benign` requires every `legitimacy_contract` on a live-weight hypothesis to resolve `authorized`; mechanism-level adversarial variants (`?adversary-controlled-*`) still require `--` refutation
- Structured assessments (++/+/-/--) replace subjective confidence

### Hook-Enforced Safety
- Python hooks validate report structure (no LLM judgment in safety checks)
- State machine prevents phase skipping
- Precedent match required for non-escalation resolution

### Conservative by Default
- When uncertain, escalate to human
- MVP is recommend-only (no auto-close actions)
- Missing data or errors → escalate with context

### Auditability
- Every investigation creates: `alert.json`, `investigation.md` (invlang companion), `state.json`, `report.md`
- JSONL investigation outcomes in `runs/audit.jsonl`
- JSONL tool call audit trail in `runs/tool_audit.jsonl` (state-changing tools)
- JSONL tool call trace in `runs/tool_trace.jsonl` (read-only tools, for debugging)
- Subagent YAML extracted into the companion via `extract_subagent_yaml.py` PostToolUse hook
- Session → run dir mapping is stable under concurrent runs (use `run_context.resolve_run_dir`, not mtime fallback)

## Adding a New Signature

See `soc-agent/knowledge/signatures/_template/README.md` for the full onboarding workflow. Summary:

1. Copy template: `cp -r soc-agent/knowledge/signatures/_template soc-agent/knowledge/signatures/{signature-id}`
2. Remove `README.md` from the copy
3. Research past tickets for this signature — pull alerts, review closed tickets, identify outcome clusters
4. Fill in `context.md` — signature logic, threat model, known false positives (grounded in real data)
5. Fill in `playbook.md` — archetype catalog, leads with predictions, optional screen table (from actual investigation patterns)
   - Optionally use `@import:name` inline to reference common lessons from `knowledge/common-investigation/lessons/`
   - The resolver (`scripts/resolve_imports.py`) loads referenced atoms automatically at skill load time
6. Create one archetype subdirectory per outcome cluster under `archetypes/{archetype-name}/` — each with a `README.md` (story + `required_anchors`) and zero or more `{TICKET-ID}.json` precedent snapshots
7. Create `soc-agent/config/signatures/{signature-id}/permissions.yaml`

## Docker Environment

Multi-container stack (`.devcontainer/docker-compose.yml`):

| Service | Purpose |
|---------|---------|
| **devcontainer** | Development environment with Docker socket access |
| **target-endpoint** | Ubuntu container generating workload activity |
| **falco** | eBPF syscall monitoring |
| **wazuh-mcp-server** | MCP interface to Wazuh API |
| **wazuh.manager** | SIEM alert correlation |
| **wazuh.indexer** | Elasticsearch for events |
| **wazuh.dashboard** | Web UI |
| **ticket-server** | Stateful FastAPI mock ticketing API (playground only) |

### Managing Containers

Always go through Compose. Never bare `docker run/start/stop/rm` on a Compose-managed container, and never invoke compose with a partial `-f` set — that splits the stack into parallel projects and collides on names like `target-endpoint`, requiring manual cleanup.

The canonical entry point is `playground/scripts/compose.sh`, which works identically from the host shell and from inside the devcontainer:

```bash
playground/scripts/compose.sh up -d --build target-endpoint
playground/scripts/compose.sh ps
playground/scripts/compose.sh logs -f wazuh-manager
playground/scripts/compose.sh down
```

The wrapper handles two pieces of plumbing that are otherwise easy to get wrong:
1. **Project name** (`cyber-response-agent_devcontainer`) — set via `name:` at the top of `docker-compose.yml`, picked up automatically
2. **File list** — set via `COMPOSE_FILE=docker-compose.yml:wazuh-stack.yml:wazuh-overrides.yml` in `.devcontainer/.env`
3. **Path translation when running from inside the devcontainer** — the docker daemon runs on the host and only speaks host paths, so compose needs `--project-directory` pointing at the host-style `.devcontainer/` for bind mount sources to resolve correctly. The wrapper sets this from `HOST_WORKSPACE` in `.devcontainer/.env`.

`.devcontainer/.env` must be created from `.devcontainer/.env.example` and have `HOST_WORKSPACE` filled in per machine. From a fresh checkout:
```bash
cp .devcontainer/.env.example .devcontainer/.env
# edit .devcontainer/.env, set HOST_WORKSPACE to the host path that maps to /workspace
```

**Persistent agent state.** The target-endpoint Wazuh agent state (`client.keys`, FIM database, anti-replay counters) persists across container recreates via the `target-endpoint-state` named volume. Combined with the `<force>` block in the manager's `<auth>` config (`playground/config/wazuh_cluster/wazuh_manager.conf`), this means container recreate / rebuild "just works" — no manual deregistration needed. To force a fresh enrollment, `docker volume rm cyber-response-agent_devcontainer_target-endpoint-state`.

## Credentials (Development Only)

Credentials are stored in `.env` (git-ignored). See `.env` for Wazuh API, indexer, and dashboard passwords. The `.env` file is loaded by docker-compose services and should be sourced or exported for CLI usage.

## Fail Fast — No Guessing

When a required value is missing, unknown, or ambiguous — **fail immediately with a clear error**. Never silently substitute a default, placeholder, or made-up value. This applies everywhere: scripts, hooks, skill arguments, tool parameters, queries, and field mappings.

- If a required argument is not provided, stop and ask or error out.
- If a field name, index, or API path is uncertain, surface the uncertainty — don't guess.
- If a SIEM query field might not exist, say so rather than fabricating a plausible name.
- Prefer a loud failure the user can diagnose over a silent wrong answer they can't.

## Known Issues

- Wazuh API not accessible from localhost (use `wazuh-manager:55000` from within Docker network)
- Falco generates alerts for healthcheck operations (expected behavior)
- `act` mode implemented for `close_ticket` only; additional action verbs (`block_ip`, `disable_user`, `isolate_host`) not yet supported. Graduation is per-signature via `permissions.yaml`; see `soc-agent/skills/handbook/content/act-mode.md`.

## Documentation

Detailed documentation in `docs/`:
- `design-v3-overview.md` — System overview and design goals
- `design-v3-architecture.md` — System architecture and component design
- `design-v3-tool-execution.md` — Tool execution architecture: lead model, SIEM CLI, query templates, composite dispatch
- `design-v3-hypothesis-archetype-rewrite.md` — Hypothesis-driven investigation and archetype model
- `design-v3-authority-consultation.md` — Authority consultation primitive and legitimacy-gated disposition
- `design-v3-reproduction.md` — Reproduction sandbox design
- `design-v3-init-and-connect.md` — Initialization and SIEM connection
- `design-v3-post-mortem.md` — Post-v3 retrospective notes
- `investigation-language.md` — Invlang spec (v2.12) + validator rules
- `evaluation-and-chaos-design.md` — Evaluation harness and chaos engineering
- `security-model.md` — Threat model and defense layers
- `packaging.md` — Dependency and packaging strategy
- `playground-elastic-stack.md` — Elastic stack companion to the Wazuh playground
- `decision-opus-sonnet-migration.md` — Model selection rationale

Pre-v3 docs are in `docs/archive/`.
