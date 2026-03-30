# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**Cyber Response Agent (v3)** — A hypothesis-driven security alert triage system. Reduces SOC analyst workload by investigating alerts through iterative hypothesis elimination, validating findings against precedents, and recommending disposition.

**Key Goal**: Zero false negatives (never auto-close real threats), high precision recommendations, mean time to resolution of 1-3 minutes.

**Approach**: Claude Code plugin with a hypothesis-driven investigation loop. The agent forms hypotheses, gathers evidence from whatever SIEM/query tools are available via MCP, eliminates candidates with structured assessments, and stops when confident. Hooks enforce structural safety. MVP is `recommend`-only. The plugin is **vendor-neutral** — it works with any SIEM that exposes tools via MCP. Wazuh signatures are included as working examples.

## Architecture

### Investigation Loop

```
/investigate $signature_id $alert_json
        │
        ├── !command: resolve_imports.py bakes knowledge into prompt
        │   (context.md + playbook.md + checklist.md + @import: atoms)
        │
        └── CONTEXTUALIZE → [SCREEN] → HYPOTHESIZE → GATHER → ANALYZE
                                 │           ↑                    │
                                 │           └────── loop ────────┘
                                 │                                │
                                 └──────────────────────┬─────────┘
                                                        │
                                                   CONCLUDE → report.md
```

The optional SCREEN phase spawns a cheap subagent (Sonnet/Haiku) that attempts fast pattern matching against playbook-defined screen patterns. If matched, skips the full loop. If not, passes gathered evidence into the full investigation.

### Core Components

| Component | Path | Purpose |
|-----------|------|---------|
| **Investigate Skill** | `soc-agent/skills/investigate/SKILL.md` | Entry point + investigation loop (merged skill) |
| **Screen Prompt** | `soc-agent/skills/investigate/screen.md` | Subagent prompt for fast pattern matching (SCREEN phase) |
| **Import Resolver** | `soc-agent/scripts/resolve_imports.py` | `!command` preprocessing: resolves signature knowledge |
| **Validate Report Hook** | `soc-agent/hooks/scripts/validate_report.py` | PostToolUse hook (Write\|Edit): combined Tier 1 + Tier 2 validation |
| **Judge Prompt** | `soc-agent/hooks/scripts/judge_prompt.md` | Prompt template for Tier 2 judge (5 criteria, two modes) |
| **Write State Script** | `soc-agent/hooks/scripts/write_state.py` | State machine enforcement |
| **Investigation Summary Hook** | `soc-agent/hooks/scripts/investigation_summary.py` | JSONL outcome log per completed investigation |
| **Tool Call Audit Hook** | `soc-agent/hooks/scripts/audit_tool_calls.py` | PostToolUse: audit + trace JSONL split |

### Safety Architecture

- **Two-tier validation** — `validate_report.py` is a PostToolUse hook (Write|Edit) that fires when report.md is written. Tier 1 enforces structural constraints deterministically. Tier 2 uses Haiku via claude CLI to validate report consistency, precedent match validity, and evidence sufficiency. Runs in full mode (5 checks) for resolved reports with precedent, or no-precedent mode (4 checks) for escalated reports. Untrusted content (alert data, investigation log) is wrapped in per-run salted delimiters to prevent prompt injection.
- **Hooks registered in plugin.json** — hooks only fire when the plugin is loaded, not during development
- **State machine** (`write_state.py`) prevents phase skipping — agent must follow CONTEXTUALIZE→[SCREEN]→HYPOTHESIZE→GATHER→ANALYZE→(loop|CONCLUDE)
- **Precedent requirement** — `status=resolved` requires `matched_precedent` pointing to an existing file
- **Adversarial hypothesis** — agent must maintain at least one threat hypothesis until explicitly refuted

## Project Structure

```
/workspace/
├── soc-agent/                     # Claude Code plugin (all agent content)
│   ├── .claude-plugin/
│   │   └── plugin.json            # Plugin manifest
│   ├── skills/
│   │   └── investigate/
│   │       ├── SKILL.md           # Merged investigation skill (entry point + loop)
│   │       └── screen.md          # Subagent prompt for SCREEN fast pattern matching
│   ├── scripts/
│   │   └── resolve_imports.py     # !command resolver: signature knowledge → stdout
│   ├── hooks/
│   │   └── scripts/
│   │       ├── validate_report.py      # PostToolUse hook: combined Tier 1 + Tier 2 validation
│   │       ├── judge_prompt.md         # Prompt template for Tier 2 judge
│   │       ├── write_state.py          # State machine enforcement
│   │       ├── investigation_summary.py # Stop hook: JSONL outcome log
│   │       └── audit_tool_calls.py     # PostToolUse: audit + trace JSONL split
│   ├── knowledge/
│   │   ├── common/                # Portable investigation methodology
│   │   │   ├── SKILL.md           # Common investigation knowledge
│   │   │   ├── checklist.md       # Investigation self-check guide
│   │   │   ├── leads/             # Reusable lead definitions (methodology)
│   │   │   └── lessons/           # Cross-cutting investigation lessons
│   │   ├── environment/           # Org-specific deployment knowledge
│   │   │   ├── context/           # Classification heuristics (IP ranges, identity patterns, etc.)
│   │   │   ├── data-sources/      # Data mapping: what data exists where (state + events)
│   │   │   └── systems/           # System-specific implementation knowledge (queries, quirks)
│   │   │       └── wazuh/         # Wazuh SIEM query patterns and field mappings
│   │   └── signatures/
│   │       ├── _template/         # Skeleton + onboarding guide for new signatures
│   │       └── wazuh-rule-5710/   # SSH Invalid User (example signature)
│   │           ├── context.md     # Signature reference + threat model
│   │           ├── playbook.md    # Hypothesis catalog + leads
│   │           └── precedents/    # Past resolved investigations
│   ├── schemas/                   # Python dataclass validators (system contracts)
│   │   ├── report_frontmatter.py
│   │   ├── state.py
│   │   └── precedent.py
│   ├── config/
│   │   └── signatures/
│   │       ├── _template/
│   │       │   └── permissions.yaml  # Template for new signatures
│   │       └── wazuh-rule-5710/
│   │           └── permissions.yaml
│   ├── tests/                     # pytest test suite
│   │   ├── test_validate_report.py
│   │   ├── test_state_transitions.py
│   │   ├── test_kb_schema.py
│   │   ├── test_resolve_imports.py
│   │   ├── test_audit_hooks.py
│   │   ├── test_e2e_mock.py
│   │   ├── test_e2e_live.py
│   │   └── fixtures/
│   └── runs/                      # Investigation run dirs (configurable via SOC_AGENT_RUNS_DIR)
│
├── .claude/
│   ├── settings.json              # Hook registration (Stop event)
│   └── settings.local.json        # Dev permissions
│
├── docs/                          # Design documentation
├── playground/                    # Container setup for testing
└── .devcontainer/                 # Docker environment
```

## Running Tests

```bash
# All unit tests (no LLM required)
pytest soc-agent/tests/ -v

# Specific test suites
pytest soc-agent/tests/test_validate_report.py -v    # Report validation
pytest soc-agent/tests/test_state_transitions.py -v   # State machine
pytest soc-agent/tests/test_kb_schema.py -v           # Knowledge base
pytest soc-agent/tests/test_audit_hooks.py -v         # Audit hooks

# Integration tests (require LLM)
pytest soc-agent/tests/test_e2e_mock.py -m llm        # Mock SIEM
pytest soc-agent/tests/test_e2e_live.py -m "llm and live"  # Live Wazuh
```

## Investigation Flow Language

The agent uses a structured vocabulary for investigations:

- **Hypotheses** prefixed with `?` — e.g., `?monitoring-probe`, `?brute-force`
- **Leads** — evidence-gathering actions that discriminate between hypotheses
- **Assessments** — `++` (strongly supports), `+` (weakly supports), `-` (weakly refutes), `--` (strongly refutes)
- **Trace** — compressed investigation path: `lead1(result)→lead2(result)→disposition:hypothesis`

## Key Design Patterns

### Hypothesis-Driven Investigation
- Agent forms candidate explanations, makes predictions, gathers evidence
- Must maintain adversarial hypothesis until explicitly refuted
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
- Every investigation creates: alert.json, investigation.md, state.json, report.md
- JSONL investigation outcomes in runs/audit.jsonl
- JSONL tool call audit trail in runs/tool_audit.jsonl (state-changing tools)
- JSONL tool call trace in runs/tool_trace.jsonl (read-only tools, for debugging)
- Full phase-by-phase investigation log

## Adding a New Signature

See `soc-agent/knowledge/signatures/_template/README.md` for the full onboarding workflow. Summary:

1. Copy template: `cp -r soc-agent/knowledge/signatures/_template soc-agent/knowledge/signatures/{signature-id}`
2. Remove `README.md` from the copy
3. Research past tickets for this signature — pull alerts, review closed tickets, identify outcome clusters
4. Fill in `context.md` — signature logic, threat model, known false positives (grounded in real data)
5. Fill in `playbook.md` — hypothesis catalog, leads with predictions (from actual investigation patterns)
   - Optionally use `@import:name` inline to reference common lessons from `knowledge/common/lessons/`
   - The resolver (`scripts/resolve_imports.py`) loads referenced atoms automatically at skill load time
6. Add precedents from representative tickets to `precedents/`
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

### Common Commands

```bash
# Start all containers
cd .devcontainer && docker compose up -d

# Start Wazuh stack
docker compose -p cyber-response-agent_devcontainer -f wazuh-stack.yml -f wazuh-overrides.yml up -d

# View Falco events
docker logs falco --follow
```

## Credentials (Development Only)

| Service | Username | Password |
|---------|----------|----------|
| Wazuh Dashboard | admin | SecretPassword |
| Wazuh API | wazuh-wui | MyS3cr37P450r.*- |

## Known Issues

- Wazuh API not accessible from localhost (use `wazuh-manager:55000` from within Docker network)
- Falco generates alerts for healthcheck operations (expected behavior)
- `act` mode not yet implemented (MVP is recommend-only)

## Documentation

Detailed documentation in `docs/`:
- `playground-setup.md` — Complete environment setup guide
- `design-v2.md` — System architecture and design decisions
- `agent-execution-architecture.md` — Agent lifecycle details
- `reproduction-agent-design.md` — Reproduction sandbox design
