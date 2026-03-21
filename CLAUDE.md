# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**Cyber Response Agent (v3)** — A hypothesis-driven security alert triage system. Reduces SOC analyst workload by investigating alerts through iterative hypothesis elimination, validating findings against precedents, and recommending disposition.

**Key Goal**: Zero false negatives (never auto-close real threats), high precision recommendations, mean time to resolution of 1-3 minutes.

**Approach**: Claude Code plugin with a hypothesis-driven investigation loop. The agent forms hypotheses, gathers evidence from whatever SIEM/query tools are available via MCP, eliminates candidates with structured assessments, and stops when confident. Hooks enforce structural safety. MVP is `recommend`-only. The plugin is **vendor-neutral** — it works with any SIEM that exposes tools via MCP. Wazuh signatures are included as working examples.

## Architecture

### Investigation Loop

```
Alert → Triage Skill → Investigator Agent → Report
                           │
              CONTEXTUALIZE → HYPOTHESIZE → GATHER → ANALYZE
                                   ↑                    │
                                   └────── loop ────────┘
                                                        │
                                                   CONCLUDE → report.md
```

### Core Components

| Component | Path | Purpose |
|-----------|------|---------|
| **Triage Skill** | `soc-agent/skills/triage/SKILL.md` | Entry point: validate alert, load permissions, spawn investigator |
| **Investigator Agent** | `soc-agent/agents/investigator.md` | Hypothesis-driven investigation loop |
| **Validate Report Hook** | `soc-agent/hooks/scripts/validate_report.py` | Stop hook: Tier 1 report validation (safety gate) |
| **Write State Script** | `soc-agent/hooks/scripts/write_state.py` | State machine enforcement |
| **Audit Logger Hook** | `soc-agent/hooks/scripts/audit_logger.py` | JSONL audit trail |

### Safety Architecture

- **Hook validation** replaces deterministic scoring — the `validate_report.py` Stop hook enforces that investigations actually happened (leads pursued, precedent match required for resolution)
- **State machine** (`write_state.py`) prevents phase skipping — agent must follow CONTEXTUALIZE→HYPOTHESIZE→GATHER→ANALYZE→(loop|CONCLUDE)
- **Precedent requirement** — `status=resolved` requires `matched_precedent` pointing to an existing file
- **Adversarial hypothesis** — agent must maintain at least one threat hypothesis until explicitly refuted

## Project Structure

```
/workspace/
├── soc-agent/                     # Claude Code plugin (all agent content)
│   ├── .claude-plugin/
│   │   └── plugin.json            # Plugin manifest
│   ├── agents/
│   │   └── investigator.md        # Hypothesis-driven investigation agent
│   ├── skills/
│   │   └── triage/
│   │       └── SKILL.md           # Entry point: triage an alert
│   ├── hooks/
│   │   └── scripts/
│   │       ├── validate_report.py # Stop hook: report validation
│   │       ├── write_state.py     # State machine enforcement
│   │       └── audit_logger.py    # JSONL audit trail
│   ├── knowledge/
│   │   ├── common/
│   │   │   ├── SKILL.md           # Common investigation knowledge
│   │   │   ├── checklist.md       # Investigation self-check guide
│   │   │   ├── lessons/           # IP classification, etc.
│   │   │   └── utilities/         # Example query patterns (Wazuh)
│   │   └── signatures/
│   │       ├── _template/         # Template for new signatures
│   │       └── wazuh-rule-5710/   # SSH Invalid User (example signature)
│   │           ├── SKILL.md
│   │           ├── context.md     # Signature reference + threat model
│   │           ├── playbook.md    # Hypothesis catalog + leads
│   │           └── precedents/    # Past resolved investigations
│   ├── schemas/                   # Python dataclass validators (system contracts)
│   │   ├── report_frontmatter.py
│   │   ├── state.py
│   │   └── precedent.py
│   ├── config/
│   │   └── signatures/
│   │       └── wazuh-rule-5710/
│   │           └── permissions.yaml
│   ├── tests/                     # pytest test suite
│   │   ├── test_validate_report.py
│   │   ├── test_state_transitions.py
│   │   ├── test_kb_schema.py
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
- JSONL audit trail in runs/audit.jsonl
- Full phase-by-phase investigation log

## Adding a New Signature

1. Copy template: `cp -r soc-agent/knowledge/signatures/_template soc-agent/knowledge/signatures/{signature-id}`
2. Edit `context.md` — signature logic, threat model, known false positives
3. Edit `playbook.md` — hypothesis catalog, lead list with predictions
4. Add precedents to `precedents/` as investigations resolve
5. Create `soc-agent/config/signatures/{signature-id}/permissions.yaml`

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
