# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**Cyber Response Agent** - An automated security alert triage system that reduces SOC analyst workload by investigating alerts and resolving false positives, duplicates, and routine issues. Uses Claude Code with isolated reproduction environments to validate findings before auto-closure.

**Key Goal**: Zero false negatives (never auto-close real threats), high precision auto-closure (>95% correct), mean time to resolution of 1-3 minutes.

## Architecture

### Core Components

```
┌────────────────────────────────────────────────────────────────────────────┐
│                            ORCHESTRATOR                                    │
│  app/orchestrator/                                                         │
│  - Receives alert data from SIEM                                           │
│  - Validates input, invokes investigation agent                            │
│  - Calculates confidence score (deterministic formula)                     │
│  - Makes routing decision: auto_close | reproduce | escalate               │
│  - Logs audit trail                                                        │
└────────────────────────────┬───────────────────────────┬───────────────────┘
                             │                           │
                             ▼                           ▼
┌────────────────────────────────────────┐  ┌────────────────────────────────┐
│       INVESTIGATION AGENT              │  │       REPRODUCTION AGENT       │
│  app/agent/investigation/              │  │  app/agent/reproduction/       │
│                                        │  │                                │
│  Claude Code subagent that:            │  │  Claude Code subagent that:    │
│  - Reads alert and knowledge base      │  │  - Builds isolated sandbox     │
│  - Queries SIEM (Wazuh MCP)            │  │  - Executes hypothesis test    │
│  - Matches against past tickets        │  │  - Compares observed vs expected│
│  - Outputs structured findings + report│  │  - Returns confirmed/refuted   │
│                                        │  │                                │
│  Isolation: Process + runtime dir      │  │  Isolation: Docker (--network  │
│  Timeout: 5 minutes                    │  │  none), ephemeral filesystem   │
└────────────────────────────────────────┘  └────────────────────────────────┘
```

### Decision Flow

```
Alert → Validate → Investigate → Calculate Confidence → Route
                                        │
                        ┌───────────────┼───────────────┐
                        ▼               ▼               ▼
                   ≥90%: AUTO_CLOSE  70-89%: REPRODUCE  <70%: ESCALATE
                        │               │               │
                        ▼               ▼               ▼
                   Close ticket    Sandbox test    Human analyst
                   Update KB       → re-evaluate   queue
```

### File-Based Knowledge System

Past investigations and playbooks are stored as files in `app/knowledge/`:

```
app/knowledge/
├── common/                     # Shared utilities and lessons
│   ├── SKILL.md               # Common skills definition
│   ├── lessons/               # Learned patterns
│   └── utilities/             # Wazuh queries, etc.
└── signatures/                # Per-signature knowledge
    ├── _template/             # Template for new signatures
    │   ├── SKILL.md
    │   ├── playbook.md
    │   ├── rule.md
    │   └── past-tickets/
    └── wazuh-rule-5710/       # Example: SSH brute force
        ├── SKILL.md
        ├── playbook.md
        ├── rule.md
        ├── lessons.md
        └── past-tickets/      # JSON files with case history
```

## Project Structure

```
/workspace/
├── app/                        # Main application code
│   ├── agent/
│   │   ├── investigation/     # Investigation agent runner + CLAUDE.md
│   │   └── reproduction/      # Reproduction agent runner + CLAUDE.md
│   ├── orchestrator/          # Manager, confidence scoring, models
│   ├── config/                # App config, signature permissions
│   ├── knowledge/             # Playbooks, past tickets, lessons
│   └── tools/                 # Utility scripts (run analyzer)
│
├── config/                    # Infrastructure configuration
│   ├── wazuh_cluster/         # Wazuh manager config, Falco rules
│   ├── wazuh_indexer/         # Elasticsearch config
│   └── wazuh_indexer_ssl_certs/
│
├── docs/                      # Documentation
│   ├── design-v1.md           # Initial design document
│   ├── design-v2.md           # Updated design
│   ├── design-alternative.md  # Alternative approaches
│   ├── playground-setup.md    # Full setup guide
│   ├── agent-execution-architecture.md
│   └── reproduction-agent-design.md
│
├── .devcontainer/             # Docker environment
│   ├── docker-compose.yml     # Main services
│   ├── wazuh-stack.yml        # Wazuh SIEM stack
│   └── wazuh-overrides.yml    # Local customizations
│
├── target-endpoint/           # Monitored endpoint container
│   ├── Dockerfile
│   └── workloads/             # Benign/suspicious activity scripts
│
├── falco-config/              # eBPF security monitoring
│
└── tests/                     # Test suite
    ├── unit/
    └── integration/
```

## Docker Environment

Multi-container stack (`.devcontainer/docker-compose.yml`):

| Service | Purpose |
|---------|---------|
| **devcontainer** | Development environment with Docker socket access |
| **target-endpoint** | Ubuntu container generating workload activity |
| **falco** | eBPF syscall monitoring → JSON events |
| **registry** | Private Docker registry for reproduction images |
| **wazuh-mcp-server** | MCP interface to Wazuh API |
| **wazuh.manager** | SIEM alert correlation (separate stack) |
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

# Investigate target endpoint
docker exec -it target-endpoint bash

# Trigger test activity
docker exec target-endpoint /opt/workloads/suspicious_patterns.sh
```

## Running the Agent

### Investigation

```bash
# Via Python module
python -m app.agent.investigation.runner \
  --ticket-id "SEC-001" \
  --signature-id "wazuh-rule-5710" \
  --alert-json '{"srcip": "10.0.1.50", "srcuser": "admin", ...}'

# Or programmatically
from app.agent.investigation.runner import InvestigationRunner

runner = InvestigationRunner(
    ticket_id="SEC-001",
    signature_id="wazuh-rule-5710",
    alert_data={"srcip": "10.0.1.50", ...}
)
result = runner.run()
```

### Reproduction

```bash
python -m app.agent.reproduction.runner \
  --ticket-id "SEC-001" \
  --hypothesis "backup.sh creates /tmp/backup.tar.gz" \
  --signature-id "wazuh-rule-5710" \
  --timeout 120
```

### Tests

```bash
# Run all tests
pytest tests/

# Unit tests only
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Specific test
pytest tests/test_confidence.py -v
```

## Key Design Patterns

### Conservative by Default
- When confidence < threshold, escalate to human
- Multiple validation layers before auto-closure
- Reproduction validates medium-confidence findings

### Deterministic Orchestration
- Confidence scoring is a formula, not LLM judgment
- Routing decisions based on thresholds
- Agent provides structured findings, orchestrator decides

### Isolation
- Investigation: Process + runtime directory
- Reproduction: Docker with `--network none`, dropped capabilities, ephemeral filesystem

### Auditability
- Every investigation creates a run directory
- Reports stored in `app/agent/*/runs/{run_id}/`
- JSON findings + markdown narrative for each run

## Configuration

### Signature Permissions (`app/config/signatures/{signature_id}/permissions.yaml`)

```yaml
allowed_dispositions:
  - benign
  - false_positive
auto_close:
  enabled: true
reproduction:
  enabled: true
  max_timeout_seconds: 300
escalation_patterns:
  critical_assets: ["domain-controller", "pci-server"]
```

### MCP Servers

Wazuh MCP Server runs at `wazuh-mcp-server:8000` for SIEM queries.

## Credentials (Development Only)

| Service | Username | Password |
|---------|----------|----------|
| Wazuh Dashboard | admin | SecretPassword |
| Wazuh API | wazuh-wui | MyS3cr37P450r.*- |

## Development Guidelines

### Adding a New Signature

1. Create directory: `app/knowledge/signatures/{signature-id}/`
2. Copy template: `cp -r app/knowledge/signatures/_template/* app/knowledge/signatures/{signature-id}/`
3. Edit `rule.md` with detection rule details
4. Edit `playbook.md` with investigation steps
5. Add past tickets to `past-tickets/`
6. Create `app/config/signatures/{signature-id}/permissions.yaml`

### Agent Development

Agent instructions are in `app/agent/*/CLAUDE.md`. Edit these to change agent behavior.

Key files:
- `app/agent/investigation/CLAUDE.md` - Investigation methodology
- `app/agent/reproduction/CLAUDE.md` - Reproduction constraints and format
- `app/agent/models.py` - Shared data models

### Testing Changes

```bash
# Run confidence scoring tests
pytest tests/test_confidence.py -v

# Test investigation runner
pytest tests/unit/test_investigation_runner.py -v

# Test reproduction runner
pytest tests/unit/test_reproduction_runner.py -v
```

## Known Issues

- Wazuh API not accessible from localhost (use `wazuh-manager:55000` from within Docker network)
- Falco generates alerts for healthcheck operations (expected behavior)

## Documentation

Detailed documentation in `docs/`:
- `playground-setup.md` - Complete environment setup guide
- `design-v2.md` - System architecture and design decisions
- `agent-execution-architecture.md` - Agent lifecycle details
- `reproduction-agent-design.md` - Reproduction sandbox design
