# soc-agent

A Claude Code plugin for automated SOC alert triage. Investigates security alerts, calculates deterministic confidence scores, and routes decisions (auto-close, reproduce, or escalate) with zero false negatives.

## Installation

```bash
# Use as a Claude Code plugin
claude --plugin-dir ./soc-agent
```

## Quick Start

```bash
# Triage an alert
claude -p '/soc-agent:triage {"ticket_id":"SEC-001","signature_id":"wazuh-rule-5710","agent":"web-server-01","srcip":"10.0.1.50","srcuser":"testuser","severity":"medium"}' --plugin-dir ./soc-agent

# Investigate only (no routing)
claude -p '/soc-agent:investigate {"ticket_id":"SEC-001","signature_id":"wazuh-rule-5710","agent":"web-server-01","srcip":"10.0.1.50"}' --plugin-dir ./soc-agent

# Reproduce a hypothesis
claude -p '/soc-agent:reproduce --ticket_id SEC-001 --hypothesis "backup.sh creates /tmp/backup.tar.gz"' --plugin-dir ./soc-agent
```

## Architecture

```
Alert -> Validate -> Investigate (subagent) -> Score (bash) -> Route (bash) -> Act
                                                  |
                                    deterministic, never LLM-judged
```

- **Investigation**: Claude Code subagent with SIEM tools and knowledge base
- **Scoring**: `confidence-scorer.sh` - deterministic formula (jq + bc)
- **Routing**: `decision-router.sh` - escalation patterns + permission checks
- **Reproduction**: Claude Code subagent in isolated Docker sandbox

## SIEM Configuration

The plugin does NOT bundle a SIEM integration. Configure your SIEM by editing `config/siem-mapping.json`:

```json
{
  "siem_name": "your-siem",
  "operations": {
    "search_events": {
      "tool": "mcp__your_siem__search",
      "description": "Search for events",
      "param_mapping": {
        "query": "your_query_param",
        "time_range_start": "your_start_param"
      }
    },
    "get_agent_info": {
      "tool": "mcp__your_siem__get_host",
      "description": "Get host information",
      "param_mapping": {
        "agent_name": "hostname"
      }
    }
  }
}
```

Required operations: `search_events`, `get_agent_info`. See `config/siem-mapping.schema.json` for full schema and `config/examples/splunk-mapping.json` for a Splunk example.

## Confidence Scoring

Deterministic formula (no LLM involvement):

| Factor | Values |
|--------|--------|
| Base (agent confidence) | high=0.85, medium=0.60, low=0.30 |
| Precedent tier | gold=+0.10, silver=+0.05, bronze=0.00, none=-0.15 |
| Reproduction | confirmed=+0.15, refuted=-0.30 |
| Asset criticality | standard=0.00, elevated=-0.05, critical=-0.15 |

### Decision Matrix

Pre-matrix rules (checked first):
1. No precedent -> ESCALATE
2. Reproduction refuted -> ESCALATE
3. Reproduction confirmed + medium+ confidence -> AUTO_CLOSE

Then a 22-entry lookup matrix based on (criticality, severity, confidence) with hierarchical fallback. Final fallback: ESCALATE.

## Adding a New Signature

```bash
# 1. Create knowledge directory
cp -r knowledge/signatures/_template knowledge/signatures/your-rule-id/

# 2. Create permissions
cp config/signatures/_template/permissions.yaml config/signatures/your-rule-id/permissions.yaml

# 3. Edit the files
# - knowledge/signatures/your-rule-id/rule.md
# - knowledge/signatures/your-rule-id/playbook.md
# - config/signatures/your-rule-id/permissions.yaml
```

## Permissions

Per-signature permissions in `config/signatures/{id}/permissions.yaml`:

```yaml
auto_close:
  enabled: true          # Allow auto-closure for this signature

escalation_patterns:     # Force escalation on pattern match
  srcuser:
    - "^admin$"
    - "^root$"

reproduction:
  enabled: false         # Enable reproduction validation
  max_timeout_seconds: 300
```

## Testing

```bash
# All tests
./tests/test-confidence.sh && ./tests/test-decision.sh && ./tests/test-hooks.sh && ./tests/test-siem-mapping.sh && ./tests/test-e2e.sh

# Individual test suites
./tests/test-confidence.sh    # 26 scoring + decision matrix tests
./tests/test-decision.sh      # 12 routing + escalation tests
./tests/test-hooks.sh         # 8 hook I/O contract tests
./tests/test-siem-mapping.sh  # 5 schema validation tests
./tests/test-e2e.sh           # 8 end-to-end pipeline scenarios
```

## Plugin Structure

```
soc-agent/
├── .claude-plugin/plugin.json       # Plugin manifest
├── skills/
│   ├── triage/SKILL.md             # Main entry point
│   ├── investigate/SKILL.md        # Investigation workflow
│   └── reproduce/SKILL.md         # Reproduction workflow
├── agents/
│   ├── investigator.md             # Investigation subagent
│   └── reproducer.md              # Reproduction subagent
├── hooks/
│   ├── hooks.json
│   └── scripts/
│       ├── confidence-scorer.sh    # Deterministic scoring
│       ├── decision-router.sh      # Routing + escalation
│       ├── audit-logger.sh         # JSONL audit trail
│       └── post-mortem.sh          # Knowledge base updates
├── knowledge/                      # Bundled knowledge base
├── config/
│   ├── siem-mapping.json          # SIEM tool mapping
│   ├── siem-mapping.schema.json   # JSON Schema
│   └── signatures/                # Per-signature permissions
├── tests/                         # Test suite
└── README.md
```

## Dependencies

- `jq` - JSON processing
- `bc` - Floating-point math
- `bash` 4+ - Shell scripting
- Docker (optional, for reproduction)
