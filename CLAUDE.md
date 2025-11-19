# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Cyber Response Agent** prototype - an automated security alert triage system designed to reduce SOC analyst workload by automatically investigating and resolving false positives, duplicates, and routine security alerts. The system leverages Claude Code with a playground environment that simulates real SIEM/EDR infrastructure using open-source tools.

**Key Goal**: Zero false negatives (never auto-close real threats), high precision auto-closure (>95%) of benign alerts, mean time to resolution of 1-3 minutes.

## Architecture

### Multi-Container Docker Environment

The project runs entirely in Docker containers orchestrated via Docker Compose (`.devcontainer/docker-compose.yml`):

1. **devcontainer** - Development environment where Claude Code runs
   - Has access to host Docker via socket mount (`/var/run/docker.sock`)
   - Working directory: `/workspace`
   - All code development happens here

2. **target-endpoint** - Ubuntu 22.04 container simulating a monitored endpoint
   - Runs scheduled workloads (benign and suspicious activity)
   - Generates realistic system events for monitoring
   - Location: `target-endpoint/`

3. **falco** - eBPF-based security monitoring (EDR simulation)
   - Monitors syscalls, file access, network activity from all containers
   - Outputs events in JSON format to `/var/log/falco/events.json`
   - Replaces auditd (which doesn't work in containers)

4. **postgres** - PostgreSQL + pgvector database
   - Stores tickets (security alerts) from Wazuh/Falco
   - Database: `cyber_response`, User: `agent`, Password: `agent_password`
   - Schema: `init-db.sql` (simple tickets table with JSONB for flexibility)
   - Port: 5432

5. **wazuh-manager**, **wazuh-indexer**, **wazuh-dashboard** - SIEM stack
   - Manager: Alert correlation and API (port 55000)
   - Indexer: Elasticsearch for event storage (port 9200)
   - Dashboard: Web UI (port 5601)
   - Credentials: admin/SecretPassword, API: wazuh-api/MyS3cr37P450r.*-

### Data Flow

```
Target Endpoint → Falco (eBPF monitoring) → Wazuh Manager → Wazuh Indexer (events)
                                                          ↘ PostgreSQL (tickets)
```

Agent investigates alerts via:
- Wazuh MCP Server (query SIEM alerts)
- PostgreSQL (manage tickets, case knowledge)
- Docker exec (investigate target endpoint directly)

## Database Commands

### PostgreSQL Access
```bash
# Connect to database (from devcontainer)
docker exec -it postgres psql -U agent -d cyber_response

# Quick query examples
docker exec postgres psql -U agent -d cyber_response -c "SELECT COUNT(*) FROM tickets;"
docker exec postgres psql -U agent -d cyber_response -c "SELECT alert_signature, severity, status FROM tickets LIMIT 10;"
```

### Schema
- **tickets** table: Core alert storage with JSONB for raw alerts
- Schema defined in `init-db.sql`
- Supports: alert metadata, investigation context, disposition tracking

## Container Management

### Start/Stop Stack
```bash
# Start all containers (from workspace root, on host Docker)
docker-compose -f .devcontainer/docker-compose.yml up -d

# Stop all containers
docker-compose -f .devcontainer/docker-compose.yml down

# View logs
docker logs target-endpoint
docker logs falco --tail 50
docker logs wazuh-manager
```

### Investigate Target Endpoint
```bash
# Access the monitored endpoint (simulates EDR console access)
docker exec -it target-endpoint bash

# Inside container - check running processes
ps aux

# Check workload logs
tail -f /var/log/workload.log

# View cron schedule
cat /etc/cron.d/workload
```

### Monitor Falco Events
```bash
# View real-time Falco alerts (JSON format)
docker logs falco --follow

# Access Falco event log file
docker exec falco cat /var/log/falco/events.json | jq .
```

## Key Design Patterns

### Conservative Investigation Approach
- **Never auto-close on uncertainty** - when confidence < 95%, escalate to human
- Multi-layer validation before any auto-closure decision
- Full audit trail for compliance and review
- Dispositions: `true_positive`, `false_positive`, `benign`, `escalated`, `inconclusive`

### Ticket-Based Workflow
1. Alerts ingested from Wazuh → PostgreSQL tickets table
2. Agent investigates using multiple data sources (SIEM, TI, past cases)
3. Confidence scoring determines disposition (auto-close vs escalate)
4. Investigation context stored in JSONB for learning and audit

### Isolation for Reproduction
- Reproduction agent runs in isolated sandbox (separate container)
- No network access, ephemeral storage, resource limits
- Used for medium-confidence alerts (80-95%) to validate hypothesis
- Designed in `cyber-response-agent-design.md` (not yet implemented)

## Important Files

### Documentation
- `playground-setup-v2.md` - Complete setup guide and implementation roadmap
- `cyber-response-agent-design.md` - System architecture, goals, flow diagrams
- `init-db.sql` - PostgreSQL schema for ticket system

### Configuration
- `.devcontainer/docker-compose.yml` - Multi-container orchestration
- `target-endpoint/Dockerfile` - Monitored endpoint container build
- `target-endpoint/entrypoint.sh` - Endpoint initialization script
- `target-endpoint/workloads/*.sh` - Benign and suspicious activity scripts

### Implementation Status (from playground-setup-v2.md)
✅ **Completed**:
- Target endpoint with workload generation
- Falco eBPF monitoring with JSON output
- Docker Compose multi-container stack
- Wazuh SIEM stack (Manager v4.9.2, Indexer, Dashboard)
- PostgreSQL database with tickets table

🚧 **In Progress**:
- Falco → Wazuh integration (mount falco-logs volume to Wazuh)

📋 **Next Steps**:
- PostgreSQL ticket ingestion from Wazuh alerts
- MORDOR dataset ingestion for realistic attack data
- Investigation agent implementation
- Reproduction sandbox

## Development Workflow

### Accessing Services
```bash
# Wazuh Dashboard: http://localhost:5601 (admin/SecretPassword)
# PostgreSQL: localhost:5432 (agent/agent_password)

# Wazuh API (from devcontainer - note: currently not accessible from localhost)
curl -k -u wazuh-api:MyS3cr37P450r.*- https://wazuh-manager:55000/
```

### Testing the Environment
```bash
# 1. Verify target endpoint is generating activity
docker logs target-endpoint --tail 20

# 2. Verify Falco is capturing events
docker logs falco --tail 50 | grep -i "critical\|warning"

# 3. Check database connectivity
docker exec postgres psql -U agent -d cyber_response -c "SELECT version();"

# 4. Manually trigger suspicious activity on target
docker exec target-endpoint /opt/workloads/suspicious_patterns.sh
```

### Adding New Workload Scripts
Place executable scripts in `target-endpoint/workloads/`:
- `benign_activity.sh` - Runs every 5 minutes (normal user behavior)
- `suspicious_patterns.sh` - Runs every 15 minutes (30% chance of suspicious activity)

Edit cron schedule in `target-endpoint/Dockerfile` if needed.

## Security Considerations

### Network Isolation
- All containers are on `response-network` bridge network
- Devcontainer can access Docker host via socket mount
- Target endpoint is isolated but accessible via `docker exec`

### Credentials in Code
- Hardcoded credentials are for playground/development ONLY
- PostgreSQL: `agent/agent_password`
- Wazuh API: `wazuh-api/MyS3cr37P450r.*-`
- Wazuh Dashboard: `admin/SecretPassword`

### Reproduction Sandbox
When implementing, ensure:
- No outbound network access (`network_mode: none`)
- Drop all capabilities (`cap_drop: ALL`)
- Read-only filesystem where possible
- Time and resource limits enforced

## Future MCP Servers (Planned)

Per `playground-setup-v2.md`, planned MCP servers to implement:

1. **Wazuh MCP Server** - Query SIEM alerts (use existing socfortress/Wazuh-MCP-Server)
2. **Ticketing MCP Server** - Close tickets, update status, add case knowledge (PostgreSQL)
3. **Threat Intel MCP Server** - IOC lookups with caching (PostgreSQL)

MCP config location: `.claude/mcp_config.json` (not yet created)

## Known Issues

- Wazuh API is not accessible from `localhost:55000` in devcontainer (connection refused)
  - Use `wazuh-manager:55000` from within the Docker network instead
- Falco generates many alerts for normal healthcheck operations (e.g., pg_isready reading /etc/shadow)
  - Expected behavior - can tune Falco rules if needed
- PostgreSQL healthcheck runs every 10s and generates Falco alerts
  - Benign - part of Docker Compose health monitoring

## Agent Design Principles (from cyber-response-agent-design.md)

1. **Conservative by Default** - Escalate when uncertain, multiple validation layers
2. **Isolation & Security** - Minimal privileges, structured outputs, no credentials in LLM context
3. **Transparency & Auditability** - Every decision logged with full justification
4. **Continuous Learning** - Knowledge base evolves from successful investigations
5. **Fail-Safe Architecture** - Circuit breakers, graceful degradation, manual override always available

## Performance Targets

- **Fast Triage**: <10s for exact duplicates and known false positives (60-70% of alerts)
- **Main Investigation**: 15-30s for hypothesis generation with SIEM/TI queries
- **Reproduction**: 30-90s for isolated environment validation
- **Overall Mean TTR**: 45-90 seconds (weighted average across all alert types)
