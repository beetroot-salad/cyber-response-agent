# Agent Execution Architecture

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Investigation isolation | Process + runtime directory | Fast startup (<100ms), sufficient isolation, simpler orchestration |
| Reproduction isolation | Container pool (DinD) | Required for security - network isolation, ephemeral filesystem |
| Run ID format | `{ticket_id}-{timestamp}-{short_uuid}` | Human readable, sortable, no external state needed |
| Report storage | PostgreSQL (ticket table JSONB) | Atomic with ticket updates, queryable, no volume complexity |
| Trigger mechanism | Manual (dev), webhook-to-API (production target) | Simplest path to working system |

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                         Trigger Layer                              │
│  DEV: Manual CLI invocation                                        │
│  PROD: Webhook → API endpoint                                      │
└────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────┐
│                         Orchestrator                               │
│  - Creates runtime directory for each investigation                │
│  - Spawns investigation agent process                              │
│  - Extracts report and updates ticket                              │
│  - Routes to reproduction pool if needed                           │
│  - Cleans up runtime directory                                     │
└────────────────────────────────────────────────────────────────────┘
                    │                           │
                    ▼                           ▼ (if reproduction needed)
┌──────────────────────────────┐    ┌──────────────────────────────┐
│     Investigation Agent      │    │     Reproduction Pool        │
│  - Process isolation         │    │  - Docker-in-Docker          │
│  - Runtime dir as workspace  │    │  - network: none             │
│  - RO access to knowledge    │    │  - Warm containers ready     │
│  - Writes report + findings  │    │  - Ephemeral filesystem      │
└──────────────────────────────┘    └──────────────────────────────┘
```

---

## Runtime Directory Structure

Each investigation gets an isolated workspace:

```
/workspace/runs/{run_id}/
├── context/                    # Read-only symlinks to shared knowledge
│   ├── signature/ → /workspace/app/knowledge/signatures/{sig_id}/
│   └── common/ → /workspace/app/knowledge/common/
├── scratchpad/                 # Agent working space (hypotheses, notes)
├── report.md                   # Final investigation report
└── findings.json               # Structured output for orchestrator
```

### Run ID Generation

```python
def generate_run_id(ticket_id: str) -> str:
    """Generate unique run ID: ticket-timestamp-short_uuid"""
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    short_uuid = uuid.uuid4().hex[:8]
    return f"{ticket_id}-{ts}-{short_uuid}"

# Example: SEC-1234-20250129-143052-a1b2c3d4
```

---

## Data Flow

### 1. Investigation Triggered

```
Trigger (manual/webhook)
    │
    ▼
Orchestrator.start_investigation(ticket_id)
    │
    ├── 1. Fetch ticket from database
    ├── 2. Generate run_id
    ├── 3. Create runtime directory structure
    ├── 4. Create RO symlinks to knowledge base
    ├── 5. Update ticket status → 'investigating'
    └── 6. Spawn investigation agent process
```

### 2. Investigation Runs

```
Investigation Agent (Claude Code process)
    │
    ├── Working directory: /workspace/runs/{run_id}/
    ├── Reads: context/ (knowledge base via symlinks)
    ├── Writes: scratchpad/ (working notes)
    ├── Queries: SIEM via MCP, ticket history via DB
    │
    └── Outputs:
        ├── findings.json (structured: recommendation, confidence, evidence)
        └── report.md (human-readable investigation narrative)
```

### 3. Results Extracted

```
Orchestrator.complete_investigation(run_id)
    │
    ├── 1. Read findings.json → parse into AgentFindings
    ├── 2. Read report.md → store as report body
    ├── 3. Calculate confidence score
    ├── 4. Make routing decision (auto_close / reproduce / escalate)
    │
    ├── If REPRODUCE:
    │   └── Route to reproduction pool (see below)
    │
    ├── 5. Update ticket:
    │   ├── status → 'closed' or 'escalated'
    │   ├── disposition → from findings
    │   ├── investigation_context JSONB:
    │   │   ├── run_id
    │   │   ├── report_summary (first 2-3 sentences)
    │   │   ├── report_body (full markdown)
    │   │   ├── findings (structured JSON)
    │   │   ├── duration_ms
    │   │   └── agent_version
    │   └── confidence_score
    │
    └── 6. Cleanup runtime directory
```

---

## Reproduction Pool

### When Triggered

Reproduction is triggered when:
- Investigation confidence is 70-90% (medium confidence)
- Signature permissions allow reproduction
- Investigation provides a testable hypothesis

### Pool Architecture

```yaml
# Warm pool configuration
reproduction_pool:
  min_warm: 1          # Minimum idle containers (dev: 1, prod: 2-3)
  max_containers: 3    # Maximum concurrent reproductions
  container_timeout: 120s
  container_config:
    image: cyber-response-sandbox:latest
    network_mode: none
    cap_drop: [ALL]
    read_only: true
    mem_limit: 512m
    tmpfs:
      /workspace: size=100M
```

### Container Lifecycle

```
WARM (idle, pre-provisioned)
    │
    ▼ acquire()
ASSIGNED (processing hypothesis)
    │
    ▼ complete/timeout/error
CLEANUP (reset state)
    │
    ▼ if healthy and under max_lifetime
WARM (recycled)
    │
    ▼ else
TERMINATED → new container provisioned
```

### Reproduction Flow

```
Orchestrator.request_reproduction(run_id, hypothesis)
    │
    ├── 1. Acquire container from pool
    ├── 2. Inject hypothesis context
    ├── 3. Execute reproduction agent
    ├── 4. Collect result (confirmed/refuted/inconclusive)
    ├── 5. Release container to pool
    └── 6. Return to investigation flow with reproduction_result
```

---

## Database Schema

### Tickets Table (existing, extended)

```sql
-- Existing columns
id, alert_id, alert_signature, severity, status, disposition,
confidence_score, closure_reason, timestamp, closed_at,
created_at, updated_at, raw_alert, investigation_context

-- investigation_context JSONB structure:
{
    "run_id": "SEC-1234-20250129-143052-a1b2c3d4",
    "report_summary": "SSH login failure from monitoring probe 10.0.1.50...",
    "report_body": "# Investigation Report\n\n## Threat Assessment\n...",
    "findings": {
        "recommendation": "benign",
        "confidence": "high",
        "matched_ticket": "SEC-2024-001",
        "matched_tier": "gold",
        "evidence": { ... }
    },
    "reproduction": {
        "run_id": "...",
        "result": "confirmed",
        "execution_log": "..."
    },
    "timing": {
        "investigation_ms": 12500,
        "reproduction_ms": 45000,
        "total_ms": 57500
    },
    "agent_version": "1.0.0"
}
```

### Agent Sessions Table (for learning/analytics)

```sql
CREATE TABLE agent_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id INTEGER REFERENCES tickets(id),
    run_id TEXT NOT NULL UNIQUE,
    agent_type TEXT NOT NULL,  -- 'investigation' | 'reproduction'

    started_at TIMESTAMP NOT NULL,
    ended_at TIMESTAMP,
    duration_ms INTEGER,

    -- Outcome
    recommendation TEXT,
    confidence_level TEXT,
    final_decision TEXT,

    -- For learning
    tool_usage JSONB,          -- Tool calls with timing
    hypotheses_tested JSONB,   -- What was considered

    -- Human feedback (populated after review)
    human_agreed BOOLEAN,
    human_feedback TEXT,
    reviewed_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_sessions_ticket ON agent_sessions(ticket_id);
CREATE INDEX idx_sessions_run ON agent_sessions(run_id);
CREATE INDEX idx_sessions_outcome ON agent_sessions(recommendation, human_agreed);
```

---

## Orchestrator Interface

```python
class Orchestrator:
    """Main entry point for investigation lifecycle."""

    async def start_investigation(self, ticket_id: str) -> str:
        """
        Start investigation for a ticket.
        Returns: run_id
        """
        pass

    async def get_investigation_status(self, run_id: str) -> InvestigationStatus:
        """Check status of running investigation."""
        pass

    async def complete_investigation(self, run_id: str) -> InvestigationSummary:
        """
        Extract results, update ticket, cleanup.
        Called automatically when agent process exits.
        """
        pass

    async def request_reproduction(
        self,
        run_id: str,
        hypothesis: ReproductionHypothesis
    ) -> ReproductionResult:
        """Route to reproduction pool for hypothesis testing."""
        pass


class ReproductionPool:
    """Manages warm container pool for reproduction agents."""

    async def start(self):
        """Pre-warm the pool."""
        pass

    async def acquire(self, timeout: float = 30.0) -> SandboxContainer:
        """Get a warm container."""
        pass

    async def release(self, container: SandboxContainer, reuse: bool = True):
        """Return container to pool or terminate."""
        pass

    async def execute(
        self,
        hypothesis: ReproductionHypothesis
    ) -> ReproductionResult:
        """High-level: acquire, execute, release."""
        pass
```

---

## CLI Interface (Dev)

```bash
# Start investigation manually
python -m app.orchestrator.cli investigate TICKET-123

# Check status
python -m app.orchestrator.cli status SEC-1234-20250129-143052-a1b2c3d4

# List recent runs
python -m app.orchestrator.cli list-runs --limit 10

# View report
python -m app.orchestrator.cli report SEC-1234-20250129-143052-a1b2c3d4

# Cleanup old runs (if not auto-cleaned)
python -m app.orchestrator.cli cleanup --older-than 7d
```

---

## Production API (Future)

```yaml
# Webhook endpoint
POST /api/v1/investigations
Content-Type: application/json

{
    "ticket_id": "TICKET-123",
    "callback_url": "https://ticketing.internal/webhook/update"  # optional
}

Response:
{
    "run_id": "TICKET-123-20250129-143052-a1b2c3d4",
    "status": "started"
}

# Status endpoint
GET /api/v1/investigations/{run_id}

Response:
{
    "run_id": "...",
    "status": "completed",
    "disposition": "benign",
    "confidence": 0.92,
    "report_url": "/api/v1/investigations/{run_id}/report"
}
```

---

## Implementation Phases

### Phase 1: Manual Investigation Loop

1. Create runtime directory management (`app/orchestrator/runtime.py`)
2. Wire orchestrator to create dir, spawn agent, extract results
3. CLI for manual triggering
4. Test with existing stub agent

### Phase 2: Full Investigation Agent

1. Replace stub with Claude Code-based investigation
2. Add SIEM query integration (Wazuh MCP)
3. Implement session logging
4. Test end-to-end with real alerts

### Phase 3: Reproduction Pool

1. Build sandbox container image
2. Implement pool manager
3. Wire reproduction agent
4. Test hypothesis confirmation flow

### Phase 4: Production Hardening

1. Add API endpoint for webhook trigger
2. Implement proper error handling and retries
3. Add monitoring and alerting
4. Human feedback loop for learning

---

## Open Questions

1. **Report retention**: How long to keep full reports in DB? Archive strategy?
2. **Concurrent limit**: Max parallel investigations in dev vs prod?
3. **Feedback UI**: How do analysts provide feedback on decisions?
