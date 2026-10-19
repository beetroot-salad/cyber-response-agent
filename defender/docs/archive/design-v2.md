# Cyber Response Agent - Consolidated Design Document

**Version:** 2.0
**Status:** Draft
**Last Updated:** November 2025

---

## 1. Executive Summary

An automated security alert triage system that reduces SOC analyst workload by resolving routine alerts based on established precedent. The system uses past investigated tickets as the source of truth, applies deterministic orchestration for safety and resource control, and leverages LLM judgment for semantic interpretation and hypothesis validation.

**Core principle:** The system's value is in reliably knowing when it doesn't know. When uncertain, escalate.

**Key differentiator:** A reproduction agent validates medium-confidence hypotheses by recreating conditions in an isolated environment, comparing observed behavior to expected patterns.

---

## 2. Goals and Success Criteria

### Primary Goals

| Goal | Metric | Target |
|------|--------|--------|
| Zero false negatives | Escalation override rate (analyst disagrees with auto-close) | < 0.5% |
| Reduce analyst workload | Auto-resolution rate for eligible alerts | 60-80% |
| Fast resolution | Mean time to resolution (auto-closed alerts) | < 3 minutes |
| Full auditability | Decisions with complete reasoning trail | 100% |

### Non-Goals (Explicit Scope Boundaries)

- **Not a threat detection system** — operates downstream of SIEM/EDR detection
- **Not for novel threats** — anything without precedent escalates to humans
- **Not for incident response** — triage and disposition only, not remediation

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ALERT INGESTION                                │
│                                                                             │
│  • Webhook from ticketing system or manual trigger                          │
│  • Input sanitization (defend against prompt injection)                     │
│  • Field normalization to consistent schema                                 │
│  • Rate limiting                                                            │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DETERMINISTIC ORCHESTRATOR                           │
│                                                                             │
│  Responsibilities (NO LLM involvement):                                     │
│  • State machine transitions                                                │
│  • Token/time budget enforcement                                            │
│  • Rate limiting and circuit breakers                                       │
│  • Confidence score aggregation (weighted formula on structured inputs)     │
│  • Reproduction trigger decision (confidence in band 0.70-0.90)             │
│  • Escalation trigger evaluation (hard rules)                               │
│  • Action gating (what requires approval)                                   │
│  • Audit log writing                                                        │
│                                                                             │
│  Does NOT decide:                                                           │
│  • Whether conditions are satisfied (LLM judgment)                          │
│  • Whether alert matches precedent semantically (LLM judgment)              │
│  • How to formulate queries or reproduction steps (LLM judgment)            │
└──────────┬──────────────────────────────────────────────────┬───────────────┘
           │                                                  │
           ▼                                                  ▼
┌─────────────────────────────┐         ┌─────────────────────────────────────┐
│     CONTEXT LOADER          │         │      INVESTIGATION AGENT            │
│     (Deterministic)         │         │      (LLM-powered)                  │
│                             │         │                                     │
│  Triggered by signature_id: │         │  • Precedent matching (semantic)    │
│  • Query precedent store    │         │  • Condition evaluation             │
│  • Fetch past tickets       │         │  • Evidence interpretation          │
│  • Load playbook            │         │  • Query formulation                │
│  • Load condition bank      │         │  • Reproduction step generation     │
│                             │         │  • Finding summarization            │
│  Output: Context bundle     │         │                                     │
│  injected into agent prompt │         │  Output: Structured results only    │
└─────────────────────────────┘         └───────────────┬─────────────────────┘
                                                        │
                                                        ▼
                              ┌──────────────────────────────────────────────┐
                              │              MCP SERVERS                     │
                              │                                              │
                              │  • Wazuh (SIEM queries, read-only)           │
                              │  • PostgreSQL (tickets, precedents)          │
                              │  • Asset inventory (criticality lookup)      │
                              │  • Identity management (user context)        │
                              └──────────────────────────────────────────────┘
                                                        │
                                      ┌─────────────────┴─────────────────┐
                                      │ If confidence in [0.70, 0.90]     │
                                      ▼                                   │
                              ┌──────────────────────────────────────────────┐
                              │          REPRODUCTION AGENT                  │
                              │          (Isolated Environment)              │
                              │                                              │
                              │  • Retrieves configuration (read-only)       │
                              │  • Builds isolated environment               │
                              │  • Executes hypothesis test steps            │
                              │  • Compares observed vs expected patterns    │
                              │  • Returns structured report                 │
                              │                                              │
                              │  Constraints:                                │
                              │  • No network egress                         │
                              │  • Ephemeral filesystem                      │
                              │  • Resource limits (CPU, memory, time)       │
                              │  • No access to production systems           │
                              └──────────────────────────────────────────────┘
```

---

## 4. Decision Boundaries: LLM vs Deterministic

### Deterministic (Orchestrator)

| Decision | Implementation |
|----------|----------------|
| Confidence score calculation | Weighted formula on structured inputs |
| "Should we reproduce?" | `confidence >= 0.70 AND confidence < 0.90` |
| "Auto-close or escalate?" | `confidence >= threshold AND no_escalation_triggers` |
| Budget exceeded? | Token count > limit OR wall_clock > timeout |
| High-value asset? | Asset criticality lookup in inventory |
| Rate limit exceeded? | Counter per signature per time window |

### LLM Judgment (Investigation Agent)

| Decision | Output Format |
|----------|---------------|
| "Does alert match precedent X?" | `{ "matches": bool, "similarity_notes": str }` |
| "Is condition C satisfied by evidence E?" | `{ "satisfied": bool, "evidence_ref": str }` |
| "What queries should we run?" | `{ "queries": [{ "source": str, "query": str }] }` |
| "What reproduction steps test hypothesis H?" | `{ "steps": [str], "expected_output": str }` |
| "Does reproduction output confirm hypothesis?" | `{ "confirmed": bool, "observations": str }` |
| "Summary for escalation" | `{ "summary": str, "key_findings": [str] }` |

**Key insight:** LLM provides structured boolean/enum outputs. Orchestrator does the math and makes final routing decisions.

---

## 5. Confidence Scoring Model

### Formula

```python
def calculate_confidence(
    precedent_tier: str,           # "gold", "silver", "bronze", None
    conditions_met: int,           # count of satisfied conditions
    conditions_total: int,         # total conditions to check
    evidence_available: bool,      # all required sources queryable
    reproduction_result: str,      # "confirmed", "refuted", "inconclusive", None
    asset_criticality: str,        # "standard", "elevated", "critical"
) -> float:

    # Base score from precedent quality (max 0.70)
    tier_scores = {"gold": 0.70, "silver": 0.50, "bronze": 0.30, None: 0.0}
    base = tier_scores.get(precedent_tier, 0.0)

    # Condition match ratio (max 0.20)
    if conditions_total > 0:
        condition_score = 0.20 * (conditions_met / conditions_total)
    else:
        condition_score = 0.0

    # Evidence availability (0.0 or 0.10)
    evidence_score = 0.10 if evidence_available else 0.0

    # Reproduction bonus/penalty
    repro_modifier = {
        "confirmed": 0.15,      # Boost confidence
        "inconclusive": 0.0,   # No change
        "refuted": -0.30,      # Strong penalty
        None: 0.0              # Not run
    }
    repro_score = repro_modifier.get(reproduction_result, 0.0)

    # Asset criticality penalty
    criticality_penalty = {
        "standard": 0.0,
        "elevated": -0.10,
        "critical": -0.25
    }
    asset_penalty = criticality_penalty.get(asset_criticality, 0.0)

    raw_score = base + condition_score + evidence_score + repro_score + asset_penalty
    return max(0.0, min(1.0, raw_score))
```

### Routing Thresholds

| Confidence | Action |
|------------|--------|
| ≥ 0.90 | Auto-close (with audit trail) |
| 0.70 - 0.89 | Trigger reproduction, then re-evaluate |
| < 0.70 | Escalate to human analyst |

### Escalation Triggers (Override Confidence)

Regardless of confidence score, escalate immediately when:

1. **No precedent match** — novel signature or pattern
2. **Critical asset involved** — predefined high-value assets always require human review
3. **Budget exhausted** — token or time limit reached without conclusion
4. **Conflicting evidence** — evidence contradicts precedent hypothesis
5. **Reproduction refuted** — isolated test disproved hypothesis
6. **System error** — MCP server unreachable, query timeout

---

## 6. Precedent System

### Quality Tiers

| Tier | Criteria | Auto-Resolution Authority |
|------|----------|---------------------------|
| **Gold** | Explicit root cause, documented evidence, "safe_when" conditions, ≥2 analysts verified, ≥N tickets with same resolution | Full (confidence base: 0.70) |
| **Silver** | Conclusion with partial reasoning, some evidence references | With lower confidence (base: 0.50) |
| **Bronze** | Resolution only, minimal documentation | Informational only, cannot justify closure (base: 0.30) |

### Precedent Schema

```yaml
precedent:
  id: string
  signature_id: string                    # Detection rule that triggered
  quality_tier: enum                      # gold, silver, bronze

  # Source validation
  source_tickets: list[string]            # Ticket IDs this was derived from
  analyst_count: int                      # Distinct analysts who verified
  created_at: datetime
  last_validated: datetime
  expiry: datetime                        # Requires revalidation after

  # Classification
  classification:
    root_cause_category: enum             # scheduled_task, misconfiguration,
                                          # legitimate_tool, policy_exception, etc.
    disposition: enum                     # false_positive, true_positive_expected,
                                          # true_positive_mitigated
    threat_level: enum                    # none, low, medium, high, critical

  # Conditions (hybrid: structured bank + natural language fallback)
  conditions:
    safe_when: list[Condition]            # All must be true for auto-resolution
    escalate_when: list[Condition]        # Any true forces escalation

  # Evidence requirements
  evidence:
    required_sources: list[string]        # Data sources that must be queried
    key_fields: list[string]              # Fields to extract and compare

  # Resolution template
  resolution:
    template: string                      # Resolution text with placeholders

  # Reproduction (optional)
  reproduction:
    applicable: bool                      # Can this hypothesis be reproduced?
    setup_steps: list[string]             # Environment setup instructions
    test_steps: list[string]              # Actions to execute
    expected_patterns: list[string]       # Log patterns that confirm hypothesis
```

### Condition Schema (Hybrid Approach)

```yaml
# Structured condition (preferred, deterministic evaluation)
- type: structured
  field: source_ip
  operator: in
  value: ${maintenance_ip_ranges}

# Natural language condition (fallback, LLM evaluation)
- type: natural_language
  description: "The process tree shows the activity originated from scheduled task manager"
  evidence_hint: "Check parent process and scheduled task logs"
```

**Condition Bank Evolution:**
- Start with natural language conditions
- When a condition is used successfully multiple times, convert to structured query
- Structured queries are faster and deterministic
- Natural language remains as fallback for edge cases

---

## 7. Context Loading (Not RAG)

Context is loaded deterministically by signature_id, not semantic search:

```
Alert arrives: signature_id = "wazuh-rule-5710"
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│  Hook: load_context_for_signature                               │
│                                                                 │
│  1. Precedent lookup:                                           │
│     SELECT * FROM precedents WHERE signature_id = ?             │
│     → Returns: precedent record (if exists)                     │
│                                                                 │
│  2. Past tickets (quality filter):                              │
│     SELECT * FROM tickets                                       │
│     WHERE signature = ?                                         │
│       AND status = 'closed'                                     │
│       AND disposition IN ('false_positive', 'true_positive_expected')  │
│     ORDER BY closed_at DESC                                     │
│     LIMIT 5                                                     │
│     → Returns: recent matching tickets                          │
│                                                                 │
│  3. Playbook lookup:                                            │
│     Load file: playbooks/{signature_category}.md                │
│     → Returns: investigation steps (if exists)                  │
│                                                                 │
│  4. Condition bank:                                             │
│     SELECT * FROM condition_bank WHERE signature_id = ?         │
│     → Returns: structured conditions for this signature         │
│                                                                 │
│  Output: Context bundle injected into agent system prompt       │
└─────────────────────────────────────────────────────────────────┘
```

**Benefits over RAG:**
- Deterministic retrieval (no semantic search failures)
- Auditable (exact query, exact results)
- Fast (indexed database lookups)
- No embedding model dependency

---

## 8. Reproduction Agent

### Purpose

Validate medium-confidence hypotheses (0.70-0.90) by recreating the suspected activity in an isolated environment and comparing observed behavior to expected patterns.

### When to Reproduce

| Scenario | Reproducible? | Example |
|----------|---------------|---------|
| "Alert caused by scheduled backup job" | Yes | Run backup script, compare logs |
| "File hash is legitimate software X" | Yes | Download known-good, compare hash |
| "Network connection from cron sync task" | Yes | Trigger sync, observe connection |
| "User performed legitimate admin action" | No | Requires user context, not reproducible |
| "Malware execution suspected" | Avoid | Use stricter sandboxing if needed |

### Isolation Requirements

```yaml
reproduction_sandbox:
  network:
    mode: none                    # No egress whatsoever

  filesystem:
    root: read-only              # Base image is immutable
    workspace: tmpfs             # Ephemeral, destroyed after

  resources:
    cpu_limit: "1.0"             # 1 CPU core max
    memory_limit: "512m"         # 512MB max
    timeout: 120s                # Hard kill after 2 minutes

  capabilities:
    drop: ALL                    # No Linux capabilities

  security:
    no_new_privileges: true
    seccomp: default             # Syscall filtering
```

### Reproduction Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│  REPRODUCTION AGENT                                             │
│                                                                 │
│  Inputs:                                                        │
│  • Hypothesis from investigation agent                          │
│  • Setup steps from precedent (or LLM-generated)                │
│  • Expected patterns from precedent                             │
│  • Relevant configuration (read-only fetch)                     │
│                                                                 │
│  Process:                                                       │
│  1. Build isolated environment                                  │
│     - Base image + required packages                            │
│     - Mount read-only config files                              │
│     - No network, no volume mounts to host                      │
│                                                                 │
│  2. Execute test steps                                          │
│     - Run commands specified in hypothesis                      │
│     - Capture stdout, stderr, exit codes                        │
│     - Monitor: process tree, file changes, syscalls             │
│                                                                 │
│  3. Compare results                                             │
│     - Pattern matching: expected_patterns vs observed logs      │
│     - LLM judgment: semantic similarity of behavior             │
│     - Hard checks: specific files created, exit codes           │
│                                                                 │
│  Output (structured):                                           │
│  {                                                              │
│    "confirmed": bool,                                           │
│    "confidence_modifier": float,  # +0.15 or -0.30              │
│    "observations": [str],                                       │
│    "pattern_matches": [                                         │
│      {"expected": str, "observed": str, "matched": bool}        │
│    ],                                                           │
│    "execution_log": str                                         │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
```

### Malware Avoidance

For alerts that may involve actual malware:

1. **Pre-filter**: If alert signature is in "potentially_malicious" category, skip reproduction
2. **Stricter sandbox**: If reproduction is attempted, use additional isolation:
   - gVisor/Kata containers for kernel-level isolation
   - No shared kernel with host
   - Memory dump analysis instead of execution (static analysis)
3. **Scope limit**: Reproduction is primarily for "software caused benign artifact" hypotheses, not malware analysis

---

## 9. Primary Triage Workflow

```
┌─────────────┐
│ Alert       │
│ Received    │
└──────┬──────┘
       │
       ▼
┌─────────────────┐     ┌─────────────────┐
│ Validate &      │────▶│ Reject          │ (malformed, rate limited)
│ Sanitize        │     │ with reason     │
└──────┬──────────┘     └─────────────────┘
       │ valid
       ▼
┌─────────────────┐
│ Load Context    │  ← Deterministic lookup by signature_id
│ (hook)          │    • Precedent, past tickets, playbook, condition bank
└──────┬──────────┘
       │
       ▼
┌─────────────────┐     ┌─────────────────┐
│ Precedent       │────▶│ No match:       │
│ Match?          │     │ Escalate as     │
│ (LLM judgment)  │     │ novel           │
└──────┬──────────┘     └────────┬────────┘
       │ match found             │
       ▼                         │
┌─────────────────┐              │
│ Gather Evidence │              │
│ (MCP queries)   │◀─────────────┘  (still gather context for analyst)
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Evaluate        │  ← LLM evaluates each condition
│ Conditions      │    Returns: { satisfied: bool, evidence_ref: str }
│ (LLM per cond)  │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Calculate       │  ← Orchestrator applies formula
│ Confidence      │    Inputs: tier, conditions_met, evidence, asset_criticality
│ (deterministic) │
└──────┬──────────┘
       │
       ├───────────────────────────────────────┐
       │                                       │
       ▼                                       ▼
┌─────────────────┐                   ┌─────────────────┐
│ confidence      │                   │ confidence      │
│ ≥ 0.90          │                   │ < 0.70          │
└──────┬──────────┘                   └──────┬──────────┘
       │                                     │
       ▼                                     ▼
┌─────────────────┐                   ┌─────────────────┐
│ Auto-close      │                   │ Escalate to     │
│ + audit trail   │                   │ analyst         │
└─────────────────┘                   └─────────────────┘

       │ confidence in [0.70, 0.90)
       ▼
┌─────────────────┐
│ Trigger         │
│ Reproduction    │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Reproduction    │  ← Isolated environment
│ Agent           │    Executes hypothesis test
└──────┬──────────┘
       │
       ├─────────────────────────────────────┐
       │                                     │
       ▼                                     ▼
┌─────────────────┐                 ┌─────────────────┐
│ confirmed       │                 │ refuted /       │
│                 │                 │ inconclusive    │
└──────┬──────────┘                 └──────┬──────────┘
       │                                   │
       ▼                                   ▼
┌─────────────────┐                 ┌─────────────────┐
│ Recalculate     │                 │ Escalate to     │
│ confidence      │                 │ analyst with    │
│ (+0.15 bonus)   │                 │ repro data      │
└──────┬──────────┘                 └─────────────────┘
       │
       ▼
┌─────────────────┐
│ If ≥ 0.90:      │
│ Auto-close      │
│ Else: Escalate  │
└─────────────────┘
```

---

## 10. Security Model

### Threat Model

| Threat | Attack Vector | Mitigation |
|--------|---------------|------------|
| Prompt injection | Malicious strings in alert fields | Input sanitization, field length limits, control char stripping |
| Precedent poisoning | Attacker creates FPs, analyst documents, attacker exploits | Quality tier requires ≥2 analysts, ≥N tickets, expiry dates |
| Denial of service | Alert flood | Rate limiting per signature, global throughput limits |
| Privilege escalation | Agent credentials misused | Minimal permissions, no creds in LLM context, scoped tokens |
| Reproduction escape | Code execution in sandbox | No egress, gVisor/Kata, resource limits, capability drop |

### Action Classification

| Action Type | Examples | Approval Required |
|-------------|----------|-------------------|
| Query | Log search, asset lookup | None |
| Annotate | Add comment, tag alert | None |
| Resolve | Close ticket as FP | Confidence threshold |
| Reversible | Disable account (with TTL) | Human approval (initially) |
| Irreversible | Delete data, permanent block | Always human approval |

### Hard Constraints (Never Violated)

1. No auto-resolution without precedent match
2. No irreversible actions without human approval
3. No credentials in LLM context
4. No reproduction with network egress
5. Audit logging cannot be disabled

---

## 11. Implementation Phases

### Phase 1: Core Prototype (Current Focus)

**Scope:**
- Single alert type (e.g., authentication anomaly from Wazuh)
- 3-5 manually curated gold-tier precedents
- Context loading via hooks (signature-based lookup)
- Investigation agent with condition evaluation
- Reproduction agent in isolated Docker container
- Deterministic confidence scoring
- Filesystem-based audit logging

**Deliverables:**
- Claude Code repository with skills and hooks
- Wazuh MCP server for SIEM queries
- PostgreSQL schema for tickets and precedents
- Reproduction sandbox container
- End-to-end triage demonstration

**Success Criteria:**
- Correctly auto-resolves alerts matching precedent (confidence ≥ 0.90)
- Correctly triggers reproduction for medium confidence (0.70-0.89)
- Correctly escalates novel/uncertain alerts (confidence < 0.70 or no precedent)
- Full reasoning chain captured in audit log

### Phase 2: Expanded Prototype

- Multiple alert types (5-10 signatures)
- Webhook integration with ticketing
- Condition bank evolution (NL → structured)
- Metrics dashboard
- Human feedback loop integration

### Phase 3: Production Hardening

- Framework migration (LangGraph or similar)
- Database-backed precedent store with versioning
- Formal security review
- Scalable deployment (Kubernetes)

---

## 12. Technology Stack (Phase 1)

| Component | Technology | Notes |
|-----------|------------|-------|
| Agent runtime | Claude Code | Prototype only, plan migration for production |
| LLM | Claude Sonnet | Via Claude Code |
| Tool integration | MCP servers | Wazuh, PostgreSQL |
| SIEM | Wazuh | Existing playground environment |
| Database | PostgreSQL + pgvector | Tickets, precedents, condition bank |
| Audit log | JSON files (append-only) | Simple, git-versioned |
| Reproduction sandbox | Docker (--network none) | gVisor for stricter isolation if needed |
| Context loading | Claude Code hooks | Trigger on alert ingestion |

---

## 13. Open Questions (To Refine Over Time)

1. **Reproduction trigger thresholds**: Start with 0.70-0.90, adjust based on observed escalation quality

2. **Precedent quality criteria**: Start with ≥2 analysts + ≥3 tickets, adjust based on override rates

3. **Condition bank growth**: Manual curation initially, later automate common pattern extraction

4. **Reproduction scope**: Which alert categories benefit most? Start with "scheduled task" and "legitimate tool" categories

5. **Feedback loop mechanics**: How does analyst override flow back to confidence weights and precedent quality?

---

## Appendix A: Example Alert Processing

**Alert:**
```json
{
  "ticket_id": "SEC-5678",
  "signature_id": "wazuh-rule-5710",
  "timestamp": "2025-11-26T02:47:00Z",
  "source_ip": "10.20.30.40",
  "target_account": "svc-backup-daily",
  "event_type": "authentication_anomaly"
}
```

**Context Loaded (by hook):**
- Precedent: `prec-auth-001` (gold tier, scheduled_maintenance)
- Past tickets: 5 similar closed as false_positive
- Condition bank: 4 structured conditions for this signature

**Investigation:**
1. LLM confirms precedent match: `{ "matches": true }`
2. LLM evaluates conditions:
   - `source_ip IN maintenance_ranges`: `{ "satisfied": true, "evidence_ref": "IP in 10.20.30.0/24" }`
   - `target_account MATCHES 'svc-*'`: `{ "satisfied": true, "evidence_ref": "svc-backup-daily" }`
   - `event_time BETWEEN 02:00-04:00 UTC`: `{ "satisfied": true, "evidence_ref": "02:47 UTC" }`
   - `scheduler.job_exists(correlation_id)`: `{ "satisfied": true, "evidence_ref": "job-backup-12345" }`
3. Evidence available: true (all queries succeeded)
4. Asset criticality: "standard"

**Confidence Calculation:**
```
base (gold):           0.70
conditions (4/4):      0.20
evidence:              0.10
reproduction:          0.00 (not triggered)
asset penalty:         0.00
─────────────────────────────
total:                 1.00 → clamped to 1.0
```

**Decision:** Auto-close (confidence 1.0 ≥ 0.90 threshold)

**Audit Log Entry:**
```json
{
  "decision_id": "dec-abc123",
  "ticket_id": "SEC-5678",
  "precedent_id": "prec-auth-001",
  "confidence": 1.0,
  "conditions_evaluated": [...],
  "decision": "auto_close",
  "reasoning": "All conditions satisfied, gold-tier precedent match"
}
```

---

## Appendix B: Example Reproduction Flow

**Alert:** Medium confidence (0.82) - "File created by legitimate backup software"

**Hypothesis:** The file `/tmp/backup-2025.tar.gz` was created by the scheduled backup job, not by malicious activity.

**Reproduction Steps:**
1. Build container with backup software installed
2. Mount backup configuration (read-only)
3. Execute backup job
4. Check if `/tmp/backup-*.tar.gz` is created
5. Compare file naming pattern and metadata

**Reproduction Output:**
```json
{
  "confirmed": true,
  "confidence_modifier": 0.15,
  "observations": [
    "Backup job created /tmp/backup-2025-11-26.tar.gz",
    "File size and permissions match alert artifact",
    "Process tree matches expected: cron -> backup.sh -> tar"
  ],
  "pattern_matches": [
    {"expected": "/tmp/backup-*.tar.gz", "observed": "/tmp/backup-2025-11-26.tar.gz", "matched": true}
  ]
}
```

**Updated Confidence:** 0.82 + 0.15 = 0.97 → Auto-close

---

*Document synthesized from original design documents and stakeholder clarifications.*
