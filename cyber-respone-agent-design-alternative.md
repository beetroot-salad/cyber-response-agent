# Defensive Cyber Response Agent

## Design & Architecture Document

**Version:** 0.1 (Prototype)  
**Status:** Draft  
**Last Updated:** November 2025

---

## 1. Executive Summary

This document describes the design of a defensive cyber response agent that automates security alert triage. The system targets the high-volume, low-complexity tier of security alerts — those that are most often false positives, duplicates, expected activity, or non-targeted trivial threats.

The agent reduces alert fatigue by applying precedent-based resolution: matching incoming alerts against previously investigated incidents with documented root causes and resolution criteria. When confident, the agent resolves alerts autonomously. When uncertain, it escalates to human analysts with enriched context.

**Key principle:** The system's value is not in being infallible, but in reliably knowing when it doesn't know.

---

## 2. Problem Statement

### The Alert Fatigue Problem

Security Operations Centers face a fundamental scaling challenge:

- Alert volume grows with infrastructure and detection coverage
- Most alerts (often 80-95%) are false positives, duplicates, or known benign activity
- Triage is repetitive: same investigation steps, same conclusions, same resolutions
- Analyst time is finite and expensive
- Alert fatigue leads to missed true positives

### Why Automation is Viable

The resolution process for routine alerts does not require novel thinking. It requires:

- Pattern matching against known scenarios
- Evidence gathering from logs and asset databases
- Comparison against established criteria
- Documentation of findings

These are tasks well-suited to an LLM-based agent with appropriate tooling and guardrails.

### What This System Is Not

This is not a threat detection system. It does not replace SIEM correlation rules, behavioral analytics, or threat intelligence feeds. It operates downstream of detection, automating the triage and resolution workflow.

This is not designed for novel or sophisticated threats. Anything that doesn't match established precedent should escalate to human analysts.

---

## 3. System Goals and Requirements

### Primary Goals

| Goal                                      | Success Metric                                                          |
| ----------------------------------------- | ----------------------------------------------------------------------- |
| Reduce analyst workload on routine alerts | 60-80% of eligible alerts auto-resolved                                 |
| Maintain security posture                 | <0.5% escalation override rate (analyst disagrees with auto-resolution) |
| Provide audit trail                       | 100% of decisions traceable with reasoning and evidence                 |
| Fail safely                               | Unknown patterns escalate, never auto-close                             |

### Functional Requirements

1. **Alert Ingestion** — Receive alerts from ticketing system via webhook or manual tagging
2. **Precedent Matching** — Query structured knowledge base of past investigations
3. **Evidence Gathering** — Query SIEM (Wazuh) and other data sources via MCP
4. **Confidence Scoring** — Quantify certainty in resolution decision
5. **Action Execution** — Update tickets, optionally execute response actions
6. **Escalation** — Route uncertain cases to human analysts with context
7. **Audit Logging** — Record all decisions, reasoning, and evidence

### Non-Functional Requirements

- **Latency:** Triage decision within 5 minutes for routine alerts
- **Availability:** Degraded mode (escalate all) if dependencies fail
- **Security:** No privilege escalation, defense in depth, input sanitization
- **Observability:** Metrics on resolution rates, confidence distributions, escalation reasons

---

## 4. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Ticketing System                              │
│                      (webhook on @agent mention)                        │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       Ingestion & Validation Layer                      │
│                                                                         │
│  • Input sanitization (defend against prompt injection)                 │
│  • Alert field normalization                                            │
│  • Deduplication check                                                  │
│  • Rate limiting                                                        │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Deterministic Orchestrator                         │
│                                                                         │
│  • State machine controlling investigation flow                         │
│  • Budget enforcement (token/time limits)                               │
│  • Escalation trigger evaluation                                        │
│  • Action approval gates                                                │
│  • Audit log writer                                                     │
└───────────┬─────────────────────────────────────────────┬───────────────┘
            │                                             │
            ▼                                             ▼
┌─────────────────────────────┐         ┌─────────────────────────────────┐
│      Precedent Store        │         │      Investigation Agent        │
│                             │         │          (LLM-powered)          │
│  Structured knowledge base  │         │                                 │
│  of past investigations:    │         │  • Reasoning about alerts       │
│                             │         │  • Query formulation            │
│  • signature_id             │         │  • Evidence interpretation      │
│  • root_cause_category      │         │  • Confidence assessment        │
│  • safe_when_conditions     │         │                                 │
│  • evidence_references      │         └───────────────┬─────────────────┘
│  • quality_tier             │                         │
│  • resolution_template      │                         │
└─────────────────────────────┘                         │
                                                        ▼
                              ┌──────────────────────────────────────────┐
                              │              MCP Servers                 │
                              │                                          │
                              │  • Wazuh API (log queries)               │
                              │  • Asset inventory                       │
                              │  • Identity management                   │
                              │  • Ticketing system                      │
                              │  • Remote execution (gated)              │
                              └──────────────────────────────────────────┘
                                                        │
                                                        ▼
                              ┌──────────────────────────────────────────┐
                              │       Reproduction Agent (Optional)      │
                              │                                          │
                              │  • Isolated Docker-in-Docker environment │
                              │  • Read-only access to prod configs      │
                              │  • Hypothesis validation via simulation  │
                              │  • Log comparison for confirmation       │
                              └──────────────────────────────────────────┘
```

### Component Responsibilities

**Ingestion & Validation Layer**

- First line of defense against malicious input
- Normalizes alert fields to consistent schema
- Checks for duplicate/recent alerts on same entity
- Enforces rate limits to prevent alert storms from overwhelming the agent

**Deterministic Orchestrator**

- Controls the investigation state machine (not the LLM)
- Enforces hard limits on token consumption and wall-clock time
- Evaluates escalation criteria after each investigation step
- Gates any write/action operations pending approval rules
- Writes immutable audit log entries

**Precedent Store**

- Structured database of past investigations (not raw tickets)
- Queryable by signature ID, affected asset type, root cause category
- Each precedent has explicit quality tier and applicability conditions
- Separated from operational ticket system for reliability

**Investigation Agent**

- LLM-powered reasoning component (Claude via Claude Code in prototype)
- Formulates queries, interprets evidence, assesses confidence
- Does NOT control its own execution — orchestrator decides next steps
- Output is structured (confidence score, reasoning, evidence refs)

**MCP Servers**

- Standardized interface to external systems
- Each server has explicit capability scope (read-only vs read-write)
- Enables tool swapping without agent logic changes

**Reproduction Agent** (Optional, Phase 2)

- Validates hypotheses by recreating conditions in isolation
- Useful for "software X creates artifact Y" type confirmations
- Adds confidence but not required for basic operation

---

## 5. Workflows

### 5.1 Primary Triage Workflow

```
┌─────────────┐
│ Alert       │
│ Received    │
└──────┬──────┘
       │
       ▼
┌─────────────────┐     ┌─────────────┐
│ Validate &      │────▶│ Reject      │ (malformed, rate limited)
│ Sanitize        │     │ with reason │
└──────┬──────────┘     └─────────────┘
       │ valid
       ▼
┌─────────────────┐
│ Extract         │
│ Signature &     │
│ Context         │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐     ┌─────────────┐
│ Lookup          │────▶│ No match:   │
│ Precedent       │     │ Flag as     │
└──────┬──────────┘     │ novel       │
       │ match found    └──────┬──────┘
       ▼                       │
┌─────────────────┐            │
│ Gather          │            │
│ Evidence        │◀───────────┘
│ (MCP queries)   │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Evaluate        │
│ Against         │
│ Precedent       │
│ Conditions      │
└──────┬──────────┘
       │
       ├─────────────────────────────────────┐
       │                                     │
       ▼                                     ▼
┌─────────────────┐                 ┌─────────────────┐
│ High Confidence │                 │ Low Confidence  │
│ (≥0.85)         │                 │ or Novel        │
└──────┬──────────┘                 └──────┬──────────┘
       │                                   │
       ▼                                   ▼
┌─────────────────┐                 ┌─────────────────┐
│ Auto-resolve    │                 │ Escalate to     │
│ with audit      │                 │ analyst with    │
│ trail           │                 │ context         │
└─────────────────┘                 └─────────────────┘
```

### 5.2 Confidence Scoring Model

Confidence is computed from multiple factors:

| Factor                       | Weight | Description                                        |
| ---------------------------- | ------ | -------------------------------------------------- |
| Precedent quality tier       | 30%    | Gold (1.0), Silver (0.7), Bronze (0.4), None (0.0) |
| Condition match completeness | 25%    | All "safe when" conditions verified vs partial     |
| Evidence availability        | 20%    | Required logs present and queryable                |
| Temporal consistency         | 15%    | Pattern timing matches precedent                   |
| Asset criticality modifier   | 10%    | Reduces confidence for high-value assets           |

**Thresholds:**

- ≥0.85: Auto-resolve eligible
- 0.60-0.84: Auto-resolve with flag for periodic review
- <0.60: Escalate to analyst

### 5.3 Escalation Triggers

The system escalates immediately (regardless of confidence score) when:

1. **Budget exhausted** — Token limit or time limit reached without conclusion
2. **Novel pattern** — No matching precedent signature exists
3. **High-value asset** — Predefined critical assets always require human review
4. **Conflicting evidence** — Evidence contradicts the precedent hypothesis
5. **Action approval denied** — Human rejected a proposed response action
6. **System error** — MCP server unreachable, query timeout, etc.

### 5.4 Precedent-Based Resolution Example

**Scenario:** Recurring "suspicious authentication" alert for a service account

**Precedent Record:**

```yaml
signature_id: "auth_anomaly_service_account"
quality_tier: "gold"
root_cause_category: "scheduled_maintenance"
safe_when:
  - "source_ip in known_maintenance_ranges"
  - "target_account matches 'svc-*' pattern"
  - "time_of_day between 02:00-04:00 UTC"
  - "associated_job_id exists in scheduler"
evidence_required:
  - "authentication_logs_24h"
  - "scheduler_job_list"
resolution_template: |
  Automated resolution: Recurring maintenance activity.
  Service account {account} authenticated from {source_ip}
  as part of scheduled job {job_id}. Pattern matches
  precedent from ticket {original_ticket}.
```

**Agent Workflow:**

1. Receives alert, extracts signature → matches "auth_anomaly_service_account"
2. Retrieves gold-tier precedent with conditions
3. Queries Wazuh for authentication logs (MCP)
4. Queries scheduler for active jobs (MCP)
5. Evaluates each "safe_when" condition:
   - Source IP 10.20.30.40 → check known_maintenance_ranges → ✓
   - Account svc-backup → matches pattern → ✓
   - Time 02:47 UTC → in range → ✓
   - Job ID job-12345 → exists in scheduler → ✓
6. All conditions met, evidence complete → confidence 0.92
7. Auto-resolve with templated resolution, log full reasoning

---

## 6. Knowledge Integration

### 6.1 Precedent Quality Tiers

Not all past investigations are equally reliable as precedent. The system classifies source tickets into quality tiers:

| Tier       | Criteria                                                                                | Usage                                                                   |
| ---------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **Gold**   | Has: explicit root cause, documented evidence, "safe when" conditions, analyst-verified | Full auto-resolution authority                                          |
| **Silver** | Has: conclusion and partial reasoning, some evidence references                         | Auto-resolve with lower confidence, flag for review                     |
| **Bronze** | Has: resolution only, minimal documentation                                             | Informational only ("this has happened before"), cannot justify closure |

### 6.2 Precedent Schema

```yaml
precedent:
  id: string # Unique identifier
  signature_id: string # Detection rule/signature that triggered
  quality_tier: enum # gold, silver, bronze
  created_from_ticket: string # Original ticket reference
  created_at: datetime
  last_validated: datetime # When human last confirmed still valid

  classification:
    root_cause_category: enum # Enumerated cause types
    disposition:
      enum # false_positive, true_positive_expected,
      # true_positive_mitigated, etc.
    threat_level: enum # none, low, medium, high, critical

  conditions:
    safe_when: list[string] # All must be true for auto-resolution
    escalate_when: list[string] # Any true forces escalation

  evidence:
    required_sources: list[string] # Data sources that must be queried
    key_fields: list[string] # Fields to extract and compare

  resolution:
    template: string # Resolution text template
    actions: list[action] # Optional response actions

  metadata:
    author: string
    review_history: list[review]
    expiry: datetime # Precedent requires revalidation after this
```

### 6.3 Forward-Looking Quality Enforcement

Rather than retrofitting quality onto old tickets, enforce it on new closures:

When an analyst closes a ticket matching a recurring signature, the system prompts for structured fields:

- Root cause category (enumerated dropdown)
- "Safe when" conditions (freeform but required)
- Evidence references (links to queries, screenshots)

The agent can act as a "documentation assistant" — asking clarifying questions before accepting closure. This improves precedent quality over time without requiring batch remediation of historical data.

### 6.4 Handling Poor Documentation

For alerts where existing documentation is insufficient:

1. **Conservative default** — If precedent doesn't meet quality bar, don't use it for auto-resolution
2. **Context provision** — Still surface the prior ticket to analysts ("similar alert was investigated in TICKET-1234")
3. **Quality feedback loop** — Track which signatures lack usable precedent, prioritize for documentation improvement

The enrichment pipeline concept (agents evaluating reasoning quality) is deferred to Phase 2. It introduces friction and complexity that isn't justified until the core system proves value.

---

## 7. Security Model

### 7.1 Threat Model

| Threat                | Attack Vector                                                                       | Impact                                     |
| --------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------ |
| Prompt injection      | Malicious strings in alert fields (filenames, process args, user-controlled data)   | Agent takes unintended actions, leaks data |
| Precedent poisoning   | Attacker creates false positives, analyst documents them, attacker exploits pattern | Future attacks auto-closed                 |
| Denial of service     | Alert flood to exhaust agent resources                                              | Agent unavailable, alerts pile up          |
| Privilege escalation  | Agent credentials used to access unauthorized systems                               | Lateral movement                           |
| Decision manipulation | Attacker learns agent patterns, crafts alerts to trigger desired response           | Automated response weaponized              |

### 7.2 Mitigations

**Input Sanitization**

- All alert fields treated as untrusted
- Strip or escape control characters, markdown, code blocks
- Limit field lengths
- Reject alerts with suspicious patterns (e.g., instructions embedded in filenames)

**Principle of Least Privilege**

- MCP servers have minimal required permissions
- Read-only by default, write operations require explicit grants
- Credentials scoped to specific systems, not broad service accounts
- No credential storage in agent context — fetched at runtime from secrets manager

**Action Classification and Gating**

| Action Type  | Examples                                  | Approval Required                                |
| ------------ | ----------------------------------------- | ------------------------------------------------ |
| Query        | Log search, asset lookup                  | None (auto-approve)                              |
| Annotate     | Add comment to ticket, tag alert          | None                                             |
| Resolve      | Close ticket as false positive            | Confidence threshold                             |
| Reversible   | Disable user account, block IP (with TTL) | Human approval initially, policy-based over time |
| Irreversible | Delete data, permanent block              | Always human approval                            |

**Rate Limiting**

- Per-signature rate limits (prevent single noisy rule from consuming all capacity)
- Global throughput limits
- Backpressure to ticketing system (stop accepting if queue depth exceeds threshold)

**Audit Trail**

- Append-only log of all decisions
- Full reasoning chain, not just conclusion
- Evidence snapshots (query results at decision time)
- Tamper-evident (signed entries or write-once storage)

**Precedent Integrity**

- Quality tier assignment requires human review
- Precedents expire and require revalidation
- Anomaly detection on precedent usage (sudden spike in matches)

### 7.3 Reproduction Agent Security

The reproduction agent has elevated risk due to code execution capabilities:

| Control               | Implementation                                                     |
| --------------------- | ------------------------------------------------------------------ |
| Network isolation     | Spawned containers have no egress (iptables DROP)                  |
| Filesystem isolation  | Docker-in-Docker with no volume mounts to host                     |
| Read-only prod access | Config fetching limited to allowlisted paths                       |
| Resource limits       | CPU, memory, disk quotas on spawned containers                     |
| Time limits           | Hard timeout, containers killed after threshold                    |
| Output sanitization   | Structured output only, no raw command output passed to main agent |

---

## 8. Considered Approaches

### 8.1 Agent Framework Selection

| Approach                    | Pros                                                                                                    | Cons                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| **Claude Code (prototype)** | Rapid iteration, built-in tool execution, context management, hooks/skills system, filesystem-as-config | Hard vendor lock-in, less control over context management, non-trivial state persistence |
| **LangChain/LangGraph**     | Framework flexibility, model-agnostic, explicit state machines, large ecosystem                         | More implementation work, need to handle tool execution and context compaction           |
| **Custom orchestration**    | Full control, minimal dependencies                                                                      | Highest implementation effort, reinventing solved problems                               |

**Decision:** Claude Code for prototype/portfolio. The reduced time-to-working-demo outweighs lock-in concerns for a learning project. Production system should migrate to LangGraph or similar for operational flexibility.

### 8.2 Knowledge Retrieval

| Approach                       | Pros                                                                    | Cons                                                        |
| ------------------------------ | ----------------------------------------------------------------------- | ----------------------------------------------------------- |
| **RAG over raw tickets**       | Uses existing data, semantic flexibility                                | Expensive, retrieval quality varies, garbage in/garbage out |
| **Structured precedent store** | Predictable retrieval, explicit quality control, queryable by signature | Requires upfront curation, less flexible                    |
| **Hybrid**                     | Best of both                                                            | Implementation complexity                                   |

**Decision:** Structured precedent store for prototype. RAG's failure modes (retrieving plausible but wrong context) are unacceptable in a security context. Structured retrieval by signature ID + asset type is reliable and auditable.

### 8.3 Confidence Modeling

| Approach                | Pros                          | Cons                                     |
| ----------------------- | ----------------------------- | ---------------------------------------- |
| **LLM self-assessment** | Simple to implement, flexible | Unreliable, models are poorly calibrated |
| **Rule-based scoring**  | Predictable, explainable      | Rigid, requires manual tuning            |
| **Learned calibration** | Potentially well-calibrated   | Requires labeled data, complexity        |

**Decision:** Rule-based scoring for prototype. LLM confidence statements ("I'm 80% sure") are not trustworthy. A deterministic scoring function based on precedent quality, condition match completeness, and evidence availability is more reliable.

---

## 9. Tradeoffs

### Automation Scope vs Safety

**Narrow scope (prototype):** Only auto-resolve alerts with gold-tier precedent and 85%+ confidence. Everything else escalates.

_Tradeoff:_ Lower automation rate, but minimal risk of false negatives. Appropriate for proving the concept and building trust.

**Broader scope (future):** Lower confidence thresholds, silver-tier precedent eligible, policy-based action approval.

_Tradeoff:_ Higher automation rate, but requires extensive validation and monitoring.

### Documentation Quality vs Adoption Friction

**High bar:** Require comprehensive documentation for any precedent.

_Tradeoff:_ Better automation quality, but analysts may resist the additional work, reducing precedent coverage.

**Low bar:** Accept minimal documentation, infer conditions.

_Tradeoff:_ More precedents available, but higher false negative risk.

**Compromise:** Tiered system. Accept all documentation but classify by quality. Only gold-tier enables full automation. This lets the system provide value immediately while incentivizing better documentation.

### Reproduction Agent Complexity vs Confidence Gain

**Include reproduction:** Higher confidence in verdicts, especially for "software caused this artifact" hypotheses.

_Tradeoff:_ Significant implementation complexity, additional attack surface, slower triage.

**Exclude reproduction:** Simpler system, faster decisions.

_Tradeoff:_ Lower confidence ceiling for certain alert types.

**Decision:** Defer reproduction agent to Phase 2. Core value proposition doesn't depend on it.

---

## 10. Guardrails and Constraints

### Hard Constraints (Never Violated)

1. **No auto-resolution without precedent** — Novel patterns always escalate
2. **No irreversible actions without human approval** — Ever
3. **No credential access in agent context** — Secrets fetched at runtime, scoped to request
4. **No direct code execution on production hosts** — Query only, or isolated reproduction
5. **Audit logging cannot be disabled** — Every decision recorded

### Soft Constraints (Configurable per Policy)

| Constraint                            | Default   | Rationale        |
| ------------------------------------- | --------- | ---------------- |
| Max tokens per investigation          | 50,000    | Cost control     |
| Max wall-clock time                   | 5 minutes | SLA              |
| Min confidence for auto-resolve       | 0.85      | Safety margin    |
| Precedent max age before revalidation | 90 days   | Drift protection |
| High-value asset auto-resolve         | Disabled  | Risk-based       |

### Operational Guardrails

- **Circuit breaker:** If escalation override rate exceeds threshold (analysts disagreeing with auto-resolutions), halt auto-resolution globally pending review
- **Anomaly detection:** Alert on unusual patterns (sudden spike in auto-resolutions, new signature suddenly matching many precedents)
- **Graceful degradation:** If SIEM unavailable, escalate all (don't guess)

---

## 11. Implementation Phases

### Phase 1: Prototype (Claude Code)

**Scope:**

- Single alert type (e.g., authentication anomaly from Wazuh)
- Manually curated precedents (3-5 gold-tier)
- Read-only investigation (no automated response actions)
- Filesystem-based alert input (no webhook integration)
- Local audit logging (JSON files)

**Deliverables:**

- Working Claude Code repository with skills and hooks
- MCP server for Wazuh queries
- Precedent store (YAML files)
- Demonstration of end-to-end triage workflow

**Success Criteria:**

- Correctly auto-resolves alerts matching precedent
- Correctly escalates novel/uncertain alerts
- Full reasoning captured in audit log

### Phase 2: Expanded Prototype

**Scope:**

- Multiple alert types (3-5 signatures)
- Webhook integration with ticketing system
- Basic response actions (with approval gate)
- Reproduction agent for hypothesis validation
- Metrics dashboard

### Phase 3: Production Architecture (Framework Migration)

**Scope:**

- Migrate to LangGraph or equivalent
- Model flexibility (not locked to Claude)
- Scalable precedent store (database-backed)
- Integration with enterprise ticketing, SIEM, identity systems
- Comprehensive monitoring and alerting
- Formal security review

---

## 12. Technology Stack

### Prototype (Phase 1)

| Component        | Technology               | Notes                     |
| ---------------- | ------------------------ | ------------------------- |
| Agent runtime    | Claude Code (headless)   | Rapid prototyping         |
| LLM              | Claude (Sonnet or Opus)  | Via Claude Code           |
| Tool integration | MCP servers              | Python-based              |
| SIEM             | Wazuh                    | Existing environment      |
| Precedent store  | YAML files               | Git-versioned             |
| Audit log        | JSON files               | Append-only               |
| Orchestration    | Claude Code hooks + bash | Lightweight state machine |

### Production (Phase 3)

| Component        | Technology                               | Notes                        |
| ---------------- | ---------------------------------------- | ---------------------------- |
| Agent runtime    | Python with LangGraph                    | Model-agnostic orchestration |
| LLM              | Configurable (Claude, GPT-4, etc.)       | Abstracted behind interface  |
| Tool integration | MCP servers                              | Same as prototype            |
| SIEM             | Wazuh / Splunk / Elastic                 | Pluggable                    |
| Precedent store  | PostgreSQL + vector store                | Structured + semantic search |
| Audit log        | Immutable ledger (e.g., S3 + write-once) | Compliance-grade             |
| Orchestration    | LangGraph state machine                  | Explicit, debuggable         |
| Deployment       | Kubernetes                               | Scalable, observable         |

---

## 13. Open Questions

1. **Precedent authoring workflow:** How do analysts create/update precedents? Dedicated UI? Structured ticket fields? Agent-assisted extraction?

2. **Multi-tenancy:** If deployed for multiple teams/environments, how is precedent scoped? Shared vs team-specific?

3. **Feedback loop:** How does analyst feedback (override auto-resolution) flow back to precedent quality scores?

4. **Reproduction agent scope:** Which alert types benefit enough from reproduction to justify the complexity?

5. **Metrics that matter:** Beyond resolution rate and override rate, what indicates the system is working well?

---

## 14. References

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## Appendix A: Precedent Example

```yaml
id: "prec-auth-001"
signature_id: "wazuh-rule-5710"
quality_tier: "gold"
created_from_ticket: "SEC-12345"
created_at: "2025-06-15T10:30:00Z"
last_validated: "2025-09-20T14:00:00Z"

classification:
  root_cause_category: "scheduled_maintenance"
  disposition: "true_positive_expected"
  threat_level: "none"

conditions:
  safe_when:
    - "source_ip IN ${maintenance_ip_ranges}"
    - "target_account MATCHES 'svc-backup-*'"
    - "event_time BETWEEN '02:00' AND '04:00' UTC"
    - "scheduler.job_exists(${correlation_id})"
  escalate_when:
    - "failed_attempt_count > 10"
    - "target_account IN ${privileged_accounts}"

evidence:
  required_sources:
    - "wazuh.authentication_logs"
    - "scheduler.job_registry"
  key_fields:
    - "source_ip"
    - "target_account"
    - "event_time"
    - "correlation_id"

resolution:
  template: |
    **Automated Resolution: Expected Maintenance Activity**

    Alert matched precedent prec-auth-001 (ticket SEC-12345).

    Findings:
    - Source IP {source_ip} is in maintenance range
    - Account {target_account} is designated service account
    - Event time {event_time} within maintenance window
    - Correlated with scheduled job {job_id}

    Disposition: True positive, expected activity. No action required.
  actions: []

metadata:
  author: "analyst@example.com"
  review_history:
    - reviewer: "senior-analyst@example.com"
      date: "2025-06-16T09:00:00Z"
      outcome: "approved_gold"
    - reviewer: "senior-analyst@example.com"
      date: "2025-09-20T14:00:00Z"
      outcome: "revalidated"
  expiry: "2025-12-20T00:00:00Z"
```

---

## Appendix B: Audit Log Schema

```json
{
  "decision_id": "uuid",
  "timestamp": "iso8601",
  "alert": {
    "ticket_id": "string",
    "signature_id": "string",
    "raw_fields": {}
  },
  "precedent_match": {
    "precedent_id": "string | null",
    "quality_tier": "string | null",
    "match_confidence": "float"
  },
  "evidence_gathered": [
    {
      "source": "string",
      "query": "string",
      "result_summary": "string",
      "timestamp": "iso8601"
    }
  ],
  "condition_evaluation": [
    {
      "condition": "string",
      "result": "boolean",
      "evidence_ref": "string"
    }
  ],
  "confidence_score": {
    "overall": "float",
    "components": {
      "precedent_quality": "float",
      "condition_match": "float",
      "evidence_completeness": "float",
      "temporal_consistency": "float",
      "asset_criticality_modifier": "float"
    }
  },
  "decision": {
    "action": "auto_resolve | escalate | error",
    "reason": "string",
    "resolution_text": "string | null"
  },
  "execution": {
    "actions_taken": [],
    "ticket_updated": "boolean",
    "errors": []
  },
  "metadata": {
    "agent_version": "string",
    "model": "string",
    "token_usage": "int",
    "wall_clock_ms": "int"
  }
}
```
