# Schema & Data Model Review

Working document for reviewing all schemas/models in the architecture, one by one.

**Status legend:** DONE = reviewed and updated in architecture doc | TODO = not yet reviewed

---

## 1. Input: Alert Data — DONE

The entry point. Comes from SIEM, passes through sanitization before the agent sees it.

```json
{
  "ticket_id": "SEC-TEST-001",
  "signature_id": "wazuh-rule-5710",
  "agent": "web-server-01",
  "timestamp": "2024-11-15T02:30:00Z",
  "srcip": "10.0.1.50",
  "srcuser": "testuser",
  "severity": "medium",
  "rule_id": 5710,
  "rule_description": "sshd: Attempt to login using a non-existent user"
}
```

Sanitized by `sanitize-input.sh` (pre-invocation) and wrapped in per-run salted delimiters `<run-{salt}-alert-data>`.

**Review decisions:**
- No global field dictionary — Claude infers standard SIEM fields from context
- Exception-only field docs at two KB levels: `knowledge/common/data-sources/` (per data source) and `knowledge/signatures/{id}/field-notes.md` (per signature)
- Both maintained via post-mortem proposals, not pre-configured
- Sanitization is narrow (control chars, length limits, salted delimiters) — honest about what it doesn't stop
- §8 rewritten: "Security: Untrusted Data Handling" with code injection threat model, interactive mode trust boundary

---

## 2. Run Directory (Agent State Files)

Each investigation creates `runs/{run_id}/` (agent-accessible) and `hooks/{run_id}/` (hook-managed, agent cannot access).

### 2.1 `state.json` — Phase Machine — DONE

```json
{
  "created_at": "2026-03-12T14:30:00Z",
  "updated_at": "2026-03-12T14:32:15Z",
  "current_phase": "GATHER",
  "previous_phase": "HYPOTHESIZE",
  "iteration": 1,
  "transitions": [
    { "from": "CONTEXTUALIZE", "to": "HYPOTHESIZE", "at": "2026-03-12T14:31:00Z" },
    { "from": "HYPOTHESIZE", "to": "GATHER", "at": "2026-03-12T14:32:15Z" }
  ]
}
```

**Validated by `validate-transition.sh`** on every write. Legal transitions:
```
CONTEXTUALIZE → HYPOTHESIZE → GATHER → ANALYZE → HYPOTHESIZE (loop)
                                                → CONCLUDE    (exit)
```

**Review decisions:**
- Added `created_at`/`updated_at` timestamps
- Removed investigation content (hypotheses, planned leads, adversarial_hypothesis_present) — moved to narrative + leads/
- Hook validates structural transitions only — can't verify agent-written content claims
- Transition log enables post-hoc pacing analysis

### 2.2 `budget.json` — Resource Tracking — DONE

```json
{
  "run_id": "run-abc123",
  "tool_calls": 12,
  "subagent_spawns": 2,
  "started_at": "2026-03-12T14:30:00Z"
}
```

**Enforced by `budget-enforcer.sh`** per tool call. Exhaustion forces conclude/escalate.

**Review decisions:**
- Moved to `hooks/{run_id}/` — physically inaccessible to agent
- Counters only — limits are config (`config/budget-defaults.yaml`, overridable per-signature in `permissions.yaml`)
- Agent learns of exhaustion through hook rejection messages, not by reading the file
- Wall-clock checked by hook comparing `now - started_at` against config

### 2.3 `leads/{lead-name}.json` — Evidence from Each Lead — TODO

```json
{
  "lead": "authentication-history",
  "method_used": "Wazuh search_events for srcip auth logs",
  "raw_result_summary": "3 successful SSH logins from 10.0.1.50 in past 7 days",
  "interpretation": "Source IP is a known, regularly authenticating host",
  "supports_hypothesis": "monitoring_probe",
  "contradicts_hypothesis": null,
  "confidence_in_evidence": "high",
  "new_leads_suggested": []
}
```

This is both the **lead subagent output** and what gets persisted.

### 2.4 `report.md` — Unified Investigation Output — DONE

Single file replaces the previous `recommendation.json` + `narrative-report.md` split. YAML frontmatter for hook validation, markdown body for analysts.

```markdown
---
ticket_id: "SEC-001"
signature_id: "wazuh-rule-5710"
signature_description: "sshd: Attempt to login using a non-existent user"
status: "resolved"                    # resolved | escalate
disposition: "benign"                 # benign | false_positive | true_positive
confidence: "high"                    # high | medium | low
matched_precedent: "SEC-2024-001"     # ticket_id | null
leads_pursued: 3
---

# Investigation Report: SEC-001

## Summary

Source IP 10.0.1.50 attempted SSH login as non-existent user "testuser"
on web-server-01. Authentication history shows a regular 5-minute interval
pattern with a single username from a known monitoring subnet (10.0.1.0/24),
consistent with an automated health check. This matches precedent
SEC-2024-001 (monitoring probe). No indicators of brute force or credential
stuffing were found — single username, no success-after-failure, internal source.

**Recommendation: Benign — monitoring probe (high confidence)**

## Investigation Log

### Lead 1: Authentication History
Queried Wazuh auth events for 10.0.1.50 → web-server-01, last 7 days.
- 47 failed auth events, all username "testuser"
- Regular 5-minute intervals (consistent with cron/monitoring)
- No successful logins following failures
- Outcome: Supports monitoring probe, refutes brute force

### Lead 2: Source Reputation
...

### Lead 3: Recent Alert Correlation
...
```

**Review decisions:**
- Merged structured recommendation and narrative report into a single file — eliminates redundancy, the JSON fields were mostly duplicating what the prose said
- Dropped `classification`, `matched_tier`, `lead_outcome_tags`, `hypotheses` array, `reproduction_result`, `evidence_conflicts` from structured fields — these either belong in the precedent record (post-mortem) or can't be meaningfully validated by hooks
- Kept `leads_pursued` as integer count for minimum evidence enforcement
- `confidence` remains an agent signal for analysts, not a guardrail input

**Stop hook validation is two-tier:**

| Tier | Check | Source | Failure action |
|------|-------|--------|----------------|
| **1: Deterministic** | Frontmatter schema valid | Frontmatter | Reject |
| 1 | `leads_pursued` >= minimum for severity | Frontmatter | Reject |
| 1 | `matched_precedent` non-null if status=resolved | Frontmatter | Override → escalate |
| 1 | Precedent exists, signature matches, structural overlap | Precedent file + alert | Override → escalate |
| 1 | Escalation pattern match | Alert data | Override → escalate |
| 1 | Critical asset check | Alert data | Override → escalate |
| **2: Semantic judge** | Precedent match validity | Report + precedent + alert | Override → escalate |
| 2 | Internal consistency (summary vs investigation log) | Report | Override → escalate |
| 2 | Unsupported conclusions | Report + alert | Override → escalate |
| 2 | Weak assumptions or missing obvious checks | Report + alert | Override → escalate |
| — | Action gating (act vs recommend) | Config | — |
| — | Audit logging | Frontmatter + alert | — |

Tier 1 runs first (milliseconds). Tier 2 runs only if Tier 1 passes — lightweight LLM (Haiku-class) that already has the precedent and alert in context for the match check. The semantic judge returns `pass` or `flag` with a reason. `flag` → escalate.

### 2.5 `audit-log.json` — External Action Log — DONE

Log of every external action (tool calls, script executions) performed during the investigation. This is an access log, not a reasoning trace — for investigation logic, read the report's investigation log.

```json
{
  "entries": [
    {
      "timestamp": "2026-03-12T14:31:02Z",
      "ticket_id": "SEC-001",
      "agent": "investigator",
      "action": "mcp_tool_call",
      "tool": "wazuh_search_events",
      "parameters": {"q": "srcip:10.0.1.50 AND rule.id:5710", "time_range": "7d", "limit": 100},
      "script_path": null
    },
    {
      "timestamp": "2026-03-12T14:31:05Z",
      "ticket_id": "SEC-001",
      "agent": "lead:authentication-history",
      "action": "script_execution",
      "tool": "python",
      "parameters": {"args": ["--srcip", "10.0.1.50"]},
      "script_path": "scripts/001-query-auth-events.py"
    }
  ]
}
```

**Review decisions:**
- Purpose is auditing external side effects ("who accessed what, when"), not debugging agent logic
- `agent` field identifies the caller: `"investigator"` or `"lead:{name}"` — useful for "who accessed what" audit even though it's not for logic debugging
- `script_path` is non-null only for agent-generated script executions, references the saved script in `scripts/`
- Written by `audit-logger.sh` hook on every tool call and at stop

### 2.6 `scripts/` — Agent-Written Scripts — DONE

Every script the agent generates is saved to `{run_dir}/scripts/` before execution. Scripts are the primary audit trail for what the agent actually ran against external systems.

**Security model — container isolation as primary defense, hook validation as defense-in-depth:**

1. **Container isolation (primary):** Scripts execute in a minimal container with:
   - Network: allowlist of SIEM and ticketing endpoints only
   - Filesystem: run directory mounted read-write, everything else read-only
   - No capabilities, no elevated privileges
   - Credentials injected via environment variables (`$WAZUH_API_TOKEN`)
   - Per-script timeout (30s default)

2. **Pre-execution hook (defense-in-depth):** `validate-script.sh` performs static checks before the container runs:
   - Python: AST-parsed for disallowed imports (`subprocess`, `os.system`, `eval`, `exec`, `importlib`, `ctypes`)
   - Bash: reject entirely, or allowlist specific patterns
   - Network targets validated against allowed endpoints
   - Suspicious patterns flagged

3. **Approved script library:** Pre-approved parameterized scripts that bypass hook validation (already trusted). Agent can use these directly or write new scripts that go through the hook + container pipeline.

**Review decisions:**
- Static analysis alone is insufficient — LLM-generated code can evade pattern matching in many ways. Container isolation bounds the blast radius even when the hook misses something
- Similar to how CI systems run untrusted build scripts: container with scoped network
- The container is lightweight (not the reproduction sandbox) — minimal Python/bash runtime, no OS simulation needed
- Approved script library provides a fast path for common queries without container overhead

### 2.7 `proposals/` — Post-Mortem KB Updates — TODO

Generated by `post-mortem.sh` stop hook. Contains: precedent JSON, KB diffs, lessons.

---

## 3. Agent-to-Agent Interfaces — TODO

### 3.1 Investigator → Lead Subagent

**Input:**
```json
{
  "lead": "source-reputation",
  "motivation": "Determine if source IP is known malicious",
  "context": { "srcip": "10.0.1.50", "signature_id": "wazuh-rule-5710" },
  "available_tools": ["search_events", "get_agent_info"]
}
```

**Output:** The lead evidence JSON (§2.3 above).

### 3.2 Investigator → Reproduction Agent (via orchestrator)

**Request (embedded in recommendation):**
```json
{
  "hypothesis": "backup.sh creates /tmp/backup.tar.gz triggering rule 5710",
  "environment_hint": "Ubuntu with sshd",
  "timeout_seconds": 120
}
```

**Reproduction output:**
```json
{
  "result": "confirmed|refuted|inconclusive",
  "hypothesis_tested": "backup.sh creates /tmp/backup.tar.gz",
  "observations": ["Process spawned as expected", "Alert generated matching signature"],
  "not_reproducible_reason": null
}
```

### 3.3 Cross-Agent Read-Only Access

Agents can **read** (never write) other agents' `state.json` and `leads/` directories for concurrent investigation awareness.

---

## 4. Confidence Scoring (Deterministic, Not LLM) — TODO

### Input (from investigation + reproduction):
```json
{
  "agent_confidence": "high|medium|low",
  "matched_tier": "gold|silver|bronze|null",
  "reproduction_result": "confirmed|refuted|null",
  "asset_criticality": "standard|elevated|critical",
  "has_precedent": true,
  "signature_severity": "low|medium|high|critical"
}
```

### Output:
```json
{
  "confidence_score": 0.85,
  "decision": "auto_close|reproduce|escalate"
}
```

**Formula:** base (high=0.85, med=0.60, low=0.30) + tier modifier (gold=+0.10, silver=+0.05, none=-0.15) + reproduction (confirmed=+0.15, refuted=-0.30) - criticality penalty (elevated=-0.05, critical=-0.15). Thresholds: ≥0.90 auto_close, 0.70-0.89 reproduce, <0.70 escalate.

---

## 5. Decision Router — TODO

### Input:
```json
{
  "scorer_output": { "confidence_score": 0.85, "decision": "reproduce" },
  "alert_data": { ... },
  "signature_id": "wazuh-rule-5710",
  "permissions_file": "config/signatures/wazuh-rule-5710/permissions.yaml",
  "recommendation": "benign"
}
```

### Output:
```json
{
  "action": "auto_close|reproduce|escalate",
  "disposition": "benign|false_positive|true_positive|escalated|inconclusive",
  "reason": "High confidence benign with gold-tier precedent match",
  "confidence_score": 0.85
}
```

---

## 6. Knowledge Base Structures — TODO

### 6.1 Precedent Records (`past-tickets/*.json`)

```json
{
  "ticket_id": "SEC-2024-001",
  "alert_id": "wazuh-5710-abc123",
  "signature_id": "wazuh-rule-5710",
  "tier": "gold",
  "timestamp": "2024-11-15T02:35:00Z",
  "status": "closed",
  "disposition": "benign",
  "confidence_score": 0.95,
  "alert_data": {
    "srcip": "10.0.1.50",
    "srcuser": "testuser",
    "agent": "web-server-01",
    "rule_id": 5710,
    "rule_description": "..."
  },
  "investigation": {
    "ip_classification": "internal",
    "failed_attempts_5min": 1,
    "distinct_usernames": ["testuser"],
    "successful_login_after": false,
    "pattern_matched": "monitoring_probe"
  },
  "investigation_notes": "...",
  "resolution": "...",
  "analyst": "system",
  "closed_at": "2024-11-15T02:35:00Z"
}
```

**Precedent matching is two-layer:** structural search (signature_id + key fields + lead outcome tags) returns candidates, then LLM judges genuine match via `key_indicators`.

### 6.2 Permissions (`config/signatures/{id}/permissions.yaml`)

```yaml
schema_version: "1.0"
allowed_dispositions: [benign, false_positive, true_positive]
allowed_capabilities: [query_siem, read_knowledge, query_assets, query_identity, query_threat_intel]
auto_close:
  enabled: true
escalation_patterns:
  srcuser: ["^root$", "^admin$"]
  srcip: ["^(?!10\\.|192\\.168\\.)"]    # external IPs
  agent: ["domain-controller", "pci-server"]
reproduction:
  enabled: true
  max_timeout_seconds: 300
log_level: standard
```

### 6.3 SIEM Mapping (`config/siem-mapping.json`)

Maps abstract operations to concrete MCP tool calls:

```json
{
  "siem_name": "wazuh",
  "operations": {
    "search_events": {
      "tool": "wazuh_search_events",
      "description": "...",
      "param_mapping": { "query": "q", "time_range": "time_range", "limit": "limit" },
      "response_mapping": { "events": "data.affected_items", "total": "data.total_affected_items" }
    },
    "get_agent_info": { ... },
    "count_events": { ... }
  }
}
```

---

## 7. Prompt Architecture (System → Agent) — TODO

Five sections in order, with security bracketing:

| # | Section | Content |
|---|---------|---------|
| 1 | System Instructions | Role, methodology, constraints, safety rules |
| 2 | Signature Context | Playbook + relevant leads (loaded as skill) |
| 3 | Recent Alert Context | Table of ~30 recent alerts + 3 investigation summaries |
| 4 | Alert Data | Sanitized JSON in `<run-{salt}-alert-data>` tags |
| 5 | Key Reminders | Rephrased safety points + canary token |

---

## 8. UI / Integration Outputs — TODO

### Ticketing System
- **Read:** ticket metadata, alert fields, investigation history (per-ticket + batch)
- **Write:** status + comments (investigation started, recommendation, disposition)

### Chat (Slack/Teams)
- Auto-close notifications
- Escalation alerts with report links

### Triage Summary (written to ticket)
```json
{
  "ticket_id": "...",
  "signature_id": "...",
  "decision": "auto_close|reproduce|escalate",
  "disposition": "benign|false_positive|true_positive|escalated|inconclusive",
  "confidence_score": 0.95,
  "findings": { ... },
  "timestamp": "ISO8601"
}
```

---

## Summary: Data Flow

```
Alert JSON
  → sanitize-input.sh → sanitized-alert.json
  → Agent (state.json transitions validated by validate-transition.sh)
  → Lead subagents (input/output JSON, budget tracked)
  → Scripts (validated by validate-script.sh, sanitized by sanitize-external.sh)
  → report.md (Tier 1: frontmatter validated by validate-report.sh)
  → report.md (Tier 2: semantic judge reviews summary + precedent match)
  → Action: close ticket / spawn reproduction / escalate
  → post-mortem.sh → proposals/ (KB updates for human review)
```
