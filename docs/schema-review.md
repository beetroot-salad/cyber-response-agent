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
- Dropped `classification`, `lead_outcome_tags`, `hypotheses` array, `reproduction_result`, `evidence_conflicts` from structured fields — these either belong in the precedent record (post-mortem) or can't be meaningfully validated by hooks
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

### 2.7 Post-Mortem KB Updates (Git-Native) — DONE

The `proposals/` directory is eliminated. Post-mortem updates the KB directly using git: edits files in-place on a branch, commits, pushes, and opens a PR. Analyst reviews the diff and merges. See architecture doc §3.7.

**Review decisions:**
- Git-native replaces the proposals directory — PRs are the approval workflow
- New files (precedents, lessons) never conflict; edits to shared files (playbooks, context) go through PR review
- No custom proposal format or review UI needed — the PR diff is the review artifact

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

### 3.2 Investigator → Reproduction Agent — Deferred

See [design-v3-reproduction.md](design-v3-reproduction.md).

### 3.3 Cross-Agent Read-Only Access

Agents can **read** (never write) other agents' `state.json` and `leads/` directories for concurrent investigation awareness.

---

## 4–5. Confidence Scoring & Decision Router — Deferred

Confidence scoring and decision routing were designed around the reproduction path. With reproduction deferred, the decision simplifies: the stop hook (§2.4) validates the report, and the outcome is **resolved** or **escalated**. No intermediate scoring step needed.

If reproduction is reintroduced, these schemas move to [design-v3-reproduction.md](design-v3-reproduction.md).

---

## 6. Knowledge Base Structures — DONE

### 6.1 Signature Context (`context.md`)

Complete signature reference. SIEM provides the rule definition at runtime; `context.md` stores only what the SIEM doesn't provide.

```markdown
---
signature_id: wazuh-rule-5710
name: "sshd: Attempt to login using a non-existent user"
severity: medium
data_sources: [wazuh-events]
mitre:
  tactics: [credential-access, initial-access]
  techniques: [T1110.001]
references: []
related_signatures: [wazuh-rule-5711, wazuh-rule-5712]
base_rate: {benign_pct: 92, sample_size: 50}
---

## Signature Logic
Fires when sshd logs a failed authentication attempt where the username
does not exist on the system. The raw query: `rule.id:5710`. Note: this
fires on *any* non-existent user attempt, including typos.

## Threat & Motivation
Detects brute force / credential stuffing targeting SSH. Adversaries
enumerate usernames or attempt common credentials. Relevant when:
external-facing SSH, weak password policies, no MFA.

## Known False Positives
- **Monitoring probes**: Source in monitoring subnet, single username,
  regular interval. Precedents: SEC-2024-001, SEC-2024-015.
- **Service account rotation**: srcuser matches svc-*, burst of 2-3
  attempts then success. Precedents: SEC-2024-008.

## Impact
Unauthorized SSH access → full shell → lateral movement, data
exfiltration, persistence.

## Field Notes
- `srcuser` is the *attempted* username — may not exist on the system.
  Don't use for identity lookups.
- See common/data-sources/wazuh-events.md for NAT/srcip quirks.

## Operational Notes
- ~50 alerts during weekly vuln scan (Sundays 2-4am UTC).
- Monitoring subnet 10.0.1.0/24 generates regular health-check traffic.

## Tuning Guidance
- Exclude srcip in monitoring subnet if health-check service account confirmed.

## Detection Gaps
- Does not detect slow brute force (>5 min between attempts).
- Does not fire if username exists but password is wrong (that's rule 5711).
```

**Field requirements:** See architecture doc §3.2 for mandatory/recommended/optional breakdown.

**Review decisions:**
- Merges old `rule.md` + `field-notes.md` + `lessons.md` into one file
- SIEM is source of truth for rule definition; `context.md` adds the human layer
- Known FPs are structured patterns referencing specific precedents — abstractions derived from recurring precedent patterns
- `base_rate` is computable from precedent outcomes, maintained by post-mortem

### 6.2 Playbook (`playbook.md`)

```markdown
---
signature_id: wazuh-rule-5710
last_updated: 2026-03-10
total_investigations: 50
auto_close_rate: 0.84
---

## Investigation

*(Investigation flow language design deferred — see §6.5)*

## Escalation Criteria

Escalate immediately if:
- Source IP is external AND successful login follows failed attempts
- Target is a critical asset (domain controller, PCI server)
- srcuser is a privileged account (root, admin, domain admin)

Escalate after investigation if:
- No precedent match after all leads pursued
- Evidence contradicts all benign hypotheses without confirming a specific threat
- Low confidence on high/critical severity

## Auto-Close Criteria

May auto-close when ALL of:
- Matches a known FP pattern OR a precedent
- All adversarial hypotheses investigated and refuted
- No escalation criteria triggered
- Source is internal and target is non-critical

## Scope

In scope: authentication patterns, source reputation, recent alert correlation.
Out of scope: full forensic analysis, malware detonation, user interviews.
```

**Review decisions:**
- Absorbs old `relevant-leads.md` — lead references live in the investigation section
- Tool-decoupled: references leads by goal, not by tool
- Priority scores are data-driven, updated by post-mortem
- Investigation flow language is the key design challenge (deferred)

### 6.3 Precedent Records (`precedents/{slug}.json`)

Curated, human-approved investigation patterns. Not raw ticket data — the ticketing system is the source of truth for ticket details.

```json
{
  "ticket_id": "SEC-2024-001",
  "signature_id": "wazuh-rule-5710",
  "disposition": "benign",
  "created_at": "2024-11-15T02:35:00Z",
  "flow": [
    {
      "lead": "authentication-history",
      "outcome": "regular-pattern",
      "detail": "5-min intervals, single username, 47 events over 7 days"
    },
    {
      "lead": "source-reputation",
      "outcome": "known-internal",
      "detail": "10.0.1.50 in monitoring subnet, known Nagios host"
    }
  ],
  "reasoning": {
    "conditions": [
      "Source IP is internal (RFC1918)",
      "Attempts follow regular interval (variance <15%)",
      "Single username across all attempts",
      "No successful login following failures within 30 min"
    ],
    "refutes": [
      "Successful login within 30 minutes of failures",
      "Multiple distinct usernames (>2)",
      "Source IP is external",
      "Attempt frequency exceeds 20/hour"
    ],
    "confidence_note": [
      "If interval is regular but source is unknown, investigate further before matching"
    ]
  },
  "key_indicators": [
    "5-minute interval pattern (cron-like)",
    "single username: testuser",
    "source: monitoring subnet 10.0.1.0/24"
  ],
  "leads_that_resolved": ["authentication-history"]
}
```

**Review decisions:**
- No `tier`/`quality` field — a precedent is a human-approved resolved case; the approval gate is the quality filter
- No `classification` field — deferred; the investigation flow + known FP patterns serve the same purpose without a controlled vocabulary to maintain
- No raw ticket data — `ticket_id` is a reference; query the ticketing system for details
- `flow` uses the same `(lead, outcome)` language as playbooks and reports
- `reasoning` captures explicit iff-conditions and refutation criteria — enables mid-investigation matching and stop hook validation
- Matching is flow-based (§3.9): structural search on `signature_id` + `(lead, outcome)` pairs, then LLM verifies `reasoning.conditions` against current evidence

### 6.4 Precedent → Known FP Lifecycle

Individual precedents accumulate. When the post-mortem agent detects N precedents with the same pattern, it proposes a known FP entry in `context.md` referencing those precedents. This gives the agent fast-path heuristics. The chain: **specific cases → abstracted patterns → investigation shortcuts**.

### 6.5 Investigation Flow Language — TODO

The `(lead, outcome)` structure is used in three places: playbooks (as a plan), precedents (as a record), reports (as a log). Designing a unified language for this is the key remaining challenge. Needs to support: sequencing, branching/decision points, priority scoring, and searchability.

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
| 2 | Signature Context | Context + playbook + precedents (loaded as skill) |
| 3 | Recent Alert Context | Table of ~30 recent alerts + 3 investigation summaries |
| 4 | Alert Data | Sanitized JSON in `<run-{salt}-alert-data>` tags |
| 5 | Key Reminders | Rephrased safety points + canary token |

---

## 8. Interface and Integrations — TODO

### 8.1 Primary Interface: Claude Code

The system is a **Claude Code plugin**. Claude Code is the runtime — the agent runs inside it, and all external access happens through tools the user configures. This is a core strength: no custom UI to build or maintain, and users bring whichever integrations fit their environment.

**Tool connectivity:** MCP servers, scripts (+ API keys), or any combination. The agent doesn't care how data arrives — it works with whatever tools are available at runtime, resolved via `siem-mapping.json` and MCP server configuration.

**Modes:**

| Mode | Behavior |
|------|----------|
| `recommend` | Agent investigates and outputs report. Human reviews and acts. |
| `act` | Agent investigates and executes actions (close ticket, post comment, tag). Validated by hooks. |

### 8.2 Recommended Integrations

These make the system effective. Without them, the agent can still investigate but with reduced capability.

| Integration | Access | Why it matters |
|-------------|--------|----------------|
| **Ticketing system** (Jira, TheHive, ServiceNow, etc.) | Read: ticket metadata, alert fields, investigation history (per-ticket + batch). Write (`act` mode): status, comments, disposition. | Core input/output — the agent reads alerts from tickets and writes results back. Batch read enables recent alert context (§1.4). |
| **SIEM** (Wazuh, Splunk, Elastic, etc.) | Read: events, rules, agent info. | Evidence gathering — most leads query the SIEM for log data. |
| **Git host** (GitHub, GitLab, or any git server) | Read/write: branches, PRs. | Powers the learning loop (§3.7) — post-mortem agent commits KB updates and opens PRs for analyst review. Without this, KB updates require manual file management. |

### 8.3 Optional Integrations

Nice to have, not required. Each adds capability for specific investigation types.

| Integration | Value |
|-------------|-------|
| **Chat** (Slack, Teams) | Auto-close notifications, escalation alerts with report links, collaborative investigation threads. |
| **EDR** (CrowdStrike, Defender, etc.) | Process trees, endpoint context, containment actions. |
| **DLP** | Data exfiltration context for relevant alert types. |
| **Firewall / network tools** | Connection logs, block actions. |
| **Threat intelligence** | IP/domain/hash reputation lookups. |
| **Identity provider** (AD, Okta, etc.) | User roles, normal behavior patterns, service account identification. |
| **Asset inventory** (CMDB, etc.) | Asset criticality, owner, purpose — feeds escalation decisions. |

The agent discovers available tools at runtime. Playbooks reference leads by goal ("check source reputation"), not by tool — the agent resolves to whatever's available.

### 8.4 Investigation Output

Every investigation produces a single `report.md` — YAML frontmatter (machine-readable) + markdown body (analyst-readable). See §2.4 for format and validation.

**Ticketing integration:** Reads frontmatter fields (`ticket_id`, `signature_id`, `status`, `disposition`, `confidence`, `matched_precedent`, `leads_pursued`) for structured updates and posts the markdown body as a ticket comment. No separate triage summary format needed.

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
  → Action: close ticket / escalate
  → post-mortem.sh → KB branch + PR (updates for analyst review)
```
