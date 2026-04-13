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

### 2.2a `investigation.md` — Working Investigation Log — DONE

The investigator's chronological working document, written in the investigation flow language (§6.5). Phase headers mirror the state machine. Content uses the same hypothesis/lead/assessment vocabulary as playbooks and precedents.

```markdown
## CONTEXTUALIZE

Alert: SSH failed auth from 10.0.1.50 → web-server-01, user "testuser" (wazuh-rule-5710)
Precedent scan: SEC-2024-001 (?monitoring-probe, 92% base rate benign)

## HYPOTHESIZE (cycle 1)

hypotheses:
  - "?monitoring-probe": automated health check generating auth failures
  - "?brute-force": credential guessing attack
  - "?credential-stuffing": leaked credential replay

Selected lead: authentication-history
  discriminates: ?monitoring-probe vs ?brute-force vs ?credential-stuffing
  predictions:
    ?monitoring-probe → regular interval, single username, bounded count
    ?brute-force → high frequency, diverse usernames, increasing
    ?credential-stuffing → burst, known-leaked names, external source

## GATHER → authentication-history

[→ leads/authentication-history.json]

## ANALYZE (cycle 1)

- lead: authentication-history
  observed: "5-min intervals, single username 'testuser', 47 events over 7 days"
  assessment:
    "?monitoring-probe": "++"   # regular interval, single user — textbook
    "?brute-force": "--"        # not high-frequency, not diverse
    "?credential-stuffing": "--" # not bursty, single username

surviving: [?monitoring-probe]

## CONCLUDE

trace: alert → authentication-history[regular-pattern ∴ ?monitoring-probe] → source-reputation[known-internal ∴ ?monitoring-probe] → benign
disposition: benign
matched_precedent: SEC-2024-001
```

**Serves three audiences at different times:**

1. **Lead subagents** (during GATHER) — read the log for investigation context instead of receiving a serialized context blob. The `goal` and `notes` in the subagent input steer attention; the log provides the full picture
2. **The investigator itself** (during ANALYZE) — the log is the working memory across cycles. Hypotheses, predictions, and prior assessments are all in one place
3. **The report** (at CONCLUDE) — `report.md` is a summary-first transformation of this log for analysts and hooks. The investigation log is the detailed record; the report is the polished output

**Relationship to other files:**

| File | Written by | When | Purpose |
|------|-----------|------|---------|
| `investigation.md` | Investigator | During investigation, appended each phase | Working log, subagent context, investigation record |
| `leads/*.json` | Lead subagents | During GATHER | Raw observations + method (reality dimension) |
| `report.md` | Investigator | At CONCLUDE | Analyst-facing output, hook-validated |
| `state.json` | Investigator | Each phase transition | Structural phase tracking (hook-validated) |

**Review decisions:**
- New file — previously investigation content was split between `report.md` and `leads/`. Now the log is the single chronological record, `leads/` stores raw subagent returns, and the report is a CONCLUDE-time summary
- Uses the flow language (§6.5) — same vocabulary as playbooks and precedents, making the log, precedents, and playbooks mutually readable
- GATHER sections are thin (just a pointer to the lead file) — the ANALYZE section that follows is where the investigator interprets subagent output against hypotheses. This makes the separation of concerns between subagent (reality) and investigator (logic) visible in the document structure
- Precedent records (§6.3) are curated projections of this log, not a separate format — the post-mortem agent extracts and compacts the relevant parts
- ANALYZE entries in the investigation log omit `type` and `why` — the preceding HYPOTHESIZE section provides that context. Precedent records retain these fields because they stand alone

### 2.3 `leads/{lead-name}.json` — Raw Subagent Returns — DONE

Each file is the raw output from a lead subagent — what was found and how. These are observation records, not analytical conclusions. The investigator interprets subagent returns against hypotheses in the ANALYZE phase and records that interpretation in `investigation.md`.

One schema for all leads. The diagnostic/scoping distinction is the investigator's concern (how it *interprets* the observations), not the subagent's.

```json
{
  "lead": "authentication-history",
  "observed": "47 failed auth events over 7 days for srcip 10.0.1.50 → web-server-01. All attempts use username 'testuser'. Interval between attempts: 5 minutes (±3 seconds). No successful logins from this IP in the same period. Most recent: 2026-03-15T02:30:00Z. Earliest: 2026-03-08T02:25:00Z.",
  "method": {
    "tool": "wazuh_search_events",
    "query": "srcip:10.0.1.50 AND rule.id:5710",
    "time_range": "7d",
    "result_count": 47
  },
  "evidence_quality": "high",
  "quality_notes": "Complete dataset, no truncation, consistent timestamps"
}
```

Another example — what would previously have been a "scoping" lead:

```json
{
  "lead": "data-access-audit",
  "observed": "Session accessed 3 files: /data/reports/q4-financials.xlsx, /data/hr/salary-bands.csv, /data/config/db-credentials.env. Access window: 14:31:02Z - 14:33:47Z (2m45s). All read operations, no writes detected.",
  "method": {
    "tool": "wazuh_search_events",
    "query": "session_id:sess-abc123 AND data.type:file_access",
    "time_range": "1h",
    "result_count": 3
  },
  "evidence_quality": "high",
  "quality_notes": "File access audit logging confirmed enabled on this host"
}
```

The subagent reports *what it found* and *how it found it*. It does not assess what the findings mean for hypotheses, suggest new leads, or categorize itself as diagnostic vs. scoping. The investigator does all of that in `investigation.md`.

**Review decisions:**
- **Single schema for all leads** — removed the diagnostic/scoping type split. The subagent's job is evidence gathering (reality dimension); the investigator handles interpretation (logic dimension). Whether observations are used for hypothesis discrimination or impact assessment is determined by the investigator in ANALYZE
- **Removed from subagent output:** `type`, `why`, `assessment`, `findings`, `purpose`, `new_leads_suggested` — all of these are investigator-level concerns. `why` is already in the investigation log (HYPOTHESIZE section). Assessments are in the investigation log (ANALYZE section). Lead suggestions are the investigator's job
- **`method` is structured** — tool name, query, parameters, result count. Supports audit trail and helps the investigator judge reliability (direct SIEM query vs. cached data vs. inferred)
- **`evidence_quality`** replaces `confidence_in_evidence` — clarifies this is about data quality (completeness, freshness, truncation), not interpretive confidence
- **`quality_notes`** is optional — only needed when there are caveats (truncated results, stale data, partial coverage)

### 2.4 `report.md` — Unified Investigation Output — DONE

Final analyst-facing output, written at CONCLUDE. YAML frontmatter for hook validation, markdown body for analysts. Summary-first structure (unlike the chronological `investigation.md`). References or imports from the investigation log — the report is the polished view, the log is the detailed record.

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

## Suggestions

- **Rule tuning**: Exclude srcip 10.0.1.0/24 + srcuser "testuser" from rule 5710.
  This monitoring probe pattern has triggered 23 times in the past 30 days.
  → Detection engineering backlog
- **Visibility**: Health check service on 10.0.1.50 should use a dedicated
  service account (e.g., svc-nagios) instead of "testuser" to reduce ambiguity.
  → Infrastructure backlog
```

**Review decisions:**
- Merged structured recommendation and narrative report into a single file — eliminates redundancy, the JSON fields were mostly duplicating what the prose said
- Dropped `classification`, `lead_outcome_tags`, `hypotheses` array, `reproduction_result`, `evidence_conflicts` from structured fields — these either belong in the precedent record (post-mortem) or can't be meaningfully validated by hooks
- Kept `leads_pursued` as integer count for minimum evidence enforcement
- `confidence` remains an agent signal for analysts, not a guardrail input
- Added Suggestions section — backlog items for other teams (rule tuning, infra hardening, visibility gaps). Written to ticket; in `act` mode, optionally created as backlog tickets. NOT stored in `knowledge/`
- The Investigation Log section is a summary drawn from `investigation.md` — the report does not duplicate the full log, it presents the key findings in analyst-friendly narrative form

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

### 2.7 Post-Mortem Output — DONE

The post-mortem subagent produces two types of output:

**KB updates (git-native):** The `proposals/` directory is eliminated. Post-mortem updates the KB directly using git: edits files in-place on a branch, commits, pushes, and opens a PR. Analyst reviews the diff and merges. See architecture doc §3.7.

**Suggestions (backlog items):** Actionable recommendations that don't belong in the KB — rule tuning, infrastructure hardening, visibility gaps. Written to the investigation ticket as a recommendations section. In `act` mode, optionally created as new tickets in the appropriate backlog (detection engineering, security engineering, etc.).

```json
{
  "suggestions": [
    {
      "type": "rule-tuning",
      "description": "Exclude srcip 10.0.1.0/24 + srcuser 'testuser' from rule 5710",
      "rationale": "Monitoring probe pattern triggered 23 times in 30 days",
      "destination": "detection-engineering"
    },
    {
      "type": "hardening",
      "description": "Health check on 10.0.1.50 should use dedicated service account",
      "rationale": "Generic username 'testuser' creates investigation ambiguity",
      "destination": "infrastructure"
    }
  ]
}
```

Suggestion types: `rule-tuning` | `rule-suppression` | `hardening` | `visibility-gap` | `playbook-gap`. The `destination` field maps to a team/backlog for routing.

**Review decisions:**
- Git-native replaces the proposals directory — PRs are the approval workflow
- New files (precedents, lessons) never conflict; edits to shared files (playbooks, context) go through PR review
- No custom proposal format or review UI needed — the PR diff is the review artifact
- Suggestions are NOT stored in `knowledge/` — they're backlog items forwarded to other teams. The KB captures investigation patterns; suggestions capture what to fix
- Post-mortem generates suggestions by comparing investigation against KB: recurring FP without rule exclusion, scoping leads that found unmonitored assets, detection gaps encountered during investigation

---

## 3. Agent-to-Agent Interfaces — DONE

### 3.1 Investigator → Lead Subagent

The interface is designed for LLM-to-LLM communication — it's guidance and context, not an API contract. Both sides understand natural language, so the schema is minimal and the investigation log carries the contextual weight.

**Separation of concerns:** The investigator owns the logic dimension (hypotheses, predictions, lead selection, assessment). The subagent owns the reality dimension (figuring out how to get the data, executing queries, returning observations). The subagent does not assess evidence against hypotheses or suggest new leads.

**Input:**

```json
{
  "lead": "source-reputation",
  "goal": "Determine if source IP 10.0.1.50 is a known internal asset or external/malicious",
  "investigation_log": "runs/run-abc123/investigation.md",
  "notes": "Auth pattern already confirmed as regular 5-min interval — focus on IP identity"
}
```

| Field | Required | Purpose |
|-------|----------|---------|
| `lead` | mandatory | Lead name — references `knowledge/common/leads/` for method guidance |
| `goal` | mandatory | Natural language description of what data is needed *this time*. The lead name is a KB reference; the goal is what the investigator actually wants |
| `investigation_log` | mandatory | Path to `investigation.md`. The subagent reads this for context — what the alert is, what's been checked, what's known so far. Later subagents get richer context because the log has grown |
| `notes` | optional | Investigator's steering for this specific pursuit — what to pay attention to, what's already established. This replaces structured context fields (`key_entities`, `alert_summary`) with natural language the investigator writes knowing *why* it's sending this subagent |

**Output:** The lead evidence JSON (§2.3) — `observed`, `method`, `evidence_quality`, and optional `quality_notes`. No hypothesis assessments, no lead suggestions, no type markers.

**How context flows:** The subagent opens `investigation.md` and reads it. From the CONTEXTUALIZE section it gets the alert details. From HYPOTHESIZE sections it understands what the investigator is looking for (without needing to do hypothesis reasoning itself). From prior ANALYZE sections it knows what's already established. The `goal` and `notes` fields steer attention to what matters for this specific lead. No separate context serialization needed.

### 3.2 Investigator → Reproduction Agent — Deferred

See [design-v3-reproduction.md](design-v3-reproduction.md).

### 3.3 Cross-Agent Read-Only Access

Agents can **read** (never write) other agents' `state.json`, `investigation.md`, and `leads/` directories for concurrent investigation awareness.

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
resolution_rate: 0.84
---

## Investigation

### Hypotheses
- **?monitoring-probe**: Automated health check generating auth failures.
  Source in monitoring subnet, single username, regular interval.
- **?brute-force**: Credential guessing attack against SSH.
  High frequency, diverse usernames, increasing over time.
- **?credential-stuffing**: Replay of leaked credentials.
  Burst of attempts, known-leaked usernames, external source.
- **?service-account-rotation**: Service account password change.
  srcuser matches svc-*, burst of 2-3 then success.

### Leads

Start with **authentication-history** — it discriminates the most common hypotheses in a single query and is almost always the fastest path to eliminating ?brute-force or confirming ?monitoring-probe.

- **authentication-history** [auth-events]
  Discriminates: ?monitoring-probe vs ?brute-force vs ?credential-stuffing
  Predictions:
    ?monitoring-probe → regular interval, single username, bounded count
    ?brute-force → high frequency, diverse usernames, increasing
    ?credential-stuffing → burst, known-leaked names, external source

- **source-reputation** [asset-info, threat-intel]
  Discriminates: ?monitoring-probe vs external threat hypotheses
  Predictions:
    ?monitoring-probe → known internal, monitoring subnet
    ?brute-force → unknown or known-malicious external
    ?credential-stuffing → external, possibly proxy/VPN

- **recent-alert-correlation** [auth-events]
  Discriminates: isolated incident vs campaign
  Predictions:
    isolated → single alert, no related activity
    campaign → cluster of alerts from same source or targeting same dest

- **session-activity-audit** [file-events]
  Discriminates: (scoping — does not discriminate hypotheses)
  Scoping: after ?brute-force or ?credential-stuffing confirmed with successful login, determine what the authenticated session accessed or modified

- **lateral-movement-check** [network-events]
  Discriminates: (scoping — does not discriminate hypotheses)
  Scoping: after any threat hypothesis confirmed, identify other systems the source IP contacted

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
- Tool-decoupled: references leads by goal, not by tool. Data tags in brackets (e.g., `[auth-events]`) connect leads to data-sources/ files for subagent tool resolution
- Two-layer investigation section: hypothesis catalog (what could be happening) + lead sequence (what to check and why)
- Replaced numeric diagnosticity scores with prose priority guidance ("Start with...") — the agent reasons about lead selection better from natural language rationale than from a numeric score. Each lead retains `discriminates` and `predictions` which carry the real information
- Merged diagnostic and scoping leads into a single `### Leads` section — the diagnostic/scoping distinction is per-use, not per-lead. Scoping leads include a `Scoping:` note with the conditional trigger (replacing the old `when:` field)
- Agent picks the most diagnostic lead for surviving hypotheses, not a fixed step sequence
- Investigation flow language fully specified in §6.5

### 6.3 Precedent Records (`precedents/{slug}.json`)

Curated, human-approved investigation patterns. Not raw ticket data — the ticketing system is the source of truth for ticket details.

```json
{
  "ticket_id": "SEC-2024-001",
  "signature_id": "wazuh-rule-5710",
  "disposition": "benign",
  "created_at": "2024-11-15T02:35:00Z",
  "hypotheses": [
    { "id": "?monitoring-probe", "status": "confirmed" },
    { "id": "?brute-force", "status": "eliminated" },
    { "id": "?credential-stuffing", "status": "eliminated" }
  ],
  "flow": [
    {
      "lead": "authentication-history",
      "type": "diagnostic",
      "why": "discriminates ?monitoring-probe (regular interval) from ?brute-force (high-frequency diverse)",
      "observed": "5-min intervals, single username, 47 events over 7 days",
      "assessment": {
        "?monitoring-probe": "++",
        "?brute-force": "--",
        "?credential-stuffing": "--"
      },
      "surviving": ["?monitoring-probe"]
    },
    {
      "lead": "source-reputation",
      "type": "diagnostic",
      "why": "confirms ?monitoring-probe (known internal) vs external threat",
      "observed": "10.0.1.50 in monitoring subnet, known Nagios host",
      "assessment": {
        "?monitoring-probe": "++"
      },
      "surviving": ["?monitoring-probe"]
    }
  ],
  "trace": "alert → authentication-history[regular-pattern ∴ ?monitoring-probe] → source-reputation[known-internal ∴ ?monitoring-probe] → benign",
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
- No separate `classification` field — hypothesis names (`?monitoring-probe`) serve as searchable classifications without a controlled vocabulary to maintain
- No raw ticket data — `ticket_id` is a reference; query the ticketing system for details
- `hypotheses` records which competing explanations were considered and their final status — enables hypothesis-based search across precedents
- `flow` captures both dimensions: evidence (what was observed) and logic (why it was checked, what it meant for each hypothesis). Assessment weights (`++/+/−/−−`) follow a four-level ACH convention; omission means neutral.
- `surviving` field in each flow entry records which hypotheses remained after that step — enables mid-investigation state matching where an agent can match on intermediate hypothesis state, not just the final outcome
- `trace` is a one-line sequential summary for grep — returns complete investigation paths, not fragments. Grammar: `step ( → step )* → disposition`
- `reasoning` captures explicit iff-conditions and refutation criteria — enables mid-investigation matching and stop hook validation
- Matching uses hypothesis overlap + flow overlap (§3.9): structural search on `signature_id` + hypothesis names + lead assessments, then LLM verifies `reasoning.conditions` against current evidence

### 6.4 Precedent → Known FP Lifecycle

Individual precedents accumulate. When the post-mortem agent detects N precedents confirming the same hypothesis (e.g., multiple `?monitoring-probe` confirmations with similar flow patterns), it proposes a known FP entry in `context.md` referencing those precedents. This gives the agent fast-path heuristics. The chain: **specific cases → shared hypothesis confirmations → abstracted known FP patterns → investigation shortcuts**.

### 6.5 Investigation Flow Language — DONE

#### The Problem

Investigations operate in two dimensions: the **hypothesis space** (logic — what could be happening, which explanations survive) and the **evidence space** (reality — what was checked, what was observed). Each investigation step transforms between them:

- **Logic → Reality** ("predict/choose"): "If ?brute-force is true, I'd expect high-frequency diverse attempts. Let me check authentication-history."
- **Reality → Logic** ("assess/update"): "I saw regular 5-min intervals. That kills ?brute-force, supports ?monitoring-probe."

The original `(lead, outcome)` structure only captured the evidence dimension. It recorded *what happened* but not *why that step was chosen* or *what it meant for competing hypotheses*. The investigation flow language must capture both dimensions and the transforms between them.

#### Design Inspirations

- **Analysis of Competing Hypotheses (ACH)** (Heuer, CIA) — Matrix of hypotheses × evidence, each cell records support/contradict/neutral. The matrix IS the transform between dimensions.
- **Differential diagnosis** (medicine) — Competing explanations, each predicting different test results. Most diagnostic test chosen first.
- **Behavior trees** (robotics/game AI) — Sequence nodes (do A then B), selector nodes (try A, if fails try B). Good for composable flow structure.
- **Gherkin/Given-When-Then** — Structured natural language designed to be both human-readable and machine-parseable.

The language combines ACH's hypothesis-evidence matrix with behavior tree sequencing, encoded in markdown/YAML that's writable in files and ticket comments.

#### Three Layers

The language has three greppable layers, each addressing a different dimension:

**Layer 1: Hypotheses** (logic atoms)

Competing explanations for the alert. Written with `?` prefix everywhere — in playbooks, precedents, reports, ticket comments. `grep "?brute-force"` across all past tickets finds every time this hypothesis was considered.

```yaml
hypotheses:
  - "?monitoring-probe": automated health check generating auth failures
  - "?brute-force": credential guessing attack
  - "?credential-stuffing": leaked credential replay
```

The hypothesis set for a signature is pre-populated in the playbook and refined during investigation. Hypotheses can split mid-investigation (e.g., `?parallel-job` splits into `?legitimate-build` vs `?supply-chain`).

**Layer 2: Leads with predictions** (logic → reality transform)

Each lead specifies which hypotheses it discriminates and what each hypothesis predicts. This is the diagnosticity — WHY this lead is being checked. Data tags in brackets connect to `data-sources/` files for subagent tool resolution.

```yaml
leads:
  - lead: authentication-history      # defined in common/leads/
    data_tags: [auth-events]          # → data-sources/authentication-events.md
    discriminates: "?monitoring-probe vs ?brute-force vs ?credential-stuffing"
    predictions:
      "?monitoring-probe": "regular interval, single username, bounded count"
      "?brute-force": "high frequency, diverse usernames, increasing over time"
      "?credential-stuffing": "burst of attempts, known-leaked usernames"
  - lead: data-access-audit           # defined in common/leads/
    data_tags: [file-events]          # → data-sources/file-events.md
    discriminates: "(scoping)"
    scoping: "after ?unauthorized-access confirmed — determine what sensitive data the session accessed"
```

The playbook uses prose priority guidance (e.g., "Start with authentication-history") rather than numeric diagnosticity scores — the agent reasons about lead selection better from natural language rationale than from a number. Each lead retains `discriminates` and `predictions` which carry the real information about what the lead reveals.

Diagnostic and scoping leads live in a single list. The diagnostic/scoping distinction is per-use, not per-lead — the same lead could be used diagnostically in one investigation and for scoping in another. Scoping entries include a `scoping:` note with conditional triggers (when the lead becomes relevant).

This layer lives in the **playbook** — it's reusable across investigations for the same signature. The agent selects the most diagnostic lead for the surviving hypotheses. The lead definition (`common/leads/`) provides the methodology (what to characterize, pitfalls); the playbook adds the hypothesis-specific layer (what each hypothesis predicts for this lead).

**Subagent tool resolution:** The subagent reads the lead's `data_tags`, finds the matching `data-sources/` file (e.g., `data-sources/authentication-events.md`), which lists available systems with coverage, priority, and pipeline notes. Two deterministic hops — no exploratory tool-space search.

**Layer 3: Evidence with assessments** (reality → logic transform)

This is the **investigator's** interpretation of subagent observations, written in `investigation.md` ANALYZE sections. The subagent returns raw observations (§2.3); the investigator records what those observations mean for each hypothesis. Assessment weights: `++` strongly supports, `+` weakly supports, `-` weakly contradicts, `--` strongly contradicts. Omission means neutral — if a hypothesis isn't listed in the assessment, the evidence was neutral for it.

In the **investigation log** (ANALYZE sections), entries omit `type` and `why` because the preceding HYPOTHESIZE section already documents the rationale:

```yaml
# In investigation.md ANALYZE section
- lead: authentication-history
  observed: "5-min intervals, single username 'testuser', 47 events over 7 days"
  assessment:
    "?monitoring-probe": "++"    # regular interval, single user — textbook
    "?brute-force": "--"         # not high-frequency, not diverse
    "?credential-stuffing": "--" # not bursty, not known-leaked names
```

For scoping leads (after a hypothesis is confirmed), the investigator records impact findings:

```yaml
# In investigation.md ANALYZE section
- lead: data-access-audit
  observed: "session accessed 3 files in /data/"
  findings:
    affected_assets: ["q4-financials.xlsx", "salary-bands.csv", "db-credentials.env"]
    severity_factors: ["credentials file accessed", "PII in salary data"]
    blast_radius: "financial data + HR PII + database credentials"
```

In **precedent records**, flow entries retain `type` and `why` because they stand alone without surrounding phase context:

```yaml
# In precedent flow field
- lead: authentication-history
  type: diagnostic
  why: "discriminates ?monitoring-probe vs ?brute-force vs ?credential-stuffing"
  observed: "5-min intervals, single username 'testuser', 47 events over 7 days"
  assessment:
    "?monitoring-probe": "++"
    "?brute-force": "--"
    "?credential-stuffing": "--"
  surviving: ["?monitoring-probe"]
```

Investigation log entries share `lead` and `observed`. The `observed` value comes from the subagent's return (`leads/*.json`). The `assessment`/`findings` are added by the investigator. Whether the entry uses `assessment` (diagnostic) or `findings` (scoping) is self-describing — no `type` marker needed. The diagnostic/scoping distinction exists at this layer (the investigator's interpretation), not at the subagent layer (which has a single schema for all leads).

This layer lives in **investigation logs** (detailed, chronological), **precedents** (compact, with `type`/`why`/`surviving`), and **reports** (narrative summary). Scoping lead findings feed the report's impact assessment and may trigger suggestions (§3.7).

#### The Trace Line: Sequential Searchability

A compact one-line representation of the entire investigation path, optimized for grep across many files:

```
alert → authentication-history[regular-pattern ∴ ?monitoring-probe] → source-reputation[known-internal ∴ ?monitoring-probe] → benign
```

**Grammar:**

```
trace       = step ( → step )* → disposition
step        = lead-name [ observation ∴ hypothesis-conclusion ]
disposition = benign | false_positive | true_positive | escalate
```

- `→` separates sequential steps
- `[...]` contains the observation and conclusion for that step
- `∴` ("therefore") separates what was seen from what it meant
- Final token is the disposition

**Why this matters:** Because the entire path is on one line, `grep` returns complete investigation sequences, not isolated fragments. When you search and find a match, you see the full chain — what came before, what came after, and where it ended.

**Search patterns:**

| Question | Grep |
|---|---|
| "Have we seen ?fork-bomb hypotheses before?" | `grep "?fork-bomb"` across precedents |
| "When was parent-child-identity lead used?" | `grep "parent-child-identity\["` in trace fields |
| "What happened after observing make→gcc?" | `grep "make.*gcc"` — trace line shows the full path |
| "Cases where ?parallel-job led to escalation?" | `grep "?parallel-job.*→ escalate"` |
| "What evidence strongly supported ?monitoring-probe?" | `grep '"?monitoring-probe": "++"'` in flow fields |
| "Which investigations refined hypotheses mid-flow?" | `grep "splits into"` in report narratives |

#### Concrete Example: Suspicious Parent-Child Process Relationship

Alert: a parent process spawned an unusual number of child processes.

**Playbook layer (plan):**

```yaml
hypotheses:
  - "?fork-bomb": resource exhaustion via exponential process spawning
  - "?parallel-job": legitimate parallel compilation or batch work
  - "?malware-spawn": malware spawning worker processes
  - "?orchestration": system management tool behavior

# Start with parent-child-identity — the parent binary and child pattern
# discriminate the three most common hypotheses in a single check.
leads:
  - lead: parent-child-identity
    discriminates: "?fork-bomb vs ?parallel-job vs ?malware-spawn"
    predictions:
      "?fork-bomb": "same binary as parent, exponential growth"
      "?parallel-job": "build tools (make/gcc/xargs), bounded count"
      "?malware-spawn": "unknown or renamed binary, steady spawning"
      "?orchestration": "known management tool (ansible, salt, systemd)"

  - lead: execution-context
    discriminates: "?legitimate-build vs ?supply-chain (after ?parallel-job confirmed)"
    predictions:
      "?legitimate-build": "CI user, build directory, expected schedule"
      "?supply-chain": "unexpected user, unusual directory or timing"
```

**Precedent layer (record):**

```yaml
hypotheses:
  - id: "?fork-bomb"
    status: eliminated
  - id: "?parallel-job"
    status: confirmed
    refined_to: ["?legitimate-build", "?supply-chain"]
  - id: "?legitimate-build"
    status: confirmed
  - id: "?malware-spawn"
    status: eliminated

flow:
  - lead: parent-child-identity
    type: diagnostic
    why: "discriminates ?fork-bomb/?parallel-job/?malware-spawn"
    observed: "parent=/usr/bin/make, children=gcc(x47), burst within 3s"
    assessment:
      "?fork-bomb": "--"          # make→gcc is not self-replication
      "?parallel-job": "++"       # textbook parallel compilation
      "?malware-spawn": "--"      # gcc is a known compiler
    surviving: ["?parallel-job"]
    refine: "?parallel-job splits into ?legitimate-build vs ?supply-chain"

  - lead: execution-context
    type: diagnostic
    why: "discriminates ?legitimate-build/?supply-chain"
    observed: "user=jenkins, cwd=/var/lib/jenkins/workspace/proj-x, 02:00 nightly"
    assessment:
      "?legitimate-build": "++"   # CI user, build directory, expected schedule
      "?supply-chain": "--"       # everything matches expected pattern
    surviving: ["?legitimate-build"]

trace: "alert → parent-child-identity[make→gcc(x47) ∴ ?parallel-job] → execution-context[jenkins,nightly ∴ ?legitimate-build] → benign"
```

**Investigation log layer** (`investigation.md`) — the investigator's working document, using phase headers and the flow language:

```markdown
## CONTEXTUALIZE

Alert: unusual parent-child process relationship on build-server-03 (wazuh-rule-5920)
Parent=/usr/bin/make spawned 47 children in 3s

## HYPOTHESIZE (cycle 1)

hypotheses:
  - "?fork-bomb": resource exhaustion via exponential process spawning
  - "?parallel-job": legitimate parallel compilation or batch work
  - "?malware-spawn": malware spawning worker processes
  - "?orchestration": system management tool behavior

Selected lead: parent-child-identity
  discriminates: ?fork-bomb vs ?parallel-job vs ?malware-spawn
  predictions:
    ?fork-bomb → same binary as parent, exponential growth
    ?parallel-job → build tools (make/gcc/xargs), bounded count
    ?malware-spawn → unknown or renamed binary, steady spawning
    ?orchestration → known management tool (ansible, salt, systemd)

## GATHER → parent-child-identity

[→ leads/parent-child-identity.json]

## ANALYZE (cycle 1)

- lead: parent-child-identity
  observed: "parent=/usr/bin/make, children=gcc(×47), burst within 3s"
  assessment:
    "?fork-bomb": "--"       # make→gcc is not self-replication
    "?parallel-job": "++"    # textbook parallel compilation
    "?malware-spawn": "--"   # gcc is a known compiler
    "?orchestration": "--"   # make is not management tooling

surviving: [?parallel-job (strong)]
Refine: ?parallel-job → ?legitimate-build vs ?supply-chain

## HYPOTHESIZE (cycle 2)

Remaining: ?legitimate-build vs ?supply-chain
Selected lead: execution-context
  predictions:
    ?legitimate-build → CI user, build directory, expected schedule
    ?supply-chain → unexpected user, unusual directory or timing

## GATHER → execution-context

[→ leads/execution-context.json]

## ANALYZE (cycle 2)

- lead: execution-context
  observed: "user=jenkins, cwd=/var/lib/jenkins/workspace/proj-x, 02:00 nightly"
  assessment:
    "?legitimate-build": "++"  # CI user, build directory, expected schedule
    "?supply-chain": "--"      # everything matches expected pattern

surviving: [?legitimate-build (confirmed)]

## CONCLUDE

trace: alert → parent-child-identity[make→gcc(x47) ∴ ?parallel-job] → execution-context[jenkins,nightly ∴ ?legitimate-build] → benign
disposition: benign
```

Note how GATHER sections are thin pointers to `leads/`. ANALYZE sections use structured YAML — `lead`, `observed`, and `assessment` (or `findings` for scoping). The subagent (in `leads/parent-child-identity.json`) returned the raw observation; the investigator added the `assessment`. The post-mortem agent enriches these entries with `type`, `why`, and `surviving` when extracting them into precedent records.

#### Where Each Layer Lives

| Layer | Playbook (plan) | Investigation log (working) | Precedent (record) | Report (output) |
|---|---|---|---|---|
| Hypotheses + predictions | Pre-populated catalog | Full set at each HYPOTHESIZE phase | Which were considered + final status | Summary of key hypotheses |
| Leads + predictions | Prioritized with prose guidance | Selected lead + predictions per HYPOTHESIZE | Which were used + `type`/`why` for standalone context | Key leads in narrative form |
| Raw observations | — | Pointer to `leads/*.json` (GATHER) | Compact `observed` per step | Summarized in narrative |
| Evidence assessments | — | Compact tabular in ANALYZE (no `type`/`why` — context from HYPOTHESIZE) | `assessment`/`findings` + `type`/`why`/`surviving` — enriched by post-mortem | Reasoning per key finding |
| Trace line | — | Generated at CONCLUDE | One-line sequential summary | Included in frontmatter or footer |
| Suggestions | — | — | — | Backlog items for other teams (§3.7) |

#### Vocabulary Management

- **Hypothesis names** (`?name`): Emerge from usage, normalized by post-mortem. The `?` prefix makes them greppable everywhere — playbooks, precedents, reports, ticket comments.
- **Outcome vocabulary** (observations): Free-text, normalized by post-mortem consolidation. No controlled vocabulary — the post-mortem agent detects drift and proposes normalization via PR.
- **Assessment weights** (`++/+/−/−−`): Fixed four-level scale, inspired by ACH. Omission means neutral — if a hypothesis isn't listed in an assessment, the evidence was neutral for it. Simple enough to write in a ticket comment, structured enough to grep.
- **Observation normalization**: The post-mortem agent normalizes observation phrasing when creating precedent records, but no strict controlled vocabulary is enforced because the primary searcher (the LLM) handles semantic similarity natively.

**Review decisions (flow language refinements):**
- **Dropped `type`/`why` from investigation log ANALYZE entries** — these fields were redundant with the HYPOTHESIZE section that immediately precedes ANALYZE. The `assessment` vs `findings` distinction is self-describing for diagnostic vs scoping. Precedent records retain `type`/`why` because they stand alone without surrounding phase context
- **Assessment weights reduced from five to four levels** (`++/+/−/−−`) — the neutral marker (`~`) was noise. If evidence is neutral for a hypothesis, simply omit it from the assessment. This is cleaner and reduces clutter in assessments where most hypotheses are unaffected
- **Replaced numeric diagnosticity scores with prose priority guidance** — the agent reasons about lead selection better from "Start with X because it discriminates the most common hypotheses in a single query" than from `diagnosticity: 9.2`. Each lead retains `discriminates` and `predictions` which carry the actual information. Numeric scores implied false precision and required post-mortem maintenance
- **Merged diagnostic and scoping leads in playbooks** — the diagnostic/scoping distinction is per-use, not per-lead. The same lead (e.g., session-activity-audit) could be used diagnostically in one investigation and for scoping in another. Unified lead entries document both what the lead can discriminate and when it's used for scoping, with conditional notes replacing the old `when:` triggers
- **Added `surviving` to precedent flow entries** — records which hypotheses remained after each step. Enables mid-investigation state matching: an agent can match on intermediate hypothesis state (e.g., "at this point ?parallel-job was the only survivor"), not just the final outcome

### 6.5a Common Knowledge Base — DONE

The `common/` directory serves both the investigator and subagents. See architecture doc §3.1a-c for the full structure and rationale. This section documents the schemas and review decisions.

#### Lead Definitions (`common/leads/`)

```markdown
---
name: authentication-history
data_tags: [auth-events]
---

## Goal

Retrieve and characterize authentication patterns for a given entity
(IP, user, or host) over a time window.

## What to Characterize

- **Timing pattern**: Classify as periodic (regular intervals — note
  interval and variance), burst (clustered in short window — note
  window and count), or irregular (no clear pattern).
- **Username diversity**: Single username, small set (<5), or many
  distinct usernames. Note if any match known patterns from
  context/identity.md (service accounts, admin accounts).
- **Success/failure sequence**: All failures, all successes, or
  mixed. If mixed, note the temporal relationship.
- **Volume and rate**: Total event count, events per hour, and
  whether rate is constant or changing.
- **Source context**: Cross-reference source IP against
  context/network.md. Note if internal/external, known subnet.

## Common Pitfalls

- NAT can collapse multiple sources into one IP. Check if srcip
  is a known NAT gateway (see context/network.md).
- Failed auth for non-existent users vs existing users are different
  signals (different SIEM rules).
- Cached/stale credentials cause periodic failures after password
  rotation — looks like low-frequency brute force but isn't.

## Data Sources

See data-sources/authentication-events.md for available systems
and pipeline notes.
```

**Review decisions:**
- Leads are the shared vocabulary between investigator and subagents. Investigator reads them when selecting leads (knows what they reveal). Subagent reads them when executing (knows what to characterize)
- `data_tags` frontmatter connects leads to data-sources/ files — the subagent's tool resolution path. Small fixed vocabulary: `auth-events`, `process-events`, `network-events`, `file-events`, `identity-info`, `asset-info`, `threat-intel`
- "What to Characterize" section guides the subagent on observation, not interpretation. The test: "can this conclusion be wrong if a different hypothesis is true?" If yes, it's interpretation → investigator's job
- No tool names, no query syntax, no hypothesis predictions in lead definitions. Tools are the tool layer's concern; predictions are the playbook's concern
- Cross-references context/ files where relevant (network.md for IP classification, identity.md for account patterns)

#### Data Source Mapping (`common/data-sources/`)

Organized by data need (matching data tags), not by vendor.

```markdown
---
name: authentication-events
provides: [auth-events]
---

## Available Systems

| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| Wazuh (SIEM) | All SSH (rules 5710-5720), most Windows auth | siem-mapping `search_events` | Primary |
| Active Directory | All domain auth (4624/4625) | AD MCP server | When SIEM gaps |
| Endpoint (auth.log) | Per-host SSH only | Direct agent access | Fallback |

## Pipeline Notes

- Wazuh normalizes AD events: original `EventID` in `data.win.eventID`,
  `TargetUserName` becomes `data.dstuser` (not `srcuser`).
- Cloud auth (Okta) NOT in Wazuh — query Okta MCP directly.
- Retention: Wazuh 90 days, AD logs on DCs 30 days.

## Known Gaps

- No auth event forwarding from database servers (db-01, db-02).
- Cloud workloads not forwarding to Wazuh.
```

**Review decisions:**
- Organized by data need (matching `data_tags`), not by vendor — a file per tag, listing all systems that provide that data type in this org
- Priority/fallback order gives the subagent a resolution strategy: try primary first, fall back if gaps exist. Addresses SIEM → local fallback pattern
- Pipeline notes capture org-specific transformation quirks (field renaming, normalization). Universal vendor field semantics live with the vendor's skill/MCP server
- Known gaps are critical — they prevent the subagent from assuming complete coverage and guide fallback decisions
- Maintained by humans (initial) + post-mortem proposals (ongoing). When investigations reveal undocumented coverage gaps, post-mortem proposes updates via PR

#### Organizational Context (`common/context/`)

Human-maintained, not schema-enforced. Free-form markdown files organized by domain. See architecture doc §3.1b for the file inventory and example content.

**Review decisions:**
- Four files covering the key domains: network topology, identity model, known infrastructure, business rhythms. Can grow but should stay small — each file is a curated reference, not a comprehensive inventory
- Initial population during onboarding. Ongoing updates via post-mortem proposals when investigations reveal undocumented organizational knowledge
- Referenced by subagents for observation context (e.g., "Is this IP internal?" → check network.md) and by the investigator for interpretation
- Does NOT sync with authoritative systems (CMDB, AD) automatically. The context files are a curated investigation-optimized view. They reference authoritative systems ("for current group membership, query AD") rather than duplicating them

### 6.6 Permissions (`config/signatures/{id}/permissions.yaml`)

```yaml
schema_version: "2.0"

# Operating mode
mode:
  allowed: [recommend]       # recommend | act (act enables mitigation skill)
  default: recommend

# Mitigation actions (enforced by mitigation skill, not investigation agent)
# Investigation agent has full read/query access — only actions are gated.
# Per action: auto (execute immediately) | approve (require human approval)
# Unlisted actions are denied with structured response to the agent.
mitigation:
  actions:
    block_ip: auto
    disable_user: approve

log_level: verbose
```

### 6.7 SIEM Mapping (`config/siem-mapping.json`)

Maps abstract operations to concrete MCP tool calls. Includes `provides` tags to connect to the data tag system — the subagent can verify that a system provides the data type it needs.

```json
{
  "siem_name": "wazuh",
  "provides": ["auth-events", "network-events", "file-events", "process-events"],
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

**Tag resolution chain:** Lead `data_tags` → `data-sources/` file (lists systems + coverage + priority) → system's tool config (siem-mapping, MCP server) → concrete tool call. The subagent follows this chain; it doesn't explore the tool space.

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

Every investigation produces `investigation.md` (working log) and `report.md` (analyst-facing output). See §2.2a and §2.4 for formats.

**Ticketing integration:** Reads `report.md` frontmatter fields (`ticket_id`, `signature_id`, `status`, `disposition`, `confidence`, `matched_precedent`, `leads_pursued`) for structured updates and posts the markdown body as a ticket comment. The investigation log and raw lead files remain in the run directory for audit.

---

## Summary: Data Flow

```
Alert JSON
  → sanitize-input.sh → sanitized-alert.json
  → Investigator (state.json transitions validated by validate-transition.sh)
  → investigation.md written in flow language (CONTEXTUALIZE → HYPOTHESIZE → ...)
  → Lead subagents read investigation.md for context, return observations to leads/
  → Investigator interprets observations in ANALYZE, appends to investigation.md
  → Scripts (validated by validate-script.sh, sanitized by sanitize-external.sh)
  → report.md generated at CONCLUDE (Tier 1: frontmatter validated by validate-report.sh)
  → report.md (Tier 2: semantic judge reviews summary + precedent match)
  → Action: close ticket / escalate
  → post-mortem.sh → KB branch + PR (updates for analyst review)
```
