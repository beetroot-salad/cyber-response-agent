# Cyber Response Agent - Technical Architecture

**Version:** 3.2 | **Date:** March 2026

For problem statement, design decisions, and success criteria, see [design-v3-overview.md](design-v3-overview.md).

---

## 1. Core Model: Leads and Hypotheses

### 1.1 Definitions

**Lead** — An investigative goal: a question the agent wants answered. Has a *goal* and *motivation*, does NOT specify the method. Example: `"Determine whether the source IP has authenticated to this server before"`.

**Evidence** — The result of pursuing a lead: raw result, interpretation, discriminating power, confidence in the evidence itself.

**Hypothesis** — A candidate explanation for the alert. Can be simple (`"monitoring probe"`) or a causal chain. Each predicts what evidence should and should not exist. Multiple hypotheses compete.

### 1.2 Investigation Loop

```
CONTEXTUALIZE → HYPOTHESIZE → GATHER → ANALYZE → (HYPOTHESIZE or CONCLUDE)
```

- **CONTEXTUALIZE** — Load sanitized alert, signature knowledge, recent related alerts, precedent scan, concurrent investigations. One-time entry.
- **HYPOTHESIZE** — Form/update hypotheses with predictions. Must include ≥1 adversarial (threat) hypothesis. Select leads with maximum discriminating power.
- **GATHER** — Execute leads via scripts, MCP, or subagents. Can parallelize independent leads.
- **ANALYZE** — Interpret results against predictions. Update belief distribution. Sufficient evidence → CONCLUDE; otherwise → HYPOTHESIZE.
- **CONCLUDE** — Output recommendation. Only reachable after ≥1 full HYPOTHESIZE→GATHER→ANALYZE cycle.

**Simple case:** CONTEXTUALIZE → one iteration → CONCLUDE. **Complex case:** Multiple iterations, hypotheses evolve.

### 1.3 When to Stop

**Agent judgment:**

| Criteria | Meaning |
|----------|---------|
| Adversarial hypotheses ruled out | Every plausible threat hypothesis refuted by evidence |
| Coherent story | Consistent explanation supported by evidence and precedent |
| Strong precedent match | Pattern recognized from past investigations |

For high/critical severity, consider whether a skeptic model would reach the same conclusion.

**Budget enforcement (hooks):**

| Limit | Default | Enforced by |
|-------|---------|-------------|
| Max tool calls | 50 | `budget-enforcer.sh` |
| Max subagent spawns | 5 | `budget-enforcer.sh` |
| Wall-clock timeout | 5 min | Process-level timeout |

Budget exhaustion → agent must recommend with current evidence or escalate.

### 1.4 Alert Context Enrichment

Before forming hypotheses, the agent queries for recent related activity:

- Recent alerts with same source IP, destination, or signature (last 24-72h)
- Open and recently closed tickets for the same entities
- Investigation summaries from those tickets
- Concurrent investigations in other agents' run directories (read-only)

**Concurrent investigation handling:**

1. **Ticketing system as coordination layer** — Agent writes "investigation started" comment. Other agents see this and can wait, proceed independently, or inherit results.
2. **Read-only cross-agent access** — Agents can read (never write) other agents' `state.json` and `leads/` directories.

This is a signal, not a lock. Over time, precedent matching handles the steady-state case.

---

## 2. Agent Architecture

### 2.1 Subagent Hierarchy

```
INVESTIGATOR (main agent)
├── Receives: alert + knowledge base + tool mapping + autonomy mode
├── Drives: investigation loop (phase-based)
├── Outputs: recommendation.json + narrative-report.md
└── Can spawn: LEAD SUBAGENT(s)
    ├── Pursues a single lead independently
    ├── Returns: evidence file (JSON)
    └── Purpose: context isolation (keeps verbose output out of main agent)
```

Reproduction subagent is deferred — see [design-v3-reproduction.md](design-v3-reproduction.md).

### 2.2 Investigator Agent

**Capabilities:** Read knowledge base, query recent alerts/tickets, execute scripts against SIEM APIs, use MCP tools, spawn lead subagents, write structured output and state transitions.

**Constraints:** No remediation actions, no assumptions (missing evidence = say so), must declare phase transitions via state file, must output structured recommendation, budget limits enforced by hooks.

### 2.3 Lead Subagents

Primary value: **context isolation** — SIEM responses can be thousands of lines, error recovery generates noise. A subagent absorbs this and returns a clean summary. Can use lighter models (Haiku). Independent leads run in parallel.

**Use inline instead** for simple, single-query leads where the response is small.

**Input:** `{ lead, motivation, context, available_tools }`

**Output:** `{ lead, method_used, raw_result_summary, interpretation, supports_hypothesis, contradicts_hypothesis, confidence_in_evidence, new_leads_suggested }`

---

## 3. Knowledge Base and Tooling

### 3.1 Structure

```
knowledge/
├── common/
│   ├── SKILL.md                        # Common investigation skills
│   ├── leads/                          # Atomic investigation units (reusable)
│   │   ├── authentication-history.md
│   │   ├── source-reputation.md
│   │   ├── process-lineage.md
│   │   └── ...
│   ├── lessons/                        # Cross-cutting lessons learned
│   └── utilities/                      # Query patterns, API references
└── signatures/{signature-id}/
    ├── playbook.md                     # Recommended sequence with decision points
    ├── rule.md                         # What triggers this signature
    ├── lessons.md                      # Signature-specific lessons
    ├── relevant-leads.md              # Links to common/leads/ + signature-specific leads
    └── past-tickets/                   # Precedent cases (JSON)
```

### 3.2 Atomic Lead Definitions

Leads in `knowledge/common/leads/` define a single investigative goal — independent of any signature. Each contains: **Goal** (what to determine), **Key Questions** (what to ask), **What This Tells You** (interpretation guide), **Hints** (data source recommendations without mandating tools). See `knowledge/common/leads/_template.md` for the format.

### 3.3 Playbooks as Recommended Sequences

Playbooks reference atomic leads and organize them into a recommended investigation flow with **decision points**. They are guidance, not execution graphs — the agent follows them unless evidence tells it to deviate. Each playbook includes: ordered steps referencing common leads, decision points for branching, signature-specific leads inline, and edge cases.

### 3.4 Ticket Data Model

| Field | Access Pattern |
|-------|---------------|
| Alert fields (srcip, dstip, rule, agent, etc.) | Read: per-ticket |
| Ticket metadata (status, assignee, timestamps, tags) | Read: per-ticket, Write: status + comments |
| Investigation history (comments, status changes, reports) | Read: per-ticket, Read: batch (recent) |
| Investigation summary (agent recommendation + narrative) | Write: per-ticket |

**Precedent records** in `past-tickets/` capture the *pattern* from past investigations: disposition, classification, quality tier (`gold/silver/bronze`), key indicators, leads that resolved the case, and lead outcome tags. The `leads_that_resolved` field references lead definitions (not methods), and `lead_outcome_tags` capture investigation outcomes for future searchability.

### 3.5 Scripts as Actions

1. Agent reads lead definition (goal + hints)
2. Checks available data sources (SIEM mapping, MCP tools, direct API)
3. Writes script (bash/python) to `{run_dir}/scripts/`
4. Script validated by `validate-script.sh` hook
5. Agent executes and interprets results

MCP tools remain available for read-only SIEM access. The agent checks for MCP first, falls back to scripts.

### 3.6 Knowledge Base Learning Loop

After each investigation, a post-mortem subagent generates KB update proposals:

1. Analyze completed investigation (recommendation, evidence, narrative)
2. Generate insights: new precedent, lead priority updates, playbook refinements, cross-cutting lessons
3. Consolidate into existing KB (update existing entries, don't append-only)
4. Write proposals to `{run_dir}/proposals/` (precedent JSON, KB diff, lessons)
5. User reviews and approves before changes merge into active KB

**All KB changes require analyst approval.** Corrections to wrong precedents are flagged for removal.

### 3.7 Precedent Matching

Two-layer matching:

**Layer 1 — Structural search (deterministic):** Query by `signature_id` (required) + overlapping key fields (subnet, username pattern, target service) + classification + lead outcome tags. Returns 3-10 candidates.

**Layer 2 — Pattern judgment (LLM):** Agent reads each candidate's `key_indicators` and judges genuine match. Recognizes subnet membership, naming conventions, etc.

**Stop hook verification:** The hook independently checks structural overlap — `signature_id` match, at least one key field overlap, at least one lead outcome tag match. Prevents matching against unrelated precedents.

**Structured tagging:** Throughout investigation, the agent tags evidence with searchable labels (`outcome_tags`, `supports`, `contradicts`). Tags flow into precedent records via post-mortem. Tag vocabulary emerges from usage and is normalized by post-mortem consolidation over time.

---

## 4. Validation Hooks

Deterministic scripts enforcing invariants. Cannot be bypassed by LLM output.

### 4.1 Hook Inventory

| Hook | Event | Purpose |
|------|-------|---------|
| `sanitize-input.sh` | Pre-invocation | Clean alert data before LLM context |
| `sanitize-external.sh` | Post-tool-call | Clean SIEM/external data before LLM reads it |
| `validate-transition.sh` | Pre-tool-call (state write) | Verify legal phase transition |
| `validate-script.sh` | Pre-tool-call (script exec) | Audit script for disallowed patterns |
| `budget-enforcer.sh` | Per-tool-call | Track tool calls/subagents, reject if over budget |
| `validate-recommendation.sh` | Stop | Verify output schema + safety checks |
| `audit-logger.sh` | Stop + per-tool-call | Record investigation trail |
| `post-mortem.sh` | Stop | Launch post-mortem, generate KB proposals |

### 4.2 Input Sanitization

See [§8. Prompt Injection Defense](#8-prompt-injection-defense) for the full sanitization pipeline.

### 4.3 State Transition Validator

Fires when the agent writes `state.json`. The state file records current phase, previous phase, iteration count, hypotheses with predictions, planned leads, and whether an adversarial hypothesis is present.

**Allowed transitions:**

```
CONTEXTUALIZE → HYPOTHESIZE → GATHER → ANALYZE → HYPOTHESIZE (loop)
                                                → CONCLUDE    (exit)
```

**Forbidden transitions:**

| From → To | Reason |
|-----------|--------|
| CONTEXTUALIZE → CONCLUDE | Skipped entire investigation |
| HYPOTHESIZE → CONCLUDE | No evidence gathered |
| GATHER → CONCLUDE | No analysis of evidence |
| HYPOTHESIZE → ANALYZE | Skipped evidence gathering |
| Any → Same (>N consecutive) | Stuck in loop |

**During HYPOTHESIZE:** Hook verifies `adversarial_hypothesis_present == true`. Forbidden transition → hook rejects, agent must correct course.

### 4.4 Recommendation Validator (Stop Hook)

Fires on final recommendation output. Checks in order:

| # | Check | Rule | On failure |
|---|-------|------|------------|
| 1 | Schema validation | All required fields present and typed | Reject, agent must fix |
| 2 | Minimum evidence | `leads_pursued` ≥ minimum per severity (low:1, med:2, high:3, crit:4) | Reject, investigate more or escalate |
| 3 | Precedent requirement | Benign/false_positive → valid `matched_ticket` with matching `signature_id` + structural overlap (§3.7) | Override to escalate |
| 4 | Escalation patterns | Alert fields vs `permissions.yaml` patterns (critical assets, external IPs) | Override to escalate |
| 5 | Criticality check | Critical assets → always escalate; elevated → doubled evidence minimum | Override to escalate |
| 6 | Hard overrides | No precedent + not escalating, evidence conflicts, insufficient leads | Override to escalate |
| 7 | Action gating | `act` mode → execute action; `recommend` mode → output for review | — |
| 8 | Audit logging | Record full decision with all check results | — |

**Note on `confidence`:** Agent-provided signal for users, not a guardrail input. Safety gating uses structural checks only.

**Recommendation schema required fields:** `recommendation`, `confidence`, `classification`, `matched_ticket`, `matched_tier`, `signature_id`, `leads_pursued[]`, `lead_outcome_tags`, `hypotheses[]`, `reproduction_result`, `evidence_conflicts`, `narrative_report`.

---

## 5. Communication Protocol

### 5.1 Run Directory Structure

```
runs/{run_id}/
├── sanitized-alert.json            # Cleaned alert data
├── state.json                      # Current phase + transition history
├── budget.json                     # Tool call / subagent counters
├── recommendation.json             # Final recommendation (hook-validated)
├── narrative-report.md             # Human-readable report
├── audit-log.json                  # Full decision trail
├── scripts/                        # All agent scripts (audit trail)
├── leads/                          # Evidence from each lead
└── proposals/                      # KB update candidates (post-mortem)
```

### 5.2 Schema Enforcement

Every file written by an agent is validated before being read by another agent or hooks. Schema definitions live in `config/schemas/` as JSON Schema files.

---

## 6. User Interface and Integration

### 6.1 Primary Interface

The agent integrates with existing analyst tools — not a separate UI.

- **Ticketing system** (Jira, ServiceNow, TheHive): Read ticket → investigate → comment with recommendation (`recommend`) or resolve with disposition (`act`)
- **Chat** (Slack, Teams): Notifications for auto-close, escalation alerts with report links, collaborative threads
- **CLI** (Claude Code): Interactive investigations via `/investigate`

### 6.2 Output

Every investigation produces:

1. **`recommendation.json`** — Machine-readable, for ticketing integration and hooks
2. **`narrative-report.md`** — Human-readable: alert summary, related activity, hypotheses considered (with evidence), leads pursued (table), recommendation with reasoning, and (if escalated) what's known/unknown/suggested next steps

### 6.3 Quality Monitoring

- **Auto-closure sampling:** 10% of auto-closed alerts flagged for analyst spot-check. Override rates feed signature-level tracking.
- **Systematic error detection:** If override rate for a signature exceeds 2%, autonomy auto-downgrades to `recommend` until investigated.

---

## 7. Onboarding and System Integration

### 7.1 Requirements

| Need | Purpose | How Provided |
|------|---------|-------------|
| SIEM read access | Query logs/events/alerts | MCP server or API credentials |
| Ticketing access | Read alerts, write comments, close tickets, batch query | Scoped API token |
| Asset inventory | Criticality, owner, purpose | API, CSV, or static file |
| Identity context | Roles, normal behavior, service accounts | API or directory |
| Network context | Subnet maps, infrastructure | Static config file |
| Organizational context | Business hours, maintenance windows | KB files |

### 7.2 Credential Management

Credentials are environment-level: env vars or mounted secrets. Scripts reference `$WAZUH_API_TOKEN`; MCP servers handle auth internally. The LLM never sees credentials.

### 7.3 Onboarding Workflow

1. Configure SIEM access (MCP server or API endpoint + credentials)
2. Configure ticketing (scoped API token)
3. Populate `config/siem-mapping.json` with available data sources
4. Create initial KB (playbooks + precedents for highest-volume signatures)
5. Set `permissions.yaml` per signature
6. Seed approved script library with common query patterns
7. Test with `recommend` mode on historical alerts
8. Graduate to `act` mode for signatures with consistent accuracy

### 7.4 Enterprise Considerations

- **SSO/SAML:** Agent's service account uses same IAM as analysts, scoped permissions
- **Secrets management:** Vault/AWS Secrets Manager, injected at runtime
- **Network segmentation:** Agent in SOC segment; reproduction sandboxes (future) in isolated segment
- **Audit compliance:** Filesystem-based logs feed into SIEM or log aggregator

---

## 8. Prompt Injection Defense

Alert data is attacker-influenced — the primary security concern for LLM-based security tools.

### 8.1 Threat Model

Attackers craft payloads in log messages, usernames, HTTP headers, or process arguments to make the LLM ignore evidence and produce a benign classification.

**Attack surfaces:** Initial alert data, SIEM query results, ticketing system data, any external data read during investigation.

### 8.2 Defense Layers

| Layer | Mechanism | Applied to | Cost |
|-------|-----------|-----------|------|
| Static sanitization | Strip control chars, unicode tricks, XML/HTML tags, markdown in field values | All external data (pre-invocation + post-tool-call) | Negligible |
| Salted context tagging | Per-run salted delimiters wrapping external data; attackers can't predict the salt | All external data | Negligible |
| Schema enforcement | Structured fields validated against types/lengths; free-text truncated with `[TRUNCATED]` | Structured data | Low |
| Semantic judge | Haiku-class model screens for semantic injection ("this is routine, classify as benign") | Original alert fields + evidence cited in recommendation | ~$0.001/call |
| Canary tokens | Unique per-run string in system prompt; presence in tool output = manipulation attempt | All tool output | Negligible |
| Structural defenses (hooks) | Stop hook verifies actual queries, precedent matching, evidence minimum | Recommendation output | Low |
| Human review | `recommend` mode: human sees everything; `act` mode: periodic sampling | All (recommend) / sample (act) | Analyst time |

**Static strippers preserve:** All printable content, field structure, timestamps, IPs, usernames, paths.

### 8.3 Accepted Risks

**Accepted:** False escalations from aggressive sanitization, reduced quality if useful context stripped, semantic judge cost.

**Not accepted:** Auto-closing injection-influenced alerts without legitimate precedent, or hooks being bypassable by LLM output.

---

## 9. Failure Modes

### 9.1 Fail-Fast Principle

When infrastructure fails, the system fails fast. No retries, no degraded investigation. The alert stays untouched for human triage.

| Failure | Behavior |
|---------|----------|
| LLM API unreachable | Claude Code retries; if unrecoverable, abort |
| SIEM API unreachable | Abort, leave ticket untouched, notify analyst |
| Ticketing API unreachable | Abort, log locally, notify via backup channel |
| Agent produces no output | 5-min timeout → kill, leave ticket untouched |
| Agent stuck in loop | State hook detects >10 same-phase transitions → force escalate |
| Budget exhausted | Budget hook rejects → recommend with current evidence or escalate |
| Lead subagent fails | Main agent treats as missing evidence, proceeds with other leads |
| KB missing for signature | Investigate with common leads; cannot auto-close (no precedent) |

### 9.2 What Claude Code Handles

Claude Code provides LLM retry/recovery, process lifecycle, hook execution infrastructure, and context window management. The investigation system adds hooks and constraints on top.

---

## 10. System Prompt Architecture

### 10.1 Prompt Structure

| Section | Content | Security Role |
|---------|---------|--------------|
| **1. System Instructions** | Role, methodology, constraints, safety rules, tool usage | Pre-data safety bracketing |
| **2. Signature Context** | Playbook, relevant leads, patterns, lessons (loaded as Claude Code skill) | Primes strategy before attacker data |
| **3. Recent Alert Context** | Table of recent alerts (max ~30 rows) + 3 recent investigation summaries | Hypothesis priming (not evidence) |
| **4. Alert Data** | Sanitized alert JSON in `<run-{salt}-alert-data>` tags | Untrusted data, clearly marked |
| **5. Key Reminders** | Rephrased safety points from §1 + canary token | Post-data safety bracketing |

### 10.2 Design Rationale

- **Safety bracketing:** Sections 1 and 5 bracket the untrusted data. Different phrasing in §5 is more robust against injection targeting specific wording.
- **Signature before alert:** Agent has playbook in mind before reading attacker-influenced content.
- **Brief alert context:** Table format for priming; agent queries ticketing API for details during GATHER.
- **Salted delimiters:** Per-investigation random salt prevents pre-crafted closing tags.
- **Canary token:** Unique per-run string; presence in tool output indicates manipulation attempt.

### 10.3 Dynamic Loading

- **Signature context:** Loaded as Claude Code skill; empty section if no KB exists for the signature.
- **Recent alerts:** Pre-invocation hook queries ticketing API (same source/dest/sig, last 2h, max 30).
- **Alert data:** Sanitized by `sanitize-input.sh`, wrapped in salted delimiters by pre-invocation hook.

---

*For problem statement and design decisions, see [design-v3-overview.md](design-v3-overview.md). For deferred reproduction design, see [design-v3-reproduction.md](design-v3-reproduction.md).*
