# Cyber Response Agent - Technical Architecture

**Version:** 3.5 | **Date:** March 2026

For problem statement, design decisions, and success criteria, see [design-v3-overview.md](design-v3-overview.md).

---

## 1. Core Model: Leads and Hypotheses

### 1.1 Definitions

Investigations operate in two dimensions: the **hypothesis space** (logic — what could be happening) and the **evidence space** (reality — what we observe). Each investigation step transforms between them: logic→reality (choosing what to check based on predictions) and reality→logic (updating hypotheses based on observations).

**Hypothesis** — A candidate explanation for the alert. Can be simple (`"monitoring probe"`) or a causal chain. Each hypothesis **predicts** what evidence should and should not exist — these predictions are what make leads diagnostic. Multiple hypotheses compete; investigation eliminates or confirms them. Written with `?` prefix for searchability: `?monitoring-probe`, `?brute-force`.

**Lead** — An investigative goal: a question the agent wants answered. Has a *goal* and *motivation*, does NOT specify the method. Leads come in two types:

- **Diagnostic leads** — Discriminate between hypotheses. Value measured by **diagnosticity**: how well possible outcomes distinguish surviving hypotheses. Example: `"Check authentication history"` discriminates `?monitoring-probe` (predicts regular pattern) from `?brute-force` (predicts high-frequency diverse attempts). These carry per-hypothesis predictions and assessments.

- **Scoping leads** — Assess impact, blast radius, timeline, or gather context that informs the response rather than the diagnosis. Example: `"Determine what data was accessed"` or `"Identify lateral movement to other systems"`. These have *findings* but no hypothesis assessments. Scoping leads often become critical after a hypothesis is confirmed — the investigation shifts from "what happened?" to "how bad is it?"

Both types produce evidence and appear in the investigation flow. Playbooks specify which leads are diagnostic vs scoping.

**Evidence** — The result of pursuing a lead. For diagnostic leads: raw observation plus an **assessment** of what it means for each hypothesis (supports/contradicts/neutral). For scoping leads: raw observation plus **findings** that inform the response (severity, affected assets, timeline bounds). Both types feed into the report and precedent record.

### 1.2 Investigation Loop

```
CONTEXTUALIZE → HYPOTHESIZE → GATHER → ANALYZE → (HYPOTHESIZE or CONCLUDE)
```

- **CONTEXTUALIZE** — Load sanitized alert, signature knowledge, recent related alerts, precedent scan, concurrent investigations. One-time entry.
- **HYPOTHESIZE** — Form/update hypotheses with predictions (logic dimension). Must include ≥1 adversarial (threat) hypothesis. Select leads with maximum discriminating power — a lead is diagnostic when different hypotheses predict different outcomes for it.
- **GATHER** — Execute leads via scripts, MCP, or subagents. Can parallelize independent leads.
- **ANALYZE** — Interpret results against predictions (reality→logic transform). Assess each piece of evidence against each surviving hypothesis. Update belief distribution. Sufficient evidence → CONCLUDE; otherwise → HYPOTHESIZE from the updated logical position.
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

Defaults in `config/budget-defaults.yaml`, overridable per-signature in `permissions.yaml`. See §5.3 for budget file details.

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
2. **Read-only cross-agent access** — Agents can read (never write) other agents' `state.json`, `investigation.md`, and `leads/` directories.

This is a signal, not a lock. Over time, precedent matching handles the steady-state case.

---

## 2. Agent Architecture

### 2.1 Subagent Hierarchy

```
INVESTIGATOR (main agent)
├── Receives: alert + knowledge base + tool mapping + autonomy mode
├── Drives: investigation loop (phase-based)
├── Writes: investigation.md (working log in flow language, §5.1)
├── Outputs: report.md (unified frontmatter + narrative, references investigation.md)
└── Can spawn: LEAD SUBAGENT(s)
    ├── Receives: lead + goal + path to investigation.md + optional notes
    ├── Returns: observations + method + evidence quality (JSON)
    └── Purpose: context isolation (keeps verbose output out of main agent)
```

Reproduction subagent is deferred — see [design-v3-reproduction.md](design-v3-reproduction.md).

### 2.2 Investigator Agent

**Capabilities:** Read knowledge base, query recent alerts/tickets, execute scripts against SIEM APIs, use MCP tools, spawn lead subagents, write structured output and state transitions.

**Constraints:** No remediation actions, no assumptions (missing evidence = say so), must declare phase transitions via state file, must output structured recommendation, budget limits enforced by hooks.

### 2.3 Lead Subagents

Primary value: **context isolation** — SIEM responses can be thousands of lines, error recovery generates noise. A subagent absorbs this and returns a clean summary. Can use lighter models (Haiku). Independent leads run in parallel.

**Use inline instead** for simple, single-query leads where the response is small.

**Separation of concerns:** The investigator owns the logic dimension — hypotheses, predictions, lead selection, assessment. The subagent owns the reality dimension — figuring out *how* to get the requested information and returning what it found. The subagent does not assess evidence against hypotheses; it reports observations and the method used to obtain them. The investigator interprets observations in the ANALYZE phase.

**Input:** `{ lead, goal, investigation_log, notes? }`

- `lead` — Lead name (references `knowledge/common/leads/`)
- `goal` — Natural language description of what data is needed *this time*
- `investigation_log` — Path to `investigation.md` for the subagent to read for context
- `notes` — Optional steering from the investigator ("source is in monitoring subnet — pay attention to timing regularity")

**Output:** `{ lead, observed, method, evidence_quality, quality_notes? }`

- `lead` — Lead name (echo back)
- `observed` — What was found, natural language
- `method` — What tool/query was used (for reliability and audit)
- `evidence_quality` — Subagent's assessment of data quality: high | medium | low
- `quality_notes` — Optional notes on data completeness, truncation, caveats

The subagent does not return hypothesis assessments, lead suggestions, or diagnostic/scoping type markers. These are the investigator's concerns. The `leads/` directory stores raw subagent returns; `investigation.md` stores the investigator's interpretation.

---

## 3. Knowledge Base and Tooling

### 3.1 Structure

```
knowledge/
├── common/
│   ├── SKILL.md                        # Loads common KB as Claude Code skill
│   ├── leads/                          # Investigation methodology (§3.1a)
│   │   ├── authentication-history.md   #   What to characterize, pitfalls, data tags
│   │   ├── source-reputation.md
│   │   ├── process-lineage.md
│   │   └── ...
│   ├── context/                        # Organizational knowledge (§3.1b)
│   │   ├── network.md                  #   Topology, subnets, NAT, known IPs
│   │   ├── identity.md                 #   Account conventions, service accounts, admin groups
│   │   ├── infrastructure.md           #   Known systems: monitoring, CI/CD, scanners
│   │   └── business-rhythms.md         #   Schedules, change windows, batch jobs
│   ├── data-sources/                   # Data pipeline: where data lives (§3.1c)
│   │   ├── authentication-events.md    #   Organized by data need, not vendor
│   │   ├── process-events.md
│   │   ├── network-events.md
│   │   └── ...
│   └── lessons/                        # Cross-cutting lessons from investigations
└── signatures/{signature-id}/
    ├── SKILL.md                        # Loads this signature's KB as Claude Code skill
    ├── context.md                      # Rule context + field notes + operational notes (§3.2)
    ├── playbook.md                     # Lead sequence, priorities, decision points (§3.3)
    └── precedents/                     # Curated investigation patterns (§3.4)
        └── {slug}.json
```

Three kinds of knowledge in `common/`, at different levels of portability:

| Directory | What it captures | Who maintains it | Portability |
|-----------|-----------------|------------------|-------------|
| `leads/` | Investigation methodology — what to characterize, pitfalls, data tags | Post-mortem + humans | Portable across orgs |
| `context/` | Organizational baseline — what's normal here | Humans + post-mortem proposals | Org-specific |
| `data-sources/` | Data pipeline — where data types live, coverage, quirks | Humans + post-mortem proposals | Org-specific |
| `lessons/` | Cross-cutting lessons from past investigations | Post-mortem proposals | Mostly portable |

**Tool knowledge** (how to query a specific system, API syntax, vendor field semantics) does NOT live in the KB. It belongs with the tool: MCP server descriptions, vendor skills, approved script library. The KB boundary is: "what does this data mean and where is it?" is KB. "How do I query this system?" is tool layer.

#### 3.1a Lead Definitions (`common/leads/`)

Leads are the **shared investigation vocabulary** between the investigator and subagents. The investigator reads lead definitions when selecting leads (it knows what authentication-history can reveal). The subagent reads them when executing leads (it knows what to characterize and what pitfalls to avoid). Playbooks add the hypothesis-specific layer on top.

Each lead definition specifies **data tags** — a lightweight vocabulary connecting leads to data sources. The subagent uses tags to find relevant systems without exploring the tool space:

```
lead: authentication-history     data-sources/authentication-events.md
  data_tags: [auth-events]   →    provides: [auth-events]
                                   systems: wazuh (rules 5710-5720), AD, endpoint/auth.log
```

**Lead definition format:**

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

Note what's absent from lead definitions: no tool names, no query syntax (that's the tool layer), no hypothesis predictions (that's the playbook). The lead captures methodology — what to characterize and what to watch out for.

The subagent's job is to **characterize observations**, not **interpret them**. "Timing is periodic, 5min ±3s" is characterization. "This is a benign monitoring probe" is interpretation — that's the investigator's job in ANALYZE. The discriminating test: **can the conclusion be wrong if a different hypothesis is true?** If yes, it's interpretation and belongs to the investigator.

#### 3.1b Organizational Context (`common/context/`)

Human-maintained knowledge about what's normal in this environment. Both the investigator and subagents reference this for interpretation.

| File | Contents | Example |
|------|----------|---------|
| `network.md` | Internal ranges, subnets, NAT gateways, DMZ, VPN pools, known external IPs | "10.0.1.0/24 is the monitoring subnet" |
| `identity.md` | Service account patterns, admin account conventions, vendor accounts | "Service accounts: svc-{service}-{purpose}" |
| `infrastructure.md` | Known systems: monitoring, CI/CD, backup, vulnerability scanners | "Nagios on 10.0.1.50 probes all servers every 5 min" |
| `business-rhythms.md` | Change windows, deployment schedules, batch job timing | "Weekly vuln scan: Sundays 02-04 UTC" |

**Maintenance:** Initial population during onboarding (§7.2). Ongoing updates via post-mortem proposals — when an investigation reveals undocumented organizational knowledge ("this IP turned out to be a new backup server"), the post-mortem proposes an update to `context/` via PR. The system works with incomplete context; gaps lead to more cautious conclusions (escalation, not auto-close).

#### 3.1c Data Sources (`common/data-sources/`)

Documents where data types live in this organization's infrastructure, organized by **data need** (not by vendor). Each file maps a data tag to available systems, coverage, pipeline quirks, and fallback order.

```markdown
---
name: authentication-events
provides: [auth-events]
---

## Available Systems

| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| Wazuh (SIEM) | All SSH (rules 5710-5720), most Windows auth | siem-mapping `search_events` | Primary |
| Active Directory | All domain auth (4624/4625) | AD MCP server | When SIEM gaps exist |
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

Vendor-specific field semantics (what CrowdStrike's `ParentProcessId` means, how Wazuh's `data.srcip` works in general) live with the vendor's skill/MCP server. `data-sources/` only captures org-specific pipeline behavior.

**The data tag vocabulary** is small and grows slowly:

| Tag | Covers |
|-----|--------|
| `auth-events` | Authentication successes, failures, lockouts |
| `process-events` | Process creation, parent-child, command lines |
| `network-events` | Connections, flows, DNS queries |
| `file-events` | File access, modification, creation |
| `identity-info` | User roles, group membership, account metadata |
| `asset-info` | Host details, OS, services, criticality |
| `threat-intel` | IP/domain/hash reputation |

Tags are a scoping mechanism, not a taxonomy. They tell the subagent which `data-sources/` file to read and which systems to check. New tags are added by post-mortem when leads can't find the data they need.

### 3.2 Signature Context (`context.md`)

The complete signature reference the agent needs. The SIEM is the source of truth for the rule definition (query, severity, fields); `context.md` stores only what the SIEM doesn't provide. During CONTEXTUALIZE, the system fetches the rule definition from the SIEM API and assembles it with `context.md` into a complete picture.

**Frontmatter (YAML, structured):**

| Field | Required | Source | Notes |
|-------|----------|--------|-------|
| `signature_id` | mandatory | SIEM | Unique identifier |
| `name` | mandatory | SIEM | Human-readable name |
| `severity` | mandatory | SIEM | low / medium / high / critical |
| `data_sources` | mandatory | SIEM or human | What log sources feed this rule |
| `created_at` | recommended | SIEM or human | When the rule was created |
| `updated_at` | recommended | SIEM or human | Last modification |
| `mitre` | recommended | Human | `{tactics: [...], techniques: [...]}` |
| `references` | recommended | Human | CVEs, advisories, attack write-ups |
| `related_signatures` | optional | Human | Rules that commonly co-occur or chain |
| `base_rate` | optional | Post-mortem | `{benign_pct: 92, sample_size: 50}` — calibrates prior |

**Body sections:**

**Mandatory:**

- **Signature Logic** — The raw detection query + plain-language explanation of what events trigger this rule. If the SIEM API provides the query, this section adds the explanation layer: what the rule *actually* detects, which is often subtly different from what its name suggests.
- **Threat & Motivation** — What threat/behavior this detects and why it matters. What adversary goal it maps to, when it's relevant (e.g., external-facing SSH, weak password policies).

**Highly recommended:**

- **Known False Positives** — Structured patterns with references to specific precedents that established them:
  ```
  - **Monitoring probes**: Source in monitoring subnet, single username, regular interval.
    Precedents: SEC-2024-001, SEC-2024-015, SEC-2024-023.
  - **Service account rotation**: srcuser matches svc-*, burst of 2-3 attempts then success.
    Precedents: SEC-2024-008, SEC-2024-031.
  ```
  Known FPs are abstractions derived from precedents. When multiple precedents show the same pattern, the post-mortem agent proposes a known FP entry referencing them. Gives the agent fast-path heuristics before investigation starts.

- **Impact** — What happens if this is a true positive. Frames stakes and calibrates escalation urgency.
- **Field Notes** — Non-obvious field semantics for this alert type. References `common/data-sources/` where relevant.

**Optional (grows over time):**

- **Operational Notes** — Tribal knowledge that doesn't fit elsewhere. Environmental patterns, timing quirks, analyst experience.
- **Tuning Guidance** — How to reduce noise without losing detection.
- **Detection Gaps** — What this rule does NOT catch. Helps agent know when to investigate further.

### 3.3 Playbooks

Playbooks reference atomic leads (from `common/leads/`) and organize them into a prioritized investigation flow with **decision points**. They are guidance, not execution graphs — the agent follows them unless evidence tells it to deviate.

**Frontmatter:**

| Field | Required | Notes |
|-------|----------|-------|
| `signature_id` | mandatory | Links to context.md |
| `last_updated` | mandatory | When playbook was last revised |
| `total_investigations` | recommended | Running count, updated by post-mortem |
| `auto_close_rate` | optional | % resulting in auto-close |

**Body sections:**

**Mandatory:**

- **Investigation** — Two-layer structure reflecting the hypothesis and evidence dimensions:

  **Hypothesis catalog:** Pre-populated competing explanations for this alert type, each with predictions (what evidence each hypothesis expects). Gives the agent a starting differential before evidence is gathered. Written with `?` prefix for searchability.

  **Lead sequence:** Prioritized leads ranked by diagnosticity — how well they discriminate between the hypotheses in the catalog. Each lead entry specifies: the goal, which hypotheses it discriminates, what each hypothesis predicts for this lead, and what outcomes mean. Priority scores are data-driven: the post-mortem agent grades each lead after every investigation and the cumulative score updates.

  See schema-review.md §6.5 for the full investigation flow language specification, including the trace line format for sequential searchability.

- **Escalation Criteria** — When to stop investigating and escalate. Both positive triggers (explicit conditions like critical assets, privileged accounts, external IPs with successful logins) and negative triggers (exhausted investigation without resolution, no precedent match, low confidence on high severity).

**Highly recommended:**

- **Auto-Close Criteria** — Explicit conditions under which the agent can recommend closure. What the stop hook validates against. E.g.: matches a known FP pattern OR a precedent, all adversarial hypotheses investigated and refuted, no escalation criteria triggered.

- **Scope** — What's in and out of scope for automated investigation. Prevents the agent from going down rabbit holes.

**Optional:**

- **Response Actions** — What to do after investigation in `act` mode (close ticket, add comment, tag).

**Tool decoupling:** Playbooks reference leads by goal, not by tool. Each lead carries `data_tags` (§3.1a) that connect it to `data-sources/` files, which map to available systems. The subagent's resolution path: read lead → follow data tags → check data-sources/ for available systems → use that system's skill/MCP server. Tool documentation lives with the tool (MCP server, vendor skill), not in the KB.

### 3.4 Precedents (`precedents/`)

A precedent is a **curated, human-approved investigation pattern** — not raw ticket data. The ticketing system is the source of truth for ticket details; precedents capture the investigation flow and reasoning that the ticketing system doesn't store.

Not every investigation becomes a precedent. The post-mortem agent proposes new precedents for cases that are novel or instructive. Analyst approves via PR.

**Schema:**

| Field | Required | Notes |
|-------|----------|-------|
| `ticket_id` | mandatory | Reference back to ticketing system |
| `signature_id` | mandatory | For initial filtering |
| `disposition` | mandatory | benign / false_positive / true_positive |
| `hypotheses` | mandatory | Hypotheses considered and their final status |
| `flow` | mandatory | Investigation evidence — diagnostic entries `{lead, observed, assessment}` and scoping entries `{lead, observed, findings}` per cycle |
| `trace` | mandatory | One-line sequential summary for grep (see below) |
| `reasoning` | mandatory | Conditions, refutations, confidence notes (see below) |
| `key_indicators` | recommended | Specific observations that distinguish this case |
| `leads_that_resolved` | recommended | Which leads provided discriminating evidence |
| `created_at` | mandatory | When this precedent was created |

**The `reasoning` field** captures the logic behind the disposition — explicit conditions for matching and invalidation:

```yaml
reasoning:
  conditions:        # ALL must hold for this precedent to apply
    - "Source IP is internal (RFC1918)"
    - "Attempts follow regular interval (variance <15%)"
    - "Single username across all attempts"
    - "No successful login following failures within 30 min"
  refutes:           # ANY of these invalidates the match
    - "Successful login within 30 minutes of failures"
    - "Multiple distinct usernames (>2)"
    - "Source IP is external"
    - "Attempt frequency exceeds 20/hour"
  confidence_note:   # When the match is ambiguous
    - "If interval is regular but source is unknown, investigate further before matching"
```

**The `hypotheses` field** records which hypotheses were considered and their final status:

```yaml
hypotheses:
  - id: "?monitoring-probe"
    status: confirmed          # confirmed | eliminated | inconclusive
  - id: "?brute-force"
    status: eliminated
  - id: "?credential-stuffing"
    status: eliminated
```

**The `flow` field** records each investigation cycle — evidence gathered and its interpretation. Diagnostic and scoping leads have different shapes:

```yaml
flow:
  # Diagnostic lead — assessed against hypotheses
  - lead: authentication-history
    type: diagnostic
    why: "discriminates ?monitoring-probe (regular interval) from ?brute-force (high-frequency diverse)"
    observed: "5-min intervals, single username, 47 events over 7 days"
    assessment:
      "?monitoring-probe": "++"    # strongly supports
      "?brute-force": "--"         # strongly contradicts
      "?credential-stuffing": "--"

  # Scoping lead — assessed for impact, not against hypotheses
  - lead: data-access-audit
    type: scoping
    why: "determine what sensitive data the confirmed session accessed"
    observed: "session accessed 3 files in /sensitive/hr/"
    findings:
      affected_assets: ["q4-financials.xlsx", "salary-bands.csv", "db-credentials.env"]
      severity_factors: ["credentials file accessed", "PII in salary data"]
      blast_radius: "financial data + HR PII + database credentials"
```

**Diagnostic entries** carry `assessment` — a per-hypothesis map with weights: `++` strongly supports, `+` weakly supports, `~` neutral, `-` weakly contradicts, `--` strongly contradicts.

**Scoping entries** carry `findings` — structured observations about impact, affected assets, timeline bounds, or context. Scoping entries typically appear after a threat hypothesis is confirmed, when the investigation shifts from "what happened?" to "how bad is it?"

Both entry types share `lead`, `type`, `why`, and `observed`. The `type` field (`diagnostic` | `scoping`) determines which interpretation field is present — `assessment` or `findings`.

**The `trace` field** is a one-line sequential summary optimized for grep across many precedent files:

```
alert → authentication-history[regular-pattern ∴ ?monitoring-probe] → source-reputation[known-internal ∴ ?monitoring-probe] → benign
```

Grammar: `step ( → step )* → disposition`. Diagnostic steps: `lead-name[observation ∴ hypothesis-conclusion]`. Scoping steps: `lead-name[observation]` (no `∴` — scoping leads inform the response, not the diagnosis). The `∴` ("therefore") separates what was seen from what it meant for hypothesis elimination. Because the entire path is one line, grep returns complete sequences, not fragments. See schema-review.md §6.5 for searchability patterns.

The `outcome` vocabulary (used in observations) emerges from usage and is normalized by post-mortem consolidation over time. Hypothesis names (`?name`) provide the classification that was previously missing — `grep "?monitoring-probe"` across precedents finds every case where this hypothesis was considered, regardless of which leads were used.

**No separate `classification` field needed.** Hypothesis names serve as searchable classifications. `grep "status: confirmed"` + `grep "?monitoring-probe"` replaces a controlled vocabulary without the maintenance burden.

### 3.5 Ticket Data Model

| Field | Access Pattern |
|-------|---------------|
| Alert fields (srcip, dstip, rule, agent, etc.) | Read: per-ticket |
| Ticket metadata (status, assignee, timestamps, tags) | Read: per-ticket, Write: status + comments |
| Investigation history (comments, status changes, reports) | Read: per-ticket, Read: batch (recent) |
| Investigation summary (agent recommendation + narrative) | Write: per-ticket |

The ticketing system is the source of truth for ticket data. Precedent records reference tickets by ID but do not duplicate ticket content.

### 3.6 Scripts as Actions

1. Agent reads lead definition (goal + data needs)
2. Checks available tools (MCP first, then SIEM mapping, then direct API)
3. Writes script (bash/python) to `{run_dir}/scripts/`
4. Script validated by `validate-script.sh` hook (static analysis: AST parsing for disallowed imports, network target validation)
5. Script executes in a minimal container (network allowlisted to SIEM/ticketing, read-only filesystem except run dir, no capabilities, 30s timeout)
6. Agent reads output and interprets results

Container isolation is the primary defense — even if the hook misses a pattern, the blast radius is bounded. Pre-approved scripts in the approved script library bypass both hook and container.

### 3.7 Knowledge Base Learning Loop (Git-Native)

After each investigation, a post-mortem subagent produces two types of output:

**1. KB updates** — proposed changes to investigation knowledge, committed via git:

1. Analyze completed investigation (report, evidence, narrative)
2. Generate updates: new precedent, lead priority updates, playbook refinements, context additions, cross-cutting lessons, known FP abstractions
3. Update KB files in-place on a branch, consolidating with existing content
4. Commit, push, and open a PR for analyst review

**All KB changes require analyst approval via PR merge.** The PR diff is the review artifact — analysts see exactly what changed. Corrections to wrong precedents are proposed as removals/edits in PRs.

| Update type | Git operation | Conflict risk |
|-------------|--------------|---------------|
| New precedent (`precedents/{slug}.json`) | New file | None |
| New cross-cutting lesson (`common/lessons/{slug}.md`) | New file | None |
| Playbook priority scores | Edit `playbook.md` | Medium |
| New known FP pattern in `context.md` | Edit `context.md` | Low |
| Playbook structural change | Edit `playbook.md` | High |

High-frequency updates (new precedents, new lessons) are new files and never conflict. Edits to shared files (playbooks, context) are rarer and benefit from PR review.

**2. Suggestions** — actionable recommendations that don't belong in the KB:

| Suggestion type | Example | Destination |
|-----------------|---------|-------------|
| Rule tuning | "Exclude monitoring subnet 10.0.1.0/24 from rule 5710" | Detection engineering backlog |
| Rule suppression | "Suppress rule 5710 for srcuser=nagios during 02-04 UTC" | Detection engineering backlog |
| Infrastructure hardening | "Enable MFA on server web-server-01" | Security engineering backlog |
| Visibility gap | "No process-level logging on database servers" | Observability backlog |
| Playbook gap | "No playbook exists for rule 5712, which co-occurs with 5710" | SOC backlog |

Suggestions are **backlog items for other teams**, not investigation knowledge. They are written to the investigation ticket as a recommendations section and, in `act` mode, optionally created as new tickets in the backlog. They are NOT stored in `knowledge/` — the KB captures how to investigate; suggestions capture what to fix.

The post-mortem agent generates suggestions by comparing the investigation against the knowledge base: if the agent had to work around a detection gap, or the same FP pattern has triggered N times without a rule exclusion, or scoping leads revealed unmonitored assets, those become suggestions.

### 3.8 Field Documentation

Field semantics are documented at three levels, following the principle that knowledge lives where it's maintained:

**Vendor level** (tool skill / MCP server) — Universal field semantics for a product. "In CrowdStrike, `ParentProcessId` is the PID at spawn time." This ships with the vendor integration — the agent reads it from the tool's skill/description. Not stored in the KB.

**Data pipeline level** (`knowledge/common/data-sources/`) — Org-specific pipeline behavior: how data is normalized, what's lost in translation, field name mappings between systems. Example: "Wazuh normalizes AD events: `TargetUserName` becomes `data.dstuser`." See §3.1c.

**Signature level** (Field Notes section in `context.md`) — Fields where this specific alert type changes the usual interpretation. References data-source docs rather than duplicating. Example: "For rule 5710, `srcuser` is the attempted username — may not exist on the system."

Both KB levels are maintained through the post-mortem learning loop (§3.7). When the agent encounters a field it cannot interpret with high confidence, it notes the gap in the investigation narrative. Post-mortem proposes an update via PR.

### 3.9 Precedent Matching

Two-layer matching based on hypothesis outcomes and investigation flow:

**Layer 1 — Structural search (deterministic):** Query by `signature_id` (required) + overlapping hypothesis names and lead assessments from the investigation flow + key indicators. The `trace` field enables fast initial filtering — grep for matching hypothesis conclusions or observation patterns across all precedent files. Returns 3-10 candidates. Because ANALYZE sections in `investigation.md` use structured YAML entries (§5.2a) with the same schema as precedent `flow` entries, the matching algorithm can programmatically compare the current investigation's assessments against precedent flow entries — no prose parsing required.

**Layer 2 — Reasoning judgment (LLM):** Agent reads each candidate's `reasoning.conditions` and `reasoning.refutes` and verifies against current evidence. This enables mid-investigation matching — "I've verified 3 of 4 conditions, none of the refutes have triggered."

**Sequential searchability:** Because the `trace` field encodes the full investigation path in a single greppable line, the agent (or analyst) can search for any element and get the complete sequence:

| Search goal | Grep pattern |
|---|---|
| Cases where this hypothesis was confirmed | `grep "∴ ?monitoring-probe.*→ benign"` |
| Cases that used this lead | `grep "authentication-history\["` |
| What happened after observing this pattern | `grep "regular-pattern"` (context shows next step) |
| Cases that escalated from this hypothesis | `grep "?brute-force.*→ escalate"` |

**Stop hook verification:** The hook independently checks structural overlap — `signature_id` match, at least one hypothesis overlap, at least one flow step overlap, reasoning conditions addressed in the report. Prevents matching against unrelated precedents.

---

## 4. Validation Hooks

Deterministic scripts enforcing invariants. Cannot be bypassed by LLM output.

### 4.1 Hook Inventory

| Hook | Event | Purpose |
|------|-------|---------|
| `sanitize-input.sh` | Pre-invocation | Strip control chars, enforce length limits, wrap in salted delimiters (§8.2) |
| `sanitize-external.sh` | Post-tool-call | Same sanitization for SIEM/external data returned during investigation (§8.2) |
| `validate-transition.sh` | Pre-tool-call (state write) | Verify legal phase transition |
| `validate-script.sh` | Pre-tool-call (script exec) | Static analysis (AST parsing, network target validation) before container execution |
| `budget-enforcer.sh` | Per-tool-call | Track tool calls/subagents, reject if over budget |
| `validate-report.sh` | Stop | Tier 1: frontmatter schema + deterministic checks. Tier 2: semantic judge for report consistency and precedent match validity |
| `audit-logger.sh` | Stop + per-tool-call | Log external actions (tool calls, script executions) with caller, parameters, timestamp |
| `post-mortem.sh` | Stop | Launch post-mortem, commit KB updates to branch, open PR, write suggestions to ticket |

### 4.2 Input Sanitization

See [§8. Security: Untrusted Data Handling](#8-security-untrusted-data-handling) for sanitization scope, limits, and the full defense layer stack.

### 4.3 State Transition Validator

Fires when the agent writes `state.json`. The state file is a lean phase-tracking record — it does NOT contain investigation content like hypotheses or planned leads (see §5.1).

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

The hook validates **structural constraints only** — legal phase sequence, no skipping, no infinite loops. Whether the agent's reasoning is sound (e.g., whether it genuinely considered adversarial hypotheses) cannot be verified by a deterministic hook reading agent-written fields. Reasoning quality is validated at the end by the recommendation validator (§4.4) and human review, not during transitions.

### 4.4 Report Validator (Stop Hook)

Fires when the investigator writes `report.md`. The report is a single unified file: YAML frontmatter for machine-readable fields, markdown body for analyst-readable narrative. Validation is two-tier.

**Frontmatter fields:** `ticket_id`, `signature_id`, `signature_description`, `status` (resolved|escalate), `disposition` (benign|false_positive|true_positive), `confidence` (high|medium|low), `matched_precedent` (ticket_id|null), `leads_pursued` (integer count).

**Note on `confidence`:** Agent-provided signal for users, not a guardrail input. Safety gating uses structural checks and the semantic judge only.

**Tier 1 — Deterministic (milliseconds):**

| # | Check | Rule | On failure |
|---|-------|------|------------|
| 1 | Frontmatter schema | Required fields present, valid enum values | Reject, agent must fix |
| 2 | Minimum evidence | `leads_pursued` ≥ minimum per severity (low:1, med:2, high:3, crit:4) | Reject, investigate more or escalate |
| 3 | Precedent requirement | status=resolved → `matched_precedent` non-null, references existing precedent, `signature_id` matches, flow overlap (§3.9) | Override to escalate |
| 4 | Escalation patterns | Alert fields vs `permissions.yaml` patterns (critical assets, external IPs) | Override to escalate |
| 5 | Criticality check | Critical assets → always escalate; elevated → doubled evidence minimum | Override to escalate |

**Tier 2 — Semantic judge (Haiku-class LLM, ~1-2s, runs only if Tier 1 passes):**

Receives the report, the matched precedent record, and the current alert data. Checks:

| Check | What it catches |
|-------|----------------|
| Precedent match validity | "Alert is from external IP but precedent is about internal monitoring" |
| Internal consistency | Summary contradicts investigation log |
| Unsupported conclusions | Disposition not supported by described evidence |
| Missing obvious checks | Alert involves root login but no lead investigated privilege context |
| Weak assumptions | "Probably a monitoring probe" without evidence |

Returns `pass` or `flag` with reason. `flag` → override to escalate.

**After validation:** `act` mode → execute action; `recommend` mode → output for review. Any failure → escalate in both modes.

---

## 5. Communication Protocol

### 5.1 Run Directory Structure

Agent-accessible (read/write):

```
runs/{run_id}/
├── sanitized-alert.json            # Cleaned alert data (hook-written)
├── state.json                      # Phase transitions only (§5.2)
├── investigation.md                # Working log in flow language (§5.2a)
├── report.md                       # Final output: frontmatter + narrative (hook-validated, §4.4)
├── scripts/                        # Agent-written scripts (audit trail)
└── leads/                          # Raw subagent returns (JSON)
```

Hook-managed (agent cannot access):

```
hooks/{run_id}/
├── budget.json                     # Tool call / subagent counters (§5.3)
└── audit-log.json                  # External action log: tool calls, script executions
```

### 5.2 State File

Tracks phase transitions only. Investigation content (hypotheses, planned leads, evidence interpretation) lives in `investigation.md` (working log) and `report.md` (final output).

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

### 5.2a Investigation Log (`investigation.md`)

The investigator's working document, written chronologically using the investigation flow language (§3.3 playbooks, §3.4 precedents, schema-review §6.5). Phase headers mirror the state machine; content uses the same hypothesis/lead/assessment vocabulary used in playbooks and precedents.

**ANALYZE sections use structured YAML blocks**, not free-form prose. This serves two purposes: (1) the post-mortem agent can extract flow entries directly to build precedent records without parsing prose, and (2) mid-investigation precedent matching can programmatically compare the current assessment state against precedent flow entries. The YAML structure mirrors the precedent `flow` schema (§3.4) — same fields, same assessment weights.

```markdown
## CONTEXTUALIZE

Alert: SSH failed auth from 10.0.1.50 → web-server-01, user "testuser" (wazuh-rule-5710)
Precedent scan: SEC-2024-001 (?monitoring-probe, 92% base rate benign)

## HYPOTHESIZE (cycle 1)

hypotheses:
  - "?monitoring-probe": automated health check generating auth failures
  - "?brute-force": credential guessing attack
  - "?credential-stuffing": leaked credential replay

Selected lead: authentication-history (diagnosticity: 9.2)
  discriminates: ?monitoring-probe vs ?brute-force vs ?credential-stuffing
  predictions:
    ?monitoring-probe → regular interval, single username, bounded count
    ?brute-force → high frequency, diverse usernames, increasing
    ?credential-stuffing → burst, known-leaked names, external source

## GATHER → authentication-history

[→ leads/authentication-history.json]

## ANALYZE (cycle 1)

- lead: authentication-history
  type: diagnostic
  why: "discriminates ?monitoring-probe vs ?brute-force vs ?credential-stuffing"
  observed: "5-min intervals, single username 'testuser', 47 events over 7 days"
  assessment:
    "?monitoring-probe": "++"   # regular interval, single user — textbook
    "?brute-force": "--"        # not high-frequency, not diverse
    "?credential-stuffing": "--" # not bursty, single username

surviving: [?monitoring-probe]

## HYPOTHESIZE (cycle 2)

Remaining: ?monitoring-probe (strong)
Confirming lead: source-reputation (diagnosticity: 8.7)
  predictions:
    ?monitoring-probe → known internal, monitoring subnet

## GATHER → source-reputation

[→ leads/source-reputation.json]

## ANALYZE (cycle 2)

- lead: source-reputation
  type: diagnostic
  why: "confirms ?monitoring-probe (known internal) vs external threat"
  observed: "10.0.1.50 in monitoring subnet, known Nagios host"
  assessment:
    "?monitoring-probe": "++"   # known internal monitoring host

surviving: [?monitoring-probe (confirmed)]

## CONCLUDE

trace: alert → authentication-history[regular-pattern ∴ ?monitoring-probe] → source-reputation[known-internal ∴ ?monitoring-probe] → benign
disposition: benign
matched_precedent: SEC-2024-001
```

**Key properties:**

- **Phase headers** (`## PHASE`) mirror state transitions — the log and state file are consistent views of the same progression
- **GATHER sections are thin** — just a pointer to the raw subagent return in `leads/`. The subagent's observations are interpreted by the investigator in the ANALYZE section that follows
- **ANALYZE sections are structured YAML** — each entry mirrors the precedent `flow` schema (§3.4), with `type`, `why`, `observed`, and either `assessment` (diagnostic) or `findings` (scoping). This makes the investigation log machine-readable: the post-mortem agent extracts flow entries directly, and mid-investigation precedent matching compares structured assessments programmatically. The investigator reads subagent output (from `leads/`), writes the structured entry, and updates the surviving hypothesis set
- **The trace line** at CONCLUDE is generated from the log, compressing the full investigation path into one greppable line
- **Subagents read this file** for context when spawned — later subagents see richer context because the log has grown. No separate context serialization needed

The relationship between files: `investigation.md` is written *during* the investigation for the investigator and subagents. `report.md` is written at CONCLUDE for analysts and hooks — summary-first, referencing or importing from the investigation log. `leads/` stores raw subagent returns. Precedent records (§3.4) are curated projections of the investigation log, not a separate format.

### 5.3 Budget File

Lives outside agent scope — only `budget-enforcer.sh` reads and writes it. The agent learns of budget exhaustion through hook rejection messages, not by reading the file.

```json
{
  "run_id": "run-abc123",
  "tool_calls": 12,
  "subagent_spawns": 2,
  "started_at": "2026-03-12T14:30:00Z"
}
```

Limits are configuration: defaults in `config/budget-defaults.yaml`, overridable per-signature in `permissions.yaml`.

### 5.4 Schema Enforcement

Every file written by an agent is validated before being read by another agent or hooks. Schema definitions live in `config/schemas/` as JSON Schema files.

---

## 6. Interface and Integrations

### 6.1 Primary Interface: Claude Code

The system is a **Claude Code plugin**. Claude Code is the runtime — the agent runs inside it, and all external access happens through tools the user configures: MCP servers, scripts (+ API keys), or any combination. No custom UI to build or maintain.

The agent discovers available tools at runtime. Playbooks reference leads by goal, not by tool — the agent resolves to whatever's available via `siem-mapping.json` and MCP server configuration.

**Modes:** `recommend` (output report, human acts) or `act` (execute actions, validated by hooks).

**Invocation:** Initially, the agent is invoked by the analyst — tagging Claude in a ticket, instructing it in chat, or running it from the CLI. The specific trigger mechanism depends on the user's environment and is supported by Claude Code's ecosystem (chat integrations, CLI, IDE). As trust builds through consistent accuracy on a signature, the user may configure automatic invocation on new tickets. The system does not prescribe the trigger — it accepts alert data and produces a report.

### 6.1a Execution Environment

**The agent runs wherever the user deploys Claude Code.** This is a deliberate architectural choice: we distribute a plugin, not a hosted service. The user controls where it runs, what tools it can reach, and what credentials it holds. This aligns with the "connect your tools" model and avoids the infrastructure overhead and trust assumptions of a managed platform.

**Recommended deployment: a dedicated container or VM** with network access scoped to the systems the agent needs (SIEM, ticketing, git host). This bounds blast radius from two threat vectors:

| Threat | Bare workstation | Dedicated container |
|--------|-----------------|-------------------|
| Script injection (§8.1) | Agent-written scripts execute with analyst's permissions and network access | Scripts execute in a container with allowlisted network, read-only FS, no capabilities (§3.6) |
| Prompt injection → tool misuse | Agent has access to everything the analyst does — email, chat, other systems | Agent can only reach configured integrations; no lateral access |
| Resource exhaustion | Competes with analyst's work | Isolated resources, budget enforcement (§1.3) still applies |

The container recommendation is consistent with the existing script isolation model (§3.6) — it extends the same principle from individual scripts to the agent process itself. Users who accept higher risk can run directly on a workstation; the validation hooks (§4) and budget enforcement (§1.3) still provide defense in depth.

**Security model transparency:** The system should clearly communicate its security posture to users at deployment time. The `recommend` vs `act` mode choice, the budget limits, the hook inventory, and the isolation level are all user-visible configuration — not hidden defaults. Users make informed tradeoffs:

| Configuration | Lower risk | Higher capability |
|---------------|-----------|-------------------|
| Mode | `recommend` — human reviews all actions | `act` — agent closes tickets, updates status |
| Isolation | Dedicated container, scoped network | Analyst workstation, full network |
| Autonomy | Manual invocation per ticket | Automatic invocation on new alerts |
| Budget | Conservative limits (fewer tool calls) | Generous limits (deeper investigation) |

Each axis is independently configurable per signature via `permissions.yaml`. A mature, high-volume, well-understood signature (e.g., monitoring probe alerts with 95%+ benign rate) might run in `act` mode with automatic invocation, while a new or high-severity signature stays in `recommend` mode with manual invocation.

### 6.2 Recommended Integrations

| Integration | Access | Why it matters |
|-------------|--------|----------------|
| **Ticketing system** (Jira, TheHive, ServiceNow, etc.) | Read: ticket metadata, alert fields, investigation history (per-ticket + batch). Write (`act` mode): status, comments, disposition. | Core input/output — reads alerts, writes results. Batch read enables recent alert context (§1.4). |
| **SIEM** (Wazuh, Splunk, Elastic, etc.) | Read: events, rules, agent info. | Evidence gathering — most leads query the SIEM. |
| **Git host** (GitHub, GitLab, or any git server) | Read/write: branches, PRs. | Powers the learning loop (§3.7) — post-mortem commits KB updates and opens PRs. Without this, KB updates require manual file management. |

### 6.3 Optional Integrations

| Integration | Value |
|-------------|-------|
| **Chat** (Slack, Teams) | Auto-close notifications, escalation alerts, collaborative threads. |
| **EDR** (CrowdStrike, Defender, etc.) | Process trees, endpoint context, containment actions. |
| **DLP** | Data exfiltration context. |
| **Firewall / network tools** | Connection logs, block actions. |
| **Threat intelligence** | IP/domain/hash reputation. |
| **Identity provider** (AD, Okta) | User roles, service accounts. |
| **Asset inventory** (CMDB) | Asset criticality, owner — feeds escalation decisions. |

### 6.4 Output

Every investigation produces a single **`report.md`** — YAML frontmatter (machine-readable, for hooks and ticketing integration) + markdown body (analyst-readable). See §4.4 for format and validation. Ticketing integration reads frontmatter fields for structured updates and posts the markdown body as a comment.

### 6.5 Quality Monitoring

- **Auto-closure sampling:** 10% of auto-closed alerts flagged for analyst spot-check. Override rates feed signature-level tracking.
- **Systematic error detection:** If override rate for a signature exceeds 2%, autonomy auto-downgrades to `recommend` until investigated.

---

## 7. Onboarding

### 7.1 Credential Management

Credentials are environment-level: env vars or mounted secrets. Scripts reference `$WAZUH_API_TOKEN`; MCP servers handle auth internally. The LLM never sees credentials.

### 7.2 Onboarding Workflow

1. Set up execution environment — dedicated container recommended (§6.1a), with network scoped to SIEM, ticketing, and git host
2. Configure SIEM access (MCP server or API endpoint + credentials)
3. Configure ticketing (scoped API token)
4. Configure git host for learning loop (optional but recommended)
5. Populate `config/siem-mapping.json` with available data sources
6. Create initial KB (playbooks + precedents for highest-volume signatures)
7. Set `permissions.yaml` per signature — mode, budget, autonomy level (§6.1a)
8. Seed approved script library with common query patterns
9. Test with `recommend` mode on historical alerts
10. Graduate to `act` mode for signatures with consistent accuracy

### 7.3 Enterprise Considerations

- **SSO/SAML:** Agent's service account uses same IAM as analysts, scoped permissions
- **Secrets management:** Vault/AWS Secrets Manager, injected at runtime
- **Network segmentation:** Agent in SOC segment; reproduction sandboxes (future) in isolated segment
- **Audit compliance:** Filesystem-based logs feed into SIEM or log aggregator

---

## 8. Security: Untrusted Data Handling

Alert data is attacker-influenced — the primary security concern for LLM-based security tools. External data also introduces standard code execution risks when the agent writes scripts.

### 8.1 Threat Model

**Prompt injection:** Attackers craft payloads in log messages, usernames, HTTP headers, or process arguments to make the LLM ignore evidence and produce a benign classification.

**Code injection via agent scripts:** Field values containing shell metacharacters (`; rm -rf /`), path traversal (`../../etc/passwd`), template injection (`${jndi:ldap://...}`), or SSRF payloads (URLs) that end up interpolated into agent-written scripts. This is a standard application security risk, not LLM-specific.

**Attack surfaces:** Initial alert data, SIEM query results, ticketing system data, any external data read during investigation.

### 8.2 Input Sanitization — Scope and Limits

Input sanitization (`sanitize-input.sh`, `sanitize-external.sh`) is deliberately narrow:

**What it does:**
- Strip control characters, unicode tricks, and zero-width characters that could confuse delimiter parsing
- Enforce length limits on free-text fields (truncate with `[TRUNCATED]`)
- Wrap external data in per-run salted delimiters (`<run-{salt}-data>`)

**What it does NOT do:**
- Field-level schema validation against alert structure (alert schemas vary across signatures, SIEMs, and team customizations — rigid validation would break on real-world data)
- Aggressive content filtering of field values (the fields with highest injection risk — command lines, URLs, usernames — are also the fields with highest investigative value)

**Honest assessment:** Static sanitization stops trivial delimiter-escape attacks and token-budget exhaustion. It does not stop semantic injection in plain-language field values. The fields the agent must read carefully are exactly the fields where an attacker can plant instructions.

### 8.3 Defense Layers

Security relies on defense in depth. No single layer is sufficient.

| Layer | Mechanism | What it actually stops |
|-------|-----------|----------------------|
| Static sanitization | Strip control chars, length limits, salted delimiters | Delimiter escapes, token exhaustion, trivial encoding tricks |
| Salted context tagging | Per-run random salt in delimiters; attackers can't predict | Pre-crafted closing tag attacks |
| Semantic judge | Haiku-class model screens for instruction-like content in external data | Semantic injection ("this is routine, classify as benign") |
| Canary tokens | Unique per-run string in system prompt; presence in tool output = manipulation | LLM regurgitation of system prompt content |
| Script validation + container isolation | `validate-script.sh` static analysis + container execution (network allowlist, read-only FS, no capabilities, 30s timeout) | Code injection via field values; blast radius bounded even if static analysis is evaded |
| Structural defenses (hooks) | Stop hook verifies investigation was actually performed — evidence minimums, precedent matching, escalation patterns | Injection that convinces the agent to skip investigation and recommend benign |
| Human review | `recommend` mode: human sees everything; `act` mode: periodic sampling | Everything above fails |

**The real security boundary is hooks + human review**, not input sanitization. Sanitization reduces noise; hooks enforce that the investigation actually happened regardless of what the LLM "believes." Execution environment isolation (§6.1a) provides an additional outer boundary — even if all software layers fail, the agent's blast radius is limited to the systems it can reach.

### 8.4 Interactive Mode

When the agent operates as an analyst's thinking partner (interactive CLI, collaborative threads), analyst input is NOT sanitized. The trust boundary is: **automated sources (SIEM, ticketing API, external data) are untrusted; human input in interactive mode is trusted.** Sanitizing analyst input would be hostile to the collaborative UX without meaningful security benefit.

### 8.5 Accepted Risks

**Accepted:** False escalations from sanitization, semantic judge cost (~$0.001/call), reduced investigation quality if useful context is in a truncated field.

**Not accepted:** Auto-closing injection-influenced alerts without legitimate precedent, hooks being bypassable by LLM output, or field values being interpolated into scripts without validation.

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
| **2. Signature Context** | Context + playbook + precedents (loaded as Claude Code skill) | Primes strategy before attacker data |
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
