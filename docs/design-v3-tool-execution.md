# Tool Execution Architecture

**Version:** 0.1 | **Date:** April 2026 | **Status:** Design sketch

For investigation methodology and knowledge base structure, see [design-v3-architecture.md](design-v3-architecture.md). This document covers the layer between investigative reasoning and tool execution — how leads become queries, how results become evidence, and how the system validates and improves over time.

---

## 1. Problem Statement

The investigation methodology (hypotheses, leads, assessments) is well-defined. The knowledge base (signatures, playbooks, precedents) is structured. The gap is the **execution layer**: how does a lead like "profile authentication history" become a concrete query against a live system, and how does the agent know the results are correct and complete?

This matters because:

- **Tool sprawl** — A production SOC touches 10+ systems. Each system has its own query language, field names, access patterns, and failure modes. Naive tool exposure (all MCP schemas loaded upfront) consumes context window budget before investigation begins.
- **Silent failures** — A query that returns zero results or partial results looks identical to "nothing happened." The agent cannot distinguish bad query from clean environment without verification.
- **Knowledge decay** — Field names change, data pipelines break, retention policies expire. Pre-built queries that worked last month may silently return wrong results today.
- **Result volume** — Raw SIEM output can be thousands of lines. Without compression, tool results drown the investigation context.

### Design principles

1. **Lazy loading** — The agent sees a lightweight index of capabilities. Full execution context loads only when a lead activates it.
2. **Scripts as executable knowledge** — Pre-built scripts carry institutional knowledge between investigations. They are readable, testable, and auditable.
3. **Built-in verification** — Every tool execution includes metadata that lets the agent assess result quality without trusting blindly.
4. **Graceful degradation** — When pre-built scripts fail or don't exist, the agent falls back to guided ad-hoc queries using environment knowledge. This is an expected path, not a failure mode.
5. **Facts up, meaning down** — Lead subagents surface quantified observations and anomalies. The main agent assigns investigative meaning.

---

## 2. Execution Mechanism: Scripts over MCP

### Why scripts (bash/python) as the primary model

MCP is the AI-native protocol, but it frontloads all tool schemas into the agent's context window. With 10 servers x 5 tools each, that's 5-10K tokens of schemas before the first message. For a budget-constrained investigation agent, this is an unacceptable tax.

The alternative: **scripts as skills**, loaded on demand. The agent sees a lightweight index ("auth profiling", "network context", "endpoint telemetry") in the lead and data-source definitions. When a lead activates, the full execution context loads — the script itself, its documentation, environment-specific defaults. This is the same lazy-loading pattern Claude Code uses with deferred tools.

| Aspect | MCP | Scripts |
|--------|-----|---------|
| Context cost | Upfront (all schemas always loaded) | On-demand (loaded per lead) |
| Credential handling | Encapsulated in server (agent never sees tokens) | Env vars or vault (agent could access) |
| Discovery | Automatic (tool list from server) | Manual (documented in data-sources + systems) |
| Flexibility | Fixed tool interface | Arbitrary logic, parameterization, output shaping |
| Testability | Opaque | Unit-testable, version-controlled |
| Maintenance | Server owner maintains | Investigation team maintains |

### Credential security

Scripts require credentials injected via environment variables or secrets manager. Unlike MCP (where the agent only invokes tools, never sees underlying tokens), bash-based execution means a compromised or manipulated agent could theoretically exfiltrate credentials (`echo $API_KEY`).

Mitigations:
- **Hook-based audit** — `audit_tool_calls.py` already logs all tool calls. Extend to flag bash commands that reference credential env vars.
- **Credential wrapping** — Scripts source credentials internally; the agent calls the script with parameters, never handles raw credentials. The script is the trust boundary.
- **Read-only by default** — All investigation scripts are read-only queries. Write operations (ticket updates, response actions) are a separate, more restricted category gated by autonomy mode.

Threat model update needed: document the credential exposure surface and mitigations explicitly.

### When MCP is still appropriate

MCP remains useful for:
- **Third-party integrations** where we don't control the API (vendor-provided MCP servers)
- **Tools with complex state** (e.g., ticketing systems with session management)
- **Environments where script deployment is restricted**

The architecture supports both. A lead's data-source mapping can point to either a script or an MCP tool. The subagent follows whichever path the data-source specifies.

---

## 3. The Lead Execution Model

### 3.1 Architecture: three layers, one directory

Each lead has three knowledge layers that serve different purposes:

```
Lead definition (definition.md)     — WHAT: methodology
  "What to characterize, common pitfalls, data tags"

Query templates (templates/{vendor}.md) — HOW: field mappings + native query patterns
  "Entity field mapping, base query in native syntax, example CLI invocations"

SIEM CLI (scripts/tools/{vendor}_cli.py) — EXECUTE: auth, HTTP, output formatting
  "Thin execution wrapper — the agent constructs queries, the CLI runs them"

Environment (systems/{vendor}/)     — WHERE: system-specific config
  "Field names, index names, API endpoints, credentials, defaults"
```

A fourth layer — **WHY** (which hypotheses this lead discriminates, predictions, priority) — lives in playbooks, not in the lead itself. Leads are hypothesis-agnostic investigation units; playbooks give them investigative meaning for a specific signature.

These layers compose through the data tag vocabulary:

```
playbook.md                    lead directory (common/leads/{lead}/)
  lists leads by name    →       definition.md — methodology + data_tags
  with predictions                    ↓ data_tags
  and priority                   operations/ file (§10)
                                      ↓ concrete operations + sources
                                 sources/ file
                                      ↓ access method + CLI
                                 templates/{vendor}.md — query template in lead dir
                                      ↓ executed via
                                 scripts/tools/{vendor}_cli.py — lean SIEM CLI
```

### 3.2 Lead directory structure

Each lead is a directory under `common/leads/`, containing its definition and optional query templates per vendor. This keeps methodology and query knowledge colocated.

```
knowledge/common-investigation/leads/
├── _template/                        # Template for new leads
│   ├── definition.md                 #   Methodology template
│   └── templates/
│       └── system-name.md            #   Query template skeleton per vendor
├── authentication-history/
│   ├── definition.md                 # What to characterize, pitfalls, data tags
│   └── templates/
│       └── wazuh.md                  # Wazuh query template: field mapping + base query + examples
├── process-lineage/
│   └── definition.md
├── source-reputation/
│   └── definition.md
├── network-analysis/
│   └── definition.md
├── recent-alert-correlation/
│   └── definition.md
├── username-analysis/
│   └── definition.md
├── data-source-debug/                # Meta-lead: debugging protocol (no templates)
│   └── definition.md
└── ad-hoc/                           # Meta-lead: checklist for undefined leads
    └── definition.md
```

Not every lead has `templates/`. Some leads (like `data-source-debug`) are methodology-only — the subagent follows the protocol using environment knowledge and ad-hoc queries. A missing `templates/` directory is a signal to the subagent: construct the query ad-hoc using `systems/{vendor}/` knowledge.

### 3.3 Query templates and SIEM CLI

The execution layer is split into two parts:

1. **Query templates** (`templates/{vendor}.md`) — per-lead, per-vendor knowledge artifacts that map the lead's investigative question to a concrete query. They contain entity field mappings, the base query in native syntax, and example CLI invocations. The agent reads these to understand *what to query and how*.

2. **SIEM CLI** (`scripts/tools/{vendor}_cli.py`) — a thin, vendor-specific wrapper that handles authentication, HTTP, pagination, and output formatting. The agent constructs queries using the template's field mappings and passes them to the CLI. The CLI never interprets query semantics — it just runs what it's given.

This separation keeps query knowledge (which field to use, what filters to apply) in the lead directory where it belongs, while execution plumbing (auth, HTTP, output formatting) lives once in the CLI.

#### Query template structure

Each template follows a standard format (see `_template/templates/system-name.md`):

```markdown
# {System} Query Template: {lead-name}

## Entity Field Mapping
| Entity type | Field        | Notes                                  |
|-------------|--------------|----------------------------------------|
| ip          | data.srcip   | Source IP of the auth attempt           |
| user        | data.srcuser | SSH only. For Windows AD use data.dstuser |

## Base Query
\`\`\`
rule.groups:sshd AND {entity_field}:{entity_value}
\`\`\`

## Example Invocations
\`\`\`bash
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND data.srcip:10.0.0.5' \
  --start 2026-04-04T10:00:00Z --window 2h
\`\`\`

## Customization Notes
- How to narrow/broaden the query for common variations
- Known quirks specific to this query on this system
```

#### SIEM CLI interface

The CLI accepts queries in the vendor's native syntax. It handles the plumbing:

```bash
# Basic query with time window
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND data.srcip:10.0.1.50' \
  --start 2026-04-04T10:00:00Z --window 2h

# Absolute time range
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND data.srcuser:admin' \
  --start 2026-04-04T08:00:00Z --end 2026-04-04T12:00:00Z

# Health check (connectivity canary — usually handled by preflight)
python3 scripts/tools/wazuh_cli.py health-check

# Raw JSON output for programmatic parsing
python3 scripts/tools/wazuh_cli.py query --query '...' --start ... --window 2h --raw
```

The CLI's formatted output includes built-in verification metadata:

| Field | Purpose |
|-------|---------|
| Query | Transparency — agent can review and adapt if needed |
| Most recent matching event | Canary — is the data source alive and current? |
| Index event count (unfiltered) | Scale reference — 0 filtered from 500K = good filtering; 0 from 0 = dead source |
| Matching events | Primary result |
| Sample events (first 5) | Sanity check — agent verifies events match expectations |
| Count breakdowns (by rule, IP, user, hour) | Quantified summary for the main agent to reason about |

#### Credential handling

The SIEM CLI is the credential trust boundary. Credentials are injected via environment variables (`WAZUH_API_PASSWORD`), never passed as CLI arguments or exposed in output. The CLI sources non-secret config (index names, endpoints, retention) from `systems/{vendor}/config.env`.

### 3.4 Baseline comparison

The agent runs the same query with a shifted time window for comparison. The SIEM CLI returns identical output structure, enabling direct comparison: "47 failed auths in alert window vs 3 in equivalent window 7 days ago — 15x deviation."

```bash
# Alert window
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND data.srcip:10.0.1.50' \
  --start "$ALERT_TIME" --window 2h

# Same query, 7 days earlier (agent computes the shifted time range)
python3 scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sshd AND data.srcip:10.0.1.50' \
  --start "$BASELINE_START" --window 2h
```

#### When to use baselines

Not every lead needs a baseline. The agent decides based on context:
- **High-volume sources** (auth, network flow) — baseline useful, "14 failed logins" means nothing without context
- **Binary checks** (file hash reputation, known-bad IP) — no baseline needed
- **Rare events** (privilege escalation, lateral movement) — baseline useful, wider comparison window (30d)

### 3.5 Missing leads: the ad-hoc path

When the main agent requests a lead that has no directory in `common/leads/`, the subagent should **fail fast** and return with available context, not attempt an open-ended investigation.

Specifically:

1. **Subagent checks** for lead directory → not found
2. **Subagent reads** `common/leads/ad-hoc/definition.md` — a checklist for undefined leads
3. **Subagent reports back** to the main agent with:
   - What data sources *might* be relevant (based on data tags or the goal description)
   - What systems are available for those data sources
   - Whether health checks pass for those systems
   - A recommendation: "I can attempt ad-hoc data gathering using [system X] for [data type Y], or the main agent can reformulate"
4. **Main agent decides** whether to re-dispatch with ad-hoc instructions or pursue a different lead

Why fail fast instead of allowing discussion? Subagents in Claude Code are one-shot — there is no back-and-forth. An open-ended "figure it out" dispatch risks the subagent burning context and budget on the wrong approach. Better to return quickly with available information so the main agent can make an informed dispatch with specific ad-hoc instructions, including which system to query and what the debugging protocol's "start wide" step should target.

The `ad-hoc/definition.md` checklist:

```markdown
# Ad-hoc Lead Execution

## When this applies
The main agent requested a lead with no pre-built definition or script.

## Checklist
1. Identify the data type needed from the goal description
2. Search data-sources/ for matching tags or related data types
3. Run health checks on candidate systems
4. Report findings to main agent:
   - Available data sources and their health status
   - Relevant field names from systems/{vendor}/ field quirks documentation
   - Suggested query approach (if straightforward)
   - Caveats and gaps
5. Do NOT execute queries without explicit ad-hoc instructions from main agent

## Why fail fast
Budget is limited. An undefined lead means the main agent's mental model
and the knowledge base are misaligned. The main agent needs this signal
to either reformulate the lead, use the debugging framework to explore
available data, or escalate.
```

---

## 4. Environment Knowledge

### 4.1 Responsibility split

The `environment/` directory is organized into four layers that serve different audiences and change at different rates. See §10 for the full data resolution model.

| Layer | Directory | Content | Audience | Mutability |
|-------|-----------|---------|----------|------------|
| **Context** | `context/` | What's normal here — IP ranges, identity patterns, business rhythms | Agent reasoning (both main + subagent) | Human-maintained, slow-changing |
| **Operations** | `operations/` | Abstract → concrete operation mapping, coverage, data gaps | Main agent (predictions, gap awareness) + subagent (what to query) | Human-maintained, changes with environment |
| **Sources** | `sources/` | Where data lives — system, index, retention, access method, coverage per operation | Subagent (source selection, fallback) | Human-maintained, changes with pipelines |
| **Access** | `access/` | Tool constraints — CLI usage, rate limits, host access rules | Subagent (execution) | Maintained with tool updates |
| **Systems** | `systems/{vendor}/` | Vendor-specific field knowledge — quirks, query patterns, config | Subagent (query construction) + templates | Maintained with tool updates |

The `systems/{vendor}/` directory contains:

```
systems/{vendor}/
├── SKILL.md                  # High-level: what this system provides
├── auth-queries.md           # Query patterns
├── field-quirks.md           # Non-obvious field semantics and gotchas
└── config.env                # Deployment config: index names, endpoints, retention
```

The `config.env` is consumed by the SIEM CLI for non-secret config (index names, endpoints, retention). The `.md` files are the knowledge that agents read when constructing queries. The SIEM CLI's `--health-check` flag provides a fast "is this data source alive?" canary.

### 4.2 Field reference: document the quirks, not the obvious

Each system should have a field reference, but it should focus on **what would confuse or trip up an experienced analyst returning after time away** — not exhaustive mappings of self-explanatory fields. `data.srcip` clearly means source IP; that doesn't need documentation. But `data.srcuser` vs `data.dstuser` meaning different things for SSH vs Windows AD events — that's the kind of silent trap that causes wrong queries.

```markdown
# Wazuh: Field Quirks

## Authentication Events — Gotchas

- **Username field splits by event source:**
  SSH events → `data.srcuser` (the user attempting login)
  Windows AD events → `data.dstuser` (NOT `data.srcuser` — Wazuh maps
  AD's TargetUserName to dstuser). Using srcuser for AD queries returns nothing.

- **No auth type for SSH:** Wazuh SSH events don't carry an equivalent
  of Windows logon_type. You cannot distinguish interactive from
  key-based SSH auth from Wazuh fields alone.

- **NTSTATUS codes in Windows auth:** `data.win.eventdata.status` and
  `data.win.eventdata.subStatus` are hex codes, not human-readable.
  Common: 0xC000006D = bad username/password, 0xC0000234 = locked out.

- **agent.name is the target host:** Not the Wazuh agent software version.
  This is where the event was collected — the destination of the auth attempt.
```

The principle: if a veteran would understand it from context without documentation, skip it. If a veteran would waste 10 minutes on a wrong query before realizing the issue, document it prominently. Scripts encode the correct field usage; the field reference explains *why* those choices were made so the agent can adapt for ad-hoc queries.

Consumed by:
- **Query templates** — reference field quirks to explain non-obvious field choices
- **Subagents** — when doing ad-hoc queries or debugging template failures
- **Main agent** — when interpreting raw sample events that contain non-obvious field semantics

---

## 5. Main Agent to Lead Subagent Workflow

### 5.1 Dispatch: main agent → subagent

The existing subagent contract ([design-v3-architecture.md §2.3](design-v3-architecture.md)) defines input as `{ lead, goal, investigation_log, notes? }`. We extend this with a **vocabulary agreement**:

```yaml
# Subagent dispatch (extended)
lead: authentication-history
goal: "Profile authentication for user jsmith over the 2h window around the alert"
investigation_log: ./investigation.md
notes: "Source is in the monitoring subnet — pay attention to timing regularity"
vocabulary:
  src: "IP address initiating the authentication"
  dest: "Host receiving the authentication attempt"
  outcome: "success or failure"
```

The `vocabulary` field is a lightweight schema that the main agent specifies when it needs to correlate across leads. It tells the subagent: "report these entities using these names in your output." This avoids the need for global field normalization — the main agent defines the vocabulary per investigation based on what it needs to correlate.

Not every dispatch needs a vocabulary. For single-lead investigations or leads where correlation isn't needed, the subagent uses whatever field names the data source provides and includes a field glossary in its response.

### 5.2 Execution: inside the subagent

The subagent's resolution path (without resolution map — full resolution):

```
1. Check for lead directory (common/leads/{lead}/)
   ├── EXISTS: Continue to step 2
   └── DOES NOT EXIST: Fail fast (§3.5)
       Read ad-hoc/definition.md, report available data sources,
       return to main agent for reformulation

2. Read lead definition (common/leads/{lead}/definition.md)
   → Understand what to characterize, pitfalls to avoid

3. Resolve data layers (§10):
   a. Follow data tags → read operations/ file (layer 1→2)
      → Which concrete operations exist for this abstract question
   b. For each concrete operation → read sources/ file (layer 3)
      → Which sources are available, priority order, coverage
   c. Select source → read access/ constraints (layer 4)

4. Check for query template (common/leads/{lead}/templates/{vendor}.md)
   ├── EXISTS: Read template for field mappings + base query
   │           Construct query with entity values + time range
   │           Execute via SIEM CLI (scripts/tools/{vendor}_cli.py)
   │           Review verification metadata in output
   │           If suspect → debug protocol (§6.2) → try next source or ad-hoc
   └── DOES NOT EXIST: Ad-hoc query construction
       a. Read systems/{vendor}/ knowledge (query patterns, field quirks)
       b. Run health check via SIEM CLI (--health-check)
       c. Construct query using patterns + dispatch parameters
       d. Execute via SIEM CLI, verify, iterate if needed

5. [Optional] Run baseline comparison — same query with shifted time window

6. Format response with verification metadata and field glossary
```

With a resolution map (passed from CONTEXTUALIZE, see §10), steps 3a-3c are pre-resolved. The subagent skips directly to step 4 using the source and CLI specified in the map.

### 5.3 The interpretation boundary

The subagent surfaces **facts and quantified anomalies**. The main agent assigns **investigative meaning**.

| Subagent SHOULD report | Subagent SHOULD NOT report |
|------------------------|---------------------------|
| "47 failed auths, 3 unique src IPs, over 2h" | "This is consistent with brute force" |
| "All attempts target the same non-existent username" | "This is likely a misconfigured service" |
| "Rate is 15x the 7-day baseline for this entity" | "This is benign/malicious" |
| "Field `logon_type` is 10 (RDP) in all events, not type 3 (Network)" | "The attacker used RDP" |
| "No events found, but data source last event was 3 days ago" | "The data source is broken" |

The boundary test: **can this statement be wrong if a different hypothesis is true?** If yes, it's interpretation.

Key nuance: the subagent may surface facts whose relevance only becomes apparent after seeing results. "All events have `logon_type=10`" might not seem relevant until the main agent realizes the playbook predicted `logon_type=3` for the brute-force hypothesis. The subagent should err on the side of including notable field distributions and unexpected patterns, even if it can't assess their investigative significance.

### 5.4 Return: subagent → main agent

The existing return contract is `{ lead, observed, method, evidence_quality, quality_notes? }`. We extend with:

```yaml
# Subagent return (extended)
lead: authentication-history
observed: |
  47 failed SSH auths for user 'jsmith' from 3 src IPs over 2h window.
  - src 10.0.1.50: 40 attempts, periodic (every 3min ±5s), single username
  - src 192.168.1.22: 5 attempts, burst (all within 30s), single username
  - src 10.0.5.100: 2 attempts, isolated
  Success/failure: all failures, no subsequent success within 30min.
  Rate vs 7-day baseline: 15x (baseline: 3 attempts in equivalent window).
method: "leads/authentication-history/templates/wazuh.md → wazuh_cli.py"
evidence_quality: high
quality_notes: "Data source healthy (last event 2min ago). Full 2h window covered."
field_glossary:
  src: "data.srcip — IP initiating SSH connection"
  username: "data.srcuser — target username in SSH attempt"
  logon_type: "not available for SSH events in Wazuh"
notable:
  - "10.0.1.50 is in the monitoring subnet (context/ip-ranges.md)"
  - "Timing pattern for 10.0.1.50 is highly periodic — unusual for interactive use"
```

The `field_glossary` helps the main agent correlate with other leads. The `notable` section surfaces observations the subagent thinks are relevant but doesn't interpret — the main agent decides what they mean for the hypotheses.

---

## 6. Validation and Debugging Framework

### 6.1 Four failure modes

Every tool execution can fail in four ways. The agent must distinguish between them:

| Outcome | What happened | Risk level | Detection |
|---------|---------------|------------|-----------|
| **Results found** | Query worked correctly | Low | — |
| **No results, source healthy** | Entity genuinely absent from data | Medium | Verify via canary query |
| **No results, source unhealthy** | Data source down or stale | **High** | Health check, `latest_event` timestamp |
| **Partial results** | Truncation, rate limit, timeout | **High (silent)** | Compare filtered vs unfiltered count |

The fourth is the most dangerous because it looks like success. A query returning 100 results when 10,000 exist produces a plausible-looking but incomplete picture.

Lead scripts mitigate this by including **unfiltered count** in verification metadata. If filtered results are a tiny fraction of unfiltered events, the query is working as expected. If both are suspiciously low, investigate the data source.

### 6.2 Debugging protocol: data dimension

When a lead returns suspect results (zero results, unexpectedly low count, unexpected field values), the subagent follows a systematic debugging protocol. This should be formalized as a **common lead** in `knowledge/common/leads/`:

```markdown
# Lead: data-source-debug

## Goal
Diagnose why a query returned suspect results. Determine whether the issue
is data availability, field naming, query construction, or source health.

## Protocol (start wide, narrow down)

### Step 1: Source health
- Query the raw index/source with no filters except time range
- Is the data source alive? Are there recent events?
- Expected: non-zero event count, latest event within expected freshness

### Step 2: Entity presence
- Free-text search for the entity identifier (IP, user, hostname)
  across all fields in the relevant index
- Is the entity visible at all in this data source?
- If yes: which fields contain the entity? (may differ from expected)

### Step 3: Field discovery
- Sample 5-10 raw events from the index
- List available field names
- Compare against expected field names from systems/{vendor}/ field quirks documentation
- Have field names changed? Are there new/renamed fields?

### Step 4: Progressive filtering
- Start from the broadest working query (from step 1 or 2)
- Add filters from the original query one at a time
- Identify which filter causes the result count to drop to zero
- That filter is the problem — field name wrong, value format mismatch, etc.

### Step 5: Resolution
- Fix the query based on findings
- If field names changed: flag for environment knowledge update
- If data source is unhealthy: note in evidence quality, suggest alternative source
- If data genuinely absent: confirm and report as finding
```

### 6.3 Debugging protocol: logic dimension

For complex queries that do processing and correlation (not just filtering), test the logic independently of the data:

- **Synthetic test data** — Equivalent of `makeresults` in SPL or test fixtures. Create a small known dataset and verify the query produces expected output. This can be built into scripts as a `--self-test` mode.
- **Decomposition** — Break a complex query into stages. Run each stage independently and verify intermediate results make sense before combining.
- **Boundary testing** — Test edge cases: what does the query return for an entity with exactly 1 event? For a time window boundary? For special characters in field values?

For the lean CLI model, logic testing means verifying query construction: does the template's base query, when parameterized with known values, produce the expected results? The SIEM CLI's `--raw` flag enables programmatic verification of query output against expected structure.

### 6.4 Cross-lead correlation as validation

When multiple leads touch overlapping data, their results should be consistent. Inconsistency is a signal that something is wrong — either a data issue or a query issue.

Examples:
- `auth-history` reports 47 failed logins from IP X. `source-reputation` should show IP X as active in the environment. If source-reputation shows no record of IP X, something is wrong.
- `process-lineage` shows a process spawned at 14:32. `network-analysis` should show network activity from that host around the same time, if the process made network connections.

The main agent performs this correlation in the ANALYZE phase. It's not a formal verification step — it's a natural consequence of hypothesis-driven reasoning. If two leads produce contradictory evidence, the agent should investigate the contradiction before drawing conclusions.

---

## 7. Templates vs Ad-hoc Queries

### 7.1 When each applies

| Situation | Approach | Rationale |
|-----------|----------|-----------|
| Lead has `templates/{vendor}.md` | Use template: read field mapping, construct query, execute via CLI | Institutional knowledge, fast, consistent |
| Lead exists, no template for this vendor | Ad-hoc via definition.md + `systems/{vendor}/` knowledge | Methodology exists, query pattern doesn't |
| Lead template returns suspect results | Template query → debug protocol (§6.2) → ad-hoc | Graceful degradation |
| No lead directory | Fail fast, return to main agent (§3.5) | Don't burn budget on undefined work |
| Main agent re-dispatches with ad-hoc instructions | Subagent follows ad-hoc checklist + specific instructions | Informed ad-hoc, not open-ended exploration |

### 7.2 Knowledge lifecycle

Templates and lead definitions are institutional knowledge that needs maintenance. The feedback loop:

```
Investigation dispatches lead
        │
        ├── Template exists and works → results enter investigation
        │
        ├── Template exists but suspect → debug protocol → ad-hoc fallback
        │   Ad-hoc methodology recorded in lead return (method field)
        │
        ├── No template → subagent uses definition.md + ad-hoc
        │   Successful ad-hoc approach recorded in method field
        │
        └── No lead directory → fail fast → main agent reformulates
            (signals knowledge base gap)

Post-mortem reviews method fields across investigations:
  - Template-to-adhoc fallback → proposes template update (field change? query fix?)
  - Repeated successful ad-hoc for same lead → proposes template creation
  - Repeated fail-fast for same lead name → proposes new lead directory
```

The investigation summary hook (`investigation_summary.py`) should flag:
- Cases where a subagent abandoned a template in favor of ad-hoc
- Leads that triggered the fail-fast path
- New lead names that don't exist in the knowledge base

This creates a maintenance backlog — closing the feedback loop from runtime to knowledge base.

### 7.3 Template readability requirement

The agent reads templates to understand query methodology. Templates must:
- **Explain field choices** — not just "data.srcip" but why this field and not another (reference field-quirks.md for non-obvious mappings)
- **Document customization** — how to narrow/broaden the query for common variations
- **Note vendor-specific quirks** — anything that would trip up an agent constructing a related ad-hoc query

The SIEM CLI itself is intentionally thin and opaque to the agent — it handles auth, HTTP, and formatting. The agent's query knowledge lives in templates and `systems/{vendor}/` docs, not in the CLI code.

---

## 8. Data Flow: End to End

Complete flow from lead request to evidence in the investigation:

```
CONTEXTUALIZE phase (main agent)
│
│  ...existing steps (alert review, precedent scan, context search)...
│
│  NEW: Build resolution map (§10)
│  1. Read operations/ files for lead data tags → concrete operations
│  2. Read sources/ for each → available sources, priority
│  3. Run --health-check per unique CLI (deduplicated)
│  4. Build resolution map: { operation → sources → health }
│  5. Note data gaps for hypothesis discrimination
│
HYPOTHESIZE phase (main agent)
│
│  Selects leads based on hypothesis predictions (from playbook)
│  Uses resolution map for:
│    - prediction specificity (which concrete operations are testable)
│    - gap awareness (what's NOT observable)
│    - lead prioritization (avoid degraded sources)
│  Sets vocabulary for cross-lead correlation
│
├─── Dispatch: lead subagent(s) ───────────────────────────────┐
│    { lead(s), goal, vocabulary?, notes?, resolution_map }     │
│                                                               │
│    ┌─ Subagent execution ──────────────────────────────────┐  │
│    │                                                        │  │
│    │  1. Check for lead directory                           │  │
│    │     └── NOT FOUND → fail fast (§3.5)                   │  │
│    │                                                        │  │
│    │  2. Read definition.md (methodology, pitfalls)         │  │
│    │  3. Use resolution map → skip to source + CLI          │  │
│    │     (or resolve layers 2-4 from scratch if no map)     │  │
│    │  4. Execute:                                           │  │
│    │     ├── Template exists → read field mappings,          │  │
│    │     │   construct query, execute via CLI                │  │
│    │     │   ├── Review verification metadata               │  │
│    │     │   │   - Source health (latest event timestamp)    │  │
│    │     │   │   - Result scale (filtered vs unfiltered)     │  │
│    │     │   │   - Sample events (sanity check)              │  │
│    │     │   └── If suspect → try next source → ad-hoc      │  │
│    │     └── No template → ad-hoc via env knowledge + CLI   │  │
│    │  5. [Optional] Baseline comparison (shifted time range)  │  │
│    │  6. Format response                                    │  │
│    │     - Quantified observations (no interpretation)      │  │
│    │     - Verification metadata                            │  │
│    │     - Field glossary (vendor fields → standard vocab)  │  │
│    │     - Notable patterns                                 │  │
│    │                                                        │  │
│    │  For composite dispatch (§11):                          │  │
│    │     Repeat steps 1-6 per lead, accumulating context.   │  │
│    │     Earlier results may refine later query parameters.  │  │
│    │     Return includes cross_lead_notes.                   │  │
│    │                                                        │  │
│    └────────────────────────────────────────────────────────┘  │
│                                                               │
│    Return: { observed, method, evidence_quality,              │
│              field_glossary, notable }                         │
│    OR composite: { leads_executed[], cross_lead_notes }       │
│    OR fail-fast: { lead, status: "undefined",                 │
│              available_sources, recommendation }               │
│                                                               │
├─── Receive lead results ─────────────────────────────────────┘
│
│  If fail-fast return:
│    Main agent decides: reformulate with ad-hoc instructions,
│    try a different lead, or note the gap and proceed
│
ANALYZE phase (main agent)
│
│  1. Review observations against hypothesis predictions
│  2. Cross-correlate across lead results (using vocabulary)
│  3. Check for contradictions between leads
│  4. Assess each hypothesis (++/+/-/--)
│  5. Check resolution map gaps — do unobservable operations
│     affect confidence in any hypothesis?
│  6. Decide: another cycle needed, or sufficient to conclude?
│
└─── Next HYPOTHESIZE or CONCLUDE
```

---

## 9. Open Questions

### Resolved in this document
- **MCP vs CLI?** — Lean SIEM CLI as primary execution layer, MCP as fallback for vendor-managed integrations. Not either/or.
- **Lead definitions vs query knowledge?** — Both, colocated in lead directories. Definitions capture methodology (`definition.md`), query templates capture vendor-specific field mappings and patterns (`templates/{vendor}.md`). Playbooks add hypothesis context on top.
- **How to validate results?** — Built-in verification metadata in SIEM CLI output (health check, unfiltered count, sample events) + formalized debug protocol.
- **What happens when a lead doesn't exist?** — Fail fast (§3.5). Subagent returns available data sources; main agent reformulates or pivots.
- **Where does query knowledge live?** — Templates inside lead directories (`common/leads/{lead}/templates/{vendor}.md`). SIEM CLI in `scripts/tools/`. Environment knowledge in `systems/{vendor}/`.

### Still open

1. **Cross-environment portability** — Templates are per-vendor. Goal: adding Splunk should require new `templates/splunk.md` per lead + `scripts/tools/splunk_cli.py` + `systems/splunk/` config, without touching definitions or playbooks. How much template content can be shared vs vendor-specific?

2. **Parallel lead execution** — Multiple independent leads can run concurrently as separate subagents. What's the coordination model? Can one lead's early results cause another to abort? How does the main agent handle partial returns?

3. **Result size management** — Sample events help, but some leads (network analysis over a wide window) produce genuinely large result sets. Need a truncation/pagination strategy that's explicit about what was omitted. The SIEM CLI's `--limit` flag caps events but doesn't communicate what was lost.

4. **Credential rotation and access review** — SIEM CLI sources credentials from environment variables. Who provisions them? How are they rotated? What audit trail exists?

5. **Ad-hoc query guardrails** — When the subagent falls back to ad-hoc, what prevents runaway queries? Budget limits apply to tool calls, but a single expensive query can still be a problem. Query-level guardrails (mandatory time filter, result limit) should be encoded in environment knowledge or enforced by the SIEM CLI.

6. **Template promotion threshold** — Post-mortem proposes template creation when ad-hoc patterns repeat. What's the threshold? Probably: post-mortem proposes, human approves — same as precedent creation.

7. **Prompt injection via tool results** — Alert data flowing through SIEM queries could contain crafted payloads. The salted-delimiter approach from the judge prompt should extend to tool result consumption, particularly for leads that pull raw log content (command lines, URLs, email subjects, user-controlled fields).

8. **Data resolution and normalization** — Resolved in §10. Four-layer model (abstract operation → concrete operation → source → access) with explicit knowledge base structure. Resolution map built per-investigation in CONTEXTUALIZE.

9. **Composite lead dispatch** — Resolved in §11. Multi-lead subagent dispatch for profiling questions. Sequential execution with cross-lead context accumulation.

---

## 10. Data Resolution: From Investigative Question to Query

### Current status (2026-04)

The 4-layer model below is the **mental frame** for reasoning about how an abstract investigative question becomes a concrete query. In the running implementation, the layers are physically collapsed — the aspirational per-layer directory structure described later in this section was never populated as originally drawn, and the agent does not walk four files at runtime.

What the implementation actually does today:

- **Layers 2–5 are cached per lead × vendor** in `soc-agent/knowledge/common-investigation/leads/{lead}/templates/{vendor}.md`. Each template file is the resolution chain materialized for one lead against one SIEM: the concrete operation, the source/index, the access CLI, and the query text live together in one reviewable artifact. A flat `tags:` frontmatter field on each template carries the layer-1/2/3 classification directly (see `leads/_template/definition.md` for the schema), so templates are greppable by tag overlap when the agent is constructing novel queries from siblings.
- **`knowledge/environment/operations/`** was repurposed during the archetype/trust-anchor rewrite. It now holds **per-anchor grounding recipes** ("how do I confirm the `approved-monitoring-sources` anchor in this deployment?"), not layer-1→2 abstract-to-concrete mappings. The renaming stuck because trust-anchor grounding is the concrete work the agent needed and the layer-1→2 files were never written.
- **`knowledge/environment/sources/`** and **`knowledge/environment/access/`** (as separate directories) do not exist on disk. Their content, where it matters, lives inside the lead templates above and inside `knowledge/environment/systems/{vendor}/` (field quirks, query patterns, discovery primitives).
- **System connectivity** is handled by the `/connect` preflight component (see `docs/design-v3-init-and-connect.md` and `soc-agent/scripts/preflight.py`). Preflight is deliberately a binary reachability check — it does not verify per-tag data freshness or index population. That's "unbounded problem" territory and the investigation methodology handles it downstream.
- **Per-tag data freshness** is handled reactively. When a GATHER query returns suspect results (zero matches, stale latest event, unexpectedly low count), the `knowledge/common-investigation/leads/data-source-debug/definition.md` protocol walks an empirical discovery loop (source health → target presence → field sampling → progressive filtering) to distinguish a coverage gap from field-schema drift from genuine absence. It calls no SIEM metadata APIs — it just runs escalating queries and reads the results.

**Why the collapse is defensible:** environments are stale. The rate at which "which SIEM holds SSH auth events" changes is measured in months, not minutes. Caching the resolve chain in per-template files, and fixing them when they break, costs less than walking a 4-file ladder on every query. The per-layer directory structure described in the rest of this section remains the **target state** if and when a second SIEM or overlapping coverage appears — at that point the agent needs to reason about *which* concrete operation / source / access method to pick without committing to a single lead/template up front, and the flat template model stops being sufficient.

The subsections below describe the target state. Read them as the design the implementation can evolve into, not the shape of the repo today.

### The problem

When the main agent asks "check authentication history," four layers of resolution happen before a query runs:

1. **What** — the abstract investigative question ("authentication")
2. **Where it happened** — concrete real-world operations ("AD domain auth", "SSH auth", "Okta SSO")
3. **Where it's documented** — sources that record those operations ("SIEM index", "DC event log", "Okta API")
4. **How to access it** — tools and methods ("splunk_cli.py", "Ansible → Get-WinEvent", "okta_cli.py")

Currently, the knowledge base conflates layers 2-3 in the `data-sources/` files and spreads layer 4 across `systems/{vendor}/` and `leads/{lead}/templates/`. The lead subagent resolves all four layers from scratch every time.

This matters for three reasons:

- **The main agent needs layer 2.** Its predictions are abstract ("if brute-force, we'd see many failed attempts from the same source") but knowing which concrete operations exist determines whether those predictions are testable. If the environment has AD auth + Okta SSO but the Okta pipeline is down, the main agent needs to know — the absence of Okta data is a gap that affects hypothesis discrimination, not just an access problem.

- **Layers have different change frequencies.** Abstract operations never change. Concrete operations change when the environment changes (new systems deployed). Sources change when pipelines change. Access methods change when tools are updated. Conflating them means the subagent can't distinguish stable knowledge from runtime state.

- **The resolution chain is data modeling.** Mapping "authentication" → "AD domain auth events (4625)" → "Splunk `index=windows_security`" → "`splunk_cli.py --query '...'`" is normalization. Experienced analysts carry this model in their heads. We're encoding it in the knowledge base, with the LLM bridging the gaps that a traditional pipeline would need rigid transformation rules for.

### The four layers

| Layer | Question | Example | Changes | Who needs it |
|-------|----------|---------|---------|-------------|
| **1. Abstract operation** | What happened? | "authentication", "process execution" | Never | Main agent (predictions) |
| **2. Concrete operation** | Where in the real world? | "AD domain auth (4625)", "SSH auth", "Sysmon process create (Event 1)" | When environment changes | Main agent (data gaps, prediction specificity) + Lead subagent (what to query) |
| **3. Source** | Where is it documented? | "Splunk `index=windows_security`", "DC local event log", "CrowdStrike API" | When pipelines change | Lead subagent (source selection) |
| **4. Access method** | How to get it? | "`splunk_cli.py`", "Ansible → `Get-WinEvent`", "`crowdstrike_cli.py`" | When tools change | Lead subagent (execution) |

Key relationships:
- **One concrete operation → multiple sources.** AD domain auth (4625) can be queried via SIEM index, directly on the DC event log, or via CrowdStrike if it captures logon telemetry.
- **One source → multiple concrete operations.** The Sysmon index contains process creation (Event 1), network connections (Event 3), DNS queries (Event 22), and file creates (Event 11).
- **One source → multiple access methods.** The DC event log can be queried via SIEM (already forwarded) or via Ansible (direct host access).

### What the LLM handles vs what we write down

This is unavoidable data modeling, but we don't need a full normalization pipeline. The LLM's semantic understanding replaces the obvious part:

| Layer | Written in knowledge base | LLM handles |
|-------|--------------------------|-------------|
| Abstract operations | List of investigative concepts, standard vocabulary | Mapping predictions to concepts |
| Concrete operations | Which exist in this environment, coverage gaps, platform specifics | — |
| Sources | Field mappings for non-obvious fields, coverage notes, known quirks | Obvious field semantics, consolidation across sources |
| Access methods | CLI usage, constraints, priority order | Query construction from template + context |

The principle from §4.2 applies: document what would trip up an experienced analyst, not the obvious. `data.srcip` means source IP — don't document that. But `data.srcuser` vs `data.dstuser` meaning different things for SSH vs Windows AD — document that prominently.

The shared vocabulary between main agent and lead subagent is the **investigative concept layer**: "parent process", "source IP", "username", "event outcome", "session duration." The main agent predicts with these concepts. The lead subagent translates them to vendor-specific fields and reports back in concept terms. This already exists implicitly in the `vocabulary` agreement (§5.1) — we're making it explicit and grounding it in the knowledge base.

### Target knowledge base structure

The current `environment/` directory conflates layers. The target structure separates them:

```
knowledge/environment/
├── SKILL.md                          # Index: what's in this directory
├── context/                          # (unchanged) Classification heuristics
│   ├── ip-ranges.md
│   ├── identity-patterns.md
│   ├── criticality.md
│   └── data-classification.md
│
├── operations/                       # Layer 1→2: abstract → concrete mapping
│   ├── SKILL.md                      # Index of investigative operations
│   ├── authentication.md             # Abstract: "authentication"
│   │                                 #   Concrete: AD domain auth, SSH, Okta SSO, ...
│   │                                 #   Per concrete op: which sources, coverage, gaps
│   ├── process-execution.md          # Abstract: "process execution"
│   │                                 #   Concrete: Sysmon Event 1, Security 4688,
│   │                                 #   CrowdStrike, Prefetch, ...
│   ├── network-activity.md           # Abstract: "network activity"
│   ├── file-access.md               # Abstract: "file access"
│   ├── identity-lookup.md           # Abstract: "who is this entity?"
│   └── asset-lookup.md              # Abstract: "what is this system?"
│
├── sources/                          # Layer 3: where data lives
│   ├── SKILL.md                      # Index of available sources
│   ├── splunk-windows-security.md    # One file per source (not per vendor)
│   │                                 #   Covers: [AD auth, process creation, file audit, ...]
│   │                                 #   Access: splunk_cli.py, index=windows_security
│   │                                 #   Retention: 90 days
│   │                                 #   Notes: "4688 command line requires audit policy"
│   ├── splunk-sysmon.md              # Covers: [process, network, DNS, file]
│   ├── splunk-firewall.md            # Covers: [network flows, URL filtering]
│   ├── crowdstrike-api.md            # Covers: [process, network, file]
│   │                                 #   Access: crowdstrike_cli.py
│   │                                 #   Notes: "Rate-limited 15 req/min"
│   ├── dc-local-eventlog.md          # Covers: [AD auth]
│   │                                 #   Access: ansible → Get-WinEvent
│   │                                 #   Notes: "Fallback when SIEM has gaps"
│   └── okta-api.md                   # Covers: [SSO auth]
│                                     #   Access: okta_cli.py
│
├── access/                           # Layer 4: tools and constraints
│   ├── SKILL.md                      # Index + general constraints
│   ├── splunk.md                     # splunk_cli.py usage, auth, limitations
│   ├── ansible.md                    # "Use for all host queries. NOT Invoke-Command."
│   ├── crowdstrike.md                # API rate limits, pagination
│   └── okta.md                       # API usage, scoping
│
└── systems/                          # (renamed/refocused) Vendor-specific field knowledge
    └── wazuh/                        # Field quirks, query syntax gotchas
        ├── field-quirks.md           # Non-obvious field semantics
        ├── auth-queries.md           # Query patterns
        └── config.env                # Deployment config (index, endpoint, retention)
```

#### Example: `operations/authentication.md`

```markdown
---
name: authentication
description: Where authentication events can be found in this environment
---

# Authentication

## Concrete Operations

### AD Domain Authentication
- **What:** Windows logon events — success (4624), failure (4625), lockout (4740)
- **Sources:** splunk-windows-security, dc-local-eventlog
- **Coverage:** All domain-joined hosts
- **Gaps:** Does not cover local account auth or service account token refresh
- **Standard vocabulary:** source IP → "source", target user → "username",
  success/failure → "outcome"

### SSH Authentication
- **What:** SSH login attempts — success/failure via PAM
- **Sources:** splunk-wazuh-sshd (rules 5710-5720)
- **Coverage:** All Linux hosts with Wazuh agent
- **Gaps:** Key-based vs password auth not distinguishable from Wazuh fields alone
- **Standard vocabulary:** source IP → "source", attempted user → "username",
  success/failure → "outcome"

### Okta SSO
- **What:** SSO authentication events — success, failure, MFA challenge
- **Sources:** okta-api
- **Coverage:** All SSO-enrolled applications
- **Gaps:** App-specific auth (non-SSO) not visible. Okta may block before
  reaching AD, so AD logs would show nothing.
- **Standard vocabulary:** client IP → "source", user → "username",
  result → "outcome", factor → "auth_method"

## Data Gaps (negative observations)

- If only AD auth is checked, Okta-only failures are invisible
- VPN auth (not currently collected) means pre-network-access auth is a blind spot
- Service account token refresh is not logged as an auth event
```

#### Example: `sources/splunk-windows-security.md`

```markdown
---
name: splunk-windows-security
description: Windows Security event log forwarded to Splunk
covers: [ad-domain-auth, process-creation-4688, file-audit-4663, logon-type]
---

# Splunk: Windows Security Index

## Access
- **CLI:** `scripts/tools/splunk_cli.py`
- **Index:** `index=windows_security`
- **Retention:** 90 days

## Operations Covered
| Operation | Event IDs | Notes |
|-----------|-----------|-------|
| AD domain auth | 4624, 4625, 4740 | Primary auth source |
| Process creation | 4688 | Command line only if audit policy enabled |
| File audit | 4663 | Only on shares with object access auditing |
| Logon type | 4624 field `LogonType` | Distinguish interactive (2), network (3), RDP (10) |

## Field Notes
- `TargetUserName` → the user being authenticated (not the caller)
- `IpAddress` → source of the auth attempt (may be `-` for local logon)
- `LogonType` → integer, see mapping above
- See systems/wazuh/field-quirks.md for Wazuh-specific normalization
```

#### Example: `access/ansible.md`

```markdown
---
name: ansible
description: Host access via Ansible for direct event log and file queries
---

# Ansible Host Access

## Usage
Ansible is the ONLY supported method for direct host queries.
Do NOT use Invoke-Command, Enter-PSSession, or direct SSH for queries.

## Common Patterns

### Windows Event Log query
\`\`\`bash
ansible {hostname} -m win_shell -a "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 100 | ConvertTo-Json"
\`\`\`

### Linux log query
\`\`\`bash
ansible {hostname} -m shell -a "journalctl -u sshd --since '2h ago' --no-pager"
\`\`\`

## Constraints
- Requires host to be in Ansible inventory
- Timeout: 30s default, extend for large queries
- Rate: no formal limit, but avoid parallel queries to same host
```

### Resolution map: runtime snapshot of layers 2-3

The main agent resolves the environment once during CONTEXTUALIZE and passes a **resolution map** to all lead dispatches. The map captures:
- Which concrete operations exist for each abstract operation the investigation needs
- Which sources are available for each concrete operation
- Source health at resolution time (from CLI `--health-check`)

```yaml
# Resolution map — built in CONTEXTUALIZE, passed to all lead subagents
resolution:
  authentication:
    operations:
      - name: "AD domain auth"
        sources:
          - source: splunk-windows-security
            cli: scripts/tools/splunk_cli.py
            health: healthy
            last_event: "2026-04-04T13:58:00Z"
          - source: dc-local-eventlog
            access: ansible
            health: not_checked   # fallback, only check if primary fails
        coverage: "All domain-joined hosts"
      - name: "SSH authentication"
        sources:
          - source: splunk-wazuh-sshd
            cli: scripts/tools/wazuh_cli.py
            health: healthy
            last_event: "2026-04-04T13:57:00Z"
        coverage: "Linux hosts with Wazuh agent"
      - name: "Okta SSO"
        sources:
          - source: okta-api
            cli: scripts/tools/okta_cli.py
            health: degraded
            notes: "API returning 429s intermittently"
        coverage: "SSO-enrolled apps"
    gaps:
      - "VPN auth not collected"
      - "Service account token refresh not logged"
```

#### Resolution process (during CONTEXTUALIZE)

1. Identify which abstract operations the signature's leads need (from lead `data_tags` + playbook)
2. Read `operations/` files for each — enumerate concrete operations + sources
3. Run `--health-check` on each primary source (deduplicated per CLI)
4. Build the resolution map
5. Pass to all subsequent lead dispatches

The main agent uses the resolution map for:
- **Prediction specificity** — knowing AD + SSH + Okta exist shapes hypothesis predictions
- **Gap awareness** — "VPN auth not collected" influences confidence assessment
- **Lead selection** — if Okta is degraded, leads depending on SSO data get lower priority

The lead subagent uses it for:
- **Skip discovery** — go straight to source → template → CLI
- **Source fallback** — if primary source returns suspect results, try the next source in the list
- **Health-aware quality reporting** — note degraded sources in `quality_notes`

#### What the resolution map does NOT contain

- **Field mappings** — those are in query templates and source docs. The subagent still reads those.
- **Access method details** — those are in `access/` docs. Static knowledge, not runtime state.
- **Full config** — `config.env` values stay in files. The map points to the CLI, not the config.

#### When to resolve fresh

- **Data-source-debug lead** (§6.2) — its purpose is diagnosing data source issues; it should resolve from scratch
- **Ad-hoc fallback** — if a template query fails, the subagent reads source/access docs directly
- **Cross-investigation** — the map is per-investigation, not persisted. Environment changes are picked up on next CONTEXTUALIZE

---

## 11. Composite Lead Dispatch

### Problem

Some investigative questions span multiple data sources and leads. "What did this user do in the 2-hour window?" requires authentication history, application logs, and data access events. Currently the main agent must:

1. Dispatch 3 separate subagents (or 3 sequential dispatches)
2. Receive 3 independent observation sets
3. Correlate them in ANALYZE

This works for truly independent leads. But for **profiling questions** — where the goal is a unified picture of an entity's activity — the leads are not independent. Knowing the auth pattern (logged in at 14:00, logged out at 14:30) directly improves the data access query (scope to that session window). Knowing the user authenticated via a service account changes what to look for in app logs.

### Design: multi-lead subagent (option b)

The main agent dispatches a **single subagent with multiple leads**. The subagent executes them sequentially, accumulating context. Earlier lead results can inform later lead execution — tighter time windows, better entity scoping, cross-lead sanity checks during execution rather than after.

#### Dispatch format

```yaml
# Composite lead dispatch
leads:
  - authentication-history
  - app-log-review
  - data-access-events
goal: "Profile user jsmith's activity in the 2h window around the alert"
investigation_log: ./investigation.md
vocabulary:
  user: "jsmith"
  time_window: "2026-04-04T10:00:00Z to 2026-04-04T12:00:00Z"
notes: "Execute leads in order. Use findings from earlier leads to refine later queries where applicable."
siem_resolution: { ... }  # from §10, if available
```

#### Execution model

The subagent processes leads sequentially:

```
For each lead in leads[]:
  1. Resolve lead (same path as §5.2, accelerated by siem_resolution if present)
  2. Execute query
     - MAY refine parameters based on prior lead results
       (e.g., narrow time window based on auth session boundaries)
     - MUST NOT skip the lead or change its methodology
     - MUST still follow the definition.md "What to Characterize" requirements
  3. Record observations
  4. Note cross-lead observations (consistencies and contradictions)
```

#### Return format

```yaml
# Composite return
leads_executed:
  - lead: authentication-history
    observed: |
      User jsmith: 1 successful SSH login at 14:02 from 10.0.1.50,
      logout at 14:28. No failed attempts.
    method: "leads/authentication-history/templates/wazuh.md → wazuh_cli.py"
    evidence_quality: high
  - lead: app-log-review
    observed: |
      3 application actions by jsmith between 14:03-14:25.
      All within authenticated session window (refined from auth-history).
    method: "ad-hoc, wazuh_cli.py"
    evidence_quality: medium
    quality_notes: "No template for app-log-review/wazuh. Query constructed ad-hoc."
  - lead: data-access-events
    observed: |
      2 data export operations at 14:20 and 14:24.
      Both within session window, both to authorized destination.
    method: "ad-hoc, wazuh_cli.py"
    evidence_quality: medium
cross_lead_notes:
  - "All activity falls within the single auth session (14:02-14:28)"
  - "Data exports occurred in last 5 minutes of session — temporal clustering"
  - "No activity outside the auth session boundaries"
field_glossary:
  user: "data.srcuser (SSH), data.user (app logs)"
  src: "data.srcip — 10.0.1.50 across all leads"
```

#### The interpretation boundary still holds

The composite subagent follows the same "facts up, meaning down" principle (§5.3). It reports cross-lead factual observations ("all activity within a single session", "temporal clustering of exports") but does not interpret them ("this looks like exfiltration"). The main agent assigns investigative meaning in ANALYZE.

The one refinement: the composite subagent MAY note **cross-lead contradictions** as explicit warnings. "Auth shows no session for jsmith, but app-logs show 3 actions attributed to jsmith" is a factual contradiction that the main agent needs to see prominently.

#### When to use composite vs single-lead dispatch

| Situation | Dispatch mode | Rationale |
|-----------|--------------|-----------|
| Independent leads, different entities | Parallel single-lead subagents | No cross-lead value, maximize speed |
| Related leads, same entity, profiling question | Composite (multi-lead) subagent | Cross-lead context improves execution |
| Single critical lead | Single-lead subagent | No composition needed |
| Lead + its baseline comparison | Single-lead subagent (agent runs both queries) | Same data source, same entity — naturally sequential |

The main agent decides the dispatch mode based on the investigative question. The playbook may suggest composite dispatch for known profiling patterns, but the main agent is not bound by this.

### Trade-offs

**Benefits of composite dispatch:**
- Cross-lead context accumulation — earlier results refine later queries
- Single subagent overhead instead of N — reduces total context window cost
- Cross-lead consistency checks happen during execution, not after
- Unified field glossary across leads

**Costs:**
- Sequential execution — no parallelism between leads in the composite
- ~2x token usage per lead (prior lead results in context during later execution)
- Error in early lead can influence later leads (mitigated by per-lead verification metadata)
- Longer single subagent run — if it fails midway, partial results may be lost

**Net assessment:** For profiling questions (2-4 related leads on the same entity), composite dispatch is the right default. The token cost is acceptable because the cross-lead context genuinely improves query quality. For independent leads or large fan-outs (5+ leads), single-lead dispatch with parallel execution is better.

### Adaptability: defined vs open-ended composition

Currently, the main agent specifies exact lead names in the composite dispatch. This is the **defined composition** model — the main agent knows which leads to run, and the subagent executes them.

An alternative is **open-ended composition**: the main agent passes a high-level investigative question ("profile this user's activity") and the subagent decides which leads to run based on the knowledge base. This would use the LLM's semantic understanding to adaptively select and sequence leads.

This is deferred for now. The defined composition model is simpler, more predictable, and maintains the main agent's control over the investigation strategy. The open-ended model is more powerful but introduces a new risk: the subagent making investigative priority decisions that belong to the main agent. If we pursue it, the boundary would need careful design — likely a "propose and confirm" step where the subagent reads the knowledge base, proposes a lead sequence, and the main agent approves before execution begins. But that reintroduces bidirectional communication, which the current single-shot architecture avoids.
