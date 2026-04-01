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

Lead execution (run.sh|run.py)      — HOW: parameterized query + verification
  "Execute query, format results, include verification metadata"

Environment (systems/{vendor}/)     — WHERE: system-specific config
  "Field names, index names, API endpoints, credentials, defaults"
```

A fourth layer — **WHY** (which hypotheses this lead discriminates, predictions, priority) — lives in playbooks, not in the lead itself. Leads are hypothesis-agnostic investigation units; playbooks give them investigative meaning for a specific signature.

These layers compose through the data tag vocabulary:

```
playbook.md                    lead directory (common/leads/{lead}/)
  lists leads by name    →       definition.md — methodology + data_tags
  with predictions                    ↓ data_tags
  and priority                   data-sources/ file
                                      ↓ points to
                                 systems/{vendor}/ — env knowledge + config
                                      ↓ consumed by
                                 run.sh — execution script in lead dir
```

### 3.2 Lead directory structure

Each lead is a directory under `common/leads/`, containing its definition, execution layer, and stored baselines. This keeps everything about a lead colocated — methodology, execution, and historical data live together.

```
knowledge/common/leads/
├── _template/                        # Template for new leads
│   ├── definition.md                 #   Methodology template
│   └── run.sh                        #   Execution template with standard output format
├── authentication-history/
│   ├── definition.md                 # What to characterize, pitfalls, data tags
│   ├── run.sh                        # Pre-built query + verification + output formatting
│   └── baselines.jsonl               # Stored execution summaries for comparison
├── process-lineage/
│   ├── definition.md
│   ├── run.sh
│   └── baselines.jsonl
├── source-reputation/
│   ├── definition.md
│   └── run.sh                        # No baselines — binary check, not volume-based
├── network-analysis/
│   ├── definition.md
│   ├── run.sh
│   └── baselines.jsonl
├── data-source-debug/                # Meta-lead: debugging protocol (no run.sh)
│   └── definition.md
└── ad-hoc/                           # Meta-lead: checklist for undefined leads
    └── definition.md
```

The existing flat `.md` files (`authentication-history.md`, etc.) become `definition.md` inside their lead directory. Content stays the same — what to characterize, common pitfalls, data tags. No hypothesis references (those belong in playbooks).

Not every lead has a `run.sh`. Some leads (like `data-source-debug`) are methodology-only — the subagent follows the protocol using environment knowledge and ad-hoc queries. A missing `run.sh` is a signal to the subagent: use the ad-hoc framework.

### 3.3 Lead execution scripts

The `run.sh` (or `run.py`) is the execution layer — a self-contained script that the subagent both **reads** (to understand methodology) and **executes** (to get results). It is a knowledge artifact that carries institutional learning between investigations.

#### Parameters and time format

Scripts accept parameters via standard CLI flags. Entity types are **open** — the examples below are common cases, not a closed list. Any entity the investigation needs to profile (user, IP, host, process, file, port, domain, hash, service account, container ID, etc.) is valid.

**Time format:** Three equally supported modes for specifying time ranges. All timestamps use ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ`). Durations use short suffix notation (`30m`, `2h`, `7d`, `1w`; regex: `^[0-9]+(m|h|d|w)$`).

| Mode | Use case | Flags |
|------|----------|-------|
| **Absolute** | Historical analysis, specific incident windows | `--start TIMESTAMP --end TIMESTAMP` |
| **Centered** | Alert-relative, symmetric window | `--center TIMESTAMP --window DURATION` |
| **Asymmetric** | Alert-relative, different before/after reach | `--center TIMESTAMP --before DURATION --after DURATION` |

```bash
# Absolute: arbitrary historical range
./run.sh --start "2026-01-01T17:20:00Z" --end "2026-01-03T08:33:00Z"

# Centered: 2h symmetric around alert (1h each side)
./run.sh --center "2026-04-01T14:30:00Z" --window 2h

# Asymmetric: 30m before to 2h after alert
./run.sh --center "2026-04-01T14:30:00Z" --before 30m --after 2h

# Baseline: any mode + offset shifts the window to a comparison period
./run.sh --center "2026-04-01T14:30:00Z" --window 2h --baseline-offset 7d
./run.sh --start "2026-01-01T17:20:00Z" --end "2026-01-03T08:33:00Z" --baseline-offset 7d
```

Absolute mode is essential for: reviewing historical activity for a user or host, investigating a specific incident window identified from another source, and re-running past analyses. `--center`/`--window` is sugar for the common alert-relative case, but `--start`/`--end` is the fundamental interface.

#### Script template

```bash
#!/usr/bin/env bash
# Lead: authentication-history
# Data tags: auth-events
#
# Queries authentication events for a given entity and time window.
# Returns structured summary with verification metadata.
#
# The agent reads this script to understand what it does and how.
# Comments explain investigative rationale, not just code mechanics.

set -euo pipefail

# --- Parameter parsing ---
# Entity: any identifier relevant to the investigation (user, ip, host, etc.)
# Not a closed list — the script handles the entity type it was built for,
# and reports clearly if asked for something it doesn't support.
ENTITY=""
VALUE=""
CENTER=""
WINDOW="2h"
BEFORE="" ; AFTER=""
START="" ; END=""
BASELINE_OFFSET=""
SELF_TEST=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --entity)   ENTITY="$2";   shift 2;;
    --value)    VALUE="$2";    shift 2;;
    --center)   CENTER="$2";   shift 2;;
    --window)   WINDOW="$2";   shift 2;;
    --before)   BEFORE="$2";   shift 2;;
    --after)    AFTER="$2";    shift 2;;
    --start)    START="$2";    shift 2;;
    --end)      END="$2";      shift 2;;
    --baseline-offset) BASELINE_OFFSET="$2"; shift 2;;
    --self-test) SELF_TEST=true; shift;;
    *) echo "Unknown param: $1" >&2; exit 1;;
  esac
done

# Validate duration format
validate_duration() { [[ $1 =~ ^[0-9]+(m|h|d|w)$ ]] || { echo "Invalid duration: $1" >&2; exit 1; }; }

# --- Environment config ---
# Source system-specific settings (index names, field mappings, credentials).
# The script never hardcodes these — they come from environment config.
# Credentials are sourced here, never passed as parameters.
source "${SOC_AGENT_DIR}/knowledge/environment/systems/${SYSTEM}/config.env"

# --- Query construction ---
# This is the core knowledge the script carries.
# Each filter is commented with WHY it exists:
#   - "rule.groups:sshd" → scopes to SSH events only (not all auth)
#   - "data.srcip:${VALUE}" → matches the source IP being investigated
# When this script returns wrong results, update it here.

# --- Self-test mode ---
# Verifies query logic against synthetic data, independent of live systems.
# Run after modifying the query to catch logic regressions.
if [[ "$SELF_TEST" == true ]]; then
  # ... run against test fixtures, verify expected output ...
  exit 0
fi

# --- Execution ---
# Execute via the configured query tool.
# The script is the credential trust boundary — credentials are used here
# and never exposed in output.

# --- Output format (standard for all lead scripts) ---
cat <<RESULT
## Lead: authentication-history
**Mode:** ${MODE}
**Parameters:** entity=${ENTITY}, value=${VALUE}, window=${WINDOW_DISPLAY}
**Query executed:** ${QUERY}
**Time range:** ${TIME_RANGE_DISPLAY}

### Data Source Health
- **Source:** ${DATA_SOURCE}
- **Most recent event in index:** ${LATEST_EVENT_TIMESTAMP}
- **Index event count (unfiltered, same window):** ${TOTAL_INDEX_EVENTS}

### Summary
- **Matching events:** ${MATCH_COUNT}
- **Unique source IPs:** ...
- **Unique usernames:** ...
- **Time pattern:** (periodic|burst|irregular), details...
- **Success/failure breakdown:** ...

### Sample Events (first 5)
${SAMPLE_EVENTS}

### Raw Event Count Breakdown
${COUNT_BREAKDOWN}
RESULT
```

#### Output format properties

| Field | Purpose |
|-------|---------|
| Query executed | Transparency — agent can review and adapt if needed |
| Most recent event in index | Canary — is the data source alive and current? |
| Unfiltered index count | Scale reference — 0 filtered from 500K = good filtering; 0 from 0 = dead source |
| Match count | Primary result |
| Sample events | Sanity check — agent verifies events match expectations |
| Count breakdown | Quantified summary for the main agent to reason about |

### 3.4 Baseline mode

Same script, different timeframe. The `--baseline-offset` flag shifts the query window to a comparison period. Output structure is identical, enabling direct comparison: "47 failed auths in alert window vs 3 in baseline — 15x deviation."

```bash
# Alert window
./run.sh --entity ip --value 10.0.1.50 --center "$ALERT_TIME" --window 2h

# Same query, 7 days earlier
./run.sh --entity ip --value 10.0.1.50 --center "$ALERT_TIME" --window 2h \
         --baseline-offset 7d
```

#### When to use baselines

Not every lead needs a baseline. The agent decides based on context:
- **High-volume sources** (auth, network flow) — baseline useful, "14 failed logins" means nothing without context
- **Binary checks** (file hash reputation, known-bad IP) — no baseline needed
- **Rare events** (privilege escalation, lateral movement) — baseline useful, wider comparison window (30d)

#### Stored baselines

Each lead directory contains an optional `baselines.jsonl` — structured summaries (not raw events) appended after each execution:

```json
{
  "timestamp": "2026-04-01T14:30:00Z",
  "entity": "ip",
  "value": "10.0.1.50",
  "window": "2h",
  "match_count": 47,
  "investigation_id": "run-2026-04-01-001"
}
```

Not a database — a reference log. Value: "the last 5 times we profiled auth for IPs in this subnet, counts were in the 5-20 range; this one shows 300."

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

## 4. Environment Knowledge: The `systems/` Layer

### 4.1 Responsibility split

The `environment/` directory serves two purposes that should be clearly separated:

| Layer | Content | Audience | Mutability |
|-------|---------|----------|------------|
| **Context** (`context/`) | What's normal here — IP ranges, identity patterns, business rhythms | Agent reasoning (both main + subagent) | Human-maintained, slow-changing |
| **Data sources** (`data-sources/`) | Where data lives — system priority, coverage, pipeline quirks, known gaps | Subagent tool selection | Human-maintained, medium-changing |
| **Systems** (`systems/{vendor}/`) | How to query — field mappings, query patterns, API specifics, defaults | Scripts + subagent ad-hoc | Maintained with tool updates |

**New: system configuration** (proposed addition to `systems/`):

```
systems/{vendor}/
├── SKILL.md                  # High-level: what this system provides
├── auth-queries.md           # Query patterns (existing)
├── field-quirks.md           # Non-obvious field semantics and gotchas
├── config.env                # Production defaults: index names, endpoints, retention
└── health-check.sh           # Canary query: "is this system alive and current?"
```

The `config.env` and `health-check.sh` are the technical glue that scripts consume. The `.md` files are the knowledge that agents and humans read. This separation means:

- Scripts source `config.env` for index names, endpoints, and defaults — no hardcoding
- The agent reads `.md` files when constructing ad-hoc queries
- `health-check.sh` provides a fast "is this data source alive?" check that any lead script can call

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
- **Scripts** — to construct queries with correct field names (the reference explains the reasoning behind the script's field choices)
- **Subagents** — when doing ad-hoc queries or debugging script failures
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

The subagent's resolution path:

```
1. Check for lead directory (common/leads/{lead}/)
   ├── EXISTS: Continue to step 2
   └── DOES NOT EXIST: Fail fast (§3.5)
       Read ad-hoc/definition.md, report available data sources,
       return to main agent for reformulation

2. Read lead definition (common/leads/{lead}/definition.md)
   → Understand what to characterize, pitfalls to avoid

3. Follow data tags → read data-sources/ file
   → Identify available systems, priority order, known gaps

4. Check for execution script (common/leads/{lead}/run.sh)
   ├── EXISTS: Read script, execute with parameters
   │           Review verification metadata in output
   │           If suspect → debug protocol (§6.2) → ad-hoc fallback
   └── DOES NOT EXIST: Ad-hoc query construction
       a. Read systems/{vendor}/ knowledge (query patterns, field quirks)
       b. Run health check
       c. Construct query using patterns + dispatch parameters
       d. Execute, verify, iterate if needed

5. [Optional] Run baseline (--baseline-offset) if lead has baselines.jsonl
   or if the agent judges baseline comparison is valuable

6. Format response with verification metadata and field glossary
```

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
method: "leads/authentication-history/run.sh, Wazuh SIEM via MCP"
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

Script self-test mode:

```bash
# Verify query logic against synthetic data
./run.sh --self-test
# Output: PASS/FAIL with explanation
```

This is particularly valuable when scripts are updated — run self-tests to verify the change didn't break the logic.

### 6.4 Cross-lead correlation as validation

When multiple leads touch overlapping data, their results should be consistent. Inconsistency is a signal that something is wrong — either a data issue or a query issue.

Examples:
- `auth-history` reports 47 failed logins from IP X. `source-reputation` should show IP X as active in the environment. If source-reputation shows no record of IP X, something is wrong.
- `process-lineage` shows a process spawned at 14:32. `network-analysis` should show network activity from that host around the same time, if the process made network connections.

The main agent performs this correlation in the ANALYZE phase. It's not a formal verification step — it's a natural consequence of hypothesis-driven reasoning. If two leads produce contradictory evidence, the agent should investigate the contradiction before drawing conclusions.

---

## 7. Pre-made Scripts vs Ad-hoc Queries

### 7.1 When each applies

| Situation | Approach | Rationale |
|-----------|----------|-----------|
| Lead directory exists, has `run.sh` | Execute script | Institutional knowledge, fast, consistent |
| Lead directory exists, no `run.sh` | Ad-hoc via definition.md + environment knowledge | Methodology exists, execution doesn't |
| Lead directory exists, `run.sh` returns suspect results | Script → debug protocol (§6.2) → ad-hoc | Graceful degradation |
| No lead directory | Fail fast, return to main agent (§3.5) | Don't burn budget on undefined work |
| Main agent re-dispatches with ad-hoc instructions | Subagent follows ad-hoc checklist + specific instructions | Informed ad-hoc, not open-ended exploration |

### 7.2 Script lifecycle

Scripts are institutional knowledge that needs maintenance. The feedback loop:

```
Investigation dispatches lead
        │
        ├── run.sh exists and works → results enter investigation
        │                              Summary appended to baselines.jsonl
        │
        ├── run.sh exists but suspect → debug protocol → ad-hoc fallback
        │   Ad-hoc methodology recorded in lead return (method field)
        │
        ├── No run.sh → subagent uses definition.md + ad-hoc
        │   Successful ad-hoc approach recorded in method field
        │
        └── No lead directory → fail fast → main agent reformulates
            (signals knowledge base gap)

Post-mortem reviews method fields across investigations:
  - Script-to-adhoc fallback → proposes script update (field change? query fix?)
  - Repeated successful ad-hoc for same lead → proposes run.sh creation
  - Repeated fail-fast for same lead name → proposes new lead directory
```

The investigation summary hook (`investigation_summary.py`) should flag:
- Cases where a subagent abandoned `run.sh` in favor of ad-hoc
- Leads that triggered the fail-fast path
- New lead names that don't exist in the knowledge base

This creates a maintenance backlog — closing the feedback loop from runtime to knowledge base.

### 7.3 Script readability requirement

The agent reads scripts to understand methodology. This means scripts must be:
- **Commented with investigative rationale** — not "filter by srcip" but "filter by srcip because this lead profiles a single source entity's auth pattern"
- **Structured** with clear sections (parameters, query construction, execution, output formatting)
- **Explicit about what they filter and why** — a `WHERE status != 0` needs a comment explaining that status 0 means success and we're looking for failures
- **Transparent about field choices** — reference the field quirks doc when using non-obvious field mappings

This is not about code quality — it's about the script being a knowledge artifact that the agent learns from.

---

## 8. Data Flow: End to End

Complete flow from lead request to evidence in the investigation:

```
HYPOTHESIZE phase (main agent)
│
│  Selects leads based on hypothesis predictions (from playbook)
│  Sets vocabulary for cross-lead correlation
│
├─── Dispatch: lead subagent(s) ───────────────────────────────┐
│    { lead, goal, vocabulary?, notes? }                        │
│                                                               │
│    ┌─ Subagent execution ──────────────────────────────────┐  │
│    │                                                        │  │
│    │  1. Check for lead directory                           │  │
│    │     └── NOT FOUND → fail fast, return available        │  │
│    │         data sources to main agent (§3.5)              │  │
│    │                                                        │  │
│    │  2. Read definition.md (methodology, pitfalls)         │  │
│    │  3. Follow data tags → read data-sources/              │  │
│    │  4. Execute:                                           │  │
│    │     ├── run.sh exists → execute with params            │  │
│    │     │   ├── Review verification metadata               │  │
│    │     │   │   - Source health (latest event timestamp)    │  │
│    │     │   │   - Result scale (filtered vs unfiltered)     │  │
│    │     │   │   - Sample events (sanity check)              │  │
│    │     │   └── If suspect → debug protocol → ad-hoc       │  │
│    │     └── No run.sh → ad-hoc via env knowledge           │  │
│    │  5. [Optional] Baseline comparison (--baseline-offset)  │  │
│    │  6. Format response                                    │  │
│    │     - Quantified observations (no interpretation)      │  │
│    │     - Verification metadata                            │  │
│    │     - Field glossary                                   │  │
│    │     - Notable patterns                                 │  │
│    │                                                        │  │
│    └────────────────────────────────────────────────────────┘  │
│                                                               │
│    Return: { observed, method, evidence_quality,              │
│              field_glossary, notable }                         │
│    OR (fail-fast): { lead, status: "undefined",               │
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
│  5. Decide: another cycle needed, or sufficient to conclude?
│
└─── Next HYPOTHESIZE or CONCLUDE
```

---

## 9. Open Questions

### Resolved in this document
- **MCP vs bash?** — Scripts as primary, MCP as fallback for vendor-managed integrations. Not either/or.
- **Lead definitions vs scripts?** — Both, colocated in lead directories. Definitions capture methodology, scripts capture execution. Playbooks add hypothesis context on top.
- **How to validate results?** — Built-in verification metadata (health check, unfiltered count, sample events) + formalized debug protocol.
- **What happens when a lead doesn't exist?** — Fail fast (§3.5). Subagent returns available data sources; main agent reformulates or pivots.
- **Time format?** — Short suffix (`2h`, `30m`, `7d`, `1w`) with `--center`/`--before`/`--after` for relative windows. ISO 8601 for timestamps.
- **Where do scripts live?** — Inside lead directories (`common/leads/{lead}/run.sh`), not in a separate `scripts/` tree.

### Still open

1. **Baseline storage and retention** — `baselines.jsonl` per lead directory grows indefinitely. What retention policy? Probably recent-N (last 100 entries) with periodic truncation. How does the agent efficiently query past baselines — tail the file? Separate index?

2. **Cross-environment portability** — Scripts source `config.env` for system-specific values. Goal: switching from Wazuh to Splunk should require changing `systems/` and `config.env`, not rewriting every `run.sh`. How much query logic can be truly system-agnostic vs needing per-vendor variants?

3. **Parallel lead execution** — Multiple independent leads can run concurrently as separate subagents. What's the coordination model? Can one lead's early results cause another to abort? How does the main agent handle partial returns?

4. **Script testing in CI** — `--self-test` validates logic against synthetic data. But how to test against realistic data without a live SIEM? Recorded responses (replay mode)? This is the traditional integration test challenge.

5. **Result size management** — Sample events help, but some leads (network analysis over a wide window) produce genuinely large result sets. Need a truncation/pagination strategy that's explicit about what was omitted.

6. **Credential rotation and access review** — Scripts source credentials from `config.env`. Who provisions them? How are they rotated? What audit trail exists? Operationally relevant because it affects the threat model.

7. **Ad-hoc query guardrails** — When the subagent falls back to ad-hoc, what prevents runaway queries? Budget limits apply to tool calls, but a single expensive query can still be a problem. Query-level guardrails (mandatory time filter, result limit) should be encoded in environment knowledge or enforced by the system skill.

8. **Script promotion threshold** — Post-mortem proposes `run.sh` creation when ad-hoc patterns repeat. What's the threshold? Every successful ad-hoc? After N uses? This affects maintenance burden. Probably: post-mortem proposes, human approves — same as precedent creation.

9. **Prompt injection via tool results** — Alert data flowing through SIEM queries could contain crafted payloads. The salted-delimiter approach from the judge prompt should extend to tool result consumption, particularly for leads that pull raw log content (command lines, URLs, email subjects, user-controlled fields).

10. **Lead directory migration** — Current leads are flat `.md` files. Migration to directory structure needs a plan: move existing files to `{lead}/definition.md`, create `_template/` directory, update references in playbooks and architecture doc.
