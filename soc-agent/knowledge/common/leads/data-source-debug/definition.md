---
name: data-source-debug
data_tags: []
---

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
- Compare against expected field names from systems/{vendor}/ field
  quirks documentation
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
