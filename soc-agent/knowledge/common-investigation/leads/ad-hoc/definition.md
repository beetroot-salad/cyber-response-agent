---
name: ad-hoc
data_tags: []
---

## Goal

Construct and execute a bespoke SIEM query when no other seed in the catalog parametrizes the evidence need. Use this when (a) no existing seed's intent matches the goal, or (b) an existing seed's intent matches but its template cannot be customized to the required shape (e.g., the query needs to combine fields no template's base query joins, or filter on a dimension no template exposes). Prefer any other matching seed first — ad-hoc is the procedural escape hatch, not the default.

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

## First pass: raw events before summaries

When ad-hoc execution is authorized, the first query should return **raw
events**, not the data source's pre-aggregated summary view. A summary
projection is a fixed schema chosen by the adapter; fields it doesn't
bucket are silently collapsed, so rows that differ on a discriminating
attribute can render identically (a row with `pname=null` and a row with
`pname=runc` both rendering as one indistinguishable bucket, for
example). For an ad-hoc lead you do not yet know which field is the
discriminator, so the summary is the wrong shape — it can hide the very
signal you came for.

Procedure:

1. Issue the broadest sensible query in the data source's raw-event
   form — the option exposed by the local CLI/API for unprojected output
   (e.g., a "raw" flag, a JSON-format parameter, a "no aggregation"
   toggle — consult the `systems/{vendor}/SKILL.md` for the local name)
   with a **very small limit, 5 events**. The goal is to see the field
   shape, not to enumerate occurrences — five events is enough to
   confirm which fields exist, which values vary, and which collapse to
   a single value across the sample. Total counts (e.g. "9703 matching
   events") come back in the query metadata; you do not pull thousands
   of events to learn that.
2. Identify the field(s) that discriminate the events you care about.
3. Re-issue against a broader window using the summary/aggregation form
   keyed on those fields, *or* keep the raw form if cardinality is low.

**Do not pipe raw output through an inline transformer in the same shell
call.** Pipe transformations replace the captured tool output with the
transformer's stdout, defeating raw-output retention and making
downstream re-read impossible. If you need to post-process, write the
raw output to a file in a separate step (or rely on the run's persisted
raw output capture, where one exists) and read it back.

## Why fail fast

Budget is limited. An undefined lead means the main agent's mental model
and the knowledge base are misaligned. The main agent needs this signal
to either reformulate the lead, use the debugging framework to explore
available data, or escalate.
