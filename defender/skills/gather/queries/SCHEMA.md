# Query template catalog — file format

This directory is the gather subagent's accumulated memory of useful queries,
organized per system of record. A template captures what an experienced
analyst already knows about a data source: the right index, the right field
names, the joins or regex tricks that took someone an afternoon to figure
out the first time. Gather binds parameters and runs; it doesn't re-derive
the query under time pressure.

## Layout

```
queries/
  SCHEMA.md                    # this file
  {system}/                    # one dir per system of record
    {template-id}.md           # one file per template
```

`{system}` is a system the gather subagent knows how to dispatch against
(one dir per onboarded system of record). It doubles as the routing
prefix for the template id and as a coarse `ls`-time filter.

`{template-id}` is kebab-case. Name it for **what the query measures**
(`auth-events`), not the axis you happen to filter on (`auth-events-by-host`)
and not why the defender asked for it (`check-if-bastion-was-pivoted`). A
single template can carry several optional filter knobs.

## File format

```markdown
---
id: {system}.auth-events
---

## Goal

What this query measures, in one or two sentences. **Write for keyword
recall** — name the concrete artifacts a future analyst would type when
searching: daemon names (sshd, sudo), file paths (/etc/passwd), log fields,
syscalls. Gather greps `## Goal` body across the catalog when the dispatch
needs to find the right template at scale.

## What to summarize

- <measurement: what to count / which field to surface / which distribution>
- <measurement: ...>

Each bullet names a measurement primitive — a count, a cardinality,
a distribution, a ratio, or a field to surface. Every item is
reported, even if "not observed"; omission is ambiguous to the
parent. The defender weighs what the values mean in ANALYZE.

## Query

The query body the system of record executes, with `${param}` placeholders.
This is system-native — a search DSL for a SIEM, a shell pipeline for a
host-state agent, SQL for a relational store, etc. The system's CLI client
is a thin dispatcher; it does not interpret a query DSL of its own. Gather
substitutes the bound params and hands the body to the client.

Parameters are discovered automatically from the `${param}` placeholders;
there is no separate `params:` declaration to keep in sync.

## Common pitfalls

- <pitfall 1: e.g. NAT collapse, time-window edge cases>

## Baseline (when applicable)

If the template's measurement only makes sense relative to a normal
pattern, describe how gather constructs a baseline / shift-window
companion query. Omit this section entirely when the measurement is
self-contained.
```

## Multi-query dispatches and `gather_raw/` naming

Gather runs each query through
`defender-record-query --lead {lead_id} --query-id {id} -- defender-{system} …`
(see `defender/skills/gather/SKILL.md` §3; `--run-dir` defaults from the run
env and `--system` is derived from the inner command). The wrapper persists raw output
by-ref to `{run_dir}/gather_raw/{lead_id}/{seq}.json` and appends one row to
`executed_queries.jsonl` (the queries table, FK `lead_id`); gather neither
redirects stdout nor names files. `seq` disambiguates N-queries-per-lead — there
is no flat `{position}.json` / `{position}{a..z}.json` projection:

- `gather_raw/l-001/0.json` — first query for lead `l-001`
- `gather_raw/l-001/1.json`, `gather_raw/l-001/2.json` — further queries for `l-001`
- `gather_raw/l-002/0.json` — first query for lead `l-002`

## What is *not* a template

Templates measure **primitives** — a single dataset, a single filter shape,
one CLI invocation. Cross-primitive correlations are not templates.

When a lead asks for "X correlated with Y at time T" (e.g. *who was logged
in when /etc/passwd changed?*), the right move is: run the two primitives
that already exist, summarize the join in the gather return. **Do not
mint a "bridge" template** — it bloats the catalog with one-offs that
won't be reused. See `defender/skills/gather/SKILL.md` §Composition leads.

## Naming a new measurement

When the lead has no matching template, gather does **not** author a
template file — it coins a measurement id and runs under it (see
`defender/skills/gather/SKILL.md` §2). The offline lead-author mints the
`_draft/{id}.md` file from the execution record and curates it. To coin
the id:

1. Pick a `{system}` based on which data source the query must hit.
2. Pick a kebab-case `{template-id}` describing what the query measures,
   not why the defender asked for it. Good: `auth-events`,
   `file-integrity-changes`. Bad: `check-bastion-pivot`,
   `auth-events-by-host` (the by-X axis is a parameter, not a separate
   template).

Bias toward coining a fresh id rather than wedging a near-match —
duplicates are cheaper to normalize later than mis-keyed cross-case joins
are to recover. But first check whether an existing template already
carries the **capability** you need with a different parameter binding
(the template body, not the filename, is what determines fit).

This file documents the template *shape* the lead-author produces when
it promotes a coined measurement; gather only supplies the id.
