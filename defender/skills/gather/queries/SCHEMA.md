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
id: {system}.sshd-auth-history
status: established        # or `draft` while under curation
engine: esql              # for elastic; omit for shell/SQL-shaped systems
---

## Goal

What this query measures, in one or two sentences, **plus an explicit note
that it is a wide/superset query you narrow** (see below). **Write for keyword
recall** — name the concrete artifacts a future analyst would type when
searching: daemon names (sshd, sudo), file paths (/etc/passwd), log fields
(`source.ip`, `user.name`), syscalls. Gather greps `## Goal` across the catalog
to find the right template at scale, so a wide template's recall keywords are
what keep a future narrowing from re-coining a sibling.

## Query

The query body the system of record executes, fenced and language-tagged
(```` ```esql ````, ```` ```sql ````, ```` ```bash ````). For elastic this is a
server-side **ES|QL** aggregation against `logs-*`; the result rows ARE the
answer. Bindings use `${param}` placeholders (`${start}`, `${user}`, `${src}`)
where a template parameterizes them; an ES|QL pipe may also inline literals that
gather rewrites per lead.

This is a **wide/superset** query — carry every filter axis (`user`, `src`,
`dst`, window) and a broad aggregation. **Gather narrows it to the lead**: drops
the predicates the lead doesn't constrain and the `BY` keys it doesn't ask for.
Fork to a new template only for a different *measurement*, never a different
parameter.

**Narrowing examples** — list 2-3 concrete narrowings (each the query above with
axes removed), so the next analyst sees the capability covers their case:

- *<one narrowing>*: keep <axes>, drop <axes>.

## Pitfalls

- <pitfall 1: e.g. a null-heavy field that needs an `IS NOT NULL` guard, a
  message-only field that needs `GROK`/`CASE`, NAT collapse, window edge cases>
```

Older templates carried `## What to summarize` and `## Baseline (when
applicable)` sections; the ES|QL migration folded both into `## Query` (the
aggregation *is* the summary; a baseline is the same wide query over a second
window, a narrowing — not a separate section). New and promoted templates use
the shape above.

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
