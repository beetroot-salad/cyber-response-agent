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
(e.g. `wazuh/`, `host-query/`). It doubles as the routing prefix for the
template id and as a coarse `ls`-time filter.

`{template-id}` is kebab-case. Name it for **what the query measures**
(`auth-events`), not the axis you happen to filter on (`auth-events-by-host`)
and not why the defender asked for it (`check-if-bastion-was-pivoted`). A
single template can carry several optional filter knobs.

## File format

```markdown
---
id: wazuh.auth-events
---

## Goal

What this query measures, in one or two sentences. **Write for keyword
recall** — name the concrete artifacts a future analyst would type when
searching: daemon names (sshd, sudo), file paths (/etc/passwd), log fields,
syscalls. Gather greps `## Goal` body across the catalog when the dispatch
needs to find the right template at scale.

## What to characterize

- <dimension 1>
- <dimension 2>

These are the bullets gather's summary back to the defender must address.
Each item is reported, even if "not observed" — omission is ambiguous to
the parent.

## Query

The query body the system of record executes, with `${param}` placeholders.
This is system-native — Elasticsearch DSL for wazuh, a shell pipeline for
host-query, SQL for relational stores, etc. The system's CLI client is a
thin dispatcher; it does not interpret a query DSL of its own. Gather
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

## What is *not* a template

Templates measure **primitives** — a single dataset, a single filter shape,
one CLI invocation. Cross-primitive correlations are not templates.

When a lead asks for "X correlated with Y at time T" (e.g. *who was logged
in when /etc/passwd changed?*), the right move is: run the two primitives
that already exist, characterize the join in the gather summary. **Do not
mint a "bridge" template** — it bloats the catalog with one-offs that
won't be reused. See `defender/skills/gather/SKILL.md` §Composition leads.

## Authoring a new template

When the lead has no matching template:

1. Pick a `{system}` based on which data source the query must hit.
2. Pick a kebab-case `{template-id}` describing what the query measures,
   not why the defender asked for it. Good: `auth-events`,
   `file-integrity-changes`. Bad: `check-bastion-pivot`,
   `auth-events-by-host` (the by-X axis is a parameter, not a separate
   template).
3. Write `## Goal` for keyword recall. Future-you will grep this body.
4. Run it, summarize for the defender, and record the id in
   `lead_sequence.yaml` like any other entry.

Bias toward authoring a fresh id rather than wedging a near-match —
duplicates are cheaper to normalize later than mis-keyed cross-case joins
are to recover. But before authoring, check whether an existing template
already carries the **capability** you need with a different parameter
binding (the template body, not the filename, is what determines fit).
