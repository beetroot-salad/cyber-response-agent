# Query template catalog — file format

This directory is the gather subagent's query catalog, organized per system
of record. Every query the defender executes against a data source is bound
to a template file here, addressed by id. When no existing template fits,
gather authors a new one and writes it back as part of the run.

## Layout

```
queries/
  SCHEMA.md                    # this file
  {system}/                    # one dir per system of record
    {template-id}.md           # one file per template
```

`{system}` is the prefix on the template id and matches a system the gather
subagent knows how to dispatch against (e.g. `wazuh/`, `host-query/`). New
systems get a new subdirectory.

`{template-id}` is kebab-case. The full id used in `lead_sequence.yaml` is
`{system}.{template-id}`.

## File format

```markdown
---
id: wazuh.auth-events-by-host
params: [host, window_start, window_end]
data_tags: [auth-events]
baseline: optional             # required | optional | not-applicable
---

## Goal

What this query measures, in one or two sentences.

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

## Common pitfalls

- <pitfall 1: e.g. NAT collapse, time-window edge cases>

## Baseline (when `baseline: required` or `optional`)

How gather constructs a baseline / shift-window query for comparison.
Skip this section when `baseline: not-applicable`.
```

## Field contracts

- **`id`** equals `{parent-dir}.{filename-stem}` by convention, so the
  cross-case key in `lead_sequence.yaml` is unambiguous.
- **`params`** is the parameter set the template declares. The lead
  sequence records the bound values; declaration order here is just for
  readability.
- **`data_tags`** marks which abstract data sources the query depends on,
  for health-probe routing.
- **`baseline: required`** means gather must also run the shift-window
  query and return both `characterization:` and `baseline:` blocks in its
  summary.

## Authoring a new template

When the lead description gather receives has no matching template:

1. Pick a `{system}` based on which data source the query must hit.
2. Pick a kebab-case `{template-id}` describing what the query measures,
   not why the defender asked for it. Good: `auth-events-by-host`.
   Bad: `check-if-bastion-was-pivoted-through`.
3. Write the template file with the four sections above.
4. Run it, summarize for the defender, and record the id in
   `lead_sequence.yaml` like any other entry.

Bias toward authoring a fresh id rather than wedging a near-match —
duplicates are cheaper to normalize later than mis-keyed cross-case joins
are to recover.
