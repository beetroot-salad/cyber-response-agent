# Query template catalog — file format

Per `tasks/defender-poc-lean-loop.md` §design-principle 4, the defender POC
identifies leads by **query template id**, minted at GATHER time. This
directory is the per-system catalog. It grows organically: GATHER mints new
templates inline when no existing one fits, writes the file here, and records
`source: minted` in the run's `lead_sequence.yaml`. Near-duplicates are
accepted early; normalization happens later when patterns stabilize.

## Layout

```
queries/
  SCHEMA.md                    # this file
  {system}/                    # one dir per system of record
    {template-id}.md           # one file per template
```

`{system}` is the prefix on the template id. Current pilot systems:
`wazuh/`, `host-query/`. New systems get a new subdirectory.

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

What this query measures, in one or two sentences. Mirrors the
"goal" line in production lead definitions.

## What to characterize

- <dimension 1>
- <dimension 2>
- ...

These are the bullets GATHER's summary must address. Each item must be
reported, even if "not observed" — omission is ambiguous to the parent.

## Query

Concrete CLI invocation (or query body) with `${param}` placeholders.
This is what GATHER substitutes parameters into and runs.

```sh
wazuh-cli auth-events --host ${host} --start ${window_start} --end ${window_end}
```

## Common pitfalls

- <pitfall 1: e.g. NAT collapse, time-window edge cases, etc.>

## Baseline (when `baseline: required` or `optional`)

How GATHER constructs a baseline / shift-window query for comparison.
Skip this section when `baseline: not-applicable`.
```

## Field contracts

- **`id`** must equal `{parent-dir}.{filename-stem}`. The parser
  enforces this so the cross-case key in `lead_sequence.yaml` is
  unambiguous.
- **`params`** is the parameter set. `lead_sequence.yaml` records the
  bound values; the order here is just declaration order.
- **`data_tags`** mirrors production lead frontmatter. Used by GATHER's
  optional health probe (POC may skip the probe; the field stays so
  templates remain compatible if probes are added later).
- **`baseline: required`** means GATHER must also run the shift-window
  query and return both `characterization:` and `baseline:` blocks.

## Minting discipline

When PLAN's lead description has no matching template:

1. GATHER picks a `{system}` based on which data source it must hit.
2. GATHER picks a kebab-case `{template-id}` describing what the query
   measures, not why PLAN asked for it. Good: `auth-events-by-host`.
   Bad: `check-if-bastion-was-pivoted-through`.
3. GATHER writes the template file with the four sections above.
4. GATHER records `source: minted` in the sequence entry.

Bias toward minting a fresh id rather than wedging a near-match — the
slug-sprawl risk is real but normalization downstream is cheaper than
mis-keyed cross-case joins.
