# `lead_sequence.yaml` — defender POC contract

The defender emits `lead_sequence.yaml` at end-of-run. It is the **contract
surface** the actor-reviewer learning loop replays
(`docs/actor-reviewer-learning-loop.md` §"Lead set projection"). If the
defender cannot project a clean lead sequence, the run is unusable for
learning.

This schema is the POC variant: per design principle 4 of
`tasks/defender-poc-lean-loop.md`, identification keys on **query template id**,
not lead slug. There is no shared slug catalog. The cross-case key the
actor-reviewers join on is `(query_template.id, params)`.

## Shape

```yaml
case_id: <run id, matches results/{run_id}/ dir name>
alert_ref: alert.json                  # relative to results/{run_id}/
entries:
  - position: 0                        # ordinal in PLAN→GATHER order
    mode: single | composite           # composite = N legs from one PLAN turn
    lead_description:
      goal: <one-sentence measurement contract>
      what_to_characterize:
        - <dimension, e.g. "timing pattern of failed auths from 10.42.7.183">
      emphasis: <optional PLAN emphasis, or null>
      scope: <window/anchor, e.g. "T0 ± 30m, host=bastion-01.corp">
    query_template:
      id: <system-prefixed kebab, e.g. wazuh.auth-events-by-host>
      source: catalog | minted         # minted = GATHER created on the fly
      params: {host: bastion-01.corp, window_start: ..., window_end: ...}
    legs: []                           # populated when mode == composite
    gather_status: ok | partial | data_missing | empty | error
    result_ref: gather_raw/0.json      # relative to results/{run_id}/
```

For `mode: composite`, `legs[]` is a list of `{lead_description,
query_template, gather_status, result_ref}` entries — same shape minus
`position` and `mode`. The parent entry's `query_template` may be the
"primary" leg or `null` if PLAN issued the legs as a batch with no
canonical primary.

## Field contracts

- **`position`** is dense and 0-indexed. Loops back through PLAN/GATHER
  produce monotonically increasing positions; ANALYZE iterations on the
  same lead don't increment.
- **`lead_description.goal`** must be PLAN's intent in PLAN's words —
  not a post-hoc paraphrase of what GATHER returned. Keep it short.
- **`query_template.id`** is the durable identifier. Format:
  `{system}.{kebab-name}` where `{system}` matches a directory under
  `defender/skills/gather/queries/`. Examples:
  `wazuh.auth-events-by-host`, `host-query.process-tree-by-pid`.
- **`query_template.source: minted`** means GATHER did not find a
  pre-existing template that fit; it minted one and wrote the template
  file back to the catalog as part of this run. New templates land at
  `defender/skills/gather/queries/{system}/{kebab-name}.md`.
- **`query_template.params`** carries the *bound* values, not parameter
  declarations. The template file declares the parameter set; the
  sequence entry records what they were resolved to.
- **`gather_status`** values:
  - `ok` — query ran, returned data, characterization is complete
  - `partial` — query ran but did not characterize every required dimension
  - `empty` — query ran, returned no rows; this is itself a finding
  - `data_missing` — required data source not available / not configured
  - `error` — query failed to run (template bug, system down, etc.)
- **`result_ref`** points to the raw payload that the gather subagent
  wrote to disk (per design principle 2). Main agent context only sees
  the gather summary; raw is on disk for replay and for the agent to
  Read on demand.

## What is NOT in this schema (and why)

- **No `selected_lead` slug.** Per principle 4, slugs are ceremonial; the
  template id is the thing that actually identifies what ran.
- **No `extended_definition.ref`** to a catalog `definition.md`. The
  per-lead catalog is gone; per-template files in
  `defender/skills/gather/queries/` carry the goal/dimensions/pitfalls
  the actor-reviewers used to read out of `definition.md`.
- **No `common_pitfalls` / `baseline` blocks** at the entry level. Those
  are properties of the *query template*, not of the lead instance, and
  live in the template file. The sequence entry is just the binding.
- **No `missing-lead` mode.** With `source: minted` on `query_template`,
  every executed lead is addressable; there is no separate "lead PREDICT
  emitted but GATHER could not run" state — that becomes
  `gather_status: data_missing` or `error`.

## Authoring discipline

- The defender writes `lead_sequence.yaml` **end-of-run**, not
  incrementally. (Open question per the task; start simple.)
- Every entry must have a `query_template.id`. If GATHER hit a wall
  before running a query, that lead does not appear in the sequence —
  the investigation log records it under ANALYZE, but the sequence
  surface is "what actually ran."
- The defender should re-read `gather_raw/{result_ref}` if its summary
  is too thin to project the entry faithfully; the raw is the source of
  truth for `params` and `gather_status`.
