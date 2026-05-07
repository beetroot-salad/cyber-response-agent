# `lead_sequence.yaml` — schema

The defender emits `lead_sequence.yaml` at end-of-run. Each entry records
one defender→gather dispatch: the natural-language lead description the
defender sent, and the query (or queries) gather actually executed in
response.

This is the surface the actor-reviewer learning loop replays
(`docs/actor-reviewer-learning-loop.md` §"Lead set projection"). The
cross-case join key is `(query.id, query.params)`. If the file does not
project cleanly, the run is not consumable by the learning loop.

> **Revisit when the learning loop lands.** The shape below is what the
> defender emits today — minimum viable for gray-box replay. Field needs
> on the consumer side will only become concrete once the actor-reviewer
> pipeline is built; expect this schema to tighten (or grow) then, not
> before.

## Shape

```yaml
case_id: <run id, matches results/{run_id}/ dir name>
alert_ref: alert.json                  # relative to results/{run_id}/
entries:
  - position: 0                        # ordinal in dispatch order
    lead_description:                  # what the defender asked gather for
      goal: <one-sentence measurement contract>
      what_to_characterize:
        - <dimension, e.g. "timing pattern of failed auths from 10.42.7.183">
    queries:                           # what gather ran
      - id: wazuh.auth-events-by-host
        params: {host: bastion-01.corp, window_start: ..., window_end: ...}
    result_ref: gather_raw/0.json      # relative to results/{run_id}/
```

When gather fans a single dispatch out into multiple queries, each query
is an entry in the same `queries` list — there is no separate "composite"
mode. When gather runs only one query, `queries` has one element.

## Field contracts

- **`position`** is dense and 0-indexed, monotonically increasing in
  dispatch order. ANALYZE iterations on the same dispatch don't
  increment.
- **`lead_description.goal`** is the defender's intent in the defender's
  words — not a post-hoc paraphrase of what gather returned.
- **`queries[].id`** is the durable identifier. Format
  `{system}.{kebab-name}`, matching a template under
  `defender/skills/gather/queries/{system}/`. If gather authored the
  template during this run, the file is written back to the catalog
  before the sequence is emitted, so every id resolves.
- **`queries[].params`** carries the *bound* values, not parameter
  declarations. The template file declares the parameter set; the
  sequence entry records what they were resolved to.
- **`result_ref`** points to the raw payload gather wrote to disk. The
  defender works from gather's summary; raw lives on disk for replay
  and for the agent to Read on demand if the summary is too thin.
  Hidden from the actor during the gray-box story phase, revealed
  after.

## Authoring discipline

- The defender writes `lead_sequence.yaml` at end-of-run, projecting from
  the investigation log.
- Every entry must have at least one query with an `id`. If gather hit a
  wall before running anything, that dispatch does not appear in the
  sequence — the investigation log records the dead end under ANALYZE,
  but the sequence surface is "what actually ran."
- The defender re-reads `gather_raw/{result_ref}` if its summary is too
  thin to project the entry faithfully; the raw is the source of truth
  for `params`.
