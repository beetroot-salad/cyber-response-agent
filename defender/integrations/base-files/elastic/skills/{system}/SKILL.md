---
name: defender-{system}
description: Elasticsearch reference for the system `{system}` — what its two search verbs can answer, what they cannot, and how to read their results.
---

`{system}` is an Elasticsearch cluster reached through one adapter. Two settings name what it may read: an events
index pattern and an alerts index pattern. The adapter refuses any other target, so what this system can answer is what
those two patterns hold. Execution detail (query syntax, the result envelope, value constraints) is in `execution.md`,
read only by gather.

## Visibility surface

### available_queries

| Verb | Answers | Reads |
|---|---|---|
| `query` | what events were recorded: who, from where, to what, when; counts and cadence over a window | the configured events pattern |
| `alerts` | which detection rules fired, on what, how often, at what severity | the configured alerts pattern |
| `esql` | counts, distributions, cardinalities and timings computed server-side | whichever configured pattern its `FROM` names |

Seed templates for `query` and `alerts` are under `skills/gather/queries/{system}/`.

Use `query` for "did this happen, and what does the timeline look like". Use `alerts` for "what else fired in this
neighborhood". Use both when an alert's discriminating signal lives in the events beneath it. Prefer `esql` for any
count, distribution or timing; use `query` when the event documents themselves are the evidence.

### gaps

- **Only the configured patterns.** Data outside them is unreachable, and so is a data stream that is not shipped into
  them. A source that never shipped answers like a quiet one, so an empty result does not say which.
- **Only what the shippers parsed.** A field is typed and filterable on the lines its ingest parsed. Other lines of the
  same index carry it null, and a null actor is a parser gap, not an anonymous one.
- **No host role and no identity authority.** Whether a host is production, or whether a user may do what they did, is
  not in event data; it comes from other systems.
- **No ticket or change state.**
- **No process ancestry beyond what the sensor records.** Where an event names a parent process it does not chain
  further back.
- **The documents returned are capped** (see `execution.md`). Totals are exact; the documents shown are one end of the
  window.

### read_guidance

- **An empty result is not a refutation.** Before treating zero as absence, check the query parses (an unknown field
  matches nothing and says nothing), that the window covers a period the stream was shipping, and that the index scope
  is the stream you meant.
- **A wide pattern searches every stream in it,** shipper self-telemetry included. Scope by a dataset field or by the
  `index` param when the question belongs to one stream.
- **Bind the window explicitly** (`start`, `end`) rather than relying on relative time: shippers and rule engines lag
  each other by seconds, and rounding to now hides ordering questions.
- **Which end of the window you got.** A capped search returns the newest documents by default. A question about what
  happened first, or what started a burst, needs the oldest end: say so with `sort`.
- **Match free text with a quoted phrase** on the analyzed text field. Never wrap the phrase in `*`: it is a silent
  no-op that leaves the total unchanged.
- **Detection alerts are signals, not facts.** An alert names a rule and the documents it matched; the discriminating
  evidence is usually in the events under it. Correlation rules fire on a pattern across hosts, so their host field can
  be null.

## Execution

Query syntax, index scoping, the result envelope and the exit codes are in `execution.md`, read by gather only.
