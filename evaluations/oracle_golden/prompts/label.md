You are reading telemetry from a synthetic security environment. A defender lead ran a
small set of related queries over a window in which some activity took place. You are
given what those queries returned over that window, and what the **same query strings**
returned over comparable windows when no such activity was running.

Your only job:

> **What did this envelope actually do, relative to its baseline?**

You are **not** given the story of what happened, and you are **not** given any
prediction about what these queries should have returned. That exclusion is deliberate:
your answer is the measurement that a prediction is later graded against, and a
measurement that has seen the prediction is not independent of it. **If you find yourself
needing either one to decide, the answer is `undecidable` — say so rather than
inferring.**

## What you are given

1. `lead` — every query in this lead: system, template id, params, and time window.
2. `sample` — a scrubbed shape skeleton for this data source.
3. `observed` — what these queries returned over the operation window.
4. `baseline` — the same query strings with only their `@timestamp` bounds moved to
   comparable no-activity windows. Each carries `window_live`: whether the environment
   was actually running during that window.
5. `environment_notes` — facts about this capture environment that change how a
   difference between two windows should be read.

Payloads may be truncated; a truncated payload carries `truncated: true` and its true
`row_count`. **Never infer absence from a truncated payload.**

A payload may also be missing entirely: `unreadable: true` means the capture never
recorded that query's result. That is **not** an empty result set and is not evidence of
anything. If the lead's other queries settle the answer, use them; if the unreadable one
was the query that mattered, return `undecidable` with `payload-shape-unreadable`.

## Rules

**An empty control window is not an empty baseline.** If `window_live` is false, the
environment was not running — zero rows means "not measured", not "nothing routine
happens here". You cannot conclude `suppressed`, and you cannot conclude that a delta is
real. Return `undecidable` with `insufficient-baseline`.

**Distinguishability is a property of the queries' fields.** Rows that differ from
baseline rows only in fields these queries do **not** surface are `indistinguishable`,
not `present`. Judge only what the payload actually carries — never a field you expect
the underlying events to have but these queries do not return.

**Unstable identifiers.** Read `environment_notes` before treating any cross-window
difference as real. A value that is not stable across windows in this environment cannot
evidence a delta — rows differing only in such a value are not a delta.

**State and lookup systems are `state-only`.** Queries returning current configuration or
an entity record rather than an event stream have no baseline-diff semantics. Tag them
`state-only` regardless of whether their rows changed.

**Judge each query, then the lead.** A lead's envelope is the union of what its queries
surface: if any single query surfaces a distinguishable delta, the lead is `present`,
even when sibling queries look at quiet windows. Record separately, in `heterogeneous`,
whether the lead's queries disagree with one another.

**Abstain freely.** `undecidable` is a designed outcome with no downstream penalty. Use
it whenever the payloads you were given do not determine the answer. Do not guess.

## `delta_kind` values

| value | meaning |
|---|---|
| `present` | the observed window carries rows that are distinguishable from baseline in a field these queries surface |
| `indistinguishable` | the observed window carries additional rows, but every surfaced field is baseline-identical |
| `suppressed` | the baseline is non-empty over a **live** window and the observed window is empty — the stream went dark |
| `absent` | no delta: the observed window matches its baseline |
| `state-only` | these queries return current configuration or an entity record, not an event stream |

## Output

Emit a **single YAML document** as your entire response. Do **not** wrap it in a
```yaml … ``` (or any other) fenced code block, and add no preamble or trailing
commentary. Your first character is `d` (the start of `delta_kind:`). The downstream
harness parses the whole output with `yaml.safe_load`.

```yaml
delta_kind: {present | indistinguishable | suppressed | absent | state-only | undecidable
             — plain scalar, unquoted}
undecidable_reason: {omit unless delta_kind is undecidable. One of: insufficient-baseline |
                     truncated-payload | payload-shape-unreadable}
heterogeneous: {true | false | null — do this lead's queries disagree with each other?
                null when fewer than two queries are decidable}
evidence: |
  {two to four sentences. Name the specific rows, columns, and counts in `observed` and
  `baseline` that decide it, and say which field carries the distinction (or that none
  does). Cite values, not impressions. If you returned undecidable, say exactly which
  payload would have settled it.}
```
