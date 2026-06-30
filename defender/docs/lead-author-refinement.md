# Lead-author agent — refinement design note (2026-05-19)

Companion to `defender/docs/learning-loop.md`. Captures the design
discussion following PR #218 (minimal lead-author + top-k neighbor
scorer). PR #218 lands the driver and prompt; this note collects the
gaps surfaced by walking the prompt and the agent's responsibilities
end-to-end, plus the proposed next-step refinements.

Status: **design discussion, not yet implemented.** When this doc and
the code disagree, the code wins. The handoff schema and prompt
structure described below are the target; the as-shipped state is
single-handoff-per-invocation with `goal_text + params + neighbors`.

> **Update 2026-06-30 — `composite_kind` / `co_dispatched_with` removed.**
> These two fields (and the `lead_classifier` module) shipped, but an ablation
> (`experiments/lead-classifier-ablation/`, N=10×2 arms×4 fixtures incl. sweep /
> join / baseline_shift) found they had **zero** effect on the lead-author's
> discard/promote decisions — the `neighbors`/narrowing check already prevents
> underfolding, and the signal only ever rides the skip-defaulted established
> handoff. They were deleted (supersedes #457, which proposed refactoring them).
> Ignore the `composite_kind` / `co_dispatched_with` mentions below.

## Scope

The lead-author is the offline curator of the executed-side query
template catalog at `defender/skills/gather/queries/`. PR #218 wires
the minimum needed to fold lessons from one defender run into the
catalog: a driver that extracts handoffs, a neighbor scorer that
surfaces sibling templates, a prompt that decides fold/split/skip per
handoff, and a post-flight scope check.

The minimum works. This note is about what's missing for the agent to
actually do its job well.

## Findings from a static read of `lead_author.md` + `lead_author.py`

1. **The agent is never told to read `result_refs`.** The decision
   procedure mentions reading `executed_template_path` plus each
   neighbor file; result payloads are pointed to but not inspected.
   Means the agent has no signal about whether an executed query
   succeeded, returned an error, or was empty — only the defender's
   stated intent.

2. **No batching guidance when handoffs share a template.** Handoffs
   are processed in order. If positions 0 / 2 / 4 all target
   `wazuh.auth-events`, the prompt doesn't say "collapse these and do
   one Read+Edit cycle." Risk: three sequential Edit calls to the
   same file, potentially contradictory.

3. **The "merge" hole is acknowledged but not instrumented.**
   `lead_author.md` says "fold lessons into the surviving one and skip
   the redundant; a human can clean up the duplicate in a follow-up
   PR." No tracker file, no commit-message marker. The signal that a
   human should merge two templates evaporates as soon as the tick
   exits.

4. **Neighbor scoring is query-body Jaccard only.** Two templates with
   the same intent but different Lucene shapes don't surface as
   neighbors. Conversely, two templates with similar Lucene shape but
   different intent do.

5. **The rendered query body isn't in the handoff.** Only `params` is
   passed. The agent can't see what the dispatched query actually
   looked like — so an unbound `${host_clause}` leaking through, or a
   wrong-shape filter, is invisible without reading the result_ref
   (see #1).

6. **Schema not loaded into prompt.** The agent has to remember (or
   follow a link to) `SCHEMA.md` for the keyword-recall + filter-binding
   conventions.

Findings #1, #5, #6 collapse to one diagnosis: **the handoff is too
thin.**

## Loud-failure filter

There isn't one. `extract()` filters only on "does the payload file
exist on disk." The CLI adapters write a payload regardless of outcome
— "no matching processes" is 35 bytes of JSON; an indexer rejection
can be a JSON body with an `error` key; a silent type-mismatch returns
zero events with no signal. All three pass through `extract()`
identically.

After extract, the agent doesn't read the payload (finding #1). So
loud failures pass through two layers of the pipeline silently.

The only true filter is "did gather crash before invoking the adapter"
— and that's invisible too (no log entry names dropped positions).

## Lead-shape taxonomy

Walking the (goal, query) cardinality dimensions:

**Atomic** (1 goal, 1 query):
- Direct measurement, state inspection, provenance, time-series-within-one-query,
  *counterfactual / null-as-answer* (where empty is the answer).

**Multi-intent on one template** (N goals, 1 query — across invocations or runs):
- `auth-events` filtered by-host vs by-user vs by-srcip.
- `process-list` filtered by different intent-patterns.
- The catalog naming convention bakes this in: name templates for
  what they measure, not for the intent that drove the invocation.

**Composite** (1 goal, N queries):
- *Baseline / shift* — foreground + shifted historical window.
- *Drill-down / decomposition* — primary aggregation + filtered detail
  informed by the agg's output. Inter-query dependency.
- *Alternative-binding sweep* — same template, N parameter values.
- *Cross-system join* — auth-events ∧ CMDB ∧ IAM, glued by entity.
  Per `SCHEMA.md` §"What is not a template," these stay as separate
  primitives.

**Meta** (out of scope for the catalog):
- Recursive / chained-on-result-content (next-loop dispatches),
  state-at-time vs. current-state, past-investigation corpus query.

The three buckets (single, multi-intent, composite) cover the
**physical (goal, query) cardinality** space. What they miss is
**structure inside the composite bucket** — composite kind (baseline /
drill-down / sweep / join) determines which template section is
load-bearing for the catalog (`## Baseline` vs `## Filter binding` vs
`## Common pitfalls`). The agent can't currently tell which composite
kind it's looking at, so it can't tell which section to grow.

For the **catalog's persistent layer**, no schema change needed —
the catalog is template-keyed, not investigation-keyed. For the
**author's transient handoff**, composite-kind should be inferred and
surfaced.

## Revised handoff schema

Key changes:

- One handoff per `executed_template_path`, not per invocation. Same
  template touched 3× in one run collapses to one handoff with 3
  invocations.
- `neighbors` moved to handoff scope, computed once.
- Each invocation carries the rendered query body, payload status
  digest, and composite-kind inference.

```jsonc
{
  "executed_template_path": "defender/skills/gather/queries/wazuh/auth-events.md",
  "query_id": "wazuh.auth-events",
  "neighbors": [
    {"template_path": "defender/skills/gather/queries/wazuh/sudo-commands.md",      "score": 0.41},
    {"template_path": "defender/skills/gather/queries/wazuh/recent-rule-fires.md",  "score": 0.33},
    {"template_path": "defender/skills/gather/queries/wazuh/dns-query-history.md",  "score": 0.29}
  ],
  "invocations": [
    {
      "position": 0,
      "query_index": 0,
      "goal_text": "Characterize SSH activity from 10.42.7.183 against bastion-01.",
      "what_to_summarize": [
        "source IP diversity",
        "auth methods (publickey vs password)",
        "success/failure ratio"
      ],
      "params": {"host": "bastion-01", "srcip": "10.42.7.183", "window": "1h"},
      "rendered_query": "python3 defender/scripts/adapters/wazuh_cli.py query --query 'rule.groups:(authentication_success OR authentication_failed) AND agent.name:bastion-01 AND data.srcip:10.42.7.183' --window 1h --run-dir <run_dir>",
      "payload_status": "ok",
      "payload_digest": "847 events; 12 distinct dstuser; 1 distinct srcip; 95% authentication_failed",
      "result_refs": ["gather_raw/0.json"],
      "composite_kind": "atomic",
      "co_dispatched_with": []
    },
    {
      "position": 4,
      "query_index": 0,
      "goal_text": "Lateral-spread check: same srcip across other hosts.",
      "what_to_summarize": ["host diversity for this srcip"],
      "params": {"srcip": "bastion-01", "window": "1h"},
      "rendered_query": "python3 defender/scripts/adapters/wazuh_cli.py query --query 'rule.groups:(authentication_success OR authentication_failed) AND data.srcip:bastion-01' --window 1h --run-dir <run_dir>",
      "payload_status": "suspect_empty",
      "payload_digest": "0 events; data.srcip is IP-typed; literal 'bastion-01' rejected silently as non-IP",
      "result_refs": ["gather_raw/4.json"],
      "composite_kind": "atomic",
      "co_dispatched_with": []
    }
  ]
}
```

### Field-level notes

**`executed_template_path` + `invocations[]`** — handles batching
naturally. The agent decides fold/split/skip once per template, with
all invocations as evidence. Eliminates the duplicate-Edit-call risk
from finding #2.

**`rendered_query`** — the driver substitutes `params` into the
template's `## Query` body and includes the literal string.
Driver-only effort, no execution. Surfaces unbound placeholders and
wrong-type bindings without requiring payload reads. Closes finding
#5.

**`payload_status`** — closed enum computed by the driver:
- `ok` — body has structured data
- `empty` — body is `[]`/`{}`/contains a "no matching X" marker
- `suspect_empty` — empty *and* params or template's filter-binding
  REFUSE rules indicate silent failure (heuristic: type-mismatch on a
  known-IP-typed field, etc.)
- `error` — JSON has `error` key, or body matches stderr-style prefix
- `partial` — truncation marker present

`suspect_empty` is the addition that gives loud-failure detection
without full payload inspection. Drives the agent toward
fold-a-pitfall on the exact case the as-shipped pipeline misses.

**`payload_digest`** — ≤ 200 chars, one-line characterization extracted
from the payload header (Wazuh: "N events, K distinct field-X";
host-query: "stdout: N lines, exit=N"; error: first 200 chars
verbatim). Sidesteps the cost of asking the agent to read 54KB
payloads.

**`composite_kind`** — `atomic | baseline_shift | drill_down | sweep |
join`. Inferred from the lead's `queries[]` structure at handoff-build
time. Lets the author know which template section to grow.

**`co_dispatched_with`** — when this invocation was one of multiple
queries in a single lead, list the other templates' paths. Makes the
join/composite relationship visible without forcing cross-handoff
correlation.

### Decision procedure shift

```
For each handoff (one per template):
  1. Read the executed template + each neighbor.
  2. Inspect invocations[]:
       - union of goal_texts → does ## Goal cover all the keywords?
       - spread of params → does ## Filter binding name the dimensions invoked?
       - payload_status distribution → are there suspect_empty / error invocations?
       - composite_kind distribution → is ## Baseline / ## Filter binding load-bearing?
  3. Decide fold | split | skip:
       - fold the union-of-intents into ## Goal (keyword recall)
       - fold suspect_empty / error patterns into ## Common pitfalls or ## Filter binding REFUSE
       - split only if invocations exercise incompatible patterns
```

Plus a hard rule:

> An invocation with `payload_status: error` or `suspect_empty` is a
> load-bearing signal. The default is to fold a pitfall/REFUSE clause
> covering the failure mode. Skip is only acceptable if the pitfall
> is already covered.

## Scope: every lead or only new templates?

The as-shipped behavior is **every lead executed in this run gets a
handoff** (filtered only on "query_id resolves in the catalog"). This
is the right default.

Rationale: the catalog learns from **use**, not novelty. An
established template with 10 invocations still benefits from
invocation #11 if it surfaces:
- a new intent shape (grows `## Goal` keyword recall)
- a `suspect_empty` from a known-bad binding (grows `## Filter binding`
  REFUSE)
- an `error` payload revealing an undocumented edge case

These are exactly the cases "only new templates" would miss.

Caveat: **skip should be the dominant decision in steady-state.** Once
the catalog matures, most invocations are routine and shouldn't drive
edits. The `payload_status` field gives the agent a clear "this is
worth your attention" trip-wire that justifies fold over skip. Without
it, the prompt has no calibration signal and the catalog will churn.

### Calibration knob

Skip rate is the single most important post-deployment metric:
- < 50%: prompt is over-eager, catalog will churn
- > 95%: prompt is too cautious, real signal dropped
- Sweet spot probably 70–85% once mature

Each tick should land a structured per-template decision record
(fold/split/skip + template_path + reason) — either in the commit
message body or as a sidecar JSONL — so the rate can be swept across
runs.

## Responsibility separation: gather adds, lead-author edits

Today gather both selects existing templates and authors new ones
mid-run, writing directly into the catalog (per CLAUDE.md's "every id
resolves" guarantee). Lead-author edits everything afterward.

Proposed sharpening:

**Gather (runtime, Haiku, time-bound, single-run):**
- Selects from existing templates (read-only against catalog).
- Drafts new templates when nothing fits — but writes them to
  `defender/skills/gather/queries/{system}/_draft/{id}.md`, not directly
  into the established catalog.
- Records observations (a `suspect_empty` outcome, an unexpected
  payload shape, a binding that needed retry) into the run dir as
  structured side data.
- Debugs by re-dispatch (retry with corrected binding, fan into
  composite).
- **Never edits established templates.** Even when gather notices a
  pitfall mid-run, it records the observation, doesn't rewrite the
  file.

**Lead-author (offline, Sonnet, batched, multi-invocation):**
- Promotes drafts → established (or discards them as duplicates).
- Folds new pitfalls and intent keywords into established templates.
- Extends `## Goal` / `## Filter binding` / `## Common pitfalls` based
  on observations gather recorded.
- Splits when invocations exercise genuinely incompatible patterns.
- **Owns all edits to established templates.** Monopoly.

### Why the draft/established split matters

Today gather's runtime authoring decisions become permanent catalog
mass before any cross-invocation observation. The catalog can't
distinguish "this template was authored 30 seconds ago by gather under
time pressure" from "this template has 50 successful uses."

A `_draft/` subdirectory + a frontmatter flag (`status: draft |
established`) fixes this without complicating gather's lookup logic:
- Gather resolves drafts by `{system}.{id}` — loader walks `_draft/`
  and the system root.
- `lead_sequence.yaml` records the id either way.
- Lead-author sees draft status in the handoff and treats promotion as
  a first-class decision alongside fold/split/skip.

It also gives lead-author the **discard primitive** the current
"no-merge" design is missing. Drafts are explicitly disposable.
Established templates are not. The driver allowlist can grant
`Bash(git mv .../_draft/*:*)` for promotion or archival without ever
granting delete on established templates.

### Architectural parallel

This is the same shape as the existing learning-loop split:
- judge emits **findings** → author distills **lessons**
- gather emits **draft templates + observations** → lead-author
  distills **catalog edits**

Runtime side records cheap signal under time pressure; offline side
does the expensive cross-instance distillation. Same pattern, same
contract shape, two independent surfaces.

## The scope fork: per-run vs corpus-aware lead-author

Once gather produces observations and drafts, lead-author has a choice
about how wide its window is:

(a) **Per-run** (PR #218 as-shipped): one tick = one run dir.
   Conservative; catalog grows in small increments.

(b) **Corpus-aware**: lead-author accumulates invocations + observations
   across runs in `_pending_leads/invocations.jsonl`, fires at threshold
   (analogous to `LEARNING_AUTHOR_THRESHOLD`). Each tick has cross-run
   vision and can answer "this template has been hit 14× across 8 runs
   in baseline-shift mode — promote `## Baseline`."

(b) maps closely to the existing `defender/learning/author.py` pattern.
The architecture is already there.

**Recommendation:** MVP at (a), design the handoff JSONL format from
day one so (b) is a driver upgrade away. Don't bake per-run
assumptions into the agent's prompt.

## Open questions

- **Pitfall promotion threshold.** If gather records "suspect_empty on
  srcip=hostname" *once*, does lead-author fold a pitfall? Or wait
  for N observations? Probably N=1 for hard-rule violations (silently-
  bad bindings) and N=3+ for soft pitfalls (NAT collapse, stale-credential
  noise). The `payload_status` taxonomy lets the prompt differentiate,
  but the threshold needs to be picked.

- **Observation schema.** Gather needs a place to write "I noticed X
  about this dispatch." Sidecar like
  `gather_raw/{position}.observations.json`? Inline in the gather
  summary the projector already parses? Either works; pick one.

- **Draft TTL.** If gather authors a draft and lead-author never sees
  it (run skipped, threshold not hit), the draft lingers. Need a
  sweeper, or a "drafts older than N days get archived" policy.

- **Cross-run aggregation key.** When moving to corpus-aware (option b),
  invocations join on `query_id` for template-level aggregation, but
  intent-keyword aggregation may want a finer key (e.g., `(query_id,
  composite_kind)`). Decide at the time, not now.

- **`merge` escape hatch via commit message.** Until lead-author owns
  a discard primitive (via `_draft/` mv), near-duplicate established
  templates accumulate. The acknowledged convention is "fold + skip
  the redundant + human cleans up later." A structured commit-message
  marker (e.g., `redundant-with: <template_path>` line) would let a
  human run a follow-up sweep without reading every diff. Cheap
  addition; consider for the next iteration.

## Migration path

Driver-only changes for the handoff schema rewrite:

1. `lead_author.py` — rewrite `build_handoff()` to group by `query_id`,
   compute `rendered_query` / `payload_status` / `payload_digest` /
   `composite_kind` per invocation. New small classifier module for
   the inference logic.
2. `lead_author.md` — rewrite the decision procedure for the
   per-template framing.
3. `lead_neighbors.py` — unchanged.
4. Tests — `test_lead_author.py` extend with batching and status-digest
   cases.

Subsequent changes for the responsibility-split + draft-vs-established
(separate PRs):

5. Gather subagent prompt — gain `_draft/` write semantics; lose
   permission to overwrite established templates (enforced by
   gather-side allowlist).
6. Template loader — walk `_draft/` in addition to system root.
7. Lead-author prompt — promote/discard as first-class decisions.
8. Observation sidecar — schema + hook to materialize.

The handoff schema rewrite is independent and can land first. Each
subsequent change is independently testable.

## Status

Design discussion captured. No implementation work scheduled. Next
concrete step is a focused empirical probe — pick one of the
hypotheses (likely T1 from the original probe set: same-template-3x
to confirm the duplicate-Edit assumption) and run it against the
as-shipped agent before committing to the rewrite.
