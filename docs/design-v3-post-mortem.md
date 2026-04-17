# Post-Mortem Hook — Rough Design

**Status:** Sketch. Not yet a spec.
**Date:** April 2026

The "post-mortem hook" is shorthand for the entry point responsible for
updating the knowledge base with insights from completed investigations.
This doc captures where a post-mortem mechanism adds value, where it
doesn't, and the rough shape of the pipeline around it. It is deliberately
not prescriptive about prompt contents or file formats yet.

---

## 1. Framing: post-mortem vs. query-past-investigations

The original mental model treated post-mortem as *the* way to let the
agent learn from past investigations. That model predates the
query-past-investigations capability (see
`docs/investigation-language.md`). Query-past-investigations is a more
flexible, custom, and powerful interface for **retrieval** — "has this
IP shown up?", "what did we do last time a 5710 matched this shape?".
For retrieval it is strictly better than baking ticket summaries into
the KB at post-mortem time.

What query-past-investigations **cannot** do is **distillation**:

- Collapse 50 tickets into a screen rule.
- Promote a recurring escalation shape to a named archetype.
- Refine a lead's pitfalls based on where it misled.
- Detect drift in environment classifications (IP ranges, identity
  patterns) that the ops source of truth hasn't caught up to.

That reframes the post-mortem's surviving job: it is the **curator of
the in-prompt hot cache** — the playbook, screen, archetype README,
lead pitfalls, vendor quirks — the artifacts that make the next
investigation fast, safe, and cheap.

**Cost model implication.** Post-mortem only pays off when it
amortizes. A $2 analysis that produces a screen rule saving $0.20
× 200 future runs is a good trade. A blanket "run on every completed
investigation" is not.

---

## 2. Where post-mortem adds value, section by section

For each KB section, the question is: does distilled, curated,
in-prompt knowledge beat query-at-runtime here?

### High leverage

**`signatures/{id}/playbook.md`** — the highest-value target. Four
compounding outputs:

1. **Screen refinement** — add/tighten indicators when fast-path false
   negatives or near-misses accumulate.
2. **New archetype proposals** — clusters of escalations with a common
   shape that isn't yet named.
3. **Starter lead reorder** — promote the lead that actually
   discriminates most often.
4. **Quirk additions** — edge cases discovered in investigation.

**`common-investigation/leads/{lead}/definition.md` + `templates/{vendor}.md`**
— pitfalls and template refinements. Triggered when a lead's result
was marked `-` or `--` but later evidence showed it should have been
supportive (template bug, field mapping drift, vendor quirk).

**`environment/systems/{vendor}/`** (field-quirks, auth-queries) —
updates when the agent used an ad-hoc lead to work around a templated
one, or a query returned unexpectedly empty and the agent diagnosed
why. Signal comes from the tool trace, not the narrative.

### Medium leverage, review-gated

**`signatures/{id}/archetypes/{name}/README.md`** — story + `required_anchors`.
Load-bearing safety content; post-mortem rarely edits directly.
Proposes edits when a pattern appears across multiple investigations
(e.g. the anchor kept being confirmed by a variant the README doesn't
mention).

**`signatures/{id}/archetypes/{name}/{TICKET}.json`** — precedent
snapshots. Natural fit but diminishing returns. Append *only* when the
snapshot extends shape coverage (new srcuser family, new
source-classification variant). After ~5 diverse snapshots per
archetype, more duplicates add nothing — invlang covers that case.

**`common-investigation/lessons/`** — planned but not yet populated.
Riskiest section: lessons easily become cargo-cult. Strong review gate
required; otherwise the KB rots in the opposite direction.

### Low leverage — skip or surface-only

**`environment/context/`** (ip-ranges, identity-patterns, criticality,
data-classification) — these are **org facts**, not investigation
learnings. Post-mortem's role is **drift detection**: "this IP has
behaved like monitoring 8 times but isn't classified" → surface as an
ops proposal, never auto-patch.

**`environment/operations/`** (approved-monitoring-sources,
scheduled-jobs, change-windows) — authoritative source is ops, not the
agent. Post-mortem detects gaps and files suggestions; never writes.

**`environment/data-sources/`** — deployment facts. Skip.

**`signatures/{id}/context.md`** — threat model / signature reference.
Mostly stable. Skip unless a genuinely novel quirk surfaces.

---

## 3. Triggers — when to run

Running post-mortem on every completed investigation is wasteful. Most
runs should be deterministically skipped.

### Deterministic skips

- **SCREEN matched** — pattern already known; at most append a snapshot
  if the shape is genuinely new.
- **Clean archetype match, high confidence, no novelty signals** —
  skip, or sample at a low rate for drift detection.

### Deterministic runs

- **Escalate-ambiguous** — highest learning density.
- **Tier 2 judge flagged anything** — consistency/evidence concerns are
  post-mortem input.
- **Low-confidence archetype match** — archetype picked but anchors
  weak or report hedging.
- **Lead gave a `--` that later findings contradict** — lead pitfall
  candidate.

### Agent judgment / sampling

- **Clean resolution later reopened in ticketing** — if invlang surfaces
  it, trigger.
- **Novel hypothesis resolved without matching any archetype** —
  candidate for a new archetype proposal.

The deterministic layer handles the obvious cases. The agent-judgment
layer only fires on the residual, and sampling bounds cost even there.

---

## 4. Structural sketch

**Post-mortem is not a live hook in the investigation.** It runs async
after Stop, against the persisted run dir (`alert.json`,
`investigation.md`, `report.md`, `state.json`, `tool_audit.jsonl`,
`tool_trace.jsonl`).

Two stages, both cheap:

1. **Triage** — cheap (Haiku or deterministic). Reads the run
   artifacts, applies the trigger rules above, and outputs a list of
   `(section, reason)` pairs. Most runs exit here.
2. **Scoped analyst** — one invocation per `(section, reason)` pair,
   with narrow input. Per-section prompts keep output focused and cost
   bounded. Haiku by default; Sonnet only for genuinely hard cases
   (e.g. "propose a new archetype"). Opus never.

**Output is proposals, not writes.** Proposals are dropped into
`runs/postmortem/{run_id}/proposals.md` (or equivalent). The KB is
never edited directly by the agent.

---

## 5. Closing the suggest → review loop

Proposals-only is theater if nobody reviews them. The fix is a CI
pipeline that validates proposed KB changes automatically, so that
human review sees a filtered, pre-vetted set.

### Two-tier validation

**Per-PR (cheap, fast):**

- Mechanical: schema valid, imports resolve, anchor references exist,
  frontmatter well-formed, hook still runs on fixtures.
- Cheap LLM: KB internal consistency — does the proposal contradict
  neighboring docs, introduce terminology drift, or misalign with the
  archetype story?

**Daily (expensive, thorough):**

- Golden-set replay: run the investigation harness against a curated
  set of past tickets with the modified KB and compare outcomes. This
  is the only tier that catches behavioral regressions — a new screen
  indicator, a reordered starter lead, a tightened anchor.

The per-PR tier cannot substitute for the daily tier. A screen rule
that's internally consistent and schema-valid can still be wrong. This
split needs to be named upfront so nobody expects the cheap tier to
catch regressions it can't.

### Golden-set maintenance is also post-mortem's job

The golden set rots — tickets drift, archetypes evolve, new signatures
appear. Letting post-mortem propose edits to the golden set itself
closes that loop. But the thing under test can now also propose
changes to its test, which is a circularity worth guarding:

- **Append** to the golden set — auto-approve (more coverage is
  strictly safer).
- **Edit or delete** golden-set entries — human approval required.

This asymmetry is load-bearing, not a nice-to-have. A relaxed rule
here lets the agent quietly remove the test cases it fails.

### Decoupling review latency from proposal latency

Agent proposes within seconds of a run completing. Per-PR validation
catches obvious breakage immediately. Real sign-off happens on the
daily cycle. Reviewers see proposals that have already passed
mechanical checks and golden-set replay, which makes review a judgment
call on distilled artifacts rather than a slog through raw output.

---

## 6. Open questions / out of scope for this sketch

- **Concrete triage prompt and rules.** Probably a mix of
  deterministic checks (state.json status, judge flags, trace anomaly
  markers) and a short Haiku call for the judgment cases. Worth
  prototyping on one section (playbook screen refinement looks like
  the best first target — highest leverage, cleanest signal) before
  generalizing.
- **Proposal format.** Markdown diff? Structured YAML? Unclear until
  we know what the review UI looks like.
- **Review cadence and ownership.** Who reviews, how often, what's the
  SLA for a proposal sitting in the queue. This is an operational
  question, not a design one, but the pipeline design assumes *some*
  cadence exists.
- **Golden-set initial construction.** Bootstrapping from real past
  tickets vs. synthetic fixtures. Probably both, with real tickets
  carrying more weight.
- **Cost ceiling enforcement.** The structural sketch caps model
  choice (Haiku default, Sonnet for hard cases, Opus never), but a
  per-run and per-day budget guard is worth adding before this goes
  live.

---

## 7. What this replaces

This design supersedes the implicit "post-mortem = summarize each
investigation into the KB" assumption that predates
query-past-investigations. In this design, post-mortem is narrower
(distillation only, not retrieval), cheaper (most runs skip), and
safer (proposals gated by CI and human review, not direct writes).
