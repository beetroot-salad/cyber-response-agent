---
title: Post-mortem stage 1 — lead-pool normalization (extraction → match → propose)
status: todo
groups: post-mortem, knowledge-learning, reliability
---

First post-mortem workstream. Establishes the artifact-extraction →
mechanical-match → LLM-shortlist → proposal pipeline on the artifact
type with the smallest blast radius (ad-hoc leads), so the plumbing is
proven before we move to higher-risk targets (archetypes, env
knowledge).

Scope is **lead pool only**. Archetype proposals, env drift detection,
and CI golden-set replay are explicitly out — they ride on this
scaffolding once it lands. SCREEN-rule refinement is *not* a follow-on
target: SCREEN is being subsumed by the predict-fastpath cache (current
branch), where PREDICT and ANALYZE replay deterministically from the
corpus and GATHER alone executes — making hand-curated screen rules
redundant once the cache populates.

## Context

- Design doc: `docs/design-v3-post-mortem.md` (§4 structural sketch,
  §5 normalization is the precise frame for this task).
- Existing lead catalog: `soc-agent/knowledge/common-investigation/leads/`
  — one dir per lead, `definition.md` with frontmatter (`data_tags`,
  `baseline`), goal/characterization/pitfalls body, and per-vendor
  templates under `templates/{vendor}.md`.
- Existing tag dimensions documented in `leads/TAGS.md` — frontmatter
  is open-ended, expect new dimensions over time.
- Ad-hoc leads land in `investigation.md` under `findings:` with a
  `lead.id` not drawn from the catalog. The `ad-hoc` lead dir already
  exists as the placeholder catalog entry.

## Pipeline (3 steps)

### 1. Extract ad-hoc lead invocations from a completed run

Inputs: `runs/{run_id}/investigation.md` (invlang companion — the
gather envelope's query block is already hydrated into
`findings[*].query_details` by `_hydrate_query_details_from_scopes`,
so we read invlang, not `tool_trace.jsonl`).

**Ad-hoc detection.** Reuse gather's existing check —
`scope.template_exists` in `soc-agent/scripts/handlers/gather.py:1635`,
which dispatches to `gather-composite` in `ad-hoc` mode when the lead
has no `templates/{vendor}.md`. Note this is *broader* than "lead id
not in catalog": it also fires for catalog leads with no
vendor-specific template. The post-mortem default should be the same
broad bar (gather treats both as ad-hoc, so both are normalization
candidates), with extraction recording which sub-case applies
(`catalog_status: missing | template_missing`) so downstream
classification can decide what proposal shape fits.

Output: a list of ad-hoc lead records, each with:

- `lead_id` (the name the agent gave it)
- `catalog_status` (`missing` — no lead dir; `template_missing` — lead
  dir exists but no `templates/{vendor}.md`)
- `query` (the SIEM query / CLI invocation — read from
  `findings[*].query_details.query` in invlang)
- `data_source` (`query_details.system`)
- `result_shape` (was it useful, empty, errored — derived from the
  invlang lead block + assessment)
- `lead_hints` (PREDICT's per-lead prose hint for this lead, keyed by
  `lead_name` in the PREDICT trailer — see `agents/predict.md:232`,
  consumed by `gather.py:1528`. This is the closest thing we have to
  "what the agent was trying to discriminate" without re-deriving
  intent from the hypothesis edge.)

Mechanical step. No LLM. Lives in
`soc-agent/scripts/postmortem/extract_ad_hoc_leads.py` (new dir).

**Open: is `lead_hints` enough context for the LLM tier?** It's prose
the agent chose to hand to gather, so it captures intent at hint
granularity but not the parent hypothesis. If duplicate-classification
quality is poor, the next layer is walking the invlang graph back to
the hypothesis edge that owns the lead. Defer until we see the
mechanical-tier output.

### 2. Compare query against the existing lead catalog

The interesting design question. Two-tier comparison:

**Mechanical tier (cheap, universal):**
- Normalized name match (case, hyphens, plurals) against existing
  lead dir names.
- Query-template substring / token overlap against
  `leads/*/templates/*.md` for the matching `data_source`.
- Frontmatter intersection — same `data_tags` narrows the candidate
  set significantly.
- Output: a shortlist of ≤5 candidate existing leads with similarity
  scores, OR empty (no plausible match → goes straight to "novel").

**Open question — can full comparison be done mechanically?**
For structured query languages (Wazuh search DSL, host-query CLI
flags) the answer is *partly*: tokens, fields, filter shape are
mechanically extractable, but two queries can be semantically the
same with very different surface form (e.g. `srcip="1.2.3.4"` vs.
`agent.ip:"1.2.3.4"` against different vendor adapters). The
mechanical tier should bias toward **recall** (more candidates than
needed) and let the LLM tier resolve.

**Threshold calibration.** Don't pick the
shortlist-cutoff / clear-duplicate / clear-novel thresholds up front.
Build the mechanical tier, run it across the existing run corpus,
eyeball the score distributions and per-ad-hoc candidate lists, then
set thresholds against observed data. Document the chosen numbers and
the corpus they were tuned on so the choice is auditable.

**LLM tier (Haiku, scoped):**
- Only invoked when the mechanical tier surfaces 1+ candidates with
  similarity above a threshold AND below a "clear duplicate"
  threshold — the in-between band.
- Prompt is narrow: "here is the new lead's query, intent, and data
  source; here are 1–5 existing leads from the catalog. Classify as
  duplicate / near-duplicate / novel and pick the canonical lead if
  one applies."
- Never sees the full catalog — only the shortlist.

### 3. Per-classification action

- **Duplicate** — emit a proposal that adds the predict-intent tag(s)
  from this run to the existing canonical lead. No definition rewrite.
  Cheap, append-only.
- **Near-duplicate** — Haiku-judged. Proposal is either "extend the
  canonical lead's templates/pitfalls to cover this variant" or "split
  the canonical lead because the variance is structural" — Haiku
  picks which framing, the proposal is what humans review.
- **Novel** — invoke Haiku to derive `data_tags`, write a one-paragraph
  goal/description, and propose a new catalog entry skeleton. Output
  goes into the proposal file, not directly into `leads/`.

## Output format

`runs/postmortem/{run_id}/proposals.md` — one file per run, sectioned
by classification. Markdown for now (the doc flags proposal format as
an open question; pick the simplest thing that lets a human review).

Never edits `leads/` directly. The CI tier (future task) reads from
`proposals.md`.

## Trigger

Spawn detached subprocess from `stop_handler.py` after the existing
`investigation_summary.py` + `close_ticket_action.py` steps. Don't
block parent — agent termination must not wait on KB analysis. Skip
the spawn entirely if the run produced no ad-hoc leads (cheap
deterministic check on `investigation.md` reusing the same
`scope.template_exists` heuristic).

Failure discipline: fail loud and keep logs. The detached subprocess
writes stdout/stderr to `runs/postmortem/{run_id}/run.log` and on
unhandled exception leaves a `proposals.failed` marker alongside the
log. No silent recovery, no retries from the parent. Crash recovery
(restart-on-boot, orphan-detection) is a follow-on — see
`tasks/postmortem-crash-recovery.md` (backlog).

## Out of scope (deferred to follow-on tasks)

- Archetype proposals (see `tasks/invlang-postmortem-loop.md` —
  hypothesis promotion is part of this surface)
- Env drift detection
- CI per-PR validation tier
- Golden-set replay harness
- Cross-signature regression diffing
- Triage layer (§4 stage 1) — this task only implements normalization
  for one artifact type; the wider triage that decides which sections
  to update across a run lands once we have proven plumbing

## Acceptance

- Script runs against any existing `runs/{run_id}/` and produces a
  proposals file (or no-op exits if no ad-hoc leads).
- Mechanical tier surfaces ≥1 candidate for at least one ad-hoc lead
  in the existing run corpus where a real catalog entry plausibly
  matches (calibration check, not pass/fail).
- Haiku tier never sees more than ~5 candidates per artifact.
- Detached subprocess from `stop_handler.py` doesn't measurably delay
  Stop completion.
- Smoke-tested by replaying 2–3 historical runs and eyeballing
  proposals for sanity.
