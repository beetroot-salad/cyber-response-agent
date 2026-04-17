---
name: invlang
description: Continue the investigation-language pilot — an iterative experiment to evolve the structured companion schema proposed in `docs/investigation-language.md`. Captures the experimental method, version deltas, current locked state, and pending work so a fresh session can pick up without rebuilding context. Project-level dev skill — not part of the production soc-agent plugin.
argument-hint: "[status | next | method | launch <case>]"
---

# Investigation Language — Pilot Experiment Skill

This skill is for continuing iterative design work on the **investigation
language** — the structured companion file proposed in
`docs/investigation-language.md`, §3. The pilot lives under
`docs/experiments/investigation-language-pilot/`.

**Working directory assumption.** All paths are relative to the repo root (mounted at `/workspace/` in the devcontainer).

---

## Current state (as of last session)

**Phase shift.** The pilot moved past writability testing (Haiku compliance)
to **fidelity and retrieval**. Three evaluation criteria now drive revisions:
(1) can weak models write the schema, (2) can it carry real-case information
without loss, (3) can future investigations retrieve it as RAG input.

**Locked baseline:** v2.2 (fully green on A.1 Haiku round; the last version
to hit 100% writability).
**In flight:** v2.3 (eight material changes, case-driven; reference-walked
against A.1 and two real cases, not yet Haiku-regression-tested).
**Current focus:** write the **query/distillation script** next. This is
where v2.3's "push retrieval load to the distiller" bet pays off or
doesn't. See `docs/experiments/investigation-language-pilot/case-a4/retrieval-needs.md`
for the 10 retrieval needs (R-1 through R-10) the script must cover.

**Status table:**

| Version | Status     | Haiku pass rate | Key changes from prior |
|---------|------------|-----------------|------------------------|
| v1      | archived   | 16/27 (59%)     | original condensed spec |
| v2      | archived   | 25/27 (93%)     | journal form, discrimination-level rule, implicit defaults, host-as-attribute, literal text match |
| v2.1    | archived   | 27/27 (100%)    | concerns unified, drop source_lead/execution/outcome.status, intended_hypothesis_set scope-only, rule 11 mechanical leads stay in data source, rule 6 negative example |
| v2.2    | **LOCKED** | 27/27 (100%)    | prediction IDs (ID-based rule 6), `type` rename, `observations` rename, authority rename + clarification, parent_vertex one-hop rule, optional `lead.observes` |
| v2.3    | **DRAFT**  | not yet Haiku-tested | type vocab cleanup (endpoint/identity/storage/database/network-device), action-as-vertex via `command`+`targeted`, `trust_anchor_result` 4-field verdict, hierarchical hypothesis IDs, lean methodology, `ceiling_test`, placeholder vertices + `identified_as`, distiller projections |

**Case coverage:**

| Case | Case kind | v2.3 artifact | Purpose |
|------|-----------|---------------|---------|
| A.1 shell-in-container | synthetic | `reference-v2.3.md` | Regression — does v2.3 still translate the locked green case? Surfaced D1, D4 as spec bugs. |
| A.4 S3 list burst | synthetic | `case-a4/walk-a4.yaml` + `retrieval-needs.md` | Retrieval-fitness — can 10 realistic retrieval needs be served from the schema? |
| rule-5710 SSH invalid-user | **real SIEM data** | `case-real-rule5710/companion-v2.2.yaml` + `fidelity.md` | Information-fidelity — what does a real investigation lose when compressed to companion form? Motivated trust_anchor_result + ceiling_test. |

**Before any further Haiku runs**, the query script should be written
and exercised against the existing companions. The outstanding question
isn't "can Haikus write v2.3" — it's "does v2.3 retrieve well enough to
feed the next investigation?"

---

## The experimental method

A single pilot round has four arms, run in parallel where possible:

1. **One Sonnet reference walk** of the target case, with running
   commentary on friction points (pauses, schema fights, backtracks).
   The commentary is the primary qualitative data — not the YAML.
2. **Three independent Haiku runs** on the same case with identical
   inputs and no cross-context. Three runs (not one) control for
   first-mistake-contextualizes-followups failure modes.
3. **Comparison writeup** tabulating validator compliance per arm,
   classifying failure modes as systematic (3/3), partial (2/3), or
   one-off, and mapping Haiku errors to reference friction points.
4. **Verdict and recommended spec changes** for the next iteration.

**Inputs given to every arm, identical:**

- `alert.json` — synthetic alert for the case
- `spec-condensed-v{version}.md` — condensed schema (~500 lines, not the
  full `investigation-language.md`). Condensed is realistic — it's what
  an agent would see at runtime. Full doc is only allowed as a fallback
  if the condensed is insufficient.
- `retrieval-sim-v{version}.yaml` — canned projection retrieval results.
  Pre-populates "what prior runs know" so the pilot measures write
  burden, not retrieval correctness.

**Haikus must not read other arms' artifacts.** The prompt explicitly
lists forbidden files (other references, other Haiku YAMLs, comparisons,
older spec versions). This is the cleanest way to prevent cross-context
contamination.

**Launch Haiku agents in parallel via the Agent tool**, `model: haiku`,
`run_in_background: true`, one Agent call per run. All three in a single
message so they execute concurrently. Write the Sonnet reference in
foreground while they run.

**The prompts emphasize two things:**
1. What changed from the previous version (Haikus don't have v1 context)
2. Which rules to watch carefully (the ones that tripped prior rounds)

**Sonnet reference format:** markdown with three parts:
- **Part 1 — friction log:** numbered pauses (P1, P2, ...), classified as
  disappeared-from-v(n-1), remaining, or new. Count total pauses as a
  trend metric.
- **Part 2 — the companion:** one YAML code block with the walk.
- **Part 3 — closing observations:** line count delta, write time,
  predictions for Haiku outcomes, one-line verdict.

**Comparison writeup format:**
- Headline in one paragraph
- Structural compliance table (per change, per arm)
- Validator rule compliance table (all rules, per arm)
- Per-Haiku notes (strengths, deviations, semantic vs literal issues)
- Systematic / partial / one-off classification with count
- Qualitative observations (self-reports, writing speed, line counts)
- Recommendations for the next iteration, ranked by impact

---

## File map (under `docs/experiments/investigation-language-pilot/`)

**Case inputs:**
- `alert.json` — synthetic Falco shell-in-container alert for A.1
- `spec-condensed.md` / `-v2.md` / `-v2.1.md` / `-v2.2.md` / `-v2.3.md` — spec iterations
- `retrieval-sim.yaml` / `-v2.yaml` — v1 / v2+ retrieval sim

**v1 / v2 / v2.1 artifacts** (archived):
- `reference.md`, `haiku-{1,2,3}.yaml`, `comparison.md`
- `reference-v2.md`, `haiku-v2-{1,2,3}.yaml`, `comparison-v2.md`
- `reference-v2.1.md`, `haiku-v21-{1,2,3}.yaml`, `comparison-v2.1.md`

**v2.2 artifacts** (last writability-tested version):
- `reference-v2.2.md`, `haiku-v22-{1,2,3}.yaml`, `comparison-v2.2.md`

**v2.3 artifacts** (in-flight; case-driven):
- `reference-v2.3.md` — A.1 regression walk under v2.3, surfaced D1/D4 spec bugs
- `case-a4/` — A.4 S3 list burst hard-case walk + retrieval-needs analysis
  - `alert-a4.json`, `walk-a4.yaml`, `retrieval-needs.md`
- `case-real-rule5710/` — real rule-5710 investigation translated to companion
  - `alert.json`, `investigation.md`, `report.md`, `state.json`, `conclusion_checks.json`
    (the original run artifacts, copied for reference)
  - `companion-v2.2.yaml` — the translation
  - `fidelity.md` — the fidelity report (features lost, features bent)

**Canonical spec:** `docs/investigation-language.md` — the original
980-line design proposal. Pilot work refines §3 (schema). §4
(retrieval projections) and §5 (query script) are the next surfaces
the pilot will touch.

---

## Version history — key deltas

### v1 → v2 (three systematic errors fixed structurally, not incrementally)

Problem profile in v1: all three Haikus failed to relocate hypotheses,
all three paraphrased `matched_prediction_text` instead of literal
match, two of three invented a `runs_in container → host` catalog
relation, and all three attached hypotheses to v-001 (the alert vertex)
regardless of depth.

v2 changes:
1. **Journal form** — four top-level keys (prologue, hypothesize,
   gather, conclude); each gather entry is a self-contained lead block
2. **Implicit defaults** — fields at default are omitted
3. **Discrimination-level rule** — run mechanical leads first,
   hypothesize at the deepest materialized vertex. Replaces relocation
   machinery entirely.
4. **Host as attribute** — host context lives on the container vertex
5. **Rule 6 strict literal copy-paste** — added explicit warning

Result: 3/3 Haikus correctly deferred hypothesizing, 2/3 passed rule 6
strictly (up from 0/3), but 2/3 materialized a session vertex in the
mechanical scope lead where the execve feed can't actually see it.

### v2 → v2.1 (one new issue fixed, metadata trimmed)

v2.1 changes:
1. **`intended_hypothesis_set`** required only on materialize/trust
2. **Drop `execution` block** (dispatched_via, duration_ms were noise)
3. **Drop `outcome.status`** (redundant with `failure_reason` presence)
4. **Drop `source_lead` field** (structural position is authoritative)
5. **Unified `concerns` field** (replaces `pitfalls` / `data_quality_note`)
6. **"Mechanical leads stay within their data source"** — new spec rule
7. **Rule 6 negative example** in §12

Result: 3/3 Haikus pass all 11 validator rules on first pass. First
pilot round where every arm is clean. One remaining soft issue: Haiku-
v21-3 passed rule 5/6 literally but cited a list entry that didn't fit
the observation (semantic mismatch within literal match). Not a
validator violation, but the subtler form of the rule 6 failure mode.

### v2.1 → v2.2 (structural fix for rule 6's residual; small renames)

v2.2 changes (six):
1. **Prediction IDs** — predictions and refutation shapes get `id`
   fields (`p1`, `p2`, `r1`, ...). Resolutions cite by
   `matched_prediction_ids: [p1, ...]` / `matched_refutation_ids: [r1, ...]`
   instead of literal text. Rule 6 becomes a mechanical ID-set check.
   Eliminates the paraphrase failure mode and decouples predictions
   from specific telemetry sources.
2. **`abstract_type` → `type`.** Same enum, shorter field.
3. **`outcome.produced` → `outcome.observations`.** Clarifies semantics.
4. **`anchor-backed` → `authoritative-source`** + explicit spec language:
   authority describes observational reliability, not legitimacy.
   `trust_root` is a walk-termination heuristic, not a certification.
5. **Optional `lead.observes`** field declaring which prediction IDs
   this lead can test. Rule 12 enforces the subset when present.
6. **`parent_vertex` one-hop clarification.** The `parent_vertex`
   inside `proposed_edge` describes the immediate upstream, not a
   distant ancestor.

**Result:** 3/3 Haikus pass cleanly on A.1 regression. v2.2 locked as
the last writability-verified version.

### v2.2 → v2.3 (retrieval-aware; case-driven)

Eight material changes, most **simplify** rather than expand. The
driving question shifted from "can weak models write this" to "can
real investigations preserve their reasoning in it, and can future
investigations retrieve it as RAG input." Motivating cases: the
rule-5710 fidelity exercise and the A.4 retrieval-needs walk.

1. **Drop `canonical` from hypothesis schema** — post-ingestion concern
   imposed at write time. Distiller can recompute.
2. **Hierarchical hypothesis IDs for refinement chains** — `h-001` →
   `h-001-001` → `h-001-001-001`. Lineage encoded in the ID; no
   `derived_from` field needed. Replaces primitive chaining in names.
3. **Lean hypothesis methodology** — hypotheses describe the immediate
   next discrimination question with 1-2 predictions; refine into
   children only when evidence forces it. Pre-committing to a deep
   narrative fragments the retrieval space.
4. **Type vocabulary cleanup.** `endpoint` replaces `host`/`device`/
   `remote-endpoint`; `identity` replaces `user`; new `storage`,
   `database`, `network-device`. Vendor specifics live in
   `attributes.kind`. `anchor-source` deprecated.
5. **Action-as-vertex via `command` + `targeted` relation.** SIEM-observed
   actions model as `command` vertices with a new `targeted: command →
   endpoint|storage|database|identity|file|container|network-device`
   edge. Uniform treatment of CloudTrail, kube-audit, pam-audit,
   sshd-audit. **Control-plane CRUD is uniform** — reads, writes,
   creates, deletes, updates all start as `command`; target entity
   promotes lazily when later reasoning references it.
6. **`outcome.trust_anchor_result`** on trust-mode leads. 4 writer
   fields: `{anchor_id, kind, result, authority_for_question}`. No
   `structured_fields` dict (the case-a1 translation showed every
   field was already in observation attributes). Substantive anchor
   returns live in observations as graph entities.
7. **`conclude.ceiling_test`** for severity-ceiling termination.
   `{kind, subject}`. Required when `termination.category:
   severity-ceiling`. Closes A.4 R-8.
8. **Distiller projects, not schema fields.** The schema does NOT
   carry `trace`, `prediction_status_at_termination`,
   `escalation_handoff`, `correlated_with`, `final_weight`,
   `mandatory_adversarial`. These are post-hoc projections computed
   at case close by the query/distillation script.

**Plus three design refinements landed in §3 post-review:**
- **Lifecycle-vs-action rule** (§3 subsection): lifecycle observations
  materialize persistent entities (model as vertex + edge verb); action
  observations are audit-log invocations (model as `command` + `targeted`).
  Rule is purely observational — does not depend on which lead or
  hypothesis the observation is being offered against.
- **Placeholder vertices** for lifecycle observations with unknown
  endpoints (FIM-without-writer). `placeholder: true` on the vertex.
  Append-only-preserving late attribution via new `identified_as`
  relation — never mutate the placeholder.
- **Don't throw data away** rule for dual-shape events. Never actively
  query a second source; never suppress data already in the envelope.
  If `kubectl exec` lands both the kube-audit record and the Falco
  execve event with distinct useful attributes, model both.

**Status:** v2.3 spec + A.1 reference walk + two real cases complete.
**Not yet Haiku-regression-tested** — the current open question is
retrieval fitness (via the query script), not writability.

---

## Key design decisions (reconstructed context)

Surfacing the reasoning so you don't re-derive it.

- **Journal form over flat collections (v2):** the companion is a log
  of a walk, not a graph snapshot. Time-ordered per-lead blocks match
  how agents write and how humans read. Distiller can flatten to
  collections at ingest.
- **Discrimination-level rule replaces relocation (v2):** hypotheses
  live at the deepest materialized vertex where explanations fork. No
  relocation machinery. Run mechanical scope leads first if the
  immediate parent is opaque.
- **Implicit defaults over explicit (v2.1):** every optional field has
  a default and is omitted when at that default. Less writing, less
  cognitive load, no loss of information.
- **Unified `concerns` replaces `pitfalls` / `data_quality_note` (v2.1):**
  same concept under different names in v2. Unified is cleaner; applies
  to vertices, edges, hypotheses, and leads.
- **Mechanical leads stay within data source (v2.1 rule 11):** a scope
  lead's observations are limited to what the underlying telemetry
  directly observes. Causally-implied vertices (sessions from execve
  context, users from kube-audit presence) wait for a subsequent
  trust lead.
- **Prediction IDs replace literal text match (v2.2):** predictions are
  source-agnostic world-state claims with stable IDs. Resolutions cite
  by ID. Rule 6 is mechanical ID-set membership. Paraphrase is no
  longer a failure mode.
- **Authority is observational, not legitimacy (v2.2):** the original
  "anchor" concept conflated "source reliably observed this" with
  "action is legitimate." v2.2 renames `anchor-backed` to
  `authoritative-source` and makes the distinction explicit. Legitimacy
  is always an agent-level derivation.

---

## Deferred / future thoughts

Don't forget these, but don't implement them without the case that
motivates them.

- **First-class observations.** Proposed and declined. Current schema
  folds observations into lead blocks. If a case forces multi-source
  reconciliation the current `citations` / `concerns` pattern can't
  express, prototype first-class observations then.
- **Source manifest for per-question trust.** Partial coverage now
  lives in `trust_anchor_result.authority_for_question` as a
  per-(anchor,question) field. A full source manifest (which source
  is authoritative for which question, at what resolution) is a
  larger piece of work that needs real corpus data.
- **Lead `observes` expansion into retrieval.** At scale the distiller
  could aggregate `observes` across leads to populate a
  `prediction_coverage_index` — "for prediction shape X, which leads
  can test it in this environment?" Useful for lead selection. Not
  urgent.
- **Semantic validator (Haiku judge) for resolutions.** v2.2's ID
  match closes the paraphrase failure mode literally, but an agent
  can still cite an ID that doesn't fit the observation. A Haiku
  judge on `++`/`--` resolutions could catch this. Defer until a
  case shows it's needed.
- **Anchor-manifest schemas for distiller projection.** v2.3's
  `trust_anchor_result` is 4 writer fields. The distiller needs
  per-anchor schemas in `anchor_manifest.yaml` to normalize
  anchor returns into retrieval indices. The manifest does not
  exist yet — it will need to be built alongside the query script.

---

## How to continue

Assume you're in a fresh session. The user invokes `/invlang`. Here
are the common next actions.

### Status / orientation

Read in this order:
1. **This skill file** — current state, phase, open questions.
2. **`spec-condensed-v2.3.md` §A** — the eight changes from v2.2.
3. **`reference-v2.3.md`** — the A.1 walk under v2.3 (friction log + worked YAML).
4. **`case-real-rule5710/fidelity.md`** — what real investigations lose when compressed.
5. **`case-a4/retrieval-needs.md`** — the 10 retrieval needs driving the query script.

### Write the query/distillation script (current priority)

v2.3's distiller-not-schema bet needs to be validated. The script
consumes completed v2.3 companions and projects retrieval indices
the writer is not required to type. Open design questions:

- **Input shape.** Glob of `companion-v2.3.yaml` files, or a fixed
  pilot directory?
- **First needs to cover.** Recommend R-1 (trace recovery),
  R-3 (trust-anchor verdict lookup), R-7 (termination category +
  ceiling test) — they exercise the three main projection classes.
- **Output shape.** JSON for machine consumption + a human-readable
  table for spot-checking.
- **Where it lives.** `docs/experiments/investigation-language-pilot/scripts/query.py`
  is the pilot-local home. Promote to `soc-agent/scripts/` only once
  it earns production use.

The script's job is to answer: "given an incoming alert, which prior
investigations' conclusions should the agent see?" Not to build a
semantic search — just to compute the projections the A.4 walk
identified as missing.

### Regression-check v2.3 on A.1 with Haikus (deferred)

Writability testing is deprioritized. The open question is retrieval
fitness, not write burden. Run Haiku regression only if:
- A spec change is proposed that plausibly affects writability
- Or the query script surfaces evidence that writers are typing
  the schema inconsistently

### Move to a harder case

Two real cases are already in hand (rule-5710, A.4). Additional cases
earn their keep only if they exercise a mechanism neither of those
touched. A.3 (sudo on production, trust-chain promotion) remains the
strongest synthetic candidate if real-data cases aren't available.

### Iterate on v2.3 or later

Case-driven revisions (like v2.2→v2.3) are preferred over cohort-
based rounds. The principle: a spec change should trace to a specific
case that surfaced the need. Scope creep warning applies — v2.3 is
eight changes + three §3 refinements, already large. Future versions
should bundle fewer changes.

---

## Argument handling

When invoked as `/invlang <arg>`:

- **`status`** (default if no arg) — summarize the current state: latest
  locked version, in-flight version, next experiment, any open
  questions. Read from this skill + the latest comparison doc.
- **`next`** — recommend the next concrete action. Usually "regression
  check v2.2 on A.1" or "launch A.4 pilot under v{locked version}".
- **`method`** — print the experimental method section verbatim for
  a quick refresher.
- **`launch <case>`** — set up a new pilot round. Walks through the
  steps: create alert + retrieval sim, draft Sonnet reference, launch
  Haiku runs in parallel, write comparison. Ask the user to confirm
  case + version before spending tokens on Haiku runs.

If the arg is unclear or ambiguous, default to `status` and ask what
the user wants.

---

## Key files to read first in a fresh session

Ordered by signal density:

1. **`docs/experiments/investigation-language-pilot/comparison-v2.1.md`**
   — current state, scorecard, recommendations. The single most
   informative file.
2. **`docs/experiments/investigation-language-pilot/spec-condensed-v2.1.md`**
   — the locked spec. Read §A (delta from v2) for the short version.
3. **`docs/experiments/investigation-language-pilot/spec-condensed-v2.2.md`**
   — the in-flight draft. Read §A for deltas from v2.1.
4. **This skill file** — context, method, open questions.

Everything else is historical. Consult if you need to verify a claim
about earlier iterations; skip otherwise.
