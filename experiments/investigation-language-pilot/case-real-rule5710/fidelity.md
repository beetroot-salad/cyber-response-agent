# Fidelity Report — Real Rule-5710 Investigation in v2.2

## Headline

Partial fit. The v2.2 schema carried the investigation's core structure faithfully — hypotheses, multi-loop gather, weight transitions, and termination all mapped without fundamental breakage. But six investigation features required genuine schema bending, and four fell on the floor entirely, leaving load-bearing context either stranded in prose reasoning strings or simply absent. The most important single loss is the structured trust-anchor result: the `approved-monitoring-sources` anchor is the investigation's central pivot (it simultaneously confirms identity and refutes the fast-path archetype), and v2.2 has no slot that captures both facts in a queryable way. The second important loss is the SCREEN phase: modeling SCREEN leads as loop:0 is a workable hack but the schema's append-only journal form was not designed for a preliminary pass that can both confirm and short-circuit the main loop.

---

## What fit cleanly

- **Hypothesis weight transitions.** `weight_history` carried the loop-by-loop weight changes for all five hypotheses cleanly. `?monitoring-bait-triggered` holding at `+` across both loops, `?monitoring-host-compromise` holding at `-`, `?internal-credential-guessing` and `?monitoring-loop-broken` moving to `--` in loops 1 and 2 respectively, and `?compromise-followup` reaching `--` in loop 1 — all expressed without ambiguity using the weight enum and per-lead resolution blocks.

- **Multi-loop gather with `loop:` discriminator.** The `loop:` field on lead blocks mapped naturally to the two-loop structure. Ordering SCREEN leads as loop:0, loop-1 leads with loop:1, and loop-2 leads with loop:2 preserves chronological sequence without mutations.

- **The failed lead (rc=127).** `outcome.failure_reason` in l-008 captured the adapter error cleanly. The enum was a string field so no vocabulary gap.

- **Predictions as source-agnostic world-state claims.** The investigation's predictions (hypothesis-level prose about what would be observable if each hypothesis held) translated into `predictions[].claim` strings without distortion. The ID system (p1, p2, …) replaced ad-hoc prose labels cleanly.

- **Strong-weight `--` resolutions with `matched_refutation_ids`.** `?internal-credential-guessing` and `?compromise-followup` each had directly-met refutation shapes (all-sentinel usernames; zero successful auths) backed by siem-event authority. Rule 5 (refutation IDs non-empty, exist in hypothesis) and rule 4 (strong-weight cites strong-authority edge) were both satisfiable.

- **`conclude.termination.category: exhaustion-escalation`.** The termination category matched the investigation's explicit rationale: all leads exhausted, no archetype match, adversarial hypothesis still live but at `-` not `--`, analyst judgment required.

- **`conclude.disposition: unclear`.** The `inconclusive` label in the original maps acceptably to `unclear`, the closest v2.2 enum member, with the caveat noted below.

- **`lead.concerns` for tooling gaps.** The deny-list blocks (`/opt/workloads/`, `/etc/cron.d/`) and `process-list` limitations (names only, no argv/parent) fit naturally into `lead.concerns` and `vertex.concerns` fields without needing a separate schema slot.

- **`ceiling_rationale`.** The conclude block's `ceiling_rationale` string provided a clean landing zone for the tooling-gap summary that explains why `--` was unachievable on `h-003`.

---

## What required bending the schema

- **Refuting trust lead.** The `approved-monitoring-sources` anchor is modeled as `mode: trust` (l-002) because it consults an org-authority anchor. But trust mode in v2.2 is designed for confirmation paths: it sets `trust_root_reached`, and the worked example only shows confirmation outcomes. Here the anchor confirmed the identity triple but refuted the cadence, producing a refutation rather than a confirmation. The schema has no `trust_root_reached: null + outcome: refuted` first-class representation. We did not set `trust_root_reached` (correct — anchor was not confirmed), but the fact that this was a trust-mode lead that produced a negative result has no dedicated expression. The resolution block on l-002 encodes the outcome in reasoning strings, which is queryable only by prose search. The structural signal that "a trust lead ran and refuted rather than confirmed" is lost.

- **SCREEN phase modeled as loop:0.** v2.2 has no SCREEN slot. Modeling SCREEN leads as `loop: 0` is a pragmatic hack: it preserves ordering and marks them as pre-loop-1, but it collapses the SCREEN phase's semantic purpose (fast-path matching against playbook archetypes) into the same lead-block form as regular evidence gathering. The SCREEN's `no_match` outcome — which is what forced the full investigation — is not expressible as a schema-level fact; it lives only in the reasoning prose and in the absence of a `matched_archetype` in conclude.

- **Archetype fit check per-loop.** The investigation has explicit archetype fit checks at the end of each ANALYZE block (loop 1 and loop 2): the agent verifies which playbook archetype (if any) matches the accumulated evidence and concludes none do. v2.2 only has `matched_archetype` at conclude time. The per-loop archetype scan is a first-class reasoning step in the investigation but has no schema slot; it is distributed across `conclude.termination.rationale` and `ceiling_rationale`. This is tolerable for a two-loop case but would be increasingly lossy in longer investigations where the archetype fit check changes across loops.

- **Tooling gaps as load-bearing escalation rationale.** The deny-list blocks are load-bearing: they are the primary reason the investigation cannot advance `h-003` to `--` and must escalate. `lead.concerns` captures the gap correctly per lead, but the cross-lead summary (these two gaps together prevent a definitive verdict) lives only in the `conclude.ceiling_rationale` string. There is no schema mechanism to mark a concern as `load-bearing: true` or to link a specific gap to the termination decision structurally. A retrieval query asking "what tooling gaps drove this escalation?" would need to parse prose.

- **`?compromise-followup` as a mandatory adversarial hypothesis.** v2.2 has no `mandatory: true` or `adversarial: true` flag on a hypothesis. The mandatory-adversarial character is captured only in `h-005.concerns`. This means a retrieval system cannot mechanically distinguish "must hold until explicitly refuted" hypotheses from ordinary ones, and a validator cannot enforce the rule that `status != refuted` until `after: "--"` is achieved.

- **The failed lead's "covered by another lead" reasoning.** `outcome.failure_reason` captured the adapter error (rc=127). But the companion reasoning — "not retried because other leads cover the same question" — has no slot in the outcome block. It is embedded in the `failure_reason` string, which means a retrieval system cannot mechanically distinguish "failed and not retried because irrelevant" from "failed and not retried because covered" from "failed and not retried because no time."

- **`connected_to` as the closest relation for a failed SSH authentication attempt.** The relation catalog has no `attempted_auth_to` or `authentication_failed` relation. `connected_to` from the session vertex to the target host is the least-bad choice, with `status: refuted` encoding the failure. But `connected_to` implies a socket-level connection, and the real observation is an application-level authentication attempt that failed before a session was established. The edge meaning is slightly distorted.

---

## What fell on the floor

- **Structured trust-anchor result.** The original report has a `trust_anchors_consulted:` block in the frontmatter with structured fields: `anchor`, `kind`, `result` (confirmed | refuted), and `citation` (a prose string explaining the confirmation or refutation logic). v2.2 models anchors as leads, which puts the anchor result in `outcome.observations.vertices[].attributes` and `resolutions[].reasoning`. The structured "what did each anchor say, and why" summary is not reconstructable from the schema without parsing unstructured strings. A future investigation asking "has approved-monitoring-sources ever returned a refutation for this source?" could not be answered by a structured field query — it would require full-text search over reasoning strings.

- **Investigation `trace` field.** The original report has a single-line compressed investigation trace: `screen(...)→loop1(...)→loop2(...)→escalate:inconclusive`. This is not a derivable YAML field; it requires a projection pass over the companion that follows lead sequence, reads resolutions, and serializes as a path expression. v2.2 has no `trace` projection or field. The trace is load-bearing for human review (it is the first thing an analyst reads) and for similarity search (comparing traces across investigations to find pattern matches). Its absence from the schema means it must be either re-derived on every read or stored outside the companion.

- **The 9-hour monitoring gap.** The investigation explicitly notes a 9-hour gap in the 24h baseline (2026-04-13T17:00–2026-04-14T01:00) and flags it as "unexplained, noted for completeness, not load-bearing." This is an investigation-level observation that is neither a hypothesis, a lead, nor a vertex/edge. It is a data-quality annotation on the 24h window result. v2.2 has `lead.concerns` and `vertex.concerns` for data-quality notes, and the gap is captured in the v-012 attributes. But the explicit annotation that it is "not load-bearing for the verdict" — which matters for a future analyst re-reading the case — has no structured slot. It lives only in the concern string.

- **Wazuh rule 5712 non-firing observation.** The report notes: "Wazuh rule 5712 (SSH brute force composite) did NOT fire despite 6 attempts in 5 minutes." This is a detection-gap observation — a meta-observation about the SIEM's own rule coverage, not about the alert or the hypotheses. v2.2 has no slot for detection-gap observations. They are not vertices, not edges, not hypotheses, not leads. This kind of observation has significant operational value (it may indicate a tuning gap worth filing with detection engineering) and is currently stranded in the report's Observations section.

---

## What v2.2 added that the original investigation didn't use

- **Prediction IDs (p1, p2, …).** The original investigation has prose hypotheses with prose predictions in a natural-language paragraph (e.g., "?monitoring-bait-triggered: only sanctioned sentinel usernames, burst = single discrete event, no successful login, …"). The predictions are never cross-referenced by ID in the investigation log — the agent writes assessments in narrative form, not as ID citations. Translating to v2.2 required inventing IDs for predictions the original never named. This adds ceremony that the original did not use, and the ID system imposed a decomposition discipline the original did not follow: some predictions were compound (e.g., "p1 OR p2 OR p3 OR p4" for h-003) which v2.2 has no OR-clause syntax for.

- **`refutation_shape` as separately enumerated records.** The original investigation mixes refutation conditions into reasoning prose, not into a separate structured list. The refutation shapes were extractable by reading carefully, but they were not expressed as a first-class list in the original. Adding them as `refutation_shape[].claim` imposed a decomposition discipline (each refutation condition as a separate named record) that the original didn't require. For h-003 (?monitoring-host-compromise), where refutation is collective and conditional rather than any single observable, this created awkward modeling (the refutation is a conjunction of absences, none of which alone is a `--`).

- **`proposed_edge` / `parent_vertex` per hypothesis.** The v2.2 schema requires a `proposed_edge` with a `parent_vertex` for each hypothesis — encoding the causal graph shape the hypothesis implies. The original investigation's hypotheses are framed as behavioral explanations ("the bait workload was triggered") not as graph edges. Translating to proposed_edge required inferring a causal graph topology from narrative text, introducing an interpretation layer that was not in the original.

- **`intended_hypothesis_set` on trust/materialize leads.** The original investigation does not explicitly bind leads to hypothesis sets — leads are chosen for their discriminating power but not formally linked to a hypothesis ID set. The `intended_hypothesis_set` field imposed a formal binding that required inferring which hypotheses each lead was targeting.

- **`outcome.observations` vertex/edge records for SIEM query results.** The schema requires materializing SIEM results as vertex/edge records in the outcome block. The original investigation captures SIEM results as raw observations in prose (e.g., "10 events total, all rule 5710, 5 distinct usernames"). Translating to vertices and edges required representing an event-set as an `anchor-source` vertex with attributes — a pragmatic but slightly artificial mapping: SIEM query result sets are not naturally graph vertices.

---

## Information density comparison

- **Source investigation.md:** 271 lines of prose (including phase headers, reasoning blocks, raw observations, assessment YAML, predictions, and a CONCLUDE section).
- **v2.2 companion.yaml:** approximately 440 lines of YAML (including comments noting schema bends).
- **Without the translation-note comments:** approximately 370 lines of YAML.

**Information ratio:** The YAML is approximately 36% longer than the source prose (comments included) or ~37% longer (comments excluded). The YAML is denser per byte of structured data — but denser in a different way: it carries schema scaffolding (IDs, field names, enum values) that the prose achieves implicitly. The information content is similar but the YAML trades readability for queryability.

**What prose carries that YAML loses:**
- Narrative coherence: the investigation reads as a story with reasoning visible at a glance; the YAML requires traversing ID references to reconstruct the reasoning chain.
- Embedded caveats: the original prose says "this is circumstantial, not authoritative" in the assessment for h-002 in a way that is semantically located relative to the weight — in YAML, the same caveat moves to a `concerns` string that is structurally adjacent but not semantically coupled to the weight assignment.
- The `trace` field (one line in the original report, zero lines in the companion).
- The "For Analyst" section: the analyst-facing summary, suggested next steps, and "what we don't know" enumeration. These are entirely outside the v2.2 schema scope.

**What YAML carries that prose loses:**
- Machine-queryable hypothesis weights and their per-lead provenance.
- Structured prediction IDs enabling mechanical refutation checking.
- Authority fields on every edge, enabling audit trails for strong-weight resolutions.
- Loop numbers enabling temporal sequencing of leads without reading prose.

---

## Retrieval implications

### Questions a future similar-alert investigation would want to ask

1. **"Has an approved monitoring source ever produced a burst shape that refuted the monitoring-probe archetype but was later determined benign?"**
   - Fields needed: `conclude.matched_archetype` (null, ruling out confirmed archetypes), `conclude.disposition` (unclear / benign), the anchor lead's result.
   - Structured? `matched_archetype: null` and `disposition: unclear` are queryable. But the anchor result (refuted the monitoring-probe shape) is in `v-006.attributes.cadence_check` — a string, not a structured boolean. A retrieval system would need to either parse that string or add a field like `anchor_result: refuted` at the lead level.

2. **"Have we seen a sub-200ms multi-sentinel burst from an internal monitoring host before, and what was the disposition?"**
   - Fields needed: `v-008.attributes.burst_detail.duration_ms`, `v-008.attributes.burst_detail.username_cycling`, `conclude.disposition`.
   - Structured? `duration_ms: "< 200"` is a string, not a number — not range-queryable. `username_cycling: true` is a boolean. This is partially structured but the burst detail is nested inside an anchor-source vertex's attributes, which is not a first-class schema slot.

3. **"Which investigations were escalated because of tooling deny-list gaps, and what was the specific gap?"**
   - Fields needed: `conclude.ceiling_rationale` (a prose string) or `lead.concerns` across all leads.
   - Structured? Not at all — the tooling gap is only in prose strings. A structured field like `tooling_gaps: [{path: "/opt/workloads/", operation: "file-stat", blocked: true}]` would make this queryable.

4. **"What was the approved-monitoring-sources anchor's result for this (srcip, srcuser, target) triple?"**
   - Fields needed: The anchor result lives in `v-006.attributes.lookup_result` and `v-006.attributes.cadence_check` in l-002's outcome observations.
   - Structured? `lookup_result: "identity-triple-approved"` and `cadence_check: "FAILED — ..."` are strings. The identity-triple is not stored as a structured triple (three separate fields for srcip, srcuser, target) — it would need string parsing to extract. The original report's `trust_anchors_consulted:` block was more queryable than the companion's encoding.

5. **"Has monitoring-host ever shown compromise indicators (non-5710 alerts) in the 4h window around a 5710 burst event?"**
   - Fields needed: `v-009.attributes.non_5710_alerts`.
   - Structured? `non_5710_alerts: 0` is an integer — queryable. This one is well-structured.

### Summary assessment

Key facts that drive retrieval (burst shape, anchor result, tooling gaps, escalation reason) are either in prose strings or nested deep in unindexed vertex attributes. The schema's queryable surface for this investigation covers hypothesis weights, dispositions, and loop counts cleanly. Everything else — the rich contextual evidence that would make this investigation useful as a retrieval hit for a future similar case — requires prose parsing or is absent.

---

## Recommendations

Ranked by impact revealed by this translation:

1. **Add a `trust_anchor_result` structured field to lead outcome for trust-mode leads.** The `outcome` block should support `trust_anchor_result: {anchor_id, kind, identity_confirmed: bool, cadence_confirmed: bool, result: confirmed | refuted | partial, citation: string}` so that anchor outcomes are structurally queryable. The current encoding buries anchor results in observation vertex attributes and resolution reasoning strings. This is the highest-impact gap: every investigation that consults an org-authority anchor has this same loss.

2. **Add a SCREEN phase block at the schema level.** Even a minimal `screen: {result: match | no_match, matched_archetype: <name> | null, leads_run: [l-id, ...], rationale: string}` block would make the SCREEN outcome queryable. Currently, the SCREEN result (which drove the full investigation) is derivable only from `matched_archetype: null` in conclude plus prose in lead reasoning. A SCREEN phase is structurally distinct from loop-1 gather because its purpose is fast-path elimination, not hypothesis discrimination.

3. **Add `mandatory_adversarial: true` to hypothesis schema.** A single boolean field distinguishing mandatory-adversarial hypotheses from ordinary ones would allow validators to enforce the rule "cannot conclude benign while any mandatory-adversarial hypothesis is above `--`" mechanically. Currently this rule is captured only in investigation methodology prose.

4. **Add `tooling_gaps: [...]` as a structured list in the conclude block or as a top-level companion field.** Each gap entry: `{host, operation, blocked_path, load_bearing: bool, prevents_refutation_of: [h-id, ...]}`. This would make "why did this investigation escalate?" answerable by a structured query instead of ceiling_rationale parsing.

5. **Add `trace: string` as a derivable but explicit field in conclude.** The one-line compressed trace is the highest-value retrieval key for similarity search across cases. It should be a first-class field even if it is technically derivable, because re-deriving it on every read is expensive and the derivation logic is non-trivial.

6. **Add a structured `burst_detail` vertex type or a standardized attribute schema for auth-event observations.** Currently the burst observation (duration_ms, username_cycling, event_count) lives in an anchor-source vertex's freeform attributes dict. For SSH-class alerts where burst shape is the primary discriminating evidence, a structured `burst_observation: {event_count, duration_ms, distinct_usernames, all_sentinel: bool}` field on auth-event observation vertices would make the burst fingerprint range-queryable.

7. **Consider an OR-clause syntax for predictions.** `?monitoring-host-compromise` has predictions that are alternatives ("username rotation beyond sentinel set, OR sustained burst, OR successful login, OR parallel alerts"). The current schema requires each prediction to be an independently confirmable claim (see rule 6: `++` requires all prediction IDs covered). Alternative predictions must either be flattened (losing the OR semantics) or modeled as a single compound claim string. A `prediction_mode: any | all` field would resolve this without structural changes to the resolution machinery.
