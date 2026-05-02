# Investigation Language

**Status:** Spec v2.15. Implemented.
**Query tool:** `soc-agent/scripts/invlang/` — see `cli.py --help`
**On-disk surface:** `​```invlang` fenced blocks. `​```yaml` fences in `investigation.md` are rejected by the validator. Block-tag grammar (`:V` / `:E` / `:H` / `:L` / `:R` / `:T` / `:G`), row shapes, and the surface-to-canonical-dict projection live in `docs/dense-investigation-format.md`. The canonical companion dict — what the validator and the corpus queries operate on — is what every block projects to via `soc-agent/scripts/handlers/_dense_parser.py`.

**v2.16 delta:** rule #36 simplified — `disposition: true_positive` now requires only `++` on a surviving hypothesis (weight-only). The v2.14 adversarial-classification token check is removed; the lexical token list desynced from playbook-canonical fork names (e.g. `?credentials-used-outside-registered-actor`) and produced false rejections of legitimately-graded `true_positive` routings. The affirmative-evidence signal is captured by the `++` requirement; the "wrong-named survivor" failure mode is caught by Tier-2 judges and rule #21. Validator implementation: `hooks/scripts/invlang_checks_authorization.py:_check_affirmative_true_positive`. Parser-side X5 (`scripts/handlers/_output_parser.py:_validate_cross_block_invariants`) similarly weight-only.

**v2.15 delta:** Validator rule consolidation — 36 → 29 active rules. Doc-only refactor; no validator behavior change. Drives:
- Reference-resolution merge: rules #12, #19, #20, and the resolution clause of #22 fold into rule #7. Single "all references resolve in scope" rule covers `v-*`, `e-*`, `h-*`, `l-*`, hierarchical `h-{parent}-{nonce}`, contract `edge_ref`, `fulfills_contract`, and `attribute_updates.target`.
- SCREEN structural integrity merge: former #16 (screen_result scope) absorbs into #17.
- Schema-validity scope expansion: rule #1 absorbs former #15 (sub-vertex `v-{parent}-{nonce}` shape) and the exclusivity clause of former #22 (target shape).
- Past-case ⇒ partial enum constraint moves from former #27a to rule #11; #27 retains the no-sole-grounding rule for benign.
- Demotion: former #10 (mechanical leads stay within data source) is now a review-only discipline guideline — semantic, not validator-enforced. Retained in §Conventions.
- Numbering preserved with redirect notes at the seven gaps (#10, #12, #15, #16, #19, #20, #22) so existing code, prompt, and test references to those rule numbers remain greppable. Rule #36 (v2.14) is unaffected by the consolidation and counts toward the 29 active rules.
- Per-rule audit: see `docs/invlang-rule-audit.md` (added 2026-04 alongside `docs/dense-investigation-format.md`).

**v2.14 delta:** rule #36 — affirmative `true_positive` disposition. Closes the absence-of-benign-confirmation cascade (4 production runs documented in `tasks/analyze-true-positive-routing.md`) by structurally rejecting `disposition: true_positive` writes whose `surviving_hypotheses[]` carries no hypothesis that is both adversarially-classified AND graded `++`. Validator implementation: `hooks/scripts/invlang_checks_authorization.py:_check_affirmative_true_positive`. Empirically motivated: trap-set evaluation showed prompt-only guidance lets ~50% of false-true-positive cases through; the structural gate raises catch rate to ~100%.

**v2.13 delta:** Tier-0 contract-completeness rules between PREDICT and ANALYZE.
- Rule #34 (prediction closure at CONCLUDE) — at REPORT, every declared `p*` / `ap*` on a non-refuted, non-shelved hypothesis must be cited in some resolution's `matched_prediction_ids[]` with a non-null `after`, OR appear in `conclude.deferred_predictions[]` with rationale. Generalises rule #6 (which only fired on `++`) into a coverage gate at REPORT regardless of weight. New conclude surface: `deferred_predictions[]` (parallel to `deferred_authorizations[]` and `deferred_impact_predictions[]`).
- Rule #35 (sibling prediction divergence) — within a sibling group (shared `parent_hypothesis_id` + `attached_to_vertex`), no two siblings may declare identical prediction signatures (combining `(subject, claim)` from `predictions[]` and `(target, attribute, claim)` from `attribute_predictions[]`, case-normalised). Generalises rule #32 (integrity-peer-specific, contract-gated) to all sibling forks regardless of contract presence.
- Companion to spec rule #33 (attribute-prediction structure) — already in schema.md; documented here for completeness.

**v2.12 delta:** top-level block rename `gather:` → `findings:`. Same merge semantics (same-id append; ANALYZE merges outcome.resolutions + verdicts onto the GATHER-populated entry), clearer name for cross-phase state. Handler-authored: subagents emit plain-YAML envelopes; `scripts/handlers/gather.py` + `scripts/handlers/analyze.py` synthesize `findings[]` and merge via the existing validator. Raw SIEM/anchor payloads moved off the companion to `runs/<run-id>/raw_details/loop-<N>/<lead-id>.yaml`; analyze-handler preloads them per-loop.

**v2.11 delta:** three orthogonal resolution axes named explicitly.
- **Impact** promoted from a signature-knowledge hand-wave to a lead-level first-class record. `impact_predictions[]` on leads declare threshold predicates before evidence lands; ANALYZE grades observations against them and emits `impact_resolutions[]` on lead outcomes; `conclude.impact_verdict` and `conclude.impact_severity` are a second axis alongside `disposition`. The authorized-but-malifying class (authorized bulk read at 3σ above baseline; authorized admin delete of 10 000 rows) resolves here — not on authz. Signature-tier `impact_profile.md` deferred pending corpus measurements; per-signature impact knowledge lives in playbook prose until threshold drift is observed.
- **Integrity** promoted from a paragraph under §Authorization to its own §Integrity section. Mechanism-hypothesis placement reaffirmed (`?adversary-controlled-*` peers with predictions on discriminating observables); integrity is evidential, not anchored, and not a contract. Discipline: `authorization_contract` on a hypothesis whose predicted edge has an acting-entity source (`session`, `identity`, `process`) expects a peer integrity hypothesis unless `integrity_waived: <rationale>` is present — closes the authorized-bulk-read-from-compromised-account shortcut. Forthcoming validator rule; guidance applies today.
- **Hypothesis cardinality 0-N** made explicit. §Lean hypotheses renamed §Hypothesis cardinality and leanness, with a table mapping cardinality to intent (0 = enriching, 1 = mechanism pinned, 2-3 = observable-diverging peers, >3 = refine under a hierarchical parent). Mirrors PREDICT Shapes D/E/I/A/M in `soc-agent/agents/predict.md`.
- **Terminology cleanup.** `vertex.trust_root: true` attribute dropped — unvalidated and unqueried; the signal already lives on `outcome.trust_root_reached: v-{id}` (ref-checked) and `conclude.termination.category: trust-root`. "Anchor" reserved for external authority surfaces (`anchor_id`, `anchor_kind`, `anchor_consultations[]`); the "anchor:" gloss on `attached_to_vertex` removed — the field name self-explains.

**v2.10 delta:** motivated by `docs/experiments/invlang-post-predict-assessment.md`.
- Rename `legitimacy_contract` → `authorization_contract` and `legitimacy_resolutions` → `authorization_resolutions`. The v2.8 name was a misnomer — 100% of corpus predicates are zero-trust ABAC authorization checks, not business-impact legitimacy reasoning. Business-impact legitimacy is parked at the signature knowledge-base layer (`impact_profile`), not the graph.
- `authorization_resolutions[]` becomes self-describing: each resolution carries `anchor_id`, `grounding_kind`, `authority_for_question`, `effective_window`, and `conditioning_context: []`. Authz provenance and temporality live on the resolution they justify.
- Anchor consultations that inform hypothesis weight but do not fulfill a contract (baselines, registry lookups, reference queries) keep a structured home at the lead outcome level: `anchor_consultations[]` — the v2.10 successor to v2.9's `trust_anchor_result`, narrowed to non-authz consultations and renamed because it records a consultation event, not a singular result. Keeps baseline/expectation evidence first-class instead of demoting it to prose.
- `authorization_resolutions[].grounding_kind ∈ {org-authority, past-case}` — baselines cannot ground an authz verdict. `anchor_consultations[].grounding_kind ∈ {org-authority, telemetry-baseline}` — past-case citations are authz-only. `past-case` uses a structured citation (`cites_past_case.run_id`, `cites_past_case.contract_ref`). Constraints: force-caps `authority_for_question` to `partial`; cannot be sole grounding for benign disposition; a past-case cannot cite another past-case as its grounding (depth cap).
- `conclude` gains `deferred_authorizations[]` — every declared `authorization_contract` must resolve OR appear here with rationale (validator rule #26). Closes the orphan-contract loophole where escalation paths silently accept unresolved contracts.
- Validator rules #19–#21 renamed `legitimacy_*` → `authorization_*`; rules #26–#28 added (orphan gate, past-case authority cap, past-case depth cap).

**v2.9 delta:** validator rules #24 (hypothesis persistence at CONCLUDE) and #25 (same-level sibling rollup for `matched_prediction_ids`). Closes two bias gaps identified during the ANALYZE-phase state-machine cutover: silent hypothesis drop across loops, and cross-sibling prediction-ID citation. See `.claude/skills/migrate-state-machine/SKILL.md` for the design context.

**v2.8 delta:** authorization as first-class edge attribute (`edge.authorization_resolutions`) driven by hypothesis-declared contracts (`hypothesis.authorization_contract`); `attribute_updates` extended to edge targets; validator rules #19–#22; supersedes the former "maintain adversarial hypothesis until `--`" bookkeeping rule. (Originally shipped with `legitimacy_*` names — renamed in v2.10; see above.)

A structured schema for recording security investigations as graph
traversals. Designed for SOC-level alert triage: the agent works
backward from an observed alert until it reaches trust-authoritative
sources or exhausts available tools.

---

## Goals

**Elegant.** Small number of primitives; everything else derivable.
No field exists solely to carry information already present in the
graph structure.

**Readable.** A companion is a document. An analyst reading it should
be able to follow the investigation's reasoning without parsing schema
headers.

**Writable.** An LLM writing a companion should rarely need to look up
a rule. The schema nudges correct behavior through structure; edge
cases are rare.

**Searchable.** Companions support corpus queries that measure
investigation effectiveness: which hypothesis patterns recur, which
leads are most discriminating, where investigations stall and why.

---

## Philosophy

### The investigation graph

An investigation maintains two layers at all times.

**Confirmed graph** — vertices and edges backed by observation
authority (SIEM events, runtime audit, authoritative sources). Grows
monotonically; nothing is ever mutated.

**Proposed frontier** — candidate graph extensions, one per active
hypothesis. Each hypothesis proposes that a specific upstream vertex
exists, connected to the confirmed graph by one edge. Leads test
whether proposed elements actually exist, moving them from proposed
to confirmed (or refuting them).

The investigation progresses by running leads that collapse the
frontier. It halts when the frontier is empty (all hypotheses
resolved) or the confirmed graph reaches a vertex where no accessible
upstream exists — a **trust root**.

This maps to graph search: the confirmed graph is the explored set;
the proposed frontier is the candidate set; each lead is an edge
measurement. The difference from static graph search is that the
graph is being constructed as it goes — each lead can both test
existing proposals and introduce new vertices that open the next
layer of questions.

### Backward traversal

Investigations look backward: observation → cause → cause-of-cause
→ until a trust root. The driving question at each step is *why does
this edge/vertex exist?* The confirmed answer becomes the new anchor
for the next question.

**Depth is forced by evidence.** Do not propose a deep causal chain
at loop 1. Form the immediate discrimination question; deepen only
when a lead confirms the current anchor and opens the next layer.

### Scale of reasoning

Model at the granularity the investigation reasons at, not finer.
A process vertex is opaque until the investigation needs to
distinguish sub-entities within it — because different sub-entities
would lead to different hypotheses, different leads, different
conclusions. Before that point, the entity is atomic and its
internal structure is transparent to the investigation.

When a lead reveals heterogeneous internal structure that changes
the investigation's trajectory, decompose into sub-vertices linked
by `component_of`. The parent vertex and its existing edges remain
valid; coarse observations are still true. Fine-grained edges
specialize them — they do not replace them.

**Cartography principle.** A world map renders an island opaque; a
city map shows streets; a floor plan shows rooms. The right
resolution depends on the question being asked. Pre-decomposing adds
entities the investigation hasn't needed to reason about — graph
clutter without discrimination value.

### Hypothesis cardinality and leanness

The loop authors **0 to N** hypotheses per PREDICT pass (realistically
N ≤ 3). Cardinality is not a structural requirement — it's a
discrimination commitment. Author a hypothesis when naming it makes a
bias explicit or partitions lead selection; don't author one when the
next move is pure enrichment.

| N | When | What the hypothesis does |
|---|---|---|
| 0 | Alert under-specified; the next lead enriches before a fork is possible | — |
| 1 | Mechanism pinned by alert fields; only authz, integrity, or impact open | Makes the open axis explicit; drives lead choice |
| 2–3 | Mechanisms diverge on already-observable fields | Makes the discriminator explicit; partitions leads |
| > 3 | Usually a refinement that belongs under a hierarchical parent | Shelve the parent; emit children as `h-{parent}-{ordinal}` |

Cardinality is structural in the companion: the `hypothesize:` block
is present iff ≥ 1 new hypotheses are authored this loop. Omission
means "continue the existing frontier." See PREDICT Shapes D/E/I/A/M
(`soc-agent/agents/predict.md`) for the authoring decision procedure.

A hypothesis, when authored, captures the **immediate next
discrimination question**, not a deep causal narrative. A lean
hypothesis has 1–2 predictions: the minimum that distinguishes it
from competing hypotheses.

Pre-committing to a deep narrative fragments the hypothesis space
across cases that should match the same retrieval pattern, creates
prediction IDs for facts not yet in evidence, and makes weight
accumulation harder. Refine into more specific children only when
evidence forces the distinction.

### Authorization as edge attribute

Authorization — is this edge *permitted by policy*? — is a property
of the (`source_vertex`, `edge`, `target_vertex`, `authority`)
quadruple at time T. The same `read` edge from a session to a storage
object is authorized when the session's identity carries the required
role and unauthorized when it does not. The mechanism is identical;
only the verdict differs. Authorization therefore lives **on the
edge**, not as a parallel hypothesis.

A hypothesis whose disposition depends on authorization declares an
`authorization_contract` naming the edge(s) whose verdict is
load-bearing and the authority that resolves them. When the resolving
lead fires, the edge gains an `authorization_resolutions` entry with
the verdict and a back-reference to the contract. Append-only is
preserved by backward traversal: the hypothesis is written once and
never mutated; the materialized edge points backward via
`fulfills_contract`.

**Authorization ≠ business-impact legitimacy.** The field was called
`legitimacy_contract` through v2.9 and renamed in v2.10 because the
name was a misnomer — agents consistently populated it with zero-trust
ABAC predicates ("is this triple listed in the approved-sources
registry?"), never with business-impact reasoning ("does this event
help or damage business needs, and by how much?"). Business-impact
legitimacy is a real but separate axis — direct damage (CIA effects),
intent signal (does this event indicate adversarial intent), and
business contribution (does this serve a sanctioned goal). Those axes
are knowledge-base concerns tied to mechanism class, not per-instance
graph elements — they live in `knowledge/signatures/{id}/impact_profile.md`,
consumed by PREDICT/CONCLUDE prompts to contextualize disposition.

**Three shapes of adversariness.** Not every adversarial question is
an authorization question:

- **Mechanism-level** — enumerate `adversary-controlled` alongside
  benign classifications when they predict observationally distinct
  world-states. Normal mechanism enumeration; no contract needed.
- **Attribute-level (policy authorization)** — same mechanism, same
  observables, but an authority would answer "allowed" differently
  depending on the source identity. This is the authorization
  contract case. Common.
- **Future-edge** — the adversarial signal is a separate downstream
  edge (a failed-auth alert followed by an unexpected success). That
  is a topology question; write it as its own hypothesis attached to
  the hypothetical future edge.

**Contracts answer policy, not integrity or impact.** A contract asks
"is this edge allowed by the relevant authority?" It does not ask
"was this edge actually executed by the claimed actor?" (integrity —
see §Integrity as mechanism enumeration) or "does this edge's effect
matter enough to escalate?" (impact — see §Impact as lead-level
prediction). The three axes are orthogonal and resolve through
different machinery.

### Integrity as mechanism enumeration

Integrity — *is the acting entity what it claims to be?* — is a
separate axis from authorization. Session hijack, token theft, MFA
bypass, process hollowing, tool masquerade are integrity questions:
if the impostor is presenting valid credentials, the IAM anchor will
answer "authorized" about the claimed identity. That verdict is
correct under the authz question's scope; it does not address whether
the session is actually the claimed session.

Integrity is **evidential, not anchored.** No single authority
answers "is this session compromised?" — the answer is composed from
behavioral observables: application-layer correlation, query-shape
template match, impossible travel, device-fingerprint mismatch,
anomalous timing against baseline, presence or absence of a
correlating upstream request.

**Representation: mechanism-hypothesis peers, not contracts.** An
integrity concern produces a peer hypothesis
(`?adversary-controlled-<entity>`) alongside the routine-mechanism
hypothesis, with predictions on the discriminating observables. The
two peers share the same authz contract (both evaluate to
`authorized` against IAM) but differ on the predictions that test the
premise. Discrimination happens at ANALYZE via normal weight-update
machinery — not through a contract verdict. Contract shape doesn't
fit integrity: the question is evidential rather than categorical, no
single anchor owns the answer, and the question is the same across
peer hypotheses (not mechanism-conditional the way authz is).

**Acting-entity discipline.** When an `authorization_contract` is
declared on a hypothesis whose predicted edge has an acting-entity
source (`session`, `identity`, `process`), a peer integrity
mechanism is expected unless the hypothesis carries an explicit
`integrity_waived: <rationale>` note. Closes the failure mode where
authz clears, impact clears, and the integrity premise was never
tested — the authorized-bulk-read from a compromised service
account. Forthcoming validator rule; guidance applies today.

Integrity bottoms out at the authentication edge: below the
session → identity authz layer, further integrity questions require
out-of-band evidence the investigation typically cannot access (TPM
attestation, endpoint EDR, identity-provider forensics). Reaching
that boundary is a `termination.category: severity-ceiling`
condition, not a trust-root.

### Impact as lead-level prediction

Impact — *does this edge's effect matter enough to escalate?* — is a
third axis, orthogonal to authorization and integrity. An
authorized, uncompromised action can still be escalation-worthy if
its consequence exceeds a threshold (authorized backup service
uploads 180 GB when baseline is 60 GB; authorized admin deletes
10 000 rows from a production table). Conversely, an unauthorized
attempt that achieves no effect stays low-impact. Disposition on the
authz/integrity axis does not determine impact on the consequence
axis.

Impact is assessed at **ANALYZE**, graded against **pre-registered
predicates** authored at **PREDICT** (lead-level). The
commit-before-evidence property that makes hypothesis predictions
reliable transfers to impact verdicts: the threshold is written into
the record before the lead runs, so ANALYZE cannot retroactively
shift the bar after seeing the observation.

**Lead-level `:L l-{id}.impact_preds`.** A PREDICT-scaffolded lead that measures impact-relevant observables carries one or more `ip*` rows. Column shape and enums: see `soc-agent/knowledge/invlang/schema.md` §Lead → Impact predictions.

One observable per `claim` (rule #29): split compound AND/OR predicates into multiple `ip*` rows so partial evidence can pivot each side independently.

**Outcome-level `:R impact`.** ANALYZE emits one row per fulfilled `ip*`. Column shape `[pred_ref|dim|observed|verdict|matched_pred|grounding|anchor_id|anchor_kind|authority|as_of|effective_window?|conditioning?|reasoning]` and per-cell enums: see schema.md §Resolutions → `:R impact`. Past-case is not admissible as `grounding` — impact reasoning is per-instance, not category-of-event.

Rule #14 (partial authority caps weight) applies — a baseline that
covers magnitude but not intent is `partial` and cannot alone force
high-severity escalation.

**Closure at CONCLUDE.** Every `impact_predictions[]` entry whose
resolving lead ran must either have a fulfilling
`impact_resolutions[]` entry OR appear in
`conclude.deferred_impact_predictions[]` with rationale. Mirrors
rule #26's orphan gate for authorization contracts.

**Two-axis CONCLUDE.** The `:T conclude` block carries both axes — `disposition` (authz/mechanism: `benign` \| `true_positive` \| `unclear`) and `impact_verdict` (impact: `none` \| `within` \| `exceeds` \| `indeterminate`), with `impact_severity` set when `impact_verdict ∈ {exceeds, indeterminate}`. They combine orthogonally:
- `(benign, within)` — routine activity, no escalation.
- `(benign, exceeds)` — **authorized but malifying.** Mechanism
  confirmed benign; consequence exceeds threshold. Requires analyst
  review on impact even though the mechanism cleared.
- `(true_positive, within)` — confirmed threat whose consequence
  stayed bounded (failed probe, denied access attempt).
- `(true_positive, exceeds)` — confirmed threat with realized
  consequence. Highest-severity class.
- `(unclear, *)` — mechanism indeterminate; impact verdict still
  recorded for handoff.

Escalation policy in the plugin configuration may drive on either
axis independently.

**Signature-tier deferred.** A per-signature `impact_profile.md`
declaring static class-level impact predicates (a 2σ threshold for
`rule-dlp-4421` regardless of instance) would strengthen the
commit-before-evidence property further but is not required in
v2.11. Lead-level authoring is the minimal honest starting point;
per-signature knowledge lives in playbook prose until corpus
measurements show PREDICT threshold drift. Promotion to a
signature-tier record is additive — `impact_predictions[].inherited_from: sig-iq1` back-reference — and does
not restructure the lead-level shape.

### Temporality of authorization

Authorization is time-bound. An authz verdict holds *as of* a specific
moment, conditional on state that was true at that moment — an oncall
rotation, an open change window, an approved travel ticket, a registry
entry. The schema records three temporal fields on every
`authorization_resolutions[]` entry:

- **`as_of`** — the timestamp the answer is authoritative *about*.
  Required.
- **`effective_window`** — optional `{start, end}` for authz grants
  with explicit time bounds (change windows, oncall shifts, travel
  approvals). When present, validates that the observed event falls
  inside.
- **`conditioning_context: []`** — optional prose list of then-true
  conditions that the verdict rests on. Examples: "operator on-shift
  per oncall rotation active 2026-04-14T00:00–2026-04-15T00:00",
  "CHG-2041 open and applicable", "user-travel-approved
  2026-04-14→2026-04-21".

Conditioning context matters forensically even after conditions
change. An authz verdict that was correct *as of* its time does not
retroactively become wrong when the underlying conditions lapse. But
analysts reading the companion months later need to see *why* the
verdict held — the conditioning list makes this auditable. The same
fields carry retrospective impact reads: if an exfil attempt was
blocked by DLP rule R33 and that rule was later removed, the
`conditioning_context` records R33 as the reason observed impact was
"failed" — without claiming the impact would still be zero today.

### Past cases as authorization source

A past investigation's conclusion that a specific triple was
authorized may serve as a **weak temporal authz source**
(`authorization_resolutions[].grounding_kind: past-case`). Constraints
are structural:

- `authority_for_question` is force-capped to `partial` regardless of
  how confidently the past case resolved — rule #14 then caps weight
  effect at `+`/`-`.
- A past-case consultation cannot be the sole grounding for
  `disposition: benign` on any contract. If every fulfilling
  resolution on a benign-eligible contract has
  `grounding_kind: past-case`, escalation is forced (rule #27).
- A past-case consultation cannot cite another past-case consultation
  as its own grounding — `cites_past_case` points to the exact prior
  contract, and that cited resolution must have
  `grounding_kind: org-authority`. Prevents bootstrap drift where past
  cases recursively authorize themselves (rule #28).

Past-case-as-authz is distinct from archetype matching at CONCLUDE.
Archetype matching is disposition-shaped ("this looks like outcome
cluster Y"); past-case-as-authz is authz-shaped ("this triple was
deemed authorized in SEC-2024-001"). The same past companion can
inform both, via different schema paths. Do not conflate.

### Leads as graph operations

A lead is an operation on the investigation graph. Two kinds:

- **Topology-extending** — materializes new vertices and edges
  (confirmed graph grows). When it discriminates between competing
  hypotheses, `tests` names them.
- **Attribute-refining** — enriches existing confirmed vertices
  without adding new topology (`attribute_updates`). No hypothesis
  target; the lead answers "what more do we know about this entity?"

Many leads are both: a trust anchor lookup may enrich an existing
vertex *and* materialize new entities in the same outcome. The
distinction is not categorical — there is no `mode` field. A lead
that produces only `attribute_updates` is implicitly attribute-
refining; one that produces `observations` is topology-extending.
Whether it discriminates between hypotheses is expressed by
`tests`, not by a type label.

### Append-only

Once written, no record is mutated. Sub-vertices are appended when
decomposition is forced; the parent stays. Placeholder vertices are
linked to their real counterpart via `identified_as` when
attribution is recovered; the placeholder stays. The graph
accumulates; it does not revise.

---

## Schema

The on-disk surface is `​```invlang` blocks. The **canonical companion dict** the validator and corpus queries operate on is what every block projects to via `soc-agent/scripts/handlers/_dense_parser.py`. This section captures the schema's design intent and invariants; the **field-level grammar** (block tags, column shapes, sub-cell packing, cell enums) lives in two places that should be read together:

- `soc-agent/knowledge/invlang/schema.md` — agent runtime reference (loaded into the investigate prompt). Every section below has a corresponding §section in schema.md.
- `docs/dense-investigation-format.md` — surface design doc with full block-tag grammar and the schema-mapping table.

### Top-level structure

```
:V prologue.vertices    — CONTEXTUALIZE: vertices derived from the alert
:E prologue.edges       — CONTEXTUALIZE: edges derived from the alert
:H hypothesize.hypotheses — PREDICT: initial proposed frontier (omit for SCREEN-matched cases)
:L findings             — GATHER + ANALYZE: one row per lead; same id merges across phases
  (per-lead sub-blocks: :V/:E/:R/:T scoped by l-{id})
:T conclude (+ sub-tables) — REPORT termination, disposition, deferreds
```

**`hypothesize` is optional.** For SCREEN-matched investigations, no
hypothesis formation step runs — the screen leads encode pattern
evaluation directly, and `outcome.screen_result: match` records the
verdict. Omit the `hypothesize` block in these cases.

For full-loop investigations, `hypothesize` is written once (after
CONTEXTUALIZE, before the first GATHER lead). Subsequent-loop hypothesis
evolution is captured inside leads via `new_hypotheses` (additions) and
`shelved` (retractions). There is no second top-level `hypothesize`
block.

### Vertex

Field grammar: `:V <block> [id|type|class|ident|attrs?|placeholder?|concerns?|citations?]` — see `soc-agent/knowledge/invlang/schema.md` §Vertex for cell-level semantics and enums. Used by `:V prologue.vertices` (CONTEXTUALIZE) and `:V l-{id}.observations.vertices` (GATHER).

**Sub-vertex IDs.** When a vertex is decomposed inward via
`component_of`, sub-vertices use `v-{parent}-{nonce}` IDs (e.g.,
`v-001-01`, `v-001-02`). This encodes containment in the ID itself,
enabling prefix queries without edge traversal.

**Trust-root signaling lives on lead outcomes and CONCLUDE, not
vertices.** When a lead reaches a vertex with no accessible upstream,
it records the vertex id in `outcome.trust_root_reached: v-{id}`; the
terminating companion sets `conclude.termination.category:
trust-root`. The investigation does not write a `trust_root: true`
flag onto the vertex itself — the signal is about the frontier
collapsing, not about the vertex having an intrinsic property.

**Placeholder vertices.** When a lifecycle edge requires two
endpoints but one is unobservable, write a placeholder vertex with
`placeholder: true`. If a later lead identifies the real entity,
append a new vertex and link via `identified_as`. Never mutate the
placeholder.

### Edge

Field grammar: `:E <block> [id|rel|src|tgt|when|auth_kind:source|attrs?|status?|trust_chain?|concerns?]` — see `soc-agent/knowledge/invlang/schema.md` §Edge for cell-level semantics and enums. Authorization verdicts live in `:R authz` rows, not on the `:E` row itself (see §Authorization below). Used by `:E prologue.edges` and `:E l-{id}.observations.edges`.

**Authority is observational, not authorization.** It describes how
reliably the source recorded the observation. `siem-event`,
`runtime-audit`, and `authoritative-source` support `++`/`--`
weight. `client-asserted` and `inferred-structural` cap at `+`/`-`.

A `client-asserted` edge on a verified trust chain gets effective
`authoritative-source` authority; record the chain in `trust_chain`.

**Authorization verdicts are plural per edge.** Each `:R authz` row resolves one contract's verdict — see `soc-agent/knowledge/invlang/schema.md` §`:R authz` for the full row grammar (column shape `[edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|effective_window?|fulfills|resolved_by|cites_past_case?|conditioning?|concerns?]` plus per-cell enums and the past-case constraints).

Plural because real edges often face parallel policy layers — IAM ×
data-classification × time-of-day — each resolved independently by a
different anchor, any one of which can deny. Do not collapse layered
policies into a single entry; each contract gets its own resolution.

**When `authorization_resolutions` appears.** Only on edges that
fulfill a declared contract. Edges not referenced by any contract
omit the field entirely. Do not write speculative verdicts — that is
verdict-on-everything clutter.

**Append-only on existing edges.** If a contract resolves against an
already-confirmed edge (not the proposed edge of its hypothesis), the
resolving lead writes the verdict via `attribute_updates` targeting
the edge — not by mutating the original edge record.

**Per-question authority** (whether a source covers all aspects of
the question being asked) is a property of the specific resolution,
not the edge itself. It lives in
`authorization_resolutions[].authority_for_question`.

### Hypothesis

Field grammar: `:H <block> [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status|concerns?]` — see `soc-agent/knowledge/invlang/schema.md` §Hypothesis for cell semantics, sub-cell packing (`p<n>:<subject>:"<claim>"`, `ap<n>:<target>:<attribute>:"<claim>"`, `r<n>[<refs>]:"<claim>"`, `ac<n>:<edge_ref>:<anchor_kind>:"<predicate>":<on_unauth>/<on_indet>`), and the integrity-waiver rule. Used by `:H hypothesize.hypotheses` (top-level) and `:H l-{id}.new_hypotheses` (born inside a lead).

**One-hop discipline.** `proposed_edge.parent_vertex` is the
immediate upstream cause — exactly one hop from `attached_to_vertex`.
Do not propose a distant ancestor.

**Refinement via hierarchical IDs.** When evidence forces a lean
hypothesis into more specific sub-cases, allocate child IDs as
`h-{parent}-{ordinal}` (e.g., `h-001` → `h-001-001`, `h-001-002`).
Write children as full hypothesis records in the lead's
`new_hypotheses`. Shelve the parent in the same block. Children
inherit no weight from the parent; their histories are independent.

**Lean means 1–2 predictions.** A single prediction captures the
core discriminating claim. Add a second only when two independent
facts each partially confirm the hypothesis and neither alone
suffices. Three or more predictions usually signals either a
non-lean hypothesis or a refinement that should be deferred.

**Authorization contracts** are declared on the hypothesis when disposition hinges on an authorization lookup (§Authorization). Each contract is one `ac<n>` sub-cell on the `:H` row's `authz?` cell — packed `ac<n>:<edge_ref>:<anchor_kind>:"<predicate>":<on_unauth>/<on_indet>` (see schema.md §Hypothesis for the sub-cell grammar). `edge_ref` is `proposed` (the hypothesis's own proposed edge) or `e-{id}` (an existing confirmed edge).

The predicate is natural language. Any AND/OR combination is
permitted — no structured DSL. The agent evaluates the predicate
against anchor data when the resolving lead fires. Declare contracts
only when the mechanism is consistent with both benign and adversarial
readings depending on authorization; when the adversarial reading IS
the mechanism (e.g., `?adversary-controlled-process`), skip the
contract — the classification already carries the claim.

**Behavioral-consistency prediction (optional).** A contract resolved
`authorized` establishes policy compliance, not integrity. The
hypothesis MAY carry one baseline-consistency prediction — positive
("expect corroborating activity X") or negative ("expect NOT to see
>Nσ volume deviation / access outside baseline file set / concurrent
geo-distant sessions"). Gates: baseline queryable, scoped to the
alert's entities, weight-sensitive. Severity caps at `moderate`.
Unavailable baseline → `indeterminate` in `concerns`; do not
confabulate.

### Lead

A lead has one header row in `:L findings` plus zero or more lead-scoped sub-blocks (all sub-block names namespaced by the lead id). Field grammar lives in `soc-agent/knowledge/invlang/schema.md` §Lead — covering the header row columns (`[id|loop|name|target|mode?|tests|system|template|query|window|trust_root?|fail_reason?|screen_result?|selection_rationale?]`) and every sub-block:

| Sub-block | Carries |
|---|---|
| `:V l-{id}.observations.vertices` | new vertices entering the confirmed graph |
| `:E l-{id}.observations.edges` | new edges entering the confirmed graph |
| `:L l-{id}.lead_preds` | conditional branch plans (`lp*`) for non-branching but interpretation-vulnerable leads |
| `:L l-{id}.impact_preds` | pre-registered threshold predicates (`ip*`) graded by ANALYZE into `:R impact` rows |
| `:L l-{id}.substitutions` | query substitutions (`key|value` pairs) |
| `:H l-{id}.new_hypotheses` | hypotheses born inside the lead |
| `:T l-{id}.shelved` (or `:T shelved` in context) | hypotheses dropped from the live frontier by this lead |
| `:R authz` | authorization-contract verdicts on confirmed edges (see §Authorization) |
| `:R consultations` | non-authz anchor queries (baselines, registry lookups) |
| `:R impact` | impact-prediction verdicts (see §Impact) |
| `:R attr_updates` | vertex/edge enrichment without new topology |
| `:T resolutions` | proof-trace lines — one per hypothesis weight transition |

**`selection_rationale` is optional.** Use it to capture the inter-lead
strategic reasoning — why this lead was chosen next given what was
already known. Omit for the first lead of an investigation (choice is
obvious) and for SCREEN leads (subagent-directed). Include when the
choice required weighting competing options: "source-classification
first because IP attribution determines which hypotheses are live
before committing to discriminating queries."

**`mode: screen`** marks leads dispatched by the SCREEN subagent (loop
0). These leads share SCREEN's fast-path purpose — pattern match or
fall through — and are always in `loop: 0`. `outcome.screen_result`
records whether the overall SCREEN matched (`match`) or fell through
(`no_match`). Only the final screen lead in the sequence needs
`screen_result`; omit it from intermediate screen leads.

**`tests` is optional.** Present when the lead is discriminating
between specific competing hypotheses. Absent when the lead is
purely informational (classification lookup, attribute enrichment,
establishing scope). A lead with no `tests` still produces
`resolutions` when its outcome happens to bear on active hypotheses
— the connection is recorded in the resolution, not pre-declared.

**`predictions` is optional — pre-commitment for interpretation-
vulnerable leads.** A lead can be non-branching (same step-1
regardless of which story is true) yet still have outcome fields
whose reading is interpretive — volume anomaly shape, process-name
plausibility, reputation-weight thresholds. For those leads,
pre-register how the outcome will be read as conditional branch
plans: `if <outcome pattern> → read_as <interpretation> →
advance_to <next step>`. The triple is auditable: the actually-run
next lead should match one of the `advance_to` values. If the
observed pattern doesn't fit any `if` branch, that is itself a
signal — HYPOTHESIZE to extend the fork space, don't silently
rationalize.

Lead-level predictions are **not** a substitute for hypothesis-level
predictions. The two are orthogonal commitments:

| Form | Commits to | When to use |
|---|---|---|
| Hypothesis + predictions | Named world models; predictions test them | Multiple plausible explanations, analytically distinct, divergent step-1 leads |
| Lead + predictions | Decision rules on a shared next-step lead | Same step-1 lead regardless; the *reading* determines step-2 |

Interpretation-vulnerability is per-field, not per-lead. A single
lead can mix mechanical fields (UID, count) with interpretive ones
(process-name plausibility, threshold judgment). Pre-register on
the specific fields that carry the judgment.

**`attribute_updates` vs `observations`.** Use `attribute_updates`
when the lead enriches an already-confirmed vertex or edge without
new topology (e.g., a classification lookup adds `classification:
monitoring-host` to an existing endpoint vertex; an authorization
resolution adds an `authorization_resolutions` entry to an existing edge).
Use `observations` when new vertices or edges enter the confirmed
graph. Both may appear in the same outcome. Each `attribute_updates`
entry targets exactly one of `target: v-{id}` or `target: e-{id}`.

**Anchor consultation vs authorization resolution.** Two records
carry anchor-query provenance; which one applies is determined by
whether the query fulfills a declared `authorization_contract`:

| Record | Where | When |
|---|---|---|
| `authorization_resolutions[]` | on the resolved edge | query produces a verdict (`authorized | unauthorized | indeterminate`) that fulfills a contract declared on some hypothesis |
| `anchor_consultations[]` | on the lead outcome | query returns evidence that informs hypothesis weight but does not fulfill a contract (baseline lookups, registry membership checks, reference queries) |

The split maps to a real semantic difference. Authorization resolutions
gate disposition (rule #21). Anchor consultations ground evidence
weight via the lead's `resolutions[]`, the same way any other observation
does. Temporal validity, authority-for-question scope, and
conditioning context are structurally shared — the same fields mean
the same thing in both records — but the verdict/contract-fulfillment
machinery is authz-only.

`as_of` is the timestamp the answer is **authoritative about** — not
the query time unless they coincide. Applies identically to both
records:
- Event anchors (did X happen at time T?) → the event timestamp
- Current-state anchors (is property X true now?) → the query time
  or snapshot timestamp
- Slowly-changing references (was status X as of last sync?) → the
  last-modified time, not the query time

`effective_window` is set when the anchor's answer has explicit time
bounds (change windows, oncall shifts, approved-travel dates for
authz; baseline-snapshot windows for expectation). When present on an
authz resolution, the validator checks that the observed event's
timestamp falls inside `[start, end]`; a mismatch demotes the verdict
to `indeterminate` regardless of the anchor's stated result.

`conditioning_context` is a prose list of then-true conditions the
verdict rests on. Authorization: `["operator on-shift per oncall
rotation active 2026-04-14T00:00–2026-04-15T00:00", "CHG-2041 open
and applicable"]`. Retrospective impact reads (recorded in the same
field on consultations or resolutions, depending on which is in
scope): `["DLP rule R33 in force, scope includes
s3://prod-data/*"]`. The list is an audit trail for later analysts
who need to understand *why* the verdict held before conditions
lapsed.

`authority_for_question: partial` means the consulted source covers
only some aspects of the question. A resolution *or* a consultation
with `authority_for_question: partial` cannot push a hypothesis past
`+` or `-` regardless of its verdict or result (validator rule 14).

`grounding_kind` distinguishes provenance from policy surface:
`anchor_kind` says *what* authority surface was queried (`iam-policy`,
`oncall-schedule`, `image-baseline`); `grounding_kind` says *what
sort of source* produced the answer.
- `authorization_resolutions[].grounding_kind ∈ {org-authority, past-case}`
- `anchor_consultations[].grounding_kind ∈ {org-authority, telemetry-baseline}`

Baselines cannot ground an authz verdict (they answer expectation,
not authorization); past-cases cannot appear as expectation evidence
(their semantic is authz-shaped). The enum constraints enforce this
structurally so rules #13/#14 from v2.9 (baselines-don't-authorize
discipline) don't have to be restated.

`grounding_kind: past-case` is a weak-temporal authz source citing a
prior companion's conclusion. Force-caps `authority_for_question` to
`partial` (rule #27), cannot be sole grounding for benign disposition
(rule #27), cannot chain on another past-case consultation (rule #28).
`cites_past_case.run_id` names the source companion; `contract_ref`
names the exact contract in that companion being relied upon.

**`failure_reason` enum.** `adapter-error` | `attribution-opaque` |
`partial-coverage` | `permission-denied` | `timeout` | `other`

**Severity of test.**

| Severity | Meaning | Max weight effect |
|---|---|---|
| `severe` | Outcome directly confirms or contradicts a core prediction | up to `++` / `--` |
| `moderate` | Constrains plausibility without direct contradiction | one step |
| `weak` | Circumstantial consistency | caps at `+` / `-` |

### Conclude

REPORT writes a flat `:T conclude` key/value block plus required sub-tables (`:T conclude.surviving`, `:T conclude.deferred_authz`, `:T conclude.deferred_impact`, `:T conclude.deferred_preds`, `:T conclude.ceiling_test`). Field grammar — every key, every sub-table column shape, every enum, and the missing-vs-empty convention — lives in `soc-agent/knowledge/invlang/schema.md` §Conclude.

**`deferred_authorizations`.** Lists authorization contracts that were
declared but not resolved by any lead. Each entry names the contract
(`h-{id}.ac{n}`) and a rationale — typical rationales are
"escalation-forced by unauthorized sibling contract, no benefit in
resolving this one", "authority anchor unavailable (see concerns on
h-003)", "superseded by mechanism refutation at lead l-007". Rule #26
rejects a `conclude:` block that leaves any declared contract
unresolved and absent from this list. Empty list is valid when every
declared contract has a fulfilling resolution.

**`surviving_hypotheses`.** When a `conclude:` block is written, every
declared hypothesis whose final effective weight is not `--` must appear in
this list (validator rule 24). Empty list is valid — it means every
hypothesis reached `--`. For `disposition: benign` the list is typically
empty; for escalation shapes it names the hypotheses that kept the
investigation from closing and should be included in the analyst handoff.

**`impact_verdict` and `impact_severity`.** The impact axis is
orthogonal to `disposition`. `impact_verdict: none` means the
investigation declared no impact predicates (low-impact signature,
alert class inherently bounded). `within` / `exceeds` / `indeterminate`
are the roll-up over fulfilled `impact_resolutions[]` — `exceeds` if
any fulfilling resolution's verdict is `exceeds`, `indeterminate` if
any is `indeterminate` and none `exceeds`, `within` when all cleared.
`impact_severity` is null unless `impact_verdict ∈ {exceeds,
indeterminate}`; severity reflects the maximum across fulfilling
resolutions, capped by `authority_for_question: partial` per rule #14.
`(benign, exceeds)` is the authorized-but-malifying class — requires
analyst review on consequence even though the mechanism cleared.

**`deferred_impact_predictions`.** Impact-axis analog of
`deferred_authorizations`. Lists `impact_predictions[]` entries that
were declared but not resolved by any lead (tool unavailable, baseline
scope-mismatch, escalation forced before the measurement landed).
Rejected by the impact closure rule (forthcoming validator rule)
when absent but a declared prediction has no fulfilling resolution.

**Termination categories.**
- `trust-root` — confirmed graph reached a vertex with no accessible
  upstream. Frontier collapsed.
- `adversarial-refuted` — every adversarial hypothesis was explicitly
  refuted by confirmed evidence.
- `severity-ceiling` — live hypotheses remain but their critical
  edges cannot be tested with available tools. `ceiling_test`
  records the out-of-band step that would resolve it.
- `exhaustion-escalation` — loop budget exhausted.

**Authorization-gated disposition.** `disposition: benign` requires
that every `authorization_contract` on every confirmed-weight
hypothesis (weight `++` or `+`, status `confirmed` or `active`) has at
least one fulfilling `authorization_resolutions` entry with `verdict:
authorized` on a contracted edge. Any contract that is unfulfilled
(and not in `deferred_authorizations`, per rule #26), or whose
fulfillment carries `verdict: indeterminate`, caps disposition at
`unclear` with `status: escalated`. Any `verdict: unauthorized` forces
`status: escalated` with disposition ∈ {`unclear`, `true_positive`}
depending on remaining evidence. Past-case-sourced resolutions
(`grounding_kind: past-case`) cannot be the sole grounding for
`authorized` on a benign-eligible contract (rule #27). This replaces
the former
"maintain adversarial hypothesis until `--`" bookkeeping rule; teeth
are structural via validator rules #21 and #26–#28.

---

## Conventions

### Lifecycle vs action observations

SIEM observations come in two shapes.

**Lifecycle** — a persistent entity that now exists: a process
running on a host, a session that was established, a file that was
written. The entity outlives the event and the investigation will
refer to it as a noun. Model it as a vertex; model the event with an
edge verb (`spawned`, `wrote`, `authenticated_as`, `runs_in`, …).

**Action** — an audit-log record of an invocation: who called what
with which arguments. Model as a `command` vertex carrying the
action's attributes, with `targeted → <thing acted on>` and (when
applicable) `executed_in → session`. Covers cloud API calls, failed
auth attempts, list/enumerate operations, configuration changes.

**Discriminator.** Is the observation's natural noun an invocation?
→ action (`command` vertex). Is it an entity whose later state the
investigation reasons about? → lifecycle (typed vertex + edge verb).

**CRUD is uniformly action-shaped.** `iam:CreateUser`,
`s3:DeleteObject`, `s3:GetObject` all model as `command` vertices.
Promote the target to its own vertex only if later reasoning
references it as a noun.

### Aggregate observations

When an observation describes N occurrences of something (17
ListObjectsV2 calls over a 172-second window), the aggregate belongs
on a single edge with `count` + `window_*` attributes. Do not
materialize one vertex per occurrence. The SIEM's native unit is the
alert; model at that unit.

### Mechanical leads stay within their data source

A scope lead's `outcome.observations` contains only vertices the
data source directly observes. If the raw event stream would not
contain a record naming a vertex by its native identity, do not
materialize it. Causal implication does not count as native naming.

---

## Types

| Type | Replaces | Notes |
|---|---|---|
| `endpoint` | host, device, remote-endpoint, ip | Compute unit with an OS. IP-only sources use `endpoint` with `attributes.knowledge: partial`. Vendor specifics in `attributes.kind`. |
| `process` | — | Running execution unit on an endpoint. |
| `thread` | — | Sub-entity of process; use with `component_of` and hierarchical ID. |
| `memory-region` | — | Sub-entity of process; use with `component_of` and hierarchical ID. |
| `module` | — | Loaded library/DLL; use with `component_of` and hierarchical ID. |
| `container` | — | Runtime container. |
| `session` | — | Authenticated interactive or API session. |
| `identity` | user | Any authenticatable entity. `attributes.kind ∈ {user, group, role, service-account, application}`. |
| `storage` | — | Object/file/blob/secret store. `attributes.kind ∈ {object-store, block, file, secrets, nfs}`. |
| `database` | — | Structured data system with query interface. |
| `network-device` | — | Firewall, switch, router, load balancer, WAF. |
| `file` | — | A specific file artifact. |
| `command` | — | An audited invocation (action-shaped observation). |
| `socket` | — | Network socket (transport-layer). |

Use `unclassified-{type}` when classification is unknown.
Use `ambiguous-{a}-or-{b}` when two classifications are genuinely
indistinguishable.

---

## Relations

| Relation | Source → Target | Notes |
|---|---|---|
| `spawned` | process → process | |
| `executed` | process → file | |
| `loaded_by` | process → file | For modules / libraries. |
| `opened` | process → socket | |
| `connected_to` | socket → endpoint | Transport-layer only. |
| `read` / `wrote` | process → file | |
| `runs_in` | process → container | |
| `runs_on` | process \| container \| database \| session → endpoint | Compute-substrate containment. |
| `authenticated_as` | session → identity | |
| `initiated_by` | session → identity \| endpoint | |
| `triggered_by` | process \| session → process \| session | |
| `escalated_privilege` | session → session | Self-edge. |
| `executed_in` | command → session | |
| `targeted` | command → endpoint \| storage \| database \| identity \| file \| container \| network-device | Action-target for command vertices. Do not use for lifecycle events. |
| `member_of` | identity → identity | User → group, role → role-bundle. |
| `identified_as` | placeholder → real-vertex | Post-hoc attribution. Never mutate the placeholder. |
| `component_of` | vertex → vertex | Part-of for inward decomposition. Sub-entity → containing entity. Vertex type discriminates semantics. |
| `listed` | session \| process → storage \| database | Enumeration/list operation. |
| `modified` | session \| process → storage \| database \| identity \| file | Configuration or state change. |
| `attempted_auth` | endpoint \| process \| session → endpoint | Observed authentication attempt (may be failed). |
| `classified_as` | vertex → classification-value | |

`listed`, `modified`, `attempted_auth` are provisional — in active
use across the pilot corpus but not yet stabilised from wider case
coverage.

---

## Validator rules

The validator enforces **29 active rules** (rules 1–36 with seven gaps). Seven historical rule numbers (#10, #12, #15, #16, #19, #20, #22) are gaps — their content was either merged into a sibling rule or demoted to review-only discipline. Numbering is preserved for grep-stability of existing code, prompt, and test references; merged rules carry a redirect to their new home. Rule #36 is the most recent addition (v2.14, affirmative true_positive disposition) — included in the 29-active count.

1. **Schema validity.** Required fields present, enums valid, IDs
   well-formed (including hierarchical patterns for hypotheses,
   sub-vertices `v-{parent}-{nonce}`, and the `target: v-{id}` /
   `target: e-{id}` exclusivity on `attribute_updates`).
   *(Absorbs former #15 sub-vertex ID shape and the shape clause of
   former #22 attribute-update target.)*

2. **Classification vocabulary.** Every `classification` is from the
   seed vocabulary (§Types classification lists) or a
   `{type}:{slug}` provisional.

3. **Relation catalog.** Every `edge.relation` appears in §Relations.

4. **Edge authority rule.** `++` or `--` resolutions cite at least
   one `siem-event`, `runtime-audit`, or `authoritative-source` edge
   in `supporting_edges`.

5. **Refutation ID match.** Every `--` resolution's
   `matched_refutation_ids` is non-empty and references IDs that
   exist in the target hypothesis.

6. **Prediction completeness for `++`.** `matched_prediction_ids`
   across all resolutions on a hypothesis must equal the full
   prediction set. Partial coverage caps at `+`. Early gate at
   write time on `++` resolutions; rule #34 is the late closure
   gate at CONCLUDE on every weight.

7. **Reference resolution.** Every `v-*`, `e-*`, `h-*`, `l-*`
   reference in any field points to a record that exists in the
   companion. Hierarchical hypothesis IDs `h-{parent}-{nonce}`
   require the parent hypothesis to be declared. Authorization
   contract `edge_ref` is the literal `proposed` or an existing
   `e-*` id. Authorization resolution `fulfills_contract` of shape
   `h-{id}.ac{n}` points to a hypothesis whose `authorization_contract`
   declares that `ac{n}`. Attribute-update `target` of shape
   `v-{id}` or `e-{id}` points to a declared record.
   *(Absorbs former #12 hierarchical hypothesis IDs, #19 contract
   edge_ref, #20 fulfills_contract back-ref, and the resolution
   clause of former #22 attribute-update target.)*

8. **Append-only.** No existing record is mutated.

9. **Lead block self-containment.** Every vertex, edge, or hypothesis
   produced by a lead lives inside that lead's `outcome.observations`,
   `new_hypotheses`, or `shelved`.

10. **(Demoted to review-only.)** *Mechanical leads stay within their
    data source* — a lead's `outcome.observations` contains only
    entities the queried system directly observes by native identity.
    Semantic discipline that requires per-system knowledge to
    enforce mechanically; not currently validator-checked. Retained
    in §Conventions as authoring guidance.

11. **Anchor-query provenance completeness and enums.** Every
    `authorization_resolutions[]` entry requires `verdict`,
    `anchor_kind`, `anchor_id`, `grounding_kind`,
    `authority_for_question`, `as_of`, `resolved_by_lead`, and
    `fulfills_contract`. When `grounding_kind: past-case`,
    `cites_past_case.run_id` and `cites_past_case.contract_ref` are
    required, AND `authority_for_question` must be `partial` (rule
    #14 then caps weight effect at `+`/`-`). Every
    `anchor_consultations[]` entry requires `anchor_id`,
    `anchor_kind`, `grounding_kind`, `result`, `as_of`, and
    `authority_for_question`. Enum constraints per §Anchor
    consultation: authz resolutions exclude `telemetry-baseline`
    from `grounding_kind`; consultations exclude `past-case`.
    *(Absorbs the past-case ⇒ partial enum clause from former #27a;
    #27 retains only the no-sole-grounding rule.)*

12. **(Merged into rule #7.)** Hierarchical hypothesis ID
    consistency — see rule #7.

13. **`ceiling_test` requires severity-ceiling.** Required when
    `termination.category: severity-ceiling`; forbidden otherwise.

14. **`partial` authority caps weight.** A hypothesis resolution
    grounded *solely* by `authorization_resolutions[]`,
    `anchor_consultations[]`, or `impact_resolutions[]` entries with
    `authority_for_question: partial` cannot push weight past `+`
    or `-` regardless of verdict or result. A resolution citing at
    least one `full`-authority entry alongside partial entries is
    *not* capped — the cap fires only when every cited grounding
    entry is partial.

15. **(Merged into rule #1.)** `component_of` sub-vertex
    ID `v-{parent}-{nonce}` shape — see rule #1 (IDs well-formed).

16. **(Merged into rule #17.)** `screen_result` requires `mode:
    screen` — see rule #17 (SCREEN structural integrity).

17. **SCREEN structural integrity.** `outcome.screen_result` is only
    valid on leads where `mode: screen` is set; only the final lead
    in a SCREEN sequence carries `screen_result` (intermediate screen
    leads omit it). When any lead carries `outcome.screen_result:
    match`, the top-level `hypothesize` block must be absent — a
    SCREEN-matched companion does not enumerate hypotheses.
    *(Absorbs former #16 — SCREEN scope and SCREEN-match
    omit-hypothesize collapse into one structural rule.)*

18. **Lead-level predictions structure.** When `lead.predictions` is
    present, each entry has `id` (matching `^lp\d+$`, unique within
    the lead), `if`, `read_as`, `advance_to`. `advance_to` is either
    a lead name appearing elsewhere in the companion, or one of
    `CONCLUDE` / `HYPOTHESIZE`. If the lead is followed by another
    lead in the same companion, the follower's `name` should match
    at least one `advance_to` value — otherwise a route-compliance
    warning is emitted.

19. **(Merged into rule #7.)** Authorization contract `edge_ref`
    resolves — see rule #7 (reference resolution).

20. **(Merged into rule #7.)** Authorization back-reference resolves
    — see rule #7 (reference resolution).

21. **Authorization-gated disposition.** A `conclude.disposition:
    benign` requires every `authorization_contract` across all
    confirmed-weight hypotheses (weight `++` or `+`, status
    `confirmed` or `active`) to have at least one fulfilling
    `authorization_resolutions` entry with `verdict: authorized`.
    Unfulfilled contracts (and not listed in `deferred_authorizations`
    per rule #26), or fulfillments with `verdict: indeterminate`,
    force `status: escalated` and disposition ∈ {`unclear`}. Any
    `verdict: unauthorized` forces `status: escalated` with
    disposition ∈ {`unclear`, `true_positive`}. Replaces the former
    "maintain adversarial hypothesis until `--`" bookkeeping rule.

22. **(Merged into rules #1 and #7.)** Attribute-update target shape
    — exclusivity check (exactly one of `v-{id}` / `e-{id}`) lives
    in rule #1 (schema validity); reference resolution lives in
    rule #7.

23. **Hypothesis fork distinctness.** Within a sibling group —
    hypotheses sharing `(parent_hypothesis_id, attached_to_vertex)` —
    no two may share `proposed_edge.parent_vertex.classification`.
    Duplicates propose the same causal upstream under two ids and
    cannot be discriminated by any lead. The HYPOTHESIZE subagent
    applies a story-diff self-check before emitting (each pair of
    active hypotheses must have at least one observable whose
    predicted value differs); this rule is the structural backstop
    when the check is skipped.

24. **Hypothesis persistence — no orphaned hypotheses at CONCLUDE.**
    When a `conclude:` block is present, every hypothesis declared in
    `hypothesize.hypotheses[]` or any prior `lead.outcome.new_hypotheses[]`
    must either (a) have its final effective weight be `--` across the
    resolutions chain, OR (b) be cited in the conclude block (as the
    termination target, as the matched archetype's mechanism, or as a
    surviving-but-indeterminate hypothesis driving `status: escalated`).
    A hypothesis declared and then silently ignored — never refuted,
    never carried into CONCLUDE — fails this rule. Closes the "silent
    hypothesis drop across loops" bias: grading blindness on one
    mechanism cannot be papered over by forgetting the hypothesis
    existed. The ANALYZE subagent is the proximate enforcer (it
    decides when weights are terminal); this rule is the structural
    backstop at the CONCLUDE write boundary.

25. **Same-level sibling rollup — prediction IDs are hypothesis-scoped.**
    On any `gather[i].resolutions[j]` entry for target hypothesis `H`,
    every id in `matched_prediction_ids[]` must appear in `H`'s own
    declared `predictions[]`. Rule 5 already enforces the equivalent
    for `matched_refutation_ids[]` on `--` resolutions; rule 25
    extends coverage to `matched_prediction_ids[]` on every weight
    and closes the same-level sibling-rollup loophole (upgrading `H`
    on the strength of a sibling's confirmed prediction). Rule 6's
    per-hypothesis coverage aggregation would silently ignore a
    mis-cited ID; rule 25 rejects it loudly so the grade is forced
    to rest on this hypothesis's own evidence.

26. **Authorization contract closure at CONCLUDE.** When a `conclude:`
    block is written, every declared `authorization_contract[]` entry
    across `hypothesize.hypotheses[]` and any
    `lead.outcome.new_hypotheses[]` must either (a) have at least one
    fulfilling entry in the
    effective set of `authorization_resolutions[]`, OR (b) appear in
    `conclude.deferred_authorizations[]` with a non-empty rationale.
    A contract that is declared and silently abandoned — never
    resolved, never deferred — fails this rule. Closes the orphan-
    contract loophole observed in the pre-v2.10 corpus where 59% of
    declared contracts had no resolution; rule #21 gated benign but
    escalation paths silently accepted orphans.

27. **Past-case no-sole-grounding for benign.** On any
    `authorization_contract` that is load-bearing for
    `disposition: benign` (i.e., the hypothesis is confirmed-weight at
    CONCLUDE), at least one fulfilling `authorization_resolutions`
    entry must have `grounding_kind: org-authority` — if every
    fulfilling resolution has `grounding_kind: past-case`, the
    contract is treated as unresolved for rule #21 and escalation is
    forced. *(Former clause (a) — past-case ⇒ partial — moved to
    rule #11 as an enum constraint.)*

28. **Past-case chain depth cap.** An `authorization_resolutions[]`
    entry with `grounding_kind: past-case` references a source
    companion via `cites_past_case.run_id` and an exact prior contract
    via `cites_past_case.contract_ref`. The referenced companion's own
    fulfilling resolution for that contract must have
    `grounding_kind: org-authority` — a past-case companion cannot
    itself cite another past-case as its grounding. Prevents bootstrap
    drift where similar alerts recursively authorize themselves
    without any real policy consultation in the chain.

29. **Impact prediction structure.** Every `impact_predictions[]`
    entry on a lead has `id` matching `^ip\d+$` and unique within the
    lead, plus required fields `dimension` (one of `confidentiality`,
    `integrity`, `availability`, `scope`), `claim`, `on_match`,
    `on_mismatch`, `on_indeterminate`, `escalation_on`. `claim` names
    one observable per entry — compound `AND` / `OR` / semicolon
    predicates must be split across entries. The full cross-lead
    identity of the prediction is `l-{lead_id}.ip{n}`.

30. **Impact resolution back-refs and grounding.** Every
    `impact_resolutions[]` entry on a lead outcome has `prediction_ref`
    resolving to a declared `impact_predictions[]` id somewhere in the
    companion (bare `ip{n}` resolves within the emitting lead; fully
    qualified `l-{id}.ip{n}` resolves across leads). `dimension` must
    match the referenced prediction's `dimension`. `verdict ∈ {within,
    exceeds, indeterminate}`. `grounding_kind ∈ {telemetry-baseline,
    business-owner-attestation, dlp-policy}` — `past-case` is forbidden
    on impact resolutions (impact is per-instance reasoning, not
    category-of-event). Required fields: `prediction_ref`, `dimension`,
    `verdict`, `grounding_kind`, `authority_for_question`, `as_of`,
    `reasoning`.

31. **Impact closure at CONCLUDE.** When a `conclude:` block is
    written, every declared `impact_predictions[]` id across all
    leads must either (a) have at least one fulfilling
    `impact_resolutions[]` entry, OR (b) appear in
    `conclude.deferred_impact_predictions[]` with a non-empty
    rationale. Mirrors rule #26's orphan gate for authorization
    contracts. `conclude.impact_verdict ∈ {none, within, exceeds,
    indeterminate}`; `conclude.impact_severity ∈ {null, low, moderate,
    high}` and is required when `impact_verdict ∈ {exceeds,
    indeterminate}` and forbidden otherwise. Rule #14 (partial
    authority cap) applies to impact resolutions as well.

32. **Integrity peer discipline.** When a hypothesis carries an
    `authorization_contract` AND its
    `proposed_edge.parent_vertex.type` is an acting-entity type
    (`session`, `identity`, `process`), either (a) a sibling
    hypothesis sharing `(parent_hypothesis_id, attached_to_vertex)`
    whose `name` starts with `?adversary-controlled-` must exist, OR
    (b) the contract-carrying hypothesis must carry
    `integrity_waived: <non-empty rationale>`. Non-acting-entity
    parent vertex types (endpoint, file, storage, database, …) are
    exempt. Closes the authorized-bulk-read-from-compromised-account
    shortcut — authz clears, impact clears, but the integrity premise
    was never tested. Integrity resolves through normal weight
    machinery on the peer, not through a separate contract.

33. **Attribute-prediction structure.** Each `attribute_predictions[]`
    entry on a hypothesis has `id` matching `^ap\d+$` (unique within the
    hypothesis), `target` ∈ {`proposed_parent`, `attached_vertex`,
    `proposed_edge`}, `attribute` (non-empty string — the field name
    being predicted), and `claim` (non-empty string, one observable per
    entry — compound `AND` / `OR` predicates split into separate
    entries). `refutation_shape[].refutes_predictions` may cite `ap*`
    ids alongside `p*` ids on the same hypothesis.
    `matched_prediction_ids[]` on a resolution may likewise cite both
    `p*` and `ap*` ids from the target hypothesis.

34. **Prediction closure at CONCLUDE.** When a `conclude:` block is
    written, every declared `predictions[].id` (`p*`) and
    `attribute_predictions[].id` (`ap*`) on a hypothesis whose final
    status is neither `refuted` nor `shelved` (i.e. `active` or
    `confirmed`) must be either (a) cited in some resolution's
    `matched_prediction_ids[]` with a non-null `after`, OR (b) listed
    in `conclude.deferred_predictions[]` with a non-empty `rationale`.
    Each `deferred_predictions[]` entry has
    `prediction_ref: h-{id}.{p|ap}{n}` and `rationale: "<why>"`.
    Late closure gate; rule #6 is the early gate at write time on
    `++` resolutions. Closes the contract analyze owes predict:
    predict pre-commits a prediction set; analyze must address every
    entry by REPORT or the loop owes a justification.

35. **Sibling prediction divergence.** Within a sibling group —
    hypotheses sharing `(parent_hypothesis_id, attached_to_vertex)` —
    no two siblings may declare identical prediction signatures. A
    signature is the union of `predictions[]` `(subject, claim)` and
    `attribute_predictions[]` `(target, attribute, claim)` tuples
    (case-normalised). Identical signatures mean both hypotheses
    propose the same observable expectations and ANALYZE has no
    discriminator to grade them differently — the fork is paraphrase,
    not mechanism. Generalises rule #32 (integrity-peer specific,
    requires shared `proposed_edge` structure and at least one
    `authorization_contract`) to all sibling forks regardless of
    contract presence; complements rule #23 (which blocks shared
    `parent_vertex.classification`) by blocking shared *prediction
    text*. Empty-signature hypotheses are skipped — leanness and
    refutation-link rules cover that shape.

36. **Affirmative true_positive disposition.** When
    `conclude.disposition` is `true_positive`, at least one entry in
    `conclude.surviving_hypotheses[]` must reference a hypothesis
    whose final weight (computed across all resolutions in document
    order) is `++`. When `surviving_hypotheses` is absent or empty,
    every declared hypothesis is candidate.

    The `++` weight is the structural signal of *affirmative grading
    evidence*: per rule #6 + edge-authority discipline, a `++`
    resolution must cite a severe lead resolving against an
    authoritative edge, so the grading is bound to concrete
    observation rather than to absence-of-benign-confirmation. Empirically
    motivated by 4 production runs (see `tasks/analyze-true-positive-
    routing.md`) where ANALYZE routed `true_positive` while no surviving
    hypothesis was graded `++` — every survivor was at `+` or null,
    i.e. no severe-lead refutation/confirmation had landed. The honest
    landing in that shape is `disposition: unclear` (paired with
    `termination_category: severity-ceiling` or
    `exhaustion-escalation`).

    **History.** v2.14 introduced this rule as a two-part check
    (adversarial-classification token + ++). The lexical token list
    desynced from playbook-canonical adversarial fork names — e.g. the
    5710 playbook's `?credentials-used-outside-registered-actor` is
    semantically adversarial (it captures the case where a third party
    used a registered credential string outside the registered actor's
    process), but lacked an allowlisted prefix and produced false
    rejections on legitimately-graded `true_positive` routings (run
    `20260429-202152-rule5710` was the first observed case). v2.16
    drops the classification check; the affirmative-evidence signal is
    fully captured by the `++` weight requirement, and the "wrong-named
    survivor routed true_positive" failure mode is caught by Tier-2
    report judges plus rule #21 (which forces `benign` on every
    `legitimacy_contract: authorized` survivor — a survivor whose
    contracts all resolve `authorized` cannot reach `true_positive`
    without contradicting #21).
