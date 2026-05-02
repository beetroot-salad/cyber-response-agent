# Investigation Language — Agent Reference

Schema v2.15. Validator: `hooks/scripts/invlang_validate.py` (PreToolUse hook on investigation.md writes; 29 active rules across numbering 1–36 with seven preserved-as-redirect gaps). Full spec: `docs/investigation-language.md`. On-disk surface grammar: `docs/dense-investigation-format.md`.

**Surface.** `investigation.md` is `​```invlang` blocks only — `​```yaml` fences are rejected by the validator. Every block tag below projects to a region of the canonical companion dict via `scripts/handlers/_dense_parser.py`; validators and corpus queries operate on the dict.

Three orthogonal resolution axes:

- **Authorization** — *is this edge permitted by policy?* Categorical verdict, single-source-of-truth anchors. Declared as `ac<n>` on a `:H` row, resolved via `:R authz` rows.
- **Integrity** — *is the acting entity what it claims to be?* Evidential, composed from observables. No contract; represented as peer mechanism hypotheses (`?adversary-controlled-*`) with predictions on discriminators.
- **Impact** — *does this edge's effect matter enough to escalate?* Quantitative, threshold-gated. Declared as lead-level `:L l-{id}.impact_preds`, graded at ANALYZE into `:R impact` rows.

CONCLUDE carries both the authz/mechanism axis (`disposition`) and the impact axis (`impact_verdict` + `impact_severity`). Integrity resolves through normal hypothesis weight machinery.

---

## Principles

**Graph discovery.** An investigation constructs a directed graph by working backward from the alert. Confirmed vertices and edges grow monotonically. The investigation halts when the frontier is empty (all active hypotheses resolved) or a trust root is reached — i.e. the lead reports `trust_root?: v-{id}` on its `:L findings` row and no live hypothesis can extend upstream.

**Entities as vertices.** Every observed entity (endpoint, process, identity, session, file…) becomes a typed vertex with a classification and identifier. Model at the resolution the investigation reasons at — don't decompose finer unless a lead forces it. When it does, append sub-vertices via `component_of` with hierarchical IDs (`v-{parent}-{nonce}`); the parent vertex remains valid.

**Relations as edges.** Observed connections and events between entities become edges. Each edge carries observational authority (how reliably the source recorded it) and — when a contract fulfills against it — one or more `:R authz` rows.

**Hypotheses as proposed edges.** A hypothesis proposes that one specific upstream vertex exists, connected to a confirmed vertex by exactly one edge. Predictions describe what observable evidence would confirm or contradict it; keep to 1–2 predictions — the minimum that distinguishes this hypothesis from competing ones. **Prediction scope is unbounded** — predictions may reference observables from any system or time range. The one-hop discipline governs what extends the confirmed graph on `++`, not where evidence may be queried. Cardinality per PREDICT pass is 0–N (realistically ≤ 3); 0 is legal when the loop is enriching before a fork is possible.

**Attributes.** Facts about a vertex that don't add topology stay in the `attrs?` cell of the vertex row, or as `:R attr_updates` rows in a lead outcome. Don't materialize a vertex just to carry an attribute.

**Leads.** A lead is a graph operation: topology-extending (new vertices/edges enter the confirmed graph via `:V`/`:E` observation sub-blocks under the lead) or attribute-refining (existing vertices/edges enriched via `:R attr_updates`), or both. The `tests` cell on `:L findings` declares which hypotheses it discriminates; `:T resolutions` rows record weight effects. A non-branching lead may pre-commit to a reading via `:L l-{id}.lead_preds` (conditional branch plans `if X → read_as Y → advance_to Z`). Leads that measure impact observables carry `:L l-{id}.impact_preds`; ANALYZE grades them into `:R impact` rows.

**Corpus.** Past investigations are queryable. Query before PREDICT to calibrate hypothesis names and weights; set `matched_archetype` at REPORT to connect this run.

---

## Phase-to-block map

| Phase | Block(s) emitted | When |
|---|---|---|
| CONTEXTUALIZE | `:V prologue.vertices`, `:E prologue.edges` | end of CONTEXTUALIZE |
| SCREEN | first lead row in `:L findings` with `mode: screen` | after screen subagent returns |
| PREDICT | `:H hypothesize.hypotheses` (only when ≥ 1 new hypotheses); lead skeleton row in `:L findings` plus `:L l-{id}.impact_preds` when applicable | end of PREDICT |
| GATHER | `:L findings` row populated with query + observation sub-blocks (`:V`, `:E`, `:R consultations`, `:R attr_updates`); no `:T resolutions` yet | end of GATHER |
| ANALYZE | same-lead merge: `:R authz`, `:R impact`, additional `:R attr_updates`; `:T resolutions`; optional `:T shelved` | end of ANALYZE |
| REPORT | `:T conclude` + sub-tables (`:T conclude.surviving`, `:T conclude.deferred_authz`, `:T conclude.deferred_impact`, `:T conclude.deferred_preds`, `:T conclude.ceiling_test`) | after the `## REPORT` header + verdict line, before `report.md` |

Call `invlang --enum` before writing any block that introduces new IDs or references existing ones.

---

## Cell conventions

These apply to every block tag below.

- **Header line:** `:<TAG> <name> [col1|col2|...]`. Cells separated by `|`. Trailing optional cells (suffixed `?`) may be empty; required cells must be filled.
- **Multi-value cells** (`attrs?`, `concerns?`, `citations?`, `trust_chain?`, `conditioning?`): semicolon-separated. `attrs?` items are `key=value`; `concerns?` / `citations?` items are free strings.
- **Quoted strings** in sub-cells: use `"…"`. Embedded `]` inside an annotation must be written as `\]`.
- **Empty arrays / absent fields:** omit the row entirely, or render as a single `none` row when the rule that consumes the block specifically requires the absence to be declared (e.g. `:T conclude.deferred_authz` carries `none` when no contract is deferred).

---

## Top-level structure

```
:V prologue.vertices    — vertices derived from the alert
:E prologue.edges       — edges derived from the alert
:H hypothesize.hypotheses — initial proposed frontier (omit when PREDICT authors 0 new hypotheses)
:L findings             — one row per lead; same id merges across GATHER/ANALYZE
  (per-lead sub-blocks: :V/:E/:R/:T scoped by l-{id})
:T conclude (+ sub-tables) — REPORT termination, disposition, deferreds
```

Leads in the same iteration share a `loop` cell value; there is no grouping wrapper.

`:H hypothesize.hypotheses` is omitted entirely when SCREEN matches (no fork is opened) or when a PREDICT pass authors 0 new hypotheses.

---

## Vertex — `:V`

```
:V <block> [id|type|class|ident|attrs?|placeholder?|concerns?|citations?]
```

Used by:
- `:V prologue.vertices` (CONTEXTUALIZE)
- `:V l-{id}.observations.vertices` (GATHER, scoped under a lead)

| Cell | Required | Shape / enum | Notes |
|---|---|---|---|
| `id` | yes | `^v-\d+(-\d+)*$` | Sub-vertex IDs use `v-{parent}-{nonce}` (e.g. `v-001-01`) and encode containment. Append-only. |
| `type` | yes | from §Type vocabulary | |
| `class` | yes | seed list or `{type}:{slug}` provisional | classification |
| `ident` | yes | string | human-readable primary key |
| `attrs?` | no | `key=value;key=value` | type-specific |
| `placeholder?` | no | `true` | omit when false; used when a lifecycle edge requires two endpoints but one is unobservable. Never mutate; if a later lead identifies the real entity, append a new vertex linked via `identified_as`. |
| `concerns?` | no | `item;item` | reliability, scope, or interpretation traps |
| `citations?` | no | `item;item` | source references; omit if implicit |

Trust-root signaling lives on the `:L findings` row's `trust_root?` cell and `:T conclude termination.category`, not on vertices.

Example:

```
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|monitoring-host|172.22.0.10|
v-002|endpoint|internal-server|target-endpoint|
```

---

## Edge — `:E`

```
:E <block> [id|rel|src|tgt|when|auth_kind:source|attrs?|status?|trust_chain?|concerns?]
```

Used by:
- `:E prologue.edges`
- `:E l-{id}.observations.edges`

| Cell | Required | Shape / enum | Notes |
|---|---|---|---|
| `id` | yes | `^e-\d+$` | append-only |
| `rel` | yes | from §Relation catalog | |
| `src` | yes | `v-{id}` | source vertex |
| `tgt` | yes | `v-{id}` | target vertex |
| `when` | yes (or empty) | ISO timestamp | empty when not meaningful |
| `auth_kind:source` | yes | `<kind>:<source>` packed | `kind ∈ {siem-event, runtime-audit, authoritative-source, client-asserted, inferred-structural}`. **Observational** authority — distinct from authz `grounding_kind` and from `:R consultations.grounding`. |
| `attrs?` | no | `key=value;key=value` | edge attributes |
| `status?` | no | `hypothesized` \| `refuted` | omit (defaults to `observed`) |
| `trust_chain?` | no | `item;item` | when set, a `client-asserted` edge gets effective `authoritative-source` authority. |
| `concerns?` | no | `item;item` | |

Authority cap: `client-asserted` and `inferred-structural` cap resolutions citing this edge at `+`/`-`. `siem-event`, `runtime-audit`, `authoritative-source` support `++`/`--` (rule #4).

**Authorization on edges.** Authorization verdicts live in `:R authz` rows (see §Resolutions below), not on the `:E` row itself. When a hypothesis declares an `ac<n>` and the resolving lead materializes the proposed edge, the new edge gets `:R authz` rows in the same lead's outcome. When a contract resolves against an *already-confirmed* edge, the resolving lead writes the verdict via a `:R attr_updates` row whose `value` cell points to a sibling `:R authz` row whose `edge` cell names the confirmed edge — never by mutating the original edge record.

Example:

```
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event:wazuh-indexer|target_user=sensu;outcome=failed
```

---

## Hypothesis — `:H`

```
:H <block> [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status|concerns?]
```

Used by:
- `:H hypothesize.hypotheses` (top-level proposed frontier from PREDICT)
- `:H l-{id}.new_hypotheses` (born inside a lead — same column shape)

| Cell | Required | Shape / enum | Notes |
|---|---|---|---|
| `id` | yes | `^h-\d+(-\d+)*$` | child refinements: `h-{parent}-{nonce}` (e.g. `h-001-001`). |
| `name` | yes | `?descriptive-slug` | leading `?` is convention. |
| `attached_to` | yes | `v-{id}` | confirmed vertex this one-hop extension grafts onto. |
| `rel` | yes | from §Relation catalog | the proposed edge's relation. |
| `parent_type` | yes | from §Type vocabulary | causal upstream's type. |
| `parent_class` | yes | string | causal upstream's classification. Sibling-fork uniqueness gate (rule #23). |
| `parent_attrs?` | no | `key=value;key=value` | omit if empty. |
| `preds` | yes | `p<n>:<subject>:"<claim>"`, `;`-separated | `subject ∈ {proposed_parent, attached_vertex, proposed_edge}`. Source-agnostic claim about world state. |
| `attr_preds?` | no | `ap<n>:<target>:<attribute>:"<claim>"`, `;`-separated | `target ∈ {proposed_parent, attached_vertex, proposed_edge}`. Per entry: one observable attribute (e.g. `cmdline`, `parent_pname`, `tty`). Claim is one assertion; compound AND/OR splits into separate entries. |
| `refuts?` | no | `r<n>[<id>,<id>]:"<claim>"`, `;`-separated | bracketed list cites the `p<n>` / `ap<n>` IDs on this hypothesis that this refutation contradicts. Non-empty bracket required. |
| `authz?` | no | `ac<n>:<edge_ref>:<anchor_kind>:"<predicate>":<on_unauth>/<on_indet>`, `;`-separated | `edge_ref ∈ {proposed, e-{id}}`. Predicate is natural-language (any AND/OR allowed). `on_unauth` / `on_indet` ∈ `{escalate}` today. |
| `integrity_waived?` | no | string | rationale; required when `authz?` is set on a hypothesis whose `parent_type` is an acting-entity type (`session` / `identity` / `process`) AND no peer `?adversary-controlled-*` exists in the same sibling group (rule #32). |
| `weight` | yes | `null` \| `++` \| `+` \| `-` \| `--` | `null` initial. |
| `status` | yes | `active` \| `confirmed` \| `refuted` \| `shelved` | |
| `concerns?` | no | `item;item` | residuals, unfalsifiability caveats. |

**Lean means 1–2 predictions.** A single prediction captures the core discriminating claim. Add a second only when two independent facts each partially confirm the hypothesis and neither alone suffices. Three+ predictions usually signals either a non-lean hypothesis or a refinement that should be deferred.

**Authorization contract semantics.** Declare `ac<n>` only when the mechanism is consistent with both benign and adversarial readings depending on authorization; when the adversarial reading IS the mechanism (e.g. `?adversary-controlled-process`), skip the contract — the classification already carries the claim. Mechanism-level adversarial variants stay separate hypotheses.

**Behavioral-consistency prediction (optional).** A contract resolved `authorized` establishes policy compliance, not integrity. The hypothesis MAY carry one baseline-consistency `ap<n>` — positive ("expect corroborating activity X") or negative ("expect NOT to see >Nσ volume deviation"). Gates: baseline queryable, scoped to the alert's entities, weight-sensitive. Severity caps at `moderate`. Unavailable baseline → `indeterminate` in `concerns?`; do not confabulate.

### Integrity discipline

When `authz?` is set and `parent_type` is an acting-entity type (`session`, `identity`, `process`), a peer integrity hypothesis (`?adversary-controlled-<entity>`) is expected — its predictions test whether the claimed entity is actually the one acting (application-layer correlation, query-shape template match, timing against baseline, device/geo consistency). The peer shares the authz contract's verdict (both `authorized` against IAM) and differs on observables that discriminate routine activity from impostor activity.

Omit the peer only when the integrity premise is out of scope for the case; in that case, set `integrity_waived?` to the rationale.

---

## Lead — `:L`

The lead has one header row in `:L findings` plus zero or more lead-scoped sub-blocks (all sub-block names are namespaced by the lead id).

### Header row

```
:L findings [id|loop|name|target|mode?|tests|system|template|query|window|trust_root?|fail_reason?|screen_result?|selection_rationale?]
```

| Cell | Required | Shape / enum | Notes |
|---|---|---|---|
| `id` | yes | `^l-\d+$` | append-only across phases |
| `loop` | yes | int | leads in the same iteration share a value |
| `name` | yes | string | |
| `target` | yes | `v-{id}` | vertex this lead operates on |
| `mode?` | no | `screen` | omit unless dispatched by the SCREEN subagent |
| `tests` | yes (or empty) | `h-{id},h-{id}` (CSV) | hypotheses this lead discriminates; empty for non-branching leads |
| `system` | yes | string | query system |
| `template` | yes | string | query template name |
| `query` | yes | string | rendered query |
| `window` | yes (or empty) | string | time window e.g. `30d` |
| `trust_root?` | no | `v-{id}` | set when the lead reaches a vertex with no accessible upstream |
| `fail_reason?` | no | `adapter-error` \| `attribution-opaque` \| `partial-coverage` \| `permission-denied` \| `timeout` \| `other` | omit unless errored or degraded |
| `screen_result?` | no | `match` \| `no_match` | only valid when `mode=screen` and only on the final screen lead in the sequence (rule #17) |
| `selection_rationale?` | no | string (1–3 sentences) | inter-lead strategic reasoning. Omit for first lead and for SCREEN leads. |

### Lead-scoped sub-blocks

All sub-block names are prefixed with the lead's `l-{id}.`.

**Observations** (topology-extending):
- `:V l-{id}.observations.vertices` — same shape as `:V prologue.vertices`
- `:E l-{id}.observations.edges` — same shape as `:E prologue.edges`

**Query substitutions:**

```
:L l-{id}.substitutions [key|value]
```

**Lead-level branch plans** (non-branching but interpretation-vulnerable leads):

```
:L l-{id}.lead_preds [id|if|read_as|advance_to]
```

| Cell | Shape |
|---|---|
| `id` | `^lp\d+$`, unique within the lead |
| `if` | quoted outcome pattern |
| `read_as` | quoted interpretation |
| `advance_to` | a lead `name` in the companion, or `REPORT`, or `PREDICT` |

Lead-level predictions are not a substitute for hypothesis-level predictions: hypothesis predictions test world models; lead-level `lp*` are decision rules on a shared next-step lead. Use when the same step-1 lead applies regardless of which hypothesis is true and the *reading* of the outcome determines step-2.

**Impact predictions** (commit-before-evidence):

```
:L l-{id}.impact_preds [id|dimension|claim|on_match|on_mismatch|on_indeterminate|escalation_on]
```

| Cell | Shape / enum |
|---|---|
| `id` | `^ip\d+$`, unique within the lead |
| `dimension` | `confidentiality` \| `integrity` \| `availability` \| `scope` |
| `claim` | quoted threshold predicate; one observable per claim — split compound AND/OR into separate `ip*` |
| `on_match` | `within` |
| `on_mismatch` | `exceeds` |
| `on_indeterminate` | `indeterminate` |
| `escalation_on` | `exceeds` \| `indeterminate` \| `none` |

**Hypotheses born inside the lead:**

```
:H l-{id}.new_hypotheses [...same columns as :H hypothesize.hypotheses...]
```

**Hypotheses dropped from the live frontier by this lead:**

```
:T l-{id}.shelved [hyp_id|by_lead|rationale]
```

(Or simply `:T shelved` when context disambiguates the owning lead.)

### Resolutions

See §Resolutions — `:R` and §Proof trace — `:T resolutions` below.

---

## Resolutions — `:R`

Four sub-types. The first three resolve grounding against an anchor; the fourth records vertex/edge enrichment. All belong under the resolving lead's phase block.

### `:R authz` — authorization contract verdicts

```
:R authz [edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|effective_window?|fulfills|resolved_by|cites_past_case?|conditioning?|concerns?]
```

| Cell | Required | Shape / enum | Notes |
|---|---|---|---|
| `edge` | yes | `e-{id}` | the resolved edge |
| `verdict` | yes | `authorized` \| `unauthorized` \| `indeterminate` | |
| `anchor_kind` | yes | string | authority surface: `iam-policy` \| `data-classification-policy` \| `oncall-schedule` \| `deploy-runs` \| `approved-monitoring-sources` \| … |
| `anchor_id` | yes | string | concrete authority identifier |
| `grounding` | yes | `org-authority` \| `past-case` | `telemetry-baseline` not admissible — baselines answer expectation, not authorization |
| `authority` | yes | `full` \| `partial` | `partial` caps weight effect at `+`/`-` (rule #14) |
| `as_of` | yes | ISO | timestamp the answer is authoritative ABOUT |
| `effective_window?` | no | `<iso>..<iso>` | when the authz grant has explicit time bounds |
| `fulfills` | yes | `h-{id}.ac{n}` | back-reference to the declaring hypothesis's contract |
| `resolved_by` | yes | `l-{id}` | the resolving lead |
| `cites_past_case?` | no | `<run-id>:h-{id}.ac{n}` | required when `grounding=past-case` |
| `conditioning?` | no | `item;item` | then-true premises the verdict rests on (e.g. `CHG-2041 active`, `oncall X`) |
| `concerns?` | no | `item;item` | snapshot freshness, partial coverage |

Plural rows because real edges often face parallel policy layers (IAM × data-classification × time-of-day) — each resolved independently by a different anchor; any one can deny.

### `:R consultations` — anchor consultations (non-authz)

Used when a lead's anchor query informs hypothesis weight but does *not* fulfill an `ac<n>` (baseline lookups, registry membership checks, reference queries).

```
:R consultations [anchor_id|anchor_kind|grounding|result|as_of|authority|effective_window?|anchor_query?|conditioning?|concerns?]
```

| Cell | Required | Shape / enum | Notes |
|---|---|---|---|
| `anchor_id` | yes | string | |
| `anchor_kind` | yes | string | vendor surface: `image-baseline`, `user-cadence`, `asset-inventory`, `sensitive-data-registry`, … |
| `grounding` | yes | `org-authority` \| `telemetry-baseline` | `past-case` not admissible — past-case citations are authz-only |
| `result` | yes | `confirmed` \| `refuted` \| `partial` \| `no-data` | |
| `as_of` | yes | ISO | |
| `authority` | yes | `full` \| `partial` | |
| `effective_window?` | no | `<iso>..<iso>` | |
| `anchor_query?` | no | string | human-readable record of what was asked |
| `conditioning?` | no | `item;item` | |
| `concerns?` | no | `item;item` | snapshot freshness, coverage caveats |

### `:R impact` — impact prediction verdicts

ANALYZE emits one row per fulfilled `:L l-{id}.impact_preds` entry.

```
:R impact [pred_ref|dim|observed|verdict|matched_pred|grounding|anchor_id|anchor_kind|authority|as_of|effective_window?|conditioning?|reasoning]
```

| Cell | Required | Shape / enum | Notes |
|---|---|---|---|
| `pred_ref` | yes | `l-{id}.ip{n}` | back-reference to the lead's impact prediction |
| `dim` | yes | matches the `ip*` `dim` | |
| `observed` | yes | string | quantitative or qualitative observation |
| `verdict` | yes | `within` \| `exceeds` \| `indeterminate` | |
| `matched_pred` | yes | quoted | verbatim predicate from `ip*` |
| `grounding` | yes | `telemetry-baseline` \| `business-owner-attestation` \| `dlp-policy` | `past-case` not admissible — impact is per-instance, not category-of-event |
| `anchor_id` | yes | string | |
| `anchor_kind` | yes | string | |
| `authority` | yes | `full` \| `partial` | |
| `as_of` | yes | ISO | |
| `effective_window?` | no | `<iso>..<iso>` | |
| `conditioning?` | no | `item;item` | |
| `reasoning` | yes | quoted | why this verdict; not a field restatement |

### `:R attr_updates` — vertex / edge enrichment

```
:R attr_updates [target|key|value]
```

| Cell | Required | Shape / enum | Notes |
|---|---|---|---|
| `target` | yes | `v-{id}` \| `e-{id}` | exactly one |
| `key` | yes | string | attribute name |
| `value` | yes | string | when target is an edge and the update is an authorization resolution, emit a separate `:R authz` row whose `edge` cell points to the targeted edge and set this row's `value` to `<see :R authz row>` |

Use `:R attr_updates` when the lead enriches an already-confirmed vertex or edge without new topology. Use `:V` / `:E` observation sub-blocks when new topology enters the confirmed graph. Both may appear in the same lead.

### Anchor consultation vs authorization resolution

| Row | Where it lives | When to use |
|---|---|---|
| `:R authz` | under the lead that fulfilled the contract; `edge` cell names the resolved edge | the query produces a verdict that fulfills an `ac<n>` declared on some hypothesis |
| `:R consultations` | under the resolving lead | the query informs hypothesis weight but does not fulfill a contract |

Authorization rows gate disposition (rule #21); consultations ground evidence weight via `:T resolutions` rows the same way any other observation does. Temporal validity (`as_of`, `effective_window?`), authority scope (`authority`), and conditioning (`conditioning?`) mean the same thing in both rows; only the verdict/contract-fulfillment machinery is authz-only.

`as_of` is the timestamp the answer is **authoritative about** — not the query time unless they coincide. Event anchors (did X happen at T?) → event timestamp. Current-state anchors (is property X true now?) → query / snapshot time. Slowly-changing references → last-modified time.

`effective_window?` is set when the anchor's answer has explicit time bounds. On a `:R authz` row, the validator checks that the resolved edge's timestamp falls inside `[start, end]`; mismatch demotes the verdict to `indeterminate`.

`grounding` distinguishes provenance from policy surface: `anchor_kind` says *what* authority surface (`iam-policy`, `oncall-schedule`, `image-baseline`); `grounding` says *what sort of source* produced the answer.

`grounding=past-case` (only on `:R authz`) is a weak-temporal authz source citing a prior companion's contract. Force-caps `authority` to `partial` (rule #11), cannot be sole grounding for benign disposition (rule #27), cannot chain on another past-case (rule #28). `cites_past_case?` names the source companion + contract.

---

## Proof trace — `:T resolutions`

One line per hypothesis weight transition.

```
:T resolutions
<hyp-id>  <before> → <after>    [<lead-id> <pred/refut-ids> <severity_of_test> ⟂ <supp-edges-or-marker> :: <annotation>]
```

| Token | Shape / enum | Notes |
|---|---|---|
| `<before>` / `<after>` | `∅` \| `++` \| `+` \| `-` \| `--` | `∅` for null |
| `<lead-id>` | `l-{id}` | resolving lead |
| `<pred/refut-ids>` | `p1,p2 r1` (CSV within type, space between types) | every cited `p*` / `ap*` must belong to *this* hypothesis (rule #25); `--` requires non-empty `r*` (rule #5) |
| `<severity_of_test>` | `severe` \| `moderate` \| `weak` | pre-result discriminating power. `severe` = direct field-read on an authoritative source for the load-bearing field; `moderate` = direct read with known coverage gaps; `weak` = downstream / co-occurrence / population baseline. `++`/`--` ⇒ `severe` (structural). |
| `<supp-edges-or-marker>` | `e-{id}[,e-{id}]` \| `no-authority` \| `partial-authority` | edges cited; rule #4 requires at least one edge of `siem-event` / `runtime-audit` / `authoritative-source` authority for `++`/`--` |
| `<annotation>` | free text | terse checklist version of the lead-resolution's reasoning. The surrounding `## ANALYZE` paragraph carries the prose — both surfaces required: validator checks the cell, agent reads the prose. Annotation runs from `::` to the last unescaped `]` on the row; embedded `]` writes as `\]`. |

**Prediction completeness for `++`** (rule #6): per-hypothesis union of `p*` + `ap*` tokens across `++` resolution rows must equal the full prediction set declared on the hypothesis's `:H` row. Partial coverage caps at `+`. Rule #34 generalises this into a coverage gate at REPORT regardless of weight.

**Optional load-bearing structured cells.** Empirical: forcing per-resolution structured load-bearing fields on every `++`/`--` increased false-true-positive rate on absence-of-confirmation traps. The annotation cell is the captured artifact; no structural validator runs on a separate load-bearing schema.

---

## Conclude — `:T conclude` (+ sub-tables)

REPORT writes a flat `:T conclude` key/value block plus required sub-tables. Each scalar row is `<key><spaces><value>`; quoted strings use `"..."`. All validator rules (#13, #21, #24, #26, #31, #34, #36) are unchanged from the prior surface.

| Key | Enum / shape | Notes |
|---|---|---|
| `termination.category` | `trust-root` \| `adversarial-refuted` \| `severity-ceiling` \| `exhaustion-escalation` | |
| `termination.rationale` | quoted sentence | |
| `disposition` | `benign` \| `true_positive` \| `unclear` | authz/mechanism axis |
| `impact_verdict` | `none` \| `within` \| `exceeds` \| `indeterminate` | impact axis |
| `impact_severity` | `null` \| `low` \| `moderate` \| `high` | required (non-`null`) when `impact_verdict ∈ {exceeds, indeterminate}` |
| `confidence` | `high` \| `medium` \| `low` | |
| `matched_archetype` | `<archetype-name>` \| `null` | archetype directory under `knowledge/signatures/{sig}/archetypes/{name}/` |
| `ceiling_rationale` | quoted string \| `n/a` | required (non-`n/a`) when `termination.category=severity-ceiling` |
| `summary` | quoted one-sentence string | |

Sub-tables (one row per entry; render as a single `none` row when the underlying array is empty; omit the sub-table entirely when the underlying field is absent — preserves the missing-vs-empty distinction). Headers and rules:

| Sub-table | Header | When required | Row shape |
|---|---|---|---|
| surviving hypotheses (rule #24) | `:T conclude.surviving [hyp_id\|final_weight]` | always; lists every declared hypothesis whose final weight is not `--` | `h-{id}\|<weight>` |
| deferred authz (rule #26) | `:T conclude.deferred_authz [contract_ref\|rationale]` | when any declared `ac*` has no fulfilling `:R authz` row | `h-{id}.ac{n}\|"<why unresolved>"` |
| deferred impact (rule #31) | `:T conclude.deferred_impact [prediction_ref\|rationale]` | when any declared `:L l-*.impact_preds` row has no fulfilling `:R impact` row | `l-{id}.ip{n}\|"<why unresolved>"` |
| deferred preds (rule #34) | `:T conclude.deferred_preds [prediction_ref\|rationale]` | for every `p*`/`ap*` on a non-refuted hypothesis without a graded resolution | `h-{id}.{p\|ap}{n}\|"<why ungraded>"` |
| ceiling test (rule #13) | `:T conclude.ceiling_test [kind\|subject]` | required (single non-`none` row) when `termination.category=severity-ceiling`; forbidden otherwise | `<kind>\|<subject>` where `kind ∈ {out-of-band-human-contact, tool-unavailable, legal-authorization, other}` |

**Two-axis disposition.** `disposition` and `impact_verdict` combine orthogonally:

| disposition | impact_verdict | Meaning |
|---|---|---|
| benign | within | Routine activity, no escalation |
| benign | exceeds | **Authorized-but-malifying** — mechanism confirmed benign; consequence exceeds threshold. Analyst review on impact |
| true_positive | within | Confirmed threat whose consequence stayed bounded (failed probe, denied access) |
| true_positive | exceeds | Confirmed threat with realized consequence. Highest-severity class |
| unclear | \* | Mechanism indeterminate; impact verdict still recorded for handoff |

`impact_severity` rolls up across fulfilling `:R impact` rows, capped by any `authority=partial` per rule #14.

**Authorization-gated disposition** (rule #21). `disposition: benign` requires every `ac<n>` on a confirmed-weight hypothesis (`++` or `+`, status `confirmed` or `active`) to have at least one fulfilling `:R authz` row with `verdict=authorized`. Any unfulfilled contract (absent from `:T conclude.deferred_authz`) or `verdict=indeterminate` caps at `unclear`. Any `verdict=unauthorized` forces disposition ∈ {`unclear`, `true_positive`}.

**Affirmative `true_positive`** (rule #36). `disposition: true_positive` requires at least one entry in `:T conclude.surviving` to reference a hypothesis whose final weight is `++`. Closes the absence-of-benign-confirmation cascade — `++` is the structural signal of affirmative grading evidence (rule #6 + edge-authority discipline). If no survivor is graded `++`, the honest landing is `disposition: unclear` (paired with `termination_category: severity-ceiling` or `exhaustion-escalation`).

**Termination categories.**
- `trust-root` — confirmed graph reached a vertex with no accessible upstream; frontier collapsed.
- `adversarial-refuted` — every adversarial hypothesis was explicitly refuted by confirmed evidence.
- `severity-ceiling` — live hypotheses remain but their critical edges cannot be tested with available tools. `:T conclude.ceiling_test` records the out-of-band step that would resolve it.
- `exhaustion-escalation` — loop budget exhausted.

---

## Observation conventions

**Lifecycle vs action.** Is the observation's natural noun an invocation? → `command` vertex with `executed_in → session` and `targeted → <thing>`. Is it an entity whose later state the investigation reasons about? → lifecycle (typed vertex + edge verb). CRUD operations (`CreateUser`, `DeleteObject`, `GetObject`) are uniformly action-shaped.

**Aggregate observations.** N occurrences of the same thing → single edge with `count` and `window_*` in `attrs?`. Do not materialize one vertex per occurrence.

---

## Type vocabulary

| Type | Notes |
|---|---|
| `endpoint` | Compute unit with OS. IP-only: `attrs?` carries `knowledge=partial` |
| `process` | Running execution unit |
| `thread` | Sub-entity of process; `component_of` + hierarchical ID |
| `memory-region` | Sub-entity of process; `component_of` + hierarchical ID |
| `module` | Loaded library/DLL; `component_of` |
| `container` | Runtime container |
| `session` | Authenticated interactive or API session |
| `identity` | `attrs?` carries `kind ∈ {user, group, role, service-account, application}` |
| `storage` | `attrs?` carries `kind ∈ {object-store, block, file, secrets, nfs}` |
| `database` | Structured data system with query interface |
| `network-device` | Firewall, switch, router, load balancer, WAF |
| `file` | Specific file artifact |
| `command` | Audited invocation (action-shaped observation) |
| `socket` | Network socket (transport-layer) |

Acting-entity types (trigger §Integrity discipline when an `ac<n>` is declared with `parent_type` from this group): `session`, `identity`, `process`.

Use `unclassified-{type}` when unknown; `ambiguous-{a}-or-{b}` when genuinely indistinguishable.

---

## Relation catalog

| Relation | Source → Target | Notes |
|---|---|---|
| `spawned` | process → process | |
| `executed` | process → file | |
| `loaded_by` | process → file | Modules/libraries |
| `opened` | process → socket | |
| `connected_to` | socket → endpoint | Transport-layer only |
| `read` / `wrote` | process → file | |
| `runs_in` | process → container | |
| `runs_on` | process \| container \| database \| session → endpoint | Compute-substrate containment |
| `authenticated_as` | session → identity | |
| `initiated_by` | session → identity \| endpoint | |
| `triggered_by` | process \| session → process \| session | |
| `escalated_privilege` | session → session | Self-edge |
| `executed_in` | command → session | |
| `targeted` | command → endpoint \| storage \| database \| identity \| file \| container \| network-device | Action-target for command vertices |
| `member_of` | identity → identity | User→group, role→bundle |
| `identified_as` | placeholder → real-vertex | Post-hoc attribution; never mutate the placeholder |
| `component_of` | vertex → vertex | Part-of for inward decomposition; sub-entity → container |
| `listed` | session \| process → storage \| database | Enumeration (provisional) |
| `modified` | session \| process → storage \| database \| identity \| file | State change (provisional) |
| `attempted_auth` | endpoint \| process \| session → endpoint | Auth attempt, may be failed (provisional) |
| `classified_as` | vertex → classification-value | |

---

## Examples

A complete worked investigation showing the surface end-to-end. The case: a failed SSH brute-force from an external IP (`203.0.113.47`) against an internal web server, where `?opportunistic-scanner` is the sole hypothesis. The source-classification lead refutes the scanner reading (the IP authenticated successfully against the same target six hours prior), grading `h-001` to `--`. CONCLUDE lands `benign` with `adversarial-refuted` termination — no surviving hypothesis, no contract closure required.

```invlang
:V prologue.vertices [id|type|class|ident|attrs]
v-001|endpoint|external-unknown|203.0.113.47|
v-002|endpoint|internal-server|web-server-01|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs]
e-001|attempted_auth|v-001|v-002||siem-event:wazuh-indexer|

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs|preds|attr_preds|refuts|authz|integrity_waived|weight|status]
h-001|?opportunistic-scanner|v-001|initiated_by|identity|automated-scanner||p1:proposed_parent:"source IP appears in threat-intel scanner list"||r1[p1]:"source IP authenticated previously in last 90d"|||null|

:L findings [id|name|loop|target|mode|system|template|query|window|status]
l-001|source-classification|1|v-001|graded|wazuh-indexer|source-ip-lookup|src_ip:203.0.113.47|30d|

:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs]
e-002|classified_as|v-001|v-002||siem-event:wazuh-indexer|

:R attr_updates [resolved_by|target|key|value]
l-001|v-001|classification|external-unknown

:T resolutions
h-001  null → --    [l-001 r1 strong ⟂ e-001 :: source IP authenticated from web-server-01 six hours prior — refutation r1 matched]

:T conclude
termination.category   adversarial-refuted
termination.rationale  "All adversarial hypotheses refuted with -- evidence"
disposition            benign
impact_verdict         none
impact_severity        null
confidence             high
matched_archetype      external-bruteforce
summary                "SSH brute force from external scanner; no successful auth"

:T conclude.surviving [hyp_id|final_weight]
none
```

Notes on this run:

- The trace line `h-001  null → --    [l-001 r1 strong ⟂ e-001 :: …]` is the proof-trace canonical form: `<hyp> <before> → <after>    [<lead> <pred/refut-ids> <severity> ⟂ <supp-edges> :: <annotation>]`. `r1` is cited (rule #5 requires `--` rows to cite at least one refutation belonging to the target hypothesis); `e-001` is `siem-event` authority (rule #4 admits `++`/`--` only against `siem-event` / `runtime-audit` / `authoritative-source`).
- `surviving: none` is correct here — `h-001` reached `--` so it is not a survivor. Rule #24 (hypothesis persistence) accepts this because every declared hypothesis was either graded `--` or listed.
- No `authorization_contract` was declared (`?opportunistic-scanner` is an adversarial-mechanism hypothesis — the classification carries the claim per §Hypothesis), so rule #21 / rule #26 don't gate this disposition.
- Companion examples covering the contract-resolution path (`:R authz` + an integrity peer), lead-level branch plans (`:L l-{id}.lead_preds`), and impact predictions (`:L l-{id}.impact_preds` + `:R impact`) live in `docs/dense-investigation-format.md`. Note: rule-#21 closure against a `:R authz` row currently has a parser↔validator gap (see `tasks/dense-r-authz-parser-validator-gap.md`); production runs continue to use the inline-on-edge `authorization_resolutions` shape until that gap closes.

---

## Key rules

The validator enforces **29 active rules** (numbering 1–36). Numbers #10, #12, #15, #16, #19, #20, #22 are gaps — those rules were either merged into a sibling rule (numbering preserved as redirects) or demoted to review-only discipline. Rule #36 (v2.14, affirmative `true_positive` disposition) is the most recent addition.

1. **Schema validity.** Required cells filled, enums valid, IDs well-formed (including hierarchical patterns for hypotheses, sub-vertices `v-{parent}-{nonce}`, and the `:R attr_updates target` exclusivity — exactly one of `v-{id}` / `e-{id}`).
2. **Classification vocabulary.** Every `class` cell is from the seed vocabulary or a `{type}:{slug}` provisional.
3. **Relation catalog.** Every `:E` `rel` and `:H` `rel` cell appears in the relation catalog.
4. **Edge authority.** `++`/`--` rows in `:T resolutions` cite at least one supporting edge whose `auth_kind` is `siem-event`, `runtime-audit`, or `authoritative-source`.
5. **Refutation IDs.** Every `--` row in `:T resolutions` cites at least one `r*` token belonging to the target hypothesis.
6. **Prediction completeness for `++`.** Per-hypothesis union of `p*`/`ap*` tokens across `++` rows in `:T resolutions` equals the hypothesis's full prediction set. Partial coverage caps at `+`. Early gate at write time; rule #34 is the late closure gate.
7. **Reference resolution.** Every `v-*` / `e-*` / `h-*` / `l-*` reference points to a declared record. Hierarchical hypothesis IDs `h-{parent}-{nonce}` require the parent. `ac<n> edge_ref` is `proposed` or an existing `e-*`. `:R authz fulfills` of shape `h-{id}.ac{n}` resolves to a declared contract. `:R attr_updates target` resolves. *(Absorbs former #12, #19, #20, and the resolution clause of former #22.)*
8. **Append-only.** No existing record is mutated.
9. **Lead block self-containment.** Every vertex, edge, or hypothesis produced by a lead lives inside that lead's `:V`/`:E`/`:H` sub-blocks or `:T shelved`.
10. *(Demoted to review-only.)* Mechanical leads stay within their data source — semantic guideline retained in the spec, not validator-enforced.
11. **Anchor-query provenance completeness.** Every `:R authz` row requires `verdict`, `anchor_kind`, `anchor_id`, `grounding`, `authority`, `as_of`, `resolved_by`, and `fulfills`. When `grounding=past-case`, `cites_past_case?` is required AND `authority` must be `partial`. Every `:R consultations` row requires `anchor_id`, `anchor_kind`, `grounding`, `result`, `as_of`, `authority`. Enum constraints: `:R authz` excludes `telemetry-baseline` from `grounding`; `:R consultations` excludes `past-case`. *(Absorbs the past-case ⇒ partial enum clause from former #27a.)*
12. *(Merged into rule #7.)* Hierarchical hypothesis ID consistency.
13. **`ceiling_test` requires severity-ceiling.** Required when `:T conclude termination.category=severity-ceiling`; forbidden otherwise.
14. **Partial authority caps weight.** A `:T resolutions` row whose every cited `:R` row has `authority=partial` cannot push weight past `+` or `-` regardless of verdict or result.
15. *(Merged into rule #1.)* `component_of` sub-vertex `v-{parent}-{nonce}` shape.
16. *(Merged into rule #17.)* `screen_result` scope.
17. **SCREEN structural integrity.** `:L findings screen_result?` is only valid on `mode=screen` rows, only on the final lead in a SCREEN sequence. SCREEN-matched companions (any lead with `screen_result=match`) omit the `:H hypothesize.hypotheses` block. *(Absorbs former #16.)*
18. **Lead-level predictions structure.** Each `:L l-{id}.lead_preds` row has `id` (`^lp\d+$`, unique within the lead), `if`, `read_as`, `advance_to`. `advance_to` is a lead `name` in the companion, or `REPORT`, or `PREDICT`.
19. *(Merged into rule #7.)* Authorization contract `edge_ref` resolves.
20. *(Merged into rule #7.)* Authorization back-reference resolves.
21. **Authorization-gated disposition.** `:T conclude disposition=benign` requires every `ac<n>` across confirmed-weight hypotheses (`++` or `+`, status `confirmed` or `active`) to have at least one fulfilling `:R authz` row with `verdict=authorized`. Unfulfilled contracts (and not listed in `:T conclude.deferred_authz`, per rule #26), or `verdict=indeterminate`, cap disposition at `unclear`. Any `verdict=unauthorized` forces disposition ∈ {`unclear`, `true_positive`}.
22. *(Merged into rules #1 and #7.)* Attribute-update target shape.
23. **Hypothesis fork distinctness.** Within a sibling group — hypotheses sharing `(parent_hypothesis_id, attached_to)` — no two may share `parent_class`.
24. **Hypothesis persistence at CONCLUDE.** Every declared hypothesis whose final effective weight is not `--` appears in `:T conclude.surviving`. Silent drops are rejected.
25. **Same-level sibling rollup.** Every id in the `<pred/refut-ids>` token of a `:T resolutions` row for hypothesis `H` belongs to `H`'s own predictions. Cross-sibling citation is rejected.
26. **Authorization contract closure at CONCLUDE.** Every declared `ac<n>` must either have a fulfilling `:R authz` row OR appear in `:T conclude.deferred_authz` with a non-empty rationale.
27. **Past-case no-sole-grounding for benign.** On any contract load-bearing for `disposition=benign`, at least one fulfilling `:R authz` row must have `grounding=org-authority`. *(Former past-case ⇒ partial enum clause moved to rule #11.)*
28. **Past-case chain depth cap.** A `:R authz` row with `grounding=past-case` cites a prior contract via `cites_past_case?`. The cited resolution must have `grounding=org-authority` — past-case cannot recursively authorize past-case.
29. **Impact prediction structure.** Each `:L l-{id}.impact_preds` row has `id` (`^ip\d+$`, unique within the lead), `dim`, `claim`, `on_match`, `on_mismatch`, `on_indeterminate`, `escalation_on`. One observable per `claim` — compound AND/OR predicates split into separate rows.
30. **Impact resolution back-reference and grounding.** Every `:R impact` row has `pred_ref` pointing to a declared `ip*`, `dim` matching the prediction, `verdict` ∈ {`within`, `exceeds`, `indeterminate`}, `grounding` ∈ {`telemetry-baseline`, `business-owner-attestation`, `dlp-policy`} (past-case not admissible), `authority`, `as_of`, and `reasoning`.
31. **Impact closure at CONCLUDE.** Every declared `:L l-{id}.impact_preds` row must either have a fulfilling `:R impact` row OR appear in `:T conclude.deferred_impact` with a non-empty rationale.
32. **Integrity peer discipline.** When `:H authz?` is set and `parent_type` is an acting-entity type (`session`, `identity`, `process`), either a peer integrity hypothesis (`?adversary-controlled-*` sharing `attached_to`) must exist in the same sibling group, or the contract-carrying hypothesis must carry `integrity_waived?` with a non-empty rationale.
33. **Attribute-prediction structure.** Each `ap<n>` sub-cell has `target` ∈ {`proposed_parent`, `attached_vertex`, `proposed_edge`}, a non-empty `attribute`, and a non-empty `claim` (one observable; compound AND/OR splits into separate `ap*`). `r*` brackets may cite `ap*` ids alongside `p*` ids on the same hypothesis. `:T resolutions` `<pred-ids>` may likewise cite both `p*` and `ap*`.
34. **Prediction closure at CONCLUDE.** When a `:T conclude` block is present, every declared `p*` and `ap*` on a hypothesis whose final status is neither `refuted` nor `shelved` must be either (a) cited in some `:T resolutions` row's pred-tokens with non-null `<after>`, OR (b) listed in `:T conclude.deferred_preds` with a non-empty rationale. Generalises rule #6 (which only fires on `++`) into a coverage check at REPORT regardless of weight — closes the contract analyze owes predict.
35. **Sibling prediction divergence.** Within a sibling group, no two siblings may declare identical prediction signatures. The signature combines `p*` `(subject, claim)` tuples and `ap*` `(target, attribute, claim)` tuples (case-normalised). Identical signatures mean ANALYZE has nothing to discriminate them on. Generalises rule #32 (integrity-peer specific, contract-gated) to all sibling forks; complements rule #23 — that rule blocks shared `parent_class`, this one blocks shared prediction text.
36. **Affirmative `true_positive` disposition.** `:T conclude disposition=true_positive` requires at least one entry in `:T conclude.surviving` to reference a hypothesis whose final weight is `++`. The `++` weight is the structural signal of *affirmative grading evidence* — per rule #6 + edge-authority discipline, `++` requires a severe lead resolving against an authoritative edge. If no survivor is graded `++`, the honest landing is `disposition=unclear`.
