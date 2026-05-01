# Dense investigation format — proposal v0.1

Status: design experiment, v0.1 (post-review revisions — closes five gaps from v0: structured CONCLUDE scaffolding, multi-loop surfaces, lead-scoped sub-blocks, `:R attr_updates`, corrected rules #14 and #34). Not implemented. Assumes familiarity with `docs/investigation-language.md` (v2.13) and `soc-agent/knowledge/invlang/schema.md`.

## Goal

Cut investigation.md tokens by ~50% without losing any data the 35 validator rules check. Cluster the load-bearing artifacts (hypothesis weights and the citations moving them) so the agent's working surface fits a smaller window.

The load-bearing wins are token compression and field adjacency. Iconicity from the graph block is a likely-but-unmeasured secondary win — speculative until benchmarked, do not load the design on it.

## Surface

Phase blocks stay as Markdown headers (`## CONTEXTUALIZE` / `## PREDICT` / `## GATHER` / `## ANALYZE` / `## REPORT`). Inside each block: free-form Markdown narrative + one or more **dense blocks**.

Narrative-bearing fields (`reasoning`, `story`, `summary`, `selection_rationale`) appear in *both* surfaces, deliberately:

- The Markdown sentence is what the agent (and a human reader) actually consumes — prose carries connective tissue and judgment that table cells can't.
- The dense-block cell is a **checklist artifact** — its presence proves the field was authored, its absence is a structural failure the validator catches. The cell content can be terse (a phrase, a noun, a citation) since the prose carries the explanation.

Concretely: on a `:T resolutions` row, the `:: <annotation>` slot is the checklist version of `reasoning`; the surrounding `## ANALYZE` paragraph is the prose version. On `:T conclude`, `summary "<one sentence>"` is the checklist; the `## REPORT` paragraph above it is the prose. Same field, two surfaces, neither redundant: the validator checks the cell, the agent reads the prose.

`conditioning_context` is *not* narrative — it is per-resolution scaffolding (then-true premises a verdict rests on, e.g. "CHG-2041 active", "oncall X"). It stays on the structured row only (`conditioning?` cell on `:R authz`, `:R consultations`, `:R impact`); the cell is canonical, no prose duplicate required.

What this rules out: silently dropping a structured field because "the prose covers it". Closure rules (#24 surviving_hypotheses, #26 deferred_authorizations, #31 deferred_impact, #34 prediction closure) only work if the cells are present and parseable. Prose alone cannot fulfill them.

Dense blocks are tagged `:<TAG> <name> [col1|col2|...]` (header) followed by `|`-separated rows. Empty trailing cells permitted; leading positional cells required. Six tags:

### `:V` — vertices

```
:V prologue.vertices [id|type|class|ident|attrs?|placeholder?|concerns?]
v-001|endpoint|monitoring-host|172.22.0.10|||
v-002|endpoint|internal-server|target-endpoint|||
```

`attrs?` packs `key=value` pairs separated by `;`. Same convention for `concerns?`.

### `:E` — edges

```
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?|status?|concerns?]
e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event:wazuh-indexer|target_user=sensu;outcome=failed||
```

### `:H` — hypotheses (predictions / refutations / authz packed into sub-cells)

```
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?monitoring-probe|v-001|initiated_by|identity|approved-monitoring-service-account|kind=service-account|p1:proposed_parent:"triple in approved-monitoring-sources"||r1[p1]:"triple absent"|ac1:proposed:approved-monitoring-sources:"triple listed as active":esc/esc||null|active
```

Sub-cell grammar:
- `p<n>:<subject>:"<claim>"` — prediction
- `ap<n>:<target>:<attribute>:"<claim>"` — attribute prediction
- `r<n>[p1,ap1]:"<claim>"` — refutation (cites pred ids it would refute)
- `ac<n>:<edge_ref>:<anchor_kind>:"<predicate>":<on_unauth>/<on_indet>` — authz contract

### `:L` — leads (header + lead-scoped sub-blocks)

A lead's structured rows belong under that lead's phase block (convention: appear lexically below the `:L findings` row in the same `## GATHER` / `## ANALYZE` block; or carry an explicit `lead=l-{id}` column for cross-references). Block tags valid under a lead: `:V l-{id}.observations.vertices`, `:E l-{id}.observations.edges`, `:R authz`, `:R consultations`, `:R impact`, `:R attr_updates`, `:L l-{id}.lead_preds`, `:L l-{id}.impact_preds`, `:L l-{id}.substitutions`, `:H l-{id}.new_hypotheses`, `:T shelved`, `:T resolutions`.

Lead header (one row per lead — only scalar/list fields):

```
:L findings [id|loop|name|target|mode?|tests|system|template|query|window|trust_root?|fail_reason?|screen_result?]
l-001|1|approved-monitoring-sources-lookup|v-001||h-001,h-002|approved-monitoring-sources|triple-lookup|src=172.22.0.10 user=sensu dst=target-endpoint|||
```

Lead-level pre-committed branch plans (non-branching but interpretation-vulnerable leads):

```
:L l-{id}.lead_preds [id|if|read_as|advance_to]
lp1|"access matches identity's prior 72h cadence within 1σ"|"periodic tooling pattern"|identity-of-use-lookup
lp2|"bursty cluster concentrated in last 10 min"|"anomalous spike"|PREDICT
```

Impact-prediction commitments authored at PREDICT (graded by ANALYZE into `:R impact` rows):

```
:L l-{id}.impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]
ip1|confidentiality|"session_total_bytes within 30d baseline ± 2σ"|within|exceeds|indeterminate|exceeds
```

Query substitutions (`query_details.substitutions`):

```
:L l-{id}.substitutions [key|value]
src|172.22.0.10
user|sensu
dst|target-endpoint
```

Hypotheses born inside a lead use the same column shape as `:H hypothesize.hypotheses`, scoped by name:

```
:H l-{id}.new_hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-003|?...|...
```

Hypotheses dropped from the live frontier:

```
:T shelved [hyp_id|by_lead|rationale]
h-003|l-002|"monitoring-window does not overlap; mechanism cannot fire"
```

### `:R` — resolution-shaped rows (authz / consultations / impact / attr_updates)

Four sub-types. The first three resolve grounding against an anchor; the fourth records vertex/edge enrichment. The `conditioning?` column carries per-resolution then-true premises (canonical, not narrative — see Surface §).

```
:R authz [edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|effective_window?|fulfills|resolved_by|cites_past_case?|conditioning?]
e-010|authorized|approved-monitoring-sources|ams-registry-2026-01|org-authority|full|2026-04-23T14:00Z|2026-01-01..2026-06-30|h-001.ac1|l-001||

:R consultations [anchor_id|anchor_kind|grounding|result|as_of|authority|effective_window?|anchor_query?|conditioning?|concerns?]
backup-30d-baseline|session-volume-baseline|telemetry-baseline|confirmed|2026-04-23T14:32Z|partial||30d session_total_bytes|30d window excludes quarter-end|

:R impact [pred_ref|dim|observed|verdict|matched_pred|grounding|anchor_id|anchor_kind|authority|as_of|effective_window?|conditioning?|reasoning]
l-002.ip1|confidentiality|180GB (3σ above 60GB μ ±40σ)|exceeds|"session_total_bytes within 30d baseline ± 2σ"|telemetry-baseline|backup-30d-baseline|session-volume-baseline|partial|2026-04-23T14:32Z||30d window excludes quarter-end|"observed 3σ; threshold 2σ; partial caps moderate"

:R attr_updates [target|key|value]
v-003|cadence_72h_mean_interval_s|576
v-003|cadence_72h_stddev_s|102
e-001|authorization_resolutions|<append :R authz row referencing this edge>
```

When `attr_updates` targets an edge to add a new authorization resolution (per §Edge authorization in the spec), emit a separate `:R authz` row whose `edge` column points to the targeted edge; the `:R attr_updates` row carries `value=<see :R authz row>` as a pointer.

### `:T` — proof trace (one line per state change)

For hypothesis weight transitions:

```
:T resolutions
h-001  ∅ → +    [l-001 p1 moderate ⟂ e-010 :: authz authorized; identity-of-use open]
h-002  ∅ → -    [l-001 weak ⟂ no-authority :: host-query unavail; h-002.p1 ungraded]
```

Form: `<hyp-id> <before> → <after>    [<lead-id> <pred/refut-ids> <severity_of_test> ⟂ <supp-edges-or-marker> :: <annotation>]`

- `<before>`/`<after>` ∈ {`∅`, `++`, `+`, `-`, `--`}
- `<severity_of_test>` ∈ {severe, moderate, weak}
- `<supp-edges-or-marker>` = `e-{id}[,e-{id}]` | `no-authority` | `partial-authority`

For CONCLUDE:

Scalar fields stay as flat key/value lines. Array-shaped fields (`surviving_hypotheses`, `deferred_authorizations`, `deferred_impact_predictions`, `deferred_predictions`, `ceiling_test`) get their own structured tables. Empty arrays render as a single `none` row; populated arrays carry one row per entry.

```
:T conclude
termination.category   exhaustion-escalation
termination.rationale  "host-query unavail; h-002 cannot reach --"
disposition            benign
impact_verdict         within
impact_severity        null
confidence             medium
matched_archetype      monitoring-probe
ceiling_rationale      n/a
summary                "SSH login as 'sensu' from internal monitoring-host confirmed sanctioned."

:T conclude.surviving [hyp_id|final_weight]
h-001|+
h-002|-

:T conclude.deferred_authz [contract_ref|rationale]
none

:T conclude.deferred_impact [prediction_ref|rationale]
none

:T conclude.deferred_preds [prediction_ref|rationale]
none

:T conclude.ceiling_test [kind|subject]
none
```

`ceiling_test` and `ceiling_rationale` carry `none` / `n/a` unless `termination.category: severity-ceiling`, in which case both are required (rule #13). For shelving inside a lead, see §`:L` lead-scoped sub-blocks (`:T shelved`).

### `:G` — frontier graph (derived view, not append-only)

```
:G frontier
v-002 endpoint:target-endpoint
  ←e-001 attempted_auth failed [siem-event:wazuh-indexer]
    v-001 endpoint:monitoring-host 172.22.0.10
      ?h-001 monitoring-probe → +    (active)
        ←e-010 initiated_by [authoritative-source:approved-monitoring-sources]
          v-003 identity:approved-monitoring-service-account sensu-svc
      ?h-002 adversary-controlled-source-session → -    (active)
```

`:G` is regenerable from `:V` + `:E` + `:H` + `:T`. Co-located in the file as a comprehension aid.

## Worked example: stress-1 (current YAML → dense)

The full re-emission of `runs/conclude-test-stress-1/investigation.md`:

```markdown
## CONTEXTUALIZE

Alert 1776600000.42 — wazuh-rule-5710. Source 172.22.0.10 (monitoring-host) attempted_auth to target-endpoint as user=sensu at 2026-04-20T09:00:00Z. Host-query DEGRADED for this run — process-lineage lead unavailable.

:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|monitoring-host|172.22.0.10|
v-002|endpoint|internal-server|target-endpoint|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-002|2026-04-20T09:00:00Z|siem-event:wazuh-indexer|target_user=sensu;outcome=failed

## PREDICT (loop 1)

Two siblings under v-001's `initiated_by`: a sanctioned-probe identity (carries the authz contract) and the §Integrity discipline peer (?adversary-controlled-source-session).

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|preds|refuts|authz?|weight|status]
h-001|?monitoring-probe|v-001|initiated_by|identity|approved-monitoring-service-account|p1:proposed_parent:"triple (172.22.0.10,sensu,target-endpoint) listed in approved-monitoring-sources"|r1[p1]:"triple absent or revoked"|ac1:proposed:approved-monitoring-sources:"triple listed as active":esc/esc|null|active
h-002|?adversary-controlled-source-session|v-001|initiated_by|process|non-monitoring-process-on-source|p1:proposed_parent:"no monitoring-scheduler audit entry correlates within ±30s"|r1[p1]:"scheduler entry correlates within ±30s"||null|active

Selected lead: anchor consult. Process-lineage skipped (host-query DEGRADED).

## GATHER (loop 1)

:L findings [id|loop|name|target|tests|system|template|query|window]
l-001|1|approved-monitoring-sources-lookup|v-001|h-001,h-002|approved-monitoring-sources|triple-lookup|src=172.22.0.10 user=sensu dst=target-endpoint|

:V l-001.observations.vertices [id|type|class|ident|attrs?]
v-003|identity|approved-monitoring-service-account|sensu-svc|kind=service-account

:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source]
e-010|initiated_by|v-003|v-001||authoritative-source:approved-monitoring-sources

:R authz [edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|fulfills|resolved_by]
e-010|authorized|approved-monitoring-sources|ams-registry-2026-01|org-authority|full|2026-04-23T14:00Z|h-001.ac1|l-001

## ANALYZE (loop 1)

Anchor confirms the triple — h-001's prediction p1 matches, contract ac1 resolves authorized. Process verification blocked (host-query DEGRADED), so identity-of-use stays open and h-001 grades to + (not ++). h-002 grades to - — anchor confirmation weakly refutes the adversarial reading, but cannot reach -- without process inspection.

:T resolutions
h-001  ∅ → +    [l-001 p1 moderate ⟂ e-010 :: authz authorized; identity-of-use open]
h-002  ∅ → -    [l-001 weak ⟂ no-authority :: host-query unavail; h-002.p1 ungraded]

## REPORT

Trace: approved-monitoring-sources(confirmed) → disposition:benign

:T conclude
termination.category   exhaustion-escalation
termination.rationale  "host-query unavail; h-002 cannot reach --"
disposition            benign
impact_verdict         within
impact_severity        null
confidence             medium
matched_archetype      monitoring-probe
ceiling_rationale      n/a
summary                "SSH login as 'sensu' from internal monitoring-host 172.22.0.10 confirmed sanctioned by approved-monitoring-sources."

:T conclude.surviving [hyp_id|final_weight]
h-001|+
h-002|-

:T conclude.deferred_authz [contract_ref|rationale]
none

:T conclude.deferred_impact [prediction_ref|rationale]
none

:T conclude.deferred_preds [prediction_ref|rationale]
none

:T conclude.ceiling_test [kind|subject]
none

:G frontier
v-002 endpoint:target-endpoint
  ←e-001 attempted_auth failed [siem-event:wazuh-indexer]
    v-001 endpoint:monitoring-host 172.22.0.10
      ?h-001 monitoring-probe → +    (active)
        ←e-010 initiated_by [authoritative-source:approved-monitoring-sources]
          v-003 identity:approved-monitoring-service-account sensu-svc
      ?h-002 adversary-controlled-source-session → -    (active)
```

Token comparison: original YAML investigation.md ≈ 1,200 chars across 123 lines. Dense form ≈ 2,400 chars across ~55 lines (longer character-wise because the original example pre-dates v2.13's authz-contract / integrity-peer scaffolding — the dense form expresses fields the YAML did not). Like-for-like on a v2.13-conformant case, the savings show: a hypothesis row collapses ~20 YAML lines into ~1 dense line.

## Schema mapping

| Current YAML | Dense form |
|---|---|
| `prologue.{vertices,edges}` | `:V prologue.vertices`, `:E prologue.edges` |
| `hypothesize.hypotheses[]` | `:H hypothesize.hypotheses` (predictions/refutations/contracts packed in sub-cells) |
| `findings[].{id,loop,name,target,mode,tests,query_details.{system,template,query,time_window},trust_root_reached,failure_reason,screen_result}` | `:L findings` row |
| `findings[].query_details.substitutions` | `:L l-{id}.substitutions` |
| `findings[].predictions[]` (lead-level lp*) | `:L l-{id}.lead_preds` |
| `findings[].impact_predictions[]` | `:L l-{id}.impact_preds` |
| `findings[].outcome.observations.{vertices,edges}` | `:V l-{id}.observations.vertices`, `:E l-{id}.observations.edges` |
| `findings[].outcome.{authorization_resolutions,anchor_consultations,impact_resolutions,attribute_updates}` | `:R authz`, `:R consultations`, `:R impact`, `:R attr_updates` |
| `findings[].new_hypotheses[]` | `:H l-{id}.new_hypotheses` (column shape inherited from top-level `:H`) |
| `findings[].shelved[]` | `:T shelved` |
| `findings[].resolutions[]` (sibling of `outcome:`, not under it) | `:T resolutions` |
| `conclude.{termination.category,termination.rationale,disposition,impact_verdict,impact_severity,confidence,matched_archetype,ceiling_rationale,summary}` | `:T conclude` flat key/value lines |
| `conclude.surviving_hypotheses[]` | `:T conclude.surviving [hyp_id\|final_weight]` |
| `conclude.deferred_authorizations[]` | `:T conclude.deferred_authz [contract_ref\|rationale]` |
| `conclude.deferred_impact_predictions[]` | `:T conclude.deferred_impact [prediction_ref\|rationale]` |
| `conclude.deferred_predictions[]` | `:T conclude.deferred_preds [prediction_ref\|rationale]` |
| `conclude.ceiling_test` | `:T conclude.ceiling_test [kind\|subject]` |
| `*.reasoning`, `*.story`, `*.summary`, `*.selection_rationale` | Dual: terse checklist cell on the row (`:T resolutions :: <annotation>`, `:T conclude summary "<…>"`, `:H ... story:"<…>"` if promoted) + Markdown prose in the phase block. Both required; validator checks cell presence, agent reads prose. |
| `*.conditioning_context[]` | Structured cell only: `conditioning?` column on `:R authz`, `:R consultations`, `:R impact` (entries semicolon-separated within the cell). Per-resolution scaffolding, not narrative. |
| `*.concerns[]` | `concerns?` column on the carrying `:V`, `:E`, `:H`, `:R *`, or `:L` row (entries semicolon-separated within the cell). |

## Validator translation (sketch)

Each rule re-expressed against a line-shape parser. Examples:

| Rule | Dense-form check |
|---|---|
| #4 edge-authority cite | every `:T resolutions` row with `++`/`--` after has at least one `e-{id}` token in supp-edges, and that edge's `auth_kind` ∈ {siem-event, runtime-audit, authoritative-source} |
| #5 refutation IDs | every `--` row's pred/refut tokens include at least one `r{n}` resolving to the target hypothesis |
| #6 prediction completeness | per-hypothesis union of `p{n}` tokens across `++` resolution rows = full prediction set declared on `:H` |
| #13 ceiling_test scope | `:T conclude.ceiling_test` row ≠ `none` *iff* `termination.category` = `severity-ceiling`; `ceiling_rationale` non-empty under the same condition. |
| #14 partial-authority cap | a `:T resolutions` row whose every cited `:R` grounding entry has `authority=partial` is capped to after ∈ {+, -}. A row with at least one full-authority cited entry is *not* capped. |
| #21 authz-gated benign | `:T conclude disposition: benign` ⇒ every `ac{n}` declared on a confirmed-weight hypothesis row appears as a `:R authz authorized` row |
| #23 sibling fork distinctness | within a sibling group, `parent_class` column unique on `:H` |
| #25 same-level rollup | every `p{n}` cited on a resolution for `h-001` belongs to `h-001`'s preds, not a sibling's |
| #34 prediction closure at CONCLUDE | for every hypothesis whose final status is neither `refuted` nor `shelved` (i.e. `active` or `confirmed`), every `p{n}` and `ap{n}` declared on `:H` either appears in a `:T resolutions` row's pred-tokens with non-null after, or as a row in `:T conclude.deferred_preds` |

The full 35-rule rewrite is mechanical. Estimated parser size: ~150 LOC Python (one regex per block tag, one tokenizer per row shape).

## ANALYZE trailer dense form (v0)

Companion proposal: extend the dense surface from the on-disk `investigation.md` (the section above) to the **subagent output trailer** that ANALYZE emits and the handler composes from. Status: design experiment, narrowest viable extension. Full design discussion in this section's commentary; the on-disk grammar above is reused verbatim where it fits.

### Why ANALYZE first (not PREDICT, not GATHER)

- **ANALYZE's `resolutions[].entries[]` is uniform-row shape.** Every entry has the same columns: hypothesis_id, weight, matched_prediction_ids, matched_refutation_ids (when `--`), supporting_edges, reasoning. Maps 1:1 onto the on-disk `:T resolutions` row already specified above.
- **PREDICT's `:H` row is the riskiest surface** — packed sub-cells for predictions/refutations/contracts. Defer until ANALYZE proves the dense trailer carries.
- **GATHER's `characterization` is structurally per-lead** — keys differ per "What to Characterize" bullet, no shared row schema. Forcing tabulation creates a fake-schema downstream phases must reverse-engineer. Skip.

### Trailer surface

Today's YAML `analyze:` envelope (per `soc-agent/agents/analyze.md`) is reshaped onto five row-blocks. All grammar reuses the on-disk format above; no new tags introduced (`:A` is the analyze-trailer-only namespace prefix; `:T` and `:R` are reused verbatim from the on-disk grammar).

```
:A loop  <int>

:T resolutions
<hyp-id>  <before> → <after>   [<lead-id> <pred-tokens> <severity> ⟂ <supp-edges> :: <annotation>]
...

:R authz | consultations | impact | attr_updates                # reuse on-disk :R rows verbatim

:A routing                                                       # PRESENT iff decision=halt
decision               halt
termination_category   trust-root | adversarial-refuted | severity-ceiling | exhaustion-escalation
disposition            benign | true_positive | unclear
confidence             high | medium | low
surviving              <hyp-id>[,<hyp-id>...]
matched_archetype      null

:A unresolved_prescribed                                         # PRESENT iff decision=continue (optional)
<lead-slug>
...

:A anomalies
<short string> | none
...

:A data_wishes
<short string> | none
...
```

### Worked translation

Source: `runs/conclude-test-3/investigation.md` upgraded to today's envelope schema. wazuh-rule-550 single-loop, three hypotheses (one ++, two -- with matched refutations), halt → adversarial-refuted/benign.

YAML trailer (~28 non-blank lines, ~1.4 kB):

```yaml
analyze:
  loop: 1
  resolutions:
    - lead_ref: l-001
      entries:
        - hypothesis_id: h-001
          weight: "++"
          matched_prediction_ids: [p1, p2, p3]
          supporting_edges: [e-010]
          reasoning: "rule-502 server-restart edge at 13:01:54Z confirms p1 (causal trigger); 9 ev/20min across 6+ files confirms p2 (bulk pattern); mtime 2025-11-19 confirms p3 (file unchanged 5mo); refutation r1 (no restart event) failed to materialize."
        - hypothesis_id: h-002
          weight: "--"
          matched_prediction_ids: [p1]
          matched_refutation_ids: [r1]
          supporting_edges: [e-010]
          reasoning: "p1 (one-time burst) refuted by 4h 5-min repeat locked to syscheck cadence; matched r1 (persistent repeat)."
        - hypothesis_id: h-003
          weight: "--"
          matched_prediction_ids: [p1, p2, p4]
          matched_refutation_ids: [r1]
          supporting_edges: [e-010]
          reasoning: "bulk pattern across 9+ unrelated files refutes p1 (targeted-one-file); unchanged hashes refute p2; mtime 2025-11-19 refutes p4; matched r1 (bulk-across-unrelated-files)."
  anomalies: []
  data_wishes: []
  routing:
    decision: halt
    termination_category: adversarial-refuted
    disposition: benign
    confidence: high
    surviving_hypotheses: [h-001]
    matched_archetype: null
```

Dense trailer (~14 non-blank lines, ~750 B — **45% reduction** on this case):

```
:A loop  1

:T resolutions
h-001  ∅ → ++   [l-001 p1,p2,p3 severe ⟂ e-010 :: restart@13:01:54Z confirms p1; 9ev/20min ≥6 files confirms p2; mtime 2025-11-19 confirms p3; r1 not-materialized]
h-002  ∅ → --   [l-001 p1 r1 severe ⟂ e-010 :: 4h 5-min repeat locked to syscheck cadence refutes one-time burst; matched r1]
h-003  ∅ → --   [l-001 p1,p2,p4 r1 severe ⟂ e-010 :: bulk across 9+ unrelated files; unchanged hashes; mtime 5mo old; matched r1]

:A routing
decision               halt
termination_category   adversarial-refuted
disposition            benign
confidence             high
surviving              h-001
matched_archetype      null
```

`anomalies`/`data_wishes` blocks omitted (both empty); `:A unresolved_prescribed` absent (decision=halt).

### `severity_of_test` — new explicit field

The on-disk `:T resolutions` row introduces a slot the YAML envelope did not have: `severity_of_test ∈ {severe | moderate | weak}`. Adopting it on the trailer surfaces a rule that today is *implicit* in the load-bearing-field paragraph (`agents/analyze.md:107-117`).

**Reading**: pre-result test power, not post-result evidence strength.

- `severe` — direct field-read on an authoritative source for the prediction's load-bearing field.
- `moderate` — direct observation but the source has known coverage gaps for this question.
- `weak` — downstream effect, co-occurrence in a different rule family, temporal proximity, population baseline match without per-instance check.

**Why this reading**: the grade tier (`++`, `+`, `-`, `--`) already encodes how decisive the *result* was. A separate severity slot is only useful if it captures something the grade doesn't — which is the test's *a priori* discriminating power. This makes the load-bearing-field rule structural: the validator can enforce "`++` or `--` ⇒ severity=severe", which is exactly what `agents/analyze.md` says today in prose.

Trailer authoring cost: one additional judgment per resolution. ANALYZE already makes this judgment when picking the grade tier — surfacing it is mostly mechanical.

### `load_bearing[]` as iff conditions (proposal)

YAML today (`agents/analyze.md:42-46`) carries an optional `load_bearing[]` per resolution:

```yaml
load_bearing:
  - field: "<field name>"
    source: "<lead-id | prologue | e-id>"
    counterfactual: "<if this had shown X, grade would have been Y>"
```

Dense form: render the resolution as a mathematical-style biconditional where the LHS *is* the load-bearing observation and the RHS *is* the matched/refuted prediction set:

```
:T resolutions
h-001  ∅ → ++   [l-001 severe ⟂ e-010 :: rule-502.event_type=server-started @ 13:01:54Z ⟺ p1 ∧ ¬r1]
h-002  ∅ → --   [l-001 severe ⟂ e-010 :: cadence(syscheck) = 5min × 4h ≢ one-time-burst ⟺ ¬p1 ∧ r1]
h-003  ∅ → --   [l-001 severe ⟂ e-010 :: |files_affected| ≥ 9 ∧ hashes_unchanged ∧ mtime=2025-11-19 ⟺ ¬p1 ∧ ¬p2 ∧ ¬p4 ∧ r1]
```

What it gets us:
- The `⟺` line *is* the load-bearing observation. The RHS *is* the matched/refuted prediction set — `matched_prediction_ids`/`matched_refutation_ids` aren't separate columns, they're the literals on the right.
- The counterfactual is implicit: flip any LHS literal, the RHS flips with it. That's what the YAML `counterfactual` field tries to capture in prose.
- Severity gets a clean structural meaning: the LHS is *either* a direct field-read on an authoritative source (severe) or it's not.

Frictions (open):
- LLM authoring tier — `⟺ p1 ∧ ¬r1` is harder to write than two YAML lists. Sonnet probably handles; Haiku unproven. Worth the same n≥10 write test PR #146 scoped for the on-disk surface.
- ASCII fallback (`<=>`, `&`, `~`, `!`) for environments where unicode round-trips badly. Adopt unicode as canonical; accept ASCII on parse.
- Validator rewrite — rules #5 (refutation IDs) and #6 (prediction completeness) currently scan list fields. Under this form they scan literals on the RHS of `⟺`. Mechanical but a real rewrite.

### Annotation bracket-escape rule

Inside `[...] :: <annotation>` the annotation runs from `::` to the *last unescaped `]`* on the row. Embedded `]` must be written as `\]`. Cheap to define, cheap to author.

### `anomalies` / `data_wishes` — defer densification

Empirical scan of the run corpus (83 investigations across `/workspace/runs/` and `/workspace/soc-agent/runs/`, 57 with an `## ANALYZE` phase) found **zero populated `anomalies[]` or `data_wishes[]` entries**. The new envelope schema is recent (handlers refactor `fbf8e61`, `359d919`); most corpus runs predate it.

Without usage data we cannot judge whether these fields hold their intended retrospective/forward split or collapse into a free-form ANALYZE→PREDICT chat channel. Don't densify a schema we may want to redesign.

**Action**: in the dense trailer v0, allow `:A anomalies` / `:A data_wishes` blocks but do not introduce new structure. Re-evaluate after ≥15–20 runs on the new envelope. Likely redesigns to consider then: collapse to one field; structure as `{lead_ref, prediction_ref, kind: gap|inconsistency, note}`; or merge `data_wishes` into `routing.unresolved_prescribed_set`.

### Omit `:A routing` on continue

On `decision: continue` the only routing field is `decision` itself + optional `unresolved_prescribed_set`. Make `:A routing` block *absent* ⇒ `decision: continue` implied; *present* ⇒ halt with the four required fields. Saves ~6 lines on every continuing loop (which is most loops). No information loss; structural and parser-cheap.

### Searchability

The invlang query CLI (`scripts/invlang/run.sh`, 12 query classes in `scripts/invlang/queries.py`) walks parsed in-memory structure, not text. Searchability survives if we maintain a single canonical parser that emits the same dataclasses for both YAML and dense surfaces. Two real costs:

1. Parser parity is a silent-failure surface. Mitigation: dual-write fixtures during migration + diff parsed structures.
2. Trailer dense form alone introduces no packed sub-cells (those live in `:H` on the on-disk surface). Each `:T resolutions` row has a flat schema. So the trailer extension does not worsen searchability.

### Empirical findings on cross-block invariant detection

Two-round empirical probe (n=3 Sonnet agents per cohort, audit-for-inconsistency task on planted-error trailers) tested whether the dense form has an attention-budget weakness on cross-block invariants vs YAML.

**Round 1** (probe with row-local + cross-block errors mixed, *implicit* cross-block invariants):
- Dense cohort caught all 3 row-local errors, missed a `routing.surviving` ↔ `termination_category` polarity inconsistency that 2/3 YAML agents caught.
- Read as: dense form's iconic row-locality biases attention toward in-row checks, away from cross-block coherence.

**Round 2** (probe with cross-block errors only, *explicit* invariants enumerated in the legend, four cohorts: vanilla dense / chained re-read / inline survival marker / YAML):
- All four cohorts: 12/12 detection at 100%. Vanilla dense matched YAML matched both interventions.
- Round 1's "dense miss" was a legend-coverage gap, not a format weakness.

**The actual lever is legend coverage, not the format.** When the cross-block invariants are *named* in the legend the subagent reads, dense form catches them as reliably as YAML. When the legend leaves them implicit, every cohort degrades.

Implications:

1. **Dense ANALYZE trailer ships with explicit cross-block invariants in the legend.** The four invariants (surviving completeness, termination polarity, disposition gating, authz fulfillment) appear as a numbered list with the rule they enforce. Don't rely on the agent inferring them from row grammar alone.
2. **Reject the chained re-read intervention.** Duplicating the trailer block before the task instruction (the technique from Xu et al. 2023, "Re-reading improves reasoning in language models") gives no detection lift on Sonnet for this task. All three chained-cohort agents explicitly reported the second pass surfaced nothing new ("the duplicate block is byte-for-byte identical so no delta existed to catch"). Cost: ~1.4× tokens for zero gain. The Xu paper's gains were observed on smaller models with longer-context multi-hop tasks; for a ~700-byte trailer with 4 explicit rules, frontier-model headroom absorbs the lift.
3. **Inline survival markers (option B1) are optional polish, not a safety lever.** Per-row `<survival> ∈ {survives, refuted}` cells (mirroring the `routing.surviving` set) didn't change detection rate but did produce shorter, crisper reasoning artifacts: agents cited the inline cell directly ("h-003 is marked `survives` but is absent from `routing.surviving`") rather than deriving survival status from `<after>`. May matter for downstream parseability of the trailer's rationale (audit trail, post-mortem queries); does not matter for self-catch reliability. Adopt only if the reasoning-clarity benefit outweighs the redundancy cost.
4. **Happy-path self-catch works** when the legend names the invariants. The validator hook still has to enforce as a safety net, but the agent will catch cross-block errors at write time before the validator fires — meaning ANALYZE doesn't pay the validator-error-recovery tax (significant time + thinking) on cross-block violations. This is the load-bearing property; surface compression is secondary.

Caveats:

- n=3 per cohort is small; differences ≤1 catch are noise.
- Single trailer per cohort within each round — no within-cohort variance on the trailer side. To call format effects with confidence, want ≥5 different trailers per cohort with errors of varied placement/type.
- Round 1 vs round 2 differed on both planted-error placement and legend coverage. Cleanly retiring "dense has an attention weakness" hypothesis would require re-running round 1's planted errors with round 2's explicit-invariant legend.

### Migration suggestion

1. Write the dense parser for the trailer surface (`:A`, `:T resolutions`, `:R *` reuse). Smaller scope than the on-disk parser — flat row schemas only, no `:H` sub-cells.
2. Dual-emit on ANALYZE: subagent emits YAML envelope; handler composes invlang and *also* writes dense trailer to `subagent_checkpoints/analyze-loop-{n}.dense` for diff.
3. Run the n≥10 Haiku-tier write test on the dense form directly (skip the YAML envelope) on rule-5710 fixtures.
4. If parse rate ≥ 95% and `routing` field set matches the YAML form, cut over.

Higher blast radius than the on-disk dual-write because the orchestrator's compose step parses the trailer on every loop — a mis-parse breaks the run. Mitigation: dense parser is fail-soft; on parse error, fall back to YAML envelope written alongside.

## Tradeoffs

- **Save**: ~50% tokens (estimated, not measured); weight-and-citation lines collocated; iconic graph at a glance.
- **Cost**: dense-form parser to maintain; silent divergence between surface (what the agent writes) and validator (what's parsed) is the main failure mode; custom syntax has weaker LLM training prior than YAML/Markdown.
- **Speculative wins**: adjacency-helps-attention and iconicity-helps-reasoning claims should not be load-bearing for the design until measured.

## Open questions

- Migration: emit-both during transition vs hard cut. Probably emit-both for one signature first, dense form as `investigation-dense.md` companion to existing `investigation.md`.
- Optional fields: empty cell vs row omission. TOON convention is empty cell; adopt that for shape uniformity.
- Heterogeneous `lead.outcome`: split into per-shape blocks under the lead's phase header — what the worked example assumes.
- `:H` packed sub-cells (predictions, refutations, contracts) are still semi-structured. If they bloat or mis-parse, promote each to a sub-block under the umbrella tag — `:H h-{id}.preds`, `:H h-{id}.refuts`, `:H h-{id}.authz` — at the cost of more block headers.

## Empirical check (Haiku)

Single-shot test against `claude-haiku-4-5-20251001`. Two prompts, both passed inline. Harness in `/tmp/dense-test/`. n=1 — directional signal, not a measurement.

### Read test — 5 fact-extraction questions on the dense stress-1 example

Prompt: brief legend (~20 lines) + the dense investigation + 5 questions.

| # | Question | Expected | Haiku |
|---|---|---|---|
| 1 | final disposition? | benign | benign ✓ |
| 2 | h-002 final weight & what blocked `--`? | `-`; host-query unavailable | "`-` (weakly refuted); host-query unavailable prevented reaching `--`" ✓ |
| 3 | which edge supports h-001? authz verdict? | e-010; authorized | "e-010; authorized" ✓ |
| 4 | which lead resolved both? | l-001 | "l-001 (approved-monitoring-sources-lookup)" ✓ |
| 5 | matched prediction id on h-001 + severity? | p1, moderate | "p1 at moderate severity" ✓ |

5/5. Reading the dense form is unambiguous for Haiku.

### Write test — synthetic SSH brute-force case

Prompt: spec legend + worked example + a natural-language case description with explicit hypothesis names, verdicts, archetype, and the lead to run. Asked Haiku to emit the dense companion.

Output: structurally well-formed across all six block tags. Phase ordering correct. `:V`, `:E`, `:H`, `:L`, `:R`, `:T resolutions`, `:T conclude` blocks all parsed cleanly. Sub-cell grammars (`p1:subject:"claim"`, `r1[p1]:"claim"`, `ac1:proposed:anchor:"predicate":esc/esc`) correctly formed. Proof-trace lines (`h-001  ∅ → ++    [l-001 p1 severe ⟂ e-010 :: ...]`) perfect shape.

Three concrete failures, all cross-field consistency violations rather than syntax:

1. **Undefined edge reference.** `:R authz` row cites `e-010` but no `:E` block in GATHER declared it. (Future validator equivalent of rule #7.)
2. **Malformed `fulfills` field.** `fulfills=h-001.p1;h-002.ac1` — wrong shape (should be a single `h-{id}.ac{n}`); `h-001` has no contract; semicolons aren't a valid separator there.
3. **Off-catalog relations.** Used `brute_force_burst` and `code_execution` (neither in the relation catalog). Caveat: the prompt did not include the catalog.

None of these failures are dense-format-specific — they are the same classes of error YAML investigations exhibit (dangling refs, wrong field types, off-vocab values). The validator catches all three under existing rules.

What this tells us about the dense format:

- **The surface parses for a small model.** Haiku-4.5 reads and writes the format on a one-shot prompt with a ~20-line legend.
- **Cross-field consistency is still the validator's job.** The format doesn't make those errors go away, but it doesn't make them worse either.
- **Sub-cell grammars (`:H`, `:T resolutions` annotations) survived a small model.** This was the riskiest part of the design — semicolon-separated `key:value:"claim"` packed cells are non-standard. Haiku produced them correctly.
- **n=1.** Before committing, run the same write prompt on N≥10 cases (varied signature/disposition/cardinality) and measure parse rate + cross-field violation rate. Compare against the same N cases emitted in current YAML.

### Next experiment, if continued

Pick one signature (suggest `wazuh-rule-5710` since it has the most stress fixtures already), generate dense companions for ~10 fixtures, run them through a draft parser, score parse rate + cross-field violation rate. If parse rate ≥ 95% and violations ≤ existing YAML violations, build the parser + dual-write migration. If parse rate < 90%, the sub-cell packing in `:H` is the most likely culprit — promote each packed sub-cell type to its own table.
