"""Variant-specific §Output format text for DP / DB / DH dense PREDICT trailers.

Three variants share a COMMON_PREFACE (rules that don't depend on density):
  - DP — packed sub-cells inside `:H` rows
  - DB — sub-blocks per hypothesis (`:P h-{id}.preds` / `.refuts` / `.authz`)
  - DH — hybrid: preds+refuts+attr_preds packed; authz + comparisons sub-blocks

All three carry the same `kind` slot, sentence-ID story prose convention,
field-presence matrix, and routing block structure.
"""

# ---------------------------------------------------------------------------
# Common preface — rules every dense variant inherits.

COMMON_PREFACE = """## Output format

Emit a **dense block-shape envelope** to stdout. No prose framing, no YAML fence — the dense blocks ARE your output. The orchestrator parses block-tagged rows mechanically into invlang state; the field-presence matrix is enforced at parse time (violations come back as remediation notes).

**Shape commitment is the literal first field.** Decide the shape per §Decision procedure before authoring anything else; the `predict` header line carries it.

**PREDICT always selects a lead.** Halting is ANALYZE's job. There is no halt / null-lead path.

### Block grammar (shared across shapes)

Each block is tagged `:<TAG> <name> [col1|col2|...]` (header) followed by `|`-separated rows. Empty trailing optional cells are permitted; required leading cells are not. Annotations inside `[...]` use `\\]` to embed a literal `]`. ASCII fallbacks accepted on parse: `=>` for `→`, `<=>` for `⟺`, `&` for `∧`, `~` for `¬`.

The envelope opens with one bare line:

```
predict loop=<int> shape=E|A|M
```

### `kind` slot — every prediction-shaped row carries one

Every `p*`, `ap*`, `r*`, and `lp*` row carries an explicit `kind` from the closed set:

| `kind`            | When to use |
|---|---|
| `geometry`        | Foreground matches / deviates from the recurring baseline geometry on a recorded dimension. |
| `cadence`         | Foreground rate / inter-event distribution falls within / outside the baseline distribution. |
| `novel-artifact`  | A category of artifact appears in foreground that's absent from baseline of comparable shape. |
| `absence`         | Foreground deviates from a structurally-zero baseline (any presence is the deviation). |
| `presence`        | Bare-presence claim NOT tied to a zero baseline. **Disallowed on `r*` refutations** (presence-test refutation anti-pattern). May appear on `p*` only when the prediction is about a directly-fielded value the alert telemetry already names. |
| `absolute`        | Direct field-read threshold — the field exists in the alert payload or anchor response and the claim is `field op value`. |

A `kind ∈ {geometry, cadence, novel-artifact, absence}` row **requires** a `comparison` slot (selector_kind + selector + dimension). A `kind ∈ {presence, absolute}` row must not carry one. The parser rejects mismatches.

### Story prose with sentence IDs

For each hypothesis `h-<id>` (Shape A or M), emit a short Markdown story block above (or co-located with) the hypothesis row:

```markdown
### story h-<id>
s1. <one sentence>
s2. <one sentence>
s3. <one sentence>
```

Each story sentence has an explicit ID (`s1`, `s2`, ...). Predictions cite a sentence ID in their `from_story` cell — not the prose. This makes story-prediction referent-match a parse-time check (`from_story` must name a sentence ID present in the matching story block).

Story blocks are NOT inside dense rows. The handler reads them as prose, parses sentence IDs, and includes them in the composed `hypothesize:` invlang block as `story:` field per hypothesis.

### Field-presence matrix (parse-time enforced)

| Shape | hypotheses | branch_plan | routing | story blocks |
|---|---|---|---|---|
| E | absent     | required (`:L lead_preds`) | required | absent |
| A | required (≥ 1, ≥ 1 carrying authz; peer hypotheses only when predictions diverge on observable fields) | absent | required | one per hypothesis |
| M | required (≥ 2, diverging on observable fields) | absent | required | one per hypothesis |

Violations are rejected by the dense parser before invlang validator runs.

"""

# ---------------------------------------------------------------------------
# Variant DP — packed sub-cells.

OUTPUT_FORMAT_DP = """### Variant DP — packed sub-cells

Predictions, attribute_predictions, refutations, and authorization_contracts all pack into trailing cells of the `:H` row, separated by `;` between cells in the same column. Comparison blocks pack as trailing positionals on the prediction sub-cell.

**`:H` row shape:**

```
:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
```

**Sub-cell grammar (inside the cells):**

- **`preds` cell** — semicolon-separated entries:
    - `p<n>:<subject>:<kind>:s<m>:"<claim>"` — when `kind ∈ {presence, absolute}`
    - `p<n>:<subject>:<kind>:s<m>:"<claim>":<selector_kind>:<selector>:<dimension>` — when `kind ∈ {geometry, cadence, novel-artifact, absence}`
    - `<subject>` ∈ `{proposed_edge, proposed_parent, attached_vertex}`
    - `s<m>` is the from-story sentence ID; must exist in the matching story block.

- **`attr_preds?` cell** — semicolon-separated:
    - `ap<n>:<target>:<attribute>:<kind>:"<claim>"` (no comparison; attribute claims are field-shape claims)
    - `<target>` ∈ `{proposed_parent, attached_vertex, proposed_edge}`

- **`refuts?` cell** — semicolon-separated:
    - `r<n>[<refutes-csv>]:<kind>:"<claim>"` — `<refutes-csv>` is a comma list of `p<n>` and/or `ap<n>` IDs on the same hypothesis
    - For deviation kinds, append `:<selector_kind>:<selector>:<dimension>` as on `p*`.
    - `kind: presence` is rejected by the parser on refutations.

- **`authz?` cell** — semicolon-separated:
    - `ac<n>:<edge_ref>:<anchor_kind>:"<predicate>":<on_unauth>/<on_indet>`
    - `<edge_ref>` is `proposed` or an existing `e-NN` ID.
    - `<on_unauth>`, `<on_indet>` ∈ `{esc, downgrade, accept}` (esc = escalate).

**Branch plan (Shape E) — `:L` block:**

```
:L lead_preds [id|kind|if|read_as|advance_to|selector_kind?|selector?|dimension?]
lp1|cadence|"foreground falls within the source's 72h authentication-cadence baseline"|periodic-tooling-pattern|fork-at-identity|historical-self|"src=<source_ip> AND rule=5710 OR rule=5715 over 72h"|inter-event-gap-distribution
lp2|novel-artifact|"foreground introduces a forward-success not present in the source's 30d baseline"|escalating-attempt|escalate|historical-self|"src=<source_ip> 30d"|forward-auth-success
```

The `selector_kind` / `selector` / `dimension` columns are required when `kind ∈ {geometry, cadence, novel-artifact, absence}`, omitted otherwise.

**Impact predictions — when the lead measures impact observables:**

```
:R impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]
ip1|confidentiality|"session_total_bytes within 30d baseline ± 2σ"|within|exceeds|indeterminate|exceeds
```

**Routing — flat block with two optional sub-blocks:**

```
:R routing
selected_lead         <lead-slug>
composite_secondary   <lead-slug>,<lead-slug>     # or '-' if none
override_data_source  <slug>                       # or '-'
rationale             "<one sentence>"

:R routing.lead_hints [lead|hint]                  # OPTIONAL — present only when used
<lead-slug>|"<prose hint>"

:R routing.scope_override [key|value]              # OPTIONAL — present only when used
window_hours|24
anchor|alert
```

### Worked example — Shape A, single hypothesis (rule-5710 loop 2 post-enrichment)

```
predict loop=2 shape=A

### story h-001
s1. Source 172.22.0.10 has emitted rule-5710 at periodic ~10min cadence for 72h, consistent with a registered monitoring probe.
s2. The approved-monitoring-sources registry is the authoritative source for whether the (src, user, dst) triple is sanctioned.
s3. If the triple is listed active, both 'is this allowed' and 'who initiated this' resolve to the registered actor.

:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?registered-actor-initiated|v-001|initiated_by|identity|approved-monitoring-service-account|kind=service-account|p1:proposed_parent:absolute:s2:"triple (172.22.0.10,sensu,target-endpoint) listed in approved-monitoring-sources"||r1[p1]:absolute:"triple absent or revoked"|ac1:proposed:approved-monitoring-sources:"triple listed as active":esc/esc|"registry anchor names the registered actor; resolves both authorization and identity-of-use"|null|active

:R routing
selected_lead         approved-monitoring-sources-lookup
composite_secondary   -
override_data_source  -
rationale             "registry consult is the cheapest disposition-settling discriminator; identity-of-use rides the same anchor (integrity waived)"
```
"""

# ---------------------------------------------------------------------------
# Variant DB — sub-blocks per hypothesis.

OUTPUT_FORMAT_DB = """### Variant DB — sub-blocks per hypothesis

The `:H` row carries metadata only (id, name, edge geometry, weight, status). Predictions, attribute_predictions, refutations, and authorization_contracts each emit their own `:P` block under that hypothesis. Comparison blocks live in a single `:P comparisons` table referenced by prediction id.

**`:H` row shape (metadata-only):**

```
:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
h-001|?registered-actor-initiated|v-001|initiated_by|identity|approved-monitoring-service-account|kind=service-account|"registry anchor names the registered actor"|null|active
```

**Per-hypothesis sub-blocks (one set per `:H` id):**

```
:P h-001.preds [id|subject|kind|from_story|claim]
p1|proposed_parent|absolute|s2|"triple listed in approved-monitoring-sources"

:P h-001.attr_preds [id|target|attribute|kind|claim]
# OPTIONAL — omit the block entirely when no attribute predictions

:P h-001.refuts [id|refutes|kind|claim]
r1|p1|absolute|"triple absent or revoked"

:P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|approved-monitoring-sources|"triple listed as active"|esc|esc
```

**Subject values** on `:P preds`: `{proposed_edge, proposed_parent, attached_vertex}`.
**Target values** on `:P attr_preds`: `{proposed_parent, attached_vertex, proposed_edge}`.
**`refutes`** is a comma list of `p*` and/or `ap*` IDs on the same hypothesis.
**`kind: presence`** is rejected on `:P *.refuts` rows.

**Comparison block (single, scoped per hypothesis):**

For every prediction or refutation row whose `kind ∈ {geometry, cadence, novel-artifact, absence}`, emit a row in the hypothesis's comparison block:

```
:P h-001.comparisons [pred_ref|selector_kind|selector|dimension]
p1|historical-self|"src=172.22.0.10 AND rule=5710 over 72h"|inter-event-gap-distribution
```

The parser checks: every deviation-kind row has a matching `comparisons` entry; every `comparisons` entry refers to a deviation-kind row. Mismatch is a parse error.

**Branch plan (Shape E) — same `:L lead_preds` block as DP, plus a sibling `:L lead_preds.comparisons` table:**

```
:L lead_preds [id|kind|if|read_as|advance_to]
lp1|cadence|"foreground within source's 72h cadence baseline"|periodic-tooling-pattern|fork-at-identity
lp2|novel-artifact|"foreground introduces forward-success not in 30d baseline"|escalating-attempt|escalate

:L lead_preds.comparisons [pred_ref|selector_kind|selector|dimension]
lp1|historical-self|"src=<source_ip> AND rule=5710 OR rule=5715 over 72h"|inter-event-gap-distribution
lp2|historical-self|"src=<source_ip> 30d"|forward-auth-success
```

**Impact predictions and routing — same as DP** (`:R impact_preds`, `:R routing`, optional `:R routing.lead_hints`, optional `:R routing.scope_override`).

### Worked example — Shape A, single hypothesis (rule-5710 loop 2 post-enrichment)

```
predict loop=2 shape=A

### story h-001
s1. Source 172.22.0.10 has emitted rule-5710 at periodic ~10min cadence for 72h, consistent with a registered monitoring probe.
s2. The approved-monitoring-sources registry is the authoritative source for whether the (src, user, dst) triple is sanctioned.
s3. If the triple is listed active, both 'is this allowed' and 'who initiated this' resolve to the registered actor.

:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
h-001|?registered-actor-initiated|v-001|initiated_by|identity|approved-monitoring-service-account|kind=service-account|"registry anchor names the registered actor; resolves both authorization and identity-of-use"|null|active

:P h-001.preds [id|subject|kind|from_story|claim]
p1|proposed_parent|absolute|s2|"triple (172.22.0.10,sensu,target-endpoint) listed in approved-monitoring-sources"

:P h-001.refuts [id|refutes|kind|claim]
r1|p1|absolute|"triple absent or revoked"

:P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|approved-monitoring-sources|"triple listed as active"|esc|esc

:R routing
selected_lead         approved-monitoring-sources-lookup
composite_secondary   -
override_data_source  -
rationale             "registry consult is the cheapest disposition-settling discriminator; identity-of-use rides the same anchor (integrity waived)"
```
"""

# ---------------------------------------------------------------------------
# Variant DH — hybrid (preds+refuts+attr_preds packed; authz + comparisons sub-blocks).

OUTPUT_FORMAT_DH = """### Variant DH — hybrid

Predictions, attribute_predictions, and refutations pack into the `:H` row's trailing cells (same sub-cell grammar as DP). Authorization contracts and comparison blocks are pulled out to their own per-hypothesis sub-blocks (same as DB) — these two surfaces have the most fields each, and lifting them keeps the packed cells readable.

**`:H` row shape:**

```
:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|integrity_waived?|weight|status]
```

(No `authz?` cell — authz is a sub-block.)

**Packed sub-cells** (`preds`, `attr_preds?`, `refuts?`) — same grammar as DP, EXCEPT comparison positionals are NOT packed onto the prediction cell. Instead:

- A deviation-kind prediction packs as `p<n>:<subject>:<kind>:s<m>:"<claim>"` — six positionals only.
- The comparison details live in `:P h-<id>.comparisons [pred_ref|selector_kind|selector|dimension]` (same as DB).

**Authorization sub-block:**

```
:P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|approved-monitoring-sources|"triple listed as active"|esc|esc
```

**Branch plan (Shape E) — same as DB** (`:L lead_preds` + `:L lead_preds.comparisons`).

**Impact predictions and routing — same as DP / DB.**

### Worked example — Shape A, single hypothesis (rule-5710 loop 2 post-enrichment)

```
predict loop=2 shape=A

### story h-001
s1. Source 172.22.0.10 has emitted rule-5710 at periodic ~10min cadence for 72h, consistent with a registered monitoring probe.
s2. The approved-monitoring-sources registry is the authoritative source for whether the (src, user, dst) triple is sanctioned.
s3. If the triple is listed active, both 'is this allowed' and 'who initiated this' resolve to the registered actor.

:H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|integrity_waived?|weight|status]
h-001|?registered-actor-initiated|v-001|initiated_by|identity|approved-monitoring-service-account|kind=service-account|p1:proposed_parent:absolute:s2:"triple (172.22.0.10,sensu,target-endpoint) listed in approved-monitoring-sources"||r1[p1]:absolute:"triple absent or revoked"|"registry anchor names the registered actor; resolves both authorization and identity-of-use"|null|active

:P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|approved-monitoring-sources|"triple listed as active"|esc|esc

:R routing
selected_lead         approved-monitoring-sources-lookup
composite_secondary   -
override_data_source  -
rationale             "registry consult is the cheapest disposition-settling discriminator; identity-of-use rides the same anchor (integrity waived)"
```
"""
