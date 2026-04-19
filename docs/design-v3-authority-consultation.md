# Authority consultation — unified primitive (sketch)

**Status:** implemented (C1–C6 landed in this session). 884 non-LLM tests passing (855 pre-refactor + 29 new). Pending live-eval validation on rule 5710 scenario B.
**Supersedes (in part):** the parallel `trust_anchors_consulted` (archetype
grounding) and `legitimacy_contract` / `legitimacy_resolutions` (v2.8
authorization) mechanisms, which answer overlapping questions with different
ceremony.

## Why

Two mechanisms have grown up side-by-side for the same operation — *ask an
authority about a (source, target, relation) triple and act on the verdict*:

- **Archetype grounding** (pre-v2.8): `report.trust_anchors_consulted[]` gates
  `matched_archetype`. Example: `approved-monitoring-sources` must return
  `result: confirmed` for the `monitoring-probe` archetype.
- **Legitimacy contracts** (v2.8 from PR #88):
  `hypothesis.legitimacy_contract[]` declares edges needing authorization;
  `edge.legitimacy_resolutions[]` records the verdicts. Example: the
  `attempted_auth` edge must have an `authorized` verdict from
  `approved-monitoring-sources` for `disposition: benign`.

Both consult the *same anchor* for the *same triple* to gate the *same
disposition*. The agent articulates either one fluently in prose (runs #35
and #36 both prove this), but writes them into two different YAML slots with
partially overlapping vocabularies and the machinery treats them as
independent. Every feature we add (validator rule, SKILL.md cue, judge check)
has to be written twice.

## Current shape (3 slots, 3 vocabularies, 1 consultation)

Report layer:

```yaml
trust_anchors_consulted:
  - anchor: approved-monitoring-sources
    kind: org-authority              # org-authority | telemetry-baseline
    result: confirmed
    citation: "<verbatim quote>"
```

Invlang lead outcome:

```yaml
outcome:
  trust_anchor_result:
    anchor_id: approved-monitoring-sources
    kind: org-authority              # now constrained (this session's fix)
    result: confirmed
    as_of: <iso>
    authority_for_question: full | partial
```

Invlang edge resolution (v2.8, as shipped):

```yaml
edges:
  - id: e-001
    ...
    legitimacy_resolutions:          # ← lives ON the edge, grows over time
      - fulfills_contract: h-001.lc1
        verdict: authorized | unauthorized | indeterminate
        anchor_kind: approved-monitoring-sources    # free-form, distinct vocabulary
        anchor_query: "<what was asked>"
        as_of: <iso>
```

The same real-world consultation produces three records, each with its own
shape and taxonomy, with no machinery recognizing them as the same event.

**Additional problem**: the edge's `legitimacy_resolutions[]` *mutates after
the edge is written* (v2.8 ships this way — subsequent leads append to the
edge's list). That violates invlang's append-only rule (rule #4). Every
other refinement in the language lives in a lead outcome
(`attribute_updates`); `legitimacy_resolutions` is the odd one out.

## Proposal: authority consultation is a lead primitive

Leads that query an authority declare it in `query_details` and emit one
structured outcome; the downstream rollups are **derived**, not authored.

**Lead declaration:**

```yaml
query_details:
  system: authority-service
  authority:
    name: approved-monitoring-sources    # specific anchor (free string)
    kind: org-authority                   # class — enum, constrained
    asks: authorization                   # expectation | authorization
  input_triple:
    source_vertex: v-001
    target_vertex: v-002
    relation: attempted_auth
  template: approved-monitoring-sources-lookup
```

**Lead outcome (extended — append-only, parallel to `attribute_updates`):**

```yaml
outcome:
  trust_anchor_result:                    # the raw consultation record
    anchor_id: approved-monitoring-sources
    kind: org-authority                   # class — rollup axis
    asks: authorization                   # expectation | authorization
    result: confirmed                     # confirmed | refuted | unavailable
    verdict: authorized                   # required when asks: authorization
                                          # authorized | unauthorized | indeterminate
    as_of: <iso>
    authority_for_question: full | partial
    citation: "<verbatim quote>"
    input_triple: {source_vertex, target_vertex, relation}  # echoes query

  attribute_updates:                      # existing pattern
    - target: e-001
      updates: {cadence_shape: periodic}

  legitimacy_resolutions:                 # NEW sibling of attribute_updates
    - target: e-001                       # element being refined
      fulfills_contract: h-001.lc1
      # `verdict`, `anchor_name`, `anchor_query`, `as_of` derived from
      # trust_anchor_result above (or repeated for local readability)
```

**Append-only:** `legitimacy_resolutions` moves off the edge record and lives
in lead outcomes alongside `attribute_updates`. Edge record is write-once.
"Current legitimacy state of edge e-001" is a computed rollup walking leads
in order — the same pattern as computing current attributes. No record ever
mutates; chronology falls out of lead order.

**Derivation (hook, not agent):**

- `report.trust_anchors_consulted[]` is composed from every lead outcome
  carrying `trust_anchor_result`. No manual rewrite at CONCLUDE.
- The graph's "current authorization state of edge e-001" is computed by
  walking `gather[].outcome.legitimacy_resolutions` in order, filtering
  `target: e-001`. Contracts are resolved when at least one matching entry
  has `verdict: authorized` (and no later entry overrides with a stronger
  signal — rules TBD for override semantics).
- Validator rules #10 (back-ref), #21 (legitimacy-gated disposition) walk
  lead outcomes rather than the edge record. Rule becomes: for every
  contract `h-X.lcN` on a live-weight hypothesis, at least one lead outcome
  has a matching `legitimacy_resolutions[]` entry with
  `verdict: authorized`.
- Contracts without resolutions fail the legitimacy gate; resolutions
  without contracts are orphans (flagged).

## What does NOT unify

- **Class vs name.** `kind: org-authority | telemetry-baseline` is a rollup
  axis ("did this disposition rest on policy or on baseline statistics?").
  `anchor_name` is the specific authority (`iam-policy`, `oncall-schedule`,
  `approved-monitoring-sources`). Keep both. The primitive carries both; the
  validator constrains class, audit preserves name.

- **Expectation vs authorization.** `telemetry-baseline` answers *expectation*
  ("has this image run 500 times before"), not *authorization* ("is this
  container sanctioned to run right now"). The `asks:` discriminator prevents
  a baseline confirmation from silently satisfying a legitimacy contract.
  Rule: **contracts only accept resolutions with `asks: authorization`.**
  Archetype `required_anchors` accept either.

- **Archetype `required_anchors` ≠ legitimacy contracts.** Both consult
  authorities, but they sit at different layers:
  - Archetype anchors declare "this archetype's shape is only grounded if
    these anchors confirm."
  - Legitimacy contracts declare "this hypothesis's `benign` disposition
    requires these authorizations on these edges."
  The *consultation mechanism* unifies; the *declaration layers* stay
  separate. A single lead outcome can ground both at once when the same
  anchor answers both questions (which is the common case).

## Migration plan

1. **Schema** —
   - Extend `trust_anchor_result` with `asks` and conditional `verdict`; add
     `input_triple` for audit.
   - **Remove `legitimacy_resolutions[]` from the Edge definition**; relocate
     to `gather[].outcome.legitimacy_resolutions[]` as a sibling of
     `attribute_updates`. Restores append-only invariant. Edge record is
     write-once; resolutions are lead-output records.
   - Update `invlang_validate.py`: rules #10 and #21 walk lead outcomes
     instead of edge fields; contract ⇒ lead with `asks: authorization` ⇒
     `verdict: authorized` ⇒ report entry composes cleanly.
2. **Knowledge base** — per-anchor operations docs declare
   `kind` + default `asks`. Lead templates in
   `knowledge/common-investigation/leads/{anchor}/` specify the authority
   shape.
3. **Skill/subagent prose** — `hypothesize.md` stops authoring
   `legitimacy_contract` and separate anchor-query planning; it names
   `required_contracts` that bind to anchor names. `analyze.md` grades off
   the single `trust_anchor_result`. `agents/gather.md` knows the authority
   lead shape.
4. **Report rollup** — CONCLUDE no longer hand-authors
   `trust_anchors_consulted`; a PreToolUse hook (or the invlang → frontmatter
   deriver) composes it. Agent still writes `matched_archetype` and
   `disposition`; the gate derives from the composed graph.
5. **Backward compatibility** — pre-MVP; no shipped runs rely on the
   parallel shape. Rewrite cleanly. Only two playbooks currently declare
   `legitimacy_contract` (5710 seeds in PR #88); migrate those to the new
   primitive in the same PR that lands the schema change.

## Validation

- Unit: `asks` enum, verdict required when `asks: authorization`, derivation
  round-trip (lead outcome → report entry, lead outcome → edge resolution),
  legitimacy-gate under the unified shape.
- E2E: scenario A on 5710 and whoami-exec on 100001 (once its playbook
  declares contracts) produce a populated edge `legitimacy_resolutions` and
  a populated report `trust_anchors_consulted` from the same lead — no
  duplicate authoring.

## Open questions

1. **Target shape.** Authority queries naturally target edges (the triple is
   an edge). But `image-baseline` targets a vertex (the container). Does the
   primitive require `target: v-* | e-*` symmetrically, or does it always
   emit an input_triple even when the thing-being-asked is a vertex
   attribute? Leaning: `input_triple` is optional; some anchors answer
   attribute-level questions (`is this image on the approved list?`) and
   bind to a vertex.
2. **One lead, multiple outcomes?** Composite leads (gather+anchor in one
   subagent dispatch) may want to emit `trust_anchor_result` and
   `observations` together. Current schema allows that. Should one lead emit
   *multiple* `trust_anchor_result[]`? Probably no — split into multiple
   leads for audit clarity.
3. **Enforce `asks` at declaration.** If a playbook's lead declares
   `kind: org-authority`, must `asks:` be explicit? Leaning yes — forces
   the playbook author to classify "is this anchor giving us expectation or
   authorization?" up front.
4. **Naming.** `trust_anchor_result` is now doing four jobs (archetype
   grounding, legitimacy resolution, report rollup source, edge provenance).
   Renaming to `authority_consultation` would be clearer but widens the
   diff.

## Diff sketch

Concrete file touches, not a patch — enough to scope the work and surface
decisions that affect the diff.

### `schemas/enums.py` — add discriminator enums

```python
# New:
VALID_ASKS = ("expectation", "authorization")

VALID_LEGITIMACY_VERDICTS = ("authorized", "unauthorized", "indeterminate")

# Unchanged (anchor class; rollup axis):
VALID_ANCHOR_KINDS = ("org-authority", "telemetry-baseline")
```

### `knowledge/invlang/schema.md`

**Edge** — remove `legitimacy_resolutions`:

```diff
 authority:
   kind: siem-event | runtime-audit | authoritative-source
       | client-asserted | inferred-structural
   source: <string>
   trust_chain: []          # omit if empty
-legitimacy_resolutions: [] # omit when no contract resolves against this edge.
-                           # Populated when a lead resolves a declared
-                           # legitimacy_contract against this edge ...
```

**Lead outcome** — extend `trust_anchor_result`, add sibling
`legitimacy_resolutions`:

```diff
 outcome:
   attribute_updates:
     - target: v-{id} | e-{id}
       updates: {}
+  legitimacy_resolutions:             # append-only refinement, parallel to attribute_updates
+    - target: e-{id}                   # (or v-{id} — see open q)
+      fulfills_contract: h-{id}.lc{n}  # must exist in hypothesize.hypotheses[*].legitimacy_contract
   observations: {...}
   trust_anchor_result:
     anchor_id: <string>
+    anchor_name: <string>             # specific authority (iam-policy, oncall-schedule, ...)
     kind: org-authority | telemetry-baseline
+    asks: expectation | authorization
     result: confirmed | refuted | unavailable
+    verdict: authorized | unauthorized | indeterminate
+                                       # required when asks: authorization; omit otherwise
     as_of: <iso>
     authority_for_question: full | partial
+    input_triple:                      # optional; when present, echoes the query shape
+      source_vertex: v-{id}
+      target_vertex: v-{id}
+      relation: <string>
```

**Validator rules** — rewrite #10, #21; add new ones:

```diff
-10. Legitimacy back-reference (v2.8). Every `edge.legitimacy_resolutions[].fulfills_contract`
-    of shape `h-{id}.lc{n}` points to an existing hypothesis whose `legitimacy_contract` contains that entry.
+10. Legitimacy back-reference. Every `gather[].outcome.legitimacy_resolutions[].fulfills_contract`
+    of shape `h-{id}.lc{n}` points to an existing hypothesis whose `legitimacy_contract` contains that entry.

-11. Legitimacy-gated disposition (v2.8). `conclude.disposition: benign` requires every `legitimacy_contract`
-    on a live-weight hypothesis ... to have at least one fulfilling `legitimacy_resolutions` entry with
-    `verdict: authorized`.
+11. Legitimacy-gated disposition. `conclude.disposition: benign` requires every `legitimacy_contract`
+    on a live-weight hypothesis to have at least one lead outcome with a
+    `legitimacy_resolutions[]` entry pointing to it AND a `trust_anchor_result.verdict: authorized`.

+NEW. trust_anchor_result shape. When `asks: authorization`, `verdict` is required and must be in
+     VALID_LEGITIMACY_VERDICTS. When `asks: expectation`, `verdict` is forbidden (baselines don't authorize).

+NEW. Resolution target shape. Every `legitimacy_resolutions[].target` is `v-{id}` or `e-{id}` and the id exists.

+NEW. Orphan resolution. A legitimacy_resolutions entry whose `fulfills_contract` names no declared
+     contract is flagged (warning, not error — allows exploratory leads).
```

### `hooks/scripts/invlang_validate.py`

- **Remove** the edge-walking path in `_check_legitimacy_resolution_backrefs`;
  replace with a lead-outcome walker that iterates
  `merged["gather"][*]["outcome"]["legitimacy_resolutions"]`.
- **Rewrite** `_check_legitimacy_gated_disposition`: build
  `{contract_id → list[resolution]}` from lead outcomes instead of edges;
  the grouping logic downstream stays.
- **Add** `_check_asks_verdict_shape`: when `trust_anchor_result.asks ==
  "authorization"`, `verdict` must be present and in
  `VALID_LEGITIMACY_VERDICTS`; when `asks == "expectation"`, `verdict` must
  be absent.
- **Add** `_check_legitimacy_resolution_target`: each resolution's `target`
  resolves to a declared v-/e- id (reuses `_collect_declared_ids`).
- Existing `_check_attribute_updates_target_shape` generalizes to cover
  `legitimacy_resolutions` too — or share a helper.

### `schemas/report_frontmatter.py`

Option A (conservative): add optional fields only.

```diff
 trust_anchors_consulted: list = field(...)
     # entry = {anchor, kind, result, citation}
+    # entry may also carry: asks, verdict, anchor_name
```

Option B (deferred — recommended): report rollup is *derived* from the
composed graph at CONCLUDE write time (a hook), not authored. Agent doesn't
write `trust_anchors_consulted` at all. Leaves report validator checking
consistency between agent-authored disposition/archetype and
hook-computed anchor list.

Start with A; move to B in a follow-up once the derivation hook exists.

### Tests

New unit cases (all in `test_invlang_validate.py`):

- `asks: authorization` without `verdict` → fail, suggest adding verdict
- `asks: expectation` with `verdict: authorized` → fail ("baselines don't
  authorize")
- Contract with matching `legitimacy_resolutions` in lead outcome +
  `trust_anchor_result.verdict: authorized` → pass, `disposition: benign`
  allowed
- Contract unfulfilled → fail rule #21
- Resolution targeting undeclared edge id → fail
- Resolution with `fulfills_contract` naming undeclared contract → warn
  (orphan), don't block

Existing `legitimacy_resolutions`-on-edge fixtures in
`test_invlang_validate.py::TestLegitimacy*` need to migrate — they'll become
lead-outcome fixtures. Count the blast radius before writing the PR.

### Playbook migration

5710 is the only playbook carrying v2.8 seeds today. Single file touch:

- `knowledge/signatures/wazuh-rule-5710/playbook.md` — hypothesis seeds
  keep `legitimacy_contract` at the hypothesis, but their lead templates
  now declare `authority: {name, kind, asks}` in `query_details`. No
  resolution-writing on edges.

100001/100110/other signatures don't declare contracts yet, so no
migration — their playbooks stay unchanged until someone adds contracts
following the new shape.

### Open questions that affect the diff

1. **Resolution target flexibility.** `target: e-{id}` covers 95% of cases
   (edges are where authorization applies). Do we allow `target: v-{id}`?
   Case: "this container vertex is baseline-approved" resolves a contract
   scoped to the shell-spawn edge. Leaning *yes*; match the existing
   `attribute_updates.target` shape.
2. **Override / supersede semantics.** If two resolutions target the same
   edge + contract with different verdicts (earlier lead returned
   `indeterminate`, later lead `authorized`), which wins? Options: latest,
   strongest, require explicit supersede marker. Leaning "latest, with a
   supersede marker on the later entry" for auditability.
3. **Must `trust_anchor_result` and `legitimacy_resolutions` co-occur?**
   When `asks: authorization`, yes — otherwise `verdict` is orphaned. When
   `asks: expectation`, the lead can carry `trust_anchor_result` alone
   (grounds an archetype, produces no resolution). Validator rule:
   `legitimacy_resolutions` on a lead ⇒ `trust_anchor_result.asks ==
   authorization`.
4. **Lead target vs resolution target.** Can a lead whose own
   `target: v-003` write a `legitimacy_resolutions` entry with
   `target: e-001`? Yes — the lead's target is "what I'm asking about";
   the resolution's target is "which graph element this verdict refines."
   They can differ.

## Non-goals

- Replacing `required_anchors` with `legitimacy_contract`. They remain
  declared separately because archetype-grounding and authorization are
  genuinely different authoring concerns — the primitive unifies *how we
  ask*, not *why we ask*.
- Auto-generating contracts from archetype anchors. A baseline-class
  anchor shouldn't become a contract silently.
- Broadening the report `kind` enum. `org-authority | telemetry-baseline`
  stays as the rollup axis.
