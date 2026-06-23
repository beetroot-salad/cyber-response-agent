# Schema Delta: Legitimacy as Edge Attribute + Hypothesis Contract

**Target:** `docs/investigation-language.md` (currently spec v2.6).
**Proposed version:** v2.7.
**Status:** Draft — pending review before promotion to the main spec.

Companion to `docs/decisions/adversarial-as-attribute-not-hypothesis.md`.

---

## 1. Philosophy — new subsection under `## Philosophy`

Insert after `### Lean hypotheses` and before `### Leads as graph operations`:

> ### Legitimacy as edge attribute
>
> Legitimacy — is this edge authorized? — is a property of the
> (`source_vertex`, `edge`, `target_vertex`, `authority`) quadruple at a
> specific time T. The same `read` edge from a session to a storage
> object is authorized when the session's identity carries the
> required role and unauthorized when it does not. The mechanism is
> identical in both cases; only the verdict differs.
>
> The confirmed graph therefore carries legitimacy **on the edge**, not
> as a parallel hypothesis. A hypothesis whose disposition depends on
> authorization declares a `legitimacy_contract` naming the edge(s)
> whose verdict is load-bearing and the authority that resolves them.
> When the resolving lead fires, the edge is augmented with a
> `legitimacy` block carrying the verdict and a back-reference to the
> contract.
>
> This preserves append-only discipline. The hypothesis is written once
> with its contract and never mutated. The materialized edge points
> backward to the contract via `fulfills_contract`; the hypothesis does
> not point forward. Queries like "what verdict did h-001's contract
> receive?" traverse from edge to hypothesis — the same backward
> traversal idiom used elsewhere in the graph.
>
> Three shapes of adversariness:
>
> - **Mechanism-level** — enumerate `adversary-controlled` alongside
>   benign classifications when they predict observationally distinct
>   world-states. Normal mechanism enumeration; no legitimacy contract
>   needed — the mechanism IS the discriminator.
> - **Attribute-level** — same mechanism, different authorization
>   (CFO vs IT operator reading the same object). One hypothesis, one
>   `legitimacy_contract`, verdict on the edge. This is the common case.
> - **Future-edge** — adversarial signal is a separate downstream edge
>   (e.g., a failed-auth alert followed by an unexpected success). Real
>   topology question — write it as its own hypothesis attached to the
>   hypothetical future edge. Not a legitimacy attribute.

---

## 2. `### Edge` — add `legitimacy` field

Replace the edge block:

```yaml
edge:
  id: e-{nonce}
  relation: <string>
  source_vertex: v-{id}
  target_vertex: v-{id}
  when: { timestamp: <iso> }
  attributes: {}
  status: observed
  authority:
    kind: siem-event | runtime-audit | authoritative-source
        | client-asserted | inferred-structural
    source: <string>
    trust_chain: []
  legitimacy:                              # NEW — omit when no contract resolves against this edge
    verdict: authorized | unauthorized | indeterminate
    anchor_kind: <string>                  # iam-policy | deploy-runs | oncall-schedule | image-baseline | workload-manifest | ...
    anchor_query: <string>                 # what was asked of the anchor (short human-readable)
    as_of: <iso>                           # timestamp the answer is authoritative ABOUT (§trust_anchor_result semantics)
    resolved_by_lead: l-{id}
    fulfills_contract: h-{id}.lc{n}        # back-reference to the hypothesis's legitimacy_contract entry
  concerns: []
```

Add commentary after the existing `**Authority is observational, not legitimacy.**` paragraph:

> **Legitimacy is distinct from authority.** `authority` describes how
> reliably the edge was *observed*. `legitimacy` records whether the
> observed edge was *authorized* by the relevant trust anchor at time
> `as_of`. Both can coexist: an edge with `authority.kind: runtime-audit`
> (high observational reliability) and `legitimacy.verdict: unauthorized`
> (IAM policy refused it) is exactly the adversarial shape — mechanism
> confirmed, authorization denied.
>
> **When `legitimacy` appears.** Only on edges that fulfill a
> `legitimacy_contract` declared by some hypothesis. Edges not referenced
> by any contract omit the field entirely. Do not write `legitimacy` on
> edges whose verdict is not load-bearing — that's verdict-on-everything
> clutter.
>
> **Append-only on existing edges.** If a contract resolves against an
> already-confirmed edge (not the proposed edge of the hypothesis), the
> lead writes the `legitimacy` block via `attribute_updates` targeting
> that edge — not by mutating the original record. See §Lead → `attribute_updates`.

---

## 3. `### Hypothesis` — add `legitimacy_contract` field

Replace the hypothesis block:

```yaml
hypothesis:
  id: h-{nonce} | h-{parent}-{nonce}
  name: "?descriptive-slug"

  attached_to_vertex: v-{id}

  proposed_edge:
    relation: <string>
    parent_vertex:
      type: <string>
      classification: <string>
      attributes: {}

  predictions:
    - id: p1
      claim: "<source-agnostic claim about world state>"

  refutation_shape:
    - id: r1
      claim: "<observation that would contradict a core prediction>"

  legitimacy_contract:                     # NEW — optional; present when disposition depends on authority lookup
    - id: lc1                              # local to hypothesis; matches ^lc\d+$
      edge_ref: proposed | e-{id}          # proposed_edge, or an already-confirmed edge id
      anchor_kind: <string>                # which authority resolves it
      predicate: "<natural-language claim — authorized iff ...>"
      on_unauthorized: escalate            # terminal routing if verdict is unauthorized
      on_indeterminate: escalate           # terminal routing if anchor unavailable or verdict indeterminate

  concerns: []
  weight: null | "++" | "+" | "-" | "--"
  weight_history: []
  status: active
```

Add commentary after the existing `**Lean means 1–2 predictions.**` paragraph:

> **Legitimacy contracts are optional and scoped.** Declare a
> `legitimacy_contract` only when the hypothesis's disposition genuinely
> hinges on an authorization lookup — i.e., the same mechanism is
> consistent with benign and adversarial outcomes depending on whether
> an authority endorses it. Most mechanism hypotheses do not need a
> contract: an `?adversary-controlled-process` hypothesis doesn't need a
> contract because the adversarial reading is already the mechanism; a
> `?sanctioned-monitoring-probe` doesn't need one because the
> classification itself is the claim.
>
> **The predicate is natural language.** Write the authorization
> condition as the agent would read it when consulting the anchor:
> `"authorized iff source.identity holds an IAM role granting
> s3:GetObject on target OR target is listed in the shared-public
> allowlist."` Any AND/OR combination is permitted. No structured
> predicate DSL — the agent evaluates the predicate against anchor data
> when the resolving lead fires.
>
> **`edge_ref: proposed` vs `e-{id}`.** Use `proposed` when the contract
> is about the hypothesis's own proposed_edge (the common case — "is
> the `read` edge I'm proposing authorized?"). Use `e-{id}` when the
> load-bearing authorization question is about an already-confirmed
> upstream edge (e.g., "the `read` mechanism is plain; the live question
> is whether the upstream `authenticated_as` was MFA-verified").
>
> **Contracts compose through the identity chain.** Zero-trust
> evaluation — "authorize every hop" — falls out of per-edge contracts
> on the chain from the action edge back to the authenticating edge.
> The schema does not encode propagation rules; the agent reasons about
> the chain during ANALYZE.

---

## 4. `### Lead` — extend `attribute_updates` to accept edge targets

Current shape:

```yaml
attribute_updates:
  - vertex: v-{id}
    updates: {}
```

New shape — target is one of vertex OR edge:

```yaml
attribute_updates:
  - target: v-{id} | e-{id}               # was: vertex: v-{id}
    updates: {}
```

Commentary update in `**`attribute_updates` vs `observations`**`:

> Use `attribute_updates` when a lead enriches an already-confirmed
> vertex or edge without adding new topology. Classification lookups
> add fields to existing vertices. Legitimacy resolutions against
> already-confirmed edges add a `legitimacy` block to the edge via
> attribute-update — never by mutating the original edge record.

---

## 5. `### Conclude` — add legitimacy-disposition coupling

Add after the termination-categories list:

> **Legitimacy-gated disposition.** `disposition: benign` requires that
> every `legitimacy_contract` on every confirmed-weight hypothesis has a
> fulfilling edge with `verdict: authorized`. Any of:
> - Contract unfulfilled (no edge carries `fulfills_contract: h-X.lcN`)
> - Fulfilling edge has `verdict: indeterminate`
> - Fulfilling edge has `verdict: unauthorized`
>
> …caps disposition. `indeterminate` or unfulfilled → `unclear` +
> `status: escalated`. `unauthorized` → `true_positive` or `unclear`
> depending on remaining evidence, with `status: escalated`.

---

## 6. `## Validator rules` — new rules

Add four rules (renumber existing #18 as needed, or append #19–#22):

> 19. **Legitimacy contract edge_ref resolves.** Every
>     `legitimacy_contract.edge_ref` is either the literal `proposed`
>     or an `e-*` id that exists in the companion.
>
> 20. **Edge legitimacy back-reference resolves.** Every
>     `edge.legitimacy.fulfills_contract` of the form `h-{id}.lc{n}`
>     points to an existing hypothesis whose `legitimacy_contract`
>     contains an entry with that id.
>
> 21. **Legitimacy-gated disposition.** A `conclude.disposition: benign`
>     requires every `legitimacy_contract` across all confirmed-weight
>     hypotheses (weight `++` or `+`, status `confirmed` or `active`) to
>     have at least one fulfilling edge with `legitimacy.verdict:
>     authorized`. Unfulfilled, `indeterminate`, or `unauthorized`
>     verdicts force `status: escalated` and disposition ∈ {`unclear`,
>     `true_positive`}.
>
> 22. **Attribute-update target shape.** Every `attribute_updates` entry
>     has exactly one of `target: v-{id}` or `target: e-{id}`, and the
>     id exists in the companion.

---

## 7. Guidance removal — SKILL.md §HYPOTHESIZE

Not a schema change, but required to keep SKILL.md consistent with the new framing:

- **Remove** from operating principle #4: "Always keep at least one
  threat hypothesis active until explicitly refuted with `--`
  evidence." Replace with pointer to legitimacy contracts.
- **Remove** from HYPOTHESIZE completeness checks: the "Adversarial"
  bullet mandating a parallel adversarial hypothesis on the same
  anchor or a hypothetical future edge.
- **Add** to HYPOTHESIZE: guidance on when to declare a
  `legitimacy_contract` (the three-shape decomposition from §1 above).

The enforcement teeth move from agent-bookkeeping ("did the agent
retain the adversarial hypothesis?") to structural validation
(validator rule #21 — every benign disposition requires every contract
resolved authorized).

---

## Example — CFO vs IT operator reading financial storage

**Alert:** DLP fires on a read of `financials.xlsx`.

**Prologue:** vertices for the session, the identity, the storage; edges for `read`, `authenticated_as`, `runs_on`.

**Hypothesis** (one, not two):

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?operator-data-access"
      attached_to_vertex: v-financials
      proposed_edge:
        relation: read
        parent_vertex:
          type: session
          classification: operator-session
      predictions:
        - id: p1
          claim: "a session from an interactive operator read v-financials during business hours"
      refutation_shape:
        - id: r1
          claim: "no session-originated read edge to v-financials in the window"
      legitimacy_contract:
        - id: lc1
          edge_ref: proposed
          anchor_kind: iam-policy
          predicate: "authorized iff source.identity holds a role granting read on target (financial-data-access, finance-admin, or auditor)"
          on_unauthorized: escalate
          on_indeterminate: escalate
      weight: null
      status: active
```

**Lead** confirms the mechanism and resolves the contract. Materialized edge:

```yaml
- id: e-005
  relation: read
  source_vertex: v-session-jane
  target_vertex: v-financials
  when: { timestamp: 2026-04-18T10:03:41Z }
  authority: { kind: runtime-audit, source: dlp-sensor }
  legitimacy:
    verdict: authorized              # cfo-jane holds financial-data-access role
    anchor_kind: iam-policy
    anchor_query: "roles(cfo-jane) ⊇ {financial-data-access}?"
    as_of: 2026-04-18T10:04:00Z
    resolved_by_lead: l-003
    fulfills_contract: h-001.lc1
```

Disposition: `benign`. No parallel `?compromise-followup` hypothesis was ever written.

**Swap the identity** to `it-bob`:

```yaml
  legitimacy:
    verdict: unauthorized            # it-bob has no financial-data-access role
    ...
    fulfills_contract: h-001.lc1
```

Validator rule #21 fires: disposition cannot be `benign`. Status flips to `escalated`, disposition defaults to `unclear` or `true_positive` depending on other evidence. Same mechanism, same hypothesis — the verdict on the edge is the entire adversarial discrimination.
