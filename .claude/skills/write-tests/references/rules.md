# Gate rules and the spec_graph artifact

The gate computes the join of the behavior layer against the structure layer and emits **typed residue**. It runs after the address space is materialized (SKILL.md step 5) and before human resolution (step 7). Rules read only formal slots (schema.md, slot discipline); every hit carries a **witness** — the concrete element and the missing demand — so the output is actionable, never a score.

## Procedure

1. Compute the delta: every structure element the change adds, removes, or modifies (demand-implied structure is all `provenance: design` elements; the grounded neighborhood is what it attaches to).
2. For each delta element, fire the matching rules below.
3. Classify every hit into the typed residue:
   - **Test obligation** — a demand must exist and doesn't; carries derivable assertion content.
   - **Design hole** — a decision is missing, not a test: an `unknown` invariant, an unresolvable address, a substitute that structurally cannot discharge its survival demand. Routed to the human.
   - **Pre-discharged** — the demand already exists (the design stated it; step 2 extracted it). Credit it explicitly; don't re-litigate.
   - **Waiver candidate** — plausibly acceptable to skip; the human decides, and the decision is recorded as `Demand {form: waiver}`.
4. The gate closes when every obligation is discharged — by an executable demand or a recorded waiver — and every hole has a human answer.

The types are **routes, not partitions**: one element can be both. A design hole, once the human resolves it, frequently spawns a test obligation (the undecided cache key becomes, decided, a uniqueness demand) — record the element in both lists, linked (`resolved_to: <demand id>` on the hole).

## Delta grammar

Change kinds are finite: `{add, remove, modify} × {actor, boundary, facet, edge, property}`. Each cell fires a rule or is a documented no-op — blind spots are enumerated, not silent.

| | add | remove | modify |
|---|---|---|---|
| **actor** | no rule alone — an actor with no edges has no contract surface; its edges fire the rules | R5 (live in-edges) | `frame` change → recompute R2 demand placement |
| **boundary** | facet rules fire per facet (below); R0 on `unknown` fields | R5 (live in-edges); demands bound to it now dangle → R0 | via its facets |
| **facet** | the facet's rule fires (R1 payload, R2 identity, R3 access, R4 domain) — a facet **materializing on existing structure** counts (e.g. a boundary becoming multi-via) | demands bound to the facet dangle → R0; a dropped contract with dependents → R5 | invariant field change → re-fire the facet's rule (new `key_axes` → R2; new `distinguished` member → R4) |
| **edge** | R1 (`sends` → payload), R2 (`write` → identity), R4 (`read` → domain), R3 (new `via` on a reached boundary), R5 (`mode: remove`) | the edge's dependents orphaned → R5 | `mode`/`via` change → R3; `interpolates` change → R2 |
| **property** | subsumed by modify | subsumed by modify | `drives.multiplicity` flip → R2 form re-selection; `trust` change → R3 + R0 |

The `modify` column is where add-only thinking goes blind: a property flip with no topology change (serial → concurrent; a via's trust level changing) fires obligations on its own. It exists only because element `id`s are stable across runs — without stable identity every change degenerates to remove+add.

## The rules

Each rule: **trigger** (a predicate over formal slots) → **obligation** (the demand that must exist, with its derivable assertion content) → **canonical escape** (the shipped bug this rule would have computed).

### R0 — well-formedness and reconciliation

- **Trigger:** a `binds:` address resolving to nothing in structure ∪ delta; an invariant field left `unknown`; an edge endpoint undefined. Plus the bidirectional check: a normative design sentence binding no element (extraction gap or phantom design); a delta element tracing to no design sentence (invented scope).
- **Output:** design holes, not test obligations — each names the artifact to fix (`provenance` routes it).
- **Canonical:** a design that consumes a knob nothing defines; an access via whose confinement policy is undecided.

### R1 — unread channel

- **Trigger:** an edge with `sends` to a payload-facet boundary, and no executable `kind: shape` demand binds `interacts(...).payload`.
- **Obligation:** a shape demand. Derivable assertions, from the facet: the fake records the inbound payload; `roles-disjoint-sources` — no two parts share a source (the same template must not arrive under two roles); `all-slots-bound` — no part contains an unsubstituted `{...}` token.
- **Canonical:** #534 dual prompt — the full template passed as both the raw system prompt (literal `{story}`/`{lesson}` braces) and, rendered, as the user turn; the suite drove a `FunctionModel` that ignored `messages` and was structurally blind to it.

### R2 — shared sink

- **Trigger:** a `write` edge to an identity-facet boundary with ≥2 writers (existing ∪ delta), or a `drives.multiplicity` / `interpolates` / `key_axes` change on such a boundary.
- **Obligation:** two parts. (a) *Key coverage:* every writer's `interpolates` covers every axis the writer set varies on — checked against `derivations`: a value with `injective: false` does **not** cover its axis. (b) *A uniqueness demand* driving ≥2 writers into one root, **bound at the composition frame** (the actor that fans the writers), never the leg — a single-leg test cannot see a cross-leg collision. Form selection: `multiplicity: serial` → drive the writers in turn (deterministic — the second `w`-open truncates the first) with a positive control that both writes landed as distinct real content; `multiplicity: concurrent` → a genuine interleaving; `sharing: serialized-append` → the demand flips to atomic/serialized append (no torn line, no lost update) under real interleaving.
- **Canonical:** #527 per-lead trace names colliding across the two direction legs (the spec's own docstring scoped distinctness to per-lead within one invocation); #534 `{error_prefix}.{lesson_stem}` — same mechanism, different surface form. The typed predicate catches both; similarity-to-the-first-instance would not.
- **Sharper when read:** if the identity boundary is also **read** (a cache, a lookup), an under-covering key is a read-path bug, not just a lost write — the reader returns *another key's content* (same-stem files from two intake dirs serving each other's cached summary is a correctness and disclosure bug). Same trigger; write the witness in read terms and the uniqueness demand asserts no cross-read.

### R3 — cross-via parity

- **Trigger:** an access-facet boundary with ≥2 vias, or a via added to a boundary an existing via reaches. If a via's `constraints` is `unknown`, R0 fires first — decide the policy, then pin it.
- **Obligation:** one parity demand per (constraint × via) cell: every constraint the established via enforces (denylist, clamp, confine, …), the new via enforces too — asserted over **all** vias, since a constraint pinned on one surface and silently absent on its sibling is the canonical fail-open.
- **Canonical:** #517 jq path-gate — the bash lane admitted bundled flags and lacked denylist parity with the read tool; each surface read alone looked correct.

### R4 — domain coverage

- **Trigger:** a `read` edge to a domain-facet boundary, or a domain facet gaining members/alternatives.
- **Obligation:** an executable demand per `distinguished` member — above all the falsy member when `falsy_valid` (an `x or DEFAULT` coercion silently swallows it) — and per `documented_alternatives` entry, especially combinations that cross a validation boundary (a value valid for one provider is rejected by another). Pin the crossing either way: the advertised combination works, or it fails loud and legibly.
- **Canonical:** #534 `wall_clock_timeout or SUBAGENT_TIMEOUT` turning a valid 0 into the default; #527 `ORACLE_EFFORT="none"` fatal under the documented `claude-*` A/B override — the spec tested only the shipped default column.

### R5 — subtraction and conservation

- **Trigger:** a removed element (actor, boundary, edge, or a `mode: remove` edge) with live in-edges; or a restriction that leaves a security-critical caller constructible in the newly-unsafe state.
- **Obligation:** a survival demand per dependent — the workflow that ran through the removed element completes via its substitute; if the substitute structurally cannot discharge it (the replacement takes one file where the original fanned N), that is a design hole, not a test to write. For restrictions: a safe-by-construction demand — the critical caller *cannot be built* in the unsafe state; assert the constructor raises, not merely that it behaves when configured right.
- **Canonical:** #517 — the suite tested only the new restriction and silently regressed the workflows the old surface quietly served.

## The artifact — spec_graph.yaml

One file per spec, committed **beside the suite** (same directory as the new tests, named `spec_graph_<issue-or-slug>.yaml`), reviewed by the human *as part of the spec*:

```yaml
schema_version: 1
design: <issue # or doc path>
demands:   [...]      # the resolved demand list, waivers included — the spec proper
structure: {actors: [...], boundaries: [...], interacts: [...], drives: [...]}
gate:
  obligations: [{rule: R2, element: <address>, witness: "<one sentence>", discharged_by: <demand id>}]
  holes:       [{rule: R0, element: <address>, resolution: "<the human's decision>"}]
  pre_discharged: [{rule: R4, element: <address>, by: <demand id>}]
```

Downstream consumers: the human reviews it with the tests; `write-code-from-spec` reconciles the implementation's actual structure against it (unrealized addresses and invented scope both flag); the later review diffs against it.

Formal-slot validation (kinds, forms, modes, vias, invariant vocabularies) is currently a hand check against schema.md — a `spec_graph` linter is deliberate future work tracked in #537. Until it exists, the step-9 gate says so in the handoff.

## Maintenance

Every future escape that ships past a green spec must be mapped: to existing (elements, rule) — an execution failure, fix how the flow ran; to a new rule over existing elements (common); or, rarely, to a schema change — and fields enter the schema only when a rule needs them (`drives.multiplicity` exists because R2's form selection reads it). An escape that fits no inventory is the strong author's territory and a candidate new blindness condition — expect those to be rare and treat them as the finding of the year, not a Tuesday.
