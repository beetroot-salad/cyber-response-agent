# Gate rules and the spec_graph artifact

The gate computes the join of the behavior layer against the structure layer and emits **typed residue**. It runs after the address space is materialized (SKILL.md step 5) and before human resolution (step 7). Rules R1–R5 trigger on predicates over formal slots (schema.md, slot discipline); two flagged parts read judgment instead — R0's reconciliation half and R5's restriction extension — and each records in the artifact that it ran. Every hit carries a **witness** — the concrete element and the missing demand — so the output is actionable, never a score.

## Procedure

1. Compute the delta: every structure element or edge the change adds, removes, or modifies. Change kinds are assigned **at extraction, from the design** — a first run needs no prior graph: an element or edge the design introduces is `add`, one whose property or semantics the design alters is `modify`, and `provenance` marks which side each came from (demand-implied structure is `provenance: design`; the grounded neighborhood it attaches to is `code`). Across runs, stable `id`s let the graph diff itself as a second source of change kinds.
2. For each delta element, fire the matching rules below, and record **every rule's outcome — fired or clean — in `gate.evaluated`**: a rule with no entry reads as skipped, not as clean.
3. Classify every hit into the typed residue:
   - **Test obligation** — a demand must exist and doesn't; carries derivable assertion content. Minted as an executable demand at SKILL.md step 6 and reviewed at step 7.
   - **Design hole** — a decision is missing, not a test: an `unknown` invariant, an unresolvable address, a substitute that structurally cannot discharge its survival demand. Routed to the human (fact-shaped `unknown`s are re-grounded first — SKILL.md step 6).
   - **Pre-discharged** — an *executable* demand already exists (the design stated it and step 2 extracted it as `form: test`). Credit it explicitly; don't re-litigate. A clause-form binding does not pre-discharge — it leaves the obligation open (that is the worked example's R4 firing).
   - **Waiver candidate** — plausibly acceptable to skip; the human decides, and the decision is recorded as `Demand {form: waiver}`.
4. The gate closes when every rule has its `evaluated` entry, every obligation is discharged — by an executable demand or a recorded waiver, never by a ledger claim — every hole has a human answer, and every load-bearing claim in the ledger carries an executed probe (a `reachability` or `behavior` claim left `unprobed` is itself a hole — see "Probed claims").

The types are **routes, not partitions**: one element can be both. A design hole, once the human resolves it, frequently spawns a test obligation (the undecided cache key becomes, decided, a uniqueness demand) — record the element in both lists, linked (`resolved_to: <demand id>` on the hole).

## Delta grammar

Change kinds are finite: `{add, remove, modify} × {actor, boundary, facet, edge, property}`. Each cell fires a rule or is a documented no-op — blind spots are enumerated, not silent.

| | add | remove | modify |
|---|---|---|---|
| **actor** | no rule alone — an actor with no edges has no contract surface; its edges fire the rules | R5 (live in-edges) | `frame` change → recompute R2 demand placement |
| **boundary** | facet rules fire per facet (below); R0 on `unknown` fields | R5 (live in-edges); demands bound to it now dangle → R0 | via its facets |
| **facet** | the facet's rule fires (R1 payload, R2 identity, R3 access, R4 domain) — a facet **materializing on existing structure** counts (e.g. a boundary becoming multi-via) | demands bound to the facet dangle → R0; a dropped contract on a boundary with live in-edges → R5 (its trigger names removed facets; the boundary's in-edges are the dependents) | invariant field change → re-fire the facet's rule (new `key_axes` → R2; new `distinguished` member → R4) |
| **edge** | R1 (`sends` → payload), R2 (`write` → identity; a new `drives` edge over writers into an identity-facet boundary also fires — its `multiplicity` selects the form), R4 (`read` → domain), R3 (new `via` on a reached boundary), R5 (`mode: remove`) | the edge's dependents orphaned → R5 | `mode`/`via` change → R3; `interpolates` change → R2 |
| **property** | subsumed by modify | subsumed by modify | `drives.multiplicity` flip → R2 form re-selection; `trust` change → R3 + R0 |

The `modify` column is where add-only thinking goes blind: a property flip with no topology change (serial → concurrent; a via's trust level changing) fires obligations on its own. Within one run, extraction assigns `modify` directly from the design (Procedure 1); across runs, stable element `id`s let the graph diff itself — without stable identity every change degenerates to remove+add.

## The rules

Each rule: **trigger** (a predicate over formal slots) → **obligation** (the demand that must exist, with its derivable assertion content) → **canonical escape** (the shipped bug this rule would have computed).

### R0 — well-formedness and reconciliation

- **Trigger:** a `binds:` address resolving to nothing in structure ∪ delta; an invariant field left `unknown` (an uncited `key_axes` counts — schema.md); a `key_axes`/`interpolates` member outside the `axes:` registry; an edge endpoint undefined. Plus the bidirectional check — the gate's one deliberate prose reading: a normative design sentence binding no element (extraction gap or phantom design); a delta element tracing to no design sentence (invented scope). Record in `gate.evaluated` that the reconciliation ran.
- **Output:** design holes, not test obligations — each names the artifact to fix (`provenance` routes it).
- **Canonical:** a design that consumes a knob nothing defines; an access via whose confinement policy is undecided.

### R1 — unread channel

- **Trigger:** an edge with `sends` to a payload-facet boundary, and no executable `kind: shape` demand binds `interacts(...).payload`.
- **Obligation:** a shape demand. Derivable assertions, from the facet: the fake records the inbound payload; `roles-disjoint-sources` — no two parts share a source (the same template must not arrive under two roles); `all-slots-bound` — no part contains an unsubstituted `{...}` token.
- **Canonical:** #534 dual prompt — the full template passed as both the raw system prompt (literal `{story}`/`{lesson}` braces) and, rendered, as the user turn; the suite drove a `FunctionModel` that ignored `messages` and was structurally blind to it.

### R2 — shared sink

- **Trigger:** an identity-facet boundary written by ≥2 writers (existing ∪ delta), **or by one writer driven over multiple invocations** (a fan, a batch, a retry — key coverage is over writer *invocations*, not writer edges), or gaining a new `drives` edge over its writers, or a `drives.multiplicity` / `interpolates` / `key_axes` change.
- **Obligation:** two parts. (a) *Key coverage:* every writer's `interpolates` covers every axis its invocation set varies on — checked against `derivations`: a value with `injective: false` does **not** cover its axis. (b) *A uniqueness demand* driving the writers into one root, **bound at the composition frame** (the actor that fans the writers), never the leg — a single-leg test cannot see a cross-leg collision. Form selection keys on `sharing` first: `unique-key` → by multiplicity (`serial` → drive the writers in turn — deterministic, the second `w`-open truncates the first — with a positive control that both writes landed as distinct real content; `concurrent` → a genuine interleaving); `serialized-append` → the demand is atomic/serialized append (no torn line, no lost update) under a genuine interleaving, whatever the declared multiplicity.
- **Canonical:** #527 per-lead trace names colliding across the two direction legs (the spec's own docstring scoped distinctness to per-lead within one invocation); #534 `{error_prefix}.{lesson_stem}` — same mechanism, different surface form. The typed predicate catches both; similarity-to-the-first-instance would not.
- **Sharper when read:** if the identity boundary is also **read** (a cache, a lookup), an under-covering key is a read-path bug, not just a lost write — the reader returns *another key's content* (same-stem files from two intake dirs serving each other's cached summary is a correctness and disclosure bug; note this fires on one writer driven over both dirs — the invocation clause above). Same trigger; write the witness in read terms and the uniqueness demand asserts no cross-read.

### R3 — cross-via parity

- **Trigger:** an access-facet boundary with ≥2 vias, or a via added to a boundary an existing via reaches. If a via's `constraints` is `unknown`, R0 fires first — decide the policy, then pin it.
- **Obligation:** one parity demand per (constraint × via) cell, bound at `<boundary>.access[<via>]` so discharge is per-cell, never facet-wide: every constraint the established via enforces (denylist, clamp, confine, …), the new via enforces too — asserted over **all** vias, since a constraint pinned on one surface and silently absent on its sibling is the canonical fail-open.
- **Canonical:** #517 jq path-gate — the bash lane admitted bundled flags and lacked denylist parity with the read tool; each surface read alone looked correct.

### R4 — domain coverage

- **Trigger:** a `read` edge to a domain-facet boundary, or a domain facet gaining members/alternatives.
- **Obligation:** an executable demand per `distinguished` member — above all the falsy member when `falsy_valid` (an `x or DEFAULT` coercion silently swallows it) — and per `documented_alternatives` entry, bound at `<boundary>.domain.alternatives[<v>]` so discharge is per-entry. Entries whose `crosses_validation` is `true` come first; `unknown` there is an R0 hole (grounding establishes the crossing — schema.md). Pin the crossing either way: the advertised combination works, or it fails loud and legibly.
- **Canonical:** #534 `wall_clock_timeout or SUBAGENT_TIMEOUT` turning a valid 0 into the default; #527 `ORACLE_EFFORT="none"` fatal under the documented `claude-*` A/B override — the spec tested only the shipped default column.

### R5 — subtraction and conservation

- **Trigger:** a removed element — actor, boundary, edge, a `mode: remove` edge, or a facet (a dropped contract) — whose dependents are live: for actors, boundaries, and edges, live in-edges; for a facet, its boundary's live in-edges.
- **Obligation:** a survival demand per dependent — the workflow that ran through the removed element completes via its substitute; if the substitute structurally cannot discharge it (the replacement takes one file where the original fanned N), that is a design hole, not a test to write.
- **Judgment extension — not slot-computable, and flagged as such:** when the delta *tightens* a constraint or flips a default rather than removing anything, ask whether a security-critical caller is left constructible in the newly-unsafe state; if so, mint a safe-by-construction demand — the critical caller *cannot be built* unsafe; assert the constructor raises, not merely that it behaves when configured right. This half rests on the author asking the question, not on a trigger — record in `gate.evaluated` that it was considered.
- **Canonical:** #517 — the suite tested only the new restriction and silently regressed the workflows the old surface quietly served.

## Probed claims — the ledger

The rules compute the right *questions*; the ledger keeps their *answers* honest. Every statement the spec rests on about reality-as-it-is is a falsifiable prediction, recorded with the probe that tests it and what the probe observed — because the escapes that ship past a green suite are dominated by plausible prose answers one probe would have refuted. Five kinds, keyed by what the probe is:

- **census** — a completeness claim (all writers / readers / copies / consumers of X). Probe: the search plus its full hit list.
- **behavior** — a claim about what existing code does (a design's bug story, a stated default, "already handles Y"). Probe: run it and watch.
- **reachability** — who or what can reach a surface, and whether a value or state is constructible ("main cannot read that dir", "the stem is filesystem-constrained"). Probe: the grep, or drive the seam.
- **discharge** — a pre-discharge credit or a waiver's rationale. Probe: whatever the rationale rests on (and pre-discharge binds the same *edge*, not merely the same boundary).
- **primitive** — an I/O primitive's contract (its exception taxonomy, its normalization, its defaults). Probe: execute the primitive, in the runtime container when the binary matters.

Two guards make the ledger bite:

- **A probe does not discharge a test obligation.** A claim can inform a waiver or correct the design, but an obligation still closes only via an executable demand or a recorded waiver. A probed tolerance that no test pins ships untested — the ledger's own failure mode, and the thing a later change silently breaks.
- **A trust-resolving claim is the first thing to probe.** When a rule's `fired: false`, a hole's resolution, or a waiver turns on "it's unreachable / constrained / already gated / cannot be built unsafe", that claim is where a blind spot hardens into green. Reachability and safety are `reachability`-kind claims with *executed* probes, never prose — "the OS/gate/filesystem constrains it" is a probe target, not an answer.

A claim only the not-yet-written implementation can settle is `verdict: deferred` and transfers to write-code-from-spec, which probes it when there is code to probe.

## The artifact — spec_graph_<issue-or-slug>.yaml

One file per spec, committed **beside the suite** (same directory as the new tests, named `spec_graph_<issue-or-slug>.yaml`), reviewed by the human *as part of the spec*:

```yaml
schema_version: 1
design: <issue # or doc path>
base: <SHA the spec branch forked from — write-code-from-spec's gate diffs against it>
demands:   [...]      # the resolved demand list, waivers included — the spec proper
structure: {axes: [...], actors: [...], boundaries: [...], interacts: [...], drives: [...]}
claims:              # every load-bearing statement about existing reality, probed not asserted
  - {id: <slug>, kind: census | behavior | reachability | discharge | primitive,
     claim: "<one falsifiable sentence>", probe: "<the exact command or procedure run>",
     observed: "<what happened>", verdict: holds | refuted | unprobed | deferred}
gate:
  evaluated: [{rule: R0..R5, fired: true | false}]   # every rule, every run — a missing entry reads as skipped
  obligations: [{rule: R2, element: <address>, witness: "<one sentence>", discharged_by: <demand id>}]
  holes:       [{rule: R0, element: <address>, resolution: "<the human's decision>", resolved_to: <demand id>}]
                        # resolved_to: present when the resolution spawned a demand
  pre_discharged: [{rule: R4, element: <address>, by: <demand id>, edge: <interacts/drives address>}]
handoff:
  forks:      ["<the fork and how it was resolved>", ...]
  refuted:    ["<a design claim the ledger refuted, and the correction>", ...]
  deferred:   ["<a claim only the implementation can settle — write-code-from-spec's probe>", ...]
  deviations: ["<degraded strong author | collapsed diff | manual slot check | reduced small-delta mode>", ...]
```

Downstream consumers: the human reviews it with the tests; `write-code-from-spec` reconciles the implementation's actual structure against it (unrealized addresses and invented scope both flag); the later review *can* diff the implementation against it — wiring the review stage to do so is future work (#537).

Formal-slot validation (kinds, forms, modes, vias, invariant vocabularies) is currently a hand check against schema.md — a `spec_graph` linter is deliberate future work tracked in #537. Until it exists, the step-9 gate records the manual check in `handoff.deviations`.

## Maintenance

Every future escape that ships past a green spec must be mapped: to existing (elements, rule) — an execution failure, fix how the flow ran; to a new rule over existing elements (common); or, rarely, to a schema change — and fields enter the schema only when a rule needs them (`drives.multiplicity` exists because R2's form selection reads it). An escape that fits no inventory is the strong author's territory and a candidate new blindness condition — expect those to be rare and treat them as the finding of the year, not a Tuesday.
