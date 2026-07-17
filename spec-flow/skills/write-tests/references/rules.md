# Gate rules and the spec_graph artifact

The gate computes the join of the behavior layer against the structure layer and emits **typed residue**. The rules are *guaranteed question-generators*: an enumeration lens might ask the two-writer collision question; a rule makes sure it is asked, every run — and its answer is routed to a real oracle (a probe or the human), never left as the author's prose. It runs after the address space is materialized (SKILL.md step 5) and before human resolution (step 7). Rules R1–R5 trigger on predicates over formal slots (schema.md, slot discipline); two flagged parts read judgment instead — R0's reconciliation half and R5's restriction extension — and each records in the artifact that it ran. Every hit carries a **witness** — the concrete element and the missing demand — so the output is actionable, never a score.

## Procedure

1. Compute the delta: every structure element or edge the change adds, removes, or modifies. Change kinds are assigned **at extraction, from the design** — a first run needs no prior graph: an element or edge the design introduces is `add`, one whose property or semantics the design alters is `modify`, and `provenance` marks which side each came from (demand-implied structure is `provenance: design`; the grounded neighborhood it attaches to is `code`). Across runs, stable `id`s let the graph diff itself as a second source of change kinds.
2. For each delta element, fire the matching rules below, and record **every rule's outcome — fired or clean — in `gate.evaluated`**: a rule with no entry reads as skipped, not as clean.
3. Classify every hit into the typed residue:
   - **Test obligation** — a demand must exist and doesn't; carries derivable assertion content. Minted as an executable demand at SKILL.md step 6 and reviewed at step 7.
   - **Design hole** — a decision is missing, not a test: an `unknown` invariant, an unresolvable address, a substitute that structurally cannot discharge its survival demand. Routed to the human (fact-shaped `unknown`s are re-grounded first — SKILL.md step 6).
   - **Pre-discharged** — an *executable* demand already exists (the design stated it and step 2 extracted it as `form: test`). Credit it explicitly; don't re-litigate. A clause-form binding does not pre-discharge — it leaves the obligation open (that is the worked example's R4 firing).
   - **Waiver candidate** — plausibly acceptable to skip; the human decides, and the decision is recorded as `Demand {form: waiver}`.
4. The gate closes when every rule has its `evaluated` entry, every obligation is discharged — by an executable demand or a recorded waiver, never by a ledger claim — every hole has a human answer, every load-bearing claim in the ledger carries an executed probe (a `reachability` or `behavior` claim left `unprobed` is itself a hole — see "Probed claims"), and every spend-point — a `fired: false`, a waiver's rationale, a pre-discharge credit, a `binds_waivers`/`actor_waivers` entry — cites the claim id it rests on.

The types are **routes, not partitions**: one element can be both. A design hole, once the human resolves it, frequently spawns a test obligation (the undecided cache key becomes, decided, a uniqueness demand) — record the element in both lists, linked (`resolved_to: <demand id>` on the hole).

## Delta grammar

Change kinds are finite: `{add, remove, modify} × {actor, boundary, facet, edge, property}`. This table is the **guide-word grid** (HAZOP): each cell is a deviation operator walked over the structure, and it either fires a rule or is a documented no-op — blind spots are enumerated, not silent.

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
- **Canonical:** a dual-prompt escape — the full template passed as both the raw system prompt (literal `{slot}` braces) and, rendered, as the user turn; the suite drove a model stub that ignored `messages` and was structurally blind to it.

### R2 — shared sink

- **Trigger:** an identity-facet boundary written by ≥2 writers (existing ∪ delta), **or by one writer driven over multiple invocations** (a fan, a batch, a retry — key coverage is over writer *invocations*, not writer edges), or gaining a new `drives` edge over its writers, or a `drives.multiplicity` / `interpolates` / `key_axes` change.
- **Obligation:** two parts. (a) *Key coverage:* every writer's `interpolates` covers every axis its invocation set varies on — checked against `derivations`: a value with `injective: false` does **not** cover its axis. (b) *A uniqueness demand* driving the writers into one root, **bound at the composition frame** (the actor that fans the writers), never the leg — a single-leg test cannot see a cross-leg collision. Form selection keys on `sharing` first: `unique-key` → by multiplicity (`serial` → drive the writers in turn — deterministic, the second `w`-open truncates the first — with a positive control that both writes landed as distinct real content; `concurrent` → a genuine interleaving); `serialized-append` → the demand is atomic/serialized append (no torn line, no lost update) under a genuine interleaving, whatever the declared multiplicity.
- **Canonical:** per-key output names colliding across two legs of one fan-out (the spec's own docstring scoped distinctness to within a single invocation); a `{prefix}.{stem}` filename collision is the same mechanism in a different surface form. The typed predicate catches both; similarity-to-the-first-instance would not.
- **Sharper when read:** if the identity boundary is also **read** (a cache, a lookup), an under-covering key is a read-path bug, not just a lost write — the reader returns *another key's content* (same-stem files from two intake dirs serving each other's cached summary is a correctness and disclosure bug; note this fires on one writer driven over both dirs — the invocation clause above). Same trigger; write the witness in read terms and the uniqueness demand asserts no cross-read.

### R3 — cross-via parity

- **Trigger:** an access-facet boundary with ≥2 vias, or a via added to a boundary an existing via reaches. If a via's `constraints` is `unknown`, R0 fires first — decide the policy, then pin it.
- **Obligation:** one parity demand per (constraint × via) cell, bound at `<boundary>.access[<via>]` so discharge is per-cell, never facet-wide: every constraint the established via enforces (denylist, clamp, confine, …), the new via enforces too — asserted over **all** vias, since a constraint pinned on one surface and silently absent on its sibling is the canonical fail-open.
- **Canonical:** a path-gate whose bash lane admitted bundled flags and lacked denylist parity with the read-tool lane; each surface read alone looked correct.

### R4 — domain coverage

- **Trigger:** a `read` edge to a domain-facet boundary, or a domain facet gaining members/alternatives.
- **Obligation:** an executable demand per `distinguished` member — above all the falsy member when `falsy_valid` (an `x or DEFAULT` coercion silently swallows it) — and per `documented_alternatives` entry, bound at `<boundary>.domain.alternatives[<v>]` so discharge is per-entry. Entries whose `crosses_validation` is `true` come first; `unknown` there is an R0 hole (grounding establishes the crossing — schema.md). Pin the crossing either way: the advertised combination works, or it fails loud and legibly.
- **Canonical:** an `x or DEFAULT` timeout coercion turning a valid `0` into the default; a documented `"none"` effort override fatal under an advertised A/B mode — the spec tested only the shipped default column.

### R5 — subtraction and conservation

- **Trigger:** a removed element — actor, boundary, edge, a `mode: remove` edge, or a facet (a dropped contract) — whose dependents are live: for actors, boundaries, and edges, live in-edges; for a facet, its boundary's live in-edges.
- **Obligation:** a survival demand per dependent — the workflow that ran through the removed element completes via its substitute; if the substitute structurally cannot discharge it (the replacement takes one file where the original fanned N), that is a design hole, not a test to write.
- **Judgment extension — not slot-computable, and flagged as such:** when the delta *tightens* a constraint or flips a default rather than removing anything, ask whether a security-critical caller is left constructible in the newly-unsafe state; if so, mint a safe-by-construction demand — the critical caller *cannot be built* unsafe; assert the constructor raises, not merely that it behaves when configured right. This half rests on the author asking the question, not on a trigger — record in `gate.evaluated` that it was considered.
- **Canonical:** a tightened access surface whose suite tested only the new restriction and silently regressed the workflows the old surface quietly served.

### R6 — rendered-sink trust walk

- **Trigger:** an edge whose payload is rendered or parsed text — a prompt splice, a generated heading or key, a line protocol, a table row — gaining a value from the delta, or a delta value reaching an existing such sink.
- **Obligation:** walk every value that reaches the rendered output — the **frame** (headings, keys, separators, the template itself) as well as the payload slots — and label each with its **chooser** (who selects this value: the author, a config, a model, an attacker-influenced file or name) and its **sanitizer** (what transformation stands between the chooser and the sink). Every slot whose chooser is model- or attacker-influenced and whose sanitizer column is empty is an obligation: a hostile-value demand at the render site, or a `reachability` break-attempt probe on the *source* — what characters does the gate, the filesystem, the schema actually admit? "It's just a filename / an id / a key" is the chooser question unasked, not answered. Sanitizing the values while rendering the frame raw discharges nothing — the frame slots are the recurring escape.
- **Canonical:** a manifest rendering `## {path.stem}` raw while only frontmatter *values* pass `yaml.safe_dump` — the write gate's `[^\x00]*` admits newlines, so a gate-approved filename forges a sibling section for a lesson the corpus does not contain. Three consecutive spec runs probed the value channel and never asked who chooses the stem.

## Probed claims — the ledger

The rules compute the right *questions*; the ledger keeps their *answers* honest. Every statement the spec rests on about reality-as-it-is is a falsifiable prediction, recorded with the probe that tests it and what the probe observed — because the escapes that ship past a green suite are dominated by plausible prose answers one probe would have refuted. Claims enter three ways, none of them "the author noticed": **inherited** from discuss-issue's sweep (the doc's `claims:` block, carried over verbatim — optionally marked `source: discuss`), **raised at extraction and grounding** (steps 1–2), and **demanded by a consumer** — a spend-point's rationale or a fake's fault content that needs a claim to cite. Six kinds, keyed by what the probe is:

- **referential** — the named symbol / path / signature exists as described. Probe: read, import, or stat it. Mostly arrives pre-probed from the sweep; re-check any the base has moved under.
- **census** — a completeness claim (all writers / readers / copies / consumers of X). Probe: the search plus its full hit list.
- **behavior** — a claim about what existing code does (a design's bug story, a stated default, "already handles Y"). Probe: `probe_kind: executed` — run it and watch; a `read` probe on a behavior claim is a finding (the instrument guard below). And the run samples the **types the boundary actually admits**, not the easy stand-in — a "skips malformed files" claim exercised only over well-formed files proves nothing about the undecodable-bytes path it silently drops (the same value-type discipline `primitive` carries one line down, applied to behavior).
- **reachability** — who or what can reach a surface, and whether a value or state is constructible ("main cannot read that dir", "the stem is filesystem-constrained"). Probe: a **break-attempt** — try to construct the forbidden value, drive the sealed seam — paired with a positive control showing the channel works at all. The verdict is only ever `unrefuted`, never confirmed: refutation is mechanical (one counterexample), confirmation is a universal over program behavior — a design that needs the universal *confirmed* routes to a safe-by-construction demand instead.
- **discharge** — a pre-discharge credit or a waiver's rationale. Probe: whatever the rationale rests on (and pre-discharge binds the same *edge*, not merely the same boundary).
- **primitive** — an I/O primitive's contract (its exception taxonomy, its normalization, its defaults). Probe: execute the primitive, in the runtime container when the binary matters. Probe (and later fixture) values must sample the **types the boundary actually admits**, not pre-normalized stand-ins: a quoted timestamp in a YAML fixture parses to `str` and proves nothing about `safe_dump`-of-`datetime`, which the unquoted form the real corpus admits would produce — a fixture that can only hand the primitive the easy type is the taxonomy assumption in disguise.

Each kind names the **instrument its probe must use**, recorded on the claim as `probe_kind` and gated against the kind (step 9): `referential` → `read` (read / import / stat); `census` → `search`; `behavior`, `primitive`, and `reachability` → `executed` (reachability's is the adversarial break-attempt with its positive control); `discharge` → the `probe_kind` the claim it cites requires. The read-vs-execute line is the whole point, not bookkeeping: a `behavior` or `primitive` claim recorded `probe_kind: read` is *"I inspected the code and it looked right"* wearing a probe's costume — precisely the move that ships a decode-time or taxonomy bug green, because a read holds at parse level over exactly the input the bug needs to see. An **inherited** claim whose kind requires `executed` but that arrives `read` or `unprobed` is re-probed here before it can back a demand — the sweep's pre-probed stamp carries the verdict, not the instrument.

These guards make the ledger bite:

- **A probe does not discharge a test obligation.** A claim can inform a waiver or correct the design, but an obligation still closes only via an executable demand or a recorded waiver. A probed tolerance that no test pins ships untested — the ledger's own failure mode, and the thing a later change silently breaks.
- **A trust-resolving claim is the first thing to probe.** When a rule's `fired: false`, a hole's resolution, or a waiver turns on "it's unreachable / constrained / already gated / cannot be built unsafe", that claim is where a blind spot hardens into green. Reachability and safety are `reachability`-kind claims with *executed* probes, never prose — "the OS/gate/filesystem constrains it" is a probe target, not an answer.
- **The probe's instrument matches the claim's kind.** Each claim records the `probe_kind` it actually used, gated against what its kind requires (the mapping above); a claim whose kind requires `executed` that closed on `probe_kind: read` is a finding. Not because reading is worthless — because a read cannot *falsify* a claim about what code does over an input, and only running it over that input can. This is the mechanical form of "run it and watch": the prose rule never bit on its own, because at gate time nothing separated an execution from an inspection.
- **A spend-point closes only by citation.** Every `fired: false`, waiver rationale, pre-discharge credit, and `binds_waivers`/`actor_waivers` entry names the claim id(s) it rests on, of the matching kind. An uncited rationale is `asserted` — a finding, not a pass.
- **A fake's fault content cites its claim.** The exception class or malformed shape a fake raises is probe-derived data (SKILL.md step 8), never authored belief — a guard and a test built from the same imagined taxonomy are the same wrong prior, green together.
- **The ledger ships in the artifact.** Claims live in the spec_graph's `claims:` block — the committed, reviewable one — not in a working file. A citation pointing at a side file the diff doesn't carry is indistinguishable from an uncited rationale to everyone downstream: the cold reviewer, write-code-from-spec, and the future session re-checking a claim the base has moved under.

A claim only the not-yet-written implementation can settle is `verdict: deferred` and transfers to write-code-from-spec, which probes it when there is code to probe.

## Suite verification — the null stub, conservation, and the reconciliation edge

Suite-verification checks that prove properties of the *suite itself* that no per-test rule can — run at step 9 unless the check says otherwise (the dismissal audit is dispatched earlier, at step 6). The first two interrogate the suite against the target and the doc; the rest interrogate it against **the run's own record** — measured escapes concentrate not in the tiers that gather facts but on the edges where a gathered fact must become a demand, an assertion, or a recorded no.

**Null-stub discrimination.** Write a throwaway implementation of the target that satisfies the imports and does nothing — functions return `None` or empty containers, writes never happen — and run the suite against it once. Every test must fail, **each on its own demand-specific assertion**: an import error or a shared fixture crash proves only that the file is broken, not that the test discriminates. A test that stays green binds nothing (the classic: a bare negative over empty output); a test that fails for someone else's reason is riding a sibling's assertion. Repair the test, delete the stub — it is never committed, and committing it would hand write-code-from-spec a skeleton to grow instead of a contract to meet.

**Conservation.** The suite is a hypothesis about the intent doc; this check tests the hypothesis instead of declaring it. Generate pointed questions from **both sides** — one per intent obligation, asked in the obligation's own surface-general terms ("can an input vanish with no visible trace?"), and one per test ("which obligation needs this?") — and have a reader who has **never seen the intent doc** answer them from the tests alone; an anchored reader confirms instead of measures. Diff the answers against the doc. Three verdicts route: an obligation the tests can't answer is **undischarged intent**; a test no obligation explains is **invented scope or a silently-resolved fork**; "unanswerable" is a first-class verdict, not a reader failure. Both findings route back through step 7 — never straight into the diff. One open-ended cold read (state the intent the suite implies, then diff against the doc) backstops the questions neither side generated; question-generation coverage is this check's known bound.

**Premise-disposition conservation.** Mechanical: every step-4 premise resolves to a demand's test, a step-7 fork/waiver record, or a `handoff.drops` entry with its reason — reconcile the counts. Conservation (above) audits the demands→tests edge; this audits the answered-premise→demand edge one step upstream, where a consensus answer can vanish without any downstream check noticing. The canonical loss: an ordering premise that reached full-answerer consensus with the correct expected value and simply never became a demand — green suite, silent hole.

**Grounding-fact→premise conservation.** Mechanical: every consequence-bearing fact the step-1 brief flagged — a side-effecting call on a read/write path, an unbounded sink, a shared trace (the closed shape vocabulary of SKILL.md step 1) — resolves to a premise, a claim, a demand, or an explicit `no-consequence` dismissal carrying its reason; reconcile the counts. This is premise-disposition conservation one tier further upstream: that check audits answered-premise→demand, this audits brief-fact→premise — the edge where a recorder side-effect like `_record_lesson_load` dies — present in the brief, carried into no premise, caught by nothing downstream. It closes the *omission* (a flagged fact with no disposition); it cannot judge whether a `no-consequence` call was *right* — that is the dismissal audit's charge, next.

**The dismissal audit — a cold read of the no-consequence calls.** The reconciliation above only checks that each flagged fact *has* a disposition, and a `no-consequence` dismissal is a judgment; so a fresh leaf, dispatched at step 6 (before the human seam, so a finding becomes a step-7 fork rather than a post-authoring re-litigation), reads the flagged brief facts and the demand list **cold — without the dismissal rationales** — and for each dismissed fact asks independently: does any demand rest on this? A dismissal it cannot reconstruct is a finding for step 7. Cold is load-bearing and not optional: handed the rationale ("it's just best-effort logging"), a reviewer ratifies it — the exact framing that makes such a side-effect invisible. It is the deliberate mirror of the cold reconciler below, which reads *hot*; leaning on that hot pass for this class asks the reader who was handed the rationale to catch that same rationale being wrong — the instrument this audit exists to replace. The audit **backstops, it does not guarantee** — the guarantee lives in the step-1 tagging and the mechanical reconciliation; the cold read earns its keep only on the wrong-dismissal residue the counts cannot see.

**Refuted-claims cross-check.** Mechanical: scan every test's expected-side literals against the refuted and stale-marked claims. A test asserting content a refutation corrects has pinned the probed bug green — the suite and its own ledger disagree, and the minimal repair under "never weaken a test" preserves the bug. Repair the test to pin the correction (red against HEAD is a spec's expected state); never resolve the contradiction by dropping the refutation. The null stub cannot catch this (the assertion is true against today's code) and conservation cannot either (it maps demands to tests, not assertions to claims).

**The cold reconciler.** A fresh agent on a frontier model (Opus) — not the orchestrator, not the step-8 author — reads the run's artifact trail (brief, ledger, dispositions, gate record) against the committed diff and asks: does the spec conserve everything the run learned? Its charge is the judgment-shaped residue the mechanical checks can't enumerate: **composition** — two facts probed separately whose intersection no demand binds — and **altitude** — a demand pinned at a different grain than its premise asked. It deliberately reads hot (the mirror of the review stage's cold read); its findings route back through step 7.

## The artifact — spec_graph_<issue-or-slug>.yaml

One file per spec, committed **beside the suite** (same directory as the new tests, named `spec_graph_<issue-or-slug>.yaml`), reviewed by the human *as part of the spec*:

```yaml
schema_version: 1
design: <issue # or doc path>
base: <SHA the spec branch forked from — write-code-from-spec's gate diffs against it>
demands:   [...]      # the resolved demand list, waivers included — the spec proper
                      # a form:test demand is a pointer {id,kind,form,binds,discharged_by}; its prose
                      # lives in the named test (check_binds scans that docstring). clause/waiver carry `outcome`.
structure: {axes: [...], actors: [...], boundaries: [...], interacts: [...], drives: [...]}
claims:              # every load-bearing statement about existing reality, probed not asserted
  - {id: <slug>, kind: referential | census | behavior | reachability | discharge | primitive,
     claim: "<one falsifiable sentence>", probe: "<the exact command or procedure run>",
     probe_kind: executed | read | search,   # the instrument ACTUALLY used — gated against `kind` (the ledger, above)
     observed: "<what happened>", verdict: holds | refuted | unrefuted | unprobed | deferred}
                     # unrefuted: reachability's ceiling — a survived break-attempt, never "confirmed"
                     # entries inherited from the discuss doc keep their ids; source: discuss is optional
gate:
  evaluated: [{rule: R0..R6, fired: true | false}]   # every rule, every run — a missing entry reads as skipped
  obligations: [{rule: R2, element: <address>, witness: "<one sentence>", discharged_by: <demand id>}]  # obligation→demand (a demand's own discharged_by is demand→test)
  holes:       [{rule: R0, element: <address>, resolution: "<the human's decision>", resolved_to: <demand id>}]
                        # resolved_to: present when the resolution spawned a demand
  pre_discharged: [{rule: R4, element: <address>, by: <demand id>, edge: <interacts/drives address>}]
handoff:
  forks:      ["<the fork and how it was resolved>", ...]
  refuted:    ["<a design claim the ledger refuted, and the correction>", ...]
  deferred:   ["<a claim only the implementation can settle — write-code-from-spec's probe>", ...]
  drops:      ["<premise name — why no demand was minted>", ...]   # every answered premise not in the suite/forks lands here (step-9 count)
  nullstub_passes: ["<test name — structure | reuse | parity>", ...]  # each recorded legitimate null-stub pass
  deviations: ["<degraded strong author | collapsed step 4 | manual slot check | reduced small-delta mode>", ...]
```

Downstream consumers: the human reviews it with the tests; `write-code-from-spec` reconciles the implementation's actual structure against it (unrealized addresses and invented scope both flag); the later review *can* diff the implementation against it — wiring the review stage to do so is future work.

Formal-slot validation (kinds, forms, modes, vias, invariant vocabularies) is currently a hand check against schema.md — a `spec_graph` linter is deliberate future work. Until it exists, the step-9 gate records the manual check in `handoff.deviations`.

## Maintenance

Every future escape that ships past a green spec must be mapped: to existing (elements, rule) — an execution failure, fix how the flow ran; to a new rule over existing elements (common); or, rarely, to a schema change — and fields enter the schema only when a rule needs them (`drives.multiplicity` exists because R2's form selection reads it). An escape that fits no inventory is the strong author's territory and a candidate new blindness condition — expect those to be rare and treat them as the finding of the year, not a Tuesday.
