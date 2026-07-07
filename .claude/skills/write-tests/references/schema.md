# The spec-coverage graph — schema

The language the spec is written in. Two layers — **demands** (what we require) and **structure** (what exists or will exist) — joined by one relation, `binds`. The demand list is the spec proper; structure is its address space. An **obligation** is a missing demand the gate computes — a structure element the change touches whose contract lacks a binding demand; rules.md owns the definition and the residue types.

## Slot discipline: every slot declares its evaluator

Every slot in this schema is one of two kinds, and nothing in between:

- **Formal** (evaluator: a gate rule) — closed vocabulary, typed values, referential integrity. Rules consume *only* these slots (the two flagged exceptions are named in rules.md).
- **Semantic surface** (evaluator: an LLM or a human) — marked `nl:`, written as full sentences with real grammar, because a person reads it. No rule may reference an `nl:` slot.

The in-between — prose chopped into key-value fragments that no rule can evaluate ("NL without conjunctions") — is banned, and the ban is checkable: no rule reads an `nl:` slot; no formal slot contains free text. When a value doesn't fit a formal vocabulary, that is a signal to either grow the vocabulary (rare, demand-driven) or admit the content is semantic and write it as a sentence.

Invariant-bearing formal slots are **mandatory with explicit `unknown`**: the extractor must claim a value or confess ignorance. An `unknown` is a first-class finding (rules.md R0) — it forces grounding or a human decision. It is never a silent null.

## Behavior layer

```yaml
Demand:
  id:         <stable slug>
  kind:       behavior | seam | shape | uniqueness | parity | domain-outcome | survival | negative   # formal
  form:       clause | test | waiver                                              # formal
  executable: true | false          # derived: form == test — never set independently
  outcome:    {nl: "<full sentence: the observable result required>"}
  binds:      [<address>, ...]      # ≥1; each must resolve (else R0)
  rejected:   [{nl: "<branch not taken>"}, ...]   # optional decision channel
```

Kind semantics:

- **behavior** — driving the entry point under stated conditions produces a specific observable result (return value, written artifact, raised error). Demand #0 — the return-value contract — and most enumerated fault outcomes are behavior demands.
- **seam** — the declared entry point or injection seam exists with the stated signature (the deps parameter, the constructor argument, the returned handle). This is the demand "pin the seam as a demand" resolves to when the design gives a dependency no seam; it is discharged by construction when every test drives the target through it, and it is what write-code-from-spec's reconciliation reads.
- **shape** — the payload sent across an edge satisfies its payload facet's invariants.
- **uniqueness** — writes into a shared sink land on distinct paths / atomically (per the identity facet's `sharing`).
- **parity** — a constraint enforced on one `via` is enforced on every `via` that reaches the boundary.
- **domain-outcome** — a specific domain member (or member combination) produces a specific observable result.
- **survival** — a workflow that depended on a removed element still completes via its substitute.
- **negative** — something must *not* be observable; **requires a paired positive-control demand** on the same address under the complementary condition (checked in the step-9 gate), or it passes vacuously. A negative binds every surface the content could reach — each of the actor's out-edges — or it is silently scoped to only the addresses someone thought to bind.

Form assignment: extraction marks a demand `test` when the suite is to pin it — the default; `clause` records a deliberate deferral to prose, and a clause-only binding on an obligated element leaves the obligation open (it never pre-discharges a rule). `waiver` is a human's recorded decision not to test something — minted only at step 7, an examined no, kept in the artifact.

## Address forms

An address names a structure element or a part of one:

```
<actor-id>                                # an actor
<boundary-id>                             # a boundary
<boundary-id>.<facet>                     # a facet         e.g. out_dir.identity
<boundary-id>.domain.distinguished[<v>]   # a domain member e.g. SUMM_TIMEOUT.domain.distinguished[0]
<boundary-id>.domain.alternatives[<v>]    # a documented_alternatives entry
<boundary-id>.access[<via>]               # one access cell e.g. jq_path.access[bash]
interacts(<actor>-><boundary>)            # an edge
interacts(<actor>-><boundary>).payload    # the edge's outbound payload
interacts(<actor>-><boundary>).response   # the edge's inbound response
drives(<actor>-><actor>)                  # a drive edge
```

An address that resolves to nothing in structure ∪ delta is an R0 finding, not an error to silently fix.

## Structure layer

```
Actor:                    # entry point, sibling producer, external driver (cron, workflow)
  id:         <stable slug>
  frame:      leg | composition       # formal — R2 uses it to place uniqueness demands
  provenance: design | code           # formal — which artifact defines it / where to fix

Boundary:                 # unified seam / resource / knob / surface — anything with a contract
  id:         <stable slug>           # stable across runs and across extraction passes: key by role+origin, not display name
  provenance: design | code
  facets:     {<facet>: <body>, ...}  # composable mapping; may be {}

interacts:  Actor -> Boundary
  mode:         invoke | read | write | remove       # formal
  via:          argv | read-tool | bash | http | env | api | fs | ...   # formal, per-repo vocabulary
  provenance:   design | code          # formal — delta membership (rules.md, Procedure); R0 routing
  sends:        <payload ref>          # present iff data flows outbound; detailed by the payload facet
  interpolates: [<axis>, ...]          # for write edges: the axes the written path varies on
  transport:    llm | subprocess | fs | http | ...   # extraction hint ONLY — no rule reads it

drives:     Actor -> Actor
  provenance:   design | code          # formal — delta membership; R0 routing
  multiplicity: serial | concurrent    # formal — selects R2's obligation form
```

The graph also carries one **`axes:` list — the axis registry**: every `key_axes` / `interpolates` member must be an axis declared there, or a `derivations` value derived from one; membership is R0-checked. Two extraction passes coining different names for one axis (`stem` vs `source_stem`) is exactly the join-breaker the registry exists to prevent.

A facetless boundary (a plain read-only input) generates no obligations — the schema stays quiet where there is no contract.

## Facets

Composable contracts on a Boundary. Rules key on facets, never on transport.

```
payload:                  # something is SENT here; its composition is a contract
  parts:
    - {role: system, source: const:<NAME>}
    - {role: user,   source: template:<NAME>, slots: {<slot>: <address>}}
  invariants: [roles-disjoint-sources, all-slots-bound]    # closed vocab, checked per rules.md R1
  nl: "<what this payload is, for the human>"

identity:                 # things landing here must be distinguishable
  key_axes:  [<axis>, ...]            # the FULL key, read off the resource, not the implementation
  evidence:  {nl: "<where each axis was read off the resource: path template, docs, call-site>"}
                                      # a claimed key without evidence is treated as unknown (R0)
  derivations:                        # when a writer interpolates a function of an axis
    - {value: <name>, fn_of: <axis>, injective: true | false}   # injective:false does NOT cover the axis
  sharing:   unique-key | serialized-append

domain:                   # a valued input
  type:          <int | str | enum | ...>
  refinement:    {nl: "<constraint in words, e.g. non-negative>"}   # semantic; the formal members below are what rules read
  default:       <value>
  distinguished: [<value>, ...]       # members that MUST be individually exercised: the falsy member,
                                      # boundary values, documented special values
  falsy_valid:   true | false
  documented_alternatives:            # every override the design/docs advertise
    - {value: <value or combination>, crosses_validation: true | false | unknown}
                                      # crosses_validation: does the shipped default stay valid under it?
                                      # (a value valid for one provider may be rejected by another) — grounding establishes this

access:                   # reachable via more than one path
  constraints_by_via:
    <via>: {trust: operator | attacker-influenced | derived,      # closed vocab
            constraints: [<denylist | clamp | confine | ...>] or unknown}
```

Consumers are not a facet — they are derived: the live in-edges (`interacts` or `drives`) from other elements. R5 reads them on removal.

## Field roles

Every field earns its place by naming its consumer; a field nothing consumes is extraction cost and drift risk.

| Field | Consumer | Role |
|---|---|---|
| `interacts.mode` / `.sends` / `.interpolates` / `.via` | R1/R2/R3/R5 triggers | rule input |
| edge `provenance` (`interacts`, `drives`) | delta membership (rules.md, Procedure); R0 routing | rule input |
| `drives.multiplicity`, `Actor.frame` | R2 form selection + demand placement | rule input |
| facet invariants (`key_axes`, `derivations`, `sharing`, `distinguished`, `falsy_valid`, `documented_alternatives`, `constraints_by_via`) | R2/R3/R4 predicates | rule input |
| `documented_alternatives[].crosses_validation` | R4's crossing obligation | rule input |
| `axes` (the registry) | R0 membership; R2's cross-writer join | rule input |
| `payload.parts` / `.invariants` | R1 trigger + the demanded test's assertion template | rule input + obligation content |
| `domain.type` / `.default` | R4 obligation content — the baseline column the alternatives cross from | obligation content |
| `Demand.kind` / `.form`, `binds` | the gate's join (`executable` is derived from `form`) | rule input |
| `Demand.rejected` | step-4 silent-branch diff; step-7 decision record | decision channel |
| element `provenance` | R0 routing; "which artifact do I fix" | completeness forcer |
| mandatory-with-`unknown` on invariants; `identity.evidence` | forces claim-or-confess, with the claim's source cited | completeness forcer |
| `id` | graph diff across runs; witness text | identity |
| `transport` | extraction reliability only | hint (the lone exception) |
| `nl:` slots, `refinement`, witness strings | the human / the test author | readability |

## Extraction contract

Two extractors populate the graph; their outputs meet at the gate.

**The grounding agent (structure, `provenance: code`)** emits the neighborhood the change attaches to:
- every shared root the change touches, with **all** its writers, their path templates, and the axes each interpolates — naming the search that established the writer list;
- every sibling surface reaching the same resources, with the constraints it enforces (as `constraints_by_via`, trust labeled);
- the consumers of anything the design removes — found by *reading* prompts and call-sites (a prompt line reading "grep, not index" names a consumer of grep), never by signature grep — naming the sweep that established the list;
- the real semantics of every external tool driven (`--help`, docs — not priors);
- every config knob: type, default, distinguished members, documented alternatives — and, per documented alternative, whether the shipped default stays valid under it (`crosses_validation`).

**Demand extraction (structure, `provenance: design`)** materializes the rest: resolving `binds:` addresses pulls the demanded boundaries, facets, and edges into existence. At spec time the delta *is* this demand-implied structure.

Both extractors fill every invariant field or write `unknown`. Reconciliation is bidirectional (rules.md R0): every normative design sentence binds ≥1 element; every delta element traces to a design sentence.

**Extraction completeness is the gate's single point of failure**: an element missing from the graph is invisible to every rule, and a clean gate then *certifies* the blind spot. No mechanical cross-check exists yet — it, and boundary-identity keying across passes, are tracked in #537. Until then: the brief names how each writer/consumer list was established, the step-5 name reconciliation unifies the two extractions' ids and axes, and the strong author (SKILL.md step 3) is explicitly charged with hunting the brief's edges.

## Worked example — demands first

Design: *"`summarize(path, out_dir, llm)` reads a text file, has an LLM summarize it, writes `<stem>.summary` into `out_dir`, returns the summary. `SUMM_TIMEOUT` caps the LLM call; 0 means no limit."* Existing code: `batch.py` fans `summarize` serially over many files into one `out_dir`.

```yaml
demands:
  - {id: returns_summary, kind: behavior, form: test,
     outcome: {nl: "summarize returns the LLM's reply and writes it to <stem>.summary in out_dir"},
     binds: ["interacts(summarize->llm).response", "interacts(summarize->out_dir)"]}
  - {id: timeout_zero, kind: domain-outcome, form: clause,
     outcome: {nl: "with SUMM_TIMEOUT=0 the LLM call runs with no time limit"},
     binds: ["SUMM_TIMEOUT.domain.distinguished[0]"]}

structure:
  axes: [input_file]
  actors:
    - {id: summarize, frame: leg,         provenance: design}
    - {id: batch_run, frame: composition, provenance: code}
  boundaries:
    - id: llm
      provenance: design
      facets:
        payload:
          parts:
            - {role: system, source: const:SYSTEM}
            - {role: user,   source: template:TEMPLATE, slots: {text: input_file}}
          invariants: [roles-disjoint-sources, all-slots-bound]
          nl: "the user turn is the summarization request over the file's text"
    - id: out_dir
      provenance: code
      facets:
        identity:
          key_axes: [input_file]
          evidence: {nl: "the write is one `<stem>.summary` per input file — read off batch.py's output template"}
          derivations: [{value: stem, fn_of: input_file, injective: false}]
          sharing: unique-key
    - id: SUMM_TIMEOUT
      provenance: design
      facets:
        domain: {type: int, refinement: {nl: "non-negative seconds"}, default: 30,
                 distinguished: [0], falsy_valid: true, documented_alternatives: []}
    - {id: input_file, provenance: design, facets: {}}
  interacts:
    - {from: summarize, to: input_file,   mode: read,   via: argv, provenance: design}
    - {from: summarize, to: SUMM_TIMEOUT, mode: read,   via: env,  provenance: design}
    - {from: summarize, to: llm,          mode: invoke, via: api,  provenance: design, sends: payload, transport: llm}
    - {from: summarize, to: out_dir,      mode: write,  via: fs,   provenance: design, interpolates: [stem]}
    - {from: batch_run, to: out_dir,      mode: write,  via: fs,   provenance: code,   interpolates: [stem]}
  drives:
    - {from: batch_run, to: summarize, provenance: code, multiplicity: serial}
```

The gate over this (rules.md): R1 fires — `interacts(summarize->llm).payload` has no `kind: shape` demand; R2 fires — two writers interpolate `stem`, a non-injective derivation of `key_axes: [input_file]`; R4 fires — `distinguished[0]` is bound only by a non-executable clause. Three obligations, each with a witness naming the missing test — none of which required the author to remember anything.
