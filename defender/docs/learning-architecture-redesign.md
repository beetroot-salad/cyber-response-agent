# Learning architecture — redesign (2026-07-30, revised 2026-08-11)

## Status

**Design, pre-implementation for the training loop. Two of the three original
components have since moved.** Amends the loop shape in `learning-loop.md` and
absorbs the deferred pointers in `learning-loop-actor-learning.md` (learning
actor) and `learning-loop.md` §Future Enhancements (live self-evaluation). When
this ships, those sections get rewritten rather than cross-referenced.

Held-out fixture recruitment is a **prerequisite for measuring any of this** and
is being handled separately. Every metric below is uncomputable until it lands.
`defender/fixtures/held-out/` still contains only a README.

### What the 2026-08-11 revision changed

The original draft had one architecture with three components. Two shipped or
were overtaken while the third was still on paper, and a working session then
reworked the third. Concretely:

- **§3 Runtime adversarial review shipped, twice.** #774 landed the write-time
  challenge gate; #796/#797 then replaced its three stages with two blind lenses
  plus a composer (`REVIEW_ROLES = ("support", "ablation", "composer")` in
  `runtime/challenge_gate.py`). The gate **writes no counter-story**, which
  retires §One corpus, one role as it was written.
- **#792 retired the offline oracle** from the learning loop entirely.
- **The oracle design inverted.** It no longer serves queries from a
  materialized world; it **intercepts real query results and modifies them**
  (§The oracle). This retires lazy generation, the base-world ledger, and the
  "scenario spec format" open question that this doc called its largest unknown.
- **Minimal-twin invariance is dropped.** Scenarios are seed → refined
  mutations with no enforced mechanical delta (§Seeds and mutations). `ΔW` is no
  longer a literal diff.
- **The judge's unit of comparison is the sibling pair**, and siblings share an
  investigation prefix up to the fork point (§The judge).
- **No `playground-v2/` file is an input.** Not the attack catalog, not
  `hosts/inventory.yaml`. A non-stale asset inventory is not a thing an
  arbitrary deployment has (§Seeds and mutations).
- **Environment facts became load-bearing** — they are the grounding substrate
  that replaces the config files, so §Environment facts is new and long, and
  environment mining moved onto the critical path.

## The diagnosis

The current loop is two mechanisms wearing one coat.

One mechanism is **counterfactual review of a real case**: a blind actor writes a
story against the lead sequence the defender actually ran, and the judge tests it
against the raw payloads. The other is **training against a simulated world**: the
oracle stands in for telemetry that was never produced.

They are fused because the oracle exists to bridge the actor's blindness. The
actor cannot see results (or it would mark its own homework), so its story has to
be converted into a falsifiable per-lead prediction before the real payloads can
contradict it. That is the oracle's actual job in this design: **it is a blinding
device, not a world model.** The judge has been white-box over the raw payloads
all along.

The cost of the fusion is that the oracle sits in the one place where its error is
undetectable. It answers a counterfactual about a world where something *else*
actually happened, which is why its whole vocabulary is a signed delta over
baseline, and why calibrating it required an entire golden-set campaign with a
held-out ledger.

This diagnosis stands and is now half-settled by events: #792 unfused the two
mechanisms by deleting the offline oracle, leaving counterfactual review as the
live gate and nothing training against a simulated world. This document is the
design for the missing half.

## The three moving pieces

The training loop is **questioner → oracle → judge**, around the **defender**
being trained. Naming them as roles rather than as pipeline stages is
load-bearing: the questioner and the judge are adversaries over the same
scenario, and the oracle is the only component that touches the real world.

| Role | Goal | Was |
|---|---|---|
| **Questioner** | author scenarios that teach, and are feasible and environment-aligned | the actor |
| **Oracle** | be a reliable proxy of the world | the telemetry oracle |
| **Judge** | improve both the questioner and the defender | the judge |
| **Defender** | the student — unchanged runtime | the defender |

The answer key is known by construction, so findings carry a warrant the current
loop cannot supply.

Two other components from the original draft remain, with changed standing:

**Frontier-keyed lesson retrieval** (§Retrieval) is unchanged and independent of
the training loop.

**Runtime adversarial review has shipped and is no longer part of this design.**
`runtime/challenge_gate.py` + `runtime/review/` run two blind lenses and a
composer on every confident close. It is a write-time gate, not a loop phase, and
`inconclusive` bypasses it. What matters here is what it *doesn't* do: the blind
lenses reconstruct rather than counter-argue, so **no counter-story is produced**,
and nothing under `learning/` reads `review_record.{turn}.json` today.

## The questioner

### Its goals conflict, and the doc previously ducked this

Four goals are in play: **teaching value**, **physical feasibility**,
**environment shape alignment**, and **environment distribution alignment**. Two
pairs genuinely fight.

**Teaching value vs. distribution — irreconcilable within one set.**
"Informative failure near the defender's frontier" is by construction selection
for the tail. Demanding the same corpus match the deployment's base rates demands
it be mostly boring. The resolution is two sets: the **curriculum is deliberately
tail-weighted**, the **held-out set is distribution-faithful**, and they never
mix. This is a second reason held-out recruitment is sequenced first.

The residue is narrower than it first appears. Because lesson retrieval is
**conditional** — a lesson enters context only when its selector matches the
frontier — a tail-weighted curriculum does not inflate the defender's global
escalation rate; the runtime alert distribution decides what loads. What survives
is *content* skew, delivered on target: if every training scenario on a given
frontier is malicious, the lesson written there encodes a skewed conditional and
fires exactly when that frontier appears.

The mitigation is a style rule, not a mechanism, and the corpus already follows
it. A lesson may state what an observable **licenses** (`loginuid=-1` licenses
non-interactive automated context and nothing more); it may not state a
**likelihood** ("authorized_keys writes are usually malicious"). The environment
corpus template already says this in its own words — *"Write what is TRUE about
this environment so the actor can reason WITH it — not 'do X' / 'don't do Y'"* —
and it should be lifted into the defender and questioner curator prompts too.

**Teaching value vs. feasibility** is resolved by §Seeds and mutations below:
mutations are refined rather than minimal, so coherence wins and mechanical
attribution is given up.

### Seeds and mutations

**No `playground-v2/` file is an input.** Not `attacks/catalog.yaml` — those
scenarios were built to exercise detection rules, not to teach triage — and not
`hosts/inventory.yaml`. A non-stale asset inventory is not something an arbitrary
deployment has, and maintaining one is its own problem; a design that depends on
one does not port.

The sources are **past tickets**, **threat intel**, and a **technique menu**
(MITRE), used as *enumerators*, with **environment facts as the grounding**
(§Environment facts).

Both wells are currently dry, and this is a build item rather than an assumption:

- `playground/ticket-server/seed/tickets.json` holds **0 tickets**.
- `playground-v2/threat-intel/seed/indicators.json` holds **15 atomic IOCs**
  (`{value, type, verdict, score, sources, tags}`) — enrichment-shaped, not
  scenario-shaped. "This IP is a tor exit, score 92" is a lookup answer, not a
  premise.

The mechanism half exists: `learning/tickets/ticket_seeds.py` already lists
closed tickets and maps them to `Seed(case_id, disposition, reason)`.

**The circularity is the thing to design around.** Closed tickets here carry the
*defender's own* disposition and reason. In a real SOC, past tickets are valuable
because an analyst adjudicated them; here they would be unadjudicated self-report,
so the curriculum would inherit the defender's errors and so would the answer key.
Two guards, both worth taking: seed from the ticket's **alert and observations,
never its disposition**, and gate the seed pool on human-adjudicated tickets.

**Division of labor:** tickets seed (they carry the deployment's real shape and
base rate), technique menu and intel enumerate and mutate (they carry variation
the ticket history does not contain). This maps onto the doc's existing mutation
vocabulary — technique variant, execution mechanism, identity, timing, cover
activity, authorization state — at two levels: the menu picks the seed's
technique, those axes are the mutation steps.

**Scenario generation is seed → refined mutations, one or two deep, with no
enforced mechanical delta.** A story-level difference propagates into completely
different downstream paths, and forcing a surgical single-fact flip produces
worlds that are incoherent or that require a closure the questioner cannot
declare honestly.

What this costs, stated plainly, because the original draft leaned on it:

- **Minimal-twin invariance dies.** "Everything outside the mutation set is
  identical by construction" is no longer true, and `ΔW` is no longer a literal
  diff. Auditing for unintended tells stops being a small-diff read.
- **Attribution weakens** from "everything else was held equal" to "did the
  defender establish the discriminating fact." The declared discriminator
  survives as the answer key and carries the weight.
- **Fork depth shortens.** Delta size sets how early siblings diverge, which sets
  how much variance reduction §The judge's shared prefix buys. At the limit —
  divergence on the first query — you are back to two independent runs.

The response to the third is to **measure realized fork depth and treat it as
questioner fitness**, not to re-impose a constraint. A mutation that stays
coherent yet still shares a long prefix produces a sharper signal than one that
forks immediately, and that is an observation rather than a rule.

Depth of one to two is a tightening of the original draft's unbounded descent.
It keeps revalidation incremental (one edit's feasibility, not a whole world),
keeps every child close to a *validated* ancestor, and keeps matched descent
meaningful — it is only informative at short distances.

### Placeholders and binding

**The questioner writes placeholders; the oracle binds them against the real
world.** A scenario names kinds, not referents —
`{{compute:web-server/internal}}`, `{{identity:service-account}}` — and binding
resolves each to an actual entity by querying.

This is the mechanism that replaces the deleted config files, and it pays four
ways:

- **Grounding with no config file and no cold-start corpus.** The questioner
  needs no prior knowledge of the deployment to write its first scenario.
- **Feasibility becomes mechanical.** An unresolvable placeholder *is* the
  infeasibility verdict — no LLM judging plausibility. This is §Scenario
  solvability's "prove it, don't assert it" moved one step earlier.
- **Deployment portability.** The same scenario template resolves differently in
  another org, so the curriculum is not bound to one lab.
- **Training does the mining.** Every binding is a real query whose answer is a
  deployment fact, so the bindings ledger accumulates an environment corpus as a
  byproduct.

**Scope limit on the mining claim: binding mines the entity graph, not query
semantics.** Resolving a placeholder teaches you which hosts exist. It does not
teach you that the CMDB indexes by hostname and not IP, that Falco reports the
Docker host while CMDB registers the logical host, or that a given stream does
not record row counts — and those are the most valuable facts in the corpus.
They are discovered when a query returns something *surprising*.

Partial recovery, and it is real: **informative bind failures are semantics
discoveries.** An oracle that tries CMDB-by-IP, gets nothing, retries by hostname
and succeeds has derived the CMDB fact at bind time. The residual is the part
that only surfaces mid-investigation, which is the runtime feed's job
(§Environment facts — producers).

**Placeholders and environment-fact keys are one vocabulary.** An unbound
reference is a placeholder; a bound one is an env-fact key
(`{{compute:web-server/internal}}` vs. `compute/web-1`). Binding is resolution.
See §The data model.

**Bind-time queries are the oracle's, not the defender's.** They must not land in
`executed_queries.jsonl`, or they pollute `ΔT` and the judge's read of what the
defender actually did.

## The oracle

### Interception, not serving

**Let the defender's gather queries execute for real. When a query is well-formed
and executes successfully, hook the result and apply the scenario's modifications
— adding and removing events, patching state — before returning it.**

This replaces the original draft's serving oracle over a materialized base world,
and it retires a whole class of problem with it: no unmaterialized territory, no
lazy generation, no total snapshots, and no need to decide whether captures are
per-envelope or per-window. The real environment *is* the base world, live and
self-consistent. Letting malformed queries fail for real is also training signal
that a synthetic world would destroy — the defender learns the actual query
surface.

It also dissolves this document's stated largest unknown. **"Scenario spec format
for systems-of-record state" is no longer the blocker**: the base is the real
deployment, and the spec is a diff against it.

**The constraint that makes or breaks it: the overlay is authored once, then
applied by code per query.** If an LLM decides the modification per response,
siblings contradict across queries — the defender asks for processes on a host,
then network connections on the same host, and two independent decisions produce
events that do not corroborate. That is the failure the original draft called
load-bearing, and it is the defender's whole method. Per-query becomes a
deterministic filter-and-merge: select overlay rows matching this predicate and
window, inject; apply removal predicates, drop. LLM cost moves from per-call to
per-scenario.

**Consistency is the load-bearing risk, not fidelity.** The defender corroborates
one system against another and pivots on values it got from an earlier answer. A
world that contradicts itself across a run teaches it that corroboration is noise.

**"Telemetry" undersells the spec.** Seven systems of record sit behind the typed
query tool and only one is an event stream. A scenario that modifies events and
lets identity / CMDB / change-mgmt / ticket / threat-intel answer unmodified
produces a host unknown to inventory and no CR for anything — and the defender
learns "no CR means malicious." The ambiguity that makes a case hard lives in the
state.

Three consequences the add/remove framing does not cover on its own:

- **Removal is harder than addition.** It is a predicate over real rows, and
  getting it wrong leaves contradicting rows behind. The golden set's
  `suppressed` delta class exists for exactly this shape.
- **Six of the seven systems have no events.** For identity, CMDB, change-mgmt,
  ticket, threat-intel and host-state the overlay is a **predicate over entities
  applied at every read**, not an edit to one response. If the patch says a host
  has a given owner, a list query returning that host among fifty rows must show
  it too. Response-level editing passes the obvious test and fails the list query
  silently.
- **The overlay is one ledger spanning all seven systems, not seven patches.** An
  injected SSH session must agree with the identity system's last-login, the
  event stream's auth record, and possibly a CR. Authoring them independently
  guarantees drift.

**Pin the scenario's time window to a fixed past window.** The deployment keeps
running — `playground-v2` alone has 21 Poisson-scheduled baseline actions — so
two runs at different times see different backgrounds and `ΔO` is contaminated by
drift that has nothing to do with the mutation. Pinning makes the real substrate
immutable so the only difference between siblings is the overlay. It costs
nothing and it is what makes `ΔO` readable.

**The fail-closed invariant inverts, so the test changes.** In the serving design
the hazard was accidentally reaching the real world (`query_tool.py:380` resolves
`registry.verbs(system)[verb]`, which falls through to the real adapters when no
override is threaded). Here, reaching the real world *is* the design, and the
hazard is a response **slipping past the applier** and returning unmodified truth
— a silent scenario deletion rather than a silent leak. The applier must be able
to assert "this envelope intersects the overlay and I patched it" versus "no
intersection," and that assertion is what a test pins.

The seam itself is cheap: `VerbRegistry` (`runtime/verbs.py:225`) is nominally
typed — its constructor refuses anything that is not a real `VerbGrant`, and
`decide()` is the single grant point — so the interception oracle is one subclass
overriding `verbs()`.

### The oracle is stateful

It remembers three distinct things, and conflating them is a defect:

- **The overlay** — what the scenario declares. Authored once, immutable for the
  run.
- **Bindings** — detail the overlay did not specify but a response needs: a PID, a
  session id, a source port, a timestamp inside a window. Invented at first
  materialization and **memoized forever after**.
- **The realization log** — what was actually served, per query. The same overlay
  row renders differently under different projections, aggregations and
  truncations, and the defender pivots on values from earlier answers. A value
  that was served has to keep existing.

### One oracle, one tool, per-fork

**A single oracle instance serves every fork, through a tool that names the fork
(`serve(query, fork_id)`).** This is not only a context saving. It is a
correctness requirement: the shared prefix in §The judge is only valid if both
forks return byte-identical responses across it, and two oracle instances would
independently invent the PIDs, session ids and ports the overlay left unspecified.
One bindings ledger shared across forks is what makes the prefix reproducible.

Fork detection falls out of the same component for free: serve a query under both
fork ids and compare. Identical means no fork is needed yet; different means this
is the fork point. No separate divergence checker is required.

### The oracle is also the feasibility and consistency checker

With no declared inventory to check against, **feasibility is established by
probing** — the same real query access that serves the run. This is
deployment-agnostic and degrades correctly: an org with a bad CMDB gets
feasibility from the systems it does have.

It also closes a hole the vocabulary has never had covered (§The vocabulary
defect). An enum check says a class tuple is *spellable*; a bind says whether it
has a **referent in this deployment**. A tuple that fails to bind means either the
vocabulary is wrong or the deployment has no such thing, and either way something
needs resolving.

## The judge

### Comparison, not rating

**The judge is given pairs, not rubrics.** Asking a model to rate an
investigation 1–10 is a weaker instrument than asking it which of two
investigations handled something better, and the contrast family supplies the
pair for free.

**The unit of judgment is therefore the sibling pair, not the run.** Nothing is
judged until both siblings have been investigated. That is a real scheduling
constraint on the loop, accepted deliberately.

Three comparisons, all same-unit and all pairwise:

| Comparison | Answers |
|---|---|
| A vs. B trajectory | did the defender move on the discriminator; did the questioner's predicted failure land |
| with-lesson vs. without | causal lesson lift (§Lesson attribution) |
| current defender vs. frozen archive | overfitting to the simulator (§What dies) |

Same-unit is the general principle, and it is why the retired frozen-actor
metric read as a vibe: it compared accuracy against catch rate.

### The fork

**Run one investigation, and fork it at the first query whose full response
differs between the two overlays.**

The legitimacy argument matters and is worth stating precisely: before that
point, both worlds return identical bytes, so the prefix is a valid investigation
*in both worlds* — not A's history replayed under B. That is what makes this
variance reduction rather than a cheat, and it is why the divergence check must
be over the full response, not the summary the main agent sees.

The payoff is not mainly cost. Independent A and B runs put LLM run-to-run
variance into `ΔT`, and for an agent this long that variance is large enough to
swamp a single mutation's effect. A shared prefix eliminates it exactly.
**Pinning the window kills environment noise; sharing the prefix kills agent
noise. What remains in `ΔT` is the mutation.**

Three consequences:

- **"No fork point" is itself a finding.** If the defender never issues a query
  the overlays differ on, there is nothing to fork and B never runs — and a
  lead-set gap has been detected for the cost of one investigation.
- **Fork position is a difficulty read.** Divergence at the last query means the
  question engaged too late; early divergence with no trajectory change is the
  informative failure the curriculum selects for.
- **The cost is resumability.** Agent state must be snapshottable at a turn
  boundary — message history plus the run dir. The two tables are append-only, so
  a fork is a copy. It also serializes A before B.

### The discriminator spine

Every scenario names its **discriminator**: the predicate whose value separates
the dispositions, the value it takes in each world, which system holds it, and
the permitted query envelope through which the defender can establish it. The
declaration is the questioner's falsifiable claim about its question, not an
answer the harness trusts.

**Scenario solvability must be proven, not asserted.** The questioner authors both
the world and the answer key, so it can produce a case no query path resolves —
and the judge will still grade the defender against it. Reality supplies
solvability for free in a real case; here it is a pre-run obligation. The pass
that proves it is the same pass that derives the resolving path, and it must
derive that path **from the world, never accept it from the questioner** — the
golden set's rule ("a label may be corrected from the environment, never from the
projection") reappearing one level up.

The judge's context is spined on **discriminating facts** — one row per fact that
must be established to resolve the case — not on the leads the defender ran.
Each row carries the predicate and its value in each sibling, the system and
query envelope that expose it, whether and when the trajectory touched it, and
what the defender concluded on receiving it.

With minimal-twin invariance gone, `ΔW` is no longer a literal diff and the
"unexpected `ΔO` outside `ΔW` is a leak" check is no longer code. What survives:

- **never querying the holding system** is a lead-set gap;
- **querying it at the wrong scope** is lead quality;
- **receiving the fact and reasoning past it** is analyze discipline;
- **establishing the fact without the warranted disposition change** is decision
  discipline.

Only the third requires reading prose (the `:T resolutions` belief trace).
A fourth bucket belongs beside them — see §Environment facts.

The questioner also declares **where it expects the defender to fail**. The
trajectory confirms or falsifies that prediction, and this half needs almost no
reasoning: the prediction was declared, the outcome is observed. Failure
elsewhere means the scenario was hard by accident; cheap resolution means it was
too easy.

**A `discard` verdict is required** (no current outcome enum has one). If the
oracle contradicted the spec or an earlier answer, the episode teaches nothing
about either player and blaming one is worse than dropping it.

**The judge's two outputs must not be one blob.** Defender findings feed the
lessons corpus; questioner findings feed question fitness. Different consumers,
different schemas.

**The failure mode moves, and the original draft under-weighted it.** Today's
judge is white-box over raw payloads on a real case, so its error is
"hallucinates a gap." A judge grading against an authored answer key errs by
**inheriting the questioner's mistake** — systematically, because one questioner
writes many scenarios. Solvability-derived-from-the-world and the `discard`
verdict are the defenses, and both are load-bearing rather than nice-to-have.

## Environment facts

Environment facts were a byproduct of the old loop. With the config files gone
they are the **grounding substrate** — the questioner's world knowledge, the
placeholder vocabulary, and the defender's standing world model. This section is
therefore on the critical path, not an appendix.

### Environment memory is an interpretation cache

The valuable content is not the data, it is the **reading**.
`svc-monitoring-network-probe-cadence-baseline` stores an observation (origin
`canary-1`, ~10 nc/hour, `first_seen` three days before the window, no covering
ticket) *and* an interpretation (at that rate one more occurrence stands out
rather than blending into an absent baseline). Live baselining regenerates the
first and not the second.

The second is where the defender has demonstrably failed. In
§Empirical grounding the defender had the `nc` events in hand and read them as a
multi-stage attack chain when they were the baseline generator doing its job. The
rows were available; the reading was wrong.

So the corpus is not compensating for data the defender cannot reach. It is
compensating for **a judgment it would plausibly get wrong re-deriving under
partial information**, which implies an authoring criterion the corpus does not
have today:

> Cache an interpretation only when a competent reader looking at the same rows
> would plausibly read them differently. If the reading is obvious from the data,
> let the defender derive it — otherwise you pay staleness risk for nothing.

### The clusters

Environment questions sort into four kinds by what the fact *does* to an
investigation, plus one that does not belong:

**Referent — "what is this thing?"** Identifier → entity and its class tuple.
`jump-box-1-ip-assignment`, `container-1df4bcd65ee4-role`.

**Norm — "what is normal here?"** Distributional; needs a baseline window and a
shape-matched control. `svc-monitoring-network-probe-cadence-baseline`.

**Semantics — "what does this answer license?"** About the instrument, not the
deployment. `cmdb-indexes-by-hostname-not-ip`,
`container-uid-namespace-isolation`.

**Sanctioned path — "how is this supposed to happen?"** Normative.
`authorized-keys-host-cr-baseline`.

**Encounter-class — "what does the standard investigation for this alert look
at?"** `sshd-success-preauthentication-shell-envelope` states that the lead set
for that rule targets auth telemetry and that in-session shell activity is
outside it. That is a fact about the **defender's playbook**, not the deployment.
It sits in this corpus because the corpus's reader is the actor and it is
gray-box blind-spot knowledge. If the corpus becomes questioner grounding plus
defender world model, this class must split off.

### Cache economics decide what belongs

The axis is **cost-to-derive × staleness half-life**, not churn alone:

| Cluster | Cost to derive | Half-life | Natural key | Needed at | Verdict |
|---|---|---|---|---|---|
| Referent | one lookup | weeks | the identifier | ORIENT | **never cache** — resolve live / bind |
| Norm | baseline + control window + a judgment | months | (entity, activity) | ORIENT, ANALYZE | cache; highest value |
| Semantics | requires a *surprise* | ~never | (system, query shape) | GATHER, ANALYZE | cache; highest value per entry |
| Sanctioned path | moderate | quarters | (activity, asset class) | ANALYZE | cache |
| Encounter-class | — | per playbook edit | **alert rule** | actor-only | does not belong here |

Four things fall out:

**Only the class that does not belong keys naturally on the alert rule.** That is
an independent confirmation that `alert_rule_ids` is the wrong anchor — it is
correct for exactly the one class to be removed.

**Referent facts should not be lessons.** They rot fastest *and* they are trivial
to re-derive, so caching buys nothing and costs correctness. This is why
`container-1df4bcd65ee4-role` and `jump-box-1-ip-assignment` are the most fragile
files in the corpus. Referents want a query — which is exactly what placeholder
binding provides.

**Norm facts are the expensive ones and are needed earliest.** They are what
"unusual" means, so they are load-bearing at ORIENT before the defender has done
any work.

**Reading a null safely requires two clusters at once.** Compare
`authorized-keys-host-cr-baseline` — *"a missing CR is positive evidence of
anomaly, not an absence of evidence"*, because 26 records exist and zero are for
this host (a **norm** fact) — with `cmdb-indexes-by-hostname-not-ip`, where a null
*"means 'lookup by IP is unsupported,' not 'host is absent'"* (a **semantics**
fact). Both are nulls; one is meaningful and one is an artifact of how the
question was asked. The defender cannot safely read any null without one fact
from each cluster, and misreading one is exactly what §Empirical grounding
records.

### Staleness, verification, and its limits

**Each cached fact should carry its derivation query and the value observed at
record time.** Then staleness stops being unanswerable and becomes one call:
re-run, compare. If the observation holds the interpretation stands; if it moved,
the reading needs revisiting. `authorized-keys-host-cr-baseline` is already
almost this — "zero approved change records for this host across 26 total
records" is precisely checkable — it just does not say how to check it.

**The query is derivation metadata, not the key** (§The data model).

**The policy is per-case, not global.** Retrieval hands the defender the cached
interpretation *and* its derivation query; whether to spend a call is decided by
how much weight the fact is about to carry. invlang already has the vocabulary:
`WEIGHT_BUCKETS` with `STRONG_WEIGHTS = {++, --}`. A fact about to support a
strong move gets re-verified; one riding at `+`/`-` takes the cache.

**Invalidation is nearly free.** Any run that queries the same ground for its own
reasons is an incidental re-verification — a run that observes 40/hour against a
cached ~10/hour has contradicted the cache, and the system can notice without a
dedicated freshness pass. This is "training does the mining" read in the other
direction: the query stream that populates the cache is the stream that
invalidates it.

Two limits to hold onto:

- **Verification catches staleness, not birth defects.** An interpretation that
  was wrong when written survives re-verification looking healthy, because the
  observation still holds. That is the promotion bar's job, not the cache's.
- **The failure is asymmetric and points the wrong way.** A stale *referent*
  fails loudly — the lookup errors or resolves to nothing. A stale *norm* fails
  **silently and toward benign**: "this identity normally pulls 40k" applied after
  that job was decommissioned excuses exactly the pull that needed catching. That
  asymmetry argues for making verify-when-load-bearing mandatory for the norm
  class rather than leaving it to judgment.

### The data model

**The key is the subject, not the query.** A query carries a time window the fact
is not about, param bindings that restate the subject, adapter dialect coupling,
and no canonical form (many queries establish one fact, so it never dedupes) —
and decisively, **procedures do not compose**. You cannot traverse from one query
to another. Subjects reference each other; that is what makes the graph possible.

**Environment facts are graph-shaped, and the edge vocabulary already exists.**
`skills/invlang/vocab.py` defines 26 relations, and the source layout already
groups the standing ones:

```
"spawned", "executed", "loaded_by", "opened", "connected_to",
"read", "wrote", "created", "deleted", "modified", "listed",
"runs_on", "contained_in",                          <- standing
"authenticated_as", "authenticated_via", "initiated_by",
"triggered_by", "escalated_privilege", "assumed_role",
"granted_consent", "issued",
"member_of", "identified_as", "component_of",       <- standing
"attempted_auth", "governs",                        <- governs: standing
```

The split is not formalized — no constant, no doc — but it is there. **Event
relations are what an investigation records; standing relations are what the
environment corpus holds.** Same vocabulary, different tense: the per-case invlang
companion is the event subgraph, the environment corpus is the standing subgraph
over the same nodes.

Two immediate payoffs:

- **`identified_as` is the alias edge** — the CMDB-vs-Falco-vs-Docker problem, and
  what `jump-box-1-ip-assignment` and `container-1df4bcd65ee4-role` encode as flat
  prose today. It also refines "do not cache referents": the **node** is stable
  and worth persisting, the **alias edges** are the volatile part and should be
  resolved live. Those two files cached the edge, not the node.
- **`governs` is the sanctioned-path edge.**

**Values may be other keys, and may be multi-valued.** Norm facts are
set-valued (an identity runs on six roles) and the natural match is containment,
so single-valued forces either explosion into N facts or stringification that
loses matching.

**MV forces one field.** An observed set read as a complete set is the null-reading
trap at the schema level: "runs on these six roles" derived from observation
almost never means "and nowhere else." Every MV value needs an explicit
`observed | exhaustive` marker, or it silently asserts closure it never
established.

A skeleton, with the claim shape varying by cluster:

```yaml
subject:  compute/dev-ws-4                 # a node — the key
relation: read                             # when the fact is about an edge
object:   database/db-1                    # a value that IS another key
claim:
  kind: norm                               # referent | norm | semantics | sanctioned
  measure: {rows_per_run: 40000, cadence: nightly}
  scope: observed                          # observed | exhaustive
derivation:
  query: {...}                             # metadata, not identity
  observed_value: 41320
  observed_at: 2026-07-14
interpretation: >
  40k from this identity against this store is routine volume; the
  discriminating signal is the initiating host, not the count.
```

**Greppability is preserved, not traded away.** Keep flat markdown files, put
references in frontmatter as **typed tokens** (`compute/dev-ws-4`), and derive the
graph by resolving them. Grep still finds every mention of a node by its token;
the graph is a view, not a database. This is the same posture as lessons already
having grep and no index.

Three decisions that need making rather than defaulting:

1. **Node-keyed or edge-keyed** — probably both, by cluster: referent facts key on
   a node, norm and sanctioned-path facts on an edge.
2. **The `observed | exhaustive` marker** above.
3. **Semantics facts do not fit the entity graph, and they are the highest-value
   class.** Their subject is `(system, verb, param-shape)` — an *instrument*, not a
   deployment entity. The graph needs a second node family that is not invlang's.
   This is the real modeling strain and is better named than papered over with a
   synthetic vertex type.

### The current schema, and what changes

`lessons-environment/_TEMPLATE.md` today:

```yaml
subject:            # OPTIONAL — kebab referent; the fold/equivalence key
alert_rule_ids: []  # REQUIRED, non-empty — THE ANCHOR
entities:           # CONJUNCTIVE invlang {type, class} selectors
relevance_criteria: # one-line predicate the actor scans
mutable: true
status: live        # live | stale (+ superseded_by)
recorded_at:        # batch id
source_observation_ids: []
```

**What is already right:** the body convention (state the standing truth, not "do
X"), which is the mechanics-not-likelihood rule the whole corpus needs;
`mutable`/`status`/`superseded_by` as a real staleness mechanism (the gap is that
nothing *drives* the flip); and `source_observation_ids` as a provenance slot an
oracle-authored fact can populate with query/response references.

**`alert_rule_ids` is removed.** It is required and non-empty today, and a lesson
with a disjoint anchor is skipped — so the questioner, which writes before an
alert exists, has no value for the mandatory key. `cmdb-indexes-by-hostname-not-ip`
shows the damage: a universal truth about how the CMDB is indexed, keyed to two
rule ids, unretrievable for any other alert. Entity/topic selectors become the
primary key, which raises the stakes on the vocabulary defect below.

**Retrieval must gain a broadening mode.** `entities` is conjunctive AND, so it
only ever narrows; there is no "everything known about this deployment region"
query, which is exactly what grounding needs.

**The curator's retrieval check needs a second form.** It re-runs retrieval with
the source case's real prologue entities, which is genuine protection against a
selector unsatisfiable by its own birth case — but a questioner-facing fact has no
source-case prologue, so "is it retrievable" must be asked against a topic query
instead.

### The vocabulary defect that blocks this

Making entity selectors the primary key requires the type/class vocabulary to be
trustworthy. It currently is not.

**`type` is well controlled.** 16 values in `skills/invlang/vocab.py::TYPES`,
served as `defender-invlang enum types`, and **validated** —
`validate.py::_check_vocab_vertices` rejects an unknown vertex type.

**`class` slot values are not validated at all.** The grammar is documented
(`compute` = `<role>/<zone>/<provenance>`, `identity` = `<kind>/<provenance>`,
etc.) and the slot enums exist in `vocab.py` (`COMPUTE_ROLE`, `COMPUTE_ZONE`,
`COMPUTE_KIND`, …), served via `enum compute.zone`. Nothing consumes them for
checking: `validate.py` checks `type`, `relation`, `auth_kind` and `anchor_kind`,
and treats `class` purely structurally (`??` open slots, refinement-key form).

**It has already drifted.** Sampling real investigations, the distinct `compute`
tuples are `web-server/prod/known-corp`, `workstation/preprod/known-corp`,
`monitoring/internal/known-corp`, `ip-only/internet/novel`. `enum compute.zone`
is `internal | dmz | partner | regulated | internet | cloud-managed | unknown` —
so `prod` and `preprod` are off-enum.

**Two docs teach the wrong grammar.** `lessons-environment/_TEMPLATE.md` says
`compute = <role>/<zone>/<kind>`, and `lessons_env_retrieve.py`'s help gives
`web-server/internal/container` as its worked example. Slot 3 is `provenance`;
`container` is a `compute.kind` value. Both documents that teach curators how to
write selectors are wrong about the same slot.

**Why it happened: the agent never enumerates.** A complete investigation trace
(`fixtures-e2e/golden-sshpivot-ab3/tool_trace.jsonl`) shows every tool call —
read `alert.json`, read `skills/invlang/SKILL.md`, `cat` two lessons,
`defender-invlang hypothesis-vocabulary`, `defender-invlang hypothesis-shape`,
four `write_file`, four `gather`, `close_investigation`. **Zero `enum` calls.**
The skill says *"They are not preloaded into this skill — look them up when you
need a value"*, and the agent never concludes that it needs to. It did call
`hypothesis-vocabulary` and `hypothesis-shape` — purpose-built commands answering
a question it was actively holding. `enum compute.zone` requires first suspecting
that one's natural word might be wrong, which a confident agent filling a slot
will not do.

`type` survived anyway because it has two protections the class slots lack: it
appears in SKILL.md's grammar table and every worked example, *and* the validator
rejects unknown values.

**The drift is slot-specific and diagnostic.** `role` and `provenance` values are
all in-enum; `zone` values are not. `compute.zone` encodes *network topology*,
but the word "zone" reads to any practitioner as *deployment tier*. Two concepts
competing for one slot name.

That yields a general test worth adopting: **the vocabulary's sole consumer is
the agent, so naturalness is measurable.** Sample what the agent writes when it
does not enumerate and diff against the enum. Agreement means the name and the
concept agree; divergence means the slot name invites a different concept.

**The failure is silent in both directions.** `_selector_satisfied` is pure string
comparison, and the retrieval help tells its reader *"No output = nothing
matched: reason from the alert and general operations knowledge."* A vocabulary
mismatch is indistinguishable from "nothing relevant exists."

**The fixes, in order of value:**

1. **Inline the catalogs into SKILL.md.** All 21 catalogs, 211 values, are
   **2,436 characters** against SKILL.md's **24,400** — 10% of one file. The
   "don't preload, look them up" trade saves that and buys a corpus whose class
   slots are both unread and unvalidated. Put the values where the agent
   demonstrably already looks.
2. **Validate class slots, dispatched on type**, in the validator that already
   checks `type`, and run lesson selectors through the same check at author time.
   Greppability helps the agent *choose*; validation is what makes a wrong choice
   *visible*.
3. **Fix `zone`** — rename the slot to what the enum means, or widen the enum to
   what the name means.
4. **Then add corpus-derived counts** (`internal (47) prod (12) dmz (3)`) as the
   discovery surface, with the enum as the floor and a novel value as a flagged
   review item rather than a hard error. That keeps the vocabulary responsive to
   what is natural without letting drift compound silently.

Placeholder binding (§Placeholders and binding) is the third and strongest check,
because it tests for a referent rather than for spelling.

### Producers

**Today both feeds are judge-emitted from actor directions**, and the curator
lives inside the benign-actor author package:

| Feed | Emitted by | Queue | Curator |
|---|---|---|---|
| FP direction | benign judge `environment_observations` | `_pending/environment_observations.jsonl` | `author_actor_benign.py` |
| Adversarial (#298) | malicious judge — positive facts from a refuted misprediction | `_pending/actor_environment_observations.jsonl` | `author_actor_env.py` |

Both fold into one corpus through `learning/author/benign_actor/prompt.md` ("You
are the **environment lessons curator**"), gated by a deterministic retrieval
check and committing their own batch. **Deferring the actor work therefore
orphans the corpus** — which is why it cannot simply be deferred alongside it.

**The replacement is one mechanism with two feeds.** Both the oracle and the
runtime are the same thing: a component holding a corpus of (query, response)
pairs against the real deployment. In training that is the oracle; at runtime it
is the persisted `executed_queries.jsonl` plus `gather_raw/` payloads, which
already exist per run. One offline miner over that corpus, two inputs.

This reopens what the original draft closed off. It ruled that a training
reviewer only sees synthetic worlds, so an environment fact authored there
describes an invented deployment. With interception, every gather query returns
real data outside the overlay — so a fact is sound as long as its supporting rows
were not patched, and **the applier knows exactly which rows it touched**. Row-level
provenance makes that a mechanical check.

**A fourth judge bucket is an environment fact.** When `ΔT` diverges, is not
explained by the mutation, and is not a reasoning error, the deployment misled the
defender. Add **environment defect** alongside lead-set gap / lead quality /
analyze discipline / decision discipline. §Empirical grounding's CMDB case is
exactly this and needed no adversary to find — a comparison found it.

**Two things this cannot produce**, both of which must come from the runtime feed:
observability facts (see §Alert realism below), and semantics facts that only
surface mid-investigation rather than at bind time.

## Authoring flow

| Corpus | Status | Producer |
|---|---|---|
| `defender/lessons/` | unchanged | the existing lessons curator, reading judge gaps |
| `lessons-actor/` | **deferred** | — |
| questioner lessons | **new, needed now** | judge comparison outcomes |
| `lessons-environment/` | **repointed** | the (query, response) miner, two feeds |

**Actor lessons defer at no cost now.** The shipped review gate runs blind lenses
that reconstruct rather than counter-argue, so it writes no counter-story and the
actor corpus has lost its runtime reader. The original draft's "one corpus, one
role" merge — questioner and runtime reviewer as the same role sharing one
corpus — is obsolete before it shipped, and with it the claim that runtime review
recruits the curriculum for free. Nothing under `learning/` reads
`review_record.{turn}.json` today.

**Questioner lessons hold strategy only.** Three jobs were proposed for them —
fix mistakes, call out bad assumptions, steer toward tougher areas. The first is
mostly mechanical (solvability, feasibility and tell detection are gates, not
lessons). The third is strategy and belongs here: which axes discriminate in this
deployment, which mutations the defender has already mastered, where the frontier
sits.

The second needs routing care. *"The questioner assumed a service account is idle
overnight"* is not a fact about the questioner — it is a fact about the
deployment. **Validity failures route to whichever corpus owns the truth**;
deployment assumptions go to the environment corpus, which the questioner reads.
Otherwise two corpora encode the same deployment truths and drift apart.

**Actor lessons, if revived, are production-facing and need the defender bar.**
A wrong tradecraft lesson would skew both the curriculum and any live challenge in
the same direction with nothing left to cross-check it.

## Lesson attribution and effectiveness

Issue [#695](https://github.com/beetroot-salad/cyber-response-agent/issues/695)
provides the cheap observational signal. Its `loaded` / `applied` / `decisive`
split is the correct contract: record `applied` at the lead or plan change before
the outcome is known, then join it to a calibrated win/loss/no-update result.
This can nominate promising lessons and order them within the already-relevant
retrieval set.

Application is evidence of involvement, not proof of effectiveness. A defender
can confidently credit a lesson that merely restates its existing belief;
preventative lessons may never feel decisive; and several applied lessons make
credit ambiguous. Successful-run self-attribution alone would therefore produce
a salience and confirmation loop.

Effectiveness needs a paired intervention. For a nominated lesson, run the same
contrast family with and without the lesson available, then evaluate withheld
siblings. The useful quantity is **causal learning lift**:

> improvement attributable to the lesson in disposition accuracy, discriminator
> reach, and investigation cost, without regressions on the opposite-disposition
> siblings.

This yields two separate fitness signals:

- **question fitness, before learning:** did a valid and affordable scenario
  expose the intended defender gap?; and
- **lesson fitness, after learning:** did the lesson close that gap and transfer
  across mechanics without creating benign false positives?

The pipeline is therefore: #695 attribution nominates; paired ablation estimates
causal lift; probe siblings test generalization; held-out performance controls
promotion and retrieval rank. Scenario evolution may use attribution as a prior,
but only replicated causal lift is an effectiveness result.

Because model runs are stochastic, no scenario or lesson is promoted from one
tournament. The shared prefix (§The fork) reduces the variance that makes this
expensive, but it does not remove the need for repetition.

## Retrieval — frontier keying

Two consequences, both load-bearing and both independent of the training loop.

**Retrieval must run per gather loop, not once at PLAN.** A lesson about what a
field does and does not license is only relevant once the field is in hand. In
§Empirical grounding the process class was still `??` when lessons loaded, so no
keying scheme could have surfaced the applicable lesson at that moment.

**Match by containment, not by similarity score.** The frontier has structure —
typed slots with `??`, plus the open hypothesis set — so a lesson declares the
pattern it applies to and matching is mechanical, fewer slots matching more. This
is assembly, not construction: the invlang advisory verb already does
frontier-keyed recall, and the environment corpus already matches by slot-wise
selector containment.

Three gaps close it. The advisory recalls precedent *cases*; lessons need
selectors and become a recall class. Its frontier is hypothesis names only —
`??` slots are out of scope today, and the motivating case's frontier item is
exactly slot-shaped. And the frontier is model-supplied at the prompt;
per-gather-loop retrieval derives it mechanically from the investigation file.
One guard: selectors need a specificity floor — fewer-slots-matching-more makes
an empty selector an every-loop lesson.

**The schema defect this fixes** is the same one §Environment facts removes
`alert_rule_ids` for: lessons key on the alert signature they were born from,
which is right for coverage lessons and wrong for observable-semantics lessons,
whose trigger condition has nothing to do with which rule fired.

## What dies, what transfers

**The frozen-actor secondary metric is already retired** (`evals/secondary.py`,
removed after #791 left it structurally unable to produce a number). Its
replacement is better-typed: real-held-out disposition accuracy against
synthetic-scenario disposition accuracy — same unit on both sides, so the gap is
directly the overfitting-to-simulator number, provided the synthetic side is
measured on a **frozen scenario archive**, never the live curriculum. Selection
deliberately holds the defender near informative failure, so live-curriculum
accuracy is depressed by design. The archive is also the only remaining home for
a fixed regression suite of historical attack shapes.

**The oracle golden set re-aims rather than pausing.** Its 37 cases (17 with real
observed payloads under `hidden/`, plus shape-matched control windows) measure
"does the world I served match a real capture of this activity." Under
interception the base world *is* real, so what needs measuring narrows to the
overlay: does a patched response remain consistent with the rows around it. The
control-window discipline transfers directly. Whether the suite is revived,
archived or retired is still an open call.

**The forward-check retires late, and is not replaced by a birth gate.** It
guards a rare failure — a lesson flipping its own source case. The live risk is
the one it never tested: over-generalization downgrading the opposite-disposition
sibling. No cheap birth gate covers that, so behavioral quality is the learning
process's job, not a gate's. Birth-time validation shrinks to two free checks: a
curator fold must preserve the gap the lesson was born from, and a selector must
be satisfiable by its source case's prologue. The retirement point is lesson
attribution landing (§Sequencing).

**Real cases remain a lesson source.** The original draft ruled they would stop
being one except through review, because a training reviewer sees only synthetic
worlds. Interception overturns that: training runs query the real deployment, and
row-level provenance separates observed rows from patched ones.

**Alert realism is bounded by rule coverage**, which is correct — triage only ever
sees what fired — but it means the training loop structurally cannot produce
observability findings. Every scenario begins from something the detection stack
caught. It can teach "you saw this and reasoned wrong"; it can never teach
"nothing would have told you."

**Unchanged and reused:** the runtime defender and its phase discipline, the
permission gate, the seven adapters and the typed query seam (one interception
point; verbs return plain JSON values — the two ticket verbs that return bare
strings do so as the answer-key defense, and the oracle must preserve that), the
two tables and their join surface, the curators, the drain/worktree/PR machinery,
and the lessons corpora themselves.

## Empirical grounding

Two findings from `20260728T161845Z-fresh-case`, a Falco `authorized_keys` write
correctly disposed `malicious`.

**The old loop yields nothing on it.** A malicious disposition routes to the FP
hunt, and no benign story survives an SSH key whose comment is literally
`attacker@elsewhere`. Skip or incoherent. A whole disposition class is silent.

**A directly applicable lesson existed and did not retrieve.** The corpus holds a
lesson stating that `loginuid=-1` licenses "non-interactive automated context" and
nothing more, that container init and cron produce an identical profile, and that
origin claims require ancestry Falco cannot supply. Two lessons loaded for this
run; that was not one of them — it is keyed to the signature it was born from, a
different rule. The investigation then inferred "no authenticated session
initiated this process — classic remote execution pattern," and separately
recorded that no parent process was captured, and reasoned past it.

That defect lands in an awkward place:

- **Training grades it as a clean win.** The disposition was right, and rests on
  one thing: the key comment literally reads `attacker@elsewhere`. Each other
  support is an artifact of the environment. `loginuid=-1` is how the scenario
  runner executes *anything*, benign included. "Host absent from CMDB" holds for
  every container case, because Falco reports the Docker host while the logical
  host is registered — the defender queried the wrong entity and read the null as
  incriminating. And the co-occurring `nc` events it reported as a multi-stage
  attack chain belong to the baseline scheduler, which generates them
  `category: noise` to fire that exact rule against that exact host. **The shipped
  report asserts an attack chain that did not happen.** Outcome grading sees none
  of this, because the disposition matched.
- **Review cannot prove it either.** It can only say the inference is unsound. The
  proof is generating that twin and watching the defender escalate.

So: **review nominates on real data, the generator falsifies.** This case is also
the source of three separate conclusions elsewhere in this document — the
null-reading trap needing two fact clusters, the environment-defect judge bucket,
and the interpretation-cache argument.

**Two cheap fixes remain available, independent of everything above**, and
neither has landed:

- Make the judge's likelihood-ratio check **symmetric**. It still runs only on
  benign dispositions (`learning/pipeline/judge/malicious.md:146` — *"When
  `report.md` records a **benign** disposition"*); on a malicious call it should
  ask whether the incriminating observables fit routine automation equally well.
- **Re-key observable-semantics lessons** off the alert signature (minding that
  the two corpora disagree on rule-id namespace) — the stopgap for §Retrieval.

## Sequencing

1. **Held-out recruitment** — separate session, blocking every metric here.
   `fixtures/held-out/` is still a README.
2. **The two cheap fixes above** — prompt edits, no architecture.
3. **The vocabulary fixes** (§The vocabulary defect) — inline the catalogs,
   validate class slots, resolve `zone`. Small, and everything keyed on entity
   selectors depends on them.
4. **Frontier retrieval + environment schema.** Give the invlang advisory a
   lessons recall class, extend its frontier from open hypotheses to `??` slots,
   derive the frontier mechanically per gather loop; drop `alert_rule_ids`, add
   the broadening query mode, add `derivation` and the `observed | exhaustive`
   marker.
5. **The environment miner.** One pass over the (query, response) corpus, runtime
   feed first. On the critical path: it is the grounding substrate, and the
   current producer is being deferred.
6. **The interception seam.** `VerbRegistry` subclass, overlay ledger, bindings
   memoization, realization log — failing closed on *un-applied* rather than on
   *leaked*. Then placeholder binding on top of it.
7. **Solvability and resolving-path derivation**, from the world.
8. **The judge's discriminator spine, the fork, and the pair as the unit of
   judgment.** Requires agent-state resumability.
9. **Questioner strategy corpus + seed pipeline** — including filling the ticket
   corpus with adjudicated cases and making the intel feed technique-shaped.
10. **Lesson attribution in shadow mode.** #695's stable identity and
    loaded/applied/decisive sidecar without changing retrieval order. Also the
    forward-check's retirement point.
11. **Paired ablation and probe siblings.** Establish causal lift before any
    attribution score affects promotion.
12. **Curriculum search.** Mutation policy, tournaments and score-informed
    retrieval only after the validity gates and held-out archive are trustworthy.

## Open questions

Resolved since the first draft, recorded so they are not reopened: the scenario
spec format for systems-of-record state (dissolved by interception); whether the
oracle needs a materialized base world (no); whether siblings must be minimal
twins (no); whether the questioner and runtime reviewer share a corpus (moot —
the shipped gate writes no counter-story).

Still open:

- **Node-keyed vs. edge-keyed environment facts**, and the second node family
  that semantics facts need (§The data model). The largest remaining modeling
  question.
- **Removal predicates.** Expressing "this baseline activity did not happen" over
  real rows, without leaving contradicting rows behind.
- **Agent-state resumability** — what exactly must be snapshotted at a fork
  boundary, and whether the run dir copy is sufficient.
- **Mutation catalog and family policy.** Which framework-backed dimensions may
  vary independently, and which must remain coupled to preserve realism.
- **Cross-family cost calibration.** Whether structural resolving-path cost is
  stable enough to compare unrelated families now that siblings are not minimal.
- **Ablation execution.** Whether trusted counterfactual replay suffices for
  lesson lift, or paired fresh runs are required for promotion-grade evidence.
- **Replication budget and promotion threshold**, given that the shared prefix
  lowers but does not remove run-to-run variance.
- **Where the sufficiency verdict lives.** The shipped review gate produces a
  per-case judgment that needs no labels and runs on every real investigation.
  That is the only quality signal moving between held-out evaluations, and
  nothing under `learning/` reads it.
- **Retirement path for the current corpora.** 16 defender lessons, 15
  environment facts and 12 actor lessons were authored under the old warrant and
  the old schema. Re-derived, grandfathered, or re-keyed only?
- **Whether the questioner counts as an actor for corpus segregation.**
  `lessons_env_retrieve.py`'s containment guard deliberately stops the malicious
  actor reaching `defender/lessons`. If environment facts become both questioner
  grounding and defender world model, that boundary needs a ruling.
