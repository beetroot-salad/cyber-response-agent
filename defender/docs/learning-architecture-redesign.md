# Training loop architecture (2026-07-30, revised 2026-08-12)

## Status

**Design, pre-implementation for the training loop. Two of the three original
components have since moved.** Amends the loop shape in `learning-loop.md` and
absorbs the deferred pointers in `learning-loop-actor-learning.md` (learning
actor) and `learning-loop.md` §Future Enhancements (live self-evaluation). When
this ships, those sections get rewritten rather than cross-referenced.

**Held-out recruitment blocks less than an earlier draft claimed.** It gates the
overfitting gap (§What dies) and promotion gating (§Lesson attribution), and
nothing else. The pairwise metrics inside the loop — realized fork depth, "no fork
point is a finding," fork position as a difficulty read, A-vs-B trajectory
comparison, question fitness, and the with/without-lesson ablation — are computed
on synthetic sibling pairs and need no held-out fixture. Recruitment is still
sequenced first because promotion is worthless without it, but it does not block
building the loop. `defender/fixtures/held-out/` still contains only a README.

### What the 2026-08-11/12 revision changed

The original draft had one architecture with three components. Two shipped or
were overtaken while the third was still on paper, and a working session then
reworked the third. Concretely:

- **§3 Runtime adversarial review shipped, twice.** #774 landed the write-time
  challenge gate; #796/#797 then replaced its three stages with two blind lenses
  plus a composer (`REVIEW_ROLES = ("support", "ablation", "composer")` in
  `runtime/challenge_gate.py`). The gate **writes no counter-story**, which
  retires the original draft's "one corpus, one role" merge as it was written.
- **#792 retired the offline oracle** from the learning loop entirely.
- **The oracle design inverted.** It no longer serves queries from a
  materialized world; the real deployment is the base and the scenario is a diff
  against it (§The oracle). This retires lazy generation, the base-world ledger,
  and the "scenario spec format" open question that this doc called its largest
  unknown.
- **The oracle mechanism splits by system class.** Only Elastic aggregates (12 of
  its 14 templates; 0 of the other 14 across the six state systems), and response
  patching cannot survive an aggregate. Elastic gets its **query target**
  rewritten to a scenario index — a config swap, with `confine_index` supplying
  fail-closed for free — while the six state systems get their **responses**
  patched.
- **Pinned windows shrank to an authoring constraint.** Time anchors must be
  absolute rather than relative to run time; there is no pinning machinery to
  build.
- **Bindings are minted at materialization**, not lazily at first query, with a
  deterministic function for the tail.
- **Minimal-twin invariance is dropped.** Scenarios are seed → refined
  mutations with no enforced mechanical delta (§Seeds and mutations). `ΔW` is no
  longer a literal diff.
- **The judge's unit of comparison is the sibling pair**, and siblings share an
  investigation prefix up to the fork point (§The judge).
- **No `playground-v2/` file is an input.** Not the attack catalog, not
  `hosts/inventory.yaml`. A non-stale asset inventory is not a thing an
  arbitrary deployment has (§Seeds and mutations).
- **Environment facts became load-bearing** — they are the grounding substrate
  that replaces the config files, which put environment mining on the critical
  path.
- **The corpus design split out.** It had grown longer than the training-loop
  subject it was serving, and it has a different reader and a different timeline:
  the training loop is unbuilt, while the corpus exists today and its vocabulary
  is already drifting. It is now `environment-corpus-and-vocabulary.md`, which
  also took frontier-keyed retrieval. §Environment facts here keeps the three
  points the training loop depends on.

## The diagnosis

The old loop was two mechanisms wearing one coat: **counterfactual review of a
real case**, and **training against a simulated world**. #792 unfused them by
deleting the offline oracle, and #774/#796 shipped review as a live write-time
gate. What is left is nothing training against a simulated world.

This document designs that half. The concrete case for why it is needed is
§Empirical grounding, which is worth reading before the design.

Note what changes about the oracle in the process. In the old loop it was **a
blinding device, not a world model** — it existed to convert a blind actor's story
into a falsifiable prediction. The component this document designs is a world
model, holds state, and is authored per scenario. Where an older doc describes the
oracle as a projection over a story, that describes the retired stage.

## Notation

Three deltas carry most of the argument below:

- **`ΔW` — world delta.** The difference between two sibling worlds: the seed
  scenario's overlay versus the mutated one's. No longer a literal diff (§Seeds
  and mutations).
- **`ΔO` — observation delta.** The difference the oracle actually exposed to the
  defender: the same query served under two fork ids, compared.
- **`ΔT` — trajectory delta.** The difference in the defender's investigation and
  verdict across the two siblings, read off the leads and queries tables.

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

So: **review nominates on real data, the generator falsifies.** This case earns
its place at the front: it is the source of the environment-defect judge bucket
(§The discriminator spine) and, in the corpus doc, of both the null-reading trap
and the interpretation-cache argument.

**Two cheap fixes remain available, independent of everything above**, and
neither has landed:

- Make the judge's likelihood-ratio check **symmetric**. It still runs only on
  benign dispositions (`learning/pipeline/judge/malicious.md:146` — *"When
  `report.md` records a **benign** disposition"*); on a malicious call it should
  ask whether the incriminating observables fit routine automation equally well.
- **Re-key observable-semantics lessons** off the alert signature (minding that
  the two corpora disagree on rule-id namespace) — the stopgap for
  the corpus doc §Retrieval.

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

**Frontier-keyed lesson retrieval** is unchanged and independent of the training
loop; it moved to the corpus doc §Retrieval with the rest
of the corpus design.

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

The response to the third needs care, because the obvious move is a trap.
**Realized fork depth is a diagnostic, and it is reported rather than selected
on.** It is tempting to make it a questioner fitness term — a mutation that stays
coherent yet shares a long prefix does produce a sharper signal. But fork depth is
monotone in delta size, so selecting on it is selection for small deltas: the
constraint this section just dropped, re-entering through the back door and
without the auditability that made minimal twins worth having. If it is ever
promoted to a fitness term, that promotion owes an argument for why soft pressure
toward small deltas is safe where a hard constraint was not.

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
  infeasibility verdict — no LLM judging plausibility. This is the "prove it,
  don't assert it" discipline of §The discriminator spine, moved one step earlier,
  and it is the first stage of the single validation pass described in §The oracle
  checks feasibility.
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
(the corpus doc §Producers).

**Placeholders and environment-fact keys are one vocabulary.** An unbound
reference is a placeholder; a bound one is an env-fact key
(`{{compute:web-server/internal}}` vs. `compute/web-1`). Binding is resolution.
See the corpus doc §The data model.

**Bind-time queries are the oracle's, not the defender's — and they need their own
table.** They must not land in `executed_queries.jsonl`, or they pollute `ΔT` and
the judge's read of what the defender actually did. But they are also exactly the
mining corpus (the corpus doc §Producers), so they cannot
simply be discarded either. They go to
a third append-only artifact alongside the run dir's two tables — call it
`oracle_queries.jsonl` — written by the oracle, read by the environment miner, and
**never** read by the judge. Naming it is not a detail: two mechanisms in this
document depend on it, and an earlier draft forbade the queries from the only log
it named while requiring them elsewhere.

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
applied by code.** If an LLM decides the modification per response, siblings
contradict across queries — the defender asks for processes on a host, then
network connections on the same host, and two independent decisions produce
events that do not corroborate. That is the failure the original draft called
load-bearing, and it is the defender's whole method. LLM cost belongs at scenario
authoring, never in the serving path.

**Consistency is the load-bearing risk, not fidelity.** The defender corroborates
one system against another and pivots on values it got from an earlier answer. A
world that contradicts itself across a run teaches it that corroboration is noise.

### The mechanism splits by system class

"Apply the overlay to the response" is the right description for six of the seven
systems and the wrong one for Elastic, because only Elastic aggregates. Counting
the shipped templates under `skills/gather/queries/`:

| System | Templates | Aggregating |
|---|---|---|
| elastic | 14 | **12** |
| change-mgmt | 3 | 0 |
| cmdb | 3 | 0 |
| host-state | 4 | 0 |
| identity | 4 | 0 |

**Response patching cannot survive an aggregate.** If a query returns
`STATS count() BY host` and the overlay injects three events, the applier has to
recompute the aggregate — which means reimplementing the result semantics of the
verb, for injection and removal both. Splitting the query at the filter/aggregate
boundary (execute the filter for real, merge overlay rows, then aggregate) works
in principle, but its limit is **data volume**, not evaluator complexity: the
aggregate exists precisely so the rows do not come back, and splitting means
pulling every pre-aggregation row to the oracle. `SORT`/`LIMIT` make it worse,
since injection must precede truncation.

So the mechanism differs by class:

| | Mechanism | Seam |
|---|---|---|
| **Elastic** | rewrite the query's **target** to a scenario index | `ELASTIC_EVENTS_INDEX` config; `confine_index` follows it |
| **The six state systems** | patch the **response** by entity predicate | the verb registry |

**For Elastic this stops being interception at all.** `elastic_adapter.py` already
resolves the target through a single indirection —
`resolved = index or config["ELASTIC_EVENTS_INDEX"]`, then
`confine_index(resolved, (config["ELASTIC_EVENTS_INDEX"],
config["ELASTIC_ALERTS_INDEX"]))`
— so pointing the defender at a scenario index is a **config swap**, not a hook.
Aggregation, `SORT` and `LIMIT` then run natively in the engine and are correct by
construction: no splitting, no local evaluator, no volume problem.

**And confinement supplies fail-closed for free.** Because the guard validates
against the same config value that was swapped, a defender query reaching the real
index is not a silent scenario deletion — it is a `ConfinementFault`. The hazard
this document previously had to pin with a test becomes structurally impossible on
the one system where volume made it most likely.

**Do not write overlay events into the raw index.** Bulk indexing would accept
them, and it is wrong four ways: synthetic attack events contaminate real
telemetry that detection rules and future baselines both read; removal remains
impossible, since a query against the raw index cannot be made to miss real
documents; cleanup by delete-by-query is expensive and eventually consistent, so
leftovers pollute the next run; and two scenarios in flight would see each other.
Data streams are append-only besides.

**Building the scenario index.** `POST _reindex` copies a window's results into a
new index and admits a script that transforms or drops documents on the way, so
addition and removal both work and nothing depends on filter semantics. Cost is
proportional to window size, which is the number to measure before committing —
it decides whether scratch indices can be per-fork (simpler, and it makes fork
divergence two indices that are identical until the mutation) or must be shared
per scenario.

Two cheaper Elastic mechanisms are worth knowing and both have caveats. An
**alias over multiple indices** gives union-with-native-aggregation and no copying
at all, but offers no removal — and note that `confine_index` refuses a comma-list
target outright (*"names a multi-index list — refused whole"*), so the union has
to be an alias, which is a single name and passes. A **filtered alias** could
express removal as `must_not: {ids: …}`, but **whether ES|QL honors alias filters
the way `_search` does is unverified** and should be settled by experiment before
anything is designed on it. Reindex is the safe default.

**What has to be true for this to port.** Not "Elastic has aliases" — the general
requirement is that **the query's data source is a rewritable indirection rather
than a hardcoded physical table**, which the adapter already satisfies. Every
serious analytical store has the equivalent: Splunk searches several indexes and
materializes through summary indexing; KQL `union`s tables and excludes with
`where`; BigQuery, Snowflake and Databricks express the whole idea as a view
(`SELECT * FROM real UNION ALL SELECT * FROM overlay WHERE id NOT IN (…)`), which
is the cleanest form of it. One honest asymmetry: **union ports everywhere,
removal is where portability thins** — and removal is already the harder half.

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

**Scenario time anchors are absolute, not relative to run time.** This is a
constraint on authoring, not a mechanism to build. The deployment keeps running —
`playground-v2` alone has 21 Poisson-scheduled baseline actions — but events are
appended at the *present*, never backfilled into the past, and the query surface
already takes a bound `${start}` (12 of 12 time-bounded templates; none uses a
`now-Nd` form). A query over a closed historical window therefore returns the same
rows whenever it runs, and sibling drift disappears without any pinning
machinery. An earlier draft of this section claimed pinning "costs nothing"; the
truth is there is nothing to pin.

Two residues, both small. The six state systems mostly have no as-of read, so they
answer "as of now" — but the overlay *declares* the state that matters, so both
siblings receive the declared value regardless, and only undeclared background
state can drift. And for Elastic the point is moot once §The mechanism splits by
system class gives the scenario its own index: that substrate is frozen by
construction.

**On the state side the fail-closed invariant inverts, so the test changes.** In
the serving design the hazard was accidentally reaching the real world
(`register_query_tool` resolves `registry.verbs(system)[verb]`, which falls
through to the real adapters when no override is threaded). For a patched
response, reaching the real world *is* the design, and the hazard is a response
**slipping past the applier** and returning unmodified truth — a silent scenario
deletion rather than a silent leak. The applier must be able to assert "this
envelope intersects the overlay and I patched it" versus "no intersection," and
that assertion is what a test pins. Elastic needs no such test, because
confinement already converts the same hazard into a fault.

The seam itself is cheap: `VerbRegistry` (`runtime/verbs.py`) is nominally typed —
its constructor refuses anything that is not a real `VerbGrant`, and `decide()` is
the single grant point — so the state-side oracle is one subclass overriding
`verbs()`.

### The oracle is stateful

It remembers three distinct things, and conflating them is a defect:

- **The overlay** — what the scenario declares. Authored once, immutable for the
  run.
- **Bindings** — detail the overlay did not specify but a response needs: a PID, a
  session id, a source port, a timestamp inside a window.
- **The realization log** — what was actually served, per query. The same overlay
  row renders differently under different projections and truncations, and the
  defender pivots on values from earlier answers. A value that was served has to
  keep existing.

**Bindings are minted at scenario materialization, not lazily at first query.**
This is the point where the author-once-apply-by-code constraint would otherwise
break: a binding invented mid-run is a decision made in the serving path, and if
an LLM makes it the constraint is void at the first unspecified field. Minting up
front also puts cross-system agreement somewhere it can be checked — an injected
session id has to agree with the identity system's last-login and with the event
stream's auth record, and that is a property of one authoring pass, not of three
independent inventions.

A lazy tail survives: a query may project a field the overlay never anticipated.
That tail must be a **deterministic function of `(row_id, field, seed)`** — never a
judgment call — so it is reproducible across forks and across re-runs.

### One oracle, one tool, per-fork

**A single oracle instance serves every fork, through a tool that names the fork
(`serve(query, fork_id)`).** This is not only a context saving. It is a
correctness requirement: the shared prefix in §The judge is only valid if both
forks return byte-identical responses across it, and that holds only if one
bindings ledger and one realization log are shared across siblings. Two instances
would diverge on the lazy tail even with the overlay minted up front.

Fork detection falls out of the same component for free: serve a query under both
fork ids and compare. Identical means no fork is needed yet; different means this
is the fork point. No separate divergence checker is required.

### The oracle checks feasibility, and detects its own contradictions

**Feasibility is established by probing**, since there is no declared inventory to
check against — the same real query access that serves the run. This is
deployment-agnostic and degrades correctly: an org with a bad CMDB gets
feasibility from the systems it does have.

It also closes a hole the vocabulary has never had covered (the corpus doc §The
vocabulary defect). An enum check says a class tuple is *spellable*; a bind says
whether it has a **referent in this deployment**. A tuple that fails to bind
means either the vocabulary is wrong or the deployment has no such thing, and
either way something
needs resolving.

**Feasibility is checked in one pass with three stages, not in three places.**
Placeholder binding, entity probing and the solvability/resolving-path derivation
(§The discriminator spine) are stages of a single pre-run validation, and each can
reject the scenario. Describing them separately invites three implementations of
one gate.

**Contradiction detection is the realization log's job.** §The judge requires a
`discard` verdict for episodes where the oracle contradicted itself or the spec,
and something has to notice. Because every served response is logged, a later
response that disagrees with an earlier one on a value the defender could have
pivoted on is mechanically detectable — same overlay row, incompatible rendering.
What the log cannot catch is a contradiction between the overlay and the *real*
substrate it was applied to; that surfaces only as an implausible answer, and it
is why `discard` also has to be available to the judge as a declared verdict.

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
swamp a single mutation's effect. A shared prefix eliminates **the prefix's**
variance exactly — and only the prefix's. Past the fork the two branches sample
independently, and the suffix is where the mutation's effect lives. So the fork
sharpens `ΔT` substantially without making it noise-free, which is why
§Lesson attribution still requires replication and why no scenario or lesson is
promoted on one pair.

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

**A `discard` verdict is required.** `OUTCOME_ENUM`
(`learning/core/config.py`) today is
`{caught, survived, undecidable, incoherent, skip-passthrough}`, and none of those
is it. `incoherent` is the near miss and the distinction matters: `incoherent`
judges the *story* — the actor produced something that does not hold together.
`discard` judges the *episode* — both players may have behaved well, but the world
they were graded in was corrupt, so no finding about either is admissible. If the
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

## Environment facts — see the companion doc

Environment facts were a byproduct of the old loop. With the `playground-v2/`
config files ruled out as inputs (§Seeds and mutations) they became the
**grounding substrate**: the questioner's world knowledge, the placeholder
vocabulary, and the defender's standing world model.

That made them large enough to own a document.
**`environment-corpus-and-vocabulary.md`** carries the corpus design — the
interpretation-cache framing, the referent/norm/semantics/sanctioned-path
clusters and their cache economics, the subject-keyed graph data model, the
schema change that drops `alert_rule_ids`, the vocabulary defect blocking it, and
frontier-keyed retrieval.

Three things from it bear on the training loop directly, and are stated here so
this document stands alone on them:

**The corpus is on the critical path, and its only current producer is being
deferred.** Both feeds are judge-emitted from actor directions, and the curator
lives inside the benign-actor author package — so deferring actor work orphans
the corpus. The replacement is one miner over a (query, response) corpus with two
feeds: the oracle in training, the persisted run tables at runtime.

**Interception is what lets training runs author environment facts at all.** The
original draft ruled they could not, because a training reviewer sees only
synthetic worlds. With the real deployment as the base, a fact is sound as long as
its supporting rows were not patched — and the applier knows exactly which rows it
touched, so row-level provenance makes that a mechanical check.

**Environment defect is the judge's fourth attribution bucket** (§The
discriminator spine). When `ΔT` diverges, is not explained by the mutation, and is
not a reasoning error, the deployment misled the defender. §Empirical grounding's
CMDB case is exactly this, and no adversary was needed to find it — a comparison
found it.

Two classes the training loop **cannot** produce, both of which must come from the
runtime feed: observability facts (rule coverage bounds them — §What dies), and
semantics facts that surface mid-investigation rather than at bind time.

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

## Sequencing

**The corpus doc carries its own sequence, and items 1–5 there run first.** The
vocabulary fixes, the schema change and the miner are prerequisites for the
questioner having anything to ground on, and none of them waits on the training
loop. What follows is this document's own order, assuming that work is in flight.

1. **Held-out recruitment** — separate session. It gates promotion and the
   overfitting gap, not the in-loop pairwise metrics (§Status), so it is first
   because promotion is worthless without it, not because it blocks the build.
   `fixtures/held-out/` is still a README.
2. **The two cheap fixes above** — prompt edits, no architecture.
3. **The oracle seam, Elastic side first.** Measure a typical investigation
   window in documents, then build the scenario index (`_reindex` with a
   transform script) and the `ELASTIC_EVENTS_INDEX` swap. This half needs no
   interception code and inherits fail-closed from `confine_index`, so it is both
   the cheaper half and the one that retires the aggregate problem.
4. **The state side.** `VerbRegistry` subclass, overlay ledger, binding minting,
   realization log, `oracle_queries.jsonl` — failing closed on *un-applied*
   rather than on *leaked*. Then placeholder binding on top of it.
5. **Solvability and resolving-path derivation**, from the world — one validation
   pass with three stages (bind, probe, derive), not three gates.
6. **The judge's discriminator spine, the fork, and the pair as the unit of
   judgment.** Requires agent-state resumability.
7. **Questioner strategy corpus + seed pipeline** — including filling the ticket
    corpus with adjudicated cases and making the intel feed technique-shaped.
8. **Lesson attribution in shadow mode.** #695's stable identity and
    loaded/applied/decisive sidecar without changing retrieval order. Also the
    forward-check's retirement point.
9. **Paired ablation and probe siblings.** Establish causal lift before any
    attribution score affects promotion.
10. **Curriculum search.** Mutation policy and score-informed retrieval only after
    the validity gates and held-out archive are trustworthy. Note that fork depth
    stays a diagnostic here (§Seeds and mutations) unless the argument for
    selecting on it gets made.

## Open questions

Resolved since the first draft, recorded so they are not reopened: the scenario
spec format for systems-of-record state (dissolved by interception); whether the
oracle needs a materialized base world (no); whether siblings must be minimal
twins (no); whether the questioner and runtime reviewer share a corpus (moot —
the shipped gate writes no counter-story).

**Decisions, not questions.** Three items block sequencing steps, so each carries
a default and a failure branch rather than waiting for an answer:

- **Removal predicates** (blocks step 6). *Default:* removal happens during
  `_reindex` — the transform script omits the documents the overlay withdraws, so
  no contradicting rows survive because the scratch index never contains them.
  *If the window turns out too large to copy:* fall back to a filtered alias, and
  if ES|QL does not honor alias filters, scenarios that require removal are
  restricted to windows small enough to reindex, and the FP-hunt direction is
  scoped accordingly.
- **Agent-state resumability** (blocks step 9). *Default:* snapshot the message
  history plus a copy of the run dir at a turn boundary; the two tables are
  append-only so a fork is a copy rather than a merge. *If a turn-boundary
  snapshot proves insufficient:* the fork degrades to two independent runs, `ΔT`
  reacquires full run-to-run variance, and the replication budget in step 12 must
  absorb it. The design still works; it gets more expensive.
- **The second node family for semantics facts** (blocks step 4). *Default:* two
  discriminated subject shapes in one schema — `entity/<type>/<id>` and
  `instrument/<system>.<verb>` — rather than a synthetic vertex type that pretends
  an instrument is a deployment entity. *If that proves unwieldy:* semantics facts
  get their own corpus with its own key, at the cost of two retrieval paths.

Still open:

- **Node-keyed vs. edge-keyed environment facts** within the entity family
  (the corpus doc §The data model) — referent facts key on a
  node, norm and sanctioned-path on
  an edge, and whether that is one schema or two is unsettled.
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
