# Training loop architecture (2026-07-30, revised 2026-08-15)

## Status

**Design, pre-implementation for the training loop. Two of the three original
components have since moved.** Amends the loop shape in `learning-loop.md` and
absorbs the deferred pointers in `learning-loop-actor-learning.md` (learning
actor) and `learning-loop.md` §Future Enhancements (live self-evaluation). When
this ships, those sections get rewritten rather than cross-referenced.

**Held-out recruitment blocks less than an earlier draft claimed.** It gates the
overfitting gap (§What dies) and promotion gating (§Lesson attribution), and
nothing else. The contrastive metrics inside the loop — realized fork depth, "no
fork point is a finding," fork position as a difficulty read, triplet trajectory
comparison, question fitness, and the with/without-lesson ablation — are computed
on synthetic siblings and need no held-out fixture. Recruitment is still sequenced
early because promotion is worthless without it, but it does not block building
the loop. `defender/fixtures/held-out/` still contains only a README.

### What the 2026-08-15 revision changed

A design session worked the questioner's grounding problem, then went looking for
defects in the accumulated run corpus. Both halves moved the design:

- **The questioner grounds by falsification search, and the environment-facts
  grounding substrate is retired.** It declares a story, predicts the data that
  would falsify it, and searches for that data (§Grounding by falsification
  search). Grounding is per-story and lands on the discriminating axis — the only
  axis that needed it. This retires the corpus-as-substrate claim the previous
  revision introduced, and with it the cold-start and staleness problems that role
  carried.
- **Solvability stops needing its own pass.** If the questioner found the
  falsifying data, the resolving path exists and it just walked it. The walk is
  the proof, so the old sequencing step for deriving it is gone.
- **The discriminator declaration and the falsification prediction are one
  object**, not two artifacts to keep consistent.
- **The judge's unit is a triplet, not a pair** — malicious, benign, and a third
  sibling mutated on a *different* axis, serving as a negative control
  (§Comparison, not rating).
- **The judge emits findings; the curators author.** Authoring, testing and dedup
  stay outside the judge, on incentive grounds as much as workload.
- **The failure-mode taxonomy is demoted** from a design input to post-hoc
  description. The buckets are not orthogonal and the architecture does not need
  them complete or accurate.
- **§Empirical grounding is no longer one case.** A survey of the 21 run dirs
  carrying a report found the same defect four times, a shipped lesson driving it,
  and a case mix that explains the thin yield without appealing to loop design.
- **Two factual corrections.** Defender lessons do not retrieve through a
  signature gate, and the Elastic config swap covers one index of two.

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

### The case that started it

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

### It is not one case

A pass over the 21 run dirs carrying a `report.md` (of 27 under
`$DEFENDER_RUNS_BASE`) found the same defect three more times, and a shipped
lesson driving it.

**The case mix explains the thin yield on its own.** 14 malicious, 6
inconclusive, 1 benign. Malicious routes to the FP hunt
(`directions.UNTRAINED_DISPOSITIONS`), and the section above says what the FP hunt
does with a key comment reading `attacker@elsewhere`. The training signal is not
thin because the loop is badly shaped; it is thin because two thirds of the corpus
routes to the direction that cannot resolve it.

**One defect shape, four instances.** In each, an artifact of how the environment
is built is read as evidence about the adversary:

| Run | What it concluded | What it actually was |
|---|---|---|
| `golden-case-014-authkeys-db1` | co-occurring `curl`/`nc` → "a multi-stage attack sequence" | `svc-health-probe`, every ~300s |
| `golden-case-002b` | "8 curl file-copy events, 8 netcat (nc) events… confirming a multi-stage attack chain" | the same scheduler |
| `golden-case-011-lotl-canary-2` | "root not existing as a registered principal in the identity system" | `root` is a local account and was never going to be in Keycloak |
| `20260728T161845Z-fresh-case` | host absent from CMDB; `loginuid=-1` | Falco reports the Docker host; the runner executes everything with `loginuid=-1` |

All four were disposed `malicious` at `confidence: high`, and the first three
reached that on 6, 7 and 11 queries. `golden-case-011` went further and called
malicious/high while recording that "the Elasticsearch cluster was unreachable
during investigation, preventing retrieval of the actual Falco event details" —
a confidence defect distinct from the environment-artifact one, and equally
invisible to outcome grading.

**A shipped lesson is driving it.** `golden-case-002b` names it:
`defender/lessons/falco-terminal-phase-no-upstream-chain.md`, whose check reads
*"scan for co-occurring Falco rules from adjacent attack phases … if any fire in
the same window, add them as upstream corroboration leads."* The baseline
guarantees the hit — `svc-health-probe` runs `curl … || nc -z 127.0.0.1 22` every
~300s across six host roles, and a second action sweeps `nc -z` over all eight
hosts and five ports — so every container window on every host contains exactly
the events the lesson sends the defender to look for.

The uncomfortable part is that **the lesson is carefully written.** It says add
them as *leads*, and its own body warns that "a container whose legitimate cadence
occasionally includes outbound tool calls would pass that check." The defender
collapsed *investigate these* into *these corroborate*, and shipped attack chains
that did not happen. The defect lives in the gap between what the lesson licenses
and what was concluded — the licenses-not-likelihood rule of §Its goals conflict,
showing up as an incident rather than as a style guideline.

**Nothing could have caught it at birth.** The forward-check tests that a lesson
does not flip its own source case. This one does not flip its source case; it
corrupts *other* cases. That is precisely the over-generalization risk §What dies
says the forward-check never tested — now observed rather than predicted.

Three consequences for this design:

- **It is the argument for the triplet.** No single run exposes it: in each, the
  inference reads as plausible and the disposition is correct. It becomes visible
  only when the same inference survives a world where it should not. Run the
  benign sibling and the off-axis sibling and the attack chain appears in all
  three, because the baseline noise is in all three. A non-discriminating
  inference is one that does not vary with the world, which is what the triplet
  measures directly.
- **It is the argument for findings-over-authoring.** The right fix is not
  obvious — delete the lesson, narrow it, or add a counter-lesson about baseline
  cadence? That is a judgment against the whole corpus, with dedup and a
  regression check. A judge holding one trajectory has no basis for it.
- **It is an acceptance test available before anything is built.** Does the
  triplet flag `falco-terminal-phase-no-upstream-chain` as non-discriminating? The
  fixtures, the lesson and the confounding baseline all exist today. A design that
  cannot catch a defect already found by hand is not ready.

**And it is live.** That lesson is in the corpus now, producing reports that
assert attack chains that did not happen. Deciding what to do about it waits on
nothing in this document.

### Correction: how lesson retrieval actually works

An earlier draft of this section said the loginuid lesson did not retrieve because
it is keyed to the signature it was born from. Defender lessons have **no
signature gate**. `scripts/lessons/lessons_fm.py` greps frontmatter across
`DIMENSIONS = ("source_signature", "telemetry_source", "attack_phase")` using
**model-supplied patterns**; only the environment corpus hard-gates on rule-id
disjointness (`lessons_env_retrieve.py:104`).

That explains both halves of the record: the terminal-phase lesson reached an
`authorized_keys` case because the two share `telemetry_source: falco`, and the
loginuid lesson missed because the model's grep did not match it. Retrieval is not
over-keyed, it is **under-determined** — which changes what re-keying can buy.

### Two environment defects found on the way

Neither is about the defender, and both are the shape the corpus doc's semantics
class exists for:

- **`v2-off-hours-sudo` has no time filter.** Its query is
  `falco.rule: "Sudo execution"` at threshold 3 per host. The `name` field is
  honest ("v2 sudo activity burst") and the description says outright that the
  rule "fires regardless of hour" — but the **`rule_id` says off-hours, and the
  `rule_id` is what propagates into the alert.** A reader keying on what the alert
  carries gets the wrong premise unless it opens the rule definition.
- **The change-mgmt seed is anchored to a fixed past date.** `changes.yaml` opens
  with *"Today (plan reference): 2026-04-24"*, months behind the running
  environment, so ad-hoc CRs are effectively historical and only the standing
  windows are live. That interacts with the absolute-time-anchor constraint in
  §The mechanism splits by system class: absolute anchors are right for Elastic,
  but change-mgmt answers relative to a `now` that disagrees with everything else.

### The two cheap fixes

**Both remain available, independent of everything above**, and neither has landed
across three revisions of this document:

- Make the judge's likelihood-ratio check **symmetric**. It still runs only on
  benign dispositions (`learning/pipeline/judge/malicious.md`, §Likelihood-ratio
  check — *"When `report.md` records a **benign** disposition"*); on a malicious
  call it should ask whether the incriminating observables fit routine automation
  equally well. Every run in the table above is a case it would have caught.
- **Re-key observable-semantics lessons** off the alert signature — the stopgap
  for the corpus doc §Retrieval. Minding the correction above: for defender
  lessons this changes what the model can usefully grep for, not the removal of a
  gate. Only the environment corpus has a gate to remove.

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

### Grounding by falsification search

**The questioner declares a story, predicts what data would falsify it, and goes
looking for that data.** Grounding is not a corpus it reads before it starts; it
is a search it runs per story, against the real deployment, on the axis that
decides the case.

This **retires the grounding-substrate role** environment facts acquired in the
previous revision, and with it the problems that role carried: cold start (the
first story works), staleness (every story re-grounds), and the epistemics of
absence (a stale source answers confidently and wrongly). What replaces them is
one search whose failure is local to one story rather than corpus-wide.

Three things fall out:

- **Solvability is proven by construction.** §The discriminator spine requires the
  resolving path be derived from the world and never accepted from the
  questioner. Here the questioner derives it *by walking it*, and
  `oracle_queries.jsonl` is the record of the walk. There is no separate
  solvability pass left to build.
- **The discriminator declaration and the falsification prediction are the same
  object** — not two artifacts that have to be kept consistent with each other.
- **A failed search is informative and localized.** It resolves to one of three
  states — the story is wrong, the query was wrong, or the deployment cannot see
  this — and all three are useful. The third is an observability finding, which
  §What dies otherwise says this loop is structurally unable to produce.

**What this does not ground is the deviation.** The search establishes the
*setting*: this host exists, this identity reaches it, this path is exercised. It
cannot establish "and had the attacker done X, Y would have appeared," because
that is counterfactual. Authoring the deviation coherently is the oracle's
problem, and none of this solves it — see §The cost of a wrong premise.

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
  byproduct. Note this is now a *byproduct* and not a dependency: since
  §Grounding by falsification search, nothing the questioner does waits on that
  corpus existing.

**Binding cardinality is a declared part of the contract.** A placeholder resolves
to a *set*, and its size changes the investigation — `{{compute:web-server/internal}}`
binding to forty hosts is a different case from binding to one. The questioner
declares the expected range and materialization asserts it, or the same archived
scenario silently changes difficulty as the deployment grows.

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

**The swap covers two indices, not one.** `confine_index` validates against
`(ELASTIC_EVENTS_INDEX, ELASTIC_ALERTS_INDEX)`, and only the first is the events
target. The alerts index is a live query surface in its own right —
`runtime/lead_zero.py:574` reads it for lead-0 resolution, `elastic_adapter.py:305`
serves it, and four shipped templates target it. Swapping only events leaves the
scenario's own alert absent from the alerts index while real alerts leak into the
scenario world: the cross-system corroboration failure this section calls
load-bearing, occurring inside the one system it declares solved. Both config
values get swapped, or the guarantee is half a guarantee.

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

### The cost of a wrong premise

The overlay can be wrong about the deployment in a way nothing catches at
authoring time — an assumed firewall rule, an assumed group membership.
§Grounding by falsification search grounds the setting but not the deviation, so
this residue is real and worth pricing, because it bounds how much authoring rigor
is worth buying.

**Direct contradiction is the cheapest layer** and often costs nothing, because
most premises have no system that answers them. There is no network-policy verb
among the seven, so a fabricated firewall rule is not directly checkable here at
all.

**Implication cost is what actually bites.** An injected connection implies an
inbound session on the far side, an auth record, possibly a process. The defender
corroborates, finds none of them, and concludes the telemetry is unreliable.
Nothing asserted the premise and nothing had to: **an injected fact costs every
fact it implies.** That yields an authoring heuristic worth more than a validation
pass — **inject at the leaves**. A key comment or a single field implies little; a
network path, a role assignment or a permission implies a subgraph.

**The teaching inversion is the real cost.** Both available defender behaviors
teach the wrong thing. If it notices the incoherence and flags it, the episode
punishes correct skepticism. If it does not notice, the episode teaches it to
accept incoherent evidence — which is the analyze-discipline defect this loop
exists to fix. There is no branch where a wrong premise is harmless, and the
asymmetry *worsens as the defender improves*, because catching the inaccuracy
becomes the correct behavior and gets graded as failure.

**But it is detectable after the fact, which is what makes it manageable.** The
overlay is known and the trajectory is recorded, so an episode in which the
defender reached ground the overlay could not support is identifiable. That is
`discard` earning a second job: today it covers the oracle contradicting itself,
and this extends it to the defender reaching unsupported ground. Scenarios
therefore do not have to be accurate — they have to be **accurate or detectably
not**, which is a far cheaper standard to hit.

## The judge

### Comparison, not rating

**The judge is given contrasts, not rubrics.** Asking a model to rate an
investigation 1–10 is a weaker instrument than asking it which of two
investigations handled something better, and the contrast family supplies the
comparison for free.

**The unit of judgment is a triplet, not a run and not a pair:** one malicious
sibling, one benign sibling, and a third mutated on a **different axis** from the
discriminator. Nothing is judged until all three have been investigated — a real
scheduling constraint, accepted deliberately.

The third sibling is a **negative control**, and it supplies what a pair cannot.
A/B tells you the trajectory changed; it cannot tell you the change was *specific
to the discriminating axis* rather than a response to being perturbed at all. An
inference that moves on the off-axis sibling too is non-discriminating — which is
exactly the defect §It is not one case found by hand, and which no single run
exposes.

This also upgrades the probe sibling's job. C was a transfer test on the
*defender* (did it learn the rule or the story). The off-axis sibling tests
whether the *judge's attribution* is real, which is the more load-bearing of the
two while the loop is young.

Three comparisons, all same-unit and all contrastive:

| Comparison | Answers |
|---|---|
| the triplet's trajectories | did the defender move on the discriminator, and only on it; did the questioner's predicted failure land |
| with-lesson vs. without | causal lesson lift (§Lesson attribution) |
| current defender vs. frozen archive | overfitting to the simulator (§What dies) |

Same-unit is the general principle, and it is why the retired frozen-actor
metric read as a vibe: it compared accuracy against catch rate.

**The third sibling's disposition may be sampled; its axis must be declared.** An
arbitrary third story restores the confounding the contrast exists to remove. What
makes it a control is that the questioner names which axis it moved and commits to
the prediction that the defender's discriminating inference should *not* move
with it.

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

**These buckets are description, not a design input, and they are not
orthogonal.** The defect in §It is not one case is simultaneously lead quality
(the wrong window), analyze discipline (over-reading co-occurrence), an
environment defect (the baseline misled it) and a lesson defect (a lesson licensed
it); naming the bucket adds nothing that the comparison did not already give.
Nothing in this architecture requires the taxonomy to be complete or accurate —
the questioner poses a question, the triplet says whether the defender's inference
tracked the world, and the category is applied afterwards for routing. A design
that had to classify first would inherit every gap in the classification.

**Where the fact is placed decides which stage is under test.** Off the default
lead path, the question is whether the defender chose to go get it — a PLAN-time
consequence. On the guaranteed path (the alert itself, or lead-0), delivery is
certain and the only remaining question is what was concluded — an ANALYZE-time
consequence, and the class §It is not one case is full of. Both screen cheaply
before a full investigation: the first on the planned lead set, the second on
whether the delivering query appears in the queries table.

**Prefer a discriminator that lands on a typed invlang slot.** An authz contract
carries `verdict ∈ authorized | unauthorized | indeterminate` and gates
`disposition: benign`; weights carry `STRONG_WEIGHTS = {++, --}`; hypotheses are
refuted or not. When the discriminating fact bears on one of those, "did the
defender update correctly" is a check on a row rather than a reading of prose —
which shrinks the one bucket above that needs an LLM at all.

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

**The judge emits findings; it does not author.** Authoring, testing and dedup
against the existing corpus are curation work and stay with the curators under
`learning/author/`, which is where they live today. The separation is an incentive
boundary as much as a division of labor: a component that both detects a defect
and writes its fix writes fixes shaped to the instance that triggered detection —
the same shape of hazard §Seeds and mutations refuses when it keeps fork depth a
diagnostic rather than a fitness term.
§It is not one case is the concrete instance: the right response to the
terminal-phase lesson is a judgment against the whole corpus, and a judge holding
one trajectory has no basis on which to make it.

**The failure mode moves, and the original draft under-weighted it.** Today's
judge is white-box over raw payloads on a real case, so its error is
"hallucinates a gap." A judge grading against an authored answer key errs by
**inheriting the questioner's mistake** — systematically, because one questioner
writes many scenarios. Solvability-derived-from-the-world and the `discard`
verdict are the defenses, and both are load-bearing rather than nice-to-have.

## Environment facts — see the companion doc

**The grounding-substrate role is retired** (§Grounding by falsification search).
Environment facts were promoted to it in the previous revision because the
`playground-v2/` config files had been ruled out as inputs and *something* had to
replace them. Falsification search replaces them instead — per story, on the
discriminating axis — so **the corpus is no longer on this loop's critical path**,
and the previous revision's "environment mining blocks the questioner" claim is
withdrawn.

That is a demotion, not a deletion, and what survives is narrower and better
targeted. **`environment-corpus-and-vocabulary.md`** carries the corpus design;
four things from it still bear on the training loop:

**The invlang vocabulary defect is independent and still live.** Class slot values
are unvalidated and already drifting — `compute.zone` carrying `prod`/`preprod`
against an enum that means network topology. That blocks entity selectors as a
retrieval key regardless of what the questioner does, so its sequence runs on its
own timeline rather than gating this one.

**Instrument semantics is the durable class**, and it is the one thing
falsification search re-derives rather than knows. The `v2-off-hours-sudo` trap in
§Two environment defects is the type case: no observation of the deployment tells
you the `rule_id` lies. Whether re-deriving it costs enough to justify caching is
a question to answer by feeling the cost, not by deciding in advance — the corpus
that gets built because it was needed will be smaller and truer than the one
designed up front.

**Environment defect is the judge's fourth attribution bucket** (§The
discriminator spine). When `ΔT` diverges, is not explained by the mutation, and is
not a reasoning error, the deployment misled the defender. §Empirical grounding's
CMDB case is exactly this, and no adversary was needed to find it — a comparison
found it.

**Interception is what lets training runs author environment facts at all.** The
original draft ruled they could not, because a training reviewer sees only
synthetic worlds. With the real deployment as the base, a fact is sound as long as
its supporting rows were not patched — and the applier knows exactly which rows it
touched, so row-level provenance makes that a mechanical check.

One class the training loop still cannot produce: semantics facts that surface
mid-investigation rather than at bind time. Observability facts are no longer
wholly excluded — §Grounding by falsification search generates one whenever a
falsifier exists in the story and nothing in the deployment records it — though
the *alert-coverage* half of that class remains bounded by rule coverage
(§What dies).

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
causal lift; the off-axis sibling separates axis-specific effects from general
ones; held-out performance controls
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

**The corpus doc no longer gates this one.** Its vocabulary items still run, and
still run early, but for a defender-side reason (entity selectors as a
trustworthy retrieval key) rather than because the questioner needs something to
ground on. That dependency is gone with §Grounding by falsification search, and
the two sequences are now independent.

1. **Decide what to do about `falco-terminal-phase-no-upstream-chain`**
   (§It is not one case). It is live and producing reports asserting attack chains
   that did not happen. This waits on nothing and is not a design question.
2. **The two cheap fixes** — prompt edits, no architecture. Unlanded across three
   revisions of this document, and the symmetric likelihood-ratio check would have
   caught every row in that section's table.
3. **Held-out recruitment** — separate session. It gates promotion and the
   overfitting gap, not the in-loop contrastive metrics (§Status), so it is early
   because promotion is worthless without it, not because it blocks the build.
   `fixtures/held-out/` is still a README.
4. **The oracle seam, Elastic side first.** Measure a typical investigation
   window in documents, then build the scenario index (`_reindex` with a
   transform script) and swap **both** index config values. This half needs no
   interception code and inherits fail-closed from `confine_index` — and its one
   unknown, window size, can invalidate the plan, which is the argument for
   putting it before anything that depends on it.
5. **The state side.** `VerbRegistry` subclass, overlay ledger, binding minting,
   realization log, `oracle_queries.jsonl` — failing closed on *un-applied*
   rather than on *leaked*. Then placeholder binding, and falsification search on
   top of it. There is no separate solvability step here any more: the search is
   the derivation (§Grounding by falsification search).
6. **The judge's discriminator spine, the fork, and the triplet as the unit of
   judgment.** Requires agent-state resumability. The acceptance test is item 1's
   lesson: does the triplet flag it as non-discriminating?
7. **Questioner strategy corpus + seed pipeline** — including filling the ticket
    corpus with adjudicated cases and making the intel feed technique-shaped.
8. **Lesson attribution in shadow mode.** #695's stable identity and
    loaded/applied/decisive sidecar without changing retrieval order. Also the
    forward-check's retirement point.
9. **Paired ablation and off-axis siblings.** Establish causal lift before any
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
the shipped gate writes no counter-story); whether the questioner needs an
environment corpus to ground on (no — §Grounding by falsification search); whether
the judge's unit is the sibling pair (no — the triplet, with an off-axis control);
and whether the judge authors its own fixes (no — it emits findings).

**The largest remaining unknown is how the deviation is authored.** The retired
spec-format question has been replaced rather than removed: falsification search
grounds the setting, and nothing grounds the counterfactual. §The cost of a wrong
premise prices the damage and offers two partial answers — inject at the leaves,
and extend `discard` to episodes that reached unsupported ground — but neither is
a method for authoring a coherent deviation across seven systems. This is where
the next design session should start.

**Decisions, not questions.** Three items block sequencing steps, so each carries
a default and a failure branch rather than waiting for an answer:

- **Removal predicates** (blocks step 4). *Default:* removal happens during
  `_reindex` — the transform script omits the documents the overlay withdraws, so
  no contradicting rows survive because the scratch index never contains them.
  *If the window turns out too large to copy:* fall back to a filtered alias, and
  if ES|QL does not honor alias filters, scenarios that require removal are
  restricted to windows small enough to reindex, and the FP-hunt direction is
  scoped accordingly.
- **Agent-state resumability** (blocks step 6). *Default:* snapshot the message
  history plus a copy of the run dir at a turn boundary; the two tables are
  append-only so a fork is a copy rather than a merge. *If a turn-boundary
  snapshot proves insufficient:* the fork degrades to independent runs, `ΔT`
  reacquires full run-to-run variance, and the replication budget in step 9 must
  absorb it. The design still works; it gets more expensive — and it gets more
  expensive again under the triplet, which is three trajectories rather than two.
- **The second node family for semantics facts** (blocks step 5). *Default:* two
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
  the old schema. Re-derived, grandfathered, or re-keyed only? §It is not one case
  raises the stakes: at least one of the 16 is actively harmful, and it was found
  by hand rather than by any gate — so the question is not only which corpora are
  stale but which are *wrong*, and nothing currently answers that.
- **Replication cost under the triplet.** Three trajectories per judgment instead
  of two, against a shared prefix that only reduces variance up to the fork. The
  control is worth paying for; how much it costs per promoted lesson is not known,
  and it compounds with the resumability decision above.
- **Whether the off-axis sibling needs its own solvability.** Its job is to *not*
  move the defender's discriminating inference. That is a weaker obligation than
  the malicious sibling's, but "nothing to find" and "something to find that the
  defender did not look for" are different worlds and probably grade differently.
- **What the questioner may read.** `lessons_env_retrieve.py`'s containment guard
  stops the malicious actor reaching `defender/lessons`, on hygiene grounds that
  do not obviously transfer — targeting blind spots is an adversary's job. There
  is a better reason to keep the boundary anyway: lessons record what the defender
  was *told*, outcomes record what it *does*, and the gap between them is the most
  valuable signal in the system (§It is not one case is exactly that gap). A
  questioner reading lessons directly cannot see it; one learning the frontier
  from measured outcomes can.
