# Learning architecture — redesign (2026-07-30, revised 2026-08-16)

## Status

**Partly shipped, and the training half is redesigned.** Three things landed since the
first draft and are no longer proposals:

- **Runtime review is live.** `runtime/challenge_gate.py` (#774/#783, 08-04) plus the
  blind lenses in `runtime/review/` (#796/#802, 08-07). §Runtime review is now a
  comparison between what was asked for and what exists.
- **The frozen-actor metric is already retired** (#795, 08-07) — §What dies described its
  death prospectively; `evals/README.md` records it.
- **The oracle stage left the loop** (#791). `run_cycle.py:113`: "the retired oracle stage
  leaves the leg's own call chain entirely — the judge is driven straight off the actor's
  story and the run's own executed evidence." §The diagnosis below is therefore a
  post-mortem, not a critique of a running system.

**What this revision changes.** The first draft proposed generating a base world from
scratch. That design is replaced by the **turn-N branch**: fork a real investigation at
the moment its evidence is in hand, and propose a pair of worlds consistent with that
evidence. The generated world survives only as the thing we decided not to build, and
§Captured base records why. Executing against a live estate stays on the table as a later
platform bet, not a prerequisite (§Execution, later).

Held-out fixture recruitment is still a **prerequisite for measuring any of this** and is
handled separately. Every metric below is uncomputable until it lands.

## The diagnosis (post-mortem)

The loop was two mechanisms wearing one coat.

One was **counterfactual review of a real case**: a blind actor wrote a story against the
lead sequence the defender actually ran, and the judge tested it against the raw payloads.
The other was **training against a simulated world**: the oracle stood in for telemetry
that was never produced.

They were fused because the oracle existed to bridge the actor's blindness. The actor
could not see results (or it would mark its own homework), so its story had to be
converted into a falsifiable per-lead prediction before the real payloads could contradict
it. That was the oracle's actual job: **a blinding device, not a world model.**

The fusion put the oracle in the one place where its error was undetectable — answering a
counterfactual about a world where something *else* actually happened, which is why its
whole vocabulary was a signed delta over baseline, and why calibrating it required a golden-set
campaign with a held-out ledger. #791 resolved this by deletion. What survives is the
half that was always sound: **the judge is white-box over the raw payloads**, and that is
now the entire mechanism. The redesign's job is to give it a question worth grading.

## The three components

### 1. Training loop — the turn-N branch

Fork a real investigation at turn N. A **questioner** proposes a pair of worlds both
consistent with the evidence gathered so far, differing by one mutation. The **student**
(the runtime defender) continues the investigation in each. The **reviewer** grades
against a ground truth known by construction — the mutation itself.

### 2. Frontier-keyed lesson retrieval

Lessons are retrieved by containment over the **invlang frontier** — the shape of what is
currently unresolved — rather than by alert signature. See §Retrieval.

### 3. Runtime adversarial review

Each confident close is challenged before it commits. This shipped; §Runtime review is now
about the gap between its design and its implementation.

## The turn-N branch

At turn N the defender holds a concrete set of payloads and has concluded nothing. Author
two worlds **both consistent with those payloads**, differing by one fact. Resume the run
in each. Ask whether the defender's trajectory diverges.

**This is the question PLAN already asks.** `SKILL.md`: *"the right next lead is the one
whose result divides them. State which hypotheses it separates and why; if you can't, you
don't yet have the lead."* A pair of worlds consistent with the evidence **is** a pair of
live hypotheses; the mutation **is** the discriminating predicate; "can the defender
discriminate the worlds" **is** "can the defender pick the discriminating lead." The
training loop stops needing a vocabulary of its own — no actor story, no oracle
projection, no judge translation layer.

The collapse goes one further. The defender at PLAN enumerates hypotheses and picks a
divider; the runtime reviewer instantiates the counter-disposition and demands a
discriminating query; the questioner proposes a pair and looks for a mutation that is
*not* divided. **One procedure at three objectives** — cooperative, adversarial-in-the-small,
adversarial-in-the-large. That is the real argument for §One corpus.

What the construction buys:

- **The discriminator is open by construction.** A pair consistent with everything the
  defender knows is, by definition, undecided at turn N. "Informative failure near the
  frontier" stops being something selection has to search for, which deletes most of the
  tournament machinery and the hazard it needed guarding against.
- **Invariance is total and free.** Both siblings share the entire observed prefix — the
  same real payloads, not "identical outside the mutation set by construction." `ΔW` is
  exactly the mutation, with no generated background to audit for tells.
- **Both siblings are runnable**, so the A/B anchor pair is the default rather than an
  authoring obligation. Which world is true is the harness's choice, and it is the key.
- **Volume from few cases.** Every real run offers N−1 branch points.
- **A real anchor.** The prefix is real payloads from a real alert, so the loop cannot
  drift into a purely synthetic distribution.

**Solvability collapses from a proof to a check.** The first draft required a pass that
derives a resolving path across a synthesized seven-system world — a reasoner as capable
as the defender, uncalibrated, on the critical path, replacing the oracle in the seat
where error is invisible. Here the obligation is *"does any proposed fact contradict these
N concrete payloads"*: a checkable predicate over a finite record set. A small **forward
reachability** check survives — the siblings agree on everything observed, so they must
differ somewhere a not-yet-run query can reach, or the pair is undiscriminable — but it is
local, not a path derivation.

**Consistency is checked against the payloads, never against the defender's beliefs.**
`executed_queries.jsonl` plus `gather_raw/`, not the `:T resolutions`. Check against its
interpretations and every branch inherits the misreadings of the run it came from.

**It distills discrimination, not hypothesis generation.** If pairs are drawn only from the
defender's stated frontier, the loop can teach it to divide hypotheses it already had and
nothing else — and the motivating case in §Empirical grounding is the other failure: the
defender never generated "this is baseline noise," it generated an attack chain. So the
questioner may propose worlds **outside** the stated frontier, bound only by consistency
with the observed evidence. That is a different selection rule from "branch at the
frontier," and both are needed.

**Calibration risk.** Branch always at the frontier and every case is hard by construction;
the defender never meets an easy one and can be trained toward over-investigation. Mix in
siblings that resolve cheaply, deliberately.

## The captured base world

The base is **captured, not authored**. Its state across the seven systems and its event
log are whatever the real adapters returned during the real run; a sibling is that capture
plus a declared mutation.

**The questioner cannot pin state, only diff it.** This is the guard the generated design
could not have. A worked probe of the generated design (§Empirical grounding) planted one
false environmental premise — a prod-criticality `canary-1` with a standing Sunday change
window, where `hosts/inventory.yaml` says `criticality: sandbox`, `change_window: null`,
and `change-mgmt/seed/standing.yaml` materializes CRs for db-1 and web-1/web-2 only — and
walked it through every gate. **All four passed.** Validity, oracle consistency,
solvability and absence-of-tells are each defined over the *authored* world; none compares
it to the deployment, and a memoized ledger makes a false premise *more* invisible by
guaranteeing every corroboration agrees. The draft had imported the golden set's rule —
*"a label may be corrected from the environment, never from the projection"* — into a
design with no environment left to be corrected from.

Under capture, that premise cannot be stated. Reaching the same world requires declaring
`change-mgmt: +CHG-CANARY-ROTATE covering canary-1` against a base where canary-1 has
never had a CR — a one-line auditable claim, catchable by a rule as cheap as *"this
mutation invents the first CR this host has ever had."* **Silence inverts**: in a generated
world anything unspecified is invented; in a captured one anything unmutated is true.

This does not make a mutation *correct* — a questioner can still declare an implausible
diff. It makes it visible and small, which is the difference between a review problem and
an undetectable one. It also does not cover a mutation's cross-system consequences falling
outside what was captured.

**What the oracle still has to do.** It serves **every** `query()` call after the branch —
lookups included, not just log queries. Serving means reading the captured base and
applying the sibling's mutation, and where the base is silent, deciding **once** and
memoizing. A per-call judgment recomputed each time is the mid-run authoring that made the
old oracle fatal; the write-through ledger is what makes `ΔO` checkable against `ΔW`.

Two seam facts belong here. The verb registry **falls back to the real adapters when no
override is threaded** (`driver.py`'s `verbs is not None` default), so a missed hook
answers from the real playground — the training hook must fail closed. And the answer
*shape* is undeclared: across the seven adapters the return annotations are `dict` ×21,
`str` ×8, `dict | list` ×2, and the query templates' frontmatter declares `verb` / `params`
/ `body_substitutions` — inputs only. An oracle can know exactly what was asked and have
nothing constraining a well-formed answer. The empirical route is the recorded payload
corpus per verb; adding a `returns:` block to the ~29 templates, seeded from it, is the
cheap fix. Note where the evidence is thinnest: the recorded corpus reachable here is 43
non-sentinel queries, 30 of them `elastic` and 3 across `cmdb` and `change-mgmt` combined,
with three of the seven systems unrepresented — so the *state* side, which carries the
substance, is exactly where there is least shape evidence to synthesize against.

**Laziness mostly evaporates.** A captured base has no unmaterialized territory to invent
into. Where generation is kept anyway, the guard is not a name check ("never touch an
entity named in the discriminator or a mutation set") — a lazily invented CR covering the
window names no discriminator entity and neutralizes it anyway, self-consistently, so no
contradiction check fires. The guard is: log raw lookup values, then **re-run the
discriminator reachability check against the final ledger** and `discard` if it moved.

**"Telemetry" undersells the spec.** Seven systems of record sit behind the typed query
tool and only one is an event stream. The ambiguity that makes a case hard lives in the
state — which is precisely what capture supplies for free and authoring supplies worst.

## The compare suite — discriminator spine

Every pair names its **discriminator**: the predicate whose value separates the
dispositions, the value it takes in each world, which system holds it, and the query
envelope through which the defender could establish it.

The reviewer's context is spined on these discriminating facts rather than on the leads the
defender ran — and under turn-N that spine is **already written**. It is the invlang
frontier at the branch point plus the mutation, in `investigation.md`, not a new artifact
to design. Each row carries the predicate and its value per sibling, the holding system and
envelope, the expected observation difference, whether and when the trajectory touched it,
and what the defender concluded on receiving it.

Three diffs the reviewer compares directly:

- **world diff (`ΔW`)** — the mutation: a literal diff, not prose;
- **observation diff (`ΔO`)** — the difference the oracle actually exposed; and
- **trajectory diff (`ΔT`)** — the defender's changed investigation and verdict.

Attribution then mostly falls out. A `ΔW` with no reachable `ΔO` is an invalid pair. An
unexpected `ΔO` outside `ΔW` is a harness leak — and with `ΔW` literal, that check is code.
Never querying the holding system is a lead-set gap; querying it at the wrong scope is
lead-quality; receiving the fact and reasoning past it is analyze-discipline; establishing
it without the warranted disposition change is decision discipline.

A `discard` verdict is required (no current outcome enum has one — `core/config.py:245`).
If the oracle contradicted the base or an earlier answer, the episode teaches nothing about
either player. Most contradictions are mechanical and belong upstream of the reviewer, but
the reviewer needs a verdict for corruption found during comparison.

**One outcome is still missing: corpus-versus-world contradiction.** When the defender holds
an environment fact contradicting the world it is served, it has no typed way to report it.
Stay silent and the contradiction is invisible; follow the corpus and the reviewer scores a
defender failure when the world was wrong. `discard` covers the oracle contradicting itself,
not the oracle contradicting the corpus.

## Sibling families and scenario sources

A family is a captured base plus declared mutations:

- **A / B** — the minimal pair: one predicate, both values, everything else identical
  because it is literally the same prefix.
- **C — probe sibling** — preserves the underlying distinction while changing one mechanic
  (process, identity, timing, authorization), or moves one controlled step toward the
  decision boundary. C tests transfer: a defender that succeeds on B and fails when the
  same principle arrives through a different mechanic learned the surface, not the rule.

**The mutation vocabulary and the scenario menu are the same artifact.** Scenario selection
should start from a technique menu — the approach the malicious actor already uses — rather
than from whatever the alert stream happened to emit: coverage becomes declarative and
auditable, and the menu is human-curated, which is the one external anchor the loop
otherwise lacks. Choosing a scenario and choosing sibling C's mutation are then the same
operation at two depths, over the same technique × variant axes. `playground-v2/attacks/`
already carries a runner and 9 scenarios; they are id-keyed, not technique-keyed, and
adding that axis is what makes them the shared table.

**Runtime review is one source of scenarios, not the source.** Its output is a
counter-disposition story anchored on a real alert and a real frontier, which is a good
seed — but it is not a coverage plan, and the first draft's claim that "no separate seeding
pathway is needed" does not survive. The mix of menu-generated and review-seeded scenarios
should be a declared ratio, not an accident.

Selection must not reward whichever child defeats the defender most often — that converges
on unobservable questions and harness exploits. Validity, consistency and reachability are
hard gates. Beyond them, turn-N supplies frontier proximity for free, so what remains for
selection is much smaller than the first draft assumed: mutation-set edit distance for
matched descent, and structural investigation cost (minimum calls on a resolving path;
systems, entities and temporal joins required; hypotheses to eliminate) only where
cross-family comparison is unavoidable. Text length and decorative facts are not
complexity. Because model runs are stochastic, nothing is promoted from one tournament.

## Lesson attribution and effectiveness

Issue [#695](https://github.com/beetroot-salad/cyber-response-agent/issues/695) provides the
cheap observational signal. Its `loaded` / `applied` / `decisive` split is the correct
contract: record `applied` at the lead or plan change before the outcome is known, then join
it to a calibrated win/loss/no-update result. This can nominate promising lessons and order
them within the already-relevant retrieval set.

Application is evidence of involvement, not proof of effectiveness. A defender can credit a
lesson that merely restates its existing belief; preventative lessons never feel decisive;
several applied lessons make credit ambiguous. Self-attribution alone produces a salience
loop.

Effectiveness needs a paired intervention — run the same family with and without the lesson
available, then evaluate withheld siblings. The useful quantity is **causal learning lift**:

> improvement attributable to the lesson in disposition accuracy, discriminator reach, and
> investigation cost, without regressions on the opposite-disposition siblings.

Two separate fitness signals follow: **question fitness, before learning** (did a valid and
affordable pair expose the intended gap?) and **lesson fitness, after learning** (did the
lesson close it and transfer across mechanics without creating benign false positives?).

The pipeline: #695 attribution nominates; paired ablation estimates causal lift; probe
siblings test generalization; held-out performance controls promotion and retrieval rank.
Attribution may act as a prior or exploration weight, but only replicated causal lift is an
effectiveness result.

## Retrieval — frontier keying

**Retrieval must fire per gather loop, not once.** A lesson about what a field does and does
not license is only relevant once the field is in hand. `SKILL.md` already ties discovery to
the lead ("once you know its telemetry source and the ATT&CK tactic"), and the shim is
available all run — so the mechanism is not the blocker. What is missing is a frontier
derived mechanically per loop instead of restated by the model, which the parser and
validator already know how to do.

**Match by containment, not by similarity score.** The frontier has structure — typed slots
with `??`, plus the open hypothesis set — so a lesson declares the pattern it applies to and
matching is mechanical, fewer slots matching more. This is assembly: the invlang advisory
verb already does frontier-keyed recall (signature anchor plus open hypothesis names), and
`scripts/lessons/lessons_env_retrieve.py` already matches by slot-wise selector containment,
`*` and fewer-slots-matching-more included.

Three gaps close it. The advisory recalls precedent *cases*; lessons need selectors and
become a recall class. Its frontier is hypothesis names only — `??` slots are out of scope,
and the motivating case's frontier item is slot-shaped. And the frontier is model-supplied at
the prompt.

**The specificity floor is not hypothetical.** An empty selector is an every-loop lesson, and
one was live: `lessons-environment/authorized-keys-host-cr-baseline.md` carried `entities: []`
with the comment `# migrated #298: entities best-effort, source prologue unrecoverable`, so a
lesson born from one host matched every authorized_keys alert on every host — while
asserting *"a missing CR is positive evidence of anomaly"* against `skills/change-mgmt/SKILL.md:39`,
*"Absence of a CR is the realistic case, not the exception."*

**Resolved (#919): that lesson was DELETED, and the floor was not built.** The #298 audit
found four `entities: []` survivors, not one, and they are three different defects rather
than one — two are legitimately unscoped (a method lesson true rule-wide, and a
deployment-wide fact about the CMDB), one is under-specific, and only the CR baseline was
actually wrong. It was wrong in CONTENT, not scope: `playground-v2/change-mgmt/seed/standing.yaml`
covers `db-1`/`web-1`/`web-2` and says ad-hoc activity stays CR-free by design, so absence of
a CR is the base rate and the inference is invalid at any scope. A specificity floor would
have forced fabricated selectors onto the two lessons where empty is the truthful answer, so
no gate ships. Note the scope of what replaces it: the specificity RANKING #919 builds is on the
DEFENDER corpus's new `frontier_nodes` / `frontier_edges` selectors, matched by
`scripts/lessons/lessons_frontier.py`. The `entities: []` lessons live in the sibling
ENVIRONMENT corpus, which `lessons_env_retrieve.py` still returns unranked and in filename
order — the three surviving under-scoped lessons there are unchanged by this work, and remain
open for the #298 follow-up.

**The schema defect this fixes.** Lessons currently key on the alert signature they were born
from. That is right for coverage lessons and wrong for observable-semantics lessons, whose
trigger condition has nothing to do with which rule fired.

## Runtime review — asked for, and shipped

What landed matches the design's **action** contract and not its **instantiation** contract.

**Met.** Exactly two outcomes — send the close back or force `inconclusive` (`CHALLENGED` /
`FORCED_INCONCLUSIVE`) — and the demand that anything unbounded carry a cap and a budget line:
`Bounds`, `raised_request_limit`, `CAUSE_TURN_BUDGET_SPENT`.

**Not met.** The design requires instantiating the **counter-disposition** — the failure mode
is agreement, and prose is not an output. What shipped is `support` + `ablation` + `composer`,
where ablation is the same lens with one edge withheld (`review/projector.py`). That tests
whether a conclusion survives losing an edge; it never asks whether an alternative story
survives. §Empirical grounding shows the difference empirically: with the strongest edge
removed the ablation lens *raised* confidence, because the remaining supports were also junk.
**Redundant junk passes an ablation test with distinction.**

**Also not met: the typed concession.** "A concession is an output, not an exit" — the
counter-story, the observed fact that kills it, and the load-bearing inferences the case never
tested. On a clear-cut case it is the *only* thing review should produce, and it carries the
mutation target. Today the review record persists `verdict` / `reviewed_disposition` /
`detail` / `failure_kind`, and its only readers are `close_tool`, `challenge_gate`,
`_run_paths` and the visualizer. Nothing under `learning/` consumes it.

**`inconclusive` bypasses the gate** (`close_tool.py:436`), which makes review a one-way
ratchet: it manufactures the one disposition class it never examines. The fix is a rule worth
having anyway — **`inconclusive` must name a missing source.** Not "I gave up" but a typed,
falsifiable claim: *predicate P would resolve this; no system in this deployment exposes P.*
That is adjudicable by the reachability check run in reverse, and a forced close that cannot
produce the claim should be refused rather than committed. It also fills the hole the training
loop structurally cannot: every scenario begins from something that fired, so training can
teach "you saw this and reasoned wrong" but never "nothing would have told you" — under this
rule the live stream produces exactly those findings.

One live consequence: the gate forces inconclusive on three causes —
`CAUSE_EVIDENCE_CANNOT_DISCRIMINATE`, `CAUSE_NOTHING_LEFT_TO_ASK`, `CAUSE_TURN_BUDGET_SPENT`.
Only the first can carry a gap claim. The other two are exhaustion, and shipping them as
`inconclusive` launders a run failure into a deployment gap, poisoning the coverage channel
with noise that correlates with budget rather than telemetry.

**This deletes design principle #1.** "Offline only. No live latency cost" was first in
`learning-loop.md`. We now pay review cost on every confident investigation. Worth it, but it
is an explicit trade.

## One corpus, one role

The questioner and the runtime reviewer are the **same role**: both construct a plausible
alternative story, the reviewer with a narrower prior. §The turn-N branch gives the stronger
version — the defender's own PLAN step is the third instance of the same procedure. "What
worked as an attack" and "what to check" are the same content read by the same kind of reader,
so there is one actor-side corpus, one selector mechanism, and no view split.

Nothing reads it yet: the shipped lenses reference no corpus at all. Wiring them to the
actor-side corpus is the concrete next unit of work, and it is smaller than "build runtime
review" was.

**The flow runs both ways.** Lessons moving generator→runtime pull the live reviewer toward
synthetic attack shapes; seeds moving runtime→generator pull the curriculum back toward real
alert surfaces. With a captured base and a technique menu, the real-alert anchor no longer
depends on that return path alone.

**The cost of merging** is that a wrong tradecraft lesson skews the curriculum and the live
challenge in the same direction, with nothing left to cross-check it. Actor lessons become
production-facing: until now a bad one only made synthetic stories worse. They need the same
promotion bar as defender lessons.

## What dies, what transfers

**The frozen-actor secondary metric is already dead** (#795). Its replacement is better-typed:
real-held-out disposition accuracy against synthetic-scenario disposition accuracy — the same
unit on both sides, so the gap is directly the overfitting number. It must be measured on a
**frozen scenario archive**: pairs pulled permanently out of training and selection, re-run
periodically, so the questioner cannot have optimized against them. Selection holds the
defender near informative failure by design, so live-curriculum accuracy is depressed and the
gap would otherwise measure curriculum pressure. Two things the first draft left undefined and
should be settled before the metric is trusted: the archive's refresh policy (a frozen set goes
stale as the curriculum moves, and refreshing it is the contamination the freeze prevents), and
whether it should also be the home for historical attack shapes — a regression suite and a
measurement holdout have different lifecycles.

**The oracle golden set re-aims rather than pausing.** What a serving oracle needs measured is
"does the world I served match a real capture of this activity" — what that apparatus already
does, and what a captured base narrows to the mutation. The envelope measurement survives. The
four-class baseline-diff labeling goes with the projection.

**The forward-check retires late, and is not replaced by a birth gate.** It guards a rare
failure — a lesson flipping its own source case. The live risk is the one it never tested:
over-generalization downgrading the opposite-disposition sibling. No cheap birth gate covers
that, so behavioral quality is the learning process's job. Birth-time validation shrinks to two
free checks: a curator fold must preserve the gap the lesson was born from, and a selector must
be satisfiable by its source case's prologue. Retirement point is lesson attribution landing.

**Real cases stop being a lesson source — except through review.** The training reviewer only
ever sees branched worlds, and an environment fact authored there describes a mutation, not the
deployment. The curators' real-case input is the runtime-review artifact (challenge, concession,
killing fact), which is where environment facts keep being born from the real world. Note the
firewall's limit, which the probe found: "lessons about the players, never about the
environment" filters by **topic, not by truth** — a player lesson's warrant can be a false
environmental premise, and it ships to production as the lesson's implicit claim.

**Unchanged and reused:** the runtime defender and its phase discipline, the permission gate,
the seven adapters and the typed query seam (one interception point; verbs return plain JSON
values — the two ticket verbs returning bare strings do so as the answer-key defense), the two
tables and their join surface, the curators, the drain/worktree/PR machinery, the lessons
corpora, and — newly load-bearing — `session_store.fork()`.

## Empirical grounding

### The case

`20260728T161845Z-fresh-case`, a Falco `authorized_keys` write correctly disposed `malicious`.

**The current loop yields nothing on it.** A malicious disposition routes to the FP hunt, and no
benign story survives an SSH key whose comment is literally `attacker@elsewhere`.

**A directly applicable lesson existed and did not retrieve.** The corpus holds a lesson stating
that `loginuid=-1` licenses "non-interactive automated context" and nothing more, and that origin
claims require ancestry Falco cannot supply. Two lessons loaded for this run; that was not one of
them — it is keyed to `v2-falco-suspicious-network-tool`, a different rule.

**Training would grade it a clean win.** The disposition was right and rests on one thing: the key
comment. Each other support is an artifact of the environment. `loginuid=-1` is how the scenario
runner executes anything. "Host absent from CMDB" holds for every container case. And the
co-occurring `nc` events reported as a multi-stage attack chain are the baseline scheduler's
`monitoring-port-probe`, which `hosts/base/baseline/catalog.yaml` generates as `category: noise`
to fire that exact rule. **The shipped report asserts an attack chain that did not happen.**

### The turn-N experiment (2026-08-16)

Forked the case at message 59 — the `ModelRequest` carrying all four leads' returns, 13 hydrated
prefix messages — and resumed it in two sibling worlds differing only in whether the `nc` activity
has a recurring cadence outside the alert window (world A: it does, matching the real playground;
world B: it does not).

**Result: `ΔW` ≠ ∅, `ΔO` = ∅, `ΔT` = ∅.** Neither run dispatched a single `gather` — post-fork
tools were `read_file`/`append_block`/`close_investigation` only, and the world-serving stub was
never called in either. Both closed `malicious`. Both were ratified.

Three arms, one case:

| Arm | Output |
|---|---|
| Turn-N pair | A typed finding: the trajectory never queried the system holding the discriminator |
| Runtime reviewer | `stands` — "the challenge review ran and left nothing about the finding unsettled" |
| Learning loop (actor→judge) | `SKIP`. No story, judge never invoked, no findings |

The composer ratified while citing the fabricated chain as *"one of three discriminating
refutations"*, and reported the ablation lens as *"confirming the disposition does not rest on any
single edge"* — the failure mode named in §Runtime review, observed. It also reproduced the corpus
inversion above: *"an empty array from a responding system is evidence of absence."*

**The wiring cost was near zero.** `store_factory` is already an injection seam and the render
processor rebuilds history from the store each request, so a store whose `new_session("main")`
returns `fork(main, at=59)` resumes the run — no driver change. One real defect surfaced:
`fork()` seeds `last_render_len` to the inherited prefix length while a fresh `agent.iter` starts
the framework's list empty, so `selection.ingest` underflows unless the prefix is passed as
`message_history`. `fork()` had no production caller before this.

**Caveats.** One trial per world. The continuation prompt said "close it when the evidence supports
a disposition," which biases toward closing over gathering — identical in both worlds, so the A/B
contrast holds, but "never asked" is partly the prompt's doing. The judge arm needed
`DEFENDER_BOX_RUNTIME=runc`, and ran with the playground down and an empty ticket pool, which may
have contributed to the SKIP. World A's cadence rows were hand-authored; a captured base removes
that authorship.

### Cheap fixes, independent of everything above

Make the judge's likelihood-ratio check symmetric (it runs only on benign dispositions; on a
malicious call it should ask whether the incriminating observables fit routine automation equally
well). Re-key observable-semantics lessons off the alert signature, minding that the two corpora
disagree on rule-id namespace (`v2-…` versus `rule-v2-…`) — done for the defender corpus in #919.
(The selector specificity floor listed here was deliberately NOT built; see above.)
The first fix inherits a caveat: an actor SKIP bypasses the judge entirely — the story is persisted
with `judge_yaml=None` — and on this case SKIP is the outcome, so persist *and judge* the rationale.

## Sequencing

1. **Held-out recruitment** — separate session, blocking every metric here.
2. **The cheap fixes above** — prompt edits and a selector floor, no architecture.
3. **Frontier retrieval.** Give the invlang advisory a lessons recall class (reusing the
   environment corpus's containment matcher), extend its frontier from open hypotheses to `??`
   slots, and derive it mechanically per gather loop.
4. **Turn-N branch wiring.** Promote the throwaway resume seam: a supported entry point that
   takes a session and a branch message, the `last_render_len` fix, and the capture format for a
   base plus a mutation. The scenario-spec spike the first draft called its largest unknown is
   deleted — state is captured, not authored.
5. **Pair authoring and the consistency check** — worlds proposed against the payload prefix,
   forward reachability, and both siblings run.
6. **Wire the shipped reviewer to the actor-side corpus**, add the typed concession, and give
   `inconclusive` its missing-source claim.
7. **Lesson attribution in shadow mode.** #695's stable identity and loaded/applied/decisive
   sidecar without changing retrieval order. Also the forward-check's retirement point.
8. **Paired ablation and probe siblings.** Establish causal lift before any score affects promotion.
9. **Menu-driven scenario selection and controlled mutation**, once the validity gates and the
   archive are trustworthy.

**Execution against a live estate** stays out of this sequence. It would delete the oracle
entirely and make solvability empirical, and `playground-v2/attacks/` already has the runner — but
it needs deterministic snapshot-restore per sibling for A/B invariance, and it gives events cheaply
and *state* expensively, which is the inverse of what the ambiguity requires. Revisit as a platform
bet after turn-N is measured.

## Open questions

- **Capture format for a base plus a mutation.** Smaller than the old spec question, not zero.
- **Which mutation dimensions may vary independently**, and which must stay coupled to preserve
  realism — the same question as the technique menu's variant axes.
- **How far outside the stated frontier** a proposed world may go before "consistent with the
  evidence" stops being a meaningful constraint.
- **Ablation execution.** Whether trusted counterfactual replay suffices for lesson lift, or paired
  fresh runs are required for promotion-grade evidence.
- **Replication budget and promotion threshold**, given stochastic runs.
- **Does the runtime reviewer see the defender's reasoning, or only its conclusion and the lead
  results?** Seeing it risks ratification; not seeing it wastes the `:T resolutions` belief trace.
- **Where the sufficiency verdict lives.** Runtime review produces an earned / unearned /
  underdetermined judgment per case that needs no labels and runs on every real investigation — the
  only quality signal that moves between held-out evaluations, and currently homeless.
- **What the actor-lesson promotion bar concretely tests.** "Same bar as defender lessons" does not
  type-check — causal lift is defined over defender behavior. The production-facing reviewer half
  has no metric, and likely shares a home with the sufficiency verdict.
- **Retirement path for the current review pipeline's artifacts.** 16 lessons, 12 actor lessons, 15
  environment facts were authored under the old warrant. Re-derived, grandfathered, or re-keyed?
