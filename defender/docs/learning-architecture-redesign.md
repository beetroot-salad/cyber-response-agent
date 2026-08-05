# Learning architecture — redesign (2026-07-30)

## Status

**Design, pre-implementation.** Nothing here is built. Amends the loop shape in
`learning-loop.md` and absorbs the deferred pointers in
`learning-loop-actor-learning.md` (learning actor) and `learning-loop.md`
§Future Enhancements (live self-evaluation). When this ships, those sections get
rewritten rather than cross-referenced.

Held-out fixture recruitment is a **prerequisite for measuring any of this** and
is being handled separately. Every metric below is uncomputable until it lands.

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
held-out ledger. Move it to a generated world and the scenario spec becomes the
answer key.

## The three components

### 1. Training loop — student / questioner / reviewer

The **questioner** (today's actor) generates a scenario. The oracle synthesizes an
alert from the deployed detection rules, then serves every world-facing query the
defender issues. The **student** (the runtime defender) investigates it as an
ordinary case. The **reviewer** (today's judge) grades against the scenario's known
ground truth and composes lessons for *both* players.

This is where learning happens. The answer key is known by construction, so
findings carry a warrant the current loop cannot supply.

### 2. Frontier-keyed lesson retrieval

Lessons are retrieved by containment over the **invlang frontier** — the shape
of what is currently unresolved — rather than by alert signature. See §Retrieval for
the two consequences that decides.

### 3. Runtime adversarial review

Each live investigation is challenged before it closes, by a distilled
counterfactual reviewer that reads the same actor-side corpus the questioner does.
Review is no longer a learning stage; it is a per-case quality gate.

## What the oracle becomes

The oracle serves **every** `query()` call — lookups included, not just log
queries. Its ledger is the **family base world** (§Contrast families): pinned
state facts plus a base event log, generated once per family. A sibling owns no
events of its own — serving a query in sibling B means reading the base and
applying B's declared mutation set.

Laziness survives in exactly one place. A query that reaches unmaterialized
territory may generate it — into the **base**, once, family-scoped — under one
rule: lazy generation never touches an entity named in the discriminator or in
any sibling's mutation set. Those regions exist before the run anyway, because
the solvability pass has to walk them to derive the resolving path; lazy was
only ever available for decoration.

If the oracle decides state lazily, it authors the case's verdict mid-run and can
contradict the answer key it is being graded against. Per-sibling lazy events
fail differently but as badly: siblings inventing their own background make
every observation diff carry junk beyond the intended difference, and the junk
correlates with disposition — a tell the defender can learn.

**Consistency is the load-bearing risk, not fidelity.** The defender's whole
method is corroborating one system against another and pivoting on values it got
from an earlier answer. A world that contradicts itself across a run teaches it
that corroboration is noise. The memoized ledger is the whole implementation of
that guarantee; there is nothing else holding it up. One seam fact belongs next
to that: the query seam's verb registry falls back to the real adapters when no
override is threaded, so a missed hook in a training run silently answers from
the real playground. The training hook must fail closed.

**"Telemetry" undersells the spec.** Seven systems of record sit behind the typed
query tool and only one is an event stream. A scenario that synthesizes events and
lets identity / CMDB / change-mgmt / ticket / threat-intel answer from the real
world produces a host unknown to inventory and no CR for anything — and the
defender learns "no CR means malicious." The ambiguity that makes a case hard
lives in the state, so the state is the substance of the spec, not a detail of
it. The oracle golden set says the same from the other side: state and lookup
leads are already its largest label class, and the current oracle only ever
answers them with "unchanged" — state *synthesis* is the slice with zero
calibration precedent.

**Scenario solvability must be proven, not asserted.** The questioner authors both
the world and the answer key, so it can produce a case no query path resolves —
and the reviewer will still grade the defender against it. Reality supplies
solvability for free in a real case; here it is a pre-run obligation. The pass
that proves it is the same pass that derives the resolving path, and it must
derive that path **from the world, never accept it from the questioner** — the
golden set's rule ("a label may be corrected from the environment, never from the
projection") reappearing one level up.

**Alert realism is bounded by rule coverage**, which is correct — triage only ever
sees what fired — but it means the training loop structurally cannot produce
observability findings. Every scenario begins from something the detection stack
caught. It can teach "you saw this and reasoned wrong"; it can never teach
"nothing would have told you."

## The compare suite — discriminator spine

Every scenario names its **discriminator**: the predicate whose value separates
the dispositions, the value it takes in each world, which system holds it, and
the permitted query envelope through which the defender can establish it. The
declaration is the questioner's falsifiable claim about its question, not an
answer the harness trusts. Before a run, the solvability pass derives the
resolving path from the world ledger and verifies that the declared discriminator
is both disposition-changing and reachable. A mismatch is a questioner finding
or a `discard`, never a defender failure.

The reviewer's context is spined on these **discriminating facts** — one row per
fact that must be established to resolve the case — not on the leads the defender
ran. Today's spine is defender-authored, which is why anything about the
questioner has to be reasoned in from the side. On a discriminator spine, each
row carries:

- the predicate and its value in each sibling world;
- the system and query envelope that expose it;
- the expected oracle-observation difference;
- whether and when the defender's trajectory touched it; and
- what the defender concluded after receiving it.

This creates three diffs the reviewer can compare directly:

- **world diff (`ΔW`)** — the sibling's mutation set: the intended difference,
  a literal diff rather than prose;
- **observation diff (`ΔO`)** — the difference the oracle actually exposed; and
- **trajectory diff (`ΔT`)** — the defender's changed investigation and verdict.

Root-cause attribution then mostly falls out of the comparison. A `ΔW` with no
reachable `ΔO` is an invalid question. An unexpected `ΔO` outside `ΔW` is an
oracle or harness leak — and with `ΔW` a literal diff, that check is code, not
judgment. Never querying the holding system is a lead-set gap;
querying it at the wrong scope is lead-quality; receiving the fact and reasoning
past it is analyze-discipline; establishing the fact without the warranted
disposition change is decision discipline. The reviewer names the gap; it does
not have to reconstruct it from prose.

The questioner also declares where it expects the defender to fail. The
trajectory confirms or falsifies that prediction. Failure somewhere else means
the scenario was hard by accident; cheap resolution means it was too easy.
Cost-to-reach is a second axis, making questioner scoring a gradient rather than
a coin flip and restoring the falsifiability the blind actor used to provide.

A `discard` verdict is required (no current outcome enum has one). If the oracle contradicted the spec or an
earlier answer, the episode teaches nothing about either player and blaming one
is worse than dropping it. Most contradictions are detectable mechanically
against the ledger and belong upstream of the reviewer, but the reviewer needs a
verdict for corruption discovered during comparison.

## Contrast families and curriculum search

The discriminator makes one scenario gradeable. It does not tell the questioner
which scenarios teach well. That signal comes from a **contrast family**: one
**base world** — pinned state plus a base event log, generated once — and one
declared **mutation set** per sibling. A sibling *is* base + diff; it owns
nothing else:

- **A — benign anchor:** one value of the discriminator;
- **B — malicious minimal twin:** the opposite value and nothing else — its
  mutation set is the minimal diff; and
- **C — probe sibling:** preserves the underlying distinction while changing one
  mechanic, or moves one controlled step toward the decision boundary.

The mutation set is what makes the family well-defined rather than three
stories sharing a premise. `ΔW` *is* the diff. Minimal-twin invariance is
mechanical — everything outside the mutation set is identical by construction,
not an obligation the questioner has to honor. "One controlled step" for C
means one mutation. Auditing for unintended tells reduces to reading a small
diff instead of comparing two freely generated worlds.

A/B makes attribution cheap: the reviewer knows exactly what should change and
what must remain invariant. C tests transfer. A defender that succeeds on B and
fails when the same principle appears through a different process, identity,
timing, or authorization mechanism learned the story's surface rather than its
rule. A boundary sibling tests calibration rather than surface invariance. The
third sibling's disposition may be sampled, but its mutation role and expected
effect must be declared; an arbitrary third story restores the confounding that
the minimal pair removed.

Three is a bootstrap, not an architectural limit. The questioner can generate a
small brood of controlled siblings, retain useful mutations, and continue from
them. Its mutation vocabulary should come from established attacker frameworks
and environment bindings: technique variant, execution mechanism, identity,
timing, cover activity, and authorization state. This is curriculum evolution,
with the base world plus each sibling's mutation set acting as the genome and
the validated ledger as the phenotype.

Selection must not reward whichever child defeats the defender most often. That
converges on unobservable questions, gratuitous ambiguity, oracle quirks, and
judge exploits. Validity, oracle consistency, solvability, and absence of
unintended tells are hard gates. Among scenarios that pass them, prefer an
**informative failure near the defender's frontier**: the intended gap is exposed,
the resolving path is affordable, and the resulting lesson improves later
behavior.

Complexity is controlled primarily by matched descent, not by pretending every
story has a reliable universal difficulty score. Compare a child with its parent
or siblings when only one mechanic changed — mutation-set edit distance is the
metric matched descent was missing. When cross-family normalization is
unavoidable, use structural investigation cost:

- minimum oracle calls on a resolving path;
- systems, entities, and temporal joins required;
- reasonable hypotheses that must be eliminated; and
- irrelevant observations that must be traversed.

Text length and number of decorative facts are not complexity. Defender cost can
then be expressed as excess work over the derived resolving path, alongside
disposition correctness and whether the discriminator was reached. Because model
runs are stochastic, no scenario or lesson is promoted from one tournament.
Evaluation uses repeated runs and a held-out sibling/archive so the questioner
cannot overfit the current defender snapshot.

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
contrast family with and without the lesson available (or use a trusted
counterfactual replay), then evaluate withheld siblings. The useful quantity is
not raw failure rate but **causal learning lift**:

> improvement attributable to the lesson in disposition accuracy, discriminator
> reach, and investigation cost, without regressions on the opposite-disposition
> siblings.

This yields two separate fitness signals:

- **question fitness, before learning:** did a valid and affordable scenario
  expose the intended defender gap?; and
- **lesson fitness, after learning:** did the lesson close that gap and transfer
  across mechanics without creating benign false positives?

The operational pipeline is therefore: #695 attribution nominates; paired
ablation estimates causal lift; probe siblings test generalization; held-out
performance controls promotion and retrieval rank. Scenario evolution may use
attribution as a prior or exploration weight, but only replicated causal lift is
an effectiveness result.

## Retrieval — frontier keying

Two consequences, both load-bearing.

**Retrieval must run per gather loop, not once at PLAN.** A lesson about what a
field does and does not license is only relevant once the field is in hand. See
§Empirical grounding: in the case we examined, the process class was still `??`
when lessons loaded, so no keying scheme could have surfaced the applicable lesson
at that moment. Frontier keying that still fires once buys much less than it looks
like.

**Match by containment, not by similarity score.** The frontier has structure —
typed slots with `??`, plus the open hypothesis set (the invlang CLI already
calls the latter "frontier"; here the word means both) — so a lesson declares
the pattern it applies to and matching is mechanical, fewer slots matching
more. This is assembly, not construction: the invlang advisory verb already
does frontier-keyed recall (signature anchor plus open hypothesis names,
composed precedent back), and the environment corpus already matches by
slot-wise selector containment. (The oracle router this section once cited as
precedent is gone — deleted with the per-lead baseline-diff oracle; containment
survives there only as a prompt instruction.)

Three gaps close it. The advisory recalls precedent *cases*; lessons need
selectors and become a recall class. Its frontier is hypothesis names only —
`??` slots are explicitly out of its scope today, and the motivating case's
frontier item is exactly slot-shaped, so hypothesis keying alone still misses
the loginuid lesson. And the frontier is model-supplied at the prompt;
per-gather-loop retrieval derives it mechanically from the investigation file,
which the parser and validator already know how to do. One guard: selectors
need a specificity floor — fewer-slots-matching-more makes an empty selector an
every-loop lesson.

**The schema defect this fixes.** Lessons currently key on the alert signature
they were born from. That is right for coverage lessons and wrong for
observable-semantics lessons, whose trigger condition has nothing to do with which
rule fired.

## Runtime review

**The failure mode is agreement.** A reviewer holding the defender's context
ratifies it. What makes it real is instantiating it on the **counter-disposition**
and requiring a committed output: a concrete discriminating query, or an explicit
concession that none exists. Prose is not an output.

**Exactly two allowed actions:** spawn one more lead, or force the disposition to
`inconclusive`. Anything else is decoration, and anything unbounded collides with
budget enforcement — a review-triggered loop needs a cap and a budget line, or a
hard case silently becomes an expensive one.

**A concession is an output, not an exit.** It persists, typed: the
counter-story, the observed fact that kills it, and the load-bearing inferences
the case never tested. On the case in §Empirical grounding it is the *only*
thing review produces — the benign twin dies on the key comment, neither action
fires — and the killing fact is exactly what the generator mutates to build the
twin. Without it, seeds flow only from cases where review acts, which excludes
the correct-but-unsound class the whole split rests on.

**This deletes design principle #1.** "Offline only. No live latency cost" was
load-bearing enough to be first in `learning-loop.md`. We are now paying review
cost on every investigation. Worth it, but it is an explicit trade, not something
a reader should discover.

## One corpus, one role

The questioner and the runtime reviewer are the **same role**: both construct a
plausible alternative story. The reviewer is a questioner with a narrower prior —
constrained to the case in hand. "What worked as an attack" and "what to check"
are the same content read by the same kind of reader, so there is one actor-side
corpus, one selector mechanism, and no view split.

Two consequences.

**Runtime review recruits the curriculum for free.** Its output is a
counter-disposition story anchored on a real alert, real entities, and a real
frontier shape — exactly what the training questioner wants as a seed.
Concessions included: on clear-cut cases they are the only output, and they
carry the mutation target. No separate seeding pathway is needed.

**The flow runs both ways, so it self-anchors.** Lessons moving generator→runtime
pull the live reviewer toward synthetic attack shapes; seeds moving
runtime→generator pull the curriculum back toward real alert surfaces. That is
the real-alert anchor among the Red Queen mitigations `learning-loop.md` asks
for, falling out of the architecture rather than bolted on. Of the other two,
the frozen-actor replay is replaced better-typed in §What dies, and the fixed
regression suite of historical attack shapes survives only by folding into the
frozen scenario archive — it has no other home here.

**The cost of merging** is that a wrong tradecraft lesson now skews the curriculum
and the live challenge in the same direction, with nothing left to cross-check it.
Actor lessons become production-facing: until now a bad one only made synthetic
stories worse. They need the same promotion bar as defender lessons, not a lighter
one.

One reader genuinely has no frontier to match on: the training questioner writes
its scenario *before* an alert exists, so it retrieves against the detection
surface rather than unresolved slots. Same corpus, same selectors — worth knowing
when picking selector defaults.

## What dies, what transfers

**The frozen-actor secondary metric dies.** It needs a blind actor emitting
falsifiable projections. Its replacement is better-typed: real-held-out
disposition accuracy against synthetic-scenario disposition accuracy. The current
pair compares accuracy against catch rate — two different units, which is why the
divergence diagnostic reads as a vibe. Same unit on both sides makes the gap
directly the overfitting-to-simulator number — provided the synthetic side is
measured on the **frozen scenario archive**, never the live curriculum.
Selection deliberately holds the defender near informative failure, so
live-curriculum accuracy is depressed by design and the gap would measure
curriculum pressure instead. The archive doubles as the home for historical
attack shapes (§One corpus).

Note the exposure this creates: real-case runs now consume actor lessons distilled
from synthetic worlds, via the runtime reviewer. The gap still measures cleanly
(both sides run the same reviewer), but the surface through which simulator
artifacts reach real conclusions is wider than it was.

**The oracle golden set re-aims rather than pausing.** What a serving oracle needs
measured is "does the world I served match a real capture of this activity" — what
that apparatus already does. The envelope measurement survives (containment was
never a measured quantity there). The four-class baseline-diff labeling already
half-died — retired as the scoring contract, kept as a stratification axis —
and the rest goes with the projection. The in-flight capture campaign should be
re-pointed, not stopped.

**The forward-check retires late, and is not replaced by a birth gate.** It
guards a rare failure — a lesson flipping its own source case. The live risk is
the one it never tested: over-generalization downgrading the
opposite-disposition sibling. No cheap birth gate covers that — checking it
means re-running the defender with the lesson loaded, which is already half of
paired ablation — so behavioral quality is the learning process's job (later
families, attribution, ablation), not a gate's. Birth-time validation shrinks
to two free checks: a curator fold must preserve the gap the lesson was born
from, and a selector must be satisfiable by its source case's prologue (the one
mechanical job the forward-check does that nothing else does). The retirement
point is lesson attribution landing (§Sequencing): a sibling downgrade is only
attributable once lesson loading on family runs is observable. Until then the
forward-check stays.

**Real cases stop being a lesson source — except through review.** Today every
lesson, environment facts included, is born from the judge reading a real run.
The training reviewer only ever sees synthetic worlds, and an environment fact
authored there describes the questioner's invented deployment — folding it into
the corpus poisons the well the questioner drinks from. So the curators stay
offline and re-point: their real-case input is the runtime-review artifact
(challenge, concession, killing fact), which is also where environment facts
keep being born from the real world. The training reviewer's lessons are about
the players, never about the environment.

**Unchanged and reused:** the runtime defender and its phase discipline, the
permission gate, the seven adapters and the typed query seam (one interception
point; verbs return plain JSON values — the two ticket verbs that return bare
strings do so as the answer-key defense, and a serving oracle must preserve
that), the two tables and their join surface, the curators, the
drain/worktree/PR machinery, and the lessons corpora themselves.

## Empirical grounding

Two findings from `20260728T161845Z-fresh-case`, a Falco `authorized_keys`
write correctly disposed `malicious`.

**The current loop yields nothing on it.** A malicious disposition routes to the
FP hunt, and no benign story survives an SSH key whose comment is literally
`attacker@elsewhere`. Skip or incoherent. A whole disposition class is silent.

**A directly applicable lesson existed and did not retrieve.** The corpus holds a
lesson stating that `loginuid=-1` licenses "non-interactive automated context" and
nothing more, that container init and cron produce an identical profile, and that
origin claims require ancestry Falco cannot supply. Two lessons loaded for this
run; that was not one of them — it is keyed to the signature it was born from, a
different rule. The investigation then inferred "no authenticated session
initiated this process — classic remote execution pattern," and separately
recorded that no parent process was captured, and reasoned past it.

That defect is the shape of thing this redesign has to handle, and it lands in an
awkward place:

- **Training grades it as a clean win.** The disposition was right, and rests
  on one thing: the key comment literally reads `attacker@elsewhere`. Each
  other support is an artifact of the environment rather than a fact about the
  adversary. `loginuid=-1` is how the scenario runner executes *anything*,
  benign included. "Host absent from CMDB" holds for every container case,
  because Falco reports the Docker host while the logical host (`canary-1`) is
  registered — the defender queried the wrong entity and read the null as
  incriminating. And the co-occurring `nc` events it reported as a multi-stage
  attack chain belong to the baseline scheduler, which generates them
  `category: noise` to fire that exact rule against that exact host. **The
  shipped report asserts an attack chain that did not happen.** Outcome grading
  sees none of this, because the disposition matched.
- **Review cannot prove it either.** It can only say the inference is unsound. The
  proof is generating that twin and watching the defender escalate.

So: **review nominates on real data, the generator falsifies.** Neither half gets
there alone. This is the concrete instance the whole split rests on.

**Two cheap fixes available now, independent of everything above:** make the
judge's likelihood-ratio check symmetric (it currently runs only on benign
dispositions — on a malicious call it should ask whether the incriminating
observables fit routine automation equally well), and re-key
observable-semantics lessons off the alert signature (minding that the two
corpora disagree on rule-id namespace). The first fix inherits a caveat: an
actor SKIP bypasses the judge entirely, and on this case a SKIP is the likely
outcome — so the symmetric check catches this run only if skips stop
short-circuiting the episode. Skips are a valid path and carry a rationale
nothing currently reads; persist and judge it — the same discipline §Runtime
review demands of a concession.

## Sequencing

1. **Held-out recruitment** — separate session, blocking every metric here.
2. **The two cheap fixes above** — prompt edits, no architecture.
3. **Frontier retrieval.** Assembly, not construction: give the invlang
   advisory a lessons recall class (reusing the environment corpus's containment
   matcher), extend its frontier from open hypotheses to `??` slots, and derive
   the frontier mechanically per gather loop instead of trusting the model to
   restate it. Independent of the training loop; the real fix behind cheap fix
   #2's stopgap re-key.
4. **Scope the scenario spec format** — now concretely: the base-world ledger
   and the mutation-set encoding. Pinning state across seven systems is the one
   part with no precedent in the tree. Worth a spike before committing to the
   rest of the training loop.
5. **Training loop.** Ledger and hook first (single seam, failing closed), then
   solvability / resolving-path derivation, then the reviewer's discriminator
   spine and A/B anchor pairs.
6. **Runtime review**, once there is an actor-side corpus worth reading.
7. **Lesson attribution in shadow mode.** Land #695's stable identity and
   loaded/applied/decisive sidecar without changing retrieval order. This is
   also the forward-check's retirement point (§What dies).
8. **Paired ablation and probe siblings.** Establish causal lesson lift before
   any attribution score affects promotion.
9. **Curriculum search.** Add controlled mutation, tournaments, and score-informed
   retrieval only after the validity gates and held-out archive are trustworthy.

## Open questions

- **Scenario spec format for systems-of-record state.** The largest unknown.
- **Mutation catalog and family policy.** Which framework-backed dimensions may
  vary independently, and which must remain coupled to preserve realism?
- **Cross-family cost calibration.** Matched siblings avoid most normalization;
  the remaining question is whether structural resolving-path cost is stable
  enough to compare unrelated families.
- **Ablation execution.** Whether trusted counterfactual replay is sufficient for
  lesson lift, or paired fresh runs are required for promotion-grade evidence.
- **Replication budget and promotion threshold.** Enough to avoid selecting on
  model noise without making every curriculum generation prohibitively costly.
- **Does the runtime reviewer see the defender's reasoning, or only its
  conclusion and the lead results?** Seeing the reasoning risks ratification;
  not seeing it wastes the `:T resolutions` belief trace, which is where
  analyze-discipline defects are visible.
- **Where the sufficiency verdict lives.** Runtime review produces an
  earned / unearned / underdetermined judgment per case that needs no labels and
  runs on every real investigation. That is the only quality signal that moves
  between held-out evaluations — but it is currently homeless.
- **What the actor-lesson promotion bar concretely tests.** "Same bar as
  defender lessons" does not type-check — causal learning lift is defined over
  defender behavior. The questioner half has question fitness; the
  production-facing reviewer half has no metric, and likely shares a home with
  the sufficiency verdict above.
- **Retirement path for the current review pipeline's artifacts.** 16 lessons, 12
  actor lessons, 15 environment facts (templates excluded) were authored under
  the old warrant. Do they get re-derived under the new gate, grandfathered, or
  re-keyed only?
