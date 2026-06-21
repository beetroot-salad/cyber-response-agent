# Lessons success scoring — design draft (2026-05-30)

Companion to `defender/learning/actor_benign.md` / `actor.md`,
`defender/scripts/lessons/lessons_env_retrieve.py` / `lessons_actor_index.py`,
and the task `tasks/benign-actor-success-retrieval.md`. Captures the
design discussion behind adding a success/usefulness signal to the
actor-retrieved lesson corpora. The benign (FP) direction —
`lessons-environment/` — is the worked case; §4 mirrors it to the
malicious (FN) direction — `lessons-actor/` — and §5 factors out the
shared helpers.

Status: **design draft, not implemented.** Both corpora ship retrieval by
classification only (env: entity `{type,class}` + `alert_rule_ids`; actor:
`techniques` + `alert_rule_ids` + `defender_lead_tags`); lessons carry no
`confidence`/`wins`/score fields. Authors exist on both directions
(`author_actor_benign.{md,py}` → `lessons-environment/`;
`author_actor.{md,py}` → `lessons-actor/`); the env corpus is seed-only
because the loop hasn't been **run enough to populate it**, not for lack
of an author. When this doc and the code disagree, the code wins.
Everything here is downstream of the premise A/B in the task file — if
classification retrieval doesn't measurably improve the actor's story,
none of this matters.

---

## 1. Problem

The benign (ops-teamer) actor reconstructs the routine operation behind an
alert to expose false positives. It retrieves `lessons-environment/`
lessons — standing deployment facts — by classification overlap with the
case (entity selectors + rule id). Retrieval is pure relevance match, no
ranking.

The proposal: add a **success signal** so that lessons which contributed
to a confirmed false positive are preferentially retrieved — a
self-reinforcing corpus where lessons that earn their keep rise. Two
sub-problems the naive version runs into:

- **Credit assignment.** A story may lean on several retrieved lessons.
  Attributing a "win" to a specific lesson is hard, and the actor reads
  lessons *silently* (`actor_benign.md` forbids citing lesson ids in the
  story — the citation would leak corpus structure into what the judge
  sees). So the story carries no trace of which lessons were load-bearing.

- **Promotion-signal safety (load-bearing).** A benign story "wins"
  (survives the judge) in two cases: a genuine FP, **or** a real attack
  the actor mislabeled benign that the defender under-investigated.
  Rewarding bare survival therefore optimizes the corpus to **make
  true-positives look benign** — it injects false-negative risk directly
  into the actor's learning signal. This is the opposite of the
  zero-false-negative goal.

## 2. Principles

1. **The win signal must be confirmed-correct, never bare survival —
   but "confirmed" is a *calibrated judge*, not a per-win oracle.**
   Requiring held-out ground truth for every promotion (the strict reading)
   starves the win signal to near-zero and makes learning unscalable.
   Instead, trust the abundant judge, and use the scarce held-out set to
   *measure* it. Three trust tiers, not two:
   - held-out `ground_truth.yaml` → **full-weight** win (unimpeachable);
   - calibrated-judge "confirmed FP" → **discounted-weight** win, the step
     sized by the judge's measured confirm-precision;
   - bare survival → **zero** (it conflates genuine FP with masked TP).

   The load-bearing risk lives in the judge's *false-confirm rate* (says
   "genuine FP" when it is a masked TP), which is the hardest rate to
   measure because masked-TP cases are rare and adversarial. So the golden
   set must be **enriched with the hard masked-TP / hard-benign slice** —
   calibrating on easy cases yields a falsely high TNR. This is the
   `validate-evaluator` discipline (TPR/TNR on the slice that matters), and
   it is what makes "trust the judge" safe rather than hand-wavy. Held-out
   thus serves twice: a full-trust win tier *and* the calibration anchor
   that licenses trusting the abundant judge at a discount.

2. **Separate the two stages that naive scoring collapses.** The *update
   rule* (how a lesson's score moves) is where **safety** lives. The
   *selection rule* (who gets retrieved) is where **curriculum** lives.
   Pessimism belongs in the first, not the second.

3. **Optimize the defender's curriculum, not the actor's regret.** The
   goal is the most robust defender, which wants a *diverse, hard, genuine*
   set of FP stories — a coverage objective. Greedy best-arm retrieval
   gives a narrow, repetitive curriculum and is the wrong target.

4. **Score is a secondary axis.** The entity/rule filter stays primary and
   gates relevance; the score only ranks *within* the filtered set. A
   high-success lesson irrelevant to the case must never crowd out a
   relevant one, and at current corpus scale (single-digit lessons, no
   over-return) the score is a near-no-op — which is why the plumbing can
   land early and stay dormant on the ranking side.

5. **Curation is the primary consumer, ranking the secondary one.**
   Retiring a wrong lesson removes FN risk directly and pays off at small
   scale; re-ranking only matters once retrieval over-returns. Frame the
   signal as feeding author/retire first.

## 3. Solution

A **safety-pessimistic contextual bandit**, with the two stages split:

**Credit assignment — actor self-rating.** The actor emits a per-lesson
**useful / not-useful binary** in a separate output trailer (not in the
story body — the silent-retrieval contract is preserved, nothing leaks to
the judge). The actor rates *usefulness-to-construction* and stays **blind
to the outcome** (it never sees the judge); the **loop supplies the
win/loss sign** afterward. A binary is far more robust than a Likert from
an LLM. To denoise the self-report, **only count a not-useful when the
story also lost** (require two weak signals to agree).

The actor's narrow input — alert + classified `case_entities` + retrieved
lessons, with **no investigation, report, or lead list** — means a win
can't come from exploiting a specific investigation's gaps. The lessons
that accumulate wins encode *generically-plausible deployment facts*, not
judge-exploits. This narrows the residual FN risk (a generically-plausible
benign framing over a real attack) but does not remove it — hence
Principle 1.

**Update rule (safety).** Asymmetric, loss-averse, and gated on run
validity + attribution:
- `Δ_win`: small, **gated** on confirmed-correct (tier-weighted per
  Principle 1).
- `Δ_loss`: larger, fires on a **valid, attributed** loss — the story
  lost *and* the actor marked the lesson useful (the not-useful+loss
  conjunction). Errs toward a more conservative actor → more escalation →
  the safe direction.
- not-useful, or loss on a lesson the actor did *not* mark useful
  (unattributed): no change.
- **No-update state** (neither win nor loss): run-invalid conditions —
  timeout, degraded dependency, inconclusive adjudication, oracle/judge
  error. A degraded run must not move any score.

A lesson needs many gated wins to climb and few attributed losses to fall,
so a lucky-early lesson regresses instead of locking in. **Retirement**
(pruning, below) requires a *minimum evidence threshold* on top of the
confidence bound — a couple of attributed losses cannot retire a lesson;
it takes sustained negative evidence plus curator review. This addresses
the adversarial-review concern that any-loss demotion could floor a true
environment fact for reasons unrelated to its correctness.

**Selection rule (curriculum).** Split the score's two jobs:
- **Pessimism for *pruning*, not ranking.** Retire / floor a lesson only
  when *confident it's bad* — e.g. its optimistic (upper) bound is still
  below a bar. A new lesson is never confidently bad (wide interval), so
  pruning **cannot starve a mid-game entrant**. This is also the curation
  consumer from Principle 5.
- **Exploration for *selection among survivors*.** **Thompson sampling**:
  each lesson has a Beta posterior; at retrieval, sample from each and rank
  by the draw. A new lesson with a wide posterior *sometimes* samples high
  and earns impressions, sits near its mean on average, self-anneals as `n`
  grows — no hard exploration knob, no top-k cliff. Stochasticity also
  breaks the deterministic rich-get-richer loop and gives the defender a
  varied curriculum across a batch.

So: **score is a floor (exclude confirmed-bad), not an order (rank the
good).** Safety in the gated update; pessimism in pruning; exploration in
selection.

**Anchor.** Co-evolution (student/teacher/judge — actor as generator,
defender as discriminator, judge as reward) self-corrects *only* with a
ground-truth anchor. Without one, actor and defender can co-evolve into a
shared blind spot (GAN-style mode collapse / reward hacking) and call it
convergence. The held-out `ground_truth.yaml` and the cross-case oracle
(`tasks/defender-learning-loop-cross-case-oracle.md`) are that anchor;
"the learning loop mitigates FN" and "gate promotion on confirmed-correct"
are the same claim from two ends.

## 4. Mirror to the malicious actor

The malicious (FN) direction — `actor.md` retrieving `lessons-actor/` —
takes the **same machinery** (self-rating trailer, asymmetric loss-averse
update, pessimism-for-pruning + Thompson-for-selection, calibrated-judge
trust tiers) but the win-gate protects the **opposite failure mode**, and
two structural differences make it the *more mature pilot surface*.

**The gate protects harness-overfit, not FN.** A malicious "win" is a
confirmed evasion (defender closed-benign a real attack). Promoting
lessons that produce *genuine* evasions is exactly what you want — it
makes the actor a stronger red-teamer and hardens the defender (the GAN
generator improving is the point; there is no FN-injection analog). The
risk is **phantom evasion**: a story scored as evaded because the
telemetry oracle under-projected or the judge missed, not because the
defender is genuinely weak. Promoting those lessons teaches tradecraft
that beats the *eval harness*, not the real defender — curriculum that
doesn't transfer. So the malicious win-gate's job is to reject
harness-artifact evasions, anchored by ground-truth-malicious **and the
telemetry oracle** (`oracle.md`, which already sits between actor and
judge and forces the story's real footprint to be projected).

**The malicious actor is *not* blind.** Unlike the benign actor, `actor.md`
sees `actor_input` — the defender's ordered query list — so it *can* tailor
to coverage. That makes its win-signal more gameable, which raises (not
lowers) the importance of the oracle anchor + calibration on this side.
The benign actor was partly protected by blindness; the malicious actor
has no such protection.

**It is the more mature surface.** `lessons-actor/` already has an author
(`author_actor.{md,py}`), a populated-by-design corpus, and a retrieval
index (`lessons_actor_index.py`) — whereas `lessons-environment/` is
seed-only pending loop runs. If we want to *pilot* success scoring on real
data, the malicious side has more of it. That flips the env-first
assumption in §6 sequencing for the pilot specifically.

**The golden set is two-sided.** Calibrating the judge (Principle 1)
requires confirmed-**benign** cases (to measure the false-confirm-FP rate
that protects the benign actor) *and* confirmed-**malicious** cases (to
measure the false-evasion rate that protects the malicious actor). One
held-out golden set, two calibration tables — an argument for designing
both directions together rather than bolting the mirror on later.

## 5. Shared helpers (high level)

Factor the corpus-agnostic bandit machinery into one module both
directions consume, mirroring the existing `_author_shared.py` precedent
(shared repo lock + per-direction generation counters; per-author queue
locks). Sketch — names illustrative, not committed:

**Shared core (`lessons_score.py`, corpus-agnostic):**
- **Score store** — per-`subject` (and per-`name` for subjectless pattern
  lessons) Beta posterior `(α, β)`. Keyed on the equivalence key, **not the
  filename**, so the score survives `supersede`/`stale` rotation.
- **Rating-trailer parser** — extract the actor's per-lesson
  useful/not-useful binary from the output trailer. Same grammar both
  actors; only the corpus path differs.
- **Outcome-trust resolver** — `(held-out?, judge verdict, oracle status,
  run validity) → {win | loss | no-update} + trust weight ∈ [0,1]`. This is
  where Principle 1's tiers and §3's no-update state live. Polarity selects
  which calibration table (benign-confirm vs. malicious-evade).
- **Update applier** — pure function of `(attributed-useful keys, label,
  trust weight) →` asymmetric loss-averse posterior update. Polarity enters
  *only* via the label the resolver already produced.
- **Ranker** — Thompson sample over posteriors for selection within the
  pre-filtered set, plus the UCB-floor prune for confident-bad retirement
  candidates.

**Per-direction adapters (thin):**
- **Win/loss labeling** — benign: win = confirmed FP, loss = caught /
  incoherent; malicious: win = confirmed evasion, loss = caught. Folded
  into the resolver via a polarity parameter.
- **Anchor source** — benign reads ground-truth-benign; malicious reads
  ground-truth-malicious + the telemetry oracle.
- **Retrieval filter + corpus path** — env uses entity+rule
  (`lessons_env_retrieve.py`); actor uses techniques+rule+lead_tags
  (`lessons_actor_index.py`). Both pre-exist; they would call the shared
  ranker for the within-set ordering.

Net factoring: the shared module *is* the whole bandit; the two corpora
differ only in (a) what labels a win, (b) where the anchor comes from, and
(c) the pre-existing retrieval filter.

## 6. Trade-offs and open questions

- **Self-rating reliability.** LLM self-reported feature importance is
  noisy (recency bias toward whatever it read last). The loss-confirmation
  conjunction (count not-useful only on a lost story) is the mitigation;
  whether it's enough is unverified.

- **Output-schema cost.** The rating trailer is a schema change. The token
  cost is trivial; the real risk is **introspection contaminating the
  story** — self-assessing mid-output may shift how Sections 1–2 are
  written. The A/B must measure *story quality* with vs. without the
  trailer, not just tokens, on a fixture where the variable is load-bearing.

- **Exploration vs. determinism.** Thompson selection occasionally feeds
  the defender a weaker FP (the price of not starving new lessons) and
  makes retrieval non-deterministic across runs. For a curriculum
  generator, diversity is a feature; reproducibility costs a seed. The
  expensive failure is the opposite (LCB starvation permanently hiding a
  class of genuine FPs), so the trade runs toward exploration — but *how
  much* diversity vs. determinism is a product call.

- **Held-out scarcity bounds the *full-trust* win signal.**
  `ground_truth.yaml` exists almost only on held-out runs. Under the strict
  reading that would starve promotion; the calibrated-judge tier
  (Principle 1) is what relieves it — held-out sizes the discount, the
  abundant judge supplies the volume. The residual bound is on calibration
  *confidence*, not on win count.

- **Calibration golden-set representativeness (load-bearing).** The
  discounted-judge tier is only as safe as the golden set is representative
  of the hard slice — masked-TP / hard-benign on the FP side, catchable-
  but-evaded on the FN side. A golden set skewed to easy cases yields a
  falsely high confirm-precision and reopens the failure the gate exists to
  close. Enriching the golden set for the adversarial slice is the real
  work behind "trust the judge."

- **Premature at current scale.** Ranking is a no-op until retrieval
  over-returns, which it doesn't yet. Land schema + rating capture early
  (cheap, starts accruing loss-signal), keep ranking dormant, and let
  curation be the first real consumer.

## 7. Dependencies / sequencing

1. **Premise A/B (gates everything).** Seed-one-lesson: does feeding a
   matching lesson to the actor produce a more grounded story than
   withholding it? If not, stop.
2. **Corpus volume, not author code.** Both authors exist
   (`author_actor_benign`, `author_actor`); the env corpus is just
   unpopulated. The dependency is *running the loop* enough to fill the
   buckets — and for a pilot, the malicious side (`lessons-actor/`) already
   has volume + an index (§4), so pilot there.
3. **Judge calibration on a two-sided golden set** (§4) — measure
   confirm-/evade-precision before any positive update is trusted.
4. **Schema + rating-trailer capture** — cheap, dormant ranking, accrues
   loss-signal. Measure story-quality cost delta.
5. **Curation consumer** (author/retire on the signal) — first real use.
6. **Thompson selection** — only once buckets routinely over-return.
