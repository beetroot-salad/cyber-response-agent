# Actor-learning workstream — design (2026-05-11)

Companion to `learning-loop.md` and `learning-loop-actor-design.md`.
Activates the deferred *actor self-learning* pointer from that doc.

Status: **design, pre-implementation.** Specs the loop, the new
corpora, the metric, and the prerequisites. Code lands in subsequent
PRs against this branch.

## Motivation

The deployed loop has a structural asymmetry that guarantees a
plateau: the defender accumulates `lessons/` monotonically; the actor
is memoryless across cases and reads a hand-curated `mitre_corpus.py`
that does not grow. Given enough generations, the defender either
exhausts the actor's static strategy space or its judge-gradable
neighborhood — whichever comes first — and learning yield drops to
zero. The plateau is the system's stable state, not a hypothesis.

This is a known self-play failure mode (one side dominates → weaker
side's gradient vanishes → stronger side overfits to a weak opponent
→ both stagnate; cf. AlphaZero / AlphaEvolve literature on population
preservation and frozen-baseline evaluation).

## Problem statement

Build a self-play loop in which the defender accumulates lessons from
adversarial alert investigations. The actor's job is to keep those
investigations hard. **Success is measured by defender capability on
a held-out alert set with ground-truth labels** — not by actor
survival rate. The actor is curriculum; the defender is the artifact.

This is "defender capability against a learning actor" — chosen over
"sustained equilibrium" because it has an externally-verifiable
headline metric and a natural stopping criterion. Equilibrium remains
out of scope until this loop is shipped and instrumented.

## Metrics

### Primary — defender disposition correctness on held-out

Defender runs against a held-out alert set with human-applied
ground-truth labels (`benign | malicious | inconclusive`). Correctness
is the fraction of runs whose `report.md` frontmatter `disposition`
matches the label. **Judge-independent at eval time.** No held-out
case's judge findings or `actor_observations` ever feed back into
`lessons/`, `lessons-actor/`, or either `_pending/` queue.

This is the headline number. Defender ships against the ship criteria
in §Ship criteria.

### Secondary — catch rate against frozen actor from K generations ago

To compute the secondary, replay *the current defender* against the
actor-as-it-was K generations ago on the held-out alert set; report
the fraction of stories the defender catches.

**Frozen actor = git checkout.** The whole `defender/` tree
(`actor.md`, `mitre_corpus.py`, `lessons-actor/`, retrieval logic,
seed policy, model selection) is the actor; reproducing actor-of-K
means reproducing all of it. Git already does this. The author commit
when it fires (see §Generation boundary) is the manifest; gen-N is
identified by a commit SHA. The replay harness checks out
`gen-{N-K}`, runs the actor stage from that working tree against the
held-out alerts, and feeds the resulting stories to the current
defender.

K = 3 by default — far enough that "actor moved" is measurable, close
enough that frozen-actor stories remain in-distribution.

**Purpose: divergence diagnostic, not single-cause verdict.** If the
primary plateaus while the secondary climbs, *something* about the
actor↔defender↔judge triangle has decoupled from real-world
correctness. Possible causes, all worth investigating:

- Actor has learned to game the judge (the canonical worry).
- Defender has overfit to recent synthetic stories, getting easy lift
  on the curriculum it trained against but no transfer to held-out.
- Judge or oracle has drifted (prompt edits, model version, sampling
  change).
- Held-out distribution no longer matches the alert stream the
  curriculum is drawn from.

The divergence triggers investigation; it does not by itself name the
cause. Re-running the actor-side judge calibration set is the
first-line diagnostic — if calibration has slipped, the judge is the
suspect.

## Architecture deltas

### Stays the same

- Runtime defender loop (ORIENT/PLAN/GATHER/ANALYZE/REPORT).
- Defender's `lessons/` pipeline and `defender/learning/author.py`.
- Actor prompt at `defender/learning/actor.md` — three-section output
  with Section 0 technique table.
- Judge v3 schema — `caught | survived | incoherent | undecidable`
  outcome plus `actor_observations` field (max 2).
- Oracle and forward-check stages unchanged.

### What's new

#### 1. Actor accumulation surface — two-channel

```
defender/lessons-actor/
  tradecraft/
    {slug}.md                       # MITRE-keyed pitfall / pattern lessons
  environment/
    {subject-slug}-{run_id}.md      # one file per write; status frontmatter
```

Environment uses **one file per write**, not one file per subject.
Each write produces a new file; on contradiction, the prior `live`
file's frontmatter is flipped to `stale` in-place. Stale files persist
on disk; the read path filters by frontmatter (see below). This keeps
each write atomic, audit-traceable in git, and avoids the multi-row-
within-a-file ambiguity.

**Tradecraft channel.** Story shapes, MITRE-combination patterns,
blending heuristics — **authored only from `caught` outcomes** (what
the defender refuted), framed as patterns to avoid. See §Outcome
filter for actor authoring below. Frontmatter:

```yaml
techniques: [T1550.001, T1078.004]   # one or more — grep key
archetype: [internal]                # multi-value, internal/external only
recorded_at: <run_id>
description: <one-line hook the actor sees in a grep listing>
```

`archetype` is a coarse viability filter — `external` cover stories
don't transfer to `internal` actors. Multi-value list (`[internal,
external]` for lessons that apply to both) — kept as a YAML list of
those two literals so `grep -l "internal"` works reliably.

**Environment channel.** Cache-style; assertions about the
deployment. Frontmatter:

```yaml
subject: <stable equivalence key, e.g., "falco.rule.coverage.docker-exec">
assertion: <the claim itself, one line>
recorded_at: <run_id>
status: live | stale
superseded_by: <run_id, when status=stale>
system_ref: defender/skills/{system}/SKILL.md#<anchor>  # required for live
```

Invalidation: contradiction-only. A new lesson with a matching
`subject` flips the prior live file's `status` to `stale` (and sets
its `superseded_by`) and writes a new live file with the new run id.
Stale files persist for audit; the read path filters to
`status: live`. No time-based TTL at MVP — environment claims aren't
time-sensitive at our cadence, and the `system_ref` grounding gate is
the stronger freshness check.

The `subject` is the load-bearing equivalence key; the author prompt
specifies how to coin one consistently (kebab-case, `{system}.{area}.{noun}`).
`system_ref` is required for `status: live` files and must resolve to
an existing path; the author validation gate enforces this. Stale
files retain whatever `system_ref` they had — they're history.

**Scope constraint — attacker-framed only, not the visibility surface.**

The 2026-05-08 A/B (`learning-loop-actor-design.md` §Resolved) showed
that exposing the actor to the defender's *visibility surface* (which
systems are queryable, which leads exist) collapses the output: actor
proposed queries that duplicated existing leads verbatim. The reframe
fixed the direct mechanism by removing the actor's "breaking evidence"
section. Environment lessons reintroduce visibility-adjacent
knowledge through a different door — without a scope constraint they
would re-create the collapse risk.

**What env lessons may say** — attacker-framed facts about the
deployment: what the world produces (audit artifacts, schedule
windows, ambient noise patterns), what makes telemetry, what blends
where, what authorization shapes look like. These are operational
ground the attacker reasons against in any real engagement.

**What env lessons may not say** — anything framed as the defender's
visibility surface. No "Falco is what the defender queries," no
"l-002 looks at X," no "the defender's lead set covers Y." The
attacker-framed equivalent of "Falco covers docker-exec" is
"`docker exec` produces a Falco syscall record at Notice severity"
— same fact, attacker-grounded, no reference to defender behavior.

The author prompt enforces this with a framing rule: any environment
lesson body that mentions the defender, leads, queries, or lead
positions is rejected at write time. The grounding citation
(`system_ref`) is allowed to *point at* a defender knowledge file
because the citation is metadata, not actor-visible prose.

This does not fully eliminate the collapse risk — actor and defender
can still converge on the same surface implicitly (both learn "X is
noisy → avoid X" / "X is noisy → expect attacks elsewhere"). The
framing rule bounds the *prose* leak; convergence at the strategy
level is a property to monitor via the secondary metric divergence
diagnostic. If observed empirically, the response is to tighten the
framing rule or restrict env-lesson topics further.

**Known risk — stale-but-uncontradicted claims.** Independent corpora
(actor and defender each maintain their own environment knowledge)
means an actor claim can become wrong in the world without producing
a contradicting actor-side lesson, if the actor never re-encounters
the surface. A wrong env claim can produce a plausible story that is
not contradicted by the alert or lead sequence, get judged `survived`,
and pollute the curriculum. This is the primary failure mode the
independent-corpora MVP accepts. Mitigations deferred to follow-up
work: (a) cross-author reconciliation, (b) per-claim re-verification
on read when the claim is older than M generations.

#### 2. Actor retrieval — grep after Section 0

Locked decision *replaces* the design-doc's "memoryless across cases"
constraint (`learning-loop-actor-design.md` §Locked decisions). The
IID-sample rationale was forward-looking to "future actor learning";
we are now that future.

Two-phase within the single actor call:

1. **Commit to Section 0.** Actor reads `alert.json`,
   `lead_sequence.yaml`, archetype, MITRE menu — drafts the Section 0
   technique table. Same as today.
2. **Grep + read lessons.** Actor greps `lessons-actor/tradecraft/`
   for `techniques:` lines matching any of its chosen T-IDs, filtered
   by `archetype`, and Reads matching files. Environment lessons are
   small and global — all `live` rows are pre-loaded into the prompt.
3. **Write Sections 1–3.** Story, goal, bypass — informed by the
   loaded lessons.

**Actor model: Sonnet.** Retrieval is a model-behavior contract
inside a single actor call; Sonnet handles grep+read reliably,
Haiku misses occasionally. The current `defender/learning/loop.py`
defaults the actor to Haiku — that defaults flips to Sonnet as part
of the actor-grep PR.

**Retrieval is audit-only at MVP, not gated.** Section 0 may not be
revised after lessons load — the technique commit is the retrieval
key, and post-hoc revision would invite circular reasoning ("read
lessons, swap to techniques whose lessons I happen to like"). The
actor's `tool_trace.jsonl` records the grep + read calls; an audit
script flags generations where the actor's chosen techniques had
matching lessons on disk but the trace shows zero reads. Audit-only
because at MVP a missed retrieval just means weaker actor performance,
not unsafe behavior. Promotion to a gate is a follow-up if audit
shows consistent retrieval failures.

#### 3. Actor author — concurrent with defender author

`defender/learning/author_actor.py` + `author_actor.md`. Mirror
shape; distinct queue, distinct corpus, distinct threshold.

**Inputs** (from `judge.md` v3 output, currently emitted but
unconsumed):

- `outcome` — gates whether a case is authored from at all.
- `actor_observations` — strategy-level notes on what failed
  (misprediction / framing-failure / discarded class). The existing
  v3 schema is sufficient; no judge edit is required.
- Story text + lead sequence as grounding for what the observation
  references.

**Outcome filter for actor authoring.**

| outcome | author? | rationale |
|---|---|---|
| `caught` | yes | defender refuted the story — the failure pattern is the lesson |
| `survived` | **no** | learn only from failures; survival may reflect judge leniency, not real tradecraft strength |
| `incoherent` | no | hygiene / prompt-quality issue, not tradecraft; surface via judge-alignment review instead |
| `undecidable` | no | by definition, no signal |
| `skip-passthrough` | no | actor declined; nothing to learn from |

The tradecraft channel is therefore **failure-only** by construction:
every lesson is a pattern the defender refuted. The actor reads these
at story time as patterns to avoid. There is no positive-pattern
channel at MVP — defender learns from where it failed (its `caught`
is defender's miss); actor learns the same way (its `caught` is the
actor's miss). Symmetric.

The judge v3 schema is unchanged.

**Routing.** Each candidate lesson is classified as tradecraft or
environment by the author prompt and written to the matching channel.
Cross-channel contamination (a tradecraft lesson masquerading as
environment) is the main authoring risk; the author's prompt must be
explicit about the channel test (environment = claim about the
deployment surface, groundable in `defender/skills/{system}/`;
tradecraft = claim about story shape or blending).

**Validation gates.**

- Tradecraft: non-duplication only (no probe-evidence gate). Soft
  channel.
- Environment: groundability check against `defender/skills/{system}/`.
  Author must cite a system+surface reference for the claim.

**Concurrency.** Actor author and defender author share no state and
run on independent `_pending` queues hitting independent thresholds
(default 5 each). They can fire in any order; no synchronization.

**Independent corpora — no cross-author reconciliation at MVP.** If
actor and defender disagree about the same environment fact, each
side sees its own world. The cost is *not* fully bounded — see the
"stale-but-uncontradicted" failure mode under the environment
channel above. Reconciliation is a follow-up; at MVP we accept the
risk and watch for it via the secondary metric divergence diagnostic.

#### 4. Generation boundary — git is the manifest

A **generation** is identified by a git commit SHA: the commit the
actor author produces when it fires. No commit, no generation. The
commit captures everything that defines the actor — `actor.md`,
`mitre_corpus.py`, `lessons-actor/` (including the newly-authored
files plus any `live`→`stale` flips from this batch), retrieval
logic, model selection in `loop.py`. Replaying a frozen actor means
checking out that SHA and running the actor stage from the resulting
working tree.

**Numbering and alignment:**

- `gen-N` refers to the *post-update* commit. The pre-update tree is
  `gen-{N-1}`.
- The actor author's commit message is the canonical place to assert
  `gen-N` (e.g. trailer `Generation: N`). A helper script walks
  `defender/lessons-actor/` history to enumerate generations.
- **No-op author runs do not advance N.** If the author finds nothing
  to write (all candidates dedupe out, or threshold hit but every
  finding fails the validation gate), no commit is created and the
  generation counter is unchanged.
- Defender-author commits do *not* advance the actor generation;
  they're a separate sequence. The two sequences interleave freely in
  git history.
- The replay harness for the secondary metric resolves `gen-{N-K}` by
  walking the actor-author commit log backward K entries from HEAD.

## Prerequisites — must land before turning on actor learning

These are not stretch goals. The loop's signal is invalid without
them.

1. **Actor-side judge calibration set.** ~30 rows. Humans label
   `(alert, story, lead_sequence) → caught/survived/incoherent/undecidable`.
   Equivalent to the defender's `defender/learning/judge-alignment/`
   work, but for actor-side outcomes. Without this, every downstream
   actor-author decision is built on uncalibrated judge output.

2. **Held-out alert set with ground-truth labels.** 20–30 alerts is
   the minimum to detect meaningful primary-metric movement (see
   §Ship criteria). These alerts live in a fixture dir and are tagged
   `held_out: true`; the learning loop's persist stage drops both
   `defender_findings` and `actor_observations` from held-out runs
   before either queue (`_pending/findings.jsonl`,
   `_pending/actor_observations.jsonl`) is touched. The filter applies
   symmetrically to both authors.

## Ship criteria

"Defender ships when the primary plateaus" is incomplete — a plateau
at poor correctness is not a ship signal. Defaults (calibrated once
baseline is measured):

- **Minimum correctness floor.** The defender's correctness on the
  held-out set must clear a floor before plateau counts as ship-
  ready. Initial floor: 80% overall, with no class falling below 70%
  (per-class floor protects against an unbalanced set hiding a
  systemic failure on the minority class).
- **Class balance in held-out.** At least 8 alerts per
  `disposition` class (`benign | malicious | inconclusive`), 24–30
  alerts total. A held-out set without representatives of a class
  cannot detect regressions on that class.
- **Plateau definition.** Three consecutive author generations with
  primary-metric delta < 2 percentage points and bootstrap 95% CI
  (N=1000 resamples) overlapping. The CI rule guards against calling
  noise a plateau on a small held-out set.
- **Secondary check.** At the same time the primary plateaus, the
  secondary metric must *not* be diverging upward — see §Secondary
  divergence diagnostic. If it is, investigate before shipping.

These are initial defaults. Re-calibrate once the held-out fixture
set lands and the current defender's baseline is measured.

## Sequencing

Land in this order, each as its own PR:

1. **Held-out fixture set + persist-stage filter.** Cheap, unblocks
   primary-metric measurement against the current defender as a
   baseline.
2. **Actor-side judge calibration set.** Highest leverage. Mirrors
   `defender/learning/judge-alignment/`.
3. **`lessons-actor/` directory + schema + scaffolding.** No code yet
   — just the corpus shape and a couple of hand-authored seed lessons
   to test grep retrieval.
4. **Actor.md edit — grep-after-Section-0 phase.** Validate that the
   actor can retrieve lessons reliably enough at MVP.
5. **Actor author** — `author_actor.py` + `author_actor.md`. Fed by
   judge `actor_observations` on `outcome: caught` only (see §Outcome
   filter). Routes to tradecraft or environment channel; environment
   author prompt enforces the attacker-framing constraint and rejects
   visibility-surface prose. Author commit on fire is the generation
   boundary; commit trailer asserts `Generation: N`.
6. **Secondary metric harness.** Replay actor stage from `gen-{N-3}`
   commit against held-out; feed stories to current defender; report
   catch rate.
7. **End-to-end loop wiring** — defender author and actor author
   firing concurrently per their own thresholds.

## Out of scope at MVP

- **Cross-author reconciliation** of environment claims. Independent
  corpora; observe empirical disagreement before adding a stage.
- **Time-based TTL** on environment claims. Contradiction-only
  invalidation. Layer in if drift is observed.
- **Multi-actor populations.** Single actor that mutates over time
  via its own lessons. Population management is the equilibrium-mode
  problem (problem statement #2), explicitly deferred.
- **Tradecraft probe-evidence gate.** Soft channel by design;
  non-duplication is the only validation.
- **Equilibrium-mode metrics** (diversity, time-to-plateau, win-rate
  stability). Not measured; not optimized for.

## Open questions tracked downstream

- **Granularity of tradecraft T-ID keying.** Per-technique is the
  default; per-(technique, tactic) or per-technique-combination may
  prove more useful empirically. Revisit when the first 20 lessons
  exist.
- **`actor_observations` richness.** Currently capped at 2 per case
  by judge v3 schema. If the author finds it consistently too thin,
  the judge prompt edit precedes any pipeline addition.
- **Snapshot retention.** All generations kept at MVP. If snapshot
  count grows unwieldy, prune by keeping every Nth generation plus
  the latest K.
