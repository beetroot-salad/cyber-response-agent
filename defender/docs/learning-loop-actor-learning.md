# Actor-learning workstream — design (2026-05-11)

Companion to `learning-loop.md` and `learning-loop-actor-design.md`.
Activates the deferred *actor self-learning* pointer from that doc.

Status: **design, pre-implementation.** Specs the loop, the new
corpora, the metric, and the prerequisites. Code lands in subsequent
PRs against this branch.

## Motivation

The deployed loop has a structural asymmetry that *plausibly* drives
a plateau: the defender accumulates `lessons/` monotonically; the
actor is memoryless across cases and reads a hand-curated
`mitre_corpus.py` that does not grow. Over enough generations the
defender may exhaust the actor's static strategy space or its
judge-gradable neighborhood, and learning yield trends toward zero.

This is the headlining risk this workstream addresses, but it is not
the only plausible cause of an observed plateau in the current
system: judge sensitivity, oracle limits, sampling policy, held-out
distribution drift, and defender retrieval ergonomics can all
flatten yield independently. We treat the static-actor hypothesis as
the most actionable lever (the others are already on the roadmap or
out of scope) and ship instrumentation that can distinguish them
post-hoc — chiefly the divergence diagnostic in §Secondary metric.

Self-play framing precedent: one side dominates → weaker side's
gradient vanishes → stronger side overfits to a weak opponent → both
stagnate; cf. AlphaZero / AlphaEvolve literature on population
preservation and frozen-baseline evaluation.

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

**Failure accounting.** Every held-out alert is in the denominator.
Runs that fail to produce a clean `report.md` with parseable
disposition frontmatter — runtime errors, timeouts, missing report,
invalid frontmatter, disposition outside the closed enum — count as
**wrong** against the ground-truth class. Excluding failures from
the denominator would inflate correctness and let regressions hide
behind crashes. Per-class recall floors apply post-bucketing, so a
malicious-ground-truth alert that produces a runtime error contributes
1 to the malicious denominator and 0 to malicious recall — i.e., it
counts against the 90% malicious floor. The failure bucket is
reported separately as a *failure rate* alongside correctness, both
for diagnostic visibility and because a non-trivial failure rate is
itself a ship-blocker even if the surviving runs are all correct.

**`inconclusive` as a labeled disposition, not a free pass.** The
ground-truth label `inconclusive` is reserved for alerts where the
correct human judgment, given the available telemetry, is "evidence
does not discriminate." When the ground truth is `benign` or
`malicious`, predicting `inconclusive` is *wrong* — exact-match.
This prevents the loop from rewarding abstention. Per-class recall
matters more than aggregate accuracy; the ship criteria call out a
per-class floor for exactly this reason. The most load-bearing class
is `malicious` recall (false negatives are the project's stated
zero-tolerance failure mode); the per-class floor binds especially
there.

This is the headline number. Defender ships against the ship criteria
in §Ship criteria.

### Secondary — catch rate against frozen actor from K generations ago

The defender does not consume actor stories — the architecture runs
defender first, then actor, then oracle + judge against the
investigation's lead sequence. So "catch rate against a frozen actor"
is shorthand for: how well does the *current defender's lead
sequence* refute stories written by an old actor?

**Replay scope — eligibility by ground-truth, not by defender
disposition.** `defender/learning/loop.py` skips alerts whose
*defender disposition* is `malicious`. If the secondary inherited
that scope literally, the eligible set would change every time the
defender's disposition on an alert flipped (e.g. as defender
improves, a previously-misclassified-benign-actually-malicious alert
gets correctly escalated and drops out of the eligible set). That
makes secondary trends conflate "actor got better" with denominator
drift.

The secondary metric fixes the eligible set by **ground-truth
label**: held-out alerts where the human-applied label is `benign`
or `inconclusive` are *always* eligible; alerts labeled `malicious`
are *never* eligible (they contribute only to the primary's
malicious-recall floor). The eligible set is therefore stable
across generations.

Within the eligible set, the *executed* set per generation is the
subset where the current-HEAD defender's disposition was not
`malicious` — that is, where the loop was actually willing to run
the actor stage. False escalations (current defender escalating an
alert whose ground truth is benign or inconclusive) drop out of the
executed set; that drop is itself a defender-quality signal and is
reported as the executed/eligible ratio alongside catch rate. Three
numbers per generation:

- Eligible set size — fixed across generations.
- Executed/eligible — fraction of eligible alerts the loop ran on.
- Catch rate — `caught / (caught + survived + incoherent +
  undecidable)` over the executed set, excluding skip-passthrough
  from the denominator.

**Replay flow (eligible held-out alert × K-generations-old actor):**

1. **Eligibility check on ground-truth label.** Skip if held-out
   label is `malicious`. Otherwise: **current defender** investigates
   the held-out alert from `HEAD` — produces `investigation.md` +
   `lead_sequence.yaml` + `gather_raw/`. If the defender's
   disposition on this run is `malicious`, the alert is *eligible
   but not executed* this generation; record it as such and skip the
   remaining steps.
2. **Frozen actor** writes a story against that lead sequence,
   running from a `gen-{N-K}` checkout. The actor sees the alert and
   the projected lead sequence; it does not see investigation
   results (gray-box, unchanged from the live loop).
3. **Current oracle** projects telemetry from story + lead set.
4. **Current judge** grades `(alert, investigation, story,
   projected_telemetry) → outcome ∈ {caught | survived | …}`.
5. **Catch rate denominator excludes `skip-passthrough`.** Actor SKIP
   means the frozen actor couldn't construct any plausible malicious
   story from the menu/archetype it was handed — that's not the
   actor failing on tradecraft, it's the actor declining. Reported
   separately as a *SKIP rate* alongside catch rate; a frozen actor
   whose SKIP rate climbs unexpectedly is itself a signal but
   distinct from "current defender caught the story." Catch rate =
   `caught / (caught + survived + incoherent + undecidable)` over
   the **executed set** (see §Replay scope) — non-executed eligible
   alerts and SKIPs contribute no catch outcome and are excluded
   from the denominator.

**Two-worktree harness.** Replay needs old actor code *and* current
defender/oracle/judge simultaneously. A single `git checkout` cannot
provide both. The harness uses two worktrees:

- `worktrees/replay-head/` checked out at `HEAD` — runs defender,
  oracle, judge.
- `worktrees/replay-gen-{N-K}/` checked out at the target generation
  commit — runs the actor stage.

**Boundary: where the actor stage starts.** The actor stage is
*everything from actor-input projection through actor invocation* —
including the projection step (`actor_input` assembly in
`defender/learning/loop.py`). The gen-{N-K} worktree owns this end
of the pipeline. The HEAD worktree hands over `lead_sequence.yaml`
(plus the alert) and receives back the actor's story; nothing in
between.

**Compatibility contract on `lead_sequence.yaml`.** The handoff
artifact crossing worktrees is `lead_sequence.yaml`. The schema
must remain backward-compatible across K generations so the
gen-{N-K} projector can parse a HEAD-produced sequence. If a
breaking schema change is necessary mid-experiment, the actor-author
commit at that generation records the schema version in its trailer,
and the replay harness refuses to cross a schema boundary
(reports the replay as `replay-incompatible` rather than producing
garbage). For K=3 and a stable schema, this is a no-op; the rule
exists so a future schema break does not silently corrupt the
secondary metric.

**Git is not the *full* manifest.** Two non-source dimensions can
drift independently of the working tree:

- **Model selection.** `defender/learning/loop.py` reads model
  identifiers from environment variables with defaults. Replay must
  pin actor model to whatever the gen-{N-K} commit specified.
  Concretely: the actor-author commit's trailer records the actor
  model in addition to `Generation: N`, and the replay harness reads
  that trailer to set the env vars before invoking the actor.
- **External API behavior.** Anthropic model versions can shift
  silently behind aliases. Replay results are not literal
  reproductions — they are best-effort, and large unexplained
  secondary-metric swings should be checked against model-version
  changes before being attributed to actor drift.

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
- Actor prompt at `defender/learning/actor.md` — four-section output
  (Section 0 technique table + Sections 1–3: Attack story / Goal /
  Bypass).
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

**Two invalidation modes:**

- **Contradiction-with-replacement** (`caught` outcomes): the
  author identifies the correct fact, writes a new live file with
  the new `recorded_at`, and flips the prior live file's `status`
  to `stale` with `superseded_by` set.
- **Stale-only invalidation** (`incoherent` outcomes): the author
  identifies that the actor's story contradicted itself because of a
  specific live env claim, but cannot derive the correct replacement
  fact from the incoherent encounter alone. The prior live file's
  `status` flips to `stale`, `superseded_by` is recorded as the
  run id that surfaced the contradiction, and **no new live file is
  written**. The subject is left without a live claim until a
  future `caught` case (or hand-authored knowledge) supplies one.

Stale files persist for audit in both modes; the read path filters
to `status: live`. No time-based TTL at MVP — environment claims
aren't time-sensitive at our cadence, and the `system_ref` grounding
gate is the stronger freshness check.

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

**Actor model: Sonnet — via a stage-specific env var.** Retrieval is
a model-behavior contract inside a single actor call; Sonnet handles
grep+read reliably, Haiku misses occasionally. The current
`defender/learning/loop.py` reads a single `CLAUDE_MODEL` shared
across actor, oracle, and judge — flipping that to Sonnet globally
would silently change oracle and judge behavior, invalidating both
judge calibration and the secondary-metric replay. The actor-grep PR
introduces stage-specific env vars (`ACTOR_MODEL`, `ORACLE_MODEL`,
`JUDGE_MODEL`) with `CLAUDE_MODEL` retained as the shared fallback;
the actor default goes to Sonnet, oracle and judge stay on their
calibrated models. The author commit trailer records the actor model
used at that generation (see §Generation boundary) — replay reads
the trailer and sets `ACTOR_MODEL` accordingly without touching
`ORACLE_MODEL` / `JUDGE_MODEL` (which always come from HEAD).

**Retrieval is audit-only at MVP, not gated.** Section 0 may not be
revised after lessons load — the technique commit is the retrieval
key, and post-hoc revision would invite circular reasoning ("read
lessons, swap to techniques whose lessons I happen to like").

**Trace capture is part of the actor-grep PR, not assumed.** The
current actor stage runs as a plain `claude -p` text invocation in
`defender/learning/loop.py` and persists only the story output — no
tool trace today. The actor-grep PR adds:

- `claude -p --output-format stream-json` (or equivalent) on the
  actor stage to capture per-tool-call events,
- a per-case `actor_trace.jsonl` artifact in the run dir,
- an audit script that scans traces and flags generations where the
  actor's chosen techniques had matching lessons on disk but the
  trace shows zero reads.

Audit-only because at MVP a missed retrieval means weaker actor
performance, not unsafe behavior. Promotion to a gate is follow-up
if audit shows consistent retrieval failures.

#### 3. Actor author — concurrent with defender author

`defender/learning/author_actor.py` + `author_actor.md`. Mirror
shape; distinct queue, distinct corpus, distinct threshold.

**Inputs** (per-case bundle):

- `outcome` — gates whether the case is authored from, and which
  channels are eligible (see §Outcome filter).
- `actor_observations` (from `judge.md` v3) — strategy-level notes
  on what failed. **Optional in the judge schema** (`judge.md`
  emits 0–2 observations per case). The author treats present
  observations as the preferred seed because they pre-isolate the
  load-bearing element; when absent on an authorable outcome
  (`caught` or `incoherent`), the author falls back to deriving
  candidate lessons from the full per-case bundle below. The judge
  schema is unchanged — the fallback discipline lives in the author
  prompt, not in a stricter judge contract.
- Alert + story + investigation + projected telemetry — the same
  four artifacts the judge saw, so the author can ground claims.
- **Env-lessons snapshot (`actor_env_lessons.yaml`)** and
  **retrieval trace (`actor_trace.jsonl`)** — two distinct artifacts
  the actor-grep PR persists per case:
  - `actor_env_lessons.yaml` — a snapshot of every live env-lesson
    file pre-loaded into the actor prompt at story time. Locked
    schema, ordered list, order matches the order injected into the
    prompt:

    ```yaml
    - order: 0                      # injection order; matters because
                                    # prompt position can influence weight
      path: defender/lessons-actor/environment/falco-rule-cov-XXX.md
      subject: falco.rule.coverage.docker-exec
      recorded_at: <run_id>
      status: live                  # always live at story time; recorded for audit
      system_ref: defender/skills/wazuh/SKILL.md#falco-rules
      assertion: |
        <verbatim one-line claim body the actor saw>
      blob_sha: <git object SHA of the file at story time>
    - order: 1
      ...
    ```

    Both `assertion` (inlined for self-containment — survives later
    edits or stale-flips) and `blob_sha` (cross-check against
    history) are recorded. Identifier-only references would lose the
    exact claim if files mutate between actor run and author run.
    Env lessons are *injected* by the orchestrator, not grepped by
    the actor, so the retrieval trace alone does not name them.
  - `actor_trace.jsonl` — the actor's tool-call trace, including
    grep + read calls into `lessons-actor/tradecraft/`.
- **Note on causality.** The retrieval trace proves *exposure*, not
  *influence*. A read does not prove the lesson shaped the story.
  The author should treat trace reads as exposure when attributing
  load-bearing tradecraft to a lesson, and avoid claims of the form
  "lesson X caused failure Y" — only "lesson X was in scope when
  failure Y occurred." A future hardening option (explicit citation
  of lesson IDs inside Section 0 or story body) is noted as
  follow-up; not in MVP.

**Pending queue contract — `_pending/actor_observations.jsonl`.**

One entry **per observation** (not per run), so the unit of dedupe
and routing is the lesson candidate. Schema, one JSONL line per
entry:

```json
{
  "id": "<case_id>:<observation_index>",
  "case_id": "<run_id of the live-loop case>",
  "observation_index": 0,
  "outcome": "caught | survived | incoherent | undecidable | skip-passthrough",
  "observation": "<verbatim actor_observations[i] text from judge>",
  "case_bundle_ref": "<relative path to the per-case artifacts directory>",
  "queued_at": "<ISO-8601 UTC>"
}
```

Rules:

- **Stable ID** = `{case_id}:{observation_index}`. The case_id comes
  from the live-loop run dir name; observation_index is the zero-
  based position in the judge's `actor_observations` array. The pair
  is unique per emitted observation and stable across re-queue
  attempts.
- **Dedup on `id`.** Replaying or rerunning the persist stage on a
  case must not double-queue. The queue writer checks `id`
  membership before append.
- **Per-observation, not per-case.** A case with two observations
  produces two entries; the actor author can fold one and defer the
  other.
- **Case-bundle reference, not inlined.** `case_bundle_ref` points
  to the per-case artifacts directory (alert, investigation, story,
  projected telemetry, `actor_env_lessons.yaml`, `actor_trace.jsonl`).
  The author Reads these from disk; inlining them would bloat the
  queue.
- **Consumed-on-fold.** Successful fold (lesson written + committed)
  removes the entry. Failed validation (e.g., environment grounding
  gate, attacker-framing rule) keeps the entry in the queue with an
  appended `attempts` counter; after N=3 attempts the entry is moved
  to `_pending/actor_observations.rejected.jsonl` for review and
  removed from the active queue. Idempotent on retry.
- **Threshold check.** Author fires when active-queue line count
  reaches `LEARNING_AUTHOR_THRESHOLD` (default 5). Rejected-queue
  entries do not count toward the threshold.
- **No outcome=`skip-passthrough` entries.** Cases that emitted
  SKIP produce no `actor_observations` and therefore no queue
  entries.

**Outcome filter for actor authoring.**

| outcome | author? | rationale |
|---|---|---|
| `caught` | yes | defender refuted the story — the failure pattern is the lesson |
| `survived` | **no** | learn only from failures; survival may reflect judge leniency, not real tradecraft strength |
| `incoherent` | environment channel only | a story that contradicts its own setup is often driven by a stale environment assumption the actor relied on — this is the only mechanism that surfaces stale env claims for invalidation under contradiction-only invalidation; tradecraft-channel authoring stays off because incoherence is not a refuted tradecraft pattern |
| `undecidable` | no | by definition, no signal |
| `skip-passthrough` | no | actor declined; nothing to learn from |

The tradecraft channel is therefore **failure-only** by construction:
every lesson is a pattern the defender refuted. The actor reads these
at story time as patterns to avoid. There is no positive-pattern
channel at MVP.

Note that `caught` is the *actor's* failure (defender's leads
refuted the story), not the defender's. The defender's failure mode
in this loop is `survived` (story would have evaded the
investigation). The actor authors from `caught`; the defender's
existing `defender_findings` pipeline draws on a different mix of
outcomes — the two authors are not perfectly symmetric.

**Environment-channel authoring on `incoherent`.** Asymmetric to
tradecraft, the environment channel does read `incoherent` outcomes
— but only for the narrow purpose of flipping stale env claims to
`stale`. Without this, contradiction-only invalidation has a gap:
a stale env claim drives the actor to write a story that contradicts
the alert or investigation; judge calls it `incoherent`; under a
strictly-caught-only filter no new env lesson is authored and the
stale claim persists. Allowing `incoherent` to invalidate (but not
to add new positive env claims unless the contradiction *names* the
correct fact) closes the loop. The author's env-channel prompt is
responsible for distinguishing "this incoherence implies env claim X
is wrong" (invalidate X) from "this incoherence is an actor logic
error unrelated to env" (no-op).

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
  channel. **Known risk: no realism gate.** A novel-but-unrealistic
  tradecraft lesson (overconfident generalization from a single
  `caught` case, judge artifact misread as a pattern) can become
  durable curriculum the actor reads at every subsequent story. The
  forward-check stage (`verify_forward.{md,py}`) is the closest thing
  to a realism check we already run on the defender side; an
  analogous stage for tradecraft is a follow-up. **At MVP we accept
  the risk and mitigate via**: (a) periodic human review of new
  tradecraft lessons at each generation boundary — feasible at MVP
  scale, ~5 lessons per generation; (b) tradecraft lesson count per
  generation is logged so unusually prolific generations are
  reviewed first; (c) lessons that consistently fail to predict
  `caught` outcomes when their pattern is invoked are flagged for
  retirement (instrumentation, not enforcement, at MVP).
- Environment: groundability check against `defender/skills/{system}/`
  (the `system_ref` frontmatter field, required for `status: live`).
  Plus the attacker-framing rule above.

**Concurrency.** Actor author and defender author write to disjoint
corpora and read disjoint `_pending` queues, but they **share the
git repository** — HEAD, the index, working-tree cleanliness, and
the commit sequence. Two authors firing simultaneously would race
on the index and produce interleaved or aborted commits.

**Two locks, fixed order in both authors:**

1. **Queue lock** — per-author, on its own `_pending` queue.
   `defender/learning/author.py:81` already takes this for the
   defender side; the actor author takes its own queue lock on its
   own pending file. Acquired first, released last.
2. **Repo lock** — `fcntl.flock` on
   `defender/learning/_author.lock`. Shared between both authors.
   Acquired **after** the queue lock and held across the **entire
   fold-and-commit flow** — including the child-agent invocation
   that mutates files, not just the final `git add` + `git commit`.

**Why the wider scope.** The existing defender author
(`defender/learning/author.py:312`,`:342`) delegates lesson edits
*and* the commit to a child agent. If the repo lock only wraps the
final commit, the other author can start its own child agent
concurrently, both children dirty the shared working tree, and the
commits interleave or stomp on each other's edits. The lock
therefore covers: child-agent launch → child writes files → child
issues commit (or parent commits, if the protocol changes — see
below) → lock release.

Ordering invariant: every author acquires `queue → repo` and
releases `repo → queue`. Same order in both authors prevents
deadlock. The queue lock is held continuously across the
fold+commit step so the batch read from the queue cannot be
trimmed by another path between read and write.

**Compatible alternatives** (not required at MVP, listed if the
wider lock turns out to hold too long in practice):
- Move commit ownership out of the child agent — child produces a
  proposed-edit bundle, parent applies it and commits under a
  narrow lock.
- Run each author in its own git worktree, merge to the canonical
  branch under lock.

Operational notes:

- Empty/no-op author runs that produce nothing to commit acquire
  both locks, decide no commit is needed, release both. Per
  §Generation boundary, the actor counter does not advance.
- After releasing the repo lock following a commit, an author
  observes the new HEAD it just created; the other author, when it
  next acquires the repo lock, sees that HEAD as its base.
- The repo lock guards only the local working tree's commit
  critical section. Push and PR creation are out of band.

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
   *two* things on the judge's full input tuple
   `(alert, investigation.md, actor story, projected_telemetry.yaml)`:

   - **Outcome label** — `caught/survived/incoherent/undecidable`.
     Calibrates the outcome enum that gates which cases the actor
     author runs on.
   - **Expected-observation gist** — a one-sentence description of
     what the load-bearing actor observation *should* be on this
     case (e.g. "story relied on docker-exec being un-audited; lead
     l-002 directly catches it"). The judge's actual
     `actor_observations` are then compared against this gist for
     pertinence and groundedness, since the observations are what
     actually trains the actor author. Outcome calibration without
     observation calibration would calibrate the gate but leave the
     training signal uncalibrated.

   The (alert, story, lead_sequence) shorthand from earlier drafts
   was wrong — `judge.md` needs the investigation log and the
   oracle's projected telemetry to grade the encounter (see
   `defender/learning/judge.md` §inputs). Calibration fixtures must
   include all four artifacts, snapshotted together. Equivalent to
   the defender's `defender/learning/judge-alignment/` work, but for
   actor-side outcomes plus observations.

   **Acceptance criteria — turning on actor learning is gated on:**
   - **Outcome agreement ≥80%** between judge and human label across
     the 30-row set. Below this, judge prompt iteration is required
     before actor learning is enabled. (Initial threshold; can be
     tightened once a stable baseline exists.)
   - **Observation pertinence ≥70%** — fraction of `actor_observations`
     judged by a human reviewer as substantively matching the
     expected-observation gist (the load-bearing element of what
     should have been observed). The lower threshold reflects that
     observation phrasing varies more than outcome enums.
   - **No silent failures**: every case must produce a parseable
     judge YAML doc. Parse failures count as outcome disagreement.

   Below either floor → judge prompt iteration precedes any actor
   author rollout. The calibration set is re-run after each judge
   prompt edit.

2. **Held-out alert set with ground-truth labels.** 24–30 alerts
   (≥8 per disposition class — see §Ship criteria for the class
   balance derivation). These alerts live in a fixture dir and are tagged
   `held_out: true`; the learning loop's persist stage drops both
   `defender_findings` and `actor_observations` from held-out runs
   before either queue (`_pending/findings.jsonl`,
   `_pending/actor_observations.jsonl`) is touched. The filter applies
   symmetrically to both authors.

## Ship criteria

"Defender ships when the primary plateaus" is incomplete — a plateau
at poor correctness is not a ship signal. Defaults (calibrated once
baseline is measured):

- **Minimum correctness floor.** Defender correctness on held-out
  must clear an aggregate floor *and* a per-class floor before
  plateau counts as ship-ready. Initial floors:
  - Aggregate: 80% exact-match.
  - Per-class recall: ≥70% on `benign`, ≥70% on `inconclusive`,
    **≥90% on `malicious`**. The asymmetric malicious floor reflects
    the project's stated zero-false-negative goal — predicting
    `inconclusive` or `benign` on a malicious alert is the failure
    mode that matters most.
- **Class balance in held-out.** At least 8 alerts per
  `disposition` class (`benign | malicious | inconclusive`), 24–30
  alerts total. Sizing rationale: with 8 per class and a 90% recall
  floor on malicious, the floor effectively requires **8/8 malicious
  correct** — 7/8 = 87.5%, already below floor. This is intended:
  any malicious miss on the held-out set is a ship-blocker, which
  aligns with the project's zero-false-negative goal. A held-out set
  without representatives of a class cannot detect regressions on
  that class.
- **Plateau axis.** The primary metric measures defender capability;
  it depends on defender state only. Plateau is therefore measured
  on the **defender-author commit sequence**, not on actor
  generations. Each defender-author commit produces an eval
  checkpoint `(defender_sha, actor_generation)`; the
  `actor_generation` is recorded for traceability but does not
  affect the plateau test. Actor-author commits that do not change
  defender corpus produce no new checkpoint.
- **Plateau definition.** Three consecutive defender-author commits
  with zero label changes on held-out, and bootstrap 95% CI (N=1000
  resamples) overlapping. On 24–30 alerts, one label flip moves
  aggregate accuracy by 3.3–4.2 pp; the prior "<2 pp" threshold was
  below single-alert resolution. The zero-change rule is the
  operational form on a small held-out set; if the set grows to
  ≥100 alerts later, swap back to a percentage-point delta.
- **Secondary check.** At ship time, the secondary metric must not
  show **upward divergence** against the primary. Concretely:
  - **Window.** Last 3 eval checkpoints (i.e., the same checkpoints
    that produced the primary plateau).
  - **Slope rule.** Linear-fit slope of secondary catch rate over
    those 3 checkpoints must be ≤ +4 pp/checkpoint. On a 24-30
    alert held-out set, +4 pp/checkpoint is roughly one alert per
    step — anything sharper is a real movement, not noise. Slope
    above the threshold blocks ship; slope at or below allows it.
  - **Confidence.** Bootstrap 95% CI (N=1000 resamples) on the
    secondary catch rate at each checkpoint. If the CIs across the
    3 checkpoints fully overlap, treat the slope as noise regardless
    of its point value; ship is not blocked.
  - **Insufficient-evidence gate.** If any of the 3 checkpoints
    has executed/eligible < 0.5 (sparse replay, mostly false
    escalations) or a non-zero `replay-incompatible` count, the
    divergence test is reported as **insufficient evidence** and
    requires manual review before ship — neither automatic-pass nor
    automatic-block.
  
  See also §Secondary metric for the full diagnostic context (the
  test only flags divergence; the causal attribution among judge
  gaming, defender overfit, oracle/judge drift, and held-out drift
  is a manual investigation triggered by the flag).

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
   actor can retrieve lessons reliably enough at MVP. **Includes
   artifact capture**: switch the actor invocation in
   `defender/learning/loop.py` to stream-json mode, persist per-case
   `actor_trace.jsonl` (tradecraft grep+read events) **and**
   `actor_env_lessons.yaml` (verbatim live env-lesson bodies +
   blob SHAs), introduce stage-specific model env vars (`ACTOR_MODEL`,
   `ORACLE_MODEL`, `JUDGE_MODEL`), and add the missed-retrieval audit
   script.
5. **Actor author** — `author_actor.py` + `author_actor.md`.
   Per-case input bundle: `outcome`, `actor_observations` (if
   present, else fall back to the full bundle), alert, investigation,
   story, projected telemetry, `actor_env_lessons.yaml`,
   `actor_trace.jsonl`. Outcome routing: `caught` → tradecraft +
   environment (contradiction-with-replacement); `incoherent` →
   environment stale-only invalidation. Environment author prompt
   enforces the attacker-framing constraint. Acquires queue lock
   then `_author.lock` (in that order, both authors) **before
   launching the child-agent fold** and holds both through commit —
   the wider scope is mandatory (see §Concurrency); narrowing the
   lock to only the final commit reintroduces the shared-worktree
   race. Author commit on fire is the generation boundary; commit
   trailer asserts `Generation: N` plus the actor-model identifier
   (for replay).
6. **Secondary metric harness.** Two-worktree replay: current defender
   investigates held-out from `HEAD`, frozen actor from `gen-{N-3}`
   writes a story against that lead sequence, current oracle + judge
   grade. Report catch rate. Reads actor-model pin from the
   gen-{N-3} commit trailer.
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
- **Generation retention.** Generations are git commits — git
  history retains them by default at no marginal storage cost.
  Nothing to prune at MVP. If commit count on the actor-author
  sequence ever becomes a navigation problem, the response is
  tagging (e.g. `gen-N` annotated tags) rather than deletion.
