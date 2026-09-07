# Investigation Review and Learning Loop

## Status

**Implementation cache; code wins on conflict.** The loop described here exists
under `defender/learning/` as branched episode (`branch/cli.py`) → questioner
(`branch/questioner/`) → staged estate (`branch/estate/`) → review by replay
(`branch/review.py`) → the family as `run.py --resume` processes → judge
(`judge/`) → findings queue → lessons curator (`author/lessons/`) with a
per-lesson forward-check gate (`author/verify_forward/`) → lessons corpus
(`defender/lessons/*.md`). This doc is not the source of truth, but it should
track the implementation closely enough that a reader can orient without
reopening every file.

**Rewritten for #922.** Until the cutover this document described a four-role
pipeline — two actors, a telemetry oracle and a judge — that invented the
material it learned from. That pipeline is deleted. The sections below describe
what replaced it; `docs/learning-loop-cutover.md` is the account of the swap
itself, and `docs/archive/learning-loop-experiments-2026-05-08.md` keeps the
empirical findings from the old shape.

This document describes an **offline learning mechanism** that mines completed
investigations for reusable lessons and writes them into
`defender/lessons/*.md`. Each curator commits from its own git worktree off
`origin/main` and opens one PR per batch. The loop is not a real-time guard.

The live investigation path is unchanged: a single investigator. A same-context
self-evaluation loop is described below as a future enhancement, not as a
current runtime stage.

## Purpose

Improve investigation **correctness and efficiency** by asking, of a finished
real investigation, a question that reading it cannot answer: **was the verdict
driven by the evidence, or would it have survived evidence pointing somewhere
else?**

The mechanism is a **counterfactual re-run, not a counterfactual story.** The
investigation is stopped at a chosen turn and restarted several times from that
exact moment — one sibling against the world as it was, the others against
worlds that each differ by one authored fact. Every sibling carries the same
history, the same alert and the same partial reasoning up to the branch point,
and diverges only in what the evidence says. Comparing their conclusions
localizes the failure: a defender that reaches the same verdict in a world where
the deciding fact is *different* was not reading that fact, and the comparison
says where it lost it — never queried the system holding it, queried it at the
wrong scope, received it and reasoned past it, or established it and did not let
it move the verdict.

That last distinction is the whole reason the loop was rebuilt. The old pipeline
graded the defender against telemetry a model had imagined, so a finding could
never be stronger than the imagination behind it. A branched episode grades it
against telemetry a run actually received.

## Inspirations

The defender + learning-loop architecture is closer in spirit to classical ML
training regimes than to "an LLM agent with a better prompt." It helps to read
the components through that lens — both because the analogies suggest concrete
techniques to import, and because they flag known failure modes early.

**Reinforcement learning.** The runtime defender is the *policy*. Its trajectory
through ORIENT → PLAN → GATHER → ANALYZE → REPORT is an *episode* — one the
write-time review gate can extend (a challenged close buys further turns) or
whose terminal action it can override (a confident disposition forced to
`inconclusive`). The judge therefore grades the *committed* disposition, which is
not always the one the policy chose. The judge's outcome
(`caught | survived | undecidable | …`) is a sparse, per-episode *reward signal*
— and like all sparse rewards, it's hard to credit-assign back to the specific
decision that earned it. The lessons corpus is a low-bandwidth *policy update*:
instead of gradient steps on weights, we get curated text injected at PLAN time.
Things to borrow from RL practice:

- *Reward shaping over outcome-only rewards.* The judge's findings are
  intermediate signal — "this lead set never reached the system holding the
  deciding fact" — that we credit-assign by hand into a lesson. Without it, we'd
  be trying to learn from `caught/survived` alone, which is exactly the regime RL
  practitioners avoid when they can.
- *Counterfactual credit assignment, not off-policy replay.* The old loop's
  claim here was off-policy evaluation: score a counterfactual without
  re-executing the defender. That was the claim the oracle could not support,
  because the counterfactual's observations were invented. The branched episode
  gives up the cheapness and **re-executes** — each sibling is a real
  investigation against a staged corpus — and buys back an intervention whose
  effect is attributable, because exactly one fact was changed and the estate
  ledger records every answer served under it.
- *Distribution shift.* Lessons authored from yesterday's cases bias the policy
  on today's cases. The same drift pathology that haunts offline-RL haunts us —
  keep an eye on whether lessons that helped on past fixtures hurt on new ones,
  and prefer a held-out eval set the curator has never seen (`evals/held_out.py`).
- *Reward hacking.* If the judge's rubric has a loophole, the defender will find
  it. The forward-check gate (`author/verify_forward/`) is the structural answer
  for promotion: a candidate lesson has to keep the source case on its
  ground-truth disposition before it is committed. The judge's prompt is part of
  the reward function and should be audited as such.

**Ablation studies.** The sharper analogy for the current shape. A family is a
control world plus one-axis interventions, and the measurement is the defender's
*sensitivity* to each axis. This imports the discipline of ablation directly:

- *One axis per arm.* A world that varies two things is unattributable — a
  changed answer says nothing about either. The questioner is held to it, and
  the review step rejects a world whose declared difference cannot be reached by
  any query.
- *A control that is genuinely the same.* World A is the capture itself,
  replayed unchanged. Without it, "the defender said malicious in both worlds"
  cannot be told apart from "the branch itself perturbed the run."
- *A refused arm invalidates the experiment, not just the arm.* A world that
  contradicts the capture ends the whole episode before any sibling starts,
  because a family with a broken arm is a comparison over an unknown baseline.

**Evolutionary / population-based methods.** The lessons corpus is a *population*
of candidate behaviors. Authoring a new lesson is *mutation*; the curator's
merge / supersede / skip decisions are *selection*. The defender at runtime
samples from this population (reads the lesson bodies whose descriptions look
relevant). Things to borrow:

- *Diversity matters.* A monoculture of similar lessons covers one failure mode
  well and misses the rest. The curator's job is partly diversity preservation —
  supersede when a new lesson genuinely obsoletes an old one, otherwise keep both.
- *Niching by relevance description.* Lessons compete for PLAN-time attention.
  The frontmatter `description` is the niche tag — the defender only reads the
  body if the description fires on the current alert shape. This makes the corpus
  scale sublinearly with size, but only if descriptions are crisp.
- *Fitness ≠ proxy fitness.* The proxy fitness we optimize is "the defender's
  verdict tracks the deciding fact across a staged family." True fitness is
  "triage quality on real production alerts." Periodically sanity-check that the
  proxy still tracks.

**What the cutover gave up: self-play.** The old actor was adversarial against
the defender's prior runs, which made the loop a (one-sided) autocurriculum — as
the defender improved, the surviving stories had to slip through tighter lead
sets. The branched episode has no adversary at all; its difficulty comes from
the case distribution, not from an opponent that adapts. That is a deliberate
trade: an autocurriculum over invented material advances against a proxy nobody
can audit. Co-evolution is a future enhancement (below), and its prerequisite is
that the branched loop is demonstrably moving the needle first.

**Where the analogy breaks.** We are not running gradient descent. There is no
continuous parameter space, no smooth loss surface, no guarantee that "more
lessons" monotonically improves anything. The update mechanism is text edits
curated by an LLM, with all the discontinuity that implies. Expect non-monotonic
improvement and budget for regression-detection accordingly.

## References

- Sutton & Barto, *Reinforcement Learning: An Introduction* — for the policy /
  reward / credit-assignment vocabulary used above.
- Pearl, *Causality* — the intervention-vs-observation distinction the branched
  episode turns on: the family is a `do()` on one fact, not a story about it.
- Lehman & Stanley, *Abandoning Objectives: Evolution Through the Search for
  Novelty Alone* — the diversity-preservation argument.
- Sculley et al., *Hidden Technical Debt in Machine Learning Systems* — for the
  failure modes of feedback loops in production ML; many apply once a lesson
  corpus starts feeding back into the runtime.

## Design Principles

1. **Offline only.** No live latency cost. No production gating. A finished run
   is not fed anywhere automatically; it is a starting point an operator picks up
   later, deliberately, by naming it.
2. **Learn from evidence a run actually received.** Every observation the judge
   reads was served to a real `run.py` process and recorded in that world's
   estate ledger. Nothing in the loop authors telemetry.
3. **One outcome per episode, one bucket per world.** The judge emits one episode
   outcome (`gradable | discard | corpus-contradiction`) plus, per world, at most
   one mechanical bucket and the findings grounded against it. There is no
   additive scoring model.
4. **Concrete observables only.** A lesson must name a specific field, artifact,
   system-of-record query, or analysis discipline failure. Abstract advice is
   rejected by the curator or the forward-check gate.
5. **Git history as the audit trail.** Each curator edits only its own corpus,
   commits from its own worktree off `origin/main`, and opens one PR per batch.
   The loop is the sole committer; spawned agents run no git.
6. **No addendum library, no index, no service.** The lesson corpus is flat
   markdown, and retrieval is grep over frontmatter — there is no index to build
   and nothing to keep in sync. Two pushes read it: the PLAN-time signature block
   (`runtime/orient.py`), and — since #919 — the FRONTIER block on the write that
   moved the document's open set (`scripts/lessons/lessons_frontier.py`, keyed on
   the optional `frontier_nodes` / `frontier_edges` selectors). Both walk the same
   flat corpus on demand.

## Loop Shape

```text
Completed run dir
(alert.json + investigation.md + report.md + executed_queries.jsonl + gather_raw/)
        │
        ▼
defender/learning/branch/cli.py <run_dir> <branch_message_id>
        │
        ├── 1. preflight        — everything that can refuse before anything is spent
        ├── 2. questioner       — family.yaml: a control world + one-axis counterfactuals
        ├── 3. staging          — each world's corpus into its own namespace
        ├── 4. review by replay — the captured query set through each world; any
        │                         rejection ends the EPISODE, so no sibling starts
        ├── 5. the family       — each accepted world as its own `run.py --resume`
        ├── 6. archive          — episodes/<id>/worlds/<label>/, self-contained
        └── 7. judge            — judge.yaml + findings appended to
                                  learning/_pending/findings.jsonl
                       │
                       ▼
defender/learning/loop.py --author-drain   (at LEARNING_AUTHOR_THRESHOLD)
        │
        ├── lock + clean-scope + idempotency + ground-truth gates
        ├── new/fold/skip lesson edits under defender/lessons/
        ├── forward-check per candidate edit
        └── commit from a worktree + open one PR + rotate the queue
```

`--lead-author-drain` is the sibling stage on the same shape: it curates the
gather query catalog and the per-system skills from its own queues, and opens its
own PR.

## The Branched Episode

`learning/branch/cli.py` is the composition root. The operator names two things —
a source run and the message to branch at — and the module decides the order
everything else happens in, which is the part no seam can enforce about itself.

### 1. Preflight

Everything that can refuse before anything is spent, asked in one place: the
branch point is in range, the source alert is a plain file, the configured corpus
patterns can carry a view name, the write door reaches the cluster, the sweep of
this episode's own namespace completes, and every registered role has a usable
model. A refusal here costs no model call, no staged name and no primed capture.

### 2. The questioner

`learning/branch/questioner/` is a **deny-all** role: it runs no tools, its whole
input is inlined in its prompt by the host, and its whole output is one YAML
manifest (`family.yaml`). It authors:

- **The discriminator** — the fact the verdict turns on, the system that holds it,
  and the query that would establish it. Everything downstream is scored against
  it. A discriminator naming something no single query could settle makes the
  episode unreadable however good the worlds are.
- **The family** — world A, the capture unchanged (the control), plus the
  counterfactual worlds, one declared axis each.

The manifest is validated into a `Family` and held to one identity gate over the
whole document before anything is staged.

### 3. Staging

`learning/branch/staging.py` + `branch/estate/` write each world's corpus into its
own namespace, every name write-ahead-recorded in `staged.yaml` *before* it is
created, so teardown can find what a crashed run left behind.

**The namespace prefix is deliberately not spelled here, and must not be added.**
A sibling is a real investigation whose model can read `defender/docs/`, and the
isolation guarantee is that the fault channel is the *only* way that scheme could
be learned — a world that knows how staged names are spelled can recognise it is
in a staged world, which is the one thing the measurement cannot survive. The
prefix, the label template and the world labels are all held out of every
prompt-reachable tree; `tests/test_947_triplet_isolation.py` sweeps
`defender/{docs,skills,knowledge}` for them on every run. Read the constant in
`branch/staging.py` if you need it. The staged estate
is what a sibling's queries are answered from: it answers for the world the run is
in, not for the real environment.

`branch/ledger.py` records **every response the estate served**, with the decision
behind it (`staged`, `patched`, `captured`, `refused`, …). The ledger is what makes
the difference between worlds checkable rather than asserted, and it is the judge's
primary evidence.

### 4. Review by replay

The captured query set is replayed through each world before any sibling runs, and
two questions are asked per world.

**Does this world contradict the capture?** World A — the control — is replayed
**first**, and the keys *it* mismatches on are the estate's own drift between the
source run and now. Those keys are subtracted from every other world's result, so
what is left for the counterfactual arms is a difference the *world* made rather
than a difference the environment made while nobody was looking. Without that
subtraction, ordinary drift would read as a contradiction and reject healthy
episodes.

**Is the declared difference observable at all?** The manifest's discriminating
envelope is run in the world. An injection nothing retrieves, a patch that applies
to nothing, and an exclusion that removes no base document are each a world that is
not the world it claims to be. Nothing has run yet, so these cost nothing to catch
here and are unattributable later.

Either failure **rejects the whole episode** — no sibling starts. A family with one
broken arm is a comparison over an unknown baseline, so the honest outcome is no
measurement rather than a partial one.

The comparison itself is **blind by signature** (`branch/comparator.py`): the
function takes two payloads and an axis, and nothing else. It cannot see which side
is the base, which world produced a payload, or what disposition a world declared —
because a comparator that could would have a verdict predictable from the label,
and the label is precisely what the measurement is supposed to be independent of.
The same function serves the review here and `delta_o` on the read side.

### 5. The family as processes

Each accepted world runs as its own `run.py --resume` **child process**, started
together, under `{episode_dir}/runs/` — never beside the source run and never
under the operator's runs base. The launcher drives no investigation in its own
process and has no path to one. Being a process is what gets a sibling the box
lifecycle, the reap scan, its own role preflight and its own provenance stamp.

### 6. Archive

`learning/branch/archive.py` copies each world into `episodes/<id>/worlds/<label>/`
so that later readers answer from the episode directory alone — the sibling run
dirs are disposable. An archived world carries the report, the investigation
document, the two tables (`executed_queries.jsonl` + `gather_raw/`), its own
provenance stamp, its scrub verdict, the lessons it loaded, the alert, its gather
summaries, and a **text pointer** naming the run dir the bytes came from. The
pointer is informational: never a symlink, and nothing follows it.

Every sibling's scrub verdict and provenance stamp is checked; agreeing stamps
write the family stamp, and anything else marks the episode `incomplete` — a
modelled outcome with a reason in `review.yaml`, not the absence of a file. The
derived readers (`branch/episode.py`: `verdicts`, `delta_o`) refuse an
`incomplete` episode, so "no differences" and "no comparison was possible" stay
different answers.

## The Judge

`learning/judge/` grades one archived episode. It runs under the questioner's
agent definition with an `agent_id` prefix of `judge:` — `AgentRole.JUDGE` was
bound to the retired pipeline's judge and #922 freed the key; #1008 is where this
role claims it. Model and effort come from `JUDGE_MODEL` / `JUDGE_EFFORT`.

Per `accepted` episode with no existing `judge.yaml`:

1. **The mechanical pass** (`judge/family.py`) — five facts per non-control world,
   read off *that world's own* archived record: its own served ledger, its own
   report and investigation document, and the manifest. Never a sibling's ledger,
   never a comparator call. A fault in the **manifest** refuses the whole pass; a
   fault in **one world's archive** marks that world `ungradable` (with `malformed:
   true` when the artifact is present and wrong) and its siblings still grade.

   The mechanical bucket, per non-control world X, where H is the family's
   validated holding system:

   | condition | bucket |
   |---|---|
   | no row on H at all | `lead-set` |
   | rows on H exist, none `staged`/`patched`, no `refused` row on H | `lead-quality` |
   | a `refused` or `fault`-adjacent H interaction, no doctored answer served | no bucket |
   | a doctored answer served, verdict == declared | no bucket |
   | a doctored answer served, no resolution moved, verdict != declared | `analyze-discipline` |
   | a doctored answer served, a resolution moved, verdict != declared | `decision-discipline` |

   These are the four places a verdict can lose the deciding fact: never asked for
   it, asked wrongly, received it and reasoned past it, established it and did not
   let it move the verdict.

2. **The model pass** (`judge/render.py` + `judge/run.py`) — one call per graded
   world per draw (`JUDGE_DRAWS`, default **1**), each written to
   `worlds/<X>/judge/<n>.yaml`. A draw that fails does not unwind the pass; the
   completed draws still count.

3. **The episode outcome** — `gradable`, `discard` (the measurement was spoilt) or
   `corpus-contradiction` (the archive disagrees with itself), decided from the
   review record and this pass's own draws. `discard` is decided
   mechanical-first and before any world's corpus-contradiction, so the answer
   does not depend on manifest order.

4. **Enqueue** (`judge/enqueue.py`) — for a `gradable` episode only, one row per
   surviving finding into `learning/_pending/findings.jsonl`. `discard` and
   `corpus-contradiction` enqueue nothing: the family record is the artifact for
   those two. A model-authored finding with an empty anchor is dropped and named
   on the report — one unusable finding is not a reason to discard every other
   world's good ones.

5. **`episodes/<id>/judge.yaml`** — written **last**, after the enqueue, carrying
   the enqueued row count and every world's completed-draw count, so its presence
   certifies the whole pass.

Queueable finding types are `lead-set`, `lead-quality`, `analyze-discipline`,
`observability` and `decision-discipline` (`core/config.py`
`QUEUEABLE_FINDING_TYPES`). The first four are the buckets a lesson can be
authored from historically; `decision-discipline` is the family judge's own.

## Lesson Delivery

### Pipeline

1. **Enqueue** — the judge appends queueable findings as JSONL to
   `defender/learning/_pending/findings.jsonl`.
2. **Threshold** — when the pending count reaches `LEARNING_AUTHOR_THRESHOLD`
   (default 5), the drain invokes the lessons curator
   (`learning/author/lessons/run.py`). `loop.py --author-drain` is the entry point;
   `core/drains.py` `_curator_queue_checks` is the one place the wakeable channels
   are named, and since #922 it names **one**.
3. **Pre-flight** — the curator takes the queue lock, requires `defender/lessons/`
   to be git-clean, filters already-authored findings via each lesson's
   `source_finding_ids`, and **holds** findings whose source disposition carries no
   ground truth (`inconclusive` or missing) — the forward-check needs one.
4. **Curator agent** — receives the remaining findings, enumerates existing
   `defender/lessons/*.md`, and decides `new`, `fold`, or `skip`. Lesson files are
   flat markdown with frontmatter: `name`, `description`, `source_finding_ids`,
   `created_at`.
5. **Forward-check** — after each new or folded lesson edit, `author/verify_forward/`
   re-runs the candidate lesson against its source-case transcript and that case's
   ground-truth disposition, asking whether the agent — with the lesson loaded at
   PLAN — would *still* reach that disposition. `GOOD` keeps the edit; `BAD` reverts
   it and leaves the finding held for later review.
6. **Commit + post-flight** — the curator commits surviving lesson edits from its
   own worktree and opens a PR. Before the commit, every file this tick left CHANGED
   in the corpus must also be **attributable**: it has to cite at least one id from
   this batch's committed set under `source_finding_ids` (#852). The commit is
   pathspec-wide, so without that a lesson the forward-check rejected would ride into
   history on a batch-mate that passed. An already-committed file whose provenance
   list is byte-identical to HEAD's is exempt — a supersede's `status: stale` flip and
   a reverted forward-BAD fold claim no new source, so they vouch for nothing and need
   no voucher. Then the queue rotates atomically: consumed findings append to
   `_pending/consumed.jsonl`, and held/skip batches log to
   `_pending/findings.held_report.log` on every tick that held or skipped a row,
   whether or not the same tick also committed.

### Why Lessons, Not an Addendum Library

- Git history is the audit trail. No separate lessons manifest to maintain.
- Lessons land in the same `defender/lessons/` corpus the runtime investigator
  already reads. No retrieval service and no index — the two pushes (PLAN-time
  signature, and the #919 frontier block on a write that moved the open set) are
  both a walk of that flat corpus, composed by the runtime at the moment they fire.

### Citation requirement

Each judge finding is grounded against the archived episode — the world's own
served ledger, report and investigation document — and the anchor is checked
before the row is queued. The curator can rewrite the lesson for future use, but
should not invent evidence. The durable lesson-to-source link is the
`source_finding_ids` frontmatter list plus the consumed queue record.

## One corpus, one queue

The old loop ran two directions and fed three corpora — defender findings into
`lessons/`, plus actor and environment observations into their own. Only the
first has a producer after the cutover, so the other two retired with the
pipeline. There is now **one** authored corpus, `defender/lessons/`, fed by **one**
queue, drained by **one** curator (plus the lead-author lane, which curates the
gather catalog and system skills rather than lessons).

`defender/lessons-actor/` and `defender/lessons-environment/` still exist on disk
as **frozen archives**: their authored lessons are left in place, nothing produces
them and nothing reads them. They are shown as retired in the posture view
(`learning/frontend/`) rather than deleted or hidden.

The canonical enumeration of the queues and their thresholds is
`learning/core/config.py` and `core/drains.py`.

## Sampling Policy

There is no scheduler or sampling layer. The API is manual:
`defender/learning/branch/cli.py <run_dir> <branch_message_id>`.

- **Which runs get branched** is an operator choice. The disposition no longer
  routes anything — the direction table that used to select which stages ran was
  deleted with the pipeline.
- **Which turn to branch at** is the operator's other choice, and it is the
  measurement's main lever: `runtime/branch.py` decides which messages may be
  branched from and where the fork lands.
- **Curator promotion** proceeds only for findings whose source case has a
  ground-truth disposition; `inconclusive` sources are held, because the
  forward-check gate needs one.

## Artifacts

```text
$DEFENDER_EPISODES_BASE/<episode_id>/
  family.yaml                 # the questioner's manifest — the contract every sibling re-parses
  staged.yaml                 # write-ahead record of every staged name, for teardown
  review.yaml                 # per-world accept/reject + the episode's recorded outcome
  provenance.json             # the family stamp, written only when every sibling's agrees
  served/base.jsonl           # the capture, primed before staging
  served/<world_token>.jsonl  # every response the estate served that world, with its decision
  worlds/<label>/
    report.md  investigation.md  alert.json  provenance.json
    executed_queries.jsonl  gather_raw/  gather_summaries/
    lessons_loaded.jsonl  scrub_verdict.json  run_dir   # `run_dir` is a text pointer, not a link
    judge/<n>.yaml            # one per judge draw
  runs/                       # the siblings' live run dirs (disposable)
  judge.yaml                  # written last; its presence certifies the whole pass

defender/learning/_pending/
  findings.jsonl              # the one queue
  consumed.jsonl              # consumed committed/idempotent/skipped findings
  findings.held_report.log    # held/skip summaries per tick

defender/lessons/
  *.md                        # committed pitfall lessons read at PLAN time
```

**`learning/runs/` is an orphan.** It holds per-case directories the deleted
pipeline's persist step wrote, and `ops/trace_lesson.py` still scans it to answer
"which cases was this lesson in context for". Nothing writes it any more, so that
answer only covers cases from before the cutover and silently stops growing.
Re-pointing the tracer at `episodes/` is unfinished work, not a decision.

## Evaluation

- **Queue yield**: findings appended per episode, by mechanical bucket.
- **Episode disposition**: `gradable` vs `discard` vs `corpus-contradiction`, and
  the rejection rate at review-by-replay — a family that rarely survives its own
  replay means the questioner is authoring unreachable differences.
- **Draw agreement**: bucket spread across a world's `JUDGE_DRAWS` draws. A world
  whose draws disagree is a judge-prompt problem, not a defender finding. At the
  default of one draw this is not measured at all — raising `JUDGE_DRAWS` is how
  you find out whether a grade was stable.
- **Forward-check pass rate**: candidate lesson edits marked `GOOD` vs `BAD`, with
  manual review of BAD holds.
- **Curator disposition**: committed vs folded vs skipped vs held-forward-bad vs
  held-no-ground-truth.
- **North star**: `evals/held_out.py` — correct-disposition rate on cases the
  curator has never seen. The frozen-actor replay and the judge A/B that used to
  sit here retired with the pipeline they measured.

## Future Enhancements

### Live self-evaluation loop

The live investigator may eventually run a same-context self-review before commit
that asks: "what counter-disposition story explains the same observations, and is
there one cheap missing check?" This is separate from the offline learning loop.
Offline learning should continue to run against the investigation as it actually
happened, regardless of whether live self-evaluation fired.

Keep this future loop small: it should surface a missing check or force an
escalation when the case is underdetermined, not become a second full investigator
or a source of post-hoc rationalization.

### Automated branch-point selection

Today an operator names the turn to branch at, and that choice largely determines
what the episode can measure. A cheap heuristic pass over a finished run — the
turn at which the open set last narrowed, say — would make the loop schedulable
without giving up the property that every episode forks a real run.

### Co-evolution (a learning adversary)

The cutover removed the adversary, and with it the autocurriculum. If it comes
back it should be on the branched loop's terms: an adversary that authors *worlds*
(staged corpora the defender must still read correctly), not stories — so its
output stays something a real run can be executed against.

Caveats from the RL/evo literature apply double. Co-evolution is notoriously prone
to **cycling** (defender learns to beat adversary v3, adversary v4 rediscovers
v1's tricks), to **arms-race drift** away from realistic alerts, and to **Red Queen
dynamics** where both sides get more capable on synthetic cases without either
gaining on real ones. Mitigations to design in from day one:

- Hold a fixed set of historical families as a regression suite; the live
  adversary must continue to surface them, not just the ones the live curator
  currently rewards.
- Periodically re-run the defender against a *frozen* prior adversary to detect
  overfitting to the current one.
- Anchor on real production alerts as ground truth — the proxy fitness must
  continue to track true fitness.

**Prerequisite.** Don't build this until the one-sided loop is demonstrably moving
the needle on real cases. A learning adversary adds a second moving part to a
system whose first moving part isn't yet proven.

## Open Questions

- Where does shared knowledge live when a lesson recurs across signatures? The
  current answer is still a flat `defender/lessons/` file that broadens its
  `description`; if that becomes too coarse, do we add tags or subdirs?
- Should the lessons curator see prior accepted lesson commits as exemplars? If
  yes, how to avoid drift toward a single editing style.
- How many worlds is a family worth? Three is what ships. More arms buy more axes
  per branch but multiply the run cost and the chance one arm rejects and voids
  the episode.
- `JUDGE_MODEL` / `JUDGE_EFFORT` are read by two unrelated judges — the family
  judge here and the golden-case eval judge (`evals/oracle_golden/judge.py`) —
  so setting either retargets both. That collision is inherited, not designed
  (`judge/run.py` still explains it against the pipeline judge #922 deleted).
  Separating them means a knob name of the family judge's own: a deliberate
  change, not a side effect.
