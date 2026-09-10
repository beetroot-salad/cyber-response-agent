# Investigation Review and Learning Loop

## Status

**Implementation cache; code wins on conflict.** The loop exists under
`defender/learning/` as branched episode (`branch/cli.py`) → questioner
(`branch/questioner/`) → staged estate (`branch/estate/`) → review by replay
(`branch/review.py`) → the family as `run.py --resume` processes → judge
(`judge/`) → findings queue → lessons curator (`author/lessons/`) with a
per-lesson forward-check (`author/verify_forward/`) → `defender/lessons/*.md`.

**Rewritten for #922.** This doc used to describe a four-role pipeline — two
actors, a telemetry oracle, a judge — that invented the material it learned
from. `git show e9e11a48` is the account of the deletion and its reasoning;
`docs/archive/learning-loop-experiments-2026-05-08.md` keeps the empirical
findings from the old shape. Two things that change how a *current* file reads,
so they are recorded here rather than left in the commit:

- **The `lessons-actor/` and `lessons-environment/` corpora were not deleted,
  only their producers were.** The directories and their authored lessons stay
  on disk as frozen archives — see §One corpus, one queue.
- **The defender's own report card moved rather than went.** It lived inside the
  deleted judge visualizer and now renders in `runtime.html`'s headline. There is
  no judge view; #1025 tracks the one the branched-episode judge needs.

Dead names from that pipeline (`actor_story.md`, `projected_telemetry.yaml`,
`run_cycle.py`, `lead_sequence.yaml`, …) still appear in superseded design docs,
the judge-alignment corpus and old run-visualization dirs. Each of those files
carries a status banner; the names resolve to nothing in shipping code.

The loop is offline and operator-initiated. Each curator commits from its own
git worktree off `origin/main` and opens one PR per batch.

## Purpose

Ask of a finished real investigation the question reading it cannot answer:
**was the verdict driven by the evidence, or would it have survived evidence
pointing somewhere else?**

The mechanism is a **counterfactual re-run, not a counterfactual story.** The
investigation is stopped at a chosen turn and restarted several times — one
sibling against the world as it was, the others against worlds differing by one
authored fact. Every sibling shares the same history, alert and partial
reasoning up to the branch point, and diverges only in what the evidence says.
Comparing their conclusions localizes the failure: a defender reaching the same
verdict in a world where the deciding fact is *different* was not reading that
fact, and the comparison says where it lost it — never queried the system
holding it, queried at the wrong scope, received it and reasoned past it, or
established it and did not let it move the verdict.

That last distinction is why the loop was rebuilt. The old pipeline graded
against telemetry a model had imagined, so a finding could never be stronger
than the imagination behind it.

## Inspirations

**Reinforcement learning.** The runtime defender is the *policy*; its ORIENT →
PLAN → GATHER → ANALYZE → REPORT trajectory is an *episode* the review gate can
extend or whose terminal action it can override — so the judge grades the
*committed* disposition, not always the one the policy chose. The judge's
outcome is a sparse per-episode *reward*, hard to credit-assign. The lessons
corpus is a low-bandwidth *policy update*: curated text at PLAN time instead of
gradient steps. What to borrow:

- *Reward shaping.* The judge's findings are intermediate signal — "this lead
  set never reached the system holding the deciding fact" — credit-assigned by
  hand into a lesson. Without it we learn from `caught/survived` alone.
- *Counterfactual credit assignment, not off-policy replay.* The old loop's
  claim here was off-policy evaluation: score a counterfactual without
  re-executing. That is exactly the claim the oracle could not support, because
  the counterfactual's observations were invented. The branched episode gives up
  the cheapness, **re-executes**, and buys an intervention whose effect is
  attributable — one fact changed, and the estate ledger records every answer
  served under it.
- *Distribution shift.* Lessons from yesterday's cases bias today's. Prefer a
  held-out set the curator has never seen (`evals/held_out.py`).
- *Reward hacking.* The forward-check is the structural answer for promotion: a
  lesson must keep its source case on its ground-truth disposition. The judge's
  prompt is part of the reward function; audit it as such.

**Ablation studies** — the sharper analogy. A family is a control plus one-axis
interventions, measuring the defender's *sensitivity* to each axis. One axis per
arm, or a changed answer says nothing about either. A control that is genuinely
the same, or "same verdict in both worlds" cannot be told from "the branch
perturbed the run". And a refused arm invalidates the *experiment*, not just the
arm — a family with a broken arm is a comparison over an unknown baseline.

**What the cutover gave up: self-play.** The old actor was adversarial against
the defender's prior runs, making the loop a one-sided autocurriculum. The
branched episode has no adversary; its difficulty comes from the case
distribution. A deliberate trade — an autocurriculum over invented material
advances against a proxy nobody can audit.

**Where the analogy breaks.** No gradient descent, no continuous parameter
space, no guarantee that "more lessons" improves anything. Expect non-monotonic
improvement and budget for regression detection.

References: Sutton & Barto (policy/reward vocabulary); Pearl, *Causality* (the
intervention-vs-observation distinction the family turns on — a `do()` on one
fact, not a story about it); Lehman & Stanley (diversity preservation); Sculley
et al. (feedback-loop debt, which starts accruing once lessons feed back).

## Design Principles

1. **Offline only.** A finished run is not fed anywhere automatically; it is a
   starting point someone names later.
2. **Learn from evidence a run actually received.** Every observation the judge
   reads was served to a real `run.py` process and recorded in that world's
   ledger. Nothing in the loop authors telemetry.
3. **One outcome per episode, one bucket per world.** No additive scoring.
4. **Concrete observables only.** A lesson names a field, artifact, query, or
   analysis-discipline failure. Abstract advice is rejected by the curator or
   the forward-check.
5. **Git history as the audit trail.** The loop is the sole committer; spawned
   agents run no git.
6. **No index, no service.** Flat markdown, grep over frontmatter. Two pushes
   read it: the PLAN-time signature block (`runtime/orient.py`) and the #919
   frontier block on a write that moved the open set
   (`scripts/lessons/lessons_frontier.py`).

## Loop Shape

```text
Completed run dir (alert.json + investigation.md + report.md
                   + executed_queries.jsonl + gather_raw/)
        │
        ▼
defender/learning/branch/cli.py <run_dir> <branch_message_id>
        ├── 1. preflight        — everything that can refuse before anything is spent
        ├── 2. questioner       — family.yaml: a control world + one-axis counterfactuals
        ├── 3. staging          — each world's corpus into its own namespace
        ├── 4. review by replay — any rejection ends the EPISODE; no sibling starts
        ├── 5. the family       — each accepted world as its own `run.py --resume`
        ├── 6. archive          — episodes/<id>/worlds/<label>/, self-contained
        └── 7. judge            — judge.yaml + findings → learning/_pending/findings.jsonl
        │
        ▼
defender/learning/loop.py --author-drain   (at LEARNING_AUTHOR_THRESHOLD)
        ├── lock + clean-scope + idempotency + ground-truth gates
        ├── new/fold/skip lesson edits under defender/lessons/
        ├── forward-check per candidate edit
        └── commit from a worktree + open one PR + rotate the queue
```

`--lead-author-drain` is the sibling stage on the same shape, curating the
gather query catalog and per-system skills from its own queues.

## The Branched Episode

`branch/cli.py` is the composition root: the operator names a source run and a
message to branch at, and this module decides the ORDER everything else happens
in — the part no seam can enforce about itself.

**1. Preflight.** Everything that can refuse before anything is spent, in one
place: branch point in range, source alert a plain file, corpus patterns able to
carry a view name, write door reaching the cluster, namespace sweep complete,
every role holding a usable model.

**2. The questioner** (`branch/questioner/`) is a **deny-all** role — no tools,
its whole input inlined by the host, its whole output one YAML manifest. It
authors the **discriminator** (the fact the verdict turns on, the system holding
it, the query that would establish it — a discriminator no single query could
settle makes the episode unreadable however good the worlds are) and the
**family** (world A, the capture unchanged, plus one-axis counterfactuals).

**3. Staging** (`branch/staging.py`, `estate/`) writes each world's corpus into
its own namespace, every name write-ahead-recorded in `staged.yaml` *before* it
is created, so teardown finds what a crashed run left behind. `branch/ledger.py`
records every response the estate served with the decision behind it — what
makes the difference between worlds checkable rather than asserted.

> **The namespace prefix is deliberately not spelled in this tree, and must not
> be added.** A sibling is a real investigation whose model can read
> `defender/docs/`; the isolation guarantee is that the fault channel is the
> *only* way that scheme could be learned, because a world that knows it is
> staged is not answering the question the family was built to ask.
> `tests/test_947_triplet_isolation.py` sweeps `defender/{docs,skills,knowledge}`
> for the prefix, the label template and world labels on every run.

**4. Review by replay** asks two questions per world before any sibling runs.
*Does this world contradict the capture?* World A — the control — replays
**first**, and the keys it mismatches on are the estate's own drift since the
source run; those are subtracted from every other world's result, so what is
left is a difference the *world* made. Without that subtraction, ordinary drift
reads as contradiction and rejects healthy episodes. *Is the declared difference
observable at all?* An injection nothing retrieves, a patch applying to nothing,
an exclusion removing no document — each is a world that is not the world it
claims. Either failure **rejects the whole episode**.

The comparison is **blind by signature** (`branch/comparator.py`): two payloads
and an axis, nothing else. It cannot see which side is the base or what a world
declared — a comparator that could would have a verdict predictable from the
label, and the label is what the measurement must be independent of. The same
function serves the review and `delta_o` on the read side.

**5. The family as processes.** Each accepted world runs as its own `run.py
--resume` **child process**, started together under `{episode_dir}/runs/`. The
launcher drives no investigation in its own process and has no path to one:
being a process is what gets a sibling the box lifecycle, the reap scan, its own
role preflight and its own provenance stamp.

**6. Archive** (`branch/archive.py`) copies each world into
`episodes/<id>/worlds/<label>/` so later readers answer from the episode
directory alone — sibling run dirs are disposable. Every sibling's scrub verdict
and provenance stamp is checked; agreeing stamps write the family stamp, and
anything else marks the episode `incomplete` — a modelled outcome with a reason,
not a missing file. The derived readers (`branch/episode.py`) refuse an
`incomplete` episode, so "no differences" and "no comparison was possible" stay
different answers.

## The Judge

`learning/judge/` grades one archived episode under its own `AgentRole.JUDGE`
definition (#1008), with an `agent_id` prefix of `judge:`. It borrowed the
questioner's definition until then, which is why some older prose pairs the two.

1. **Mechanical pass** (`judge/family.py`) — five facts per non-control world,
   read off *that world's own* archived record: its own ledger, report and
   investigation document, plus the manifest. Never a sibling's, never a
   comparator call. A manifest fault refuses the whole pass; a fault in one
   world's archive marks that world `ungradable` and its siblings still grade.

   The bucket, per non-control world, where H is the validated holding system:

   | condition | bucket |
   |---|---|
   | no row on H at all | `lead-set` |
   | rows on H, none `staged`/`patched`, no `refused` row on H | `lead-quality` |
   | a `refused`/`fault`-adjacent H interaction, nothing doctored served | no bucket |
   | doctored answer served, verdict == declared | no bucket |
   | doctored answer served, no resolution moved, verdict != declared | `analyze-discipline` |
   | doctored answer served, a resolution moved, verdict != declared | `decision-discipline` |

   These are the four places a verdict can lose the deciding fact.

2. **Model pass** — one call per graded world per draw (`JUDGE_DRAWS`, default
   **1**) into `worlds/<X>/judge/<n>.yaml`. A failed draw does not unwind the
   pass.

3. **Episode outcome** — `gradable`, `discard` (measurement spoilt) or
   `corpus-contradiction` (archive disagrees with itself). `discard` is decided
   mechanical-first and before any world's contradiction, so the answer does not
   depend on manifest order.

4. **Enqueue** (`judge/enqueue.py`) — for `gradable` only, one row per surviving
   finding. `discard`/`corpus-contradiction` enqueue nothing: the family record
   is the artifact. A finding with an empty anchor is dropped and named on the
   report rather than discarding its siblings' good ones.

5. **`judge.yaml`** — written **last**, carrying enqueued row count and per-world
   completed draws, so its presence certifies the whole pass.

Queueable types: `lead-set`, `lead-quality`, `analyze-discipline`,
`observability`, `decision-discipline` (`core/config.py`).

## Lesson Delivery

1. **Threshold** — at `LEARNING_AUTHOR_THRESHOLD` (default 5) AUTHORABLE queued
   findings the drain invokes `author/lessons/run.py`. Any row carrying
   `held_reason` is not counted (#881): the pre-author gate's own holds are
   permanent — the facts they wait on have no writer — so counting them woke the
   drain every tick to hold the same rows again. The stamp is sticky and the
   count does not distinguish, so a *forward-check* hold (step 4) is uncounted
   too even though the next tick would retry it. `core/drains.py`
   `_curator_queue_checks` is the one place wakeable channels are named, and
   since #922 it names **one**.
2. **Pre-flight** — queue lock, `defender/lessons/` git-clean, findings already
   authored filtered by `source_finding_ids`, and findings whose source carries
   no ground truth **held** (the forward-check needs one).
3. **Curator** — decides `new`, `fold`, or `skip` over flat markdown with `name`,
   `description`, `source_finding_ids`, `created_at`.
4. **Forward-check** — re-runs the candidate lesson against its source-case
   transcript and ground-truth disposition: would the agent, with the lesson
   loaded at PLAN, *still* reach that disposition? `GOOD` keeps, `BAD` reverts
   and holds the finding.
5. **Commit + post-flight** — commits from its own worktree and opens a PR. Every
   file left CHANGED must be **attributable** — citing an id from this batch's
   committed set (#852) — because the commit is pathspec-wide, so without it a
   forward-check-rejected lesson rides in on a batch-mate that passed. A file
   whose provenance list is byte-identical to HEAD's is exempt: a supersede's
   `status: stale` flip and a reverted fold claim no new source. Then the queue
   rotates atomically, consumed rows append to `consumed.jsonl`, and held/skip
   batches log to `findings.held_report.log`.

Findings are grounded against the archived episode and the anchor is checked
before queueing. The durable lesson-to-source link is `source_finding_ids` plus
the consumed queue record.

## One corpus, one queue

The old loop ran two directions into three corpora. Only `defender/lessons/` has
a producer now, fed by **one** queue and drained by **one** curator (plus the
lead-author lane, which curates the catalog and system skills).

`defender/lessons-actor/` and `defender/lessons-environment/` remain on disk as
**frozen archives** — nothing produces them, nothing reads them. The posture view
(`learning/frontend/`) marks them retired rather than deleting or hiding them.

Canonical enumeration: `core/config.py` and `core/drains.py`.

## Sampling Policy

Manual. **Which runs get branched** is an operator choice — the disposition
routes nothing now, the direction table having gone with the pipeline. **Which
turn to branch at** is the measurement's main lever (`runtime/branch.py` decides
which messages may be branched from). **Curator promotion** proceeds only for
findings whose source case has a ground truth.

## Artifacts

```text
$DEFENDER_EPISODES_BASE/<episode_id>/
  family.yaml                 # the questioner's manifest — every sibling re-parses it
  staged.yaml                 # write-ahead record of every staged name, for teardown
  review.yaml                 # per-world accept/reject + the episode's recorded outcome
  provenance.json             # the family stamp, only when every sibling's agrees
  served/base.jsonl           # the capture, primed before staging
  served/<world_token>.jsonl  # every response served that world, with its decision
  worlds/<label>/
    report.md  investigation.md  alert.json  provenance.json
    executed_queries.jsonl  gather_raw/  gather_summaries/
    lessons_loaded.jsonl  scrub_verdict.json  run_dir   # a text pointer, not a link
    judge/<n>.yaml            # one per judge draw
  runs/                       # the siblings' live run dirs (disposable)
  judge.yaml                  # written last; its presence certifies the pass

defender/learning/_pending/{findings,consumed}.jsonl + findings.held_report.log
defender/lessons/*.md         # committed lessons read at PLAN time
```

**`learning/runs/` is an orphan.** It holds per-case directories the deleted
pipeline's persist step wrote, and `ops/trace_lesson.py` still scans it to answer
"which cases was this lesson in context for" — so that answer covers only
pre-cutover cases and silently stops growing. Re-pointing the tracer at
`episodes/` is unfinished work, not a decision.

## Evaluation

- **Queue yield** per episode, by bucket.
- **Episode disposition** and the rejection rate at review-by-replay — a family
  that rarely survives its own replay means the questioner is authoring
  unreachable differences.
- **Draw agreement** across `JUDGE_DRAWS`. At the default of one draw this is not
  measured; raising it is how you learn whether a grade was stable.
- **Forward-check pass rate**, with manual review of BAD holds.
- **North star**: `evals/held_out.py`. The frozen-actor replay and judge A/B
  retired with the pipeline they measured.

## Future Enhancements

**Live self-evaluation.** A same-context pre-commit self-review asking "what
counter-disposition story explains the same observations, and is there one cheap
missing check?" Separate from offline learning, which must keep running against
the investigation as it actually happened. Keep it small: surface a missing check
or force an escalation, don't become a second investigator.

**Automated branch-point selection.** The operator's choice of turn largely
determines what an episode can measure. A cheap heuristic — the turn at which the
open set last narrowed, say — would make the loop schedulable without giving up
forking a real run.

**Co-evolution.** If an adversary returns it should author *worlds* (staged
corpora the defender must still read correctly), not stories, so its output stays
executable. Co-evolution is prone to cycling, arms-race drift, and Red Queen
dynamics where both sides improve on synthetic cases and neither on real ones —
so hold a fixed set of historical families as a regression suite, periodically
re-run against a frozen prior adversary, and anchor on real alerts. Prerequisite:
the one-sided loop demonstrably moving the needle first.

## Open Questions

- Where does shared knowledge live when a lesson recurs across signatures? Today
  a flat file broadening its `description`; if that goes coarse, tags or subdirs?
- Should the curator see prior accepted lesson commits as exemplars, and how to
  avoid drift toward one editing style?
- How many worlds is a family worth? Three ships. More arms buy more axes but
  multiply run cost and the chance one arm rejects and voids the episode.
- `JUDGE_MODEL` / `JUDGE_EFFORT` are read by two unrelated judges — this one and
  the golden-case eval judge (`evals/oracle_golden/judge.py`) — so setting either
  retargets both. Inherited, not designed; separating them means a knob name of
  this judge's own.
