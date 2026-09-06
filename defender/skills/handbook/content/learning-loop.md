# Learning loop

The offline, self-improving loop — the defender's headlining experiment. It
does **not** run in-process after an investigation: a finished run is a
starting point an operator picks up later, deliberately, by naming it.

```
python3 defender/learning/branch/cli.py <run_dir> <branch_message_id>
```

For the *why* — the RL / evolutionary-algorithms framing — read
`defender/docs/learning-loop.md`. For what changed and when, read
`defender/docs/learning-loop-cutover.md`.

## What replaced what (#922)

Until the cutover the loop authored its own material: an **actor** invented a
candidate story about the alert, an **oracle** invented the telemetry that
story would have produced, and a **judge** graded the defender against both.
Everything the loop learned from was therefore imagined, and the judge was
grading a world no system had ever answered for.

That pipeline is **deleted**. Nothing under `defender/learning/pipeline/`
exists; neither do the `actor`, `oracle` and `judge` agent roles, the
disposition→direction routing, or the `lessons-actor/` and
`lessons-environment/` corpora that the actor-side curators fed.

What runs now branches a **real** investigation instead of inventing one.

## The branched episode

1. **Fork** — an operator names a finished run and a message to rewind to.
   Everything the defender had concluded past that point is discarded; what
   it had *observed* up to it is kept.
2. **Question** (`learning/branch/questioner/`) — a deny-all role reads the
   captured past and authors a **family** of sibling worlds that differ from
   the base by one deliberate fact. Its whole input is inlined in its prompt
   by the host and its whole output is one YAML manifest; it runs no tools.
3. **Stage** (`learning/branch/staging.py`, `estate/`) — each world's corpus
   is written into its own namespace, every name recorded before it is
   created. This is what a sibling's queries are answered from: the estate
   answers for the world the run is in, not for the real environment.
4. **Review by replay** — the captured query set is replayed through each
   world. A world that contradicts the capture, or whose declared difference
   no query could reach, is rejected — and a rejected world ends the whole
   episode, so no sibling starts.
5. **Run the family** — each accepted world runs as its own
   `run.py --resume` process, started together, under the episode.
6. **Judge** (`learning/judge/`) — grades the archived episode: a mechanical
   pass per world, then one model call per world per draw. The episode comes
   out `gradable`, `discard` (the measurement was spoilt) or
   `corpus-contradiction` (the archive disagrees with itself).
7. **Enqueue** — a gradable episode's surviving findings are appended to
   `_pending/findings.jsonl`, the same queue the curators have always read.

## How lessons feed back

Unchanged by the cutover, and it is the joint the whole thing swings on. The
runtime-facing output is the `defender/lessons/` corpus. Once the findings
queue reaches `LEARNING_AUTHOR_THRESHOLD` (default **5**), the lessons
curator folds the queued rows into `defender/lessons/*.md`:

```
python3 defender/learning/loop.py --author-drain
```

Every edit passes the **forward-check** before it commits
(`author/verify_forward/`): a same-case regression gate that re-runs the
candidate lesson against its source-case transcript and that case's
ground-truth disposition, asking whether the agent — with the lesson loaded
at PLAN — would *still* reach that disposition. `GOOD` keeps the edit; `BAD`
reverts it. The gate needs a ground truth, so `inconclusive` source cases are
held rather than authored.

At **PLAN** time the runtime agent enumerates `defender/lessons/*.md`, reads
each file's frontmatter `description:`, and reads the body of any lesson that
looks relevant to the current alert shape — before writing its `:H`/`:L`
blocks. Bodies teach what to *check next time*, not what conclusion to reach.
That is the loop closing. See `content/knowledge-and-skills.md` §Lessons.

`--lead-author-drain` is the sibling stage on the same shape: it curates the
gather query catalog and the per-system skills, and opens its own PR.

## One corpus, one queue

The old loop ran two directions and fed three corpora — defender findings
into `lessons/`, plus actor and environment observations into their own. Only
the first had a producer after the cutover, so the other two retired with the
pipeline. There is now **one** authored corpus, `defender/lessons/`, fed by
**one** queue, drained by **one** curator.

The canonical enumeration of the queues and their thresholds is
`defender/learning/core/config.py` and `core/drains.py`.

## Why a forward-check gate but no runtime validators

The defender has no runtime safety gates by design (`content/design.md`), but
the *learning* loop does gate — the forward-check confirms a candidate lesson
would not flip its own source case off the correct disposition before it is
allowed into the corpus. The asymmetry is deliberate: a bad lesson is durable
(it shapes every future run), so the offline path earns a verification step
that the fast online path does not.

## Evaluating the loop itself

`defender/evals/` is the eval home: the held-out metric driver
(`held_out.py`, the north-star) plus the harness-on-the-harness
(`harness.py` + `scenarios/`). The `judge-alignment/` calibration set lives
under `defender/learning/`. `defender/tests/` covers learning-loop
invariants.

Sources: `defender/CLAUDE.md` §Learning loop, `defender/learning/branch/cli.py`,
`defender/learning/judge/`, `defender/learning/core/drains.py`,
`defender/docs/learning-loop.md`, `defender/docs/learning-loop-cutover.md`.
