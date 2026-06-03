# Learning loop

The offline, self-improving pipeline — the defender's headlining
experiment. It runs in-process after the runtime loop exits (skip with
`--no-learn`) and can also run standalone:
`python3 defender/learning/loop.py <run_dir>`.

The orchestrator is `defender/learning/loop.py` (and the `_loop_*.py`
modules it composes). Each stage is a paired prompt + driver in
`defender/learning/` (`actor.md` + driver, `judge.md` + driver, etc.). For
the *why* — the RL / evolutionary-algorithms framing — read
`defender/docs/learning-loop.md`.

## The pipeline (adversarial direction)

1. **Normalize** — read the disposition from `report.md` frontmatter. Skips
   `malicious` at MVP (story already confirmed, nothing to learn).
2. **Project** — turn `lead_sequence.yaml` into an actor-facing view of what
   the investigation looked at.
3. **Actor** (`actor.md`, gray-box adversarial) — given the alert + lead set
   + an `actor_archetype` (`internal` / `external`) + a `mitre_menu` (a
   12-technique subset sampled from `mitre_corpus.py`), writes a candidate
   attack story citing the techniques used in a Section 0 table. The seed is
   derived from the run id, so the menu + archetype are reproducible per
   case. Can short-circuit with **SKIP** — required when the menu lacks an
   Initial Access technique for the archetype.
4. **Telemetry oracle** (`oracle.md`) — synthesizes the per-lead events the
   actor's story would have produced. It sits *between* actor and judge so
   the judge isn't grading its own imagination.
5. **Judge** (`judge.md`) — classifies the outcome and emits findings.
   Outcome is one of: `caught` | `survived` | `undecidable` | `incoherent`
   | `skip-passthrough`.
6. **Forward-check gate** (`verify_forward.{md,py}`) — re-runs each queued
   finding against the actor story to confirm it actually *bites* before it
   reaches the queue. A finding that doesn't change the outcome is dropped.
7. **Persist + queue** — write artifacts under `defender/learning/runs/` and
   append queueable findings to `_pending/findings.jsonl`.
   `detection-confirmed` findings are audit-only (they don't queue — the
   investigation already worked).
8. **Author** (`author.{md,py}`) — once `_pending` reaches
   `LEARNING_AUTHOR_THRESHOLD` (default **5**), the lessons curator folds the
   queued findings into `defender/lessons/*.md` and commits.

## How lessons feed back

The output of the loop is the `lessons/` corpus. At **PLAN** time the
runtime agent enumerates `defender/lessons/*.md`, reads each file's
frontmatter `description:`, and Reads the body of any lesson that looks
relevant to the current alert shape — *before* writing its `:H`/`:L` blocks.
Bodies are short and teach what to *check next time*, not what conclusion to
reach. That's the loop closing: a gap the actor exploited in one run becomes
a lesson the next run reads. See `content/knowledge-and-skills.md` §Lessons.

## Two directions

The pipeline above is the **adversarial** direction — it runs on
`inconclusive` (and feeds the audit-only `detection-confirmed` type when the
investigation already caught the attack). There is a parallel **benign**
direction (`actor_benign.md`, `author_actor_benign.md`, with its own
`_pending` queue) that probes the false-positive side. Both directions feed
`lessons/` through the same author mechanism. The canonical enumeration of
queues, thresholds, and finding types is `defender/learning/_loop_config.py`
and `_loop_orchestrate.py`.

## Why a forward-check gate but no runtime validators

The defender has no runtime safety gates by design (`content/design.md`),
but the *learning* loop does gate — the forward-check confirms a finding
actually changes the adversarial outcome before it's allowed to mint a
lesson. The asymmetry is deliberate: a bad lesson is durable (it shapes
every future run), so the offline path earns a verification step that the
fast online path does not.

## Evaluating the loop itself

`defender/learning/eval/` is the harness-on-the-harness — scenarios for
evaluating the learning loop, plus `eval_held_out.py` / `eval_secondary.py`
and the `judge-alignment/` calibration set. `defender/tests/` covers
learning-loop invariants (lesson schema, author pre/post-flight, atomic
writes, forward-check) — the guarantees not enforced by a hook.

Sources: `defender/CLAUDE.md` §Learning loop, `defender/learning/loop.py`,
`defender/learning/_loop_config.py`, `defender/docs/learning-loop.md`.
