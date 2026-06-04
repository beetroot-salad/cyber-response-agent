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

1. **Normalize** — read and validate the disposition from `report.md`
   frontmatter (`benign | inconclusive | malicious`); it selects which
   direction(s) run (see §Two directions).
2. **Project** — turn `lead_sequence.yaml` into an actor-facing view of what
   the investigation looked at.
3. **Actor** (`actor.md`, gray-box adversarial) — given the alert + lead set
   + an `actor_archetype` (`internal` / `external`) + a `mitre_menu` (a
   12-technique subset sampled from `mitre_corpus.py`), writes a candidate
   attack story citing the techniques used in a Section 0 table. The seed is
   derived from the run id, so the menu + archetype are reproducible per
   case. Can short-circuit with **SKIP** when no coherent story fits the
   menu — required when a causal step the story needs (e.g. initial access)
   has no covering technique to cite from it.
4. **Telemetry oracle** (`oracle.md`) — synthesizes the per-lead events the
   actor's story would have produced. It sits *between* actor and judge so
   the judge isn't grading its own imagination.
5. **Judge** (`judge.md`) — classifies the outcome and emits findings.
   The adversarial outcome is one of: `caught` | `survived` | `undecidable`
   | `incoherent` | `skip-passthrough`. The benign direction (§Two
   directions) uses the mirror enum: `caught` becomes `refuted` — the
   defender's evidence refuted the actor's legitimate-activity story, so the
   escalation was justified (the analog of adversarial `caught`). The other
   four labels are shared, and `survived` carries the mirror meaning across
   both directions — "the defender failed to handle the story" (a missed
   attack / FN-risk adversarially, a routine operation escalated past /
   FP-risk here). See `_loop_config.py` and `judge_benign.md`.
6. **Persist + queue** — write artifacts under `defender/learning/runs/` and
   append queueable findings to `_pending/findings.jsonl`.
   `detection-confirmed` findings are audit-only (they don't queue — the
   investigation already worked).
7. **Author + forward-check gate** — once `_pending` reaches
   `LEARNING_AUTHOR_THRESHOLD` (default **5**), the lessons curator
   (`author.{md,py}`) folds the queued findings into `defender/lessons/*.md`.
   After each new or folded lesson edit, and *before* committing, it runs the
   forward-check (`verify_forward.{md,py}`): a **same-case regression gate**
   that re-runs the candidate *lesson* against its source-case transcript and
   that case's ground-truth disposition, asking whether the agent — with the
   lesson loaded at PLAN — would *still* reach that disposition. `GOOD` keeps
   the edit and it commits; `BAD` (the lesson would flip a correctly-resolved
   case off its disposition) reverts it. The gate needs a ground-truth
   disposition, so `inconclusive` source cases are held rather than authored.

## How lessons feed back

The runtime-facing output of the loop is the `defender/lessons/` corpus (the
defender-findings corpus from §Two directions; the `lessons-actor/` /
`lessons-environment/` corpora are direction-specific and consumed elsewhere).
At **PLAN** time the runtime agent enumerates `defender/lessons/*.md`, reads
each file's
frontmatter `description:`, and Reads the body of any lesson that looks
relevant to the current alert shape — *before* writing its `:H`/`:L` blocks.
Bodies are short and teach what to *check next time*, not what conclusion to
reach. That's the loop closing: a gap the actor exploited in one run becomes
a lesson the next run reads. See `content/knowledge-and-skills.md` §Lessons.

## Two directions

The pipeline above is the **adversarial** direction — it hunts false
negatives (what would an attacker have done that this investigation missed?),
and feeds the audit-only `detection-confirmed` type when the investigation
already caught the attack. There is a parallel **benign** direction
(`actor_benign.md`, `author_actor_benign.md`, with its own `_pending` queue)
that hunts false positives (could legitimate activity have produced this
picture?).

The **disposition selects which direction(s) run** (`_loop_orchestrate.py`
`_directions_for`, gating on the `ADVERSARIAL_DISPOSITIONS` /
`BENIGN_DISPOSITIONS` sets in `_loop_config.py`):

| Disposition | Directions run |
|---|---|
| `benign` | adversarial only — hunt the missed attack (FN) |
| `malicious` | benign only — hunt the over-escalation (FP) |
| `inconclusive` | both directions |

`malicious` is **not** skipped — it is exactly what triggers the benign,
FP-hunting leg.

Each leg emits two kinds of output on **separate** queue → author → corpus
pipelines — don't assume one shared `lessons/`:

- **Defender findings** (the judge findings about the *investigation*, steps
  5–7 above) → `_pending/findings.jsonl`, which **both** directions append to
  (tagged `direction`) → `author.py` at `LEARNING_AUTHOR_THRESHOLD` (default
  **5**) → `defender/lessons/`. This is the corpus the runtime agent reads at
  PLAN.
- **Direction-specific observations** (about the actor / environment, not the
  defender's moves) → a per-direction queue + curator: the adversarial leg
  feeds `_pending/actor_observations.jsonl` → `author_actor.py`
  (`LEARNING_AUTHOR_ACTOR_THRESHOLD`) → `defender/lessons-actor/`; the benign
  leg feeds `_pending/environment_observations.jsonl` →
  `author_actor_benign.py` (`LEARNING_AUTHOR_ENV_THRESHOLD`) →
  `defender/lessons-environment/`.

So "both directions feed the same corpus" holds only for defender findings;
the actor/environment corpora are direction-specific. The canonical
enumeration of queues, thresholds, dispositions, and finding types is
`defender/learning/_loop_config.py` and `_loop_orchestrate.py`.

## Why a forward-check gate but no runtime validators

The defender has no runtime safety gates by design (`content/design.md`),
but the *learning* loop does gate — the forward-check confirms a candidate
lesson would **not** flip its own source case off the correct disposition
before it's allowed into the corpus. It's a same-case regression check (does
this lesson still resolve the case it came from?), not a "does this finding
bite?" test. The asymmetry is deliberate: a bad lesson is durable (it shapes
every future run), so the offline path earns a verification step that the
fast online path does not.

## Evaluating the loop itself

`defender/learning/eval/` is the harness-on-the-harness — `harness.py` plus
`scenarios/` for evaluating the learning loop. The held-out / secondary eval
drivers (`eval_held_out.py`, `eval_secondary.py`) and the `judge-alignment/`
calibration set live alongside it, directly under `defender/learning/`.
`defender/tests/` covers
learning-loop invariants (lesson schema, author pre/post-flight, atomic
writes, forward-check) — the guarantees not enforced by a hook.

Sources: `defender/CLAUDE.md` §Learning loop, `defender/learning/loop.py`,
`defender/learning/_loop_config.py`, `defender/docs/learning-loop.md`.
