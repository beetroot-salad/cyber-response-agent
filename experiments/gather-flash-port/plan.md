# gather on GLM 5.3 Flash vs DeepSeek V4.1 Flash — the Kimi K2.6 replacement

Fireworks decommissions Kimi K2.6 serverless on **2026-09-25**. Kimi K2.6 is gather's
default. GLM 5.2 goes on the same date; the three learning-loop roles on it move to GLM 5.3
without a test (they run at `medium`), outside this experiment.

## Question

**Engineering** — which of `glm-5.3-flash` and `deepseek-v4.1-flash` replaces `kimi-k2.6`
as the gather default: does either hold Kimi's per-dispatch summary fidelity and completion
rate at a lower gather bill, and if both do, which is better?

The unit of analysis is a **gather dispatch** (one lead → one summary), not a run. A run
yields ~4–8 of them, and the variable touches only gather; MAIN and the review gate are
constant noise both arms share.

## Variants

One variable: `DEFENDER_GATHER_MODEL`. Set via env, never `--model` (`--model` moves MAIN
and the review gate together). MAIN stays on its `glm-5.3` default, review on `kimi-k3`.

### current (regression validator)
```
DEFENDER_GATHER_MODEL=kimi-k2.6          # reasoning off (gather's shipped effort = none)
```
### glm-flash
```
DEFENDER_GATHER_MODEL=glm-5.3-flash      # provider clamps effort none → low (thinking-only model)
```
### ds-flash
```
DEFENDER_GATHER_MODEL=deepseek-v4.1-flash   # reasoning off — probed 2026-09-11, 0 reasoning tokens
```

The GLM arm's `low` is not a second variable I chose: it is the clamp the provider already
applies to a thinking-only model, i.e. a property of the model. It *is* a regime difference
and `analyze.py` reports reasoning tokens separately so the cost line shows where it lands.

**Prep before validation (code, needed by the port regardless of the winner):**
1. Aliases `glm-5.3-flash` → `accounts/fireworks/models/glm-5p3-flash` and
   `deepseek-v4.1-flash` → `accounts/fireworks/models/deepseek-v4p1-flash` in the Fireworks
   alias map. (The `fireworks:` passthrough works today, but the runtime's per-call cost
   would bill V4.1 at $0 — the table's honest "unknown" — and every trace would read wrong.)
2. A price row for `deepseek-v4.1-flash`. Fireworks has not published one; the docs page
   still lists only V4 Flash 0731 and routes the old name to V4.1. **Provisionally the 0731
   row ($0.22 / $0.007 / $0.66), flagged in the row comment**; re-check the pricing page
   before the final write-up and re-price from the token counts if it moved.

### Prior evidence, so the plan doesn't pretend to start cold
- `invlang-clerk-986` arms D/E (n=3, clerk role, not gather): GLM 5.3 Flash fixed validator
  refusals in 1.6 rounds vs DeepSeek **V4** Flash's 2.7, took no bait, judged better 5–2–2.
  Stale in one respect: that was V4 Flash 0731, and V4.1 Flash is claimed to beat V4 Pro.
- `glm53-container-attribution/runs/glm53-flashgather-{2,low-1}`: two whole runs with GLM
  5.3 Flash already as gather (09-09 Falco alert). Both completed and closed
  `malicious / stands`, 5 and 7 summaries, 4 and 3 query errors of 26/29. `flashgather-1`
  died on the `none` refusal — the #1023 crash the clamp now prevents. So GLM Flash gather
  runs to completion; nothing is known yet about its fidelity, and nothing about V4.1.

## Fixtures

Two past alerts from `invlang-clerk-986`, reused as-is (each has `alert.json` + `label.yaml`):

- `fixtures/F1-off-hours-sudo/` → `../invlang-clerk-986/fixtures/F1-off-hours-sudo/`
  (`v2-off-hours-sudo`, 2026-08-30T09:59Z, **benign** by construction). Exercises the
  ES|QL auth/sudo path and the change-management verbs; 4–6 gather dispatches per run.
- `fixtures/F2-authorized-keys/` → `../invlang-clerk-986/fixtures/F2-authorized-keys/`
  (`v2-falco-authorized-keys-modification`, 2026-07-28T16:16Z, **malicious** by
  construction). Falco + container-resolution path; the alert names only the Docker host,
  so gather has to pivot through the container id — the dispatch shape where a weak
  summary costs MAIN the case.

Load-bearing for the variable: both fixtures produce dispatches across ≥2 systems of record
with multi-row payloads to condense, so summary fidelity has room to differ.

**Shape-current check is part of validation, not assumed.** The playground was restored
from the 08-12 snapshot on 09-01; if ES no longer holds the events around either window
(gather payloads empty on every arm), swap that fixture for
`../glm53-container-attribution/fixtures/alert.json` (captured live 09-09, same Falco
detection type as F2, no label file — disposition then reported against the prior runs'
`malicious` rather than a label).

**Not hermetic.** Runs query the live playground; baseline generators add drift between
trials. Query windows anchor on the alert timestamp, which bounds it. Noise all arms share.

## Trials

Validation: 1 per arm per fixture (6 runs). Confirms the two aliases resolve, the review
gate stayed `kimi-k3`, the GLM arm ran at `low` and the DeepSeek arm at `none` (read off the
wire log), payloads are non-empty, and `analyze.py` extracts every metric.

Scale-up: **N=5 runs per arm per fixture = 30 runs, ≈150 gather dispatches (~50/arm)**.
Roughly 12–16 min and $0.5–0.9 per run, 3 concurrent (one per arm, staggered 25 s as
`invlang-clerk-986/run_arm.sh` does) → ~2.5 h wall, ~$20 in runs plus ~$10 of judge.

Mid-run analysis after **3 per arm on F1 (9 runs, 30%)**: run `analyze.py`, decide
continue / abort / adjust. Abort conditions: an arm with completion < 80% on F1 (the model
can't run gather's tool loop — no point spending F2 on it), or a fixture returning empty
payloads (shape drift — swap the fixture first).

Analysis script: `experiments/gather-flash-port/analyze.py`, **written before scale-up**.
One row per gather dispatch, from the run dir:

| metric | source | why |
|---|---|---|
| `completed` | `gather_summaries/{lead}.md` exists | primary reliability — a dispatch that hits the 40-request limit or dies on `UnexpectedModelBehavior` gives MAIN nothing |
| `fidelity` | LLM judge (`claude-opus-5`, blind to arm) scores each `what_to_summarize` dimension **exact / wrong / dropped** against the payloads gather itself retrieved (`gather_raw/{lead}/*.json`, capped at 60 KB/dispatch via the same view the model read), plus **unsupported**: a measurement the summary states that no payload contains | primary quality — the #289 rubric, ground truth = the dispatch's own payloads |
| `requests`, `retries`, `queries`, `query_errors` | wire log (`agent_id=gather:*`), retry-prompt parts, `executed_queries.jsonl` `exit_code` | how hard the model works the loop; retries = shape corrections absorbed |
| `gather $`, cached share, reasoning tokens | wire log usage × `defender.scripts.pricing` | cost, and where the GLM `low` clamp lands |
| `wall` per dispatch; parallel overlap | first/last wire-log timestamp per `gather:*` | the capacity question — GLM 5.3 Flash has no priority tier on Fireworks |

Per run: leads dispatched (does MAIN plan more leads when summaries are weaker — the open
question `invlang-clerk-986` left), disposition vs label, concluded, review outcome.

Ranking: per-dispatch mean with `n` shown; per-run figures likewise. No count-weighting.

## Decision criteria

Define **error rate** = (wrong + dropped + unsupported) / dimensions, per dispatch.

- **A flash arm is acceptable** if, over ≥40 dispatches: completion ≥ current − 5 points;
  error rate ≤ current + 5 points; unsupported rate ≤ current (no new hallucination
  class); gather $ per dispatch ≤ 50% of current.
- **Between two acceptable arms:** the lower error rate wins if the gap is ≥ 5 points;
  otherwise the cheaper per dispatch wins — unless its per-dispatch wall under parallel
  dispatch is ≥ 1.5× the other's, in which case the faster one (capacity is a real cost).
- **Exactly one acceptable:** it ships.
- **Neither acceptable:** gather moves to `glm-5.3` (non-flash, `low`) as the stop-gap
  before 09-25 — ~10× the flash input price, but no capability question — and the flash
  question reopens with a prompt fix if the failure is a shape the prompt can teach.
- **`current` retained** is not an outcome available after 09-25; the regression arm is here
  to put a number on what the port costs in quality, not to be kept.

## Layout

```
experiments/gather-flash-port/
  plan.md
  variants/            # the three env lines above, one file per arm
  fixtures/            # symlinks to the two invlang-clerk-986 fixtures
  runs/{arm}-{fixture}-t{n}/ + manifest.jsonl + per-run logs   (DEFENDER_RUNS_BASE here)
  run_trials.sh        # adapted from invlang-clerk-986 (arm → DEFENDER_GATHER_MODEL)
  analyze.py           # before scale-up
  results/             # extractions/ (judge cache), mid-run.md, final.md
```

## Validation outcome & adjustments (2026-09-11)

Six runs, all concluded, models confirmed per arm off the wire log (MAIN `glm-5p3` in every
run; gather `kimi-k2p6` / `glm-5p3-flash` / `deepseek-v4p1-flash`; GLM at `low` — reasoning
tokens present — the other two at `none` — zero). Both fixture windows still hold their events
on the 09-09 snapshot (F1: 867 Falco / 33.9k logs in the alert hour; F2: 3.0k / 94k). Table in
`results/validation.md`. Two extractor fixes before scale-up, both to `analyze.py`:

1. **Retries were counted once per request they were replayed in.** The wire log writes one
   record per history message per turn, so a correction recurs in every later record of the
   dispatch (80 counted, 12 real on one Kimi dispatch). Now deduped by tool-call id.
2. **The judge's ground truth was the saved payload files; it is now every tool return the
   model saw.** Adapters return error text (an HTTP 404 body, "host not found") that gather
   reads and reports but that lands in no payload file, so the first pass flagged those as
   unsupported in every arm (Kimi 0.7/dispatch → 0.3 after the fix). The residual calls are
   real: miscounted sums, a wrong time gap, an attribution the rows don't make.

Also seen, not changed: the harness's own context lead (`l-00c`, request limit 8) hits its
limit in every arm on F2 — a fixed budget, shared noise, reported as `terminated=request_limit`
and excluded from fidelity like any cut-short dispatch.

Trial `t0` of each arm is configured identically to the scale-up trials and is kept in the
final N (so N=6 per arm per fixture if all scale-up trials complete).

## Outcome (2026-09-11) — see `results/final.md`

**GLM 5.3 Flash ships as the gather default.** Passes every bar with room: 97% completion
(Kimi 78%), 13% error (17%), equal unsupported, 7% of the cost. DeepSeek V4.1 Flash fails the
unsupported bar 4× over (0.83/dispatch vs 0.21) and the error bar (34%). Cut at 27/30 runs by
an intermittent Fireworks 412 spending-limit suspension. Run-level: with GLM summaries MAIN's
verdict missed the label 9/9 (confident `malicious` on benign F1, `inconclusive` on attack
F2); pairwise judging says GLM-arm records are the better-earned on F2 (5–1–3) and the worse
on F1 (5–20–5) — both fixtures' known contamination, cutting both ways. Follow-up filed: a
clean held-out fixture before the F1 over-commit is read as gather's doing.
