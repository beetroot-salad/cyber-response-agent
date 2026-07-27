# Results — judge model A/B, GLM 5.2 vs Kimi K3

**n=2, validation only.** One fresh alert (`ssh-brute-force-canary --seed 42`), disposition
`inconclusive`, so direction dispatch fired both legs and one run supplied both cases:
`case-001` adversarial (FN axis) and `case-002` benign (FP axis). No statistical claim is
available at this scale and none is made below.

## Recommendation

**Do not port yet, and do not read this as a defence of GLM 5.2.** The run did not fail to
find a difference between the two models — it found that *the incumbent's run-to-run variance
is larger than any model difference this design can resolve*. That is a finding about the
judge stage, not about K3, and it blocks the port decision either way.

Two things are settled and one is not:

| Question | Answer |
|---|---|
| Does K3 satisfy the judge's structured-output contract? | **Yes** — `cand_parse_failure_rate` 0%, `cand_punt_rate` 0%. This was the main wiring risk and it is cleared. |
| What does K3 cost? | **Unanswerable from public pricing** — the honest range spans 15×. See below. |
| Is K3 a better judge? | **Not established.** Suggestive, not shown. See the adjudication caveat. |

## 1. The incumbent is not self-consistent — this is the headline

`run_judge_ab.py` runs the reference twice (`ref-a`, `ref-b`) to establish the noise floor.
GLM 5.2 at `medium` disagreed **with itself on both cases**, and both disagreements land on
the `caught↔survived` / `refuted↔survived` axis — the one the harness singles out as
"systematic" because it drives FN/FP accounting and decides which findings become lessons.

| case | direction | ref-a (glm-5.2) | ref-b (glm-5.2) | cand (kimi-k3) |
|---|---|---|---|---|
| 001 | adversarial | `survived` | `caught` | `caught` |
| 002 | benign | `refuted` | `survived` | `refuted` |

**Self-consistency floor: 0%.** The harness's summary — `outcome-match 50%`, `1 flip`,
"WITHIN the noise floor" — is arithmetically correct and carries no information: a candidate
cannot be measured against a reference that is a coin flip on the exact axis under test.
K3 agrees with exactly one GLM rep on each case, which is what a random draw looks like.

This matters well beyond the port question. The judge is the loop's ground truth; its
`outcome` drives FN/FP accounting and its `defender_findings` become the lessons the author
trains on. A judge that returns `survived` or `caught` at random on the same frozen input is
injecting label noise into training, and the forward-check gate cannot catch it because that
gate re-runs the same stochastic judge.

Caveat on scale: this is 2 cases. The floor is 0/2, not a measured rate. But 0/2 on the
gating axis is enough to say the floor must be characterised properly before any model
comparison at this stage is interpretable.

## 2. Cost — cannot be answered from public pricing

Cache reads are **86% of the judge's tokens** (611,328 of 710,930 for the K3 arm), and
Fireworks publishes no cache-read rate for K3 at either quoted SKU. That single unpublished
number moves cost by 15×:

| K3 in/out hypothesis | cache read $0.00 | $0.30 | $0.60 | $0.95 | $3.00 |
|---|---|---|---|---|---|
| $3.00 / $15.00 (1M ctx) | $0.2634 | **$0.3551** | $0.4468 | $0.5538 | $1.1804 |
| $0.95 / $4.00 (262k) | $0.0763 | $0.1680 | $0.2597 | **$0.3667** | $0.9933 |

per judge invocation; double for a learning cycle (adversarial + benign legs).
Reference: **glm-5.2 $0.2306/invocation** at its published $0.14 cache-read rate.

The bolded cells are the two hypotheses `pricing.py` and `analyze.py` carry; the rest is the
sensitivity that makes the point. K3 is anywhere from **3× cheaper to 5× more expensive**
than GLM depending on a number nobody has published. `pricing.py` carries the conservative
$3/$15 with cache_r $0.30 so accounting cannot silently understate; the billing dashboard
after this run is what settles it.

Measured token counts, per invocation (mean of 2):

| arm | model responses | in | out | cache read |
|---|---|---|---|---|
| ref-a glm-5.2 | 17.5 | 72,680 | 14,966 | 449,651 |
| ref-b glm-5.2 | 21.5 | 79,415 | 20,953 | 593,219 |
| cand kimi-k3 | 13.5 | 40,301 | 9,501 | 305,664 |

K3 reached its verdicts in consistently fewer turns and fewer tokens. On equal per-token
pricing it would be the cheaper arm; the pricing is not equal and is not known.

## 3. Adjudication — suggestive, and undercut by the adjudicator itself

Because `outcome_match` at n=2 can only be 0/50/100%, Opus adjudicated the paired verdict
text blind (`A`/`B`, no model names, arms swapped between pairings). Since GLM disagreed with
itself, "the reference" has no single referent, so each K3 verdict was adjudicated against
**both** GLM reps.

| pairing | winner |
|---|---|
| case-001 vs ref-a | glm-5.2 |
| case-001 vs ref-b | **kimi-k3** |
| case-002 vs ref-a | **kimi-k3** |
| case-002 vs ref-b | **kimi-k3** |

K3 wins 3 of 4, and it is not position bias — K3 was presented first in two pairings and
second in two, winning twice in the first slot and once in the second.

**The caveat that limits this result.** On case-001 the adjudicator contradicted itself
about what the correct outcome even is:

- vs ref-a: *"Correct outcome: **survived**."*
- vs ref-b: *"Both reach `caught`, which is right."*

It agreed with whichever verdict(s) it was shown. That is anchoring, not independent
judgement, and it means case-001's two adjudications cannot both be trusted — the one K3
loss and one of its wins are on that unstable case. On case-002 Opus called `refuted`
consistently in both pairings and gave substantive, differentiated reasons.

So the defensible claim is narrower than 3/4: **on the one case where the adjudicator was
self-consistent, K3 beat both GLM reps** — reaching the outcome Opus independently
considered correct, where ref-b did not, and grounding its findings better than ref-a, which
reached the same outcome. Recurring in Opus's reasoning across pairings: both models attach
citations that do not carry the claims made on them, and K3 does it less.

## 4. What to do next

1. **Characterise the judge's noise floor before comparing models at all.** ≥5 reps of the
   incumbent over ≥8 cases. If the 0/2 here reflects the real rate, the finding is that the
   judge stage needs stabilising (higher effort, a tightened rubric, self-consistency
   sampling with a majority vote) — a much larger win than any model swap, and a prerequisite
   for measuring one.
2. **Settle K3's price from the billing dashboard** for this run. Everything else about cost
   is guesswork.
3. **Re-run the comparison only once the floor is known**, at the plan's original 8 cases, with
   an adjudicator that states its own outcome *before* seeing either verdict — the anchoring
   above is a fixable prompt defect (`adjudicate.py` currently shows both verdicts up front).

## Run artifacts

```
fixtures/case-001, case-002   frozen judge inputs (run_dir/ excludes llm_requests.jsonl — no judge input reads it)
minted_alert/                 the alert this run was minted from
runs/{ref-a,ref-b,cand}/      per-arm judge traces
results/ab-report.md          the harness's own report
results/cost.json             per-invocation token + cost record
results/adjudication/         prompts, Opus adjudications, blind-label mapping
snapshot_cases.py             LEARN output → frozen case layout
analyze.py                    traces → tokens, cost, price sensitivity
adjudicate.py                 blind paired adjudication
```

## Known fixture defect (does not affect the comparison)

The alert is a **threshold** rule, and `mint_alert.py` drops `kibana.alert.threshold_result`
— so the defender was handed an alert missing the grouping and count that actually fired it.
`experiments/oracle-telemetry-fidelity/extract_alert.py` preserves that field deliberately
("a threshold rule's evidence IS its grouping + count"); `mint_alert.py` predates that fix.

All three arms saw the identical alert, so this does not bias the A/B — it makes the *case*
less faithful than the alert that fired, not the comparison unfair. It cannot be corrected
now without re-minting against a live lab.

The handoff logged these two scripts as duplicates to collapse. They are not duplicates:
they differ in transport (SSH + `docker exec` vs `infra/bin/es.sh`), target index, CLI shape,
and this field. `extract_alert.py` is the better of the two; the fix is to retire
`mint_alert.py` in favour of it plus a transport flag, not to merge them.

## Deviations from the plan

- **Effort held at `medium` for both arms**, per plan; this required passing `--ref-effort
  medium` explicitly, since the harness defaults `--ref-effort low`.
- **`LEARNING_SUBAGENT_TIMEOUT_SECONDS=1800`** for the A/B. At the shipped 450s, GLM 5.2 at
  `medium` **timed out on the adversarial leg of the LEARN run** for this same case
  (886,917 tokens, 20 responses, 29 bash + 12 read_file calls, no verdict). Raising it was
  necessary so neither arm was truncated by the clock — but note that the incumbent failing to
  complete a real run at production settings is itself a finding, and it is the same case
  whose verdict GLM then flipped on.
- **Curator thresholds raised to 100000** for the LEARN run so re-processing a run for an
  experiment could not trip a lessons-authoring PR.
- **Adjudicator runs without `ANTHROPIC_API_KEY`.** The repo's metered first-party key is out
  of credit; the CLI falls back to the interactive claude.ai login. The actor stages default
  to a Claude model and will hit the same wall on the next LEARN.
