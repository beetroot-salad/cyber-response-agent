# Arm D — clerk on DeepSeek V4 Flash, F1 (benign), n=3

Same design, prompt and 6-round budget as arm C; only the clerk's model changes
(`accounts/fireworks/models/deepseek-v4-flash-0731`; Fireworks serverless Standard $0.22 /
$0.007 cached / $0.66 out per M — a quarter of kimi-k2.6. **Correction:** the first version
of this file priced it from the training-API table, 8× too high; every $ below is at the
inference price, re-scored from the same wire logs.)
Run 2026-09-01 13:30–14:08Z, three concurrent. Score rows in `final.jsonl`; judge in
`judge-F1-AD.jsonl` (vs current) and `judge-F1-CD.jsonl` (vs kimi clerk).

| per run | A current (n=4) | C kimi clerk (n=4) | **D deepseek clerk (n=3)** |
|---|---|---|---|
| whole run $ | 0.955 | 0.787 | **0.639** |
| MAIN $ | 0.433 | 0.170 | 0.175 |
| clerk $ | — | 0.270 | **0.057** |
| gather $ | 0.476 | 0.266 | 0.326 |
| MAIN output tokens | 42.7k | 15.1k | 14.7k |
| MAIN write refusals | 1.25 | 0 | 0 |
| clerk record calls / rounds per record | — | 6.8 / 2.78 | 6.7 / 2.65 |
| clerk give-ups | — | 1.25 | **0** |
| clerk gaps reported | — | 17.3 | 15.7 |
| correct vs label (benign) | 2/4 | 3/4 | **1/3** |
| dispositions | benign ×2, inconclusive, malicious | benign ×3, false-positive | benign, malicious, unresolved |
| what MAIN proposed at close | — | — | benign, malicious, benign |
| record validates at end | 4/4 | 4/4 | 3/3 |
| wall min | 15.5 | 16.5 | 13.0 |

| run | disposition | proposed → review | $ total | $ clerk | clerk refusals absorbed | gaps |
|---|---|---|---|---|---|---|
| D-t1 | unresolved | benign → challenged, then the composer's reply failed to parse (`forced-inconclusive`) | 0.72 | 0.05 | 9 | 14 |
| D-t2 | malicious | malicious → stands | 0.77 | 0.08 | 17 | 20 |
| D-t3 | benign | benign → stands | 0.43 | 0.03 | 7 | 13 |

## What the swap changed

- **MAIN's saving is clerk-independent.** MAIN cost $0.175 with DeepSeek, $0.170 with kimi —
  the 60% drop from arm A is the prose-only prompt, not the clerk's model.
- **DeepSeek is the cheaper clerk by ~5×: $0.057/run vs $0.27 ($0.003 vs $0.014 per call).**
  That is despite a worse cache profile — per call it reads 13.0k fresh + 5.3k cached tokens
  (kimi: 8.2k + 10.6k), a 29% prompt-cache hit share against kimi's 56% — because its per-token
  price is a quarter of kimi's. It also emits less per call (500 vs 1,200 output tokens),
  which is not all saving: thinner blocks mean more `record` calls carry rows a later block
  has to restate. With this clerk the split nets a real saving on the part of the run it
  touches: MAIN+clerk $0.23 against A's MAIN alone at $0.43; whole run −33% vs A.
- **It never gave up, but it did not need fewer rounds** (2.65 per record vs 2.78). Two runs
  spent 5–6 rounds on ORIENT alone. The multi-owner-lead pattern that blocked kimi is not the
  blocker here; DeepSeek's refusals are spread across parse, vocab and reference errors.
- **Quality moved the wrong way, with the usual caveats at n=3.** MAIN proposed benign twice
  and malicious once. The malicious close (D-t2) is the same operator-SSH bait A-t3 took and
  no kimi-clerk run took — "external SSH as root to the VPS host from 147.235.199.7 … 10,782
  logins from a prior IP over 18 days": the `docker --context soc-playground` sessions that
  drive the playground, read as persistent compromise. D-t1's benign was overturned by the challenge review, which then
  failed on its own (the composer, on glm-5.2 via `--model`, returned non-JSON) and the run
  was host-terminated `unresolved` — a review-gate fault, arm-independent, but it lands in
  D's column.

## Blinded pairwise judge on F1 (claude-opus-5, both orders, order-flip = tie)

- **kimi clerk vs DeepSeek clerk: C preferred 10/12, D 0/12, tie 2/12.** D-t1 and D-t3 lost
  all four of their pairs; D-t2 (the malicious close) tied two and lost two. Both arms share
  the missing-close-block gap, so this comparison is not confounded by it: on the same prompt
  and budget, the record DeepSeek compiles is read as the weaker document every time.
- **current vs DeepSeek clerk: A preferred 7/12, D preferred 2/12, tie 3/12.** Per D run: {'D-t1': {'tie': 1, 'A': 3}, 'D-t2': {'D': 2, 'A': 1, 'tie': 1}, 'D-t3': {'tie': 1, 'A': 3}}. (Confounded by the close-block gap, like every A-vs-clerk pair.)

## Read

Same `:T conclude` gap as arm C: 1 of 3 D records carries a close block (D-t3); the judge
numbers below inherit that confound.

The clerk's model does not touch MAIN's saving and does decide the clerk's bill: DeepSeek
makes the clerk nearly free ($0.06/run) and the whole run a third cheaper than today. What it
costs is the record: judged the weaker document in 10 of 12 pairs against the kimi clerk, and
on this fixture it did not reproduce the kimi arm's discipline (3/4 benign, no malicious) —
with three runs that is a flag, not a finding. The obvious next arm is the cheap clerk with
a real prompt fix (the multi-owner-lead rule, the close-block gap) and n≈6, and `glm-5.3-flash`
($0.15 / $0.03 / $0.50) as a second cheap candidate.
