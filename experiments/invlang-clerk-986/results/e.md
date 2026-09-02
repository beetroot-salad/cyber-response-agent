# Arm E — clerk on GLM 5.3 Flash, F1 (benign), n=3

Same design, prompt and 6-round budget as arms C/D; clerk model `glm-5p3-flash` (Fireworks
serverless Standard $0.15 / $0.03 cached / $0.50 out per M). **One regime difference:** the
model refuses `reasoning_effort=none` ("reasoning cannot be disabled"), so this clerk ran at
`low` where kimi and DeepSeek ran with reasoning off. Run 2026-09-01 14:35–15:05Z, three
concurrent. Rows in `final.jsonl`; judge in `judge-F1-CE.jsonl` / `judge-F1-DE.jsonl`.

| per run | A current (4) | C kimi (4) | D deepseek (3) | **E glm-5.3-flash (3)** |
|---|---|---|---|---|
| whole run $ | 0.955 | 0.787 | 0.639 | **0.513** |
| MAIN $ | 0.433 | 0.170 | 0.175 | 0.170 |
| clerk $ | — | 0.270 | 0.057 | **0.032** |
| gather $ | 0.476 | 0.266 | 0.326 | 0.244 |
| MAIN output tokens | 42.7k | 15.1k | 14.7k | 16.0k |
| clerk rounds per record | — | 2.78 | 2.65 | **1.56** |
| clerk give-ups / run | — | 1.25 | 0 | 0.33 |
| clerk calls / run | — | 18.8 | 17.7 | **13.0** |
| clerk per call: fresh in / cached / out tokens | — | 8.2k / 10.6k / 1.2k | 13.0k / 5.3k / 0.5k | 11.7k / 8.2k / 0.9k |
| correct vs label (benign) | 2/4 | 3/4 | 1/3 | **2/3** |
| dispositions | benign ×2, inconcl., malicious | benign ×3, false-pos. | benign, malicious, unresolved | benign ×2, inconclusive |
| closed malicious on the startup script | 1 | 0 | 1 | **0** |
| `:T conclude` block in record | 4/4 | 1/4 | 1/3 | 1/3 |
| record validates at end | 4/4 | 4/4 | 3/3 | 3/3 |
| wall min | 15.5 | 16.5 | 13.0 | 14.9 |

| run | disposition | proposed → review | $ total | $ clerk | rounds/record | give-ups | gaps |
|---|---|---|---|---|---|---|---|
| E-t1 | benign | benign → challenged once, then stood | 0.60 | 0.016 | 1.0 | 0 | 22 |
| E-t2 | inconclusive | inconclusive (no review needed) | 0.64 | 0.066 | 2.3 | 1 | 28 |
| E-t3 | benign | benign → stands | 0.29 | 0.014 | 1.2 | 0 | 19 |

## What the swap changed

- **Cheapest whole run of any arm: $0.51, 46% under the current arm**, with the clerk at
  $0.03/run. MAIN's cost is the same $0.17 it is under every clerk — the saving MAIN makes
  is the prose-only prompt's, and the clerk's bill is now small enough that it stops
  mattering which cheap model it is.
- **Fewest rounds of any clerk (1.56 per record vs 2.7–2.8)** and the fewest model calls per
  run (13 vs 18–19), *with reasoning on*. GLM reads the validator's refusal and fixes it in
  one go where kimi and DeepSeek took two or three. Its output per call (0.9k) sits between
  the two; cache-hit share (41%) too.
- **No bait taken.** Benign twice, inconclusive once; no `malicious` on the startup script
  (A and DeepSeek each closed malicious once on the operator's SSH session) and no
  `unresolved`. E-t2's inconclusive is the run with the give-up and 14 absorbed refusals —
  the one run where the clerk struggled is the one that failed to reach benign.
- Same `:T conclude` gap as every clerk arm (1 of 3 records carries the close block) — the
  prompt fault documented in `findings.md`, not the model's.

## Blinded pairwise judge on F1 (claude-opus-5, both orders, order-flip = tie)

- **DeepSeek clerk vs GLM clerk: E preferred 5/9, D 2/9, tie 2/9.** Every E run wins or ties
  a majority of its three pairs. Clean on the close-block axis (both arms share the gap).
- **kimi clerk vs GLM clerk: C preferred 10/12, E 1/12, tie 1/12.** Every kimi run beats
  every GLM run except one pair. Also clean on the close-block axis.

So the three clerks rank the same way on every instrument that reads the record: kimi > GLM
> DeepSeek (kimi 10–0–2 over DeepSeek, 10–1–1 over GLM; GLM 5–2–2 over DeepSeek). Cost ranks
the other way: GLM $0.03, DeepSeek $0.06, kimi $0.27 per run. The dispositions on this
fixture do not follow the record ranking — GLM 2/3 correct with no bait taken, DeepSeek 1/3
with one malicious, kimi 3/4 — which is the label/judge disagreement seen throughout: the
judge scores the document, the label scores the verdict, and MAIN reaches the verdict
largely without re-reading the rows.

## Caveats

- n=3, one fixture. The DeepSeek arm showed what three runs can do: its quality flag may or
  may not survive n=6, and so may E's clean sheet.
- `low` reasoning is not the regime the other clerks ran in. It may be *why* E converges
  faster; it is also the reason the comparison is not one-variable.
- The judge numbers below inherit the close-block confound only where they compare against
  arm A; E-vs-C and E-vs-D are clean on that axis.
