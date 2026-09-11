# Result — gather moves to GLM 5.3 Flash. DeepSeek V4.1 Flash fails the hallucination bar.

27 clean runs (F1 benign: Kimi 5 / GLM Flash 6 / DeepSeek 5; F2 malicious: 3 / 3 / 3),
202 gather dispatches, live playground on the 2026-09-09 snapshot, 2026-09-11 07:45–09:35Z.
Plan asked for 30; the last nine F2 runs were cut when Fireworks began returning HTTP 412
"account suspended (monthly spending limit)" intermittently at 09:35Z — one Kimi run died on
it and is excluded as infrastructure. Tables: `interim.md` (per arm × fixture). Rows:
`dispatches.jsonl`, `runs.jsonl`. Judge cache: `extractions/`. Pairwise: `pairwise/`.

## Gather level — the decision criteria

Per dispatch, both fixtures pooled (n = judged dispatches; completion over all dispatches):

| | current (Kimi K2.6) | **GLM 5.3 Flash** | DeepSeek V4.1 Flash |
|---|---|---|---|
| dispatches / judged | 68 / 53 | 68 / 66 | 66 / 63 |
| **completed** (real summary, not cut short) | 78% | **97%** | 95% |
| **error rate** (wrong + dropped + unsupported per dimension) | 17% | **13%** | 34% |
| **unsupported claims / dispatch** | 0.21 | 0.21 | **0.83** |
| dispatches with ≥1 error | 12/53 | 17/66 | **31/63** |
| dropped dimensions | 0 | 0 | 0 |
| requests / dispatch | 14.5 | **6.9** | 9.0 |
| queries / dispatch (errors) | 12.1 (1.8) | 4.9 (0.9) | 7.7 (1.0) |
| **$ / dispatch** | 0.071 | **0.005** | 0.007 |
| gather $ / run | 0.60 | **0.04** | 0.06 |
| cached input share | 86% | 78% | 82% |
| reasoning tokens / dispatch (share of output) | ~0 | 390 (28%) | 0 |
| wall s / dispatch (mean) | 57 | 39 | 40 |
| cut short: request limit / dead end / abnormal | 11 / 3 / 1 | 2 / 0 / 0 | 3 / 0 / 0 |

Against the plan's bars (completion ≥ current − 5; error ≤ current + 5; unsupported ≤
current; $ ≤ 50% of current):

- **GLM 5.3 Flash: passes all four**, and not narrowly — +19 points completion, −4 points
  error, equal unsupported, 7% of the cost. Its forced `low` reasoning is 28% of its output
  tokens and still leaves it the cheapest arm; it also runs the loop in half Kimi's requests
  and 40% of Kimi's queries, with the fewest query errors.
- **DeepSeek V4.1 Flash: fails unsupported (0.83 vs 0.21) and error (34% vs 17%).** Its
  misses are measurements it did not make, stated as made — a host list "of 11" naming eight,
  a change window quoted at 09:00–10:00Z that the record gives as 04:00–06:00Z, a cmdline
  paraphrased into a different command, "the sole account with a grant" after looking up one
  account, a timing gap of "9.6 s" the timestamps put at 10.4. Half its dispatches carry at
  least one. On the attack fixture it was better (22% error, 0.50 unsupported) than on the
  benign one (39%, 0.96), but worse than Kimi on both.
- **Kimi's weakness was budget, not fidelity**: 22% of its dispatches were cut short, eleven
  of them on the 40-request limit, because it runs twice the requests per dispatch.

**Decision, per the plan: GLM 5.3 Flash ships as the gather default.** DeepSeek is not the
fallback either; if GLM Flash serving fails, the fallback is full GLM 5.3 at `low`.

## Run level — reported, not a criterion; and it needs its own follow-up

| per run | current | GLM Flash arm | DeepSeek arm |
|---|---|---|---|
| F1 benign — disposition | inconclusive ×4, malicious ×1 | **malicious ×5, inconclusive ×1** | inconclusive ×4, false-positive ×1 |
| F2 malicious — disposition | malicious ×3 | **inconclusive ×3** | malicious ×3 |
| correct vs label | 3/8 | **0/9** | 3/8 |
| leads / run | 8.5 | 7.5 | 8.3 |
| MAIN $ / run | 0.33 | 0.25 | 0.33 |
| whole run $ | 1.03 | **0.40** | 0.46 |

With GLM Flash writing the summaries, MAIN's verdict missed the label in every run: confident
`malicious` on the benign alert, `inconclusive` on the attack. The gather summaries are not
where the error is — they score best on fidelity — so I ran the blinded pairwise judge from
`invlang-clerk-986` over whole investigations, GLM-arm vs Kimi-arm, both orders:

- **F2 (attack): GLM arm 5, Kimi arm 1, tie 3.** The judge reads the Kimi arm's `malicious`
  closes as *not earned by their own rows* — "the appended key was never observed in use, the
  only source IP is a pre-existing baseline actor, the same alert shape recurs 97×/30d" — and
  the GLM arm's `inconclusive` as the honest reading of the same evidence. That is the
  fixture's known contamination (`invlang-clerk-986`: the attack runner has planted the same
  `attacker@elsewhere` key on that host for months). The label says the GLM arm is wrong; the
  record says it is the arm that noticed.
- **F1 (benign): Kimi arm 20, GLM arm 5, tie 5.** Here the GLM arm's closes are the badly
  earned ones: "closes `adversarial-confirmed / high confidence` while its own loop-2 grading
  concedes the commands read as environment provisioning", "rests on absence-of-records plus a
  'no prior baseline' assertion that no row carries". F1 carries the other known contamination
  (the operator's own root SSH into the VPS inside the window), and MAIN, fed GLM's cleaner
  and more complete summaries of it — the root password change, the external publickey login
  44 s after the burst — commits where the other arms hedge.

So the run-level effect is real, it cuts both ways, and this experiment cannot separate "GLM's
summaries push MAIN to over-commit" from "GLM's summaries are the ones faithful enough to
expose two contaminated fixtures". What it can say: the over-commit on F1 is MAIN contradicting
its own record, which is a MAIN calibration problem that the gather change *surfaces* rather
than a gather defect — and it costs a false positive, not a false negative. **Follow-up: rerun
the GLM-Flash arm against a held-out fixture with neither contamination before trusting the
F1 pattern either way; scrub F1 and F2 as `invlang-clerk-986` already asked.**

## What else the run establishes

- Whole-run cost drops from $1.03 to $0.40 with the gather swap alone — gather was 58% of the
  bill on Kimi and is 9% on GLM Flash. MAIN's own bill also fell 24%, with fewer leads per run
  (7.5 vs 8.5); at this n that is a hint, not a finding.
- Capacity: no sign of GLM Flash's missing priority tier under 1.2–1.6 concurrent dispatches.
  Wall per dispatch is the lowest of the three. One 608 s dispatch (23 requests, 8 query
  errors) was a hard lead, not throttling.
- The V4.1 Flash price row is still the 0731 copy; the arm's cost is arithmetic on that.
  Moot for the decision — it lost on fidelity, and at any plausible price.
- The harness's own context lead (`l-00c`, request limit 8) exhausts in nearly every run on
  F2 regardless of arm — a fixed budget too tight for that alert's entity count. Filed as a
  standalone observation, not part of this decision.

## Limitations

- N=3 per arm on F2; the F2 verdict split is 0/3 vs 3/3 vs 3/3 and would have been 6/6 had
  the account not tripped. The gather-level numbers are on 53–66 judged dispatches per arm.
- Not hermetic: live playground, baseline generators drifting between trials; both fixtures
  known-contaminated on the axis the verdict is judged on.
- The dispatch judge sees tool returns capped at 120 KB per dispatch; two Kimi dispatches
  and one DeepSeek dispatch exceeded it (leniency on truncation is in the rubric).
- GLM Flash ran with reasoning on (`low`), the others off — a property of the model, but it
  may be *why* it needs half the requests.
