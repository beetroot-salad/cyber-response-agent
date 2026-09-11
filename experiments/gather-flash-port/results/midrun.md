# Mid-run analysis — F1, 3 runs per arm (9 runs, 86 dispatches), 2026-09-11 09:05Z

Table: `midrun-F1.md`. Judge cache: `extractions/`. No abort condition met (completion ≥ 80%
every arm; payloads non-empty). **Decision: continue to N=6 per arm per fixture unchanged.**

## Gather-level (the decision criteria)

| per dispatch | current (kimi) | glm-flash | ds-flash |
|---|---|---|---|
| n | 35 | 21 | 30 |
| completed | 83% | **100%** | **100%** |
| error rate (wrong+dropped+unsupported / dims) | 16% | **12%** | **45%** |
| unsupported claims / dispatch | 0.24 | **0.19** | **1.03** |
| dispatches with ≥1 error | 6/29 | 6/21 | **19/30** |
| $ / dispatch | 0.070 | **0.006** | 0.006 |
| requests / dispatch | 14.5 | 7.4 | 7.9 |
| wall s (mean / p90) | 63 / 131 | 52 / 81 | 36 / 84 |

- **GLM 5.3 Flash clears every acceptance bar** at this n: completion +17 pts over Kimi, error
  rate 4 pts under, fewer unsupported claims, 8% of the cost. Reasoning-on (`low`) costs it
  ~500 reasoning tokens/dispatch, invisible in the bill at $0.50/M out.
- **DeepSeek V4.1 Flash fails two bars: unsupported ≤ current and error ≤ current + 5.** Its
  misses are not misreads of a table; they are measurements it did not make, stated as made:
  "the store's 11 known hosts are [8 names]", "svc.security is the sole account with a
  per-host grant" after looking up one account, a change window quoted as 09:00–10:00Z that
  the record gives as 04:00–06:00Z, a cmdline it paraphrased into a different command. Two of
  three runs, 19 of 30 dispatches. This is the hallucination class the criteria were written
  to catch; n=30 is enough to say it is a property of the arm, not of a run.
- Kimi's completion (83%) is the low one: four request-limit exhaustions, one abnormal end
  (12 corrections on one bash-parse rule), one dead end. It runs twice the requests and
  queries per dispatch of either flash arm.

## Run-level (reported, not a criterion — and the thing to watch)

| | current | glm-flash | ds-flash |
|---|---|---|---|
| F1 (benign) disposition ×3 | inconclusive ×3 | **malicious ×3** | inconclusive ×3 |
| F2 (malicious) so far | malicious ×2 | **inconclusive ×2** | malicious ×2 |
| leads / run (F1) | 11.7 | **7.0** | 10.0 |
| $ total / run (F1) | 1.24 | **0.37** | 0.48 |

With GLM Flash as gather, MAIN's verdict is wrong against the label in 5/5 runs; with the
other two it is right on F2 (4/4) and hedged (`inconclusive`) on F1. The gather summaries are
not the defect — GLM's score best on fidelity — and the closes read as MAIN acting on what
they surface: on F1 the root password change at 09:53:47Z and the external root SSH login
(the operator's own session, the fixture caveat `invlang-clerk-986` recorded), closed
`adversarial-confirmed`; on F2 the 199 root logins from the operator IP and the
`attacker@elsewhere`-labelled key, closed "exercise simulation vs real persistence, not
resolvable". Both fixtures carry the confound that punishes completeness. It is still a
5/5-vs-0/5 split on the axis the product is judged on, so N=6 is worth finishing to see whether
it holds on F2 — and if it does, the follow-up is a held-out fixture without the operator
contamination, because this experiment cannot separate "GLM's summaries mislead MAIN" from
"GLM's summaries are the ones faithful enough to expose the fixture".

## Instrument notes
- One GLM dispatch took 608 s (23 requests, 19 queries, 8 query errors); p90 is 81 s. Not
  capacity — a long dispatch. Overlap (concurrent siblings) 1.3–1.6 in every arm.
- The harness's context lead `l-00c` (request limit 8) exhausts in every arm on F2; excluded
  from fidelity as cut-short, as any terminated dispatch is.
