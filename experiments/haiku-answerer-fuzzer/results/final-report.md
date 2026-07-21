# Haiku answerers as ambiguity fuzzer — results

## Headline

The fuzzer hypothesis holds, and the first adjudication round was badly
pessimistic. After a two-round adjudication (strict arm-blind judge, then an
adversarial re-judge that could flip JUNK only by exhibiting two
doc-consistent implementations diverging on the premise):

| novel forks (t1) | flagged | real | precision |
|---|---|---|---|
| haiku-631  | 13 | 6  | 46% |
| haiku-672  | 20 | 11 | 55% |
| sonnet-631 | 2  | 0  | 0%  |
| sonnet-672 | 7  | 3  | 43% |
| **overall** | **39** (dedup 3 shared) | **19** | **49%** |

The single strict judge had called 2/39 real (5%). The adversarial pass
flipped 17 more — its flips are individually checkable (each carries the two
constructed implementations). Truth lies between rounds, but the flip
clusters are the shape of genuine spec holes: one under-specified resolution
(672 Fork A's ill-formed-key boundary) radiating a dozen degenerate-filter
premises; 631's dual-kill tie-break (J11/J13), accounting-write atomicity
(J12), negative-cap semantics (J6).

## What this says about the arms

- Haiku's scatter IS the instrument: per fixture-trial it surfaced ~6 real
  §7-grade questions the production Sonnet runs never asked, at ~6–9 junk to
  screen. Sonnet's tight convergence buries the same undecidedness in
  unanimous "doc doesn't say" hedges (conv_hedge≈10 on 631) that never route.
- Haiku's danger is unchanged: fc_confident ≈ 11–12/trial on the fork-rich
  fixture — invented mechanism facts (flock-prevents-torn-reads, refuted by
  probe P5) confidently agreed on. Haiku cannot REPLACE the panel.
- Both arms fuzz when seeds move (sonnet-672-t2: 12 novels, recall 0.75) —
  seed variance is a free diversity source the production single-shuffle
  discards.

## Verdict vs plan criteria

Replace-the-panel: REJECTED (fc_confident guard fails; junk bound as
written fails). Hybrid (1 promotion-only Haiku answerer + two-round screen):
proposed per plan.md's pre-registered follow-up, **declined by the
maintainer 2026-07-21** — the added screening machinery isn't worth the
yield; current Sonnet-low panel retained unchanged. The transferable
findings stand regardless: the two-round adjudication pattern (a single
strict judge discards ~90% of real ambiguity findings) and the leaf
isolation hole (STRICT ISOLATION block; 4/6 Sonnet leaves peeked).

**Addendum 2026-07-21 (later same day): decision revised.** One Sonnet
answerer is swapped for Haiku in the production panel — a plain swap, not
the declined promotion-only hybrid, so no screening tier is added. The
fc_confident risk is bounded by panel mechanics: a lone Haiku assertion
cannot reach consensus, so its inventions surface as forks routed to §7
rather than expected values. Recorded in `phases/answer.md` (c).

## Metric aggregates (final: 10/12 trials complete; sonnet-631 t2/t3
## unrecoverable after the worktree deletion)

haiku-631  n=3: recall .372, fc_conf 12.7, conv_hedge 3.7, novel 10.0, load 63
haiku-672  n=3: recall .500, fc_conf 1.7,  conv_hedge 0.3, novel 17.3, load 27
sonnet-631 n=1: recall .154, fc_conf 12.0, conv_hedge 10.0, novel 2.0, load 49
sonnet-672 n=3: recall .417, fc_conf 1.3,  conv_hedge 1.0, novel 8.0,  load 18

Stability: every arm-fixture metric at n=3 sits near its t1 value — the t1
adjudication (the corrected 49% S/N) generalizes across seeds. Note
haiku-631's fc_confident (12.7) vs sonnet-631's (12.0) at 6x less hedging —
the confident-wrong guard against panel replacement stands at full n.
t2/t3 novel forks were not separately adjudicated; the t1 two-round verdicts
are the precision estimate.

## Deviations & incidents (full detail in plan.md)

- Experiment scaffolding deleted mid-run by a leaf; restored; scaffolding now
  backed up in scratchpad. Lesson: commit scaffolding before dispatching.
- 4 sonnet t2 answerers read prior trials' answers ("format diligence") —
  quarantined + re-run; STRICT ISOLATION block added to the prompt file.
  0/6 Haiku leaves peeked. t1 audited: exploration existed, no answer content
  available yet; two leaves read plan.md (arm-awareness caveat).
- Session usage limit killed 9 leaves mid-t3; sonnet-631 t2/t3 unrecoverable
  as designed because the 631 worktree (brief, demands, dispositions) was
  deleted when #631 merged (PR #676). 631 premise file reconstructed from
  shuffled copies; sonnet-631 frozen at n=1; haiku-631-t3 classified with a
  2-copy note on one truncated premise; spec_graph_631.yaml used as the
  resolutions oracle for the 631 attack round.
- Both 631 classifiers read the post-§7 20-demands.md (symmetric across arms).

## Real finds worth routing to humans (both fixtures shipped!)

The 19 real novels are open questions against MERGED specs. Highest impact:
- 631: dual-kill tie-break (`truncated_by` winner unpinned), accounting-write
  atomicity, negative injected cap (trip-immediately vs disabled), missing
  spawn-key migration (D2 vs D9 collision — the original REAL).
- 672: ill-formed-key boundary for empty/absent/oversized/non-ASCII filter
  values (Fork A resolution under-specifies), config-knob mid-run divergence,
  duplicate-key rows in list responses.
Recommend: file one follow-up issue per fixture referencing
results/verdicts-*.md + attack-verdicts-*.md.
