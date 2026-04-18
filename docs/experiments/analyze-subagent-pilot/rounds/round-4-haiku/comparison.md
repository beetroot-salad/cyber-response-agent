# Round 4 Haiku — Comparison

**Question:** Is Haiku capable of the Arm A minimal-bundle ANALYZE contract?
**Method:** Two parallel Haiku (`claude-haiku-4-5`) runs on the clean
`case-ssh-brute-loop3` fixture, identical prompts, to measure Haiku's
own variance before comparing to Sonnet baseline.

## Headline

Haiku matches Sonnet at the clean fixture. **Both runs produced 4/4
grade-exact output against ground truth**, correct routing (CONCLUDE
true_positive, opportunistic-scanner, high confidence), and correct
adversarial refutation. Variance between the two Haiku runs is
**essentially zero on grades and routing**; prose depth varies.

## Per-run scoring

| Dimension | Run 1 | Run 2 | Ground truth |
|---|---|---|---|
| `?opportunistic-scanner` | `++` (was `+`) ✓ | `++` (was `+`) ✓ | `++` |
| `?targeted-brute-force` | `--` (was `+`) ✓ | `--` (was `+`) ✓ | `--` |
| `?credential-stuffing-external` | `--` (was `-`) ✓ | `--` (was `-`) ✓ | `--` |
| `?compromise-followup` | `--` (was live) ✓ | `--` (was live) ✓ | `--` |
| Routing | CONCLUDE ✓ | CONCLUDE ✓ | CONCLUDE |
| matched_archetype | opportunistic-scanner ✓ | opportunistic-scanner ✓ | opportunistic-scanner |
| Confidence | high ✓ | high ✓ | high |
| Disposition | true_positive ✓ | true_positive ✓ | true_positive |
| Refutation-attempt discipline | Named (env-specific names, rate, forward-window) ✓ | Named (same three) ✓ | Named |
| Adversarial preservation | `?compromise-followup` carried live → refuted on forward window ✓ | Same ✓ | Same |
| Hallucinated context | None | None | — |
| Precedent claim | "14 prior scanner-class closures" (mirrors ground truth) | Omitted | Ground truth cites 14 |

Run 1 carries more precedent/archetype-fit narrative; Run 2 is terser
and more structured (bulleted YAML-adjacent form). Neither adds claims
not supported by the inputs.

## Variance observations

- **Grade variance: zero.** All 4 hypotheses matched across both runs.
- **Routing variance: zero.** Both CONCLUDE with identical disposition.
- **Format variance: moderate.** Run 1 uses prose paragraphs per
  hypothesis; Run 2 uses bulleted assessments closer to the
  ground-truth YAML form. Both are schema-compatible with the current
  prompt's "plain markdown ANALYZE block" spec.
- **Self-report variance: low.** Both explicitly attribute the clean
  result to the pre-committed refutation shapes at loop-3 HYPOTHESIZE.
  Both report "no anomalies" — which is correct for this clean
  fixture.
- **Tool use: 4 calls each, ~30s wall time each, ~26.5k total tokens
  each.** Substantially cheaper than Sonnet Arm A on the same fixture.

## Caveats — do not overgeneralize from one fixture

1. **Clean fixture.** case-ssh-brute-loop3 is the cleanest baseline:
   pre-committed refutation shapes match evidence exactly, trust-root
   reached, no rollup conflicts, no archetype anchor ambiguity. Haiku
   succeeding here is necessary but not sufficient evidence of
   general capability.
2. **No adversarial stressors.** The poisoned-rollup test
   (`case-ssh-brute-loop3-poisoned` / `-var1`) is the one that
   discriminated Sonnet's internal-consistency reasoning in round-3.
   Haiku has not faced it yet.
3. **No ambiguous routing.** case-rule5710-loop1 (the fixture with
   ambiguous routing ground truth that split Sonnet arms A/B/C in
   round 1) has not been run on Haiku.
4. **No mid-loop grade reversal.** The rollup-drift dimension remains
   untested on Haiku.

## Recommendation — next Haiku rounds

To promote Haiku beyond "capable on the easy case," run (in priority order):

1. **Haiku on `case-ssh-brute-loop3-var1` (poisoned, neutral name).**
   Two parallel runs. Does Haiku catch the unjustified loop-2 `++`
   upgrade via internal-consistency reasoning, the way Sonnet did in
   round-3-stress? This is the load-bearing capability test.
2. **Haiku on `case-rule5710-loop1` (ambiguous routing).** Two
   parallel runs. Does Haiku split CONCLUDE vs HYPOTHESIZE the way
   Sonnet did, or does it commit to one route? Informs whether
   Haiku's lower capability shows as deterministic-but-wrong vs
   variance-across-runs.
3. **Haiku trust handoff.** If 1 and 2 survive, feed Haiku's ANALYZE
   into a fresh Sonnet main agent (as round-3 did) to confirm the
   handoff contract still works when the subagent is Haiku.

## Contract implication (provisional)

If rounds 4.1–4.3 hold up, the decision-owning ANALYZE contract is
compatible with Haiku on clean cases at substantial token savings.
The poisoned-rollup test (4.1) is the gate: if Haiku fails there,
drop back to Sonnet for ANALYZE or widen the bundle with an explicit
"check prior-loop reasoning for internal consistency" instruction.
