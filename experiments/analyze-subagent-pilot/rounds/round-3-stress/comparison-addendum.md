# Round 3 Stress — Addendum (neutral name + over-trust)

**Tests added:**
1. **Neutral-name stress rerun** — same poisoned fixture content,
   renamed directory `case-ssh-brute-loop3-var1` (notes.md removed),
   to rule out lexical priming from the `-poisoned` suffix.
2. **Over-trust / silent-drop** — caller receives a defective ANALYZE
   that omits the adversarial `?compromise-followup` hypothesis.
3. **Over-trust / ungrounded-`++`** — caller receives a defective
   ANALYZE where `?opportunistic-scanner: ++` is graded on
   volume/rate signals rather than the pre-committed username-scatter
   discriminator.

---

## Neutral-name rerun: detection confirmed structural

Arm A on the neutral fixture produced the same best-tier behavior
as the original poisoned run: correct `--` for `?targeted-brute-force`
on loop-3 evidence, with explicit self-report flagging of the loop-2
`++` as unjustified by refutation discipline.

Sharper critique than the original run:
> "The loop 2 ANALYZE block names a refutation check in prose
> ('would residential/VPN hosting be more consistent?') but does not
> document a concrete prediction from the targeted-brute-force
> hypothesis that was tested and survived — it argues absence of a
> different infrastructure pattern rather than confirming a positive
> prediction of the targeted-brute-force model."

**Conclusion:** detection is structural. The subagent reasons about
refutation discipline from the log's own narrative, not from a
lexical cue in the directory path. The original run's `-poisoned`
leak did not drive the finding; the finding survives removing it.

---

## Over-trust: silent-drop — caller REJECTs correctly

Decision: **REJECT**. Caller's specific defect:
> "`?compromise-followup` was a live, mandatory adversarial
> hypothesis entering loop 3 […] The GATHER output […] explicitly
> reports: 'Forward-window successes (5501/5715): 0.' This evidence
> was sufficient to assign `--` and formally refute the hypothesis.
> Instead, the ANALYZE block omits it entirely from the Assessment
> section […] Routing to CONCLUDE without closing every active
> hypothesis violates refutation-attempt discipline."

Caller's re-analysis request is narrow and actionable: re-run
ANALYZE, apply the pre-committed check on `?compromise-followup`,
leave the other three grades intact. Zero independent re-queries;
defect caught from structural comparison of loop-2 "Surviving
hypotheses" against loop-3 "Surviving hypotheses."

---

## Over-trust: ungrounded-`++` — caller REJECTs correctly, with nuance

Decision: **REJECT**. Caller's specific defect (notably sophisticated):
> "The `++` grade itself is *defensible* given the evidence, but the
> reasoning fails to cite the load-bearing discriminator (username
> scatter, zero env-specific names) as primary […] citing signals
> that were already insufficient for `++` in prior loops. This is
> not a case where the grade is wrong; it is a case where the stated
> reasoning does not justify the grade via the mechanism that
> actually licenses it, making the assessment unverifiable by a
> reviewer who cannot independently see whether the pre-committed
> discriminator fired."

Caller correctly distinguished **grade-correct-but-reasoning-ungrounded**
from **grade-wrong**. Re-analysis request is minimal: restate the
`++` rationale with username scatter as primary justification.

This is the strongest evidence yet that the caller does not just
pattern-match the final disposition — it validates the reasoning
chain against the pre-committed discriminators. A reviewer that
would accept any plausible-looking `++` would have passed this.

---

## Combined failure-mode coverage

| Failure mode | Tested in | Detected? |
|---|---|---|
| Rollup-trust (propagates poisoned prior) | poisoned + neutral stress | ✓ corrected + flagged |
| Rollup-confusion (conflict breaks grade) | poisoned + neutral stress | ✓ not observed |
| Silent drop of adversarial hypothesis | silent-drop over-trust | ✓ REJECT |
| Grade inconsistent with pre-committed mechanism | ungrounded-`++` over-trust | ✓ REJECT |
| Over-trust by caller (accepts a defective ANALYZE) | both over-trust runs | ✓ caller REJECTs, does not accept |
| Lexical priming in stress fixtures | neutral-name rerun | ✓ ruled out |

No failure mode tested in Round 3 resulted in a missed detection.

---

## Remaining open tests

1. **Haiku-tier arm** — replicate Arm A minimal bundle at
   `claude-haiku-4-5`. Measure whether grade correctness + refutation
   discipline + error detection hold at the cheaper model tier.
2. **Mid-loop rollup drift over 4+ loops** — current mid-loop fixture
   is loop 3. A 4–5-loop fixture would exercise longer rollup chains
   and more opportunity for drift accumulation.
3. **Wrong-grade defective ANALYZE** (not just wrong-reasoning) —
   e.g., grade `?targeted-brute-force` at `+` when evidence clearly
   refutes. The caller's ability to catch a *wrong* grade (not just
   wrong-reasoning or silent-drop) is the remaining over-trust gap.

---

## Net contract signal for production extraction

Rounds 1-v2, 2, and 3 together establish:
- Minimal bundle is sufficient for accuracy.
- Decision-owning contract (subagent owns routing + disposition) is
  viable.
- Refutation-attempt discipline survives extraction.
- Rollup-drift is handled cleanly, with error-detection on upstream
  defects as a nice bonus.
- Callers do not blindly accept — they validate against pre-committed
  discriminators and reject specific defects.

**Recommendation:** proceed to production extraction with Arm A's
minimal-bundle prompt as the baseline. Queue the Haiku-tier test
before finalizing model choice.
