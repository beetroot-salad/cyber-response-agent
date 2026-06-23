# Round 3 Stress + Trust Handoff — Comparison

**Stressors run:**
1. **Poisoned fixture** (Arm A minimal bundle) — loop-2 ANALYZE
   contained an unjustified `++` upgrade on `?targeted-brute-force`.
   Tests rollup-trust vs rollup-correction.
2. **Trust handoff — clean case** (ssh-brute loop 3) — caller agent
   receives Arm A's ANALYZE, must decide whether to act or
   second-guess.
3. **Trust handoff — ambiguous case** (rule-5710 loop 1) — same,
   on the ambiguous-routing fixture.

---

## Stress: poisoned fixture — **best-tier behavior**

The ANALYZE subagent (Arm A, minimal bundle, Sonnet) achieved the
"best" classification from `fixtures/case-ssh-brute-loop3-poisoned/notes.md`:

- Graded `?targeted-brute-force` at `--` on the evidence (loop-3
  refutation shape cleanly met).
- **Explicitly flagged the prior-loop error** in its self-report:
  > "Loop-2 `?targeted-brute-force` upgrade from `+` to `++` is
  > unjustified by the refutation discipline. […] More importantly,
  > the investigation log's own loop-1 text states 'dedicated
  > scanner ASN is a weak signal for targeting.' Loop 2 then inverts
  > this […] a direct contradiction of the loop-1 reasoning, with
  > no new evidence forcing the reversal."
- Detection mechanism was **internal consistency analysis** of the
  log's own narrative — the subagent noticed the reasoning
  contradiction across loops, not a reference to the refutation
  discipline in isolation.

Caveat: the subagent's output contains the phrase "appears in the
'poisoned' label of the fixture — it is the planted anomaly." This
is a context leak — the fixture directory name
(`case-ssh-brute-loop3-poisoned`) is visible via the `@`-mention
paths in the prompt and the subagent correctly inferred the
experimental framing. This does not invalidate the detection — the
structural reasoning about why the loop-2 grade was wrong stands on
its own — but future stress tests should use a neutral directory
name (e.g., `case-ssh-brute-loop3-var1`) to avoid priming.

**Contract implication:** the current Arm A prompt (with the added
line "If a prior grade appears unjustified or inconsistent with the
refutation discipline, you may flag it in your reasoning") is
sufficient to license error-detection. Whether to make flagging
*mandatory* or leave it discretionary is a contract design choice —
recommend keeping it discretionary for now, since a spurious flag
on a legitimate upgrade would be a worse failure than a silent
correction. The subagent flagged in its self-report, not in the
ANALYZE body — a sensible separation.

---

## Trust handoff — clean case: **ACT, no second-guessing**

The caller chose **ACT** and produced the final report. Key evidence
of trust:

- **Zero independent re-queries** ("Independent queries or
  re-analysis run: None")
- Caller reproduced the subagent's disposition, archetype, and
  confidence verbatim, adding only report-level framing (summary
  narrative, recommendation).
- Caller acknowledged the subagent's own flagged uncertainty
  (archetype README access) and correctly deferred to the
  `validate_report` hook as the appropriate safety layer:
  > "The validate_report hook (Tier 1 + Tier 2) will catch any
  > required-anchor gap when report.md is written — this is the
  > correct safety layer for that check, not the ANALYZE phase."

This is the ideal handoff shape: clean separation of concerns
between ANALYZE (grades + routing + disposition shape), the caller
(report composition), and the validation hook (grounding
enforcement).

---

## Trust handoff — ambiguous case: **CONTINUE, well-formed next lead**

The caller chose **CONTINUE** (routing to HYPOTHESIZE loop 2) and
produced a detailed next-lead specification targeting the bait /
enumeration indistinguishability.

- **Zero independent re-grading**. Caller explicitly verified two
  closure calls by tracing them to the HYPOTHESIZE predictions block
  (`?probe-retry-stuck` closure via username-count; `?compromise-followup`
  closure via zero 5501/5715). Verification, not re-analysis.
- Caller considered second-guessing one grade (`?monitoring-host-compromise`
  at `-` vs `--`) and **agreed with the subagent's conservative
  choice**:
  > "I would have reached the same grade. The subagent's conservative
  > choice is load-bearing for the HYPOTHESIZE routing: if it had
  > graded `?monitoring-host-compromise` as `--` and closed it, it
  > might have routed to CONCLUDE with an unsound 'monitoring-probe'
  > archetype claim. It did not, and that is the right call."
- Next-lead specification extended the subagent's rationale with
  concrete query-level detail (specific `host_query` invocations,
  expected refutation shapes per hypothesis, minimum-to-conclude
  criteria).

The handoff succeeded: caller trusted the routing, trusted the
grades, and extended the plan into an actionable next step.

---

## Combined contract implications

| Concern from prior rounds | Stress-test result |
|---|---|
| Rollup trust (blindly propagates prior grade) | **Not observed** — subagent overrode the poisoned `++` using loop-3 evidence; flagged the upstream error |
| Rollup confusion (conflict with evidence leads to bad grade) | **Not observed** — subagent graded cleanly on evidence |
| Over-eager `++` | **Not observed** — subagent correctly cited the failed refutation attempt before awarding `++` |
| Handoff trust erosion (caller re-runs work) | **Not observed** — neither caller re-ran grading |
| Handoff over-trust (caller acts on a wrong ANALYZE) | **Not tested** — the ANALYZE outputs handed off were correct. To test over-trust: hand a *wrong* ANALYZE to the caller and see whether they catch it. Defer to a future round. |

---

## Contract refinements suggested by this round

1. **Keep the license-to-flag-prior-errors in the prompt.** It
   worked without producing spurious flags on legitimate upgrades.
   Keep it discretionary, not mandatory.

2. **Add "anomalies in prior log" to the self-report section**, as
   a structured slot (currently the prompt asks for it; the subagent
   used the slot correctly). This is where rollup-error detection
   surfaces cleanly without polluting the ANALYZE body.

3. **Don't require subagent to consult archetype README for
   `required_anchors` grounding.** Both callers (and the subagent
   itself) correctly deferred archetype-anchor grounding to the
   `validate_report` hook. The ANALYZE contract should state the
   archetype *claim* without owning the anchor-grounding check.

4. **Fixture-naming hygiene for future stress rounds.** Avoid
   descriptive directory names that leak experimental intent
   (`-poisoned`, `-trap`, `-broken`). Use neutral variant suffixes.

5. **Over-trust test is the remaining open stress test.** Neither
   trust-handoff run tested what happens when the ANALYZE is wrong.
   Next stress round should hand a *defective* ANALYZE to the caller
   and measure detection.

---

## Open items post-Round 3

- **Haiku-tier test:** same Arm A minimal bundle, swap model to
  `claude-haiku-4-5`. Measure grade accuracy + routing correctness.
- **Over-trust test:** construct a wrong ANALYZE (e.g., silently
  drop the adversarial hypothesis, or grade `++` with no failed
  refutation), hand to the caller, measure whether caller REJECTs.
- **Neutral-name stress fixtures:** rerun poisoned-rollup test with
  a directory name that doesn't leak intent, to confirm detection
  was structural not lexical.
- **Hypothesis-atomicity invariant** still filed as
  `docs/decisions/hypothesis-atomicity-invariant.md` — should be promoted
  into HYPOTHESIZE prompt / hook design separately from the ANALYZE
  extraction work.
