# Fixture: case-ssh-brute-loop3

**Source:** `docs/experiments/investigation-language-pilot/case-ssh-brute/companion-v2.5.yaml` (synthesized prose form; the YAML companion was the authoritative representation).

**Cut point:** immediately before `## ANALYZE (loop 3)`. The subagents receive CONTEXTUALIZE + SCREEN + HYPOTHESIZE + GATHER for loops 1–2 (with prior ANALYZE blocks for rollup context) + HYPOTHESIZE (loop 3) + GATHER (loop 3 lead output). They must produce ANALYZE (loop 3).

**Why this fixture** (complement to `case-rule5710-loop1`):

- **Crisp routing ground truth.** Loop 3's ANALYZE concludes decisively — `?opportunistic-scanner` at `++`, all competitors at `--`, trust-root reached at v-001, archetype matches with all anchor conditions confirmed. The correct next action is CONCLUDE with `disposition: true_positive`. No ambiguity between CONCLUDE and HYPOTHESIZE.
- **Mid-loop — exercises rollup-drift.** Three prior ANALYZE blocks (loops 1 and 2) exist in the log with in-flight weights. ANALYZE loop 3 must:
  - promote `?opportunistic-scanner` from `+` → `++` (rollup on new evidence)
  - reverse `?targeted-brute-force` from `+` → `--` (true weight reversal)
  - advance `?credential-stuffing-external` from `-` → `--` (rollup confirmation)
  - assess `?compromise-followup` from live → `--` (first resolution)
- **Tests refutation-attempt discipline (`++` awarding).** `?opportunistic-scanner` reaches `++`; the ANALYZE should cite the *attempted* refutation (env-specific names) that was actively checked and not found. This is the check Round 1 never exercised (no `++` grades).
- **True-positive disposition** — contrasts with rule-5710 fixture's inconclusive disposition. Tests whether ANALYZE can commit to a non-escalation true_positive conclusion when evidence warrants.

**Ground-truth highlights:**
- `?opportunistic-scanner`: `++` (was `+` loop 2; attempted refutation failed → promotion)
- `?targeted-brute-force`: `--` (was `+` loop 2; weight reversal on env-specific names absence)
- `?credential-stuffing-external`: `--` (was `-` loop 2; rollup confirmation)
- `?compromise-followup`: `--` (first graded; refuted by zero successes in forward window)
- Archetype fit: `opportunistic-scanner` matches; anchor conditions all satisfied; 14 prior precedent closures
- Trust-root: v-001 reached; frontier collapsed
- Next action: CONCLUDE with disposition:true_positive, matched_archetype:opportunistic-scanner

**Hypothesis atomicity:** all hypotheses in this fixture name a single mechanism with a single prediction shape (lesson applied from Round 1 v2).

**No known limitations** — unlike rule-5710-loop1, this fixture has a decisive routing answer and exercises rollup drift.
