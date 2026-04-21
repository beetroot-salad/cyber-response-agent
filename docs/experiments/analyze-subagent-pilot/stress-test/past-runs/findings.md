# ANALYZE subagent — past-investigation stress tests

Three fixtures from `docs/experiments/analyze-subagent-pilot/fixtures/` (real
past investigations + one adversarial variant), each run 3× against the
updated `soc-agent/agents/analyze.md` (terminal YAML trailer + rule 24/25
language).

Complements the synthetic-bias stress tests in the sibling directories — those
test specific trap shapes we designed; these test the subagent against real
investigation-language output from completed runs, including one deliberately
poisoned variant.

## Headline

**9/9 trials produced well-formed terminal YAML** parseable by the handler —
the prompt-alignment change lands cleanly on realistic inputs.

**Routing differences from ground truth are defensible in every case.** The
subagent either matches ground-truth routing (6/9) or diverges with a
disciplined rationale (3/9, where it routed HYPOTHESIZE citing a GATHER
inconsistency the ground truth had silently absorbed).

**3/3 poisoned-variant trials resisted the upstream error** — the subagent did
NOT carry forward a falsely-`++` grade from the injected loop-2 ANALYZE and
correctly refuted `?targeted-brute-force` at `--` on every trial.

## Per-fixture results

### case-rule5710-loop1 — ambiguous-evidence fixture

Real rule-5710 investigation (2026-04-14) with an internal-monitoring source
producing a sub-second burst across sentinel usernames. Ground-truth routes
CONCLUDE escalated / inconclusive with two surviving hypotheses
(`?monitoring-bait-triggered` at `+`, `?monitoring-host-compromise` at `-`).

| Trial | Routing | Notes |
|---|---|---|
| 1 | HYPOTHESIZE | Detected a GATHER narrative-vs-data contradiction ("different sentinel per event" prose vs. raw sample showing 5× sensu). Refused to grade `?probe-retry-stuck` or `?probe-enumeration-misconfigured` at ++/-- on contradicted evidence. Discriminator: per-event srcuser for each burst event. |
| 2 | HYPOTHESIZE | Similar discipline; discriminator asks whether burst was isolated vs. recurring, and what monitoring-host cron shows. |
| 3 | HYPOTHESIZE | Same pattern; discriminator asks whether burst was the bait workload or a misconfigured probe, plus compromise indicators on monitoring-host. |

**Divergence from ground truth is the good kind.** Ground truth's CONCLUDE
escalated with the same ambiguity the subagent detected — both shapes are
valid readings of the evidence. The subagent's choice ("one more lead to
disambiguate before escalating") is discipline-aligned with the prompt's
"do not force a grade the evidence doesn't support" rule. All three trials
also flagged the prior-loop anomaly (HYPOTHESIZE block lacks formal `r{N}`
IDs) — self-report anomaly detection is active.

### case-ssh-brute-loop3 — clean archetype match

Multi-loop SSH brute-force investigation where loop-3 evidence authoritatively
confirms `?opportunistic-scanner` and refutes three competing hypotheses.
Ground-truth routes CONCLUDE true_positive / high /
`matched_archetype: opportunistic-scanner`.

| Trial | Routing | Disposition | Confidence | matched_archetype |
|---|---|---|---|---|
| 1 | CONCLUDE | true_positive | high | external-bruteforce |
| 2 | CONCLUDE | true_positive | high | external-bruteforce |
| 3 | CONCLUDE | true_positive | high | external-bruteforce |

**3/3 match ground-truth routing + disposition + confidence.** Archetype
label differs (`external-bruteforce` vs. ground truth's `opportunistic-scanner`)
— both name the same shape; the fixture's synthetic archetype directory
doesn't actually exist, so archetype grounding is a claim-only assertion on
either side. Not a regression.

### case-ssh-brute-loop3-poisoned — robustness to upstream error

Variant of `case-ssh-brute-loop3` with the loop-2 ANALYZE poisoned to grade
`?targeted-brute-force` at `++` instead of `+`. Ground truth is unchanged —
loop-3 evidence directly refutes `?targeted-brute-force` via the
pre-registered refutation shape regardless of the loop-2 grade. The test:
does the subagent trust the poisoned prior or correct it?

| Trial | Routing | `?targeted-brute-force` grade | Poison called out? |
|---|---|---|---|
| 1 | CONCLUDE / true_positive / high | `--` (matched r1) | Yes — "loop 2 upgrade was unjustified" in Self-report |
| 2 | CONCLUDE / true_positive / high | `--` (matched r_tgt1) | Yes — "the `++` carried from loop 2 was itself methodologically suspect" |
| 3 | CONCLUDE / true_positive / high | `--` (matched r_target1) | Yes — "prior loop-2 `++` was itself anomalous" |

**3/3 in the "Best" category** per the fixture's classification table
(grades at `--` using pre-committed refutation shape AND flags the prior
error). The subagent is robust to upstream errors; it grounds grading on
the current-loop evidence against pre-registered refutation shapes, not on
history-as-prior. Trial 3 additionally matched ground-truth archetype name
(`opportunistic-scanner`) exactly.

## Observations

- **Terminal YAML well-formedness: 9/9.** The new trailer parses cleanly on
  every trial. No prompt-alignment fallout on realistic inputs.
- **`surviving_hypotheses` field populated correctly in all 6 CONCLUDE
  trials.** Two shapes observed: bare hypothesis ID (`[h-001]`) and
  hypothesis name (`["?opportunistic-scanner"]`). Prompt says "IDs (not
  names)" — minor prompt-clarity drift worth a follow-up touch; neither
  shape fails validator rule 24 in practice because the fixtures used the
  name-form as ID (`?opportunistic-scanner` is the declared hypothesis
  name/ID for these fixtures, and rule 24 matches strings against declared
  hypothesis IDs).
- **Self-report anomaly detection is load-bearing.** Six of nine trials
  surfaced real prior-loop issues:
  - case-rule5710-loop1 trials 1–3: lack of formal `r{N}` refutation IDs in
    the HYPOTHESIZE block (a fixture inconsistency)
  - case-ssh-brute-loop3-poisoned trials 1–3: the injected loop-2 `++`
    upgrade called out as anomalous
- **Discipline over ground-truth matching.** The rule-5710 fixture
  divergence (HYPOTHESIZE vs. ground-truth CONCLUDE escalated) reflects the
  subagent correctly applying "ambiguous evidence → don't force a grade"
  rather than imitating the ground truth. This is the right direction.

## Caveats

- **N=3 per fixture, three fixtures.** Rough signal, not a statistical claim.
- **Ground-truth labels were built before the terminal-YAML prompt change.**
  The subagent's Markdown assessment structure differs from the ground truth's
  YAML-style `hypotheses:` block within the Assessment section. Structural
  similarity was not scored — only routing, disposition, confidence,
  archetype, and grade-at-terminal-hypothesis.
- **Fixture archetype directories don't exist on disk for the SSH cases.**
  The subagent's archetype claim is unverifiable either way; ground-truth
  label agreement is a weak signal.

## Follow-ups noted

- Tighten `surviving_hypotheses` documentation in `agents/analyze.md` to
  eliminate the name-vs-id ambiguity observed across trials.
- Consider adding these fixtures to `analyze-pilot/rounds/` as the Round 2
  baseline (the pilot was paused at Round 1 on case-rule5710-loop1 only).
