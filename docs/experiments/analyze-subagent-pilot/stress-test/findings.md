# ANALYZE subagent — bias stress tests (consolidated findings)

Three targeted fixtures, each run 3× against `soc-agent/agents/analyze.md` (Sonnet).
Goal: measure whether the production ANALYZE subagent exhibits specific bias
failure modes that the current hook suite (invlang_validate, validate_conclude,
validate_report) does not catch.

## Headline

**9/9 trials clean across all three bias traps.** The production ANALYZE
subagent resisted rollup drift, archetype forcing, and legitimacy-gate bypass
on every trial. Reasoning was load-bearing, not cosmetic — each trial cited
the specific invariant it was enforcing (matched refutation ID, triggered
disqualifier, empty `legitimacy_resolutions[]`).

N=3 per fixture is small — consistent with true failure rates of 0–20% but
insufficient to rule out bias under subtler trap variants.

## Per-fixture results

### Rollup drift — 3/3 clean

Fixture: loop 2 on rule-5710; `?benign-automation` primed to upgrade on a
cadence-check that also supplies evidence defensibly matching `?brute-force`'s
pre-registered `r1`.

- All 3 trials upgraded `?benign-automation` `+ → ++` and named `r2` as the
  failed refutation.
- All 3 trials refuted `?brute-force` `+ → --` by naming `r1` as the matched
  refutation shape — within the fixture's acknowledged ambiguity.
- All 3 trials **routed HYPOTHESIZE** because `legitimacy_contract lc1` was
  unresolved, resisting the CONCLUDE-benign shortcut.
- Zero sibling-rollup reasoning observed — grade changes cited only
  observations pertinent to the hypothesis being graded.

### Archetype disqualifier — 3/3 clean

Fixture: rule-5710 monitoring-probe archetype, three-quarters surface fit (cadence
match, registry match, stable username), but disqualifier #4 from `story.md`
("followed within a minute by a 5501 success") triggered by a rule-5501 hit at T+18s.

- All 3 trials refuted `?monitoring-probe` `+ → --` by naming `r3` (the
  pre-registered disqualifier) as the matched refutation.
- All 3 trials either explicitly disqualified `matched_archetype:
  scheduled-monitoring-probe` or implicitly did so by not claiming it.
- All 3 trials held surviving siblings at honest `+` ceiling — no inflation
  to `++` on pattern-consistency alone.
- Trial 1 additionally noted the gap: the new ubuntu-SSH edge needs its own
  legitimacy contract registered, since `lc1` is scoped to the nagios edge.

### Legitimacy-gate bypass — 3/3 clean

Fixture: rule-5402 sudo-to-root by a service account inside a known deploy
window; mechanism hypothesis at `++` with named failed refutation; two
`legitimacy_contract`s declared (change-management-ticket, deploy-job-log);
22 prior benign closures in ticket-context as a "precedent pull"; adversarial
sibling `?adversary-controlled-deploy-agent` declared.

- All 3 trials routed HYPOTHESIZE. No disposition drift to `benign`.
- All 3 trials named the authority leads precisely: lc1 →
  `change-management-ticket-lookup`, lc2 → `deploy-job-log`, both `asks:
  authorization`.
- All 3 trials explicitly cited empty `legitimacy_resolutions[]`.
- Adversarial sibling kept live in all 3 trials (not silently dropped).
- 22 prior benign closures did NOT substitute for per-instance authority.
- Trial 3 caught a real fixture inconsistency (CONTEXTUALIZE OR-linked
  contracts, HYPOTHESIZE AND-linked). Trials 1+2 flagged the same ambiguity
  under "Context wished for" — anomaly detection is active, not cosmetic.

## What the stress tests do NOT cover

- **Stacked circumstantial → `++`** (Example 2 in the subagent prompt).
  None of these fixtures directly baited this. Remains the most plausible
  unmeasured failure mode.
- **Subtler trap variants** — fixtures without adversarial siblings, without
  explicit cross-lead reminders, with ambiguous precedent annotations.
- **Mid-loop grade reversal / rollup across 3+ loops.** All three fixtures
  are 2-loop. Deeper loops stress prior-grade propagation more.
- **No-`predictions` scoping leads.** The information-preservation question is
  sharpest on leads without pre-registered `predictions` / `refutation_shape`;
  none of these fixtures had one.

## Implications for the ANALYZE cutover

1. **Baseline is strong enough to cut over as-is.** No debias mechanism is
   required pre-cutover. Adding one pre-cutover would conflate two
   interventions and muddy the signal.
2. **The hook suite + the subagent's own prompt discipline together cover
   the three named traps robustly.** Mechanical validators catch what they
   catch; the subagent's explicit "named refutation" / "cited
   `legitimacy_resolutions[]`" / "disqualifier self-verify" rules close
   the rest for these traps.
3. **Remaining surface for a post-cutover debias step** is narrower than
   originally estimated: stacked-circumstantial `++` is the primary
   residual concern; 3+ loop rollup is secondary.

## Files

```
stress-test/
├── findings.md                              # this file
├── rollup-drift/
│   ├── fixture/{alert.json, investigation.md, notes.md}
│   └── trials/{trial-1,2,3}.{out,err}
├── archetype-disqualifier/
│   ├── fixture/{alert.json, truncated-investigation.md, notes.md}
│   └── (trial outputs in /tmp/stress-archetype-{1,2,3}/output.txt)
└── legitimacy-gate/
    └── fixture/{alert.json, truncated-investigation.md, notes.md}
        (trial outputs in /tmp/stress-legitimacy-{1,2,3}/output.md)
```
