# Arm B validation results

**Date:** 2026-05-13
**Trials:** 1 per fixture (validation pass)
**Pass rate:** 4/5 correct, 1 wrong, 0 partial, 0 unparseable.
**Median latency:** 23.2s per call.

## Per-fixture

| Fixture | Category | Verdict | Notes |
|---|---|---|---|
| F-cust-01 | baseline-shift | correct | Backshifted `--start` 7d, kept window length, kept IP entity scope, dropped incidental user. Reasoning concise. |
| F-cust-02 | entity-swap | correct | Pivoted from IP-scoped to user-scoped cleanly. Added explicit alert-anchored `--start` (not required by rubric, but sensible). |
| F-cust-03 | rule-filter | correct | Used the full failed-auth rule-ID set `(5710 OR 5712 OR 5716)`, not just one. Picked the broader read of "failures" without prompting. |
| F-cust-04 | forward-bracket | **wrong** | See diagnosis below. |
| F-cust-05 | composite-filter | correct | All three RFC1918 ranges, `data.action:drop`, srcip scoping, 2h window. Did not leak the incident-specific dstip. |

## F-cust-04 diagnosis — template defect, not adaptation failure

Haiku produced:
```
--query 'data.output_fields.container.id:17bc2dde3fb0 AND rule.id:[100000 TO 100099] AND NOT rule.id:100001'
--start 2026-04-24T15:02:23Z --window 30m
```

The need asked for "30min window BRACKETING the alert — 15min before T0 through 15min after T0." Correct answer: `--start 2026-04-24T14:47:23Z --window 30m`. Haiku used T0 itself as `--start`, producing `[T0, T0+30min]`, not `[T0-15min, T0+15min]`.

**Why:** The `correlated-endpoint-events/templates/wazuh.md` example invocation at lines 47-51 is itself internally inconsistent:

```
Co-fires on a container in ±15 min around the alert:
  ... --start 2026-04-24T15:02:23Z --window 30m
```

`wazuh_cli.py` `compute_time_range` (script line 158-159: `start = end - window`; or with `--start S --window 30m` → `[S, S+30m]`) means the example actually queries T0 to T0+30min, not ±15min around T0. The template's claim and example disagree.

Haiku faithfully copied the template's pattern. The forward-bracket discipline lives in `agents/gather.md:55` prose ("`--start (T0 - lookback) --end (T0 + 60s)`") but is absent from the seed itself.

**This is a real seed defect.** A lead-author agent doing post-mortem on this seed should flag the intent↔example inconsistency.

## Implications for the design conversation

1. **Seeds-not-templates is viable.** Haiku reliably adapts intent + example to specific needs. The 4 passes covered window shifting, entity-field swapping, multi-rule filtering, and composite negation — all without rigid parameter slots.

2. **The lead-author agent's load-bearing discipline is intent↔example consistency.** F-cust-04 is the case-study: the bug isn't query construction, it's that the template's example doesn't follow the discipline its prose claims. A post-mortem author should:
   - Cross-check every template example against the intent it claims to demonstrate.
   - Flag examples that materially diverge from the agent-facing discipline (here: gather.md's forward-bracket rule).

3. **Open methodological note.** The customization prompt didn't include `agents/gather.md`'s forward-bracket discipline as context. In production, gather sees that prose. A fairer test would include it. But — even with that prose, Haiku would still face an inconsistent template example, so the seed bug remains the load-bearing finding. Including gather.md prose in a follow-up trial would isolate whether Haiku can resolve the inconsistency or just defers to the example.

4. **One-trial-per-fixture is thin.** Pass rate of 4/5 on a single trial each gives directional signal but not statistical confidence. Worth running 3+ trials per fixture if results need to be robust before kicking off Arm A; if not, this is enough to proceed.

## Recommendation

**Proceed to Arm A** (NL-goal → seed matching at scale). The foundational assumption holds. The single failure is informative about the lead-author agent's discipline — flag intent↔example inconsistency on existing seeds — and gives Arm A's design a concrete check it should implement.

**Side action:** file the `correlated-endpoint-events` template inconsistency as a real bug. The fix is `--start 2026-04-24T14:47:23Z` in the example (or equivalent end-time form).
