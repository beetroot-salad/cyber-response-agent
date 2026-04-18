# Round 1 assessment — single-alert probe, 3 context-management arms

Fixture: `fixture/alert.json` + `fixture/investigation.md` (CONTEXTUALIZE
complete, archetype scan rendered, ASSESS decided branching fork).
Model: Sonnet for all three arms. N=1 per arm.

## Cost

| Arm | Total tokens | Tool uses | Wall time |
|---|---:|---:|---:|
| A (pointers) | 27,253 | 6 | 64 s |
| B (inlined bundle) | 27,665 | 3 | 53 s |
| C (hybrid digest) | **19,997** | 3 | 79 s |

C is ~28% cheaper on tokens. A and B are within noise of each other —
concatenating 4 files into one bundle vs. reading them individually is
the same total payload.

## Output quality

### Shape compliance (one-hop, ≤2 predictions, refutation shape named)

All three arms produced well-formed hypotheses. B's hypotheses were the
most structurally crisp (every field filled with the exact schema
labels). A and C were slightly freer in phrasing but structurally sound.

### Classification coverage

- **A:** 4 hypotheses — automation / mistake / credential-guessing / compromise-followup. Full coverage across automated / human-authorized / human-unauthorized / adversarial.
- **B:** same 4 hypotheses, same coverage.
- **C:** 3 hypotheses — explicitly suppressed `?credential-guessing` as redundant with `?compromise-followup` given volume=1 and internal source. Defensible on leanness grounds, but is a coverage loss: `?credential-guessing` and `?compromise-followup` predict different observable shapes (any-success within-window vs. continued-guessing). Merging them is the umbrella failure mode the SKILL.md rule calls out.

### Adversarial hypothesis retained

All three kept `?compromise-followup` live. Good.

### Lead selection

- **A:** `source-classification`, single dispatch. Aligns with playbook starter-lead order.
- **B:** `source-classification`, primary-deferred (with `authentication-history` named as mandatory second regardless of outcome, to service `?compromise-followup`). Slightly more sophisticated framing than A.
- **C:** `authentication-history`, single dispatch. **Diverges.** C's stated reason: "the digest already partially resolved IP classification (internal), so source-classification's marginal value is lower." This is wrong in a load-bearing way — the playbook's `source-classification` lead partitions `internal-monitoring-host` vs. `internal-other` vs. known automation subnets. The digest collapsed those sub-classifications into the single label "internal", and C lost the signal. Skipping source-classification means the `?legitimate-automation` vs. `?credential-guessing` fork is still live when `authentication-history` runs.

### Pitfalls

- **B's pitfalls section was the sharpest**: the note that "the CONTEXTUALIZE 4-hour backward-look does not cover the 60-second forward window needed to refute `?compromise-followup`" is exactly the reasoning trap to flag pre-registration.
- A's pitfalls are comparable in quality, just slightly less precise on the forward/backward distinction.
- C's pitfalls are good but include a softer variant of the same window point.

## Verdict (single-case, low confidence)

| | Quality | Cost | Risk |
|---|---|---|---|
| **A (pointers)** | High | Mid | Subagent may skip a file that matters. Acceptable in practice — A correctly skipped `archetypes/*/story.md` because the scan was already rendered in investigation.md. |
| **B (inlined bundle)** | High (sharpest) | Mid | None, context is deterministic. Larger prompt. |
| **C (hybrid digest)** | Mixed — lost `source-classification` granularity | Lowest | Digest-authoring risks dropping load-bearing details. This run exhibited exactly that failure. |

**Provisional lean:** Arm A. Cost is indistinguishable from B; quality is comparable; the subagent choosing what to read is a desirable property (A correctly skipped the already-rendered archetype scan). B is a safe runner-up with deterministic context. C is cheapest but the single observed failure is a category of failure (digest loses discriminating sub-classifications) worth taking seriously before recommending.

## Open questions for next rounds

1. **Variance.** N=1 is not enough. Re-run each arm 3× and check whether C's `source-classification` shortcut is reproducible or a one-off.
2. **Digest design.** Can C's digest be rewritten to preserve sub-classifications ("10.30.18.42: internal, not in approved-monitoring-sources, not in scheduled-jobs registry") rather than collapsing to "internal"? If yes, the cost advantage is worth preserving.
3. **Second fixture.** Run an archetype-match case where the screen almost fires (e.g., monitoring-probe with sentinel username). Do the arms converge on fast-path vs. defend-the-adversarial?
4. **Handoff trust.** Feed each arm's output into a fresh "main agent" and measure whether downstream GATHER/ANALYZE reasoning degrades. The subagent's output is only useful if the caller can act on it.
