# Round 6 Haiku v2 — Prompt template (with routing gate)

Arm A minimal bundle, model `claude-haiku-4-5`. Revision of the
round-4/5 prompt: **adds a routing gate** to address the partial
failure on pattern 5 (mixed evidence → over-commit to CONCLUDE).

## Task

1. For each active hypothesis, assign a weight `++` / `+` / `-` / `--`.
   Rollup-aware: carry prior weights forward, adjust on new evidence.
2. Decide the next action per the routing gate below.
3. Note any hypothesis that remains adversarially live.
4. If a prior grade appears unjustified or inconsistent with the
   refutation discipline, you may flag it in your reasoning.

## Weight semantics

- `++` — confirms a core prediction AND an attempted refutation
  failed (name the check). If two sibling hypotheses both pass their
  individual refutation checks on the same evidence, the evidence is
  *not discriminating* and neither earns `++` — grade both `+`.
- `+` — consistent but circumstantial, or consistent-but-not-uniquely-so.
- `-` — somewhat inconsistent.
- `--` — direct contradiction of a core prediction.

**Do not grade `--` on absence of data.** If a query errored or
returned no results because the data path was unhealthy, that is a
data gap, not a refutation. Hold the prior weight, route to HYPOTHESIZE
(fallback lead), and flag the gap in self-report.

## Routing gate

Your default action is **HYPOTHESIZE** unless all of the following hold:

- Exactly one hypothesis is graded `++`, OR all `+` hypotheses share a
  single archetype and disposition.
- All `--` grades are justified by direct evidence, not by absence.
- The adversarial hypothesis is either `--` (refuted on evidence) or
  retained live with explicit rationale.
- No discriminating follow-on lead would materially reduce
  uncertainty within the remaining loop budget.

If any of these fails, route **HYPOTHESIZE** and name the
discriminating lead — even if the immediate disposition "seems clear."

If you route CONCLUDE, state the archetype + disposition + confidence
explicitly. `matched_archetype` is a *claim* — the caller's
validation layer checks anchor grounding, you do not.

## Output format

Plain markdown ANALYZE block with rollup notation `(was {prior})`,
followed by a `## Self-report` section. Self-report must answer:
context wished for, claims uncertain, anomalies or inconsistencies
noticed in the prior investigation log.

## Forbidden

- All `ground-truth-analyze.md` files in any fixture.
- All `notes.md` files in any fixture.
- All files under `docs/experiments/analyze-subagent-pilot/rounds/`.
- All files under `docs/experiments/investigation-language-pilot/`.
- Do not search the codebase or read any `runs/` directory.

Read ONLY the truncated-investigation.md and lead-output.md for
the specific fixture named in your launch prompt.
