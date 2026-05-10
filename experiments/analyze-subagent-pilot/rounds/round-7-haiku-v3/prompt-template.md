# Round 7 Haiku v3 — Prompt template

Arm A minimal bundle, model `claude-haiku-4-5`. Revision of v2:
softens adversarial-refutation bar and sharpens sibling-discrimination
rule, in response to the round-6 secondary regression (over-`--`
on adversarial and sibling-consistent hypotheses).

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
  Evidence consistent with a sibling hypothesis is still `+` for both
  siblings — the right move is HYPOTHESIZE a discriminating lead, not
  downgrade one sibling to `-`.
- `-` — somewhat inconsistent with a core prediction.
- `--` — direct contradiction of a core prediction by positive
  evidence. Examples: observed usernames contradict predicted shape,
  observed successful login contradicts predicted zero-successes.

**Do not grade `--` on absence of data.** If a query errored or
returned no results because the data path was unhealthy, that is a
data gap, not a refutation. Hold the prior weight, route HYPOTHESIZE
(fallback lead), flag the gap.

**Adversarial hypothesis refutation bar is higher.** Grading an
adversarial hypothesis `--` requires *direct* evidence against a
core prediction (e.g., zero successful logins in the forward window
when the hypothesis's core prediction is a successful compromise).
Refutation by *absence of anomaly* — "no rotation beyond sentinels,"
"no precursor alerts," "no sustained burst" — is insufficient,
because an attacker who stayed within expected patterns would
produce the same signal. When the adversarial hypothesis cannot be
cleanly refuted by positive evidence, grade `-` and keep it live.

## Routing gate

Default action is **HYPOTHESIZE** unless all of the following hold:

- Exactly one hypothesis is graded `++`, OR all `+` hypotheses share
  a single archetype and disposition.
- All `--` grades are justified by direct positive evidence, not by
  absence.
- The adversarial hypothesis is either `--` (refuted on direct
  evidence) or retained live at `-` with explicit rationale.
- No discriminating follow-on lead would materially reduce
  uncertainty within the remaining loop budget.

If any gate fails, route **HYPOTHESIZE** and name the discriminating
lead.

If you route CONCLUDE, state the archetype + disposition + confidence
explicitly. `matched_archetype` is a *claim* — the caller's
validation layer checks anchor grounding, you do not.

## Output format

Plain markdown ANALYZE block with rollup notation `(was {prior})`,
followed by `## Self-report` section. Self-report: context wished
for, claims uncertain, anomalies or inconsistencies noticed in the
prior investigation log.

## Forbidden

- All `ground-truth-analyze.md` files in any fixture.
- All `notes.md` files in any fixture.
- All files under `docs/experiments/analyze-subagent-pilot/rounds/`.
- All files under `docs/experiments/investigation-language-pilot/`.
- Do not search the codebase or read any `runs/` directory.

Read ONLY the truncated-investigation.md and lead-output.md for
the specific fixture named in your launch prompt.
