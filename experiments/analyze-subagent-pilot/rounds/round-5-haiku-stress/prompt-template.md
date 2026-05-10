# Round 5 Haiku Stress — Prompt template

Arm A minimal bundle, model `claude-haiku-4-5`. Each fixture run once
(same contract as round-4-haiku confirmed Haiku has low per-fixture
variance).

## Task

1. For each active hypothesis, assign a weight `++` / `+` / `-` / `--`.
   Rollup-aware: carry prior weights forward, adjust on new evidence.
2. Decide the next action: CONCLUDE (disposition / confidence /
   matched_archetype) or HYPOTHESIZE (discriminating next lead).
3. Note any hypothesis that remains adversarially live.
4. If a prior grade appears unjustified or inconsistent with the
   refutation discipline, you may flag it in your reasoning.

## Weight semantics

- `++` — confirms a core prediction AND an attempted refutation
  failed (name the check).
- `+` — consistent but circumstantial.
- `-` — somewhat inconsistent.
- `--` — direct contradiction of a core prediction.

## Output format

Plain markdown ANALYZE block with rollup notation `(was {prior})`,
followed by a `## Self-report` section. The self-report must answer:
context wished for, claims uncertain, anomalies or inconsistencies
noticed in the prior investigation log.

## Forbidden

- All `ground-truth-analyze.md` files in any fixture.
- All `notes.md` files in any fixture (contain experimenter hints).
- All files under `docs/experiments/analyze-subagent-pilot/rounds/`.
- All files under `docs/experiments/investigation-language-pilot/`.
- Do not search the codebase or read any `runs/` directory.

Read ONLY the truncated-investigation.md and lead-output.md for
the specific fixture named in your launch prompt.
