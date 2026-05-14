# Lead-seed Haiku experiment

Captures the design conversation that motivates this experiment. The seeds-not-templates assumption is foundational; if Haiku can't customize a seed to a specific need, the lead-author agent design (and the broader seed-based catalog) falls apart.

## Arms

- **Arm B (this run) — seed customization.** Given a real seed (definition.md intent + templates/wazuh.md example) + a specific alert + an NL adaptation note, can Haiku produce a correct adapted query? **Gating arm — runs first.**
- **Arm A (deferred until Arm B passes) — NL-goal → seed matching at scale.** Catalog-size sweep on selection accuracy. Pointless to run if Arm B fails.

## Arm B method

- **Model.** Haiku via `claude -p --model haiku --output-format text` (matches `soc-agent/hooks/scripts/judge_runner.py:55`).
- **Prompt.** `variants/customization_prompt.md` — single fixed prompt; the variable is the fixture content, not the prompt.
- **5 fixtures, one per adaptation category:**
  - `F-cust-01-baseline-shift` — produce a 7d-shifted baseline query for `authentication-history` given the foreground window.
  - `F-cust-02-entity-swap` — pivot from IP-scoped to user-scoped within the same seed.
  - `F-cust-03-rule-filter` — narrow `authentication-history` to failed-auth rule IDs only.
  - `F-cust-04-forward-bracket` — produce a ±15min bracket query for `correlated-endpoint-events` (tests time arithmetic + forward-bracket discipline).
  - `F-cust-05-composite-filter` — combine `network-analysis` filters: srcip + RFC1918 negation + `data.action:drop` + window.
- **Trials.** Validation pass: 1 trial per fixture. If results are directional (clear pass/fail per fixture), stop. If noisy (mixed within-fixture), scale to 3 trials each.
- **Scoring.** Mechanical substring rubric per fixture: `expected_substrings` must all appear in the produced query; `forbidden_substrings` must not. Categorical verdict `correct` / `partially-correct` / `wrong` / `unparseable`. No LLM judge.

## Decision criteria

- **Seeds-not-templates is viable → lead-author agent can focus on intent-quality** if customization is `correct` on ≥4/5 fixtures at the validation pass (or ≥80% under scale-up).
- **Seeds-not-templates is too aggressive → leads need rigid templates with parameter slots** if `correct` is ≤2/5, or any category fails systematically across trials.
- **Specific categories that break** point to where templates need to remain rigid (e.g., if time arithmetic fails consistently, baseline-shift and forward-bracket need template helpers).

## Open methodology choices (logged)

- **Single-rater reference queries.** I (the experiment author) wrote the reference queries. Risk of subtle wrongness. Mitigation: rubric scores against *substrings* (entity field, time, filter tokens), not exact-match. A semantically correct query that uses different but valid phrasing scores correctly.
- **Hard-side NL phrasing.** Adaptation notes describe the evidence need, not the operation. E.g., F-cust-03 says "failed attempts only" — Haiku has to know that maps to specific rule IDs and which.
- **Wazuh-only.** Cross-vendor customization (e.g., port to host-query) is deferred. Most leads in the current catalog have only Wazuh templates anyway.
