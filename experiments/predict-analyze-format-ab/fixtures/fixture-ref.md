# Fixture reference

Run dir: `/tmp/soc-agent-orchestrate-eval/20260429-202152-rule5710/runs/e00fe8c3-7c47-400e-8df0-ee276651ecc1/`

Branch: `main` @ `9be69cd` (post #155 + #156)

Shape: fork-shaped Shape-M predict (2 hypotheses), analyze halt routed `disposition=true_positive` → X5 violation in production run.

## Prompt sources

- predict L2: `subagent_outputs/20260429T203448662999Z-predict-57417cd6.txt` lines 4–630 (`=== PROMPT ===` to `=== STDOUT ===`)
- analyze L2: `subagent_outputs/20260429T204243448642Z-analyze-66833cd2.txt` lines 4–108 (`=== PROMPT ===` to `=== STDOUT ===`)

Replayed verbatim by harness; no environment dependencies (analyze prompt embeds `<current_gather>`; predict prompt embeds `<investigation>`).

## Reference stdout (production run)

- predict L2 stdout: 5315 chars, parsed clean, Shape M with h-001/h-002.
- analyze L2 stdout: 2034 chars, parsed clean structurally — but X5 cross-block violation: `disposition=true_positive` with `surviving=[h-002]` where h-002 = `?credentials-used-outside-registered-actor` (no adversarial token).
