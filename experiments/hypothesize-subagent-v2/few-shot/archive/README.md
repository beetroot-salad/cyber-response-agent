# HYPOTHESIZE few-shot examples

Three worked examples for testing and (eventually) prompting the
hypothesize subagent. Each shows the alert + investigation state at
the decision point, the HYPOTHESIZE output, and annotations explaining
what makes it good or bad against `docs/investigation-language.md`
§Hypothesis and `soc-agent/skills/investigate/SKILL.md` §HYPOTHESIZE /
§ASSESS.

| File | Label | Domain | Loop | Illustrates |
|---|---|---|---|---|
| `example-1-endpoint-initial.md` | positive | endpoint | 1 | Clean mechanism fork at loop 1 when the alert carries the discriminating data (`pname`/`aname`). Ambiguous ancestry truncation forces ≥2 competing topologies. |
| `example-2-network-mid.md` | positive | network | 2 | Refinement via hierarchical IDs (`h-{parent}-{ordinal}`) after a parent mechanism was confirmed at loop 1. Sub-mechanisms differ by predicted observable shape. |
| `example-3-identity-bad.md` | negative | identity | 1 | Narrative-umbrella failure mode from the v1 pilot: multi-attribute predictions packed into one label, premature HYPOTHESIZE entry when the mechanical/interpretive lane is correct. |

## Usage

- **In testing (now):** ground-truth reference when scoring hypothesize-subagent arm outputs. An arm output that resembles example 3 fails regardless of polish; an arm output matching the shape of example 1 or 2 passes the relevant rubric dimensions.
- **In prompting (later):** see `tasks/hypothesize-prompt-few-shot-examples.md`. These three are candidates for inlining into SKILL.md §HYPOTHESIZE as worked examples once the rubric is stable.

## Coverage rationale

- **Initial loop + mid loop** — the hypothesize subagent must handle both "form the first fork" and "refine a confirmed parent." Different disciplines apply (leanness + coverage vs. hierarchical-ID refinement).
- **Endpoint + network + identity** — spans the three signature shapes the playbook pass established:
  - Endpoint (rule-100001): alert carries mechanism data → fork at loop 1.
  - Network (rule-100110): enrichment-first → fork opens after GATHER.
  - Identity (rule-5710): enrichment-first → often no fork at all; disposition resolves through attribute enrichment.
- **Data (FIM / rule-550) omitted** — same enrichment-first shape as identity; no additional discipline illustrated.

## What each example does NOT include

- No parallel adversarial hypothesis (no `?compromise-followup` shape). Legitimacy is consistently modeled as a trust-anchor attribute. See `tasks/adversarial-as-attribute-not-hypothesis.md` for the SKILL.md-level rule reframe this depends on.
- No narrative classifications that conflate mechanism + intent + shape. Example 3 shows and labels this failure explicitly.
- No sub-archetype pre-decomposition at loop 1. Example 1 stays at the mechanism layer; archetype disposition is deferred to CONCLUDE-time anchor work.
