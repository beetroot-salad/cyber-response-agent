---
title: Test live companion writing — markdown-with-YAML-blocks format
status: todo
groups: invlang, investigate, schema
---

## What this tests

Rewrite the investigation skill to produce a single markdown-with-YAML-blocks artifact
(`investigation.md`) instead of a freeform narrative. The majority of the investigation
record lives in YAML blocks; minimal prose serves only as state-machine markers and
non-schema commentary. `report.md` survives unchanged as the analyst-facing document.

This is a format comparison test. If the test run passes the success criteria, commit to
markdown-with-YAML-blocks as the primary investigation format. If it fails, fall back to
the Tier-1 minimal companion strategy: agent writes freeform `investigation.md` as before,
and a minimal `companion.yaml` is extracted post-investigation at CONCLUDE (documented in
`wire-the-investigation-language-and-is-query-interface-to-the-main-investigate-flow.md`).

## Comparison baseline

**Run #20 / `20260416-052335-rule100001`** — wazuh-rule-100001 ("Terminal shell in
container"), Sonnet 4.6, thin playbook (no SCREEN, no precedents, archetypes but no
grounding recipes). Result: `escalated/benign/medium`, ~$1.37, 668s.

Key quality markers from run #20:
- 6 hypotheses formed from archetype seeds + one novel (`?ssh-monitoring-probe-whoami`)
- Ticket-context co-fire ambiguity correctly handled (4× rule-100002 co-fires identified
  as sshd dup2 noise, not reverse shell)
- Adversarial hypothesis (`?post-exploit-interactive`) explicitly held at `+` (not `++`,
  not resolved without authoritative evidence)
- Circumstantial-vs-authoritative labeling applied throughout ANALYZE

## What to implement

1. **Update `investigation.md` schema** — each phase writes a YAML code block immediately
   after its `## PHASE` header. Prose is allowed outside blocks only for transition
   commentary ("Falling through to HYPOTHESIZE — SCREEN returned no_match") and brief
   analyst asides. The block is the record; prose is not.

2. **Phase-to-block mapping:**
   - `## CONTEXTUALIZE` → `prologue:` YAML block (vertices, edges from alert)
   - `## SCREEN` → `gather:` YAML block with `mode: screen` leads
   - `## HYPOTHESIZE` → `hypothesize:` YAML block (initial hypothesis frontier)
   - `## GATHER` / `## ANALYZE` → `gather:` YAML block (lead + resolutions fused per lead)
   - `## CONCLUDE` → `conclude:` YAML block

3. **Tier 2 judge** — update `judge_prompt.md` to read the YAML blocks rather than
   narrative prose. The judge's five criteria map to YAML fields directly.

4. **Run on wazuh-rule-100001** using the same manual trigger shape as run #20. Compare
   quality dimensions side by side.

## Success criteria

All of the following must hold for the run to count as a pass:

| # | Criterion | What to verify |
|---|---|---|
| 1 | **Correct disposition** | `escalated/benign` (same as run #20); `true_positive` is a failure |
| 2 | **Adversarial hypothesis lifecycle** | `?post-exploit-interactive` (or equivalent) present in `hypothesize` block; explicitly refuted with `--` + `severity_of_test: severe` or `moderate` in a resolution, or explicitly NOT upgraded to `++` with a recorded reasoning |
| 3 | **Ticket-context co-fire handling** | The 4× rule-100002 co-fires are correctly characterized (sshd dup2 / monitoring-host noise), not inflated into a reverse-shell narrative |
| 4 | **YAML schema validity** | All YAML blocks parse without error; no missing required fields in prologue, gather, or conclude blocks; validator rules 1–17 hold on the produced artifact |
| 5 | **State machine intact** | `## CONTEXTUALIZE`, `## HYPOTHESIZE`, `## GATHER`, `## ANALYZE`, `## CONCLUDE` headers present and in valid order; hooks fire without illegal-transition rejections |
| 6 | **Cost bound** | Total cost ≤ 2× run #20 baseline ($2.74); model pricing differences are expected — count this against investigation efficiency, not raw dollars |
| 7 | **report.md unchanged** | `report.md` is still produced at CONCLUDE with its existing schema; Tier 1 + Tier 2 judge both PASS |

## Failure criteria (auto-fail regardless of disposition)

- Agent produces freeform narrative instead of YAML blocks (format not adopted)
- YAML blocks produced but fail to parse (schema too complex to author reliably)
- State machine bypass (agent writes `state.json` directly or skips a phase)
- Tier 2 judge reads narrative fields that no longer exist (judge not updated)

## Rollback plan

If the test fails: revert the skill changes and implement the Tier-1 minimal companion
strategy from `wire-the-investigation-language-and-is-query-interface-to-the-main-
investigate-flow.md` instead. The minimal companion is written at CONCLUDE by the agent
after `report.md`, covering hypotheses + final weights, lead names + weight deltas +
one-line reasoning, anchor results, and disposition. ~60–100 lines. No vertex/edge graph.

## Notes

- The SCREEN subagent prompt (`screen.md`) is NOT in scope for this test — it reads its
  own instructions file and doesn't produce investigation.md content directly.
- The invlang schema additions (`selection_rationale`, `mode: screen`, `screen_result`,
  HYPOTHESIZE collapse) are already landed in `docs/investigation-language.md`.
- wazuh-rule-100001 has no SCREEN table, so this test will not exercise SCREEN YAML blocks.
  A second test run on wazuh-rule-5710 (Scenario A) is needed to validate the SCREEN format,
  but is out of scope here.
