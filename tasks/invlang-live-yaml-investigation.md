---
title: Migrate investigation.md to live YAML blocks — full v2.6 schema
status: done
groups: invlang, investigate, schema
---

## Design decision

investigation.md stays the single artifact and primary corpus entry. It keeps its `## PHASE`
headers (state machine is unchanged) and gains embedded YAML blocks at each phase. The YAML
is the full v2.6 schema — vertex/edge graph included — written live during the investigation,
not reconstructed post-mortem.

No separate companion.yaml. `corpus.py` already handles `.md` files with YAML blocks.

Supersedes:
- `wire-the-investigation-language-and-is-query-interface-to-the-main-investigate-flow.md`
  (Tier-1 post-mortem companion strategy — valid as rollback only)
- `invlang-companion-live-writing-test.md` (tested YAML-replaces-narrative; rejected —
  YAML contains reasoning via string fields, narrative alongside is still valuable for analyst
  readability and judge context)

## Phase-to-block mapping

| Header | Block written | When |
|---|---|---|
| `## CONTEXTUALIZE` | `prologue:` — full vertex/edge graph from alert entities | end of CONTEXTUALIZE |
| `## SCREEN` | `gather:` leads with `mode: screen` | after screen subagent returns |
| `## HYPOTHESIZE` | `hypothesize:` — hypotheses with predictions, weight: null | end of HYPOTHESIZE |
| `## GATHER` | narrative observation only — no YAML block | during GATHER |
| `## ANALYZE` | complete `gather:` lead block — `outcome` + `resolutions` together | end of ANALYZE |
| `## CONCLUDE` | `conclude:` block | after conclusion_checks.json, before report.md |

GATHER writes narrative characterization (characterize, don't interpret). ANALYZE writes the
full lead YAML block once both observation and analysis are complete. No partial blocks, no
mutation of prior blocks.

## ID consistency

Vertex, edge, hypothesis, and lead IDs must be stable across turns. The invlang CLI's
`--enum` flag (or equivalent) gives the agent the current ID namespace before each write.
Agent calls this before writing any block that introduces new IDs or references existing ones.

## What changes

1. **SKILL.md phase templates** — each phase section gets a YAML block template alongside
   the existing prose template. GATHER template explicitly notes: narrative only, YAML written
   at ANALYZE.

2. **judge_prompt.md** — Tier 2 judge currently reads narrative fields. Update to read YAML
   fields for its five criteria (COMPLETENESS, PROPORTIONALITY, ADVERSARIAL, PRECEDENT,
   EVIDENCE_SUFFICIENCY). The YAML fields are more directly queryable than narrative — this
   is likely a cleaner judge prompt.

3. **invlang CLI** — add/expose `--enum` pre-write ID enumeration. Likely already partially
   present; verify and document in SKILL.md.

## What does NOT change

- `## PHASE` headers and infer_state.py — entirely unaffected
- report.md schema — unchanged
- validate_report.py (Tier 1) — entirely unaffected
- Tier-2 rich hand-curated companions — unchanged; continue to be the high-fidelity curation path
- conclusion_checks.md and conclusion_checks.json flow — unchanged

## Rollback

If live YAML writing degrades investigation quality (agent fills schema fields mechanically
without genuine reasoning), revert SKILL.md phase templates and implement the Tier-1
post-mortem minimal companion from the deferred wire task instead. The minimal companion is
written at CONCLUDE by the agent after report.md, covering hypotheses + final weights, lead
names + weight deltas + one-line reasoning, anchor results, and disposition.

## Success criteria (test run against wazuh-rule-100001)

Use run #20 / `20260416-052335-rule100001` as baseline (escalated/benign/medium, ~$1.37, 668s).

| # | Criterion |
|---|---|
| 1 | Correct disposition: `escalated/benign` |
| 2 | Adversarial hypothesis lifecycle: present in `hypothesize` block, explicitly refuted in a resolution with `severity_of_test: severe` or `moderate` |
| 3 | Ticket-context co-fire handling: 4× rule-100002 co-fires correctly characterized |
| 4 | YAML validity: all blocks parse; required fields present; validator rules 1–17 hold |
| 5 | State machine intact: headers present and in valid order; no illegal-transition rejections |
| 6 | Cost bound: ≤ 2× run #20 baseline ($2.74) |
| 7 | report.md unchanged: produced at CONCLUDE with existing schema; Tier 1 + Tier 2 judge both PASS |
| 8 | Reasoning quality: YAML string fields (predictions, reasoning, selection_rationale) contain substantive content — not mechanical schema completion |