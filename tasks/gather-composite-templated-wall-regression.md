---
title: gather-composite wall-time regression on templated composite dispatches (285s → was 149s)
status: backlog
groups: gather, cost-optimization, orchestrator
---

**Goal.** Investigate why the orchestrator's `gather-composite` Sonnet subagent took **285 s on a single loop-1 dispatch** when its prior baseline on a comparable dispatch was 149 s, and decide whether the regression is in the subagent prompt, the dispatched lead set, the underlying tool latency, or the prompt-size envelope. Produce one of: (a) a localized fix, (b) a profiling bench that reproduces the slowdown across runs, or (c) a documented root cause we accept as inherent to the new dispatch shape.

## Why

Recorded run `/tmp/soc-agent-orchestrate-eval/20260427-164551-rule100001/runs/ed4e10fa-9d03-458f-92ed-22ced17568fd/`:

- Dispatched leads: `selected_lead: container-baseline` + `composite_secondary: [correlated-endpoint-events]` — both **templated** leads with on-disk definitions, not ad-hoc.
- Subagent wall: **285 825 ms** (Sonnet), `stdout=5931` chars.
- Prior reference: the first /testrun in this conversation (commit branch `predict-fastpath-cache` at `e9b10ae`, same 100001 alert shape, same dispatcher) — 5 successive gather-composite dispatches at 149 / 82 / 118 / 99 / 49 s. Max 149.
- Same eval also produced an ANALYZE 300 s timeout downstream (separate task — see `analyze-orchestrator-loop1-timeout.md`); the gather-composite stdout size is the suspected upstream driver of that timeout, so the two investigations may share findings.

The original /testrun's user assertion was that ad-hoc gather-composite must stay under 200 s wall. This new run was not ad-hoc, so the assertion technically does not apply — but the prompt-level changes between branches (Tier 1 PREDICT cues + raw-events guidance in `ad-hoc/definition.md` + benign-action-class awareness threaded into the lead hint) are the most plausible delta and worth pinning down before they ride further into PR #139.

## What changed between the two measurements

Branch `predict-fastpath-cache` accumulated the following between the 149 s baseline and the 285 s observation:

1. **Slim `gather-composite` output schema** (`agents/gather-composite.md`) — drops prompt-known fields (mode, time_range, system, template, substitutions, time_window) the handler reconstructs. Smaller output should be faster, but the schema rewrite added §Schema-is-intentionally-lean prose plus the lossless-vs-summarized callout.
2. **First-pass raw-events guidance** in `knowledge/common-investigation/leads/ad-hoc/definition.md` — adds 35 lines of procedure for the ad-hoc path. Does not apply to templated leads, but the file is still loaded into the subagent prompt.
3. **`save_raw_tool_output` pipe-detection** (`hooks/scripts/save_raw_tool_output.py`) — pre-tool hook now skips persistence when the matched binary is not the terminal segment. No prompt impact, but tool-call latency may shift if the hook is on the hot path of every wazuh_cli invocation.
4. **`_subagent.py` cwd pin** to plugin root — relative `scripts/tools/wazuh_cli.py` resolves first try, but the cwd change may interact with plugin-snapshot path conventions.
5. **PREDICT cues** (`agents/predict.md`) — added structural-consistency + refutation-shape-adequacy + backward-traversal cues. The dispatched lead hints in this run carry extra prose ("Focus specifically on proc.pname=runc spawns" + "per playbook composition rules these escalate immediately") which PREDICT's richer story authoring may now generate by default.
6. **100001 playbook** picked up `## Contextualize leads` + `## Benign action classes` sections — the latter is referenced by PREDICT, threaded into the dispatched `lead_hint` prose.

The cleanest explanation is (5)+(6): PREDICT's lead hints are now more verbose, which inflates the gather-composite prompt and stretches its turn budget. But that is a hypothesis; the run did not capture per-block token counts.

## Method

1. **Reproduce the regression deterministically.** Replay the same alert against `eval_run_orchestrate.sh 100001 --window 5m` three times on the current `predict-fastpath-cache` HEAD; record wall + stdout size for the gather-composite step. If variance is wide (e.g., 150 s ↔ 300 s across trials), the issue is stochastic and (5)/(6) are unlikely the carry — pursue prompt-size profiling instead.
2. **Bisect by reverting prompt changes.** On a temp branch off `predict-fastpath-cache`:
   - (a) revert `agents/predict.md` Tier 1 hunks → re-run, measure.
   - (b) revert `100001/playbook.md` `## Contextualize leads` + `## Benign action classes` → re-run, measure.
   - (c) revert `agents/gather-composite.md` slim-schema rewrite → re-run, measure.
   The first revert that restores the 149 s baseline names the carry.
3. **Capture per-turn timing inside the subagent.** `subagent_outputs/<ts>-gather-composite-<sid>.txt` already records the rendered prompt; cross-reference with `~/.claude/projects/-workspace-soc-agent/<session_id>.jsonl` to extract per-turn elapsed time. If most of the 285 s sits in a single thinking turn, the cause is upfront-restatement (meta-finding #17b on the testrun skill) and the fix is preload trimming, not prompt rewrite.
4. **Tool-latency baseline.** Run the dispatched query (`data.output_fields.container.image.repository:"cyber-response-agent_devcontainer-target-endpoint" AND rule.id:100001` over 7 d) directly via `wazuh_cli.py query` outside the orchestrator; record server-side wall. If the wazuh-indexer itself is slow today, much of the 285 s may be network/SIEM, not subagent reasoning.

## What "done" looks like

Either:

- A localized fix lands (prompt trim, preload reduction, or lead-hint normalization) and re-run wall returns to ≤ 180 s on three consecutive trials, OR
- The regression is documented as inherent to the new dispatch shape (with concrete per-turn timing evidence) and the testrun skill's gather-composite section is updated with the new baseline + threshold, OR
- The investigation traces the slowdown to an upstream driver (PREDICT verbosity, ANALYZE preload-size pressure, wazuh-indexer load) and a separate task is filed for that driver instead.

## Files / pointers

- Suspect run: `/tmp/soc-agent-orchestrate-eval/20260427-164551-rule100001/runs/ed4e10fa-9d03-458f-92ed-22ced17568fd/`
  - `subagent_audit.jsonl` — per-subagent wall + stdout
  - `subagent_outputs/20260427T165459811022Z-gather-composite-27cf4718.txt` — full prompt + stdout
- Sibling testrun runs: search `/tmp/soc-agent-orchestrate-eval/` for older `*-rule100001` dirs; the 149 / 82 / 118 / 99 / 49 baselines are in the first /testrun of the active conversation (`20260427-110339-rule100001/`).
- Related skill: `/workspace/.claude/skills/testrun/SKILL.md` — quirk #22 (loop-N timeout pattern) names the same prompt-size driver from a different angle; cross-reference if the bisect points at preload size.
- Branch: `predict-fastpath-cache` (HEAD `eda4f4a`).

## Out of scope

- ANALYZE 300 s timeout — separate task `analyze-orchestrator-loop1-timeout.md`. The two may share root cause (gather-composite stdout drives ANALYZE preload), but the investigations are independent: this task asks "why is gather-composite slow?", that task asks "why does ANALYZE time out on this stdout shape?".
- ad-hoc gather-composite wall — different dispatch path, original assertion was specific to it; not part of this regression.
- gather-composite Level 1/2 finish-discipline + checkpoint recovery (already validated in run #42 of the cost-baseline table).
