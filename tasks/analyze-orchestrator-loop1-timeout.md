---
title: ANALYZE subagent times out at 300 s on loop-1 dispatches when gather-composite stdout is large
status: backlog
groups: analyze, orchestrator, timeouts
---

**Goal.** Identify why `agents/analyze.md` dispatched on loop 1 (a phase that should be the cheapest of the four) is hitting the orchestrator's 300 s hard ceiling, and pick a fix from the leverage list — preload trim, dynamic timeout, or a structural decoupling of ANALYZE from gather-composite stdout size.

## Why

Recorded run `/tmp/soc-agent-orchestrate-eval/20260427-164551-rule100001/runs/ed4e10fa-9d03-458f-92ed-22ced17568fd/`:

- `state.json.history`: `[CONTEXTUALIZE, PREDICT, GATHER, ANALYZE]` — never advanced past ANALYZE.
- `driver.log` final line: `FAILED: subagent analyze timed out after 300s`.
- Loop-1 ANALYZE dispatch hit the `SOC_AGENT_CONCLUDE_TIMEOUT_SECONDS`-class hard ceiling (300 s for ANALYZE, similar value for CONCLUDE).
- Upstream gather-composite returned `stdout_chars=5931` after 285 s — well above the prior 49–149 s baseline for the same harness.
- No `subagent_outputs/*-analyze-*.txt` artifact exists — the subagent never produced output before the kill.
- Orchestrator `subagent_spawns: 0` in `budget.json` (counter unrelated; budget enforcer is main-agent only).

Quirk #22 in `/workspace/.claude/skills/testrun/SKILL.md` already documents this failure class on **loop-N** runs (loop-2+ HYPOTHESIZE / CONCLUDE under expanded `investigation.md`). What's new here is the same pattern firing on **loop 1**, where investigation.md is at its smallest and the only large preload component is the just-returned gather-composite stdout. That extends the failure mode's reach and shifts the leverage analysis: the loop-N preload-trim fix won't help loop 1.

## Hypothesized drivers (in priority order)

1. **Gather-composite stdout dominates ANALYZE preload on loop 1.** ANALYZE's `_context_loader` blob inlines: alert, investigation.md (small on loop 1), playbook + signature knowledge (constant), and the ANALYZE input from the GATHER step (which on loop 1 IS the 5.9 KB gather-composite YAML). That puts ~12–15 K of the prompt into a single dense YAML block whose structure makes upfront-restatement-thinking expensive. Fix candidates: pre-summarize gather-composite into a compact ANALYZE-input format, or strip the lead-by-lead `query` + `health_probe` blocks ANALYZE doesn't grade against.
2. **PREDICT verbosity inflated the lead-hints carried into ANALYZE's view of GATHER.** Tier 1 PREDICT cues drove longer story prose; the lead hints PREDICT now writes (e.g., *"Focus specifically on proc.pname=runc spawns — frequency, recurrence, and command bodies"*) get echoed into the GATHER prompt and may be re-rendered into ANALYZE's preload via the gather-composite output's metadata fields. Verify by counting lead-hint vs raw-observation chars in the gather-composite YAML.
3. **300 s ceiling is sized for the old preload regime.** Pre-Tier-1 ANALYZE preloads were 6–8 K and finished in 90–150 s consistently. The current 12–15 K shape is ~2× the size; under Sonnet's typical thinking-restatement pattern that maps to ~250–300 s, putting every loop on a knife-edge. A dynamic timeout (`max(300, prompt_chars * 25 ms / char + 60 s)`) is cheap and unblocks empirically without a prompt rewrite.
4. **Sonnet thinking-restatement on the gather-composite YAML.** If the subagent restates the inlined YAML in its first thinking turn before grading, the upfront cost scales linearly with stdout size. Forensic confirmation requires a session-jsonl read; if confirmed, the structural fix is preload-as-XML-tagged-summary rather than verbatim YAML.

## Method

1. **Re-trigger the run and capture forensics.**
   - Same alert (`docker exec -t target-endpoint bash -c whoami`), same harness (`eval_run_orchestrate.sh 100001 --window 5m`).
   - Before launch: instrument `scripts/handlers/analyze.py`'s subprocess.run timeout to capture the actual rendered prompt at dispatch time (write to `{run_dir}/analyze_loop_{n}_prompt.txt`). This is a 3-line patch; revert after the investigation.
   - On timeout, read the prompt artifact + `~/.claude/projects/-workspace-soc-agent/<session_id>.jsonl` to break down per-turn elapsed.
2. **Quantify the preload composition.** Per the captured prompt, count chars by section: `<alert>`, `<investigation>`, `<gather-composite-output>`, `<signature-knowledge>`, `<lead-catalog>`. If gather-composite > 50 % of total, hypothesis (1) is the carry.
3. **Test fix candidates in priority order.**
   - **(a) Compact ANALYZE-input projection.** Add a `_compact_gather_for_analyze()` function in `scripts/handlers/analyze.py` that drops `query.query`, `query.refinements_applied`, `health_probe`, and any `cross_lead_notes` already covered by raw observations; keeps `id`, `name`, `status`, `characterization`, `baseline.characterization`, `outcome` (the grade-relevant fields per `agents/analyze.md`'s grading rulebook). Re-run; measure ANALYZE wall.
   - **(b) Dynamic timeout.** Add `_compute_analyze_timeout(prompt_chars)` returning `max(300, int(prompt_chars * 0.025) + 60)`. Wire into `subprocess.run`. Re-run; if ANALYZE returns at 320–380 s, this is the cheap unblock — but does not address the underlying driver.
   - **(c) Preload-as-XML-summary.** If (a) does not recover the wall, replace the inlined gather YAML with an XML-tagged summary the handler composes from the same data; ANALYZE reads the summary, can fall back to the full YAML on demand via Read.
4. **Decide on durable fix.** (a) is the strongest if it brings wall back under 180 s without losing grade quality. (b) is a safety net independent of (a). (c) is reserved for the case where neither works and the structural decoupling is forced.

## What "done" looks like

Either:

- ANALYZE wall returns to ≤ 200 s on loop 1 across three consecutive 100001 runs with comparable gather-composite stdout, AND grade quality on a known-disposition replay is preserved, OR
- A dynamic timeout lands as a documented safety net AND a follow-up task captures the underlying driver (preload size pressure) for later structural work, OR
- The investigation traces the timeout to a different driver (e.g., wazuh-indexer query latency stacking inside the subagent's tool calls — though ANALYZE shouldn't run tools), and the task is closed with a redirect to that driver.

In all cases: `testrun/SKILL.md` quirk #22 is updated to extend the loop-N pattern coverage to loop 1 when gather-composite stdout exceeds whatever threshold the bench identifies.

## Files / pointers

- Failed run: `/tmp/soc-agent-orchestrate-eval/20260427-164551-rule100001/runs/ed4e10fa-9d03-458f-92ed-22ced17568fd/`
  - `state.json` — phase history stops at ANALYZE
  - `driver.log` — `FAILED: subagent analyze timed out after 300s`
  - `subagent_outputs/20260427T165459811022Z-gather-composite-27cf4718.txt` — the upstream stdout that drives ANALYZE's preload
  - No `*-analyze-*.txt` (subagent killed before output)
- Handler code: `/workspace/soc-agent/scripts/handlers/analyze.py` (timeout config + subprocess dispatch).
- Preload composition: `/workspace/soc-agent/scripts/handlers/_context_loader.py` — search for `analyze` to find the section assembly.
- Sibling skill: `/workspace/.claude/skills/testrun/SKILL.md` quirk #22 — naming convention + leverage-ordered fix list (a)/(b)/(c) above mirrors that section's framing intentionally.
- Branch: `predict-fastpath-cache` (HEAD `eda4f4a`). Tier 1 PREDICT cue commit (`eda4f4a`) is the most recent prompt change; bisecting against `e9b10ae` would say whether the preload-size delta predates Tier 1 or is caused by it.

## Out of scope

- gather-composite wall regression itself — separate task `gather-composite-templated-wall-regression.md`. Findings may overlap (gather-composite output drives ANALYZE preload), but the questions are independent.
- ANALYZE quality (grade-rule effectiveness, load-bearing-field naming, etc.) — Tier 2 evaluation work, blocked on this task succeeding.
- CONCLUDE timeout pattern (separate, well-documented in quirk #22 already).
- Main-agent harness ANALYZE behavior — different code path; this task is orchestrator-only.
