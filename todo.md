# v3 Cyber Response Agent — Status

## Done (v3 rewrite)

- [x] Delete v2 pipeline (shell hooks, bash scoring, old tests)
- [x] Python schemas: report_frontmatter, state machine, precedent (dataclass validators)
- [x] Hooks: validate_report.py (Stop hook safety gate), write_state.py (state machine), investigation_summary.py (JSONL outcomes), audit_tool_calls.py (PostToolUse JSONL)
- [x] Hook registration moved to plugin.json (plugin-only, not fired during development)
- [x] Knowledge base migrated: context.md, playbook.md (hypothesis catalog + leads), precedents/ (v3 schema)
- [x] Signature template updated for v3 vocabulary
- [x] Investigator agent: hypothesis-driven 5-phase loop (C→H→G→A→CONCLUDE) with looping
- [x] Triage skill: entry point, validates alert, spawns investigator
- [x] Investigation checklist: self-check guide agent reads at CONTEXTUALIZE, verifies before CONCLUDE
- [x] Vendor-neutral: no hardcoded SIEM mapping, works with any MCP tools
- [x] Wazuh content marked as example/testing reference
- [x] Unit tests: 72 passing (report validation, state transitions, KB schema, fixtures, e2e structural)
- [x] LLM integration tests: 6 passing (real Claude CLI invocation, validates full pipeline output)
- [x] CLAUDE.md updated for v3

## MVP — Remaining

- [ ] Run manual end-to-end test with live Wazuh playground (validate with real SIEM data)
- [ ] Test with a second alert scenario (brute-force) to check investigator handles escalation correctly
- [ ] Wire up the triage skill as actual Claude Code plugin invocation (currently tested via prompt, not `/soc-agent:triage`)

## Followups from archetype-directory refactor (2026-04-11)

- [ ] **Ticket-context subagent: entity-set past-ticket query.** Extend the ticket-context subagent (invoked at CONTEXTUALIZE) to query the ticketing system for past resolved tickets matching the current alert's entity set (srcip, srcuser, host, container image, etc.) — not just by signature or time window. CONCLUDE should then be able to cite a specific `matched_ticket_id` grounded in a real past ticket, without a second subagent round-trip. Related: the existing CONTEXTUALIZE precedent-scan subagent scans cached KB snapshots under `archetypes/*/*.json`, which are hand-curated. The ticketing-system query is the live source of truth that those snapshots cache.
- [ ] **Precedent-matching temporal awareness.** When the ticket-context subagent (above) ranks past tickets as candidate precedents, it must filter out temporal anchor confirmations: a past ticket whose `anchors_at_time` included `temporal: true` entries (on-call windows, change tickets, deploy runs) does not transfer forward in time without re-confirmation. The skill at the matching step should surface "this past ticket matches shape + entity class, BUT its grounding depended on temporal state that has since elapsed — the current investigation must re-confirm the equivalent anchor today." Judge Tier 2 already does this semantic check (GROUNDING_MATCH criterion); the skill side needs the same logic applied at match time to avoid surfacing stale matches as confident.
- [ ] **Precedent auto-extraction from ticketing system.** Currently the KB's precedent snapshots under `archetypes/*/{TICKET-ID}.json` are hand-curated. Long-term, build a sync pipeline that automatically captures snapshots from the real ticketing system when tickets close under an archetype — so precedents stay fresh without manual curation and so `captured_at` reflects real ticket-close times. Requires deciding: which ticketing system (ServiceNow / Jira / Linear / ...), what fields map to the schema, how to mark temporal anchors at capture time.

## Next — Reliability & Evaluation

### Post-mortem surfaces screen misclassifications as improvement input

Run #9 made this sharp: the alert the agent investigated was a real regularly-scheduled `monitoring_probe.sh` invocation at the `:30:02` cron slot — the canonical SEC-2024-001 shape — and the archetype precedent was pre-cached. In a well-tuned deployment, this *should* have been a SCREEN match resolving to benign/high in 3-5 minutes. Instead the SCREEN subagent returned `no_match` because the 5-min window contained an off-cadence stray (my manual trigger), and the full loop ran for 11 minutes and $2.28 before escalating the analyst with an accurate-but-verbose hand-off.

**This is an improvement signal, not a bug**. In a realistic deployment, the operator will encounter it as: "why is my SOC agent burning $2/run on something it already has a precedent for?" The answer is almost always that the SCREEN table for the relevant signature is too narrow — it fails on edge cases the agent *could* recognize if the indicators were defined more precisely. This is exactly the kind of observation the `/investigate` post-mortem loop should catch and surface.

**The post-mortem should flag every run where all three of these are true simultaneously:**

1. **Disposition is "escalated / benign"** (or "escalated / inconclusive" with the analyst hand-off leading to a benign hypothesis) — i.e. the full investigation arrived at a recommendation the SCREEN path could theoretically have provided.
2. **A precedent match was identified in CONTEXTUALIZE but NOT used for resolution** — either the precedent-scan subagent ranked a precedent as `strong` and the agent then refused the transfer, OR the agent reached ANALYZE with a `matched_archetype` candidate that was declined at CONCLUDE.
3. **The archetype's trust anchor was refuted on a SHAPE violation, not a CONTENT violation** — i.e. the investigation failed the archetype not because the evidence contradicted the benign reading but because the observed shape (attempt count, timing cadence, username rotation, etc.) technically exceeded the archetype's confirmation-shape constraints.

When all three fire, the post-mortem should output a structured finding like:

```
Screen-miss candidate:
  signature: wazuh-rule-5710
  archetype: monitoring-probe
  precedent: SEC-2024-001 (strong match, refused at CONCLUDE)
  refusal reason: attempt_count_5min=2 (shape violation on "single attempt, no retry burst")
  stray event: 23:25:49.198Z srcuser=monitorprobe (off-cadence ~4m14s)
  improvement candidates:
    - relax the attempt_count_5min indicator from "exactly 1" to "≤ 2 AND cadence-consistent"
    - add a cadence-jitter tolerance to approved-monitoring-sources anchor
    - introduce a "scheduled-probe-with-jitter" sub-archetype
  cost saved if screen had matched: ~$1.65 (run #9 $2.28 vs run #7 $0.63 SCREEN-resolved baseline)
```

- [ ] **Implement screen-miss detection in the investigation post-mortem.** Walk `runs/*/report.md` frontmatter + the `runs/*/audit.jsonl` outcome logs, filter for the three-condition pattern above, and emit a screen-miss report per signature. Should be runnable ad-hoc (`scripts/screen_miss_report.py --since 2026-04-01`) and also periodically (cron-friendly).
- [ ] **Feed the output back into signature onboarding as structured input.** The `/author` skill already exists for authoring signature playbooks. Add a post-mortem intake step: when opening a playbook for revision, check for recent screen-miss reports for that signature and surface them as "the agent is fighting these shapes, should the SCREEN table be adjusted?" Do NOT auto-apply — this is an analyst-mediated loop, not a self-modifying one.
- [ ] **Archetype refinement over rewriting.** When a screen-miss points at a shape-violation refusal, the fix is almost always *refining the archetype's declared confirmation shape* (or adding a sub-archetype for the observed variant), NOT relaxing the anchor's safety guarantees. The post-mortem output should suggest archetype-level changes, not anchor-level ones.

Cross-reference: see `.claude/skills/evaluate/SKILL.md` run #9 entry for the canonical example. The `monitoring-probe` archetype is the first concrete candidate for this refinement loop — its current `attempt_count_5min: exactly 1` indicator is too brittle and will trip on any cron jitter, duplicate cron entry, or operator-manually-invoked probe, forcing the full loop on alerts the precedent already resolves.

### Sonnet-main eval sweep findings (2026-04-13)

Findings surfaced by running 4 Sonnet-main evals (runs #11–#14 in `.claude/skills/evaluate/SKILL.md`) with the three new SKILL.md discipline cues (circumstantial-vs-authoritative, statistical predictions, pitfalls subsection). Keeping as distinct items because each is independently actionable regardless of the migration timeline.

- [x] **Preload hook race condition fixed (2026-04-13).** `contextualize_preload.py` was forking a detached child to spawn both ticket-context and archetype-scan in the background; the main agent's first CONTEXTUALIZE read raced the detached writes. Opus was slow enough that files landed in time; Sonnet reads raced past. Fix: ticket-context is now dispatched inline by the main agent as a Haiku `Agent()` call (synchronous by construction, no race). Archetype-scan stays in preload because SKILL.md's graceful fallback handles the race. Validated in run #14.

- [ ] **Forward-looking burst check on 5710 screen.** The `attempt_count_5min` indicator in `knowledge/signatures/wazuh-rule-5710/playbook.md` is backward-looking only ("5 minutes PRECEDING the alert"). For the first alert of a burst, the preceding window is empty so count=1 passes the screen — subsequent burst attempts never get queried. Add a second indicator: `attempts_from_source_60s_after <= 0` (forward-looking), so a burst's first alert correctly fails the screen. Low priority but worth doing before the next Sonnet-main eval cycle on bait-shape scenarios.

- [ ] **Alert-selection determinism in `fetch_alert.py`.** Same scenario, two runs, different alert selected (first-of-burst vs mid-burst). Eval reproducibility requires a stable ordering. Options: (a) add a `--select {latest,earliest,first}` flag, default to `latest`; (b) respect `--offset N` so the eval harness can skip past the first-of-burst alert deliberately. Either works; latest is probably the right default because it matches what a human analyst would pick up. Affects eval reproducibility only, not the agent itself.

- [ ] **Runtime Opus→Sonnet consultation design.** The 3-run Sonnet eval sweep produced one failure (run #11 on 100001: shallow GATHER query + hypothesis bundling + confident-wrong narrative) and three passes. The failure mode is signature-maturity-dependent, not model-capability-dependent — 5710 is mature and Sonnet matches Opus quality, 100001 has thin scaffolding and Sonnet collapsed. Belt-and-suspenders principle says: **keep the knowledge-maturation investment as primary defense, add a narrow runtime Opus consultation at 1–2 high-leverage points as a backstop**. Design decisions pending:
  - **Consultation point 1 — HYPOTHESIZE → GATHER boundary (query construction + hypothesis completeness).** The 100001 failure was upstream at the query: Sonnet queried `rule.groups:falco AND container.id` without pulling `proc.name`, which stripped the sshd-vs-bash discriminator. Opus would have queried with `proc.name` surfaced because it knows the field is load-bearing for 100002 disambiguation. The consultation input is `{alert, active_hypotheses, selected_lead, lead_definition}` → Opus returns `{minimum_discriminating_fields_to_query, flagged_bundled_hypotheses, missing_mechanism_variants}`. This blocks the GATHER dispatch until Opus approves the query shape. Cost: ~1 Opus call per investigation, most expensive under caching.
  - **Consultation point 2 — ANALYZE → CONCLUDE boundary (only when adversarial is being refuted on circumstantial evidence).** Not mandatory on every loop — gated by a hook-level check: "does the ANALYZE assessment assign `--` to the adversarial hypothesis based on anything other than an authoritative query result?" If yes, consult Opus before CONCLUDE; if no, allow the commit. This gate catches the "coherent confabulation" failure mode without the cost of always-on consultation.
  - **What context Opus contributes**: (a) field schema awareness for SIEM queries (which fields carry the discriminators for which signatures), (b) mechanism-variant enumeration (splitting bundled hypotheses into testable distinct ones), (c) environment-knowledge integration (reading the ip-ranges / identity-patterns / variant documentation as Opus did unprompted in run #13).
  - **Not included**: a CONCLUDE-side consultation that duplicates Tier 2 judge work. The judge already receives full investigation + report + archetype + precedent and runs 6 criteria; a pre-CONCLUDE Opus call would double-tax the same check.
  - Defer implementation to the migration session. Design-only here.

- [ ] **Real-world robustness caveats.** The 4 Sonnet runs were on a medium-quality harness (playground containers, manually triggered alerts, mature-for-this-eval signatures) with relatively short investigations (≤6 phases, ≤2 hypothesis loops). Production conditions that the eval sweep did NOT exercise and that are the most likely sources of Sonnet-specific failure:
  - **Missing or degraded data sources** — Wazuh backlog, SIEM index gap, `data-source-debug` lead fires. Sonnet's query-formulation depth may or may not survive this. Opus #9's recovery on 9 denied/errored tool results in one run is the baseline to match.
  - **Stale knowledge** — ip-ranges.md with terminated monitoring sources, anchor docs referencing deprecated tickets, `approved-monitoring-sources.md` out of sync with production. Sonnet may accept stale citations at face value where Opus would notice the mismatch.
  - **Longer investigation loops** — 5+ hypothesis loops with verification and scoping cycles. The short-investigation hypothesis bundling we observed may compound over many loops; coherence decay over long contexts is an untested Sonnet failure mode.
  - **Novel alert shapes** — alerts outside the playbook's archetype space that require genuine first-principles mechanism enumeration. Run #13's `?monitoring-bait-scenario` novel hypothesis was encouraging, but it was enabled by explicit environment-variant documentation. Truly-novel cases where no documentation grounds the variant are untested.
  - **Ambiguous anchor confirmations** — the change-management ticket is in a weird state, the on-call schedule is in a transition, the approval cadence has a pending update. Sonnet's tendency to commit confidently may produce wrong grounding assertions here.
  - **Rate-limited or noisy SIEM queries** — production indexes with 10×–100× the event volume of the playground. Subagent query-construction quality matters much more under high volume.
  Path forward before production: eval sweep on a harder signature (100001 or a genuinely novel one) post-scaffolding-maturation, and at least one eval where we deliberately degrade a data source to see how Sonnet handles the fallback.

### Past investigations as first-class investigation input (2026-04-13)

Today the agent learns from past investigations only via hand-curated precedent snapshots under `archetypes/{name}/*.json` and the ticket-context subagent (which queries the ticketing system, not prior agent runs). The corpus of prior `runs/*/` with completed `report.md` + passing Tier 2 judge is currently unused — it's an audit trail, not a learning substrate. This is a structural gap: the agent's richest source of shape-matching signal (its own past work on similar alerts) is invisible to the hypothesis loop.

This deserves its own PR once the Sonnet-main migration stabilizes. The work splits into two linked tracks:

**Track A — past-runs as queryable evidence.**

- [ ] **Define "successful run"** for past-run indexing. Minimum bar: `report.md` exists, Tier 1 passed, Tier 2 VERDICT:PASS, `status=resolved` with grounding leg satisfied. Escalated runs with clear analyst disposition (via a post-hoc feedback loop) could eventually qualify but not in v1. Store the eligibility flag in `runs/audit.jsonl` at run completion so the index doesn't have to re-compute it.
- [ ] **Build a past-runs index.** Per signature, extract: entity set (srcip, srcuser, host, image family, …), trace line, matched_archetype, disposition, confidence, key `++`/`--` observations from the investigation log. Store as a flat index (SQLite or JSONL) keyed by signature_id + entity-class hash, so a query can land in <100ms without reading every run dir.
- [ ] **Expose as a lead: `past-investigations`.** Follows the same shape as every other lead — a `leads/past-investigations/definition.md` + per-vendor templates (in this case a single template pointing at the local index). The lead takes the current alert's entity set as input, returns the top-N matching past runs ranked by entity similarity + recency + Tier 2 pass, plus a one-line summary of each. The main agent can select it at HYPOTHESIZE just like any other lead.
- [ ] **Temporal staleness check** — past runs older than a threshold (or whose grounding leg depended on temporal anchors) should be flagged as "shape-transferable but grounding must be re-confirmed," matching the existing precedent-staleness logic in Tier 2 GROUNDING_MATCH.

**Track B — strengthen the investigation language so past runs are comparable.**

This is the harder half. For past runs to be queryable as pattern fuel, the structured content in `investigation.md` — hypothesis names, lead names, weight assessments, observation phrasing — needs to converge across runs. Today each run invents its own hypothesis names (`?compromise-followup` vs `?session-compromise` vs `?followup-success`), which makes cross-run matching fuzzy.

- [ ] **Canonicalize hypothesis vocabulary per signature.** Each signature's playbook should define a canonical seed-hypothesis name set; the agent can refine descriptions but must not rename the seeds. Freeform novel hypotheses remain allowed but are flagged as "novel" so the cross-run matcher knows they aren't canonical.
- [ ] **Canonicalize lead names.** `leads/` directory names are already the authoritative naming registry; enforce that investigation.md's "Selected lead:" field must match a directory entry exactly. A Layer 2 schema check (see "State Machine Transition Verification Criteria" — next design iteration) can enforce this deterministically.
- [ ] **Structured observation snippets.** ANALYZE's `reasoning: "..."` field is today freeform prose. Adding a lightweight convention — "prediction: X, observation: Y, result: matches|contradicts|partial" — would make cross-run observation matching possible without an LLM in the loop. Non-trivial prompt change; defer until Track A shows value.
- [ ] **Post-mortem feedback loop** — when a novel hypothesis wins in a run, the post-mortem should flag it as a candidate for promotion into the signature's canonical seed set. Analyst-mediated, not automatic (same model as the screen-miss detection above).

**Why this matters for the Sonnet-main decision.** A stronger past-runs channel reduces the reasoning load on the main agent at HYPOTHESIZE — the agent is increasingly *matching* to prior work rather than *generating* from first principles. That shifts more of the weight toward pattern recognition (where Sonnet is competitive) and away from novel reasoning (where Opus wins). The cost lever compounds with the migration, but the migration should not wait for this work — they are independent.

### Prompt-level cost reduction: reduce turns and output volume (2026-04-12)

Analysis of run #9 transcript (full 6-phase loop, $2.28) and run #9-SCREEN (SCREEN-resolved, $0.89) reveals the main agent's cost is driven by **turn count × context size** (cache reads) and **output volume** (tool inputs, investigation.md, report.md). The agent generates 52K chars of output across 52 turns in the full loop; 80% is tool input (Write/Edit/Agent calls), 18% thinking, 3% text. The three largest output chunks are investigation.md edits (15.9K chars), report.md write (12.3K chars), and subagent prompts (5.9K chars).

These levers are **orthogonal to the Sonnet migration** — they reduce the work done regardless of which model does it. Combined, they multiply with the model-tier savings below.

| Configuration | SCREEN-resolved | Full loop |
|---|---|---|
| Current Opus baseline | $0.89 | $2.28 |
| Opus + prompt levers | ~$0.50 | ~$1.30 |
| Sonnet (no prompt levers) | ~$0.30 | ~$0.75 |
| Sonnet + prompt levers | ~$0.18 | ~$0.45 |

**SCREEN rate is the dominant cost variable.** At 500 alerts/day, the difference between 70% and 30% SCREEN rate exceeds $400/day — larger than any single optimization. Prompt levers and Sonnet migration matter most at scale when SCREEN rate is already high (>60%).

#### Lever 1 — Compressed investigation.md format

investigation.md is the agent's working document, consumed by itself and the Tier 2 judge. It currently uses full prose narratives (4K chars per ANALYZE section alone). The judge needs structured evidence and assessment weights (++/+/-/--), not prose — it checks INTERNAL_CONSISTENCY, EVIDENCE_SUFFICIENCY, and ADVERSARIAL_CHECK against the assessment YAML blocks and specific observations, not narrative quality.

Switch SKILL.md phase templates to terse structured notation. Report.md (analyst-facing) stays verbose.

- [ ] **Rewrite investigation.md templates in SKILL.md** to use compressed YAML-style notation. Each phase section should be ~30-50% of current size. Preserve: hypothesis names, assessment weights with 1-line reasoning, specific observations (IPs, counts, timestamps), lead names, and phase headers. Remove: narrative transitions, repeated context, explanatory prose.
- [ ] **Verify Tier 2 judge still passes** on the compressed format — the judge prompt references "investigation log" and checks for assessment blocks and hypothesis outcomes. Run a manual test with a compressed investigation.md against the judge to confirm.

Estimated savings: ~$0.15-0.20/run (60-70% less output tokens for investigation.md writes, plus reduced context growth for subsequent turns).

#### Lever 2 — Batch parallel reads in CONTEXTUALIZE

CONTEXTUALIZE currently consumes 18 turns in the full-loop run. Many are sequential Read calls for knowledge files (ip-ranges.md, identity-patterns.md, lead definitions) that could be issued as parallel tool calls in a single turn. Claude Code supports multiple tool calls per message.

- [ ] **Add explicit batching instruction to SKILL.md CONTEXTUALIZE section**: "When reading multiple knowledge or environment files, batch independent reads into a single turn using parallel tool calls. Do not issue sequential Reads for files that don't depend on each other."

Estimated savings: ~$0.15-0.25/run (3-5 fewer turns × ~$0.05/turn in cache reads).

#### Lever 3 — Batch write_state with investigation.md writes

Every phase transition currently takes two turns: one Bash call to `write_state.py`, then a separate Write/Edit to investigation.md. These are independent and can be batched into a single turn.

- [ ] **Add explicit batching instruction to SKILL.md phase transitions**: "At each phase transition, issue the `write_state.py` Bash call and the investigation.md Edit as parallel tool calls in the same message."

Estimated savings: ~$0.25-0.30/run (5-6 fewer turns × ~$0.05/turn).

#### Lazy-load — evaluated and deferred

Considered removing the investigation checklist (3.1K chars) and non-matching archetype stories (6.8K chars) from the base prompt and having the agent read them on demand. **Deferred**: the checklist frames the agent's investigative discipline from turn 1 (adversarial hypothesis maintenance, lead severity, grounding requirements). Removing it saves ~$0.23/run in cache reads but risks degrading investigation quality that the Tier 2 judge validates. The archetype stories similarly help COMPLETENESS — having all four in context helps the agent consider sibling archetypes without an extra read. The savings don't justify the quality risk.

### Model-usage architecture: staged migration to Sonnet main agent (2026-04-12)

Run #9 cost split: Opus 1M main **$1.86 (82%)**, Sonnet ticket-context subagent $0.29 (13%), Haiku precedent-scan + screen $0.13 (5%), total $2.28. The main-agent Opus share dominates; PR #34's subagent model pins already captured the easy subagent savings. Next lever: the main agent itself.

**Research findings on whether Sonnet can be the main agent** (all citations in `code.claude.com/docs/en/agent-sdk/*`):

1. **Subagent dispatch is NOT a cost problem on the main agent.** Per Agent SDK subagents doc: "Each subagent runs in its own fresh conversation. Intermediate tool calls and results stay inside the subagent; only its final message returns to the parent." Costs are billed independently. This means the main agent's Opus share in run #9 came from *its own investigation work* (reading knowledge, running queries, reasoning, writing investigation.md and report.md), NOT from orchestrating 3 subagents. The concern that "a Sonnet main agent will be overwhelmed by coordinating subagent spawns" is not architecturally grounded — dispatching 3 `Agent()` calls costs the main agent ~3 turns and no context budget beyond the returned summaries.

2. **Hooks CAN inject initial context via `additionalContext`** on `SessionStart` / `UserPromptSubmit` / `PreToolUse` / `PostToolUse` events, up to 10,000 chars (content over that gets auto-saved to a file and replaced with a preview pointer). This is the documented supported field.

3. **Hooks CAN shell out to `claude --print` subprocesses** — this is the canonical pattern, already in use by the plugin's `validate_report.py` Tier 2 judge. 600s default hook timeout, `async: true` available. Nested sessions do NOT inherit parent MCP config / allowlist / settings automatically — they must be passed explicitly via CLI flags (as the judge already does).

4. **"Pre-loaded subagent result" pattern is not explicitly named in docs** but all the building blocks interoperate. A `SessionStart` or `UserPromptSubmit` hook can synchronously spawn N parallel `claude --print` subprocesses, collect their results, and inject via `additionalContext` on the main agent's initial prompt.

5. **`AgentDefinition.model` supports per-subagent model pins**, so "Opus as consultant called from Sonnet main" is a supported pattern — just declare a subagent with `model: "opus"` and call it only when deep reasoning is needed.

6. **No published benchmarks** compare Sonnet vs Opus as the *orchestrator* in multi-subagent plugins. The capability risk for Sonnet maintaining state-machine discipline and adversarial-hypothesis holding across 30+ turns is real and **empirically untested**.

**Staged migration plan.** Each stage is independently shippable; do not skip forward without measuring the previous stage's result.

#### Stage 1 — Hook-based CONTEXTUALIZE preload (KEEP Opus main)

Move the `ticket-context` and `precedent-scan` subagents out of main-agent dispatch. A new `hooks/scripts/contextualize_preload.py` runs on `SessionStart` (or `UserPromptSubmit` if SessionStart doesn't work through plugin.json command hooks), synchronously spawns two parallel `claude --print` subprocesses for ticket-context + precedent-scan, collects their results, and injects via `additionalContext`. SCREEN stays as a main-agent-dispatched `Agent()` call (it depends on CONTEXTUALIZE's narrative output, so it can't preload).

- [ ] **Implement `contextualize_preload.py`** with parallel subprocess spawn (`asyncio.gather` or `concurrent.futures.ProcessPoolExecutor`), timeout handling, and structured `additionalContext` output keyed as `## Ticket Context` / `## Precedent Scan` sections.
- [ ] **Register on SessionStart or UserPromptSubmit** in `plugin.json`. The hook must read the alert JSON (from the investigation's `alert.json` or the first user prompt's embedded payload) to know what to query.
- [ ] **Shorten `skills/investigate/SKILL.md` CONTEXTUALIZE section** — remove the "dispatch these subagents in parallel" directive, replace with "the preloaded `## Ticket Context` and `## Precedent Scan` sections are already in your context; integrate them into the CONTEXTUALIZE narrative".
- [ ] **Keep `ticket-context.md` and `precedent-scan.md` subagent prompts** — they become the input prompts to the subprocess invocation. No wasted work.
- [ ] **Measure**: re-run evals. Expect -30-60s wall clock, -3 main-agent turns, -$0.15 to -$0.25 cost vs run #9. Same model, no capability risk.

**Why this is worth doing even without a model flip**: the hook-based preload is also **more deterministic** than agent-driven dispatch. Tier 1 validation currently has a `check_ticket_context_spawned` guard because the main agent sometimes forgot to spawn the subagent. A hook-driven preload can't be skipped. Once Stage 1 ships, that soft gate becomes dead code and can be retired.

#### Stage 2 — Sonnet drafts report.md, Opus reviews and edits

Splits the CONCLUDE-phase report write between a cheap draft and an expensive review. Today the main Opus agent writes the entire report.md as its final turn in CONCLUDE — this is the single highest-output-token operation in the whole investigation (run #9 emitted ~29K output tokens total, a meaningful fraction of which was the report body).

- [ ] **New subagent `report-drafter`** pinned to Sonnet. Reads `investigation.md` + `state.json` + `alert.json`, produces a first-draft `report.md` in the correct frontmatter schema.
- [ ] **Main agent (still Opus) reads the draft and edits** via `Edit` rather than re-writing from scratch. The Tier 1 + Tier 2 judge hooks fire on the Edit the same way they fire on a Write, so the existing validation pipeline needs no change.
- [ ] **Safety check**: if the report-drafter subagent fails to produce valid frontmatter or a Tier 2 judge rejects the post-edit version twice, fall back to the current path (main agent writes from scratch). This keeps Stage 2 risk-bounded — worst case is we pay the old price.
- [ ] **Measure**: report-write cost reduction vs run #9's CONCLUDE phase cost. Expect 30-50% savings on the report-write operation specifically.

**Why this lands before the main-agent flip**: the report write is the single highest-leverage target for incremental savings without flipping models. It also validates that Sonnet can produce structurally-correct output under our schema constraints, which de-risks Stage 4.

#### Stage 3 — Sonnet writes hypothesis stories, Opus makes predictions

HYPOTHESIZE-phase work splits into two different cognitive modes that map cleanly onto different models:

- **Stories** are narrative descriptions of what a hypothesis *means* ("the source is a sanctioned monitoring probe firing on its declared ~10-minute cadence using an approved sentinel username"). Descriptive text, cheap output, no hard reasoning — Sonnet-friendly.
- **Predictions** are the *testable implications* of the hypothesis that drive lead selection ("if this is true: exactly 1 attempt in the 5-min window, no retries within 60s, attempt_count_5min ≤ 1, source IP on the approved-monitoring-sources list, username in the monitoring-pattern set; if any of these fail, the hypothesis is refuted"). Hard reasoning about what evidence would discriminate between hypotheses — Opus-worthy.

The split lets the cheap model do the verbose descriptive work (high output tokens, low reasoning load) and reserves the expensive model for the lead-discrimination question (low output tokens, high reasoning load).

- [ ] **New subagent `hypothesis-story`** pinned to Sonnet. Given the CONTEXTUALIZE narrative + the playbook's candidate-hypothesis seed list, produces a structured story per hypothesis: background, what it explains, what it doesn't explain, how the analyst would colloquially describe it. Output: one `story.md` per hypothesis in the run dir.
- [ ] **Main agent (still Opus) reads stories and generates testable predictions**. For each story, Opus produces the discriminating evidence list — exactly the `required_anchors` / `predictions` shape the archetype model already expects. Main agent then picks leads to confirm/refute based on the predictions, not the stories.
- [ ] **Guard against Sonnet over-generation**: cap stories at 4-6 per run (the playbook seed count is already the natural limit). If the Sonnet drafter tries to generate new hypotheses outside the playbook seeds, reject and retry — new hypotheses should come from the main agent's evidence-driven reasoning, not from a drafter that's looking at the playbook.
- [ ] **Measure**: HYPOTHESIZE phase output-token cost reduction vs run #9. Stories are where the verbose narrative lives; extracting them should visibly move the needle.

**Why Stage 3 before the main-agent flip**: stories-vs-predictions is a natural cognitive-split test of whether Sonnet can handle the *descriptive* half of our workload safely. If it can, we have stronger evidence that Sonnet can handle the broader investigation work in Stage 4. If Sonnet produces garbage stories that poison the predictions, we learn that before betting the whole main agent on Sonnet.

#### Stage 4 — Flip main agent to Sonnet (AFTER Stages 1-3 ship and measure cleanly)

Do not attempt Stage 4 until:
- Stages 1-3 are all merged and have at least 5 clean eval runs each showing no regression on: adversarial-hypothesis discipline, Tier 2 judge pass rate, state-machine phase progression, report schema validity.
- The `/evaluate` skill's eval suite is larger than 1 run per configuration so comparisons are statistically meaningful (currently a single-run-per-config experiment, which is not enough).
- The post-mortem screen-miss detection (above section) is implemented and has catalogued what fraction of "escalated benign" runs *should* have been SCREEN-resolved — this tells us how much of the capability risk is already absorbed by the SCREEN path and how much lands on the main agent.

When ready:

- [ ] **Change `claude` invocation in `eval_run.sh` and plugin.json** to pin the main agent to Sonnet. Use `--model sonnet` or the config equivalent.
- [ ] **Re-run full eval suite** across both Scenario A (monitoring-probe, SCREEN fast-path) and Scenario B (monitoring-bait, full loop). Compare turn-by-turn against the Opus baselines (#5, #7, #9, and any Stage 1-3 baselines).
- [ ] **Specific safety metrics to watch**:
  - Adversarial hypothesis refutation timing (Sonnet may refute too quickly)
  - State-machine bypass attempts (Sonnet may try to skip phases — hooks enforce externally, but bypass *attempts* are a signal)
  - Tier 2 judge retry count per run (Sonnet may need more edits)
  - Budget overruns (Sonnet may run longer to reach the same conclusion, partially offsetting cost savings)
  - Lead-choice diagnosticity (Sonnet may pick less discriminating leads)
- [ ] **Revert immediately** if any safety metric regresses meaningfully. Sonnet-main is a cost-saving move, not a load-bearing architectural change.

#### Stage 5 — Opus consultant subagent (Sonnet main escalates to Opus for hard calls)

Once Sonnet-main is stable, introduce a `deep-reason` subagent pinned to Opus that the Sonnet main agent calls at specific high-stakes decision points. This recovers capability on hard cases without paying Opus rates everywhere.

- [ ] **Declare `deep-reason` subagent** with `model: "opus"` and a prompt focused on diagnostic-lead selection and evidence synthesis.
- [ ] **Wire call-points** at specific SKILL.md decision moments:
  - HYPOTHESIZE → GATHER transition when hypothesis count > 2 AND evidence is ambiguous
  - GATHER → ANALYZE when a query returns ambiguous results that could support multiple hypotheses
  - ANALYZE → CONCLUDE when the hypothesis ledger has no clear winner AND no clear escalation trigger
- [ ] **Budget guard**: cap `deep-reason` to 2 invocations per run by default. Sonnet main should not be able to escalate to Opus unbounded — that's how we slide back toward Opus-everywhere without a measurable benefit.
- [ ] **Measure**: compare full-eval cost with `deep-reason` vs without. If the consultant adds material cost without moving disposition-accuracy metrics, revert — it's a nice-to-have, not a load-bearing component.

### Subagent enforcement — stronger gating

The Tier 1 ticket-context check (`validate_report.check_ticket_context_spawned`) catches missing spawns at conclude-time by walking `tool_audit.jsonl`. This is a soft gate: the agent only finds out it was wrong at the very end, then has to retry the report write. If observed in eval runs that the recovery is expensive (extra Tier 2 judge invocations, wall-clock blow-out, agent confusion about what went wrong), promote to a hard gate via a new PreToolUse hook:

- [ ] PreToolUse blocking hook: count tool calls per session against `tool_audit.jsonl`, and after N tool calls (N≈5) reject any further tool call until a Task call referencing `ticket-context` has been recorded. Error message points the agent at SKILL.md §CONTEXTUALIZE step 3 with the Task template.
  - Caveat: PreToolUse hooks fire before EVERY tool call so they need to be cheap (read-only, no LLM). Implementation should cache the "ticket-context spawned" boolean per session_id.
  - Risk: blocking too aggressively can fight the agent if it needs a few read calls before spawning. Tune N based on observed eval data.
  - Also extend the same pattern for Explore/precedent-scan subagent if eval data shows it being skipped too.

### State machine bypass — soft boundary, not isolated

Discovered during the first eval run: when `write_state.py` is unavailable (e.g., blocked by allowlist, unavailable env, etc.), the agent can — and does — write `state.json` directly via the `Write` tool, bypassing the phase-ordering checks in `write_state.py` entirely. The agent in the eval run wrote `state.json` with `phase: "ANALYZE"` and a fabricated history list `["CONTEXTUALIZE", "SCREEN", "HYPOTHESIZE", "GATHER", "ANALYZE"]` even though it had only completed CONTEXTUALIZE work.

Implication: the state machine in the SKILL.md design is **enforcement-by-convention**, not enforcement-by-isolation. A misaligned (or under-resourced) agent that knows the state.json schema can fake state transitions whenever it wants. The Tier 1 validation in `validate_report.py` catches malformed reports but does not catch faked state history.

Possible mitigations (pick one, not all):

- [ ] PreToolUse hook gates `Write` against any path matching `*/state.json` inside a run dir, allowing only invocations originating from `write_state.py`. Cleanest but requires identifying the invoker, which PreToolUse may not surface.
- [ ] Move state out of a file the agent can write. Use a sqlite db or a write-only socket that only `write_state.py` knows how to address.
- [ ] Accept the soft-boundary model and document explicitly that the safety guarantee is "well-aligned agent + structural validation of outputs" rather than "process-isolated state machine". Update `docs/security-model.md` accordingly.

The decision matters more than the implementation. The current behavior is "the state machine looks isolated but isn't", which is the worst of both worlds.

### State Machine Transition Verification Criteria

Goal: Add actionable verification gates to each transition so `write_state.py` can reject transitions where the agent hasn't done meaningful work. Currently the state machine enforces _legal transitions_ but not _quality of work within a phase_. Data from evaluation runs should inform which criteria matter most (start loose, tighten based on observed failure modes).

**Criteria to define per transition (gather data first, then enforce):**

- [ ] CONTEXTUALIZE → SCREEN/HYPOTHESIZE: Did investigation.md get written? Does it contain alert observables, entity extraction, and a resolution map (available operations + gaps)?
- [ ] SCREEN → CONCLUDE: Does screen output contain `screen_result: match`, a named `matched_pattern`, and a valid `matched_precedent` file that exists? Were the required leads actually run (not zero)?
- [ ] SCREEN → HYPOTHESIZE: Does screen output contain `screen_result: no_match` with a `reason`? Is evidence from screen leads carried forward into investigation.md?
- [ ] HYPOTHESIZE → GATHER: Does investigation.md contain at least one `?hypothesis` with status `active`? Is there a selected lead with predictions (what each hypothesis predicts this lead will show)?
- [ ] GATHER → ANALYZE: Was at least one tool call made (query executed)? Does investigation.md contain raw observations for the lead (not just "no results")?
- [ ] ANALYZE → HYPOTHESIZE (loop): Does investigation.md contain assessment weights (++/+/-/--) for the just-completed lead? Is there a stated reason for needing another loop (unresolved hypotheses, new questions)?
- [ ] ANALYZE → CONCLUDE: Is there exactly one `++` hypothesis? Are all adversarial hypotheses explicitly `--` refuted with reasoning? Does the investigation meet min-leads-by-severity?

**Approach:**

1. Instrument: log what the agent actually writes at each transition during evaluation runs
2. Identify failure modes: where does the agent skip work, produce shallow output, or transition prematurely?
3. Define thresholds: which criteria are hard gates (block transition) vs soft warnings (log but allow)?
4. Implement incrementally in `write_state.py` — start with structural checks (file exists, field present), defer semantic checks

### Precedent schema — abstract the environment out

Discovered during the SCREEN cost-reduction workstream: `monitoring-probe-001.json` has literal environment values (`srcip: 10.0.1.50`) baked into `key_indicators` and `alert_data`, which conflicts with the actual playground network (`172.22.0.0/16`) and — more importantly — doesn't generalize to any real deployment. A precedent is an abstract story; the raw tickets attached to it are what carry the environment-grounded details.

- [ ] Refactor precedent schema: move literal values (IPs, hostnames, ticket-specific timestamps) out of `key_indicators` and `alert_data`. Introduce a sibling `tickets/` directory per precedent containing the raw alerts that resolved via this story, so historical matching can work without the precedent file claiming specific values.
- [ ] `key_indicators` should carry semantic classifications (`source_classification: internal-monitoring-host`, `username_classification: monitoring-pattern`), matching the shape the new 5710 screen indicators already use.
- [ ] Update `precedent.py` schema validator + `test_kb_schema.py` accordingly.
- [ ] Migrate the existing `monitoring-probe-001.json` and `brute-force-001.json` as the first pass.

### Main-agent baseline cost lever

`eval_run.sh` does not pass `--model` to `claude`, so the main investigation loop runs at whatever the harness default is (observed: `claude-opus-4-6[1m]`). For a signature that's hypothesis-driven but not deeply adversarial, Sonnet may be sufficient and would drop baseline cost substantially. SCREEN's Haiku override is the bigger lever, but this is worth evaluating once SCREEN is pinned.

- [ ] Add `--model sonnet` to the `claude` invocation in `playground/scripts/eval_run.sh`.
- [ ] Run a matched eval pair (same alert, Opus vs Sonnet) and compare: disposition correctness, tool-call count, loop count, cost, wall clock.
- [ ] If Sonnet is comparable on quality, promote it to the default. Document the finding in `.claude/skills/evaluate/SKILL.md` quirks.

### Evaluation Plan — Screening Phase

Screening is the right starting point for evaluation:

- Most common sub-flow (most alerts should match a known pattern)
- Runs before the investigation loop — poor screening contaminates downstream context
- Cheapest to evaluate (1-2 leads, deterministic pattern matching, clear pass/fail)

**Evaluation approach:**

- [ ] Build a test corpus: ~10-20 alerts per signature covering the pattern space (clear matches, near-misses, true negatives)
- [ ] Define ground truth: expected screen_result, matched_pattern, and disposition per alert
- [ ] Run screening subagent against corpus, collect structured output
- [ ] Score: accuracy, false match rate, false no-match rate, output format compliance
- [ ] Identify failure modes: which patterns break, which indicators are ambiguous, which prompts need tuning
- [ ] After screening is solid: extend to ticket-context subagent, then full investigation loop

### External retry-on-truncation wrapper (observed 2026-04-11, eval run #8)

In eval run #8 the agent produced a high-quality CONTEXTUALIZE + SCREEN, correctly refused to short-circuit on a polluted monitoring-probe window, transitioned into HYPOTHESIZE, read grounding knowledge, then called `Read` against `knowledge/environment/operations/` — a directory. The tool returned `EISDIR is_error=true`, the Stop hook fired, and the Claude Code loop closed the session with `terminal_reason: "completed"` / `stop_reason: "end_turn"` — **without feeding the tool error back to the model for another turn**. No retry, no recovery, no report.md. The agent consumed \$1.15 and 331s of wall clock on a run that produced a complete investigation.md through SCREEN but an empty HYPOTHESIZE section.

Claude Code docs say "turns continue until Claude produces output with no tool calls" — so in principle a tool_use followed by is_error should continue the loop. Our observation conflicts with that. Docs do not cover the stream-json result event schema, `terminal_reason` values, or tool-error-in-loop behavior, so we can't tell from docs alone whether this is a 2.1.101 bug, a Stop-hook interaction quirk, or a subtle edge case. **Classes of "the CLI hangs up mid-investigation" bugs will keep happening** — either from tool errors, transient API failures, hook misbehavior, or unknown-unknowns — and the right structural fix is not to hunt them one by one.

**Proposal: external retry-on-truncation wrapper around `eval_run.sh` (and eventually production `/investigate` dispatch).**

- [ ] **`playground/scripts/eval_run.sh` wrapper that detects truncated runs and resumes from transcript state.** When `claude --print` exits, check if `runs/<uuid>/report.md` exists. If not, the run is truncated. Walk `runs/<uuid>/state.json` (last phase), `runs/<uuid>/investigation.md` (phase sections populated), and the `transcript.jsonl` tail to identify where the agent stopped. Re-invoke `claude` with a continuation prompt that hands the agent the existing run dir and asks it to pick up from the recorded phase. The continuation invocation MUST NOT restart CONTEXTUALIZE — it should read the existing `investigation.md` + `state.json` and resume at the recorded phase. Hard cap on retry count (e.g. 2) to avoid infinite retry loops on genuine dead-ends. Log every retry to `runs/<uuid>/retry.jsonl` with the trigger condition so the eval postmortem can distinguish "completed naturally" from "completed after N retries".
- [ ] **Only fix the underlying Read-directory-crashes-the-loop issue if it recurs across multiple evals.** Low priority until we see it again — a single observation under polluted test conditions is not enough signal to justify a skill-prompt patch or a hook-level workaround, and adding defensive pre-Glob instructions everywhere `Read` appears would bloat SKILL.md for a suspected one-off.
- [ ] **File Claude Code feedback** on the termination-after-tool-error observation — docs gap is real regardless of whether the underlying behavior is a bug. See `.claude/skills/evaluate/SKILL.md` run #8 entry for the exact symptoms and transcript location.

Why an external wrapper and not an in-agent hook: a Stop hook or PreToolUse hook can't restart the agent loop from outside — the CLI process owns the loop. A wrapper sits one level up, owns retry policy, and works for any class of CLI-level truncation (tool errors, transient failures, SIGKILL'd subprocess, etc.). The investigation run dir is already designed for resumption — `state.json` carries phase history, `investigation.md` is append-only, `alert.json` never changes. The wrapper just needs to tell the agent "here's the run dir, here's the phase you stopped at, continue from there."

## Phase 2 — Post-MVP

### Agent Architecture

- [x] Lead subagents — refactor so each lead is executed by a subagent with isolated context. Subagent receives hypothesis predictions + lead definition, executes queries, returns structured summary (observation + characterization). Keeps raw SIEM data out of the main agent's context window. Reframe Philosophy to reflect agent-as-director, subagents-as-executors
- [ ] Context window management — migrate detailed investigation reasoning to a subagent. Main agent holds: investigation flow, phase state, key findings, hypothesis table. Reasoning subagent handles: detailed evidence analysis, hypothesis weighting, narrative construction. Prevents context exhaustion on complex multi-loop investigations
- [ ] Tool discovery refactor — split into two concerns: (1) data availability (main agent consults `knowledge/environment/data-sources/` to know what questions can be answered), (2) tool mechanics (lead subagent consults `knowledge/environment/systems/` for query patterns). Also: not all tools are MCP — agent may need to call APIs via scripts
- [x] Tier 2 semantic judge — Haiku validates report consistency after investigation (judge_report.py + judge_prompt.md, invoked via claude CLI)
- [x] Precedent schema: added `alert_data` field (raw alert for judge comparison + future post-mortem seeding)
- [x] CONTEXTUALIZE: Explore subagent for recent alerts — situational awareness, alert correlation (added to SKILL.md)
- [x] Playbook-driven vs investigation-loop separation — implemented as SCREEN phase: playbooks define fast-path patterns checked by a cheap subagent (Sonnet/Haiku) before the full investigation loop. Falls through to full loop on no match.
- [x] Ticket-context skill/subagent — extract CONTEXTUALIZE alert context (recent + related alert scanning) into a dedicated skill with pre-made queries. Reusable across signatures and invocable independently
- [x] Budget enforcement hook — cap token/cost spend per investigation
- [x] Input sanitization hooks — validate alert_json before investigation starts

### Knowledge Expansion

- [x] Telemetry infrastructure for 3 new signature domains (FIM, process execution, DNS)
  - dnsmasq local resolver with query logging + Wazuh decoder + rules (100100-100117)
  - Wazuh agent syscheck: 5-min frequency, realtime+report_changes on /etc
  - Workload scripts: fim_activity.sh, dns_activity.sh, enhanced suspicious_patterns.sh
- [x] Signature knowledge: FIM (Wazuh syscheck rule 550) — context.md, playbook.md, precedents/
- [x] Signature knowledge: Suspicious Process Execution (Falco/Wazuh 100001) — context.md, playbook.md, precedents/
- [x] Signature knowledge: Suspicious DNS Query (Wazuh 100110+) — context.md, playbook.md, precedents/
- [x] `common/leads/` — reusable lead definitions across signatures (directory scaffolded)
- [x] `environment/data-sources/` — data mapping: what data exists where (state + events)
- [x] `environment/context/` — classification heuristics (ip-ranges, identity-patterns, criticality, data-classification)
- [x] `environment/systems/` — system-specific implementation knowledge (wazuh/ migrated from common/utilities/)
- [ ] Populate lead definitions in `common/leads/` (authentication-history, source-reputation, etc.)
- [ ] Populate environment files with real org data (currently example/template content)

### SIEM CLI

- [x] ~~Configurable host/port~~ — deferred: config file + env var override is sufficient; CLI flags add no value for agent-invoked tools
- [x] ~~Multiple authentication options~~ — deferred: Wazuh only supports username/password→JWT (Manager) and basic auth (Indexer); no alternative auth methods to implement
- [x] ~~Vendor abstraction~~ — deferred: intentionally separate CLI per SIEM (different configs, query languages, auth flows); abstraction layer adds complexity without benefit

### Operations

- [ ] `act` mode — auto-close for mature signatures with high-confidence precedent matches
- [ ] Retention policy for run data (configurable cleanup)
- [ ] Audit dashboard / analytics on investigation outcomes

### Package Management

- [x] Finalize packaging strategy — stdlib-only core, optional dep groups (`[dev]`, `[wazuh]`), Dockerfile installs only system packages + uv, postCreateCommand runs `uv pip install -e '.[dev,wazuh]'`

## Backlog Ideas

### Analytics Suite

- High-volume alert detection: track alert frequency per signature over time windows
- Should this live at SIEM level or application level? Probably SIEM correlation rules
- Consider: alert fatigue metrics, auto-close rate tracking, escalation patterns

### Knowledge Learning

- Post-investigation knowledge updates (new precedents, lessons learned)
- Impose increasing costs per token appended to lessons/utilities to avoid unbounded growth
- Mechanism for pruning stale knowledge
