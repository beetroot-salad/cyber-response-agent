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

## Next — Reliability & Evaluation

### State Machine Transition Verification Criteria

Goal: Add actionable verification gates to each transition so `write_state.py` can reject transitions where the agent hasn't done meaningful work. Currently the state machine enforces *legal transitions* but not *quality of work within a phase*. Data from evaluation runs should inform which criteria matter most (start loose, tighten based on observed failure modes).

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
- [ ] Signature knowledge: FIM (Wazuh syscheck rule 550) — context.md, playbook.md, precedents/
- [ ] Signature knowledge: Suspicious Process Execution (Falco/Wazuh 100001) — context.md, playbook.md, precedents/
- [ ] Signature knowledge: Suspicious DNS Query (Wazuh 100110+) — context.md, playbook.md, precedents/
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
