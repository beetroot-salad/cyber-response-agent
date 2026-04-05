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

## Phase 2 — Post-MVP

### Agent Architecture
- [ ] Lead subagents — refactor so each lead is executed by a subagent with isolated context. Subagent receives hypothesis predictions + lead definition, executes queries, returns structured summary (observation + characterization). Keeps raw SIEM data out of the main agent's context window. Reframe Philosophy to reflect agent-as-director, subagents-as-executors
- [ ] Context window management — migrate detailed investigation reasoning to a subagent. Main agent holds: investigation flow, phase state, key findings, hypothesis table. Reasoning subagent handles: detailed evidence analysis, hypothesis weighting, narrative construction. Prevents context exhaustion on complex multi-loop investigations
- [ ] Tool discovery refactor — split into two concerns: (1) data availability (main agent consults `knowledge/environment/data-sources/` to know what questions can be answered), (2) tool mechanics (lead subagent consults `knowledge/environment/systems/` for query patterns). Also: not all tools are MCP — agent may need to call APIs via scripts
- [x] Tier 2 semantic judge — Haiku validates report consistency after investigation (judge_report.py + judge_prompt.md, invoked via claude CLI)
- [x] Precedent schema: added `alert_data` field (raw alert for judge comparison + future post-mortem seeding)
- [x] CONTEXTUALIZE: Explore subagent for recent alerts — situational awareness, alert correlation (added to SKILL.md)
- [x] Playbook-driven vs investigation-loop separation — implemented as SCREEN phase: playbooks define fast-path patterns checked by a cheap subagent (Sonnet/Haiku) before the full investigation loop. Falls through to full loop on no match.
- [x] Ticket-context skill/subagent — extract CONTEXTUALIZE alert context (recent + related alert scanning) into a dedicated skill with pre-made queries. Reusable across signatures and invocable independently
- [ ] Budget enforcement hook — cap token/cost spend per investigation
- [ ] Input sanitization hooks — validate alert_json before investigation starts

### Knowledge Expansion
- [ ] Second signature — validate cross-signature generalization (e.g., Falco rule or different Wazuh rule)
- [x] `common/leads/` — reusable lead definitions across signatures (directory scaffolded)
- [x] `environment/data-sources/` — data mapping: what data exists where (state + events)
- [x] `environment/context/` — classification heuristics (ip-ranges, identity-patterns, criticality, data-classification)
- [x] `environment/systems/` — system-specific implementation knowledge (wazuh/ migrated from common/utilities/)
- [ ] Populate lead definitions in `common/leads/` (authentication-history, source-reputation, etc.)
- [ ] Populate environment files with real org data (currently example/template content)

### SIEM CLI
- [ ] Configurable host/port (not just env vars — support CLI flags, config file, or env)
- [ ] Multiple authentication options (API key, token file, username/password, etc.)
- [ ] Vendor abstraction — CLI should work across SIEM backends, not just Wazuh

### Operations
- [ ] `act` mode — auto-close for mature signatures with high-confidence precedent matches
- [ ] Retention policy for run data (configurable cleanup)
- [ ] Audit dashboard / analytics on investigation outcomes

### Package Management
- [ ] Finalize packaging strategy — using `uv` + `pyproject.toml` in `soc-agent/` for now. Decide on venv integration, Dockerfile install step, and dev vs prod deps
- Current external deps: `opensearch-py` (used by wazuh_cli.py)

## Backlog Ideas

### Analytics Suite
- High-volume alert detection: track alert frequency per signature over time windows
- Should this live at SIEM level or application level? Probably SIEM correlation rules
- Consider: alert fatigue metrics, auto-close rate tracking, escalation patterns

### Knowledge Learning
- Post-investigation knowledge updates (new precedents, lessons learned)
- Impose increasing costs per token appended to lessons/utilities to avoid unbounded growth
- Mechanism for pruning stale knowledge
