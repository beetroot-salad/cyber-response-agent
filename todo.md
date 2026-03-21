# v3 Cyber Response Agent — Status

## Done (v3 rewrite)

- [x] Delete v2 pipeline (shell hooks, bash scoring, old tests)
- [x] Python schemas: report_frontmatter, state machine, precedent (dataclass validators)
- [x] Hooks: validate_report.py (Stop hook safety gate), write_state.py (state machine), investigation_summary.py (JSONL outcomes), audit_tool_calls.py (PostToolUse JSONL)
- [x] Hook registration in .claude/settings.json
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
- [ ] Lead subagents — context isolation for verbose SIEM responses
- [ ] Tier 2 semantic judge — Haiku validates report consistency after investigation
- [ ] Budget enforcement hook — cap token/cost spend per investigation
- [ ] Input sanitization hooks — validate alert_json before investigation starts

### Knowledge Expansion
- [ ] Second signature — validate cross-signature generalization (e.g., Falco rule or different Wazuh rule)
- [ ] `common/leads/` — reusable lead definitions across signatures
- [ ] `common/data-sources/` — data source documentation
- [ ] `common/context/` — organizational context (asset inventory, team structure)

### Operations
- [ ] `act` mode — auto-close for mature signatures with high-confidence precedent matches
- [ ] Retention policy for run data (configurable cleanup)
- [ ] Audit dashboard / analytics on investigation outcomes

## Backlog Ideas

### Analytics Suite
- High-volume alert detection: track alert frequency per signature over time windows
- Should this live at SIEM level or application level? Probably SIEM correlation rules
- Consider: alert fatigue metrics, auto-close rate tracking, escalation patterns

### Knowledge Learning
- Post-investigation knowledge updates (new precedents, lessons learned)
- Impose increasing costs per token appended to lessons/utilities to avoid unbounded growth
- Mechanism for pruning stale knowledge
