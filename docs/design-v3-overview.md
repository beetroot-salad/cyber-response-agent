# Cyber Response Agent - Design v3: Lead-Based Investigation

**Version:** 3.2
**Status:** Draft
**Date:** March 2026

This document covers the problem statement, design decisions, and success criteria. For technical architecture and implementation details, see [design-v3-architecture.md](design-v3-architecture.md).

---

## 1. Problem Statement

SOC teams face a fundamental scaling problem: alert volume grows faster than analyst headcount. Most alerts are routine — known false positives, expected automation, familiar benign patterns. But every alert must be investigated because the cost of missing a real threat is catastrophic.

An automated triage agent can help, but it introduces its own risks:

| Risk | Consequence | How serious |
|------|-------------|-------------|
| False negative (auto-close a real threat) | Attacker gains time, breach expands | Critical — must be near-zero |
| False positive (escalate a benign alert) | Analyst wastes time, loses trust in system | Annoying but safe |
| Slow investigation | No better than manual triage | Defeats the purpose |
| Brittle system | Breaks when environment changes, new signatures appear | High maintenance cost |
| Prompt injection | Attacker manipulates the agent via crafted log data | Could cause false negatives |

The challenge is balancing **reliability** (never miss a real threat), **security** (resist manipulation), **speed** (resolve in minutes), and **flexibility** (adapt to new alert types without rearchitecting).

### What v2 Got Right

- Deterministic confidence scoring — the LLM doesn't make the final call alone
- Precedent requirement — novel patterns always escalate
- Reproduction concept — empirical validation of hypotheses
- Conservative default — when uncertain, escalate

### Where v2 Falls Short

1. **Rigid pipeline** — Every alert runs the same sequence regardless of complexity. A known monitoring probe gets the same heavyweight treatment as a novel lateral movement pattern.

2. **All-or-nothing investigation** — A single agent does the full investigation, then a single reproduction validates it. No intermediate checkpoint where we can catch problems.

3. **Method-coupled knowledge** — Playbooks encode specific SIEM queries rather than investigative goals. Couples the system to a specific toolset.

4. **Reproduction as pipeline stage** — Triggered by a confidence band (0.70-0.90), not by whether a mechanistic question actually needs answering.

5. **Heavy orchestration** — The deterministic orchestrator manages state transitions, but most of that complexity exists to handle a rigid pipeline.

---

## 2. Design Decisions and Trade-offs

### 2.1 Agent-Driven Investigation with Hook-Validated State Transitions

**Decision:** The LLM agent drives the investigation loop through a defined phase sequence. Deterministic hooks validate that transitions are legal and that no phase was skipped.

| Option | Pro | Con |
|--------|-----|-----|
| Deterministic loop (v2) | Predictable, auditable sequence | Rigid, same depth for all alerts |
| LLM drives loop + hook guardrails (v3) | Adapts to complexity, natural investigation flow | Less predictable sequence |
| Hybrid (LLM proposes, orchestrator approves each step) | Maximum control | Slow, high overhead |

**Why v3 wins:** Most alerts are simple. Hook-based guardrails give the same safety guarantees without constraining the investigation path. The agent is free to investigate, but must declare its phase transitions — and hooks enforce that no forbidden transitions occur.

**The risk we accept:** Investigation paths are less predictable. Mitigation: state file audit trail, minimum evidence requirements, forbidden transition enforcement.

**Epistemic foundation:** The investigation loop follows the hypothetico-deductive method:

1. **Falsificationism (Popper):** The agent must always maintain at least one adversarial hypothesis (a threat scenario) and actively seek evidence that would *support* it. A benign conclusion is strongest when built on the *absence* of threat indicators, not just the *presence* of benign ones.

2. **Maximum information gain:** At each iteration, pursue the lead whose result would most change the belief distribution across hypotheses, regardless of direction.

**Phase sequence:**

```
Entry:  CONTEXTUALIZE  (load alert, signature context, recent alerts, precedent scan)
Loop:   HYPOTHESIZE → GATHER → ANALYZE → (HYPOTHESIZE or CONCLUDE)
Exit:   CONCLUDE
```

- **CONTEXTUALIZE** — Load all available context. One-time entry point.
- **HYPOTHESIZE** — Form or update candidate explanations. Must include at least one adversarial (threat) hypothesis.
- **GATHER** — Execute leads via scripts, MCP, or subagents.
- **ANALYZE** — Interpret results against predictions. Determine: conclude or iterate?
- **CONCLUDE** — Output recommendation. Only reachable after at least one full HYPOTHESIZE→GATHER→ANALYZE cycle.

Forbidden transitions and enforcement details are in [architecture §4.3](design-v3-architecture.md#43-state-transition-validator).

### 2.2 Leads as Goals vs. Method-Specific Playbooks

**Decision:** Playbooks define investigative goals ("determine authentication pattern") not methods ("run this Wazuh query"). The agent chooses methods at runtime.

**Why:** Method-coupled playbooks break when the SIEM changes or a data source is unavailable. Goal-oriented playbooks are portable and let the agent adapt.

**The risk we accept:** The agent might choose suboptimal methods. Mitigation: knowledge base includes hints without mandating specific tools.

### 2.3 Scripts as Actions

**Decision:** The agent writes and executes scripts against available APIs, rather than relying on dedicated MCP tools per signature.

| Option | Pro | Con |
|--------|-----|-----|
| Dedicated MCP tools per data source | Type-safe, discoverable, constrained | Heavy context, rigid, doesn't scale |
| Agent writes/runs scripts | Flexible, lean context, adapts to any API | Less constrained, harder to audit |
| Hybrid: read-only MCP + scripts | Safe reads via MCP, flexible analysis | Two paradigms to maintain |

**Why scripts win:** Investigations are exploratory — the agent composes queries dynamically. MCP can remain for read-only SIEM access where preferred. Scripts are secured through persistence (audit trail), pre-execution hook validation, approved script library, and environment-level credential injection.

### 2.4 Reproduction: Deferred

**Decision:** Reproduction (sandbox-based hypothesis testing) is **deferred from v3**. Host-level reproduction covers only a narrow slice of investigations. Most useful reproduction requires network simulation (mock services, traffic replay), which is a substantial design effort.

**What we preserve:** The reproduction concept and I/O schemas are documented in [design-v3-reproduction.md](design-v3-reproduction.md) for future use. The `reproduction_result` field remains in the recommendation schema (value: `null`).

### 2.5 Communication: Filesystem-Based Inter-Agent Protocol

**Decision:** Agents communicate via structured JSON files in a shared run directory.

**Why:** Inspectable (humans and hooks read the same files), validatable (hooks verify schema), persistent (audit without extra effort), decoupled (agents don't need the same process).

**Context cost note:** The real cost is LLM context consumption, not I/O. The agent should summarize evidence into the state file rather than re-reading raw files. Lead subagents exist partly to keep verbose output out of the main agent's context.

### 2.6 Human Control: Autonomy Toggle

**Decision:** The analyst controls per-invocation whether the agent can modify the ticket directly (`act`) or only generate a recommendation (`recommend`). Same hooks enforce the same safety invariants in both modes.

**Rollback:** The agent uses a dedicated service account and tags all actions. Rollback is handled by the ticketing system's native mechanisms. Periodic sampling catches systematic errors.

---

## 3. Success Criteria

| Goal | Metric | Target |
|------|--------|--------|
| Zero false negatives | Human overrides of auto-close | < 0.5% |
| Reduce workload | Alerts resolved without human action | 60-80% of eligible |
| Fast resolution | Time to disposition | < 3 min (auto), < 10 min (assisted) |
| Auditability | Decisions with complete trail | 100% |
| Investigation quality | Leads pursued per recommendation | >= minimum per severity |

### Non-Goals

- Not a threat detection system (operates downstream of SIEM/EDR)
- Not for novel threats without human review
- Not for incident response / remediation (investigation and recommendation only)

---

## 4. Open Questions

### Resolved in v3.1

- ~~Confidence scoring as guardrail~~ → Confidence is agent signal for users; hard checks do actual gating
- ~~Reproduction as pipeline stage~~ → Deferred until network simulation is viable
- ~~Script vs MCP security~~ → Both equally vulnerable to prompt injection; defense is sanitization + hook validation
- ~~Knowledge base update workflow~~ → Post-mortem as PR model with user approval

### Resolved in v3.2

- ~~State transition mechanism~~ → Epistemic loop with hook-validated `state.json` (§2.1)
- ~~Multi-alert handling~~ → Ticketing system as coordination layer + read-only cross-agent access
- ~~Prompt architecture~~ → Five-section structure with safety bracketing
- ~~Precedent matching mechanism~~ → Two-layer: structural search + LLM judgment with structured tagging

### Open

1. **Lead library scope** — How many common leads before first signatures are viable? Estimate: 8-12.
2. **Script execution sandboxing** — Should investigation scripts run in a lighter sandbox? Probably: allow network to SIEM only, restrict filesystem.
3. ~~**Autonomy defaults per signature**~~ → Resolved: `permissions.yaml` v2.0 uses `mode.allowed` + `mode.default` per signature, with mitigation actions gated individually.
4. **Multi-SIEM support** — Multiple entries in siem-mapping.json; agent picks per lead.
5. **Knowledge base cold-start** — Training mode for bootstrapping from historical alerts?
6. **Skeptic model for high-severity** — Separate model receives raw evidence without narrative?

### Design Gaps (Requiring Dedicated Design)

1. **Tag vocabulary convergence** — How fast does convergence happen? May need seed vocabulary.
2. **Skeptic model protocol** — What does it receive? How is disagreement resolved? Needs prototyping.
3. **Cross-signature correlation** — Multi-stage attack patterns crossing signature boundaries may require higher-level orchestration.

---

*This document supersedes design-v2.md. For technical architecture, see [design-v3-architecture.md](design-v3-architecture.md). For deferred reproduction design, see [design-v3-reproduction.md](design-v3-reproduction.md).*
