# Design

High-level answer to "what is this plugin and how does it work?"

## What it is

The cyber-response-agent is a **hypothesis-driven security alert triage plugin** for Claude Code. A SOC analyst (or an orchestrator) hands the agent a single alert; the agent investigates it through iterative hypothesis elimination and outputs a recommendation — `resolved` with a disposition, or `escalated` with context for a human.

The plugin is **vendor-neutral**: it works with any SIEM, EDR, or lookup system exposed via MCP tools, CLI scripts, or Bash-callable commands. The shipped knowledge includes Wazuh-flavoured examples (signatures, system knowledge) because they're the reference implementation, but nothing in the investigation loop is Wazuh-specific.

## Goals

- **Zero false negatives.** Missing a real threat is catastrophically worse than escalating a benign alert. The agent is designed so that its failure mode is escalation, never silent auto-close.
- **High precision on recommendations.** When the agent resolves an alert, the reasoning is grounded in explicit evidence, a matched archetype or precedent, and (for archetype resolutions) confirmed trust anchors.
- **Mean time to resolution of 1–3 minutes** for alerts that match a known pattern, with an optional SCREEN fast-path that skips the full loop when a mechanical pattern match is unambiguous.
- **Conservative by default.** When uncertain, escalate. When tools fail, escalate. When the hypothesis space feels incomplete, escalate.
- **Recommend-only MVP.** The current shipped version does not take actions (no blocking, no account changes, no firewall rules). The `act` mode is reserved for future work.

## Approach: hypothesis-driven investigation

Every investigation is a loop of:

> form candidate explanations → predict what each would look like → gather evidence that distinguishes them → eliminate the ones that fail → repeat until one survives.

This is hypothetico-deductive triage. It replaces a linear runbook (`"check field A, then field B, then B.1..."`) with an adaptive strategy: the agent chooses the next lead based on which one would discriminate the most between surviving hypotheses.

The key rules:

- **Maintain at least one adversarial (threat) hypothesis** until it is explicitly refuted with strong evidence. A benign conclusion is strongest when built on the *absence* of threat indicators, not just the presence of benign ones.
- **Structured assessments** (`++`, `+`, `-`, `--`) replace subjective confidence wording. Each lead's observations are weighted against each surviving hypothesis explicitly.
- **Severity of tests.** A lead that would refute a hypothesis if it were wrong is more valuable than one that merely fits. Prefer leads where different hypotheses predict *different* outcomes.
- **Absence is evidence.** "I queried for X and found zero results" can be just as informative as "I queried for X and found a match" — especially when the hypothesis predicts what should *not* be there.
- **Watch for the unexplained.** If the best surviving hypothesis leaves significant evidence unexplained, the hypothesis space is probably incomplete. That's an escalation signal.

## Safety model: hooks enforce structure, LLM decides strategy

The plugin keeps the LLM in charge of *investigative strategy* — which hypotheses to form, which leads to run, how to weigh evidence — but wraps that in deterministic guardrails enforced by Python hooks. The LLM cannot:

- Skip phases of the loop (state machine enforces transitions)
- Claim `status=resolved` without matching an existing archetype or precedent file
- Close an alert with fewer leads than the signature's severity requires
- Write a report with inconsistent frontmatter (Tier 1 validation)
- Produce a report the Haiku semantic judge flags as inconsistent, under-evidenced, or failing the adversarial check (Tier 2 validation)

The separation is deliberate: **Python code handles what can be verified structurally; the LLM handles what requires judgment.** No safety-critical check relies on LLM self-assessment of its own work — those are done by an independent judge (a separate Claude call, with untrusted content wrapped in per-run salted delimiters).

See `content/validation.md` for the two-tier validation detail, and `content/investigation-loop.md` for the state machine.

## The investigation loop at a glance

```
CONTEXTUALIZE → [SCREEN] → HYPOTHESIZE → GATHER → ANALYZE → CONCLUDE
                    │         ↑                      │
                    │         └────── loop ──────────┘
                    │                                │
                    └────────── fast-path ───────────┘
```

- **CONTEXTUALIZE** — read signature knowledge, parse alert, dispatch ticket-context and precedent-scan subagents in parallel, build a resolution map of available tools.
- **SCREEN** *(optional, if the playbook defines a `## Screen` section)* — a cheap subagent attempts a mechanical pattern match against known benign outcomes. Match → straight to CONCLUDE. No match → fall through to the full loop with evidence already gathered.
- **HYPOTHESIZE** — generate or update candidate explanations, pick the most diagnostic lead.
- **GATHER** — execute the lead (single or composite dispatch), characterize raw observations.
- **ANALYZE** — weight evidence against each surviving hypothesis. Loop back, or conclude.
- **CONCLUDE** — write `report.md` with structured frontmatter and a trace line.

A maximum of 7 hypothesis loops is enforced by the state machine. Most investigations resolve in 2–3.

## Core separation of concerns

| Dimension | Owned by | What it does |
|---|---|---|
| **Logic** — hypotheses, predictions, assessments, lead selection | Main investigation agent | Decides what to think, what to test next, what the evidence means |
| **Reality** — running queries, parsing raw results, characterizing observations | Lead subagents, SIEM CLIs, MCP tools | Returns "what I found and how I found it," no interpretation |
| **Safety** — phase transitions, report shape, precedent existence, evidence threshold | Python hooks | Cannot be negotiated with; failures return exit code 2 which the agent sees and must fix |
| **Credentials** — endpoints, tokens, passwords | Adapter scripts (CLIs and MCP servers), environment variables | The agent itself never sees raw secrets; it calls the adapter, which has them |

This boundary is what makes the system auditable. Every decision the LLM makes is visible in `investigation.md`; every structural guarantee is enforced by code in `hooks/scripts/`; every external call is logged to `runs/tool_audit.jsonl`.

## Vendor neutrality

The investigation loop is written in terms of *abstract operations* (authentication history, process lineage, network flows) rather than vendor-specific queries. The agent discovers at runtime:

1. What leads the signature's playbook wants it to pursue (`knowledge/common-investigation/leads/`)
2. Where the data for those leads lives in *this* environment (`knowledge/environment/data-sources/`)
3. How to query the systems holding that data (`knowledge/environment/systems/`)
4. What trust anchors exist for legitimacy questions (`knowledge/environment/operations/`)

Swapping Wazuh for Splunk is a matter of writing a new `knowledge/environment/systems/splunk/` directory and a Splunk CLI adapter. No changes to the investigation skill, hooks, schemas, or loop logic. See `content/knowledge-base.md` for how these pieces compose.

## What the plugin ships

When you install the plugin you get:

- The **investigate skill** — entry point, investigation loop, SCREEN and ticket-context subagent prompts
- **Python hooks** — report validation (two tiers), state machine, audit logging, tool output tagging, budget enforcement, investigation summary
- **Schemas** — dataclass validators for report frontmatter, state transitions, precedent shape
- **Knowledge scaffolding** — portable `common-investigation` methodology (checklist, lead definitions, lessons), the 4-area `environment/` directory with SKILL.md overviews, a signature `_template/`, and reference Wazuh signatures
- **Setup scripts** — run directory setup, alert sanitization, precedent search, import resolver
- The **handbook, author, and connect skills** (this one, plus its siblings)

What you bring:
- Your environment knowledge (edit files under `environment/context/`, `environment/data-sources/`, `environment/operations/`, `environment/systems/`)
- Your signatures (author new directories under `knowledge/signatures/`, use `/author` for guided editing)
- Your data source integrations (use `/connect` to bootstrap adapters and scaffold `environment/systems/` and `environment/data-sources/` entries)

The shipped Wazuh signatures and the playground `host-query` system knowledge are **reference examples**, not required components. You can delete them if they don't apply to your environment.
