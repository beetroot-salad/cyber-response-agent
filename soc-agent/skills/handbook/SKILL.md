---
name: handbook
description: Reference documentation for the cyber-response-agent plugin. Answers "how does this thing work?" — architecture, investigation loop, safety model, knowledge base layout, and artifact schemas. Load on demand when the user asks about plugin internals or when you need to ground an explanation in the design docs.
---

# Cyber Response Agent Handbook

On-demand reference for the cyber-response-agent plugin. This skill does **not** investigate alerts — it explains how the plugin does. Use `/investigate` for actual alert work. `/author` (signature authoring) and `/connect` (data source adapter) are planned sibling skills; see the relationship table below.

## When to use this skill

The user (or you, on the user's behalf) invokes `/handbook` when they want to:

- Understand what the plugin is and how its pieces fit together
- Look up the investigation loop and state machine
- Check how a particular guardrail works (two-tier validation, precedent requirement, adversarial hypothesis rule, loop cap)
- See the layout of `state.json`, `report.md`, `investigation.md`, or other run artifacts
- Understand how environment knowledge, signatures, and lead templates compose
- Figure out how to extend or customize the plugin (new signature, new SIEM, new lead)

If the user's question is narrow, **read only the relevant content file**. Do not load all of `content/` into context — the documents are cross-referenced and individually complete, so loading one at a time keeps context lean.

## How to use this skill

1. Identify what the user is actually asking about — architecture overview, a specific phase, a specific guardrail, a specific artifact.
2. Pick the smallest set of content files that answer it. Default to one.
3. Read those files with the `Read` tool from `${CLAUDE_SKILL_DIR}/content/`.
4. Answer the user's question directly, citing the file and section you used. Quote sparingly — link the user to the file for full context.
5. If the content you need does not exist yet, say so explicitly rather than guessing. The handbook only covers what is actually documented; missing topics are gaps to flag, not gaps to fill from memory.

## Content index

Each file under `content/` is a standalone reference document. Start here, then read what you need.

| File | Topic | Read when |
|---|---|---|
| `content/design.md` | High-level "what is this plugin and how does it work" — goals, investigation approach, safety model, separation of concerns, vendor neutrality, what ships vs what the user brings | User asks an overview question, or you need to ground a general answer |
| `content/investigation-loop.md` | The six-phase state machine (CONTEXTUALIZE → [SCREEN] → HYPOTHESIZE → GATHER → ANALYZE → CONCLUDE), legal transitions, loop cap, termination rules, how `state.json` relates to `investigation.md` | User asks about phase transitions, loop counting, what's legal/forbidden, or how hooks enforce the sequence |
| `content/phases.md` | Per-phase reference — goal, work, legal next phases, and `investigation.md` template for CONTEXTUALIZE, SCREEN, HYPOTHESIZE, GATHER, ANALYZE, CONCLUDE | User asks what a specific phase is supposed to do, what gets written where, or how verification and scoping fit into the loop |
| `content/validation.md` | Two-tier report validation — Tier 1 (deterministic frontmatter, precedent, archetype, minimum-leads checks) and Tier 2 (semantic judge with 5 criteria, full vs no-precedent mode, salted delimiter injection defense) | User asks why a report was rejected, how the judge works, how precedent recency or archetype anchors are enforced, or how the plugin defends against prompt injection in the alert |
| `content/run-artifacts.md` | Run directory layout — `alert.json`, `meta.json`, `investigation.md`, `state.json`, `report.md`, plus the cross-run `audit.jsonl`, `tool_audit.jsonl`, `tool_trace.jsonl` logs. Who writes each, who reads each, and how to use them for debugging | User asks what's in the runs directory, how to debug a surprising outcome, where a particular file comes from, or what the difference is between `tool_audit.jsonl` and `tool_trace.jsonl` |
| `content/knowledge-base.md` | How `common-investigation/`, `environment/`, `signatures/`, `config/signatures/`, and `schemas/` compose at runtime. The step-by-step of how a single lead resolves from playbook → definition → data source → template → CLI. Where new signatures, systems, leads, and lessons belong | User asks how the knowledge layers fit together, where to add a new signature or a new SIEM, or what the role of each directory is |

Additional content files may be added over time. When you add one, include it in the table above so `/handbook` can find it.

## Relationship to other skills

| Skill | Status | Purpose | When to defer to it |
|---|---|---|---|
| `/investigate` | shipped | Runs an actual alert investigation | Any question of the form "please triage this alert" |
| `/handbook` (this skill) | shipped | Explains the plugin itself | Pure reference questions, no state changes |
| `/author` | planned | Guided signature authoring — context.md, playbook.md, precedents, permissions | User wants to create or edit a signature's knowledge |
| `/connect` | planned | Connects a new data source: adapter CLI, environment knowledge scaffolding, credential setup instructions | User wants to wire up a new SIEM/EDR/lookup system |

`/author` and `/connect` are referenced in the design but not yet implemented. If a user asks about them, acknowledge them as planned siblings and either answer the question from the design docs (`content/design.md`, `docs/design-v3-init-and-connect.md`) or tell the user the skill isn't available yet.

The handbook is read-only. It does not write files, create runs, modify knowledge, or generate code. If a user question drifts into "now please do it," hand off to the appropriate shipped skill above or tell the user the planned skill isn't available yet.

## House rules

- **Read on demand.** Do not preload content files at skill start. Let the user's question drive which files you open.
- **Answer from the docs, not from memory.** If the handbook is silent on a topic, say so. Do not speculate about internals you cannot verify from the files.
- **Cite the file.** When you answer, reference the file and section (e.g., `content/investigation-loop.md#termination-rules`) so the user can verify and read more.
- **Stay out of investigation state.** This skill never writes to run directories, never modifies `state.json`, never edits signature knowledge. It is purely informational.
- **Flag stale docs.** If you notice content that contradicts the current codebase (e.g., a file path that no longer exists, a hook that was removed), tell the user — the handbook is only useful if it tracks reality.
