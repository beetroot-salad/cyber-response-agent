---
name: handbook
description: Reference documentation for the cyber-response-agent plugin. Answers "how does this thing work?" — architecture, investigation loop, safety model, knowledge base layout, and artifact schemas. Load on demand when you (or the user) need to ground an explanation in the design docs.
allowed-tools: Read, Glob, Grep
---

# Cyber Response Agent Handbook

On-demand reference for the cyber-response-agent plugin. This skill explains how the plugin works — it does not investigate alerts. Use `/investigate` for actual alert work, `/author` for knowledge-base edits, or `/connect` (planned) for data source wiring. See the relationship table below.

## Who asks this skill questions

Both are first-class:

- **The user** wants to understand the plugin — "how does the loop cap work?", "what's in the runs directory?", "why was my report rejected?"
- **The agent** wants to ground its own behavior — checking an invariant before writing a report, confirming the right path for an artifact, verifying a phase transition is legal, or finding the definition of a term it's about to use.

Either way, the job is the same: pull the smallest slice of documentation that answers the question, read it, and respond. The only difference is that agent self-questions typically don't need a narrative response — a crisp "yes/no, here's the rule" is usually enough.

## When to use this skill

- Understanding what the plugin is and how its pieces fit together
- Looking up the investigation loop and state machine
- Checking how a particular guardrail works (two-tier validation, two-leg resolution requirement, adversarial hypothesis rule, loop cap)
- Seeing the layout of `state.json`, `report.md`, `investigation.md`, or other run artifacts
- Understanding how environment knowledge, signatures, and lead templates compose
- Figuring out how to extend or customize the plugin (new signature, new SIEM, new lead)
- Confirming a rule before acting on it (e.g., "does a screen-resolved report still need a matched_archetype?")

If the question is narrow, **read only the relevant content file**. Do not load all of `content/` into context — the documents are cross-referenced and individually complete, so loading one at a time keeps context lean.

## How to use this skill

1. Identify what's actually being asked — architecture overview, a specific phase, a specific guardrail, a specific artifact, a yes/no invariant check.
2. Pick the smallest set of content files that answer it. Default to one.
3. Read those files with the `Read` tool from `${CLAUDE_SKILL_DIR}/content/`. Use `Glob` / `Grep` when you're not sure which file covers a topic.
4. Answer directly. Match response weight to question weight: a quick question gets a quick answer; a design question gets the context it needs. Don't pad.
5. If the content you need does not exist, say so explicitly rather than guessing. The handbook only covers what is actually documented; missing topics are gaps to flag, not gaps to fill from memory.

## Content index

Each file under `content/` is a standalone reference document. Start here, then read what you need.

| File | Topic | Read when |
|---|---|---|
| `content/design.md` | High-level "what is this plugin and how does it work" — goals, investigation approach, safety model, separation of concerns, vendor neutrality, what ships vs what the user brings | Overview question, or you need to ground a general answer |
| `content/investigation-loop.md` | The six-phase state machine (CONTEXTUALIZE → [SCREEN] → HYPOTHESIZE → GATHER → ANALYZE → CONCLUDE), legal transitions, loop cap, termination rules, how `state.json` relates to `investigation.md` | Questions about phase transitions, loop counting, what's legal/forbidden, or how hooks enforce the sequence |
| `content/phases.md` | Per-phase reference — goal, work, legal next phases, and `investigation.md` template for CONTEXTUALIZE, SCREEN, HYPOTHESIZE, GATHER, ANALYZE, CONCLUDE | Questions about what a specific phase is supposed to do, what gets written where, or how verification and scoping fit into the loop |
| `content/validation.md` | Two-tier report validation — Tier 1 (deterministic frontmatter, archetype shape, grounding leg, minimum-leads checks) and Tier 2 (semantic judge with 6 criteria, full vs escalation mode, salted delimiter injection defense) | Questions about why a report was rejected, how the judge works, how the shape and grounding legs are enforced, or how the plugin defends against prompt injection in the alert |
| `content/run-artifacts.md` | Run directory layout — `alert.json`, `meta.json`, `investigation.md`, `state.json`, `report.md`, plus the cross-run `audit.jsonl`, `tool_audit.jsonl`, `tool_trace.jsonl` logs. Who writes each, who reads each, how they support debugging and live monitoring, and the ingest-time sanitization layer of the prompt-injection defense | Questions about what's in the runs directory, how to monitor or debug the agent, where a file comes from, the difference between `tool_audit.jsonl` and `tool_trace.jsonl`, or the ingest-side (Layer 1) half of prompt-injection defense. Pair with `content/validation.md` for the judge-side (Layer 2) half |
| `content/knowledge-base.md` | How `common-investigation/`, `environment/`, `signatures/`, `config/signatures/`, and `schemas/` compose at runtime. The step-by-step of how a single lead resolves from playbook → definition → data source → template → CLI. Where new signatures, systems, leads, and lessons belong | Questions about how the knowledge layers fit together, where to add a new signature or SIEM, or the role of each directory |

Additional content files may be added over time. When you add one, include it in the table above so `/handbook` can find it.

## Relationship to other skills

| Skill | Status | Purpose | When to defer to it |
|---|---|---|---|
| `/investigate` | shipped | Runs an actual alert investigation | "Please triage this alert" |
| `/handbook` (this skill) | shipped | Explains the plugin itself | Pure reference questions, no state changes |
| `/author` | shipped | Edits the knowledge base — signatures (context.md, playbook.md, archetype directories + precedent snapshots), leads, environment knowledge, permissions — with deterministic checks plus probe evidence feeding a self-reflection step | Creating or editing knowledge content; post-mortem archetype authoring |
| `/connect` | planned | Connects a new data source: adapter CLI, environment knowledge scaffolding, credential setup instructions | Wiring up a new SIEM/EDR/lookup system |

`/author` is shipped — for questions about its design and contract, ground answers in `skills/author/design.md` (the design lives inside the skill directory). `/connect` is still referenced in the design but not yet implemented; for questions about it, answer from the design docs (`content/design.md`, `docs/design-v3-init-and-connect.md`) or say the skill isn't available yet.

The handbook is read-only by contract. The `allowed-tools` frontmatter restricts this skill to `Read`, `Glob`, and `Grep` — no writes, no edits, no shell. If a question drifts into "now please do it," hand off to the appropriate shipped skill above, or tell the user the planned skill isn't available yet.

## House rules

- **Read on demand.** Do not preload content files at skill start. Let the question drive which files you open.
- **Ground answers in content.** Every claim must come from a file you actually read during this invocation. Do not fill gaps from memory of the design — read the file.
- **Match weight to weight. Don't pad.** A one-line question deserves a one-line answer. Don't expand a quick lookup into an essay; don't compress an architectural question into a sentence. If in doubt, err on the side of shorter — the user can always ask for more.
- **Reference sources at the end, not inline.** When it's useful (e.g., the user might want to read more, or a claim is surprising), mention the source files in a short trailer like "from `content/validation.md`" at the bottom. Inline citation on every sentence is overkill for quick questions — skip it unless the user explicitly asks for citations or you're disambiguating between multiple sources.
- **Silence is a valid answer.** If the handbook doesn't cover something, say so. Do not guess at internals you cannot verify from the files.
- **Stay read-only.** This skill never writes to run directories, never modifies `state.json`, never edits signature knowledge. The `allowed-tools` restriction enforces this at the tool layer; your behavior should match it.
- **Flag stale docs.** If content contradicts the current codebase (a file path that no longer exists, a hook that was removed), say so — the handbook is only useful if it tracks reality.
