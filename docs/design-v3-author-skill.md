## `/author` — Knowledge Base Authoring Skill

**Version:** 0.1 | **Date:** April 2026 | **Status:** Design sketch

Single entry point for editing and customizing the plugin's knowledge base. Takes a user or agent request ("add a screen section to wazuh-rule-5710", "refine archetype X to only include logon type 3", "onboard signature wazuh-rule-5712"), locates the right files, makes the edit, and validates that the edit works as expected.

Referenced as a planned skill in `skills/handbook/SKILL.md` and `handbook/content/design.md`. This document locks in the design so implementation can proceed.

---

## 1. Problem Statement

Today, every KB change is hand-edited. There is no guardrail against:

- Writing a playbook that references a lead definition that doesn't exist.
- Adding an archetype whose `required_anchors` aren't defined in `environment/operations/`.
- Breaking `resolve_imports.py` by referencing a missing `@import:` atom.
- Writing knowledge that is structurally valid but doesn't actually communicate — a human reading it couldn't answer "what does this signature detect?"
- Drifting from the design philosophy ("grounded in real data", conservative, hypothesis-driven) without noticing.

We need a skill that handles all of these in one workflow, usable by both humans and the investigate agent (during post-mortem when a recurring pattern has been identified).

---

## 2. Design Principles

1. **Handbook is the library; `/author` is the editor.** `/author` reads `skills/handbook/content/*.md` on demand to ground edits. It does not re-document KB structure. One source of truth for "where things live."
2. **Knowledge-only scope.** `/author` edits `knowledge/` and `config/signatures/`. It never touches `schemas/`, `scripts/`, or `hooks/` — those are code and go through normal review.
3. **Git is version control.** We assume the KB is a git working tree (init script bootstraps this). No dry-run, no soft-revert mechanism, no author-owned history log. Rollback = git.
4. **Validate every edit.** Structural check → reader comprehension check → self-reflection check. Uncommunicative or philosophy-drifted knowledge is as bad as structurally broken knowledge.
5. **Fail loud on ambiguity.** Same rule as the rest of the plugin: if a file location, field name, or intent is unclear, surface it — don't guess.
6. **No git operations by default.** The skill does not commit, branch, or push unless explicitly asked. If asked, defer to `/ship` rather than rolling its own git.

---

## 3. Audience and Invocation Modes

Three shapes, one skill:

| Mode | Caller | Shape | Example |
|---|---|---|---|
| **Interactive** | Human | Conversational; may span many edits; agent plans before applying when edits are non-trivial | "Onboard wazuh-rule-5712" |
| **Targeted** | Human | One-shot, narrow edit | "Add a screen section to wazuh-rule-5710 playbook matching `?vendor-scanner`" |
| **Post-mortem handoff** | `/investigate` (agent) | Structured input from a completed run; creates or refines an archetype | `/author from-run runs/2026-04-10T14-22-19/` (exact shape TBD — see §11) |

The skill's SKILL.md must explicitly name these so the agent picks the right flow at the start.

---

## 4. Relationship to `/handbook`

`/author` **consumes** `/handbook` as reference. It does not duplicate KB structure in its own content.

Concretely:

- Before locating a file, `/author` reads `handbook/content/knowledge-base.md` if the area is unfamiliar.
- Before writing a report-shaped artifact, `/author` reads `handbook/content/validation.md` to know what the investigate-side judge will check.
- Before writing a new lead or archetype, `/author` reads the matching handbook content.

This keeps the handbook's read-only contract intact (it still only answers "what/where") and prevents the two skills from drifting. When `knowledge-base.md` changes, `/author` picks up the new reality on the next run.

What `/author` owns in its own content: **workflow, philosophy, and the edit-validate loop** — things handbook doesn't cover.

---

## 5. Scope

### In scope
- `knowledge/signatures/{id}/` — context.md, playbook.md, archetypes/, precedents/
- `knowledge/environment/` — context, data-sources, operations, systems
- `knowledge/common-investigation/leads/` and `lessons/`
- `config/signatures/{id}/permissions.yaml`

### Out of scope
- `schemas/` — Python dataclasses, code review territory
- `scripts/` and `hooks/` — code
- `runs/` — investigation outputs, read-only from `/author`'s perspective
- Git operations (unless explicitly requested, then delegate to `/ship`)
- Research/ticket-pulling from SIEM (see §9)

### Explicit non-goals
- No dry-run / preview mode. Git handles that.
- No author-owned audit log beyond debug tracing (see §10).
- No multi-user locking. Single-user plugin.

---

## 6. Flow

```
REQUEST → CLARIFY → LOCATE → READ CONTEXT → PLAN → EDIT → VALIDATE → (loop | DONE)
```

1. **Clarify intent.** For ambiguous asks, one targeted question. For post-mortem handoff, intent comes pre-structured. For trivial edits, skip.
2. **Locate.** Glob/Grep to find target files. Never guess paths. If unfamiliar with the area, read `handbook/content/knowledge-base.md`.
3. **Read context.** The file(s) being edited, adjacent files (sibling signatures, `_template/`), and the matching handbook content file. Identify **ripple files** — other files that may need updating because they reference what's changing (e.g., renaming a hypothesis in playbook.md forces updates in archetypes/ that reference it).
4. **Plan.** For non-trivial edits, write out what changes and why. For interactive-human mode, show the plan before applying. For targeted and post-mortem modes, apply directly unless scope crosses ripple files.
5. **Edit.** Apply via Edit/Write. Multi-file edits are sequential and individually validated.
6. **Validate.** Layer 1 → Layer 2 → Layer 3 (§7). If any layer fails, diagnose and re-edit. Cap at 3 iterations, then escalate.
7. **Done.** Summarize what changed and why. Leave git state clean (user commits when ready).

---

## 7. Validation Layers

Every edit runs through three layers. Layers 1 and 2 are always run; Layer 3 is always run but its weight depends on edit size.

### Layer 1 — Structural (deterministic)

No LLM. Runs existing tooling:

- `resolve_imports.py` succeeds for the affected signature.
- Frontmatter parses against the matching schema (`report_frontmatter.py`, archetype schema, precedent schema).
- Markdown parses; required sections present.
- Cross-references resolve: lead names in playbooks exist under `common-investigation/leads/`; `@import:` atoms exist; archetype `required_anchors` exist under `environment/operations/`; `permissions.yaml` references valid modes and tools.

Cost: free. Fails fast. Always runs first.

### Layer 2 — Reader comprehension (dumb subagents)

Spawn 2–3 Haiku subagents (`context: fork`, `agent: Explore`) with **only** the new/edited file(s) in context. Ask pointed questions the file is supposed to be able to answer:

- "What does this signature detect?"
- "Name the most common benign outcome and the single query that confirms it."
- "What must be confirmed before a `?known-scanner` resolution is legal?"
- "If authentication-history returns zero failures, what does that mean for this hypothesis?"

The editor (main `/author` context) grades the answers against intent. If Haiku readers can't answer what the file is supposed to teach, the file isn't communicating — re-edit.

Why subagents and not self-read: the editor has the intent in its head, which contaminates the comprehension test. A fresh reader simulates what the investigate agent will actually see at runtime.

### Layer 3 — Self-reflection (philosophy alignment)

**Not a subagent.** The editor itself answers three structured questions in-context, citing the edit:

1. **"Why is this right?"** — Point at the specific textual claim or structural choice that justifies the edit. Must cite something: past ticket data, handbook rule, existing pattern in sibling signature.
2. **"Why is it aligned with the design philosophy?"** — Reference the specific principle (grounded in real data / conservative by default / hypothesis-driven / fail-fast / adversarial posture maintained) and how the edit honors it.
3. **"What would make it misaligned? Does that condition exist right now?"** — Name the counter-case that would invalidate the edit. Check whether that counter-case is present in the actual edit.

This is cheaper than an external reviewer (no context handoff), keeps the editor's knowledge of intent and surrounding code, and produces a rationale the user can read. If any of the three questions can't be answered honestly, the edit is wrong.

### Destructive edits — regression check

Deletes and renames get an extra step between Layer 1 and Layer 2:

- Find recent `runs/*/report.md` that matched the deleted/renamed archetype or precedent.
- For each: hand the run artifacts + the **new** KB state to a Haiku subagent and ask "what disposition would this investigation reach now?"
- Compare to the historical disposition.
- Classify and surface: "run 2026-03-12/... now resolves as escalated — expected because the deleted archetype was the fast path" (OK), or "run 2026-03-12/... now resolves as escalated — reason unclear, is this intentional?" (warn).

Deletes are allowed when environment/policy changes require them, but the regression result is reported back so the user can approve or revert.

---

## 8. Tools, Model, Frontmatter

Skills support `model`, `effort`, `allowed-tools`, `hooks`, `context: fork`, and `agent` in frontmatter ([docs](https://code.claude.com/docs/en/skills#frontmatter-reference)).

```yaml
---
name: author
description: Edit the plugin knowledge base — signatures, archetypes, leads, environment knowledge, permissions. Validates structural correctness, reader comprehension, and philosophy alignment. Use for any edit under knowledge/ or config/signatures/.
allowed-tools: Read Write Edit Glob Grep Task Bash(python3 scripts/resolve_imports.py *) Bash(python3 -m pytest soc-agent/tests/test_kb_schema.py *) Bash(python3 -m pytest soc-agent/tests/test_resolve_imports.py *)
model: claude-sonnet-4-6
---
```

Rationale:

- **Sonnet** for the main loop. Opus is overkill for most edits; Haiku is too weak for design-judgment work. User can override at the session level for heavy design work.
- **Haiku for Layer 2 readers**, spawned via Task with `context: fork, agent: Explore`. Cheap and parallelizable.
- **Bash whitelisted**, not open. Only the commands Layer 1 needs. No git. No network. No shell loops. If a broader need surfaces, add it explicitly.
- **No MCP / SIEM tools** by default. See §9.
- **Task tool** required for spawning Layer 2 readers.

---

## 9. Signature Authoring and SIEM Access

When creating a new signature (interactive mode, cold start), the agent needs to answer two things:

1. **What are the signature's attributes?** — Detection logic, alert fields, severity, related rules. This is required to write `context.md` and to frame the playbook's hypothesis catalog.
2. **What past alerts exist, if any?** — Required for archetypes, screen patterns, and precedents. **Optional** for core investigation — the investigate agent can run a brand-new signature without any archetypes, it just won't have fast paths.

The high-level decision: **`/author` should have SIEM access when creating signatures**, but degrade gracefully when there's no history.

Sources the user can provide instead of (or alongside) SIEM queries:
- Org policy documents
- Existing analyst playbooks (to be migrated)
- Closed ticket exports
- Rule XML / YAML from the SIEM config

When past alert data is unavailable, `/author` writes what it can and marks the archetype section as "TODO — no historical data; add after first N real investigations."

This is the one exception to knowledge-only scope: `/author` may invoke the connected-system adapter CLIs (e.g., `scripts/siem/wazuh_cli.py`) read-only during signature authoring, the same way `/investigate` does. It still does not write to those systems.

---

## 10. Observability

Git already captures the "what changed" and "when" of every edit that lands. `/author` does not maintain its own audit log.

For debugging uncommitted/in-progress edits, `/author` emits a lightweight trace to `runs/author_trace.jsonl` — one line per validation run, recording which files were touched and which layers passed. This is debug-only, git-ignored, and the cost is negligible.

---

## 11. Open Questions

Parked for follow-up, not blocking implementation:

1. **Template / schema drift.** When a schema gains a required field, existing files become invalid. `/author` should detect this during Locate and surface it to the user with three options: *defer*, *migrate all*, *mark this one as TODO*. The detection heuristic and UX are TBD. Out of scope for MVP; tracked here.

2. **Post-mortem handoff contract.** `/investigate` → `/author` needs a defined shape (run dir path? structured draft archetype? free-text findings?). Design in a separate doc once the post-mortem step is built; `/author` currently assumes a run dir path plus free-text intent.

3. **Idempotency.** Running the same request twice should not duplicate. Git makes this recoverable but not prevented. A fully idempotent skill-only implementation is possible (diff intended state against current state before editing) but adds complexity. Deferred.

4. **Archetype vs. precedent boundary.** The two are being disambiguated in a parallel design session (archetype = abstract portable story; precedent = instance; resolution requires archetype match AND trust match via live anchors or non-temporal precedent comparison). `/author` will follow whatever the final shape lands on. Until then, it edits both shapes as they currently exist and defers model questions to `/handbook`.

---

## 12. Relationship to Other Skills

| Skill | Relationship |
|---|---|
| `/handbook` | Source of truth for KB structure and rules. `/author` reads `handbook/content/*.md` on demand. |
| `/investigate` | Consumer of `/author`'s output. Post-mortem can invoke `/author` to create or refine archetypes. |
| `/connect` | Sibling, not dependency. `/connect` wires data sources; `/author` writes knowledge that uses them. They touch adjacent files (`environment/systems/`, `environment/data-sources/`) and should agree on conventions but don't call each other. |
| `/ship` | Destination for git ops. `/author` never commits; users who want a commit hand off to `/ship`. |
