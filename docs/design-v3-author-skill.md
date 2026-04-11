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
4. **Validate every edit.** Deterministic checks plus Haiku probes feeding a main-agent self-reflection step. Probes produce evidence; the main agent judges. Uncommunicative or regressed knowledge is as bad as structurally broken knowledge.
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
6. **Validate.** Run deterministic checks, then spawn Haiku probes in parallel, then self-reflect on the probe evidence (§7). If self-reflection surfaces an unresolved concern, diagnose and re-edit. Cap at 3 iterations, then escalate with the probe evidence.
7. **Done.** Summarize what changed and why. Leave git state clean (user commits when ready).

---

## 7. Validation

Two aspects: **deterministic checks** that run existing tooling, and **evidence gathering** through Haiku probes whose output feeds a single main-agent self-reflection step. Probes produce data — not verdicts. Only the main agent judges, because only it holds the edit intent and the full surrounding context.

### Deterministic checks

No LLM. Runs existing tooling:

- `resolve_imports.py` succeeds for the affected signature.
- Frontmatter parses against the matching schema (`report_frontmatter.py`, archetype schema, precedent schema).
- Markdown parses; required sections present.
- Cross-references resolve: lead names in playbooks exist under `common-investigation/leads/`; `@import:` atoms exist; archetype `required_anchors` exist under `environment/operations/`; `permissions.yaml` references valid modes and tools.

Free. Runs first. If anything fails here, skip the probe layer entirely and re-edit — there's no point probing a structurally broken file.

### Probes

Four probe types, each targeting a specific class of failure mode. Each probe is one Haiku subagent call (spawned via Task, `context: fork`, `agent: Explore`). Probes run in parallel when scheduled together. Each returns structured evidence the main agent consumes during self-reflection.

| Probe | What Haiku does | What it surfaces |
|---|---|---|
| **Reconstruction** | Read the edited file fresh, write a high-level summary: what this artifact is for, what cases it covers, what cases it explicitly doesn't, what fields/thresholds/anchors it depends on | Information loss (detail dropped), ambiguity introduced, scope drift |
| **Comprehension** | Answer N targeted questions the file is supposed to be able to answer — e.g., "what discriminates `?monitoring-probe` from `?brute-force`?", "what anchors must confirm a `?known-scanner` resolution?" | Silent prescriptive weakening, contradictions between frontmatter and body, typo'd field names |
| **Coherence** | Given two related files (playbook + context, archetype + playbook, lead-def + vendor template), report what each says about a shared topic | Cross-file drift — playbook and context disagreeing, archetype referencing hypotheses the playbook no longer describes, template querying fields the definition doesn't mention |
| **Replay** | Given a historical alert and the edited playbook, name the hypothesis that best matches and the lead to pursue first | Runtime behavior drift — hypothesis space shrinks/widens, lead ordering regressed, screen pattern now matches different runs |

No probe makes a judgment call. Reconstruction doesn't say "this is worse" — it produces a summary the main agent compares against the pre-edit version via `git diff`. Comprehension doesn't grade answers — it produces data the main agent compares to expectations. Coherence doesn't say "these contradict" — it produces paired statements. Replay doesn't say "this regressed" — it produces a "what this reader would do" that the main agent compares to the historical trace.

### Self-reflection

Once probes return, the main agent does one consolidated self-reflection pass citing probe evidence:

1. **Did the edit lose information?** — Compare the pre-edit file (from `git diff`) against the reconstruction probe output. Anything in the pre-edit file that the reconstruction dropped was either intentional pruning or silent loss. Main agent decides which.
2. **Did the edit introduce contradiction?** — Read comprehension and coherence probe outputs. Any answer that conflicts with frontmatter, adjacent files, or the stated edit intent is a flag.
3. **Would past investigations still resolve correctly?** — Compare replay probe outputs against historical traces. Intentional changes (improved fast-path, deliberate narrowing) are fine; unexplained differences are a flag.

If all three come back clean, the edit is accepted. If any surfaces an unresolved concern, re-edit and re-probe. Cap at 3 iterations, then escalate to the user with the probe evidence.

### When each probe runs

Probes are cheap but not free. A tiered model:

| Edit class | Heuristic | Probes |
|---|---|---|
| **Routine** | ≤5 files touched **and** ≤50 lines changed **and** no destructive ops | Reconstruction + Comprehension |
| **Cross-cutting** | >5 files **or** >50 lines | + Coherence on the obvious file pairs |
| **Destructive** | Any delete/rename of a named artifact (hypothesis, archetype, lead, precedent) | + Replay on 1 recent historical run that referenced the artifact |
| **Signature creation / rewrite** | New signature directory, or full playbook+context+archetypes replacement | All four probes; Replay on up to 3 recent runs |

The file/line thresholds are proxies — tune after the skill is in use. Total Haiku probe calls per edit are capped at **10** as a sanity boundary — far more than any normal edit needs, but enough headroom to catch runaway re-probing cycles rather than clamp them prematurely. Replay sample size per destructive edit is 1: this is a sanity check, not strong validation (see Known gaps).

### Known gaps

Being explicit about what this validation model doesn't catch:

- **Real runtime fidelity.** Replay is Haiku approximating a Sonnet-size investigator. It can miss regressions the real investigate agent would hit. Acceptable — if a Haiku replay is the only thing between the user and a bad merge, the user is also looking at the edit in git review.
- **Multi-edit sessions.** Validation runs per-edit, so an intermediate broken state can validate if a later edit fixes it. Git's final state is what matters; intermediate validation is advisory.
- **Grounding in real tickets.** The main agent asks "is this grounded?" but Haiku can't verify a claim is backed by a real ticket. That's a judgment call that stays with the main agent and ultimately the user.
- **Future attack patterns.** Replay regression-tests only against history. New patterns are by construction unrepresented.
- **Subtle prescriptive drift.** "MUST" → "SHOULD" is usually detectable in reconstruction; "verify carefully" → "verify" may not be.

---

## 8. Tools, Model, Frontmatter

Skills support `model`, `effort`, `allowed-tools`, `hooks`, `context: fork`, and `agent` in frontmatter ([docs](https://code.claude.com/docs/en/skills#frontmatter-reference)).

### Model composition

From the cost analysis:

| Edit class | Main agent | Probes |
|---|---|---|
| Routine, cross-cutting, destructive | Haiku 4.5 | Haiku 4.5 |
| Signature creation / rewrite | Sonnet 4.6 | Haiku 4.5 |

Haiku handles the bulk of editing; Sonnet is escalated to only for full-signature writes where design-philosophy judgment matters most. At ~22 edits/week (15 routine + 6 cross-cutting + 1 massive), expected cost is ~$7/month uncached, ~$4/month with prompt caching. Probes are ~$0.50/week total — negligible.

The composition is configurable via `SOC_AGENT_AUTHOR_MAIN_MODEL` and `SOC_AGENT_AUTHOR_MASSIVE_MODEL` environment variables. Default is Haiku + Sonnet as above. Higher-stakes environments can bump routine to Sonnet (~$15/month) or massive to Opus (~$20/month) without editing the skill. Probe model stays Haiku.

### Frontmatter sketch

```yaml
---
name: author
description: Edit the plugin knowledge base — signatures, archetypes, leads, environment knowledge, permissions. Validates structural correctness via deterministic checks and evidence probes, then self-reflects on the evidence. Use for any edit under knowledge/ or config/signatures/.
allowed-tools: Read Write Edit Glob Grep Task Bash(python3 scripts/resolve_imports.py *) Bash(python3 -m pytest soc-agent/tests/test_kb_schema.py *) Bash(python3 -m pytest soc-agent/tests/test_resolve_imports.py *) Bash(git diff *) Bash(git status)
model: claude-haiku-4-5
---
```

### Rationale

- **Haiku as default.** Pinning to Haiku in frontmatter ensures routine edits are cheap regardless of invoking context. The safety net is the probe layer, not the main agent's raw capability.
- **Sonnet escalation for massive edits.** The main agent detects edit class during Locate/Plan and escalates when classification hits "signature creation / rewrite." Escalation mechanism is TBD — see §11.
- **Haiku for all probes**, spawned via Task with `context: fork, agent: Explore`. Cheap, parallelizable, no judgment calls. Per-edit probe cap is 10 (see §7).
- **Git whitelisted read-only.** `git diff` and `git status` are needed for the reconstruction-vs-original comparison. No mutating git operations.
- **Bash whitelisted**, not open. Only deterministic-layer commands. No network. No shell loops. No `git commit` / `git push` — those live in `/ship`.
- **No MCP / SIEM tools** in allowed-tools. See §9 — signature authoring that needs SIEM data is a two-step flow.
- **Task tool** required for spawning probes.

---

## 9. Signature Authoring Without Direct SIEM Access

When creating a new signature (interactive mode, cold start), the agent needs two kinds of information:

1. **Signature attributes** — detection logic, alert fields, severity, related rules. Required for `context.md` and the hypothesis catalog.
2. **Historical alerts** — for archetypes, screen patterns, and precedents. **Optional** for core investigation: the investigate agent handles a brand-new signature without any archetypes, it just has no fast paths.

The question is how `/author` obtains that data. Three options were considered:

- **Option 1 — Abstract capability tag.** `/author` declares a `siem-read` capability; `/connect` resolves it to concrete tool permissions at install time. Clean in theory, but Claude Code's `allowed-tools` is concrete (`Bash(...)`, `mcp__vendor__tool`), not abstract. No portable way to express this in frontmatter today.
- **Option 2 — Hardcoded MCP patterns.** `/author` whitelists `mcp__*__query` / `mcp__*__search` and relies on namespace conventions. Brittle, and skips the deterministic path for deployments that use adapter CLIs instead of MCP servers.
- **Option 3 — Two-step workflow.** `/author` has no SIEM tools at all. Signature authoring is split: first a research step (`/investigate` exploratory mode, or a dedicated research skill) pulls the data, then `/author` shapes it into knowledge files. The research output lands in a scratch file that `/author` reads as input.

**Decision: Option 3.** Reasons:

- Keeps `/author`'s scope pure (knowledge files only, no external tools in allowed-tools).
- Leans on `/investigate`'s already-working SIEM adapter path — one place that knows how to talk to the SIEM.
- The two steps are independently reviewable artifacts.
- When the SIEM access model changes (new vendor, MCP vs CLI, identity proxy), only the research step cares.

Sources the user can provide to `/author` instead of live SIEM data:
- A research scratch file from a prior exploratory `/investigate` run
- Org policy documents
- Existing analyst playbooks to migrate
- Closed ticket exports
- Rule definitions exported from the SIEM config

When historical alert data is unavailable or sparse, `/author` writes what it can and marks archetype sections as "TODO — no historical data; add after first N real investigations." The investigate loop still works for the new signature; it just has no fast paths until the backfill happens.

The research scratch file format is TBD — see §11.

---

## 10. Observability

Git already captures the "what changed" and "when" of every edit that lands. `/author` does not maintain its own audit log.

For debugging uncommitted/in-progress edits, `/author` emits a lightweight trace to `runs/author_trace.jsonl` — one line per validation run, recording which files were touched and which layers passed. This is debug-only, git-ignored, and the cost is negligible.

---

## 11. Open Questions

Parked for follow-up, not blocking implementation:

1. **Model escalation mechanism.** Default composition is Haiku main + Sonnet for massive edits. How does a Haiku invocation detect it's a massive edit and route up to Sonnet? Options: (a) explicit user invocation flag (`/author --mode=new-signature`); (b) Haiku runs Clarify/Locate/Plan, classifies the edit, and refuses to proceed at "massive" tier, prompting re-invocation with a higher model; (c) two entry points (`/author` and `/author-signature`). Pick during implementation.

2. **Probe quality baseline.** Haiku replay is a sanity check, not strong validation. Before relying on it, run an eval: take N past edits with known outcomes, see whether the probe layer would have caught the bad ones. Tracks the probe suite's true precision/recall.

3. **Research scratch format.** Option 3 in §9 assumes a scratch file shape for the `/investigate` → `/author` handoff. Needs design — probably lands with the post-mortem contract (below).

4. **Post-mortem handoff contract.** `/investigate` → `/author` needs a defined shape (run dir path? structured draft archetype? free-text findings?). Design in a separate doc once the post-mortem step is built; `/author` currently assumes a run dir path plus free-text intent.

5. **Template / schema drift.** When a schema gains a required field, existing files become invalid. `/author` should detect this during Locate and surface it to the user with three options: *defer*, *migrate all*, *mark this one as TODO*. Detection heuristic and UX are TBD. Out of scope for MVP.

6. **Idempotency.** Running the same request twice should not duplicate. Git makes this recoverable but not prevented. A fully idempotent skill-only implementation is possible (diff intended state against current state before editing) but adds complexity. Deferred.

7. **Archetype vs. precedent boundary.** The two are being disambiguated in a parallel design session (archetype = abstract portable story; precedent = instance; resolution requires archetype match AND trust match via live anchors or non-temporal precedent comparison). `/author` will follow whatever the final shape lands on. Until then, it edits both shapes as they currently exist and defers model questions to `/handbook`.

---

## 12. Relationship to Other Skills

| Skill | Relationship |
|---|---|
| `/handbook` | Source of truth for KB structure and rules. `/author` reads `handbook/content/*.md` on demand. |
| `/investigate` | Consumer of `/author`'s output. Post-mortem can invoke `/author` to create or refine archetypes. |
| `/connect` | Sibling, not dependency. `/connect` wires data sources; `/author` writes knowledge that uses them. They touch adjacent files (`environment/systems/`, `environment/data-sources/`) and should agree on conventions but don't call each other. |
| `/ship` | Destination for git ops. `/author` never commits; users who want a commit hand off to `/ship`. |
