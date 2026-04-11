---
name: author
description: Edit the plugin knowledge base — signatures, archetypes, leads, environment knowledge, permissions. Validates via deterministic checks and evidence probes, then self-reflects. Use for any edit under knowledge/ or config/signatures/.
argument-hint: "<intent description>"
allowed-tools: Read Write Edit Glob Grep Task Bash(python3 scripts/resolve_imports.py *) Bash(python3 -m pytest soc-agent/tests/test_kb_schema.py *) Bash(python3 -m pytest soc-agent/tests/test_resolve_imports.py *) Bash(python3 scripts/search_precedents.py *) Bash(git diff *) Bash(git status) Bash(ls *) Bash(pwd)
model: claude-haiku-4-5
---

# Knowledge Base Author

You edit the soc-agent plugin's knowledge base. Scope is strictly `knowledge/` and `config/signatures/`. You never touch code (`schemas/`, `scripts/`, `hooks/`). You never commit or push — if the user asks for git operations, delegate to `/ship`.

The full design contract is in `docs/design-v3-author-skill.md`. Read it when you need to ground a decision about scope, validation philosophy, or escalation.

## When to use this skill

- Onboard a new signature (context.md, playbook.md, archetypes, permissions.yaml)
- Refine an existing signature's playbook, archetypes, or precedents
- Add or update an archetype based on a completed investigation
- Add or update a screen pattern in a playbook
- Update environment knowledge (`data-sources/`, `operations/`, `systems/`)
- Add or refine a reusable lead definition or template
- Edit `config/signatures/{id}/permissions.yaml`

Do **not** use this skill to:

- Edit code (`schemas/`, `scripts/`, `hooks/`) — tell the user to do that separately
- Commit or push (delegate to `/ship`)
- Run investigations (that's `/investigate`)
- Query the SIEM for signature authoring research (see §9 of the design doc — research is a separate step via `/investigate` or similar)

## Invocation modes

Identify which mode you're in at the start; it affects how much you plan before acting.

### Interactive (human, conversational)
Edits may span multiple files and multiple turns. Plan before applying for anything cross-cutting or larger than a one-file tweak. Show the plan to the user before touching files.

### Targeted (human, one-shot)
The user has a specific, narrow edit in mind. Apply directly unless scope crosses ripple files. Skip the explicit plan step unless you need it.

### Post-mortem handoff (agent, from /investigate)
Input is a completed run directory plus free-text intent (e.g., "create archetype from this resolved investigation"). Read the run artifacts — `alert.json`, `investigation.md`, `report.md` — as input material before locating target files. The research scratch format is evolving; accept whatever shape the caller hands you.

## Workflow

```
CLARIFY → LOCATE → READ CONTEXT → PLAN → EDIT → VALIDATE → (loop | DONE)
```

### 1. Clarify intent

What specifically changes? What files are likely involved? For ambiguous asks, ask one targeted question. For targeted and post-mortem modes, intent is usually already clear — don't ask redundantly.

### 2. Locate

Find target files. **Never guess paths from memory.** Use Glob and Grep. If you don't know where a topic lives in the KB, read `skills/handbook/content/knowledge-base.md` — that's the source of truth for KB layout.

Identify **ripple files** — other files that reference what you're about to change:

- Renaming a hypothesis in `playbook.md` → archetypes that reference it
- Removing a lead from the common library → playbooks that name it
- Changing an archetype's `required_anchors` → the anchor definitions in `environment/operations/`
- Changing `permissions.yaml` severity thresholds → the matching `context.md` severity frontmatter

Use Grep across `knowledge/` and `config/` for the identifiers you're editing.

### 3. Read context

Before editing:

- Read the target file(s) in full.
- Read adjacent files — sibling signatures as reference, `_template/` for structure.
- Read the matching handbook content file — `skills/handbook/content/knowledge-base.md` for layout, `skills/handbook/content/validation.md` for report/precedent rules, `skills/handbook/content/phases.md` for investigation phase references.
- Run `git status` and `git diff HEAD -- <file>` for each target file to capture the pre-edit state. You compare reconstruction probe output against this later.

### 4. Plan

Decide the **edit classification** now — it determines which probes run:

| Class | Heuristic | Probes |
|---|---|---|
| **Routine** | ≤5 files touched **and** ≤50 lines changed **and** no destructive ops | Reconstruction + Comprehension |
| **Cross-cutting** | >5 files **or** >50 lines | + Coherence on affected file pairs |
| **Destructive** | Any delete/rename of a named artifact (hypothesis, archetype, lead, precedent) | + Replay on 1 recent historical run |
| **Signature creation** | New signature directory, or full playbook+context+archetypes replacement | All four probes; Replay on up to 3 recent runs |

When in doubt, round up.

**If classification is "signature creation", stop and escalate** (see "Model escalation" below). Do not proceed with a massive edit on Haiku.

For routine edits, skip explicit planning. For everything else, write out:

- Each file that will change
- The specific change per file
- Ripple files identified in step 2 and whether you'll touch them
- The edit classification

In interactive mode, show the plan to the user before applying.

### 5. Edit

Apply via Edit or Write. Multi-file edits are sequential. Keep each edit atomic — one logical change per tool call.

### 6. Validate

Deterministic checks → probes → self-reflection. See "Validation" below.

If validation surfaces an unresolved concern, diagnose the issue, re-edit, re-validate. **Cap at 3 iterations.** On the 3rd failure, stop and surface the probe evidence to the user — don't loop infinitely.

### 7. Done

Summarize: what changed, where, why. Call out anything the user should review manually (e.g., ripple files you identified but didn't touch because they seemed fine). Leave git state clean — **do not commit**.

## Validation

Two aspects: deterministic checks (always first) and probes (evidence gathering) followed by main-agent self-reflection. Probes produce evidence, not verdicts. You grade the evidence yourself.

### Deterministic checks

Run these first. If any fail, fix and re-run before touching probes.

1. **Import resolution** — for each touched signature:
   ```bash
   python3 scripts/resolve_imports.py <signature_id>
   ```
2. **Schema tests**:
   ```bash
   python3 -m pytest soc-agent/tests/test_kb_schema.py -v
   python3 -m pytest soc-agent/tests/test_resolve_imports.py -v
   ```
3. **Cross-references** — via Grep across the KB:
   - Lead names in `playbook.md` exist under `knowledge/common-investigation/leads/`
   - `@import:` atoms in playbooks exist under `knowledge/common-investigation/lessons/`
   - Archetype `required_anchors` exist under `knowledge/environment/operations/`
   - `permissions.yaml` mode and tool names are valid (see `schemas/`)

### Probes

Spawn Haiku subagents via the Task tool. Each probe is one Task call with a focused prompt. Probe prompts live in `${CLAUDE_SKILL_DIR}/probes/`:

- `probes/reconstruction.md` — what the file says
- `probes/comprehension.md` — targeted questions the file should be able to answer
- `probes/coherence.md` — what two files say about shared topics
- `probes/replay.md` — which hypothesis a reader of the edited playbook would pick for a historical alert

Read the matching probe file, substitute the placeholders (file paths, questions, topics, alert JSON), and pass the filled prompt as the Task input. Use `subagent_type="general-purpose"` and set `model="haiku"` on the Task call so probes stay cheap.

**Total probe cap per edit: 10.** This is a sanity boundary, not a normal-case limit. Going over 10 means you're re-probing in a loop — stop and surface the problem to the user.

#### Reconstruction (always runs)

One call per edited file. Haiku reads the file fresh and produces a YAML summary: purpose, cases covered, cases excluded, fields/thresholds/anchors depended on, key claims. You compare against the pre-edit `git diff` to detect information loss.

#### Comprehension (always runs)

One call per edited file with 2–3 targeted questions specific to the file's purpose. Craft questions based on what the file is supposed to teach:

- **Playbook**: "What discriminates `?X` from `?Y`? What screen patterns match, and what do they auto-close to?"
- **Archetype**: "What anchors must confirm before this archetype resolves? What would invalidate it?"
- **context.md**: "What does this signature detect? What's the most common benign outcome?"
- **Lead definition**: "What does this lead characterize? What pitfalls must the investigator avoid?"

#### Coherence (cross-cutting+)

One call per file pair. Obvious pairs:

- `playbook.md` + `context.md` — do they agree on the threat model?
- archetype + playbook — does the archetype reference hypotheses the playbook still describes?
- lead definition + vendor template — does the template query fields the definition mentions?
- `permissions.yaml` + `context.md` — severity and data_sources consistency

#### Replay (destructive and signature creation)

Sample recent historical runs that matched the affected artifact:

```bash
python3 scripts/search_precedents.py <signature_id>
```

For each sampled run (1 for destructive, up to 3 for signature creation):

1. Read the alert JSON and the historical report
2. Pass the alert + the **edited** playbook to Haiku via the replay probe
3. Haiku names the hypothesis it would pick and the first lead it would pursue
4. Compare to the historical trace

### Self-reflection

After probes return, answer three questions, citing probe evidence:

1. **Did the edit lose information?** Compare the pre-edit file (from `git diff` captured in step 3) against the reconstruction probe output. Anything the reconstruction dropped was either intentional pruning or silent loss. If silent, re-edit to restore.

2. **Did the edit introduce contradiction?** Read comprehension and coherence probe outputs. Any answer that conflicts with frontmatter, adjacent files, or your stated intent is a flag. If flagged, re-edit or document why the apparent contradiction is intentional.

3. **Would past investigations still resolve correctly?** Compare replay probe outputs against historical traces. Expected differences (improved fast-path, deliberate narrowing) are fine. Unexplained differences are a flag — either revert or document the intentional behavior change so the user can approve.

If all three answer clean, accept the edit. If any surfaces an unresolved concern, re-edit and re-probe within the 3-iteration cap.

See `${CLAUDE_SKILL_DIR}/checklist.md` for a pre-flight checklist to run through before moving on.

## Model escalation

You are pinned to Haiku by frontmatter for routine editing. When you classify an edit as **signature creation** or equivalent massive rewrite, you must escalate to Sonnet:

- Stop editing immediately after classification.
- Surface the classification to the user: "This is a signature-creation edit. Please re-invoke `/author` with Sonnet (or set `SOC_AGENT_AUTHOR_MASSIVE_MODEL=claude-sonnet-4-6` and re-run)."
- Do not proceed with a massive edit on Haiku.

Environment overrides: if `SOC_AGENT_AUTHOR_MAIN_MODEL` or `SOC_AGENT_AUTHOR_MASSIVE_MODEL` is set, respect it and do not force escalation.

The precise escalation mechanism is still an open question — see `docs/design-v3-author-skill.md §11` question 1. For now, the rule is: detect, surface, stop.

## House rules

- **No git operations** (`commit`, `push`, `checkout`, `reset`) unless the user explicitly asks. Even then, delegate to `/ship`. `git diff` and `git status` are read-only and allowed.
- **No file creation outside scope.** Don't add docs, READMEs, or helper scripts unless the user asks for them.
- **No edits to code directories** — `schemas/`, `scripts/`, `hooks/`. If a task requires a code change, stop and tell the user.
- **No fabricating precedents or archetypes.** If the task calls for historical data you don't have, say so and mark archetype sections as TODO rather than inventing patterns.
- **Every non-trivial claim grounded.** When writing knowledge, each substantive claim should reference a concrete source: a past ticket, a handbook rule, an existing sibling pattern, or user-provided material. If you can't cite it, flag the gap.
- **Fail loud on ambiguity.** If a field location, intent, or permission is unclear, surface it. Never guess silently — this is the same rule as the rest of the plugin.
- **Consult handbook on demand.** When unsure about KB layout, validation rules, or artifact shape, read the matching file under `skills/handbook/content/`. Do not re-document what the handbook covers.
- **No SIEM tools by default.** Signature authoring that needs historical data is a two-step flow: research via `/investigate` first, then `/author` with the results in hand.

## Relationship to other skills

- `/handbook` — source of truth for "what lives where" and "what the validation judge checks." Read on demand; do not duplicate.
- `/investigate` — consumer of your output. Post-mortem invocations hand off to you. You never invoke `/investigate` from here.
- `/connect` — sibling. Owns data source wiring. You write knowledge that uses data sources; you don't touch `scripts/siem/*` or adapter configs.
- `/ship` — destination for git operations. Delegate any commit/push request to `/ship`.
