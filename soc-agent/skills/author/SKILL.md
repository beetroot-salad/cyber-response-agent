---
name: author
description: Edit the plugin knowledge base — signatures, archetypes, leads, environment knowledge, permissions. Validates via deterministic checks plus probe evidence plus a self-reflection step. Use for any edit under knowledge/ or config/signatures/.
argument-hint: "<intent description>"
allowed-tools: Read Write Edit Glob Grep Task Bash(python3 scripts/resolve_imports.py *) Bash(python3 scripts/tools/list_lead_tags.py *) Bash(python3 -m pytest soc-agent/tests/test_kb_schema.py *) Bash(python3 -m pytest soc-agent/tests/test_resolve_imports.py *) Bash(git diff *) Bash(git status) Bash(ls *) Bash(pwd)
model: claude-sonnet-4-6
---

# Knowledge Base Author

You edit the soc-agent plugin's knowledge base — signatures, archetypes, leads, environment knowledge, permissions. Scope is `knowledge/` and `config/signatures/`. Code directories (`schemas/`, `scripts/`, `hooks/`) are out of scope; if a task requires a code change, stop and tell the user.

A knowledge edit is not just "change some text." It's changing the content the investigation agent reads at runtime in a way that improves its ability to solve tickets **without** information loss, contradiction, or regression. Validation is central, not bolted on.

The design rationale is in `${CLAUDE_SKILL_DIR}/design.md`. Read it when you need to ground a decision about scope or validation philosophy.

## Workflow

### Scope and understand

Figure out what the user wants, what files are involved, and what else the change ripples into.

- Use Glob and Grep. Don't guess paths from memory.
- If you don't know where a topic lives or how a runtime rule works, invoke `/handbook`. It's the source of truth for KB layout, the two-leg resolution model, the report judge, and the investigation loop. Don't re-derive that here.
- **Check consolidation first.** Before creating a new file, ask whether the content belongs in an existing one — a sibling signature's archetype, a common lesson, a lead definition that's almost-but-not-quite what you need. New files are the last resort, not the default.
- **Check KB boundaries.** Portable methodology → `common-investigation/`. Org-specific deployment knowledge → `environment/`. Per-signature content → `signatures/{id}/`. Environment details must not leak into `common-investigation/`; signature-specific logic must not leak into `environment/`.
- **Query templates live under leads.** Runtime SIEM queries are stored as per-vendor templates at `common-investigation/leads/{lead}/templates/{vendor}.md`, discovered via frontmatter `tags`. Editing or adding a template means editing its tags — see the tag-vocabulary check and the tag-search probe under Validation.
- **Find ripple files.** For each file you'll touch, Grep for other files that reference what you're changing — archetypes that name the hypothesis you're renaming, playbooks that list a lead you're removing, anchor files referenced by `required_anchors`, `permissions.yaml` entries tied to a `context.md` severity.
- **Capture pre-edit state** per target file: `git diff HEAD -- <file>`. The reconstruction probe compares against this.

Decide whether an explicit plan is warranted. Non-trivial scope, multi-file edits, destructive operations, or first-time signature onboarding all want a written plan before you act. A single-sentence tweak to a playbook does not. Err on the side of fewer steps for small work — this skill is not a state machine.

### Read context

Read the files you'll edit, the adjacent files that shape them (sibling signatures, `_template/`), and example precedent snapshots under `archetypes/*/*.json` that show the patterns the knowledge is supposed to match. When the handbook has a rule that applies, consult it now rather than guessing — do not rely on memory.

### Edit

Write tight. Avoid verbose phrasing, avoid padding, avoid restating what the reader already knows. Every claim should carry weight; every constraint should be load-bearing. Tight knowledge is better knowledge — it gets read, the load-bearing words stand out, and the agent at runtime wastes less context on hedging.

### Validate

Deterministic checks → probes → self-reflection, in that order. See "Validation" below.

If validation surfaces an unresolved concern, diagnose and re-edit. **Cap at 3 iterations.** On the 3rd failure, stop and surface the probe evidence to the user — don't loop forever.

### Finish

Confirm every file you intended to change actually changed. Confirm every ripple file you identified was either touched or explicitly deferred with a stated reason. Summarize: what changed, where, why, and what you deliberately didn't touch. Leave git state clean.

Walk through `${CLAUDE_SKILL_DIR}/checklist.md` before calling the edit done.

## Validation

Three aspects: **deterministic checks**, **probes** for evidence gathering, and **your self-reflection** using the probe evidence. Probes produce data, not verdicts. You are the only judge, because only you have the edit intent and the full surrounding context.

### Deterministic checks

No LLM. Run first.

1. **Imports resolve** for each touched signature:
   ```bash
   python3 scripts/resolve_imports.py <signature_id>
   ```
2. **Schema tests**:
   ```bash
   python3 -m pytest soc-agent/tests/test_kb_schema.py -v
   python3 -m pytest soc-agent/tests/test_resolve_imports.py -v
   ```
3. **Cross-references** via Grep:
   - Lead names in playbooks exist under `knowledge/common-investigation/leads/`
   - `@import:` atoms exist under `knowledge/common-investigation/lessons/`
   - Archetype `required_anchors` exist under `knowledge/environment/operations/`
   - `permissions.yaml` modes and tools are valid shapes
4. **Tag vocabulary** for any touched lead query template:
   ```bash
   python3 scripts/tools/list_lead_tags.py --check <template-path>
   ```
   The script collects the tag vocabulary across all existing `leads/*/templates/*.md` frontmatter and reports, for the target file: tags that are new to the vocabulary, tags that are near-duplicates of existing ones (e.g., `auth` vs `authentication`), and tags that violate the `snake_case` convention. Treat every flagged tag as an edit decision — reuse the existing term if one fits, introduce the new term deliberately, or rename to snake_case. Never let the check pass by ignoring it.

If any fail, fix and re-run before touching probes.

### Probes

Spawn Haiku subagents via Task. Each probe reads one or more files and returns structured evidence. Probe prompt templates live in `${CLAUDE_SKILL_DIR}/probes/`:

| Probe | Targets | When to run |
|---|---|---|
| `reconstruction.md` | Information loss — can a reader rebuild the underlying artifact (SIEM query, alert shape, archetype story, query template) from the edited file? | Always |
| `comprehension.md` | Silent prescriptive weakening, internal contradiction, typo'd field names | Always |
| `coherence.md` | Cross-file drift — do the files that should agree on a shared topic still say the same things? | Multi-file edits |
| `replay.md` | Runtime behavior drift — does the edited playbook lead to the same 2-step investigation path for historical alerts? | Destructive edits; signature creation/rewrite |
| `tag-search.md` | Tag discoverability — would a reader in the middle of an investigation naturally reach for this template using the tags you set? | Touched or new lead query templates |

Total probe cap per edit: **10**. Sanity boundary, not a per-edit target. Going over 10 means you're stuck in a re-probing loop — surface the problem to the user rather than loop.

Dispatch in parallel when probes are independent. Use `Task` with `subagent_type="general-purpose"` and `model="haiku"`. Substitute file paths, questions, topics, and alert JSON into the template before passing. The `tag-search.md` probe spawns multiple runners with different framings — its own file documents the dispatch pattern.

### Self-reflection

After probes return, answer three questions, citing the probe evidence:

1. **Did the edit lose information?** Compare the pre-edit state (from `git diff`) against the reconstruction probe output. If the reconstructed artifact has diverged from the real underlying thing — a wrong field, a dropped threshold, a missing clause — the edit distorted load-bearing content. Fix it.

2. **Did the edit introduce contradiction?** Read comprehension and coherence probe outputs. Any answer that conflicts with frontmatter, adjacent files, or your stated intent is a flag. Re-edit, or document why the apparent contradiction is intentional.

3. **Would past investigations still resolve correctly?** Compare replay probe outputs against historical traces in `runs/*/report.md` and the archetype example JSONs. Expected differences (improved fast-path, deliberate narrowing) are fine. Unexplained differences are a flag.

If all three come back clean, accept the edit. If any surfaces an unresolved concern, re-edit and re-probe within the 3-iteration cap.

## Ground rules

- **Every non-trivial claim grounded.** Each substantive claim references a concrete source: a past ticket, a handbook rule, an existing sibling pattern, or user-provided material. If you can't cite it, flag the gap rather than invent grounding.
- **No fabricating history.** If a task calls for historical data you don't have (archetypes based on recurring patterns, precedents based on real tickets), say so and mark sections TODO. Inventing history is the one failure mode the safety net can't catch.
- **Fail loud on ambiguity.** If a field location, intent, or rule is unclear, surface it rather than guess. Same rule as the rest of the plugin.
- **Consult `/handbook` on demand.** When you need to check KB layout, validation rules, or artifact shape, invoke `/handbook`. Do not re-derive or re-document what the handbook covers.
- **Research via `/investigate`.** Signature authoring that needs historical SIEM data is a two-step flow: `/investigate` pulls data in an exploratory run, then `/author` shapes it into knowledge files. You don't have SIEM tools.
