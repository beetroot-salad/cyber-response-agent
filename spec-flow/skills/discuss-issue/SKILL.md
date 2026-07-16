---
name: discuss-issue
description: "Explain a GitHub issue in plain terms, check it against the current codebase, and surface the open questions that need answering before anyone designs or implements. Use when a bare issue report needs to be understood and grounded in the real code."
argument-hint: "[issue number]"
effort: medium
---

# Discuss issue

Understand a bare issue and pin down the one or two things that actually have to be decided before anyone designs on it — in chat, not against a template. The job is to save downstream churn: catch a false premise before it becomes a design, and settle the fork a design would otherwise thrash on. The thinking is yours; this skill is about where to point it.

Load the issue first. If a number was passed: `gh issue view <n> --comments` (empty output is a failed read, not an empty issue — retry with `--json title,body,comments`). Otherwise take it from the conversation, or the file path or pasted text you were given. Read the comments — some of this may already be settled.

## Precondition — is the issue accurate and complete?

Check the issue against the code it describes *before* discussing anything on top of it; a discussion built on a false premise is wasted.

- **Accurate.** Issues assert "X works like Y" from stale memory. Read the named files and confirm, citing `file:line`; hand broad reading to an Explore subagent, but settle anything enumerable or executable with a tool run, not the reader's impression. An issue premised on in-flight work (an open PR, a stacked branch) is checked against *that* tree, and you say which — "refuting" a correct issue by reading the wrong base is the failure mode. The mirror case: an issue filed from a review can have been true when filed and fixed by a later merge, so check the named files' history back to the filing point, not just their current state — "already resolved by #NNN" is a finding, not a baseless report.
- **Complete.** Does it carry enough to act on — the motivation, a done criterion, the dependencies? Name what's missing.

If the issue's picture is wrong, correcting it is the first finding — fix the premise before going further.

## What is this really about?

Explain the problem plainly — what it is, where it lives, why it surfaces — the way you'd tell a colleague who knows the system but not this issue. If you can't explain the mechanism without hand-waving, read the code until you can.

Then **narrow**. An issue usually turns on one or two things that genuinely have to be nailed down; once those are settled the rest follows. Find them and lead with them — don't hand back five decisions as if they carried equal weight. For each, say what's unclear and your read on it; skip whatever the codebase or an existing convention already answers.

The angles below are scaffolding for finding those one or two things — prompts, not a checklist:

- **Worth doing?** — real and worth solving now, or is "won't fix" / "not yet" the honest answer?
- **Root cause** — is the reported symptom the real problem, or a downstream effect of a deeper cause that's the better fix?
- **The hard part** — the constraint in tension, the invariant easy to break. Usually where the real forks live.
- **Scope** — what's in, what's an explicit non-goal, whether two problems wear one issue.
- **The same pattern elsewhere** — the sites the issue names are a sample, not a census; once the mechanism is clear, derive the other occurrences with a tool at the issue's altitude (its motivation and mechanism, never its file list) and give each an in-or-out verdict. When "the same" is a *symbol* — a function, class, constant — the **symbol-refs** skill resolves who references it past grep's lexical false positives. One the issue missed is a finding; an exclusion is a decision worth recording.

## Closing with a design doc

Talk it through with the user; nothing here forces an artifact, and a discussion that ends in "won't fix" ends in chat. When the issue is heading to implementation, close by compiling what was settled into the intent+design doc write-tests consumes. **references/design-doc.md** carries that step — the doc's typed sections, the claims sweep that verifies it, and the cold review that checks it before it posts. Read it then; scale the ceremony to the issue.
