---
name: discuss-issue
description: "Explain a GitHub issue to someone who hasn't read it, ground it in the current code, and settle the one or two things that gate a design — closing, when the issue heads to implementation, with the typed intent+design doc write-tests consumes. Use before designing on a bare issue report."
argument-hint: "[issue number]"
effort: medium
---

# Discuss issue

Explain the issue, check it against the code, settle what has to be settled before anyone designs on it. The thinking is yours; this file only says where to point it.

Load it first — `gh issue view <n> --comments` (empty output is a failed read, not an empty issue; retry with `--json title,body,comments`), or take it from the conversation, a path, or pasted text. Read the comments; some of this may already be settled.

## The discussion

**Explain it.** To a colleague who knows the system but hasn't read this issue: what the problem is, where it lives, why it surfaces. Hand-waving the mechanism means you haven't read enough code yet.

**Ground it.** Issues assert "X works like Y" from stale memory, and a discussion built on a false premise is wasted. Confirm against the code, cited `file:line` — and against the *right* tree, when the issue is premised on an open branch or a stacked change. The mirror case: an issue can have been true when filed and fixed by a later merge, so check the named files' history back to the filing point. A corrected premise is the first finding, sometimes the only one.

**Climb.** Issues are filed at instance level — one failing run, one alert, one call site. The design lives a level up: the mechanism that produced the instance, and the class of case it belongs to. So the sites the issue names are a sample, not a census — derive the rest at the issue's altitude (its motivation and mechanism, never its file list) and give each an in-or-out verdict. When "the same thing" is a symbol, **symbol-refs** resolves that census past grep's lexical false positives.

**Evaluate the oracle.** What will say this is fixed, and can it be wrong? An oracle that cannot fail, or that stands in for the property actually wanted, will pass a broken implementation just as happily. When the judging thing is itself what the issue is about — a scorer, an eval, a detection rule, an assertion — that circularity *is* the discussion, and it decides whether the issue is ready to implement at all.

**Narrow.** An issue usually turns on one or two things that genuinely have to be nailed down; once those are settled the rest follows. Lead with them and your read on each — not five decisions handed back as equals. Worth doing at all, symptom vs. root cause, the invariant in tension, what's an explicit non-goal: prompts for finding those one or two, not a checklist to answer. Skip whatever the codebase or an existing convention already answers.

## Where it lands

Everything that matters goes in the conversation — the explanation, the corrected premise, the census, your read on the forks. The user shouldn't have to open GitHub to know what was decided or why. A discussion that ends in "won't fix" or "already resolved by #NNN" ends here, in a short disposition; forcing an implementation doc onto an issue that shouldn't be implemented is its own failure.

The issue comment is written for the *agent* that picks this up cold, so it is typed and terse, not a narrative of the discussion. When the issue is heading to implementation, close by compiling what was settled into the intent+design doc write-tests consumes: **references/design-doc.md** carries its sections, the claims sweep that probes them, and the cold review before it posts. Read it then, and scale the ceremony to the issue.
