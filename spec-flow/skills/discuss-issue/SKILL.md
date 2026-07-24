---
name: discuss-issue
description: "Explain a GitHub issue to someone who hasn't read it, ground it in the current code, and settle what gates a design — closing, when the issue heads to implementation, with the typed intent+design doc write-tests consumes. Use before designing on a bare issue report."
argument-hint: "[issue number]"
effort: medium
---

# Discuss issue

Explain the issue, check it against the code, settle what has to be settled before anyone designs on it. The thinking is yours; this file only says where to point it.

Load it first — `gh issue view <n> --comments` (empty output is a failed read, not an empty issue; retry with `--json title,body,comments`), or take it from the conversation, a path, or pasted text. Read the comments; some of this may already be settled.

## Open with the problem

Your first message establishes what the problem is, and stops there. Explain it to a colleague who knows the system but hasn't read this issue: what it is, where it lives, why it surfaces. Hand-waving the mechanism means you haven't read enough code yet.

Issues assert "X works like Y" from stale memory, so ground the claims as you go, cited `file:line` — against the right tree when the issue is premised on an open branch, and against history when a later merge may already have fixed it. A corrected premise is the first finding, sometimes the only one.

Success criteria, scope, and design come later, as the discussion earns them.

## As it develops

**Climb.** Issues are filed at instance level — one failing run, one alert, one call site. The design lives a level up: the mechanism that produced the instance, and the class of case it belongs to. The sites the issue names are a sample, not a census — derive the rest at that altitude and give each an in-or-out verdict; **symbol-refs** resolves the census past grep when "the same thing" is a symbol.

**Evaluate the oracle.** What will say this is fixed, and can it be wrong? An oracle that cannot fail, or that stands in for the property actually wanted, passes a broken implementation just as happily. When the judging thing is itself what the issue is about — a scorer, an eval, a detection rule, an assertion — that circularity decides whether the issue is ready to implement at all.

**Narrow.** An issue turns on one or two things that genuinely have to be nailed down; once those are settled the rest follows. Lead with them and your read on each, not five decisions handed back as equals. Skip whatever the codebase or an existing convention already answers.

## The issue holds the state

The conversation is where the discussion happens; the issue is where its state lives — for the next agent to pick up cold, and for a human to debug from months later. So what got settled goes in a comment, typed and terse rather than a narrative: the corrected premise, the census, the decisions and what they turned on. Won't-fix and already-resolved are state too — post the disposition and stop there.

When the issue is heading to implementation, that closing comment is the intent+design doc write-tests consumes. **references/design-doc.md** carries its sections, the claims sweep that probes them, and the cold review before it posts; read it then, and scale the ceremony to the issue.
