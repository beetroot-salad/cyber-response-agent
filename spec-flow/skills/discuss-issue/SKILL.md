---
name: discuss-issue
description: "Explain a GitHub issue to someone who hasn't read it, ground it in the current code, and say plainly what in it takes judgement — closing, when the issue heads to implementation, with the typed intent+design doc write-tests consumes. Use before designing on a bare issue report."
argument-hint: "[issue number, what to discuss]"
effort: high
---

# Discuss issue

Explain the issue, check it against the code, say what in it takes judgement. The thinking is yours; this file only says where to point it.

Load it first — `gh issue view [issue number] --comments` (empty output is a failed read, not an empty issue; retry with `--json title,body,comments`), or take it from the conversation, a path, or pasted text. Read the comments; some of this may already be settled.

Ground the issue against the code base. Explore it, read it and execute small snippets when relevant. The goal is to run the discussion against the correct model of the code base, less so to nitpick the issue (so try to avoid claims like "The issue says X but it is actually Y").

Then it depends on whether "what to discuss" was specified or not. If yes, answer that based on the knowledge you gathered about the code base. If not, explain what the problem is, why it is a problem, and what takes judgement, **plainly**. Ignore the suggested solution or fix the issue proposes; take only the problem statement from there.

## Meta Note: the issue holds the state

The conversation is where the discussion happens; the issue is where its state lives — for the next worker to pick up cold, or to debug months later. So what got settled goes in a comment, typed and terse rather than a narrative: the corrected premise, the decisions and what they turned on. Won't-fix and already-resolved are state too — post the disposition and stop there.

When the issue is heading to implementation, that closing comment is the intent+design doc write-tests consumes. **references/design-doc.md** carries its sections, the claims sweep that probes them, and the cold review before it posts; read it then, and scale the ceremony to the issue.
