---
name: handoff
description: "Write a terse handoff note (~1 paragraph) that lets a fresh session resume the current work without re-deriving it. Use when wrapping up mid-task, or when the user asks for a handoff or to continue later. Takes an optional GitHub issue to post the note to."
argument-hint: "[issue number or URL]"
effort: low
---

# Handoff

Write a terse handoff note — aim for one dense paragraph — that a fresh session can act on immediately. Capture only what isn't recoverable by reading the repo:

- **Goal** — what we're trying to do, in one line.
- **State** — what's done and verified vs. what's in-flight; name the branch / PR / key files (`path:line`) so the next session lands in the right place.
- **Next step** — the single concrete action to take next, not a menu of options.
- **Gotchas** — the non-obvious constraint, the dead-end already ruled out, or the decision already made, so it isn't re-litigated.

Skip what the code, git history, or an open PR already say — link to them instead. No status-report padding; the note is a launch point, not a summary.

## Where it goes

- **No argument** — output the note in the chat.
- **An issue number or URL is given** — post the note as a **comment** on that issue with `gh issue comment <n> --body "<note>"` (a comment, so nothing already on the issue is overwritten), then report the comment URL. Show the note in the chat too, so it's visible without opening GitHub.
