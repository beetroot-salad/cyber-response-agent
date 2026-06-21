---
name: discuss
description: "Take an issue from a bare report to a comprehensive design. Audit it for completeness, accuracy (verified against the codebase), and clarity, then seed and run an interactive design discussion that closes the open forks. Use when a GitHub issue needs to become a design before anyone implements it."
---

# Discuss

Turn an issue into a design. Three moves: **audit** it (completeness, accuracy, clarity), **seed** the design forks it leaves open, then **run** the discussion to close them — all in chat. The deliverable is a comprehensive design, not a patched issue.

## 1. Load the issue

Default to a GitHub issue: `gh issue view <n> --comments`. Read the comments — a partial discussion may already be underway, so don't re-seed points already settled there. If given a file path or pasted text instead, work from that.

Restate the core ask in a sentence or two and confirm you're solving the right problem before auditing.

## 2. Audit

Check three axes. The issue is a starting point, not a source of truth — ground every claim in the actual repo.

**Completeness** — what's missing to design or act:
- problem and motivation (why now; what breaks without it)
- scope and explicit non-goals
- affected components / blast radius
- done criteria — how we'd know it's solved
- constraints, dependencies, prior art (linked issues, PRs, `defender/docs/`)

**Accuracy** — verify each factual claim against the codebase. Issues routinely assert "X works like Y" or "Z handles W" from stale memory. Grep and read the named files; flag every claim that conflicts with current code and cite `file:line`. When the claim surface is broad, delegate verification to an Explore subagent. A design built on a false premise is wasted work — this axis gates the rest.

**Clarity** — name each ambiguity and its candidate readings. Flag conflated concerns (two problems wearing one issue), undefined referents, and terms used loosely.

Report findings compactly (see Output format). Don't rewrite the issue text — surface what the design has to resolve.

## 3. Seed

Convert the gaps into **decision points** — the real design forks, not trivia. For each: the question, 2–3 viable options with their tradeoffs, and your recommendation with a reason. Order by what unblocks the most downstream choices. Drop anything already resolved in the issue or its comments.

## 4. Discuss

Resolve the decision points with the user, highest-leverage first.
- Where there's a genuine fork, ask (AskUserQuestion) with your recommendation first.
- Where the codebase or an existing convention dictates the answer, state it and move on — don't manufacture a choice.
- Pull in fresh grounding (read code, check `defender/docs/` and conventions) as resolved decisions raise new questions.
- Track resolved vs open out loud. Loop until the open set is empty.

## 5. Converge

Present the comprehensive design in chat, in the shape of an existing `defender/docs/*-design.md`:

- **Status** — design; what it depends on or supersedes
- **What this is** — the mechanism in a paragraph
- **Design** — how it works; the load-bearing decisions and why each
- **Kept / dropped** — what's in scope and what's explicitly not
- **Open questions** — anything deferred, and what would close it

Offer to write it to `defender/docs/<name>-design.md` or post a summary back to the issue — only if the user asks.

## Output format

The audit and seed, in one pass:

```
## Audit — #<n> <title>

### Completeness
- <what's missing> — <why it blocks the design>

### Accuracy
- <file:line> — issue claims "<x>"; code shows <y>

### Clarity
- "<phrase>" → reading A: <…> / reading B: <…>

## Decision points
1. <question>
   - A: <option> — <tradeoff>
   - B: <option> — <tradeoff>
   Rec: <A/B>, because <reason>
2. …
```

Then proceed to §4 — resolve the points before drafting the design.
