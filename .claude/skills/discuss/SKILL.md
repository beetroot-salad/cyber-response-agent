---
name: discuss
description: "Take an issue from a bare report to a finalized design. Analyze it for scope, correctness, completeness, and clarity; seed a design discussion with a tight summary, the alternative fixes and their tradeoffs, and a recommendation; run the discussion to close the open forks; then finalize as a design doc or a refined issue. Use when a GitHub issue needs to become a design before anyone implements it."
---

# Discuss

Turn a bare issue into a finalized design. The arc: **analyze** it (scope, correctness, completeness, clarity), **seed** the discussion (a summary, the alternative fixes with tradeoffs, a recommendation), **discuss** to close the open forks, then **finalize** — as a design doc or a refined issue. All in chat.

## 1. Load the issue

Default to a GitHub issue: `gh issue view <n> --comments`. Read the comments — a partial discussion may already be underway, so don't re-seed points already settled there. If given a file path or pasted text instead, work from that.

Restate the core ask in a sentence to confirm you're solving the right problem before you analyze.

## 2. Analyze

Check four axes. The issue is a starting point, not a source of truth — ground every claim in the actual repo.

**Scope** — what the change is and isn't:
- what's in scope, and the explicit non-goals
- affected components / blast radius
- whether two problems are wearing one issue (split them)

**Correctness** — verify each factual claim against the codebase. Issues routinely assert "X works like Y" or "Z handles W" from stale memory. Grep and read the named files; flag every claim that conflicts with current code and cite `file:line`. When the claim surface is broad, delegate verification to an Explore subagent. A design built on a false premise is wasted work — this axis gates the rest.

**Completeness** — what's missing to design or act:
- problem and motivation (why now; what breaks without it)
- done criteria — how we'd know it's solved
- constraints, dependencies, prior art (linked issues, PRs, `defender/docs/`)

**Clarity** — name each ambiguity and its candidate readings. Flag undefined referents and terms used loosely.

Report findings compactly (see Output format) — surface what the design has to resolve.

## 3. Seed

Produce the discussion seeds in one pass (see Output format):

- **Summary** — the issue distilled to its context and problem, in a few sentences. Summarize, don't transcribe; this is the anchor the discussion builds on.
- **Alternative fixes** — convert the open gaps into the real design forks, not trivia. For each fork, 2–3 viable options with their tradeoffs. Order by what unblocks the most downstream choices. Drop anything already resolved in the issue or its comments.
- **Recommendation** — for each fork, your pick and the reason.

## 4. Discuss

Resolve the open forks with the user, highest-leverage first.
- Where there's a genuine fork, ask (AskUserQuestion) with your recommendation first.
- Where the codebase or an existing convention dictates the answer, state it and move on — don't manufacture a choice.
- Pull in fresh grounding (read code, check `defender/docs/` and conventions) as resolved forks raise new questions.
- Track resolved vs open out loud. Loop until the open set is empty.

## 5. Finalize

Once the open set is empty, close out one of two ways — match the weight of the outcome:

**Design doc** — when the result is a real design worth its own artifact. Present it in chat in the shape of an existing `defender/docs/*-design.md`:
- **Status** — design; what it depends on or supersedes
- **What this is** — the mechanism in a paragraph
- **Design** — how it works; the load-bearing decisions and why each
- **Kept / dropped** — what's in scope and what's explicitly not
- **Open questions** — anything deferred, and what would close it

Offer to write it to `defender/docs/<name>-design.md`.

**Refined issue** — when the outcome is better folded back into the issue than spun into a doc (smaller change, or the issue is the right home). Rewrite the issue body so it states the resolved problem, scope, chosen approach, and done criteria — no longer a bare report.

Pick by the change's weight; when unsure, ask. Write the doc or update the issue only on the user's go-ahead.

## Output format

The analysis and seeds, in one pass:

```
## #<n> <title>

**Summary** — <2–3 sentences: the context and the problem; what breaks without it>

### Analysis
- Scope: <in / out; blast radius> — <gap, or confirmed sound>
- Correctness: <file:line> — issue claims "<x>"; code shows <y>
- Completeness: <what's missing> — <why it blocks the design>
- Clarity: "<phrase>" → reading A: <…> / reading B: <…>

### Alternative fixes
1. <fork — the question>
   - A: <option> — <tradeoff>
   - B: <option> — <tradeoff>
   Rec: <A/B>, because <reason>
2. …
```

Then proceed to §4 — resolve the forks before finalizing.
