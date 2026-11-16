# Sketch, spike and from-scratch review

Three charges that try a draft design against the code before the human decides on it (SKILL.md §2–§3). Each runs as one worker; none is split across workers. Commit nothing. The spike's code is throwaway and goes to the reviewer only, never to a later stage: the code stage has to earn green on its own.

## Sketch

You write a thin set of tests against the draft design, in your own worktree on the recorded base. You receive the draft, the code map and the project's test conventions. The sketch makes the design concrete as cheaply as possible: one representative case per important promise and main flow, through real entry points, with explicit expected results. Leave variants and edge cases to write-tests' thorough pass.

Your most valuable output is every point where writing a setup or an expected value forced a choice the design does not make. Report each with the case that exposed it rather than picking an answer. Keep the cases well-formed so write-tests can carry them forward. Return the cases as a patch, the forced choices, and the test entry points and fixtures you used, for the code map.

## Spike

The spike is a throwaway implementation of the core flows, written to find where the design meets friction in the real code. Work in your own detached worktree, against the design and the sketch, and take the path a competent implementer would naturally take. Don't polish, and don't invent clever workarounds that make the design look easier than it is. Run the sketch against it without editing the tests.

The deliverable is a **friction log**, for a review that traces the problems to their causes. One entry per place where the design didn't say enough or didn't fit the code, and you had to guess, work around something, or depart from its mechanism: cite the code (`path:line`), the design element involved, and what you did instead. Where the existing code pulled toward a different shape, such as another owner, model or flow, say what it was. Sketch harness defects and existing tests that would need changing go in a separate list at the end, for the test author rather than the review. Return the log and the diff.

## From-scratch review

You are the first independent review of a draft design, with evidence most reviewers lack: a thin sketch and a throwaway spike. The checks in SKILL.md §3 still apply. Explain the problems the sketch and spike expose so plainly that the human can redesign from your account. Ask how you would design this from scratch so they never arise: that is how you find each problem's cause.

**1. Collect the tensions.** They come in two kinds:

- **Inside the design:** promises that contradict each other, choices the sketch was forced to make, promises no case could observe at a real boundary, flows the design implies but never states, and grounding claims the code contradicts.
- **Between the design and the code it lands in:** read the spike's diff, not only its log. An implementer doesn't stop at friction the way a person does; it writes the workaround, so the workarounds the design forced are in the code. A friction counts when the design caused it; mess from the spike's own shortcuts is noise.

Ignore sketch harness defects and existing tests that will need changing: the spike lists them for the test author. Raise one only when it hides a design tension, and then as part of that tension.

**2. Find the causes.** Take the tensions as one set, not a list to patch. Several symptoms usually share one cause: an owner, model, flow or rule in the draft. To find it, work from the problem and the promises rather than the draft's mechanism, and try more than one shape that would make the tensions impossible rather than handled. Fit each to the existing code as the spike found it. Weigh each against the project's principles and threat model, not only against the tensions it removes: a shape that removes three tensions and weakens a trust boundary is a trade-off to show, not a fix.

**3. Return the problems first, written for the human, then the evidence:**

1. **The problems.** One per cause, not per symptom, most consequential first. For each: what goes wrong, as a concrete scenario; which part of the design causes it; and why patching each symptom would leave the cause in place. The reader knows the design but not the code, so name a file or symbol only alongside what it does. Say how sure you are.
2. **Shapes that would remove them.** For each cause a different shape would remove: the shapes you tried, what each changes, which problems it removes, and what it costs or weakens. These are options with trade-offs, not a verdict; if you lean toward one, say so and why, marked as your lean. If the draft's shape holds and the problems are local, say that plainly.
3. **Decisions for the human.** The choices left, including any choice between shapes.
4. **Readiness.** What has to be settled before the design is ready for the executable contract.
5. **Evidence.** Per tension: the cited code, sketch case or spike entry, labelled confirmed (read in code or run) or inferred; and the local fix for each tension no change of shape addresses.

Keep parts 1 to 4 short enough to read in one sitting; the detail belongs in the evidence.

## Cache

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: <tags> | <application>`. Each applies a rule above to the context its tags name. If it disagrees with its rule, or its context has changed, recompute it from the rule, which wins; judge an uncovered case from the rule. Project-specific entries use the same format in the project's `.claude/contract-first-cache.md`: grep it for this skill's name.

- discuss-issue/sketch-and-spike §sketch author | ctx: models=claude-5 | Opus at medium effort.
- discuss-issue/sketch-and-spike §spike implementer | ctx: models=claude-5 | Sonnet at medium effort.
- discuss-issue/sketch-and-spike §spike,review friction-kinds | ctx: past-runs | two owners of one fact; a collision with a widely used signature, guard, lint, census or import boundary; a mechanism other than the design's; a value threaded through layers that shouldn't know it; a special case keyed to a fixture; swallowed errors.
- discuss-issue/sketch-and-spike §review reviewer | ctx: models=claude-5 | Opus at high effort.
