# Sketch, spike and from-scratch review

Three charges that try a draft design against the code before the human decides on it (SKILL.md §2–§3). Each runs as one worker; none is split across workers. Never write or commit production code, and commit nothing: the code stage has to earn green on its own, and the spike's code is never shown to a later stage.

## Sketch

You write a thin set of tests against the draft design, in your own worktree on the recorded base. You receive the draft, the code map and the project's test conventions. The sketch makes the design concrete as cheaply as possible: one representative case per important promise and main flow, through real entry points, with explicit expected results. Leave variants and edge cases to write-tests' thorough pass.

Your most valuable output is every point where writing a setup or an expected value forced a choice the design does not make. Report each with the case that exposed it rather than picking an answer. Keep the cases well-formed so write-tests can carry them forward. Return the cases as a patch, the forced choices, and the test entry points and fixtures you used, for the code map.

## Spike

The spike is a throwaway implementation of the core flows, written to find where the design meets friction in the real code. Work in your own detached worktree, against the design and the sketch, and take the path a competent implementer would naturally take. Don't polish, and don't invent clever workarounds that make the design look easier than it is. Run the sketch against it without editing the tests.

The deliverable is a **friction log**, for a review that asks how the design should have been shaped so these problems never arose. One entry per place where the design didn't say enough or didn't fit the code, and you had to guess, work around something, or depart from its mechanism: cite the code (`path:line`), the design element involved, and what you did instead. Where the existing code pulled toward a different shape, such as another owner, model or flow, say what it was. Sketch harness defects and existing tests that would need changing go in a separate list at the end, for the test author rather than the review. Return the log and the diff.

## From-scratch review

You are the first independent review of a draft design, with evidence most reviewers lack: a thin sketch and a throwaway spike. The checks in SKILL.md §3 still apply. Your question is not where the draft has holes but whether it has the right shape: knowing what the sketch and spike showed, how would you design this from scratch so those problems never arise?

**1. Collect the tensions.** They come in two kinds:

- **Inside the design:** promises that contradict each other, choices the sketch was forced to make, promises no case could observe at a real boundary, flows the design implies but never states, and grounding claims the code contradicts.
- **Between the design and the code it lands in:** read the spike's diff, not only its log. An implementer doesn't stop at friction the way a person does; it writes the workaround, so the workarounds the design forced are in the code. A friction counts when the design caused it; mess from the spike's own shortcuts is noise.

Ignore sketch harness defects and existing tests that will need changing: the spike lists them for the test author. Raise one only when it hides a design tension, and then as part of that tension.

**2. Redesign from scratch.** Take the tensions as one set, not a list to patch. Work from the problem and the promises, not the draft's mechanism, and ask what design would not have produced them: which owner, model, flow or rule makes them impossible rather than handled. Try more than one shape. Fit each to the existing code as the spike found it; where one needs that code to change, say what and what it costs. Keep the promises; a redesign that needs one changed names it as a scope choice for the human.

**3. Compare.** Set your best design against the draft. Either the draft's shape holds and the tensions are local, or a different shape removes a group of them.

**Return what the human will read first, then the evidence.** The first three parts fit on one screen:

1. **The proposed design.** Whether the draft's shape holds, and each change you would make: what changes, which tensions it removes, what it costs. Then the shapes you tried and rejected, each with the reason.
2. **Decisions for the human.** The choices no redesign settles, each with your recommendation.
3. **Readiness.** Whether the design is ready for the executable contract once those are settled, and what blocks it otherwise.
4. **Evidence.** Per tension: the cited code, sketch case or spike entry, labelled confirmed (read in code or run) or inferred; and the local fix for each tension the redesign leaves.

## Cache

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: <tags> | <application>`. Each applies a rule above to the context its tags name. If it disagrees with its rule, or its context has changed, recompute it from the rule, which wins; judge an uncovered case from the rule. Project-specific entries use the same format in the project's `.claude/contract-first-cache.md`: grep it for this skill's name.

- discuss-issue/sketch-and-spike §sketch author | ctx: models=claude-5 | Opus at medium effort.
- discuss-issue/sketch-and-spike §spike implementer | ctx: models=claude-5 | Sonnet at medium effort.
- discuss-issue/sketch-and-spike §spike what-it-catches | ctx: past-runs | two owners of one fact, mechanisms that collide with existing constraints, shortcuts the design invites.
- discuss-issue/sketch-and-spike §spike friction-kinds | ctx: past-runs | two places that would own the same fact; a collision with a widely used signature, a guard, a lint or census, an import boundary; a mechanism other than the design's; a value threaded through layers that shouldn't know it; something special-cased to make a test pass.
- discuss-issue/sketch-and-spike §review reviewer | ctx: models=claude-5 | Opus at high effort.
- discuss-issue/sketch-and-spike §review spike-workarounds | ctx: past-runs | two places owning one fact, a special case keyed to a fixture, a value threaded through layers that shouldn't know it, a bypassed guard or census, a signature change that ripples to many callers, swallowed errors, a mechanism other than the design's.
