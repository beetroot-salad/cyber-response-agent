# Contract author charge

Read when authoring or repairing tests. Inputs: the current design and decisions, grounding evidence and base, test profile/conventions, assigned obligations and files, existing shared machinery, and relevant findings. Work only in the designated worktree and owned files. Return changed paths, obligation/test mapping, checks and observations, remaining assertion reachability gaps, and findings. Do not implement production behavior or edit another writer's files.

## Translate promises into executable cases

Independently understand the intended behavior before copying any existing test expectation. Start with a real entry point and an observable result for each important promise. Use unit tests for narrow rules and integration/end-to-end tests for wiring and flows. An isolated unit test does not establish that production uses the rule.

For each scenario, identify the condition, action, expected result, observation channel, and a plausible violation the assertion would reject. Derive expected values from the design and explicit fixtures, never a reimplementation of target logic. Explain meaningful fixtures; input data must actually enter the condition the test claims to exercise.

Use the design properties to generate relevant variants and interactions: identity/replay, partial progress/recovery, shared-state ordering, removed-reader survival, alternate access paths, or guard partitions where applicable. Do not multiply the full Cartesian product of cases or write one test per imagined exception. Prefer a few cases that distinguish materially different outcomes, plus property-based checks where the invariant and oracle are clear.

Keep design commitments distinct from convenient signatures. Choose local seams and test machinery under existing conventions; surface choices that impose a new architecture, state owner, or lifecycle. A missing target import can be expected before implementation; it is not a reason to commit a production skeleton.

## Use real observations

- Drive the real entry point for an obligation about a flow. Assert observable output, stored state, errors, or recorded boundary calls. Introspection such as `isinstance`, `hasattr`, or a non-null field cannot establish wiring.
- Assert on the inbound payload a dependency fake captures when outbound content matters; a canned response alone leaves that channel unchecked.
- Prefer real faults through real primitives: malformed bytes, collisions, interrupted operations, or actual filesystem inputs. For an expensive/nondeterministic dependency, use a fake grounded in observed behavior or its established contract. Do not present an imagined exception taxonomy as reality; probe a load-bearing uncertainty or report it.
- Fakes inject inputs/faults and record calls; they must not implement the policy under test. Prefer existing injection idioms and shared harnesses. Verify which production resolution/setup paths the harness bypasses; include real construction/entry-path coverage where behavior depends on them.
- Pair negatives with positive controls that demonstrate the same observation channel can expose the prohibited behavior under the complementary allowed condition. `secret not in output` over empty output and `nothing queued` when no finding exists prove nothing about redaction or queue policy.
- Match fixture value types to real inputs, including serialization and environment-sensitive forms. Shared helpers must not make every case fail on the same unrelated assertion before reaching its own promise.

Ground only facts relevant to the contract. Inherit evidence still valid at the base; probe claims whose scope or environment changed. Preserve claim IDs and record new observations. A fact about today's bug may inform the test setup; it must not become the expected result when the design requires correcting it.

## Check while authoring

Run assigned files and relevant shared-harness checks using the project interpreter. Check collection separately from execution. Inspect each distinct failure class: expected missing behavior, broken test/harness, or assertion reached and rejected. Lint/type checks should distinguish pre-existing failures and unavailable target symbols from defects introduced by tests.

Where a new target prevents later assertions from running, test-only temporary doubles can validate machinery and challenge assertions, but are not evidence that production wiring works. Keep them out of production and clearly distinguish their evidence from a real target run. Record exactly which assertion groups still need verification after implementation.

Keep the contract map current and report design gaps early. A known bad assertion is an authoring defect to repair, not a deferred verification item. Tests strengthened to enforce settled intent need independent rechecking; changes to expected behavior need an approved design amendment.
