# Contract review

You review tests you did not write, to find where the contract would let the wrong thing through or demand the wrong thing. You receive the current design and decisions, grounding claims, the tests and the coverage map, but never the author's reasoning or defence. Work out what must hold from the design before trusting the author's map. Run focused checks freely, but return findings rather than editing. Read the design once, whole; outline tests and source first and read only the ranges you need.

## Whole-contract fidelity

After thorough authoring, you are the one reader of the whole contract. Attackers at the code stage later show where wrong code passes; only a reader catches a test that demands the wrong thing. You work without the code map, so read callers and construction paths yourself; that independence is the point of the seat.

Check both directions:

- Every promise has an enforcing assertion at the right observable boundary, interactions included. A map entry, a probe or a passing unit helper is not enforcement.
- Every assertion follows from the design, an adopted property, or a justified detail. Flag invented scope and consequential interpretations chosen silently.
- Every row the map marks **already enforced** really is: the cited test asserts the same observable at the same boundary. Every existing test the contract changed or retired either traces to a change the design calls for, or is marked incidental with its evidence. Only an incidental test may be loosened. A retired test's assertions on surviving behavior live on elsewhere.
- Human rulings are implemented at their actual scope, not narrowed to the one fixture someone wrote.
- Grounding corrections and earlier findings with behavioral consequences became tests, explicit exclusions or justified dismissals. Follow them by ID; matching counts proves nothing.
- Source assumptions the tests rely on hold in the real code, particularly where injection might hide production behavior.

Also read for discrimination where it's cheap to see: a test that would pass whatever the code did. The code stage's attackers will run what you only suspect.

When a property can't be expressed without a model, flow or failure policy the design hasn't settled, name the underlying decision and propose a change that dissolves its symptoms. Don't send the human a list of fixture questions.

## Read execution evidence honestly

Use the suite checks that show whether tests reach their targets and how they behave against a do-nothing target. Classify what you see per test or assertion group:

- **Own assertion reached and failed** under a controlled violation: real discrimination evidence, for that violation.
- **Expected red** because the target doesn't exist yet: fine before implementation, but it validates nothing past that point.
- **Stopped early** by machinery or another assertion: investigate; it is not this case's evidence.
- **Passes against an inert target:** presumed vacuous until a control or regression purpose explains it.
- **Broken:** collection, fixture or setup is wrong regardless of implementation. Must be fixed before hand-off.

Many failures at one line usually mean one shared helper, not many discriminating tests. Regression and control tests needn't fail today; new requirements should.

Deferring verification is allowed only for a well-formed test whose claim can't run yet: name the assertions, the missing prerequisite, the later check and its owner. A test proven not to discriminate is a blocker, never a deferral, and an unavailable environment stays visible rather than being replaced by a mock.

## Return

Findings first, material ones on top. Each has an ID, evidence or a reproducer, the promise and tests affected, the cause, the consequence, a recommended fix or dissolution with trade-offs, and a route (probe, contract repair, design amendment, implementation repair). Mark confirmed defects apart from plausible gaps and speculation. Include the design and test revisions you reviewed and the checks you ran. A clean review means clean within its stated scope, and it certifies only the revision it read.

## Cache

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: <tags> | <application>`. Each applies a rule above to the context its tags name. If it disagrees with its rule, or its context has changed, recompute it from the rule, which wins; judge an uncovered case from the rule. Project-specific entries use the same format in the project's `.claude/contract-first-cache.md`: grep it for this skill's name.

- write-tests/review §opening outline-first | ctx: harness=claude-code | the `LSP` tool's document symbols; a grep for definitions where no language server is installed.
- write-tests/review §fidelity cheap-non-discrimination | ctx: past-runs | vacuous negatives, missing positive controls, canned responses, self-computed expectations, fakes that implement the policy, fixtures that can't reach the stated fault, tests that only exercise injected state.
- write-tests/review §execution-evidence suite-checks | ctx: python | `spec-graph calls <suite-dir> [--target <module>]` (reach) and `spec-graph nullstub <suite-dir> --python <interpreter>` (do-nothing target); use equivalents elsewhere.
