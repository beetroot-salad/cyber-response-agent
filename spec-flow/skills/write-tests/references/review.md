# Independent contract review

Read when reviewing a candidate contract. You did not author these tests. Read the design once, whole; outline tests and source with `py-outline` before reading line ranges, rather than dumping whole files. Receive the current design and decisions, grounding evidence/base, tests, map and project conventions; do not request the author's conversation or defence. Inspect and run focused checks, but return findings rather than modifying the reviewed artifact. Derive the required behavior from the design before trusting the author's coverage map.

## Design check

When charged with the design check, you read the design and a thin sketch, not a finished suite. Answer one question: does the design, made concrete by these cases, specify the right behavior completely enough to write a thorough contract against? Look for contradictions between promises, choices the sketch had to make that the design does not, promises no sketch case could express at an observable boundary, and missing flows the design implies. Do not assess discrimination, variant coverage or test mechanics; the sketch is deliberately thin. Return design-level findings grouped by underlying decision, each with a proposed dissolution and trade-offs, using the fidelity guidance below. A clean check means the design is ready for thorough authoring, not that the contract is.

## Fidelity and conservation

Compare in both directions:

- Every promised outcome has an enforcing assertion at the appropriate observable boundary, including important interactions. A map entry, a probe, or a passing unit helper is not sufficient.
- Every asserted requirement follows from the design, an adopted property, or a justified contract detail. Flag invented scope and silently selected consequential interpretations.
- Test expectations implement human decisions at their actual scope. Broad rulings must not narrow to the one fixture or path someone happened to write.
- Grounding corrections and review findings with behavioral consequences become tests, explicit design changes/exclusions, or justified dismissals. Follow items by ID and evidence; matching counts cannot establish conservation.
- Verify source assumptions where the tests rely on them. Read actual callers and real construction paths where injection might hide production behavior. Probe runtime claims that materially determine outcomes.

If a property cannot be expressed without choosing a data model, flow, or failure policy the design has not settled, identify the underlying decision. Group symptoms and propose a change that dissolves them, with alternatives and trade-offs. Do not send the human a list of fixture or implementation questions.

## Discrimination

For each important assertion or coherent assertion group, ask what plausible incorrect behavior would still pass. Check:

- Vacuous negatives, absent positive controls, canned responses, self-computed expectations, inert defaults, and assertions on type/shape where the promise is about content or wiring.
- Fakes that implement the decision being tested, fixtures that cannot reach the stated fault, and helpers whose early assertion substitutes for all callers' distinct assertions.
- Tests that exercise only injected state while real entry points resolve their own state or dependencies.
- Interacting guarantees: individually correct checks may permit incorrect identity, ordering, partial progress, or cross-surface behavior in combination.
- Input partitions relevant to the invariant, rather than only branches or example values in current code.

Use focused test-only counterexamples, mutations, or null stubs where useful. This pass is not a full adversarial implementation; the code stage separately tries to pass the committed tests while violating stated intent. Neither pass proves exhaustive correctness.

## Interpret execution evidence honestly

For Python projects, `spec-graph calls <suite-dir> [--target <module>]` checks static target reachability and `spec-graph nullstub <suite-dir> --python <interpreter>` runs tests against a temporary do-nothing target. Both consume the suite directly; use equivalent checks for other stacks. Follow project interpreter and injection conventions.

Classify results per test or meaningful assertion group:

- **Own assertion exercised:** a controlled violation reaches and fails the promised assertion. Useful discrimination evidence, not proof of all violations.
- **Expected pre-implementation red:** a missing target or behavior prevents completion. Legitimate before code exists, but does not validate later assertions.
- **Non-assertion / shared early failure:** machinery or another assertion stopped the test. Investigate; do not count it as that case's discrimination.
- **Pass against an inert target:** presumed vacuous until a justified regression/control purpose or stronger assertion explains it.
- **Broken test:** collection, fixture, signature, or setup is wrong independently of missing implementation. Repair before handoff.

Inspect clusters of failures at the same line. A nominal assertion failure in one shared helper does not establish discrimination for every scenario. A temporary stub validates only the paths it actually exercises. Do not demand that every regression/control test fail against today's code; distinguish their purpose from newly required behavior.

Deferred assertion verification is allowed only for a well-formed test whose claim cannot yet be exercised. Name the assertions, missing prerequisite, required later check, and code-stage owner. A proven non-discriminating test is a blocker, not a deferred item. An unavailable environment must remain visible; do not replace a required real integration result with a mock and call it verified.

## Return actionable findings

Each finding has an ID, evidence or reproducer, affected design promise and tests, root cause, consequence, recommended patch/dissolution and trade-offs, and route: probe, contract repair, design amendment, or implementation repair. Distinguish confirmed defects from plausible gaps and speculative concerns.

Return the input design and test revisions, checks actually run with outcomes, material findings first, and remaining verification obligations. A clean review means no findings within the stated review scope. Recheck affected revisions and shared consequences after repairs; do not let an old clean verdict certify changed assertions.

The design check is one Opus reader at high effort. The review panel after thorough authoring consists of one whole-contract Opus reviewer at high effort and two or three Sonnet reviewers at high effort with distinct, design-relevant lenses. Specify each lens's question and reconcile every reviewer's output before calling review complete. Repairs need targeted rechecks of the affected assertions, not a fresh full panel unless material revisions invalidate its scope. Run each recheck as a fresh reviewer briefed with the findings, the repair diff and the affected tests; do not resume an idle earlier reviewer. A tests-only blind reader remains optional.
