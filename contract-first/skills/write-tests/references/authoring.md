# Contract author charge

You write or repair tests in your own worktree and owned files. You receive the current design and decisions, grounding claims, the code map, test conventions, your assigned obligations and files, and any findings to address. Return changed paths, the obligation-to-test mapping, checks you ran and what they showed, assertions that cannot run until implementation exists, and any design gaps you found. Never write production behavior or edit another writer's files: the code stage has to earn green on its own.

## Sketch

The sketch makes the design concrete as cheaply as possible: one representative case per important promise and main flow, through real entry points, with explicit expected results. Leave variants and edge cases to the thorough pass. Your most valuable output is every point where writing a setup or an expected value forced a choice the design does not make. Report each with the case that exposed it rather than picking an answer. Keep the cases well-formed so the thorough pass can keep them.

## Spike

The spike is a throwaway implementation of the core flows, written to find where the design meets friction in the real code. Work in your own detached worktree, against the design and the sketch, and take the path a competent implementer would naturally take. Don't polish, and don't invent clever workarounds that make the design look easier than it is. Run the sketch against it without editing the tests.

The deliverable is a **friction log**: one entry per place where the design didn't say enough or didn't fit the code, and you had to guess, work around something, or depart from its mechanism. Cite the code (`path:line`), the design element involved, and what you did instead. Return the log and the diff; commit nothing.

## Writing the thorough contract

Work in four steps: decide the cases, survey the existing suite, fold, then write. Deciding first keeps old tests from anchoring you, since they may encode today's bug. Writing last means you don't pay for test code that folding would throw away.

**1. Decide the cases, before opening any existing test.** Write the case table from the design: one row per case, naming its obligation, condition, action, what it observes and at which boundary, the expected value, and a plausible wrong implementation it would reject. For each important promise, start from a real entry point and an observable result. Unit tests suit narrow rules, but an isolated unit test cannot show that production uses the rule, so flows need tests through their real wiring. Expected values come from the design and explicit fixtures, never from re-implementing the target's logic. Let the design's properties pick the variants worth having (replay, partial progress, ordering, alternate access paths, guard partitions) rather than multiplying combinations. A few cases that separate materially different outcomes beat many that don't; use property-based checks where the invariant and oracle are clear. When the design promises something over a whole class, the test covers the class: generated inputs, or an input defined only by membership. A hand-picked list of members invites an implementation that handles exactly that list. Pin only the behavior the design promises, for conditions that can arise where the system is deployed; don't demand that code tolerate, repair or sort conditions the principles say to refuse. One refusal test over the class replaces one acceptance test per bad value. Sketch cases are rows too. This table becomes the contract map.

**2. Survey, per case.** Find the nearest existing tests and fixtures for each row's entry point through the code map and an outline of the test files, and read only those. You're asking two questions: does something already enforce this, and does something pin the opposite?

**3. Fold.** Give every row one outcome and record it in the map:

- **already enforced**: an existing test asserts this observable at the same boundary. Cite it and write nothing. A test that checks only shape, or checks at another boundary, doesn't count; extend it instead;
- **extend**: add a parameter row or an assertion to an existing test;
- **new test in an existing file**, reusing its fixtures and conventions;
- **new file**, only for a surface no existing file covers;
- **conflict**: an existing test pins behavior the design changes. Update it as part of the contract and flag it in the map for review; never change it quietly. A conflict the design didn't list is a gap to report.

Don't sweep the rest of the suite for tests of replaced behavior. Those fail once real code exists, and the code stage returns them (SKILL.md §5, stale existing tests).

**4. Write.** Make sure fixture data actually reaches the condition each test claims to exercise.

Choose seams and machinery within existing conventions. Surface any choice that would impose a new architecture, state owner or lifecycle. A missing target import is expected before implementation, never a reason to commit a skeleton.

### Observe what actually happens

The commonest way a suite lies is by checking something that would be true either way. For each assertion, ask what wrong code would also satisfy it, and observe at a boundary where wrong code would look different.

- Fakes inject inputs and record calls; they never implement the policy under test. Ground a fake for an expensive or nondeterministic dependency in its observed behavior. Know which production setup paths the harness bypasses, and cover them where behavior depends on them.
- Prefer real faults through real primitives over invented ones.
- Pair every negative with a positive control on the same channel.
- Make fixtures look like real inputs, and don't let a shared helper fail every case on one unrelated assertion.

Ground only facts the contract depends on. Reuse claims still valid at the base, re-probe those whose scope changed, and keep claim IDs.

## Read narrowly, write tersely

Everything you read stays in your context and is re-sent on every later step, and everything you write is read again by every later stage.

- Read the design once, whole: it is the shared language.
- Use the code map for where things are. Open raw files to check an entry you rely on or to read what you change, and report wrong entries instead of quietly working around them.
- Outline before reading, then read only the ranges you need, such as the tests you change and one or two neighbours whose conventions you follow. Check edits through the diff.
- Docstrings are at most two lines: the promised outcome and its obligation ID. The test body carries the detail and the contract map the reasoning. Comment only what the body can't say, and stay no denser than neighbouring tests.

## Check as you go

Run your files with the project interpreter, checking collection separately from execution. Tell apart the three kinds of red: missing behavior (expected), broken test or harness (fix it), and an assertion reached and rejected (the evidence you want). Separate lint and type failures you introduced from pre-existing ones and from symbols that don't exist yet.

Test-only doubles can check machinery and challenge assertions while the target is missing, but they say nothing about production wiring: keep them out of production, label their evidence, and record which assertions still need a real run. A known bad assertion is a defect to fix now, not something to defer. Strengthened tests need an independent recheck; changed expected behavior needs an approved design amendment.

## Cache

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: <tags> | <application>`. Each applies a rule above to the context its tags name. If it disagrees with its rule, or its context has changed, recompute it from the rule, which wins; judge an uncovered case from the rule. Project-specific entries use the same format in the project's `.claude/contract-first-cache.md`: grep it for this skill's name.

- write-tests/authoring §spike friction-kinds | ctx: past-runs | two places that would own the same fact; a collision with a widely used signature, a guard, a lint or census, an import boundary; a mechanism other than the design's; a value threaded through layers that shouldn't know it; something special-cased to make a test pass.
- write-tests/authoring §writing whole-class-inputs | ctx: python | any error (a test-defined exception type), any malformed record, any bytes.
- write-tests/authoring §observe true-either-way | ctx: python past-runs | `isinstance`, `hasattr` or a non-null field as proof of wiring (assert output, stored state, errors or recorded boundary calls instead); a fake's return value where outbound content matters (assert what it received); `secret not in output` over empty output.
- write-tests/authoring §observe real-faults | ctx: past-runs | malformed bytes, collisions, interrupted operations, real files; not an invented exception taxonomy.
- write-tests/authoring §observe realistic-fixtures | ctx: past-runs | match value types, including serialized and environment-dependent forms.
- write-tests/authoring §read-narrowly outline-first | ctx: harness=claude-code | the `LSP` tool's document symbols; a grep for definitions where no language server is installed.
