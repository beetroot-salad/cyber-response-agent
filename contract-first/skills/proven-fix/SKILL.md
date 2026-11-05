---
name: proven-fix
description: "Fix a bug where the code disagrees with settled intent, or make a small behavior change whose intent the human states in one sentence, and prove the guarding test can fail: record the intent, sweep for every place that decides the same rule, write the test red first, make the smallest fix, mutate the lines it touched, then have a fresh agent review the diff cold. Use when the human routes a fix or small change here; a design question hands back to discuss-issue."
argument-hint: "[issue # or bug description]"
model: sonnet
effort: medium
---

# Proven fix

Either the code disagrees with intent that is already settled, or the human wants a small behavior change and states the intended behavior in one sentence. The change is usually the easy part. The point is a guarding test that actually discriminates: one that fails without the change and catches its likely regressions.

Read the project's CLAUDE.md files for how tests run here and the traps that make a local run lie, and the CI config for the checks CI runs; where they disagree, CI wins.

**Stay inside the lane.** The change stays inside one owner and one surface, with no lifecycle, and its intent has one reasonable reading. Anything wider is a design question: stop and hand it back for `/contract-first:discuss-issue`, saying why. The Cache lists what has crossed that line before.

## 1. Record the intent and sweep

Write the one-sentence intent where a later reader finds it, the issue or the PR body, as the decision this change rests on. For a bug, cite where the intent was settled.

Then find every other place that decides the same rule, using `symbol-refs` for a resolved census when the rule lives in a symbol. Each one gets the same fix, with its own guarding case; merging the copies into one owner is design work, so if that is what the change needs, hand back. Don't leave a second copy deciding the old way.

## 2. Red first

Write the test before the change, in the existing test file that covers this behavior, and run it on the unchanged tree. Quote the failure: the assertion and the actual value.

Take expected values from the stated intent, never from the code under test. An expectation copied from the code passes whatever the code does.

A test that passes before the change is the finding, not a formality. Either it doesn't reach the defect (go back to the input) or it asserts something that already held. Say which, and stop.

## 3. Change

Make the smallest change that turns the test green, at every site the sweep found. Run the touched test files, the tests that cover the changed code, the relevant e2e replay, and CI's lint and type checks. Leave the full suite to CI.

Never edit an existing test to make the change pass. If one contradicts it, dispatch one fresh reader with the test, its history and the one-sentence intended behavior, not your reasoning. It rules the test incidental only if nothing decided what the test pins and nothing relies on it; mixed evidence is not incidental. If so, it makes the change and your report lists it. Otherwise stop and say what the test pins and why the change disagrees: that is an intent question.

## 4. Mutate the deciding lines

From `git diff -U0`, take the lines that decide something: conditions, boundaries, returned values. Hand-write a few mutants across them, each a plausible wrong version of one deciding line. Run only the tests that reach each line. A surviving mutant names a line nothing pins: add the test if it's cheap, otherwise report it.

Then read each added or edited test for shapes that pass without checking anything.

## 5. Fresh review

Mutants only reach the lines the change touched. Dispatch one fresh agent to review the diff cold, without your reasoning, for what they can't reach: the cases and places the change should have decided and didn't. Fix what the stated intent decides. A finding that needs a new decision hands back.

## Report

Where the intent is recorded; the sweep's sites and how each is covered; the step-2 failure, quoted; surviving mutants or `none survived over N mutants on M lines`; any can't-fail shape; any existing test ruled incidental, with the evidence; the review's findings and what became of each; check results.

## Cache

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: <tags> | <application>`. Each applies a rule above to the context its tags name. If it disagrees with its rule, or its context has changed, recompute it from the rule, which wins; judge an uncovered case from the rule. Project-specific entries use the same format in the project's `.claude/contract-first-cache.md`: grep it for this skill's name.

- proven-fix §opening hand-back | ctx: past-runs | the change crosses a process or service boundary; involves shutdown, signals, threads or lifecycle; touches a rule with more than one owner that it can't cover; has two reasonable readings; or adds a new verdict, refusal or model-visible surface.
- proven-fix §2 copied-expectation | ctx: past-runs | a test that copied its field list from the code it checked.
- proven-fix §4 mutants | ctx: past-runs | up to five: flip a comparison, negate a condition, delete a guard, move a boundary, return the other branch.
- proven-fix §4 cant-fail-shapes | ctx: python | each has shipped green here: `parametrize` over an empty collection (reported as skipped, reads as coverage); an assertion whose search surface excludes its own subject; a disjunction the common case satisfies (`result is None or …`); one sentinel meaning two things; a structural claim checked by substring search, which a comment can satisfy.
- proven-fix §5 fresh-review | ctx: harness=claude-code | a fresh agent running `/code-review high` on the diff.
- proven-fix §5 what-mutants-miss | ctx: past-runs | the same rule decided at a sibling site (#1378 → #1396 → a third); the mirror case across a boundary (#1398 → #1404 → proxy side); a case nobody handled (stopping after the budget).
