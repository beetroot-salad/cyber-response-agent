---
name: proven-fix
description: "Fix a bug where the code disagrees with settled intent, and prove the guarding test can fail: write it red first, make the smallest fix, then mutate the lines the fix touched. Use when the human routes a bug fix here; a design question hands back to discuss-issue."
argument-hint: "[issue # or bug description]"
model: sonnet
effort: medium
---

# Proven fix

The code disagrees with intent that is already settled, so no test covers the case. The fix is usually the easy part. The point is a guarding test that actually discriminates: one that fails without the fix and catches its likely regressions.

Read the project's CLAUDE.md files for how tests run here and the traps that make a local run lie, and the CI config for the checks CI runs; where they disagree, CI wins. The intended behavior must fit in a sentence. If the work turns up a design question rather than a defect — a new verdict, refusal or model-visible surface, or two reasonable readings of the intent — stop and hand it back for `/contract-first:discuss-issue`. A decision made here has nowhere to be recorded.

## 1. Red first

Write the test before the fix, in the existing test file that covers this behavior, and run it on the unfixed tree. Quote the failure: the assertion and the actual value.

A test that passes before the fix is the finding, not a formality. Either it doesn't reach the defect (go back to the input) or it asserts something that already held. Say which, and stop.

## 2. Fix

Make the smallest change that turns the test green. Run the touched test files, the tests that cover the changed code, the relevant e2e replay, and CI's lint and type checks. Leave the full suite to CI.

Never edit an existing test to make the fix pass. If one contradicts the fix, stop and say what it pins and why the fix disagrees: that is an intent question.

## 3. Mutate the deciding lines

From the fix's diff, take the lines that decide something. Hand-write a few mutants across them, each the smallest change that would make the line decide differently. Run only the tests that reach each line. A surviving mutant names a line nothing pins: add the test if it's cheap, otherwise report it.

Then read each added or edited test for a way it could pass without checking anything: an assertion that would hold whatever the code did, or a case that never reaches what it claims to test.

If you notice another place that decides the same rule, report it. Don't fix it here: collapsing a duplicate is design work.

## Report

The step-1 failure, quoted; surviving mutants or `none survived over N mutants on M lines`; any can't-fail shape; any second copy noticed; check results.

## Cache

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: <tags> | <application>`. Each applies a rule above to the context its tags name. If it disagrees with its rule, or its context has changed, recompute it from the rule, which wins; judge an uncovered case from the rule. Project-specific entries use the same format in the project's `.claude/contract-first-cache.md`: grep it for this skill's name.

- proven-fix §3 deciding-lines | ctx: git | from `git diff -U0`: conditions, boundaries, returned values.
- proven-fix §3 mutants | ctx: past-runs | up to five: flip a comparison, negate a condition, delete a guard, move a boundary, return the other branch.
- proven-fix §3 tests-that-check-nothing | ctx: python past-runs | `parametrize` over an empty collection (reported as skipped, reads as coverage); an assertion whose search surface excludes its own subject; a disjunction the common case satisfies (`result is None or …`); one sentinel meaning two things; a structural claim checked by substring search, which a comment can satisfy.
