---
name: refactor
description: "Restructure code without changing behavior, with the existing suite as the guard: tests stay unchanged except for mechanical follow-through. Add a lint when the change removes a pattern that could creep back. Use when the human routes a refactor here; any behavior change hands back."
argument-hint: "[issue # or description]"
model: sonnet
effort: medium
---

# Refactor

Nothing the system promises changes, so the existing suite already says what must hold. Your job is to change the structure and keep that guard honest.

Read the project's CLAUDE.md files for how tests run here and the traps that make a local run lie, and the CI config for the checks CI runs; where they disagree, CI wins.

## Tests stay as they are

Edit tests only mechanically: imports, names and paths that follow the moved code. Keep the same cases with the same assertions. If an assertion needs to change, behavior is changing, and this is no longer a refactor: stop and say what the test pins and why the change disagrees. The human decides whether it becomes a bug fix (`proven-fix`) or a design change (`discuss-issue`).

A test that only reached its subject through the old structure may need a new seam. Move the test with the code, keep its assertions, and say so in the report.

## Check

Run the tests that cover the changed code, the relevant e2e replay, and CI's lint and type checks, before and after the change. The same tests should pass both times. Leave the full suite to CI. If coverage of the changed code is thin, say so; a refactor over untested code changes behavior unseen.

## Keep the pattern from coming back

When the refactor removes something a later change could reintroduce, add a rule to the project's lints. Examples: a second owner of one value, a banned import, a duplicated helper, a path read the wrong way. Follow the existing lint conventions: a new rule starts with an empty baseline, and its test shows it fires on the old pattern and stays quiet on the new code. Skip it when nothing plausible would reintroduce the pattern, and say why.

## Report

What moved and why; tests touched (mechanical only) and any moved to a new seam; the before and after test results; the lint added, or why none; thin coverage you noticed.
