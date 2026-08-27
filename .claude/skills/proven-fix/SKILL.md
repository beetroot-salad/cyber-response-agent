---
name: proven-fix
description: "Make a small fix and prove the test guarding it can actually fail: write the test red first, fix, then mutate only the lines the fix touched. Use for bug fixes and small settled changes, where spec-flow's committed spec graph and adversary worktree are too heavy."
---

# Proven fix

Three steps, one agent. The fix is the easy part; the point is that the test guarding it discriminates.

Read `.claude/spec-flow.json` for `gate.test`, `gate.checks` and the project's traps. If it is missing, run `/spec-flow:init`.

## When NOT to use this

The intent must fit in a sentence and no design may be in question. Anything that changes what the system promises — a new verdict, a new refusal, a surface the model sees — goes to `/spec-flow:discuss-issue`: this skill has nowhere to record a decision, and a decision made here is a decision nobody can find later.

Kick back the moment step 1 turns up a design question rather than a defect.

## 1. Red first, and watch it fail

Write the test before the fix and run it on the unfixed tree. Quote the failure — the assertion and the actual value, not "it failed".

**A test that passes before the fix is the finding, not a formality.** Two causes:

- It does not reach the defect. You have not reproduced the bug; go back to the input.
- It asserts something that already held. It is a guard that can never fail, and adding it grows the suite without strengthening it.

Neither is fixable by carrying on. Say which one you hit and stop.

Some changes have no natural failing test — a rename, a dead-code deletion, a docstring correction. Say so and skip to step 2 rather than inventing one.

## 2. Fix

The smallest change that turns the test green. Then `gate.test`, then `gate.checks`.

**Never edit an existing test to make the change pass.** If one contradicts the fix, stop and say what it pins and why the fix disagrees — that is a spec question wearing a red build.

## 3. Mutate the lines you changed

`git diff -U0` names them. For each meaningful line, hand-write a mutant, run only the tests that reach it, and record whether any failed. Five that pay for themselves:

- flip a comparison (`<` ↔ `<=`, `==` ↔ `!=`)
- negate a condition
- delete a guard clause and let the body run
- move a boundary (`0` ↔ `1`, one member in or out of a frozen set)
- return the other branch's value

A **surviving mutant** — nothing failed — names a line no test pins. Add the test if it is cheap; otherwise report what is unpinned.

Scope is the whole discipline. Mutating the tree is something nobody runs twice; mutating a fix's own lines takes minutes.

## 4. Read the new tests for shapes that cannot fail

A surviving mutant finds an untested line. It cannot find a test that runs, asserts, and pins nothing — that one is read, not measured. Check every test the change adds or edits against these five, each of which has shipped green in this repo:

- **`@pytest.mark.parametrize` over an empty collection.** Pytest reports SKIPPED; the body and its docstring survive and read as coverage.
- **An assertion whose search surface excludes its own subject** — `assert x not in MESSAGE.replace("<the text under review>", "")`.
- **A disjunction the common case satisfies** — `assert result is None or <the real check>`, where every refusal returns `None`.
- **One sentinel for two meanings** — a helper returning `None` for both "we refused it" and "not applicable", so a regression in the second reads as the first.
- **A structural claim made by substring search** — `assert "NAME" in path.read_text()`, satisfied by a comment that merely mentions it. Parse the file instead.

## 5. If the changed rule has a second copy

Another module deciding the same thing, a constant restated, a hand-written model of a stdlib call. Both copies pass their own tests; the drift between them is what nobody tests, and it is invisible until an input straddles the boundary they disagree about.

Prefer deleting one. Where the duplicate is a **value**, give it one owner and assert in one line that the others read it — that check never goes stale. Where it is a **procedure** you cannot collapse, add a differential over a swept input domain, and assert on the artifact both copies produce, not on the outcome: comparing allow/deny is blind to a rule that changed the value it authorised.

## Report

- the step-1 failure, quoted
- surviving mutants, or `none survived over N mutants on M lines`
- any vacuity shape from step 4
- gate results
