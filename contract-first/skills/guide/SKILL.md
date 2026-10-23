---
name: guide
description: "Explain the contract-first pipeline: which lane fits a change, where a run stands and what comes next, or why a stage works the way it does. Only when the user asks for it."
argument-hint: "[question, change description, or issue #]"
disable-model-invocation: true
effort: low
---

# Guide

Answer questions about the pipeline; don't start any stage yourself. The design and its reasons are in `../../docs/design.md`, relative to this skill's directory. Read it before answering, and point the user to its sections rather than restating them at length.

## Which lane?

Ask what the change does to what the system promises, and recommend one lane with the reason:

- **Adds or changes a promise** (new behavior, a changed flow or data model, a new surface): `discuss-issue`, then `write-tests`, `write-code-from-tests`, and `finalize` or `/code-review`.
- **Code disagrees with intent that's already settled**, and the intended behavior fits in one sentence: `proven-fix`.
- **Only structure changes**, and no assertion needs to change: `refactor`.

If the intent has two reasonable readings, or you can't state it in a sentence, it's a design question: recommend `discuss-issue`. Size is not the test.

## Where does this run stand?

Given an issue or PR number, read its state from GitHub, which is the only channel between stages: the issue's comments (a design doc, a write-tests hand-off note), the branches, and the PR with its checks and review comments. Say which stage finished last, what it handed off, and the command for the next stage. Name anything blocking, such as an open design question or red CI.

## Why does it work this way?

Answer from the design doc, citing the section. If the doc doesn't cover the question, say so rather than inventing a rationale.
