---
name: write-tests
description: "Turn a candidate design into a committed executable contract before implementation. Write tests to expose design holes, independently review their fidelity and discrimination, and iterate through patches or dissolving design amendments. Use after discuss-issue, or to repair a contract exposed by implementation or adversarial review."
argument-hint: "[design doc path or issue #; optionally contract repair findings]"
model: opus
effort: medium
---

# Write tests

Own the **executable contract between design and code**. The design states intended behavior, models, flows, architecture, and reasons; the tests enforce its observable commitments. Coverage records are agent scaffolding, not another design for the human to approve. Tests green is evidence about what those assertions enforce, never proof of complete intent or correct code.

The working loop is **author → independently review → patch or dissolve → recheck**. Construct executable cases early: writing them is a way to discover design holes, not the last assembly step after exhaustive premise enumeration. Implementation and exploit-based testing of the contract belong to the code stage; this skill prepares and repairs the contract they work against.

## 1. Establish the candidate and boundaries

Read the current discuss-issue design and decisions, grounding evidence, and project profile (`.claude/spec-flow.json`). If the profile is absent, derive the required test/harness facts from the repo or use init; do not guess commands or force unrelated setup before useful contract work. Resolve which design revision is current before authoring. If only a bare report exists, use discuss-issue; do not silently invent intended behavior. Missing headings or evidence formatting alone need not restart design: normalize useful sections and probe load-bearing gaps. If a missing factual answer could change the contract, settle it or block that part.

Use a dedicated git worktree, adopting an appropriate existing one or creating a branch from the intended base. Record its base commit. Confirm the interpreter and imports resolve into this worktree; validate affected baseline/harness behavior before interpreting failures. Keep the tests separate from implementation: **do not write or commit production skeletons, implementation, or policy-bearing substitute code**. If implementation already exists, this is contract repair; record that fact rather than claim a new independent tests-first run.

Read **references/contract.md** for the compact coverage record, checkpoints, and handoff. Initialize working state under `.spec-flow/` and exclude scratch state through the worktree's git exclude mechanism. Use stable design obligation and finding IDs. The design and executable tests are the contract; do not produce a separate formal spec or require numbered frontier files.

## 2. Author the contract

Use **references/authoring.md** as the author charge. One author can handle a small suite; the orchestrator may author or integrate, but cannot also supply its independent review. Give authors the design revision, applicable decisions/properties, grounding evidence, project test conventions, worktree, and owned files. Use **Opus at medium effort** for the test author, including delegated author slices and contract repairs. Set model and effort explicitly when dispatching general-purpose workers; do not inherit orchestration settings. Run deterministic checks directly.

Start from the important observable promises and representative flows. Write executable tests using existing machinery, then expand where concrete construction reveals missing behavior, interactions, or weak observations. Maintain a compact **contract map** linking design obligations, scenarios/surfaces, and test assertions. Test names/docstrings state the promised outcome and the design obligation they enforce. A mapping or a probe is not itself coverage.

Authors may probe relevant reality and report design gaps as they arise. Do not wait for a complete suite to report a foundational contradiction. Continue independent portions when useful, but do not freeze assertions downstream of an unresolved design choice. Use the design properties to resolve details; a new preference is a proposal, not an adopted requirement.

Scale by **interpretive uncertainty, behavioral coupling, and consequence of failure**, not file counts or entry-point counts. Add scenario depth and focused probes where those dimensions demand it. For work too large for one context, read **references/decomposition.md**: partition by coherent obligations and ownership, assign shared fixtures to one owner, and retain integration scenarios for spanning properties. The orchestrator dispatches workers directly; avoid nested polling coordinators. Do not invent separate survey/integrator agents for a single small file.

## 3. Independently review the contract

Dispatch a fresh **Opus reviewer at high effort**, plus **two or three independent Sonnet reviewers at high effort with distinct lenses**, using **references/review.md**. Set each reviewer's model and effort explicitly. Each reviewer receives the design, decisions, grounding evidence, tests, and contract map, but not the author's discussion or defence. Each independently derives what must hold before comparing coverage and checks both **design fidelity** (the right behavior is specified) and **discrimination** (the assertions could detect violations). This review is mandatory even for a small contract; it is independent of the later adversarial implementer.

The Opus reviewer owns the whole-contract reading. Start with two Sonnet lenses selected for the actual design, such as lifecycle/recovery, boundary and input behavior, compatibility, or cross-surface interactions; add a third for a distinct consequential risk. Give each lens a focused question and the relevant design, evidence and tests, without the author's defence or other reviewers' findings. Each returns concrete gaps or design tensions, not an unbounded list of hypotheticals. Consolidate all reviewer findings before patching; unread review output adds no protection. A tests-only blind reader is optional when the inferred contract is itself in doubt.

Run relevant deterministic checks directly; they need no dedicated agent. Use the project's targeted test command, collection and applicable lint/type checks. For supported Python suites, `spec-graph calls <suite-dir> [--target <module>]` and `spec-graph nullstub <suite-dir> --python <project-interpreter>` can expose missing calls and vacuity directly from the suite; these commands do not create or require a separate spec artifact. Read the results, not just exit codes: expected red, test breakage, and demand-specific assertion failure are different evidence. Detailed triage is in **references/review.md**. Record unavailable checks and their consequences.

## 4. Reconcile, patch or dissolve

Consolidate findings by cause before patching or contacting the human. Every finding has evidence/scenario, affected promise, cause, proposed resolution and consequences. Distinguish:

- **Lookup/probe:** a factual uncertainty. Investigate it; do not ask the human to perform a lookup or pick reality.
- **Contract defect:** tests omit, misstate, or fail to enforce settled behavior. Have an author repair them, preserving intent. The independent reviewer rechecks the affected assertions and interactions.
- **Design defect or unresolved choice:** the product behavior, scope, data model, flow, architectural commitment, or trade-off needs to change or be settled. Propose a patch or a design change that dissolves the family of findings, using discuss-issue's amendment protocol.
- **Implementation defect on a repair run:** adequate tests and design already reject the behavior. Return the bug to the code stage; do not amend the design to accommodate it.

Test mechanics, fixtures, helper names, and ordinary local technical decisions stay with agents when settled intent determines the outcome. Missing project principles do not justify a generic questionnaire: ask only for a consequential preference that the current design cannot resolve.

For a demonstrated bug, frame the human decision as **"This is a bug; here are the trade-offs of fixing it."** Bring a consolidated recommendation about behavior, models, flows, or architecture, with costs and meaningful alternatives. Do not present a question per edge case, ask whether correctness is wanted, or reopen approved intent. A suggested dissolution is not permission to adopt a new design. Record the human's ruling accurately, including its scope.

On amendment, update the current design and decision record through discuss-issue; do not leave tests based on a private alternative. Identify impacted obligations, assertions, fixtures, census and evidence. Keep unaffected work, but refresh changed scope and invalidate reviews whose inputs changed. Reauthor and independently recheck the affected contract, including cross-slice effects. Do not restart everything or mechanically retain an old census after adding a new mechanism.

## 5. Iterate to readiness, not a round count

Set a review budget proportional to the named risks and any user limit. Start with authorship and the Opus plus two or three lensed Sonnet review panel. Stop and report the blocker if two repair rounds make no material progress; do not silently extend a user budget. Repeat for material findings and consequential revisions; additional lenses or full passes need a specific remaining risk. Repeated findings of the same class are a signal to revisit the model or test approach. Minor locally determined corrections need targeted rechecks, not another whole pipeline.

Readiness requires:

- Every in-scope promise and adopted amendment has enforcing assertions, or an explicit design-level exclusion; no unsupported coverage claim substitutes for a test.
- No known blocking contract defect, vacuous assertion presented as coverage, or unresolved consequential design choice remains.
- The independent review covers the current material revision, and its findings have evidence-backed dispositions.
- Expected failures are distinguished from broken machinery. Assertions not yet exercised are individually identified with implementation-stage verification obligations.
- The design, tests, map, evidence and handoff agree at the recorded base and revisions.

An exhausted budget with a known blocker means **blocked/incomplete**, with the exact finding and next action. Never convert a blocking defect into an implementer note and label the contract ready. Some verification genuinely needs implementation or an unavailable environment: it may be deferred only when the contract is unambiguous and the tests have no known defect, with its owner and completion condition recorded. Deferred verification is not a waiver of intended behavior.

## 6. Commit and hand off

Follow **references/contract.md**. Commit the executable contract separately before implementation; preserve an immutable tests ref for both honest and adversarial implementers. Communicate coverage, uncertainty, design amendments, and required implementation-stage checks. Do not start coding or ship a PR from this skill.

**Handoff:** give `write-code-from-tests` the committed suite and compact coverage/review record linked to the current design. State the immutable contract ref and next action. Do not generate or maintain `spec_graph_*.yaml`; requirements belong in the design and enforcing tests, not a parallel spec.
