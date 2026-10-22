---
name: write-tests
description: "Turn a candidate design into a committed executable contract before implementation. Write tests to expose design holes, independently review their fidelity and discrimination, and iterate through patches or dissolving design amendments. Use after discuss-issue, or to repair a contract exposed by implementation or adversarial review."
argument-hint: "[design doc path or issue #; optionally contract repair findings]"
model: opus
effort: medium
---

# Write tests

Own the **executable contract between design and code**. The design states intended behavior, models, flows, architecture, and reasons; the tests enforce its observable commitments. Coverage records are agent scaffolding, not another design for the human to approve. Tests green is evidence about what those assertions enforce, never proof of complete intent or correct code.

The working loop is **sketch → design check → dissolve → author thoroughly → independently review → patch → recheck**. Construct executable cases early: writing them is a way to discover design holes, not the last assembly step after exhaustive premise enumeration. A thin sketch finds those holes before the expensive thorough pass is written against a design that then changes. Implementation and exploit-based testing of the contract belong to the code stage; this skill prepares and repairs the contract they work against.

## 0. Keep agent work cheap

Almost all of this skill's cost is agents re-reading their own history: every step re-sends the whole context, and context grows with each file read and search result. Output is a rounding error. Spend on **fewer steps over smaller histories**, not on cheaper prose.

- **Dispatch fresh, do not resume.** A worker that has finished and sits idle loses its cache within minutes; messaging it again pays to reload its entire history. For a repair, recheck, or next round, start a new worker with a short brief: findings, owned files, current revisions. Resume only a worker that is still mid-task.
- **Bound each worker.** Give it one slice and one return. When the slice is done, or its history has grown large (on the order of 100 tool calls), it writes its progress and remaining work to the working record and hands back; the orchestrator dispatches a fresh worker for the remainder.
- **Start from the code map.** Facts about the code — where entry points, seams, fixtures and owners are — are gathered once per issue and shared through the code map (§1). Judgments are not shared: each worker derives what must hold from the design itself. Open raw files to check a map entry you rely on, or to read the lines you are changing; report a wrong or missing entry rather than silently working around it. The **whole-contract reviewer** (§4) works without the map, so one reading of the code is not shaped by it.
- **Outline before reading.** The design is the shared truth and language: read it once, whole, and do not re-read it. For existing tests and source, start from `py-outline <file-or-dir>` (`--tests` for test names and fixtures only): line ranges, signatures and first docstring lines at a tenth of the file's size. Then read only the line ranges you need. After an edit, check the diff, not the whole file. Search with limited result counts and file filters, and filter test output to failures. A result the worker will not use still costs on every later step.
- **Set model and effort on every dispatch.** Use the models this skill names for each role; never let a worker inherit the orchestrator's model. Deterministic checks need no agent.

## 1. Establish the candidate and boundaries

Read the current discuss-issue design and decisions, grounding evidence and code map, and project profile (`.claude/spec-flow.json`). Extend the code map with what contract work needs and grounding did not cover: the harness entry points, shared fixtures, and the interface of any shared test machinery once it is written. Fix map errors at the source as workers report them, so the correction happens once. A missing map is built here, before any author is dispatched.

Brief workers with the **current** design only. When a section of a superseded design or amendment still applies, fold it into the current design rather than send workers to read the history. If the profile is absent, derive the required test/harness facts from the repo or use init; do not guess commands or force unrelated setup before useful contract work. Resolve which design revision is current before authoring. If only a bare report exists, use discuss-issue; do not silently invent intended behavior. Missing headings or evidence formatting alone need not restart design: normalize useful sections and probe load-bearing gaps. If a missing factual answer could change the contract, settle it or block that part.

Use a dedicated git worktree, adopting an appropriate existing one or creating a branch from the intended base. Record its base commit. Confirm the interpreter and imports resolve into this worktree; validate affected baseline/harness behavior before interpreting failures. Keep the tests separate from implementation: **do not write or commit production skeletons, implementation, or policy-bearing substitute code**. If implementation already exists, this is contract repair; record that fact rather than claim a new independent tests-first run.

Read **references/contract.md** for the compact coverage record, checkpoints, and handoff. Initialize working state under `.spec-flow/` and exclude scratch state through the worktree's git exclude mechanism. Use stable design obligation and finding IDs. The design and executable tests are the contract; do not produce a separate formal spec or require numbered frontier files.

## 2. Sketch and check the design

Before thorough authoring, settle the design the tests will enforce. **One author (Opus at medium effort)** writes a thin executable sketch: one representative case per important promise and per main flow, through real entry points, using existing machinery. The sketch is not decomposed and does not chase variants, partitions, or discrimination; its job is to force every load-bearing choice into concrete setup and expected results, where gaps show. Follow **references/authoring.md** under "Sketch".

Then dispatch **one fresh Opus reader at high effort** for a design check, using **references/review.md** under "Design check". It receives the design, decisions, grounding evidence and sketch, not the author's discussion, and answers only: is this the right behavior, and what does the design leave unsettled or contradictory? Not the full review panel — that comes after thorough authoring.

Reconcile its findings and the author's reported gaps through §5: probe factual questions, and dissolve design defects through discuss-issue's amendment protocol before thorough authoring starts. Sketch cases carry into the thorough pass when the design they rest on survives; discard the rest.

**Skip the sketch** when the change is small and the design leaves no consequential choice open — a single obligation, a settled flow, an existing harness. Record the skip and go straight to §3. A skip does not shrink the §4 review.

## 3. Author the contract thoroughly

Use **references/authoring.md** as the author charge. One author can handle a small suite; the orchestrator may author or integrate, but cannot also supply its independent review. Give authors the design revision, applicable decisions/properties, grounding evidence, project test conventions, worktree, owned files, and the sketch cases they inherit. Use **Opus at medium effort** for the test author, including delegated author slices and contract repairs. Set model and effort explicitly when dispatching general-purpose workers; do not inherit orchestration settings. Run deterministic checks directly.

Build out from the checked design and the sketch: the important observable promises and representative flows. Write executable tests using existing machinery, then expand where concrete construction reveals missing behavior, interactions, or weak observations. Maintain a compact **contract map** linking design obligations, scenarios/surfaces, and test assertions. Test names/docstrings state the promised outcome and the design obligation they enforce, in at most two lines (see **references/authoring.md**). A mapping or a probe is not itself coverage.

Authors may probe relevant reality and report design gaps as they arise. Do not wait for a complete suite to report a foundational contradiction. Continue independent portions when useful, but do not freeze assertions downstream of an unresolved design choice. Use the design properties to resolve details; a new preference is a proposal, not an adopted requirement.

Scale by **interpretive uncertainty, behavioral coupling, and consequence of failure**, not file counts or entry-point counts. Add scenario depth and focused probes where those dimensions demand it. For work too large for one context, read **references/decomposition.md**: partition by coherent obligations and ownership, assign shared fixtures to one owner, and retain integration scenarios for spanning properties. The orchestrator dispatches workers directly; avoid nested polling coordinators. Do not invent separate survey/integrator agents for a single small file.

## 4. Independently review the contract

Dispatch a fresh **Opus reviewer at high effort**, plus **two or three independent Sonnet reviewers at high effort with distinct lenses**, using **references/review.md**. Set each reviewer's model and effort explicitly. Each reviewer receives the design, decisions, grounding evidence, tests, and contract map, but not the author's discussion or defence. Each independently derives what must hold before comparing coverage and checks both **design fidelity** (the right behavior is specified) and **discrimination** (the assertions could detect violations). When a design check ran, the design itself is settled: weight this review toward discrimination and toward fidelity of what the thorough pass added, and raise a design-level finding only with evidence the check could not have seen. This review is mandatory even for a small contract; it is independent of the later adversarial implementer.

The Opus reviewer owns the whole-contract reading; it is the only Opus seat on the panel. It does not receive the code map and reads the code itself, so map errors and blind spots have one reader they cannot reach. Lens reviewers start from the map. Lens reviewers run on **Sonnet** — an all-Opus panel multiplies cost without adding an independent reading. Start with two Sonnet lenses selected for the actual design, such as lifecycle/recovery, boundary and input behavior, compatibility, or cross-surface interactions; add a third for a distinct consequential risk. Give each lens a focused question and the relevant design, evidence and tests, without the author's defence or other reviewers' findings. Each returns concrete gaps or design tensions, not an unbounded list of hypotheticals. Consolidate all reviewer findings before patching; unread review output adds no protection. A tests-only blind reader is optional when the inferred contract is itself in doubt.

Run relevant deterministic checks directly; they need no dedicated agent. Use the project's targeted test command, collection and applicable lint/type checks. For supported Python suites, `spec-graph calls <suite-dir> [--target <module>]` and `spec-graph nullstub <suite-dir> --python <project-interpreter>` can expose missing calls and vacuity directly from the suite; these commands do not create or require a separate spec artifact. Read the results, not just exit codes: expected red, test breakage, and demand-specific assertion failure are different evidence. Detailed triage is in **references/review.md**. Record unavailable checks and their consequences.

## 5. Reconcile, patch or dissolve

Consolidate findings by cause before patching or contacting the human. Every finding has evidence/scenario, affected promise, cause, proposed resolution and consequences. Distinguish:

- **Lookup/probe:** a factual uncertainty. Investigate it; do not ask the human to perform a lookup or pick reality.
- **Contract defect:** tests omit, misstate, or fail to enforce settled behavior. Have an author repair them, preserving intent. A fresh independent reviewer rechecks the affected assertions and interactions.
- **Design defect or unresolved choice:** the product behavior, scope, data model, flow, architectural commitment, or trade-off needs to change or be settled. Propose a patch or a design change that dissolves the family of findings, using discuss-issue's amendment protocol.
- **Implementation defect on a repair run:** adequate tests and design already reject the behavior. Return the bug to the code stage; do not amend the design to accommodate it.

Test mechanics, fixtures, helper names, and ordinary local technical decisions stay with agents when settled intent determines the outcome. Missing project principles do not justify a generic questionnaire: ask only for a consequential preference that the current design cannot resolve.

For a demonstrated bug, frame the human decision as **"This is a bug; here are the trade-offs of fixing it."** Bring a consolidated recommendation about behavior, models, flows, or architecture, with costs and meaningful alternatives. Do not present a question per edge case, ask whether correctness is wanted, or reopen approved intent. A suggested dissolution is not permission to adopt a new design. Record the human's ruling accurately, including its scope.

On amendment, update the current design and decision record through discuss-issue; do not leave tests based on a private alternative. Identify impacted obligations, assertions, fixtures, census and evidence. Keep unaffected work, but refresh changed scope and invalidate reviews whose inputs changed. Reauthor and independently recheck the affected contract, including cross-slice effects, with fresh workers briefed on the change (§0). Do not restart everything or mechanically retain an old census after adding a new mechanism.

## 6. Iterate to readiness, not a round count

Set a review budget proportional to the named risks and any user limit. Start with authorship and the Opus plus two or three lensed Sonnet review panel. **Two repair rounds after the §4 review is a hard limit.** If blockers remain after the second, stop and report them as blocked/incomplete with the next action; do not dispatch a third round on your own judgment, and do not silently extend a user budget. Only the human extends it. Within that limit, repeat for material findings and consequential revisions; additional lenses or full passes need a specific remaining risk. A design amendment discovered after thorough authoring means the design check missed something: record what, so the sketch and check can improve. Repeated findings of the same class are a signal to revisit the model or test approach. Minor locally determined corrections need targeted rechecks, not another whole pipeline.

Readiness requires:

- Every in-scope promise and adopted amendment has enforcing assertions, or an explicit design-level exclusion; no unsupported coverage claim substitutes for a test.
- No known blocking contract defect, vacuous assertion presented as coverage, or unresolved consequential design choice remains.
- The independent review covers the current material revision, and its findings have evidence-backed dispositions.
- Expected failures are distinguished from broken machinery. Assertions not yet exercised are individually identified with implementation-stage verification obligations.
- The design, tests, map, evidence and handoff agree at the recorded base and revisions.

An exhausted budget with a known blocker means **blocked/incomplete**, with the exact finding and next action. Never convert a blocking defect into an implementer note and label the contract ready. Some verification genuinely needs implementation or an unavailable environment: it may be deferred only when the contract is unambiguous and the tests have no known defect, with its owner and completion condition recorded. Deferred verification is not a waiver of intended behavior.

## 7. Commit and hand off

Follow **references/contract.md**. Commit the executable contract separately before implementation; preserve an immutable tests ref for both honest and adversarial implementers. Communicate coverage, uncertainty, design amendments, and required implementation-stage checks. Do not start coding or ship a PR from this skill.

**Handoff:** give `write-code-from-tests` the committed suite and compact coverage/review record linked to the current design. State the immutable contract ref and next action. Do not generate or maintain `spec_graph_*.yaml`; requirements belong in the design and enforcing tests, not a parallel spec.
