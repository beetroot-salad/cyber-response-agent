---
name: write-tests
description: "Turn a candidate design into a committed executable contract before implementation. Write tests to expose design holes, review their fidelity, and iterate through patches or dissolving design amendments. Use after discuss-issue, or to repair a contract exposed by implementation or by the code stage's attackers."
argument-hint: "[design doc path or issue #; optionally contract repair findings]"
model: opus
effort: medium
---

# Write tests

You own the **executable contract between design and code**. The design says what should happen and why; the tests enforce its observable commitments. Green tests are evidence about what those assertions check, never proof of complete intent or correct code. The contract you hand off has been checked for fidelity, so the code stage can trust what it demands. Whether it rejects wrong code is tested at the code stage, where attackers start from the honest implementation.

The flow is **sketch and spike → design check → author thoroughly → review → repair → hand off**. Its shape follows where problems are cheapest to fix. Writing concrete cases is how design holes surface, so start early and thin. Writing code surfaces a different kind of hole, where the design does not fit the existing system, so a throwaway spike runs before any thorough tests exist. Only once the design has survived both does the expensive pass begin.

## Keep agent work cheap

Almost all of this skill's cost is agents re-sending what they have already read: every step carries the whole context, and context grows with each file read. So spend on fewer steps over smaller histories.

- **Share facts, not judgments.** Facts about the code (where entry points, seams, fixtures and owners are) are gathered once and shared through the code map. Each worker still derives from the design, on its own, what must hold. Workers open raw files to check a map entry they rely on or to read what they change, and report wrong entries so they are fixed once.
- **Read narrowly.** Read the design once, whole: it is the shared language. For tests and source, outline first (`py-outline <file-or-dir>`, `--tests` for tests and fixtures) and read only the line ranges needed. Check an edit through its diff.
- **Dispatch fresh workers with a short brief** rather than resuming an idle one, whose cached history has expired and must be paid for again. Give each worker one slice and one return; one that has grown large (roughly a hundred tool calls) records its progress and hands back.
- **Set the model on every dispatch**, as named per role below. Workers never inherit the orchestrator's model. Deterministic checks (collection, targeted test runs, lint, `spec-graph calls` and `spec-graph nullstub` for Python suites) need no agent; run them directly and read the results, not just the exit codes.

## 1. Establish the candidate

Start from the current discuss-issue design, its decisions, grounding claims and code map, and the project's CLAUDE.md files and CI config. If there is only a bare report, the design work has not happened: use discuss-issue rather than invent intended behavior. Missing formatting is not a reason to restart; a missing fact that could change the contract is a reason to settle it or block that part.

Extend the code map with what tests need and grounding did not cover: harness entry points, shared fixtures, and the interface of any shared test machinery once written. If there is no map, build it now, before any author starts. Brief workers with the current design only; fold any still-applicable part of a superseded design into it rather than send workers through the history.

Work in a dedicated worktree on a recorded base, with imports resolving into it. The contract is tests and test machinery only: **never write or commit production code, skeletons, or a helper that implements the policy under test**, because the code stage must earn green on its own. If implementation already exists, this is contract repair; record it as such. Keep working state under `.contract-first/`, outside the diff, following **references/contract.md**.

## 2. Sketch, spike and check the design

Settle the design before the tests that enforce it are written in depth.

**Sketch** — one author, **Opus at medium effort**, writes one representative case per important promise and main flow through real entry points. Its job is to force every load-bearing choice into concrete setup and expected results, where gaps show; variants and edge cases wait.

**Spike** — one implementer, **Sonnet at medium effort**, writes a throwaway implementation of the core flows in a detached worktree, runs the sketch against it, and logs every guess, workaround and departure from the design's mechanism. Its code is never committed or shown to any later worker; only its findings travel. This catches what past runs found only at code review: two owners of one fact, mechanisms that collide with existing constraints, shortcuts the design invites.

**Design check** — one fresh reader, **Opus at high effort**, reads the design, sketch, spike diff and log, without the author's or implementer's reasoning, and asks: is this the right behavior, and where is the design unsettled, contradictory, or a poor fit for the code it lands in? A spike finding counts only when it names the design choice it conflicts with.

Resolve what it finds (§5) before thorough authoring. Mechanism changes it accepts are written into the design so the implementer does not rediscover them. Sketch cases carry forward where their design survived.

Skip sketch and spike for a small change whose design leaves nothing consequential open; skip only the spike when the change touches no existing owner, flow or shared mechanism. Record why. A skip never shrinks §4.

Detailed charges: **references/authoring.md** (Sketch, Spike) and **references/review.md** (Design check). These three are never split across workers.

## 3. Author the contract thoroughly

Authors run on **Sonnet at medium effort**, including slices and later repairs: the design is settled by now, so this pass expands and corrects rather than interprets. The orchestrator may author or integrate, but never also supplies the review. Follow **references/authoring.md**; for work too large for one context, **references/decomposition.md**.

Decide the cases from the design first, then survey the existing suite, fold the cases into it, and write last (**references/authoring.md**). New behavior belongs in the suite that already tests its neighbours, not in a parallel file per issue. Build toward what makes the contract trustworthy: real observations at real boundaries, variants and interactions where the design's properties call for them, positive controls beside negatives. Depth follows interpretive uncertainty, coupling and consequence of failure, not file counts. The case table becomes the compact **contract map**, from design obligations to the tests that enforce them; a map entry or a probe is not coverage. Docstrings state the promised outcome and its obligation in at most two lines.

Report design gaps as they appear rather than at the end, and don't build assertions on top of an unresolved choice. A new preference is a proposal, not a requirement.

## 4. Review the contract

Commit the candidate suite as a **candidate ref**. One fresh whole-contract reviewer, **Opus at high effort** (**references/review.md**), owns **fidelity**: does the suite demand the right behavior, nothing invented, nothing narrowed? It sees neither the author's reasoning nor the code map, so one reading of the code is free of the map's blind spots. Mandatory even for a small contract.

**Discrimination**, whether the suite rejects wrong code, is shown by running, not reading, and is tested in write-code-from-tests §3. There, lensed attackers start from the honest implementation and try to keep the suite green with deliberately wrong variants. Attacking here would mean each attacker first building working code that the code stage builds anyway. The holes they find come back to §5 as contract repairs.

## 5. Reconcile, repair or dissolve

Group findings by cause before acting; one cause usually explains several. Then route by what kind of problem it is:

- **A factual question:** probe it. The human does not choose what the code does.
- **A contract defect** (tests omit, misstate or fail to enforce settled behavior): a fresh author repairs it, preserving intent. Recheck with fresh workers: the fidelity reviewer reads changed assertions. On a repair from the code stage, the repaired test must also fail against the exploit that exposed it, and the affected attacker rechecks.
- **A design defect or open choice:** propose the change that dissolves the whole family, through discuss-issue's amendment protocol. A proposal is not adopted until the human rules on it.
- **An implementation defect, on a repair run:** return it to the code stage; don't bend the design around it.

Test mechanics and local technical choices stay with agents when settled intent decides them. Bring the human only consequential choices, consolidated: **"This is a bug; here are the trade-offs of fixing it,"** with a recommendation and real alternatives. Never a question per edge case, never "do you want this correct", never reopening approved intent. Record rulings with their scope. After an amendment, repair what it touched and invalidate the reviews whose inputs changed; keep the rest.

## 6. Readiness

**Two repair rounds after §4 is a hard limit.** If blockers remain, stop and report them as blocked with the next action; only the human extends the budget. Within the limit, spend in proportion to the named risks. A design amendment found after thorough authoring means the design check missed something: record what, so the earlier steps improve. The same class of finding recurring means the test approach, not the tests, needs revisiting.

The contract is ready when:

- every in-scope promise and adopted amendment has enforcing assertions or an explicit design-level exclusion;
- no known blocking defect, vacuous assertion counted as coverage, or unresolved consequential choice remains;
- the fidelity review covers the current revision and its findings are dispositioned; on a repair run, so do the rechecks of the exploits that prompted it;
- expected failures are told apart from broken machinery, and assertions that cannot run until implementation exists are named with who verifies them and how;
- design, tests, maps and handoff agree at the recorded revisions.

Never turn a known blocker into an implementer note and call the contract ready. Verification that genuinely needs real code may be deferred only for an unambiguous contract with no known defect; deferral is not a waiver.

## 7. Commit and hand off

Commit the contract on its own, before any implementation, as an immutable ref (**references/contract.md**). Hand `write-code-from-tests` that ref, the coverage and review record, the code map, the current design revision, and the checks it owes. Requirements live in the design and the tests, not in a parallel spec. Do not start coding or open a PR from this skill.
