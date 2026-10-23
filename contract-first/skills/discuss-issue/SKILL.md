---
name: discuss-issue
description: "Turn an issue or feature description into a grounded, reviewed design: product behavior, scope, data models, flows, architecture, and their trade-offs. Use before writing contract tests, or when tests or code expose a consequential design defect. Start with the problem and open questions so the human can form an independent view."
argument-hint: "[issue number, description, or design amendment to discuss]"
effort: high
---

# Discuss issue

Own the **design**: what the feature adds, its boundaries, its data models and flows, and the architecture chosen to implement it. Tests will be its executable contract; coverage records are downstream agent scaffolding. A design is ready when it supports the promised behavior and guides consequential decisions, not when it enumerates every imaginable case.

## 1. Open with the problem, not the solution

Load the issue and comments (`gh issue view <n> --comments`; retry an empty read with `--json title,body,comments`), or use the supplied conversation, path, or text. Keep this initial read bounded to understanding the problem; full grounding and design work come later. Read relevant code only as needed to avoid misrepresenting it. Distinguish settled decisions from proposals; an issue's suggested fix is a candidate, while the human's explicit requirements and chosen constraints remain binding.

**The first message to the human contains only:**

- What the problem is, who experiences it, and why it matters, in terms someone unfamiliar with the issue can understand.
- The open questions, framed around intended behavior, scope, data, flows, or architectural constraints. Label uncertainty rather than inventing facts.

**No proposed design, solution options, recommendations, implementation details, or process narration in this opening.** Let the human develop a cold reading and respond before presenting design work. Read-only investigation may continue while waiting; silence is not a decision. Do not require an answer to every opening question: some will be answered by grounding or dissolved by a later design choice.

On a returned design defect, open with the bug and what remains unsettled; do not repeat the whole original discussion. When the user specifies a narrow question, keep the discussion to it rather than forcing a full design exercise.

## 2. Ground and draft

Read the project profile (`.claude/contract-first.json`) if present, its principles pointer, relevant code and tests, and neighboring issues or PRs the design depends on. A missing profile need not block discussion. Verify assumptions that could change the design: current behavior, ownership, data boundaries, callers and execution contexts, dependency behavior, and constraints. Explore outwards from the affected flow; do not turn this into a repository-wide audit.

Use executed probes for behavior claims, reads for structure, and reproducible searches for a claimed census. A failed or unavailable probe leaves uncertainty, not a confirmed claim. Record grounding evidence with the revision it describes, separately from the human-facing design; **references/design-doc.md** defines the inherited `claims:` format and the **code map** that records where the relevant code lives, so later stages do not each re-read it. Correct the model of the problem plainly, without turning the discussion into a list of inaccuracies in the issue.

Draft the design using **references/design-doc.md**. Settle purpose, scope, models, flows, and architectural direction enough to attempt contract tests. Specify useful **design properties with reasons**: rules that resolve families of cases. Inherit project principles and the human's decisions. Propose new properties explicitly; do not present inferred preferences as adopted principles. Ask for a missing preference when it changes a consequential choice, rather than blocking all work on a generic values questionnaire.

## 3. Review, then patch or dissolve

For a design introducing or changing behavior, a data model, a flow, or architecture, obtain an **independent subagent review before presenting the proposed design for decision**. Give the reviewer the problem statement, current candidate design, grounding evidence, relevant constraints and repo access, but not the discussion transcript or the author's defence. The reviewer may read the design's rationale, but must check its premises and consider alternatives independently. It must not edit artifacts or post externally. A narrow explanation, already-resolved issue, or mechanical correction with no design choice can skip this; record the reason in the handoff.

Start with one reviewer. Add a targeted lens only when an identified uncertainty or coupling warrants it: data lifecycle/recovery, trust boundaries, compatibility, performance, or another relevant concern. Split independent regions when useful. Do not require a fixed panel, invent concerns to fill lenses, or dispatch trivial mechanical checks solely to create more agents.

The review checks:

- **Grounding:** do load-bearing facts hold, and are unknowns visible?
- **Coherence:** do requirements, models, ownership, and flows agree, including credible failures and interactions?
- **Decision sufficiency:** is a consequential choice being left to the test author or implementer? Can the promised outcomes be observed?
- **Scope:** does every mechanism serve intended behavior or a justified constraint? Are exclusions explicit without narrowing a broad promise accidentally?
- **Generality:** do the design properties answer concrete cases consistently, or hide unresolved decisions?
- **Elegance:** can one concept replace several exceptions? Does the model prevent invalid states? Do flows follow ownership? Would a proposed abstraction earn its complexity within this scope?

A finding names **evidence or a concrete scenario → affected promise/property → underlying cause → recommended resolution and trade-offs**. Separate demonstrated defects, unresolved choices, and speculative concerns. Edge cases are useful when they expose a consequential choice or challenge a promised property; reject unbounded hypothetical completeness as a review goal.

Reconcile findings before showing them to the human. Confirm defects and distinguish deliberate exclusions. Group findings by cause; ask which model, ownership rule, flow, or principle would dissolve the group. Compare that change with local patches, including migration, operational cost, and new complexity. A local bug can deserve a local fix; dissolution is not an excuse to expand scope.

Apply corrections already determined by the agreed design. Bring unresolved consequential choices to §4. Re-probe changed factual assumptions and review the consequences of material revisions, using a fresh reader when independence matters. Recheck affected portions rather than restarting the whole analysis. Do not discard unaffected grounding, but refresh a census when new mechanisms, callers, or base changes invalidate its scope.

**Bound the loop.** Start with an authoring pass and an independent review; repeat when the revision introduces consequential interactions or review still finds material defects. Move forward when remaining details follow from adopted properties or are explicitly outside scope. Spend additional passes on named consequential risks, not on speculative completeness or a prescribed number of rounds. If repeated rounds produce the same class of findings, revisit the model rather than keep patching. A budget exhausted with a blocking design uncertainty means an incomplete design and a concrete next choice, not a successful handoff.

## 4. Put design choices to the human

Present the revised candidate design in plain language, followed by the few choices that remain. Human judgment belongs on product behavior, scope, data models, flows, architecture, and consequential trade-offs. Agents own local technical details that follow from these choices.

Lead with a recommendation and consequences, grouped by root cause. For a demonstrated defect, say **"This is a bug; here are the trade-offs of fixing it"** rather than ask whether correct behavior is wanted. Do not reopen settled intent. An architectural change that removes several failures deserves a consolidated explanation, not a question per symptom.

Each decision states the problem, recommended change, the cases it resolves, its costs and what it forecloses, and meaningful alternatives. A technical explanation earns its place when it changes that decision. Do not dump reviewer reports, claims ledgers, or menus of implementation choices. Explicitly distinguish an agent recommendation from a human decision; route changes outside approved intent back here. Approval of a design does not authorize implementation or unrelated external actions.

## 5. Preserve the design and hand off

The conversation is where discussion happens; the issue or supplied design document is where its state lives. For work heading to implementation, preserve one current **intent+design document** in the format in **references/design-doc.md**, with supporting grounding evidence. Use the issue thread when working on an issue and the task authorizes posting; otherwise leave a local document or draft. Use body files for multiline CLI posts.

Won't-fix and already-resolved outcomes need a short disposition, not a manufactured design. A narrow discussion can end with its answer and decisions. Do not automatically invoke tests or implementation.

For a defect returned from tests or code, first check whether the approved design already determines the fix. If the implementation violates an adequate design, hand back the implementation defect and preserve the design. Amend only when its commitments or mechanisms actually change; revise the existing design rather than create a competing one. State what changed, why, which decisions remain valid, and which downstream contracts or flows need rechecking. Mark the previous revision superseded and make the latest version easy to find. Preserve grounded facts still valid at the recorded base; update affected evidence and review material consequences.

The handoff names the current design revision, settled decisions, any unresolved or deferred verification, and the next action. Readiness means **ready to attempt the executable contract**, not a claim that later test construction or code review cannot discover a design hole.
