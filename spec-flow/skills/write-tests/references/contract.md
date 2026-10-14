# Contract map, working state, and handoff

Read when starting, resuming, or handing off contract work. Use the smallest record that lets a cold agent reconstruct coverage, decisions, uncertainty and next actions. No new schema checker or fixed frontier phase map is required.

## Working record

Keep scratch material under `.spec-flow/` outside the committed diff. Record:

- Design source and revision/content hash, repository base commit, relevant dependency/environment identity, profile revision/hash, current test diff/ref, and the skill/plugin revision used.
- Named design obligations, with scenarios and entry surfaces, enforcing test names/assertion groups, relevant evidence, and verification status. A Markdown table is enough; many-to-many mappings are allowed.
- Findings and decisions by stable ID: cause, disposition, rationale/evidence, human ruling where required, and affected obligations/tests. Do not silently discard a probe result, exclusion, or adopted amendment.
- Completed reviews with their input revisions and scope, unresolved verification and its owner/completion condition, and the next action.

An example map row is `O-retry | same operation after uncertain result | import API | test_retry_preserves_identity: returned ID + row count | awaiting real implementation`. This records a coverage claim to inspect, not proof that the test enforces it.

Record inherited `claims:` entries and new load-bearing observations with their source/base and instruments, using discuss-issue's format. Unprobed facts are not settled because they have IDs. Do not build a separate ledger of every possible interpretation or reconcile bookkeeping counts across reports.

## Resume and invalidation

Persist meaningful boundaries: candidate authored, reviewed, amended/repaired, and ready or blocked. A resumed worker compares recorded identities with current inputs before reusing work. Missing/stale review evidence means not yet reviewed. A changed design, shared fixture, target/base, profile or relevant environment triggers an impact check; invalidate affected tests/evidence/review and cross-boundary consequences, keeping unaffected facts.

Mtimes or a `complete` label alone do not establish freshness. For an old numbered run, migrate the relevant validated evidence and decisions into this compact record, explicitly invalidating affected work. Do not regenerate historical scaffolding or confuse its completion labels with current semantic readiness.

## Deliverable and commit

The primary deliverable is the executable suite, including test-only fixtures/helpers. Do not commit production implementations, production stubs, scratch working state, or a test helper that substitutes the policy under test.

Commit it independently before implementation. Record the base and immutable tests commit/ref in the durable handoff; both honest and adversarial implementers must start from that same contract. If contract repairs occur after implementation, make separate test changes and identify them honestly as a revision; seeing implementation cannot be undone by a new commit. Never rewrite history to fabricate independence. Keep a separate contract-only repair ref for the adversary, as described below.

Publish or link a compact coverage/review record through the issue or supplied durable design/document location when authorized. Scratch paths alone cannot carry decisions or verification into a cold session. A durable record contains the mapping, findings dispositions, evidence, design identity and outstanding checks; it need not include raw reviewer transcripts. Use structured posting arguments or a body file for multiline CLI text.

`write-code-from-tests` accepts tests/test machinery and declared coverage metadata. Keep the durable record in the issue handoff or a supplied document location; it need not be committed with the tests. If publication/push is part of the task, verify the remote contains the contract ref before posting a ready-to-implement baton; otherwise identify the local ref and publication as the next action.

For repairs after implementation exists, branch from the last contract-only ref, apply only reviewed test/metadata changes, and retain the original base. Record the revised immutable ref and its relationship to the original. The honest code worker incorporates only those contract changes into its implementation worktree; the adversary forks the repaired contract ref, without honest source changes. A separate tests commit on the implementation branch alone is not an isolated adversarial starting point. Missing contract-only history must be reported, not hidden by changing the base.

## Handoff

State **ready**, **blocked/incomplete**, or **contract repair required**, together with:

- Current design source/revision, branch, base, immutable contract ref and suite paths.
- Durable coverage/review record location.
- Design amendments and consequential decisions; implementation constraints and chosen mechanisms remain binding even when tests cannot fully observe them.
- Actual checks and their results, expected reds, unexercised assertions and environmental gaps, each required later check and its code-stage owner/completion condition.
- Open blockers, if any, and the precise next action. No known blocker accompanies a ready verdict.

The code stage owns exploit-based attacks and implementation-stage verification. Name `write-code-from-tests` as the next implementer. The old `write-code-from-spec` entry delegates to that same workflow and preserves existing tests-first refs on historical resumes.
