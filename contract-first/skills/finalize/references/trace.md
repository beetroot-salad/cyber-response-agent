# The tracer's charge

One shipped-green finding in, one artifact-proven attribution out. Find where the defense should have held — in the record, not in a plausible story. You read everything the dispatching reviewer must not (the design's rationale, the handoff notes, the transcripts); return the diagnosis, never the argument — quote the line that proves the attribution, not the reasoning around it.

Dispatch hands you: the finding (file:line, class, the evidence the review produced), the PR and issue numbers, and the immutable test-contract ref.

## The trail, most durable first

- The committed tests at the contract ref and shipped revision — assertions, fixtures, and contract repairs. Trace the actual enforcing assertion, not just the test name.
- The durable design and coverage/review record, usually linked from the issue thread — obligations mapped to tests, findings and dispositions, human decisions, verification gaps and their owners, and the adversary's verdict if posted.
- The contract and implementation branch history — what the contract pinned, what changed after, and whether required verification completed before shipping.
- Surviving `.contract-first/` working records, including those of older pipeline versions, which are historical evidence, not required artifacts.
- Session transcripts, where the thread links them.

## The verdict

Answer one question — *where should the defense have held?* — with exactly one class, each provable by a specific artifact:

- **never scoped** — no obligation in the design doc covers the class → discuss-issue's miss.
- **scoped, never demanded** — the design obligation exists; no test enforces it. Check the coverage/review record and actual suite: was it surfaced and dropped, mapped to a nonexistent assertion, or never considered? Cite the evidence → write-tests' coverage or reconciliation.
- **demanded, non-discriminating** — a test intended to enforce the obligation passes on the buggy code; the shipped bug is itself the proof — cite the assertion and mapped obligation → write-tests' authoring or intent review.
- **surfaced, resolved away** — the fork reached the human in the design/decision record (or a historical resolution record) and they chose this reading or waived the obligation → a decision that played out, not a miss; report it as such.
- **flagged, then shipped** — the adversary, the gate, or a prior review surfaced it and the record shows it accepted or left unresolved → a known hole; cite the record.
- **outside the run** — pre-existing code the diff never touched → out of this pass's jurisdiction.

Where the trail is gone — worktree pruned, transcript unlinked — say **evidence unavailable** for that hop and mark the attribution *provisional*; a plausible reconstruction is exactly the failure mode you exist to prevent.

Return inline, per finding: `{class, stage attributed, citations (artifact + line), proven | provisional, deck-eligible, lever candidate (one line)}`. **Deck-eligible** means the class is *scoped-never-demanded* or *demanded-non-discriminating* — intent was stated and the suite greened anyway, so the exploit shape belongs in the attack deck; include the entry text, phrased as a generic replay that transfers to other contracts, never only this bug's specifics.

## Cache

One entry per line: `<skill>[/<file>] §<section> <rule> | ctx: <tags> | <application>`. Each applies a rule above to the context its tags name. If it disagrees with its rule, or its context has changed, recompute it from the rule, which wins; judge an uncovered case from the rule. Project-specific entries use the same format in the project's `.claude/contract-first-cache.md`: grep it for this skill's name.

- finalize/trace §the-trail issue-thread | ctx: github | `gh issue view <n> --comments`.
- finalize/trace §the-verdict replay-phrasing | ctx: past-runs | "assert shape, not substance, on serialization demands".
