# Working record, commit and hand-off

Keep the smallest record that lets a cold agent pick up the work: what the contract covers, what was decided, what is uncertain, and what comes next.

## Working record

Scratch state lives under `.contract-first/`, outside the committed diff. It holds:

- the identities everything depends on: design revision, base commit, profile, current test ref, and the skill revision used;
- the **contract map**: design obligations, their scenarios and entry points, the enforcing tests by node ID, each row's fold outcome (already enforced, extended, new, or conflict updated), and verification status. A Markdown table is enough, for example `O-retry | same operation after uncertain result | import API | tests/test_import.py::test_retry_preserves_identity (extended): returned ID + row count | awaiting implementation`. A row is a claim to inspect, not proof. Because folded tests sit in many files, the map's node IDs, not a file list, define the contract;
- findings and decisions by stable ID, with cause, disposition, evidence, the human's ruling where one was needed, and what they affect. Nothing gets silently dropped;
- the claims inherited from discuss-issue plus new load-bearing observations, in its format. An ID does not make an unprobed fact settled;
- which reviews ran against which revision, what verification is still owed and by whom, and the next action.

## Resume and invalidation

Mark the boundaries a resume needs: sketch and spike checked (or skipped, and why; their findings, never the spike's code), candidate authored, reviewed, repaired, ready or blocked. A worker that hands back mid-slice writes its progress here so a fresh worker can continue without its history.

Before reusing anything, compare its recorded identities with the current inputs. A changed design, shared fixture, base, profile or environment invalidates the work that depended on it, and nothing else. Missing or stale review evidence means not reviewed; timestamps and "complete" labels prove nothing. Migrate an old-format run by carrying over its validated evidence and decisions, not its scaffolding.

## Commit

The deliverable is the executable suite with its test-only fixtures and helpers. Never commit production code, stubs, scratch state, or a helper that substitutes for the policy under test.

Commit it on its own before any implementation, and record the base and the immutable ref in the hand-off. The implementer starts from that ref, and any later repair is measured against it.

Repairs after implementation exists keep that independence honest. Branch from the last contract-only ref, apply only reviewed test changes, keep the original base, and record the new ref beside the old. The implementation branch takes in only those test changes. An exploit recheck applies the attacker's patch to the implementation with the repaired tests in place. Disclose when a repair author saw the implementation, since a new commit can't undo that. Never rewrite history to fake independence, and report missing contract-only history rather than hide it by moving the base.

## Durable record and hand-off

Scratch paths don't survive into a cold session, so publish a compact coverage and review record through the issue or the supplied design location when authorized. It holds the mapping, finding dispositions, evidence, design identity and outstanding checks, not raw transcripts. If pushing is part of the task, confirm the remote has the contract ref before posting a ready-to-implement hand-off.

State **ready**, **blocked**, or **repair required**, with:

- design revision, branch, base, immutable contract ref, and the contract's test node IDs (with the files that hold them);
- where the durable record and the code map live;
- design amendments and consequential decisions. Chosen mechanisms bind the implementer even where tests can't observe them;
- the checks actually run and their results, expected reds, and every assertion or environment check owed by the code stage, with its owner;
- open blockers and the precise next action. A ready verdict carries no known blocker.

Name `write-code-from-tests` as the next stage.
