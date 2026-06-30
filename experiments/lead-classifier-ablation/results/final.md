# Final result — lead-classifier ablation (N=10 per arm per fixture, 80 live runs)

Date: 2026-06-30. Model: claude-sonnet-4-6. Live `claude -p` (subscription).
Arms: `current` (HEAD, classifier present) vs `proposed` (composite_kind /
co_dispatched removed from build_handoff + lead_author.md).

## Result: no measurable effect

| fixture | composite_kind exercised | current underfold | proposed underfold | current discard | proposed discard |
|---|---|---|---|---|---|
| atomic-control | atomic (inert) | 0/10 | 0/10 | 10/10 | 10/10 |
| sweep-srcip-host | sweep | 0/10 | 0/10 | 10/10 | 10/10 |
| join-cross-system | join | 0/10 | 0/10 | 10/10 | 10/10 |
| baseline-shift-two-window | baseline_shift | 0/10 | 0/10 | 10/10 | 10/10 |

Both arms discarded the coined narrow draft correctly on every one of 80 trials.
Δ underfold = 0.0pp on all fixtures. The atomic-control (where the metadata is
inert) behaves identically across arms → the harness/variant is not confounded.

## Decision: DELETE the classifier (passes the plan's "proposed wins" criterion)

Proposed wins if underfold stays within ~10pp of current and discards don't
collapse. Observed: identical (0% underfold, 100% discard) in both arms. The
`composite_kind` / `co_dispatched_with` metadata adds nothing to the lead-author's
discard/promote decision on these scenarios.

This goes beyond #457 (which proposed *refactoring* the dict round-trip): the
metadata can be **removed entirely** — delete `lead_classifier.py`, the
`build_handoff` wiring (the `entries`/`template_path_by_id` reconstruction + the
two invocation keys), and the four `lead_author.md` references. The `proposed`
worktree (`exp/lead-classifier-proposed`) already is this change, minus deleting
`lead_classifier.py` + its tests.

## Why (mechanism, not just the numbers)
The discard decision is driven by the **narrowing check** — is `executed_query`
a subset of a high-scoring `neighbors` template — which is present in BOTH arms.
`composite_kind` only ever rides the **established** template's handoff (which
defaults to *skip*), never the coined draft (a single execution → always
`atomic`). So the signal is structurally one step removed from the decision it
was meant to inform, and the neighbors/narrowing signal already suffices.

## Caveats (honest scope)
- **Zero underfolds in EITHER arm.** We measured "metadata is unnecessary"
  (the agent never underfolds here, with or without it), NOT "metadata rescues a
  failing baseline." We could not construct a borderline case where the *current*
  arm underfolds, despite hardening the coined drafts to look like new
  measurements (DATE_TRUNC bucket / suspect-user triage / burst-profile). That
  robustness is itself the finding.
- Single model (Sonnet 4.6), 4 scenarios, the sshd-auth-history capability. Not
  exhaustive — but the structural argument generalizes beyond these fixtures.
- Recommendation is to delete; if a future scenario surfaces a real underfold the
  metadata would have caught, revisit. None appeared in 40 current-arm trials.

## Reproduce
`bash run_batch.sh 10 4` (after recreating the two worktrees + applying
`variants/remove-classifier.patch`); `python analyze.py`.
