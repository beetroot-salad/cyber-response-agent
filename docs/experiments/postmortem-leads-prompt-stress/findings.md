# Post-mortem leads agent-prompt stress test — findings

Ran `claude -p --permission-mode acceptEdits` (Sonnet) against 3 real
runs from `/workspace/runs/` with ad-hoc findings, in fresh git
worktrees. Per-run rendered prompt + stdout / stderr / commit / diff
are in `outputs/`.

## Summary

| run_id | leads | outcome | commits | files_changed | elapsed | scope |
|---|---:|---|---:|---:|---:|---|
| ac307d29 | 3 | COMMITTED | 1 | 5 | 530.7s | clean |
| 81ae27f2 | 2 | COMMITTED | 1 | 2 | 460.1s | clean |
| ed5d7c88 | 1 | COMMITTED | 1 | 3 | **374.8s** | **`_PROMPT.txt` leaked** |

All 3 produced a single commit at rc=0. Wall-time scales sub-linearly
with `leads` count — the model warms quickly across leads in one
prompt invocation.

## What worked

- **Classification quality is high.** The agent distinguished
  `source-reputation` (what is the entity?) from
  `approved-monitoring-sources` / `authorization-anchor-consultation`
  (is the activity sanctioned?) and refused to conflate
  classification with sanction. Picked appropriate
  `data_tags` / `baseline` defaults (`data_tags: []` and
  `baseline: not-applicable` for meta-leads).
- **Cross-linking discipline.** New leads cite their orthogonal
  catalog peers in the body (`actor-attribution` cross-references
  `process-lineage`, `authentication-history`, `network-analysis`,
  `approved-monitoring-sources`). Matches the leads/ convention.
- **Vendor-template grounding.** The agent's `templates/{vendor}.md`
  files include concrete CLI invocations grounded in
  `environment/systems/{vendor}/SKILL.md` rather than fabricated
  query strings.
- **Pushback on PREDICT errors.** Run 1: the agent flagged that the
  orchestrator's `template_missing` classification on
  `approved-monitoring-sources` was wrong (the lead simply did not
  exist). It re-classified as NOVEL. Useful signal that the
  classification metadata isn't load-bearing — the agent verifies
  against the catalog itself.

## What broke

### Stage scope discipline (run 3)

The prompt explicitly says:

> Stage only catalog files — never `git add -A` in this worktree.
> Stray repo state must not hitchhike into the post-mortem PR.

Run 3 nevertheless committed `_PROMPT.txt` (the rendered prompt the
stress runner had written into the worktree as scratch). The agent
likely ran `git add -A` despite the instruction and skipped the
`git status` verification step. **The prompt's halt-on-non-leads
check is not enforceable agent-side.** The reviewer's "risky" comment
on this exact line proved correct in 1 of 3 runs.

**Fix landed in this PR**: the orchestrator now does a post-commit
scope check (`_committed_paths` + `_out_of_scope` against
`soc-agent/knowledge/common-investigation/leads/`) and refuses to
push if any committed file falls outside the catalog prefix. A
`failed` marker captures the out-of-scope file list. Test
`test_out_of_scope_commit_fails_loud` reproduces the failure mode.
Stress runner also moved `_PROMPT.txt` *out* of the worktree
(written as a sibling under `outputs/`) so future stress runs don't
even tempt the agent.

This is the right layering: the prompt expresses intent, the
orchestrator enforces invariants. Don't trust the agent to gate on
its own `git status`.

## Wall-time

| leads | elapsed | s/lead |
|---:|---:|---:|
| 1 | 374.8 | 374.8 |
| 2 | 460.1 | 230.0 |
| 3 | 530.7 | 176.9 |

Roughly 6–9 minutes per run. The fixed cost (catalog scan, prompt
parse, planning) dominates over per-lead work, so batching findings
into one agent invocation per run remains the right call.

## What this validates

- The prompt produces useful, on-pattern catalog edits across
  diverse ad-hoc findings.
- The frontmatter + classification rules + commit format are
  followed.
- Sonnet is the right model tier; Haiku would likely struggle on the
  near-duplicate vs. novel distinction and the cross-link discipline.
- The `claude -p --permission-mode acceptEdits` invocation pattern
  (with a project-local `.claude/settings.local.json` allowlist)
  works under root in this devcontainer.

## What this does NOT validate

- Cost / token consumption. Not measured.
- Behavior on findings that should be DUPLICATE (no run in the
  sample produced a clear duplicate of an existing lead — the
  catalog is small and the findings happened to be novel /
  near-duplicate). Cover this in the next stress sweep, ideally with
  a fixture that re-runs against the post-stress catalog.
- Behavior when the agent SHOULD halt (truly ambiguous findings).
  All 3 stress runs landed a commit. Need a hand-crafted negative
  fixture to validate the halt path.
