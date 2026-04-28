# Post-Mortem Pipeline

How the plugin learns from completed investigations. Distinct from `/author`, which is a human-driven knowledge editor: this is an automated pipeline that fires after the Stop event, classifies what an investigation surfaced, and proposes catalog edits as a pull request.

## Status

**Slice 1 shipped (PR #140).** Extraction, worktree setup, and orchestrator skeleton are in place. The coding-agent invocation is stubbed (`_spawn_agent` returns 1) pending decisions on model, permission scope, and output handling. Real agent dispatch lands in a follow-up.

## What runs at Stop

`hooks/scripts/stop_handler.py` composes three steps in explicit order (see `content/run-artifacts.md` for the audit/action steps):

1. `investigation_summary.main(payload)` — append the outcome row to `runs/audit.jsonl`.
2. `close_ticket_action.main(payload)` — act-mode dispatch (see `content/act-mode.md`).
3. `postmortem.leads.run.main(payload)` — post-mortem leads pipeline (this file).

The post-mortem step is gated by an in-process pre-check (`has_ad_hoc_leads`) — runs that surfaced no ad-hoc leads are skipped without spawning anything.

## Pipeline shape

For runs where the gate passes, the pipeline:

1. **Extracts ad-hoc lead invocations** from the run's `investigation.md` via `scripts/postmortem/leads/extract.py`. An `AdHocLead` record is emitted whenever a `findings:` entry has `query_details.template == "ad-hoc"` OR no `templates/{vendor}.md` exists for the lead. SCREEN-mode findings are excluded. `selection_rationale` is captured as the per-finding intent prose.
2. **Creates a per-run git worktree** off the current branch via `scripts/postmortem/worktree.py`. Mechanical `git worktree add/remove` helpers fail loud on detached HEAD, existing paths, or pre-existing branches.
3. **Spawns a coding agent** in the worktree with the prompt at `scripts/postmortem/leads/agent_prompt.md`. The agent's surface is narrow: classify each finding, edit `knowledge/common-investigation/leads/`, commit. Everything else is mechanical Python.
4. **Pushes the branch and opens a PR** via `gh`. The PR diff is the proposal — there is no `proposals.md` schema or intermediate proposal artifact. Recovery if the agent's edits are wrong is `git checkout` the post-mortem branch and inspect the diff.

## Why a PR, not a proposal file

Earlier slices of this design carried a `proposals.md` artifact and a mechanical scoring tier that ranked candidate edits before applying them. That layer was dropped: a PR review is already the trust boundary, so adding a human-readable intermediate file just doubled the review surface. Reviewing one diff is cheaper than reviewing a proposals doc plus the diff that eventually emerges from it.

## Relationship to `/author`

`/author` and the post-mortem pipeline both edit `knowledge/`, but on different timelines and with different inputs:

| Path | Trigger | Inputs | Surface |
|---|---|---|---|
| `/author` (human) | User invokes `/author <intent>` | A run dir or user-provided material | Any file under `knowledge/` or `config/signatures/` |
| Post-mortem pipeline | Stop hook on every completed run | The run's `investigation.md` + invlang companion | `knowledge/common-investigation/leads/` only (in slice 1) |

The pipeline is narrow by design — slice 1 only normalizes the ad-hoc lead pool. Future slices may extend its scope (archetype proposal, signature-context drift, lessons extraction), but each extension lands under `scripts/postmortem/{topic}/` with the same extract → worktree → agent → PR shape.

## Recovery and debugging

The pipeline's outputs are visible in the project's git history: the post-mortem branch, the open PR, and the worktree at `.claude/worktrees/postmortem-{run-id}/` (preserved for review-time inspection). If the agent's edits are wrong, the recovery path is the same as any other PR: close it, or `git checkout` the branch and inspect.

The Stop hook itself never crashes the session — failures inside the pipeline appear as warning rows in `runs/audit.jsonl` and as exit codes in the stop_handler trace.
