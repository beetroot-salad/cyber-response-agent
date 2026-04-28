# Run Artifacts

Every investigation produces a set of files that together form the complete audit trail. This document is the reference for what each file is, where it lives, who writes it, and who reads it.

## Layout

```
runs/
├── {run_id}/                  # one directory per investigation
│   ├── alert.json             # sanitized alert input — who, what, when
│   ├── meta.json              # run_id, signature_id, per-run salt
│   ├── investigation.md       # agent's narrative log (per-phase sections)
│   ├── state.json             # state machine state (phase, history, timestamps)
│   ├── report.md              # final report — structured frontmatter + body
│   └── raw_details/           # off-companion SIEM/anchor payloads, per loop
│       └── loop-{N}/{lead-id}.yaml
├── audit.jsonl                # one JSON line per completed investigation
├── tool_audit.jsonl           # one JSON line per state-changing tool call
└── tool_trace.jsonl           # one JSON line per read-only tool call
```

The runs directory path is set via `SOC_AGENT_RUNS_DIR` and is **required** — `scripts/setup_run.py` errors out if the variable is unset rather than falling back to a default. The canonical deployment uses a repo-root `runs/` directory (moved out from under `soc-agent/` in PR #68 so investigation artifacts live alongside, not inside, the plugin source tree). Inside it, every investigation gets its own UUID-named directory so artifacts can't collide.

## Per-investigation files

### `alert.json`

**Who writes:** `scripts/setup_run.py` at the start of every investigation.
**Who reads:** the main agent (CONTEXTUALIZE), CONTEXTUALIZE preload subagents (ticket-context, contextualize-prologue), screen subagent, archetype-match (REPORT), Tier 2 judge.

The input alert, passed as a JSON string argument to `/investigate` and parsed at run setup. Before being written, `setup_run.py` recursively sanitizes every string value to:

- Strip dangerous invisible unicode (zero-width spaces, bidi marks, tag characters, BOM, line separators).
- Strip ANSI escape sequences.
- Truncate any field longer than `MAX_FIELD_LEN = 4096` with a `[TRUNCATED]` marker.

This is **structural sanitization** (Layer 1 of the injection defense), not semantic defense. It protects human reviewers from hidden content and prevents invisible characters from confusing delimiter parsing. It does not stop an LLM from obeying a plain-language instruction buried in an alert field — that's what Layer 2 (the judge's salted delimiters, described in `content/validation.md#prompt-injection-defense`) and the investigation's "treat alerts as evidence" rule are for.

The alert is considered **untrusted** throughout the investigation. The agent reads it as data, not instructions.

### `meta.json`

**Who writes:** `scripts/setup_run.py`.
**Who reads:** `validate_report.py` (Tier 2 salt lookup), `tag_tool_results.py` (untrusted-data wrapping), adapter CLIs with `--run-dir` for salted output.

Three fields:

```json
{
  "run_id": "...",         // UUID
  "signature_id": "...",   // e.g. wazuh-rule-5710
  "salt": "..."            // per-run random hex, 16 chars
}
```

The `salt` is the injection defense primitive (Layer 2 — see `content/validation.md#prompt-injection-defense` for the full story). Every piece of untrusted content the plugin forwards to the Tier 2 judge gets wrapped in `<run-{salt}-{tag}>...</run-{salt}-{tag}>` delimiters. An attacker crafting a prompt-injection payload into an alert cannot know the salt at authoring time, so they cannot forge a closing delimiter to escape the wrapper.

The salt is generated per run (`secrets.token_hex(8)`) specifically so it cannot leak into training data or documentation and become forgeable — static delimiters would eventually.

**Note on CONTEXTUALIZE subagent outputs.** Earlier versions of this plugin preloaded `ticket_context.yaml` and `archetype_scan.yaml` into the run directory via a background `!command`. Both preloads are now dispatched inline by the main agent during CONTEXTUALIZE and their outputs come back directly in the tool result, not as files on disk. Ticket-context is a `Bash()` call to `scripts/tools/ticket_context.py` on the main path (with the legacy `soc-agent:ticket-context` subagent kept as a fallback). The prologue (vertices + edges from the alert) is authored by the `contextualize-prologue` subagent and written into `investigation.md`'s `prologue:` companion block. Archetype matching no longer runs at CONTEXTUALIZE — it moved to REPORT (PR #118), where the `archetype-match` subagent picks the disposition label given the final hypothesis weights, contract resolutions, and anchor confirmations.

### `investigation.md`

**Who writes:** the main agent, appending one section per phase.
**Who reads:** the agent (on later phases, to remember what it's done), the Tier 2 judge (to verify the report's conclusion matches the log).

A markdown document with one `## {PHASE}` section per phase transition. See `content/phases.md` for the per-phase templates. The sections accumulate — the agent never rewrites earlier sections. By REPORT, `investigation.md` is a complete narrative of the investigation: hypotheses formed, leads selected, observations gathered, weights assigned, decisions made.

This file is the **agent-owned log**. The structural record lives in `state.json`; the narrative lives here. The Tier 2 judge reads `investigation.md` (and only this, not `state.json`) when evaluating `INTERNAL_CONSISTENCY`, `EVIDENCE_SUFFICIENCY`, `COMPLETENESS`, and `AUTHORIZATION_CHECK`.

### `state.json`

**Who writes:** the `infer_state.py` PostToolUse hook, triggered automatically when the agent writes `## PHASE` headers to `investigation.md`.
**Who reads:** `infer_state.py` (to validate the proposed transition), `validate_report.py` (to detect screen-resolved investigations), the agent (to check its current loop count).

```json
{
  "run_id": "b5f8d2e1-...",
  "ticket_id": "ALERT-12345",
  "signature_id": "wazuh-rule-5710",
  "phase": "ANALYZE",
  "history": [
    "CONTEXTUALIZE",
    "SCREEN",
    "PREDICT",
    "GATHER",
    "ANALYZE",
    "PREDICT",
    "GATHER",
    "ANALYZE"
  ],
  "updated_at": "2026-04-11T14:32:08.401234+00:00"
}
```

The `history` array is append-only and records every phase the investigation has entered, in order. `infer_state.py` uses it to count cycles (number of `PREDICT` plus `ANALYZE` entries) against `MAX_LOOPS = 12`, and `validate_report_precheck.py` + `validate_report.py` use `SCREEN in history and PREDICT not in history` to detect screen-resolved investigations that are exempt from the REPORT self-check and that must be backed by a playbook declaring a `## Screen` section.

This file is **machine-owned**. The agent should never edit it directly — all updates go through the `infer_state.py` hook (triggered by `investigation.md` writes) so the state machine can validate the transition. Attempting to edit `state.json` directly is a way to bypass safety, and it will lose against the PostToolUse audit hook even if it succeeds momentarily.

### `report.md`

**Who writes:** the main agent at REPORT (via the report-narrative subagent).
**Who reads:** the user, downstream ticketing automation, `validate_report.py` (on write).

The final report. YAML frontmatter encodes the machine-readable decision; the markdown body explains it to a human.

Frontmatter shape (validated by `schemas/report_frontmatter.py`):

```yaml
---
ticket_id: ALERT-12345
signature_id: wazuh-rule-5710
status: resolved              # resolved | escalated
disposition: benign           # benign | true_positive | unclear
confidence: high              # high | medium | low
matched_archetype: known-scanner         # required for resolved; directory name under archetypes/
matched_ticket_id: SEC-2024-042          # optional grounding via cached precedent snapshot
trust_anchors_consulted:
  - anchor: asset-inventory
    kind: org-authority       # org-authority | telemetry-baseline
    result: confirmed         # confirmed | refuted | unavailable
    citation: "Source IP registered as vendor monitoring scanner"
leads_pursued: 3
trace: "source-reputation(scanner) -> asset-inventory(monitoring-vendor) -> benign:known-scanner"
---
```

`status=resolved` requires `matched_archetype` naming a real archetype directory AND grounding — at least one of: every `required_anchors` entry confirmed, OR `matched_ticket_id` citing a valid precedent snapshot inside the same archetype directory. Archetypes with no `required_anchors` must be grounded by `matched_ticket_id`. These rules are enforced by Tier 1 validation.

Body sections expected by convention (not structurally enforced):

- **Summary** — 2–3 sentence overview
- **Investigation Trace** — the trace line
- **Hypothesis Outcomes** — one line per hypothesis with its final state and reasoning
- **Key Evidence** — bullet list of the specific observations that mattered
- **Observations** — incidental findings worth noting but not part of the verdict (coverage gaps, anomalous configurations, data quality issues)
- **Verdict** — the explicit recommendation
- **For Analyst** *(escalated reports only)* — What We Know / What We Don't Know / Suggested Next Steps

Writing `report.md` triggers the `validate_report.py` PostToolUse hook. See `content/validation.md`.

### `raw_details/loop-{N}/{lead-id}.yaml`

**Who writes:** the `save_raw_tool_output.py` PostToolUse hook on `Bash` and `mcp__*` calls dispatched from a GATHER subagent.
**Who reads:** the `analyze` handler/subagent, preloading per-loop raw payloads when grading observations.

Per-loop directory of raw SIEM/anchor responses, written off the invlang companion so the companion stays trim. The hook keys writes by `loop` (from the active GATHER cycle) and `lead-id` so analyze can correlate raw payloads back to the `findings:` entry it merges into. This is the v2.12 "handler-authored synthesis" half of the design — subagents emit plain-YAML envelopes, the orchestrator/skill handler synthesizes the canonical `findings[]`, and the bulky raw evidence lives here instead of in `investigation.md`. The full evidence is preserved under the run; only the structured graph survives in the companion.

## Cross-run JSONL logs

Three append-only JSONL files sit at the top of the runs directory. Each is a single file accumulating one line per event across all investigations.

### `runs/audit.jsonl`

**Who writes:** `hooks/scripts/investigation_summary.py` (Stop hook), once per completed investigation.
**Contains:** one JSON object per investigation. Fields:

- **Outcome** — `run_id`, `ticket_id`, `signature_id`, `status`, `disposition`, `confidence`, `matched_archetype`, `matched_ticket_id`, `leads_pursued`.
- **Timestamps** — `start_timestamp` (from `meta.json::created_at`), `end_timestamp` (Stop hook fire time, UTC ISO 8601).
- **Token usage** — `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens` (deduped by `message.id` when the persisted session transcript is used; taken from the `result` record when stream-json is piped in).
- **Cost and models** — `total_cost_usd` (from the stream-json `result` record when present), `models` (sorted distinct list of every model name seen on assistant messages — typically one element, more if `/model` was used mid-session or a subagent ran on a different model).

This is the canonical "what did the agent decide" log. Downstream analytics (false-negative rate, mean time to disposition, resolution rate per signature, cost per run) read this file.

### `runs/tool_audit.jsonl`

**Who writes:** `hooks/scripts/audit_tool_calls.py` (PostToolUse hook), once per state-changing tool call.
**Contains:** tool name, tool input, tool output summary, run directory context, timestamp.

"State-changing" covers every tool that touches the outside world or the run directory: `Bash`, `Write`, `Edit`, `Agent` (subagent spawn), `mcp__*` (any MCP tool call). These are the calls whose history matters for an after-the-fact reconstruction of what the agent did, so they get audited.

### `runs/tool_trace.jsonl`

**Who writes:** the same hook, for read-only tools.
**Contains:** tool name, tool input, output summary, run directory context, timestamp.

"Read-only" covers `Read`, `Glob`, and `Grep` — tools that navigate the codebase without changing anything. They're separated out so `tool_audit.jsonl` stays focused on consequential actions without being drowned in navigation noise. `tool_trace.jsonl` is for debugging and performance analysis, not for safety audit.

## Why this split

- **Per-investigation directory** isolates artifacts so runs can be replayed, diffed, or archived independently. Cleaning up a bad investigation is `rm -rf runs/{run_id}`.
- **Cross-run JSONL** makes outcome analysis cheap — one `jq` pipeline over `audit.jsonl` produces disposition rates, signature breakdowns, time-to-disposition distributions.
- **Agent-owned vs machine-owned** separation (`investigation.md` vs `state.json`) lets the agent write freely in the narrative log while the state machine guards the structural record.
- **Audit vs trace split** keeps the "consequential actions" log useful without drowning it in file reads.

## Monitoring a live investigation

The runs directory is also the primary interface for **watching an investigation as it happens**. Because every artifact is a plain file that the agent updates incrementally, a second process (human, script, or dashboard) can `tail` them without coordinating with the agent.

Useful live-monitoring views:

- **`tail -f runs/{run_id}/investigation.md`** — the agent's narrative log, section by section. This is the highest-signal view of what the agent is thinking right now: which hypotheses it formed, which lead it just picked, what the observation was, how it weighed the evidence.
- **`watch cat runs/{run_id}/state.json`** — the structural state. Shows current phase, history, and loop count. Useful when you want to see "is the agent stuck looping" vs "is it advancing" without reading prose.
- **`tail -f runs/tool_audit.jsonl | jq 'select(.run_id == "{run_id}")'`** — the consequential actions, filtered to one run. Shows every Bash, Write, Edit, subagent spawn, and MCP call as it happens. Good for catching "what did the agent just try to do" in near real-time.
- **`tail -f runs/tool_trace.jsonl | jq 'select(.run_id == "{run_id}")'`** — read-only navigation. Very chatty, but useful for understanding what files and fields the agent is looking at.
- **`tail -f runs/audit.jsonl`** — one line per completed investigation. This is the cross-run "what did the agent just decide on everything it finished" feed — useful for a dashboard showing disposition rate, escalations per hour, or streaks of the same outcome.

Two properties make this work:

1. **Append-only JSONL**. Nothing rewrites earlier lines, so a `tail -f` consumer never misses events and never needs to handle truncation. Each line is a complete record.
2. **One file per concern**. `investigation.md` is human narrative. `state.json` is structural state. `tool_audit.jsonl` is consequential actions. `tool_trace.jsonl` is navigation. A monitor can subscribe to whichever view it cares about without parsing the others.

For production monitoring, the standard pattern is a sidecar process that tails `runs/audit.jsonl` for completed-investigation outcomes and `runs/tool_audit.jsonl` for per-action telemetry, fanning both into the org's observability stack. No agent-side changes are needed — the agent just writes the files.

## Reading the artifacts for debugging

When an investigation produces a surprising outcome, the standard post-hoc inspection sequence is:

1. **`report.md`** — what did the agent decide?
2. **`investigation.md`** — what was the reasoning?
3. **`state.json`** — did the agent actually run the phases it claims it did?
4. **`alert.json`** — what was the input? (Check for malformed fields, prompt-injection attempts, missing data.)
5. **`meta.json`** — run id, signature id, salt (mostly for correlating with other files).
6. **`runs/tool_audit.jsonl`** — filter by `run_id` to see the exact tool calls the agent made, in order. Useful for understanding why a subagent decided what it decided.
7. **`runs/tool_trace.jsonl`** — the read-heavy debugging log. Useful when investigating agent confusion about file layout or field mappings.

If the `validate_report.py` hook rejected a report, the error message is in the agent's transcript, not on disk — hook failure output goes to stderr and is surfaced to the agent as a tool failure, and the agent's next action is to edit the report. You can reconstruct the failure from `investigation.md` (which edits happened) and the sequence of `Write|Edit` entries in `tool_audit.jsonl`.
