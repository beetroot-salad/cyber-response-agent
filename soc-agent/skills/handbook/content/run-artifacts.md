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
│   └── report.md              # final report — structured frontmatter + body
├── audit.jsonl                # one JSON line per completed investigation
├── tool_audit.jsonl           # one JSON line per state-changing tool call
└── tool_trace.jsonl           # one JSON line per read-only tool call
```

The runs directory path is configurable via `SOC_AGENT_RUNS_DIR`, defaulting to `soc-agent/runs/` under the plugin root. Inside it, every investigation gets its own UUID-named directory so artifacts can't collide.

## Per-investigation files

### `alert.json`

**Who writes:** `scripts/setup_run.py` at the start of every investigation.
**Who reads:** the main agent (CONTEXTUALIZE), ticket-context and screen subagents, Tier 2 judge.

The input alert, passed as a JSON string argument to `/investigate` and parsed at run setup. Before being written, `setup_run.py` recursively sanitizes every string value to:

- Strip dangerous invisible unicode (zero-width spaces, bidi marks, tag characters, BOM, line separators).
- Strip ANSI escape sequences.
- Truncate any field longer than `MAX_FIELD_LEN = 4096` with a `[TRUNCATED]` marker.

This is **structural sanitization**, not semantic defense. It protects human reviewers from hidden content and prevents invisible characters from confusing delimiter parsing. It does not stop an LLM from obeying a plain-language instruction buried in an alert field — that's what the judge's salted delimiters and the investigation's "treat alerts as evidence" rule are for.

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

The `salt` is the injection defense primitive. Every piece of untrusted content the plugin reads or forwards gets wrapped in `<run-{salt}-{tag}>...</run-{salt}-{tag}>` delimiters. An attacker crafting a prompt-injection payload into an alert cannot know the salt at authoring time, so they cannot forge a closing delimiter to escape the wrapper.

The salt is generated per run (`secrets.token_hex(8)`) specifically so it cannot leak into training data or documentation and become forgeable — static delimiters would eventually.

### `investigation.md`

**Who writes:** the main agent, appending one section per phase.
**Who reads:** the agent (on later phases, to remember what it's done), the Tier 2 judge (to verify the report's conclusion matches the log).

A markdown document with one `## {PHASE}` section per phase transition. See `content/phases.md` for the per-phase templates. The sections accumulate — the agent never rewrites earlier sections. By CONCLUDE, `investigation.md` is a complete narrative of the investigation: hypotheses formed, leads selected, observations gathered, weights assigned, decisions made.

This file is the **agent-owned log**. The structural record lives in `state.json`; the narrative lives here. The Tier 2 judge reads `investigation.md` (and only this, not `state.json`) when evaluating `INTERNAL_CONSISTENCY`, `EVIDENCE_SUFFICIENCY`, `COMPLETENESS`, and `ADVERSARIAL_CHECK`.

### `state.json`

**Who writes:** `hooks/scripts/write_state.py`, called by the agent at every phase transition.
**Who reads:** `write_state.py` (to validate the proposed transition), `validate_report.py` (to detect screen-resolved investigations), the agent (to check its current loop count).

```json
{
  "run_id": "b5f8d2e1-...",
  "ticket_id": "ALERT-12345",
  "signature_id": "wazuh-rule-5710",
  "phase": "ANALYZE",
  "history": [
    "CONTEXTUALIZE",
    "SCREEN",
    "HYPOTHESIZE",
    "GATHER",
    "ANALYZE",
    "HYPOTHESIZE",
    "GATHER",
    "ANALYZE"
  ],
  "updated_at": "2026-04-11T14:32:08.401234+00:00"
}
```

The `history` array is append-only and records every phase the investigation has entered, in order. `write_state.py` uses it to count loops (number of `HYPOTHESIZE` entries) against `MAX_LOOPS = 7`, and `validate_report.py` uses `SCREEN in history and HYPOTHESIZE not in history` to detect screen-resolved investigations that are exempt from the minimum-leads-by-severity check.

This file is **machine-owned**. The agent should never edit it directly — all updates go through `write_state.py` so the state machine can validate the transition. Attempting to edit `state.json` directly is a way to bypass safety, and it will lose against the PostToolUse audit hook even if it succeeds momentarily.

### `report.md`

**Who writes:** the main agent at CONCLUDE.
**Who reads:** the user, downstream ticketing automation, `validate_report.py` (on write).

The final report. YAML frontmatter encodes the machine-readable decision; the markdown body explains it to a human.

Frontmatter shape (validated by `schemas/report_frontmatter.py`):

```yaml
---
ticket_id: ALERT-12345
signature_id: wazuh-rule-5710
status: resolved              # resolved | escalated
disposition: benign           # benign | false_positive | true_positive | inconclusive
confidence: high              # high | medium | low
matched_archetype: known-scanner.md  # optional; file under archetypes/
matched_precedent: null       # or precedent filename under precedents/
trust_anchors_consulted:
  - anchor: asset-inventory
    kind: org-authority       # org-authority | telemetry-baseline
    result: confirmed         # confirmed | refuted | unavailable
    citation: "Source IP registered as vendor monitoring scanner"
leads_pursued: 3
trace: "source-reputation(scanner) -> asset-inventory(monitoring-vendor) -> benign:?known-scanner"
---
```

`status=resolved` requires either `matched_archetype` or `matched_precedent`. If `matched_archetype` is set, every anchor listed in its `required_anchors` frontmatter must appear here with `result: confirmed`. These rules are enforced by Tier 1 validation.

Body sections expected by convention (not structurally enforced):

- **Summary** — 2–3 sentence overview
- **Investigation Trace** — the trace line
- **Hypothesis Outcomes** — one line per hypothesis with its final state and reasoning
- **Key Evidence** — bullet list of the specific observations that mattered
- **Observations** — incidental findings worth noting but not part of the verdict (coverage gaps, anomalous configurations, data quality issues)
- **Verdict** — the explicit recommendation
- **For Analyst** *(escalated reports only)* — What We Know / What We Don't Know / Suggested Next Steps

Writing `report.md` triggers the `validate_report.py` PostToolUse hook. See `content/validation.md`.

## Cross-run JSONL logs

Three append-only JSONL files sit at the top of the runs directory. Each is a single file accumulating one line per event across all investigations.

### `runs/audit.jsonl`

**Who writes:** `hooks/scripts/investigation_summary.py` (Stop hook), once per completed investigation.
**Contains:** one JSON object per investigation summarizing outcome — ticket id, signature id, status, disposition, confidence, leads pursued, trace, timestamps.

This is the canonical "what did the agent decide" log. Downstream analytics (false-negative rate, mean time to disposition, resolution rate per signature) read this file.

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

## Reading the artifacts for debugging

When an investigation produces a surprising outcome, the standard inspection sequence is:

1. **`report.md`** — what did the agent decide?
2. **`investigation.md`** — what was the reasoning?
3. **`state.json`** — did the agent actually run the phases it claims it did?
4. **`alert.json`** — what was the input? (Check for malformed fields, prompt-injection attempts, missing data.)
5. **`meta.json`** — run id, signature id, salt (mostly for correlating with other files).
6. **`runs/tool_audit.jsonl`** — filter by `run_id` to see the exact tool calls the agent made, in order. Useful for understanding why a subagent decided what it decided.
7. **`runs/tool_trace.jsonl`** — the read-heavy debugging log. Useful when investigating agent confusion about file layout or field mappings.

If the `validate_report.py` hook rejected a report, the error message is in the agent's transcript, not on disk — hook failure output goes to stderr and is surfaced to the agent as a tool failure, and the agent's next action is to edit the report. You can reconstruct the failure from `investigation.md` (which edits happened) and the sequence of `Write|Edit` entries in `tool_audit.jsonl`.
