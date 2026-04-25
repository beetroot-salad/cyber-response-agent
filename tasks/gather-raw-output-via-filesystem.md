---
title: GATHER raw output via filesystem path, not envelope passthrough
status: doing
groups: gather, analyze, hooks
---

## Why

Today the gather subagent pastes the SIEM CLI's verbatim stdout into the `raw.siem_response` field of its output YAML. ANALYZE then reads that field when its grading needs to inspect raw discriminator fields the characterization compressed past (proc.name vs proc.exepath impersonation, fd.lport / fd.sip direction, srcport distribution duplicates).

This is wasteful. A typical Wazuh CLI response is 50–200 KB of JSON; with composite dispatch (2–3 leads per loop), the raw payload dominates the gather envelope, eats Sonnet/Haiku tokens on every gather output, and forces a truncation discipline (`### Raw Sample Events` first 3 dicts + tail truncation marker) that the agent has to enforce manually. The recently-tightened verbatim-passthrough rules in `agents/gather.md` and `agents/gather-composite.md` exist *because* this discipline keeps slipping — agents under turn pressure compress the raw to prose and lose the discriminator fields.

The cheaper design: a PostToolUse hook saves the raw tool result to disk for matched tools, and the gather handler mechanically merges those paths into the in-memory envelope after parsing. The agent never authors the path — it's invisible to the agent and robust to compression.

## Design

### PostToolUse hook saves raw to disk (Bash + MCP, uniform)

A new hook `hooks/scripts/save_raw_tool_output.py` registered on `PostToolUse` matches an allowlist of tools and writes their full result body to:

```
{run_dir}/raw_query_outputs/{loop_n}-{nonce}.{ext}
```

- `loop_n` derived from current investigation state (`state.json` → count of `GATHER` entries in `history`).
- `nonce` is a 4-char base36 random id, generated per-call. ~1.6M space, collision-prob negligible across the hundreds of calls in a run; stateless, no shared counter to plumb.
- `ext` is vendor-appropriate (`.jsonl` / `.json`), inferred from allowlist entry.

The hook returns `additionalContext` with the path so the agent *can* re-read if it wants, but doesn't have to. Stdout / MCP result body still flows back to the model normally — no behavior change at gather call time. This is uniform across **Bash adapters and MCP tools**: `additionalContext` is supported on both (verified against Claude Code hook docs); we deliberately avoid `updatedMCPToolOutput` since it's MCP-only.

**Allowlist** (configurable, lives next to the hook at `save_raw_tool_output.allowlist.yaml`):
- Bash command patterns: `wazuh_cli.py`, `host_query.py`, `*_ticket_cli.py` (any future adapter is added by entry, not by code).
- MCP tool-name patterns: `mcp__*` per server config.

Anything outside the allowlist is ignored — we don't save every Bash stdout indiscriminately.

Each save also drops a sidecar manifest entry at `{run_dir}/raw_query_outputs/manifest.jsonl` with `{ts, session_id, tool_use_id, agent_id, agent_type, tool_name, schema, loop_n, path, bytes, command_summary}` — used for downstream merge.

### Mechanical envelope merge in the gather handler

**Course correction from the original plan**: tracing the gather flow showed `parse_gather_envelope` reads subagent stdout *directly* (via `_invoke_gather`), not anything emitted by `extract_subagent_yaml.py`'s `additionalContext`. So the manifest-merge logic lives in the gather handler, not in the YAML extractor hook.

A new helper `scripts/handlers/_raw_manifest.py` exposes three pure functions:
- `consume_new_entries(run_dir)` — cursor-based JSONL reader. Sidecar `_consumed_offset` tracks byte position; each call returns entries appended since last call and advances the cursor. Sequential subagent dispatch in the main loop means "new entries since last consume" precisely scopes to the most recent gather invocation.
- `correlate_to_leads(entries, leads)` — groups manifest entries by lead id, matching `command_summary` substring against each lead's `query.query`. Unmatched entries fall through to the first lead (covers consultations with no query, leads whose query string isn't a clean substring).
- `attach_paths_to_envelope(raw_by_lead, grouped)` — additively attaches `paths: [{path, schema, bytes, ts}, ...]` per lead, preserving any existing keys.

`gather.py:_dispatch_single` and `_dispatch_composite` call `_merge_manifest_into_envelope(ctx, envelope)` after envelope construction. Errors silenced — manifest enrichment never blocks gather.

### ANALYZE reads paths when grading needs it

The analyze prompt's by-role deviation rubric and the existing discriminator-field reads (proc.exepath, fd.lport, etc.) get rewired: when characterization is ambiguous, `Read({path})` directly from one of the listed paths. The Pitfalls bullet about "characterization compressed past load-bearing fields" stays — but the recovery path is now a file read, not a YAML field read.

Most ANALYZE invocations won't need to read raw at all — characterization handles the common case. The files are the recovery surface.

## Surface changes

| Surface | Change |
|---|---|
| `hooks/scripts/save_raw_tool_output.py` | New PostToolUse hook. Allowlist-matched Bash + MCP tools → write body to `{run_dir}/raw_query_outputs/{loop_n}-{nonce}.{ext}`, drop manifest entry, return `additionalContext` with path. |
| `hooks/scripts/save_raw_tool_output.allowlist.yaml` | New: declares `{kind, pattern, schema, ext}` entries for adapters. |
| `scripts/handlers/_raw_manifest.py` | New helper module: `consume_new_entries`, `correlate_to_leads`, `attach_paths_to_envelope`. |
| `scripts/handlers/gather.py` | Calls `_merge_manifest_into_envelope` after envelope parse in single + composite dispatch. |
| `.claude-plugin/plugin.json` | Register `save_raw_tool_output.py` on `PostToolUse` (`Bash\|mcp__.*` matcher) after `tag_tool_results.py`. |
| `scripts/handlers/_output_parser.py` (Phase C) | When `raw_by_lead[lead]["paths"]` present, read file contents and use as `siem_response` source. Falls back to agent-authored if paths absent. |
| `scripts/handlers/gather.py:_write_raw_details` (Phase C) | Use path-sourced contents to write `raw_details/loop-N/{lead-id}.yaml` so analyze prompt is unchanged. |
| `agents/gather.md` (Phase D) | Drop `raw.siem_response` field and the verbatim-passthrough discipline. No mention of `raw.paths` either — it's mechanically injected. |
| `agents/gather-composite.md` (Phase D) | Same. |
| `agents/analyze.md` | **No change.** `<raw_details>` block + `_load_raw_details` keep working — the per-lead `raw_details/loop-N/{lead-id}.yaml` shape is preserved by the parser change. |
| `scripts/cleanup_runs.py` | **No change.** `raw_query_outputs/` rides the existing run-dir TTL. |
| `tests/test_save_raw_tool_output.py` | New: hook unit + integration tests (34 cases). |
| `tests/test_raw_manifest.py` | New: helper module tests (19 cases — cursor, correlation, attach). |
| `tests/test_e2e_*.py` (Phase C/D) | Adjust assertions that read `raw.siem_response` — read the path's contents instead. |

## Migration

This supersedes the recently-committed verbatim-passthrough discipline (commits on `predict-prompt-redesign` strengthening `raw.siem_response`). Those commits get reverted in Phase D — their work is subsumed by the hook-saved file being verbatim by construction.

In-flight runs / replay scenarios: existing run dirs that don't have `raw_query_outputs/` directories will be missing the raw files. Replay is best-effort — characterization in the persisted envelope is enough for most ANALYZE work; raw recovery only matters when grading needs it. Document this as a one-time break for runs prior to migration.

## Implementation phases

Each phase is independently shippable and revertible.

### ✅ Phase A — Hook + allowlist + tests, no agent integration

**Status: complete.** Files saved on every matched call; manifest accumulates; downstream consumers untouched. Zero risk — additive.

Landed:
- `hooks/scripts/save_raw_tool_output.py` (~190 LoC)
- `hooks/scripts/save_raw_tool_output.allowlist.yaml`
- `tests/test_save_raw_tool_output.py` (34 tests, all passing)
- `.claude-plugin/plugin.json` registers hook after `tag_tool_results.py` on `Bash|mcp__.*`

### ✅ Phase B — Manifest merge into envelope (additive)

**Status: complete.** `raw_by_lead[lead]["paths"]` populated alongside agent-authored `siem_response`; no downstream consumer reads paths yet.

Landed:
- `scripts/handlers/_raw_manifest.py` (cursor-based consume + correlate + attach)
- `scripts/handlers/gather.py` integrates `_merge_manifest_into_envelope` in single + composite dispatch
- `tests/test_raw_manifest.py` (19 tests, all passing)
- Full unit suite: 1402/1402 passing

### Phase C — Parser/handler reads paths preferentially

`_output_parser._extract_gather_leads` (or a wrapper) reads `paths[]` first; if any path resolves, use its file contents as `siem_response`; else fall back to agent-authored. `_write_raw_details` continues to write `raw_details/loop-N/{lead-id}.yaml` — but now sourced from hook-saved files, so the analyze prompt and `_load_raw_details` are unchanged.

### Phase D — Agent prompts drop `raw.siem_response`

`agents/gather.md` and `agents/gather-composite.md` remove the field and the verbatim-passthrough discipline. At this point the parser must use paths (no fallback exercised). Verify on `gather_baseline_test` fixture before flipping.

### Phase E — MCP matcher

Added once the first MCP-backed adapter ships; allowlist-only entry, no code changes needed.

## Open questions

1. **Composite lead correlation accuracy.** Phase B uses substring match on `command_summary` against `query.query`, with first-lead fallback. Robust to: leads with unique queries, single-lead gather, consultations. Fragile to: leads sharing query substrings, queries substituted in non-obvious ways. Verify on a real composite-dispatch run; if false attribution becomes visible in analyze, switch to per-lead checkpoint timestamps as the bracket signal.

2. **`agent_id` correlation feasibility.** Manifest carries `agent_id` and `agent_type`, but Phase B doesn't use them — cursor-based consume sidesteps the question. Live runs of Phase A will populate manifests we can inspect to confirm whether `agent_id` is set on subagent-internal Bash calls (useful if cursor approach becomes insufficient under future parallelism).

3. **Schema declaration.** `raw.schema` is recorded per-entry from the allowlist. Auto-inferred from tool name pattern. Per-template overrides could come later if needed.

4. **Recovery path raw.** `_recover_single` / `_recover_composite` rebuild envelopes from checkpoints. Phase B doesn't apply manifest data on recovery branches; those branches use agent-authored siem_response from checkpoint files. Phase C/D should decide whether checkpoint replay also reads from saved files (probably yes — checkpoints could carry `paths[]` references).

## Related

- Original deviations / structured-baseline work: `tasks/baseline-counterfactual-prediction-flow.md` (PR #129). The verbatim-passthrough commits there are the immediate predecessor of this task.
- Hook architecture conventions: see `CLAUDE.md` "Hook Architecture" section. New hook follows the same `hooks/scripts/*.py` + `plugin.json` registration convention.
- **Discarded alternative — adapter `--raw-out` flag.** Considered adding a `--raw-out` convention to `schemas/adapter_contract.py` and per-adapter flags (wazuh_cli, host_query, ticket_cli). Rejected because (a) doesn't cover MCP tools, (b) requires per-adapter test sprawl, (c) the agent still has to author the path in the envelope, which is exactly the discipline-failure mode this task exists to remove. The hook-based design covers Bash and MCP uniformly with one allowlist-driven script.
- **Discarded alternative — extract_subagent_yaml.py YAML mutation.** Original plan was to extend `extract_subagent_yaml.py` to inject `raw.paths[]` into the gather envelope before returning it as `additionalContext`. Rejected during implementation because the gather parser reads subagent stdout directly via `_invoke_gather`, never seeing the hook's `additionalContext`. Manifest merge moved to `gather.py` post-parse; `extract_subagent_yaml.py` stays untouched.
