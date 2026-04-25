---
title: GATHER raw output via filesystem path, not envelope passthrough
status: backlog
groups: gather, analyze, adapters
---

## Why

Today the gather subagent pastes the SIEM CLI's verbatim stdout into the `raw.siem_response` field of its output YAML. ANALYZE then reads that field when its grading needs to inspect raw discriminator fields the characterization compressed past (proc.name vs proc.exepath impersonation, fd.lport / fd.sip direction, srcport distribution duplicates).

This is wasteful. A typical Wazuh CLI response is 50–200 KB of JSON; with composite dispatch (2–3 leads per loop), the raw payload dominates the gather envelope, eats Sonnet/Haiku tokens on every gather output, and forces a truncation discipline (`### Raw Sample Events` first 3 dicts + tail truncation marker) that the agent has to enforce manually. The recently-tightened verbatim-passthrough rules in `agents/gather.md` and `agents/gather-composite.md` exist *because* this discipline keeps slipping — agents under turn pressure compress the raw to prose and lose the discriminator fields.

The cheaper design: the adapter writes the raw output to a file at query time; the gather subagent emits a path pointer; ANALYZE reads the file directly when grading needs it. No verbatim passthrough through any LLM context.

## Design

### Adapter writes raw at query time

Every CLI adapter (`scripts/tools/wazuh_cli.py`, `host_query.py`, `*_ticket_cli.py`) writes the raw response to a deterministic per-query path:

```
{run_dir}/raw_query_outputs/{loop_n}-{lead_id}-{query_hash}.{ext}
```

- `loop_n` and `lead_id` come from the subagent invocation context (already plumbed for checkpoints).
- `query_hash` is a stable hash of `(query_string, time_window, substitutions)` — disambiguates multiple calls on the same lead.
- `ext` is vendor-appropriate (`.json` for JSON-shaped responses, `.txt` for prose, `.ndjson` for streaming results).

The CLI also prints to stdout (preserves CLI ergonomics for ad-hoc invocation), but stdout becomes truncatable / discardable: the file is the authoritative copy. A `--raw-out` flag explicitly names the path; if absent, adapter falls back to a `RAW_QUERY_OUTPUTS_DIR` env var the gather subagent sets, or stdout-only when neither is present (preserves standalone CLI use).

### Gather envelope carries `raw.path`, not raw content

```yaml
result:
  characterization: { ... }
  baseline: { ... }
  raw:
    path: "{run_dir}/raw_query_outputs/2-l-001-a3f8.json"
    bytes: 184320
    schema: "wazuh-search-response"   # vendor-declared schema id
    digest: "sha256:..."              # integrity check; optional
```

`raw.siem_response` is dropped entirely. The gather subagent doesn't read or paste the raw content — it just reports the path the adapter wrote.

### ANALYZE reads `raw.path` when grading needs it

The analyze prompt's by-role deviation rubric and the existing discriminator-field reads (proc.exepath, fd.lport, etc.) get rewired: when characterization is ambiguous, `Read({raw.path})` directly. The Pitfalls bullet about "characterization compressed past load-bearing fields" stays — but the recovery path is now a file read, not a YAML field read.

Most ANALYZE invocations won't need to read raw at all — characterization handles the common case. The file is the recovery surface.

### Composite dispatch: same shape per lead

Each lead in `gather-composite.md`'s output gets its own `raw.path`. Composite dispatch's only added complexity is the per-lead path discrimination, already covered by `lead_id` in the filename.

## Surface changes

| Surface | Change |
|---|---|
| `scripts/tools/wazuh_cli.py` | Add `--raw-out PATH` flag; honor `RAW_QUERY_OUTPUTS_DIR` env var as default; write raw response (verbatim, no truncation) to that path before printing to stdout. |
| `scripts/tools/host_query.py`, `*_ticket_cli.py` | Same convention. |
| `scripts/handlers/_subagent.py` | Set `RAW_QUERY_OUTPUTS_DIR` env var when dispatching gather/gather-composite; ensure the directory exists. |
| `agents/gather.md` | Drop `raw.siem_response` field. Replace with `raw: { path, bytes, schema, digest }`. Drop the verbatim-passthrough discipline (no longer needed — the file is verbatim by construction). |
| `agents/gather-composite.md` | Same envelope change per-lead. |
| `agents/analyze.md` | Update Pitfalls bullet on "characterization compressed past load-bearing fields" — reference `raw.path` and the `Read` tool for recovery, not field-level passthrough. |
| `tests/test_wazuh_cli.py` | New tests for `--raw-out` and `RAW_QUERY_OUTPUTS_DIR`. |
| `tests/test_e2e_*.py` | Adjust assertions that read `raw.siem_response` — read the path's contents instead. |

## Migration

This supersedes the recently-committed verbatim-passthrough discipline (commits on `predict-prompt-redesign` strengthening `raw.siem_response` to require complete CLI output including `### Raw Sample Events` JSON). Those commits get reverted by this task — their work is subsumed by the file-write path being verbatim by construction.

In-flight runs / replay scenarios: existing run dirs that don't have `raw_query_outputs/` directories will be missing the raw file. Replay is best-effort — characterization in the persisted envelope is enough for most ANALYZE work; raw recovery only matters when grading needs it. Document this as a one-time break for runs prior to migration.

## Open questions

1. **Should the gather subagent be allowed to read raw too?** Cleanest: no — it characterizes from CLI stdout (which the adapter still prints) and emits the path. Letting gather also read the file invites gather to do ANALYZE's job. But: when the CLI's stdout is truncated and characterization needs raw fields the adapter compressed in stdout, the gather subagent might genuinely need the file. Lean: allow it; the discipline against interpretation is enforced separately.

2. **Raw retention.** `raw_query_outputs/` will grow unbounded across runs. Hooks into `scripts/cleanup_runs.py`'s retention policy — same TTL as the run dir.

3. **Schema declaration.** `raw.schema` lets ANALYZE know what shape to expect (e.g., `wazuh-search-response` vs `host-query-process-list`). Could be auto-inferred from the adapter or declared per-template. Lean: declared in the vendor template's frontmatter, propagated by the adapter, surfaced in the envelope.

## Implementation order

1. **wazuh_cli.py first** — pilot the file-write path. `--raw-out` flag + env-var default.
2. **gather.md envelope update** — single-lead path swap. Verify on the existing gather_baseline_test fixture.
3. **gather-composite.md envelope update** — multi-lead.
4. **analyze.md Pitfalls update** — recovery path documentation.
5. **Other adapters** — host_query, ticket_cli — once the pattern is proven on Wazuh.
6. **Verbatim-passthrough discipline rollback** — drop the now-unneeded text from gather*.md once all consumers read from path.
7. **Tests** — adapter-level + e2e.

## Related

- Original deviations / structured-baseline work: `tasks/baseline-counterfactual-prediction-flow.md` (PR #129). The verbatim-passthrough commits there are the immediate predecessor of this task.
- Adapter contract base: `soc-agent/schemas/adapter_contract.py` — the `--raw-out` convention should ideally live as a contract method on the base ABC, not a per-adapter argparse hack. Worth surfacing in the design.
