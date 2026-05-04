---
title: Environment memory retrieval — anchor-tagged atoms across knowledge/environment/, preloaded into every phase by mechanic + entity + signature anchors
status: done
groups: knowledge-base, predict, gather, analyze, infrastructure
---

## Status (2026-04-25)

**v1 thin slice shipped — PR [#130](https://github.com/beetroot-salad/cyber-response-agent/pull/130) (branch `worktree-env-memory-retrieval`, 3 commits).**

Implemented:
- `soc-agent/scripts/handlers/env_memory.py` — Atom dataclass, MECHANIC_VOCAB (15 buckets, `token-issuance`→`token-lifecycle`), TRIPLE_TO_MECHANIC (~40 entries), parse_atoms_from_file, derive_mechanics_for_edge, extract_anchors, retrieve, format_env_memory_block. Walk-per-call (no index, no cache). Unified `valid: {from, to}` field; `stale`/`pre_window` flags, no hard exclusion. Mechanic on hypotheses derived from `(parent_type, relation, child_type)` triple — no invlang schema extension.
- `soc-agent/scripts/env_memory_lint.py` — schema + reference (blocking), window-expiry, default-window, conflict-candidate pool, triple-coverage (warnings). Exit 0 on PR's atom corpus.
- `soc-agent/scripts/handlers/predict.py` — `_safe_env_memory_section` mirrors `_safe_priors_section` (degrade-to-banner). Block injected after priors, omitted on empty match.
- `soc-agent/knowledge/environment/fleet/wazuh-indexer-bundled-jdk/co-fire-patterns.md` — moved from `systems/target-endpoint/` (image is the baseline source, not the host's role label). 4 atoms appended. New `fleet/` top-level dir for deployment-state knowledge (sibling to `systems/`, which stays for adapter quirks).
- Tests: `test_env_memory.py` (30 cases), `test_env_memory_lint.py` (14 cases), 3 new on `test_handlers_predict.py`. Full non-llm suite 1343 passed, no regressions.

Live verified end-to-end on rule 100001 (orchestrator eval `20260425-060309-rule100001-envmem`): the `wazuh-indexer-rule-100001-cofire-100002` atom successfully injected into the live PREDICT subagent prompt with correct `<environment-memory atom_id=... stale=... pre_window=...>` framing. 1 of 4 atoms matched — the other 3 require `vertex_classification: host-with-wazuh-indexer-jdk` which CONTEXTUALIZE didn't emit (see follow-up #5 below).

Two PR-#130 fixes landed during the eval:
- 1be5fe6 (review feedback): hypothesis-status filter via shared constant; INV_FENCE_RE shared; lint dedup; lint sample-cap constant.
- 74493b2 (live-eval discovery): `extract_anchors` now extracts ≥4-digit runs from `ctx.signature_id` so atoms anchored on bare numeric (`100001`) match `wazuh-rule-100001` ctx.

Out of scope for v1 (kept in this task as follow-ups, see below). Post-mortem flow / ledger / soft-signal counts are explicitly deferred.

**Conflict with PR #129 (`predict-prompt-redesign`)**: trivial 1-line overlap on `format_signature_text_block(signature_texts, exclude_archetype_catalog=True)` inside `_assemble_prompt`'s blocks list. Whoever merges second adds the kwarg inside the new `blocks.extend([...])`. No other file overlap.

## Next steps (in priority order)

1. **Atom anchors vs CONTEXTUALIZE classification vocabulary alignment.** Live eval showed only 1 of 4 atoms matched because CONTEXTUALIZE emits generic classifications (e.g. `endpoint`, `internal-server`) where atoms anchor on tighter ones (`host-with-wazuh-indexer-jdk`). Two paths: (a) broaden atom anchors to include the generic classifications + tighter ones, scored by overlap weight; (b) extend CONTEXTUALIZE prompt to emit image-rooted classifications when derivable from prologue evidence. (b) is the right fix — image identity belongs in the prologue. (a) is a stopgap.
2. **CONTEXTUALIZE entity-status-only retrieval pass** — second `retrieve()` call with mechanic-anchor disabled, fires on prologue alone so identity/asset facts (sabbatical, travel-flag) land before any mechanism hypothesis is authored.
3. **ANALYZE + GATHER + GATHER-COMPOSITE handler wiring** — same `_safe_env_memory_section` pattern. ANALYZE benefits most (grading discrimination); GATHER second (lead-execution context).
4. **Second batch of atoms** — wazuh quirks (`fleet/wazuh-manager-baseline/`?), one identity/sabbatical-style file under `fleet/identities/` to validate cross-signature surfacing + entity-status retrieval.
5. **Atom prose self-containment audit** — atom `body:` strings reach the prompt without surrounding markdown context. Each must qualify its own scope (e.g. "hosts running the wazuh-indexer image") rather than relying on the file header. The 4 v1 atoms were authored to this discipline; future authoring needs the discipline documented in `docs/environment-memory-schema.md`.
6. **Dead-atom lint** — synthetic Context per signature × archetype, report atoms that never match. Useful once the corpus passes ~20 atoms.
7. **CI integration** — `env_memory_lint.py` to pre-commit / pytest.
8. **Optional `mechanic` override field on `proposed_edge`** — only if derivation proves too coarse in practice. Add when you see repeated misclassifications.
9. **Post-mortem flow** — `_ledger.jsonl`, `_candidates/<run-id>.yaml`, soft-signal counts (load-bearing / contradiction / irrelevance counters). Explicitly punted from v1.

## Why

The knowledge base today is keyed by signature + system. Two failure modes:

1. **Single-loop preload misses loop-N emergence.** PREDICT loop 1 may not yet have authored a hypothesis whose mechanism surfaces a relevant fact; loop 2 does, but no mechanism reloads relevant knowledge against the larger investigation state.
2. **Search-required ≠ used.** The 2026-04-24 A/B harness (Variant C) confirmed that a search hint pointing at a knowledge file is functionally equivalent to "no knowledge" — the agent doesn't go look. Knowledge that should fire MUST be preloaded; the question is which knowledge fires when.

The KB is **not** a "how to investigate X" manual — that's the past-investigation corpus's job. The KB is the agent's **environment memory**: the quirks, baselines, identity facts, and tooling pitfalls that turn a generic analyst into one with deployment experience. Without anchor-tagged retrieval, env knowledge has to be either (a) signature-bound and pre-declared (doesn't compose across signatures), or (b) globally preloaded (preload bloat).

## Design

### Three atom categories

Every atom belongs to one of three categories, encoded by which anchors it carries — not as a separate enum:

| Category | Primary anchors | Examples |
|---|---|---|
| **Mechanism context** (most atoms) | `mechanic` + `vertex_classification` | "brute-force on monitoring-vlan = baseline noise"; "service-account auth from outside scheduled-job window = anomalous" |
| **Entity status** | `vertex_identifier` or `vertex_classification`, no mechanic | "bob@corp on sabbatical until 2026-06-01"; "alice@corp HR travel-flag set"; "subnet 10.0.50.0/24 is monitoring-vlan" |
| **Source / tool quirk** | `data_source` and/or `signature_id` | "Wazuh 5710 logs to non-default path on this fleet — query through Wazuh, not host-tail"; "DLP `ALERT_TIME` = agent flush time, correlate ±15min" |

Categories are descriptive — they shape default TTLs and which retrieval pass picks them up, but the matcher operates uniformly on anchors.

### Mechanic vocabulary (raw OS/auth/network primitives, ~15-20 buckets)

Atoms anchor on what *actually happened at the OS/auth/network layer*, not on what tripped the alert. Signatures are instances of these primitives in specific manifestations.

`authentication`, `process-exec`, `file-write`, `file-read`, `network-connect`, `dns-resolution`, `privilege-transition`, `scheduled-job`, `data-transfer`, `service-control`, `interactive-session`, `cred-access`, `discovery-query`, `ipc`, `token-issuance`.

(MITRE technique IDs may be added as a side-anchor for cross-referencing past investigations, but they are NOT the primary key — they force premature mechanism commitment at write time.)

### Atom anchor schema

Atoms live inside knowledge files as YAML blocks (per-topic file, sectioned atoms). Each atom:

```yaml
- id: monitoring-vlan-bf-baseline       # stable, manually authored
  body: |
    Brute-force-shaped 5710/5712 from 10.0.50.0/24 to monitoring-jumphosts is
    baseline ssh-keyscan probing. Lone 5710 without 5712 within ±10s is real.
  anchors:
    mechanic: [authentication]
    vertex_classification: [monitoring-host, monitoring-vlan-source]
    signature_id: [5710, 5712]            # optional; mechanism is primary
    domain: [endpoint, network]           # optional; for lint summaries
  verified_at: 2026-03-12
  ttl: 12mo                               # category default if omitted
  # valid_window: {from: 2026-05-12, to: 2026-05-19}    # optional; one-shot bounded validity
  # valid_recurring: {dow: [wed], hours: [14, 15], tz: GMT}  # optional; cyclic bounded validity
  salience: normal                        # high | normal — high wins ties
```

Anchor matching is OR within a key (any value matches), AND across keys (all declared keys must match). Empty / omitted keys do not constrain.

### Retrieval primitive (`scripts/handlers/env_memory.py`)

Module-level functions:

```python
def build_index(soc_agent_root: Path) -> EnvMemoryIndex:
    """Walk knowledge/environment/**/*.md, parse frontmatter atoms,
    validate schema, return immutable index. Cached at import time."""

def retrieve(index: EnvMemoryIndex, ctx: Context, k: int = 8) -> list[Atom]:
    """Extract anchors from current investigation state:
      - vertex_identifier + vertex_classification from prologue.vertices
        + every materialized vertex in findings
      - mechanic from active hypotheses (each hypothesis declares mechanic
        in its proposed_edge — schema extension required)
      - signature_id from ctx.signature_id
      - data_source from any phase-specific scope (GATHER lead's source)
      - clock from now()
    Score each atom by weighted anchor-overlap (mechanic 2x, identifier 1.5x,
    others 1x). Apply salience tie-break. Return top-K.
    Mark expired atoms with stale=True; do NOT exclude."""
```

Loop 1 retrieves against post-CONTEXTUALIZE state. Loop N re-runs every phase — newly materialized vertices and new mechanism hypotheses pull in additional atoms. Set grows monotonically across loops.

### TTL + freshness + bounded validity

Two distinct temporal models, both supported:

**TTL (probabilistic decay)** — the fact is *probably* still true but should be re-verified.
- Each atom carries `verified_at` and `ttl`. Computed `expires_at = verified_at + ttl`.
- Default TTLs by category: entity-status = 30d, asset/topology = 6mo, mechanism-context = 12mo, source-quirk = 12mo (refresh on vendor upgrade).
- Retrieval surfaces expired atoms with a stale flag in the prompt block — the LLM down-weights, hard exclusion is brittle.
- Refreshing = bump `verified_at`; one-line edit when content unchanged.

**Bounded validity (certain windows)** — the fact is true ONLY during a specific window.
- Atom carries `valid_window: {from: <date>, to: <date>}` for one-shot windows (business trips, sabbaticals, maintenance windows, scheduled exercises).
- Or `valid_recurring: {dow: [...], hours: [...], tz: ...}` for cyclic windows (business hours, on-call rotations, weekly RT exercises).
- Retrieval semantics: before `from` or after `to` → atom does NOT match (hard exclusion). Within window → matches normally. This differs from TTL: certainty of state change, not probability of decay; two-sided; hard.
- TTL must be ≥ window length; lint enforces.

**Gardener lint pass:**
- TTL-expired atoms grouped by category for batch re-verification (warning).
- Window-expired atoms (`valid_window.to < today`) → tombstone candidates (warning).
- Future-windowed atoms (`from > today + 30d`) → confirm authoring intent (info).

### Phase-handler wiring

Each phase handler's `_assemble_prompt` calls `env_memory.retrieve(ctx)` and injects matched atoms as XML blocks before existing context blocks:

```
<environment-memory atom_id="monitoring-vlan-bf-baseline" stale="false">
  Brute-force-shaped 5710/5712 from 10.0.50.0/24 ...
</environment-memory>
<environment-memory atom_id="..." stale="true" expired_days_ago="14">...</environment-memory>
```

CONTEXTUALIZE additionally runs an entity-status-only pass on the prologue alone (no mechanic anchor required) so identity/asset facts land before any mechanism is hypothesized.

### Lint + gardener (`scripts/env_memory_lint.py`)

1. **Schema validation** — every atom under indexed paths parses against the schema.
2. **Reference validation** — `mechanic`, `vertex_classification`, `signature_id`, `data_source` values exist in invlang / playbook / config vocabularies.
3. **Dead-atom detection** — runs retrieval against synthetic investigation states (one per signature × representative archetype) and reports atoms that never match.
4. **Coverage summary** — per signature × archetype, list which atoms surface.
5. **Staleness summary** — atoms past `expires_at`, grouped by category.
6. **Conflict detection** — two atoms with overlapping anchor scope and contradicting bodies (heuristic; flagged for human review, not blocked).

CI runs this; staleness and dead-atom detection are warnings, schema/reference are blocking.

## Concrete surface changes

| Surface | Change |
|---|---|
| **Atom schema** | New per-atom YAML inside knowledge files: `id`, `body`, `anchors`, `verified_at`, `ttl`, `valid_window`/`valid_recurring` (optional), `salience`, `status` (default `live`; `superseded`/`tombstoned` for invalidations). Documented in `docs/environment-memory-schema.md` (new file). |
| **`env_memory.py`** (new) | `build_index()` + `retrieve()` + `Atom` dataclass. Reuses invlang vertex/edge walkers for anchor extraction. Reads `_ledger.jsonl` to decorate atoms with feedback counts. |
| **`env_memory_lint.py`** (new) | CLI tool — schema, reference, dead-atom, staleness, window-expiry, conflict. `--aggregate` mode folds per-run `atom_feedback.jsonl` into the ledger. CI-wired. |
| **Post-mortem subagent / skill** (new) | Consumes a completed run (alert + investigation.md + report.md + retrieved atoms), emits new-atom / invalidation / eviction candidates to `_candidates/<run-id>.yaml` and updates `_ledger.jsonl`. Report subagent unchanged. |
| **`_ledger.jsonl` + `_candidates/`** | New paths under `knowledge/environment/`. Ledger is the post-mortem-driven coherence record; `_candidates/` stages proposals for author-skill review. |
| **Phase handlers** (`predict.py`, `analyze.py`, `gather.py`) | `_assemble_prompt` calls retrieve, injects `<environment-memory>` blocks. Cached index at handler-import; retrieval per-phase. |
| **Hypothesize subagent schema** | `proposed_edge` extended with `mechanic` field (drawn from the ~15-20 vocab) so retrieval can anchor on it. |
| **Existing `knowledge/environment/**` files** | NOT moved. Extend in place: add atom blocks with anchor metadata over time. Files past ~20 atoms split into a directory. |
| **`docs/environment-memory-schema.md`** (new) | Reference doc — atom schema, mechanic vocabulary, anchor types, TTL defaults, lint rules. |
| **CI** | Add `python3 scripts/env_memory_lint.py` to test suite / pre-commit. |

## Edge cases + non-goals

- **Topology-edge matching is dropped.** That belongs to the corpus retrieval (`predict.py:_compute_priors`), which already does it. Env memory is anchor-tagged, not topology-keyed.
- **Embedding-based retrieval out of scope.** Anchor lists are debuggable; embeddings are fuzzy. If the corpus grows past several hundred atoms, reconsider. Per-anchor recall + lossy top-K is fine — atoms are short, LLM filters.
- **No CMDB / entity inventory.** The KB is interpretive overlay, not authoritative entity store. Entity-status atoms exist only when the fact is *non-obvious to a generic analyst* (Bob on sabbatical, alice's travel-flag). Hostnames / IPs / ownership records belong in the source-of-truth system.
- **`anchors` evolution.** Schema starts narrow. Add new anchor keys (`severity_class`, `business_unit`, ...) only when authoring real atoms surfaces a need. Avoid speculative keys.

## Implementation order

1. **Schema + index module** — write `env_memory.py`. Unit tests via synthetic atom blocks + synthetic Context states.
2. **Lint tool** — write `env_memory_lint.py`. Fixture corpus + investigation states; exercise schema, reference, dead-atom, staleness checks.
3. **Hypothesize schema extension** — add `mechanic` to `proposed_edge`. Update invlang validator.
4. **First batch of atoms** — backfill atoms into existing files: `target-endpoint/co-fire-patterns.md` (already drafted on `predict-prompt-redesign`), Wazuh quirk file, one entity-status file. Run lint, confirm clean.
5. **PREDICT handler wiring** — `_assemble_prompt` calls retrieve, injects `<environment-memory>` blocks. Verify against the 2026-04-24 A/B harness pre-state.
6. **CONTEXTUALIZE entity-status pass** — second retrieval pass restricted to entity-status atoms, fires on prologue alone.
7. **ANALYZE + GATHER wiring** — same pattern.
8. **Second batch of atoms** — 5-10 more across categories, validate cross-signature surfacing.
9. **CI integration** — lint runs on every test invocation; failure modes per severity.
10. **Loop-N validation** — synthesize an investigation where loop 1 has no mechanic-anchored atoms relevant, loop 2 does. Confirm retrieval picks them up.

## Cache invalidation — post-mortem driven

The CONCLUDE subagent and `report.md` artifact are NOT extended for KB bookkeeping. They stay focused on disposition. All KB management — authoring, invalidation, eviction — flows through a single dedicated **post-mortem** pass that analyzes the completed investigation (alert + `investigation.md` + `report.md`) against the env-memory atoms that retrieved into it.

**Two-tier policy — soft signals are automated annotations from the post-mortem; hard changes go through the author skill.**

**Soft signals (annotate, don't delete):**
- TTL stale flag (covered in freshness section; clock-driven, no post-mortem needed).
- Window-expired flag (`valid_window.to < today`; clock-driven).
- Contradiction count, load-bearing count, irrelevance count — all populated by post-mortem analysis.
- Low-utility flag (matched many times, rarely load-bearing).
- Authoring-time conflict flag (lint detects overlapping anchor scope + contradicting bodies).

Soft-signal counts travel into retrieval as decorations on the atom (`<environment-memory atom_id="..." contradiction_count="2">...`) so the LLM down-weights in context.

**Hard changes (human-gated via author skill):**
- Supersede: new atom replaces old; old becomes tombstone (`status: superseded`, `superseded_by: <new-id>`). Tombstones GC'd after 6mo by gardener.
- Delete / `/forget`: explicit invalidation by anchor (e.g. `/forget vertex_identifier=mon-jh-01 reason="decommissioned"` tombstones every atom with that anchor).
- Edit: in-place content change, bumps `verified_at`.

### Post-mortem flow

Triggered manually after an investigation concludes (or in batch over recent runs). The post-mortem subagent / skill consumes:
- `alert.json`, `investigation.md`, `report.md` for the run.
- The `<environment-memory>` atoms that retrieved into each phase (recoverable from prompt logs or by re-running retrieval against the run's investigation state).
- The current KB.

It produces three kinds of output, all written to `knowledge/environment/_candidates/<run-id>.yaml` for human/author review — never directly to the live KB:

1. **New atom candidates.** Facts that emerged in the investigation that would have shortened it. ("Service `s3-rotator-svc` runs at 03:00 daily and produces exfil-shaped traffic — would have ruled out the data-exfil hypothesis at loop 1.")
2. **Invalidation candidates.** Atoms that retrieved but were contradicted by findings. ("Atom `bob-sabbatical` was used; investigation found bob legitimately active. Suggest tombstone or window-update.")
3. **Eviction candidates.** Atoms that retrieved but were never load-bearing across this run AND have a long history of irrelevance in the ledger. ("Atom X has matched 47 times, load-bearing 1; tighten anchors or remove.")

The post-mortem also updates `_ledger.jsonl` with the per-atom verdicts from this run (load_bearing / irrelevant / contradicted counts), so the ledger compounds value across runs without polluting the report-writing path.

```jsonl
{"atom_id": "bob-sabbatical", "contradicted": 2, "load_bearing": 0, "irrelevant": 1, "last_match": "2026-04-24", "last_contradicted": "2026-04-24"}
```

Retrieval reads the ledger and decorates atoms with counts. Threshold (e.g. 3 contradictions in 30d) → soft-flag for author review.

### Why post-mortem instead of inline

- **Separation of concerns.** Report subagent stays single-purpose (disposition); post-mortem is single-purpose (KB hygiene). Neither has to balance both jobs in one prompt.
- **Better signal quality.** Post-mortem reads the *whole* investigation including the final disposition — it can judge load-bearing-ness against actual outcome, not just self-report at conclude time. Anti-laziness mitigations become less necessary because the post-mortem has the full record to ground its labels.
- **Batching.** Post-mortem can process N runs at once, surface patterns across runs ("atom X contradicted in 4 of last 10 runs"), and propose batched invalidations. Inline labeling can't see across runs.
- **Optional / cheap to defer.** No post-mortem run = no ledger updates, but live retrieval still works on TTL + windows + salience. The system degrades gracefully when post-mortem is skipped.

### Atom ID stability

- IDs are hand-authored, lint enforces uniqueness.
- Renaming requires explicit `previously_id: <old>` lineage entry so the ledger maps old feedback to new ID.

### Bootstrapping

No ledger exists day 1. Retrieval runs on TTL + windows + salience until post-mortems accumulate. The first useful ledger signal appears after a handful of post-mortems on the same atom — fine because the KB is small day 1.

## Open questions

- **Post-mortem trigger model.** Manual on-demand, post-Stop-hook automatic, or batched (e.g. nightly across last N runs)? Lean: manual on-demand for v1 (lowest commitment), add batched run later. Per-run automatic in the Stop hook risks running an LLM pass on every investigation when most won't yield useful candidates.
- **Per-topic file vs per-atom file.** Per-topic with sectioned atoms is the default (5-8 atoms per file). Files past ~20 atoms split into a directory. No per-entity files (avoids CMDB drift).
- **Phase-scoping atoms.** Should an atom declare `relevant_phases: [PREDICT, ANALYZE]`? Defaults to all. Add only when prompt bloat surfaces phase-specific atoms.

## Related

- `tasks/baseline-counterfactual-prediction-flow.md` — adds structured baseline data via GATHER lead definitions; this task adds env-memory context via anchor retrieval. Different sources, complementary.
- A/B harness on 2026-04-24 (`/tmp/predict_ab_harness/`) — Variant C confirms search-required knowledge isn't used; only preloaded works.
- `knowledge/environment/systems/target-endpoint/co-fire-patterns.md` — drafted on `predict-prompt-redesign`. Step 4 above gains its atom blocks.
- Existing `knowledge/environment/{context,data-sources,operations,systems}/` — files extend in place, no migration.
- `invlang.hypothesis_topology` — used by `predict.py:_compute_priors` for corpus-case retrieval. Env memory uses different anchor extraction (vertex id/class + mechanic + signature + clock), not topology.