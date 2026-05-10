---
title: PREDICT/GATHER contract realignment — leads as the shared vocabulary, missing-lead as a lifecycle event
status: todo
groups: predict, gather, lead-catalog, prompt, schema
---

**Goal.** Realign the PREDICT → GATHER contract so each subagent owns its own layer of the work, and make the lead catalog the single shared vocabulary they communicate through. PREDICT picks leads and adds emphasis; GATHER picks systems, constructs queries, and characterizes results. Missing leads are routed to a catalog-evolution path, not invented at GATHER time. Composite envelopes carry the host-profile / cross-aspect characterization shape.

This task replaces the earlier "subject_kind triple" framing and supersedes the contract sections of `tasks/declarative-lead-invlang-frontmatter.md` where the two overlap (cross-reference at landing time).

## Why

Run-mirror loop 2 (rule-5710 zabbix monitoring probe — `experiments/predict-analyze-format-ab/fixtures/run-mirror/investigation.md`) is the load-bearing case. PREDICT routed `selected_lead: monitoring-system-audit` (ad-hoc, no definition), `override_data_source: -`, and a prose `lead_hint` saying "query 172.22.0.10 via host_query for Zabbix daemon scheduled-action log entries... compare foreground record count at t-0 against the tool's 72h per-tick baseline." GATHER constructed a cross-source query that bundled the load-bearing host_query process check with a redundant wazuh re-query of the `(srcip, srcuser, target)` slice already saturated in loop 1. The wazuh re-query yielded zero new evidence; the host_query side carried the actual disposition signal.

The current envelope has three responsibilities tangled in one block:

- **What** — `selected_lead` (planning, PREDICT's job).
- **Why / with what emphasis** — `lead_hints`, `rationale` (enrichment, PREDICT's job).
- **How / where** — `override_data_source` (execution, GATHER's job leaking into PREDICT).

Once `override_data_source` is in the contract at all, PREDICT is being asked an execution question. Promoting it to required (the obvious "make optional fields load-bearing" fix) doubles down on the misalignment instead of fixing it. The right cut is to remove it.

The deeper miss in run-mirror is that `monitoring-system-audit` should never have reached GATHER as an unstructured ad-hoc lead. The question PREDICT was asking — "is there a Zabbix daemon doing this?" — has no lead in the catalog. Today that gap is filled by ad-hoc lead invention; under the realigned model it routes to a `lead_specification` block (a missing-lead declaration) whose contract mirrors the useful parts of an on-disk lead definition. Lead invention stops being an at-runtime construction and becomes a catalog lifecycle event.

## Core Model

### The division of expertise

```
PREDICT:  decides what to gather
          - picks leads (catalog-first; composite-of-catalog second; declare-missing third)
          - adds emphasis (free-text per leg, one sentence)
          - sets scope (window + anchor)
          - does NOT name systems, query shapes, or CLIs

GATHER:   decides how to gather, runs the gather, summarizes
          - picks systems per lead based on reachability + cost
          - leans on the lead's pre-baked vendor templates (the cache)
          - constructs ad-hoc only when no template exists for a reachable system
          - characterizes per the lead's `What to Characterize` contract

LEADS:    the shared contract
          - lead names are PREDICT's vocabulary
          - lead definitions (subject of measurement, characterization contract,
            per-vendor templates) are GATHER's cache layer
          - a missing lead is a catalog gap, not a runtime invention
```

PREDICT may *not* name a data source, a CLI, or a query shape. GATHER may *not* invent leads, redefine subjects, or fork composites that PREDICT did not declare. Each subagent's prompt enforces this in its own discipline section.

### Realigned envelope — single lead

```
:R routing
mode             single                     # optional; parser defaults omitted mode
                                            #   to single
selected_lead    <slug>                     # required; must exist in catalog,
                                            #   be a declared composite, or be a
                                            #   non-existing slug accompanied by
                                            #   lead_specification (see below)
emphasis         "<one sentence>"           # optional; enrichment to the lead's
                                            #   default characterization
                                            #   ("watch source-port distribution",
                                            #    "characterize baseline in the
                                            #     week prior")
scope_override   window_hours, anchor       # optional; replaces 1h default
```

Removed: `override_data_source`. Removed: `composite_secondary`. Hard cut: no migration shim, no parse-time synthesis, no transitional compatibility surface. Renamed: `lead_hints` → `emphasis` (one sentence, scoped to enrichment, not query construction).

**Emphasis discipline.** A sentence that names a system, a CLI, a field name, or a query operator gets rejected by the parser. Emphasis names *what to notice* in the lead's measurement — never *how* to take it.

### Realigned envelope — composite

For cross-aspect characterizations (the "host profile" / "session profile" / "identity profile" pattern), PREDICT declares a composite envelope:

```
:R routing
mode             composite
intent           "<one sentence>"           # required; the general characterization
                                            #   request ("characterize monitoring-host
                                            #   to determine which process produced
                                            #   the SSH probes")
legs             <lead-slug>,<lead-slug>    # required; the decomposition into
                                            #   catalog leads (or declared composites)
emphasis         per-leg map                # optional; keyed by leg slug
scope_override   per-leg map                # optional; keyed by leg slug
```

Each leg is itself a valid single-lead reference — catalog lead, declared composite (stage 2), or a non-existing slug with a `lead_specification` in the same output. GATHER receives the legs as independent invocations sharing the same entity bindings and (default) scope, runs the per-leg health probes and queries, and returns a composite outcome. The cross-leg refinement work `gather-composite` already does (using one leg's result to refine another's window) stays in GATHER — it's an execution-layer concern.

### Missing-lead declaration

When PREDICT needs a measurement no catalog lead covers and no composite of catalog leads decomposes cleanly, it picks a slug describing **one real-world activity** and emits a `lead_specification` block with the runtime subset of an on-disk `definition.md`: `Goal` and `What to Characterize`.

```
:R routing
selected_lead          <new-slug>           # invented, descriptive of one activity
mode                   missing-lead

:R lead_specification
goal                   "<one sentence>"     # mirrors definition.md ## Goal; names what
                                            #   measurement would answer, not where/how
load_bearing           "<one sentence>"     # why answering this changes the next move

:R lead_specification.characterization [dimension|description]
daemon_presence|"whether a monitoring daemon exists and was running on the source host"
scheduled_probe_shape|"whether its scheduled action count at T0 matches its recurring per-tick shape"
```

The block is intentionally minimal: `goal`, `load_bearing`, and a short `what_to_characterize` list. The characterization rows are the dimensions GATHER must try to answer, equivalent to the bullets under an eventual `## What to Characterize` section. Tags are deliberately omitted — they are catalog search metadata, not the runtime contract. Subject taxonomy, authority hints, system names, CLI names, fields, query operators, and templates are likewise omitted; those are catalog-author or GATHER execution concerns, and pinning them at PREDICT time leaks "how" back into "what."

GATHER inspects the missing-lead leg and either:

- runs it if it can identify a reachable system that can measure the `goal` and characterize the requested dimensions — recorded as `query_source: ad-hoc-missing-lead`, OR
- **early-exits** the leg with `status: missing_lead_unrunnable` if no reachable system fits, without going back to PREDICT.

Either way, the `lead_specification` is captured on the lead's `findings[]` entry as `missing_lead_spec: {goal, load_bearing, what_to_characterize}`. Executed missing leads keep the normal execution status (`ok`, `partial`, `data_missing`, etc.) plus `query_source: ad-hoc-missing-lead`; unrunnable missing leads use the single new status `missing_lead_unrunnable`. The post-mortem normalization pipeline picks up entries with `missing_lead_spec` and writes proper catalog leads (see `tasks/postmortem-pr-not-proposals.md` style — same pipeline shape).

No `substitute_with` mechanism. Substitution would re-create the run-mirror failure mode (PREDICT smuggling a subject narrowing into emphasis on a generic catalog lead). If PREDICT can't find a clean catalog or composite path, it declares the missing lead and lets GATHER's reachability call decide whether the loop runs or skips.

This is a real behavioral change. Today an invented slug is GATHER's problem; under realignment it's the catalog's problem, with GATHER allowed an early-exit when reachability fails. Both outcomes are better than the run-mirror trajectory.

### GATHER refinement under the realignment

GATHER's job grows by the system-selection axis and shrinks by the lead-invention axis. The discipline:

1. **System selection** — per leg, GATHER picks among reachable systems that can satisfy the lead's measurement contract. Order of preference: (a) lead has a `templates/{vendor}.md` for a reachable system → use that template; (b) lead has a catalog `definition.md` whose `Goal` / `What to Characterize` contract is clear and a reachable system can produce it, but no vendor template exists → ad-hoc construction against that system, recorded as `query_source: ad-hoc-template-gap`; (c) lead is a declared missing lead and a reachable system can measure its `goal` / characterization dimensions → ad-hoc construction recorded as `query_source: ad-hoc-missing-lead`; (d) no reachable system can produce the leg's measurement → `status: data_missing` for catalog leads, or `status: missing_lead_unrunnable` for missing-lead declarations.
2. **Ad-hoc construction is narrowed.** Today's `query_source: ad-hoc` covers two distinct cases: lead has no definition (the run-mirror failure) and lead has a definition but no template for the reachable system. Split these. Undefined slugs are legal only when paired with `lead_specification`, in which case the query source is `ad-hoc-missing-lead`; catalog leads with clear definitions but missing reachable templates use `ad-hoc-template-gap`.
3. **Refinement stays single-source.** A leg may refine its query within its chosen system (widen window, drop a filter, change aggregation) but may not re-issue against a different system without going back to PREDICT. Multi-system per-leg work is structurally a missing composite, not a refinement.
4. **`What to Characterize` contract is enforced per leg.** GATHER's outcome must address every dimension the lead's `definition.md` declares. Emphasis adds dimensions; it doesn't remove them.

The empty-result / `data-source-debug` protocol remains unchanged — that's already a single-source health check. The `bracket the alert, don't just look back` discipline likewise stays.

### Coverage memory — kept simple under realignment

Coverage keys cleanly on `(lead_slug, entity_bindings_canonical, window)`. The lead is the slice abstraction; no data-source cross-reference is needed at the key level (GATHER chose the system, the system choice is metadata on the entry).

Coverage memory is a separate task (stage 3). Stage 1 does **not** add a redundancy-rejection rule, a coverage projection in the frontier view, or anchor-consult `effective_window` semantics — defer all of that to stage 3 and design it on top of the realigned `(lead_slug, entity_bindings, window)` key. The only coverage-adjacent obligation in stage 1 is plumbing `data_missing` / `missing_lead_unrunnable` through ANALYZE and the frontier view (stage plan §9) so the same lead is not blindly re-selected.

### Dense grammar / parser alignment

The dense grammar must stay aligned with the existing dense block style and the handler output schema. Do **not** introduce a YAML-only shortcut for the new routing contract.

Implementation note for `agents/predict/dense-schema.md`, `_predict_dense.py`, and `_output_parser.py`: add parser comments beside the `:R` branch that document the exact projection from dense blocks to `PredictParseResult.routing`. The expected shape is:

```
routing = {
  "mode": "single" | "composite" | "missing-lead",  # omitted dense row defaults to "single"
  "selected_lead": "<slug>",                 # single / missing-lead
  "legs": ["<slug>", ...],                   # composite
  "intent": "<one sentence>",                # composite
  "emphasis": "<sentence>" | {"<slug>": "<sentence>"},
  "scope_override": {...} | {"<slug>": {...}},
  "lead_specification": {
    "goal": "<one sentence>",
    "load_bearing": "<one sentence>",
    "what_to_characterize": [
      {"dimension": "<key>", "description": "<what to characterize>"}
    ]
  }
}
```

Old fields (`override_data_source`, `composite_secondary`, `lead_hints`) are rejected, not ignored. The lexical rejects for `emphasis`, `intent`, `goal`, and characterization descriptions share the same reserved-token helper so system slugs, CLI invocations, field names, and query operators cannot re-enter through renamed prose.

Parser boundary: `_predict_dense.py` validates the structural pairing (`mode: missing-lead` requires `lead_specification`; catalog modes must not include it). Catalog existence is handler-level validation because it requires filesystem context: a non-existing slug is accepted only when the parsed routing carries `mode: missing-lead` plus `lead_specification`; otherwise it is rejected before GATHER dispatch.

## Stage Plan

### Stage 1 — contract realignment (this task's body of work)

1. **`agents/predict/SKILL.md`** — rewrite §"composite_secondary and overrides" to describe the realigned division. Remove `override_data_source` from the trailer schema. Rename `lead_hints` → `emphasis`. Tighten "Ad-hoc leads are legal" to "Declaring a missing lead" with the `lead_specification` block. Add the composite envelope as the primary path for cross-aspect characterizations. Add the execute-or-early-exit rule for missing leads.
2. **`agents/predict/dense-schema.md`** — update the dense grammar for the new `:R routing` shape, the composite envelope, and the `lead_specification` / `lead_specification.characterization` blocks. Document the parser projection into `PredictParseResult.routing` so the grammar, parser comments, and output schema stay aligned. Reject grammar where `emphasis`, `intent`, `goal`, or characterization descriptions name a system/CLI/field/operator (regex-level lexical check).
3. **`agents/predict/examples/`** — update `shape-A.md`, `shape-E.md`, `shape-M.md` worked examples to use the new envelope. Add a worked example for the host-profile composite case (rule-5710 loop 2 with the missing-lead routing path).
4. **`agents/gather.md` and `agents/gather-composite.md`** — drop `override_data_source` from inputs. Add system-selection discipline (preference order above). Tighten ad-hoc construction to `ad-hoc-template-gap` for catalog leads and `ad-hoc-missing-lead` for declared missing leads. Add the `missing_lead_spec` finding payload and document that GATHER either executes such legs or early-exits with `status: missing_lead_unrunnable`. Keep `bracket the alert` and `data-source-debug`.
5. **`scripts/handlers/_predict_dense.py` + `_output_parser.py` + companion dense parser where `findings[]` projection needs it** — accept the new shape; reject `override_data_source`, `composite_secondary`, and `lead_hints`; reject reserved tokens in `emphasis`, `intent`, `goal`, and characterization descriptions; validate `lead_specification` block shape. Write or update tests in `soc-agent/tests/`.
6. **`scripts/handlers/gather.py` + `scripts/handlers/analyze.py`** — emit missing-lead findings cleanly; project them into `findings[]` with `missing_lead_spec` payload and either normal execution status (`ok`, `partial`, `data_missing`, etc.) or `status: missing_lead_unrunnable`. Ensure `coverage_signature` projection (when added) keys on `lead_slug` not on system.
7. **Catalog audit** — pass over `knowledge/common-investigation/leads/` to confirm every existing lead carries a clear subject + characterization contract under the realigned terminology; tighten any lead that conflated "what" and "how". Lightweight; mostly read-and-confirm.
8. **Drop `composite_secondary` cleanly.** Nothing has shipped; no migration shim, no parse-time synthesis. Remove the field, the prompt sections, and any handler branches in the same PR. Stage 1 is the cut.

9. **Plumb `data_missing` / `missing_lead_unrunnable` through ANALYZE and back into PREDICT's frontier view.** ANALYZE treats these statuses as load-bearing context for a more complete weighted assessment (the leg was attempted, reachability failed — that's an evidence statement, not silence). PREDICT's frontier view surfaces them so the same lead is not re-selected loop-over-loop. Without this, the new failure shape silently degrades to "lead disappears."

### Stage 2 — composite leads as first-class catalog entries

Composite leads can be stored in `knowledge/common-investigation/leads/<composite-slug>/definition.md` with a `kind: composite, legs: [<slug>, ...]` block. PREDICT references them as a single slug; GATHER decomposes into legs at dispatch time. Stage 2 work:

1. Composite-lead definition format under `knowledge/common-investigation/leads/`.
2. PREDICT prompt update: "use catalog composites by name when one matches your characterization; declare an inline composite envelope only when the combination is novel."
3. Catalog seed: at minimum a `host-profile` composite (`process-state`, `network-history`, `authentication-history`) and a `session-profile` composite. Driven by post-mortem normalization once stage 1 surfaces the recurring inline composites.
4. Dispatch: GATHER expands a catalog composite into legs identically to an inline composite. Same per-leg discipline.

Stage 2 is gated on stage 1 producing measurable corpus signal that the same inline composites recur — driven by data, not by anticipation. Stage-2 task file follows once stage 1 is in.

### Stage 3 — coverage memory

Tracked separately. Plugs in via the `(lead_slug, entity_bindings, window)` projection. Not blocked on stage 1 but lands cleanly on top of it.

## Verbosity Control

The main failure mode is emphasis spam (PREDICT re-stating the lead's default characterization, or smuggling system selection in via prose). Defenses:

- One sentence per `emphasis`, hard cap.
- Lexical reject of system slugs and CLI tokens in emphasis strings.
- Composite legs default to no emphasis; the per-leg map is opt-in.
- `intent` on a composite is one sentence; lexical reject of multi-clause structure that names two systems or two subjects.

## What Not To Do In This Iteration

- Do not introduce a `subject_kind` / `authority_kind` / `data_source` triple per lead. The lead's existing `definition.md` is the contract; the parser doesn't need a typed mirror of it.
- Do not let GATHER negotiate back to PREDICT mid-loop on data-source choice. Reachability is GATHER's call; if no reachable system can produce the leg, it returns `status: data_missing` for catalog leads or `status: missing_lead_unrunnable` for missing-lead declarations, and PREDICT decides next loop.
- Do not introduce any substitution mechanism. If no catalog lead or clean composite fits, PREDICT declares the missing lead and GATHER either executes it via `ad-hoc-missing-lead` or early-exits with `missing_lead_unrunnable`.
- Do not block stage 1 on coverage memory or composite-lead catalog entries. Stage 1 stands alone.
- Do not bundle this with the unknowns work (`tasks/unknowns-as-first-class.md`). Both touch PREDICT but they're orthogonal — unknowns shape the question; this task shapes the contract for asking it.

## Acceptance — outcome deltas, not process checks

Three fixtures, three outcomes:

1. **run-mirror loop 2 (rule-5710 zabbix)** — PREDICT routes a missing-lead declaration whose `goal` is "determine whether a monitoring daemon on monitoring-host issued the scheduled SSH probes" (or a composite whose legs include such a declaration) and whose `what_to_characterize` includes daemon/process presence and alert-time scheduled-probe shape. GATHER either executes against the reachable host system (`query_source: ad-hoc-missing-lead`) or early-exits with `status: missing_lead_unrunnable`. The single-`process-state`-with-Zabbix-emphasis path is **not acceptable** — it's the run-mirror failure pattern in new clothing. Measurable by: (i) absence of wazuh in loop-2 query trace for the missing-lead leg, and (ii) presence of a `missing_lead_spec` finding payload citing the goal and characterization dimensions.
2. **A clean ad-hoc-needed case** — pick a fixture where the original PREDICT invented a lead slug. New PREDICT either decomposes into catalog leads or emits a missing-lead declaration. GATHER decides reachability and either runs (`ad-hoc-missing-lead`) or early-exits (`missing_lead_unrunnable`). The post-mortem pipeline picks up the declaration as a catalog candidate. Measurable by `findings[*].missing_lead_spec` count and post-mortem extraction.
3. **A clean catalog-hit case** — pick a fixture where the original PREDICT correctly named a catalog lead. New PREDICT does the same with no emphasis (the lead's default characterization suffices). Verify the parser does not require emphasis. Measurable by absence of `:R routing.emphasis` in the output.

Without all three, the eval can only show "the new shape is producible," not "the new contract investigates better."

## Open Design Questions

1. **Catalog audit scope.** Read-and-confirm only, or full pass with edits? Bias: read-and-confirm for stage 1; defer edits to a follow-up unless an existing lead actively conflicts with the realigned terminology.
2. **Missing-lead finality.** Does it count toward the loop's lead budget? Bias: counts when GATHER actually runs it (`ad-hoc-missing-lead` with normal execution status); does not count when GATHER early-exits (`missing_lead_unrunnable`).
3. **Anchor consultations under the realigned model.** Authority anchors (`approved-monitoring-sources`, etc.) are *not* leads — they're a parallel surface today. Does the new contract change anything for them? Bias: no, they keep their own envelope; document the boundary explicitly so anchor consultations don't drift into the lead namespace.
4. **GATHER's authority to decline.** When no reachable system can produce a catalog lead's measurement, is `data_missing` the right finding, or should GATHER raise something stronger that escalates the run? Bias: `data_missing` for catalog leads and `missing_lead_unrunnable` for missing-lead declarations; revisit if eval shows leads silently failing.
