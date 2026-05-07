---
title: Defender POC — lean single-agent investigation loop (paired with learning loop)
status: todo
groups: defender, critic-architecture, poc, prompt
---

**Goal.** Stand up a from-scratch **defender** agent under
`experiments/critic-architecture/` that pairs with the
adversarial/benign actor-reviewer learning loop described in
`experiments/critic-architecture/actor_reviewer_design.md`. The defender is the
*execution* side; the actor-reviewers are the *learning* side. Bitter pill:
**the learning loop is the value.** The execution loop should be as small and
unopinionated as we can make it without sacrificing the artifacts the learning
loop needs to mine.

This is a POC. No validation hooks. No state machine. Get the AI flow right
first; harden later.

## Design principles

1. **One agent, one prompt, one model.** Sonnet, medium thinking. The agent owns
   what is currently split across `contextualize`, `predict`, `analyze`, and
   `report`. Phases are *prompt-level discipline*, not separate subagents. We
   are basically extracting a ReAct loop into clearer named phases.
2. **Gather is the only delegation, and it's mandatory.** Every query goes
   through a gather subagent — query output is heavy in tokens and we don't
   want raw results in the main agent's context. Gather returns a **summary**
   of what it observed, not the raw payload. Raw output is written to disk
   under the run dir as a fallback the main agent can Read on demand.
3. **No preload. Knowledge is structured as skills.** Don't hand the agent a
   playbook + checklist + lead catalog up front. Domain knowledge lives as
   on-disk skills the agent loads when it decides it needs them. The defender
   prompt names the skills that exist; the agent invokes them as Skills, not
   as preloaded prose.
4. **Identification lives at GATHER, keyed by query template — not at PLAN.**
   Earlier designs leaned on a slugged lead catalog as the contract between
   PLAN-picks-a-lead and GATHER-runs-a-lead. In practice the agent always
   layers extra guidance, so the slug is ceremonial; worse, it labels intent
   rather than what actually ran. Drop it from PLAN entirely. PLAN emits a
   free-form lead description (goal + what to characterize). GATHER picks a
   **query template** from the per-system catalog, records the template id +
   parameter bindings, and *that* is the cross-case key the learning loop
   joins on. Rationale: the actor-reviewers' questions ("was XYZ in the lead
   set?", "what minimum query would have resolved this benignly?") are
   query-shaped, not intent-shaped, so aligning the key with the executed
   template makes the live and learning loops speak the same language.

   For **novel leads with no matching template**, GATHER authors a new
   template inline (kebab-case, system-prefixed, e.g.
   `wazuh.auth-events-by-host`), runs it, and writes the template back to
   the catalog before the run ends. The catalog grows organically with
   usage; we accept some near-duplicate templates early and normalize
   downstream when patterns stabilize. This keeps every executed query
   addressable by id from day one — the alternative ("uncategorized" tail)
   was simpler but pushed the problem onto the actor-reviewer corpus.

   Two things the catalog earns its keep on: (a) cutting data-source
   debugging out of the loop — which index holds auth events, field names,
   timestamp formats, NAT collapse, plus non-trivial shapes (joins,
   aggregations, regex pitfalls) — so the agent doesn't re-derive plumbing
   under time pressure; (b) anchoring reproducibility for the learning
   loop, since cases join cross-run on `(template id, bound params)` and
   ad-hoc one-off queries would not be corpus-queryable by what was
   actually measured.

   The lead-sequence schema does *not* carry a `source: catalog | minted`
   distinction or a per-dispatch `mode: single | composite` flag — both
   are factually derivable but serve no purpose in the gray-box flow.
   Per-dispatch `gather_status` is also dropped; what the gray-box actor
   needs is the dispatch (lead description) and the queries that ran,
   nothing more.
5. **Schemas only where the learning loop reads them.** PLAN must emit the
   ordered lead-contract sequence (the actor-reviewers replay this). Beyond
   that, drop schema scaffolding — no extraction contracts, no analyze grading
   units, no surviving/deferred_* tables, no report frontmatter validators.
6. **Dense language from day one.** The investigation log uses the dense
   `invlang` block surface (`​```invlang` fences with `:V` / `:E` / `:H` /
   `:L` / `:R` / `:T` blocks). Reason: deterministic retrieval downstream —
   the actor-reviewers and any later analytics need to query the corpus by
   structure, not regex over prose. We won't run the validator hook in the
   POC, but the surface is the same so artifacts are corpus-compatible.
7. **Bitter-pilled defaults.** Default to escalation when uncertain. The
   defender's job is to be honest about what it knows; the learning loop
   discovers what it should have known.

## Tools

Whitelist for the POC:

- `Read`, `Write`, `Edit` — agent's own working notes + investigation log + final report.
- `Grep`, `Glob` (or shell equivalents) — explore the workspace.
- `Bash` — light ad-hoc shell. Not for SIEM queries — those go through gather.
- `Task` (subagent) — gather subagents (mandatory for any data-source query).
- `Skill` — load on-demand knowledge skills.

No MCP, no special hooks. We are testing the core loop, not the harness.

## Loop shape

```
alert.json
   │
   ▼
DEFENDER (single agent, single prompt — phase-disciplined ReAct)

   ORIENT
     state what we want to determine; list the main unknowns; cheap
     prologue (who/what/when from the alert)

   PLAN  (renamed from PREDICT — more honest)
     choose the next lead(s); predict the observation that would resolve
     each unknown; emit the ordered lead contract entries the learning
     loop replays

   GATHER  (delegated)
     spawn a gather subagent per lead → returns a summary, writes raw to
     disk; main agent never sees raw query output

   ANALYZE  (in-line in the main agent, not a subagent)
     update the investigation log with what the summary actually showed;
     decide: continue (back to PLAN), pivot, or stop

   REPORT
     minimal: disposition + one-paragraph reason. The investigation log
     is the debug surface; the report is just the headline.

   ▼
investigation.md (dense invlang)  +  lead_sequence.yaml  +  report.md (minimal)
```

`lead_sequence.yaml` is the contract surface for the actor-reviewers. If the
agent can't project an ordered lead contract from its run, the run is unusable
for learning.

## Deliverables

1. `defender/SKILL.md` — the single-agent
   skill prompt (top-level skill the user invokes). Principles + phase prose +
   two or three worked examples (cherry-pick from existing `runs/` — bait,
   cron-noise, real brute force). Examples carry the shape; no checklists.
2. `defender/skills/` — domain knowledge as
   loadable skills. At minimum:
   - `gather/SKILL.md` — gather subagent prompt: take a lead description,
     pick the right query template, run it, summarize for the parent, write
     raw output to disk.
   - `gather/queries/` — query templates per system of record (the query
     catalog that *does* pay for itself).
   - `dense-language/SKILL.md` — invlang surface reference, loaded by the
     defender when authoring the investigation log.
   - Stubs for whatever environment skills the pilot fixtures need (e.g.
     `wazuh/SKILL.md`, `host-query/SKILL.md`).
3. `defender/run.sh` — wrapper that takes
   `alert.json`, sets up a run dir, invokes the defender, and captures
   `investigation.md` + `lead_sequence.yaml` + `report.md` +
   `tool_trace.jsonl` + `gather_raw/`.
4. `defender/lead_sequence_schema.md` — minimal
   yaml schema (mirror `actor_reviewer_design.md` §"Lead set projection",
   stripped of catalog-slug fields since we're not using a shared lead
   catalog).
5. Pilot runs against existing fixtures from
   `experiments/critic-architecture/fixtures/` plus 2–3 hard cases from
   `soc-agent/runs/` (bait, ambiguous, true-malicious-with-subtle-tell).
   Transcripts under `defender/results/`.

## Out of scope (explicit)

- Validation hooks (invlang validator, report precheck, state machine). Dense
  surface yes; gating no. Add gating after the loop is stable enough to know
  what's worth enforcing.
- Plugin packaging. Lives in `experiments/`, not `soc-agent/`.
- Knowledge-base authoring tooling. The actor-reviewer PR pipeline is the
  delivery mechanism; the defender just consumes whatever skills exist.
- Multi-round critic / debate. Separate experiment.
- Cost tuning. Sonnet medium-thinking; measure after behavior is right.

## Open questions (resolve during build)

- How does the gather subagent's summary stay faithful? Risk: summary loses
  the one field the main agent needed. Mitigation: raw on disk + main agent
  can Read it if the summary feels thin. Watch for cases where the agent
  should have re-read raw and didn't.
- Incremental vs end-of-run `lead_sequence.yaml`? Incremental is friendlier
  to crash recovery; end-of-run is simpler. Start end-of-run.
- How does PLAN signal "this lead is composite" without a slugged catalog?
  Probably just "here are N leads, run them as a batch" in the lead
  description — let GATHER decide whether to fan out. Watch what happens.
- How aggressive should GATHER be about minting new template ids vs reusing
  a near-match? Bias toward minting (option (a) per design principle 4); we
  can normalize duplicates later. Watch for slug sprawl in the first
  pilots — if every run mints fresh ids, the catalog isn't actually
  growing, just accumulating.
  - **Resolved (2026-05-07, Haiku probe @ 36-template synthetic catalog):**
    models reuse cleanly when a template's `## Goal` describes the
    measurement they want, even with different parameter bindings. They
    reach for "author new" mainly on **correlation leads** that no single
    primitive owns — handled now by an explicit §Composition leads
    protocol in `gather/SKILL.md` (run the primitives, characterize the
    join in the summary; do not mint a bridge template). Primitive
    templates name what they measure (`auth-events`), not the axis they
    happen to filter on (`auth-events-by-host`).
- How does the catalog stay searchable as it scales? Probe results: at
  ≤15 templates per system, read-all is fine. Past that, models grep —
  on **concept words** in `## Goal` body, not on controlled `data_tags`
  vocabulary (which they ignored even when the prompt highlighted it).
  Conclusion: drop `data_tags` and `params` from frontmatter, optimize
  `## Goal` body for keyword recall, keep per-system dirs as the routing
  prefix. Reflected in `defender/skills/gather/queries/SCHEMA.md`.

## Success criteria for the POC

- Runs end-to-end on at least 5 fixtures without manual intervention.
- Emits a `lead_sequence.yaml` the gray-box adversarial actor can consume —
  i.e., the contract surface from `actor_reviewer_design.md` works against
  real defender output.
- `investigation.md` parses as dense invlang (manual check; no validator yet)
  so the corpus query CLI could index it.
- Disposition quality is *no worse* than the current single-agent loop on the
  same fixtures, judged manually. We are not trying to beat the production
  loop; we are trying to produce a defender the learning loop can lift over
  time.
- Token / wall-clock cost is in the same order of magnitude as the production
  loop. If it's 5× more expensive, "lean" failed.
