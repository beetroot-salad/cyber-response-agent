---
phase: "7"
status: complete
inputs:
  - {path: 45-dispositions.md, inventory_echo: {forks: 8, fork_premises: 11, silent_branch: 1}}
  - {path: 20-demands.md, inventory_echo: {forks: 2}}   # f1 == Fork B; f2 (naming) resolved here
  - {path: 60-residue.md, inventory_echo: {waiver_candidates: 2, obligations: 1, pre_discharged: 12}}
  - {path: 65-forkd-probe.md, inventory_echo: {questions: 4}}
inventory: {decisions: 13, resolved: 13, unresolved: 0, demands_minted: 5, demands_amended: 4, waivers: 2, design_corrections: 2}
---

## Digest

13 decisions in, 13 resolved, 0 unresolved: 8 dispositions forks (A-H, covering 11 fork premises and
all 10 phase-B markers), 1 silent branch, 1 demand-frontier fork (f2 naming), 2 gate waiver candidates,
1 gate test obligation. Human took the recommendation on 10; departed on 2 (Fork B: mirror the query
tool FULLY, not record-free+truncation; Fork E: full breaker participation, following B) and refined 1
(Fork A: minimal key grammar as a defined schema). **Demand #0's provisional reading FLIPPED** (record-free
-> capture-row + truncation): SKILL.md §7 mandates re-running C's classification against the resolved
shape before phase E. Fork D was challenged by the human as unreachable; an executed probe (65-forkd-probe.md)
refuted the challenge — the store enum is open|in_progress|closed and the pin refuses all non-closed, so an
in_progress ticket is cached-but-refused with no race; gather reaches the ticket system unrestricted and
unpinned. Two design corrections fall out of that probe (judge/run.py:80 teaches "it is open", contradicted
by the close; skills/ticket/SKILL.md advertises two statuses the server never had). 5 demands minted,
4 amended, 2 waivers, 2 corrections. Counts computed by grep over this file's own decision entries.

## Red flags

- **d0 re-classification is REQUIRED before phase E** (SKILL.md §7: "the author must never receive answers
  written against a rejected contract"). Forks B and E jointly move the tool from the record-free,
  breaker-isolated shape phase C answered against, to full query-tool mirroring: capture row, truncation
  note, and two-way breaker participation. Every phase-C consensus entry that cited F4's "no queries row,
  no breaker trip" as settled mechanism is now answering against a rejected contract.
- Fork B's chosen arm re-entangles what the design deliberately scoped out. The author must treat the
  query tool's capture/truncation/breaker machinery (`runtime/query_tool.py`) as the mirror target, and
  F4's "seam-only mirror" note in the graph is now stale — it needs rewriting, not citing.
- Two teaching surfaces are wrong TODAY, independent of this change (probe side findings). They are
  design corrections, not new obligations; both were folded into the M6 rewrite scope below.

## Decisions

### Fork A — the ill-formed-key boundary
**Resolved: pin a minimal key grammar, defined as a schema.** Reject empty, whitespace-only, and any key
carrying path/URL-significant characters with a retry-class response *before any store attempt*; everything
else flows to the store opaquely and a refusal folds into the O4 fault path. The human refined the arm:
the grammar is to be an explicit, defined schema, not an ad-hoc validator body.
Amends d10 (gives it three concrete driving shapes); closes the raw-interpolation reshaping risk the
adversarial and dependency lenses independently raised (`get_ticket` interpolates `key` into the URL path
unescaped, while `list_tickets` urlencodes its params).

### Fork B — oversized payload / recording (= demand-frontier fork f1)
**Resolved: mirror the query tool FULLY** — recorded row AND truncation note. *Departs from the
recommendation* (record-free + truncation) and *flips demand #0's provisional pinned reading*.
Consequences: d0 loses `provisional: true` and asserts a capture row plus a bounded, truncation-noted
inline view; an audit trail of judge ticket reads now exists and is test-visible; the design's
"seam-only mirror" of the query tool (F4) is superseded.

### Fork C — the case's own already-closed ticket
**Resolved: exclude the case-under-judgment's key at the tool boundary.** A key exclusion alongside the
status pin; the leg's deps already identify its case. Closes the circular-confirmation path where a case
confirms its own survived verdict. Mints a new mechanism + demand.
Grounding: three lenses independently traced that the case's own ticket is normally already closed by
judge time, so the status pin alone structurally cannot protect it.

### Fork D — what satisfies "the store confirmed it"
**Resolved: the live closed-only read only.** Cached `gather_raw` payloads are context, never confirmation;
the sentence is wired into the rewritten `_cited_policy_read_section` so d16 tests it.
**Reachability challenged and settled by probe** (65-forkd-probe.md): the human argued the scenario cannot
arise because tickets the judge queries are closed by the system. Refuted — (1) the store enum is
`open|in_progress|closed` and the pin refuses every non-`closed` status, so an `in_progress` ticket is
refused live while cached, needing no race; (2) gather reaches the ticket system unrestricted
(`descriptor_catalog()` advertises it to every dispatch, `GATHER_DEF` has `query=True`, no per-lead pin)
and its read is unpinned (`require_closed` defaults False on both verbs); (3) the case's own close is
opt-in behind `--update-ticket` (default OFF) and is skipped entirely on a driver crash (`run.py:207`
sits after the try/finally). Verdict: structurally reachable, empirically unobserved — a test, not a
dismissal.

### Fork E — circuit breaker
**Resolved: full participation** — honor and contribute. An open breaker gives an immediate failed result
with no transport attempt; judge-side faults trip it. *Departs from the recommendation* (two-way
isolation), following coherently from Fork B: the query tool's capture and breaker are the same machinery.
Amends d6/d8 fixtures (a store outage now fails fast rather than paying full price per call) and resolves
the annexed premise `test_repeated_store_failures_across_one_judge_run` — its converged "each call pays
full price, no breaker participation" assertion is **rewritten** by this arm, not confirmed.

### Fork F — in-flight call at run cutoff
**Resolved: cut loose, documented.** Cancellation re-raises immediately (d9), the transport thread dies on
its own inner timeout, and an unfinished attempt still counts as the one attempt (d8). Awaiting a clean
stop would hold every cancelled run open for up to the full inner timeout for no benefit.

### Fork G — a non-closed item inside a closed listing
**Resolved: add the client-side re-check.** The list path verifies each returned item's status is closed
and drops or faults non-closed items before the envelope — mirroring onto `list` the body check `get`
already performs. Keeps O2's outcome wording honest rather than silently narrowing it to request
formation. Mints a new mechanism + demand under O2.

### Fork H — a closed ticket's free text quotes the open in-flight ticket
**Resolved: scope O2 record-wise + targeted screen.** O2 governs which records are fetchable; the residual
transitive path is recorded as an explicit N-note. Fork C's key exclusion is extended to refuse a closed
ticket whose payload names the case-under-judgment's own key — closing the one instance (the answer key)
whose identifier the seam actually knows. General free-text screening is not implementable at this seam
and is not owed.

### Silent branch — wrong-JSON-type key
**Resolved: assert the model-visible observable.** d10 pins a retry-class response and zero store attempts,
layer-agnostic, so it holds whether the framework's schema validation or the tool body rejects. Fork A's
grammar decides which layer owns which shape.

### Fork f2 — tool and capability-bit naming
**Resolved: keep the proposed names.** Capability bit `closed_tickets`; two model-facing tools
(`list_closed_tickets`, `get_closed_ticket`). Consistent with the doc, the assembled graph, and every
demand name already written. No renames propagate.

### Waiver 1 — `ticket_store.access[query-tool]` (the N7 carve-out)
**Resolved: waive as out of scope for #672.** Mint `Demand{form: waiver, cites: [r1, r1-extended]}` binding
`ticket_store.access[query-tool]`. Gather's route to the same verb bodies defaults `require_closed=False`
and persists payloads to `gather_raw`. Recorded as an examined decline, not a silence.
**Follow-up warranted**: the Fork D probe makes this the live route by which non-closed ticket content
reaches the judge. Extending closed-only parity onto the query-tool path is a design change beyond this
issue — file it as its own issue at handoff.

### Waiver 2 — `ticket_store.access[subprocess-cli]` (consumer parity)
**Resolved: waive as out of scope for #672.** Mint `Demand{form: waiver}` binding
`ticket_store.access[subprocess-cli]`. The two CLI callers run at operator trust; the live gap is
timeout/env parity between `ctx.deps`-sourced config and the ambient environment, plus `ticket_seeds`
trusting the server-side `--status closed` filter without the explicit flag. Pre-existing, untouched by
this design. Converts the phase-C silent consensus
(`test_typed_tool_config_env_divergence_from_cli_callers`) into an examined, human-ratified decline.

### Gate test obligation — registration reaches every benign call site
**Resolved: mint as a static census test.** `d22_registration_reaches_every_call_site` /
`test_closed_ticket_registration_reaches_every_benign_call_site`, binding the three `drives` edges
(`learning_loop`, `run_judge_ab`, `judge_equivalence` -> `invoke_judge`), `closed_tickets`, and
`JudgeWiring.closed_ticket_read`. Discharge shape: confirm all three drivers funnel through the identical
stage-build call with no bypass, paired with d1/d2's existing per-leg behavior checks. Not the
per-entrypoint investigation drive (too heavy); not folded into d1 (the `tools=` threading is brand-new
plumbing whose per-site completeness has never been demonstrated).

## Design corrections (from the Fork D probe; fold into M6's rewrite scope)

1. **`defender/learning/pipeline/judge/run.py:80`** asserts to the model that the in-flight ticket "is open"
   — contradicted by the unconditional close. This line sits inside `_cited_policy_read_section`, which M6
   already rewrites; the rewrite must not carry the false claim forward. Wrong TODAY, independent of #672.
2. **`defender/skills/ticket/SKILL.md`** advertises two ticket statuses the server has never had (the real
   enum is `open|in_progress|closed`). Add to M6's teaching-surface census — which also answers the phase-C
   synthesis red flag that no premise bound teaching-surface currency. Wrong TODAY, independent of #672.

## Conservation

| Incoming | Count | Resolved | Unresolved |
|---|---|---|---|
| 45-dispositions forks (A-H) | 8 | 8 | 0 |
| 45-dispositions silent branch | 1 | 1 | 0 |
| 20-demands fork f2 (naming) | 1 | 1 | 0 |
| 60-residue waiver candidates | 2 | 2 | 0 |
| 60-residue test obligation | 1 | 1 | 0 |
| **Total** | **13** | **13** | **0** |

The 11 fork *premises* behind the 8 fork decisions and all 10 phase-B fork markers are covered
transitively (A:3 premises/3 markers, B:1/2, C:1/2, D:1/1, E:2/1, F:1/1, G:1/0, H:1/0).
60-residue's 12 pre-discharged entries are unchanged by §7 and stay in the artifact's `gate:` block.

Outgoing to phase E: 5 demands minted (Fork C key exclusion, Fork G list re-check, Fork H self-key
payload screen, 2 waivers, d22 census — counted as 5 minted + 1 obligation-derived), 4 demands amended
(d0 de-provisionalized and re-shaped; d10 given its grammar and observable; d6/d8 re-fixtured for
breaker participation; d16 given the live-read-only rule), 2 design corrections folded into M6.
