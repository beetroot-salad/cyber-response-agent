---
phase: C
leaf: classifier
issue: 672
status: complete
inputs:
  - {path: 40-premises.md, inventory_echo: {premises: 53, probe_obligations: 22, forks_flagged: 10, merges: 18, merged_lens_premises: 45, standalone_premises: 35}}
  - {path: 20-demands.md, inventory_echo: {demands: 22, claims: 24, background: 9, forks: 2}}
  - {path: 70-resolutions.md, inventory_echo: {decisions: 13, resolved: 13, unresolved: 0}}   # authoritative over any phase-C answer
inventory: {consensus: 41, forks: 11, silent_branches: 1, drops: 0}
cold_pass: {leaf: strong-cold, status: complete, moved_consensus_to_forks: 3}
seam_pass: {leaf: re-classification, status: complete, authority: 70-resolutions.md, decisions_changed: 0}
revised_by_seam: 35
---

## Digest

53 premises in → 53 dispositions out — 41 consensus (28 doc-pinned, 13 converged-on-silence), 11 fork premises
across eight §7 decisions, 1 silent branch, 0 drops; 41+11+1+0=53. Counts unchanged by this pass.
**§7 re-classification applied in place**: the human's 13 decisions (70-resolutions.md) FLIPPED demand #0's
provisional reading. Phase C answered against a record-free, breaker-isolated, seam-only mirror of the query tool
(F4); the resolved tool mirrors it FULLY — a recorded capture row, a bounded truncation-noted inline view, and
two-way breaker participation. **35 of 53 entries were written against the rejected contract and are rewritten**,
each marked `revised-by-§7` with the fork letter governing it: 23 consensus (15 doc-pinned, 8
converged-on-silence) plus all 11 fork premises and the silent branch. Beyond B/E, the propagated flips are
A (unvalidated key pass-through → a defined key schema rejecting before any store attempt), C/H (the case's own
key excluded at the boundary, extended to a self-key payload screen), D (cached `gather_raw` is context, never
confirmation), G (list-path server-trust → a client-side per-item status re-check), F (cut loose), f2 (names
pinned), plus one silence minted as the d22 census and one converted into Waiver 2. 18 entries are untouched —
wiring/registration/salt/toolset-shape, the business-refusal classes, and the inherited filter-semantics
silences, none of which cite the rejected mechanism. No human decision was changed; this pass propagates, it does
not re-decide. Marker count computed by grep over this file's own content.

## Red flags

- **§7 re-classification is DONE (this pass), not pending.** The prior red flag ("d0 re-classification is REQUIRED
  before phase E") is discharged here: every entry that cited F4's "no queries row, no capture row, no breaker
  trip" as settled mechanism has been rewritten to the resolved shape and marked `revised-by-§7`. Phase E must
  read the revised assertions; the pre-seam text survives only inside the fork blocks' verbatim relay, which is
  history, not contract.
- **F4's "seam-only mirror" note is stale and must be rewritten in the graph, never cited.** `runtime/query_tool.py`
  is now the mirror target for capture, truncation, and breaker machinery alike. Any phase-E test that reaches for
  F4's wording will re-import the rejected contract.
- **Two forks reversed their own recommendations (B, E).** The classifier recommended record-free+truncation and
  two-way isolation; the human chose full mirroring and full participation. The recommendation text is preserved
  verbatim for the record but is NOT the contract — each fork block's `Resolved (§7)` paragraph is.
- **A new fault taxonomy line falls out of Fork E and is now test-visible**: transport/malformed-response faults
  contribute to the breaker; business refusals (404, non-closed) do not. Entries on either side of that line were
  revised or left untouched accordingly; phase E should pin the line explicitly rather than infer it per-test.
- Carried forward, unchanged by this pass: the benign call-site wiring census is no longer a silence — §7 minted
  it as `d22` (see the revised entry). The answered copies live under the scratchpad shuffle dir only and must
  never be committed (a lingering copy matches pytest's `test_*.py` glob).

## Dispositions — consensus, doc-pinned (28)

- consensus: test_get_closed_ticket_key_not_found_vs_wrong_status (3/3) — one O4 "refused (non-closed/404)" class;
  failed tool result either way; no distinguishable fault code promised beyond free-text detail. Untouched by §7:
  a business refusal, not a fault — it does not contribute to the breaker. [d5, d7]
- consensus: test_get_closed_ticket_response_omits_status (3/3) — must not be treated as confirmed-closed: O2
  demands an affirmative closed check, so a status-less 200 fails into the refused/fault class.
  **revised-by-§7 [Fork E]**: the mechanism split this entry left unpinned (failed check vs unmapped fault) is no
  longer immaterial — under full breaker participation a failed *check* is a business refusal that does not trip,
  an *unmapped fault* does. The entry still asserts the failed result; phase E must pin which side of that line a
  status-less 200 lands on. [d4, d5]
- consensus: test_get_closed_ticket_status_third_lifecycle_state (3/3) — the design's binary is closed vs
  not-closed; any unenumerated state refuses like open, as a failed result (copy3 notes this is closed-only
  inference, not stated enumeration). Untouched by §7; the Fork D probe independently confirms the real store enum
  is `open|in_progress|closed`, which strengthens rather than changes this reading. [d5, PO4]
- consensus: test_list_closed_tickets_malformed_store_response (3/3) — O4/M4 catch-all: failed tool result
  carrying fault detail; never an unwind, never a retry. **revised-by-§7 [Fork E, Fork B]**: the fault now also
  **contributes to the breaker** (judge-side faults trip it) and the attempt still writes its capture row — so a
  second malformed response inside one run may fail fast with no transport attempt rather than paying full price.
  [d7, PO3]
- consensus: test_get_closed_ticket_response_shape_mismatch (3/3) — same catch-all: failed result, no crash.
  **revised-by-§7 [Fork E, Fork B]**: as above — the fault trips the breaker and the attempt is recorded. [d7]
- consensus: test_ticket_content_contains_envelope_delimiter_lookalike (3/3) — the defense is the fresh per-bind
  uuid4 salt making the wrap unforgeable. **revised-by-§7 [Fork H, Fork B]**: "no content filtering exists or is
  claimed" is now overbroad — no *general* filtering exists, but Fork H mints exactly one targeted screen (a closed
  ticket whose payload names the case's own key is refused), and Fork B's bounded view means a lookalike may arrive
  truncated with a note. The salt, not the delimiter text, is still what makes the wrap unforgeable. [d0, d11, PO5]
- consensus: test_ticket_content_carries_model_directed_language (3/3) — enters only inside the salted untrusted
  envelope (O7). **revised-by-§7 [Fork H]**: wrap posture is the whole defense *for this shape* — the only
  detection the design now owns is Fork H's self-key payload screen, which model-directed language that never
  names the case-under-judgment's key does not trip. [d11, PO5]
- consensus: test_list_closed_tickets_no_filters_supplied (3/3) — valid call shape; the require_closed pin is
  unconditional. **revised-by-§7 [Fork B, Fork G]**: the listing is no longer an "unbounded closed-only listing" —
  the success view is bounded with a truncation note and records a capture row, and each returned item passes the
  client-side closed re-check before the envelope. [d0, d3, d4]
- consensus: test_list_filter_crafted_to_cross_the_closed_boundary (3/3) — cannot cross: the closed pin is on the
  request, unconditional on filter content, and no status parameter exists in the schema.
  **revised-by-§7 [Fork G]**: the scoping question this entry deferred is answered — the response side IS inside O2's
  surface, so "safe-by-construction" now rests on the request pin *and* the per-item re-check, not on the pin
  alone. [d3, d4, PO18]
- consensus: test_list_closed_tickets_result_empty (3/3) — zero matches is a normal success view, not a fault.
  **revised-by-§7 [Fork B]**: the empty view still records its capture row — d0's amended shape makes the row
  unconditional on result size. [d0]
- consensus: test_get_closed_ticket_without_a_prior_list_call (3/3) — no ordering between the two tools.
  **revised-by-§7 [Fork A, Fork C]**: get no longer stands alone on *any* key however obtained — the key must
  first satisfy the defined key schema, and the case-under-judgment's own key is excluded at the tool boundary.
  Every other well-formed, non-self key stands alone. [d10]
- consensus: test_get_closed_ticket_key_repeated_identical_calls_same_run (3/3) — fully independent fresh live
  reads; no cache, no memo. **revised-by-§7 [Fork B, Fork E]**: F4's "no capture row" is superseded — each repeat
  writes its own queries-table row, and the repeats stay independent of each other but are no longer independent
  of shared breaker state. [d0, PO9]
- consensus: test_concurrent_closed_ticket_calls_in_one_turn (3/3, mechanism-implied) — per-call VerbContext off
  ctx.deps implies per-call independence; the doc pins no explicit concurrency guarantee.
  **revised-by-§7 [Fork B, Fork E]**: "no shared capture/breaker state" is superseded — concurrent calls share the capture
  sink and the breaker, so a fault on one sibling can fail-fast another. [PO7]
- consensus: test_ticket_flips_state_between_list_and_get (3/3) — each call is authoritative for its own moment;
  the get re-checks live and refuses (c2). **revised-by-§7 [Fork G]**: the list path re-checks too, so the flip is
  caught at whichever call observes the non-closed state; there is still no *cross-call* reconciliation or
  discrepancy detection between the two views. [d5]
- consensus: test_ticket_status_transitions_around_the_read (3/3) — one-live-check-per-call granularity;
  mid-request races are inherited transport behavior; no settled-for-the-run guarantee exists anywhere.
  Untouched by §7: Fork G adds a check *point* on list, not a second granularity for a single call. [PO17]
- consensus: test_ticket_key_that_was_never_opened_at_all (3/3) — collapses into the same refused (non-closed/404)
  handling; no distinct never-existed path. Untouched by §7: a well-formed key passes Fork A's schema and the
  refusal is a business refusal, not a breaker-tripping fault. [d5, d7]
- consensus: test_cited_ticket_enriched_between_its_own_closure_and_a_later_citation (3/3) — the read reflects
  live post-enrichment state; no snapshot-at-closure exists. Untouched by §7.
- consensus: test_two_reads_of_the_same_closed_key_disagree_within_one_run (3/3) — live uncached reads can
  genuinely disagree if a write lands between; no reconciliation mechanism; model-perceived contradiction
  unaddressed. Untouched by §7 (both reads now leave capture rows, which records the disagreement without
  resolving it — no assertion changes).
- consensus: test_cited_seed_state_changes_between_sample_and_confirm (3/3) — the confirm observes live state at
  confirm time; changed-since-cited gets no special case. **revised-by-§7 [Fork D]**: d16 is amended — only the
  live closed-only read satisfies "the store confirmed it", so a `gather_raw` payload of the same seed is context
  and cannot stand in for the confirm; "does not survive on that basis" governs uniformly and unbypassably. [d16]
- consensus: test_concurrent_legs_no_toolset_bleed (3/3) — the benign schema carries exactly the two tools, the
  adversarial schema carries none; replace() over the frozen JUDGE_DEF whose static default keeps the bit off;
  no shared mutable toolset state. Untouched by §7. [d1, d2, PO15]
- consensus: test_each_concurrently_running_leg_gets_its_own_independently_scoped_salt (3/3) — fresh uuid4 per
  bind; not derivable across legs. Untouched by §7. [d11]
- consensus: test_per_leg_toolset_exact_beyond_the_new_bit (3/3) — read+bash ToolSet bits identical on both legs;
  only closed_tickets varies (O6's narrowing changes what the bash grant reaches, not the bits). Untouched by §7.
  [d12]
- consensus: test_repeated_builds_of_the_same_leg_do_not_accumulate_registrations (3/3, mechanism-inferred) —
  each build starts from the frozen base and registers the pair exactly once; nothing accumulates.
  Untouched by §7. [d1]
- consensus: test_wiring_bit_does_not_leak_from_one_built_leg_into_the_next (3/3, mechanism-inferred) — each
  build's bit derives from its own JudgeWiring value via a fresh replace(); no cross-build carrier exists.
  Untouched by §7. [d1, d2, PO16]
- consensus: test_taught_tool_names_match_registered_names (3/3) — the taught surfaces must describe the
  actually-registered tools. **revised-by-§7 [Fork f2]**: the exact strings are no longer pending — capability bit
  `closed_tickets`, tools `list_closed_tickets` and `get_closed_ticket`; no renames propagate, so this entry is
  now assertable with literal names. [d15]
- consensus: test_no_surface_teaches_the_tool_to_a_leg_that_lacks_it (3/3) — M6's two rewrite sites are
  benign-scoped; teaching is benign-only by construction; the doc neither performs nor promises a cross-role
  census (see also 40-premises.md's stale-doc-surface red flag). Untouched by §7 as an assertion; note that §7's
  two design corrections (run.py:80's false "it is open"; skills/ticket/SKILL.md's non-existent statuses) enter
  M6's rewrite scope alongside it. [d2, d15, PO20]
- consensus: test_same_case_judged_a_second_time_after_an_earlier_judgment (3/3) — judgments independent: fresh
  bind, fresh salt. **revised-by-§7 [Fork B]**: "nothing persisted (N5, F4)" is superseded — the first judgment's
  capture rows persist and are visible in the audit trail. What stays unpersisted is anything the second
  judgment's *verdict* can read; the independence claim narrows to verdict inputs, not to the record. [PO12]
- consensus: test_operator_policy_cli_after_the_demo_scope_removal (3/3) — still compiles/displays the judge
  policy minus the demo scope (and its wrong-script bug); does not display typed-tool presence (N6).
  Untouched by §7. [d20]

## Dispositions — consensus, converged-on-silence (13)

The agreed assertion is that the doc takes no position: behavior is inherited or environmental, not pinnable as an
expected value. Kept as data for phase D/E (drive-only or probe-first territory), not as suite expectations —
**except where §7 converted a silence into a decision, marked below.**

- consensus: test_get_closed_ticket_key_pathologically_long (3/3 silence) — no length bound anywhere.
  **revised-by-§7 [Fork A]**: no longer plain pass-through — the key first meets the defined key schema, which
  bounds *shape*, not length, so a long-but-well-formed key clears the schema and reaches the store. The silence
  on length survives, but now as an explicit non-clause of a written grammar rather than an absence. [d10]
- consensus: test_get_closed_ticket_key_non_ascii (3/3 silence) — no charset handling described.
  **revised-by-§7 [Fork A]**: the defined key schema decides this rather than the question defaulting — non-ASCII
  carrying no path/URL-significant character clears the schema and reaches the store; percent-encoded bytes are
  rejected with a retry-class response before any store attempt. What the schema does not enumerate stays
  inherited. [d10]
- consensus: test_get_closed_ticket_status_case_or_whitespace_variant (3/3 silence) — status-string normalization
  is inherited, uncharacterized verb-body behavior. **revised-by-§7 [Fork G]**: no longer purely inherited on the
  list path — the client-side per-item re-check owns a status comparison this change writes, so what counts as
  "closed" for a case/whitespace variant is now this seam's decision. [PO2]
- consensus: test_list_closed_tickets_label_empty_string (3/3 silence) — inherited verb-body handling.
  Untouched by §7: Fork A's grammar is scoped to `key`, not to filters. [PO8]
- consensus: test_list_closed_tickets_q_empty_string (3/3 silence) — inherited verb-body handling.
  Untouched by §7, same scoping. [PO8]
- consensus: test_list_closed_tickets_label_and_q_together (3/3 silence) — allowed call shape; combination
  semantics inherited, unspecified. Untouched by §7.
- consensus: test_list_closed_tickets_q_pathologically_long (3/3 silence) — no bound described. Untouched by §7:
  Fork B bounds the *response view*, not the outgoing query.
- consensus: test_filter_values_with_shell_and_url_metacharacters (3/3 silence) — the pre-existing host-side
  transport's handling is inherited unchanged (copy3: the in-process call removes the model-text-to-argv assembly;
  the transport-layer risk predates this design). **revised-by-§7 [Fork A]**: "no new escaping introduced" is now
  true only of the *filter* path — Fork A's schema screens path/URL-significant characters out of `key` (which
  `get_ticket` interpolates into the URL path unescaped), while `label`/`q` keep riding `list_tickets`'
  urlencoding with no new screen. The asymmetry is chosen, not accidental, and this entry is the record of it.
- consensus: test_list_closed_tickets_response_contains_duplicate_key (3/3 silence) — no dedup described.
  **revised-by-§7 [Fork G]**: the response now passes a per-item check, but that check is status-only —
  duplicates survive it intact, so pass-through remains the reading, now as an explicit non-consequence of a
  filter this change owns rather than as an absence of any filter.
- consensus: test_case_under_judgment_own_ticket_state_at_judgment_time (3/3 silence) — the judge has no control
  over the state (N5). **revised-by-§7 [Fork C]**: the design now *does* observe the case's identity — the
  case-under-judgment's key is excluded at the tool boundary regardless of its state. The ticket's state stays an
  environmental fact the design neither pins nor observes; the exclusion does not depend on it, so O2's guard no
  longer fires conditionally here. [PO14]
- consensus: test_closed_ticket_registration_reaches_every_benign_call_site (3/3 silence-on-completeness) —
  intent universal (O1/O6), the carrier is the single M3 seam, per-site completeness asserted but nowhere
  demonstrated. **revised-by-§7 [gate obligation]**: the silence is discharged, not carried — §7 mints
  `d22_registration_reaches_every_call_site` / `test_closed_ticket_registration_reaches_every_benign_call_site`
  as a static census binding the three `drives` edges (`learning_loop`, `run_judge_ab`, `judge_equivalence` ->
  `invoke_judge`), `closed_tickets`, and `JudgeWiring.closed_ticket_read`. Discharge shape: all three drivers
  funnel through the identical stage-build call with no bypass, paired with d1/d2's per-leg behavior checks. This
  is now a suite expectation, not drive-only data. [d1, d22, PO16]
- consensus: test_typed_tool_config_env_divergence_from_cli_callers (3/3 silence) — parity between the
  ctx.deps-sourced env and the ambient environment the CLI subprocess callers inherit is unpinned.
  **revised-by-§7 [Waiver 2]**: converted into an examined, human-ratified decline — `Demand{form: waiver}`
  binding `ticket_store.access[subprocess-cli]`, out of scope for #672 (the two CLI callers run at operator
  trust; the live gap is timeout/env parity plus `ticket_seeds` trusting the server-side `--status closed` filter
  without the explicit flag; pre-existing, untouched by this design). Neither a suite expectation nor drive-only
  data: a recorded waiver. [PO22]
- consensus: test_ticket_config_knob_value_changes_between_two_calls_in_one_run (3/3 silence) — when config
  resolves relative to calls (per call vs fixed at bind/process start) is stated nowhere. Untouched by §7. [PO13]

## Dispositions — forks (11 premises, eight decisions) — relay text preserved verbatim; contract is each block's `Resolved (§7)`

**Reading order for phase E**: the `Situation`, `Spread`, `Impact`, and `Recommendation` paragraphs below are the
phase-C relay as it went to the human — history, not contract. The `Resolved (§7)` paragraph in each block is the
assertion the suite must carry. Forks B and E departed from their recommendation; do not read the recommendation
as the answer there.

### Fork A — where "ill-formed key" ends and a store-refusable value begins (phase-B flagged, 3 markers)

- fork: test_get_closed_ticket_key_empty_string — revised-by-§7 [Fork A]
- fork: test_get_closed_ticket_key_whitespace_only — revised-by-§7 [Fork A]
- fork: test_get_closed_ticket_key_is_lexically_engineered — revised-by-§7 [Fork A]

Situation: get_closed_ticket's key is the empty string, whitespace-only, or lexically engineered (path
separators, `..` segments, query delimiters, percent-encoded bytes, case/whitespace variant of a real key) —
each a syntactically valid string the schema accepts. M4 reserves ModelRetry for "malformed calls
(missing/ill-formed key)" and never defines ill-formed.
Spread (three copies converged on the same hole; listed as forks because phase B flagged all three):
- copy1: "unclear — M4 reserves ModelRetry for 'malformed calls (missing/ill-formed key)' but the doc never
  defines the ill-formed boundary."
- copy2: "Undetermined — this is the named fork. ... the doc doesn't say whether it is validator-rejected or
  passed through to the store as an ordinary lookup."
- copy3: "unclear — the third independent framing of the same undefined boundary."
Impact: d10 (test_malformed_key_model_retry) cannot pick its driving inputs or assert "no store attempt" until
the boundary is drawn; unvalidated pass-through decides whether path/query metacharacters in a key can reshape
the request the transport emits (the adversarial and dependency lenses' concern; PO1, PO2).
Recommendation: pin a minimal key grammar at the tool boundary — reject empty, whitespace-only, and any key
carrying path/URL-significant characters with ModelRetry before any store attempt; everything else flows to the
store opaquely and a refusal folds into O4. Rationale: the cheapest closure of the request-reshaping risk, keeps
the store authoritative on existence/status, and gives d10 three concrete driving shapes.

**Resolved (§7)** — recommendation taken, refined: the minimal key grammar is an **explicit, defined schema**,
not an ad-hoc validator body. All three premises assert the same shape — empty, whitespace-only, and any key
carrying path/URL-significant characters draw a retry-class response with **zero store attempts**, the rejection
landing *before* any store attempt; everything else flows to the store opaquely and a store refusal folds into
the O4 fault path. Amends d10 and gives it three concrete driving shapes. Closes the raw-interpolation reshaping
risk the adversarial and dependency lenses independently raised (`get_ticket` interpolates `key` into the URL
path unescaped; `list_tickets` urlencodes its params).

### Fork B — oversized payload: record-free-inline vs mirrored capture/truncation (= fork f1; phase-B flagged, 2 markers)

- fork: test_oversized_ticket_payload_or_result_set — revised-by-§7 [Fork B]

Situation: a single ticket record or a listing far past the scale dive's "handful of reads" assumption — does
the success view ride inline in full, or truncated with a note (and a recorded row), as the query tool does?
Spread (converged that the doc leaves it open):
- copy1: "Whether an oversized payload gets inlined in full or truncated is exactly the doc's named fork (f1)."
- copy2: "Undetermined — named fork (f1). ... no truncation, size-bounding, or record-free-and-inline decision is
  pinned by the doc."
- copy3: "neither the doc nor the brief says whether the query tool's truncation-note idiom (which lives
  alongside capture in that tool) is part of what M4 does or doesn't mirror."
Impact: decides what every success-path test asserts (d0 is provisional on exactly this), whether an audit trail
of judge ticket reads exists at all, and the judge run's context survival against an adversarially fat ticket.
Recommendation: keep the pinned record-free reading (no queries row — F4's seam-only mirror) but bound the inline
view with a truncation note. Rationale: capture would re-entangle the breaker F4 deliberately leaves out; an
unbounded inline payload is the one size risk three lenses independently raised; a bound keeps d0's envelope
assertion stable.

**Resolved (§7) — the recommendation was REJECTED.** Not record-free: **mirror the query tool FULLY.** An
oversized payload or result set yields a **recorded capture row** in the queries table AND a **bounded inline
view carrying a truncation note**. d0 loses `provisional: true` and asserts both. Consequences the suite must
carry: an audit trail of judge ticket reads now exists and is test-visible; `runtime/query_tool.py`'s
capture/truncation machinery is the mirror target; **F4's "seam-only mirror / no queries row" framing is
superseded — it needs rewriting in the graph, not citing.** This flip is the reason this whole pass exists.

### Fork C — the case's own already-closed ticket: readable precedent or protected asset? (phase-B flagged, 2 markers)

- fork: test_judged_cases_own_ticket_already_closed — revised-by-§7 [Fork C]

Situation: the case under judgment's own ticket has already transitioned to closed when the benign judge cites
that very key to the closed-ticket read.
Spread (the one fork with genuine outcome spread, not just converged silence):
- copy1: "by M2's mechanism, it reads through like any other closed ticket ... But O2's own wording singles out
  'the open in-flight ticket ... for the case under judgment' ... whether closed status genuinely legitimizes the
  self-citation (answer key and all) or the design simply failed to consider this case is exactly the flagged
  fork."
- copy2: "Undetermined — named fork (twice over). ... the doc names no key-exclusion mechanism that would keep
  protecting the case's own ticket once it transitions to closed."
- copy3: "per the doc's literal wording, once the case's own ticket transitions to closed it is NOT excluded ...
  a legitimately readable 'past case' like any other closed ticket ... This confirms rather than resolves the
  premise's fork."
Impact: decides whether d5/O2's tests need a self-key case, and whether a benign judge can satisfy "the store
confirmed it" by citing the very case it is judging — circular confirmation of its own survived verdict.
Recommendation: exclude the case-under-judgment's key at the tool boundary (a key exclusion alongside the status
pin; the leg's deps already identify its case). Rationale: a precedent search that can return the case itself
lets a case confirm itself — the status pin structurally cannot express this, and the three lenses that converged
here (dependency, lifecycle-state, author) all treated the self-read as the anomaly. The alternative
(accept + document) costs nothing mechanically but leaves the circular-confirmation path open.

**Resolved (§7)** — recommendation taken: **exclude the case-under-judgment's key at the tool boundary**, a key
exclusion alongside the status pin (the leg's deps already identify its case). The premise asserts a refusal on
the self-key **even when the ticket is genuinely closed** — the circular-confirmation path is closed structurally,
not left to the status pin, which cannot express it. Mints a new mechanism + demand. Grounding: three lenses
independently traced that the case's own ticket is normally already closed by judge time.

### Fork D — what satisfies "the store confirmed it": cached payload or live read? (phase-B flagged, 1 marker)

- fork: test_cached_open_payload_beside_live_refusal — revised-by-§7 [Fork D]

Situation: gather_raw holds an investigation-time payload of ticket K (fetched while K was open); the live
closed-ticket read refuses K; the judge has both in view for the same cited case.
Spread:
- copy1: "the doc does not say which of the two the 'store confirmed it' survived-verdict rule actually trusts."
- copy2: "Leans toward the live read governing, but not fully decided — named fork."
- copy3: "O1 ... leans toward the live read being the intended confirmation source — but the doc never states
  that a cached payload cannot itself satisfy 'the store confirmed it'."
Impact: decides d16's meaning. If a gather_raw cache can confirm, O2's closed-only guard is bypassable for
exactly the tickets it protects (any ticket open at gather time), and the rewritten teaching section (M6/d15)
must say so either way.
Recommendation: pin confirmation to the live closed-only read; cached payloads are context, never confirmation.
Rationale: matches O1's framing of the new mechanism as the confirmation path; the alternative makes O2
decorative; wire the sentence into the rewritten _cited_policy_read_section so d16 tests it.

**Resolved (§7)** — recommendation taken: **only the live closed-only read satisfies "the store confirmed it"**;
cached `gather_raw` payloads are context, never confirmation. The premise asserts that with both in view the
verdict follows the live refusal. The sentence is wired into the rewritten `_cited_policy_read_section` so d16
tests it. **Reachability was challenged by the human and settled by executed probe** (65-forkd-probe.md):
refuted — the store enum is `open|in_progress|closed` and the pin refuses every non-`closed` status, so an
`in_progress` ticket is refused live while cached with no race needed; gather reaches the ticket system
unrestricted and unpinned (`require_closed` defaults False on both verbs); the case's own close is opt-in behind
`--update-ticket` and is skipped on a driver crash. Verdict: structurally reachable, empirically unobserved — a
test, not a dismissal.

### Fork E — open circuit breaker: honor or bypass? (phase-B flagged, 1 marker; +1 premise annexed by the strong cold pass)

- fork: test_store_breaker_open_when_judge_reads — revised-by-§7 [Fork E]
- fork: test_repeated_store_failures_across_one_judge_run (moved from consensus by the strong cold pass) — revised-by-§7 [Fork E]

Situation: the store-protecting breaker is already open (tripped by gather-side or CLI-side faults) when the
benign judge drives a ticket read.
Spread (converged on the mechanism; the fork is the design's silence on intent):
- copy1: "the design, by omission, has the judge's read bypass the breaker entirely rather than honoring it."
- copy2: "each call to the new tool is independent of the breaker the query tool/CLI callers use. Whether that is
  the intended behavior or an unexamined gap is exactly the fork this premise names."
- copy3: "full isolation, not honoring, not contributing ... the doc names no rationale for the omission."
Impact: decides whether tests assert two-way isolation (an open breaker doesn't block the judge; judge faults
don't trip it) or honoring (open breaker → immediate failed result, no transport attempt). Changes d6/d8's
fixtures during a store outage.
Recommendation: keep two-way isolation and record it as a decided note beside O5. Rationale: judge reads are a
handful per leg, already bounded by the mandatory inner timeout and the run request budget; coupling them to
CLI-side breaker state imports exactly the cross-contamination the dependency lens warned about, for negligible
extra store protection.

Annexed premise (was consensus, 3/3; moved by the strong cold pass): test_repeated_store_failures_across_one_judge_run.
Its converged assertion — each call pays full price: no breaker participation, no memo, only the run request
budget bounds it — is this fork's isolation arm stated as a settled suite expectation. F4 does pin the
*contribute* direction (the tool writes no queries row and trips no breaker; O5 keeps breaker keying CLI-side),
but the *honor* direction is exactly what this fork leaves to §7, and during a store outage the honoring arm
changes this premise's expected value (fail-fast without a transport attempt vs full price per call — the d6/d8
fixture change named under Impact).
Spread (converged, quoted):
- copy1: "nothing in the design caches, memoizes, or circuit-breaks the judge's own repeated attempts within one
  run."
- copy2: "each call pays its own full transport cost (including its mandatory inner timeout) independently. The
  only overall bound is the run's general request budget."
- copy3: "no described backoff or discount for repeated failures — each call pays independently."

**Resolved (§7) — the recommendation was REJECTED.** Not two-way isolation: **full breaker participation —
honor and contribute**, following coherently from Fork B (the query tool's capture and breaker are the same
machinery). Two assertions the suite must carry:

1. `test_store_breaker_open_when_judge_reads` — an already-open breaker yields an **immediate failed result with
   NO transport attempt**. Not a bypass, not a full-price call.
2. `test_repeated_store_failures_across_one_judge_run` — the converged "each call pays full price: no breaker
   participation, no memo, only the run request budget bounds it" assertion is **REWRITTEN, not confirmed**.
   Repeated judge-side store failures within one run **trip the breaker**; subsequent reads then fail fast with
   no transport attempt and no inner-timeout cost. The run request budget is no longer the only bound.

Amends d6/d8 fixtures: a store outage now fails fast rather than paying full price per call. F4's "no breaker
trip" contribute-direction pin is superseded along with its no-queries-row pin. [d6, d8]

### Fork F — in-flight call when the run is cut off (phase-B flagged, 1 marker)

- fork: test_ticket_tool_call_in_flight_when_the_surrounding_run_is_cut_off — revised-by-§7 [Fork F]

Situation: the judge run ends (budget exhausted, cancelled from above) while a closed-ticket call's host-side
subprocess is still running under its own mandatory inner timeout.
Spread (converged mechanism, undecided design):
- copy1: "abandoned-but-still-running past its parent's own end, not awaited to a clean stop. Whether the run's
  'one attempt' accounting treats that abandoned, never-finished call as consumed is not decided by the doc."
- copy2: "the doc itself never commits to this outcome or states whether 'one attempt' accounting holds for a
  call that never finished."
- copy3: "an asyncio-level cancellation of the parent run does NOT stop the in-flight subprocess; it keeps
  running host-side until its own timeout ... Neither the doc nor the brief states whether this is the intended
  design or an accepted gap."
Impact: orphaned host-side docker-exec-curl processes outliving cancelled judge runs (bounded only by
TIMEOUT_SEC+10); what d9's CancelledError-propagation test may assert about the transport thread; whether attempt
accounting counts unfinished calls.
Recommendation: accept cut-loose and document it — CancelledError re-raises immediately (d9), the transport
thread dies on its own inner timeout, and an unfinished attempt still counts as the one attempt (d8). Rationale:
F5 says asyncio cannot kill the thread; awaiting a stopping point would hold every cancelled run open for up to
the full inner timeout for nothing, and the inner timeout already reaps the orphan.

**Resolved (§7)** — recommendation taken: **cut loose, documented.** Cancellation re-raises immediately (d9), the
transport thread dies on its own inner timeout, and **an unfinished attempt still counts as the one attempt**
(d8). No await-to-clean-stop: awaiting one would hold every cancelled run open for up to the full inner timeout
for no benefit.

### Fork G — a non-closed item inside a closed listing: trust the store or re-check the response? (moved from consensus by the strong cold pass; no phase-B marker)

- fork: test_list_closed_tickets_response_contains_non_closed_item — revised-by-§7 [Fork G]

Situation: the listing is scoped closed-only by the hard-coded request pin (M2/c3), yet the store's response
carries an item whose state is not closed — misfiltering, or a `q` value the store's inherited, uncharacterized
query semantics let cross the filter. What does the judge see for that item?
Spread (3/3 converged on the gap — no answer spread; moved because the converged answer embeds an undecided
O2-scoping decision, not a doc position):
- copy1: "The doc describes no response-side validation that would catch or strip a non-closed item the store
  nonetheless includes in a nominally-closed listing. Whether the design intends to trust the store's filtering
  completely or apply its own check is not stated — undecided by the doc."
- copy2: "it appears to trust server-side enforcement of the filter ... this sits in tension with O2's 'cannot
  obtain the content of any non-closed ticket' if the store misbehaves, but the doc doesn't resolve that tension
  — undetermined."
- copy3: "O2's safe-by-construction claim rests on the request-level pin, not on response-level checking, so this
  scenario tests a boundary the design doesn't explicitly discharge."
Why this is a decision against intent: O2 is worded as an outcome universal ("cannot obtain the content of any
non-closed ticket through the live ticket-store read") but scoped "over the surface this change controls" — and
whether the store's own filtering sits inside that controlled surface is exactly what the doc never says. The
two tools already differ: get's verb body demonstrably re-checks the fetched ticket's status (c2's UpstreamFault
on status=open); list's pin is on the outgoing request only (c3), so a misfiltered item rides the response
unchecked. Trust-the-store narrows O2 to request formation and needs an explicit N-note beside d18; a
client-side re-check keeps O2's outcome wording and needs a new mechanism and demand. The two arms mint
different suites; a silence classification lets the choice default invisibly.
Impact: whether phase D mints a response-side validation demand under O2 (today's O2 demands — d3, d4, d5, d18 —
are all request-side or route-census); this premise's own expected value (item served wrapped vs
dropped/faulted); the crafted-filter consensus entry's "safe-by-construction" rationale inherits the same
scoping answer.
Recommendation: add the client-side re-check — the list path verifies each returned item's status is closed and
drops or faults non-closed items before the envelope. Rationale: it mirrors onto list the body check get already
performs (c2), the status field is already in the payload, the check is a few lines at the seam this change
owns, and #338 calls closed-only "the entire security property" — an outcome-worded O2 that quietly means
"request-side only" is a narrowing that should be chosen, not defaulted. Trust-the-store is acceptable only as
an explicit N-note recording the store as trusted for filter enforcement. [PO6]

**Resolved (§7)** — recommendation taken: **add the client-side per-item re-check.** The list path verifies each
returned item's status is closed and **drops or faults non-closed items before the envelope**, mirroring onto
`list` the body check `get` already performs (c2). Server-side filter trust is no longer the assertion. O2's
outcome wording stays honest rather than silently narrowing to request formation. Mints a new mechanism + demand
under O2; the crafted-filter consensus entry inherits this scoping answer (response side IS inside O2's
controlled surface). [PO6]

### Fork H — a closed ticket's free text quotes the open in-flight ticket: does O2 cover carried content? (moved from consensus by the strong cold pass; no phase-B marker)

- fork: test_closed_ticket_content_names_the_open_ticket — revised-by-§7 [Fork H]

Situation: a genuinely closed ticket, legitimately returned under the pin, carries free text — summary,
resolution, a comment — that references, quotes, or links the still-open ticket for the case under judgment. The
answer key rides a record the status check rightly passes.
Spread (3/3 converged on the gap — no answer spread; moved because "no obligation names it" is one of two
readings of O2, and choosing between them is the human's decision):
- copy1: "still inside the untrusted envelope per O7, but not blocked or redacted. O2's status-only mechanism
  cannot distinguish or prevent this indirect exposure path, and the doc doesn't name or address this scenario
  anywhere in O2-O7 or M1-M6."
- copy2: "O7's untrusted-wrap still applies to the returned text (it's ticket-store content), but that wrap is a
  prompt-injection defense, not a confidentiality guard against quoted/leaked content."
- copy3: "a transitive exposure path O2's wording doesn't cover, since the tool never directly reads the
  non-closed ticket in that scenario ... no obligation names it, no mechanism discharges it."
Why this is a decision against intent: the security dive names the asset as "specifically the open in-flight
ticket (the answer key for the case under judgment)", and O2 exists to keep its content from the benign judge.
Read record-wise, O2 governs only which records are fetchable, and quoted content is out of scope; read
information-wise, "the content of any non-closed ticket" obtained "through the live ticket-store read" is
exactly what arrived. The copies converged on the record-wise reading stated as fact; the information-wise
reading says O2 names this path directly. The choice decides whether any mechanism is owed.
Impact: if information-wise, no existing mechanism discharges it (the wrap is O7 injection posture; no content
filtering exists or is claimed — see the delimiter-lookalike consensus entry) and a new demand or an explicit
accepted-risk note is owed; if record-wise, the spec should carry an N-note so O2's universal stops implying
coverage. Interacts with Fork C: the leg's deps already identify its case, so the one high-stakes instance — the
self-case's own key — is screenable at this seam.
Recommendation: scope O2 record-wise and record the residual as an explicit N-note — general free-text screening
for arbitrary open-ticket content is not implementable at this seam — and, if Fork C lands its key exclusion,
extend it to refuse a closed ticket whose payload names the case-under-judgment's own key, closing the one
instance (the answer key) whose identifier the seam actually knows. Rationale: bounded, implementable, aimed at
the named asset rather than a general confidentiality guard the design never promised. [PO18]

**Resolved (§7)** — recommendation taken: **scope O2 record-wise + targeted screen.** O2 governs which records
are fetchable; the residual transitive path is recorded as an explicit N-note. **Fork C's key exclusion is
EXTENDED to refuse a closed ticket whose payload names the case-under-judgment's own key** — closing the one
instance (the answer key) whose identifier the seam actually knows. General free-text screening is not
implementable at this seam and is not owed. The premise asserts both halves: a closed ticket quoting the
self-case key is refused; a closed ticket quoting any *other* non-closed ticket rides the salted untrusted
envelope unredacted, under the N-note. [PO18]

## Dispositions — silent branch (1, routes as a fork)

- silent-branch: test_get_closed_ticket_key_wrong_json_type — revised-by-§7 [silent branch / Fork A]

Situation: the model's call supplies a non-string value where the key belongs.
Spread — two settled, one hedged; looks resolved from inside either single reading:
- copy1 (hedges): "likely rejected at the schema/framework boundary, not stated outright ... nor does it say
  whether such a rejection routes through M4's ModelRetry ('missing/ill-formed key') or an earlier, separate
  framework-level validation error — inferred from the 'typed tool' framing, not a stated position."
- copy2 (settled): "per the doc's intent this should be rejected as a malformed call (the ModelRetry path), not
  passed to the store as if it were a valid key."
- copy3 (settled): "unambiguously ill-formed ... it must be rejected with ModelRetry before any store attempt,
  mirroring the query tool's validator."
Impact: d10's assertion target — a wrong-typed argument may never reach the tool body at all (framework schema
validation), in which case a body-level ModelRetry assertion tests the wrong layer and passes vacuously or fails
spuriously depending on harness plumbing.
Recommendation: pin d10 to the model-visible observable — a retry-class response and zero store attempts —
layer-agnostic, and let Fork A's boundary decision say which layer owns which shape. Rationale: the observable is
what all three readings share; the layer split is exactly what the hedge exposed.

**Resolved (§7)** — recommendation taken: **assert the model-visible observable.** d10 pins a **retry-class
response and zero store attempts**, layer-agnostic, so it holds whether the framework's schema validation or the
tool body performs the rejection. The test must not assert which layer rejected. Fork A's **defined key schema**
decides which layer owns which shape.

## Dispositions — drops (0)

No premise dropped. All 53 names appear exactly once across the four blocks above.

## Conservation

- Premises: 53 in (canonical 40-premise-file.py and each answered copy: grep -c over def lines = 53/53/53/53)
  = 41 consensus + 11 fork premises + 1 silent branch + 0 drops out.
- **§7 re-classification pass (this file, updated in place): 0 entries added, 0 dropped, 0 moved between blocks,
  0 human decisions changed.** The pass rewrites assertions only. 35 of 53 entries carry a `revised-by-§7`
  marker naming the fork that governs the rewrite; 18 are untouched and say so inline. 35 + 18 = 53. Counts
  computed by grep over this file's own content, not recalled.
  - Revised: 15 consensus doc-pinned, 8 consensus converged-on-silence, 11 fork premises, 1 silent branch.
  - Untouched: 13 consensus doc-pinned (wiring/registration/salt/toolset-shape, the business-refusal classes, the
    live-state-disagreement entries), 5 converged-on-silence (filter-semantics inherited from the verb bodies,
    which Fork A's key-scoped grammar does not reach, and the config-resolution-timing silence).
- Governing authority for the rewrite: 70-resolutions.md's 13 resolved decisions. The flip that forced the pass:
  demand #0's provisional record-free reading (F4's seam-only, breaker-isolated mirror) → Fork B's full mirror
  (capture row + bounded truncation-noted view) and Fork E's full breaker participation.
- Strong cold pass (earlier, this file, in place): 3 entries moved consensus → fork, none added, none dropped —
  test_repeated_store_failures_across_one_judge_run (doc-pinned → annexed to Fork E),
  test_list_closed_tickets_response_contains_non_closed_item (converged-on-silence → Fork G),
  test_closed_ticket_content_names_the_open_ticket (converged-on-silence → Fork H). Consensus 44→41 (doc-pinned
  29→28, converged-on-silence 15→13), fork premises 8→11, §7 decisions six→eight. All three were subsequently
  resolved at the human seam and carry `revised-by-§7` markers.
- Phase-B fork markers: 10 in → 10 accounted: Fork A carries 3 (one per premise), Fork B carries 2 (both markers
  on the oversized premise), Fork C carries 2 (author + lifecycle-state markers on the self-citation premise),
  Forks D/E/F carry 1 each. Forks G/H and Fork E's annexed premise carry none (unflagged in phase B; moved cold —
  the shared-blind-spot case the strong pass exists to catch). The silent branch was unflagged and adds none.
- Extract-phase forks f1/f2 (20-demands.md): f1 is Fork B (resolved: full mirror); f2 (naming) had no premise and
  was resolved at §7 — names kept — and is now propagated into the taught-names consensus entry.
- 70-resolutions.md's two waivers, one gate obligation, and two design corrections land as follows: Waiver 2 and
  the d22 census rewrite their corresponding converged-on-silence entries (marked); Waiver 1
  (`ticket_store.access[query-tool]`) binds no premise in this file and stays a demand-level record; the two
  design corrections (run.py:80's false "it is open"; skills/ticket/SKILL.md's non-existent statuses) fold into
  M6's rewrite scope and are noted on the teaching-surface consensus entry.
- Answered copies consumed from the session scratchpad shuffle dir (40-premise-file.copy{1,2,3}.py, seed-stamped,
  identical def sets verified by sorted-name diff); never committed.
