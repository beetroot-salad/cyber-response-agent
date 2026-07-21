# Adversarial re-judge verdicts — fixture 672 (attacking 23 JUNK citations)

J1 test_closed_ticket_registration_reaches_every_benign_call_site
VERDICT: UPHELD
WHY: d22 explicitly mandates all three drivers funnel through the identical stage-build seam "with no bypass"; an impl that leaves any benign call site's tools absent violates d22 and is not doc-consistent, so every conforming impl reaches uniform benign-only registration. The reader hedges are about implementation STATUS (is the threading built yet), not two valid impls diverging on the outcome — the design obligates uniform reach.

J2 test_filter_values_with_shell_and_url_metacharacters
VERDICT: UPHELD
WHY: The tool reuses the list_tickets body, which Fork A establishes urlencodes its params; urlencoding percent-encodes every shell/URL metacharacter (all are URL-unsafe), so a filter value cannot reinterpret the store query or any transport-fork command whether the fork uses argv or a shell. The citation's "no shell exists" is imprecise (a bastion/docker-exec subprocess does exist), but that gap opens no divergence — urlencoding neutralizes the value either way, so both a shell-string and an argv-list transport produce the same safe observable.

J3 test_get_closed_ticket_key_not_found_vs_wrong_status
VERDICT: FLIPPED
WHY: Impl A gives a 404 a distinct detail ("SOC-1 not found") vs a non-closed ticket's "status='open', not 'closed'" (distinguishable); Impl B maps both to one uniform "not a confirmable closed ticket" refusal (indistinguishable). O4 explicitly GROUPS "non-closed/404" as a single refused class and c2 only exhibits the wrong-status detail — neither mandates distinct 404-vs-status detail strings, so the citation's "distinct-detail by construction" is an implication the doc doesn't make.

J4 test_get_closed_ticket_key_pathologically_long
VERDICT: UPHELD
WHY: Fork A pins the get-key grammar to exactly three reject shapes (empty, whitespace, path/URL-significant chars) and "everything else flows to the store opaquely"; a long-but-clean key matches none of the three and is explicitly covered by "everything else flows," so every conforming impl forwards it and folds a store refusal into O4. Length is not the request-reshaping risk Fork A exists to close, so no doc-consistent impl adds a length screen at the key boundary.

J5 test_get_closed_ticket_response_omits_status
VERDICT: FLIPPED
WHY: Impl A's get body checks `status != 'closed'`, so an absent status (None) is refused; Impl B guards the re-check on presence (`'status' in body and body['status'] != 'closed'`) or trusts the require_closed=True request filter and passes the 200 content through as a success view. Both satisfy c2 (both refuse an explicit 'open' — the only case c2 exhibits), and the doc never pins absent-status handling, so fault-vs-passthrough genuinely diverges.

J6 test_get_closed_ticket_response_shape_mismatch
VERDICT: FLIPPED
WHY: Impl A reads `body['status']` on the array/string/number → TypeError → M4 catch-all → a parse-fault envelope; Impl B defensively isinstance-guards, treats a non-object as no confirmable record, and returns an empty/refused success-shaped result. M4's catch-all only governs RAISED exceptions — it doesn't mandate that a shape mismatch raises — so whether the model sees a parse-fault detail or a graceful non-confirmation (C3's exact split) is underdetermined.

J7 test_get_closed_ticket_status_case_or_whitespace_variant
VERDICT: FLIPPED
WHY: Impl A normalizes (`status.strip().lower() == 'closed'`) and accepts 'Closed'/' closed '; Impl B uses strict equality and rejects the variant. Both pass c2, which probed a clean lowercase 'open' value and thus never exhibits normalization behavior; the citation's "one determined inherited comparison" asserts a normalization outcome that c2 does not fix.

J8 test_list_closed_tickets_label_and_q_together
VERDICT: UPHELD
WHY: The tool forwards both label and q to the reused list_tickets body (c3 param-forwarding); supplying both simply places both in params, and any AND/OR interaction is the FIXED store's semantics, not an implementation choice of this design. Mutual exclusivity would be an unsanctioned added restriction, so all conforming thin-wrapper impls forward both — the reader divergence is over store semantics, not tool behavior.

J9 test_list_closed_tickets_label_empty_string
VERDICT: FLIPPED
WHY: Impl A coalesces the empty label to None (falsy → omitted → unfiltered set); Impl B forwards `label=` as an empty-string param, letting the store apply an empty-string filter (a possibly different or zero result set). The citation itself CONCEDES "coalesce-vs-pass-through is inherited" and only dismisses the divergence as "negligible" via an unproven store-semantics assumption (empty substring ≈ no filter) — that dismissal is an implication the doc doesn't make.

J10 test_list_closed_tickets_no_filters_supplied
VERDICT: FLIPPED
WHY: Impl A treats label/q as optional, so a no-filter call is a valid unbounded closed listing (Fork B truncates the oversized result); Impl B's schema requires at least one filter, so a no-filter call is a ModelRetry (malformed). M1 only NAMES label/q as filters and never states optionality (C2's exact flag), so required-vs-optional is a live implementer choice the citation asserts as pinned.

J11 test_list_closed_tickets_q_empty_string
VERDICT: FLIPPED
WHY: Same fork as J9 for q — Impl A coalesces empty q to None (unfiltered); Impl B forwards `q=` empty-string, giving a different store query and possibly a different result set. The citation concedes the inherited coalesce-vs-send fork and dismisses it only through an unproven "empty substring matches everything" store assumption.

J12 test_list_closed_tickets_q_pathologically_long
VERDICT: FLIPPED
WHY: Impl A forwards a pathologically long q to the store (transport-bounded only); Impl B's list schema imposes a maxLength and rejects it. Fork A's grammar and its "everything else flows opaquely" govern only the get KEY, not list filters, so the doc is silent on q-length — unlike the key (J4), no resolution pins list-filter flow-through, and both a length-screen and a passthrough are consistent.

J13 test_list_closed_tickets_response_contains_duplicate_key
VERDICT: UPHELD
WHY: The tool "returns the store's listing" after only Fork G's non-closed drop; duplicates are not non-closed, so the thin-wrapper character pins them to pass through unchanged. Adding a dedup step is an alteration the doc never sanctions (Fork G only adds closed-filtering), so no conforming impl removes duplicates — the outcome is a determinate passthrough.

J14 test_list_closed_tickets_result_empty
VERDICT: UPHELD
WHY: A zero-match list is a normal HTTP-200 empty array — neither a malformed call, an AdapterFault, nor a raised exception — so M4's fault reservations do not fire and the reused body returns an empty list wrapped as a success view. Fault is affirmatively EXCLUDED by M4, leaving success as the only outcome; the reader hedges note the doc doesn't spell it out, but the mechanism forces it.

J15 test_no_surface_teaches_the_tool_to_a_leg_that_lacks_it
VERDICT: FLIPPED
WHY: Impl A rewrites only M6's enumerated sites (benign.md item 7, _cited_policy_read_section, _JUDGE_DENY_REASON), leaving other tool-teaching surfaces visible to non-benign audiences (docs/runtime-gates.md, skills/ticket/SKILL.md, docs/state-surface-adapters.md — the last already surfaced as an incomplete-census correction in the resolutions); Impl B runs an exhaustive per-audience census and scrubs all of them. M6's list is a rewrite scope, not a completeness proof — the resolutions themselves EXPANDED it (adding SKILL.md) — so the citation's scope is narrower than the premise's per-audience census, and the two impls diverge on whether an adversarial-visible surface still teaches the tool.

J16 test_operator_policy_cli_after_the_demo_scope_removal
VERDICT: UPHELD
WHY: N6 explicitly pins that policy show does NOT display typed-tool presence ("it does not display the query bit today either"), O5 pins the CLI surface/exit codes survive, and O6 pins the residual grant set (cat + defender-sql); the operator observable is fully determined. copy3's "must display the closed-ticket tools" directly contradicts N6 — a reader error, not doc underdetermination.

J17 test_repeated_builds_of_the_same_leg_do_not_accumulate_registrations
VERDICT: UPHELD
WHY: Each build is a fresh dataclasses.replace off the frozen shared def producing a new def+agent, and register_tools populates that per-build agent's schema once (c12); agents cannot be cached across builds because each leg needs its own model/effort override, so re-registration onto a shared agent is impossible. No doc-consistent impl accumulates — the "no explicit idempotency guarantee" hedge is about doc prose, not two diverging impls.

J18 test_taught_tool_names_match_registered_names
VERDICT: UPHELD
WHY: Fork f2 fixes ONE set of names (bit closed_tickets; tools list_closed_tickets/get_closed_ticket) for both the teaching surfaces and the registration, "no renames propagate"; a conforming impl uses that one set everywhere, so taught==registered is forced. An impl registering a name different from what it teaches would violate Fork f2 (or the rewrite that teaches Fork f2's names), so it isn't doc-consistent — a mismatch is a bug, not an alternative impl.

J19 test_ticket_config_knob_value_changes_between_two_calls_in_one_run
VERDICT: FLIPPED
WHY: Impl A captures the config into ctx.deps once at run start, so both calls observe the run-start value and a mid-run flip is invisible; Impl B rebuilds VerbContext per call reading os.environ late, so the second call observes the new value. Waiver 2's "ctx.deps-sourced" names only the SOURCE (deps, not ambient) and does not fix WHEN deps reads env, so the citation's "fixed per-run snapshot" is an implication the doc doesn't make — readers split precisely on early-vs-late binding.

J20 test_ticket_key_that_was_never_opened_at_all
VERDICT: FLIPPED
WHY: Same fork as J3 — Impl A gives a never-opened key a distinct "not found" detail vs an open ticket's "not closed" detail; Impl B collapses both into one uniform refusal. O4's umbrella grouping of "non-closed/404" permits the collapse and c2 only exhibits the non-closed detail, so distinguishability is not pinned by reuse (the manifest itself directs settling this jointly with J3).

J21 test_ticket_status_transitions_around_the_read
VERDICT: UPHELD
WHY: The tool performs a single live point-in-time read (M1, Fork D "live closed-only read only") with no lock and no re-read obligation, so every conforming impl observes the store's status as of the one HTTP response — no valid impl reads a different instant. Fork D settled the temporal reachability and Fork C excludes the case's own key; the behavior is determined by the read-time status uniformly, so there is no divergence to exploit.

J22 test_typed_tool_config_env_divergence_from_cli_callers
VERDICT: FLIPPED
WHY: Impl A hands the tool a ctx.deps config matching the CLI callers' ambient env (no divergence); Impl B lets the tool's deps-sourced config diverge from the ambient env the subprocess callers inherit — the exact timeout/env-parity gap Waiver 2 names. Waiver 2 WAIVES this as out of scope: a waiver de-obligates parity, it does not DETERMINE the observed config, so both divergence and non-divergence are doc-consistent — the citation confuses "waived" with "pinned," and the readers' direct contradiction (c3 "same env" vs c2 "may diverge") reflects the genuine underdetermination.

J23 test_wiring_bit_does_not_leak_from_one_built_leg_into_the_next
VERDICT: UPHELD
WHY: The bit rides a per-leg dataclasses.replace off the FROZEN JUDGE_DEF (static default off), producing an independent immutable def per build with no shared mutable state, and agents can't be shared across legs (differing model/effort/bit); the adversarial build's def carries the bit off regardless of the benign build. Registration is per-agent (c7/c12), not a global table, so no cross-leg leak is possible in any conforming impl — sequential or interleaved.

TALLY: FLIPPED 12 / UPHELD 11
