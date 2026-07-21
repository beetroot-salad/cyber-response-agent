# Novel-fork adjudication verdicts — fixture 672 (24 premises)

P1 test_closed_ticket_registration_reaches_every_benign_call_site
VERDICT: JUNK
CITE: This premise IS the gate-test obligation d22, explicitly minted in the resolutions ("d22_registration_reaches_every_call_site ... confirm all three drivers funnel through the identical stage-build call with no bypass"); the outcome (uniform benign-only registration across all three drives) is pinned, not undecided.

P2 test_filter_values_with_shell_and_url_metacharacters
VERDICT: JUNK
CITE: O1 makes the read host-side in-process (no shell exists for shell metacharacters to reach), and c3 shows list_tickets urlencodes its params in the reused body (M2/N4); both the transport-boundary and store-query observables are pinned.

P3 test_get_closed_ticket_key_non_ascii
VERDICT: REAL
CITE: Fork A rejects keys "carrying path/URL-significant characters" but never defines that set for non-ASCII; live reading (1) non-ASCII are not reserved URI delimiters, so under "everything else flows to the store opaquely" they pass; live reading (2) get_ticket interpolates key into the URL path unescaped, so a char that cannot appear literally is "URL-significant" and retry-rejected — the resolution excludes neither.

P4 test_get_closed_ticket_key_not_found_vs_wrong_status
VERDICT: JUNK
CITE: O4 explicitly groups "refused (non-closed/404)" as one class surfacing "the fault detail," and M4 carries the adapter's own exit_code/detail through unchanged, so 404 and wrong-status arrive as distinct-detail faults of the same refused class by construction — the observable is pinned by reuse, not underdetermined.

P5 test_get_closed_ticket_key_pathologically_long
VERDICT: JUNK
CITE: Fork A's three reject shapes are empty/whitespace/path-URL-significant (character properties, not length) and "everything else flows to the store opaquely"; a long-but-clean key is not in the reject set under any reading, so it flows to the store and folds into O4 — settled.

P6 test_get_closed_ticket_response_omits_status
VERDICT: JUNK
CITE: The get body's require_closed check (c2) requires a positive closed status before any content is treated as confirmed; an absent status field cannot satisfy "status == closed" so it is refused, and O4 guarantees no crash — both pinned by the reused body plus the security intent (only a confirmed-closed read confirms, Fork D).

P7 test_get_closed_ticket_response_shape_mismatch
VERDICT: JUNK
CITE: M4's catch-all pins this — "an unmapped BaseException → the fault-class envelope, never an unwind"; a parse failure on an array/string/number surfaces as a salt-wrapped failed tool result, and ModelRetry is reserved for malformed calls only, so the observable is settled.

P8 test_get_closed_ticket_status_case_or_whitespace_variant
VERDICT: JUNK
CITE: The closed comparison lives in the reused get body (c2: "status='open', not 'closed'"), unchanged per M2/N4, and Fork G's list re-check explicitly "mirror[s] the body check get already performs"; the outcome is determined by the inherited comparison (one behavior), not a live implementer choice.

P9 test_list_closed_tickets_label_and_q_together
VERDICT: JUNK
CITE: Both are optional filters forwarded to the reused list_tickets body (M1: "label/q filters"; c3 shows the params dict); supplying both simply places both in params — inherited param-building, no undecided outcome.

P10 test_list_closed_tickets_label_empty_string
VERDICT: JUNK
CITE: Fork A's empty/whitespace rejection is scoped to the key (get); for list filters the value is forwarded to the reused list_tickets param-building, whose coalesce-vs-pass-through is inherited and whose observable consequence is negligible (empty substring ≈ no filter, same result set) — mechanism-level noise, not a meaningful fork.

P11 test_list_closed_tickets_no_filters_supplied
VERDICT: JUNK
CITE: Both filters are optional in the two-tool schema (M1), so a no-filter call is a valid unbounded closed-only listing; nothing requires a filter, and Fork B's full query-tool mirror (truncation note + capture row) governs an oversized result — settled.

P12 test_list_closed_tickets_q_empty_string
VERDICT: JUNK
CITE: Same as P10 — Fork A's empty rejection is key-only; an empty q forwards to the reused list_tickets, coalesce-vs-send is inherited and cosmetic (empty substring matches everything, identical result set) — mechanism-level noise.

P13 test_list_closed_tickets_q_pathologically_long
VERDICT: JUNK
CITE: A long q is a filter value forwarded/urlencoded by the reused list_tickets body (c3); Fork A's grammar covers the key only and imposes no length screen, and Fork B's truncation governs the response not the request — the request-side behavior is inherited/settled.

P14 test_list_closed_tickets_response_contains_duplicate_key
VERDICT: JUNK
CITE: The tool returns the store's listing after Fork G's per-item closed re-check; no obligation imposes uniqueness/dedup, so a duplicate simply passes through the thin wrapper — a determinate pass-through with no security/survival consequence, mechanism-level noise.

P15 test_list_closed_tickets_result_empty
VERDICT: JUNK
CITE: For a list operation an empty match set is a normal successful empty result (c3's params-shaped read); M4 reserves ModelRetry/faults for malformed calls and adapter faults, not zero-match results, so empty→success is the only reading.

P16 test_no_surface_teaches_the_tool_to_a_leg_that_lacks_it
VERDICT: JUNK
CITE: The design is benign-only by construction (O3, M3, Fork f2) and M6 enumerates the teaching-surface rewrites (benign.md item 7, _cited_policy_read_section, _JUDGE_DENY_REASON) as benign-scoped; the intended census outcome — only benign-audience surfaces teach the tool — is pinned, with no live reading where the adversarial leg is legitimately taught an absent tool.

P17 test_operator_policy_cli_after_the_demo_scope_removal
VERDICT: JUNK
CITE: N6 pins that policy show does not display typed-tool presence ("it does not display the query bit today either"), O5 pins the CLI surface/exit codes survive, and O6 pins the residual grant set (cat + defender-sql); M6 removes policy_cli.py:52 as a latent wrong-script demo bug — the operator observable is fully determined.

P18 test_repeated_builds_of_the_same_leg_do_not_accumulate_registrations
VERDICT: JUNK
CITE: M3/c12 pin the mechanism — each build is a fresh dataclasses.replace off the frozen shared def producing a new agent, with register_tools following that agent's defn.tools; a fresh agent per build registers its tools once by construction, so no accumulation is a determinate outcome (a test obligation, not an undecided fork).

P19 test_taught_tool_names_match_registered_names
VERDICT: JUNK
CITE: Fork f2 fixes the names (bit closed_tickets; tools list_closed_tickets/get_closed_ticket) as "consistent with the doc, the assembled graph, and every demand name ... no renames propagate"; taught==registered is then a settled correctness invariant, not a live choice.

P20 test_ticket_config_knob_value_changes_between_two_calls_in_one_run
VERDICT: JUNK
CITE: M1 builds the VerbContext from ctx.deps, and Waiver 2 characterizes the config as "ctx.deps-sourced" diverging from "the ambient environment" — i.e. a fixed per-run snapshot; a mid-run ambient-env flip is not observed, both calls see the deps value fixed earlier in the run.

P21 test_ticket_key_that_was_never_opened_at_all
VERDICT: JUNK
CITE: Same as P4 — O4 groups "non-closed/404" as one refused class and M4 carries the adapter's own detail through, so a never-opened key (404 fault) and an open ticket (require_closed fault) arrive as distinct-detail faults of the same class by construction; the observable is pinned by reuse.

P22 test_ticket_status_transitions_around_the_read
VERDICT: JUNK
CITE: The tool performs a single live point-in-time read (M1), and the Fork D probe explicitly settled the temporal question ("an in_progress ticket is cached-but-refused with no race"); Fork C already excludes the case's own key entirely — there is no re-read/lock obligation and no live alternative reading.

P23 test_typed_tool_config_env_divergence_from_cli_callers
VERDICT: JUNK
CITE: Waiver 2 names this exact test: it "Converts the phase-C silent consensus (test_typed_tool_config_env_divergence_from_cli_callers) into an examined, human-ratified decline" — the design explicitly waives the divergence as out of scope, settling it.

P24 test_wiring_bit_does_not_leak_from_one_built_leg_into_the_next
VERDICT: JUNK
CITE: M3 pins isolation — "JUDGE_DEF's static default keeps the bit off, so the adversarial leg's agent is built without the tool," and c12's frozen-def + per-leg replace produces a new immutable def per build; no shared mutable state means no cross-leg leak by construction (a gate/regression test, not an undecided fork).

REAL 1 / JUNK 23
