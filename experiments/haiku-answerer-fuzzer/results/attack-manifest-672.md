# Adversarial re-judge manifest — fixture 672 (23 JUNK verdicts under attack)

### J1: test_closed_ticket_registration_reaches_every_benign_call_site
Situation: every call site that builds a benign-direction judge run must end up with
    the same benign-only tool registration — does the new per-leg wiring reach all
    of them uniformly, or can one path build a benign judge whose ticket tools are
    silently absent?
Judge's JUNK citation: This premise IS the gate-test obligation d22, explicitly minted in the resolutions ("d22_registration_reaches_every_call_site ... confirm all three drivers funnel through the identical stage-build call with no bypass"); the outcome (uniform benign-only registration across all three drives) is pinned, not undecided.
Observed reader spreads (independent panels, arm-stripped):
  - copy3 states settled, enumerating specific call sites (learning_loop, evals/run_judge_ab.py, judge_equivalence.py) that must and do reach the override uniformly; copy1 hedges/flags as unimplemented ("no tools parameter threads through run_stage/build_stage_agent today... uniform reach is future work"); copy2 partially hedges, conditioning the claim on "threading being complete."
  - copy1 states uniform reach as settled fact; copy2 and copy3 both flag that the required threading (JudgeWiring.closed_ticket_read through run_stage/build_stage_agent) is new/not-yet-implemented.

### J2: test_filter_values_with_shell_and_url_metacharacters
Situation: A list filter value (label or q) carries shell and URL metacharacters and
    flows through the host-side transport fork. What must be observable at the
    transport boundary, and in the query the store receives?
Judge's JUNK citation: O1 makes the read host-side in-process (no shell exists for shell metacharacters to reach), and c3 shows list_tickets urlencodes its params in the reused body (M2/N4); both the transport-boundary and store-query observables are pinned.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 and copy2 state settled ("transport URL-encodes params; not re-interpreted by shell, safe"); copy3 hedges ("unclear how shell/URL metacharacters are escaped or quoted at the transport fork boundary").
  - C1 and C3 state as settled that filter values are handled as opaque/URL-encoded strings, not reinterpreted; C2 hedges explicitly ("unclear whether... escaped... reinterpreted by the shell, or reach the store as-is")
  - copy1 and copy3 state metacharacters pass through safely as URL-encoded params, never shell-interpreted; copy2 hedges ("unclear whether opaque or reinterpreted").
  - copy2 and copy3 state settled that label/q are structured params with no shell composition on this in-process path (ruling out shell-boundary reinterpretation); copy1 hedges, explicitly leaving open whether metacharacters could reinterpret the command/URL boundary since the doc never states the escaping mechanism.

### J3: test_get_closed_ticket_key_not_found_vs_wrong_status
Situation: get_closed_ticket is called on a key that names no ticket at all in the
    store — a distinct situation from a key that names an existing, non-closed
    ticket. What, if anything, distinguishes the two failed results as seen by the
    model?
Judge's JUNK citation: O4 explicitly groups "refused (non-closed/404)" as one class surfacing "the fault detail," and M4 carries the adapter's own exit_code/detail through unchanged, so 404 and wrong-status arrive as distinct-detail faults of the same refused class by construction — the observable is pinned by reuse, not underdetermined.
Observed reader spreads (independent panels, arm-stripped):
  - c1: "design does not enumerate distinct fault types; both fail the same way, no distinction" | c2: "fault detail field DOES distinguish them: 'status=open' vs 'key not found'" | c3: "unclear whether fault details distinguish the two" | impact: whether the test can assert a distinguishing detail string for not-found vs wrong-status, or must assert only a generic failed result — changes test specifi
  - C2 states settled (the model can tell the two apart by the detail content); C1 hedges ("presumably" differs); C3 hedges explicitly ("unclear whether the model can actually distinguish the two").

### J4: test_get_closed_ticket_key_pathologically_long
Situation: get_closed_ticket's key is far longer than any real ticket identifier —
    thousands of characters.
Judge's JUNK citation: Fork A's three reject shapes are empty/whitespace/path-URL-significant (character properties, not length) and "everything else flows to the store opaquely"; a long-but-clean key is not in the reject set under any reading, so it flows to the store and folds into O4 — settled.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 states settled ("no size limit; tool passes the key to the store, surfaces whatever comes back"); copy2 and copy3 hedge ("unclear whether the tool validates length before passing to the store").
  - copy1 and copy3 state the key is accepted (no length limit, transport-bounded only); copy2 hedges ("unclear whether accepts, truncates, or rejects").

### J5: test_get_closed_ticket_response_omits_status
Situation: the store answers a get on a cited ticket with a 200 body that carries no
    status field at all — neither open nor closed — what must the tool do before
    treating any of that response's content as a confirmed-closed case?
Judge's JUNK citation: The get body's require_closed check (c2) requires a positive closed status before any content is treated as confirmed; an absent status field cannot satisfy "status == closed" so it is refused, and O4 guarantees no crash — both pinned by the reused body plus the security intent (only a confirmed-closed read confirms, Fork D).
Observed reader spreads (independent panels, arm-stripped):
  - copy1 and copy3 state the tool refuses/raises UpstreamFault when status is absent; copy2 hedges ("ambiguous or impossible... unclear what strategy").
  - copy2 states settled (must fail closed — a status-absent response can't affirmatively satisfy "is closed," so it must surface as a failed result); copy1 hedges harder, flagging that the doc doesn't even confirm this is treated as a fault at all versus silently passing through; copy3 leans toward copy2's reading but marks it an inference from O2's posture, not a doc statement.

### J6: test_get_closed_ticket_response_shape_mismatch
Situation: the store's response to a single-ticket lookup is not shaped like one
    record — an array, a bare string, or a bare number where an object belongs.
Judge's JUNK citation: M4's catch-all pins this — "an unmapped BaseException → the fault-class envelope, never an unwind"; a parse failure on an array/string/number surfaces as a salt-wrapped failed tool result, and ModelRetry is reserved for malformed calls only, so the observable is settled.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 and copy3 state settled (mismatch is a mapped fault — Transport/ConfigFault or AdapterFault — surfaces as a failed result); copy2 hedges ("unclear whether it triggers a structured parse error or unspecified behavior").
  - C1 and C2 state as settled that shape mismatches are caught and returned as a fault-class envelope; C3 hedges on the same question (deserialization error vs empty/default value)

### J7: test_get_closed_ticket_status_case_or_whitespace_variant
Situation: the ticket's state value uses a different letter case or has surrounding
    whitespace compared to the plain closed-state spelling.
Judge's JUNK citation: The closed comparison lives in the reused get body (c2: "status='open', not 'closed'"), unchanged per M2/N4, and Fork G's list re-check explicitly "mirror[s] the body check get already performs"; the outcome is determined by the inherited comparison (one behavior), not a live implementer choice.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 and copy3 state settled ("must match the exact closed value; case/whitespace variants are rejected, no normalization"); copy2 hedges ("unclear whether the tool normalizes or requires exact-case matching").
  - copy1 and copy3 state the check is strict string equality (variant fails); copy2 hedges ("doc does not specify... unclear what constitutes closed").

### J8: test_list_closed_tickets_label_and_q_together
Situation: both label and q are supplied on the same list_closed_tickets call.
Judge's JUNK citation: Both are optional filters forwarded to the reused list_tickets body (M1: "label/q filters"; c3 shows the params dict); supplying both simply places both in params — inherited param-building, no undecided outcome.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 and copy3 state settled (both permitted together; copy3 guesses "likely AND logic"); copy2 hedges ("unclear whether accepted with AND logic, rejected, or unspecified").
  - copy3 states the store ANDs the two filters (intersection); copy1 and copy2 hedge on precedence/interaction semantics.

### J9: test_list_closed_tickets_label_empty_string
Situation: list_closed_tickets' label argument is an empty string rather than
    omitted.
Judge's JUNK citation: Fork A's empty/whitespace rejection is scoped to the key (get); for list filters the value is forwarded to the reused list_tickets param-building, whose coalesce-vs-pass-through is inherited and whose observable consequence is negligible (empty substring ≈ no filter, same result set) — mechanism-level noise, not a meaningful fork.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 states settled ("empty label has no effect on filtering; returns all matching tickets"); copy2 and copy3 hedge ("unclear whether accepted or rejected").
  - copy1 and copy3 state empty-string label is accepted as a valid filter value; copy2 hedges ("unclear whether valid or malformed").
  - C3 states settled, grounded in PO8 (empty string and omitted take the same truthiness-filtered code path); C1 and C2 hedge as unaddressed/not stated.

### J10: test_list_closed_tickets_no_filters_supplied
Situation: list_closed_tickets is called with neither filter argument supplied — an
    unbounded closed-ticket listing.
Judge's JUNK citation: Both filters are optional in the two-tool schema (M1), so a no-filter call is a valid unbounded closed-only listing; nothing requires a filter, and Fork B's full query-tool mirror (truncation note + capture row) governs an oversized result — settled.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 and copy2 state settled ("unbounded listing permitted; returns all closed tickets"); copy3 hedges ("unclear whether omitting both filters is even allowed, or a validation error").
  - C1 and C3 state settled (omitting both filters is a valid call, returns an unbounded closed-only listing); C2 hedges that the doc doesn't even confirm label/q are optional.

### J11: test_list_closed_tickets_q_empty_string
Situation: list_closed_tickets' q argument is an empty string rather than omitted.
Judge's JUNK citation: Same as P10 — Fork A's empty rejection is key-only; an empty q forwards to the reused list_tickets, coalesce-vs-send is inherited and cosmetic (empty substring matches everything, identical result set) — mechanism-level noise.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 states settled (same shape as the label case, for q); copy2 and copy3 hedge ("unclear whether accepted or rejected").
  - copy1 and copy3 state empty-string q is accepted as a valid filter value; copy2 hedges ("unclear whether valid or rejected").
  - same pattern as label: C3 states settled via PO8's truthiness-filter grounding; C1 and C2 hedge as unaddressed.

### J12: test_list_closed_tickets_q_pathologically_long
Situation: list_closed_tickets' q argument is a pathologically long substring
    filter.
Judge's JUNK citation: A long q is a filter value forwarded/urlencoded by the reused list_tickets body (c3); Fork A's grammar covers the key only and imposes no length screen, and Fork B's truncation governs the response not the request — the request-side behavior is inherited/settled.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 states settled ("no size limit; passed to the store unchanged"); copy2 and copy3 hedge ("unclear whether the tool validates length or passes it through").
  - copy1 and copy3 state arbitrarily long q values are accepted (transport-bounded only); copy2 hedges ("unclear whether accepts, truncates, rejects").

### J13: test_list_closed_tickets_response_contains_duplicate_key
Situation: the listing contains the same ticket key more than once.
Judge's JUNK citation: The tool returns the store's listing after Fork G's per-item closed re-check; no obligation imposes uniqueness/dedup, so a duplicate simply passes through the thin wrapper — a determinate pass-through with no security/survival consequence, mechanism-level noise.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 states settled ("no dedup; duplicates flow through to the model"); copy2 and copy3 hedge ("unclear whether the store would ever return duplicates, or whether the tool dedupes").
  - copy3 states duplicates pass through unmodified, no dedup, no fault; copy1 and copy2 hedge ("design does not specify or forbid").

### J14: test_list_closed_tickets_result_empty
Situation: the closed-ticket listing matching the given filters comes back with zero
    tickets.
Judge's JUNK citation: For a list operation an empty match set is a normal successful empty result (c3's params-shaped read); M4 reserves ModelRetry/faults for malformed calls and adapter faults, not zero-match results, so empty→success is the only reading.
Observed reader spreads (independent panels, arm-stripped):
  - C1 and C2 hedge (unclear whether success, error, or some other outcome); C3 states as settled that an empty result is a successful, untrusted-wrapped empty list
  - copy1 and copy2 state settled (not a fault — a normal successful tool result with an empty list); copy3 hedges — doc doesn't spell out this exact scenario, leaving fault-vs-success technically open.
  - C2 states settled (a genuinely empty result is a legitimate success view, not a fault); C1 and C3 hedge (doc never explicitly says so, even though nothing suggests treating it as an error).

### J15: test_no_surface_teaches_the_tool_to_a_leg_that_lacks_it
Situation: A prompt, skill, or doc surface visible to the adversarial leg — or to any
    non-judge role — instructs the closed-ticket tools that leg does not have.
    What must the per-audience census of teaching surfaces observably show?
Judge's JUNK citation: The design is benign-only by construction (O3, M3, Fork f2) and M6 enumerates the teaching-surface rewrites (benign.md item 7, _cited_policy_read_section, _JUDGE_DENY_REASON) as benign-scoped; the intended census outcome — only benign-audience surfaces teach the tool — is pinned, with no live reading where the adversarial leg is legitimately taught an absent tool.
Observed reader spreads (independent panels, arm-stripped):
  - copy2 states settled (teaching text appears only on the benign-direction path, nowhere else); copy1 and copy3 hedge — the doc names only the two rewritten sites (benign.md item 7, _cited_policy_read_section), not an exhaustive per-audience census proving no other surface teaches the tool.
  - C1 states settled ("no such surface may exist"); C2 hedges that the doc doesn't guarantee a full census; C3 hedges strongly, naming a concrete gap — three teaching surfaces (docs/runtime-gates.md:42, skills/ticket/SKILL.md, docs/state-surface-adapters.md:113-114) outside every prior census that no premise actually tests for audience-scoping.

### J16: test_operator_policy_cli_after_the_demo_scope_removal
Situation: An operator runs the policy show/explain surface for the judge role after
    the bash plumbing and its demo scope are deleted. What must that operator
    surface observably still do?
Judge's JUNK citation: N6 pins that policy show does not display typed-tool presence ("it does not display the query bit today either"), O5 pins the CLI surface/exit codes survive, and O6 pins the residual grant set (cat + defender-sql); M6 removes policy_cli.py:52 as a latent wrong-script demo bug — the operator observable is fully determined.
Observed reader spreads (independent panels, arm-stripped):
  - copy3 states settled (operator CLI must continue to display the closed-ticket tools via ToolSet registration, not a hardcoded demo scope); copy1 and copy2 hedge ("does not specify what the operator surface shows after the demo scope is removed" / "unclear what operator-facing surface remains").
  - C1 and C3 state as settled that policy show/explain continues working unchanged aside from the demo-scope removal; C2 hedges (unclear whether it continues to work or is broken by the removal)

### J17: test_repeated_builds_of_the_same_leg_do_not_accumulate_registrations
Situation: the same role's agent is built more than once in one process (an eval
    driver iterating over many cases, a retried leg) — each build goes through the
    new per-leg tools= override. does a second build of the benign leg register the
    two closed-ticket tools exactly once, or could repeated builds accumulate
    duplicate registrations?
Judge's JUNK citation: M3/c12 pin the mechanism — each build is a fresh dataclasses.replace off the frozen shared def producing a new agent, with register_tools following that agent's defn.tools; a fresh agent per build registers its tools once by construction, so no accumulation is a determinate outcome (a test obligation, not an undecided fork).
Observed reader spreads (independent panels, arm-stripped):
  - copy2 and copy3 state settled (repeated builds register the tools exactly once, no accumulation, citing an existing test pinning the exact list+order); copy1 hedges ("brief notes the override isn't threaded through yet; design does not specify behavior for repeated builds").
  - copy1 states settled (no accumulation — each build registers exactly once via its own replace() call); copy2 states flatly that cross-build accumulation is "not addressed" by the doc; copy3 leans toward no-accumulation but flags the doc never walks through the repeated-build scenario.
  - C2 states settled ("no accumulation"); C1 and C3 hedge that the doc never states an explicit idempotency guarantee, only that the replace()-onto-frozen-base mechanism suggests it.

### J18: test_taught_tool_names_match_registered_names
Situation: The rewritten teaching surfaces name the closed-ticket tools; the built
    benign agent registers them under whatever names are finally confirmed; the
    model follows the prompt's names literally. What must hold between the taught
    names and the registered schema?
Judge's JUNK citation: Fork f2 fixes the names (bit closed_tickets; tools list_closed_tickets/get_closed_ticket) as "consistent with the doc, the assembled graph, and every demand name ... no renames propagate"; taught==registered is then a settled correctness invariant, not a live choice.
Observed reader spreads (independent panels, arm-stripped):
  - copy2 states settled (names must match; a mismatch would be a defect in M6's execution, not something the design tolerates); copy1 and copy3 hedge — the doc never pins the literal registered tool names or states name-parity as a checked invariant.

### J19: test_ticket_config_knob_value_changes_between_two_calls_in_one_run
Situation: TICKET_URL_BASE / TICKET_BASTION_HOST / TICKET_TIMEOUT_SEC change (a
    per-key env override flips) between two closed-ticket tool calls inside the
    same judge run — does the second call observe the new value, or does something
    fixed earlier in the run's life keep using the value that was live at that
    earlier point?
Judge's JUNK citation: M1 builds the VerbContext from ctx.deps, and Waiver 2 characterizes the config as "ctx.deps-sourced" diverging from "the ambient environment" — i.e. a fixed per-run snapshot; a mid-run ambient-env flip is not observed, both calls see the deps value fixed earlier in the run.
Observed reader spreads (independent panels, arm-stripped):
  - copy2 and copy3 state settled (config is re-read per call at fork time; the second call observes the new value); copy1 hedges ("may or may not see config changes made between calls").
  - C1 and C2 hedge (unclear whether config is read fresh or cached at bind time); C3 states as settled that VerbContext is built fresh per call, so the second call observes the new env value
  - copy1 states the tool reads the live environment at call time (late-bound); copy2 and copy3 hedge ("design does not specify early-bound vs late-bound").

### J20: test_ticket_key_that_was_never_opened_at_all
Situation: the model queries a case id that never had a ticket opened for it (tracking
    was off, or the id is simply not a real case) — as distinct from a ticket that
    exists and is open, this key never entered the store's lifecycle at any point.
    does the tool's fault path treat "never existed" as its own situation, or does
    it collapse into the same handling as "exists but not closed"?
Judge's JUNK citation: Same as P4 — O4 groups "non-closed/404" as one refused class and M4 carries the adapter's own detail through, so a never-opened key (404 fault) and an open ticket (require_closed fault) arrive as distinct-detail faults of the same class by construction; the observable is pinned by reuse.
Observed reader spreads (independent panels, arm-stripped):
  - c1: "no distinction between never-existed and non-closed" | c2: "fault detail DOES distinguish 'not found' from 'exists but not closed'" | c3: "design does not distinguish 'never existed' from 'exists but non-closed'" | impact: same as test_get_closed_ticket_key_not_found_vs_wrong_status — whether fault details are distinguishable changes test specificity. | rec: settle jointly with test_get_close
  - copy2 and copy3 state settled (collapses into the same not-closed/refused handling as O4's umbrella wording); copy1 hedges — calls it only "plausible," noting the doc never explicitly confirms the collapse.

### J21: test_ticket_status_transitions_around_the_read
Situation: the case ticket that get_closed_ticket/list_closed_tickets is reading is
    not in a fixed state across the judge's run: its status transitions between
    open and closed at some point relative to the tool's own read — before,
    during, or shortly after — rather than being settled for the whole run the way
    a single fixed-state call assumes.
Judge's JUNK citation: The tool performs a single live point-in-time read (M1), and the Fork D probe explicitly settled the temporal question ("an in_progress ticket is cached-but-refused with no race"); Fork C already excludes the case's own key entirely — there is no re-read/lock obligation and no live alternative reading.
Observed reader spreads (independent panels, arm-stripped):
  - copy1 and copy2 state directly that the tool observes state at its own read time with no design assumption of fixed state; copy3 opens with "unclear whether... is pinned by the design" before describing the same mechanism — hedging on whether the design actually settles this at all.
  - C1 and C2 hedge (unclear which point-in-time state is observed); C3 states as settled that the tool sees the value as of HTTP response receipt
  - copy2 and copy3 state the tool observes live state at the moment of the HTTP call (copy3 further notes mid-flight transitions are undetermined); copy1 hedges ("unclear whether protected against").

### J22: test_typed_tool_config_env_divergence_from_cli_callers
Situation: the store's config knobs (URL base, bastion host, timeout) are set only in
    the ambient host environment, a placement the two existing subprocess CLI
    callers see because they inherit the ambient process environment — but that
    the new in-process tool may or may not see depending on what environment it is
    handed: what config does the tool's read actually observe?
Judge's JUNK citation: Waiver 2 names this exact test: it "Converts the phase-C silent consensus (test_typed_tool_config_env_divergence_from_cli_callers) into an examined, human-ratified decline" — the design explicitly waives the divergence as out of scope, settling it.
Observed reader spreads (independent panels, arm-stripped):
  - c1: "does not specify whether tool sees ambient env or something set up differently; unclear if it matches the investigation's environment" | c2: "tool's env MAY DIVERGE from the ambient/investigation's writer context if per-key overrides were applied after investigation start" | c3: "this IS THE SAME environment the subprocess CLI callers inherit — no divergence" | impact: directly contradictory 
  - C3 states as settled that the tool observes the same ambient environment as the CLI callers; C1 leans toward alignment but frames it as a requirement rather than an observed fact; C2 hedges explicitly (unclear whether they match or diverge)

### J23: test_wiring_bit_does_not_leak_from_one_built_leg_into_the_next
Situation: one process builds a benign leg (closed_ticket_read=True) and, close in
    time, an adversarial leg (closed_ticket_read=False) — possibly for different
    cases, possibly interleaved across an eval sweep. does the tool-registration
    bit set on one built agent ever show up on a different build's agent that
    should not carry it?
Judge's JUNK citation: M3 pins isolation — "JUDGE_DEF's static default keeps the bit off, so the adversarial leg's agent is built without the tool," and c12's frozen-def + per-leg replace produces a new immutable def per build; no shared mutable state means no cross-leg leak by construction (a gate/regression test, not an undecided fork).

REAL 1 / JUNK 23
Observed reader spreads (independent panels, arm-stripped):
  - copy2 and copy3 state settled (no leak between builds); copy1 hedges ("implementation of leak-free isolation is future work; per-leg override not yet threaded through").
  - C2 states settled ("no leak by construction"); C1 and C3 hedge — C1 notes the doc names only the concurrent case explicitly, not the sequential/interleaved one; C3 flags this as requiring phase-D-grade confirmation (PO15), not doc-confirmed.
