# Novel-fork adjudication manifest — fixture 672 (24 premises)

### P1: test_closed_ticket_registration_reaches_every_benign_call_site
Situation: every call site that builds a benign-direction judge run must end up with
    the same benign-only tool registration — does the new per-leg wiring reach all
    of them uniformly, or can one path build a benign judge whose ticket tools are
    silently absent?

### P2: test_filter_values_with_shell_and_url_metacharacters
Situation: A list filter value (label or q) carries shell and URL metacharacters and
    flows through the host-side transport fork. What must be observable at the
    transport boundary, and in the query the store receives?

### P3: test_get_closed_ticket_key_non_ascii
Situation: get_closed_ticket's key contains non-ASCII characters.

### P4: test_get_closed_ticket_key_not_found_vs_wrong_status
Situation: get_closed_ticket is called on a key that names no ticket at all in the
    store — a distinct situation from a key that names an existing, non-closed
    ticket. What, if anything, distinguishes the two failed results as seen by the
    model?

### P5: test_get_closed_ticket_key_pathologically_long
Situation: get_closed_ticket's key is far longer than any real ticket identifier —
    thousands of characters.

### P6: test_get_closed_ticket_response_omits_status
Situation: the store answers a get on a cited ticket with a 200 body that carries no
    status field at all — neither open nor closed — what must the tool do before
    treating any of that response's content as a confirmed-closed case?

### P7: test_get_closed_ticket_response_shape_mismatch
Situation: the store's response to a single-ticket lookup is not shaped like one
    record — an array, a bare string, or a bare number where an object belongs.

### P8: test_get_closed_ticket_status_case_or_whitespace_variant
Situation: the ticket's state value uses a different letter case or has surrounding
    whitespace compared to the plain closed-state spelling.

### P9: test_list_closed_tickets_label_and_q_together
Situation: both label and q are supplied on the same list_closed_tickets call.

### P10: test_list_closed_tickets_label_empty_string
Situation: list_closed_tickets' label argument is an empty string rather than
    omitted.

### P11: test_list_closed_tickets_no_filters_supplied
Situation: list_closed_tickets is called with neither filter argument supplied — an
    unbounded closed-ticket listing.

### P12: test_list_closed_tickets_q_empty_string
Situation: list_closed_tickets' q argument is an empty string rather than omitted.

### P13: test_list_closed_tickets_q_pathologically_long
Situation: list_closed_tickets' q argument is a pathologically long substring
    filter.

### P14: test_list_closed_tickets_response_contains_duplicate_key
Situation: the listing contains the same ticket key more than once.

### P15: test_list_closed_tickets_result_empty
Situation: the closed-ticket listing matching the given filters comes back with zero
    tickets.

### P16: test_no_surface_teaches_the_tool_to_a_leg_that_lacks_it
Situation: A prompt, skill, or doc surface visible to the adversarial leg — or to any
    non-judge role — instructs the closed-ticket tools that leg does not have.
    What must the per-audience census of teaching surfaces observably show?

### P17: test_operator_policy_cli_after_the_demo_scope_removal
Situation: An operator runs the policy show/explain surface for the judge role after
    the bash plumbing and its demo scope are deleted. What must that operator
    surface observably still do?

### P18: test_repeated_builds_of_the_same_leg_do_not_accumulate_registrations
Situation: the same role's agent is built more than once in one process (an eval
    driver iterating over many cases, a retried leg) — each build goes through the
    new per-leg tools= override. does a second build of the benign leg register the
    two closed-ticket tools exactly once, or could repeated builds accumulate
    duplicate registrations?

### P19: test_taught_tool_names_match_registered_names
Situation: The rewritten teaching surfaces name the closed-ticket tools; the built
    benign agent registers them under whatever names are finally confirmed; the
    model follows the prompt's names literally. What must hold between the taught
    names and the registered schema?

### P20: test_ticket_config_knob_value_changes_between_two_calls_in_one_run
Situation: TICKET_URL_BASE / TICKET_BASTION_HOST / TICKET_TIMEOUT_SEC change (a
    per-key env override flips) between two closed-ticket tool calls inside the
    same judge run — does the second call observe the new value, or does something
    fixed earlier in the run's life keep using the value that was live at that
    earlier point?

### P21: test_ticket_key_that_was_never_opened_at_all
Situation: the model queries a case id that never had a ticket opened for it (tracking
    was off, or the id is simply not a real case) — as distinct from a ticket that
    exists and is open, this key never entered the store's lifecycle at any point.
    does the tool's fault path treat "never existed" as its own situation, or does
    it collapse into the same handling as "exists but not closed"?

### P22: test_ticket_status_transitions_around_the_read
Situation: the case ticket that get_closed_ticket/list_closed_tickets is reading is
    not in a fixed state across the judge's run: its status transitions between
    open and closed at some point relative to the tool's own read — before,
    during, or shortly after — rather than being settled for the whole run the way
    a single fixed-state call assumes.

### P23: test_typed_tool_config_env_divergence_from_cli_callers
Situation: the store's config knobs (URL base, bastion host, timeout) are set only in
    the ambient host environment, a placement the two existing subprocess CLI
    callers see because they inherit the ambient process environment — but that
    the new in-process tool may or may not see depending on what environment it is
    handed: what config does the tool's read actually observe?

### P24: test_wiring_bit_does_not_leak_from_one_built_leg_into_the_next
Situation: one process builds a benign leg (closed_ticket_read=True) and, close in
    time, an adversarial leg (closed_ticket_read=False) — possibly for different
    cases, possibly interleaved across an eval sweep. does the tool-registration
    bit set on one built agent ever show up on a different build's agent that
    should not carry it?
