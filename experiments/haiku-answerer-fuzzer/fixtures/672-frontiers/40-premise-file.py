# Phase C synthesis — issue 672
# Deduplicated premise set from five lens frontiers (30-premises-{dependency,
# input-surface,lifecycle-state,adversarial-input,author}.md). 80 lens premises in,
# 53 kept out (35 standalone + 18 merges of 45 lens premises). See 40-premises.md for
# the full conservation accounting, the merged probe-obligation list (PO1-PO22),
# forks, and red flags. Each function below is a signature + situation docstring —
# no assertions; the answerer leaf fills in the assertion per premise.
#
# Trailing comments per premise:
#   # origin: <lens[, lens...]>        which lens(es) raised this premise
#   # fork: ...                        carried verbatim from the source frontier(s)
#   # probe: see POn[, POm]            mechanism fact this premise depends on


# ============================================================================
# get_closed_ticket's key argument shape space
# ============================================================================

def test_get_closed_ticket_key_empty_string():
    """get_closed_ticket is called with key set to the empty string rather than
    omitted — is an empty key a malformed call the model never should have made, or
    a well-formed request that simply won't resolve at the store?"""
    # origin: input-surface
    # fork: where the "missing or ill-formed key" boundary sits — does an empty
    # string count as ill-formed (no store attempt) or as a value the store gets to
    # reject?


def test_get_closed_ticket_key_whitespace_only():
    """get_closed_ticket's key is a string of only whitespace — the same open
    question as the empty-string case, a distinct shape worth its own situation."""
    # origin: input-surface
    # fork: same boundary as the empty-string case — is whitespace-only
    # "ill-formed"?


def test_get_closed_ticket_key_is_lexically_engineered():
    """the `key` argument to get_closed_ticket is a string engineered to diverge
    from a bare ticket id — embedded path separators, `..` segments, query-string
    delimiters, percent-encoded bytes, or a case/whitespace variant of a real
    ticket's key — while still parsing as a syntactically valid string argument the
    schema accepts."""
    # origin: adversarial-input, dependency (url-significant chars), input-surface
    # (reshapes request path; case variant of a real ticket), author
    # fork: which key grammar counts as "malformed" (validator-reject before any
    # store attempt) vs flows to the store — the design leaves "ill-formed key"
    # undefined. Route to §7. [author] — a third independent framing of the same
    # ill-formed-key boundary the two premises above also raise as forks; see Digest.
    # probe: see PO1, PO2.


def test_get_closed_ticket_key_pathologically_long():
    """get_closed_ticket's key is far longer than any real ticket identifier —
    thousands of characters."""
    # origin: input-surface


def test_get_closed_ticket_key_non_ascii():
    """get_closed_ticket's key contains non-ASCII characters."""
    # origin: input-surface


def test_get_closed_ticket_key_wrong_json_type():
    """the model's call supplies a non-string value (e.g. a number) where the key
    belongs."""
    # origin: input-surface


def test_get_closed_ticket_key_not_found_vs_wrong_status():
    """get_closed_ticket is called on a key that names no ticket at all in the
    store — a distinct situation from a key that names an existing, non-closed
    ticket. What, if anything, distinguishes the two failed results as seen by the
    model?"""
    # origin: input-surface


# ============================================================================
# Status field ambiguity
# ============================================================================

def test_get_closed_ticket_response_omits_status():
    """the store answers a get on a cited ticket with a 200 body that carries no
    status field at all — neither open nor closed — what must the tool do before
    treating any of that response's content as a confirmed-closed case?"""
    # origin: dependency, input-surface


def test_get_closed_ticket_status_third_lifecycle_state():
    """the ticket named by the key exists with a lifecycle state that is neither
    the closed value nor the open value — a third state the design never
    enumerated."""
    # origin: input-surface, author (author's framing also names the status-absent
    # case, already covered separately by test_get_closed_ticket_response_omits_status
    # above)
    # probe: see PO4.


def test_get_closed_ticket_status_case_or_whitespace_variant():
    """the ticket's state value uses a different letter case or has surrounding
    whitespace compared to the plain closed-state spelling."""
    # origin: input-surface
    # probe: see PO2.


# ============================================================================
# Response shape faults
# ============================================================================

def test_list_closed_tickets_malformed_store_response():
    """the ticket store's list endpoint answers with a body that parses as JSON but
    is not the expected tickets-list shape (a bare object with no tickets key, or a
    list of non-ticket values) — what must the tool return?"""
    # origin: dependency, input-surface (response not shaped like a collection —
    # a single object where an array belongs — the same fault)
    # probe: see PO3.


def test_get_closed_ticket_response_shape_mismatch():
    """the store's response to a single-ticket lookup is not shaped like one
    record — an array, a bare string, or a bare number where an object belongs."""
    # origin: input-surface


# ============================================================================
# Adversarial ticket content
# ============================================================================

def test_closed_ticket_content_names_the_open_ticket():
    """a ticket that is genuinely closed, and legitimately returned by
    get_closed_ticket/list_closed_tickets under require_closed=True, carries a
    free-text field — summary, description, or a comment — that itself references,
    quotes, or links the still-open ticket for the case under judgment."""
    # origin: adversarial-input
    # probe: see PO18.


def test_ticket_content_contains_envelope_delimiter_lookalike():
    """a closed ticket's free-text field contains a substring resembling the
    untrusted-envelope's own delimiter syntax — an attempt to terminate or nest the
    wrap early — rather than ordinary incident narrative."""
    # origin: adversarial-input, input-surface (content resembles envelope markers —
    # the same fault)
    # probe: see PO5.


def test_ticket_content_carries_model_directed_language():
    """a closed ticket's free-text field is phrased as an instruction or directive
    aimed at whatever reads it next, rather than as incident narrative addressed to
    a human analyst."""
    # origin: adversarial-input
    # probe: see PO5.


# ============================================================================
# list_closed_tickets' filter space (label/q)
# ============================================================================

def test_list_closed_tickets_no_filters_supplied():
    """list_closed_tickets is called with neither filter argument supplied — an
    unbounded closed-ticket listing."""
    # origin: input-surface


def test_list_closed_tickets_label_empty_string():
    """list_closed_tickets' label argument is an empty string rather than
    omitted."""
    # origin: input-surface
    # probe: see PO8.


def test_list_closed_tickets_q_empty_string():
    """list_closed_tickets' q argument is an empty string rather than omitted."""
    # origin: input-surface
    # probe: see PO8.


def test_list_closed_tickets_label_and_q_together():
    """both label and q are supplied on the same list_closed_tickets call."""
    # origin: input-surface


def test_list_closed_tickets_q_pathologically_long():
    """list_closed_tickets' q argument is a pathologically long substring
    filter."""
    # origin: input-surface


def test_filter_values_with_shell_and_url_metacharacters():
    """A list filter value (label or q) carries shell and URL metacharacters and
    flows through the host-side transport fork. What must be observable at the
    transport boundary, and in the query the store receives?"""
    # origin: author, input-surface (label content resembles a second filter
    # expression — is it read as opaque text, or does something re-interpret it —
    # the same reinterpretation concern)


def test_list_filter_crafted_to_cross_the_closed_boundary():
    """list_closed_tickets is driven with a `label`/`q` value chosen to be
    maximally broad, or chosen specifically to match text that appears only in the
    open in-flight ticket, rather than a value chosen to scope a genuine precedent
    search."""
    # origin: adversarial-input
    # probe: see PO18.


# ============================================================================
# list_closed_tickets' result faults
# ============================================================================

def test_list_closed_tickets_result_empty():
    """the closed-ticket listing matching the given filters comes back with zero
    tickets."""
    # origin: input-surface


def test_list_closed_tickets_response_contains_non_closed_item():
    """an item inside the listing carries a state other than the closed value,
    despite the listing itself being scoped to closed tickets — what does the judge
    see for that one item?"""
    # origin: input-surface, author (list result contains a non-closed ticket — the
    # same fault)
    # probe: see PO6.


def test_list_closed_tickets_response_contains_duplicate_key():
    """the listing contains the same ticket key more than once."""
    # origin: input-surface


# ============================================================================
# Oversized payloads (single record and result set)
# ============================================================================

def test_oversized_ticket_payload_or_result_set():
    """a single ticket record, or a list-tickets result set, is large — a long
    free-text field, many comments, or many matching tickets — well past the volume
    the design's own scale-dive treats as typical (a handful of reads per leg)."""
    # origin: adversarial-input, input-surface (single-record pathologically large
    # payload; listing result pathologically large — both folded in here), author
    # (oversized closed ticket payload, judge run's context survival)
    # fork: f1 (20-demands.md) — record-free-and-inline vs the query tool's
    # mirrored capture/truncation-note idiom; this situation is exactly what that
    # fork leaves open, and F4 (M4 mirrors the error seam, not the capture it's
    # entangled with) sharpens it. [adversarial-input]
    # fork: rides f1 — inline-in-full vs a truncated view is a size dimension the
    # pinned record-free reading leaves open. Route with f1 to §7. [author]
    # probe: see PO5.


# ============================================================================
# Ordering and repetition
# ============================================================================

def test_get_closed_ticket_without_a_prior_list_call():
    """the model calls get-closed-ticket for a case id it never obtained via
    list-closed-tickets in this turn — a seed offered outside the tool call, or a
    guessed id — is there any assumed ordering between the two tools, or does
    either stand alone?"""
    # origin: dependency, input-surface (called without a prior list in the run —
    # the same fault)


def test_get_closed_ticket_key_repeated_identical_calls_same_run():
    """the same key is requested by get_closed_ticket more than once within a
    single judge run — is a second identical read observably different from the
    first, or fully independent?"""
    # origin: input-surface, lifecycle-state (a long-running leg calling the same
    # closed ticket many times in a row — the many-calls variant of the same fault)
    # probe: see PO9.


def test_concurrent_closed_ticket_calls_in_one_turn():
    """the model issues more than one closed-ticket tool call as part of the same
    turn (list then get, or two gets for different cited cases), dispatched
    concurrently — do the concurrent host-side dependency reads share any state
    that could interleave incorrectly across them?"""
    # origin: dependency
    # probe: see PO7.


def test_ticket_flips_state_between_list_and_get():
    """A ticket the list call showed as closed is reopened before the follow-up
    get on the same key, inside one benign leg — the two tool results now disagree
    about the same cited case. What must be observable?"""
    # origin: author, lifecycle-state (a ticket seen in a list result changed by
    # the matching get — the same fault)


def test_ticket_status_transitions_around_the_read():
    """the case ticket that get_closed_ticket/list_closed_tickets is reading is
    not in a fixed state across the judge's run: its status transitions between
    open and closed at some point relative to the tool's own read — before,
    during, or shortly after — rather than being settled for the whole run the way
    a single fixed-state call assumes."""
    # origin: adversarial-input
    # probe: see PO17.


# ============================================================================
# The case-under-judgment's own ticket / self-citation
# ============================================================================

def test_case_under_judgment_own_ticket_state_at_judgment_time():
    """when a benign judge run begins, what is the actual lifecycle state of that
    same case's own ticket in the store — genuinely still open (in-flight), already
    closed (because the tracking run.py invocation that owns it finished and closed
    it before ever queuing this case for learning), or never created at all
    (tracking was off)? does the answer depend on anything the judge run itself can
    observe or control?"""
    # origin: lifecycle-state
    # probe: see PO14.


def test_judged_cases_own_ticket_already_closed():
    """The case under judgment's own ticket has already reached closed — its
    investigation finished and transitioned it; only a crashed run leaves it open —
    when the benign judge cites that very key to the closed-ticket read. What must
    be observable?"""
    # origin: author, dependency (a status check, not an identity check, against
    # the doc's "in particular the open in-flight ticket" framing), lifecycle-state
    # (a benign judge citing its own case as a closed precedent) — a 3-way
    # independent convergence: none of the three lenses saw the others' frontier.
    # fork: is the case-under-judgment's ticket inside O2's protected set once
    # closed, or does closed status make it a legitimately readable past case,
    # answer key and all? Status-only pinning cannot tell these apart; a key
    # exclusion could. Route to §7. [author]
    # fork: whether self-citation of one's own already-closed case is a risk worth
    # guarding against at all, versus harmless because the judge already has the
    # case's full context — the design never names this scenario, so nobody has
    # picked a side. [lifecycle-state]
    # probe: see PO14, PO19, PO21.


def test_ticket_key_that_was_never_opened_at_all():
    """the model queries a case id that never had a ticket opened for it (tracking
    was off, or the id is simply not a real case) — as distinct from a ticket that
    exists and is open, this key never entered the store's lifecycle at any point.
    does the tool's fault path treat "never existed" as its own situation, or does
    it collapse into the same handling as "exists but not closed"?"""
    # origin: lifecycle-state


# ============================================================================
# Content mutation over time
# ============================================================================

def test_cited_ticket_enriched_between_its_own_closure_and_a_later_citation():
    """a closed ticket the benign judge cites was stamped with seed-eligibility and
    a grounded resolution method by offline enrichment running well after it was
    first closed — does the tool's read reflect the ticket's state as of the
    citation (post-enrichment), as of its original closure (pre-enrichment), or is
    that undetermined by anything the design pins?"""
    # origin: lifecycle-state


def test_two_reads_of_the_same_closed_key_disagree_within_one_run():
    """the model calls get-closed-ticket on the same key twice within one judge run
    (or once via list-closed-tickets and again via get-closed-ticket), and an
    enrichment write to that ticket lands in the gap between the two calls — do the
    two reads of "the same" ticket return the same content, and would a difference
    read as a contradiction to the model?"""
    # origin: lifecycle-state


def test_cited_seed_state_changes_between_sample_and_confirm():
    """a case offered as a covering-policy seed earlier in this same offline run
    has since changed state at the store — reopened, edited, or its resolution
    rewritten — by the time the benign judge's tool reads it back to confirm the
    citation: which state does the confirm observe, and does the judge treat a
    changed-since-cited case any differently than one whose state never moved?"""
    # origin: dependency


def test_cached_open_payload_beside_live_refusal():
    """gather_raw holds an investigation-time payload of ticket K, fetched by the
    unpinned gather read while K was open; the live closed-ticket read refuses K;
    the benign judge has both in view for the same cited case. What governs "the
    store confirmed it" for the survived-verdict rule?"""
    # origin: author
    # fork: does a cached payload alone ever count as store confirmation, or must
    # confirmation come from the live closed-only read? The N7 carve-out keeps the
    # cache readable; it does not say which source the confirm rule trusts. Route
    # to §7.


# ============================================================================
# Concurrency
# ============================================================================

def test_concurrent_legs_no_toolset_bleed():
    """Both judge legs are built and run concurrently in one process over the one
    shared frozen definition — the benign-only capability must not surface on the
    concurrently built adversarial agent, nor the adversarial build strip it from
    the benign one. What must each leg's built schema observably contain?"""
    # origin: author, dependency (concurrent leg builds sharing no tool state),
    # lifecycle-state (concurrent legs over one shared run dir), adversarial-input
    # (concurrent leg builds' tool registration) — a 4-way independent convergence.
    # probe: see PO15.


def test_each_concurrently_running_leg_gets_its_own_independently_scoped_salt():
    """the benign and adversarial legs of the same case each mint their own bind,
    and each bind mints its own fresh salt, at close to the same wall-clock moment
    — is the untrusted envelope the benign leg's ticket tool wraps its returns in
    ever confusable with, or derivable from, anything the concurrently-running
    adversarial leg's own bind produces?"""
    # origin: lifecycle-state


# ============================================================================
# Wiring completeness and repeated builds
# ============================================================================

def test_closed_ticket_registration_reaches_every_benign_call_site():
    """every call site that builds a benign-direction judge run must end up with
    the same benign-only tool registration — does the new per-leg wiring reach all
    of them uniformly, or can one path build a benign judge whose ticket tools are
    silently absent?"""
    # origin: dependency, author (eval drivers building legs through the same
    # seams — the eval-driver-specific instance of the same completeness question)
    # probe: see PO16.


def test_per_leg_toolset_exact_beyond_the_new_bit():
    """The new per-leg override rebinds the toolset on the way to each leg's
    build — beyond the ticket pair's presence or absence, what must each leg's
    remaining tool complement (its existing read and bash capabilities included)
    observably be?"""
    # origin: author


def test_repeated_builds_of_the_same_leg_do_not_accumulate_registrations():
    """the same role's agent is built more than once in one process (an eval
    driver iterating over many cases, a retried leg) — each build goes through the
    new per-leg tools= override. does a second build of the benign leg register the
    two closed-ticket tools exactly once, or could repeated builds accumulate
    duplicate registrations?"""
    # origin: lifecycle-state


def test_wiring_bit_does_not_leak_from_one_built_leg_into_the_next():
    """one process builds a benign leg (closed_ticket_read=True) and, close in
    time, an adversarial leg (closed_ticket_read=False) — possibly for different
    cases, possibly interleaved across an eval sweep. does the tool-registration
    bit set on one built agent ever show up on a different build's agent that
    should not carry it?"""
    # origin: lifecycle-state, author (repeated leg builds across a long loop,
    # case-after-case alternation — the same cross-build-leak question; also
    # touches the accumulation premise above but is kept distinct from it since
    # that premise tests same-role repetition, not cross-role bleed)
    # probe: see PO16.


def test_taught_tool_names_match_registered_names():
    """The rewritten teaching surfaces name the closed-ticket tools; the built
    benign agent registers them under whatever names are finally confirmed; the
    model follows the prompt's names literally. What must hold between the taught
    names and the registered schema?"""
    # origin: author


def test_no_surface_teaches_the_tool_to_a_leg_that_lacks_it():
    """A prompt, skill, or doc surface visible to the adversarial leg — or to any
    non-judge role — instructs the closed-ticket tools that leg does not have.
    What must the per-audience census of teaching surfaces observably show?"""
    # origin: author
    # probe: see PO20.


# ============================================================================
# Config/env resolution
# ============================================================================

def test_typed_tool_config_env_divergence_from_cli_callers():
    """the store's config knobs (URL base, bastion host, timeout) are set only in
    the ambient host environment, a placement the two existing subprocess CLI
    callers see because they inherit the ambient process environment — but that
    the new in-process tool may or may not see depending on what environment it is
    handed: what config does the tool's read actually observe?"""
    # origin: dependency, author (the judge leg resolving the same store as the
    # investigation — the same config-resolution-consistency question, framed as
    # the judge's learning-run context vs. the investigation's writer context)
    # probe: see PO22.


def test_ticket_config_knob_value_changes_between_two_calls_in_one_run():
    """TICKET_URL_BASE / TICKET_BASTION_HOST / TICKET_TIMEOUT_SEC change (a
    per-key env override flips) between two closed-ticket tool calls inside the
    same judge run — does the second call observe the new value, or does something
    fixed earlier in the run's life keep using the value that was live at that
    earlier point?"""
    # origin: lifecycle-state
    # probe: see PO13.


# ============================================================================
# Dependency reliability
# ============================================================================

def test_repeated_store_failures_across_one_judge_run():
    """the ticket store stays down for an entire benign judge turn, and the model
    calls the closed-ticket tools several times across separate turns (once per
    cited seed) before giving up — does anything constrain or shortcut that
    repeated cost, or does each call pay full price independently?"""
    # origin: dependency


def test_store_breaker_open_when_judge_reads():
    """The store-protecting circuit breaker is already open — tripped by earlier
    gather-side or CLI-side faults in the same run — when the benign judge drives a
    ticket read. What must be observable?"""
    # origin: author, dependency (the bidirectional framing: does the judge's own
    # read cross-contaminate the breaker state another consumer relies on, and the
    # reverse — isolation, not just the open-breaker consequence)
    # fork: honor the breaker vs bypass it — the design's record-free mirror
    # silently picks bypass for a protection built to stop hammering a failing
    # store. Route to §7.
    # probe: see PO11.


def test_ticket_tool_call_in_flight_when_the_surrounding_run_is_cut_off():
    """the judge's own run ends — its request budget is exhausted, or it is
    cancelled from above — while a closed-ticket tool call's host-side subprocess
    is still running, held open only by its own mandatory inner timeout. what
    becomes of that in-flight call: awaited to completion, abandoned with the
    subprocess still running past its parent's own end, or something else — and
    does the run's own accounting of "one attempt" still hold if the attempt never
    got to finish?"""
    # origin: lifecycle-state, dependency (stage timeout during an in-flight store
    # call), author (a leg cancelled while transport is in flight) — a 3-way
    # independent convergence.
    # fork: awaited-to-a-stopping-point vs. cut loose is a real design choice
    # nobody has made — the two leave very different amounts of orphaned host-side
    # process behind
    # probe: see PO10.


# ============================================================================
# Re-judging and long-run consistency
# ============================================================================

def test_same_case_judged_a_second_time_after_an_earlier_judgment():
    """a case is judged more than once — a re-drain after a crash, a manual
    reprocessing via the direct `loop.py <run_dir>` entrypoint, an eval harness
    invoking the judge repeatedly over the same run_dir — each judgment is its own
    bind with its own fresh salt. does the second judgment's typed-tool behavior
    depend in any way on what the first judgment already did (which tickets it
    read, what it concluded), or is each judgment's view of the store independent
    of every earlier one?"""
    # origin: lifecycle-state
    # probe: see PO12.


# ============================================================================
# Operator-facing behavior
# ============================================================================

def test_operator_policy_cli_after_the_demo_scope_removal():
    """An operator runs the policy show/explain surface for the judge role after
    the bash plumbing and its demo scope are deleted. What must that operator
    surface observably still do?"""
    # origin: author
