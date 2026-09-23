"""#1047 O2 — the ticket lane decides per exit class, from a source the box cannot write.

TODAY the lane asks one question: is there a readable `report.md`? If yes it closes the ticket
on whatever disposition the report carries; if no it leaves the ticket open and the missing
report IS the escalation (`ticket_writer.py:119-123`). That worked while "no report" and "the
environment was unreachable" were the same state. Since #992 they are not: the two forced-close
exits now write a host `unresolved` report (claim h1, narrowed by ddd41b88), so a run the
circuit breaker aborted and a run that spent its request budget are told apart by nothing the
lane can see — and an operator gets `unresolved` where they needed "escalate, the environment
appears unreachable".

THE FIX: the lane branches on the EXIT CLASS, handed to it in-process.

    aborted                        -> the breaker's escalation note; the ticket stays open
    request-limit, retry-exhausted -> the record, proposing the host's forced `unresolved`
    budget, store                  -> no call at all
    None, or a value with no arm   -> the record, proposing the report's disposition

UNDER #767 EVERY ARM IS A COMMENT. The host's client cannot transition a case — closing is a
person's act, and that is what lets the store's `closed` mean "a person reviewed this" to
every later reader — so what used to be "close `unresolved`" / "close off the report" is now
the RECORD: one comment proposing the disposition for the person who closes. The note and the
record are the two comment kinds, told apart by their body (`S.TicketCall.is_note` /
`is_record`); `transitions` is the census every scenario expects empty.

§7 RESOLUTIONS APPLIED HERE AS SETTLED:

* **F3 reading A (human)** — the exit class arrives as a PARAMETER from `run.py`, exactly as
  `enqueue_curation` already takes one twelve lines later (`run.py:589`). Reading B — recover
  the case id from `session_store_pointer.json` and open the store — was rejected: that pointer
  file is inside the box's own rw bind, and it is precisely the box-writable input O1's
  security dive forbids as a decider of "was this run cut short".
* **F4 reading A (human) + F-D (auto, CONFIRMED by round-2 probe #30, EXECUTED)** — the note is
  a real second call to the operator's ticket system, and its ticket identity is `run_dir.name`:
  the probe drove the real `open_case_ticket` with NO `report.md` on disk and it produced the
  same key string the close addresses in its path. `read_case_record`'s report gate is
  POSITIONAL, not semantic — `case_id = run_dir.name` is computed three lines past a
  `require_report` that raises over it.
* **F7 (auto)** — an exit value the table does not name takes the report-driven fallback, not a
  fail-safe leave-open: a future vocabulary member would otherwise silently stop closing
  tickets that used to close.
* **F-I (auto)** — the lane calls `normalized_truncated_by` on its own parameter as its FIRST
  act rather than trusting the caller.
* **F-K (auto)** — a forced-close-set exit whose own forced close FAILED (so no report exists)
  takes the same leave-open-with-escalation shape as the aborted arm, rather than closing
  `unresolved` off a payload that does not exist.
* **F-L (auto)** — a failed note call never breaks the run, and its outcome is written into
  `ticket_write.json` either way.
* **F-R (auto)** — an unconfigured lane stays silent for every exit class, aborted included: an
  operator with no ticket config has already opted out, and inventing a side channel for one
  arm would override that choice.
* **F-A reading B (human, §7 round 2)** — the leave-open arms DEFER to a genuine model close.
  A run whose model had already decided when the cut landed closes off its own verdict.
* **F-Q (waived)** — `record_case_ticket` has no dedupe key today and the new note call inherits
  that; fixing it needs a second mechanism O2 does not ask for.

RED against `59bdea44`: the lane takes `(run_dir, deps)` and branches on nothing but the
report's readability.
"""
from __future__ import annotations

import json

from defender.tests import _spec1047 as S


# ---------------------------------------------------------------------------------------
# one arm per exit class
# ---------------------------------------------------------------------------------------


def test_an_aborted_run_leaves_its_ticket_open_with_the_escalation(tmp_path):
    """A run whose exit class is `aborted` leaves its ticket open and records the breaker's
    escalation — the environment appears unreachable, escalate with the visibility gap named —
    rather than transitioning the ticket to any resolution.

    The note is addressed to the SAME ticket key the open leg wrote under, which is what makes
    the arm reachable at all for a run with no `report.md`: the key is `run_dir.name` and the
    report gate that hides it is positional (fork F-D, round-2 probe #30, EXECUTED). Both legs
    are driven here so the shared namespace is observed rather than assumed.

    `closed_before_cut` is False — the model never decided — which is what makes leaving the
    ticket open the right answer (F-A reading B); its complement is pinned one test below."""
    run_dir = S.closed_run_dir(tmp_path, report=False)
    opened = S.open_ticket(run_dir)
    fake = S.record_ticket(run_dir, truncated_by="aborted", closed_before_cut=False)

    assert fake.records == [], (
        "an aborted run recorded a verdict; the environment was unreachable, so nothing "
        "about the case was settled and there is nothing to propose to a person")
    assert len(fake.notes) == 1, f"the aborted arm made {len(fake.notes)} note calls, not one"
    note = fake.notes[0]
    assert note.method == "POST"
    assert note.key == opened.calls[0].body["key"], (
        f"the note addressed ticket {note.key!r} while the open leg wrote "
        f"{opened.calls[0].body['key']!r} — two namespaces, so the note lands on no ticket")
    body = note.text().lower()
    assert "aborted" in body, f"the note does not name the exit class: {note.text()!r}"
    assert "escalate" in body, (
        f"the note does not carry the escalation ask: {note.text()!r} — leaving the ticket "
        "open without one is silence, not an escalation")


def test_a_request_limit_run_records_unresolved(tmp_path):
    """A run whose exit class is `request-limit` records `unresolved` off the host's forced
    report — a comment proposing it, for a person to close on; never a transition.

    The model spent what it had and settled nothing, which is what `unresolved` records; the
    host wrote that report itself (claim h1's forced-close set), so the payload exists."""
    run_dir = S.closed_run_dir(tmp_path, disposition="unresolved")
    fake = S.record_ticket(run_dir, truncated_by="request-limit")
    assert fake.transitions == [], "the request-limit arm transitioned the ticket"
    assert len(fake.records) == 1, "the request-limit arm made no record"
    assert "unresolved" in fake.records[0].text()
    assert fake.notes == [], "the request-limit arm also raised an escalation note"
    assert (S.receipt(run_dir) or {}).get("ok") is True


def test_a_retry_exhausted_run_records_unresolved(tmp_path):
    """A run whose exit class is `retry-exhausted` records `unresolved` off the host's forced
    report — the second member of the forced-close set, same shape as its sibling.

    The second member of the forced-close set, driven separately rather than parametrized with
    its sibling: `forced_close_set_does_not_decide_the_ticket` is about the set NOT deciding
    anything, and a single loop over the set would make that demand's own subject unobservable
    here."""
    run_dir = S.closed_run_dir(tmp_path, disposition="unresolved")
    fake = S.record_ticket(run_dir, truncated_by="retry-exhausted")
    assert fake.transitions == []
    assert len(fake.records) == 1
    assert "unresolved" in fake.records[0].text()
    assert fake.notes == []


def test_a_budget_kill_leaves_its_ticket_open_and_makes_no_call(tmp_path):
    """A run killed by the budget leaves its ticket open and makes no call at all — the
    missing report IS the escalation, and that stays true once the lane keys on the exit
    class.

    Driven WITH a report present as well as without, because that is the whole content of the
    demand: once the lane keys on the exit class, the presence of a report may not resurrect a
    record for a class that is not a finding about the case."""
    for report in (False, True):
        run_dir = S.closed_run_dir(tmp_path / f"report-{report}", report=report)
        fake = S.record_ticket(run_dir, truncated_by="budget")
        assert fake.calls == [], (
            f"report={report}: the budget arm made {fake.calls} — it must make no call at all")
        assert S.receipt(run_dir) is None, "the budget arm wrote a receipt for a call it never made"


def test_a_store_fault_leaves_its_ticket_open_and_makes_no_call(tmp_path):
    """A run ended by a store fault leaves its ticket open and makes no call, as it does
    today.

    `store` is also the arm where the store column and the driver's summary disagree: on the
    setup-failure path (`driver/__init__.py:586-606`) the summary says `store` and
    `_flush_run_end` is never reached, so the column was never stamped. Under F3 this lane
    reads the summary, so it is right on that path where a store-reading lane would be
    wrong."""
    for report in (False, True):
        run_dir = S.closed_run_dir(tmp_path / f"report-{report}", report=report)
        fake = S.record_ticket(run_dir, truncated_by="store")
        assert fake.calls == [], f"report={report}: the store arm made {fake.calls}"


def test_a_run_that_was_not_cut_short_still_records_off_its_report(tmp_path):
    """A run with no exit class recorded records its ticket from the report — the ordinary
    completed run is untouched by this change.

    The disposition on the wire is the model's own, not the host's: an ordinary run is the case
    this whole piece must not move."""
    run_dir = S.closed_run_dir(tmp_path, disposition="malicious")
    fake = S.record_ticket(run_dir, truncated_by=None)
    assert fake.transitions == []
    assert len(fake.records) == 1
    assert "malicious" in fake.records[0].text()
    assert fake.notes == []
    assert (S.receipt(run_dir) or {}).get("ok") is True


def test_record_case_ticket_given_no_exit_class(tmp_path):
    """An omitted keyword, a `.get()` miss and an explicit None all collapse to the same row:
    the record is made from the report exactly as today. The fallback is intended, not a bug.

    All three spellings are driven, because they are three different things at the call site —
    `record_case_ticket(run_dir, deps)` from a caller that predates this change,
    `summary.get("truncated_by")` on a summary that has no such key, and an explicit `None` —
    and a signature that defaulted differently for any of them would move the ordinary run."""
    summaries: list[dict] = [{}, {"truncated_by": None}]
    outcomes = []
    run_dir = S.closed_run_dir(tmp_path, disposition="benign")
    outcomes.append(S.record_ticket(run_dir).records)
    for summary in summaries:
        outcomes.append(
            S.record_ticket(run_dir, truncated_by=summary.get("truncated_by")).records)
    assert [len(t) for t in outcomes] == [1, 1, 1], (
        f"the three no-exit-class spellings did not agree: {outcomes}")
    assert all("benign" in t[0].text() for t in outcomes)


def test_an_exit_class_the_table_does_not_name_takes_the_report_driven_fallback(tmp_path):
    """An exit value the per-class table does not name — `dead-end`, or any string a future
    writer adds — takes the report-driven fallback rather than silently leaving the ticket in
    whichever state the last arm happened to reach.

    `dead-end` is a REAL member of `TRUNCATED_BY_VALUES` with no arm in the table (it is
    lead-only today), which is the case F7 decided: a future vocabulary member must not
    silently stop recording tickets that used to record. Positive control: the same run dir
    with `truncated_by=None` records identically, so the fallback really is TODAY's behaviour
    and not a third thing."""
    assert "dead-end" in S.vocabulary(), (
        "the control failed: `dead-end` left the vocabulary, so this no longer tests a real "
        "member with no arm in the table")
    run_dir = S.closed_run_dir(tmp_path, disposition="malicious")
    unmapped = S.record_ticket(run_dir, truncated_by="dead-end")
    baseline = S.record_ticket(run_dir, truncated_by=None)
    assert len(unmapped.records) == 1, "an unmapped exit class made no record at all"
    assert unmapped.records[0].body == baseline.records[0].body, (
        "an unmapped exit class recorded the ticket differently from a run with no exit class")
    assert unmapped.notes == []


def test_record_case_ticket_given_an_out_of_vocabulary_string(tmp_path):
    """`dead-end` — a real vocabulary member with no arm in the per-class table — takes the
    report-driven fallback (F7 resolved); a string outside the vocabulary entirely normalises
    to None at the owner and takes the same fallback.

    Fork F-O split these two apart deliberately: they reach the same ticket outcome by
    different routes, and conflating them hides that the lane calls the owner on its own
    parameter first (F-I). The out-of-vocabulary arm is what proves it does."""
    run_dir = S.closed_run_dir(tmp_path, disposition="malicious")
    for value in ("dead-end", "REQUEST-LIMIT", " aborted ", "totally-invented", 7):
        fake = S.record_ticket(run_dir, truncated_by=value)
        assert len(fake.records) == 1, f"{value!r} did not take the report-driven fallback"
        assert fake.notes == [], f"{value!r} reached the escalation-note arm"


def test_a_run_with_no_exit_class_and_no_usable_report_records_that_and_proposes_nothing(
        tmp_path):
    """A run with no exit class and no usable report.md still records — the fixed "no
    disposition could be recorded" sentence (#767 §7 R10), with no proposal in it — and the
    ticket stays open for a person. This is where #767 moved #1047's silent leave-open: an
    ordinary run that ends with nothing parsable is an anomaly the person should see on the
    ticket, not infer from its absence. The cut-short classes keep their own arms: a
    forced-close-set exit with no report escalates (F-K), and `budget`/`store` make no call.

    Three unusable shapes, each a real file through the real reader: absent, present but with
    no frontmatter at all, and present with a headline outside the disposition vocabulary."""
    for name, write in (
        ("absent", None),
        ("no-frontmatter", "just some prose, no headline anywhere\n"),
        ("bad-headline", S.report_text("not-a-disposition")),
    ):
        run_dir = S.closed_run_dir(tmp_path / name, report=False)
        if write is not None:
            (run_dir / "report.md").write_text(write, encoding="utf-8")
        fake = S.record_ticket(run_dir, truncated_by=None)
        assert fake.transitions == [], f"{name}: an unusable report still closed the ticket"
        assert len(fake.records) == 1, f"{name}: an unusable report left the ticket in silence"
        assert S.UNREADABLE_MARK in fake.records[0].text(), (
            f"{name}: the record proposes something off a report that yields no disposition")
        for word in S.sym("_vocab", "DISPOSITION_VALUES"):
            assert word not in fake.records[0].text().lower(), (
                f"{name}: an unreadable report's record names a disposition ({word!r})")
        assert (S.receipt(run_dir) or {}).get("ok") is True


def test_adding_an_exit_to_the_forced_close_set_cannot_change_what_a_ticket_does(tmp_path):
    """What a ticket does is decided by the exit class alone: a run whose exit class is `budget`
    leaves its ticket open whether or not a report.md is present, so widening the forced-close
    set later cannot move a ticket by side effect.

    The forced-close set's ONLY observable effect on a run dir is whether a `report.md` exists
    (claim h1), and the lane no longer reads that fact for a run with an exit class. Driven
    with the report present and absent: for each class the lane's calls must be the same both
    ways, which is the property "the set does not decide the ticket" actually means.

    SCOPED TO `S.NO_REPORT_EXITS`, which is the demand's own premise and not a narrowing.
    Widening `_CUT_SHORT_WITH_A_MODEL_STILL_OWED_A_CLOSE` can only ADD a forced `report.md` to
    a class that writes none today (claim h1), so `aborted`/`budget`/`store` are exactly the
    classes such a widening could reach — and they are what the demand's thesis is about. Over
    the WHOLE vocabulary the parity is false on purpose, by two later §7 resolutions this suite
    also pins: `request-limit`/`retry-exhausted` record with a report and escalate without
    one (fork F-K, `test_a_forced_close_set_exit_whose_own_forced_close_failed_...`), and
    `dead-end` — a member with no arm — takes the report-driven fallback, which is DEFINED as
    report-driven (fork F7, `ticket_report_presence_fallback_stays`). Asserting parity there
    would contradict both."""
    for exit_class in S.NO_REPORT_EXITS:
        with_report = S.record_ticket(
            S.closed_run_dir(tmp_path / f"{exit_class}-with", disposition="unresolved"),
            truncated_by=exit_class)
        without = S.record_ticket(
            S.closed_run_dir(tmp_path / f"{exit_class}-without", report=False),
            truncated_by=exit_class)
        assert [c.path for c in with_report.calls] == [c.path for c in without.calls], (
            f"{exit_class}: the presence of a report.md changed which calls the lane made "
            f"({[c.path for c in with_report.calls]} vs {[c.path for c in without.calls]}) — "
            "widening the forced-close set would then move this ticket by side effect")


# ---------------------------------------------------------------------------------------
# F-A — the exit class and a genuine model verdict, together
# ---------------------------------------------------------------------------------------


def test_a_ticket_for_a_run_that_closed_and_was_then_cut_short(tmp_path):
    """A run whose model had ALREADY CLOSED when the exit class was stamped records its own
    verdict, and raises no escalation note — the no-verdict arms defer to a genuine model close
    (fork F-A, reading B, human, §7 round 2).

    Probe p21 (EXECUTED) confirmed the collision is real: the forced close returns early when
    `ReviewState.of(deps).closed`, and the three classes that never force a close reach it
    trivially — so a run can carry a confident model verdict AND an `aborted` stamp. Reading A
    (the exit class is an unconditional trump) was rejected because an operator would then get
    an "environment unreachable, escalate" note about a case that actually concluded.

    Positive control on the same exit class: with `closed_before_cut=False` the same run dir
    takes the aborted arm, so what is under test is the field and not the report."""
    run_dir = S.closed_run_dir(tmp_path, disposition="malicious")
    decided = S.record_ticket(run_dir, truncated_by="aborted", closed_before_cut=True)
    assert len(decided.records) == 1, (
        "a run that reached its own confident close recorded nothing; the model decided, "
        "and the exit class arrived afterwards")
    assert "malicious" in decided.records[0].text(), (
        "the record proposes something other than the model's own verdict")
    assert decided.notes == [], (
        "an escalation note was raised about a case that actually concluded")

    undecided = S.record_ticket(run_dir, truncated_by="aborted", closed_before_cut=False)
    control_failed = (
        "the control failed: the same run dir with `closed_before_cut=False` no longer takes "
        "the aborted arm, so the assertions above are not about that field")
    assert undecided.records == [], control_failed
    assert len(undecided.notes) == 1, control_failed


def test_record_case_ticket_given_truncated_by_and_report_disagreeing(tmp_path):
    """When the exit class and the report disagree about whether anything was settled, the
    RECORD decides — not the report, and not the exit class alone.

    A report carrying a confident `malicious` beside a leave-open exit class is exactly the
    disagreement fork F-A names, and it is unresolvable from the report: `validate_report`
    admits whatever the box writes (claim h3), and the value pair `unresolved` +
    `CAUSE_NOT_REVIEWED` that marks a host close is incidental rather than a designed
    discriminator (probe p21). So `closed_before_cut` — written host-side, from
    `ReviewState.of(deps).closed` — is the tiebreak, and it is checked for EVERY leave-open
    class, not only for `aborted`."""
    for exit_class in S.NO_REPORT_EXITS:
        run_dir = S.closed_run_dir(tmp_path / exit_class, disposition="malicious")
        host_wins = S.record_ticket(run_dir, truncated_by=exit_class, closed_before_cut=False)
        assert host_wins.records == [], (
            f"{exit_class}: a report the model never wrote was recorded; a planted "
            "report.md is one of the box's own files")
        model_wins = S.record_ticket(run_dir, truncated_by=exit_class, closed_before_cut=True)
        assert len(model_wins.records) == 1, (
            f"{exit_class}: a genuine model verdict was discarded because the run was later "
            "cut short")
        assert "malicious" in model_wins.records[0].text()


def test_a_forced_close_set_exit_whose_own_forced_close_failed_leaves_the_ticket_open_with_the_escalation(
        tmp_path):
    """A `request-limit` or `retry-exhausted` run whose own forced close FAILED — so no
    `report.md` exists — takes the same escalation shape as the aborted arm, rather than
    recording `unresolved` off a payload that does not exist.

    Fork F-K (auto, §7 round 2), reusing F-D's now-confirmed report-independent identity.
    `_close_a_run_cut_short` returns `ForcedCloseFailed` on exactly this path and the run
    dead-letters at persist; closing `unresolved` off an invented payload would assert more
    than is known. Positive control: the same exit class WITH its forced report records
    `unresolved`, pinned by `test_a_request_limit_run_records_unresolved`.

    THE LAST ARM IS F-K's INTERSECTION WITH F-A's DEFERRAL, which neither resolution answers on
    its own: `closed_before_cut=True` AND no `report.md`. It is reachable — the box is root on
    its own rw bind, so it can commit a close (which sets `ReviewState.closed`) and then delete
    `report.md` before teardown — and the two rules point opposite ways read alone. F-A says a
    world that decided closes off its own verdict; there is NO verdict on disk to close off, so
    the close payload would have to be invented, which is exactly what F-K was resolved to
    refuse. F-K's reading therefore wins at the intersection: leave open, escalate. An
    implementer ordering the two checks the other way would silently drop the escalation, and
    nothing else in the suite would notice."""
    for exit_class in S.FORCED_CLOSE_SET:
        run_dir = S.closed_run_dir(tmp_path / exit_class, report=False)
        fake = S.record_ticket(run_dir, truncated_by=exit_class)
        assert fake.records == [], (
            f"{exit_class}: `unresolved` was recorded with no report to record it off")
        assert len(fake.notes) == 1, (
            f"{exit_class}: a run whose forced close failed left the ticket open in silence")
        assert exit_class in fake.notes[0].text()

        decided = S.closed_run_dir(tmp_path / f"{exit_class}-decided", report=False)
        both = S.record_ticket(decided, truncated_by=exit_class, closed_before_cut=True)
        assert both.records == [], (
            f"{exit_class}: a run that had closed but left no report.md still recorded a "
            "verdict — off what? F-A's deferral has no verdict on disk to defer to here, and "
            "inventing the payload is what F-K refuses")
        assert len(both.notes) == 1, (
            f"{exit_class}: `closed_before_cut=True` swallowed F-K's escalation on a run whose "
            "own forced close failed, leaving the ticket open in silence")
        assert exit_class in both.notes[0].text()


def test_a_failed_note_call_never_breaks_the_run_and_is_recorded_in_the_receipt(tmp_path):
    """A note call that fails is swallowed — the run never breaks over it — and the outcome is
    written into `ticket_write.json` either way (fork F-L, auto, §7 round 2).

    Both concerns at once: run safety and operator visibility. The failure is the transport's
    own answer shape, `(None, "transport error: …")`, which `ticket_writer._request` returns
    for a `TransportFault`; the receipt is already demand #0b's stated observable, so recording
    the failure there costs nothing new. The receipt must not claim the ticket closed —
    nothing can: the host has no transition call."""
    ok_dir = S.closed_run_dir(tmp_path / "ok", report=False)
    S.record_ticket(ok_dir, truncated_by="aborted")
    ok = S.receipt(ok_dir)
    assert ok is not None, "a successful note call left no receipt at all"
    assert ok.get("ok") is True, f"a successful note call was recorded as a failure: {ok!r}"
    assert ok.get("status") != "closed", (
        f"the receipt claims the ticket closed on the leave-open arm: {ok!r}")

    bad_dir = S.closed_run_dir(tmp_path / "bad", report=False)
    S.record_ticket(bad_dir, ticket=S.FakeTicketSystem(status=None), truncated_by="aborted")
    bad = S.receipt(bad_dir)
    assert bad is not None, "a failed note call left no receipt; the operator cannot see it"
    assert bad.get("ok") is False, f"a failed note call was recorded as a success: {bad!r}"


def test_an_unconfigured_ticket_lane_stays_silent_for_every_exit_class(tmp_path):
    """An operator with no case-history configuration gets today's silence for EVERY exit
    class, `aborted` included: no call, no receipt, no side channel (fork F-R, auto).

    Configuring no ticket system is already an opt-out; inventing a channel for one arm would
    override that choice. Positive control: the same run and exit class with a configured lane
    makes its call."""
    for exit_class in (*S.vocabulary(), None):
        run_dir = S.closed_run_dir(tmp_path / f"unconfigured-{exit_class}")
        fake = S.record_ticket(run_dir, ticket=S.FakeTicketSystem(configured=False),
                              truncated_by=exit_class)
        assert fake.calls == [], f"{exit_class}: an unconfigured lane called out anyway"
        assert S.receipt(run_dir) is None, f"{exit_class}: an unconfigured lane wrote a receipt"
    configured = S.record_ticket(
        S.closed_run_dir(tmp_path / "configured", report=False), truncated_by="aborted")
    assert len(configured.notes) == 1, (
        "the control failed: a configured lane made no note call either, so the silences "
        "above are not about configuration")


# ---------------------------------------------------------------------------------------
# nothing inside the run dir is an input to the decision
# ---------------------------------------------------------------------------------------


def test_no_planted_file_under_the_run_dir_changes_which_comment_record_case_ticket_makes_for_any_exit_class(
        tmp_path):
    """No file planted anywhere under the run dir changes which comment the ticket lane makes,
    for any exit class — under F3's reading the lane takes no run-dir input to DECIDE at all
    (the report's own text is the record's content, which is why both run dirs here carry the
    same one).

    Every exit class is driven twice over run dirs that differ only in what the box planted,
    and the calls must match path for path and body for body. Positive control:
    `test_a_request_limit_run_records_unresolved` — the same lane does make a different call
    when the EXIT CLASS differs, so the channel can see a difference."""
    for exit_class in (*S.vocabulary(), None):
        clean = S.closed_run_dir(tmp_path / f"clean-{exit_class}", disposition="unresolved")
        salted = S.closed_run_dir(tmp_path / f"salted-{exit_class}", disposition="unresolved")
        S.salt_run_dir(salted, value="request-limit")
        (salted / "report.md").write_text(S.report_text("unresolved"), encoding="utf-8")
        a = S.record_ticket(clean, truncated_by=exit_class)
        b = S.record_ticket(salted, truncated_by=exit_class)
        assert [(c.path.split("/")[-1], c.body) for c in a.calls] == \
               [(c.path.split("/")[-1], c.body) for c in b.calls], (
            f"{exit_class}: a planted file changed what the ticket lane did")


def test_a_forged_session_store_pointer_file_is_never_consulted_by_the_ticket_lane_for_any_exit_class(
        tmp_path):
    """A forged session_store_pointer.json is never consulted for any exit class: F3 reading A
    was chosen precisely to avoid the pointer file, and reading B was rejected as the
    box-writable input the design's own negative universal forbids.

    The box is ROOT on the run dir's mount (flagged fact F4), so both of the pointer's fields
    are rewritable after the host wrote them — a lane that recovered a case id from it would be
    reading an attacker-chosen value. Three forgeries: a pointer naming another case, a pointer
    that is not JSON at all, and a pointer that is a dangling symlink. None of them may move
    the lane, and none of them may make it raise."""
    pointer_name = S.sym("_run_paths", "RUN_LAYOUT").session_pointer.name
    forgeries = {
        "other-case": json.dumps({"case_id": "someone-elses-case", "session_id": "sid"}),
        "not-json": "{{{ not json at all",
        "empty": "",
    }
    for exit_class in (*S.vocabulary(), None):
        control = S.record_ticket(
            S.closed_run_dir(tmp_path / f"control-{exit_class}", disposition="unresolved"),
            truncated_by=exit_class)
        for name, content in forgeries.items():
            run_dir = S.closed_run_dir(tmp_path / f"{name}-{exit_class}",
                                       disposition="unresolved")
            (run_dir / pointer_name).write_text(content, encoding="utf-8")
            fake = S.record_ticket(run_dir, truncated_by=exit_class)
            assert [c.path.split("/")[-1] for c in fake.calls] == \
                   [c.path.split("/")[-1] for c in control.calls], (
                f"{exit_class}/{name}: a forged pointer file moved the ticket lane")

    dangling = S.closed_run_dir(tmp_path / "dangling", disposition="unresolved")
    (dangling / pointer_name).symlink_to(tmp_path / "nowhere.json")
    assert len(S.record_ticket(dangling, truncated_by="request-limit").records) == 1, (
        "a dangling symlink at the pointer's name stopped the ticket lane, so something is "
        "reading it")


def test_a_forged_ticket_write_receipt_claiming_prior_closure_does_not_suppress_the_real_record_or_note_call(
        tmp_path):
    """A ticket_write.json forged to claim a prior closure suppresses nothing: the genuine
    record/note call is issued regardless, because nothing in this design reads the receipt
    back as an input.

    The receipt is an OUTPUT — the lane's own record of what it did — and the run dir it sits
    in is the box's rw bind, so treating it as an input would let the graded subject suppress
    its own record. Both arms are driven: the record arm and the note arm."""
    for exit_class, expect in (("request-limit", "records"), ("aborted", "notes")):
        run_dir = S.closed_run_dir(tmp_path / exit_class, disposition="unresolved",
                                   report=expect == "records")
        (run_dir / "ticket_write.json").write_text(
            json.dumps({"key": run_dir.name, "status": "closed", "ok": True,
                        "url": "http://tickets.test/tickets/forged"}), encoding="utf-8")
        fake = S.record_ticket(run_dir, truncated_by=exit_class)
        assert len(getattr(fake, expect)) == 1, (
            f"{exit_class}: a forged receipt claiming the ticket was already closed suppressed "
            "the real call")


def test_ticket_and_grading_given_a_report_planted_on_a_no_report_exit_class(tmp_path):
    """A report.md planted on an aborted/budget/store run moves neither lane: grading never
    reads frontmatter, and the ticket branches on the in-process parameter.

    The three classes write no report at all (claim h1), so ANY report.md on such a run is
    either the box's or a leftover — and under the old report-presence rule it would have
    been recorded. Positive control: `test_a_budget_kill_leaves_its_ticket_open_and_makes_
    no_call`'s report-present arm."""
    for exit_class in S.NO_REPORT_EXITS:
        run_dir = S.closed_run_dir(tmp_path / f"ticket-{exit_class}", disposition="benign")
        S.plant_frontmatter(run_dir, extra=f"truncated_by: {exit_class}\n", disposition="benign")
        fake = S.record_ticket(run_dir, truncated_by=exit_class)
        assert fake.records == [], (
            f"{exit_class}: a planted report was recorded on a class that settles nothing")

        ep = S.cut_short_episode(tmp_path / f"grade-{exit_class}", cut={"b": exit_class})
        S.plant_frontmatter(ep / "worlds" / "b", extra="truncated_by: null\n")
        row = S.graded(ep)["b"]
        assert row.get("cut_short") == exit_class, (
            f"{exit_class}: a planted `truncated_by: null` frontmatter line un-cut-shorted the "
            "world")


# ---------------------------------------------------------------------------------------
# #767 O1 — the host never transitions; the store's `closed` is a person's word
# ---------------------------------------------------------------------------------------


def test_no_exit_class_transitions_the_ticket(tmp_path):
    """For EVERY exit class, with and without a report, and whether or not the model had
    closed, the lane makes no transition call: the only writes are comments. This is the
    property that makes the store's own `closed` status mean "a person reviewed this" to a
    later run's reader (#767 O1/O2) — not a check in the writer, but the absence of the call.
    Positive control: the same drives do make comment calls, so the census sees writes."""
    seen_writes = 0
    for exit_class in (*S.vocabulary(), None):
        for report in (False, True):
            for closed in (False, True):
                run_dir = S.closed_run_dir(
                    tmp_path / f"{exit_class}-{report}-{closed}", report=report)
                fake = S.record_ticket(run_dir, truncated_by=exit_class,
                                       closed_before_cut=closed)
                assert fake.transitions == [], (
                    f"{exit_class}/report={report}/closed_before_cut={closed}: the host "
                    f"transitioned the ticket — {[c.path for c in fake.transitions]}")
                assert all(c.is_comment for c in fake.writes), (
                    f"{exit_class}: a write that is neither a comment nor a transition: "
                    f"{[c.path for c in fake.writes]}")
                seen_writes += len(fake.writes)
    assert seen_writes, "the control failed: no drive wrote anything, so the census is empty"
