"""#767 — the read half: a later run sees a case's comments only once a person has closed it.

Every test is one demand of `spec-flow/specs/spec_graph_767-ticket-store-approval.yaml`,
named by that demand's `discharged_by`. RED against `a77335d5` by construction: D4's
per-ticket release step, the mapper's `is_released` predicate and the mapping's
`released:`/`comment:` sections are all coined by this spec.

The entry point every test here drives is the REAL one: `query_tool._screen_ticket_payload`,
the single insertion point the query tool calls after `handler(args)` and before
`_record`/`_model_view` (r5/c6). D4 attaches its step there, behind the own-case exclusion.

WHAT THE REWORK DECIDED THAT EVERY ASSERTION HERE RESTS ON:

* **The release signal is the case's LIFECYCLE STATE.** A person closes a case once they
  have reviewed it; the mapping's `released.status` names that state and the screen asks
  nothing else. `status` is a closed vocabulary the store enforces (c8: a Literal, 422 on
  anything else), so no alert-rendered field can move a case along it and no loader guard
  over label templates is needed — the old collision class has no surface left to exist on.
* **A released case is served WHOLE; an unreleased case serves NO comments.** There is no
  "who wrote this comment" question: a comment's `author` is whatever the posting client
  sent, so a rule built on it was never sound (the identity set, the alias list and the
  "latest agent comment" rule all went with it). The person's close covers every comment on
  the case at that moment, and the writer never appends behind a close.
* **Fail closed on the read side, and never raise into the model's turn** (R1/FAM-1). A
  ticket whose state cannot be determined is UNRELEASED. An undecidable record is SCREENED
  AND KEPT in the listing, never dropped and never refused whole-call (N5's correlation
  benefit is not spent to solve a robustness problem).
* **The status matches EXACTLY** — no case folding, no trimming, no prefix tolerance. The
  store canonicalises the vocabulary; the one thing normalised is the MAPPING's own spelling,
  stripped once at load so a quoted YAML scalar cannot configure a state nothing can reach.
* **Nothing here claims a byte bound over what the STORE handed back** (FK41). A forged
  comment bypasses D2/D3 entirely (N6); the write-side bounds are pinned in
  `test_767_writer.py`, over the outbound payload alone.
"""
from __future__ import annotations

import copy
import json

import pytest

from defender.runtime.ticket_screen import MALFORMED_EXIT
from defender.scripts.case_history import case_ticket
from defender.scripts.gather_tools.payload_view import PASSTHROUGH_MAX_BYTES_DEFAULT
from defender.tests._spec767 import (
    OPEN_STATUS,
    OTHER_KEY,
    RELEASED_STATUS,
    SELF_KEY,
    WIRE_BOUND_BYTES,
    FakeStore,
    comment,
    listing,
    make_run,
    mapping_doc,
    record,
    rendered,
    require,
    screen_get,
    screen_list,
    served_comments,
    served_tickets,
    ticket,
    use_mapping,
)

AGENT_TEXT = "PRIOR-RUN-NOTES-a-model-wrote-these"
OLDER_TEXT = "PRIOR-RUN-NOTES-an-earlier-run-wrote-these"
HUMAN_TEXT = "an analyst's own note"


def _mapping(monkeypatch, tmp_path, **kw):
    return use_mapping(monkeypatch, tmp_path / "dfn", mapping_doc(**kw))


def _released(key: str = OTHER_KEY, *, comments=None, **kw) -> dict:
    return ticket(
        key, status=RELEASED_STATUS, labels=["sig:5710"],
        comments=[comment(AGENT_TEXT)] if comments is None else comments, **kw,
    )


def _unreleased(key: str = "SOC-OPEN", *, comments=None, status: str = OPEN_STATUS, **kw) -> dict:
    return ticket(
        key, status=status, labels=["sig:5710"],
        comments=[comment(AGENT_TEXT)] if comments is None else comments, **kw,
    )


def _one(payload) -> dict:
    kept = served_tickets(payload)
    assert len(kept) == 1, f"expected one served ticket, got {[t.get('key') for t in kept]}"
    return kept[0]


# =======================================================================================
# O2 / S3 — comments only from released cases
# =======================================================================================


def test_767_unreleased_ticket_serves_no_comment(tmp_path, monkeypatch):
    """o2_unreleased_no_comment — NEGATIVE. No comment from an unreleased case reaches a
    model, on either ticket verb, in the screened payload or in what gather's payload view
    renders from it — whoever wrote it, whatever shape it has.

    The lifecycle arms are the states a person has NOT yet closed: `open`, `in_progress`.
    The undecidable arms take the SAME outcome, by §7 R1/FAM-1's read-side direction: a
    ticket with no `status` at all, a non-string status, and a record the predicate cannot
    decide about are screened as UNRELEASED and KEPT in the listing (FK17).

    The adversarial arm is the exact-match one: a status merely confusable with the
    configured spelling — different case, a prefix, a trailing word, surrounding whitespace, a
    Cyrillic homoglyph — does NOT release. The store's vocabulary is canonical, so there is no
    variant a vendor adds "without a person's involvement" and no concession to make.

    The shape arms are the ones the retired author predicate used to own: a bare string, a
    number, an authorless object, an object whose author is a list. None is served, because
    the screen never asks what an element IS — an unreleased case's list is emptied whole.

    Its declared positive control on the same address is `o2_released_serves_whole` — the
    same bytes ARE served once a person closes the case.
    """
    _mapping(monkeypatch, tmp_path)

    withheld = {
        "open": _unreleased(),
        "in progress": _unreleased("SOC-WIP", status="in_progress"),
        "no status field at all (FK14)": ticket(
            "SOC-NOSTATUS", comments=[comment(AGENT_TEXT)], drop_status=True),
        "status is not a string (FAM-1)": _unreleased("SOC-BADSTATUS", status=["closed"]),
        "status is null (FAM-1)": _unreleased("SOC-NULLSTATUS", status=None),
        "a confusable status: case": _unreleased("SOC-CASE", status="Closed"),
        "a confusable status: a prefix": _unreleased("SOC-PREFIX", status="closed-out"),
        "a confusable status: padded": _unreleased("SOC-PADDED", status=f" {RELEASED_STATUS} "),
        "a confusable status: a homoglyph": _unreleased("SOC-HOMOGLYPH", status="сlosed"),
        "an authorless comment": _unreleased(
            "SOC-NOAUTHOR", comments=[comment(AGENT_TEXT, drop_author=True)]),
        "a human-attributed comment": _unreleased(
            "SOC-HUMAN", comments=[comment(AGENT_TEXT, author="analyst")]),
        "a bare-string comment": _unreleased("SOC-STR", comments=[AGENT_TEXT]),
        "a number and a listy author": _unreleased(
            "SOC-JUNK", comments=[17, {"author": ["not", "a", "string"], "body": AGENT_TEXT}]),
        "comments is not a list": _unreleased("SOC-STRC", comments=AGENT_TEXT),
    }
    for why, t in withheld.items():
        for verb, (payload, code, detail) in (
            ("list-tickets", screen_list(listing(copy.deepcopy(t)))),
            ("get-ticket", screen_get(copy.deepcopy(t))),
        ):
            assert code == 0, f"{why} on {verb}: the screen refused the whole call ({detail})"
            served = _one(payload) if verb == "list-tickets" else payload
            assert served is not None, f"{why} on {verb}: the record was dropped, not screened"
            assert served_comments(served) == [], f"{why} on {verb}: a comment was served"
            assert AGENT_TEXT not in json.dumps(served, ensure_ascii=False), (
                f"{why} on {verb}: the text survived somewhere in the record"
            )
            assert AGENT_TEXT not in rendered(served, tmp_path), (
                f"{why} on {verb}: the text reached the model through the payload view"
            )

    # The positive control on the same address, so the negatives above cannot be green merely
    # because the screen serves nothing at all.
    closed, code, _ = screen_list(listing(_released("SOC-CLOSED")))
    assert code == 0
    assert [c["body"] for c in served_comments(_one(closed))] == [AGENT_TEXT], (
        "the control failed: a closed case served no comment"
    )


def test_767_released_ticket_serves_comments_whole(tmp_path, monkeypatch):
    """o2_released_serves_whole — a released case is served WHOLE: every comment, in the
    store's own list order, agent-authored or not, untouched. The person's close covers the
    list as it stood when they closed it, and the writer never appends behind a close
    (`test_767_writer_never_records_behind_a_release`), so there is nothing on a closed case
    a person has not seen.

    The fixture's `created` stamps CONTRADICT list order on purpose, and two comments share a
    stamp: a screen that sorted, deduped or picked a "latest" entry changes the list, and the
    assertion is list identity."""
    _mapping(monkeypatch, tmp_path)

    comments = [
        comment(OLDER_TEXT, created="2026-01-02T00:00:00Z"),
        comment(HUMAN_TEXT, author="analyst", created="2026-01-03T00:00:00Z"),
        comment(AGENT_TEXT, created="2026-01-01T00:00:00Z"),
        comment(AGENT_TEXT, created="2026-01-01T00:00:00Z"),
        comment("a note nobody signed", drop_author=True),
    ]
    source = _released(comments=copy.deepcopy(comments))
    payload, code, _ = screen_list(listing(copy.deepcopy(source)))
    assert code == 0
    served = _one(payload)
    assert served["comments"] == comments, (
        "a released case's comment list was rewritten — sorted, deduped, trimmed or "
        "annotated — instead of served as the person closed it"
    )
    assert served == source, "a released case was rewritten outside its comment list"

    got, code, _ = screen_get(copy.deepcopy(source))
    assert (got, code) == (source, 0)


def test_767_release_screen_applies_on_both_ticket_verbs(tmp_path, monkeypatch):
    """o2_both_verbs_screened — PARITY, per access cell. Every constraint D4 states is
    enforced on `list-tickets` AND on `get-ticket`: the own-case exclusion, emptying the
    comments when unreleased, serving them whole when released, and leaving no marker.

    Bound per cell rather than facet-wide because that is the canonical fail-open this demand
    exists for — a constraint pinned on one verb and silently absent on its sibling. Both
    verbs reach the store through the same dispatch point (`_screen_ticket_payload`, r5), so
    the parity is asserted by driving the SAME record down both and comparing the surviving
    comments cell by cell."""
    _mapping(monkeypatch, tmp_path)
    released = _released(comments=[comment(OLDER_TEXT), comment(AGENT_TEXT)])
    unreleased = _unreleased(comments=[comment(OLDER_TEXT), comment(AGENT_TEXT)])

    for record_in, expected in ((released, [OLDER_TEXT, AGENT_TEXT]), (unreleased, [])):
        listed, list_code, _ = screen_list(listing(copy.deepcopy(record_in)))
        got, get_code, _ = screen_get(copy.deepcopy(record_in))
        assert (list_code, get_code) == (0, 0)
        by_verb = {
            "list-tickets": [c["body"] for c in served_comments(_one(listed))],
            "get-ticket": [c["body"] for c in served_comments(got)],
        }
        assert by_verb["list-tickets"] == by_verb["get-ticket"] == expected, (
            f"the two verbs must both serve {expected} for {record_in['key']}; they served "
            f"{by_verb} — a constraint pinned on one access cell and absent on its sibling is "
            "the canonical fail-open"
        )


def test_767_release_screen_runs_after_the_own_case_exclusion(tmp_path, monkeypatch):
    """d4_screen_after_own_case — D4's per-ticket step runs AFTER the own-case exclusion, in
    both verbs. The ordering is observable rather than read off source: the run's OWN case,
    closed and carrying comments, is removed ENTIRELY from a listing and refused outright on
    `get-ticket` — a release-first screen would have kept it and served it whole.

    The control is the same record under a different key: a sibling case, closed and carrying
    the SAME two comments, survives whole, which is what makes the control discriminating
    rather than a pass-through."""
    _mapping(monkeypatch, tmp_path)
    both = [comment(OLDER_TEXT), comment(AGENT_TEXT)]
    own = _released(SELF_KEY, comments=copy.deepcopy(both))
    sibling = _released(OTHER_KEY, comments=copy.deepcopy(both))

    payload, code, _ = screen_list(listing(own, sibling))
    assert code == 0
    kept = served_tickets(payload)
    assert [t["key"] for t in kept] == [OTHER_KEY], (
        "the run's own closed case survived the listing — the own-case exclusion no longer "
        "runs first"
    )
    assert payload["total"] == 1, "`total` still advertises the record the screen removed"
    assert [c["body"] for c in served_comments(kept[0])] == [OLDER_TEXT, AGENT_TEXT]

    refused, exit_code, detail = screen_get(copy.deepcopy(own))
    assert refused is None, "the run's own closed case was served through get-ticket"
    assert exit_code != 0, "get-ticket answered its own case with a success exit code"
    assert AGENT_TEXT not in detail, "the refusal detail carries the withheld content"


def test_767_screen_leaves_no_marker(tmp_path, monkeypatch):
    """d4_no_marker — NEGATIVE. The screen adds, removes and annotates nothing outside each
    ticket's own `comments` list: it returns the envelope it received, with `total` restated
    to what survived, and it follows the own-case exclusion's precedent — a screen filters
    SILENTLY. `payload_view`'s elision record stays the view's alone (c7's note).

    Its positive control is `o2_released_serves_whole`: the screen demonstrably DOES change
    the comments list on an unreleased case, so "nothing else changed" is not "nothing
    happened"."""
    _mapping(monkeypatch, tmp_path)
    source = _unreleased(comments=[comment(AGENT_TEXT), comment(HUMAN_TEXT, author="analyst")])
    source["resolution"] = "benign — a legacy close-lane resolution"
    envelope = listing(copy.deepcopy(source), source="ticket-store")

    payload, code, detail = screen_list(copy.deepcopy(envelope))
    assert (code, detail) == (0, "")
    served = _one(payload)

    assert set(served) == set(source), (
        f"fields appeared or vanished on the record: "
        f"{set(served) ^ set(source)}"
    )
    for field, value in source.items():
        if field == "comments":
            continue
        assert served[field] == value, f"the screen rewrote `{field}`"
    assert set(payload) == set(envelope), "the envelope gained or lost a key"
    assert payload["source"] == "ticket-store"
    assert served["comments"] == [], (
        "the positive half failed: the screen did not empty the comments list at all"
    )

    got, code, detail = screen_get(copy.deepcopy(source))
    assert (code, detail) == (0, ""), "get-ticket annotated its refusal channel instead"
    assert set(got) == set(source)


def test_767_unreleased_tickets_stay_visible_for_correlation(tmp_path, monkeypatch):
    """n5_unreleased_non_comment_fields_visible — an unreleased case is NOT withheld: its
    other fields stay visible so a later run can still answer "is this already on the SOC's
    radar". Withholding unreleased tickets entirely was examined and rejected (N5).

    This is the demand that makes FAM-1's "screen it, keep it" concrete (FK17): a record the
    predicate cannot decide about is screened as unreleased and KEPT — neither dropped from
    the listing nor allowed to refuse the whole call, because dropping spends N5's stated
    benefit to solve a robustness problem and refusing turns one malformed record into a
    gather-wide outage.

    The one thing the rework changed here: an analyst's own note on an OPEN case is no longer
    served either. Nothing tells it apart from an agent's, so it waits for the close with
    the rest of the list."""
    _mapping(monkeypatch, tmp_path)
    undecidable = ticket("SOC-UNDECIDABLE", drop_status=True, labels=["sig:5710"],
                         comments=[comment(AGENT_TEXT)])
    ordinary = _unreleased("SOC-OPEN", comments=[comment(HUMAN_TEXT, author="analyst")])
    released = _released()

    payload, code, _ = screen_list(listing(undecidable, ordinary, released))
    assert code == 0, "one undecidable record refused the whole listing"
    kept = served_tickets(payload)
    assert [t["key"] for t in kept] == ["SOC-UNDECIDABLE", "SOC-OPEN", OTHER_KEY], (
        "an unreleased or undecidable record was dropped from the listing"
    )
    assert payload["total"] == 3
    for t in kept[:2]:
        assert t["summary"] == "a prior case", (
            "an unreleased record lost the summary correlation reads"
        )
        assert t["labels"] == ["sig:5710"], "an unreleased record lost its signature label"
        assert served_comments(t) == []
    assert kept[1]["status"] == OPEN_STATUS, "an unreleased record lost its lifecycle state"
    assert [c["body"] for c in served_comments(kept[2])] == [AGENT_TEXT]


def test_767_released_ticket_is_unchanged(tmp_path, monkeypatch):
    """d_released_ticket_unchanged — settled premise 39, restated for the lifecycle screen. A
    released case is served exactly as the store answered it, comments or no comments: the
    screen has nothing to do on a closed case and does nothing.

    Byte-identity is the assertion, so a screen that rebuilt the record — reordering keys,
    dropping a field it did not recognise, stamping a marker — fails even though the comment
    count is trivially right."""
    _mapping(monkeypatch, tmp_path)
    for source in (
        _released(comments=[comment(HUMAN_TEXT, author="analyst")]),
        _released("SOC-EMPTY", comments=[]),
        _released("SOC-NOC", drop_comments=True),
        _released("SOC-NULLC", comments=None),
    ):
        payload, code, _ = screen_list(listing(copy.deepcopy(source)))
        assert code == 0
        assert _one(payload) == source, f"a released case was rewritten: {source['key']}"

        got, code, _ = screen_get(copy.deepcopy(source))
        assert (got, code) == (source, 0)


def test_767_each_query_is_screened_against_the_store_at_call_time(tmp_path, monkeypatch):
    """d_each_query_screened_at_call_time — settled premise 40. Each query is screened
    against the store state AT THE TIME OF THAT CALL: D4 is a per-payload step and the doc
    names no snapshot and no cache, so two queries in one run may legitimately see different
    outcomes.

    Driven as the pair the premise describes — the same record, read twice, with the person's
    close in between — so a screen that cached its first verdict fails on the second call
    rather than passing by construction. And a third read after a RE-OPEN, which is the
    lifecycle's own "revoke": the same bytes go back behind the screen."""
    _mapping(monkeypatch, tmp_path)
    before = _unreleased("SOC-PENDING")
    first, code, _ = screen_list(listing(copy.deepcopy(before)))
    assert code == 0
    assert served_comments(_one(first)) == []

    after = copy.deepcopy(before)
    after["status"] = RELEASED_STATUS
    second, code, _ = screen_list(listing(after))
    assert code == 0
    assert [c["body"] for c in served_comments(_one(second))] == [AGENT_TEXT], (
        "the second query in the same process saw the first query's verdict — D4 grew a "
        "snapshot or a cache the design does not name"
    )

    reopened = copy.deepcopy(after)
    reopened["status"] = "in_progress"
    third, code, _ = screen_list(listing(reopened))
    assert code == 0
    assert served_comments(_one(third)) == [], (
        "a re-opened case kept serving its comments — release is the case's CURRENT state, "
        "not a latch"
    )


def test_767_a_sibling_world_reads_through_the_same_screen(tmp_path, monkeypatch):
    """d_sibling_world_reads_through_the_same_screen — PARITY, settled premise 43. A sibling
    world's gather reaches the store through the IDENTICAL path: the own-case exclusion, then
    the D4 release screen. No sibling exemption exists anywhere in D1-D8 (g12: nothing in
    the branch estate redirects the ticket system).

    Driven as parity across readers rather than across a code path: the same store state is
    screened once as the parent (`self_key` = the parent's case) and once as a sibling
    (`self_key` = the sibling's own id), and the two must agree on every case but the one
    each reader is itself working on.

    PROBE PR1 IS OPEN and decides only WHICH of the two filters removes the parent's fresh
    comment — whether a sibling's `run_id` differs from its parent's. Both filters are
    asserted here, so this demand holds either way: the parent's own case is excluded by
    identity for the parent, and it is unreleased for the sibling."""
    _mapping(monkeypatch, tmp_path)
    # A text distinct from AGENT_TEXT: the closed sibling case legitimately carries AGENT_TEXT
    # and is visible to BOTH readers (the parity this test drives), so the parent's own
    # withheld comment needs its own, unique body — otherwise a negative on AGENT_TEXT would
    # be vacuously satisfied (or defeated) by the sibling's own legitimate comment.
    parent_fresh_text = "PRIOR-RUN-NOTES-the-parents-own-fresh-comment"
    parent_case = _unreleased(SELF_KEY, comments=[comment(parent_fresh_text)])
    closed_sibling_case = _released(OTHER_KEY)
    store = listing(parent_case, closed_sibling_case)

    as_parent, code, _ = screen_list(copy.deepcopy(store), self_key=SELF_KEY)
    assert code == 0
    as_sibling, code, _ = screen_list(copy.deepcopy(store), self_key="20260917T000000Z-world-B")
    assert code == 0

    assert parent_fresh_text not in json.dumps(as_parent), (
        "the parent read back its own fresh comment"
    )
    assert parent_fresh_text not in json.dumps(as_sibling), (
        "a sibling world read the parent's unreleased comment — no sibling exemption exists"
    )
    parent_view = {t["key"]: [c["body"] for c in served_comments(t)]
                   for t in served_tickets(as_parent)}
    sibling_view = {t["key"]: [c["body"] for c in served_comments(t)]
                    for t in served_tickets(as_sibling)}
    assert parent_view[OTHER_KEY] == sibling_view[OTHER_KEY] == [AGENT_TEXT], (
        "the two readers disagree about a closed case neither of them owns"
    )
    assert SELF_KEY not in parent_view, "the own-case exclusion did not fire for the parent"
    assert SELF_KEY in sibling_view, (
        "the sibling's own-case exclusion removed the parent's case, so this scenario proves "
        "nothing about the release screen — re-site this demand on PR1's answer"
    )


def test_767_a_served_comment_cannot_re_enter_without_a_second_human_act(
    tmp_path, monkeypatch
):
    """d_two_hop_chain_closed_by_release — NEGATIVE, settled premise 61. The two-hop chain is
    closed by the person's CLOSE, not by content inspection: a run's own fresh comment lands
    on its own case, which is open until a person closes it, so a served comment's influence
    on a later report cannot re-enter any model's context without a SECOND human act.

    Driven end to end across the two halves this spec owns: the writer deposits a comment
    whose text is the very content a model read, and the screen then refuses to serve it back
    until the case is closed. The doc requires no detection of novel-vs-reproduced content
    (S5) — the hop is closed by the person, and this test's second half is that person acting.

    Its positive control is `o2_released_serves_whole`; the inline control is the third step
    below, where the close makes the same bytes servable."""
    _mapping(monkeypatch, tmp_path)
    laundered = "LAUNDERED-FROM-AN-UNRELEASED-TICKET"
    run_dir = make_run(tmp_path, name=SELF_KEY, body=laundered)
    store = FakeStore()
    record(run_dir, store)
    body = store.comment_body()
    assert laundered in body, "the run's own record did not carry the round-tripped text"

    own_case = _unreleased(SELF_KEY, comments=[comment(body)])
    served, code, _ = screen_list(listing(copy.deepcopy(own_case)))
    assert code == 0
    assert laundered not in json.dumps(served), "a run read its own fresh comment straight back"

    as_other, code, _ = screen_list(listing(copy.deepcopy(own_case)), self_key="some-later-run")
    assert code == 0
    assert laundered not in json.dumps(as_other), (
        "a LATER run read the comment with no person having closed the case — the chain is "
        "closed by release, and no release has happened"
    )

    closed_case = copy.deepcopy(own_case)
    closed_case["status"] = RELEASED_STATUS
    after_the_close, code, _ = screen_list(listing(closed_case), self_key="some-later-run")
    assert code == 0
    assert laundered in json.dumps(after_the_close), (
        "the control failed: the close did not make the comment servable, so the negatives "
        "above could be green for any reason at all"
    )


def test_767_the_lifecycle_state_is_served_to_the_model(tmp_path, monkeypatch):
    """d_status_is_served_to_the_model — settled premise 70. The state that governs the
    screen is itself in the `status` a model reads back: D4 filters COMMENTS only, and N5
    keeps the other fields visible. That is harmless and deliberate — the model cannot
    transition a case (O6/c2) and text cannot become a status (S5) — and it is what lets a
    later run see that a case has been closed, and read the person's `resolution` beside it."""
    _mapping(monkeypatch, tmp_path)
    closed = _released(resolution="benign — the person's own verdict")
    payload, code, _ = screen_list(listing(closed, _unreleased()))
    assert code == 0
    kept = {t["key"]: t for t in served_tickets(payload)}
    assert kept[OTHER_KEY]["status"] == RELEASED_STATUS, "the status was stripped from the record"
    assert kept[OTHER_KEY]["resolution"] == closed["resolution"]
    assert kept["SOC-OPEN"]["status"] == OPEN_STATUS
    assert RELEASED_STATUS in rendered(payload, tmp_path), (
        "the status never reached the model through the payload view"
    )


def test_767_screen_ticket_comment_shape(tmp_path, monkeypatch):
    """d0_screen_shape — the screen's own return contract: `(payload, 0, "")` with each
    surviving unreleased ticket's `comments` emptied IN PLACE, `total` restated to what
    survived, and every other field of every record untouched — including a LEGACY
    `resolution` written by the pre-#767 close lane.

    §7 R9/FK05 recorded that legacy field as an EXAMINED NO rather than a second field D4
    screens, and the ground is claim c3 (executed): on any close-tool report the `resolution`
    is the HOST's cause sentence, never the model's body — `close_tool.py:296` renders
    `cause:` unconditionally from the closed `REPORT_CAUSES` set, so a legacy `resolution`
    carries closed host vocabulary plus a `{disposition}`, not free model text. After the
    rework it is also simply the person's own field on a closed case.

    The malformed arms are FAM-1's, and every one of them is screened rather than raised into
    the model's turn: `comments` null, absent or not a list is served as NO COMMENTS on an
    unreleased ticket and the ticket keeps its other fields (FK16). A comment from a THIRD
    identity — the stub's own `system` transition stamp, a retired lane's `learning` — gets
    no special reading: on an unreleased case nothing is served, on a released one everything
    is."""
    _mapping(monkeypatch, tmp_path)
    legacy = _unreleased("SOC-LEGACY", comments=[comment(AGENT_TEXT)])
    legacy["resolution"] = "benign — Disposition recorded by the close gate. outcome=holds"

    payload, code, detail = screen_list(listing(copy.deepcopy(legacy)))
    assert (code, detail) == (0, "")
    served = _one(payload)
    assert served["resolution"] == legacy["resolution"], (
        "the screen grew a second field to screen; §7 R9 recorded `resolution` as an "
        "examined no on c3's ground"
    )
    assert served["comments"] == []

    for why, t in {
        "comments is null (FK16)": ticket("SOC-NULLC", labels=["sig:1"], comments=None),
        "comments is absent (FK16)": ticket("SOC-NOC", labels=["sig:1"], drop_comments=True),
        "comments is not a list (FK16)": ticket("SOC-STRC", labels=["sig:1"], comments="nope"),
    }.items():
        out, code, detail = screen_list(listing(copy.deepcopy(t)))
        assert code == 0, f"{why}: the screen raised into the model's turn ({detail})"
        kept = _one(out)
        assert kept["summary"] == "a prior case", f"{why}: the record lost its other fields"
        assert served_comments(kept) == [], f"{why}: a comment was served from a malformed list"
        assert ("comments" in kept) == ("comments" in t), (
            f"{why}: the screen invented or removed the `comments` key"
        )

    third = [
        comment("the store's own transition stamp", author="system"),
        comment("a retired lane's note", author="learning"),
        comment(AGENT_TEXT),
    ]
    out, code, _ = screen_list(listing(_unreleased("SOC-THIRD", comments=copy.deepcopy(third))))
    assert code == 0
    assert _one(out)["comments"] == [], "a third identity was served on an unreleased case"
    out, code, _ = screen_list(listing(_released("SOC-THIRD-C", comments=copy.deepcopy(third))))
    assert code == 0
    assert _one(out)["comments"] == third, "a third identity was withheld on a released case"

    for malformed in (None, [{"key": "SOC-1"}], {"tickets": "not-a-list"}):
        out, code, detail = screen_list(malformed)
        assert (out, code) == (None, MALFORMED_EXIT), f"{malformed!r} was served"
        assert "malformed ticket store response" in detail


def test_767_a_failed_ticket_read_puts_no_content_in_the_turn(tmp_path, monkeypatch):
    """d_failed_ticket_read_puts_no_content_in_the_turn — NEGATIVE, §7 FK36. A ticket read
    that fails before the screen runs puts NO ticket content into the model's turn or the
    capture. The error's class and the run's fate stay with the query tool's pre-existing
    envelope: this lane changes neither, and pinning them here would freeze behaviour the
    design never claimed.

    O2 is vacuously satisfied by a failed read either way, which is exactly why the positive
    control matters and is asserted on the same address: a SUCCESSFUL read of the same
    closed case does put its content in the turn."""
    _mapping(monkeypatch, tmp_path)
    for malformed in (None, "a string body", ["a bare array"], 17):
        payload, code, detail = screen_get(malformed)
        assert payload is None, f"{malformed!r} was passed through unscreened"
        assert code == MALFORMED_EXIT
        assert AGENT_TEXT not in detail

    served, code, _ = screen_get(_released())
    assert code == 0, "the control failed: a successful read of a closed case was refused"
    assert AGENT_TEXT in json.dumps(served), (
        "the control failed: a successful read of a closed case served nothing, so the "
        "negatives above prove nothing about the read path"
    )


# =======================================================================================
# D4's predicate — where it lives, and that it cannot be built in a serving state
# =======================================================================================


def test_767_release_predicate_lives_in_the_mapper(tmp_path, monkeypatch):
    """d4_predicates_in_mapper — SEAM. `is_released(ticket)` lives in the mapper
    (`scripts/case_history/case_ticket.py`), and the screen decides through it: changing the
    mapping changes BOTH the predicate's answer and what the screen keeps, with no code edit
    (O5).

    Driven, not enumerated: the mapping is rewritten to a different released status, and the
    screen is then observed following it. An `isinstance`/`hasattr` check over the name would
    certify that it exists and never that it is WIRED — which is the discharge this demand
    exists to refuse.

    `ticket_screen` imports nothing from `query_tool` and is deliberately a LEAF (c6), so the
    predicate must reach it as an injected value rather than as an import back into it."""
    is_released = require(case_ticket, "is_released", "D4's predicate lives in the mapper")

    _mapping(monkeypatch, tmp_path, released_status="resolved")
    resolved = ticket("SOC-CUSTOM", status="resolved", comments=[comment(AGENT_TEXT)])

    assert is_released(resolved) is True
    assert is_released(_unreleased()) is False
    assert is_released(_released()) is False, (
        f"the previous released status {RELEASED_STATUS!r} still releases after the mapping "
        "named another — the predicate is keyed on a code literal, not on the mapping"
    )

    payload, code, _ = screen_list(listing(copy.deepcopy(resolved)))
    assert code == 0
    assert [c["body"] for c in served_comments(_one(payload))] == [AGENT_TEXT], (
        "the mapping moved and the screen did not follow it"
    )

    # The store's `closed` is no longer the released state under this mapping, so a closed
    # case serves nothing — the same wiring, observed in the other direction.
    out, code, _ = screen_list(listing(_released("SOC-STALE")))
    assert code == 0
    assert served_comments(_one(out)) == [], "the screen kept binding the retired status"


def test_767_release_predicate_cannot_be_built_in_a_serving_state(tmp_path, monkeypatch):
    """d_predicates_fail_closed_by_construction — SAFE BY CONSTRUCTION. §7 R1's downstream
    consequence, decided with FAM-1: once fail-closed lands, the predicate must be
    unbuildable in a state that defaults to SERVING unscreened content — the constructor
    RAISES rather than merely behaving when configured right.

    The constructor refuses a mapping missing `released.status`, carrying a non-string or
    blank one — never coercing, because a coerced list produces a status spelling no store
    will ever answer, which is a silent permanent un-release of the whole store (FK18) — and
    one whose `open.status` IS the released status, under which every case would open
    already released and the writer would refuse every record.

    The whitespace arm is the one normalisation the rework keeps, and it is on the MAPPING's
    side only: `" closed "` in a quoted YAML scalar configures `closed`, because the ticket's
    own status is compared exactly and a padded configured value would otherwise name a state
    nothing can reach.

    The second half is FK20's read-side extension, and it is the one the design genuinely
    left open: O7 is stated for the WRITE only, so a read-path config failure must not break
    a gather. A screen whose predicate cannot be built treats every ticket as UNRELEASED and
    returns a payload — it does not raise into the model's turn, and it does not refuse the
    whole call (N5 keeps the records visible) — and says so ONCE on stderr, because a
    degrade nobody can see is a store that mysteriously has no comments.

    `release_predicate` is coined by this spec, like every other symbol here; if the
    implementation spells the constructor otherwise, this name follows the code."""
    build = require(
        case_ticket, "release_predicate",
        "§7 R1 makes the predicate safe by construction: there is a constructor and it "
        "refuses the unsafe state",
    )
    root = tmp_path / "dfn"

    use_mapping(monkeypatch, root, mapping_doc())
    built = build()
    assert built.is_released(_released()) is True, "the control failed: a valid mapping builds"

    use_mapping(monkeypatch, root, mapping_doc(released_status=f"  {RELEASED_STATUS} "))
    assert build().is_released(_released()) is True, (
        "a quoted, padded `released.status` configured a state no ticket can carry"
    )
    assert build().is_released(_unreleased(status=f"  {RELEASED_STATUS} ")) is False, (
        "the ticket's own status was trimmed — the store's vocabulary is canonical"
    )

    unsafe = {
        "the released section is missing (FK11)": mapping_doc(with_released=False),
        "released.status is a list (FK18)": mapping_doc(released_status=["closed"]),
        "released.status is a number (FK18)": mapping_doc(released_status=7),
        "released.status is blank (FK19)": mapping_doc(released_status="  "),
        "open.status is the released status": mapping_doc(open_status=RELEASED_STATUS),
        "an unmigrated pre-767 mapping (FK13)": mapping_doc(
            with_comment=False, with_released=False,
            close_section={"status": "closed", "resolution": "{disposition} — {reason}"}),
    }
    for why, doc in unsafe.items():
        use_mapping(monkeypatch, root, doc)
        with pytest.raises(case_ticket.CaseTicketError):
            build()

        # FK20's read-side half: the screen degrades, it does not raise into the turn and it
        # does not refuse the whole call.
        payload, code, detail = screen_list(listing(_released(), _unreleased()))
        assert code == 0, f"{why}: the screen refused the whole gather call ({detail})"
        kept = served_tickets(payload)
        assert len(kept) == 2, f"{why}: records were dropped rather than screened (N5)"
        for t in kept:
            assert served_comments(t) == [], (
                f"{why}: a comment was served under a mapping the predicate cannot be built "
                "from — the undecidable case defaulted to SERVING"
            )
            assert t["summary"] == "a prior case", f"{why}: a record lost its other fields"

    use_mapping(monkeypatch, root, mapping_doc(comment_body="{disposition}"))
    assert build().is_released(_released()) is True, (
        "the control failed after the loop: a valid mapping must still build"
    )


def test_767_an_unreadable_mapping_file_degrades_the_screen(tmp_path, monkeypatch, said, caplog):
    """FK20's read-side degrade holds for a mapping that is not even text. A non-UTF-8 byte
    in the file is the loader's OWN typed refusal (so the writer can receipt it like any other
    mapping fault), and the screen degrades on it exactly as on a missing section: the call
    answers `0`, every record stays visible, no comment is served — and ONE warning names the
    cause on stderr, so the degrade is visible to the operator who can fix it rather than to
    nobody. The screen still catches EVERY exception out of the predicate, not only the typed
    one — a raise escaping into the query tool's generic fault path would refuse the whole
    ticket query as an INFRA fault and charge the `ticket` breaker for a config defect, the
    opposite of "never refuse the whole gather call" (N5)."""
    root = tmp_path / "dfn"
    use_mapping(monkeypatch, root, mapping_doc())
    path = root / "knowledge/environment/systems/case-history/mapping.yaml"
    path.write_bytes(b"released:\n  status: \xff\xfe not utf-8\n")

    with pytest.raises(case_ticket.CaseTicketError, match="UTF-8"):
        case_ticket.release_predicate()

    said.readouterr()
    payload, code, detail = screen_list(listing(_released(), _unreleased()))
    assert code == 0, f"an unreadable mapping refused the whole gather call ({detail})"
    kept = served_tickets(payload)
    assert len(kept) == 2, "records were dropped rather than screened (N5)"
    for t in kept:
        assert served_comments(t) == [], "a comment was served under an unreadable mapping"
        assert t["summary"] == "a prior case"
    warned = [r for r in caplog.records
              if r.levelname == "WARNING" and "ticket release predicate" in r.getMessage()]
    err = said.readouterr().err
    assert warned, (
        "the screen degraded silently — from every gather turn a broken mapping is now "
        "indistinguishable from a store with no comments"
    )
    assert "UTF-8" in err, "the warning does not name the cause"


# =======================================================================================
# Scale — what the model's view does with a listing of released cases
# =======================================================================================


def test_767_many_commented_tickets_stay_within_the_listing_ceiling(tmp_path, monkeypatch):
    """scale_model_view_stays_bounded — the model's view of a ticket listing stays BOUNDED,
    and the bound IS elision: verbatim delivery below `PASSTHROUGH_MAX_BYTES_DEFAULT` (8192
    bytes) and elision above it.

    THE PREMISE ANSWER THIS DEMAND WOULD HAVE BEEN WRITTEN FROM IS REFUTED (RFJ2/FK08). It
    asserted that each released ticket's served entry contains its one comment intact at the
    full 4096-byte bound, "not further elided". Claim c7, executed twice, observed
    `1x4096 (4223 B): verbatim` and `2x4096 (8421 B): ELIDED`. Written to that answer this
    test would be red forever, or "fixed" by raising `PASSTHROUGH_MAX_BYTES_DEFAULT` and
    silently widening every other gather payload in the system. It is written to what c7
    actually gives, at the boundary, on both sides.

    What keeps a listing SMALL after the rework is the writer, not the screen: a case a
    person closed takes no further record (`test_767_writer_never_records_behind_a_release`),
    so a closed case carries the runs that commented before the close and no more. The
    whole-payload ceiling has no per-item exemption (RFJ4): a single ticket that alone
    exceeds 8192 bytes elides the listing that contains it."""
    _mapping(monkeypatch, tmp_path)

    def released_with(n_bytes: int, key: str) -> dict:
        return _released(key, comments=[comment("c" * n_bytes)])

    one, code, _ = screen_list(listing(released_with(WIRE_BOUND_BYTES, "SOC-1")))
    assert code == 0
    one_view = rendered(one, tmp_path)
    assert len(json.dumps(one)) < PASSTHROUGH_MAX_BYTES_DEFAULT
    assert one_view == json.dumps(one), (
        "a single released ticket at the wire bound no longer renders verbatim (c7: 4223 B)"
    )

    two, code, _ = screen_list(listing(
        released_with(WIRE_BOUND_BYTES, "SOC-1"), released_with(WIRE_BOUND_BYTES, "SOC-2")))
    assert code == 0
    assert len(json.dumps(two)) > PASSTHROUGH_MAX_BYTES_DEFAULT
    two_view = rendered(two, tmp_path)
    assert two_view != json.dumps(two), (
        "two released tickets at the wire bound (c7: 8421 B) rendered verbatim — the ceiling "
        "moved, which widens every other gather payload in the system"
    )
    assert "<<ELIDED" in two_view, "the view grew past the ceiling without marking a reduction"

    # A closed case is served whole — the two comments a person closed over both survive —
    # and three such cases still fit under the ceiling.
    many = listing(*[
        _released(f"SOC-{i}", comments=[comment("c" * 600), comment("d" * 600)])
        for i in range(3)
    ])
    screened, code, _ = screen_list(many)
    assert code == 0
    for t in served_tickets(screened):
        assert len(served_comments(t)) == 2
    assert rendered(screened, tmp_path) == json.dumps(screened), (
        "three closed cases with two comments each no longer fit under the ceiling"
    )
