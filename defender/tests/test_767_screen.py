"""#767 — the read half: a later run sees agent-authored text only from approved cases.

Every test is one demand of `spec-flow/specs/spec_graph_767-ticket-store-approval.yaml`,
named by that demand's `discharged_by`. RED against `a77335d5` by construction: D4's
per-ticket approval step, the mapper's `is_approved`/`is_agent_comment` predicates and the
mapping's `approved:`/`comment:` sections are all coined by this spec.

The entry point every test here drives is the REAL one: `query_tool._screen_ticket_payload`,
the single insertion point the query tool calls after `handler(args)` and before
`_record`/`_model_view` (r5/c6). D4 attaches its step there, behind the own-case exclusion.

WHAT §7 DECIDED THAT EVERY ASSERTION HERE RESTS ON:

* **"The latest agent comment" is the last agent-authored entry in the STORE'S OWN LIST
  ORDER** (R3/FK02), not a `created`-timestamp sort — the stub appends and offers no sort
  (r4/c8), and the vendor is the ordering authority for a record defender does not own. List
  order is total, so FK03's tie question is moot; either way the rule must guarantee NEVER
  TWO, because O8's observable is a count.
* **Fail closed on the read side, and never raise into the model's turn** (R1/FAM-1). A
  ticket whose approval cannot be determined is UNAPPROVED. A comment whose authorship
  cannot be determined is AGENT-AUTHORED — the protective direction, chosen over the
  escalation copies' contradictory readings, which is why the phrase "fail closed" never
  appears here unqualified: the two copies used it, and the word "safe", for OPPOSITE
  behaviours on this exact member. An undecidable record is SCREENED AND KEPT in the
  listing, never dropped and never refused whole-call (N5's correlation benefit is not spent
  to solve a robustness problem).
* **The tag matches EXACTLY, with surrounding whitespace stripped and nothing else**
  (FK22) — no case folding, no unicode normalization, no prefix tolerance. A typo that fails
  to approve is visible and self-correcting; a confusable that approves is invisible and
  permanent. Whitespace is the one variant a vendor UI adds without a person's involvement.
* **`is_agent_comment` is a POSITIVE match against the mapping's identity SET** (FK23) —
  the current `comment.author` plus every `comment.author_aliases` entry (R4/FK10). A third
  identity (the stub's `system` transition stamp, a retired lane's `learning`) is NOT
  agent-authored and is served as non-agent content; the doc gives no vocabulary for "a
  person", so the negative reading is unimplementable as stated.
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
    AGENT_AUTHOR,
    APPROVED_LABEL,
    OTHER_KEY,
    SELF_KEY,
    WIRE_BOUND_BYTES,
    FakeStore,
    agent_comments,
    comment,
    listing,
    make_run,
    mapping_doc,
    record,
    rendered,
    require,
    screen_get,
    screen_list,
    served_tickets,
    ticket,
    use_mapping,
    write_report,
)

AGENT_TEXT = "PRIOR-RUN-NOTES-a-model-wrote-these"
OLDER_TEXT = "PRIOR-RUN-NOTES-an-earlier-run-wrote-these"
HUMAN_TEXT = "an analyst's own note"


def _mapping(monkeypatch, tmp_path, **kw):
    return use_mapping(monkeypatch, tmp_path / "dfn", mapping_doc(**kw))


def _approved(key: str = OTHER_KEY, *, comments=None, labels=None) -> dict:
    return ticket(
        key,
        labels=["sig:5710", APPROVED_LABEL] if labels is None else labels,
        comments=[comment(AGENT_TEXT)] if comments is None else comments,
    )


def _unapproved(key: str = "SOC-UNAPPROVED", *, comments=None, labels=None) -> dict:
    return ticket(
        key,
        labels=["sig:5710"] if labels is None else labels,
        comments=[comment(AGENT_TEXT)] if comments is None else comments,
    )


def _one(payload) -> dict:
    kept = served_tickets(payload)
    assert len(kept) == 1, f"expected one served ticket, got {[t.get('key') for t in kept]}"
    return kept[0]


# =======================================================================================
# O2 / S3 — agent text only from approved cases
# =======================================================================================


def test_767_unapproved_ticket_serves_no_agent_comment(tmp_path, monkeypatch):
    """o2_unapproved_no_agent_comment — NEGATIVE. No agent-authored comment from an
    unapproved case reaches a model, on either ticket verb, in the screened payload or in
    what gather's payload view renders from it.

    The undecidable arms take the SAME outcome, by §7 R1/FAM-1's read-side direction: a
    ticket with no `labels` key at all (FK14), a ticket whose `labels` is not a list, and a
    ticket in a listing the predicate cannot decide about (FK17) are all screened as
    UNAPPROVED and KEPT in the listing. A comment with no `author` is treated as
    AGENT-AUTHORED (FK15) and therefore withheld here.

    The adversarial arm is FK22's: a tag that is merely confusable with the configured
    spelling — different case, a prefix, a trailing word, a Cyrillic homoglyph — does NOT
    approve. The one concession is surrounding whitespace, which a vendor UI adds without a
    person's involvement, and that arm is a POSITIVE control: `" approved "` DOES approve, so
    the negatives above are not green merely because the predicate refuses everything.

    Its declared positive control on the same address is
    `o2_approved_serves_latest` — the same bytes ARE served once a person tags the case.
    """
    _mapping(monkeypatch, tmp_path)

    withheld = {
        "plainly unapproved": _unapproved(),
        "no labels field at all (FK14)": ticket(
            "SOC-NOLABELS", comments=[comment(AGENT_TEXT)], drop_labels=True),
        "labels is not a list (FAM-1)": ticket(
            "SOC-BADLABELS", labels="approved", comments=[comment(AGENT_TEXT)]),
        "an authorless comment (FK15)": _unapproved(
            "SOC-NOAUTHOR", comments=[comment(AGENT_TEXT, drop_author=True)]),
        "a null author (FK15)": _unapproved(
            "SOC-NULLAUTHOR", comments=[comment(AGENT_TEXT, author=None)]),
        "a confusable tag: case (FK22)": _unapproved(
            "SOC-CASE", labels=["Approved"]),
        "a confusable tag: a prefix (FK22)": _unapproved(
            "SOC-PREFIX", labels=["approved-by-soc"]),
        "a confusable tag: a homoglyph (FK22)": _unapproved(
            "SOC-HOMOGLYPH", labels=["аpproved"]),
    }
    for why, t in withheld.items():
        for verb, (payload, code, detail) in (
            ("list-tickets", screen_list(listing(copy.deepcopy(t)))),
            ("get-ticket", screen_get(copy.deepcopy(t))),
        ):
            assert code == 0, f"{why} on {verb}: the screen refused the whole call ({detail})"
            served = _one(payload) if verb == "list-tickets" else payload
            assert served is not None, f"{why} on {verb}: the record was dropped, not screened"
            assert agent_comments(served) == [], f"{why} on {verb}: an agent comment was served"
            assert AGENT_TEXT not in json.dumps(served, ensure_ascii=False), (
                f"{why} on {verb}: the agent's text survived somewhere in the record"
            )
            assert AGENT_TEXT not in rendered(served, tmp_path), (
                f"{why} on {verb}: the agent's text reached the model through the payload view"
            )

    # The whitespace concession — a POSITIVE control, so the negatives above cannot be green
    # merely because the predicate approves nothing at all.
    padded, code, _ = screen_list(listing(_unapproved("SOC-PADDED", labels=[f"  {APPROVED_LABEL} "])))
    assert code == 0
    assert [c["body"] for c in agent_comments(_one(padded))] == [AGENT_TEXT], (
        "a vendor UI's surrounding whitespace defeated approval — §7 FK22 strips surrounding "
        "whitespace and nothing else"
    )


def test_767_approved_ticket_serves_latest_agent_comment(tmp_path, monkeypatch):
    """o2_approved_serves_latest — an approved case serves exactly ONE agent comment: the
    LAST agent-authored entry in the store's own list order (§7 R3/FK02). Non-agent comments
    are untouched.

    The fixture's `created` stamps CONTRADICT list order on purpose: a `created`-timestamp
    sort would serve the older analysis, which is the reading §7 rejected — the stub appends
    and offers no sort (r4/c8), and the design's answer to freshness is the human's tag, not
    a sort. Two agent comments sharing an identical `created` are the FK03 arm: whichever
    rule a future re-litigation adopts, it must still return exactly one."""
    _mapping(monkeypatch, tmp_path)

    out_of_order = _approved(comments=[
        comment(OLDER_TEXT, created="2026-01-02T00:00:00Z"),
        comment(HUMAN_TEXT, author="analyst", created="2026-01-03T00:00:00Z"),
        comment(AGENT_TEXT, created="2026-01-01T00:00:00Z"),
    ])
    payload, code, _ = screen_list(listing(out_of_order))
    assert code == 0
    served = _one(payload)
    assert [c["body"] for c in agent_comments(served)] == [AGENT_TEXT], (
        "the served agent comment is not the last agent-authored entry in list order — a "
        "`created` sort would have served the earlier-arriving, later-stamped one"
    )
    assert HUMAN_TEXT in json.dumps(served), "a non-agent comment was dropped"

    tied = _approved("SOC-TIE", comments=[
        comment(OLDER_TEXT, created="2026-01-01T00:00:00Z"),
        comment(AGENT_TEXT, created="2026-01-01T00:00:00Z"),
    ])
    tied_payload, code, _ = screen_list(listing(tied))
    assert code == 0
    assert len(agent_comments(_one(tied_payload))) == 1, (
        "two agent comments with an identical `created` served more than one — O8's "
        "observable is a COUNT, so any rule that can return two is refuted by the obligation"
    )


def test_767_approval_screen_applies_on_both_ticket_verbs(tmp_path, monkeypatch):
    """o2_both_verbs_screened — PARITY, per access cell. Every constraint D4 states is
    enforced on `list-tickets` AND on `get-ticket`: the own-case exclusion, dropping agent
    comments when unapproved, keeping only the latest when approved, and leaving no marker.

    Bound per cell rather than facet-wide because that is the canonical fail-open this demand
    exists for — a constraint pinned on one verb and silently absent on its sibling. Both
    verbs reach the store through the same dispatch point (`_screen_ticket_payload`, r5), so
    the parity is asserted by driving the SAME record down both and comparing the surviving
    agent text cell by cell."""
    _mapping(monkeypatch, tmp_path)
    approved = _approved(comments=[comment(OLDER_TEXT), comment(AGENT_TEXT)])
    unapproved = _unapproved()

    for record_in, expected in ((approved, [AGENT_TEXT]), (unapproved, [])):
        listed, list_code, _ = screen_list(listing(copy.deepcopy(record_in)))
        got, get_code, _ = screen_get(copy.deepcopy(record_in))
        assert (list_code, get_code) == (0, 0)
        by_verb = {
            "list-tickets": [c["body"] for c in agent_comments(_one(listed))],
            "get-ticket": [c["body"] for c in agent_comments(got)],
        }
        assert by_verb["list-tickets"] == by_verb["get-ticket"] == expected, (
            f"the two verbs must both serve {expected} for {record_in['key']}; they served "
            f"{by_verb} — a constraint pinned on one access cell and absent on its sibling is "
            "the canonical fail-open"
        )


def test_767_approval_screen_runs_after_the_own_case_exclusion(tmp_path, monkeypatch):
    """d4_screen_after_own_case — D4's per-ticket step runs AFTER the own-case exclusion, in
    both verbs. The ordering is observable rather than read off source: the run's OWN case,
    approved and carrying an agent comment, is removed ENTIRELY from a listing and refused
    outright on `get-ticket` — an approval-first screen would have kept it and merely trimmed
    its comments.

    The control is the same record under a different key: a sibling case, approved and
    carrying the SAME two agent comments, survives — trimmed to its latest one, which is what
    makes the control discriminating rather than a pass-through."""
    _mapping(monkeypatch, tmp_path)
    both = [comment(OLDER_TEXT), comment(AGENT_TEXT)]
    own = _approved(SELF_KEY, comments=copy.deepcopy(both))
    sibling = _approved(OTHER_KEY, comments=copy.deepcopy(both))

    payload, code, _ = screen_list(listing(own, sibling))
    assert code == 0
    kept = served_tickets(payload)
    assert [t["key"] for t in kept] == [OTHER_KEY], (
        "the run's own approved case survived the listing — the own-case exclusion no longer "
        "runs first"
    )
    assert payload["total"] == 1, "`total` still advertises the record the screen removed"
    assert [c["body"] for c in agent_comments(kept[0])] == [AGENT_TEXT]

    refused, exit_code, detail = screen_get(copy.deepcopy(own))
    assert refused is None, "the run's own approved case was served through get-ticket"
    assert exit_code != 0, "get-ticket answered its own case with a success exit code"
    assert AGENT_TEXT not in detail, "the refusal detail carries the withheld content"


def test_767_screen_leaves_no_marker(tmp_path, monkeypatch):
    """d4_no_marker — NEGATIVE. The screen adds, removes and annotates nothing outside each
    ticket's own `comments` list: it returns the envelope it received, with `total` restated
    to what survived, and it follows the own-case exclusion's precedent — a screen filters
    SILENTLY. `payload_view`'s elision record stays the view's alone (c7's note).

    Its positive control is `o2_approved_serves_latest`: the screen demonstrably DOES change
    the comments list, so "nothing else changed" is not "nothing happened"."""
    _mapping(monkeypatch, tmp_path)
    source = _unapproved(comments=[comment(AGENT_TEXT), comment(HUMAN_TEXT, author="analyst")])
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
    assert [c["body"] for c in served["comments"]] == [HUMAN_TEXT], (
        "the positive half failed: the screen did not rewrite the comments list at all"
    )
    for kept in served["comments"]:
        assert set(kept) <= set(comment()), f"a comment gained an annotation: {sorted(kept)}"

    got, code, detail = screen_get(copy.deepcopy(source))
    assert (code, detail) == (0, ""), "get-ticket annotated its refusal channel instead"
    assert set(got) == set(source)


def test_767_unapproved_tickets_stay_visible_for_correlation(tmp_path, monkeypatch):
    """n5_unapproved_non_agent_fields_visible — an unapproved case is NOT withheld: its
    non-agent fields stay visible so a later run can still answer "is this already on the
    SOC's radar". Withholding unapproved tickets entirely was examined and rejected (N5).

    This is the demand that makes FAM-1's "screen it, keep it" concrete (FK17): a record the
    predicate cannot decide about is screened as unapproved and KEPT — neither dropped from
    the listing nor allowed to refuse the whole call, because dropping spends N5's stated
    benefit to solve a robustness problem and refusing turns one malformed record into a
    gather-wide outage."""
    _mapping(monkeypatch, tmp_path)
    undecidable = ticket("SOC-UNDECIDABLE", drop_labels=True, comments=[comment(AGENT_TEXT)])
    ordinary = _unapproved("SOC-OPEN", comments=[comment(HUMAN_TEXT, author="analyst")])
    approved = _approved()

    payload, code, _ = screen_list(listing(undecidable, ordinary, approved))
    assert code == 0, "one undecidable record refused the whole listing"
    kept = served_tickets(payload)
    assert [t["key"] for t in kept] == ["SOC-UNDECIDABLE", "SOC-OPEN", OTHER_KEY], (
        "an unapproved or undecidable record was dropped from the listing"
    )
    assert payload["total"] == 3
    for t in kept[:2]:
        assert t["summary"] == "a prior case", (
            "an unapproved record lost the summary correlation reads"
        )
        assert t["status"] == "open", "an unapproved record lost its lifecycle state"
    assert kept[1]["comments"][0]["body"] == HUMAN_TEXT, "a human comment was withheld"
    assert agent_comments(kept[0]) == []


def test_767_approved_ticket_with_no_agent_comment_is_unchanged(tmp_path, monkeypatch):
    """d_approved_ticket_without_agent_comment_unchanged — settled premise 39. An approved
    case carrying no agent comment is served with zero agent comments and every other field
    untouched: D4's "keep only the latest" over an empty set adds nothing and removes
    nothing.

    Byte-identity is the assertion, so a screen that rebuilt the record — reordering keys,
    dropping a field it did not recognise, stamping a marker — fails even though the agent
    comment count is trivially right."""
    _mapping(monkeypatch, tmp_path)
    source = _approved(comments=[comment(HUMAN_TEXT, author="analyst")])
    payload, code, _ = screen_list(listing(copy.deepcopy(source)))
    assert code == 0
    assert _one(payload) == source, "an approved case with no agent comment was rewritten"

    got, code, _ = screen_get(copy.deepcopy(source))
    assert (got, code) == (source, 0)


def test_767_each_query_is_screened_against_the_store_at_call_time(tmp_path, monkeypatch):
    """d_each_query_screened_at_call_time — settled premise 40. Each query is screened
    against the store state AT THE TIME OF THAT CALL: D4 is a per-payload step and the doc
    names no snapshot and no cache, so two queries in one run may legitimately see different
    approval outcomes.

    Driven as the pair the premise describes — the same record, read twice, with the person's
    tag added in between — so a screen that cached its first verdict fails on the second
    call rather than passing by construction."""
    _mapping(monkeypatch, tmp_path)
    before = _unapproved("SOC-PENDING")
    first, code, _ = screen_list(listing(copy.deepcopy(before)))
    assert code == 0
    assert agent_comments(_one(first)) == []

    after = copy.deepcopy(before)
    after["labels"] = [*after["labels"], APPROVED_LABEL]
    second, code, _ = screen_list(listing(after))
    assert code == 0
    assert [c["body"] for c in agent_comments(_one(second))] == [AGENT_TEXT], (
        "the second query in the same process saw the first query's verdict — D4 grew a "
        "snapshot or a cache the design does not name"
    )


def test_767_a_sibling_world_reads_through_the_same_screen(tmp_path, monkeypatch):
    """d_sibling_world_reads_through_the_same_screen — PARITY, settled premise 43. A sibling
    world's gather reaches the store through the IDENTICAL path: the own-case exclusion, then
    the D4 approval screen. No sibling exemption exists anywhere in D1-D8 (g12: nothing in
    the branch estate redirects the ticket system).

    Driven as parity across readers rather than across a code path: the same store state is
    screened once as the parent (`self_key` = the parent's case) and once as a sibling
    (`self_key` = the sibling's own id), and the two must agree on every case but the one
    each reader is itself working on.

    PROBE PR1 IS OPEN and decides only WHICH of the two filters removes the parent's fresh
    comment — whether a sibling's `run_id` differs from its parent's. Both filters are
    asserted here, so this demand holds either way: the parent's own case is excluded by
    identity for the parent, and it is unapproved for the sibling."""
    _mapping(monkeypatch, tmp_path)
    # A text distinct from AGENT_TEXT: the sibling's own approved case (`tagged_sibling_case`)
    # legitimately carries AGENT_TEXT and is visible to BOTH readers (the parity this test
    # drives), so the parent's own withheld comment needs its own, unique body — otherwise a
    # negative on AGENT_TEXT would be vacuously satisfied (or defeated) by the sibling's own
    # legitimate comment sharing the same literal text.
    parent_fresh_text = "PRIOR-RUN-NOTES-the-parents-own-fresh-comment"
    parent_case = _approved(SELF_KEY, comments=[comment(parent_fresh_text)])
    parent_case["labels"] = ["sig:5710"]  # the parent's fresh comment: nobody has tagged it yet
    tagged_sibling_case = _approved(OTHER_KEY)
    store = listing(parent_case, tagged_sibling_case)

    as_parent, code, _ = screen_list(copy.deepcopy(store), self_key=SELF_KEY)
    assert code == 0
    as_sibling, code, _ = screen_list(copy.deepcopy(store), self_key="20260917T000000Z-world-B")
    assert code == 0

    assert parent_fresh_text not in json.dumps(as_parent), (
        "the parent read back its own fresh comment"
    )
    assert parent_fresh_text not in json.dumps(as_sibling), (
        "a sibling world read the parent's un-approved comment — no sibling exemption exists"
    )
    parent_view = {t["key"]: [c["body"] for c in agent_comments(t)] for t in served_tickets(as_parent)}
    sibling_view = {t["key"]: [c["body"] for c in agent_comments(t)]
                    for t in served_tickets(as_sibling)}
    assert parent_view[OTHER_KEY] == sibling_view[OTHER_KEY] == [AGENT_TEXT], (
        "the two readers disagree about an approved case neither of them owns"
    )
    assert SELF_KEY not in parent_view, "the own-case exclusion did not fire for the parent"
    assert SELF_KEY in sibling_view, (
        "the sibling's own-case exclusion removed the parent's case, so this scenario proves "
        "nothing about the approval screen — re-site this demand on PR1's answer"
    )


def test_767_a_served_agent_comment_cannot_re_enter_without_a_second_human_act(
    tmp_path, monkeypatch
):
    """d_two_hop_chain_closed_by_approval — NEGATIVE, settled premise 61. The two-hop chain is
    closed by APPROVAL, not by content inspection: a run's own fresh comment lands on its own
    case, which is unapproved until a person tags it, so an approved comment's influence on a
    later report cannot re-enter any model's context without a SECOND human act.

    Driven end to end across the two halves this spec owns: the writer deposits a comment
    whose text is the very content a model read, and the screen then refuses to serve it back
    until the tag is present. The doc requires no detection of novel-vs-reproduced content
    (S5) — the hop is closed by the person, and this test's second half is that person acting.

    Its positive control is `o2_approved_serves_latest`; the inline control is the third step
    below, where the tag makes the same bytes servable."""
    _mapping(monkeypatch, tmp_path)
    laundered = "LAUNDERED-FROM-AN-UNAPPROVED-TICKET"
    run_dir = make_run(tmp_path, name=SELF_KEY, body=laundered)
    store = FakeStore()
    record(run_dir, store)
    body = store.comment_body()
    assert laundered in body, "the run's own record did not carry the round-tripped text"

    own_case = ticket(SELF_KEY, labels=["sig:5710"], comments=[comment(body)])
    served, code, _ = screen_list(listing(copy.deepcopy(own_case)))
    assert code == 0
    assert laundered not in json.dumps(served), "a run read its own fresh comment straight back"

    as_other, code, _ = screen_list(listing(copy.deepcopy(own_case)), self_key="some-later-run")
    assert code == 0
    assert laundered not in json.dumps(as_other), (
        "a LATER run read the comment with no person having tagged the case — the chain is "
        "closed by approval, and no approval has happened"
    )

    approved_case = copy.deepcopy(own_case)
    approved_case["labels"] = [*approved_case["labels"], APPROVED_LABEL]
    after_the_tag, code, _ = screen_list(listing(approved_case), self_key="some-later-run")
    assert code == 0
    assert laundered in json.dumps(after_the_tag), (
        "the control failed: the tag did not make the comment servable, so the negatives "
        "above could be green for any reason at all"
    )


def test_767_the_approved_label_is_served_to_the_model(tmp_path, monkeypatch):
    """d_approved_label_is_served_to_the_model — settled premise 70. The tag that governs the
    screen is itself in the `labels` a model reads back: D4 filters COMMENTS only, and N5
    keeps non-agent fields visible. That is harmless and deliberate — the model cannot write
    a label (O6/c2) and cannot become one (S5) — and it is what lets a later run see that a
    case has been released for reading."""
    _mapping(monkeypatch, tmp_path)
    payload, code, _ = screen_list(listing(_approved(), _unapproved()))
    assert code == 0
    kept = {t["key"]: t.get("labels") for t in served_tickets(payload)}
    assert APPROVED_LABEL in kept[OTHER_KEY], "the approved tag was stripped from the record"
    assert APPROVED_LABEL not in kept["SOC-UNAPPROVED"]
    assert APPROVED_LABEL in rendered(payload, tmp_path), (
        "the tag never reached the model through the payload view"
    )


def test_767_screen_ticket_comment_shape(tmp_path, monkeypatch):
    """d0_screen_shape — the screen's own return contract: `(payload, 0, "")` with each
    surviving ticket's `comments` rewritten IN PLACE, `total` restated to what survived, and
    every other field of every record untouched — including a LEGACY `resolution` written by
    the pre-#767 close lane.

    §7 R9/FK05 recorded that legacy field as an EXAMINED NO rather than a second field D4
    screens, and the ground is claim c3 (executed): on any close-tool report the `resolution`
    is the HOST's cause sentence, never the model's body — `close_tool.py:296` renders
    `cause:` unconditionally from the closed `REPORT_CAUSES` set, so a legacy `resolution`
    carries closed host vocabulary plus a `{disposition}`, not free model text. Extending the
    screen to it would buy nothing and widen `ticket_screen`'s binding to the stub envelope
    N8 deliberately scopes out.

    The malformed arms are FAM-1's, and every one of them is screened rather than raised into
    the model's turn: `comments` null, absent or not a list is treated as NO COMMENTS and the
    ticket is still served with its other fields (FK16); a comment from a THIRD identity — the
    stub's own `system` transition stamp, a retired lane's `learning` — is NOT agent-authored
    and is served on an unapproved case as non-agent content (FK23)."""
    _mapping(monkeypatch, tmp_path)
    legacy = _unapproved("SOC-LEGACY", comments=[comment(AGENT_TEXT)])
    legacy["resolution"] = "benign — Disposition recorded by the close gate. outcome=holds"

    payload, code, detail = screen_list(listing(copy.deepcopy(legacy)))
    assert (code, detail) == (0, "")
    served = _one(payload)
    assert served["resolution"] == legacy["resolution"], (
        "the screen grew a second field to screen; §7 R9 recorded `resolution` as an "
        "examined no on c3's ground"
    )
    assert agent_comments(served) == []

    for why, t in {
        "comments is null (FK16)": ticket("SOC-NULLC", labels=["sig:1"], comments=None),
        "comments is absent (FK16)": ticket("SOC-NOC", labels=["sig:1"], drop_comments=True),
        "comments is not a list (FK16)": ticket("SOC-STRC", labels=["sig:1"], comments="nope"),
    }.items():
        out, code, detail = screen_list(listing(copy.deepcopy(t)))
        assert code == 0, f"{why}: the screen raised into the model's turn ({detail})"
        kept = _one(out)
        assert kept["summary"] == "a prior case", f"{why}: the record lost its other fields"
        assert not agent_comments(kept), f"{why}: a comment was served from a malformed list"

    third = _unapproved("SOC-THIRD", comments=[
        comment("the store's own transition stamp", author="system"),
        comment("a retired lane's note", author="learning"),
        comment(AGENT_TEXT),
    ])
    out, code, _ = screen_list(listing(third))
    assert code == 0
    authors = [c.get("author") for c in _one(out)["comments"]]
    assert authors == ["system", "learning"], (
        "`is_agent_comment` is not a positive match against the mapping's identity set: a "
        "third identity must be served as non-agent content (FK23), and the agent's own "
        "comment must not be"
    )

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
    approved case does put its content in the turn."""
    _mapping(monkeypatch, tmp_path)
    for malformed in (None, "a string body", ["a bare array"], 17):
        payload, code, detail = screen_get(malformed)
        assert payload is None, f"{malformed!r} was passed through unscreened"
        assert code == MALFORMED_EXIT
        assert AGENT_TEXT not in detail

    served, code, _ = screen_get(_approved())
    assert code == 0, "the control failed: a successful read of an approved case was refused"
    assert AGENT_TEXT in json.dumps(served), (
        "the control failed: a successful read of an approved case served nothing, so the "
        "negatives above prove nothing about the read path"
    )


# =======================================================================================
# D4's predicates — where they live, and that they cannot be built in a serving state
# =======================================================================================


def test_767_approval_predicates_live_in_the_mapper(tmp_path, monkeypatch):
    """d4_predicates_in_mapper — SEAM. `is_approved(ticket)` and `is_agent_comment(comment)`
    live in the mapper (`scripts/case_history/case_ticket.py`), and the screen decides through
    them: changing the mapping changes BOTH the predicates' answers and what the screen keeps,
    with no code edit (O5).

    Driven, not enumerated: the mapping is rewritten to a different tag and a different agent
    identity, and the screen is then observed following it. An `isinstance`/`hasattr` check
    over the two names would certify that the fields exist and never that they are WIRED —
    which is the discharge this demand exists to refuse.

    `ticket_screen` imports nothing from `query_tool` and is deliberately a LEAF (c6), so the
    predicates must reach it as injected values rather than as an import back into it."""
    is_approved = require(case_ticket, "is_approved", "D4's predicates live in the mapper")
    is_agent = require(case_ticket, "is_agent_comment", "D4's predicates live in the mapper")

    _mapping(monkeypatch, tmp_path, approved_label="greenlit", comment_author="soc-bot")
    tagged = ticket("SOC-CUSTOM", labels=["greenlit"],
                    comments=[comment(AGENT_TEXT, author="soc-bot")])

    assert is_approved(tagged) is True
    assert is_approved(_unapproved()) is False
    assert is_agent(comment(AGENT_TEXT, author="soc-bot")) is True
    assert is_agent(comment(AGENT_TEXT, author=AGENT_AUTHOR)) is False, (
        "the previous agent identity still matches after the mapping named another — the "
        "predicate is keyed on a code literal, not on the mapping"
    )

    payload, code, _ = screen_list(listing(copy.deepcopy(tagged)))
    assert code == 0
    assert [c["body"] for c in agent_comments(_one(payload), authors=("soc-bot",))] == [AGENT_TEXT], (
        "the mapping moved and the screen did not follow it"
    )

    # The default identity is no longer agent-authored under this mapping, so its comment is
    # served on an unapproved case — the same wiring, observed in the other direction.
    stale = _unapproved("SOC-STALE", comments=[comment(AGENT_TEXT, author=AGENT_AUTHOR)])
    out, code, _ = screen_list(listing(stale))
    assert code == 0
    assert _one(out)["comments"], "the screen kept binding the retired identity"


def test_767_approval_predicates_cannot_be_built_in_a_serving_state(tmp_path, monkeypatch):
    """d_predicates_fail_closed_by_construction — SAFE BY CONSTRUCTION. §7 R1's downstream
    consequence, decided with FAM-1: once fail-closed lands, the predicates must be
    unbuildable in a state that defaults to SERVING unscreened content — the constructor
    RAISES rather than merely behaving when configured right.

    The loader refuses a mapping missing `comment.author`, missing `comment.body`, missing
    `approved.label`, or carrying a non-string `approved.label` — never coercing, because a
    coerced list produces a label spelling no person will ever type, which is a silent
    permanent un-approval of the whole store (FK18).

    The second half is FK20's read-side extension, and it is the one the design genuinely
    left open: O7 is stated for the WRITE only, so a read-path config failure must not break
    a gather. A screen whose predicates cannot be built treats every ticket as UNAPPROVED and
    every comment as AGENT-AUTHORED and returns a payload — it does not raise into the
    model's turn, and it does not refuse the whole call (N5 keeps the records visible).

    `approval_predicates` is coined by this spec, like every other symbol here; if the
    implementation spells the constructor otherwise, this name follows the code."""
    build = require(
        case_ticket, "approval_predicates",
        "§7 R1 makes the predicates safe by construction: there is a constructor and it "
        "refuses the unsafe state",
    )
    root = tmp_path / "dfn"

    use_mapping(monkeypatch, root, mapping_doc())
    built = build()
    assert built.is_approved(_approved()) is True, "the control failed: a valid mapping builds"

    unsafe = {
        "the comment section is missing (FK12)": mapping_doc(with_comment=False),
        "comment.author is missing (FK12)": mapping_doc(comment_author=None),
        "comment.author renders empty (FK19)": mapping_doc(comment_author=""),
        "comment.body is missing (FK12)": mapping_doc(comment_body=None),
        "the approved section is missing (FK11)": mapping_doc(with_approved=False),
        "approved.label is a list (FK18)": mapping_doc(approved_label=["approved"]),
        "approved.label is a number (FK18)": mapping_doc(approved_label=7),
        "an unmigrated pre-767 mapping (FK13)": mapping_doc(
            with_comment=False, with_approved=False,
            close_section={"status": "closed", "resolution": "{disposition} — {reason}"}),
    }
    for why, doc in unsafe.items():
        use_mapping(monkeypatch, root, doc)
        with pytest.raises(case_ticket.CaseTicketError):
            build()

        # FK20's read-side half: the screen degrades, it does not raise into the turn and it
        # does not refuse the whole call.
        payload, code, detail = screen_list(listing(_approved(), _unapproved()))
        assert code == 0, f"{why}: the screen refused the whole gather call ({detail})"
        kept = served_tickets(payload)
        assert len(kept) == 2, f"{why}: records were dropped rather than screened (N5)"
        for t in kept:
            assert agent_comments(t) == [], (
                f"{why}: agent text was served under a mapping the predicates cannot be "
                "built from — the undecidable case defaulted to SERVING"
            )
            assert t["summary"] == "a prior case", f"{why}: a record lost its non-agent fields"

    use_mapping(monkeypatch, root, mapping_doc(comment_body="{disposition}"))
    assert build().is_approved(_approved()) is True, (
        "the control failed after the loop: a valid mapping must still build"
    )


def test_767_an_unattributable_comment_is_never_served_unreleased(tmp_path, monkeypatch):
    """FK15's undecidable reading, applied to EVERY element of `comments` and not only to the
    object-shaped ones. `is_agent_comment` already answers "agent-authored" for a comment it
    cannot attribute — a bare string, a number, an object with no readable author — and the
    screen must put every element to it rather than pre-filter by shape: a shape check in
    the screen is a second, contradicting answer to the same question, under which a forged
    or vendor-mangled comment (N6: forged comments bypass D2/D3) walks past the predicate
    unexamined and is served on a case nobody released.

    The positive control is the released case, where the latest agent-authored entry — by
    the predicate's own reading — is served."""
    _mapping(monkeypatch, tmp_path)
    junk = ["PRIOR RUN NOTES as a bare string", 17, {"body": "no author at all"},
            {"author": ["not", "a", "string"], "body": "unreadable author"}]
    for element in junk:
        unreleased = _unapproved("SOC-JUNK", comments=[element, comment(AGENT_TEXT)])
        out, code, _ = screen_list(listing(copy.deepcopy(unreleased)))
        assert code == 0
        assert _one(out)["comments"] == [], (
            f"{element!r} was served on an unreleased case — the screen answered the "
            "attribution question itself instead of asking the predicate"
        )
        by_get, code, _ = screen_get(copy.deepcopy(unreleased))
        assert code == 0
        assert by_get["comments"] == [], f"{element!r} served through get-ticket"

    human_then_junk = _unapproved("SOC-MIXED", comments=[comment(HUMAN_TEXT, author="analyst"),
                                                         "a bare string"])
    out, code, _ = screen_list(listing(human_then_junk))
    assert code == 0
    assert [c["body"] for c in _one(out)["comments"]] == [HUMAN_TEXT], (
        "the analyst's own note was dropped alongside the unattributable one, or the "
        "unattributable one survived"
    )

    released = _approved("SOC-OK", comments=[comment(OLDER_TEXT), comment(AGENT_TEXT)])
    out, code, _ = screen_list(listing(released))
    assert code == 0
    assert [c["body"] for c in agent_comments(_one(out))] == [AGENT_TEXT], "the control failed"


def test_767_an_unreadable_mapping_file_degrades_the_screen(tmp_path, monkeypatch):
    """FK20's read-side degrade holds for EVERY way the predicates can fail to build, not only
    for the mapper's own typed refusal. The mapping is a file: a non-UTF-8 byte in it raises
    a decode error out of the loader, which is no `CaseTicketError`. A screen that caught only
    the typed refusal would let that raise escape into the query tool's generic fault path —
    refusing the whole ticket query as an INFRA fault and charging the `ticket` breaker for a
    config defect, the opposite of "never refuse the whole gather call" (N5).

    The observable is the same as the typed case's: the call answers `0`, every record stays
    visible, and no agent text is served."""
    root = tmp_path / "dfn"
    use_mapping(monkeypatch, root, mapping_doc())
    path = root / "knowledge/environment/systems/case-history/mapping.yaml"
    path.write_bytes(b"approved:\n  label: \xff\xfe not utf-8\n")

    # The control: the loader does NOT classify this one — it is the untyped raise the screen
    # must survive. Were it ever classified, this test would stop exercising that case.
    with pytest.raises(UnicodeDecodeError):
        case_ticket.approval_predicates()

    payload, code, detail = screen_list(listing(_approved(), _unapproved()))
    assert code == 0, f"an unreadable mapping refused the whole gather call ({detail})"
    kept = served_tickets(payload)
    assert len(kept) == 2, "records were dropped rather than screened (N5)"
    for t in kept:
        assert agent_comments(t) == [], "agent text was served under an unreadable mapping"
        assert t["summary"] == "a prior case"


def test_767_an_author_rename_does_not_unhide_history(tmp_path, monkeypatch):
    """d_author_alias_keeps_history_withheld — SECURITY. §7 R4/FK10: renaming the mapping's
    agent identity must not UN-HIDE history. `is_agent_comment` matches a SET — the current
    `comment.author` plus every `comment.author_aliases` entry — so a comment authored under
    a superseded spelling is still agent-authored, and is still withheld on an unapproved
    case.

    This is the half of FK10 that fails OPEN and the reason it was promoted: the approved-tag
    half of a mapping rename fails CLOSED (a case tagged under the old spelling reads as
    unapproved, a person re-tags), but the agent-author half fails OPEN — an old comment no
    longer matching the predicate is NOT dropped, and on an unapproved ticket it is served to
    the model. That is O2's exact failure witness, reached by editing a field O5 explicitly
    invites an operator to edit.

    The positive control is the same store record on an APPROVED case: the aliased comment is
    still recognised as the agent's, so it competes for — and takes — the single served slot
    rather than riding through as non-agent content."""
    _mapping(monkeypatch, tmp_path,
             comment_author="defender-v2", author_aliases=(AGENT_AUTHOR, "defender-v1"))

    for alias in (AGENT_AUTHOR, "defender-v1"):
        withheld = _unapproved(f"SOC-{alias}", comments=[comment(AGENT_TEXT, author=alias)])
        payload, code, _ = screen_list(listing(withheld))
        assert code == 0
        assert AGENT_TEXT not in json.dumps(_one(payload)), (
            f"a comment authored as the superseded spelling {alias!r} was served on an "
            "unapproved case — an operator's mapping rename un-hid the store's history"
        )

    approved = _approved(comments=[
        comment(OLDER_TEXT, author=AGENT_AUTHOR),
        comment(HUMAN_TEXT, author="analyst"),
        comment(AGENT_TEXT, author="defender-v2"),
    ])
    payload, code, _ = screen_list(listing(approved))
    assert code == 0
    served = _one(payload)
    kept = [c for c in served["comments"] if c.get("author") != "analyst"]
    assert [c["body"] for c in kept] == [AGENT_TEXT], (
        "the aliased comment was not treated as the agent's: it must compete for the single "
        f"served slot, not ride through as non-agent content (served {kept})"
    )
    assert HUMAN_TEXT in json.dumps(served), "the analyst's own comment was dropped"


# =======================================================================================
# O8 / Scale — the per-ticket bound, and what the model's view does with it
# =======================================================================================


def test_767_one_agent_comment_per_ticket_however_many_runs(tmp_path, monkeypatch):
    """o8_one_agent_comment_per_ticket — a ticket's agent text served to a model is bounded
    per ticket REGARDLESS of how many runs commented: the write side appends
    unconditionally, and the read side serves exactly one.

    §7 R6/FK35 settled the write half — append unconditionally, no write-side dedupe —
    precisely so this demand is FALSIFIABLE: a writer that no-op'd on repeat would make
    "exactly one is served" pass over a store that never held two. So both halves are driven
    here: the REAL writer records the same case three times, the three captured payloads are
    what the store then holds, and the screen serves the last of them in list order."""
    _mapping(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path, name="20260101T000000Z-prior", body="first run's notes")
    store = FakeStore()

    record(run_dir, store)
    for n in (2, 3):
        write_report(run_dir, body=f"run {n}'s notes")
        record(run_dir, store)

    posted = store.comment_payloads
    assert len(posted) == 3, (
        "the writer deduped: with only one comment ever on the ticket, the read-side "
        "'exactly one' assertion below would be unfalsifiable (§7 R6/FK35)"
    )

    accrued = _approved(comments=[
        comment(posted[0]["body"], author=posted[0]["author"]),
        comment(HUMAN_TEXT, author="analyst"),
        comment(posted[1]["body"], author=posted[1]["author"]),
        comment(posted[2]["body"], author=posted[2]["author"]),
    ])
    payload, code, _ = screen_list(listing(accrued))
    assert code == 0
    served = agent_comments(_one(payload))
    assert len(served) == 1, f"{len(served)} agent comments were served, not one"
    assert "run 3's notes" in served[0]["body"], (
        "the served comment is not the last agent-authored entry in the store's own list order"
    )
    assert "first run's notes" not in json.dumps(payload)


def test_767_many_commented_tickets_stay_within_the_listing_ceiling(tmp_path, monkeypatch):
    """scale_model_view_stays_bounded — the model's view of a ticket listing stays BOUNDED,
    and the bound IS elision: verbatim delivery below `PASSTHROUGH_MAX_BYTES_DEFAULT` (8192
    bytes) and elision above it.

    THE PREMISE ANSWER THIS DEMAND WOULD HAVE BEEN WRITTEN FROM IS REFUTED (RFJ2/FK08). It
    asserted that each approved ticket's served entry contains its one comment intact at the
    full 4096-byte bound, "not further elided". Claim c7, executed twice, observed
    `1x4096 (4223 B): verbatim` and `2x4096 (8421 B): ELIDED`. Written to that answer this
    test would be red forever, or "fixed" by raising `PASSTHROUGH_MAX_BYTES_DEFAULT` and
    silently widening every other gather payload in the system. It is written to what c7
    actually gives, at the boundary, on both sides.

    D4's one-comment-per-ticket rule is what keeps such a listing SMALL — not exempt (c7's
    own note). The whole-payload ceiling has no per-item exemption (RFJ4): a single ticket
    that alone exceeds 8192 bytes elides the listing that contains it."""
    _mapping(monkeypatch, tmp_path)

    def approved_with(n_bytes: int, key: str) -> dict:
        return _approved(key, comments=[comment("c" * n_bytes)])

    one, code, _ = screen_list(listing(approved_with(WIRE_BOUND_BYTES, "SOC-1")))
    assert code == 0
    one_view = rendered(one, tmp_path)
    assert len(json.dumps(one)) < PASSTHROUGH_MAX_BYTES_DEFAULT
    assert one_view == json.dumps(one), (
        "a single approved ticket at the wire bound no longer renders verbatim (c7: 4223 B)"
    )

    two, code, _ = screen_list(listing(
        approved_with(WIRE_BOUND_BYTES, "SOC-1"), approved_with(WIRE_BOUND_BYTES, "SOC-2")))
    assert code == 0
    assert len(json.dumps(two)) > PASSTHROUGH_MAX_BYTES_DEFAULT
    two_view = rendered(two, tmp_path)
    assert two_view != json.dumps(two), (
        "two approved tickets at the wire bound (c7: 8421 B) rendered verbatim — the ceiling "
        "moved, which widens every other gather payload in the system"
    )
    assert "<<ELIDED" in two_view, "the view grew past the ceiling without marking a reduction"

    # The per-ticket half D4 owns: however many runs commented, each served entry carries ONE
    # agent comment, which is what keeps a listing of approved cases small rather than exempt.
    many = listing(*[
        _approved(f"SOC-{i}", comments=[comment("c" * 600), comment("d" * 600)])
        for i in range(3)
    ])
    screened, code, _ = screen_list(many)
    assert code == 0
    for t in served_tickets(screened):
        assert len(agent_comments(t)) == 1
    assert rendered(screened, tmp_path) == json.dumps(screened), (
        "three approved cases with one agent comment each no longer fit under the ceiling"
    )
