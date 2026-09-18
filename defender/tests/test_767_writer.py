"""#767 — the host records its investigation into the case, and a person closes it.

THE WRITE HALF. Every test is one demand of
`spec-flow/specs/spec_graph_767-ticket-store-approval.yaml`, named by that demand's
`discharged_by`. RED against `a77335d5` by construction: `record_case_ticket`,
`case_record_to_comment`, the `CaseRecord` split and the release predicate are all coined by
this spec and none of them exists yet. If the implementation spells one otherwise, these
names follow the code.

WHAT §7 DECIDED THAT EVERY ASSERTION HERE RESTS ON:

* **One bound, 4096 UTF-8 BYTES on the rendered body** (R2/FK01). `_TICKET_REASON_MAX`
  (472 characters, r2/c10) retires with `CaseRecord.reason`; the cut rounds DOWN to the
  last whole character and the `…` sits INSIDE the bound.
* **Fail closed on the write side, never into the run** (R1/FAM-1). The writer refuses to
  POST rather than send an unattributable comment; it warns; the exit code is unchanged (O7).
* **The release signal is the case's lifecycle STATUS, which the store's own closed
  vocabulary enforces** — so no alert-rendered field can move a case along its lifecycle,
  and the loader needs no guard over label templates at all. The one thing the loader
  refuses is a mapping whose `open.status` IS its `released.status`, under which every case
  would open already released and every record would be refused.
* **O7 is the whole obligation on a fault** (R6/FAM-3). One POST, no retry; every fault is
  caught, warned once, and leaves the exit code exactly what it would have been; the receipt
  is written on BOTH branches with `ok` reflecting the outcome (r1/c14 — copy2's "no receipt
  on failure" reading is REFUTED and is not carried here).
* **The bounds are properties of the HOST'S OWN WRITE** (FK41). Nothing here claims 4096
  bytes about anything the store hands back; a forged comment bypasses this whole lane (N6).
"""
from __future__ import annotations

import inspect
import json
import re

import pytest

from defender.scripts.case_history import case_ticket, ticket_writer
from defender.tests._spec767 import (
    AGENT_AUTHOR,
    OPEN_STATUS,
    RELEASED_STATUS,
    COMMENTS_SUFFIX,
    ELLIPSIS,
    HOST_CAUSE,
    NO_NOTES,
    TICKETS_PATH,
    TRANSITIONS_SUFFIX,
    WIRE_BOUND_BYTES,
    FakeStore,
    make_run,
    mapping_doc,
    open_ticket,
    receipt,
    record,
    require,
    shipped_mapping_doc,
    ticket,
    use_mapping,
    write_mapping,
    writer_deps,
)

STANDALONE_FENCE = re.compile(r"(?m)^---\s*$")


def _case_record(**kw):
    """A `CaseRecord` as D3 splits it — `cause` (the host sentence) and `narrative` (the
    report body), never the retired single `reason`."""
    cls = require(case_ticket, "CaseRecord", "D3 splits CaseRecord.reason into cause + narrative")
    fields = {
        "case_id": "20260917T000000Z-sshd",
        "signature_id": "5710",
        "disposition": "benign",
        "cause": HOST_CAUSE,
        "narrative": "The account is a decommissioned service identity.",
    }
    fields.update(kw)
    return cls(**fields)


def _render_comment(rec):
    fn = require(
        case_ticket, "case_record_to_comment",
        "D3 replaces case_record_to_close with case_record_to_comment",
    )
    return fn(rec)


# =======================================================================================
# Demand #0 — the return-value contract, the rendered comment, the receipt
# =======================================================================================


def test_767_record_case_ticket_returns_and_receipts(tmp_path, monkeypatch):
    """d0_record_return — `record_case_ticket(run_dir, deps)` returns nothing, posts exactly
    one comment to `POST /tickets/{case_id}/comments` and no transition, and leaves a
    `run_dir/ticket_write.json` receipt `{key, status, url, ok}` on BOTH branches — the
    success word is `"commented"`, not `"closed"`, and a fault writes `ok: false`.

    §7 R6/FK29 decided the success word: the receipt has ZERO readers (c5), so nothing breaks,
    and keeping `"closed"` would record an event that no longer happens — after D2 the host
    closes nothing. The failure branch's receipt is r1/c14's own observation, not a new
    obligation: the `'error'` word and the `ok` boolean exist precisely for it."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    run_dir = make_run(tmp_path)

    ok_store = FakeStore()
    assert record(run_dir, ok_store) is None, "the post-step returns a value some caller reads"
    assert [(c.method, c.path) for c in ok_store.writes()] == [
        ("POST", f"{TICKETS_PATH}/{run_dir.name}{COMMENTS_SUFFIX}")
    ], "D2 is ONE comment POST and no transition"
    assert [(c.method, c.path) for c in ok_store.calls] == [
        ("GET", f"{TICKETS_PATH}/{run_dir.name}"),
        ("POST", f"{TICKETS_PATH}/{run_dir.name}{COMMENTS_SUFFIX}"),
    ], "the writer reads the case back once, before its one POST, and nothing else"
    assert not ok_store.paths(TRANSITIONS_SUFFIX), "the host still transitions the case (N1/O1)"

    good = receipt(run_dir)
    assert good["key"] == run_dir.name
    assert good["ok"] is True
    assert good["status"] == "commented", (
        "the receipt still says `closed` — after D2 nothing closes, so that word records a "
        "false event (§7 R6/FK29)"
    )
    assert good["url"].endswith(f"{TICKETS_PATH}/{run_dir.name}")

    failed_dir = make_run(tmp_path, name="20260917T000001Z-sshd")
    record(failed_dir, FakeStore(transport_fault_on=COMMENTS_SUFFIX))
    bad = receipt(failed_dir)
    assert bad["ok"] is False, "the failure branch wrote no `ok: false` receipt"
    assert bad["status"] != "commented", "a failed POST is receipted as a success"


def test_767_case_record_to_comment_shape(tmp_path, monkeypatch):
    """d0_comment_render — the outbound comment is `{author, body}` and its body is the
    mapping's own `"{disposition} — {cause}\\n\\n{narrative}"` rendering: the proposed
    disposition and the host's cause sentence on the first line, a blank line, then the
    report's notes. An EMPTY narrative renders `(no notes)` in the narrative segment alone —
    the disposition line and the blank line survive (20-demands F2, settled with FK06's
    split: an empty BODY under a parsable disposition is the ordinary branch).

    Asserted against the fake's CAPTURED INBOUND PAYLOAD as well as the renderer's return, so
    the outbound channel is pinned and not just the pure function."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    rendered = _render_comment(_case_record())
    assert set(rendered) == {"author", "body"}, (
        f"the comment payload carries fields beyond {{author, body}}: {sorted(rendered)}"
    )
    assert rendered["body"] == (
        f"benign — {HOST_CAUSE}\n\nThe account is a decommissioned service identity."
    )

    empty = _render_comment(_case_record(narrative=""))
    assert empty["body"] == f"benign — {HOST_CAUSE}\n\n{NO_NOTES}", (
        "an empty narrative must render the no-notes marker in the NARRATIVE SEGMENT; the "
        "disposition line and the blank line are not part of what it replaces"
    )

    run_dir = make_run(tmp_path, body="The account is a decommissioned service identity.")
    store = FakeStore()
    record(run_dir, store)
    assert store.comment_body() == rendered["body"], (
        "what crossed the wire is not what the renderer produced"
    )


# =======================================================================================
# O1 — the disposition and the case's lifecycle are a person's
# =======================================================================================


def test_767_open_payload_status_and_labels(tmp_path, monkeypatch):
    """o1_open_payload_status_open — the bridge open carries the mapping's literal
    `status: open`, and NO alert field reaches that status: a crafted `rule.id`, description
    and timestamp whose values are the released status's own spelling render into the
    labels and summary they are templated into and nowhere else.

    That is the whole of the write-side guarantee, and it needs no loader guard: the status
    is a literal in the `open:` section, the store enforces its vocabulary, and a label — any
    label — is not a lifecycle state. `alert_to_open_payload` hands the WHOLE `open:` section
    to the wire unfiltered (g7), so the assertion is over the payload's every value, not over
    `labels` alone."""
    use_mapping(monkeypatch, tmp_path / "dfn")

    hostile = {"rule": {"id": RELEASED_STATUS, "description": RELEASED_STATUS},
               "timestamp": RELEASED_STATUS}
    payload = case_ticket.alert_to_open_payload(hostile, "case-1")

    assert payload["status"] == OPEN_STATUS, "an alert field moved the open's status"
    assert payload["labels"] == [f"sig:{RELEASED_STATUS}", f"evt:{RELEASED_STATUS}"]
    assert payload["summary"] == RELEASED_STATUS
    # Positive control on the same address: the ordinary alert still ships its labels, so the
    # assertion above is not green merely because the label set is empty.
    ordinary = case_ticket.alert_to_open_payload(
        {"rule": {"id": "5710", "description": "sshd"}, "timestamp": "2026-05-07T07:15:01Z"},
        "case-2",
    )
    assert ordinary["labels"] == ["sig:5710", "evt:2026-05-07T07:15:01Z"]
    assert ordinary["status"] == OPEN_STATUS


def test_767_writer_never_records_behind_a_release(tmp_path, monkeypatch, capsys):
    """The writer's half of the release invariant. A person's close is a statement about the
    comments on the ticket WHEN THEY CLOSED IT; the screen serves a closed case whole, so a
    comment appended after the close would be served under it with no person having seen it.
    The writer never moves the status (O1), so it keeps the close true the only other way: it
    reads the case back first and refuses to append to a released one — a receipt, a warning,
    and no POST.

    Undecidable reads as released: a case the writer cannot read back (no such key, a
    transport fault, a reply that is not a ticket object) is not written to either — and so
    is a case whose release the MAPPING cannot spell (no `released:` section), which is a
    config fault and receipts like one rather than escaping past the receipt. Each arm
    starts from a run dir with no receipt, so the assertion is about that arm's own write.
    The positive control is the default fake's open case, on which the POST proceeds."""
    root = tmp_path / "dfn"
    use_mapping(monkeypatch, root)
    run_dir = make_run(tmp_path)

    released = FakeStore(ticket=ticket("any", status=RELEASED_STATUS, labels=["sig:5710"]))
    assert record(run_dir, released) is None
    assert released.writes() == [], "the writer appended a comment behind a person's close"
    assert [c.method for c in released.calls] == ["GET"], "the writer did more than read back"
    assert receipt(run_dir) == {
        **receipt(run_dir), "status": ticket_writer.RECEIPT_REFUSED_RELEASED, "ok": False,
    }
    assert "WARN" in capsys.readouterr().err, "the refusal was silent"

    for why, store, doc in (
        ("no such key (404 on the read-back)", FakeStore(ticket=None), None),
        ("a transport fault on the read-back",
         FakeStore(transport_fault_on=f"{TICKETS_PATH}/{run_dir.name}"), None),
        ("a (None, detail) transport error on the read-back",
         FakeStore(transport_error_on=f"{TICKETS_PATH}/{run_dir.name}"), None),
        ("a read-back that is not JSON",
         FakeStore(status_by_suffix={f"{TICKETS_PATH}/{run_dir.name}": "200"},
                   body="<html>not json"), None),
        ("a read-back that is JSON but not a ticket object",
         FakeStore(status_by_suffix={f"{TICKETS_PATH}/{run_dir.name}": "200"}, body="[1, 2]"),
         None),
        ("a mapping that cannot spell the released state",
         FakeStore(), mapping_doc(with_released=False)),
    ):
        use_mapping(monkeypatch, root, doc)
        undecidable_dir = make_run(tmp_path, name=run_dir.name)
        (undecidable_dir / "ticket_write.json").unlink(missing_ok=True)
        assert record(undecidable_dir, store) is None, f"{why}: the fault escaped into the run"
        assert store.writes() == [], f"{why}: the writer POSTed without knowing the case's state"
        assert receipt(undecidable_dir)["ok"] is False, f"{why}: receipted as a success"
    use_mapping(monkeypatch, root)

    control = FakeStore()
    record(run_dir, control)
    assert [c.method for c in control.calls] == ["GET", "POST"], (
        "the control failed: an unreleased case was not recorded, so the refusals above prove "
        "nothing"
    )
    assert receipt(run_dir)["ok"] is True


def test_767_no_host_payload_sets_verdict(tmp_path, monkeypatch, capsys):
    """o1_no_host_verdict_write — NEGATIVE. No payload the host sends carries a case verdict
    or moves the case's lifecycle: not the open, not the record, and there is no third write
    site. `status` other than the bridge's `open`, any `resolution`, and the released status
    are all absent from every outbound body, and no transition path is requested at all.

    Bound over EVERY surface the content could reach: the two POST bodies, their paths, and
    the receipt the run leaves on disk. The positive control is
    `o1_open_payload_status_and_labels` — the open's own `status: open` and its label set DO
    cross, so "absent" here is not "the payload was empty"."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    run_dir = make_run(tmp_path)
    store = FakeStore()

    open_ticket(run_dir, store)
    record(run_dir, store)

    assert [c.path for c in store.writes()] == [
        TICKETS_PATH, f"{TICKETS_PATH}/{run_dir.name}{COMMENTS_SUFFIX}"
    ], "the writer's site census is two POSTs — an open and a comment (c1/r3, S1)"

    for call in store.writes():
        body = call.body if isinstance(call.body, dict) else {}
        wire = json.dumps(body, ensure_ascii=False)
        assert "resolution" not in body, f"{call.path} carries a resolution"
        assert body.get("status", OPEN_STATUS) == OPEN_STATUS, (
            f"{call.path} sets a status the host owns"
        )
        assert f'"{RELEASED_STATUS}"' not in wire, (
            f"{call.path} carries the released status verbatim"
        )
    assert not store.paths(TRANSITIONS_SUFFIX), "the host requested a transition"

    assert RELEASED_STATUS not in json.dumps(receipt(run_dir)), "the receipt carries the status"
    assert RELEASED_STATUS not in capsys.readouterr().err, "the writer's log carries the status"


def test_767_alert_content_cannot_reach_the_lifecycle(tmp_path, monkeypatch):
    """o1_alert_cannot_move_lifecycle — the release signal has no surface an alert can reach.
    The retired label guard existed because labels were BOTH the release channel and a slot
    alert fields render into; a status is neither templated from an alert in the shipped
    mapping nor, on the store's side, anything but a closed vocabulary. So the loader walks
    no templates and refuses nothing about labels: an operator may template any label they
    like, including one spelled exactly `closed`, and the open still opens `open`.

    The one refusal that remains is about the MAPPING's own two literals: `open.status`
    equal to `released.status` opens every case already released. That is a config error a
    person makes, refused at construction and named, not an attack surface."""
    root = tmp_path / "dfn"

    for why, labels in (
        ("a label with no prefix", ("{signature}", "evt:{event_time}")),
        ("a label that is the released status's own spelling", ("sig:{signature}", RELEASED_STATUS)),
        ("a bare-string label template", "{summary}"),
    ):
        use_mapping(monkeypatch, root, mapping_doc(open_labels=labels) if isinstance(labels, tuple)
                    else mapping_doc(extra_open={"labels": labels}))
        loaded = case_ticket._load_mapping()
        assert loaded["open"]["labels"], f"{why}: the loader refused a label template"
        payload = case_ticket.alert_to_open_payload(
            {"rule": {"id": RELEASED_STATUS, "description": RELEASED_STATUS},
             "timestamp": RELEASED_STATUS}, "c",
        )
        assert payload["status"] == OPEN_STATUS, f"{why}: an alert moved the open's status"
        assert case_ticket.is_released(payload) is False, (
            f"{why}: the open payload reads as released"
        )

    use_mapping(monkeypatch, root, mapping_doc(open_status=RELEASED_STATUS))
    with pytest.raises(case_ticket.CaseTicketError) as refusal:
        case_ticket.release_predicate()
    assert RELEASED_STATUS in str(refusal.value), (
        "the loader refused an open/released collision without naming the status"
    )


def test_767_the_shipped_mapping_loads_and_a_broken_one_skips_the_write(
    tmp_path, monkeypatch, capsys
):
    """d_loader_refusal_positive_control — the POSITIVE CONTROL for the mapper's refusals,
    and §7 R12/FK-X1's decision: today's shipped mapping LOADS and records, a mapping whose
    `open.status` is its `released.status` is refused, and a refusal warns and skips the
    write rather than aborting the run.

    Without this demand every refusal test passes just as well against a loader that refuses
    EVERYTHING. §7 R12: warn and skip, never abort — O7 is a whole-lane guarantee and a
    config error must not take the estate's detection offline; the estate write is the
    expendable part, which is what O7's precedence over O4 already says."""
    root = tmp_path / "dfn"
    shipped = shipped_mapping_doc()
    for dead in ("close", "annotate", "enrich"):
        shipped.pop(dead, None)

    use_mapping(monkeypatch, root, shipped)
    loaded = case_ticket._load_mapping()
    assert loaded["open"]["labels"], "the shipped mapping was refused"
    assert case_ticket.release_predicate().is_released(
        case_ticket.alert_to_open_payload({"rule": {"id": "5710"}}, "c")
    ) is False, "the shipped mapping opens a case already released"

    run_dir = make_run(tmp_path)
    store = FakeStore()
    record(run_dir, store)
    assert store.comment_payloads, "the shipped mapping did not produce a comment"

    use_mapping(monkeypatch, root, mapping_doc(open_status=RELEASED_STATUS))
    refused_dir = make_run(tmp_path, name="20260917T000002Z-sshd")
    refused_store = FakeStore()
    assert record(refused_dir, refused_store) is None, "a refused mapping aborted the run"
    assert refused_store.writes() == [], "a refused mapping still wrote to the estate"
    assert "WARN" in capsys.readouterr().err, "the refusal was skipped silently"


# =======================================================================================
# O3 / S1 — attributable writes, and nothing else on the wire
# =======================================================================================


def test_767_comment_carries_mapping_author(tmp_path, monkeypatch, capsys):
    """o3_comment_author_identity — every comment the system writes carries the mapping's
    fixed author identity, and a mapping that cannot supply one produces NO write at all.

    §7 R1/FAM-1, write side: the writer REFUSES TO POST rather than send an unattributable
    comment, warns, and leaves the exit code unchanged (O7). C1's phrase "fail closed BY
    ACCIDENT" is why this is pinned rather than assumed — an accidental fail-closed is not a
    specification. Two undecidable shapes are exercised: the `comment` section missing
    entirely (FK12) and an author that renders to the empty string (FK19 — an unattributable
    comment on a store where attribution is what a person reads to know whose note it is).

    Asserted on the CAPTURED INBOUND PAYLOAD; the identity is read back out of the mapping
    the test wrote, never a literal the writer may hardcode (that is o5's demand)."""
    root = tmp_path / "dfn"
    use_mapping(monkeypatch, root, mapping_doc(comment_author="soc-bot"))
    run_dir = make_run(tmp_path)
    store = FakeStore()
    record(run_dir, store)
    assert store.only_comment()["author"] == "soc-bot", (
        "the author on the wire does not follow the mapping"
    )

    for n, (why, doc) in enumerate((
        ("the comment section is missing (FK12)", mapping_doc(with_comment=False)),
        ("the author renders empty (FK19)", mapping_doc(comment_author="")),
        ("the author key is absent (FK12)", mapping_doc(comment_author=None)),
    )):
        use_mapping(monkeypatch, root, doc)
        silent_dir = make_run(tmp_path, name=f"run-unattributable-{n}")
        silent = FakeStore()
        assert record(silent_dir, silent) is None, f"{why}: the writer raised into the run"
        assert silent.calls == [], f"{why}: an unattributable comment was POSTed anyway"
    assert "WARN" in capsys.readouterr().err, "the refusals were silent"


def test_767_comment_payload_keys_are_author_and_body_only(tmp_path, monkeypatch):
    """s1_payload_keys_subset — the record's outbound payload keys are exactly
    `{author, body}`: the renderer emits the mapping's `comment:` section and nothing else,
    so no status, resolution, label or transition field can ride along even when the mapping
    carries them elsewhere.

    The control is the same call with a mapping whose `close:` section is still present and
    populated (FK27): those keys are inert — nothing reads them after D5 — and they must not
    reach the wire through the comment write."""
    use_mapping(monkeypatch, tmp_path / "dfn", mapping_doc(close_section={
        "status": "closed",
        "resolution": "{disposition} — {cause}",
        "author": "someone-else",
        "comment": "Disposition: {disposition}.",
    }))
    run_dir = make_run(tmp_path)
    store = FakeStore()
    record(run_dir, store)

    payload = store.only_comment()
    assert set(payload) == {"author", "body"}, (
        f"the comment payload carries {sorted(set(payload) - {'author', 'body'})} beyond "
        "{author, body}"
    )
    assert payload["author"] == AGENT_AUTHOR, (
        "the writer bound the stale `close.author` instead of the top-level `comment.author` "
        "— the two sections spell the same key names (r6/FK27) and the binding must be explicit"
    )
    assert payload["body"].startswith("benign — ")


# =======================================================================================
# O4 — what a person needs to approve
# =======================================================================================


def test_767_comment_first_line_is_proposed_disposition(tmp_path, monkeypatch):
    """o4_first_line_disposition — the comment's FIRST line is the host-rendered
    `{disposition} — {cause}`, above a blank line, so a person opening the case reads the
    proposed disposition before anything the model wrote.

    O4's own failure witness is "a comment whose first line lacks the proposed disposition",
    and the structural guarantee is exactly this wide (S5/N11): the first line is host-
    rendered from the closed cause vocabulary and the author is a field. Nothing about the
    narrative's content is claimed."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    for disposition in ("benign", "malicious", "false-positive", "inconclusive"):
        run_dir = make_run(tmp_path, name=f"run-{disposition}", disposition=disposition,
                           body="model notes")
        store = FakeStore()
        record(run_dir, store)
        body = store.comment_body()
        first, blank, rest = body.split("\n", 2)
        assert first == f"{disposition} — {HOST_CAUSE}", f"first line is {first!r}"
        assert blank == "", "the host line and the narrative are not separated by a blank line"
        assert rest.strip() == "model notes"


def test_767_unreadable_report_still_comments(tmp_path, monkeypatch):
    """o4_unreadable_report_records_the_fact — a run whose report yields no parsable
    disposition still comments, with a host sentence saying so and NO narrative; an EMPTY
    `report.md` takes that same branch (§7 R10/FK06).

    BINDING IMPLEMENTATION CONSTRAINT (§7 R10, the human's own words): the empty-report case
    must NOT be built as a second, bespoke emptiness check. `defender._report` is the SINGLE
    existing reader of `report.md` — `read_case_record` already goes through
    `require_report`, which raises `ReportUnreadable` exactly when `read_report(...)` yields
    no disposition — and the unreadable classification must be a CONSUMER of that reader's own
    result. This test is written so a parallel reader cannot satisfy it: the expected
    classification is COMPUTED IN THE TEST from `_report.read_report` over each member, never
    enumerated as a literal, and every member of the no-disposition family must produce the
    SAME host sentence. A bespoke check that handled "empty" on its own would have to
    reproduce the shared reader's verdict on every other member — missing file, no
    frontmatter, unparsable frontmatter, a disposition outside the vocabulary — to stay green.

    The positive control is the complementary condition FK06 splits on: a report with a
    PARSABLE disposition and an empty body is the ORDINARY branch, rendering `(no notes)`.
    """
    from defender._report import read_report

    use_mapping(monkeypatch, tmp_path / "dfn")

    members = {
        "empty": "",
        "whitespace-only": "   \n\n\t\n",
        "no frontmatter at all": "just prose, no fence\n",
        "frontmatter with no disposition": "---\ncase_id: c\nconfidence: high\n---\nbody text\n",
        "a disposition outside the vocabulary":
            "---\ndisposition: totally-not-a-disposition\n---\nbody text\n",
    }
    sentences = {}
    for n, (why, text) in enumerate(members.items()):
        run_dir = make_run(tmp_path, name=f"run-unreadable-{n}", text=text)
        assert read_report(run_dir / "report.md").disposition is None, (
            f"the shared reader DOES parse a disposition from {why!r} — this member belongs "
            "to the ordinary branch, and the family this test derives has moved"
        )
        store = FakeStore()
        record(run_dir, store)
        body = store.comment_body()
        assert "body text" not in body, f"{why}: the report's text crossed as a narrative"
        assert NO_NOTES not in body, f"{why}: the ordinary branch's marker was rendered instead"
        assert len(body.split()) > 3, (
            f"{why}: the body is a marker token, not a host sentence — D2 says `a host "
            "sentence saying so`, and `(unreadable)` must not become a literal by accident"
        )
        sentences[why] = body

    assert len(set(sentences.values())) == 1, (
        "the no-disposition family produced more than one host sentence "
        f"({sentences}) — the branch is keyed on something other than the shared reader's "
        "single 'no parsable disposition' result"
    )

    # The missing file is the same family, reached without writing a report at all.
    missing = tmp_path / "run-missing"
    missing.mkdir()
    missing.joinpath("alert.json").write_text("{}", encoding="utf-8")
    missing_store = FakeStore()
    record(missing, missing_store)
    assert missing_store.comment_body() == next(iter(sentences.values()))

    # Positive control — the complementary condition.
    ordinary = make_run(tmp_path, name="run-ordinary", body="")
    ordinary_store = FakeStore()
    record(ordinary, ordinary_store)
    assert ordinary_store.comment_body() == f"benign — {HOST_CAUSE}\n\n{NO_NOTES}"


def test_767_narrative_is_the_fence_stripped_report_body(tmp_path, monkeypatch):
    """o4_narrative_is_report_body — the narrative segment is the report's own body, carried
    verbatim up to the 4096-byte wire bound, with the frontmatter-fence strip applied.

    This is `s4_no_standalone_fence`'s POSITIVE CONTROL and takes its shape: the same bytes
    that a planted fence would have truncated ARE delivered through the sanctioned path when
    no fence is present. Under §7 R2 there is ONE bound and it is 4096 bytes, so a body of a
    few hundred characters crosses whole — under a surviving 472-character
    `_TICKET_REASON_MAX` (r2) it would arrive as two sentences."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    body = (
        "The account is a decommissioned service identity retained for a quarterly batch "
        "job. " * 12
    ).strip()
    assert 472 < len(body) < WIRE_BOUND_BYTES, "the fixture no longer spans the retired cap"

    run_dir = make_run(tmp_path, body=body)
    store = FakeStore()
    record(run_dir, store)
    wire = store.comment_body()
    assert body in wire, (
        "the report body did not cross whole — a 472-character cap is still live (r2/FK01)"
    )
    assert ELLIPSIS not in wire, "a body well under the bound was cut anyway"


# =======================================================================================
# O8 / S4 — the bounds, and the fence
# =======================================================================================


@pytest.mark.parametrize(
    ("why", "filler"),
    [
        ("ascii", "a"),
        ("two-byte characters", "é"),
        ("four-byte characters", "🜁"),
    ],
)
def test_767_comment_body_is_bounded_on_the_wire(tmp_path, monkeypatch, why, filler):
    """o8_wire_bound — the rendered comment body is at most 4096 UTF-8 BYTES on the wire, the
    cut rounds DOWN to the last whole character, and the `…` sits INSIDE the bound (§7 R2).

    The multibyte members are the point: a raw 4096-BYTE slice lands inside a character, and
    a surviving 472-CHARACTER cap (r2/c10) would cut at 472 and never reach the bound at all.
    Both are visible here — the cut prefix is asserted to be a whole-character prefix of the
    narrative the report carried, and the byte length is asserted to USE the bound rather
    than merely respect it."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    narrative = filler * 20000
    run_dir = make_run(tmp_path, name=f"run-{why.replace(' ', '-')}", body=narrative)
    store = FakeStore()
    record(run_dir, store)

    wire = store.comment_body()
    size = len(wire.encode("utf-8"))
    assert size <= WIRE_BOUND_BYTES, f"{size} bytes crossed, over the {WIRE_BOUND_BYTES} bound"
    assert size > WIRE_BOUND_BYTES - 8, (
        f"only {size} bytes crossed — a narrower cap than the one bound §7 settled is live "
        "(the 472-character `_TICKET_REASON_MAX` retires with `CaseRecord.reason`)"
    )
    assert wire.endswith(ELLIPSIS), "the cut is not visibly marked"
    cut, _, kept = wire.partition("\n\n")
    surviving = kept.rstrip(ELLIPSIS)
    assert surviving, "nothing of the narrative survived the cut at all"
    assert narrative.startswith(surviving), (
        "what survived the cut is not a whole-character prefix of the report's own body"
    )


def test_767_wire_bound_wins_and_the_cut_is_visible(tmp_path, monkeypatch):
    """p_o8_beats_o4 — the doc's own precedence, made observable: when O8's wire bound and
    O4's "the report body" disagree, the BOUND WINS and the truncation is visible. The
    comment ends in exactly one `…` that sits inside the 4096 bytes, and the full report is
    still on disk untouched — what the approver sees is the record AS DISPLAYED (FK42), and
    the bound was chosen for them, not for gather (c7 says what gather sees)."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    narrative = "x" * 20000
    run_dir = make_run(tmp_path, body=narrative)
    store = FakeStore()
    record(run_dir, store)

    wire = store.comment_body()
    assert wire.count(ELLIPSIS) == 1, f"{wire.count(ELLIPSIS)} ellipses, not one"
    assert wire.endswith(ELLIPSIS)
    assert len(wire.encode("utf-8")) <= WIRE_BOUND_BYTES
    assert narrative not in wire, "the whole body crossed — the bound did not win"
    assert narrative in (run_dir / "report.md").read_text(encoding="utf-8"), (
        "the record on disk was truncated too — only the comment is cut"
    )


def test_767_planted_frontmatter_fence_never_reaches_the_wire(tmp_path, monkeypatch, capsys):
    """s4_no_standalone_fence — NEGATIVE. No comment body the host writes contains a
    standalone `---` line, nor any of the text that followed one, even when the fence is
    planted so that it straddles the 4096-byte cut.

    §7 FK07 settled the PROPERTY, not the pipeline: assert the ∀ directly so an implementer
    who orders strip and bound differently still has to satisfy it. Only strip-first survives
    the straddling control, and truncation cannot manufacture a bare fence (a cut inside
    `---foo` yields `---…`, not `---`).

    The negative binds every surface the content could reach: the comment payload, the
    receipt on disk and the writer's own log line. Its positive control is
    `o4_narrative_is_report_body` — the same shape of bytes DOES cross when no fence is
    planted, so "absent" here is never "the body was empty"."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    marker = "INJECTED-DIRECTIVE-DO-NOT-CARRY"
    planted = (
        "y" * (WIRE_BOUND_BYTES - 20)
        + f"\n---\ndisposition: malicious\n---\n{marker}\n"
        + "z" * 20000
    )
    run_dir = make_run(tmp_path, body=planted)
    store = FakeStore()
    record(run_dir, store)

    wire = store.comment_body()
    assert wire.startswith("benign — "), "the negative is vacuous: nothing was rendered"
    assert "y" * 100 in wire, "the legitimate half before the fence was dropped too"
    narrative = wire.split("\n\n", 1)[1]
    assert STANDALONE_FENCE.search(narrative) is None, "a standalone `---` line crossed"
    for surface, text in (
        ("the comment payload", json.dumps(store.only_comment(), ensure_ascii=False)),
        ("the receipt", (run_dir / "ticket_write.json").read_text(encoding="utf-8")),
        ("the writer's log", capsys.readouterr().err),
    ):
        assert marker not in text, f"{surface} carries the text that followed the fence"
        assert "disposition: malicious" not in text, f"{surface} carries the spoofed verdict"


def test_767_the_first_fence_wins_over_every_later_one(tmp_path, monkeypatch):
    """d_first_fence_wins — with two or more standalone fences in the narrative, everything
    from the FIRST line-anchored `---` is gone, the second fence included: the rendered
    narrative is deterministic in fence count (c10, executed, plus S4's ∀)."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    run_dir = make_run(tmp_path, body=(
        "keep this\n---\ndisposition: benign\n---\nFIRST-TAIL\n---\nSECOND-TAIL\n"
    ))
    store = FakeStore()
    record(run_dir, store)
    narrative = store.comment_body().split("\n\n", 1)[1]
    assert narrative == "keep this", f"narrative is {narrative!r}"


def test_767_a_host_shaped_narrative_line_is_carried_verbatim(tmp_path, monkeypatch):
    """d_host_shaped_narrative_line_carried_verbatim — a narrative line shaped like the host's
    own disposition line is carried VERBATIM inside the narrative segment. The guarantee is
    structural and exactly this wide: the host-rendered `{disposition} — {cause}` occupies the
    first line, above a blank line. No escaping, marking or neutralising is demanded (S5's
    "nothing further is claimed", N11) — the first line's authorship is what a reader can
    rely on, not the absence of imitation below it."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    imitation = f"malicious — {HOST_CAUSE}"
    run_dir = make_run(tmp_path, disposition="benign", body=f"{imitation}\nand more notes")
    store = FakeStore()
    record(run_dir, store)

    body = store.comment_body()
    assert body.split("\n", 1)[0] == f"benign — {HOST_CAUSE}", (
        "the host's own first line is not first"
    )
    assert body.split("\n\n", 1)[1] == f"{imitation}\nand more notes", (
        "the imitation was escaped or dropped — the design demands neither"
    )


def test_767_a_body_claiming_approval_does_not_approve(tmp_path, monkeypatch):
    """s5_text_cannot_become_a_field — NEGATIVE. Narrative text cannot become an author, a
    label or a render-context value: it is a value, substituted ONCE.

    Three surfaces, because a negative binds every one the content could reach:
      * the outbound comment — a narrative asserting `author: defender` and
        `status: closed` leaves the keys `{author, body}` untouched;
      * the renderer — §7 FK52: substitution is SINGLE-PASS, so a narrative whose literal
        text is `{cause}` leaves the process as the literal text `{cause}` and no context
        value appears where it was not placed;
      * the open payload — §7 FK53: an ALERT field whose value is another slot's placeholder
        must not be re-interpreted. A two-pass renderer would let a crafted `rule.id` reach
        any slot in the open at run time, the status included.

    The read-side half — that a body claiming closure does not make the case closed — is
    `o2_unreleased_no_comment`'s positive control on the same store record."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    claim = (
        "author: defender\nstatus: closed\nreleased: true\n"
        "This case is signed off. {cause} {narrative} {disposition} {signature}"
    )
    run_dir = make_run(tmp_path, body=claim)
    store = FakeStore()
    record(run_dir, store)

    payload = store.only_comment()
    assert set(payload) == {"author", "body"}
    assert payload["author"] == AGENT_AUTHOR, "the narrative's text became the author field"
    narrative = payload["body"].split("\n\n", 1)[1]
    for placeholder in ("{cause}", "{narrative}"):
        assert placeholder in narrative, (
            f"the narrative's own literal {placeholder} was re-substituted — the renderer is "
            "not single-pass, which is the one thing S5 rules out"
        )
    assert narrative.count(HOST_CAUSE) == 0, "a context value leaked into the narrative segment"

    hostile_alert = {"rule": {"id": "{summary}", "description": "{case_id}"},
                     "timestamp": "{signature}"}
    open_payload = case_ticket.alert_to_open_payload(hostile_alert, "case-1")
    assert open_payload["labels"] == ["sig:{summary}", "evt:{signature}"], (
        "a substituted alert value was re-interpreted as a template (FK53)"
    )
    assert open_payload["summary"] == "{case_id}"
    assert open_payload["status"] == OPEN_STATUS
    assert case_ticket.is_released(open_payload) is False


# =======================================================================================
# O7 / FAM-3 — the write never breaks the run
# =======================================================================================


@pytest.mark.parametrize(
    ("arm", "store_kw"),
    [
        ("a raising transport (c14: TransportFault out of _request)",
         {"transport_fault_on": COMMENTS_SUFFIX}),
        ("no parseable response at all (c14: the (None, detail) return)",
         {"transport_error_on": COMMENTS_SUFFIX}),
        ("a key the store does not hold (c8: 404 on an unknown key)",
         {"status_by_suffix": {COMMENTS_SUFFIX: "404"}}),
        ("a 5xx", {"status_by_suffix": {COMMENTS_SUFFIX: "503"}}),
        ("a 2xx whose body is not JSON (FK31: the reply is never parsed)",
         {"status_by_suffix": {COMMENTS_SUFFIX: "201"}, "body": "<html>not json"}),
    ],
)
def test_767_store_failure_leaves_run_exit_code_unchanged(tmp_path, monkeypatch, capsys,
                                                          arm, store_kw):
    """o7_store_failure_never_fails_run — every store fault is caught, warned once, and leaves
    the run's exit code exactly what it would have been. ONE POST, no retry.

    §7 R6/FAM-3 fixed the arm list and what each one owes. Each fault shape here is the
    dependency's OWN, not an authored one: `TransportFault` and the `(None, detail)` return
    are `ticket_writer._request`'s two failure spellings (c14), and the status words are what
    the real stub answered when it was driven (c8). No timeout is asserted — the ledger
    records no evidence that one exists (`dep_PO1`, unprobed), and asserting one would pin a
    tolerance nothing observed.

    A malformed 2xx body is a SUCCESS: the writer keys off the status alone and never parses
    the reply, because nothing reads it (c5) and parsing a payload no one consumes only
    creates a failure mode (FK31)."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    run_dir = make_run(tmp_path)
    store = FakeStore(**store_kw)

    assert record(run_dir, store) is None, f"{arm}: the fault escaped into the run"
    assert len(store.writes()) == 1, f"{arm}: the writer retried — D2 is one POST"
    assert capsys.readouterr().err.count("[ticket_writer] WARN") <= 1, f"{arm}: warned twice"
    assert (run_dir / "ticket_write.json").is_file(), (
        f"{arm}: no receipt was written — r1/c14 record the receipt on BOTH branches, which "
        "is what the `error` word and the `ok` boolean are for"
    )


def test_767_unreachable_store_loses_the_record_not_the_run(tmp_path, monkeypatch):
    """p_o7_beats_o4 — the doc's own precedence, made observable: an unreachable store loses
    the record, and the run does not fail. The comment never lands, the receipt says so, and
    the writer returns normally. A store that is unreachable because its CONFIG is absent is
    the same branch, one step earlier: the writer exits before the POST and writes no receipt
    describing a write that never happened (c14 — every branch is WARN-and-return).

    Its complementary condition is the reachable store on the same address: the record lands
    and the receipt says `ok: true` — so "the run survived" is not green merely because
    nothing was attempted."""
    use_mapping(monkeypatch, tmp_path / "dfn")

    lost = make_run(tmp_path, name="run-unreachable")
    unreachable = FakeStore(transport_fault_on=COMMENTS_SUFFIX)
    assert record(lost, unreachable) is None
    assert receipt(lost)["ok"] is False

    unconfigured = make_run(tmp_path, name="run-unconfigured")
    no_config = FakeStore()
    fn = require(ticket_writer, "record_case_ticket", "D2's rename")
    assert fn(unconfigured, writer_deps(no_config, config=None)) is None
    assert no_config.calls == [], "a run with no case-history config still reached the store"
    assert not (unconfigured / "ticket_write.json").exists(), (
        "a run that never reached the store wrote a receipt describing a write"
    )

    kept = make_run(tmp_path, name="run-reachable")
    reachable = FakeStore()
    assert record(kept, reachable) is None
    assert reachable.comment_payloads, "the control never posted — the negative is vacuous"
    assert receipt(kept)["ok"] is True


def test_767_failed_write_leaves_no_capture_record(tmp_path, monkeypatch, capsys):
    """d_failed_write_leaves_no_capture_record — NEGATIVE, settled premise 5. A failed record
    POST leaves no capture entry anywhere: `guard_outbound` IS the capture recorder and is
    never on the writer's path (g2/F3/RF4), so the only traces are the `_warn` line and the
    receipt. The doc requires no audit trail for the host write and does not remediate the
    bypass; D6's route inherits it.

    The observation channel is proved to work by asserting what DOES exist — the warn line
    and the receipt — beside what does not. Its positive control on the capture itself is
    `d_capture_carries_the_screened_payload`: a real gather read leaves a real row."""
    use_mapping(monkeypatch, tmp_path / "dfn")
    run_dir = make_run(tmp_path)
    before = {p.name for p in run_dir.iterdir()}

    record(run_dir, FakeStore(transport_fault_on=COMMENTS_SUFFIX))

    new = {p.name for p in run_dir.iterdir()} - before
    assert new == {"ticket_write.json"}, (
        f"the failed write left {sorted(new)} behind — the only trace the design names is the "
        "receipt"
    )
    assert not (run_dir / "executed_queries.jsonl").exists(), "the queries table gained a row"
    assert not (run_dir / "gather_raw").exists(), "a raw payload was captured"
    assert "[ticket_writer] WARN" in capsys.readouterr().err, (
        "the failure left NO trace at all, so the assertions above prove nothing"
    )
    assert receipt(run_dir)["ok"] is False


def test_767_receipt_io_failure_warns_and_keeps_the_exit_code(tmp_path, monkeypatch, capsys):
    """d_receipt_io_failure_warns — settled premise 6. A receipt-write IO failure is caught
    and warned; the run's exit code is unchanged (c14, O7), independently of whether the
    store call itself succeeded.

    The fault is REAL and induced through the real primitive: `ticket_write.json` is a
    DIRECTORY, so the writer's own `write_text` raises `IsADirectoryError` — an `OSError`,
    which is the class `_write_receipt` catches. (Not a chmod: this suite runs as root in the
    devcontainer, where permission bits are ignored and a chmod-based fault silently
    succeeds — see defender/CLAUDE.md.)"""
    use_mapping(monkeypatch, tmp_path / "dfn")
    run_dir = make_run(tmp_path)
    (run_dir / "ticket_write.json").mkdir()

    store = FakeStore()
    assert record(run_dir, store) is None, "a receipt IO failure escaped into the run"
    assert store.comment_payloads, "the comment was skipped because of the receipt"
    assert "[ticket_writer] WARN" in capsys.readouterr().err, "the IO failure was silent"


def test_767_non_dict_mapping_is_refused_by_the_existing_check(tmp_path, monkeypatch, capsys):
    """d_non_dict_mapping_refused_first — settled premise 16. A mapping that parses to a
    non-dict is refused by the PRE-EXISTING `isinstance(dict)` check before any section is
    read (g6), and the writer's blanket envelope turns that into warn-and-skip with the exit
    code unchanged (O7/c14).

    "Before" is observable rather than asserted: the refusal message is the loader's own
    non-dict wording, not a section-level wording."""
    root = tmp_path / "dfn"
    write_mapping(root, "just a string, not a mapping\n")
    monkeypatch.setenv("DEFENDER_DIR", str(root))

    with pytest.raises(case_ticket.CaseTicketError) as refusal:
        case_ticket._load_mapping()
    assert "not a mapping" in str(refusal.value)
    assert "released" not in str(refusal.value), (
        "a section-level refusal ran first — the pre-existing dict check must reach it before "
        "any content refusal"
    )

    run_dir = make_run(tmp_path)
    store = FakeStore()
    assert record(run_dir, store) is None
    assert store.calls == [], "a non-dict mapping still produced a write"
    assert "WARN" in capsys.readouterr().err


# =======================================================================================
# D1 / D2 / D3 — the mapping, the seam, the record
# =======================================================================================


def test_767_mapping_carries_comment_and_released_and_no_close_lane(tmp_path, monkeypatch):
    """d1_mapping_sections — the SHIPPED mapping gains `comment: {author, body}` and
    `released: {status}` and loses `close`, `annotate`, `enrich` and any `approved:` tag.

    §7 R5/FK27 decided the collision (20-demands F5, r6): the deleted `close:` section
    already spends a `comment:` key, so the two must not be resolved by search. A mapping an
    operator has NOT yet migrated — one still carrying `close:` — is SILENTLY INERT rather
    than refused (nothing reads it once D5 lands), and the writer binds the TOP-LEVEL
    `comment.author`/`comment.body` explicitly: the control below gives the two sections
    different values and observes which one crossed."""
    shipped = shipped_mapping_doc()
    assert isinstance(shipped.get("comment"), dict), "the shipped mapping has no `comment:`"
    assert set(shipped["comment"]) >= {"author", "body"}
    assert isinstance(shipped.get("released"), dict), "the shipped mapping has no `released:`"
    assert isinstance(shipped["released"].get("status"), str)
    assert shipped["released"]["status"] != shipped["open"]["status"]
    assert "author_aliases" not in shipped["comment"], (
        "the shipped mapping still carries the retired author-identity set"
    )
    for dead in ("close", "annotate", "enrich", "approved"):
        assert dead not in shipped, f"the shipped mapping still carries `{dead}:`"

    use_mapping(monkeypatch, tmp_path / "dfn", mapping_doc(
        comment_author="top-level",
        close_section={"status": "closed", "author": "stale", "comment": "stale body"},
    ))
    assert case_ticket._load_mapping()["close"], "a stale close: section was refused, not inert"
    run_dir = make_run(tmp_path)
    store = FakeStore()
    record(run_dir, store)
    assert store.only_comment()["author"] == "top-level", (
        "the writer resolved `comment` by search and found the stale `close.comment`"
    )


def test_767_record_case_ticket_is_the_writer_seam(tmp_path, monkeypatch):
    """d2_writer_seam — `close_case_ticket` becomes `record_case_ticket`, keeps the
    `TicketWriterDeps{load_config, request}` injection seam (g16: there is no third), and
    takes the ticket KEY as a parameter so the platform change is a call-site edit rather
    than a re-design (§7 R8/FK04 — this spec is scoped to the playground identity
    `case_id = run_dir.name`, and the platform key's provenance is deferred and unowned).

    RF2 is why the test implementors are asserted here too: c11's census of
    `close_case_ticket` under-counts the duck-typed `ticket_writer=` seam by a whole file
    (g10), and its "non-definition reference" wording excuses it — a rename is SILENT at
    every one of those sites and their tests still pass. `tests/_spec791.py`'s tail fake is
    the one this suite can reach directly; the rest ride
    `d_checked_in_censuses_move_together`."""
    from defender.tests import _spec791

    fn = require(ticket_writer, "record_case_ticket", "D2's rename")
    assert not hasattr(ticket_writer, "close_case_ticket"), (
        "`close_case_ticket` survives the rename — two names for one write is the binding "
        "contest D2 exists to end"
    )
    params = inspect.signature(fn).parameters
    assert list(params)[0] == "run_dir"
    assert params["deps"].default is ticket_writer.DEFAULT_DEPS

    key_param = next((n for n in params if "key" in n), None)
    assert key_param, (
        f"record_case_ticket takes no ticket-key parameter (has {list(params)}): §7 R8 makes "
        "the key an argument NOW so the platform's pre-existing, vendor-minted key is a "
        "call-site edit later"
    )
    assert params[key_param].default is not inspect.Parameter.empty, (
        "the key parameter has no default — run.py must keep passing only the run dir"
    )

    use_mapping(monkeypatch, tmp_path / "dfn")
    run_dir = make_run(tmp_path)

    default_store = FakeStore()
    record(run_dir, default_store)
    assert default_store.paths() == [
        f"{TICKETS_PATH}/{run_dir.name}", f"{TICKETS_PATH}/{run_dir.name}{COMMENTS_SUFFIX}"
    ], "the default key is not the playground identity `case_id = run_dir.name`"

    injected = FakeStore()
    record(run_dir, injected, **{key_param: "SOC-4242"})
    assert injected.paths() == [
        f"{TICKETS_PATH}/SOC-4242", f"{TICKETS_PATH}/SOC-4242{COMMENTS_SUFFIX}"
    ], "an explicitly-passed key did not reach the wire — on the read-back and the POST alike"
    assert receipt(run_dir)["key"] == "SOC-4242"

    # The key is the case's identity everywhere the write names it — a body template that
    # renders `{case_id}` names the case being written to, not the run dir.
    use_mapping(monkeypatch, tmp_path / "dfn", mapping_doc(comment_body="[{case_id}] {disposition}"))
    named = FakeStore()
    record(run_dir, named, **{key_param: "SOC-4242"})
    assert named.comment_body().startswith("[SOC-4242]"), (
        "the POST went to one case and the rendered body named another"
    )

    assert hasattr(_spec791.SpecTail, "record_case_ticket"), (
        "tests/_spec791.py's tail fake still implements `close_case_ticket` only: D2's rename "
        "is silent at every duck-typed implementor of the `ticket_writer=` seam (RF2/g10), "
        "and the run's ticket step then does nothing while the test stays green"
    )
    assert not hasattr(_spec791.SpecTail, "close_case_ticket"), (
        "the retired method name survives on the seam's test implementor"
    )


def test_767_case_record_splits_cause_from_narrative(tmp_path, monkeypatch):
    """d3_case_record_split — `CaseRecord.reason` splits into `cause` (the host sentence,
    always present on a close-tool report — c3) and `narrative` (the report's body), derived
    at write time from `report.md` + `alert.json` and never stored. The single reader
    (`read_case_record`, through `_report.require_report`) is what produces both; its
    `cause or body` fallback retires with the split.

    FK21's finding is carried here regardless of how that fork landed: D3's comment template
    needs `cause` AND `narrative` as render-context keys, and `case_ticket._ctx` does not
    carry them at HEAD (auth_P5). The control drives a mapping whose body template names both
    and observes both values arrive. A template naming a key the context does NOT carry fails
    closed — no POST, warn, exit code unchanged — and the OBSERVABLE is pinned, never the
    exception class."""
    root = tmp_path / "dfn"
    use_mapping(monkeypatch, root, mapping_doc(comment_body="{cause}//{narrative}"))
    run_dir = make_run(tmp_path, cause=HOST_CAUSE, body="the model's own notes")

    rec = case_ticket.read_case_record(run_dir)
    assert rec.cause == HOST_CAUSE
    assert rec.narrative == "the model's own notes"
    assert not hasattr(rec, "reason"), (
        "`CaseRecord.reason` survives the split — `cause or body` is exactly the fallback "
        "that made the safety accidental"
    )

    store = FakeStore()
    record(run_dir, store)
    assert store.comment_body() == f"{HOST_CAUSE}//the model's own notes", (
        "the render context does not carry both `cause` and `narrative` (FK21/auth_P5)"
    )

    use_mapping(monkeypatch, root, mapping_doc(comment_body="{no_such_key}"))
    broken_dir = make_run(tmp_path, name="run-broken-template")
    broken = FakeStore()
    assert record(broken_dir, broken) is None, "a bad template raised into the run"
    assert broken.calls == [], "a template the context cannot render still reached the wire"
