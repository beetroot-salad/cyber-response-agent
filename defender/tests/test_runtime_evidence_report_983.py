"""#983 mechanism A — the baseline consultation's carrier into `report.md`, and where it stops.

O3 wants a human reading a closed case to see whether the alerted pattern is recognized as
recurring in this estate, on exactly the cases O1 creates — which are BENIGN closes. The design
doc says this rides "the same mechanism that already projects `ceiling_test` notes there, not a
new architecture", and probing that (claim c11 / red flag RF1) found the cited carrier does not
reach a benign close at all: `conclude_ceiling_test_rows` is called inside the
`NO_REVIEW_DISPOSITIONS` branch under `if disposition == "inconclusive"`, and the post-review
`_CloseFields(...)` takes the `ceiling_test=()` default. So the carrier is EXTENDED, not reused:
a second companion-derived field populated at BOTH construction sites.

WHAT THIS SUITE PINS, beyond the demands:

  * `_gating.conclude_runtime_evidence_rows(companion_text) -> tuple[RuntimeEvidenceReceipt, ...]`
    beside `conclude_ceiling_test_rows`, for the same reason that one is public: `report.md` is
    written from the close's disposition ARGUMENT and never re-reads the companion, so the
    close carries these in itself.
  * `render_report(..., runtime_evidence=receipts)` renders one line per receipt into the BODY
    and never the frontmatter. Never the frontmatter for the same reason a `ceiling_test`
    `note` is not there: the block is under a 512-byte cap (`_artifact_schema`), a size cap on
    ungated text is itself a gate, and a value the write gate accepted that the render then
    refused strands the run.
  * `render_report`'s docstring stops claiming `ceiling_test` is "the ONE exception" to
    "no model-supplied body". That claim becomes FALSE with a second field, and the docstring
    is the load-bearing statement of an invariant on a function whose output rides verbatim
    into the judge's prompt and out through the ticket bridge (claim c12 / RF2) — a stale
    invariant there is worse than none, because the next author reads it as still true.

  * `RuntimeEvidenceReceipt` is a FROZEN DATACLASS beside `CeilingReceipt`, and the tests
    assert on its FIELDS. That is this suite's hardening pass, and it is not a style
    preference: written against a bare pre-rendered string, every assertion in this file was a
    substring check, and a `conclude_runtime_evidence_rows` that returned
    `("runtime-evidence 1500 occurrences ...",)` — the fixture's own text, hardcoded — passed
    all of them. Nothing asked whether a `:R consultations` row had been READ. Fields make
    that question askable: `window_start`/`window_end` are `datetime`s, so the row's window
    has to be genuinely parsed, and two rows carrying different windows cannot both come out
    of one canned string.

    The STRUCTURED half is the window (parsed), the anchor kind, grounding, id and the owning
    lead — the cells the format itself gives columns to. `result` and `reasoning` are carried
    VERBATIM as free text, deliberately: the occurrence count and the actor/host scope live
    inside `result`'s prose because the design adds no columns to `:R consultations`, and
    regex-mining a model-authored sentence for a number is the free-text judgment #923 spent a
    round removing from `ceiling_test`. What holds them honest instead is that the render is
    asserted to carry EACH row's own text, from a fixture whose two rows differ.

Receipts are OBTAINED from `conclude_runtime_evidence_rows` rather than constructed, so the
projection and the render are pinned to agree — the property `ceiling_test_block`'s "ONE
renderer for both" comment exists to hold.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json

from defender._frontmatter import split_frontmatter
from defender.runtime import close_tool
from defender.tests import _tacit983 as scene

#: The second baseline in the two-row fixture: a different anchor id, a different window and a
#: different count. Everything the render is asserted to carry differs between the two rows, so
#: a renderer emitting one row's values twice — or a projection handing back one canned
#: receipt per row — is visible.
WINDOW_90D = "2026-02-04T00:00:00Z/2026-05-04T00:00:00Z"
ANCHOR_90D = "tk-baseline-90d"
RESULT_90D = "4100 occurrences over 90d; actor uid-0 and host build-runner-07.prod throughout"


def _utc(text: str) -> dt.datetime:
    """The moment an ISO-8601 `Z` timestamp names, as an aware UTC `datetime`.

    Spelled here rather than imported from the code under test: an oracle that called the
    parser it is checking could not disagree with it (`lint-oracle`), and the whole point of
    asserting on `window_start` is that the receipt did a real parse."""
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def _receipts(text: str):
    """The baseline receipts a companion carries.

    Imported inside the call rather than at module scope so the two tests that ask nothing of
    this function — the docstring invariant and the `_CloseFields` shape — report their own
    failure instead of being masked by one module-level ImportError.

    The reader takes a PARSED companion (the close holds one by the time it reaches this, and a
    second parse out here was also an unguarded one on the close paths that reach it without
    pricing anything). These suites hold text, so the parse is here."""
    from defender.skills.invlang.parser import parse_dense_companion
    from defender.skills.invlang.validate._gating import conclude_runtime_evidence_rows

    return conclude_runtime_evidence_rows(parse_dense_companion(text)[0])

#: A document carrying one qualifying baseline consultation and the receipted authz pair —
#: the shape a benign close over a container-root case actually has. It carries TWO
#: `:R consultations` rows (the lead's recorded registry hit and the baseline) and exactly ONE
#: of them qualifies, which is what makes "the projection selects" a claim with a witness.
BENIGN_DOC = scene.benign_document(rows=scene.authorized_rows(baseline=True))


def _body(report: str) -> str:
    """The report's BODY — everything past the frontmatter, read through the shared splitter
    rather than by counting `---` fences (`lint-frontmatter`)."""
    _fm, _raw, body = split_frontmatter(report)
    return body


def test_runtime_evidence_receipt_carries_the_rows_parsed_fields():
    """A receipt is a TYPED record of one `:R consultations` row — the owning lead, the anchor
    id, the free-text result and reasoning, and the effective window BOTH verbatim and PARSED
    into two `datetime`s.

    Mirrors `CeilingReceipt` (`validate/_gating`) down to the split it makes: a structured half
    that is mechanically checkable and a free-text half that is for the human analyst. The
    parsed window is what makes the guard and the report read ONE value — mechanism A's first
    guard has to compare the window's end against the alert's timestamp, and a second parse
    living in the renderer is the two-derivations-of-one-quantity shape (`lint-owns`).

    A FROZEN dataclass, like `CeilingReceipt`: these travel from the projection into the close
    tool's disposition argument and out into `report.md`, and a mutable record handed across
    three boundaries is one any of them can edit on the way."""
    (receipt,) = _receipts(BENIGN_DOC)

    assert dataclasses.is_dataclass(receipt)
    assert type(receipt).__dataclass_params__.frozen, (
        "the receipt is mutable — it crosses the projection, the close and the render"
    )

    assert receipt.resolved_by_lead == scene.LEAD, (
        "the receipt does not say which lead measured the baseline, so the report's reader "
        "cannot get from the claim back to the retrieval"
    )
    assert receipt.anchor_kind == "runtime-evidence"
    assert receipt.grounding_kind == "telemetry-baseline"
    assert receipt.anchor_id == "tk-baseline-30d"
    assert "1500 occurrences over 30d" in receipt.result, (
        "the occurrence count did not survive into the receipt"
    )
    assert "build-runner-07.prod" in receipt.result, "the scope did not survive into the receipt"
    assert "no adverse outcome" in receipt.reasoning

    assert receipt.window == scene.WINDOW_BEFORE_ALERT, (
        "the window cell is not carried verbatim — the report shows the analyst what the row "
        "said, not a re-rendering of it"
    )
    assert receipt.window_start == _utc("2026-04-04T00:00:00Z")
    assert receipt.window_end == _utc("2026-05-04T00:00:00Z"), (
        "the window's END is not parsed — it is the endpoint mechanism A's guard compares "
        "against the alerted event, and a receipt that never parsed it cannot have been "
        "produced by a check that did"
    )


def test_runtime_evidence_rows_project_off_the_consultation_bucket():
    """`conclude_runtime_evidence_rows` selects the `:R consultations` rows whose `anchor_kind`
    is `runtime-evidence`, in document order, and nothing else.

    Selection, not a filter over everything the document says: a consultation under some other
    anchor kind is a different question being answered, and a `:R authz` row is a verdict. Both
    are excluded, so the projection cannot widen into "every model-authored row" by accident.

    `BENIGN_DOC` is the sharp case and the reason the fixture carries two consultations: the
    lead's `tacit-knowledge` lookup record sits in the SAME bucket, one row above the baseline,
    and it is not a baseline. A projection selecting the bucket rather than the anchor kind
    would carry a registry citation into `report.md`'s recurrence paragraph."""
    receipts = _receipts(BENIGN_DOC)
    assert [r.anchor_id for r in receipts] == ["tk-baseline-30d"], (
        "the lead's own `tacit-knowledge` lookup record was projected as a baseline — the "
        "selection is on the bucket, not on the anchor kind"
    )

    other_kind = scene.document(
        contract_anchor_kind="iam-policy", system="identity",
        rows=scene.consult_block(scene.consultation_row(
            anchor_kind="change-mgmt", grounding="org-authority")),
    )
    assert _receipts(other_kind) == (), (
        "a consultation under another anchor kind was projected as a baseline"
    )

    no_baseline = scene.document(rows=scene.authorized_rows())
    assert [r.anchor_id for r in _receipts(no_baseline)] == [], (
        "a `:R authz` row reached the baseline channel — the projection is not selecting on "
        "the consultation bucket"
    )


def test_runtime_evidence_consultation_lands_in_report_body():
    """A close projects every qualifying `:R consultations` row into `report.md`'s BODY — one
    line per row, in the body and never the frontmatter (demand `consultation_reaches_report_body`,
    fork F4).

    The unit half, over `render_report` itself; the whole-close half (benign AND inconclusive,
    both `_CloseFields` construction sites) is `e2e/test_tacit_authz_e2e_983.py`."""
    receipts = _receipts(BENIGN_DOC)
    assert len(receipts) == 1, "fixture control: the document carries one qualifying consultation"
    (receipt,) = receipts

    report = close_tool.render_report(
        "benign", outcome=close_tool.STANDS, cause=close_tool.CAUSE_STORY_SETTLED,
        runtime_evidence=receipts,
    )
    _fm, frontmatter, body = split_frontmatter(report)

    assert body.count("runtime-evidence") == len(receipts), (
        "not one body line per receipt — a close with two baselines would render one of them"
    )
    #: Asserted against the RECEIPT's own fields, not against the fixture's literals: the
    #: property is that what the projection parsed is what the report shows. A body compared
    #: to hand-copied constants passes for a renderer that ignores its argument and prints
    #: them.
    for field in (receipt.window, receipt.anchor_id, receipt.resolved_by_lead):
        assert field in body, f"{field!r} was parsed into the receipt and never rendered"
    assert "1500 occurrences over 30d" in body, (
        "the occurrence count did not reach the body — `result` is the only place the design "
        "leaves for it, since `:R consultations` gains no columns"
    )

    assert "runtime-evidence" not in (frontmatter or ""), (
        "the baseline reached the FRONTMATTER — that block is under a 512-byte cap and a size "
        "cap on ungated model text is itself a gate; the note lane is the body"
    )

    without = close_tool.render_report(
        "benign", outcome=close_tool.STANDS, cause=close_tool.CAUSE_STORY_SETTLED,
    )
    assert "runtime-evidence" not in without, (
        "a close with no baseline rendered one — the default has to be the empty tuple"
    )


def test_render_report_no_longer_claims_ceiling_test_is_the_one_exception():
    """`render_report`'s docstring stops claiming `ceiling_test` is "the ONE exception" to
    "no model-supplied body", and says honestly that there are now two.

    A DOC test because the claim is an INVARIANT, not a comment: `render_report` is one of the
    most heavily invariant-documented functions in the tree (RS12, the 512-byte cap, the
    judge-prompt and ticket-bridge egress), and the next author reads a stale invariant as
    still true. Both halves are asserted — the false claim is gone, AND the rationale that
    survives it (model-CHOSEN structure, never model-AUTHORED prose) is still stated — so the
    repair cannot be to delete the paragraph that explains why either exception is safe."""
    doc = close_tool.render_report.__doc__ or ""
    assert "the ONE exception" not in doc, (
        "the docstring still claims a single exception to the host-rendered body while a "
        "second companion-derived field is being rendered beside it"
    )
    assert "runtime_evidence" in doc, (
        "the second exception is rendered and undocumented — the invariant paragraph names "
        "`ceiling_test` alone"
    )
    assert "model-supplied body" in doc, "RS12 itself must survive the edit"
    assert "model-CHOSEN structure" in doc or "model-chosen structure" in doc.lower(), (
        "the rationale that makes either exception safe is what the paragraph is FOR"
    )


def test_baseline_context_does_not_reach_the_case_ticket(tmp_path):
    """The baseline consultation reaches `report.md` and stops there: the case ticket's closing
    comment carries no consultation content (demand `baseline_not_wired_to_ticket`,
    non-obligation 3).

    Wiring baseline context out to `ticket_writer.py` is an acknowledged gap this change
    DEFERS, and the deferral is minted as a test so a later change that quietly widens the
    egress trips something. It holds today because `read_case_record` takes its outbound reason
    from the frontmatter's `cause` — the host's own typed sentence — and falls back to the body
    only for a report that carries no cause at all; every close-gate report carries one."""
    from defender.scripts.case_history import case_ticket

    receipts = _receipts(BENIGN_DOC)
    report = close_tool.render_report(
        "benign", outcome=close_tool.STANDS, cause=close_tool.CAUSE_STORY_SETTLED,
        runtime_evidence=receipts,
    )
    assert "1500 occurrences" in _body(report), "fixture control: the body carries the baseline"

    run_dir = tmp_path / "case-983"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_text(
        json.dumps({"rule": {"id": "5710", "key": "spec.rule"},
                    "timestamp": "2026-05-05T03:42:11Z"}),
        encoding="utf-8",
    )
    (run_dir / "report.md").write_text(report, encoding="utf-8")
    (run_dir / "investigation.md").write_text(BENIGN_DOC, encoding="utf-8")

    payload = case_ticket.case_record_to_close(case_ticket.read_case_record(run_dir))
    wire = json.dumps(payload, sort_keys=True)
    for leaked in ("runtime-evidence", "1500 occurrences", scene.WINDOW_BEFORE_ALERT):
        assert leaked not in wire, (
            f"{leaked!r} reached the outbound ticket payload — the baseline's egress is "
            f"`report.md` and the deferral is deliberate"
        )


def test_the_projection_and_the_render_read_one_set():
    """Whatever `conclude_runtime_evidence_rows` hands back is what `render_report` writes —
    the "ONE renderer for both" discipline `ceiling_test_block` already states.

    Two rows that DIFFER in every rendered cell — id, window, count — so three failures are
    visible that one row or two identical rows would hide: a render that collapses or
    deduplicates them, a render that emits the first row's values twice, and a projection
    handing back a canned receipt per row rather than each row's own parse. A reader that
    re-derived "qualifying" independently could disagree with the projection that already ran
    and carry a row into `report.md` nothing ever selected."""
    doc = scene.document(
        rows=scene.consult_block(
            scene.consultation_row(),
            scene.consultation_row(
                anchor_id=ANCHOR_90D, result=RESULT_90D, window=WINDOW_90D),
        ),
        settled=False,
    )
    receipts = _receipts(doc)
    assert len(receipts) == 2, "fixture control: two qualifying consultations"

    first, second = receipts
    assert (first.anchor_id, first.window) == ("tk-baseline-30d", scene.WINDOW_BEFORE_ALERT)
    assert (second.anchor_id, second.window) == (ANCHOR_90D, WINDOW_90D), (
        "the second row's own cells did not reach its receipt — the projection is not parsing "
        "per row"
    )
    assert second.window_start == _utc("2026-02-04T00:00:00Z")
    assert first.window_start != second.window_start, (
        "both receipts carry one window — a canned value, not two parses"
    )

    body = _body(close_tool.render_report(
        "inconclusive", outcome=close_tool.STANDS, cause=close_tool.CAUSE_NOT_REVIEWED,
        runtime_evidence=receipts,
    ))
    assert body.count("runtime-evidence") == 2
    for receipt in receipts:
        assert receipt.anchor_id in body, (
            f"{receipt.anchor_id} was dropped on the way into the body"
        )
        assert receipt.window in body, (
            f"{receipt.anchor_id}'s window was dropped, or replaced by its sibling's"
        )
    assert "4100 occurrences over 90d" in body, "the second baseline's count never rendered"


def test_close_fields_carries_the_baseline_on_every_disposition():
    """`_CloseFields` carries the baseline as a companion-derived field alongside `ceiling_test`,
    and it defaults empty.

    The structural half of fork F4: `ceiling_test` is populated at ONE of the two construction
    sites and only for `inconclusive`, which is why the cited carrier never reaches a benign
    close. This asserts the field exists and is defaulted; the e2e asserts both sites actually
    populate it."""
    fields = {f.name: f for f in dataclasses.fields(close_tool._CloseFields)}
    assert "runtime_evidence" in fields, (
        "`_CloseFields` has no baseline field — the projection has no way onto either close path"
    )
    assert fields["runtime_evidence"].default == (), (
        "the baseline field is not defaulted empty — every existing construction site would "
        "have to name it, and a close with no baseline has none to name"
    )
