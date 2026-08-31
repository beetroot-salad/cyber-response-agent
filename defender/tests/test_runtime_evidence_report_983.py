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

Receipts are obtained from `conclude_runtime_evidence_rows` rather than constructed, so the
tests do not pin the dataclass's field names — only that the projection and the render agree,
which is the property `ceiling_test_block`'s "ONE renderer for both" comment exists to hold.
"""

from __future__ import annotations

import json

from defender._frontmatter import split_frontmatter
from defender.runtime import close_tool
from defender.tests import _tacit983 as scene


def _receipts(text: str):
    """The baseline receipts a companion carries.

    Imported inside the call rather than at module scope so the two tests that ask nothing of
    this function — the docstring invariant and the `_CloseFields` shape — report their own
    failure instead of being masked by one module-level ImportError."""
    from defender.skills.invlang.validate._gating import conclude_runtime_evidence_rows

    return conclude_runtime_evidence_rows(text)

#: A document carrying one qualifying baseline consultation and the discharging authz row —
#: the shape a benign close over a container-root case actually has.
BENIGN_DOC = scene.benign_document(
    rows=scene.authz_block(scene.authz_row()) + "\n" + scene.consult_block(
        scene.consultation_row()),
)


def _body(report: str) -> str:
    """The report's BODY — everything past the frontmatter, read through the shared splitter
    rather than by counting `---` fences (`lint-frontmatter`)."""
    _fm, _raw, body = split_frontmatter(report)
    return body


def test_runtime_evidence_rows_project_off_the_consultation_bucket():
    """`conclude_runtime_evidence_rows` selects the `:R consultations` rows whose `anchor_kind`
    is `runtime-evidence`, in document order, and nothing else.

    Selection, not a filter over everything the document says: a consultation under some other
    anchor kind is a different question being answered, and a `:R authz` row is a verdict. Both
    are excluded, so the projection cannot widen into "every model-authored row" by accident."""
    (receipt,) = _receipts(BENIGN_DOC)
    rendered = str(receipt)
    assert scene.WINDOW_BEFORE_ALERT in rendered or "window" in rendered.lower(), (
        "the receipt carries no window — the field that makes a baseline judgeable"
    )

    other_kind = scene.document(
        contract_anchor_kind="iam-policy", system="identity",
        rows=scene.consult_block(scene.consultation_row(
            anchor_kind="change-mgmt", grounding="org-authority")),
    )
    assert _receipts(other_kind) == (), (
        "a consultation under another anchor kind was projected as a baseline"
    )

    authz_only = scene.document(rows=scene.authz_block(scene.authz_row()))
    assert _receipts(authz_only) == (), (
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
    assert receipts, "fixture control: the document carries one qualifying consultation"

    report = close_tool.render_report(
        "benign", outcome=close_tool.STANDS, cause=close_tool.CAUSE_STORY_SETTLED,
        runtime_evidence=receipts,
    )
    _fm, frontmatter, body = split_frontmatter(report)

    assert body.count("runtime-evidence") == len(receipts), (
        "not one body line per receipt — a close with two baselines would render one of them"
    )
    assert scene.WINDOW_BEFORE_ALERT in body, "the window did not reach the body"
    assert "1500 occurrences" in body, "the occurrence count did not reach the body"

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

    Two rows, so a render that collapsed or deduplicated them is visible. A reader that
    re-derived "qualifying" independently could disagree with the projection that already ran
    and carry a row into `report.md` nothing ever selected."""
    doc = scene.document(
        rows=scene.consult_block(scene.consultation_row())
        + scene.consultation_row(anchor_id="tk-baseline-90d", result="4100 occurrences over 90d")
        + "\n",
        settled=False,
    )
    receipts = _receipts(doc)
    assert len(receipts) == 2, "fixture control: two qualifying consultations"

    body = _body(close_tool.render_report(
        "inconclusive", outcome=close_tool.STANDS, cause=close_tool.CAUSE_NOT_REVIEWED,
        runtime_evidence=receipts,
    ))
    assert body.count("runtime-evidence") == 2
    for anchor in ("tk-baseline-30d", "tk-baseline-90d"):
        assert anchor in body, f"{anchor} was dropped on the way into the body"


def test_close_fields_carries_the_baseline_on_every_disposition():
    """`_CloseFields` carries the baseline as a companion-derived field alongside `ceiling_test`,
    and it defaults empty.

    The structural half of fork F4: `ceiling_test` is populated at ONE of the two construction
    sites and only for `inconclusive`, which is why the cited carrier never reaches a benign
    close. This asserts the field exists and is defaulted; the e2e asserts both sites actually
    populate it."""
    import dataclasses

    fields = {f.name: f for f in dataclasses.fields(close_tool._CloseFields)}
    assert "runtime_evidence" in fields, (
        "`_CloseFields` has no baseline field — the projection has no way onto either close path"
    )
    assert fields["runtime_evidence"].default == (), (
        "the baseline field is not defaulted empty — every existing construction site would "
        "have to name it, and a close with no baseline has none to name"
    )
