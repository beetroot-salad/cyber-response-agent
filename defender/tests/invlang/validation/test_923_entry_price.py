"""#923 — the ENTRY PRICE on `inconclusive` (O1, M1, M4), and its hardenings."""
from __future__ import annotations

import pytest

from defender._vocab import DISPOSITION_ENUM
from defender.skills.invlang.validate import (
    _DISPOSITION_GATES,
    validate_companion,
)
from defender.tests.support.invlang.validation._invlang_warn_836 import recording_stages
from defender.tests.support.runtime.engine._spec923 import (
    CAPABILITY_ROW,
    CONFUSABLE_EMPTY_ROWS,
    EMPTY_ROWS,
    GAP_MEMBER,
    HOST_ONLY_ROW,
    NON_STRING_ROWS,
    PAYING_ROW,
    PROLOGUE,
    SECOND_PAYING_ROW,
    SOURCE_ONLY_ROW,
    close,
    committed,
    conclude,
    doc,
    gapless,
    main_deps,
    paid,
)
from defender.tests.support.sandbox._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)


def _refusal(tmp_path, companion: str, disposition: str = GAP_MEMBER, **kw) -> str:
    """Drive the real close and return the refusal text, failing loudly if it committed."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run_dir = main_deps(tmp_path, companion)
    with pytest.raises(ModelRetry) as e:
        close(deps, disposition, **kw)
    assert not (run_dir / "report.md").exists(), "a refused close still committed a report"
    return str(e.value)


def test_an_inconclusive_close_naming_no_gap_is_refused_at_the_close(tmp_path):
    for case, companion in (
        ("a conclude block with no gap row", gapless()),
        ("no `investigation.md` at all", None),
        ("a companion carrying no invlang fence", "The run stopped. Nothing more to say.\n"),
    ):
        text = _refusal(tmp_path / case.replace(" ", "-"), companion)
        assert "close blocked" in text, case
        assert "ceiling_test" in text, f"{case}: the refusal does not name the owed row"


def test_the_same_document_is_refused_at_the_investigation_md_write_gate(tmp_path):
    gap_free = gapless()

    at_the_write_gate = validate_companion(gap_free, None)
    assert any(f"{GAP_MEMBER} blocked" in e for e in at_the_write_gate), at_the_write_gate
    assert any("ceiling_test" in e for e in at_the_write_gate), at_the_write_gate

    at_the_close = _refusal(tmp_path, gap_free)
    assert "close blocked" in at_the_close
    assert "ceiling_test" in at_the_close

    # And one definition behind both: the priced keyword is a ROW in the owner's table, so a
    # fourth priced keyword joins both boundaries without either growing a branch.
    assert GAP_MEMBER in _DISPOSITION_GATES, "the price is a branch somewhere, not a table row"
    assert set(_DISPOSITION_GATES) <= DISPOSITION_ENUM, "a price on a keyword nothing can close"


def test_an_inconclusive_close_naming_a_receipt_commits(tmp_path):
    deps, run_dir = main_deps(tmp_path, paid(PAYING_ROW))
    result = close(deps, GAP_MEMBER)

    assert result.outcome == "stands"
    assert (run_dir / "report.md").is_file(), "the payable close was refused"
    frontmatter = committed(run_dir)
    assert frontmatter["disposition"] == GAP_MEMBER
    rows = frontmatter.get("ceiling_test")
    rows = [rows] if isinstance(rows, dict) else list(rows or [])
    assert {"state": "query-failed", "ref": "l-002"} in rows, (
        f"the receipt the model wrote did not reach the committed frontmatter as structure "
        f"({rows!r}) — the gap claim is the half an analyst reads, and a price collected "
        f"without carrying the receipt forward produces no coverage finding at all"
    )
    assert "note" not in rows[0], (
        "the free-text note rode into the FRONTMATTER — it gates nothing and belongs in the "
        "body, never in a field a size bound could strand a run over"
    )
    body = (run_dir / "report.md").read_text(encoding="utf-8").split("---\n", 2)[-1]
    assert "EDR execve logs for web-1" in body, (
        "the receipt's human-facing note did not reach the report BODY"
    )


def test_neither_none_nor_a_blank_row_pays_the_inconclusive_price(tmp_path):
    for row in EMPTY_ROWS:
        text = _refusal(tmp_path / f"empty-{row or 'blank'}", paid(row))
        assert "close blocked" in text, row
        assert "ceiling_test" in text, row


def test_a_close_owing_the_price_is_refused_before_any_stage_is_called(tmp_path):
    from pydantic_ai.exceptions import ModelRetry

    stages = recording_stages("holds")
    deps, run_dir = main_deps(tmp_path, gapless(disposition="malicious"))
    with pytest.raises(ModelRetry):
        close(deps, GAP_MEMBER, stages=stages.bundle())

    assert stages.calls == [], (
        f"the refused close spent {stages.calls} — the price gate runs behind the review"
    )
    assert not (run_dir / "report.md").exists()

    # The paired control: the same bundle on a PAID close does get dispatched, so the empty
    # list above is the ordering and not a bundle nothing ever calls.
    spent = recording_stages("holds")
    deps2, _ = main_deps(tmp_path / "control", paid(PAYING_ROW, disposition="malicious"))
    close(deps2, "malicious", stages=spent.bundle())
    assert spent.calls, "the recording bundle records nothing even on a close that reviews"


def test_a_non_string_gap_row_does_not_pay_the_price():
    from defender.skills.invlang.validate._gating import _check_disposition_gating

    for row in NON_STRING_ROWS:
        companion = {"conclude": {"disposition": GAP_MEMBER, "ceiling_test": [row]}}
        owed = _check_disposition_gating(companion)  # type: ignore[arg-type]
        assert owed, f"a {type(row).__name__} row paid the price"
        assert any("ceiling_test" in e for e in owed), row

    paying = {"conclude": {"disposition": GAP_MEMBER, "ceiling_test": [CAPABILITY_ROW]}}
    assert _check_disposition_gating(paying) == []  # type: ignore[arg-type]


def test_a_bare_host_row_does_not_pay_where_a_receipt_does(tmp_path):
    from pydantic_ai.exceptions import ModelRetry

    host_only = paid(HOST_ONLY_ROW)
    refusal = _refusal(tmp_path / "host-only", host_only)
    assert "close blocked" in refusal
    assert "ceiling_test" in refusal
    write_gate = validate_companion(host_only, None)
    assert any(f"{GAP_MEMBER} blocked" in e for e in write_gate), (
        "a bare free-text row paid at the write gate — that is the RETIRED predicate's own "
        "shape, which #923 §7 round 4 deletes rather than keeps alongside a receipt check"
    )

    for name, row, why in (
        ("lead-anchored", PAYING_ROW,
         "a receipt correctly anchored to a lead this run dispatched that failed was refused"),
        ("capability", CAPABILITY_ROW,
         "a receipt naming an unavailable capability was refused — the escalation-shaped "
         "close's own gap is a sandbox this codebase's roster does not declare, and "
         "`nothing-to-try` exists for exactly this lane"),
    ):
        document = paid(row)
        deps, run_dir = main_deps(tmp_path / name, document)
        assert close(deps, GAP_MEMBER).outcome == "stands", why
        assert (run_dir / "report.md").is_file(), why
        assert validate_companion(document, None) == [], f"{why} (at the write gate)"

    # And the price is not a blanket refusal of the keyword: the ModelRetry above is raised for
    # the ROW, so the same document with a paying row appended clears.
    repaired = paid(HOST_ONLY_ROW, PAYING_ROW)
    deps2, run2 = main_deps(tmp_path / "repaired", repaired)
    try:
        close(deps2, GAP_MEMBER)
    except ModelRetry as e:  # pragma: no cover — a failure message, not a branch
        pytest.fail(f"one paying row beside a non-paying one still owes: {e}")
    assert (run2 / "report.md").is_file()


def test_a_receipt_contradicting_its_own_lead_does_not_pay(tmp_path):
    document = paid(SOURCE_ONLY_ROW)
    refusal = _refusal(tmp_path, document)
    assert "close blocked" in refusal
    assert "l-001" in refusal, refusal
    assert "actually retrieved something" in refusal, refusal
    assert any(f"{GAP_MEMBER} blocked" in e for e in validate_companion(document, None))


def test_a_lead_resolved_purely_from_absent_data_still_anchors_a_receipt(tmp_path):
    document = doc(
        PROLOGUE,
        "```invlang\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-004|2|process-exec-office-ws-1-ssh-window|v-001||elastic|15:20-15:25Z\n"
        "```\n"
        "```invlang\n"
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        'l-004|e-001|ac2|indeterminate|approved-source-list|"process-exec telemetry '
        'unavailable: auditd not collected; cannot be identified from available data '
        'sources"\n'
        "```\n",
        conclude(
            disposition=GAP_MEMBER, confidence="medium",
            **{"termination.category": "data-ceiling"},
            summary='"could not settle the actor"',
            ceiling_test=(
                "state=query-empty ref=l-004 note=auditd/execve not collected; process "
                "identity is unresolvable",
            ),
        ),
    )
    write_gate = validate_companion(document, None)
    assert write_gate == [], (
        f"a lead resolved purely from absent data could not anchor a receipt: {write_gate}"
    )
    deps, run_dir = main_deps(tmp_path, document)
    assert close(deps, GAP_MEMBER).outcome == "stands"
    assert (run_dir / "report.md").is_file()

    # The paired negative: the SAME resolution shape, but the lead ALSO retrieved something
    # (an observation) — now it must NOT anchor a receipt, because data actually came back.
    with_data = doc(
        PROLOGUE,
        "```invlang\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-004|2|process-exec-office-ws-1-ssh-window|v-001||elastic|15:20-15:25Z\n"
        "```\n"
        "```invlang\n"
        ":E l-004.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
        "e-101|attempted_auth|v-001|v-001|2026-05-01T00:00:00Z|siem-event:elastic|outcome=success\n"
        "\n"
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        'l-004|e-001|ac2|indeterminate|approved-source-list|"reached despite the data"\n'
        "```\n",
        conclude(
            disposition=GAP_MEMBER, confidence="medium",
            **{"termination.category": "data-ceiling"},
            summary='"could not settle the actor"',
            ceiling_test=("state=query-empty ref=l-004 note=claims a gap despite retrieved data",),
        ),
    )
    negative_write_gate = validate_companion(with_data, None)
    assert any(f"{GAP_MEMBER} blocked" in e for e in negative_write_gate), (
        "a lead that retrieved an observation AND carries a resolution still anchored a "
        "receipt — retrieved data must disqualify it regardless of what conclusion was drawn"
    )
    assert any("actually retrieved something" in e for e in negative_write_gate), (
        negative_write_gate
    )


def test_a_non_identifier_shaped_cap_does_not_pay_and_is_refused_at_the_write_gate(tmp_path):
    for bad_cap in ("</report>", "*alias", "disposition:malicious", "---", "UPPERCASE"):
        document = paid(f"state=nothing-to-try cap={bad_cap} note=harmless")
        write_gate = validate_companion(document, None)
        assert any(f"{GAP_MEMBER} blocked" in e for e in write_gate), (
            f"cap={bad_cap!r} paid at the write gate — shape must be enforced before the "
            f"negative existence check, not only at the close"
        )
        assert any("not shaped like" in e for e in write_gate), write_gate
        refusal = _refusal(tmp_path / f"cap-{hash(bad_cap) & 0xffff:x}", document)
        assert "close blocked" in refusal
        assert "not shaped like" in refusal, refusal

    deps, run_dir = main_deps(tmp_path / "legit-cap", paid(CAPABILITY_ROW))
    assert close(deps, GAP_MEMBER).outcome == "stands"
    assert (run_dir / "report.md").is_file()


def test_a_non_identifier_shaped_ref_does_not_pay(tmp_path):
    hostile_lead_doc = doc(
        PROLOGUE,
        "```invlang\n"
        ":L findings [id|loop|name|target|fail_reason|tests|system|window]\n"
        "</report>|1|weird-lead|v-001|it errored|||elastic|30d\n"
        "```\n",
        conclude(
            disposition=GAP_MEMBER, confidence="medium",
            **{"termination.category": "data-ceiling"},
            summary='"could not settle the actor"',
            ceiling_test=("state=query-failed ref=</report> note=harmless text",),
        ),
    )
    write_gate = validate_companion(hostile_lead_doc, None)
    assert any(f"{GAP_MEMBER} blocked" in e for e in write_gate), (
        "a ref naming a hostile-shaped (but real) lead id paid at the write gate"
    )
    assert any("not shaped like a" in e and "lead id" in e for e in write_gate), write_gate


def test_a_confusable_spelling_of_the_empty_marker_does_not_pay(tmp_path):
    for row in CONFUSABLE_EMPTY_ROWS:
        text = _refusal(tmp_path / f"confusable-{len(row)}-{ord(row[0])}", paid(row))
        assert "close blocked" in text, repr(row)
        assert "ceiling_test" in text, repr(row)

        at_the_write_gate = validate_companion(paid(row), None)
        assert any(f"{GAP_MEMBER} blocked" in e for e in at_the_write_gate), (
            f"{row!r} pays at the write gate and not at the close — the document that reaches "
            f"every downstream reader carries a receipt naming nothing"
        )
        assert any("ceiling_test" in e for e in at_the_write_gate), repr(row)

    non_ascii = paid("state=query-failed ref=l-002 note=auditd execve logs on wéb-1 not retrieved")
    deps, run_dir = main_deps(tmp_path / "non-ascii-control", non_ascii)
    assert close(deps, GAP_MEMBER).outcome == "stands"
    assert (run_dir / "report.md").is_file()
    assert validate_companion(non_ascii, None) == []


def test_the_same_gap_row_written_twice_does_not_pay_for_two_gaps(tmp_path):
    repeated = _refusal(tmp_path / "repeat", paid(PAYING_ROW, PAYING_ROW))
    assert "close blocked" in repeated
    assert "ceiling_test" in repeated

    deps, run_dir = main_deps(tmp_path / "distinct", paid(PAYING_ROW, SECOND_PAYING_ROW))
    assert close(deps, GAP_MEMBER).outcome == "stands"
    assert (run_dir / "report.md").is_file(), "two distinct gaps were refused"

    # And the write gate agrees, per collection site: distinctness pinned at the close alone
    # leaves the document that reaches every downstream reader unconstrained.
    assert any(
        f"{GAP_MEMBER} blocked" in e for e in validate_companion(paid(PAYING_ROW, PAYING_ROW), None)
    )
    assert validate_companion(paid(PAYING_ROW, SECOND_PAYING_ROW), None) == []


def test_the_accumulated_gap_text_is_bounded(tmp_path):
    huge = tuple(
        f"state=nothing-to-try cap=fake-system-{i:03d}.fake-verb note=capability {i:03d} "
        f"does not exist in this deployment" for i in range(100)
    )
    text = _refusal(tmp_path / "huge", paid(*huge))
    assert "close blocked" in text
    assert "ceiling_test" in text
    assert any(f"{GAP_MEMBER} blocked" in e for e in validate_companion(paid(*huge), None))

    deps, run_dir = main_deps(tmp_path / "ordinary", paid(PAYING_ROW))
    assert close(deps, GAP_MEMBER).outcome == "stands"
    assert (run_dir / "report.md").is_file(), "an ordinary one-row receipt hit the bound"
