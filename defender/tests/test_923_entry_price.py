"""#923 — the ENTRY PRICE on `inconclusive` (O1, M1, M4), and its hardenings.

Every test here is one demand of `spec-flow/specs/spec_graph_923-inconclusive.yaml`, named by
that demand's `discharged_by`.

THE PRICE PREDICATE WAS REOPENED AND REPLACED AT §7 ROUND 4 (a SECOND human decision,
POST-PHASE — the round-4 WIDENING this module used to pin, "a row naming a source or an
unavailable capability", is itself now superseded). Measured against that widened free-text
predicate: it refused a three-letter telemetry source (`EDR not available` — `_row_names_a_
source_or_capability` stripped filler words down to `edr`, four characters short of paying)
while `ceiling_test "unknown"` bought a close outright. The predicate is DELETED, not kept
alongside a new one: a `ceiling_test` row is now a RECEIPT the host verifies MECHANICALLY
against this run's own transcript, never a judgment of what the row's prose says.

A row pays by parsing as `state=<query-failed|query-empty|nothing-to-try>
[ref=<lead-id>|cap=<system[.verb]>] note=<text>`. `query-failed`/`query-empty` anchor to a
`:L findings` lead THIS RUN dispatched (`ref=`) — a foreign-key check against `_leads`, reusing
`_lead_returned_a_result` (the SAME lookup `entity_check` uses, not a second one), plus a
consistency check between the claimed state and that lead's own recorded `fail_reason`.
`nothing-to-try` is the one lane with no call to point at — a capability that does not exist AT
ALL, so nothing was dispatchable — checked NEGATIVELY against the closed verb roster this
codebase's own `scripts/adapters/` ships (`cap=`, never `ref=`). `note` is free text for the
human analyst: it gates NOTHING (only `state`/`ref`/`cap` are checked) and rides into the report
BODY, never the frontmatter, so it can never strand a run.
`test_a_bare_host_row_does_not_pay_where_a_receipt_does` is where the discriminating negative
lives — the retired free-text shape does not even PARSE as a receipt — and it is the test the
rest of this module leans on: without it a build that still judges prose passes every other
scenario here.
"""
from __future__ import annotations

import pytest

from defender._vocab import DISPOSITION_ENUM
from defender.skills.invlang.validate import (
    _DISPOSITION_GATES,
    disposition_entry_price,
    validate_companion,
)
from defender.tests._invlang_warn_836 import recording_stages
from defender.tests._spec923 import (
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
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)

pytestmark = pytest.mark.gate


def _refusal(tmp_path, companion: str, disposition: str = GAP_MEMBER, **kw) -> str:
    """Drive the real close and return the refusal text, failing loudly if it committed."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run_dir = main_deps(tmp_path, companion)
    with pytest.raises(ModelRetry) as e:
        close(deps, disposition, **kw)
    assert not (run_dir / "report.md").exists(), "a refused close still committed a report"
    return str(e.value)


# ---------------------------------------------------------------------------------------
# O1 — the price, at the close and at the write gate.
# ---------------------------------------------------------------------------------------

def test_an_inconclusive_close_naming_no_gap_is_refused_at_the_close(tmp_path):
    """A close supplying `inconclusive` whose parsed `:T conclude` carries no `ceiling_test`
    row that pays the price is refused at `close_investigation`, by a `ModelRetry` whose text
    names the owed row. The refusal covers the no-companion and the unparseable-companion cases
    alike: no companion means no stating row, which means no payment.

    All three inputs are real text through the real primitive — the file is absent, the file
    holds prose that is not invlang at all, or the fence is there and the row is not — so the
    taxonomy assumption is re-probed on every run rather than pinned once."""
    for case, companion in (
        ("a conclude block with no gap row", gapless()),
        ("no `investigation.md` at all", None),
        ("a companion carrying no invlang fence", "The run stopped. Nothing more to say.\n"),
    ):
        text = _refusal(tmp_path / case.replace(" ", "-"), companion)
        assert "close blocked" in text, case
        assert "ceiling_test" in text, f"{case}: the refusal does not name the owed row"


def test_the_same_document_is_refused_at_the_investigation_md_write_gate(tmp_path):
    """The one document that is refused at the close is refused at the `investigation.md` write
    gate too, and for the same owed row: the price is a property of the TABLE
    (`_DISPOSITION_GATES`), collected at both boundaries from one definition, not a branch
    written twice.

    Asserted PER COLLECTION SITE, never once at the table's altitude — a constraint pinned on
    one surface and silently absent on its sibling is this repo's canonical fail-open, and it is
    the exact hole `benign` carried until the close grew its own reader.

    The document concludes `inconclusive` AND the close commits `inconclusive`, because the two
    boundaries dispatch on different values by design: the write gate on the keyword the
    DOCUMENT wrote, the close on the keyword the CALLER is about to commit."""
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
    """An `inconclusive` close whose `ceiling_test` names a valid receipt commits: the price is
    payable, the report lands, `ref`/`state` arrive in the committed FRONTMATTER unchanged, and
    the `note` arrives in the report BODY (never the frontmatter — it gates nothing).

    Without this control every refusal in this module passes on a build where the price gate
    refuses everything, and this is also the paired positive for
    `test_the_cause_stays_composed_from_report_causes_and_the_verdict_stays_host_chosen`: the
    receipt DOES land, legitimately, lifted from the companion."""
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
    """The honest empty marker `none` and the blank string both project as stating nothing, so
    neither pays the price: a close carrying only such a row is refused exactly as one carrying
    no row at all.

    These are the two inputs the design's own probe covered. `ceiling_test  ""` is the sharper
    of the pair — it projects as a ONE-ELEMENT list holding the empty string, so a price written
    as a truthiness test over the list makes the blank strictly easier to get past than the
    honest marker."""
    for row in EMPTY_ROWS:
        text = _refusal(tmp_path / f"empty-{row or 'blank'}", paid(row))
        assert "close blocked" in text, row
        assert "ceiling_test" in text, row


def test_every_termination_category_owes_the_same_row(tmp_path):
    """The price is owed on the VERDICT alone. An `inconclusive` close owes the same row whether
    it terminates on `exhaustion`, `data-ceiling`, `severity-ceiling` or the misspelling
    `severity_ceiling` — the free-text category cannot silently disable it, which is the whole
    reason the trigger moved off `conclude.termination.category` and onto a closed validated
    enum.

    `severity_ceiling` is the load-bearing row: `termination.category` has no vocabulary, so a
    single typo turns the OLD severity-ceiling rule off with nothing said, and the new price
    must not inherit that."""
    for category in ("exhaustion", "data-ceiling", "severity-ceiling", "severity_ceiling"):
        text = _refusal(tmp_path / category, gapless(category=category))
        assert "close blocked" in text, category
        assert "ceiling_test" in text, category


def test_a_close_owing_the_price_is_refused_before_any_stage_is_called(tmp_path):
    """A close that owes the price is refused before any review stage is dispatched and before
    any disposition branch is taken: no reviewer model call is spent on a close that is going to
    be refused anyway.

    Driven and OBSERVED, not inferred: the review bundle records every stage call, and the
    assertion is that it recorded none. Asserting only that the close failed would pass on a
    build that ran the whole review first and refused afterwards, which is the cost this
    ordering exists to avoid."""
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
    """A non-string `ceiling_test` row — a list, a mapping, an int, `None`, a bool — is treated
    as not-stating, with no exception: the close is refused exactly as it would be for `none` or
    `''`. It refuses CLOSED, not open, which is the safe direction.

    Driven against the parsed companion dict rather than through `investigation.md` text, and
    that is not a shortcut: the real parser's row regex can only ever produce a `str` (or drop
    the row), so a non-string row is reachable only from a programmatically built companion —
    an imported run dir, a replayed fixture, a caller that assembled the body itself. The
    premise that first raised this ("a type check fails") described a mechanism that does not
    exist; nothing raises, and the correction is what is pinned here."""
    from defender.skills.invlang.validate._gating import _check_disposition_gating

    for row in NON_STRING_ROWS:
        companion = {"conclude": {"disposition": GAP_MEMBER, "ceiling_test": [row]}}
        owed = _check_disposition_gating(companion)  # type: ignore[arg-type]
        assert owed, f"a {type(row).__name__} row paid the price"
        assert any("ceiling_test" in e for e in owed), row

    # The control on the same surface: a stating STRING row in the same position pays, so the
    # refusals above are the row's type and not a check that refuses every companion dict.
    # `CAPABILITY_ROW`, not `PAYING_ROW`: this companion carries no `:L findings` at all, and a
    # `nothing-to-try` receipt is the one shape that needs no lead to resolve.
    paying = {"conclude": {"disposition": GAP_MEMBER, "ceiling_test": [CAPABILITY_ROW]}}
    assert _check_disposition_gating(paying) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------------
# The settled predicate, and the three hardenings.
# ---------------------------------------------------------------------------------------

def test_a_bare_host_row_does_not_pay_where_a_receipt_does(tmp_path):
    """A `ceiling_test` row pays by being a RECEIPT the host verifies mechanically, never by
    what a sentence about a limitation says.

    Three rows decide this:

    * bare free prose (`web-1 could not be fully checked`) does NOT pay. It carries no
      `state=`/`ref=`/`cap=`/`note=` fields at all, so it does not even PARSE as a receipt —
      this is the retired predicate's own shape, and it is the assertion a build that still
      judges prose fails;
    * a receipt anchored to a lead THIS RUN dispatched that came back with nothing
      (`SOURCE_ONLY_ROW`... wait, see below) DOES pay when the state matches what that lead's
      own row says happened;
    * a receipt naming a CAPABILITY this deployment's closed verb roster does not declare at
      all (`CAPABILITY_ROW`, `state=nothing-to-try`) DOES pay — the one lane with no lead to
      point at, checked against code this repo owns rather than a catalogue of what exists in
      the world.

    All three directions are asserted at BOTH boundaries, because a predicate that drifts
    between the write gate and the close reopens the bypass the two-boundary collection closed.
    The bare-host row is what keeps the mechanical check falsifiable: a build that still reads
    any sentence about a limitation as a claim pays for `web-1 could not be fully checked` and
    fails here."""
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
    """A well-FORMED receipt — `ref` resolves to a real `:L findings` lead — still does not pay
    when it is INCONSISTENT with what that lead's own RETRIEVAL says happened: `SOURCE_ONLY_ROW`
    names `l-001`, which `LEAD_RESULT` attaches an actual observation to, so the receipt claims
    a gap the transcript itself contradicts. This is the mechanical check `_lead_retrieval_
    came_back` runs — checked against `outcome`'s retrieval-populated keys, never against
    whether a resolution exists (see `test_a_lead_resolved_purely_from_absent_data_still_
    anchors_a_receipt` for why a resolution alone must NOT disqualify a lead) — and it is what
    makes a receipt a RECEIPT rather than a structured-looking sentence: naming a real id is
    not enough, the id's own retrieval has to have actually failed or come back empty."""
    document = paid(SOURCE_ONLY_ROW)
    refusal = _refusal(tmp_path, document)
    assert "close blocked" in refusal
    assert "l-001" in refusal, refusal
    assert "actually retrieved something" in refusal, refusal
    assert any(f"{GAP_MEMBER} blocked" in e for e in validate_companion(document, None))


def test_a_lead_resolved_purely_from_absent_data_still_anchors_a_receipt(tmp_path):
    """A lead that reaches an analytical CONCLUSION about an absence of data still anchors a
    `ceiling_test` receipt — a resolution alone does not disqualify it, only RETRIEVED DATA
    does.

    This is the shape `golden-v2sshd`'s real `l-004` takes, and it is the most common real gap
    shape in that corpus: the query ran, found nothing, and the model drew a conclusion (an
    authz verdict of `indeterminate`) from that absence anyway — "process-exec telemetry
    unavailable... cannot be identified from available data sources". Before
    `_lead_retrieval_came_back` replaced `_lead_returned_a_result` at this ONE call site, that
    resolution alone made `l-004` read as "returned a result" — identical to a lead that
    resolved from data it actually retrieved — so the most common real gap shape in the
    shipped corpus was unanchorable by any receipt, and the only way to ship the fixture was to
    fold that gap into another receipt's `note` as unstructured prose: exactly the shape this
    redesign exists to remove, now smuggled back in through the one example that teaches the
    format.

    Driven through the REAL primitive: a lead with a `:R authz` resolution and no `:V`/`:E`
    observations and no `:R attr_updates` of its own — the same shape, built minimally rather
    than through the full golden fixture, so this test does not depend on that document's own
    unrelated structure."""
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
    """`cap` is checked by ABSENCE — `not _capability_exists(cap)` — and a negative check
    cannot constrain SHAPE: it is satisfied by any string that happens not to name a real
    capability. Measured, `cap=</report>` reaches this far: it is a well-formed
    `state=nothing-to-try` receipt, it is not a real capability, so the negative check alone
    pays it — and PyYAML writes an UNQUOTED `cap: </report>` into the frontmatter, which
    `_artifact_schema.validate_report` then refuses for carrying the judge's own report-block
    delimiter. Companion writes are append-only, so that refusal is not repairable: a paid
    write-gate close that fails at commit with no legal retry is exactly the #923 stranded-run
    failure `_REPORT_CLOSE_DELIMITER` exists to prevent, reopened through a field that
    delimiter check never looked at.

    THE FIX IS SHAPE, NOT A SECOND DELIMITER CHECK: `cap` must match `<system>` or
    `<system.verb>` — the same identifier alphabet `runtime.verbs.is_system_name` checks a real
    system against — BEFORE the negative existence check ever runs. That closes the whole
    class: the delimiter, YAML metacharacters (`cap=*alias`, `cap=---`), and anything else that
    is not a valid `system[.verb]` token, none of which needs its own named check.

    Pinned at the WRITE GATE, not only at the close — the point of the entry price is that a
    paid close never fails for a reason the model could not see coming, and a defect reachable
    only from the close would mean the write gate waved this document through first."""
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

    # The control: a real capability this deployment does not provide, correctly shaped, still
    # pays — the shape check refuses malformed tokens, not every `cap` a build could tighten
    # into refusing everything.
    deps, run_dir = main_deps(tmp_path / "legit-cap", paid(CAPABILITY_ROW))
    assert close(deps, GAP_MEMBER).outcome == "stands"
    assert (run_dir / "report.md").is_file()


def test_a_non_identifier_shaped_ref_does_not_pay(tmp_path):
    """The SAME class of bug, the OTHER field: `ref` is checked by membership in `:L findings`
    (`_lead_by_id`), which reads as a closed check but is not one — a `:L findings` row's `id`
    cell is unquoted free text with no shape rule anywhere in the parser, so a lead literally
    declared with `id=</report>` parses with zero warnings and `ref=</report>` then resolves
    against it, exactly as cleanly as `ref=l-002` resolves against an ordinary lead. Measured
    end to end: a companion carrying such a lead pays the write gate and renders an UNQUOTED
    `ref: </report>` into the frontmatter, which `_artifact_schema.validate_report` refuses at
    the close with no legal retry — the identical stranded-run shape `cap`'s fix above closes.

    Fixed the same way: `ref` is checked against the shape every `:L findings` id takes in this
    format (`l-<alphanumeric>`, `_LEAD_REF_RE`) BEFORE the table lookup, so a hostile id cannot
    be planted in `:L findings` and then cited — the lookup alone was never enough, because the
    table it checks membership in is not itself shape-constrained."""
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
    """A row that RENDERS to a human as the empty marker does not pay, whatever codepoints it
    is spelled with, in ALL FOUR spellings an executed probe measured paying and at BOTH
    boundaries.

    A visually-blank row satisfying a coverage receipt is the sharpest thing in this change:
    alert data is attacker-influenced, the row is model-authored after reading it, and the
    receipt is what an analyst counts. The four spellings are P10's own output against a
    checker that normalizes case, whitespace and quoting and does no Unicode normalization at
    all.

    THE DEMAND IS THE OUTCOME AND NOT THE MECHANISM THE RESOLUTION NAMED, because measured, the
    named mechanism cannot meet it: the normalizer the disposition keywords already go through
    (`_vocab.normalized_disposition` → `strip_zero_width`) catches 2 of these 4, NFKC would
    reach a third, and the Cyrillic homoglyph needs a confusable/skeleton fold that exists
    nowhere under `defender/`. Extending that shared normalizer is the route this repo's own
    doctrine points at — a second, field-specific spelling of normalization is how its rules
    have already drifted — and its existing callers need checking when it moves. Narrowing the
    demand to the two the normalizer catches was refused: two documented ways to pay with an
    invisible row, shipped knowingly.

    BOTH boundaries, per collection site. J1, J25 and J28 each bind both; a confusable-blind
    write gate beside a hardened close is this repo's canonical fail-open, and it leaves the
    document every downstream reader actually reads unconstrained."""
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

    # The control that keeps this from passing on a build that refuses every non-ASCII row: an
    # ordinary receipt whose NOTE carries a non-ASCII character still pays, at both — the note
    # is free text for a human and is never checked, so nothing about its content should matter.
    non_ascii = paid("state=query-failed ref=l-002 note=auditd execve logs on wéb-1 not retrieved")
    deps, run_dir = main_deps(tmp_path / "non-ascii-control", non_ascii)
    assert close(deps, GAP_MEMBER).outcome == "stands"
    assert (run_dir / "report.md").is_file()
    assert validate_companion(non_ascii, None) == []


def test_the_same_gap_row_written_twice_does_not_pay_for_two_gaps(tmp_path):
    """Rows must be DISTINCT: repetition does not pay for more than one gap. A `:T conclude`
    whose `ceiling_test` rows repeat is refused, and the refusal names the repeat.

    The cost was weighed and accepted: this is a policy call with no probe behind it and it will
    refuse some legitimate runs — a run that genuinely writes the same sentence twice has to
    edit one of them. What it buys is that the receipt's row COUNT means what an analyst reads
    it as, on a channel whose whole output is counted gaps.

    The control is the same document with the duplicate replaced by a second, different gap:
    several rows are the ordinary case and must commit."""
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
    """The accumulated `ceiling_test` FRONTMATTER — `ref`/`state`/`cap` alone, never the notes,
    which gate nothing and cannot be bounded without becoming a gate — is BOUNDED, and a close
    whose receipts exceed it is refused at both boundaries.

    A hundred DISTINCT `nothing-to-try` receipts (a hundred capabilities this deployment does
    not provide) is the shape that exercises the bound honestly: each is individually tiny and
    individually valid, so only the ACCUMULATED structured block — not any one receipt's
    content — can be what trips it. The bound's exact value is an implementation choice this
    test does not pin: it asserts the two ends far apart — one ordinary receipt commits, a
    hundred distinct ones do not — so any sane bound satisfies it and NO bound fails it.

    Accepted cost, on the record with distinctness: a run with genuinely many gaps has to
    summarise, and this will refuse some legitimate runs."""
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


# ---------------------------------------------------------------------------------------
# The neighbour rule the price must not absorb.
# ---------------------------------------------------------------------------------------

def test_both_rules_fire_independently_on_one_document():
    """The existing severity-ceiling rule (keyed on `conclude.termination.category`) and the new
    disposition price fire INDEPENDENTLY on one document: neither is removed, renamed or
    subsumed by the other, neither contains the other, and each must be satisfied separately.

    Three documents separate them. A `malicious` close terminating on a severity ceiling with no
    row owes the OLD rule and no price. An `inconclusive` close terminating on exhaustion owes
    the PRICE and not the old rule. One document doing both draws both messages — which is what
    "neither contains the other" means as an observation rather than as a claim about the
    source. Unifying the two rules was considered and is not attempted this round."""
    old_only = validate_companion(gapless(disposition="malicious", category="severity-ceiling"), None)
    assert any("severity-ceiling" in e and "ceiling_test" in e for e in old_only), old_only
    assert not any(f"{GAP_MEMBER} blocked" in e for e in old_only), (
        "the severity-ceiling rule now speaks for the disposition price too"
    )

    price_only = validate_companion(gapless(category="exhaustion"), None)
    assert any(f"{GAP_MEMBER} blocked" in e for e in price_only), price_only
    assert not any("termination.category severity-ceiling" in e for e in price_only)

    both = validate_companion(gapless(category="severity-ceiling"), None)
    assert any("termination.category severity-ceiling" in e for e in both), both
    assert any(f"{GAP_MEMBER} blocked" in e for e in both), both

    # The old rule keeps its own scope: a `malicious` close on any other category owes it
    # nothing, so the price did not widen it on the way past.
    assert validate_companion(
        doc(conclude(disposition="malicious", **{"termination.category": "exhaustion"})), None,
    ) == []


def test_the_entry_price_is_owed_by_the_keyword_the_close_commits():
    """The price follows the close's disposition ARGUMENT, never the document's
    `conclude.disposition` — executed, and it is what makes the two-boundary collection
    necessary rather than redundant.

    A document can conclude one keyword while the close commits a different, differently-priced
    one, and nothing refuses the disagreement; `report.md` is written from the ARGUMENT, and
    `report.md` is what the learning loop, the evals and the ticket lane read."""
    concluded_benign = paid(PAYING_ROW, disposition="benign")
    assert disposition_entry_price(GAP_MEMBER, concluded_benign).owed == ()

    concluded_gap = gapless()
    assert disposition_entry_price("malicious", concluded_gap).owed == ()
    assert disposition_entry_price(GAP_MEMBER, concluded_gap).owed, (
        "the close's own keyword owes nothing — the price reads the document's instead"
    )

    # #722's mechanism at this dispatch, and THE WRITE-SIDE HALF OF THE §7-ROUND-4 DESIGN
    # CHANGE: a keyword that is not a member fails CLOSED here — it still OWES — rather than
    # taking the unpriced branch, and the rationale comes back off the SAME lookup.
    #
    # This is what stops "a malformed verdict is never coerced" from being implemented by
    # gutting the shared normalizer. Executed against two scratch builds carrying M1: removing
    # the coercion and NOTHING ELSE makes this laced keyword unpriced and turns this assertion
    # red, while removing it and refusing a non-member at this dispatch passes both this and
    # `test_a_malformed_committed_verdict_is_marked_not_coerced`. On write there is still an
    # author to ask; on read there is not, and the two halves must not be swapped.
    laced = disposition_entry_price(f"{GAP_MEMBER}​", concluded_gap)
    assert laced.owed, (
        "a zero-width-laced priced keyword took the UNPRICED branch — the price dispatch is a "
        "write gate and fails open on a malformed keyword"
    )
    assert laced.rationale
