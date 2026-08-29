"""#923 — the ENTRY PRICE on `inconclusive` (O1, M1, M4), and the three hardenings.

Every test here is one demand of `spec-flow/specs/spec_graph_923-inconclusive.yaml`, named by
that demand's `discharged_by`. RED against HEAD is the expected state: `_DISPOSITION_GATES` has
two rows and `inconclusive` is not one of them, so today every close below commits.

THE PRICE PREDICATE IS SETTLED AND IT IS NEITHER OF THE TWO THE DESIGN OFFERED. A row pays when
it names a specific DATA SOURCE that was not retrieved, OR a CAPABILITY the run did not have; a
host is permitted but never required. "A row that states something" is strictly weaker — it is
paid by a row naming a host and no source — and "host plus data source" is strictly stronger,
and would refuse the deployment-wide gap ("no system here exposes this predicate") that is the
finding class this issue exists to surface.
`test_a_bare_host_row_does_not_pay_where_a_source_row_and_a_capability_row_do` is where that
lives, and it is the test the rest of this module leans on: without it a build that implemented
the weaker predicate would pass every other scenario here.

THE CAPABILITY HALF IS THE §7-ROUND-4 WIDENING, and it is not a generalization for its own
sake: the issue's own framing is "predicate P would resolve this; nothing here exposes P",
which is a statement about what the deployment can DO and not only about what it has recorded.
The one shipped escalation-shaped close says so in its own prose — confirming C2 "would require
sandbox detonation or traffic-content inspection, and neither is in the runtime tool surface" —
so the alternative was to relabel a missing sandbox as a missing data source, which forces a
real case into a shape that does not fit and is how a rule starts collecting compliant rows
that mislead. The cost is stated: "capability" is the looser of the two words, and it stays
falsifiable only because the bare-host row remains a refused input in the same test.

The accepted cost of the source half is on the record too: `auditd not collected` pays without
saying where, so a single-host gap can read as deployment-wide and the channel loses scope
information it could have carried.
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


def test_an_inconclusive_close_naming_a_host_and_a_data_source_commits(tmp_path):
    """An `inconclusive` close whose `ceiling_test` block names a host AND the data source that
    could not be reached commits: the price is payable, the report lands, and the row's text
    arrives in the committed report unchanged.

    Without this control every refusal in this module passes on a build where the price gate
    refuses everything, and this is also the paired positive for
    `test_the_cause_stays_composed_from_report_causes_and_the_verdict_stays_host_chosen`: model
    text DOES land, legitimately, in the `ceiling_test` slot lifted from the companion."""
    deps, run_dir = main_deps(tmp_path, paid(PAYING_ROW))
    result = close(deps, GAP_MEMBER)

    assert result.outcome == "stands"
    assert (run_dir / "report.md").is_file(), "the payable close was refused"
    frontmatter = committed(run_dir)
    assert frontmatter["disposition"] == GAP_MEMBER
    rows = frontmatter.get("ceiling_test")
    rows = [rows] if isinstance(rows, str) else list(rows or [])
    assert PAYING_ROW in rows, (
        "the row the model wrote did not reach the committed report — the gap claim is the "
        "half an analyst reads, and a price collected without carrying the claim forward "
        "produces no coverage finding at all"
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
    paying = {"conclude": {"disposition": GAP_MEMBER, "ceiling_test": [PAYING_ROW]}}
    assert _check_disposition_gating(paying) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------------
# The settled predicate, and the three hardenings.
# ---------------------------------------------------------------------------------------

def test_a_bare_host_row_does_not_pay_where_a_source_row_and_a_capability_row_do(tmp_path):
    """A row pays when it names an unretrieved DATA SOURCE **or** an unavailable CAPABILITY. A
    host is PERMITTED but NEVER REQUIRED.

    Three rows decide this, and they decide it in opposite directions:

    * a row naming a host and no source and no capability (`web-1 could not be fully checked`)
      does NOT pay. It is a row that states something, so a price written to the REJECTED
      weaker predicate accepts it — this is the assertion such a build fails — and it names no
      check anyone can go make;
    * a row naming a source and no host (`process-ancestry telemetry is not collected anywhere
      in this deployment`) DOES pay. That class — no system in this deployment exposes the
      predicate — has no host to name, and a host-and-source rule would refuse exactly the
      coverage findings this change exists to produce;
    * a row naming a CAPABILITY the run did not have and no data source at all (`no detonation
      sandbox is available to this runtime`) DOES pay. This is the §7-round-4 widening, and the
      shipped escalation document is why: its real gap is a sandbox it could not detonate in,
      and calling that an unretrieved data source would have been a relabelling rather than a
      finding.

    All three directions are asserted at BOTH boundaries, because a predicate that drifts
    between the write gate and the close reopens the bypass the two-boundary collection closed.
    The bare-host row is what keeps the widened predicate falsifiable: "capability" is a looser
    word than "data source", and a build that reads any sentence about a limitation as a
    capability claim pays for `web-1 could not be fully checked` and fails here."""
    from pydantic_ai.exceptions import ModelRetry

    host_only = paid(HOST_ONLY_ROW)
    refusal = _refusal(tmp_path / "host-only", host_only)
    assert "close blocked" in refusal
    assert "ceiling_test" in refusal
    write_gate = validate_companion(host_only, None)
    assert any(f"{GAP_MEMBER} blocked" in e for e in write_gate), (
        "a row naming a host and neither a data source nor a capability paid at the write "
        "gate — that is the `row-states-something` predicate J1 rejected"
    )

    for name, row, why in (
        ("deployment-wide", SOURCE_ONLY_ROW,
         "the deployment-wide gap was refused — this is the finding class the change exists "
         "to surface, and it has no host to name"),
        ("capability", CAPABILITY_ROW,
         "a row naming an unavailable capability and no data source was refused — the "
         "escalation-shaped close's own gap is a sandbox, and §7 round 4 widened the "
         "predicate rather than relabel it"),
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
    # ordinary paying row whose host name carries a non-ASCII character still pays, at both.
    non_ascii = paid("auditd execve logs on wéb-1 not retrieved")
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
    """The accumulated `ceiling_test` text is BOUNDED, and a close whose rows exceed the bound
    is refused at both boundaries.

    The rows are model-authored, they are now MANDATORY on every priced close rather than
    present on two fixture documents, and they ride verbatim into the committed report, into the
    judge model's prompt and out through the ticket bridge's HTTP egress. Nothing else bounds
    them. The bound's exact value is an implementation choice this test does not pin: it asserts
    the two ends far apart — one ordinary row commits, a hundred distinct rows of a hundred
    characters each does not — so any sane bound satisfies it and NO bound fails it.

    Accepted cost, on the record with distinctness: a run with genuinely many gaps has to
    summarise, and this will refuse some legitimate runs."""
    huge = tuple(f"data source {i:03d} on host-{i:03d} not retrieved {'x' * 100}" for i in range(100))
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
