"""The review findings on #983's first cut, each pinned as the document or call that used to
get through (PR #991).

FOUR CLASSES, and they are worth keeping apart because the repairs are different in kind:

  * **A run the close can never finish.** Model free text now reaches `report.md`'s BODY, and
    the report schema caps the WHOLE FILE and refuses a literal `</report>` anywhere in it. So
    a `:R consultations` cell the invlang write gate accepted could render a report
    `validate_report` then refused — on an APPEND-ONLY companion, whose offending row cannot be
    withdrawn, which makes every retry fail identically. `render_report`'s own docstring argued
    body text could not do this. Both are charged at the write gate now, against the bytes the
    renderer writes.

  * **The authorization receipt, priced at zero.** Mechanism B's claim is that faking a
    `tacit-knowledge` authorization costs two coordinated rows. Three ways it cost less: omit
    the optional `anchor_id` and the receipt is skipped entirely; misspell `grounding` and the
    telemetry refusal (an exact string match) does not fire; write a citation beside a lookup
    the row itself records as a MISS, since the check keyed on the id's presence and the
    hit/miss split was a convention rather than a rule.

  * **A guard that was off.** Mechanism A refuses a baseline whose window does not end before
    the alert — but only when the document carried a parseable alerted moment, and nothing
    requires a prologue EDGE at all. One `??` and "a pattern that begins with the incident is
    the incident" was unenforced.

  * **The registry file's own rules, unenforced.** The 180-day freshness bound is a bound on
    the SPAN between two dates, and the read side tested only the far end — so moving both
    dates into the future bought unlimited validity. A YAML-resolved timestamp was dropped by
    the very branch that exists to keep unquoted dates. Duplicate ids loaded silently, and the
    lookup answered with whichever came first.

WHAT IS DELIBERATELY NOT HERE. Two review findings are about REPORTING rather than about a
document getting through, and they are asserted at the bottom under their own names: a refusal
printed twice, and a repeated row rendered twice. Neither admits a bad close; both are pinned
because the fix is a one-line dedup that a later refactor drops without noticing.

Each test states the shape that USED to pass and asserts it is refused, then asserts the honest
neighbour still is not — a gate that refuses everything passes half of these on its own.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from defender._artifact_schema import REPORT_FILE_MAX, validate_report
from defender.runtime import close_tool
from defender.scripts.adapters import tacit_knowledge_adapter as tk
from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import validate_companion

from defender.tests import _tacit983 as scene
from defender.tests._spec923 import close, committed, main_deps
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)

pytestmark = pytest.mark.gate


def _errors(document: str) -> list[str]:
    """Every error-severity refusal the write gate files against `document`."""
    return validate_companion(document, None)


def _receipts(document: str):
    """The baseline receipts the close would carry out of `document`."""
    from defender.skills.invlang.validate import conclude_runtime_evidence_rows

    return conclude_runtime_evidence_rows(parse_dense_companion(document)[0])


#: The document a real container-root benign close writes: the recorded registry hit, the
#: `:R authz` row citing it, and the recurrence baseline beside them. THE CONTROL — every test
#: below moves one cell of it, so a refusal any of them reports is about the cell that moved.
GOOD = scene.benign_document(rows=scene.authorized_rows(baseline=True))


def test_the_control_document_still_closes() -> None:
    """Fixture control, and the half of every test below that a blanket refusal would fail.

    Asserted FIRST and on its own so a gate that got stricter than it meant to reports here,
    at the document the mechanisms exist to make reachable, rather than as a confusing pass
    somewhere in the negatives."""
    assert _errors(GOOD) == [], "the shape mechanism B exists to admit is refused"


# ---------------------------------------------------------------------------------------
# A run the close can never finish.
# ---------------------------------------------------------------------------------------

def test_a_baseline_carrying_the_report_delimiter_is_refused_on_write() -> None:
    """`result` and `reasoning` ride verbatim into `report.md`'s body, so a literal `</report>`
    in either is refused where the row can still be written differently.

    THE COST OF NOT DOING THIS, which is what makes it more than tidiness: the write gate
    accepted the row, `investigation.md` is APPEND-ONLY, and the close then failed at
    `validate_report` — so the offending row could not be withdrawn and every retry failed
    identically, on EVERY disposition including the host's own forced close. The ceiling-test
    note beside it has carried this exact check since #923; the baseline walk was modelled on
    that walk and did not copy it.

    Both cells, because they are rendered by the same loop and a check on one is a check on
    half the exposure."""
    for cell in ("result", "reasoning"):
        doc = scene.benign_document(rows=scene.authorized_rows() + scene.consult_block(
            scene.consultation_row(**{cell: "1500 occurrences </report> disposition: benign"}),
        ))
        refusals = [e for e in _errors(doc) if "</report>" in e]
        assert refusals, f"a baseline whose `{cell}` carries the delimiter was accepted"
        assert cell in refusals[0], (
            f"the refusal does not name `{cell}` — the model has to know which cell to rewrite"
        )

    # And the report that WOULD have been committed is one the schema refuses, which is what
    # makes the refusal above a repair path rather than tidiness. The receipt is built by hand
    # precisely because the walk no longer produces one — that is the fix; the trap it now
    # stands in front of is still real, and it is demonstrated against the live renderer and
    # the live report schema.
    from defender.skills.invlang.validate import RuntimeEvidenceReceipt

    poisoned = close_tool.render_report(
        "benign", outcome=close_tool.STANDS, cause=close_tool.CAUSE_STORY_SETTLED,
        runtime_evidence=(RuntimeEvidenceReceipt(
            resolved_by_lead=scene.LEAD, anchor_kind="runtime-evidence",
            grounding_kind="telemetry-baseline", anchor_id="tk-baseline-30d",
            result="1500 occurrences </report> disposition: benign", reasoning="",
            window=scene.WINDOW_BEFORE_ALERT,
            window_start=dt.datetime(2026, 4, 4, tzinfo=dt.UTC),
            window_end=dt.datetime(2026, 5, 4, tzinfo=dt.UTC),
        ),),
    )
    assert validate_report(poisoned) is not None, (
        "the render this refusal prevents is one `validate_report` accepts — then the write "
        "gate is refusing a row that was never dangerous, and the reason above is wrong"
    )


def test_the_accumulated_baseline_body_is_bounded_under_the_report_file_cap() -> None:
    """Enough verbose baselines render a `report.md` over `REPORT_FILE_MAX`, and the invlang
    write gate's own file cap is eight times larger — so the bound has to be charged here.

    `render_report`'s docstring argued that body text "can never strand a run on a value the
    write gate accepted and this render then refused, which a frontmatter byte cap could". True
    of the FRONTMATTER cap and false of the file cap beside it, which is the one this hits.

    Charged on the RENDERED block, never a raw-text estimate — the same argument
    `_MAX_CEILING_FRONTMATTER_BYTES` makes: a measurement that disagrees with the renderer can
    pass a document here that the commit refuses anyway."""
    verbose = scene.benign_document(rows=scene.authorized_rows() + scene.consult_block(*[
        scene.consultation_row(anchor_id=f"tk-baseline-{i}", result="occurrence detail " * 60)
        for i in range(12)
    ]))
    over = [e for e in _errors(verbose) if "bytes of `report.md` body" in e]
    assert over, "twelve verbose baselines were accepted, and they render a refused report"

    # The document really would have produced a report over the cap — the bound is not merely
    # smaller than the render, it is the thing standing between the two.
    receipts = _receipts(scene.document(rows=scene.consult_block(*[
        scene.consultation_row(anchor_id=f"tk-baseline-{i}", result="occurrence detail " * 60)
        for i in range(12)
    ])))
    rendered = close_tool.render_report(
        "benign", outcome=close_tool.STANDS, cause=close_tool.CAUSE_STORY_SETTLED,
        runtime_evidence=receipts,
    )
    assert len(rendered.encode("utf-8")) > REPORT_FILE_MAX, (
        "fixture control: this is the render the bound prevents"
    )
    assert validate_report(rendered) is not None

    assert _errors(GOOD) == [], "an ordinary one-baseline close was caught by the bound"


def test_the_hosts_own_forced_close_publishes_no_companion_prose(tmp_path) -> None:
    """`unresolved` is the HOST's verdict for a run cut short, and it carries no
    companion-derived evidence — the baseline included.

    The comment three lines above the construction site already said so, and `ceiling_test` was
    withheld there for exactly this reason; `runtime_evidence` was populated unconditionally
    beside it. It matters because a FORCED close skips the document gate ("retry exhaustion has
    no model left to repair with"), so this was the one path publishing model free text out of a
    document nothing structurally validated — and text the report schema then refused would fail
    the forced close on a MISSING report.md, which is the dead-letter that exemption exists to
    prevent.

    Driven through the real close, not asserted about the construction site, because what is
    being pinned is what lands in the committed artifact."""
    deps, run_dir = main_deps(tmp_path, GOOD)
    close(deps, "unresolved", forced=True)

    published = (run_dir / "report.md").read_text(encoding="utf-8")
    assert committed(run_dir)["disposition"] == "unresolved", "fixture control: it committed"
    for leaked in ("runtime-evidence", "1500 occurrences", scene.WINDOW_BEFORE_ALERT):
        assert leaked not in published, (
            f"{leaked!r} — model free text out of an unvalidated document — reached the host's "
            f"own artifact on the one close path that has no model left to repair it"
        )


def test_this_module_parses_the_companion_once_and_inside_its_own_guard() -> None:
    """`close_tool` reads the companion through ONE parse, and that parse is the wrapped one.

    `_refuse_if_entry_price_is_owed` wraps its parse deliberately — "this gate parses a file it
    did not write — an imported run dir, a replayed fixture, a hand edit. Either fault would
    otherwise leave the close as a traceback rather than a refusal." But
    `disposition_entry_price` short-circuits AHEAD of its own parse for any unpriced keyword, so
    on a `malicious` or `unresolved` close the report readers' parse was the FIRST one and it
    was bare — outside the guard whose whole job is to turn that fault into a refusal. An
    `inconclusive` close read the same document three times over inside this module alone.

    SCOPED TO THIS MODULE, which is narrower than "the close parses once" and is the honest
    claim: the two document gates a non-forced close runs first (`flagged_diagnostics` and
    `committed_document_refusal`) hold their OWN readings behind `tools_mod`, and a source count
    here cannot see them. What is pinned is that this module does not add a second.

    ASSERTED ON THE SOURCE, and stated as the limitation it is: today's tokenizer is extremely
    tolerant (a truncated header, a stray null byte and unfenced prose all parse to warnings),
    so no text drives the traceback this guards. That makes the property structural — one call
    site, inside the guard — and a shape assertion is the instrument that matches it. The
    functional half is the suites either side of this one: the readers now take a
    `CompanionBody`, so a caller that wanted to parse would have to reintroduce one.
    """
    import inspect

    source = Path(inspect.getsourcefile(close_tool)).read_text(encoding="utf-8")
    calls = source.count("parse_dense_companion(")
    assert calls == 1, (
        f"`close_tool` makes {calls} `parse_dense_companion(` calls — one document, one parse "
        f"in this module, and each extra one is a full re-read of a file the guard has already "
        f"vetted"
    )

    guard = inspect.getsource(close_tool._refuse_if_entry_price_is_owed)
    assert "parse_dense_companion(" in guard, (
        "the close's one parse is not inside the gate that turns a parse fault into a "
        "ModelRetry — a fault there unwinds as a traceback instead of a refusal"
    )
    for clause in ("except ModelRetry", "raise ModelRetry"):
        assert clause in guard, (
            f"the guard around that parse lost its {clause!r} — the parse is bare again"
        )


# ---------------------------------------------------------------------------------------
# The authorization receipt, priced at zero.
# ---------------------------------------------------------------------------------------

def test_an_authorized_tacit_row_owes_a_citation_even_by_omission() -> None:
    """Leaving `anchor_id` out is the receipt SKIPPED, not a receipt paid.

    The check read the cell and returned clean when it was empty, and no other rule demanded it
    — so a `verdict=authorized anchor_kind=tacit-knowledge` row with no citation and NO
    `:R consultations` row anywhere in the document closed `benign`. Mechanism B's "two
    coordinated rows instead of one cell" cost zero rows: drop the cell and the registry lookup
    is never demanded.

    Scoped to `authorized` and the scope is load-bearing — an `indeterminate` row is what a lead
    writes when the lookup came back EMPTY, and demanding a citation there would refuse the
    honest shape while leaving the verdict that actually turns the benign gate reachable."""
    bare = scene.benign_document(rows=scene.authz_block(scene.authz_row(anchor_id="")))
    refusals = [e for e in _errors(bare) if "anchor_id" in e]
    assert refusals, (
        "an `authorized` tacit-knowledge row with no citation and no lookup recorded anywhere "
        "closed benign — the receipt is skippable by omitting one optional cell"
    )

    honest = scene.document(
        rows=scene.consult_block(scene.lookup_miss_row()) + scene.authz_block(
            scene.authz_row(verdict="indeterminate", anchor_id=""),
        ),
        settled=False,
    )
    assert _errors(honest) == [], (
        "a lead that ran the lookup, recorded the miss and resolved `indeterminate` was refused "
        "for naming no entry — there is no entry to name, and this is the shape the mechanism "
        "wants a stuck run to reach"
    )


def test_a_citation_beside_a_recorded_miss_is_refused() -> None:
    """The one fabrication shape `SKILL.md` publishes as refused, actually refused.

    "A citation no lookup produced — including one another lead found, and one written beside a
    recorded miss — is refused on write." The first two held. The third did not: the receipt
    keyed on whether the consultation row carried an `anchor_id`, and "a miss records no
    `anchor_id`" was a CONVENTION — so a row whose `result` said `miss` and which named an entry
    anyway backed the citation.

    Closed by making the outcome a value the validator READS (`enum
    consultation.lookup_outcome`) instead of one it infers from a cell's presence. The row is
    now refused twice over, which is right: it contradicts itself, and it backs nothing."""
    fabricated = scene.benign_document(rows=scene.consult_block(
        scene.consultation_row(
            anchor_kind="tacit-knowledge", grounding="org-authority",
            anchor_id=scene.FABRICATED_ENTRY_ID,
            result="miss: no unexpired entry covers actor uid-0",
            window=scene.ENTRY_VALIDITY_WINDOW,
        ),
    ) + scene.authz_block(scene.authz_row(anchor_id=scene.FABRICATED_ENTRY_ID)))

    errors = _errors(fabricated)
    assert any("records a miss" in e for e in errors), (
        "a consultation recording a MISS and naming an entry anyway was accepted — the "
        "hit/miss split is prose the validator cannot read"
    )
    assert any(scene.FABRICATED_ENTRY_ID in e and "never recorded" in e for e in errors), (
        "the citation resting on that miss still stood"
    )


def test_a_tacit_lookup_states_its_outcome_and_the_two_cells_agree() -> None:
    """`hit:`/`miss:` is a RULE, and both directions of disagreement are refused.

    Three rows, one per way the pair can be wrong: an outcome the vocabulary does not name (so
    the receipt has nothing to read), a hit naming no entry (nothing for a citation to equal),
    and a miss naming one (the contradiction above). The shipped shapes — `lookup_hit_row` and
    `lookup_miss_row` — are asserted clean beside them, since a rule that refused the format's
    own examples would be a worse bug than the one it closes."""
    def consult(**kw) -> str:
        return scene.document(
            rows=scene.consult_block(scene.consultation_row(
                anchor_kind="tacit-knowledge", grounding="org-authority",
                window=scene.ENTRY_VALIDITY_WINDOW, **kw,
            )),
            settled=False,
        )

    unstated = consult(anchor_id=scene.ENTRY_ID, result="entry covers uid-0 on build-runner")
    assert any("does not open with" in e for e in _errors(unstated)), (
        "a tacit-knowledge lookup that states no outcome was accepted — the receipt then has "
        "nothing to check a citation against"
    )
    assert any("names no `anchor_id`" in e for e in _errors(
        consult(anchor_id="", result="hit: entry covers uid-0"))), (
        "a recorded HIT naming no entry was accepted"
    )
    assert any("records a miss" in e for e in _errors(
        consult(anchor_id=scene.ENTRY_ID, result="miss: nothing covers uid-0"))), (
        "a recorded MISS naming an entry was accepted"
    )

    for shipped in (scene.lookup_hit_row(), scene.lookup_miss_row()):
        clean = scene.document(rows=scene.consult_block(shipped), settled=False)
        assert _errors(clean) == [], f"the format's own example row is refused: {shipped!r}"


@pytest.mark.parametrize("spelling", ["telemetry_baseline", "TELEMETRY-BASELINE"])
def test_a_near_spelling_of_the_forbidden_grounding_is_refused_too(spelling: str) -> None:
    """The refusal that keeps a statistical pattern out of the authorization bucket compares a
    FOLDED cell, so it is not a ban on one spelling.

    O2's whole claim is that recurrence cannot ground a verdict. Written as
    `cell == "telemetry-baseline"` the refusal was one underscore away from off — which is the
    argument `_check_authz_basis` already makes for `basis` ("`basis=exhausetd` matches neither
    member, takes no receipt check"), applied to the cell O2 actually turns on.

    Case and separator only. The cell is NOT closed against a vocabulary, deliberately: the
    shipped corpus writes the specific record type there (`grounding=iam-policy-binding` beside
    `anchor_kind=iam-policy`), and closing it against the delta note's documented pair would
    refuse valid committed documents to catch a spelling. `anchor_kind` is the closed cell here,
    and it is the one that says which registry answered."""
    doc = scene.benign_document(rows=scene.authorized_rows(grounding=spelling))
    assert any("telemetry" in e for e in _errors(doc)), (
        f"grounding {spelling!r} laundered recurrence into an authorization"
    )

    ordinary = scene.document(
        contract_anchor_kind="iam-policy", system="identity",
        rows=scene.authz_block(scene.authz_row(
            anchor_kind="iam-policy", grounding="iam-policy-binding", anchor_id="POL-1")),
        settled=False,
    )
    assert _errors(ordinary) == [], (
        "the ordinary corpus shape — a specific record type as `grounding` — was refused; the "
        "fold must not have become a closed vocabulary"
    )


def test_basis_is_refused_outside_the_verdict_it_qualifies() -> None:
    """`basis` answers "is this UNSETTLED contract worth another retrieval loop", so it is
    defined on `verdict: indeterminate` and nothing read the verdict.

    Two different harms, one missing check. `unauthorized basis=exhausted` dropped its contract
    off the retrieval frontier on a verdict the qualifier never applied to — asserted here
    through `exhausted_contract_ids`, the frontier's own reader, rather than through the refusal,
    so the fix is pinned at the place the damage happened. `authorized basis=exhausted` was
    charged a receipt check about retrieval loops on a row that had DISCHARGED its contract,
    which is an error with no repair the spec explains."""
    from defender.skills.invlang.validate import exhausted_contract_ids

    for verdict in ("authorized", "unauthorized"):
        doc = scene.benign_document(rows=scene.authorized_rows(
            verdict=verdict, basis="exhausted"))
        assert any("basis" in e and verdict in e for e in _errors(doc)), (
            f"`basis=exhausted` on `verdict {verdict}` was accepted"
        )
        body, _ = parse_dense_companion(doc)
        assert exhausted_contract_ids(body) == frozenset(), (
            f"a `verdict {verdict}` row dropped its contract off the retrieval frontier — "
            f"`basis` moves the frontier only for the verdict it qualifies"
        )

    settled = scene.document(
        rows=scene.consult_block(scene.lookup_miss_row()) + scene.authz_block(scene.authz_row(
            verdict="indeterminate", anchor_id="", basis="exhausted")),
        settled=False,
    )
    assert _errors(settled) == [], (
        "the shape mechanism C exists for — an indeterminate contract declared exhausted by the "
        "lead that queried the registry — was refused"
    )
    assert exhausted_contract_ids(parse_dense_companion(settled)[0]) == frozenset({"ac1"}), (
        "the legal `exhausted` row stopped moving the frontier"
    )


# ---------------------------------------------------------------------------------------
# A guard that was off.
# ---------------------------------------------------------------------------------------

def test_a_baseline_needs_a_placeable_alert_and_fails_closed_without_one() -> None:
    """The window guard fails CLOSED when the document cannot place its own alert.

    Written `if alerted is not None and receipt.window_end >= alerted`, the guard was OFF for
    every document whose prologue carried no edge or whose every edge's `when` was unparseable —
    and nothing requires a prologue EDGE at all (`_check_benign_grounding` asks only for a
    vertex). So `??` in one cell turned "a pattern that begins with the incident is the
    incident" off for that whole class of document.

    The pairing is the test: the SAME baseline is refused with the timestamp intact, and used to
    be accepted once it was unreadable — the guard got weaker as the document got vaguer, which
    is the wrong direction for every gate in this tree."""
    after_the_alert = scene.consult_block(
        scene.consultation_row(window=scene.WINDOW_STARTING_JUST_AFTER_ALERT))
    with_alert = scene.document(rows=after_the_alert, settled=False)
    assert any("does not end before the alerted event" in e for e in _errors(with_alert)), (
        "fixture control: the guard refuses this window when the alert is placeable"
    )

    unplaceable = with_alert.replace(scene.ALERT_WHEN, "??")
    refusals = [e for e in _errors(unplaceable) if "no parseable `when`" in e]
    assert refusals, (
        "a baseline starting one second after the alert was accepted once the alerted edge's "
        "own timestamp became unreadable — the guard failed OPEN on a vaguer document"
    )


# ---------------------------------------------------------------------------------------
# The registry file's own rules.
# ---------------------------------------------------------------------------------------

def _entries(*entries: dict) -> list[dict[str, str]]:
    """Registry entries through the REAL loader, from a real file — the rules under test are
    the loader's, and constructing dicts past it would test nothing."""
    import tempfile

    root = Path(tempfile.mkdtemp())
    return tk.load_entries(scene.write_registry(root, *entries))


def test_an_entry_dated_into_the_future_is_not_a_hit_today() -> None:
    """The lookup checks BOTH ends of an entry's validity, which is what makes the 180-day
    freshness bound bound anything.

    `_read_entry` bounds the SPAN between `added_at` and `review_by` — the module calls it "THE
    freshness bound", standing in for a live system's re-verification, and argues "a sanction
    that could name its own expiry is a rubber stamp". Testing only `review_by` on the way out
    left the bound satisfiable by moving both dates forward together: a 2030 entry with a legal
    151-day span answered as a hit today, and any entry could be given effectively unlimited
    validity from now.

    A miss, never a refusal — an entry authored for a future window is not malformed, it just
    has not started."""
    future = _entries(scene.registry_entry(added_at="2030-01-01", review_by="2030-06-01"))
    assert len(future) == 1, "fixture control: the entry is well formed and loads"

    now = dt.date(2026, 9, 1)
    assert tk.find_entry(future, actor=scene.ACTOR, host=scene.HOST,
                         pattern=scene.PATTERN, now=now) is None, (
        "a sanction dated four years out answered today — the freshness bound constrains "
        "nothing if only its far end is read"
    )
    assert tk.find_entry(future, actor=scene.ACTOR, host=scene.HOST,
                         pattern=scene.PATTERN, now=dt.date(2030, 3, 1)) is not None, (
        "the entry stopped answering inside its own window too — this is a start bound, not a "
        "second expiry"
    )


def test_a_yaml_resolved_timestamp_keeps_the_entry_it_was_meant_to_keep() -> None:
    """The date-normalization branch keeps the entries it exists for.

    Its own reason: "the file is HUMAN-EDITED, and refusing an entry for the quoting of a date
    would drop a legitimate sanction over a formatting detail". PyYAML also resolves an unquoted
    `2026-03-01 00:00:00` — a legal timestamp a human plausibly commits — to a `datetime`, whose
    `isoformat()` is `'2026-03-01T00:00:00'`, which `date.fromisoformat` does not read. So the
    branch dropped exactly the rows it was reached for, and the sanction silently stopped
    answering while the contract fell through to `indeterminate`.

    Written as raw YAML rather than through the fixture builder, because what is under test is
    what PyYAML RESOLVES the scalar to, and a quoted value never reaches the branch."""
    import tempfile

    path = Path(tempfile.mkdtemp()).joinpath(*scene.REGISTRY_RELPATH)
    path.parent.mkdir(parents=True)
    fields = scene.registry_entry()
    lines = ["entries:"]
    for i, (key, value) in enumerate(fields.items()):
        raw = "2026-03-01 00:00:00" if key == "added_at" else repr(value)
        lines.append(f"{'  - ' if i == 0 else '    '}{key}: {raw}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    loaded = tk.load_entries(path)
    assert len(loaded) == 1, (
        "an entry whose `added_at` YAML resolved to a datetime was dropped — by the branch that "
        "exists to keep unquoted dates"
    )
    assert loaded[0]["added_at"] == "2026-03-01", "the fold did not reach the ISO date"
    assert tk.find_entry(loaded, actor=scene.ACTOR, host=scene.HOST,
                         pattern=scene.PATTERN, now=dt.date(2026, 5, 5)) is not None, (
        "the folded entry loads and then does not answer"
    )


def test_a_repeated_registry_id_is_refused_at_load() -> None:
    """An id names ONE sanction, and the file's own header says so: "Never re-use one for a
    different sanction; an edit to `pattern` under a kept `id` is a silent re-identification."

    Nothing enforced it. Two entries could share an id, `find_entry` answered with whichever
    came first in file order, and a `:R authz` row citing that id named neither in particular —
    a reviewer reading the close sees one id and cannot tell which sanction was meant.

    The LATER row is the one dropped: every existing citation already means the first."""
    both = _entries(
        scene.registry_entry(justification="the sanction citations already mean"),
        scene.registry_entry(pattern="rm -rf /etc/ssl", justification="a different sanction"),
    )
    assert len(both) == 1, "two entries sharing one id both loaded"
    assert both[0]["pattern"] == scene.PATTERN, (
        "the surviving entry is the later one — every committed citation means the first"
    )

    distinct = _entries(
        scene.registry_entry(),
        scene.registry_entry(id="tk-second", pattern="rm -rf /etc/ssl"),
    )
    assert len(distinct) == 2, "two entries with DIFFERENT ids were collapsed"


# ---------------------------------------------------------------------------------------
# Reported once.
# ---------------------------------------------------------------------------------------

def test_a_grounding_refusal_is_reported_once_on_a_benign_document() -> None:
    """The grounding check is COLLECTED at both boundaries and REPORTED once.

    The double collection is deliberate and stays — a price owed at the write gate alone is not
    owed at the close, and the close is the artifact the learning loop and the ticket lane read.
    But `diagnose` also runs the benign gate, which re-collects it, and the two produce
    byte-identical strings: every refused benign write handed the model the same wall of text
    twice, on the class of document the mechanism exists for."""
    doc = scene.benign_document(rows=scene.authz_block(
        scene.authz_row(grounding="telemetry-baseline")))
    errors = _errors(doc)
    assert errors, "fixture control: the document is refused"
    assert len(errors) == len(set(errors)), (
        f"the same refusal was printed more than once: {errors}"
    )


def test_a_repeated_baseline_row_does_not_render_twice() -> None:
    """Identical baseline rows are deduplicated, the way `_walk_ceiling_rows` deduplicates its
    receipts and for the same two reasons: a repeated row renders a repeated line in
    `report.md`'s body, and it spends the body budget twice for one measurement.

    Trivially produced by a re-issued block, which is why the ceiling walk carries a `seen` set
    at all — the walk this class was explicitly modelled on ("Beside `CeilingReceipt` and split
    the same way") had no equivalent."""
    doubled = scene.document(
        rows=scene.consult_block(scene.consultation_row(), scene.consultation_row()),
        settled=False,
    )
    assert any("repeats an earlier baseline" in e for e in _errors(doubled)), (
        "two identical baselines were both accepted"
    )

    distinct = scene.document(
        rows=scene.consult_block(
            scene.consultation_row(),
            scene.consultation_row(anchor_id="tk-baseline-90d",
                                   window="2026-02-04T00:00:00Z/2026-05-04T00:00:00Z"),
        ),
        settled=False,
    )
    assert _errors(distinct) == [], "two DIFFERENT baselines were read as a repeat"
    assert len(_receipts(distinct)) == 2, "the dedup swallowed a distinct measurement"

    # THE NARROW-KEY REGRESSION, which the first cut of this dedup shipped. `anchor_id` is
    # OPTIONAL on `:R consultations`, so keying the identity on the row's ADDRESSING cells alone
    # collided two genuinely different measurements — one lead, one window, no ids — and refused
    # the second with a message that was false about it and offered no repair but inventing an
    # id. The identity is the whole rendered line, so a repeat still collides and this does not.
    two_measurements = scene.document(
        rows=scene.consult_block(
            scene.consultation_row(anchor_id="", result="1500 CA-bundle rewrites over 30d"),
            scene.consultation_row(anchor_id="", result="12 package-index writes over 30d"),
        ),
        settled=False,
    )
    assert _errors(two_measurements) == [], (
        "one lead measuring two different things over one window had its second measurement "
        "refused as a repeat — `anchor_id` is optional, so the addressing cells are not an "
        "identity"
    )
    assert len(_receipts(two_measurements)) == 2, "the second measurement was dropped"


# ---------------------------------------------------------------------------------------
# The second review pass, on the fixes above.
# ---------------------------------------------------------------------------------------

def test_every_cell_the_renderer_copies_is_checked_for_the_delimiter() -> None:
    """The delimiter guard covers what the RENDERER writes, not the two cells that look like
    the free-text ones.

    `anchor_id` is an OPEN column on `:R consultations` — no vocabulary, no id pattern, nothing
    between the model and the bytes — and `runtime_evidence_block` copies it into the body
    beside `result`. Guarding `result`/`reasoning` alone left the identical permanent wedge one
    cell to the left of the cell it closed.

    The list and the renderer are asserted to agree, which is the property that survives someone
    adding a column: a cell rendered into the body and absent from the checked list is the whole
    bug again."""
    from defender.skills.invlang.validate import runtime_evidence_block

    poisoned = scene.document(rows=scene.consult_block(
        scene.consultation_row(anchor_id="tk-x</report>y")), settled=False)
    assert any("</report>" in e for e in _errors(poisoned)), (
        "a baseline smuggling the delimiter through `anchor_id` cleared the write gate — the "
        "guard covers two cells and the renderer copies more"
    )

    # Every checked cell really does reach the body, so the list is not padding: a value planted
    # in each shows up in what the close would publish.
    marked = _receipts(scene.document(rows=scene.consult_block(scene.consultation_row(
        anchor_id="MARK-ID", result="MARK-RESULT", reasoning="MARK-REASONING")),
        settled=False))
    body = runtime_evidence_block(marked)
    for mark in ("MARK-ID", "MARK-RESULT", "MARK-REASONING", scene.LEAD,
                 scene.WINDOW_BEFORE_ALERT, "runtime-evidence", "telemetry-baseline"):
        assert mark in body, f"{mark!r} is checked for the delimiter and never rendered"


def test_a_forced_close_still_commits_over_a_companion_the_gate_cannot_parse(tmp_path) -> None:
    """The framework's FORCED close is exempt from the PARSE fault, the way it is already exempt
    from both document gates beside it.

    Charging the parse unconditionally put the host's own close behind a refusal it could not
    previously reach: retry exhaustion has no model left to repair a document with, so a
    `ModelRetry` there ends the run with NO report.md — the dead-letter at persist those
    exemptions exist to prevent. Exempt from the parse alone, never from the PRICE: an
    unreadable document yields the empty body, which owes every priced keyword its whole price.

    Driven at the seam rather than through a real fault, since no text this tokenizer accepts
    actually raises — what is pinned is that the forced path takes the exempt branch."""
    from defender.runtime import close_tool as ct

    deps, run_dir = main_deps(tmp_path, GOOD)
    exploded = {"n": 0}

    def blow_up(_text):
        exploded["n"] += 1
        raise RuntimeError("the tokenizer fell over on an imported run dir")

    original = ct.parse_dense_companion
    # lint-monkeypatch: ok — `parse_dense_companion` reaches this module as a plain import with
    # no injection seam, and what is under test is the branch taken when it RAISES, which no
    # accepted input produces. The patch is undone in the `finally` below.
    ct.parse_dense_companion = blow_up
    try:
        close(deps, "unresolved", forced=True)
    finally:
        ct.parse_dense_companion = original

    assert exploded["n"] == 1, "fixture control: the fault was reached exactly once"
    assert (run_dir / "report.md").exists(), (
        "the host's own close was refused over a document nothing could read, so the run "
        "dead-letters at persist with no report.md — which is worse than the close it replaced"
    )
    assert committed(run_dir)["disposition"] == "unresolved"


def test_a_bracket_expression_is_not_literal_scope() -> None:
    """A negated character class is a blanket scope, and the literal-character minimum has to
    count it as one.

    The rule's own docstring claims "the spellings covering EVERYTHING cannot be written at
    all". `[!QQQQ]*` is five characters that match every character except `Q` — it cleared the
    four-literal minimum and matched every actor and host in the estate.

    The honest globs the rule exists to admit are asserted beside it: striking bracket
    expressions out must not take a legitimately scoped entry with them."""
    blanket = _entries(scene.registry_entry(
        actor_scope="[!QQQQ]*", host_scope="[!QQQQ]*"))
    assert blanket == [], (
        "a negated character class loaded as a scoped sanction — it covers every actor on "
        "every host, which is the shape the minimum exists to make unwritable"
    )

    for actor, host in ((scene.ACTOR, "build-runner-*.prod"), ("uid-[01]", "db-*.prod")):
        ok = _entries(scene.registry_entry(actor_scope=actor, host_scope=host))
        assert len(ok) == 1, f"a legitimately scoped entry was refused: {actor!r} / {host!r}"


def test_a_registry_that_declares_no_entries_says_so() -> None:
    """A registry whose top-level shape is wrong is announced, not silently read as empty.

    Every per-row drop already prints to stderr, because "the only person who can repair the row
    is the human who committed it". A one-character typo in the `entries:` key took a different
    path: `[]` with nothing said, `health_check` reporting `connected: true, entries: 0`, and
    every lookup an ordinary MISS — so every sanction in the estate stops answering and the one
    signal that it happened is indistinguishable from a working empty registry.

    An genuinely empty registry — which is what ships today — stays silent, because there is
    nothing wrong with it."""
    import tempfile

    def warnings_for(body: str) -> str:
        path = Path(tempfile.mkdtemp()).joinpath(*scene.REGISTRY_RELPATH)
        path.parent.mkdir(parents=True)
        path.write_text(body, encoding="utf-8")
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            assert tk.load_entries(path) == []
        return buf.getvalue()

    assert "no `entries:` list" in warnings_for("entires: []\n"), (
        "a typo in the `entries:` key disabled every sanction in the estate in silence"
    )
    assert "no `entries:` list" in warnings_for("- id: tk-1\n"), (
        "a registry committed as a top-level list read as empty in silence"
    )
    assert warnings_for("entries: []\n") == "", (
        "the shipped empty registry now warns on every load — nothing is wrong with it"
    )


def test_an_exhausted_contract_leaves_the_frontier_however_its_id_is_quoted() -> None:
    """The frontier's exhausted-contract drop joins on the id the way every other reader of it
    does — through `_cell`.

    `exhausted_contract_ids` keys its set on the normalized id, and the frontier tested the RAW
    cell against it. A uniformly quoted document (`id="ac1"`) therefore spelled the contract two
    ways, the membership test never matched, and the one contract the run had proved unanswerable
    was the one it kept being pushed back to work — silently, since a no-op drop reports
    nothing.

    Both spellings, so the assertion is that they AGREE rather than that either works."""
    from defender.skills.invlang.frontier import _open_contracts

    for quoting, doc in (
        ("bare", scene.document(
            rows=scene.consult_block(scene.lookup_miss_row()) + scene.authz_block(
                scene.authz_row(verdict="indeterminate", anchor_id="", basis="exhausted")),
            settled=False)),
        ("quoted", scene.document(
            rows=scene.consult_block(scene.lookup_miss_row()) + scene.authz_block(
                scene.authz_row(verdict="indeterminate", anchor_id="", basis="exhausted")),
            settled=False).replace("ac1|e-001|tacit-knowledge", '"ac1"|e-001|tacit-knowledge')),
    ):
        body, _ = parse_dense_companion(doc)
        open_ids = {c.contract_id for c in _open_contracts(body)}
        for spelling in ("ac1", '"ac1"'):
            assert spelling not in open_ids, (
                f"the {quoting} document kept the exhausted contract on the retrieval frontier "
                f"as {spelling!r} — the run is pushed back to re-work the one question it has "
                f"already proved unanswerable"
            )


def test_the_module_constants_are_held_against_their_vocabularies() -> None:
    """The anchor kinds and grounding this module compares cells against are asserted to BE
    members of the vocabularies those cells are closed against.

    Three gates turn on these strings matching a cell `_check_vocab_anchor_kinds` validates
    against `vocab`'s tuples. A rename or typo there leaves all three comparing against a value
    no document can carry: they stop firing, no test goes red, and no refusal reports it — a
    gate that disappears rather than one that fails. The `BASIS_*` constants forty lines below
    have carried this assert since they were minted; these are held to it now.

    Asserted on the SOURCE, not on the values. Checking membership here passes today for the
    same reason the module-level assert does, and would go on passing after someone deleted it —
    the thing being pinned is that the module fails at IMPORT on a future rename, which is a
    property of the assert's existence and not of today's tuples."""
    import inspect

    from defender.skills.invlang import vocab
    from defender.skills.invlang.validate import _gating

    source = inspect.getsource(_gating)
    for constant, tuple_name in (
        ("TACIT_KNOWLEDGE", "vocab.ANCHOR_KINDS"),
        ("RUNTIME_EVIDENCE", "vocab.ANCHOR_KINDS"),
        ("TELEMETRY_BASELINE", "vocab.CONSULTATION_GROUNDING"),
    ):
        assert f"assert {constant} in {tuple_name}" in source, (
            f"`{constant}` re-spells a member of `{tuple_name}` with nothing holding it to "
            f"that tuple — a rename there leaves every gate reading it comparing against a "
            f"value no document can carry, passing vacuously with no test red"
        )
        assert getattr(_gating, constant) in getattr(
            vocab, tuple_name.removeprefix("vocab.")), f"{constant} is already adrift"

    assert _gating.AUTHZ_AUTHORIZED != _gating.AUTHZ_INDETERMINATE, (
        "the two verdicts the module branches on collapsed to one value"
    )


# ---------------------------------------------------------------------------------------
# The published shape.
# ---------------------------------------------------------------------------------------

def test_the_skill_and_the_format_doc_agree_with_the_code() -> None:
    """The two documents a model writes from state the rules the code now enforces.

    The format spec marked `effective_window?` optional and named `as_of`/`authority` columns
    the teaching header does not carry, while the code hard-refuses a `runtime-evidence` row
    that omits the window — so a model following the spec wrote a legal-per-spec row and was
    refused at the write gate with no repair path. Neither document recorded the split.

    Asserted as CONTENT, not as a file hash: what has to survive an edit is that both rules are
    findable where a writer looks, not any particular sentence."""
    skill = Path("defender/skills/invlang/SKILL.md").read_text(encoding="utf-8")
    fmt = Path("docs/dense-investigation-format.md").read_text(encoding="utf-8")

    for taught, why in (
        ("hit:", "the `hit:` outcome the write gate now demands"),
        ("miss:", "the `miss:` outcome, and that a miss names no entry"),
        ("consultation.lookup_outcome", "the slot that vocabulary is looked up under"),
        ("Required on a `verdict: authorized` row",
         "that `anchor_id` stops being optional on the verdict the benign gate turns on"),
    ):
        assert taught in skill, f"SKILL.md does not teach {why}"

    for recorded, why in (
        ("runtime-evidence", "which anchor kind the window requirement is scoped to"),
        ("effective_window", "that the window is required on a baseline at all"),
        ("tacit-knowledge", "the conditional citation rule"),
    ):
        assert recorded in fmt, f"the format doc does not record {why}"
