"""#961 / #964 — every writer of `investigation.md` meets the schema, and the close is one of
them.

The two issues are one defect seen from two sides. `_artifact_schema` owns what a well-formed
artifact is; `permission.decide_write` applies it to every write a MODEL makes. That made a
sentence true and load-bearing — *a committed investigation parses* — and #954's design rests
on it explicitly. It was only ever true of the verbs the agent writes through:

  #964  the harness seeds lead-0's declaring `:L findings` row before MAIN's first turn by
        concatenating text and calling `write_guarded` directly. No tool call, no gate, no
        schema. Harmless in fact — one block, one row — and load-bearing anyway, because the
        invariant everything downstream inherits is about the ARTIFACT, not about the verbs.
  #961  `close_investigation` is the verb that PUBLISHES: it commits the report the learning
        loop trains on and hands the parsed companion to the review gate. It validated the
        report it wrote and never the companion it published, so a document carrying an
        error-severity finding closed successfully.

A third site turned up when `lint_ungated_artifact_write` first ran: the turn-N branch seeds a
sibling run's whole document from a fence-boundary prefix of the source, and a valid source
does NOT guarantee a valid prefix. It is tested here with the other two because it is the same
defect, not a neighbour of it.

What this suite holds that the lint cannot: the lint asks whether a schema call sits in the
frame, which is a syntactic question. Whether the close actually REFUSES, and whether a
refusing seed actually declines to write, are behavioural — and #961's half is not a write bug
at all, so no write-shaped gate could have caught it.
"""

from __future__ import annotations

import pytest

from defender.tests._invlang_warn_836 import (
    CONCLUDE_BENIGN,
    PROLOGUE,
    attr_block,
    main_deps,
    seed_investigation,
)

#: A document whose ONLY defect is error-severity: two rows refining one slot to two different
#: values inside a single block (#962). Error severity is the point — a WARN-family row is the
#: repair window's business and is refused by a different gate one line up, so a warn document
#: could not tell the two apart.
_ERROR_DOC = PROLOGUE + attr_block(
    "l-001|v-001|class|bastion",
    "l-001|v-001|class|workstation",
)

#: The same shape with the collision removed — every other property held constant, so a test
#: that passes on one and fails on the other is measuring the defect and not the fixture.
_CLEAN_DOC = PROLOGUE + attr_block("l-001|v-001|class|bastion")


def _pay_inconclusive_price(deps) -> None:
    """#923: `inconclusive` now carries its own entry price (a `ceiling_test` row naming a
    source or capability) — unrelated to anything this module tests, which is about
    #961/#964's gate on the write path itself, not about the price. Append a paying row
    directly to the run's `investigation.md` bytes (never through a tool, so it cannot itself
    trip the very gates this suite is testing) rather than editing every fixture document."""
    from pathlib import Path

    path = Path(deps.run_dir) / "investigation.md"
    existing = path.read_bytes() if path.exists() else b""
    addition = (
        b'\n```invlang\n:T conclude\nceiling_test  state=nothing-to-try cap=telemetry.collect note=process telemetry not retrieved\n```\n'
    )
    path.write_bytes(existing + addition)


def _close(deps, disposition, **kw):
    from defender.runtime import challenge_gate
    from defender.runtime.close_tool import close_investigation
    from defender.tests import _review_bundle

    if disposition == "inconclusive" and not kw.get("forced"):
        _pay_inconclusive_price(deps)
    return close_investigation(
        deps, disposition,
        stages=_review_bundle.bundle(composer=_review_bundle.composer_reply("holds")),
        bounds=challenge_gate.default_bounds(),
        **kw,
    )


# #961 — the close is a gated write path

def test_a_close_over_an_error_severity_document_commits_nothing(tmp_path):
    """THE defect. A document carrying an error-severity finding used to close successfully and
    commit `report.md` untouched.

    Asserted on the ARTIFACT, not only on the refusal: what #961 is about is a disposition
    reaching disk, so a test that only caught the exception would still pass against an
    implementation that raised after committing."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, _ERROR_DOC)

    with pytest.raises(ModelRetry) as exc:
        _close(deps, "inconclusive")

    assert "close blocked" in str(exc.value)
    assert not (run / "report.md").exists(), "the close committed a report anyway"


def test_the_same_document_without_the_defect_closes(tmp_path):
    """POSITIVE CONTROL, and the one that keeps the test above honest: the gate refuses the
    defect rather than refusing everything. `inconclusive` bypasses the review gate, so what is
    measured is the document check and nothing behind it."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, _CLEAN_DOC + CONCLUDE_BENIGN)

    _close(deps, "inconclusive")

    assert (run / "report.md").is_file()


def test_the_close_refusal_names_the_rows_and_the_repair_verb(tmp_path):
    """The refusal is the model's only channel: it is told its own context IS the file, so a
    close it cannot act on is a close it will retry unchanged until the budget runs out.

    Three things have to be in it — that nothing was committed, which rows are wrong, and the
    verb that reaches them."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, _ERROR_DOC)

    with pytest.raises(ModelRetry) as exc:
        _close(deps, "inconclusive")
    message = str(exc.value)

    assert "refined twice in this write" in message
    assert "fix_row" in message
    assert "publishes" in message, "say why a close is the moment this is checked"


def test_the_frameworks_forced_close_is_exempt(tmp_path):
    """The exemption the flagged-row gate already carries, for its own reason: retry
    exhaustion has no model left to repair with, so gating the FORCED close would dead-letter
    the run at persist for a MISSING report.md.

    A malformed companion is worse to publish than a well-formed one; a run with no
    disposition at all is worse than either.

    #923: the framework's forced close commits `unresolved` — the host's own verdict — not
    `inconclusive`, which now carries an entry price a forced caller (no model left to pay it
    with) is refused for supplying at all (`close_tool.py`'s host-boundary check, fork J31)."""
    deps, run = main_deps(tmp_path)
    seed_investigation(run, _ERROR_DOC)

    from defender._vocab import HOST_ONLY_DISPOSITION
    from defender.runtime import challenge_gate
    from defender.runtime.close_tool import _close_investigation_async
    from defender.tests import _review_bundle
    import asyncio

    asyncio.run(_close_investigation_async(
        deps, HOST_ONLY_DISPOSITION,
        stages=_review_bundle.bundle(composer=_review_bundle.composer_reply("holds")),
        bounds=challenge_gate.default_bounds(),
        forced=True,
    ))

    assert (run / "report.md").is_file(), "the framework must always be able to close"


def test_an_undecodable_document_still_closes(tmp_path):
    """H7's condition, and the line the close's structure check has to keep straight.

    A document that DECODES and does not validate is refused. A document whose BYTES do not
    decode is a different thing — nothing can be derived from it at all — and #836 settled
    that one: fail OPEN, because turning an unrelated read fault into an unclosable run is the
    wedge that mechanism exists to remove.

    Reading leniently would collapse the two and answer the second with the first: the
    replacement character lands mid-header and the validator reports a broken block nobody
    wrote."""
    deps, run = main_deps(tmp_path)
    (run / "investigation.md").write_bytes(b"```invlang\n:R attr\xff\xfe updates\n```\n")

    _close(deps, "inconclusive")

    assert (run / "report.md").is_file()


def test_the_price_gate_still_answers_first_for_what_it_prices(tmp_path):
    """ORDERING, which is load-bearing rather than cosmetic.

    The structure check runs the WHOLE validator, and some of its rules are conditioned on the
    disposition the DOCUMENT concludes. Ahead of the entry-price gate it would answer a close
    of `false-positive` with a complaint about the `benign` the companion happens to declare —
    true, but about a keyword the model is no longer claiming, and it would shadow the specific
    obligation the model can actually discharge.
    """
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, "```invlang\n:T conclude\ndisposition            benign\n```\n")

    with pytest.raises(ModelRetry) as exc:
        _close(deps, "false-positive")

    assert "entity_check" in str(exc.value), (
        "the disposition-specific obligation must not be shadowed by the document check"
    )


def test_a_committed_unfenced_header_does_not_make_the_run_unclosable(tmp_path):
    """The close reads the document as ITS OWN BASELINE, not against no baseline at all.

    Every check keyed on `current` asks what THIS WRITE INTRODUCES, and a close introduces
    nothing. `_check_surface` subtracts the baseline's orphaned headers from the proposal's, so
    with `None` every unfenced block header already committed reads as newly added — a family
    the write gate deliberately scopes to what a write ADDS, precisely because append-only and
    a `:R`-only `fix_row` leave those bytes unreachable forever. Read that way the close would
    refuse, for the life of the run, a document every write gate had accepted, with no repair
    the model could make.
    """
    deps, run = main_deps(tmp_path)
    seed_investigation(
        run,
        PROLOGUE + "\n## PLAN\n\n:H hypothesize.hypotheses [id|claim]\n",
    )

    _close(deps, "inconclusive")

    assert (run / "report.md").is_file()


def test_an_error_severity_row_is_repairable_rather_than_a_dead_end(tmp_path):
    """The close names `fix_row`, so `fix_row` has to be able to reach what the close refused.

    The repair WINDOW is warn-severity — the rows whose presence blocks an append. The repair
    SET is what the verb may touch, and an error-severity row belongs in it: it blocks every
    write just as hard, but was not in the window, so `fix_row` refused it and was not even
    offered. That left no legal move — close refuses and names `fix_row`, `fix_row` says
    nothing is flagged, `append_block` refuses the same bytes — and the model would spend its
    whole retry budget before the framework force-closed `inconclusive`, discarding the
    disposition the run had actually reached.

    Reachable because a document valid when written can stop being valid later: a rule that
    ships after the bytes landed judges what is already committed, and #962 is exactly one.
    """
    from defender.runtime.tools import (
        _tool_fix_row, committed_document_refusal, flagged_diagnostics,
        repairable_diagnostics,
    )

    deps, run = main_deps(tmp_path)
    seed_investigation(run, _ERROR_DOC)

    assert flagged_diagnostics(deps) == (), "the warn window is empty — that was the trap"
    assert [d.locus.row_text for d in repairable_diagnostics(deps)] == [
        "l-001|v-001|class|workstation"
    ]
    assert committed_document_refusal(deps) is not None

    _tool_fix_row(deps, "l-001|v-001|class|workstation", "")

    assert committed_document_refusal(deps) is None
    _close(deps, "inconclusive")
    assert (run / "report.md").is_file()


def test_the_repair_set_is_widened_by_severity_and_not_by_scope(tmp_path):
    """An error-severity row OUTSIDE `:R attr_updates` stays out, and that is what keeps the
    widening safe.

    The warn window walks `:R attr_updates` and nothing else, so every guard downstream of it
    inherited the scope for free — `_attr_block_columns` answers `None` for a row no such block
    holds, and `_tool_fix_row` reads that `None` as "skip the shape guard", the guard that
    makes "no verb mutates or removes a committed `:V`/`:E` record" true by construction.
    Parse diagnostics carry a locus and a real row for EVERY block, so admitting them by
    severity alone would put a committed `:V` declaration in the repair set with nothing in
    front of it: this `new_row` spans two lines and would forge a whole second vertex.

    Both halves are asserted, because either alone leaves the hole open: the row is not in the
    set, and the verb refuses it if the model quotes it anyway.
    """
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime.tools import _tool_fix_row, repairable_diagnostics

    bad_vertex = "v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical|extra"
    doc = (
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        f"{bad_vertex}\n"
        "\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|cmdb-lookup|v-001||cmdb|n/a\n"
        "```\n"
    )
    deps, run = main_deps(tmp_path)
    seed_investigation(run, doc)

    assert repairable_diagnostics(deps) == (), "a :V row is not a row `fix_row` may address"

    with pytest.raises(ModelRetry):
        _tool_fix_row(
            deps, bad_vertex,
            "v-001|compute|workstation/internal/known-corp|attacker.corp|kind=physical\n"
            "v-009|compute|bastion/internal/known-corp|planted.corp|kind=physical",
        )
    assert (run / "investigation.md").read_text(encoding="utf-8") == doc


def test_a_row_naming_no_text_stays_out_of_the_repair_set(tmp_path):
    """The set is the rows `fix_row` can ADDRESS, and one nobody can quote back is not one.

    The repeated-lead-id family reports at BLOCK scope, so it carries a locus whose `row_text`
    is empty — and `fix_row` reads an empty `old_row` as DELETE. Admitting it would offer a
    repair that names nothing and deletes on sight, and would quietly reverse #954's decision
    that a document holding that repeat is refused at every write verb with no legacy
    exemption.
    """
    from defender.runtime.tools import repairable_diagnostics
    from defender.tests._invlang_amendment_954 import VERTICES, findings_block

    deps, run = main_deps(tmp_path)
    seed_investigation(run, VERTICES + findings_block(
        "l-001|1|first|v-001||cmdb|n/a", "l-001|2|second|v-002||edr|48h"))

    assert repairable_diagnostics(deps) == ()


def test_a_validator_that_raises_does_not_make_the_run_unclosable(tmp_path, capsys):
    """The close's structure gate fails OPEN on a validator fault, like the gate one line above
    it (#836 H7) and unlike the WRITE gate it shares a schema with.

    On a write, failing closed is free — nothing lands and the model re-sends. Here the same
    choice turns a validator BUG into an unclosable run: there is no repair for it, so the
    model retries until the framework force-closes and the real disposition is discarded. A
    gate that failed open on unreadable BYTES and closed on an unreadable VALIDATOR would be
    answering one question two ways.
    """
    import defender._artifact_schema as schema

    def _boom(_text, _current):
        raise RecursionError("validator blew up")

    original = schema.diagnose
    schema.diagnose = _boom
    try:
        assert schema.committed_investigation_reason("anything") is None
    finally:
        schema.diagnose = original

    assert "could not be validated" in capsys.readouterr().err, "the fault must be logged"


# #964 — the harness's own seed

def test_the_harness_seed_lands_when_it_validates(tmp_path):
    """The ordinary path, asserted first so the refusal test below cannot pass by the seed
    never working at all."""
    from defender.runtime.lead_zero import _declare_l_finding

    run = tmp_path / "run"
    run.mkdir()
    _declare_l_finding(run, "l-00c", "correlation lead", "elastic")

    text = (run / "investigation.md").read_text(encoding="utf-8")
    assert "l-00c" in text


def test_a_seed_that_would_not_validate_is_not_written(tmp_path, capsys):
    """The decision #964 asks for, not just the check.

    Writing it anyway would rebuild the bypass under a new name. Skipping costs a reserved id
    that MAIN may then cite — and the validator answers that citation with `undeclared lead`, a
    refusal MAIN reads, can act on, and can clear by declaring the lead itself. Loud,
    actionable and recoverable, where a laundered write is none of the three.

    The baseline here is ALREADY malformed, which is the realistic trigger: the seed is built
    from a fixed template, so a failure means the document it is appending to was broken before
    this frame ever looked at it."""
    from defender.runtime.lead_zero import _declare_l_finding

    run = tmp_path / "run"
    run.mkdir()
    (run / "investigation.md").write_text(_ERROR_DOC, encoding="utf-8")

    _declare_l_finding(run, "l-00c", "correlation lead", "elastic")

    after = (run / "investigation.md").read_text(encoding="utf-8")
    assert after == _ERROR_DOC, "the seed appended to a document that does not validate"
    assert "refused to declare l-00c" in capsys.readouterr().out


def test_the_seed_never_raises_into_a_run_that_has_not_started(tmp_path):
    """Best-effort is preserved in BOTH directions. This frame runs before MAIN's first turn
    and its whole posture is that it cannot break a run — a refusal that raised would trade
    one bug for a worse one."""
    from defender.runtime.lead_zero import _declare_l_finding

    run = tmp_path / "run"
    run.mkdir()
    (run / "investigation.md").write_text(_ERROR_DOC, encoding="utf-8")

    _declare_l_finding(run, "l-00c", "correlation lead", "elastic")  # must not raise


def test_a_skipped_seed_leaves_the_model_a_repair_it_is_not_forbidden_from_making(tmp_path):
    """#964's decision is only safe if what the MODEL sees is actionable, and by default it was
    not — it was a trap.

    The seed's own refusal goes to stdout; no model reads it. What MAIN reads is the ORIENT
    heading, which said the reserved ids were "already claimed; do not reuse them". With the
    declaring row missing, MAIN cites the id, is refused with `undeclared lead`, and the only
    repair available is to write the very `:L findings` row it has been told not to write. Told
    the id is claimed and told not to reuse it, MAIN has no move.

    Both ends are asserted, because either alone leaves the trap half-shut: the heading now
    says the row is missing and that declaring it is not reuse, and the validator's refusal
    carries the same instruction for a model that reached it without re-reading ORIENT.
    """
    from defender.runtime.lead_zero import (
        L0, LeadZeroResult, _declare_l_finding, render_orient_section,
    )
    from defender.skills.invlang.validate import diagnose

    run = tmp_path / "run"
    run.mkdir()
    (run / "investigation.md").write_text(_ERROR_DOC, encoding="utf-8")
    _declare_l_finding(run, L0, "ancestor resolution", "elastic")

    heading = render_orient_section(LeadZeroResult(text="", status="resolved"), run)
    assert "is NOT in investigation.md" in heading
    assert "declare it yourself" in heading
    assert "not reuse" in heading

    cited = f"```invlang\n:R attr_updates [resolved_by|target|key|value]\n{L0}|v-1|class|x\n```"
    undeclared = [d for d in diagnose(cited, None) if "undeclared lead" in d.message]
    assert undeclared, "the fixture must actually reach the undeclared-lead check"
    assert "Declare it in a `:L findings` block" in undeclared[0].message
    assert "not reusing it" in undeclared[0].message


def test_the_heading_says_nothing_extra_when_the_seed_landed(tmp_path):
    """POSITIVE CONTROL, and prompt hygiene: the note appears only when the row is actually
    missing. A line carried on every run would cost tokens on each one and, worse, would tell
    a model whose document is fine to go looking for a problem it does not have."""
    from defender.runtime.lead_zero import (
        L0, LeadZeroResult, _declare_l_finding, render_orient_section,
    )

    run = tmp_path / "run"
    run.mkdir()
    _declare_l_finding(run, L0, "ancestor resolution", "elastic")

    heading = render_orient_section(LeadZeroResult(text="", status="resolved"), run)
    assert "is NOT in investigation.md" not in heading

    # ...and the degraded arm, which has no run dir to look in, is the heading unchanged.
    assert "is NOT in investigation.md" not in render_orient_section(
        LeadZeroResult(text="", status="failed"))


# the third site — the turn-N branch's seed

def test_a_valid_document_can_have_an_invalid_fence_prefix():
    """The premise the branch seed rested on, refuted by construction.

    The reference rules are order-INDEPENDENT: `_check_lead_refs` asks whether a cited lead is
    declared ANYWHERE in the document, not whether it was declared first. So a source whose
    `:R` block cites a lead its `:L findings` block declares one fence LATER is well-formed as
    a whole and `undeclared lead` when cut between the two — which is exactly what a
    fence-boundary seed does.

    No document in the checked-in corpus has that shape. That is why this is built rather than
    sampled: the class is reachable, and "we have not seen one" is not the same claim.
    """
    from defender.skills.invlang.parser import scan_fences
    from defender.skills.invlang.validate import diagnose
    from defender.tests._invlang_amendment_954 import (
        VERTICES, attr_block as amend_attr_block, findings_block,
    )

    doc = (
        VERTICES
        + amend_attr_block("l-001|v-001|class|server")
        + findings_block("l-001|1|probe|v-001||cmdb|n/a")
    )

    def errors(text):
        return [d for d in diagnose(text, None) if d.severity != "warning"]

    assert errors(doc) == [], "the whole document is well-formed"

    spans = scan_fences(doc).spans
    prefix = doc[: spans[1][1]]
    assert any("undeclared lead" in d.message for d in errors(prefix)), (
        "the two-fence prefix of a valid document is invalid"
    )
