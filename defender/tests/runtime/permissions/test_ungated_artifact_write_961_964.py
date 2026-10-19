"""#961/#964: every writer of investigation.md meets the schema. The close validates the companion it publishes (an error-severity document commits nothing; a forced close is exempt; an unreadable document closes unresolved), reads it once for every gate, and the harness lead-0 seed is validated before it lands and never raises into a run."""

from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _writer_run_1165
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import pytest

from defender.tests.support.invlang.validation._invlang_warn_836 import (
    CONCLUDE_BENIGN,
    PROLOGUE,
    attr_block,
    main_deps,
    seed_investigation,
)

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
    #961/#964's gate on the write path itself, not about the price. Append a paying row"""
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
    from defender.tests.support.runtime.permissions import _review_bundle

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
    commit `report.md` untouched."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, _ERROR_DOC)

    with pytest.raises(ModelRetry) as exc:
        _close(deps, "inconclusive")

    assert "close blocked" in str(exc.value)
    assert not (run / "report.md").exists(), "the close committed a report anyway"


def test_the_same_document_without_the_defect_closes(tmp_path):
    deps, run = main_deps(tmp_path)
    seed_investigation(run, _CLEAN_DOC + CONCLUDE_BENIGN)

    _close(deps, "inconclusive")

    assert (run / "report.md").is_file()


def test_the_close_refusal_names_the_rows_and_the_repair_verb(tmp_path):
    """The refusal is the model's only channel: it is told its own context IS the file, so a
    close it cannot act on is a close it will retry unchanged until the budget runs out."""
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
    deps, run = main_deps(tmp_path)
    seed_investigation(run, _ERROR_DOC)

    from defender._vocab import HOST_ONLY_DISPOSITION
    from defender.runtime import challenge_gate
    from defender.runtime.close_tool import _close_investigation_async
    from defender.tests.support.runtime.permissions import _review_bundle
    import asyncio

    asyncio.run(_close_investigation_async(
        deps, HOST_ONLY_DISPOSITION,
        stages=_review_bundle.bundle(composer=_review_bundle.composer_reply("holds")),
        bounds=challenge_gate.default_bounds(),
        forced=True,
    ))

    assert (run / "report.md").is_file(), "the framework must always be able to close"


def test_an_unreadable_document_closes_unresolved_not_the_models_verdict(tmp_path):
    """H7's condition, and the line the close has to keep straight."""
    import os
    from defender._vocab import HOST_ONLY_DISPOSITION
    from defender.runtime.close_tool import CAUSE_REVIEW_INCOMPLETE, FORCED_INCONCLUSIVE, STAGE_ERROR
    from defender.tests.support.runtime.engine._spec992 import frontmatter, record

    def plant_undecodable(path):
        path.write_bytes(b"```invlang\n:R attr\xff\xfe updates\n```\n")

    def plant_directory(path):
        path.mkdir()

    def plant_fifo(path):
        os.mkfifo(path)

    for name, plant in [
        ("undecodable", plant_undecodable), ("directory", plant_directory), ("fifo", plant_fifo),
    ]:
        deps, run = main_deps(tmp_path / name)
        plant(run / "investigation.md")

        result = _close(deps, "malicious")

        assert result.outcome == FORCED_INCONCLUSIVE, name
        assert result.failure_kind == STAGE_ERROR, name
        fm = frontmatter(run)
        assert fm["disposition"] == HOST_ONLY_DISPOSITION, (name, fm)
        assert fm["cause"] == CAUSE_REVIEW_INCOMPLETE, (name, fm)
        rec = record(run, 1)
        assert rec["reviewed_disposition"] == "malicious", (name, rec)
        assert rec["reviewed"] is True, "a review that could not run was still attempted"
        assert rec["failure_kind"] == STAGE_ERROR, (name, rec)
        assert "\ncompanion: " in rec["detail"], (name, rec)  # framed, like every stage detail


def test_an_io_fault_reading_the_companion_is_refused_not_overruled(tmp_path):
    from defender.runtime.tools import read_companion
    from defender.tests.support.integrations._roster1035 import EXIT_RAISED_EXPECTED, handed_to_nobody, run_as_nobody
    from defender.tests.support.runtime.engine._spec992 import record_files, trace_files
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    doc = seed_investigation(run, _CLEAN_DOC)

    def probe():
        read = read_companion(deps)
        assert read.text is None, "the fault was not met — the document read fine"
        assert read.retryable is True, read
        return _close(deps, "malicious")

    with handed_to_nobody(tmp_path, doc, 0o000):
        verdict = run_as_nobody(probe, expected=ModelRetry)
    assert verdict.code == EXIT_RAISED_EXPECTED, verdict.describe()
    assert "could not be read" in verdict.message, verdict.describe()
    assert "retry" in verdict.message.lower(), verdict.describe()
    assert not (run / "report.md").exists(), "the refusal committed a report"
    assert record_files(run) == [], "the refusal wrote a review record"
    assert trace_files(run) == [], "the refusal wrote trace rows"


def test_the_price_gate_still_answers_first_for_what_it_prices(tmp_path):
    """ORDERING, which is load-bearing rather than cosmetic."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, "```invlang\n:T conclude\ndisposition            benign\n```\n")

    with pytest.raises(ModelRetry) as exc:
        _close(deps, "false-positive")

    assert "entity_check" in str(exc.value), (
        "the disposition-specific obligation must not be shadowed by the document check"
    )


def test_one_read_answers_every_gate(tmp_path):
    import os
    import signal

    from defender._io import ALIAS_READ_REFUSAL
    from defender.runtime.tools import (
        committed_document_refusal, flagged_in, read_companion,
    )

    deps, run = main_deps(tmp_path)
    absent = read_companion(deps)
    assert (absent.text, absent.refusal) == ("", None)
    assert (flagged_in(absent), committed_document_refusal(absent)) == ((), None)

    (run / "investigation.md").write_bytes(_CLEAN_DOC.replace("\n", "\r\n").encode("utf-8"))
    assert read_companion(deps) == read_companion(deps)
    assert read_companion(deps).text == _CLEAN_DOC

    (run / "investigation.md").write_bytes(b"```invlang\n:R attr\xff\xfe updates\n```\n")
    undecodable = read_companion(deps)
    assert undecodable.text is None
    assert "utf-8" in undecodable.refusal
    assert undecodable.retryable is False, "bytes that do not decode are not a passing fault"
    assert flagged_in(undecodable) == (), "an unreadable document is no window (fail open)"
    assert committed_document_refusal(undecodable) is None, "not this gate's question"

    (run / "investigation.md").unlink()
    (run / "investigation.md").mkdir()
    squatted = read_companion(deps)
    assert squatted.text is None
    assert ALIAS_READ_REFUSAL in squatted.refusal
    assert squatted.retryable is False, "a planted entry is not a passing fault"
    assert (flagged_in(squatted), committed_document_refusal(squatted)) == ((), None)

    (run / "investigation.md").rmdir()
    os.mkfifo(run / "investigation.md")

    def _timed_out(signum, frame):
        raise AssertionError("read_companion blocked on a fifo planted at investigation.md")

    previous = signal.signal(signal.SIGALRM, _timed_out)
    signal.alarm(5)
    try:
        planted = read_companion(deps)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert planted.text is None
    assert ALIAS_READ_REFUSAL in planted.refusal
    assert planted.retryable is False


def test_the_write_verbs_build_on_the_reading_they_judged(tmp_path):
    from defender._io import ALIAS_READ_REFUSAL
    from defender.runtime.tools import _tool_append_block, _tool_fix_row
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    elsewhere = run / "elsewhere.md"
    elsewhere.write_text(_CLEAN_DOC, encoding="utf-8")
    (run / "investigation.md").symlink_to(elsewhere)

    with pytest.raises(ModelRetry) as refused:
        _tool_append_block(deps, "+ a row the link's target must never receive\n")
    assert "cannot be read" in str(refused.value), str(refused.value)
    assert ALIAS_READ_REFUSAL in str(refused.value), str(refused.value)
    assert "retry" not in str(refused.value).lower(), "a planted entry is not a passing fault"
    assert elsewhere.read_text(encoding="utf-8") == _CLEAN_DOC, "the append followed the link"
    with pytest.raises(ModelRetry) as refused:
        _tool_fix_row(deps, "l-001|v-001|class|bastion", "")
    assert elsewhere.read_text(encoding="utf-8") == _CLEAN_DOC, "the repair followed the link"

    (run / "investigation.md").unlink()
    (run / "investigation.md").write_bytes(b"```invlang\n:R attr\xff\xfe updates\n```\n")
    with pytest.raises(ModelRetry) as refused:
        _tool_append_block(deps, "+ a row\n")
    assert "utf-8" in str(refused.value).lower()
    assert (run / "investigation.md").read_bytes() == b"```invlang\n:R attr\xff\xfe updates\n```\n"


def test_a_committed_unfenced_header_does_not_make_the_run_unclosable(tmp_path):
    """The close reads the document as ITS OWN BASELINE, not against no baseline at all."""
    deps, run = main_deps(tmp_path)
    seed_investigation(
        run,
        PROLOGUE + "\n## PLAN\n\n:H hypothesize.hypotheses [id|claim]\n",
    )

    _close(deps, "inconclusive")

    assert (run / "report.md").is_file()


def test_an_error_severity_row_is_repairable_rather_than_a_dead_end(tmp_path):
    """The close names `fix_row`, so `fix_row` has to be able to reach what the close refused."""
    from defender.runtime.tools import (
        _tool_fix_row, committed_document_refusal, flagged_diagnostics, read_companion,
        repairable_diagnostics,
    )

    deps, run = main_deps(tmp_path)
    seed_investigation(run, _ERROR_DOC)

    assert flagged_diagnostics(deps) == (), "the warn window is empty — that was the trap"
    assert [d.locus.row_text for d in repairable_diagnostics(deps)] == [
        "l-001|v-001|class|workstation"
    ]
    assert committed_document_refusal(read_companion(deps)) is not None

    _tool_fix_row(deps, "l-001|v-001|class|workstation", "")

    assert committed_document_refusal(read_companion(deps)) is None
    _close(deps, "inconclusive")
    assert (run / "report.md").is_file()


def test_the_repair_set_is_widened_by_severity_and_not_by_scope(tmp_path):
    """An error-severity row OUTSIDE `:R attr_updates` stays out, and that is what keeps the
    widening safe."""
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
    """The set is the rows `fix_row` can ADDRESS, and one nobody can quote back is not one."""
    from defender.runtime.tools import repairable_diagnostics
    from defender.tests.support.invlang.validation._invlang_amendment_954 import VERTICES, findings_block

    deps, run = main_deps(tmp_path)
    seed_investigation(run, VERTICES + findings_block(
        "l-001|1|first|v-001||cmdb|n/a", "l-001|2|second|v-002||edr|48h"))

    assert repairable_diagnostics(deps) == ()


def test_a_validator_that_raises_does_not_make_the_run_unclosable(tmp_path, capsys):
    """The close's structure gate fails OPEN on a validator fault, like the gate one line above
    it (#836 H7) and unlike the WRITE gate it shares a schema with."""
    import defender.records._artifact_schema as schema

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

    run = tmp_path / fixture_uuid("run")
    run.mkdir()
    _declare_l_finding(_writer_run_1165(run), "l-00c", "correlation lead", "elastic")

    text = (run / "investigation.md").read_text(encoding="utf-8")
    assert "l-00c" in text


def test_a_seed_that_would_not_validate_is_not_written(tmp_path, capsys):
    """The decision #964 asks for, not just the check."""
    from defender.runtime.lead_zero import _declare_l_finding

    run = tmp_path / fixture_uuid("run")
    run.mkdir()
    (run / "investigation.md").write_text(_ERROR_DOC, encoding="utf-8")

    _declare_l_finding(_writer_run_1165(run), "l-00c", "correlation lead", "elastic")

    after = (run / "investigation.md").read_text(encoding="utf-8")
    assert after == _ERROR_DOC, "the seed appended to a document that does not validate"
    assert "refused to declare l-00c" in capsys.readouterr().err


def test_the_seed_never_raises_into_a_run_that_has_not_started(tmp_path):
    from defender.runtime.lead_zero import _declare_l_finding

    run = tmp_path / fixture_uuid("run")
    run.mkdir()
    (run / "investigation.md").write_text(_ERROR_DOC, encoding="utf-8")

    _declare_l_finding(_writer_run_1165(run), "l-00c", "correlation lead", "elastic")  # must not raise


def test_a_skipped_seed_leaves_the_model_a_repair_it_is_not_forbidden_from_making():
    from defender.runtime.lead_zero import L3
    from defender.skills.invlang.validate import diagnose

    cited = f"```invlang\n:R attr_updates [resolved_by|target|key|value]\n{L3}|v-1|class|x\n```"
    undeclared = [d for d in diagnose(cited, None) if "undeclared lead" in d.message]
    assert undeclared, "the fixture must actually reach the undeclared-lead check"
    assert "Declare it in a `:L findings` block" in undeclared[0].message
    assert "not reusing it" in undeclared[0].message


# the third site — the turn-N branch's seed

def test_a_valid_document_can_have_an_invalid_fence_prefix():
    """The premise the branch seed rested on, refuted by construction."""
    from defender.skills.invlang.parser import scan_fences
    from defender.skills.invlang.validate import diagnose
    from defender.tests.support.invlang.validation._invlang_amendment_954 import (
        VERTICES, attr_block as amend_attr_block, findings_block,
    )

    doc = (
        VERTICES
        + amend_attr_block("l-001|v-001|class|file-server/internal/known-corp")
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
