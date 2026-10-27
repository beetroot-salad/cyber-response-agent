"""The derived repair window (warn_diagnostics) and the append/close gate that keeps it closed while a row is flagged."""
from __future__ import annotations

import asyncio

import pytest

from defender.tests.support.invlang.validation._invlang_warn_836 import (
    CLEAN_BLOCK,
    PROLOGUE,
    REPAIRED_ROW,
    SECOND_WARN_ROW,
    WARN_DOC,
    WARN_ROW,
    attr_block,
    build_main_agent,
    flagged_rows,
    main_deps,
    offered_tool_names,
    recording_stages,
    seed_investigation,
    warn_window,
)


#: EXECUTED at c0dca747 — two warn-family diagnostics, no others.
TWO_WARN_DOC = PROLOGUE + attr_block(WARN_ROW, SECOND_WARN_ROW)


def _pay_inconclusive_price(deps) -> None:
    """#923: `inconclusive` now carries its own entry price (a `ceiling_test` row naming a source or capability), unrelated to anything this module tests — the warn-severity repair window."""
    from pathlib import Path

    from defender.investigation.tools import flagged_diagnostics

    if flagged_diagnostics(deps):
        return
    path = Path(deps.run_dir) / "investigation.md"
    existing = path.read_bytes() if path.exists() else b""
    addition = (
        b'\n```invlang\n:T conclude\nceiling_test  state=nothing-to-try cap=telemetry.collect note=process telemetry not retrieved\n```\n'
    )
    path.write_bytes(existing + addition)


def _close(deps, disposition, *, stages=None, bounds=None):
    from defender.investigation import challenge_gate
    from defender.investigation.close_tool import close_investigation
    from defender.tests.support.runtime.permissions import _review_bundle

    if disposition == "inconclusive":
        _pay_inconclusive_price(deps)
    return close_investigation(
        deps, disposition,
        stages=stages if stages is not None else _review_bundle.bundle(
            composer=_review_bundle.composer_reply("holds")
        ),
        bounds=bounds if bounds is not None else challenge_gate.default_bounds(),
    )


class _NullStore:
    """The store `_drive_agent` flushes through. Both call sites are already inside
    best-effort `try/except` blocks in the driver, so this only has to exist."""

    def last_render_len(self, _session_id):
        return 0

    def set_truncated_by(self, _session_id, _value):
        return None


# M3 — the window is DERIVED

def test_window_is_derived_from_the_on_disk_document(tmp_path):
    """The window is a pure function of the document's current bytes:"""
    _deps, run = main_deps(tmp_path)
    inv = seed_investigation(run, WARN_DOC)

    assert flagged_rows(inv.read_text(encoding="utf-8")) == (WARN_ROW,)

    inv.write_text(PROLOGUE + attr_block(REPAIRED_ROW), encoding="utf-8")
    assert flagged_rows(inv.read_text(encoding="utf-8")) == ()

    inv.write_text(WARN_DOC, encoding="utf-8")
    assert flagged_rows(inv.read_text(encoding="utf-8")) == (WARN_ROW,)


def test_prepare_read_before_investigation_md_exists(tmp_path):
    """`prepare=` runs on EVERY model request, including turn 1 — before any write verb has created `investigation.md` at all."""
    deps, run = main_deps(tmp_path)

    assert not (run / "investigation.md").exists()
    offered = offered_tool_names(deps)

    assert "append_block" in offered, "the observation channel is empty — nothing was offered"
    assert "fix_row" not in offered

    seed_investigation(run, WARN_DOC)
    assert "fix_row" in offered_tool_names(deps)


def test_warn_diagnostics_over_empty_investigation_md(tmp_path):
    """A zero-byte or fence-less document is the "no window open" case, not an error case:
    there are no blocks to iterate, so the flagged set is empty."""
    for text in ("", "   \n", "just prose, no fences at all\n"):
        assert warn_window(text) == ()
        assert flagged_rows(text) == ()


def test_every_gate_flags_the_same_row_set(tmp_path):
    """All three derivation sites compute ONE function over ONE on-disk text, so they agree."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.investigation.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    seed_investigation(run, TWO_WARN_DOC)

    with pytest.raises(ModelRetry) as append_exc:
        _tool_append_block(deps, CLEAN_BLOCK)
    with pytest.raises(ModelRetry) as close_exc:
        _close(deps, "inconclusive")

    for exc in (append_exc, close_exc):
        assert WARN_ROW in str(exc.value)
        assert SECOND_WARN_ROW in str(exc.value)
    assert "fix_row" in offered_tool_names(deps)


def test_window_is_recomputed_after_each_fix_row(tmp_path):
    """The window is re-derived from disk after every repair — there is no cached set to
    invalidate, which is M3's whole reason for being derived."""
    from defender.investigation.tools import _tool_fix_row

    deps, run = main_deps(tmp_path)
    inv = seed_investigation(run, TWO_WARN_DOC)

    assert set(flagged_rows(inv.read_text(encoding="utf-8"))) == {WARN_ROW, SECOND_WARN_ROW}

    _tool_fix_row(deps, WARN_ROW, REPAIRED_ROW)
    assert flagged_rows(inv.read_text(encoding="utf-8")) == (SECOND_WARN_ROW,)

    _tool_fix_row(deps, SECOND_WARN_ROW, "l-001|v-002|attrs.dept|finance")
    assert flagged_rows(inv.read_text(encoding="utf-8")) == ()


def test_partial_repair_leaves_other_row_flagged(tmp_path):
    from pydantic_ai.exceptions import ModelRetry

    from defender.investigation.tools import _tool_append_block, _tool_fix_row

    deps, run = main_deps(tmp_path)
    seed_investigation(run, TWO_WARN_DOC)
    _tool_fix_row(deps, WARN_ROW, REPAIRED_ROW)

    with pytest.raises(ModelRetry) as exc:
        _tool_append_block(deps, CLEAN_BLOCK)

    assert SECOND_WARN_ROW in str(exc.value)
    assert WARN_ROW not in str(exc.value), "the refusal still names the repaired row"


def test_window_reopens_after_a_later_unrelated_defect(tmp_path):
    """A fully-repaired earlier episode leaves NO residue, because there is no stored state
    to leave any: a fresh window opens exactly as the first one did."""
    from defender.investigation.tools import _tool_append_block, _tool_fix_row

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)
    _tool_fix_row(deps, WARN_ROW, REPAIRED_ROW)
    inv = run / "investigation.md"
    assert flagged_rows(inv.read_text(encoding="utf-8")) == ()

    _tool_append_block(deps, attr_block(SECOND_WARN_ROW))

    assert flagged_rows(inv.read_text(encoding="utf-8")) == (SECOND_WARN_ROW,)


def test_window_derivation_failure_does_not_wedge_the_run(tmp_path):
    """H7: when the window CANNOT be derived, every one of the three paths fails OPEN."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.investigation.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    (run / "investigation.md").write_bytes(b"```invlang\n:R attr\xff\xfe updates\n```\n")

    # prepare= — the derivation runs on every model request and must not take the run down
    assert "fix_row" not in offered_tool_names(deps)

    # the write path — a refusal the model can read, never an exception out of the gate
    with pytest.raises(ModelRetry):
        _tool_append_block(deps, CLEAN_BLOCK)

    # the close path — the run stays closable
    _close(deps, "inconclusive")
    assert (run / "report.md").is_file()

    # ...and the control: a readable flagged document DOES refuse the close.
    deps2, run2 = main_deps(tmp_path / "control")
    seed_investigation(run2, WARN_DOC)
    with pytest.raises(ModelRetry):
        _close(deps2, "inconclusive")
    assert not (run2 / "report.md").exists()


# O1 / F-E — the accept path

def test_a_warn_family_defect_lands_and_returns_a_warning(tmp_path):
    """O1, the cost lever: a block whose only defect is warn-family LANDS, and the model is handed the warning instead of having to re-emit the whole block."""
    from defender.investigation.tools import _tool_append_block

    deps, run = main_deps(tmp_path)

    result = _tool_append_block(deps, WARN_DOC)

    assert (run / "investigation.md").read_text(encoding="utf-8") == WARN_DOC
    assert WARN_ROW in result
    assert "fix_row" in result


def test_the_accept_path_derives_its_warning_after_the_gate_returned_none(tmp_path):
    """F-E option (i), and the two-passes-per-accepted-append correction to the Scale note."""
    from defender.records._artifact_schema import validate_investigation
    from defender.investigation.tools import _tool_append_block

    deps, _run = main_deps(tmp_path)

    assert validate_investigation(WARN_DOC, None) is None, "the gate produced no text to reuse"
    result = _tool_append_block(deps, WARN_DOC)

    assert WARN_ROW in result
    assert "refinement key" in result, "the rendered warning itself never reached the model"


# M5 — the gate

def test_append_block_refused_while_a_row_is_flagged(tmp_path):
    """M5 on the write side:"""
    from pydantic_ai.exceptions import ModelRetry

    from defender.investigation.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry) as exc:
        _tool_append_block(deps, CLEAN_BLOCK)

    assert WARN_ROW in str(exc.value)
    assert "fix_row" in str(exc.value), "the refusal offers no reachable remedy"
    assert (run / "investigation.md").read_text(encoding="utf-8") == WARN_DOC


def test_close_investigation_refused_while_a_row_is_flagged(tmp_path):
    """O4 on the close side:"""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry) as exc:
        _close(deps, "inconclusive")

    assert WARN_ROW in str(exc.value)
    assert not (run / "report.md").exists()


def test_close_gate_precedes_every_disposition_branch(tmp_path):
    """H5: the gate sits at the TOP of the close — after the disposition-enum and terminal-closed checks, and before ANY disposition branch."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    for disposition in ("inconclusive", "false-positive", "benign"):
        with pytest.raises(ModelRetry) as exc:
            _close(deps, disposition)
        assert WARN_ROW in str(exc.value), disposition
        assert not (run / "report.md").exists(), disposition

    with pytest.raises(ModelRetry) as exc:
        _close(deps, "not-a-disposition")
    assert "disposition must be exactly one of" in str(exc.value)
    assert WARN_ROW not in str(exc.value), "the enum refusal lost its precedence"


def test_close_gate_precedes_the_review_spend(tmp_path):
    """H5's other half: a close refused for a flagged row never spends a review."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)
    stages = recording_stages("holds")

    with pytest.raises(ModelRetry):
        _close(deps, "benign", stages=stages.bundle())

    assert stages.calls == [], "a doomed close spent a review"

    # ...control: with the window closed, the same call DOES drive the gate's stages.
    deps2, run2 = main_deps(tmp_path / "control")
    seed_investigation(run2, PROLOGUE + attr_block(REPAIRED_ROW))
    stages2 = recording_stages("holds")
    _close(deps2, "benign", stages=stages2.bundle())
    assert stages2.calls, "the recording bundle cannot see a review at all"


def test_gate_refusal_names_the_flagged_rows_and_their_use_alternatives(tmp_path):
    """Both gate refusals hand the model the row AND the corrections it can paste back."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.investigation.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry) as append_exc:
        _tool_append_block(deps, CLEAN_BLOCK)
    with pytest.raises(ModelRetry) as close_exc:
        _close(deps, "inconclusive")

    for exc in (append_exc, close_exc):
        text = str(exc.value)
        assert f"row: {WARN_ROW}" in text
        assert "use: l-001|v-001|attrs.owner|svc.config-mgmt" in text
        assert "use: l-001|v-001|class|svc.config-mgmt" not in text
        assert "no `class` alternative is offered here" in text


def test_a_gated_refusal_leaves_both_artifacts_byte_identical(tmp_path):
    """The negative the refusal's own prose is claiming:"""
    from pydantic_ai.exceptions import ModelRetry

    from defender.investigation.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    inv = seed_investigation(run, WARN_DOC)
    before = inv.read_bytes()

    with pytest.raises(ModelRetry):
        _tool_append_block(deps, CLEAN_BLOCK)
    with pytest.raises(ModelRetry):
        _close(deps, "inconclusive")

    assert inv.read_bytes() == before
    assert not (run / "report.md").exists()

    # ...positive control, the complementary condition: window closed, both writes land.
    deps2, run2 = main_deps(tmp_path / "control")
    seed_investigation(run2, PROLOGUE + attr_block(REPAIRED_ROW))
    _tool_append_block(deps2, CLEAN_BLOCK)
    _close(deps2, "inconclusive")
    assert (run2 / "report.md").is_file()
    assert CLEAN_BLOCK.strip() in (run2 / "investigation.md").read_text(encoding="utf-8")


def test_a_landed_warn_row_refires_on_the_next_append(tmp_path):
    """The gate is FORCED, not chosen:"""
    from pydantic_ai.exceptions import ModelRetry

    from defender.investigation.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    _tool_append_block(deps, WARN_DOC)

    for attempt in range(3):
        with pytest.raises(ModelRetry) as exc:
            _tool_append_block(deps, CLEAN_BLOCK)
        assert WARN_ROW in str(exc.value), f"attempt {attempt}"


# H1 — the framework's forced close

def _drive_to_retry_exhaustion(deps):
    """Run the REAL agent loop with a model that never stops retrying a refused call, so pydantic-ai exhausts `DEFAULT_TOOL_RETRIES` (10, well inside the 62-request ceiling) and the driver's own forced-close limb runs."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    from defender.investigation import challenge_gate, driver

    class _Stuck:
        __name__ = "Stuck"

        def __call__(self, messages, info):
            return ModelResponse(parts=[
                ToolCallPart(tool_name="read_file", args={"path": "/nonexistent/denied.txt"}),
            ])

    agent = build_main_agent(_Stuck())
    run, end, exit_reason = asyncio.run(driver._drive_agent(
        agent, "go", deps, _NullStore(), "sid", challenge_gate.default_bounds(),
    ))
    return run, end.truncated_by, exit_reason


def test_close_gate_distinguishes_model_invoked_from_framework_invoked(tmp_path):
    """H1, the one written-down exception to O4's negative universal."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(ModelRetry) as exc:
        _close(deps, "inconclusive")
    assert WARN_ROW in str(exc.value)
    assert not (run / "report.md").exists()

    deps2, run2 = main_deps(tmp_path / "framework")
    seed_investigation(run2, WARN_DOC)
    _run, truncated_by, exit_reason = _drive_to_retry_exhaustion(deps2)

    assert exit_reason == "UnexpectedModelBehavior", "the forced-close limb never ran"
    assert truncated_by is not None
    assert (run2 / "report.md").is_file(), "the framework's forced close was gated too"


def test_forced_close_failure_is_distinguishable_from_a_committed_close(tmp_path):
    """Renamed from `test_forced_close_handler_surfaces_a_gate_refusal` (HD-1 repairs) to state the property this body actually asserts."""
    deps_ok, run_ok = main_deps(tmp_path / "commits")
    seed_investigation(run_ok, PROLOGUE)
    _run, _t_ok, exit_ok = _drive_to_retry_exhaustion(deps_ok)
    assert (run_ok / "report.md").is_file()

    deps_bad, run_bad = main_deps(tmp_path / "refused")
    seed_investigation(run_bad, PROLOGUE)
    (run_bad / "report.md").mkdir()
    _run, _t_bad, exit_bad = _drive_to_retry_exhaustion(deps_bad)

    assert not (run_bad / "report.md").is_file(), "the fault never reached the commit"
    assert exit_bad != exit_ok, (
        "a forced close that FAILED is indistinguishable from one that committed — the "
        f"handler swallowed it (both report {exit_ok!r})"
    )
