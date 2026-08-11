"""#836 M1/M2 — `Diagnostic.severity`, and the three validator surfaces that read it.

The change: `_check_attr_update_keys` becomes WARN severity. The block LANDS, the model is
told which row is wrong, and every further write on `investigation.md` is refused until the
row is repaired. This module owns the severity partition itself and the four surfaces that
have to agree about it — `validate_investigation` (the write gate), `validate_artifact` (the
contract that must NOT change), `validate_companion` (persist's read-side filter), and the
learning mirror that carries a warn-only document onward (O2).

Red against `c0dca747` is the expected state: at that base `Diagnostic` carries no `severity`
field at all (claim p1) and `validate_investigation` denies on ANY diagnostic (claim p5).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests._invlang_warn_836 import (
    CONCLUDE_BENIGN,
    PROLOGUE,
    REPAIRED_ROW,
    WARN_DOC,
    WARN_ROW,
    attr_block,
    flagged_rows,
    main_deps,
    seed_investigation,
    warn_window,
)

# --------------------------------------------------------------------------- #
# error-severity documents, one per family that must NOT become a warning (N1)
# --------------------------------------------------------------------------- #

#: EXECUTED at c0dca747 — one `parse error: ... row has 5 cells but 4 expected` diagnostic.
#: PR-3's finding is that only the too-MANY direction produces one; one cell too FEW is
#: padded by `_row_cells` and emits nothing at any severity, so the fixture takes the side
#: that actually reaches the validator.
_PARSE_ERROR = PROLOGUE + attr_block("l-001|v-001|owner|a|b")

#: EXECUTED — one `undeclared lead` diagnostic, from a document-global check with no locus.
_UNDECLARED_LEAD = (
    "```invlang\n:R attr_updates [resolved_by|target|key|value]\n"
    "l-404|v-001|class|x\n```\n"
)

#: EXECUTED — one `disposition benign blocked` diagnostic (an unresolved `??` class).
_BENIGN_GATED = (
    PROLOGUE.replace("bastion/internal/known-corp|bastion-01.corp", "??/??/??|bastion-01.corp")
    + CONCLUDE_BENIGN
)

_ERROR_FAMILY_DOCS = [
    ("parse", _PARSE_ERROR),
    ("undeclared-lead", _UNDECLARED_LEAD),
    ("benign-gating", _BENIGN_GATED),
]


def _diagnose(text: str, current: str | None = None) -> list:
    from defender.skills.invlang.validate import diagnose

    return diagnose(text, current)


def _rendered_warning(tmp_path: Path, doc: str) -> str:
    """The warning as the MODEL sees it, taken off the accept path's own return value.

    Not off `_render_diagnostic` directly: F-E's whole finding is that the renderer was
    private to the DENY path, so a test that reached past the tool body would assert the
    renderer works while leaving the accept-path channel — the thing #836's saving is made
    of — unpinned."""
    from defender.runtime.tools import _tool_append_block

    deps, _run = main_deps(tmp_path)
    return _tool_append_block(deps, doc)


def _stage_run(root: Path, investigation: str) -> Path:
    run = root / "run"
    run.mkdir(parents=True)
    (run / "alert.json").write_text('{"id": "a-1"}\n', encoding="utf-8")
    (run / "report.md").write_text(
        "---\ndisposition: benign\n---\n\nnothing to see\n", encoding="utf-8"
    )
    seed_investigation(run, investigation)
    return run


# --------------------------------------------------------------------------- #
# demand #0 — the return contract
# --------------------------------------------------------------------------- #

def test_return_contract_shapes(tmp_path):
    """The whole change's return surface, in one census, because six demands' assertion
    shapes hang off it (fork f1, CONFIRMED at §7 rather than flipped).

    `warn_diagnostics` returns a TUPLE of `Diagnostic`; `validate_investigation` still
    returns `str | None` and `None` for a warn-only document; `validate_companion` returns
    only the error-severity messages; a warn-family `append_block` RETURNS a success string
    carrying the byte count, the rendered warning and the repair instruction; and every
    refusal on the write lane raises `ModelRetry`, matching the three existing write verbs
    (claim p10)."""
    from pydantic_ai.exceptions import ModelRetry

    from defender._artifact_schema import validate_investigation
    from defender.runtime.tools import _tool_append_block
    from defender.skills.invlang.validate import Diagnostic, validate_companion

    window = warn_window(WARN_DOC)
    assert isinstance(window, tuple)
    assert window
    assert all(isinstance(d, Diagnostic) for d in window)

    assert validate_investigation(WARN_DOC, None) is None
    assert isinstance(validate_investigation(_PARSE_ERROR, None), str)
    assert validate_companion(WARN_DOC, None) == []

    deps, run = main_deps(tmp_path)
    landed = _tool_append_block(deps, WARN_DOC)
    assert isinstance(landed, str)
    assert str(len(WARN_DOC.encode("utf-8"))) in landed, "the byte count is missing"
    assert WARN_ROW in landed, "the rendered warning does not name the flagged row"
    assert "fix_row" in landed, "the repair instruction names no verb"

    # ...and the refusal channel: every new refusal is a ModelRetry, never a returned string.
    with pytest.raises(ModelRetry):
        _tool_append_block(deps, PROLOGUE)
    assert (run / "investigation.md").read_text(encoding="utf-8") == WARN_DOC


# --------------------------------------------------------------------------- #
# M1 — the severity field and its partition
# --------------------------------------------------------------------------- #

def test_diagnostic_severity_defaults_to_error():
    """`Diagnostic.severity` is additive and defaults to `"error"`, so every one of the
    families that does not opt in keeps exactly today's behaviour.

    Asserted on a CONSTRUCTED diagnostic rather than on the dataclass's field list: a
    default nothing reads is not a default. The observable half is the second loop — a
    diagnostic carrying the default still refuses the write."""
    from defender._artifact_schema import validate_investigation
    from defender.skills.invlang.validate import Diagnostic

    assert Diagnostic(message="anything").severity == "error"

    for name, doc in _ERROR_FAMILY_DOCS:
        assert all(d.severity == "error" for d in _diagnose(doc)), name
        assert validate_investigation(doc, None) is not None, f"{name} stopped refusing"


def test_only_attr_update_key_family_warns():
    """N1's partition, asserted as a partition rather than as one example.

    `_check_attr_update_keys` is the ONLY family that emits `severity="warning"`. Parse
    errors, undeclared refs and the disposition gates stay refusals — the model re-sends and
    nothing is written. A suite that only pinned the warn side would go green on an
    implementation that made every family permissive, which is the exact shape that turns a
    cost lever into a validator bypass.

    N5 rides here too: `_check_strong_move_provenance` keeps checking presence only (claim
    p15); citation relevance is out of scope and is not silently upgraded."""
    warn = [d for d in _diagnose(WARN_DOC) if d.severity == "warning"]

    assert len(warn) == 1
    assert "refinement key" in warn[0].message
    assert warn[0].locus is not None
    assert warn[0].locus.row_text == WARN_ROW

    for name, doc in _ERROR_FAMILY_DOCS:
        severities = [d.severity for d in _diagnose(doc)]
        assert severities, f"{name} stopped producing a diagnostic at all"
        assert set(severities) == {"error"}, name


def test_append_block_mixes_warn_and_error_defects(tmp_path):
    """One `append_block` whose text carries BOTH a warn-family row and an error-family
    defect is refused IN FULL and writes nothing — M2 narrows only the warn path.

    The settled premise, and the one that keeps the cost lever from becoming a hole: the
    model re-sends the whole block (N1), so the warn row does not land either.

    The second block is the complementary condition, and it is what makes the first mean
    "M2 narrows" rather than "everything still refuses": the SAME text with the error-family
    row removed LANDS."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    mixed = PROLOGUE + attr_block(WARN_ROW, "l-001|v-002|dept|a|b")

    with pytest.raises(ModelRetry) as exc:
        _tool_append_block(deps, mixed)

    assert "parse error" in str(exc.value)
    assert not (run / "investigation.md").exists(), "a mixed block left residue on disk"

    warn_only = PROLOGUE + attr_block(WARN_ROW, "l-001|v-002|dept|finance")
    _tool_append_block(deps, warn_only)
    assert (run / "investigation.md").read_text(encoding="utf-8") == warn_only


# --------------------------------------------------------------------------- #
# M2 — the write gate, the two entry points, and the two other validators
# --------------------------------------------------------------------------- #

def test_validate_investigation_returns_none_on_warn_only(tmp_path):
    """The gate ACCEPTS a document whose only defects are warn-severity — with the size
    bound, the encodability check and the append-only baseline all still applied.

    This is the per-cell contract for `investigation_md.access[append_block]`: decide-write,
    encodable, size-bound and warn-severity-permissive on one address. The three arms below
    are the ones that must NOT have been relaxed alongside the severity change."""
    from defender._artifact_schema import (
        INVESTIGATION_FILE_MAX,
        validate_artifact,
        validate_investigation,
    )

    assert validate_investigation(WARN_DOC, None) is None

    # ...and the same surface still refuses when any of the other three arms is broken.
    assert validate_investigation("x" * (INVESTIGATION_FILE_MAX + 1), None) is not None
    assert validate_artifact(
        "investigation.md", "\ud800", None
    ) is not None, "the encodability arm relaxed"
    assert validate_investigation(
        PROLOGUE.replace("bastion-01.corp", "OTHER.corp"), PROLOGUE
    ) is not None, "the append-only baseline arm relaxed"


def test_validate_artifact_still_returns_str_or_none():
    """`validate_artifact`'s `str | None` contract is UNCHANGED by M2 — the seam the close
    tool and the permission gate are both written against (claim g4).

    F-E's option (ii) — returning the warning through the write gate — would have cost this
    demand; §7 took option (i) instead, and this is what records that the price was not
    paid."""
    from defender._artifact_schema import validate_artifact

    assert validate_artifact("investigation.md", WARN_DOC, None) is None
    assert isinstance(validate_artifact("investigation.md", _PARSE_ERROR, None), str)
    assert isinstance(validate_artifact("report.md", "not frontmatter", None), str)
    assert validate_artifact(
        "report.md", "---\ndisposition: benign\n---\nbody\n", None
    ) is None


def test_validate_companion_drops_warnings():
    """`validate_companion` returns only the ERROR-severity messages, so its `list[str]`
    surface reads as "reasons to refuse" for its one production caller (persist.py:207,
    claim p6) rather than as "everything diagnose found".

    Paired control: the error-family document still comes back with its message, so the
    filter is a filter and not a silencer."""
    from defender.skills.invlang.validate import validate_companion

    assert validate_companion(WARN_DOC, None) == []
    assert len(validate_companion(_PARSE_ERROR, None)) == 1
    assert "parse error" in validate_companion(_PARSE_ERROR, None)[0]


def test_two_validator_entry_points_stay_in_parity(tmp_path):
    """Both named production exports onto the same validator agree about warn severity —
    `decide_write` (the gate the write verbs face) and `_decide_investigation_write` (brief
    F6, kept because the frames suite drives it directly).

    Parity is per-CELL, not per-boundary: each via is driven with the same two documents and
    each is asserted on its own answer. Claim g4 says the second invokes the first rather
    than reimplementing it, so this is the cheap regression that keeps that true."""
    from defender.agents import MAIN_DEF
    from defender.runtime.agent_definition import bind
    from defender.runtime.permission.files import _decide_investigation_write, decide_write

    run = tmp_path / "run"
    run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir()
    deps = bind(MAIN_DEF, run, defender_dir=dfn)
    inv = run / "investigation.md"

    assert decide_write(
        inv, WARN_DOC, run_dir=run, defender_dir=dfn, policy=deps.policy,
    ).allow is True
    assert _decide_investigation_write(WARN_DOC, inv).allow is True

    assert decide_write(
        inv, _PARSE_ERROR, run_dir=run, defender_dir=dfn, policy=deps.policy,
    ).allow is False
    assert _decide_investigation_write(_PARSE_ERROR, inv).allow is False


def test_close_report_validator_meets_a_diagnostic_it_never_saw_before():
    """Vacuously unchanged, and pinned so nobody invents a mechanism for it: the new
    severity is scoped to an `investigation.md`-specific, `:R`-specific check that
    `report.md`'s validation never runs.

    Driven at the close's own edge (`interacts(close_investigation->validate_artifact)`) with
    a report body that CONTAINS the flagged row's text, so the row reaching the report
    validator is real rather than hypothetical."""
    from defender._artifact_schema import validate_artifact

    body = f"---\ndisposition: benign\n---\n\nthe flagged row was: {WARN_ROW}\n"

    assert validate_artifact("report.md", body, None) is None
    # ...and the same bytes as an investigation are a warn-only document, not a clean one.
    assert flagged_rows(WARN_DOC) == (WARN_ROW,)


def test_persist_reads_document_written_under_different_severity_semantics(tmp_path):
    """Severity is assigned per check family at diagnose time and is NEVER document content
    (claims p1/g5), so a document of any age is validated under current semantics and no
    migration mechanism exists to invent.

    Observed at the copy gate: bytes written before M1 shipped — which is to say, any bytes —
    validate identically whether they arrive from a fresh write or from disk."""
    from defender.skills.invlang.validate import validate_companion

    on_disk = tmp_path / "aged.md"
    on_disk.write_text(WARN_DOC, encoding="utf-8")
    from_disk = on_disk.read_text(encoding="utf-8")

    assert validate_companion(from_disk, None) == []
    assert validate_companion(WARN_DOC, None) == []
    assert [d.severity for d in warn_window(from_disk)] == ["warning"]


# --------------------------------------------------------------------------- #
# O2 — the copy gate and the readers downstream of it
# --------------------------------------------------------------------------- #

def test_persist_copy_path_accepts_warn_only_document(tmp_path):
    """O2, discharged AT THE COPY GATE: a run whose only defect is a warn-family row still
    reaches the learning loop instead of dead-lettering.

    Observed failing at `c0dca747` by `learning/core/persist.py:207` raising
    `RunUnprocessable` (claims r4/g13). The paired control is the second half — an
    error-severity document still refuses, so the gate is narrowed, not removed."""
    from defender.learning.core.config import RunUnprocessable
    from defender.learning.core.persist import _copy_shared_inputs

    run = _stage_run(tmp_path / "warn", WARN_DOC)
    mirror = tmp_path / "learning" / "run-1"
    _copy_shared_inputs(run, mirror)

    assert (mirror / "investigation.md").read_text(encoding="utf-8") == WARN_DOC

    bad = _stage_run(tmp_path / "broken", _PARSE_ERROR)
    with pytest.raises(RunUnprocessable):
        _copy_shared_inputs(bad, tmp_path / "learning" / "run-2")


def test_the_learning_mirror_carries_a_warn_only_document_onward(tmp_path):
    """O2's other half, and R7's per-reader discipline: the three UNMOVED readers of
    `investigation.md` are each driven over a warn-only document and observed AT THEIR OWN
    EDGE, not at the boundary.

    Nothing downstream of the copy persists "this document was warned", so each reader's
    answer must be indistinguishable from its answer over the repaired twin. A demand at
    `investigation_md`'s own altitude would read green with two of the three readers moved,
    which is exactly the bug R7 exists to compute."""
    from defender.learning import lead_repository
    from defender.learning.author.verify_forward.forward import load_run_context
    from defender.learning.core.persist import _copy_shared_inputs
    from defender.learning.core.prologue import extract_case_entities

    repaired = PROLOGUE + attr_block(REPAIRED_ROW)
    warn_run = _stage_run(tmp_path / "warn", WARN_DOC)
    clean_run = _stage_run(tmp_path / "clean", repaired)
    for run in (warn_run, clean_run):
        (run / "source_refs.yaml").write_text(
            "normalized_disposition: benign\n", encoding="utf-8"
        )
        _copy_shared_inputs(run, run.parent / "mirror")

    # reader 1 — the prologue scan, at interacts(prologue_extract->investigation_md)
    warn_entities = extract_case_entities(warn_run.parent / "mirror" / "investigation.md")
    clean_entities = extract_case_entities(clean_run.parent / "mirror" / "investigation.md")
    assert warn_entities == clean_entities
    assert "v-001" in warn_entities, "the reader saw nothing at all — a vacuous comparison"

    # reader 2 — the forward check, at interacts(forward_check->investigation_md)
    warn_text, warn_disp = load_run_context(warn_run.name, runs_dir=warn_run.parent)
    assert warn_text == WARN_DOC
    assert warn_disp == "benign"

    # reader 3 — the run-level cross-check, at interacts(run_common_cross_check->investigation_md)
    assert (
        lead_repository.narration_crosscheck_from_run(warn_run)
        == lead_repository.narration_crosscheck_from_run(clean_run)
    )


# --------------------------------------------------------------------------- #
# A2 — what the rendered warning shows the model
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("label", "row"), [
    ("ordinary", WARN_ROW),
    ("zero-width", "l-001|v-001|ow\u200bner|svc.config-mgmt"),
    ("bidi", "l-001|v-001|own\u202eer|svc.config-mgmt"),
])
def test_warning_renders_the_flagged_row_byte_exactly(tmp_path, label, row):
    """PR-1, settled as FACT rather than offered as a choice: the row the model is shown is
    byte-identical to the row `fix_row` will require back.

    Executed over the three shapes PR-1 covered and found equal — ordinary content (pr1a), a
    zero-width space and a bidi override (pr1c). `str.strip()` removes only White_Space, and
    U+200B / U+202E are category Cf, so the mechanism that breaks the trailing-whitespace
    case (pr1b, REFUTED) leaves these untouched. The suppression branch never fires for this
    family (pr1e, REFUTED) — the message is built from `rec.get('target')` and the key, never
    from the row.

    M4's whole intended workflow is this round trip, so it is asserted as a round trip: the
    row the rendered message prints IS a member of the flagged set."""
    doc = PROLOGUE + attr_block(row)

    rendered = _rendered_warning(tmp_path, doc)

    assert f"row: {row}" in rendered, label
    assert flagged_rows(doc) == (row,), label


def test_renderer_does_not_truncate_a_long_flagged_row(tmp_path):
    """pr1d, the one point the two escalation copies asserted opposite answers on: a flagged
    row past 200 characters is printed WHOLE.

    `_render_diagnostic` applies no length check at all; the 200-character truncation belongs
    to `ParseWarning.format()` (parser.py:71), a different diagnostic family. A renderer that
    truncated would break the copy-paste round trip for exactly the rows most likely to need
    one."""
    row = "l-001|v-001|owner|svc." + "x" * 260
    doc = PROLOGUE + attr_block(row)

    rendered = _rendered_warning(tmp_path, doc)

    assert len(row) > 274, "the fixture stopped being a long row"
    assert f"row: {row}" in rendered
    assert flagged_rows(doc) == (row,)
