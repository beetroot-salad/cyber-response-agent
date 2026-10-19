"""`Diagnostic.severity`: the warn/error partition across the write gate, artifact validator, companion filter and persist mirror."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.invlang.validation._invlang_warn_836 import (
    CONCLUDE_BENIGN,
    PROLOGUE,
    WARN_DOC,
    WARN_ROW,
    attr_block,
    flagged_rows,
    main_deps,
    warn_window,
)

# error-severity documents, one per family that must NOT become a warning (N1)

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
    """The warning as the MODEL sees it, taken off the accept path's own return value."""
    from defender.runtime.tools import _tool_append_block

    deps, _run = main_deps(tmp_path)
    return _tool_append_block(deps, doc)


# demand #0 — the return contract


# M1 — the severity field and its partition


def test_only_attr_update_key_family_warns():
    """N1's partition, asserted as a partition rather than as one example."""
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
    """One `append_block` whose text carries BOTH a warn-family row and an error-family defect is refused IN FULL and writes nothing — M2 narrows only the warn path."""
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


# M2 — the write gate, the two entry points, and the two other validators

def test_validate_investigation_returns_none_on_warn_only(tmp_path):
    """The gate ACCEPTS a document whose only defects are warn-severity — with the size bound, the encodability check and the append-only baseline all still applied."""
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
    """`validate_artifact`'s `str | None` contract is UNCHANGED by M2 — the seam the close tool and the permission gate are both written against (claim g4)."""
    from defender._artifact_schema import validate_artifact

    assert validate_artifact("investigation.md", WARN_DOC, None) is None
    assert isinstance(validate_artifact("investigation.md", _PARSE_ERROR, None), str)
    assert isinstance(validate_artifact("report.md", "not frontmatter", None), str)
    assert validate_artifact(
        "report.md", "---\ndisposition: benign\n---\nbody\n", None
    ) is None


def test_validate_companion_drops_warnings():
    """`validate_companion` returns only the ERROR-severity messages, so its `list[str]` surface reads as "reasons to refuse" for its one production caller (persist.py:207, claim p6) rather than as "everything diagnose found"."""
    from defender.skills.invlang.validate import validate_companion

    assert validate_companion(WARN_DOC, None) == []
    assert len(validate_companion(_PARSE_ERROR, None)) == 1
    assert "parse error" in validate_companion(_PARSE_ERROR, None)[0]


def test_the_write_gate_applies_the_validators_warn_severity(tmp_path):
    from defender.agents import MAIN_DEF
    from defender.runtime.agent_definition import bind
    from defender.runtime.permission.files import decide_write

    run = tmp_path / "run"
    run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir()
    deps = bind(MAIN_DEF, run, defender_dir=dfn)
    inv = run / "investigation.md"

    assert decide_write(
        inv, WARN_DOC, run_dir=run, defender_dir=dfn, policy=deps.policy,
    ).allow is True

    assert decide_write(
        inv, _PARSE_ERROR, run_dir=run, defender_dir=dfn, policy=deps.policy,
    ).allow is False


def test_persist_reads_document_written_under_different_severity_semantics(tmp_path):
    """Severity is assigned per check family at diagnose time and is NEVER document content (claims p1/g5), so a document of any age is validated under current semantics and no migration mechanism exists to invent."""
    from defender.skills.invlang.validate import validate_companion

    on_disk = tmp_path / "aged.md"
    on_disk.write_text(WARN_DOC, encoding="utf-8")
    from_disk = on_disk.read_text(encoding="utf-8")

    assert validate_companion(from_disk, None) == []
    assert validate_companion(WARN_DOC, None) == []
    assert [d.severity for d in warn_window(from_disk)] == ["warning"]


# O2 — the copy gate and the readers downstream of it


# A2 — what the rendered warning shows the model

@pytest.mark.parametrize(("label", "row"), [
    ("ordinary", WARN_ROW),
    ("zero-width", "l-001|v-001|ow\u200bner|svc.config-mgmt"),
    ("bidi", "l-001|v-001|own\u202eer|svc.config-mgmt"),
])
def test_warning_renders_the_flagged_row_byte_exactly(tmp_path, label, row):
    """PR-1, settled as FACT rather than offered as a choice:"""
    doc = PROLOGUE + attr_block(row)

    rendered = _rendered_warning(tmp_path, doc)

    assert f"row: {row}" in rendered, label
    assert flagged_rows(doc) == (row,), label
