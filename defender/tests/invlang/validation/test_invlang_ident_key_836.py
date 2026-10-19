from __future__ import annotations

import pytest

from defender.tests.support.invlang.validation._invlang_warn_836 import (
    CONCLUDE_BENIGN,
    PROLOGUE,
    WARN_ROW,
    attr_block,
    flagged_rows,
    main_deps,
)

_IDENT_ROW = "l-001|v-001|ident|svc.config-mgmt"
_DECLARED_IDENT = "bastion-01.corp"


def _diagnose(text, current=None):
    from defender.skills.invlang.validate import diagnose

    return diagnose(text, current)


def _effective(text):
    from defender.skills.invlang.parser import parse_dense_companion
    from defender.skills.invlang.validate import effective_vertex_state

    companion, _warnings = parse_dense_companion(text)
    return effective_vertex_state(companion)


# the vocabulary itself

def test_ident_is_accepted_as_a_refinement_key(tmp_path):
    """O6: `key=ident` is legal, so the operation 7 of 7 measured refusals reached for finally exists."""
    from defender.runtime.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    doc = PROLOGUE + attr_block(_IDENT_ROW)

    _tool_append_block(deps, doc)

    assert _diagnose(doc, None) == []
    assert (run / "investigation.md").read_text(encoding="utf-8") == doc
    assert flagged_rows(doc) == ()


def test_attr_update_key_unrecognized_value_other_than_ident(tmp_path):
    """Every key that is not `class` / `attrs.*` / (post-M6) `ident` still WARNS."""
    doc = PROLOGUE + attr_block(WARN_ROW)
    diags = _diagnose(doc, None)

    assert len(diags) == 1
    assert diags[0].severity == "warning"
    assert flagged_rows(doc) == (WARN_ROW,)


def test_attr_update_key_cell_is_empty(tmp_path):
    """A blank `key` cell is still REFUSED — asserted as the observable refusal, deliberately not as which internal check fired."""
    from defender._artifact_schema import validate_investigation

    doc = PROLOGUE + attr_block("l-001|v-001||svc.config-mgmt")
    diags = _diagnose(doc, None)

    assert len(diags) == 1
    assert diags[0].severity == "error"
    assert validate_investigation(doc, None) is not None
    assert flagged_rows(doc) == (), "a blank key opened a repair window instead of refusing"


# R2 — where the sharpened value lands

def test_ident_refinement_reaches_effective_vertex_state(tmp_path):
    """The sharpened value lands in a DISTINCT top-level `identifier` slot — never in `attributes["ident"]`."""
    state = _effective(PROLOGUE + attr_block(_IDENT_ROW))["v-001"]

    assert state["identifier"] == "svc.config-mgmt"
    assert "ident" not in state["attributes"]


def test_ident_refined_more_than_once_across_runs_history(tmp_path):
    """Last value in document order wins, with no history retained."""
    doc = (
        PROLOGUE
        + attr_block("l-001|v-001|ident|first.corp")
        + attr_block("l-001|v-001|ident|second.corp")
        + attr_block("l-001|v-001|ident|third.corp")
    )

    assert _diagnose(doc, None) == []
    assert _effective(doc)["v-001"]["identifier"] == "third.corp"
    assert "first.corp" in doc
    assert "second.corp" in doc


def test_the_same_ident_refinements_inside_one_block_are_refused(tmp_path):
    """The other side of the line #962 drew, pinned against the test above so the two shapes cannot drift into each other."""
    doc = PROLOGUE + attr_block(
        "l-001|v-001|ident|first.corp",
        "l-001|v-001|ident|second.corp",
        "l-001|v-001|ident|third.corp",
    )

    errors = [d for d in _diagnose(doc, None) if d.severity != "warning"]
    assert len(errors) == 2, "one per value discarded, not one per row"
    assert all("refined twice in this write" in d.message for d in errors)
    # The fold is unchanged — the refusal is the whole of what #962 added.
    assert _effective(doc)["v-001"]["identifier"] == "third.corp"


def test_two_attr_blocks_in_one_fence_are_one_write(tmp_path):
    """Splitting the block in two does not buy a second chance at the same slot."""
    doc = PROLOGUE + (
        "\n```invlang\n"
        ":R attr_updates [resolved_by|target|key|value]\n"
        "l-001|v-001|ident|first.corp\n"
        "\n"
        ":R attr_updates [resolved_by|target|key|value]\n"
        "l-001|v-001|ident|second.corp\n"
        "```\n"
    )

    errors = [d for d in _diagnose(doc, None) if d.severity != "warning"]
    assert len(errors) == 1
    assert "refined twice in this write" in errors[0].message
    assert _effective(doc)["v-001"]["identifier"] == "second.corp"


def test_a_sharpened_ident_does_not_gate_a_benign_disposition(tmp_path):
    """N3, and A4's non-obligation N9 pinned as its positive control."""
    resolved = attr_block("l-001|v-001|class|bastion/internal/known-corp")

    concrete = PROLOGUE + resolved + attr_block(_IDENT_ROW) + CONCLUDE_BENIGN
    assert _diagnose(concrete, None) == []

    unresolved = PROLOGUE + resolved + attr_block("l-001|v-001|ident|??") + CONCLUDE_BENIGN
    assert _diagnose(unresolved, None) == [], "a `??` identifier newly blocked a benign close"
    assert _effective(unresolved)["v-001"]["identifier"] == "??"

    blocked = PROLOGUE + resolved + attr_block("l-001|v-001|attrs.owner|??") + CONCLUDE_BENIGN
    assert any("disposition benign blocked" in d.message for d in _diagnose(blocked, None))


def test_refinement_targets_a_vertex_never_declared(tmp_path):
    """H8: a refinement naming a vertex no `:V` block ever declared is REFUSED, at error severity."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime.tools import _tool_append_block

    for row in (
        "l-001|v-999|attrs.owner|svc.config-mgmt",
        "l-001|v-999|ident|svc.config-mgmt",
        "l-001|v-999|class|bastion/internal/known-corp",
    ):
        doc = PROLOGUE + attr_block(row)
        diags = _diagnose(doc, None)
        assert diags, f"{row} still lands clean"
        assert all(d.severity == "error" for d in diags), row

        deps, run = main_deps(tmp_path / f"undeclared-{row.split('|')[2]}")
        with pytest.raises(ModelRetry):
            _tool_append_block(deps, doc)
        assert not (run / "investigation.md").exists(), row

    # ...and the same rows against a DECLARED target are accepted, so the check is an
    # existence check and not a ban on refinements.
    declared = PROLOGUE + attr_block("l-001|v-002|attrs.owner|svc.config-mgmt")
    assert _diagnose(declared, None) == []


# O3 — the `:V` declaration stays immutable


def test_append_only_still_compares_the_declared_identifier(tmp_path):
    """The negative M6 must not weaken:"""
    from defender.runtime.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    _tool_append_block(deps, PROLOGUE)
    committed = (run / "investigation.md").read_text(encoding="utf-8")

    mutated = PROLOGUE.replace(_DECLARED_IDENT, "attacker.corp")
    reasons = _diagnose(mutated, committed)
    assert any("append-only violation" in d.message for d in reasons)
    assert all(d.severity == "error" for d in reasons)

    # ...and the same holds for v-002 — the exact vertex/field b3's ledger entry names.
    mutated_v2 = PROLOGUE.replace(
        "v-002|identity|user/known-corp|jsmith|",
        "v-002|identity|user/known-corp|attacker|",
    )
    reasons_v2 = _diagnose(mutated_v2, committed)
    assert any(
        "append-only violation" in d.message and "v-002" in d.message for d in reasons_v2
    ), reasons_v2
    assert all(d.severity == "error" for d in reasons_v2)

    # ...and the sanctioned route to the same intent lands.
    _tool_append_block(deps, attr_block(_IDENT_ROW))
    assert _effective(
        (run / "investigation.md").read_text(encoding="utf-8")
    )["v-001"]["identifier"] == "svc.config-mgmt"
