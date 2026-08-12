"""#836 M6 — `ident` becomes a third legal refinement key.

O6, and the operation the model keeps reaching for: every bad-refinement-key refusal measured
across eight local runs is `key='ident'` — 7 of 7 under global-unique dedup (claim g7), 14 of
14 under the doc's own per-occurrence unit (claim c1). M6 makes that spelling legal and lands
the sharpened value in a DISTINCT top-level `identifier` slot beside `classification` and
`attributes` (resolution R2), never in `attributes["ident"]`.

The routing matters and is not cosmetic. `_check_benign_open_slots` is `_effective_vertex_
state`'s SOLE consumer (claims p3/g9) and refuses a benign disposition on any `??`-valued
ATTRIBUTE — so routing `ident` into attributes would make `ident=??` newly block a benign
close, which N3 forbids.

§7's decisions applied here:

  H8  a refinement naming a vertex that was never declared is REFUSED, and the `identifier`
      slot is carried at BOTH effective-state construction sites
  A4  three explicit NON-obligations (N7-N9), so they cannot re-enter as assumptions: no
      cross-vertex uniqueness check on the effective identifier; no precedence rule between
      `key=ident` and `attrs.ident`; and an unresolved `??` in the `identifier` slot does NOT
      block a benign close — R2's decision made visible, pinned below as a positive control

The refusal-family census the design leans on was CORRECTED at extraction: claim c2 is
refuted (its family counts sum to 33 against a stated total of 17, so they count per-refusal
occurrences). The corrected census is 26 globally-unique diagnostic lines — attr-key 7, parse
6, provenance 5, gating 5, undeclared-ref 3 (g8). The "dominant family is one missing
capability" framing survives; the margin shrinks from 14-to-6 to 7-to-6.
"""
from __future__ import annotations

import pytest

from defender.tests._invlang_warn_836 import (
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
    from defender.skills.invlang.validate import _effective_vertex_state

    companion, _warnings = parse_dense_companion(text)
    return _effective_vertex_state(companion)


# --------------------------------------------------------------------------- #
# the vocabulary itself
# --------------------------------------------------------------------------- #

def test_ident_is_accepted_as_a_refinement_key(tmp_path):
    """O6: `key=ident` is legal, so the operation 7 of 7 measured refusals reached for
    finally exists.

    Observed failing at `c0dca747` by exactly this row being refused. Driven through the
    write verb rather than the validator alone, because "legal" has to mean the write LANDS —
    the refusal is what the measured token cost was made of."""
    from defender.runtime.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    doc = PROLOGUE + attr_block(_IDENT_ROW)

    _tool_append_block(deps, doc)

    assert _diagnose(doc, None) == []
    assert (run / "investigation.md").read_text(encoding="utf-8") == doc
    assert flagged_rows(doc) == ()


def test_class_key_still_accepted_after_the_vocabulary_widens(tmp_path):
    """The positive control for the vocabulary change: M6 ADDS a member, it does not replace
    one. `class` and the `attrs.*` wildcard both stay legal.

    Cheap, and exactly the regression a "replace the allowlist" implementation would trip."""
    for row in (
        "l-001|v-001|class|bastion/internal/known-corp",
        "l-001|v-001|attrs.owner|svc.config-mgmt",
        _IDENT_ROW,
    ):
        doc = PROLOGUE + attr_block(row)
        assert _diagnose(doc, None) == [], row


def test_attr_update_key_unrecognized_value_other_than_ident(tmp_path):
    """Every key that is not `class` / `attrs.*` / (post-M6) `ident` still WARNS.

    M1 upgrades the CHECK, not the measured `ident` population — which is what makes the
    warn+repair loop ship on expectation rather than on frequency. The doc's own accepted
    risk is that after M6 the entire measured warn population simply succeeds; the next inert
    key (`user`, `path`, `owner`) is what the loop is actually for."""
    doc = PROLOGUE + attr_block(WARN_ROW)
    diags = _diagnose(doc, None)

    assert len(diags) == 1
    assert diags[0].severity == "warning"
    assert flagged_rows(doc) == (WARN_ROW,)


def test_attr_update_key_cell_is_empty(tmp_path):
    """A blank `key` cell is still REFUSED — asserted as the observable refusal, deliberately
    not as which internal check fired.

    Probe PR-4 corrected the mechanism the design and two of three readings pointed at:
    `_check_attr_update_keys` treats `not key` exactly like a legal key and continues
    (validate.py:653). The refusal comes from the PARSER's own "attr_updates missing
    target/key" warn (parser.py:1074), at error severity. A test that pinned
    `_check_attr_update_keys` here would go green against an implementation where that check
    never runs on this input at all."""
    from defender._artifact_schema import validate_investigation

    doc = PROLOGUE + attr_block("l-001|v-001||svc.config-mgmt")
    diags = _diagnose(doc, None)

    assert len(diags) == 1
    assert diags[0].severity == "error"
    assert validate_investigation(doc, None) is not None
    assert flagged_rows(doc) == (), "a blank key opened a repair window instead of refusing"


def test_attr_update_key_whitespace_or_case_variant_of_ident(tmp_path):
    """Probe PR-9, both halves — a suite pinning only the trim would go green on a
    case-folding implementation.

    `_split_cells` captures every token as `''.join(cur).strip()` UNCONDITIONALLY, so
    `' ident '` reaches the legal-key comparison as `ident` and becomes legal with M6. No
    `.lower()` / `.casefold()` exists anywhere in `_cells.py`, so `Ident` and `IDENT` stay
    ILLEGAL after M6 and keep warning."""
    padded = PROLOGUE + attr_block("l-001|v-001| ident |svc.config-mgmt")
    assert _diagnose(padded, None) == [], "the trim stopped reaching the comparison"
    assert flagged_rows(padded) == ()

    for variant in ("Ident", "IDENT", "Attrs.ident"):
        doc = PROLOGUE + attr_block(f"l-001|v-001|{variant}|svc.config-mgmt")
        diags = _diagnose(doc, None)
        assert len(diags) == 1, variant
        assert diags[0].severity == "warning", variant


def test_document_written_before_the_key_became_legal(tmp_path):
    """No migration behaviour: re-reading old bytes under new code simply makes a
    previously-refused key legal.

    Severity and legality are computed at diagnose time and are never document content
    (claims p1/g5), so a document's age is not a property anything can read. For `key=ident`
    the state is near-unreachable in practice anyway — pre-M6 the row was refused and nothing
    was written (claim r1) — which is why this is pinned rather than mechanised."""
    from defender._artifact_schema import validate_investigation

    aged = tmp_path / "aged.md"
    aged.write_text(PROLOGUE + attr_block(_IDENT_ROW), encoding="utf-8")

    from_disk = aged.read_text(encoding="utf-8")
    assert validate_investigation(from_disk, None) is None
    assert _effective(from_disk)["v-001"]["identifier"] == "svc.config-mgmt"


# --------------------------------------------------------------------------- #
# R2 — where the sharpened value lands
# --------------------------------------------------------------------------- #

def test_ident_refinement_reaches_effective_vertex_state(tmp_path):
    """The sharpened value lands in a DISTINCT top-level `identifier` slot — never in
    `attributes["ident"]`.

    Resolution R2, and the routing N3 depends on: `_check_benign_open_slots` iterates
    `classification` and `attributes` only, so a third top-level key is naturally invisible
    to it. Both halves are asserted, because an implementation that wrote BOTH slots would
    satisfy the first alone and still re-introduce the gating N3 forbids."""
    state = _effective(PROLOGUE + attr_block(_IDENT_ROW))["v-001"]

    assert state["identifier"] == "svc.config-mgmt"
    assert "ident" not in state["attributes"]


def test_both_effective_state_construction_sites_carry_the_identifier_slot(tmp_path):
    """H8's coherence half: BOTH construction sites carry the new slot.

    `_effective_vertex_state` is built at two places — `_seed_vertex_state` from the `:V`
    declarations, then `_apply_attr_updates` over the `:R` refinements — and R2 pinned the
    slot without saying both carry it. A slot present at only one site is a `KeyError` for
    the consumer on every document that does not happen to exercise the other.

    Each site is driven ALONE: a document with no refinement at all reaches only the seed,
    and the seed's own function is then called into an empty state directly, so the second
    assertion cannot be satisfied by `_apply_attr_updates` filling in behind it."""
    from defender.skills.invlang.parser import parse_dense_companion
    from defender.skills.invlang.validate import _seed_vertex_state

    seeded = _effective(PROLOGUE)
    assert set(seeded) == {"v-001", "v-002"}
    assert seeded["v-001"]["identifier"] == _DECLARED_IDENT
    assert seeded["v-002"]["identifier"] == "jsmith"

    companion, _warnings = parse_dense_companion(PROLOGUE)
    direct: dict = {}
    _seed_vertex_state(companion, direct)
    assert direct["v-001"]["identifier"] == _DECLARED_IDENT

    refined = _effective(PROLOGUE + attr_block(_IDENT_ROW))["v-001"]
    assert refined["identifier"] == "svc.config-mgmt"


def test_ident_refined_more_than_once_across_runs_history(tmp_path):
    """Last value in document order wins, with no history retained.

    M6 reuses `_apply_attr_updates`' existing fold, so the superseded value survives only as
    the raw rows on disk. Asserted with THREE refinements so a "second wins" implementation
    is distinguishable from a "last wins" one."""
    doc = PROLOGUE + attr_block(
        "l-001|v-001|ident|first.corp",
        "l-001|v-001|ident|second.corp",
        "l-001|v-001|ident|third.corp",
    )

    assert _diagnose(doc, None) == []
    assert _effective(doc)["v-001"]["identifier"] == "third.corp"
    assert "first.corp" in doc
    assert "second.corp" in doc


def test_ident_refinement_and_warn_defect_on_same_vertex(tmp_path):
    """Severity is per check family and per ROW, so the two are independent: a legal `ident`
    refinement folds into effective state whether or not another row on the same vertex is
    flagged, and the flag gates the run regardless of the legal refinement."""
    doc = PROLOGUE + attr_block(_IDENT_ROW, WARN_ROW)

    assert _effective(doc)["v-001"]["identifier"] == "svc.config-mgmt"
    assert flagged_rows(doc) == (WARN_ROW,)


def test_a_sharpened_ident_does_not_gate_a_benign_disposition(tmp_path):
    """N3, and A4's non-obligation N9 pinned as its positive control.

    Legalizing `ident` changes NO downstream behaviour: the sharpened value lands in a slot
    `_check_benign_open_slots` does not read, so a benign close is unaffected. N9 is the
    sharper half and the one that had to be decided rather than assumed — an unresolved `??`
    in the `identifier` slot does NOT block a benign close. That is R2's decision made
    visible, not an oversight, and it is asserted here so it cannot re-enter later as a bug
    report.

    The control is the third block: a `??` ATTRIBUTE still blocks, so the gate is intact and
    the first two assertions are not green because the gate stopped working."""
    resolved = attr_block("l-001|v-001|class|bastion/internal/known-corp")

    concrete = PROLOGUE + resolved + attr_block(_IDENT_ROW) + CONCLUDE_BENIGN
    assert _diagnose(concrete, None) == []

    unresolved = PROLOGUE + resolved + attr_block("l-001|v-001|ident|??") + CONCLUDE_BENIGN
    assert _diagnose(unresolved, None) == [], "a `??` identifier newly blocked a benign close"
    assert _effective(unresolved)["v-001"]["identifier"] == "??"

    blocked = PROLOGUE + resolved + attr_block("l-001|v-001|attrs.owner|??") + CONCLUDE_BENIGN
    assert any("disposition benign blocked" in d.message for d in _diagnose(blocked, None))


def test_refinement_targets_a_vertex_never_declared(tmp_path):
    """H8: a refinement naming a vertex no `:V` block ever declared is REFUSED, at error
    severity.

    Probe PR-11 executed the gap this closes. The literal `key=ident` case denies today only
    because `ident` is itself illegal (confounded); the ISOLATION CONTROL — a legal key, same
    undeclared target — emits ZERO diagnostics, does not deny, and `_effective_vertex_state`
    then FABRICATES the vertex out of nothing: `{'v-999': {'classification': '', 'attributes':
    {'ident': 'svc.config-mgmt'}}}`. No undeclared/unresolved-ref family covers attr_updates
    targets, and there is no existence check between `_seed_vertex_state` and
    `_apply_attr_updates`.

    N3's argument for leaving this alone was "nothing reads the effective identifier" — which
    is the very premise M6 invalidates, because after M6 the field is writable and its values
    flow from alert content.

    Both the legal-key control and the `ident` spelling are driven, and the write is observed
    at the verb: refused, nothing on disk, no fabricated vertex."""
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


# --------------------------------------------------------------------------- #
# O3 — the `:V` declaration stays immutable
# --------------------------------------------------------------------------- #

def test_declared_identifier_after_a_sharpening(tmp_path):
    """Append-only compares the DECLARED identifier, so a sharpening is invisible to it.

    `_vertex_core` is `(type, classification, identifier)` and reads the value off the `:V`
    row (claim p4); the `:R` refinement never touches that row, so the document's history is
    unchanged and the append lands. This is what makes b1/b2's "a bad-key row is inert"
    framing hold, and what makes M6 additive rather than a change to the record."""
    from defender.runtime.tools import _tool_append_block

    deps, run = main_deps(tmp_path)
    _tool_append_block(deps, PROLOGUE)
    _tool_append_block(deps, attr_block(_IDENT_ROW))

    text = (run / "investigation.md").read_text(encoding="utf-8")
    assert _DECLARED_IDENT in text, "the declared row was rewritten"
    assert _effective(text)["v-001"]["identifier"] == "svc.config-mgmt"


def test_append_only_still_compares_the_declared_identifier(tmp_path):
    """The negative M6 must not weaken: mutating a committed vertex's `ident` IN THE `:V`
    DECLARATION still trips append-only.

    Claim b3 executed exactly this construction — "mutate v-002's ident in the :V
    declaration, run _check_append_only" — an IN-PLACE edit of the row already on disk, one
    declaration, rewritten, never a second one appended after it. Driven directly through
    `diagnose`/`_check_append_only` on both vertices (v-001's `ident`, then v-002's), because
    that is the layer b3 actually probed and the layer that genuinely refuses it.

    `_tool_append_block` CANNOT construct this case at all: it only ever composes
    `on_disk + text`, so a "mutated" declaration submitted through it necessarily arrives as a
    SECOND `:V prologue.vertices` block, and `_check_append_only`'s `_by_id_first` keeps the
    FIRST declaration per id — the untouched original — so the comparison never sees the
    duplicate. That gap is real, pre-existing, and out of this suite's scope (tracked as FU-3
    in the spec graph's handoff block); this test does not attempt to discharge it through the
    verb.

    M6 gives the model a LEGAL route to the same intent (a `:R` refinement), and the positive
    control below is that route succeeding, so the negative is not green merely because the
    document became unwritable."""
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
