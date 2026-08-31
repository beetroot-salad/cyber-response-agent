"""#986: `class`-tuple slots and their closed-vocabulary `attrs` siblings are never checked.

`_check_vocab_vertices` (validate/_structure.py) refuses an unknown vertex `type`, and
`_check_vocab_edges` refuses an unknown edge `rel`/`auth_kind` — but nothing refuses an
unknown *value inside* a `class` cell, even though `vocab.py` already ships the full grammar
needed to (`CLASS_GRAMMAR`, `vocab.SLOTS`) and both are already used elsewhere (`class_arity`,
`lessons_frontier._class_pins`).

The real-world instance: a run resolved a container's identity and wrote
`v-005|compute|container/internal/novel|db-1|...` — `container` is a member of `COMPUTE_KIND`
(the vertex's own deployment-form attribute), not `COMPUTE_ROLE` (the first slot of a
`compute` vertex's `class` tuple). The write landed clean; nothing caught the category
confusion. `defender/tests/_golden_invlang/turnN-A.investigation.md` carried the identical
defect independently (`v-004|compute|container/??/??|...`), now fixed alongside this suite.

RED AGAINST HEAD IS THE EXPECTED STATE for every test below except the ones proving the
non-obligations (process stays freeform; the six `impact.*`/`attr-pred.target` SLOTS keys are
not vertex-attrs cells). No implementation exists yet.
"""
from __future__ import annotations

from defender.skills.invlang.validate import validate_companion


def _companion(*blocks: str) -> str:
    return "```invlang\n" + "\n".join(blocks) + "\n```\n"


def _vertex_doc(row: str) -> str:
    return _companion(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        row,
    )


def _refine_doc(vertex_row: str, refine_row: str) -> str:
    return _companion(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        vertex_row,
        "",
        ":L findings [id|loop|name|target|tests|system|window]",
        "l-001|1|lookup|v-001||cmdb|n/a",
        "",
        ":R attr_updates [resolved_by|target|key|value]",
        refine_row,
    )


# ---------------------------------------------------------------------------
# class-tuple slots — the three CLASS_GRAMMAR types
# ---------------------------------------------------------------------------


def test_compute_role_slot_off_vocab_is_refused():
    doc = _vertex_doc("v-001|compute|container/internal/novel|db-1|")
    errors = validate_companion(doc, None)
    assert errors, "compute.role=container (a COMPUTE_KIND value) must be refused"
    assert any("compute.role" in e or "enum compute.role" in e for e in errors), errors


def test_compute_role_slot_off_vocab_names_the_slot_it_actually_belongs_to():
    """The error message itself carries the fix, not a doc the author had to have pre-read:
    `container` is a `compute.kind` value, not a `compute.role` one."""
    doc = _vertex_doc("v-001|compute|container/internal/novel|db-1|")
    errors = validate_companion(doc, None)
    assert any("compute.kind" in e for e in errors), errors


def test_compute_role_slot_valid_value_passes():
    doc = _vertex_doc("v-001|compute|web-server/internal/known-corp|web-1|")
    assert validate_companion(doc, None) == []


def test_compute_zone_slot_off_vocab_is_refused():
    doc = _vertex_doc("v-001|compute|web-server/nowhere-land/known-corp|web-1|")
    errors = validate_companion(doc, None)
    assert any("compute.zone" in e for e in errors), errors


def test_compute_provenance_slot_off_vocab_is_refused():
    doc = _vertex_doc("v-001|compute|web-server/internal/imaginary|web-1|")
    errors = validate_companion(doc, None)
    assert any("compute.provenance" in e for e in errors), errors


def test_identity_kind_slot_off_vocab_is_refused():
    doc = _vertex_doc("v-001|identity|imaginary-kind/known-corp|dev.dana|")
    errors = validate_companion(doc, None)
    assert any("identity.kind" in e for e in errors), errors


def test_identity_class_tuple_valid_passes():
    doc = _vertex_doc("v-001|identity|user/known-corp|dev.dana|")
    assert validate_companion(doc, None) == []


def test_application_vendor_slot_off_vocab_is_refused():
    doc = _vertex_doc("v-001|application|imaginary-vendor/corp-tenant|acme|")
    errors = validate_companion(doc, None)
    assert any("application.vendor" in e for e in errors), errors


def test_application_class_tuple_valid_passes():
    doc = _vertex_doc("v-001|application|salesforce/corp-tenant|acme|")
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# open-slot / candidate-set / catch-all escape hatches pass through unchecked
# ---------------------------------------------------------------------------


def test_fully_open_class_passes():
    doc = _vertex_doc("v-001|compute|??/??/??|1df4bcd65ee4|")
    assert validate_companion(doc, None) == []


def test_candidate_set_slot_passes():
    doc = _vertex_doc(
        "v-001|compute|{web-server,database-server}/internal/known-corp|db-1|"
    )
    assert validate_companion(doc, None) == []


def test_unclassified_catchall_passes():
    doc = _vertex_doc("v-001|compute|unclassified-compute/??/??|1df4bcd65ee4|")
    assert validate_companion(doc, None) == []


def test_ambiguous_catchall_passes():
    doc = _vertex_doc(
        "v-001|compute|ambiguous-web-server-or-database-server/internal/known-corp|db-1|"
    )
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# attrs-side closed-vocab cells — the sibling gap (compute.kind, session.class, etc.)
# ---------------------------------------------------------------------------


def test_compute_kind_attr_off_vocab_is_refused():
    doc = _vertex_doc("v-001|compute|unclassified-compute/??/??|1df4bcd65ee4|kind=imaginary")
    errors = validate_companion(doc, None)
    assert any("compute.kind" in e for e in errors), errors


def test_compute_kind_attr_container_is_the_right_home_for_it():
    """The exact discriminator: `container` belongs in `attrs.kind`, not the role slot."""
    doc = _vertex_doc("v-001|compute|unclassified-compute/??/??|1df4bcd65ee4|kind=container")
    assert validate_companion(doc, None) == []


def test_session_class_off_vocab_is_refused():
    doc = _vertex_doc("v-001|session|imaginary-class|session@db-1|")
    errors = validate_companion(doc, None)
    assert any("session.class" in e for e in errors), errors


def test_session_class_valid_passes():
    doc = _vertex_doc("v-001|session|interactive|session@db-1|")
    assert validate_companion(doc, None) == []


def test_socket_protocol_attr_off_vocab_is_refused():
    doc = _vertex_doc("v-001|socket|listening|sock-1|protocol=imaginary")
    errors = validate_companion(doc, None)
    assert any("socket.protocol" in e for e in errors), errors


def test_socket_protocol_attr_valid_passes():
    doc = _vertex_doc("v-001|socket|listening|sock-1|protocol=tcp")
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# non-obligation: `process`'s freeform class is not vocabulary-checked
# ---------------------------------------------------------------------------


def test_process_class_stays_freeform():
    doc = _vertex_doc("v-001|process|some-random-binary|some-random-binary[pid=1]|")
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# :R attr_updates refinements — the SKILL's own documented common path
# ---------------------------------------------------------------------------


def test_attr_updates_class_refinement_off_vocab_is_refused():
    doc = _refine_doc(
        "v-001|compute|??/??/??|1df4bcd65ee4|",
        "l-001|v-001|class|container/internal/novel",
    )
    errors = validate_companion(doc, None)
    assert any("compute.role" in e for e in errors), errors


def test_attr_updates_class_refinement_valid_passes():
    """The SKILL.md worked example's own shape: `l-001|v-001|class|monitoring-agent/
    internal/known-corp` — a refinement resolving an open class tuple."""
    doc = _refine_doc(
        "v-001|compute|??/??/??|10.42.7.183|",
        "l-001|v-001|class|monitoring-agent/internal/known-corp",
    )
    assert validate_companion(doc, None) == []


def test_attr_updates_attrs_kind_refinement_off_vocab_is_refused():
    doc = _refine_doc(
        "v-001|compute|unclassified-compute/??/??|1df4bcd65ee4|",
        "l-001|v-001|attrs.kind|imaginary",
    )
    errors = validate_companion(doc, None)
    assert any("compute.kind" in e for e in errors), errors


def test_attr_updates_attrs_kind_refinement_valid_passes():
    doc = _refine_doc(
        "v-001|compute|unclassified-compute/??/??|1df4bcd65ee4|",
        "l-001|v-001|attrs.kind|container",
    )
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# e2e-flavored: a realistic multi-block investigation slice, the actual reported shape
# ---------------------------------------------------------------------------


def test_986_e2e_realistic_investigation_flags_the_reported_defect():
    """Reproduces the real run's loop-2 write verbatim (minus unrelated blocks):
    `.defender-runs/20260830T100154Z-fresh-alert-input/investigation.md`."""
    doc = _companion(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        "v-001|compute|??/??/known-corp|soc-playground|knowledge=partial",
        "",
        ":L findings [id|loop|name|target|mode?|tests|system|window]",
        "l-006|2|container-identification|v-001|||host-state|n/a",
        "",
        ":V l-006.observations.vertices [id|type|class|ident|attrs?]",
        "v-005|compute|container/internal/novel|db-1|container_id=e5b0213bd690",
        "",
        ":E l-006.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]",
        "e-005|runs_on|v-005|v-001||runtime-audit:host-state|",
        "e-006|contained_in|v-005|v-001||runtime-audit:host-state|",
    )
    errors = validate_companion(doc, None)
    assert any("compute.role" in e for e in errors), (
        "the real reported defect (v-005's class cell) must be refused",
        errors,
    )
