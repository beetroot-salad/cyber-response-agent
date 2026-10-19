"""Closed-vocabulary checks on class-tuple slots and their attrs siblings, plus repair-route hints."""
from __future__ import annotations

from defender.skills.invlang.validate import diagnose, validate_companion


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


def test_compute_role_slot_off_vocab_is_refused():
    doc = _vertex_doc("v-001|compute|container/internal/novel|db-1|")
    errors = validate_companion(doc, None)
    assert errors, "compute.role=container (a COMPUTE_KIND value) must be refused"
    assert any("compute.role" in e or "enum compute.role" in e for e in errors), errors


def test_compute_role_slot_off_vocab_names_the_slot_it_actually_belongs_to():
    """The error message itself carries the fix, not a doc the author had to have pre-read: `container` is a..."""
    doc = _vertex_doc("v-001|compute|container/internal/novel|db-1|")
    errors = validate_companion(doc, None)
    assert any("compute.kind" in e for e in errors), errors


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


def test_application_vendor_slot_off_vocab_is_refused():
    doc = _vertex_doc("v-001|application|imaginary-vendor/corp-tenant|acme|")
    errors = validate_companion(doc, None)
    assert any("application.vendor" in e for e in errors), errors


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


def test_socket_protocol_attr_off_vocab_is_refused():
    doc = _vertex_doc("v-001|socket|listening|sock-1|protocol=imaginary")
    errors = validate_companion(doc, None)
    assert any("socket.protocol" in e for e in errors), errors


def test_process_class_stays_freeform():
    doc = _vertex_doc("v-001|process|some-random-binary|some-random-binary[pid=1]|")
    assert validate_companion(doc, None) == []


def test_attr_updates_class_refinement_off_vocab_is_refused():
    doc = _refine_doc(
        "v-001|compute|??/??/??|1df4bcd65ee4|",
        "l-001|v-001|class|container/internal/novel",
    )
    errors = validate_companion(doc, None)
    assert any("compute.role" in e for e in errors), errors


def test_attr_updates_attrs_kind_refinement_off_vocab_is_refused():
    doc = _refine_doc(
        "v-001|compute|unclassified-compute/??/??|1df4bcd65ee4|",
        "l-001|v-001|attrs.kind|imaginary",
    )
    errors = validate_companion(doc, None)
    assert any("compute.kind" in e for e in errors), errors


def test_986_e2e_realistic_investigation_flags_the_reported_defect():
    """Reproduces the real run's loop-2 write verbatim (minus unrelated blocks):..."""
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
        f"the real reported defect (v-005's class cell) must be refused; got {errors}"
    )


def test_a_class_grammar_position_is_not_an_attrs_vocabulary():
    """`compute.role` closes the FIRST SLASH-SLOT of a `compute` class cell, not an `attrs.role`. SKILL.md..."""
    for attrs in ("role=primary", "zone=us-east-1a", "provenance=vendor-supplied"):
        doc = _vertex_doc(f"v-001|compute|web-server/internal/known-corp|db-1|{attrs}")
        assert validate_companion(doc, None) == [], attrs

    # ...and the arity-1 types keep theirs, because SKILL.md says the single class token IS
    # "the corresponding `attrs.kind` enum where the type has one".
    doc = _vertex_doc("v-001|storage|secrets|vault-1|kind=imaginary")
    assert any("storage.kind" in e for e in validate_companion(doc, None))


def test_a_quoted_value_is_judged_as_the_value_it_quotes():
    """A quote PROTECTS a delimiter in this format and is kept by `_split_cells`, so the same value arrives bare..."""
    assert validate_companion(
        _vertex_doc('v-001|compute|web-server/internal/known-corp|db-1|kind="container"'),
        None,
    ) == []
    assert validate_companion(
        _refine_doc(
            "v-001|compute|web-server/internal/known-corp|db-1|",
            'l-001|v-001|attrs.kind|"container"',
        ),
        None,
    ) == []
    assert validate_companion(
        _refine_doc(
            "v-001|compute|??/??/??|db-1|",
            'l-001|v-001|class|"web-server/internal/known-corp"',
        ),
        None,
    ) == []


def test_a_vertex_re_declared_under_a_second_type_has_no_grammar_to_dispatch_on():
    """`_walkers.vertex_types` is FIRST-DECLARATION-WINS while `effective_vertex_state` folds a LATER row's class..."""
    doc = _companion(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        "v-001|compute|??/??/??|x|",
        "",
        ":L findings [id|loop|name|target|tests|system|window]",
        "l-001|1|lookup|v-001||cmdb|n/a",
        "",
        ":V l-001.observations.vertices [id|type|class|ident|attrs?]",
        "v-001|session|interactive|x|",
    )
    assert validate_companion(doc, None) == []


def test_the_cross_slot_hint_names_a_slot_on_this_vertexs_own_type():
    """The hint is for the category confusion #986 is about — two axes of ONE type. Taking the first hit in..."""
    errors = validate_companion(
        _vertex_doc("v-001|application|unknown/corp-tenant|acme|"), None
    )
    assert any("application.trust" in e for e in errors), errors
    assert not any("compute.role" in e for e in errors), errors


def test_the_offered_class_repair_is_withheld_when_this_check_would_refuse_it():
    """The illegal-key repair rewrites the KEY and keeps the author's VALUE, so on a `compute` vertex the `class`..."""
    doc = _companion(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        "v-001|compute|web-server/internal/known-corp|host|",
        "",
        ":L findings [id|loop|name|target|tests|system|window]",
        "l-001|1|cmdb-lookup|v-001||cmdb|n/a",
        "",
        ":R attr_updates [resolved_by|target|key|value]",
        "l-001|v-001|owner|svc.config-mgmt",
    )
    offers = [c for d in diagnose(doc, None) for c in d.fix]
    assert offers, "withholding every route leaves the flagged row with no repair at all"
    for candidate in offers:
        repaired = doc.replace("l-001|v-001|owner|svc.config-mgmt", candidate)
        assert validate_companion(repaired, None) == [], candidate

    # ...and the control: on a type whose class cell no enum closes, the `class` route stands.
    freeform = doc.replace(
        "v-001|compute|web-server/internal/known-corp|host|",
        "v-001|process|bash|bash[pid=1]|",
    )
    assert any(
        c == "l-001|v-001|class|svc.config-mgmt"
        for d in diagnose(freeform, None) for c in d.fix
    ), "the route is withheld for the VALUE, never for the key"


def test_every_offered_repair_route_lands_clean_not_only_the_class_one():
    """The `attrs.<name>` route keeps the author's VALUE exactly as the `class` route does, and `attr_slot_key`..."""
    doc = _companion(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        "v-001|compute|web-server/internal/known-corp|host|",
        "",
        ":L findings [id|loop|name|target|tests|system|window]",
        "l-001|1|cmdb-lookup|v-001||cmdb|n/a",
        "",
        ":R attr_updates [resolved_by|target|key|value]",
        "l-001|v-001|kind|imaginary",
    )
    flagged = [d for d in diagnose(doc, None) if d.locus and d.fix is not None]
    assert flagged, "the illegal key still has to be flagged"
    for d in flagged:
        for candidate in d.fix:
            repaired = doc.replace("l-001|v-001|kind|imaginary", candidate)
            assert validate_companion(repaired, None) == [], candidate
    message = " ".join(d.message for d in flagged)
    assert "no `class` alternative is offered here" in message, message
    assert "no `attrs.kind` alternative is offered here" in message, message

    # ...and the complement: an `attrs.<name>` naming NO closed vocabulary carries any value,
    # so that route stands where the `class` one does not.
    other = doc.replace("l-001|v-001|kind|imaginary", "l-001|v-001|owner|imaginary")
    assert any(
        c == "l-001|v-001|attrs.owner|imaginary"
        for d in diagnose(other, None) for c in d.fix
    )


def test_a_withheld_route_is_explained_only_where_it_was_a_candidate():
    """A quoted LEGAL key has exactly one route — the key the author quoted. A `class` refusal printed beside..."""
    doc = _companion(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        "v-001|compute|web-server/internal/known-corp|host|",
        "",
        ":L findings [id|loop|name|target|tests|system|window]",
        "l-001|1|cmdb-lookup|v-001||cmdb|n/a",
        "",
        ":R attr_updates [resolved_by|target|key|value]",
        'l-001|v-001|"ident"|svc.config-mgmt',
    )
    flagged = [d for d in diagnose(doc, None) if d.locus and d.locus.row_text.endswith(
        'l-001|v-001|"ident"|svc.config-mgmt'
    )]
    assert flagged
    for d in flagged:
        assert d.fix == ("l-001|v-001|ident|svc.config-mgmt",), d.fix
        assert "alternative is offered here" not in d.message, d.message


def test_a_later_declaration_the_fold_discards_is_still_checked():
    """`_seed_vertex_state` upgrades a held class only from BLANK or OPEN, so a concrete cell written over a..."""
    doc = _companion(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        "v-001|compute|web-server/internal/known-corp|host|",
        "",
        ":L findings [id|loop|name|target|tests|system|window]",
        "l-001|1|container-identification|v-001||host-state|n/a",
        "",
        ":V l-001.observations.vertices [id|type|class|ident|attrs?]",
        "v-001|compute|container/internal/novel|host|",
    )
    errors = validate_companion(doc, None)
    assert any("compute.role" in e for e in errors), errors
    # ...and exactly once: the declared-row walk and the folded walk both reach a cell the fold
    # DOES take, and one defect must not print as two.
    once = _vertex_doc("v-001|compute|container/internal/novel|db-1|")
    assert len(validate_companion(once, None)) == 1, validate_companion(once, None)


def test_the_cross_slot_hint_never_names_a_catalog_no_vertex_cell_is_drawn_from():
    """`vocab.SLOTS` also registers `types`, `relations`, `disposition`, the `impact.*` grading keys and..."""
    errors = validate_companion(_vertex_doc("v-001|storage|created|s-1|"), None)
    assert any("storage.kind" in e for e in errors), errors
    assert not any("relations" in e for e in errors), errors

    # ...and the complement: a real cross-TYPE vertex slot is still named, because it tells the
    # author the vertex may be the wrong type rather than the cell the wrong value.
    cross = validate_companion(_vertex_doc("v-001|database|file|db-1|"), None)
    assert any("storage.kind" in e for e in cross), cross


def test_a_re_declaration_does_not_smuggle_a_refinement_past_the_check():
    """A `:R attr_updates` refinement is the write this check exists for, and skipping every re-declared id..."""
    doc = _companion(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        "v-001|compute|??/??/??|x|",
        "",
        ":L findings [id|loop|name|target|tests|system|window]",
        "l-001|1|lookup|v-001||cmdb|n/a",
        "",
        ":V l-001.observations.vertices [id|type|class|ident|attrs?]",
        "v-001|session|??|x|",
        "",
        ":R attr_updates [resolved_by|target|key|value]",
        "l-001|v-001|class|container/internal/novel",
    )
    errors = validate_companion(doc, None)
    assert any("compute.role" in e for e in errors), errors

    stands = doc.replace(
        "l-001|v-001|class|container/internal/novel", "l-001|v-001|class|interactive"
    )
    assert validate_companion(stands, None) == [], validate_companion(stands, None)


def test_an_attrs_name_one_declared_type_leaves_free_is_not_refused():
    """The `attrs` half of the same rule. `attrs.kind` is closed on `compute` and free on `session` (SKILL.md..."""
    doc = _companion(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        "v-001|compute|??/??/??|x|",
        "",
        ":L findings [id|loop|name|target|tests|system|window]",
        "l-001|1|lookup|v-001||cmdb|n/a",
        "",
        ":V l-001.observations.vertices [id|type|class|ident|attrs?]",
        "v-001|session|??|x|",
        "",
        ":R attr_updates [resolved_by|target|key|value]",
        "l-001|v-001|attrs.kind|imaginary",
    )
    assert validate_companion(doc, None) == []


def test_a_non_vertex_type_never_reaches_a_grading_vocabulary():
    """`vocab.SLOTS` also registers `impact.*`, `conclude.*` and `attr-pred.target` — the grading vocabularies of..."""
    errors = validate_companion(
        _vertex_doc("v-001|impact|x|y|dimension=bogus"), None
    )
    assert any("is not a known vertex type" in e for e in errors), errors
    assert not any("impact.dimension" in e for e in errors), errors
