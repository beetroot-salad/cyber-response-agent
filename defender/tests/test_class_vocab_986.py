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

The check is `validate._check_vocab_class_cells`, and the tests below are its contract: the
positives that must be refused, the escape hatches (`??`, a candidate set, the two documented
catch-alls) that must pass through unchecked, and the non-obligations (process stays freeform;
a `CLASS_GRAMMAR` position is not an `attrs` vocabulary; the six `impact.*`/`attr-pred.target`
SLOTS keys are not vertex-attrs cells at all).
"""
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
        f"the real reported defect (v-005's class cell) must be refused; got {errors}"
    )


# ---------------------------------------------------------------------------
# the boundaries a membership check has to stop at, or it refuses honest writes
# ---------------------------------------------------------------------------


def test_a_class_grammar_position_is_not_an_attrs_vocabulary():
    """`compute.role` closes the FIRST SLASH-SLOT of a `compute` class cell, not an
    `attrs.role`. SKILL.md registers no `attrs.role` and no `attrs.zone`, so an author writing
    a database's `role=primary` or a cloud AZ's `zone=us-east-1a` means a free attribute that
    happens to share a word with a class slot — closing it against the class enum refuses an
    honest write and advises a vocabulary that answers a different question."""
    for attrs in ("role=primary", "zone=us-east-1a", "provenance=vendor-supplied"):
        doc = _vertex_doc(f"v-001|compute|web-server/internal/known-corp|db-1|{attrs}")
        assert validate_companion(doc, None) == [], attrs

    # ...and the arity-1 types keep theirs, because SKILL.md says the single class token IS
    # "the corresponding `attrs.kind` enum where the type has one".
    doc = _vertex_doc("v-001|storage|secrets|vault-1|kind=imaginary")
    assert any("storage.kind" in e for e in validate_companion(doc, None))


def test_a_quoted_value_is_judged_as_the_value_it_quotes():
    """A quote PROTECTS a delimiter in this format and is kept by `_split_cells`, so the same
    value arrives bare from a `:V` attrs cell and quoted from a `:R attr_updates` value cell.
    Judging the raw bytes makes one vocabulary answer two ways about one value."""
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
    """`_walkers.vertex_types` is FIRST-DECLARATION-WINS while `effective_vertex_state` folds a
    LATER row's class over an open one, so pairing the two judges the second row's cell by the
    first row's type — `interactive` refused as a `compute.role`, a refusal about a cell nobody
    wrote. A cell one declared type CAN hold is not refused.

    That is a rule about the FOLDED walk only. Each `:V` ROW still carries its own `type` cell
    and is judged by it (`_declared_row_errors`), which is why both rows here have to be
    individually legal for this to come back empty — and why the re-declaration is not a way to
    smuggle an off-vocabulary class past the gate (the refinement half of that claim is
    `test_a_re_declaration_does_not_smuggle_a_refinement_past_the_check`)."""
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
    """The hint is for the category confusion #986 is about — two axes of ONE type. Taking the
    first hit in `SLOTS` order instead points an `application` vertex at `compute.role`, a slot
    no cell on that vertex can ever hold."""
    errors = validate_companion(
        _vertex_doc("v-001|application|unknown/corp-tenant|acme|"), None
    )
    assert any("application.trust" in e for e in errors), errors
    assert not any("compute.role" in e for e in errors), errors


def test_the_offered_class_repair_is_withheld_when_this_check_would_refuse_it():
    """The illegal-key repair rewrites the KEY and keeps the author's VALUE, so on a `compute`
    vertex the `class` route turns `owner|svc.config-mgmt` into `class|svc.config-mgmt` — which
    this check refuses. An offer the validator's own gate rejects is the F-47 shape: the model
    pastes the bytes it was handed and is refused for a cell it did not choose."""
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
    """The `attrs.<name>` route keeps the author's VALUE exactly as the `class` route does, and
    `attr_slot_key` closes `compute.kind` — so `kind|imaginary` was offered
    `attrs.kind|imaginary` as its ONLY repair and the paste earned this check's refusal. Same
    defect, one route over: a route is offered only when the document it produces stands.

    Withholding EVERY route is the honest answer here — no repair keeps `imaginary` on a
    `compute` vertex — and the message has to say so for each route it withheld, or the author
    reads a sentence naming `class` and `attrs.<name>` as legal beside no `use:` line at all.
    """
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
    """A quoted LEGAL key has exactly one route — the key the author quoted. A `class` refusal
    printed beside `"ident"` explains withholding something that was never going to be offered,
    and reads as the validator refusing the repair it just printed."""
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
    """`_seed_vertex_state` upgrades a held class only from BLANK or OPEN, so a concrete cell
    written over a concrete one is dropped by the fold — and a check reading only the fold never
    sees the row the model just wrote. It is on disk forever under append-only, and it is #986's
    own shape: a lead's observations block re-declaring an already-classified host."""
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
    """`vocab.SLOTS` also registers `types`, `relations`, `disposition`, the `impact.*` grading
    keys and `attr-pred.target`. `created` is a RELATION, so a hint scanning the whole registry
    told a `storage` author their class token "is a `relations` value" — advice about a catalog
    no cell on a vertex is ever drawn from, which the hint's own rationale calls worse than no
    hint at all."""
    errors = validate_companion(_vertex_doc("v-001|storage|created|s-1|"), None)
    assert any("storage.kind" in e for e in errors), errors
    assert not any("relations" in e for e in errors), errors

    # ...and the complement: a real cross-TYPE vertex slot is still named, because it tells the
    # author the vertex may be the wrong type rather than the cell the wrong value.
    cross = validate_companion(_vertex_doc("v-001|database|file|db-1|"), None)
    assert any("storage.kind" in e for e in cross), cross


def test_a_re_declaration_does_not_smuggle_a_refinement_past_the_check():
    """A `:R attr_updates` refinement is the write this check exists for, and skipping every
    re-declared id handed it a bypass: declare `v-001` once `compute` and once `session` — a
    shape the validator accepts silently (#919 follow-up) — and the `container/internal/novel`
    class refinement was judged by neither grammar.

    `container` is not a `compute.role` AND not a `session.class`, so it is wrong under every
    reading the document offers, which is the verdict the ambiguity still leaves available."""
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

    # ...and the complement, which is what keeps this from refusing a cell nobody wrote: a
    # value ONE of the declared types holds stands. `interactive` is no `compute.role`, but it
    # is the `session.class` the second declaration names.
    stands = doc.replace(
        "l-001|v-001|class|container/internal/novel", "l-001|v-001|class|interactive"
    )
    assert validate_companion(stands, None) == [], validate_companion(stands, None)


def test_an_attrs_name_one_declared_type_leaves_free_is_not_refused():
    """The `attrs` half of the same rule. `attrs.kind` is closed on `compute` and free on
    `session` (SKILL.md registers no `session.kind`), so a re-declared vertex carrying
    `kind=imaginary` has a reading that holds it and the check must not refuse it — refusing
    would be the "a refusal about a cell nobody wrote" failure one column over."""
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
    """`vocab.SLOTS` also registers `impact.*`, `conclude.*` and `attr-pred.target` — the
    grading vocabularies of a resolution row. `attr_slot_key` keys on the PAIR to keep those
    off a vertex, but the pair is built from the row's own `type` cell, which
    `_check_vocab_vertices` refuses without stopping the walk — so `v-001|impact|…` used to
    earn a SECOND refusal quoting `enum impact.dimension` at a vertex."""
    errors = validate_companion(
        _vertex_doc("v-001|impact|x|y|dimension=bogus"), None
    )
    assert any("is not a known vertex type" in e for e in errors), errors
    assert not any("impact.dimension" in e for e in errors), errors
