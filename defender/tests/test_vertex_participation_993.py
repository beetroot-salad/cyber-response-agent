"""#993: a lead that declares a `:V` vertex no `:E` row ever names gets one diagnostic. An edge in the same or another lead's block, or a hypothesis attached to the vertex, clears it; attr_updates, undeclared-target and self edges do not; the opening prologue and rows the baseline already carries are exempt."""
from __future__ import annotations

from defender.skills.invlang.validate import validate_companion


def _fence(*blocks: str) -> str:
    """ONE `append_block` call — one ```invlang fence carrying as many `:X` blocks as the
    author put in it."""
    return "```invlang\n" + "\n\n".join(b for b in blocks if b) + "\n```\n"


#: One prologue vertex, present in every document below purely so `:L findings`' `target`
#: column has something legal to point at — it plays no role in what is under test.
_PROLOGUE_VERTEX = "v-001|compute|web-server/internal/known-corp|host-1|"

#: The orphan under test in most cases: a lead observed a process and recorded it as a
#: vertex — the real #993 shape (`v-004|process|psql|psql[pid=??]|user=postgres`).
_ORPHAN_VERTEX = "v-010|process|psql|psql[pid=??]|user=postgres"
_SECOND_ORPHAN_VERTEX = "v-011|process|postgres|postgres[pid=??]|user=postgres"

#: A `:H` row attached to the orphan — the "found it, can only guess how it connects" record.
#: Header copied from `tests/test_frontier_recall_919.py`.
_HYPOTHESIS_ON_ORPHAN = (
    "h-010|?psql-spawned-by-the-webapp|v-010|spawned|process|unclassified-process||null|active"
)
_HYPOTHESIS_ON_PROLOGUE = (
    "h-010|?host-1-was-reached|v-001|runs_on|process|unclassified-process||null|active"
)


def _prologue(*extra_vertices: str) -> str:
    return "\n".join([
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        _PROLOGUE_VERTEX,
        *extra_vertices,
    ])


def _findings(*lead_ids: str) -> str:
    return "\n".join([
        ":L findings [id|loop|name|target|tests|system|window]",
        *(f"{lid}|1|lookup|v-001||cmdb|n/a" for lid in lead_ids),
    ])


def _obs_vertices(lid: str, *rows: str) -> str:
    return "\n".join(
        [f":V {lid}.observations.vertices [id|type|class|ident|attrs?]", *rows]
    )


def _obs_edges(lid: str, *rows: str) -> str:
    return "\n".join(
        [
            f":E {lid}.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]",
            *rows,
        ]
    )


def _new_hypotheses(lid: str, *rows: str) -> str:
    return "\n".join([
        f":H {lid}.new_hypotheses [id|name|attached_to|rel|parent_type|parent_class|"
        f"integrity_waived?|weight|status]",
        *rows,
    ])


def _attr_updates(*rows: str) -> str:
    return "\n".join([":R attr_updates [resolved_by|target|key|value]", *rows])


#: The two writes every document below opens on: ORIENT declares the graph, PLAN declares the
#: leads. Neither records an observation, so both are still the document's opening.
_OPENING = _fence(_prologue()) + _fence(_findings("l-001"))


_ORPHAN_DOC = _OPENING + _fence(_obs_vertices("l-001", _ORPHAN_VERTEX))


def test_orphan_vertex_is_refused_with_exactly_one_diagnostic():
    errors = validate_companion(_ORPHAN_DOC, None)
    assert len(errors) == 1, errors
    assert "l-001" in errors[0]
    assert "v-010" in errors[0]


def test_edge_in_same_lead_naming_it_as_source_clears_it():
    doc = _OPENING + _fence(
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        _obs_edges("l-001", "e-001|spawned|v-010|v-001||siem-event:siem|"),
    )
    assert validate_companion(doc, None) == []


def test_edge_in_same_lead_naming_it_as_target_clears_it():
    doc = _OPENING + _fence(
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        _obs_edges("l-001", "e-001|spawned|v-001|v-010||siem-event:siem|"),
    )
    assert validate_companion(doc, None) == []


def test_edge_in_a_different_leads_block_clears_it():
    doc = (
        _fence(_prologue())
        + _fence(_findings("l-001", "l-002"))
        + _fence(_obs_vertices("l-001", _ORPHAN_VERTEX))
        + _fence(_obs_edges("l-002", "e-001|spawned|v-010|v-001||siem-event:siem|"))
    )
    assert validate_companion(doc, None) == []


def test_prologue_declared_vertex_with_no_edge_is_exempt():
    assert validate_companion(_OPENING, None) == []


def test_lead_redeclaring_a_prologue_id_with_no_edge_is_exempt():
    """The prologue is the declaring site for `v-001`; a lead's own `:V` block re-observing
    the same id is not a NEW graph object, so it inherits the prologue's exemption."""
    doc = _OPENING + _fence(_obs_vertices("l-001", _PROLOGUE_VERTEX))
    assert validate_companion(doc, None) == []


def test_vertex_named_only_by_an_attr_updates_row_still_gets_a_diagnostic():
    doc = _OPENING + _fence(
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        _attr_updates("l-001|v-010|attrs.user|postgres"),
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


_TWO_ORPHAN_DOC = _OPENING + _fence(
    _obs_vertices("l-001", _ORPHAN_VERTEX, _SECOND_ORPHAN_VERTEX)
)


def test_two_orphan_vertices_in_one_lead_get_two_diagnostics():
    errors = validate_companion(_TWO_ORPHAN_DOC, None)
    assert len(errors) == 2, errors
    joined = " ".join(errors)
    assert "v-010" in joined
    assert "v-011" in joined


def test_the_repair_paragraph_is_printed_once_per_write():
    first, second = validate_companion(_TWO_ORPHAN_DOC, None)
    assert "attr_updates" in first
    assert "attr_updates" not in second
    assert "v-011" in second


def test_a_hypothesis_attached_to_the_vertex_clears_it():
    doc = _OPENING + _fence(
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        _new_hypotheses("l-001", _HYPOTHESIS_ON_ORPHAN),
    )
    assert validate_companion(doc, None) == []


def test_a_hypothesis_attached_elsewhere_does_not_clear_it():
    """Scoped to the id the `:H` row actually names. A run carrying any hypothesis at all
    would otherwise discharge every orphan in the document."""
    doc = _OPENING + _fence(
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        _new_hypotheses("l-001", _HYPOTHESIS_ON_PROLOGUE),
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


def test_an_edge_to_an_undeclared_id_does_not_clear_it():
    doc = _OPENING + _fence(
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        _obs_edges("l-001", "e-001|spawned|v-010|v-999||siem-event:siem|"),
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


def test_a_self_edge_does_not_clear_it():
    doc = _OPENING + _fence(
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        _obs_edges("l-001", "e-001|spawned|v-010|v-010||siem-event:siem|"),
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


def test_an_edge_to_an_open_endpoint_clears_it():
    doc = _OPENING + _fence(
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        _obs_edges("l-001", "e-001|spawned|v-010|??||siem-event:siem|"),
    )
    assert validate_companion(doc, None) == []


def test_a_prologue_block_written_after_a_lead_reported_is_not_exempt():
    doc = (
        _OPENING
        + _fence(
            _obs_vertices("l-001", _PROLOGUE_VERTEX),
            _obs_edges("l-001", "e-001|runs_on|v-001|??||siem-event:siem|"),
        )
        + _fence(_prologue(_ORPHAN_VERTEX))
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


def test_a_prologue_block_sharing_a_fence_with_a_lead_report_is_not_exempt():
    doc = _OPENING + _fence(
        _prologue(_ORPHAN_VERTEX),
        _obs_vertices("l-001", _SECOND_ORPHAN_VERTEX),
        _obs_edges("l-001", "e-001|spawned|v-011|v-001||siem-event:siem|"),
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


def test_a_second_prologue_fence_before_any_observation_is_still_exempt():
    doc = _fence(_prologue()) + _fence(_findings("l-001")) + _fence(_prologue(_ORPHAN_VERTEX))
    assert validate_companion(doc, None) == []


def test_an_orphan_the_baseline_already_carries_is_not_refused():
    proposed = _ORPHAN_DOC + _fence(_attr_updates("l-001|v-010|attrs.user|postgres"))
    assert validate_companion(proposed, _ORPHAN_DOC) == []


def test_a_committed_document_read_as_its_own_baseline_is_not_refused():
    assert validate_companion(_ORPHAN_DOC, _ORPHAN_DOC) == []


def test_an_orphan_this_write_adds_is_still_refused_against_a_baseline():
    """The other half: baseline-keyed does not mean unenforced. The write that APPENDS the
    row is the one write at which it is new, and that is the write this refuses."""
    errors = validate_companion(_ORPHAN_DOC, _OPENING)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


def test_a_whole_document_written_as_one_fence_keeps_its_prologue_exemption():
    one_fence = _fence(
        _prologue(),
        _findings("l-001"),
        _obs_vertices("l-001", _ORPHAN_VERTEX),
    )
    errors = validate_companion(one_fence, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]
    assert "v-001" not in errors[0]
