"""#993 (hygiene half): a lead can declare a `:V` vertex that no `:E` row ever names.

The spec already says "don't create vertices just for facts" (`skills/invlang/SKILL.md`
`### :R observations and learned facts`) but is silent on the mirror mistake: declare a
vertex because a lead *did* observe a graph object, and then never write the edge that
observation actually is. The real instance (#993): a lead declared
`v-004|process|psql|psql[pid=??]|user=postgres` and `v-006|process|postgres|...` and wrote
no `:E` row naming either — two facts recorded as graph objects with no graph.

What DISCHARGES the obligation is half the rule. An `:E` row does, and so does a `:H` row
attached to the vertex — the only honest record a lead has for an entity whose relation it
can still only hypothesize, and a shape the rule would otherwise make unwritable. An
`:R attr_updates` row does not, and neither does an `:E` row that names the vertex without
connecting it: a target no `:V` block declares, or the vertex itself.

Two exemptions, both scoped so that neither renaming a block header nor re-reading committed
bytes can buy them: the OPENING prologue, measured by where the block sits rather than by what
it is called, and any row the baseline already carries.

DOCUMENTS ARE BUILT FENCE BY FENCE here, and that is not decoration: `append_block` sends one
```invlang fence per call, the exemption is scoped to the write, and a fixture that folded a
whole run into one fence would answer the position question with a shape no run ever has.
The corpus regression lives where it already did —
`test_shipped_invlang_documents.py::test_a_shipped_document_would_survive_the_write_gate`
runs every shipped document through this same entry point.
"""
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


# ---------------------------------------------------------------------------
# 1. the orphan: one diagnostic, naming the lead and the vertex, carrying every repair
# ---------------------------------------------------------------------------

_ORPHAN_DOC = _OPENING + _fence(_obs_vertices("l-001", _ORPHAN_VERTEX))


def test_orphan_vertex_is_refused_with_exactly_one_diagnostic():
    errors = validate_companion(_ORPHAN_DOC, None)
    assert len(errors) == 1, errors


def test_orphan_diagnostic_names_the_lead_and_the_vertex():
    (error,) = validate_companion(_ORPHAN_DOC, None)
    assert "l-001" in error
    assert "v-010" in error


def test_orphan_diagnostic_offers_the_write_the_edge_repair():
    (error,) = validate_companion(_ORPHAN_DOC, None)
    assert "l-001.observations.edges" in error


def test_orphan_diagnostic_offers_the_hypothesize_it_repair():
    (error,) = validate_companion(_ORPHAN_DOC, None)
    assert "attached_to" in error


def test_orphan_diagnostic_offers_the_dont_declare_it_repair():
    (error,) = validate_companion(_ORPHAN_DOC, None)
    assert "attr_updates" in error


def test_orphan_diagnostic_warns_against_inferring_from_a_text_field():
    """The spec's "don't reach below the resolution of your detector" rule, stated as an
    explicit refusal here — the repair must not be satisfiable by reading an edge off a
    `cmdline` attribute the detector never recorded as its own event."""
    (error,) = validate_companion(_ORPHAN_DOC, None)
    assert "do not infer" in error.lower() or "not infer" in error.lower()
    assert "cmdline" in error


# ---------------------------------------------------------------------------
# 2. an edge in the SAME lead's block, either direction, clears the vertex
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# 3. participation is document-wide: an edge in a DIFFERENT lead's block clears it too
# ---------------------------------------------------------------------------


def test_edge_in_a_different_leads_block_clears_it():
    doc = (
        _fence(_prologue())
        + _fence(_findings("l-001", "l-002"))
        + _fence(_obs_vertices("l-001", _ORPHAN_VERTEX))
        + _fence(_obs_edges("l-002", "e-001|spawned|v-010|v-001||siem-event:siem|"))
    )
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# 4. the prologue exemption: first declaration wins, matching `_walkers.vertex_types`
# ---------------------------------------------------------------------------


def test_prologue_declared_vertex_with_no_edge_is_exempt():
    assert validate_companion(_OPENING, None) == []


def test_lead_redeclaring_a_prologue_id_with_no_edge_is_exempt():
    """The prologue is the declaring site for `v-001`; a lead's own `:V` block re-observing
    the same id is not a NEW graph object, so it inherits the prologue's exemption."""
    doc = _OPENING + _fence(_obs_vertices("l-001", _PROLOGUE_VERTEX))
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# 5. participation is `:E` rows only — an `:R attr_updates` target does not count
# ---------------------------------------------------------------------------


def test_vertex_named_only_by_an_attr_updates_row_still_gets_a_diagnostic():
    doc = _OPENING + _fence(
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        _attr_updates("l-001|v-010|attrs.user|postgres"),
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


# ---------------------------------------------------------------------------
# 6. two orphans in one lead → two diagnostics, one per vertex, one repair paragraph
# ---------------------------------------------------------------------------

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
    """The guidance rides on the FIRST diagnostic and nowhere else. `diagnose` already paid
    for the alternative once (`validate/__init__.py`, the benign-gating dedup): a refusal that
    hands the model the same wall of text N times buries the one line that differs — which
    vertex — under N copies of the one that does not."""
    first, second = validate_companion(_TWO_ORPHAN_DOC, None)
    assert "attr_updates" in first
    assert "attr_updates" not in second
    assert "v-011" in second


# ---------------------------------------------------------------------------
# 7. a hypothesis attached to the vertex discharges it
# ---------------------------------------------------------------------------


def test_a_hypothesis_attached_to_the_vertex_clears_it():
    """The shape the language exists to carry: a lead found an entity and can only
    HYPOTHESIZE how it connects. Without this arm the rule is unsatisfiable — writing the
    `:E` row commits an observation the lead does not have (and the refusal's own last
    sentence forbids inferring one), while dropping the `:V` row strands the hypothesis,
    since `_check_hypothesis_refs` demands that `attached_to` resolve to a declared vertex."""
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


# ---------------------------------------------------------------------------
# 8. what an `:E` row has to be to count: a connection, not a mention
# ---------------------------------------------------------------------------


def test_an_edge_to_an_undeclared_id_does_not_clear_it():
    """The cheapest way past the refusal, if a mention were enough: point the edge at an id
    nothing declares. Nowhere else in the validator refuses that, and `frontier`'s edge index
    and the review projector both read an endpoint as a real graph object."""
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
    """`??` is §Open questions' honest spelling of "observed, not yet identified", not a
    phantom: the event was recorded and the slot is tracked to the close. Demanding that both
    ends resolve would refuse `_golden_invlang/turnN-A`'s three such rows."""
    doc = _OPENING + _fence(
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        _obs_edges("l-001", "e-001|spawned|v-010|??||siem-event:siem|"),
    )
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# 9. the prologue exemption is anchored to POSITION, not to the block name
# ---------------------------------------------------------------------------


def test_a_prologue_block_written_after_a_lead_reported_is_not_exempt():
    """`parser/_project.py` extends `prologue.vertices` from wherever the block sits, because
    append-only makes a second block the only legal way to add one. Keyed on the block NAME,
    the whole rule is then defeated by renaming one header."""
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
    """The fence is the unit, so ordering inside one write buys nothing either: a model that
    puts its `:V prologue.vertices` block above its `:V l-001.observations.vertices` block in
    the same `append_block` call has still filed a lead's finding as an opening declaration."""
    doc = _OPENING + _fence(
        _prologue(_ORPHAN_VERTEX),
        _obs_vertices("l-001", _SECOND_ORPHAN_VERTEX),
        _obs_edges("l-001", "e-001|spawned|v-011|v-001||siem-event:siem|"),
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


def test_a_second_prologue_fence_before_any_observation_is_still_exempt():
    """Position, not "the first block wins". `lead_zero` writes lead-0's declaring
    `:L findings` row before main's first turn, so in every real run the ORIENT prologue lands
    after a `:L findings` block — the opening ends when a lead says what it FOUND, and until
    then the graph is still being declared, over as many writes as the author takes."""
    doc = _fence(_prologue()) + _fence(_findings("l-001")) + _fence(_prologue(_ORPHAN_VERTEX))
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# 10. scoped to what THIS write introduces
# ---------------------------------------------------------------------------


def test_an_orphan_the_baseline_already_carries_is_not_refused():
    """`investigation.md` is append-only: a committed `:V` row can never be removed and
    `fix_row` reaches only flagged `attr_updates` rows, so a document-global reading refuses
    every later write of a run that already carries an orphan — for bytes no repair reaches."""
    proposed = _ORPHAN_DOC + _fence(_attr_updates("l-001|v-010|attrs.user|postgres"))
    assert validate_companion(proposed, _ORPHAN_DOC) == []


def test_a_committed_document_read_as_its_own_baseline_is_not_refused():
    """The two callers that pass a document as both halves — the learning loop's persist gate
    and the branch seeder — mean "this write introduces nothing". Read document-globally, the
    first dead-letters every finished run carrying an orphan into `queue/failed/` with no
    repair available, and the second makes any such run unbranchable and unresumable."""
    assert validate_companion(_ORPHAN_DOC, _ORPHAN_DOC) == []


def test_an_orphan_this_write_adds_is_still_refused_against_a_baseline():
    """The other half: baseline-keyed does not mean unenforced. The write that APPENDS the
    row is the one write at which it is new, and that is the write this refuses."""
    errors = validate_companion(_ORPHAN_DOC, _OPENING)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


def test_a_whole_document_written_as_one_fence_keeps_its_prologue_exemption():
    """The document's FIRST fence is its opening whatever else it carries: a document written
    all at once — the shipped examples, and the one-fence `_companion` fixtures the invlang
    tests are built on — declares its graph and reports on it in the same breath, with no
    earlier write for the prologue to be trailing. Costs the rule nothing a run can reach: the
    first fence of a live investigation is the harness's, written before main's first turn.
    The lead's own orphan in that same fence is still refused, which is what keeps the
    carve-out from standing the rule down."""
    one_fence = _fence(
        _prologue(),
        _findings("l-001"),
        _obs_vertices("l-001", _ORPHAN_VERTEX),
    )
    errors = validate_companion(one_fence, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]
    assert "v-001" not in errors[0]
