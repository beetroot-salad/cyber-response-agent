"""#993 (hygiene half): a lead can declare a `:V` vertex that no `:E` row ever names.

The spec already says "don't create vertices just for facts" (`skills/invlang/SKILL.md`
`### :R observations and learned facts`) but is silent on the mirror mistake: declare a
vertex because a lead *did* observe a graph object, and then never write the edge that
observation actually is. The real instance (#993): a lead declared
`v-004|process|psql|psql[pid=??]|user=postgres` and `v-006|process|postgres|...` and wrote
no `:E` row naming either — two facts recorded as graph objects with no graph.

RED AGAINST HEAD IS THE EXPECTED STATE for every test below except the ones proving the
non-obligations (a prologue-declared vertex, and a lead re-declaring a prologue id, are both
exempt). No implementation exists yet.

Companion-document construction follows `tests/test_class_vocab_986.py`'s `_companion`
helper (a bare ```invlang fence built from block strings, fed straight to
`validate_companion`); the corpus regression reuses `tests/_invlang_corpus.py`'s
`corpus_docs`/`corpus_id`, the same parametrization `test_shipped_invlang_documents.py`
already drives.
"""
from __future__ import annotations

import pytest

from defender.skills.invlang.validate import validate_companion
from defender.tests._invlang_corpus import corpus_docs, corpus_id


def _companion(*blocks: str) -> str:
    return "```invlang\n" + "\n".join(blocks) + "\n```\n"


#: One prologue vertex, present in every document below purely so `:L findings`' `target`
#: column has something legal to point at — it plays no role in what is under test.
_PROLOGUE_VERTEX = "v-001|compute|web-server/internal/known-corp|host-1|"

#: The orphan under test in most cases: a lead observed a process and recorded it as a
#: vertex — the real #993 shape (`v-004|process|psql|psql[pid=??]|user=postgres`).
_ORPHAN_VERTEX = "v-010|process|psql|psql[pid=??]|user=postgres"
_SECOND_ORPHAN_VERTEX = "v-011|process|postgres|postgres[pid=??]|user=postgres"


def _prologue(*extra_vertices: str) -> str:
    return "\n".join([
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        _PROLOGUE_VERTEX,
        *extra_vertices,
    ])


def _findings_header() -> str:
    return ":L findings [id|loop|name|target|tests|system|window]"


def _lead_row(lid: str, target: str = "v-001") -> str:
    return f"{lid}|1|lookup|{target}||cmdb|n/a"


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


def _attr_updates(*rows: str) -> str:
    return "\n".join([":R attr_updates [resolved_by|target|key|value]", *rows])


# ---------------------------------------------------------------------------
# 1. the orphan: one diagnostic, naming the lead and the vertex, carrying both repairs
# ---------------------------------------------------------------------------


def test_orphan_vertex_is_refused_with_exactly_one_diagnostic():
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        "",
        _obs_vertices("l-001", _ORPHAN_VERTEX),
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 1, errors


def test_orphan_diagnostic_names_the_lead_and_the_vertex():
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        "",
        _obs_vertices("l-001", _ORPHAN_VERTEX),
    )
    (error,) = validate_companion(doc, None)
    assert "l-001" in error
    assert "v-010" in error


def test_orphan_diagnostic_offers_the_write_the_edge_repair():
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        "",
        _obs_vertices("l-001", _ORPHAN_VERTEX),
    )
    (error,) = validate_companion(doc, None)
    assert "l-001.observations.edges" in error


def test_orphan_diagnostic_offers_the_dont_declare_it_repair():
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        "",
        _obs_vertices("l-001", _ORPHAN_VERTEX),
    )
    (error,) = validate_companion(doc, None)
    assert "attr_updates" in error


def test_orphan_diagnostic_warns_against_inferring_from_a_text_field():
    """The spec's "don't reach below the resolution of your detector" rule, stated as an
    explicit refusal here — the repair must not be satisfiable by reading an edge off a
    `cmdline` attribute the detector never recorded as its own event."""
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        "",
        _obs_vertices("l-001", _ORPHAN_VERTEX),
    )
    (error,) = validate_companion(doc, None)
    assert "do not infer" in error.lower() or "not infer" in error.lower()
    assert "cmdline" in error


# ---------------------------------------------------------------------------
# 2. an edge in the SAME lead's block, either direction, clears the vertex
# ---------------------------------------------------------------------------


def test_edge_in_same_lead_naming_it_as_source_clears_it():
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        "",
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        "",
        _obs_edges("l-001", "e-001|spawned|v-010|v-001||siem-event:siem|"),
    )
    assert validate_companion(doc, None) == []


def test_edge_in_same_lead_naming_it_as_target_clears_it():
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        "",
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        "",
        _obs_edges("l-001", "e-001|spawned|v-001|v-010||siem-event:siem|"),
    )
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# 3. participation is document-wide: an edge in a DIFFERENT lead's block clears it too
# ---------------------------------------------------------------------------


def test_edge_in_a_different_leads_block_clears_it():
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        _lead_row("l-002"),
        "",
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        "",
        _obs_edges("l-002", "e-001|spawned|v-010|v-001||siem-event:siem|"),
    )
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# 4. the prologue exemption: first declaration wins, matching `_walkers.vertex_types`
# ---------------------------------------------------------------------------


def test_prologue_declared_vertex_with_no_edge_is_exempt():
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
    )
    assert validate_companion(doc, None) == []


def test_lead_redeclaring_a_prologue_id_with_no_edge_is_exempt():
    """The prologue is the declaring site for `v-001`; a lead's own `:V` block re-observing
    the same id is not a NEW graph object, so it inherits the prologue's exemption."""
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        "",
        _obs_vertices("l-001", _PROLOGUE_VERTEX),
    )
    assert validate_companion(doc, None) == []


# ---------------------------------------------------------------------------
# 5. participation is `:E` rows only — an `:R attr_updates` target does not count
# ---------------------------------------------------------------------------


def test_vertex_named_only_by_an_attr_updates_row_still_gets_a_diagnostic():
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        "",
        _obs_vertices("l-001", _ORPHAN_VERTEX),
        "",
        _attr_updates("l-001|v-010|attrs.user|postgres"),
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 1, errors
    assert "v-010" in errors[0]


# ---------------------------------------------------------------------------
# 6. two orphans in one lead → two diagnostics, one per vertex
# ---------------------------------------------------------------------------


def test_two_orphan_vertices_in_one_lead_get_two_diagnostics():
    doc = _companion(
        _prologue(),
        "",
        _findings_header(),
        _lead_row("l-001"),
        "",
        _obs_vertices("l-001", _ORPHAN_VERTEX, _SECOND_ORPHAN_VERTEX),
    )
    errors = validate_companion(doc, None)
    assert len(errors) == 2, errors
    joined = " ".join(errors)
    assert "v-010" in joined
    assert "v-011" in joined


# ---------------------------------------------------------------------------
# 7. corpus regression: every shipped/golden document stays clean under the new rule
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", corpus_docs(), ids=corpus_id)
def test_corpus_documents_stay_clean_under_the_participation_rule(path) -> None:
    """`test_shipped_invlang_documents.py::test_a_shipped_document_would_survive_the_write_
    gate` already asserts zero errors for every corpus document and would catch a regression
    here too — this pins the SAME corpus against the SAME entry point so the new rule is
    measured explicitly, and documents the one document known to carry a legitimate orphan:
    `tests/_golden_invlang/turnN-A.investigation.md` declares `v-001` in its prologue and
    never edges it, which is exactly the prologue exemption this rule carries."""
    assert validate_companion(path.read_text(encoding="utf-8"), None) == [], (
        f"{corpus_id(path)} was refused by the vertex-participation rule"
    )


def test_golden_turn_n_a_prologue_orphan_v001_stays_clean() -> None:
    """The named regression case from the brief: `turnN-A.investigation.md`'s `v-001` is a
    prologue-declared vertex with no edge naming it anywhere in the document, and it must
    stay clean — the exemption is for the PROLOGUE, not for "no orphans exist"."""
    from defender.tests._invlang_corpus import DEFENDER

    path = DEFENDER / "tests" / "_golden_invlang" / "turnN-A.investigation.md"
    text = path.read_text(encoding="utf-8")
    assert "v-001|compute|container-host" in text, "the golden's v-001 row moved"
    assert validate_companion(text, None) == []
