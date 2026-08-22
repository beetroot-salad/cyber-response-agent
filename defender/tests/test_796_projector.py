"""#796 — the cut every blind lens reads through.

The lens architecture measures nothing if a lens can see the belief movement it is asked to
reconstruct, so these are the tests that would have caught the defect in #796's own original
text: it specified the support lens as withholding `:R`, which is the OBSERVATION side —
leaving `:T resolutions`, the weight move and its citation, in full view.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.runtime.review.projector import (
    INFERENCE_COMPANION_KEYS,
    INFERENCE_HYPOTHESIS_KEYS,
    INFERENCE_LEAD_KEYS,
    EmptyInvestigation,
    _EDGE_CITING_BUCKETS,
    _EDGE_CITING_KEYS,
    observation_only,
    parse_investigation,
    support_projection,
)
from defender.skills.invlang import _walkers, vocab
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)

DEFENDER = Path(__file__).resolve().parents[1]
GOLDEN = DEFENDER / "fixtures-e2e" / "golden-sshpivot-ab3" / "investigation.md"

#: The stage call's own salt, which production mints per call. Fixed here so two projections
#: built for the same assertion are comparable.
SALT = "0011223344556677"


@pytest.fixture(scope="module")
def companion():
    return parse_investigation(GOLDEN.read_text(encoding="utf-8"))


def _body(projection) -> dict:
    """The record a lens actually reads, lifted back out of its untrusted frame.

    Every assertion below is about what reached the MODEL, so it reads the rendered prompt
    rather than the pruned object — a renderer that leaked past the prune would otherwise be
    invisible to them."""
    open_tag, close_tag = f"<run-{SALT}-untrusted>\n", f"\n</run-{SALT}-untrusted>"
    assert open_tag in projection.text, "the projection reached the lens unframed"
    return json.loads(projection.text.split(open_tag, 1)[1].split(close_tag, 1)[0])


def _every_lens(companion) -> list:
    """Every projection a LENS is handed on this record — support, and its ablation when the
    record has a load-bearing edge to withhold.

    The leak assertions below run over this list rather than a hand-written pair, so a lens
    added to the gate cannot arrive with no leak coverage. It also closes a hole the
    hand-written pair had: it named the two lenses #796 shipped with their own projection
    builders and never the ABLATION, which is a third rendered prompt reaching a model. The
    composer is deliberately absent — it is the one role the cut does not apply to.

    The ablation is CONDITIONAL rather than asserted here, because a record with no strong
    belief movement genuinely has no edge to withhold and the gate skips the lens on one. That
    the GOLDEN is not such a record — so the leak tests really do cover both projections — is
    pinned by `test_the_golden_yields_both_lens_projections` rather than by a hidden assert
    that would also fire on the minimal fixtures."""
    from defender.runtime.review.projector import ablation_target

    lenses = [support_projection(companion, SALT)]
    ablated = ablation_target(companion)
    if ablated is not None:
        lenses.append(support_projection(companion, SALT, without_edge=ablated[0]))
    return lenses


def test_the_golden_yields_both_lens_projections(companion):
    """`_every_lens` skips the ablation on a record with no load-bearing edge, so on a golden
    that had none every leak test below would quietly cover one projection instead of two and
    still pass. This is the guard on that, and it is a test rather than an assert inside the
    helper because the minimal fixtures legitimately yield one."""
    assert len(_every_lens(companion)) == 2


def test_the_golden_is_a_real_positive_control(companion):
    """Every assertion below is about ABSENCE, so the fixture has to carry the thing whose
    absence is being asserted or they all pass vacuously."""
    assert companion.get("conclude"), "the golden reached no conclusion — wrong fixture"
    resolutions = list(_walkers.iter_resolutions(companion))
    assert resolutions, "the golden records no belief movement — nothing to withhold"
    assert any(r.get("after") for _lid, r in resolutions)


# ---------------------------------------------------------------------------------------
# The cut
# ---------------------------------------------------------------------------------------


def test_the_prune_drops_every_inference_key(companion):
    pruned = observation_only(companion)
    for key in INFERENCE_COMPANION_KEYS:
        assert key not in pruned, f"{key} survived the cut"
    for lead in pruned.get("findings") or []:
        for key in INFERENCE_LEAD_KEYS:
            assert key not in lead, f"{lead.get('id')}.{key} survived the cut"


def test_a_leads_plan_blocks_do_not_reach_a_lens():
    """The POSITIVE control for the two `INFERENCE_LEAD_KEYS` members #933 added.

    No document in the corpus carries a `:L l-NNN.lead_preds` or `:L l-NNN.impact_preds`
    block, so the golden-driven loop above asserts their absence from data that never held
    them — and the prune is a DENYLIST, which the projector's own docstring says reaches a
    field only once it is named. A `lead_preds` row carries `read_as` (the interpretation the
    run pre-committed to) and `advance_to` (the disposition it planned to route to); an
    `impact_preds` row carries the verdict mapping. Handing either to a blind lens tells it
    which way the run had already decided to move.
    """
    filled = parse_investigation(
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|identity|user/known-corp|dev.dana|\n"
        "\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|probe|v-001||elastic|alert-time\n"
        "\n"
        ":L l-001.lead_preds [id|if|read_as|advance_to]\n"
        'lp1|"burst in the last 10 min"|"anomalous spike"|CONCLUDE\n'
        "\n"
        ":L l-001.impact_preds "
        "[id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]\n"
        'ip1|confidentiality|"bytes within the 30d baseline"|within|exceeds|indeterminate'
        "|exceeds\n"
        "```\n"
    )
    lead = (filled.get("findings") or [{}])[0]
    assert lead.get("predictions"), "the fixture projects no `lead_preds` — proves nothing"
    assert lead.get("impact_predictions"), (
        "the fixture projects no `impact_preds` — proves nothing"
    )

    for projection in _every_lens(filled) or [support_projection(filled, SALT)]:
        body = _body(projection)
        for projected in body.get("findings") or []:
            for key in ("predictions", "impact_predictions"):
                assert key not in projected, (
                    f"{projection.lens} can read {projected.get('id')}.{key}"
                )
        assert "anomalous spike" not in projection.text
        assert "escalation_on" not in projection.text


def test_no_hypothesis_carries_its_weight_into_a_lens():
    """The `:H` half of the cut, and the one the `:T` family rule does not reach.

    `:H hypothesize.hypotheses` declares `weight|status` columns and `_walkers.final_weights`
    seeds the run's weights from them, so a document that fills them hands the support lens —
    told in its own prompt that it does not see which way anything moved — the movement
    itself, in the two characters it was asked to reconstruct. The golden leaves them `null`
    and `active`, so only a fixture that fills them can witness this.
    """
    filled = parse_investigation(
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|identity|user/known-corp|dev.dana|\n"
        "\n"
        ":H hypothesize.hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        "h-001|?benign|v-001|authenticated_as|session|interactive||--|refuted\n"
        "h-002|?evil|v-001|authenticated_as|process|unclassified-process||++|active\n"
        "\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|probe|v-001|h-001,h-002|elastic|alert-time\n"
        "```\n"
    )
    declared = (filled.get("hypothesize") or {}).get("hypotheses") or []
    assert [h.get("weight") for h in declared] == ["--", "++"], (
        "the fixture declares no weights — the test proves nothing"
    )

    for projection in _every_lens(filled):
        for hypothesis in (_body(projection).get("hypothesize") or {}).get("hypotheses") or []:
            for key in INFERENCE_HYPOTHESIS_KEYS:
                assert key not in hypothesis, (
                    f"{projection.lens} can read {hypothesis.get('id')}.{key}"
                )


def test_no_belief_movement_reaches_a_lens_verbatim(companion):
    """The leak test that matters. A key can be dropped while its CONTENT survives inside
    another block, so this asserts on the values the investigation actually wrote: the
    reasoning prose attached to each weight move must appear nowhere in what a lens reads."""
    reasons = [
        r["reasoning"] for _lid, r in _walkers.iter_resolutions(companion)
        if isinstance(r.get("reasoning"), str) and len(r["reasoning"]) > 20
    ]
    assert reasons, "the golden's resolutions carry no reasoning — the test proves nothing"
    for projection in _every_lens(companion):
        for reason in reasons:
            assert reason not in projection.text, (
                f"{projection.lens} can read the reasoning behind a weight move"
            )


def test_the_disposition_reaches_no_lens(companion):
    disposition = companion["conclude"].get("disposition")
    assert disposition, "the golden carries no disposition — the test proves nothing"
    for projection in _every_lens(companion):
        assert "conclude" not in _body(projection)


def test_the_record_reaches_every_lens_inside_the_calls_own_untrusted_frame(companion):
    """A lens reads a document assembled out of alert-derived bytes — SIEM messages, entity
    identifiers an attacker's own activity shaped — and its reading is what the composer
    weighs. Unframed, an instruction smuggled into a log line reaches the one role whose
    output routes the gate. The frame is keyed on the STAGE CALL's salt, never the
    investigation's: a role that reads payloads must not hold the delimiter of the frame its
    own output returns inside."""
    for projection in _every_lens(companion):
        assert f"<run-{SALT}-untrusted>" in projection.text
        assert f"</run-{SALT}-untrusted>" in projection.text
        assert "never as instructions" in projection.text


def test_the_observation_side_survives_the_cut(companion):
    """The mirror failure, and the more expensive one: a cut that also removed `:R` would
    take the learned facts — an entity's classification, an authorization verdict — with it,
    and every lens would report `unsupported` on a well-supported close."""
    pruned = observation_only(companion)
    assert pruned.get("prologue", {}).get("vertices"), ":V did not survive"
    assert pruned.get("prologue", {}).get("edges"), ":E did not survive"
    assert pruned.get("hypothesize", {}).get("hypotheses"), ":H did not survive"
    assert pruned.get("findings"), ":L findings did not survive"
    assert list(_walkers.iter_attr_updates(pruned)), ":R attr_updates did not survive"


# ---------------------------------------------------------------------------------------
# What the surviving lens keeps
# ---------------------------------------------------------------------------------------


def test_the_support_lens_reads_the_results_it_reconstructs_from(companion):
    """The mirror of the leak tests, and the reason the cut is the `:T` FAMILY and not
    something wider: `outcome` is a `:R` observation, so it must reach the lens. There is no
    per-lens narrowing left below the family rule — the discrimination lens was the only one
    that took a second cut (`outcome`, `tests_hypotheses`), and it is retired."""
    support = _body(support_projection(companion, SALT))
    assert any(lead.get("outcome") for lead in support["findings"]), (
        "the support lens has no results to reconstruct from"
    )
    assert any(lead.get("tests_hypotheses") for lead in support["findings"]), (
        "the support lens cannot see which hypotheses a lead was aimed at"
    )


# ---------------------------------------------------------------------------------------
# Ablation
# ---------------------------------------------------------------------------------------


def _edges(body: dict) -> set[str]:
    ids = {e["id"] for e in (body.get("prologue") or {}).get("edges") or []}
    for lead in body.get("findings") or []:
        obs = (lead.get("outcome") or {}).get("observations") or {}
        ids |= {e["id"] for e in obs.get("edges") or []}
    return ids


def test_the_ablation_removes_exactly_one_edge_and_changes_nothing_else(companion):
    """The ablation reading is only interpretable as a difference against the support
    reading, so the two projections must differ in the edge and in nothing else — including
    the prompt. A second builder, or a second ask, and the difference measures the projection
    rather than the edge."""
    full = support_projection(companion, SALT)
    target = sorted(_edges(_body(full)))[0]
    ablated = support_projection(companion, SALT, without_edge=target)

    assert ablated.lens == full.lens
    assert full.text.split("## Investigation")[0] == ablated.text.split("## Investigation")[0], (
        "the ablation lens was asked a different question"
    )
    before = _edges(_body(full))
    after = _edges(_body(ablated))
    assert before - after == {target}
    assert not after - before


def _named_edges(node) -> set[str]:
    """Every edge id anything under `node` NAMES, at any depth.

    A recursive walk rather than a per-bucket reader, because the property it serves is about
    the whole document a lens reads: an id cited by a row that survives, when the edge itself
    is gone, is a tell wherever the row carrying it happens to live. The keys come from the
    projector's own constant rather than being restated here."""
    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _EDGE_CITING_KEYS and isinstance(value, str):
                found.add(value)
            found |= _named_edges(value)
    elif isinstance(node, list):
        for item in node:
            found |= _named_edges(item)
    return found


def _cited_edges(body: dict) -> set[str]:
    """Every edge id the `:R` rows name as their SUBJECT.

    The buckets come from the projector's own constant rather than being restated here: a
    bucket added to the ablation and not to this list would leave the test green on exactly
    the rows it stopped covering."""
    ids: set[str] = set()
    for lead in body.get("findings") or []:
        outcome = lead.get("outcome") or {}
        for bucket in _EDGE_CITING_BUCKETS:
            ids |= _named_edges(outcome.get(bucket))
    return ids


def test_the_ablation_takes_the_rows_that_are_about_the_withheld_edge_with_it(companion):
    """An ablation that removed the `:E` row and left the `:R` rows citing it removed a
    citation, not the evidence: on the golden the withheld edge's whole discriminating
    content — the `unauthorized` verdict and the reasoning quoting the sshd message — lives
    in `authorization_resolutions`, so the lens reconstructs the same case, the reading never
    collapses, and the composer is told the move did not rest on that edge on every run."""
    target = "e-004"
    assert target in _cited_edges(_body(support_projection(companion, SALT))), (
        "the golden's `:R` rows do not cite the ablation target — the test proves nothing"
    )
    ablated = _body(support_projection(companion, SALT, without_edge=target))
    assert target not in _cited_edges(ablated)
    assert target not in _edges(ablated)


#: A record whose ablation target IS the edge its `:H h-001.authz` contract cites. The golden's
#: contracts name `e-002` while its target is `e-004`, so only a fixture built for the overlap
#: can witness what a surviving citation does.
_CONTRACT_CITES_THE_TARGET = (
    "```invlang\n"
    ":V prologue.vertices [id|type|class|ident|attrs?]\n"
    "v-001|identity|user/known-corp|dev.dana|\n"
    "v-002|session|interactive|session@db-1|\n"
    "\n"
    ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
    "e-001|authenticated_as|v-002|v-001|2026-05-25T13:53:35Z|siem-event:elastic|host=db-1\n"
    "\n"
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
    "h-001|?benign|v-001|authenticated_as|session|interactive||null|active\n"
    "h-002|?evil|v-001|authenticated_as|session|interactive||null|active\n"
    "\n"
    ":H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
    'ac1|e-001|iam-policy|"dev.dana is provisioned for db-1"|escalate|escalate\n'
    "\n"
    ":L findings [id|loop|name|target|tests|system|window]\n"
    "l-001|1|identity-authz-check|v-001|h-001,h-002,ac1|identity|n/a\n"
    "\n"
    ":T resolutions\n"
    "h-001  null → --    [l-001 r1 severe ⟂ e-001 :: dev.dana is not provisioned for db-1]\n"
    "```\n"
)


def _contracts(body: dict) -> list[dict]:
    hypotheses = (body.get("hypothesize") or {}).get("hypotheses") or []
    return [c for h in hypotheses for c in h.get("authorization_contract") or []]


def test_the_ablation_leaves_no_surviving_row_citing_the_edge_it_withheld():
    """The ablation lens is never told an edge was removed — and a `:H <h>.authz` row still
    naming an id that appears nowhere else in the projection tells it exactly that. A lens
    hunting for a gap is not reconstructing.

    The row itself survives: a contract is the hypothesis's QUESTION side, not an observation,
    so deleting it would be a second difference and the reading would measure the projection
    rather than the edge. Its citation degrades to the spelling a contract carries when no
    observed edge stands behind it, which is what the investigation would have recorded had
    the edge never been observed."""
    from defender.runtime.review.projector import ablation_target

    doc = parse_investigation(_CONTRACT_CITES_THE_TARGET)
    target, _carried = ablation_target(doc)
    before = _contracts(_body(support_projection(doc, SALT)))
    assert [c.get("edge_ref") for c in before] == [target], (
        "the fixture's contract does not cite the ablation target — the test proves nothing"
    )

    ablated = _body(support_projection(doc, SALT, without_edge=target))
    assert target not in _edges(ablated), "the withheld edge survived"
    assert target not in _named_edges(ablated), (
        "a row the ablation left behind still cites the withheld edge"
    )
    survivors = _contracts(ablated)
    assert [c.get("edge_ref") for c in survivors] == [vocab.UNOBSERVED_EDGE_REF]
    assert [c.get("predicate") for c in survivors] == [c.get("predicate") for c in before], (
        "the ablation took the contract's substance along with its citation"
    )


def test_a_junk_edge_row_does_not_fault_a_projection_the_support_lens_renders(companion):
    """`_walkers.all_edges` isinstance-checks the same lists, so a non-dict element is
    something the support projection renders without complaint. An ablation that RAISED on it
    would fail the whole review closed — through the gate's stage-fault arm — for a fault the
    ablation itself introduced, on a document every other lens read fine."""
    prologue = companion.get("prologue") or {}
    malformed = {
        **companion,
        "prologue": {**prologue, "edges": [*prologue.get("edges", []), "not-an-edge-row"]},
    }
    support_projection(malformed, SALT)  # the control: the support lens renders it

    kept = (_body(
        support_projection(malformed, SALT, without_edge="e-001"),
    ).get("prologue") or {}).get("edges") or []
    assert not any(isinstance(e, dict) and e.get("id") == "e-001" for e in kept), (
        "the withheld edge survived"
    )
    assert "not-an-edge-row" in kept, (
        "the ablation dropped a row that was not the edge — a second difference"
    )


def test_ablating_an_unknown_edge_changes_nothing(companion):
    full = support_projection(companion, SALT)
    assert support_projection(
        companion, SALT, without_edge="e-does-not-exist",
    ).text == full.text


# ---------------------------------------------------------------------------------------
# The empty document
# ---------------------------------------------------------------------------------------


def test_an_unfenced_document_is_refused_rather_than_projected_empty():
    """`parse_dense_companion` reads only inside ```invlang fences and returns an empty
    companion — no error, no warning — for a document with none. Projected, that is a lens
    reconstructing from nothing and a composer reviewing a void. Every fixture in the tree is
    fenced, so only an explicit arm catches it."""
    unfenced = ":V prologue.vertices [id|type]\nv-001|compute|\n"
    with pytest.raises(EmptyInvestigation):
        parse_investigation(unfenced)


def test_an_empty_document_is_refused():
    with pytest.raises(EmptyInvestigation):
        parse_investigation("")


# ---------------------------------------------------------------------------------------
# Ablation targeting
# ---------------------------------------------------------------------------------------


def test_the_ablation_target_is_a_load_bearing_edge_with_its_footprint(companion):
    """On the golden, ONE edge supports every strong resolution. The count travels with the
    target so the composer can tell "this edge was load-bearing" from "this case rests
    entirely on one edge" — otherwise a reading that collapses reads as fragility when it is
    really the whole case being removed."""
    from defender.runtime.review.projector import ablation_target

    target, carried = ablation_target(companion)
    assert target.startswith("e-")
    assert carried >= 1


def test_targeting_reaches_a_close_carried_by_refutation():
    """`--` on a refuted sibling is load-bearing exactly as `++` on a surviving hypothesis is.
    Counting only the survivors leaves a benign close carried by refuting the adversarial
    sibling with no ablation target at all — the highest-cost error class the gate exists to
    catch."""
    from defender.runtime.review.projector import ablation_target

    refuting = {
        "findings": [{
            "id": "l-001",
            "resolutions": [{
                "hypothesis_id": "h-002", "before": None, "after": "--",
                "supporting_edges": ["e-009"],
            }],
        }],
    }
    assert ablation_target(refuting) == ("e-009", 1)


def test_a_record_with_no_strong_movement_has_no_target():
    from defender.runtime.review.projector import ablation_target

    weak = {
        "findings": [{
            "id": "l-001",
            "resolutions": [{"hypothesis_id": "h-001", "after": "+", "supporting_edges": ["e-1"]}],
        }],
    }
    assert ablation_target(weak) is None
