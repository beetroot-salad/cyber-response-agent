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
    DISCRIMINATION_WITHHELD_LEAD_KEYS,
    INFERENCE_COMPANION_KEYS,
    INFERENCE_LEAD_KEYS,
    EmptyInvestigation,
    discrimination_projection,
    observation_only,
    parse_investigation,
    support_projection,
)
from defender.skills.invlang import _walkers
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)

DEFENDER = Path(__file__).resolve().parents[1]
GOLDEN = DEFENDER / "fixtures-e2e" / "golden-sshpivot-ab3" / "investigation.md"


@pytest.fixture(scope="module")
def companion():
    return parse_investigation(GOLDEN.read_text(encoding="utf-8"))


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


def test_no_belief_movement_reaches_a_lens_verbatim(companion):
    """The leak test that matters. A key can be dropped while its CONTENT survives inside
    another block, so this asserts on the values the investigation actually wrote: the
    reasoning prose attached to each weight move must appear nowhere in what a lens reads."""
    reasons = [
        r["reasoning"] for _lid, r in _walkers.iter_resolutions(companion)
        if isinstance(r.get("reasoning"), str) and len(r["reasoning"]) > 20
    ]
    assert reasons, "the golden's resolutions carry no reasoning — the test proves nothing"
    for projection in (discrimination_projection(companion), support_projection(companion)):
        for reason in reasons:
            assert reason not in projection.text, (
                f"{projection.lens} can read the reasoning behind a weight move"
            )


def test_the_disposition_reaches_no_lens(companion):
    disposition = companion["conclude"].get("disposition")
    assert disposition, "the golden carries no disposition — the test proves nothing"
    for projection in (discrimination_projection(companion), support_projection(companion)):
        body = json.loads(projection.text.split("## Investigation (host-rendered)\n", 1)[1])
        assert "conclude" not in body


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
# Per-lens narrowing
# ---------------------------------------------------------------------------------------


def test_the_discrimination_lens_is_not_handed_its_own_answer(companion):
    """It is asked what a lead could separate. `tests_hypotheses` is the investigation's own
    answer to that, and it sits on the `:L` side of the tag cut, so the family rule alone
    does not withhold it."""
    projection = discrimination_projection(companion)
    body = json.loads(projection.text.split("## Investigation (host-rendered)\n", 1)[1])
    for lead in body.get("findings") or []:
        for key in DISCRIMINATION_WITHHELD_LEAD_KEYS:
            assert key not in lead, f"{lead.get('id')}.{key} reached the discrimination lens"


def test_the_support_lens_reads_the_results_the_discrimination_lens_cannot(companion):
    support = json.loads(
        support_projection(companion).text.split("## Investigation (host-rendered)\n", 1)[1]
    )
    assert any(lead.get("outcome") for lead in support["findings"]), (
        "the support lens has no results to reconstruct from"
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
    full = support_projection(companion)
    target = sorted(_edges(json.loads(
        full.text.split("## Investigation (host-rendered)\n", 1)[1])))[0]
    ablated = support_projection(companion, without_edge=target)

    assert ablated.lens == full.lens
    assert full.text.split("## Investigation")[0] == ablated.text.split("## Investigation")[0], (
        "the ablation lens was asked a different question"
    )
    before = _edges(json.loads(full.text.split("## Investigation (host-rendered)\n", 1)[1]))
    after = _edges(json.loads(ablated.text.split("## Investigation (host-rendered)\n", 1)[1]))
    assert before - after == {target}
    assert not after - before


def test_ablating_an_unknown_edge_changes_nothing(companion):
    full = support_projection(companion)
    assert support_projection(companion, without_edge="e-does-not-exist").text == full.text


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
