"""#983 e2e — the four outcome-level demands, driven through the real close.

Unit tests can show that a vocabulary member exists and that a check refuses a row. What they
cannot show is the thing #983 is actually for: that a container-root alert with an authored
registry entry behind it reaches `disposition: benign` through `close_investigation`, and that
the three ways of faking that entry do not. Those are close-level outcomes — the entry price is
collected at the close as well as at the write gate, and `report.md` is written from the close's
own argument — so each scenario is driven end to end through `driver.run_investigation` on the
shared replay harness.

The document is the SHARED container-root scene (`tests/_tacit983.py`); each scenario moves one
cell. The registry lookup itself is NOT dispatched here: gather is not driven in these scripts,
the model authors the `:R authz` row the way a real run does after its lead comes back, and
the adapter's own semantics (expiry, scope containment, the no-wildcard load) are pinned in
`tests/test_tacit_knowledge_registry_983.py`. What this suite owns is what the CLOSE does with
the row once it is written.

`drive` defaults its review-stage bundle to a hermetic composer that finds `holds`, so a benign
close — a CONFIDENT disposition, and therefore a reviewed one — runs the whole gate without a
provider. That matters here beyond hermeticity: `benign` takes the POST-REVIEW `_CloseFields`
construction site, which is the one the `ceiling_test` carrier never reaches (claim c11), so a
mechanism-A field populated only on the no-review branch would pass every unit test and fail
`test_runtime_evidence_lands_in_a_benign_report_body` alone.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from defender.skills.invlang.frontier import frontier_from_text
from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import validate_companion
from defender.tests import _tacit983 as scene
from defender.tests.e2e._replay_harness import (
    GOLDEN,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e


def _run(tmp_path: Path, doc: str, disposition: str, *, run_id: str):
    """Land `doc` as the run's `investigation.md` through MAIN's own writer, then close.

    `append_block` rather than a seeded file: the write gate — invlang validation included —
    is half of what these scenarios are about, and a document staged around it would let a
    refusal the gate WOULD have made read as a close that succeeded."""
    run_dir = materialize(tmp_path, GOLDEN)
    replay = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": doc})]),
        Turn(tool_calls=[("close_investigation", {"disposition": disposition})]),
        Turn(text="Investigation complete."),
    ])
    drive(run_dir, run_id=run_id, main=replay)
    return run_dir, replay


def _investigation(run_dir: Path, replay: ReplayFn) -> str:
    """The committed `investigation.md`, or a failure naming what the write gate said.

    Read through a helper rather than inline, because the interesting failure here is the gate
    REFUSING the document and the bare `FileNotFoundError` a direct read raises says nothing
    about which rule refused it."""
    path = run_dir / "investigation.md"
    assert path.is_file(), (
        f"nothing was committed — the write gate refused the document. Feedback the model "
        f"received:\n{_feedback(replay)[-2000:]}"
    )
    return path.read_text(encoding="utf-8")


def _committed_disposition(run_dir: Path) -> str | None:
    report = run_dir / "report.md"
    if not report.is_file():
        return None
    m = re.search(r"^disposition:\s*(\S+)", report.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else None


def _feedback(replay: ReplayFn) -> str:
    """Everything the model was told across the run — where a gate's refusal lands."""
    return "\n".join(replay.seen)


# ---------------------------------------------------------------- O1: benign becomes reachable


def test_registry_hit_lets_a_container_root_case_close_benign(tmp_path):
    """A live hypothesis whose only open authz contract is matched by an unexpired,
    scope-matching registry entry pays benign's entry price and closes `benign` — without any
    row asserting a registry hit that did not happen (demand `benign_reachable_on_registry_hit`).

    THE issue's case: 50 identical events a day for 30 days from container UID 0, closed
    `inconclusive` every time because no identity system in this deployment holds a record for
    that actor (claim c7, accepted as given). The registry entry is what changes, and nothing
    else about the run does: the same document, the same gates, the same review.

    Deliberately NOT routing the contract to whatever identity became root so a real identity
    check becomes possible — that is a hypothesis/lead-design question and is out of scope
    here (non-obligation 1)."""
    doc = scene.benign_document(
        rows=scene.authz_block(scene.authz_row()) + "\n"
        + scene.consult_block(scene.consultation_row()),
    )
    run_dir, replay = _run(tmp_path, doc, "benign", run_id="tacit-benign")

    assert replay.calls == 3, (
        f"the run stopped early ({replay.calls}/3) — a gate denied something:\n{_feedback(replay)}"
    )
    produced = _investigation(run_dir, replay)
    assert validate_companion(produced, None) == []
    assert _committed_disposition(run_dir) == "benign", (
        "a container-root case with an authored registry entry behind it still could not "
        "close benign — O1's failure, unchanged"
    )

    assert frontier_from_text(produced).contracts == (), (
        "the discharged contract is still on the retrieval frontier, so the run would be "
        "pushed back to re-ask a question an authored registry entry already answered"
    )


def test_runtime_evidence_lands_in_a_benign_report_body(tmp_path):
    """A benign close's `report.md` BODY carries one line per qualifying `:R consultations` row,
    so a human reading the closed case can see whether the alerted pattern is recognized as
    recurring in this estate (demand `consultation_reaches_report_body`, fork F4 / RF1).

    Driven through the REVIEWED close on purpose. `benign` is a confident disposition, so it
    takes the post-challenge-gate `_CloseFields(...)` — the construction site that omits
    `ceiling_test` entirely and takes the `= ()` default. A baseline field populated the way
    `ceiling_test` is would be empty here, which is exactly the gap RF1 found in the design's
    "not a new architecture" claim, and exactly the disposition O3 needs it on."""
    doc = scene.benign_document(
        rows=scene.authz_block(scene.authz_row()) + "\n"
        + scene.consult_block(scene.consultation_row()),
    )
    run_dir, replay = _run(tmp_path, doc, "benign", run_id="tacit-benign-body")

    _investigation(run_dir, replay)
    assert (run_dir / "report.md").is_file(), f"the close was refused:\n{_feedback(replay)[-2000:]}"
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    head, _, body = report.partition("---\n")[2].partition("---\n")
    assert "runtime-evidence" in body, (
        "the baseline consultation did not reach the committed report's body — O3's gap "
        "(the density the agent already computes never reaching report.md) is unchanged"
    )
    assert scene.WINDOW_BEFORE_ALERT in body, "the window did not travel with it"
    assert "runtime-evidence" not in head, (
        "the baseline reached the FRONTMATTER, which is capped at 512 bytes and gates things"
    )


def test_runtime_evidence_lands_in_an_inconclusive_report_body(tmp_path):
    """...and on the OTHER `_CloseFields` construction site too.

    `inconclusive` skips the review and commits from the `NO_REVIEW_DISPOSITIONS` branch. Both
    sites, because mechanism A's whole point is visibility on every close and a field wired at
    one site is a field that reports the baseline for half the corpus."""
    doc = scene.inconclusive_document(rows=scene.consult_block(scene.consultation_row()))
    run_dir, replay = _run(tmp_path, doc, "inconclusive", run_id="tacit-inconclusive-body")

    _investigation(run_dir, replay)
    assert (run_dir / "report.md").is_file(), f"the close was refused:\n{_feedback(replay)[-2000:]}"
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    body = report.partition("---\n")[2].partition("---\n")[2]
    assert "runtime-evidence" in body
    assert "ceiling_test" in body, (
        "the existing ceiling_test note lane stopped working — the new field displaced it "
        "rather than sitting beside it"
    )


# ---------------------------------------------------------------- O2: the three fakes


def test_expired_entry_falls_through_to_indeterminate(tmp_path):
    """An entry whose `review_by` is in the past does not discharge: the lookup is simply no
    hit, and the contract falls through to `indeterminate` exactly as on any other registry
    miss — never to `unauthorized`, and never to a stale `authorized`
    (demand `expired_entry_does_not_discharge`).

    `indeterminate`, not `unauthorized`: an expired sanction says nothing about whether the
    action is permitted, only that nobody has re-attested it. Writing `unauthorized` here would
    escalate every action whose sanction simply aged out.

    The run's own attempt at `benign` is refused, and the refusal is asserted on the FEEDBACK
    the model got as well as on the absent report — a close that silently did nothing and a
    close that was refused with a reason are different runs, and only one of them is repairable."""
    doc = scene.document(
        rows=scene.authz_block(scene.authz_row(
            verdict="indeterminate", grounding="", anchor_id="", basis="retry",
            reasoning="registry entry tk-ca-bundle-build-runner expired 2026-04-15; no hit",
        )),
        settled=False,
    )
    run_dir, replay = _run(tmp_path, doc, "benign", run_id="tacit-expired")

    produced = _investigation(run_dir, replay)
    assert validate_companion(produced, None) == [], (
        "the expired-entry document is well formed — recording the miss is legal"
    )
    assert "authorized" not in _authz_verdicts(produced), (
        "a stale registry entry produced an `authorized` verdict"
    )
    assert "unauthorized" not in _authz_verdicts(produced), (
        "an expired sanction was read as a refusal rather than as no answer"
    )

    assert _committed_disposition(run_dir) != "benign", (
        "an expired registry entry bought a benign close"
    )
    assert "ac1" in _feedback(replay), (
        "the close was refused without naming the contract that is still open — the model has "
        "nothing to repair"
    )


def test_recurrence_alone_never_authorizes(tmp_path):
    """A dense, long-running occurrence pattern with NO registry entry behind it produces no
    `authorized` verdict and no benign close — a patient adversary's month of quiet activity
    cannot self-authorize (demand `no_statistical_self_authorization`, O2).

    THE regression guard of this whole change, and the one a corner-cutting implementation
    would most want to fake: the discarded middle design had raw telemetry recurrence grounding
    authorization directly, and it was discarded because it cannot tell established practice
    from an ongoing bad habit nobody has caught. The consultation here is as strong as a
    baseline gets — 1500 occurrences over 30 days, one actor, one host, nothing adverse inside
    the window, and the window closes before the alert — and it still buys nothing.

    The contract is a `tacit-knowledge` one: this is the container-root case with the registry
    QUERIED and empty, which is the only honest way to reach the shape the guard is about."""
    doc = scene.document(rows=scene.consult_block(scene.consultation_row()), settled=False)
    run_dir, replay = _run(tmp_path, doc, "benign", run_id="tacit-recurrence")

    produced = _investigation(run_dir, replay)
    assert validate_companion(produced, None) == [], (
        "recording the baseline is legal — it is context, and refusing it would delete O3"
    )
    assert _authz_verdicts(produced) == [], "the document records no authz verdict at all"

    assert _committed_disposition(run_dir) is None, (
        "a benign close committed on a baseline consultation alone — the type with no "
        "`fulfills_contract` field discharged a contract"
    )
    assert "ac1" in _feedback(replay)
    assert [c.contract_id for c in frontier_from_text(produced).contracts] == ["ac1"], (
        "the unanswered contract left the retrieval frontier, so nothing pushes the run to "
        "keep working it"
    )


def test_exhausted_contract_is_not_looped_back_but_still_escalates(tmp_path):
    """An `indeterminate` contract carrying `basis=exhausted` leaves `verdict` and the forced
    escalation exactly as they are, and only stops being re-dispatched
    (demands `exhausted_is_not_redispatched` + `indeterminate_escalation_unchanged`, O4).

    Both halves in one run, because the demand is a PAIR and asserting either alone admits the
    build that gets the other backwards: a `basis` that also discharged the contract would
    satisfy "not re-dispatched" perfectly."""
    row = scene.authz_row(
        verdict="indeterminate", grounding="", anchor_id="", basis="exhausted",
        reasoning="every anchor kind applicable to this predicate was queried; none answered",
    )
    doc = scene.inconclusive_document(rows=scene.authz_block(row))
    run_dir, replay = _run(tmp_path, doc, "inconclusive", run_id="tacit-exhausted")

    produced = _investigation(run_dir, replay)
    assert validate_companion(produced, None) == []
    assert _committed_disposition(run_dir) == "inconclusive", (
        "`basis=exhausted` changed what the run commits — it may only change whether the run "
        "loops back"
    )
    assert frontier_from_text(produced).contracts == (), (
        "a contract no registry in this deployment can ever answer is still being handed back "
        "for another retrieval loop — O4's burned loop"
    )


def _authz_verdicts(text: str) -> list[str]:
    from defender.skills.invlang import _walkers

    companion, _ = parse_dense_companion(text)
    return [
        row.get("verdict", "") for row in _walkers.iter_authz_resolutions(companion)
    ]
