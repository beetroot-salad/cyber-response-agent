"""#1546 (design r8) PR2/PR7/PR8 at the per-job helper's socket: every record a job sends is parsed, capped and screened
on receipt and staged as a closed typed fact (or `refused/<name>`); an object is accepted only when the fact that owes it is
staged; a write after the claim's reference ended is refused. Driven through the real helper over a container stand-in;
facts read from `jobs.staged_facts`, uploads from `jobs.uploads`, bytes from the real Garage."""
from __future__ import annotations

import asyncio
import json
import sys
import uuid

import pytest

from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures
from defender.tests.support.evidence._facts1546 import screened, sent_arm, sent_arms, sent_findings, sent_page, staged_arms, staged_knowledge
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._helper_evidence1546 import (
    INV_PROGRESS,
    LEARNING_PROGRESS,
    RUN_PAGE,
    EPISODE_PAGE,
    VALID,
    accepted,
    arm_page,
    closing,
    drive,
    facts,
    inv_outcome,
    learning_outcome,
    mutants,
    non_records,
    plant,
    put_object,
    send,
    spool_bytes,
    uploads,
)
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import execute

from defender.tests.support.jobs import _helper_evidence1546 as H  # noqa: E402

evidence_store = H.evidence_store
process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.openbao, pytest.mark.garage,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

PAGE = b"<html>the renderer's page</html>"
BUNDLE = b"bundle bytes " * 100
SMALL_OUTCOME = {"investigation": inv_outcome(), "learning": learning_outcome()}


def _refused(staged: dict, name: str) -> dict:
    body = staged.get(f"refused/{name}")
    assert isinstance(body, dict), (name, sorted(staged))
    assert isinstance(body.get("reason"), str), body
    assert body["reason"], body
    return body


# --- PR2: valid records are staged as sent -----------------------------------------------------------------------------

@pytest.mark.parametrize("case", sorted(VALID))
def test_a_valid_record_of_each_kind_is_staged_as_the_closed_shape_it_was(scene, evidence_store, case):
    """The control of every malformed-record case: a valid outcome/page/result, sent on its verb, is staged whole under its
    name, and no `refused/` fact exists. (PR2)"""
    kind, verb, record, name, want = VALID[case]
    planted = plant(scene, kind)
    got: dict = {}

    def job(c) -> int:
        got["answer"] = send(c, verb, record=record)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)
    assert staged[name] == want
    assert not [n for n in staged if n.startswith("refused/")], staged


@pytest.mark.parametrize("closing_state", [
    closing(), {"found": "never_closed"}, {"found": "could_not_look"}], ids=["found", "never_closed", "could_not_look"])
def test_an_investigation_outcome_carries_each_closing_lookup_result_through_staged(scene, evidence_store, closing_state):
    """`closing: found | never_closed | could_not_look` are each valid and staged as sent. (PR2)"""
    planted = plant(scene, "investigation")
    outcome = inv_outcome(closing=closing_state)
    drive(scene, planted, lambda c: send(c, "outcome", record=outcome) and 0, **evidence_store.seams)
    assert facts(scene.dsn, scene.claim)["outcome"] == outcome


def test_the_helper_stages_started_and_the_served_knowledge_itself(scene, evidence_store):
    """`started` and `knowledge` are the helper's own facts of an investigation, not the job's: staged with no job record. (PR2)"""
    planted = plant(scene, "investigation")
    drive(scene, planted, lambda c: 0, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)
    assert "started" in staged
    assert staged["knowledge"] == staged_knowledge(scene.t.commit)


# --- PR2: whole-class malformed records ------------------------------------------------------------------------------------

def _malformed_cases():
    out = []
    for case, (_kind, _verb, record, _name, _staged) in sorted(VALID.items()):
        pool = [*mutants(record, seed=1546, n=5), *non_records(seed=len(case), n=2)[:3]]
        for i, bad in enumerate(pool[:8]):
            out.append(pytest.param(case, bad, id=f"{case}-{i}"))
    return out


@pytest.mark.parametrize(("case", "bad"), _malformed_cases())
def test_a_malformed_outcome_page_or_result_is_staged_refused_and_owes_nothing(scene, evidence_store, case, bad):
    """A record of any malformed shape (a key dropped, an unknown key, a wrong type, non-records, raw bytes) on any verb is
    staged `refused/<name>{reason}` and never as `<name>`. (PR2, "Done when")"""
    kind, verb, _record, name, _staged = VALID[case]
    planted = plant(scene, kind)
    drive(scene, planted, lambda c: send(c, verb, record=bad) and 0, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)
    _refused(staged, name)
    assert name not in staged, "a malformed record was staged as a fact"
    assert uploads(scene.dsn, scene.claim) == {}


def test_a_record_missing_altogether_is_staged_refused(scene, evidence_store):
    """An `outcome` request carrying no record is a malformed record too. (PR2)"""
    planted = plant(scene, "investigation")
    drive(scene, planted, lambda c: send(c, "outcome") and 0, **evidence_store.seams)
    _refused(facts(scene.dsn, scene.claim), "outcome")


def test_a_malformed_progress_is_dropped_and_a_later_valid_one_still_lands(scene, evidence_store, caplog):
    """Every malformed `progress` is dropped (never staged, never `refused/progress`) and logged; a valid one after them
    lands, and a newer valid one replaces it (the one replaced fact). (PR2)"""
    planted = plant(scene, "investigation")
    bad = [*mutants(INV_PROGRESS, seed=7, n=6), *non_records(seed=3, n=4)]
    seen: dict = {}

    def job(c) -> int:
        for b in bad:
            send(c, "progress", record=b)
        seen["before"] = facts(scene.dsn, scene.claim).get("progress")
        send(c, "progress", record=INV_PROGRESS)
        send(c, "progress", record={"cost_usd": 0.7})
        return 0

    with caplog.at_level("INFO"):
        drive(scene, planted, job, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)
    assert seen["before"] is None, "a malformed progress was staged"
    assert "refused/progress" not in staged
    assert staged["progress"] == {"cost_usd": 0.7}
    assert caplog.records, "a dropped progress was not logged"


def test_a_learning_progress_of_today_s_shape_is_staged(scene, evidence_store):
    """A learning job's progress (`fork_message_id`, `stage`, `sibling_cost_usd`) is valid and staged as sent. (PR2)"""
    planted = plant(scene, "learning")
    drive(scene, planted, lambda c: send(c, "progress", record=LEARNING_PROGRESS) and 0, **evidence_store.seams)
    assert facts(scene.dsn, scene.claim)["progress"] == LEARNING_PROGRESS


def test_the_first_outcome_stays_the_fact_a_second_never_replaces_it(scene, evidence_store):
    """Facts are create-once by `(token, name)`: an outcome sent twice keeps the first. (PR2)"""
    planted = plant(scene, "investigation")
    first, second = inv_outcome(cost_usd=0.1), inv_outcome(cost_usd=9.0)

    def job(c) -> int:
        send(c, "outcome", record=first)
        send(c, "outcome", record=second)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert facts(scene.dsn, scene.claim)["outcome"] == first


# --- PR2: the learning findings screen ---------------------------------------------------------------------------------------

def _finding_row(job: str, n: int, **over) -> dict:
    from defender.tests.support.jobs._findings1487 import defender_row

    return defender_row(job, n, **over)


def _findings_text(finding=(), questioner=()) -> str:
    from defender.tests.support.jobs._findings1487 import text_of

    return text_of(list(finding), list(questioner))


def test_findings_that_pass_the_screen_are_staged_screened_by_channel(scene, evidence_store):
    """A learning outcome whose findings pass #1487's screen stages `findings = screened{rows by channel}`. (PR2, D11)"""
    planted = plant(scene, "learning")
    rows = [_finding_row(planted.owner, 0), _finding_row(planted.owner, 1)]
    outcome = learning_outcome(findings=sent_findings(_findings_text(rows)))
    drive(scene, planted, lambda c: send(c, "outcome", record=outcome) and 0, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)["outcome"]
    assert staged["findings"] == screened(*rows)
    assert staged["status"] == "completed"


@pytest.mark.parametrize("why", ["foreign-id", "not-a-row", "over-cap", "malformed-state"])
def test_findings_that_fail_the_screen_or_the_cap_are_staged_refused_inside_a_valid_outcome(scene, evidence_store, why):
    """Rows of another job's id, a non-object row, text over 8 MiB, or a findings field in a non-`ok` state: the outcome
    stays staged (status etc.) with `findings = refused{reason}`, never rows. (PR2, D11)"""
    planted = plant(scene, "learning")
    mine = planted.owner
    findings = {
        "foreign-id": sent_findings(_findings_text([_finding_row(str(uuid.uuid4()), 0)])),
        "not-a-row": sent_findings(json.dumps({"finding": ["text"], "questioner_finding": []})),
        "over-cap": sent_findings(_findings_text([_finding_row(mine, 0, subject_topic="x" * (8 * 1024 * 1024))])),
        "malformed-state": {"state": "malformed"},
    }[why]
    outcome = learning_outcome(findings=findings)
    drive(scene, planted, lambda c: send(c, "outcome", record=outcome) and 0, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)
    assert "refused/outcome" not in staged, "a findings refusal is inside a valid outcome"
    got = staged["outcome"]
    assert got["findings"]["state"] == "refused"
    assert got["findings"]["reason"]
    assert got["status"] == "completed"


# --- PR2: the arms roster and arm facts ----------------------------------------------------------------------------------------

def test_an_arm_fact_is_staged_only_for_a_run_on_the_roster_and_its_malformed_records_are_refused(scene, evidence_store):
    """`arm/<run id>` lands for a roster id and not for a stranger; a malformed record of a roster id is staged
    `refused/arm/<id>`, whatever its shape (generated). The roster itself is staged before arms. (PR2)"""
    planted = plant(scene, "learning")
    roster = [{"run_id": str(uuid.uuid4()), "world_id": str(uuid.uuid4())} for _ in range(14)]
    good, stranger = roster[0]["run_id"], str(uuid.uuid4())
    valid = sent_arm()
    bad = [*mutants(valid, seed=5, n=6), *non_records(seed=9, n=6)]

    def job(c) -> int:
        send(c, "arms", record=sent_arms(*[(a["run_id"], a["world_id"]) for a in roster]))
        send(c, "arm", run_id=good, record=valid)
        send(c, "arm", run_id=stranger, record=valid)
        for arm, b in zip(roster[1:], bad, strict=False):
            send(c, "arm", run_id=arm["run_id"], record=b)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)
    assert staged["arms"] == staged_arms(*[(a["run_id"], a["world_id"]) for a in roster])
    assert staged[f"arm/{good}"] == valid
    assert f"arm/{stranger}" not in staged
    for arm in roster[1:1 + len(bad)]:
        _refused(staged, f"arm/{arm['run_id']}")
        assert f"arm/{arm['run_id']}" not in staged


def test_an_arm_fact_before_any_roster_is_not_staged(scene, evidence_store):
    """With no `arms` roster staged no run is on it: an `arm/<id>` fact is not staged. (PR2)"""
    planted = plant(scene, "learning")
    run = str(uuid.uuid4())
    drive(scene, planted, lambda c: send(c, "arm", run_id=run, record=sent_arm()) and 0,
          **evidence_store.seams)
    assert f"arm/{run}" not in facts(scene.dsn, scene.claim)


# --- PR8: an object needs its fact --------------------------------------------------------------------------------------------

def _stored(scene, obj: str) -> str | None:
    return (uploads(scene.dsn, scene.claim).get(obj) or {}).get("status")


def test_a_bundle_put_before_any_outcome_is_refused_and_leaves_no_row_no_spool_and_no_object(scene, evidence_store):
    """With no `outcome` (or `refused/outcome`) staged, a `put` of the bundle is refused: no upload row, none of its bytes in
    the spool, nothing in the bucket; with the outcome staged the same put is accepted (control). (PR8)"""
    planted = plant(scene, "investigation")
    got: dict = {}

    def job(c) -> int:
        got["early"] = c.refused("evidence.put", object="bundle", part=0, last=True, data=BUNDLE)
        got["spool_early"] = spool_bytes(scene)
        send(c, "outcome", record=inv_outcome())
        got["late"] = put_object(c, "bundle", BUNDLE)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert got["early"].code
    assert BUNDLE not in got["spool_early"]
    assert got["late"], "control: the put after the outcome was refused"
    assert uploads(scene.dsn, scene.claim)["bundle"]["status"] == "uploaded"
    assert len(evidence_store.garage.list(f"t/{scene.tenant}/")) == 1


def test_a_refused_outcome_still_owes_the_bundle_so_the_bundle_is_accepted(scene, evidence_store):
    """After a malformed outcome (`refused/outcome`) the bundle is kept for debugging: its put is accepted and uploaded. (PR8)"""
    planted = plant(scene, "investigation")

    def job(c) -> int:
        send(c, "outcome", record={"setup": ["no"]})
        put_object(c, "bundle", BUNDLE)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert "refused/outcome" in facts(scene.dsn, scene.claim)
    assert _stored(scene, "bundle") == "uploaded"


@pytest.mark.parametrize("page_state", [None, "rendered", "render_failed", "none"])
def test_an_investigation_page_is_accepted_only_with_its_page_fact_rendered(scene, evidence_store, page_state):
    """The run page needs a `page` fact with `page = rendered`: absent, `render_failed` or `none` refuse the put and leave no
    row; `rendered` accepts it. The bundle (outcome staged) is the control on the same channel. (PR8, D14)"""
    planted = plant(scene, "investigation")
    got: dict = {}

    def job(c) -> int:
        send(c, "outcome", record=inv_outcome())
        if page_state is not None:
            send(c, "page", record=sent_page(page_state))
        got["page"] = send(c, "evidence.put", object=RUN_PAGE, part=0, last=True, data=PAGE)
        put_object(c, "bundle", BUNDLE)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert _stored(scene, "bundle") == "uploaded", "control"
    if page_state == "rendered":
        assert _stored(scene, RUN_PAGE) == "uploaded"
    else:
        assert _stored(scene, RUN_PAGE) is None
        assert isinstance(got["page"], __import__("defender.job_host", fromlist=["Refused"]).Refused)


@pytest.mark.parametrize("arm_state", [None, "rendered", "render_failed", "none"])
def test_an_arm_page_is_accepted_only_with_its_arm_fact_rendered(scene, evidence_store, arm_state):
    """A learning job's arm page needs its `arm/<id>` fact with `page = rendered`; with no fact, or another page state, the put
    is refused and leaves no row; the episode page (outcome staged) is the control. (PR8, D3, D14)"""
    planted = plant(scene, "learning")
    arm, world = str(uuid.uuid4()), str(uuid.uuid4())

    def job(c) -> int:
        send(c, "arms", record=sent_arms((arm, world)))
        if arm_state is not None:
            send(c, "arm", run_id=arm, record=sent_arm("clean", arm_state))
        send(c, "evidence.put", object=arm_page(arm), part=0, last=True, data=PAGE)
        send(c, "outcome", record=learning_outcome())
        put_object(c, EPISODE_PAGE, PAGE)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert _stored(scene, EPISODE_PAGE) == "uploaded", "control"
    assert (_stored(scene, arm_page(arm)) == "uploaded") == (arm_state == "rendered")


def test_the_episode_page_needs_the_learning_outcome(scene, evidence_store):
    """A learning job's episode page and bundle are refused before its outcome (or `refused/outcome`) is staged. (PR8)"""
    planted = plant(scene, "learning")
    got: dict = {}

    def job(c) -> int:
        got["page"] = c.refused("evidence.put", object=EPISODE_PAGE, part=0, last=True, data=PAGE)
        got["bundle"] = c.refused("evidence.put", object="bundle", part=0, last=True, data=BUNDLE)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert got["page"].code
    assert got["bundle"].code
    assert uploads(scene.dsn, scene.claim) == {}


# --- PR7 at the helper: the write fence -----------------------------------------------------------------------------------------

def _end_by_cancel(scene, planted) -> None:
    from defender.tests.support.jobs._jobs1342 import job_store

    async def go() -> None:
        async with job_store(scene.dsn) as store:
            await store.cancel_investigation(scene.tenant, planted.owner, actor="u-1")

    asyncio.run(go())


def _end_by_take_over(scene, planted) -> None:
    from defender.tests.support.jobs._jobs1342 import job_store

    execute(scene.dsn, f"UPDATE jobs.{planted.owner_table} SET lease_expires_at = now() - interval '1 second' "  # noqa: S608
                       "WHERE id = %s", (planted.owner,))

    async def go() -> None:
        async with job_store(scene.dsn) as store:
            await store.take_over()

    asyncio.run(go())


@pytest.mark.parametrize("ender", ["cancel", "take-over", "learning-take-over"])
def test_a_write_after_the_references_end_is_refused_and_one_before_it_was_not_lost(scene, evidence_store, ender):
    """The job stages `progress` and puts a small object before its owner row ends (by the store's own cancel or take-over) and
    again after: the facts staged before stand and the late `progress`, `arms` and put leave no new fact; no upload row
    is made for the late put and nothing is promoted. Codes and lock mode are not pinned. (PR7)"""
    kind = "learning" if ender == "learning-take-over" else "investigation"
    planted = plant(scene, kind)
    seen: dict = {}
    early = LEARNING_PROGRESS if kind == "learning" else INV_PROGRESS
    late = {**LEARNING_PROGRESS, "sibling_cost_usd": 5.0} if kind == "learning" else {"cost_usd": 5.0}

    def job(c) -> int:
        send(c, "progress", record=early)
        send(c, "outcome", record=SMALL_OUTCOME[kind])
        put_object(c, "bundle", BUNDLE)
        seen["before"] = facts(scene.dsn, scene.claim)
        (_end_by_cancel if ender == "cancel" else _end_by_take_over)(scene, planted)
        send(c, "progress", record=late)
        send(c, "arms", record=sent_arms())
        send(c, "evidence.put", object=EPISODE_PAGE if kind == "learning" else RUN_PAGE, part=0, last=True, data=PAGE)
        seen["after"] = facts(scene.dsn, scene.claim)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert "progress" in seen["before"], "control: the writes before the end landed"
    assert "outcome" in seen["before"], "control: the writes before the end landed"
    assert seen["after"] == seen["before"], "a fact was written after the reference ended"
    rows = uploads(scene.dsn, scene.claim)
    assert set(rows) <= {"bundle"}, f"an upload row was written after the end: {sorted(rows)}"
    assert accepted(scene.dsn, scene.claim) == [], "the helper promoted (only the applier may, PR3)"
