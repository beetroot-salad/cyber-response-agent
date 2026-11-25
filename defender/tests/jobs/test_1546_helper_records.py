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
from defender.tests.support.evidence._facts1546 import (
    ARM_RUN,
    ARM_WORLD,
    VERB_ARM,
    VERB_ARMS,
    screened,
    sent_arm,
    sent_arms,
    sent_findings,
    sent_page,
    staged_arms,
    staged_knowledge,
    up,
)
from defender.tests.support.jobs._ending1546 import decide
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
    uploads,
)
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import execute

from defender.tests.support.jobs import _helper_evidence1546 as H  # noqa: E402
from defender.tests.jobs import test_adoption_helper_1471 as ADOPT  # noqa: E402 — the adoption code-tree fixture

evidence_store = H.evidence_store
checkout = ADOPT.checkout
process_state = J.process_state
scene = H.fresh_scene

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

def _base_files_for(request, kind: str) -> None:
    """An adoption's helper refuses at setup unless its system's adapter ships base files: plant them (as the folders tests do)."""
    if kind == "adoption":
        request.getfixturevalue("checkout")


def _send_record(c, verb: str, record):
    """The job's send of one record on its verb (an `arm` after the roster naming it, as a job does)."""
    if verb == VERB_ARM:
        send(c, VERB_ARMS, record=sent_arms((ARM_RUN, ARM_WORLD)))
        return send(c, verb, run_id=ARM_RUN, record=record)
    return send(c, verb, record=record)


@pytest.mark.parametrize("case", sorted(VALID))
def test_a_valid_record_of_each_kind_is_staged_as_the_closed_shape_it_was(request, scene, evidence_store, case):
    """The control of every malformed-record case: a valid outcome/page/arms/arm/result record of its kind, sent on
    its verb, is staged whole under its name, and no `refused/` fact exists. (PR2)"""
    kind, verb, record, name, want = VALID[case]
    _base_files_for(request, kind)
    planted = plant(scene, kind)
    drive(scene, planted, lambda c: _send_record(c, verb, record) and 0, **evidence_store.seams)
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


@pytest.mark.parametrize("word", ["proxy-access", "provider-down", "box-lost"])
def test_an_investigation_outcome_carries_each_run_end_word_as_cut_short_through_staged(scene, evidence_store, word):
    """A run cut short sends its run-end word (`run_end.TRUNCATED_BY_VALUES`) as `cut_short`: the helper stages the outcome
    as sent, word whole, and refuses nothing (#1363 B6's record half, moved from the job-end file to the staged fact;
    the worker's reading of it is `test_proxy_access_run_end::test_1363_b6_*`). (PR2)"""
    from defender.records import run_end

    assert word in run_end.TRUNCATED_BY_VALUES, "premise: a run-end word"
    planted = plant(scene, "investigation")
    outcome = inv_outcome(report_committed=False, closing=None, scrub="not_run", cut_short=word)
    drive(scene, planted, lambda c: send(c, "outcome", record=outcome) and 0, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)
    assert staged["outcome"] == outcome
    assert not [n for n in staged if n.startswith("refused/")], staged


def test_the_helper_stages_started_and_the_served_knowledge_itself(scene, evidence_store):
    """`started` and `knowledge` are the helper's own facts of an investigation, not the job's: staged with no job record. (PR2)"""
    planted = plant(scene, "investigation")
    drive(scene, planted, lambda c: 0, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)
    assert "started" in staged
    assert staged["knowledge"] == staged_knowledge(scene.t.commit)


# --- PR2: whole-class malformed records ------------------------------------------------------------------------------------

#: The kinds' `decide` input (a host request's three kinds are one).
DECIDE_KIND = {"investigation": "investigation", "learning": "learning", "readiness": "host_request",
               "adoption": "host_request", "drain": "host_request"}


def _is_still_valid(case: str, valid: dict, bad) -> bool:
    """`bad` is the valid record itself: the one mutant that is no malformed record. (r10 (f): the nullable keys were the
    readiness `knowledge` record's, whose verb is gone.)"""
    return bad == valid


def _malformed_cases():
    """Every (kind, record name) of `VALID` crossed with records near its valid one and records of no kind; a record that is a
    bare int (a drain's `result`) gets the values that are no int."""
    out = []
    for case, (_kind, _verb, record, _name, _staged) in sorted(VALID.items()):
        scalars = non_records(seed=len(case), n=2)
        picks = [scalars[i] for i in (0, 5, 7, 8, 11, 14)]  # None, 3.5, "outcome", [], {"x": 1}, b"{}"
        if isinstance(record, dict):
            pool = [b for b in mutants(record, seed=1546, n=0) if not _is_still_valid(case, record, b)][:5] + picks[:3]
        else:
            pool = [*picks, "0", [0], {"status": 0}, 3.5]
        for i, bad in enumerate(pool):
            out.append(pytest.param(case, bad, id=f"{case}-{i}"))
    return out


@pytest.mark.parametrize(("case", "bad"), _malformed_cases())
def test_a_malformed_record_of_any_kind_and_name_is_staged_refused_and_a_refused_outcome_or_result_reads_bad_record(
        request, scene, evidence_store, case, bad):
    """Whole class, every kind by every record name (outcome, page, arms, arm, result): a malformed
    record is staged `refused/<name>{reason}`, never `<name>`, and owes nothing; a refused `outcome` or `result` reads
    `bad_record` in the ending. (PR2, PR9, "Done when": every kind)"""
    kind, verb, _record, name, _staged = VALID[case]
    _base_files_for(request, kind)
    planted = plant(scene, kind)

    def job(c) -> int:
        if verb == VERB_ARM:
            send(c, VERB_ARMS, record=sent_arms((ARM_RUN, ARM_WORLD)))
            send(c, verb, run_id=ARM_RUN, record=bad)
        else:
            send(c, verb, record=bad)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)
    _refused(staged, name)
    assert name not in staged, "a malformed record was staged as a fact"
    assert uploads(scene.dsn, scene.claim) == {}
    if name in ("outcome", "result"):
        end = decide(DECIDE_KIND[kind], staged, {}, "exited")
        assert (end.stage, end.failure_reason) == ("failed", "bad_record"), (end.stage, end.failure_reason)


# --- PR2: whole-class records the store cannot hold ----------------------------------------------------------------------

#: Text the store cannot hold (JSONB refuses `\u0000` and a lone surrogate): each text position gets each, appended.
UNSTORABLE_TEXT = {"nul": "\x00", "lone-surrogate": "\ud800"}
#: Numbers the store cannot hold (no JSON number is NaN or infinite; an int past float range overflows a float column).
UNSTORABLE_NUMBER = {"nan": float("nan"), "infinity": float("inf"), "past-float-range": 10**400}
#: Positions left out of the walk, with why: `findings.text` is the findings screen's raw input, parsed and never stored as
#: sent (its unscreenable text is `findings: refused` inside a valid outcome, pinned by the findings tests below).
NOT_STORED_AS_SENT = {("learning-outcome", ("findings", "text"))}
#: Positions screened by their own field's rule as well: a learning outcome's `findings` field that is not `{state: ok, text}`
#: may be `findings: refused{reason}` inside a valid outcome (the findings tests below) rather than the whole outcome refused;
#: either holds only what the store can hold, and neither is the sent value.
SCREENED_BY_ITS_FIELD = {("learning-outcome", "findings")}


def _positions(value, path=()):
    """Every (path, kind) of `value`: `text`, `number` and `null` leaves, `empty-list` leaves and `object` levels (a key
    position). A bool is no position: it has no unstorable member of its own type."""
    if isinstance(value, dict):
        yield path, "object"
        for key, member in value.items():
            yield from _positions(member, (*path, key))
    elif isinstance(value, list):
        if not value:
            yield path, "empty-list"
        for i, member in enumerate(value):
            yield from _positions(member, (*path, i))
    elif isinstance(value, str):
        yield path, "text"
    elif value is None:
        yield path, "null"
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield path, "number"


def _replaced(value, path, new):
    """`value` with the member at `path` replaced by `new(old)` (copies along the path; `value` is untouched)."""
    if not path:
        return new(value)
    head, rest = path[0], path[1:]
    if isinstance(value, dict):
        return {**value, head: _replaced(value[head], rest, new)}
    return [_replaced(m, rest, new) if i == head else m for i, m in enumerate(value)]


def _members_for(where: str) -> dict[str, object]:
    """The replacements (label -> `old -> new`) a position of kind `where` gets: a text each unstorable text appended, a
    number each unstorable number, a null (a nullable field, text or number) each of both, an empty list one element of
    each, and an object level a key holding each unstorable text."""
    texts = {label: (lambda old, bad=bad: old + bad) for label, bad in UNSTORABLE_TEXT.items()}
    numbers = {label: (lambda _old, bad=bad: bad) for label, bad in UNSTORABLE_NUMBER.items()}
    fresh_texts = {label: (lambda _old, bad=bad: f"text{bad}") for label, bad in UNSTORABLE_TEXT.items()}
    elements = {f"element-{label}": (lambda _old, bad=bad: [bad])
                for label, bad in {**{k: f"text{v}" for k, v in UNSTORABLE_TEXT.items()}, **UNSTORABLE_NUMBER}.items()}
    keys = {f"key-{label}": (lambda old, bad=bad: {**old, f"key{bad}": 1}) for label, bad in UNSTORABLE_TEXT.items()}
    return {"text": texts, "number": numbers, "null": {**numbers, **fresh_texts}, "empty-list": elements,
            "object": keys}[where]


def _unstorable(record):
    """(path, label, record) for every position of `record` crossed with every member the store cannot hold that fits it
    (`_members_for`)."""
    for path, where in _positions(record):
        at = ".".join(map(str, path)) or "record"
        for label, new in _members_for(where).items():
            yield path, f"{at}-{label}", _replaced(record, path, new)


def _unstorable_cases():
    """Every `VALID` case (every kind by every record name) crossed with `_unstorable` of its valid record."""
    return [pytest.param(case, bad, (case, path[:1] and path[0]) in SCREENED_BY_ITS_FIELD, id=f"{case}-{label}")
            for case, (_kind, _verb, record, _name, _staged) in sorted(VALID.items())
            for path, label, bad in _unstorable(record) if (case, path) not in NOT_STORED_AS_SENT]


def test_the_unstorable_cases_reach_every_kind_and_every_position_kind():
    """The generator's own premise: every `VALID` case has cases, and text, number, null, list and key positions all occur."""
    cases = {p.values[0] for p in _unstorable_cases()}
    assert any(p.values[2] for p in _unstorable_cases()), "premise: findings positions are generated"
    assert cases == set(VALID), set(VALID) - cases
    ids = " ".join(p.id for p in _unstorable_cases())
    for label in (*UNSTORABLE_TEXT, *UNSTORABLE_NUMBER, "key-nul", "element-nul", "summary-nul", "cost_usd-past-float-range",
                  "message-nul", "sibling_cost_usd-nan", "record-past-float-range"):
        assert label in ids, label


@pytest.mark.parametrize(("case", "bad", "in_findings"), _unstorable_cases())
def test_a_record_the_store_cannot_hold_is_staged_refused_and_a_refused_outcome_still_owes_its_bundle(
        request, scene, evidence_store, case, bad, in_findings):
    """Whole class, every kind by every record name by every text, number, null, list and key position: a record carrying a
    value the store cannot hold (NUL, a lone surrogate, NaN or infinity, an int past float range) is screened once at the
    helper like any malformed record: staged `refused/<name>{reason}`, never `<name>`, and never a fault that stages
    nothing. A refused `outcome` still owes the bundle, which is uploaded, and the ending reads `bad_record` with evidence
    `partial`; a refused `result` reads `bad_record`. Inside a learning outcome's `findings` the field's own rule may hold instead:
    the outcome staged with `findings: refused`, never the sent value. (PR2, PR8, r8 "Done when": a malformed outcome or
    result of every kind ends `bad_record`)"""
    kind, verb, _record, name, _staged = VALID[case]
    _base_files_for(request, kind)
    planted = plant(scene, kind)
    owes_bundle = name == "outcome"

    def job(c) -> int:
        _send_record(c, verb, bad)
        if owes_bundle:
            put_object(c, "bundle", BUNDLE)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    staged = facts(scene.dsn, scene.claim)
    rows = uploads(scene.dsn, scene.claim)
    if in_findings and name in staged:  # the findings field's own rule, inside a valid outcome
        assert f"refused/{name}" not in staged, staged
        assert staged[name]["findings"]["state"] == "refused", staged[name]["findings"]
        assert rows["bundle"]["status"] == "uploaded", rows
        return
    _refused(staged, name)
    assert name not in staged, "a record the store cannot hold was staged as a fact"
    if not owes_bundle:
        assert rows == {}, "a refused record owes nothing"
    else:
        assert set(rows) == {"bundle"}, rows
        assert rows["bundle"]["status"] == "uploaded", rows
    if name in ("outcome", "result"):
        end = decide(DECIDE_KIND[kind], staged, {o: up(r["status"], r["scrub"]) for o, r in rows.items()}, "exited")
        assert (end.stage, end.failure_reason) == ("failed", "bad_record"), (end.stage, end.failure_reason)
        if owes_bundle:
            assert end.evidence_state == "partial", end.evidence_state


@pytest.mark.parametrize("kind", ["readiness", "investigation", "learning", "adoption", "drain"])
def test_a_knowledge_request_is_an_unknown_verb_for_every_kind_and_the_staged_knowledge_stays_the_helpers_own(
        request, scene, evidence_store, kind):
    """r10 (c) U-3: the readiness `knowledge` verb is dropped (PR4: trusted code never reads job-written bytes it can know
    itself), so a `knowledge` request carrying a record that names another commit is refused as an unknown verb by every
    kind, and stages nothing: no `knowledge` and no `refused/knowledge` fact of the job's. Where the helper stages the
    knowledge itself (readiness, investigation), it is the source it settled, never the job's commit. Control: the job's
    own verb on the same channel (`progress` for an investigation or learning job, `result` for a host request) is still
    answered."""
    from defender.tests.support.evidence._facts1546 import KNOWLEDGE_RECORD, KNOWLEDGE_VERB_GONE, VALID as RECORDS

    _base_files_for(request, kind)
    planted = plant(scene, kind)
    other = "e" * 40
    assert other != scene.t.commit, "premise: the job's record names another commit"
    got: dict = {}

    def job(c) -> int:
        got["refusal"] = send(c, KNOWLEDGE_VERB_GONE, record={**KNOWLEDGE_RECORD, "commit": other})
        if kind in ("investigation", "learning"):
            got["own"] = send(c, "progress", record=INV_PROGRESS if kind == "investigation" else LEARNING_PROGRESS)
        else:
            _k, verb, record, _n, _s = RECORDS[f"{kind}-result"]
            got["own"] = send(c, verb, record=record)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    from defender import job_host

    assert isinstance(got["refusal"], job_host.Refused), f"a {kind} job's `knowledge` request was answered: {got['refusal']!r}"
    # The verb is dropped from the registry (r10 U-3; (f) "the helper's registration (`job_host/_evidence.py:429-430`)"): an
    # unregistered name, refused `unknown-request` for every kind, not a name still registered for some other kind.
    assert got["refusal"].code == "unknown-request", got["refusal"].code
    assert not isinstance(got["own"], job_host.Refused), f"control: the {kind} job's own verb was refused: {got['own']!r}"
    staged = facts(scene.dsn, scene.claim)
    assert "refused/knowledge" not in staged, staged.get("refused/knowledge")
    known = staged.get("knowledge")
    assert known is None or known.get("commit") != other, f"the job's knowledge record was staged: {known!r}"
    if kind in ("readiness", "investigation"):
        assert known == staged_knowledge(scene.t.commit), f"the helper's own knowledge was not staged: {known!r}"


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


def test_an_arm_fact_before_the_roster_is_refused_and_the_same_fact_after_it_lands(scene, evidence_store):
    """The roster (`arms`) is staged before the first `arm/<id>`: an arm fact sent before it is not staged (no roster names
    its run); once the roster is staged the same fact is, as its control. (PR2, G11: roster before the first arm)"""
    planted = plant(scene, "learning")
    run, world = str(uuid.uuid4()), str(uuid.uuid4())
    seen: dict = {}

    def job(c) -> int:
        send(c, "arm", run_id=run, record=sent_arm())
        seen["before"] = dict(facts(scene.dsn, scene.claim))
        send(c, "arms", record=sent_arms((run, world)))
        send(c, "arm", run_id=run, record=sent_arm())
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert f"arm/{run}" not in seen["before"]
    assert facts(scene.dsn, scene.claim)[f"arm/{run}"] == sent_arm(), "control: with the roster staged the arm fact lands"


# --- PR8: an object needs its fact --------------------------------------------------------------------------------------------

def _stored(scene, obj: str) -> str | None:
    return (uploads(scene.dsn, scene.claim).get(obj) or {}).get("status")


def test_a_bundle_put_before_any_outcome_is_refused_and_leaves_no_row_no_spool_and_no_object(scene, evidence_store):
    """With no `outcome` (or `refused/outcome`) staged, a `put` of the bundle is refused: no upload row, nothing in the bucket;
    with the outcome staged the same put is accepted (control). The spool is cleared at refusal or at the job's exit. (PR8)"""
    planted = plant(scene, "investigation")
    got: dict = {}

    def job(c) -> int:
        got["early"] = c.refused("evidence.put", object="bundle", part=0, last=True, data=BUNDLE)
        send(c, "outcome", record=inv_outcome())
        got["late"] = put_object(c, "bundle", BUNDLE)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert got["early"].code
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


@pytest.mark.parametrize("page_state", [None, "rendered", "render_failed", "none"])
def test_a_learning_jobs_episode_page_is_accepted_only_with_its_page_fact_rendered(scene, evidence_store, page_state):
    """Like the run page and an arm's: with its outcome staged, the episode page still needs a `page` fact with
    `page = rendered`; absent, `render_failed` or `none` refuse the put and leave no row. The bundle is the control.
    (PR8, D14; #1625: one rule for every page)"""
    planted = plant(scene, "learning")
    got: dict = {}

    def job(c) -> int:
        send(c, "outcome", record=learning_outcome())
        if page_state is not None:
            send(c, "page", record=sent_page(page_state))
        got["page"] = send(c, "evidence.put", object=EPISODE_PAGE, part=0, last=True, data=PAGE)
        put_object(c, "bundle", BUNDLE)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert _stored(scene, "bundle") == "uploaded", "control"
    if page_state == "rendered":
        assert _stored(scene, EPISODE_PAGE) == "uploaded"
    else:
        assert _stored(scene, EPISODE_PAGE) is None
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
        send(c, "page", record=sent_page())
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
        send(c, "page", record=sent_page())  # #1625: the page is owed by its fact, so only the outcome is missing
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


@pytest.mark.parametrize("ender", ["none", "none-learning", "cancel", "take-over", "learning-take-over"])
def test_a_write_after_the_references_end_is_refused_and_one_before_it_was_not_lost(scene, evidence_store, ender):
    """The job stages `progress`, its outcome, its page or roster fact and a bundle before its owner row ends (by the store's
    own cancel or take-over); afterwards each late write is one that is OWED and valid (a new `progress`, an owed object put,
    an arm fact of a roster id): with no end (control) they all land, after an end none does: no new fact, no upload row,
    nothing promoted. Codes and lock mode are not pinned. (PR7)"""
    kind = "learning" if ender.endswith("learning") or ender == "learning-take-over" else "investigation"
    planted = plant(scene, kind)
    seen: dict = {}
    early = LEARNING_PROGRESS if kind == "learning" else INV_PROGRESS
    late = {**LEARNING_PROGRESS, "sibling_cost_usd": 5.0} if kind == "learning" else {"cost_usd": 5.0}
    arm, world = str(uuid.uuid4()), str(uuid.uuid4())
    owed = EPISODE_PAGE if kind == "learning" else RUN_PAGE

    def job(c) -> int:
        send(c, "progress", record=early)
        send(c, "outcome", record=SMALL_OUTCOME[kind])
        if kind == "learning":
            send(c, "arms", record=sent_arms((arm, world)))
        send(c, "page", record=sent_page())
        put_object(c, "bundle", BUNDLE)
        seen["before"] = facts(scene.dsn, scene.claim)
        if not ender.startswith("none"):
            (_end_by_cancel if ender == "cancel" else _end_by_take_over)(scene, planted)
        send(c, "progress", record=late)
        if kind == "learning":
            send(c, "arm", run_id=arm, record=sent_arm())
        send(c, "evidence.put", object=owed, part=0, last=True, data=PAGE)
        seen["after"] = facts(scene.dsn, scene.claim)
        return 0

    drive(scene, planted, job, **evidence_store.seams)
    assert "progress" in seen["before"], "control: the writes before the end landed"
    assert "outcome" in seen["before"], "control: the writes before the end landed"
    rows = uploads(scene.dsn, scene.claim)
    if ender.startswith("none"):
        assert seen["after"]["progress"] == late, "control: a late `progress` of a live claim lands"
        assert set(rows) == {"bundle", owed}, "control: an owed put of a live claim is accepted"
        if kind == "learning":
            assert f"arm/{arm}" in seen["after"], "control: an arm fact of a roster id lands"
        return
    assert seen["after"] == seen["before"], "a fact was written after the reference ended"
    assert set(rows) <= {"bundle"}, f"an upload row was written after the end: {sorted(rows)}"
    assert accepted(scene.dsn, scene.claim) == [], "the helper promoted (only the applier may, PR3)"
