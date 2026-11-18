"""#1487 sketch (design r1; D1 (a) staged findings, D3 accepted): the learning store reached from a job container through
its per-job host helper. The learning job hands its findings in once (`findings.publish`); the post-step's tick calls
the store's own verbs, one request each (`store.<verb>`), the helper setting the claim's tenant and its own settings.
Driven through the real helper (`job_host.main`) over the container stand-in, as `test_job_helper_learning.py`; the
store is a real PostgreSQL. Names the design leaves open are `_relay1487`'s."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import uuid

import pytest

from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import OTHER_TENANT
from defender.tests.support.jobs._job_helper_learning import learning_end, run_kind
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.jobs._relay1487 import (
    FINDINGS,
    KIND,
    QUESTIONER,
    admitted,
    defender_row,
    relay_store,
    world_finding_row,
)
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, ONE, call, finding, lapse_lease

process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]


def _no_database_in(env: dict, scene) -> None:
    assert [k for k in env if "DSN" in k.upper() or "DATABASE" in k.upper()] == [], "the container holds a database setting"
    assert scene.dsn not in [v for v in env.values() if v], "the container holds the database login"


def _items(scene, tenant: str | None = None, **kw) -> list:
    return list(call(scene.dsn, "work", tenant or scene.tenant, **kw))


# --- Flow 1: the learning job's hand-in --------------------------------------------------------------------------------

def test_o1_a_learning_jobs_hand_in_lands_its_rows_staged_for_the_claims_tenant_under_its_job_id(scene):
    """One `findings.publish` with both channels is answered `published` with each kind's count; the rows are the
    claim's tenant's, under the job's id, and staged: no claim sees them until the worker's end write (D1 a). The
    container held no database address. (O1, P1, P4)"""
    job_id = str(uuid.uuid4())
    rows = {FINDINGS: [defender_row(job_id)], QUESTIONER: [world_finding_row(job_id)]}
    admitted(rows)
    got: dict = {}

    def job(c) -> int:
        got["env"] = dict(c.env)
        got["answer"] = c.request("findings.publish", channels=rows)
        return 0

    run_kind(scene, "learning", job, job_id=job_id)

    assert got["answer"] == {"outcome": "published", "counts": {KIND[FINDINGS]: 1, KIND[QUESTIONER]: 1}}, got["answer"]
    staged = _items(scene, statuses=["staged"])
    assert sorted(i.key for i in staged) == sorted(r["finding_id"] for ch in rows.values() for r in ch)
    assert {i.source_run for i in staged} == {job_id}, "the rows are not the job's own"
    assert not call(scene.dsn, "lane_work", scene.tenant, AUTHOR_LANE, thresholds=ONE).claimable, \
        "a staged row is claimable before the job's end write"
    _no_database_in(got["env"], scene)


def test_o2_a_bad_row_in_either_channel_refuses_the_whole_hand_in_and_stores_nothing(scene):
    """A good defender row and a questioner row holding a NUL: the hand-in is answered `refused` with the rule's reason,
    and neither channel's rows are stored, in any state. (O2)"""
    job_id = str(uuid.uuid4())
    good = defender_row(job_id)
    bad = world_finding_row(job_id, finding="a NUL \x00 here")
    admitted({FINDINGS: [good]})
    got: dict = {}

    def job(c) -> int:
        got["answer"] = c.request("findings.publish", channels={FINDINGS: [good], QUESTIONER: [bad]})
        return 0

    run_kind(scene, "learning", job, job_id=job_id)

    assert got["answer"].get("outcome") == "refused", got["answer"]
    assert got["answer"].get("reason"), "a refusal with no reason"
    assert _items(scene) == [], "a refused hand-in left rows in the store"


def test_o3_a_hand_in_meeting_an_unreachable_store_waits_and_a_stop_hands_the_job_back(scene, monkeypatch):
    """The helper's store goes away after the container started: the hand-in is not answered while it is retried;
    the helper is then stopped, the hand-in is refused and the job is handed back (`stopped`), never `completed`
    with nothing stored. (O3, D1)"""
    relay = J.TcpRelay(scene.dsn)
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", relay.dsn)  # the helper's own login, through a relay the test cuts
    job_id = str(uuid.uuid4())
    rows = {FINDINGS: [defender_row(job_id)]}
    got: dict = {}

    def job(c) -> int:
        relay.cut()
        answered = threading.Event()

        def hand_in() -> None:
            try:
                got["answer"] = c.request("findings.publish", channels=rows)
            except Exception as refused:  # noqa: BLE001 — kept for the case
                got["refused"] = refused
            answered.set()

        threading.Thread(target=hand_in, daemon=True).start()
        got["waited"] = not answered.wait(3.0)
        os.kill(os.getpid(), signal.SIGTERM)
        assert c.stopping.wait(15), "the helper never stopped the container"
        answered.wait(15)
        return 143

    run_kind(scene, "learning", job, job_id=job_id)

    assert got["waited"], f"the hand-in was answered while the store was unreachable: {got}"
    assert "answer" not in got, got
    assert getattr(got.get("refused"), "code", None) == "signalled", got
    end = learning_end(scene, job_id)
    assert end is not None
    assert end.status == "stopped", end
    assert _items(scene) == []


# --- Flow 2: the post-step's store, verb for verb ----------------------------------------------------------------------

def test_o5_a_post_steps_store_acts_on_its_claims_tenant_whatever_tenant_it_names(scene):
    """The other tenant is active and has work and a lapsed batch. Asked for the other tenant's work, the relay lists
    the claim's tenant's; asked to take over the other tenant's batch, it is not found. (O5, P1)"""
    register_tenant(scene.dsn, OTHER_TENANT)
    call(scene.dsn, "publish_findings", scene.tenant, "run-own", [finding("own/w/0/0")], kind="finding")
    call(scene.dsn, "publish_findings", OTHER_TENANT, "run-other", [finding("other/w/0/0")], kind="finding")
    theirs = call(scene.dsn, "claim", OTHER_TENANT, AUTHOR_LANE, owner="other-tick", thresholds=ONE)
    assert theirs is not None, "premise: the other tenant's batch was claimed"
    lapse_lease(scene.dsn, str(theirs.batch_id))
    assert [i.key for i in _items(scene, OTHER_TENANT)] == ["other/w/0/0"], "premise: the other tenant has work"
    got: dict = {}

    def job(c) -> int:
        store = relay_store(c, scene.tenant)
        got["work"] = [i.key for i in store.work(OTHER_TENANT)]
        try:
            store.take_over(OTHER_TENANT, str(theirs.batch_id), owner="x")
        except LookupError as missing:
            got["take_over"] = missing
        return 0

    run_kind(scene, "post-step", job)

    assert got["work"] == ["own/w/0/0"], got["work"]
    assert isinstance(got.get("take_over"), LookupError), got
    assert call(scene.dsn, "batches", OTHER_TENANT)[0].token == theirs.token, "the other tenant's batch moved"


@pytest.mark.parametrize(("kind", "request_name", "fields"), [
    ("learning", "store.work", {"tenant": "<tenant>"}),
    ("investigation", "store.work", {"tenant": "<tenant>"}),
    ("post-step", "findings.publish", {"channels": {}}),
])
def test_o5_p3_a_verb_not_on_the_kinds_list_is_refused_for_the_kind(scene, kind, request_name, fields):
    """A learning job or an investigation gets no store verb, a post-step no hand-in: each is refused `not-for-kind`
    (the request is one the helper knows), and the same socket answers the kind's own request. (O5, P3)"""
    own = {"learning": ("pass", {"id": "<job>"}), "investigation": ("pass", {"id": "<job>"}),
           "post-step": ("store.batches", {"tenant": "<tenant>"})}
    job_id = str(uuid.uuid4())
    got: dict = {}

    def fill(f):
        return {k: (job_id if v == "<job>" else scene.tenant if v == "<tenant>" else v) for k, v in f.items()}

    def job(c) -> int:
        name, own_fields = own[kind]
        got["own"] = c.request(name, **fill(own_fields))
        got["refusal"] = c.refused(request_name, **fill(fields))
        return 0

    run_kind(scene, kind, job, job_id=job_id)

    assert got["own"] is not None, "control: the kind's own request was refused"
    assert got["refusal"].code == "not-for-kind", (got["refusal"].code, str(got["refusal"]))


def test_o6_a_stopping_ticks_unwind_is_answered_after_the_signal_and_a_renewal_is_not(scene, monkeypatch):
    """A batch claimed through the relay before the stop: after the helper is signalled, `renew` is refused
    `signalled` and `abandon_clean` is answered, ending the batch `abandoned` (stopped) and giving its items back.
    (O6)"""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")  # the helper's threshold (D3), one finding due
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("f/w/0/0")], kind="finding")
    got: dict = {}

    def job(c) -> int:
        store = relay_store(c, scene.tenant)
        held = store.claim(scene.tenant, AUTHOR_LANE, owner="tick", thresholds={"finding": 1})
        got["held"] = held
        os.kill(os.getpid(), signal.SIGTERM)
        assert c.stopping.wait(15), "the helper never stopped the container"
        try:
            store.renew(held)
        except Exception as refused:  # noqa: BLE001 — kept for the case
            got["renew"] = refused
        store.abandon_clean(held)
        got["abandoned"] = True
        return 143

    run_kind(scene, "post-step", job)

    assert got.get("held") is not None, "control: the claim was not answered before the signal"
    assert getattr(got.get("renew"), "code", None) == "signalled", got.get("renew")
    assert got.get("abandoned"), "the stop window's abandon was not answered"
    [batch] = call(scene.dsn, "batches", scene.tenant)
    assert (batch.phase, batch.outcome, batch.reason) == ("ended", "abandoned", "stopped"), batch
    assert [i.status for i in _items(scene)] == ["waiting"]


def test_d3_the_helper_supplies_the_thresholds_and_the_owner_whatever_the_tick_sends(scene, monkeypatch):
    """The helper's threshold is 1 and the tick sends 1000 and an owner of its choosing: the claim is made on the
    helper's threshold, and the batch's owner is not the one the job named. (D3)"""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("f/w/0/0")], kind="finding")
    got: dict = {}

    def job(c) -> int:
        got["held"] = relay_store(c, scene.tenant).claim(scene.tenant, AUTHOR_LANE, owner="forged-owner",
                                                          thresholds={"finding": 1000, "questioner_finding": 1000})
        return 0

    run_kind(scene, "post-step", job)

    assert got["held"] is not None, "the claim used the job's thresholds, not the helper's"
    [batch] = call(scene.dsn, "batches", scene.tenant)
    assert batch.lease_owner != "forged-owner", batch.lease_owner


_TICK_STORE = r'''
import json, sys
from defender.learning.core import store_tick
with store_tick.opened_store() as store:
    print(json.dumps({"keys": [i.key for i in store.work(sys.argv[1])],
                      "waiting": store_tick.lane_waiting(store, sys.argv[1], "author", tick_thresholds={"finding": 1}),
                      "renew_every": float(store.renew_every)}))
'''


def test_o4_the_ticks_own_store_door_in_a_container_process_reaches_the_store_through_the_helper(scene):
    """A real process with the container's environment (no database address) opens the tick's store
    (`store_tick.opened_store`) and reads the tenant's work and the wake question through the helper; the store's
    renewal period is the helper's setting. (O4, D3)"""
    from defender import job_host
    from defender.learning_store._store import DEFAULT_RENEW_SECONDS
    from defender.tests.support.jobs._learning_container1170 import child_environment

    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("f/w/0/0")], kind="finding")
    got: dict = {}

    def job(c) -> int:
        env = child_environment(c)
        env[job_host.SOCKET_ENV] = str(c.socket())
        got["env"] = env
        done = subprocess.run([sys.executable, "-c", _TICK_STORE, scene.tenant], env=env, capture_output=True,
                              text=True, timeout=60, check=False)
        got["out"], got["err"] = done.stdout, done.stderr
        return 0

    run_kind(scene, "post-step", job)

    assert got["out"].strip(), f"the tick's store did not open in the container: {got['err'][-2000:]}"
    seen = json.loads(got["out"].strip().splitlines()[-1])
    assert seen["keys"] == ["f/w/0/0"]
    assert seen["waiting"] is True
    assert seen["renew_every"] == DEFAULT_RENEW_SECONDS
    _no_database_in({k: v for k, v in got["env"].items() if k not in ("PYTHONPATH", "PATH")}, scene)
