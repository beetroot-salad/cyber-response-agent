"""#1344 O8 as #1487 reshapes it (design r5 O7, O4, Flow 3): the post-step runs the author tick and nothing else. Findings
are published by the worker at the learning job's end, so the post-step publishes nothing, hands nothing over, writes no
record and opens no database: its tick reaches the store through the helper (`store=`; the port's own tests are
`tests/jobs/test_1487_store_relay.py`). What the tenant's findings and "work still waiting" are now live in the worker's
end write and the predicate (`test_1344_amend_post_step.py`, `tests/jobs/test_1487_post_step_waiting.py`). The tenant's
own episodes are on disk."""
from __future__ import annotations

import contextlib
import os
from pathlib import Path

import pytest

from defender.learning.core.config import LoopPaths
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
from defender.tenancy._tenant import requested_tenant
from defender.tests.learning.branch.test_1344_job_lane import sink_files
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import DSN_ENV, call
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import fixture_data_root
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

#: The store's kind of each episode-sink channel's rows.
_KIND = {FINDINGS.name: "finding", QUESTIONER_FINDINGS.name: "questioner_finding"}


@pytest.fixture
def store_dsn(migrated_database, monkeypatch):  # noqa: F811 — the imported fixture
    """A tenant active in a database of the test's own, named by the variable the store's tests read it from (the
    post-step itself is never given it, `post_step_in_container`)."""
    register_tenant(migrated_database, S.FIXTURE_TENANT)
    monkeypatch.setenv(DSN_ENV, migrated_database)
    return migrated_database


class Boom(Exception):
    """An exception class no production code lists."""


def _job_episode(tmp_path, name: str, *, topic: str = "the lead was never revisited", findings: bool = True,
                 subject: str = "defender", comparable: bool = True):
    """A graded job episode under the tenant's real episodes folder: its judge ran in the job lane.
    `subject="world"` files a world finding, `subject="both"` one of each; `comparable=False` leaves a family no judge
    call is bought for."""
    est = S.estate(tmp_path)
    est.place(tenant_id=S.FIXTURE_TENANT)
    episode_id = fixture_uuid(f"1344-post-{name}")
    ep = S.judged_episode(tmp_path, doc=S.family_v2(episode_id=episode_id), outcome=None, episode_id=episode_id)
    S.outcome_record(ep, "accepted", family_stamp=False)
    if comparable:
        J.comparable_family_stamp(ep)
    subjects = ("defender", "world") if subject == "both" else (subject,)
    # Beside a defender finding, the world's is `mislabelled`: an `incoherent` one leaves the draw not measured.
    world_bucket = "mislabelled" if subject == "both" else "incoherent"
    filed = [J.finding_doc(bucket=world_bucket if one == "world" else "lead-quality", subject=one,
                           topic=topic if subject != "both" else f"{topic} ({one})",
                           **({"systems": ["idp"]} if one == "world" else {}))
             for one in subjects] if findings else []
    world = J.reply_doc(findings=filed)
    world.update(bucket="lead-quality", systems=["idp"])
    judge = J.scripted_judge(default=S.as_reply_text(world), family_default=S.as_reply_text(J.family_reply()))
    before = {p for p in ep.rglob("*") if p.is_file()}
    J.grade(ep, judge=judge, job_lane=True)
    if not comparable:
        assert not judge.calls, "premise: a family that is not comparable bought no judge call"
    return ep, sorted({p for p in ep.rglob("*") if p.is_file()} - before)


def _tenant_of(ep: Path):
    data_root, tenant_id = J.episode_location(ep)
    return requested_tenant(fixture_data_root(data_root), tenant_id)


def _learning_paths(ep: Path) -> LoopPaths:
    """The tenant's learning paths; the store, not a folder here, holds what is queued (O10)."""
    return LoopPaths.for_tenant(_tenant_of(ep))


def _queue(ep: Path, channel=FINDINGS) -> list[dict]:
    """The payloads of the store's items of `channel`'s kind for the episode's tenant (interface request: `.payload`)."""
    _data_root, tenant_id = J.episode_location(ep)
    return [i.payload for i in call(os.environ[DSN_ENV], "work", tenant_id) if i.kind == _KIND[channel.name]]


def post_step_in_container(job: str | None, tenant_id: str, **seams) -> int:
    """The real post-step in its job container (#1170 A6): its argv as the helper starts it (no `--parent-pid`), a
    job socket answering the helper's `launch` facts (the helper's own answers are `tests/jobs/`'s), and only the
    environment a job container is given: the helper's own filter drops the database address and every login (A8), so
    a step that reads one from its process environment meets what it would inside the container."""
    from unittest import mock

    from defender.job_host import _container
    from defender.learning.branch import post_step
    from defender.tests.support.jobs._socket_standin1170 import SocketStandIn

    seams.pop("still_waiting", None)  # retired seam (#1487 O7: the worker asks, not the post-step); older callers still pass it
    argv = [*(["--job", job] if job is not None else []), "--tenant", tenant_id]
    denied = _container._denied_values(os.environ)
    contained = {k: v for k, v in os.environ.items() if _container._setting(k, v, denied)}
    with SocketStandIn(tenant_id, launch={"kind": "post-step", "job": job}) as helper, \
            mock.patch.dict(os.environ, {**contained, **helper.environ_delta()}, clear=True):
        return post_step.main(argv, environ=dict(os.environ), **seams)


def _sink_channels() -> list:
    """Every channel the episode's findings sink holds (the sink's own table, not a hand-named list)."""
    from defender.learning.judge import enqueue
    from defender.tests.support.learning.curation._drain719 import channel_of

    return [pytest.param(channel_of(name), id=name) for name in sorted(enqueue._SINK_RECORDS)]


def _sink_file(ep: Path, channel) -> Path:
    from defender.learning.judge import enqueue
    from defender.records.formats import LAYOUT

    return ep / getattr(LAYOUT, enqueue._SINK_RECORDS[channel.name])


def _files_under(ep: Path) -> dict[str, bytes]:
    """Every file in the tenant's folder (episodes included), by path, with its bytes."""
    data_root, tenant_id = J.episode_location(ep)
    root = Path(data_root) / tenant_id
    return {str(p): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.mark.parametrize("family_less", [False, True], ids=["job", "family-less"])
@pytest.mark.parametrize("exit_code", [0, 3])
def test_o7_the_post_step_runs_the_tick_once_and_writes_no_record_and_no_hand_over(tmp_path, family_less, exit_code):
    """With no list handed to it, the post-step runs the tick once and returns its exit; no file appears in or changes
    under the tenant's folder (no `<key>.post-step.json`, no `<key>.post-step-pending.json`). (O7, Flow 3, #1487 retirements)"""
    ep, _ = _job_episode(tmp_path, f"quiet-{exit_code}-{family_less}")
    _data_root, tenant_id = J.episode_location(ep)
    before = _files_under(ep)
    ticks: list[int] = []

    code = post_step_in_container(None if family_less else ep.name, tenant_id,
                                  author_tick=lambda *_a, **_k: ticks.append(1) or exit_code)

    assert ticks == [1], "the tick did not run exactly once"
    assert code == exit_code
    assert _files_under(ep) == before, "the post-step left a file in the tenant's folder"


@pytest.mark.parametrize("family_less", [False, True], ids=["job", "family-less"])
def test_o7_a_failing_tick_leaves_no_record_either(tmp_path, family_less):
    """The tick raises: the post-step still wrote nothing, so there is no record for a failed tick to make lie. (O7)"""
    ep, _ = _job_episode(tmp_path, f"tickfails-{family_less}")
    _data_root, tenant_id = J.episode_location(ep)
    before = _files_under(ep)

    def failing(*_a, **_k):
        raise Boom("the author tick failed")

    with contextlib.suppress(Exception, SystemExit):
        post_step_in_container(None if family_less else ep.name, tenant_id, author_tick=failing)

    assert _files_under(ep) == before


@pytest.mark.parametrize("family_less", [False, True], ids=["job", "family-less"])
def test_o4_the_post_step_opens_no_database_and_publishes_no_episode(tmp_path, monkeypatch, family_less):
    """A graded job episode with findings on disk and a store that must not be opened: the post-step opens none and its
    episode's findings stay where they are (the worker stores them at the job's end). (O4, O1, #1487 retirements)"""
    from defender import learning_store

    ep, new = _job_episode(tmp_path, f"nodb-{family_less}")
    assert sink_files(new), f"premise: the job lane left findings in the episode: {new}"
    _data_root, tenant_id = J.episode_location(ep)
    opened: list[str] = []

    def opening(*args, **kwargs):
        opened.append("blocking")
        raise AssertionError("the post-step opened the learning store itself")

    monkeypatch.setattr(learning_store, "blocking", opening)  # lint-monkeypatch: ok — records any in-process opening of the store; the post-step's store is the port's
    post_step_in_container(None if family_less else ep.name, tenant_id, author_tick=lambda *_a, **_k: 0)

    assert opened == []
