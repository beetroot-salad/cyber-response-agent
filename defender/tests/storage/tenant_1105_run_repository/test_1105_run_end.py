"""Run end keeps its order: cross-check, ticket, curation, page."""
from __future__ import annotations

import dataclasses

from defender.tests.support.shared._locations_1210 import location_path

import errno
import logging
from typing import Any

from defender import run as run_py
from defender import run_common
from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant
from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv, in_process_publish
from defender.tests.support.sandbox._spec791 import (
    SpecTail,
    author_markers,
    plant_alert,
    require_tail_seam,
    satisfy_entrypoint_keys,
)

CROSS_CHECK = "cross_check"
TICKET = "record_case_ticket"
ENQUEUE = "enqueue"
PAGE = "visualize"


class _Order(logging.Handler):
    """Notes the cross-check's own warning into the run's step order (an observation)."""

    def __init__(self, order: list[str], sample: Any = None) -> None:
        super().__init__(level=logging.WARNING)
        self._steps = order
        self._sample = sample

    def emit(self, record: logging.LogRecord) -> None:
        if "narration cross-check FAILED" in record.getMessage():
            self._steps.append(CROSS_CHECK)
            if self._sample is not None:
                self._sample(CROSS_CHECK)


class _Tail(SpecTail):
    """`_spec791`'s tail fake, noting each step into the shared order; `fail` names the one
    seam that raises, with the fault that seam really raises."""

    def __init__(self, paths: Any, order: list[str], *, fail: str | None = None, sample: Any = None) -> None:
        super().__init__(paths)
        self.order = order
        self.fail = fail
        self.sample = sample
        self.enqueued: list[dict[str, Any]] = []

    def _note(self, name: str, run_dir: Any) -> None:
        super()._note(name, run_dir)
        self.order.append(name)
        if self.sample is not None:
            self.sample(name)

    def record_case_ticket(self, run: Any, **kw: Any) -> None:
        super().record_case_ticket(run, **kw)
        if self.fail == TICKET:
            raise OSError(errno.EIO, "spec 1105: the ticket store failed (RG-08-b)")

    def visualize(self, run: Any, *, tenant: Any, update_ticket: bool = False) -> None:
        super().visualize(run, tenant=tenant, update_ticket=update_ticket)
        if self.fail == PAGE:
            raise run_common.VisualizeFailed("spec 1105: the page was not saved (RG-08-d)")

    def enqueue(self, run: Any, alert: Any, **kw: Any) -> bool:
        # `run.main` hands its enqueue seam the run's `Run`, passed on unchanged.
        self.order.append(ENQUEUE)
        if self.sample is not None:
            self.sample(ENQUEUE)
        self.enqueued.append(dict(kw))
        if self.fail == ENQUEUE:
            raise OSError(errno.ENOSPC, "spec 1105: the queue is full (RG-08-c)")
        return run_common.enqueue_curation(run, alert, **kw)


def _drive(arm: Any, monkeypatch: Any, *, fail: str | None = None, directory: Any = None, during: Any = None,
           tails: list[Any] | None = None, sample: Any = None):
    """The REAL `run.main` over one alert under `--update-ticket`, with the tail's seams
    injected and this arm's own learning state; returns (the order the steps ran in, main's
    return value or what it raised, the curation requests queued)."""
    require_tail_seam(run_py.main)
    from defender.learning.core.config import LoopPaths

    root = arm / "data"
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    satisfy_entrypoint_keys(monkeypatch, arm)
    tenant = set_up_tenant(root)
    location_path(tenant.learning).mkdir(exist_ok=True)
    repo = arm / "repo"
    (repo / "defender").mkdir(parents=True)
    paths = dataclasses.replace(LoopPaths.for_tenant(tenant), repo_root=repo)
    order: list[str] = []
    tail = _Tail(paths, order, fail=fail, sample=sample)
    if tails is not None:
        tails.append((tenant, tail))

    def lifecycle(*a: Any, **k: Any) -> Any:  # `during` runs mid-run, after acceptance
        if during is not None:
            during()
        return tail.lifecycle(*a, **k)
    handler = _Order(order, sample)
    logger = logging.getLogger(run_common.__name__)
    logger.addHandler(handler)
    try:
        alert = plant_alert(arm / f"alert-{arm.name}")
        argv = [str(alert), "--tenant", str(tenant.id), "--update-ticket"]
        try:
            # Plus the in-process launch-time publish.
            given = directory(root, str(tenant.id)) if directory is not None else directory_for_argv(argv)
            outcome: Any = run_py.main(argv, directory=given, lifecycle=lifecycle,
                                       visualize=tail.visualize,
                                       ticket_writer=tail, enqueue=tail.enqueue,
                                       publish=in_process_publish())
        except Exception as exc:  # noqa: BLE001 — a raising step's propagation is observed
            outcome = exc
    finally:
        logger.removeHandler(handler)
    return order, outcome, author_markers(paths)


def test_1105_run_end_keeps_todays_order_cross_check_ticket_curation_page(tmp_path, monkeypatch):
    order, outcome, queued = _drive(tmp_path / "ok", monkeypatch)
    tail_steps = [s for s in order if s in (CROSS_CHECK, TICKET, ENQUEUE, PAGE)]
    assert tail_steps == [CROSS_CHECK, TICKET, ENQUEUE, PAGE], (
        f"run end ran {order}, not cross-check -> ticket -> curation -> page")
    assert outcome == 0, f"a completing run exits 0: {outcome!r}"
    assert queued, "no curation request was queued"
    assert order.index("lifecycle") < order.index(CROSS_CHECK), "run end follows the lifecycle"

    order, outcome, queued = _drive(tmp_path / "ticket-fails", monkeypatch, fail=TICKET)
    assert isinstance(outcome, OSError), (
        f"a raising ticket record did not propagate out of run.main: {outcome!r}")
    assert outcome.errno == errno.EIO, f"the ticket store's own fault propagates: {outcome!r}"
    assert ENQUEUE not in order, f"the enqueue ran after a raising ticket record: {order}"
    assert PAGE not in order, f"the page ran after a raising ticket record: {order}"
    assert queued == [], f"a curation request was queued after a raising ticket record: {queued}"

    order, outcome, queued = _drive(tmp_path / "enqueue-fails", monkeypatch, fail=ENQUEUE)
    assert isinstance(outcome, OSError), (
        f"a raising enqueue did not propagate out of run.main: {outcome!r}")
    assert outcome.errno == errno.ENOSPC, f"the enqueue's own fault propagates: {outcome!r}"
    assert PAGE not in order, f"the page ran after a raising enqueue: {order}"

    order, outcome, queued = _drive(tmp_path / "page-fails", monkeypatch, fail=PAGE)
    assert outcome == 0, f"a page that was not saved still exits 0: {outcome!r}"
    assert queued, "no curation request was queued before the page failed"
    assert order[-1] == PAGE, f"the page is still the last step: {order}"


def test_the_run_end_curation_request_uses_the_runs_tenant_with_no_second_read(tmp_path, monkeypatch):
    """Run end hands the curation request the run's accepted tenant and reads no tenant record again: a tenant
    offboarded mid-run still gets the request, written under the run's held lock (r10 O-A5, Flows: run end)."""
    from defender.tenancy import TenantDirectory
    from defender.tests.support.tenancy._active1214 import CREATED, active_repository, run_sync
    from defender.tests.support.tenancy._host1214 import ENQUEUE_TENANT

    opened: list[str] = []
    twins: list[Any] = []

    def directory(root: Any, tenant_id: str) -> Any:
        twin = active_repository(location_path(root), tenant_id)
        twins.append((twin, tenant_id))

        def repository() -> Any:
            opened.append("read")
            return twin
        return TenantDirectory(repository)

    at_flip: list[int] = []

    def offboard() -> None:
        twin, tenant_id = twins[-1]
        at_flip.append(len(opened))
        run_sync(twin.request_offboard(tenant_id, now=CREATED))

    tails: list[Any] = []
    order, outcome, queued = _drive(tmp_path / "offboarded-mid-run", monkeypatch, directory=directory,
                                    during=offboard, tails=tails)
    assert outcome == 0, f"a completing run exits 0: {outcome!r}"
    assert at_flip, "control: the run reached its lifecycle"
    assert at_flip[0] >= 1, "control: the run read its tenant record before the flip"
    assert queued, "the request of a run whose tenant was offboarded mid-run was not written"
    assert len(opened) == at_flip[0], f"run end read the tenant records again: {opened}"
    [(tenant, tail)] = tails
    [kw] = tail.enqueued
    assert str(kw[ENQUEUE_TENANT].id) == str(tenant.id), f"the enqueue seam was not handed the run's tenant: {kw}"


def test_the_run_is_recorded_under_its_tenants_host_lock_for_as_long_as_it_runs(tmp_path, monkeypatch):
    """The run is recorded mid-run (the lifecycle step, after acceptance) and leaves nothing recorded and no lock once
    `main` returned (r10 O-A2, O-A6)."""
    from defender.tests.support.tenancy import _host1214 as H
    from defender.tests.support.tenancy._active1214 import active_directory

    where: dict[str, Any] = {}

    def directory(root: Any, tenant_id: str) -> Any:
        where["at"] = (location_path(root), tenant_id)
        return active_directory(location_path(root), tenant_id)

    def during() -> None:
        data_root, tenant_id = where["at"]
        where["during"] = (H.recorded(data_root, tenant_id), H.exclusive_free(data_root, tenant_id))

    _order, outcome, _queued = _drive(tmp_path / "recorded", monkeypatch, directory=directory, during=during)
    assert outcome == 0, f"a completing run exits 0: {outcome!r}"
    assert "during" in where, "control: the run reached its lifecycle"
    recorded, free = where["during"]
    assert recorded == H.this_process(), "the run was not recorded while it ran"
    assert not free, "the run's tenant lock was free while it ran"
    data_root, tenant_id = where["at"]
    assert H.recorded(data_root, tenant_id) == []
    assert H.exclusive_free(data_root, tenant_id)


def test_the_run_stays_recorded_and_locked_through_every_step_of_its_end(tmp_path, monkeypatch):
    """The cross-check, the case ticket, the curation request and the page each run while this process is recorded under
    the run's tenant lock and the lock is held, and neither outlasts `main` (r10 O-A2: for as long as the command works)."""
    from defender.tests.support.tenancy import _host1214 as H
    from defender.tests.support.tenancy._active1214 import active_directory

    where: dict[str, Any] = {}
    seen: dict[str, tuple[bool, bool]] = {}

    def directory(root: Any, tenant_id: str) -> Any:
        where["at"] = (location_path(root), tenant_id)
        return active_directory(location_path(root), tenant_id)

    def sample(step: str) -> None:
        data_root, tenant_id = where["at"]
        seen[step] = (H.recorded(data_root, tenant_id) == H.this_process(), H.lock_held(data_root, tenant_id))

    _order, outcome, queued = _drive(tmp_path / "held-to-the-end", monkeypatch, directory=directory, sample=sample)
    assert outcome == 0, f"a completing run exits 0: {outcome!r}"
    assert queued, "control: a completing run queues its request"
    steps = (CROSS_CHECK, TICKET, ENQUEUE, PAGE)
    assert {step: seen.get(step) for step in steps} == dict.fromkeys(steps, (True, True)), (
        f"(recorded, locked) at each run-end step: {seen}")
    data_root, tenant_id = where["at"]
    assert H.recorded(data_root, tenant_id) == []
    assert not H.lock_held(data_root, tenant_id)
