"""Run end keeps its order: cross-check, ticket, curation, page."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import errno
import logging
from typing import Any

from defender import run as run_py
from defender import run_common
from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant
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

    def __init__(self, order: list[str]) -> None:
        super().__init__(level=logging.WARNING)
        self._steps = order

    def emit(self, record: logging.LogRecord) -> None:
        if "narration cross-check FAILED" in record.getMessage():
            self._steps.append(CROSS_CHECK)


class _Tail(SpecTail):
    """`_spec791`'s tail fake, noting each step into the shared order; `fail` names the one
    seam that raises, with the fault the ledger observed on the real `run.main` (RG-08-b..d)."""

    def __init__(self, paths: Any, order: list[str], *, fail: str | None = None) -> None:
        super().__init__(paths)
        self.order = order
        self.fail = fail

    def _note(self, name: str, run_dir: Any) -> None:
        super()._note(name, run_dir)
        self.order.append(name)

    def record_case_ticket(self, run: Any, **kw: Any) -> None:
        super().record_case_ticket(run, **kw)
        if self.fail == TICKET:
            raise OSError(errno.EIO, "spec 1105: the ticket store failed (RG-08-b)")

    def visualize(self, run: Any, *, tenant: Any, update_ticket: bool = False) -> None:
        super().visualize(run, tenant=tenant, update_ticket=update_ticket)
        if self.fail == PAGE:
            raise run_common.VisualizeFailed("spec 1105: the page was not saved (RG-08-d)")

    def enqueue(self, run: Any, alert: Any, **kw: Any) -> bool:
        # `run.main` hands its enqueue seam the run's `Run` (#1105 PR 2), passed on unchanged.
        self.order.append(ENQUEUE)
        if self.fail == ENQUEUE:
            raise OSError(errno.ENOSPC, "spec 1105: the queue is full (RG-08-c)")
        return run_common.enqueue_curation(run, alert, **kw)


def _drive(arm: Any, monkeypatch: Any, *, fail: str | None = None):
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
    paths = LoopPaths.for_tenant(tenant).with_repo_root(repo)
    order: list[str] = []
    tail = _Tail(paths, order, fail=fail)
    handler = _Order(order)
    logger = logging.getLogger(run_common.__name__)
    logger.addHandler(handler)
    try:
        # The alert's folder names the minted run id's label: one id per arm.
        alert = plant_alert(arm / f"alert-{arm.name}")
        argv = [str(alert), "--tenant", str(tenant.id), "--update-ticket"]
        try:
            outcome: Any = run_py.main(argv, lifecycle=tail.lifecycle, visualize=tail.visualize,
                                       ticket_writer=tail, enqueue=tail.enqueue)
        except Exception as exc:  # noqa: BLE001 — a raising step's propagation is observed
            outcome = exc
    finally:
        logger.removeHandler(handler)
    return order, outcome, author_markers(paths)


def test_1105_run_end_keeps_todays_order_cross_check_ticket_curation_page(tmp_path, monkeypatch):
    order, outcome, queued = _drive(tmp_path / "ok", monkeypatch)
    tail_steps = [s for s in order if s in (CROSS_CHECK, TICKET, ENQUEUE, PAGE)]
    assert tail_steps == [CROSS_CHECK, TICKET, ENQUEUE, PAGE], (
        f"run end ran {order}, not cross-check -> ticket -> curation -> page (N-h)")
    assert outcome == 0, f"a completing run exits 0: {outcome!r}"
    assert queued, "the curation request was queued (RG-08-a)"
    assert order.index("lifecycle") < order.index(CROSS_CHECK), "run end follows the lifecycle"

    order, outcome, queued = _drive(tmp_path / "ticket-fails", monkeypatch, fail=TICKET)
    assert isinstance(outcome, OSError), (
        f"a raising ticket record propagates out of run.main today (RG-08-b): {outcome!r}")
    assert outcome.errno == errno.EIO, f"the ticket store's own fault propagates: {outcome!r}"
    assert ENQUEUE not in order, f"the enqueue ran after a raising ticket record: {order}"
    assert PAGE not in order, f"the page ran after a raising ticket record: {order}"
    assert queued == [], "no curation request after a raising ticket record (RG-08-b)"

    order, outcome, queued = _drive(tmp_path / "enqueue-fails", monkeypatch, fail=ENQUEUE)
    assert isinstance(outcome, OSError), (
        f"a raising enqueue propagates out of run.main today (RG-08-c): {outcome!r}")
    assert outcome.errno == errno.ENOSPC, f"the enqueue's own fault propagates: {outcome!r}"
    assert PAGE not in order, f"the page ran after a raising enqueue: {order}"

    order, outcome, queued = _drive(tmp_path / "page-fails", monkeypatch, fail=PAGE)
    assert outcome == 0, f"a page that was not saved still exits 0 (RG-08-d): {outcome!r}"
    assert queued, "the curation request was queued before the page failed (RG-08-d)"
    assert order[-1] == PAGE, f"the page is still the last step: {order}"
