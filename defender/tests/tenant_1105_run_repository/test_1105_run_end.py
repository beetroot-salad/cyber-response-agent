"""#1105 PR 1 — run end keeps today's order (N-h; ruling 2; 20-demands F-13 (a), auto).

PR 1 adds no timeout and reorders nothing at run end. Today's order (R4-20, re-executed as
RG-08-a..d at 80888efb) is: the narration cross-check (`run.py:615`), then the ticket record
when `--update-ticket` (`:621-625`), then the curation enqueue (`:629-634`), then the run page
(`:636-639`). This test drives the REAL `run.main` through its existing keyword seams
(`lifecycle=`, `visualize=`, `ticket_writer=`, `enqueue=` — `tests/_spec791.py`'s tail fake for
the first three, the REAL `run_common.enqueue_curation` wrapped to note its call for the
fourth) and observes the order; the cross-check, which has no seam, is observed through the
warning it logs over a tree whose tables disagree with its `investigation.md` (RG-08-a).

A raising step is driven only through a seam whose fault the ledger observed on the real
`run.main` (RG-08-b: the ticket record raising `OSError(EIO)`; RG-08-c: the enqueue raising
`OSError(ENOSPC)`; RG-08-d: the page raising `VisualizeFailed`).

GREEN at base 80888efb by design: this pins behaviour PR 1 must not change (O5). It does not
touch the new package, so `spec-graph calls` reaches it only with `--target defender.run`, and
its null-stub pass is recorded (class: reuse).
"""
from __future__ import annotations

import errno
import logging
from typing import Any

from defender import run as run_py
from defender import run_common
from defender.tests._data_root_1078 import ensure_d9_tenant
from defender.tests._spec791 import (
    SpecTail,
    author_markers,
    loop_paths,
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
        self._order = order

    def emit(self, record: logging.LogRecord) -> None:
        if "narration cross-check FAILED" in record.getMessage():
            self._order.append(CROSS_CHECK)


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

    def record_case_ticket(self, run_dir: Any, **kw: Any) -> None:
        super().record_case_ticket(run_dir, **kw)
        if self.fail == TICKET:
            raise OSError(errno.EIO, "spec 1105: the ticket store failed (RG-08-b)")

    def visualize(self, run: Any, *, update_ticket: bool = False) -> None:
        super().visualize(run, update_ticket=update_ticket)
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
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(arm / "state"))
    satisfy_entrypoint_keys(monkeypatch, arm)
    paths = loop_paths(arm)
    order: list[str] = []
    tail = _Tail(paths, order, fail=fail)
    handler = _Order(order)
    logger = logging.getLogger(run_common.__name__)
    logger.addHandler(handler)
    try:
        # The alert's folder names the minted run id's label: one id per arm.
        alert = plant_alert(arm / f"alert-{arm.name}")
        argv = [str(alert), "--tenant", ensure_d9_tenant(), "--update-ticket"]
        try:
            outcome: Any = run_py.main(argv, lifecycle=tail.lifecycle, visualize=tail.visualize,
                                       ticket_writer=tail, enqueue=tail.enqueue)
        except Exception as exc:  # noqa: BLE001 — a raising step's propagation is observed
            outcome = exc
    finally:
        logger.removeHandler(handler)
    return order, outcome, author_markers(paths)


def test_1105_run_end_keeps_todays_order_cross_check_ticket_curation_page(tmp_path, monkeypatch):
    """A replayed run with --update-ticket ends in today's order through run.main's existing
    keyword seams: the cross-check, then the ticket write, then the curation enqueue, then the
    run page; and a step that raises leaves the later steps, the exit status and the records as
    today's (RG-08-a..d)."""
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
