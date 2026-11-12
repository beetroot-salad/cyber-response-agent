"""A learning store that cannot take a request costs the investigation and the launch nothing (run-end enqueue, the judge).

#1135 pinned the exemptions from the state-refusal halt over the file queues. #1278 deleted the refusals with the handle; the
obligation behind two of them survives against the store (design r8 Flows, `run_common.enqueue_curation`, `branch.cli._grade`):
a store that is not set, cannot be reached, or will not take the item (the tenant is not active) is logged and costs only
that request, never the investigation's exit status or the launch.

Retired from this file (design r8 A1/O10, Locks, Schema "Retired files"):
- `test_e2_the_queue_page_counts_a_refused_sidecar_unreadable`, `test_1135_the_failed_folder_is_a_planted_entry_when_the_page_lists_failed_requests`:
  a linked graveyard, delivery record or failed folder under the root; the files and the root are gone. The queue page is
  rebuilt over the store and observed in `tests/runtime/engine/test_903_queue_view_1278.py`.
- `test_describe_strings_keep_every_display_reader_coherent`: `describe`'s file path and the `enqueued_to` display strings of
  the queue file are gone with the handle (the record names the store, `StoreFindings.describe`).
- `test_pitfalls_curator_on_a_non_default_root_writes_nothing_under_the_default_root`: there is no root to be non-default;
  where a call's folder lives is observed in `tests/learning/curation/test_1278_call_folders.py`.
"""
from __future__ import annotations

import logging

import pytest

from defender import run as run_py
from defender import run_common
from defender.learning.branch import cli as branch_cli
from defender.box import _scrub as scrub_mod
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135 as S
from defender.tests.support.learning.core._store1278 import DSN_ENV, call, migrated_database  # noqa: F401 — fixture
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.sandbox._spec791 import (
    SpecTail,
    TailStep,
    drive_tail,
    make_run_dir,
    plant_alert,
    satisfy_entrypoint_keys,
)
from defender.records import RunPaths, case_ref

pytestmark = pytest.mark.postgres

#: The ways a store cannot take a request: no address, an address nothing answers at, and a store that refuses (the tenant is
#: not active in it). The control of each case is the reachable store with the tenant active.
UNTAKEN = ["no-address", "unreachable", "tenant-not-active"]


def _store_that_cannot_take(how: str, dsn: str, monkeypatch) -> None:
    if how == "no-address":
        monkeypatch.delenv(DSN_ENV, raising=False)
    elif how == "unreachable":
        monkeypatch.setenv(DSN_ENV, "postgresql://nobody:none@127.0.0.1:1/none")
    else:
        monkeypatch.setenv(DSN_ENV, dsn)  # reachable and migrated; the tenant has no active row


class _Tail(SpecTail):
    """`SpecTail` recording each step's name only: the file marker listing it also kept is gone with the file queue."""

    def _note(self, name, run_dir) -> None:
        self.steps.append(TailStep(name=name, curation_requests=(), tree_certified=bool(scrub_mod.tree_verified(run_dir))))


def _register(dsn: str, tenant_id: str) -> None:
    from defender.tests.support.jobs._jobs1342 import register_tenant

    register_tenant(dsn, tenant_id)


def _tree_snapshot(root) -> dict[str, bytes | str]:
    """Every entry under `root` by relative path: a file's bytes, a link's target text, a directory's marker."""
    out: dict[str, bytes | str] = {}
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        out[rel] = ("-> " + str(p.readlink())) if p.is_symlink() else (b"" if p.is_dir() else p.read_bytes())
    return out


def _caught(call_):
    try:
        call_()
    except Exception as e:  # noqa: BLE001 — the exception is the observation
        return e
    return None


def _warnings(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize("how", UNTAKEN)
def test_e1_a_curation_request_the_store_cannot_take_costs_the_investigation_nothing(
        tmp_path, monkeypatch, caplog, migrated_database, how):  # noqa: F811 — the imported fixture
    satisfy_entrypoint_keys(monkeypatch, tmp_path)
    planted = S.curation_run_dir("case-1135")
    run_dir = make_run_dir(planted.parent, name=planted.name, disposition="benign")
    scrub_mod.scrub(run_dir)
    tenant_id = run_dir.parent.parent.name
    case_id = case_ref(RunPaths(run_dir).alert.read_bytes())
    _store_that_cannot_take(how, migrated_database, monkeypatch)

    caplog.set_level(logging.INFO)
    answered: list[bool] = []
    answered.append(run_common.enqueue_curation(S.run_of(run_dir), run_dir / "alert.json", tenant=S.tenant_of(run_dir)))
    assert answered == [False], f"a request the store could not take answered {answered!r}, not False"
    assert any("NOT enqueuing for curation" in r.getMessage() and "learning store" in r.getMessage() for r in caplog.records
               if r.levelno >= logging.ERROR), f"no line says the request was not filed: {[r.getMessage() for r in caplog.records]}"

    # `plant_alert`'s default bytes are `make_run_dir`'s, so the investigation's own case_ref is `case_id`: its own enqueue
    # meets the same store and is refused the same way, and the run goes on to render.
    tail = _Tail(None)
    rc = drive_tail(run_py.main, plant_alert(tmp_path / "investigation"), tail)
    assert rc == 0, f"a request the store could not take changed the investigation's exit status to {rc}"
    assert "visualize" in tail.names, f"the refused request took the render step with it (ran {tail.names})"

    # Positive control: the store reachable and the tenant active, the same request is filed under its run.
    monkeypatch.setenv(DSN_ENV, migrated_database)
    _register(migrated_database, tenant_id)
    assert run_common.enqueue_curation(S.run_of(run_dir), run_dir / "alert.json", tenant=S.tenant_of(run_dir)) is True
    [item] = [i for i in call(migrated_database, "work", tenant_id) if i.kind == "curation_request"]
    assert (item.key, item.payload["case_id"]) == (run_dir.name, case_id)


@pytest.mark.parametrize("how", UNTAKEN)
def test_e3_a_store_that_cannot_take_the_findings_leaves_the_launch_unaffected(
        tmp_path, monkeypatch, caplog, migrated_database, how):  # noqa: F811 — the imported fixture
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / T.world_id(ep, "b") / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    tenant_id = ep.parent.parent.name
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    _store_that_cannot_take(how, migrated_database, monkeypatch)
    archived = _tree_snapshot(ep)
    model = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))

    caplog.set_level(logging.INFO)
    escaped = _caught(lambda: branch_cli._grade(J.episode_runs_for(ep), episode_id=ep.name, judge=model))

    assert escaped is None, f"_grade raised {escaped!r} into the launch"
    after = _tree_snapshot(ep)
    rewritten = sorted(k for k, v in archived.items() if after.get(k) != v)
    assert not rewritten, f"the failed grade changed the episode's own records: {rewritten}"
    failed = [r for r in _warnings(caplog) if r.exc_info and "the judge pass failed" in r.getMessage()]
    assert failed, f"_grade logged no judge failure for the store that could not take its findings: {[r.getMessage() for r in _warnings(caplog)]}"
    if how == "tenant-not-active":
        assert [i for i in call(migrated_database, "work", tenant_id)] == [], "findings reached a tenant that is not active"

    # Positive control: the store reachable and the tenant active, a fresh episode (the failed one is left `queueing` by the
    # pass that stopped between its append and its commit, and is refused a re-run) grades through and queues its rows.
    control = J.accepted_episode(tmp_path / "control", ledgers={"b": [J.oracle_row("b")], "c": []},
                                 dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (control / "worlds" / T.world_id(control, "b") / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    control_tenant = control.parent.parent.name
    monkeypatch.setenv(DSN_ENV, migrated_database)
    _register(migrated_database, control_tenant)
    caplog.clear()
    assert _caught(lambda: branch_cli._grade(J.episode_runs_for(control), episode_id=control.name, judge=J.FakeJudge(
        default=J.as_reply_text(J.reply_doc())))) is None
    assert not [r for r in _warnings(caplog) if r.exc_info], f"the control's grade failed: {[r.getMessage() for r in _warnings(caplog)]}"
    queued = [i for i in call(migrated_database, "work", control_tenant) if i.kind in ("finding", "questioner_finding")]
    assert queued, "the control's grade queued no rows"
    assert len(queued) == J.judge_record(control).get("enqueued_rows"), "the store holds other than the episode's enqueued count"
