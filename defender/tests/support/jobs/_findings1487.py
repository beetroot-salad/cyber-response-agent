"""#1487 test support: findings in a learning job's end record and the worker's end write over a real database.

Builders for the rows the channel rules admit (premise-checked by the tests), the end record as the entry writes it,
a scripted learning child that leaves a record per job, and real faults for the end transaction: a database trigger
that raises a chosen SQLSTATE on a table (once or always) and a statement-level exception hook. Nothing here decides
what the target does with any of them."""
from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from defender.tests.support.shared._postgres1339 import execute

END = "{id}.learning-end.json"
FINDING, QUESTIONER = "finding", "questioner_finding"
_ABSENT = object()
_ANCHORED = {"subject_anchor": "the lead", "subject_topic": "the lead was never revisited"}


def defender_row(job: str, n: int = 0, **over: Any) -> dict[str, Any]:
    """A defender finding the job's judge could have held: id `<job>/w-b/0/<n>`, admitted by `_validate_row`."""
    from defender.tests.support.learning.curation._drain719 import finding_row

    return finding_row(f"{job}/w-b/0/{n}", run_id=job, subject="defender", **{**_ANCHORED, **over})


def world_row(job: str, n: int = 0, **over: Any) -> dict[str, Any]:
    """A questioner finding the job's judge could have held: id `<job>/w-c/0/<n>`, admitted by `_validate_world_row`."""
    from defender.tests.support.learning.curation._spec773 import world_row as make

    return make(f"{job}/w-c/0/{n}", run_id=job, direction="world", type="mislabelled",
                citations=["family.yaml#worlds"], **{**_ANCHORED, **over})


def text_of(finding: list | Any = (), questioner: list | Any = ()) -> str:
    """The findings text object: each channel's rows under the store's kind names."""
    return json.dumps({FINDING: finding if not isinstance(finding, tuple) else list(finding),
                       QUESTIONER: questioner if not isinstance(questioner, tuple) else list(questioner)})


def ok(finding: Any = (), questioner: Any = ()) -> dict[str, Any]:
    return {"state": "ok", "text": text_of(finding, questioner)}


def record(status: str = "completed", reason: str | None = None, *, findings: Any = _ABSENT, count: int = 0,
           message: str | None = None, cost: float = 0.0) -> str:
    """The learning end record (the interface's whole shape) with the `findings` field as given, or without it."""
    body: dict[str, Any] = {"status": status, "reason": reason, "message": message, "fork_message_id": "m-1",
                            "stage": "judge", "findings_count": count, "sibling_cost_usd": cost}
    if findings is not _ABSENT:
        body["findings"] = findings
    return json.dumps(body)


def child_class():
    """`RecordsChild`: a scripted learning child leaving the record in `.records[job id]`, one spec file per launch (so
    concurrent launches never read each other's)."""
    from defender.tests.jobs.test_1344_learning_jobs import JobChild
    from defender.tests.support.shared.filesystem._handoff import write_whole

    class RecordsChild(JobChild):
        records: dict[str, str]

        def __call__(self, launch: Any) -> list[str]:
            spec = self.spec_dict()
            spec["files"] = {END: self.records[launch.job_id]}
            path = self.where / f"spec-{launch.job_id}.json"
            write_whole(path, json.dumps(spec))
            return [sys.executable, str(self.script), str(path), "--job", launch.job_id,
                    "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

    return RecordsChild


def quiet_post_class():
    """A post-step stand-in that leaves nothing and exits 0, asking nothing of the launch but the job and tenant."""
    from defender.tests.support.jobs._jobs1342 import ScriptedChild

    class QuietPost(ScriptedChild):
        def __call__(self, launch: Any) -> list[str]:
            from defender.tests.support.shared.filesystem._handoff import write_whole

            write_whole(self.spec, json.dumps(self.spec_dict()))
            return [sys.executable, str(self.script), str(self.spec), "--job", launch.job_id,
                    "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]

    return QuietPost


# --- real faults ------------------------------------------------------------------------------------------


def trigger_fault(dsn: str, table: str, sqlstate: str, *, when: str = "TRUE", once: bool = False,
                  name: str = "f1487") -> None:
    """A trigger on `table` (before an insert or update of a row matching `when`) raising `sqlstate`: every time, or
    the first time only (a sequence, which a rolled-back transaction does not rewind)."""
    seq = f"public.{name}_seq"
    execute(dsn, f"CREATE SEQUENCE {seq}")
    raising = f"RAISE EXCEPTION 'injected {sqlstate}' USING ERRCODE = '{sqlstate}';"
    body = f"IF nextval('{seq}') = 1 THEN {raising} END IF;" if once else raising
    execute(dsn, f"CREATE FUNCTION public.{name}() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN {body} "  # noqa: S608
                 "RETURN NEW; END $f$")
    execute(dsn, f"CREATE TRIGGER {name} BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW WHEN ({when}) "  # noqa: S608
                 f"EXECUTE FUNCTION public.{name}()")


def fault_fired(dsn: str, name: str = "f1487") -> bool:
    """Whether a `once` trigger has raised (its sequence has been drawn from)."""
    [(called,)] = execute(dsn, f"SELECT is_called FROM public.{name}_seq")
    return bool(called)


@contextlib.contextmanager
def statement_fault(exc: BaseException, *, containing: str = "INSERT INTO learning.work_items") -> Iterator[list[str]]:
    """Every statement run through an engine that contains `containing` raises `exc` first (not a database error: the
    way a bug in the insert path would surface). Yields the statements it raised for."""
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    hit: list[str] = []

    def before(_conn, _cursor, statement, _parameters, _context, _many):
        if containing in statement:
            hit.append(statement)
            raise exc

    event.listen(Engine, "before_cursor_execute", before)
    try:
        yield hit
    finally:
        event.remove(Engine, "before_cursor_execute", before)


def work_items(dsn: str, job: str) -> list[tuple[str, str, str, str]]:
    """`(tenant, kind, key, status)` of every item whose `source_run` is `job`."""
    return [tuple(r) for r in execute(dsn, "SELECT tenant_id, kind, item_key, status FROM learning.work_items "
                                           "WHERE source_run = %s ORDER BY kind, item_key", (job,))]


def all_items(dsn: str) -> list[tuple[str, str, str]]:
    return [tuple(r) for r in execute(dsn, "SELECT tenant_id, kind, item_key FROM learning.work_items "
                                           "ORDER BY tenant_id, kind, item_key")]


def breaking_screen(monkeypatch: Any, exc: BaseException) -> list[str]:
    """Every loaded `defender` module's `screen_findings` raises `exc` (and records its call); the modules patched."""
    import importlib

    importlib.import_module("defender.learning.judge.enqueue")
    called: list[str] = []

    def screen(*_a: Any, **_k: Any) -> None:
        called.append("called")
        raise exc

    patched = [name for name, module in list(sys.modules.items())
               if name.startswith("defender.") and "screen_findings" in getattr(module, "__dict__", {})]
    for name in patched:
        monkeypatch.setattr(sys.modules[name], "screen_findings", screen)
    breaking_screen.called = called  # type: ignore[attr-defined]
    return patched


def path_of(runs: Path, job: str) -> Path:
    return runs / END.format(id=job)
