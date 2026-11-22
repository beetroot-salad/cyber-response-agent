"""#1546 PR9: nothing but the applier writes a terminal column of a job row (or promotes an upload). Two forms, because
each sees what the other cannot:

- a census over production source (AST, not grep: `store.py` writes terminal columns by `update().values(k=...)`, by ORM
  attribute assignment and by dict splats) that cannot be fooled by a new ender added anywhere in `defender/`, but sees only
  statically spelled writes (a column name built at run time, or a write by a database trigger, escapes it);
- a behavioural run over every ender with `apply` made to raise, which sees any path whatever its spelling but only the
  enders it drives (the census of G19), and relies on the enders calling `self.apply`.
The census is checked on synthetic sources too, so it can fail."""
from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

import pytest

from defender.tests.support.jobs._ending1546 import (
    STARTED,
    inv_row,
    learn_row,
    plant_complete_source,
    plant_facts,
    queue_learning_job,
    host_row,
)
from defender.tests.support.jobs._jobs1342 import T1, lapse_lease, register_tenant
from defender.tests.support.jobs._worker1342 import _queued
from defender.tests.support.shared._postgres1339 import execute

SOURCE = Path(__file__).resolve().parents[2]
#: The columns whose being set ends (or accepts the evidence of) a job row. Not the lease, the running cost or progress.
TERMINAL = frozenset({"stage", "status", "failure_reason", "failure_message", "reason", "message", "finished_at",
                      "disposition", "scrub", "evidence_state", "publish_state", "result", "accepted_at", "knowledge"})
JOB_ROWS = frozenset({"InvestigationRow", "LearningJobRow", "HostRequestRow", "UploadRow"})
SCOPE = re.compile(r"InvestigationRow|LearningJobRow|HostRequestRow|UploadRow|jobs\.(investigations|learning_jobs|"
                   r"host_requests|uploads)")
RAW = re.compile(r"UPDATE\s+(jobs\.)?(investigations|learning_jobs|host_requests|uploads)\b(?P<rest>.*)", re.I | re.S)
EXPIRE_ONLY = re.compile(r"SET\s+evidence_state\s*=\s*'expired'\s*(WHERE|$)", re.I)


def _is_applier(qualname: str, module: str) -> bool:
    last = qualname.rsplit(".", 1)[-1]
    return module.startswith("jobs/") and (last == "apply" or last.startswith("_apply"))


def _is_renewal(qualname: str) -> bool:
    return qualname.rsplit(".", 1)[-1].lstrip("_").startswith("renew")


class _Census(ast.NodeVisitor):
    def __init__(self, module: str) -> None:
        self.module, self.stack, self.found = module, [], []

    def _flag(self, node: ast.AST, what: str) -> None:
        qual = ".".join(self.stack) or "<module>"
        if not _is_applier(qual, self.module):
            self.found.append((self.module, qual, node.lineno, what))

    def _scoped(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scoped

    @staticmethod
    def _targets_a_job_table(func: ast.Attribute) -> bool:
        """The `.values` receiver's chain holds `update(X)` / `insert(X)` with X a job row class or a variable (a class
        passed in), not another table's class."""
        node: ast.AST = func.value
        while isinstance(node, ast.Call | ast.Attribute):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ("update", "insert", "pg_insert") and node.args:
                    first = node.args[0]
                    return isinstance(first, ast.Name) and (first.id in JOB_ROWS or not first.id[:1].isupper())
                node = node.func
            else:
                node = node.value
        return False

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr == "values" and self._targets_a_job_table(node.func):
            running = {k.arg for k in node.keywords
                       if k.arg in ("stage", "status") and isinstance(k.value, ast.Constant) and k.value.value in ("running", "queued")}
            keys = {k.arg for k in node.keywords if k.arg} - running
            for arg in node.args:
                if isinstance(arg, ast.Dict):
                    keys |= {k.value for k in arg.keys if isinstance(k, ast.Constant)}
            splat = any(k.arg is None for k in node.keywords)
            expire_only = keys == {"evidence_state"} and "expired" in ast.unparse(node)
            qual = ".".join(self.stack)
            if (keys & TERMINAL and not expire_only) or (splat and not _is_renewal(qual)):
                self._flag(node, f".values({sorted(keys)}{', **' if splat else ''})")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            for t in ast.walk(target):
                if isinstance(t, ast.Attribute) and t.attr in TERMINAL and not (
                        isinstance(t.value, ast.Name) and t.value.id == "self"):
                    self._flag(node, f".{t.attr} = ...")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and (m := RAW.search(node.value)) and not EXPIRE_ONLY.search(node.value):
            if any(re.search(rf"\b{c}\b", m["rest"].split("WHERE")[0], re.I) for c in TERMINAL):
                self._flag(node, "raw UPDATE of a terminal column")


def census(files: dict[str, str]) -> list[tuple[str, str, int, str]]:
    """Terminal writes outside the applier, over `{module path: source}` (only files that name a job table)."""
    out: list[tuple[str, str, int, str]] = []
    for module, text in files.items():
        if not SCOPE.search(text):
            continue
        visitor = _Census(module)
        visitor.visit(ast.parse(text))
        out += visitor.found
    return out


def production() -> dict[str, str]:
    skip = {"tests", "migrations", ".venv", "node_modules", "frontend"}
    return {str(p.relative_to(SOURCE)): p.read_text() for p in SOURCE.rglob("*.py")
            if not skip & set(p.relative_to(SOURCE).parts)}


SYNTHETIC = textwrap.dedent('''
    from sqlalchemy import update
    class S:
        async def sneaky(self, s):
            await s.execute(update(InvestigationRow).where(x).values(stage="failed"))
        async def apply(self, s):
            await s.execute(update(InvestigationRow).where(x).values(stage="failed", evidence_state="none"))
        async def splat(self, s, ending):
            await s.execute(update(LearningJobRow).values(finished_at=now, **ending))
        async def attr(self, row):
            row.status, row.reason = "failed", "x"
        async def raw(self, s):
            await s.execute(text("UPDATE jobs.investigations SET stage = 'failed' WHERE id = :i"))
        async def sweep(self, s):
            await s.execute(update(InvestigationRow).where(x).values(evidence_state="expired"))
        async def renew(self, s):
            await s.execute(update(InvestigationRow).values(lease_expires_at=t, **_progress()))
        async def claim(self, s):
            await s.execute(update(InvestigationRow).values(stage="running", started_at=t, lease_expires_at=t))
        async def other_table(self, s):
            await s.execute(pg_insert(AlertMappingRow).values(**fields).on_conflict_do_update(set_=dict(a=1)))
        async def lease(self, s):
            await s.execute(update(InvestigationRow).values(lease_expires_at=t, cost_usd=1.0))
''')


def test_the_census_flags_every_spelling_of_a_terminal_write_outside_the_applier_and_nothing_else():
    """On a synthetic source: keyword, splat, attribute and raw-SQL writes are found outside `apply`; the applier's own,
    the expiry sweep, a renewal and a lease write are not. (PR9: the census can fail)"""
    got = census({"jobs/store.py": SYNTHETIC})
    assert sorted({qual for _, qual, _, _ in got}) == ["S.attr", "S.raw", "S.sneaky", "S.splat"]


def test_nothing_in_production_outside_the_applier_writes_a_terminal_column_of_a_job_row():
    """Over all of `defender/` (tests and migrations aside): every write of a terminal column or an upload's promotion is
    inside `JobStore.apply` (or its `_apply*` helpers) in `jobs/`; the retention sweep may set `evidence_state` to
    `expired` only. (PR9, A-O4)"""
    files = production()
    outside = census(files)
    assert outside == [], "terminal writers outside the applier:\n" + "\n".join(
        f"{m}:{line} {q} {what}" for m, q, line, what in outside)
    # not vacuous: the applier exists, in jobs, and writes terminal columns itself
    assert re.search(r"async def apply\(", files["jobs/store.py"])
    assert re.search(r"\.values\([^)]*(stage|status)", files["jobs/store.py"]), "the applier writes no terminal column"


async def _enders(store, dsn):
    """One scene per ender of G19, each a callable ending its own row: cancel, offboard, take-over of an investigation,
    a learning job and a host request, queue expiry. Returns `{name: (call, check)}`."""
    scenes = {}
    inv = {}
    for name in ("cancel", "takeover"):
        inv[name] = await _queued(store, f"T-{name}", f"k-{name}")
        claim = await store.claim()
        plant_facts(dsn, claim.token, {"started": STARTED})
    scenes["cancel"] = (lambda: store.cancel_investigation(T1, inv["cancel"], actor="u-1"),
                        lambda: inv_row(dsn, inv["cancel"], "stage")["stage"])
    lapse_lease(dsn, inv["takeover"])
    scenes["takeover"] = (store.take_over, lambda: inv_row(dsn, inv["takeover"], "stage")["stage"])
    alert, source = await plant_complete_source(dsn, store, T1)
    job = await queue_learning_job(dsn, T1, alert.alert_id, source, key="k-j")
    await store.claim_learning_job()
    execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s", (job,))
    scenes["takeover-learning"] = (store.take_over, lambda: learn_row(dsn, job, "status")["status"])
    old = await queue_learning_job(dsn, T1, alert.alert_id, source, key="k-old")
    execute(dsn, "UPDATE jobs.learning_jobs SET created_at = now() - interval '2 days' WHERE id = %s", (old,))
    scenes["expiry"] = (store.claim_learning_job, lambda: learn_row(dsn, old, "status")["status"])
    rec, _ = await store.create_readiness(T1, actor="u-1")
    await store.claim_host_request()
    execute(dsn, "UPDATE jobs.host_requests SET lease_expires_at = now() - interval '1 second' WHERE id = %s",
            (rec.request_id,))
    scenes["takeover-host"] = (store.take_over, lambda: host_row(dsn, rec.request_id)["stage"])
    scenes["offboard"] = (lambda: store.offboard_tenant(T1, actor="u-1"), lambda: inv_row(dsn, inv["cancel"], "stage")["stage"])
    return scenes


LIVE = {"queued", "running"}


@pytest.mark.anyio
@pytest.mark.postgres
@pytest.mark.parametrize("applier_available", [False, True], ids=["apply-raises", "control-real-apply"])
async def test_every_ender_ends_its_row_only_through_apply(migrated_database, applier_available):
    """With `apply` raising, no ender (cancel, offboard, take-over of each kind, queue expiry) changes its row's stage;
    with the real applier the same scenes end them. (PR9; relies on the enders calling `self.apply`)"""
    from defender.jobs import JobStore
    from defender.tests.support.jobs._jobs1342 import fixed_clock

    class NoApply(JobStore):
        async def apply(self, *args, **kwargs):
            raise AssertionError("an ender reached for apply")

    dsn = migrated_database
    register_tenant(dsn, T1)
    store = (JobStore if applier_available else NoApply)(dsn, clock=fixed_clock, learning_max_age=3600)
    try:
        scenes = await _enders(store, dsn)
        for name, (call, observe) in scenes.items():
            before = observe()
            try:
                await call()
            except AssertionError:
                assert not applier_available, name
            after = observe()
            if applier_available:
                assert after not in LIVE, (name, after)
            else:
                assert after == before, (name, before, after)
    finally:
        await store.close()
