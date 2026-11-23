"""#1546 PR9: nothing but the applier writes a terminal column of a job row (or promotes an upload). Two forms, because
each sees what the other cannot:

- a census over production source (AST, not grep: `store.py` writes terminal columns by `update().values(k=...)`, by ORM
  attribute assignment and by dict splats) that cannot be fooled by a new ender added anywhere in `defender/`, but sees only
  statically spelled writes (a column name built at run time, or a write by a database trigger, escapes it);
- a behavioural run over every ender with `apply` made to raise, which sees any path whatever its spelling but only the
  enders it drives (the census of G19), and relies on the enders calling `self.apply`.
The census is checked on synthetic sources too, so it can fail. Terminal columns are per table: an upload's only terminal
column is `accepted_at` (the applier's promotion; `begin_upload` and `finish_upload` own its `status` and `scrub`); a
non-terminal insert and a renewal's non-terminal columns are exempt (G3a)."""
from __future__ import annotations

import ast
import datetime as dt
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
from defender.tests.support.jobs._jobs1342 import NOW, T1, lapse_lease, register_tenant
from defender.tests.support.jobs._worker1342 import _queued
from defender.tests.support.shared._postgres1339 import execute

SOURCE = Path(__file__).resolve().parents[2]
#: Per table, the columns whose being set ends (or accepts the evidence of) a job row. Not the lease, the running cost or
#: progress. An upload's `status` and `scrub` are written by its own verbs (`begin_upload`, `finish_upload`), not terminal.
TERMINAL_BY_TABLE = {
    "InvestigationRow": frozenset({"stage", "failure_reason", "failure_message", "finished_at", "disposition", "scrub",
                                   "evidence_state", "knowledge", "cost_is_lower_limit"}),
    "LearningJobRow": frozenset({"status", "reason", "message", "finished_at", "publish_state", "evidence_state",
                                 "sibling_cost_is_lower_limit"}),
    "HostRequestRow": frozenset({"stage", "failure_reason", "failure_message", "finished_at", "result"}),
    "UploadRow": frozenset({"accepted_at"}),
}
SQL_TABLE = {"investigations": "InvestigationRow", "learning_jobs": "LearningJobRow", "host_requests": "HostRequestRow",
             "uploads": "UploadRow"}
#: A variable naming the table (a class passed in) or an attribute write on a row of unknown class: every table's set but
#: the upload's, plus `accepted_at` (an object named `*upload*` is read as an upload row).
ANY_TABLE = frozenset().union(*(v for k, v in TERMINAL_BY_TABLE.items() if k != "UploadRow")) | {"accepted_at"}
#: Columns a renewal may write although the applier writes them at an end too (a running row's knowledge copy).
RENEWAL_EXEMPT = frozenset({"knowledge"})
JOB_ROWS = frozenset(TERMINAL_BY_TABLE)
SCOPE = re.compile(r"InvestigationRow|LearningJobRow|HostRequestRow|UploadRow|jobs\.(investigations|learning_jobs|"
                   r"host_requests|uploads)")
RAW = re.compile(r"UPDATE\s+(jobs\.)?(?P<table>investigations|learning_jobs|host_requests|uploads)\b(?P<rest>.*)",
                 re.I | re.S)
EXPIRE_ONLY = re.compile(r"SET\s+evidence_state\s*=\s*'expired'\s*(WHERE|$)", re.I)
LIVE_WORDS = ("running", "queued")


def _is_applier(qualname: str, module: str) -> bool:
    last = qualname.rsplit(".", 1)[-1]
    return module.startswith("jobs/") and (last == "apply" or last.startswith("_apply"))


def _is_renewal(qualname: str) -> bool:
    return qualname.rsplit(".", 1)[-1].lstrip("_").startswith("renew")


def _names_an_upload(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and "upload" in node.id.lower()


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
    def _target(func: ast.Attribute) -> tuple[str, str | None] | None:
        """`(verb, table)` of the `update(X)` / `insert(X)` in the `.values` receiver's chain, X a job row class (its name)
        or a variable (a class passed in: `None`, so every table's set applies); None for another table's class."""
        node: ast.AST = func.value
        while isinstance(node, ast.Call | ast.Attribute):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ("update", "insert", "pg_insert") and node.args:
                    first, verb = node.args[0], ("update" if node.func.id == "update" else "insert")
                    if not isinstance(first, ast.Name):
                        return None
                    if first.id in JOB_ROWS:
                        return verb, first.id
                    return (verb, None) if not first.id[:1].isupper() else None
                node = node.func
            else:
                node = node.value
        return None

    def visit_Call(self, node: ast.Call) -> None:
        target = self._target(node.func) if isinstance(node.func, ast.Attribute) and node.func.attr == "values" else None
        if target is not None:
            verb, table = target
            terminal = TERMINAL_BY_TABLE[table] if table else ANY_TABLE
            consts = {k.arg: k.value.value for k in node.keywords if k.arg and isinstance(k.value, ast.Constant)}
            live = {c for c in ("stage", "status") if consts.get(c) in LIVE_WORDS}
            keys = {k.arg for k in node.keywords if k.arg} - live
            for arg in node.args:
                if isinstance(arg, ast.Dict):
                    keys |= {k.value for k in arg.keys if isinstance(k, ast.Constant)}
            splat = any(k.arg is None for k in node.keywords)
            qual = ".".join(self.stack)
            if _is_renewal(qual):
                keys -= RENEWAL_EXEMPT
            expire_only = keys == {"evidence_state"} and "expired" in ast.unparse(node)
            # An insert of a queued or running row (or of one with no stage) is not an ending; an upload's insert is
            # exempt too unless it carries `accepted_at`.
            ends = any(k.arg in ("stage", "status") and not (isinstance(k.value, ast.Constant)
                                                              and k.value.value in LIVE_WORDS) for k in node.keywords)
            fresh = verb == "insert" and table != "UploadRow" and not ends
            if not fresh and ((keys & terminal and not expire_only) or (splat and not _is_renewal(qual)
                                                                        and verb == "update")):
                self._flag(node, f".values({sorted(keys)}{', **' if splat else ''})")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            for t in ast.walk(target):
                if isinstance(t, ast.Attribute) and not (isinstance(t.value, ast.Name) and t.value.id == "self") and (
                        t.attr in (TERMINAL_BY_TABLE["UploadRow"] if _names_an_upload(t.value) else ANY_TABLE)):
                    self._flag(node, f".{t.attr} = ...")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if (isinstance(node.value, str) and (m := RAW.search(node.value)) and not EXPIRE_ONLY.search(node.value)
                and any(re.search(rf"\b{c}\b", m["rest"].split("WHERE")[0], re.I)
                        for c in TERMINAL_BY_TABLE[SQL_TABLE[m["table"].lower()]])):
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
        async def promote(self, s):
            await s.execute(update(UploadRow).where(x).values(accepted_at=now))
        async def promote_raw(self, s):
            await s.execute(text("UPDATE jobs.uploads SET accepted_at = now() WHERE token = :t"))
        async def insert_ended(self, s):
            await s.execute(pg_insert(InvestigationRow).values(stage="failed", failure_reason="x"))
        async def sweep(self, s):
            await s.execute(update(InvestigationRow).where(x).values(evidence_state="expired"))
        async def renew(self, s):
            await s.execute(update(InvestigationRow).values(lease_expires_at=t, knowledge=k, **_progress()))
        async def claim(self, s):
            await s.execute(update(InvestigationRow).values(stage="running", started_at=t, lease_expires_at=t))
        async def begin_upload(self, s):
            await s.execute(insert(UploadRow).values(token=t, object=o, status="pending", scrub=None))
        async def finish_upload(self, s, upload):
            await s.execute(update(UploadRow).where(x).values(status="uploaded", scrub="clean"))
            upload.status = "refused"
            await s.execute(text("UPDATE jobs.uploads SET status = 'uploaded' WHERE token = :t"))
        async def queue(self, s):
            await s.execute(insert(LearningJobRow).values(status="queued", publish_state="none", sibling_cost_usd=0))
            await s.execute(insert(InvestigationRow).values(stage="queued", cost_usd=0))
        async def other_table(self, s):
            await s.execute(pg_insert(AlertMappingRow).values(**fields).on_conflict_do_update(set_=dict(a=1)))
        async def lease(self, s):
            await s.execute(update(InvestigationRow).values(lease_expires_at=t, cost_usd=1.0))
''')


def test_the_census_flags_every_spelling_of_a_terminal_write_outside_the_applier_and_nothing_else():
    """On a synthetic source: keyword, splat, attribute, raw-SQL, promotion and ended-insert writes are found outside `apply`;
    the applier's own, the expiry sweep, a renewal, a claim, a queued insert, the upload verbs (which own `status` and
    `scrub`) and a lease write are not. (PR9: the census can fail and does not flag the upload verbs)"""
    got = census({"jobs/store.py": SYNTHETIC})
    assert sorted({qual for _, qual, _, _ in got}) == ["S.attr", "S.insert_ended", "S.promote", "S.promote_raw", "S.raw",
                                                        "S.sneaky", "S.splat"]


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
    execute(dsn, "UPDATE jobs.learning_jobs SET created_at = %s WHERE id = %s",  # aged by the store's clock, which wrote it
            (NOW - dt.timedelta(days=2), old))
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
