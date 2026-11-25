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
                   r"host_requests|uploads)|UPDATE\s+jobs\.", re.I)
#: A part of SQL text the census cannot read statically: an f-string's `{...}`, a `.format` or `%` placeholder, or a string
#: concatenated with a name. Read as any table (after `jobs.`) or any column (before `=` in the SET list).
HOLE = "\x00"
RAW = re.compile(r"UPDATE\s+(?:(?:jobs\.)?(?P<table>investigations|learning_jobs|host_requests|uploads)\b|jobs\.(?P<any>"
                 + HOLE + r"))(?P<rest>.*)", re.I | re.S)
FORMAT_HOLE = re.compile(r"\{[^{}]*\}|%\(\w+\)s|%s")
HOLE_COLUMN = re.compile(r"(?:\bSET\s+|,\s*)" + HOLE + r"\s*=", re.I)
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

    def _raw_sql(self, node: ast.AST, text: str) -> None:
        """SQL text (a literal, an f-string, a concatenation or a format template, holes marked `HOLE`): an UPDATE of a
        job table, named or formatted, that sets a terminal column, named or formatted, is a terminal write."""
        text = FORMAT_HOLE.sub(HOLE, text)
        m = RAW.search(text)
        if m is None or EXPIRE_ONLY.search(text):
            return
        columns = ANY_TABLE if m["any"] else TERMINAL_BY_TABLE[SQL_TABLE[m["table"].lower()]]
        sets = re.split(r"\bWHERE\b", m["rest"], maxsplit=1, flags=re.I)[0]
        if HOLE_COLUMN.search(sets) or any(re.search(rf"\b{c}\b", sets, re.I) for c in columns):
            self._flag(node, "raw UPDATE of a terminal column")

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self._raw_sql(node, node.value)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:  # an f-string: its formatted parts are holes
        self._raw_sql(node, _sql_text(node) or "")  # its parts are not visited again: one write, one finding

    def visit_BinOp(self, node: ast.BinOp) -> None:  # `"UPDATE jobs." + table + " SET ..."`, `"... %s ..." % x`
        text = _sql_text(node)
        if text is None:
            self.generic_visit(node)
            return
        self._raw_sql(node, text)
        for side in (node.left, node.right):  # a nested call or name is still visited; its string parts are not re-read
            if not isinstance(side, ast.Constant | ast.JoinedStr | ast.BinOp):
                self.visit(side)


def _sql_text(node: ast.AST) -> str | None:
    """The text a string expression builds, with each part the census cannot read as `HOLE`; None for no string at all."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else HOLE
                       for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _sql_text(node.left)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _sql_text(node.left), _sql_text(node.right)
        if left is None and right is None:
            return None
        return (HOLE if left is None else left) + (HOLE if right is None else right)
    return None


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


SYNTHETIC_BUILT = textwrap.dedent('''
    from sqlalchemy import text
    class B:
        async def reaper(self, s):
            for table, column in (("investigations", "stage"), ("learning_jobs", "status")):
                await s.execute(text(f"UPDATE jobs.{table} SET {column} = 'failed', finished_at = now() "
                                     f"WHERE {column} = 'running'"))
        async def formatted_table(self, s, table):
            await s.execute(text(f"UPDATE jobs.{table} SET evidence_state = 'none' WHERE id = :i"))
        async def formatted_column(self, s, column):
            await s.execute(text(f"UPDATE jobs.investigations SET {column} = 'failed' WHERE id = :i"))
        async def concatenated(self, s, table):
            await s.execute(text("UPDATE jobs." + table + " SET status = 'failed' WHERE id = :i"))
        async def templated(self, s, table):
            await s.execute(text("UPDATE jobs.{} SET finished_at = now() WHERE id = :i".format(table)))
        async def percent(self, s, table):
            await s.execute(text("UPDATE jobs.%s SET failure_reason = 'x' WHERE id = :i" % table))
        async def plain(self, s):
            sql = "UPDATE jobs.learning_jobs SET reason = 'x' WHERE id = :i"
            await s.execute(text(sql))
        async def _apply_built(self, s, table):
            await s.execute(text(f"UPDATE jobs.{table} SET stage = 'failed' WHERE id = :i"))
        async def built_lease(self, s, table, at):
            await s.execute(text(f"UPDATE jobs.{table} SET lease_expires_at = {at}, cost_usd = %s WHERE id = :i"))
        async def built_expiry(self, s, table):
            await s.execute(text(f"UPDATE jobs.{table} SET evidence_state = 'expired' WHERE id = :i"))
        async def other_schema(self, s, table):
            await s.execute(text(f"UPDATE tenancy.{table} SET stage = 'failed' WHERE id = :i"))
        async def built_queue(self, s, table):
            await s.execute(text(f"UPDATE jobs.{table} SET attempt = attempt + 1 WHERE id = :i"))
''')


def test_the_census_reads_sql_built_at_run_time_as_a_write_to_every_job_table():
    """On a synthetic source: an UPDATE whose table or column is an f-string part, a concatenation, a `.format` or `%`
    template, or a plain string held in a name, setting a terminal column (or a formatted one), is found outside `apply`;
    the same text inside `_apply*`, a built lease or queue write, a built expiry, and another schema's table are not.
    (PR9, triage 1 family D3: a table name formatted in is a write to every job table)"""
    got = census({"jobs/store.py": SYNTHETIC_BUILT})
    assert sorted({qual for _, qual, _, _ in got}) == ["B.concatenated", "B.formatted_column", "B.formatted_table",
                                                        "B.percent", "B.plain", "B.reaper", "B.templated"], got
    assert len([q for _, q, _, _ in got if q == "B.reaper"]) == 1, "one built statement is one finding"
    assert census({"worker/elsewhere.py": SYNTHETIC_BUILT}), (
        "a module outside jobs/ that only builds its job-table SQL is not in the census's scope")


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
    execute(dsn, "UPDATE jobs.learning_jobs SET created_at = now() - interval '2 days' WHERE id = %s",  # the DB clock (D10)
            (old,))
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
