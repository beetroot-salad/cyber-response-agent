"""#1214 O6: the tenant's last publish outcome lives in `tenancy.publish_status` (not `publish-status.json`): recorded by
host processes, readable, replaced by the next outcome and deleted at `finish` (O6, P2, Flow 2.4). Successors of #1108 P4's
file-based assertions: a misconfiguration is recorded then cleared by a success; a transient outage and an operator
refusal are told apart.

GAP-Rc-2 (pinned here, not by r9): on both repositories, `await repo.record_publish_status(T, line, *, by)` stores the
outcome a launch-time publish report `line` states (`fresh <commit>`; `stale:transient <why>`; `stale:operator <why>`;
`misconfigured <why>`) and `await repo.publish_status(T) -> dict | None` reads it with the keys of the old file: `by`,
`published` (the commit) or `refused` (the reason) with `kind` (`transient` | `operator`); None when none is recorded.
Who records the first publish in prepare (the publish child or the host actor) is not pinned (GAP-Rc-3): the recording
publish fake writes nothing, so no case asserts prepare's own write.

#1214 attack-3 hole 6 (O6): after a publish nothing named `tenant.json` or `publish-status.json` exists under the data
root, and no production string expression folds to either name (a concatenation is not a constant).

#1214 O6: production code neither reads nor writes `tenant.json` or `publish-status.json`.

No production module spells either name, `tenancy/_tenant.py` (the row's former owner) included: the lab's old row
file is deleted by hand when it moves, not by code (DC-8, SK-6).
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytest.importorskip('fastapi')

from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402
from defender.tests.tenancy.lifecycle_1214.test_repository_contract import (  # noqa: E402,F401
    ABSENT,
    T1,
    Store,
    store,
)
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, unbind_forge


BY = "launch-time publish"


async def _record(s: Store, line: str, tenant: str = T1) -> None:
    await s.repo.record_publish_status(tenant, line, by=BY)


@pytest.mark.anyio
async def test_a_tenant_with_no_outcome_reads_none(store):
    """Nothing recorded reads as None, also for an unknown tenant (O6)."""
    await store.seed(T1)
    assert await store.repo.publish_status(T1) is None
    assert await store.repo.publish_status(ABSENT) is None


@pytest.mark.anyio
async def test_a_published_commit_is_recorded_and_readable(store):
    """`fresh <commit>` reads back as published at that commit by the recorder, with no refusal (O6)."""
    await store.seed(T1)
    await _record(store, "fresh 0123abcd")
    status = await store.repo.publish_status(T1)
    assert status["published"] == "0123abcd" and status["by"] == BY
    assert "refused" not in status


@pytest.mark.anyio
@pytest.mark.parametrize(("line", "kind"), [
    ("stale:transient the forge is unreachable", "transient"),
    ("stale:operator the history diverged", "operator"),
    ("misconfigured no issuer config", "operator"),
])
async def test_a_refusal_is_recorded_with_its_kind_and_reason(store, line, kind):
    """A transient outage and an operator refusal are told apart; a misconfiguration needs a human (O6, O-SEE)."""
    await store.seed(T1)
    await _record(store, "fresh 0123abcd")  # control: a published outcome is replaced, not kept beside
    await _record(store, line)
    status = await store.repo.publish_status(T1)
    assert status["kind"] == kind and line.partition(" ")[2] in status["refused"]
    assert "published" not in status


@pytest.mark.anyio
async def test_a_misconfiguration_is_recorded_and_a_later_success_clears_it(store):
    """The refusal stands until a publish succeeds; then only the commit is left (O6)."""
    await store.seed(T1)
    await _record(store, "misconfigured the issuer config is missing")
    assert (await store.repo.publish_status(T1))["refused"]
    await _record(store, "fresh feedbeef")
    status = await store.repo.publish_status(T1)
    assert status["published"] == "feedbeef" and "refused" not in status and "kind" not in status


@pytest.mark.anyio
async def test_one_tenants_outcome_is_not_anothers(store):
    """Status is keyed by tenant (O6)."""
    await store.seed(T1)
    await store.seed(ABSENT)
    await _record(store, "stale:operator diverged", T1)
    assert await store.repo.publish_status(ABSENT) is None
    assert (await store.repo.publish_status(T1))["kind"] == "operator"


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


@pytest.mark.anyio
def test_finish_deletes_the_publish_status_and_nothing_earlier_does(world):
    """The status is still there while the tenant is being torn down and gone once `finish` has run (Flow 2.4, O6)."""
    tenant = world.active_tenant()
    world.call(world.tenants.record_publish_status, tenant, "fresh 0123abcd", by=BY)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive(stop=lambda: world.item(tenant)["step"] == "finish")
    assert world.item(tenant)["step"] == "finish"
    assert world.call(world.tenants.publish_status, tenant)["published"] == "0123abcd", "deleted before finish"
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    assert world.call(world.tenants.publish_status, tenant) is None


def _shadow_files(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for name in (ROW, STATUS) for p in root.rglob(name))


def test_the_shadow_file_check_sees_a_planted_file(tmp_path):
    """Control: the check reports a file of either name wherever it sits under the root."""
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / STATUS).write_text("x", encoding="utf-8")
    (tmp_path / ROW).write_text("x", encoding="utf-8")
    assert _shadow_files(tmp_path) == [f"t/{STATUS}", ROW]


@pytest.mark.parametrize("outcome", ["fresh", "misconfigured"])
def test_a_publish_leaves_no_row_or_status_file_under_the_data_root(tmp_path, data_root, outcome):
    """The publish child's success and its local misconfiguration both record to the database only (O6)."""
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        if outcome == "misconfigured":
            unbind_forge(t)
        else:
            t.merge(B.MERGE_FILES)
        line = B.run_child(t, mint=outcome == "misconfigured")
        assert B.outcome_class(line) == outcome, line
        assert _shadow_files(Path(t.data_root)) == []


def _folded(node: ast.AST) -> str | None:
    """The string a constant-only expression builds: literals, `+`, f-strings without fields, `''.join` of literals,
    `%` and `.format` of literals; None for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded(node.left), _folded(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = [_folded(v) for v in node.values]
        return None if None in parts else "".join(parts)  # type: ignore[arg-type]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple)):
        # `str.join` on a literal separator: a method of a value, which `_astlib.callee` cannot resolve.
        if node.func.attr != "join":  # lint-ast-resolve: ok — a str method on a literal receiver; the spelling is the fact
            return None
        sep = _folded(node.func.value)
        parts = [_folded(e) for e in node.args[0].elts]
        return None if sep is None or None in parts else sep.join(parts)  # type: ignore[arg-type]
    return None


def test_the_folding_scan_sees_each_way_of_building_a_name():
    """Control for the scan below: concatenation, f-string and join spell the name; a plain word does not."""
    for source in ('"publish-" + "status.json"', '"-".join(["publish", "status.json"])', 'f"publish-status.json"'):
        assert _folded(ast.parse(source, mode="eval").body) == "publish-status.json", source
    assert _folded(ast.parse('"publish" + "ing"', mode="eval").body) == "publishing"


def test_no_production_expression_folds_to_the_row_or_status_file_name():
    """No `+`, f-string or join in production builds `publish-status.json`; `tenant.json` is built only by the owner (O6)."""
    hits = []
    for path in _production_sources():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call)):
                value = _folded(node)
                owner_row = _rel(path) == "tenancy/_tenant.py" and value is not None and Path(value).name == ROW
                if value is not None and Path(value).name in (ROW, STATUS) and not owner_row:
                    hits.append(f"{_rel(path)}:{node.lineno}:{value}")
    assert hits == []


DEFENDER = Path(__file__).resolve().parents[3]


#: The row's former owner: held to the same rule as every other module.
FORMER_OWNER = "tenancy/_tenant.py"


ROW, STATUS = "tenant.json", "publish-status.json"


#: Names whose use outside the owner is a read or write of the retired row (O6).
ROW_READERS = {"ROW_NAME", "retire_row", "row_path", "create_tenant", "require_tenant", "read_forge_binding",
               "refuse_foreign_data_root", "ForgeBinding"}


def _production_sources() -> list[Path]:
    return [p for p in DEFENDER.rglob("*.py")
            if "tests" not in p.relative_to(DEFENDER).parts and ".venv" not in p.parts]


def _strings(tree: ast.AST) -> list[tuple[int, str]]:
    """Every string constant of `tree` except docstrings: (line, value)."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return [(n.lineno, n.value) for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]


def _spells(value: str, name: str) -> bool:
    return value == name or value.endswith("/" + name)


def _rel(path: Path) -> str:
    return path.relative_to(DEFENDER).as_posix()


def test_no_production_module_spells_tenant_json():
    """No production module spells the row's file name, its former owner included (O6, SK-6)."""
    sources = _production_sources()
    assert any(_rel(p) == FORMER_OWNER for p in sources)  # control: the census sees the former owner and production
    found = [f"{_rel(p)}:{n}" for p in sources
             for n, value in _strings(ast.parse(p.read_text(encoding="utf-8"))) if _spells(value, ROW)]
    assert found == []


def test_no_production_module_spells_publish_status_json():
    """Publish status lives in PostgreSQL: not even the owner names the file (O6)."""
    found = [f"{_rel(p)}:{n}" for p in _production_sources()
             for n, value in _strings(ast.parse(p.read_text(encoding="utf-8"))) if _spells(value, STATUS)]
    assert found == []


def test_no_production_module_reads_the_row_through_its_names():
    """The row's readers, writers and remover are gone: no import or use of them anywhere (O6)."""
    hits = []
    for path in _production_sources():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.Attribute):
                names = [node.attr]
            elif isinstance(node, ast.Name):
                names = [node.id]
            hits += [f"{_rel(path)}:{node.lineno}:{n}" for n in names if n in ROW_READERS]
    assert hits == []
