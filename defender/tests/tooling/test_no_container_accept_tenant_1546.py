"""#1546 (design r10 (b), "New lint"): no job-container entry calls `accept_tenant`, directly or through its host wrappers
(`systems.run_tenant.host_tenant`, `tenancy.requested_tenant`); each builds its `JobTenant` from the launch facts
(`job_tenant_from_launch`). Static, in the style of #1618's `test_no_lock_1618` census.

Scope (r10's list, by function): `run.py`'s container entries `job_main` (investigation), `readiness_main` (readiness),
`_sibling_set_up` (the learning arms) and the tenant builder they share, `_container_tenant`; `learning/branch/cli.py`'s
container admission `_admitted` and the learning job's entry `learning/branch/job_entry.py`'s `main`; adoption's `main` and
`_deliver`. Each is scanned with every module-level function of the same module it calls or names (a function handed on as
a value is reached too), transitively. Out of scope (r10, claim R10-L8): the operator paths
in the same modules (`run.main`, `cli._launch`'s host branch, which reach `host_tenant`), and the post-step and drain entries,
which keep `accept_tenant` over the bound tenant folder while H4's bind stands; the drain and post-step entries are this
scanner's control that it sees a real call."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

#: The checkout's `defender/` (a namespace package: no `__file__`).
DEFENDER = Path(__file__).resolve().parents[2]

#: `accept_tenant` and the host wrappers that reach it (r10 (b)); `requested_tenant_id` (an id parse) is not one.
FORBIDDEN = frozenset({"accept_tenant", "host_tenant", "requested_tenant"})

#: (module, entry function, builds): the job-container entry paths of the five `JobTenant` kinds; `builds` marks the
#: functions that must themselves (with what they reach) build the tenant with `job_tenant_from_launch`.
ENTRIES = [("run.py", "job_main", False), ("run.py", "readiness_main", False), ("run.py", "_container_tenant", True),
           ("run.py", "_sibling_set_up", True), ("learning/branch/cli.py", "_admitted", True),
           ("learning/branch/job_entry.py", "main", False), ("adoption/__main__.py", "main", True),
           ("adoption/__main__.py", "_deliver", True)]

#: Entries r10 leaves on `accept_tenant` (H4's bind): the scanner's control over real code.
EXEMPT = [("learning/branch/post_step.py", "main"), ("learning/branch/drain_job.py", "main")]


def _module(rel: str) -> ast.Module:
    return ast.parse((DEFENDER / rel).read_text(encoding="utf-8"), filename=rel)


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def reached(tree: ast.Module, entry: str) -> tuple[list[str], set[str]]:
    """The forbidden calls (`name:line`) in `entry` and the module-level functions it reaches; and that set of functions."""
    functions = _functions(tree)
    assert entry in functions, f"the entry `{entry}` is not a module-level function (renamed? update ENTRIES)"
    seen, todo, found = set(), [entry], []
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for node in ast.walk(functions[name]):
            if isinstance(node, ast.Call) and _name(node.func) in FORBIDDEN:
                found.append(f"{name}:{node.lineno}:{_name(node.func)}")
            elif isinstance(node, ast.Name) and node.id in functions:  # called, or handed on as a value
                todo.append(node.id)
    return found, seen


def _calls(tree: ast.Module, functions: set[str], callee: str) -> bool:
    by_name = _functions(tree)
    return any(isinstance(n, ast.Call) and _name(n.func) == callee for f in functions for n in ast.walk(by_name[f]))


@pytest.mark.parametrize(("rel", "entry", "builds"), ENTRIES, ids=[f"{r.split('/')[-2] if '/' in r else 'run'}-{e}"
                                                                      for r, e, _b in ENTRIES])
def test_a_job_container_entry_reaches_no_accept_tenant_and_builds_its_job_tenant_from_the_launch(rel, entry, builds):
    """The entry, and every function of its module it reaches, calls none of `accept_tenant`, `host_tenant`,
    `requested_tenant`; and a `builds` entry does build its tenant with `job_tenant_from_launch` (so a renamed or emptied
    entry is not vacuously clean). (r10 (b): every container entry, uniformly)"""
    tree = _module(rel)
    found, seen = reached(tree, entry)
    assert found == [], f"{rel}: a container entry reaches the host acceptance: {found}"
    if builds:
        assert _calls(tree, seen, "job_tenant_from_launch"), f"{rel}:{entry} builds no `JobTenant` from the launch facts"


@pytest.mark.parametrize(("rel", "entry"), EXEMPT, ids=["post_step", "drain"])
def test_control_the_scanner_finds_the_accept_tenant_the_exempt_entries_keep(rel, entry):
    """Control over real code: the post-step and drain entries (out of scope, r10 R10-L8) still call `accept_tenant`, and
    the scanner reports it, so its silence over the entries above is not blindness."""
    found, _seen = reached(_module(rel), entry)
    assert any(f.endswith(":accept_tenant") for f in found), f"{rel}: the scanner saw no `accept_tenant`: {found}"


@pytest.mark.parametrize("src", [
    "from defender import tenancy\ndef entry(ns, root):\n    return tenancy.accept_tenant(root, ns.tenant)\n",
    "from defender.tenancy import accept_tenant\ndef entry(ns, root):\n    return accept_tenant(root, ns.tenant)\n",
    "def helper(root, t):\n    return run_tenant.host_tenant(root, t)\n\ndef entry(ns, root):\n    return helper(root, ns.tenant)\n",
    "def entry(ns, root):\n    return tenancy.requested_tenant(ns.tenant)\n",
], ids=["attribute", "bare", "through_a_module_helper", "requested_tenant"])
def test_control_a_planted_violation_is_found_however_it_is_reached(src):
    """Planted violations: a direct call, spelled either way, one reached through a helper of the same module, and the
    `requested_tenant` wrapper are each found."""
    found, _seen = reached(ast.parse(src), "entry")
    assert len(found) == 1, found


def test_control_an_id_parse_and_the_launch_build_are_no_findings():
    """`requested_tenant_id` (an id parse) and `job_tenant_from_launch` are not the host acceptance."""
    src = ("def entry(ns, root, launch):\n    tenancy.requested_tenant_id(ns.tenant)\n"
           "    return tenancy.job_tenant_from_launch(root, ns.tenant, launch)\n")
    found, seen = reached(ast.parse(src), "entry")
    assert found == []
    assert _calls(ast.parse(src), seen, "job_tenant_from_launch")
