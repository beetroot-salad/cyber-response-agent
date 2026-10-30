# ruff: noqa: PT018
"""#1214 attack-3 hole 3 (P3, RC-9): the by-hand revert (`cli/learning/revert_lesson.py`) works for a tenant only
while it is `active`; it mints a credential and opens a PR, so a refusal must come before either.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared.contracts._by_path import import_lint_lib
from defender.tests.tenancy.tenant_1108_delivery._support import merged_agent_lesson
from defender.tests.tenancy.tenant_1108_p4._drain_support import critical_text, remote_branches
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge
from defender.tests.tenancy.tenant_1108_p4.test_revert_cli import LESSON, LESSON_PATH, _cli

DEFENDER = Path(__file__).resolve().parents[3]
_astlib = import_lint_lib("_astlib")


def _directory_for(t: Any, state: str | None) -> Any:
    """The tenant's directory in `state`, wiring and a live generation recorded; `None` is a directory that holds no row."""
    from defender.tenancy import InMemoryTenantRepository, TenantDirectory

    if state is None:
        twin: Any = InMemoryTenantRepository()
        return TenantDirectory(lambda: twin)
    return t.directory_with(state=state)


@pytest.mark.parametrize("state", ["active", "creating", "offboarding", "offboarded", None])
def test_the_by_hand_revert_proceeds_only_for_an_active_tenant(p4_tenant, caplog, state):
    """Revert of a lesson refuses a tenant that is creating, offboarding, offboarded or unknown: exit 2 naming why, no
    branch pushed, no PR; the active tenant's revert opens its PR (control)."""
    t = p4_tenant
    bind_forge(t)
    merged_agent_lesson(t.p3, t.scratch, "seed-revert", LESSON_PATH, b"agent-written lesson\n")
    before = set(remote_branches(t.remote, prefix=""))
    with caplog.at_level(logging.INFO):
        rc = _cli().main(["--tenant", t.tenant_id, LESSON], client=t.forge.client, identity=t.vault.identity(),
                         directory=_directory_for(t, "active" if state == "active" else state))
    after = set(remote_branches(t.remote, prefix=""))
    if state == "active":
        assert rc == 0, critical_text(caplog)
        assert len(after - before) == 1 and len(t.forge.creates) == 1
        return
    assert rc == 2, critical_text(caplog)
    text = critical_text(caplog)
    assert (state in text and "not active" in text) if state else "no such tenant" in text, text
    assert after == before and t.forge.creates == []


def _functions_calling(tree: ast.Module, name: str, module: str) -> set[str]:
    """The functions of `module` with a call to `name`: a callee `_astlib` resolves to an origin ending in `.name`
    (an alias or the attribute form is the same function), or, where the receiver is a value it cannot resolve, a
    method spelled `name`."""
    env = _astlib.module_env(tree, module=module)
    found: set[str] = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                origin = _astlib.callee(node, env)
                if (origin.rpartition(".")[2] == name if origin is not None
                        else isinstance(node.func, ast.Attribute) and node.func.attr == name):
                    found.add(fn.name)
    return found


def _module_name(rel: str) -> str:
    return "defender." + rel.removesuffix(".py").replace("/", ".")


def _calling(rel: str, name: str) -> set[str]:
    return _functions_calling(ast.parse((DEFENDER / rel).read_text(encoding="utf-8")), name, _module_name(rel))


def test_the_census_lists_every_credential_caller_and_every_admission_site():
    """RC-9: the modules that mint or open a delivery, and the modules that admit a tenant, are named (which private
    function does it is the implementer's); the by-hand revert admits; a new admitting module fails here."""
    credential = {"learning/author/version_control/delivery.py": "forge_credential",
                  "learning/author/version_control/publish.py": "forge_credential",
                  "learning/core/drains.py": "opened_delivery", "cli/tenant.py": "opened_delivery"}
    for rel, call in credential.items():
        assert _calling(rel, call), f"{rel} no longer reaches the credential through {call}"
    admitting = {"run.py": set(), "learning/core/cli.py": set(), "learning/core/drains.py": {"revert_delivery"},
                 "cli/tenant.py": set()}
    for rel, required in admitting.items():
        found = _calling(rel, "admit_tenant")
        assert found and required <= found, (rel, found)
    others = [p.relative_to(DEFENDER).as_posix() for p in DEFENDER.rglob("*.py")
              if "tests" not in p.relative_to(DEFENDER).parts and ".venv" not in p.parts
              and p.relative_to(DEFENDER).as_posix() not in admitting
              and _calling(p.relative_to(DEFENDER).as_posix(), "admit_tenant")]
    assert others == [], "a new module admits a tenant: list it in this census"
    # the by-hand revert reaches the delivery only through the admitting `revert_delivery`
    assert _calling("cli/learning/revert_lesson.py", "revert_delivery")
