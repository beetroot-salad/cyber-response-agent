"""#1618 flow 5: onboarding's prepare calls the fetch seam the way the production launcher accepts it.

The lifecycle world's fetch seam (`_fetch_1618`, `K.Fetch`) takes `dest` either positionally or by keyword, so a prepare that
passed it in a shape the production binding refuses stayed green there. Here prepare is handed what `lifecycle/__main__.py`
hands it, `investigation.publish_launch.launch_publish`, executed for real: only its child's command is a stand-in printing one
valid report line (the launcher's own `command=` seam), so whatever prepare passes reaches the production signature.
"""
from __future__ import annotations

import ast
import functools
import sys
from pathlib import Path

import pytest

from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

#: The commit the stand-in child reports (a full id; the launcher judges the line's grammar).
REPORTED = "0123456789abcdef0123456789abcdef01234567"
LIFECYCLE_MAIN = Path(__file__).resolve().parents[3] / "lifecycle" / "__main__.py"


def _wired_fetch() -> tuple[str, str]:
    """`(module, name)` of what `lifecycle/__main__.py` passes as `HostActor(..., fetch=)`, read from its source with the
    lints' shared name resolver (`tooling/lint/_astlib.py`: real scoping, so an alias, an attribute form or a local
    shadow resolves as Python would)."""
    from defender.tests.support.shared.contracts._by_path import import_lint_lib

    astlib = import_lint_lib("_astlib")
    tree = ast.parse(LIFECYCLE_MAIN.read_text(encoding="utf-8"))
    env = astlib.module_env(tree, module="defender.lifecycle.__main__", package="defender.lifecycle")
    passed = [astlib.origin(kw.value, env) for node in ast.walk(tree) if isinstance(node, ast.Call)
              and astlib.callee(node, env) == "defender.lifecycle.HostActor"
              for kw in node.keywords if kw.arg == "fetch"]
    assert len(passed) == 1, f"lifecycle/__main__.py does not hand HostActor one fetch seam: {passed}"
    assert passed[0] is not None, "lifecycle/__main__.py's fetch seam is not an imported name"
    module, _dot, name = passed[0].rpartition(".")
    return module, name


@pytest.fixture
def world(tmp_path, data_root):
    import importlib

    module, name = _wired_fetch()
    production = getattr(importlib.import_module(module), name)
    stand_in_child = [sys.executable, "-c", f"print('ok {REPORTED}')"]
    w = LifecycleWorld(tmp_path, data_root)
    w.host_actor = w.new_host(w.tenants, fetch=functools.partial(production, command=stand_in_child))
    w.production_fetch = (module, name)
    yield w
    w.close()


def test_1618_f5_prepare_is_wired_to_the_production_launcher_and_calls_it_in_the_shape_it_accepts(world):
    """`lifecycle/__main__.py` hands the host actor the run launcher (`launch_publish`); prepare, handed that same function,
    completes onboarding: its call (tenant id, the destination and the data root) binds the production signature, and the
    launcher's `ok <commit>` line is what prepare reads. (Flow 5, D5; the seam shape is `fetch(tenant_id, dest, *, data_root,
    commit=None)`, the launcher's `dest` keyword-only)"""
    assert world.production_fetch == ("defender.investigation.publish_launch", "launch_publish"), world.production_fetch
    tenant = world.create()
    world.drive()
    item = world.item(tenant)
    assert item["state"] == "active", f"prepare did not complete over the production launcher: {item}"
