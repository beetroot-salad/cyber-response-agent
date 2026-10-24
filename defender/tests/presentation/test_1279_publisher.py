"""#1279 A4 — the publisher for an accepted tenant: a layout over the one publish root, refusing outside `dev`."""
from __future__ import annotations

import importlib

import pytest

from defender.configuration import _env
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared.contracts._data_root_1078 import D9_TENANT_ID, set_up_tenant

RUN = fixture_uuid("run:publisher-1279")
OTHER_RUN = fixture_uuid("run:publisher-1279-other")
SECOND_TENANT = fixture_uuid("tenant:publisher-1279-second")


@pytest.fixture
def dev(monkeypatch):
    monkeypatch.setenv(_env.DEPLOYMENT_ENV, "dev")


def _publisher():
    return importlib.import_module("defender.presentation.publisher")


@pytest.fixture
def tenants(data_root):
    """Two accepted tenants of one data root (the second planted by hand: `create_tenant` admits one)."""
    return set_up_tenant(data_root, D9_TENANT_ID), H5.tenant(data_root, SECOND_TENANT)


def test_1279_a4_targets_sit_in_the_tenants_area_under_the_publish_root(
        dev, tenants, run_visualizations_dir):
    """A4: a run page is `<root>/<T>/runs/<R>/runtime.html`; a learning page `<root>/<T>/learning/<name>`."""
    pub = _publisher().Publisher.for_tenant(tenants[0])

    assert pub.run_page(RUN).path == run_visualizations_dir / D9_TENANT_ID / "runs" / RUN / "runtime.html"
    assert pub.learning_page("queues.html").path == (
        run_visualizations_dir / D9_TENANT_ID / "learning" / "queues.html")
    assert pub.learning_page("lessons.json").path.parent == pub.learning_page("queues.html").path.parent


def test_1279_a4_two_tenants_get_disjoint_areas_for_the_same_run_id_and_page_name(
        dev, tenants, run_visualizations_dir):
    """O2: tenant B's run R cannot land in, or overwrite, tenant A's area."""
    a, b = (_publisher().Publisher.for_tenant(t) for t in tenants)

    for name in ("runs", "learning"):
        pa = a.run_page(RUN).path if name == "runs" else a.learning_page("queues.html").path
        pb = b.run_page(RUN).path if name == "runs" else b.learning_page("queues.html").path
        assert pa != pb
        assert not pa.is_relative_to(run_visualizations_dir / SECOND_TENANT)
        assert not pb.is_relative_to(run_visualizations_dir / D9_TENANT_ID)

    a.run_page(RUN).write("A's page")
    b.run_page(RUN).write("B's page")
    assert a.run_page(RUN).path.read_text(encoding="utf-8") == "A's page"
    assert b.run_page(RUN).path.read_text(encoding="utf-8") == "B's page"


def test_1279_a4_a_write_makes_the_area_and_replaces_by_a_new_inode_leaving_neighbours(
        dev, tenants, run_visualizations_dir, tmp_path):
    """A4: stage-then-rename — a hard-linked old page is replaced, not written through; other pages stay."""
    pub = _publisher().Publisher.for_tenant(tenants[0])
    other = pub.run_page(OTHER_RUN)
    other.write("other run")
    target = pub.run_page(RUN)
    target.path.parent.mkdir(parents=True)
    bystander = tmp_path / "bystander.html"
    bystander.write_text("BYSTANDER", encoding="utf-8")
    target.path.hardlink_to(bystander)

    target.write("the page")

    assert target.path.read_text(encoding="utf-8") == "the page"
    assert bystander.read_text(encoding="utf-8") == "BYSTANDER", "the page was written through the old inode"
    assert other.path.read_text(encoding="utf-8") == "other run"
    assert sorted(p.name for p in target.path.parent.iterdir()) == ["runtime.html"], "a staged file was left behind"


@pytest.mark.parametrize("deployment", [None, "production", "staging"], ids=["unset", "production", "typo"])
def test_1279_o4_outside_dev_there_is_no_publisher_and_the_refusal_names_the_deployment(
        tenants, monkeypatch, run_visualizations_dir, deployment):
    """O4: the publisher refuses to exist without a root; nothing is written."""
    mod = _publisher()
    monkeypatch.setenv(_env.DEPLOYMENT_ENV, "dev")
    mod.Publisher.for_tenant(tenants[0])  # positive control: the same tenant has a publisher on dev
    if deployment is None:
        monkeypatch.delenv(_env.DEPLOYMENT_ENV)
    else:
        monkeypatch.setenv(_env.DEPLOYMENT_ENV, deployment)

    with pytest.raises(mod.NoPublishRoot) as refused:
        mod.Publisher.for_tenant(tenants[0])

    assert "production" in str(refused.value), f"the refusal does not name the deployment: {refused.value}"
    assert not list(run_visualizations_dir.iterdir())


def test_1279_a4_the_publisher_follows_the_root_at_call_time(dev, tenants, monkeypatch, tmp_path):
    """A4: the override is host configuration read when asked, not frozen at import."""
    mod = _publisher()
    first, second = tmp_path / "first", tmp_path / "second"
    monkeypatch.setenv("DEFENDER_RUN_VISUALIZATIONS_DIR", str(first))
    assert mod.Publisher.for_tenant(tenants[0]).run_page(RUN).path.is_relative_to(first)
    monkeypatch.setenv("DEFENDER_RUN_VISUALIZATIONS_DIR", str(second))
    assert mod.Publisher.for_tenant(tenants[0]).run_page(RUN).path.is_relative_to(second)


# A4 census: callers pass the tenant they already accepted; the presentation and the build never
# accept one again. An entry point's own `main` / `__main__` block is where its one acceptance of
# the command line's tenant legitimately sits (the CLI hands the accepted Tenant on), so that is
# the one place a call is allowed.

_ACCEPTANCE = frozenset({
    "accept_tenant", "requested_tenant", "requested_tenant_id", "accept_requested_tenant",
    "resolve_data_root", "command_line_paths", "accept_placed_knowledge",
})
_ENTRY_POINT_FUNCTIONS = frozenset({"main"})


def _acceptance_calls(source: str) -> list[tuple[int, str]]:
    """`(line, name)` of each call to tenant acceptance outside an entry point's `main` or
    `if __name__ == "__main__":` block. An import alias of an acceptance name counts as the name."""
    import ast

    tree = ast.parse(source)
    banned = set(_ACCEPTANCE)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom | ast.Import):
            banned |= {a.asname for a in node.names if a.asname and a.name.split(".")[-1] in _ACCEPTANCE}

    def is_main_guard(node: ast.AST) -> bool:
        return (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__")

    found: list[tuple[int, str]] = []

    def visit(node: ast.AST, exempt: bool) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in _ENTRY_POINT_FUNCTIONS:
            exempt = True
        if is_main_guard(node):
            exempt = True
        if isinstance(node, ast.Call) and not exempt:
            f = node.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if name in banned:
                found.append((node.lineno, name))
        for child in ast.iter_child_nodes(node):
            visit(child, exempt)

    visit(tree, False)
    return found


def test_1279_a4_the_census_sees_a_reacceptance_and_spares_an_entry_points_own_acceptance():
    """The detector can fail (a synthetic negative) and is not blind to aliases, attributes or nesting."""
    reaccepts = {
        "a helper": "def publish(raw):\n    return requested_tenant(root, raw)\n",
        "a method call": "def publish(t):\n    return t.accept_requested_tenant(1)\n",
        "a module attribute": "def f():\n    return _tenant.resolve_data_root()\n",
        "an alias": "from x import accept_tenant as take\ndef f():\n    return take(1, 2)\n",
        "a function beside main": "def main():\n    def f():\n        return accept_tenant(1, 2)\n    return f\n"
                                     "def g():\n    return accept_tenant(1, 2)\n",
        "module level": "tenant = accept_tenant(1, 2)\n",
    }
    for what, source in reaccepts.items():
        assert _acceptance_calls(source), f"the census missed {what}"
    own = {
        "main": "def main(argv):\n    return requested_tenant(resolve_data_root(), argv[0])\n",
        "the main guard": "if __name__ == '__main__':\n    sys.exit(main(command_line_paths(p, 1)))\n",
    }
    for what, source in own.items():
        assert _acceptance_calls(source) == [], f"the census flagged an entry point's own {what}"


def test_1279_a4_no_presentation_or_frontend_module_accepts_a_tenant_outside_its_entry_point():
    """A4: the publisher, the mirror, the renderers and the build take the `Tenant` their caller accepted."""
    from pathlib import Path

    defender = Path(__file__).resolve().parents[2]
    modules = sorted([*(defender / "presentation").rglob("*.py"),
                      *(defender / "learning" / "frontend").rglob("*.py")])
    assert len(modules) > 5, f"the census saw almost no modules: {modules}"
    offences = [f"{path.relative_to(defender)}:{line} {name}()"
                for path in modules
                for line, name in _acceptance_calls(path.read_text(encoding="utf-8"))]
    assert offences == [], "tenant acceptance outside an entry point's main:\n" + "\n".join(offences)
