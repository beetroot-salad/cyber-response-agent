"""#1279 A4 — the publisher for an accepted tenant: a layout over the one publish root, refusing outside `dev`."""
from __future__ import annotations

import ast
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
# accept one again. The only places a call is allowed are an `if __name__ == "__main__":` block and
# a function named `main` whose first parameter is `argv` (the command line's own entry point, where
# the one acceptance of the command line's tenant sits). Inner code named `main` that takes anything
# else (`build.main(tenant)`) is scanned like any other function. Chosen: the `argv`-parameter rule
# rather than a per-module list, so a new entry point needs no edit here.

_ACCEPTANCE = frozenset({
    "accept_tenant", "requested_tenant", "requested_tenant_id", "accept_requested_tenant",
    "resolve_data_root", "command_line_paths", "accept_placed_knowledge",
    "open_requested_run", "open_command_line_run",
})


def _is_main_guard(node: ast.AST) -> bool:
    t = getattr(node, "test", None)
    return (isinstance(node, ast.If) and isinstance(t, ast.Compare)
            and isinstance(t.left, ast.Name) and t.left.id == "__name__"
            and len(t.comparators) == 1 and len(t.ops) == 1 and isinstance(t.comparators[0], ast.Constant)
            and isinstance(t.ops[0], ast.Eq)
            and t.comparators[0].value == "__main__")


def _is_entry_point(node: ast.AST) -> bool:
    if not (isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "main"):
        return False
    params = [*node.args.posonlyargs, *node.args.args]
    return bool(params) and params[0].arg == "argv"


def _acceptance_calls(source: str) -> list[tuple[int, str]]:
    """`(line, name)` of each call to tenant acceptance outside an entry point: an
    `if __name__ == "__main__":` block (its body only, comparison `==`) or a module-level
    `main(argv, ...)` function. An import alias of an
    acceptance name counts as the name."""
    tree = ast.parse(source)
    banned = set(_ACCEPTANCE)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom | ast.Import):
            banned |= {a.asname for a in node.names if a.asname and a.name.split(".")[-1] in _ACCEPTANCE}

    found: list[tuple[int, str]] = []

    def visit(node: ast.AST, exempt: bool) -> None:
        if isinstance(node, ast.Call) and not exempt:
            f = node.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if name in banned:
                found.append((node.lineno, name))
        if _is_main_guard(node):
            # only the guard's own body is the entry point; its test and `else` are scanned
            for child in ast.iter_child_nodes(node):
                visit(child, exempt or child in node.body)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, exempt or (node is tree and _is_entry_point(child)))

    visit(tree, False)
    return found


def test_1279_a4_the_census_sees_a_reacceptance_and_spares_an_entry_points_own_acceptance():
    """The detector can fail (a synthetic negative) and is not blind to aliases, attributes or nesting."""
    reaccepts = {
        "a helper": "def publish(raw):\n    return requested_tenant(root, raw)\n",
        "a method call": "def publish(t):\n    return t.accept_requested_tenant(1)\n",
        "a module attribute": "def f():\n    return _tenant.resolve_data_root()\n",
        "an alias": "from x import accept_tenant as take\ndef f():\n    return take(1, 2)\n",
        "a function beside main": "def main(argv):\n    def f():\n        return accept_tenant(1, 2)\n    return f\n"
                                     "def g():\n    return accept_tenant(1, 2)\n",
        "module level": "tenant = accept_tenant(1, 2)\n",
        "an inner main(tenant)": "def main(tenant):\n    return accept_tenant(1, 2)\n",
        "a run opener": "def f(raw):\n    return open_requested_run(raw)\n",
        "a command-line run opener": "def f(raw):\n    return open_command_line_run(raw)\n",
        "a non-main guard": "if __name__ == 'other':\n    accept_tenant(1, 2)\n",
        "a negated main guard": "if __name__ != '__main__':\n    accept_tenant(1, 2)\n",
        "the else of a main guard": "if __name__ == '__main__':\n    main()\nelse:\n    accept_tenant(1, 2)\n",
        "a main(argv) nested in a function": "def outer():\n    def main(argv):\n        return accept_tenant(1, argv)\n"
                                              "    return main\n",
    }
    for what, source in reaccepts.items():
        assert _acceptance_calls(source), f"the census missed {what}"
    own = {
        "main(argv)": "def main(argv):\n    return requested_tenant(resolve_data_root(), argv[0])\n",
        "main(argv) accepting": "def main(argv):\n    t = accept_tenant(1, argv)\n    return t\n",
        "the main guard": "if __name__ == '__main__':\n    sys.exit(main(command_line_paths(p, 1)))\n",
    }
    for what, source in own.items():
        assert _acceptance_calls(source) == [], f"the census flagged an entry point's own {what}"


def test_1279_a4_no_presentation_or_frontend_module_accepts_a_tenant_outside_its_entry_point():
    """A4: the publisher, the root owner, the mirror, the renderers and the build take the `Tenant`
    their caller accepted. The scanned set is derived from the owners' module objects plus the
    `presentation/` and `learning/frontend/` trees."""
    from pathlib import Path

    publisher = importlib.import_module("defender.presentation.publisher")
    publish_root = importlib.import_module("defender.configuration.publish_root")
    defender = Path(__file__).resolve().parents[2]
    modules = sorted({Path(publisher.__file__), Path(publish_root.__file__),
                      *(defender / "presentation").rglob("*.py"),
                      *(defender / "learning" / "frontend").rglob("*.py")})
    assert len(modules) > 5, f"the census saw almost no modules: {modules}"
    offences = [f"{path.relative_to(defender)}:{line} {name}()"
                for path in modules
                for line, name in _acceptance_calls(path.read_text(encoding="utf-8"))]
    assert offences == [], "tenant acceptance outside an entry point's main:\n" + "\n".join(offences)


# A4 census: the deployment rule ("only `dev` has a publish destination") is stated once, in the
# publish root's owner. Reading the deployment elsewhere re-states it. Allowed: the environment
# module that defines `deployment()`, the owner, and the publisher's refusal message (which only
# names the value the owner refused on). Scanned: every production module of the package.

_DEPLOYMENT_READERS = frozenset({"configuration/_env.py", "configuration/publish_root.py",
                                 "presentation/publisher.py"})
_DEPLOYMENT_NAMES = frozenset({"deployment", "DEPLOYMENT_ENV", "DEPLOYMENTS"})


def _deployment_reads(source: str) -> list[tuple[int, str]]:
    """`(line, what)` of each read of the deployment: a call or attribute named `deployment`,
    a `deployment`/`DEPLOYMENT_ENV` import (alias included), a `DEPLOYMENT_ENV` reference, or the
    variable's literal name."""
    found: list[tuple[int, str]] = []
    tree = ast.parse(source)
    docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                  if isinstance(n, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
                  and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _DEPLOYMENT_NAMES:
            found.append((node.lineno, node.attr))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "deployment":
            found.append((node.lineno, "deployment()"))
        elif isinstance(node, ast.Name) and node.id in {"DEPLOYMENT_ENV", "DEPLOYMENTS"}:
            found.append((node.lineno, node.id))
        elif isinstance(node, ast.ImportFrom):
            found += [(node.lineno, a.name) for a in node.names if a.name in _DEPLOYMENT_NAMES]
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and id(node) not in docstrings and "DEFENDER_DEPLOYMENT" in node.value):
            found.append((node.lineno, "DEFENDER_DEPLOYMENT"))
    return found


def test_1279_a4_the_deployment_census_sees_a_restated_rule_and_spares_innocent_code():
    """The detector can fail (a synthetic negative) and is not fooled by a local named `deployment`."""
    restated = {
        "a call through the module": "def f():\n    return _env.deployment() != 'dev'\n",
        "an aliased import": "from defender.configuration._env import deployment as d\ndef f():\n    return d()\n",
        "a bare call": "def f():\n    return deployment() == 'dev'\n",
        "a stored reference": "get = _env.deployment\n",
        "the variable's name": "def f():\n    return os.environ.get(_env.DEPLOYMENT_ENV)\n",
        "the variable's literal": "def f():\n    return os.environ['DEFENDER_DEPLOYMENT']\n",
        "an imported name": "from defender.configuration._env import DEPLOYMENT_ENV\n",
    }
    for what, source in restated.items():
        assert _deployment_reads(source), f"the census missed {what}"
    innocent = "def f(deployment):\n    label = deployment\n    return label.upper()\n"
    assert _deployment_reads(innocent) == [], "the census flagged a local named `deployment`"


def test_1279_a4_only_the_publish_root_owner_reads_the_deployment():
    """A4: the rule is stated only in `configuration/publish_root.py`; no mirror, build or run
    step restates it (the allow-list: `_env.py`, the owner, and `publisher.py`'s refusal message)."""
    from pathlib import Path

    defender = Path(importlib.import_module("defender.presentation.publisher").__file__).resolve().parents[1]
    # The publish consumers: the mirror and renderers, the learning build, box start and the
    # run's own steps (the places a copy of the rule would be tempting).
    scanned = [defender / "presentation", defender / "learning" / "frontend", defender / "box"]
    modules = sorted({*(p for root in scanned for p in root.rglob("*.py")),
                      defender / "run_common.py", defender / "run.py", defender / "configuration" / "publish_root.py"})
    assert len(modules) > 20, f"the census saw almost no modules: {len(modules)}"
    readers = {p.relative_to(defender).as_posix() for p in modules if _deployment_reads(p.read_text(encoding="utf-8"))}
    assert "configuration/publish_root.py" in readers, f"positive control: the owner was not seen reading it: {readers}"
    assert sorted(readers - _DEPLOYMENT_READERS) == [], (
        "the deployment rule is restated outside the publish root's owner")


def test_1279_a4_the_run_step_hands_on_the_tenant_it_was_given_and_never_accepts_one():
    """A4: `run_common.visualize` forwards its `tenant` and holds no acceptance call of its own."""
    from pathlib import Path

    run_common = importlib.import_module("defender.run_common")
    source = Path(run_common.__file__).read_text(encoding="utf-8")
    (func,) = (n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "visualize")
    segment = ast.get_source_segment(source, func)
    assert segment is not None
    assert _acceptance_calls(segment) == [], "run_common.visualize accepts a tenant instead of forwarding its own"
