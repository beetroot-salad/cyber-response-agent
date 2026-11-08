"""Query-template placeholder/param invariant, lead_neighbors tokenising, connect examples compile."""
from __future__ import annotations

import inspect
import py_compile
import re
from pathlib import Path

from defender.tests.support.shared.contracts._by_path import load_module

from defender.knowledge import _corpus
from defender.learning.leads import lead_neighbors as ln

_DEFENDER = Path(__file__).resolve().parents[3]
_ROOT = _DEFENDER.parent
#: The catalogs the placeholder<->param invariant sweeps: the pre-P4 shipped catalog, kept as a
#: fixture since catalogs moved into each tenant's `agent/skills/gather/queries/` (the fullest,
#: over adapters that stay in the product tree), and every committed tenant catalog.
_QUERIES = _DEFENDER / "tests" / "fixtures" / "pre-p4-shipped" / "agent" / "skills" / "gather" / "queries"
_CATALOGS = (_QUERIES, *sorted(_ROOT.glob("knowledge/*/agent/skills/gather/queries")))
_EXAMPLES = _DEFENDER / "skills" / "connect" / "examples"


def test_placeholder_is_a_declared_param_or_marked_body_substitution(tmp_path):
    """A `${placeholder}` must be a declared param of the template's verb; judged by `check_template`."""
    from defender.knowledge._corpus import read_query_template
    from defender.systems._scaffold_rules import VerbResolver, check_template

    resolver = VerbResolver(_DEFENDER)
    probes = tmp_path / "cmdb"
    probes.mkdir()

    def passes(text: str) -> bool:
        path = probes / "probe.md"
        path.write_text(text, encoding="utf-8")
        template, reason = read_query_template(path)
        assert template is not None, reason
        return not check_template(template, resolver.verbs(template.system))

    good = (
        "---\nid: cmdb.get-host-demo\nstatus: established\n"
        "verb: get-host\nparams: [host]\n---\n\n"
        "## Query\n\n```query\nverb: get-host\nparams:\n  host: ${host}\n```\n"
    )
    bad_undeclared = (
        "---\nid: cmdb.get-host-demo\nstatus: established\n"
        "verb: get-host\nparams: [host]\n---\n\n"
        "## Query\n\n```query\nverb: get-host\nparams:\n  host: ${mystery}\n```\n"
    )
    bad_no_verb = (
        "---\nid: cmdb.get-host-demo\nstatus: established\n---\n\n"
        "## Query\n\n```\nget-host ${host}\n```\n"
    )
    assert passes(good), "a verb-declaring template with every placeholder declared must pass"
    assert not passes(bad_undeclared), "an undeclared ${placeholder} must FAIL the invariant"
    assert not passes(bad_no_verb), "a template that declares no verb is undecidable -> FAIL"

    shipped = list(_corpus.iter_query_templates(_QUERIES))
    assert len(shipped) >= 20, (
        f"the swept catalog {_QUERIES} yields {len(shipped)} template(s): the invariant checks nothing")
    templates = [t for catalog in _CATALOGS for t in _corpus.iter_query_templates(catalog)]
    assert len(templates) > len(shipped), f"no committed tenant catalog was swept: {_CATALOGS}"
    failing = [
        f"{t.path}: {f.message}"
        for t in templates
        for f in check_template(t, resolver.verbs(t.system))
    ]
    assert failing == [], (
        f"{len(failing)} template(s) fail the placeholder<->param invariant: {failing[:5]}"
    )


def test_lead_neighbors_scores_the_new_param_only_fence():
    """A structured, param-only query fence keeps its verb and value tokens, and real params
    (`start`, `end`, `limit`) are not dropped as plumbing."""
    fence_a = "```query\nverb: get-host\nparams:\n  host: web-1\n```"
    fence_b = "```query\nverb: list-hosts\nparams:\n  role: bastion\n```"

    var_a = ln._query_variants(fence_a)
    tokens_a = frozenset().union(*var_a) if var_a else frozenset()
    var_b = ln._query_variants(fence_b)
    tokens_b = frozenset().union(*var_b) if var_b else frozenset()

    assert tokens_a - ln.PLUMBING_TOKENS, "structured param-only fence tokenized to only plumbing"
    assert "get-host" in tokens_a, f"structured fence lost its verb token: {sorted(tokens_a)}"
    assert "web-1" in tokens_a, f"structured fence lost its value token: {sorted(tokens_a)}"
    assert tokens_a != tokens_b, "two distinct param-only measurements collapsed to one variant"

    assert "start" not in ln.PLUMBING_TOKENS, "start is a real param — must not be dropped as plumbing"
    assert "end" not in ln.PLUMBING_TOKENS, "end is a real param — must not be dropped as plumbing"
    assert "limit" not in ln.PLUMBING_TOKENS, "limit is a real param — must not be dropped as plumbing"


def _load_example(name: str):
    """Load a connect example module by path, with examples/ and the worktree root on sys.path
    so both the current (`from _adapter import …`) and the migrated (`from defender…`) import
    forms resolve."""
    return load_module(_EXAMPLES / f"{name}.py", name=f"_connect_example_{name}",
                       sys_path=(_EXAMPLES, _ROOT))


def test_connect_examples_compile_against_the_live_tree():
    """Every connect example compiles; `example_adapter` declares a health-check verb that returns
    a value, and no example defines a retired CLI-shim symbol."""
    for py in sorted(_EXAMPLES.glob("*.py")):
        py_compile.compile(str(py), doraise=True)

    example_adapter = _load_example("example_adapter")

    assert isinstance(getattr(example_adapter, "VERBS", None), dict), \
        "example_adapter.py exposes no VERBS mapping"
    assert example_adapter.VERBS, "example_adapter.py exposes an empty VERBS mapping"
    assert "health-check" in example_adapter.VERBS, "example_adapter.py VERBS declares no health-check"
    src = inspect.getsource(example_adapter)
    assert "VerbContext" in src, "example_adapter.py does not reference VerbContext"
    assert "faults" in src, "example_adapter.py does not use the faults.py taxonomy"

    hc = example_adapter.VERBS["health-check"]
    hc_src = inspect.getsource(hc)
    assert re.search(r"\breturn\b", hc_src), "example_adapter health-check does not return a value"
    assert "print(" not in hc_src, \
        "example_adapter health-check still prints instead of returning a dict"
    assert "SystemExit" not in hc_src, \
        "example_adapter health-check still raises SystemExit instead of returning a dict"

    for name in ("example_adapter", "_adapter"):
        if not (_EXAMPLES / f"{name}.py").exists():
            continue
        mod = _load_example(name)
        for dead in ("AdapterArgumentParser", "build_parser", "main", "die", "resolve_auth",  # lint-stale-ref: ok — asserts the retired shim name is absent from connect/
                     "EXIT_USAGE"):
            assert not hasattr(mod, dead), f"examples/{name}.py still defines the dead symbol {dead!r}"


def test_the_connect_example_reaches_its_system_through_the_proxy_at_its_declared_base(tmp_path):
    """The example a custom adapter is copied from calls its system through the credential proxy,
    at the base of the system's own access declaration, with the timeout from its record — the
    folder gone from disk after resolve, so the record is all it reads. A base written in its
    `config.env` is not a setting it reads: the settings check refuses it by name."""
    import pytest

    from defender.kit.faults import ConfigFault
    from defender.tests.support.tenancy import _tenants1106 as T1106
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

    example = _load_example("example_adapter")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="oex")
    S.write_config(folder, "example", 'EXAMPLE_TIMEOUT_SEC="5"\n')
    access = S.settings_of(folder) / "systems" / "example" / "access.yaml"
    access.write_text(T1106.access_text("oex", "example"), encoding="utf-8")
    record = S.resolve(root)
    S.config_path(folder, "example").unlink()
    access.unlink()

    assert example.check_settings(record) is None, "a declared, timed system is usable"
    stand_in = S.ProxyStandIn(tmp_path / "proxy", [S.answer('{"id": "r1"}')])
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ctx = S.verb_context(record, run_dir, {}, proxy_url=stand_in.url, request_token="token-oex")
    assert example.get_record(ctx, id="r1") == {"id": "r1"}
    [request] = stand_in.requests()
    assert (request["system"], request["method"], request["url"], request["timeout_sec"]) == (
        "example", "GET", f"{T1106.default_base('oex', 'example')}/records/r1", 5), request

    S.write_config(folder, "example", 'EXAMPLE_TIMEOUT_SEC="5"\nEXAMPLE_URL_BASE="http://elsewhere:1"\n')
    access.write_text(T1106.access_text("oex", "example"), encoding="utf-8")
    with pytest.raises(ConfigFault, match="EXAMPLE_URL_BASE"):
        example.check_settings(S.resolve(root))
    # An adapter listing URL_BASE among the keys it reads is the adapter's bug, not the tenant's.
    from defender.kit import transport
    with pytest.raises(ValueError, match="access.yaml"):
        transport.record_config(record, "example", "EXAMPLE", ("URL_BASE", "TIMEOUT_SEC"))
