"""Query-template placeholder/param invariant, lead_neighbors tokenising, connect examples compile."""
from __future__ import annotations

import inspect
import py_compile
import re
from pathlib import Path

from defender.tests._by_path import load_module

from defender import _corpus
from defender.learning.leads import lead_neighbors as ln

_DEFENDER = Path(__file__).resolve().parents[1]
_ROOT = _DEFENDER.parent
_QUERIES = _DEFENDER / "skills" / "gather" / "queries"
_EXAMPLES = _DEFENDER / "skills" / "connect" / "examples"


def test_placeholder_is_a_declared_param_or_marked_body_substitution(tmp_path):
    """A `${placeholder}` must be a declared param of the template's verb; judged by `check_template`."""
    from defender._corpus import read_query_template
    from defender._scaffold_rules import VerbResolver, check_template

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

    # Over the corpus IN PLACE — a template's system is derived from where it sits, so the
    # fixtures above are checked through a `cmdb/` tmp dir and the shipped files are not moved.
    # Drafts included: `_established()` was this sweep's scope until #901, which is the same
    # exclusion `validate_scaffold` carried and the reason the lead lane's output was outside
    # every content check.
    failing = [
        f"{t.path}: {f.message}"
        for t in _corpus.iter_query_templates(_QUERIES)
        for f in check_template(t, resolver.verbs(t.system))
    ]
    assert failing == [], (
        f"{len(failing)} template(s) fail the placeholder<->param invariant: {failing[:5]}"
    )


def test_lead_neighbors_scores_the_new_param_only_fence():
    """demand: lead_neighbors_scores_the_new_param_only_fence.

    A param-only template's new structured ## Query fence produces a non-degenerate token
    variant in ``lead_neighbors._query_variants``, and the scorer still discriminates
    same-measurement siblings. ``PLUMBING_TOKENS`` drops ``start``/``end``/``limit``, which are
    real params of elastic.query/alerts — the migration must not silently collapse that signal.
    """
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
    """demand: connect_examples_compile_against_the_live_tree.

    ``connect/examples/`` modules import/compile against the current tree and instantiate the
    LIVE shape (a ``VERBS`` mapping, ``VerbContext``, ``faults.py``, a health-check that RETURNS
    a dict) — not ``AdapterArgumentParser`` / ``build_parser`` / ``main()`` / ``die()`` /  # lint-stale-ref: ok — asserts the retired shim name is absent from connect/
    ``EXIT_*`` / a bash shim, none of which any shipped adapter imports.
    """
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


