# PARKED 2026-10-04 (scope cut of #1080, human-decided): preserved, NOT collected.
# Moved verbatim out of defender/tests/scripts_1080_split/test_1080_placement_census_direction.py by the cut author:
# 8 test function(s) whose demands were parked with an owner issue, plus the
# imports, constants and helpers they use (a helper the live file still uses is COPIED, not
# moved). The file name does not match test_*.py, so pytest never collects it. Each
# demand is a `form: clause` in spec-flow/specs/spec_graph_1080-scripts-split.yaml whose
# `parked.preserved_test` names its function here; the owner adopts the test into its own
# spec (restoring form: test) when it lands. The module docstring below is the source file's,
# unchanged: it describes the whole suite file as it stood before the cut.
# GOLDENS: the files only parked tests read (exitcodes.json, integrations.json, pages/*.html,
# runpage/*.html) moved to ./goldens/ beside this file; every other golden stays in
# defender/tests/scripts_1080_split/goldens/ (a kept test still reads it). `S.golden` and
# `S.GOLDENS` read the suite's folder, so the adopter moves the parked goldens back with the test.
"""#1080 — the placement contract, the O1 import census, the O2 direction test, the wrapper
rules and the shippable-surface lint's reach into integrations (spec
`spec-flow/specs/spec_graph_1080-scripts-split.yaml`, §7 record `70-resolutions.md`).

Every check here is STATIC (s129): it reads tracked files and parses ASTs through
`_census1080`, never imports a moved module to learn where it lives. Moved code is reached at
call time through `_spec1080`'s symbol locator, so a home that does not exist yet is one
failing test, not a collection error. Faults are planted in a tmp git copy of the tree
(`tree_copy` / `plant`) or in an `overlay`, never in the real tree.

At the base (80888efb) the demands the move must satisfy are red here — the files are still
under `defender/scripts/`, the old edges still exist, the new homes do not. The tests that pin a
property of the census itself (a planted edge is found, junk is ignored, a string is not an
import) are green at the base by construction: they drive the same scan over a planted copy.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import textwrap

import pytest

from defender.tests.scripts_1080_split import _census1080 as C
from defender.tests.scripts_1080_split import _spec1080 as S


def _rel_edges(edges: list[C.Edge]) -> list[tuple[str, int, str]]:
    return [(e.importer, e.line, e.target) for e in edges]


def _overlay_with(relpath: str, extra: str) -> dict[str, str]:
    """`relpath`'s real source with `extra` appended (an overlay entry)."""
    p = S.REPO_ROOT / relpath
    before = p.read_text(encoding="utf-8") if p.is_file() else ""
    if before and not before.endswith("\n"):
        before += "\n"
    return {relpath: before + extra}


def _line_of(source: str, needle: str) -> int:
    for i, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"{needle!r} is not in the planted source")


# PARKED 2026-10-04 (scope cut): owner #1172; demand o2a_integrations_imports_down
def test_1080_integrations_imports_only_the_flat_tier_stdlib_and_third_party_packages():
    """Every module in integrations' generic core imports only `defender._*` flat-tier
    modules, the stdlib and third-party packages. It imports nothing from `runtime/`,
    `learning/`, reports, the lessons engine or `scripts/`. The per-vendor sub-packages
    (write-back, Elastic) are named carve-outs listed as exceptions (M-C (a)).

    Observed: the direction test's half (a) over the real tree's integrations core (which must
    exist: the generic check and the fault types are found under it). Positive control
    (o2_planted_edge_fails): a runtime import planted in the core is reported.
    """
    core = C.integrations_core()
    for anchor in ("guard_outbound", "AdapterFault"):
        assert S.home_of(anchor, home=S.INTEGRATIONS) in core
    assert all(not S.under(c, cut) for c in core for cut in C.carve_outs())
    findings = [e for e in C.direction_findings() if e.importer in core]
    assert _rel_edges(findings) == []
    target = core[0]
    overlay = _overlay_with(target, "from defender.runtime import verbs\n")
    assert any(e.importer == target and e.target.startswith("defender.runtime")
               for e in C.direction_findings(overlay=overlay))


# PARKED 2026-10-04 (scope cut): owner #1105; demand o2b_runtime_imports_no_reports
def test_1080_runtime_imports_nothing_from_reports():
    """No module under `defender/runtime/` imports anything from `defender/reports/`.

    Observed: the direction test's half (b) over the real tree, restricted to `runtime/`, with
    reports present (the run page's renderer is found under it). Positive control: a reports
    import planted in a runtime module is reported.
    """
    assert S.under(S.home_of("render_page", home=S.REPORTS), S.REPORTS)
    findings = [e for e in C.direction_findings() if S.under(e.importer, S.RUNTIME)]
    assert _rel_edges(findings) == []
    overlay = _overlay_with("defender/runtime/verbs.py", "from defender.reports import x\n")
    assert any(e.importer == "defender/runtime/verbs.py"
               for e in C.direction_findings(overlay=overlay))


# PARKED 2026-10-04 (scope cut): owner #1105; demand o2_planted_edge_fails
def test_1080_the_direction_test_fails_a_planted_edge_outside_its_exception_list(tmp_path):
    """The direction test, run over a copy of the tree with an import of a reports module
    planted in a runtime module (and a runtime import planted in integrations' core), reports
    both edges.

    Observed: a tmp git copy with both edges planted (the integrations module is a new core
    file, so the plant does not depend on the core's file names); the direction test over the
    copy reports exactly those two edges beyond what the unplanted copy reported.
    """
    root = C.tree_copy(tmp_path / "copy")
    before = set(_rel_edges(C.direction_findings(root)))
    r_line = C.plant(root, "defender/runtime/verbs.py",
                     "from defender.reports import render_page\n")
    i_line = C.plant(root, "defender/integrations/_spec1080_core_probe.py",
                     "from defender.runtime.verbs import read_roster\n")
    after = set(_rel_edges(C.direction_findings(root)))
    new = sorted(after - before)
    assert [e[:2] for e in new] == sorted([
        ("defender/integrations/_spec1080_core_probe.py", i_line),
        ("defender/runtime/verbs.py", r_line)])
    assert all(e[2].startswith(("defender.reports", "defender.runtime")) for e in new), new


# PARKED 2026-10-04 (scope cut): owner #1105; demand o2_exception_list_is_the_listed_edges
def test_1080_the_direction_tests_exceptions_are_exactly_the_listed_existing_edges():
    """The direction test's exception list is exactly the stated existing edges: under F7(a),
    N5's `learning/branch/cli.py` and `learning/frontend/*` importing reports. Every listed edge
    still exists, so no stale entry silently widens the allowance.

    Observed: the list is the two N5 entries; dropping either from the list makes the direction
    test report an edge from that importer (so each entry excuses a live edge); with the full
    list the learning side reports nothing.
    """
    assert C.N5_EXCEPTIONS == (("defender/learning/branch/cli.py", "defender.reports"),
                               ("defender/learning/frontend", "defender.reports"))
    for i, (importer, _target) in enumerate(C.N5_EXCEPTIONS):
        others = C.N5_EXCEPTIONS[:i] + C.N5_EXCEPTIONS[i + 1:]
        uncovered = C.direction_findings(exceptions=others)
        assert any(S.under(e.importer, importer) for e in uncovered), \
            f"the exception for {importer} excuses no live edge (stale)"
    assert [e for e in C.direction_findings() if S.under(e.importer, "defender/learning")] == []


def _shippable_lint():
    """The lint module, imported off `scripts/lint/` without leaving that dir on `sys.path`
    (the test_verb_dispositions_995 precedent: removed by value)."""
    lint_dir = str(S.REPO_ROOT / "scripts" / "lint")
    sys.path.insert(0, lint_dir)
    try:
        import lint_shippable_surface as mod
    finally:
        if lint_dir in sys.path:
            sys.path.remove(lint_dir)
    return mod


# PARKED 2026-10-04 (scope cut): owner #1172; demand o7_integrations_names_no_system
@pytest.mark.gate
def test_1080_integrations_names_no_system_under_the_extended_shippable_surface_lint():
    """`lint_shippable_surface`, with its token list extended by the roster system names, finds
    nothing in integrations' generic core and grants it no exemption.

    Observed: every roster system name (the base roster) is matched by one of the lint's
    patterns; no core module is excluded by the lint's own exclusion rule; the lint's scan over
    the real tree reports no finding in a core module; its baseline carries no core module.
    Positive control: o7_lint_flags_roster_names.
    """
    lint = _shippable_lint()
    systems = sorted(S.golden("core")["roster_verbs"])
    assert [s for s in systems if not any(p.search(s) for p in lint.FORBIDDEN)] == []
    core = C.integrations_core()
    assert core, "integrations' generic core does not exist"
    prefixes = lint.excluded_prefixes(S.REPO_ROOT)
    assert [c for c in core if lint._excluded(c, prefixes)] == []
    findings = [f.display for f in lint._scan() if f.fingerprint.split(":", 1)[0] in core]
    assert findings == []
    baseline = (S.REPO_ROOT / "scripts/lint/lint_shippable_surface_baseline.json").read_text()
    assert [c for c in core if c in baseline] == []

_O7_PLANT = textwrap.dedent('''\
    """A generic-core module."""
    # reaches the cmdb for the host
    # opens a ticket for the case
    # reads host-state for the box
    # queries elastic for the alert
''')


# PARKED 2026-10-04 (scope cut): owner #1172; demand o7_lint_flags_roster_names
def test_1080_the_shippable_surface_lint_flags_a_roster_system_name_planted_in_integrations(
        tmp_path):
    """The extended lint flags `cmdb`, `ticket` or `host-state` planted in a comment in an
    integrations core module, and it still flags `elastic`.

    Observed: a tmp git copy (the lint, its baselines and the skills' committed markers
    included) with a new integrations core module holding one comment per token; the copy's own
    lint, run in a child, reports each of the four lines.
    """
    root = C.tree_copy(tmp_path / "copy", commit=True, also=("scripts/lint", "defender/skills"))
    rel = "defender/integrations/_spec1080_o7_probe.py"
    C.plant(root, rel, _O7_PLANT)
    body = ("import json, sys\n"
            f"sys.path.insert(0, {str(root / 'scripts' / 'lint')!r})\n"
            "import lint_shippable_surface as L\n"
            "print(json.dumps([f.display for f in L._scan()]))\n")
    cp = S.python("-c", body, cwd=root, env=S.child_env(pythonpath=False, PYTHONPATH=str(root)))
    assert cp.returncode == 0, cp.stderr.decode()
    flagged = {int(d.split(":", 2)[1]) for d in json.loads(cp.stdout)
               if d.startswith(rel + ":")}
    assert flagged == {2, 3, 4, 5}, f"lines flagged in the planted module: {sorted(flagged)}"


# PARKED 2026-10-04 (scope cut): owner #1172; demand s005
def test_old_import_path_keeps_resolving_because_the_remainder_imports_the_moved_names():
    """An outside importer of the old dotted path (the five confinement importers:
    estate/registry, stagers/elastic, redaction, staging, runtime/branch/_family) is a census
    hit even if the name still resolves because the remainder re-imports it. After the move
    each importer takes the fault type, the generic check or the world-view names from their
    new homes (integrations, product Elastic module); the old path resolving by accident is not
    a pass. O1 is stated over the import statement, not over resolution.

    Observed: for each importer and each name it took from the old confinement module at the
    base (golden), the import statement now names the module that defines the name (or a
    package above it), and the importer's bound object IS the moved object. Positive control:
    an import of the old path planted in one importer is a census hit whether or not it
    resolves.
    """
    for importer, names in S.golden("core")["confinement_importers"].items():
        src = (S.REPO_ROOT / importer).read_bytes()
        stmts = list(S.import_statements(importer, src))
        mod = importlib.import_module(S.dotted(importer))
        for name in names:
            where = S.home_of(name)
            assert not S.under(where, "defender/scripts"), f"{name} has not moved: {where}"
            home = S.dotted(where)
            froms = [st.module for st in stmts if name in st.names]
            assert froms, f"{importer} no longer imports {name}"
            assert all(home == m or home.startswith(m + ".") for m in froms), \
                f"{importer} takes {name} from {froms}, not from its home {home}"
            assert getattr(mod, name) is S.moved(name), f"{importer}.{name} is a copy"
    old = "from defender.scripts.adapters.confinement import world_view\n"
    importer = "defender/learning/branch/redaction.py"
    overlay = _overlay_with(importer, old)
    assert (importer, _line_of(overlay[importer], old.strip()),
            "defender.scripts.adapters.confinement") in _rel_edges(C.census(overlay=overlay))

_PAGE_IMPORTS = textwrap.dedent('''\
    from typing import TYPE_CHECKING
    from defender.reports import render_page
    if TYPE_CHECKING:
        from defender.reports.visualize_run import publish_page
    def f():
        from defender.reports import write_page
        from defender.scripts.visualize import visualize_run
        return write_page, visualize_run
''')


# PARKED 2026-10-04 (scope cut): owner #1105; demand s092
def test_a_runtime_module_imports_a_page_module_inside_a_function_or_under_a_type_check_guard():
    """The O2(b) direction test and the O1 census flag every import statement of a page module
    from a runtime module wherever it sits: function body, `if TYPE_CHECKING:` or ordinary, with
    a planted edge as positive control. The string-built or path-built reach is not an import
    statement and is the same open question as A01.

    Observed: a planted runtime module with a reports import in each position (the direction
    test reports all three lines) and an old page-module import inside a function (the census
    reports it).
    """
    rel = "defender/runtime/_spec1080_pages.py"
    overlay = {rel: _PAGE_IMPORTS}
    lines = {e.line for e in C.direction_findings(overlay=overlay) if e.importer == rel}
    assert lines == {2, 4, 6}
    assert any(e[:2] == (rel, 7) and e[2].startswith("defender.scripts.visualize")
               for e in _rel_edges(C.census(overlay=overlay)))
