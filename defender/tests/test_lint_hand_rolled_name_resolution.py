"""Unit tests for scripts/lint/lint_hand_rolled_name_resolution.py.

The gate exists because ONE mistake — treating a name in source as the thing it refers to —
got past three rounds of review on #1008 in four different spellings. Its own contract has two
halves and both are silent if wrong, so both are pinned here rather than left to the baseline:

  * it must FIRE on a module that parses real source and matches names lexically without ever
    reaching `_astlib` — that is the shipped bug class;
  * it must STAY QUIET on the three things that are not that bug: a module that goes through
    the resolver, a module that only parses synthetic source it wrote itself, and a definition
    matched by name (`FunctionDef.name`), which has no binding to get wrong.

A gate that fires on everything gets suppressed everywhere, and one that fires on nothing
shows a green empty baseline; the quiet cases are as load-bearing as the loud one.
"""
from __future__ import annotations

import ast

from defender.tests._by_path import import_lint_lib

import pytest


def _gate():
    return import_lint_lib("lint_hand_rolled_name_resolution")


def _findings(source: str, rel: str = "defender/tests/test_made_up.py"):
    gate = _gate()
    return gate._findings_for(ast.parse(source), source, rel)


REAL_SOURCE_HEADER = (
    "import ast\n"
    "from pathlib import Path\n"
    "def check():\n"
    "    tree = ast.parse(Path('x.py').read_text(encoding='utf-8'))\n"
)


def test_it_fires_on_a_callee_matched_by_spelling_over_real_source():
    """The shape that shipped twice: a call census over a real file, matched by `.func.id`.

    Both an alias (`from m import run_stage as _rs`) and the attribute form
    (`mod.run_stage(...)`) are the same function under a name this comparison does not match,
    which is how a widening call hid from a census written to count exactly those calls.
    """
    found = _findings(REAL_SOURCE_HEADER + (
        "    return [n for n in ast.walk(tree)\n"
        "            if isinstance(n, ast.Call) and n.func.id == 'run_stage']\n"))
    assert [f.fingerprint for f in found] == [
        "callee-by-name defender/tests/test_made_up.py::check"], found


def test_it_fires_on_the_getattr_spelling_of_the_same_comparison():
    """`getattr(node.func, "id", None) == X` is the same question written defensively."""
    found = _findings(REAL_SOURCE_HEADER + (
        "    return [n for n in ast.walk(tree)\n"
        "            if getattr(n.func, 'id', None) == 'build_registry']\n"))
    assert len(found) == 1, found
    assert found[0].fingerprint.startswith("callee-by-name"), found


def test_it_fires_on_an_import_alias_read():
    """Reading `.asname` has one purpose: deciding what a name is bound to.

    That is the resolver's question, and the hand-written version of it missed a function-local
    import shadowing an honest module-level one at the line that used the name.
    """
    found = _findings(REAL_SOURCE_HEADER + (
        "    for node in ast.walk(tree):\n"
        "        if isinstance(node, ast.ImportFrom):\n"
        "            for a in node.names:\n"
        "                if a.asname is None:\n"
        "                    return a\n"))
    assert any(f.fingerprint.startswith("alias-by-hand") for f in found), found


def test_it_is_quiet_on_a_module_that_reaches_the_resolver():
    """The ownership half. A module that goes through `_astlib` has ASKED THE OWNER; whether it
    also compares a name somewhere is not this gate's business, because the resolver returns
    None for a duck-typed method and a lexical fallback there is correct, not a hand-roll."""
    source = REAL_SOURCE_HEADER.replace(
        "import ast\n", "import ast\nfrom _astlib import module_env\n") + (
        "    env = module_env(tree)\n"
        "    return [n for n in ast.walk(tree)\n"
        "            if isinstance(n, ast.Call) and n.func.id == 'run_stage']\n")
    assert _findings(source) == []


def test_it_is_quiet_on_synthetic_source_the_module_wrote_itself():
    """A claim about a fixture written three lines up is a claim about a spelling, and the
    spelling IS the fact there. Only a claim about a SHIPPED file has to survive how that file
    actually spells things."""
    source = (
        "import ast\n"
        "def check():\n"
        "    tree = ast.parse('def f(): pass')\n"
        "    return [n for n in ast.walk(tree)\n"
        "            if isinstance(n, ast.Call) and n.func.id == 'f']\n")
    assert _findings(source) == []


def test_it_is_quiet_on_a_definition_matched_by_name():
    """`FunctionDef.name` is a definition, not a reference. Finding the function called `foo`
    in a file is a lexical question with a lexical answer — there is no binding to get wrong,
    which is exactly why this gate does not flag it."""
    found = _findings(REAL_SOURCE_HEADER + (
        "    return [n for n in ast.walk(tree)\n"
        "            if isinstance(n, ast.FunctionDef) and n.name == 'seam']\n"))
    assert found == [], found


def test_the_suppression_marker_silences_one_site_and_only_that_site():
    """Two flagged sites, one marked: the mark is per-line, so it cannot silence a second
    hand-rolled match added later in the same function."""
    found = _findings(REAL_SOURCE_HEADER + (
        "    a = [n for n in ast.walk(tree)\n"
        "         if n.func.id == 'one']  # lint-ast-resolve: ok — reason\n"
        "    b = [n for n in ast.walk(tree) if n.func.attr == 'two']\n"
        "    return a, b\n"))
    assert len(found) == 1, found


def test_the_resolver_itself_is_out_of_scope():
    """`_astlib` must read `.func.id`, `.asname` and `.module` — that IS the implementation of
    the question this gate points everyone at, so the owner cannot be held to its own rule."""
    gate = _gate()
    assert gate.OWNER.name == "_astlib.py"
    assert gate.OWNER.is_file(), "the gate points at a resolver that is not there"


@pytest.mark.gate
def test_the_shipped_tree_has_no_unbaselined_site():
    """The ratchet itself, over the real tree."""
    assert _gate().main([]) == 0
