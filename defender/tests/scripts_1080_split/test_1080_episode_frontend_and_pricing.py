"""#1080 — group `pages`: the episode page, the run page's footer, the learning frontend's page
primitives and pricing, after `defender/scripts/` is split into its homes.

SCOPE CUT (2026-10-04, human): the page renderers stay in `scripts/visualize/` (#1105), so the
episode-page, footer and frontend tests are parked with #1105
(`spec-flow/specs/parked/1080/parked_episode_frontend_and_pricing.py`). Kept here: pricing, the
lessons-frontier consumers (s052), the location-derived values of the moved modules (m2) and
the O5 suites' assertions (s043). No kept test imports `defender._run_paths` (E4).

The renderers land under `defender/reports/` (M-F (a)) and pricing in the flat tier
(`S.PRICING`; first pinned under `runtime/providers/`, moved after review); every other home is found by symbol (dF0). Every
moved name is reached at CALL time through `_spec1080` (`S.moved` / `S.moved_module` /
`S.home_of`), so a missing home is one failure per test, never a collection error. Modules that
do not move (`learning/branch/cli.py`, `learning/frontend/build.py`, `runtime/observe.py`,
`runtime/lessons_push.py`, `runtime/tools/_document.py`) are imported inside the test bodies
too: each imports a moved module at its own module level or lazily, and a stale import there is
exactly the failure these tests exist to show.

"As today" is `goldens/pages.json` (the whole-page captures `goldens/pages/*.html` moved to
`spec-flow/specs/parked/1080/goldens/` with the parked page tests), captured once at
the base 80888efb by running the BASE code over the same fixtures these tests build. The
fixtures, the run-dir/git setup and the one path normalizer (`_norm`) live here and the capture
script imported them from this file, so capture and test cannot drift on shape.

Faults are real inputs through the real primitive: an unimportable renderer through
`sys.modules` (the test_1110 precedent), an empty PATH, a copy of this checkout's `defender/`
package under `tmp_path` that is not a repository / tracks no lesson / is owned by another uid,
exported repository-locating variables pointing at a real second repository. No
`monkeypatch.setattr`.
"""
from __future__ import annotations

import ast
import copy
import importlib
import json
import sys
from pathlib import Path

import pytest

from defender.tests import _triplet_947 as T
from defender.tests.scripts_1080_split import _spec1080 as S
from defender.tests import _state1135

GOLDEN = "pages"

# ======================================================================================
# Shared by the capture script and the tests (ONE shape, ONE normalizer)
# ======================================================================================


def _g(key: str):
    return copy.deepcopy(S.golden(GOLDEN)[key])


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """test_1025's roots: the launcher's episodes root, the runs base and the learning state root
    inside `tmp_path`, so no episode this file builds or launches lands in the checkout."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


# --------------------------------------------------------------------------------------
# Pricing
# --------------------------------------------------------------------------------------

_USAGE = {"input_tokens": 1000, "output_tokens": 2000, "cache_creation_input_tokens": 300,
          "cache_read_input_tokens": 4000}
#: (model, usage): every spelling family `usage_cost` resolves, the absorbed empty model, an
#: unknown model, a non-dict usage, an empty usage, a huge count, a bool and a float count.
PRICING_ROWS = (
    ("kimi-k3", _USAGE),
    ("accounts/fireworks/models/kimi-k3", _USAGE),
    ("fireworks:glm-5p3", _USAGE),
    ("glm-5.3-flash", _USAGE),
    ("anthropic:claude-sonnet-4-6-20250514", _USAGE),
    ("claude-haiku-4-5", _USAGE),
    ("deepseek-v4p1-flash", {"input_tokens": 123_456_789, "cache_read_input_tokens": 7}),
    ("", _USAGE),
    ("gpt-4o", _USAGE),
    ("glm-5.2", "not a usage mapping"),
    ("kimi-k2p6", {}),
    ("glm-5p2", {"input_tokens": True, "output_tokens": 1.5}),
)

#: Checked against the child's `sys.modules`: the agent framework and the provider/MCP stack.
AGENT_FRAMEWORK = S.BOX_BLOCKED

_MODULES_CHILD = (
    "import importlib, json, sys\n"
    "blocked = set(sys.argv[1].split(','))\n"
    "seen = {}\n"
    "for name in sys.argv[2:]:\n"
    "    importlib.import_module(name)\n"
    "    seen[name] = sorted(m for m in sys.modules if m.split('.')[0] in blocked)\n"
    "print(json.dumps(seen))\n"
)


def _cold_import(*modules: str) -> dict[str, list[str]]:
    """For each module in turn, imported cold in one child: the agent-framework modules loaded
    so far."""
    proc = S.python("-c", _MODULES_CHILD, ",".join(AGENT_FRAMEWORK), *modules)
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout)


def _pricing_rows(usage_cost) -> list:
    return [[S.canon(model), S.canon(usage), S.canon(usage_cost(model, usage))]
            for model, usage in PRICING_ROWS]


# --------------------------------------------------------------------------------------
# s043: the O5 suites
# --------------------------------------------------------------------------------------

#: Each O5 suite, and the moved symbols it reaches (with the home they must be found under):
#: the file must import the module that now defines each. A suite whose base version imports no
#: moving module reaches the moved code through the runtime only and carries no entry. E2 of
#: the 2026-10-04 scope cut: the three symbol rows (`payload_digest`, `TransportFault`,
#: `mirror_root`) name modules the cut leaves in place, so every row is empty and the check is
#: "assertions unchanged".
O5_SUITES: dict[str, tuple[tuple[str, str | None], ...]] = {
    "defender/tests/e2e/test_replay_skeleton.py": (),
    "defender/tests/e2e/test_query_tool_611.py": (),
    "defender/tests/e2e/test_808_run_dir_tables.py": (),
    "defender/tests/e2e/test_1084_mirror_e2e.py": (),
    "defender/tests/test_1096_entrypoint_closure.py": (),
}


def _asserts(relpath: str) -> list[str]:
    """Every `assert` statement in the file, normalized through the AST (formatting, comments
    and line numbers fall away), as a sorted multiset."""
    tree = ast.parse((S.REPO_ROOT / relpath).read_bytes(), filename=relpath)
    return sorted(ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.Assert))


def _imports_module(relpath: str, dotted: str) -> bool:
    """Whether the file imports `dotted` — `import dotted`, `from dotted import …`, or
    `from <package> import <leaf>` naming it — anywhere (module level or a function body)."""
    source = (S.REPO_ROOT / relpath).read_bytes()
    for st in S.import_statements(relpath, source):
        if st.module == dotted or any(f"{st.module}.{n}" == dotted for n in st.names):
            return True
    return False


# ======================================================================================
# The learning frontend
# ======================================================================================


def test_one_of_two_consumers_of_a_moved_module_is_repointed_and_the_other_is_not(tmp_path):
    """Each consumer of a moved module is pinned by its own test that observes real output: the
    fold push and the document tool each produce the frontier block from the moved
    `lessons_frontier`. A suite that exercises only one consumer is not enough: leaving the
    other on the old path turns its own test red. (The learning frontend build's consumers, the
    page primitives and the run renderer, stay in `scripts/visualize/` under the 2026-10-04
    scope cut; that half is parked with #1105.)

    Both frontier consumers fail open on an import error (RG4 S3, S4), so each is driven over a
    real corpus holding a lesson the fixture document matches, and each must return a block
    naming that lesson under its own header: the fold row (`compose_fold`) and the write-return
    recall (`_frontier_recall`)."""
    pytest.importorskip("pydantic_ai")
    from defender.tests import _fold_936 as F
    from defender.tests._lessons_corpus import _main_deps, _write_lesson

    engine = S.dotted(S.home_of("FOLD_LEAD"))
    deps, _run, defender_dir = _main_deps(tmp_path)
    corpus = defender_dir / "lessons"
    corpus.mkdir()
    lesson = _write_lesson(corpus, F.CLASS_LESSON, nodes=F.CLASS_SELECTOR)

    lessons_push = importlib.import_module("defender.runtime.lessons_push")
    text, on_minted = lessons_push.compose_fold(deps, "the record", F.FOLDING_DOC)
    assert on_minted is not None, "the fold push produced no block (it failed open)"
    block = text[len("the record"):]
    assert block.startswith("\n\n"), text
    assert str(lesson.resolve()) in block, block
    assert F.FOLD_HEADER in block.strip().splitlines()[0], block

    document = importlib.import_module("defender.runtime.tools._document")
    recall = document._frontier_recall(deps, "", F.FOLDING_DOC)
    assert str(lesson.resolve()) in recall, f"the document tool produced no block: {recall!r}"
    assert F.WRITE_RETURN_HEADER in recall, recall
    assert engine in sys.modules, f"neither consumer loaded the moved engine {engine}"


# ======================================================================================
# Location-derived values
# ======================================================================================


def test_1080_values_derived_from_a_moved_files_location_resolve_as_before():
    """After the move, each of these resolves to the same directory or file as at the base:
    `lessons_fm.REPO_ROOT`, `lessons_frontier.REPO_ROOT` and `_venv`'s `_DEFENDER_DIR`. (The
    2026-10-04 scope cut keeps these three cells; `mirror_root()`'s default, `_MIRROR_WRITER`,
    `visualize_primitives.REPO_ROOT` / `ASSETS` and `workspace_map`'s `DEFENDER_DIR` belong to
    modules that stay in `scripts/`, parked with #1105.)

    Each module is located by a symbol only it defines. The golden holds each value as the base
    resolved it, repo-relative: the checkout root and `defender/`."""
    g = _g("location_values")
    assert Path(S.moved_module("cmd_tags").REPO_ROOT).resolve() \
        == (S.REPO_ROOT / g["lessons_fm_REPO_ROOT"]).resolve()
    assert Path(S.moved_module("WRITE_RETURN_LEAD").REPO_ROOT).resolve() \
        == (S.REPO_ROOT / g["lessons_frontier_REPO_ROOT"]).resolve()
    assert Path(S.moved_module("reexec_into_venv", home=S.FLAT_TIER)._DEFENDER_DIR).resolve() \
        == (S.REPO_ROOT / g["venv_DEFENDER_DIR"]).resolve()


# ======================================================================================
# s043: the O5 suites keep their assertions
# ======================================================================================


@pytest.mark.parametrize("suite", sorted(O5_SUITES))
def test_suite_assertions_kept_while_a_fixture_points_the_test_at_another_target(suite):
    """Each O5 suite keeps its assert statements and still exercises the real moved code: a
    fixture that loads by path, stubs a renderer or spawns the wrapper instead of the engine
    must still reach the real implementation, and the assertion fails if the engine, wrapper or
    renderer is broken. An unchanged assertion that now holds against a stub is a failure.

    The suite's `assert` statements, read through the AST, are the base's multiset exactly
    (fixtures and imports may change, assertions may not). A suite that imported a moving
    module at the base must import the module that now defines the symbols it reaches — the
    moved implementation, not a stand-in."""
    assert _asserts(suite) == _g("suite_asserts")[suite], (
        f"{suite}: its assert statements changed with the move")
    for symbol, home in O5_SUITES[suite]:
        target = S.dotted(S.home_of(symbol, home=home))
        assert _imports_module(suite, target), (
            f"{suite} does not import {target}, where `{symbol}` lives now")


# ======================================================================================
# Pricing
# ======================================================================================


def test_1080_observe_costs_usage_through_pricing_in_providers_as_today():
    """`runtime/observe.py`'s `usage_cost` comes from the moved pricing module (the flat tier
    since the post-review change; the name keeps its first home for the record). A fixed usage
    record costs the same amount as at the base. Importing it loads no `pydantic_ai`.

    Observed through the observer's own binding: `observe.usage_cost` is the moved function,
    and over the fixed table every cost equals the base's (type-preserving). A cold child
    importing the moved pricing module has loaded no agent framework; the same child then
    importing the observer shows the agent framework loaded — the channel sees it."""
    moved = S.moved("usage_cost", home=S.PRICING)
    observe = importlib.import_module("defender.runtime.observe")
    assert observe.usage_cost is moved
    assert _pricing_rows(observe.usage_cost) == _g("pricing")["rows"]

    seen = _cold_import(S.dotted(S.home_of("usage_cost", home=S.PRICING)),
                        "defender.runtime.observe")
    pricing_mod, observer = list(seen)
    assert seen[pricing_mod] == [], f"importing pricing loaded {seen[pricing_mod]}"
    assert "pydantic_ai" in seen[observer], "positive control: the observer loads pydantic_ai"


def test_pricing_module_lands_in_a_package_whose_initialiser_must_not_load_the_agent_framework():
    """The price table is importable with the standard library alone: its module imports only
    the standard library, and a cold import of it loads no third-party package at all — not the
    agent framework, not pydantic. (Post-review change, human: under `runtime/providers/` every
    import paid for the providers package, which builds the provider objects and loads
    pydantic.) A fixed usage record costs exactly what it costs today.

    Observed: the module's import statements read through the AST, and a child with every
    import outside the standard library and this tree refused importing it. Positive control:
    the same child refuses `defender.runtime.providers`."""
    from defender.tests._import_blocker import run_blocked

    home = S.home_of("usage_cost", home=S.PRICING)
    src = (S.REPO_ROOT / home).read_text(encoding="utf-8")
    third = [i.module for i in S.import_statements(home, src)
             if i.module.split(".")[0] not in sys.stdlib_module_names and i.module != "__future__"]
    assert third == [], f"{home} imports outside the standard library: {third}"
    env = {"PYTHONPATH": str(S.REPO_ROOT), "PATH": "/usr/bin:/bin"}
    for module, ok in ((S.dotted(home), True), ("defender.runtime.providers", False)):
        done = run_blocked(f"import {module}\n", allow_only=("defender", "__main__"),
                           no_site=True, env=env)
        assert (done.returncode == 0) is ok, (module, done.stderr.decode()[-400:])
    assert _pricing_rows(S.moved("usage_cost", home=S.PRICING)) == _g("pricing")["rows"]
