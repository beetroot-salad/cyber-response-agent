from __future__ import annotations

import copy
import importlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tooling.layout_contracts import _spec1080 as S
from defender.tests.support.learning.core import _state1135

GOLDEN = "pages"


def _g(key: str):
    return copy.deepcopy(S.golden(GOLDEN)[key])


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """test_1025's roots: the launcher's episodes root, the runs base and the learning state root
    inside `tmp_path`, so no episode this file builds or launches lands in the checkout."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


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


def _main_deps_over_run_copy(tmp_path: Path) -> tuple[Any, Path]:
    """MAIN deps through the real `bind` seam with the run's tenant agent root — a run copy's
    `agent/` (`<T>/run-knowledge/<run_id>/agent/`, r3 data model) — handed through the
    existing `RunScope(tenant_agent=...)` keyword, over a code tree holding no corpus."""
    from dataclasses import replace

    from defender.agents import MAIN_DEF
    from defender.run_repository import Run
    from defender.runtime.agent_definition import RunScope, bind
    from defender.tests.support.shared._fixture_uuid import fixture_uuid
    from defender.tests.support.shared._locations_1210 import fixture_runs_base

    run = tmp_path / fixture_uuid("run")
    run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir()
    agent = tmp_path / "tenant" / "run-knowledge" / run.name / "agent"
    agent.mkdir(parents=True)
    deps = bind(MAIN_DEF, run, defender_dir=dfn, scope=RunScope(tenant_agent=agent))
    return replace(deps, run=Run.under(fixture_runs_base(run.parent), run.name)), agent


def test_one_of_two_consumers_of_a_moved_module_is_repointed_and_the_other_is_not(tmp_path):
    """Both consumers of the moved frontier engine push lessons from the RUN COPY (#1108 P4
    O2: pushed lessons and the document tool's recall read the run copy's corpus; O-TEXT: the
    model is shown it at `/agent/lessons/<name>`, the model view's agent root, never under
    `/defender`). ASSUMED SEAM (S-G2): the push lanes' corpus is the deps' tenant agent root's
    `lessons/` (`RunScope.tenant_agent`, already a `bind` keyword), not `defender_dir/lessons`."""
    pytest.importorskip("pydantic_ai")
    from defender.tests.support.shared.contracts import _fold_936 as F
    from defender.tests.support.learning.retrieval._lessons_corpus import _write_lesson

    engine = S.dotted(S.home_of("FOLD_LEAD"))
    deps, agent = _main_deps_over_run_copy(tmp_path)
    corpus = agent / "lessons"
    corpus.mkdir()
    lesson = _write_lesson(corpus, F.CLASS_LESSON, nodes=F.CLASS_SELECTOR)

    lessons_push = importlib.import_module("defender.runtime.lessons_push")
    text, on_minted = lessons_push.compose_fold(deps, "the record", F.FOLDING_DOC)
    assert on_minted is not None, "the fold push produced no block (it failed open)"
    block = text[len("the record"):]
    assert block.startswith("\n\n"), text
    model_lesson = f"- /agent/lessons/{lesson.name} — matched"
    assert model_lesson in block, block
    assert F.FOLD_HEADER in block.strip().splitlines()[0], block

    document = importlib.import_module("defender.runtime.tools._document")
    recall = document._frontier_recall(deps, "", F.FOLDING_DOC)
    assert model_lesson in recall, f"the document tool produced no block: {recall!r}"
    assert F.WRITE_RETURN_HEADER in recall, recall
    assert engine in sys.modules, f"neither consumer loaded the moved engine {engine}"


def test_1080_values_derived_from_a_moved_files_location_resolve_as_before():
    g = _g("location_values")
    # `lessons_frontier`'s cell is retired with its subject (#1108 P4 O4): the import-time
    # `DEFAULT_CORPUS` (the checkout's corpus) becomes a function of an agent root, and S-A's
    # symbol census (`tenant_1108_p4/test_census.py`) bans the constant. The golden's
    # `lessons_frontier_REPO_ROOT` value is kept as base history and read by nothing.
    # `lessons_fm`'s cell is retired the same way (OD12 class (i)): its `REPO_ROOT` existed only
    # to root the checkout corpus (`LESSONS_DIR`) and the repo-relative `--show` paths into it;
    # the corpus is now `$DEFENDER_AGENT_DIR/lessons` (O2), covered by
    # `learning/retrieval/test_lessons_fm.py` (its corpus fixture and `--show` confinement cases).
    # The golden's `lessons_fm_REPO_ROOT` value is kept as base history and read by nothing.
    assert Path(S.moved_module("reexec_into_venv", home=S.VENV)._DEFENDER_DIR).resolve() \
        == (S.REPO_ROOT / g["venv_DEFENDER_DIR"]).resolve()


def test_1080_observe_costs_usage_through_pricing_in_providers_as_today():
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
    from defender.tests.support.shared.contracts._import_blocker import run_blocked

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
