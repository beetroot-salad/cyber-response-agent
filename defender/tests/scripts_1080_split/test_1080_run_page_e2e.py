"""#1080 — the fail-open lazy import sites that reach a moved module, over REAL outputs (group
`runpage`).

SCOPE CUT (2026-10-04, human): the run page, its mirror writer and its assets stay in
`scripts/visualize/` (#1105), so this file's run-page tests are parked with #1105
(`spec-flow/specs/parked/1080/parked_run_page_e2e.py`). What is left is s037's two lazy sites
that reach the moved lessons engine (`lessons_frontier`): the compaction fold's push and the
document tool's write return. Neither imports the old run-handle or run-path module
(E4: #1105 PR1 deletes those modules, so no kept test may import them at module level).
"""
from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender.tests.scripts_1080_split import _spec1080 as S

pytestmark = pytest.mark.e2e


# ======================================================================================
# Shared drivers
# ======================================================================================


def _make_unimportable(monkeypatch, dotted: str) -> None:
    """`dotted` cannot be imported for the rest of the test: `None` in `sys.modules`, and the
    attribute its package may already carry removed (`test_1110`'s pattern; monkeypatch
    restores both). The precondition is asserted so a fault that did not take stops here."""
    package, _, leaf = dotted.rpartition(".")
    monkeypatch.setitem(sys.modules, dotted, None)
    with_pkg = sys.modules.get(package) or importlib.import_module(package)
    monkeypatch.delattr(with_pkg, leaf, raising=False)
    with pytest.raises(ImportError):
        importlib.import_module(dotted)


# ======================================================================================
# s037 — every fail-open lazy site pinned by its real output
# ======================================================================================


def _lesson_fixture(tmp_path: Path):
    from defender.tests._lessons_corpus import _main_deps, _write_lesson

    tmp_path.mkdir(parents=True, exist_ok=True)
    deps, _run, dfn = _main_deps(tmp_path)
    corpus = dfn / "lessons"
    corpus.mkdir(parents=True, exist_ok=True)
    _write_lesson(corpus, "lazy-site-1080-lesson", nodes=("type: compute, slot: class",))
    doc = ("```invlang\n"
           ":V prologue.vertices [id|type|class|ident|attrs?]\n"
           "v-001|compute|??|x|\n"
           "```\n")
    return deps, doc


def _site_lessons_push(tmp_path: Path) -> Callable[[], dict[str, Any]]:
    from defender.runtime import lessons_push

    deps, doc = _lesson_fixture(tmp_path / "site-push")

    def observe() -> dict[str, Any]:
        text, after = lessons_push.compose_fold(deps, "ROW-1080", doc)
        return {"real": text.startswith("ROW-1080\n\n") and "lazy-site-1080-lesson" in text
                and after is not None,
                "fallback": text == "ROW-1080" and after is None}

    return observe


def _site_document_tool(tmp_path: Path) -> Callable[[], dict[str, Any]]:
    from defender.runtime.tools import _frontier_recall

    deps, doc = _lesson_fixture(tmp_path / "site-document")

    def observe() -> dict[str, Any]:
        block = _frontier_recall(deps, "", doc)
        return {"real": "lazy-site-1080-lesson" in block, "fallback": block == ""}

    return observe


def test_lazy_import_repointed_to_a_path_that_does_not_exist(tmp_path, monkeypatch):
    """Each fail-open site that lazily imports a moved module (under the 2026-10-04 scope cut,
    the frontier block in the lessons pushes: the compaction fold and the document tool's write
    return, both reaching the moved `lessons_frontier`) is pinned by a test that observes the
    real output, not the absence of an error: the frontier block in the push. A lazy import
    repointed to a missing module or a missing name therefore turns a test red even though the
    census is clean, every module-level import resolves and the run exits 0. (The run page,
    workspace map and episode page sites lazily import modules the cut leaves in place; their
    cells are parked with #1105.)

    Observed at each site through its own entry point (`compose_fold`, the document tool's
    `_frontier_recall`): with the moved module importable, the REAL output is there — the push
    and the recall carrying the planted lesson. Then the moved module each site lazily imports
    is made unimportable (what a stale repoint gives): every site still fails open — no
    exception reaches the caller — and the real-output check is FALSE at every one, so these
    assertions are the ones a stale lazy import turns red."""
    sites = {
        "lessons_push": (_site_lessons_push(tmp_path), ("FOLD_LEAD", None)),
        "document_tool": (_site_document_tool(tmp_path), ("WRITE_RETURN_LEAD", None)),
    }
    for name, (observe, _target) in sites.items():
        got = observe()
        assert got["real"], f"{name}: the real output is missing with every module in place: {got}"
        assert not got.get("fallback"), f"{name}: the fallback showed with the module in place"

    for name, (observe, (symbol, home)) in sites.items():
        with monkeypatch.context() as m:
            _make_unimportable(m, S.dotted(S.home_of(symbol, home=home)))
            got = observe()
        assert not got["real"], (
            f"{name}: the real-output check still passes with the lazily imported module gone, "
            f"so it cannot catch a stale repoint: {got}")
        assert got["fallback"], f"{name}: the site did not fail open as today: {got}"
