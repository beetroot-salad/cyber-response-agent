from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender.tests.tooling.layout_contracts import _spec1080 as S

pytestmark = pytest.mark.e2e


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


def _lesson_fixture(tmp_path: Path):
    from defender.tests.support.learning.retrieval._lessons_corpus import _main_deps, _write_lesson

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
