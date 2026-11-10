"""Tests for the lint_run_endings gate: only the endings table orders run endings."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_run_endings")


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "defender"
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


@pytest.mark.parametrize("src", [
    "from defender._exception_groups import carried_unless_overridden\n"
    "x = carried_unless_overridden(e, K, (B,))\n",
    "from defender._exception_groups import carried_unless_overridden as c\nx = c(e, K, ())\n",
    "from defender import _exception_groups as g\nx = g.carried_unless_overridden(e, K, ())\n",
])
def test_a_second_site_that_orders_endings_is_found_however_it_is_spelled(tmp_path, src):
    found = _GATE.scan(_tree(tmp_path, {"investigation/driver.py": src}))
    assert len(found) == 1, found


@pytest.mark.parametrize("rel, src", [
    ("investigation/run_endings.py",
     "from defender._exception_groups import carried_unless_overridden\n"
     "x = carried_unless_overridden(e, K, ())\n"),
    ("x.py", "from mine import carried_unless_overridden\nx = carried_unless_overridden(e)\n"),
    ("x.py", "from defender._exception_groups import carried\nx = carried(e, K)\n"),
    ("tests/x.py", "from defender._exception_groups import carried_unless_overridden\n"
                   "x = carried_unless_overridden(e, K, ())\n"),
], ids=["the_table", "unrelated_function", "plain_carried", "tests_are_not_swept"])
def test_the_table_and_unrelated_code_have_no_findings(tmp_path, rel, src):
    assert _GATE.scan(_tree(tmp_path, {rel: src})) == []


def test_this_checkout_is_clean():
    assert _GATE.scan(_GATE.DEFENDER) == []
