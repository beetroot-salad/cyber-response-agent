"""Tests for the lint_store_ownership gate: every session-store open has an owner that closes it
(#1324)."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_store_ownership")


def _found(tmp_path: Path, body: str) -> list[str]:
    root = tmp_path / "defender"
    root.mkdir()
    (root / "mod.py").write_text(body, encoding="utf-8")
    return _GATE.scan(root)


@pytest.mark.parametrize("body", [
    "def f():\n    with ss.open_store(case_id='a') as s:\n        s.read()\n",
    "def f():\n    with closing(open_store_for_read(p)) as s:\n        s.read()\n",
    "def f(stack):\n    return stack.enter_context(closing(ss.open_store(case_id='a')))\n",
    "def f(stack):\n    stack.enter_context(open_source_store(d, source_run=r))\n",
    "def f():\n    return ss.open_store(case_id='a')\n",
    "factory = lambda c, d: open_store(case_id=c)\n",
    "def f(p):\n    ss.open_store_for_read(p).close()\n",
    "def f(d, r):\n    s = source_store_if_any(d, source_run=r)\n    if s is None:\n"
    "        return None\n    with s:\n        return s.read()\n",
    "def f(d, r):\n    s = open_source_store(d, source_run=r)\n    with closing(s):\n"
    "        return s.read()\n",
    "def f():\n    h = open_store(case_id='a')  # lint-store-ownership: ok — a factory\n"
    "    return Wrapper(h)\n",
], ids=["with", "with-closing", "enter_context-closing", "enter_context", "return", "lambda",
        "closed-on-the-spot", "assigned-then-with", "assigned-then-with-closing", "suppressed"])
def test_an_owned_open_is_clean(tmp_path, body):
    assert _found(tmp_path, body) == []


@pytest.mark.parametrize("body", [
    # The shape #1324 shipped: closed by hand, on some exits only.
    "def f():\n    s = ss.open_store(case_id='a')\n    try:\n        s.read()\n"
    "    finally:\n        s.close()\n",
    "def f():\n    ss.open_store(case_id='a').read()\n",
    "def f():\n    use(open_store_for_read(p))\n",
    "def f():\n    return Wrapper(open_store(case_id='a'))\n",
    # A `with` on the name in ANOTHER function owns nothing here.
    "def f():\n    s = open_store(case_id='a')\n    return s.path\n"
    "def g(s):\n    with s:\n        pass\n",
    "def f(d, r):\n    self.s = source_store_if_any(d, source_run=r)\n",
    # `.close` named but never called: the handle is still open.
    "def f(p):\n    later = open_store_for_read(p).close\n    return later\n",
], ids=["try-finally", "used-inline", "passed-on", "wrapped-and-returned", "with-elsewhere",
        "attribute-target", "close-not-called"])
def test_an_unowned_open_is_found(tmp_path, body):
    found = _found(tmp_path, body)
    assert len(found) == 1 and "has no owner" in found[0], found


def test_the_line_number_survives_a_form_feed_earlier_in_the_file(tmp_path):
    """`str.splitlines` also breaks on `\\f`, which `ast` does not count: a suppression must be
    read off the line the call is really on."""
    body = "# section\f\ndef f():\n    s = open_store(case_id='a')  # lint-store-ownership: ok — x\n"
    assert _found(tmp_path, body) == []


def test_a_file_that_does_not_parse_is_exit_2(tmp_path):
    root = tmp_path / "defender"
    root.mkdir()
    (root / "bad.py").write_text("def (:\n", encoding="utf-8")
    assert _GATE.main(["--root", str(root)]) == 2
