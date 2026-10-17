"""Differential + property spec for the `cat` operand extractor (`grant.cat_input_files`)."""
from __future__ import annotations

import shutil
import subprocess

import pytest

from defender.runtime.permission.grant import cat_input_files

_CAT = shutil.which("cat")
requires_cat = pytest.mark.skipif(_CAT is None, reason="cat binary not available")


def _real_cat_opens(argv, sentinels):
    """A lower bound on the files real `cat` opens for `argv` (paths already inlined): run `cat` on empty stdin..."""
    proc = subprocess.run(
        [_CAT, *argv], capture_output=True, text=True, timeout=10, input="",
    )
    blob = proc.stdout + proc.stderr
    return {path for path, marker in sentinels.items() if marker in blob}


@requires_cat
def test_gate_superset_single_operand(tmp_path):
    op = tmp_path / "op.json"
    op.write_text('{"k":"SENT_OP"}')
    argv = [str(op)]
    gate = set(cat_input_files(["cat", *argv]))
    observed = _real_cat_opens(argv, {str(op): "SENT_OP"})
    assert observed == {str(op)}
    assert gate >= observed


@requires_cat
def test_gate_superset_multiple_operands_behind_a_bundle(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text('"SENT_A"')
    b.write_text('"SENT_B"')
    argv = ["-nE", str(a), str(b)]
    gate = set(cat_input_files(["cat", *argv]))
    observed = _real_cat_opens(argv, {str(a): "SENT_A", str(b): "SENT_B"})
    assert observed == {str(a), str(b)}
    assert gate >= observed


@requires_cat
def test_gate_superset_operand_after_double_dash(tmp_path):
    """`--` ends options, so a following `-`-prefixed token is an OPERAND cat opens. The gate must list it rather..."""
    weird = tmp_path / "-nE"
    weird.write_text('"SENT_W"')
    argv = ["--", str(weird)]
    gate = set(cat_input_files(["cat", *argv]))
    observed = _real_cat_opens(argv, {str(weird): "SENT_W"})
    assert observed == {str(weird)}
    assert gate >= observed


@requires_cat
def test_gate_reports_nothing_for_stdin_only(tmp_path):
    """A downstream pipe stage (`… | cat`) and an explicit `-` name no file: nothing to gate, so the stage is..."""
    assert cat_input_files(["cat"]) == []
    assert cat_input_files(["cat", "-"]) == []
    assert _real_cat_opens([], {}) == set()


@pytest.mark.parametrize(("argv", "expected"), [
    (["cat", "a.json"], ["a.json"]),
    (["cat", "a.json", "b.json"], ["a.json", "b.json"]),
    (["cat", "-n", "a.json"], ["a.json"]),
    (["cat", "-nE", "-v", "a.json"], ["a.json"]),
    (["cat", "--", "-n"], ["-n"]),
    (["cat", "--", "a", "-b"], ["a", "-b"]),
    (["cat", "a", "-", "b"], ["a", "b"]),
    (["cat"], []),
    (["cat", "-"], []),
])
def test_cat_input_files_table(argv, expected):
    assert cat_input_files(argv) == expected


@pytest.mark.parametrize("argv", [
    ["cat", "-f", "x"],
    ["cat", "-z", "x"],
    ["cat", "-nf", "/etc/passwd"],
    ["cat", "--unknown", "x"],
    ["cat", "--files0-from=/etc/passwd"],
    ["cat", "-L/etc/ssh", "x"],
])
def test_cat_input_files_fails_closed(argv):
    assert cat_input_files(argv) is None
