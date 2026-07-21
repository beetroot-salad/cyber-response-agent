"""Differential + property spec for the `cat` operand extractor (`grant.cat_input_files`).

The extractor's job: the SET of files it reports must be a SUPERSET of the files real `cat`
actually opens — `gate_files ⊇ cat_opens` — so no file `cat` reads escapes the scope check.
Verified two ways:

  - a property differential against the real `cat` binary WITHOUT strace: each candidate
    file gets a unique sentinel, and `cat` echoes what it reads; any file whose sentinel
    leaks into cat's stdout was demonstrably opened, so the extractor must have listed it;
  - a reviewed table of argv -> expected operands (runs without `cat`).

`cat_input_files` returns None to FAIL CLOSED on a shape it won't reason about (any
`-`-prefixed token that is not a known boolean bundle or `--`); a None result denies the
whole command, so it trivially satisfies the superset property (nothing runs).

#575 moved the function from `bash._cat_input_files` to `grant.cat_input_files` and made it
the ONE entry in the global `PROGRAMS` table that is not `OPENS_NOTHING`: `cat` is now the
SOLE file-opening program on every lane, so this superset property is no longer the judge's
special case (`operand_gated`, deleted) but the general containment rule — every grant of
`cat`, for every agent, resolve()s exactly the operands this function reports and matches
them against that grant's scope. The property under test is unchanged; its blast radius grew
from one agent to all of them, which is the point.

Why `cat` and nothing else: it is the only granted program with NO arg-taking flag, so
"which files does this argv open?" is answerable without reimplementing an option parser
(the retired `test_jq_operand_gate_differential.py` had to model jq's
`-f`/`-L`/`--slurpfile`/`--rawfile` and short-bundle arg consumption). Every other program
earns its `OPENS_NOTHING` claim structurally, by a shape that admits no file-opening flag —
pinned in test_grant_gate_575.py (b7/b8).
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from defender.runtime.permission.grant import cat_input_files

_CAT = shutil.which("cat")
requires_cat = pytest.mark.skipif(_CAT is None, reason="cat binary not available")


def _real_cat_opens(argv, sentinels):
    """A lower bound on the files real `cat` opens for `argv` (paths already inlined): run
    `cat` on empty stdin and return the subset of `sentinels` (path -> unique content
    marker) whose marker leaked into cat's stdout — proof cat read that file."""
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
    """`--` ends options, so a following `-`-prefixed token is an OPERAND cat opens. The
    gate must list it rather than mistake it for a flag — the fail-open shape here."""
    weird = tmp_path / "-nE"
    weird.write_text('"SENT_W"')
    argv = ["--", str(weird)]
    gate = set(cat_input_files(["cat", *argv]))
    observed = _real_cat_opens(argv, {str(weird): "SENT_W"})
    assert observed == {str(weird)}
    assert gate >= observed


@requires_cat
def test_gate_reports_nothing_for_stdin_only(tmp_path):
    """A downstream pipe stage (`… | cat`) and an explicit `-` name no file: nothing to
    gate, so the stage is inert and must not be denied for lack of operands."""
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
