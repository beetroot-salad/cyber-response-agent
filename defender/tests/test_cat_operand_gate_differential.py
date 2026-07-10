"""Differential + property spec for the `cat` file-operand gate (`bash._cat_input_files`).

The gate's job (the judge's `operand_gated` lane): the SET of files the gate reports must
be a SUPERSET of the files real `cat` actually opens — `gate_files ⊇ cat_opens` — so no
file `cat` reads escapes the read-root path-gate. Verified two ways:

  - a property differential against the real `cat` binary WITHOUT strace: each candidate
    file gets a unique sentinel, and `cat` echoes what it reads; any file whose sentinel
    leaks into cat's stdout was demonstrably opened, so the gate must have listed it;
  - a reviewed table of argv -> expected operands (runs without `cat`).

`_cat_input_files` returns None to FAIL CLOSED on a shape it won't reason about (any
`-`-prefixed token that is not a known boolean bundle or `--`); a None result denies the
whole command, so it trivially satisfies the superset property (nothing runs).

This file REPLACES `test_jq_operand_gate_differential.py`: the judge moved off `jq` (whose
argv opens files through `-f`/`-L`/`--slurpfile`/`--rawfile`/`--argfile` and short-bundle
arg consumption, needing a reimplementation of jq's option parser) onto `cat … |
defender-sql`, where the file-opening program has NO arg-taking flag and the compute
program opens no file at all. The property under test is identical; the surface is smaller.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from defender.runtime.permission.bash import _cat_input_files

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


# ---------------------------------------------------------------------------
# property differential against the real cat binary
# ---------------------------------------------------------------------------

@requires_cat
def test_gate_superset_single_operand(tmp_path):
    op = tmp_path / "op.json"
    op.write_text('{"k":"SENT_OP"}')
    argv = [str(op)]
    gate = set(_cat_input_files(["cat", *argv]))
    observed = _real_cat_opens(argv, {str(op): "SENT_OP"})
    assert observed == {str(op)}          # cat demonstrably read the operand
    assert gate >= observed               # the gate covers every file cat opened


@requires_cat
def test_gate_superset_multiple_operands_behind_a_bundle(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text('"SENT_A"')
    b.write_text('"SENT_B"')
    argv = ["-nE", str(a), str(b)]        # a boolean bundle opens no file of its own
    gate = set(_cat_input_files(["cat", *argv]))
    observed = _real_cat_opens(argv, {str(a): "SENT_A", str(b): "SENT_B"})
    assert observed == {str(a), str(b)}
    assert gate >= observed


@requires_cat
def test_gate_superset_operand_after_double_dash(tmp_path):
    """`--` ends options, so a following `-`-prefixed token is an OPERAND cat opens. The
    gate must list it rather than mistake it for a flag — the fail-open shape here."""
    weird = tmp_path / "-nE"              # a filename that looks exactly like a flag
    weird.write_text('"SENT_W"')
    argv = ["--", str(weird)]
    gate = set(_cat_input_files(["cat", *argv]))
    observed = _real_cat_opens(argv, {str(weird): "SENT_W"})
    assert observed == {str(weird)}       # real cat DOES open it
    assert gate >= observed


@requires_cat
def test_gate_reports_nothing_for_stdin_only(tmp_path):
    """A downstream pipe stage (`… | cat`) and an explicit `-` name no file: nothing to
    gate, so the stage is inert and must not be denied for lack of operands."""
    assert _cat_input_files(["cat"]) == []
    assert _cat_input_files(["cat", "-"]) == []
    assert _real_cat_opens([], {}) == set()


# ---------------------------------------------------------------------------
# reviewed operand table (no cat needed)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("argv", "expected"), [
    (["cat", "a.json"], ["a.json"]),                          # one operand
    (["cat", "a.json", "b.json"], ["a.json", "b.json"]),      # two operands
    (["cat", "-n", "a.json"], ["a.json"]),                    # boolean flag skipped
    (["cat", "-nE", "-v", "a.json"], ["a.json"]),             # bundles + repeats skipped
    (["cat", "--", "-n"], ["-n"]),                            # after `--`: a flag-shaped FILE
    (["cat", "--", "a", "-b"], ["a", "-b"]),                  # everything after `--` is an operand
    (["cat", "a", "-", "b"], ["a", "b"]),                     # bare `-` is stdin, not a file
    (["cat"], []),                                            # stdin only
    (["cat", "-"], []),                                       # explicit stdin skipped
])
def test_cat_input_files_table(argv, expected):
    assert _cat_input_files(argv) == expected


@pytest.mark.parametrize("argv", [
    ["cat", "-f", "x"],                  # not a cat flag at all -> don't guess, deny
    ["cat", "-z", "x"],                  # unknown short flag
    ["cat", "-nf", "/etc/passwd"],       # a bundle carrying an unknown letter
    ["cat", "--unknown", "x"],           # unknown long option might take a file
    ["cat", "--files0-from=/etc/passwd"],  # a real coreutils flag — but `wc`'s, not `cat`'s
    ["cat", "-L/etc/ssh", "x"],          # attached-value shape
])
def test_cat_input_files_fails_closed(argv):
    assert _cat_input_files(argv) is None
