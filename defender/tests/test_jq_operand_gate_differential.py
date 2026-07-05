"""Differential + property spec for the jq file-operand gate (`bash._jq_input_files`).

The gate's job (issue #522 migration step 2, the item the #517 xhigh review recommended):
the SET of files the gate reports must be a SUPERSET of the files real `jq` actually opens
— `gate_files ⊇ jq_opens` — so no file jq reads escapes the read-root path-gate. Verified
two ways:

  - a property differential against the real `jq` binary WITHOUT strace: each candidate
    file gets a unique sentinel and jq is run so the loaded content surfaces; any file whose
    sentinel leaks into jq's stdout+stderr was demonstrably opened, so the gate must have
    listed it (or fail closed). This is exactly what would have caught the #517 bundled-flag
    fail-open automatically;
  - a reviewed table of argv -> expected operands (runs without jq).

`_jq_input_files` returns None to FAIL CLOSED on a shape it won't reason about (a short
bundle carrying an arg-taking flag, an unknown long option); a None result denies the whole
command, so it trivially satisfies the superset property (nothing runs).
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from defender.runtime.permission.bash import _jq_input_files

_JQ = shutil.which("jq")
requires_jq = pytest.mark.skipif(_JQ is None, reason="jq binary not available")


def _real_jq_opens(argv, sentinels):
    """A lower bound on the files real jq opens for `argv` (file paths already inlined):
    run jq and return the subset of `sentinels` (path -> unique content marker) whose marker
    leaked into jq's stdout+stderr — proof jq read that file."""
    proc = subprocess.run([_JQ, *argv], capture_output=True, text=True, timeout=10)
    blob = proc.stdout + proc.stderr
    return {path for path, marker in sentinels.items() if marker in blob}


# ---------------------------------------------------------------------------
# property differential against the real jq binary
# ---------------------------------------------------------------------------

@requires_jq
def test_gate_superset_input_operand(tmp_path):
    op = tmp_path / "op.json"
    op.write_text('{"k":"SENT_OP"}')
    argv = [".", str(op)]
    gate = set(_jq_input_files(["jq", *argv]))
    observed = _real_jq_opens(argv, {str(op): "SENT_OP"})
    assert observed == {str(op)}          # jq demonstrably read the operand
    assert gate >= observed               # the gate covers every file jq opened


@requires_jq
def test_gate_superset_slurpfile(tmp_path):
    sf = tmp_path / "sf.json"
    sf.write_text('"SENT_SF"')
    argv = ["-n", "--slurpfile", "s", str(sf), "$s"]
    gate = set(_jq_input_files(["jq", *argv]))
    observed = _real_jq_opens(argv, {str(sf): "SENT_SF"})
    assert observed == {str(sf)}          # --slurpfile really opened it
    assert gate >= observed               # even though the trailing operand looks clean


@requires_jq
def test_gate_superset_dash_f_program_and_input(tmp_path):
    prog = tmp_path / "prog.jq"
    prog.write_text(".")                  # identity filter -> the input's content surfaces
    op = tmp_path / "op.json"
    op.write_text('{"k":"SENT_OP"}')
    argv = ["-f", str(prog), str(op)]
    gate = set(_jq_input_files(["jq", *argv]))
    observed = _real_jq_opens(argv, {str(op): "SENT_OP"})
    assert observed == {str(op)}
    assert gate >= observed
    assert str(prog) in gate              # the -f program file is itself path-gated (#517)


@requires_jq
def test_gate_fails_closed_on_bundle_jq_would_open(tmp_path):
    # `jq -nf PROG` opens PROG as the filter program (jq echoes a compile error's source to
    # stderr). The gate FAILS CLOSED (None) on the short bundle, so the command is denied —
    # no un-gated open escapes. This is the #517 fail-open, now regression-locked.
    prog = tmp_path / "prog.jq"
    prog.write_text("this is not valid jq SENT_PROG")
    argv = ["-nf", str(prog)]
    observed = _real_jq_opens(argv, {str(prog): "SENT_PROG"})
    assert observed == {str(prog)}                     # real jq DOES open it
    assert _jq_input_files(["jq", *argv]) is None      # gate denies the whole command


# ---------------------------------------------------------------------------
# reviewed operand table (no jq needed)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("argv", "expected"), [
    (["jq", ".", "a.json"], ["a.json"]),                                   # one operand
    (["jq", "-s", ".", "a.json", "b.json"], ["a.json", "b.json"]),         # slurp: two operands
    (["jq", "--slurpfile", "s", "sf.json", ".", "op.json"], ["sf.json", "op.json"]),
    (["jq", "--rawfile", "r", "rf.txt", "-n", "$r"], ["rf.txt"]),
    (["jq", "-f", "prog.jq", "op.json"], ["prog.jq", "op.json"]),          # -f program + input
    (["jq", "--arg", "k", "v", ".", "op.json"], ["op.json"]),              # --arg value is NOT a file
    (["jq", "-n", "--args", ".", "x", "y"], []),                          # after --args: strings
    (["jq", "."], []),                                                     # stdin only
    (["jq", ".", "-"], []),                                                # explicit stdin skipped
])
def test_jq_input_files_table(argv, expected):
    assert _jq_input_files(argv) == expected


@pytest.mark.parametrize("argv", [
    ["jq", "-nf", "/etc/passwd"],            # short bundle carrying -f -> desyncs the count
    ["jq", "-Rf", "/etc/passwd"],            # -R + -f
    ["jq", "-L/etc/ssh", "."],              # attached -L<dir>
    ["jq", "-L", "/etc/ssh", "."],           # standalone -L <dir>: jq module search path, an
    ["jq", "--library-path", "/etc", "."],   #   ungated `<dir>/<mod>.jq` read oracle -> fail closed
    ["jq", "--totally-unknown", "."],       # unknown long option might take a file
])
def test_jq_input_files_fails_closed(argv):
    assert _jq_input_files(argv) is None
