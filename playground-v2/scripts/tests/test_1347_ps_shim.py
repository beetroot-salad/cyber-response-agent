"""#1347 r6.4 D6 (re-covered per A10): the replica hosts' `ps` shim prints the captured proc-tree.

Entry point bound by this contract: executable `playground-v2/hosts/base/ps-shim` (baked into
replica images as `ps`), reading the captured tree from the file named by `V2_PS_SHIM_TREE` (r6.4.4: lab
variables carry the `V2_` prefix, playground-v2/CLAUDE.md; the unprefixed `PS_SHIM_TREE` has no effect).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

SHIM = Path(__file__).resolve().parents[2] / "hosts" / "base" / "ps-shim"
FIXED_ARGV = ["-eo", "pid,ppid,user,stat,etime,cmd", "--forest"]
TREE = (b"  PID  PPID USER STAT     ELAPSED CMD\n    1     0 root Ss     01:02:03 /sbin/init\n"
        b"   42     1 www  S      00:10:00  \\_ nginx: worker process\n")


def _run(env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run([str(SHIM), *FIXED_ARGV], capture_output=True,
                          env={"PATH": "/usr/bin:/bin", **env})


def test_the_shim_prints_the_captured_tree_for_the_verbs_fixed_argv(tmp_path):
    """D6: `ps -eo pid,ppid,user,stat,etime,cmd --forest` yields exactly the captured bytes."""
    tree = tmp_path / "tree.txt"
    tree.write_bytes(TREE)
    proc = _run({"V2_PS_SHIM_TREE": str(tree)})
    assert proc.returncode == 0 and proc.stdout == TREE


def test_the_shim_prints_whatever_tree_it_was_captured_with(tmp_path):
    """D6 control: a different captured tree gives different output, so it is not canned."""
    tree = tmp_path / "tree.txt"
    tree.write_bytes(b"other tree\n")
    assert _run({"V2_PS_SHIM_TREE": str(tree)}).stdout == b"other tree\n"


def test_the_shim_is_executable_and_never_answers_without_a_captured_tree(tmp_path):
    """D6: an unset or missing tree file is a non-zero exit with nothing on stdout, never an
    empty process list that reads as 'no processes'."""
    assert os.access(SHIM, os.X_OK)
    for env in ({}, {"V2_PS_SHIM_TREE": str(tmp_path / "absent.txt")}):
        proc = _run(env)
        assert proc.returncode != 0 and proc.stdout == b""


def test_the_unprefixed_PS_SHIM_TREE_alone_has_no_effect(tmp_path):
    """r6.4.4 (finding 6): `/workspace/.env` is sourced into every shell and shadows unprefixed names, so the shim
    reads only `V2_PS_SHIM_TREE`: with the unprefixed name alone it answers as with no tree at all."""
    tree = tmp_path / "tree.txt"
    tree.write_bytes(TREE)
    proc = _run({"PS_SHIM_TREE": str(tree)})
    assert proc.returncode != 0 and proc.stdout == b"", proc
