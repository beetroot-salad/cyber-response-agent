"""#1347 D6: the replica hosts' `ps` shim prints the captured proc-tree.

Entry point bound by this contract: executable `playground-v2/hosts/base/ps-shim` (baked into
replica images as `ps`), reading the captured tree from the file named by `PS_SHIM_TREE`.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

SHIM = Path(__file__).resolve().parents[2] / "hosts" / "base" / "ps-shim"
FIXED_ARGV = ["-eo", "pid,ppid,user,stat,etime,cmd", "--forest"]
TREE = (b"  PID  PPID USER STAT     ELAPSED CMD\n    1     0 root Ss     01:02:03 /sbin/init\n"
        b"   42     1 www  S      00:10:00  \\_ nginx: worker process\n")


def test_the_shim_prints_the_captured_tree_for_the_verbs_fixed_argv(tmp_path):
    """D6: `ps -eo pid,ppid,user,stat,etime,cmd --forest` yields exactly the captured bytes."""
    tree = tmp_path / "tree.txt"
    tree.write_bytes(TREE)
    proc = subprocess.run([str(SHIM), *FIXED_ARGV], capture_output=True,
                          env={"PS_SHIM_TREE": str(tree), "PATH": "/usr/bin:/bin"})
    assert proc.returncode == 0 and proc.stdout == TREE


def test_the_shim_prints_whatever_tree_it_was_captured_with(tmp_path):
    """D6 control: a different captured tree gives different output, so it is not canned."""
    tree = tmp_path / "tree.txt"
    tree.write_bytes(b"other tree\n")
    proc = subprocess.run([str(SHIM), *FIXED_ARGV], capture_output=True,
                          env={"PS_SHIM_TREE": str(tree), "PATH": "/usr/bin:/bin"})
    assert proc.stdout == b"other tree\n"
