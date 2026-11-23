"""#1108 P4: a liveness judgement, a wrong-but-green production variant.

#1618 retires the rest of this file with the builders it drove (flow 1: the fetch child fills the caller's owned empty
folder; there is no `copy_for_run`, `materialise_export`, `exports/` or `resolve_source`, K8), each with its successor:
- "a run copy build that fails leaves no half-built folder":
  `knowledge_1618/test_run_start_1618.py::test_a6_a_child_killed_mid_fill_leaves_nothing_and_the_run_refuses`;
- "an export build that fails leaves no staging folder": `knowledge_1618/test_fetch_child_1618.py::test_a11_*` and
  `::test_a19_*` (refused content leaves nothing; the private repository is gone after);
- "a pinned commit with no export is refused when it is resolved":
  `knowledge_1618/test_run_start_1618.py::test_a9_a_pin_forgejo_does_not_serve_refuses_naming_the_commit` and
  `test_run_start.py::test_o_pin_a_pin_to_a_commit_forgejo_does_not_serve_refuses_before_message_zero`.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest


# --- liveness ---------------------------------------------------------------------------------

def test_r6_a_zombie_is_not_a_live_owner(tmp_path):
    from defender.tenancy._owner import OWNER_FILE, owner_alive, process_start

    proc = subprocess.Popen([sys.executable, "-c", "pass"])  # noqa: S603 — not waited for
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            stat = Path(f"/proc/{proc.pid}/stat").read_text()
            if stat[stat.rindex(")") + 2] == "Z":
                break
            time.sleep(0.02)
        else:
            pytest.fail("premise: the child never became a zombie")
        assert process_start(proc.pid) is None
        folder = tmp_path / "copy"
        folder.mkdir()
        (folder / OWNER_FILE).write_text(
            f'{{"pid": {proc.pid}, "start": "{stat[stat.rindex(")") + 2:].split()[19]}"}}',
            encoding="utf-8")
        assert not owner_alive(folder)
    finally:
        proc.wait()
