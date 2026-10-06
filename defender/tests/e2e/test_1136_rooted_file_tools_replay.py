"""#1136 through the real driver: MAIN's `read_file` and `append_block` reach the run dir
through the rooted core.

One replayed run over a run dir holding a hard link to a host file outside every read root.
Today `read_file` hands the host bytes to the model (the gate's `resolve()` cannot see a hard
link). Through the core the read is a retry, the loop carries on, a plain read still returns
the alert, and `append_block` still lands its bytes in `investigation.md`.
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

HOST_MARK = "HOST-SECRET-1136"


def test_a_hard_link_read_is_a_retry_and_the_run_reads_and_appends_on(tmp_path):
    """The model asks for `notes.txt`, a hard link to a host file: the host bytes never reach
    any later model turn. Then a plain read (the alert) comes back, and an append lands — the
    refusal did not wedge the loop, and the plain lanes still work through the move."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    host = tmp_path / "outside" / "secret.txt"
    host.parent.mkdir()
    host.write_text(f"{HOST_MARK} do not disclose\n", encoding="utf-8")
    os.link(host, run_dir / "notes.txt")
    alert_marker = (run_dir / "alert.json").read_text(encoding="utf-8").strip()[:40]

    main = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": "notes.txt"})]),
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(tool_calls=[("append_block", {"text": "+ recovered after a refused read\n"})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="rooted-1136", main=main)

    assert main.calls == 4, "the loop did not survive the refused read"
    assert not any(HOST_MARK in seen for seen in main.seen), (
        "read_file handed the bytes of a hard-linked host file to the model"
    )
    assert alert_marker in main.seen[2], "the plain read after the refusal returned nothing"
    assert (run_dir / "investigation.md").read_text(encoding="utf-8") == (
        "+ recovered after a refused read\n"
    )
    assert host.read_text(encoding="utf-8") == f"{HOST_MARK} do not disclose\n"
