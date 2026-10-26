from __future__ import annotations

import os

import pytest

from defender.tests.support.runtime.state import _1255_view as V
from defender.tests.support.runtime.state._1255_view import model_path

pytest.importorskip("pydantic_ai")

from defender.records import RunPaths  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

HOST_MARK = "HOST-SECRET-1136"


def test_a_hard_link_read_is_a_retry_and_the_run_reads_and_appends_on(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='rooted-1136')
    host = tmp_path / "outside" / "secret.txt"
    host.parent.mkdir()
    host.write_text(f"{HOST_MARK} do not disclose\n", encoding="utf-8")
    os.link(host, run_dir / "notes.txt")
    alert_marker = RunPaths(run_dir).alert.read_text(encoding="utf-8").strip()[:40]

    main = V.Recorder([
        Turn(tool_calls=[("read_file", {"path": "notes.txt"})]),
        Turn(tool_calls=[("read_file", {"path": model_path(RunPaths(run_dir).alert, run_dir=run_dir)})]),
        Turn(tool_calls=[("append_block", {"text": "+ recovered after a refused read\n"})]),
        Turn(text="done"),
    ])
    drive(run_dir, run_id="rooted-1136", main=main)

    assert main.calls == 4, "the loop did not survive the refused read"
    assert HOST_MARK not in main.all_text(), (
        "read_file handed the bytes of a hard-linked host file to the model"
    )
    kind, text = main.answer_to(2)
    assert kind == "return", f"the plain read after the refusal returned nothing: {kind} {text[:300]}"
    assert alert_marker in text, f"the plain read after the refusal returned nothing: {kind} {text[:300]}"
    assert (run_dir / "investigation.md").read_text(encoding="utf-8") == (
        "+ recovered after a refused read\n"
    )
    assert host.read_text(encoding="utf-8") == f"{HOST_MARK} do not disclose\n"
