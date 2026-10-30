"""#1347 O1 and D9: capture is all-or-nothing, and no attack fires while a capture holds the lock.

Not run by CI. Locally:

    flock /tmp/defender-pytest.lock uv run --no-project --python 3.12 \
        --with pyyaml --with pytest -m pytest playground-v2/attacks/tests/test_1347_capture.py
"""
from __future__ import annotations

import fcntl
import importlib.util
from pathlib import Path
from typing import Any

import pytest

PLAYGROUND = Path(__file__).resolve().parents[2]
RUNNER = PLAYGROUND / "attacks" / "runner.py"
CAPTURE = PLAYGROUND / "scripts" / "capture_case.py"
LEDGER_REF = "ledger-0001"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCENARIO = {"id": "ssh-brute-force-canary", "target_host": "web-1", "source_host": "dev-ws-1",
            "steps": [{"cmd": "true"}]}


def _fire(runner: Any, tmp_path: Path, lock: Path) -> list[Any]:
    calls: list[Any] = []

    def exec_fn(*args: Any, **kw: Any) -> tuple[int, str, str]:
        calls.append(args)
        return 0, "", ""

    runner.run_scenario(SCENARIO, 42, {}, False, runs_dir=tmp_path / "runs",
                        exec_fn=exec_fn, capture_lock=lock)
    return calls


def test_the_runner_refuses_to_fire_while_the_capture_lock_is_held(tmp_path):
    """D9: with the capture lock held nothing is dispatched and no run is written; released, the
    same scenario fires."""
    runner = _load(RUNNER, "runner_1347")
    lock = tmp_path / "capture.lock"
    lock.touch()

    with lock.open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(SystemExit):
            _fire(runner, tmp_path, lock)
        assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").iterdir())

    assert _fire(runner, tmp_path, lock), "with the lock free the scenario did not fire"


class Ops:
    """The lab operations capture drives, recorded; `fail_at` raises inside that step."""

    def __init__(self, fail_at: str | None = None) -> None:
        self.fail_at, self.calls = fail_at, []

    def __getattr__(self, step: str) -> Any:
        def op(*args: Any, **kw: Any) -> Any:
            self.calls.append(step)
            if step == self.fail_at:
                raise RuntimeError(f"{step} failed")
            if step == "fire":
                return {"ledger_ref": LEDGER_REF, "alert": {"@timestamp": "2026-10-20T08:00:00Z"}}
            if step == "revert":
                return None
            return {}

        return op


def test_a_failure_mid_capture_reverts_the_fault_and_writes_no_freeze(tmp_path):
    """O1: a step failing after the fault is live (committing host images) reverts it by its
    ledger ref and leaves no freeze beside the case."""
    capture = _load(CAPTURE, "capture_1347")
    case_dir = tmp_path / "m05-lsass-access"
    case_dir.mkdir()
    ops = Ops(fail_at="commit_hosts")

    with pytest.raises(RuntimeError):
        capture.capture(case_dir, scenario="ssh-brute-force-canary", chaos="stale-cmdb", ops=ops)

    assert "revert" in ops.calls, f"the fault was left live: {ops.calls}"
    assert sorted(p.name for p in case_dir.iterdir()) == [], (
        f"a partial freeze was written: {list(case_dir.iterdir())}")
