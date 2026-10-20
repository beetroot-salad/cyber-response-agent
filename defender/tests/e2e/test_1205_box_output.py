"""#1205: output overflow is fatal through MAIN and correlation-lead boundaries."""
from __future__ import annotations

import shutil
import uuid
from pathlib import Path

import pytest

from defender import box
from defender.execution import bash_exec
from defender.runtime.exception_groups import carried
from defender.runtime.providers import ProviderDown
from defender.runtime.run_end import CALL_RECORDS, CallRecordWriteFailed
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood
from defender.tests.support.sandbox._spec1092 import make_run_dir
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

pytestmark = pytest.mark.e2e


def _fault(shape):
    overflow = box.BoxOutputLimitExceeded()
    if shape == "bare":
        return overflow
    if shape == "nested":
        return ExceptionGroup("outer", [ExceptionGroup("inner", [overflow])])
    if shape == "call-record":
        return ExceptionGroup("mixed", [CallRecordWriteFailed(sorted(CALL_RECORDS)[0], "test"), overflow])
    return ExceptionGroup("mixed", [ProviderDown(model="test", status=503, attempts=4), overflow])


@pytest.mark.parametrize("shape", ["bare", "nested", "mixed", "call-record"])
@pytest.mark.parametrize("where", ["main", "correlation"])
def test_overflow_ends_the_run_instead_of_becoming_a_retry_or_fallback(tmp_path, shape, where):
    fault = _fault(shape)
    injected = S.LeadFault(raise_on=1, exc=lambda: fault)
    main = S.MainScript([S.text(S.DONE)], fault=injected if where == "main" else S.CLEAN)
    result = S.run_alert(tmp_path, main=main,
                         lead_faults={S.L3: injected} if where == "correlation" else None)
    assert result.raised is not None
    assert carried(result.raised, box.BoxOutputLimitExceeded) is not None
    assert main.requests == (1 if where == "main" else 0)
    assert not (result.folder / "report.md").exists()


@pytest.mark.parametrize("runtime", ["runsc", "runc"])
def test_live_box_printing_past_limit_is_refused_and_stopped(tmp_path, runtime):
    if not daemon_reachable():
        pytest.skip("no reachable Docker daemon")
    if runtime not in docker_runtimes():
        pytest.skip(f"runtime {runtime} is not registered")
    anchor = dood_anchor() if is_dood() else tmp_path
    if anchor is None:
        pytest.skip("Docker daemon cannot bind the checkout")
    root = anchor / f"output-1205-{uuid.uuid4().hex}"
    root.mkdir(parents=True)
    executor = None
    try:
        run_dir = make_run_dir(root, name="run-1205")
        executor = box.start_box(run_dir, Path(__file__).resolve().parents[2],
                                 spec=box.BoxSpec(runtime=runtime))
        assert executor.sandboxed
        cwd = Path("/runs/current")
        control = executor.run_parsed(bash_exec.parse("echo answer"), command="echo answer", cwd=cwd, timeout=30)
        assert control.out == b"answer\n"
        # Finite output keeps a regression safe: ~64 MiB, never an unbounded producer.
        command = f"head -c {box.BOX_OUTPUT_LIMIT + 1} /dev/zero"
        with pytest.raises(box.BoxOutputLimitExceeded):
            executor.run_parsed(bash_exec.parse(command), command=command, cwd=cwd, timeout=60)
        status = box._docker(["docker", "inspect", "-f", "{{.State.Status}}", executor.name])
        assert status.stdout.strip() in {"exited", "dead"}
        with pytest.raises(box.BoxOutputLimitExceeded):
            executor.run_parsed([], command="again", cwd=cwd, timeout=5)
    finally:
        if executor is not None:
            box.stop_box(executor)
        shutil.rmtree(root)
