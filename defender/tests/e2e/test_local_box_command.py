"""The host stand-in for an in-box marker read does not inherit pytest's sys.path."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts._by_path import DEFENDER, WORKTREE

_START_WITHOUT_PYTHONPATH = """
import json, os, sys
from pathlib import Path
assert 'PYTHONPATH' not in os.environ
# pytest makes the worktree importable in-process; that does not export child env.
sys.path.insert(0, sys.argv[1])
from defender._tenant import TenantId
from defender import box
from defender.tests.support.sandbox._spec1092 import STOCK_ROOTFS, make_run_dir
from defender.tests.e2e._box665 import RecordingDocker
from defender.tests.tenancy.tenant_1108_p2._support import AgentReadDocker
root = Path(sys.argv[2])
agent = root / 'agent'
agent.mkdir()
(agent / '.tenant-id').write_bytes(bytes.fromhex(sys.argv[4]))
docker = RecordingDocker() if sys.argv[3] == 'recording' else AgentReadDocker(agent)
try:
    executor = box.start_box(make_run_dir(root / 'runs'), Path(sys.argv[1]) / 'defender',
                             spec=box.BoxSpec(rootfs=STOCK_ROOTFS), docker=docker,
                             tenant_agent=agent, tenant_id=TenantId('ci-marker'))
except box.BoxFault as error:
    result = {'sandboxed': False, 'error': str(error)}
else:
    result = {'sandboxed': executor.sandboxed, 'error': ''}
    box.stop_box(executor)
result['marker_reads'] = sum(call[1] == 'exec' and call[-1].endswith('/.tenant-id')
                             for call in docker.calls if len(call) > 1)
print(json.dumps(result))
"""


@pytest.mark.parametrize("fake", ["recording", "agent"])
@pytest.mark.parametrize("marker", [b"ci-marker\r\n", b"ci-marker\r"], ids=["accepted", "malformed"])
def test_marker_read_uses_the_test_runtime_without_inherited_pythonpath(
    tmp_path: Path, fake: str, marker: bytes,
) -> None:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    proc = subprocess.run(
        [sys.executable, "-c", _START_WITHOUT_PYTHONPATH, str(WORKTREE), str(tmp_path),
         fake, marker.hex()],
        cwd=DEFENDER, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    seen = json.loads(proc.stdout)
    assert seen["marker_reads"] == 1, seen
    if marker == b"ci-marker\r\n":
        assert seen["sandboxed"] is True, seen
        assert seen["error"] == "", seen
    else:
        assert seen["sandboxed"] is False, seen
        assert "exactly a tenant id" in seen["error"], seen
