"""#1096 — the box entrypoint's per-exec import closure stays stdlib.

`bash_exec` run as `__main__` is the process every `docker exec` inside a box starts. Since
#1092 the `defender.runtime.box` package door pulls `defender._model` and with it pydantic,
paid once per agent command. The entrypoint only ever needed the wire codec and the env
allowlist, so those live in `box_codec.py` (stdlib) and the entrypoint imports that module
directly. The package keeps re-exporting the constants; there is still one owner.
"""
from __future__ import annotations

import subprocess
import sys

from defender.runtime import bash_exec, box, box_codec
from defender.tests._by_path import WORKTREE as REPO_ROOT

# Blocks the third-party packages the way the pre-#1092 box image did: absent. Installed on
# `sys.meta_path` (via `find_spec`, the 3.12+-surviving hook) BEFORE the entrypoint runs, and
# the entrypoint runs exactly as the box runs it — `-m defender.runtime.bash_exec` semantics,
# frame on stdin, frame on stdout.
_BLOCKED_ENTRYPOINT = (
    "import runpy, sys\n"
    "class Blocker:\n"
    "    def find_spec(self, name, path=None, target=None):\n"
    "        if name.split('.')[0] in ('pydantic', 'pydantic_core', 'pydantic_ai'):\n"
    "            raise ModuleNotFoundError(f'No module named {name!r} (blocked by the test)')\n"
    "        return None\n"
    "sys.meta_path.insert(0, Blocker())\n"
    "runpy.run_module('defender.runtime.bash_exec', run_name='__main__', alter_sys=True)\n"
)


def _run_entrypoint_without_pydantic(frame: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-c", _BLOCKED_ENTRYPOINT],
        input=frame, capture_output=True, cwd=REPO_ROOT, timeout=180,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO_ROOT), "DEFENDER_BOX_TIMEOUT": "30"},
    )


def test_the_entrypoint_answers_a_frame_with_pydantic_uninstalled():
    """One `docker exec` worth of work, with pydantic blocked at the import system: the
    entrypoint decodes the request, runs it, and answers with a response frame whose stdout is
    the command's — it never reaches for the `box` package door."""
    frame = box_codec.encode_request([bash_exec.Pipeline(
        connector="first",
        stages=[bash_exec.Stage(argv=["echo", "hi from the box"], stderr="capture")],
    )])
    done = _run_entrypoint_without_pydantic(frame)
    assert done.returncode == 0, (
        f"the entrypoint died before answering (rc={done.returncode}):\n"
        f"{done.stderr.decode('utf-8', 'replace')}")
    result = box_codec.decode_response(done.stdout)
    assert result.rc == 0, result
    assert result.out == b"hi from the box\n", result
    assert result.err == b"", result


def test_the_entrypoint_still_filters_its_env_through_the_allowlist():
    """The env the pipeline sees is the allowlist's members only: a credential-shaped key in
    the entrypoint's own environment does not reach the command, and the marker does. Same
    blocked interpreter, so a filter that reached for the package door would fail here too."""
    frame = box_codec.encode_request([bash_exec.Pipeline(
        connector="first",
        stages=[bash_exec.Stage(argv=["env"], stderr="capture")],
    )])
    done = subprocess.run(
        [sys.executable, "-c", _BLOCKED_ENTRYPOINT],
        input=frame, capture_output=True, cwd=REPO_ROOT, timeout=180,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO_ROOT), "DEFENDER_BOX": "1",
             "AWS_SECRET_ACCESS_KEY": "hunter2", "DEFENDER_BOX_TIMEOUT": "30"},
    )
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    seen = dict(line.split("=", 1) for line in
                box_codec.decode_response(done.stdout).out.decode().splitlines() if "=" in line)
    assert "AWS_SECRET_ACCESS_KEY" not in seen, seen
    assert seen.get("DEFENDER_BOX") == "1", seen
    assert set(seen) <= set(box_codec.BOX_ENV_ALLOWLIST), sorted(set(seen) - set(box_codec.BOX_ENV_ALLOWLIST))


def test_the_allowlist_and_the_mark_have_one_owner():
    """`box_codec` owns both constants; the package door hands out the same objects, not a
    restated copy that could drift from what the entrypoint filters by."""
    assert box.BOX_ENV_ALLOWLIST is box_codec.BOX_ENV_ALLOWLIST
    assert box._BOX_MARK_ENV is box_codec._BOX_MARK_ENV  # type: ignore[attr-defined]
    assert set(box_codec._BOX_MARK_ENV) <= set(box_codec.BOX_ENV_ALLOWLIST)  # type: ignore[attr-defined]
