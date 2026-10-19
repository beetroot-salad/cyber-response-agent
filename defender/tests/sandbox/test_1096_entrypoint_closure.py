"""The box entrypoint (bash_exec as __main__) keeps a stdlib-only import closure: it runs once per agent command."""
from __future__ import annotations

import subprocess

from defender.execution import bash_exec, box_codec
from defender import box
from defender.tests.support.shared.contracts._by_path import WORKTREE as REPO_ROOT
from defender.tests.support.shared.contracts._import_blocker import run_blocked

_ALLOWED = ("defender", "__main__", "_virtualenv")

# The entrypoint, run exactly as a box runs it: module main, request frame on stdin, response
# frame on stdout.
_ENTRYPOINT_BODY = (
    "import runpy\n"
    "runpy.run_module('defender.execution.bash_exec', run_name='__main__', alter_sys=True)\n"
)


def _run_entrypoint(frame: bytes, env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    """One `docker exec` worth of work, under an interpreter that refuses every import outside
    the standard library and this tree. `env` is the whole environment, as a box's is: the
    allowlist is what the box's `docker run --env` put there, and the entrypoint filters
    `os.environ` by it again."""
    return run_blocked(_ENTRYPOINT_BODY, allow_only=_ALLOWED, cwd=REPO_ROOT, stdin=frame,
                       env={"PYTHONPATH": str(REPO_ROOT), **env})


def _frame(*argv: str) -> bytes:
    return box_codec.encode_request([bash_exec.Pipeline(
        connector="first", stages=[bash_exec.Stage(argv=list(argv), stderr="capture")])])


def test_the_entrypoint_answers_a_frame_with_no_third_party_package_importable():
    done = _run_entrypoint(_frame("echo", "hi from the box"), {"PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, (
        f"the entrypoint died before answering (rc={done.returncode}):\n"
        f"{done.stderr.decode('utf-8', 'replace')}")
    result = box_codec.decode_response(done.stdout)
    assert result.rc == 0, result
    assert result.out == b"hi from the box\n", result
    assert result.err == b"", result


def test_the_entrypoint_hands_the_command_exactly_the_allowlisted_keys():
    done = _run_entrypoint(_frame("env"), {
        "PATH": "/usr/bin:/bin", "DEFENDER_BOX": "1", "TZ": "UTC",
        "AWS_SECRET_ACCESS_KEY": "hunter2",
    })
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    seen = dict(line.split("=", 1) for line in
                box_codec.decode_response(done.stdout).out.decode().splitlines() if "=" in line)
    # Exact, not a subset: a subset check passes a filter that is too STRICT as happily as a
    # correct one, and `PYTHONPATH` is the member most likely to be dropped by mistake.
    assert set(seen) == {"PATH", "PYTHONPATH", "DEFENDER_BOX", "TZ"}, sorted(seen)
    assert seen["DEFENDER_BOX"] == "1", seen
    assert "hunter2" not in done.stdout.decode("utf-8", "replace")


_REPORT_SECOND_COPY = (
    "import runpy, sys\n"
    "try:\n"
    "    runpy.run_module('defender.execution.bash_exec', run_name='__main__', alter_sys=True)\n"
    "except SystemExit:\n"
    "    pass\n"
    "m = sys.modules.get('defender.execution.bash_exec')\n"
    "sys.stderr.write('UNDER_IMPORT_NAME=' + (m.__name__ if m else '<absent>') + '\\n')\n"
)


def test_the_entrypoint_does_not_load_a_second_copy_of_itself():
    done = run_blocked(_REPORT_SECOND_COPY, allow_only=_ALLOWED, cwd=REPO_ROOT,
                       stdin=_frame("true"),
                       env={"PYTHONPATH": str(REPO_ROOT), "PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    report = done.stderr.decode("utf-8", "replace").strip().splitlines()[-1]
    assert report == "UNDER_IMPORT_NAME=__main__", (
        f"{report}: the interpreter holds a SECOND copy of the entrypoint module — the one it "
        "ran as the main module, and another that `box_codec`'s import built from source, "
        "paid on every `docker exec`")


_REPORT_CLOBBER = (
    "import runpy, sys\n"
    "import defender.execution.bash_exec as real\n"
    "try:\n"
    "    runpy.run_module('defender.execution.bash_exec', run_name='__main__', alter_sys=True)\n"
    "except SystemExit:\n"
    "    pass\n"
    "still = sys.modules['defender.execution.bash_exec'] is real\n"
    "sys.stderr.write('ORDINARY_IMPORT_SURVIVED=' + str(still) + '\\n')\n"
)


def test_running_as_main_never_displaces_an_ordinary_import_of_itself():
    done = run_blocked(_REPORT_CLOBBER, allow_only=_ALLOWED, cwd=REPO_ROOT,
                       stdin=_frame("true"),
                       env={"PYTHONPATH": str(REPO_ROOT), "PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    report = done.stderr.decode("utf-8", "replace").strip().splitlines()[-1]
    assert report == "ORDINARY_IMPORT_SURVIVED=True", (
        f"{report}: running the entrypoint as the main module REPLACED the module object that "
        "an ordinary import had already put in place")


def test_the_allowlist_and_the_mark_have_one_owner():
    """`box_codec` owns both constants; the package door hands out the same objects, not a
    restated copy that could drift from what the entrypoint filters by."""
    assert box.BOX_ENV_ALLOWLIST is box_codec.BOX_ENV_ALLOWLIST
    assert box._BOX_MARK_ENV is box_codec._BOX_MARK_ENV  # type: ignore[attr-defined]
    assert set(box_codec._BOX_MARK_ENV) <= set(box_codec.BOX_ENV_ALLOWLIST)  # type: ignore[attr-defined]
