"""#1096 — the box entrypoint's per-exec import closure stays stdlib.

`bash_exec` run as `__main__` is the process every `docker exec` inside a box starts, and
there is one `docker exec` per command an agent issues. Since #1092 the `defender.runtime.box`
package door pulls `defender._model` and with it pydantic, which is paid on that path, per
command. The entrypoint only ever needed the wire codec and the env allowlist, so those live
in `box_codec.py` (stdlib) and the entrypoint imports that module directly. The package keeps
re-exporting the constants; there is still one owner.

TWO RULES, and #1092's d26 retired the first one, not this one:

  * the AVAILABILITY rule — "pydantic is not installed in a box, so the closure must not
    import it" — is GONE. The owned image installs it, `BoxSpec` is a `@model` dataclass, and
    d26 (`test_1092_box_mark_env.py`) pins that retirement.
  * the COST rule below is #1096's and is new. Pydantic RESOLVES in a box; it is just
    expensive, and the entrypoint has no use for it. The guard is therefore about what the
    entrypoint's closure REACHES FOR, which is why it may not be relaxed by the fact that the
    import would now succeed.
"""
from __future__ import annotations

import subprocess

from defender.runtime import bash_exec, box, box_codec
from defender.tests._by_path import WORKTREE as REPO_ROOT
from defender.tests._import_blocker import run_blocked

#: The closure is held to an ALLOWLIST — the standard library plus this tree — not to a
#: denylist of the packages that happen to be expensive today. `pyyaml`, `duckdb` and
#: `typing-extensions` are in the box image too, and an import of any of them would be paid on
#: the same hot path. `_virtualenv` is the one exemption: a `.pth` hook this repo's venv runs
#: at interpreter start, before any test code, which no box has.
_ALLOWED = ("defender", "__main__", "_virtualenv")

# The entrypoint, run exactly as a box runs it: module main, request frame on stdin, response
# frame on stdout.
_ENTRYPOINT_BODY = (
    "import runpy\n"
    "runpy.run_module('defender.runtime.bash_exec', run_name='__main__', alter_sys=True)\n"
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
    """The entrypoint decodes the request, runs it, and answers with a response frame carrying
    the command's own stdout — without reaching for the `box` package door or for anything
    else outside the stdlib."""
    done = _run_entrypoint(_frame("echo", "hi from the box"), {"PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, (
        f"the entrypoint died before answering (rc={done.returncode}):\n"
        f"{done.stderr.decode('utf-8', 'replace')}")
    result = box_codec.decode_response(done.stdout)
    assert result.rc == 0, result
    assert result.out == b"hi from the box\n", result
    assert result.err == b"", result


def test_the_entrypoint_hands_the_command_exactly_the_allowlisted_keys():
    """The env the command sees is the allowlist's members that were present, no more and no
    fewer: a credential-shaped key in the entrypoint's own environment does not reach the
    command, the in-box mark does, and a key the filter wrongly dropped is caught too."""
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


#: Runs the entrypoint to completion and then reports what the interpreter has registered
#: under the module's own import name. A box starts the file as `__main__`, and `box_codec`
#: imports it by name, so without the alias the two are different module objects.
_REPORT_SECOND_COPY = (
    "import runpy, sys\n"
    "try:\n"
    "    runpy.run_module('defender.runtime.bash_exec', run_name='__main__', alter_sys=True)\n"
    "except SystemExit:\n"
    "    pass\n"
    "m = sys.modules.get('defender.runtime.bash_exec')\n"
    "sys.stderr.write('UNDER_IMPORT_NAME=' + (m.__name__ if m else '<absent>') + '\\n')\n"
)


def test_the_entrypoint_does_not_load_a_second_copy_of_itself():
    """The codec imports `bash_exec` by name while `bash_exec` is the running main module, so
    the entrypoint would execute its own 600-odd lines twice per `docker exec` — and the tree
    is mounted read-only, so no bytecode cache makes the second pass cheap. The main module
    registers itself under its import name first, and this is what says so: the object found
    under that name IS the running main module, not a second copy of it."""
    done = run_blocked(_REPORT_SECOND_COPY, allow_only=_ALLOWED, cwd=REPO_ROOT,
                       stdin=_frame("true"),
                       env={"PYTHONPATH": str(REPO_ROOT), "PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    report = done.stderr.decode("utf-8", "replace").strip().splitlines()[-1]
    assert report == "UNDER_IMPORT_NAME=__main__", (
        f"{report}: the interpreter holds a SECOND copy of the entrypoint module — the one it "
        "ran as the main module, and another that `box_codec`'s import built from source, "
        "paid on every `docker exec`")


#: Imports the module the ordinary way FIRST, then runs it as the main module, and reports
#: whether the ordinary import survived. This is the case `setdefault` exists for: a plain
#: assignment would replace a module other code already holds references into.
_REPORT_CLOBBER = (
    "import runpy, sys\n"
    "import defender.runtime.bash_exec as real\n"
    "try:\n"
    "    runpy.run_module('defender.runtime.bash_exec', run_name='__main__', alter_sys=True)\n"
    "except SystemExit:\n"
    "    pass\n"
    "still = sys.modules['defender.runtime.bash_exec'] is real\n"
    "sys.stderr.write('ORDINARY_IMPORT_SURVIVED=' + str(still) + '\\n')\n"
)


def test_running_as_main_never_displaces_an_ordinary_import_of_itself():
    """The alias is `setdefault`, not an assignment, and this is the difference: where the
    module was already imported under its own name, that one stays. An assignment would swap
    it for the main-module copy under everything already holding a reference to it."""
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
