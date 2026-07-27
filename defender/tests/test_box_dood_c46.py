"""C46 — the box's bind sources under docker-outside-of-Docker, and F1's runtime lever.

Two defects, both about `box.py` being unable to start a box on a perfectly healthy daemon:

**C46 / `C_dood`.** `_create_argv` and `_render_argv` emitted `source=<a path this process
can see>`. Under docker-outside-of-Docker the daemon resolves that string in a DIFFERENT
namespace, so it names nothing and `docker run` fails at create. `tests/e2e/
test_540_box_boundary.py` skips wholesale for exactly this reason. The fix translates the
bind SOURCE through this container's own mount table and leaves `target=` alone — the
equality the RSD's mount-ordering note depends on is *in-isolate path == the path the
downstream reader uses*, not *source == target*, because artifacts, orient's workspace map,
and `raw_command` all record the target and the learning loop reads them back through this
same namespace.

**F1 (`intent_540.md` §542).** The resolution was "anchor the default (runsc) in the
dataclass, read ONE env var to override the runtime axis". `BoxSpec.from_env` implemented
the lever but no call path invoked it — `DEFAULT_SPEC = BoxSpec()` hard-pinned every run to
runsc, making the RSD's "ships on whatever the host supports rather than waiting on a
privileged runsc host" unreachable. F1 also asks for the knob to be "exercised at both
settings in CI, not stubbed at one", which `test_runtime_lever_*` below does.

These are hermetic: the translation helpers are pure, and the one wiring test fakes the
`docker=` seam, so nothing here needs a daemon.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from defender.runtime.box import (
    BoxSpec,
    _covered,
    _create_argv,
    _daemon_source,
    _render_argv,
    start_box,
)
from defender.runtime.box_codec import BoxFault

# The shape `docker inspect <self>` returns in a devcontainer: the workspace is bind-mounted
# from somewhere else entirely, and the docker socket is passed through at an IDENTICAL path.
MOUNTS: tuple[tuple[Path, Path], ...] = (
    (Path("/var/run/docker.sock"), Path("/var/run/docker.sock")),
    (Path("/workspace"), Path("/home/dev/projects/repo")),
    (Path("/root/.claude"), Path("/home/dev/.claude")),
)


# --------------------------------------------------------------------------- #
# C46 — source translation
# --------------------------------------------------------------------------- #
def test_a_nested_path_is_rewritten_through_its_covering_mount():
    assert _daemon_source(Path("/workspace/defender"), MOUNTS) == Path(
        "/home/dev/projects/repo/defender"
    )


def test_the_mount_point_itself_translates():
    assert _daemon_source(Path("/workspace"), MOUNTS) == Path("/home/dev/projects/repo")


def test_a_pass_through_mount_translates_to_itself():
    """Identity is a legitimate MAPPING here, not a missing one — the socket is bind-mounted
    at the same path on both sides, so `_covered` must still report it as covered."""
    p = Path("/var/run/docker.sock")
    assert _covered(p, MOUNTS) and _daemon_source(p, MOUNTS) == p


def test_no_mounts_is_the_identity_so_a_native_daemon_is_unchanged():
    """The native case must be byte-identical to pre-fix behavior: no mount table discovered
    (not in a container, or the daemon could not be asked) => no rewriting at all."""
    for p in ("/tmp/defender-runs/r1", "/workspace/defender", "/etc"):
        assert _daemon_source(Path(p), ()) == Path(p)


def test_an_uncovered_path_is_left_alone_by_the_pure_helper():
    """`_daemon_source` stays total; refusing an uncovered path is the CALLER's job, so the
    two argv builders can raise one message that names the shared mounts."""
    assert _daemon_source(Path("/tmp/defender-runs/r1"), MOUNTS) == Path("/tmp/defender-runs/r1")
    assert not _covered(Path("/tmp/defender-runs/r1"), MOUNTS)


def test_create_argv_translates_the_source_and_keeps_the_target_canonical():
    """The load-bearing assertion. source= must be the DAEMON's path; target=, --workdir and
    the env must stay the path this process (and every downstream reader) uses."""
    argv = _create_argv(
        "defender-run-r1", Path("/workspace/.defender-runs/r1"), Path("/workspace/defender"),
        BoxSpec(), MOUNTS,
    )
    joined = " ".join(argv)
    assert (
        "type=bind,source=/home/dev/projects/repo/.defender-runs/r1,"
        "target=/workspace/.defender-runs/r1" in joined
    )
    assert (
        "type=bind,source=/home/dev/projects/repo/defender,"
        "target=/workspace/defender,readonly" in joined
    )
    # The in-isolate geography is untouched — this is what artifacts record.
    assert argv[argv.index("--workdir") + 1] == "/workspace/.defender-runs/r1"
    assert "/home/dev/projects/repo" not in joined.split("--workdir")[1]


def test_create_argv_is_untouched_when_there_is_no_mount_table():
    argv = _create_argv(
        "defender-run-r1", Path("/tmp/defender-runs/r1"), Path("/srv/defender"), BoxSpec(), (),
    )
    joined = " ".join(argv)
    assert "type=bind,source=/tmp/defender-runs/r1,target=/tmp/defender-runs/r1" in joined
    assert "type=bind,source=/srv/defender,target=/srv/defender,readonly" in joined


def test_create_argv_refuses_a_run_dir_off_every_shared_mount():
    """The pre-fix failure surfaced as docker's "bind source path does not exist", which reads
    like a bug rather than a topology mismatch — and sends the operator to
    DEFENDER_ALLOW_UNSANDBOXED, trading away the boundary O10 exists to guarantee."""
    with pytest.raises(BoxFault) as e:
        _create_argv(
            "defender-run-r1", Path("/tmp/defender-runs/r1"), Path("/workspace/defender"),
            BoxSpec(), MOUNTS,
        )
    assert "C46" in str(e.value)
    assert "/workspace" in str(e.value)


def test_render_argv_translates_request_mounts_too():
    """The BoxRequest path (the learning loop's run-cycle + drain boxes) had the identical
    defect; fixing only `_create_argv` would leave the loop broken under DooD."""
    from defender.runtime.box import BoxRequest, Mount

    request = BoxRequest(
        name="defender-runcycle-r1",
        mounts=(
            Mount(source=Path("/workspace/defender/learning"), target=Path("/workspace/defender/learning"), writable=True),
            Mount(source=Path("/workspace/defender/lessons"), target=Path("/workspace/defender/lessons")),
        ),
        workdir=Path("/workspace"),
    )
    joined = " ".join(_render_argv(request, MOUNTS))
    assert (
        "type=bind,source=/home/dev/projects/repo/defender/learning,"
        "target=/workspace/defender/learning" in joined
    )
    assert (
        "type=bind,source=/home/dev/projects/repo/defender/lessons,"
        "target=/workspace/defender/lessons,readonly" in joined
    )


def test_render_argv_refuses_an_uncovered_request_mount():
    from defender.runtime.box import BoxRequest, Mount

    request = BoxRequest(
        name="defender-runcycle-r1",
        mounts=(Mount(source=Path("/srv/elsewhere"), target=Path("/srv/elsewhere")),),
        workdir=Path("/workspace"),
    )
    with pytest.raises(BoxFault) as e:
        _render_argv(request, MOUNTS)
    assert "C46" in str(e.value)


# --------------------------------------------------------------------------- #
# F1 — the runtime lever, exercised at BOTH settings (intent_540 §542)
# --------------------------------------------------------------------------- #
class _CapturingDocker:
    """Minimal `docker=` seam: reports no live container, fails create so `start_box` raises
    before any sentinel work, and hands back an empty mount table."""

    def __init__(self):
        self.create_argv: list[str] | None = None

    def __call__(self, argv, **_kw) -> subprocess.CompletedProcess:
        if argv[:2] == ["docker", "run"]:
            self.create_argv = argv
            return subprocess.CompletedProcess(argv, 1, "", "create refused by the fake")
        return subprocess.CompletedProcess(argv, 0, "", "")


def _runtime_of(monkeypatch, value: str | None) -> str:
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    if value is None:
        monkeypatch.delenv(BoxSpec.ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(BoxSpec.ENV_VAR, value)
    rec = _CapturingDocker()
    with pytest.raises(BoxFault):
        start_box(Path("/tmp/defender-runs/r1"), Path("/srv/defender"), docker=rec)
    assert rec.create_argv is not None
    return rec.create_argv[rec.create_argv.index("--runtime") + 1]


def test_runtime_lever_defaults_to_runsc_when_unset(monkeypatch):
    """The default is ANCHORED, not env-derived: runc is the weaker isolation tier and must
    never be reached by fallback."""
    assert _runtime_of(monkeypatch, None) == "runsc"


def test_runtime_lever_honours_an_explicit_runc(monkeypatch):
    """Pre-fix this returned runsc — `from_env` existed but nothing called it, so the RSD's
    "ships on whatever the host supports" could not actually be exercised."""
    assert _runtime_of(monkeypatch, "runc") == "runc"


def test_runtime_lever_rejects_an_unknown_runtime(monkeypatch):
    monkeypatch.setenv(BoxSpec.ENV_VAR, "gvisor")
    with pytest.raises(ValueError, match="not a known box runtime"):
        BoxSpec.from_env({BoxSpec.ENV_VAR: "gvisor"})
