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

from defender.runtime import box as box_mod
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
    assert _covered(p, MOUNTS)
    assert _daemon_source(p, MOUNTS) == p


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


def test_a_traversal_path_cannot_smuggle_a_source_off_the_shared_mount():
    """`PurePath` does not collapse `..`, so `/workspace/../etc` lists `/workspace` among its
    parents. Un-normalized, that passes the coverage check AND translates to a daemon path
    outside the shared tree — the exact bind the check exists to refuse."""
    escape = Path("/workspace/../etc/shadow")
    assert not _covered(escape, MOUNTS)
    assert _daemon_source(escape, MOUNTS) == escape


def test_a_normalized_traversal_that_stays_inside_still_translates():
    assert _daemon_source(Path("/workspace/defender/../defender/bin"), MOUNTS) == Path(
        "/home/dev/projects/repo/defender/bin"
    )


def test_create_argv_refuses_a_traversal_run_dir():
    """The traversal has to be refused by the ARGV BUILDER, not merely reported uncovered by
    the pure helper: the builder is what emits `source=`, so a `..` that slipped past it
    would bind a host tree outside the shared mount rw into the box."""
    with pytest.raises(BoxFault) as e:
        _create_argv(
            "defender-run-r1", Path("/workspace/../etc/runs/r1"), Path("/workspace/defender"),
            BoxSpec(), MOUNTS,
        )
    assert "C46" in str(e.value)


def test_render_argv_refuses_a_traversal_mount_source():
    """Same for the request builder — `_render_argv` checks each mount source separately, so
    fixing only `_create_argv` would leave the learning loop's boxes translating an escape."""
    from defender.runtime.box import BoxRequest, Mount

    request = BoxRequest(
        name="defender-runcycle-r1",
        mounts=(Mount(source=Path("/workspace/../etc"), target=Path("/etc")),),
        workdir=Path("/workspace"),
    )
    with pytest.raises(BoxFault) as e:
        _render_argv(request, MOUNTS)
    assert "C46" in str(e.value)


def test_a_nested_mount_wins_over_the_parent_that_also_contains_the_path():
    """`_own_container_mounts` sorts longest-destination-first precisely so this resolves to
    the INNER mount. Picking the outer one would translate through the wrong source and
    produce a path that exists on the daemon — a wrong bind, not a failed one."""
    nested = (
        (Path("/workspace/vendor"), Path("/mnt/vendor")),
        (Path("/workspace"), Path("/home/dev/projects/repo")),
    )
    assert _daemon_source(Path("/workspace/vendor/lib"), nested) == Path("/mnt/vendor/lib")
    assert _daemon_source(Path("/workspace/defender"), nested) == Path(
        "/home/dev/projects/repo/defender"
    )


def test_the_refusal_names_the_knob_that_actually_moves_the_uncovered_path():
    """DEFENDER_RUNS_BASE relocates the RUN dir and nothing else. Naming it for an uncovered
    defender dir sends the operator at a knob that cannot help — and legibility is the entire
    purpose of this error path."""
    with pytest.raises(BoxFault) as e:
        _create_argv(
            "defender-run-r1", Path("/workspace/.defender-runs/r1"), Path("/srv/defender"),
            BoxSpec(), MOUNTS,
        )
    message = str(e.value)
    assert "defender dir /srv/defender" in message
    assert "DEFENDER_RUNS_BASE" not in message, (
        "the run-dir knob was offered for an uncovered defender dir"
    )


# --------------------------------------------------------------------------- #
# C46 — discovering THIS container's mount table (the half that runs in production)
# --------------------------------------------------------------------------- #
class _InspectDocker:
    """Answers `docker inspect <id>` for one known id and fails for every other."""

    def __init__(self, known: str, stdout: str):
        self.known, self.stdout = known, stdout
        self.asked: list[str] = []

    def __call__(self, argv, **_kw) -> subprocess.CompletedProcess:
        self.asked.append(argv[2])
        if argv[2] == self.known:
            return subprocess.CompletedProcess(argv, 0, self.stdout, "")
        return subprocess.CompletedProcess(argv, 1, "", "No such object\n")


_TABLE = "/workspace\t/home/dev/repo\n/workspace/x\t/mnt/x\n/tmp/s.sock\t\n\n"


def test_the_mount_table_parses_and_sorts_longest_destination_first():
    assert box_mod._own_container_mounts(_InspectDocker("abc", _TABLE), ["abc"]) == (
        (Path("/workspace/x"), Path("/mnt/x")),
        (Path("/workspace"), Path("/home/dev/repo")),
    )


def test_a_sourceless_mount_row_is_skipped():
    """tmpfs mounts appear in `.Mounts` with an EMPTY source — there is no host path to
    bind, so a row like that must not become a covering mount."""
    table = box_mod._own_container_mounts(_InspectDocker("abc", _TABLE), ["abc"])
    assert Path("/tmp/s.sock") not in [d for d, _ in table]


def test_a_renamed_host_falls_back_to_the_id_from_proc():
    """`--hostname`, compose, and Kubernetes all override /etc/hostname. Without the
    /proc/self/mountinfo fallback the inspect fails, the table comes back empty, and C46
    silently reverts to docker's illegible 'bind source path does not exist'."""
    cid = "a" * 64
    rec = _InspectDocker(cid, _TABLE)
    assert box_mod._own_container_mounts(rec, ["my-service", cid])
    assert rec.asked == ["my-service", cid], "the renamed host must be tried first, then the id"


def test_no_candidate_id_means_the_identity_not_a_crash():
    assert box_mod._own_container_mounts(_InspectDocker("abc", _TABLE), []) == ()


def test_the_proc_id_is_recovered_when_the_hostname_is_a_service_name(tmp_path):
    (tmp_path / "hostname").write_text("my-service\n", encoding="utf-8")
    (tmp_path / "mountinfo").write_text(
        f"896 res /var/lib/docker/containers/{'a' * 64}/hosts rw\n", encoding="utf-8",
    )
    assert box_mod._own_container_ids(tmp_path / "hostname", tmp_path / "mountinfo") == (
        "my-service", "a" * 64,
    )


def test_an_undecodable_hostname_is_skipped_rather_than_raising(tmp_path):
    """#589: a UnicodeDecodeError is a ValueError, NOT an OSError. Guarding the read with
    `except OSError` would let it escape start_box uncaught — past `_opt_out_or_raise` and
    past core/faults.py's SYSTEMIC_FAULTS."""
    (tmp_path / "hostname").write_bytes(b"\xff\xfe not utf-8")
    (tmp_path / "mountinfo").write_text("no container id here", encoding="utf-8")
    assert box_mod._own_container_ids(tmp_path / "hostname", tmp_path / "mountinfo") == ()


def test_absent_id_sources_off_a_container_are_not_an_error(tmp_path):
    assert box_mod._own_container_ids(tmp_path / "nope", tmp_path / "also-nope") == ()


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
    """Through `start_box`, not just `from_env`: the wiring is the thing under test, and a
    typo'd lever must fail LOUDLY rather than fall back to a tier nobody asked for."""
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.setenv(BoxSpec.ENV_VAR, "gvisor")
    with pytest.raises(ValueError, match="not a known box runtime"):
        start_box(Path("/tmp/defender-runs/r1"), Path("/srv/defender"), docker=_CapturingDocker())


def test_a_typoed_lever_does_not_break_the_request_path_that_ignores_it(monkeypatch):
    """`start_box(request)` never uses the `spec=` parameter — a BoxRequest carries its own.
    Resolving the env there anyway would raise ValueError out of a call that has no use for
    it, and ValueError is in neither `_opt_out_or_raise` nor SYSTEMIC_FAULTS, so a global
    typo would dead-letter case after case instead of aborting."""
    from defender.runtime.box import BoxRequest

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    request = BoxRequest(name="defender-runcycle-r1", workdir=Path("/workspace"))
    monkeypatch.setenv(BoxSpec.ENV_VAR, "gvisor")  # AFTER the request is built
    with pytest.raises(BoxFault):  # the create fault, not a ValueError
        start_box(request, docker=_CapturingDocker())


def _request_runtime_of(monkeypatch, value: str | None) -> str:
    """The lever as reached through a BoxRequest — the learning run-cycle's and the curator
    drains' only entry point. `start_box` resolves the env only for its run_dir overload; a
    request carries its own spec, so the default_factory is what has to read the lever."""
    from defender.runtime.box import BoxRequest

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    if value is None:
        monkeypatch.delenv(BoxSpec.ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(BoxSpec.ENV_VAR, value)
    rec = _CapturingDocker()
    request = BoxRequest(name="defender-runcycle-r1", workdir=Path("/workspace"))
    with pytest.raises(BoxFault):
        start_box(request, docker=rec)
    assert rec.create_argv is not None
    return rec.create_argv[rec.create_argv.index("--runtime") + 1]


def test_request_runtime_lever_defaults_to_runsc_when_unset(monkeypatch):
    assert _request_runtime_of(monkeypatch, None) == "runsc"


def test_request_runtime_lever_honours_an_explicit_runc(monkeypatch):
    """Pre-fix this returned runsc: `BoxRequest.spec` defaulted to a bare `BoxSpec()`, so
    every boxed LEARN cycle demanded gVisor no matter what the operator set."""
    assert _request_runtime_of(monkeypatch, "runc") == "runc"


# --------------------------------------------------------------------------- #
# C46 — the wiring: the discovered table must actually REACH the argv builders
# --------------------------------------------------------------------------- #
# Every translation test above calls the argv builders directly with a table handed in. That
# leaves the connection between discovery and use unpinned: drop the mounts argument at
# either call site and all of them stay green while the shipped code emits untranslated
# sources again — the exact pre-fix defect. These drive the start paths instead.


def test_the_discovered_table_reaches_the_run_dir_create_argv():
    rec = _CapturingDocker()
    with pytest.raises(BoxFault):  # the fake refuses create; the argv is already captured
        box_mod._start_boxed(
            Path("/workspace/.defender-runs/r1"), Path("/workspace/defender"),
            BoxSpec(), rec, lambda _docker: MOUNTS,
        )
    joined = " ".join(rec.create_argv or [])
    assert (
        "type=bind,source=/home/dev/projects/repo/.defender-runs/r1,"
        "target=/workspace/.defender-runs/r1" in joined
    )
    assert (
        "type=bind,source=/home/dev/projects/repo/defender,"
        "target=/workspace/defender,readonly" in joined
    )


def test_the_discovered_table_reaches_the_request_render_argv():
    from defender.runtime.box import BoxRequest, Mount

    rec = _CapturingDocker()
    request = BoxRequest(
        name="defender-runcycle-r1",
        mounts=(Mount(source=Path("/workspace/defender/lessons"),
                      target=Path("/workspace/defender/lessons")),),
        workdir=Path("/workspace"),
    )
    with pytest.raises(BoxFault):
        box_mod._start_boxed_request(request, rec, lambda _docker: MOUNTS)
    assert (
        "type=bind,source=/home/dev/projects/repo/defender/lessons,"
        "target=/workspace/defender/lessons,readonly" in " ".join(rec.create_argv or [])
    )


def test_an_uncovered_run_dir_is_refused_before_any_container_is_created():
    """The refusal happens while BUILDING the argv, so nothing is created and there is no
    container to reap. A check that fired after `docker run` would leave a box behind on
    every misconfigured host."""
    rec = _CapturingDocker()
    with pytest.raises(BoxFault, match="C46"):
        box_mod._start_boxed(
            Path("/tmp/defender-runs/r1"), Path("/workspace/defender"),
            BoxSpec(), rec, lambda _docker: MOUNTS,
        )
    assert rec.create_argv is None, "a container was created despite the refusal"


def test_both_start_paths_default_to_the_real_discovery_seam():
    """The seam exists for the tests above; its DEFAULT is what production takes. A seam
    wired everywhere but defaulted to something inert would make every test here green
    against code that never discovers a mount table at all."""
    import inspect

    for fn in (box_mod._start_boxed, box_mod._start_boxed_request):
        default = inspect.signature(fn).parameters["shared_mounts"].default
        assert default is box_mod._shared_mounts, fn.__name__


def test_the_discovery_seam_degrades_to_the_identity_when_no_id_resolves():
    """`_shared_mounts` composes ids -> table. On a daemon that knows none of this process's
    candidate ids the composition must yield an empty table (the native-daemon identity),
    never raise — this runs on bare CI runners and inside devcontainers alike."""
    unknown = _InspectDocker("no-such-container-id", _TABLE)
    assert box_mod._shared_mounts(unknown) == ()
