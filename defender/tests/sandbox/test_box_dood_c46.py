"""C46 — the box's bind sources under docker-outside-of-Docker, and F1's runtime lever."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from defender import box as box_mod
from defender.box import (
    BoxSpec,
    _covered,
    _create_argv,
    _run_lane_mounts,
    _daemon_source,
    _render_argv,
    start_box,
)
from defender.execution.box_codec import BoxFault


@pytest.fixture(autouse=True)
def _input_dir_not_under_test(monkeypatch):
    """The run dirs here do not exist (mount translation is the subject), so the input-directory check is stubbed out."""
    from defender.box import _lifecycle

    monkeypatch.setattr(  # lint-monkeypatch: ok — the input-directory check has its own tests
        _lifecycle, "_input_dir_source", lambda run_dir: Path(run_dir) / "alert_input")

# The shape `docker inspect <self>` returns in a devcontainer: the workspace is bind-mounted
# from somewhere else entirely, and the docker socket is passed through at an IDENTICAL path.
MOUNTS: tuple[tuple[Path, Path], ...] = (
    (Path("/var/run/docker.sock"), Path("/var/run/docker.sock")),
    (Path("/workspace"), Path("/home/dev/projects/repo")),
    (Path("/root/.claude"), Path("/home/dev/.claude")),
)

#: The real tree, for the env-lever tests below: they cannot pin a `spec=`, so the rootfs
#: resolves from the mounted tree (#1092).
REPO_ROOT = Path(__file__).resolve().parents[3]

#: A stock image for the fake trees, which lack the image inputs. Refusal sites keep `BoxSpec()`:
#: C46 refuses before the image resolver runs.
PINNED = BoxSpec(rootfs="python:3.11-slim")


# C46 — source translation
def test_a_nested_path_is_rewritten_through_its_covering_mount():
    assert _daemon_source(Path("/workspace/defender"), MOUNTS) == Path(
        "/home/dev/projects/repo/defender"
    )


def test_the_mount_point_itself_translates():
    assert _daemon_source(Path("/workspace"), MOUNTS) == Path("/home/dev/projects/repo")


def test_a_pass_through_mount_translates_to_itself():
    """Identity is a real mapping here (the socket is bind-mounted at the same path), so it counts as covered."""
    p = Path("/var/run/docker.sock")
    assert _covered(p, MOUNTS)
    assert _daemon_source(p, MOUNTS) == p


def test_no_mounts_is_the_identity_so_a_native_daemon_is_unchanged():
    """No mount table (off-container, or the daemon could not be asked) means no rewriting at all."""
    for p in ("/tmp/defender-runs/r1", "/workspace/defender", "/etc"):
        assert _daemon_source(Path(p), ()) == Path(p)


def test_an_uncovered_path_is_left_alone_by_the_pure_helper():
    """`_daemon_source` stays total; refusing is the callers' job, so both argv builders raise one message."""
    assert _daemon_source(Path("/tmp/defender-runs/r1"), MOUNTS) == Path("/tmp/defender-runs/r1")
    assert not _covered(Path("/tmp/defender-runs/r1"), MOUNTS)


def test_create_argv_translates_the_source_and_keeps_the_target_canonical():
    """`source=` is the daemon's path; `target=` and `--workdir` stay the box's fixed paths."""
    argv = _create_argv("defender-run-r1", Path("/workspace/.defender-runs/r1"), Path("/workspace/defender"), PINNED, MOUNTS, lane=_run_lane_mounts(Path("/workspace/.defender-runs/r1"), Path("/workspace/defender"), None)).argv
    joined = " ".join(argv)
    assert (
        "type=bind,source=/home/dev/projects/repo/.defender-runs/r1,"
        "target=/runs/current" in joined
    )
    assert (
        "type=bind,source=/home/dev/projects/repo/defender,"
        "target=/defender,readonly" in joined
    )
    assert argv[argv.index("--workdir") + 1] == "/runs/current"
    # Neither namespace's host path follows the sources: not the daemon's, not this process's.
    after_mounts = joined.split("--workdir")[1]
    assert "/home/dev/projects/repo" not in after_mounts
    assert "/workspace" not in after_mounts


def test_create_argv_is_untouched_when_there_is_no_mount_table():
    argv = _create_argv("defender-run-r1", Path("/tmp/defender-runs/r1"), Path("/srv/defender"), PINNED, (), lane=_run_lane_mounts(Path("/tmp/defender-runs/r1"), Path("/srv/defender"), None)).argv
    joined = " ".join(argv)
    # No table, no translation of the source; the target is the model view's fixed path.
    assert "type=bind,source=/tmp/defender-runs/r1,target=/runs/current" in joined
    assert "type=bind,source=/srv/defender,target=/defender,readonly" in joined


def test_create_argv_refuses_a_run_dir_off_every_shared_mount():
    """A C46 refusal naming the shared mounts, not docker's misleading "bind source path does not exist"."""
    with pytest.raises(BoxFault) as e:
        _create_argv("defender-run-r1", Path("/tmp/defender-runs/r1"), Path("/workspace/defender"), BoxSpec(), MOUNTS, lane=_run_lane_mounts(Path("/tmp/defender-runs/r1"), Path("/workspace/defender"), None))
    assert "C46" in str(e.value)
    assert "/workspace" in str(e.value)


def test_render_argv_translates_request_mounts_too():
    from defender.box import BoxRequest, Mount

    request = BoxRequest(
        name="defender-runcycle-r1",
        mounts=(
            Mount(source=Path("/workspace/defender/learning"), target=Path("/workspace/defender/learning"), writable=True),
            Mount(source=Path("/workspace/defender/lessons"), target=Path("/workspace/defender/lessons"),
                  kind="data"),
        ),
        workdir=Path("/workspace"),
        spec=PINNED,
    )
    joined = " ".join(_render_argv(request, MOUNTS).argv)
    assert (
        "type=bind,source=/home/dev/projects/repo/defender/learning,"
        "target=/workspace/defender/learning" in joined
    )
    assert (
        "type=bind,source=/home/dev/projects/repo/defender/lessons,"
        "target=/workspace/defender/lessons,readonly" in joined
    )


def test_render_argv_refuses_an_uncovered_request_mount():
    from defender.box import BoxRequest, Mount

    request = BoxRequest(
        name="defender-runcycle-r1",
        mounts=(Mount(source=Path("/srv/elsewhere"), target=Path("/srv/elsewhere"), kind="data"),),
        workdir=Path("/workspace"),
    )
    with pytest.raises(BoxFault) as e:
        _render_argv(request, MOUNTS)
    assert "C46" in str(e.value)


def test_a_traversal_path_cannot_smuggle_a_source_off_the_shared_mount():
    """`PurePath` keeps `..`, so `/workspace/../etc` has `/workspace` as a parent and, un-normalized, looks covered."""
    escape = Path("/workspace/../etc/shadow")
    assert not _covered(escape, MOUNTS)
    assert _daemon_source(escape, MOUNTS) == escape


def test_a_normalized_traversal_that_stays_inside_still_translates():
    assert _daemon_source(Path("/workspace/defender/../defender/bin"), MOUNTS) == Path(
        "/home/dev/projects/repo/defender/bin"
    )


def test_create_argv_refuses_a_traversal_run_dir():
    """The builder emits `source=`, so it must refuse the traversal itself, not just see it reported uncovered."""
    with pytest.raises(BoxFault) as e:
        _create_argv("defender-run-r1", Path("/workspace/../etc/runs/r1"), Path("/workspace/defender"), BoxSpec(), MOUNTS, lane=_run_lane_mounts(Path("/workspace/../etc/runs/r1"), Path("/workspace/defender"), None))
    assert "C46" in str(e.value)


def test_render_argv_refuses_a_traversal_mount_source():
    """`_render_argv` checks each mount source on its own, so it needs the same refusal as `_create_argv`."""
    from defender.box import BoxRequest, Mount

    request = BoxRequest(
        name="defender-runcycle-r1",
        mounts=(Mount(source=Path("/workspace/../etc"), target=Path("/etc"), kind="data"),),
        workdir=Path("/workspace"),
    )
    with pytest.raises(BoxFault) as e:
        _render_argv(request, MOUNTS)
    assert "C46" in str(e.value)


def test_a_nested_mount_wins_over_the_parent_that_also_contains_the_path():
    """The outer mount would give a path that exists on the daemon: a wrong bind, not a failed one."""
    nested = (
        (Path("/workspace/vendor"), Path("/mnt/vendor")),
        (Path("/workspace"), Path("/home/dev/projects/repo")),
    )
    assert _daemon_source(Path("/workspace/vendor/lib"), nested) == Path("/mnt/vendor/lib")
    assert _daemon_source(Path("/workspace/defender"), nested) == Path(
        "/home/dev/projects/repo/defender"
    )


# C46 — discovering THIS container's mount table (the half that runs in production)
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
    """The sourceless (tmpfs) row is dropped: with no host path to bind, it must not cover anything."""
    assert box_mod._own_container_mounts(_InspectDocker("abc", _TABLE), ["abc"]) == (
        (Path("/workspace/x"), Path("/mnt/x")),
        (Path("/workspace"), Path("/home/dev/repo")),
    )


def test_a_renamed_host_falls_back_to_the_id_from_proc():
    """`--hostname`, compose and Kubernetes override /etc/hostname; without the mountinfo id the table is empty."""
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
    """A `UnicodeDecodeError` is a `ValueError`, not an `OSError`, so it would escape `start_box` (#589)."""
    (tmp_path / "hostname").write_bytes(b"\xff\xfe not utf-8")
    (tmp_path / "mountinfo").write_text("no container id here", encoding="utf-8")
    assert box_mod._own_container_ids(tmp_path / "hostname", tmp_path / "mountinfo") == ()


def test_absent_id_sources_off_a_container_are_not_an_error(tmp_path):
    assert box_mod._own_container_ids(tmp_path / "nope", tmp_path / "also-nope") == ()


# F1 — the runtime lever, exercised at both settings
class _CapturingDocker:
    """Minimal `docker=` seam: inspect finds nothing, create fails, so `start_box` raises after capturing the argv."""

    def __init__(self):
        self.create_argv: list[str] | None = None

    def __call__(self, argv, **_kw) -> subprocess.CompletedProcess:
        if argv[:2] == ["docker", "run"]:
            self.create_argv = argv
            return subprocess.CompletedProcess(argv, 1, "", "create refused by the fake")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 1, "", "No such object\n")
        return subprocess.CompletedProcess(argv, 0, "", "")


def _runtime_of(monkeypatch, value: str | None) -> str:
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    if value is None:
        monkeypatch.delenv(BoxSpec.ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(BoxSpec.ENV_VAR, value)
    rec = _CapturingDocker()
    with pytest.raises(BoxFault):
        start_box(Path("/tmp/defender-runs/r1"), REPO_ROOT / "defender", docker=rec)
    assert rec.create_argv is not None
    return rec.create_argv[rec.create_argv.index("--runtime") + 1]


def test_runtime_lever_defaults_to_runsc_when_unset(monkeypatch):
    """The default is anchored, not env-derived: runc, the weaker tier, is never reached by fallback."""
    assert _runtime_of(monkeypatch, None) == "runsc"


def test_runtime_lever_honours_an_explicit_runc(monkeypatch):
    assert _runtime_of(monkeypatch, "runc") == "runc"


def test_runtime_lever_rejects_an_unknown_runtime(monkeypatch):
    """Through `start_box`, not just `from_env`: a typo'd lever fails loudly instead of falling back to a tier."""
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.setenv(BoxSpec.ENV_VAR, "gvisor")
    with pytest.raises(ValueError, match="not a known box runtime"):
        start_box(Path("/tmp/defender-runs/r1"), Path("/srv/defender"), docker=_CapturingDocker())


def test_a_typoed_lever_does_not_break_the_request_path_that_ignores_it(monkeypatch):
    """`start_box(request)` ignores `spec=`, so a typo must not raise there: a `ValueError` dead-letters case after case."""
    from defender.box import BoxRequest

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    # The request's own spec factory is under test; its rootfs resolves from `workdir / "defender"`.
    request = BoxRequest(name="defender-runcycle-r1", workdir=REPO_ROOT)
    monkeypatch.setenv(BoxSpec.ENV_VAR, "gvisor")  # AFTER the request is built
    with pytest.raises(BoxFault):  # the create fault, not a ValueError
        start_box(request, docker=_CapturingDocker())


def test_the_discovered_table_reaches_the_run_dir_create_argv(tmp_path):
    workspace = tmp_path / "workspace"
    run_dir = workspace / ".defender-runs" / "r1"
    run_dir.mkdir(parents=True)
    defender_dir = workspace / "defender"
    defender_dir.mkdir()
    mounts = ((workspace, Path("/home/dev/projects/repo")),)
    rec = _CapturingDocker()
    with pytest.raises(BoxFault):  # the fake refuses create; the argv is already captured
        box_mod._start_boxed(
            run_dir, defender_dir, PINNED, rec, lambda _docker: mounts,
        )
    joined = " ".join(rec.create_argv or [])
    # Targets are the model view's fixed paths; the sources carry the translation.
    assert (
        "type=bind,source=/home/dev/projects/repo/.defender-runs/r1,"
        "target=/runs/current" in joined
    )
    assert (
        "type=bind,source=/home/dev/projects/repo/defender,"
        "target=/defender,readonly" in joined
    )


def test_the_discovered_table_reaches_the_request_render_argv():
    from defender.box import BoxRequest, Mount

    rec = _CapturingDocker()
    request = BoxRequest(
        name="defender-runcycle-r1",
        mounts=(Mount(source=Path("/workspace/defender/lessons"),
                      target=Path("/workspace/defender/lessons"), kind="data"),),
        workdir=Path("/workspace"),
        spec=PINNED,
    )
    with pytest.raises(BoxFault):
        box_mod._start_boxed_request(request, rec, lambda _docker: MOUNTS)
    assert (
        "type=bind,source=/home/dev/projects/repo/defender/lessons,"
        "target=/workspace/defender/lessons,readonly" in " ".join(rec.create_argv or [])
    )


def test_an_uncovered_run_dir_is_refused_before_any_container_is_created():
    """The refusal fires while building the argv; a check after `docker run` would leave a box behind."""
    rec = _CapturingDocker()
    with pytest.raises(BoxFault, match="C46"):
        box_mod._start_boxed(
            Path("/tmp/defender-runs/r1"), Path("/workspace/defender"),
            BoxSpec(), rec, lambda _docker: MOUNTS,
        )
    assert rec.create_argv is None, "a container was created despite the refusal"


def test_the_discovery_seam_degrades_to_the_identity_when_no_id_resolves():
    """No known id yields the empty (native) table, never a raise: this runs on bare CI runners and in devcontainers."""
    unknown = _InspectDocker("no-such-container-id", _TABLE)
    assert box_mod._shared_mounts(unknown) == ()
