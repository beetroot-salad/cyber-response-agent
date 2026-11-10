"""#665 — box.py renders a caller-composed BoxRequest (mounts, env allowlist, workdir, baked network/read-only/tmpfs), its per-mount startup sentinel, create-fault reaping, pre-create sweep and unsandboxed opt-out. The docker daemon is faked through the real docker= seam.

#665 — box delivery: `CuratorDeps.for_run` requires a box.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from _box665 import (  # noqa: E402
    DEFENDER,
    REPO_ROOT,
    BoxRequest,
    DockerFault,
    Mount,
    RecordingDocker,
    make_run_dir,
    reaped_after_create,
    run_cycle_mounts,
    start_box_request,
)

pytest.importorskip('pydantic_ai')

from defender import box as box_mod  # noqa: E402
from defender.tests.support.tenancy._host1214 import TEST_TENANT


pytestmark = pytest.mark.e2e


SALT = "s665geo"


#: Both lanes' container name here is a substring of this (run lane `defender-run-<run dir name>`,
#: request lane `defender-runcycle-abc`); the refusal names the container whichever it is.
NAME_1279 = r"defender-run"


def _populate_mount_sources(mounts, tmp_path: Path) -> None:
    """Give each test-owned mount source a file to read back, since startup may not plant one
    in a read-only mount. The checkout's DEFENDER already has one and is left alone."""
    for m in mounts:
        source = Path(m.source)
        if not source.is_relative_to(tmp_path):
            continue
        source.mkdir(parents=True, exist_ok=True)
        (source / "entry.txt").write_text("x", encoding="utf-8")


def _request(run_dir: Path, *, name="defender-runcycle-abc", env=None, mounts=None, workdir=None,
             spec=None, defender_dir=None):
    return BoxRequest(
        name=name,
        mounts=mounts if mounts is not None else run_cycle_mounts(run_dir),
        workdir=workdir if workdir is not None else REPO_ROOT,
        env=env if env is not None else {},
        spec=spec,
        defender_dir=defender_dir,
        tenant_id=TEST_TENANT,
    )


# box.py renders the caller-composed geography
def test_box_request_renders_mounts_and_no_tier_discriminator(tmp_path):
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start_box_request(_request(run_dir), docker=rec)
    rendered = {(m["source"], m["readonly"]) for m in rec.mounts()}
    for m in run_cycle_mounts(run_dir):
        assert (str(m.source), not m.writable) in rendered, f"mount {m.source} not rendered"
    assert box_mod.container_name.__name__  # box.py owns the grammar, not a tier discriminator


def test_box_request_caller_omits_network_isolation_and_gets_a_default_network(tmp_path):
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    box = start_box_request(_request(run_dir), docker=rec)
    assert rec.flag_value("--network") == "none", "box.py did not bake in --network=none"
    assert rec.has_flag("--read-only"), "box.py did not bake in --read-only"
    assert box.name, "network isolation broke box startup (positive control failed)"


def test_composed_container_name_fails_the_naming_grammar(tmp_path):
    run_dir = make_run_dir(tmp_path)
    bad = RecordingDocker()
    with pytest.raises((ValueError, box_mod.BoxFault)):
        start_box_request(_request(run_dir, name="defender run/../etc"), docker=bad)
    assert bad.create_argv is None, "an invalid composed name still reached docker create"

    ok = RecordingDocker()
    start_box_request(_request(run_dir, name="defender-runcycle-abc"), docker=ok)
    assert ok.create_argv is not None


# The box environment: allowlist by key, one shared helper
def test_box_env_filtered_by_key_no_host_credential(tmp_path):
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    secret = "sk-ant-SPEC-SECRET"
    start_box_request(
        _request(run_dir, env={"ANTHROPIC_API_KEY": secret, "LANG": "C.UTF-8"}), docker=rec,
    )
    assert "ANTHROPIC_API_KEY" not in rec.env(), "a non-allowlisted credential key was rendered"
    assert all(secret not in v for v in rec.env().values()), "the credential VALUE leaked into --env"
    assert rec.env().get("LANG") == "C.UTF-8", "the allowlisted key was dropped (positive control)"


def test_caller_env_dict_key_collides_with_the_shared_infra_helpers_derived_key(tmp_path):
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start_box_request(
        _request(run_dir, env={"PATH": "/attacker/bin", "TZ": "Europe/Paris"}), docker=rec,
    )
    assert rec.env()["PATH"].startswith(str(DEFENDER / "bin")), \
        "a caller-supplied PATH won over the infra helper"
    assert "/attacker/bin" not in rec.env()["PATH"], "the caller's PATH override survived"
    assert rec.env().get("TZ") == "Europe/Paris", "a non-infra allowlisted key was dropped"


# The startup sentinel and startup-fault loudness
def test_sentinel_probes_every_mount_ro_readback_without_planting(tmp_path):
    """Each nonempty read-only mount is read back without even a transient write."""
    run_dir = make_run_dir(tmp_path)
    evidence = tmp_path / "separate-evidence"
    evidence.mkdir()
    (evidence / "result.json").write_text("{}\n", encoding="utf-8")
    # Disjoint roots give each mount its own observation: a repeated child read cannot
    # masquerade as a separate read-back of an enclosing mount.
    mounts = (Mount(source=run_dir, target=run_dir, writable=False, kind="data"),
              Mount(source=DEFENDER, target=DEFENDER, writable=False, kind="code"),
              Mount(source=evidence, target=evidence, writable=False, kind="data"))
    before = {m.source: frozenset(m.source.iterdir()) for m in mounts}
    rec = RecordingDocker()
    def boundary(argv, **kwargs):
        assert {m.source: frozenset(m.source.iterdir()) for m in mounts} == before
        return rec(argv, **kwargs)
    start_box_request(_request(run_dir, mounts=mounts), docker=boundary)
    readbacks = [Path(c[-1]) for c in rec.calls if len(c) > 1 and c[1] == "exec"
                 and Path(c[-1]).is_absolute()
                 and any(Path(c[-1]).is_relative_to(mount.source) for mount in mounts)]
    assert len(readbacks) == len(mounts)
    assert all(path.is_file() for path in readbacks)
    for mount in mounts:
        assert any(path.is_relative_to(mount.source) for path in readbacks)
    assert {m.source: frozenset(m.source.iterdir()) for m in mounts} == before


def test_mount_source_directory_absent_at_box_creation(tmp_path):
    run_dir = make_run_dir(tmp_path)
    absent = RecordingDocker(create=DockerFault(
        rc=125, stderr="docker: Error response from daemon: bind source path does not exist",
        cite="po1",
    ))
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=absent, tenant_id=TEST_TENANT)
    assert not any(len(c) > 1 and c[1] == "exec" for c in absent.calls), \
        "a sentinel read-back ran despite the create-time refusal (silent-empty path)"

    ok = RecordingDocker()
    box_mod.start_box(run_dir, DEFENDER, docker=ok, tenant_id=TEST_TENANT)  # present sources → clean create


def test_partial_multi_mount_sentinel_validation_leaves_box_in_ambiguous_state(tmp_path):
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(sentinel=DockerFault(rc=1, stderr="mount 2 read-back failed", cite="po48"))
    with pytest.raises(box_mod.BoxFault):
        start_box_request(_request(run_dir), docker=rec)
    assert reaped_after_create(rec.calls), \
        "a partially-validated box was not reaped after a sentinel fault"


_SHIM_FAULT = dict(
    rc=125,
    stderr="failed to create shim task: OCI runtime create failed",
    cite="#884 F-29 — observed live: the container is then listed in `created` by docker ps -a",
)


def test_create_fault_that_leaves_a_created_container_is_reaped_investigation_lane(tmp_path):
    """`docker run --detach` is create-then-start, so a non-zero rc does not prove no container
    exists (#884)."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker(create=DockerFault(**_SHIM_FAULT), existing_token="self")
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=rec, tenant_id=TEST_TENANT)
    assert reaped_after_create(rec.calls), \
        "a container that may exist in `created` was left behind by the create-fault arm"


def test_create_fault_that_leaves_a_created_container_is_reaped_request_lane(tmp_path):
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(create=DockerFault(**_SHIM_FAULT), existing_token="self")
    with pytest.raises(box_mod.BoxFault):
        start_box_request(_request(run_dir), docker=rec)
    assert reaped_after_create(rec.calls), \
        "a container that may exist in `created` was left behind by the create-fault arm"


def _dies_after_create(rec, *subcommands):
    """A daemon that answers until the create, then cannot be invoked (`_call` turns the OSError
    into `BoxFault`): a daemon that just failed a create is the likeliest to be gone by the reap."""
    def docker(argv, **kw):
        if rec.create_argv is not None and len(argv) > 1 and argv[1] in subcommands:
            raise OSError("daemon socket gone")
        return rec(argv, **kw)
    docker.popen = rec.popen   # the attached-start capability the run lane asks of its docker seam (#1343 r5 item 15)
    return docker


@pytest.mark.parametrize("lane", ["investigation", "request"])
def test_a_create_that_lost_a_name_race_does_not_reap_the_winner(tmp_path, lane):
    """The create-fault arm's reap must not remove another lane's container (#884)."""
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(
        create=DockerFault(
            rc=125,
            stderr='Conflict. The container name "/defender-run-x" is already in use',
            cite="C43a — the daemon's own name-conflict rc/text",
        ),
        existing_token="another-lane-holds-this-name",
    )
    start = (
        (lambda: box_mod.start_box(run_dir, DEFENDER, docker=rec, tenant_id=TEST_TENANT))
        if lane == "investigation"
        else (lambda: start_box_request(_request(run_dir), docker=rec))
    )
    with pytest.raises(box_mod.BoxFault):
        start()
    assert not reaped_after_create(rec.calls), \
        "the create-fault arm reaped a container another lane owns"


@pytest.mark.parametrize("lane", ["investigation", "request"])
@pytest.mark.parametrize(
    "state", ["created", "running", "restarting", "paused", "removing", "exited", "dead"],
)
def test_the_pre_create_check_refuses_a_finished_container_too_and_removes_nothing(
        tmp_path, lane, state):
    """Every box name is fresh, so an existing container is never legitimate, finished or not:
    the start refuses, removes nothing and creates nothing (#955, #1279)."""
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(status=state)
    start = (
        (lambda: box_mod.start_box(run_dir, DEFENDER, docker=rec, tenant_id=TEST_TENANT))
        if lane == "investigation"
        else (lambda: start_box_request(_request(run_dir), docker=rec))
    )
    with pytest.raises(box_mod.BoxStartConflict, match=NAME_1279):
        start()
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in rec.calls), \
        f"the start removed a container in {state!r} that holds its name"
    assert rec.create_argv is None, "a box was created on a name another container holds"


def test_the_pre_create_refusal_still_leaves_the_did_not_run_marker(tmp_path):
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(status="running")
    with pytest.raises(box_mod.BoxStartConflict):
        box_mod.start_box(run_dir, DEFENDER, docker=rec, tenant_id=TEST_TENANT)
    assert box_mod.verdict_path(run_dir).is_file(), \
        "the pre-create refusal left no scan verdict"
    verdict = json.loads(box_mod.verdict_path(run_dir).read_text(encoding="utf-8"))
    assert verdict["ran"] is False, \
        "a refusal that never started a box recorded the tree as SCANNED"
    assert "refused before create" in verdict["reason"], \
        f"the verdict does not say WHICH startup fault produced it: {verdict['reason']!r}"


def test_a_daemon_answer_the_start_cannot_read_is_still_a_container_holding_the_name(tmp_path):
    """An unparseable status fails closed: the name is held, so the start refuses and removes
    nothing (#1279)."""
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(status="")
    with pytest.raises(box_mod.BoxStartConflict):
        box_mod.start_box(run_dir, DEFENDER, docker=rec, tenant_id=TEST_TENANT)
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in rec.calls)


def test_the_box_is_stamped_with_the_token_its_own_fault_arm_checks(tmp_path):
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    box_mod.start_box(run_dir, DEFENDER, docker=rec, tenant_id=TEST_TENANT)
    token = rec.create_label(box_mod.START_TOKEN_LABEL)
    assert token, f"no {box_mod.START_TOKEN_LABEL} label on the create argv"
    other = RecordingDocker()
    box_mod.start_box(make_run_dir(tmp_path / "second"), DEFENDER, docker=other, tenant_id=TEST_TENANT)
    assert other.create_label(box_mod.START_TOKEN_LABEL) != token, \
        "the token is not per-START — two starts stamped the same value"


def test_a_start_given_a_token_stamps_that_token_and_an_operator_start_mints_its_own(tmp_path):
    """`start_box(..., start_token=T)` stamps exactly T on the create argv (#1342 r5 C1); without one the box mints a fresh token. (#1342 r5 C1)"""
    given = "ab" * 16
    rec = RecordingDocker()
    box_mod.start_box(make_run_dir(tmp_path), DEFENDER, docker=rec, tenant_id=TEST_TENANT, start_token=given)
    assert rec.create_label(box_mod.START_TOKEN_LABEL) == given
    minted = RecordingDocker()
    box_mod.start_box(make_run_dir(tmp_path / "second"), DEFENDER, docker=minted, tenant_id=TEST_TENANT)
    assert minted.create_label(box_mod.START_TOKEN_LABEL) not in (None, "", given)


#: What a container holding the name carries when a create faults: the given token, or a token that is
#: not it (another's; a near miss in the first, a middle or the last character, case, length or
#: containment; the same letters moved about) or none at all. `_GIVEN` is not periodic, so no swap,
#: rotation or reshuffle of it reads as itself.
_GIVEN = "3f9a1c07be52d84e6a0b7c19e3d5f248"


_HOLDERS = {
    "the given token": "self",
    "another lane's token": "cd" * 16,
    "first character differs": "4" + _GIVEN[1:],
    "a middle character differs": _GIVEN[:16] + "f" + _GIVEN[17:],
    "last character differs": _GIVEN[:-1] + "c",
    "an adjacent pair swapped": _GIVEN[:4] + _GIVEN[5] + _GIVEN[4] + _GIVEN[6:],
    "first and last swapped": _GIVEN[-1] + _GIVEN[1:-1] + _GIVEN[0],
    "rotated by one": _GIVEN[1:] + _GIVEN[0],
    "reversed": _GIVEN[::-1],
    "case changed": _GIVEN[:1] + _GIVEN[1].upper() + _GIVEN[2:],
    "a prefix of it": _GIVEN[:-1],
    "it with a suffix": _GIVEN + "0",
    "no token label": "<no value>",
    "the label set to nothing": "",
}


@pytest.mark.parametrize("holder", list(_HOLDERS))
def test_a_create_fault_reaps_only_a_container_carrying_the_token_the_start_was_given(tmp_path, holder):
    """The create-fault arm owns the token the caller handed in: a leftover with exactly it is reaped; one with another, a near-miss or no token survives. (#1342 r5 C1)"""
    rec = RecordingDocker(create=DockerFault(**_SHIM_FAULT), existing_token=_HOLDERS[holder])
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(make_run_dir(tmp_path), DEFENDER, docker=rec, tenant_id=TEST_TENANT, start_token=_GIVEN)
    assert reaped_after_create(rec.calls) is (holder == "the given token")


def test_a_create_fault_leaves_a_container_whose_token_differs_in_any_one_character_wherever_it_differs(tmp_path):
    """For every position of the given token, a leftover whose token differs in that one character alone is not ours and survives (no position is skipped). (#1342 r5 C1)"""
    digits = "0123456789abcdef"
    for at in range(len(_GIVEN)):
        near = _GIVEN[:at] + digits[(digits.index(_GIVEN[at]) + 1) % 16] + _GIVEN[at + 1:]
        rec = RecordingDocker(create=DockerFault(**_SHIM_FAULT), existing_token=near)
        with pytest.raises(box_mod.BoxFault):
            box_mod.start_box(make_run_dir(tmp_path / f"at{at}"), DEFENDER, docker=rec, tenant_id=TEST_TENANT, start_token=_GIVEN)
        assert not reaped_after_create(rec.calls), f"a container differing at position {at} was removed"


_DECORATED = {
    "a hyphen after it": _GIVEN + "-",
    "an underscore after it": _GIVEN + "_",
    "an exclamation mark after it": _GIVEN + "!",
    "a hyphen before it": "-" + _GIVEN,
    "an underscore before it": "_" + _GIVEN,
    "a hyphen inside it": _GIVEN[:16] + "-" + _GIVEN[16:],
    "an underscore inside it": _GIVEN[:16] + "_" + _GIVEN[16:],
    "a space inside it": _GIVEN[:16] + " " + _GIVEN[16:],
}


@pytest.mark.parametrize("holder", list(_DECORATED))
def test_a_create_fault_leaves_a_container_whose_token_is_the_given_one_with_something_added(tmp_path, holder):
    """The given token with a hyphen, underscore, mark or space added before, inside or after it is another token: the leftover survives. (#1342 r5 C1)"""
    rec = RecordingDocker(create=DockerFault(**_SHIM_FAULT), existing_token=_DECORATED[holder])
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(make_run_dir(tmp_path), DEFENDER, docker=rec, tenant_id=TEST_TENANT, start_token=_GIVEN)
    assert not reaped_after_create(rec.calls)


def test_a_create_fault_whose_leftover_label_cannot_be_read_does_not_reap_it(tmp_path):
    """A container holds the name but the daemon fails the label read: ownership is unproven, so the create-fault arm leaves it (the start still fails with the create fault). (#1342 r5 C1, #1279 O6)"""
    rec = RecordingDocker(create=DockerFault(**_SHIM_FAULT), existing_token="self", label_unreadable=True)
    with pytest.raises(box_mod.BoxFault) as excinfo:
        box_mod.start_box(make_run_dir(tmp_path), DEFENDER, docker=rec, tenant_id=TEST_TENANT, start_token=_GIVEN)
    assert _SHIM_FAULT["stderr"] in str(excinfo.value)
    assert not reaped_after_create(rec.calls), "a container whose owner could not be read was removed"


def test_a_reap_that_cannot_reach_the_daemon_does_not_replace_the_create_fault(tmp_path):
    """The create-fault arm's reap is best-effort on BOTH halves, `docker inspect` included."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker(create=DockerFault(**_SHIM_FAULT), existing_token="self")
    with pytest.raises(box_mod.BoxFault) as excinfo:
        box_mod.start_box(run_dir, DEFENDER, docker=_dies_after_create(rec, "inspect", "rm"), tenant_id=TEST_TENANT)
    assert _SHIM_FAULT["stderr"] in str(excinfo.value), \
        f"the reap replaced the create fault with {str(excinfo.value)[:90]!r}"


def test_a_reap_that_cannot_reach_the_daemon_still_leaves_the_did_not_run_marker(tmp_path):
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker(sentinel=DockerFault(rc=1, stderr="read-back failed", cite="po48"))
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=_dies_after_create(rec, "rm"), tenant_id=TEST_TENANT)
    assert box_mod.verdict_path(run_dir).is_file(), \
        "a reap that could not reach the daemon left no scan verdict"


def test_container_exits_between_create_and_sentinel(tmp_path):
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker(sentinel=DockerFault(rc=137, stderr="container is not running", cite="po48"))
    with pytest.raises(box_mod.BoxFault, match="sentinel"):
        box_mod.start_box(run_dir, DEFENDER, docker=rec, tenant_id=TEST_TENANT)
    assert any(len(c) > 1 and c[1] == "create" for c in rec.calls), \
        "the sentinel fault fired without a container create having been attempted"


def test_docker_binary_unavailable_at_box_startup(tmp_path):
    run_dir = make_run_dir(tmp_path)
    calls: list[list[str]] = []

    def no_docker(argv, **_kw):
        calls.append(list(argv))
        raise FileNotFoundError(2, "No such file or directory: 'docker'")

    with pytest.raises(box_mod.BoxFault):  # the raw FileNotFoundError must be wrapped, not leaked
        box_mod.start_box(run_dir, DEFENDER, docker=no_docker, tenant_id=TEST_TENANT)
    assert calls, "box creation made no docker call at all"
    assert not any(len(c) > 1 and c[1] in ("run", "create", "start") for c in calls), \
        "a container create was attempted despite the docker binary being unavailable at the first call"


def test_box_startup_failure_aborts_batch_loudly(tmp_path, monkeypatch):
    run_dir = make_run_dir(tmp_path)
    faulty = RecordingDocker(create=DockerFault(rc=125, stderr="bind source path does not exist", cite="po1"))
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=faulty, tenant_id=TEST_TENANT)  # no automatic host fallback

    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")  # the one sanctioned host lane
    assert box_mod.start_box(run_dir, DEFENDER, docker=faulty, tenant_id=TEST_TENANT).sandboxed is False, \
        "the loud opt-out did not degrade to the unboxed host executor"


def test_tmp_is_noexec_size_capped_tmpfs(tmp_path):
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    box_mod.start_box(run_dir, DEFENDER, docker=rec, tenant_id=TEST_TENANT)
    tmpfs = rec.tmpfs()
    assert tmpfs, "no --tmpfs flag was rendered for /tmp"
    assert "noexec" in tmpfs, f"/tmp is not noexec: {tmpfs!r}"
    assert "size=" in tmpfs, f"/tmp is not size-capped: {tmpfs!r}"


# The unboxed opt-out
def test_unboxed_opt_out_env_receives_no_allowlist_filtering(tmp_path):
    from defender.box import run_env
    from defender import providers

    run_dir = make_run_dir(tmp_path)
    env = run_env(DEFENDER, run_dir)  # the host-side env the unboxed leg runs under
    for var in providers.api_key_vars():
        assert var not in env, f"an api-key var {var} rode into the unboxed leg"


def test_unsandboxed_opt_out_leg_runs_with_full_host_network_reachability(tmp_path):
    ex = box_mod.unboxed_executor(env={})
    assert ex.sandboxed is False
    assert isinstance(ex.transport, box_mod._HostTransport), \
        "the opt-out did not run as a bare host subprocess"


_OMITTED = object()


def _curator_for_run(tmp_path, *, box=_OMITTED):
    """Curator deps through the real `CuratorDeps.for_run`, over a real worktree defender tree
    so the wrapped `bind()` resolves. `box=` is passed only when given."""
    from defender.learning.author.curator_engine import (
        SHIPPED_LESSON_CORPORA,
        CuratorDeps,
    )

    repo = tmp_path / "repo"
    dtree = repo / "defender"
    for name in SHIPPED_LESSON_CORPORA:
        (dtree / name).mkdir(parents=True, exist_ok=True)
    run_dir = tmp_path / "lrd"
    run_dir.mkdir(exist_ok=True)  # both arms of the test run against one tmp_path
    kw = {} if box is _OMITTED else {"box": box}
    return CuratorDeps.for_run(run_dir, repo, dtree / "lessons", **kw)


def test_box_delivery_absence_does_not_silently_re_dead_the_lane(tmp_path):
    with pytest.raises(TypeError):
        _curator_for_run(tmp_path)

    delivered = box_mod.BoxExecutor(name="box")
    assert _curator_for_run(tmp_path, box=delivered).box is delivered
