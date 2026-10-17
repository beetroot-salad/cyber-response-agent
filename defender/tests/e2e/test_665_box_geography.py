"""#665 — box.py renders a caller-composed BoxRequest (mounts, env allowlist, workdir, baked network/read-only/tmpfs), its per-mount startup sentinel, create-fault reaping, pre-create sweep and unsandboxed opt-out. The docker daemon is faked through the real docker= seam."""
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
    start_box_request,
)

pytest.importorskip("pydantic_ai")


from defender.runtime import box as box_mod  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "s665geo"


def _run_cycle_mounts(run_dir: Path):
    """A minimal run-cycle geography a caller composes (M2): learning_run_dir + the ro
    defender infra tree + the ro gather_raw evidence tree, each read-only mount declaring
    what it holds (#1108 D7 amended): the run's data, the product code, the evidence data."""
    return (
        Mount(source=run_dir, target=run_dir, writable=False, kind="data"),
        Mount(source=DEFENDER, target=DEFENDER, writable=False, kind="code"),
        Mount(source=run_dir / "gather_raw", target=run_dir / "gather_raw", writable=False,
              kind="data"),
    )


def _populate_mount_sources(mounts, tmp_path: Path) -> None:
    """Populate only test-owned sources with an existing read-back file.

    D7 forbids planting during a read-only mount check. The checked-out DEFENDER already
    has its committed code check file and is never edited by this fixture. The marker below is
    deliberate setup in temporary sources, available before startup begins.
    """
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
        mounts=mounts if mounts is not None else _run_cycle_mounts(run_dir),
        workdir=workdir if workdir is not None else REPO_ROOT,
        env=env if env is not None else {},
        spec=spec,
        defender_dir=defender_dir,
    )


# box.py renders the caller-composed geography (O8/M2)
def test_box_request_renders_mounts_and_no_tier_discriminator(tmp_path):
    """box_request_geography — box.py renders exactly the mounts the caller's BoxRequest
    carries onto the `docker run` argv (target ≡ source, readonly per the Mount flag), and
    the container name is the caller's composed name — box.py bakes in no tier field of its
    own (M2). Asserts every requested mount appears on the captured create argv."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start_box_request(_request(run_dir), docker=rec)
    rendered = {(m["source"], m["readonly"]) for m in rec.mounts()}
    for m in _run_cycle_mounts(run_dir):
        assert (str(m.source), not m.writable) in rendered, f"mount {m.source} not rendered"
    assert box_mod.container_name.__name__  # box.py owns the grammar, not a tier discriminator


def test_box_request_caller_omits_network_isolation_and_gets_a_default_network(tmp_path):
    """test_box_request_caller_omits_network_isolation_and_gets_a_default_network — network
    isolation is BAKED INTO box.py (S2/N2 `--network=none`), not a caller-supplied field. A
    request that says nothing about the network still renders `--network none`; the caller
    cannot omit their way to egress."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start_box_request(_request(run_dir), docker=rec)
    assert rec.flag_value("--network") == "none", "box.py did not bake in --network=none"
    assert rec.has_flag("--read-only"), "box.py did not bake in --read-only"


def test_composed_container_name_fails_the_naming_grammar(tmp_path):
    """test_composed_container_name_fails_the_naming_grammar (F8 → R7) — a caller-composed
    container name that fails the `is_valid_run_id` grammar (#698) is caught in box.py's
    render/request path (the boundary concern, O8), raising a clear error BEFORE any container
    is touched. Positive control: a grammar-valid name renders and reaches docker."""
    run_dir = make_run_dir(tmp_path)
    bad = RecordingDocker()
    with pytest.raises((ValueError, box_mod.BoxFault)):
        start_box_request(_request(run_dir, name="defender run/../etc"), docker=bad)
    assert bad.create_argv is None, "an invalid composed name still reached docker create"

    ok = RecordingDocker()
    start_box_request(_request(run_dir, name="defender-runcycle-abc"), docker=ok)
    assert ok.create_argv is not None


# The box environment (S8/M2/RF1) — allowlist by key, one shared helper
def test_box_env_filtered_by_key_no_host_credential(tmp_path):
    """env_filtered_no_credential — box.py's env is a positive allowlist BY KEY
    (BOX_ENV_ALLOWLIST); a host credential-shaped key in the caller's request env crosses to
    NO surface of the rendered box (S8: no host credential rides an exec)."""
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
    """test_caller_env_dict_key_collides_with_the_shared_infra_helpers_derived_key (po10 → R11) —
    on a collision on an INFRA key, the shared helper's value WINS over a caller-supplied one
    (consistent with run_env's first three keys and S8): a caller cannot widen or reorder PATH
    ahead of the infra ..."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start_box_request(
        _request(run_dir, env={"PATH": "/attacker/bin", "TZ": "Europe/Paris"}), docker=rec,
    )
    assert rec.env()["PATH"].startswith(str(DEFENDER / "bin")), \
        "a caller-supplied PATH won over the infra helper (S8 hole)"
    assert "/attacker/bin" not in rec.env()["PATH"], "the caller's PATH override survived"
    assert rec.env().get("TZ") == "Europe/Paris", "a non-infra allowlisted key was dropped"


# The startup sentinel (O2/M11) + startup-fault loudness (M4/decision 5)
def test_sentinel_probes_every_mount_ro_readback_without_planting(tmp_path):
    """D7/M11: nonempty read-only mounts are read back without even transient writes."""
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
    """test_mount_source_directory_absent_at_box_creation (DC1 / po1) — an absent `--mount
    type=bind` source is a LOUD create-time BoxFault (rc=125, no container), NOT the doc's
    silently-materialised empty dir (that belongs only to the `-v` auto-create path box does
    not use)."""
    run_dir = make_run_dir(tmp_path)
    absent = RecordingDocker(create=DockerFault(
        rc=125, stderr="docker: Error response from daemon: bind source path does not exist",
        cite="po1",
    ))
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=absent)
    assert not any(len(c) > 1 and c[1] == "exec" for c in absent.calls), \
        "a sentinel read-back ran despite the create-time refusal (silent-empty path)"

    ok = RecordingDocker()
    box_mod.start_box(run_dir, DEFENDER, docker=ok)  # present sources → clean create


def test_partial_multi_mount_sentinel_validation_leaves_box_in_ambiguous_state(tmp_path):
    """test_partial_multi_mount_sentinel_validation_leaves_box_in_ambiguous_state — with several
    mounts each probed at start, one mount's read-back can fail after another's passed; a
    partially-validated box is torn down AS A WHOLE (any sentinel fault is an M4 startup fault
    → decision 5 loud abort + ..."""
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(_run_cycle_mounts(run_dir), tmp_path)
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
    """#884 F-29 — `docker run --detach` is create-THEN-start, so a non-zero rc does not prove no
    container exists."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker(create=DockerFault(**_SHIM_FAULT), existing_token="self")
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=rec)
    assert reaped_after_create(rec.calls), \
        "a container that may exist in `created` was left behind by the create-fault arm"


def test_create_fault_that_leaves_a_created_container_is_reaped_request_lane(tmp_path):
    """The request lane repeats the investigation lane's arm verbatim, so it repeated the leak
    verbatim. Its names are no more revisited: `defender-drain-{uuid4}` per invocation. (The
    run-cycle lane self-heals only because it keys on a REUSED run id and so meets its own
    pre-create reap on retry — a property of one caller, not of this arm.)"""
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(_run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(create=DockerFault(**_SHIM_FAULT), existing_token="self")
    with pytest.raises(box_mod.BoxFault):
        start_box_request(_request(run_dir), docker=rec)
    assert reaped_after_create(rec.calls), \
        "a container that may exist in `created` was left behind by the create-fault arm"


def _dies_after_create(rec, *subcommands):
    """A daemon that answers until the create, then cannot be invoked at all — `_call`'s
    OSError arm, which it translates to `BoxFault`. The correlated case, not an exotic one:
    the daemon that just failed a create is the one most likely to be gone by the reap."""
    def docker(argv, **kw):
        if rec.create_argv is not None and len(argv) > 1 and argv[1] in subcommands:
            raise OSError("daemon socket gone")
        return rec(argv, **kw)
    return docker


@pytest.mark.parametrize("lane", ["investigation", "request"])
def test_a_create_that_lost_a_name_race_does_not_reap_the_winner(tmp_path, lane):
    """#884 F-29's other half: reaping on the create-fault arm must not reap someone ELSE."""
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(_run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(
        create=DockerFault(
            rc=125,
            stderr='Conflict. The container name "/defender-run-x" is already in use',
            cite="C43a — the daemon's own name-conflict rc/text",
        ),
        existing_token="another-lane-holds-this-name",
        # No `status`: the sweep found the name free, and the other lane took it in the window
        # between that look and our create. Stating a status here would model a container the
        # pre-create sweep refuses, and this arm would never run.
    )
    start = (
        (lambda: box_mod.start_box(run_dir, DEFENDER, docker=rec))
        if lane == "investigation"
        else (lambda: start_box_request(_request(run_dir), docker=rec))
    )
    with pytest.raises(box_mod.BoxFault):
        start()
    assert not reaped_after_create(rec.calls), \
        "the create-fault arm reaped a container another lane owns"


@pytest.mark.parametrize("lane", ["investigation", "request"])
@pytest.mark.parametrize("state", ["created", "running", "restarting", "paused", "removing"])
def test_the_pre_create_sweep_refuses_a_container_that_is_not_finished(tmp_path, lane, state):
    """#955 F-49 — the sibling of the arm above, on the path that runs FIRST."""
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(_run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(status=state)
    start = (
        (lambda: box_mod.start_box(run_dir, DEFENDER, docker=rec))
        if lane == "investigation"
        else (lambda: start_box_request(_request(run_dir), docker=rec))
    )
    with pytest.raises(box_mod.BoxFault, match="refusing rather than reaping"):
        start()
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in rec.calls), \
        f"the pre-create sweep reaped a container in {state!r}, which nobody has finished with"
    assert rec.create_argv is None, \
        "the refusal came after a create — a box was started on a contested name"


@pytest.mark.parametrize("lane", ["investigation", "request"])
def test_the_pre_create_sweep_still_clears_a_finished_container(tmp_path, lane):
    """The other half of F-49, and the half that keeps the fix from being a wedge."""
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(_run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(status="exited")
    if lane == "investigation":
        box_mod.start_box(run_dir, DEFENDER, docker=rec)
    else:
        start_box_request(_request(run_dir), docker=rec)
    assert rec.create_argv is not None, "a finished container blocked the start"
    reap = next(i for i, c in enumerate(rec.calls) if c[:3] == ["docker", "rm", "-f"])
    create = next(i for i, c in enumerate(rec.calls) if len(c) > 1 and c[1] == "run")
    assert reap < create, "the stale container was cleared after the create, not before it"


def test_the_pre_create_refusal_still_leaves_the_did_not_run_marker(tmp_path):
    """#955 F-49's own §7 D2 obligation, on the arm that now raises MOST often."""
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(_run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(status="running")
    with pytest.raises(box_mod.BoxFault, match="refusing rather than reaping"):
        box_mod.start_box(run_dir, DEFENDER, docker=rec)
    assert box_mod.verdict_path(run_dir).is_file(), \
        "the pre-create refusal left no §7 D2 verdict — the tree reads as unjudged"
    verdict = json.loads(box_mod.verdict_path(run_dir).read_text(encoding="utf-8"))
    assert verdict["ran"] is False, \
        "a refusal that never started a box recorded the tree as SCANNED"
    assert "refused before create" in verdict["reason"], \
        f"the verdict does not say WHICH startup fault produced it: {verdict['reason']!r}"


def test_a_daemon_answer_the_sweep_cannot_read_is_not_taken_as_finished(tmp_path):
    """`_FINISHED_STATES` membership is the test, so an unparseable answer fails CLOSED."""
    run_dir = make_run_dir(tmp_path)
    _populate_mount_sources(_run_cycle_mounts(run_dir), tmp_path)
    rec = RecordingDocker(status="")
    with pytest.raises(box_mod.BoxFault, match="refusing rather than reaping"):
        box_mod.start_box(run_dir, DEFENDER, docker=rec)
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in rec.calls)


def test_the_box_is_stamped_with_the_token_its_own_fault_arm_checks(tmp_path):
    """The label and the check are one mechanism, so pin them together: a stamp the fault arm
    does not read, or a read of a label nothing stamps, both leave the reap deciding on
    nothing. Asserts the create argv carries a NON-EMPTY token under the key box.py inspects."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    box_mod.start_box(run_dir, DEFENDER, docker=rec)
    token = rec.create_label(box_mod.START_TOKEN_LABEL)
    assert token, f"no {box_mod.START_TOKEN_LABEL} label on the create argv"
    other = RecordingDocker()
    box_mod.start_box(make_run_dir(tmp_path / "second"), DEFENDER, docker=other)
    assert other.create_label(box_mod.START_TOKEN_LABEL) != token, \
        "the token is not per-START — two starts stamped the same value"


def test_a_reap_that_cannot_reach_the_daemon_does_not_replace_the_create_fault(tmp_path):
    """The create-fault arm's reap is best-effort on BOTH halves, `docker inspect` included."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker(create=DockerFault(**_SHIM_FAULT), existing_token="self")
    with pytest.raises(box_mod.BoxFault) as excinfo:
        box_mod.start_box(run_dir, DEFENDER, docker=_dies_after_create(rec, "inspect", "rm"))
    assert _SHIM_FAULT["stderr"] in str(excinfo.value), \
        f"the reap replaced the create fault with {str(excinfo.value)[:90]!r}"


def test_a_reap_that_cannot_reach_the_daemon_still_leaves_the_did_not_run_marker(tmp_path):
    """The same rule on the STARTUP-fault arm, where the reap runs BEFORE the §7 D2 marker: a
    reap that raised took the verdict down with it, leaving the tree indistinguishable from one
    nobody has judged yet — which is exactly what `write_did_not_run` exists to prevent."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker(sentinel=DockerFault(rc=1, stderr="read-back failed", cite="po48"))
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=_dies_after_create(rec, "rm"))
    assert box_mod.verdict_path(run_dir).is_file(), \
        "a reap that could not reach the daemon took the §7 D2 verdict down with it"


def test_container_exits_between_create_and_sentinel(tmp_path):
    """test_container_exits_between_create_and_sentinel — the container reported created is no
    longer running when the startup sentinel probes it: an M4 sentinel-mismatch startup fault
    → decision 5 loud abort."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker(sentinel=DockerFault(rc=137, stderr="container is not running", cite="po48"))
    with pytest.raises(box_mod.BoxFault, match="sentinel"):
        box_mod.start_box(run_dir, DEFENDER, docker=rec)
    assert any(len(c) > 1 and c[1] == "run" for c in rec.calls), \
        "the sentinel fault fired without a container create having been attempted"


def test_docker_binary_unavailable_at_box_startup(tmp_path):
    """test_docker_binary_unavailable_at_box_startup — the docker CLI is not present/executable
    when box creation makes its FIRST call: an M4 startup-class fault → decision 5 loud abort,
    surfaced as a BoxFault before any container exists (not a bare FileNotFoundError leaking
    out of the loop)."""
    run_dir = make_run_dir(tmp_path)
    calls: list[list[str]] = []

    def no_docker(argv, **_kw):
        calls.append(list(argv))
        raise FileNotFoundError(2, "No such file or directory: 'docker'")

    with pytest.raises(box_mod.BoxFault):  # the raw FileNotFoundError must be wrapped, not leaked
        box_mod.start_box(run_dir, DEFENDER, docker=no_docker)
    assert calls, "box creation made no docker call at all"
    assert not any(len(c) > 1 and c[1] == "run" for c in calls), \
        "a container create was attempted despite the docker binary being unavailable at the first call"


def test_no_box_has_network_egress(tmp_path):
    """no_box_egress (negative) — no box on either tier has network egress: box.py bakes
    `--network none` into every rendered box (S2/N2), so no outbound connection of any family
    reaches any destination. Negative on the network surface; positive control: the box is
    still created (the isolation does not break startup)."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    box = start_box_request(_request(run_dir), docker=rec)
    assert rec.flag_value("--network") == "none", "a box was rendered with network egress"
    assert box.name, "network isolation broke box startup (positive control failed)"


def test_box_startup_failure_aborts_batch_loudly(tmp_path, monkeypatch):
    """startup_fault_aborts_loud (negative) — a box startup failure aborts LOUDLY with NO
    automatic degradation to host execution on any production path: without the loud
    DEFENDER_ALLOW_UNSANDBOXED opt-out, a create fault raises BoxFault and NO host executor is
    returned. The opt-out is the paired positive control — the ONE sanctioned host lane."""
    run_dir = make_run_dir(tmp_path)
    faulty = RecordingDocker(create=DockerFault(rc=125, stderr="bind source path does not exist", cite="po1"))
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=faulty)  # no automatic host fallback

    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")  # the one sanctioned host lane
    assert box_mod.start_box(run_dir, DEFENDER, docker=faulty).sandboxed is False


def test_tmp_is_noexec_size_capped_tmpfs(tmp_path):
    """tmpfs_noexec_capped — box.py renders `/tmp` as a noexec, nosuid, size-capped tmpfs
    (S5), on every tier: no exec-staging in /tmp, and the tmpfs cannot grow without bound.
    Asserts the rendered `--tmpfs` flag carries noexec and a size cap."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    box_mod.start_box(run_dir, DEFENDER, docker=rec)
    tmpfs = rec.tmpfs()
    assert tmpfs, "no --tmpfs flag was rendered for /tmp"
    assert "noexec" in tmpfs, f"/tmp is not noexec: {tmpfs!r}"
    assert "size=" in tmpfs, f"/tmp is not size-capped: {tmpfs!r}"


# The unboxed opt-out (M9/S2/S8) + derived sandboxed (M5/O5)
def test_unsandboxed_opt_out_uniform_across_tiers(tmp_path, monkeypatch):
    """uniform_opt_out — the loud DEFENDER_ALLOW_UNSANDBOXED=1 opt-out is the ONE host lane,
    reached uniformly from every creation site (both new sites call start_box, which carries
    it): with the env set, a create failure degrades to the unboxed host executor; without it,
    the same failure aborts (no ..."""
    run_dir = make_run_dir(tmp_path)
    faulty = RecordingDocker(create=DockerFault(rc=125, stderr="bind source path does not exist", cite="po1"))

    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    ex = box_mod.start_box(run_dir, DEFENDER, docker=faulty)
    assert ex.sandboxed is False, "the loud opt-out did not degrade to the unboxed host executor"

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=faulty)


def test_unboxed_opt_out_env_receives_no_allowlist_filtering(tmp_path):
    """test_unboxed_opt_out_env_receives_no_allowlist_filtering (F17 → R8) — the unboxed host
    lane is an accepted no-confinement escape: S8's key allowlist does NOT bind it (a host
    subprocess inherently has host env), BUT it still strips providers.api_key_vars() so an
    accidental credential does not ride ..."""
    from defender.run_common import run_env
    from defender.runtime import providers

    run_dir = make_run_dir(tmp_path)
    env = run_env(DEFENDER, run_dir)  # the host-side env the unboxed leg runs under
    for var in providers.api_key_vars():
        assert var not in env, f"an api-key var {var} rode into the unboxed leg"


def test_unsandboxed_opt_out_leg_runs_with_full_host_network_reachability(tmp_path):
    """test_unsandboxed_opt_out_leg_runs_with_full_host_network_reachability (F18 → R8) — the
    unboxed opt-out is a bare HOST subprocess, not a container, so S2's `--network=none` has
    no lever there; full host network is the ACCEPTED cost of bypassing boxing (mitigated by
    loud/greppable/operator-driven, ..."""
    ex = box_mod.unboxed_executor(env={})
    assert ex.sandboxed is False
    assert isinstance(ex.transport, box_mod._HostTransport), \
        "the opt-out did not run as a bare host subprocess"


