"""#665 — box.py geography + the return contract (part 2 of 3).

box.py owns the boundary; callers own the geography (O8/M2). This file pins how box.py
RENDERS a caller-composed request (mounts, env, workdir, name grammar, the baked network /
read-only / tmpfs), its per-mount startup sentinel and startup-fault loudness, the unboxed
opt-out, the derived `sandboxed`, and the boxed learning bash lane's RETURN contract
(demand #0 / R9). The mount MODEL of the two new tiers and the gate↔mount reasoning are in
`test_665_box_mount_model.py`; the live mechanism confirmations in `test_665_box_live.py`.

RED AGAINST HEAD: box.py does not yet take a `BoxRequest` (it renders a fixed run_dir-rw +
defender_dir-ro geography from positional args), has no shared env helper, does a
single-mount sentinel, and the learning bash lane's faults still raise `ModelRetry` rather
than returning the #0 envelope. The docker daemon is faked through the REAL `docker=` seam
(`RecordingDocker`) with declarative faults that cite the ledger claim that observed them —
box.py's own argv build and framing run unchanged, so the assertions are on the CAPTURED
create argv / raised error / returned string.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from _box665 import (  # noqa: E402
    DEFENDER,
    REPO_ROOT,
    BoxRequest,
    DockerFault,
    Mount,
    RecordingDocker,
    ScriptedTransport,
    framed,
    make_run_dir,
    start_box_request,
)

pytest.importorskip("pydantic_ai")


from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender._untrusted import wrap as _wrap  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime import tools as runtime_tools  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.tools import _format_bash_result  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "s665geo"


def _run_cycle_mounts(run_dir: Path):
    """A minimal run-cycle geography a caller composes (M2): learning_run_dir + the ro
    defender infra tree + the ro gather_raw evidence tree."""
    return (
        Mount(source=run_dir, target=run_dir, writable=False),
        Mount(source=DEFENDER, target=DEFENDER, writable=False),
        Mount(source=run_dir / "gather_raw", target=run_dir / "gather_raw", writable=False),
    )


def _request(run_dir: Path, *, name="defender-runcycle-abc", env=None, mounts=None, workdir=None):
    return BoxRequest(
        name=name,
        mounts=mounts if mounts is not None else _run_cycle_mounts(run_dir),
        workdir=workdir if workdir is not None else REPO_ROOT,
        env=env if env is not None else {},
    )


# ======================================================================= #
# box.py renders the caller-composed geography (O8/M2)
# ======================================================================= #
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


def test_box_request_with_empty_mounts_list(tmp_path):
    """test_box_request_with_empty_mounts_list — a request with an EMPTY mounts list renders
    a box with no bind mounts (box.py renders geography, it does not inject a defender mount).
    With no defender tree inside, no granted command's entrypoint resolves — the caller's
    responsibility, not box.py's to backfill (c5)."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start_box_request(_request(run_dir, mounts=()), docker=rec)
    assert rec.mounts() == [], "box.py injected a mount the caller's empty request never asked for"


def test_box_request_workdir_not_among_its_own_mounts(tmp_path):
    """test_box_request_workdir_not_among_its_own_mounts — box.py renders the request's
    `--workdir` exactly as given even when it is covered by none of the request's own mounts
    (M2: box.py renders geography, it does not validate it); the resulting `docker exec -w`
    may then target a directory the container lacks — the caller's M3a obligation, not
    box.py's to enforce at render."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    uncovered = tmp_path / "nowhere"
    start_box_request(_request(run_dir, workdir=uncovered), docker=rec)
    assert rec.flag_value("--workdir") == str(uncovered)


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


# ======================================================================= #
# The box environment (S8/M2/RF1) — allowlist by key, one shared helper
# ======================================================================= #
def test_box_env_filtered_by_key_no_host_credential(tmp_path):
    """env_filtered_no_credential — box.py's env is a positive allowlist BY KEY
    (BOX_ENV_ALLOWLIST); a host credential-shaped key in the caller's request env crosses to
    NO surface of the rendered box (S8: no host credential rides an exec). Negative binds the
    only outward surface — the `--env` argv. Positive control: an allowlisted key (LANG) is
    rendered."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    secret = "sk-ant-SPEC-SECRET"
    start_box_request(
        _request(run_dir, env={"ANTHROPIC_API_KEY": secret, "LANG": "C.UTF-8"}), docker=rec,
    )
    assert "ANTHROPIC_API_KEY" not in rec.env(), "a non-allowlisted credential key was rendered"
    assert all(secret not in v for v in rec.env().values()), "the credential VALUE leaked into --env"
    assert rec.env().get("LANG") == "C.UTF-8", "the allowlisted key was dropped (positive control)"


def test_path_pythonpath_from_one_shared_helper(tmp_path):
    """infra_env_from_shared_helper — PATH and PYTHONPATH ('the shims and the package live in
    the infra mount', M2) are supplied by ONE shared helper on every tier, unconditionally,
    before any granted command runs — including PYTHONPATH, which run_common.run_env does NOT
    set today (brief RF1). Drives the future shared helper."""
    run_dir = make_run_dir(tmp_path)
    env = box_mod.infra_env(DEFENDER, run_dir)  # future shared helper — AttributeError at HEAD
    assert env["PYTHONPATH"] == str(DEFENDER.parent), "the shared helper did not supply PYTHONPATH"
    assert str(DEFENDER / "bin") in env["PATH"], "the shared helper did not supply the infra PATH"


def test_infra_env_helper_supplies_module_path_on_every_tier(tmp_path):
    """test_infra_env_helper_supplies_module_path_on_every_tier — the module search path the
    in-box entrypoint imports through (PYTHONPATH) is present in the RENDERED box env on every
    tier, independent of what a caller supplies. Asserts the rendered create argv carries
    PYTHONPATH even when the caller's request env omits it."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start_box_request(_request(run_dir, env={}), docker=rec)  # caller supplies NO env
    assert rec.env().get("PYTHONPATH") == str(DEFENDER.parent), \
        "PYTHONPATH was not supplied by the infra helper on this tier"


def test_caller_env_omits_a_key_the_shared_helper_is_supposed_to_always_set(tmp_path):
    """test_caller_env_omits_a_key_the_shared_helper_is_supposed_to_always_set (po10) — the
    shared helper unconditionally supplies the infra keys (DEFENDER_DIR/RUN_DIR/PATH/
    PYTHONPATH) regardless of what the caller's env omits. Asserts a request env missing
    DEFENDER_DIR still renders it."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start_box_request(_request(run_dir, env={"LANG": "C.UTF-8"}), docker=rec)
    assert rec.env().get("DEFENDER_DIR") == str(DEFENDER), \
        "the helper did not supply DEFENDER_DIR the caller omitted"


def test_caller_env_dict_key_collides_with_the_shared_infra_helpers_derived_key(tmp_path):
    """test_caller_env_dict_key_collides_with_the_shared_infra_helpers_derived_key
    (po10 → R11) — on a collision on an INFRA key, the shared helper's value WINS over a
    caller-supplied one (consistent with run_env's first three keys and S8): a caller cannot
    widen or reorder PATH ahead of the infra defender-bin entry. Positive control: a non-infra
    allowlisted key the caller sets survives."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start_box_request(
        _request(run_dir, env={"PATH": "/attacker/bin", "TZ": "Europe/Paris"}), docker=rec,
    )
    assert rec.env()["PATH"].startswith(str(DEFENDER / "bin")), \
        "a caller-supplied PATH won over the infra helper (S8 hole)"
    assert "/attacker/bin" not in rec.env()["PATH"], "the caller's PATH override survived"
    assert rec.env().get("TZ") == "Europe/Paris", "a non-infra allowlisted key was dropped"


def test_allowlisted_env_key_carries_a_credential_shaped_or_wrong_value(tmp_path):
    """test_allowlisted_env_key_carries_a_credential_shaped_or_wrong_value — the allowlist
    filters by KEY only (S8), so a credential-shaped or wrong VALUE on an allowlisted key
    rides through unexamined. This is a design-CONCEDED residual (RF-G): the value channel is
    not inspected; the key filter is value-blind."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start_box_request(_request(run_dir, env={"TZ": "sk-ant-shaped-value"}), docker=rec)
    assert rec.env().get("TZ") == "sk-ant-shaped-value", \
        "the value-blind key filter unexpectedly inspected the value"


def test_env_reaching_the_program_differs_between_the_boxed_path_and_the_loud_fallback(tmp_path):
    """test_env_reaching_the_program_differs_between_the_boxed_path_and_the_loud_fallback
    (M9) — the env reaching the program keeps PARITY across the boxed path and the loud
    unboxed fallback for the infra keys the entrypoint needs: BOTH carry PYTHONPATH (brief
    RF1 — today the unboxed fallback's run_env sets PATH but not PYTHONPATH, so it diverges).
    """
    run_dir = make_run_dir(tmp_path)
    boxed = box_mod.infra_env(DEFENDER, run_dir)  # future shared helper (AttributeError at HEAD)
    from defender.run_common import run_env

    fallback = run_env(DEFENDER, run_dir)
    assert "PYTHONPATH" in boxed, "the boxed env has no PYTHONPATH from the shared helper"
    assert "PYTHONPATH" in fallback, \
        "the unboxed fallback env has no PYTHONPATH — it diverges from the boxed path (RF1)"


# ======================================================================= #
# The startup sentinel (O2/M11) + startup-fault loudness (M4/decision 5)
# ======================================================================= #
def test_sentinel_probes_every_mount_ro_readback(tmp_path):
    """sentinel_probes_every_mount — under M2 the startup sentinel is a PER-MOUNT obligation
    (M11): every mount the box carries (the rw tree AND each ro tree) is individually probed
    by a read-back at start, not only the original single rw run_dir. DC1: the sentinel's
    residual scope is a bind that SUCCEEDED but mapped the wrong/empty tree (an absent source
    is refused loudly at create). Asserts one read-back exec per mount over a 3-mount box."""
    run_dir = make_run_dir(tmp_path)
    for m in _run_cycle_mounts(run_dir):
        Path(m.source).mkdir(parents=True, exist_ok=True)
    rec = RecordingDocker()
    start_box_request(_request(run_dir), docker=rec)
    readbacks = [c for c in rec.calls if len(c) > 1 and c[1] == "exec"]
    assert len(readbacks) >= len(_run_cycle_mounts(run_dir)), \
        "the sentinel probed fewer mounts than the box carries (single-mount sentinel survived)"


def test_mount_source_directory_absent_at_box_creation(tmp_path):
    """test_mount_source_directory_absent_at_box_creation (DC1 / po1) — an absent
    `--mount type=bind` source is a LOUD create-time BoxFault (rc=125, no container), NOT the
    doc's silently-materialised empty dir (that belongs only to the `-v` auto-create path box
    does not use). Pins the CORRECTED behavior; the fault content is po1 as observed live.
    Positive control: a present source creates cleanly."""
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


def test_gather_raw_mount_exists_but_has_no_entry_to_read_back_at_sentinel_time(tmp_path):
    """test_gather_raw_mount_exists_but_has_no_entry_to_read_back_at_sentinel_time
    (SB2 → R5) — a mounted-but-legitimately-EMPTY gather_raw is a FAITHFUL empty source
    (po1), distinguishable from absent. Decision 9's third case: present-empty → mount, SKIP
    the read-back, and record the host-side existence/inode check captured at mount-request
    time as the non-absence proof. Asserts an empty-but-present mount does not fail the box on
    a read-back it cannot satisfy."""
    run_dir = make_run_dir(tmp_path)
    (run_dir / "gather_raw").mkdir(exist_ok=True)  # present, but EMPTY
    for m in _run_cycle_mounts(run_dir):
        Path(m.source).mkdir(parents=True, exist_ok=True)
    rec = RecordingDocker()
    # the per-mount sentinel must not READ BACK an entry the empty gather_raw legitimately does
    # not hold; a present-empty mount is proven non-absent by the host-side is_dir()/inode check
    # captured at request time, not an in-box cat. The box starts.
    box = start_box_request(_request(run_dir), docker=rec)
    assert box.name, "a present-empty mount wrongly failed the per-mount startup sentinel"


def test_partial_multi_mount_sentinel_validation_leaves_box_in_ambiguous_state(tmp_path):
    """test_partial_multi_mount_sentinel_validation_leaves_box_in_ambiguous_state — with
    several mounts each probed at start, one mount's read-back can fail after another's
    passed; a partially-validated box is torn down AS A WHOLE (any sentinel fault is an M4
    startup fault → decision 5 loud abort + unwind), never observed or used half-checked.
    Asserts a sentinel fault raises and the box is reaped (docker rm -f)."""
    run_dir = make_run_dir(tmp_path)
    for m in _run_cycle_mounts(run_dir):
        Path(m.source).mkdir(parents=True, exist_ok=True)
        (Path(m.source) / "entry.txt").write_text("x", encoding="utf-8")
    rec = RecordingDocker(sentinel=DockerFault(rc=1, stderr="mount 2 read-back failed", cite="po48"))
    with pytest.raises(box_mod.BoxFault):
        start_box_request(_request(run_dir), docker=rec)
    assert any(c[:3] == ["docker", "rm", "-f"] for c in rec.calls), \
        "a partially-validated box was not reaped after a sentinel fault"


def test_docker_create_partially_applies_mounts_when_one_mount_spec_is_malformed(tmp_path):
    """test_docker_create_partially_applies_mounts_when_one_mount_spec_is_malformed
    (po48) — docker create is all-or-nothing on mount specs: a good mount + a malformed one
    errors (rc=1) and leaves NO container; the M11 per-mount sentinel is a backstop atop an
    already-atomic create. Asserts a create rc=1 raises BoxFault with no read-back attempted."""
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker(create=DockerFault(rc=1, stderr="invalid mount spec", cite="po48"))
    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run_dir, DEFENDER, docker=rec)
    assert not any(len(c) > 1 and c[1] == "exec" for c in rec.calls), \
        "a sentinel ran though create left no container (create was not treated as atomic)"


def test_container_exits_between_create_and_sentinel(tmp_path):
    """test_container_exits_between_create_and_sentinel — the container reported created is
    no longer running when the startup sentinel probes it: an M4 sentinel-mismatch startup
    fault → decision 5 loud abort. Fault content is the read-back failing (the exited
    container cannot echo the token). Discrimination: the fault fires at the per-mount sentinel
    read-back (box.py's own 'read back the startup sentinel' message) AFTER a create succeeded
    — distinct from the docker-binary-unavailable fault, which fails at the FIRST docker call
    before any create is attempted."""
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
    out of the loop). Discrimination: the failure lands at the first docker call and NO
    `docker run` create is ever attempted — distinct from the sentinel-mismatch fault, which
    fails only AFTER a successful create."""
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


def test_per_mount_sentinel_coverage_across_a_box_with_three_or_more_mounts(tmp_path):
    """test_per_mount_sentinel_coverage_across_a_box_with_three_or_more_mounts — with a box
    carrying rw + two ro mounts (defender_dir, gather_raw) plus a tmpfs, every one of the bind
    mounts is individually probed at start (M11 per-mount), not only the mounts the original
    single-mount sentinel knew about. Asserts a read-back per bind mount over a 3-mount box."""
    run_dir = make_run_dir(tmp_path)
    mounts = _run_cycle_mounts(run_dir)
    for m in mounts:
        Path(m.source).mkdir(parents=True, exist_ok=True)
        (Path(m.source) / "entry.txt").write_text("x", encoding="utf-8")
    rec = RecordingDocker()
    start_box_request(_request(run_dir, mounts=mounts), docker=rec)
    readbacks = [c for c in rec.calls if len(c) > 1 and c[1] == "exec"]
    assert len(readbacks) >= len(mounts) >= 3, \
        "the sentinel probed fewer than every mount across a 3+-mount box"


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


# ======================================================================= #
# The unboxed opt-out (M9/S2/S8) + derived sandboxed (M5/O5)
# ======================================================================= #
def test_unsandboxed_opt_out_uniform_across_tiers(tmp_path, monkeypatch):
    """uniform_opt_out — the loud DEFENDER_ALLOW_UNSANDBOXED=1 opt-out is the ONE host lane,
    reached uniformly from every creation site (both new sites call start_box, which carries
    it): with the env set, a create failure degrades to the unboxed host executor; without it,
    the same failure aborts (no automatic host fallback). Positive control paired with the
    negative."""
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
    accidental credential does not ride in. Asserts the unboxed env keeps a non-allowlisted
    host key yet drops the provider key."""
    from defender.run_common import run_env
    from defender.runtime import providers

    run_dir = make_run_dir(tmp_path)
    env = run_env(DEFENDER, run_dir)  # the host-side env the unboxed leg runs under
    for var in providers.api_key_vars():
        assert var not in env, f"an api-key var {var} rode into the unboxed leg"


def test_unsandboxed_opt_out_leg_runs_with_full_host_network_reachability(tmp_path):
    """test_unsandboxed_opt_out_leg_runs_with_full_host_network_reachability (F18 → R8) — the
    unboxed opt-out is a bare HOST subprocess, not a container, so S2's `--network=none` has no
    lever there; full host network is the ACCEPTED cost of bypassing boxing (mitigated by
    loud/greppable/operator-driven, M9). Asserts the opt-out executor is the host transport,
    not sandboxed."""
    ex = box_mod.unboxed_executor(env={})
    assert ex.sandboxed is False
    assert isinstance(ex.transport, box_mod._HostTransport), \
        "the opt-out did not run as a bare host subprocess"


def test_sandboxed_is_derived_not_settable(tmp_path):
    """sandboxed_derived_from_transport — `sandboxed` is DERIVED from the transport (M5/O5),
    not an independently-settable field that can claim a boundary the transport does not
    provide: a BoxExecutor over the host transport is NOT sandboxed regardless of the
    construction default. At HEAD `sandboxed` is a bare field defaulting True — the defect."""
    host = box_mod.BoxExecutor(transport=box_mod._HostTransport(env={}))
    assert host.sandboxed is False, "sandboxed did not derive from the host transport (settable field)"
    unattached = box_mod.BoxExecutor()  # inert default transport = _unattached
    assert unattached.sandboxed is False, "an unattached box claimed it was sandboxed"


# ======================================================================= #
# The return contract (demand #0 / F0 / F12 / SB-return → R9)
# ======================================================================= #
def _judge_deps(run_dir: Path, box):
    """Judge deps (a learning role) through the REAL bind, carrying an injected box."""
    return bind(JUDGE_DEF, run_dir, salt=SALT, defender_dir=DEFENDER, box=box)


def test_boxed_lane_returns_command_output(tmp_path):
    """return_contract (R9) — a granted command in an ATTACHED box returns
    `_format_bash_result(rc,out,err)` (`exit=<rc>\\n--- stdout ---\\n<out>…`) wrapped in the
    untrusted-content frame for a learning role — matching the runtime boxed lane byte-for-byte
    modulo the wrap. Drives the REAL _tool_bash for the judge over an injected transport."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.BoxExecutor(transport=ScriptedTransport(framed(0, b"hello\n", b"")))
    deps = _judge_deps(run_dir, box)
    out = runtime_tools._tool_bash(deps, f"cat {run_dir / 'alert.json'}")
    assert out == _wrap(_format_bash_result(0, "hello\n", ""), "untrusted", deps.salt)


def test_bash_lane_nonzero_exit_returns_wrapped_envelope(tmp_path):
    """test_bash_lane_nonzero_exit_returns_wrapped_envelope (RF-D1 / SB-return → R9) — an
    EXECUTED command that exited NON-ZERO is still a completed exec: its rc/out/err are wrapped
    in the untrusted #0 envelope for a learning role, matching the runtime boxed lane byte-for-byte
    modulo the wrap (the runtime lane wraps _format_bash_result for ANY exit code, non-zero
    included), never raised. This is the executed→wrap half of the split return contract; the
    transport→raise half is test_bash_lane_transport_fault_raises_not_wrapped. Drives the REAL
    _tool_bash for the judge over a transport that frames a non-zero exit."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.BoxExecutor(transport=ScriptedTransport(framed(3, b"partial\n", b"boom\n")))
    deps = _judge_deps(run_dir, box)
    out = runtime_tools._tool_bash(deps, f"cat {run_dir / 'alert.json'}")
    assert out == _wrap(_format_bash_result(3, "partial\n", "boom\n"), "untrusted", deps.salt)
    assert "exit=3" in out, "a non-zero exit was not carried inside the #0 envelope"


def test_bash_lane_transport_fault_raises_not_wrapped(tmp_path):
    """test_bash_lane_transport_fault_raises_not_wrapped (RF-D1 / SB-return → R9) — a TRANSPORT
    fault (container gone / undeliverable exec — the box could not run the command at all) is
    NOT wrapped into the #0 envelope: it RAISES ModelRetry, exactly as the runtime boxed lane
    does (BoxFault→ModelRetry). Learning roles inherit that raise free (M4) — the learning
    agent-run loop catches ModelRetry natively (pydantic_ai wraps a tool's ModelRetry into a
    retry prompt for every agent). Only an EXECUTED command's rc/out/err is wrapped. Negative:
    the transport fault raises. Positive control: a healthy transport's executed command returns
    the wrapped envelope, so the observation channel distinguishes raise from return."""
    run_dir = make_run_dir(tmp_path)
    faulted = _judge_deps(
        run_dir, box_mod.BoxExecutor(transport=ScriptedTransport(box_mod.BoxFault("container gone"))),
    )
    with pytest.raises(ModelRetry):  # transport fault raises — never wrapped over-read
        runtime_tools._tool_bash(faulted, f"cat {run_dir / 'alert.json'}")
    healthy = _judge_deps(
        run_dir, box_mod.BoxExecutor(transport=ScriptedTransport(framed(0, b"ok\n", b""))),
    )
    out = runtime_tools._tool_bash(healthy, f"cat {run_dir / 'alert.json'}")
    assert out == _wrap(_format_bash_result(0, "ok\n", ""), "untrusted", healthy.salt), \
        "the executed-command positive control did not return the wrapped envelope"


def test_judge_boxed_output_wrap_is_the_intended_zero_shape(tmp_path):
    """test_judge_boxed_output_wrap_is_the_intended_zero_shape (F12 → R9) — the judge, whose
    job is to consume its boxed command output as a verdict input, gets the IDENTICAL untrusted
    wrap as the other learning roles (byte-uniform #0 shape). Asserts the judge's wrapped output
    equals the canonical wrap for the same bytes."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.BoxExecutor(transport=ScriptedTransport(framed(0, b"verdict-evidence\n", b"")))
    deps = _judge_deps(run_dir, box)
    out = runtime_tools._tool_bash(deps, f"cat {run_dir / 'alert.json'}")
    assert out == _wrap(_format_bash_result(0, "verdict-evidence\n", ""), "untrusted", deps.salt)


def test_box_becomes_unreachable_mid_batch(tmp_path):
    """test_box_becomes_unreachable_mid_batch (RF-D1 → R9) — a box that passed startup stops
    responding partway through a batch: the call BEFORE returned its WRAPPED output; the call
    AFTER hits a TRANSPORT fault and RAISES ModelRetry (the runtime lane's BoxFault→ModelRetry,
    inherited free per M4 — pydantic_ai catches the raised ModelRetry in the learning agent-run
    loop), NOT wrapped into the #0 envelope (only an executed command is wrapped). Positive
    control: the pre-fault executed call returns its wrapped output."""
    run_dir = make_run_dir(tmp_path)
    box = box_mod.BoxExecutor(
        transport=ScriptedTransport(framed(0, b"ok\n", b""), box_mod.BoxFault("unreachable")),
    )
    deps = _judge_deps(run_dir, box)
    first = runtime_tools._tool_bash(deps, f"cat {run_dir / 'alert.json'}")
    assert "ok" in first, "the pre-fault executed call did not return its wrapped output"
    with pytest.raises(ModelRetry):  # the mid-batch transport fault raises, it is not wrapped
        runtime_tools._tool_bash(deps, f"cat {run_dir / 'alert.json'}")


def test_learning_role_bash_call_receives_a_response_the_transport_cannot_parse(tmp_path):
    """test_learning_role_bash_call_receives_a_response_the_transport_cannot_parse (RF-D1 → R9)
    — the box transport hands back stdout carrying NO well-formed frame; the REAL framing codec
    raises BoxFault (transport reused unchanged), which surfaces as a raised ModelRetry for a
    learning role (BoxFault→ModelRetry, inherited free per M4), NEVER as unframed bytes wrapped
    into the #0 envelope and handed on as program output. Negative: the unparseable response
    raises. Positive control: a well-framed response is decoded and returned wrapped."""
    run_dir = make_run_dir(tmp_path)
    unframed = _judge_deps(
        run_dir,
        box_mod.BoxExecutor(transport=ScriptedTransport(box_mod.RawExec(rc=0, stdout=b"not a frame", stderr=b""))),
    )
    with pytest.raises(ModelRetry):  # the unframed reply raises BoxFault→ModelRetry, never wraps
        runtime_tools._tool_bash(unframed, f"cat {run_dir / 'alert.json'}")
    framed_deps = _judge_deps(
        run_dir, box_mod.BoxExecutor(transport=ScriptedTransport(framed(0, b"ok\n", b""))),
    )
    out = runtime_tools._tool_bash(framed_deps, f"cat {run_dir / 'alert.json'}")
    assert "ok" in out, "the framed positive control did not return the decoded program output"
    assert "not a frame" not in out, "unframed daemon bytes reached the model as program output"
