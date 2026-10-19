"""#771 — the alias ban: a seccomp profile (derived from the platform default minus six alias syscalls) on every box lane, a startup probe that observes the ban rather than trusting configuration, and a not-opt-out-able fault when it is not in force."""
from __future__ import annotations

import json
import os
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender.runtime import bash_exec, box as box_mod
from defender.tests._docker import dood_anchor, is_dood
from defender.tests.e2e._spec771 import (
    BAN_ABSENT,
    BAN_IN_FORCE,
    BANNED_SHAPES,
    PLATFORM_COMPARISON_PROBE,
    SCAN_ONLY_SHAPES,
    AliasProbeDocker,
    DockerFault,
    ProbeVerdict,
    alias_profile_path,
    allowed_syscalls,
    ban_not_in_force_error,
    load_seccomp_generator,
    requires_daemon,
    requires_real_box,
    run_probe_under_profile,
    run_tree,
    shapes_named_in,
)

pytestmark = pytest.mark.e2e

DEFENDER = Path(__file__).resolve().parents[2]


def _start_investigation_lane(run_dir: Path, docker) -> object:
    """Drive the REAL investigation-lane creation path (`_create_argv` tier)."""
    return box_mod.start_box(run_dir, DEFENDER, docker=docker)


def _request(tmp_path: Path, *, writable: bool = True) -> object:
    """A REAL `BoxRequest` in the shape the generic builder produces — the tier C8-new made
    serve the drain lane AND the learning run-cycle."""
    src = tmp_path / "wt"
    # parents=True: callers hand this a per-lane subdirectory that does not exist yet, and an
    # exist_ok-only mkdir raises FileNotFoundError there — a failure that reads as the lane
    # being unbuildable rather than as a missing directory.
    src.mkdir(parents=True, exist_ok=True)
    return box_mod.BoxRequest(
        name="r-771-lane",
        mounts=(box_mod.Mount(source=src, target=src, writable=writable),),
        workdir=src,
        env={},
        # An explicit rootfs: `src` is a fake tree with none of the three hash inputs, and an
        # unset rootfs resolves the image from `workdir / "defender"` and refuses (#1092).
        # Every caller drives a scripted daemon, so the stock name is the right pin.
        spec=box_mod.BoxSpec(rootfs="python:3.11-slim"),
    )


# M1 — the profile on the argv, on every lane
def test_box_argv_carries_the_alias_profile(tmp_path):
    """alias_profile_seam — the rendered `docker run` argv carries `--security-opt seccomp=<the
    shipped profile>`, pointing at a file that exists and parses as the deny profile."""
    rec = AliasProbeDocker()
    _start_investigation_lane(run_tree(tmp_path), rec)

    value = rec.flag_value("--security-opt")
    assert value is not None, "the create argv carries no --security-opt at all"
    assert value.startswith("seccomp="), f"--security-opt is not a seccomp profile: {value!r}"
    profile = Path(value.split("=", 1)[1])
    assert profile.is_file(), f"the argv names a profile that does not exist: {profile}"
    assert profile == alias_profile_path(), (
        "the argv's profile path is not the one resolved value both builders must share"
    )


def test_every_box_lane_carries_the_alias_profile(tmp_path):
    """alias_profile_on_every_box_lane — both argv builders attach the alias profile, and they
    attach the IDENTICAL resolved value: the investigation lane's builder and the generic
    request builder that serves the drain lane and the learning run-cycle alike."""
    lane_a = AliasProbeDocker()
    _start_investigation_lane(run_tree(tmp_path), lane_a)

    lane_b = AliasProbeDocker()
    box_mod.start_box(_request(tmp_path), docker=lane_b)

    a, b = lane_a.flag_value("--security-opt"), lane_b.flag_value("--security-opt")
    assert a is not None, "the investigation lane ships with no ban"
    assert b is not None, "the generic request lane ships with no ban"
    assert a == b, f"the two builders' profile paths drifted: {a!r} vs {b!r}"


def test_alias_profile_denies_the_six_syscalls_and_allows_everything_else(tmp_path):
    """profile_denies_exactly_six — the shipped profile denies each of the six banned shapes and
    nothing the platform default allowed, by being the platform default with the six
    SUBTRACTED from its allowlist."""
    profile = json.loads(alias_profile_path().read_text(encoding="utf-8"))

    assert profile["defaultAction"] == "SCMP_ACT_ERRNO", (
        "the profile is not default-deny, so it is not the platform default with the ban "
        "subtracted — and a default-ALLOW profile hands the box back every syscall the "
        "platform denies, which is what attaching it REPLACES"
    )
    # Under a default-ERRNO allowlist a syscall is banned by ABSENCE, not by an explicit deny
    # rule: naming it nowhere is what makes `defaultErrnoRet` answer for it. So the deny
    # assertion is about what the profile does NOT name.
    allowed = allowed_syscalls(profile)
    assert not (allowed & set(BANNED_SHAPES)), (
        f"a banned shape is still reachable: {sorted(allowed & set(BANNED_SHAPES))}"
    )
    assert profile.get("defaultErrnoRet") == 1, (
        "the default action does not answer EPERM, so the six no longer fail with the errno "
        "the startup probe and every guarded writer classify a refusal by"
    )

    # SCAN_ONLY_SHAPES stays out of the ban, and under a subtractive profile "stays out" means
    # the syscalls behind it are still ALLOWED rather than merely un-denied. Executed: AF_UNIX
    # bind succeeds under this exact profile (X2/G5, and re-executed against Docker 29.6.1).
    scan_only_syscalls = {"bind", "socket"}
    assert scan_only_syscalls <= allowed, (
        f"the scan-only shape {SCAN_ONLY_SHAPES[0]} lost "
        f"{sorted(scan_only_syscalls - allowed)} to the subtraction — AF_UNIX bind must "
        f"SUCCEED, and denying it faults every box at startup (C5-fix/F3)"
    )


def test_the_alias_profile_does_not_widen_the_platform_syscall_surface(tmp_path):
    """profile_does_not_widen_the_platform_syscall_surface — the shipped profile allows nothing
    the vendored platform default did not, and is byte-exactly what the generator derives from
    that default, so the two cannot drift apart unobserved."""
    gen = load_seccomp_generator()
    shipped_text = alias_profile_path().read_text(encoding="utf-8")

    assert shipped_text == gen.build(), (
        "the shipped profile is not what the generator derives from the vendored platform "
        "default — it has been hand-edited, or the vendored default moved under it. Run "
        "`python3 scripts/gen_seccomp_profile.py` and review the diff; a hand-edit here is "
        "exactly the drift that reintroduces a profile nobody derived."
    )

    default_profile = json.loads(gen.MOBY_DEFAULT_PATH.read_text(encoding="utf-8"))
    platform_allows = allowed_syscalls(default_profile)
    shipped_allows = allowed_syscalls(json.loads(shipped_text))

    assert not (shipped_allows - platform_allows), (
        f"the profile allows syscalls the platform default does not: "
        f"{sorted(shipped_allows - platform_allows)} — attaching it WIDENS every box's syscall "
        f"surface, which is the failure mode a replacing profile has and a merging one cannot"
    )
    assert platform_allows - shipped_allows == set(BANNED_SHAPES), (
        f"the subtraction is not exactly the ban: "
        f"{sorted(platform_allows - shipped_allows - set(BANNED_SHAPES))} were also removed"
    )


@requires_daemon
def test_the_profile_differs_from_the_live_daemon_default_by_exactly_the_ban(tmp_path):
    """profile_matches_the_live_daemon_default_but_for_the_ban — the same syscall witness set,
    attempted once under whatever the daemon applies BY ITSELF and once under the shipped
    profile, differs on exactly the six banned shapes and on nothing else."""
    default_seen = run_probe_under_profile(PLATFORM_COMPARISON_PROBE, None)
    shipped_seen = run_probe_under_profile(PLATFORM_COMPARISON_PROBE, alias_profile_path())

    if "unsupported_arch" in default_seen:
        pytest.skip(f"no syscall table for {default_seen['unsupported_arch']}")

    assert set(default_seen) == set(shipped_seen), (
        "the two probe runs attempted different witness sets, so the comparison below would "
        "be over a subset neither run agreed on"
    )
    differing = {op for op in default_seen if default_seen[op] != shipped_seen[op]}
    assert differing == set(BANNED_SHAPES), (
        f"the shipped profile does not differ from the live daemon default by exactly the "
        f"ban.\n  unexpectedly different: "
        f"{ {op: (default_seen[op], shipped_seen[op]) for op in differing - set(BANNED_SHAPES)} }"
        f"\n  banned but identical: "
        f"{ {op: default_seen[op] for op in set(BANNED_SHAPES) - differing} }\n"
        f"An unexpected difference in the ALLOW direction means the profile widens the box's "
        f"syscall surface; in the DENY direction it means the vendored default no longer "
        f"describes this daemon and the pin needs refreshing."
    )
    assert all(shipped_seen[op] != "ok" for op in BANNED_SHAPES), (
        f"a banned shape succeeded under the shipped profile on the live daemon: "
        f"{ {op: shipped_seen[op] for op in BANNED_SHAPES if shipped_seen[op] == 'ok'} }"
    )


@pytest.mark.parametrize("shape", BANNED_SHAPES)
def test_each_banned_syscall_is_denied_and_a_partial_ban_faults_the_box(shape, tmp_path):
    """partial_enforcement_faults_the_box — when the box can still create ONE of the six shapes,
    box startup faults exactly as it does when none of them is denied, and the fault names the
    shape that was admitted."""
    rec = AliasProbeDocker(ProbeVerdict(allowed=(shape,), cite="G6"))

    with pytest.raises(ban_not_in_force_error()) as e:
        _start_investigation_lane(run_tree(tmp_path), rec)

    assert shape in str(e.value), (
        f"the fault does not name the admitted shape {shape!r}, so a partial ban reads the "
        f"same as any other startup failure"
    )


def test_an_altered_or_unreadable_profile_faults_the_box_like_a_missing_one(tmp_path):
    """altered_profile_faults_like_a_missing_one — a profile that is not the shipped one at box
    create ends in a fault BEFORE the first model turn, the same way an absent one does, from
    EITHER rejecting side: the create itself refusing to load it, and the box starting with a
    profile that does not enforce."""
    rec = AliasProbeDocker(
        BAN_ABSENT,
        create=DockerFault(rc=1, stderr="docker: Error response from daemon: cannot load "
                                        "seccomp profile: unexpected end of JSON input\n",
                           cite="E2"),
    )
    with pytest.raises(box_mod.BoxFault):
        _start_investigation_lane(run_tree(tmp_path), rec)

    rec2 = AliasProbeDocker(BAN_ABSENT)
    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path / "second"), rec2)


# M2 — the startup probe
def test_startup_probe_refuses_each_banned_shape(tmp_path):
    """probe_banned_shapes_fail — at every box start the probe attempts each banned shape inside
    the box, observes each one refused, and confirms afterwards that no entry of that shape is
    present in the tree it probed."""
    run = run_tree(tmp_path)
    rec = AliasProbeDocker(BAN_IN_FORCE)
    _start_investigation_lane(run, rec)

    assert rec.probe_count() >= 1, "no probe exec ran at box start"
    assert rec.shapes_attempted() == set(BANNED_SHAPES), (
        f"the probe attempted {sorted(rec.shapes_attempted())} rather than each banned shape, "
        f"so 'observed each one refused' is a claim about shapes it never tried"
    )
    # WRITE-CODE-FROM-SPEC FIX: the nlink check is scoped to REGULAR files. An ordinary
    # directory carries nlink >= 2 on Linux (its own "." entry plus its parent's reference to
    # it) — `run_tree` always creates some, so the unscoped check flagged every ordinary
    # directory as if it were a planted hard link, on every run regardless of the probe's
    # actual behavior. `scrub._check_entry` already gets this right by restricting the nlink
    # test to `stat.S_ISREG`; this oracle now matches it.
    leftovers = [
        p for p in run.rglob("*")
        if os.path.islink(p) or (p.is_file() and os.lstat(p).st_nlink > 1)
    ]
    assert not leftovers, (
        f"the probe reported refusal while leaving an entry of a banned shape behind: {leftovers}"
    )


def test_startup_probe_ordinary_create_succeeds_in_the_same_exec(tmp_path):
    """probe_ordinary_create_succeeds — the probe also demonstrates an ORDINARY create succeeding
    in the same exec, and a box whose probe produced no such signal faults rather than
    passing."""
    _start_investigation_lane(run_tree(tmp_path), AliasProbeDocker(BAN_IN_FORCE))

    silent = AliasProbeDocker(ProbeVerdict(create_ok=False, cite="E1"))
    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path / "no-control"), silent)


def test_startup_probe_set_is_the_banned_set_not_the_scrub_set(tmp_path):
    """probe_set_matches_ban — the shape set the probe attempts is the BAN's set: the six denied
    syscalls and no member of the reap scan's wider refusal set."""
    rec = AliasProbeDocker(BAN_IN_FORCE)
    _start_investigation_lane(run_tree(tmp_path), rec)

    attempted = rec.shapes_attempted()
    assert attempted == set(BANNED_SHAPES), f"the probe's attempted set drifted: {sorted(attempted)}"
    assert not (attempted & set(SCAN_ONLY_SHAPES)), (
        "the probe attempts a scan-only shape — it would fault every box at startup"
    )

    # THE CONTROL: a probe narrowed to the two `*at` variants must read as two, not as six.
    # These are exactly the two whose names contain the other four, so this is the argv the
    # substring reader graded as full coverage.
    narrowed = shapes_named_in("docker exec box python3 -c os.symlinkat(); os.mknodat()")
    assert narrowed == {"symlinkat", "mknodat"}, (
        f"the shape reader cannot see a narrowed probe: it read {sorted(narrowed)} from an argv "
        f"naming two shapes, so the equality above passes for a ban enforced on a subset — the "
        f"partial enforcement O2 refuses to grade, reported as success"
    )


def test_the_alias_probe_runs_once_per_box_start(tmp_path):
    """probe_runs_at_every_box_start — the probe runs exactly ONCE per box start, on every start,
    with nothing cached across boxes: a host whose registration state changes between two
    starts is re-observed on the second."""
    first = AliasProbeDocker(BAN_IN_FORCE)
    _start_investigation_lane(run_tree(tmp_path), first)
    assert first.probe_count() == 1, f"the probe ran {first.probe_count()} times for one box"

    second = AliasProbeDocker(BAN_ABSENT)
    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path / "second"), second)
    assert second.probe_count() == 1, (
        "the second start reused a cached verdict — host registration state that changed "
        "between the two boxes would go unobserved"
    )


def test_an_interrupted_or_truncated_probe_sequence_reads_as_a_startup_fault(tmp_path):
    """interrupted_probe_sequence_reads_as_failed — a probe exec that is INTERRUPTED — killed
    mid-sequence, so it never reported an outcome at all — faults box startup: incomplete is
    FAILED, never a pass."""
    rec = AliasProbeDocker(ProbeVerdict(exec_rc=137, cite="E2"))

    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path), rec)

    assert any(a[:3] == ["docker", "rm", "-f"] for a in rec.calls), (
        "a box whose probe never completed was left running — the sentinel precedent removes it"
    )


def test_the_alias_probe_reruns_in_full_and_cleans_its_own_leavings_on_both_arms(tmp_path):
    """alias_probe_is_rerun_in_full_and_cleans_both_arms — after a transient box-start retry the
    probe is re-run in FULL rather than resumed or skipped, and its own leavings are removed
    on both the pass and the fault arm."""
    run = run_tree(tmp_path)
    transient = AliasProbeDocker(BAN_IN_FORCE, create=DockerFault(rc=1, stderr="daemon busy\n",
                                                                  cite="R3"))
    with pytest.raises(box_mod.BoxFault):
        _start_investigation_lane(run, transient)

    retry = AliasProbeDocker(BAN_IN_FORCE)
    _start_investigation_lane(run, retry)

    assert retry.probe_count() == 1, "the retry skipped or resumed the probe instead of re-running"
    assert retry.shapes_attempted() == set(BANNED_SHAPES), (
        "the retry's probe attempted a narrowed set — a resumed sequence, not a full re-run"
    )
    residue = [p.name for p in run.iterdir() if p.name.startswith(".alias-probe")]
    assert not residue, f"the probe left its own leavings behind on the pass arm: {residue}"

    # THE FAULT ARM, driven on its own tree. The retry above faults BEFORE the probe runs (the
    # create is what fails), so a residue check after a successful retry says nothing about a
    # probe that ran and then faulted — and that is the arm where leavings matter most: a shape
    # that succeeded when it should have been denied is a banned entry the probe itself created,
    # and leaving it hands the reap scan a taint the box did not cause.
    faulted = run_tree(tmp_path / "probe-faulted")
    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(faulted, AliasProbeDocker(BAN_ABSENT))
    fault_residue = [p.name for p in faulted.iterdir() if p.name.startswith(".alias-probe")]
    assert not fault_residue, (
        f"the probe left its own leavings behind on the fault arm: {fault_residue}"
    )


# F4/D5 — the fault that must not be swallowed
def test_box_start_faults_when_the_ban_is_not_in_force(tmp_path):
    """probe_failure_faults_box_start — when the probe observes the ban absent, box startup
    faults: no executor is returned, and no model turn is ever reached."""
    rec = AliasProbeDocker(BAN_ABSENT)

    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path), rec)


def test_ban_not_in_force_is_not_opt_out_able(tmp_path, monkeypatch):
    """ban_failure_not_opt_out_able — with the unsandboxed opt-out set to its one live value, an
    ordinary box-startup fault still degrades to the unboxed host executor, and the ban-not-
    in-force fault still raises."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")

    ordinary = AliasProbeDocker(BAN_IN_FORCE,
                                create=DockerFault(rc=1, stderr="Cannot connect to the Docker "
                                                                "daemon\n", cite="X3"))
    degraded = _start_investigation_lane(run_tree(tmp_path), ordinary)
    assert degraded.sandboxed is False, (
        "an ordinary daemon fault stopped degrading — F4 carved too broadly (X3/G7)"
    )

    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path / "banned"), AliasProbeDocker(BAN_ABSENT))


@pytest.mark.parametrize(
    "value", ["0", "true", "TRUE", "01", " 1", "1 ", "yes", "", "1\n"],
)
def test_the_unsandboxed_opt_out_matches_exactly_one_value(value, tmp_path, monkeypatch):
    """unboxed_opt_out_exact_match — every near-miss spelling of the unsandboxed opt-out fails
    CLOSED: only the exact string `1` degrades a box-startup fault to the host executor."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", value)
    rec = AliasProbeDocker(BAN_IN_FORCE,
                           create=DockerFault(rc=1, stderr="Cannot connect to the Docker daemon\n",
                                              cite="X3"))

    with pytest.raises(box_mod.BoxFault):
        _start_investigation_lane(run_tree(tmp_path), rec)


def test_alias_ban_enforcement_by_runtime(tmp_path, monkeypatch):
    """ban_enforcement_per_runtime — under `runc` the profile is enforced unconditionally; under
    the shipped `runsc` default it is enforced IF AND ONLY IF the runtime is registered with
    `--oci-seccomp`, and an unregistered runsc host faults rather than skipping."""
    monkeypatch.setenv(box_mod.BoxSpec.ENV_VAR, "runc")
    rec = AliasProbeDocker(BAN_IN_FORCE)
    _start_investigation_lane(run_tree(tmp_path / "runc"), rec)
    assert rec.flag_value("--runtime") == "runc"
    assert rec.flag_value("--security-opt"), "the runc lane started with no profile attached"

    monkeypatch.setenv(box_mod.BoxSpec.ENV_VAR, "runsc")
    unregistered = AliasProbeDocker(BAN_ABSENT)
    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path / "runsc"), unregistered)


# mechanism confirmations against a REAL box — selected by CI's `test` job
def _box_probe(box, run_dir: Path, name: str, source: str) -> dict:
    """Run a probe script inside the box and decode its one JSON line."""
    script = run_dir / f"_probe_{name}.py"
    script.write_text(source, encoding="utf-8")
    command = f"python3 /runs/current/{script.name}"
    result = box.run_parsed(
        bash_exec.parse(command), command=command, cwd=Path("/runs/current"), timeout=60)
    assert result.rc == 0, (
        f"the {name} probe did not run to completion inside the box (rc={result.rc}): "
        f"{result.err.decode('utf-8', 'replace')!r} — this is a broken probe, not a denial"
    )
    return json.loads(result.out.decode("utf-8", "replace").strip().splitlines()[-1])


#: One probe body, three attempts, each reported as data. Used by the ordinary-operation
#: confirmation; the deny-side confirmations reuse the same reporting shape.
_ORDINARY_OPS_PROBE = """
import json, os, socket
out = {}
for name, fn in (
    ("create", lambda: open("/tmp/ok", "w").write("x")),
    ("mkdir",  lambda: os.mkdir("/tmp/probe-dir")),
    ("bind",   lambda: socket.socket(socket.AF_UNIX).bind("/tmp/probe.sock")),
):
    try:
        fn()
        out[name] = "ok"
    except OSError as e:
        out[name] = "%s:%s" % (type(e).__name__, e.errno)
print(json.dumps(out))
"""


@pytest.fixture
def live_run_base(tmp_path: Path) -> Iterator[Path]:
    """Keep real daemon bind sources on the shared mount under DooD."""
    if not is_dood():
        yield tmp_path
        return
    anchor = dood_anchor()
    assert anchor is not None, "the real-box guard requires a shared repo mount under DooD"
    base = anchor / f"t771-{uuid.uuid4().hex[:12]}"
    base.mkdir(parents=True)
    try:
        yield base
    finally:
        # The box writes as root; cleanup matches the other live-box shared fixtures.
        shutil.rmtree(base, ignore_errors=True)


@requires_real_box
def test_box_under_the_alias_profile_still_starts_and_creates_ordinarily(live_run_base):
    """box_starts_and_creates_ordinarily_under_the_profile — a real box under the exact deny set
    still starts, and ordinary file creation, `mkdir` and AF_UNIX `bind` all still succeed
    inside it."""
    run = run_tree(live_run_base)
    box = box_mod.start_box(run, DEFENDER)
    try:
        seen = _box_probe(box, run, "ordinary", _ORDINARY_OPS_PROBE)
    finally:
        box_mod.stop_box(box)

    refused = {op: outcome for op, outcome in seen.items() if outcome != "ok"}
    assert not refused, (
        f"an ordinary operation was refused under the profile: {refused} — the deny set is "
        f"wider than the six shapes, and an AF_UNIX refusal in particular would fault every "
        f"box at startup through the probe's own control"
    )
    assert set(seen) == {"create", "mkdir", "bind"}, (
        f"the probe reported {sorted(seen)} rather than all three operations, so the check "
        f"above passed on a subset it was not asked about"
    )


@requires_real_box
def test_no_unobserved_window_between_the_probe_and_the_first_real_write(live_run_base):
    """ban_in_force_for_the_whole_box_life — the ban observed by the startup probe is still in
    force at the first real driver write: an alias attempted after the probe returned is
    refused exactly as it was during the probe."""
    run = run_tree(live_run_base)
    box = box_mod.start_box(run, DEFENDER)
    try:
        seen = _box_probe(box, run, "after_probe", """
import json, os
out = {}
try:
    os.symlink("/etc/passwd", "/tmp/l")
    out["symlink"] = "ok"
except OSError as e:
    out["symlink"] = "%s:%s" % (type(e).__name__, e.errno)
print(json.dumps(out))
""")
    finally:
        box_mod.stop_box(box)

    assert seen["symlink"] == "PermissionError:1", (
        "an alias created AFTER the startup probe returned succeeded — a window opened between "
        "the probe's observation and the first real write, which is the one thing the "
        "creation-time attachment is supposed to make impossible"
    )


@requires_real_box
def test_an_alias_between_two_artifacts_inside_the_tree_is_refused_too(live_run_base):
    """intra_tree_alias_also_refused — an alias between two artifacts BOTH inside the shared tree
    is refused as well, not merely one pointing outside it."""
    run = run_tree(live_run_base)
    first = run / "gather_raw" / "l-001" / "0.json"
    first.write_text("[]", encoding="utf-8")
    second = run / "gather_raw" / "l-001" / "1.json"
    box = box_mod.start_box(run, DEFENDER)
    try:
        seen = _box_probe(box, run, "intra_tree", f"""
import json, os
out = {{}}
try:
    os.link({str(Path("/runs/current") / first.relative_to(run))!r}, {str(Path("/runs/current") / second.relative_to(run))!r})
    out["link"] = "ok"
except OSError as e:
    out["link"] = "%s:%s" % (type(e).__name__, e.errno)
print(json.dumps(out))
""")
    finally:
        box_mod.stop_box(box)

    assert seen["link"] == "PermissionError:1", (
        f"the intra-tree link must reach the syscall ban, not fail on a missing operand: {seen}")
    assert not second.exists(), (
        f"the link call reported {seen['link']} but the second name exists anyway, so the "
        f"refusal is being read off an exit status while the entry was created"
    )


#: C7-new's FOUR falsified statements, one row each: the doc that carries it, the literal this
#: change makes false, and an anchor the correction will NOT remove. The anchor is what keeps
#: each row from going vacuously green — a `phrase not in body` check also passes when the
#: section was renamed, moved to another file, or deleted wholesale, and three of these four
#: are load-bearing justifications rather than passing remarks.
FALSIFIED_STATEMENTS = (
    ("NO8's justification for not preventing symlink creation",
     "tests/intent_540.md", "no structural way to deny it", "**NO8."),
    ("C19's recorded claim in the same file's ledger",
     "tests/intent_540.md", "runsc silently ignores the OCI", "id: C19"),
    ("the sandbox design's Filesystem-isolation reasoning",
     "docs/runtime-sandbox-design.md", "no structural `symlink`-deny on the default runtime",
     "Filesystem isolation"),
    ("the sandbox design's Network-isolation reasoning",
     "docs/runtime-sandbox-design.md", "does **not** honor the OCI", "Network isolation"),
)


