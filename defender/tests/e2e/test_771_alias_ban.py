"""#771 — the executable spec for the ALIAS BAN half: M1's seccomp profile on every box lane
(O2), M2's startup probe that observes the ban's effect rather than trusting configuration
(O3), and the not-opt-out-able fault F4 resolved.

Every test here is exactly one demand of `spec-flow/specs/spec_graph_771.yaml`, named by
that demand's `discharged_by`; the docstring carries the demand's observable-outcome prose.

RED BY CONSTRUCTION: `box.ALIAS_PROFILE_PATH`, `box._probe_alias_ban` and
`box.AliasBanNotInForce` do not exist at `c98bc86c`, and neither argv builder passes
`--security-opt` today (R1).

THE ONE UNKNOWN IS NOW CLOSED. X19 — the exact registration syntax carrying `--oci-seccomp`
into the daemon's `runtimeArgs` — was the load-bearing unknown handed to implementation, and
48-reground EXECUTED it against real runsc release-20260727.0: `runsc install -- --oci-seccomp`
writes `runtimeArgs: ["--oci-seccomp"]` into the named runtime's `daemon.json` entry. Nothing
below is authored around a guessed spelling.

AND CI REALLY DOES START BOXES. The brief's inference that the live-box guard skips every live
box test in CI described a RETIRED posture: 48-reground read the guard's own predicates against
both jobs and found neither hits the skip branch — the `test` job runs boxes natively, and
`box-dood` runs them under a deliberately anchor-satisfying split. So the runtime registration
is load-bearing, and without `--oci-seccomp` in it every box in CI faults on arrival the moment
F4's not-opt-out-able fault ships. That is why the CI workflow change is part of this PR's
definition of done rather than a follow-up.

Fakes enter through `docker=` only. Fault content is declarative and cites the ledger claim
that observed it on a real daemon (`ProbeVerdict.cite`).

WHICH JOB RUNS THE REAL-BOX TESTS. The three mechanism confirmations at the bottom of this
file carry `@requires_real_box`, NOT `@pytest.mark.live` — and that is a correction, not a
style choice. The gate runs `pytest tests/ -m "not live"`, so a `live`-marked test is
deselected in the `test` job; the `box-dood` job collects `tests/e2e/test_540_box_boundary.py`
alone and never sees this file. Carried on `live`, those confirmations would be selected by NO
CI job, and the two obligations they alone pin — the ban in force for the box's whole life,
and an intra-tree alias refused — would be specified and never exercised by any job at all.

They run in the **`test` job**. 48-reground settled it: the blanket docker-outside-of-Docker
skip is retired posture, the `test` job runs pytest on the runner (so the DooD predicate is
false outright), and its gVisor step hard-fails unless the daemon lists runsc — the same three
predicates `test_540_box_boundary.py` already relies on to run real boxes there.

AND THAT JOB IS ADVISORY. `main` carries no branch protection and no ruleset, no job declares
a dependency, and no aggregating check exists — so the `test` job's result is a signal a human
chooses to respect, not something that blocks a merge. Everywhere this suite says an
obligation is "verified in CI", read it as verified in a job whose red can be merged past.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from defender.runtime import bash_exec, box as box_mod
from defender.tests.e2e._spec771 import (
    BAN_ABSENT,
    BAN_IN_FORCE,
    BANNED_SHAPES,
    CI_WORKFLOW,
    DAEMON_RUNTIME_ARGS_KEY,
    OCI_SECCOMP_FLAG,
    PLATFORM_COMPARISON_PROBE,
    REPO_ROOT,
    RUNSC_INSTALL_CMD,
    SCAN_ONLY_SHAPES,
    AliasProbeDocker,
    DockerFault,
    ProbeVerdict,
    alias_profile_path,
    allowed_syscalls,
    ban_dependency_files,
    ban_not_in_force_error,
    daemon_engine_version,
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
    )


# --------------------------------------------------------------------------- #
# M1 — the profile on the argv, on every lane
# --------------------------------------------------------------------------- #
def test_box_argv_carries_the_alias_profile(tmp_path):
    """alias_profile_seam — the rendered `docker run` argv carries
    `--security-opt seccomp=<the shipped profile>`, pointing at a file that exists and parses
    as the deny profile.

    Neither builder passes `--security-opt` today (R1), so this is the seam the whole ban
    hangs off. The CLI reads the profile CLIENT-SIDE and ships the JSON, so the path lives in
    the caller's namespace rather than the daemon's — which is what makes a
    unreadable-at-create profile a client-side fault rather than a silently divergent box."""
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
    request builder that serves the drain lane and the learning run-cycle alike.

    C8-new: the second builder is not "the drain lane" — it is the generic box-request builder,
    so a demand written as "the drain box carries the profile" under-specifies the surface. Fork
    R16 resolves the path ONCE and asserts both carry the same string, because a drift between
    the two ships one lane with no ban at all and nothing else would notice."""
    lane_a = AliasProbeDocker()
    _start_investigation_lane(run_tree(tmp_path), lane_a)

    lane_b = AliasProbeDocker()
    box_mod.start_box(_request(tmp_path), docker=lane_b)

    a, b = lane_a.flag_value("--security-opt"), lane_b.flag_value("--security-opt")
    assert a is not None, "the investigation lane ships with no ban"
    assert b is not None, "the generic request lane ships with no ban"
    assert a == b, f"the two builders' profile paths drifted: {a!r} vs {b!r}"


def test_the_read_only_run_cycle_lane_still_starts_under_the_ban(tmp_path):
    """run_cycle_lane_survives_the_ban — the learning run-cycle box, whose mounts are ALL
    read-only, still starts under the alias profile and still renders every mount readonly.

    "The ban costs a read-only lane nothing" is a claim about a lane, not a truism, and X16
    refuted the neighbouring assumption it rides on ("every box lane has a writable shared
    tree") — the run-cycle request's mounts render with `,readonly` across the board and its
    only writable path is the box `/tmp` tmpfs. Observed, not asserted."""
    from defender.learning.core.run_cycle import _run_cycle_box_request

    run_dir = run_tree(tmp_path)
    learning_run_dir = tmp_path / "learning-run"
    learning_run_dir.mkdir()
    request = _run_cycle_box_request(run_dir, learning_run_dir, DEFENDER)

    rec = AliasProbeDocker()
    box_mod.start_box(request, docker=rec)

    assert rec.flag_value("--security-opt"), "the read-only lane started with no ban"
    assert all(m["readonly"] for m in rec.mounts()), (
        "a run-cycle mount rendered writable — X16's premise moved and the lane now has a tree"
    )


def test_alias_profile_denies_the_six_syscalls_and_allows_everything_else(tmp_path):
    """profile_denies_exactly_six — the shipped profile denies each of the six banned shapes
    and nothing the platform default allowed, by being the platform default with the six
    SUBTRACTED from its allowlist.

    C2-FIX'S WITHDRAWAL RESTED ON A FALSE PREMISE, AND THIS DEMAND IS THE REPAIR. Deriving the
    profile from the platform default was withdrawn on two grounds. The first is right and is
    the argument FOR deriving: `--security-opt seccomp=<file>` REPLACES with no merge. The
    second — G9, "the daemon's default is compiled in and undumpable" — is FALSE, and it is
    what made the resulting cost look unavoidable. The default is a JSON document versioned as
    its own Go module and vendored verbatim into moby; it never has to be dumped from a running
    daemon, it has to be PINNED. The generator names the exact bytes and their digest.

    WHAT THE WITHDRAWAL COST, MEASURED RATHER THAN ARGUED. Under the hand-written allow-all
    profile, executed against a real daemon (Docker 29.6.1, runc lane): `unshare(CLONE_NEWUSER)`
    SUCCEEDS, and `keyctl` returns ENOKEY — the errno of a syscall that reached the kernel and
    looked up a keyring. Both are denied with EPERM under the platform default and under this
    derived profile. That is a container-escape surface the ban was paying for six filesystem
    syscalls, on the lane (`DEFENDER_BOX_RUNTIME=runc`) where no sandbox absorbs it.

    NO5 IS SATISFIED, NOT OVERTURNED. NO5 declines GENERAL syscall hardening — a profile that
    denies things for reasons this ledger never probed. Restoring the platform default's own
    denials is not that: it is the posture every box already ran under before M1, so the
    derived profile hardens nothing relative to the pre-ban box. The default-ERRNO action below
    is the platform default's, not a new policy."""
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
    that default, so the two cannot drift apart unobserved.

    THIS IS THE DEMAND THE OLD SHAPE COULD NOT STATE. Fork R6 chose "assert the six denials, do
    NOT assert that nothing else changed", because against a hand-written profile there was no
    baseline to compare with — the platform default was believed unobtainable (G9). With the
    default vendored and pinned, "nothing else changed" becomes a set equation over two files,
    and the accepted cost R6 recorded is not accepted any more: it is asserted away.

    THE RESIDUAL THIS LEAVES, NAMED RATHER THAN HIDDEN. A vendored allowlist denies every
    syscall NEWER than the copy pinned — the `clone3`/`faccessat2` breakage class, where a box
    image on a newer libc gets EPERM from a profile nobody edited. That residual is a PIN
    staleness problem, not a widening one, and it is why the generator records the upstream
    tag, the module version and the digest instead of just the bytes."""
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
    profile, differs on exactly the six banned shapes and on nothing else.

    THIS IS THE ONE CHECK A DIGEST CANNOT MAKE. Every other guard on the derivation compares
    two documents we control: the shipped profile against the vendored default, the vendored
    default against its recorded digest. All of them stay green when the DAEMON moves and the
    vendored copy stops describing it — which is the residual the derivation actually carries,
    since a pinned allowlist ages against the host it runs on. There is no way to ask a daemon
    what its default profile contains, so this asks what it DOES.

    WHY THE WITNESS SET IS SHAPED THE WAY IT IS. Every member is unprivileged-reachable, so a
    denial is attributable to seccomp rather than to a missing capability — `mount` is the
    instructive non-member, EPERM from the absent CAP_SYS_ADMIN under every profile and
    therefore mute. Four members carry the discrimination, MEASURED by running this exact probe
    against the hand-written allow-all profile this PR replaced (Docker 29.6.1): `unshare`
    succeeds outright, and `keyctl`/`add_key`/`pivot_root` return ENOKEY and EFAULT — errnos
    only a syscall that REACHED the kernel can produce. All four are EPERM under the daemon's
    own default. That profile differs from the default on ten members here; the derived one
    differs on exactly six, so a future profile that stops being a subtraction turns red with
    the extra members named in the failure text.

    One member is knowingly mute on this host: `userfaultfd` is EPERM everywhere because
    `vm.unprivileged_userfaultfd` is 0, so it discriminates only where that sysctl is 1. Kept
    rather than dropped — a mute witness costs one syscall and stops being mute on a host
    configured differently, which is the direction a witness set should fail in.

    It is a SAMPLE and says so: no test can attempt every syscall, and the ones worth
    attempting mostly need privilege or destroy the container. What it buys is that it reads
    the daemon in front of it rather than the document we vendored."""
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


@requires_daemon
def test_the_vendored_default_pin_is_not_older_than_the_daemon(tmp_path):
    """vendored_default_pin_tracks_the_daemon — the daemon serving this host is not NEWER than
    the moby release the vendored platform default was taken from.

    THE MAINTENANCE SIGNAL FOR THE DERIVATION'S ONE RESIDUAL. A vendored allowlist denies every
    syscall newer than the copy pinned — the `clone3`/`faccessat2` breakage class, where a box
    image on a newer libc gets EPERM from a profile nobody edited. That failure is silent at
    the point it matters and shows up as an unrelated crash inside a box, so it needs a signal
    somewhere it will be read.

    DIRECTIONAL, NOT AN EQUALITY. An OLDER daemon is fine: our profile then denies nothing it
    would have allowed, and dockerd ignores allowlist names its libseccomp does not know. A
    NEWER daemon is the staleness case, and the fix is a re-pin rather than a code change.
    Expect this to go red when the runner's Docker is upgraded — that is the check working,
    and the job it lands in is advisory, so it reports rather than blocks."""
    gen = load_seccomp_generator()
    pinned = tuple(
        int(part) for part in gen.MOBY_TAG.removeprefix("docker-v").split(".") if part.isdigit()
    )
    assert pinned, f"the generator's MOBY_TAG is not a parseable release: {gen.MOBY_TAG!r}"

    running = daemon_engine_version()
    assert running <= pinned, (
        f"this daemon ({'.'.join(map(str, running))}) is newer than the moby release the "
        f"vendored platform default was taken from ({gen.MOBY_TAG}, "
        f"{gen.MOBY_PROFILE_MODULE}). The pinned allowlist may be missing syscalls this "
        f"daemon's default permits, which surfaces inside a box as an unexplained EPERM. "
        f"Re-fetch {gen.MOBY_PROFILE_URL} at the matching tag, update MOBY_TAG / "
        f"MOBY_PROFILE_MODULE / MOBY_PROFILE_SHA256, and regenerate."
    )


def test_the_shipped_profile_sits_outside_every_box_writable_mount(tmp_path):
    """alias_profile_is_outside_every_box_writable_mount — every file the alias ban's
    correctness depends on — the seccomp profile, the write lint's ratchet baseline and the CI
    workflow that registers the runtime — lives outside every mount any lane renders writable,
    so no box can edit the files that ban it.

    THE SWEEP D7 AND D8 ARE TWO INSTANCES OF: a control whose own dependency sits inside the
    boundary it polices is not a control. The refusal record was moved out of the tree for it,
    and the scan's verdict after that; this is the same question asked of the ban's own
    CONFIGURATION rather than of its evidence. The profile is read CLIENT-SIDE at create, so a
    box that could rewrite it would not affect its own container — it would neuter the next
    one, and the startup probe would then report the ban absent for a reason no operator could
    place. The mount set is what makes that unreachable, exactly as it does for the hard-link
    non-obligation, and it is unreachable today only by accident of where the file was put.

    Driven against every lane's RENDERED mounts rather than against a path convention, because
    the drain lane's writable set is batch-dependent (X16) — "which tree" is not a static
    property of the lane, so neither is "is the profile inside one".

    THE DRAIN LANE IS RENDERED FROM ITS PRODUCTION BUILDER, and until round four it was not:
    the third lane here was a synthetic request built in this test over a temp directory, so
    the sweep certified a property on every lane EXCEPT the one whose writable set its own
    docstring cites as the reason for driving mounts at all. A sweep that skips the case it was
    created for is how this shape came back a second and a third time.

    AND THE DRAIN LANE IS CHECKED IN THE COORDINATES THAT CAN FAIL. Its writable mounts are
    inside a per-batch WORKTREE CHECKOUT of this repo, at a temp path — so comparing absolute
    paths against a profile in the developer's checkout can never fire, whatever the profile's
    location, and adding the lane without this arm would have been the same unearned coverage
    one level down. The property that actually matters there is repo-relative: the drain box
    writes into a checkout of this repo and the lane's whole job is opening a PR from it, so a
    profile sited under a triggered corpus is one the box can rewrite AND get merged — the
    weakened profile then reaches every later box through main, which is exactly the "leave the
    NEXT container unbanned" escape, laundered through review.

    AND THE RULE IS SWEPT OVER ALL THREE OF ITS INSTANCES, not just the one that was named. The
    argument above is about a file the ban's correctness rests on, and the profile is one of
    three: the lint's ratchet baseline (ratchet a census row into it and the write backstop
    stops gating that writer, with nothing turning red) and the CI workflow (it is what carries
    `--oci-seccomp`, without which the shipped default runtime enforces nothing) both qualify
    on identical reasoning. Neither is inside a triggered corpus in any batch shape available
    today — the same accident of placement that protected the profile — so this arm is what
    turns three accidents into one rule. Applying the rule only to the case it was raised on is
    the shape this run has already corrected three times."""
    from defender.learning.core.config import LoopPaths
    from defender.learning.core.drains import _drain_box_request
    from defender.learning.core.run_cycle import _run_cycle_box_request

    dependencies = {what: p.resolve() for what, p in ban_dependency_files().items()}

    lanes: dict[str, AliasProbeDocker] = {}
    lanes["investigation"] = AliasProbeDocker(BAN_IN_FORCE)
    _start_investigation_lane(run_tree(tmp_path), lanes["investigation"])

    learning_run_dir = tmp_path / "learning-run"
    learning_run_dir.mkdir()
    lanes["run_cycle"] = AliasProbeDocker(BAN_IN_FORCE)
    box_mod.start_box(
        _run_cycle_box_request(run_tree(tmp_path / "rc"), learning_run_dir, DEFENDER),
        docker=lanes["run_cycle"],
    )

    lanes["generic_request"] = AliasProbeDocker(BAN_IN_FORCE)
    box_mod.start_box(_request(tmp_path / "generic"), docker=lanes["generic_request"])

    # The REAL drain lane, one batch shape: a worktree leaf read-only, and the triggered lesson
    # corpus writable. The empty state dir is what makes the triggered set the base corpus
    # alone — the production builder decides that, not this test.
    worktree = tmp_path / "drain-wt"
    (worktree / "defender" / "lessons").mkdir(parents=True)
    (worktree / "defender" / "skills").mkdir(parents=True)
    paths = LoopPaths(repo_root=worktree, state_dir=tmp_path / "drain-state")
    lanes["drain"] = AliasProbeDocker(BAN_IN_FORCE)
    box_mod.start_box(
        _drain_box_request(worktree, "b-771", "author_drain", paths), docker=lanes["drain"])

    exposed = {
        (what, name): m["source"]
        for what, dependency in dependencies.items()
        for name, rec in lanes.items()
        for m in rec.mounts()
        if not m["readonly"] and dependency.is_relative_to(Path(m["source"]).resolve())
    }
    assert not exposed, (
        f"a file the ban depends on is inside a mount the box can write: {exposed} — the box "
        f"cannot weaken its own container this way, but it can leave the next one unbanned, and "
        f"the probe would then report a misconfiguration nobody introduced"
    )
    assert any(rec.mounts() for rec in lanes.values()), (
        "no lane rendered any mount at all, so the check above passed by having nothing to look "
        "at — the vacuous shape a mount-set assertion fails into"
    )

    # The drain lane, repo-relative — the arm that can actually fire for a file shipped in this
    # repository, swept over all three dependencies rather than over the one that was named.
    drain_writable = [m for m in lanes["drain"].mounts() if not m["readonly"]]
    assert drain_writable, (
        "the drain lane rendered no writable mount, so the containment check below looks at "
        "nothing — the production builder gives this batch shape one, and a lane with none "
        "cannot demonstrate the property either way"
    )
    for what, dependency in dependencies.items():
        assert dependency.is_relative_to(REPO_ROOT), (
            f"{what} sits at {dependency}, outside this repository, so the drain-lane arm has "
            f"no checkout coordinate to compare against — re-derive the arm rather than letting "
            f"it pass by not applying"
        )
        in_checkout = (worktree / dependency.relative_to(REPO_ROOT)).resolve()
        inside = [m["source"] for m in drain_writable
                  if in_checkout.is_relative_to(Path(m["source"]).resolve())]
        assert not inside, (
            f"in a drain worktree {what} falls inside a writable corpus mount ({inside}) — the "
            f"box can rewrite a file the ban rests on and the lane's PR carries the weakened "
            f"version back to main, where every later box reads it"
        )


@pytest.mark.parametrize("shape", BANNED_SHAPES)
def test_each_banned_syscall_is_denied_and_a_partial_ban_faults_the_box(shape, tmp_path):
    """partial_enforcement_faults_the_box — when the box can still create ONE of the six
    shapes, box startup faults exactly as it does when none of them is denied, and the fault
    names the shape that was admitted.

    O2 requires EACH shape to fail, so partial enforcement faults exactly as total absence
    does — there is no graded pass state (firm consensus #3). The demand is bound per member
    and driven per member, because five denied and one admitted is precisely the escape a
    facet-wide assertion cannot see."""
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
    profile that does not enforce.

    M2 observes the EFFECT, not the configuration, which is exactly why this is one demand and
    not four: the design does not say whether the CLI fails client-side or the daemon proceeds
    with a divergent profile, and it does not need to — both end at the same observable (firm
    consensus #4 and #5). The two arms below are those two SIDES, which is the disjunction the
    consensus is about; "altered, truncated, unreadable, mid-write" are four spellings of one
    condition and this test does not claim to enumerate them. The truncated profile whose
    remaining rules happen to parse is the dangerous one, and it is the second arm: the fake
    reports the effect that follows rather than a parse error."""
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


# --------------------------------------------------------------------------- #
# M2 — the startup probe
# --------------------------------------------------------------------------- #
def test_startup_probe_refuses_each_banned_shape(tmp_path):
    """probe_banned_shapes_fail — at every box start the probe attempts each banned shape
    inside the box, observes each one refused, and confirms afterwards that no entry of that
    shape is present in the tree it probed.

    The post-exec tree check is fork R15's resolution and it costs one listing: without it the
    verdict is formed only from the exec's exit signal, and a "refused" verdict could stand
    alongside a present entry of that shape. It is the only thing that makes the verdict
    falsifiable from outside the exec.

    "EACH banned shape" is asserted here and not left to the sibling demand. This body used to
    observe that A probe ran and that the tree was clean afterwards, which is also true of a
    probe that attempted one shape — the per-shape half of its own outcome sentence was carried
    by `probe_set_matches_ban` alone. The two are still different demands: that one pins the
    SET the probe attempts (and refuses the scan-only shape), this one pins that the attempts
    were refused and left nothing behind."""
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
    """probe_ordinary_create_succeeds — the probe also demonstrates an ORDINARY create
    succeeding in the same exec, and a box whose probe produced no such signal faults rather
    than passing.

    O2's own oracle-can-be-wrong answer: without this control a probe that never ran reads
    identically to a probe that was refused. Firm consensus #2 applies it to the exec itself —
    a `docker exec` that never ran produces neither required signal and must read as a startup
    fault, not a pass. E1/X2 executed the control on a real box: under this exact deny set
    ordinary create, `mkdir` and AF_UNIX bind all still succeed."""
    _start_investigation_lane(run_tree(tmp_path), AliasProbeDocker(BAN_IN_FORCE))

    silent = AliasProbeDocker(ProbeVerdict(create_ok=False, cite="E1"))
    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path / "no-control"), silent)


def test_startup_probe_set_is_the_banned_set_not_the_scrub_set(tmp_path):
    """probe_set_matches_ban — the shape set the probe attempts is the BAN's set: the six
    denied syscalls and no member of the reap scan's wider refusal set.

    C5-fix retracted the anti-drift clause that derived M2's shapes from the scan's refusal
    predicate. Probed: under the deny set `bind(2)` on AF_UNIX SUCCEEDS and leaves a socket in
    the tree (X2/G5, executed twice, independently) — so a literal derivation would demand that
    bind fail and would fault every box at startup. NO4 stands and is now load-bearing: the
    socket shape is covered by the reap scan ALONE, deliberately.

    The attempted set is read off the probe's own argv rather than off a reported verdict, so
    a probe that silently narrowed its set cannot pass by reporting success.

    THE SET IS COMPARED EXACTLY, ON WHOLE TOKENS, AND THE SECOND ARM IS THE PROOF THAT CAN
    FAIL. Until round four the reader asked, per name, whether that name appeared ANYWHERE in
    the argv text — and `symlinkat` contains `symlink`, `linkat` and `link`, while `mknodat`
    contains `mknod`. A probe that attempted two shapes therefore read as all six, in the one
    demand pinning O2's per-member requirement, which is the requirement the whole design leans
    on: M2 exists because enforcement is OBSERVED rather than configured, and an oracle that
    cannot fail here undoes that claim. The control below drives the same reader over a
    deliberately narrowed argv and asserts it reports the narrowing — without it, the equality
    above is an assertion nobody has shown capable of failing."""
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
    """probe_runs_at_every_box_start — the probe runs exactly ONCE per box start, on every
    start, with nothing cached across boxes: a host whose registration state changes between
    two starts is re-observed on the second.

    M2 never trusts the flag; it observes the ban's effect at every box start (C1-fix), which
    is what turns M2's failure from a permanent property of the runtime into a
    misconfiguration. The cardinality is its own demand because the nearest precedent has the
    WRONG one: the neighbouring mount sentinel probes once per MOUNT (X8), and copying it would
    probe a three-mount lane three times and a zero-mount lane never."""
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


def test_the_alias_probe_runs_on_every_box_lane(tmp_path):
    """probe_on_every_box_lane — every lane that starts a box runs the probe, including the
    lane whose mounts are all read-only, where the probe acts in the box `/tmp` tmpfs; an
    earlier lane's pass grants no exemption to a later one.

    PINNED PROVISIONALLY, and the pin contradicts the design's literal "in the shared tree"
    wording — which is why it is recorded as a pin rather than read out of the design. X16
    refuted "every lane has a writable shared tree": the learning run-cycle box's mounts are
    ALL `writable=False`. The ban is a syscall filter and not a path policy, so the observation
    is equally valid in the tmpfs; the alternatives are worse in named ways — skipping makes
    the ban configured rather than observed exactly where nobody is watching, and adding a
    scratch writable mount solely to be probed widens the attack surface to test the control.

    No cross-lane trust (firm consensus #7). The process-level aggregate response when one lane
    of several faults is design-silent and is NOT decided here."""
    from defender.learning.core.run_cycle import _run_cycle_box_request

    lanes: dict[str, AliasProbeDocker] = {}

    lanes["investigation"] = AliasProbeDocker(BAN_IN_FORCE)
    _start_investigation_lane(run_tree(tmp_path), lanes["investigation"])

    learning_run_dir = tmp_path / "learning-run"
    learning_run_dir.mkdir()
    lanes["run_cycle"] = AliasProbeDocker(BAN_IN_FORCE)
    box_mod.start_box(
        _run_cycle_box_request(run_tree(tmp_path / "rc"), learning_run_dir, DEFENDER),
        docker=lanes["run_cycle"],
    )

    lanes["drain"] = AliasProbeDocker(BAN_IN_FORCE)
    box_mod.start_box(_request(tmp_path / "drain"), docker=lanes["drain"])

    silent = {name for name, rec in lanes.items() if rec.probe_count() != 1}
    assert not silent, f"these lanes started a box without observing the ban: {sorted(silent)}"

    tmpfs_lane = lanes["run_cycle"]
    assert tmpfs_lane.tmpfs(), (
        "the read-only lane has no tmpfs for the probe to act in, so the provisional pin has "
        "no target and the lane cannot demonstrate the ban at all"
    )


def test_an_interrupted_or_truncated_probe_sequence_reads_as_a_startup_fault(tmp_path):
    """interrupted_probe_sequence_reads_as_failed — a probe exec that is INTERRUPTED — killed
    mid-sequence, so it never reported an outcome at all — faults box startup: incomplete is
    FAILED, never a pass.

    Fork R20, and it is O2's oracle-can-be-wrong answer applied literally — an absent
    ordinary-create signal cannot read as a pass, and neither can an absent refusal. The
    teardown inherits R3's sentinel-mismatch precedent: the container is removed rather than
    left running behind a failed start.

    THE OTHER SPELLING OF INCOMPLETE IS PINNED NEXT DOOR, and the outcome sentence used to
    claim both while driving one. A probe that RETURNS but is missing a required signal is
    `probe_ordinary_create_succeeds`'s second arm — its fake reports an exec that ran and
    produced no ordinary-create signal, and a box start on it must fault. Driving a
    partially-reported sequence here would have needed a fake that invents the probe's stdout
    format for a partial report, which no ledger claim covers; the interrupted exec is the arm
    a real observation (E2) supports."""
    rec = AliasProbeDocker(ProbeVerdict(exec_rc=137, cite="E2"))

    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path), rec)

    assert any(a[:3] == ["docker", "rm", "-f"] for a in rec.calls), (
        "a box whose probe never completed was left running — the sentinel precedent removes it"
    )


def test_the_alias_probe_reruns_in_full_and_cleans_its_own_leavings_on_both_arms(tmp_path):
    """alias_probe_is_rerun_in_full_and_cleans_both_arms — after a transient box-start retry the
    probe is re-run in FULL rather than resumed or skipped, and its own leavings are removed on
    both the pass and the fault arm.

    PINNED PROVISIONALLY (§7 H10.6): no answerer found the design addressing a retry's effect
    on the probe's own idempotency. The pin is also the answer to the strong author's finding
    that a FAILED probe plants the very shape it was testing for — if a shape succeeded when it
    should have been denied, the probe has created a banned entry, and leaving it behind hands
    the reap scan a taint the box did not cause. A wrong pin here is a spec bug, not an
    implementation bug."""
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


# --------------------------------------------------------------------------- #
# F4/D5 — the fault that must not be swallowed
# --------------------------------------------------------------------------- #
def test_box_start_faults_when_the_ban_is_not_in_force(tmp_path):
    """probe_failure_faults_box_start — when the probe observes the ban absent, box startup
    faults: no executor is returned, and no model turn is ever reached.

    This is O3's whole content — the condition the ban exists to close must not reach a model
    turn. With the ban absent the model write gate's check-then-write race is live and the
    design offers the gate no fallback (firm consensus #8)."""
    rec = AliasProbeDocker(BAN_ABSENT)

    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path), rec)


def test_the_ban_fault_is_its_own_exception_type(tmp_path):
    """ban_fault_has_its_own_exception_type — the ban-not-in-force fault is raised as its own
    exception class, and a caller written against the general startup fault does NOT catch it.

    TAKEN BY THE ORCHESTRATOR, FLAGGED FOR OVERRIDE (§7 D5). It is a mechanical consequence of
    the human's not-opt-out-able decision rather than a policy choice: F4 is only enforceable
    if the fault cannot be caught by the broad handler every other startup fault degrades
    through. Sharing the class leaves a security-critical caller constructible in exactly the
    state that decision exists to close, and message-matching is the failure mode fork R23's
    own note describes — a distinct type is the only identity a future maintainer cannot
    accidentally erase.

    An ordinary startup fault stays opt-out-able; only this one does not."""
    fault_type = ban_not_in_force_error()

    assert not issubclass(box_mod.BoxFault, fault_type), (
        "every startup fault is now a ban fault — the carve-out swallowed the general case"
    )
    caught_by_general = issubclass(fault_type, box_mod.BoxFault)
    assert not caught_by_general, (
        "the ban fault is a BoxFault subclass, so the existing `except BoxFault -> degrade` "
        "handler re-swallows exactly the fault F4 says must never be swallowed"
    )


def test_ban_not_in_force_is_not_opt_out_able(tmp_path, monkeypatch):
    """ban_failure_not_opt_out_able — with the unsandboxed opt-out set to its one live value,
    an ordinary box-startup fault still degrades to the unboxed host executor, and the
    ban-not-in-force fault still raises.

    F4 carves an explicit exception out of the opt-out, and this is the first time any startup
    fault is not survivable. Both arms are driven because the carve-out has two failure
    directions and both are bad: carve too broadly and a daemon blip stops being survivable,
    which is a real availability regression on laptops; carve too narrowly and the fault F4
    protects gets swallowed.

    Rejected and recorded: degrading to runc (trades isolation strength for one control,
    silently) and letting the box run while recording enforcement state (a control that reports
    its own absence into a log nobody reads)."""
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
    CLOSED: only the exact string `1` degrades a box-startup fault to the host executor.

    Fork R22 needed no human policy call in the end — the re-probe settled it as FACT. Driving
    the real start path once per value of the knob across `{unset, "1", "0", "true", "TRUE",
    "01", " 1", "1 ", "yes", ""}` found exactly one that degrades; every other value, including
    every near-miss, re-raises. The opt-out is already maximally strict.

    What was missing is a demand pinning it against future softening — and F4 makes that matter
    more than it did, because a near-miss silently read as "set" would change which faults are
    survivable at exactly the moment one of them stopped being."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", value)
    rec = AliasProbeDocker(BAN_IN_FORCE,
                           create=DockerFault(rc=1, stderr="Cannot connect to the Docker daemon\n",
                                              cite="X3"))

    with pytest.raises(box_mod.BoxFault):
        _start_investigation_lane(run_tree(tmp_path), rec)


def test_ban_fault_message_names_the_runtime_configuration_to_apply(tmp_path, monkeypatch):
    """ban_fault_message_names_the_configuration — the ban fault's message names the runtime the
    lane actually STARTED under and the exact registration change for it, not a fixed reference
    to the default runtime's configuration.

    F4 made the message's content a demand rather than cosmetics: a fault that says only "the
    alias ban is not in force" gets worked around rather than fixed, which reintroduces the hole
    it exists to close. Fork R10 adds the per-runtime half — F2 put the ban on BOTH runtimes, so
    a hardcoded single-runtime instruction violates F4's own requirement on the other lane.

    The literal text is now pinnable: 48-reground executed `runsc install -- --oci-seccomp`
    against a scratch daemon config and observed it write `runtimeArgs: ["--oci-seccomp"]` into
    the runtime's entry. That is the remedy an operator can act on."""
    for runtime in ("runsc", "runc"):
        monkeypatch.setenv(box_mod.BoxSpec.ENV_VAR, runtime)
        with pytest.raises(ban_not_in_force_error()) as e:
            _start_investigation_lane(run_tree(tmp_path / runtime), AliasProbeDocker(BAN_ABSENT))
        message = str(e.value)
        assert runtime in message, f"the {runtime} lane's fault names the wrong runtime: {message}"
        if runtime == "runsc":
            assert OCI_SECCOMP_FLAG in message, (
                f"the runsc fault names no --oci-seccomp registration: {message}"
            )
            assert RUNSC_INSTALL_CMD in message, (
                "the runsc fault does not carry the exact registration command "
                f"48-reground executed: {message}"
            )


def test_alias_ban_enforcement_by_runtime(tmp_path, monkeypatch):
    """ban_enforcement_per_runtime — under `runc` the profile is enforced unconditionally;
    under the shipped `runsc` default it is enforced IF AND ONLY IF the runtime is registered
    with `--oci-seccomp`, and an unregistered runsc host faults rather than skipping.

    C1-fix, on an executed two-arm probe against real runsc release-20260727.0 differing only
    in the runtime flag: OFF gave `SYMLINK_ALLOWED, Seccomp: 0`; ON gave `SYMLINK_DENIED,
    Seccomp: 2`. gVisor does not lack the capability — #540's C19 measured only the default arm
    and was written up as a capability limit, and NO8's justification does not survive.

    The verification asymmetry is worth stating: the ALTERNATIVE runtime is the verified lane
    here, while the shipped default rests on a probe not re-runnable in this environment. That
    is why this test must not pass by SKIPPING — a skip on an unregistered host is precisely
    the state the fault exists to report."""
    monkeypatch.setenv(box_mod.BoxSpec.ENV_VAR, "runc")
    rec = AliasProbeDocker(BAN_IN_FORCE)
    _start_investigation_lane(run_tree(tmp_path / "runc"), rec)
    assert rec.flag_value("--runtime") == "runc"
    assert rec.flag_value("--security-opt"), "the runc lane started with no profile attached"

    monkeypatch.setenv(box_mod.BoxSpec.ENV_VAR, "runsc")
    unregistered = AliasProbeDocker(BAN_ABSENT)
    with pytest.raises(ban_not_in_force_error()):
        _start_investigation_lane(run_tree(tmp_path / "runsc"), unregistered)


def test_ci_registers_the_box_runtime_with_oci_seccomp(tmp_path):
    """oci_seccomp_registration_ships_with_the_ban — every CI step that registers the box
    runtime carries `--oci-seccomp`, so the daemon's `runtimeArgs` names it and the boxes both
    jobs start actually enforce the ban.

    This is the non-skippable half of the enforcement claim, and it is CI-breaking rather than
    merge-blocking — `main` has no branch protection, so a red `test` job is a signal and not a
    barrier. X15 read the workflow: both the `test` job and the `box-dood` job apt-install runsc, run
    `sudo runsc install`, restart docker and hard-fail unless the daemon then lists runsc — with
    no `--oci-seccomp` anywhere. 48-reground then settled the other half of the argument: the
    live-box guard does NOT skip these jobs (that was a retired posture), so real boxes start in
    both, and under F4's not-opt-out-able fault every one of them faults on arrival until the
    registration changes. There is no degraded path to hide behind.

    The step is located by what it RUNS rather than by its name, and a guard fires if the
    install step moves — a fixture assertion that silently matches nothing is the vacuous
    shape this idiom exists to avoid."""
    import yaml

    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    steps = [s for job in workflow["jobs"].values() for s in job.get("steps", [])]
    installs = [s for s in steps if "runsc install" in str(s.get("run", ""))]

    assert len(installs) == 2, (
        f"expected the two gVisor install steps X15 found, got {len(installs)} — the step "
        f"moved, so re-scope this demand rather than trusting a vacuous pass"
    )
    for step in installs:
        run_text = str(step["run"])
        assert OCI_SECCOMP_FLAG in run_text, (
            f"{step.get('name')!r} registers the runtime without {OCI_SECCOMP_FLAG}; every box "
            f"in this job faults at startup once the ban ships"
        )
        assert RUNSC_INSTALL_CMD in run_text, (
            "the flag is present but not passed through `install --` as runtimeArgs (expected "
            f"the literal {RUNSC_INSTALL_CMD!r}), so the daemon's {DAEMON_RUNTIME_ARGS_KEY} "
            f"entry stays empty: {run_text!r}"
        )


# --------------------------------------------------------------------------- #
# mechanism confirmations against a REAL box — selected by CI's `test` job
# --------------------------------------------------------------------------- #
def _box_probe(box, run_dir: Path, name: str, source: str) -> dict:
    """Run a probe script inside the box and decode its one JSON line.

    DRIVES THE REAL ENTRY POINT, and the shape is `test_540_box_boundary.py`'s: the real
    `bash_exec.parse` decomposition — the same object the permission gate validates — handed to
    `run_parsed`. `box.run(command=..., cwd=..., timeout=...)` does NOT work: `run` IS
    `run_parsed`, whose first parameter is the parsed pipeline list, so the keyword-only call
    the three confirmations below used to make raised `TypeError` before reaching the box.
    Nothing caught it because these three are the only tests here that need a daemon.

    The probe CATCHES its own `OSError` and reports the class and errno as data, exiting 0
    either way (C56): the assertion is then on the outcome the box produced and never on an
    exception subclass, and a probe that failed to run at all is distinguishable from one whose
    syscall was denied."""
    script = run_dir / f"_probe_{name}.py"
    script.write_text(source, encoding="utf-8")
    command = f"python3 {script}"
    result = box.run_parsed(
        bash_exec.parse(command), command=command, cwd=run_dir, timeout=60)
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


@requires_real_box
def test_box_under_the_alias_profile_still_starts_and_creates_ordinarily(tmp_path):
    """box_starts_and_creates_ordinarily_under_the_profile — a real box under the exact deny set
    still starts, and ordinary file creation, `mkdir` and AF_UNIX `bind` all still succeed
    inside it.

    Revises the withdrawn `profile_preserves_platform_default`, whose premise died with C2-fix.
    E1 and X2 executed exactly this on a real daemon: symlink/hardlink/mkfifo/mknod all EPERM,
    while create, mkdir and socket bind SUCCEEDED — the last of which is what makes the reap
    scan's socket refusal NO4's boundary rather than a redundant belt.

    ALL THREE ARE DRIVEN, and the socket one is why that matters rather than being tidy. The
    body used to check the file create alone while the docstring promised three. `bind(2)`
    succeeding under this exact deny set is the fact that makes the ban's set and the scan's
    set DELIBERATELY different — it is what retracted the design's anti-drift clause and what
    keeps the probe from demanding a failure that would fault every box at startup. The deny
    set's size is pinned elsewhere; this is the only test that observes the allow side live,
    and it was observing a third of it."""
    run = run_tree(tmp_path)
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
def test_no_unobserved_window_between_the_probe_and_the_first_real_write(tmp_path):
    """ban_in_force_for_the_whole_box_life — the ban observed by the startup probe is still in
    force at the first real driver write: an alias attempted after the probe returned is refused
    exactly as it was during the probe.

    The profile is attached at container CREATION and enforced for the container's whole life,
    so no window opens between the probe returning and the first write (firm consensus #1).
    Grounded in G4, executed: `docker exec` inherits the creation-time profile, with identical
    denials to the creation-time run — which is why the probe's own mechanism is under the same
    filter as the box it certifies.

    SELECTED BY CI'S `test` JOB. This obligation is pinned by this test and no other, so where
    it runs decides whether it is verified at all. It carries no `live` marker precisely
    because `-m "not live"` would deselect it there and the `box-dood` job never collects this
    file — the property would be specified and exercised by nothing that gates a merge."""
    run = run_tree(tmp_path)
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

    assert seen["symlink"] != "ok", (
        "an alias created AFTER the startup probe returned succeeded — a window opened between "
        "the probe's observation and the first real write, which is the one thing the "
        "creation-time attachment is supposed to make impossible"
    )


@requires_real_box
def test_an_alias_between_two_artifacts_inside_the_tree_is_refused_too(tmp_path):
    """intra_tree_alias_also_refused — an alias between two artifacts BOTH inside the shared
    tree is refused as well, not merely one pointing outside it.

    No obligation targets an intra-tree alias, but M1's deny is target-agnostic, so it is
    refused as a side effect (firm consensus #15). Pinned so the side effect is a property a
    later narrowing of the profile has to break deliberately rather than one it can remove
    silently — the intra-tree case is where a consumer's "each payload is a distinct file"
    assumption dies without anything leaving the tree.

    SELECTED BY CI'S `test` JOB, for the same reason as its sibling above: this test is the
    only thing pinning the obligation, and a `live` marker would have left it deselected by
    the gate that actually runs."""
    run = run_tree(tmp_path)
    first = run / "gather_raw" / "l-001" / "0.json"
    first.write_text("[]", encoding="utf-8")
    second = run / "gather_raw" / "l-001" / "1.json"
    box = box_mod.start_box(run, DEFENDER)
    try:
        seen = _box_probe(box, run, "intra_tree", f"""
import json, os
out = {{}}
try:
    os.link({str(first)!r}, {str(second)!r})
    out["link"] = "ok"
except OSError as e:
    out["link"] = "%s:%s" % (type(e).__name__, e.errno)
print(json.dumps(out))
""")
    finally:
        box_mod.stop_box(box)

    assert seen["link"] != "ok", "an intra-tree hard link succeeded under the ban"
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


@pytest.mark.parametrize(
    ("what", "rel", "stale", "anchor"), FALSIFIED_STATEMENTS,
    ids=[rel.split("/")[-1] + ":" + stale[:24] for _w, rel, stale, _a in FALSIFIED_STATEMENTS],
)
def test_the_falsified_runsc_seccomp_statements_are_corrected(what, rel, stale, anchor, tmp_path):
    """doc_corrections_ship_with_the_ban — each of the FOUR written statements this change
    falsifies no longer claims that runsc cannot enforce an OCI seccomp profile, and the
    section that carried it is still there to have been corrected.

    C7-new: these statements are false BECAUSE of this PR, so they are corrected in the same PR
    rather than filed. Two further consequences are recorded and NOT actioned here — the network
    socket-deny belt (#540's territory, filed independently) and the bash lane's "no allowed
    tool creates a symlink" convention, which becomes mechanism-backed the moment the ban ships
    and is a doc claim change rather than work.

    FOUR ROWS, DRIVEN, and the count is the fix: the demand said four statements and the body
    matched three phrases, so the fourth — the design doc's SECOND section, which reasons from
    the same false premise about the network belt — was described and never checked. Each row
    is its own case, so a partial correction names the statement it missed instead of reporting
    a set difference."""
    doc = DEFENDER / rel
    assert doc.is_file(), f"the doc carrying {what} moved: {doc}"
    body = doc.read_text(encoding="utf-8")
    assert anchor in body, (
        f"{rel} no longer contains {anchor!r}, so the section carrying {what} was renamed or "
        f"removed rather than corrected — and this check would pass by not applying"
    )
    assert stale not in body, (
        f"{rel} still carries the falsified statement for {what}: {stale!r}"
    )
