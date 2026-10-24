"""#771 — lifecycle half: the §7 D2 scan-verdict marker (written on both reap arms, kept outside the tree it judges, unmarked tree reads unverified), fail-closed partial scans, guarded setup writers, and box-start / teardown fault handling."""
from __future__ import annotations

import contextlib
import errno
import json
import os
import shutil
import tarfile
from pathlib import Path

import pytest

from defender import box as box_mod
from defender.box import _scrub as scrub_mod
from defender.tests.e2e._box665 import reaped_after_create
from defender.tests.e2e._spec771 import (
    BAN_ABSENT,
    BAN_IN_FORCE,
    CENSUS,
    FORGED_IN_TREE_VERDICT_NAME,
    AliasProbeDocker,
    DockerFault,
    ban_not_in_force_error,
    drive_writer,
    outside,
    plant_hardlink,
    plant_symlink,
    quarantine_a_tainted_tree,
    read_verdict,
    run_tree,
    tree_verified,
    verdict_sidecar,
    worktree_tree,
    write_verdict,
)

pytestmark = pytest.mark.e2e

DEFENDER = Path(__file__).resolve().parents[2]


class _Recorder:
    """A recording `stop_box`/`scrub_tree` pair for driving `stop_and_scrub` directly — the
    seams the reap pair already carries as REQUIRED keyword arguments."""

    def __init__(self, *, stop_fault: BaseException | None = None):
        self.events: list[str] = []
        self._stop_fault = stop_fault

    def stop_box(self, _box, *_a, **_kw) -> None:
        self.events.append("stop")
        if self._stop_fault is not None:
            raise self._stop_fault

    def scrub_tree(self, tree: Path) -> None:
        self.events.append("scrub")
        scrub_mod.scrub(tree)


# §7 D2 — the scan that never ran
@pytest.mark.parametrize("in_flight", [False, True], ids=["teardown-fault", "in-flight-failure"])
def test_a_skipped_reap_scan_leaves_a_did_not_run_marker(in_flight, tmp_path):
    tree = run_tree(tmp_path)
    before_tree = {str(p.relative_to(tree)) for p in tree.rglob("*")}
    rec = _Recorder(stop_fault=box_mod.BoxFault("teardown failed"))

    with contextlib.suppress(box_mod.BoxFault):
        box_mod.stop_and_scrub(object(), tree, stop_box=rec.stop_box,
                               scrub_tree=rec.scrub_tree, in_flight=in_flight)

    assert "scrub" not in rec.events, (
        "the walk ran after a teardown fault — the premise this demand exists for moved, and "
        "the marker is now testing nothing"
    )
    verdict = read_verdict(tree)
    assert verdict, f"the skipped scan left no verdict at {verdict_sidecar(tree)}"
    assert verdict.get("ran") is False, f"the verdict does not record the skip: {verdict}"
    assert verdict.get("reason"), "the verdict names no reason, so an operator cannot act on it"
    new_in_tree = {str(p.relative_to(tree)) for p in tree.rglob("*")} - before_tree
    assert not new_in_tree, (
        f"recording the skipped scan created entries INSIDE the tree it judges "
        f"({sorted(new_in_tree)}) — the box owns that tree, so a verdict written there is one "
        f"it can plant an alias at or author outright"
    )


def test_consumers_treat_an_unmarked_tree_as_unverified(tmp_path):
    never_started = run_tree(tmp_path / "never-started")
    assert not tree_verified(never_started), (
        "a tree whose box never started read as verified — the crash path most likely to hold "
        "what a box planted is the one that must not"
    )

    skipped = run_tree(tmp_path / "skipped")
    write_verdict(skipped, {"ran": False, "reason": "teardown faulted"})
    assert not tree_verified(skipped)

    scanned = run_tree(tmp_path / "scanned")
    scrub_mod.scrub(scanned)
    assert tree_verified(scanned), (
        "a tree the scan walked clean still reads as unverified, so every consumer is stranded"
    )


def test_the_scan_verdict_lands_outside_the_tree_it_judges(tmp_path):
    for build in (run_tree, worktree_tree):
        tree = build(tmp_path / build.__name__)
        before = {str(p.relative_to(tree)) for p in tree.rglob("*")}

        scrub_mod.scrub(tree)

        marker = verdict_sidecar(tree)
        assert marker.is_file(), (
            f"the completed walk over {tree.name} left no verdict at {marker} — a tree with no "
            f"verdict is unverified, so every clean run of this lane is stranded"
        )
        assert not marker.is_relative_to(tree), (
            "the verdict landed inside the tree it judges, which is the siting D8 rejected"
        )
        assert {str(p.relative_to(tree)) for p in tree.rglob("*")} == before, (
            f"the scan wrote into {tree.name} while judging it — the walk is a reader, and a "
            f"reader that writes is a writer no census counted"
        )
        assert tree_verified(tree), "a tree the scan walked clean still reads as unverified"


def test_a_verdict_planted_inside_the_tree_is_never_read_as_one(tmp_path):
    tree = run_tree(tmp_path)
    forged = tree / FORGED_IN_TREE_VERDICT_NAME
    forged.write_text(json.dumps({"ran": True, "reason": "clean"}), encoding="utf-8")

    assert not tree_verified(tree), (
        "a verdict written INSIDE the tree was read as authoritative — the box is root on that "
        "mount, so this is the attacker certifying their own tree"
    )

    write_verdict(tree, {"ran": True, "reason": "walk completed"})
    assert tree_verified(tree), (
        "the real out-of-tree verdict does not make the tree read verified either, so the "
        "negative above passes by the consumer refusing everything"
    )
    assert forged.is_file(), "the consumer removed the planted entry — reading must not sanitize"


def test_a_quarantined_tainted_tree_carries_its_verdict_beside_the_archive(tmp_path):
    qdir = tmp_path / "quarantine"

    judged = run_tree(tmp_path / "judged")
    archive, doc = quarantine_a_tainted_tree(
        judged, qdir, batch_id="b-judged", verdict={"ran": True, "reason": "walk completed"})

    assert archive is not None, "nothing was preserved at all, so the rest of this is vacuous"
    assert archive.is_file(), f"the quarantine reported {archive} and wrote nothing there"
    with tarfile.open(archive) as tar:
        members = {Path(m.name).name for m in tar.getmembers()}
    assert FORGED_IN_TREE_VERDICT_NAME not in members, (
        "the verdict is inside the archive, so it was inside the tree — D8's siting is undone"
    )
    assert doc.get("verdict") == read_verdict(judged), (
        f"the quarantine manifest does not carry the tree's verdict: {doc.get('verdict')!r} — "
        f"the archive is a tar of the tree and the marker is not in the tree, so this manifest "
        f"is the only thing that can tell a human whether the tree was ever judged"
    )

    unjudged = run_tree(tmp_path / "unjudged")
    _archive, doc2 = quarantine_a_tainted_tree(unjudged, qdir, batch_id="b-unjudged")
    assert "verdict" in doc2, (
        "a tree with no verdict produced a manifest with no verdict FIELD — indistinguishable "
        "from a manifest written before the field existed, so an unjudged tree reads as one "
        "nobody thought to record"
    )
    assert not doc2["verdict"], (
        f"the manifest invented a verdict for a tree that has none: {doc2['verdict']!r}"
    )


def test_a_partial_reap_scan_failure_fails_closed_over_the_whole_tree(tmp_path):
    tree = run_tree(tmp_path)

    def half_walk(root, **_kw):
        yield str(tree), [], ["alert.json"]
        yield str(tree), [], ["vanished.json"]      # listed, then not there to inspect

    with pytest.raises(scrub_mod.RunTainted) as e:
        scrub_mod.scrub(tree, lister=half_walk)

    assert "vanished.json" in str(e.value), "the partial walk's fault does not name the entry"
    assert read_verdict(tree).get("ran") is not True, (
        "a partially-walked tree recorded a completed scan, so a consumer reads it as verified"
    )


def test_an_entry_that_changes_shape_between_listing_and_inspection_is_refused(tmp_path):
    tree = run_tree(tmp_path)
    victim = tree / "report.md"
    victim.write_text("ordinary\n", encoding="utf-8")
    target = outside(tmp_path)

    def swapping_walk(root, **_kw):
        victim.unlink()
        plant_symlink(victim, target)               # the shape changes inside the window
        yield str(tree), [], ["report.md"]

    with pytest.raises(scrub_mod.RunTainted) as e:
        scrub_mod.scrub(tree, lister=swapping_walk)

    assert "report.md" in str(e.value)


def test_the_pre_first_turn_setup_writers_are_individually_guarded_in_any_order(tmp_path):
    setup = [w for w in CENSUS if w.id in {"start_box", "write_case_pointer"}]
    assert len(setup) == 2, "the pre-first-turn setup writer set drifted from the pin's two"

    for label, order in (("forward", setup), ("reversed", list(reversed(setup)))):
        d = tmp_path / label
        d.mkdir()
        run = run_tree(d)
        target = outside(d)
        original = target.read_bytes()
        for writer in order:
            plant_symlink(run / writer.artifact, target)

        for writer in order:
            refused = isinstance(drive_writer(writer, run), BaseException)
            assert target.read_bytes() == original, (
                f"{label}: {writer.id} redirected its setup write after "
                f"{[w.id for w in order[:order.index(writer)]]} ran ahead of it, so the order "
                f"IS load-bearing and the pin is wrong"
            )
            assert refused, (
                f"{label}: {writer.id} left the outside file alone but did not refuse either — "
                f"a guarded write that silently no-ops on every call (not only the aliased one) "
                f"passes the identity check above vacuously"
            )
            assert os.path.islink(run / writer.artifact), (
                f"{label}: {writer.id} removed the planted alias, so the writers that follow it "
                f"in this order meet a clean tree and the sequence proves nothing"
            )


def test_a_live_run_dir_is_never_reused_and_a_stale_mount_never_follows_it(tmp_path, monkeypatch):
    from defender import run_common
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    data_root = tmp_path / "data"
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(data_root))
    tenant = set_up_tenant(data_root, fixture_uuid("tenant:t771"))
    alert = tmp_path / "alert.json"
    alert.write_text('{"id": "a-771"}\n', encoding="utf-8")

    # ARM 1 — the run dir's creation is exclusive: a directory a RUN has been in is refused, and
    # touched in no way. A container from that run may still be mounted on the tree. (#1279 O8:
    # there is no resume, so setup-only leftovers are refused too.)
    first_run = run_common.materialize_run(alert, tenant=tenant)
    first = first_run.run_dir
    (first / "report.md").write_text("FIRST RUN\n", encoding="utf-8")
    before = sorted(p.name for p in first.iterdir())

    with pytest.raises(FileExistsError):
        first_run.make_run_dir()

    assert sorted(p.name for p in first.iterdir()) == before, (
        "the refused mint still wrote into the existing tree"
    )
    assert (first / "report.md").read_text(encoding="utf-8") == "FIRST RUN\n", (
        "the refused mint overwrote the earlier run's artifact"
    )
    # The complementary condition: a FRESH run under the same base materializes, so the refusal
    # above is the existing directory and not a mint that fails on everything.
    fresh = run_common.materialize_run(alert, tenant=tenant).run_dir
    assert fresh.is_dir(), "no run dir can be minted at all under this base"
    assert fresh != first, "a fresh run minted the same directory the refusal was about"

    # ARM 2 — a reference taken while the tree was alive is a reference to the OBJECT. This
    # re-probes the kernel rule on every run rather than pinning a one-time observation of it.
    pinned = os.open(str(first), os.O_RDONLY | os.O_DIRECTORY)
    try:
        from defender.tests.support.storage._alert_plant import unseal_fixture_input
        unseal_fixture_input(first)
        shutil.rmtree(first)
        first.mkdir()
        (first / "report.md").write_text("SECOND RUN\n", encoding="utf-8")

        assert (first / "report.md").read_text(encoding="utf-8") == "SECOND RUN\n", (
            "the recreated tree holds nothing, so the three checks below would pass by having "
            "nothing to find — the vacuous shape this arm fails into"
        )
        assert os.listdir(pinned) == [], (
            f"the reference followed the path to the recreated directory and now lists the "
            f"later run's files: {os.listdir(pinned)}"
        )
        with pytest.raises(FileNotFoundError):
            os.open("report.md", os.O_RDONLY, dir_fd=pinned)
        with pytest.raises(FileNotFoundError):
            os.open("planted", os.O_WRONLY | os.O_CREAT, dir_fd=pinned)
    finally:
        os.close(pinned)

    # ARM 3 — the half this codebase owns: what the box actually pins.
    run = run_tree(tmp_path / "boxed")
    rec = AliasProbeDocker(BAN_IN_FORCE)
    box_mod.start_box(run, DEFENDER, docker=rec)

    argv = rec.create_argv or []
    specs = [tok for prev, tok in zip(argv, argv[1:], strict=False) if prev == "--mount"]
    assert specs, "the lane rendered no mount at all, so the two checks below look at nothing"
    assert all(s.startswith("type=bind,") for s in specs), (
        f"a box mount is no longer a bind: {specs} — a mount type that resolves its host path "
        f"lazily follows a directory recreated at that path, and the isolation this premise "
        f"rests on is gone without any code #771 touches having changed"
    )
    writable = [m for m in rec.mounts() if not m["readonly"]]
    assert len(writable) == 1, f"the writable bind set moved: {writable}"
    assert Path(writable[0]["source"]).resolve() == run.resolve(), (
        f"the writable bind is sourced at {writable[0]['source']!r} rather than at the run dir "
        f"itself — an ancestor source pins a directory the run dir's deletion never removes, so "
        f"a container from an earlier run walks straight into the later run's tree"
    )


def test_a_planted_hard_link_still_refuses_the_guarded_write(tmp_path):
    """guarded_write_refuses_a_hard_link — the guarded primitive refuses a HARD LINK planted at
    an artifact name, not only a symlink: the aliased file outside the tree keeps its bytes."""
    run = run_tree(tmp_path)
    target = outside(tmp_path)
    original = target.read_bytes()
    planted = plant_hardlink(run / "report.md", target)

    with pytest.raises(OSError) as e:  # noqa: PT011 — the errno is asserted immediately below
        write_guarded_hardlink_arm(planted)

    assert e.value.errno in (errno.EEXIST, errno.EMLINK), (
        f"the refusal did not come from the link-count check: errno={e.value.errno} — under a "
        f"hard-link plant `O_NOFOLLOW` does not fire at all (B9), so an ELOOP here would mean "
        f"the primitive refused for a reason this plant cannot produce"
    )
    assert target.read_bytes() == original, "the guarded write truncated through the hard link"
    assert os.lstat(target).st_nlink == 2, "the refusal unlinked the plant (sanitizing)"


def write_guarded_hardlink_arm(path: Path) -> None:
    """Drive the guarded primitive at `path` — split out so the demand's test body reads as
    one assertion about one observable."""
    from defender.tests.e2e._spec771 import write_guarded

    write_guarded(path, "REDIRECTED\n")


def test_the_box_start_fault_removes_the_container_it_created(tmp_path):
    """box_start_fault_reaps_its_container — a box whose ban probe failed is removed rather than
    left running, so a faulted start leaks no container holding the shared tree open."""
    rec = AliasProbeDocker(BAN_ABSENT)
    with pytest.raises(ban_not_in_force_error()):
        box_mod.start_box(run_tree(tmp_path), DEFENDER, docker=rec)

    assert reaped_after_create(rec.calls), "the faulted start left its container running"


def test_a_teardown_fault_under_an_in_flight_failure_still_reports_both(tmp_path):
    tree = run_tree(tmp_path)
    rec = _Recorder(stop_fault=box_mod.BoxFault("teardown failed while a run error was in flight"))
    in_flight_failure = RuntimeError("the investigation itself failed")

    escaped: BaseException | None = None
    try:
        try:
            raise in_flight_failure
        finally:
            box_mod.stop_and_scrub(object(), tree, stop_box=rec.stop_box,
                                   scrub_tree=rec.scrub_tree, in_flight=True)
    except BaseException as e:  # noqa: BLE001 — WHICH exception escapes is the observable
        escaped = e

    assert escaped is in_flight_failure, (
        f"the run's own failure did not reach the caller: {escaped!r} — the work's own error "
        f"is the more informative signal, and a teardown BoxFault raised on top of it replaces "
        f"the reason the run was already dying with a complaint about the box"
    )
    assert "stop" in rec.events, "the teardown never ran, so nothing could have faulted"
    verdict = read_verdict(tree)
    assert verdict.get("ran") is False, (
        f"the swallowed teardown left no did-not-run verdict on the tree: {verdict}"
    )
    assert "teardown" in str(verdict.get("reason", "")).lower(), (
        f"the swallowed teardown fault left no trace of its cause: {verdict}"
    )


def test_a_faulted_box_create_leaves_a_verdict_on_the_tree_it_touched(tmp_path):
    run = run_tree(tmp_path)
    rec = AliasProbeDocker(BAN_IN_FORCE,
                           create=DockerFault(rc=1, stderr="no such image\n", cite="R3"))

    with pytest.raises(box_mod.BoxFault):
        box_mod.start_box(run, DEFENDER, docker=rec)

    verdict = read_verdict(run)
    assert verdict, (
        f"a faulted create left no verdict at {verdict_sidecar(run)} for the tree the host had "
        f"already written into — this demand would then discharge to the absence rule its "
        f"sibling already pins, and the provisional pin reads as confirmed untested"
    )
    assert verdict.get("ran") is False, f"the verdict does not record the skip: {verdict}"
    assert verdict.get("reason"), (
        "the verdict names no reason, so an operator meeting this tree cannot tell a faulted "
        "create from any other unscanned tree"
    )
    assert not tree_verified(run), (
        "a tree whose box never started reads as verified — the fail-closed default D2 sets"
    )
