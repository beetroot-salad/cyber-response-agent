"""#1546 sketch (r6), "The box" (D2, D3, D4; A-O10): the scrub returns a three-state verdict, never writes `ran: true`
for a tree it refuses, counts an unreadable entry as `tainted`; a learning family's arm whose tree is tainted is not
verified; the box binds its run folder read-only and runs the alias-ban start probe from `/tmp`.

No services: the scrub over real trees, `verify_family` over a real episode (`_triplet_947`), and `start_box` over
`e2e/_box665.RecordingDocker` (the real argv build, no daemon). The last case needs a native daemon (`live`).

Seams: `box._scrub.scrub(...)` returns the verdict word for a clean walk (r6: "`scrub()` returns its verdict"); it
still raises `RunTainted` for a tainted one. FORCED CHOICE: the verdict file's shape (r6 keeps the file "inside the
job" and says `_scrub_ran` "reads the three states", not their spelling); these cases never read the file
themselves, only through production's readers (`tree_verified`, `verify_family`, and the seam
`box._scrub.verdict_state(tree) -> "clean" | "tainted" | "not_run" | None`, the one reader of the three states).
"""
from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from defender.tests.e2e._box665 import DEFENDER, make_run_dir
from defender.tests.support.tenancy._host1214 import TEST_TENANT


def _clean_tree(tmp_path: Path, name: str = "run") -> Path:
    tree = tmp_path / "runs" / name
    (tree / "gather_raw").mkdir(parents=True)
    (tree / "gather_raw" / "a.json").write_text("{}", encoding="utf-8")
    return tree


def test_a_clean_walk_returns_clean_and_reads_verified(tmp_path):
    from defender.box import _scrub

    tree = _clean_tree(tmp_path)
    assert _scrub.scrub(tree) == "clean"
    assert _scrub.verdict_state(tree) == "clean"
    assert _scrub.tree_verified(tree) is True


def test_a_tainted_tree_raises_its_findings_and_never_reads_verified(tmp_path):
    """A hard link inside the tree: `RunTainted` with the finding, and the verdict beside the tree does not read
    verified (today it records `ran: true` first, `box/_scrub.py:211,218`). (D2, A-O10)"""
    from defender.box import _scrub

    tree = _clean_tree(tmp_path)
    os.link(tree / "gather_raw" / "a.json", tree / "alias.json")
    with pytest.raises(_scrub.RunTainted) as raised:
        _scrub.scrub(tree)
    assert {f.kind for f in raised.value.findings} == {"hardlink"}
    assert _scrub.verdict_state(tree) == "tainted"
    assert _scrub.tree_verified(tree) is False


def test_an_unreadable_entry_is_tainted_not_a_skipped_walk(tmp_path):
    """The walk meets an entry it cannot read: `tainted` (r6 A-O10: "an unreadable one included"), not `not_run`.
    Observable: `RunTainted` naming an `unreadable` finding, and the verdict not verified."""
    from defender.box import _scrub

    tree = _clean_tree(tmp_path)

    def lister(top, onerror):
        onerror(OSError(errno.EACCES, "Permission denied", str(Path(top) / "gather_raw")))
        yield str(top), [], []

    with pytest.raises(_scrub.RunTainted) as raised:
        _scrub.scrub(tree, lister=lister)
    assert [f.kind for f in raised.value.findings] == ["unreadable"]
    assert _scrub.verdict_state(tree) == "tainted"
    assert _scrub.tree_verified(tree) is False


def test_a_tainted_arm_is_left_out_of_the_familys_verified_arms(tmp_path, data_root):
    """Three arms; the real scrub walks each tree beside its run (as the arm's own process does); arm b's tree holds a
    hard link. `verify_family` lists a and c as scrub-verified, never b (D3: today `_scrub_ran` reads only `ran`,
    `learning/branch/verification.py:61-73`, so b counts as verified). The episode rule is unchanged otherwise."""
    from defender.box import _scrub
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.support.storage import _spec1133 as S

    ep = T.episode(tmp_path)
    T.plant_roster(ep)
    for label in T.WORLDS:
        run = T.sibling_run_dir(ep / "runs", label, scrub_ran=None)
        if label == "b":
            os.link(run / "investigation.md", run / "alias.md")
        try:
            _scrub.scrub(run)
        except _scrub.RunTainted:
            assert label == "b"

    with S.open_episode(ep) as episode:
        report = T.mod("learning.branch.cli").verify_family(episode, T.family_arms(episode, T.WORLDS),
                                                             source=T.provenance_record())
    assert sorted(report["scrub_verified"]) == sorted(T.world_id(ep, label) for label in ("a", "c"))


def test_the_run_box_binds_its_run_folder_read_only_and_probes_the_alias_ban_from_tmp(tmp_path, data_root):
    """D4: the run lane's run-folder bind is read-only, so the box has no read-write bind of the host's; the alias-ban
    start probe runs with `/tmp` as its working directory (as request boxes already do). (`box/_lifecycle.py:121`,
    `box/_alias.py:146-150`, `:606`)
    FORCED CHOICE: the start-up sentinel probe (`_plant_sentinel`, `box/_lifecycle.py:317-320`) is host-planted and
    read back through the box, so it survives a read-only bind; but `test_the_box_keeps_network_none_and_one_rw_bind`
    (`tests/storage/test_box_and_read_gate.py:103`) pins exactly one rw bind: r6/D4 says such tests "get updated",
    without saying whether the box keeps any host rw bind (none, here)."""
    from defender import box as box_mod
    from defender.box._lifecycle import _run_lane_mounts
    from defender.tests.e2e._box665 import RecordingDocker
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root

    run_dir = make_run_dir(tmp_path)
    lane = _run_lane_mounts(run_dir, DEFENDER, None)
    docker = RecordingDocker()
    box = box_mod.start_box(run_dir, DEFENDER, docker=docker, tenant_id=TEST_TENANT, data_root=current_data_root())
    try:
        argv = docker.create_argv or []
        binds = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
        probes = [c for c in docker.calls if "exec" in c and any("alias-probe" in str(a) for a in c)]
    finally:
        box_mod.stop_box(box, docker=docker)
    seen = {"lane_run_readonly": [m.readonly for m in lane if m.source == run_dir],
            "rw_binds": [b for b in binds if "readonly" not in b],
            "probe_cwds": sorted({c[c.index("-w") + 1] for c in probes})}
    assert seen == {"lane_run_readonly": [True], "rw_binds": [], "probe_cwds": ["/tmp"]}, seen


@pytest.mark.e2e
@pytest.mark.live
def test_a_live_box_cannot_create_a_file_in_its_run_folder(tmp_path, data_root):
    """"Done when": a box cannot create a file in its run folder (a real daemon; under docker-outside-of-Docker the
    run folder sits under the shared anchor, as `test_alert_place._live_tree` does)."""
    import shutil
    import uuid

    from defender import box as box_mod
    from defender.execution import bash_exec
    from defender.tests.support.sandbox._docker import daemon_reachable, dood_anchor, is_dood
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root

    if not daemon_reachable():
        pytest.skip("no reachable Docker daemon")
    base = tmp_path
    if is_dood():
        anchor = dood_anchor()
        if anchor is None:
            pytest.skip("docker-outside-of-Docker with no shared anchor")
        base = anchor / f"t1546-{uuid.uuid4().hex[:12]}"
        base.mkdir(parents=True)
    run_dir = make_run_dir(base)
    try:
        box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod.run_docker, tenant_id=TEST_TENANT,
                                data_root=current_data_root())
    except box_mod.BoxFault as fault:
        if "docker-outside-of-Docker" in str(fault):
            pytest.skip(f"this host cannot bind the run folder: {fault}")
        raise
    try:
        cmd = "printf x > /runs/current/made-in-box"
        res = box.run_parsed(bash_exec.parse(cmd), command=cmd, cwd=Path("/runs/current"), timeout=60.0)
    finally:
        box_mod.stop_box(box)
    made = (run_dir / "made-in-box").exists()
    if base != tmp_path:
        shutil.rmtree(base, ignore_errors=True)
    assert res.rc != 0
    assert not made
