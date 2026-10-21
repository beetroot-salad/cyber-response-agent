"""#1047 O3 — each archived world carries a HOST-WRITTEN record of how its run ended."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json

import pytest
from defender.tests.support.storage._alert_plant import plant_alert

from defender.episodes._episode_handle import Episode
from defender.tests.support.shared.filesystem import _spec1047 as S
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.learning.branch import _triplet_947 as T


def _archive():
    return S.mod("learning.branch.archive")


def _episode_with(tmp_path, worlds=("b", "c"), **kw):
    """An episode dir plus a runs base holding one finished sibling run dir per world."""
    base, _src = location_path(S.runs_base)(tmp_path)
    ep = S.episode(tmp_path)
    return ep, {w: S.sibling_run_dir(base, w, **kw) for w in worlds}, base


def _record(episode_dir, label):
    path = episode_dir / "worlds" / T.world_id(episode_dir, label) / S.run_end_name()
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


# the archive writes the record itself


def test_the_archive_writes_each_worlds_run_end_record_itself(tmp_path):
    ep, dirs, _base = _episode_with(tmp_path)
    S.plant_sidecar(dirs["b"], truncated_by="request-limit")
    S.plant_sidecar(dirs["c"], truncated_by="aborted", closed_before_cut=True)
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    assert _record(ep, "b") == {"truncated_by": "request-limit", "closed_before_cut": False}
    assert _record(ep, "c") == {"truncated_by": "aborted", "closed_before_cut": True}


def test_the_worlds_exit_class_is_read_from_a_source_no_box_can_write(tmp_path):
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="store", closed_before_cut=True)
    for planted in S.salt_run_dir(dirs["b"], value="request-limit"):
        assert planted.exists(), f"the fixture failed to plant {planted}"
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    assert _record(ep, "b") == {"truncated_by": "store", "closed_before_cut": True}, (
        "the archived record does not match the host's own sidecar — something inside the "
        "box's rw bind reached it")


def test_a_forged_run_end_file_in_the_run_dir_is_never_the_archived_one(tmp_path):
    """A run dir holding a file at the archived record's own name is archived with the host's own
    record, byte-for-byte — the planted file's content never appears in worlds/<label>/."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="aborted")
    forged = {"truncated_by": "request-limit", "closed_before_cut": True, "forged": True}
    (dirs["b"] / S.run_end_name()).write_text(json.dumps(forged), encoding="utf-8")
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    archived = _record(ep, "b")
    assert archived == {"truncated_by": "aborted", "closed_before_cut": False}, (
        f"the planted file reached the archive: {archived!r}")
    assert "forged" not in json.dumps(archived)


def test_a_pre_existing_record_at_the_destination_is_overwritten_through_the_guarded_seam(
        tmp_path):
    """A pre-existing REGULAR FILE at `worlds/<label>/run_end.json` is overwritten with the host's
    own record; a pre-existing HARD LINK there is refused rather than written through."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="budget")
    dest = ep / "worlds" / T.world_id(ep, "b")
    dest.mkdir(parents=True, exist_ok=True)
    (dest / S.run_end_name()).write_text('{"truncated_by": "PRE-EXISTING"}', encoding="utf-8")
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    assert _record(ep, "b") == {"truncated_by": "budget", "closed_before_cut": False}, (
        "a stale record at the destination survived a re-archive; a retried world would keep "
        "reporting the attempt it no longer has")

    victim = tmp_path / "victim.json"
    victim.write_text("VICTIM\n", encoding="utf-8")
    linked_ep, linked_dirs, _b2 = _episode_with(tmp_path / "linked", worlds=("b",))
    S.plant_sidecar(linked_dirs["b"], truncated_by="budget")
    world = linked_ep / "worlds" / T.world_id(linked_ep, "b")
    world.mkdir(parents=True, exist_ok=True)
    (world / S.run_end_name()).hardlink_to(victim)
    with pytest.raises(S.refusals()), Episode.open(linked_ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in linked_dirs.items()})
    assert victim.read_text(encoding="utf-8") == "VICTIM\n", (
        "the archive wrote this world's record through a hard link planted at the "
        "destination, landing it outside the archive tree")
    assert not (world / "report.md").exists(), (
        "the archive copied part of the world before refusing the planted hard link")


def test_an_unreadable_sidecar_is_copied_verbatim_and_the_judge_reads_no_record(tmp_path):
    for name, raw in (("empty", ""), ("torn", '{"truncated_by": "abor'),
                      ("list", '[{"truncated_by": "aborted"}]')):
        ep, dirs, _base = _episode_with(tmp_path / name, worlds=("b",))
        S.plant_sidecar(dirs["b"], raw=raw)
        with Episode.open(ep) as episode:
            _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
        archived = ep / "worlds" / T.world_id(ep, "b") / S.run_end_name()
        assert archived.read_text(encoding="utf-8") == raw, (
            f"{name}: the archive rewrote the sidecar's bytes instead of copying them")
        assert (ep / "worlds" / T.world_id(ep, "b") / "report.md").is_file(), (
            f"{name}: an unreadable sidecar cost the world its other artifacts")
        graded = S.cut_short_episode(tmp_path / f"{name}-graded")
        S.plant_archived_record(graded, "b", raw=raw)
        row = S.graded(graded)["b"]
        assert row.get("ungradable") is not True, (
            f"{name}: bytes that hold no record made the world ungradable")
        assert row.get("cut_short") is None


def test_a_directory_squatting_the_sidecars_name_refuses_the_world_like_any_planted_entry(
        tmp_path):
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.sidecar_path(dirs["b"]).mkdir(parents=True, exist_ok=True)
    with pytest.raises(S.refusals()), Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    assert not (ep / "worlds" / T.world_id(ep, "b") / "report.md").exists(), (
        "the archive copied part of the world before refusing it")


# the destination is screened — a link at the record's own name is never followed


def test_a_destination_side_symlink_at_the_run_end_path_pointing_outside_the_archive_tree_is_never_followed_for_the_write(
        tmp_path):
    outside = tmp_path / "outside" / "stolen.json"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text("OUTSIDE\n", encoding="utf-8")
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="store")
    world = ep / "worlds" / T.world_id(ep, "b")
    world.mkdir(parents=True, exist_ok=True)
    (world / S.run_end_name()).symlink_to(outside)
    with pytest.raises(S.refusals() + (OSError,)), Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    assert outside.read_text(encoding="utf-8") == "OUTSIDE\n", (
        "the archive followed a link out of the archive tree and wrote this world's record "
        "over a file the episode does not own")


def test_a_symlink_planted_inside_the_run_dir_at_the_sidecars_basename_is_not_read_as_the_run_end_record(
        tmp_path):
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="budget")
    decoy = tmp_path / "decoy.json"
    decoy.write_text(json.dumps({"truncated_by": "request-limit"}), encoding="utf-8")
    inside = dirs["b"] / S.sidecar_path(dirs["b"]).name
    inside.symlink_to(decoy)
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    assert _record(ep, "b") == {"truncated_by": "budget", "closed_before_cut": False}


# the sidecar's own identity, and the fan that writes several of them


def test_the_host_side_record_source_is_not_reachable_from_inside_a_box(tmp_path):
    """NOT reachable: the investigation box mounts exactly the run dir (rw), the defender dir (ro)
    and a tmpfs (claims h23, n2), and the sidecar's parent is not bound."""
    from defender.box._lifecycle import _create_argv
    from defender.box._spec import BoxSpec

    run_dir = tmp_path / "defender-runs" / "2026-09-16T12-00-00Z_case-1047"
    run_dir.mkdir(parents=True, exist_ok=True)
    plant_alert(run_dir)
    sidecar = S.sidecar_path(run_dir)
    # An explicit rootfs: the tree is fake (no `box.Dockerfile`/`uv.lock`/`pyproject.toml`),
    # and with `rootfs` unset the builder would resolve the image from it and refuse (#1092).
    argv = _create_argv(
        "defender-run-1047", run_dir, tmp_path / "srv" / "defender",
        BoxSpec(rootfs="python:3.11-slim"), (),
    ).argv
    rw_specs = [spec for spec in argv if spec.startswith("type=bind,") and "readonly" not in spec]
    writable = [spec.split("source=", 1)[1].split(",", 1)[0] for spec in rw_specs]
    assert writable == [str(run_dir)], (
        f"the box's writable binds are {writable}; O3's whole argument is that there is "
        "exactly one and it is the run dir")
    # #1255 (design rev 4, P1): the box sees that bind at the model view's `/runs/current`; the
    # sidecar's containment is judged on the bind's host SOURCE, which is the run dir.
    assert [spec.split("target=", 1)[1].split(",", 1)[0] for spec in rw_specs] == [
        "/runs/current"], rw_specs
    assert not str(sidecar).startswith(str(run_dir) + "/"), (
        f"{sidecar} is inside the box's own rw bind — the record would be forgeable by the "
        "subject it is about")
    assert sidecar.parent == run_dir.parent


def test_the_run_end_sidecar_leaf_never_collides_with_a_run_dir_or_another_siblings_leaf_under_runs_base(
        tmp_path):
    ep = S.episode(tmp_path)
    cli = S.mod("learning.branch.cli")
    runs = ep / "runs"  # the siblings' container (#1105 PR 2: `cli.sibling_runs_base` is gone)
    written: dict[str, object] = {}
    faults: list[BaseException] = []

    def spawn(argv, *, env=None, **_kw):
        # `start_family` records a thread that died as a NON-ZERO exit rather than re-raising,
        # so a fault in here would otherwise reach the assertions below as "the launcher fanned
        # nothing" — a message about the wrong thing.
        try:
            label = next(argv[i + 1] for i, tok in enumerate(argv) if tok == "--world")
            # #1187: the child's run folder is the arm id the roster names for its label.
            run_dir = runs / T.read_roster(ep)[T.world_id(ep, label)]
            run_dir.mkdir(parents=True, exist_ok=True)
            S.plant_sidecar(run_dir, truncated_by="aborted")
            written[label] = run_dir
        except BaseException as fault:  # noqa: BLE001 — re-raised verbatim below
            faults.append(fault)
            raise
        return 0

    with Episode.open(ep) as episode:
        # #1105 PR 2: the launcher makes the container (with the tenant's record) before the
        # first sibling; `start_family` no longer does.
        T.episode_view(episode)
        cli.start_family(episode, [T.world_id(ep, label) for label in ("b", "c")], spawn=spawn, tenant_id=T1106.PLAYGROUND_ID)
    if faults:
        raise faults[0]
    assert set(written) == {"b", "c"}, f"the launcher fanned {sorted(written)}"
    leaves = {label: S.sidecar_path(run_dir) for label, run_dir in written.items()}
    assert leaves["b"] != leaves["c"], "both siblings' records landed at one path"
    for label, leaf in leaves.items():
        assert leaf.is_file(), f"{label}: no sidecar at {leaf}"
        for other, run_dir in written.items():
            assert leaf != run_dir, f"{label}'s sidecar collided with {other}'s run dir"
    assert json.loads(leaves["b"].read_text(encoding="utf-8")) == S.record_doc("aborted")


# the driver end: what actually writes the sidecar


def _deps(tmp_path):
    from defender.tests.support.runtime.engine import _spec923

    return _spec923.main_deps(tmp_path)


def test_run_end_write_happens_even_for_a_run_that_ended_cleanly(tmp_path):
    """The sidecar write is UNCONDITIONAL for every run THAT REACHES THE AGENT LOOP: a clean run
    writes {"truncated_by": null}."""
    deps, run_dir = _deps(tmp_path)
    _run, end, _reason = S.drive(deps, S.clean_model())
    assert end.truncated_by is None, "the clean model did not produce a clean run"
    assert S.sidecar_doc(run_dir) == {"truncated_by": None, "closed_before_cut": False}, (
        f"a clean run left {S.sidecar_doc(run_dir)!r} beside its run dir")


def test_the_driver_records_whether_the_model_had_already_closed_when_the_exit_was_stamped(
        tmp_path):
    from defender.runtime import challenge_gate
    from defender.tests.support.runtime.engine import _spec923

    closed_deps, closed_run = _deps(tmp_path / "closed")
    challenge_gate.ReviewState.of(closed_deps).closed = True
    _run, truncated_by, _reason = _spec923.drive_to_retry_exhaustion(closed_deps)
    assert truncated_by is not None, "the run was not cut short at all"
    assert S.sidecar_doc(closed_run) == {"truncated_by": truncated_by,
                                         "closed_before_cut": True}

    open_deps, open_run = _deps(tmp_path / "open")
    _run, open_truncated, _reason = _spec923.drive_to_retry_exhaustion(open_deps)
    assert S.sidecar_doc(open_run) == {"truncated_by": open_truncated,
                                       "closed_before_cut": False}, (
        "the control failed: a run whose model never closed also recorded "
        "`closed_before_cut: true`, so the field distinguishes nothing")


def test_a_failed_run_end_write_is_a_reason_not_to_write_the_forced_report(tmp_path):
    from defender.tests.support.runtime.engine import _spec923

    deps, run_dir = _deps(tmp_path / "blocked")
    blocked = S.sidecar_path(run_dir)
    blocked.mkdir(parents=True, exist_ok=True)
    _run, truncated_by, _reason = _spec923.drive_to_retry_exhaustion(deps)
    assert truncated_by == "retry-exhausted", (
        "the run did not reach a forced-close-set exit, so no forced report was ever owed")
    assert S.sidecar_doc(run_dir) is None, (
        "the fixture failed: the record write landed despite a directory at its own path, so "
        "nothing below is about a FAILED write")
    assert not (run_dir / "report.md").exists(), (
        "the forced `unresolved` report was written although the run-end record write failed "
        "— the report-without-a-record shape claim h2 observed flipping verdict_word from "
        "`caught` to `survived`")

    ok_deps, ok_run = _deps(tmp_path / "ok")
    _run, ok_truncated, _reason = _spec923.drive_to_retry_exhaustion(ok_deps)
    control_failed = (
        "the control failed: the same exit class with a writable sidecar path did not produce "
        "a record AND a forced report, so the suppression above is not about the failed write")
    assert ok_truncated == "retry-exhausted", control_failed
    assert S.sidecar_doc(ok_run) is not None, control_failed
    assert (ok_run / "report.md").is_file(), control_failed


def test_one_world_is_cut_short_while_a_sibling_archive_is_refused(tmp_path):
    """World b archives and grades per its own exit class independently of world c's refusal: the
    archive's refuse-and-report is per-world and per-entry (flagged fact F6), not per-episode."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b", "c"))
    # Archive order is by opaque UUID: arrange the clean world before the refused one.
    first, second = sorted(T.world_id(ep, label) for label in ("b", "c"))
    T.write_family(ep, T.family_doc(worlds=[
        T.base_world(), T.world_doc("b", world_id=first), T.world_doc("c", world_id=second)]))
    S.plant_sidecar(dirs["b"], truncated_by="request-limit")
    S.plant_sidecar(dirs["c"], truncated_by="aborted")
    secret = tmp_path / "secret.md"
    secret.write_text("ROOT-PRIVATE-KEY", encoding="utf-8")
    (dirs["c"] / "report.md").unlink()
    (dirs["c"] / "report.md").symlink_to(secret)
    with pytest.raises(S.refusals()), Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    assert _record(ep, "b") == {"truncated_by": "request-limit", "closed_before_cut": False}, (
        "world c's refusal cost world b the record its own run produced")
    assert not (ep / "worlds" / T.world_id(ep, "c") / "report.md").exists()


def test_a_run_dir_emptied_or_corrupted_by_the_box_at_run_end_still_grades_a_genuinely_cut_short_world_correctly(
        tmp_path):
    """A run dir the box emptied or corrupted at run end still grades a genuinely cut-short world
    correctly: the exit class was captured host-side, beside the run dir, not inside it."""
    import shutil

    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="request-limit")
    for entry in sorted(dirs["b"].iterdir()):
        shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
    assert list(dirs["b"].iterdir()) == [], "the fixture did not empty the run dir"
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    assert _record(ep, "b") == {"truncated_by": "request-limit", "closed_before_cut": False}

    graded = S.cut_short_episode(tmp_path / "graded", cut={"b": "request-limit"})
    assert S.graded(graded)["b"].get("cut_short") == "request-limit"


def test_a_path_traversal_style_value_written_by_the_box_anywhere_in_the_run_dir_cannot_make_any_host_side_write_for_this_feature_land_outside_the_run_dirs_own_bind(
        tmp_path):
    """No host-side path for this feature is derived from box-writable content — every path is
    host-held — so a traversal-shaped value planted in the run dir moves no write."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="aborted")
    escape = "../../../../tmp/defender-1047-escape.json"
    for name in S.FORGEABLE_NAMES:
        (dirs["b"] / name).write_text(
            json.dumps({"truncated_by": escape, "path": escape, "run_end": escape}),
            encoding="utf-8")
    with Episode.open(ep) as episode:
        _archive().archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in dirs.items()})
    assert _record(ep, "b") == {"truncated_by": "aborted", "closed_before_cut": False}
    landed = sorted(p.relative_to(ep) for p in ep.rglob(S.run_end_name()))
    assert [str(p) for p in landed] == [f"worlds/{T.fixture_world_id('b')}/{S.run_end_name()}"], (
        f"the feature's write landed at {landed} — a path derived from box-written content")
