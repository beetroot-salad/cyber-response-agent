"""#1047 O3 — each archived world carries a HOST-WRITTEN record of how its run ended.

THE FORGERY FINDING THAT CHANGED THE DESIGN. The first draft put the exit class in the forced
`report.md`'s frontmatter. The cold review's finding: the judge reads the ARCHIVED report,
copied verbatim from a run dir the box has an rw bind on (claim h4), and `validate_report`
admits unknown keys (claim h3, EXECUTED — a spliced `truncated_by:` line returned `None` from
the validator, i.e. accepted). A planted line would let the graded subject exclude its own
world from grading: a new capability, handed to the adversary by the fix. The field cannot
carry policy.

SO THE RECORD IS THE HOST'S, ON A PATH THE BOX HAS NO BIND ON, END TO END:

1. The sibling's own host-side driver writes a SIDECAR beside its run dir — `verdict_path`'s
   shape (`runtime/scrub.py:124-129`, "the reap scan's verdict lives BESIDE the tree it judges
   … in-tree it would be both PLANTABLE and FORGEABLE"), the precedent F2 reading A chose.
2. `archive_episode` reads that sidecar — never anything inside the run dir — and writes
   `worlds/<label>/run_end.json` itself. The record is NOT in `_single_files`, the copy list: a
   same-named entry in the run dir is not an input to anything.

§7 RESOLUTIONS APPLIED HERE AS SETTLED:

* **F2 reading A (human)** — the sidecar, not a store read. Reading B (launcher-minted session
  ids threaded through argv, archive opens the source store) was rejected as a wider change
  handing the launcher an identity concern it does not have, for the same observable outcome.
* **F-B reading B (human, §7 round 2)** — the write sits in the DRIVER, before the forced
  report. Probe p25 (EXECUTED) drove three arms of `run.py`'s tail that raise and skip
  everything after them — `scrub_tree` raising `RunTainted`, `stop_box` raising `BoxFault`, and
  `run_investigation` itself raising at the unguarded `logger.close()` — and on the third the
  summary never exists, so a tail-sited write has no value to write even in principle.
* **F-F (auto, narrowed by round-2 probe #11, EXECUTED)** — the write goes through
  `write_guarded`, NEVER the `copy2` lane. The executed probe found `copy2` writes THROUGH a
  pre-existing hard link at a destination leaf (a hard link planted at `worlds/<label>/report.md`
  left the link's target holding the archived bytes), where `write_guarded`'s
  `_refuse_unless_plain` refuses `S_ISREG and st_nlink > 1` with `EMLINK`. That hole is
  PRE-EXISTING and affects all six already-archived artifacts; it is out of this piece's scope
  to fix broadly, and it is why the new leaf takes the stricter of the archive's two lanes.
* **F-H (auto, §7 round 2, BOTH clauses)** — a failed record write is swallowed and the run
  continues, logged loudly (every precedent for a post-run write in this tree is best-effort);
  AND, coupled to F-B, that failure is a reason NOT to write the forced report, which closes
  the window F-B was about for a write that RAISED rather than a process that was KILLED. The
  second clause reached no demand, constraint or test until the phase-F reconciliation; it is
  pinned here by `test_a_failed_run_end_write_is_a_reason_not_to_write_the_forced_report`.
* **F-G / F-AB (auto)** — an unreadable or type-mismatched sidecar is SKIPPED AND REPORTED,
  reusing the archive's existing absent/planted/refused three-way split rather than minting a
  fourth answer.
* **F-U (human, §7 round 2)** — a real I/O error gets no special-casing: round-2 probe #11
  found the existing destination screen already lets EIO/EACCES propagate as a bare `OSError`
  for its other six artifacts (only ENOENT/ENOTDIR/EBADF/ELOOP fold into "absent"), and the new
  leaf is consistent with that rather than an outlier.

RED against `59bdea44`: `runtime/run_end.py` does not exist, the archived run-end record has
no name anywhere, and `archive_episode` writes six single files and knows nothing about it.
(That name now lives on `_episode_paths`, reached as `WORLD_LEAVES.run_end` — #1077 D7 —
rather than as a constant re-exported from the archive module.)
"""
from __future__ import annotations

import json

import pytest

from defender.tests import _spec1047 as S


def _archive():
    return S.mod("learning.branch.archive")


def _episode_with(tmp_path, worlds=("b", "c"), **kw):
    """An episode dir plus a runs base holding one finished sibling run dir per world."""
    base, _src = S.runs_base(tmp_path)
    ep = S.episode(tmp_path)
    return ep, {w: S.sibling_run_dir(base, w, **kw) for w in worlds}, base


def _record(episode_dir, label):
    path = episode_dir / "worlds" / label / S.run_end_name()
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


# ---------------------------------------------------------------------------------------
# the archive writes the record itself
# ---------------------------------------------------------------------------------------


def test_the_archive_writes_each_worlds_run_end_record_itself(tmp_path):
    """archive_episode writes worlds/<label>/run_end.json for each archived world, carrying the
    exit class the sibling's own host-side process recorded in its sidecar, copied in the same
    screened way the scrub verdict already is — never read from anything the box wrote inside
    the run dir.

    Both fields land, because both are the record: `truncated_by` and `closed_before_cut`
    (F-A reading B). The two worlds carry different exit classes so "the record is per world"
    is observable rather than assumed."""
    ep, dirs, _base = _episode_with(tmp_path)
    S.plant_sidecar(dirs["b"], truncated_by="request-limit")
    S.plant_sidecar(dirs["c"], truncated_by="aborted", closed_before_cut=True)
    _archive().archive_episode(ep, dirs)
    assert _record(ep, "b") == {"truncated_by": "request-limit", "closed_before_cut": False}
    assert _record(ep, "c") == {"truncated_by": "aborted", "closed_before_cut": True}


def test_the_worlds_exit_class_is_read_from_a_source_no_box_can_write(tmp_path):
    """The value the archive writes is taken from a host-owned sidecar beside the run dir,
    outside every box's rw bind; with the run dir emptied of every file a box could have
    written, the archived record still names the exit — and still says whether the model had
    already closed.

    The run dir keeps only what the archive's other six roles need to exist at all; every one
    of them is then replaced with a forgery naming a different exit class. The record the
    archive writes is the sidecar's, on both fields."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="store", closed_before_cut=True)
    for planted in S.salt_run_dir(dirs["b"], value="request-limit"):
        assert planted.exists(), f"the fixture failed to plant {planted}"
    _archive().archive_episode(ep, dirs)
    assert _record(ep, "b") == {"truncated_by": "store", "closed_before_cut": True}, (
        "the archived record does not match the host's own sidecar — something inside the "
        "box's rw bind reached it")


def test_a_forged_run_end_file_in_the_run_dir_is_never_the_archived_one(tmp_path):
    """A run dir holding a file at the archived record's own name is archived with the host's
    own record, byte-for-byte — the planted file's content never appears in worlds/<label>/.

    Positive control: `test_the_archive_writes_each_worlds_run_end_record_itself`, the same
    archive over the same sidecar with nothing planted, which produces the record this test
    asserts is unchanged."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="aborted")
    forged = {"truncated_by": "request-limit", "closed_before_cut": True, "forged": True}
    (dirs["b"] / S.run_end_name()).write_text(json.dumps(forged), encoding="utf-8")
    _archive().archive_episode(ep, dirs)
    archived = _record(ep, "b")
    assert archived == {"truncated_by": "aborted", "closed_before_cut": False}, (
        f"the planted file reached the archive: {archived!r}")
    assert "forged" not in json.dumps(archived)


def test_a_pre_existing_record_at_the_destination_is_overwritten_through_the_guarded_seam(
        tmp_path):
    """A pre-existing REGULAR FILE at `worlds/<label>/run_end.json` is overwritten with the
    host's own record; a pre-existing HARD LINK there is refused rather than written through.

    Fork F-F, found by round-2 probe #11 (EXECUTED): the archive's `copy2` lane silently
    overwrites a regular file AND wrote through a hard link at a destination leaf, while
    `write_guarded`'s `_refuse_unless_plain` refuses `S_ISREG and st_nlink > 1`. Resolved at
    the LANE: the record is the seventh single file, and the lane's pre-copy destination
    screen now refuses a hard link at any of the seven (`_run_paths.plain_file`) — so a
    planted alias cannot redirect the host's own record, or any other artifact, out of the
    archive, and the whole world is refused before a byte lands."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="budget")
    dest = ep / "worlds" / "b"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / S.run_end_name()).write_text('{"truncated_by": "PRE-EXISTING"}', encoding="utf-8")
    _archive().archive_episode(ep, dirs)
    assert _record(ep, "b") == {"truncated_by": "budget", "closed_before_cut": False}, (
        "a stale record at the destination survived a re-archive; a retried world would keep "
        "reporting the attempt it no longer has")

    victim = tmp_path / "victim.json"
    victim.write_text("VICTIM\n", encoding="utf-8")
    linked_ep, linked_dirs, _b2 = _episode_with(tmp_path / "linked", worlds=("b",))
    S.plant_sidecar(linked_dirs["b"], truncated_by="budget")
    world = linked_ep / "worlds" / "b"
    world.mkdir(parents=True, exist_ok=True)
    (world / S.run_end_name()).hardlink_to(victim)
    with pytest.raises(S.refusals()):
        _archive().archive_episode(linked_ep, linked_dirs)
    assert victim.read_text(encoding="utf-8") == "VICTIM\n", (
        "the archive wrote this world's record through a hard link planted at the "
        "destination, landing it outside the archive tree")
    assert not (world / "report.md").exists(), (
        "the archive copied part of the world before refusing the planted hard link")


def test_an_unreadable_sidecar_is_copied_verbatim_and_the_judge_reads_no_record(tmp_path):
    """A sidecar that holds no record — zero bytes, truncated JSON, a JSON list — is archived
    BYTE FOR BYTE, exactly as the scrub verdict is: the archive is a copy, not an interpreter,
    and what the bytes MEAN is decided once, by the judge through `run_end.parse_record`,
    which reads all three as "no record" and grades the world as today.

    The rest of the world archives either way: a record the host could not produce is the
    `missing_run_end_grades_as_today` state, which is handled, and losing the world's other
    artifacts over it would be a strictly worse answer."""
    for name, raw in (("empty", ""), ("torn", '{"truncated_by": "abor'),
                      ("list", '[{"truncated_by": "aborted"}]')):
        ep, dirs, _base = _episode_with(tmp_path / name, worlds=("b",))
        S.plant_sidecar(dirs["b"], raw=raw)
        _archive().archive_episode(ep, dirs)
        archived = ep / "worlds" / "b" / S.run_end_name()
        assert archived.read_text(encoding="utf-8") == raw, (
            f"{name}: the archive rewrote the sidecar's bytes instead of copying them")
        assert (ep / "worlds" / "b" / "report.md").is_file(), (
            f"{name}: an unreadable sidecar cost the world its other artifacts")
        graded = S.cut_short_episode(tmp_path / f"{name}-graded")
        S.plant_archived_record(graded, "b", raw=raw)
        row = S.graded(graded)["b"]
        assert row.get("ungradable") is not True, (
            f"{name}: bytes that hold no record made the world ungradable")
        assert row.get("cut_short") is None


def test_a_directory_squatting_the_sidecars_name_refuses_the_world_like_any_planted_entry(
        tmp_path):
    """A DIRECTORY at the sidecar's own path is not an unreadable record but an entry that is
    not the artifact — and the archive answers it the way it answers the scrub verdict's name
    being squatted: the whole world is refused before anything is copied, never a half-world
    archived without one role. The sidecar's path is host-side, so a directory there is a
    host fault, and a host fault is the launcher's to see rather than the archive's to paper
    over."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.sidecar_path(dirs["b"]).mkdir(parents=True, exist_ok=True)
    with pytest.raises(S.refusals()):
        _archive().archive_episode(ep, dirs)
    assert not (ep / "worlds" / "b" / "report.md").exists(), (
        "the archive copied part of the world before refusing it")


# ---------------------------------------------------------------------------------------
# the destination is screened — a link at the record's own name is never followed
# ---------------------------------------------------------------------------------------


def test_destination_preexisting_symlink_never_followed_for_the_write(tmp_path):
    """A symlink already sitting at worlds/<label>/run_end.json is never followed by the
    archive's write — the new write takes the same destination screen and guarded seam every
    other archived leaf does.

    Positive control: `test_the_archive_writes_each_worlds_run_end_record_itself` — the same
    archive over the same sidecar with an empty destination writes the record."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="aborted")
    target = tmp_path / "elsewhere.json"
    target.write_text("UNTOUCHED\n", encoding="utf-8")
    world = ep / "worlds" / "b"
    world.mkdir(parents=True, exist_ok=True)
    (world / S.run_end_name()).symlink_to(target)
    with pytest.raises(S.refusals() + (OSError,)):
        _archive().archive_episode(ep, dirs)
    assert target.read_text(encoding="utf-8") == "UNTOUCHED\n", (
        "the archive followed a planted link and wrote this world's record over the link's "
        "target")


def test_a_destination_side_symlink_at_the_run_end_path_pointing_outside_the_archive_tree_is_never_followed_for_the_write(
        tmp_path):
    """A destination-side symlink pointing OUTSIDE the archive tree is refused rather than
    followed, so no host write for this feature lands outside the episode's own worlds/
    directory.

    The link points at a path in a sibling tree the episode dir does not contain — the escape
    the destination screen exists for, stated as the adversary's framing of the same address:
    the episode dir is reachable from a sibling box's rw bind, which is why `merge_review` and
    the run-dir pointer both already go through the guarded seam."""
    outside = tmp_path / "outside" / "stolen.json"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text("OUTSIDE\n", encoding="utf-8")
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="store")
    world = ep / "worlds" / "b"
    world.mkdir(parents=True, exist_ok=True)
    (world / S.run_end_name()).symlink_to(outside)
    with pytest.raises(S.refusals() + (OSError,)):
        _archive().archive_episode(ep, dirs)
    assert outside.read_text(encoding="utf-8") == "OUTSIDE\n", (
        "the archive followed a link out of the archive tree and wrote this world's record "
        "over a file the episode does not own")


def test_a_symlink_planted_inside_the_run_dir_at_the_sidecars_basename_is_not_read_as_the_run_end_record(
        tmp_path):
    """A symlink planted inside the run dir at the sidecar's basename is not read as the
    record: the sidecar's path is a pure function of a host-held path, the `scrub.verdict_path`
    precedent.

    The sidecar lives BESIDE the run dir, so a file inside the run dir wearing its basename is
    simply a different path — there is no lookup for it to intercept. Positive control:
    `test_the_worlds_exit_class_is_read_from_a_source_no_box_can_write`."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="budget")
    decoy = tmp_path / "decoy.json"
    decoy.write_text(json.dumps({"truncated_by": "request-limit"}), encoding="utf-8")
    inside = dirs["b"] / S.sidecar_path(dirs["b"]).name
    inside.symlink_to(decoy)
    _archive().archive_episode(ep, dirs)
    assert _record(ep, "b") == {"truncated_by": "budget", "closed_before_cut": False}


# ---------------------------------------------------------------------------------------
# the sidecar's own identity, and the fan that writes several of them
# ---------------------------------------------------------------------------------------


def test_the_host_side_record_source_is_not_reachable_from_inside_a_box(tmp_path):
    """NOT reachable: the investigation box mounts exactly the run dir (rw), the defender dir
    (ro) and a tmpfs (claims h23, n2), and the sidecar's parent is not bound.

    Driven over the REAL `_create_argv` — the one place a box's mount set is composed — and the
    assertion is about the argv it emits, not about a list of mounts restated here. The
    sidecar's path is beside the run dir, so the rw bind's target does not contain it; a box
    that wanted to forge the record would have to write outside every mount it has."""
    from defender.runtime.box._lifecycle import _create_argv
    from defender.runtime.box._spec import BoxSpec

    run_dir = tmp_path / "defender-runs" / "2026-09-16T12-00-00Z_case-1047"
    run_dir.mkdir(parents=True, exist_ok=True)
    sidecar = S.sidecar_path(run_dir)
    # An explicit rootfs: the tree is fake (no `box.Dockerfile`/`box-requirements.txt`),
    # and with `rootfs` unset the builder would resolve the image from it and refuse (#1092).
    argv = _create_argv(
        "defender-run-1047", run_dir, tmp_path / "srv" / "defender",
        BoxSpec(rootfs="python:3.11-slim"), (),
    ).argv
    writable = [
        spec.split("target=", 1)[1].split(",", 1)[0]
        for spec in argv if spec.startswith("type=bind,") and "readonly" not in spec
    ]
    assert writable == [str(run_dir)], (
        f"the box's writable binds are {writable}; O3's whole argument is that there is "
        "exactly one and it is the run dir")
    assert not str(sidecar).startswith(str(run_dir) + "/"), (
        f"{sidecar} is inside the box's own rw bind — the record would be forgeable by the "
        "subject it is about")
    assert sidecar.parent == run_dir.parent


def test_the_run_end_sidecar_leaf_never_collides_with_a_run_dir_or_another_siblings_leaf_under_runs_base(
        tmp_path):
    """For two siblings fanned by one `start_family` call, each sibling's run-end sidecar lands
    at a path derived from its own run_id and collides with neither the other sibling's run dir
    nor its sidecar — `sidecar_name`'s injective derivation from `run_id`, driven at the
    composition frame that fans the writers.

    The fan is the REAL `start_family` through its own `spawn=` seam, with each fake child
    doing what a real child's driver does at the end of its run: materialise its run dir and
    write its sidecar beside it. Two writers under one shared root is exactly the shape a
    uniqueness demand exists for, and driving one writer twice would not produce it."""
    ep = S.episode(tmp_path)
    cli = S.mod("learning.branch.cli")
    runs = cli.sibling_runs_base(ep)
    written: dict[str, object] = {}
    faults: list[BaseException] = []

    def spawn(argv, *, env=None, **_kw):
        # `start_family` records a thread that died as a NON-ZERO exit rather than re-raising,
        # so a fault in here would otherwise reach the assertions below as "the launcher fanned
        # nothing" — a message about the wrong thing.
        try:
            label = next(argv[i + 1] for i, tok in enumerate(argv) if tok == "--world")
            run_dir = runs / f"{S.EPISODE_ID}-{label}"
            run_dir.mkdir(parents=True, exist_ok=True)
            S.plant_sidecar(run_dir, truncated_by="aborted")
            written[label] = run_dir
        except BaseException as fault:  # noqa: BLE001 — re-raised verbatim below
            faults.append(fault)
            raise
        return 0

    cli.start_family(ep, ["b", "c"], spawn=spawn)
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


def test_sidecar_write_ordering_relative_to_the_archives_own_run_dir_discovery(tmp_path):
    """There is no launcher-level race: the spawn seam is `subprocess.run(...).returncode`, so
    the sibling has exited before the launcher composes {label: run_dir} and before any archive
    pass reads a sidecar.

    Observed rather than read off the seam's source: each fake child writes its sidecar as its
    LAST act, and every sidecar is on disk by the time `start_family` returns — which is the
    point at which the launcher holds the `{label: run_dir}` map it hands the archive. A
    non-blocking seam would let the archive run against a sibling that had not written yet."""
    ep = S.episode(tmp_path)
    cli = S.mod("learning.branch.cli")
    runs = cli.sibling_runs_base(ep)
    dirs: dict[str, object] = {}
    faults: list[BaseException] = []

    def spawn(argv, *, env=None, **_kw):
        try:
            label = next(argv[i + 1] for i, tok in enumerate(argv) if tok == "--world")
            run_dir = S.sibling_run_dir(runs, label)
            S.plant_sidecar(run_dir, truncated_by="request-limit")
            dirs[label] = run_dir
        except BaseException as fault:  # noqa: BLE001 — re-raised verbatim below
            faults.append(fault)
            raise
        return 0

    exits = cli.start_family(ep, ["b", "c"], spawn=spawn)
    if faults:
        raise faults[0]
    assert set(exits) == {"b", "c"}
    for label, run_dir in dirs.items():
        assert S.sidecar_path(run_dir).is_file(), (
            f"{label}'s sidecar was not on disk when the launcher returned; the spawn seam did "
            "not wait for the child")
    _archive().archive_episode(ep, dict(dirs))
    assert _record(ep, "b") == S.record_doc("request-limit")


# ---------------------------------------------------------------------------------------
# the driver end: what actually writes the sidecar
# ---------------------------------------------------------------------------------------


def _deps(tmp_path):
    from defender.tests import _spec923

    return _spec923.main_deps(tmp_path)


def test_run_end_write_happens_even_for_a_run_that_ended_cleanly(tmp_path):
    """The sidecar write is UNCONDITIONAL for every run THAT REACHES THE AGENT LOOP: a clean run
    writes {"truncated_by": null}. The data model names null as valid CONTENT, not as "absent
    when null".

    Driven through the REAL agent loop with a model that answers once and stops, so the run
    really does end with no exit class. If the write were conditional, "not cut short" and "the
    host never got to say" would be one state on disk, and `missing_run_end_grades_as_today`'s
    fallback would be doing double duty for a case the design says is normal.

    THE ONE RECORDED EXCEPTION, and why it is not tested here. F-B sites the write inside
    `_drive_agent`; the SETUP-FAILURE arm at `driver/__init__.py:586-606` returns
    `truncated_by="store"` from `run_investigation` without ever entering that frame, so it
    writes no sidecar — the sixth `store` producer the graph's `handoff.deviations` already
    names. No test here can see it because every test of this demand drives the loop, and moving
    the write out to cover it would move it out of the only frame that can read
    `ReviewState.of(deps).closed`, which F-A's second field needs. Recorded on the demand
    (`s33`'s note), not silently widened away."""
    deps, run_dir = _deps(tmp_path)
    _run, end, _reason = S.drive(deps, S.clean_model())
    assert end.truncated_by is None, "the clean model did not produce a clean run"
    assert S.sidecar_doc(run_dir) == {"truncated_by": None, "closed_before_cut": False}, (
        f"a clean run left {S.sidecar_doc(run_dir)!r} beside its run dir")


def test_the_driver_records_whether_the_model_had_already_closed_when_the_exit_was_stamped(
        tmp_path):
    """The run-end record's second field is written by the DRIVER, at the moment the exit class
    is stamped and before the forced report: a run whose `ReviewState.of(deps).closed` is True
    when the cut lands records `closed_before_cut: true`, and one whose model never closed
    records `false`.

    Fork F-A/F-B reading B (human, §7 round 2). `run.py` does NOT already hold this value —
    `_run_summary`'s seven keys do not include it (probe p21) — so the field is threaded out of
    the driver, which is the only frame that can see it. `ReviewState.of(deps).closed` is set
    directly here because that is the real primitive: probe p21 (EXECUTED over the real
    `AgentDeps`) drove exactly this and found the forced close returns early, leaving the run
    dir byte-identical.

    The write is sited before the forced report (F-B), which is what closes the crash window
    `missing_run_end_grades_as_today` otherwise leaves open: a kill between the two writes
    leaves a record and no report, the state F5's ordering already handles."""
    from defender.runtime import challenge_gate
    from defender.tests import _spec923

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
    """A run-end write that FAILS is swallowed — the run does not break over it — and it is
    also a reason not to write the forced `unresolved` report: fork F-H's second clause, the
    half that closes the window F-B was about.

    F-H's first clause alone (swallow and continue, log loudly) is not the fix. The ORDERING
    constraint — the record before the forced report — closes F-B's window for a run the host
    KILLED between the two writes; it does nothing for a write that RAISED and was swallowed.
    A `request-limit`/`retry-exhausted` run that swallowed its failed record write and then
    wrote its forced report produces precisely the configuration claim h2 observed EXECUTING:
    a forced `unresolved` report on disk, no record beside it, and the family's `verdict_word`
    flipping `caught -> survived` because the judge grades the host's report as the world's own
    conclusion. That is the pre-#1047 bug, reachable inside this piece's own mechanism, and it
    is why F-B and F-H were relayed to the human together.

    TIER 1 FAULT: a real DIRECTORY at the sidecar's own path, so the real write really fails
    through the real guarded seam — not a fake that reports a failure. Positive control: the
    same exit class with a writable sidecar path writes BOTH the record and the report, so what
    is under test is the suppression and not a run that never got that far."""
    from defender.tests import _spec923

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


def test_budget_kill_reaches_its_own_sidecar_write(tmp_path):
    """A missing sidecar — budget-killed, crashed, or pre-feature — grades as today,
    indistinguishably; and because `budget` writes no report.md (claim h1) the absent record is
    genuinely inert on this class, so F-B's hazard cannot apply to it.

    The kill is the REAL `BudgetKill`, raised from the model call — the seam the real kill
    reaches the loop through. Two halves: the driver does reach its write on this class, and a
    world whose record never landed at all grades exactly as a world that predates the feature
    does, with no forced report to be mistaken for a verdict."""
    from defender.hooks.budget_enforcer import BudgetKill

    deps, run_dir = _deps(tmp_path)
    _run, end, _reason = S.drive(
        deps, S.killing_model(BudgetKill("budget tail exhausted at read_file")))
    assert end.truncated_by == "budget"
    assert S.sidecar_doc(run_dir) == {"truncated_by": "budget", "closed_before_cut": False}
    assert not (run_dir / "report.md").exists(), (
        "the budget arm wrote a report.md; claim h1 says it does not, and the whole reason an "
        "absent record is inert on this class is that there is no report to grade")

    missing = S.cut_short_episode(tmp_path / "missing")
    assert S.graded(missing)["b"].get("cut_short") is None


def test_store_stamp_failure_does_not_leak_into_the_sidecar_or_ticket_value(tmp_path):
    """A swallowed store-stamp failure (`_flush_run_end` is best-effort, claim h20) changes
    neither the sidecar's value nor the ticket's: both take the in-process summary value, and
    neither lane reads the store.

    The store handed to the driver raises from `set_truncated_by` — a real failure through the
    real best-effort path, not a fake that reports one. The store column is then empty while
    the run really was cut short, which is the divergence F3 reading A was chosen to be
    immune to."""
    from defender.hooks.budget_enforcer import BudgetKill
    from defender.runtime import session_store
    from defender.tests import _spec923

    class _BrokenStore(_spec923.NullStore):
        """A store whose stamp fails, as `_flush_run_end` already tolerates."""

        def set_truncated_by(self, _session_id, _value):
            raise session_store.StoreAppendError("the store is exactly what is broken")

    deps, run_dir = _deps(tmp_path)
    _run, end, _reason = S.drive(
        deps, S.killing_model(BudgetKill("budget tail exhausted at read_file")),
        store=_BrokenStore())
    truncated_by = end.truncated_by
    assert truncated_by == "budget", "the run did not reach the handled exit at all"
    assert S.sidecar_doc(run_dir) == {"truncated_by": "budget", "closed_before_cut": False}, (
        "the sidecar took its value from the store rather than from what the driver observed")
    ticket_run = S.closed_run_dir(tmp_path / "ticket")
    fake = S.record_ticket(ticket_run, truncated_by=truncated_by)
    assert fake.writes == [], (
        "the ticket lane did not see the exit class the driver observed")


def test_sibling_spawn_never_starts_at_all(tmp_path):
    """A world whose process never started (SPAWN_FAILED_EXIT=70, claim h14) has no sidecar, so
    the archived record is absent and the world grades as today, whatever the launcher-level
    cause.

    The run dir exists (the launcher made it) and holds nothing a child would have written —
    the state a spawn failure leaves. Nothing invents a record for it: "the host never got to
    say" and "the run was not cut short" stay one answer, which is what
    `missing_run_end_grades_as_today` already handles."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    assert not S.sidecar_path(dirs["b"]).exists()
    _archive().archive_episode(ep, dirs)
    assert _record(ep, "b") is None, "the archive invented a record for a world that never ran"
    graded = S.cut_short_episode(tmp_path / "graded")
    assert S.graded(graded)["b"].get("cut_short") is None, (
        "a world with no record acquired an exit class")


def test_sibling_crashes_after_sidecar_written_before_archive_ever_runs(tmp_path):
    """A sidecar written before the sibling died is read by a later archive pass and becomes
    worlds/<label>/run_end.json normally — the design states no staleness window.

    The sibling's process is gone by archive time in every episode (claim h14: the spawn seam
    blocks), so "the writer is no longer running" is the ordinary case, not a hazard. The run
    dir is left exactly as a crash leaves it — the sidecar on disk, the run dir's own contents
    whatever they were."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="store")
    _archive().archive_episode(ep, dirs)
    assert _record(ep, "b") == {"truncated_by": "store", "closed_before_cut": False}


def test_one_world_is_cut_short_while_a_sibling_archive_is_refused(tmp_path):
    """World b archives and grades per its own exit class independently of world c's refusal:
    the archive's refuse-and-report is per-world and per-entry (flagged fact F6), not
    per-episode.

    c's refusal is a REAL one through the real screen — a symlink at an artifact's name in its
    run dir, the shape `_screen` raises `ArchiveRefused` for — and worlds are processed in
    sorted order, so b's archive has already happened when c's refusal lands."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b", "c"))
    S.plant_sidecar(dirs["b"], truncated_by="request-limit")
    S.plant_sidecar(dirs["c"], truncated_by="aborted")
    secret = tmp_path / "secret.md"
    secret.write_text("ROOT-PRIVATE-KEY", encoding="utf-8")
    (dirs["c"] / "report.md").unlink()
    (dirs["c"] / "report.md").symlink_to(secret)
    with pytest.raises(S.refusals()):
        _archive().archive_episode(ep, dirs)
    assert _record(ep, "b") == {"truncated_by": "request-limit", "closed_before_cut": False}, (
        "world c's refusal cost world b the record its own run produced")
    assert not (ep / "worlds" / "c" / "report.md").exists()


def test_a_run_dir_emptied_or_corrupted_by_the_box_at_run_end_still_grades_a_genuinely_cut_short_world_correctly(
        tmp_path):
    """A run dir the box emptied or corrupted at run end still grades a genuinely cut-short
    world correctly: the exit class was captured host-side, beside the run dir, not inside it.

    The run dir is really emptied — every entry removed — after the driver wrote its sidecar,
    which is what a box that is root on its own rw bind can do at any moment before teardown.
    The world still archives with the host's record and still files the third row shape."""
    import shutil

    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="request-limit")
    for entry in sorted(dirs["b"].iterdir()):
        shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
    assert list(dirs["b"].iterdir()) == [], "the fixture did not empty the run dir"
    _archive().archive_episode(ep, dirs)
    assert _record(ep, "b") == {"truncated_by": "request-limit", "closed_before_cut": False}

    graded = S.cut_short_episode(tmp_path / "graded", cut={"b": "request-limit"})
    assert S.graded(graded)["b"].get("cut_short") == "request-limit"


def test_a_path_traversal_style_value_written_by_the_box_anywhere_in_the_run_dir_cannot_make_any_host_side_write_for_this_feature_land_outside_the_run_dirs_own_bind(
        tmp_path):
    """No host-side path for this feature is derived from box-writable content — every path is
    host-held — so a traversal-shaped value planted in the run dir moves no write.

    Traversal-shaped values are planted at every box-writable name (the pointer file, the
    receipt, the report's frontmatter, a file at the record's own name), and the archive is then
    driven. The record lands at the one path the host composed, and nothing appears anywhere
    else under the episode root. Positive control:
    `test_the_worlds_exit_class_is_read_from_a_source_no_box_can_write`."""
    ep, dirs, _base = _episode_with(tmp_path, worlds=("b",))
    S.plant_sidecar(dirs["b"], truncated_by="aborted")
    escape = "../../../../tmp/defender-1047-escape.json"
    for name in S.FORGEABLE_NAMES:
        (dirs["b"] / name).write_text(
            json.dumps({"truncated_by": escape, "path": escape, "run_end": escape}),
            encoding="utf-8")
    _archive().archive_episode(ep, dirs)
    assert _record(ep, "b") == {"truncated_by": "aborted", "closed_before_cut": False}
    landed = sorted(p.relative_to(ep) for p in ep.rglob(S.run_end_name()))
    assert [str(p) for p in landed] == [f"worlds/b/{S.run_end_name()}"], (
        f"the feature's write landed at {landed} — a path derived from box-written content")


def test_archive_episode_still_copies_report_md_verbatim_regardless_of_the_worlds_exit_class(
        tmp_path):
    """`archive_episode`'s unconditional verbatim copy of `report.md` into the world archive is
    unaffected by this change — it copies the same bytes whether the world's run was cut short
    or not, on both a cut-short and a control world in one episode.

    R7: `archive_episode` is an unmoved READER of `report_md` while `_grade_world` and
    `record_case_ticket` both moved (claims h4, h8). If the new write had been folded into the
    copy list, or the exit class had been allowed to gate the copy, a cut-short world would
    archive with no report at all and the judge's tier-1 reason would change meaning."""
    ep, dirs, _base = _episode_with(tmp_path)
    S.plant_sidecar(dirs["b"], truncated_by="request-limit")
    S.plant_sidecar(dirs["c"])
    bytes_before = {w: (dirs[w] / "report.md").read_bytes() for w in dirs}
    _archive().archive_episode(ep, dirs)
    for label, raw in bytes_before.items():
        assert (ep / "worlds" / label / "report.md").read_bytes() == raw, (
            f"{label}: the archived report is not the run dir's bytes")
