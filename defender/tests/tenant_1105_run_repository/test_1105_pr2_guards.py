"""#1105 PR 2 — the guard table (rev 5.1 part 2, G1–G25; O6): every guard on a migrated path that
no existing test pins through an observable that survives the move.

PR 2 moves callers behind the tenant-scoped repository; O6 says no migrated path drops a guard
that holds on it today, and its discharge is "a guard plus a positive control for each row". The
census of existing pins (one block per row) is the table below; this file adds a test for each
row, or sub-clause, that has none — or whose only pin goes through a helper or an argument shape
PR 2 deletes (`tenant_of_run_dir`, `_sibling_tenant_agrees`, `episodes_root`/`episode_dir_for`
called directly, `Run.at`, `--resume`, a path positional).

EVERY TEST HERE IS GREEN AT BASE `301f196c` AND STAYS GREEN AFTER PR 2. Each drives the real
entry point through `_spec1105_pr2`'s argument builders (TODAY's shape; PR 2 re-points the
builders, never these tests) and asserts the refusal's observable — exit, nothing spent (the
questioner / preflight / lifecycle seams never called), nothing written (a tree census) — beside
a positive control on the same address.

| Row | Existing pin (file::test)                                                       | Here |
|-----|---------------------------------------------------------------------------------|------|
| G1  | test_1120_entry_points::…refuses_a_relative_or_defender_tree_data_root…;          | — (#1187 R1: no record; O8 pins below) |
|     | test_1120_entry_points::…refuses_what_accept_tenant_refuses[branch.cli.main]     |      |
| G2  | test_1106_sibling_seed::test_a_source_stamp_disagreeing_with_its_runs_base_…     | —    |
| G3  | test_1107_branch::test_s7_mf13_launcher_refuses_box_mounted_tenants_root         | —    |
| G4  | test_947_triplet_launcher::…screens_the_source_alert_before_the_questioner…      | sibling screen (pinned only via `--resume`) |
| G5  | test_1078_run_main::test_o5_disagreeing_tenant_refused (via `--resume`);         | — (#1187 O4b: the roster; see below) |
|     | test_947_triplet_sibling::…runs_base_names_another_tenant…  (+c recordless)      |      |
| G6  | none                                                                            | — (#1187 dc5: retired, see below) |
| G7  | test_1105_run_setup::* , test_1105_spec_holes::…non_directory_runs_folder…,      | —    |
|     | (test_1078_materialize's record-mismatch test: retired by #1187 R1; nearest:     |      |
|     | ids_1187/test_1187_layout_isolation.py::test_a_container_with_no_record_opens_   |      |
|     | lists_and_hands_out_every_run)                                                  |      |
| G8  | moot: the judge's same-alert union is REMOVED (fork decision J3, 6100061869);   | —    |
|     | the removal is declared-change test `test_dc2_…`                                |      |
| G9  | test_1049_page::test_1049_result_event_reads_the_tool_trace_through_the_jsonl…   | (ii) a linked `runs/` reads as absent |
| G10 | learning/test_loop::test_lead_author_drain_marks_artifact_missing (old rows)     | — (rows change: declared change 8) |
| G11 | test_1077_handle::test_run_at_refuses_a_nonexistent_path_and_a_file (`Run.at`)   | the CLI itself |
| G12 | test_1110_run_page_record_e2e::test_1110_o8_s2_…; test_1134_lead_author_handle    | —    |
| G13 | — (#1187 dc1/dc4: the 206-byte bound and the composed sibling id are gone)       | —    |
| G14 | test_1120_refusal_spends_nothing::test_the_launcher_refuses_before_its_role_…    | —    |
| G15 | #1187: ids_1187/test_1187_layout_isolation.py::test_create_episode_claims_a_uuid_ | (ii), (iii) at the launcher |
|     | folder_under_the_tenant_and_reads_no_environment, ::test_two_episodes_get_two_    |      |
|     | fresh_uuid_folders_and_never_a_retry_suffix, ::test_the_episodes_variable_changes_ |      |
|     | nothing_and_no_episodes_root_refusal_fires                                      |      |
| G16 | test_1078_launcher::test_pass_a_episode_sibling_bases_carry_a_record_naming_…    | another tenant's store, at the launcher |
| G17 | REMOVED: under J3 as settled (the spine's ruling on #1105) the judge's label    | —    |
|     | probe over `<T>/runs` goes — it guarded `resolve_run_bundle`, which has no       |      |
|     | production caller (E-27). The removal is declared-change test `test_dc3_…`; its  |      |
|     | pin test_921_family_facts::test_921_a_world_label_colliding_… is on that file's  |      |
|     | edit list                                                                       |      |
| G18 | test_1133_o4::test_the_sibling_door_refuses_a_resume_manifest_not_named_…        | replaced: declared-change test `test_dc6_…episode_id…` |
| G19 | test_1078_run_main::test_o5_* (no write census)                                 | no write before the refusal |
| G20 | none (no guard today)                                                           | declared change 4 |
| G21 | none (no guard today)                                                           | declared change 8 |
| G22 | none (no guard today)                                                           | repository surface |
| G23 | test_1133_o4::test_o4_8_2_*_refuses_a_missing_episode_dir_… ; the file case     | the page's file-at-the-name |
|     | only via test_1025_page_contract::…names_an_existing_regular_file… (bare path)   |      |
| G24 | test_1133_entry_points::test_o3_the_judge_pass_reads_and_writes_through_one_…    | —    |
| G25 | test_1133_entry_points::test_h1_start_family_refuses_a_linked_runs_base_…        | —    |

Expected at base 301f196c: every test in this module PASSES.

#1187 (design rev 2) changes four rows. G1(ii) and G5 judged a container record, which R1
retires: the guards become the per-level no-follow walk from `<T>` and the arm roster
(`ids_1187/test_1187_layout_isolation.py::test_another_tenants_episode_is_absent_to_this_tenants_repository`,
`ids_1187/test_1187_roster_sibling.py::test_the_sibling_is_refused_before_the_manifest_unless_its_roster_names_it`).
G6's scenario — a data root inside an episode container under a configured episodes base —
cannot be built once the base is retired (declared change 5: an episode is `<T>/episodes/<uuid>`,
inside the data root), so `test_g6_…` is retired with no replacement (S-acc's box-mounted
check itself stands, unpinned here). G15(i), the unusable-base refusals, are gone with the
variable (O9). Each flipped test names its declared change in its own docstring.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from defender.tests import _episode_1025 as E
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _episode_names() -> set[str]:
    """Every entry under any tenant's `<data root>/<T>/episodes/` — #1187 Layout A, where every
    launch claims its episode (O9: no configured episodes root). Each refusal's control shows
    the census sees the episode a launch makes, so "no episode made" is not vacuous."""
    root = P.data_root()
    return {str(p.relative_to(root)) for p in root.glob("*/episodes/*")}


def _no_episode_made(before: set[str]) -> bool:
    return _episode_names() == before


# ==========================================================================================
# The launcher (G1, G15, G16): refused before anything is spent; the control launches.
# ==========================================================================================

def test_g15_a_source_id_that_leaves_no_room_for_a_sibling_is_refused_before_anything_is_spent(
        tmp_path, monkeypatch):
    """G15(ii), at the entry point: a source id the launcher cannot branch from is refused
    before the questioner, with no episode folder. The positive control is a source under a
    fresh data root: it launches.

    #1187 declared changes 1, 3 and 4: nothing is derived from the source id any more — the
    episode is a fresh UUID, so no "room for `-<label>`" rule exists. The 201-byte source id is
    refused because it is not a UUID (`RunId` admits only canonical lowercase UUID text, and
    the launcher's `--tenant T <id>` refuses an old id), never for the room it leaves. The
    control's source is named by a UUID. (Name kept.)"""
    import uuid

    long_id = ("2026" + "x" * 199)[:201]
    est, src = P.launch_source(tmp_path, source_run_id=long_id)
    assert len(src.name.encode()) == 201
    before = _episode_names()

    refused = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert refused.raised is not None, "a non-uuid source id was not refused"
    assert refused.rc != 0, "a non-uuid source id was not refused"
    assert "room" not in refused.message, (
        f"refused by the retired room-for-a-label rule: {refused.message!r}")
    assert refused.questioner.calls == 0
    assert _no_episode_made(before)

    # The control under a fresh data root: two sources of one tenant would share the fixture's
    # one session-store case, and the second could never seed its branch point.
    (tmp_path / "control").mkdir()
    monkeypatch.setenv(P.DATA_ROOT_ENV, str(tmp_path / "control-data"))
    est2, short = P.launch_source(tmp_path / "control", source_run_id=str(uuid.uuid4()))
    control = P.drive_launch(est2, P.launch_argv(P.LAUNCH_TENANT, short))
    assert control.questioner.calls > 0, f"the control never launched: {control.message!r}"
    assert len(P.launched_episodes()) == 1, (
        f"the census never saw the control's episode: {sorted(_episode_names())}")


def test_g15_a_link_at_the_derived_episode_name_is_passed_over_and_left_untouched(tmp_path):
    """G15(iii), at the entry point. The launcher's exclusive claim adopts nothing: a link
    planted among the tenant's episodes (pointing at a real folder outside the data root) is
    passed over, the launch claims an episode of its own and runs there, and the link and its
    target are untouched.

    #1187 declared change 3: there is no derived episode name to squat and no `<id>-r2` to move
    on to. The launch claims a fresh canonical-UUID folder under `<T>/episodes/` — a real
    directory, holding the manifest — beside the link, which is left as it was. The source is
    named by a UUID (declared change 1). (Name kept.)"""
    import uuid

    from defender.tests.ids_1187 import _spec1187 as S

    est, src = P.launch_source(tmp_path, source_run_id=str(uuid.uuid4()))
    root = S.episodes_dir(P.data_root(), P.LAUNCH_TENANT)
    root.mkdir(parents=True, exist_ok=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep.txt").write_text("not an episode\n", encoding="utf-8")
    squatted = S.new_id()
    os.symlink(elsewhere, root / squatted)
    before = P.tree(elsewhere)

    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src), spawn=P.T.FakeSpawn())

    assert got.questioner.calls > 0, f"the launch never ran: {got.message!r}"
    assert (root / squatted).is_symlink()
    assert os.readlink(root / squatted) == str(elsewhere)
    assert P.tree(elsewhere) == before, "the launch wrote through the link"
    claimed = [p for p in root.iterdir() if p.name != squatted]
    assert len(claimed) == 1, sorted(p.name for p in root.iterdir())
    assert S.is_canonical_uuid(claimed[0].name), f"claimed {claimed[0].name!r}, not a uuid"
    assert not claimed[0].is_symlink(), sorted(p.name for p in root.iterdir())
    assert claimed[0].is_dir(), sorted(p.name for p in root.iterdir())
    assert (claimed[0] / "family.yaml").is_file()


def test_g16_a_source_pointer_naming_another_tenants_store_is_refused_before_anything_is_spent(
        tmp_path):
    """G16. `open_source_store` refuses a source whose session pointer names a store other than
    the one derived from the run folder — here another real tenant's `sessions/` holding a copy
    of the store. Driven through the launcher's branch-point check: refused before the
    questioner, no episode folder. (Fork S moves where `runs_base` comes from; the compare and
    its `.resolve()` stay.) The positive control is the source's own pointer: it launches."""
    import json

    from defender.run_repository import RunPaths

    est, src = P.launch_source(tmp_path)
    beta = P.second_tenant(P.data_root(), "beta")
    # #1235: the case pointer is the host-only sidecar beside the run folder.
    pointer = RunPaths(src).session_pointer()
    honest = pointer.read_text(encoding="utf-8")
    doc = json.loads(honest)
    foreign = Path(beta.sessions) / Path(doc["store_path"]).name
    foreign.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(doc["store_path"], foreign)
    pointer.write_text(json.dumps({**doc, "store_path": str(foreign)}), encoding="utf-8")
    before = _episode_names()

    refused = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert refused.raised is not None, "a source pointing at another tenant's store launched"
    assert refused.rc != 0, "a source pointing at another tenant's store launched"
    assert "store" in refused.message, f"not the store compare's refusal: {refused.message!r}"
    assert refused.questioner.calls == 0
    assert _no_episode_made(before)

    pointer.write_text(honest, encoding="utf-8")
    control = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert control.questioner.calls > 0, f"the control never launched: {control.message!r}"
    assert not _no_episode_made(before), (
        f"the census never saw the control's episode: {sorted(_episode_names())}")


# ==========================================================================================
# The sibling (G4, G19): refused before the spend; the control runs its arm.
# ==========================================================================================

def test_g4_a_sibling_refuses_a_source_alert_that_is_a_link_and_never_copies_its_target(
        tmp_path):
    """G4, the sibling's screen (`run.py:460-475`), pinned today only through `--resume`. The
    source run's `alert.json` is a link to a file outside it: the sibling refuses before any
    lifecycle, and no arm's alert carries the target's bytes. The positive control restores a
    plain alert: the sibling reaches its lifecycle, its arm's alert being the source's.

    #1187 declared change 2: the arm's folder no longer spells `<episode>-<label>`, so the
    no-copy check reads every arm folder in the container, not one composed name. (Name kept.)"""
    src, ep = P.sibling_scene(tmp_path)
    secret = tmp_path / "secret.json"
    secret.write_text('{"secret": "outside the source run"}\n', encoding="utf-8")
    from defender._episode_paths import EpisodePaths
    alert = EpisodePaths(ep).source_alert
    plain = alert.read_bytes()
    alert.unlink()
    os.symlink(secret, alert)

    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    assert refused is not None, f"the sibling ran over a linked alert ({rc})"
    assert rc is None, f"the sibling ran over a linked alert ({rc})"
    assert "alert" in P.refusal_text(refused), P.refusal_text(refused)
    assert "lifecycle" not in rec.order
    # #1187 declared change 2: an arm's folder is its roster id, not `<episode>-b`; every
    # folder in the container is checked, so the check holds wherever the arm would be made.
    arms = [d for d in (ep / "runs").iterdir() if d.is_dir()] if (ep / "runs").is_dir() else []
    for arm in arms:
        copied = arm / "alert_input" / "alert.json"
        assert not copied.exists() or b"outside the source run" not in copied.read_bytes(), (
            f"{arm.name} carries the link's target")

    alert.unlink()
    alert.write_bytes(plain)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert ok.run_dir is not None
    assert (ok.run_dir / "alert_input" / "alert.json").read_bytes() == plain


def test_g19_a_sibling_for_another_tenant_is_refused_before_any_write_or_spend(tmp_path):
    """G19. A hand resume naming another real tenant (`acme`) over T's episode is refused before the preflight (no model key spent), before the lifecycle,
    and BEFORE ANY WRITE: the episodes root and the data root are census-identical after it.
    Today `_sibling_tenant_agrees` refuses after the manifest read; PR 2 refuses earlier, at
    `runs.episode(ep)`. The existing pins assert no spend but take no write census. The positive
    control is the same episode resumed by T: it runs.

    #1187 declared changes 6 and 8 (R1, O8): the record half flips. `acme`'s repository looks
    for the episode under `<acme>/episodes/` only, finds nothing and refuses — it reads nothing
    of the owning tenant's, so its refusal can no longer name that tenant (today it does, from
    the container record). (Name kept.)"""
    src, ep = P.sibling_scene(tmp_path)
    P.second_tenant(P.data_root(), "acme")
    episodes_before, data_before = P.tree(P.episodes(P.SIBLING_TENANT)), P.tree(P.data_root())

    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(P.sibling_argv("acme", ep, "b"), rec)
    assert refused is not None, "a sibling resumed another tenant's episode"
    assert rc is None, "a sibling resumed another tenant's episode"
    said = P.refusal_text(refused)
    assert "acme" in said, f"the refusal does not name the requested tenant: {said!r}"
    assert P.SIBLING_TENANT not in said.replace(str(P.data_root()), "<data root>"), (
        f"the refusal names the episode's tenant, so something of it was read: {said!r}")
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"
    assert P.tree(P.episodes(P.SIBLING_TENANT)) == episodes_before, (
        "the refused sibling wrote under the episode's tenant's episodes")
    assert P.tree(P.data_root()) == data_before, "the refused sibling wrote under the data root"

    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"


# ==========================================================================================
# The pages (G9, G11, G23).
# ==========================================================================================

def _sample(tmp_path: Path, tenant_id: str) -> E.Episode:
    """`_episode_1025`'s sample episode at `<data root>/<tenant_id>/episodes/<uuid>/` (#1187
    Layout A), as RUNS leaves it: the arm roster naming every world, each arm at its roster id.
    No container record (R1)."""
    return E.sample_episode(tmp_path, root=P.episodes(tenant_id))


def test_g9_a_linked_episode_container_reads_as_absent_on_the_page(tmp_path, d9_tenant):
    """G9(ii) (R51-20). A link at `<episode>/runs` — to a real folder holding T's record and the
    arms — is never followed by the page: the page renders, every arm reads "run directory
    absent", and no arm's run-page link appears. PR 2 keeps this: the view records an
    unreadable container and does not raise. The positive control is the same episode with a
    real `runs/`: the page links each arm's run page.

    #1187 declared change 15 (R2): the arm's run-page link is to the id the episode's arm
    roster holds for it, never the composed `runs/<episode>-<label>/`. The test plants what
    `start_runs` leaves (the roster, each arm at its roster id); the episode is the shared
    fixture's, at `<T>/episodes/<uuid>/` (`_sample`). (Name kept.)"""
    from defender.tests.tenant_1105_run_repository import test_1105_pr2_declared_changes as DC

    ep = _sample(tmp_path, d9_tenant)
    roster = DC._roster_by_hand(ep.dir)
    arm_link = f"runs/{roster[E.CONTROL]}/runtime.html"

    ok = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert ok.rc == 0, f"the control page was not rendered: {ok.said}"
    assert arm_link in ep.page.read_text(encoding="utf-8")

    moved = tmp_path / "moved-runs"
    (ep.dir / "runs").rename(moved)
    os.symlink(moved, ep.dir / "runs")
    ep.page.unlink()
    linked = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert linked.rc == 0, f"a linked runs/ refused the page instead of reading as absent: {linked.said}"
    text = ep.page.read_text(encoding="utf-8")
    assert arm_link not in text, "the page followed the linked runs/ to an arm"
    assert "run directory absent" in text
    assert (ep.dir / "runs").is_symlink()


def test_g11_the_run_page_refuses_an_absent_run_and_a_file_at_the_runs_name(tmp_path):
    """G11, at the CLI (today's pin calls `Run.at`, which leaves the run page). For a run id
    with nothing at it, and for one whose name is a regular file in T's runs folder, the run
    page exits non-zero and writes nothing: the absent name stays absent, the file is
    byte-for-byte unchanged. The positive control renders T's real run.

    #1187 declared change 1: the two names are UUIDs — an old-shaped id would now be refused as
    a bad id before any lookup, which is not the guard this row pins. (Name kept.)"""
    import uuid

    src, _ep = P.sibling_scene(tmp_path)
    runs = src.parent
    absent = runs / str(uuid.uuid4())
    a_file = runs / str(uuid.uuid4())
    a_file.write_bytes(b"not a run\n")
    before = P.tree(runs)

    for target in (absent, a_file):
        got = P.drive_cli(P.run_page_main(), P.run_page_argv(P.SIBLING_TENANT, target))
        assert got.rc not in (0, None) or (got.raised is not None and got.rc != 0), (
            f"the run page rendered {target.name}: {got.said}")
    assert not absent.exists()
    assert a_file.read_bytes() == b"not a run\n"
    assert P.tree(runs) == before

    ok = P.drive_cli(P.run_page_main(), P.run_page_argv(P.SIBLING_TENANT, src))
    assert ok.rc == 0, f"the control run page failed: {ok.said}"
    assert (src / "runtime.html").is_file()


def test_g23_the_page_refuses_a_file_at_the_episodes_name_and_leaves_it_untouched(
        tmp_path, d9_tenant):
    """G23 (#1133 O4.8.2), the file case at the page — pinned today only through the CLI's bare
    path. A regular file at the episode's name is refused: non-zero exit, the file unchanged,
    nothing made beside it. The positive control is a real episode at the same name: its page
    renders.

    #1187 declared changes 1 and 5 (O9): the episode's name is `<T>/episodes/<uuid>` — the
    file squats there, under the tenant, not under `DEFENDER_EPISODES_BASE` — and the real
    episode is that folder with its manifest naming the uuid and its arm roster. (Name kept.)"""
    from defender.tests import _triplet_947 as T
    from defender.tests.ids_1187 import _spec1187 as S

    root = S.episodes_dir(P.data_root(), d9_tenant)
    root.mkdir(parents=True, exist_ok=True)
    episode_id = S.new_id()
    squatter = root / episode_id
    squatter.write_bytes(b"a file, not an episode\n")
    before = P.tree(root)

    got = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, episode_id))
    assert got.rc not in (0, None) or got.raised is not None, f"the page rendered a file: {got.said}"
    assert P.tree(root) == before

    squatter.unlink()
    ep = S.make_episode(P.data_root(), d9_tenant, episode_id, labels=T.WORLDS, roster=True)
    T.write_family(ep, T.family_doc(episode_id=episode_id, source_run_id=S.new_id()))
    assert ep == squatter
    ok = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, episode_id))
    assert ok.rc == 0, f"the control page was not rendered: {ok.said}"
    assert (ep / E.PAGE_NAME).is_file()
