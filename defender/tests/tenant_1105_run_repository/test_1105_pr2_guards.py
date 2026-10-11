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
| G1  | test_1120_entry_points::…refuses_a_relative_or_defender_tree_data_root…;          | (ii) another tenant's record |
|     | test_1120_entry_points::…refuses_what_accept_tenant_refuses[branch.cli.main]     |      |
| G2  | test_1106_sibling_seed::test_a_source_stamp_disagreeing_with_its_runs_base_…     | —    |
| G3  | test_1107_branch::test_s7_mf13_launcher_refuses_box_mounted_tenants_root         | —    |
| G4  | test_947_triplet_launcher::…screens_the_source_alert_before_the_questioner…      | sibling screen (pinned only via `--resume`) |
| G5  | test_1078_run_main::test_o5_disagreeing_tenant_refused (via `--resume`);         | container record + its positive control |
|     | test_947_triplet_sibling::…runs_base_names_another_tenant…  (+c recordless)      |      |
| G6  | none                                                                            | yes  |
| G7  | test_1105_run_setup::* , test_1105_spec_holes::…non_directory_runs_folder…,      | —    |
|     | test_1078_materialize::test_o6_record_mismatch_refused                          |      |
| G8  | moot: the judge's same-alert union is REMOVED (fork decision J3, 6100061869);   | —    |
|     | the removal is declared-change test `test_dc2_…`                                |      |
| G9  | test_1049_page::test_1049_result_event_reads_the_tool_trace_through_the_jsonl…   | (ii) a linked `runs/` reads as absent |
| G10 | learning/test_loop::test_lead_author_drain_marks_artifact_missing (old rows)     | — (rows change: declared change 8) |
| G11 | test_1077_handle::test_run_at_refuses_a_nonexistent_path_and_a_file (`Run.at`)   | the CLI itself |
| G12 | test_1110_run_page_record_e2e::test_1110_o8_s2_…; test_1134_lead_author_handle    | —    |
| G13 | test_1105_review_followups::test_a_sibling_id_over_the_bound_is_refused_…        | —    |
| G14 | test_1120_refusal_spends_nothing::test_the_launcher_refuses_before_its_role_…    | —    |
| G15 | test_1078_launcher::test_d4_episodes_root_rekeyed (helper only);                  | (i), (ii), (iii) at the launcher |
|     | test_947_branch_cli::* (helper only)                                            |      |
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


def _episodes() -> Path:
    return Path(os.environ[P.EPISODES_BASE_ENV])


def _no_episode_made(before: set[str]) -> bool:
    root = _episodes()
    now = {p.name for p in root.iterdir()} if root.is_dir() else set()
    return now == before


def _episode_names() -> set[str]:
    root = _episodes()
    return {p.name for p in root.iterdir()} if root.is_dir() else set()


# ==========================================================================================
# The launcher (G1, G15, G16): refused before anything is spent; the control launches.
# ==========================================================================================

def test_g1_a_source_whose_runs_record_names_another_tenant_is_refused_before_anything_is_spent(
        tmp_path):
    """G1(ii). The launch fixture tenant T's source run sits in T's natural runs folder, and that
    folder's `_tenant.json` names U — another REAL tenant under the same data root. Today the
    launcher derives the tenant from the record and refuses the location; after PR 2 the
    request names T and `runs.open` judges the record against T. Either way: a refusal before
    the question-writer is paid, and no episode folder.

    No existing launcher test plants a record naming another EXISTING tenant at T's folder
    (`test_1105_review_followups` covers it only through PR 1's lookups). The positive control
    is the same source with the record naming T: the launch reaches the questioner."""
    est, src = P.launch_source(tmp_path)
    P.second_tenant(P.data_root(), "beta")
    record = src.parent / "_tenant.json"
    honest = record.read_bytes()
    P.plant_record(tmp_path / "scratch-runs", "beta")
    record.write_bytes((tmp_path / "scratch-runs" / "_tenant.json").read_bytes())
    before = _episode_names()

    refused = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))

    assert refused.raised is not None, (
        f"a source whose runs record names another tenant launched (rc {refused.rc})")
    assert refused.rc != 0, (
        f"a source whose runs record names another tenant launched (rc {refused.rc})")
    assert refused.questioner.calls == 0, "the question-writer was paid before the refusal"
    assert "beta" in refused.message, f"the refusal does not name the record's tenant: {refused.message!r}"
    assert _no_episode_made(before), "an episode folder was made before the refusal"
    assert record.read_bytes() != honest  # the plant is still in place: nothing rewrote it

    record.write_bytes(honest)
    control = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert control.questioner.calls > 0, (
        f"the control (record naming T) never reached the questioner: {control.message!r}")


def test_g15_the_launcher_refuses_an_unusable_episodes_base_before_anything_is_spent(
        tmp_path, monkeypatch):
    """G15(i), at the entry point. `episodes_root`'s refusals — the setting unset, and a base
    inside the data root — fire before the question-writer is paid and make no episode folder.
    Today every pin calls `episodes_root` / `episode_dir_for` directly; PR 2 moves that code
    into the episode owner (D-ep), so only the launcher's observable survives. The positive
    control is the same source with the configured base outside both: it launches."""
    est, src = P.launch_source(tmp_path)
    configured = os.environ[P.EPISODES_BASE_ENV]

    monkeypatch.delenv(P.EPISODES_BASE_ENV)
    unset = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert unset.raised is not None, "a launch with no episodes base ran"
    assert unset.rc != 0, "a launch with no episodes base ran"
    assert P.EPISODES_BASE_ENV in unset.message, (
        f"the refusal does not name the setting: {unset.message!r}")
    assert unset.questioner.calls == 0

    inside = P.data_root() / "episodes-inside"
    monkeypatch.setenv(P.EPISODES_BASE_ENV, str(inside))
    nested = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert nested.raised is not None, "a launch whose episodes base lies inside the data root ran"
    assert nested.rc != 0, "a launch whose episodes base lies inside the data root ran"
    assert "data root" in nested.message, nested.message
    assert nested.questioner.calls == 0
    assert not inside.exists(), "an episodes base inside the data root was created"

    monkeypatch.setenv(P.EPISODES_BASE_ENV, configured)
    control = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert control.questioner.calls > 0, f"the control never launched: {control.message!r}"
    assert (Path(configured) / P.EPISODE_ID).is_dir()


def test_g15_a_source_id_that_leaves_no_room_for_a_sibling_is_refused_before_anything_is_spent(
        tmp_path, monkeypatch):
    """G15(ii), at the entry point. The derived episode id is `<source run id>-n<message>`;
    `refuse_bad_episode_id` refuses one that leaves no room for `-<label>` within a run id's
    206 bytes. A 201-byte source id is a valid run id (so after PR 2 `runs.open` admits it),
    and so is its 205-byte episode id — but that one leaves no room for a sibling, so it is
    refused before the questioner, with no episode folder. The positive control is a short
    source id under a fresh data root: it launches."""
    long_id = ("2026" + "x" * 199)[:201]
    est, src = P.launch_source(tmp_path, source_run_id=long_id)
    assert len(src.name.encode()) == 201
    before = _episode_names()

    refused = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert refused.raised is not None, "the episode id was not refused"
    assert refused.rc != 0, "the episode id was not refused"
    assert "room" in refused.message, f"not the episode-id rule's refusal: {refused.message!r}"
    assert refused.questioner.calls == 0
    assert _no_episode_made(before)

    # The control under a fresh data root: two sources of one tenant would share the fixture's
    # one session-store case, and the second could never seed its branch point.
    (tmp_path / "control").mkdir()
    monkeypatch.setenv(P.DATA_ROOT_ENV, str(tmp_path / "control-data"))
    est2, short = P.launch_source(tmp_path / "control")
    control = P.drive_launch(est2, P.launch_argv(P.LAUNCH_TENANT, short))
    assert control.questioner.calls > 0, f"the control never launched: {control.message!r}"


def test_g15_a_link_at_the_derived_episode_name_is_passed_over_and_left_untouched(tmp_path):
    """G15(iii), at the entry point. N17's exclusive claim adopts nothing: a link planted at the
    derived episode name (pointing at a real folder outside the root) is passed over, the launch
    claims `<id>-r2` and runs there, and the link and its target are untouched. Today the only
    pins call `prepare_episode` directly."""
    est, src = P.launch_source(tmp_path)
    root = _episodes()
    root.mkdir(parents=True, exist_ok=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep.txt").write_text("not an episode\n", encoding="utf-8")
    os.symlink(elsewhere, root / P.EPISODE_ID)
    before = P.tree(elsewhere)

    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src), spawn=P.T.FakeSpawn())

    assert got.questioner.calls > 0, f"the launch never ran: {got.message!r}"
    assert (root / P.EPISODE_ID).is_symlink()
    assert os.readlink(root / P.EPISODE_ID) == str(elsewhere)
    assert P.tree(elsewhere) == before, "the launch wrote through the link"
    claimed = root / f"{P.EPISODE_ID}-r2"
    assert claimed.is_dir(), sorted(p.name for p in root.iterdir())
    assert not claimed.is_symlink(), sorted(p.name for p in root.iterdir())
    assert (claimed / "family.yaml").is_file()


def test_g16_a_source_pointer_naming_another_tenants_store_is_refused_before_anything_is_spent(
        tmp_path):
    """G16. `open_source_store` refuses a source whose session pointer names a store other than
    the one derived from the run folder — here another real tenant's `sessions/` holding a copy
    of the store. Driven through the launcher's branch-point check: refused before the
    questioner, no episode folder. (Fork S moves where `runs_base` comes from; the compare and
    its `.resolve()` stay.) The positive control is the source's own pointer: it launches."""
    import json

    est, src = P.launch_source(tmp_path)
    beta = P.second_tenant(P.data_root(), "beta")
    pointer = src / "session_store_pointer.json"
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


# ==========================================================================================
# The sibling (G4, G5, G6, G19): refused before the spend; the control runs its arm.
# ==========================================================================================

def test_g4_a_sibling_refuses_a_source_alert_that_is_a_link_and_never_copies_its_target(
        tmp_path):
    """G4, the sibling's screen (`run.py:460-475`), pinned today only through `--resume`. The
    source run's `alert.json` is a link to a file outside it: the sibling refuses before any
    lifecycle, and no arm's alert carries the target's bytes. The positive control restores a
    plain alert: the sibling reaches its lifecycle, its arm's alert being the source's."""
    src, ep = P.sibling_scene(tmp_path, container=P.SIBLING_TENANT)
    secret = tmp_path / "secret.json"
    secret.write_text('{"secret": "outside the source run"}\n', encoding="utf-8")
    alert = src / "alert.json"
    plain = alert.read_bytes()
    alert.unlink()
    os.symlink(secret, alert)

    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    assert refused is not None, f"the sibling ran over a linked alert ({rc})"
    assert rc is None, f"the sibling ran over a linked alert ({rc})"
    assert "alert" in P.refusal_text(refused), P.refusal_text(refused)
    assert "lifecycle" not in rec.order
    arm = ep / "runs" / f"{P.EPISODE_ID}-b"
    assert not (arm / "alert.json").exists() or b"outside the source run" not in (
        arm / "alert.json").read_bytes()

    alert.unlink()
    alert.write_bytes(plain)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert ok.run_dir is not None
    assert (ok.run_dir / "alert.json").read_bytes() == plain


def test_g5_a_sibling_whose_container_names_another_tenant_is_refused_and_writes_nothing(
        tmp_path):
    """G5. The episode's container `runs/_tenant.json` names another real tenant (`acme`) while
    the request names T. Today run setup's record check refuses it (`run_common.py:102`); after
    PR 2 `runs.episode(ep)` refuses it before the manifest. Observable either way: a refusal,
    no lifecycle, no arm folder, and the foreign record byte-for-byte unchanged.

    The positive control is NEW: the existing ones run over a container with no record, which
    PR 2 refuses (declared change 6). Here the same episode with its container naming T resumes,
    and its arm lands inside that container."""
    src, ep = P.sibling_scene(tmp_path, container="acme")
    P.second_tenant(P.data_root(), "acme")
    record = ep / "runs" / "_tenant.json"
    foreign = record.read_bytes()

    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    assert refused is not None, "a sibling ran in another tenant's container"
    assert rc is None, "a sibling ran in another tenant's container"
    assert "acme" in P.refusal_text(refused), P.refusal_text(refused)
    assert "lifecycle" not in rec.order
    assert sorted(p.name for p in (ep / "runs").iterdir()) == ["_tenant.json"]
    assert record.read_bytes() == foreign

    shutil.rmtree(ep / "runs")
    P.plant_record(ep / "runs", P.SIBLING_TENANT)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert ok.run_dir == ep / "runs" / f"{P.EPISODE_ID}-b"


def test_g6_a_sibling_whose_tenant_lies_under_the_episode_container_is_refused(
        tmp_path, monkeypatch):
    """G6. A sibling's box mounts its episode container; the tenant's settings half must lie
    under no tree a box mounts. Here the data root itself lies inside `<episode>/runs`, so the
    tenant's settings would be inside the box's mount. Today acceptance refuses it
    (`box_mounted=(episode.runs.path,)`); after PR 2 the episode owner's root check refuses an
    episodes base containing the data root first. Either way: refused before the preflight and
    the lifecycle. No existing test drives this through `run.py`.

    The positive control is the same episode with the data root outside it: the sibling runs."""
    episodes = _episodes()
    ep = episodes / P.EPISODE_ID
    inner_root = ep / "runs" / "data"
    inner_root.mkdir(parents=True)
    monkeypatch.setenv(P.DATA_ROOT_ENV, str(inner_root))
    _base, src = P.T.runs_base(tmp_path, source_run_id=P.SOURCE_RUN_ID)
    assert inner_root in src.parents
    P.T.episode(tmp_path, doc=P.family_doc(src), root=episodes)
    P.plant_record(ep / "runs", P.SIBLING_TENANT)

    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    assert refused is not None, "a sibling ran with its tenant under its box mount"
    assert rc is None, "a sibling ran with its tenant under its box mount"
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"

    outside_ep = tmp_path / "outside-ep"
    monkeypatch.setenv(P.DATA_ROOT_ENV, str(tmp_path / "data-outside"))
    monkeypatch.setenv(P.EPISODES_BASE_ENV, str(outside_ep))
    src2, ep2 = P.sibling_scene(tmp_path / "control", container=P.SIBLING_TENANT)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep2, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert src2.is_dir()


def test_g19_a_sibling_for_another_tenant_is_refused_before_any_write_or_spend(tmp_path):
    """G19. A hand resume naming another real tenant (`acme`) over T's episode — whose container
    record names T — is refused before the preflight (no model key spent), before the lifecycle,
    and BEFORE ANY WRITE: the episodes root and the data root are census-identical after it.
    Today `_sibling_tenant_agrees` refuses after the manifest read; PR 2 refuses earlier, at
    `runs.episode(ep)`. The existing pins assert no spend but take no write census. The positive
    control is the same episode resumed by T: it runs."""
    src, ep = P.sibling_scene(tmp_path, container=P.SIBLING_TENANT)
    P.second_tenant(P.data_root(), "acme")
    episodes_before, data_before = P.tree(_episodes()), P.tree(P.data_root())

    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(P.sibling_argv("acme", ep, "b"), rec)
    assert refused is not None, "a sibling resumed another tenant's episode"
    assert rc is None, "a sibling resumed another tenant's episode"
    said = P.refusal_text(refused)
    assert "acme" in said, f"the refusal does not name the requested tenant: {said!r}"
    assert P.SIBLING_TENANT in said, f"the refusal does not name the episode's tenant: {said!r}"
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"
    assert P.tree(_episodes()) == episodes_before, "the refused sibling wrote under the episodes root"
    assert P.tree(P.data_root()) == data_before, "the refused sibling wrote under the data root"

    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"


# ==========================================================================================
# The pages (G9, G11, G23).
# ==========================================================================================

def _sample(tmp_path: Path, tenant_id: str) -> E.Episode:
    """`_episode_1025`'s sample episode under the configured episodes base, its container
    `runs/` carrying the `_tenant.json` naming `tenant_id` that the launcher's `start_family`
    writes before the first arm (C-18) — the fixture predates #1078 and carries none."""
    ep = E.sample_episode(tmp_path, root=_episodes())
    P.plant_record(ep.dir / "runs", tenant_id)
    return ep


def test_g9_a_linked_episode_container_reads_as_absent_on_the_page(tmp_path, d9_tenant):
    """G9(ii) (R51-20). A link at `<episode>/runs` — to a real folder holding T's record and the
    arms — is never followed by the page: the page renders, every arm reads "run directory
    absent", and no arm's run-page link appears. PR 2 keeps this: the view records an
    unreadable container and does not raise. The positive control is the same episode with a
    real `runs/`: the page links each arm's run page."""
    ep = _sample(tmp_path, d9_tenant)
    arm_link = f"runs/{P.EPISODE_ID}-{E.CONTROL}/runtime.html"

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
    byte-for-byte unchanged. The positive control renders T's real run."""
    src, _ep = P.sibling_scene(tmp_path, container=P.SIBLING_TENANT)
    runs = src.parent
    absent = runs / "20990101t000000z-absent"
    a_file = runs / "20990101t000000z-a-file"
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
    path. A regular file at `<episodes root>/<episode id>` is refused: non-zero exit, the file
    unchanged, nothing made beside it. The positive control is a real episode at the same name:
    its page renders."""
    root = _episodes()
    root.mkdir(parents=True, exist_ok=True)
    squatter = root / P.EPISODE_ID
    squatter.write_bytes(b"a file, not an episode\n")
    before = P.tree(root)

    got = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, squatter))
    assert got.rc not in (0, None) or got.raised is not None, f"the page rendered a file: {got.said}"
    assert P.tree(root) == before

    squatter.unlink()
    ep = _sample(tmp_path, d9_tenant)
    assert ep.dir == squatter
    ok = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert ok.rc == 0, f"the control page was not rendered: {ok.said}"
    assert ep.page.is_file()
