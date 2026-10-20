"""Guards on migrated paths: cross-tenant sources and containers, links and files at derived names are refused before anything is spent or written."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P


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

    from defender.tests.storage.ids_1187 import _spec1187 as S

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
    import json

    from defender.run_repository import RunPaths

    est, src = P.launch_source(tmp_path)
    beta = P.second_tenant(P.data_root(), H.U_ID)
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
    from defender.episodes._episode_paths import EpisodePaths
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
    P.second_tenant(P.data_root(), H.T_ID)
    episodes_before, data_before = P.tree(P.episodes(P.SIBLING_TENANT)), P.tree(P.data_root())

    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(P.sibling_argv(H.T_ID, ep, "b"), rec)
    assert refused is not None, "a sibling resumed another tenant's episode"
    assert rc is None, "a sibling resumed another tenant's episode"
    said = P.refusal_text(refused)
    assert H.T_ID in said, f"the refusal does not name the requested tenant: {said!r}"
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


def _sample(tmp_path: Path, tenant_id: str) -> E.Episode:
    """`_episode_1025`'s sample episode at `<data root>/<tenant_id>/episodes/<uuid>/` (#1187
    Layout A), as RUNS leaves it: the arm roster naming every world, each arm at its roster id.
    No container record (R1)."""
    return E.sample_episode(tmp_path, root=P.episodes(tenant_id))


def test_g9_a_linked_episode_container_reads_as_absent_on_the_page(tmp_path, d9_tenant):
    ep = _sample(tmp_path, d9_tenant)
    roster = E.T.read_roster(ep.dir)
    arm_link = f"runs/{roster[E.T.world_id(ep.dir, E.CONTROL)]}/runtime.html"

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
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.storage.ids_1187 import _spec1187 as S

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
