"""Guards on migrated paths: cross-tenant sources and containers, links and files at derived names are refused before anything is spent or written."""
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


def test_g1_a_source_whose_runs_record_names_another_tenant_is_refused_before_anything_is_spent(
        tmp_path):
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


def test_g4_a_sibling_refuses_a_source_alert_that_is_a_link_and_never_copies_its_target(
        tmp_path):
    src, ep = P.sibling_scene(tmp_path, container=P.SIBLING_TENANT)
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
    arm = ep / "runs" / f"{P.EPISODE_ID}-b"
    assert not (arm / "alert.json").exists() or b"outside the source run" not in (
        arm / "alert_input" / "alert.json").read_bytes()

    alert.unlink()
    alert.write_bytes(plain)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert ok.run_dir is not None
    assert (ok.run_dir / "alert_input" / "alert.json").read_bytes() == plain


def test_g5_a_sibling_whose_container_names_another_tenant_is_refused_and_writes_nothing(
        tmp_path):
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


def _sample(tmp_path: Path, tenant_id: str) -> E.Episode:
    """`_episode_1025`'s sample episode under the configured episodes base, its container
    `runs/` carrying the `_tenant.json` naming `tenant_id` that the launcher's `start_family`
    writes before the first arm (C-18) — the fixture predates #1078 and carries none."""
    ep = E.sample_episode(tmp_path, root=_episodes())
    P.plant_record(ep.dir / "runs", tenant_id)
    return ep


def test_g9_a_linked_episode_container_reads_as_absent_on_the_page(tmp_path, d9_tenant):
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
