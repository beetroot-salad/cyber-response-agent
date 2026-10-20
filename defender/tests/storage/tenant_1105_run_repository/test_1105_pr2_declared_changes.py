"""Migrated callers (launcher, run page, judge enqueue/drain, tracer, ...) address runs by tenant and id: refusals for links, absent containers, and bad rows."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid


import copy
import json
import os
import shutil
from pathlib import Path

import pytest

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P


RID_R1 = fixture_uuid('pr2-dc8-r1')

ONLY_IN_U = fixture_uuid('pr2-dc8-only-in-u')

NOPE = fixture_uuid('pr2-dc8-nope')

LINKED = fixture_uuid('pr2-dc8-linked')

@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _episode_names() -> set[str]:
    """Every entry under any tenant's `<data root>/<T>/episodes/` — #1187 Layout A, where every
    launch claims its episode (O9: no configured episodes root)."""
    root = P.data_root()
    return {str(p.relative_to(root)) for p in root.glob("*/episodes/*")}


def _launched(got: P.Launched) -> bool:
    return got.raised is None and got.rc == 0 and got.questioner.calls > 0


def _refused_unspent(got: P.Launched) -> bool:
    """Refused (an operator exit or a non-zero status) before the question-writer was paid."""
    return (got.raised is not None or got.rc not in (0, None)) and got.questioner.calls == 0


def _sample(tmp_path: Path, tenant_id: str) -> E.Episode:
    """Create a tenant-scoped sample with a roster and arms at their recorded UUIDs."""
    return E.sample_episode(tmp_path, root=P.episodes(tenant_id))


def _corrupt_manifest(ep: Path) -> None:
    (ep / "family.yaml").write_text("episode_id: [this is not a manifest\n", encoding="utf-8")


def test_dc1_a_source_under_a_linked_runs_folder_is_refused(tmp_path):
    est, src = P.launch_source(tmp_path)

    runs = src.parent
    moved = tmp_path / "runs-elsewhere"
    runs.rename(moved)
    os.symlink(moved, runs)
    before = _episode_names()

    refused = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _refused_unspent(refused), "a source under a linked runs folder launched"
    assert _episode_names() == before

    os.unlink(runs)
    moved.rename(runs)
    control = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(control), f"the control did not launch: {control.message!r}"


def test_dc2_the_judges_prompt_carries_no_sibling_view_or_tally(tmp_path):
    est, src = P.launch_source(tmp_path)
    prior = src.parent / "20260101t000000z-prior-trial"
    prior.mkdir()
    (prior / "alert.json").write_text(json.dumps({"alert_id": P.J.ALERT_ID}), encoding="utf-8")
    (prior / "report.md").write_text(P.T.report_text("benign"), encoding="utf-8")

    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(got), f"the launch did not run: {got.message!r}"
    prompts = got.judge.prompts
    assert prompts, "the judge was never asked"
    from defender.learning.judge.layout import FOCUS_VIEW_TITLES

    # #1234 M3/A10: the focus world's report view is titled, in host text, by its world label.
    assert any(f" — {FOCUS_VIEW_TITLES['report']}" in p for p in prompts)
    for prompt in prompts:
        assert "SIBLING TRIALS" not in prompt, "the prompt still carries the sibling view"
        assert "TRIAL SPREAD" not in prompt, "the prompt still carries the trial spread"
        assert prior.name not in prompt, "a same-alert prior run reached the judge"


def test_dc3_a_world_label_equal_to_a_natural_run_id_grades(tmp_path, caplog):
    import yaml

    from defender.tests.support.learning.judge import _judge_921 as J

    est, src = P.launch_source(tmp_path)
    natural = H.make_run(src.parent, "b")
    (natural / "report.md").write_text(P.T.report_text("benign"), encoding="utf-8")

    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(got), f"the launch did not run: {got.message!r}"
    judge_failures = [r.getMessage() for r in caplog.records if "judge pass failed" in r.getMessage()]
    assert got.judge.prompts, (
        f"the judge was never asked — a world label equal to a natural run id under <T>/runs "
        f"refused the grade: {judge_failures}")
    ep = _the_launched_episode()
    graded = J.world_rows(J.judge_record(ep))
    assert {"b", "c"} <= set(graded), f"the episode's worlds were not graded: {sorted(graded)}"
    assert natural.is_dir()

    manifest = ep / "family.yaml"
    good = manifest.read_bytes()
    for bad in ("family", "x y"):
        doc = yaml.safe_load(good)
        # A deep copy: a shared node would be dumped as a YAML alias, which the manifest
        # reader refuses before any label is judged.
        seat = copy.deepcopy(next(w for w in doc["worlds"] if w.get("label") == "c"))
        doc["worlds"].append({**seat, "label": bad, "world_id": fixture_uuid("world:invalid:" + bad)})
        manifest.write_text(yaml.safe_dump(doc), encoding="utf-8")
        with pytest.raises(J.refusals()) as refused:
            P.grade(ep, P.LAUNCH_TENANT)
        # Quoted: the bare word `family` is also in every `family.yaml` refusal.
        assert repr(bad) in str(refused.value), (
            f"the label gate did not refuse {bad!r} by name: {refused.value}")
        assert not (ep / "judge.yaml").exists()


def test_dc4_the_page_judges_the_container_record_first(tmp_path, d9_tenant):
    P.second_tenant(P.data_root(), H.U_ID)
    ep, episode_id = _tenant_episode(H.U_ID)
    page = ep / E.PAGE_NAME
    good_manifest = (ep / "family.yaml").read_bytes()
    before = P.tree(ep)

    foreign = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, episode_id))
    assert foreign.rc not in (0, None) or foreign.raised is not None, (
        "another tenant's episode was rendered")
    assert not page.exists()
    assert P.tree(ep) == before, "T's request changed beta's episode"

    _corrupt_manifest(ep)
    first = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, episode_id))
    assert first.rc not in (0, None) or first.raised is not None
    assert "family.yaml" not in first.said, (
        f"T's request read beta's manifest before refusing: {first.said!r}")

    own_corrupt = P.drive_cli(P.page_main(), P.new_page_argv(H.U_ID, episode_id))
    assert own_corrupt.rc not in (0, None) or own_corrupt.raised is not None
    assert "family.yaml" in own_corrupt.said, (
        f"control: beta's own request did not reach its manifest: {own_corrupt.said!r}")
    (ep / "family.yaml").write_bytes(good_manifest)
    ok = P.drive_cli(P.page_main(), P.new_page_argv(H.U_ID, episode_id))
    assert ok.rc == 0, ok.said
    assert page.is_file(), ok.said


def test_dc4_the_page_roster_is_the_manifests_arms_and_no_stray(tmp_path, d9_tenant):
    from defender.tests.storage.ids_1187 import _spec1187 as S

    ep = _sample(tmp_path, d9_tenant)
    roster = _roster_by_hand(ep.dir)
    for label in E.WORLDS:
        E.run_dir(ep.dir, label)
        decoy = ep.dir / "runs" / f"{P.EPISODE_ID}-{label}"
        (decoy / "gather_raw").mkdir(parents=True, exist_ok=True)
        (decoy / "runtime.html").write_text("<!doctype html><title>decoy</title>",
                                            encoding="utf-8")
    strays = ("stray_run_dir", f"{P.EPISODE_ID}-orphan", S.new_id())
    for name in strays:
        (ep.dir / "runs" / name / "gather_raw").mkdir(parents=True)

    ok = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert ok.rc == 0, f"the page was not rendered: {ok.said}"
    page = E.read_page(ep)
    for label in E.WORLDS:
        assert f"world-{label}" in page.by_id, f"the manifest arm {label} has no section"
        assert f"runs/{roster[P.T.world_id(ep.dir, label)]}/runtime.html" in page.hrefs, (
            f"the manifest arm {label} has no run-page link at its roster id: {page.hrefs}")
        assert not any(f"runs/{P.EPISODE_ID}-{label}/" in href for href in page.hrefs), (
            f"the manifest arm {label} is linked at its composed decoy: {page.hrefs}")
    shown = sorted(i for i in page.ids_with("world-")
                   if i not in {f"world-{label}" for label in E.WORLDS})
    assert shown == [], f"a stray runs/ entry was sectioned: {shown}"
    for name in strays:
        assert not any(name in href for href in page.hrefs), f"{name} is linked"
        assert name not in page.text, f"{name} is shown on the page"
        assert (ep.dir / "runs" / name).is_dir()
    assert "not declared in the manifest" not in page.text


class _LinkingSibling(P.J.FakeSibling):
    """`FakeSibling` whose arm `b` is materialised OUTSIDE the container, with a link left at
    its name: the one arm-entry shape a host (never a box: seccomp, B-03) can leave. #1187: the
    arm's name is the id the episode's roster holds for `b`."""

    def __init__(self, *, outside: Path) -> None:
        super().__init__()
        self.outside = outside

    def __call__(self, argv, *, env=None, **kw):
        rc = super().__call__(argv, env=env, **kw)
        if self.episode_dir is None:
            return rc
        arm_id = P.T.read_roster(self.episode_dir).get(P.T.world_id(self.episode_dir, "b"))
        if arm_id is None:
            return rc
        arm = self.episode_dir / "runs" / arm_id
        if arm.is_dir() and not arm.is_symlink():
            target = self.outside / arm.name
            shutil.move(str(arm), str(target))
            (target / "report.md").write_text(
                P.T.report_text("benign", extra="OUTSIDE-THE-CONTAINER"), encoding="utf-8")
            os.symlink(target, arm)
        return rc


def test_dc5_an_arm_entry_that_is_a_link_is_never_archived(tmp_path, monkeypatch):
    est, src = P.launch_source(tmp_path)
    outside = tmp_path / "outside-arms"
    outside.mkdir()
    linking = _LinkingSibling(outside=outside)
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src), spawn=linking)
    assert got.questioner.calls > 0, f"the launch never ran: {got.message!r}"
    ep = _the_launched_episode()
    assert linking.faults == [], linking.faults
    assert any(p.is_symlink() for p in (ep / "runs").iterdir()), (
        "the double left no link at arm b's name: the scene this test is about was not built")
    archived = [p for p in (ep / "worlds").rglob("*") if p.is_file()] if (
        ep / "worlds").is_dir() else []
    leaked = [p for p in archived if b"OUTSIDE-THE-CONTAINER" in p.read_bytes()]
    assert leaked == [], f"the link's target was archived: {leaked}"

    control_root = tmp_path / "control"
    control_root.mkdir()
    monkeypatch.setenv(P.DATA_ROOT_ENV, str(tmp_path / "control-data"))
    P.roots(control_root, monkeypatch)
    est2, src2 = P.launch_source(control_root)
    clean = P.drive_launch(est2, P.launch_argv(P.LAUNCH_TENANT, src2))
    assert _launched(clean), f"the control did not launch: {clean.message!r}"
    assert (_the_launched_episode() / "worlds" / P.T.world_id(_the_launched_episode(), "b") / "report.md").is_file()


def test_dc6_a_sibling_over_an_absent_container_is_refused(tmp_path):
    src, ep = P.sibling_scene(tmp_path, roster=False)
    assert not (ep / "runs").exists()
    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    assert refused is not None, "a sibling ran over an episode that never reached RUNS"
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"
    assert not (ep / "runs").exists(), "the refused sibling made the container"

    roster = _start_runs_by_hand(ep)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert ok.run_dir == ep / "runs" / roster[P.T.world_id(ep, "b")], f"the arm is at {ok.run_dir}"


def test_dc6_the_sibling_judges_the_container_before_the_manifest(tmp_path):
    """Malformed UUID roster keys refuse before the poisoned manifest is read."""
    from defender import _yaml
    from defender.tests.storage.ids_1187 import _spec1187 as S

    poison = "zz_dc6_never_read_before_the_roster"
    src, ep = P.sibling_scene(tmp_path, roster=False)
    good = (ep / "family.yaml").read_bytes()
    roster = _start_runs_by_hand(ep)
    S.write_roster(ep, {**roster, "b": roster[P.T.world_id(ep, "b")]})
    doc = _yaml.safe_load(good.decode("utf-8"))
    (ep / "family.yaml").write_text(_yaml.safe_dump({**doc, poison: "read"}), encoding="utf-8")

    rec = P.SiblingRecorder()
    _rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    said = f"{P.refusal_text(refused)}\n{err}"
    assert refused is not None
    assert rec.order == []
    assert poison not in said, f"the manifest was read before the roster: {said!r}"

    S.write_roster(ep, roster)
    mrec = P.SiblingRecorder()
    _rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), mrec)
    assert refused is not None
    assert poison in f"{P.refusal_text(refused)}\n{err}", (
        "past the roster, the manifest's refusal should name the poisoned field")
    assert mrec.order == []

    (ep / "family.yaml").write_bytes(good)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"


def test_dc7_the_run_page_refuses_a_linked_run_folder(tmp_path):
    src, _ep = P.sibling_scene(tmp_path)
    # #1187 declared change 1: the link's name is a uuid, so the id rule admits it and the
    # refusal is the link's (O8), never the id grammar's.
    target = tmp_path / "elsewhere" / fixture_uuid("dc7-linked")
    shutil.copytree(src, target)
    link = src.parent / target.name
    os.symlink(target, link)
    before = P.tree(target)

    got = P.drive_cli(P.run_page_main(), P.run_page_argv(P.SIBLING_TENANT, link))
    assert got.rc not in (0, None) or got.raised is not None, "the run page followed a linked run"
    assert P.tree(target) == before, "the run page wrote into the link's target"

    ok = P.drive_cli(P.run_page_main(), P.run_page_argv(P.SIBLING_TENANT, src))
    assert ok.rc == 0, ok.said
    assert (src / "runtime.html").is_file(), ok.said


def test_dc8_a_natural_run_enqueues_its_address_not_its_folder(tmp_path, d9_tenant):
    from defender.box import _scrub as scrub
    from defender.learning.core.config import LoopPaths
    from defender.tenancy._tenant import requested_tenant

    tenant = requested_tenant(P.data_root(), d9_tenant)
    tenant.learning.mkdir(exist_ok=True)
    alert = H.alert_file(tmp_path / "in")
    rec = P.SiblingRecorder()

    def scrubbed_lifecycle(**kwargs):
        rec.order.append("lifecycle")
        rec.lifecycle_kwargs = kwargs
        scrub.scrub(Path(kwargs["run"].run_dir))
        return {"output": "ok", "requests": 0, "truncated_by": None}

    seams = {k: v for k, v in rec.seams().items() if k != "enqueue"}
    seams["lifecycle"] = scrubbed_lifecycle
    from defender import run as run_py

    rc = run_py.main([str(alert), "--tenant", d9_tenant], **seams)
    assert rc == 0
    run_dir = rec.run_dir
    assert run_dir is not None
    assert run_dir.parent == P.data_root() / d9_tenant / "runs"
    queue = LoopPaths.for_tenant(tenant).state_root / "author-queue"
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(queue.glob("*.json"))]
    assert len(rows) == 1, rows
    row = rows[0]
    assert set(row) == {"case_id", "tenant_id", "run_id"}, f"the row is {row!r}"
    assert row["tenant_id"] == d9_tenant
    assert row["run_id"] == run_dir.name
    assert not any(str(run_dir) in str(v) for v in row.values())


def _drain_scene(tmp_path: Path):
    """Two real tenants under the data root, each with a natural runs folder holding `RID_R1`, and
    the drain's paths (a git work tree and a state root)."""
    root = P.data_root()
    t = H.tenant(root, H.T_ID)
    u = H.tenant(root, H.U_ID)
    for tenant in (t, u):
        H.runs_folder(tenant)
        H.make_run(tenant.runs, RID_R1)
    return t, u, P.loop_paths(tmp_path)


def test_dc8_the_drain_rehydrates_the_row_in_its_own_tenant(tmp_path):
    t, u, paths = _drain_scene(tmp_path)
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": H.T_ID, "run_id": RID_R1})
    P.queue_row(paths, "case-u", {"case_id": "case-u", "tenant_id": H.U_ID, "run_id": RID_R1})
    lane = P.Lane()
    P.drain(paths, lane)
    assert sorted(lane.run_dirs) == sorted([Path(t.runs) / RID_R1, Path(u.runs) / RID_R1]), (
        f"served {lane.run_dirs}")
    assert P.dead_letter(paths, "case-t") is None
    assert P.dead_letter(paths, "case-u") is None


def test_dc8_a_row_that_cannot_be_reached_is_artifact_missing(tmp_path):
    t, u, paths = _drain_scene(tmp_path)
    H.make_run(u.runs, ONLY_IN_U)
    os.symlink(Path(t.runs) / RID_R1, Path(t.runs) / LINKED)
    gone = {
        "absent": {"case_id": "absent", "tenant_id": H.T_ID, "run_id": NOPE},
        "crossed": {"case_id": "crossed", "tenant_id": H.T_ID, "run_id": ONLY_IN_U},
    }
    not_now = {
        "ghost": {"case_id": "ghost", "tenant_id": fixture_uuid("tenant:ghost"), "run_id": RID_R1},
        "linked": {"case_id": "linked", "tenant_id": H.T_ID, "run_id": LINKED},
    }
    for case_id, body in {**gone, **not_now}.items():
        P.queue_row(paths, case_id, body)
    P.queue_row(paths, "own", {"case_id": "own", "tenant_id": H.U_ID, "run_id": ONLY_IN_U})
    lane = P.Lane()
    P.drain(paths, lane)
    assert lane.run_dirs == [Path(u.runs) / ONLY_IN_U], f"served {lane.run_dirs}"
    for case_id in gone:
        letter = P.dead_letter(paths, case_id)
        assert letter is not None, f"{case_id}: {letter!r}"
        assert letter.get("failed") == "artifact-missing", f"{case_id}: {letter!r}"
    for case_id in not_now:
        assert P.dead_letter(paths, case_id) is None, f"{case_id} was dead-lettered at once"
        assert P.still_queued(paths, case_id), f"{case_id} was not re-queued"


def test_dc8_a_drain_with_no_data_root_leaves_its_rows_queued(tmp_path, monkeypatch):
    t, _u, paths = _drain_scene(tmp_path)
    root = os.environ[P.DATA_ROOT_ENV]
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": H.T_ID, "run_id": RID_R1})
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    lane = P.Lane()
    H.raised(P.drain, paths, lane)
    assert lane.handed == [], "the drain served a row with no data root"
    assert P.dead_letter(paths, "case-t") is None
    assert P.still_queued(paths, "case-t")

    monkeypatch.setenv(P.DATA_ROOT_ENV, root)
    P.drain(paths, lane)
    assert lane.run_dirs == [Path(t.runs) / RID_R1]


def _lead_author_main():
    from defender.learning.leads import lead_author

    return lead_author.main


def _workspace_map_main():
    from defender.cli import workspace_map

    return workspace_map.main


def _lesson(lessons: Path, stem: str) -> None:
    lessons.mkdir(exist_ok=True)
    (lessons / f"{stem}.md").write_text(
        f"---\nname: {stem}\ndescription: d\ncreated_at: 2026-06-04\n---\nbody\n",
        encoding="utf-8")


def test_dc10_the_tracer_walks_the_tenants_runs_and_refuses_a_stray(tmp_path, d9_tenant):
    import uuid

    from defender.cli.learning import trace_lesson

    lessons = tmp_path / "lessons"
    _lesson(lessons, "L")
    runs = P.data_root() / d9_tenant / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    run = runs / str(uuid.uuid4())
    run.mkdir()
    from defender.tests.support.storage._alert_plant import plant_alert
    plant_alert(run)
    (run / "report.md").write_text("---\ndisposition: benign\n---\nbody\n", encoding="utf-8")
    (run / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}) + "\n",
        encoding="utf-8")

    ok = P.drive_cli(trace_lesson.main, ["--tenant", d9_tenant, "--all",
                                         "--lessons-dir", str(lessons)])
    assert ok.rc == 0, ok.said
    assert ok.out.splitlines() == ["L\td\t1\t0"], ok.out

    gone = P.drive_cli(trace_lesson.main, ["--tenant", d9_tenant, "--all", "--lessons-dir",
                                           str(lessons), "--runs-dir", str(runs)])
    assert gone.rc not in (0, None) or gone.raised is not None, "--runs-dir was accepted"

    (runs / "stray.txt").write_text("x\n", encoding="utf-8")
    stray = H.raised(P.drive_cli, trace_lesson.main,
                     ["--tenant", d9_tenant, "--all", "--lessons-dir", str(lessons)])
    if stray is None:
        got = P.drive_cli(trace_lesson.main, ["--tenant", d9_tenant, "--all",
                                              "--lessons-dir", str(lessons)])
        assert got.rc not in (0, None) or got.raised is not None, "a stray was skipped silently"
        assert "stray.txt" in got.said, got.said
    else:
        assert "stray.txt" in str(stray), repr(stray)


def _the_launched_episode() -> Path:
    """Return the single episode created under the launch tenant."""
    made = P.launched_episodes()
    assert len(made) == 1, f"expected the launch's one episode under <T>/episodes: {made}"
    return made[0]


def _tenant_episode(tenant_id: str) -> tuple[Path, str]:
    """#1187's layout (decision 1, declared change 5): `<data root>/<tenant_id>/episodes/<uuid>/`
    holding a manifest the family model loads (`_triplet_947.family_doc`, worlds a, b, c) that
    names that uuid (R5), and the arm roster `arms.json` naming every manifest world — no
    container record anywhere. Returns `(folder, episode id)`."""
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.storage.ids_1187 import _spec1187 as S

    episode_id = S.new_id()
    ep = S.make_episode(P.data_root(), tenant_id, episode_id, labels=T.WORLDS, roster=True)
    T.write_family(ep, T.family_doc(episode_id=episode_id, source_run_id=S.new_id()))
    return ep, episode_id


def _roster_by_hand(ep: Path) -> dict[str, str]:
    """Reuse a roster or migrate fixture arms and sidecars to freshly recorded UUIDs."""
    from defender import _yaml
    from defender.tests.storage.ids_1187 import _spec1187 as S

    if (ep / P.T.ROSTER_NAME).is_file():
        return S.read_roster(ep)
    doc = _yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    roster = {w["world_id"]: S.new_id() for w in doc["worlds"]}
    runs = ep / "runs"
    runs.mkdir(exist_ok=True)
    for world in doc["worlds"]:
        label, arm_id = world["label"], roster[world["world_id"]]
        composed = runs / f"{P.EPISODE_ID}-{label}"
        if composed.is_dir():
            composed.rename(runs / arm_id)
        for sidecar in runs.glob(f"{P.EPISODE_ID}-{label}.*"):
            sidecar.rename(runs / f"{arm_id}{sidecar.name[len(composed.name):]}")
    S.write_roster(ep, roster)
    return roster


def _start_runs_by_hand(ep: Path) -> dict[str, str]:
    """Write a complete roster for the manifest worlds, matching the RUNS step."""
    from defender import _yaml
    from defender.tests.storage.ids_1187 import _spec1187 as S

    doc = _yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    roster = {w["world_id"]: S.new_id() for w in doc["worlds"]}
    (ep / "runs").mkdir(exist_ok=True)
    S.write_roster(ep, roster)
    return roster
