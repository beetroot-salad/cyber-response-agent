"""Migrated callers (launcher, run page, judge enqueue/drain, tracer, ...) address runs by tenant and id: refusals for links, absent containers, and bad rows."""
from __future__ import annotations


import copy
import json
import os
import shutil
from pathlib import Path

import pytest

from defender.tests import _episode_1025 as E
from defender.tests.tenant_1105_run_repository import _spec1105 as H
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _episodes() -> Path:
    return Path(os.environ[P.EPISODES_BASE_ENV])


def _episode_names() -> set[str]:
    root = _episodes()
    return {p.name for p in root.iterdir()} if root.is_dir() else set()


def _launched(got: P.Launched) -> bool:
    return got.raised is None and got.rc == 0 and got.questioner.calls > 0


def _refused_unspent(got: P.Launched) -> bool:
    """Refused (an operator exit or a non-zero status) before the question-writer was paid."""
    return (got.raised is not None or got.rc not in (0, None)) and got.questioner.calls == 0


def _sample(tmp_path: Path, tenant_id: str | None) -> E.Episode:
    """`_episode_1025`'s sample episode under the configured episodes base, its container
    record naming `tenant_id` (`None`: the fixture as it is, with no record — an episode
    launched before #1078)."""
    ep = E.sample_episode(tmp_path, root=_episodes())
    if tenant_id is not None:
        P.plant_record(ep.dir / "runs", tenant_id)
    return ep


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
    # The cause is the link: the refusal names `<T>/runs` as one, and (its paths set aside, so
    # a temp folder's name cannot speak for it) it is neither C2's nor G16's.
    assert str(runs) in refused.message, (
        f"the refusal does not name the runs folder: {refused.message!r}")
    assert "is a link" in refused.message, (
        f"the refusal does not call the runs folder a link: {refused.message!r}")
    said = refused.message.replace(str(src), "<source>").replace(str(runs), "<runs>")
    for other in ("snapshot", "store"):
        assert other not in said, (
            f"refused for the source's {other}, not the link: {refused.message!r}")

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

    from defender.tests import _judge_921 as J

    est, src = P.launch_source(tmp_path)
    natural = H.make_run(src.parent, "b")
    (natural / "report.md").write_text(P.T.report_text("benign"), encoding="utf-8")

    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(got), f"the launch did not run: {got.message!r}"
    judge_failures = [r.getMessage() for r in caplog.records if "judge pass failed" in r.getMessage()]
    assert got.judge.prompts, (
        f"the judge was never asked — a world label equal to a natural run id under <T>/runs "
        f"refused the grade: {judge_failures}")
    ep = _episodes() / P.EPISODE_ID
    graded = J.world_rows(J.judge_record(ep))
    assert {"b", "c"} <= set(graded), f"the episode's worlds were not graded: {sorted(graded)}"
    assert natural.is_dir()

    manifest = ep / "family.yaml"
    good = manifest.read_bytes()
    for bad in ("family", "x y"):
        doc = yaml.safe_load(good)
        # A deep copy: a shared node would be dumped as a YAML alias, which the manifest
        # reader refuses before any label is judged.
        seat = copy.deepcopy(next(w for w in doc["worlds"] if w.get("world_id") == "c"))
        doc["worlds"].append({**seat, "world_id": bad})
        manifest.write_text(yaml.safe_dump(doc), encoding="utf-8")
        with pytest.raises(J.refusals()) as refused:
            P.grade(ep, P.LAUNCH_TENANT)
        # Quoted: the bare word `family` is also in every `family.yaml` refusal.
        assert repr(bad) in str(refused.value), (
            f"the label gate did not refuse {bad!r} by name: {refused.value}")
        assert not (ep / "judge.yaml").exists()


def test_dc4_a_container_with_no_record_refuses_the_page(tmp_path, d9_tenant):
    ep = _sample(tmp_path, None)
    assert not (ep.dir / "runs" / "_tenant.json").exists()

    refused = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert refused.rc not in (0, None) or refused.raised is not None, (
        "an episode whose container holds no record was rendered")
    assert not ep.page.exists()

    P.plant_record(ep.dir / "runs", d9_tenant)
    ok = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert ok.rc == 0, ok.said
    assert ep.page.is_file(), ok.said


def test_dc4_the_page_judges_the_container_record_first(tmp_path, d9_tenant):
    ep = _sample(tmp_path, d9_tenant)
    P.second_tenant(P.data_root(), "beta")
    record = ep.dir / "runs" / "_tenant.json"
    own = record.read_bytes()
    record.unlink()
    P.plant_record(ep.dir / "runs", "beta")
    good_manifest = (ep.dir / "family.yaml").read_bytes()

    foreign = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert foreign.rc not in (0, None) or foreign.raised is not None, (
        "another tenant's episode was rendered")
    assert not ep.page.exists()

    _corrupt_manifest(ep.dir)
    first = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert first.rc not in (0, None) or first.raised is not None
    assert "_tenant.json" in first.said or "beta" in first.said, (
        f"the manifest was judged before the container record: {first.said!r}")

    record.write_bytes(own)
    manifest_first = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert manifest_first.rc not in (0, None) or manifest_first.raised is not None
    assert "_tenant.json" not in manifest_first.said
    (ep.dir / "family.yaml").write_bytes(good_manifest)
    ok = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert ok.rc == 0, ok.said
    assert ep.page.is_file(), ok.said


def test_dc4_the_page_roster_is_the_manifests_arms_and_no_stray(tmp_path, d9_tenant):
    ep = _sample(tmp_path, d9_tenant)
    strays = ("stray_run_dir", f"{P.EPISODE_ID}-orphan")
    for name in strays:
        (ep.dir / "runs" / name / "gather_raw").mkdir(parents=True)

    ok = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert ok.rc == 0, f"the page was not rendered: {ok.said}"
    page = E.read_page(ep)
    for label in E.WORLDS:
        assert f"world-{label}" in page.by_id, f"the manifest arm {label} has no section"
        assert f"runs/{P.EPISODE_ID}-{label}/runtime.html" in page.hrefs, (
            f"the manifest arm {label} has no run-page link: {page.hrefs}")
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
    its name: the one arm-entry shape a host (never a box: seccomp, B-03) can leave."""

    def __init__(self, episode_dir: Path, *, outside: Path) -> None:
        super().__init__(episode_dir)
        self.outside = outside

    def __call__(self, argv, *, env=None, **kw):
        rc = super().__call__(argv, env=env, **kw)
        arm = self.episode_dir / "runs" / f"{P.EPISODE_ID}-b"
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
    ep = _episodes() / P.EPISODE_ID
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src),
                         spawn=_LinkingSibling(ep, outside=outside))
    assert got.questioner.calls > 0, f"the launch never ran: {got.message!r}"
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
    assert (_episodes() / P.EPISODE_ID / "worlds" / "b" / "report.md").is_file()


def test_dc6_a_sibling_over_an_absent_container_is_refused(tmp_path):
    src, ep = P.sibling_scene(tmp_path, container=None)
    assert not (ep / "runs").exists()
    rec = P.SiblingRecorder()
    rc, refused, _err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    assert refused is not None, "a sibling ran over an episode with no container"
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"
    assert not (ep / "runs").exists(), "the refused sibling made the container"

    P.plant_record(ep / "runs", P.SIBLING_TENANT)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"


def test_dc6_the_sibling_judges_the_container_before_the_manifest(tmp_path):
    src, ep = P.sibling_scene(tmp_path, container="beta")
    P.second_tenant(P.data_root(), "beta")
    good = (ep / "family.yaml").read_bytes()
    _corrupt_manifest(ep)

    rec = P.SiblingRecorder()
    _rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    said = f"{P.refusal_text(refused)}\n{err}"
    assert refused is not None
    assert rec.order == []
    assert "_tenant.json" in said or "beta" in said, (
        f"the manifest was read before the container record: {said!r}")

    shutil.rmtree(ep / "runs")
    P.plant_record(ep / "runs", P.SIBLING_TENANT)
    mrec = P.SiblingRecorder()
    _rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), mrec)
    assert refused is not None
    assert "_tenant.json" not in f"{P.refusal_text(refused)}\n{err}"

    (ep / "family.yaml").write_bytes(good)
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"


def test_dc6_a_sibling_needs_the_episodes_base(tmp_path, monkeypatch):
    src, ep = P.sibling_scene(tmp_path, container=P.SIBLING_TENANT)
    monkeypatch.delenv(P.EPISODES_BASE_ENV)
    rec = P.SiblingRecorder()
    _rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    assert refused is not None, "a sibling ran with no episodes base"
    assert rec.order == [], "a sibling ran with no episodes base"
    assert P.EPISODES_BASE_ENV in f"{P.refusal_text(refused)}\n{err}"

    monkeypatch.setenv(P.EPISODES_BASE_ENV, str(ep.parent))
    ok = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0, f"the control was refused: {P.refusal_text(refused)} {err}"


def test_dc7_the_run_page_refuses_a_linked_run_folder(tmp_path):
    src, _ep = P.sibling_scene(tmp_path, container=P.SIBLING_TENANT)
    target = tmp_path / "elsewhere" / "20260101t000000z-linked"
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
    from defender.runtime import scrub

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
    from defender.learning.core.config import loop_paths

    queue = Path(loop_paths().state_root) / "author-queue"
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(queue.glob("*.json"))]
    assert len(rows) == 1, rows
    row = rows[0]
    assert set(row) == {"case_id", "tenant_id", "run_id"}, f"the row is {row!r}"
    assert row["tenant_id"] == d9_tenant
    assert row["run_id"] == run_dir.name
    assert not any(str(run_dir) in str(v) for v in row.values())


def _drain_scene(tmp_path: Path):
    """Two real tenants under the data root, each with a natural runs folder holding `r1`, and
    the drain's paths (a git work tree and a state root)."""
    root = P.data_root()
    t = H.tenant(root, H.T_ID)
    u = H.tenant(root, H.U_ID)
    for tenant in (t, u):
        H.runs_folder(tenant)
        H.make_run(tenant.runs, "r1")
    return t, u, P.loop_paths(tmp_path)


def test_dc8_the_drain_rehydrates_the_row_in_its_own_tenant(tmp_path):
    t, u, paths = _drain_scene(tmp_path)
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": H.T_ID, "run_id": "r1"})
    P.queue_row(paths, "case-u", {"case_id": "case-u", "tenant_id": H.U_ID, "run_id": "r1"})
    lane = P.Lane()
    P.drain(paths, lane)
    assert sorted(lane.run_dirs) == sorted([Path(t.runs) / "r1", Path(u.runs) / "r1"]), (
        f"served {lane.run_dirs}")
    assert P.dead_letter(paths, "case-t") is None
    assert P.dead_letter(paths, "case-u") is None


def test_dc8_a_row_that_cannot_be_reached_is_artifact_missing(tmp_path):
    t, u, paths = _drain_scene(tmp_path)
    H.make_run(u.runs, "only-in-u")
    os.symlink(Path(t.runs) / "r1", Path(t.runs) / "linked")
    gone = {
        "absent": {"case_id": "absent", "tenant_id": H.T_ID, "run_id": "nope"},
        "crossed": {"case_id": "crossed", "tenant_id": H.T_ID, "run_id": "only-in-u"},
    }
    not_now = {
        "ghost": {"case_id": "ghost", "tenant_id": "ghost", "run_id": "r1"},
        "linked": {"case_id": "linked", "tenant_id": H.T_ID, "run_id": "linked"},
    }
    for case_id, body in {**gone, **not_now}.items():
        P.queue_row(paths, case_id, body)
    P.queue_row(paths, "own", {"case_id": "own", "tenant_id": H.U_ID, "run_id": "only-in-u"})
    lane = P.Lane()
    P.drain(paths, lane)
    assert lane.run_dirs == [Path(u.runs) / "only-in-u"], f"served {lane.run_dirs}"
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
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": H.T_ID, "run_id": "r1"})
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    lane = P.Lane()
    H.raised(P.drain, paths, lane)
    assert lane.handed == [], "the drain served a row with no data root"
    assert P.dead_letter(paths, "case-t") is None
    assert P.still_queued(paths, "case-t")

    monkeypatch.setenv(P.DATA_ROOT_ENV, root)
    P.drain(paths, lane)
    assert lane.run_dirs == [Path(t.runs) / "r1"]


def _lead_author_main():
    from defender.learning.leads import lead_author

    return lead_author.main


def _workspace_map_main():
    from defender.scripts import workspace_map

    return workspace_map.main


def _lesson(lessons: Path, stem: str) -> None:
    lessons.mkdir(exist_ok=True)
    (lessons / f"{stem}.md").write_text(
        f"---\nname: {stem}\ndescription: d\ncreated_at: 2026-06-04\n---\nbody\n",
        encoding="utf-8")


def test_dc10_the_tracer_walks_the_tenants_runs_and_refuses_a_stray(tmp_path, d9_tenant):
    from defender.learning.ops import trace_lesson

    lessons = tmp_path / "lessons"
    _lesson(lessons, "L")
    runs = P.data_root() / d9_tenant / "runs"
    P.plant_record(runs, d9_tenant)
    run = runs / "20260605t000000z-case-a"
    run.mkdir()
    from defender.tests._alert_plant import plant_alert
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
