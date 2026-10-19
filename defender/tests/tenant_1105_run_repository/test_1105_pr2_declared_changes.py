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


# ==========================================================================================
# 0 — PR 1's Tenant-taking lookups leave the door.
# ==========================================================================================


# ==========================================================================================
# 1 — the launcher's edge: `--tenant T <source_run_id>`.
# ==========================================================================================


def test_dc1_a_source_under_a_linked_runs_folder_is_refused(tmp_path):
    """Declared changes 1 and 11 (R51-14): T's natural runs folder `<T>/runs` is a link to a
    real folder holding the source run and T's record. `runs.open` holds `<T>/runs` no-follow,
    so the launch is refused before the questioner, with no episode. The positive control
    puts the real folder back at `<T>/runs`: the same launch runs.

    The source is a LEGAL one: it keeps its session store, so it carries the fork snapshot
    #1255 requires (N4/C2: a storeless source is refused before the questioner for having no
    snapshot, and the control could then never launch). The negative and the control differ
    only in the link, and the refusal is pinned to the link by its text: it names `<T>/runs`
    as a link, and neither the snapshot check (C2) nor G16's store compare (the store derived
    from the resolved folder is not the recorded one) is what spoke. Both read the source's
    store, which is found only once the source is open, and `runs.open` refuses the link first.
    RED at base: `tenant_of_run_dir` compares resolved paths, so the linked source is opened
    and only G16's compare refuses it — a refusal that does not name the link."""
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


# ==========================================================================================
# J3 — the judge's same-alert union is removed.
# ==========================================================================================

def test_dc2_the_judges_prompt_carries_no_sibling_view_or_tally(tmp_path):
    """Fork decision J3 (6100061869): the "siblings" view and its tally leave the judge's
    prompt; the judge reads only the episode it is handed. A prior finished run of the SAME
    alert sits in T's runs folder (alert id `v2-cross-tier-ssh-pivot`, the worlds' own, and a
    report). The episode is launched and graded: every prompt the judge was handed carries the
    judged world's own report view (positive control: the capture is real), and none carries
    the sibling-trials view, the trial spread, or the prior run's id. RED at base: VIEW 4 lists
    the prior run and TRIAL SPREAD tallies it."""
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
    """Declared change 3 / J3 as settled (the spine's ruling on #1105): the judge's world-label
    collision probe over `<T>/runs` (G17) is removed — it guarded `resolve_run_bundle`, which
    has no production caller (E-27); the judge reads only the episode it is handed.

    T's natural runs folder holds a finished run whose id is `b`, which is also a world label
    of the family the launcher authors (worlds a, b, c). The launch reaches its judge pass and
    the episode GRADES: the judge is asked, and `judge.yaml` carries a row for `b` and for `c`.
    POSITIVE CONTROL, same episode, through the judge's own entry point (`P.grade`): a manifest
    world wearing a reserved label (`family`) or a label off the run-id grammar (`x y`) is still
    refused at manifest load, naming the label — the label gate is live; only the probe over
    `<T>/runs` left. RED at base: `_check_world_labels` finds `<T>/runs/b` and raises
    `JudgeRefused` ("collides with a real run"), the launcher logs it, and nothing is graded."""
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


# ==========================================================================================
# 4 — the episode page: `--tenant T <episode_id>`, its container record judged first.
# ==========================================================================================


def test_dc4_a_container_with_no_record_refuses_the_page(tmp_path, d9_tenant):
    """Declared change 4 / N-c″ (owner ruling, old episodes not supported): a present `runs/`
    with no `_tenant.json` — an episode launched before #1078 (R51-22) — refuses the page: a
    non-zero exit and no `learning.html`. The positive control is the same episode once its
    container record names T: the page renders. RED at base: the page reads `runs/` whatever
    its record and renders."""
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
    """Declared change 4 / G20 / S1: the page opens `runs.episode(ep)` before `_load_episode`
    reads anything. With the container record naming ANOTHER real tenant the page is refused,
    no `learning.html` written; and with the manifest also corrupt, the refusal is the record's
    (it names `_tenant.json` or the other tenant), not the manifest's. Positive controls on the
    same episode: the record naming T with the corrupt manifest refuses for the manifest (no
    `_tenant.json` in the refusal), and with the manifest restored the page renders. RED at
    base: the page checks no tenant, and reads the manifest first."""
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
    """Declared change 4 / J3 as settled (the spine's ruling on #1105): the page's arm roster
    comes from the manifest's runnable labels, each arm opened by id through the episode view;
    an entry in the episode's `runs/` that is no manifest arm is no longer shown (the
    `ROSTER_STRAY_RUN_DIR` rows go).

    The episode's `runs/` (its record naming T) holds, beside the three arms, a directory whose
    name is not `<episode>-<label>` (`stray_run_dir`) and one that decomposes to a label no
    manifest world carries (`<episode>-orphan`). The page renders; POSITIVE CONTROL: every
    runnable manifest label has its world section and its arm's run-page link. Neither stray
    has a section, a link or its name on the page, no line reads "not declared in the
    manifest", and both are left on disk. RED at base: `_build_roster` sections every `runs/`
    directory — `world-stray_run_dir` ("not declared in the manifest") and `world-orphan`."""
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


# ==========================================================================================
# 5 — verify opens each arm through the view.
# ==========================================================================================

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
    """Declared change 5: verify opens each finished arm with `view.open(view.arm_id(label))`,
    whose entry rule refuses anything but a real directory. An arm whose entry is a link to a
    run folder outside the container is never archived from its target: no world's archive
    carries the target's bytes — however verify surfaces the refusal (the design leaves that to
    J3, so nothing about the launch's exit or the other arms is asserted). The positive
    control is a clean launch under fresh roots: arm `b`'s report IS archived at
    `worlds/b/report.md`, so the channel this test watches is the one the archive writes.
    RED at base: verify joins `runs/<ep>-<label>` by hand and the archive copies through the
    link."""
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


# ==========================================================================================
# 6 — the sibling: `run.py --tenant T --episode <ep> --world L`.
# ==========================================================================================


def test_dc6_a_sibling_over_an_absent_container_is_refused(tmp_path):
    """Declared change 6 / G5 / R51-02: an episode with no container yet (pre-RUNS) has no
    record binding it to any tenant, so a sibling over it is refused — before the preflight
    and the lifecycle — and NO container is made (today run setup would mint the requesting
    tenant's record over it, whoever's episode it is). The positive control is the same
    episode once the launcher's container (naming T) exists: the sibling runs, its arm inside.
    RED at base: run setup creates the container for whoever asks."""
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
    """Declared change 6 / G19 / S-c1 amended: the sibling's view judges the container record
    right after acceptance, BEFORE the manifest. With the record naming another real tenant
    and the manifest corrupt, the refusal is the record's (it names `_tenant.json` or the other
    tenant). Positive controls on the same episode: the record naming T with the corrupt
    manifest refuses for the manifest (no `_tenant.json` in it); the manifest restored, the
    sibling runs. RED at base: the manifest is read (and refused) first."""
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
    """Declared change 6: the sibling opens its episode through the episode owner, so it needs
    `DEFENDER_EPISODES_BASE`; a hand resume without it is refused naming the setting, with
    nothing spent. (The launcher's spawn passes its own environment, C-18.) The positive
    control sets it: the sibling runs. RED at base: `--resume` opens the manifest's path and
    never reads the setting."""
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


# ==========================================================================================
# 7 — the run page: `--tenant T [--episode ep] <run_id>`.
# ==========================================================================================


def test_dc7_the_run_page_refuses_a_linked_run_folder(tmp_path):
    """Declared changes 7 and 11 (B-28): T's run name `<T>/runs/<id>` is a link to a real run
    folder elsewhere. The run page opens through `runs.open`, which never follows it: a
    non-zero exit and nothing written into the target. The positive control renders the real
    folder. RED at base: `Run.at` follows the link and writes `runtime.html` into its target."""
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


# ==========================================================================================
# 8 — curation rows are `{case_id, tenant_id, run_id}`.
# ==========================================================================================

def test_dc8_a_natural_run_enqueues_its_address_not_its_folder(tmp_path, d9_tenant):
    """Declared change 8 (D-stored; decision 7): a natural run through `run.py <alert> --tenant
    T` — the real run setup, the real reap scan, the real enqueue — queues exactly
    `{case_id, tenant_id: T, run_id: <its id>}`: a natural run's `RunAddress`, no path. RED at
    base: the row is `{case_id, run_dir}`."""
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
    """Declared change 8 / G21: the drain accepts each row's `tenant_id` and opens `run_id` in
    THAT tenant's repository, then serves the lead author that run. Two tenants each hold a run
    `r1`; the rows for each are served with their own folder, never the other's. RED at base:
    a row with no `run_dir` is quarantined as "unreadable" and nothing is served."""
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
    """Declared changes 8 and 11 / G21 (S9, as the owner amended it on PR #1236): a well-formed
    row whose run is GONE — absent in its tenant, or present only in ANOTHER tenant — is
    quarantined at once as "artifact-missing" and never served. A row that cannot be reached
    right now — its tenant refused (no such tenant), its run folder a link (never followed) —
    is not: it is a counted transient attempt, re-queued (`test_1105_pr2_review_fixes.py` pins
    the retry ceiling). The positive control in the same tick: U's own row is served with U's
    folder. RED at base: such rows have no `run_dir` and take "unreadable" instead."""
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
    """Declared change 8: the drain resolves the data root once per tick; with none it refuses
    the tick — the lead author is never called and the row is neither served nor dead-lettered
    (it waits, queued or in its claim slot, for a tick that can serve it). The positive
    control restores the root: the same row is served. RED at base: the drain reads no data
    root and dead-letters the address row as "unreadable"."""
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


# ==========================================================================================
# 9 — the manifest: `source_run_dir` no longer written; tolerated, never read.
# ==========================================================================================


# ==========================================================================================
# 10 / J8 — the lead author, the tracer and `workspace_map` take `--tenant T`.
# ==========================================================================================


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
    """Declared change 10 / J3 / J8: `trace_lesson --tenant T --all` walks T's natural runs
    folder (`<T>/runs`, no longer the dead `<state root>/runs` default): a run there that
    loaded lesson L counts. `--runs-dir` is gone (a usage error). The tracer applies the
    repository's listing rule (rev 4.1 H4): a stray file in `<T>/runs` fails it loudly, naming
    the stray. RED at base: the tracer does not know `--tenant`."""
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


