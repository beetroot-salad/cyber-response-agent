"""Hardening: refused siblings/pages read no episode record, foreign records and linked runs refused, malformed drain rows quarantined, CLI smoke as a process."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import contextlib
import difflib
import importlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P


_F6_R1, _F6_R2 = (fixture_uuid('f6-r1'), fixture_uuid('f6-r2'))

@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _launched(got: P.Launched) -> bool:
    return got.raised is None and got.rc == 0 and got.questioner.calls > 0


def _refused(got: P.CliResult) -> bool:
    return got.rc not in (0, None) or got.raised is not None


def _lint(name: str) -> ModuleType:
    """A lint program, imported as `test_1105_layout_lint` imports it (its own directory on
    `sys.path`, since the gates import `_astlib` by bare name)."""
    lint_dir = H.WORKTREE / "tooling" / "lint"
    if str(lint_dir) not in sys.path:
        sys.path.insert(0, str(lint_dir))
    return importlib.import_module(f"tooling.lint.{name}")


_OPENED: list[str] = []
_ARMED: list[bool] = [False]
_HOOKED: list[bool] = [False]


def _audit(event: str, args: tuple) -> None:
    if not _ARMED[0] or event != "open":
        return
    try:
        target = args[0]
        _OPENED.append(os.path.basename(os.fsdecode(target)) if isinstance(
            target, (str, bytes, os.PathLike)) else "")
    except Exception:  # noqa: BLE001, S110 — an audit hook never raises into the code it watches
        pass


@contextlib.contextmanager
def _opens() -> Iterator[list[str]]:
    """The basename of every file or folder opened (`open` audit events: `io.open` and
    `os.open`, the bind primitive's one-component-at-a-time opens included) while the block runs."""
    if not _HOOKED[0]:
        sys.addaudithook(_audit)
        _HOOKED[0] = True
    _OPENED.clear()
    _ARMED[0] = True
    try:
        yield _OPENED
    finally:
        _ARMED[0] = False


def _episode_records(episode_dir: Path) -> set[str]:
    """The episode's own top-level record names — everything at its top but its container."""
    return {p.name for p in Path(episode_dir).iterdir()} - {"runs"}


def test_f2_a_refused_sibling_reads_no_episode_record(tmp_path):
    from defender import _yaml
    from defender.tests.storage.ids_1187 import _spec1187 as S

    src, ep = P.sibling_scene(tmp_path, roster=False)
    doc = _yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    (ep / "runs").mkdir(exist_ok=True)
    S.write_roster(ep, {w["world_id"]: S.new_id() for w in doc["worlds"]})
    P.second_tenant(location_path(P.data_root)(), H.U_ID)
    records = _episode_records(ep)
    assert {"family.yaml", S.ROSTER_NAME} <= records

    rec = P.SiblingRecorder()
    with _opens() as opened:
        rc, refused, err = P.drive_run_py(P.sibling_argv(H.U_ID, ep, "b"), rec)
    assert refused is not None or rc not in (0, None), f"another tenant's episode was run: {err}"
    assert "lifecycle" not in rec.order
    read = sorted(set(opened) & records)
    assert read == [], f"the refused sibling read {read} of another tenant's episode"

    ok = P.SiblingRecorder()
    with _opens() as opened:
        rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert "family.yaml" in opened, "the hook did not see the manifest read"


def test_f2_a_refused_page_reads_no_episode_record(tmp_path, d9_tenant):
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.storage.ids_1187 import _spec1187 as S

    episode_id = S.new_id()
    ep = S.make_episode(location_path(P.data_root)(), d9_tenant, episode_id, labels=T.WORLDS, roster=True)
    T.write_family(ep, T.family_doc(episode_id=episode_id, source_run_id=S.new_id()))
    E.write_outcome(ep, "accepted", reason="F2 outcome", family_stamp=False)
    P.second_tenant(location_path(P.data_root)(), H.U_ID)
    records = _episode_records(ep)
    assert {"family.yaml", S.ROSTER_NAME, "outcome.yaml"} <= records

    with _opens() as opened:
        got = P.drive_cli(P.page_main(), P.new_page_argv(H.U_ID, episode_id))
    assert _refused(got), "another tenant's episode was rendered"
    assert not (ep / E.PAGE_NAME).exists()
    read = sorted(set(opened) & records)
    assert read == [], f"the refused page read {read} of another tenant's episode"

    with _opens() as opened:
        ok = P.drive_cli(P.page_main(), P.new_page_argv(d9_tenant, episode_id))
    assert ok.rc == 0, ok.said
    assert "family.yaml" in opened, "the hook did not see the manifest read"


_SALT = re.compile(r"run-[0-9a-f]{16}-")


def _judge_prompts(ep: Path) -> dict[str, str]:
    """Grade one published family afresh; normalize only each call's fresh frame salt."""
    from defender.tests.support.learning.core._state1135 import env_state

    (ep / "judge.yaml").unlink(missing_ok=True)
    judge = P.quiet_judge()
    P.J.grade_at(ep, judge=judge, state=env_state())
    assert len(judge.agent_ids) == len(judge.prompts)
    assert len(set(judge.agent_ids)) == len(judge.agent_ids)
    return {agent: _SALT.sub("run-SALT-", prompt)
            for agent, prompt in zip(judge.agent_ids, judge.prompts, strict=True)}


def test_f3_a_same_alert_prior_run_changes_no_judge_prompt(tmp_path, monkeypatch):
    from defender.records import _alert_input
    from defender.records import RunPaths
    from defender.tests.support.storage._alert_plant import plant_alert

    P.roots(tmp_path, monkeypatch)
    est, src = P.launch_source(tmp_path)
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(got), f"the launch did not run: {got.message!r}"
    (ep,) = P.launched_episodes()
    bare = _judge_prompts(ep)

    other = src.parent / fixture_uuid("f3-prior-trial")
    other.mkdir()
    source_paths, prior_paths = RunPaths(src), RunPaths(other)
    source_raw, source_record = _alert_input.verified_alert(
        source_paths.alert, source_paths.alert_record, run_name=src.name)
    plant_alert(other, source_raw)
    prior_raw, prior_record = _alert_input.verified_alert(
        prior_paths.alert, prior_paths.alert_record, run_name=other.name)
    assert prior_raw == source_raw
    assert prior_record == source_record
    assert prior_record.facts.signature == json.loads(source_raw)["rule"]["id"]
    assert prior_record.facts.signature is not None
    (other / "report.md").write_text(
        P.T.report_text("benign") + "\nPRIOR-RUN-ONLY-MARKER\n", encoding="utf-8")
    with_prior = _judge_prompts(ep)
    assert bare, "the judge was never asked"
    worlds = [agent for agent in bare if not agent.startswith("judge:family:")]
    assert worlds
    from defender.learning.judge.layout import FOCUS_VIEW_TITLES

    # #1234 M3/A10: the focus world's report view is titled, in host text, by its world label.
    labels = {P.T.world_id(ep, label): label for label in P.T.WORLDS}
    assert all(f"world {labels[agent.split(':')[1]]} — {FOCUS_VIEW_TITLES['report']}" in bare[agent]
               for agent in worlds)
    assert sorted(with_prior) == sorted(bare)
    for agent, prompt in sorted(with_prior.items()):
        assert "PRIOR-RUN-ONLY-MARKER" not in prompt
        assert prompt == bare[agent], f"{agent}: another run of the alert reached the prompt:\n" + (
            "\n".join(difflib.unified_diff(bare[agent].splitlines(), prompt.splitlines(),
                                           lineterm="", n=0)))


def _link_runs(runs: Path, elsewhere: Path) -> Path:
    runs.rename(elsewhere)
    os.symlink(elsewhere, runs)
    return elsewhere


def test_f5_the_run_page_refuses_a_foreign_record_and_a_linked_runs(tmp_path):
    src, _ep = P.sibling_scene(tmp_path)
    runs = src.parent
    argv = P.new_run_page_argv(P.SIBLING_TENANT, src.name)
    ok = P.drive_cli(P.run_page_main(), argv)
    assert ok.rc == 0, f"--tenant T <run id> did not render: {ok.said}"
    assert (src / "runtime.html").is_file()
    (src / "runtime.html").unlink()

    moved = _link_runs(runs, tmp_path / "runs-elsewhere")
    linked = P.drive_cli(P.run_page_main(), argv)
    assert _refused(linked), "the run page followed a linked <T>/runs"
    assert not (moved / src.name / "runtime.html").exists()


def test_f5_workspace_map_refuses_a_foreign_record_and_a_linked_runs(tmp_path, d9_tenant):
    import uuid

    from defender._paths import adapters_under
    from defender.systems.verbs import read_roster
    from defender.cli import workspace_map as wm

    runs = location_path(P.data_root)() / d9_tenant / "runs"
    run = H.make_run(runs, str(uuid.uuid4()))
    expected = wm.workspace_map(
        run, systems=tuple(read_roster(adapters_under(wm.DEFENDER_DIR)).accepted))
    argv = ["workspace_map.py", "--tenant", d9_tenant, run.name]
    ok = P.drive_cli(wm.main, argv)
    assert ok.rc == 0, ok.said
    assert ok.out == expected

    _link_runs(runs, tmp_path / "runs-elsewhere")
    linked = P.drive_cli(wm.main, argv)
    assert _refused(linked), "workspace_map followed a linked <T>/runs"
    assert linked.out == ""


@pytest.mark.parametrize(("case_id", "body"), [
    ("no-run", {"tenant_id": H.T_ID}),
    ("run-null", {"tenant_id": H.T_ID, "run_id": None}),
    ("run-int", {"tenant_id": H.T_ID, "run_id": 7}),
    ("run-list", {"tenant_id": H.T_ID, "run_id": [_F6_R1]}),
    ("run-upper", {"tenant_id": H.T_ID, "run_id": _F6_R1.upper()}),
    ("run-empty", {"tenant_id": H.T_ID, "run_id": ""}),
    ("tenant-null", {"tenant_id": None, "run_id": _F6_R1}),
    ("tenant-int", {"tenant_id": 7, "run_id": _F6_R1}),
    ("tenant-dict", {"tenant_id": {"id": H.T_ID}, "run_id": _F6_R1}),
])
def test_f6_a_malformed_row_is_quarantined_and_the_drain_goes_on(tmp_path, case_id, body):
    root = location_path(P.data_root)()
    t = H.tenant(root, H.T_ID)
    H.runs_folder(t)
    for run_id in (_F6_R1, _F6_R2):
        H.make_run(location_path(t.runs), run_id)
    paths = P.loop_paths(tmp_path)
    P.queue_row(paths, case_id, {"case_id": case_id, **body})
    P.queue_row(paths, "good", {"case_id": "good", "tenant_id": H.T_ID, "run_id": _F6_R1})

    lane = P.Lane()
    assert H.raised(P.drain, paths, lane) is None, "the malformed row raised out of the drain"
    assert lane.run_dirs == [Path(location_path(t.runs)) / _F6_R1], f"served {lane.run_dirs}"
    letter = P.dead_letter(paths, case_id)
    assert letter is not None, f"{case_id} was not quarantined"
    assert str(letter.get("failed", "")).startswith("unreadable"), letter
    assert not P.still_queued(paths, case_id)

    # The next tick: it raises nothing and serves the next row. (This lane double never
    # consumes what it is handed, so the tick may hand it `good` again; that is the harness's.)
    P.queue_row(paths, "next", {"case_id": "next", "tenant_id": H.T_ID, "run_id": _F6_R2})
    again = P.Lane()
    assert H.raised(P.drain, paths, again) is None, "the next tick raised: the drain is wedged"
    assert Path(location_path(t.runs)) / _F6_R2 in again.run_dirs, f"the next tick served {again.run_dirs}"


_ABSENT = fixture_uuid("pr2-absent")


def _process(*command: str) -> subprocess.CompletedProcess:
    """One CLI as a real process of this interpreter, the checkout first on its path, under
    this test's configured roots (the environment)."""
    env = {**os.environ,
           "PYTHONPATH": os.pathsep.join(filter(None, [str(H.WORKTREE),
                                                       os.environ.get("PYTHONPATH")]))}
    return subprocess.run(  # noqa: S603 — this interpreter, a checkout CLI, ids
        [sys.executable, *command], capture_output=True, text=True, encoding="utf-8",
        check=False, env=env, cwd=str(H.WORKTREE), timeout=300)


def _refused_naming(child: subprocess.CompletedProcess, what: str) -> None:
    said = child.stdout + child.stderr
    assert child.returncode != 0, f"exit 0: {said[-600:]!r}"
    assert what in said, f"the refusal does not name {what}: {said[-600:]!r}"
    assert "usage:" not in said, f"an argument error, not a refusal: {said[-600:]!r}"


def _script(*parts: str) -> str:
    return str(H.WORKTREE.joinpath("defender", *parts))


def test_f7_workspace_map_as_a_process(tmp_path, d9_tenant):
    import uuid

    from defender._paths import adapters_under
    from defender.systems.verbs import read_roster
    from defender.cli import workspace_map as wm

    runs = location_path(P.data_root)() / d9_tenant / "runs"
    run = H.make_run(runs, str(uuid.uuid4()))
    expected = wm.workspace_map(
        run, systems=tuple(read_roster(adapters_under(wm.DEFENDER_DIR)).accepted))
    script = _script("cli", "workspace_map.py")
    ok = _process(script, "--tenant", d9_tenant, run.name)
    assert ok.returncode == 0, ok.stderr[-600:]
    assert ok.stdout == expected
    _refused_naming(_process(script, "--tenant", d9_tenant, _ABSENT), _ABSENT)


def _done_run(tenant_id: str) -> Path:
    """A run of `tenant_id` the lead author has already served (its `done` sentinel written
    through the real writer), so serving it again is the clean no-op exit 0. #1187 declared
    changes 1 and 6: UUID-named, in a container holding no `_tenant.json`."""
    import uuid

    from defender.learning.leads import lead_author

    tenant = H.tenant(location_path(P.data_root)(), tenant_id)
    location_path(tenant.learning).mkdir(exist_ok=True)
    run = H.make_run(location_path(tenant.runs), str(uuid.uuid4()))
    lead_author.write_done_sentinel(run, "0" * 40)
    return run


def test_f9_the_lead_author_resolves_tenant_and_run_id_and_refuses_a_path(tmp_path, d9_tenant):
    from defender.learning.leads import lead_author

    run = _done_run(d9_tenant)
    ok = P.drive_cli(lead_author.main, ["--tenant", d9_tenant, run.name])
    assert ok.rc == 0, f"--tenant T <run id> was not served: {ok.said}"

    P.second_tenant(location_path(P.data_root)(), H.U_ID)
    for argv in (["--tenant", d9_tenant, str(run)],
                 ["--tenant", H.U_ID, run.name],
                 ["--tenant", d9_tenant, _ABSENT]):
        got = P.drive_cli(lead_author.main, argv)
        assert _refused(got), f"the lead author served {argv}"
