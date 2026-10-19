"""Hardening: refused siblings/pages read no episode record, foreign records and linked runs refused, malformed drain rows quarantined, CLI smoke as a process."""
from __future__ import annotations

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

from defender.tests import _episode_1025 as E
from defender.tests.tenant_1105_run_repository import _spec1105 as H
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _episodes() -> Path:
    return Path(os.environ[P.EPISODES_BASE_ENV])


def _launched(got: P.Launched) -> bool:
    return got.raised is None and got.rc == 0 and got.questioner.calls > 0


def _refused(got: P.CliResult) -> bool:
    return got.rc not in (0, None) or got.raised is not None


def _lint(name: str) -> ModuleType:
    """A lint program, imported as `test_1105_layout_lint` imports it (its own directory on
    `sys.path`, since the gates import `_astlib` by bare name)."""
    lint_dir = H.WORKTREE / "scripts" / "lint"
    if str(lint_dir) not in sys.path:
        sys.path.insert(0, str(lint_dir))
    return importlib.import_module(f"scripts.lint.{name}")


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
    src, ep = P.sibling_scene(tmp_path, container="beta")
    P.second_tenant(P.data_root(), "beta")
    records = _episode_records(ep)
    assert "family.yaml" in records

    rec = P.SiblingRecorder()
    with _opens() as opened:
        rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)
    assert refused is not None or rc not in (0, None), f"a foreign container was run: {err}"
    assert "lifecycle" not in rec.order
    read = sorted(set(opened) & records)
    assert read == [], f"the refused sibling read {read} before the container record refused"

    (ep / "runs" / "_tenant.json").unlink()
    P.plant_record(ep / "runs", P.SIBLING_TENANT)
    ok = P.SiblingRecorder()
    with _opens() as opened:
        rc, refused, err = P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), ok)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert "family.yaml" in opened, "the hook did not see the manifest read"


def test_f2_a_refused_page_reads_no_episode_record(tmp_path, d9_tenant):
    ep = E.sample_episode(tmp_path, root=_episodes())
    P.second_tenant(P.data_root(), "beta")
    P.plant_record(ep.dir / "runs", "beta")
    records = _episode_records(ep.dir)
    assert {"family.yaml", "judge.yaml", "worlds"} <= records

    with _opens() as opened:
        got = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert _refused(got), "another tenant's episode was rendered"
    assert not ep.page.exists()
    read = sorted(set(opened) & records)
    assert read == [], f"the refused page read {read} before the container record refused"

    (ep.dir / "runs" / "_tenant.json").unlink()
    P.plant_record(ep.dir / "runs", d9_tenant)
    with _opens() as opened:
        ok = P.drive_cli(P.page_main(), P.page_argv(d9_tenant, ep.dir))
    assert ok.rc == 0, ok.said
    assert "family.yaml" in opened, "the hook did not see the manifest read"


_SALT = re.compile(r"run-[0-9a-f]{16}-")


def _judge_prompts(root: Path, monkeypatch, *, prior: bool) -> dict[str, str]:
    """One launch under fresh roots at `root`, its judge's prompts by agent id, with the
    roots' path and the per-run frame salt normalised (the only bytes two identical launches
    differ in). `prior`: a FINISHED run of the same alert sits in T's runs folder."""
    P.roots(root, monkeypatch)
    monkeypatch.setenv(P.DATA_ROOT_ENV, str(root / "data-root"))
    est, src = P.launch_source(root)
    if prior:
        other = src.parent / "20260101t000000z-prior-trial"
        other.mkdir()
        (other / "alert.json").write_text(json.dumps({"alert_id": P.J.ALERT_ID}),
                                          encoding="utf-8")
        (other / "report.md").write_text(
            P.T.report_text("benign") + "\nPRIOR-RUN-ONLY-MARKER\n", encoding="utf-8")
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert _launched(got), f"the launch did not run: {got.message!r}"
    assert len(got.judge.agent_ids) == len(got.judge.prompts)
    return {agent: _SALT.sub("run-SALT-", prompt.replace(str(root), "<ROOT>"))
            for agent, prompt in zip(got.judge.agent_ids, got.judge.prompts, strict=True)}


def test_f3_a_same_alert_prior_run_changes_no_judge_prompt(tmp_path, monkeypatch):
    bare = _judge_prompts(tmp_path / "bare", monkeypatch, prior=False)
    with_prior = _judge_prompts(tmp_path / "prior", monkeypatch, prior=True)
    assert bare, "the judge was never asked"
    worlds = [agent for agent in bare if not agent.startswith("judge:family:")]
    assert worlds
    from defender.learning.judge.layout import FOCUS_VIEW_TITLES

    # #1234 M3/A10: the focus world's report view is titled, in host text, by its world label.
    assert all(f"world {agent.split(':')[1]} — {FOCUS_VIEW_TITLES['report']}" in bare[agent]
               for agent in worlds)
    assert sorted(with_prior) == sorted(bare)
    for agent, prompt in sorted(with_prior.items()):
        assert "PRIOR-RUN-ONLY-MARKER" not in prompt
        assert prompt == bare[agent], f"{agent}: another run of the alert reached the prompt:\n" + (
            "\n".join(difflib.unified_diff(bare[agent].splitlines(), prompt.splitlines(),
                                           lineterm="", n=0)))


def _swap_record(runs: Path, tenant_id: str) -> bytes:
    """Re-plant `<runs>/_tenant.json` naming `tenant_id`; returns the record it replaced."""
    record = runs / "_tenant.json"
    own = record.read_bytes()
    record.unlink()
    P.plant_record(runs, tenant_id)
    return own


def _restore_record(runs: Path, own: bytes) -> None:
    record = runs / "_tenant.json"
    record.unlink()
    record.write_bytes(own)


def _link_runs(runs: Path, elsewhere: Path) -> Path:
    runs.rename(elsewhere)
    os.symlink(elsewhere, runs)
    return elsewhere


def test_f5_the_run_page_refuses_a_foreign_record_and_a_linked_runs(tmp_path):
    src, _ep = P.sibling_scene(tmp_path, container=P.SIBLING_TENANT)
    runs = src.parent
    argv = P.new_run_page_argv(P.SIBLING_TENANT, src.name)
    ok = P.drive_cli(P.run_page_main(), argv)
    assert ok.rc == 0, f"--tenant T <run id> did not render: {ok.said}"
    assert (src / "runtime.html").is_file()
    (src / "runtime.html").unlink()

    P.second_tenant(P.data_root(), "beta")
    own = _swap_record(runs, "beta")
    foreign = P.drive_cli(P.run_page_main(), argv)
    assert _refused(foreign), "the run page rendered under a record naming another tenant"
    assert not (src / "runtime.html").exists()
    _restore_record(runs, own)

    moved = _link_runs(runs, tmp_path / "runs-elsewhere")
    linked = P.drive_cli(P.run_page_main(), argv)
    assert _refused(linked), "the run page followed a linked <T>/runs"
    assert not (moved / src.name / "runtime.html").exists()


def test_f5_workspace_map_refuses_a_foreign_record_and_a_linked_runs(tmp_path, d9_tenant):
    from defender._paths import adapters_under
    from defender.runtime.verbs import read_roster
    from defender.scripts import workspace_map as wm

    runs = P.data_root() / d9_tenant / "runs"
    P.plant_record(runs, d9_tenant)
    run = H.make_run(runs, "20260605t000000z-case-a")
    expected = wm.workspace_map(
        run, systems=tuple(read_roster(adapters_under(wm.DEFENDER_DIR)).accepted))
    argv = ["workspace_map.py", "--tenant", d9_tenant, run.name]
    ok = P.drive_cli(wm.main, argv)
    assert ok.rc == 0, ok.said
    assert ok.out == expected

    P.second_tenant(P.data_root(), "beta")
    own = _swap_record(runs, "beta")
    foreign = P.drive_cli(wm.main, argv)
    assert _refused(foreign), "workspace_map mapped a run under another tenant's record"
    assert foreign.out == ""
    _restore_record(runs, own)

    _link_runs(runs, tmp_path / "runs-elsewhere")
    linked = P.drive_cli(wm.main, argv)
    assert _refused(linked), "workspace_map followed a linked <T>/runs"
    assert linked.out == ""


@pytest.mark.parametrize(("case_id", "body"), [
    ("no-run", {"tenant_id": H.T_ID}),
    ("run-null", {"tenant_id": H.T_ID, "run_id": None}),
    ("run-int", {"tenant_id": H.T_ID, "run_id": 7}),
    ("run-list", {"tenant_id": H.T_ID, "run_id": ["r1"]}),
    ("run-upper", {"tenant_id": H.T_ID, "run_id": "R1"}),
    ("run-empty", {"tenant_id": H.T_ID, "run_id": ""}),
    ("tenant-null", {"tenant_id": None, "run_id": "r1"}),
    ("tenant-int", {"tenant_id": 7, "run_id": "r1"}),
    ("tenant-dict", {"tenant_id": {"id": H.T_ID}, "run_id": "r1"}),
])
def test_f6_a_malformed_row_is_quarantined_and_the_drain_goes_on(tmp_path, case_id, body):
    root = P.data_root()
    t = H.tenant(root, H.T_ID)
    H.runs_folder(t)
    for run_id in ("r1", "r2"):
        H.make_run(t.runs, run_id)
    paths = P.loop_paths(tmp_path)
    P.queue_row(paths, case_id, {"case_id": case_id, **body})
    P.queue_row(paths, "good", {"case_id": "good", "tenant_id": H.T_ID, "run_id": "r1"})

    lane = P.Lane()
    assert H.raised(P.drain, paths, lane) is None, "the malformed row raised out of the drain"
    assert lane.run_dirs == [Path(t.runs) / "r1"], f"served {lane.run_dirs}"
    letter = P.dead_letter(paths, case_id)
    assert letter is not None, f"{case_id} was not quarantined"
    assert str(letter.get("failed", "")).startswith("unreadable"), letter
    assert not P.still_queued(paths, case_id)

    # The next tick: it raises nothing and serves the next row. (This lane double never
    # consumes what it is handed, so the tick may hand it `good` again; that is the harness's.)
    P.queue_row(paths, "next", {"case_id": "next", "tenant_id": H.T_ID, "run_id": "r2"})
    again = P.Lane()
    assert H.raised(P.drain, paths, again) is None, "the next tick raised: the drain is wedged"
    assert Path(t.runs) / "r2" in again.run_dirs, f"the next tick served {again.run_dirs}"


_ABSENT = "20990101t000000z-pr2-absent"


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
    from defender._paths import adapters_under
    from defender.runtime.verbs import read_roster
    from defender.scripts import workspace_map as wm

    runs = P.data_root() / d9_tenant / "runs"
    P.plant_record(runs, d9_tenant)
    run = H.make_run(runs, "20260605t000000z-case-a")
    expected = wm.workspace_map(
        run, systems=tuple(read_roster(adapters_under(wm.DEFENDER_DIR)).accepted))
    script = _script("scripts", "workspace_map.py")
    ok = _process(script, "--tenant", d9_tenant, run.name)
    assert ok.returncode == 0, ok.stderr[-600:]
    assert ok.stdout == expected
    _refused_naming(_process(script, "--tenant", d9_tenant, _ABSENT), _ABSENT)


def _done_run(tenant_id: str) -> Path:
    """A run of `tenant_id` the lead author has already served (its `done` sentinel written
    through the real writer), so serving it again is the clean no-op exit 0."""
    from defender.learning.leads import lead_author

    runs = P.data_root() / tenant_id / "runs"
    P.plant_record(runs, tenant_id)
    run = H.make_run(runs, "20260605t000000z-case-a")
    lead_author.write_done_sentinel(run, "0" * 40)
    return run


def test_f9_the_lead_author_resolves_tenant_and_run_id_and_refuses_a_path(tmp_path, d9_tenant):
    from defender.learning.leads import lead_author

    run = _done_run(d9_tenant)
    ok = P.drive_cli(lead_author.main, ["--tenant", d9_tenant, run.name])
    assert ok.rc == 0, f"--tenant T <run id> was not served: {ok.said}"

    P.second_tenant(P.data_root(), "beta")
    for argv in (["--tenant", d9_tenant, str(run)],
                 ["--tenant", "beta", run.name],
                 ["--tenant", d9_tenant, _ABSENT]):
        got = P.drive_cli(lead_author.main, argv)
        assert _refused(got), f"the lead author served {argv}"
