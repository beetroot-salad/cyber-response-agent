"""#1105 PR 2 — tightening after the red-team pass (ADVERSARY.md, findings F1–F10) over the
tests-before-code commit `2197f074`.

Each test here closes one finding: an implementation the adversary showed green on the first
commit fails it. EVERY TEST HERE IS RED AT BASE `301f196c` for the reason in the table, and goes
green when PR 2 lands as designed (rev 5.1, #1105 comments 6099907018 / 6099907229 / 6099907462,
fork decisions 6100061869, the J3 follow-through 6100455891). F6(b) lives in
`test_1105_pr2_repository.py`, F8 is the fixture fix in `test_dc7_…` (declared-changes file),
and the edit-list additions F1/F7 name are in that file's docstring.

| Finding | Test                                                               | Red at base because                                         |
|---------|--------------------------------------------------------------------|-------------------------------------------------------------|
| F1      | test_f1_the_layout_fence_ends_with_an_empty_allow_list             | `ALLOW_LIST` holds PR 1's 18 entries                        |
| F1      | test_f1_the_1210_work_list_is_at_zero                              | the census counts 12 / 13 / 12 / 1 sites                    |
| F2      | test_f2_a_refused_sibling_reads_no_episode_record                  | `--resume` opens `family.yaml` before the record refuses    |
| F2      | test_f2_a_refused_page_reads_no_episode_record                     | the page renders another tenant's episode                   |
| F3      | test_f3_a_same_alert_prior_run_changes_no_judge_prompt             | VIEW 4 / TRIAL SPREAD carry the prior run                   |
| F4      | test_f4_an_old_source_run_dir_never_stands_in_for_an_absent_source | the sibling copies the old field's run (T's decoy)          |
| F5      | test_f5_the_run_page_refuses_a_foreign_record_and_a_linked_runs    | the run page takes a folder path ("usage")                  |
| F5      | test_f5_workspace_map_refuses_a_foreign_record_and_a_linked_runs   | `workspace_map` takes a folder path ("usage")               |
| F6(a)   | test_f6_a_malformed_row_is_quarantined_and_the_drain_goes_on[*]    | the good new-shape row is quarantined, never served         |
| F7      | test_f7_*_as_a_process                                             | each CLI's process refuses `--tenant` (argparse "usage")    |
| F9      | test_f9_the_lead_author_resolves_tenant_and_run_id_and_refuses_a_path | the lead author does not know `--tenant` (argparse)       |
| F10     | test_f10_no_cli_usage_prose_names_the_old_arguments                | the named docs still spell `--resume <`, `<run_dir>`, …     |

NOT PINNED: the launcher's SUCCESS as a process (F7) — a launch spends the questioner, the
oracle and the judge, which a process cannot be handed fakes for; its process refusal is pinned,
and its in-process launch is pinned by the declared-change and guard tests.

The F2 audit hook is installed once per test process (an audit hook cannot be removed). It
checks a module-level flag first, records only `open` events while a test arms it, and never
raises.
"""
from __future__ import annotations

import ast
import contextlib
import difflib
import importlib
import json
import os
import re
import shutil
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


# ==========================================================================================
# F1 — the fence's end state: the layout lint's allow-list is empty, and #1210's work list is
# at zero (part 2: "PR 2 ends with every count at zero"; D7″: 18 entries -> 0; J15).
# ==========================================================================================

def _lint(name: str) -> ModuleType:
    """A lint program, imported as `test_1105_layout_lint` imports it (its own directory on
    `sys.path`, since the gates import `_astlib` by bare name)."""
    lint_dir = H.WORKTREE / "scripts" / "lint"
    if str(lint_dir) not in sys.path:
        sys.path.insert(0, str(lint_dir))
    return importlib.import_module(f"scripts.lint.{name}")


def test_f1_the_layout_fence_ends_with_an_empty_allow_list():
    """F1 / O1(a) / D7″ / J15: `lint_run_layout_imports.ALLOW_LIST` is EMPTY after PR 2 (the
    owners add the hand-outs migrated callers need; no allow-list entries), and the lint is
    clean on the tree with it — so every one of PR 1's 18 gated uses moved behind the
    repository, none kept load-bearing. The lint's own positive controls (a planted gated use is
    flagged) are `test_1105_layout_lint`'s. RED at base: the allow-list holds PR 1's 18."""
    lint = _lint("lint_run_layout_imports")
    listed = [tuple(entry) for entry in lint.ALLOW_LIST]
    assert listed == [], f"the layout fence still allow-lists {len(listed)} uses: {listed}"
    found = lint.scan(lint.DEFENDER, allow_list=())
    assert found == [], "\n".join(f.display for f in found)
    assert lint.main([]) == 0


#: #1210's list A: the attribute reads it bans outside the owners (count at base: 12).
_FENCE_NAMES = ("runs", "data_root", "trust_root")


def _owner_callee(func: ast.expr) -> bool:
    """An owner callable a non-owner may hand a folder to: a `RunPaths(…)` method (the
    sidecar accessors, row 24), a `session_store.` function (fork S) or a `_tenant.` function
    (row 14)."""
    if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call)
            and ast.unparse(func.value.func) == "RunPaths"):
        return True
    return ast.unparse(func).startswith(("session_store.", "_tenant."))


def _parents(node: ast.AST, rel: str) -> list[str]:
    return [f"{rel}:{sub.lineno} {ast.unparse(sub)}" for sub in ast.walk(node)
            if isinstance(sub, ast.Attribute) and sub.attr == "parent"]


def _is_runs_base_export(node: ast.Assign) -> bool:
    return any(isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
               and t.value.id == "env" and isinstance(t.slice, ast.Constant)
               and t.slice.value == "DEFENDER_RUNS_BASE" for t in node.targets)


def _is_arm_join(node: ast.BinOp) -> bool:
    """`<folder> / f"{<episode…>}-{<label>}"`: the hand-built join of a sibling's arm."""
    if not (isinstance(node.op, ast.Div) and isinstance(node.right, ast.JoinedStr)):
        return False
    parts = node.right.values
    return (len(parts) == 3 and isinstance(parts[0], ast.FormattedValue)
            and isinstance(parts[1], ast.Constant) and parts[1].value == "-"
            and isinstance(parts[2], ast.FormattedValue)
            and "episode" in ast.unparse(parts[0].value))


def _census_1210(sources: dict[str, str]) -> dict[str, list[str]]:
    """#1210's work list over `sources` (module path -> text), as part 2 counts it:

    A. a read of an attribute named `runs`, `data_root` or `trust_root`;
    B. a function with a `runs_base` parameter;
    C. an `x.parent` handed to an owner callable (`_owner_callee`) or exported as
       `env["DEFENDER_RUNS_BASE"]` — a call inside an f-string is message text (J13), not a site;
    D. a hand-built arm join (`_is_arm_join`); the judge's `base / label` join goes with B and
       the J3 removal (`test_dc3_…`)."""
    found: dict[str, list[str]] = {"A": [], "B": [], "C": [], "D": []}
    for rel, text in sorted(sources.items()):
        tree = ast.parse(text)
        quoted = {id(sub) for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)
                  for sub in ast.walk(node) if sub is not node}
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in _FENCE_NAMES:
                found["A"].append(f"{rel}:{node.lineno} {ast.unparse(node)}")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                params = node.args
                if "runs_base" in [a.arg for a in (*params.posonlyargs, *params.args,
                                                   *params.kwonlyargs)]:
                    found["B"].append(f"{rel}:{node.lineno} {getattr(node, 'name', 'lambda')}")
            elif (isinstance(node, ast.Call) and id(node) not in quoted
                  and _owner_callee(node.func)):
                for arg in (*node.args, *(kw.value for kw in node.keywords)):
                    found["C"].extend(_parents(arg, rel))
            elif isinstance(node, ast.Assign) and _is_runs_base_export(node):
                found["C"].extend(_parents(node.value, rel))
            elif isinstance(node, ast.BinOp) and _is_arm_join(node):
                found["D"].append(f"{rel}:{node.lineno} {ast.unparse(node)}")
    return found


def test_f1_the_1210_work_list_is_at_zero():
    """F1 / O1(b) / part 2's #1210 work list: "PR 2 ends with every count at zero". Over
    `lint_run_records`' sweep, its owner modules excluded, the census (`_census_1210`) finds no
    banned attribute read (A), no `runs_base` parameter (B; fork S takes the session store's
    two too), no `x.parent` handed to an owner callable or env export (C) and no hand-built arm
    join (D). A non-zero count is a site the design moves; if one must stay, the design's "every
    count at zero" is re-ruled first, never this census loosened.

    POSITIVE CONTROL: the census over a planted module holding one site of each kind counts
    each once, and does not count a `.parent` inside a refusal's f-string (J13). RED at base:
    A 12, B 13, C 12, D 1."""
    planted = {"planted.py": (
        "def f(tenant, runs_base, run_dir, env, episode_id, label, runs):\n"
        "    tenant.data_root\n"
        "    RunPaths(run_dir).ticket_write(run_dir.parent)\n"
        "    env['DEFENDER_RUNS_BASE'] = str(run_dir.parent)\n"
        "    print(f'{_tenant.record_path(run_dir.parent)} is a message')\n"
        "    return runs / f'{episode_id}-{label}'\n")}
    control = _census_1210(planted)
    assert {k: len(v) for k, v in control.items()} == {"A": 1, "B": 1, "C": 2, "D": 1}, control

    records = _lint("lint_run_records")
    owners = set(records.OWNER_MODULES)
    sources = {}
    for path in records.sweep_files():
        rel = Path(path).relative_to(records.DEFENDER).as_posix()
        if rel not in owners:
            sources[rel] = Path(path).read_text(encoding="utf-8")
    found = _census_1210(sources)
    left = {k: v for k, v in found.items() if v}
    assert not left, "#1210's work list is not at zero:\n" + "\n".join(
        f"  {k}: {site}" for k, sites in left.items() for site in sites)


# ==========================================================================================
# F2 — the container record is judged before ANY read of the episode (G19, G20, S-c1): the
# order is observed, not inferred from which refusal's message wins.
# ==========================================================================================

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
    """F2 / G19 / S-c1 amended: a sibling over an episode whose container record names another
    real tenant is refused by the view's one read of `runs/_tenant.json`, "before it reads B's
    manifest or any other episode record; that one read is the refusal". Observed through the
    process's `open` audit events: no top-level episode record (`family.yaml`, `served`) is
    opened before the refusal. POSITIVE CONTROL: with the record naming T the sibling runs, and
    the same hook sees `family.yaml` opened (the hook reaches the read primitive). RED at base:
    `--resume` reads the manifest first, then refuses on the record."""
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
    """F2 / G20: the page judges `runs/_tenant.json` "before `_load_episode` … reads the
    manifest, outcome, samples, archive or judge records". With the record naming another real
    tenant the page is refused and no top-level episode record (`family.yaml`, `judge.yaml`,
    `outcome.yaml`, `samples.yaml`, `worlds`, …) is opened. POSITIVE CONTROL: with the record
    naming T the page renders and the hook sees `family.yaml` opened. RED at base: the page
    checks no record and renders another tenant's episode."""
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


# ==========================================================================================
# F3 — J3: nothing of another run of the alert reaches the judge, whatever its headings.
# ==========================================================================================

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
    """F3 / J3: "the judge reads only the episode it is handed". The same launch is run twice
    under fresh roots — once with a finished run of the SAME alert (disposition `benign`, a
    marker line in its report) in T's runs folder, once without — and every prompt the judge is
    handed is byte-identical between the two, once the roots' path and the frame salt are
    normalised: no view, tally, row or disposition of the other run, under any heading.
    POSITIVE CONTROL: the prompts are real (each world's carries its own report view) and the
    marker reaches none. RED at base: VIEW 4 lists the prior run and TRIAL SPREAD tallies it."""
    bare = _judge_prompts(tmp_path / "bare", monkeypatch, prior=False)
    with_prior = _judge_prompts(tmp_path / "prior", monkeypatch, prior=True)
    assert bare, "the judge was never asked"
    worlds = [agent for agent in bare if not agent.startswith("judge:family:")]
    assert worlds
    assert all("THE JUDGED WORLD'S OWN report.md" in bare[agent] for agent in worlds)
    assert sorted(with_prior) == sorted(bare)
    for agent, prompt in sorted(with_prior.items()):
        assert "PRIOR-RUN-ONLY-MARKER" not in prompt
        assert prompt == bare[agent], f"{agent}: another run of the alert reached the prompt:\n" + (
            "\n".join(difflib.unified_diff(bare[agent].splitlines(), prompt.splitlines(),
                                           lineterm="", n=0)))


# ==========================================================================================
# F4 — decision A: an old manifest's `source_run_dir` is never read, even when the id names
# nothing.
# ==========================================================================================

def test_f4_an_old_source_run_dir_never_stands_in_for_an_absent_source(tmp_path):
    """F4 / decision A / security item 6: `source_run_dir` "is never read …, so it cannot steer
    a source to another tenant". An old manifest whose `source_run_id` names NO run of T, while
    its `source_run_dir` names a real run — T's own decoy, then another tenant's (beta's) — is
    refused: the sibling never reaches its lifecycle, and no arm carries the decoy's alert. A
    fallback to the old field on `RunAbsent` fails this. POSITIVE CONTROL: the same manifest
    with `source_run_id` naming T's source resumes, its arm's alert the source's. RED at base:
    the sibling reads its source from `source_run_dir` and resumes from T's decoy."""
    base, src = P.T.runs_base(tmp_path, source_run_id=P.SOURCE_RUN_ID)
    own_decoy = base / "20260101t000000z-decoy"
    beta = P.second_tenant(P.data_root(), "beta")
    H.runs_folder(beta)
    beta_decoy = Path(beta.runs) / "20260101t000000z-betas-run"
    for decoy in (own_decoy, beta_decoy):
        shutil.copytree(src, decoy)
        (decoy / "alert.json").write_text('{"rule": {"id": "DECOY-ONLY-ALERT"}}\n',
                                          encoding="utf-8")

    def sibling(i: int, decoy: Path, source_run_id: str) -> tuple[P.SiblingRecorder, tuple]:
        sub = tmp_path / f"scene{i}"
        sub.mkdir()
        episode_id = f"{P.EPISODE_ID}-r{i + 2}"
        doc = P.family_doc(src, source_run_dir=str(decoy), episode_id=episode_id)
        doc["source_run_id"] = source_run_id
        _s, ep = P.sibling_scene(sub, container=P.SIBLING_TENANT, episode_id=episode_id,
                                 doc=doc)
        rec = P.SiblingRecorder()
        return rec, P.drive_run_py(P.sibling_argv(P.SIBLING_TENANT, ep, "b"), rec)

    for i, decoy in enumerate((own_decoy, beta_decoy)):
        rec, (rc, refused, err) = sibling(i, decoy, "20260101t000000z-gone")
        steered = rec.run_dir is not None and b"DECOY-ONLY-ALERT" in (
            rec.run_dir / "alert.json").read_bytes()
        assert not steered, f"the old field stood in for the absent source: {decoy}"
        assert refused is not None or rc not in (0, None), f"{decoy}: the sibling ran: {err}"
        assert "lifecycle" not in rec.order

    rec, (rc, refused, err) = sibling(2, own_decoy, P.SOURCE_RUN_ID)
    assert refused is None, f"the control was refused: {P.refusal_text(refused)} {err}"
    assert rc == 0
    assert (rec.run_dir / "alert.json").read_bytes() == (src / "alert.json").read_bytes()


# ==========================================================================================
# F5 — the run page and `workspace_map` open through the repository: the record is judged and
# a linked `<T>/runs` is never followed (declared change 7, O3, O1).
# ==========================================================================================

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
    """F5 / declared change 7 / O3: `visualize_run.py --tenant T <run_id>` opens through
    `runs.open`. POSITIVE CONTROL first: T's run renders. Then T's runs folder's `_tenant.json`
    names another real tenant: refused, no page written. Then (record restored) `<T>/runs` is a
    link to a real folder holding the same run: refused, nothing written into the link's target.
    A run page composing `<data root>/<T>/runs/<id>` by hand fails both. RED at base: the CLI
    takes a folder path ("usage")."""
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
    """F5 / declared change 10 / O3: `workspace_map.py --tenant T <run_id>` opens through the
    repository. POSITIVE CONTROL first: it prints the library's map of T's run. Then T's
    `_tenant.json` names another real tenant: refused, nothing printed. Then (record restored)
    `<T>/runs` is a link to a real folder: refused. RED at base: the CLI takes a folder path."""
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


# ==========================================================================================
# F6(a) — D-stored: every named member of the malformed-row domain is quarantined, and the
# drain goes on.
# ==========================================================================================

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
    """F6(a) / D-stored: "a row whose `tenant_id` or `run_id` is missing, not a string, or off
    its grammar takes today's 'unreadable: …' quarantine". One such row and a well-formed row
    are queued: the tick raises nothing, the bad row is dead-lettered "unreadable…", and the
    good row is served (POSITIVE CONTROL). A second tick then raises nothing and serves the next
    well-formed row — a row left in flight that raises on every reclaim would wedge it. RED at
    base: the good new-shape row has no `run_dir`, so it is quarantined and nothing is served."""
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


# ==========================================================================================
# F7 — the migrated CLIs as the operator runs them: real processes, their `__main__` lines lit.
# ==========================================================================================

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


#: Run a script's `__main__` block in this process, argv as the operator types it. The
#: launcher's first lines re-exec into `defender/.venv/bin/python3` whenever `sys.executable`
#: differs from it — a deployment convenience, not under test, that would hand the child to
#: whatever that venv holds (a bare one in a fresh worktree). Naming that interpreter as
#: `sys.executable` keeps the child here; everything after the guard, `main(sys.argv[1:])`
#: included, runs as written.
_AS_MAIN = (
    "import runpy, sys; from pathlib import Path; script = sys.argv[1]; "
    "sys.executable = str(Path(script).resolve().parents[2] / '.venv' / 'bin' / 'python3'); "
    "sys.argv = sys.argv[1:]; runpy.run_path(script, run_name='__main__')"
)


def test_f7_workspace_map_as_a_process(tmp_path, d9_tenant):
    """F7 / declared change 10: `python defender/scripts/workspace_map.py --tenant T <run_id>`
    exits 0 printing the library's map of T's run; for an absent run id it exits non-zero naming
    the id, with no argument error. A `__main__` that hands `main` the wrong slice of argv fails
    both. RED at base: the script takes a folder path ("usage")."""
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


def test_f7_the_launcher_as_a_process(tmp_path):
    """F7 / declared change 1: `python defender/learning/branch/cli.py --tenant T <run_id>
    <branch_message_id>` over a source id with no run in T exits non-zero naming the id, before
    anything is spent, with no argument error (`--help` alone, today's only process run, cannot
    see an argv slice off by one). Its success is NOT pinned as a process: a launch spends real
    models. RED at base: the launcher does not know `--tenant` ("usage")."""
    P.launch_source(tmp_path)
    cli = _script("learning", "branch", "cli.py")
    _refused_naming(_process("-c", _AS_MAIN, cli, *P.new_launch_argv(P.LAUNCH_TENANT, _ABSENT)),
                    _ABSENT)


def _done_run(tenant_id: str) -> Path:
    """A run of `tenant_id` the lead author has already served (its `done` sentinel written
    through the real writer), so serving it again is the clean no-op exit 0."""
    from defender.learning.leads import lead_author

    runs = P.data_root() / tenant_id / "runs"
    P.plant_record(runs, tenant_id)
    run = H.make_run(runs, "20260605t000000z-case-a")
    lead_author.write_done_sentinel(run, "0" * 40)
    return run


def test_f7_the_lead_author_as_a_process(tmp_path, d9_tenant):
    """F7 / declared change 10: `python -m defender.learning.leads.lead_author --tenant T
    <run_id>` over T's already-served run exits 0 (the done sentinel's no-op); over an absent
    run id it exits non-zero naming the id, with no argument error. RED at base: the lead author
    does not know `--tenant` ("usage")."""
    run = _done_run(d9_tenant)
    ok = _process("-m", "defender.learning.leads.lead_author", "--tenant", d9_tenant, run.name)
    assert ok.returncode == 0, ok.stderr[-600:]
    _refused_naming(_process("-m", "defender.learning.leads.lead_author",
                             "--tenant", d9_tenant, _ABSENT), _ABSENT)


def test_f7_the_tracer_as_a_process(tmp_path, d9_tenant):
    """F7 / declared change 10: `python defender/learning/ops/trace_lesson.py --tenant T --all
    --lessons-dir D` walks T's runs and prints lesson L's row (one run loaded it); with a stray
    file in `<T>/runs` it exits non-zero naming the stray, with no argument error. RED at base:
    the tracer does not know `--tenant` ("usage")."""
    lessons = tmp_path / "lessons"
    lessons.mkdir()
    (lessons / "L.md").write_text(
        "---\nname: L\ndescription: d\ncreated_at: 2026-06-04\n---\nbody\n", encoding="utf-8")
    runs = P.data_root() / d9_tenant / "runs"
    P.plant_record(runs, d9_tenant)
    run = runs / "20260605t000000z-case-a"
    run.mkdir()
    (run / "report.md").write_text("---\ndisposition: benign\n---\nbody\n", encoding="utf-8")
    (run / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}) + "\n",
        encoding="utf-8")
    command = (_script("learning", "ops", "trace_lesson.py"), "--tenant", d9_tenant, "--all",
               "--lessons-dir", str(lessons))
    ok = _process(*command)
    assert ok.returncode == 0, ok.stderr[-600:]
    assert ok.stdout.splitlines() == ["L\td\t1\t0"], ok.stdout

    (runs / "stray-file.txt").write_text("not a run\n", encoding="utf-8")
    _refused_naming(_process(*command), "stray-file.txt")


# ==========================================================================================
# F9 — the lead author resolves (tenant, run id) and no longer takes a path (D5″ row 20,
# O1(d)).
# ==========================================================================================

def test_f9_the_lead_author_resolves_tenant_and_run_id_and_refuses_a_path(tmp_path, d9_tenant):
    """F9 / D5″ row 20 / O1(d): `lead_author --tenant T <run_id>` serves T's run (here already
    served: the done sentinel's exit 0, reached only once the run was resolved and opened). The
    SAME run named by its folder path is refused — a path is not a run id — and so is the id
    under another real tenant and an absent id. A lead author that requires `--tenant` but keeps
    the positional a path fails the first assertion. RED at base: the lead author does not know
    `--tenant`."""
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


# ==========================================================================================
# F10 — declared change 13: the CLI usage prose names the new arguments.
# ==========================================================================================

#: The documents and docstrings declared change 13 names, and the ones a grep for the old
#: argument shapes finds beside them.
_PROSE = (
    "README.md", "defender/CLAUDE.md", "defender/docs/learning-loop.md",
    "defender/docs/run-records.md", "defender/skills/handbook/content/learning-loop.md",
    "defender/skills/handbook/content/run-artifacts.md", "defender/runtime/branch/_family.py",
    "defender/learning/ops/trace_lesson.py", "defender/learning/leads/lead_author/__main__.py",
    "defender/learning/branch/cli.py", "defender/run.py",
    "defender/scripts/visualize/visualize_run.py", "defender/scripts/workspace_map.py",
)

#: An old argument shape, and what replaced it.
_STALE = (
    (re.compile(r"run\.py --resume|--resume <"), "a sibling is --tenant T --episode ep --world L"),
    (re.compile(r"--runs-dir"), "the tracer walks <T>/runs (J8)"),
    (re.compile(r"cli\.py <run_dir>"), "the launcher takes --tenant T <source_run_id>"),
    (re.compile(r"lead_author <run_dir>"), "the lead author takes --tenant T <run_id>"),
    (re.compile(r"visualize_run\.py <run_dir>"), "the run page takes --tenant T <run_id>"),
    (re.compile(r"workspace_map\.py <run_dir>"), "workspace_map takes --tenant T <run_id>"),
)


def _stale_lines(text: str) -> list[str]:
    return [f"{line.strip()[:120]!r} ({why})" for line in text.splitlines()
            for pattern, why in _STALE if pattern.search(line)]


def test_f10_no_cli_usage_prose_names_the_old_arguments():
    """F10 / declared change 13: no CLI usage text in the named documents and docstrings spells
    an argument shape PR 2 removes (`run.py --resume`, `--resume <manifest>`, `--runs-dir`, a
    `<run_dir>` positional for the launcher, the lead author, the run page or `workspace_map`).
    POSITIVE CONTROL: every named file exists, and the matcher flags each old shape in a
    planted line. RED at base: README.md:166, defender/CLAUDE.md:75/:120, the learning-loop docs,
    `_family.py:5`, `trace_lesson.py:30`, … still spell them."""
    planted = ("python3 defender/learning/branch/cli.py <run_dir> 1\n"
               "run.py --resume <manifest> --world b\ntrace_lesson.py --runs-dir X\n"
               "python -m defender.learning.leads.lead_author <run_dir>\n"
               "usage: visualize_run.py <run_dir>\nusage: workspace_map.py <run_dir>\n")
    assert len(_stale_lines(planted)) == len(_STALE)

    stale = []
    for rel in _PROSE:
        path = H.WORKTREE / rel
        assert path.is_file(), f"{rel} is gone; re-point this census"
        stale += [f"{rel}: {hit}" for hit in _stale_lines(path.read_text(encoding="utf-8"))]
    assert stale == [], "usage prose still names the old arguments:\n" + "\n".join(stale)
