"""#1078 pass (A) — the environment a run hands its children, the model's prior-run corpus,
and the tools and lanes that must keep working unchanged (D5, O8, N9, D9, settled s074-s087).

D5: `run_env` and `infra_env` keep exporting `DEFENDER_RUNS_BASE=run_dir.parent`, which is now
the tenant's runs base (`<root>/<T>/runs`) for a fresh run, or an episode's `runs/` for a
sibling. The value is DERIVED — no operator sets it — so the invlang corpus (O8, read by the
real `defender-invlang` shim off that variable, C15) is scoped by construction. Every run dir
here is built by the REAL `materialize_run_dir(..., tenant_id=T)` where the demand is about a
run's own environment, so "the run's runs base" is what the code made, never a path the test
composed and then asserted it had composed.

Faults are real inputs through the real primitive: the stale inherited `DEFENDER_RUNS_BASE`,
the investigation planted under the tenant's `episodes/`, the uncovered bind source. The only
seams driven are the shipped ones (`lead_author_drain(run_lead_author=, branch=, start_box=,
...)`, the replay harness's `drive(...)`), each recording what it was handed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests import _triplet_947 as T
from defender.tests.tenant_1078_pass_a import _spec1078 as H

TENANT = H.VALID_ID


def _fresh_run(root: Path, run_id: str = "r2", tenant_id: str = TENANT) -> Path:
    """A fresh run of `tenant_id` materialised by the REAL `materialize_run_dir` under the
    data root this process resolves (the tenant is created first, through `create_tenant`)."""
    if not H.row_path(root, tenant_id).is_file():
        H.make_tenant(root, tenant_id)
    alert = H.plant_alert(root.parent / f"alert-{run_id}")
    return H.run_common().materialize_run_dir(alert, run_id, tenant_id=tenant_id)


def _sibling_run(tmp_path: Path, root: Path, episodes_root: Path) -> tuple[Path, Path]:
    """A pass-(A) sibling: its source at a tenant location, its episode under the OLD
    episodes base (outside the data root — O4's gap until (B)), materialised by the real
    `materialize_run_dir`'s sibling arm. Returns (sibling run dir, episode dir)."""
    _base, src = H.tenant_source(root, TENANT, row=not H.row_path(root, TENANT).is_file())
    episode_dir = episodes_root / T.EPISODE_ID
    manifest = H.family_for(src, episode_dir)
    world = H.run_py().resume_world(manifest, "b")
    run_dir = H.run_common().materialize_run_dir(
        src / "alert.json", world.run_id, tenant_id=TENANT, world=world)
    return Path(run_dir), episode_dir


def _corpus_paths(corpus_root: str | Path) -> set[Path]:
    """The investigation documents the corpus reader actually LOADED from `corpus_root`."""
    corpus, _report = H.mod("skills.invlang.corpus").load_corpus(corpus_root)
    return {Path(c.source_path).resolve() for c in corpus}


def _shim_loaded(env: dict[str, str]) -> str:
    """Run the REAL `defender-invlang` shim (the command orient and the model run) in `env`,
    and hand back the corpus line it prints: `loaded <n>/<scanned> cases ...`."""
    proc = subprocess.run(  # noqa: S603 — the checkout's own shim, fixed argv
        [str(H.DEFENDER / "bin" / "defender-invlang"), "hypotheses", "*"],
        env=env, capture_output=True, text=True, encoding="utf-8", timeout=120, check=False)
    assert proc.returncode == 0, f"defender-invlang failed:\n{proc.stderr}"
    lines = [ln for ln in proc.stderr.splitlines() if ln.startswith("loaded ")]
    assert lines, f"the shim printed no corpus line:\n{proc.stderr}"
    return lines[0]


def _plant_corpus_layout(root: Path) -> tuple[Path, Path, Path]:
    """T with a prior finished run in `<root>/T/runs/r1` and an investigation planted under
    `<root>/T/episodes/x/runs/y/`, both REAL corpus documents (the committed golden — a stub
    parses to nothing and every corpus assertion would read 0 == 0). Then a fresh run r2 of T,
    materialised for real. Returns (r2's run dir, r1's document, the planted document)."""
    H.make_tenant(root, TENANT)
    prior = T.corpus_document(H.runs_dir(root, TENANT) / "r1")
    planted = T.corpus_document(root / TENANT / "episodes" / "x" / "runs" / "y")
    run_dir = _fresh_run(root, "r2")
    return Path(run_dir), prior, planted


# ======================================================================================
# O8 — the model's prior-run corpus is the run's own runs base
# ======================================================================================

def test_o8_corpus_is_own_runs_base(tmp_path, monkeypatch):
    """Orient's corpus for a fresh run under <root>/T/runs/ includes a prior run's
    investigation.md in <root>/T/runs/.

    The corpus root is what orient hands the shim — `run_env(defender_dir, run_dir)`'s
    DEFENDER_RUNS_BASE — and it is read here through the REAL `defender-invlang` shim and the
    real corpus loader."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    run_dir, prior, _planted = _plant_corpus_layout(root)
    assert run_dir == H.runs_dir(root, TENANT) / "r2", f"the fresh run landed at {run_dir}"
    env = H.run_common().run_env(H.DEFENDER, run_dir)
    assert Path(env["DEFENDER_RUNS_BASE"]) == H.runs_dir(root, TENANT)
    assert prior.resolve() in _corpus_paths(env["DEFENDER_RUNS_BASE"]), (
        "the prior run of the same tenant is missing from the fresh run's corpus")
    assert _shim_loaded(env).startswith("loaded 1/1 "), (
        "the shim's corpus is not exactly T's one prior run")


def test_o8_episode_runs_absent(tmp_path, monkeypatch):
    """An investigation.md planted under <root>/T/episodes/x/runs/y/ is absent from that
    corpus, and the corpus root is never the data root, <root>/T/ or <root>/T/episodes/.

    Paired with `test_o8_corpus_is_own_runs_base` on the same layout; the prior run's presence
    is re-checked here so an EMPTY corpus cannot satisfy the absence."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    run_dir, prior, planted = _plant_corpus_layout(root)
    env = H.run_common().run_env(H.DEFENDER, run_dir)
    corpus_root = Path(env["DEFENDER_RUNS_BASE"]).resolve()
    assert corpus_root not in {root.resolve(), (root / TENANT).resolve(),
                               (root / TENANT / "episodes").resolve()}, (
        f"the corpus root is {corpus_root}, a tree that holds more than T's own runs")
    loaded = _corpus_paths(corpus_root)
    assert planted.resolve() not in loaded, "an episode's sibling run leaked into the corpus"
    assert prior.resolve() in loaded, "the corpus is empty — the absence above proves nothing"


def test_corpus_for_a_fresh_run_holds_the_record_and_sidecars(tmp_path, monkeypatch):
    """A fresh run's corpus is <T>/runs, which holds _tenant.json and the sidecars as today's
    base does; the tenant row sits beside runs/, outside the corpus; orient's own filtering is
    unchanged."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, TENANT)
    prior = T.corpus_document(H.runs_dir(root, TENANT) / "r1")
    sidecar = H.runs_dir(root, TENANT) / "r1.run-end.json"
    sidecar.write_text(json.dumps({"exit_class": "completed"}), encoding="utf-8")
    run_dir = _fresh_run(root, "r2")
    corpus_root = Path(H.run_common().run_env(H.DEFENDER, run_dir)["DEFENDER_RUNS_BASE"])
    assert corpus_root == H.runs_dir(root, TENANT)
    assert (corpus_root / H.RECORD_NAME).is_file(), "the runs-base record is not in the corpus"
    assert sidecar.parent == corpus_root
    row = H.row_path(root, TENANT)
    assert row.is_file(), "setup's row is missing"
    assert corpus_root not in row.parents, "the row sits inside the corpus"
    corpus, report = H.mod("skills.invlang.corpus").load_corpus(corpus_root)
    assert {Path(c.source_path).resolve() for c in corpus} == {prior.resolve()}
    # the record and the sidecar are not documents: only r1's investigation.md is scanned
    assert report.scanned == 1, f"orient's filter changed: it scanned {report.scanned} entries"


# ======================================================================================
# D5 and the box/host env (settled s077-s081)
# ======================================================================================

def test_d5_derived_export_parity(tmp_path, monkeypatch):
    """run_env and infra_env both export DEFENDER_RUNS_BASE=run_dir.parent: <root>/T/runs for
    a fresh run and <ep>/runs for a sibling."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    box = H.mod("runtime.box")
    fresh = _fresh_run(root, "r1")
    sibling, episode_dir = _sibling_run(tmp_path, root, tmp_path / "episodes")
    for run_dir, expected in ((fresh, H.runs_dir(root, TENANT)),
                              (sibling, episode_dir / "runs")):
        host = H.run_common().run_env(H.DEFENDER, run_dir)["DEFENDER_RUNS_BASE"]
        boxed = box.infra_env(H.DEFENDER, run_dir)["DEFENDER_RUNS_BASE"]
        assert host == boxed == str(run_dir.parent), (host, boxed, run_dir)
        assert Path(host) == expected, f"{run_dir}'s runs base is {host}, not {expected}"


def test_box_remedy_text_rewritten_to_name_the_data_root(tmp_path):
    """The box's not-shared remedy (_lifecycle.py:47) names DEFENDER_DATA_ROOT, and the module
    still passes lint_ci_hygiene. P8 stays carried.

    Driven through the real argv builder with a run dir on no shared mount (C46's refusal);
    the lint half is a hygiene finding count over `_lifecycle.py` only."""
    box = H.mod("runtime.box")
    run_dir = tmp_path / "data" / TENANT / "runs" / "r1"
    run_dir.mkdir(parents=True)
    nowhere = tmp_path / "shared-nowhere"
    with pytest.raises(H.mod("runtime.box_codec").BoxFault) as fault:
        box._create_argv("defender-r1", run_dir, H.DEFENDER,
                         H.mod("runtime.box._spec").DEFAULT_SPEC, mounts=((nowhere, nowhere),))
    text = str(fault.value)
    assert "the run dir" in text, f"a different refusal fired: {text}"
    assert H.DATA_ROOT_ENV in text, f"the remedy does not name {H.DATA_ROOT_ENV}: {text}"
    assert "DEFENDER_RUNS_BASE" not in text, (
        "the remedy still tells the operator to set the retired runs-base knob")
    from defender.tests._by_path import load_lint_gate

    hygiene = load_lint_gate("lint_ci_hygiene")
    source = (H.DEFENDER / "runtime" / "box" / "_lifecycle.py").read_text(encoding="utf-8")
    flagged = [ln for ln in source.splitlines()
               if "lint-hygiene: ok" not in ln and hygiene.PATH_PATTERN.search(ln)
               and not any(p.search(ln) for p in hygiene.DEFAULT_PATTERNS)]
    assert flagged == [], f"_lifecycle.py fails lint_ci_hygiene's path check: {flagged}"


def test_data_root_value_reaches_host_subprocesses(tmp_path, monkeypatch):
    """Host subprocesses a run spawns inherit DEFENDER_DATA_ROOT unchanged, alongside the
    derived DEFENDER_RUNS_BASE."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    run_dir = _fresh_run(root, "r1")
    env = H.run_common().run_env(H.DEFENDER, run_dir)
    child = subprocess.run(  # noqa: S603 — the test's own interpreter
        [sys.executable, "-c",
         "import json, os; print(json.dumps({k: os.environ.get(k) for k in "
         "('DEFENDER_DATA_ROOT', 'DEFENDER_RUNS_BASE')}))"],
        env=env, capture_output=True, text=True, timeout=60, check=True)
    seen = json.loads(child.stdout)
    assert seen["DEFENDER_DATA_ROOT"] == str(root), "the host child lost the data root"
    assert seen["DEFENDER_RUNS_BASE"] == str(H.runs_dir(root, TENANT))


def test_run_env_export_clobbers_stale_runs_base(tmp_path, monkeypatch):
    """run_env and infra_env overwrite an inherited DEFENDER_RUNS_BASE with run_dir.parent
    for every child they build (C9).

    The stale value is a real inherited environment (an operator shell still exporting the
    retired knob); the children observed are the host env, the box's infra env and the box's
    own `docker run` argv."""
    stale = tmp_path / "old-defender-runs"
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(stale))
    run_dir = tmp_path / "data" / TENANT / "runs" / "r1"
    run_dir.mkdir(parents=True)
    box = H.mod("runtime.box")
    assert H.run_common().run_env(H.DEFENDER, run_dir)["DEFENDER_RUNS_BASE"] == \
        str(run_dir.parent)
    assert box.infra_env(H.DEFENDER, run_dir)["DEFENDER_RUNS_BASE"] == str(run_dir.parent)
    argv = box._create_argv("defender-r1", run_dir, H.DEFENDER,
                            H.mod("runtime.box._spec").DEFAULT_SPEC).argv
    exported = [a for a in argv if a.startswith("DEFENDER_RUNS_BASE=")]
    assert exported == [f"DEFENDER_RUNS_BASE={run_dir.parent}"], exported


def test_box_env_allowlist_survives_knob_retirement(tmp_path):
    """box_codec.py:33's allowlist entry for DEFENDER_RUNS_BASE survives the knob retirement:
    it is independent of resolve_runs_base (C92), and the O7 census allowlists it (demand fork
    F2, auto: the provisional allowlist stands).

    Observed in the retired world: `resolve_runs_base` is gone from `run_common`, and a box's
    `docker run` argv still carries the derived DEFENDER_RUNS_BASE."""
    assert not hasattr(H.run_common(), "resolve_runs_base"), (
        "the knob is not retired yet: run_common still defines resolve_runs_base")
    assert "DEFENDER_RUNS_BASE" in H.mod("runtime.box_codec").BOX_ENV_ALLOWLIST
    run_dir = tmp_path / "data" / TENANT / "runs" / "r1"
    run_dir.mkdir(parents=True)
    argv = H.mod("runtime.box")._create_argv(
        "defender-r1", run_dir, H.DEFENDER, H.mod("runtime.box._spec").DEFAULT_SPEC).argv
    assert f"DEFENDER_RUNS_BASE={run_dir.parent}" in argv, (
        "the box no longer receives the derived runs base the in-box shim requires")


def test_box_environment_for_a_sibling_under_the_old_episodes_base(tmp_path, monkeypatch):
    """A pass-A sibling's box env exports DEFENDER_RUNS_BASE=run_dir.parent, its episode's
    runs dir under the old episodes base (O4's gap until (B))."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    old_episodes = tmp_path / "old-episodes-base"
    run_dir, episode_dir = _sibling_run(tmp_path, root, old_episodes)
    assert run_dir.parent == episode_dir / "runs"
    assert root.resolve() not in run_dir.resolve().parents, (
        "the sibling landed under the data root — that is pass (B)'s layout, not (A)'s")
    env = H.mod("runtime.box").infra_env(H.DEFENDER, run_dir)
    assert env["DEFENDER_RUNS_BASE"] == str(episode_dir / "runs")


# ======================================================================================
# Survivals: N9's directory tools, D9's replay harness, the pre-(C) lead-author drain
# ======================================================================================

def _lesson(lessons: Path, name: str) -> None:
    lessons.mkdir(parents=True, exist_ok=True)
    (lessons / f"{name}.md").write_text(
        "---\ncreated_at: 2026-06-04T00:00:00+00:00\n---\nbody\n", encoding="utf-8")


def _loaded_run(runs: Path, name: str, lesson: str) -> None:
    rd = runs / name
    rd.mkdir(parents=True)
    (rd / "report.md").write_text("---\ndisposition: benign\n---\nbody\n", encoding="utf-8")
    (rd / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": lesson, "ts": "2026-06-05T00:00:00+00:00"}) + "\n",
        encoding="utf-8")


def test_n9_directory_tools_survive(tmp_path, monkeypatch, capsys):
    """visualize_run, visualize_episode, held_out's positional runs dir, trace_lesson
    --runs-dir and bin/defender-invlang with DEFENDER_RUNS_BASE set run with no --tenant and
    read the directory they are given.

    Every tool runs with DEFENDER_DATA_ROOT UNSET (so none of them can be resolving a tenant
    behind the operator's back) and is pointed at a runs dir under a tenant layout — they read
    what they are given."""
    H.set_data_root(monkeypatch, None)
    monkeypatch.delenv("DEFENDER_RUNS_BASE", raising=False)
    runs = tmp_path / "data" / TENANT / "runs"
    runs.mkdir(parents=True)

    # visualize_run — a real, renderable run (it follows the run's session pointer)
    src = H.source_run(runs)
    assert H.mod("scripts.visualize.visualize_run").main(["visualize_run.py", str(src)]) == 0
    assert (src / "runtime.html").is_file()

    # visualize_episode — reads only the episode dir
    ep = T.episode(tmp_path / "episodes-home")
    assert H.mod("scripts.visualize.visualize_episode").main([str(ep)]) == 0

    # held_out's positional runs dir — scores the fixture's run found IN that dir
    fixtures = tmp_path / "held-out"
    (fixtures / "m01-case").mkdir(parents=True)
    (fixtures / "m01-case" / "alert.json").write_text("{}", encoding="utf-8")
    (fixtures / "m01-case" / "ground_truth.yaml").write_text(
        "held_out: true\ndisposition: benign\n", encoding="utf-8")
    (runs / "m01-case").mkdir()
    (runs / "m01-case" / "report.md").write_text(
        "---\ndisposition: benign\nconfidence: high\n---\n", encoding="utf-8")
    try:
        status = H.mod("evals.held_out").main([str(runs), "--fixtures-dir", str(fixtures)])
    except SystemExit as refused:
        status = refused.code
    assert status == 0, "held_out's positional runs dir did not score the run it was given"

    # trace_lesson --runs-dir
    lessons = tmp_path / "lessons"
    _lesson(lessons, "L")
    _loaded_run(runs, "case-a", "L")
    from defender.tests._by_path import load_trace_lesson

    capsys.readouterr()
    assert load_trace_lesson("trace_lesson").main(
        ["L", "--runs-dir", str(runs), "--lessons-dir", str(lessons)]) == 0
    assert "case-a" in capsys.readouterr().out, "trace_lesson did not read the dir it was given"

    # bin/defender-invlang, host use, with DEFENDER_RUNS_BASE set by the operator
    T.corpus_document(runs / "r-doc")
    env = {k: v for k, v in os.environ.items() if k != H.DATA_ROOT_ENV}
    env.update({"DEFENDER_DIR": str(H.DEFENDER), "DEFENDER_RUNS_BASE": str(runs)})
    assert _shim_loaded(env).startswith("loaded 1/")


def test_d9_replay_harness_survives(tmp_path, monkeypatch):
    """The replay harness scenarios pass with no tenant configured.

    One small scenario through the harness (C22: it builds its own run dir and needs no
    tenant), with DEFENDER_DATA_ROOT and DEFENDER_RUNS_BASE both unset."""
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e import _replay_harness as R

    H.set_data_root(monkeypatch, None)
    monkeypatch.delenv("DEFENDER_RUNS_BASE", raising=False)
    run_dir = R.materialize(tmp_path, R.GOLDEN_AB3)
    replay = R.ReplayFn([
        R.Turn(tool_calls=[("append_block", {"text": "+ spec1078 probe\n"})]),
        R.Turn(text="done"),
    ])
    R.drive(run_dir, run_id="d9-no-tenant", main=replay)
    assert replay.calls >= 1, "the replayed model was never asked"
    assert "+ spec1078 probe" in (run_dir / "investigation.md").read_text(encoding="utf-8"), (
        "the scripted turn never reached the run dir")


def test_pass_a_marker_consumed_by_the_pre_c_lead_author_drain(tmp_path, monkeypatch):
    """A pass-A curation marker naming <root>/T/runs/r1 is served by the unchanged pre-C
    lead-author drain. P16 stays carried.

    The marker is the REAL run-end one (`run_common.enqueue_curation` over a certified,
    tenant-materialised run dir); the drain is the real `lead_author_drain` through its shipped
    seams (the curator recorded, the worktree lifecycle and box lifecycle recorded, not run)."""
    from defender.runtime import scrub as scrub_mod
    from defender.tests import _spec791 as S791

    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    state = S791.loop_paths(tmp_path)
    run_dir = _fresh_run(root, "r1")
    assert run_dir == H.runs_dir(root, TENANT) / "r1"
    S791.populate_run_dir(run_dir, disposition="benign")
    scrub_mod.scrub(run_dir)
    assert H.run_common().enqueue_curation(run_dir, run_dir / "alert.json") is True
    body = json.loads(next(state.author_queue_dir.glob("*.json")).read_text(encoding="utf-8"))
    assert Path(body["run_dir"]) == run_dir.resolve()

    served: list[Path] = []
    rc = H.mod("learning.core.drains").lead_author_drain(
        state,
        run_lead_author=lambda _paths, rd, *, box=None, **_kw: served.append(rd),
        run_pitfalls=lambda *_a, **_kw: 0,
        branch=S791.SpecBranch(tmp_path / "worktrees"),
        start_box=S791.noop_start_box, stop_box=S791.noop_stop_box, scrub=S791.noop_scrub,
    )
    assert rc == 0
    assert served == [run_dir.resolve()], f"the drain did not serve the pass-A run ({served})"
