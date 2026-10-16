"""The environment a run hands its children: DEFENDER_RUNS_BASE is derived from the run's runs base, and the prior-run corpus is scoped to the tenant."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


from defender.tests._alert_plant import plant_alert
from defender.tests import _triplet_947 as T
from defender.tests.tenant_1078_pass_a import _spec1078 as H

TENANT = H.VALID_ID


def _fresh_run(root: Path, run_id: str = "r2", tenant_id: str = TENANT) -> Path:
    """A fresh run of `tenant_id` materialised by the REAL `materialize_run` under the
    data root this process resolves (the tenant is created first, through `create_tenant`
    over a placed knowledge folder, then accepted there as the entry does)."""
    if not H.row_path(root, tenant_id).is_file():
        H.make_tenant(root, tenant_id)
    alert = H.plant_alert(root.parent / f"alert-{run_id}")
    tenant = H.accept(H.resolve_data_root(), tenant_id)
    return H.run_common().materialize_run(alert, run_id, tenant=tenant).run_dir




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
    investigation.md in <root>/T/runs/."""
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
    corpus, and the corpus root is never the data root, <root>/T/ or <root>/T/episodes/."""
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




# ======================================================================================
# D5 and the box/host env (settled s077-s081)
# ======================================================================================





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
    for every child they build (C9)."""
    stale = tmp_path / "old-defender-runs"
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(stale))
    run_dir = tmp_path / "data" / TENANT / "runs" / "r1"
    run_dir.mkdir(parents=True)
    plant_alert(run_dir)
    box = H.mod("runtime.box")
    assert H.run_common().run_env(H.DEFENDER, run_dir)["DEFENDER_RUNS_BASE"] == \
        str(run_dir.parent)
    assert box.infra_env(H.DEFENDER, run_dir)["DEFENDER_RUNS_BASE"] == str(run_dir.parent)
    argv = box._create_argv("defender-r1", run_dir, H.DEFENDER,
                            H.mod("runtime.box._spec").DEFAULT_SPEC).argv
    exported = [a for a in argv if a.startswith("DEFENDER_RUNS_BASE=")]
    assert exported == [f"DEFENDER_RUNS_BASE={run_dir.parent}"], exported






# ======================================================================================
# Survivals: N9's directory tools, D9's replay harness, the pre-(C) lead-author drain
# ======================================================================================









