"""Runs-base consumers (pre-flight replay env, held_out) take their base from a tenant, never a default."""
from __future__ import annotations

from datetime import datetime

import json
import importlib
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H

TENANT = H.VALID_ID
#: The family's branch-point clock pre-flight's context carries.
_AS_OF = datetime.fromisoformat(T.AS_OF)


def _held_out():
    return importlib.import_module("evaluations.held_out")


def _fixtures(tmp_path: Path, slug: str = "slug-one", disposition: str = "benign") -> Path:
    """One labeled held-out fixture: `<fixtures>/<slug>/{alert.json, ground_truth.yaml}`."""
    fx = tmp_path / "fixtures" / slug
    fx.mkdir(parents=True)
    (fx / "alert.json").write_text(json.dumps({"rule": {"id": slug}}), encoding="utf-8")
    (fx / "ground_truth.yaml").write_text(
        f"held_out: true\ndisposition: {disposition}\n", encoding="utf-8")
    return fx.parent


def _scored_run(runs: Path, disposition: str, slug: str = "slug-one") -> Path:
    run = runs / slug
    run.mkdir(parents=True, exist_ok=True)
    plant_alert(run, {"rule": {"id": slug}})
    (run / "report.md").write_text(T.report_text(disposition), encoding="utf-8")
    return run


def _drive_held_out(argv: list[str], capsys) -> tuple[Any, str]:
    """`held_out.main(argv)` → (its status — a return code or a SystemExit code, `None` for a
    clean `--help`), and everything it printed."""
    try:
        status: Any = _held_out().main(argv)
    except SystemExit as stopped:
        status = stopped.code
    out = capsys.readouterr()
    return status, out.out + out.err


SCORED = "# Held-out eval"


def _preflight_context(ep: Path, source: Any, tenant: Any) -> Any:
    """The context pre-flight's host-side reads run in (`cli._preflight_context`), for the
    opened source `Run` (#1105 PR 2: the env's runs base is the source's own hand-out)."""
    return H.branch_cli()._preflight_context(ep, source, tenant, _AS_OF)


def _tenant_source(root: Path) -> Any:
    """T's finished source run at `<root>/T/runs/<id>`, opened by id through T's repository —
    what the launcher hands pre-flight (#1105 PR 2)."""
    _base, src = H.tenant_source(root, TENANT, row=False)
    return T.open_source(src)


def test_d4_preflight_env_threaded(tmp_path, monkeypatch):
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, TENANT)
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "stale"))
    ep = tmp_path / "episodes-root" / "ep-1"
    ep.mkdir(parents=True)
    base = root.resolve() / TENANT / "runs"

    ctx = _preflight_context(ep, _tenant_source(root), H.T1106.run_tenant(H.accept(root, TENANT)))
    assert ctx.env["DEFENDER_RUNS_BASE"] == str(base)
    assert ctx.env["DEFENDER_RUNS_BASE"] != str(ep.parent)
    assert ctx.run_dir == ep, "the replay context stopped being the episode dir"

    with pytest.raises(TypeError):
        H.branch_cli()._preflight_context(ep, as_of=_AS_OF)


def test_d4_held_out_exactly_one(tmp_path, monkeypatch, capsys):
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, TENANT)
    fixtures = _fixtures(tmp_path)
    _scored_run(H.runs_dir(root, TENANT), "benign")
    stale = tmp_path / "stale-runs"
    _scored_run(stale, "malicious")
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(stale))
    positional = tmp_path / "given-dir"
    _scored_run(positional, "inconclusive")
    fx = ["--fixtures-dir", str(fixtures)]

    status, out = _drive_held_out([str(positional), *fx], capsys)
    assert status == 0, out
    assert "predicted='inconclusive'" in out, f"the positional dir was not the one scored:\n{out}"

    for argv, what in ((["--tenant", TENANT, *fx], "--tenant"),
                       ([str(positional), "--tenant", TENANT, *fx], "a runs dir and --tenant"),
                       (fx, "no runs dir")):
        status, out = _drive_held_out(argv, capsys)
        assert status not in (0, None), f"held_out with {what} was not refused"
        assert SCORED not in out, f"held_out with {what} scored something before refusing:\n{out}"


def test_s7_j50_held_out_positional_ignores_data_root(tmp_path, monkeypatch, capsys):
    """held_out <runs_dir> scores the directory it is given under DEFENDER_DATA_ROOT=rel/ (and
    with it unset): the positional branch never resolves the data root or a tenant."""
    monkeypatch.chdir(tmp_path)
    fixtures = _fixtures(tmp_path)
    given = tmp_path / "given-dir"
    _scored_run(given, "benign")
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "stale-knob"))
    for value in ("rel/", None):
        if value is None:
            H.set_data_root(monkeypatch, None)
        else:
            monkeypatch.setenv(H.DATA_ROOT_ENV, value)
        status, out = _drive_held_out([str(given), "--fixtures-dir", str(fixtures)], capsys)
        assert status == 0, f"DEFENDER_DATA_ROOT={value!r}: {out}"
        assert "slug-one: predicted='benign'" in out, out
        assert "WRONG" not in out, out
    assert not (tmp_path / "rel").exists(), "the positional branch created the data root"
