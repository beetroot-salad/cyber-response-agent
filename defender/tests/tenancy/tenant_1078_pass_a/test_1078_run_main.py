"""run.py main front door: tenant required and checked before anything is spent, sibling tenant from the episode record, data-root faults, refusal confinement."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid

CASE_X = fixture_uuid("case-x")

import json
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H


def _refused(argv: list[str], rec: H.Recorder, capsys=None) -> str:
    """Drive `main`, assert it REFUSED with nothing spent, and return what it said (the exit's
    own message, plus stderr when an argparse-level refusal printed there)."""
    rc, refused = H.drive_main(argv, rec)
    assert refused is not None, f"run.py accepted {argv!r} (exit {rc}, ran {rec.order})"
    assert refused.code not in (0, None), f"run.py 'refused' {argv!r} with a success exit"
    assert not rec.spent, f"run.py spent before refusing {argv!r}: {rec.order}"
    text = H.refusal_text(refused)
    if capsys is not None:
        text += "\n" + capsys.readouterr().err
    return text


def _accepted(argv: list[str], rec: H.Recorder) -> dict[str, Any]:
    """Drive `main`, assert it reached materialize once, and return what materialize got."""
    rc, refused = H.drive_main(argv, rec)
    assert refused is None, f"run.py refused {argv!r}: {H.refusal_text(refused)!r}"
    assert rc == 0, f"run.py exited {rc} for {argv!r} (ran {rec.order})"
    assert len(rec.materialize_calls) == 1, f"materialize ran {rec.materialize_calls}"
    return rec.materialize_calls[0]


def _sibling(tmp_path: Path, root: Path, tenant_id: str = H.VALID_ID, *, monkeypatch: Any = None,
             row: bool = True) -> tuple[Path, Path]:
    """A source run at T's tenant location plus an episode manifest naming it, at
    `<root>/<T>/episodes/<uuid>` as RUNS leaves it (#1187 Layout A, R2: `runs/` and the arm
    roster; no container record, R1). Returns (source run dir, manifest). `tmp_path` and
    `monkeypatch` are unused: no episodes base is configured (O9)."""
    del tmp_path, monkeypatch
    _base, src = H.tenant_source(root, tenant_id, row=row)
    manifest = H.family_for(src)
    return src, manifest


def _stamp_tenant(run_dir: Path, tenant_id: str) -> None:
    """Rewrite the run's provenance stamp to carry `tenant_id` — the box-writable file (C7)."""
    stamp = run_dir / "provenance.json"
    doc = json.loads(stamp.read_text(encoding="utf-8"))
    doc["tenant_id"] = tenant_id
    stamp.write_text(json.dumps(doc), encoding="utf-8")


def test_o1_fresh_run_without_tenant_refused(tmp_path, data_root, capsys):
    alert = H.plant_alert(tmp_path / "in")
    before = H.census(data_root)
    said = _refused([str(alert)], H.Recorder(tmp_path / "run"), capsys)
    assert "--tenant" in said, f"the refusal does not name the missing --tenant: {said!r}"
    assert H.census(data_root) == before
    assert not (tmp_path / "run").exists()
    H.make_tenant(data_root, H.VALID_ID)
    got = _accepted([str(alert), "--tenant", H.VALID_ID], H.Recorder(tmp_path / "run2"))
    assert got["tenant"].id == H.VALID_ID


def test_o2_unknown_tenant_refused_writes_nothing(tmp_path, data_root):
    alert = H.plant_alert(tmp_path / "in")
    before = H.census(data_root)
    said = _refused([str(alert), "--tenant", "acme"], H.Recorder(tmp_path / "run"))
    assert H.census(data_root) == before, "the refused run wrote under the data root"
    assert not (data_root / "acme").exists()
    H.assert_verbatim(said, H.owner_refusal(H.require_tenant, H.resolve_data_root(), "acme"),
                      entry="run.py main")
    H.make_tenant(data_root, "acme")
    assert _accepted([str(alert), "--tenant", "acme"],
                     H.Recorder(tmp_path / "run2"))["tenant"].id == "acme"


def test_o2_existing_tenant_runs(tmp_path, data_root):
    H.make_tenant(data_root, "acme")
    alert = H.plant_alert(tmp_path / "in")
    rec = H.Recorder(tmp_path / "run")
    got = _accepted([str(alert), "--tenant", "acme"], rec)
    assert got["tenant"].id == "acme"
    assert rec.order.index("preflight") < rec.order.index("materialize")


def test_o5_sibling_tenant_from_record(tmp_path, data_root, monkeypatch):
    src, manifest = _sibling(tmp_path, data_root, "acme", monkeypatch=monkeypatch)
    _stamp_tenant(src, "acme")
    got = _accepted(H.sibling_argv(manifest, "b", "--tenant", "acme"),
                    H.Recorder(tmp_path / "sib"))
    assert got["tenant"].id == "acme"


def test_o5_forged_stamp_ignored(tmp_path, data_root, monkeypatch):
    src, manifest = _sibling(tmp_path, data_root, "acme", monkeypatch=monkeypatch)
    H.plant_row(data_root, "victim")
    _stamp_tenant(src, "victim")
    got = _accepted(H.sibling_argv(manifest, "b", "--tenant", "acme"),
                    H.Recorder(tmp_path / "sib"))
    assert got["tenant"].id == "acme", f"the sibling took its tenant from the stamp: {got}"
    _refused(H.sibling_argv(manifest, "b", "--tenant", "victim"), H.Recorder(tmp_path / "sib2"))


def test_o5_disagreeing_tenant_refused(tmp_path, data_root, monkeypatch):
    src, manifest = _sibling(tmp_path, data_root, "acme", monkeypatch=monkeypatch)
    H.plant_row(data_root, "victim")
    said = _refused(H.sibling_argv(manifest, "b", "--tenant", "victim"),
                    H.Recorder(tmp_path / "sib"))
    assert said.startswith("[run.py] "), f"not a '[run.py] ...' refusal: {said!r}"
    assert "victim" in said, f"the refusal does not name the disagreeing --tenant: {said!r}"
    got = _accepted(H.sibling_argv(manifest, "b", "--tenant", "acme"),
                    H.Recorder(tmp_path / "sib2"))
    assert got["tenant"].id == "acme"


def test_o5_resume_without_tenant_refused(tmp_path, data_root, monkeypatch, capsys):
    src, manifest = _sibling(tmp_path, data_root, "acme-corp", monkeypatch=monkeypatch)
    recorded = "acme-corp"
    said = _refused(H.sibling_argv(manifest), H.Recorder(tmp_path / "sib"), capsys)
    assert "--tenant" in said, f"the refusal does not name the missing --tenant: {said!r}"
    got = _accepted(H.sibling_argv(manifest, "b", "--tenant", recorded),
                    H.Recorder(tmp_path / "sib2"))
    assert got["tenant"].id == recorded


def test_launch_whose_source_row_disappears_before_the_siblings_start(tmp_path, data_root,
                                                                      monkeypatch):
    src, manifest = _sibling(tmp_path, data_root, "acme", monkeypatch=monkeypatch)
    # #1105 PR 2: the launcher accepts the request's tenant (`tenant_of_run_dir` is gone, F-13).
    assert H.require_tenant(data_root, "acme").tenant_id == "acme", (
        "the launcher's own acceptance must pass first")
    H.row_path(data_root, "acme").write_text("{torn", encoding="utf-8")
    owner = H.owner_refusal(H.require_tenant, H.resolve_data_root(), "acme")
    for world in ("a", "b", "c"):
        said = _refused(H.sibling_argv(manifest, world, "--tenant", "acme"),
                        H.Recorder(tmp_path / f"sib-{world}"))
        H.assert_verbatim(said, owner, entry=f"sibling {world}")
    assert manifest.is_file(), "the prepared episode dir is not the sibling's to remove"


def test_s7_j42_resume_episode_resolves_through_its_tenant(tmp_path, data_root, monkeypatch):
    _src, manifest = _sibling(tmp_path, data_root, "acme", monkeypatch=monkeypatch)
    episode = manifest.parent.resolve()
    expected_runs = H.S.EpisodePaths(episode).runs
    link = tmp_path / "episodes-link"
    link.symlink_to(manifest.parent.parent, target_is_directory=True)
    monkeypatch.chdir(tmp_path)
    for n, base in enumerate((Path("episodes"), link)):
        monkeypatch.setenv(T.EPISODES_BASE_ENV, str(base))
        # #1187 opens by id through the tenant; the external-root spelling is a decoy.
        got = _accepted(H.sibling_argv(manifest, "b", "--tenant", "acme"),
                        H.Recorder(tmp_path / "sib" / str(n)))
        world = got["world"]
        assert Path(world.episode_dir).is_absolute(), f"{base}: {world.episode_dir}"
        assert Path(world.episode_dir) == episode, (
            f"{base}: the episode was not resolved through its tenant ({world.episode_dir})")
        assert H.S.EpisodePaths(world.episode_dir).runs == expected_runs


def test_setup_shell_and_run_shell_resolve_different_data_roots(tmp_path, monkeypatch):
    setup_root, run_root = tmp_path / "setup-root", tmp_path / "run-root"
    run_root.mkdir()
    H.place_knowledge(setup_root, "acme")  # #1120 DC2: the operator's clone, before setup
    done = H.run_setup(setup_root, "acme")
    H.assert_setup_ran(done)
    assert done.returncode == 0, H.setup_output(done)
    H.set_data_root(monkeypatch, run_root)
    before = (H.census(setup_root), H.census(run_root))
    said = _refused([str(H.plant_alert(tmp_path / "in")), "--tenant", "acme"],
                    H.Recorder(tmp_path / "run"))
    H.assert_verbatim(said, H.owner_refusal(H.require_tenant, run_root.resolve(), "acme"),
                      entry="run.py main")
    assert (H.census(setup_root), H.census(run_root)) == before


def test_data_root_is_a_regular_file(tmp_path, monkeypatch):
    root_file = tmp_path / "data-root-file"
    root_file.write_text("not a directory\n", encoding="utf-8")
    alert = H.plant_alert(tmp_path / "in")
    before = H.census(tmp_path)
    proc = H.run_setup(root_file, "acme")
    H.assert_setup_ran(proc)
    assert proc.returncode != 0, f"setup accepted a regular file as its data root: {proc}"
    assert H.census(tmp_path) == before, "the refused setup wrote something"
    H.set_data_root(monkeypatch, root_file)
    _refused([str(alert), "--tenant", "acme"], H.Recorder(tmp_path / "run"))
    assert H.census(tmp_path) == before, "the refused run wrote something"


def test_shell_that_never_received_the_compose_variable(tmp_path, monkeypatch):
    retired_default = Path("/tmp/defender-data")
    default_existed = retired_default.exists()
    H.set_data_root(monkeypatch, None)
    owner = H.owner_refusal(H.resolve_data_root)
    assert H.DATA_ROOT_ENV in str(owner)
    alert = H.plant_alert(tmp_path / "in")
    before = H.census(tmp_path)
    proc = H.run_setup(None, "acme")
    H.assert_setup_ran(proc)
    assert proc.returncode != 0, "setup ran with no data root at all"
    assert H.DATA_ROOT_ENV in H.setup_output(proc), H.setup_output(proc)
    rec = H.Recorder(tmp_path / "run")
    said = _refused([str(alert), "--tenant", "acme"], rec)
    H.assert_verbatim(said, owner, entry="run.py main")
    assert "lifecycle" not in rec.order, "a box was started"
    assert H.census(tmp_path) == before
    if not default_existed:
        assert not retired_default.exists(), "something resolved the retired code default"


def test_data_root_moves_after_runs_exist(tmp_path, monkeypatch):
    old, new = tmp_path / "old-root", tmp_path / "new-root"
    H.set_data_root(monkeypatch, old)
    src, manifest = _sibling(tmp_path, old, "acme", monkeypatch=monkeypatch)
    (H.runs_dir(old, "acme") / CASE_X).mkdir()
    old_census = H.census(old)
    H.set_data_root(monkeypatch, new)

    alert = H.plant_alert(tmp_path / "in")
    argv = [str(alert), "--run-id", CASE_X, "--tenant", "acme"]
    _refused(argv, H.Recorder(tmp_path / "run"))

    H.place_knowledge(new, "acme")  # #1120 DC2: the operator's clone, before setup
    proc = H.run_setup(new, "acme")
    H.assert_setup_ran(proc)
    assert proc.returncode == 0, H.setup_output(proc)
    assert H.row_path(new, "acme").is_file()

    # #1187 Layout A refuses at the absent episode under the NEW root before any source read.
    with pytest.raises(FileNotFoundError) as opened:
        H.accept(new, "acme").runs_repository().episode(manifest.parent.name)
    location = opened.value
    said = _refused(H.sibling_argv(manifest, "b", "--tenant", "acme"),
                    H.Recorder(tmp_path / "sib"))
    H.assert_verbatim(said, location, entry="run.py --episode (old root)")

    got = _accepted(argv, H.Recorder(tmp_path / "run2"))
    assert got["tenant"].id == "acme"
    assert H.census(old) == old_census, "the old data root was touched"


@pytest.mark.parametrize("bad", H.REFUSED_IDS)
def test_o3_grammar_refusal_parity(tmp_path, data_root, bad):
    fresh = tmp_path / "fresh-root"
    proc = H.run_setup(fresh, bad)
    H.assert_setup_ran(proc)
    assert proc.returncode != 0, f"setup accepted {bad!r}"
    assert H.census(fresh) == {}, f"the refused setup of {bad!r} created a path"
    H.owner_refusal(H.create_tenant, fresh, bad)
    assert not fresh.exists()
    H.owner_refusal(H.TenantPaths, fresh, bad)

    H.make_tenant(data_root, H.VALID_ID)
    before = H.census(data_root)
    _refused([str(H.plant_alert(tmp_path / "in")), "--tenant", bad],
             H.Recorder(tmp_path / "run"))
    H.owner_refusal(H.require_tenant, data_root, bad)
    assert H.census(data_root) == before

    rows = tmp_path / "rows"
    H.plant_row(rows, H.VALID_ID, row_tenant_id=bad)
    reads = H.census(tmp_path)
    H.owner_refusal(H.require_tenant, rows, H.VALID_ID)
    assert H.census(tmp_path) == reads, "a refused row read wrote something"


def _confined(text: str, value: str, *, surface: str) -> None:
    """R-g_r6 (§7, human): the refused value is rendered ESCAPED (repr-style) — its escaped
    form appears, its raw control content does not, and no line of the message begins with
    text the value smuggled in."""
    escaped = repr(value)[1:-1]
    assert escaped in text, f"{surface}: the refused value is not named escaped ({escaped!r}): {text!r}"
    if "\n" in value:
        assert value not in text, f"{surface}: the raw newline-bearing value reached the text"
        forged = value.split("\n", 1)[1]
        if forged:
            assert not any(line.lstrip().startswith(forged) for line in text.splitlines()), (
                f"{surface}: the value forged a line of its own: {text!r}")


@pytest.mark.parametrize("value", H.HOSTILE_IDS)
def test_g_r6_refusal_confinement(tmp_path, data_root, value):
    _confined(str(H.owner_refusal(H.create_tenant, tmp_path / "c", value)), value,
              surface="create_tenant")
    said = _refused([str(H.plant_alert(tmp_path / "in")), "--tenant", value],
                    H.Recorder(tmp_path / "run"))
    _confined(said, value, surface="run.py main")
    proc = H.run_setup(tmp_path / "s", value)
    H.assert_setup_ran(proc)
    assert proc.returncode != 0
    _confined(H.setup_output(proc), value, surface="tenant.py setup")

    H.make_tenant(data_root, H.VALID_ID)
    base = H.runs_dir(data_root, H.VALID_ID)
    src = H.source_run(base)
    launched = H.drive_launch(src, tenant_id=value)
    assert isinstance(launched, H.branch_cli().LauncherRefused), launched
    _confined(H.refusal_text(launched), value, surface="the branch launcher")
