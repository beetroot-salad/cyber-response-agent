"""#1078 pass (A) — `run.py main`, the request's front door (D3, O1, O2, O5, O6's argv half).

Every scenario drives the REAL `main` through its own injection seams (`_spec1078.Recorder`:
`preflight=`, `materialize=`, `lifecycle=`, `visualize=`, `enqueue=`), which record what they
are handed and inject nothing. "Refused before anything is spent" is therefore an
observation — the recorder saw no preflight (the model-key step), no materialize (the run dir)
and no lifecycle (the box) — never an inspection of a flag. "Refused by X" is the entry's
refusal text containing the owner's OWN refusal of the same input, verbatim (demand #0's rule,
§7 F0/J29).

The setup halves (s003, s004, s008, s009, o3's setup cell, g_r6's setup output) run the
operator's own command as a process (`_spec1078.run_setup`). The sibling scenarios build a
source run AT A TENANT LOCATION (`<root>/<T>/runs/<run>` with the runs-base record naming T)
and an episode manifest naming it, outside the data root — pass (A)'s fork layout (episodes
stay under the old episodes base until (B)).
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.tests import _spec791
from defender.tests import _triplet_947 as T
from defender.tests.tenant_1078_pass_a import _spec1078 as H

#: `_Investigate`'s parameters at base ed5386bc (run.py:230-233) — D3: "The `materialize` seam
#: gains `tenant_id`; `_Investigate` does not."
INVESTIGATE_PARAMS = ["self", "alert_path", "run_dir", "run_id", "defender_dir", "model_name",
                      "model_override", "box", "world"]


# ======================================================================================
# cluster helpers
# ======================================================================================

def _main(argv: list[str], rec: H.Recorder, **override: Any) -> tuple[Any, BaseException | None]:
    """`H.drive_main`, with one seam replaced (a failing preflight, say)."""
    seams = {**rec.seams(), **override}
    try:
        return H.run_py().main(argv, **seams), None
    except SystemExit as refused:
        return None, refused


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


def _sibling(tmp_path: Path, root: Path, tenant_id: str = H.VALID_ID, *,
             record: str | None = "same", row: bool = True) -> tuple[Path, Path]:
    """A source run at T's tenant location plus an episode manifest naming it (outside the data
    root). Returns (source run dir, manifest)."""
    _base, src = H.tenant_source(root, tenant_id, record=record, row=row)
    manifest = H.family_for(src, tmp_path / "episodes" / T.EPISODE_ID)
    return src, manifest


def _stamp_tenant(run_dir: Path, tenant_id: str) -> None:
    """Rewrite the run's provenance stamp to carry `tenant_id` — the box-writable file (C7)."""
    stamp = run_dir / "provenance.json"
    doc = json.loads(stamp.read_text(encoding="utf-8"))
    doc["tenant_id"] = tenant_id
    stamp.write_text(json.dumps(doc), encoding="utf-8")


# ======================================================================================
# O1 — every run names its tenant; there is no default
# ======================================================================================

def test_o1_fresh_run_without_tenant_refused(tmp_path, data_root, capsys):
    """run.py main given an alert and no --tenant (and no --resume) exits with a refusal, and
    the injected preflight and materialize seams are never called, so no run dir, box or model
    call exists.

    The positive control is the same argv with `--tenant` naming an existing tenant, which
    reaches materialize: the refusal is about the tenant, not the alert."""
    alert = H.plant_alert(tmp_path / "in")
    before = H.census(data_root)
    said = _refused([str(alert)], H.Recorder(tmp_path / "run"), capsys)
    assert "--tenant" in said, f"the refusal does not name the missing --tenant: {said!r}"
    assert H.census(data_root) == before
    assert not (tmp_path / "run").exists()
    H.make_tenant(data_root, H.VALID_ID)
    got = _accepted([str(alert), "--tenant", H.VALID_ID], H.Recorder(tmp_path / "run2"))
    assert got["tenant_id"] == H.VALID_ID


def test_o1_run_id_resume_without_tenant_refused(tmp_path, data_root, capsys):
    """run.py main given --run-id X and no --tenant is refused before the preflight and
    materialize, exactly as a fresh run is.

    Even with a setup-only run dir already under T's runs base for that id: the operator must
    name the tenant to resume it (O6), and nothing is a default."""
    H.make_tenant(data_root, H.VALID_ID)
    (H.runs_dir(data_root, H.VALID_ID) / "case-x").mkdir(parents=True)
    alert = H.plant_alert(tmp_path / "in")
    before = H.census(data_root)
    said = _refused([str(alert), "--run-id", "case-x"], H.Recorder(tmp_path / "run"), capsys)
    assert "--tenant" in said, f"the refusal does not name the missing --tenant: {said!r}"
    assert H.census(data_root) == before


def test_fresh_run_order(tmp_path, data_root):
    """For a fresh run, main checks the --tenant grammar, then require_tenant, both before the
    preflight; materialize is reached only after the preflight passes.

    Four arms on one argv shape: an off-grammar id meets the GRAMMAR refusal (not the absent
    row's, though its row is absent too); a well-formed id with no row meets require_tenant's
    own refusal; an existing tenant with a failing preflight never reaches materialize; and the
    passing preflight reaches it, in that order."""
    alert = H.plant_alert(tmp_path / "in")
    grammar = H.owner_refusal(H.tenant().refuse_bad_tenant_id, "Acme")
    said = _refused([str(alert), "--tenant", "Acme"], H.Recorder(tmp_path / "r1"))
    H.assert_verbatim(said, grammar, entry="run.py main (grammar first)")

    absent_row = H.owner_refusal(H.require_tenant, H.resolve_data_root(), "acme")
    said = _refused([str(alert), "--tenant", "acme"], H.Recorder(tmp_path / "r2"))
    H.assert_verbatim(said, absent_row, entry="run.py main (require_tenant second)")

    H.make_tenant(data_root, "acme")
    rec = H.Recorder(tmp_path / "r3")
    rc, refused = _main([str(alert), "--tenant", "acme"], rec,
                        preflight=lambda _m=None: rec.order.append("preflight") or 2)
    assert refused is None, f"a failing preflight was reported as a refusal: {refused!r}"
    assert rc == 2, f"a failing preflight did not stop the run ({rc})"
    assert rec.order == ["preflight"], f"materialize ran after a failed preflight: {rec.order}"

    rec = H.Recorder(tmp_path / "r4")
    _accepted([str(alert), "--tenant", "acme"], rec)
    assert rec.order[:3] == ["preflight", "materialize", "lifecycle"], rec.order


# ======================================================================================
# O2 — only an existing tenant runs
# ======================================================================================

def test_o2_unknown_tenant_refused_writes_nothing(tmp_path, data_root):
    """run.py main --tenant acme, well-formed but with no row, is refused and the data root's
    tree is identical before and after (no runs/, no sessions/, no row); the preflight and
    materialize are never called.

    Refused by require_tenant: the exit carries its refusal verbatim. The positive control:
    once `acme` is created, the same argv reaches materialize."""
    alert = H.plant_alert(tmp_path / "in")
    before = H.census(data_root)
    said = _refused([str(alert), "--tenant", "acme"], H.Recorder(tmp_path / "run"))
    assert H.census(data_root) == before, "the refused run wrote under the data root"
    assert not (data_root / "acme").exists()
    H.assert_verbatim(said, H.owner_refusal(H.require_tenant, H.resolve_data_root(), "acme"),
                      entry="run.py main")
    H.make_tenant(data_root, "acme")
    assert _accepted([str(alert), "--tenant", "acme"],
                     H.Recorder(tmp_path / "run2"))["tenant_id"] == "acme"


def test_o2_existing_tenant_runs(tmp_path, data_root):
    """With T created by create_tenant, run.py main --tenant T passes require_tenant and
    reaches materialize with T as its tenant_id keyword."""
    H.make_tenant(data_root, "acme")
    alert = H.plant_alert(tmp_path / "in")
    rec = H.Recorder(tmp_path / "run")
    got = _accepted([str(alert), "--tenant", "acme"], rec)
    assert got["tenant_id"] == "acme"
    assert rec.order.index("preflight") < rec.order.index("materialize")


def test_d3_materialize_seam_tenant(tmp_path, data_root):
    """main calls the materialize seam with T as its tenant_id keyword argument;
    _Investigate's parameters are unchanged.

    For a fresh run AND for a `--resume` sibling (whose T is derived, not given): the seam is
    handed the tenant by keyword. `_Investigate` gains no tenant parameter — everything it
    drives follows from `run_dir` (C24, C29)."""
    H.make_tenant(data_root, H.VALID_ID)
    alert = H.plant_alert(tmp_path / "in")
    fresh = _accepted([str(alert), "--tenant", H.VALID_ID], H.Recorder(tmp_path / "run"))
    assert "tenant_id" in fresh, f"materialize was not handed tenant_id by keyword: {fresh}"
    assert fresh["tenant_id"] == H.VALID_ID, fresh

    base = H.runs_dir(data_root, H.VALID_ID)
    H.plant_record(base, H.VALID_ID)
    src = H.source_run(base)
    manifest = H.family_for(src, tmp_path / "episodes" / T.EPISODE_ID)
    sibling = _accepted(H.resume_argv(manifest), H.Recorder(tmp_path / "sib"))
    assert sibling.get("tenant_id") == H.VALID_ID, sibling

    params = list(inspect.signature(H.run_py()._Investigate.__call__).parameters)
    assert params == INVESTIGATE_PARAMS, f"_Investigate's parameters changed: {params}"


# ======================================================================================
# O5 — a fork keeps its tenant, learnt from the host-only record
# ======================================================================================

def test_o5_sibling_tenant_from_record(tmp_path, data_root):
    """A sibling launched from <root>/T/runs/r1, whose runs-base record and stamp both carry
    T, runs under T: its materialize receives T as its tenant_id."""
    src, manifest = _sibling(tmp_path, data_root, "acme")
    _stamp_tenant(src, "acme")
    got = _accepted(H.resume_argv(manifest), H.Recorder(tmp_path / "sib"))
    assert got["tenant_id"] == "acme"


def test_o5_forged_stamp_ignored(tmp_path, data_root):
    """With the source run's provenance.json rewritten to name tenant U, the sibling still
    runs under T.

    U is made a REAL tenant (a hand-made second row, which N13 says nothing refuses), so a
    sibling that read its tenant off the box-writable stamp would run — under U. The positive
    control is `test_o5_sibling_tenant_from_record`: the same launch with an honest stamp."""
    src, manifest = _sibling(tmp_path, data_root, "acme")
    H.plant_row(data_root, "victim")
    _stamp_tenant(src, "victim")
    got = _accepted(H.resume_argv(manifest), H.Recorder(tmp_path / "sib"))
    assert got["tenant_id"] == "acme", f"the sibling took its tenant from the stamp: {got}"


def test_o5_disagreeing_tenant_refused(tmp_path, data_root):
    """run.py --resume <manifest> --world L --tenant U, where the source derives T != U, is
    refused before the preflight and materialize.

    U exists (a hand-made row), so the refusal is the disagreement, not an unknown tenant; the
    refusal is a '[run.py] ...' exit naming the refused U. The control: `--tenant T` (agreeing)
    is accepted and runs under T."""
    src, manifest = _sibling(tmp_path, data_root, "acme")
    H.plant_row(data_root, "victim")
    said = _refused(H.resume_argv(manifest, "b", "--tenant", "victim"),
                    H.Recorder(tmp_path / "sib"))
    assert said.startswith("[run.py] "), f"not a '[run.py] ...' refusal: {said!r}"
    assert "victim" in said, f"the refusal does not name the disagreeing --tenant: {said!r}"
    got = _accepted(H.resume_argv(manifest, "b", "--tenant", "acme"),
                    H.Recorder(tmp_path / "sib2"))
    assert got["tenant_id"] == "acme"


def test_o5_resume_without_tenant_derives(tmp_path, data_root):
    """run.py --resume with no --tenant is accepted and runs under the T that
    tenant_of_run_dir(family.source_run_dir) derives."""
    src, manifest = _sibling(tmp_path, data_root, "acme-corp")
    derived = H.tenant_of_run_dir(src)
    assert derived == "acme-corp"
    got = _accepted(H.resume_argv(manifest), H.Recorder(tmp_path / "sib"))
    assert got["tenant_id"] == derived


def test_resume_flag_combined_with_run_id_and_tenant(tmp_path, data_root):
    """`run.py --resume <manifest> --world a --run-id X --tenant T`: the tenant checks are D3's
    (T derived from the source; --tenant must equal it); --run-id handling is unchanged from
    today (the resume path takes the sibling's id from the manifest)."""
    src, manifest = _sibling(tmp_path, data_root, "acme")
    H.plant_row(data_root, "victim")
    world_run_id = H.run_py().resume_world(manifest, "a").run_id
    got = _accepted(H.resume_argv(manifest, "a", "--run-id", "case-x", "--tenant", "acme"),
                    H.Recorder(tmp_path / "sib"))
    assert got["tenant_id"] == "acme"
    assert got["run_id"] == world_run_id, (
        f"the resume path took --run-id over the manifest's sibling id: {got['run_id']!r}")
    _refused(H.resume_argv(manifest, "a", "--run-id", "case-x", "--tenant", "victim"),
             H.Recorder(tmp_path / "sib2"))


def test_launch_whose_source_row_disappears_before_the_siblings_start(tmp_path, data_root):
    """A row that becomes unreadable after the launcher's own derivation: every sibling
    refuses at its own derivation (require_tenant) and none materializes; the
    already-prepared episode dir may remain."""
    src, manifest = _sibling(tmp_path, data_root, "acme")
    assert H.tenant_of_run_dir(src) == "acme", "the launcher's own derivation must pass first"
    H.row_path(data_root, "acme").write_text("{torn", encoding="utf-8")
    owner = H.owner_refusal(H.require_tenant, H.resolve_data_root(), "acme")
    for world in ("a", "b", "c"):
        said = _refused(H.resume_argv(manifest, world), H.Recorder(tmp_path / f"sib-{world}"))
        H.assert_verbatim(said, owner, entry=f"sibling {world}")
    assert manifest.is_file(), "the prepared episode dir is not the sibling's to remove"


def test_s7_j42_resume_manifest_resolved_at_entry(tmp_path, data_root, monkeypatch):
    """run.py --resume given a relative or symlinked manifest path resolves it at entry,
    before deriving episode_dir, so the sibling's runs base is the same absolute
    EpisodePaths(ep).runs whatever the invoking cwd.

    Observed on what the materialize seam is handed: the world's `episode_dir`, the root
    `materialize_run_dir`'s sibling arm derives `EpisodePaths(world.episode_dir).runs` from."""
    _src, manifest = _sibling(tmp_path, data_root, "acme")
    episode = manifest.parent.resolve()
    expected_runs = H.S.EpisodePaths(episode).runs
    link = tmp_path / "episodes-link"
    link.symlink_to(manifest.parent.parent, target_is_directory=True)
    monkeypatch.chdir(tmp_path)
    for spelling in (Path("episodes") / T.EPISODE_ID / "family.yaml",
                     link / T.EPISODE_ID / "family.yaml"):
        got = _accepted(H.resume_argv(spelling), H.Recorder(tmp_path / "sib" / spelling.name))
        world = got["world"]
        assert Path(world.episode_dir).is_absolute(), f"{spelling}: {world.episode_dir}"
        assert Path(world.episode_dir) == episode, (
            f"{spelling}: the manifest was not resolved at entry ({world.episode_dir})")
        assert H.S.EpisodePaths(world.episode_dir).runs == expected_runs


# ======================================================================================
# The data root seen from the request (settled s003/s004/s008/s009/s040/s042)
# ======================================================================================

def test_setup_shell_and_run_shell_resolve_different_data_roots(tmp_path, monkeypatch):
    """A fresh run whose shell resolves a data root holding no row for T is refused by O2
    before anything is spent (no run dir, no box, no model call), and nothing is written under
    either root. Naming the resolved root in the message is not demanded."""
    setup_root, run_root = tmp_path / "setup-root", tmp_path / "run-root"
    run_root.mkdir()
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
    """DEFENDER_DATA_ROOT naming an existing regular file: setup and a fresh run both fail
    non-zero and write nothing anywhere. The refusal's shape rides F0 / J11 (#5)."""
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
    """A shell that never received the compose variable has DEFENDER_DATA_ROOT unset, so
    resolve_data_root refuses, naming the variable, for setup and for the run alike
    (consistent with d2_data_root_default); nothing is written and no box is started. There
    is no code default to resolve."""
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
    """After the data root moves: a fork of a run under the old root is refused by location
    (O5); `--run-id X --tenant T` under the new root is refused by O2 until setup has run
    there; setup into the new, empty root creates the row (O10); the old root's runs are
    neither read, moved nor cleaned (N13: a second data root is unsupported)."""
    old, new = tmp_path / "old-root", tmp_path / "new-root"
    H.set_data_root(monkeypatch, old)
    src, manifest = _sibling(tmp_path, old, "acme")
    (H.runs_dir(old, "acme") / "case-x").mkdir()
    old_census = H.census(old)
    H.set_data_root(monkeypatch, new)

    location = H.owner_refusal(H.tenant_of_run_dir, src)
    said = _refused(H.resume_argv(manifest), H.Recorder(tmp_path / "sib"))
    H.assert_verbatim(said, location, entry="run.py --resume (old root)")

    alert = H.plant_alert(tmp_path / "in")
    argv = [str(alert), "--run-id", "case-x", "--tenant", "acme"]
    _refused(argv, H.Recorder(tmp_path / "run"))

    proc = H.run_setup(new, "acme")
    H.assert_setup_ran(proc)
    assert proc.returncode == 0, H.setup_output(proc)
    assert H.row_path(new, "acme").is_file()
    got = _accepted(argv, H.Recorder(tmp_path / "run2"))
    assert got["tenant_id"] == "acme"
    assert H.census(old) == old_census, "the old data root was touched"


def test_unknown_tenant_with_a_pinned_run_id(tmp_path, data_root):
    """`--run-id X --tenant acme` with no row, but a hand-made <root>/acme/runs/X/: refused by
    O2 before materialize; nothing under acme/ is read, written or changed."""
    (H.runs_dir(data_root, "acme") / "case-x").mkdir(parents=True)
    (H.runs_dir(data_root, "acme") / "case-x" / "alert.json").write_text("{}", encoding="utf-8")
    before = H.census(data_root / "acme")
    said = _refused([str(H.plant_alert(tmp_path / "in")), "--run-id", "case-x",
                     "--tenant", "acme"], H.Recorder(tmp_path / "run"))
    H.assert_verbatim(said, H.owner_refusal(H.require_tenant, H.resolve_data_root(), "acme"),
                      entry="run.py main")
    assert H.census(data_root / "acme") == before


def test_tenant_grammar_vs_data_root_validity_order(tmp_path, monkeypatch):
    """An off-grammar --tenant together with a relative DEFENDER_DATA_ROOT: the operator sees
    the grammar refusal (Flows, fresh run: grammar first), and nothing is written."""
    monkeypatch.chdir(tmp_path)
    H.set_data_root(monkeypatch, "relative/root")
    alert = H.plant_alert(tmp_path / "in")
    before = H.census(tmp_path)
    grammar = H.owner_refusal(H.tenant().refuse_bad_tenant_id, "../x")
    said = _refused([str(alert), "--tenant", "../x"], H.Recorder(tmp_path / "run"))
    H.assert_verbatim(said, grammar, entry="run.py main")
    assert H.census(tmp_path) == before


# ======================================================================================
# s105 — the argv-driven tail tests supply --tenant
# ======================================================================================

def test_argv_driven_tail_tests_without_tenant(tmp_path, data_root):
    """_spec791.drive_tail and the direct parse_args/main callers supply --tenant and the D9
    tenant; without it they are refused by O1.

    `drive_tail` is driven over a recording stand-in for `main` (same tail seam), so what it
    HANDS the entry point is observed: `--tenant <D9 tenant>`, whose row exists in this test's
    own data root. The same argv without `--tenant`, handed to the real `main`, is refused
    before anything is spent."""
    seen: dict[str, Any] = {}

    def main(argv, *, lifecycle=None, visualize=None, ticket_writer=None):
        seen["argv"] = list(argv)
        return 0

    alert = H.plant_alert(tmp_path / "in")
    tail = SimpleNamespace(lifecycle=None, visualize=None)
    assert _spec791.drive_tail(main, alert, tail, "--no-learn") == 0
    argv = seen["argv"]
    assert "--tenant" in argv, f"drive_tail hands main no --tenant: {argv}"
    tenant_id = argv[argv.index("--tenant") + 1]
    assert H.require_tenant(data_root, tenant_id).tenant_id == tenant_id
    H.run_py().parse_args([str(alert), "--tenant", tenant_id])  # the direct parser caller's argv
    stripped = [a for i, a in enumerate(argv)
                if a != "--tenant" and (i == 0 or argv[i - 1] != "--tenant")]
    _refused(stripped, H.Recorder(tmp_path / "run"))


# ======================================================================================
# O3 parity and the refusal's confinement (g_r6)
# ======================================================================================

@pytest.mark.parametrize("bad", H.REFUSED_IDS)
def test_o3_grammar_refusal_parity(tmp_path, data_root, bad):
    """Each of '../x', 'A', 'a/b', '', a 64-character id, a leading digit ('1abc') and
    'acme\\n' is refused at tenant.py setup and create_tenant, at run.py main --tenant, at
    every record read (the tenant row and the runs-base record), and by the TenantPaths
    constructor, and no refusal creates a path.

    The record reads are real bytes on disk: a row and a runs-base record whose `tenant_id`
    field carries the refused id (at ed5386bc a runs-base record's `tenant_id` of `../../x`
    reads back unchallenged, C23)."""
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
    H.owner_refusal(H.require_tenant, rows, H.VALID_ID)
    base = H.runs_dir(data_root, H.VALID_ID)
    H.plant_record(base, bad)
    (base / "r1").mkdir()
    reads = H.census(tmp_path)
    H.owner_refusal(H.tenant_of_run_dir, base / "r1")
    H.owner_refusal(H.ensure_runs_base_record, base, H.VALID_ID)
    assert H.census(tmp_path) == reads, "a refused record read wrote something"


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
    """A refusal raised for an off-grammar tenant_id that contains a newline, a path separator
    or other control content (the R3/R4 'trailing-newline', '../x', 'a/b' members) names the
    value in its message without letting that value forge a second refusal-shaped line or
    otherwise corrupt the message's own structure; the same holds for tenant.setup's exit
    output.

    Four surfaces (§7 R-g_r6): create_tenant's refusal, `run.py main --tenant`'s exit,
    `tenant.py setup`'s output, and the branch launcher's refusal of a source whose runs-base
    record carries the value (the launcher takes no --tenant; its tenant comes off the
    record)."""
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
    H.plant_record(base, value)
    src = H.source_run(base)
    launched = H.drive_launch(src)
    assert isinstance(launched, H.branch_cli().LauncherRefused), launched
    _confined(H.refusal_text(launched), value, surface="the branch launcher")
