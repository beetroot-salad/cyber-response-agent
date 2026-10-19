"""tenant.py setup: row step and refusals on a non-empty data root, re-runs, rowless own folder, alias refusal at the row."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H

O10_TEXT = "the data root is not empty"
TID = H.VALID_ID


def _refused_writing_nothing(root: Path, tenant_id: str = TID, *, names: str) -> str:
    """Run setup against `root`, and assert it REFUSED (exit 1, output naming `names`) and
    wrote nothing (the census of `root` is unchanged). Returns the setup's output."""
    before = H.census(root)
    proc = H.run_setup(root, tenant_id)
    H.assert_setup_ran(proc)
    out = H.setup_output(proc)
    assert proc.returncode == 1, f"setup exited {proc.returncode}, not 1 (refused):\n{out}"
    assert names in out, f"the refusal does not name {names!r}:\n{out}"
    assert H.census(root) == before, "the refused setup wrote into the data root"
    return out


def _verbatim_owner(out: str, root: Path, tenant_id: str = TID) -> BaseException:
    """The setup output passed `create_tenant`'s own refusal through verbatim — the owner is
    asked AFTER the process, on the same untouched root, and must refuse the same way."""
    before = H.census(root)
    owner = H.owner_refusal(H.create_tenant, root, tenant_id)
    assert H.census(root) == before, "the refusing create_tenant wrote into the data root"
    H.assert_verbatim(out, owner, entry="tenant.py setup")
    return owner


@pytest.mark.parametrize("shape", ["empty", "populated"])
def test_o10_rowless_folder_refused(tmp_path, shape):
    """Setup into a data root holding a rowless old/ folder is refused naming 'old', and writes
    nothing."""
    root = tmp_path / "data"
    (root / "old").mkdir(parents=True)
    if shape == "populated":
        (root / "old" / "runs" / "r1").mkdir(parents=True)
        (root / "old" / "runs" / "r1" / "report.md").write_text("x\n", encoding="utf-8")
    out = _refused_writing_nothing(root, names="old")
    assert O10_TEXT in out, f"the refusal is not O10's:\n{out}"
    _verbatim_owner(out, root)


@pytest.mark.parametrize("shape", ["absent", "empty", "missing-parent"])
def test_o10_fresh_root_writes_exactly_row(tmp_path, shape):
    top = tmp_path / "top"
    root = {"absent": top, "empty": top, "missing-parent": top / "a" / "b" / "c"}[shape]
    if shape == "empty":
        root.mkdir()
    H.place_knowledge(root, TID)
    before = H.census(top)
    proc = H.run_setup(root, TID)
    H.assert_setup_ran(proc)
    assert proc.returncode == 0, H.setup_output(proc)
    rel_root = root.relative_to(top).as_posix()
    prefix = "" if rel_root == "." else f"{rel_root}/"
    after = H.census(top)
    assert set(after) - set(before) == {f"{prefix}{TID}/{H.ROW_NAME}"}, (
        f"setup wrote more (or less) than the row: {sorted(set(after) - set(before))}")
    assert {k: after[k] for k in before} == before, "setup changed the placed knowledge folder"
    assert after[f"{prefix}{TID}/{H.ROW_NAME}"][0] == "file"
    row = json.loads(H.row_path(root, TID).read_text(encoding="utf-8"))
    assert row["tenant_id"] == TID


def test_setup_refuses_a_path_shaped_id_before_looking_under_the_data_root(tmp_path):
    root = tmp_path / "data"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret-name").write_text("x", encoding="utf-8")
    proc = H.run_setup(root, "../outside")
    H.assert_setup_ran(proc)
    said = H.setup_output(proc)
    assert proc.returncode == 1, said
    assert "not a valid tenant id" in said, said
    assert "secret-name" not in said, f"the refusal listed a directory outside the root: {said}"
    assert not root.exists() or list(root.iterdir()) == []
    H.place_knowledge(root, H.VALID_ID)  # #1120 DC2: the operator's clone precedes setup
    assert H.run_setup(root, H.VALID_ID).returncode == 0


def test_setup_reports_a_corrupt_row_instead_of_already_exists(tmp_path):
    """A row that is already there but corrupt is reported as what is wrong with it — the
    owner's `require_tenant` refusal, verbatim — not folded into "already exists"."""
    root = tmp_path / "data"
    H.place_knowledge(root, H.VALID_ID)  # #1120 DC2: the operator's clone precedes setup
    assert H.run_setup(root, H.VALID_ID).returncode == 0
    H.row_path(root, H.VALID_ID).write_text("{torn", encoding="utf-8")
    proc = H.run_setup(root, H.VALID_ID)
    said = H.setup_output(proc)
    assert proc.returncode == 1, said
    assert "not valid JSON" in said, said
    assert "already exists" not in said, said


def test_o10_rerun_no_second_row(tmp_path):
    """A re-run of setup with the same id, where the root's only entry is <id>/ holding a valid
    row, succeeds and leaves that row byte-identical."""
    root = tmp_path / "data"
    H.place_knowledge(root, TID)  # #1120 DC2: the operator's clone precedes setup
    first = H.run_setup(root, TID)
    H.assert_setup_ran(first)
    assert first.returncode == 0, H.setup_output(first)
    row_bytes = H.row_path(root, TID).read_bytes()
    before = H.census(root)
    again = H.run_setup(root, TID)
    assert again.returncode == 0, f"the same-id re-run was refused:\n{H.setup_output(again)}"
    assert H.row_path(root, TID).read_bytes() == row_bytes, "the re-run rewrote the row"
    assert H.census(root) == before, "the re-run wrote something"


def test_setup_re_run_after_the_tenant_already_has_runs(tmp_path):
    root = tmp_path / "data"
    H.place_knowledge(root, TID)  # #1120 DC2: the operator's clone precedes setup
    first = H.run_setup(root, TID)
    H.assert_setup_ran(first)
    assert first.returncode == 0, H.setup_output(first)
    base = H.runs_dir(root, TID)
    (base / "r1").mkdir(parents=True)
    (base / "r1" / "report.md").write_text("disposition: benign\n", encoding="utf-8")
    # #1187 R1 (review-4 F42): no runs-base record — a used tenant's runs/ holds runs only.
    H.sessions_dir(root, TID).mkdir()
    (H.sessions_dir(root, TID) / "case-1.db").write_bytes(b"SQLite format 3\x00")
    before = H.census(root)
    again = H.run_setup(root, TID)
    assert again.returncode == 0, f"a re-run over a used tenant was refused:\n{H.setup_output(again)}"
    assert H.census(root) == before, "the re-run changed something under <T>/"



def test_data_root_holds_a_dangling_symlink_entry(tmp_path):
    """A data root whose only entry is a dangling symlink: setup is refused by O10, naming the
    entry, and writes nothing."""
    root = tmp_path / "data"
    root.mkdir()
    (root / "ghost").symlink_to(tmp_path / "nowhere")
    out = _refused_writing_nothing(root, names="ghost")
    _verbatim_owner(out, root)
    assert (root / "ghost").is_symlink() and not (tmp_path / "nowhere").exists()  # noqa: PT018 — one fact: the link is left, dangling


def test_s7_j08_setup_rerun_completes_rowless_own_folder(tmp_path):
    root = tmp_path / "data"
    H.place_knowledge(root, TID)
    before = H.census(root)
    done = H.run_setup(root, TID)
    H.assert_setup_ran(done)
    assert done.returncode == 0, f"the unfinished setup was not completed:\n{H.setup_output(done)}"
    assert set(H.census(root)) == set(before) | {f"{TID}/{H.ROW_NAME}"}
    assert H.require_tenant(root, TID).tenant_id == TID

    foreign = tmp_path / "foreign-in-own"
    H.place_knowledge(foreign, TID)
    (H.tenant_dir(foreign, TID) / "runs").mkdir()
    out = _refused_writing_nothing(foreign, names=f"{TID}/runs")
    assert O10_TEXT in out, out

    other = tmp_path / "other-id"
    H.tenant_dir(other, "other").mkdir(parents=True)
    out = _refused_writing_nothing(other, names="other")
    assert O10_TEXT in out, out


@pytest.mark.parametrize("alias", ["symlink", "hardlink"])
def test_s7_j60_create_tenant_census_row_reaches_write(tmp_path, alias):
    for driver in ("owner", "setup"):
        root = tmp_path / driver / "data"
        H.tenant_dir(root, TID).mkdir(parents=True)
        target = tmp_path / driver / "outside.json"
        target.write_text("ORIGINAL OUTSIDE\n", encoding="utf-8")
        plant = H.row_path(root, TID)
        if alias == "symlink":
            plant.symlink_to(target)
        else:
            os.link(target, plant)
        before = os.lstat(target)
        if driver == "owner":
            text = str(H.owner_refusal(H.create_tenant, root, TID))
        else:
            proc = H.run_setup(root, TID)
            H.assert_setup_ran(proc)
            text = H.setup_output(proc)
            assert proc.returncode == 1, f"setup accepted a planted row alias:\n{text}"
        assert O10_TEXT not in text, (
            f"O10 short-circuited the plant ({driver}); the guarded write was never reached:\n"
            f"{text}")
        assert target.read_text(encoding="utf-8") == "ORIGINAL OUTSIDE\n", (
            f"the {alias} plant was written through ({driver})")
        assert os.lstat(target).st_mtime_ns == before.st_mtime_ns
        assert os.path.lexists(plant), "the refusal removed the plant (sanitizing, D1)"

    control = tmp_path / "control" / "data"
    H.tenant_dir(control, TID).mkdir(parents=True)
    assert H.create_tenant(control, TID).tenant_id == TID
    assert not H.row_path(control, TID).is_symlink()
