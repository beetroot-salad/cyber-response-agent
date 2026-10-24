"""#1084/#1110 e2e: the dev-only run-page mirror copy. Replaced by stage+rename (never truncated in place), a planted link at the page name is refused and warned, a failed copy never fails the render, and (as root) pages are written as the checkout's owner and never through a link to a root-only target."""
from __future__ import annotations

import logging
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from defender import run_common
from defender.configuration import _env
from defender.tests.e2e.test_922_renderer import MARKER, driven_run, tenant_run

pytestmark = pytest.mark.e2e

ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"
PAGE = "runtime.html"


@pytest.fixture(autouse=True)
def _dev_deployment(deployment_unset, monkeypatch):
    """Every test in this module is about the copy, which only a `dev` deployment makes (#1110 O3)."""
    monkeypatch.setenv(_env.DEPLOYMENT_ENV, "dev")


def _renderer():
    from defender.presentation import visualize_run

    return visualize_run


def _publish_root():
    from defender.configuration import publish_root

    return publish_root


def tenant_of(run):
    """The accepted `Tenant` of the run's tenant in this test's data root: what `run.py` holds and
    hands the post-run step (#1279 A4)."""
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, set_up_tenant

    return set_up_tenant(current_data_root(), run.tenant_id)


def area(root: Path, run) -> Path:
    """Where run R of tenant T is published under `root` (#1279 O2)."""
    return root / run.tenant_id / "runs" / run.run_dir.name / PAGE


def _warnings(caplog) -> list[str]:
    """Every visualization WARNING, formatted WITH its exception (if any): the
    design names what the warning must say, not whether it rides in the message or the
    attached exception."""
    fmt = logging.Formatter()
    return [fmt.format(r) for r in _warning_records(caplog)]


def _assert_warned(caplog, needle: str) -> None:
    """#1110 O5:"""
    warned = _warnings(caplog)
    assert any(needle in w for w in warned), (
        f"the copy failed silently: no WARNING names {needle!r}; warnings were {warned!r}")


def _warning_records(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno == logging.WARNING
            and r.name == "defender.presentation.visualize_run"]


def _assert_one_warning_naming_the_destination_once(caplog, dest: Path) -> str:
    """#1110 review:"""
    records = _warning_records(caplog)
    assert len(records) == 1, (
        f"expected one WARNING for the failed copy; got {[r.getMessage() for r in records]!r}")
    message = records[0].getMessage()
    assert message.count(str(dest)) == 1, (
        f"the warning names the destination {message.count(str(dest))} times, not once: "
        f"{message!r}")
    return logging.Formatter().format(records[0])


def _assert_the_errors_reason_not_its_str(message: str, type_name: str, reason: str) -> None:
    """#1110 second review:"""
    assert type_name in message, f"the warning does not name the error's type {type_name}: {message!r}"
    assert reason in message, f"the warning does not carry the error's reason {reason!r}: {message!r}"
    assert "[Errno" not in message, f"the warning carries the error's str(), not its reason: {message!r}"


def _assert_record_written(run_dir: Path) -> None:
    """#1110 O4:"""
    record = run_dir / PAGE
    assert record.is_file(), f"the page record {record} was not written"
    assert MARKER in record.read_text(encoding="utf-8"), (
        "the page record does not carry this run's own final turn")


def test_1084_an_existing_mirror_page_is_replaced_not_rewritten_in_place(
        tmp_path, run_visualizations_dir):
    """The page at the mirror is made a HARD LINK to an unrelated file before the render."""
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    folder = area(run_visualizations_dir, run).parent
    folder.mkdir(parents=True)
    bystander = tmp_path / "bystander.html"
    bystander.write_bytes(b"BYSTANDER\n")
    os.link(bystander, folder / PAGE)

    run_common.visualize(run, tenant=tenant_of(run))

    assert (folder / PAGE).read_bytes() == (run_dir / PAGE).read_bytes(), (
        "positive control: the mirror does not hold the run's page")
    assert bystander.read_bytes() == b"BYSTANDER\n", (
        "the page was written through the existing file in place, not staged and renamed")
    assert os.lstat(folder / PAGE).st_ino != os.lstat(bystander).st_ino


def test_1084_a_failed_mirror_write_is_warned_and_the_record_kept(tmp_path, monkeypatch, caplog):
    """RE-PINNED BY #1110 (O4/O5) from `..._fails_the_render`."""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"a file, not a folder\n")
    monkeypatch.setenv(ENV, str(blocker / "run-visualizations"))
    dest = area(blocker / "run-visualizations", run)
    tenant = tenant_of(run)

    caplog.set_level(logging.DEBUG)
    assert vr.publish_page(run, tenant=tenant) == "failed"
    _assert_one_warning_naming_the_destination_once(caplog, dest)
    _assert_the_errors_reason_not_its_str(
        _warning_records(caplog)[0].getMessage(), "NotADirectoryError", "Not a directory")
    caplog.clear()
    run_common.visualize(run, tenant=tenant)  # a failed copy is not a failed render: no VisualizeFailed

    _assert_record_written(run_dir)
    _assert_one_warning_naming_the_destination_once(caplog, dest)
    assert blocker.read_bytes() == b"a file, not a folder\n"

    good = tmp_path / "good"
    monkeypatch.setenv(ENV, str(good))
    caplog.clear()
    run_common.visualize(run, tenant=tenant)
    assert area(good, run).read_bytes() == (run_dir / PAGE).read_bytes()
    assert _warnings(caplog) == [], "a copy that landed was warned about"


def test_1084_a_link_at_the_page_name_is_refused_in_process_and_warned_naming_it_once(
        tmp_path, run_visualizations_dir, caplog):
    """#1110 second review, on the IN-PROCESS lane:"""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    tenant = tenant_of(run)
    root = _publish_root().publish_root()
    assert root == run_visualizations_dir, "precondition: the copy resolves to the override"
    assert os.geteuid() != 0 or os.lstat(root.parent).st_uid == 0, (
        "precondition: the copy is written in-process, not by a dropped-privilege child")
    dest = area(root, run)
    dest.parent.mkdir(parents=True)
    outside = tmp_path / "outside.html"
    outside.write_bytes(b"OUTSIDE\n")
    os.symlink(outside, dest)

    caplog.set_level(logging.DEBUG)
    assert vr.publish_page(run, tenant=tenant) == "failed"
    _assert_one_warning_naming_the_destination_once(caplog, dest)
    _assert_the_errors_reason_not_its_str(
        _warning_records(caplog)[0].getMessage(), "OSError", "refusing to replace a symlink")
    assert outside.read_bytes() == b"OUTSIDE\n", "the copy was written through the planted link"
    assert dest.is_symlink(), "the planted link was replaced"
    assert os.readlink(dest) == str(outside), "the planted link was re-aimed"

    caplog.clear()
    run_common.visualize(run, tenant=tenant)  # a refused copy is not a failed render: no VisualizeFailed
    _assert_record_written(run_dir)
    _assert_one_warning_naming_the_destination_once(caplog, dest)
    assert outside.read_bytes() == b"OUTSIDE\n", "the post-run step wrote through the link"

    dest.unlink()
    caplog.clear()
    assert vr.publish_page(run, tenant=tenant) == "copied"
    assert dest.read_bytes() == (run_dir / PAGE).read_bytes()
    assert _warning_records(caplog) == [], "a copy that landed was warned about"


root_only = pytest.mark.skipif(
    os.geteuid() != 0, reason="D5's drop-privilege lane runs only when the render runs as root")


def _non_root_ids() -> tuple[int, int]:
    try:
        pw = pwd.getpwnam("nobody")
    except KeyError:
        return 65534, 65534
    return pw.pw_uid, pw.pw_gid


@dataclass(frozen=True)
class Tree:
    """A layout a non-root uid can reach:"""
    base: Path
    checkout: Path
    uid: int
    gid: int

    @property
    def mirror(self) -> Path:
        return self.checkout / "run-visualizations"

    @property
    def root_file(self) -> Path:
        return self.base / "root-only.html"

    @property
    def root_dir(self) -> Path:
        return self.base / "root-only-dir"


@pytest.fixture
def owned_tree(monkeypatch):
    """The layout, with the override pointed at `<checkout>/run-visualizations` (so the owner the render consults..."""
    uid, gid = _non_root_ids()
    base = Path(tempfile.mkdtemp(prefix="defender-1084-", dir="/tmp"))
    try:
        os.chmod(base, 0o755)
        checkout = base / "checkout"
        checkout.mkdir()
        os.chmod(checkout, 0o755)
        os.chown(checkout, uid, gid)
        tree = Tree(base, checkout, uid, gid)
        tree.root_file.write_bytes(b"ROOT-ONLY\n")
        os.chmod(tree.root_file, 0o660)
        tree.root_dir.mkdir()
        os.chmod(tree.root_dir, 0o770)
        monkeypatch.setenv(ENV, str(tree.mirror))
        yield tree
    finally:
        shutil.rmtree(base)


def _lane_precondition(tree: Tree) -> None:
    """The drop-privilege child must be able to start at all as the uid;"""
    probe = subprocess.run(  # noqa: S603 — the interpreter itself, as the uid, doing nothing
        [sys.executable, "-I", "-c", "pass"], user=tree.uid, group=tree.gid, extra_groups=[],
        capture_output=True, text=True, encoding="utf-8", check=False)
    assert probe.returncode == 0, (
        f"infrastructure: uid {tree.uid} cannot run {sys.executable}: {probe.stderr}")


def _user_dir(path: Path, tree: Tree) -> None:
    path.mkdir()
    os.chmod(path, 0o755)
    os.chown(path, tree.uid, tree.gid)


def _owned_by(path: Path, uid: int, gid: int) -> None:
    st = os.lstat(path)
    assert (st.st_uid, st.st_gid) == (uid, gid), (
        f"{path} is owned by {st.st_uid}:{st.st_gid}, not {uid}:{gid}")


def _fingerprint(path: Path) -> tuple:
    st = os.lstat(path)
    listing = sorted(os.listdir(path)) if stat.S_ISDIR(st.st_mode) else path.read_bytes()
    return st.st_uid, st.st_gid, st.st_mode, st.st_mtime_ns, listing


@root_only
def test_1084_a_root_render_writes_the_mirror_as_the_checkouts_owner(tmp_path, owned_tree):
    """(a) The mirror's parent belongs to a non-root uid and `run-visualizations/` does not exist yet."""
    _lane_precondition(owned_tree)
    run_dir = driven_run(tmp_path)
    assert not owned_tree.mirror.exists()

    run = tenant_run(run_dir)
    run_common.visualize(run, tenant=tenant_of(run))

    page = area(owned_tree.mirror, run)
    for made in (owned_tree.mirror, page.parent.parent.parent, page.parent.parent, page.parent, page):
        _owned_by(made, owned_tree.uid, owned_tree.gid)
    assert page.read_bytes() == (run_dir / PAGE).read_bytes()
    assert MARKER in page.read_text(encoding="utf-8")


@root_only
def test_1084_a_root_render_replaces_a_root_owned_page_left_by_the_old_writer(tmp_path, owned_tree):
    """(b) Today's pages are root:root 0644 (issue C4)."""
    _lane_precondition(owned_tree)
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    stale = area(owned_tree.mirror, run)
    for folder in (owned_tree.mirror, stale.parent.parent.parent, stale.parent.parent, stale.parent):
        _user_dir(folder, owned_tree)
    stale.write_bytes(b"STALE\n")
    os.chmod(stale, 0o644)

    run_common.visualize(run, tenant=tenant_of(run))

    assert not stale.is_symlink()
    assert stale.read_bytes() == (run_dir / PAGE).read_bytes(), "the stale page was not replaced"
    _owned_by(stale, owned_tree.uid, owned_tree.gid)
    _owned_by(owned_tree.mirror, owned_tree.uid, owned_tree.gid)


@root_only
@pytest.mark.parametrize("site", ["run-visualizations", "run-visualizations/<tenant>",
                                  "run-visualizations/<tenant>/runs",
                                  "run-visualizations/<tenant>/runs/<run>",
                                  "run-visualizations/<tenant>/runs/<run>/runtime.html"])
def test_1084_a_link_planted_at_any_mirror_name_toward_a_root_only_target_is_refused_and_warned(
        tmp_path, owned_tree, site, caplog):
    """O4 — RE-PINNED BY #1110 (O4/O5) from `..._fails_the_render`."""
    _lane_precondition(owned_tree)
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    rel = site.replace("<run>", run_dir.name).replace("<tenant>", run.tenant_id)
    link = owned_tree.checkout / rel
    for parent in reversed(link.relative_to(owned_tree.checkout).parents[:-1]):
        _user_dir(owned_tree.checkout / parent, owned_tree)
    target = owned_tree.root_file if site.endswith(PAGE) else owned_tree.root_dir
    os.symlink(target, link)
    os.lchown(link, owned_tree.uid, owned_tree.gid)
    before = _fingerprint(target)

    caplog.set_level(logging.DEBUG)
    run_common.visualize(run, tenant=tenant_of(run))  # a refused copy is not a failed render: no VisualizeFailed

    _assert_record_written(run_dir)
    _assert_warned(caplog, str(area(owned_tree.mirror, run)))
    assert _fingerprint(target) == before, f"the root-only target changed through {site}"
    assert link.is_symlink(), f"the link at {site} was replaced or removed"
    assert os.readlink(link) == str(target), f"the link at {site} was re-aimed"


@root_only
@pytest.mark.parametrize("shape", ["root-owned-0755", "users-own-0555"])
def test_1084_a_mirror_folder_the_owner_cannot_write_is_left_untouched_and_warned(
        tmp_path, owned_tree, shape, caplog):
    """RE-PINNED BY #1110 (O4/O5) from `..._fails_the_render_untouched`."""
    _lane_precondition(owned_tree)
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    owned_tree.mirror.mkdir()
    if shape == "root-owned-0755":
        os.chmod(owned_tree.mirror, 0o755)
    else:
        os.chown(owned_tree.mirror, owned_tree.uid, owned_tree.gid)
        os.chmod(owned_tree.mirror, 0o555)
    before = _fingerprint(owned_tree.mirror)

    caplog.set_level(logging.DEBUG)
    run_common.visualize(run, tenant=tenant_of(run))  # a failed copy is not a failed render: no VisualizeFailed

    _assert_record_written(run_dir)
    warned = _assert_one_warning_naming_the_destination_once(
        caplog, area(owned_tree.mirror, run))
    assert "Permission denied" in warned, f"the warning does not carry the error: {warned!r}"
    assert _fingerprint(owned_tree.mirror) == before, f"the {shape} mirror folder was written"


# --------------------------------------------------------------------------------------
# #1279 O2/O4 — the dev copy lands in the run's tenant area; outside dev it is skipped


def test_1279_o2_the_dev_copy_lands_under_the_runs_tenant_area_not_the_flat_folder(
        tmp_path, run_visualizations_dir):
    """O2: on dev, run R of tenant T is copied to `<root>/<T>/runs/<R>/runtime.html` only."""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)

    assert vr.publish_page(run, tenant=tenant_of(run)) == "copied"

    dest = area(run_visualizations_dir, run)
    assert dest.is_file(), f"no copy at {dest}: {sorted(run_visualizations_dir.rglob('*'))}"
    assert dest.read_bytes() == (run_dir / PAGE).read_bytes()
    assert not (run_visualizations_dir / run_dir.name).exists(), "the copy still lands flat"
    assert [p.name for p in run_visualizations_dir.iterdir()] == [run.tenant_id]


def test_1279_o2_another_tenants_run_with_the_same_id_cannot_overwrite_or_land_in_the_first_area(
        tmp_path, data_root, run_visualizations_dir):
    """O2: tenants A and B each publish a run with one id; A's published page is untouched by B's."""
    from defender.run_repository import Run
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5
    from defender.tests.support.shared._fixture_uuid import fixture_uuid
    from defender.tests.support.shared._locations_1210 import fixture_runs_base

    vr = _renderer()
    run_a = tenant_run(driven_run(tmp_path / "a"))
    tenant_a = tenant_of(run_a)
    b_id = fixture_uuid("tenant:second-1279")
    tenant_b = H5.tenant(data_root, b_id)
    run_b_dir = driven_run(tmp_path / "b")
    run_b = Run.under(fixture_runs_base(run_b_dir.parent), run_b_dir.name, tenant_id=b_id)
    assert run_a.run_dir.name == run_b.run_dir.name, "precondition: the two runs share one id"
    planted = area(run_visualizations_dir, run_a)
    planted.parent.mkdir(parents=True)
    planted.write_bytes(b"A-SENTINEL\n")

    assert vr.publish_page(run_b, tenant=tenant_b) == "copied"

    assert planted.read_bytes() == b"A-SENTINEL\n", "B's run overwrote A's published page"
    assert area(run_visualizations_dir, run_b).read_bytes() == (run_b_dir / PAGE).read_bytes()
    assert sorted(p.name for p in run_visualizations_dir.iterdir()) == sorted([run_a.tenant_id, b_id])
    assert tenant_a.id == run_a.tenant_id


@pytest.mark.parametrize("deployment", ["production", "staging"])
def test_1279_o4_outside_dev_the_copy_is_skipped_and_the_run_page_is_still_saved(
        tmp_path, run_visualizations_dir, monkeypatch, caplog, deployment):
    """O4: no publish destination outside dev: the copy is skipped (logged, not warned), the record kept, nothing published."""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    run = tenant_run(run_dir)
    tenant = tenant_of(run)
    assert vr.publish_page(run, tenant=tenant) == "copied", "positive control: dev publishes"
    shutil.rmtree(run_visualizations_dir)
    run_visualizations_dir.mkdir()
    (run_dir / PAGE).unlink()
    monkeypatch.setenv(_env.DEPLOYMENT_ENV, deployment)
    caplog.set_level(logging.DEBUG)

    assert vr.publish_page(run, tenant=tenant) == "skipped"

    _assert_record_written(run_dir)
    assert not list(run_visualizations_dir.iterdir()), "a non-dev run published a page"
    assert _warnings(caplog) == [], "a skipped copy was warned about"
