"""#1084 — the run-page mirror, driven end to end over a REAL run.

Every test here renders a run dir produced by the replay harness (`test_922_renderer.
driven_run`: one hermetic run whose final turn is `MARKER`), through the production entry
point `run_common.visualize` (the subprocess hop `run.py` takes) or, where the in-process
return value is the thing pinned, `visualize_run.render_and_mirror` / `main`.

- O2: a render writes nothing under `defender/` (a before/after snapshot of this checkout's
  `defender/` tree is identical), and the page is at `<override>/<run>/runtime.html`,
  byte-identical to the run's own page.
- M2: an existing mirror page is REPLACED (stage + rename), never truncated in place; a failed
  mirror write fails the render.
- M3: `main` prints the mirror's ABSOLUTE path, so an override outside the running checkout
  does not crash the render.
- O3: a render under pytest with the override removed is refused, in-process and in the child.
- D5/O1/O4 (root only): with the mirror's parent owned by a non-root uid, every path the render
  creates belongs to that uid; a link the user could plant at any of the three names, aimed at
  a root-only target, fails the render and leaves the target untouched.

The renderer is imported inside each test, so this file collects against the tree that does
not have the new names yet.
"""
from __future__ import annotations

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

from defender import _git, run_common
from defender.tests.e2e.test_922_renderer import MARKER, driven_run

pytestmark = pytest.mark.e2e

ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"
PAGE = "runtime.html"
#: Not part of the checkout's content: the venv (a symlink in a worktree), bytecode the child
#: interpreter compiles as it imports, and tool caches. Pruned — neither descended nor recorded.
_NOT_CONTENT = frozenset({".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"})


def _renderer():
    from defender.scripts.visualize import visualize_run

    return visualize_run


def _under(path: Path, root: Path) -> bool:
    return path.resolve().is_relative_to(root.resolve())


def _defender_snapshot() -> dict[str, tuple[int, int] | None]:
    """This checkout's `defender/` tree: every FILE with (size, mtime_ns), every DIRECTORY by
    its presence. Directory mtimes are left out on purpose: the render's child interpreter may
    create a `__pycache__/` beside a module it compiles, which bumps the parent's mtime without
    the render having written anything a reader would call content."""
    root = run_common.DEFENDER_DIR
    out: dict[str, tuple[int, int] | None] = {}
    for here, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _NOT_CONTENT]
        for d in dirs:
            out[str((Path(here) / d).relative_to(root))] = None
        for f in files:
            p = Path(here) / f
            st = p.lstat()
            out[str(p.relative_to(root))] = (st.st_size, st.st_mtime_ns)
    return out


# ---------------------------------------------------------------------------------------
# O2 — nothing under defender/; the page at the override
# ---------------------------------------------------------------------------------------


def _main_checkout_by_git() -> Path:
    """The real main checkout, from git itself — independent of the resolver under test, and
    of the per-test override that would otherwise answer for it."""
    try:
        return Path(_git.git(["rev-parse", "--path-format=absolute", "--git-common-dir"],
                             cwd=run_common.REPO_ROOT).strip()).parent
    except (_git.GitError, OSError):
        return run_common.REPO_ROOT


def _stray_state(page: Path) -> tuple | None:
    """What sits at a real checkout's mirror page name — compared, not required absent, since
    an operator's own pages may already be there. Ignored by git, so `git status` can't see it."""
    try:
        st = os.lstat(page)
    except FileNotFoundError:
        return None
    return st.st_ino, st.st_mtime_ns, st.st_size


def test_1084_a_render_writes_nothing_under_defender_and_mirrors_into_the_override(
        tmp_path, run_visualizations_dir):
    """A snapshot of this checkout's `defender/` taken immediately before and after
    `run_common.visualize(run_dir)` is identical — no mirror folder, no page, no touched file —
    with the D4 override pointing at a per-test tmp dir (the conftest's).

    Positive control on the new address: the page is at
    `<override>/<run_dir.name>/runtime.html`, byte-identical to `run_dir/runtime.html` and
    carrying the run's own final turn — so an empty diff is not a render that wrote nothing.
    """
    run_dir = driven_run(tmp_path)
    assert not _under(run_dir, run_common.DEFENDER_DIR), (
        "precondition: the run dir must not sit under defender/, or its own writes would be "
        "in the snapshot")
    mirrored = run_visualizations_dir / run_dir.name / PAGE
    assert not mirrored.exists(), "precondition: a stale page at the override"
    strays = [root / "run-visualizations" / run_dir.name / PAGE
              for root in (run_common.REPO_ROOT, _main_checkout_by_git())]
    strays_before = [_stray_state(p) for p in strays]
    before = _defender_snapshot()
    assert "run.py" in before, "positive control: the snapshot is not reading defender/"
    assert len(before) > 100, "positive control: the snapshot is not reading defender/"

    run_common.visualize(run_dir)

    after = _defender_snapshot()
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    assert changed == [], f"the render wrote under defender/: {changed}"
    assert [_stray_state(p) for p in strays] == strays_before, (
        "the render also wrote a copy at a real checkout's top-level mirror, bypassing the "
        "override (#1084 adversary H3)")
    assert mirrored.is_file(), f"no mirrored page at {mirrored}"
    page = (run_dir / PAGE).read_bytes()
    assert mirrored.read_bytes() == page, "the mirror is not the run's page"
    assert MARKER in page.decode("utf-8"), "the page does not carry this run's own final turn"


def test_1084_render_and_mirror_returns_the_path_under_mirror_root(tmp_path, run_visualizations_dir):
    """In-process, `render_and_mirror(run_dir)` keeps its signature and returns exactly
    `[mirror_root() / run_dir.name / "runtime.html"]` — here the override's page — and that
    file holds the run's page."""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    expected = vr.mirror_root() / run_dir.name / PAGE
    assert expected == run_visualizations_dir / run_dir.name / PAGE

    assert vr.render_and_mirror(run_dir) == [expected]
    assert expected.read_bytes() == (run_dir / PAGE).read_bytes()


# ---------------------------------------------------------------------------------------
# M2 — replace, never truncate in place; a failed mirror write fails the render
# ---------------------------------------------------------------------------------------


def test_1084_an_existing_mirror_page_is_replaced_not_rewritten_in_place(
        tmp_path, run_visualizations_dir):
    """The page at the mirror is made a HARD LINK to an unrelated file before the render. A
    stage-then-rename writer swaps the name to a new inode and the other file keeps its bytes;
    an open-truncate-write (`shutil.copyfile`, today's writer) writes the page INTO that other
    file. Positive control: the mirror name does end up holding the run's page."""
    run_dir = driven_run(tmp_path)
    folder = run_visualizations_dir / run_dir.name
    folder.mkdir()
    bystander = tmp_path / "bystander.html"
    bystander.write_bytes(b"BYSTANDER\n")
    os.link(bystander, folder / PAGE)

    run_common.visualize(run_dir)

    assert (folder / PAGE).read_bytes() == (run_dir / PAGE).read_bytes(), (
        "positive control: the mirror does not hold the run's page")
    assert bystander.read_bytes() == b"BYSTANDER\n", (
        "the page was written through the existing file in place, not staged and renamed")
    assert os.lstat(folder / PAGE).st_ino != os.lstat(bystander).st_ino


def test_1084_a_failed_mirror_write_fails_the_render(tmp_path, monkeypatch):
    """The override is placed under a regular FILE, so no folder can be created there. The
    in-process `render_and_mirror` raises an `OSError` out, and `run_common.visualize` raises
    `VisualizeFailed` (the child exits non-zero) — a mirror that silently did not happen is
    not a successful render. Positive control on the same run: pointed at a writable dir,
    the same call succeeds and the page lands."""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"a file, not a folder\n")
    monkeypatch.setenv(ENV, str(blocker / "run-visualizations"))

    with pytest.raises(OSError):  # noqa: PT011 — the interface binds that it raises, not its words
        vr.render_and_mirror(run_dir)
    with pytest.raises(run_common.VisualizeFailed):
        run_common.visualize(run_dir)
    assert blocker.read_bytes() == b"a file, not a folder\n"

    good = tmp_path / "good"
    monkeypatch.setenv(ENV, str(good))
    run_common.visualize(run_dir)
    assert (good / run_dir.name / PAGE).read_bytes() == (run_dir / PAGE).read_bytes()


def test_1084_a_mirror_write_that_fails_after_its_folder_exists_fails_the_render(
        tmp_path, run_visualizations_dir):
    """The fault is past the mkdir: the page NAME is a non-empty directory, so creating the
    folders succeeds and only the final replace can fail — even as root. A writer that
    swallows a fault around the stage/replace (#1084 adversary H4) passes the mkdir-only case
    above and fails here. Positive control: with the name cleared, the same render lands."""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    occupied = run_visualizations_dir / run_dir.name / PAGE
    occupied.mkdir(parents=True)
    (occupied / "keep").write_bytes(b"KEEP\n")

    with pytest.raises(OSError):  # noqa: PT011 — the interface binds that it raises, not its words
        vr.render_and_mirror(run_dir)
    with pytest.raises(run_common.VisualizeFailed):
        run_common.visualize(run_dir)
    assert (occupied / "keep").read_bytes() == b"KEEP\n"

    shutil.rmtree(occupied)
    run_common.visualize(run_dir)
    assert occupied.read_bytes() == (run_dir / PAGE).read_bytes()


# ---------------------------------------------------------------------------------------
# M3 — the absolute path is printed; an outside override does not crash the render
# ---------------------------------------------------------------------------------------


def test_1084_the_render_names_the_mirror_by_its_absolute_path(tmp_path, capfd, monkeypatch):
    """With the override OUTSIDE the running checkout, `run_common.visualize` succeeds (a
    `dest.relative_to(<repo>)` would raise `ValueError` in the child and surface as
    `VisualizeFailed`) and the child's stdout — forwarded to stderr — names the mirror's
    absolute path. The in-process `main` prints the same absolute path on its own stdout."""
    run_dir = driven_run(tmp_path)
    outside = tmp_path / "pages"
    assert not _under(outside, run_common.REPO_ROOT), "precondition: outside the checkout"
    monkeypatch.setenv(ENV, str(outside))
    mirrored = outside / run_dir.name / PAGE
    assert mirrored.is_absolute()
    capfd.readouterr()

    run_common.visualize(run_dir)
    forwarded = capfd.readouterr().err
    assert str(mirrored) in forwarded, f"the render did not name {mirrored}: {forwarded!r}"
    assert mirrored.is_file()

    assert _renderer().main(["visualize_run.py", str(run_dir)]) == 0
    printed = capfd.readouterr().out
    assert str(mirrored) in printed, f"main did not print {mirrored}: {printed!r}"


# ---------------------------------------------------------------------------------------
# O3 — the detector bites a render, not only the bare resolver
# ---------------------------------------------------------------------------------------


def test_1084_a_render_under_pytest_without_the_override_is_refused(
        tmp_path, monkeypatch, run_visualizations_dir):
    """With the override removed, `render_and_mirror` raises `MirrorRootRefused` in-process,
    and the child `run_common.visualize` spawns (which inherits `PYTEST_CURRENT_TEST`) fails
    with `VisualizeFailed` — so the renderer reaches the refusing default resolution, not a
    `start` passed explicitly around it. The bare resolver is asked first, so a resolver that
    does not refuse stops the test before any render could reach a real checkout.

    Positive control: the override restored, the same run renders into it."""
    vr = _renderer()
    run_dir = driven_run(tmp_path)
    monkeypatch.delenv(ENV)
    with pytest.raises(vr.MirrorRootRefused):
        vr.mirror_root()

    with pytest.raises(vr.MirrorRootRefused):
        vr.render_and_mirror(run_dir)
    with pytest.raises(run_common.VisualizeFailed):
        run_common.visualize(run_dir)

    monkeypatch.setenv(ENV, str(run_visualizations_dir))
    run_common.visualize(run_dir)
    assert (run_visualizations_dir / run_dir.name / PAGE).is_file()


# ---------------------------------------------------------------------------------------
# D5 / O1 / O4 — written as the owner (root only)
# ---------------------------------------------------------------------------------------

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
    """A layout a non-root uid can reach: `base` (root, 0755, under /tmp — pytest's tmp base
    is 0700 and no other uid can traverse it) holding `checkout` (the mirror's parent, owned
    by the uid unless a test says otherwise) and two root-only TARGETS outside it."""
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
    """The layout, with the override pointed at `<checkout>/run-visualizations` (so the
    owner the render consults is `lstat(<checkout>)`).

    The targets are root:root 0660 / 0770 — root-only for a process that dropped to the uid
    AND its supplementary groups. A child that kept root's supplementary group 0 (no
    `extra_groups=[]`) could write them, so that omission fails here too."""
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
    """The drop-privilege child must be able to start at all as the uid; if the interpreter
    sits somewhere that uid cannot reach, every assertion below would fail on infrastructure
    rather than on the behavior, so say so plainly."""
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
    """(a) The mirror's parent belongs to a non-root uid and `run-visualizations/` does not
    exist yet. After a root render, `run-visualizations/`, `<run>/` and `<run>/runtime.html`
    all belong to that uid:gid, and the page is the run's own. This is also the positive
    control for the planted-link cases below: unplanted, the same render succeeds."""
    _lane_precondition(owned_tree)
    run_dir = driven_run(tmp_path)
    assert not owned_tree.mirror.exists()

    run_common.visualize(run_dir)

    page = owned_tree.mirror / run_dir.name / PAGE
    for made in (owned_tree.mirror, page.parent, page):
        _owned_by(made, owned_tree.uid, owned_tree.gid)
    assert page.read_bytes() == (run_dir / PAGE).read_bytes()
    assert MARKER in page.read_text(encoding="utf-8")


@root_only
def test_1084_a_root_render_replaces_a_root_owned_page_left_by_the_old_writer(tmp_path, owned_tree):
    """(b) Today's pages are root:root 0644 (issue C4). One sits at the mirror name inside the
    user's own `<run>/`. The re-render replaces it: the name now holds the run's page, owned by
    the uid. The uid can rename over a file in its own folder but cannot open a root 0644 file
    for writing — so a truncate-in-place writer fails here, and only stage+rename passes."""
    _lane_precondition(owned_tree)
    run_dir = driven_run(tmp_path)
    _user_dir(owned_tree.mirror, owned_tree)
    _user_dir(owned_tree.mirror / run_dir.name, owned_tree)
    stale = owned_tree.mirror / run_dir.name / PAGE
    stale.write_bytes(b"STALE\n")
    os.chmod(stale, 0o644)

    run_common.visualize(run_dir)

    assert not stale.is_symlink()
    assert stale.read_bytes() == (run_dir / PAGE).read_bytes(), "the stale page was not replaced"
    _owned_by(stale, owned_tree.uid, owned_tree.gid)
    _owned_by(owned_tree.mirror, owned_tree.uid, owned_tree.gid)


@root_only
@pytest.mark.parametrize("site", ["run-visualizations", "run-visualizations/<run>",
                                  "run-visualizations/<run>/runtime.html"])
def test_1084_a_link_planted_at_any_mirror_name_toward_a_root_only_target_fails_the_render(
        tmp_path, owned_tree, site):
    """O4. The user plants a symlink (lchowned to them — what they could make themselves) at
    one of the three names, aimed OUTSIDE the checkout at a root-only folder (the two folder
    names) or file (the page name). The render must FAIL (`VisualizeFailed`), the target must
    be unchanged in content/listing, owner, mode and mtime, and the link must still be the
    user's link to it.

    For the page name this means the writer refuses a link sitting at `runtime.html` rather
    than renaming over it: the design's O4 names all three sites as "the render must have
    failed", and a rename-over alone would silently succeed there.

    Positive control: `test_1084_a_root_render_writes_the_mirror_as_the_checkouts_owner` —
    the same render, unplanted, in this module — succeeds."""
    _lane_precondition(owned_tree)
    run_dir = driven_run(tmp_path)
    rel = site.replace("<run>", run_dir.name)
    link = owned_tree.checkout / rel
    for parent in reversed(link.relative_to(owned_tree.checkout).parents[:-1]):
        _user_dir(owned_tree.checkout / parent, owned_tree)
    target = owned_tree.root_file if site.endswith(PAGE) else owned_tree.root_dir
    os.symlink(target, link)
    os.lchown(link, owned_tree.uid, owned_tree.gid)
    before = _fingerprint(target)

    with pytest.raises(run_common.VisualizeFailed):
        run_common.visualize(run_dir)

    assert _fingerprint(target) == before, f"the root-only target changed through {site}"
    assert link.is_symlink(), f"the link at {site} was replaced or removed"
    assert os.readlink(link) == str(target), f"the link at {site} was re-aimed"


@root_only
def test_1084_a_users_own_link_at_run_visualizations_is_followed_as_the_user(tmp_path, owned_tree):
    """A `run-visualizations` symlink the user made toward a folder THEY own is followed — the
    design's stated non-obligation (the user's choice, bounded by what the user can write).
    Paired with the planted-link case: the link itself is not what fails a render; the
    root-only target is."""
    _lane_precondition(owned_tree)
    run_dir = driven_run(tmp_path)
    theirs = owned_tree.base / "users-pages"
    _user_dir(theirs, owned_tree)
    os.symlink(theirs, owned_tree.mirror)
    os.lchown(owned_tree.mirror, owned_tree.uid, owned_tree.gid)

    run_common.visualize(run_dir)

    page = theirs / run_dir.name / PAGE
    assert page.read_bytes() == (run_dir / PAGE).read_bytes()
    _owned_by(page, owned_tree.uid, owned_tree.gid)
    _owned_by(page.parent, owned_tree.uid, owned_tree.gid)


@root_only
def test_1084_a_root_owned_checkout_is_written_in_process_as_root(tmp_path, owned_tree):
    """When the mirror's parent belongs to root, nothing is dropped: the render writes the
    mirror itself and every path it creates is root's. The control that the ownership above
    comes from the parent's owner, not from a fixed uid."""
    os.chown(owned_tree.checkout, 0, 0)
    run_dir = driven_run(tmp_path)

    run_common.visualize(run_dir)

    page = owned_tree.mirror / run_dir.name / PAGE
    for made in (owned_tree.mirror, page.parent, page):
        _owned_by(made, 0, 0)
    assert page.read_bytes() == (run_dir / PAGE).read_bytes()


@root_only
@pytest.mark.parametrize("shape", ["root-owned-0755", "users-own-0555"])
def test_1084_a_mirror_folder_the_owner_cannot_write_fails_the_render_untouched(
        tmp_path, owned_tree, shape):
    """The checkout belongs to the uid, but its REAL (not linked) `run-visualizations/` is one
    the uid cannot write: root:root 0755 (the state today's root-written pages leave behind),
    or the uid's own folder at 0555. Written as the uid (D5), the render fails and the folder is
    unchanged. A root writer that vets links and chowns afterwards (#1084 adversary H1), or one
    that takes the owner from `run-visualizations/` rather than from its parent (H2), writes
    into it — root ignores mode bits. Positive control: case (a), the same render into a
    folder the uid can write, succeeds."""
    _lane_precondition(owned_tree)
    run_dir = driven_run(tmp_path)
    owned_tree.mirror.mkdir()
    if shape == "root-owned-0755":
        os.chmod(owned_tree.mirror, 0o755)
    else:
        os.chown(owned_tree.mirror, owned_tree.uid, owned_tree.gid)
        os.chmod(owned_tree.mirror, 0o555)
    before = _fingerprint(owned_tree.mirror)

    with pytest.raises(run_common.VisualizeFailed):
        run_common.visualize(run_dir)

    assert _fingerprint(owned_tree.mirror) == before, f"the {shape} mirror folder was written"


@root_only
def test_1084_the_child_takes_the_checkouts_gid_not_the_uids_passwd_group(tmp_path, owned_tree):
    """The group is the checkout's `st_gid`, not the uid's passwd entry: a host uid need not
    exist in the container's passwd at all, and its folder's group is what the operator sees.
    The checkout is chowned to `<uid>:4242`; the page, its folder and `run-visualizations/`
    come out `<uid>:4242` (#1084 adversary H8)."""
    _lane_precondition(owned_tree)
    run_dir = driven_run(tmp_path)
    gid = 4242
    assert gid != owned_tree.gid, "precondition: 4242 must differ from the uid's passwd group"
    os.chown(owned_tree.checkout, owned_tree.uid, gid)

    run_common.visualize(run_dir)

    page = owned_tree.mirror / run_dir.name / PAGE
    for made in (owned_tree.mirror, page.parent, page):
        _owned_by(made, owned_tree.uid, gid)
    assert page.read_bytes() == (run_dir / PAGE).read_bytes()
