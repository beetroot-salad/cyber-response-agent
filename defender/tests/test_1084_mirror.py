"""#1084 — the run-page mirror moves out of `defender/`, to the MAIN checkout's top level.

The contract is the owner's settled design on the issue (O1-O5, M1-M6, D1-D6). This module
holds the units that need no driven run:

- M1, the resolver `visualize_run.mirror_root(start=None)`, over FAKE checkout layouts built
  in `tmp_path` — a main checkout (`.git` is a directory), a worktree (`.git` is a
  `gitdir:` file whose `commondir` names the main `.git`, by absolute and by relative
  gitdir), an image build (no `.git`), and a mismatched or malformed chain (fallback to
  `start` plus a warning on stderr). This is O1/D3's and O2's default-path coverage: the
  resolution is exercised without ever rendering into the real root.
- D4, the override (`DEFENDER_RUN_VISUALIZATIONS_DIR`), read at CALL time: it wins even over
  an explicit `start`, and setting it after import changes the answer.
- O3, the detector: under pytest, with the override removed and no explicit `start`, the
  resolver raises `MirrorRootRefused` rather than name a real checkout's folder.
- O5 / D6 / M5, the ignore rules: both the new and the old mirror path are ignored by the
  ROOT `.gitignore` (the old nested one is `git rm`ed) and excluded from docker contexts.

The renderer module is imported INSIDE each test, never at module level, so this file
collects against a tree that does not have the new names yet and each test is red on its own.
"""
from __future__ import annotations

import importlib
import os
import re
from pathlib import Path

import pytest

from defender import _git, run_common

REPO = run_common.REPO_ROOT
ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"
MIRROR = "run-visualizations"


def _renderer():
    return importlib.import_module("defender.scripts.visualize.visualize_run")


def _same(a: Path, b: Path) -> bool:
    """Path identity by where the kernel would land, so a result spelled with `..` (or not)
    compares by the directory it names — not by its spelling."""
    return a.resolve() == b.resolve()


# ---------------------------------------------------------------------------------------
# fake layouts — written the way git writes them (trailing newlines included)
# ---------------------------------------------------------------------------------------


def _checkout(root: Path, *, git_dir: bool = True, defender: bool = True) -> Path:
    root.mkdir(parents=True)
    if defender:
        (root / "defender").mkdir()
    if git_dir:
        (root / ".git").mkdir()
    return root


def _worktree(main: Path, wt: Path, *, relative: bool = False, name: str = "wt") -> Path:
    """`wt/.git` is the file `gitdir: <main>/.git/worktrees/<name>`, and that admin dir holds
    `commondir` = `../..` (relative to itself) — exactly the chain `git worktree add` leaves."""
    admin = main / ".git" / "worktrees" / name
    admin.mkdir(parents=True)
    (admin / "commondir").write_text("../..\n", encoding="utf-8")
    (admin / "gitdir").write_text(f"{wt / '.git'}\n", encoding="utf-8")
    (admin / "HEAD").write_text("ref: refs/heads/wt\n", encoding="utf-8")
    wt.mkdir(parents=True)
    (wt / "defender").mkdir()
    pointer = os.path.relpath(admin, wt) if relative else str(admin)
    (wt / ".git").write_text(f"gitdir: {pointer}\n", encoding="utf-8")
    return admin


@pytest.fixture
def no_override(monkeypatch):
    """The D4 override removed, so the resolver's own order (2)/(3) is what answers."""
    monkeypatch.delenv(ENV, raising=False)


# ---------------------------------------------------------------------------------------
# D4 — the override, and its identity with the name the conftest sets
# ---------------------------------------------------------------------------------------


def test_1084_the_renderers_override_is_the_variable_every_test_is_given(run_visualizations_dir):
    """`visualize_run.MIRROR_DIR_ENV` is `DEFENDER_RUN_VISUALIZATIONS_DIR` — the variable the
    autouse conftest fixture sets per test — and, with nothing else changed, `mirror_root()`
    answers with that per-test dir as-is. If the two names drifted, the conftest's prevention
    would silently stop reaching the renderer and O3's detector would be the only guard left.
    """
    vr = _renderer()
    assert vr.MIRROR_DIR_ENV == ENV
    assert os.environ[vr.MIRROR_DIR_ENV] == str(run_visualizations_dir), (
        "precondition: the autouse fixture set the override for this test")
    assert vr.mirror_root() == run_visualizations_dir


def test_1084_the_override_wins_even_over_an_explicit_start(tmp_path, monkeypatch):
    """With the override set, `mirror_root(start=<a well-formed main checkout>)` returns
    `Path(<override>)` exactly — the setting is step (1), ahead of any layout. Positive
    control on the same `start`: with the override removed, the same call names the layout's
    own `run-visualizations/`, so the override (not a broken layout) is what changed it."""
    vr = _renderer()
    main = _checkout(tmp_path / "main")
    elsewhere = tmp_path / "elsewhere" / "pages"
    monkeypatch.setenv(ENV, str(elsewhere))
    assert vr.mirror_root(start=main) == elsewhere

    monkeypatch.delenv(ENV)
    assert _same(vr.mirror_root(start=main), main / MIRROR)


def test_1084_the_override_is_read_at_call_time_not_at_import(tmp_path, monkeypatch):
    """The module is imported first; only then is the override removed, set, changed and
    removed again, and every call follows the environment of that moment. A module constant
    (or a cached first answer) fails the second or third call."""
    vr = _renderer()
    main = _checkout(tmp_path / "main")
    monkeypatch.delenv(ENV, raising=False)
    assert _same(vr.mirror_root(start=main), main / MIRROR)

    first, second = tmp_path / "first", tmp_path / "second"
    monkeypatch.setenv(ENV, str(first))
    assert vr.mirror_root(start=main) == first
    monkeypatch.setenv(ENV, str(second))
    assert vr.mirror_root(start=main) == second
    assert vr.mirror_root() == second, "the no-`start` call reads the same moment's setting"

    monkeypatch.delenv(ENV)
    assert _same(vr.mirror_root(start=main), main / MIRROR)


# ---------------------------------------------------------------------------------------
# M1 — the git-less resolution over fake layouts (O1/D3, and O2's default path)
# ---------------------------------------------------------------------------------------


def test_1084_a_main_checkout_resolves_to_its_own_top_level_folder(tmp_path, capsys, no_override):
    """`start/.git` is a directory → `start` is the main checkout → `start/run-visualizations`,
    and nothing is written to stderr (a well-formed layout is not warned about)."""
    main = _checkout(tmp_path / "main")
    got = _renderer().mirror_root(start=main)
    assert got.name == MIRROR
    assert _same(got, main / MIRROR)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("relative", [False, True], ids=["absolute-gitdir", "relative-gitdir"])
def test_1084_a_worktree_resolves_to_the_main_checkouts_folder_not_its_own(
        tmp_path, capsys, no_override, relative):
    """D3: a worktree's `.git` is the file `gitdir: <main>/.git/worktrees/<name>` (absolute, or
    relative to the worktree); that dir's `commondir` (`../..`) names the main `.git`, whose
    parent is the main checkout. The page goes to `<main>/run-visualizations`, never
    `<worktree>/run-visualizations`, and a well-formed chain draws no warning.

    Discriminates an implementation that takes `Path.parent` of an unnormalized
    `.../worktrees/wt/../..` (which eats one `..` and lands in `.git/worktrees`) — that path
    has no `defender/`, so it falls back to the worktree and fails here."""
    main = _checkout(tmp_path / "main")
    wt = tmp_path / "trees" / "wt"
    _worktree(main, wt, relative=relative)
    got = _renderer().mirror_root(start=wt)
    assert got.name == MIRROR
    assert _same(got, main / MIRROR), f"resolved {got}, not the main checkout's folder"
    assert not _same(got, wt / MIRROR)
    assert capsys.readouterr().err == ""


def test_1084_no_git_at_all_falls_back_to_start_without_a_warning(tmp_path, capsys, no_override):
    """(3) an image build has no `.git`: the answer is `start/run-visualizations`, and that is
    an expected layout, not a malformed one — stderr stays empty."""
    image = _checkout(tmp_path / "image", git_dir=False)
    got = _renderer().mirror_root(start=image)
    assert _same(got, image / MIRROR)
    assert capsys.readouterr().err == ""


def _break_commondir_target(main: Path, wt: Path, admin: Path) -> None:
    """The chain resolves, but to a checkout with no `defender/` (the sanity check)."""
    (main / "defender").rmdir()


def _break_git_file_prefix(main: Path, wt: Path, admin: Path) -> None:
    (wt / ".git").write_text(f"not-a-gitdir-line {admin}\n", encoding="utf-8")


def _break_gitdir_missing(main: Path, wt: Path, admin: Path) -> None:
    (wt / ".git").write_text(f"gitdir: {admin.parent / 'gone'}\n", encoding="utf-8")


def _break_commondir_missing(main: Path, wt: Path, admin: Path) -> None:
    (admin / "commondir").unlink()


def _break_commondir_content(main: Path, wt: Path, admin: Path) -> None:
    """`commondir` exists but NAMES somewhere else (with no `defender/`): a resolver that only
    checks the file exists and assumes `../..` lands on `main` and is caught here (#1084
    adversary H5)."""
    elsewhere = main.parent / "elsewhere" / ".git"
    elsewhere.mkdir(parents=True)
    (admin / "commondir").write_text(f"{os.path.relpath(elsewhere, admin)}\n", encoding="utf-8")


def _break_git_file_undecodable(main: Path, wt: Path, admin: Path) -> None:
    """Bytes that are not UTF-8 in the pointer: malformed, so a fallback — not a raise (#1084
    adversary H9)."""
    (wt / ".git").write_bytes(b"gitdir: \xff\xfe\n")


def _break_commondir_undecodable(main: Path, wt: Path, admin: Path) -> None:
    (admin / "commondir").write_bytes(b"\xff\xfe\n")


@pytest.mark.parametrize("breakage", [
    _break_commondir_target, _break_git_file_prefix, _break_gitdir_missing,
    _break_commondir_missing, _break_commondir_content, _break_git_file_undecodable,
    _break_commondir_undecodable,
], ids=["commondir-names-a-checkout-without-defender", "git-file-without-gitdir-prefix",
        "gitdir-points-nowhere", "commondir-missing", "commondir-names-elsewhere",
        "git-file-undecodable", "commondir-undecodable"])
def test_1084_a_mismatched_or_malformed_chain_falls_back_to_start_and_warns(
        tmp_path, capsys, no_override, breakage):
    """Positive control first, on the SAME layout: well-formed, the worktree resolves to the
    main checkout with an empty stderr. Then one link of the chain is broken; the answer is
    `start/run-visualizations` (the worktree's own top level — never a folder with no
    `defender/` beside it, never a raise) and a warning is written to stderr."""
    vr = _renderer()
    main = _checkout(tmp_path / "main")
    wt = tmp_path / "trees" / "wt"
    admin = _worktree(main, wt)
    assert _same(vr.mirror_root(start=wt), main / MIRROR), "positive control: well-formed"
    assert capsys.readouterr().err == "", "positive control: a well-formed chain is not warned"

    breakage(main, wt, admin)
    got = vr.mirror_root(start=wt)
    assert _same(got, wt / MIRROR), f"a broken chain resolved to {got}, not the fallback"
    assert capsys.readouterr().err.strip(), "the fallback was taken silently"


def test_1084_commondir_is_followed_to_whichever_checkout_it_names(tmp_path, capsys, no_override):
    """The worktree's `commondir` is READ, not assumed to be `../..`: pointed at a second,
    well-formed checkout, the answer is that checkout's folder, with no warning. Positive
    control on the same worktree: with git's own `../..`, the answer is the first checkout
    (#1084 adversary H5)."""
    vr = _renderer()
    main = _checkout(tmp_path / "main")
    other = _checkout(tmp_path / "other")
    wt = tmp_path / "trees" / "wt"
    admin = _worktree(main, wt)
    assert _same(vr.mirror_root(start=wt), main / MIRROR), "positive control: `../..`"

    (admin / "commondir").write_text(f"{os.path.relpath(other / '.git', admin)}\n",
                                     encoding="utf-8")
    assert _same(vr.mirror_root(start=wt), other / MIRROR)
    assert capsys.readouterr().err == ""


def test_1084_the_resolver_does_not_ask_git(tmp_path, monkeypatch, no_override):
    """M1 finds the main checkout by reading `.git`, never by running git — which, as root in a
    user-owned repo, answers per `safe.directory` and per an inherited `GIT_DIR`. A real
    decoy repository is exported through `GIT_DIR`/`GIT_COMMON_DIR`; a resolver that asks git
    names the decoy, one that reads the files names the layout's own main checkout (#1084
    adversary H6). Positive control: the decoy is a working repository git does answer for."""
    vr = _renderer()
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    (decoy / "defender").mkdir()
    _git.git(["init", "-q", str(decoy)], cwd=tmp_path)
    main = _checkout(tmp_path / "main")
    wt = tmp_path / "trees" / "wt"
    _worktree(main, wt)
    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    monkeypatch.setenv("GIT_COMMON_DIR", str(decoy / ".git"))
    answered = Path(_git.git(["rev-parse", "--path-format=absolute", "--git-common-dir"],
                             cwd=wt).strip())
    assert _same(answered, decoy / ".git"), "positive control: git answers for the decoy"

    assert _same(vr.mirror_root(start=wt), main / MIRROR)
    assert _same(vr.mirror_root(start=main), main / MIRROR)


def test_1084_the_default_start_is_the_checkout_holding_this_defender_package(monkeypatch):
    """With no `start`, the resolver starts from the directory that holds the `defender/`
    package it lives in — not the cwd — and follows that checkout's own chain to the MAIN
    checkout. The oracle is independent of the resolver: git's own `--git-common-dir`.

    Value only: the pytest refusal is lifted for this one call by removing
    `PYTEST_CURRENT_TEST` (and the override), and nothing is rendered or written — the path is
    computed, compared, and dropped."""
    try:
        common = Path(_git.git(["rev-parse", "--path-format=absolute", "--git-common-dir"],
                               cwd=REPO))
    except (_git.GitError, OSError) as e:
        pytest.skip(f"no git checkout to take the oracle from: {e}")
    monkeypatch.delenv(ENV, raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.chdir("/")
    assert _same(_renderer().mirror_root(), common.parent / MIRROR)


# ---------------------------------------------------------------------------------------
# O3 — the detector
# ---------------------------------------------------------------------------------------


def test_1084_under_pytest_without_the_override_the_default_resolution_is_refused(
        tmp_path, monkeypatch):
    """With `PYTEST_CURRENT_TEST` set (pytest sets it for every phase) and the override
    removed, `mirror_root()` with no `start` raises `MirrorRootRefused` instead of naming the
    real checkout's folder. Positive controls on the same call: with the override set it
    returns it as-is; and an explicit `start` is not refused (that is how the layout units
    above reach the default order at all)."""
    vr = _renderer()
    assert issubclass(vr.MirrorRootRefused, Exception)
    monkeypatch.delenv(ENV, raising=False)
    assert "PYTEST_CURRENT_TEST" in os.environ, "precondition: the detector's input is present"
    with pytest.raises(vr.MirrorRootRefused):
        vr.mirror_root()

    main = _checkout(tmp_path / "main")
    assert _same(vr.mirror_root(start=main), main / MIRROR)

    elsewhere = tmp_path / "pages"
    monkeypatch.setenv(ENV, str(elsewhere))
    assert vr.mirror_root() == elsewhere


def test_1084_an_empty_override_is_not_an_override(monkeypatch):
    """The override counts only when non-empty: `DEFENDER_RUN_VISUALIZATIONS_DIR=` must not
    become `Path("")` (the cwd) — under pytest it is refused like an unset one."""
    vr = _renderer()
    monkeypatch.setenv(ENV, "")
    with pytest.raises(vr.MirrorRootRefused):
        vr.mirror_root()


# ---------------------------------------------------------------------------------------
# O5 / D6 / M5 — ignore rules for both the new and the old path
# ---------------------------------------------------------------------------------------

NEW_PAGE = "run-visualizations/x/runtime.html"
OLD_PAGE = "defender/run-visualizations/x/runtime.html"


def test_1084_both_mirror_paths_are_ignored_by_the_root_gitignore():
    """`git check-ignore` succeeds for a page under the new top-level folder AND under the old
    `defender/` one (worktrees' leftovers), and for both the rule that matches is the ROOT
    `.gitignore` — the nested `defender/run-visualizations/.gitignore` is `git rm`ed (D6), so
    nothing under the old folder is tracked any more. Positive control: a tracked source file
    is not ignored, so a check-ignore that answered yes to everything cannot pass."""
    assert not _git.git_ok(["check-ignore", "-q", "defender/run.py"], cwd=REPO), (
        "positive control: a tracked source file reads as ignored")
    for page in (NEW_PAGE, OLD_PAGE):
        assert _git.git_ok(["check-ignore", "-q", page], cwd=REPO), f"{page} is not ignored"
        verbose = _git.git(["check-ignore", "-v", page], cwd=REPO)
        source = verbose.split(":", 1)[0]
        assert source == ".gitignore", (
            f"{page} is ignored by {source!r}, not by the root .gitignore ({verbose!r})")
    assert _git.git(["ls-files", "--", "defender/run-visualizations"], cwd=REPO) == "", (
        "files under defender/run-visualizations/ are still tracked")


def _docker_pattern(pattern: str) -> re.Pattern[str]:
    """One `.dockerignore` pattern as docker's matcher reads it: `**` any run of path
    segments (a leading `**/` also none), `*` and `?` within one segment."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out + r"\Z")


def _docker_excludes(path: str) -> bool:
    """Whether the repo-root `.dockerignore` keeps `path` out of a build context: last match
    wins, `!` re-includes, and a pattern matching any parent directory excludes the path."""
    lines = (REPO / ".dockerignore").read_text(encoding="utf-8").splitlines()
    parts = path.split("/")
    prefixes = ["/".join(parts[:n]) for n in range(1, len(parts) + 1)]
    excluded = False
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        pattern = os.path.normpath(line.lstrip("!").strip()).lstrip("/")
        rx = _docker_pattern(pattern)
        if any(rx.match(p) for p in prefixes):
            excluded = not negate
    return excluded


def test_1084_both_mirror_paths_are_kept_out_of_docker_build_contexts():
    """The runtime image COPYs `defender/`, and the dev image's context is the repo root: a
    page under either folder must be excluded by `.dockerignore`. Positive controls through
    the same matcher: an already-listed transient path is excluded, a source file is not."""
    assert _docker_excludes("defender/learning/runs/x/y.json"), "positive control: listed path"
    assert not _docker_excludes("defender/run.py"), "positive control: a source file is excluded"
    assert _docker_excludes(NEW_PAGE), f"{NEW_PAGE} would ship in a build context"
    assert _docker_excludes(OLD_PAGE), f"{OLD_PAGE} would ship in a build context"
