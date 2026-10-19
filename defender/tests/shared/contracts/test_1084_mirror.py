"""#1084 — the run-page mirror moves out of `defender/`, to the MAIN checkout's top level."""
from __future__ import annotations

import importlib
import logging
import os
from pathlib import Path

import pytest


ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"
MIRROR = "run-visualizations"


def _renderer():
    return importlib.import_module("defender.presentation.visualize_run")


def _same(a: Path, b: Path) -> bool:
    """Path identity by where the kernel would land, so a result spelled with `..` (or not)
    compares by the directory it names — not by its spelling."""
    return a.resolve() == b.resolve()


# fake layouts — written the way git writes them (trailing newlines included)


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


@pytest.fixture
def warned(caplog):
    """The WARNING-or-worse records logged so far, as their messages (#1110 review: the
    resolver's fallback notice is a `logging` WARNING, not a raw stderr write). Capture starts
    at DEBUG so a notice logged at any level is SEEN — and then judged by its level here."""
    caplog.set_level(logging.DEBUG)

    def read() -> list[str]:
        out = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        caplog.clear()
        return out

    return read


# D4 — the override, and its identity with the name the conftest sets


def test_1084_the_override_wins_even_over_an_explicit_start(tmp_path, monkeypatch):
    """With the override set, `mirror_root(start=<a well-formed main checkout>)` returns
    `Path(<override>)` exactly — the setting is step (1), ahead of any layout."""
    vr = _renderer()
    main = _checkout(tmp_path / "main")
    elsewhere = tmp_path / "elsewhere" / "pages"
    monkeypatch.setenv(ENV, str(elsewhere))
    assert vr.mirror_root(start=main) == elsewhere

    monkeypatch.delenv(ENV)
    assert _same(vr.mirror_root(start=main), main / MIRROR)


def test_1084_the_override_is_read_at_call_time_not_at_import(tmp_path, monkeypatch):
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


# M1 — the git-less resolution over fake layouts (O1/D3, and O2's default path)


def test_1084_a_main_checkout_resolves_to_its_own_top_level_folder(tmp_path, warned, no_override):
    """`start/.git` is a directory → `start` is the main checkout → `start/run-visualizations`,
    and nothing is warned (a well-formed layout is not warned about)."""
    main = _checkout(tmp_path / "main")
    got = _renderer().mirror_root(start=main)
    assert got.name == MIRROR
    assert _same(got, main / MIRROR)
    assert warned() == []


@pytest.mark.parametrize("relative", [False, True], ids=["absolute-gitdir", "relative-gitdir"])
def test_1084_a_worktree_resolves_to_the_main_checkouts_folder_not_its_own(
        tmp_path, warned, no_override, relative):
    main = _checkout(tmp_path / "main")
    wt = tmp_path / "trees" / "wt"
    _worktree(main, wt, relative=relative)
    got = _renderer().mirror_root(start=wt)
    assert got.name == MIRROR
    assert _same(got, main / MIRROR), f"resolved {got}, not the main checkout's folder"
    assert not _same(got, wt / MIRROR)
    assert warned() == []


def test_1084_no_git_at_all_falls_back_to_start_without_a_warning(tmp_path, warned, no_override):
    """(3) an image build has no `.git`: the answer is `start/run-visualizations`, and that is
    an expected layout, not a malformed one — nothing is warned."""
    image = _checkout(tmp_path / "image", git_dir=False)
    got = _renderer().mirror_root(start=image)
    assert _same(got, image / MIRROR)
    assert warned() == []


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
        tmp_path, warned, no_override, breakage):
    """Positive control first, on the SAME layout: well-formed, the worktree resolves to the main
    checkout with nothing warned."""
    vr = _renderer()
    main = _checkout(tmp_path / "main")
    wt = tmp_path / "trees" / "wt"
    admin = _worktree(main, wt)
    assert _same(vr.mirror_root(start=wt), main / MIRROR), "positive control: well-formed"
    assert warned() == [], "positive control: a well-formed chain is not warned"

    breakage(main, wt, admin)
    got = vr.mirror_root(start=wt)
    assert _same(got, wt / MIRROR), f"a broken chain resolved to {got}, not the fallback"
    notices = warned()
    assert len(notices) == 1, f"the fallback was not ONE logged warning: {notices!r}"
    assert str(wt) in notices[0], f"the warning does not name the fallback folder: {notices!r}"


def test_1084_commondir_is_followed_to_whichever_checkout_it_names(tmp_path, warned, no_override):
    """The worktree's `commondir` is READ, not assumed to be `../..`: pointed at a second, well-
    formed checkout, the answer is that checkout's folder, with no warning."""
    vr = _renderer()
    main = _checkout(tmp_path / "main")
    other = _checkout(tmp_path / "other")
    wt = tmp_path / "trees" / "wt"
    admin = _worktree(main, wt)
    assert _same(vr.mirror_root(start=wt), main / MIRROR), "positive control: `../..`"

    (admin / "commondir").write_text(f"{os.path.relpath(other / '.git', admin)}\n",
                                     encoding="utf-8")
    assert _same(vr.mirror_root(start=wt), other / MIRROR)
    assert warned() == []


# O3 — the detector


def test_1084_under_pytest_without_the_override_the_default_resolution_is_refused(
        tmp_path, monkeypatch):
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
