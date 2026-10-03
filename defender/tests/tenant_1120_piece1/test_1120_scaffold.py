"""#1120 piece 1 — D7 `tenant.py scaffold <id> <dir>`: a new tenant repo from the template.

`scaffold` copies `knowledge/tenant-template` (without `examples/`) into an EMPTY directory the
operator names, writes `agent/.tenant-id` (the id plus a newline — M8), runs `git init` on
branch `main` and commits (N5): the operator then pushes it to a new private repo. It needs no
data root (N10). It refuses a bad id, a non-directory, a non-empty or an in-checkout target
writing nothing; it preflights git and a commit identity before any write; a failure after it
began leaves the target as it found it (N5). Its git calls run with an explicit `cwd` AND the
ambient `GIT_*` environment scrubbed (N3), because an exported `GIT_DIR`/`GIT_WORK_TREE` decides
the repository whatever `cwd=` says (J-PO1, executed — 45's D-1 is refuted).

Driven as the operator runs it: a process. Every git fault is a REAL git mechanism configured
for that process alone — a `$HOME/.gitconfig` the test writes (`HOME` and `XDG_CONFIG_HOME`
point into `tmp_path`), a `PATH` holding no `git`, an exported `GIT_DIR` naming a SCRATCH repo
that stands for the product repo. The real worktree and the real product repo are never the
target of any write. "Left as found" is a before/after census of the target (bytes, mtimes,
modes). See `_spec1120.py` for the coined names.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from defender.scripts import tenant as tenant_py
from defender.tests.tenant_1120_piece1 import _spec1120 as H

#: Every ambient git variable is dropped from the scaffold process's environment, so the test,
#: not the developer's shell, decides what git sees (`EMAIL` too: git reads it for identity).
_AMBIENT_GIT = tuple(k for k in os.environ if k.startswith("GIT_")) + ("EMAIL",)


def _home(tmp: Path, *, identity: bool = True, extra: str = "") -> Path:
    """A private `$HOME` whose `.gitconfig` is the only git configuration the scaffold process
    reads (with `XDG_CONFIG_HOME` beside it). `identity` writes `user.name`/`user.email`;
    without it `user.useConfigOnly` stops git guessing one from the host name. `extra` is
    appended verbatim — the fault a cell configures."""
    home = tmp / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "xdg").mkdir(exist_ok=True)
    user = ("[user]\n\tname = spec1120\n\temail = spec1120@example.invalid\n" if identity
            else "[user]\n\tuseConfigOnly = true\n")
    (home / ".gitconfig").write_text(user + extra, encoding="utf-8")
    return home


def _scaffold(tenant_id: str, target: Path, *, home: Path, script: Path | None = None,
              cwd: Path | None = None, identity_env: bool = True,
              **env: str) -> subprocess.CompletedProcess:
    """`tenant.py scaffold <tenant_id> <target>` as a process, under `home`'s git config.
    `script` runs another checkout's copy of `tenant.py` (default: this checkout's)."""
    extra = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "xdg")}
    if identity_env:
        extra.update(H.GIT_IDENTITY)
    extra.update(env)
    return H.run_script(script or H.script_of(tenant_py), "scaffold", tenant_id, str(target),
                        root=None, cwd=cwd, unset=_AMBIENT_GIT, **extra)


def _refused(proc: subprocess.CompletedProcess, *names: str) -> str:
    """Refused on scaffold's own terms: a non-zero exit, no traceback, and the output naming
    every one of `names`."""
    H.assert_ran(proc)
    text = H.output(proc)
    assert proc.returncode != 0, f"scaffold exited 0 where it must refuse:\n{text}"
    for name in names:
        assert name in text, f"the refusal does not name {name!r}:\n{text}"
    return text


def _product_repo(tmp: Path) -> Path:
    """A SCRATCH git repository with one commit, standing for the product repo the operator
    runs `scaffold` from. Never the real worktree."""
    repo = tmp / "product"
    (repo / "defender").mkdir(parents=True)
    (repo / "defender" / "run.py").write_text("# product code\n", encoding="utf-8")
    H.git(repo, "init", "-q", "-b", "main")
    H.git(repo, "add", "-A")
    H.git(repo, "commit", "-q", "-m", "product")
    return repo


def _repo_state(repo: Path) -> dict[str, object]:
    """The product repo's HEAD, index and refs, byte for byte."""
    git_dir = repo / ".git"
    packed = git_dir / "packed-refs"
    return {
        "HEAD": (git_dir / "HEAD").read_bytes(),
        "index": (git_dir / "index").read_bytes(),
        "refs": H.tree_census(git_dir / "refs"),
        "packed-refs": packed.read_bytes() if packed.exists() else None,
    }


def _template_files() -> dict[str, bytes]:
    """The template's files the scaffold copies (`examples/` never copied), by relative path."""
    return {
        p.relative_to(H.TEMPLATE).as_posix(): p.read_bytes()
        for p in sorted(H.TEMPLATE.rglob("*"))
        if p.is_file() and "examples" not in p.relative_to(H.TEMPLATE).parts
    }


def _committed_files(repo: Path) -> set[str]:
    listing = H.git(repo, "ls-tree", "-r", "-z", "--name-only", "HEAD").stdout
    return {name for name in listing.split("\0") if name}


def _empty_dir(path: Path) -> Path:
    path.mkdir(parents=True)
    return path


# ======================================================================================
# The happy path.
# ======================================================================================

def test_1120_scaffold_copies_the_template_writes_the_tenant_id_and_commits(
        tmp_path: Path, data_root: Path) -> None:
    """`tenant.py scaffold acme <empty dir>` exits 0. The directory then holds the template's
    settings/ files byte-equal to knowledge/tenant-template's, its agent/ half with no
    examples/, agent/.tenant-id reading acme plus a newline (M8: scaffold writes the id and one
    line ending), and a git repository on branch main with exactly one commit containing all of
    the above, with `git status --porcelain` empty. The positive control: `tenant.py check
    --folder <dir>` exits 0 over the scaffolded folder."""
    target = _empty_dir(tmp_path / "acme-tenant")
    proc = _scaffold(H.TID, target, home=_home(tmp_path))
    H.assert_clean(proc)

    template = _template_files()
    for rel, data in template.items():
        copied = target / rel
        assert copied.is_file(), f"scaffold did not copy the template's {rel}"
        assert copied.read_bytes() == data, f"{rel} differs from knowledge/tenant-template's"
    assert not [p for p in target.rglob("examples")], "scaffold copied the template's examples/"
    assert (target / H.TENANT_ID_FILE).read_bytes() == b"acme\n", (
        "agent/.tenant-id must hold the id plus one newline (M8)")

    assert (target / ".git").is_dir(), "scaffold made no git repository"
    assert H.git(target, "rev-list", "--count", "HEAD").stdout.strip() == "1", (
        "the new repository must hold exactly one commit")
    assert H.git(target, "symbolic-ref", "--short", "HEAD").stdout.strip() == "main"
    expected = set(template) | {H.TENANT_ID_FILE.as_posix()}
    assert _committed_files(target) == expected, (
        f"the commit does not hold exactly the template plus agent/.tenant-id: "
        f"{sorted(_committed_files(target) ^ expected)}")
    assert H.git_status(target) == "", "the scaffolded repository is not clean"

    H.assert_clean(H.check(tenant_py, data_root, "--folder", str(target)))


# ======================================================================================
# Refusals: a bad id, a non-empty, non-directory or in-checkout target (N5).
# ======================================================================================

def _dir_holding_a_file(tmp: Path) -> Path:
    target = _empty_dir(tmp / "occupied")
    (target / "notes.txt").write_text("the operator's own file\n", encoding="utf-8")
    return target


def _regular_file(tmp: Path) -> Path:
    target = tmp / "a-file"
    target.write_text("not a directory\n", encoding="utf-8")
    return target


@pytest.mark.parametrize(("tenant_id", "cell"), [
    pytest.param("../x", "bad-id", id="../x"),
    pytest.param(H.TID, "non-empty", id="non-empty"),
    pytest.param(H.TID, "regular-file", id="regular-file"),
    pytest.param(H.TID, "inside-checkout", id="inside-checkout"),
])
def test_1120_scaffold_refuses_a_bad_id_or_a_non_empty_target_and_writes_nothing(
        tmp_path: Path, tenant_id: str, cell: str) -> None:
    """`scaffold ../x <empty dir>`, `scaffold acme <dir holding a file>`, `scaffold acme
    <a regular file>` and `scaffold acme <an empty dir inside the running checkout>` each exit
    non-zero, naming the id or the target, and leave the target exactly as found: no file
    copied, no .tenant-id, no repository. The in-checkout cell runs a COPY of the checkout
    (the running checkout is the copy), so the real worktree is never written; its positive
    control is the same copy scaffolding an empty directory outside itself, which exits 0."""
    home = _home(tmp_path / "cfg")
    work = tmp_path / "work"
    script = None
    if cell == "bad-id":
        target = _empty_dir(work / "empty")
    elif cell == "non-empty":
        target = _dir_holding_a_file(work)
    elif cell == "regular-file":
        work.mkdir()
        target = _regular_file(work)
    else:
        work = H.tmp_checkout(tmp_path / "checkout")
        script = work / H.script_of(tenant_py).relative_to(H.REPO_ROOT)
        target = _empty_dir(work / "acme-tenant")
    before = H.tree_census(work)
    proc = _scaffold(tenant_id, target, home=home, script=script)
    _refused(proc, tenant_id if cell == "bad-id" else str(target))
    assert H.census_diff(before, H.tree_census(work)) == [], (
        "the refused scaffold wrote something")
    if cell == "inside-checkout":
        outside = _empty_dir(tmp_path / "outside" / "acme-tenant")
        H.assert_clean(_scaffold(H.TID, outside, home=home, script=script))
        assert (outside / H.TENANT_ID_FILE).is_file(), "the control scaffold wrote no tenant"


def test_1120_s3_scaffold_into_a_regular_file(tmp_path: Path) -> None:
    """`<dir>` names an existing regular file, not a directory: scaffold is refused with a
    non-zero exit naming the path. The file is unchanged (bytes, mtime and mode) and nothing
    is written beside it. The positive control: an empty directory at a sibling path is
    scaffolded (exit 0)."""
    (tmp_path / "work").mkdir()
    target = _regular_file(tmp_path / "work")
    before = H.tree_census(tmp_path / "work")
    home = _home(tmp_path / "cfg")
    _refused(_scaffold(H.TID, target, home=home), str(target))
    assert H.census_diff(before, H.tree_census(tmp_path / "work")) == [], (
        "scaffold changed the regular file or wrote beside it")

    H.assert_clean(_scaffold(H.TID, _empty_dir(tmp_path / "work" / "dir"), home=home))


# ======================================================================================
# git: the product repo, a refused commit, the preflight (N3, N5).
# ======================================================================================

def test_1120_scaffold_leaves_the_product_repo_unchanged_under_an_exported_git_dir(
        tmp_path: Path) -> None:
    """With GIT_DIR and GIT_WORK_TREE exported naming the product repo — here a SCRATCH repo
    in tmp standing for it, never the real worktree — `tenant.py scaffold acme <empty dir>`
    exits 0, leaves that repo's HEAD, index and refs byte-identical, and the TARGET gets the
    repository: its own .git holding one commit with agent/.tenant-id. An exported GIT_DIR
    decides the repository whatever cwd says (J-PO1), so scaffold scrubs the ambient GIT_*
    environment from its git calls (N3)."""
    # rejected: automatic retry and a clone timeout (N3).
    product = _product_repo(tmp_path)
    before = _repo_state(product)
    target = _empty_dir(tmp_path / "acme-tenant")
    proc = _scaffold(H.TID, target, home=_home(tmp_path), cwd=product,
                     GIT_DIR=str(product / ".git"), GIT_WORK_TREE=str(product))
    H.assert_clean(proc)
    assert _repo_state(product) == before, (
        "scaffold changed the product repo named by the exported GIT_DIR")
    assert (target / ".git").is_dir(), "the target got no repository of its own"
    assert H.git(target, "rev-list", "--count", "HEAD").stdout.strip() == "1"
    assert H.TENANT_ID_FILE.as_posix() in _committed_files(target)


def test_1120_a_failed_scaffold_leaves_its_target_as_found_and_a_retry_succeeds(
        tmp_path: Path) -> None:
    """A commit git refuses after the preflight passed — commit.gpgSign set with gpg.program
    pointing at `false` (git cannot sign, so it refuses to write the commit object) and
    core.hooksPath naming a pre-commit hook that exits 1, two real git mechanisms configured in
    the scaffold process's own $HOME/.gitconfig — makes
    `tenant.py scaffold acme <empty dir>` exit non-zero naming git, and leaves the target as it
    found it: still an empty directory, no copied file, no .tenant-id, no .git. A retry once
    the fault is removed succeeds (exit 0, one commit)."""
    false = shutil.which("false")
    assert false, "no `false` executable on this host to stand in for a failing gpg"
    target = _empty_dir(tmp_path / "acme-tenant")
    before = H.tree_census(target)
    hooks = _empty_dir(tmp_path / "hooks")
    (hooks / "pre-commit").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (hooks / "pre-commit").chmod(0o755)
    faulty = _home(tmp_path, extra=(f"[commit]\n\tgpgSign = true\n[gpg]\n\tprogram = {false}\n"
                                    f"[core]\n\thooksPath = {hooks}\n"))
    _refused(_scaffold(H.TID, target, home=faulty), "git")
    assert H.census_diff(before, H.tree_census(target)) == [], (
        "the failed scaffold left files in its target")

    healthy = _home(tmp_path)  # rewrites the same .gitconfig without the fault
    H.assert_clean(_scaffold(H.TID, target, home=healthy))
    assert H.git(target, "rev-list", "--count", "HEAD").stdout.strip() == "1"


#: Words any "no commit identity" refusal carries — scaffold's own preflight message or git's
#: ("Author identity unknown … Please tell me who you are … user.email").
_IDENTITY_WORDS = ("identity", "user.email", "user.name", "who you are")


@pytest.mark.parametrize("fault", [
    pytest.param("absent", id="absent"),
    pytest.param("no-identity", id="no-identity"),
])
def test_1120_scaffold_without_git_or_a_commit_identity_refuses_before_any_write(
        tmp_path: Path, fault: str) -> None:
    """`tenant.py scaffold acme <empty dir>` with no git on PATH, or with no committer identity
    (a private $HOME whose config sets user.useConfigOnly and names no user, and no identity
    variable in the environment), exits non-zero naming git — and, for the missing identity,
    naming the identity — BEFORE any write: the target is left as found and the product repo
    the command runs from (a SCRATCH repo standing for it) is unchanged. The positive control:
    the same target with git and an identity is scaffolded (exit 0)."""
    product = _product_repo(tmp_path)
    repo_before = _repo_state(product)
    target = _empty_dir(tmp_path / "acme-tenant")
    before = H.tree_census(target)
    if fault == "absent":
        no_git = _empty_dir(tmp_path / "bin-without-git")
        proc = _scaffold(H.TID, target, home=_home(tmp_path / "cfg"), cwd=product,
                         PATH=str(no_git))
        text = _refused(proc, "git")
    else:
        proc = _scaffold(H.TID, target, home=_home(tmp_path / "cfg", identity=False),
                         cwd=product, identity_env=False, GIT_CONFIG_NOSYSTEM="1")
        text = _refused(proc, "git")
        assert any(w in text for w in _IDENTITY_WORDS), (
            f"the refusal does not name the missing commit identity:\n{text}")
    assert H.census_diff(before, H.tree_census(target)) == [], (
        "scaffold wrote into its target before the git preflight refused")
    assert _repo_state(product) == repo_before, "scaffold changed the product repo"

    H.assert_clean(_scaffold(H.TID, target, home=_home(tmp_path / "ok"), cwd=product))
