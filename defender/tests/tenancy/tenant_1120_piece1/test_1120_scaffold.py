"""D7 `tenant.py scaffold <id> <dir>`: a new tenant repo from the template."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

#: Every ambient git variable is dropped from the scaffold process's environment, so the test,
_AMBIENT_GIT = tuple(k for k in os.environ if k.startswith("GIT_")) + ("EMAIL",)


def _home(tmp: Path, *, identity: bool = True, extra: str = "") -> Path:
    """A private `$HOME` whose `.gitconfig` is the only git configuration the scaffold process reads
    (with `XDG_CONFIG_HOME` beside it)."""
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


def test_1120_scaffold_copies_the_template_writes_the_tenant_id_and_commits(
        tmp_path: Path, data_root: Path) -> None:
    """`tenant.py scaffold acme <empty dir>` exits 0."""
    target = _empty_dir(tmp_path / "acme-tenant")
    proc = _scaffold(H.TID, target, home=_home(tmp_path))
    H.assert_clean(proc)

    template = _template_files()
    for rel, data in template.items():
        copied = target / rel
        assert copied.is_file(), f"scaffold did not copy the template's {rel}"
        assert copied.read_bytes() == data, f"{rel} differs from knowledge/tenant-template's"
    assert not [p for p in target.rglob("examples")], "scaffold copied the template's examples/"
    assert (target / H.TENANT_ID_FILE).read_bytes() == f"{H.TID}\n".encode(), (
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


def test_1120_scaffold_leaves_the_product_repo_unchanged_under_an_exported_git_dir(
        tmp_path: Path) -> None:
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
_IDENTITY_WORDS = ("identity", "user.email", "user.name", "who you are")


@pytest.mark.parametrize("fault", [
    pytest.param("absent", id="absent"),
    pytest.param("no-identity", id="no-identity"),
])
def test_1120_scaffold_without_git_or_a_commit_identity_refuses_before_any_write(
        tmp_path: Path, fault: str) -> None:
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
