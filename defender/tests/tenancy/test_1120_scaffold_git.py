"""tenant.py scaffold commits exactly what the product repo's HEAD commits and asks git for the identity the new repo will see."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.scripts import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
from defender.tests.tenancy.tenant_1120_piece1 import test_1120_scaffold as S

_TEMPLATE_REL = Path("knowledge") / "tenant-template"


def _committed(repo: Path) -> set[str]:
    listing = H.git(repo, "ls-tree", "-r", "-z", "--name-only", "HEAD").stdout
    return {name for name in listing.split("\0") if name}


def _template_in_head(checkout: Path) -> set[str]:
    listing = H.git(checkout, "ls-tree", "-r", "-z", "--name-only", "HEAD", "--",
                    _TEMPLATE_REL.as_posix()).stdout
    return {Path(n).relative_to(_TEMPLATE_REL).as_posix() for n in listing.split("\0")
            if n and "examples" not in Path(n).relative_to(_TEMPLATE_REL).parts}


def test_scaffold_copies_what_head_commits_not_what_sits_on_disk(tmp_path: Path) -> None:
    checkout = H.tmp_checkout(tmp_path / "checkout")
    template = checkout / _TEMPLATE_REL
    (template / ".DS_Store").write_bytes(b"\0\0finder")
    (template / "settings" / "systems" / "cmdb" / ".env").write_text("TOKEN=secret\n",
                                                                     encoding="utf-8")
    edited = template / "settings" / "lead-zero.yaml"
    committed_bytes = edited.read_bytes()
    edited.write_bytes(committed_bytes + b"# a local edit\n")
    target = S._empty_dir(tmp_path / "acme")
    script = checkout / H.script_of(tenant_py).relative_to(H.REPO_ROOT)
    H.assert_clean(S._scaffold(H.TID, target, home=S._home(tmp_path / "cfg"), script=script))
    assert _committed(target) == _template_in_head(checkout) | {H.TENANT_ID_FILE.as_posix()}
    assert (target / "settings" / "lead-zero.yaml").read_bytes() == committed_bytes


def test_scaffold_commits_template_files_the_operators_ignore_rules_match(
        tmp_path: Path) -> None:
    """The operator's global ignore file holds `*.env` and `*.yaml`: the new repo still commits
    every template file (each `config.env`, every table), and `git status` is clean."""
    home = S._home(tmp_path / "cfg", extra="[core]\n\texcludesFile = ~/ignore\n")
    (home / "ignore").write_text("*.env\n*.yaml\n", encoding="utf-8")
    target = S._empty_dir(tmp_path / "acme")
    H.assert_clean(S._scaffold(H.TID, target, home=home))
    committed = _committed(target)
    assert _template_in_head(H.REPO_ROOT) <= committed, (
        sorted(_template_in_head(H.REPO_ROOT) - committed))
    assert any(name.endswith("config.env") for name in committed), committed


def test_scaffold_identity_from_an_includeif_gitdir_rule_counts(tmp_path: Path) -> None:
    """The operator's only identity comes from `[includeIf "gitdir:<work>/"]`, and the target
    is under `<work>`: scaffold exits 0 and commits under that identity."""
    work = tmp_path / "work"
    included = tmp_path / "work-identity"
    included.write_text("[user]\n\tname = Work\n\temail = work@example.invalid\n",
                        encoding="utf-8")
    home = S._home(tmp_path / "cfg", identity=False,
                   extra=f'[includeIf "gitdir:{work}/"]\n\tpath = {included}\n')
    target = S._empty_dir(work / "acme")
    H.assert_clean(S._scaffold(H.TID, target, home=home, identity_env=False,
                               GIT_CONFIG_NOSYSTEM="1"))
    author = H.git(target, "log", "-1", "--format=%ae").stdout.strip()
    assert author == "work@example.invalid", author


def test_scaffold_does_not_borrow_an_enclosing_repos_identity(tmp_path: Path) -> None:
    enclosing = tmp_path / "enclosing"
    enclosing.mkdir()
    H.git(enclosing, "init", "-q", "-b", "main")
    H.git(enclosing, "config", "user.name", "Enclosing")
    H.git(enclosing, "config", "user.email", "enclosing@example.invalid")
    target = S._empty_dir(enclosing / "acme")
    proc = S._scaffold(H.TID, target, home=S._home(tmp_path / "cfg", identity=False),
                       identity_env=False, GIT_CONFIG_NOSYSTEM="1")
    text = S._refused(proc, "git")
    assert "identity" in text, text
    assert "failed and was undone" not in text, (
        f"the preflight passed on the enclosing repo's identity; the commit then failed:\n{text}")
    assert not any(target.iterdir()), sorted(p.name for p in target.iterdir())


def test_scaffold_into_a_relative_target_asks_the_identity_of_that_target(
        tmp_path: Path) -> None:
    parent = tmp_path / "work"
    included = tmp_path / "work-identity"
    included.write_text("[user]\n\tname = Work\n\temail = work@example.invalid\n",
                        encoding="utf-8")
    home = S._home(tmp_path / "cfg", identity=False,
                   extra=f'[includeIf "gitdir:{parent}/"]\n\tpath = {included}\n')
    S._empty_dir(parent / "newrepo")
    H.assert_clean(S._scaffold(H.TID, Path("newrepo"), home=home, cwd=parent,
                               identity_env=False, GIT_CONFIG_NOSYSTEM="1"))
    author = H.git(parent / "newrepo", "log", "-1", "--format=%ae").stdout.strip()
    assert author == "work@example.invalid", author


@pytest.mark.skipif(os.geteuid() == 0, reason="root removes a read-only folder's entries")
def test_a_failed_undo_is_reported_not_raised(tmp_path: Path) -> None:
    target = S._empty_dir(tmp_path / "acme")
    hooks = S._empty_dir(tmp_path / "hooks")
    (hooks / "pre-commit").write_text(
        "#!/bin/sh\nmkdir -p stuck && touch stuck/f && chmod 555 stuck\nexit 1\n",
        encoding="utf-8")
    (hooks / "pre-commit").chmod(0o755)
    home = S._home(tmp_path / "cfg", extra=f"[core]\n\thooksPath = {hooks}\n")
    checkout = H.tmp_checkout(tmp_path / "checkout")  # owned by whoever runs the test
    script = checkout / H.script_of(tenant_py).relative_to(H.REPO_ROOT)
    try:
        text = S._refused(S._scaffold(H.TID, target, home=home, script=script), str(target))
    finally:
        (target / "stuck").chmod(0o755)
    assert "undoing it failed too" in text, text
