"""#1120 piece 1 — `tenant.py scaffold` commits exactly the template the product repo commits,
and asks git for an identity as the repository it creates will see it (code review, max).

  * A file beside the template that the product repo does not commit (a `.DS_Store`, a stray
    `.env`) never reaches the tenant's repo, and a local edit to a template file is not
    carried either: the template is read from the checkout's HEAD.
  * The operator's own ignore rules (`core.excludesFile`) cannot drop a template file from the
    commit: scaffold stages exactly the files it wrote.
  * The identity preflight asks as the new repository will: an `includeIf "gitdir:…"`
    identity counts, and an enclosing repository's identity is not borrowed (which would let
    the preflight pass and the commit fail after the first write).
"""
from __future__ import annotations

from pathlib import Path

from defender.scripts import tenant as tenant_py
from defender.tests.tenant_1120_piece1 import _spec1120 as H
from defender.tests.tenant_1120_piece1 import test_1120_scaffold as S

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
    """A tmp checkout whose template holds an untracked `.DS_Store` at its top and an untracked
    `settings/systems/cmdb/.env`, and a locally edited `settings/lead-zero.yaml`: the new
    repo commits exactly HEAD's template files plus `.tenant-id`, with HEAD's bytes."""
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
    """The target sits inside a repository whose own config sets the identity, and the
    operator has none: scaffold refuses at its preflight, naming the identity, before any
    write — not by writing, failing the commit and undoing — and leaves the target as found."""
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
    """`scaffold acme newrepo` (relative, from the target's parent) under an `includeIf
    "gitdir:<parent>/"` identity: exits 0 and commits under it. (A relative `GIT_DIR` read
    from `cwd=target` named `newrepo/newrepo/.git`, which git refused outright.)"""
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
