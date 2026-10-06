"""#1204 — every run's stamp names the tenant knowledge revision it started with (O1, O4).

Runs read `settings/` (and, after #1108, lessons, queries and skills) from the tenant's own
knowledge clone, yet the stamp named only the PRODUCT commit. This suite pins the new field at
its reader (`capture_knowledge`), its one production write site (`run_common.materialize_run`)
and its wire (`RunProvenance.as_json` / `from_obj`). The fork check that consumes it is
`test_1204_family_knowledge.py`.

THE PYTHON NAME CONTRACT these tests fix (the implementation matches it):

* `defender._provenance.capture_knowledge(knowledge_dir: Path) -> KnowledgeRevision` — never
  raises, never runs a subprocess (git is not in the runtime image), never follows a link below
  `knowledge_dir`, never searches upward for a parent repo.
* `defender._provenance.KnowledgeRevision` — a frozen VALUE (equal when its variant and payload
  are equal) with three variants, built by
    - `KnowledgeRevision.at(commit: str)`            -> wire `{"commit": "<sha>"}`
    - `KnowledgeRevision.unversioned()`              -> wire `"unversioned"`
    - `KnowledgeRevision.unavailable_because(reason: str)` -> wire `{"unavailable": "<reason>"}`
  and carrying `.commit: str | None` (the sha, only on `at`), `.unavailable: str | None` (the
  reason, only on `unavailable_because`) and `.as_wire()` (the JSON-able wire value above).
* `RunProvenance.knowledge: KnowledgeRevision | None = None`. `as_json` always emits the key
  `"knowledge"`: the wire value, or `null` when the record does not say. `from_obj` folds any
  malformed knowledge value to `None` WITHOUT voiding the rest of the record.
* A commit is 40 or 64 LOWERCASE hex characters, after stripping surrounding whitespace; any
  other shape is unavailable when captured and malformed (-> `None`) when read back.

Assertions are on the WIRE shape (what `as_json` writes and what lands on disk), with attribute
reads kept to the three the contract names. New names are reached per test (`T.sym`), so a
missing one is one red per test rather than one collection error hiding the rest.

Every git fixture is a REAL repository built by the real `git` (through the `_git` facade, with
global and system config shut out so a contributor's `init.defaultBranch`, hooks or signing
cannot change what is built); every link is a real symlink whose target is a VALID ref holding
a VALID sha, so an implementation that followed it would return a commit and fail. The no-follow
refusals asserted here were first observed on the real primitive (`_io.bind` + `stat_entry`):
a link at `.git`, `.git/refs`, `.git/refs/heads`, a leaf ref or `HEAD` answers with a refusal
`reason`, never the target's bytes.

RED before #1204: `capture_knowledge`, `KnowledgeRevision` and `RunProvenance.knowledge` do not
exist, and the stamp has no `"knowledge"` key.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any

import pytest

from defender import _git, _provenance
from defender._episode_handle import Episode
from defender._provenance import RunProvenance
from defender.run_repository import RunPaths
from defender.tests import _triplet_947 as T
from defender.tests._data_root_1078 import FIXTURE, set_up_tenant


def _capture(knowledge_dir: Path) -> Any:
    return T.sym("_provenance", "capture_knowledge")(Path(knowledge_dir))


def _wire(knowledge_dir: Path) -> Any:
    """What `capture_knowledge` answers for `knowledge_dir`, as the wire value the stamp holds."""
    return _capture(knowledge_dir).as_wire()


def _revision() -> Any:
    return T.sym("_provenance", "KnowledgeRevision")


# ---------------------------------------------------------------------------------------
# Real-git fixtures
# ---------------------------------------------------------------------------------------


def _git_env() -> dict[str, str]:
    """The process environment minus the repo-locating variables, with global and system git
    config shut out and a fixed identity — so what `git` builds here does not depend on the
    machine (a global `init.defaultBranch`, `core.hooksPath` or `commit.gpgsign`)."""
    return {
        **_git.env_for_cwd(), "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
    }


def _g(cwd: Path, *args: str) -> str:
    return _git.git(list(args), cwd=Path(cwd), env=_git_env())


def _commit(repo: Path, content: str) -> str:
    """One more commit on whatever HEAD names; returns the new HEAD sha. The change lands in
    `README.md`, a name a tenant knowledge folder may hold at its top level, so a tenant built
    from one of these repos is still one `accept_tenant` admits."""
    (repo / "README.md").write_text(f"{content}\n", encoding="utf-8")
    _g(repo, "add", "-A")
    _g(repo, "commit", "-q", "-m", content)
    return _head(repo)


def _head(repo: Path) -> str:
    return _g(repo, "rev-parse", "HEAD")


def _repo(path: Path, *init_flags: str, commit: bool = True) -> Path:
    """A real repository on `main` at `path` (with one commit unless `commit=False`)."""
    path.mkdir(parents=True, exist_ok=True)
    _g(path, "init", "-q", "-b", "main", *init_flags)
    if commit:
        _commit(path, "first")
    return path


def _git_supports(*init_flags: str, tmp: Path) -> bool:
    """Can this host's git `init` with these flags (reftable needs >= 2.45, sha256 >= 2.29)?"""
    probe = Path(tempfile.mkdtemp(prefix="git-probe-", dir=tmp))
    return _git.git_ok(["init", "-q", *init_flags], cwd=probe, env=_git_env())


def _assert_unavailable(wire: Any, *, mentions: tuple[str, ...] = (),
                        never: tuple[str, ...] = ()) -> str:
    """`wire` is the UNAVAILABLE shape — not `"unversioned"`, not a commit — with a non-empty
    reason naming each of `mentions` (case-folded), and no sha in `never` anywhere in it.
    Returns the reason."""
    assert isinstance(wire, dict), f"expected {{'unavailable': <reason>}}, got {wire!r}"
    assert set(wire) == {"unavailable"}, f"expected {{'unavailable': <reason>}}, got {wire!r}"
    reason = wire["unavailable"]
    assert isinstance(reason, str), wire
    assert reason.strip(), wire
    for word in mentions:
        assert word.casefold() in reason.casefold(), (word, reason)
    text = json.dumps(wire)
    for sha in never:
        assert sha not in text, f"a commit the reader must not reach leaked into {wire!r}"
    return reason


# ---------------------------------------------------------------------------------------
# O1 / D1 — capture_knowledge over the ref layouts git really produces
# ---------------------------------------------------------------------------------------


def test_1204_a_clone_on_a_branch_names_the_commit_its_loose_ref_holds(tmp_path):
    """O1/D1: a tenant knowledge folder is a CLONE of the tenant's repo. `git clone` leaves HEAD
    as `ref: refs/heads/main`, the branch as a LOOSE ref file, and the remote-tracking refs in
    `packed-refs` — the commit is the loose ref's. Without this the field never names a commit
    at all, or names one read from the wrong place."""
    upstream = _repo(tmp_path / "upstream")
    upstream_head = _commit(upstream, "second")
    clone = tmp_path / "knowledge"
    _g(tmp_path, "clone", "-q", str(upstream), str(clone))
    assert (clone / ".git" / "refs" / "heads" / "main").is_file(), "precondition: a loose ref"
    assert _head(clone) == upstream_head

    assert _wire(clone) == {"commit": upstream_head}
    revision = _capture(clone)
    assert revision.commit == upstream_head
    assert revision.unavailable is None


def test_1204_a_packed_ref_is_read_past_the_header_and_the_peeled_lines(tmp_path):
    """O1/D1: after `git pack-refs --all` the branch has no loose file; its commit is the
    `packed-refs` line naming it — past the `# pack-refs with:` header, and never a `^` peeled
    line (an annotated tag's target). The fixture is built so that every plausible misread
    answers WRONG: the peeled lines and the tag object name older commits, and one peeled line
    sits BEFORE HEAD's own line (git peels every packed ref naming a tag object, and
    `refs/backup/v1` sorts before `refs/heads/`); a branch `ma` sorts first and is a prefix of
    `main`; a branch `a/refs/heads/main` sorts first and ends with the very name HEAD points
    at. Without this a packed clone (git packs on `gc`) stamps another branch's or a tag's
    sha."""
    repo = _repo(tmp_path / "knowledge")
    first = _head(repo)
    _g(repo, "tag", "-a", "v1", "-m", "an annotated tag on the first commit")
    tag_object = _g(repo, "rev-parse", "v1")
    _g(repo, "update-ref", "refs/backup/v1", "refs/tags/v1")
    _g(repo, "branch", "ma")
    _g(repo, "branch", "a/refs/heads/main")
    head = _commit(repo, "second")
    _g(repo, "pack-refs", "--all")

    assert not (repo / ".git" / "refs" / "heads" / "main").exists(), "precondition: packed"
    packed = (repo / ".git" / "packed-refs").read_text(encoding="utf-8")
    lines = packed.splitlines()
    assert lines[0].startswith("#"), packed
    peeled = [line[1:] for line in lines if line.startswith("^")]
    assert peeled == [first, first], packed
    assert head not in (first, tag_object), "precondition: a misread must give a WRONG answer"
    assert lines.index(f"^{first}") < lines.index(f"{head} refs/heads/main"), (
        "precondition: a peeled line precedes HEAD's ref line", packed)
    assert f"{first} refs/heads/a/refs/heads/main" in lines, packed
    assert f"{first} refs/heads/ma" in lines, packed
    assert lines.index(f"{first} refs/heads/ma") < lines.index(f"{head} refs/heads/main")

    assert _wire(repo) == {"commit": head}


def test_1204_a_loose_ref_written_after_packing_wins_over_the_stale_packed_line(tmp_path):
    """O1/D1: a commit made after `pack-refs` writes a fresh LOOSE ref while `packed-refs` keeps
    the old line — git reads the loose one, so the stamp must too. Without this a repacked clone
    that has since been pulled stamps the commit before the pull."""
    repo = _repo(tmp_path / "knowledge")
    _g(repo, "pack-refs", "--all")
    stale = _head(repo)
    head = _commit(repo, "after the pack")
    assert f"{stale} refs/heads/main" in (repo / ".git" / "packed-refs").read_text(
        encoding="utf-8"), "precondition: the packed line is stale"
    assert (repo / ".git" / "refs" / "heads" / "main").is_file()

    assert _wire(repo) == {"commit": head}


def test_1204_a_detached_head_names_the_sha_it_holds_not_the_branch(tmp_path):
    """O1/D1: `git checkout --detach <c>` writes the bare sha into HEAD; the commit is that sha
    even though `main` has moved on. Without this a detached clone stamps the branch tip."""
    repo = _repo(tmp_path / "knowledge")
    first = _head(repo)
    tip = _commit(repo, "second")
    _g(repo, "checkout", "-q", "--detach", first)
    assert (repo / ".git" / "HEAD").read_text(encoding="utf-8").strip() == first

    assert _wire(repo) == {"commit": first}
    assert tip not in json.dumps(_wire(repo))


def test_1204_a_sha256_repository_stamps_its_64_hex_commit(tmp_path):
    """Non-obligation made positive (SHA-256 repos are accepted): a repository made with
    `--object-format=sha256` has 64-hex object names, and its commit is stamped as-is."""
    if not _git_supports("--object-format=sha256", tmp=tmp_path):
        pytest.skip("this host's git cannot make a sha256 repository")
    repo = _repo(tmp_path / "knowledge", "--object-format=sha256")
    head = _head(repo)
    assert len(head) == 64, head

    assert _wire(repo) == {"commit": head}


def test_1204_the_commit_is_read_with_git_off_the_path(tmp_path, monkeypatch):
    """Decision 2 / C8: production runs where there is NO git binary (the runtime image), with
    the tenant clone's `.git/` mounted in. The commit is read from `.git`'s files, so emptying
    PATH changes nothing. Without this the field reads `unavailable` on every production run —
    the one environment it exists for."""
    repo = _repo(tmp_path / "knowledge")
    head = _commit(repo, "second")
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    assert shutil.which("git") is None, "precondition: git is off PATH"

    assert _wire(repo) == {"commit": head}


def test_1204_a_plain_folder_is_unversioned_and_a_repo_there_is_not(tmp_path):
    """O1/A1: a knowledge folder with no `.git` is `"unversioned"` — said, not guessed. The
    positive control is the SAME folder after `git init` + commit, which names its commit.
    Without the pair, `"unversioned"` could be a constant answer."""
    knowledge = tmp_path / "knowledge"
    shutil.copytree(FIXTURE, knowledge, symlinks=True)
    assert _wire(knowledge) == "unversioned"
    revision = _capture(knowledge)
    assert revision.commit is None
    assert revision.unavailable is None

    _repo(knowledge)
    assert _wire(knowledge) == {"commit": _head(knowledge)}


@pytest.mark.parametrize("between", [(), ("data",), ("data", "acme")],
                         ids=["depth-1", "depth-2", "depth-3"])
def test_1204_a_plain_folder_inside_another_repo_is_unversioned_not_the_parents_commit(
        tmp_path, between):
    """O1/A1/C7: no upward search, at ANY depth. A plain knowledge folder nested inside a git
    checkout — directly inside it, one folder down, or two (the dev layout, where the data root
    sits inside the product repo) — is `"unversioned"`, and the PARENT's sha appears nowhere in
    what is stamped. `git rev-parse` from inside it would answer the parent's commit (C7,
    executed), which is exactly the borrowed commit O1 forbids; a search bounded to a few
    levels up is still a search."""
    outer = _repo(tmp_path / "product")
    outer_head = _commit(outer, "product work")
    knowledge = outer.joinpath(*between, "knowledge")
    shutil.copytree(FIXTURE, knowledge, symlinks=True)
    assert _g(knowledge, "rev-parse", "HEAD") == outer_head, (
        "precondition: git itself would borrow the parent's commit here")

    wire = _wire(knowledge)
    assert wire == "unversioned"
    assert outer_head not in json.dumps(wire)


def test_1204_an_unborn_branch_is_unavailable_and_says_so(tmp_path):
    """O1/D1: `git init` with no commit leaves HEAD naming `refs/heads/main`, which exists
    nowhere (no loose file, no packed line). There is no commit to name, and the reason says
    the branch is unborn. The positive control is the same repo after its first commit."""
    repo = _repo(tmp_path / "knowledge", commit=False)
    assert (repo / ".git" / "HEAD").read_text(encoding="utf-8").strip() == "ref: refs/heads/main"
    _assert_unavailable(_wire(repo), mentions=("unborn",))

    head = _commit(repo, "first")
    assert _wire(repo) == {"commit": head}


def test_1204_a_head_naming_a_ref_that_is_nowhere_is_an_unborn_branch(tmp_path):
    """O1/D1: "ref named nowhere -> unavailable, unborn branch" holds for any branch name, not
    only the one `init` chose: a HEAD switched to a branch with no loose file and no packed line
    is unborn, and the existing branch's commit is not substituted for it."""
    repo = _repo(tmp_path / "knowledge")
    main_head = _head(repo)
    _g(repo, "pack-refs", "--all")
    assert _wire(repo) == {"commit": main_head}, "positive control: HEAD on main"
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/gone\n", encoding="utf-8")

    _assert_unavailable(_wire(repo), mentions=("unborn",), never=(main_head,))


def test_1204_a_reftable_repository_is_unavailable_naming_reftable(tmp_path):
    """O1/D1: a repository made with `--ref-format=reftable` keeps its refs in binary tables
    under `.git/reftable/`; on disk `HEAD` reads `ref: refs/heads/.invalid` and
    `.git/refs/heads` is a plain FILE. A files-backend reader that went HEAD-first would answer
    "unborn" or a walk refusal; the reason must name reftable, so an operator knows the fix is
    the repo's ref format — which forces the reftable check to precede ref resolution."""
    if not _git_supports("--ref-format=reftable", tmp=tmp_path):
        pytest.skip("this host's git (< 2.45) cannot make a reftable repository; the planted "
                    "directory case below still pins D1's rule")
    repo = _repo(tmp_path / "knowledge", "--ref-format=reftable")
    head = _head(repo)
    assert (repo / ".git" / "reftable").is_dir(), "precondition: a reftable repo"

    _assert_unavailable(_wire(repo), mentions=("reftable",), never=(head,))


def test_1204_a_reftable_directory_is_unavailable_even_beside_readable_loose_refs(tmp_path):
    """O1/D1 keys reftable on the PRESENCE of `.git/reftable/`, so this plants that directory in
    an otherwise ordinary files-backend repo whose loose ref still holds a valid sha. Legitimate
    rather than imagined: D1's rule is "reftable dir present -> unavailable", independent of
    whatever else `.git` holds, and this host-independent arm keeps that rule pinned where
    git is too old to make a reftable repo. The positive control is the same repo before the
    directory is planted."""
    repo = _repo(tmp_path / "knowledge")
    head = _head(repo)
    assert _wire(repo) == {"commit": head}

    (repo / ".git" / "reftable").mkdir()
    _assert_unavailable(_wire(repo), mentions=("reftable",), never=(head,))


@pytest.mark.parametrize("what", ["link", "file"])
def test_1204_a_non_directory_at_git_reftable_is_named_for_what_it_is(tmp_path, what):
    """O1/D1, one rule for every read's answer (review fix): `.git/reftable` decides the ref
    format only when a DIRECTORY is there. A link (no-follow: a link is present, whatever it
    points at) or a plain file at that name is not a reftable repository — it is unavailable
    with a reason naming what stands there, never the reftable-refs reason. The link's target
    is a real directory, so a reader that followed it would call this a reftable repo. The
    positive control is a real directory at the same name in the same repo, whose reason is
    the reftable one — and the two reasons differ."""
    repo = _repo(tmp_path / "knowledge")
    head = _head(repo)
    reftable = repo / ".git" / "reftable"
    reftable.mkdir()
    reftable_reason = _assert_unavailable(_wire(repo), mentions=("reftable",), never=(head,))
    reftable.rmdir()
    assert _wire(repo) == {"commit": head}, "positive control: nothing at .git/reftable"

    if what == "link":
        target = tmp_path / "a-real-directory"
        target.mkdir()
        reftable.symlink_to(target)
    else:
        reftable.write_text("not a ref table\n", encoding="utf-8")
    reason = _assert_unavailable(_wire(repo), mentions=("reftable",), never=(head,))
    assert reason != reftable_reason, reason
    named = ("link",) if what == "link" else ("file", "not a directory")
    assert any(word in reason.casefold() for word in named), (named, reason)


def test_1204_a_git_FILE_is_unavailable_and_its_gitdir_is_not_followed(tmp_path):
    """O1/A1/D1: `.git` that is not a real directory is not versioned-and-readable here. A
    `git worktree` (like a submodule) has a `.git` FILE reading `gitdir: <elsewhere>`; following
    it leaves the knowledge folder. Unavailable — not `"unversioned"`, which would claim there
    is no repo — and the main repo's commit is not reached. The positive control is the main
    repo itself."""
    main = _repo(tmp_path / "main")
    head = _head(main)
    worktree = tmp_path / "knowledge"
    _g(main, "worktree", "add", "-q", "--detach", str(worktree))
    assert (worktree / ".git").is_file(), "precondition: a gitfile"
    assert _head(worktree) == head, "precondition: git itself follows it to a valid commit"

    _assert_unavailable(_wire(worktree), never=(head,))
    assert _wire(main) == {"commit": head}


#: The entries a no-follow reader must refuse to traverse, each replaced by a link to the SAME
#: entry in a real repo. `.git/packed-refs` is linked in a packed repo so its line is the only
#: place the commit is.
LINKED = {
    ".git": False,
    ".git/refs": False,
    ".git/refs/heads": False,
    ".git/refs/heads/main": False,
    ".git/HEAD": False,
    ".git/packed-refs": True,
}


@pytest.mark.parametrize("linked", sorted(LINKED))
def test_1204_a_link_anywhere_on_the_read_path_is_unavailable_and_never_followed(
        tmp_path, linked):
    """O1/D1/C16: every read below the knowledge folder is no-follow on EVERY component, not
    only the last. Each arm builds a knowledge `.git` as a byte-for-byte copy of a real repo's
    (the positive control: it names that commit), then replaces one entry with a symlink to the
    same entry in that real repo — so a reader that followed the link would get a valid ref
    holding a valid sha and answer it. Unavailable, not `"unversioned"`, and the sha is not in
    the stamp. Without this `.git/refs` linked to another tenant's clone stamps that tenant's
    commit."""
    real = _repo(tmp_path / "real")
    head = _commit(real, "second")
    if LINKED[linked]:
        _g(real, "pack-refs", "--all")
        assert not (real / ".git" / "refs" / "heads" / "main").exists()
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    shutil.copytree(real / ".git", knowledge / ".git", symlinks=True)
    assert _wire(knowledge) == {"commit": head}, "positive control: the plain copy"

    planted = knowledge / linked
    if planted.is_dir() and not planted.is_symlink():
        shutil.rmtree(planted)
    else:
        planted.unlink()
    planted.symlink_to(real / linked)
    assert planted.is_symlink()

    _assert_unavailable(_wire(knowledge), never=(head,))


def test_1204_a_linked_folder_of_a_slashed_branch_is_unavailable_and_never_followed(tmp_path):
    """O1/D1/C16: no-follow holds on EVERY component of whatever ref HEAD names, not on a fixed
    list of names. HEAD is on the slashed branch `team/x`, so its loose ref sits under a folder
    `refs/heads/team/` that no fixed list mentions; that folder is replaced by a link into
    ANOTHER repository whose `refs/heads/team/x` holds a valid sha of its own. A reader that
    followed it would stamp the other repository's commit. Unavailable, neither sha stamped;
    the positive control is the same copy before the link is planted."""
    real = _repo(tmp_path / "real")
    _g(real, "checkout", "-q", "-b", "team/x")
    head = _commit(real, "on team/x")
    other = _repo(tmp_path / "other")
    _g(other, "checkout", "-q", "-b", "team/x")
    other_head = _commit(other, "the other repository's team/x")
    assert other_head != head
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    shutil.copytree(real / ".git", knowledge / ".git", symlinks=True)
    assert (knowledge / ".git" / "HEAD").read_text(encoding="utf-8").strip() == (
        "ref: refs/heads/team/x")
    assert _wire(knowledge) == {"commit": head}, "positive control: the plain copy"

    team = knowledge / ".git" / "refs" / "heads" / "team"
    shutil.rmtree(team)
    team.symlink_to(other / ".git" / "refs" / "heads" / "team")
    assert (team / "x").read_text(encoding="utf-8").strip() == other_head, (
        "precondition: following the link reaches a valid ref")

    _assert_unavailable(_wire(knowledge), never=(head, other_head))


def test_1204_a_linked_loose_ref_is_not_read_as_absent_and_the_stale_packed_line_is_not_used(
        tmp_path):
    """O1/D1: "the loose ref, ELSE the packed-refs line" falls through only when the loose ref
    is ABSENT. A loose ref that is there but refused (a link) shadows the packed line exactly
    as git's own loose-over-packed rule does — so the stale packed commit beneath it is not
    stamped either. Built from real git: pack at the first commit, commit again (a fresh loose
    ref over a stale packed line), copy, then link the loose ref back to the real one."""
    real = _repo(tmp_path / "real")
    _g(real, "pack-refs", "--all")
    stale = _head(real)
    head = _commit(real, "second")
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    shutil.copytree(real / ".git", knowledge / ".git", symlinks=True)
    assert _wire(knowledge) == {"commit": head}, "positive control: the plain copy"
    loose = knowledge / ".git" / "refs" / "heads" / "main"
    loose.unlink()
    loose.symlink_to(real / ".git" / "refs" / "heads" / "main")

    _assert_unavailable(_wire(knowledge), never=(head, stale))


@pytest.mark.parametrize("head_bytes", [
    b"", b"\n", b"garbage\n", b"ref:\n", b"ref: \n", b"ref: refs/heads/\n",
    b"ref: refs/heads/../../../outside\n", b"ref: /ABSOLUTE\n",
    b"ref: refs/heads/ma\x00in\n", b"\xff\xfe not utf-8\n", b"ref: ORIG_HEAD\n",
    b"ref: refs/../ORIG_HEAD\n", b"ref: refs/heads/main\xff\n",
], ids=["empty", "newline", "garbage", "ref-colon", "ref-blank", "ref-dir", "ref-dotdot",
        "ref-absolute", "ref-nul", "not-utf8", "ref-outside-refs", "ref-dotdot-inside-git",
        "ref-undecodable"])
def test_1204_a_malformed_head_is_unavailable_and_never_raises(tmp_path, head_bytes):
    """O1/O4/D1: anything in HEAD that is neither `ref: refs/<name>` nor a bare sha is
    unavailable with a reason — never a raise (a raise out of the stamp would take the run
    down), never a guess. The traversal arms point at a file OUTSIDE `.git` that holds a valid
    sha (`..` and an absolute name), so a reader that resolved them as paths would stamp it;
    `ref: ORIG_HEAD` names a file inside `.git` that also holds one but is not a ref under
    `refs/` (git itself refuses to point HEAD outside `refs/`), and `ref: refs/../ORIG_HEAD`
    reaches the same file by a `..` that never leaves `.git` — so a containment check on the
    normalised path does not catch it. `ref: refs/heads/main\\xff` is the real ref's name with
    an undecodable byte after it: a reader that decoded leniently would resolve `main`. The
    positive control is the same repo with its real HEAD."""
    repo = _repo(tmp_path / "knowledge")
    head = _head(repo)
    assert _wire(repo) == {"commit": head}
    (repo / "outside").write_text(head + "\n", encoding="utf-8")
    (repo / ".git" / "ORIG_HEAD").write_text(head + "\n", encoding="utf-8")
    absolute = tmp_path / "ABSOLUTE"
    absolute.write_text(head + "\n", encoding="utf-8")
    payload = head_bytes.replace(b"/ABSOLUTE", os.fsencode(absolute))

    (repo / ".git" / "HEAD").write_bytes(payload)
    _assert_unavailable(_wire(repo), never=(head,))


#: The three places a commit is read from, by the ref layout that makes each the one read.
READ_SITES = ("HEAD", "loose-ref", "packed-refs")
#: Faults a real filesystem can put at a read site: bytes that do not decode, a directory, and
#: a FIFO — which a plain `open()` + read blocks on until something writes to it.
SITE_FAULTS = ("undecodable", "directory", "fifo")

#: How long a capture may take before it counts as hung. Generous: a capture is a few small
#: reads, so anything near this is a reader waiting on a FIFO, not a slow disk.
CAPTURE_TIME_BOUND_S = 10.0


def _plant_site_fault(repo: Path, site: str, fault: str, head: str) -> Path:
    """Replace the entry `site` names in a real repo with `fault`; returns its path. For the
    packed site the repo is packed first, so `packed-refs` is the only place the commit is.
    The undecodable bytes sit where a LENIENT decode (`errors="ignore"`) would still read the
    real commit or the real ref name — so only a strict reader answers unavailable."""
    git_dir = repo / ".git"
    if site == "packed-refs":
        _g(repo, "pack-refs", "--all")
        assert not (git_dir / "refs" / "heads" / "main").exists()
    path = {"HEAD": git_dir / "HEAD", "loose-ref": git_dir / "refs" / "heads" / "main",
            "packed-refs": git_dir / "packed-refs"}[site]
    path.unlink()
    if fault == "directory":
        path.mkdir()
    elif fault == "fifo":
        os.mkfifo(path)
    else:
        path.write_bytes({
            "HEAD": b"ref: refs/heads/main\xff\n",
            "loose-ref": head.encode() + b"\xff\n",
            "packed-refs": (b"# pack-refs with: peeled fully-peeled sorted \n"
                            + f"{head} refs/heads/main".encode() + b"\xff\n"),
        }[site])
    return path


def _capture_within_bound(knowledge: Path, fifo: Path | None = None) -> Any:
    """`capture_knowledge(knowledge)`'s wire value, taken on a thread and given
    `CAPTURE_TIME_BOUND_S` to answer: a reader still blocked after that fails the test (the
    stamp is taken before the box starts, so a hang there is a run that never starts). Anything
    the capture RAISES fails it too. A FIFO a hung reader is waiting on is opened for writing
    afterwards, which releases the reader so the thread does not outlive the test."""
    outcome: dict[str, Any] = {}

    def capture() -> None:
        try:
            outcome["wire"] = _wire(knowledge)
        except BaseException as e:  # noqa: BLE001 — reported by the assertion below
            outcome["raised"] = e

    worker = threading.Thread(target=capture, daemon=True)
    worker.start()
    worker.join(CAPTURE_TIME_BOUND_S)
    hung = worker.is_alive()
    if hung and fifo is not None:
        with contextlib.suppress(OSError):
            os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        worker.join(CAPTURE_TIME_BOUND_S)
    assert not hung, (f"capture_knowledge was still blocked after {CAPTURE_TIME_BOUND_S}s "
                      f"(a FIFO opened and read like a file)")
    assert "raised" not in outcome, f"capture_knowledge raised {outcome.get('raised')!r}"
    return outcome["wire"]


@pytest.mark.parametrize("fault", SITE_FAULTS)
@pytest.mark.parametrize("site", READ_SITES)
def test_1204_a_fault_at_any_read_site_is_unavailable_promptly_and_never_raises(
        tmp_path, site, fault):
    """O1/O4/D1 at EVERY place a commit is read — HEAD, the loose ref HEAD names, and
    `packed-refs` — not only at HEAD: bytes that do not decode, a directory where a file
    belongs, and a FIFO are each unavailable, answered within a time bound, never raised, and
    the real commit is not stamped. A decode error or `IsADirectoryError` raised out of the
    capture would take the stamp down with it; a FIFO read like a file blocks run start
    forever. The positive control is the same repo before the fault is planted."""
    repo = _repo(tmp_path / "knowledge")
    head = _head(repo)
    assert _wire(repo) == {"commit": head}, "positive control: the real layout"
    planted = _plant_site_fault(repo, site, fault, head)

    wire = _capture_within_bound(repo, fifo=planted if fault == "fifo" else None)
    _assert_unavailable(wire, never=(head,))


def test_1204_a_missing_or_non_file_head_is_unavailable(tmp_path):
    """O1/O4: a `.git` directory with no HEAD, or with a DIRECTORY at HEAD, cannot name a
    commit; unavailable, never a raise."""
    repo = _repo(tmp_path / "knowledge")
    head = _head(repo)
    assert _wire(repo) == {"commit": head}, "positive control: the real HEAD"
    (repo / ".git" / "HEAD").unlink()
    _assert_unavailable(_wire(repo), never=(head,))
    (repo / ".git" / "HEAD").mkdir()
    _assert_unavailable(_wire(repo), never=(head,))


def test_1204_a_knowledge_folder_that_is_missing_or_a_file_is_unavailable(tmp_path):
    """O1/O4, one rule for every read's answer (review fix): `"unversioned"` is a statement
    ABOUT a folder — it is there, and it is not a repository — so a knowledge folder that does
    not exist is unavailable, with a reason saying it is missing, not "unversioned"; a FILE at
    the knowledge path is unavailable too. Neither raises. The positive control is an existing
    plain folder, which is `"unversioned"`."""
    plain = tmp_path / "plain"
    plain.mkdir()
    assert _wire(plain) == "unversioned", "positive control: a folder that is there"

    missing = _assert_unavailable(_wire(tmp_path / "nowhere"))
    assert any(word in missing.casefold()
               for word in ("missing", "absent", "does not exist", "no such")), missing
    as_file = tmp_path / "a-file"
    as_file.write_text("not a folder\n", encoding="utf-8")
    _assert_unavailable(_wire(as_file))


#: Where a sha can be written: a detached HEAD, a loose ref, a packed-refs line.
SHA_SITES = ("detached-head", "loose-ref", "packed-ref")


def _plant_sha(repo: Path, site: str, sha: str) -> None:
    """Put `sha` where `site` says, in a real repo, as the ONLY place HEAD's commit is read.
    The packed site rewrites the `refs/heads/main` line of a `packed-refs` that real git wrote
    (the test packs once, up front — git itself would refuse to re-pack over a malformed
    line)."""
    git_dir = repo / ".git"
    if site == "detached-head":
        (git_dir / "HEAD").write_text(sha + "\n", encoding="utf-8")
    elif site == "loose-ref":
        (git_dir / "refs" / "heads" / "main").write_text(sha + "\n", encoding="utf-8")
    else:
        packed = git_dir / "packed-refs"
        lines = packed.read_text(encoding="utf-8").splitlines()
        hits = [i for i, line in enumerate(lines)
                if line.endswith(" refs/heads/main") and not line.startswith("#")]
        assert len(hits) == 1, lines
        lines[hits[0]] = f"{sha} refs/heads/main"
        packed.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.mark.parametrize("site", SHA_SITES)
def test_1204_only_a_40_or_64_lowercase_hex_sha_is_a_commit(tmp_path, site):
    """D1 + non-obligation: a commit is 40 or 64 LOWERCASE hex characters at every place one
    is read. Uppercase hex (which `git rev-parse` itself accepts), an abbreviation, one
    character short or long, non-hex of the right length and a sha split by a space are
    unavailable. The positive controls, at the same site of the same repo, are the real sha and
    a 64-hex value — and, where the value is a whole file (HEAD, a loose ref), the real sha
    with surrounding whitespace, which D1 strips."""
    repo = _repo(tmp_path / f"knowledge-{site}")
    head = _head(repo)
    if site == "packed-ref":
        _g(repo, "pack-refs", "--all")
        assert not (repo / ".git" / "refs" / "heads" / "main").exists()
    goods = [(head, head), ("a" * 64, "a" * 64)]
    if site != "packed-ref":
        goods.append((f" {head}\t\r", head))
    for good, expected in goods:
        _plant_sha(repo, site, good)
        assert _wire(repo) == {"commit": expected}, (site, good)
    for bad in (head.upper(), head[:7], head[:39], head + "0", "g" * 40, "a" * 63, "a" * 65,
                head[:20] + " " + head[20:]):
        _plant_sha(repo, site, bad)
        _assert_unavailable(_wire(repo))


# ---------------------------------------------------------------------------------------
# O1 / D3 — the one production write site: materialize_run -> _stamp
# ---------------------------------------------------------------------------------------

TENANT_ID = "acme"


def _tenant_with_knowledge(tmp_path: Path, monkeypatch, *, versioned: bool) -> tuple[Any, str]:
    """A fresh data root holding one tenant set up from the committed fixture (#1120), its
    knowledge folder either a real git CLONE of the tenant's repo (`versioned`) or the plain
    copy every other suite uses (`_data_root_1078.set_up_tenant`, C11). The clone is placed
    BEFORE the tenant is accepted, so the real `accept_tenant` admits it (C10: `.git` is a
    permitted top-level name and is never walked). Returns the accepted `Tenant` and the
    clone's HEAD (`""` for the plain copy)."""
    data_root = tmp_path / "data"
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(data_root))
    knowledge = data_root / TENANT_ID / "knowledge"
    head = ""
    if versioned:
        upstream = tmp_path / "tenant-repo"
        shutil.copytree(FIXTURE, upstream, symlinks=True)
        _repo(upstream)
        head = _commit(upstream, "the tenant's own change")
        knowledge.parent.mkdir(parents=True)
        _g(tmp_path, "clone", "-q", str(upstream), str(knowledge))
        # Uncommitted, as `scaffold` leaves it: the stamp names HEAD regardless (no dirty bit
        # for knowledge, decision 1).
        (knowledge / "agent" / ".tenant-id").write_text(f"{TENANT_ID}\n", encoding="utf-8")
    tenant = set_up_tenant(data_root, TENANT_ID)
    assert tenant.knowledge == knowledge
    assert (knowledge / ".git").is_dir() is versioned
    return tenant, head


def _materialise(tmp_path: Path, tenant: Any, run_id: str) -> tuple[Path, dict]:
    """One run through the real `materialize_run`, and its stamp as the JSON on disk."""
    from defender import run_common

    alert = tmp_path / f"{run_id}.alert.json"
    alert.write_text(json.dumps({"id": run_id}), encoding="utf-8")
    run_dir = run_common.materialize_run(alert, run_id, tenant=tenant).run_dir
    stamp = RunPaths(run_dir).provenance
    assert stamp.is_file(), "the run was not stamped at all"
    return run_dir, json.loads(stamp.read_text(encoding="utf-8"))


def test_1204_a_run_on_a_versioned_tenant_stamps_its_knowledge_clones_commit(
        tmp_path, monkeypatch):
    """O1/D3 at the ONE place every executed run is stamped (`materialize_run` -> `_stamp`,
    fork siblings included): the written `provenance.json` carries `"knowledge": {"commit":
    <the tenant clone's HEAD>}` beside the product `commit`, and the two differ — so a stamp
    that borrowed the product's commit (or the build stamp's) cannot pass. The record reads
    back with the same revision. Not via the e2e replay harness, which writes its own stamp
    (C15)."""
    tenant, knowledge_head = _tenant_with_knowledge(tmp_path, monkeypatch, versioned=True)
    run_dir, doc = _materialise(tmp_path, tenant, "20260101t000000z-versioned")

    assert doc["knowledge"] == {"commit": knowledge_head}
    assert doc["commit"] != knowledge_head, "the knowledge commit is the PRODUCT's"
    assert doc["tenant_id"] == TENANT_ID
    record = _provenance.read(RunPaths(run_dir).provenance)
    assert record is not None
    assert record.knowledge == _revision().at(knowledge_head)


def test_1204_a_run_on_a_plain_copy_tenant_stamps_unversioned(tmp_path, monkeypatch):
    """O1/D3, the negative beside the positive above on the same entry point: a tenant whose
    knowledge is a plain copy (every test tenant today, C11) is stamped `"unversioned"` — said
    explicitly — never `null`, never a commit. Without the pair a writer that always wrote
    `"unversioned"` (or always the product's commit) would pass one of the two."""
    tenant, _ = _tenant_with_knowledge(tmp_path, monkeypatch, versioned=False)
    _run_dir, doc = _materialise(tmp_path, tenant, "20260101t000000z-plain")

    assert doc["knowledge"] == "unversioned"
    assert doc["tenant_id"] == TENANT_ID


def test_1204_an_unreadable_knowledge_git_stamps_unavailable_and_the_run_goes_on(
        tmp_path, monkeypatch):
    """O4 at the write site: stamping never takes a run down. The tenant's `.git` is replaced
    after acceptance by a gitfile naming nowhere — the run is still materialised, its stamp is
    still written with the product's fields, and `knowledge` says unavailable."""
    tenant, _ = _tenant_with_knowledge(tmp_path, monkeypatch, versioned=True)
    git_dir = tenant.knowledge / ".git"
    shutil.rmtree(git_dir)
    git_dir.write_text(f"gitdir: {tmp_path / 'nowhere'}\n", encoding="utf-8")

    _run_dir, doc = _materialise(tmp_path, tenant, "20260101t000000z-gitfile")
    _assert_unavailable(doc["knowledge"])
    assert doc["commit"] is not None or doc["unavailable"] is not None
    assert doc["tenant_id"] == TENANT_ID


@pytest.mark.parametrize("fault", ["undecodable", "directory"])
def test_1204_a_read_fault_inside_the_knowledge_git_still_writes_the_whole_stamp(
        tmp_path, monkeypatch, fault):
    """O4 at the write site, for faults that are NOT a gitfile: the clone's loose ref is
    replaced (after acceptance) by bytes that do not decode, or by a directory. A decode error
    is not an `OSError`, and an `IsADirectoryError` is one `_stamp` swallows as "could not
    stamp" — either way a capture that RAISED would leave the run unstamped or crash it. The
    run is materialised, its stamp is written, the product's fields are the product's capture,
    and `knowledge` says unavailable without naming the clone's commit."""
    from defender import run_common

    tenant, knowledge_head = _tenant_with_knowledge(tmp_path, monkeypatch, versioned=True)
    _plant_site_fault(tenant.knowledge, "loose-ref", fault, knowledge_head)
    product = _provenance.capture_tree(run_common.REPO_ROOT)

    _run_dir, doc = _materialise(tmp_path, tenant, f"20260101t000000z-{fault}")
    _assert_unavailable(doc["knowledge"], never=(knowledge_head,))
    assert doc["commit"] == product.commit
    assert doc["scope"] == _provenance.CODE_SCOPE
    assert doc["tenant_id"] == TENANT_ID


def test_1204_a_fork_sibling_materialised_through_the_real_path_stamps_the_clones_commit(
        tmp_path, monkeypatch):
    """O1/D3/C3: "every executed run, fork siblings included" — a branched sibling is a `run.py
    --resume` process that reaches the same `materialize_run`, with a `ResumeWorld` resolved
    from its episode's manifest. Stamped on a versioned tenant, the SIBLING's stamp carries
    `{"commit": <the clone's HEAD>}` beside its lineage (world, source run, branch point) — so
    `verify_family` has a knowledge commit to compare on every real sibling, not only on
    unforked runs. Without this a writer that skipped knowledge on the fork path would leave
    every real family with knowledge-absent siblings (waivable), and the anchor would never
    bite."""
    from defender import run_common
    from defender.tests.tenant_1078_pass_a import _spec1078 as H

    tenant, knowledge_head = _tenant_with_knowledge(tmp_path, monkeypatch, versioned=True)
    data_root = tmp_path / "data"
    _base, src = H.tenant_source(data_root, TENANT_ID, row=False)
    episode_dir = tmp_path / "episodes" / T.EPISODE_ID
    manifest = H.family_for(src, episode_dir)
    world = H.run_py().resume_world(
        Episode.open(manifest.parent), "b",
        tenant=lambda: H.T1106.run_tenant(H.accept(data_root, TENANT_ID)))

    run_dir = run_common.materialize_run(
        src / "alert.json", world.run_id, tenant=tenant, world=world).run_dir
    assert run_dir.parent == episode_dir / "runs", "precondition: the fork path, not a fresh run"
    doc = json.loads(RunPaths(run_dir).provenance.read_text(encoding="utf-8"))
    assert doc["world_id"] == world.world_id
    assert doc["parent_run_id"] == world.family.source_run_id
    assert doc["fork_turn"] == world.family.branch_message_id
    assert doc["knowledge"] == {"commit": knowledge_head}


# ---------------------------------------------------------------------------------------
# D2 / O4 — the wire, and a bad knowledge value never voids the stamp
# ---------------------------------------------------------------------------------------

#: A record with EVERY field set to a non-default value, so "everything else intact" is a claim
#: about eleven fields rather than about two.
RICH: dict[str, Any] = {
    "commit": "a" * 40, "dirty": True, "dirty_paths": ["x.md", "y.md"], "dirty_path_count": 3,
    "unavailable": "git status: a note beside the dirt", "scope": "defender", "model": "m-1",
    "tenant_id": "acme", "world_id": "20260728t161845z-fresh-case-n59.b",
    "parent_run_id": "20260728T161845Z-fresh-case", "fork_turn": 59,
}

SHA = "b" * 40

#: Every malformed knowledge value, by name. Each must fold to `knowledge=None` and leave the
#: rest of the record exactly as it was.
MALFORMED: dict[str, Any] = {
    "empty commit": {"commit": ""},
    "blank commit": {"commit": "   "},
    "both keys": {"commit": SHA, "unavailable": "x"},
    "non-hex commit": {"commit": "nothex" + "0" * 34},
    "uppercase commit": {"commit": SHA.upper()},
    "abbreviated commit": {"commit": SHA[:7]},
    "39-hex commit": {"commit": SHA[:39]},
    "41-hex commit": {"commit": SHA + "b"},
    "63-hex commit": {"commit": "c" * 63},
    "65-hex commit": {"commit": "c" * 65},
    "int commit": {"commit": 42},
    "null commit": {"commit": None},
    "list commit": {"commit": [SHA]},
    "int reason": {"unavailable": 42},
    "null reason": {"unavailable": None},
    "empty object": {},
    "unknown extra key beside a commit": {"commit": SHA, "dirty": False},
    "unknown key alone": {"revision": SHA},
    "a list": [SHA],
    "another string": "versioned",
    "unversioned, shouted": "UNVERSIONED",
    "an int": 42,
    "a bool": True,
}

#: Every valid wire value. Each reads back as itself.
VALID: dict[str, Any] = {
    "a 40-hex commit": {"commit": SHA},
    "a 64-hex commit": {"commit": "c" * 64},
    "unversioned": "unversioned",
    "unavailable": {"unavailable": "reftable refs are not read here"},
}


def _without_knowledge() -> dict[str, Any]:
    return json.loads(json.dumps(RICH))


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_1204_a_malformed_knowledge_value_folds_to_none_and_keeps_every_other_field(
        tmp_path, name):
    """O4/D2: the stamp sits in the box's rw bind, so its knowledge value is arbitrary on read.
    A malformed one folds to `knowledge=None` BEFORE the record is built — it never trips
    `__post_init__`'s refusal, which voids the WHOLE record (C17) — and every other field reads
    back exactly as written, off disk through the guarded reader as through `from_obj`.
    Without this one forged knowledge value would erase the product commit the fork check
    and the judge depend on."""
    doc = {**_without_knowledge(), "knowledge": MALFORMED[name]}
    record = RunProvenance.from_obj(doc)
    assert record is not None, "a bad knowledge value voided the whole stamp"
    assert record.knowledge is None, record.knowledge
    assert json.loads(record.as_json()) == {**RICH, "knowledge": None}
    assert record == RunProvenance.from_obj(_without_knowledge())

    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert _provenance.read(path) == record


@pytest.mark.parametrize("name", sorted(VALID))
def test_1204_each_valid_knowledge_value_reads_back_as_itself(tmp_path, name):
    """The positive control for the folding above, on the same record: each of the three wire
    shapes (both sha lengths) reads back as itself, is written back out verbatim by `as_json`,
    and survives the guarded write/read round trip. Without it, folding EVERY knowledge value
    to `None` would pass the arm above."""
    doc = {**_without_knowledge(), "knowledge": VALID[name]}
    record = RunProvenance.from_obj(doc)
    assert record is not None
    assert record.knowledge is not None
    assert record.knowledge.as_wire() == VALID[name]
    assert json.loads(record.as_json()) == {**RICH, "knowledge": VALID[name]}

    path = tmp_path / "provenance.json"
    _provenance.write(path, record)
    assert json.loads(path.read_text(encoding="utf-8"))["knowledge"] == VALID[name]
    assert _provenance.read(path) == record


def test_1204_a_stamp_that_does_not_say_writes_null_and_an_old_stamp_reads_as_none():
    """D2: `as_json` always emits the `"knowledge"` key — `null` for a record that does not say
    — and a stamp written before #1204 (no key at all) reads back as `knowledge=None` with
    every other field intact, as does an explicit `null`. Without the first a missing key could
    mean "old writer" or "new writer, no answer"; without the second every pre-#1204 run
    becomes unreadable."""
    on_disk = json.loads(RunProvenance(commit="a" * 40, dirty=False).as_json())
    assert "knowledge" in on_disk, on_disk
    assert on_disk["knowledge"] is None, on_disk
    for old in (_without_knowledge(), {**_without_knowledge(), "knowledge": None}):
        record = RunProvenance.from_obj(old)
        assert record is not None
        assert record.knowledge is None
        assert json.loads(record.as_json()) == {**RICH, "knowledge": None}


def test_1204_the_three_constructors_build_the_three_wire_shapes():
    """The contract's surface, held to its wire: `at`, `unversioned` and `unavailable_because`
    build exactly the three shapes, carry `.commit`/`.unavailable` only on their own variant,
    compare as values, and are frozen. Without the value equality a record read back off disk
    would never equal the one written."""
    revision = _revision()
    at = revision.at(SHA)
    assert at.as_wire() == {"commit": SHA}
    assert (at.commit, at.unavailable) == (SHA, None)
    unversioned = revision.unversioned()
    assert unversioned.as_wire() == "unversioned"
    assert (unversioned.commit, unversioned.unavailable) == (None, None)
    unavailable = revision.unavailable_because("unborn branch")
    assert unavailable.as_wire() == {"unavailable": "unborn branch"}
    assert (unavailable.commit, unavailable.unavailable) == (None, "unborn branch")

    assert revision.at(SHA) == at
    assert revision.at("c" * 40) != at
    assert revision.unversioned() == unversioned != at
    assert revision.unavailable_because("unborn branch") == unavailable
    assert revision.unavailable_because("reftable") != unavailable
    with pytest.raises(AttributeError):
        at.commit = "c" * 40
