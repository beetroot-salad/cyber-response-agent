from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import contextlib
import json
import os
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender.records import _provenance
from defender.records._provenance import RunProvenance
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.shared.contracts._data_root_1078 import FIXTURE


def _capture(knowledge_dir: Path) -> Any:
    return T.sym("records._provenance", "capture_knowledge")(Path(knowledge_dir))


def _wire(knowledge_dir: Path) -> Any:
    """What `capture_knowledge` answers for `knowledge_dir`, as the wire value the stamp holds."""
    return _capture(knowledge_dir).as_wire()


def _revision() -> Any:
    return T.sym("records._provenance", "KnowledgeRevision")


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


def test_1204_a_clone_on_a_branch_names_the_commit_its_loose_ref_holds(tmp_path):
    """O1/D1."""
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
    """O1/D1."""
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
    """Decision 2 / C8."""
    repo = _repo(tmp_path / "knowledge")
    head = _commit(repo, "second")
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    assert shutil.which("git") is None, "precondition: git is off PATH"

    assert _wire(repo) == {"commit": head}


def test_1204_a_plain_folder_is_unversioned_and_a_repo_there_is_not(tmp_path):
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
    """O1/A1/C7."""
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
    repo = _repo(tmp_path / "knowledge", commit=False)
    assert (repo / ".git" / "HEAD").read_text(encoding="utf-8").strip() == "ref: refs/heads/main"
    _assert_unavailable(_wire(repo), mentions=("unborn",))

    head = _commit(repo, "first")
    assert _wire(repo) == {"commit": head}


def test_1204_a_head_naming_a_ref_that_is_nowhere_is_an_unborn_branch(tmp_path):
    repo = _repo(tmp_path / "knowledge")
    main_head = _head(repo)
    _g(repo, "pack-refs", "--all")
    assert _wire(repo) == {"commit": main_head}, "positive control: HEAD on main"
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/gone\n", encoding="utf-8")

    _assert_unavailable(_wire(repo), mentions=("unborn",), never=(main_head,))


def test_1204_a_reftable_repository_is_unavailable_naming_reftable(tmp_path):
    """O1/D1."""
    if not _git_supports("--ref-format=reftable", tmp=tmp_path):
        pytest.skip("this host's git (< 2.45) cannot make a reftable repository; the planted "
                    "directory case below still pins D1's rule")
    repo = _repo(tmp_path / "knowledge", "--ref-format=reftable")
    head = _head(repo)
    assert (repo / ".git" / "reftable").is_dir(), "precondition: a reftable repo"

    _assert_unavailable(_wire(repo), mentions=("reftable",), never=(head,))


def test_1204_a_git_FILE_is_unavailable_and_its_gitdir_is_not_followed(tmp_path):
    """O1/A1/D1."""
    main = _repo(tmp_path / "main")
    head = _head(main)
    worktree = tmp_path / "knowledge"
    _g(main, "worktree", "add", "-q", "--detach", str(worktree))
    assert (worktree / ".git").is_file(), "precondition: a gitfile"
    assert _head(worktree) == head, "precondition: git itself follows it to a valid commit"

    _assert_unavailable(_wire(worktree), never=(head,))
    assert _wire(main) == {"commit": head}


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
    """O1/D1/C16."""
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
    """O1/D1/C16."""
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
    """O1/D1."""
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
    """Replace the entry `site` names in a real repo with `fault`;"""
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
    `CAPTURE_TIME_BOUND_S` to answer."""
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
    `packed-refs` — not only at HEAD."""
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
    """O1/O4, one rule for every read's answer (review fix)."""
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
    """Put `sha` where `site` says, in a real repo, as the ONLY place HEAD's commit is read."""
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
    """D1 + non-obligation."""
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


# #1108 P4 (OD12 class i): six cases here drove `materialize_run` over an accepted tenant and
# pinned its stamp's `knowledge` field to what the TENANT CLONE's `.git` said at that moment —
# `test_1204_a_run_on_a_versioned_tenant_stamps_its_knowledge_clones_commit`,
# `test_1204_a_run_on_a_plain_copy_tenant_stamps_unversioned`,
# `test_1204_an_unreadable_knowledge_git_stamps_unavailable_and_the_run_goes_on`,
# `test_1204_a_read_fault_inside_the_knowledge_git_still_writes_the_whole_stamp[undecodable|directory]`
# and `test_1204_a_fork_sibling_materialised_through_the_real_path_stamps_the_clones_commit`.
# P4 removes that mechanism: the run process reads nothing of the clone (census,
# `tests/tenancy/tenant_1108_p4/test_census.py::test_the_run_process_reads_nothing_from_the_tenant_clone`)
# and a run's knowledge stamp is the export it copied — never the clone's HEAD, and never a
# plain copy (a tenant is published, hence versioned, before any run reads it; with no export
# the run is refused before message zero). Successors:
# `tests/tenancy/tenant_1108_p4/test_run_start.py::test_o_b_the_stamp_is_the_export_copied_never_the_clones_head`,
# `tests/tenancy/tenant_1108_p4/test_run_start.py::test_o_a_no_current_and_a_failed_publish_refuses_before_message_zero`,
# `tests/tenancy/tenant_1108_p4/test_run_start.py::test_o_pin_a_pinned_launch_reads_that_export_skips_publish_and_records_pinned`
# (siblings: the launcher's `--knowledge-commit` is the pin, owner ruling 3), and
# `tests/tenancy/tenant_1108_p4/test_branch_replay.py::test_o_b_the_live_capture_stamps_the_pinned_export_so_the_anchor_survives_a_publish`.
# The reader (`capture_knowledge`) and the wire value it produces stay pinned above and below.


#: A record with EVERY field set to a non-default value, so "everything else intact" is a claim
#: about eleven fields rather than about two.
RICH: dict[str, Any] = {
    "commit": "a" * 40, "dirty": True, "dirty_paths": ["x.md", "y.md"], "dirty_path_count": 3,
    "unavailable": "git status: a note beside the dirt", "scope": "defender", "model": "m-1",
    "tenant_id": fixture_uuid("tenant:acme"), "world_id": fixture_uuid("world:knowledge-revision:b"),
    "parent_run_id": fixture_uuid("run:knowledge-revision:source"), "fork_turn": 59,
    "started_at": "2026-07-28T16:18:45+00:00", "alert_label": "fresh-case",
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
    """O4/D2."""
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
    """The positive control for the folding above, on the same record."""
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
    """D2."""
    on_disk = json.loads(RunProvenance(commit="a" * 40, dirty=False).as_json())
    assert "knowledge" in on_disk, on_disk
    assert on_disk["knowledge"] is None, on_disk
    for old in (_without_knowledge(), {**_without_knowledge(), "knowledge": None}):
        record = RunProvenance.from_obj(old)
        assert record is not None
        assert record.knowledge is None
        assert json.loads(record.as_json()) == {**RICH, "knowledge": None}
