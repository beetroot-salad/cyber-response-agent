"""#1546 A-O3/A-O10, "Objects per owner": the bundle packer packs only lone regular files and directories, lists every
omitted entry in `scrub-findings.json`, refuses escaping paths and over-cap sizes, and carries session stores whole.

Pinned (design leaves open): `defender.evidence.bundle` with `pack(root, dest, *, exclude=(), max_packed=MAX_PACKED_BYTES)`,
`unpack(source, into, *, max_unpacked=MAX_UNPACKED_BYTES)` (both over files), `BundleRefused`, `FINDINGS_FILE`,
`MAX_PACKED_BYTES`, `MAX_UNPACKED_BYTES`; `exclude` is relative POSIX paths, each a whole subtree. The findings file sits at
the archive root as a list of `{path, kind, mode, link_count, target}`; `target` is the symlink's text, else null.
"""
from __future__ import annotations

import contextlib
import gzip
import io
import json
import os
import random
import socket
import sqlite3
import stat
import tarfile
from pathlib import Path

import pytest

KINDS = ("symlink-file", "symlink-dir", "symlink-dangling", "symlink-outside", "fifo", "socket", "hardlink",
         "chardev", "blockdev")


def _bundle():
    from defender.evidence import bundle

    return bundle


def _plant(root: Path, rel: str, kind: str, outside: Path) -> list[str]:
    """Plant one entry of `kind` at `rel` under `root`; the paths it makes (a hard link is two)."""
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "symlink-file":
        path.symlink_to("alpha.txt")
    elif kind == "symlink-dir":
        path.symlink_to("sub")
    elif kind == "symlink-dangling":
        path.symlink_to("/nonexistent/target")
    elif kind == "symlink-outside":
        path.symlink_to(outside)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "socket":
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(path))
        sock.close()
    elif kind == "hardlink":
        os.link(root / "alpha.txt", path)
        return [rel, "alpha.txt"]
    else:
        try:
            os.mknod(path, mode={"chardev": stat.S_IFCHR, "blockdev": stat.S_IFBLK}[kind] | 0o600, device=os.makedev(1, 3))
        except PermissionError:
            pytest.skip(f"cannot create a {kind} here")
    return [rel]


@pytest.fixture
def tree(tmp_path) -> Path:
    root = tmp_path / "tenant"
    (root / "sub" / "deep").mkdir(parents=True)
    (root / "empty").mkdir()
    (root / "alpha.txt").write_bytes(b"alpha")
    (root / "sub" / "beta.bin").write_bytes(bytes(range(256)))
    (root / "sub" / "deep" / "gamma.txt").write_text("gamma\n", encoding="utf-8")
    return root


@pytest.fixture
def outside(tmp_path) -> Path:
    folder = tmp_path / "outside"
    folder.mkdir()
    (folder / "secret.txt").write_text("OUTSIDE-SECRET", encoding="utf-8")
    return folder


def _round_trip(b, root: Path, tmp_path: Path, **kw) -> tuple[Path, list[dict]]:
    archive, into = tmp_path / "x.bundle", tmp_path / "unpacked"
    b.pack(root, archive, **kw)
    b.unpack(archive, into)
    found = into / b.FINDINGS_FILE
    return into, (json.loads(found.read_text(encoding="utf-8")) if found.exists() else [])


def _files(root: Path) -> dict[str, bytes | None]:
    return {p.relative_to(root).as_posix(): (p.read_bytes() if p.is_file() else None) for p in sorted(root.rglob("*"))}


def test_a_clean_tree_round_trips_files_directories_and_lists_nothing(tmp_path, tree):
    """Positive control: regular files and directories (an empty one too) come back byte for byte; no omissions. (A-O10)"""
    b = _bundle()
    into, findings = _round_trip(b, tree, tmp_path)
    assert {k: v for k, v in _files(into).items() if k != b.FINDINGS_FILE} == _files(tree)
    assert findings == []


@pytest.mark.parametrize("kind", KINDS)
def test_every_non_regular_entry_type_is_omitted_and_listed(tmp_path, tree, outside, kind):
    """Any entry that is not a lone regular file or a directory is left out and listed with path, kind, mode, link count, target. (A-O10)"""
    b = _bundle()
    planted = _plant(tree, "sub/planted", kind, outside)
    into, findings = _round_trip(b, tree, tmp_path)

    listed = {row["path"]: row for row in findings}
    assert set(listed) == set(planted), findings
    for rel in planted:
        assert not (into / rel).exists()
        assert not (into / rel).is_symlink()
        row = listed[rel]
        assert {"path", "kind", "mode", "link_count", "target"} <= set(row)
        assert row["link_count"] == os.lstat(tree / rel).st_nlink
    if kind.startswith("symlink"):
        assert listed["sub/planted"]["target"] == os.readlink(tree / "sub/planted")
    else:
        assert listed["sub/planted"]["target"] is None
    # What the symlink pointed at is never followed into the bundle (its target text is all that is kept).
    assert b"OUTSIDE-SECRET" not in b"".join(v or b"" for v in _files(into).values())
    # The control rides with it: the rest of the tree is intact.
    assert (into / "sub" / "beta.bin").read_bytes() == bytes(range(256))


def test_a_hard_link_is_omitted_under_both_names(tmp_path, tree, outside):
    """A regular file with link count 2 is not packed under either name, and each is listed with `link_count` 2. (A-O10)"""
    b = _bundle()
    _plant(tree, "linked", "hardlink", outside)
    into, findings = _round_trip(b, tree, tmp_path)
    assert {row["path"]: row["link_count"] for row in findings} == {"alpha.txt": 2, "linked": 2}
    assert not (into / "alpha.txt").exists()
    assert not (into / "linked").exists()


@pytest.mark.parametrize("seed", range(8))
def test_the_packer_omits_exactly_the_entries_the_scrub_refuses(tmp_path, outside, seed):
    """One classifier: over a generated tree, the omitted paths equal the scrub's finding paths and the rest is packed. (A-O10, D2)"""
    from defender.box import _scrub

    b = _bundle()
    rng = random.Random(seed)
    root = tmp_path / "gen"
    (root / "d0").mkdir(parents=True)
    (root / "alpha.txt").write_bytes(b"alpha")
    (root / "sub").mkdir()
    for i in range(30):
        rel = f"d{rng.randrange(3)}/n{i}" if rng.random() < .8 else f"n{i}"
        (root / rel).parent.mkdir(exist_ok=True)
        kind = rng.choice(("file", "file", "dir", *KINDS))
        if kind == "file":
            (root / rel).write_bytes(bytes([i]) * rng.randrange(1, 50))
        elif kind == "dir":
            (root / rel).mkdir()
        else:
            _plant(root, rel, kind, outside)
    with pytest.raises(_scrub.RunTainted) as refused:
        _scrub.scrub(root)
    refused_paths = {f.path.relative_to(root).as_posix() for f in refused.value.findings}
    assert refused_paths, "premise: the generated tree holds something the scrub refuses"

    into, findings = _round_trip(b, root, tmp_path)
    assert {row["path"] for row in findings} == refused_paths
    survivors = {p.relative_to(root).as_posix() for p in root.rglob("*")} - refused_paths
    assert {k for k in _files(into) if k != b.FINDINGS_FILE} == survivors


def _tar(members: list[tuple[tarfile.TarInfo, bytes | None]], path: Path) -> Path:
    with gzip.open(path, "wb") as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def _member(name: str, *, data: bytes | None = b"x", type_: bytes = tarfile.REGTYPE, link: str = "") -> tuple:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = type_, link
    info.size = len(data) if data is not None and type_ == tarfile.REGTYPE else 0
    info.mode = 0o644
    return info, data if type_ == tarfile.REGTYPE else None


def test_a_well_formed_archive_unpacks(tmp_path):
    """Positive control for the refusals below: relative members unpack."""
    b = _bundle()
    archive = _tar([_member("ok/inner.txt", data=b"fine")], tmp_path / "a.tgz")
    b.unpack(archive, tmp_path / "into")
    assert (tmp_path / "into" / "ok" / "inner.txt").read_bytes() == b"fine"


@pytest.mark.parametrize("name", ["ABS", "ABS/nested", "../escape", "a/../../escape", "a/b/../../../escape",
                                  "./../escape", "..", "/"])
def test_an_unpack_refuses_an_absolute_or_dotdot_member_and_writes_nothing_outside(tmp_path, name):
    """Any member path that is absolute or climbs out of the root is refused on unpack, and nothing lands outside it. (A-O3)"""
    b = _bundle()
    parent = tmp_path / "box"
    into = parent / "into"
    parent.mkdir()
    target = tmp_path / "abs-target"      # an absolute member names a place of the test's own
    name = name.replace("ABS", str(target))
    archive = _tar([_member("first.txt", data=b"before"), _member(name, data=b"escaped")], tmp_path / "evil.tgz")
    with pytest.raises(b.BundleRefused):
        b.unpack(archive, into)
    assert not target.exists()
    assert not (parent / "escape").exists()
    assert sorted(p.name for p in parent.iterdir()) in (["into"], [])


@pytest.mark.parametrize("link_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_a_member_cannot_be_written_through_a_link_member_out_of_the_root(tmp_path, link_type):
    """A link member planted first never lets a later member land outside the root. (A-O3)"""
    b = _bundle()
    parent = tmp_path / "box"
    outside = parent / "outside"
    outside.mkdir(parents=True)
    into = parent / "into"
    link_target = str(outside) if link_type == tarfile.SYMTYPE else "../outside/hard"
    archive = _tar([_member("hop", type_=link_type, link=link_target), _member("hop/pwned.txt", data=b"escaped")],
                   tmp_path / "evil.tgz")
    with contextlib.suppress(b.BundleRefused):
        b.unpack(archive, into)
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("name", ["/abs-exclude", "../up", "sub/../../up"])  # no file is made: pack only refuses
def test_a_pack_refuses_an_absolute_or_dotdot_exclude(tmp_path, tree, name):
    """An exclude naming an absolute or escaping path is refused on pack, and no archive is left. (A-O3)"""
    b = _bundle()
    with pytest.raises(b.BundleRefused):
        b.pack(tree, tmp_path / "x.bundle", exclude=[name])
    assert not (tmp_path / "x.bundle").exists()


def test_the_caps_are_512_mib_packed_and_2_gib_unpacked():
    """The design's two numbers. (A-O3)"""
    b = _bundle()
    assert (b.MAX_PACKED_BYTES, b.MAX_UNPACKED_BYTES) == (512 * 2**20, 2 * 2**30)


def test_a_pack_over_the_packed_cap_is_refused_and_leaves_no_archive(tmp_path, tree):
    """Incompressible content over `max_packed` is refused; the same tree under the cap packs. (A-O3)"""
    b = _bundle()
    (tree / "noise.bin").write_bytes(random.Random(1).randbytes(3 * 2**20))
    b.pack(tree, tmp_path / "ok.bundle", max_packed=16 * 2**20)
    assert (tmp_path / "ok.bundle").stat().st_size > 3 * 2**20
    with pytest.raises(b.BundleRefused):
        b.pack(tree, tmp_path / "big.bundle", max_packed=2**20)
    assert not (tmp_path / "big.bundle").exists()


def test_an_unpack_over_the_unpacked_cap_stops_while_unpacking(tmp_path):
    """A tiny archive that expands past `max_unpacked` is refused before it is written out: at most the cap, plus one read. (A-O3)"""
    b = _bundle()
    archive = _tar([_member("zeros.bin", data=bytes(8 * 2**20))], tmp_path / "bomb.tgz")
    assert archive.stat().st_size < 64 * 2**10, "premise: a small archive of a large file"
    into = tmp_path / "into"
    with pytest.raises(b.BundleRefused):
        b.unpack(archive, into, max_unpacked=2**20)
    written = sum(p.stat().st_size for p in into.rglob("*") if p.is_file()) if into.exists() else 0
    assert written <= 2**20 + 2**18, written
    b.unpack(archive, tmp_path / "fits", max_unpacked=16 * 2**20)
    assert (tmp_path / "fits" / "zeros.bin").stat().st_size == 8 * 2**20


def _store(path: Path, rows: int) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None)
    assert conn.execute("pragma journal_mode=wal").fetchone()[0] == "wal"
    conn.execute("pragma wal_autocheckpoint=0")
    conn.execute("create table t (n integer)")
    conn.executemany("insert into t values (?)", [(i,) for i in range(rows)])
    return conn


def test_a_session_store_with_its_rows_only_in_the_wal_is_packed_whole(tmp_path):
    """A store whose latest rows live only in `-wal` unpacks, from the `.db` file alone, with every row. (A-O3)"""
    b = _bundle()
    live = tmp_path / "live" / "sessions" / "arm1.db"
    conn = _store(live, 50)
    root = tmp_path / "tenant"
    (root / "sessions").mkdir(parents=True)
    for suffix in ("", "-wal"):   # the crash image: what a job's folder holds if nothing closed the store
        if Path(f"{live}{suffix}").exists():
            (root / "sessions" / f"arm1.db{suffix}").write_bytes(Path(f"{live}{suffix}").read_bytes())
    conn.close()
    assert (root / "sessions" / "arm1.db-wal").stat().st_size > 0, "premise: the rows are in the WAL"
    into, _findings = _round_trip(b, root, tmp_path)
    copy = sqlite3.connect(f"file:{into / 'sessions' / 'arm1.db'}?mode=ro", uri=True)
    assert copy.execute("select count(*) from t").fetchone() == (50,)


def test_exclude_drops_a_whole_subtree_and_keeps_every_arm_session_database(tmp_path):
    """A learning job's bundle leaves out the pulled source's run folder and keeps each arm's session database. (D12)"""
    b = _bundle()
    root = tmp_path / "tenant"
    for run in ("src", "src-sibling", "arm-a", "arm-b"):
        (root / "runs" / run / "gather_raw").mkdir(parents=True)
        (root / "runs" / run / "investigation.md").write_text(run, encoding="utf-8")
    for arm in ("arm-a", "arm-b"):
        _store(root / "sessions" / f"{arm}.db", 3).close()
    into, _findings = _round_trip(b, root, tmp_path, exclude=["runs/src"])
    assert not (into / "runs" / "src").exists(), "the pulled source's run folder rode in the bundle"
    kept = sorted(p.name for p in (into / "runs").iterdir())
    assert kept == ["arm-a", "arm-b", "src-sibling"], "exclude matched by prefix, not by whole path component"
    for arm in ("arm-a", "arm-b"):
        db = sqlite3.connect(f"file:{into / 'sessions' / f'{arm}.db'}?mode=ro", uri=True)
        assert db.execute("select count(*) from t").fetchone() == (3,)
