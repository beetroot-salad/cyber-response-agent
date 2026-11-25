"""The evidence bundle: one gzip tar of a job's folder, packed by the job and unpacked by the next.

A boxed run's folder may hold what the box planted, so the packer packs only what the scrub lets
survive (lone regular files and directories) and lists each entry it left out, with what triage
needs, in `scrub-findings.json` at the archive root. The classifier is the scrub's own
(`defender.box._scrub.classify_entry`): the packer's omissions and the scrub's findings are one
set. The archive holds no link, device, fifo or socket member and no path outside its root, and
the unpacker refuses an archive that does (#1546 A-O3, A-O10).

Session stores are carried whole: a SQLite store with a write-ahead log is checkpointed into a
private copy first, so its `.db` file alone holds every row.
"""
from __future__ import annotations

import contextlib
import errno
import gzip
import io
import json
import os
import shutil
import sqlite3
import stat
import tarfile
import tempfile
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path, PurePosixPath
from typing import IO, Any

from defender.box import Finding, Lister, classify_entry, unreadable_finding

#: The omitted entries, a list of `{path, kind, mode, link_count, target}`, at the archive root.
FINDINGS_FILE = "scrub-findings.json"
#: What a packed bundle may weigh, and what it may expand to.
MAX_PACKED_BYTES = 512 * 2**20
MAX_UNPACKED_BYTES = 2 * 2**30

_CHUNK = 1 << 16
#: Each member counts at least a tar header against the unpacked cap, so a bomb of empty
#: entries is bounded as well as one of large files.
_MEMBER_COST = 512
_SQLITE_MAGIC = b"SQLite format 3\x00"
_NOFOLLOW_READ = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


class BundleRefused(Exception):
    """A bundle that may not be packed or unpacked: a path that escapes its root, a member that
    is not a plain file or directory, or a size over its cap."""


# ---------------------------------------------------------------------------------------
# pack
# ---------------------------------------------------------------------------------------


class _Counting:
    """The archive's file, refusing once more than `cap` bytes were written."""

    def __init__(self, fh: IO[bytes], cap: int) -> None:
        self._fh, self._cap, self.written = fh, cap, 0

    def write(self, data: bytes) -> int:
        self.written += len(data)
        if self.written > self._cap:
            raise BundleRefused(f"the bundle is over {self._cap} bytes packed")
        return self._fh.write(data)

    def flush(self) -> None:
        self._fh.flush()


def _excluded(exclude: Iterable[str]) -> list[PurePosixPath]:
    """The exclude paths, each a relative POSIX subtree; an absolute one, one climbing out of
    the root, or one naming the root itself is refused."""
    parsed = []
    for raw in exclude:
        path = PurePosixPath(raw)
        parts = [p for p in path.parts if p != "."]
        if path.is_absolute() or ".." in parts or not parts or "\\" in raw:
            raise BundleRefused(f"the exclude {raw!r} is not a relative path inside the bundle's root")
        parsed.append(PurePosixPath(*parts))
    return parsed


def _is_excluded(rel: PurePosixPath, excludes: Sequence[PurePosixPath]) -> bool:
    """Whole path components: `runs/src` drops `runs/src/x`, never `runs/src-sibling`."""
    return any(rel == ex or ex in rel.parents for ex in excludes)


def _finding_row(root: Path, finding: Finding) -> dict:
    return {"path": finding.path.relative_to(root).as_posix(), "kind": finding.kind,
            "mode": finding.filemode, "link_count": finding.nlink, "target": finding.target}


def _tar_member(name: str, **attrs: object) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    for key, value in attrs.items():
        setattr(info, key, value)
    return info


def _tar_info(rel: str, st: os.stat_result, *, directory: bool) -> tarfile.TarInfo:
    owner = {"uid": 0, "gid": 0, "uname": "", "gname": "", "mtime": int(st.st_mtime)}
    if directory:
        return _tar_member(rel, type=tarfile.DIRTYPE, mode=0o755, **owner)
    return _tar_member(rel, type=tarfile.REGTYPE, size=st.st_size, mode=0o644 | (st.st_mode & 0o111), **owner)


def _open_plain(path: Path) -> tuple[int, os.stat_result]:
    """Open a lone regular file without following a link, judged again on the open descriptor
    (the walk's judgment may be stale by now)."""
    fd = os.open(path, _NOFOLLOW_READ)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
            raise OSError(errno.ESTALE, "the entry changed shape while it was packed")
    except BaseException:
        os.close(fd)
        raise
    return fd, st


class _Packer:
    def __init__(self, root: Path, tar: tarfile.TarFile, excludes: Sequence[PurePosixPath], scratch: Path) -> None:
        self.root, self.tar, self.excludes, self.spill = root, tar, excludes, scratch
        self.findings: list[Finding] = []

    def add_file(self, path: Path, rel: str) -> None:
        try:
            fd, st = _open_plain(path)
        except OSError as e:
            self.findings.append(unreadable_finding(path, e))
            return
        with os.fdopen(fd, "rb") as fh:
            self.tar.addfile(_tar_info(rel, st, directory=False), fh)

    def add_checkpointed(self, path: Path, rel: str, wal: Path) -> bool:
        """A session store with a write-ahead log, as one `.db` file holding every row. `False`
        when it is not a store that can be checkpointed, which then rides as it is."""
        try:
            copy = self.spill / f"store-{len(os.listdir(self.spill))}.db"
            for source, target in ((path, copy), (wal, copy.with_name(copy.name + "-wal"))):
                fd, _ = _open_plain(source)
                with os.fdopen(fd, "rb") as src, open(target, "wb") as dst:
                    if source == path and src.read(len(_SQLITE_MAGIC)) != _SQLITE_MAGIC:
                        return False
                    src.seek(0)
                    shutil.copyfileobj(src, dst)
            conn = sqlite3.connect(copy, isolation_level=None)
            try:
                if conn.execute("pragma wal_checkpoint(truncate)").fetchone()[0] != 0:
                    return False
            finally:
                conn.close()
            if copy.with_name(copy.name + "-wal").exists() and copy.with_name(copy.name + "-wal").stat().st_size:
                return False
        except (OSError, sqlite3.Error):
            return False
        fd, st = _open_plain(copy)
        with os.fdopen(fd, "rb") as fh:
            self.tar.addfile(_tar_info(rel, st, directory=False), fh)
        return True

    def pack_directory(self, parent: str, dirs: list[str], files: list[str]) -> None:
        """One directory of the walk: classify every entry with the scrub's classifier, prune
        the directories not packed, pack the files."""
        here = Path(parent)
        dirs.sort()
        files.sort()
        clean_files: list[str] = []
        for name in (*dirs, *files):
            rel = PurePosixPath((here / name).relative_to(self.root).as_posix())
            if _is_excluded(rel, self.excludes):
                continue
            finding = classify_entry(here / name)
            if finding is not None:
                self.findings.append(finding)
            elif name in dirs:
                self.tar.addfile(_tar_info(rel.as_posix(), (here / name).lstat(), directory=True))
                continue
            else:
                clean_files.append(name)
        dirs[:] = [d for d in dirs if self._descends(here / d)]
        if here == self.root:
            # The archive's own findings member is the only one of that name: one left in the
            # tree (an unpacked bundle packed again) is superseded by this pack's list.
            clean_files = [n for n in clean_files if n != FINDINGS_FILE]
        self.pack_files(here, clean_files)

    def _descends(self, path: Path) -> bool:
        rel = PurePosixPath(path.relative_to(self.root).as_posix())
        if _is_excluded(rel, self.excludes):
            return False
        return not any(f.path == path for f in self.findings)

    def pack_files(self, here: Path, names: list[str]) -> None:
        present = set(names)
        consumed: set[str] = set()
        for name in names:
            rel = (here / name).relative_to(self.root).as_posix()
            if name in consumed:
                continue
            wal = f"{name}-wal"
            if wal in present and not name.endswith(("-wal", "-shm")) \
                    and self.add_checkpointed(here / name, rel, here / wal):
                consumed |= {wal, f"{name}-shm"}
                continue
            self.add_file(here / name, rel)


def _pack_walk(root: Path, tar: tarfile.TarFile, excludes: Sequence[PurePosixPath], lister: Lister,
               scratch: Path) -> list[Finding]:
    packer = _Packer(root, tar, excludes, scratch)

    def refuse_unwalkable(err: OSError) -> None:
        packer.findings.append(unreadable_finding(Path(err.filename or root), err))

    for parent, dirs, files in lister(root, onerror=refuse_unwalkable):
        packer.pack_directory(parent, dirs, files)
    return packer.findings


def _findings_member(root: Path, findings: Sequence[Finding]) -> tuple[tarfile.TarInfo, bytes]:
    rows = [_finding_row(root, f) for f in sorted(findings, key=lambda f: f.path)]
    body = (json.dumps(rows, indent=2) + "\n").encode("utf-8")
    return _tar_member(FINDINGS_FILE, size=len(body), mode=0o644, mtime=0), body


def pack(root: Path, dest: Path, *, exclude: Iterable[str] = (), max_packed: int = MAX_PACKED_BYTES,
         lister: Lister = os.walk) -> None:
    """Pack the tree at `root` into the gzip tar `dest`, replacing it.

    Only lone regular files and directories are packed; every other entry (a link, device, fifo,
    socket, a hard-linked file under each of its names, an entry that could not be read) is left
    out and listed in `scrub-findings.json` at the archive root, always written, an empty list
    when nothing was left out. `exclude` names relative POSIX subtrees to drop whole (matched by
    path component). Refused (`BundleRefused`), with no archive left, are an exclude that is
    absolute or climbs out of `root`, a `root` that is not a real directory, and a bundle over
    `max_packed` bytes. `lister` is the scrub's walk seam."""
    root, dest = Path(root), Path(dest)
    excludes = _excluded(exclude)
    if not stat.S_ISDIR(os.lstat(root).st_mode):
        raise BundleRefused(f"{root} is not a real directory")
    partial = dest.with_name(dest.name + ".part")
    try:
        with tempfile.TemporaryDirectory(prefix="bundle-") as scratch, open(partial, "wb") as out:
            counted = _Counting(out, max_packed)
            with gzip.GzipFile(fileobj=counted, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tar:
                findings = _pack_walk(root, tar, excludes, lister, Path(scratch))
                info, body = _findings_member(root, findings)
                tar.addfile(info, io.BytesIO(body))
        os.replace(partial, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise


# ---------------------------------------------------------------------------------------
# unpack
# ---------------------------------------------------------------------------------------


def _member_path(name: str) -> PurePosixPath:
    """A member's path under the root, or `BundleRefused` for one that is absolute, climbs out
    of it, or names nothing."""
    path = PurePosixPath(name)
    parts = [p for p in path.parts if p != "."]
    if path.is_absolute() or ".." in parts or not parts or "\\" in name or "\x00" in name:
        raise BundleRefused(f"the member {name!r} is not a relative path inside the bundle")
    return PurePosixPath(*parts)


def _make_parents(into: Path, rel: PurePosixPath) -> Path:
    """Make the folders above `rel` under `into`, none of them a link, and return `rel`'s path."""
    here = into
    for part in rel.parts[:-1]:
        here = here / part
        with contextlib.suppress(FileExistsError):
            os.mkdir(here, 0o755)  # lint-unguarded-tree-write: ok — the unpack's own fresh folder; checked by lstat below, no link followed
        if not stat.S_ISDIR(os.lstat(here).st_mode):
            raise BundleRefused(f"the member {rel} lies beyond something that is not a folder")
    return here / rel.parts[-1]


class _Budget:
    def __init__(self, cap: int) -> None:
        self.cap, self.spent = cap, 0

    def spend(self, n: int) -> None:
        self.spent += n
        self.check(0)

    def check(self, upcoming: int) -> None:
        if self.spent + upcoming > self.cap:
            raise BundleRefused(f"the bundle expands past {self.cap} bytes")


def _write_member(tar: tarfile.TarFile, member: tarfile.TarInfo, target: Path, budget: _Budget) -> None:
    src = tar.extractfile(member)
    if src is None:
        raise BundleRefused(f"the member {member.name!r} has no content to read")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "wb") as dst:
        while chunk := src.read(_CHUNK):
            budget.spend(len(chunk))
            dst.write(chunk)
        os.fchmod(dst.fileno(), 0o644 | (member.mode & 0o111))


def _extract(tar: tarfile.TarFile, into: Path, budget: _Budget) -> None:
    for member in tar:
        rel = _member_path(member.name)
        budget.spend(_MEMBER_COST)
        if not (member.isreg() or member.isdir()):
            raise BundleRefused(f"the member {member.name!r} is not a plain file or folder")
        if member.isreg():
            budget.check(member.size)    # a declared size past the cap stops before any byte is written
        target = _make_parents(into, rel)
        try:
            if member.isdir():
                with contextlib.suppress(FileExistsError):
                    os.mkdir(target, 0o755)  # lint-unguarded-tree-write: ok — the unpack's own fresh folder; checked by lstat below
                if not stat.S_ISDIR(os.lstat(target).st_mode):
                    raise BundleRefused(f"the member {member.name!r} lies over something that is not a folder")
            else:
                _write_member(tar, member, target, budget)
        except FileExistsError as e:
            raise BundleRefused(f"the member {member.name!r} is there twice") from e


def push(request: Callable[..., dict[str, Any]], root: Path, packed: Path, *, exclude: Iterable[str] = ()) -> None:
    """Pack the tree at `root` into `packed` (`pack`) and push it to the job's helper as the `bundle` object
    (`job_socket.push_object`); `packed` is removed however that ends. A refusal raises (`BundleRefused`,
    `job_socket.Refused`, `OSError`, `ValueError`): the caller logs it."""
    from defender import job_socket
    from defender.records.job_facts import BUNDLE

    try:
        pack(root, packed, exclude=exclude)
        job_socket.push_object(request, BUNDLE, packed)
    finally:
        packed.unlink(missing_ok=True)


def unpack(source: Path, into: Path, *, max_unpacked: int = MAX_UNPACKED_BYTES) -> None:
    """Unpack the bundle at `source` under `into` (made if absent).

    Refused (`BundleRefused`) is an archive that is not a gzip tar, a member that is absolute or
    climbs out of `into`, one that is not a plain file or folder (a link member is never
    honoured), a name twice, and one whose content passes `max_unpacked` bytes, which stops
    while unpacking. On a refusal `into` may hold what came before the member refused: the
    caller discards it."""
    into = Path(into)
    os.makedirs(into, exist_ok=True)
    budget = _Budget(max_unpacked)
    try:
        with tarfile.open(source, mode="r|gz") as tar:
            _extract(tar, into, budget)
    except (tarfile.TarError, EOFError, OSError, ValueError) as e:
        raise BundleRefused(f"the bundle could not be read: {e}") from e
