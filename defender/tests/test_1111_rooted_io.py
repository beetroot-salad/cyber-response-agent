"""#1111 — every read and write the `Run` handle makes walks no-follow from the record's
trust root.

The contract is issue #1111's discuss-issue design ("the handle's reads AND writes walk
no-follow from the record's trust root") and its implementation-start addendum (`create`
keeps #1078's complete-or-absent lane). The seam is four `defender._io` functions whose names
and signatures the design fixes: `rooted_read(root, name, *, binary=False)`,
`rooted_mkdir(root, folder_name)`, `rooted_write(root, name, text, *, mode, stage_name=,
open_unnamed=)` and `rooted_locked_for_rewrite(root, name, *, binary=False)`. Each takes a
trust root, whose spelling is followed, and a name relative to it, which never is. The handle
(`RecordHandle`, `Run.record`, `ArchivedWorld`) reaches them through its `io=` seam.

What each section pins:

- O1/O3/O4, the READ matrix. Every member of the shipped `GROUP_MEMBERS` and of
  `ArchivedWorld.members` gets every plant its address can carry: a hard link, a symlink, a
  FIFO, a socket or a directory at the name. Where the record has holding folders below its
  root, each folder in turn is replaced by a symlink (to a folder INSIDE the root, which is
  what reaches the new walk for the `_confine`d kinds, and to one outside it), a plain file or
  a FIFO. A plant reads `None` without blocking. A plain file at the same address reads back.
  `Run.record`'s source reads and the schema-gated write's pre-read get the same plants.
- O2/O3/O6/O7, the WRITE matrix. Every member's own verb (`write`, `append`, `update`) meets
  the same plants. The refusal keeps today's exception, errno and alias mark, row for row. An
  `observability` append swallows a refused LEAF into `run.partial_failures` but raises a
  refused holding folder. The whole temp tree is unchanged: the plant, the file a link or a
  hard link reaches, the folder a link points at. Then the plant is removed and the same call
  lands, so every negative carries its positive control on the same address.
- O5. The root's own spelling is followed (a symlinked run dir, runs base, data root, world
  dir). A write under a missing root creates it, following links; a read under one is `None`.
- O6's rows no plant reaches: the write-once second write, and the occupied staged name (via
  `rooted_write`'s `stage_name=` seam). Also its "unchanged" owner refusals.
- O8. A pass-through recorder on the handle's `io=` seam sees each member op as the expected
  `rooted_*` call, carrying the trust root, the name relative to it, the mode and the payload,
  and sees no other `_io` call (in particular, no path-based seam).
- The seam's own narrow rules, driven directly: the name grammar, a missing parent, the plant
  rows, `create`'s complete-or-absent lane and its `open_unnamed=` fallback, `replace`'s staged
  name, and the lock.

The member matrix is ENUMERATED from the shipped tables (`_run_handle.GROUP_MEMBERS`,
`MEMBER_VERB`, `ArchivedWorld.members`), and each member's trust root and relative name are
DERIVED from the path its own accessor builds. A member added later lands in every matrix with
no code here (O4). `Run.record`'s source reads are enumerated the same way, by recording the
reads it makes.

Fakes: pass-through recorders on the handle's `io=` seam (`_spec1077.RecordingIo`, and one
subclass that hands `rooted_write` an occupied `stage_name`), and `rooted_write`'s own
`open_unnamed=` / `stage_name=` seams. Every plant is a real filesystem entry.

Red before #1111 lands: every direct `_io.rooted_*` call (the seam does not exist), the O8
seam tests, the occupied-staged-name row through the handle, and every READ through a
symlinked holding folder (today's `read_guarded` judges only the leaf and follows the folder:
claim C1). The rest holds today and must keep holding.
"""
from __future__ import annotations

import contextlib
import dataclasses
import errno
import fcntl
import json
import os
import shutil
import stat
import threading
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender import _run_handle as H
from defender._artifact_schema import INVESTIGATION_FILE_MAX
from defender._provenance import RunProvenance
from defender._run_paths import RUN_LAYOUT, RunPaths, SessionPaths
from defender.tests import _spec1077 as S

RUN_ID = "run-1111"
#: How long one call may take before O3 calls it hung. A right answer takes milliseconds; the
#: deadline only bounds a regression, so it fails the test rather than wedging the run.
DEADLINE = 3.0

#: The design's M1 seam. A member op makes these `_io` calls and no others.
ROOTED_OPS = frozenset({"rooted_read", "rooted_write", "rooted_mkdir",
                        "rooted_locked_for_rewrite"})

#: Today's write-once members (`create`; a second write is refused). Not #1111's to change.
WRITE_ONCE = frozenset({"alert", "provenance", "run_end", "leads"})

#: What a plant can put AT a record's name.
LEAF_PLANTS = ("hardlink", "symlink", "fifo", "socket", "directory")
#: What a plant can put at a holding folder between the root and the record.
FOLDER_PLANTS = ("folder_link_inside", "folder_link_outside", "folder_file", "folder_fifo")

#: O6's write-side table, row for row: plant -> (exception type, errno, alias-marked). Unmarked
#: means `write_guarded_alias` is absent or False: `hooks/budget_enforcer.py` reads it with
#: `getattr(e, "write_guarded_alias", False)`, so both spellings count toward the kill circuit.
O6_ROWS: dict[str, tuple[type[OSError], int, bool]] = {
    "symlink": (OSError, errno.ELOOP, True),
    "hardlink": (OSError, errno.EMLINK, True),
    "directory": (OSError, errno.ELOOP, False),
    "fifo": (OSError, errno.ELOOP, False),
    "socket": (OSError, errno.ELOOP, False),
    "folder_link_inside": (OSError, errno.ELOOP, False),
    "folder_link_outside": (OSError, errno.ELOOP, False),
    "folder_file": (NotADirectoryError, errno.ENOTDIR, False),
    "folder_fifo": (NotADirectoryError, errno.ENOTDIR, False),
}

#: What a planted entry holds, or what a link or hard link reaches: the bytes a read that
#: followed it would return, and that a write through it would change.
HOST_BYTES = b'{"planted": "HOST"}\n'
#: What a plain file at the record's own address holds: the positive control's answer.
PLAIN = "plain record at its own address\n"


# ---------------------------------------------------------------------------------------
# The members, enumerated from the shipped tables and addressed from their own paths (O4)
# ---------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Member:
    """One record, addressed as the design's M2 addresses it: a trust root (`run_dir`,
    `runs_base`, `session_root` or `world_dir`) and the record's name relative to it."""

    group: str
    name: str
    verb: str | None
    root: str
    rel: PurePosixPath

    def __str__(self) -> str:
        return f"{self.group}.{self.name}"

    @property
    def folders(self) -> tuple[PurePosixPath, ...]:
        """Every holding folder strictly between the root and the record, outermost first."""
        return tuple(reversed(self.rel.parents[:-1]))


def trust_roots(runs_base: Path, world_dir: Path) -> dict[str, Path]:
    """The design's M2 trust-root table, most specific first: an in-run record's root is the
    run dir, a sidecar's the runs base, the session db's `SessionPaths(runs_base).trust_root`,
    an archived world's member's the world dir."""
    return {
        "run_dir": runs_base / RUN_ID,
        "runs_base": runs_base,
        "session_root": SessionPaths(runs_base).trust_root,
        "world_dir": world_dir,
    }


def _address(path: Path, roots: dict[str, Path]) -> tuple[str, PurePosixPath]:
    """The most specific trust root holding `path`, and `path` relative to it."""
    for key, root in roots.items():
        if path.is_relative_to(root):
            return key, PurePosixPath(path.relative_to(root).as_posix())
    raise AssertionError(f"{path} is under none of the trust roots {roots}")


_PROBE_BASE = Path("/nonexistent-1111/data/runs")
_PROBE_WORLD = Path("/nonexistent-1111/worlds/overlay_a")


def _run_members() -> tuple[Member, ...]:
    """`GROUP_MEMBERS` x `MEMBER_VERB`, each addressed from the path its accessor builds."""
    run = H.Run.under(_PROBE_BASE, RUN_ID)
    roots = trust_roots(_PROBE_BASE, _PROBE_WORLD)
    out = []
    for group, names in H.GROUP_MEMBERS.items():
        for name in names:
            path = S.member(run, group, name, *S.member_args(name)).path
            root, rel = _address(path, {k: v for k, v in roots.items() if k != "world_dir"})
            out.append(Member(group, name, H.MEMBER_VERB[name], root, rel))
    return tuple(out)


def _archived_members() -> tuple[Member, ...]:
    world = H.ArchivedWorld.at(_PROBE_WORLD)
    return tuple(
        Member("archived", name, None, "world_dir",
               PurePosixPath(getattr(world, name).path.relative_to(_PROBE_WORLD).as_posix()))
        for name in world.members)


RUN_MEMBERS = _run_members()
ARCHIVED_MEMBERS = _archived_members()
READABLE = (*RUN_MEMBERS, *ARCHIVED_MEMBERS)
WRITABLE = tuple(m for m in RUN_MEMBERS if m.verb in ("write", "append", "update"))
REPLACED = tuple(m for m in WRITABLE if m.verb == "write" and m.name not in WRITE_ONCE)


def _member(name: str) -> Member:
    (m,) = [m for m in RUN_MEMBERS if m.name == name]
    return m


@dataclasses.dataclass(frozen=True)
class Tree:
    """A run's world on disk: the runs base (and the sessions folder beside it, under the data
    root), the run dir, an archived world dir, and a host folder outside every trust root,
    where a planted link points and a hard link's other name lives."""

    tmp: Path
    runs_base: Path
    world_dir: Path
    host: Path

    def root(self, m: Member) -> Path:
        return trust_roots(self.runs_base, self.world_dir)[m.root]

    def path(self, m: Member) -> Path:
        return self.root(m) / m.rel

    def run(self, io: Any = _io) -> Any:
        """The handle as application code builds it (no tenant record: none is needed)."""
        return H.Run.for_tenant(S.DEFAULT_TENANT_ID, RUN_ID, runs_base=self.runs_base, io=io)

    def handle(self, m: Member, *, run: Any = None, io: Any = _io) -> Any:
        if m.root == "world_dir":
            return getattr(H.ArchivedWorld(self.world_dir, io=io), m.name)
        return S.member(run if run is not None else self.run(io), m.group, m.name,
                        *S.member_args(m.name))


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    runs_base = tmp_path / "data" / "runs"
    (runs_base / RUN_ID).mkdir(parents=True)
    world = tmp_path / "worlds" / "overlay_a"
    world.mkdir(parents=True)
    host = tmp_path / "host"
    host.mkdir()
    return Tree(tmp_path, runs_base, world, host)


# ---------------------------------------------------------------------------------------
# Plants, the tree census, the deadline
# ---------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Planted:
    kind: str
    at: Path  # the entry planted: the record's own name, or one of its holding folders

    @property
    def fifo(self) -> Path | None:
        return self.at if self.kind in ("fifo", "folder_fifo") else None

    def remove(self) -> None:
        if self.at.is_symlink() or not self.at.is_dir():
            self.at.unlink()
        else:
            shutil.rmtree(self.at)


def plant_leaf(record: Path, kind: str, *, host: Path, body: bytes = HOST_BYTES) -> Planted:
    """Plant `kind` at the record's own name; its holding folders are real."""
    record.parent.mkdir(parents=True, exist_ok=True)
    if kind == "hardlink":
        other = host / f"other-name-of-{record.name}"
        other.write_bytes(body)
        os.link(other, record)
    elif kind == "symlink":
        target = host / f"link-target-of-{record.name}"
        target.write_bytes(body)
        record.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(record)
    elif kind == "socket":
        # `mknod` makes a socket inode unprivileged; a bound AF_UNIX socket would need a path
        # under 108 bytes, which a pytest temp dir is not.
        os.mknod(record, stat.S_IFSOCK | 0o600)
    elif kind == "directory":
        record.mkdir()
        (record / "keep").write_bytes(body)
    else:
        raise AssertionError(kind)
    return Planted(kind, record)


def plant_folder(root: Path, rel: PurePosixPath, folder: PurePosixPath, kind: str, *,
                 host: Path, body: bytes = HOST_BYTES) -> Planted:
    """Plant `kind` at `folder`, one of `rel`'s holding folders. A link points at a folder
    holding the rest of the record's name, with `body` in it, so a walk that followed the link
    would find a real file there."""
    at = root / folder
    at.parent.mkdir(parents=True, exist_ok=True)
    if kind == "folder_file":
        at.write_bytes(body)
        return Planted(kind, at)
    if kind == "folder_fifo":
        os.mkfifo(at)
        return Planted(kind, at)
    elsewhere = (root if kind == "folder_link_inside" else host) / f"elsewhere-{folder.name}"
    reached = elsewhere / rel.relative_to(folder)
    reached.parent.mkdir(parents=True, exist_ok=True)
    reached.write_bytes(body)
    at.symlink_to(elsewhere, target_is_directory=True)
    return Planted(kind, at)


def plant(tree: Tree, m: Member, kind: str, folder: PurePosixPath | None) -> Planted:
    if folder is None:
        return plant_leaf(tree.path(m), kind, host=tree.host)
    return plant_folder(tree.root(m), m.rel, folder, kind, host=tree.host)


def census(top: Path) -> dict[str, tuple]:
    """Every entry under `top`, judged without following: a link's target, a regular file's
    bytes, mtime and link count, a folder, or any other kind. It never opens a FIFO."""
    out: dict[str, tuple] = {}
    for dirpath, dirnames, filenames in os.walk(top):
        for entry in (*dirnames, *filenames):
            p = Path(dirpath) / entry
            st = os.lstat(p)
            key = p.relative_to(top).as_posix()
            if stat.S_ISLNK(st.st_mode):
                out[key] = ("link", os.readlink(p))
            elif stat.S_ISREG(st.st_mode):
                out[key] = ("file", p.read_bytes(), st.st_mtime_ns, st.st_nlink)
            elif stat.S_ISDIR(st.st_mode):
                out[key] = ("dir",)
            else:
                out[key] = ("other", stat.S_IFMT(st.st_mode))
    return out


def in_time(fn: Callable[[], Any], *, fifo: Path | None = None) -> Any:
    """`fn()`'s value (or its exception, re-raised), failing if it has not returned within
    `DEADLINE` (O3). A call stuck opening `fifo` is released by opening the FIFO's other end,
    so a regression costs one failed test, not a wedged run."""
    outcome: dict[str, Any] = {}

    def body() -> None:
        try:
            outcome["value"] = fn()
        except BaseException as e:  # noqa: BLE001 — handed back to the caller's thread
            outcome["error"] = e

    worker = threading.Thread(target=body, daemon=True)
    worker.start()
    worker.join(DEADLINE)
    if worker.is_alive():
        if fifo is not None:
            with contextlib.suppress(OSError):
                os.close(os.open(fifo, os.O_RDWR | os.O_NONBLOCK))
        worker.join(DEADLINE)
        pytest.fail(f"the call did not return within {DEADLINE}s over a planted FIFO — O3: a "
                    "special file at a record's address is refused without blocking")
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def raised_by(fn: Callable[[], Any], *, fifo: Path | None = None) -> BaseException | None:
    """The exception `fn` raised under the deadline, or `None` when it returned."""
    try:
        in_time(fn, fifo=fifo)
    except Exception as e:  # noqa: BLE001 — the refusal under test, whatever its type
        return e
    return None


def assert_row(exc: BaseException | None, kind: str, *, where: str) -> None:
    """`exc` is O6's row for a `kind` plant: its type, its errno, and its alias mark."""
    typ, code, marked = O6_ROWS[kind]
    assert exc is not None, f"{where}: the write into a {kind} plant was not refused"
    want = f"O6's {typ.__name__} {errno.errorcode[code]}"
    assert isinstance(exc, typ), f"{where}: a {kind} plant raised {exc!r}, not {want}"
    assert getattr(exc, "errno", None) == code, (
        f"{where}: a {kind} plant raised {exc!r}, not {want}")
    assert bool(getattr(exc, "write_guarded_alias", False)) is marked, (
        f"{where}: a {kind} plant's refusal is {'un' if marked else ''}marked as an alias; "
        f"O6 says {'marked' if marked else 'unmarked'} (budget_enforcer's kill circuit keys "
        "on it)")


def owner_refusal(h: Any) -> BaseException | None:
    """The owner's own refusal of the address (`_confine` on a composed path resolving outside
    the run), which fires before any I/O and is unchanged by #1111. `None` if the owner builds
    the path."""
    try:
        _ = h.path
    except (OSError, ValueError) as e:
        return e
    return None


def assert_same_refusal(got: BaseException | None, owner: BaseException, *, where: str) -> None:
    assert got is not None, f"{where}: the owner refuses this address, but the op went ahead"
    assert (type(got), getattr(got, "errno", None), getattr(got, "write_guarded_alias", None)) \
        == (type(owner), getattr(owner, "errno", None),
            getattr(owner, "write_guarded_alias", None)), (
        f"{where}: the owner's refusal ({owner!r}) no longer fires first — the op raised {got!r}")


# ---------------------------------------------------------------------------------------
# A member's own verb, a payload it accepts, and what landing looks like
# ---------------------------------------------------------------------------------------

def document(m: Member, tag: str) -> str:
    """A whole document `m.write` accepts. The report must meet its schema; every other
    written record, the investigation included, takes plain text."""
    if m.rel == RUN_LAYOUT.report:
        return S.report_text(f"{m.name} {tag}\n")
    return f"{m.name} {tag}\n"


def rows(m: Member, tag: str) -> list[dict]:
    return [{"member": m.name, "tag": tag}, {"row": 2}]


def patch(m: Member, tag: str) -> dict:
    return {"member": m.name, "tag": tag}


def verb_call(h: Any, m: Member, tag: str) -> Callable[[], Any]:
    if m.verb == "write":
        return lambda: h.write(document(m, tag))
    if m.verb == "append":
        return lambda: h.append(rows(m, tag))
    if m.verb == "update":
        return lambda: h.update(patch(m, tag))
    raise AssertionError(f"{m} has no write verb")


def assert_landed(path: Path, m: Member, tag: str) -> None:
    assert not path.is_symlink(), f"{m}: a link stands at {path}"
    assert path.is_file(), f"{m}: nothing landed at {path}"
    text = path.read_text(encoding="utf-8")
    if m.verb == "write":
        assert text == document(m, tag), f"{m}: the write did not land whole"
    elif m.verb == "append":
        assert [json.loads(line) for line in text.splitlines()] == rows(m, tag), (
            f"{m}: the append did not land")
    else:
        assert json.loads(text) == patch(m, tag), f"{m}: the update did not land"


def seam_calls(rec: S.RecordingIo, mark: int) -> list[tuple[str, dict[str, Any]]]:
    """The `_io` calls `rec` saw after `mark`, each with its arguments bound by name."""
    return [(op, S.bound_arguments(op, a, kw)) for op, a, kw in rec.invocations[mark:]]


# =======================================================================================
# O4 — the matrix is the shipped tables, and it reaches every kind of address
# =======================================================================================

def test_o4_the_matrix_is_enumerated_from_the_shipped_tables_and_reaches_every_address_kind():
    """The guard matrices below are parametrized over `RUN_MEMBERS` / `ARCHIVED_MEMBERS`, built
    from `_run_handle.GROUP_MEMBERS`, `MEMBER_VERB` and `ArchivedWorld.members`, with each
    member's trust root and relative name derived from its accessor's path. So a member added
    later is guarded with no per-member code.

    Non-vacuity: the enumeration covers the spec's own copy of the table, and the derived
    addresses include every kind the design's matrix names: root-level and subfolder in-run
    records, a name two folders deep, the runs-base sidecars, and the session db under
    `sessions/`."""
    spec_names = {n for names in S.GROUP_MEMBERS.values() for n in names}
    assert spec_names <= {m.name for m in RUN_MEMBERS}, "the shipped table lost a member"
    assert set(S.ARCHIVED_WORLD_MEMBERS) <= {m.name for m in ARCHIVED_MEMBERS}
    assert any(m.root == "run_dir" and not m.folders for m in RUN_MEMBERS)
    assert any(m.root == "run_dir" and len(m.folders) == 1 for m in RUN_MEMBERS)
    assert any(m.root == "run_dir" and len(m.folders) >= 2 for m in RUN_MEMBERS)
    assert any(m.root == "runs_base" for m in RUN_MEMBERS)
    assert any(m.root == "session_root" and m.folders for m in RUN_MEMBERS)
    assert _member("wire_log").rel == RUN_LAYOUT.wire_log, "the wire log's address moved"


# =======================================================================================
# O1 / O3 — no read escapes the root, and no plant hangs a read
# =======================================================================================

def _read_cases():
    for m in READABLE:
        for kind in LEAF_PLANTS:
            yield pytest.param(m, kind, None, id=f"{m}-{kind}")
        for folder in m.folders:
            for kind in FOLDER_PLANTS:
                yield pytest.param(m, kind, folder, id=f"{m}-{kind}@{folder}")


@pytest.mark.parametrize(("m", "kind", "folder"), list(_read_cases()))
def test_o1_o3_a_plant_at_a_records_address_reads_none_and_a_plain_file_there_reads_back(
        tree, m, kind, folder):
    """O1: no handle read returns the bytes of a file reached through a symlink at any
    component below the trust root, or of anything but a plain single-linked regular file. A
    refused read is `None`, as today. O3: a FIFO (at the name, or as a holding folder) is
    refused without blocking.

    Holding folders are the new ground (C1: today's `read_guarded` judges only the leaf, so a
    `wire_logs -> /host` link reads the host's bytes). A link to a folder INSIDE the root
    reaches the walk even for the `_confine`d composed kinds. A link outside the root is
    refused by `_confine` itself for those kinds, before any read, as today (O6's "owner
    refusals fire first").

    The read changes nothing on disk. Positive control on the same address: with the plant
    removed and a plain file written there, the same handle reads it back."""
    planted = plant(tree, m, kind, folder)
    h = tree.handle(m)
    owner = owner_refusal(h)
    before = census(tree.tmp)

    if owner is not None:
        assert_same_refusal(raised_by(h.read, fifo=planted.fifo), owner, where=str(m))
    else:
        got = in_time(h.read, fifo=planted.fifo)
        assert got is None, (
            f"{m}: a {kind} plant{f' at {folder}/' if folder else ''} read {got!r} — a read "
            "escaped the record's trust root")
    assert census(tree.tmp) == before, f"{m}: a read changed the tree"

    planted.remove()
    record = tree.path(m)
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(PLAIN, encoding="utf-8")
    assert h.read() == PLAIN, f"control: a plain file at {m}'s own address did not read back"


def _fill_record_sources(tree: Tree) -> None:
    """A run whose `run.record` has something from every file it reads."""
    run_dir = tree.runs_base / RUN_ID
    owner = RunPaths(run_dir)
    owner.provenance.write_text(RunProvenance(
        commit="0" * 40, dirty=False, model="m-1111", tenant_id=S.DEFAULT_TENANT_ID,
        world_id="w-1111").as_json(), encoding="utf-8")
    owner.alert.write_bytes(b'{"alert": "1111"}\n')
    owner.report.write_text(S.report_text("# the report\n"), encoding="utf-8")
    owner.run_end_sidecar(tree.runs_base).write_text(
        json.dumps({"truncated_by": "budget", "closed_before_cut": False}), encoding="utf-8")


#: The `_io` reads `run.record` may make: today's path-based pair, and the rooted read.
_RECORD_READ_OPS = ("rooted_read", "read_guarded", "read_bytes_guarded")


def _record_sources(tree: Tree) -> list[Path]:
    """Every file `run.record` reads, by construction (O4): the address of each read call a
    pass-through recorder captured, whichever read seam it went through."""
    rec = S.RecordingIo()
    run = tree.run(io=rec)
    mark = len(rec.invocations)
    _ = run.record
    found = set()
    for op, a in seam_calls(rec, mark):
        if op == "rooted_read":
            found.add(Path(a["root"]) / PurePosixPath(a["name"]))
        elif op in _RECORD_READ_OPS:
            found.add(Path(a["path"]))
    return sorted(found)


@pytest.mark.parametrize("kind", LEAF_PLANTS)
def test_o1_o3_a_plant_at_any_file_run_record_reads_counts_as_absent(tree, kind):
    """O1 over `Run.record`: a plant at any file the record reads (enumerated by recording its
    reads, O4) makes the record exactly what it is with that file ABSENT. It is never what the
    plant's bytes would give, and never a hang (O3).

    Controls: every source feeds the record (removing it changes the record, so the negative
    can see a leak), and restoring the plain file restores the full record. Floor: the four
    reads the design names (provenance, alert bytes, report, run-end sidecar) are among those
    recorded, so the enumeration cannot shrink to nothing."""
    _fill_record_sources(tree)
    sources = _record_sources(tree)
    owner = RunPaths(tree.runs_base / RUN_ID)
    floor = {owner.provenance, owner.alert, owner.report, owner.run_end_sidecar(tree.runs_base)}
    assert floor <= set(sources), f"run.record's recorded reads {sources} miss {floor}"
    full = tree.run().record

    for src in sources:
        body = src.read_bytes()
        src.unlink()
        absent = tree.run().record
        assert absent != full, f"control: {src.name} does not feed run.record"
        planted = plant_leaf(src, kind, host=tree.host, body=body)
        before = census(tree.tmp)
        got = in_time(lambda: tree.run().record, fifo=planted.fifo)
        assert got == absent, f"a {kind} at {src.name} fed run.record: {got!r}"
        assert census(tree.tmp) == before, f"reading run.record changed the tree at {src.name}"
        planted.remove()
        src.write_bytes(body)
        assert tree.run().record == full, f"control: restoring {src.name} did not restore it"


@pytest.mark.parametrize("kind", LEAF_PLANTS)
def test_o1_the_schema_gated_writes_pre_read_does_not_read_through_a_plant(tree, kind):
    """O1 over the schema-gated write's pre-read. The investigation is validated against what
    is on disk. An over-bound document's refusal names the committed share when there is one
    ("N of those bytes are already committed") and says "Trim it" when there is none. So the
    refusal's words show what the pre-read returned.

    Control: a plain `investigation.md` holding N bytes is named in the refusal. The same N
    bytes behind a plant are not: the pre-read saw nothing, the refusal is the schema's
    `ValueError` with "Trim it", and the tree is unchanged."""
    m = _member("investigation")
    record = tree.path(m)
    committed = "x" * 1000
    over = "y" * (INVESTIGATION_FILE_MAX + 1)
    h = tree.handle(m)

    record.write_text(committed, encoding="utf-8")
    with pytest.raises(ValueError, match="1000 of those bytes are already committed"):
        h.write(over)
    record.unlink()

    planted = plant_leaf(record, kind, host=tree.host, body=committed.encode())
    before = census(tree.tmp)
    refused = raised_by(lambda: h.write(over), fifo=planted.fifo)
    assert isinstance(refused, ValueError), f"not the schema's refusal: {refused!r}"
    assert "already committed" not in str(refused), (
        f"the pre-read returned the {kind} plant's bytes: {refused}")
    assert "Trim it" in str(refused), f"not the refusal of a document with no baseline: {refused}"
    assert census(tree.tmp) == before


# =======================================================================================
# O2 / O3 / O6 / O7 — no write escapes the root; today's error shapes; the partial-failure line
# =======================================================================================

def _write_cases():
    for m in WRITABLE:
        for kind in LEAF_PLANTS:
            yield pytest.param(m, kind, None, id=f"{m}-{kind}")
        for folder in m.folders:
            for kind in FOLDER_PLANTS:
                yield pytest.param(m, kind, folder, id=f"{m}-{kind}@{folder}")


@pytest.mark.parametrize(("m", "kind", "folder"), list(_write_cases()))
def test_o2_o3_o6_o7_a_write_into_a_plant_is_refused_in_todays_shape_and_changes_nothing(
        tree, m, kind, folder):
    """O2: no handle write (`write` in create or replace, `append`, `update`), and no
    holding-folder creation it does, creates, truncates or modifies any entry reached through
    a symlink below the root, or writes into a non-plain entry. The whole temp tree is
    unchanged: the plant, the file a link or hard link reaches, the folder a link points at,
    and no folder is made anywhere. O3: a FIFO is refused without blocking.

    O6: the refusal is today's, row for row (`O6_ROWS`). A marked alias at the leaf
    (symlink ELOOP, hard link EMLINK). An unmarked ELOOP for any other non-plain leaf. An
    unmarked ELOOP for a symlinked folder, an unmarked ENOTDIR for a non-directory folder. The
    owner's `_confine` refusal still fires first for an outside link on a composed kind.

    O7: an `observability` append swallows a refused LEAF write into `run.partial_failures`
    ("<member>: append failed") and does not raise. A refused holding FOLDER propagates, as
    `_mkdir` runs outside the append's `try`.

    Positive control on the same address: the plant removed, the same call lands."""
    planted = plant(tree, m, kind, folder)
    run = tree.run()
    h = tree.handle(m, run=run)
    owner = owner_refusal(h)
    before = census(tree.tmp)

    raised = raised_by(verb_call(h, m, "refused"), fifo=planted.fifo)

    if owner is not None:
        assert_same_refusal(raised, owner, where=str(m))
    elif folder is None and m.group == "observability" and m.verb == "append":
        assert raised is None, f"O7: {m}'s refused leaf append raised {raised!r}"
        assert run.partial_failures == (f"{m.name}: append failed",), (
            f"O7: {m}'s refused leaf append was not recorded: {run.partial_failures!r}")
    else:
        assert_row(raised, kind, where=f"{m}.{m.verb}")
        assert run.partial_failures == (), (
            f"O7: a refused holding folder is not a partial failure: {run.partial_failures!r}")
    assert census(tree.tmp) == before, f"{m}: a refused {m.verb} changed the tree"

    planted.remove()
    verb_call(h, m, "landed")()
    assert_landed(tree.path(m), m, "landed")


def test_o7_a_fifo_at_the_tool_trace_is_a_partial_failure_not_a_raise_and_not_a_hang(tree):
    """O7, first case, as the design names it: a FIFO planted at `tool_trace.jsonl` with no
    reader. The append returns promptly (C22: an unguarded append open blocks forever),
    records `tool_trace: append failed`, and leaves the FIFO in place. Control: a plain file
    there takes the rows."""
    m = _member("tool_trace")
    run = tree.run()
    fifo = plant_leaf(tree.path(m), "fifo", host=tree.host)
    in_time(verb_call(tree.handle(m, run=run), m, "fifo"), fifo=fifo.at)
    assert run.partial_failures == ("tool_trace: append failed",)
    assert stat.S_ISFIFO(os.lstat(fifo.at).st_mode), "the planted FIFO was replaced"

    fifo.remove()
    verb_call(tree.handle(m, run=run), m, "plain")()
    assert_landed(tree.path(m), m, "plain")
    assert run.partial_failures == ("tool_trace: append failed",)


def test_o7_a_symlinked_wire_logs_folder_raises_and_records_no_partial_failure(tree):
    """O7, second case: `wire_logs -> <host dir>` is a holding-folder refusal, so the wire-log
    append RAISES (unmarked ELOOP) and is not swallowed into `run.partial_failures`. The host
    dir is untouched (C2). Control: a real `wire_logs/` takes the append."""
    m = _member("wire_log")
    run = tree.run()
    planted = plant_folder(tree.root(m), m.rel, m.folders[0], "folder_link_outside",
                           host=tree.host)
    before = census(tree.host)
    assert_row(raised_by(verb_call(tree.handle(m, run=run), m, "x")), "folder_link_outside",
               where="wire_log.append")
    assert run.partial_failures == ()
    assert census(tree.host) == before

    planted.remove()
    verb_call(tree.handle(m, run=run), m, "plain")()
    assert_landed(tree.path(m), m, "plain")


@pytest.mark.parametrize("m", [m for m in WRITABLE if m.verb == "write"], ids=str)
def test_o6_a_second_write_is_refused_as_write_once_only_where_the_record_is_write_once(
        tree, m):
    """O6's write-once row: a second `write` of a write-once record raises `FileExistsError`
    with the "is write-once" message, unmarked, and the first write stands. Control: every
    other written record takes the second write whole (replace)."""
    h = tree.handle(m)
    h.write(document(m, "first"))
    if m.name in WRITE_ONCE:
        with pytest.raises(FileExistsError, match="is write-once") as again:
            h.write(document(m, "second"))
        assert not getattr(again.value, "write_guarded_alias", False), (
            "a write-once collision is not an alias")
        assert_landed(tree.path(m), m, "first")
    else:
        h.write(document(m, "second"))
        assert_landed(tree.path(m), m, "second")


#: The staged name the occupying double hands out: already taken when the replace stages.
OCCUPIED = ".staged-occupied"


class _OccupiedStageIo(S.RecordingIo):
    """The pass-through recorder, handing every `rooted_write` a `stage_name` whose answer is
    already taken. It is the one O6 row no plant can reach through the handle: the real staged
    name is unpredictable (`<leaf>.staged-<16 hex>`) by design."""

    def rooted_write(self, *args: Any, **kwargs: Any) -> Any:
        kwargs["stage_name"] = lambda leaf: f"{leaf}{OCCUPIED}"
        return self._dispatch("rooted_write")(*args, **kwargs)


@pytest.mark.parametrize("m", REPLACED, ids=str)
def test_o6_an_occupied_staged_name_refuses_the_replace_as_a_marked_eexist(tree, m):
    """O6's staged-name row, through the handle: when the name the replace stages under is
    already taken, the write raises `EEXIST`, marked as an alias, and changes nothing (neither
    the record nor the occupying entry). Control: the same call with the real staged name
    lands."""
    record = tree.path(m)
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(document(m, "before"), encoding="utf-8")
    record.with_name(f"{record.name}{OCCUPIED}").write_bytes(HOST_BYTES)
    before = census(tree.tmp)

    refused = raised_by(lambda: tree.handle(m, io=_OccupiedStageIo()).write(document(m, "x")))
    assert isinstance(refused, OSError), f"{m}: an occupied staged name raised {refused!r}"
    assert refused.errno == errno.EEXIST, f"{m}: {refused!r} is not O6's EEXIST"
    assert getattr(refused, "write_guarded_alias", None) is True, "O6: the EEXIST is marked"
    assert census(tree.tmp) == before

    tree.handle(m).write(document(m, "after"))
    assert_landed(record, m, "after")


def _hostile(args: tuple[Any, ...]) -> tuple[Any, ...]:
    return tuple("../escape" if isinstance(a, str) else -1 for a in args)


@pytest.mark.parametrize("m", [m for m in RUN_MEMBERS if S.member_args(m.name)], ids=str)
def test_o6_a_malformed_component_is_the_owners_value_error_before_any_io(tree, m):
    """O6, "also unchanged": the owner's path-building refusal (`ValueError` for a malformed
    component) fires first, for the read and for the verb, and the handle's `io` sees no call.
    Control: the well-formed component reaches `io`."""
    rec = S.RecordingIo()
    run = tree.run(io=rec)
    mark = len(rec.invocations)
    h = S.member(run, m.group, m.name, *_hostile(S.member_args(m.name)))
    ops = [h.read] + ([verb_call(h, m, "x")] if m in WRITABLE else [])
    for op in ops:
        # The owner's wording differs per accessor; its type is the contract.
        with pytest.raises(ValueError):  # noqa: PT011
            op()
    assert rec.invocations[mark:] == [], f"{m}: io was reached before the owner refused"

    tree.handle(m, run=run).read()
    assert rec.invocations[mark:], "control: the well-formed read never reached io"


# =======================================================================================
# O5 — the root's spelling is followed; a missing root is created on write, absent on read
# =======================================================================================

@pytest.mark.parametrize("m", [m for m in RUN_MEMBERS if m.root == "run_dir"], ids=str)
def test_o5_run_at_over_a_symlinked_run_dir_reads_and_writes_every_in_run_record(tree, m):
    """O5: `Run.at` over a symlinked spelling of the run dir keeps that spelling (C16) and
    every in-run record reads and writes through it. The root is host-trusted and followed;
    only what is below it is judged."""
    alias = tree.tmp / "alias-of-the-run"
    alias.symlink_to(tree.runs_base / RUN_ID, target_is_directory=True)
    h = S.member(H.Run.at(alias), m.group, m.name, *S.member_args(m.name))
    assert h.path == alias / m.rel, "Run.at no longer keeps the alias spelling"

    real = tree.path(m)
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text(PLAIN, encoding="utf-8")
    assert h.read() == PLAIN, f"{m}: a plain read through a symlinked run dir was refused"
    if m.verb in ("write", "append", "update"):
        real.unlink()
        verb_call(h, m, "via-alias")()
        assert_landed(real, m, "via-alias")


@pytest.mark.parametrize("aliased", ["data_root", "runs_base"])
@pytest.mark.parametrize("m", RUN_MEMBERS, ids=str)
def test_o5_a_symlinked_runs_base_or_data_root_keeps_every_record_readable_and_writable(
        tmp_path, m, aliased):
    """O5, one symlinked spelling per trust root: a symlinked runs base (C12), and a symlinked
    data root above it. The data root is the session db's own trust root; the runs base is the
    sidecars'; either link is an ancestor of the run dir. Every record reads, and every
    writable one writes, through the followed spelling."""
    real = tmp_path / "real-data"
    (real / "runs" / RUN_ID).mkdir(parents=True)
    data = tmp_path / "data"
    if aliased == "data_root":
        data.symlink_to(real, target_is_directory=True)
    else:
        data.mkdir()
        (data / "runs").symlink_to(real / "runs", target_is_directory=True)
    tree = Tree(tmp_path, data / "runs", tmp_path / "unused-world", tmp_path)
    h = tree.handle(m)

    record = tree.path(m)
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(PLAIN, encoding="utf-8")
    assert h.read() == PLAIN, f"{m}: a plain read under a symlinked {aliased} was refused"
    if m.verb in ("write", "append", "update"):
        record.unlink()
        verb_call(h, m, "via-alias")()
        assert_landed(record, m, "via-alias")


@pytest.mark.parametrize("m", ARCHIVED_MEMBERS, ids=str)
def test_o5_an_archived_world_at_a_symlinked_world_dir_reads_every_member(tree, m):
    """O5 for `ArchivedWorld`: its root, the world dir, is followed when spelled through a
    symlink."""
    alias = tree.tmp / "alias-of-the-world"
    alias.symlink_to(tree.world_dir, target_is_directory=True)
    (tree.world_dir / m.rel).write_text(PLAIN, encoding="utf-8")
    assert getattr(H.ArchivedWorld.at(alias), m.name).read() == PLAIN


@pytest.mark.parametrize("m", WRITABLE, ids=str)
def test_o5_a_write_under_a_missing_root_creates_it_following_links(tmp_path, m):
    """O5 (C23): a write under a root that does not exist yet (here neither the runs base nor
    the run dir) creates it, following the links in its spelling as `guarded_mkdir` does. The
    data root is a symlink, and the record lands in the folder it points at."""
    real = tmp_path / "real-data"
    real.mkdir()
    (tmp_path / "data").symlink_to(real, target_is_directory=True)
    tree = Tree(tmp_path, tmp_path / "data" / "runs", tmp_path / "unused-world", tmp_path)
    assert not tree.root(m).exists()

    verb_call(tree.handle(m), m, "created")()
    assert_landed(real / tree.path(m).relative_to(tmp_path / "data"), m, "created")


@pytest.mark.parametrize("m", READABLE, ids=str)
def test_o5_a_read_under_a_missing_root_is_none_and_creates_nothing(tmp_path, m):
    """O5: a read under a root that does not exist is absent: `None`, and nothing is made."""
    tree = Tree(tmp_path, tmp_path / "data" / "runs", tmp_path / "worlds" / "gone", tmp_path)
    before = census(tmp_path)
    assert tree.handle(m).read() is None
    assert census(tmp_path) == before, f"{m}: a read under a missing root made something"


def test_o5_run_record_reads_through_a_symlinked_runs_base_and_a_symlinked_run_dir(tree):
    """O5 over `Run.record`: through a symlinked runs base, and through `Run.at` over a
    symlinked run dir, the record reads exactly what the real spelling reads. The run-end
    field needs the runs base, which `Run.at` does not hold."""
    _fill_record_sources(tree)
    full = tree.run().record
    assert full.alert_ref is not None, "precondition: the alert is read"
    assert full.exit_class is not None, "precondition: the run-end sidecar is read"

    base_alias = tree.tmp / "alias-of-runs"
    base_alias.symlink_to(tree.runs_base, target_is_directory=True)
    via_base = H.Run.for_tenant(S.DEFAULT_TENANT_ID, RUN_ID, runs_base=base_alias).record
    assert via_base == full

    run_alias = tree.tmp / "aliases" / RUN_ID  # the run id is the directory's own name
    run_alias.parent.mkdir()
    run_alias.symlink_to(tree.runs_base / RUN_ID, target_is_directory=True)
    assert H.Run.at(run_alias).record == dataclasses.replace(full, exit_class=None)


# =======================================================================================
# O8 — every handle file op crosses the `io=` seam as a rooted call carrying (root, name)
# =======================================================================================

@pytest.mark.parametrize("m", READABLE, ids=str)
def test_o8_a_read_crosses_the_io_seam_as_one_rooted_read_of_its_trust_root_and_name(tree, m):
    """O8: `RecordHandle.read` / `_ArchivedRecordHandle.read` is exactly one
    `io.rooted_read(root, name)`. `root` is the member's trust root from the design's M2 table
    (the run dir; the runs base for a sidecar; `SessionPaths(runs_base).trust_root` for the
    session db; the world dir). `name` is the record's name relative to it; `binary` is
    False. No other `_io` call is made, so no path-based seam (`read_guarded`)."""
    record = tree.path(m)
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(PLAIN, encoding="utf-8")
    rec = S.RecordingIo()
    h = tree.handle(m, io=rec)
    mark = len(rec.invocations)

    assert h.read() == PLAIN
    calls = seam_calls(rec, mark)
    assert [op for op, _ in calls] == ["rooted_read"], (
        f"{m}'s read reached {[op for op, _ in calls]}, not one rooted read")
    ((_, a),) = calls
    assert (Path(a["root"]), PurePosixPath(a["name"]), a["binary"]) \
        == (tree.root(m), m.rel, False), f"{m}: read as {a!r}"


@pytest.mark.parametrize("m", WRITABLE, ids=str)
def test_o8_a_write_crosses_the_io_seam_as_rooted_calls_carrying_root_name_mode_and_payload(
        tree, m):
    """O8, and M2's routing table: a member's verb makes only rooted calls, each on the
    member's trust root.

    - Exactly one writing call, on the record's relative name. `write` is
      `rooted_write(mode="create")` for a write-once record and `mode="replace"` otherwise,
      with the given text. `append` is ONE `rooted_write(mode="append")` whose text is the
      whole batch as JSONL. `update` is `rooted_locked_for_rewrite` in text mode.
    - Before it, a `rooted_mkdir` on the same root: for a record in a subfolder, of that
      folder. The folder's spelling for a root-level record is left to the implementation.
    - The two schema-gated documents first read their current text with `rooted_read` of the
      same name; nothing else reads.

    The write really lands."""
    rec = S.RecordingIo()
    h = tree.handle(m, io=rec)
    mark = len(rec.invocations)
    verb_call(h, m, "seam")()
    assert_landed(tree.path(m), m, "seam")

    calls = seam_calls(rec, mark)
    ops = [op for op, _ in calls]
    assert set(ops) <= ROOTED_OPS, f"{m}.{m.verb} reached {ops}: a path-based `_io` seam"
    root = tree.root(m)
    assert all(Path(a["root"]) == root for _, a in calls), f"{m}: not all on {root}: {calls}"

    writer = "rooted_locked_for_rewrite" if m.verb == "update" else "rooted_write"
    at = [i for i, op in enumerate(ops) if op == writer]
    assert len(at) == 1, f"{m}.{m.verb}: {len(at)} {writer} calls in {ops}"
    a = calls[at[0]][1]
    assert PurePosixPath(a["name"]) == m.rel
    if m.verb == "write":
        assert a["mode"] == ("create" if m.name in WRITE_ONCE else "replace")
        assert a["text"] == document(m, "seam")
    elif m.verb == "append":
        assert a["mode"] == "append"
        assert a["text"].endswith("\n")
        assert [json.loads(line) for line in a["text"].splitlines()] == rows(m, "seam")
    else:
        assert a["binary"] is False

    mkdirs = [i for i, op in enumerate(ops) if op == "rooted_mkdir"]
    assert mkdirs, f"{m}: no rooted_mkdir made its holding folder: {ops}"
    assert max(mkdirs) < at[0], f"{m}: the rooted_mkdir came after the write: {ops}"
    if m.folders:
        assert m.rel.parent in {PurePosixPath(calls[i][1]["folder_name"]) for i in mkdirs}, (
            f"{m}: its holding folder {m.rel.parent} was not made through rooted_mkdir")

    reads = [(i, a) for i, (op, a) in enumerate(calls) if op == "rooted_read"]
    if m.rel in (RUN_LAYOUT.report, RUN_LAYOUT.investigation):
        assert len(reads) == 1, f"{m}: not one schema pre-read: {ops}"
        assert reads[0][0] < at[0], f"{m}: the schema pre-read came after the write: {ops}"
        assert PurePosixPath(reads[0][1]["name"]) == m.rel
    else:
        assert reads == [], f"{m}: read something while writing: {ops}"


def test_o8_the_alert_bytes_are_written_as_given_through_the_create_lane(tree):
    """O8 on the production write run setup makes (`run_common._write_alert_once`): the alert's
    bytes, CRLF and non-ASCII included, reach `rooted_write(mode="create")` as given and land
    byte for byte."""
    body = b'{"alert": "\xc3\xa9t\xc3\xa9"}\r\n'
    rec = S.RecordingIo()
    run = tree.run(io=rec)
    mark = len(rec.invocations)
    run.facts.alert.write(body)
    assert (tree.runs_base / RUN_ID / RUN_LAYOUT.alert).read_bytes() == body
    writes = [a for op, a in seam_calls(rec, mark) if op == "rooted_write"]
    assert [(w["mode"], w["text"]) for w in writes] == [("create", body)]


def test_o8_run_record_reads_its_four_sources_as_rooted_reads(tree):
    """O8 over `Run.record`: its reads are `rooted_read`s and nothing else. The provenance,
    the alert (as bytes, `binary=True`, for the hash) and the report are read on the run dir.
    The run-end sidecar is read on the runs base."""
    _fill_record_sources(tree)
    rec = S.RecordingIo()
    run = tree.run(io=rec)
    mark = len(rec.invocations)
    assert run.record.alert_ref is not None

    calls = seam_calls(rec, mark)
    assert {op for op, _ in calls} == {"rooted_read"}, [op for op, _ in calls]
    run_dir = tree.runs_base / RUN_ID
    got = sorted((str(Path(a["root"])), PurePosixPath(a["name"]).as_posix(), a["binary"])
                 for _, a in calls)
    want = sorted([
        (str(run_dir), RUN_LAYOUT.provenance.as_posix(), False),
        (str(run_dir), RUN_LAYOUT.alert.as_posix(), True),
        (str(run_dir), RUN_LAYOUT.report.as_posix(), False),
        (str(tree.runs_base), RunPaths(run_dir).run_end_sidecar(tree.runs_base).name, False),
    ])
    assert got == want


# =======================================================================================
# The seam itself — `_io.rooted_read` / `rooted_mkdir` / `rooted_write` /
# `rooted_locked_for_rewrite`, driven directly
# =======================================================================================

#: A name two folders deep, so each folder is planted in turn.
DEEP = PurePosixPath("a/b/rec.json")
MODES = ("create", "replace", "append")

#: Names outside `_parse_name`'s grammar: absolute, climbing, empty or `.` components, a NUL.
BAD_NAMES = ("", "/abs/rec.json", "..", "../rec.json", "a/../rec.json", "a//rec.json",
             "./rec.json", "a/", "rec\x00.json")


@dataclasses.dataclass(frozen=True)
class Scratch:
    tmp: Path
    root: Path
    host: Path

    def real_folders(self, rel: PurePosixPath = DEEP) -> Path:
        (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
        return self.root / rel


@pytest.fixture
def scratch(tmp_path: Path) -> Scratch:
    root = tmp_path / "root"
    root.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    return Scratch(tmp_path, root, host)


def _seam_plants():
    for kind in LEAF_PLANTS:
        yield pytest.param(kind, None, id=kind)
    for folder in DEEP.parents[:-1]:
        for kind in FOLDER_PLANTS:
            yield pytest.param(kind, folder, id=f"{kind}@{folder}")


def _plant_deep(s: Scratch, kind: str, folder: PurePosixPath | None) -> Planted:
    if folder is None:
        return plant_leaf(s.root / DEEP, kind, host=s.host)
    return plant_folder(s.root, DEEP, folder, kind, host=s.host)


# -- rooted_read ------------------------------------------------------------------------

def test_rooted_read_returns_the_text_or_the_bytes_of_a_plain_file(scratch):
    """The positive half, and the return shape of `read_guarded` / `read_bytes_guarded`:
    `(text, None)`, or `(bytes, None)` with `binary=True` (exact bytes, CRLF kept). `name`
    may be a `str` or a `PurePosixPath`."""
    target = scratch.real_folders()
    target.write_bytes(b"line\r\nnext\n")
    assert _io.rooted_read(scratch.root, "a/b/rec.json", binary=True) \
        == (b"line\r\nnext\n", None)
    text, reason = _io.rooted_read(scratch.root, DEEP)
    assert reason is None
    assert isinstance(text, str)
    assert text.replace("\r", "") == "line\nnext\n"


def test_rooted_read_is_absent_for_a_missing_leaf_folder_or_root(scratch):
    """Absence is `(None, reason)`, never a raise: a missing record, a missing holding folder,
    a missing root (O5)."""
    (scratch.root / "a").mkdir()
    for root, name in ((scratch.root, "a/rec.json"), (scratch.root, "a/b/rec.json"),
                       (scratch.tmp / "no-such-root", "rec.json")):
        text, reason = _io.rooted_read(root, name)
        assert text is None, (root, name)
        assert isinstance(reason, str), (root, name)
        assert reason, (root, name)


def test_rooted_read_refuses_undecodable_text_but_returns_its_bytes(scratch):
    """A non-UTF-8 record is a text refusal, `(None, reason)`, as `read_guarded`'s is. Its
    bytes read as bytes."""
    (scratch.root / "rec.json").write_bytes(b"\xff\xfe not utf-8")
    text, reason = _io.rooted_read(scratch.root, "rec.json")
    assert text is None
    assert isinstance(reason, str)
    assert _io.rooted_read(scratch.root, "rec.json", binary=True) == (b"\xff\xfe not utf-8", None)


@pytest.mark.parametrize(("kind", "folder"), list(_seam_plants()))
@pytest.mark.parametrize("binary", [False, True], ids=["text", "bytes"])
def test_rooted_read_refuses_every_plant_without_blocking(scratch, kind, folder, binary):
    """M1's read rule: every component below the root opened no-follow, the leaf opened
    `O_NONBLOCK` and judged on its descriptor. Any plant (a link or hard link to a real file, a
    special file, a symlinked or non-directory folder) is `(None, reason)`, promptly, and
    changes nothing. Control: the plant removed and a plain file written, the same call reads
    it."""
    planted = _plant_deep(scratch, kind, folder)
    before = census(scratch.tmp)
    got, reason = in_time(lambda: _io.rooted_read(scratch.root, DEEP, binary=binary),
                          fifo=planted.fifo)
    assert got is None, f"a {kind} plant read {got!r}"
    assert isinstance(reason, str), f"a {kind} plant's refusal gave no reason: {reason!r}"
    assert census(scratch.tmp) == before

    planted.remove()
    scratch.real_folders().write_bytes(b"plain\n")
    assert _io.rooted_read(scratch.root, DEEP, binary=binary)[0] \
        == (b"plain\n" if binary else "plain\n")


def test_rooted_read_follows_the_roots_own_spelling(scratch):
    """O5: the root is opened following its spelling (a symlinked root, or a root under a
    symlinked folder). Only what is below it is judged."""
    scratch.real_folders().write_text(PLAIN, encoding="utf-8")
    alias = scratch.tmp / "alias"
    alias.symlink_to(scratch.root, target_is_directory=True)
    assert _io.rooted_read(alias, DEEP) == (PLAIN, None)
    via = scratch.tmp / "via"
    via.symlink_to(scratch.tmp, target_is_directory=True)
    assert _io.rooted_read(via / "root", DEEP) == (PLAIN, None)


@pytest.mark.parametrize("name", BAD_NAMES)
def test_rooted_read_never_reads_a_name_outside_the_grammar(scratch, name):
    """A name outside `_parse_name`'s grammar is never read. The design leaves open whether
    it raises `ValueError` (`Bound.read` does) or answers `(None, reason)`. It must not
    return the file a climbing name would reach."""
    (scratch.tmp / "rec.json").write_bytes(HOST_BYTES)
    (scratch.root / "rec.json").write_bytes(HOST_BYTES)
    try:
        got = _io.rooted_read(scratch.root, name)
    except ValueError:
        return
    assert got[0] is None, f"{name!r} read {got!r}"
    assert isinstance(got[1], str), f"{name!r} answered {got!r}, not (None, reason)"


# -- rooted_mkdir -----------------------------------------------------------------------

def test_rooted_mkdir_creates_a_missing_root_following_links_then_each_folder(scratch):
    """M1: a missing root is created following links (`os.makedirs`, as `guarded_mkdir`'s
    base). Each missing folder is then created relative to its parent. It is idempotent."""
    link = scratch.tmp / "link"
    link.symlink_to(scratch.host, target_is_directory=True)
    root = link / "new" / "root"
    _io.rooted_mkdir(root, "a/b")
    assert (scratch.host / "new" / "root" / "a" / "b").is_dir()
    assert not (scratch.host / "new" / "root" / "a").is_symlink()
    _io.rooted_mkdir(root, PurePosixPath("a/b"))
    _io.rooted_mkdir(scratch.root, "a")
    assert (scratch.root / "a").is_dir()


@pytest.mark.parametrize("kind", FOLDER_PLANTS)
@pytest.mark.parametrize("folder", [PurePosixPath("a"), PurePosixPath("a/b")], ids=str)
def test_rooted_mkdir_refuses_a_linked_or_non_directory_folder_in_todays_shape(
        scratch, kind, folder):
    """O6's folder rows for the holding-folder creation: a symlinked folder is an unmarked
    `ELOOP`; a non-directory (a file, a FIFO, promptly) is an unmarked `NotADirectoryError`.
    Nothing is created through the link or anywhere else. Control: the plant removed, the
    same call creates the folders."""
    planted = plant_folder(scratch.root, DEEP, folder, kind, host=scratch.host)
    before = census(scratch.tmp)
    assert_row(raised_by(lambda: _io.rooted_mkdir(scratch.root, "a/b"), fifo=planted.fifo),
               kind, where="rooted_mkdir")
    assert census(scratch.tmp) == before

    planted.remove()
    _io.rooted_mkdir(scratch.root, "a/b")
    assert not (scratch.root / "a" / "b").is_symlink()
    assert (scratch.root / "a" / "b").is_dir()


@pytest.mark.parametrize("name", [n for n in BAD_NAMES if n != ""])
def test_rooted_mkdir_refuses_a_name_outside_the_grammar_and_creates_nothing(scratch, name):
    """`_parse_name`'s grammar, before anything is made. (The empty name is left out: the
    design does not say how the handle names "the root itself" for a root-level record.)"""
    before = census(scratch.tmp)
    with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract, not the wording
        _io.rooted_mkdir(scratch.root, name)
    assert census(scratch.tmp) == before


# -- rooted_write -----------------------------------------------------------------------

def _assert_single_plain_0644(path: Path) -> None:
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode), f"{path} is not a regular file"
    assert st.st_nlink == 1, f"{path} has {st.st_nlink} names, not one"
    assert stat.S_IMODE(st.st_mode) == 0o644, f"{path} has mode {oct(stat.S_IMODE(st.st_mode))}"


def test_rooted_write_create_lands_once_single_linked_and_a_second_create_is_unmarked(scratch):
    """`create`: the record lands whole, single-linked, mode 0644 (#1078's lane). A second
    create of the same name is the ordinary race: `FileExistsError`, unmarked, the first
    content standing."""
    target = scratch.real_folders()
    _io.rooted_write(scratch.root, DEEP, "first\n", mode="create")
    assert target.read_text(encoding="utf-8") == "first\n"
    _assert_single_plain_0644(target)
    with pytest.raises(FileExistsError) as again:
        _io.rooted_write(scratch.root, DEEP, "second\n", mode="create")
    assert not getattr(again.value, "write_guarded_alias", False)
    assert target.read_text(encoding="utf-8") == "first\n"


def test_rooted_write_create_links_the_unnamed_file_it_opened_off_the_parent_descriptor(
        scratch):
    """The addendum's lane 1: `open_unnamed(dir_fd)` gets a descriptor of the record's own
    parent folder, reached by the walk, not a path. The name is then linked to exactly that
    unnamed file (same inode), which has one name and mode 0644. A reader sees the name
    absent or complete, never partial."""
    target = scratch.real_folders()
    seen: dict[str, Any] = {}

    def open_unnamed(dir_fd: int) -> int:
        st = os.fstat(dir_fd)
        seen["dir"] = (st.st_dev, st.st_ino, stat.S_ISDIR(st.st_mode))
        seen["absent_at_open"] = not os.path.lexists(target)
        fd = os.open(".", os.O_TMPFILE | os.O_WRONLY, 0o644, dir_fd=dir_fd)
        seen["file"] = os.dup(fd)
        return fd

    _io.rooted_write(scratch.root, DEEP, "body\n", mode="create", open_unnamed=open_unnamed)
    try:
        parent = os.stat(target.parent)
        assert seen["dir"] == (parent.st_dev, parent.st_ino, True), (
            "open_unnamed was not handed the record's parent folder")
        assert seen["absent_at_open"], "the name existed before the unnamed file was opened"
        unnamed = os.fstat(seen["file"])
        linked = os.stat(target)
        assert (linked.st_dev, linked.st_ino) == (unnamed.st_dev, unnamed.st_ino), (
            "the name was not linked to the unnamed file (a named create, not lane 1)")
    finally:
        os.close(seen["file"])
    assert target.read_text(encoding="utf-8") == "body\n"
    _assert_single_plain_0644(target)


def _no_unnamed_files(errno_: int) -> Callable[[int], int]:
    """An `open_unnamed` answering as a filesystem without `O_TMPFILE` does (NFS, virtiofs), or
    with a real failure."""
    def refuse(dir_fd: int) -> int:
        raise OSError(errno_, os.strerror(errno_))
    return refuse


@pytest.mark.parametrize("unsupported", [errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL],
                         ids=errno.errorcode.get)
def test_rooted_write_create_falls_back_where_no_unnamed_file_can_be_made(scratch, unsupported):
    """The addendum's lane 2: where the unnamed open answers EOPNOTSUPP / EISDIR / EINVAL, the
    create falls back to one named `O_EXCL|O_NOFOLLOW` open. The record lands once, and a
    second create is `FileExistsError`, unmarked."""
    target = scratch.real_folders()
    _io.rooted_write(scratch.root, DEEP, "{}\n", mode="create",
                     open_unnamed=_no_unnamed_files(unsupported))
    assert target.read_text(encoding="utf-8") == "{}\n"
    assert os.lstat(target).st_nlink == 1
    with pytest.raises(FileExistsError) as again:
        _io.rooted_write(scratch.root, DEEP, "{}\n", mode="create",
                         open_unnamed=_no_unnamed_files(unsupported))
    assert not getattr(again.value, "write_guarded_alias", False)


def test_rooted_write_create_propagates_an_unrelated_unnamed_open_failure(scratch):
    """Any other errno from the unnamed open (here ENOSPC) is this call's own failure. It
    propagates, is not retried through the fallback, and leaves nothing at the name."""
    target = scratch.real_folders()
    with pytest.raises(OSError) as failed:  # noqa: PT011 — its errno is asserted below
        _io.rooted_write(scratch.root, DEEP, "{}\n", mode="create",
                         open_unnamed=_no_unnamed_files(errno.ENOSPC))
    assert failed.value.errno == errno.ENOSPC
    assert not os.path.lexists(target)


@pytest.mark.parametrize("lane", ["unnamed", "fallback"])
def test_rooted_write_create_that_fails_mid_write_leaves_the_name_absent(scratch, lane):
    """A create whose body cannot be written (an unencodable string) leaves no entry at all,
    in either lane: the entry this call would have made is never named, or is removed."""
    target = scratch.real_folders()
    before = census(scratch.tmp)
    kw = {} if lane == "unnamed" else {"open_unnamed": _no_unnamed_files(errno.EOPNOTSUPP)}
    with pytest.raises(UnicodeError):
        _io.rooted_write(scratch.root, DEEP, "bad \udc80 surrogate", mode="create", **kw)
    assert not os.path.lexists(target)
    assert census(scratch.tmp) == before


def test_rooted_write_replace_swaps_the_whole_record_in_and_leaves_no_staged_file(scratch):
    """`replace`: the new text replaces the old whole, the record stays one plain name, and no
    `.staged-` entry is left beside it. Bytes land as given."""
    target = scratch.real_folders()
    target.write_text("old\n", encoding="utf-8")
    _io.rooted_write(scratch.root, DEEP, "new\n", mode="replace")
    assert target.read_text(encoding="utf-8") == "new\n"
    _io.rooted_write(scratch.root, "a/b/rec.json", b"\x00raw\r\n", mode="replace")
    assert target.read_bytes() == b"\x00raw\r\n"
    assert os.lstat(target).st_nlink == 1
    assert sorted(p.name for p in target.parent.iterdir()) == ["rec.json"]


def test_rooted_write_replace_stages_under_the_name_stage_name_gives_for_the_leaf(scratch):
    """The `stage_name(leaf: str) -> str` seam: it is asked for the record's leaf name, and
    an already-taken answer refuses the replace with `EEXIST`, marked as an alias (O6). The
    record and the occupying entry are unchanged. Control: a free staged name lands, and is
    gone afterwards."""
    target = scratch.real_folders()
    target.write_text("old\n", encoding="utf-8")
    (target.parent / "rec.json.staged-taken").write_bytes(HOST_BYTES)
    asked: list[str] = []

    def taken(leaf: str) -> str:
        asked.append(leaf)
        return f"{leaf}.staged-taken"

    before = census(scratch.tmp)
    with pytest.raises(OSError) as refused:  # noqa: PT011 — its errno is asserted below
        _io.rooted_write(scratch.root, DEEP, "new\n", mode="replace", stage_name=taken)
    assert refused.value.errno == errno.EEXIST
    assert getattr(refused.value, "write_guarded_alias", None) is True
    assert asked == ["rec.json"], f"stage_name was asked {asked!r}, not the leaf name"
    assert census(scratch.tmp) == before

    _io.rooted_write(scratch.root, DEEP, "new\n", mode="replace",
                     stage_name=lambda leaf: f"{leaf}.staged-free")
    assert target.read_text(encoding="utf-8") == "new\n"
    assert not (target.parent / "rec.json.staged-free").exists()


def test_rooted_write_replace_that_fails_mid_write_keeps_the_record_and_removes_its_stage(
        scratch):
    """A replace whose body cannot be written leaves the record as it was and removes the
    staged file it made."""
    target = scratch.real_folders()
    target.write_text("old\n", encoding="utf-8")
    before = census(scratch.tmp)
    with pytest.raises(UnicodeError):
        _io.rooted_write(scratch.root, DEEP, "bad \udc80 surrogate", mode="replace")
    assert census(scratch.tmp) == before


def test_rooted_write_append_creates_then_appends(scratch):
    """`append`: the record is created when absent, then each call adds to its end."""
    target = scratch.real_folders()
    _io.rooted_write(scratch.root, DEEP, '{"n": 1}\n', mode="append")
    _io.rooted_write(scratch.root, DEEP, '{"n": 2}\n', mode="append")
    assert target.read_text(encoding="utf-8") == '{"n": 1}\n{"n": 2}\n'


@pytest.mark.parametrize("mode", MODES)
def test_rooted_write_walks_the_folders_without_creating_them(scratch, mode):
    """M1: `rooted_write` walks the holding folders no-follow and does NOT create them. A
    missing folder, or a missing root, is `FileNotFoundError` and nothing is made. Folders
    are `rooted_mkdir`'s job."""
    before = census(scratch.tmp)
    with pytest.raises(FileNotFoundError):
        _io.rooted_write(scratch.root, DEEP, "x\n", mode=mode)
    with pytest.raises(FileNotFoundError):
        _io.rooted_write(scratch.tmp / "no-such-root", "rec.json", "x\n", mode=mode)
    assert census(scratch.tmp) == before


@pytest.mark.parametrize(("kind", "folder"), list(_seam_plants()))
@pytest.mark.parametrize("mode", MODES)
def test_rooted_write_refuses_every_plant_in_todays_shape_and_changes_nothing(
        scratch, mode, kind, folder):
    """O2/O3/O6 at the seam, for each mode. The leaf is judged before any open: a symlink is a
    marked ELOOP, a hard link a marked EMLINK, and any other non-plain leaf an unmarked ELOOP,
    promptly. A symlinked folder is an unmarked ELOOP; a non-directory folder an unmarked
    ENOTDIR. The planted entry, and whatever it reaches, are unchanged. Control: the plant
    removed (and real folders made), the same call lands."""
    planted = _plant_deep(scratch, kind, folder)
    before = census(scratch.tmp)
    assert_row(raised_by(lambda: _io.rooted_write(scratch.root, DEEP, "x\n", mode=mode),
                         fifo=planted.fifo), kind, where=f"rooted_write({mode})")
    assert census(scratch.tmp) == before

    planted.remove()
    target = scratch.real_folders()
    _io.rooted_write(scratch.root, DEEP, "x\n", mode=mode)
    assert target.read_text(encoding="utf-8") == "x\n"


@pytest.mark.parametrize("mode", MODES)
def test_rooted_write_follows_the_roots_own_spelling(scratch, mode):
    """O5: a symlinked root is followed; the record lands in the folder it points at."""
    scratch.real_folders()
    alias = scratch.tmp / "alias"
    alias.symlink_to(scratch.root, target_is_directory=True)
    _io.rooted_write(alias, DEEP, "via alias\n", mode=mode)
    assert (scratch.root / DEEP).read_text(encoding="utf-8") == "via alias\n"


@pytest.mark.parametrize("name", BAD_NAMES)
@pytest.mark.parametrize("mode", MODES)
def test_rooted_write_refuses_a_name_outside_the_grammar_and_writes_nothing(
        scratch, mode, name):
    (scratch.root / "a").mkdir()
    before = census(scratch.tmp)
    with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract, not the wording
        _io.rooted_write(scratch.root, name, "x\n", mode=mode)
    assert census(scratch.tmp) == before


def test_rooted_write_refuses_an_unknown_mode_and_writes_nothing(scratch):
    scratch.real_folders()
    before = census(scratch.tmp)
    with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract, not its wording
        _io.rooted_write(scratch.root, DEEP, "x\n", mode="truncate")
    assert census(scratch.tmp) == before


# -- rooted_locked_for_rewrite -----------------------------------------------------------

def test_rooted_locked_for_rewrite_yields_the_record_locked_at_position_0(scratch):
    """The locked read-modify-write: the record at position 0 with its current text, under an
    exclusive `flock` that a second open cannot take until the block exits. What the block
    writes persists."""
    target = scratch.real_folders()
    target.write_text('{"k": 1}', encoding="utf-8")
    with _io.rooted_locked_for_rewrite(scratch.root, DEEP) as f:
        assert f.tell() == 0
        assert f.read() == '{"k": 1}'
        other = os.open(target, os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(other)
        f.seek(0)
        f.truncate()
        f.write('{"k": 2}')
    assert target.read_text(encoding="utf-8") == '{"k": 2}'
    other = os.open(target, os.O_RDONLY)
    try:
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(other)


def test_rooted_locked_for_rewrite_creates_a_missing_record_and_reads_bytes_in_binary(scratch):
    target = scratch.real_folders()
    with _io.rooted_locked_for_rewrite(scratch.root, DEEP) as f:
        assert f.read() == ""
    assert target.is_file()
    assert os.lstat(target).st_nlink == 1
    target.write_bytes(b"\x00raw")
    with _io.rooted_locked_for_rewrite(scratch.root, "a/b/rec.json", binary=True) as f:
        assert f.read() == b"\x00raw"


@pytest.mark.parametrize(("kind", "folder"), list(_seam_plants()))
def test_rooted_locked_for_rewrite_refuses_every_plant_before_its_block_runs(
        scratch, kind, folder):
    """O2/O3/O6 for `update`'s seam: the same rows as `rooted_write`, promptly, before the
    block runs, with nothing changed. Control: the plant removed, the block runs on the
    record."""
    planted = _plant_deep(scratch, kind, folder)
    before = census(scratch.tmp)
    entered: list[bool] = []

    def lock() -> None:
        with _io.rooted_locked_for_rewrite(scratch.root, DEEP):
            entered.append(True)

    assert_row(raised_by(lock, fifo=planted.fifo), kind, where="rooted_locked_for_rewrite")
    assert entered == [], "the locked block ran on a plant"
    assert census(scratch.tmp) == before

    planted.remove()
    scratch.real_folders()
    lock()
    assert entered == [True]


def test_rooted_locked_for_rewrite_follows_the_roots_own_spelling(scratch):
    target = scratch.real_folders()
    target.write_text("{}", encoding="utf-8")
    alias = scratch.tmp / "alias"
    alias.symlink_to(scratch.root, target_is_directory=True)
    with _io.rooted_locked_for_rewrite(alias, DEEP) as f:
        assert f.read() == "{}"


@pytest.mark.parametrize("name", BAD_NAMES)
def test_rooted_locked_for_rewrite_refuses_a_name_outside_the_grammar(scratch, name):
    (scratch.root / "a").mkdir()
    before = census(scratch.tmp)
    lock = _io.rooted_locked_for_rewrite
    # The grammar's type is the contract, not its wording.
    with pytest.raises(ValueError), lock(scratch.root, name):  # noqa: PT011
        pass
    assert census(scratch.tmp) == before
