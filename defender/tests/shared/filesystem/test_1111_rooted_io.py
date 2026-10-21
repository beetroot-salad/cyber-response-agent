"""Every read and write the Run handle makes walks no-follow from the record's trust root: the plant matrix (symlink, hardlink, FIFO, device, folder links) over every record member, the root's own spelling being followed, and the direct _io.rooted_* seam rules (name grammar, create complete-or-absent lane, replace staging)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base, location_path

import contextlib
import dataclasses
import errno
import json
import os
import random
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender.run_repository import _handle as H
from defender.records._artifact_schema import INVESTIGATION_FILE_MAX
from defender.records._provenance import RunProvenance
from defender.run_repository import RUN_LAYOUT, RunPaths, SessionPaths
from defender.tests.support.shared.contracts import _spec1077 as S
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.support.shared.contracts._create_lane import assert_single_plain, no_unnamed_files
from defender.tests.support.shared.filesystem._umask import umask
from defender.tests.support.shared._fixture_uuid import fixture_uuid

#: #1187 declared change 1: a run id is a canonical lowercase uuid4 text.
RUN_ID = fixture_uuid("rooted-io-1111")
#: How long one call may take before O3 calls it hung. A right answer takes milliseconds; the
#: deadline only bounds a regression, so it fails the test rather than wedging the run.
DEADLINE = 3.0


#: Today's write-once members (`create`; a second write is refused). Not #1111's to change.
WRITE_ONCE = frozenset({"alert", "alert_record", "provenance", "leads"})

#: What a plant can put AT a record's name.
LEAF_PLANTS = ("hardlink", "symlink", "fifo", "socket", "directory")
#: What a plant can put at a holding folder between the root and the record.
FOLDER_PLANTS = ("folder_link_inside", "folder_link_outside", "folder_file", "folder_fifo")

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
    # A device node is "any other non-plain leaf" too (see the device and posing tests below).
    "char_device": (OSError, errno.ELOOP, False),
    "block_device": (OSError, errno.ELOOP, False),
}

#: What a planted entry holds, or what a link or hard link reaches: the bytes a read that
#: followed it would return, and that a write through it would change.
HOST_BYTES = b'{"planted": "HOST"}\n'
#: What a plain file at the record's own address holds: the positive control's answer.
PLAIN = "plain record at its own address\n"


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
        "session_root": location_path(SessionPaths(fixture_runs_base(runs_base)).trust_root),
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
    run = H.Run.under(fixture_runs_base(_PROBE_BASE), RUN_ID)
    roots = trust_roots(_PROBE_BASE, _PROBE_WORLD)
    out = []
    for group, names in H.GROUP_MEMBERS.items():
        for name in names:
            path = S.member(run, group, name, *S.member_args(name)).path
            root, rel = _address(path, {k: v for k, v in roots.items() if k != "world_dir"})
            verb = "append_text" if name in {"wire_log", "policy_denials", "review_trace"} else H.MEMBER_VERB[name]
            out.append(Member(group, name, verb, root, rel))
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
WRITABLE = tuple(m for m in RUN_MEMBERS if m.verb in ("write", "append", "append_text", "update"))
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
        return trust_roots(location_path(self.runs_base), self.world_dir)[m.root]

    def path(self, m: Member) -> Path:
        return self.root(m) / m.rel

    def run(self, io: Any = _io) -> Any:
        """The handle as application code builds it. #1187 (R1): `Run.for_tenant` and the
        runs base's `_tenant.json` it read are retired; `Run.under(container, id, tenant_id=)`
        replaces it, over a container holding no record."""
        return H.Run.under(location_path(self.runs_base), RUN_ID, tenant_id=S.DEFAULT_TENANT_ID, io=io)

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
    if m.verb == "append_text":
        return lambda: h.append_text("".join(json.dumps(row) + "\n" for row in rows(m, tag)))
    if m.verb == "update":
        return lambda: h.update(patch(m, tag))
    raise AssertionError(f"{m} has no write verb")


def assert_landed(path: Path, m: Member, tag: str) -> None:
    assert not path.is_symlink(), f"{m}: a link stands at {path}"
    assert path.is_file(), f"{m}: nothing landed at {path}"
    text = path.read_text(encoding="utf-8")
    if m.verb == "write":
        assert text == document(m, tag), f"{m}: the write did not land whole"
    elif m.verb in ("append", "append_text"):
        assert [json.loads(line) for line in text.splitlines()] == rows(m, tag), (
            f"{m}: the append did not land")
    else:
        assert json.loads(text) == patch(m, tag), f"{m}: the update did not land"


def seam_calls(rec: S.RecordingIo, mark: int) -> list[tuple[str, dict[str, Any]]]:
    """The `_io` calls `rec` saw after `mark`, each with its arguments bound by name."""
    return [(op, S.bound_arguments(op, a, kw)) for op, a, kw in rec.invocations[mark:]]


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
    run_dir = location_path(tree.runs_base) / RUN_ID
    owner = RunPaths(run_dir)
    owner.provenance.write_text(RunProvenance(
        commit="0" * 40, dirty=False, model="m-1111", tenant_id=S.DEFAULT_TENANT_ID,
        world_id="w-1111").as_json(), encoding="utf-8")
    plant_alert(run_dir, b'{"alert": "1111"}\n')
    owner.report.write_text(S.report_text("# the report\n"), encoding="utf-8")
    owner.run_end_sidecar(location_path(tree.runs_base)).write_text(
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
    _fill_record_sources(tree)
    sources = _record_sources(tree)
    owner = RunPaths(location_path(tree.runs_base) / RUN_ID)
    floor = {owner.provenance, owner.alert, owner.alert_record, owner.report,
             owner.run_end_sidecar(location_path(tree.runs_base))}
    assert floor <= set(sources), f"run.record's recorded reads {sources} miss {floor}"
    full = tree.run().record

    for src in sources:
        body = src.read_bytes()
        src.unlink()
        absent = tree.run().record
        if src != owner.alert:
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


@pytest.mark.parametrize("m", [m for m in RUN_MEMBERS if m.root == "run_dir"], ids=str)
def test_o5_run_at_over_a_symlinked_run_dir_reads_and_writes_every_in_run_record(tree, m):
    alias = tree.tmp / "alias-of-the-run"
    alias.symlink_to(location_path(tree.runs_base) / RUN_ID, target_is_directory=True)
    h = S.member(H.Run.at(alias), m.group, m.name, *S.member_args(m.name))
    assert h.path == alias / m.rel, "Run.at no longer keeps the alias spelling"

    real = tree.path(m)
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text(PLAIN, encoding="utf-8")
    assert h.read() == PLAIN, f"{m}: a plain read through a symlinked run dir was refused"
    if m.verb in ("write", "append", "append_text", "update"):
        real.unlink()
        verb_call(h, m, "via-alias")()
        assert_landed(real, m, "via-alias")


@pytest.mark.parametrize("aliased", ["data_root", "runs_base"])
@pytest.mark.parametrize("m", RUN_MEMBERS, ids=str)
def test_o5_a_symlinked_runs_base_or_data_root_keeps_every_record_readable_and_writable(
        tmp_path, m, aliased):
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
    if m.verb in ("write", "append", "append_text", "update"):
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
    real = tmp_path / "real-data"
    real.mkdir()
    (tmp_path / "data").symlink_to(real, target_is_directory=True)
    tree = Tree(tmp_path, tmp_path / "data" / "runs", tmp_path / "unused-world", tmp_path)
    assert not tree.root(m).exists()

    # #1105 NH-3 planted the runs base's record here, after the precondition; #1187 (R1)
    # retired the record, but the runs base is still made here so the cases stay the ones the
    # docstring names.
    if m.root != "world_dir":
        location_path(tree.runs_base).mkdir()
    verb_call(tree.handle(m), m, "created")()
    assert_landed(real / tree.path(m).relative_to(tmp_path / "data"), m, "created")


@pytest.mark.parametrize("m", READABLE, ids=str)
def test_o5_a_read_under_a_missing_root_is_none_and_creates_nothing(tmp_path, m):
    tree = Tree(tmp_path, tmp_path / "data" / "runs", tmp_path / "worlds" / "gone", tmp_path)
    if m.root != "world_dir":  # #1105 NH-3's precondition, kept (#1187 R1: no record now)
        location_path(tree.runs_base).mkdir(parents=True)
    before = census(tmp_path)
    assert tree.handle(m).read() is None
    assert census(tmp_path) == before, f"{m}: a read under a missing root made something"


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

def test_rooted_write_create_lands_once_single_linked_and_a_second_create_is_unmarked(scratch):
    target = scratch.real_folders()
    with umask(0o022):
        _io.rooted_write(scratch.root, DEEP, "first\n", mode="create")
    assert target.read_text(encoding="utf-8") == "first\n"
    assert_single_plain(target, 0o644)
    with pytest.raises(FileExistsError) as again:
        _io.rooted_write(scratch.root, DEEP, "second\n", mode="create")
    assert not getattr(again.value, "write_guarded_alias", False)
    assert target.read_text(encoding="utf-8") == "first\n"


def test_rooted_write_create_links_the_unnamed_file_it_opened_off_the_parent_descriptor(
        scratch):
    target = scratch.real_folders()
    seen: dict[str, Any] = {}

    def open_unnamed(dir_fd: int) -> int:
        st = os.fstat(dir_fd)
        seen["dir"] = (st.st_dev, st.st_ino, stat.S_ISDIR(st.st_mode))
        seen["absent_at_open"] = not os.path.lexists(target)
        fd = os.open(".", os.O_TMPFILE | os.O_WRONLY, 0o644, dir_fd=dir_fd)
        seen["file"] = os.dup(fd)
        return fd

    with umask(0o022):
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
    assert_single_plain(target, 0o644)


@pytest.mark.parametrize("unsupported", [errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL],
                         ids=errno.errorcode.get)
def test_rooted_write_create_falls_back_where_no_unnamed_file_can_be_made(scratch, unsupported):
    target = scratch.real_folders()
    _io.rooted_write(scratch.root, DEEP, "{}\n", mode="create",
                     open_unnamed=no_unnamed_files(unsupported))
    assert target.read_text(encoding="utf-8") == "{}\n"
    assert os.lstat(target).st_nlink == 1
    with pytest.raises(FileExistsError) as again:
        _io.rooted_write(scratch.root, DEEP, "{}\n", mode="create",
                         open_unnamed=no_unnamed_files(unsupported))
    assert not getattr(again.value, "write_guarded_alias", False)


@pytest.mark.parametrize("lane", ["unnamed", "fallback"])
def test_rooted_write_create_that_fails_mid_write_leaves_the_name_absent(scratch, lane):
    """A create whose body cannot be written (an unencodable string) leaves no entry at all,
    in either lane: the entry this call would have made is never named, or is removed."""
    target = scratch.real_folders()
    before = census(scratch.tmp)
    kw = {} if lane == "unnamed" else {"open_unnamed": no_unnamed_files(errno.EOPNOTSUPP)}
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


class PassThroughOs:
    """The real `os` module, handed in as the seam's `os_`: every attribute is the real one
    unless a subclass overrides it."""

    def __getattr__(self, name: str) -> Any:
        return getattr(os, name)


DEVICES = {"char_device": (stat.S_IFCHR, os.makedev(1, 3)),
           "block_device": (stat.S_IFBLK, os.makedev(7, 200))}


def plant_device(path: Path, kind: str) -> Planted:
    fmt, dev = DEVICES[kind]
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mknod(path, fmt | 0o600, dev)
    except PermissionError:
        pytest.skip("making a device node needs CAP_MKNOD, which CI's non-root runner lacks; "
                    "the posing tests below pin the same row on every host")
    return Planted(kind, path)


#: The seam ops a leaf judge guards: both reads and each write mode. (The lock,
#: `rooted_locked_for_rewrite`, left with #1235.)
SEAM_OPS = ("read", "read_bytes", "create", "replace", "append")


def seam_op(s: Scratch, op: str, **kw: Any) -> Callable[[], Any]:
    """One seam op on `DEEP`, with `kw` (an `os_=`) passed through."""
    if op == "read":
        return lambda: _io.rooted_read(s.root, DEEP, **kw)
    if op == "read_bytes":
        return lambda: _io.rooted_read(s.root, DEEP, binary=True, **kw)
    if op in MODES:
        return lambda: _io.rooted_write(s.root, DEEP, f"{op} landed\n", mode=op, **kw)
    raise AssertionError(f"no seam op {op!r}")


def assert_seam_refused(op: str, kind: str, fn: Callable[[], Any], *,
                        fifo: Path | None = None) -> None:
    """A read answers `(None, reason)`; every write mode raises O6's row for `kind`.
    Promptly, either way."""
    if op.startswith("read"):
        got = in_time(fn, fifo=fifo)
        assert got[0] is None, f"{op} of a {kind} leaf returned {got[0]!r}"
        assert isinstance(got[1], str), f"{op} of a {kind} leaf gave no reason: {got!r}"
    else:
        assert_row(raised_by(fn, fifo=fifo), kind, where=f"{op} of a {kind} leaf")


def assert_seam_lands(s: Scratch, op: str, **kw: Any) -> None:
    """The positive control: the same op, on a plain file (or, for `create`, on no file),
    lands."""
    target = s.real_folders()
    if op.startswith("read"):
        target.write_bytes(b"plain\n")
        want = b"plain\n" if op == "read_bytes" else "plain\n"
        assert seam_op(s, op, **kw)() == (want, None), f"control: {op} of a plain file"
        return
    if op == "create" and os.path.lexists(target):
        target.unlink()
    seam_op(s, op, **kw)()
    assert target.read_text(encoding="utf-8").endswith(f"{op} landed\n"), f"control: {op}"


# -- hole 1: a device at the leaf ----------------------------------------------------------

@pytest.mark.parametrize("op", SEAM_OPS)
@pytest.mark.parametrize("kind", sorted(DEVICES))
def test_o1_o2_o6_a_device_node_at_the_leaf_is_refused_as_non_plain(scratch, kind, op):
    planted = plant_device(scratch.root / DEEP, kind)
    before = census(scratch.tmp)
    assert_seam_refused(op, kind, seam_op(scratch, op))
    assert census(scratch.tmp) == before

    planted.remove()
    assert_seam_lands(scratch, op)


def test_o1_o2_a_device_node_at_any_members_address_is_refused_through_the_handle(tree):
    for m in READABLE:
        planted = plant_device(tree.path(m), "char_device")
        assert tree.handle(m).read() is None, f"{m}: a device at its address read back"
        planted.remove()
    for m in WRITABLE:
        planted = plant_device(tree.path(m), "char_device")
        run = tree.run()
        h = tree.handle(m, run=run)
        raised = raised_by(verb_call(h, m, "refused"))
        if m.group == "observability" and m.verb == "append":
            assert raised is None, f"O7: {m}'s refused leaf append raised {raised!r}"
            assert run.partial_failures == (f"{m.name}: append failed",)
        else:
            assert_row(raised, "char_device", where=f"{m}.{m.verb}")
        planted.remove()
        verb_call(h, m, "landed")()
        assert_landed(tree.path(m), m, "landed")


class _PosesAs(PassThroughOs):
    """Reports one real, plain, single-linked file's `stat` / `lstat` / `fstat` (the calls
    named in `on`) as another kind: its file-type bits swapped for `fmt`, and/or its link count
    for `nlink`. Every other entry's answers are the real ones, matched by device and inode, so
    only the leaf is posed."""

    def __init__(self, target: Path, *, fmt: int, nlink: int | None = None,
                 on: tuple[str, ...] = ("stat", "fstat")) -> None:
        real = os.lstat(target)
        self._identity = (real.st_dev, real.st_ino)
        self._fmt = fmt
        self._nlink = nlink
        self._on = on

    def _pose(self, st: os.stat_result, call: str) -> os.stat_result:
        if call not in self._on or (st.st_dev, st.st_ino) != self._identity:
            return st
        fields = list(st)  # (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime)
        fields[0] = self._fmt | stat.S_IMODE(st.st_mode)
        if self._nlink is not None:
            fields[3] = self._nlink
        return os.stat_result(fields)

    def stat(self, *a: Any, **kw: Any) -> os.stat_result:
        return self._pose(os.stat(*a, **kw), "stat")

    def lstat(self, *a: Any, **kw: Any) -> os.stat_result:
        return self._pose(os.lstat(*a, **kw), "stat")

    def fstat(self, fd: int) -> os.stat_result:
        return self._pose(os.fstat(fd), "fstat")


#: A type-bit pattern no `S_IF*` constant names: a deny-list of the known non-plain kinds
#: lets it through; the allow-list (`S_ISREG` and one name) does not.
_UNKNOWN_TYPE = 0o030000

#: What `_PosesAs` makes a plain file look like: `(file-type bits, link count or None)`.
POSES: dict[str, tuple[int, int | None]] = {
    "as_char_device": (stat.S_IFCHR, None),
    "as_block_device": (stat.S_IFBLK, None),
    "as_fifo": (stat.S_IFIFO, None),
    "as_socket": (stat.S_IFSOCK, None),
    "as_directory": (stat.S_IFDIR, None),
    "as_unknown_type": (_UNKNOWN_TYPE, None),
    "as_symlink": (stat.S_IFLNK, None),
    "as_hard_linked": (stat.S_IFREG, 2),
}
O6_ROWS.update({
    **{pose: (OSError, errno.ELOOP, False) for pose in POSES},
    "as_symlink": (OSError, errno.ELOOP, True),
    "as_hard_linked": (OSError, errno.EMLINK, True),
})


# -- hole 2: the race window between the leaf's check and its open ------------------------

@pytest.mark.parametrize("op", ["read", "read_bytes", "append"])
@pytest.mark.parametrize("pose", sorted(p for p in POSES if p != "as_symlink"))
def test_o2_o3_the_opened_leaf_is_rejudged_on_its_descriptor(scratch, pose, op):
    target = scratch.real_folders()
    target.write_bytes(b"plain\n")
    fmt, nlink = POSES[pose]
    before = census(scratch.tmp)
    posing = _PosesAs(target, fmt=fmt, nlink=nlink, on=("fstat",))
    assert_seam_refused(op, pose, seam_op(scratch, op, os_=posing))
    assert census(scratch.tmp) == before, f"{op} wrote into a leaf its descriptor called {pose}"

    assert_seam_lands(scratch, op, os_=PassThroughOs())


class _SwapsAfterCheck(PassThroughOs):
    """Answers the leaf's pre-open no-follow `stat` (relative to its parent's descriptor)
    truthfully, THEN runs `swap`, which replaces the leaf with a plant: the race window between
    the check and the open, made deterministic. `swapped` says whether that check ran."""

    def __init__(self, leaf: str, swap: Callable[[], None] | None) -> None:
        self._leaf = leaf
        self._swap = swap
        self.swapped = False

    def stat(self, path: Any, *a: Any, **kw: Any) -> os.stat_result:
        try:
            return os.stat(path, *a, **kw)
        finally:
            if (not self.swapped and kw.get("dir_fd") is not None
                    and kw.get("follow_symlinks") is False and os.fspath(path) == self._leaf):
                self.swapped = True
                if self._swap is not None:
                    self._swap()


@pytest.mark.parametrize("op", ["append"])
@pytest.mark.parametrize("swap", ["hardlink", "fifo", "symlink", "directory"])
def test_o2_o3_a_plant_swapped_in_after_the_leaf_check_is_refused_on_the_descriptor(
        scratch, swap, op):
    target = scratch.real_folders()
    target.write_bytes(b"plain\n")
    host_file = scratch.host / "host-file"
    host_file.write_bytes(HOST_BYTES)

    def plant_now() -> None:
        target.unlink()
        if swap == "hardlink":
            os.link(host_file, target)
        elif swap == "fifo":
            os.mkfifo(target)
        elif swap == "directory":
            target.mkdir()
        else:
            target.symlink_to(host_file)

    host_before = (host_file.read_bytes(), os.stat(host_file).st_mtime_ns)
    racing = _SwapsAfterCheck(target.name, plant_now)
    raised = raised_by(seam_op(scratch, op, os_=racing), fifo=target if swap == "fifo" else None)
    assert racing.swapped, (
        "no pre-open `os_.stat(<leaf>, dir_fd=<parent>, follow_symlinks=False)` ran "
        f"(the {op} raised {raised!r})")
    assert_row(raised, swap, where=f"{op} into a {swap} swapped in after the check")
    assert (host_file.read_bytes(), os.stat(host_file).st_mtime_ns) == host_before, (
        f"the {op} went through the swapped-in {swap} into the host file")
    kind = stat.S_IFMT(os.lstat(target).st_mode)
    assert kind == {"hardlink": stat.S_IFREG, "fifo": stat.S_IFIFO, "symlink": stat.S_IFLNK,
                    "directory": stat.S_IFDIR}[swap]

    if swap == "directory":
        target.rmdir()
    else:
        target.unlink()
    target.write_bytes(b"plain\n")
    control = _SwapsAfterCheck(target.name, None)
    assert_seam_lands(scratch, op, os_=control)
    assert control.swapped, "control: the pre-open check did not run"


# -- one plainness rule, read and write alike ---------------------------------------------

@pytest.mark.parametrize("op", ["read", "read_bytes", "bound_read", "append"])
def test_a_file_a_replace_unnamed_after_it_was_opened_still_counts_as_plain(scratch, op):
    target = scratch.real_folders()
    target.write_bytes(b"plain\n")
    unnamed = _PosesAs(target, fmt=stat.S_IFREG, nlink=0, on=("fstat",))
    if op == "read":
        assert _io.rooted_read(scratch.root, DEEP, os_=unnamed) == ("plain\n", None)
    elif op == "read_bytes":
        assert _io.rooted_read(scratch.root, DEEP, binary=True, os_=unnamed) == (b"plain\n", None)
    elif op == "bound_read":
        with _io.bind(scratch.root, os_=unnamed) as bound:
            assert bound.read(DEEP.as_posix()).text == "plain\n"
    else:
        assert_seam_lands(scratch, op, os_=unnamed)


def test_a_write_once_collision_writes_no_body(scratch):
    target = scratch.real_folders()
    target.write_text("first\n", encoding="utf-8")
    opened: list[int] = []

    def open_unnamed(dir_fd: int) -> int:
        opened.append(dir_fd)
        return _io.open_unnamed_at(dir_fd)

    with pytest.raises(FileExistsError) as again:
        _io.rooted_write(scratch.root, DEEP, "second\n", mode="create", open_unnamed=open_unnamed)
    assert not getattr(again.value, "write_guarded_alias", False)
    assert opened == [], "a body was staged for a create the standing record already refused"
    assert target.read_text(encoding="utf-8") == "first\n"


# -- hole 3: create's DEFAULT lane --------------------------------------------------------

class _RecordsCreate(PassThroughOs):
    """Records every `link`, with whether the record's name already existed at that moment
    (a real `lstat`, before delegating), and every `open` of the record's name that carried
    `O_CREAT`."""

    def __init__(self, target: Path) -> None:
        self._target = target
        self.links: list[dict[str, Any]] = []
        self.creating_opens: list[tuple[str, int]] = []

    def link(self, src: Any, dst: Any, *a: Any, **kw: Any) -> None:
        self.links.append({
            "src": os.fspath(src), "dst": os.fspath(dst), "dst_dir_fd": kw.get("dst_dir_fd"),
            "follow_symlinks": kw.get("follow_symlinks", True),
            "name_existed": os.path.lexists(self._target)})
        return os.link(src, dst, *a, **kw)

    def open(self, path: Any, flags: int, *a: Any, **kw: Any) -> int:
        if os.path.basename(os.fspath(path)) == self._target.name and flags & os.O_CREAT:
            self.creating_opens.append((os.fspath(path), flags))
        return os.open(path, flags, *a, **kw)


def test_create_with_the_default_open_unnamed_links_an_unnamed_file_and_never_opens_the_name(
        scratch):
    target = scratch.real_folders()
    recorder = _RecordsCreate(target)
    with umask(0o022):
        _io.rooted_write(scratch.root, DEEP, "body\n", mode="create", os_=recorder)

    assert recorder.creating_opens == [], (
        f"the default create opened the record's name with O_CREAT: {recorder.creating_opens}")
    assert len(recorder.links) == 1, f"not one link names the record: {recorder.links}"
    (link,) = recorder.links
    assert link["src"].startswith("/proc/self/fd/"), f"not an unnamed file's link: {link}"
    assert link["dst"] == target.name, link
    assert link["dst_dir_fd"] is not None, f"not linked relative to the parent: {link}"
    assert link["follow_symlinks"] is True, link
    assert link["name_existed"] is False, "the name existed before its one link"
    assert target.read_text(encoding="utf-8") == "body\n"
    assert_single_plain(target, 0o644)


#: A child looping over the handle's production write-once write (run setup's alert), each in
#: a fresh run dir, until it is killed.
_ALERT_CRASH_CHILD = r"""
import os, sys, uuid
from pathlib import Path
from defender.run_repository import Run
root = Path(sys.argv[1])
body = b"A" * (int(sys.argv[2]) - 1) + b"\n"
print("ready", flush=True)
while True:
    run_id = str(uuid.uuid4())  # #1187: a run id is canonical uuid4 text
    os.mkdir(root / run_id)
    Run.under(root, run_id).facts.alert.write(body)
"""

ALERT_BODY_BYTES = 1 << 20
ALERT_KILLS = 16


def _alert_leftovers(root: Path, body: bytes) -> tuple[list[str], int]:
    """Every run dir the killed child made holds nothing, or one whole single-named alert."""
    bad: list[str] = []
    whole = 0
    for d in sorted(root.iterdir()):
        names = sorted(os.listdir(d))
        if names not in ([], [RUN_LAYOUT.alert_input_dir.name]):
            bad.append(f"{d.name}: stray entries {names}")
            continue
        if not names:
            continue
        held = sorted(os.listdir(d / RUN_LAYOUT.alert_input_dir))
        if held not in ([], [RUN_LAYOUT.alert.name]):
            bad.append(f"{d.name}: stray entries {held} in the input directory")
            continue
        if not held:
            continue
        alert = d / RUN_LAYOUT.alert
        st = os.lstat(alert)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            bad.append(f"{d.name}: the alert is not one plain name ({st})")
        elif alert.read_bytes() != body:
            bad.append(f"{d.name}: a torn alert of {st.st_size} bytes")
        else:
            whole += 1
    return bad, whole


def test_the_handles_alert_write_leaves_no_alert_or_a_whole_one_when_killed(tmp_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{S.REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)
    body = b"A" * (ALERT_BODY_BYTES - 1) + b"\n"

    def one_kill(kill: int) -> tuple[list[str], int]:
        root = tmp_path / f"kill-{kill}"
        root.mkdir()
        # A file, not a pipe: reading a live child's stderr pipe for a failure message would
        # block until it exits, and this child never does on its own.
        errors = tmp_path / f"kill-{kill}.stderr"
        with errors.open("w", encoding="utf-8") as err:
            child = subprocess.Popen(  # noqa: S603 — fixed argv, the test's own interpreter
                [sys.executable, "-c", _ALERT_CRASH_CHILD, str(root), str(ALERT_BODY_BYTES)],
                env=env, stdout=subprocess.PIPE, stderr=err, text=True)
        try:
            assert child.stdout is not None
            assert child.stdout.readline().strip() == "ready", errors.read_text(encoding="utf-8")
            time.sleep(random.uniform(0.02, 0.15))
            if child.poll() is not None:
                pytest.fail("the alert-writing child died on its own: "
                            + errors.read_text(encoding="utf-8"))
            child.send_signal(signal.SIGKILL)
        finally:
            # On every exit (a failed assert, an interrupt): the child loops forever, writing
            # 1 MiB alerts, so it is killed here, never left running.
            if child.poll() is None:
                child.kill()
            child.wait(timeout=30)
            if child.stdout is not None:
                child.stdout.close()
        bad, landed = _alert_leftovers(root, body)
        return [f"kill {kill}: {b}" for b in bad], landed

    # Each kill is its own child in its own run dir, so they run side by side: sixteen start-ups
    # one after another were the whole cost of this test.
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(one_kill, range(ALERT_KILLS)))
    torn = [line for lines, _ in outcomes for line in lines]
    whole = sum(landed for _, landed in outcomes)
    assert torn == [], "a kill left a torn or stray alert:\n" + "\n".join(torn)
    assert whole > 0, "the child wrote no whole alert, so the kills observed nothing"
