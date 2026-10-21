from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import fixture_data_root

import dataclasses
import errno
import functools
import hashlib
import json
import os
import stat
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.tenancy import _tenant as owner
from defender.tests.support.shared.contracts._create_lane import assert_single_plain
from defender.tests.support.shared.filesystem._umask import umask
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H

TID = fixture_uuid("tenant:acme")
OTHER = fixture_uuid("tenant:beta")
#: The good row's timestamp.
GOOD_AT = "2026-09-26T00:00:00+00:00"
#: The row a linked `<T>` leads to has its own timestamp, so "served" is seen to be THAT row.
LINKED_AT = "2026-01-02T03:04:05+00:00"
#: The second name a hard-linked row has, outside the data root.
SECOND_NAME = "second-name.json"
#: How long one entry-point call may take before the test calls it hung.
_PATIENCE = 60

_NEEDS_FIFO = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="this platform has no FIFOs")


@dataclasses.dataclass(frozen=True)
class Where:
    """One test's data root, and a sibling folder outside it that holds link targets and a hard
    link's second name."""

    root: Path
    outside: Path

    @property
    def dir(self) -> Path:
        return self.root / TID

    @property
    def row(self) -> Path:
        return self.dir / "tenant.json"


def _where(tmp_path: Path) -> Where:
    w = Where(tmp_path / "data", tmp_path / "outside")
    w.outside.mkdir()
    return w


def _row_text(tenant_id: str = TID, created_at: str = GOOD_AT) -> str:
    """A row as `create_tenant` writes one: the two fields, sorted, indented, newline-ended."""
    return json.dumps({"tenant_id": tenant_id, "created_at": created_at},
                      indent=2, sort_keys=True) + "\n"


#: The good row's text.
GOOD_ROW = _row_text()


def _put_row(w: Where, body: str | bytes = GOOD_ROW) -> None:
    """A plain, single-named row at `<T>/tenant.json`, with `<T>` made first. It is a good row
    unless `body` says otherwise; bytes are written verbatim."""
    w.dir.mkdir(parents=True, exist_ok=True)
    if isinstance(body, bytes):
        w.row.write_bytes(body)
    else:
        w.row.write_text(body, encoding="utf-8")


def _remove(path: Path) -> None:
    """Take away whatever stands at `path`, without following it: a link or file is unlinked,
    an (empty) folder removed."""
    if stat.S_ISDIR(os.lstat(path).st_mode):
        path.rmdir()
    else:
        path.unlink()


def _restore(w: Where, *, remove: Path | None = None) -> None:
    """The positive control's plain state: `remove` cleared, then a good row put at the row."""
    if remove is not None:
        _remove(remove)
    _put_row(w)


def _tree_state(top: Path) -> dict[str, tuple[int, int, int, str | None]]:
    """Every entry below `top`, judged without following it: its type, permission bits and link
    count, plus a link's target or a regular file's digest. Nothing but a regular file is ever
    opened, because a FIFO opened to hash it would block."""
    state: dict[str, tuple[int, int, int, str | None]] = {}
    pending = [top]
    while pending:
        folder = pending.pop()
        with os.scandir(folder) as listing:
            for entry in listing:
                st = entry.stat(follow_symlinks=False)
                detail: str | None = None
                if stat.S_ISLNK(st.st_mode):
                    detail = os.readlink(entry.path)
                elif stat.S_ISREG(st.st_mode):
                    # Streamed, not read whole: the oversized-row shape is past READ_LIMIT.
                    with open(entry.path, "rb") as plain:
                        detail = hashlib.file_digest(plain, "sha256").hexdigest()
                elif stat.S_ISDIR(st.st_mode):
                    pending.append(Path(entry.path))
                state[os.path.relpath(entry.path, top)] = (
                    stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_nlink, detail)
    return state


def _outcome(fn: Callable[..., Any], *args: Any, **kw: Any) -> tuple[Any, Exception | None]:
    """`fn(*args, **kw)`'s value, or the exception it raised. The call runs in a daemon thread
    with `_PATIENCE` seconds to finish, so a reader that opened a planted FIFO blocking fails the
    test instead of hanging the suite."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = fn(*args, **kw)
        except Exception as raised:  # noqa: BLE001 — classified by the caller
            box["raised"] = raised

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(_PATIENCE)
    if worker.is_alive():
        pytest.fail(f"{fn.__name__} did not return within {_PATIENCE}s; did it open a planted "
                    "FIFO without O_NONBLOCK?")
    return box.get("value"), box.get("raised")


def _served(fn: Callable[..., Any], *args: Any, **kw: Any) -> Any:
    value, raised = _outcome(fn, *args, **kw)
    assert raised is None, f"{fn.__name__} refused where today it serves: {raised!r}"
    return value


def _refused(fn: Callable[..., Any], *args: Any, **kw: Any) -> str:
    """The refusal's message, after checking that the call refused with `TenantRefused` itself:
    no subclass, and no bare `OSError` or `ValueError` escaping."""
    value, raised = _outcome(fn, *args, **kw)
    assert raised is not None, f"{fn.__name__} served {value!r} where today it refuses"
    assert type(raised) is owner.TenantRefused, (
        f"{fn.__name__} refused with {type(raised).__name__}, not TenantRefused: {raised}")
    return str(raised)


def _assert_names(message: str, subject: Path, *, folder: bool = False) -> None:
    """The refusal opens with `subject`'s path: the row's, or, for a refused folder, `<T>`'s
    followed by `: `, so that a refusal naming the row does not pass for one naming its folder."""
    opening = f"{subject}: " if folder else str(subject)
    assert message.startswith(opening), (
        f"the refusal does not open with {opening!r}: {message!r}")


@dataclasses.dataclass(frozen=True)
class ReadShape:
    """One shape the row or its folder takes. `repair` is None for a shape that is served (it
    is its own positive control); otherwise it turns the same address into a good, plain row.
    `words`, when set, is a phrase the refusal carries that the design keeps."""

    plant: Callable[[Where], None]
    repair: Callable[[Where], None] | None
    words: str | None = None


def _plant_linked_dir(w: Where) -> None:
    """`<T>` is a link to a real folder outside the root, which holds a good row (LINKED_AT)."""
    real = w.outside / "real-T"
    real.mkdir()
    (real / "tenant.json").write_text(_row_text(created_at=LINKED_AT), encoding="utf-8")
    w.root.mkdir(parents=True)
    w.dir.symlink_to(real)


def _plant_live_link(w: Where) -> None:
    """The row is a link to a GOOD row outside the root: a reader that followed it would serve."""
    target = w.outside / "target.json"
    target.write_text(GOOD_ROW, encoding="utf-8")
    w.dir.mkdir(parents=True)
    w.row.symlink_to(target)


def _plant_dangling_link(w: Where) -> None:
    w.dir.mkdir(parents=True)
    w.row.symlink_to(w.outside / "nowhere.json")


def _plant_fifo(w: Where) -> None:
    w.dir.mkdir(parents=True)
    os.mkfifo(w.row)


def _plant_hard_link(w: Where) -> None:
    """A GOOD row with a second name outside the root."""
    _put_row(w)
    os.link(w.row, w.outside / SECOND_NAME)


def _plant_file_at_dir(w: Where) -> None:
    """A regular file stands at `<T>`. It holds a good row's text."""
    w.root.mkdir(parents=True)
    w.dir.write_text(GOOD_ROW, encoding="utf-8")


#: A complete, valid row except for one byte that is not UTF-8, inside `created_at`. A reader
#: that decoded with replacement would serve it.
_UNDECODABLE = (b'{\n  "created_at": "2026-09-26T00:00:00+00:00\xff",\n'
                + f'  "tenant_id": "{TID}"\n}}\n'.encode())

#: A good row followed by whitespace past `READ_LIMIT`.
_OVERSIZED = GOOD_ROW + " " * _io.READ_LIMIT

READ_SHAPES: dict[str, ReadShape] = {
    # Served.
    "good-row": ReadShape(_put_row, None),
    "linked-T": ReadShape(_plant_linked_dir, None),
    # Refused at the open: the entry at the row's name is not a plain, single-named file.
    "directory-at-row": ReadShape(lambda w: w.row.mkdir(parents=True),
                                  lambda w: _restore(w, remove=w.row), _io.ALIAS_READ_REFUSAL),
    "live-link-at-row": ReadShape(_plant_live_link, lambda w: _restore(w, remove=w.row),
                                  _io.ALIAS_READ_REFUSAL),
    "dangling-link-at-row": ReadShape(_plant_dangling_link, lambda w: _restore(w, remove=w.row),
                                      _io.ALIAS_READ_REFUSAL),
    "fifo-at-row": ReadShape(_plant_fifo, lambda w: _restore(w, remove=w.row),
                             _io.ALIAS_READ_REFUSAL),
    "hard-linked-row": ReadShape(_plant_hard_link,
                                 lambda w: (w.outside / SECOND_NAME).unlink(),
                                 _io.ALIAS_READ_REFUSAL),
    # Refused by the read. The reason's wording is the declared change, so none is pinned.
    "absent-row": ReadShape(lambda w: w.dir.mkdir(parents=True), _restore),
    "absent-T": ReadShape(lambda w: w.root.mkdir(parents=True), _restore),
    "file-at-T": ReadShape(_plant_file_at_dir, lambda w: _restore(w, remove=w.dir)),
    "undecodable-row": ReadShape(lambda w: _put_row(w, _UNDECODABLE), _restore),
    # A good row padded past the read limit with whitespace: valid JSON as a whole, and a
    # prefix read would serve it. The whole-file read's size bound refuses it, as today.
    "oversized-row": ReadShape(lambda w: _put_row(w, _OVERSIZED), _restore,
                               "larger than the read limit"),
    # Refused by the parse, which D1 leaves alone.
    "empty-row": ReadShape(lambda w: _put_row(w, ""), _restore, "is not valid JSON"),
    "malformed-json": ReadShape(lambda w: _put_row(w, "{not json"), _restore,
                                "is not valid JSON"),
    "non-object": ReadShape(lambda w: _put_row(w, f'["{TID}"]'), _restore,
                            "is not a JSON object"),
    "missing-field": ReadShape(lambda w: _put_row(w, json.dumps({"tenant_id": TID})), _restore,
                               "created_at"),
    "other-tenant": ReadShape(lambda w: _put_row(w, _row_text(tenant_id=OTHER)), _restore,
                              f"names {OTHER!r}, not {TID!r}"),
}


def _read_params(names: list[str]) -> list[Any]:
    return [pytest.param(n, marks=_NEEDS_FIFO) if n == "fifo-at-row" else n for n in names]


def _expected_at(shape: str) -> str:
    return LINKED_AT if shape == "linked-T" else GOOD_AT


def _assert_row_refusal(message: str, w: Where, shape: str) -> None:
    _assert_names(message, w.row)
    words = READ_SHAPES[shape].words
    if words is not None:
        assert words in message, f"the {shape} refusal lacks {words!r}: {message!r}"


@pytest.mark.parametrize("shape", _read_params(sorted(READ_SHAPES)))
def test_require_tenant_reads_the_row_as_it_did(tmp_path, shape):
    w = _where(tmp_path)
    case = READ_SHAPES[shape]
    case.plant(w)
    if case.repair is None:
        row = _served(owner.require_tenant, fixture_data_root(w.root), TID)
        assert (row.tenant_id, row.created_at) == (TID, _expected_at(shape))
        return
    before = _tree_state(tmp_path)
    _assert_row_refusal(_refused(owner.require_tenant, fixture_data_root(w.root), TID), w, shape)
    assert _tree_state(tmp_path) == before, f"refusing the {shape} row changed the tree"
    case.repair(w)
    row = _served(owner.require_tenant, fixture_data_root(w.root), TID)
    assert (row.tenant_id, row.created_at) == (TID, GOOD_AT), "the positive control"


def _place_knowledge_if_reachable(w: Where) -> None:
    """The operator's knowledge folder, placed at `<T>/knowledge` when `<T>` is a folder
    (through the link, for a linked `<T>`). A missing or file `<T>` can hold none."""
    if w.dir.is_dir() and not (w.dir / "knowledge").exists():
        H.place_knowledge(w.root, TID)


def _unlink_dir_and_move_target_in(w: Where) -> None:
    """The linked `<T>`'s control: the link replaced by the real folder it led to."""
    w.dir.unlink()
    os.rename(w.outside / "real-T", w.dir)


def _assert_knowledge_refusal(message: str, w: Where) -> None:
    """Refused at the knowledge step, not at the row: N2 lets the row read follow a linked
    `<T>`, and acceptance refuses the link later, naming the knowledge folder."""
    assert not message.startswith(str(w.row)), f"refused at the row, not later: {message!r}"
    assert str(w.dir / "knowledge") in message, f"the refusal names no knowledge folder: {message!r}"


def _refuse_then_repair(accept: Callable[..., Any], w: Where, shape: str, top: Path) -> None:
    """One acceptance entry over a planted shape: it refuses, at the knowledge step for a
    linked `<T>` and at the row for every other shape, and leaves `top` as it found it. The same
    address is then made plain (the link replaced by the folder it led to, or the shape's own
    repair), with the knowledge folder in place, ready for the caller's positive control."""
    before = _tree_state(top)
    message = _refused(accept, fixture_data_root(w.root), TID)
    if shape == "linked-T":
        _assert_knowledge_refusal(message, w)
        repair: Callable[[Where], None] | None = _unlink_dir_and_move_target_in
    else:
        _assert_row_refusal(message, w, shape)
        repair = READ_SHAPES[shape].repair
    assert _tree_state(top) == before, f"refusing the {shape} tenant changed the tree"
    assert repair is not None, f"{shape} has no positive control"
    repair(w)
    _place_knowledge_if_reachable(w)


@pytest.mark.parametrize("shape", _read_params(sorted(READ_SHAPES)))
def test_accept_tenant_reads_the_row_as_it_did(tmp_path, shape):
    w = _where(tmp_path)
    READ_SHAPES[shape].plant(w)
    _place_knowledge_if_reachable(w)
    accept = functools.partial(owner.accept_tenant, defender_dir=H.DEFENDER)
    if shape == "good-row":
        tenant = _served(accept, fixture_data_root(w.root), TID)
        assert (tenant.id, tenant.row.tenant_id, tenant.row.created_at) == (TID, TID, GOOD_AT)
        return
    _refuse_then_repair(accept, w, shape, tmp_path)
    tenant = _served(accept, fixture_data_root(w.root), TID)
    assert (tenant.id, tenant.row.created_at) == (TID, _expected_at(shape)), "the positive control"


#: The shapes that never reach `accept_placed_knowledge`'s row read: with no folder at `<T>`,
#: `lexists(<row>)` is false and the knowledge step refuses. That is not the row's verdict.
_NO_ROW_READ = frozenset({"absent-T", "file-at-T"})


@pytest.mark.parametrize("shape", _read_params(sorted(set(READ_SHAPES) - _NO_ROW_READ)))
def test_accept_placed_knowledge_reads_a_present_row_as_it_did(tmp_path, shape):
    w = _where(tmp_path)
    READ_SHAPES[shape].plant(w)
    _place_knowledge_if_reachable(w)
    place = functools.partial(owner.accept_placed_knowledge, defender_dir=H.DEFENDER)
    settings = w.dir / "knowledge" / "settings"
    if shape in ("good-row", "absent-row"):
        assert _served(place, fixture_data_root(w.root), TID) == (settings, shape == "good-row")
        return
    _refuse_then_repair(place, w, shape, tmp_path)
    assert _served(place, fixture_data_root(w.root), TID) == (settings, True), "the positive control"


def _file_mode(mask: int) -> int:
    return 0o644 & ~mask


def _folder_mode(mask: int) -> int:
    return 0o777 & ~mask


def _assert_created(w: Where, row: Any, mask: int) -> None:
    """`row` is what create_tenant returned. On disk is the one plain file holding exactly that
    row, at the umask's file mode, and require_tenant serves it back."""
    assert type(row) is owner.TenantRow, row
    assert row.tenant_id == TID, row
    assert datetime.fromisoformat(row.created_at).utcoffset() == timedelta(0), row.created_at
    assert_single_plain(w.row, _file_mode(mask), body=_row_text(created_at=row.created_at),
                        why=f"umask {oct(mask)}")
    assert json.loads(w.row.read_text(encoding="utf-8")) == {
        "tenant_id": TID, "created_at": row.created_at}
    assert _served(owner.require_tenant, fixture_data_root(w.root), TID) == row


CREATE_FRESH: dict[str, Callable[[Where], Any]] = {
    "root-absent": lambda w: None,
    "root-empty": lambda w: w.root.mkdir(),
    "T-holding-only-knowledge": lambda w: H.place_knowledge(w.root, TID),
}


@pytest.mark.parametrize("mask", [0o022, 0o027, 0o077], ids=lambda m: f"umask-{m:03o}")
@pytest.mark.parametrize("shape", sorted(CREATE_FRESH))
def test_create_tenant_mints_the_row_into_a_fresh_root(tmp_path, shape, mask):
    w = _where(tmp_path)
    CREATE_FRESH[shape](w)
    made_root, made_dir = not w.root.exists(), not w.dir.exists()
    knowledge_before = _tree_state(w.dir / "knowledge") if not made_dir else None
    dir_mode_before = None if made_dir else stat.S_IMODE(os.lstat(w.dir).st_mode)
    with umask(mask):
        row = _served(owner.create_tenant, fixture_data_root(w.root), TID)
    _assert_created(w, row, mask)
    assert sorted(os.listdir(w.root)) == [TID]
    assert sorted(os.listdir(w.dir)) == sorted(
        ["tenant.json"] + ([] if made_dir else ["knowledge"]))
    assert stat.S_ISDIR(os.lstat(w.dir).st_mode), "<T> is not a real folder"
    if made_root:
        assert stat.S_IMODE(os.lstat(w.root).st_mode) == _folder_mode(mask), "the root's mode"
    if made_dir:
        assert stat.S_IMODE(os.lstat(w.dir).st_mode) == _folder_mode(mask), "<T>'s mode"
    else:
        assert stat.S_IMODE(os.lstat(w.dir).st_mode) == dir_mode_before, "<T>'s mode changed"
        assert _tree_state(w.dir / "knowledge") == knowledge_before, "knowledge/ was touched"


@dataclasses.dataclass(frozen=True)
class CreateShape:
    """One address create_tenant refuses. `subject` names the path the refusal opens with
    ("row", "dir", or "root", which the foreign-root refusal only names somewhere in the
    message). `words` is the stable phrase the design keeps, or None where only the verdict is
    pinned. `repair` removes the plant, after which the same create succeeds. It is None only
    for the occupied row, whose plant WAS the positive control."""

    plant: Callable[[Where], Any]
    repair: Callable[[Where], None] | None
    subject: str
    words: str | None


def _plant_dir_link(w: Where, *, live: bool) -> None:
    target = w.outside / ("real-T" if live else "no-such-T")
    if live:
        target.mkdir()
    w.root.mkdir(parents=True)
    w.dir.symlink_to(target)


def _plant_occupied_row(w: Where) -> Any:
    """The first create on this root, which succeeds: the positive control for the second."""
    with umask(0o022):
        first = _served(owner.create_tenant, fixture_data_root(w.root), TID)
    _assert_created(w, first, 0o022)
    return first


def _plant_hard_linked_row(w: Where) -> None:
    _put_row(w)
    os.link(w.row, w.outside / SECOND_NAME)


#: The occupied row's own words: unchanged by design.
_ALREADY_EXISTS = "already exists — a tenant is created once"
#: The fresh-root refusal's words (`refuse_foreign_data_root`, which does not move).
_NOT_FRESH = "a tenant is created only into a fresh data root"

CREATE_REFUSED: dict[str, CreateShape] = {
    "row-exists": CreateShape(_plant_occupied_row, None, "row", _ALREADY_EXISTS),
    # Something other than a plain file stands at the row's name. The core's not-plain sentence.
    "live-link-at-row": CreateShape(_plant_live_link, lambda w: w.row.unlink(), "row",
                                    _io._NOT_PLAIN),
    "dangling-link-at-row": CreateShape(_plant_dangling_link, lambda w: w.row.unlink(), "row",
                                        _io._NOT_PLAIN),
    "directory-at-row": CreateShape(lambda w: w.row.mkdir(parents=True),
                                    lambda w: w.row.rmdir(), "row", _io._NOT_PLAIN),
    "fifo-at-row": CreateShape(_plant_fifo, lambda w: w.row.unlink(), "row", _io._NOT_PLAIN),
    "hard-link-at-row": CreateShape(_plant_hard_linked_row, lambda w: w.row.unlink(), "row",
                                    _io._NOT_PLAIN),
    # `<T>` is not a real folder. The core's folder refusals, naming `<T>`.
    "linked-T": CreateShape(functools.partial(_plant_dir_link, live=True),
                            lambda w: w.dir.unlink(), "dir", _io._LINKED_FOLDER),
    "dangling-linked-T": CreateShape(functools.partial(_plant_dir_link, live=False),
                                     lambda w: w.dir.unlink(), "dir", _io._LINKED_FOLDER),
    "file-at-T": CreateShape(_plant_file_at_dir, lambda w: w.dir.unlink(), "dir",
                             _io._NOT_A_FOLDER),
    # Not a fresh data root (O10), refused before anything is made.
    "foreign-tenant-folder": CreateShape(lambda w: (w.root / OTHER).mkdir(parents=True),
                                         lambda w: (w.root / OTHER).rmdir(), "root",
                                         _NOT_FRESH),
    "foreign-file-at-root": CreateShape(
        lambda w: (w.root.mkdir(), (w.root / "notes.txt").write_text("x\n", encoding="utf-8")),
        lambda w: (w.root / "notes.txt").unlink(), "root", _NOT_FRESH),
    "foreign-entry-in-rowless-T": CreateShape(lambda w: (w.dir / "runs").mkdir(parents=True),
                                              lambda w: (w.dir / "runs").rmdir(), "root",
                                              _NOT_FRESH),
    "root-is-a-file": CreateShape(
        lambda w: w.root.write_text("x\n", encoding="utf-8"), lambda w: w.root.unlink(), "dir",
        os.strerror(errno.ENOTDIR)),
    "root-is-a-dangling-link": CreateShape(
        lambda w: w.root.symlink_to(w.outside / "no-such-root"), lambda w: w.root.unlink(),
        "dir", os.strerror(errno.EEXIST)),
}


@pytest.mark.parametrize("shape", [pytest.param(n, marks=_NEEDS_FIFO) if n == "fifo-at-row"
                                   else n for n in sorted(CREATE_REFUSED)])
def test_create_tenant_refuses_as_it_did(tmp_path, shape):
    w = _where(tmp_path)
    case = CREATE_REFUSED[shape]
    first = case.plant(w)
    before = _tree_state(tmp_path)
    message = _refused(owner.create_tenant, fixture_data_root(w.root), TID)
    if case.subject == "root":
        assert str(w.root) in message, f"the refusal does not name the data root: {message!r}"
    else:
        _assert_names(message, w.row if case.subject == "row" else w.dir,
                      folder=case.subject == "dir")
    if case.words is not None:
        assert case.words in message, f"the {shape} refusal lacks {case.words!r}: {message!r}"
    assert ("already exists" in message) == (shape == "row-exists"), (
        f"only an occupied row is told it already exists; {shape}: {message!r}")
    assert _tree_state(tmp_path) == before, f"refusing {shape} changed the tree"
    if case.repair is None:
        assert _served(owner.require_tenant, fixture_data_root(w.root), TID) == first, "the first row was disturbed"
        return
    case.repair(w)
    with umask(0o022):
        row = _served(owner.create_tenant, fixture_data_root(w.root), TID)
    _assert_created(w, row, 0o022)


_UNPRIVILEGED = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="root ignores permission bits")


@_UNPRIVILEGED
def test_an_unreadable_row_is_refused_naming_it(tmp_path):
    """A row the process may not open is refused with TenantRefused naming the row, never a
    raw PermissionError; readable again, it is served."""
    w = _where(tmp_path)
    _put_row(w)
    w.row.chmod(0)
    try:
        _assert_names(_refused(owner.require_tenant, fixture_data_root(w.root), TID), w.row)
    finally:
        w.row.chmod(0o644)
    assert _served(owner.require_tenant, fixture_data_root(w.root), TID).tenant_id == TID


@_UNPRIVILEGED
def test_a_row_create_into_an_unwritable_folder_is_refused_naming_the_row(tmp_path):
    w = _where(tmp_path)
    (w.dir / "knowledge").mkdir(parents=True)
    w.dir.chmod(0o555)
    try:
        _assert_names(_refused(owner.create_tenant, fixture_data_root(w.root), TID), w.row)
        assert not os.path.lexists(w.row), "the refused create left an entry at the row"
    finally:
        w.dir.chmod(0o755)
    assert _served(owner.create_tenant, fixture_data_root(w.root), TID).tenant_id == TID


@_UNPRIVILEGED
def test_a_folder_create_into_an_unwritable_root_is_refused_naming_the_folder(tmp_path):
    """The data root exists but cannot be written: making `<T>` is refused with TenantRefused
    naming `<T>`, and no `<T>` is made; writable again, the same create succeeds."""
    w = _where(tmp_path)
    w.root.mkdir(parents=True)
    w.root.chmod(0o555)
    try:
        _assert_names(_refused(owner.create_tenant, fixture_data_root(w.root), TID), w.dir, folder=True)
        assert not os.path.lexists(w.dir), "the refused create made <T>"
    finally:
        w.root.chmod(0o755)
    assert _served(owner.create_tenant, fixture_data_root(w.root), TID).tenant_id == TID
