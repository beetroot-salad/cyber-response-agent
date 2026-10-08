"""#1137: the tenant row moves onto the rooted core. These tests pin what must not move with it.

The row is `<data root>/<T>/tenant.json`. #1137 changes HOW it is read (`_tenant._read_row`,
which `require_tenant`, `accept_tenant`, `accept_placed_knowledge` and `tenant_of_run_dir`
share) and created (`create_tenant`): from the path seams (`read_guarded`, `guarded_mkdir`,
`write_guarded`) to the rooted core (`_io.bind(<T>).read`, `_io.hold_new`,
`Held.write(mode="create")`). It is a refactor. The design (issue #1137, "Intent + design
(discussion 2026-10-08)") states two obligations, and this file holds their tests.

**O2: the verdicts do not move.** There is one characterization table per entry point. It was
written against 96e4cdb0 and passes there unchanged. Every row is a real filesystem plant, with
no fakes. What is pinned:

* served or refused, and for a refusal its exact class (`TenantRefused` itself) and its subject.
  Every read refusal opens with the row's path, an absent or file `<T>` included. A create
  refusal opens with the row's path, or with `<T>`'s for a folder the create cannot make, or
  names the data root when the root is not fresh;
* for the READ, nothing of an `OSError`'s text. The reason's wording is the design's one
  declared change: `[Errno 2] No such file or directory: '<row>'` becomes `absent`. Two kinds of
  words that the design keeps ARE pinned, so a refusal cannot pass for the wrong reason. A
  non-plain row (a directory, a link, a FIFO, a hard link) carries the core's alias sentence
  (`_io.ALIAS_READ_REFUSAL`): it was refused at the open, not opened, read and then refused by
  the parse. A malformed row carries the parse's own words, which D1 leaves alone. The planted
  bytes are chosen to catch a reader that follows or tolerates too much. The link leads to a
  GOOD row, the hard link IS a good row, and the undecodable row is valid JSON apart from one
  byte. So a reader that followed the link or decoded leniently would SERVE those rows;
* for the CREATE, the message is unchanged by design (C3). Its stable words are pinned through
  the core's own constants, never respelled. No refusal but the occupied row may claim that the
  row "already exists".

Every refusal is paired with a positive control ON THE SAME ADDRESS: the plant is removed, the
plain state is put in its place, and the same call then serves (or creates). A refusal also
leaves the tree exactly as it found it: the plant stays in place, a link's target stays
untouched, and nothing is made. A created row is a plain regular file with one name, holding
exactly the row, at the mode the process umask gives (0644 and 0777 masked, #1144). Each
create runs under a pinned umask, so the expected modes are computed from that umask.

**O1: the row's file access goes through the core.** A census over `defender/_tenant.py`, run
through `test_1133_census`'s scanner (its resolver and its `PATH_SEAMS`), finds no path-seam
reach except in the runs-folder stamp's two functions, `read_tenant` and
`ensure_runs_base_record`, which #1105 PR 2 retires. RED at 96e4cdb0 by design (`_read_row`,
`create_tenant`). An allow-list entry whose function no longer reaches a seam fails too, so the
list shrinks with the code.

Out of scope:
* the stamp (`<runs folder>/_tenant.json`), and `tenant_of_run_dir`, which reads the stamp
  before it reads the row and leaves with #1105 PR 2;
* a lost create race. `tenant_1078_pass_a/test_1078_owner.py::test_d1_create_exclusive` already
  races real `create_tenant` calls on fresh roots. The design holds the complete-or-absent lane
  safe by construction given O1 (`Held.write(mode="create")`, #1130's create-lane tests).
"""
from __future__ import annotations

import ast
import dataclasses
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
from defender import _tenant as owner
from defender.tests._create_lane import assert_single_plain
from defender.tests._umask import umask
from defender.tests.tenant_1078_pass_a import _spec1078 as H

TID = "acme"
OTHER = "beta"
#: The good row's timestamp.
GOOD_AT = "2026-09-26T00:00:00+00:00"
#: The row a linked `<T>` leads to has its own timestamp, so "served" is seen to be THAT row.
LINKED_AT = "2026-01-02T03:04:05+00:00"
#: The second name a hard-linked row has, outside the data root.
SECOND_NAME = "second-name.json"
#: How long one entry-point call may take before the test calls it hung.
_PATIENCE = 60

_NEEDS_FIFO = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="this platform has no FIFOs")


# ======================================================================================
# The address under test, spelled by hand (never read back from the owner's layout).
# ======================================================================================

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
                    detail = hashlib.sha256(
                        _io.read_bytes_capped(Path(entry.path))).hexdigest()
                elif stat.S_ISDIR(st.st_mode):
                    pending.append(Path(entry.path))
                state[os.path.relpath(entry.path, top)] = (
                    stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_nlink, detail)
    return state


# ======================================================================================
# Calling an entry point: served, or refused with the one refusal class.
# ======================================================================================

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


# ======================================================================================
# O2, the read: require_tenant, accept_tenant, accept_placed_knowledge.
# ======================================================================================

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
                b'  "tenant_id": "acme"\n}\n')

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
    """require_tenant serves a good row, and a row reached through a linked `<T>` (N2: the
    read follows `<T>`'s spelling, and that row is the one served). It refuses every other
    shape with TenantRefused, opening with the row's path and leaving the tree untouched; the
    same address, made plain, is then served."""
    w = _where(tmp_path)
    case = READ_SHAPES[shape]
    case.plant(w)
    if case.repair is None:
        row = _served(owner.require_tenant, w.root, TID)
        assert (row.tenant_id, row.created_at) == (TID, _expected_at(shape))
        return
    before = _tree_state(tmp_path)
    _assert_row_refusal(_refused(owner.require_tenant, w.root, TID), w, shape)
    assert _tree_state(tmp_path) == before, f"refusing the {shape} row changed the tree"
    case.repair(w)
    row = _served(owner.require_tenant, w.root, TID)
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
    message = _refused(accept, w.root, TID)
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
    """accept_tenant over a real knowledge folder. A good row is accepted. Every row shape that
    require_tenant refuses is refused here first, at step 2, naming the row and not the
    knowledge folder, with the tree untouched. A linked `<T>` passes the row and is refused at
    the knowledge step. Each refused address, made plain, is then accepted."""
    w = _where(tmp_path)
    READ_SHAPES[shape].plant(w)
    _place_knowledge_if_reachable(w)
    accept = functools.partial(owner.accept_tenant, defender_dir=H.DEFENDER)
    if shape == "good-row":
        tenant = _served(accept, w.root, TID)
        assert (tenant.id, tenant.row.tenant_id, tenant.row.created_at) == (TID, TID, GOOD_AT)
        return
    _refuse_then_repair(accept, w, shape, tmp_path)
    tenant = _served(accept, w.root, TID)
    assert (tenant.id, tenant.row.created_at) == (TID, _expected_at(shape)), "the positive control"


#: The shapes that never reach `accept_placed_knowledge`'s row read: with no folder at `<T>`,
#: `lexists(<row>)` is false and the knowledge step refuses. That is not the row's verdict.
_NO_ROW_READ = frozenset({"absent-T", "file-at-T"})


@pytest.mark.parametrize("shape", _read_params(sorted(set(READ_SHAPES) - _NO_ROW_READ)))
def test_accept_placed_knowledge_reads_a_present_row_as_it_did(tmp_path, shape):
    """Setup's half of acceptance, over a real knowledge folder. With no row it serves and says
    the row is absent; with a good row it serves and says it is present. A row that IS there is
    read as require_tenant reads it, so every refused shape is refused naming the row, with the
    tree untouched, and then served once made plain. A linked `<T>` is refused at the knowledge
    step."""
    w = _where(tmp_path)
    READ_SHAPES[shape].plant(w)
    _place_knowledge_if_reachable(w)
    place = functools.partial(owner.accept_placed_knowledge, defender_dir=H.DEFENDER)
    settings = w.dir / "knowledge" / "settings"
    if shape in ("good-row", "absent-row"):
        assert _served(place, w.root, TID) == (settings, shape == "good-row")
        return
    _refuse_then_repair(place, w, shape, tmp_path)
    assert _served(place, w.root, TID) == (settings, True), "the positive control"


# ======================================================================================
# O2, the create: create_tenant.
# ======================================================================================

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
    assert _served(owner.require_tenant, w.root, TID) == row


CREATE_FRESH: dict[str, Callable[[Where], Any]] = {
    "root-absent": lambda w: None,
    "root-empty": lambda w: w.root.mkdir(),
    "T-holding-only-knowledge": lambda w: H.place_knowledge(w.root, TID),
}


@pytest.mark.parametrize("mask", [0o022, 0o027, 0o077], ids=lambda m: f"umask-{m:03o}")
@pytest.mark.parametrize("shape", sorted(CREATE_FRESH))
def test_create_tenant_mints_the_row_into_a_fresh_root(tmp_path, shape, mask):
    """A missing root, an empty root, and a `<T>` holding only the operator's `knowledge/` each
    get the row. It is plain, has one name and holds exactly the row; the file and any folder
    the create made have the modes the umask gives; and nothing else lands beside it. A
    knowledge folder already there is left exactly as it was."""
    w = _where(tmp_path)
    CREATE_FRESH[shape](w)
    made_root, made_dir = not w.root.exists(), not w.dir.exists()
    knowledge_before = _tree_state(w.dir / "knowledge") if not made_dir else None
    dir_mode_before = None if made_dir else stat.S_IMODE(os.lstat(w.dir).st_mode)
    with umask(mask):
        row = _served(owner.create_tenant, w.root, TID)
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
        first = _served(owner.create_tenant, w.root, TID)
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
    # The data root itself is not a folder. Outside the design's table: base words come from
    # `guarded_mkdir`'s `makedirs` and are not pinned. Pinned: the verdict, and that the
    # refusal names `<T>`.
    "root-is-a-file": CreateShape(
        lambda w: w.root.write_text("x\n", encoding="utf-8"), lambda w: w.root.unlink(), "dir",
        None),
    "root-is-a-dangling-link": CreateShape(
        lambda w: w.root.symlink_to(w.outside / "no-such-root"), lambda w: w.root.unlink(),
        "dir", None),
}


@pytest.mark.parametrize("shape", [pytest.param(n, marks=_NEEDS_FIFO) if n == "fifo-at-row"
                                   else n for n in sorted(CREATE_REFUSED)])
def test_create_tenant_refuses_as_it_did(tmp_path, shape):
    """create_tenant refuses every address that is not a fresh root or a plain path to the row,
    with TenantRefused naming the same path in the same words. Only an occupied row is told it
    "already exists". The refusal leaves the tree exactly as it was: the plant stays in place,
    a link's target is untouched, and no `<T>` or row is made. Once the plant is removed, the
    same create succeeds."""
    w = _where(tmp_path)
    case = CREATE_REFUSED[shape]
    first = case.plant(w)
    before = _tree_state(tmp_path)
    message = _refused(owner.create_tenant, w.root, TID)
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
        assert _served(owner.require_tenant, w.root, TID) == first, "the first row was disturbed"
        return
    case.repair(w)
    with umask(0o022):
        row = _served(owner.create_tenant, w.root, TID)
    _assert_created(w, row, 0o022)


# ======================================================================================
# O1: no path seam reached from the tenant module, except by the stamp until #1105 PR 2.
# ======================================================================================

#: The functions of `defender/_tenant.py` that may still reach a path seam, and why. Both are
#: the runs-folder stamp's, which #1105 PR 2 retires; the list is empty once it lands.
STAMP_SEAM_CALLERS: dict[str, str] = {
    "read_tenant": "retired by #1105 PR 2",
    "ensure_runs_base_record": "retired by #1105 PR 2",
}

_TENANT_MODULE = "_tenant.py"


def _census1133() -> Any:
    """#1133's census module, for its scanner and its `PATH_SEAMS`. It is imported here and
    bound to no module-level name, so its tests are not collected a second time under this
    file."""
    from defender.tests import test_1133_census

    return test_1133_census


def _seam_reaches(source: str) -> set[tuple[str, str]]:
    """`(enclosing function, seam)` for every call to, or other reference to, a path seam in
    `source`, scanned as `defender/_tenant.py`. The resolver is #1133's, which follows import
    aliases, module-level aliases and the attribute form on any receiver (`_real_io.<seam>`, an
    `io=` parameter's `io.<seam>`)."""
    census = _census1133()
    tree = ast.parse(source, filename=_TENANT_MODULE)
    return {(where, callee) for _module, where, callee in census.census_of(_TENANT_MODULE, tree)
            if callee in census.PATH_SEAMS}


@functools.cache
def _tenant_seam_reaches() -> frozenset[tuple[str, str]]:
    path = _census1133().PACKAGE / _TENANT_MODULE
    return frozenset(_seam_reaches(_io.read_text_utf8(path)))


def test_o1_census_sees_every_spelling_of_a_seam_reach():
    """The census's positive control, on synthetic source shaped like `_tenant.py`. A seam
    reached through the module alias, through an `io=` parameter, through an import alias,
    bare, as a default value, or through a module-level alias is collected under its enclosing
    function (`<module>` for the alias itself). The core's own verbs are not collected, and
    neither is a docstring that names a seam."""
    source = '''
from defender import _io as _real_io
from defender._io import guarded_mkdir as _mk, read_guarded

_reader = _real_io.write_guarded


def via_module(p):
    return _real_io.read_guarded(p)


def via_parameter(p, *, io=_real_io):
    io.write_guarded(p, "x", mode="create")


def via_import_alias(p):
    _mk(p, base=p)


def bare(p):
    return read_guarded(p)


def as_a_default(p, read=_real_io.read_bytes_guarded):
    return read(p)


def via_module_alias(p):
    _reader(p, "x")


def on_the_core(root, name):
    """Was read_guarded and write_guarded; now the rooted core."""
    with _real_io.bind(root) as bound:
        bound.read(name)
    with _real_io.hold_new(root, name) as held:
        held.write(name, "x", mode="create")
'''
    assert _seam_reaches(source) == {
        ("<module>", "write_guarded"),
        ("via_module", "read_guarded"),
        ("via_parameter", "write_guarded"),
        ("via_import_alias", "guarded_mkdir"),
        ("bare", "read_guarded"),
        ("as_a_default", "read_bytes_guarded"),
        ("via_module_alias", "write_guarded"),
    }


def test_o1_the_tenant_module_reaches_no_path_seam_outside_the_stamp():
    """O1: the row and its folder are read and made through the rooted core
    (`_io.bind(<T>).read`, `_io.hold_new`, `Held.write(mode="create")`). So no function in
    `defender/_tenant.py`, and nothing at module level, reaches a name in #1133's `PATH_SEAMS`,
    except the stamp's functions on `STAMP_SEAM_CALLERS`. RED at 96e4cdb0: `_read_row` reads
    the row through `read_guarded`, and `create_tenant` makes `<T>` through `guarded_mkdir` and
    the row through `write_guarded`."""
    stray = sorted(r for r in _tenant_seam_reaches() if r[0] not in STAMP_SEAM_CALLERS)
    assert stray == [], (
        "defender/_tenant.py reaches a path seam outside the stamp's allow-list. The tenant row "
        "and its folder go through the rooted core (_io.bind(...).read, _io.hold_new, "
        "Held.write(mode='create')), #1137 O1:\n  "
        + "\n  ".join(f"{where}: {seam}" for where, seam in stray))


@pytest.mark.parametrize("function", sorted(STAMP_SEAM_CALLERS))
def test_o1_each_allow_listed_stamp_function_still_reaches_a_seam(function):
    """The allow-list shrinks with the code. An entry whose function no longer reaches a path
    seam (or no longer exists) is stale, and it fails here until it is deleted."""
    reached = sorted(seam for where, seam in _tenant_seam_reaches() if where == function)
    assert reached, (
        f"{function} is on STAMP_SEAM_CALLERS ({STAMP_SEAM_CALLERS[function]}) but no longer "
        "reaches a path seam in defender/_tenant.py. Delete its entry from STAMP_SEAM_CALLERS "
        "in this file: the list is meant to empty out as #1105 PR 2 retires the stamp.")


#: Everything #1133's scanner collects from `defender/_tenant.py`, not only `PATH_SEAMS`: the
#: core's own verbs it keys (`hold_new`), raw `os` opens, `getattr(<module>)` and `_io`'s
#: private internals. Exact, so a reach respelled past `PATH_SEAMS` (an `_io._*` helper inlining
#: a seam, `os.makedirs`, `getattr(_real_io, ...)`) is a new row here. The stamp's rows leave with
#: #1105 PR 2, and this set shrinks with them.
EXPECTED_FULL_CENSUS = frozenset({
    ("create_tenant", "hold_new"),
    ("ensure_runs_base_record", "read_guarded"),
    ("ensure_runs_base_record", "write_guarded"),
    ("read_tenant", "read_guarded"),
    ("read_tenant_id_file", "os.open"),
})

#: The row's two functions, and the one `_io` name each may touch: the core's door to `<T>`.
ROW_DOORS = {"_read_row": "bind", "create_tenant": "hold_new"}


def test_o1_the_tenant_module_reaches_exactly_the_expected_io():
    """O1, closed against respelling (adversary E2): the whole census of `defender/_tenant.py`,
    in the scanner's full vocabulary, is exactly `EXPECTED_FULL_CENSUS`."""
    census = _census1133()
    path = census.PACKAGE / _TENANT_MODULE
    tree = ast.parse(_io.read_text_utf8(path), filename=_TENANT_MODULE)
    found = frozenset((where, callee)
                      for _module, where, callee in census.census_of(_TENANT_MODULE, tree))
    assert found == EXPECTED_FULL_CENSUS, (
        f"unexpected: {sorted(found - EXPECTED_FULL_CENSUS)}; "
        f"missing: {sorted(EXPECTED_FULL_CENSUS - found)}")


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


@pytest.mark.parametrize("function", sorted(ROW_DOORS))
def test_o1_each_row_function_enters_through_its_core_door_only(function):
    """O1, closed against `getattr` (adversary E1), which the scanner keys for a module receiver
    but not for a parameter: each row function takes no `io` parameter (N4), calls no `getattr`,
    and touches exactly one name on the `_io` module — its door (`bind` for the read,
    `hold_new` for the create). The positive half: the door is touched, so the function is on
    the core and not merely off the seams."""
    path = _census1133().PACKAGE / _TENANT_MODULE
    fn = _function(ast.parse(_io.read_text_utf8(path), filename=_TENANT_MODULE), function)
    params = {a.arg for a in (*fn.args.args, *fn.args.kwonlyargs, *fn.args.posonlyargs)}
    assert "io" not in params, f"{function} still takes an io= seam"
    getattrs = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name) and n.func.id in ("getattr", "vars")]
    assert getattrs == [], f"{function} reaches a name dynamically"
    io_names = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name) and n.value.id in ("_real_io", "_io")}
    assert io_names == {ROW_DOORS[function]}, (
        f"{function} touches {sorted(io_names)} on the _io module; only its core door "
        f"{ROW_DOORS[function]!r} belongs there")
