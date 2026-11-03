"""A tenant folder is judged by its knowledge folder alone; no `tenant.json` is read (#1214 O6, Flow 4).

The pre-#1214 row readers and writers (`require_tenant`, `create_tenant`, the row shapes and the row-create
matrix) are retired with the on-disk row; what still guards a tenant folder lives here.
"""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import fixture_data_root

import dataclasses
import hashlib
import json
import os
import stat
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.tenancy import _tenant as owner
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H

TID = fixture_uuid("tenant:acme")
OTHER = fixture_uuid("tenant:beta")
#: How long one entry-point call may take before the test calls it hung.
_PATIENCE = 60
#: The second name a hard-linked file has, outside the data root.
SECOND_NAME = "second-name.json"

_NEEDS_FIFO = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="this platform has no FIFOs")


@dataclasses.dataclass(frozen=True)
class Where:
    """One test's data root, and a sibling folder outside it that holds link targets and a hard link's
    second name."""

    root: Path
    outside: Path

    @property
    def dir(self) -> Path:
        return self.root / TID

    @property
    def row(self) -> Path:
        """Where the retired row used to live. Nothing reads it now."""
        return self.dir / "tenant.json"


def _where(tmp_path: Path) -> Where:
    w = Where(tmp_path / "data", tmp_path / "outside")
    w.outside.mkdir()
    return w


def _tree_state(top: Path) -> dict[str, tuple[int, int, int, str | None]]:
    """Every entry below `top`, judged without following it: its type, permission bits and link count,
    plus a link's target or a regular file's digest. Nothing but a regular file is ever opened, because a
    FIFO opened to hash it would block."""
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
                    with open(entry.path, "rb") as plain:
                        detail = hashlib.file_digest(plain, "sha256").hexdigest()
                elif stat.S_ISDIR(st.st_mode):
                    pending.append(Path(entry.path))
                state[os.path.relpath(entry.path, top)] = (
                    stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_nlink, detail)
    return state


def _outcome(fn: Callable[..., Any], *args: Any) -> tuple[Any, Exception | None]:
    """`fn(*args)`'s value, or the exception it raised. The call runs in a daemon thread with `_PATIENCE`
    seconds to finish, so a reader that opened a planted FIFO blocking fails the test instead of hanging
    the suite."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = fn(*args)
        except Exception as raised:  # noqa: BLE001 — classified by the caller
            box["raised"] = raised

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(_PATIENCE)
    if worker.is_alive():
        pytest.fail(f"{fn.__name__} did not return within {_PATIENCE}s; did it open a planted FIFO "
                    "without O_NONBLOCK?")
    return box.get("value"), box.get("raised")


def _accept(w: Where) -> Any:
    return owner.accept_tenant(fixture_data_root(w.root), TID, defender_dir=H.DEFENDER)


def _served(w: Where) -> Any:
    value, raised = _outcome(_accept, w)
    assert raised is None, f"acceptance refused where it should serve: {raised!r}"
    return value


def _refused(w: Where) -> str:
    """The refusal's message, after checking that acceptance refused with `TenantRefused` itself: no
    subclass, and no bare `OSError` or `ValueError` escaping."""
    value, raised = _outcome(_accept, w)
    assert raised is not None, f"acceptance served {value!r} where it should refuse"
    assert type(raised) is owner.TenantRefused, (
        f"acceptance refused with {type(raised).__name__}, not TenantRefused: {raised}")
    return str(raised)


def _knowledge(w: Where) -> None:
    """The knowledge folder at `<T>/knowledge` (through a linked `<T>` too)."""
    H.place_knowledge(w.root, TID)


# --- shapes a stale `tenant.json` may take: acceptance never looks at it (O6) -------------------------

_GOOD_ROW = json.dumps({"tenant_id": TID, "created_at": "2026-09-26T00:00:00+00:00"}, indent=2) + "\n"


def _row_bytes(body: str | bytes) -> Callable[[Where], None]:
    def plant(w: Where) -> None:
        w.row.write_bytes(body if isinstance(body, bytes) else body.encode())
    return plant


def _plant_live_link(w: Where) -> None:
    target = w.outside / "target.json"
    target.write_text(_GOOD_ROW, encoding="utf-8")
    w.row.symlink_to(target)


def _plant_hard_link(w: Where) -> None:
    w.row.write_text(_GOOD_ROW, encoding="utf-8")
    os.link(w.row, w.outside / SECOND_NAME)


#: Every shape the retired row could be in, each a refusal or an escape before r9. A tenant with a
#: knowledge folder is accepted whatever stands at the row's name, and nothing there is touched.
STALE_ROW_SHAPES: dict[str, Callable[[Where], None]] = {
    "no-row": lambda w: None,
    "good-row": _row_bytes(_GOOD_ROW),
    "empty-row": _row_bytes(""),
    "malformed-json": _row_bytes("{not json"),
    "non-object": _row_bytes(f'["{TID}"]'),
    "missing-field": _row_bytes(json.dumps({"tenant_id": TID})),
    "other-tenant": _row_bytes(json.dumps({"tenant_id": OTHER, "created_at": "2026-09-26T00:00:00+00:00"})),
    "undecodable-row": _row_bytes(b'{"tenant_id": "\xff"}'),
    "oversized-row": _row_bytes(_GOOD_ROW + " " * _io.READ_LIMIT),
    "directory-at-row": lambda w: w.row.mkdir(),
    "live-link-at-row": _plant_live_link,
    "dangling-link-at-row": lambda w: w.row.symlink_to(w.outside / "nowhere.json"),
    "fifo-at-row": lambda w: os.mkfifo(w.row),
    "hard-linked-row": _plant_hard_link,
}


@pytest.mark.parametrize("shape", [pytest.param(n, marks=_NEEDS_FIFO) if n == "fifo-at-row" else n
                                   for n in sorted(STALE_ROW_SHAPES)])
def test_a_tenant_with_a_knowledge_folder_is_accepted_whatever_stands_at_the_old_row(tmp_path, shape):
    """Acceptance neither reads nor writes `tenant.json`, in any shape, and changes nothing (O6, Flow 4)."""
    w = _where(tmp_path)
    _knowledge(w)
    STALE_ROW_SHAPES[shape](w)
    before = _tree_state(tmp_path)
    assert _served(w).id == TID
    assert _tree_state(tmp_path) == before, f"accepting with a {shape} row changed the tree"


def test_accepting_a_tenant_never_makes_a_row(tmp_path):
    """A tenant accepted with no row is still without one afterwards (O6)."""
    w = _where(tmp_path)
    _knowledge(w)
    assert _served(w).id == TID
    assert not os.path.lexists(w.row), "acceptance wrote the retired row"
    assert sorted(os.listdir(w.dir)) == ["knowledge"]


# --- the folder rules that survive: a foreign or malformed tenant folder is refused (Flow 4) ----------

@dataclasses.dataclass(frozen=True)
class FolderShape:
    """One malformed `<T>`. `repair` turns the same address into a plain tenant folder with its
    knowledge folder in place (the positive control)."""

    plant: Callable[[Where], None]
    repair: Callable[[Where], None]


def _plant_linked_dir(w: Where, *, live: bool) -> None:
    """`<T>` is a link: to a real folder outside the root, or to nothing. A good knowledge folder stands
    behind a live one, so only the link itself can be the refusal."""
    target = w.outside / "real-T"
    w.root.mkdir(parents=True)
    w.dir.symlink_to(target)
    if live:
        target.mkdir()
        _knowledge(w)


def _linked(live: bool) -> Callable[[Where], None]:
    return lambda w: _plant_linked_dir(w, live=live)


def _repair_linked_dir(w: Where) -> None:
    real = w.outside / "real-T"
    w.dir.unlink()
    if real.exists():
        os.rename(real, w.dir)
    else:
        _knowledge(w)


def _repair_with_knowledge(w: Where) -> None:
    if w.dir.is_file():
        w.dir.unlink()
    _knowledge(w)


def _file_at_dir(w: Where) -> None:
    w.root.mkdir(parents=True)
    w.dir.write_text("x\n", encoding="utf-8")


def _only_a_row(w: Where) -> None:
    w.dir.mkdir(parents=True)
    w.row.write_text(_GOOD_ROW, encoding="utf-8")


FOLDER_SHAPES: dict[str, FolderShape] = {
    "linked-T": FolderShape(_linked(True), _repair_linked_dir),
    "dangling-linked-T": FolderShape(_linked(False), _repair_linked_dir),
    "file-at-T": FolderShape(_file_at_dir, _repair_with_knowledge),
    "absent-T": FolderShape(lambda w: w.root.mkdir(parents=True), _repair_with_knowledge),
    "T-without-knowledge": FolderShape(lambda w: w.dir.mkdir(parents=True), _repair_with_knowledge),
    "T-holding-only-a-row": FolderShape(_only_a_row, _repair_with_knowledge),
}


@pytest.mark.parametrize("shape", sorted(FOLDER_SHAPES))
def test_a_tenant_folder_that_is_not_a_real_one_with_knowledge_is_refused_naming_the_knowledge_folder(
        tmp_path, shape):
    """A link or file at `<T>`, or no knowledge folder, is refused naming `<T>/knowledge` and changes nothing;
    the repaired address is accepted (Flow 4 'folder checks as today')."""
    w = _where(tmp_path)
    case = FOLDER_SHAPES[shape]
    case.plant(w)
    before = _tree_state(tmp_path)
    message = _refused(w)
    assert str(w.dir / "knowledge") in message, f"the refusal names no knowledge folder: {message!r}"
    assert _tree_state(tmp_path) == before, f"refusing the {shape} tenant changed the tree"
    case.repair(w)
    assert _served(w).id == TID, "the positive control"


# --- #1214 O7: the one-tenant guard is gone (slice C's cells, kept) -----------------------------------

def _foreign_tenant_folder(root: Path) -> None:
    (root / OTHER).mkdir(parents=True)


def _foreign_file(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "notes.txt").write_text("x\n", encoding="utf-8")


def _foreign_entry_in_own_folder(root: Path) -> None:
    (root / TID / "runs").mkdir(parents=True)


@pytest.mark.parametrize("plant", [_foreign_tenant_folder, _foreign_file, _foreign_entry_in_own_folder],
                         ids=["another-tenant-folder", "another-file-at-root", "runs-in-own-folder"])
def test_1214_a_tenant_is_accepted_beside_what_the_one_tenant_guard_refused(tmp_path, plant):
    """The three `_NOT_FRESH` shapes are no refusal now (#1214 O7): the tenant is accepted with the same data root contents."""
    root = tmp_path / "data"
    H.place_knowledge(root, TID)
    assert H.accept(root, TID).id == TID  # control: alone it is accepted
    plant(root)
    before = _tree_state(tmp_path)
    assert H.accept(root, TID).id == TID
    assert _tree_state(tmp_path) == before, "acceptance changed the tree"
    assert not hasattr(owner, "refuse_foreign_data_root"), "the fresh-data-root rule still exists"
