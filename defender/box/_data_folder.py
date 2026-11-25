"""A folder of the product's own under the data root, outside every tenant's folder (#1170 H9, #1469 D1).

`<data root>/<parent>/<name>/`: the parent is traverse-only (0711, so the names in it cannot be listed) and belongs to
the data root's owner, whichever process made it; the folder is made exclusively, with its mode set explicitly (the
umask would narrow a create mode) and owned by the data root's owner too. Every process on the data root, the helper
running as root or the operator's run as the owner, can then make its own folder in the one parent and set the
parent's mode again; a process of any other uid fails closed (the data root has one owner by design). An existing
parent is judged no-follow first. The job sockets' folders and the box check's folders are both made here."""
from __future__ import annotations

import contextlib
import os
import shutil
import stat
from pathlib import Path

#: The parent's mode: traverse-only for everyone but its owner.
PARENT_MODE = 0o711


def _give_to_owner(path: Path, owner: os.stat_result) -> None:
    if os.geteuid() == 0 and (owner.st_uid, owner.st_gid) != (0, 0):
        os.chown(path, owner.st_uid, owner.st_gid)


def make_data_folder(data_root: Path, parent: str, name: str, *, mode: int) -> Path:
    """Make `<data_root>/<parent>/<name>/` with `mode` (module doc) and return it. Raises `OSError`: `FileExistsError`
    when the folder exists, `NotADirectoryError` when the parent is not a folder (a link included)."""
    owner = os.stat(data_root)
    above = data_root / parent
    with contextlib.suppress(FileExistsError):
        above.mkdir(mode=PARENT_MODE)  # lint-unguarded-tree-write: ok — under the data root, in no box's or job's bind
    if above.is_symlink() or not above.is_dir():
        raise NotADirectoryError(f"{above} is not a folder this product made")
    _give_to_owner(above, owner)
    os.chmod(above, PARENT_MODE)
    folder = above / name
    folder.mkdir(mode=0o700)  # lint-unguarded-tree-write: ok — exclusive, fresh, made before anything binds it
    try:
        os.chmod(folder, mode)
        _give_to_owner(folder, owner)
    except BaseException:
        os.rmdir(folder)
        raise
    return folder


def remove_data_folder(folder: Path) -> None:
    """`folder` removed whole, no link below it followed (a link is removed as the link). A folder a run made read-only
    (its `alert_input/`, mode 0555) is made writable first, so a process that is not root removes what it made; an entry
    already gone counts as removed. Raises `OSError` for what still cannot be removed."""
    if not os.path.lexists(folder):
        return
    if folder.is_symlink() or not folder.is_dir():
        folder.unlink()
        return

    def writable(path: str) -> None:
        with contextlib.suppress(OSError):
            mode = os.lstat(path).st_mode
            if stat.S_ISDIR(mode) and mode & 0o700 != 0o700:
                os.chmod(path, mode | 0o700)

    writable(str(folder))
    for top, dirs, _files in os.walk(folder):  # os.walk follows no link: a linked folder is listed, never entered
        for name in dirs:
            writable(os.path.join(top, name))
    with contextlib.suppress(FileNotFoundError):
        shutil.rmtree(folder)
