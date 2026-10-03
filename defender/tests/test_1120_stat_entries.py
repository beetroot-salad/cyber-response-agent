"""`_io.stat_entries` (#1120 piece 1, code review third pass): every entry of a bound directory,
judged without following it, in one walk to the directory."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from defender import _io


def test_each_entry_is_judged_as_itself(tmp_path: Path) -> None:
    """A file, a directory, a link and a FIFO (never opened, so it cannot block): each
    answers with its own kind. An absent directory answers absent; a linked one is refused."""
    d = tmp_path / "root" / "d"
    d.mkdir(parents=True)
    (d / "file").write_text("x", encoding="utf-8")
    (d / "sub").mkdir()
    (d / "link").symlink_to("file")
    os.mkfifo(d / "fifo")
    (tmp_path / "root" / "linked").symlink_to("d")
    with _io.bind(tmp_path / "root") as bound:
        got = _io.stat_entries(bound.under("d"))
        absent = _io.stat_entries(bound.under("nothing"))
        linked = _io.stat_entries(bound.under("linked"))
    assert got.stats is not None, got
    kinds = {name: stat.S_IFMT(st.st_mode) for name, st in got.stats.items()}
    assert kinds == {"file": stat.S_IFREG, "sub": stat.S_IFDIR, "link": stat.S_IFLNK,
                     "fifo": stat.S_IFIFO}, kinds
    assert absent.absent, absent
    assert absent.stats is None, absent
    assert linked.stats is None, linked
    assert linked.reason == _io.ALIAS_READ_REFUSAL, linked
