"""#1105 PR 1 — the two `_io` changes outside the package (amendment A, DV-1; OQ-5 (a), D3.4).

* `_io.hold(root, *, follow=False)`: the repository's one held runs-folder handle is opened
  no-follow. It opens with `_STEP_FLAGS` (`O_PATH|O_NOFOLLOW|O_CLOEXEC`) and judges the
  descriptor by `fstat`, as `_step` judges each folder below a root (R41-02, R41-03, R41-23):
  a link at the root, dangling or not, is `OSError(ELOOP, "refusing to create through a
  symlinked path component")`; a regular file or a FIFO is `NotADirectoryError`; an absent path
  is `FileNotFoundError`. Ancestors are host configuration and are followed (P1). The default
  `follow=True` keeps today's behaviour, which follows a link root (R41-01).
* `Bound.read(name, *, max_bytes=N)`: reads no more than N bytes of the file, so the episode
  record reader (which asks for the cap plus one byte) can tell an over-cap record from one
  within the cap without reading it whole. Without the keyword `Bound.read` keeps today's
  whole-file read (R41-16).

Both are new keywords on existing functions, so at base 80888efb each call raises
`TypeError: … unexpected keyword argument`; the tests turn that into `pytest.fail(...)`, an
assertion-class red. The byte count is observed through `_io`'s own `os_=` seam, with an `os`
proxy that delegates every call and only counts the bytes each read hands back — it injects
nothing.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender.tests.tenant_1105_run_repository import _spec1105 as H

_LINK_REFUSAL = "refusing to create through a symlinked path component"


def _require_keyword(fn: Any, *args: Any, keyword: str, **kwargs: Any) -> Any:
    """`fn(*args, **kwargs)`, where `kwargs` carries the new `keyword`; a `TypeError` naming
    that keyword (the keyword does not exist yet) fails the test instead of crashing it."""
    try:
        return fn(*args, **kwargs)
    except TypeError as exc:
        if keyword in str(exc):
            pytest.fail(f"{getattr(fn, '__qualname__', fn)} takes no {keyword}= keyword: {exc}")
        raise


class _CountingOS:
    """`os`, delegated call for call, counting the bytes every read hands back off a file —
    `os.read`, `os.pread`, and the reads of each file object `fdopen` returns. It changes no
    answer and injects no fault: `_io`'s own `os_=` seam, used as an observation channel."""

    def __init__(self) -> None:
        self.delivered = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(os, name)

    def read(self, fd: int, n: int) -> bytes:
        data = os.read(fd, n)
        self.delivered += len(data)
        return data

    def pread(self, fd: int, n: int, offset: int) -> bytes:
        data = os.pread(fd, n, offset)
        self.delivered += len(data)
        return data

    def fdopen(self, fd: int, *args: Any, **kwargs: Any) -> Any:
        return _CountingFile(os.fdopen(fd, *args, **kwargs), self)


class _CountingFile:
    """A file object whose reads are counted into `_CountingOS.delivered`."""

    def __init__(self, fh: Any, owner: _CountingOS) -> None:
        self._fh = fh
        self._owner = owner

    def _count(self, data: Any) -> Any:
        self._owner.delivered += len(data.encode("utf-8") if isinstance(data, str) else data)
        return data

    def read(self, *args: Any) -> Any:
        return self._count(self._fh.read(*args))

    def readline(self, *args: Any) -> Any:
        return self._count(self._fh.readline(*args))

    def readinto(self, buf: Any) -> int:
        n = self._fh.readinto(buf)
        self._owner.delivered += n or 0
        return n

    def __iter__(self) -> Any:
        for line in self._fh:
            yield self._count(line)

    def __enter__(self) -> _CountingFile:
        return self

    def __exit__(self, *exc: object) -> None:
        self._fh.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._fh, name)


def test_1105_hold_follow_false_refuses_a_link_root_and_tells_the_states_apart(tmp_path):
    """_io.hold(root, follow=False) holds a real directory and a directory under a linked
    ancestor; it raises OSError(ELOOP, 'refusing to create through a symlinked path component')
    for a link at root, dangling or not, NotADirectoryError for a regular file or a FIFO, and
    FileNotFoundError for an absent path, and it creates nothing. Positive control: hold(root)
    with the default follow=True still follows a link root as today (R41-01)."""
    real = tmp_path / "real"
    real.mkdir()
    (real / "r1").mkdir()
    ancestor = tmp_path / "ancestor"
    (ancestor / "runs" / "a1").mkdir(parents=True)
    linked_ancestor = tmp_path / "linked-ancestor"
    os.symlink(ancestor, linked_ancestor)
    other = tmp_path / "other-tenant-runs"
    (other / "b1").mkdir(parents=True)
    link = tmp_path / "link"
    os.symlink(other, link)
    dangling = tmp_path / "dangling"
    os.symlink(tmp_path / "nowhere", dangling)
    regular = tmp_path / "regular"
    regular.write_text("not a folder\n", encoding="utf-8")
    fifo = H.make_fifo(tmp_path / "fifo")
    absent = tmp_path / "absent"
    before = H.tree_state(tmp_path)

    held = _require_keyword(_io.hold, real, keyword="follow", follow=False)
    with held:
        assert held.view().entries().dirs() == ["r1"], "a real directory is held and listed"
    with _io.hold(linked_ancestor / "runs", follow=False) as under_link:
        assert under_link.view().entries().dirs() == ["a1"], (
            "a directory under a linked ancestor is held: ancestors are host configuration")
    for root in (link, dangling):
        err = H.raised(_io.hold, root, follow=False)
        assert isinstance(err, OSError), f"a link at the root ({root.name}) gave {err!r}"
        assert err.errno == errno.ELOOP, f"a link at the root is ELOOP: {err!r}"
        assert _LINK_REFUSAL in str(err), f"the link refusal's text: {err!r}"
        assert not isinstance(err, (FileNotFoundError, NotADirectoryError)), err
    for root in (regular, fifo):
        err = H.raised(_io.hold, root, follow=False)
        assert isinstance(err, NotADirectoryError), f"{root.name} gave {err!r}"
    err = H.raised(_io.hold, absent, follow=False)
    assert isinstance(err, FileNotFoundError), f"an absent root gave {err!r}"
    assert H.tree_state(tmp_path) == before, "hold(follow=False) created or changed something"

    with _io.hold(link) as followed:
        assert followed.view().entries().dirs() == ["b1"], (
            "the default follow=True still follows a link root (R41-01)")


def test_1105_bound_read_max_bytes_reads_no_more_than_it_is_asked(tmp_path):
    """Bound.read(name, max_bytes=N) reads no more than N bytes of the file, so a caller can
    tell a file longer than N - 1 bytes from one within it without reading it whole; without the
    keyword Bound.read keeps today's whole-file read (R41-16). The bytes are counted through
    _io's own os_= seam (an os proxy that only counts what each read hands back)."""
    n = 64
    folder = tmp_path / "records"
    folder.mkdir()
    contents = {"within.json": "a" * (n - 1), "at.json": "b" * n,
                "over.json": "c" * (1024 * 1024)}
    for name, text in contents.items():
        (folder / name).write_text(text, encoding="utf-8")
    counting = _CountingOS()
    with _io.hold(folder, os_=counting) as held:
        view = held.view()
        rec = _require_keyword(view.read, "within.json", keyword="max_bytes", max_bytes=n)
        assert rec.text == contents["within.json"], f"a file within N - 1 bytes reads whole: {rec!r}"
        for name in ("at.json", "over.json"):
            counting.delivered = 0
            rec = view.read(name, max_bytes=n)
            assert counting.delivered <= n, (
                f"read(max_bytes={n}) of {name} took {counting.delivered} bytes off the file")
            assert rec.text is not None, f"{name} read under max_bytes gave {rec!r}"
            assert len(rec.text.encode("utf-8")) == n, (
                f"{name} is longer than N - 1 bytes and its read must say so: {rec!r}")
            assert rec.text == contents[name][:n], f"the first N bytes of {name}: {rec.text!r}"
        counting.delivered = 0
        whole = view.read("over.json")
        assert whole.text == contents["over.json"], "without max_bytes the read is whole"
        assert counting.delivered == len(contents["over.json"]), (
            f"without max_bytes the whole file is read: {counting.delivered} bytes")
    with _io.bind(folder) as bound:
        assert bound.read("at.json", max_bytes=n).text == contents["at.json"], (
            "a bind()'s Bound takes the same keyword")
    assert Path(folder / "over.json").stat().st_size == len(contents["over.json"])
