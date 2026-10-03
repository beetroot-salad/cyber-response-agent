"""#1174 — one bounded read step under every whole-file read of a guarded plain file.

The design (issue comment on #1174): every plain-file reader in `_io` — `Bound.read` (so
`read_jsonl`), `rooted_read`, `read_plain`, `read_plain_bytes`, `read_guarded`,
`read_bytes_guarded` — and the two read-modify-write reads through the rewrite handles
(`_run_handle`'s `update` verb, `hooks/_run_dir.update_json_locked`) owe:

- O1: a file over `READ_LIMIT` (64 MiB) is refused before any byte is read, path-free; a file
  that grows past it while read is refused too; no `MemoryError`.
- O2: a read that gets no data on the non-blocking descriptor (`EAGAIN`) is a refusal.
- O3: absent means absent at the walk or the open only; an `ENOENT` after the descriptor was
  judged plain (a `read`, or any `fstat` after the plainness one) is never absent, and a
  refusal's reason differs from the absent answer word for word.
- O4: a name or path that does not encode is refused before any I/O; a surrogateescape name
  (an undecodable byte) is still a name.
- O5: a successful read is unchanged — universal newlines, `errors=`, exact bytes.

Real faults where they are cheap (a sparse file costs no disk); the rest enter through each
reader's `os_=` seam (`FaultOs`), never `monkeypatch.setattr`.
"""
from __future__ import annotations

import errno
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _io
from defender import _run_handle as H
from defender.hooks import _run_dir
from defender.tests import _spec1077 as S

MiB = 1024 * 1024
NAME = "rec.txt"
ABSENT_TEXT = os.strerror(errno.ENOENT)


# ---------------------------------------------------------------------------------------
# The seam: a pass-through `os` with one fault switched on
# ---------------------------------------------------------------------------------------


class FaultOs:
    """`os`, except: `read_fault(fd, n)` replaces `read`; `vanish_on_second_reg_fstat` makes the
    second `fstat` that sees a regular file on the same descriptor raise ENOENT (the first is
    the open's plainness judgement; a second would be a reader asking again); `calls` records
    names."""

    def __init__(self, *, read_fault: Callable[[int, int], bytes] | None = None,
                 vanish_on_second_reg_fstat: bool = False) -> None:
        self._read_fault = read_fault
        self._vanish = vanish_on_second_reg_fstat
        self._reg_seen: dict[int, int] = {}
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        self.calls.append(name)
        return getattr(os, name)

    def read(self, fd: int, n: int) -> bytes:
        self.calls.append("read")
        if self._read_fault is not None:
            return self._read_fault(fd, n)
        return os.read(fd, n)

    def fstat(self, fd: int) -> os.stat_result:
        self.calls.append("fstat")
        st = os.fstat(fd)
        if self._vanish and stat.S_ISREG(st.st_mode):
            self._reg_seen[fd] = self._reg_seen.get(fd, 0) + 1
            if self._reg_seen[fd] >= 2:
                raise FileNotFoundError(errno.ENOENT, ABSENT_TEXT)
        return st


def eagain(_fd: int, _n: int) -> bytes:
    raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))


def vanishing_read(_fd: int, _n: int) -> bytes:
    raise FileNotFoundError(errno.ENOENT, ABSENT_TEXT)


class Endless:
    """A file that never reaches EOF — one that keeps growing while it is read. `handed` counts
    the bytes it gave out, so a bound looser than the limit shows."""

    def __init__(self) -> None:
        self.handed = 0

    def __call__(self, _fd: int, n: int) -> bytes:
        self.handed += n
        return b"a" * n


# ---------------------------------------------------------------------------------------
# The readers, each answering one normalized outcome
# ---------------------------------------------------------------------------------------
#
# ("ok", value) | ("absent", None) | ("refused", reason). `rooted_read` and the `_guarded`
# readers fold absence into a reason; their "absent" is recognised by the reason they give for
# a really missing file (`absent_reason`), so a read-phase refusal must differ from it.


def _bound(root: Path, name: str, os_: Any, binary: bool) -> tuple[str, Any]:
    with _io.bind(root, os_=os_) as b:
        rec = b.read(name)
    if rec.absent:
        return "absent", None
    if rec.text is None:
        return "refused", rec.reason
    return "ok", rec.text


def _rooted(root: Path, name: str, os_: Any, binary: bool) -> tuple[str, Any]:
    value, reason = _io.rooted_read(root, name, binary=binary, os_=os_)
    if value is None:
        return "refused", reason
    return "ok", value


def _plain(root: Path, name: str, os_: Any, binary: bool) -> tuple[str, Any]:
    fn = _io.read_plain_bytes if binary else _io.read_plain
    try:
        return "ok", fn(root / name, os_=os_)
    except FileNotFoundError:
        return "absent", None
    except _io.TEXT_READ_ERRORS as e:
        return "refused", str(e)


def _guarded(root: Path, name: str, os_: Any, binary: bool) -> tuple[str, Any]:
    fn = _io.read_bytes_guarded if binary else _io.read_guarded
    value, reason = fn(root / name, os_=os_)
    if value is None:
        return "refused", reason
    return "ok", value


READERS = {
    "Bound.read": (_bound, False),
    "rooted_read": (_rooted, False),
    "rooted_read(binary)": (_rooted, True),
    "read_plain": (_plain, False),
    "read_plain_bytes": (_plain, True),
    "read_guarded": (_guarded, False),
    "read_bytes_guarded": (_guarded, True),
}
FOLDS_ABSENCE = {"rooted_read", "rooted_read(binary)", "read_guarded", "read_bytes_guarded"}


def read(reader: str, root: Path, name: str = NAME, os_: Any = os) -> tuple[str, Any]:
    fn, binary = READERS[reader]
    return fn(root, name, os_, binary)


def absent_reason(reader: str, root: Path, name: str = NAME) -> Any:
    """What `reader` answers for a really missing `name` — the absent answer a read-phase
    refusal must not be mistaken for."""
    assert not (root / name).exists()
    kind, payload = read(reader, root, name)
    return payload if reader in FOLDS_ABSENCE else kind


def open_fds() -> int:
    return len(os.listdir("/proc/self/fd"))


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "root-SECRET-1174"
    r.mkdir()
    return r


def sparse(path: Path, size: int) -> Path:
    with open(path, "wb") as f:  # lint-text-io: ok — test plant of a sparse file
        f.truncate(size)
    return path


def assert_path_free(reason: Any, root: Path) -> None:
    assert reason, reason
    assert "SECRET-1174" not in str(reason), f"the reason names the path: {reason!r}"


def assert_refused_vanished(reader: str, root: Path, outcome: tuple[str, Any],
                            missing: Any) -> None:
    kind, payload = outcome
    assert kind == "refused", f"{reader}: a read-phase ENOENT answered {outcome}, not a refusal"
    assert "vanished" in str(payload), f"{reader}: the read-phase reason is not its own: {payload!r}"
    assert ABSENT_TEXT not in str(payload), (
        f"{reader}: the read-phase reason reuses the absent words: {payload!r}")
    if reader in FOLDS_ABSENCE:
        assert payload != missing, (
            f"{reader}: the read-phase refusal reads exactly as absent: {payload!r}")
    assert_path_free(payload, root)


# ---------------------------------------------------------------------------------------
# O1 — size
# ---------------------------------------------------------------------------------------


def test_the_read_limit_is_64_mib():
    assert 64 * MiB == _io.READ_LIMIT


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("size", [64 * MiB + 1, 1 << 40], ids=["limit+1", "1TiB"])
def test_o1_a_sparse_file_over_the_limit_is_refused_before_any_read(root, reader, size):
    """A planted sparse file (`truncate -s`) just over the limit, and a 1 TiB one, is refused:
    no `MemoryError` (CPython would pre-size a buffer of `st_size + 1`), no read, a reason that
    names no path. The descriptor is closed."""
    sparse(root / NAME, size)
    rec = FaultOs()
    before = open_fds()
    outcome = read(reader, root, os_=rec)
    assert open_fds() == before, f"{reader}: a descriptor leaked on the size refusal"
    kind, reason = outcome
    assert kind == "refused", f"{reader}: {outcome!r}"
    assert_path_free(reason, root)
    assert "read" not in rec.calls, f"{reader}: read before refusing on size: {rec.calls}"


@pytest.mark.parametrize("reader", ["read_plain", "read_plain_bytes"])
def test_o1_the_raising_readers_refuse_with_efbig(root, reader):
    sparse(root / NAME, 64 * MiB + 1)
    fn = _io.read_plain_bytes if reader == "read_plain_bytes" else _io.read_plain
    with pytest.raises(OSError, match="read limit") as ei:
        fn(root / NAME)
    assert ei.value.errno == errno.EFBIG
    assert not isinstance(ei.value, FileNotFoundError)
    assert "SECRET-1174" not in str(ei.value)


def test_o1_a_file_exactly_at_the_limit_is_read(root):
    """Positive control on the bound: `> READ_LIMIT` is refused, `== READ_LIMIT` is read."""
    sparse(root / NAME, 64 * MiB)
    data = _io.read_plain_bytes(root / NAME)
    assert len(data) == 64 * MiB


@pytest.mark.parametrize("reader", READERS)
def test_o1_a_file_growing_past_the_limit_while_read_is_refused(root, reader):
    """`fstat` says small; the reads never reach EOF (the file grows). The running total past
    the limit is the same refusal, not an unbounded buffer."""
    (root / NAME).write_bytes(b"small\n")
    before = open_fds()
    endless = Endless()
    kind, reason = read(reader, root, os_=FaultOs(read_fault=endless))
    assert open_fds() == before, f"{reader}: a descriptor leaked"
    assert kind == "refused", f"{reader}: {kind} {str(reason)[:80]!r}"
    assert_path_free(reason, root)
    assert endless.handed <= _io.READ_LIMIT + 1 * MiB, (
        f"{reader}: took in {endless.handed} bytes before refusing — the running bound is "
        "looser than the limit")


# ---------------------------------------------------------------------------------------
# O2 — EAGAIN on the non-blocking descriptor
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("reader", READERS)
def test_o2_a_read_with_no_data_yet_is_a_refusal(root, reader):
    """FUSE/procfs can answer `EAGAIN` on the `O_NONBLOCK` descriptor. That is a refusal — not
    a `TypeError` from a `None` read, not a silently empty answer."""
    (root / NAME).write_text("payload\n")
    before = open_fds()
    outcome = read(reader, root, os_=FaultOs(read_fault=eagain))
    assert open_fds() == before, f"{reader}: a descriptor leaked"
    assert outcome[0] == "refused", f"{reader}: {outcome!r}"


@pytest.mark.parametrize("reader", READERS)
def test_o2_control_the_same_seam_without_the_fault_reads_the_file(root, reader):
    (root / NAME).write_text("payload\n")
    kind, value = read(reader, root, os_=FaultOs())
    assert kind == "ok"
    assert value in ("payload\n", b"payload\n")


# ---------------------------------------------------------------------------------------
# O3 — absent only at the walk or the open
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("reader", READERS)
def test_o3_enoent_from_read_is_a_refusal_not_absent(root, reader):
    missing = absent_reason(reader, root)
    (root / NAME).write_text("payload\n")
    before = open_fds()
    outcome = read(reader, root, os_=FaultOs(read_fault=vanishing_read))
    assert open_fds() == before, f"{reader}: a descriptor leaked"
    assert_refused_vanished(reader, root, outcome, missing)


@pytest.mark.parametrize("reader", READERS)
def test_o3_enoent_from_an_fstat_after_the_plainness_judgement_never_answers_absent(root, reader):
    """After the open judged the descriptor plain, an `fstat` raising ENOENT never answers
    absent. The read step takes the size from the open's own `fstat` (#1049 pins one `fstat`
    per opened handle), so it asks no second one, and the read succeeds; any second `fstat`
    an implementation adds must refuse, not answer absent."""
    missing = absent_reason(reader, root)
    (root / NAME).write_text("payload\n")
    kind, payload = read(reader, root, os_=FaultOs(vanish_on_second_reg_fstat=True))
    if kind == "ok":
        assert payload in ("payload\n", b"payload\n")
    else:
        assert_refused_vanished(reader, root, (kind, payload), missing)


@pytest.mark.parametrize("reader", READERS)
def test_o3_control_a_really_missing_file_is_still_absent(root, reader):
    kind, payload = read(reader, root)
    if reader in FOLDS_ABSENCE:
        assert kind == "refused", (reader, payload)
        assert ABSENT_TEXT in payload, (reader, payload)
    else:
        assert kind == "absent", (reader, kind, payload)


@pytest.mark.parametrize("fn", [_io.read_plain, _io.read_plain_bytes])
def test_o3_read_plain_raises_a_non_filenotfound_oserror_for_a_read_phase_enoent(root, fn):
    """`read_plain`'s `FileNotFoundError` means absent to its caller (`_document.py` reads it as
    an empty companion), so a read-phase ENOENT must raise some other `OSError`."""
    (root / NAME).write_text("payload\n")
    with pytest.raises(OSError, match="vanished") as ei:
        fn(root / NAME, os_=FaultOs(read_fault=vanishing_read))
    assert not isinstance(ei.value, FileNotFoundError), type(ei.value)


# ---------------------------------------------------------------------------------------
# O4 — names and paths that do not encode
# ---------------------------------------------------------------------------------------


#: Lone surrogates `os.fsencode` cannot encode: everything in U+D800..U+DFFF except the
#: surrogateescape range U+DC80..U+DCFF, which spells an undecodable byte.
UNENCODABLE = ["\ud800", "\udbff", "\udc00", "\udc7f", "\udd00", "\udfff"]
SURROGATEESCAPE = ["\udc80", "\udcff"]


def test_o4_the_samples_are_what_fsencode_says():
    for ch in UNENCODABLE:
        with pytest.raises(UnicodeEncodeError):
            os.fsencode(ch)
    for ch in SURROGATEESCAPE:
        assert len(os.fsencode(ch)) == 1


@pytest.mark.parametrize("name", [*UNENCODABLE, "a/\ud800", "\udfff.md", "x\udc00y"])
def test_o4_parse_name_refuses_a_lone_surrogate(name):
    with pytest.raises(ValueError, match="not a valid relative name"):
        _io._parse_name(name)


@pytest.mark.parametrize("name", [*UNENCODABLE, "dir/\ud800"])
def test_o4_bound_and_rooted_refuse_an_unencodable_name_before_any_io(root, name):
    rec = FaultOs()
    with _io.bind(root, os_=rec) as b:
        rec.calls.clear()
        with pytest.raises(ValueError, match="not a valid relative name"):
            b.read(name)
        assert rec.calls == [], f"I/O before the name was refused: {rec.calls}"
    rec2 = FaultOs()
    with pytest.raises(ValueError, match="not a valid relative name"):
        _io.rooted_read(root, name, os_=rec2)
    assert rec2.calls == [], f"I/O before the name was refused: {rec2.calls}"


@pytest.mark.parametrize("name", SURROGATEESCAPE)
def test_o4_control_a_surrogateescape_name_is_still_a_name(root, name):
    """`\\udc80`..`\\udcff` are undecodable bytes as `os.fsdecode` spells them — real names,
    for the name readers and the path readers alike."""
    _io._parse_name(name)
    with _io.bind(root) as b:
        assert b.read(name).absent
    (root / name).write_text("x")
    with _io.bind(root) as b:
        assert b.read(name).text == "x"
    assert _io.rooted_read(root, name) == ("x", None)
    assert _io.read_plain(root / name) == "x"
    assert _io.read_guarded(root / name) == ("x", None)
    assert _io.read_plain_bytes(root / name) == b"x"


PATH_READERS = ["read_plain", "read_plain_bytes", "read_guarded", "read_bytes_guarded"]


@pytest.mark.parametrize("reader", PATH_READERS)
@pytest.mark.parametrize("ch", UNENCODABLE)
def test_o4_a_path_reader_refuses_an_unencodable_path_as_a_read_error(root, reader, ch):
    """`read_guarded` promises `(None, reason)`; a `UnicodeEncodeError` (not a
    `TEXT_READ_ERRORS` member) must not escape it, nor `read_plain`'s contract. The refusal
    names no path."""
    rec = FaultOs()
    kind, reason = read(reader, root, name=f"x{ch}", os_=rec)
    assert kind == "refused", (reader, kind, reason)
    assert "open" not in rec.calls, f"{reader}: opened before refusing: {rec.calls}"
    assert_path_free(reason, root)


@pytest.mark.parametrize("reader", PATH_READERS)
def test_o4_control_a_path_reader_opens_through_its_seam(root, reader):
    """The positive control for the row above: on a good path the same seam does see the
    open, so "no open" there means refused first, not a seam the open never crosses."""
    (root / NAME).write_text("payload\n")
    rec = FaultOs()
    kind, _value = read(reader, root, os_=rec)
    assert kind == "ok"
    assert "open" in rec.calls, f"{reader}: the open did not go through os_: {rec.calls}"


# ---------------------------------------------------------------------------------------
# O5 — a successful read is unchanged
# ---------------------------------------------------------------------------------------


def _mixed_content() -> bytes:
    """~600 KiB: `\\r\\n`, lone `\\r` and `\\n`, with a `\\r\\n` and a two-byte UTF-8 character
    straddling every 64 KiB boundary, so a chunked read must stitch both. The filler is ASCII,
    so the planted sequences never split a character of their own; `é` also recurs elsewhere."""
    out = bytearray()
    line = 0
    while len(out) < 600 * 1024:
        out += f"line {line} ".encode() + (b"\r\n", b"\r", b"\n")[line % 3]
        line += 1
    e_acute = "é".encode()
    for k in range(1, 9):
        at = k * 64 * 1024
        # Both shapes straddle 64, 128 and 256 KiB multiples alike: `\r\n` at 64k·{1,3,4,5,7},
        # `é` at 64k·{2,6,8} — so 256 KiB carries `\r\n` and 512 KiB carries `é`.
        out[at - 1:at + 1] = e_acute if k in (2, 6, 8) else b"\r\n"
        out[at + 100:at + 102] = e_acute
    out[1000:1002] = e_acute
    data = bytes(out)
    data.decode("utf-8")  # the fixture itself is valid UTF-8
    return data


@pytest.mark.parametrize("reader", READERS)
def test_o5_a_multi_chunk_mixed_newline_file_reads_as_read_text_would(root, reader):
    data = _mixed_content()
    (root / NAME).write_bytes(data)
    kind, value = read(reader, root)
    assert kind == "ok", (reader, kind)
    if READERS[reader][1]:
        assert value == data
    else:
        assert value == (root / NAME).read_text(encoding="utf-8")


def trickle(k: int) -> Callable[[int, int], bytes]:
    """A descriptor that hands out at most `k` bytes per `read` — a short read is legal at any
    size, so a reader must loop and stitch whatever the chunking."""
    return lambda fd, n: os.read(fd, min(n, k))


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("k", [7, 4093])
def test_o5_short_reads_of_any_size_stitch_to_the_same_answer(root, reader, k):
    """Kills per-chunk decoding or newline translation (a `\\r\\n` or a two-byte character
    split across two reads) and a single big `read` with no loop."""
    data = _mixed_content()
    (root / NAME).write_bytes(data)
    kind, value = read(reader, root, os_=FaultOs(read_fault=trickle(k)))
    assert kind == "ok", (reader, kind, str(value)[:80])
    if READERS[reader][1]:
        assert value == data
    else:
        assert value == (root / NAME).read_text(encoding="utf-8")


def test_o5_errors_replace_and_strict_are_unchanged(root):
    data = b"ok \xff\xfe bad\r\nmore \xc3"
    (root / NAME).write_bytes(data)
    expected = (root / NAME).read_text(encoding="utf-8", errors="replace")
    assert _io.read_plain(root / NAME, errors="replace") == expected
    assert _io.read_guarded(root / NAME, errors="replace") == (expected, None)
    with _io.bind(root) as b:
        assert b.read(NAME, errors="replace").text == expected
        strict = b.read(NAME)
    assert strict.text is None
    assert not strict.absent
    with pytest.raises(UnicodeDecodeError) as ei:
        _io.read_plain(root / NAME)
    with pytest.raises(UnicodeDecodeError) as want:
        data.decode("utf-8")
    assert (ei.value.start, ei.value.end, ei.value.reason) == (
        want.value.start, want.value.end, want.value.reason)


@pytest.mark.parametrize("reader", READERS)
def test_o5_an_empty_file_is_an_empty_read(root, reader):
    (root / NAME).write_bytes(b"")
    assert read(reader, root) in (("ok", ""), ("ok", b""))


# ---------------------------------------------------------------------------------------
# The rewrite reads (M1b)
# ---------------------------------------------------------------------------------------


def _budget(tmp_path: Path) -> Any:
    runs_base = tmp_path / "data" / "runs"
    (runs_base / "run-1174").mkdir(parents=True)
    run = H.Run.for_tenant(S.DEFAULT_TENANT_ID, "run-1174", runs_base=runs_base, io=_io)
    group = next(g for g, names in H.GROUP_MEMBERS.items() if "budget" in names)
    return S.member(run, group, "budget", *S.member_args("budget"))


def test_m1b_the_run_handle_update_refuses_a_huge_record_and_leaves_it_whole(tmp_path):
    h = _budget(tmp_path)
    sparse(h.path, 1 << 40)
    with pytest.raises(OSError, match="read limit") as ei:
        h.update({"k": 1})
    assert ei.value.errno == errno.EFBIG
    assert h.path.stat().st_size == 1 << 40, "the refused update truncated the record"


def test_m1b_control_the_run_handle_update_still_merges(tmp_path):
    h = _budget(tmp_path)
    h.update({"a": 1})
    h.update({"b": 2})
    assert json.loads(h.path.read_text()) == {"a": 1, "b": 2}


def test_m1b_update_json_locked_refuses_a_huge_document_and_leaves_it_whole(tmp_path):
    p = sparse(tmp_path / "state.json", 1 << 40)
    with pytest.raises(OSError, match="read limit") as ei:
        _run_dir.update_json_locked(p, lambda d: d.update(k=1))
    assert ei.value.errno == errno.EFBIG
    assert p.stat().st_size == 1 << 40, "the refused update truncated the document"


def test_m1b_control_update_json_locked_still_merges(tmp_path):
    p = tmp_path / "state.json"
    _run_dir.update_json_locked(p, lambda d: d.update(a=1))
    _run_dir.update_json_locked(p, lambda d: d.update(b=2))
    assert json.loads(p.read_text()) == {"a": 1, "b": 2}


class _NoDataYet:
    """A rewrite handle whose read finds no data yet (`FileIO.readall` → `None` on EAGAIN)."""

    def __init__(self, fd: int) -> None:
        self._fd = fd

    def fileno(self) -> int:
        return self._fd

    def read(self, *_a: Any) -> None:
        return None


class _Grows:
    """A rewrite handle over a real small file whose reads hand out far more than its `fstat`
    said — `flock` is advisory, so a writer that ignores it can grow the file under the lock.
    `asked` records each `read` size (`None` for an unbounded `read()`)."""

    def __init__(self, f: Any) -> None:
        self._f = f
        self.asked: list[int | None] = []

    def fileno(self) -> int:
        return self._f.fileno()

    def read(self, n: int | None = None, /) -> str:
        self.asked.append(n)
        size = _io.READ_LIMIT + 1 * MiB if n is None or n < 0 else min(n, _io.READ_LIMIT + MiB)
        return "a" * size

    def __getattr__(self, name: str) -> Any:
        return getattr(self._f, name)


def test_m1b_a_rewrite_read_growing_past_the_limit_is_refused(tmp_path):
    p = tmp_path / "f"
    p.write_text("{}")
    with open(p, "r+", encoding="utf-8") as f:
        g = _Grows(f)
        with pytest.raises(OSError, match="read limit"):
            _io.read_locked_whole(g)
    assert g.asked, "the helper never read"
    assert all(n is not None and 0 <= n <= _io.READ_LIMIT + 1 for n in g.asked), (
        f"the rewrite read asked for more than the limit: {g.asked}")


class _GrowingIo:
    """`_io` for a run handle, except its rewrite handle grows under the lock (`_Grows`)."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_io, name)

    @staticmethod
    def rooted_locked_for_rewrite(*a: Any, **kw: Any) -> Any:
        import contextlib

        @contextlib.contextmanager
        def cm() -> Any:
            with _io.rooted_locked_for_rewrite(*a, **kw) as f:
                yield _Grows(f)
        return cm()


def test_m1b_the_run_handle_update_refuses_a_record_growing_past_the_limit(tmp_path):
    runs_base = tmp_path / "data" / "runs"
    (runs_base / "run-1174").mkdir(parents=True)
    run = H.Run.for_tenant(S.DEFAULT_TENANT_ID, "run-1174", runs_base=runs_base,
                           io=_GrowingIo())
    group = next(g for g, names in H.GROUP_MEMBERS.items() if "budget" in names)
    h = S.member(run, group, "budget", *S.member_args("budget"))
    h.path.parent.mkdir(parents=True, exist_ok=True)
    h.path.write_text('{"seed": 1}')
    before = h.path.read_bytes()
    with pytest.raises(OSError, match="read limit"):
        h.update({"k": 1})
    assert h.path.read_bytes() == before, "the refused update rewrote the record"


def test_m1b_a_rewrite_read_with_no_data_yet_is_blocking_io_error(tmp_path):
    p = tmp_path / "f"
    p.write_text("{}")
    fd = os.open(p, os.O_RDONLY)
    try:
        with pytest.raises(BlockingIOError):
            _io.read_locked_whole(_NoDataYet(fd))
    finally:
        os.close(fd)
