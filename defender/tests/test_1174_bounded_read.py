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
from defender._run_paths import RunPaths
from defender.hooks import _run_dir
from defender.hooks import budget_enforcer as BE
from defender.runtime import circuit_breaker as CB
from defender.runtime.lead_zero import _capture as CAP
from defender.runtime.lead_zero._spec import ITEM1_SYSTEM
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
# Amendment 2 — the locked JSON update and read (M4/M7), the wrappers (M5), the breaker (M6)
# ---------------------------------------------------------------------------------------
#
# Callers get contents, never a handle to read. Unusable run-state content — too big,
# undecodable, not JSON, nested past `JSON_NESTING_LIMIT`, not an object — heals to the default
# on the update (O6) and reads as `{}` (O8) or, for the breaker, as tripped (O10). A read fault
# that is not about the content propagates out of the update (O7).


def _deep(depth: int) -> bytes:
    return ('{"a": ' + "[" * depth + "]" * depth + "}").encode()


#: Each unusable shape, planted by `plant_unusable`. The sparse one is above the limit; the
#: real one is 65 MiB of bytes on disk.
UNUSABLE = ("too_big_sparse", "too_big_real", "undecodable", "not_json", "too_deep",
            "unclosed_deep", "not_object")


def plant_unusable(path: Path, kind: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "too_big_sparse":
        sparse(path, 64 * MiB + 1)
    elif kind == "too_big_real":
        path.write_bytes(b"x" * (65 * MiB))
    else:
        path.write_bytes({
            "undecodable": b'{"a": "\xff\xfe"}',
            "not_json": b"{nope",
            "too_deep": _deep(_io.JSON_NESTING_LIMIT + 50),
            "unclosed_deep": b"[" * 200_000,
            "not_object": b"[1, 2]",
        }[kind])


def run_dir_at(tmp_path: Path) -> Path:
    runs_base = tmp_path / "data" / "runs"
    run_dir = runs_base / "run-1174"
    run_dir.mkdir(parents=True)
    return run_dir


def load(path: Path) -> Any:
    return json.loads(path.read_bytes())


# -- O6: the update heals ------------------------------------------------------------------


@pytest.mark.parametrize("kind", UNUSABLE)
def test_o6_open_budget_heals_unusable_content_to_the_default_with_the_change(tmp_path, kind):
    """`open_budget` runs outside any `try` at a resumed run's start; on unusable content it
    starts from the default, applies its change and writes, rather than raising."""
    run_dir = run_dir_at(tmp_path)
    plant_unusable(RunPaths(run_dir).budget, kind)
    state = BE.open_budget(run_dir, "run-1174")
    assert state["run_id"] == "run-1174"
    assert state["tool_calls"] == 0
    assert load(RunPaths(run_dir).budget) == state


@pytest.mark.parametrize("kind", UNUSABLE)
def test_o6_update_budget_locked_heals(tmp_path, kind):
    run_dir = run_dir_at(tmp_path)
    plant_unusable(RunPaths(run_dir).budget, kind)
    state = BE.update_budget_locked(run_dir, "run-1174", "gather")
    assert state["run_id"] == "run-1174"
    assert state["tool_calls"] == 1
    assert state["subagent_spawns"] == 1
    assert load(RunPaths(run_dir).budget) == state


def _infra_exit() -> int:
    return min(CB.INFRA_EXIT_CODES)


@pytest.mark.parametrize("kind", UNUSABLE)
def test_o6_record_outcome_heals_and_counts(tmp_path, kind):
    """Before, a too-big or too-deep state made `record_outcome` stop counting for the rest of
    the run (its `except` logs and returns `{}`). Now it starts over and counts."""
    run_dir = run_dir_at(tmp_path)
    plant_unusable(RunPaths(run_dir).circuit_breaker, kind)
    state = CB.record_outcome(run_dir, "elastic", _infra_exit())
    assert state["systems"]["elastic"]["failures"] == 1
    assert state["total_failures"] == 1
    assert load(RunPaths(run_dir).circuit_breaker) == state


def _budget_handle(run_dir: Path, io: Any = _io) -> Any:
    run = H.Run.for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=run_dir.parent, io=io)
    group = next(g for g, names in H.GROUP_MEMBERS.items() if "budget" in names)
    return S.member(run, group, "budget", *S.member_args("budget"))


@pytest.mark.parametrize("kind", UNUSABLE)
def test_o6_the_run_handle_update_heals(tmp_path, kind):
    run_dir = run_dir_at(tmp_path)
    h = _budget_handle(run_dir)
    plant_unusable(h.path, kind)
    h.update({"k": 1})
    assert load(h.path) == {"k": 1}


def test_o6_control_valid_documents_are_merged_not_reset(tmp_path):
    run_dir = run_dir_at(tmp_path)
    BE.open_budget(run_dir, "run-1174")
    BE.update_budget_locked(run_dir, "run-1174", "x")
    BE.update_budget_locked(run_dir, "run-1174", "x")
    assert load(RunPaths(run_dir).budget)["tool_calls"] == 2
    CB.record_outcome(run_dir, "elastic", _infra_exit())
    CB.record_outcome(run_dir, "elastic", _infra_exit())
    assert load(RunPaths(run_dir).circuit_breaker)["systems"]["elastic"]["failures"] == 2
    h = _budget_handle(run_dir)
    h.update({"a": 1})
    h.update({"b": 2})
    assert load(h.path)["a"] == 1
    assert load(h.path)["b"] == 2


def test_o6_the_rewrite_leaves_exactly_the_new_document(tmp_path):
    """`lseek` 0, `ftruncate` 0, then the whole write: a long old document shrinking to a short
    one leaves no tail and no leading NULs, byte for byte."""
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"long": "x" * 5000}))
    _run_dir.update_json_locked(p, lambda d: (d.clear(), d.update(k=1)))
    assert load(p) == {"k": 1}
    assert not p.read_bytes().startswith(b"\x00")
    assert p.read_bytes() == json.dumps({"k": 1}, indent=2).encode()


def test_o6_the_shared_update_heals_a_file_growing_past_the_limit(tmp_path):
    """Too big while growing is too big: it heals too (the step's own size refusal, by type)."""
    p = tmp_path / "state.json"
    p.write_text('{"a": 1}')
    f = FaultOs(read_fault=Endless())
    state = _io.locked_json_update(_io.locked_for_rewrite(p, os_=f), lambda d: d.update(k=1),
                                   default=dict, os_=f)
    assert state == {"k": 1}
    assert load(p) == {"k": 1}


# -- O7: a read fault that is not about the content propagates ------------------------------


def eio(_fd: int, _n: int) -> bytes:
    raise OSError(errno.EIO, os.strerror(errno.EIO))


def efbig_fault(_fd: int, _n: int) -> bytes:
    raise OSError(errno.EFBIG, os.strerror(errno.EFBIG))


@pytest.mark.parametrize("fault", [eio, eagain, vanishing_read, efbig_fault],
                         ids=["EIO", "EAGAIN", "vanished", "EFBIG-from-a-fault"])
@pytest.mark.parametrize("opener", ["path", "rooted"])
def test_o7_a_read_fault_propagates_out_of_the_update_and_changes_nothing(
        tmp_path, fault, opener):
    """Healing is decided by type: only the step's own size refusal heals, so an unrelated
    `EFBIG` raised by a fault propagates like `EIO`."""
    p = tmp_path / "state.json"
    p.write_text('{"keep": true}')
    f = FaultOs(read_fault=fault)
    cm = (_io.locked_for_rewrite(p, os_=f) if opener == "path"
          else _io.rooted_locked_for_rewrite(tmp_path, "state.json", os_=f))
    with pytest.raises(OSError):  # noqa: PT011 — each fault keeps its own errno and words
        _io.locked_json_update(cm, lambda d: d.update(k=1), default=dict, os_=f)
    assert p.read_text() == '{"keep": true}'


# -- O8: the locked read is bounded and creates nothing --------------------------------------


@pytest.mark.parametrize("kind", UNUSABLE)
def test_o8_read_budget_answers_empty_for_unusable_content(tmp_path, kind):
    run_dir = run_dir_at(tmp_path)
    plant_unusable(RunPaths(run_dir).budget, kind)
    assert BE.read_budget(run_dir) == {}


@pytest.mark.parametrize("fault", [eio, eagain, vanishing_read], ids=["EIO", "EAGAIN", "vanished"])
def test_o8_the_locked_read_answers_empty_for_any_read_error(tmp_path, fault):
    p = tmp_path / "state.json"
    p.write_text('{"a": 1}')
    f = FaultOs(read_fault=fault)
    assert _io.locked_json_read(_io.locked_for_read(p, os_=f), os_=f) == {}


def test_o8_control_the_locked_read_answers_the_document(tmp_path):
    p = tmp_path / "state.json"
    p.write_text('{"a": 1}')
    assert _io.locked_json_read(_io.locked_for_read(p)) == {"a": 1}
    assert _run_dir.read_json_locked(p) == {"a": 1}


def test_o8_reading_creates_neither_budget_nor_sidecar(tmp_path):
    run_dir = run_dir_at(tmp_path)
    assert BE.read_budget(run_dir) == {}
    assert not RunPaths(run_dir).budget.exists()
    assert BE.accounting_failure_state(run_dir) == {
        "consecutive_failures": 0, "first_failure_at": None}
    assert not BE._accounting_failure_path(run_dir).exists()


def test_o8_the_locked_read_refuses_a_link_without_following_it(tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_text('{"secret": 1}')
    p = tmp_path / "state.json"
    p.symlink_to(target)
    assert _run_dir.read_json_locked(p) == {}


def test_o8_a_sparse_sidecar_reads_as_no_failures(tmp_path):
    run_dir = run_dir_at(tmp_path)
    sparse(BE._accounting_failure_path(run_dir), 1 << 40)
    assert BE.accounting_failure_state(run_dir) == {
        "consecutive_failures": 0, "first_failure_at": None}


def test_o8_account_call_survives_a_sparse_budget(tmp_path):
    """`account_call` reads through `read_budget` before every tool call: a sparse plant there
    reads as no state, never `MemoryError`."""
    run_dir = run_dir_at(tmp_path)
    sparse(RunPaths(run_dir).budget, 1 << 40)
    state = BE.account_call(run_dir, "run-1174", "x", limits=BE.DEFAULT_LIMITS, tier="main")
    assert state["tool_calls"] == 1


# -- O11: the path update judges plainness on the descriptor ---------------------------------


class HardLinkBeforeOpen(FaultOs):
    """Plants a hard link to `target` between the precheck and the open (the race window)."""

    def __init__(self, target: Path, other: Path) -> None:
        super().__init__()
        self._target, self._other = target, other

    def open(self, path: Any, *a: Any, **kw: Any) -> int:
        self.calls.append("open")
        if Path(path) == self._target and not self._other.exists():
            os.link(self._target, self._other)
        return os.open(path, *a, **kw)


def test_o11_a_hard_link_planted_after_the_precheck_is_refused_on_the_descriptor(tmp_path):
    p = tmp_path / "budget.json"
    p.write_text('{"keep": true}')
    f = HardLinkBeforeOpen(p, tmp_path / "other")
    with pytest.raises(OSError, match="non-plain") as ei:
        _io.locked_json_update(_io.locked_for_rewrite(p, os_=f), lambda d: d.update(k=1),
                               default=dict, os_=f)
    assert ei.value.errno == errno.EMLINK
    assert p.read_text() == '{"keep": true}'


def test_o11_control_without_the_plant_the_update_lands(tmp_path):
    p = tmp_path / "budget.json"
    p.write_text('{"keep": true}')
    f = FaultOs()
    _io.locked_json_update(_io.locked_for_rewrite(p, os_=f), lambda d: d.update(k=1),
                           default=dict, os_=f)
    assert load(p) == {"keep": True, "k": 1}


# -- O10: the breaker reads fail closed on any unusable content ------------------------------


@pytest.mark.parametrize("kind", UNUSABLE)
def test_o10_the_breaker_reads_unusable_state_as_tripped(tmp_path, kind):
    run_dir = run_dir_at(tmp_path)
    plant_unusable(RunPaths(run_dir).circuit_breaker, kind)
    assert CB._load(run_dir).get("_unreadable") is True
    assert CB.is_tripped(run_dir, "elastic") is True
    assert CB.is_tripped(run_dir, "any_other_system") is True


@pytest.mark.parametrize("kind", UNUSABLE)
def test_o10_breaker_failures_degrades_without_raising(tmp_path, kind):
    """`_breaker_failures` reads through `_load`: unusable state degrades only this read (0),
    never `MemoryError` or `RecursionError`."""
    run_dir = run_dir_at(tmp_path)
    plant_unusable(RunPaths(run_dir).circuit_breaker, kind)
    assert CAP._breaker_failures(run_dir) == 0


def test_o10_control_a_valid_state_reads_as_before(tmp_path):
    run_dir = run_dir_at(tmp_path)
    RunPaths(run_dir).circuit_breaker.write_text(json.dumps(
        {"systems": {ITEM1_SYSTEM: {"failures": 2}}, "total_failures": 2}))
    assert CAP._breaker_failures(run_dir) == 2
    assert CB._load(run_dir).get("_unreadable") is None
    assert CB.is_tripped(run_dir, "never_failed") is False


# -- O1 widened, O9: the canonical wrappers ---------------------------------------------------


def test_o1_the_wrappers_refuse_a_file_over_their_limit(tmp_path):
    p = sparse(tmp_path / "big.txt", 64 * MiB + 1)
    with pytest.raises(OSError, match="read limit"):
        _io.read_text_utf8(p)
    text, reason = _io.read_text_soft(p)
    assert text is None
    assert reason
    with pytest.raises(OSError, match="read limit"):
        _io.read_jsonl_rows_report(p)
    with pytest.raises(OSError, match="read limit"):
        _io.read_jsonl_rows(p)


def test_o1_the_wrappers_take_a_per_caller_limit(tmp_path):
    p = tmp_path / "small.txt"
    p.write_text("x" * 100)
    with pytest.raises(OSError, match="read limit"):
        _io.read_text_utf8(p, limit=10)
    assert _io.read_text_soft(p, limit=10)[0] is None
    assert _io.read_text_utf8(p, limit=100) == "x" * 100
    big = sparse(tmp_path / "big.jsonl", 64 * MiB + 1)
    assert _io.read_jsonl_rows_report(big, limit=None) == ([], 1)


def test_o1_the_wire_log_reader_reads_past_the_default_limit(tmp_path):
    """`visualize_messages.load_messages` reads the wire log (up to 115 MB seen) and passes
    `limit=None`: an operator tool over a host-written log."""
    run_dir = run_dir_at(tmp_path)
    wire = RunPaths(run_dir).wire_log
    wire.parent.mkdir(parents=True, exist_ok=True)
    sparse(wire, 64 * MiB + 1)
    # Imported here, as test_1077_replay does: the visualize modules import each other.
    from defender.scripts.visualize.visualize_messages import load_messages
    assert load_messages(run_dir) == []


def test_o9_the_wrappers_still_follow_links(tmp_path):
    target = tmp_path / "real.jsonl"
    target.write_text('{"a": 1}\n')
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    assert _io.read_text_soft(link) == ('{"a": 1}\n', None)
    assert _io.read_text_utf8(link) == '{"a": 1}\n'
    assert _io.read_jsonl_rows(link) == [{"a": 1}]


def test_o5_the_wrappers_read_as_before(tmp_path):
    p = tmp_path / "mixed.txt"
    data = _mixed_content()
    p.write_bytes(data)
    want = p.read_text(encoding="utf-8")
    assert _io.read_text_utf8(p) == want
    assert _io.read_text_soft(p) == (want, None)
    bad = tmp_path / "rows.jsonl"
    bad.write_bytes(b'{"a": 1}\r\n\xff\xfe\n{"b": 2}\rnot json\n')
    expected = _io._jsonl_rows_of(bad.read_text(encoding="utf-8", errors="replace"))
    assert _io.read_jsonl_rows_report(bad) == expected
    assert expected[0] == [{"a": 1}, {"b": 2}]


def test_o5_a_procfs_file_reporting_size_zero_reads_in_full():
    """`/proc/self/mountinfo` reports `st_size` 0; the step reads to EOF whatever `fstat` says
    (`runtime/box/_docker.py` reads it through `read_text_soft`)."""
    proc = Path("/proc/self/mountinfo")
    assert os.stat(proc).st_size == 0
    text, reason = _io.read_text_soft(proc)
    assert reason is None
    assert text
    assert text.splitlines()[0] == proc.read_text().splitlines()[0]
