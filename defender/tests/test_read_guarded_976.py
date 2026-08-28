"""`_io.read_guarded` — the read-side twin of the write seam (#976).

WHY THIS SEAM EXISTS. Every read of a path inside a run dir, an episode dir or the drain
corpus is a read from a tree a live box is root on, so an entry at an expected artifact's name
may be something the model planted. The write side has had ONE seam for that since M3; the
read side had a per-module habit, and the habit was wrong twice in one file inside a single
change — no screen at all, then an `S_ISREG` screen that admitted a hard link. Two guards on
one path that do not match is not a defect you fix once, which is what makes it a function.

The arms below are the refusal set. Each is paired with the write side asking the same
question, because "twins" is the claim and a test that only exercised one half would let them
drift apart exactly as the comment they replaced did.
"""
from __future__ import annotations

import contextlib
import os
import signal
import stat

import pytest

from defender import _io  # type: ignore[import-not-found]


@contextlib.contextmanager
def _deadline(seconds: int):
    """Turn "this call never returns" into an ordinary test failure.

    `SIGALRM` rather than a thread or a subprocess: the read under test is a blocking syscall,
    so only a signal can interrupt it in-process, and pytest has no timeout plugin here."""

    def _fire(_signum, _frame):
        raise AssertionError(f"read_guarded did not return within {seconds}s — it blocked")

    previous = signal.signal(signal.SIGALRM, _fire)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _content(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("payload\n", encoding="utf-8")
    return real


def test_a_plain_file_reads(tmp_path):
    """The positive control. A guard that refused everything would pass every arm below."""
    text, err = _io.read_guarded(_content(tmp_path))
    assert text == "payload\n"
    assert err is None


def test_a_symlink_is_refused_not_followed(tmp_path):
    """`O_NOFOLLOW` refuses at the OPEN, so there is no window: a check-then-act pair answers
    about whatever the name meant a moment ago, and that window is where a plant belongs."""
    real = _content(tmp_path)
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    text, err = _io.read_guarded(link)
    assert text is None
    assert err
    with pytest.raises(OSError, match="aliased entry"):
        _io.write_guarded(link, "x")


def test_a_hard_link_is_refused(tmp_path):
    """THE SHAPE THAT GOT THROUGH. `O_NOFOLLOW` never fires for a hard link — the open
    SUCCEEDS — so the link count has to be asked of the descriptor rather than inferred from
    the open having worked. The `S_ISREG` screen this replaced accepted it."""
    real = _content(tmp_path)
    link = tmp_path / "hard.txt"
    os.link(real, link)
    text, err = _io.read_guarded(link)
    assert text is None, "a hard-linked file was read as though it were its own artifact"
    assert _io.ALIAS_READ_REFUSAL in err
    with pytest.raises(OSError, match="aliased entry"):
        _io.write_guarded(link, "x")


def test_a_directory_at_the_name_is_refused(tmp_path):
    """Folded into the same refusal as an alias, for the reason `_refuse_unless_plain` gives:
    a caller must not have to tell a squatting directory apart from a planted symlink to know
    it has no artifact."""
    d = tmp_path / "dir.txt"
    d.mkdir()
    text, err = _io.read_guarded(d)
    assert text is None
    assert err


def test_a_fifo_at_the_name_is_refused_rather_than_blocking_forever(tmp_path):
    """The shape whose failure mode is not a wrong answer but NO answer: an ordinary read of a
    fifo with no writer blocks until one appears, so a reader without this screen hangs
    whatever called it."""
    fifo = tmp_path / "pipe.txt"
    os.mkfifo(fifo)
    assert stat.S_ISFIFO(os.lstat(fifo).st_mode)
    # THE ARM ENFORCES ITS OWN BOUND. Without `O_NONBLOCK` this call never returns, and a test
    # that demonstrated the hang BY hanging would wedge CI instead of reporting a failure —
    # the alarm turns "never answers" into the assertion failure it is.
    with _deadline(5):
        text, err = _io.read_guarded(fifo)
    assert text is None
    assert err


def test_a_missing_file_is_a_reason_not_an_exception(tmp_path):
    """Absent is a refusal here, unlike the write side where it is the ordinary case — and it
    must not raise, because every caller of this already tolerates "you have no content"."""
    text, err = _io.read_guarded(tmp_path / "nope.txt")
    assert text is None
    assert err


def test_undecodable_bytes_are_a_reason_not_an_exception(tmp_path):
    """`UnicodeDecodeError` is not an `OSError`, which is why `TEXT_READ_ERRORS` names both —
    the exact family mistake this change's review found three times elsewhere."""
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"\xff\xfe not utf-8 \xff")
    text, err = _io.read_guarded(bad)
    assert text is None
    assert err


def test_the_descriptor_is_not_leaked_on_the_refusal_paths(tmp_path):
    """The refusal returns BEFORE `fdopen` takes ownership, so the close is the caller's — and
    a leak here is invisible until a long-lived process runs out of descriptors."""
    real = _content(tmp_path)
    link = tmp_path / "hard.txt"
    os.link(real, link)
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(64):
        _io.read_guarded(link)
        _io.read_guarded(tmp_path / "absent.txt")
        _io.read_guarded(real)
    assert len(os.listdir("/proc/self/fd")) <= before + 2
