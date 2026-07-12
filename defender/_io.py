"""The text-IO contract: UTF-8-pinned reads, the guard that holds them, tolerant JSONL,
atomic writes. Shared across learning/, scripts/, runtime/ and hooks/.

One contract for "read a text file the model wrote", "read a live-appended JSONL queue" and
"rewrite a file atomically", so the copies can't drift apart again. ``read_jsonl_rows`` skips
torn/blank lines (an append interrupted mid-write leaves a half-line — see #446);
``write_atomic`` does the ``tmp → write → os.replace`` dance so a reader never sees
a partial file.

**The encoding contract (#588/#589).** Reading a text file has two independent traps, and a
caller that solves only one still breaks:

1. *The pin.* A bare ``read_text()`` decodes under the **ambient locale**, so where the
   interpreter's encoding really is ascii, a valid UTF-8 file containing ``café`` raises. Every
   read here pins ``encoding="utf-8"``; :func:`use_utf8_stdio` is the matching pin on the WRITE
   side, without which a pinned read only moves the crash downstream.
2. *The guard.* An undecodable byte raises ``UnicodeDecodeError``, which is a **``ValueError``,
   NOT an ``OSError``** — and not a ``json.JSONDecodeError`` or a ``yaml.YAMLError`` either
   (those are *siblings*, not superclasses). An ``except OSError`` around a read therefore does
   not hold it: it escapes and takes the whole caller down. This is locale-independent — any
   truncated write or binary blob triggers it on any machine. Hence :data:`TEXT_READ_ERRORS`,
   the one importable name for "what a text read can raise", so a caller that reads-and-parses
   under a single ``try`` cannot re-derive the tuple and get it wrong (#589 is exactly that
   mistake, made one directory over from a correct copy).

Lives at the ``defender.`` namespace root (no ``__init__.py`` — PEP 420
namespace package), like ``defender._frontmatter`` (see #322/#323), so it is
importable from ``learning/``, ``scripts/``, ``runtime/`` and ``hooks/`` alike —
crucially without the runtime/hooks layers taking a dependency on
``defender.learning`` (the #317 decoupling), where these helpers used to live.
Deliberately **pure stdlib at import time**, for the same reason ``_corpus.py`` is: the actor
runs the pinned lesson scripts under the *system* interpreter and only then re-execs into the
venv, and those scripts import this module.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

TEXT_READ_ERRORS: tuple[type[Exception], ...] = (OSError, UnicodeDecodeError)
"""What reading a text file can raise: unreadable (``OSError``) or undecodable
(``UnicodeDecodeError``, a ``ValueError``).

Exported as one name because the *guard* half of the bug is not fixable by a reader function.
A caller whose whole response to a bad file is "skip it" can use :func:`read_text_soft` — but a
caller that reads AND parses under one ``try`` (``iter_lessons``, the curators' yaml loads, the
invlang companion walk) must still write its own ``except``, and that is precisely where the
next wrong tuple gets written. Spell it ``except (SomeParseError, *TEXT_READ_ERRORS)`` and a
grep for this name is the audit of who guards a read correctly.
"""


def read_text_utf8(path: Path) -> str:
    """Read ``path`` as UTF-8 text. Raises :data:`TEXT_READ_ERRORS` — nothing else.

    For the caller that reads and parses under one ``try``. A caller that only wants to skip a
    bad file should use :func:`read_text_soft` instead of restating the guard.
    """
    return path.read_text(encoding="utf-8")  # lint-text-io: ok — the canonical pinned reader


def read_text_soft(path: Path) -> tuple[str | None, str | None]:
    """``(text, None)``, or ``(None, reason)`` when ``path`` can't be read OR decoded.

    The skip-one-bad-file contract, defined once. Branch on ``text is None`` (or equivalently
    ``reason is not None``) — never on ``if not text``: an empty file legitimately returns
    ``("", None)``, and treating that as a failure converts a valid read into a silent drop, the
    same class of loss this guards against. ``text is None`` is also the check that narrows the
    type for the caller.

    ``reason`` is ``str(e)`` with no prefix baked in, so a caller can frame it in its own terms
    (invlang's corpus report says ``f"read error: {reason}"``).
    """
    try:
        return read_text_utf8(path), None
    except TEXT_READ_ERRORS as e:
        return None, str(e)


def use_utf8_stdio() -> None:
    """Pin this process's stdout/stderr to UTF-8 — the WRITE half of the read's ``encoding`` pin.

    The corpora are UTF-8 and say so: 42 of the checked-in lessons carry non-ASCII today,
    em-dashes in the ``description`` above all, and the invlang companions the defender authors
    carry them too. Every corpus CLI *prints* that text, so pinning only the read leaves the
    other direction decoding under the ambient locale — and the failure is not hypothetical.
    Under the same C locale :func:`read_text_utf8`'s pin is tested against, a bare
    ``defender-lessons`` over the real corpus dies with an ascii ``UnicodeEncodeError`` on the
    tenth lesson: the defender's PLAN-time retrieval (``SKILL.md`` §Lessons) exits non-zero
    having emitted a silently truncated corpus. Same locale dependence as the read bug, one
    direction over.

    Idempotent. A stream that cannot be reconfigured (a replaced ``sys.stdout`` under pytest's
    capture) is left alone rather than raising — this is hardening, never a new failure mode.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8")


def read_jsonl_rows(path: Path) -> list[dict]:
    """All rows in a JSONL file (tolerant of blank/malformed lines).

    The single tolerant JSONL reader for the live-appended queues: a torn line
    from an interrupted append is skipped, not raised, so a drain that reads its
    queue never crashes on a half-written record.

    Pinned **lossy** — ``errors="replace"``, not :func:`read_text_utf8` — and that is not
    sloppiness: an append interrupted mid-write can tear a *multi-byte character* in half, so a
    raising pin here would crash every drain on every tick over a torn em-dash. That is #446
    again, entered from the encoding side. The mangled char becomes U+FFFD, its line then fails
    ``json.loads``, and the guard below skips it — the torn row is dropped exactly as a torn
    ascii row already is.
    """
    if not path.is_file():
        return []
    rows: list[dict] = []
    text = path.read_text(encoding="utf-8", errors="replace")  # lint-jsonl-io: ok — the canonical tolerant reader  # noqa: E501
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            rows.append(json.loads(s))
        except json.JSONDecodeError:
            continue
    return rows


def append_jsonl(path: Path, rows: list[dict]) -> int:
    """Append ``rows`` as JSON lines, creating parent dirs; return the count.

    A no-op (returns 0) on an empty ``rows`` so callers needn't guard.
    """
    if not rows:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")  # lint-jsonl-io: ok — the canonical JSONL appender
    return len(rows)


def write_atomic(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically via a sibling ``.tmp`` + ``os.replace``.

    A concurrent reader sees either the old file or the whole new one, never a
    partial write. Caller owns serialization; the replace itself is atomic on POSIX.
    The parent dir must already exist — unlike ``append_jsonl`` this does not
    ``mkdir``, since atomic-rewrite callers target a file that's already there.
    """
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
