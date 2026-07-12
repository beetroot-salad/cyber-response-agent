"""The one walk over a lesson corpus.

``iter_lessons`` is the single reader every consumer of a lesson corpus goes through: the three
``scripts/lessons/`` CLIs (which re-export it from ``_lessons_common``), the curators' corpus
manifest and id pre-flights (``learning/author/``), the lessons frontend (``learning/frontend/
serialize.py``) and the ops traceability CLI (``learning/ops/trace_lesson.py --all``). It lives in
a neutral module — next to ``_frontmatter.py``, the parser it wraps — because those consumers are
not lessons *scripts* and must not have to reach sideways into ``scripts/`` to find it.
(``reexec_into_venv`` → ``scripts/_venv.py`` took the same move for the same reason.)

Deliberately **pure stdlib at import time**: nothing here imports ``yaml`` — or anything
yaml-backed, ``defender._frontmatter`` above all — at module scope. The actor runs the pinned
lesson scripts as ``python3 <script>`` on its bash lane under the *system* interpreter, which has
no PyYAML; each script imports ``_lessons_common`` (and so this module) at module scope and only
then re-execs into the venv. A module-top yaml import here breaks the actor's lesson retrieval
live in the learning loop. :func:`iter_lessons` therefore imports the parser *lazily*, inside the
function body — and :class:`Lesson` is a plain stdlib dataclass for the same reason.
(``defender._io``, imported at module scope below, is pure stdlib for exactly this reason and
must stay that way; the text-IO contract it owns — the utf-8 pin and the guard that holds it —
is not lesson-specific and lives there, not here.)
"""
from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._io import TEXT_READ_ERRORS, read_text_utf8


@dataclass(frozen=True)
class Lesson:
    """One well-formed lesson: the file, its parsed frontmatter, the raw YAML between the fences,
    and the body after them.

    Deliberately **not** a ``NamedTuple``. ``raw`` was the middle *element* of the old
    ``(path, raw, fm)`` tuple and ``fm`` is the middle *field* here, so an unpackable Lesson would
    let an un-migrated ``for path, raw, fm in iter_lessons(...)`` keep running while silently
    binding ``raw <- fm``: ``cmd_tags`` would ``.get()`` on a string and report wrong counts with
    nothing raising. A missed call site must fail loud instead.

    Frozen to say the record is a *read* of a file on disk, not a workspace: rebinding a field is
    a bug, so it raises. Note the freeze is SHALLOW and cannot be otherwise — ``fm`` is a plain
    ``dict`` and ``lesson.fm["k"] = v`` still mutates it. That is not the hazard it looks like:
    :func:`iter_lessons` re-reads and re-parses on every call, so each walk hands out its own
    freshly-parsed ``fm`` and no dict is shared between consumers. A consumer that wants to keep a
    mutated copy should ``dict(lesson.fm)`` and own it.
    """

    path: Path
    fm: dict[str, Any]
    raw: str
    body: str


def iter_lesson_paths(corpus_dir: Path) -> list[Path]:
    """The corpus DISCOVERY rule on its own: ``*.md`` sorted by full path, ``_``-prefixed skipped.

    Split out of :func:`iter_lessons` because a second caller needs the file set *before* any
    parse: the curators' observation-id pre-flight stats these paths to build its mtime cache
    signature (``learning/author/curator.py``). It used to restate the rule inline, which is
    exactly the drift this module exists to prevent — and the drift is one-directionally
    dangerous. If the signature ever sees FEWER files than the walk, a modified lesson leaves the
    cache stale, an already-consumed observation id reads as unconsumed, and the curator authors a
    duplicate of a lesson it cannot see. One definition, two consumers.

    Discovery only: a path coming back from here is a *candidate*. It may still be unreadable or
    malformed — that is the walk's business, not this rule's.
    """
    if not corpus_dir.is_dir():
        return []
    return [p for p in sorted(corpus_dir.glob("*.md")) if not p.name.startswith("_")]


def iter_lessons(
    corpus_dir: Path,
    *,
    warn_label: Callable[[Path], str] | None = None,
) -> Iterator[Lesson]:
    """Yield a :class:`Lesson` per well-formed lesson under ``corpus_dir``: ``*.md`` sorted,
    skipping ``_``-prefixed files, warning-and-skipping on a malformed one.

    One shape, always populated: ``raw`` and ``body`` are slices of text already read, so
    materializing them unconditionally is free and there is no flag to get wrong.
    ``warn_label`` formats the skipped path in the warning (default ``path.name``; the actor index
    passes a repo-relative label, the curators name their stage). The yaml-backed parser is
    imported lazily so this module stays importable before the venv re-exec.

    Sorted by full path, not by stem — the two keys diverge when one stem is a prefix of
    another (``cover-prereqs.md`` < ``cover.md`` by name; the reverse by stem), and this order
    is LLM-visible: the CLIs stream it straight to the actor and the manifest renders it for the
    curator. It is stable across reruns, which is the property that matters; a stem re-sort to
    serve one consumer would silently reorder the others.

    The read goes through :func:`defender._io.read_text_utf8`, which pins ``encoding="utf-8"``. A
    bare ``read_text()`` decodes under the *ambient* locale, so where the interpreter's encoding
    really is ascii a valid UTF-8 lesson containing ``café`` raises an ascii ``UnicodeDecodeError``,
    is warn-skipped by the guard below, and vanishes from the actor's retrieval and the curator's
    manifest — silent data loss dressed up as a malformed lesson, and invisible on a UTF-8 dev
    machine.

    Be precise about the trigger, because a reader who cannot reproduce it will conclude the pin is
    cosmetic and drop it: a *bare* ``LC_ALL=C`` does NOT reproduce it. CPython >= 3.7 coerces the C
    locale to C.UTF-8 (PEP 538) whenever that locale exists, as it does in this repo's runtime
    image, and UTF-8 mode (PEP 540) covers the rest. The pin is therefore latent hardening for the
    images where coercion cannot fire — which is exactly why ``test_d5`` has to disable
    ``PYTHONCOERCECLOCALE`` and ``PYTHONUTF8`` to drive it. See
    :func:`defender._io.use_utf8_stdio` for the matching pin on the WRITE side, without which this
    one only moves the crash downstream.

    "Malformed" covers the READ as well as the PARSE, so the read is inside the ``try``, and the
    guard names ``TEXT_READ_ERRORS`` rather than restating it: an undecodable lesson raises
    ``UnicodeDecodeError``, which is a ``ValueError`` and NOT an ``OSError``, so an ``except
    OSError`` would let it escape and take the whole caller down (the actor's
    ``lessons_actor_index`` / ``lessons_env_retrieve`` run this on their bash lane mid-run),
    defeating the skip-one-bad-file contract this function exists to provide. That is not a
    hypothetical: #589 is a hand-rolled copy of this guard, one directory over, that caught only
    ``OSError``.
    """
    from defender._frontmatter import FrontmatterError, split_frontmatter

    label = warn_label or (lambda p: p.name)
    for path in iter_lesson_paths(corpus_dir):
        try:
            text = read_text_utf8(path)
            fm, raw, body = split_frontmatter(text)
        except (FrontmatterError, *TEXT_READ_ERRORS) as e:
            print(f"warn: skipping {label(path)} (malformed lesson: {e})", file=sys.stderr)
            continue
        yield Lesson(path=path, fm=fm, raw=raw, body=body)
