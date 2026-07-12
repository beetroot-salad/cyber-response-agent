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
"""
from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Lesson:
    """One well-formed lesson: the file, its parsed frontmatter, the raw YAML between the fences,
    and the body after them.

    Deliberately **not** a ``NamedTuple``. ``raw`` was the middle *element* of the old
    ``(path, raw, fm)`` tuple and ``fm`` is the middle *field* here, so an unpackable Lesson would
    let an un-migrated ``for path, raw, fm in iter_lessons(...)`` keep running while silently
    binding ``raw <- fm``: ``cmd_tags`` would ``.get()`` on a string and report wrong counts with
    nothing raising. A missed call site must fail loud instead.

    Frozen because the four fields are a *read* of a file on disk: a consumer that mutated ``fm``
    in place would corrupt what the next consumer of the same walk sees.
    """

    path: Path
    fm: dict[str, Any]
    raw: str
    body: str


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

    The read pins ``encoding="utf-8"``. A bare ``read_text()`` decodes under the *ambient* locale,
    so on a C-locale box a valid UTF-8 lesson containing ``café`` raises an ascii
    ``UnicodeDecodeError``, is warn-skipped by the guard below, and vanishes from the actor's
    retrieval and the curator's manifest — silent data loss dressed up as a malformed lesson, and
    invisible on a UTF-8 dev machine.

    "Malformed" covers the READ as well as the PARSE, so the read is inside the ``try``: it raises
    ``UnicodeDecodeError`` on undecodable bytes, which is a ``ValueError`` and NOT an ``OSError``
    — outside the guard it would escape and take the whole caller down (the actor's
    ``lessons_actor_index`` / ``lessons_env_retrieve`` run this on their bash lane mid-run),
    defeating the skip-one-bad-file contract this function exists to provide.
    """
    from defender._frontmatter import FrontmatterError, parse_frontmatter

    label = warn_label or (lambda p: p.name)
    if not corpus_dir.is_dir():
        return
    for path in sorted(corpus_dir.glob("*.md")):
        if path.name.startswith("_"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
            fm, body = parse_frontmatter(text)
        except (FrontmatterError, OSError, UnicodeDecodeError) as e:
            print(f"warn: skipping {label(path)} (malformed lesson: {e})", file=sys.stderr)
            continue
        norm = text.replace("\r\n", "\n").replace("\r", "\n")
        raw = norm[4:norm.find("\n---", 4)]  # the YAML the parser consumed, between the fences
        yield Lesson(path=path, fm=fm, raw=raw, body=body)
