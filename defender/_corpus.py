"""The one walk over a lesson corpus.

``iter_lessons`` is the single reader every consumer of a lesson corpus goes through: the three
``scripts/lessons/`` CLIs (which re-export it from ``_lessons_common``) and the curators' corpus
manifest (``learning/author/shared.py``). It lives in a neutral module — next to
``_frontmatter.py``, the parser it wraps — because the second consumer is not a lessons *script*
and must not have to reach sideways into ``scripts/`` to find it. (``reexec_into_venv`` →
``scripts/_venv.py`` took the same move for the same reason.)

Deliberately **pure stdlib at import time**: nothing here imports ``yaml`` — or anything
yaml-backed, ``defender._frontmatter`` above all — at module scope. The actor runs the pinned
lesson scripts as ``python3 <script>`` on its bash lane under the *system* interpreter, which has
no PyYAML; each script imports ``_lessons_common`` (and so this module) at module scope and only
then re-execs into the venv. A module-top yaml import here breaks the actor's lesson retrieval
live in the learning loop. :func:`iter_lessons` therefore imports the parser *lazily*, inside the
function body.
"""
from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from pathlib import Path


def iter_lessons(
    corpus_dir: Path,
    *,
    with_raw: bool = False,
    warn_label: Callable[[Path], str] | None = None,
) -> Iterator[tuple]:
    """Yield well-formed lessons under ``corpus_dir``: ``*.md`` sorted, skipping
    ``_``-prefixed files, warning-and-skipping on a malformed one.

    Yields ``(path, frontmatter)`` by default, or ``(path, raw_frontmatter, fm)``
    when ``with_raw`` (the raw YAML between the fences, for frontmatter grep).
    ``warn_label`` formats the skipped path in the warning (default ``path.name``;
    the actor index passes a repo-relative label, the corpus manifest names its stage).
    The yaml-backed parser is imported lazily so this module stays importable before
    the venv re-exec.

    Sorted by full path, not by stem — the two keys diverge when one stem is a prefix of
    another (``cover-prereqs.md`` < ``cover.md`` by name; the reverse by stem), and this order
    is LLM-visible: the CLIs stream it straight to the actor and the manifest renders it for the
    curator. It is stable across reruns, which is the property that matters; a stem re-sort to
    serve one consumer would silently reorder the others.

    "Malformed" covers the READ as well as the PARSE, so ``read_text()`` is inside the
    ``try``: it raises ``UnicodeDecodeError`` on undecodable bytes, which is a ``ValueError``
    and NOT an ``OSError`` — outside the guard it would escape and take the whole caller down
    (the actor's ``lessons_actor_index`` / ``lessons_env_retrieve`` run this on their bash lane
    mid-run), defeating the skip-one-bad-file contract this function exists to provide.
    """
    from defender._frontmatter import FrontmatterError, parse_frontmatter

    label = warn_label or (lambda p: p.name)
    if not corpus_dir.is_dir():
        return
    for path in sorted(corpus_dir.glob("*.md")):
        if path.name.startswith("_"):
            continue
        try:
            text = path.read_text()
            fm, _body = parse_frontmatter(text)
        except (FrontmatterError, OSError, UnicodeDecodeError) as e:
            print(f"warn: skipping {label(path)} (malformed lesson: {e})", file=sys.stderr)
            continue
        if with_raw:
            norm = text.replace("\r\n", "\n").replace("\r", "\n")
            raw = norm[4:norm.find("\n---", 4)]  # YAML between the fences
            yield path, raw, fm
        else:
            yield path, fm
