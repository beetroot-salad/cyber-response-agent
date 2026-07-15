"""The one walk over a lesson corpus — and the one walk over the query-template corpus.

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

:func:`iter_query_templates` is the same contract one corpus over: the single walk over
``skills/gather/queries/``. It lives here rather than in ``learning/`` because ``runtime/`` reads
this corpus too (the gather dispatch index) and may not import ``defender.learning.*`` (#575), and
because there were three partial walks of it at HEAD. It inherits both rules above verbatim — the
parser import is lazy, and the read goes through ``read_text_utf8`` under ``TEXT_READ_ERRORS``.
"""
from __future__ import annotations

import re
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
    on_skip: Callable[[Path], None] | None = None,
) -> Iterator[Lesson]:
    """Yield a :class:`Lesson` per well-formed lesson under ``corpus_dir``: ``*.md`` sorted,
    skipping ``_``-prefixed files, warning-and-skipping on a malformed one.

    One shape, always populated: ``raw`` and ``body`` are slices of text already read, so
    materializing them unconditionally is free and there is no flag to get wrong.
    ``warn_label`` formats the skipped path in the warning (default ``path.name``; the actor index
    passes a repo-relative label, the curators name their stage). ``on_skip`` (when given)
    receives each warn-skipped path, in walk order — the seam for a consumer that must account
    for every DISCOVERED lesson rather than silently losing the skipped ones (#590:
    ``trace_lesson --all``'s marker rows). It reports from the same single walk, so there is no
    second glob for a consumer to race against. The yaml-backed parser is
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

    malformed: tuple[type[BaseException], ...] = (FrontmatterError, *TEXT_READ_ERRORS)
    label = warn_label or (lambda p: p.name)
    for path in iter_lesson_paths(corpus_dir):
        try:
            text = read_text_utf8(path)
            fm, raw, body = split_frontmatter(text)
        except malformed as e:
            print(f"warn: skipping {label(path)} (malformed lesson: {e})", file=sys.stderr)
            if on_skip is not None:
                on_skip(path)
            continue
        yield Lesson(path=path, fm=fm, raw=raw, body=body)


# ---------------------------------------------------------------------------
# The query-template corpus
# ---------------------------------------------------------------------------

# Matched per LINE, never with re.MULTILINE over the whole body — the fence state (see
# `_sections`) is what decides whether a `## ` line is a heading at all, and a whole-body sweep
# has no way to know it.
_HEADING_RE = re.compile(r"^## (.+)$")
_FENCE_RE = re.compile(r"^(?:```|~~~)")


@dataclass(frozen=True)
class QueryTemplate:
    """One well-formed query template: its file, its identity, the two section bodies every
    consumer reads, and the whole markdown body they were sliced out of.

    ``body`` is the full post-frontmatter markdown — every section, not just the two named ones.
    A template carries more prose than ``Goal`` + ``Query``: ``## What to summarize`` is on 54 of
    the 63 in the corpus, and the ``## Pitfalls`` / ``## Filter binding`` sections on ~30 more, all
    of it exactly the concrete-artifact vocabulary ``SCHEMA.md`` tells authors to write for keyword
    recall. A searcher that reads only the two parsed sections would report "no template's text
    carries that text" about text a template plainly carries (see
    ``tools_gather._tool_template_search``), which is the same coin-a-duplicate failure as an
    empty return.

    ``status`` is the frontmatter value verbatim when it is a non-empty string, and ``""`` when the
    key is absent or empty — NOT ``"established"``. The pre-fold walk defaulted it with
    ``fm.get("status") or "established"``, an ``or`` mis-fire on a valid-falsy value (the very shape
    ``defender/CLAUDE.md``'s anchor-a-default rule bans), which silently PROMOTED a draft skeleton
    that had lost its frontmatter key. Absent status is unknown status; a consumer that admits only
    established templates must say so positively (see ``tools_gather._template_index``, which
    additionally requires the file to sit outside ``_draft/`` — the field and the location must
    agree, and they fail closed when they don't).
    """

    path: Path
    id: str
    system: str
    status: str
    goal: str
    query: str
    body: str


def section_bodies(body: str) -> dict[str, str]:
    """The ``## Heading`` → body map of a template's markdown, headings stripped.

    Public because it has two consumers: the walk below, and ``learning/leads/lead_render.py``,
    which renders a template's ``## Query`` for the lead author. That one carried its own
    fence-blind copy of this parse until #598 — the same defect, one file over. One parser, so a
    fix lands once.

    A heading is only a heading OUTSIDE a fenced code block (#598). Every template's ``## Query``
    is a fence, and a query body is free to contain a line that starts with ``## `` — a shell or
    ES|QL comment, an embedded markdown snippet, a ``#``-prefixed literal inside a string. A
    regex sweep for ``^## `` treats that line as the next section, which does two things at once:
    it TRUNCATES ``## Query`` at the comment, and it invents a section named after whatever
    followed. Both are silent. The truncated body is the one gather reads before it binds
    ``query_id``, and the ``(query_id, params)`` join keys on templates gather says it reused —
    so a half-read query corrupts the join rather than failing loudly.

    No template in the shipped corpus trips this today; the guard is here because the fold (#585)
    put this parser on the runtime dispatch path, where it now runs on every gather dispatch.
    """
    heads: list[tuple[str, int, int]] = []   # (name, heading start, content start)
    pos = 0
    fenced = False
    for line in body.splitlines(keepends=True):
        if _FENCE_RE.match(line.lstrip()):
            fenced = not fenced
        elif not fenced and (m := _HEADING_RE.match(line)):
            heads.append((m.group(1).strip(), pos, pos + len(line)))
        pos += len(line)

    out: dict[str, str] = {}
    for i, (name, _start, content) in enumerate(heads):
        end = heads[i + 1][1] if i + 1 < len(heads) else len(body)
        out[name] = body[content:end].strip()
    return out


def iter_query_templates(catalog_dir: Path) -> Iterator[QueryTemplate]:
    """Yield a :class:`QueryTemplate` per well-formed template under ``catalog_dir`` —
    established ones at ``{system}/*.md`` and drafts at ``{system}/_draft/*.md`` — sorted by full
    path, warning-and-skipping on a malformed one.

    ``catalog_dir`` is READ AS GIVEN: there is no ``None`` overload and no ``PATHS`` fallback
    resolved behind the caller's back. ``evals/harness_lead.py`` materializes a tmp tree, copies
    the real catalog into it, overlays the scenario's ``catalog_overlay/`` on top and re-execs the
    lead author against THAT tree — a walk that reached for a module-level root would silently
    score the eval against the real repo's corpus and ignore the overlay entirely. The runtime's
    index has the same requirement one tree over (``deps.defender_dir``, so a worktree run indexes
    its own catalog).

    Skip-one-bad-file, exactly as :func:`iter_lessons`: the read is INSIDE the ``try`` (an
    undecodable byte raises ``UnicodeDecodeError``, a ``ValueError`` and not an ``OSError``), and a
    file with no ``id:`` is a skip with a warning rather than a silent drop. The pre-fold walk read
    outside its ``try`` and dropped an id-less file silently, which was survivable while it only ran
    in an offline drain. This one runs on EVERY gather dispatch, so one bad byte among the 63
    templates would otherwise take down every dispatch in the run.
    """
    from defender._frontmatter import FrontmatterError, parse_frontmatter

    # The read goes through `read_text_utf8` under `TEXT_READ_ERRORS` — the one text-IO contract
    # (#589), named rather than restated: an undecodable template raises `UnicodeDecodeError`,
    # which is a `ValueError` and NOT an `OSError`, so an `except OSError` would let it escape and
    # take the whole dispatch down instead of skipping the one bad file.
    malformed: tuple[type[BaseException], ...] = (FrontmatterError, *TEXT_READ_ERRORS)

    if not catalog_dir.is_dir():
        return
    paths = sorted(
        list(catalog_dir.glob("*/*.md")) + list(catalog_dir.glob("*/_draft/*.md"))
    )
    for path in paths:
        try:
            fm, body = parse_frontmatter(read_text_utf8(path))
        except malformed as e:
            print(f"warn: skipping {path.name} (malformed template: {e})", file=sys.stderr)
            continue
        tid = fm.get("id")
        if not tid or not isinstance(tid, str):
            print(f"warn: skipping {path.name} (malformed template: no `id:`)", file=sys.stderr)
            continue
        status = fm.get("status")
        sections = section_bodies(body)
        # A draft's system dir is the GRANDparent — it sits under `{system}/_draft/`.
        parent = path.parent
        system = parent.parent.name if parent.name == "_draft" else parent.name
        yield QueryTemplate(
            path=path,
            id=tid,
            system=system,
            status=status if isinstance(status, str) else "",
            goal=sections.get("Goal", ""),
            query=sections.get("Query", ""),
            body=body,
        )
