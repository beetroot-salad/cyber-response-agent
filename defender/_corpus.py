from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

from defender._io import TEXT_READ_ERRORS, read_text_utf8
from defender._model import model

_logger = logging.getLogger(__name__)


#: A lesson's bookkeeping keys — provenance, not content. Shared by every surface that renders
#: lesson frontmatter for a model, so none leaks bookkeeping the others drop.
PROVENANCE_KEYS = frozenset(
    {"source_finding_ids", "source_observation_ids", "created_at", "recorded_at"}
)


@model(frozen=True)
class Lesson:

    path: Path
    #: Keys `Any`: YAML builds non-`str` keys, and a `str` claim would raise a `ValidationError`
    #: that `iter_lessons`' warn-and-skip does not catch.
    fm: dict[Any, Any]
    raw: str
    body: str


def iter_lesson_paths(corpus_dir: Path) -> list[Path]:
    if not corpus_dir.is_dir():
        return []
    return [p for p in sorted(corpus_dir.glob("*.md")) if not p.name.startswith("_")]


def iter_lessons(
    corpus_dir: Path,
    *,
    warn_label: Callable[[Path], str] | None = None,
    on_skip: Callable[[Path], None] | None = None,
) -> Iterator[Lesson]:
    from defender._frontmatter import FrontmatterError, split_frontmatter

    malformed: tuple[type[BaseException], ...] = (FrontmatterError, *TEXT_READ_ERRORS)
    label = warn_label or (lambda p: p.name)
    for path in iter_lesson_paths(corpus_dir):
        try:
            text = read_text_utf8(path)
            fm, raw, body = split_frontmatter(text)
        except malformed as e:
            _logger.warning(f"warn: skipping {label(path)} (malformed lesson: {e})")
            if on_skip is not None:
                on_skip(path)
            continue
        yield Lesson(path=path, fm=fm, raw=raw, body=body)



_HEADING_RE = re.compile(r"^## (.+)$")
_FENCE_RE = re.compile(r"^(?:```|~~~)")


@model(frozen=True)
class QueryTemplate:

    path: Path
    id: str
    system: str
    status: str
    goal: str
    query: str
    body: str
    verb: str = ""
    #: The declaration keys `SCHEMA.md` defines alongside `verb:`: the verb's params, and the
    #: `${name}`s that are query-language body text rather than params.
    params: tuple[str, ...] = ()
    body_substitutions: tuple[str, ...] = ()
    #: Every coined `query_id` this template accounts for — the `covers:` key. Lets
    #: `synthesize_drafts` treat those ids as answered (so a draft is not re-minted each time a
    #: run coins the same id), and lets the commit gate match a deleted draft to the template
    #: that absorbed it.
    covers: tuple[str, ...] = ()
    #: A draft's `## Executed query` — the verbatim recording of the call that minted it. Kept
    #: out of `query`: a `## Query`'s `${name}`s are placeholders checked against the verb's
    #: params, while every `${…}` in a recording was sent literally.
    recording: str = ""


def is_established(t: QueryTemplate) -> bool:
    """Is `t` in the catalog's established tier — `status: established` and not under `_draft/`?

    A file where location and status disagree is in neither tier. Shared by the gather
    template index and lead zero's run-start check so they cannot disagree.
    """
    return t.status == "established" and "_draft" not in t.path.parts


def section_bodies(body: str) -> dict[str, str]:
    heads: list[tuple[str, int, int]] = []
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


def _declared_names(value: Any) -> tuple[str, ...]:
    """A frontmatter declaration list, normalized to names.

    Accepts a sequence, a mapping, a sequence of single-key mappings, or a bare scalar — all
    natural spellings, and dropping any would leave a declaration unenforced or refuse a name
    the author did declare. Any other shape declares nothing rather than raising, so one
    malformed key cannot sink the corpus walk.
    """
    if isinstance(value, Mapping):
        return tuple(str(k) for k in value)
    if isinstance(value, str):
        # Before the sequence branch: a `str` is iterable and would yield one name per character.
        return (value,)
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for v in value:
            if isinstance(v, Mapping):
                out.extend(str(k) for k in v)
            elif isinstance(v, str):
                out.append(v)
            elif isinstance(v, (int, float)):
                # Includes `bool`: YAML reads unquoted `on`/`yes`/`no` as booleans. Keeping
                # `"True"` makes `check_template` report it, telling the author their name was
                # coerced instead of silently dropping the declaration.
                out.append(str(v))
        return tuple(out)
    if isinstance(value, (int, float)):
        # Scalar form of the above: `params: on` arrives as `True`.
        return (str(value),)
    return ()


def read_query_template(path: Path) -> tuple[QueryTemplate | None, str]:
    """One template file, as `(template, reason)` — `reason` empty on success, else why the file
    is not a template.

    For callers holding one path (the commit gate), which need the reason to refuse with."""
    try:
        text = read_text_utf8(path)
    except TEXT_READ_ERRORS as e:
        return None, f"malformed template: {e}"
    return parse_query_template(text, path)


def parse_query_template(text: str, path: Path) -> tuple[QueryTemplate | None, str]:
    """`read_query_template` for content already in hand (e.g. a deleted draft's pre-image from
    `git show HEAD:…`); `path` supplies only location facts (system, `path` field)."""
    from defender._frontmatter import FrontmatterError, parse_frontmatter

    try:
        fm, body = parse_frontmatter(text)
    except FrontmatterError as e:
        return None, f"malformed template: {e}"
    tid = fm.get("id")
    if not tid or not isinstance(tid, str):
        return None, "malformed template: no `id:`"
    status = fm.get("status")
    sections = section_bodies(body)
    parent = path.parent
    system = parent.parent.name if parent.name == "_draft" else parent.name
    verb = fm.get("verb")
    return QueryTemplate(
        path=path,
        id=tid,
        system=system,
        status=status if isinstance(status, str) else "",
        goal=sections.get("Goal", ""),
        query=sections.get("Query", ""),
        recording=sections.get("Executed query", ""),
        body=body,
        verb=verb if isinstance(verb, str) else "",
        params=_declared_names(fm.get("params")),
        body_substitutions=_declared_names(fm.get("body_substitutions")),
        # `_declared_names` for its shape tolerance (e.g. a bare `covers: cmdb.network-map`).
        covers=_declared_names(fm.get("covers")),
    ), ""


def query_catalog_dir(defender_dir: Path) -> Path:
    """The query catalog of the tree at `defender_dir`."""
    return Path(defender_dir) / "skills" / "gather" / "queries"


def iter_query_templates(catalog_dir: Path) -> Iterator[QueryTemplate]:
    if not catalog_dir.is_dir():
        return
    paths = sorted(
        list(catalog_dir.glob("*/*.md")) + list(catalog_dir.glob("*/_draft/*.md"))
    )
    for path in paths:
        template, reason = read_query_template(path)
        if template is None:
            _logger.warning(f"warn: skipping {path.name} ({reason})")
            continue
        yield template
