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

    path: Path
    fm: dict[str, Any]
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
            print(f"warn: skipping {label(path)} (malformed lesson: {e})", file=sys.stderr)
            if on_skip is not None:
                on_skip(path)
            continue
        yield Lesson(path=path, fm=fm, raw=raw, body=body)



_HEADING_RE = re.compile(r"^## (.+)$")
_FENCE_RE = re.compile(r"^(?:```|~~~)")


@dataclass(frozen=True)
class QueryTemplate:

    path: Path
    id: str
    system: str
    status: str
    goal: str
    query: str
    body: str
    verb: str = ""
    #: The two DECLARATION keys `SCHEMA.md` defines alongside `verb:` — the params the verb
    #: declares, and the `${name}`s that are query-language body text rather than params. They
    #: ride on the one corpus walk for the same reason `verb` does: the scaffold rules
    #: (`_scaffold_rules`) are the only reader that needs them, and a second frontmatter parse
    #: in each caller is how the two enforcement copies of one rule drifted apart (#901).
    params: tuple[str, ...] = ()
    body_substitutions: tuple[str, ...] = ()


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
    """A frontmatter declaration list, normalized to names. A shape that is not a sequence
    declares NOTHING rather than raising — the same tolerance `validate_scaffold` already read
    `body_substitutions:` with, kept deliberately because it fails in the safe direction: a
    declaration the walk cannot read narrows the allowed set, so the placeholder rule refuses
    the template rather than waving it through."""
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value if isinstance(v, (str, int, float)))
    return ()


def read_query_template(path: Path) -> tuple[QueryTemplate | None, str]:
    """One template file, as `(template, reason)` — `reason` empty on success, else why the file
    is not a template.

    Split out of the walk so a caller holding ONE path (the loop's commit gate, which is handed
    changed paths by git and not a directory to walk) reads it through the same parser the
    corpus does. Returning the reason rather than printing it is what lets that caller refuse a
    commit *with* the reason; `iter_query_templates` keeps the warn-and-skip behavior its
    readers depend on."""
    from defender._frontmatter import FrontmatterError, parse_frontmatter

    malformed: tuple[type[BaseException], ...] = (FrontmatterError, *TEXT_READ_ERRORS)
    try:
        fm, body = parse_frontmatter(read_text_utf8(path))
    except malformed as e:
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
        body=body,
        verb=verb if isinstance(verb, str) else "",
        params=_declared_names(fm.get("params")),
        body_substitutions=_declared_names(fm.get("body_substitutions")),
    ), ""


def iter_query_templates(catalog_dir: Path) -> Iterator[QueryTemplate]:
    if not catalog_dir.is_dir():
        return
    paths = sorted(
        list(catalog_dir.glob("*/*.md")) + list(catalog_dir.glob("*/_draft/*.md"))
    )
    for path in paths:
        template, reason = read_query_template(path)
        if template is None:
            print(f"warn: skipping {path.name} ({reason})", file=sys.stderr)
            continue
        yield template
