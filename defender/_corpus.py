from __future__ import annotations

import contextlib
import errno
import logging
import os
import re
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path, PurePath
from typing import Any, TypeAlias

from defender._io import ENTRY_OTHER, Bound, bind
from defender._model import model
from defender._tree_listing import TreeListing, list_tree

_logger = logging.getLogger(__name__)

#: The skip reason of a `<sys>` or `_draft` catalog entry the listing showed as no real
#: directory (a link, a FIFO, a socket): never entered. One whose own listing was refused is
#: skipped with that listing's reason instead, verbatim.
_NOT_A_PLAIN_FOLDER = "not a plain folder"


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


#: What every shared reader takes as its tree (#1134 A4): a `Bound` the caller holds, or a `Path`.
#: Drain code passes its held mount's view — `corpus.view()`, `skills.view().under("gather/queries")`
#: — with `where=`, the Path that folder is spelled as. A `Path` is opened here with `bind(path)`
#: and closed again (N-h's call shape, for callers outside the drain); it roots wherever it points,
#: following its own spelling, so drain code never passes one (D6).
Tree: TypeAlias = "Bound | Path"


def _spelled(tree: Tree, where: Path | None) -> Path:
    """The Path `tree`'s folder is spelled as: `where` for a `Bound` (which has no path; required),
    the Path itself otherwise (which takes no `where`). Opens nothing."""
    if isinstance(tree, Bound):
        if where is None:
            raise ValueError("a Bound has no path: pass where=, the folder it is spelled as")
        return Path(where)
    if where is not None:
        raise ValueError("where= spells a Bound; a Path spells itself")
    return Path(tree)


@contextlib.contextmanager
def _viewed(tree: Tree) -> Iterator[Bound]:
    """`tree` as a view: a `Bound` as given (the caller's, never closed here), a `Path` bound
    here and closed on leaving."""
    if isinstance(tree, Bound):
        yield tree
        return
    with bind(Path(tree)) as view:
        yield view


def _listed(view: Bound, where: Path, *, depth: int) -> TreeListing:
    """`list_tree(view, depth=…)`, the tree's fixed shape (#1134 addendum 2, B2). Absent is
    silent, as a missing folder always was. A refused top — a linked or non-directory folder,
    an unreadable one — logs one skip naming `where`; either way `entries` is then `None`, and
    the tree reads as a missing one (#1134 O5.5). What a refused or gone folder below the top
    costs is the selection's to say."""
    listed = list_tree(view, depth=depth)
    if listed.reason is not None:
        _logger.warning(f"warn: skipping {where} ({listed.reason})")
    return listed


def _read_text(view: Bound, name: str, path: Path) -> tuple[str | None, str]:
    """The text of the plain file at `name` below `view` (`""` reason), or `(None, reason)`: a
    refusal's path-free reason (a link, hard link or non-plain entry is never read through), or,
    for a file gone since it was listed, today's `FileNotFoundError` words for `path`."""
    rec = view.read(name)
    if rec.text is not None:
        return rec.text, ""
    if rec.absent:
        return None, str(FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(path)))
    return None, rec.reason or ""


def _lesson_names(view: Bound, where: Path) -> list[str]:
    """Every `*.md` directly in the corpus not named `_…`, by name whatever stands there (a link
    or a directory is listed, and refused when read), in path order. The corpus is flat: one
    level is listed, and no folder in it is ever entered."""
    return [name for name in _listed(view, where, depth=1).entries or {}
            if name.endswith(".md") and not name.startswith("_")]


def iter_lesson_paths(corpus: Tree, *, where: Path | None = None) -> list[Path]:
    """The corpus' lesson files — every `*.md` directly in it whose name does not start `_` —
    sorted, each spelled `<where>/<name>` (see `Tree`; for a `Path`, today's spelling). Selected
    by name whatever stands there. An absent corpus lists nothing; a refused one is warned and
    lists nothing."""
    spelled = _spelled(corpus, where)
    with _viewed(corpus) as view:
        return [spelled / name for name in _lesson_names(view, spelled)]


def iter_lessons(
    corpus: Tree,
    *,
    where: Path | None = None,
    warn_label: Callable[[Path], str] | None = None,
    on_skip: Callable[[Path], None] | None = None,
) -> Iterator[Lesson]:
    """Each lesson `iter_lesson_paths` lists, read through the view (never through a link) and
    parsed, `path` spelled as there. One that cannot be read or parsed is warned
    (`warn_label(path)`, else its name), handed to `on_skip`, and skipped. A `Path` corpus is
    bound when iteration starts and closed when it ends or the iterator is closed."""
    spelled = _spelled(corpus, where)
    return _lessons(corpus, spelled, warn_label or (lambda p: p.name), on_skip)


def _lessons(corpus: Tree, spelled: Path, label: Callable[[Path], str],
             on_skip: Callable[[Path], None] | None) -> Iterator[Lesson]:
    from defender._frontmatter import FrontmatterError, split_frontmatter

    with _viewed(corpus) as view:
        for name in _lesson_names(view, spelled):
            path = spelled / name
            text, reason = _read_text(view, name, path)
            if text is not None:
                try:
                    fm, raw, body = split_frontmatter(text)
                except FrontmatterError as e:
                    reason = str(e)
                else:
                    yield Lesson(path=path, fm=fm, raw=raw, body=body)
                    continue
            _logger.warning(f"warn: skipping {label(path)} (malformed lesson: {reason})")
            if on_skip is not None:
                on_skip(path)



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


def read_query_template(
    source: Tree, name: str | PurePath | None = None, *, where: Path | None = None,
) -> tuple[QueryTemplate | None, str]:
    """One template file, as `(template, reason)` — `reason` empty on success, else why the file
    is not a template. A link, hard link or anything but a plain file at the name is refused,
    never followed. For callers holding one name (the commit gate), which need the reason.

    `read_query_template(view, name, where=…)`: the template at `name` below the `Bound` `view`
    (its `read` grammar), spelled `where / name` — the drain's form, e.g. `(skills.view(),
    "gather/queries/<sys>/x.md", where=skills_dir)`. `read_query_template(path)`: today's form,
    `path.name` read under `bind(path.parent)` (rooted there, following that spelling, so never
    from drain code)."""
    if isinstance(source, Bound):
        if name is None:
            raise ValueError("read_query_template(view, name, where=…): a Bound needs the name")
        spelled = _spelled(source, where)
        spelling = name.as_posix() if isinstance(name, PurePath) else name
        return _template_at(source, spelling, spelled / spelling)
    if name is not None:
        raise ValueError("read_query_template(path): a Path names its own file")
    _spelled(source, where)  # a Path spells itself: `where=` is refused
    path = Path(source)
    if path.name in ("", ".."):  # no file name to read (`/`, `.`, `x/..`): a folder, as today
        folder = IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), str(path))
        return None, f"malformed template: {folder}"
    with bind(path.parent) as view:
        return _template_at(view, path.name, path)


def _template_at(view: Bound, name: str, path: Path) -> tuple[QueryTemplate | None, str]:
    text, reason = _read_text(view, name, path)
    if text is None:
        return None, f"malformed template: {reason}"
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


def _template_names(view: Bound, where: Path) -> list[str]:
    """The catalog's template names, `<sys>/*.md` and `<sys>/_draft/*.md`, by name whatever
    stands there, in path order, from one listing of the catalog's fixed shape (three levels).
    A `<sys>` or `<sys>/_draft` entry that is not a real directory (a link, a FIFO) is never
    entered and is warned, and so is one whose own listing was refused (with that listing's
    reason); every other system still yields. One found gone by its own listing — removed since
    the folder above was listed — is passed over silently, as a missing folder always was. A
    plain file there is passed over silently, as `SCHEMA.md` is. A folder the selection never
    takes from is never warned, whatever its listing said."""
    listed = _listed(view, where, depth=3)
    names: list[str] = []
    for name, kind in (listed.entries or {}).items():
        parts = name.split("/")
        if parts[-1].endswith(".md") and (
                len(parts) == 2 or (len(parts) == 3 and parts[1] == "_draft")):
            names.append(name)
        elif len(parts) == 1 or (len(parts) == 2 and parts[1] == "_draft"):
            if kind == ENTRY_OTHER:
                _logger.warning(f"warn: skipping {where / name} ({_NOT_A_PLAIN_FOLDER})")
            elif name in listed.refused:
                _logger.warning(f"warn: skipping {where / name} ({listed.refused[name]})")
    return names


def iter_query_templates(catalog: Tree, *, where: Path | None = None) -> Iterator[QueryTemplate]:
    """Every template of the catalog (see `_template_names`), in path order, `path` spelled
    `<where>/<name>` (see `Tree`). One that cannot be read or parsed is warned and skipped; an
    absent catalog yields nothing, a refused one is warned and yields nothing. A `Path` catalog
    is bound when iteration starts and closed when it ends or the iterator is closed."""
    return _templates(catalog, _spelled(catalog, where))


def _templates(catalog: Tree, spelled: Path) -> Iterator[QueryTemplate]:
    with _viewed(catalog) as view:
        for name in _template_names(view, spelled):
            template, reason = _template_at(view, name, spelled / name)
            if template is None:
                _logger.warning(f"warn: skipping {name.rsplit('/', 1)[-1]} ({reason})")
                continue
            yield template
