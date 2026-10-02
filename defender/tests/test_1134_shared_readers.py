"""#1134 step 4 (v3): the shared readers take a `Bound`, and list it with `list_tree`.

The contract is the step-4 contract over #1134's design (D4 "Shared readers", N-h, the reader
part of O5.1, the iterator part of O5.5, A4 with addendum 2's B2/B3) and D7's
guard-plus-positive-control shape. The readers are `_corpus.iter_lesson_paths`, `iter_lessons`,
`iter_query_templates`, `read_query_template` and `lead_neighbors.load_catalog`. Each takes a
`Bound` (any of `bind(folder)`, `hold(folder).view()`, `hold(mount).view().under(prefix)`) plus a
keyword-only `where`, the Path the caller says that folder is spelled as, used only to spell
output paths and warnings and never opened. Or it takes a bare `Path`, as today, which it binds
itself and closes. `read_query_template` takes `(view, name, *, where)` or `(path)`. The
iterators list their tree with `_tree_listing.list_tree` (depth 1 for a corpus, 3 for the
catalog), never a walk of their own, and select by name.

This file is v2 step 4's suite (v1's adversary-hardened rows, holes H1-H5, plus v2's adversary
holes H1-H7) ported onto addendum 2. v2 listed with `Bound.walk`, which v3 does not have; the
rows that pinned that walk's vocabulary are retargeted to `list_tree`'s: an `"unlisted"` folder
is now a folder in the listing's `refused`; the walk's whole-tree refusal for an errno below the
top is now that one folder's refusal (EIO at a `<sys>` costs that system and one warning, and
the rest still yields); the walk's depth is now `list_tree`'s, so a folder below it is never
entered, not merely ignored. New in v3: a folder found gone by its own listing (the listing's
`gone`) is silent, and a folder REALLY swapped between its parent's listing and its own ends
up refused or gone and is never listed through.

The tree. One tmp dir holds `t/`, the tree the readers are pointed at, `host/` beside it, where an
outside link points and every hard link keeps its other name, and `decoy/`, where a lying `where`
points. `t/lessons/` is a flat corpus. Its selection takes dot names (`.hidden.md`, `.md`) as
today's glob does. `t/skills/gather/queries/` is a catalog with a `<sys>/*.md`, a
`<sys>/_draft/*.md`, a top-level `_draft/` system, and systems named so that path-parts order
and string order disagree (`cmdb`, `cmdb-ext`, `cmdb.v2`). Its selection takes dot and `_` names
at every level (`.dotsys/`, the system that sorts first, with a `_draft/` of its own;
`wazuh/.hidden.md`, `wazuh/_private.md`, `wazuh/_draft/_x.md`, `cmdb/.md`). Each tree also holds
valid records its selection must NOT take. The corpus has a `_` name, a non-`.md` name, a
nested `.md`, and near misses that hold `.md` but do not end with it (`notes.md.bak`, `x.mdx`,
`x.md~`). The catalog has a `SCHEMA.md` (and `SCHEMA.md.orig`) at `<sys>` level, a middle
folder that is not `_draft`, a draft one level too deep, and near misses (`wazuh/x.md.orig`,
`wazuh/_draft/y.mdown`). The record addresses under test ("probes") are empty in the built
tree: a plant or the control's plain file goes there.

Call forms (`FORMS`): `path` (the bare Path of the corpus or catalog), `bound` (`bind(top)`),
`held-view` (`hold(top).view()`) and `held-view-under`, the drain's shape
(`hold(t).view().under("lessons")`, `hold(t/skills).view().under("gather/queries")`). Each Bound
form passes `where=top`. `read_query_template`'s forms are the bare Path, `bind(catalog)` with
`"<sys>/x.md"`, `hold(skills).view()` with `"gather/queries/<sys>/x.md"` (as a `str` and as a
`PurePosixPath`), and `hold(skills).view().under("gather/queries")` with `"<sys>/x.md"` and
`where=catalog`. In every Bound form the output Path is `where / name`, which is today's
Path-form spelling of the same file.

What each section pins:

- Argument rules. A Bound without `where` is `ValueError` before any I/O (an empty `os_` record).
  A Path with `where` is `ValueError`, and so is `load_catalog(None, where=...)`.
  `read_query_template`: a Bound without a name, a Path with a name, and a malformed name are
  `ValueError`. `where` is keyword-only.
- Parity. On a plain tree every form of every reader yields today's records in today's order,
  spelled as today, with no warning. The expected records are built from the planted text with
  the parsers alone (`split_frontmatter`, `parse_query_template`), never by a reader. Over the
  repo's real corpora and catalog every form equals today's walk (written out here), with no
  warning. `load_catalog(None)` is `PATHS.catalog_dir`'s catalog.
- Selected by name whatever the kind, refused at read. A symlink at a probe gets the existing
  per-record warning with exactly the read's path-free reason (`ALIAS_READ_REFUSAL`): live to a
  VALID record under `host` carrying `HOST_MARK`, live to one inside the root where no selection
  takes carrying `INSIDE_MARK`, or dangling. So do a directory named `*.md`, a hard link (other
  name under `host`) and a FIFO. `on_skip` and `warn_label` get `where / name`, and the rest
  still yields. `iter_lesson_paths` only lists, so it lists the plant. `read_query_template`
  answers `(None, "malformed template: <reason>")`.
- Folders. A linked (outside, inside, dangling) or non-directory (file, FIFO) folder on the
  Bound's prefix gives ONE `warn: skipping <where> (<the listing's reason>)`, nothing yielded,
  no raise. Those prefix folders are `lessons` and `gather/queries` below the held mount, and
  `gather` above the catalog. The same plant at a `<sys>` or `<sys>/_draft` folder (an
  `ENTRY_OTHER` row of the listing) gives ONE `warn: skipping <where>/<name> (not a plain
  folder)`; it is never entered and the rest yields. A plain file there is silent. A `<sys>` or
  `_draft` folder whose own listing is refused (an `os_` seam refusing it by its real path, on
  each route, with EACCES or EIO, and a REAL permission bit read as an unprivileged user) gives
  ONE `warn: skipping <where>/<name> (<the listing's reason, verbatim>)` and every other record
  still yields, exactly. One found gone by its own listing is silent. One the selection never
  reads from is silent, refused or gone. A refused top gives one `warn: skipping <where>
  (<reason>)` and nothing. An absent root or folder is silent and empty. A directory named
  `<sys>/x.md` whose listing is refused is a refused RECORD (the malformed warning), not a
  folder warning. A folder below the listing's depth is never entered.
- Fault text kept byte for byte. An undecodable plain record's warning is today's. A missing
  template is `(None, "malformed template: [Errno 2] No such file or directory: '<where/name>'")`.
  So is a record gone between the listing and the read. A plain record refused for an errno is
  `strerror` alone (a declared delta).
- `where` only spells. A `where` that does not exist, or one that names a decoy tree of marked
  records, spells the Bound's records and is never opened.
- Lifetime. A Bound passed in is the caller's: the reader leaves it open. The Path form leaves
  no descriptor open: after `iter_lesson_paths`, `load_catalog` and `read_query_template`; after
  a generator is exhausted, closed or collected; and before a generator's first `next` (the
  bind is in its body). Counted on `/proc/self/fd`, so an explicit close and CPython's
  collection of a dropped Bound (its handle's `__del__`) look alike here; both are "closed".
- Positive facts, not guards. The root itself is opened following its spelling (N-h): a linked
  root yields the same records, spelled under the link. A regular file or FIFO passed as the root
  yields nothing and gives one `warn: skipping <path> (Not a directory)` (a declared delta).

Every guard row asserts three things. (1) Nothing from a target: no mark in any record or
warning. The kernel saw no read(2) of any marked file and no open of any marked file but a hard
link's shared inode (the core opens that one no-follow to judge it). It also saw no open or
listing of any folder a link points at (`_shared_readers_1134.kernel_watch`, inotify `IN_ACCESS`
and `IN_OPEN`, by any route, in every form). In the Bound forms, the `os_` seam also saw the
reader's I/O go through the Bound it was handed, and no open by a spelling that could follow a
link. (2) The plant is left in place: the census of the whole
tmp dir is unchanged. (3) The positive control: the plant removed and a plain file (or the real
folder) put back at the SAME address, the SAME call (the same Bound, so it is still open) yields
today's records with no warning, and the kernel watch saw that call read a plain record, so the
watch is not blind. Every call runs under `in_time`'s deadline, so a FIFO costs a failed row,
never a wedged run.

Every plant is a real filesystem entry. `os_` stand-ins go only through `bind` / `hold`'s `os_`
and are used only where a real fault cannot be made as root, or at a moment no outside actor
can hit: a refused listing, EIO, a folder or record gone at listing or read time, a plain record
whose open is refused, a folder REALLY moved and replaced between two listings. Nothing is
monkeypatched. The real-permission rows run in-process when the test runs unprivileged (CI), and as root in a child interpreter that drops to uid/gid 65534
after its imports, under a deadline. The Path form's open audit (H2 below) also runs in a
child interpreter, under a deadline: the test worker installs no audit hook.

Red against the step-3 base (1341 of 1422 rows; v2 counted 1153 of 1234 before v3's ENOENT
and swap-between-listings rows): every Bound-form row (today's readers take no `where`:
`TypeError`; given none, `.is_dir()` on the Bound is `AttributeError`); every argument-rule row
but the keyword-only ones (today's signatures already refuse a second positional); every
Path-form plant row of the four reading readers (today's `read_text` follows a link to its
target's record, reads a hard link, blocks on a FIFO, and words a directory or a dangling link
with its own errno and path, never the alias reason); the Path-form `<sys>`/`_draft` folder rows
but the plain-file ones (today's glob follows a linked system and is silent about a dangling one
or a FIFO); the real-permission `<sys>`, `_draft` and top rows (today's glob swallows
`PermissionError` silently); the non-directory root rows (today silent); the Path-form swap,
unreadable-record and open-audit rows (today's `read_text` opens `where / name` by its
spelling); and the relative warning rows. Green today, and must stay green (81): the Path-form
parity (absolute and relative), absent, fault-text, lifetime and root-following rows, the real
trees by path, the keyword-only rows, the silent real-permission rows and their uid check, the
Path-form plain-file folder rows, and `iter_lesson_paths`' Path-form plant and
unreadable-record rows (today's glob lists any entry by name and opens none).

Added after v2's step-4 implementation, each against a green but wrong reader v2's adversary
built on it (H1-H7), each checked red against that reader and green against v2's
implementation, and kept here as they were:
- H1: a reader that stopped the whole catalog listing at the first non-plain `<sys>` folder. The
  folder plants, the seam refusals and the real-permission rows now also hit `.dotsys` and
  `.dotsys/_draft`, which sort first, so every later system must still yield exactly.
- H2: a Path form that judged each name by `lstat` and then read it by its path. Three rows
  now catch it. A folder (the listed one, or a `<sys>`) is swapped for a link to marked records
  after the first record, so the rest must come through the held handle. A plain record of
  mode 0o000 is read for real, unprivileged: `strerror` alone, never `[Errno 13] ...: '<path>'`.
  And the open audit (a child interpreter's audit hook) checks that the Path form opens nothing
  below its root by a spelling.
- H3: a Bound answering absent that fell back to reading `where` by path. The Bound's folder is
  removed and a marked tree (a folder, or a link) is put at `where`: nothing, silently, never
  opened.
- H4: a `read_query_template` that logged its refusals. Every row of it now asserts that it
  logs nothing.
- H5: a selection that took `.md` anywhere in a name: the near misses above.
- H6: a Path form that made its path absolute: relative-path rows (`monkeypatch.chdir` to the
  tmp dir) for records, warnings, `on_skip` and `read_query_template`.
- H7: a `read_query_template` that spelled a view under a prefix as `where / prefix / name`: the
  `held-view-under` form.

Added after v3's step-4 implementation, each against a green but wrong reader v3's scoped
adversary built (V3-H1 to V3-H5), each checked red against it and green against the
implementation (the section at the end of this file): a reader that listed a `<sys>` again
instead of keeping its listing's `refused` (exactly-once asks, and a refused-once row); one that
passed through only the reasons the other rows use (uncommon errnos); one that warned out of
path order (several faults in one catalog); a Path form that listed below the shape (a kernel
watch on the folder below); and a Path-form generator that listed before its first `next`.
"""
from __future__ import annotations

import contextlib
import dataclasses
import errno
import gc
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender._corpus import (
    Lesson,
    QueryTemplate,
    iter_lesson_paths,
    iter_lessons,
    iter_query_templates,
    parse_query_template,
    read_query_template,
)
from defender._frontmatter import split_frontmatter
from defender._io import ALIAS_READ_REFUSAL, bind, hold, read_text_utf8
from defender._paths import PATHS
from defender.learning.leads import lead_neighbors as ln
from defender.tests._shared_readers_1134 import (
    NOBODY,
    REFUSAL_ROUTES,
    SWAP_PLANTS,
    RefusesFolder,
    RefusesFolders,
    SpellingRecorder,
    SwapsFolderBetweenListings,
    VanishesOnOpen,
    kernel_watch,
    project_record,
    run_readers,
)
from defender.tests._tree_listing_1134 import CHILD_DEADLINE, CallRecorder, descriptors_under
from defender.tests.test_1111_rooted_io import Planted, census, in_time, plant_leaf

# ---------------------------------------------------------------------------------------
# The tree
# ---------------------------------------------------------------------------------------

#: What every link target, hard link's other name, planted folder and decoy holds, inside a
#: VALID record: a reader that followed the plant would yield it, not warn about it.
#: `HOST_MARK` is outside every root (under `host`). `INSIDE_MARK` is inside the root the row
#: opens, at a place no selection takes, so only a reader that followed (or re-resolved) the
#: plant reaches it. `DECOY_MARK` is under the decoy `where`, which no reader may open.
HOST_MARK = "host-bytes-7c1d"
INSIDE_MARK = "inside-bytes-3e8a"
DECOY_MARK = "decoy-bytes-5b20"
MARKS = (HOST_MARK, INSIDE_MARK, DECOY_MARK)

#: The reasons, path-free: a link, hard link or non-plain entry at a name, or a linked prefix
#: folder, is the alias sentence; a file or FIFO on the prefix is `Not a directory`.
ALIAS = ALIAS_READ_REFUSAL
NOT_A_DIR = os.strerror(errno.ENOTDIR)
DENIED = os.strerror(errno.EACCES)
NOT_A_PLAIN_FOLDER = "not a plain folder"
#: What today's `read_text_utf8` says of a file whose first byte is `0xff`.
DECODE_FAULT = "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"


def lesson_text(slug: str) -> str:
    return f"---\nname: {slug}\ndescription: what {slug} teaches\n---\nThe body of {slug}.\n"


def template_text(system: str, slug: str, status: str = "established") -> str:
    return (f"---\nid: {system}.{slug}\nstatus: {status}\nverb: search\n"
            f"covers: [{system}.{slug}-coined]\n---\n\n## Goal\n\nmeasures {slug}\n\n"
            f"## Query\n\n```esql\nFROM {system} | WHERE k == \"{slug}\"\n```\n")


CATALOG = "skills/gather/queries"

#: The built tree, `t`-relative.
FILES: dict[str, str] = {
    "lessons/alpha.md": lesson_text("alpha"),
    "lessons/zulu.md": lesson_text("zulu"),
    "lessons/.hidden.md": lesson_text("dot-name"),
    "lessons/.md": lesson_text("bare-dot"),
    "lessons/_TEMPLATE.md": lesson_text("underscore-name"),
    "lessons/notes.txt": lesson_text("not-md"),
    "lessons/sub/nested.md": lesson_text("nested"),
    # Near misses: `.md` inside a name that does not END `.md` (H5).
    "lessons/notes.md.bak": lesson_text("near-miss-bak"),
    "lessons/x.mdx": lesson_text("near-miss-mdx"),
    "lessons/x.md~": lesson_text("near-miss-tilde"),
    "skills/gather/defender-sql.md": "# the gather SQL skill, beside the catalog\n",
    f"{CATALOG}/SCHEMA.md": template_text("schema", "sys-level"),
    f"{CATALOG}/SCHEMA.md.orig": template_text("schema", "near-miss-orig"),
    f"{CATALOG}/cmdb/host-by-ip.md": template_text("cmdb", "host-by-ip"),
    f"{CATALOG}/cmdb/.md": template_text("cmdb", "bare-dot"),
    # `cmdb-ext` and `cmdb.v2` sort after `cmdb` by path parts, before it as a string ('-' and
    # '.' < '/').
    f"{CATALOG}/cmdb-ext/asset-owner.md": template_text("cmdb-ext", "asset-owner"),
    f"{CATALOG}/cmdb.v2/v2-host.md": template_text("cmdb.v2", "v2-host"),
    f"{CATALOG}/wazuh/auth-events.md": template_text("wazuh", "auth-events"),
    f"{CATALOG}/wazuh/_draft/novel.md": template_text("wazuh", "novel", "draft"),
    # Today's glob takes a dot or `_` name in the catalog, at every level it selects, and a
    # top-level `_draft` folder as a system of its own (`*/*.md`).
    f"{CATALOG}/wazuh/_private.md": template_text("wazuh", "underscore-name"),
    f"{CATALOG}/wazuh/.hidden.md": template_text("wazuh", "dot-name"),
    f"{CATALOG}/wazuh/_draft/_x.md": template_text("wazuh", "underscore-draft", "draft"),
    # `.dotsys` sorts FIRST of the systems, so a plant there has every other system after it.
    f"{CATALOG}/.dotsys/dot-system.md": template_text("dotsys", "dot-system"),
    f"{CATALOG}/.dotsys/_draft/dot-draft.md": template_text("dotsys", "dot-draft", "draft"),
    f"{CATALOG}/_draft/top-level.md": template_text("draftsys", "top-level", "draft"),
    f"{CATALOG}/wazuh/notes/aside.md": template_text("wazuh", "other-middle"),
    f"{CATALOG}/wazuh/_draft/deeper/buried.md": template_text("wazuh", "too-deep"),
    f"{CATALOG}/wazuh/x.md.orig": template_text("wazuh", "near-miss-orig"),
    f"{CATALOG}/wazuh/_draft/y.mdown": template_text("wazuh", "near-miss-mdown", "draft"),
}
#: The record addresses under test, empty in the built tree, and the control's plain text.
PROBE_TEXT: dict[str, str] = {
    "lessons/mid.md": lesson_text("mid"),
    f"{CATALOG}/wazuh/probe.md": template_text("wazuh", "probe"),
    f"{CATALOG}/wazuh/_draft/probe-draft.md": template_text("wazuh", "probe-draft", "draft"),
}
TEXT = {**FILES, **PROBE_TEXT}


@dataclasses.dataclass(frozen=True)
class Shape:
    """One tree the readers walk, `t`-relative: `top` the walked folder, `mount` the held root
    of the `held-view-under` form (`""` is `t` itself), `records` what the built tree yields."""

    top: str
    mount: str
    noun: str
    records: tuple[str, ...]
    probes: tuple[str, ...]
    #: A record every control reads: the kernel watch must see it read (non-vacuity).
    sentinel: str

    @property
    def folder(self) -> str:
        return self.top.removeprefix(self.mount).lstrip("/")


TREES: dict[str, Shape] = {
    "lessons": Shape("lessons", "", "lesson",
                     ("lessons/.hidden.md", "lessons/.md", "lessons/alpha.md",
                      "lessons/zulu.md"),
                     ("lessons/mid.md",), "lessons/alpha.md"),
    "catalog": Shape(CATALOG, "skills", "template",
                     (f"{CATALOG}/.dotsys/_draft/dot-draft.md",
                      f"{CATALOG}/.dotsys/dot-system.md", f"{CATALOG}/_draft/top-level.md",
                      f"{CATALOG}/cmdb/.md", f"{CATALOG}/cmdb/host-by-ip.md",
                      f"{CATALOG}/cmdb-ext/asset-owner.md", f"{CATALOG}/cmdb.v2/v2-host.md",
                      f"{CATALOG}/wazuh/.hidden.md",
                      f"{CATALOG}/wazuh/_draft/_x.md", f"{CATALOG}/wazuh/_draft/novel.md",
                      f"{CATALOG}/wazuh/_private.md", f"{CATALOG}/wazuh/auth-events.md"),
                     (f"{CATALOG}/wazuh/probe.md", f"{CATALOG}/wazuh/_draft/probe-draft.md"),
                     f"{CATALOG}/cmdb/host-by-ip.md"),
}
HOST_TEXT = {"lessons": lesson_text(HOST_MARK), "catalog": template_text("host", HOST_MARK)}
INSIDE_TEXT = {"lessons": lesson_text(INSIDE_MARK),
               "catalog": template_text("inside", INSIDE_MARK)}
DECOY_TEXT = {"lessons": lesson_text(DECOY_MARK), "catalog": template_text("decoy", DECOY_MARK)}


def under(rel: str, site: str) -> bool:
    """Is `rel` at or below `site` (`""` is `t` itself)?"""
    return site == "" or rel == site or rel.startswith(f"{site}/")


def strictly_below(site: str, root: str) -> bool:
    return site != root and under(site, root)


def below(rel: str, top: str) -> PurePosixPath:
    return PurePosixPath(rel).relative_to(top or ".")


def tree_of(rel: str) -> str:
    return "lessons" if under(rel, "lessons") else "catalog"


@dataclasses.dataclass(frozen=True)
class Scene:
    tmp: Path

    @property
    def t(self) -> Path:
        return self.tmp / "t"

    @property
    def host(self) -> Path:
        return self.tmp / "host"

    @property
    def decoy(self) -> Path:
        return self.tmp / "decoy"

    def put(self, rels: Iterable[str], *, base: Path | None = None, site: str = "") -> None:
        """Write each `rel`'s text at `base / <rel below site>` (by default, at `t / rel`)."""
        for rel in rels:
            at = (base or self.t) / below(rel, site)
            at.parent.mkdir(parents=True, exist_ok=True)
            at.write_text(TEXT[rel], encoding="utf-8")


@pytest.fixture
def scene(tmp_path: Path) -> Scene:
    built = Scene(tmp_path)
    built.host.mkdir()
    built.put(FILES)
    return built


# ---------------------------------------------------------------------------------------
# The readers and their call forms
# ---------------------------------------------------------------------------------------

def lesson_record(path: Path, text: str) -> Lesson:
    fm, raw, body = split_frontmatter(text)
    return Lesson(path=path, fm=fm, raw=raw, body=body)


def template_record(path: Path, text: str) -> QueryTemplate:
    template, reason = parse_query_template(text, path)
    assert template is not None, reason
    return template


def catalog_row(t: Any) -> tuple[Any, ...]:
    """What a `load_catalog` `Template` carries of its `QueryTemplate`."""
    return (t.id, t.system, t.path, t.status, t.goal, t.covers)


def _same(record: Any) -> Any:
    return record


@dataclasses.dataclass(frozen=True)
class Reader:
    """One iterator. `record(path, text)` builds today's record for the plain file at `path`;
    `key` projects a yielded record (and an expected one) to what is compared; `reads` is False
    for the reader that only lists."""

    name: str
    tree: str
    call: Callable[..., Any]
    record: Callable[[Path, str], Any]
    key: Callable[[Any], Any] = _same
    reads: bool = True

    def run(self, arg: Any, kw: dict[str, Any]) -> list[Any]:
        return [self.key(r) for r in self.call(arg, **kw)]

    def expected(self, where: Path, rels: Iterable[str]) -> list[Any]:
        """Today's answer for plain records at `rels` (`t`-relative): sorted by path parts,
        each spelled `where / <its name below the walked folder>`."""
        top = TREES[self.tree].top
        order = sorted(rels, key=lambda rel: PurePosixPath(rel).parts)
        return [self.key(self.record(where / below(rel, top), TEXT[rel])) for rel in order]


READERS = (
    Reader("iter_lesson_paths", "lessons", iter_lesson_paths, lambda path, _text: path,
           reads=False),
    Reader("iter_lessons", "lessons", iter_lessons, lesson_record),
    Reader("iter_query_templates", "catalog", iter_query_templates, template_record),
    Reader("load_catalog", "catalog", ln.load_catalog, template_record, key=catalog_row),
)
BY_NAME = {r.name: r for r in READERS}
READING = tuple(r for r in READERS if r.reads)
CATALOG_READERS = tuple(r for r in READERS if r.tree == "catalog")
FORMS = ("path", "bound", "held-view", "held-view-under")
BOUND_FORMS = FORMS[1:]


def reader_id(reader: Reader) -> str:
    return reader.name


def form_root(tree: str, form: str) -> str:
    """The folder each form opens, `t`-relative: the walked folder, or the held mount."""
    shape = TREES[tree]
    return shape.mount if form == "held-view-under" else shape.top


@contextlib.contextmanager
def called_as(scene: Scene, tree: str, form: str,
              os_: Any = os) -> Iterator[tuple[Any, dict[str, Any]]]:
    """`(first argument, keyword arguments)` of a reader of `tree` in `form`, its Bound opened
    over `os_` (and closed after)."""
    shape = TREES[tree]
    top = scene.t / shape.top
    if form == "path":
        yield top, {}
        return
    with contextlib.ExitStack() as stack:
        if form == "bound":
            arg = stack.enter_context(bind(top, os_=os_))
        elif form == "held-view":
            arg = stack.enter_context(hold(top, os_=os_)).view()
        else:
            arg = stack.enter_context(hold(scene.t / shape.mount, os_=os_)).view().under(
                shape.folder)
        yield arg, {"where": top}


RQT_FORMS = ("path", "bound", "held", "held-purepath", "held-view-under")
#: The forms the plant rows drive: the `PurePosixPath` name is the prefixed `str` name's twin.
RQT_PLANT_FORMS = ("path", "bound", "held", "held-view-under")


def rqt_where(probe: str, form: str) -> str:
    """The folder `where` spells, and `name` is relative to (`t`-relative): the bare Path's
    parent; the catalog for `bind(catalog)` and for the held `skills` view under
    `gather/queries`; `skills` for the held `skills` view itself."""
    if form == "path":
        return str(PurePosixPath(probe).parent)
    return "skills" if form in ("held", "held-purepath") else CATALOG


def rqt_root(probe: str, form: str) -> str:
    """The folder the form opens, following its spelling (`t`-relative)."""
    return "skills" if form == "held-view-under" else rqt_where(probe, form)


@contextlib.contextmanager
def rqt_called_as(scene: Scene, probe: str, form: str, os_: Any = os,
                  where: Path | None = None) -> Iterator[tuple[tuple[Any, ...], dict[str, Any]]]:
    """`read_query_template`'s `(args, kwargs)` for `probe` in `form`: the bare Path; a Bound
    on the catalog with `"<sys>/x.md"`; a held `skills` view with the prefixed name (`str`, or
    `PurePosixPath`); the held `skills` view under `gather/queries` with `"<sys>/x.md"` (H7).
    `where` defaults to the folder the name is relative to."""
    if form == "path":
        yield (scene.t / probe,), {}
        return
    where_rel = rqt_where(probe, form)
    root = scene.t / rqt_root(probe, form)
    name = below(probe, where_rel).as_posix()
    with contextlib.ExitStack() as stack:
        if form == "bound":
            view = stack.enter_context(bind(root, os_=os_))
        else:
            view = stack.enter_context(hold(root, os_=os_)).view()
            if form == "held-view-under":
                view = view.under(below(CATALOG, "skills"))
        named = PurePosixPath(name) if form == "held-purepath" else name
        yield (view, named), {"where": where if where is not None else scene.t / where_rel}


def rqt_expected(scene: Scene, probe: str) -> tuple[QueryTemplate, str]:
    return template_record(scene.t / probe, PROBE_TEXT[probe]), ""


def probe_id(probe: str) -> str:
    return PurePosixPath(probe).name


def said(caplog: pytest.LogCaptureFixture) -> list[str]:
    """The warnings the defender's loggers logged since the last clear."""
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and r.name.startswith("defender")]


def rqt_quietly(caplog: pytest.LogCaptureFixture, args: tuple[Any, ...],
                kw: dict[str, Any]) -> tuple[QueryTemplate | None, str]:
    """`read_query_template(*args, **kw)` under the deadline. It must log nothing, whatever it
    answers: its caller (the commit gate) words the refusal from the reason it returns (H4)."""
    caplog.clear()
    got = in_time(lambda: read_query_template(*args, **kw))
    assert said(caplog) == [], f"read_query_template logged: {said(caplog)}"
    return got


def gone(path: Path) -> str:
    """Today's words for a record absent at read time."""
    return str(FileNotFoundError(errno.ENOENT, "No such file or directory", str(path)))


# ---------------------------------------------------------------------------------------
# Plants, the guarded run and the control
# ---------------------------------------------------------------------------------------

LEAF_PLANTS = ("symlink", "symlink_inside", "dangling", "directory", "hardlink", "fifo")
FOLDER_PLANTS = ("link", "link_inside", "dangling_link", "file", "fifo")
#: The walk's reason for each plant on the Bound's prefix (and `Bound.read`'s for each plant at
#: a holding folder): a linked folder is `_step`'s ELOOP, a file or FIFO its ENOTDIR.
PREFIX_REASON = {"link": ALIAS, "link_inside": ALIAS, "dangling_link": ALIAS,
                 "file": NOT_A_DIR, "fifo": NOT_A_DIR}
#: Where a `symlink_inside` plant at each probe points: a folder no selection takes, inside
#: every root that probe's rows open (`read_query_template`'s bare `Path` roots at the probe's
#: own folder).
INSIDE_LEAF = {
    "lessons/mid.md": "lessons/sub/inside-target.md",
    f"{CATALOG}/wazuh/probe.md": f"{CATALOG}/wazuh/notes/inside-target.md",
    f"{CATALOG}/wazuh/_draft/probe-draft.md": f"{CATALOG}/wazuh/_draft/deeper/inside-target.md",
}
#: Where a `link_inside` plant at each folder site points: inside every root the site's rows
#: open (each strictly above the site), at a place no walk selects from (outside the walked
#: folder, or at the catalog walk's last level, listed and never entered).
INSIDE_ATTIC = {
    "lessons": "attic/lessons",
    "skills/gather": "skills/attic/gather",
    CATALOG: "skills/attic/queries",
    f"{CATALOG}/wazuh": f"{CATALOG}/cmdb/notes/attic-wazuh",
    f"{CATALOG}/wazuh/_draft": f"{CATALOG}/cmdb/notes/attic-draft",
    f"{CATALOG}/.dotsys": f"{CATALOG}/wazuh/notes/attic-dotsys",
    f"{CATALOG}/.dotsys/_draft": f"{CATALOG}/wazuh/notes/attic-dotsys-draft",
}
#: The folders each tree's plants go at: the walked folder and every folder above it below
#: `t/skills`, then the `<sys>` and `_draft` levels: in the system that sorts LAST (`wazuh`), and
#: in the one that sorts FIRST (`.dotsys`), so a reader that stops at the plant loses every
#: system after it (H1).
FOLDER_SITES = {
    "lessons": ("lessons",),
    "catalog": ("skills/gather", CATALOG, f"{CATALOG}/.dotsys", f"{CATALOG}/.dotsys/_draft",
                f"{CATALOG}/wazuh", f"{CATALOG}/wazuh/_draft"),
}


def link_to(at: Path, target: Path) -> None:
    """A symlink at `at` to `target`, spelled relative, as a link planted inside a tree is."""
    at.symlink_to(os.path.relpath(target, at.parent), target_is_directory=target.is_dir())


def plant_record(scene: Scene, probe: str, kind: str) -> Planted:
    """`kind` at the record address `probe`. A live symlink's target, a hard link's other name
    and a directory's inner `.md` each hold a valid record carrying `HOST_MARK`; a
    `symlink_inside` points at one carrying `INSIDE_MARK`, at `INSIDE_LEAF[probe]`."""
    at = scene.t / probe
    body = HOST_TEXT[tree_of(probe)]
    if kind == "symlink_inside":
        target = scene.t / INSIDE_LEAF[probe]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(INSIDE_TEXT[tree_of(probe)], encoding="utf-8")
        link_to(at, target)
    elif kind == "dangling":
        at.symlink_to(scene.host / f"no-such-{at.name}")
    elif kind == "directory":
        at.mkdir()
        (at / "inner.md").write_text(body, encoding="utf-8")
    else:
        return plant_leaf(at, kind, host=scene.host, body=body.encode())
    return Planted(kind, at)


def plant_folder_at(scene: Scene, site: str, kind: str) -> Planted:
    """The real folder at `site` replaced by `kind`. A `link` points at a folder under `host`
    holding a copy of everything the real one held, plus a `HOST_MARK` record at each probe
    below `site`: a reader that followed it would yield all of that. A `link_inside` is the
    same with its target at `INSIDE_ATTIC[site]`, inside the root, marked `INSIDE_MARK`."""
    at = scene.t / site
    shutil.rmtree(at)
    if kind in ("link", "link_inside"):
        inside = kind == "link_inside"
        target = scene.t / INSIDE_ATTIC[site] if inside else scene.host / f"elsewhere-{at.name}"
        marked = INSIDE_TEXT if inside else HOST_TEXT
        scene.put([rel for rel in FILES if under(rel, site)], base=target, site=site)
        for probe in PROBE_TEXT:
            if under(probe, site):
                marked_record = target / below(probe, site)
                marked_record.parent.mkdir(parents=True, exist_ok=True)
                marked_record.write_text(marked[tree_of(probe)], encoding="utf-8")
        target.mkdir(parents=True, exist_ok=True)
        link_to(at, target)
    elif kind == "dangling_link":
        at.symlink_to(scene.host / f"no-such-{at.name}", target_is_directory=True)
    elif kind == "file":
        at.write_text(HOST_TEXT[tree_of(site)], encoding="utf-8")
    else:
        os.mkfifo(at)
    return Planted(kind, at)


def plant_decoy(scene: Scene, tree: str) -> Path:
    """A decoy of `tree`'s walked folder under `decoy/`: a VALID record carrying `DECOY_MARK`
    at every name the selection takes. Answers its top."""
    shape = TREES[tree]
    top = scene.decoy / shape.top
    for rel in (*shape.records, *shape.probes):
        at = top / below(rel, shape.top)
        at.parent.mkdir(parents=True, exist_ok=True)
        at.write_text(DECOY_TEXT[tree], encoding="utf-8")
    return top


def watch_lists(scene: Scene, before: dict[str, tuple]) -> tuple[list[Path], list[Path]]:
    """`(reads, opens)` for the kernel watch over the census `before`. Every marked regular file
    is watched for reads, and for opens too unless it has more than one name (the core opens a
    hard link no-follow to judge it). Every folder a link points at, and every decoy folder, is
    watched for opens and listings."""
    reads: list[Path] = []
    opens: list[Path] = []
    for key, row in before.items():
        at = scene.tmp / key
        if row[0] == "file" and any(mark.encode() in row[1] for mark in MARKS):
            (reads if row[3] > 1 else opens).append(at)
        elif row[0] == "link":
            target = Path(os.path.realpath(at))
            if target.is_dir():
                opens.extend(Path(d) for d, _dirs, _files in os.walk(target))
    if scene.decoy.is_dir():
        opens.extend(Path(d) for d, _dirs, _files in os.walk(scene.decoy))
    return reads, opens


def run_guarded(scene: Scene, fn: Callable[[], Any], *, planted: Planted | None,
                caplog: pytest.LogCaptureFixture, recorder: SpellingRecorder | None = None,
                folders: Iterable[Path] = ()) -> tuple[Any, list[str]]:
    """`fn()` over a plant, under the deadline, with the guard's invariants checked: nothing
    from a target in the answer or the warnings; the kernel saw no read of a marked file, no
    open of one but a hard link's, and no open or listing of a folder a link points at; the
    seam (Bound forms) saw the reader's I/O go through the Bound it was handed and no open by a
    spelling that could follow; and the whole tmp dir (the plant, `host`, the inside targets,
    the decoy) is unchanged. `folders` are watched for opens and listings too. Returns the
    answer and the warnings."""
    before = census(scene.tmp)
    reads, opens = watch_lists(scene, before)
    opens += list(folders)
    caplog.clear()
    if recorder is not None:
        recorder.mark()
    with kernel_watch(reads=reads, opens=opens) as events:
        got = in_time(fn, fifo=None if planted is None else planted.fifo)
        seen = events()
    warned = said(caplog)
    kind = "decoy" if planted is None else planted.kind
    for mark in MARKS:
        assert mark not in repr(got) + repr(warned), (
            f"a {kind} plant's target was read: {got!r} {warned!r}")
    assert seen == [], f"the kernel saw a {kind} plant's target opened or read: {seen}"
    if recorder is not None:
        assert recorder.opens, "nothing went through the Bound handed in: the row is void"
        following = recorder.following()
        assert following == [], f"opened by a spelling that could follow a link: {following}"
    assert census(scene.tmp) == before, f"the {kind} plant was not left in place"
    return got, warned


def run_control(scene: Scene, planted: Planted, rels: Iterable[str], fn: Callable[[], Any],
                caplog: pytest.LogCaptureFixture, *,
                sentinel: Path | None) -> tuple[Any, list[str]]:
    """The positive control: the plant removed, plain files at `rels` (the same address), and
    the same call again. When `sentinel` is given, the kernel watch must see the call read it:
    the watch the guard relied on is not blind."""
    planted.remove()
    scene.put(rels)
    caplog.clear()
    with kernel_watch(reads=[sentinel] if sentinel is not None else []) as events:
        got = in_time(fn)
        seen = events()
    if sentinel is not None:
        assert (str(sentinel), "read") in seen, (
            f"the kernel watch did not see the control read {sentinel}: it would be blind")
    return got, said(caplog)


def sentinel_of(scene: Scene, reader: Reader) -> Path | None:
    return scene.t / TREES[reader.tree].sentinel if reader.reads else None


# =======================================================================================
# The argument rules
# =======================================================================================

@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_a_bound_without_where_is_a_value_error_before_any_io(scene, reader):
    """A Bound has no path, so the Bound form needs `where`. Refused before the reader asks the
    Bound's `os_` for anything."""
    rec = CallRecorder()
    with bind(scene.t / TREES[reader.tree].top, os_=rec) as bound:
        made = len(rec.calls)
        with pytest.raises(ValueError):  # noqa: PT011 — the type is the contract, not the wording
            reader.run(bound, {})
        assert rec.calls[made:] == [], "the reader did I/O before refusing a missing `where`"


def test_read_query_template_on_a_bound_without_where_is_a_value_error_before_any_io(scene):
    rec = CallRecorder()
    with bind(scene.t / CATALOG, os_=rec) as bound:
        made = len(rec.calls)
        with pytest.raises(ValueError):  # noqa: PT011
            read_query_template(bound, "wazuh/auth-events.md")
        assert rec.calls[made:] == []


@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_a_path_with_where_is_a_value_error(scene, reader):
    """The Path spells itself: `where` beside it is a caller's mistake."""
    top = scene.t / TREES[reader.tree].top
    with pytest.raises(ValueError):  # noqa: PT011
        reader.run(top, {"where": top})


def test_load_catalog_of_none_with_where_is_a_value_error():
    with pytest.raises(ValueError):  # noqa: PT011
        ln.load_catalog(None, where=PATHS.catalog_dir)


#: `read_query_template` calls that are `ValueError`: a Bound with no name, a Path with a name
#: or a `where`, and a name outside `Bound.read`'s grammar.
RQT_MISUSE: dict[str, Callable[[Scene, Any], Any]] = {
    "bound-no-name": lambda s, b: read_query_template(b, where=s.t / CATALOG),
    "bound-none-name": lambda s, b: read_query_template(b, None, where=s.t / CATALOG),
    "path-with-name": lambda s, b: read_query_template(s.t / CATALOG, "wazuh/auth-events.md"),
    "path-with-purepath-name": lambda s, b: read_query_template(
        s.t / CATALOG, PurePosixPath("wazuh/auth-events.md")),
    "path-with-where": lambda s, b: read_query_template(
        s.t / CATALOG / "wazuh/auth-events.md", where=s.t / CATALOG / "wazuh"),
    "climbing-name": lambda s, b: read_query_template(
        b, "../queries/wazuh/auth-events.md", where=s.t / CATALOG),
    "absolute-name": lambda s, b: read_query_template(
        b, str(s.t / CATALOG / "wazuh/auth-events.md"), where=s.t / CATALOG),
    "empty-component": lambda s, b: read_query_template(
        b, "wazuh//auth-events.md", where=s.t / CATALOG),
    "empty-name": lambda s, b: read_query_template(b, "", where=s.t / CATALOG),
}


@pytest.mark.parametrize("case", list(RQT_MISUSE))
def test_read_query_template_refuses_a_misused_call(scene, case):
    with bind(scene.t / CATALOG) as bound, pytest.raises(ValueError):  # noqa: PT011
        RQT_MISUSE[case](scene, bound)


@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_where_is_keyword_only(scene, reader):
    top = scene.t / TREES[reader.tree].top
    with bind(top) as bound, pytest.raises(TypeError):
        list(reader.call(bound, top))


def test_read_query_templates_where_is_keyword_only(scene):
    misuse: Callable[..., Any] = read_query_template  # the call under test is ill-typed on purpose
    with bind(scene.t / CATALOG) as bound, pytest.raises(TypeError):
        misuse(bound, "wazuh/auth-events.md", scene.t / CATALOG)


# =======================================================================================
# Parity: every form reads a plain tree as today
# =======================================================================================

def assert_reads_the_whole_tree(scene: Scene, reader: Reader, form: str,
                                caplog: pytest.LogCaptureFixture) -> None:
    """With a plain record at every probe too, `reader` in `form` yields today's answer for
    the whole tree, spelled under `t`, and warns nothing."""
    shape = TREES[reader.tree]
    scene.put(shape.probes)
    caplog.clear()
    with called_as(scene, reader.tree, form) as (arg, kw):
        got = in_time(lambda: reader.run(arg, kw))
    assert got == reader.expected(scene.t / shape.top, (*shape.records, *shape.probes))
    assert said(caplog) == []


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_every_reader_reads_a_plain_tree_alike_in_each_call_form(scene, reader, form, caplog):
    """Selection is today's: the corpus takes `*.md` directly in the folder, dot names
    included, `_`-prefixed not; the catalog takes `<sys>/*.md` and `<sys>/_draft/*.md` (dot and
    `_` names at every level, a top-level `_draft` system too) and nothing at `<sys>` level,
    under another middle folder or deeper. Sorted by path parts (`cmdb` before `cmdb-ext`),
    spelled `where / name` (today's `corpus_dir / "x.md"`), and silent: the `<sys>`-level
    `SCHEMA.md` warns nothing."""
    assert_reads_the_whole_tree(scene, reader, form, caplog)


@pytest.mark.parametrize("form", RQT_FORMS)
@pytest.mark.parametrize("probe", TREES["catalog"].probes, ids=probe_id)
def test_read_query_template_reads_one_plain_template_in_each_call_form(
        scene, probe, form, caplog):
    """The template's `path` is `where / name` in every form (today's `repo_root / path` for
    the drain's `skills` view; the catalog's spelling for a view under `gather/queries`, H7),
    `system` comes from it (a draft's is the folder above `_draft`), and nothing is logged."""
    scene.put([probe])
    with rqt_called_as(scene, probe, form) as (args, kw):
        got = rqt_quietly(caplog, args, kw)

    assert got == rqt_expected(scene, probe)
    assert got[0] is not None
    assert got[0].system == "wazuh"


def test_load_catalog_with_no_argument_is_the_repo_catalog():
    """`load_catalog(None)` still defaults to `PATHS.catalog_dir`, and reads the same catalog
    as the drain's call, the `skills` view under `gather/queries`."""
    by_default = ln.load_catalog()

    assert by_default, "the checkout's catalog is not empty"
    assert by_default == ln.load_catalog(None) == ln.load_catalog(PATHS.catalog_dir)
    with hold(PATHS.skills_dir) as skills:
        assert by_default == ln.load_catalog(skills.view().under("gather/queries"),
                                             where=PATHS.catalog_dir)


def todays_lesson_paths(corpus: Path) -> list[Path]:
    """Today's corpus selection, written out: `*.md` directly in `corpus`, not `_`-prefixed,
    sorted."""
    return [p for p in sorted(corpus.glob("*.md")) if not p.name.startswith("_")]


def todays_lessons(corpus: Path) -> list[Lesson]:
    return [lesson_record(p, read_text_utf8(p)) for p in todays_lesson_paths(corpus)]


def todays_catalog(catalog: Path) -> list[QueryTemplate]:
    """Today's catalog walk, written out: `*/*.md` and `*/_draft/*.md`, sorted, each parsed."""
    paths = sorted([*catalog.glob("*/*.md"), *catalog.glob("*/_draft/*.md")])
    return [template_record(p, read_text_utf8(p)) for p in paths]


#: The repo's real trees: `(the walked folder, the drain's held mount, the prefix below it,
#: the tree kind)`.
REAL_TREES: dict[str, Callable[[], tuple[Path, Path, str, str]]] = {
    "lessons": lambda: (PATHS.lessons_dir, PATHS.defender_dir, "lessons", "lessons"),
    "lessons-questioner": lambda: (PATHS.lessons_questioner_dir, PATHS.defender_dir,
                                   "lessons-questioner", "lessons"),
    "catalog": lambda: (PATHS.catalog_dir, PATHS.skills_dir, "gather/queries", "catalog"),
}
TODAYS: dict[str, Callable[[Path], list[Any]]] = {
    "iter_lesson_paths": todays_lesson_paths,
    "iter_lessons": todays_lessons,
    "iter_query_templates": todays_catalog,
    "load_catalog": lambda top: [catalog_row(t) for t in todays_catalog(top)],
}
REAL_ROWS = [
    pytest.param(label, reader, form, id=f"{label}-{reader.name}-{form}")
    for label, kind in (("lessons", "lessons"), ("lessons-questioner", "lessons"),
                        ("catalog", "catalog"))
    for reader in READERS if reader.tree == kind
    for form in FORMS
]


@pytest.mark.parametrize(("label", "reader", "form"), REAL_ROWS)
def test_the_real_trees_read_alike_in_every_form(label, reader, form, caplog):
    """Over the checkout's own corpora and catalog, each form yields exactly today's records,
    spelled under the walked folder, with no warning."""
    top, mount, folder, _kind = REAL_TREES[label]()
    want = TODAYS[reader.name](top)
    assert want, f"the checkout's {label} tree is not empty"
    caplog.clear()
    with contextlib.ExitStack() as stack:
        if form == "path":
            got = reader.run(top, {})
        elif form == "bound":
            got = reader.run(stack.enter_context(bind(top)), {"where": top})
        elif form == "held-view":
            got = reader.run(stack.enter_context(hold(top)).view(), {"where": top})
        else:
            view = stack.enter_context(hold(mount)).view().under(folder)
            got = reader.run(view, {"where": top})

    assert got == want
    assert said(caplog) == []


# =======================================================================================
# A non-plain entry at a record's name: selected by name, refused, skipped with its warning
# =======================================================================================

LEAF_ROWS = [
    pytest.param(reader, probe, plant, form,
                 id=f"{reader.name}-{probe_id(probe)}-{plant}-{form}")
    for reader in READERS
    for probe in TREES[reader.tree].probes
    for plant in LEAF_PLANTS
    for form in FORMS
]


@pytest.mark.parametrize(("reader", "probe", "plant", "form"), LEAF_ROWS)
def test_a_non_plain_entry_at_a_record_name_is_refused_and_skipped(
        scene, reader, probe, plant, form, caplog):
    """The plant is selected by its `*.md` name whatever it is, reaches the read, is refused,
    and costs exactly the reader's existing per-record warning with the read's path-free
    reason; every other record still yields. `iter_lesson_paths` only lists, so it returns the
    plant's path and warns nothing. Control: a plain record at the same address, through the
    same Bound, yields as today."""
    shape = TREES[reader.tree]
    where = scene.t / shape.top
    planted = plant_record(scene, probe, plant)
    rec = None if form == "path" else SpellingRecorder()

    with called_as(scene, reader.tree, form, os_=rec or os) as (arg, kw):
        got, warned = run_guarded(scene, lambda: reader.run(arg, kw), planted=planted,
                                  caplog=caplog, recorder=rec)
        if reader.reads:
            assert got == reader.expected(where, shape.records)
            assert warned == [
                f"warn: skipping {planted.at.name} (malformed {shape.noun}: {ALIAS})"]
        else:
            assert got == reader.expected(where, (*shape.records, probe))
            assert warned == []
        got, warned = run_control(scene, planted, [probe], lambda: reader.run(arg, kw), caplog,
                                  sentinel=sentinel_of(scene, reader))
    assert got == reader.expected(where, (*shape.records, probe))
    assert warned == []


@pytest.mark.parametrize("form", RQT_FORMS)
@pytest.mark.parametrize("plant", LEAF_PLANTS)
@pytest.mark.parametrize("probe", TREES["catalog"].probes, ids=probe_id)
def test_read_query_template_refuses_a_non_plain_entry_at_the_name(
        scene, probe, plant, form, caplog):
    """`(None, "malformed template: <the read's reason>")`, and nothing read from the plant.
    Control: a plain template at the same address reads as today."""
    planted = plant_record(scene, probe, plant)
    rec = None if form == "path" else SpellingRecorder()

    with rqt_called_as(scene, probe, form, os_=rec or os) as (args, kw):
        got, warned = run_guarded(scene, lambda: read_query_template(*args, **kw),
                                  planted=planted, caplog=caplog, recorder=rec)
        assert got == (None, f"malformed template: {ALIAS}")
        assert warned == [], "read_query_template logs nothing: its caller words the refusal"
        got, warned = run_control(scene, planted, [probe],
                                  lambda: read_query_template(*args, **kw), caplog,
                                  sentinel=scene.t / probe)
    assert got == rqt_expected(scene, probe)
    assert warned == []


@pytest.mark.parametrize("form", FORMS)
def test_a_refused_lesson_reaches_warn_label_and_on_skip_spelled_under_where(
        scene, form, caplog):
    """`on_skip` gets the refused lesson's path and `warn_label` labels it, spelled
    `where / name` (today's `corpus_dir / "x.md"`) in every form."""
    shape = TREES["lessons"]
    probe = shape.probes[0]
    plant_record(scene, probe, "symlink")
    skipped: list[Path] = []
    labelled: list[Path] = []

    def label(p: Path) -> str:
        labelled.append(p)
        return f"<{p}>"

    caplog.clear()
    with called_as(scene, "lessons", form) as (arg, kw):
        got = in_time(lambda: list(iter_lessons(arg, warn_label=label, on_skip=skipped.append,
                                                **kw)))

    assert got == BY_NAME["iter_lessons"].expected(scene.t / shape.top, shape.records)
    assert skipped == [scene.t / probe]
    assert labelled == [scene.t / probe]
    assert said(caplog) == [f"warn: skipping <{scene.t / probe}> (malformed lesson: {ALIAS})"]


# =======================================================================================
# Today's fault text, byte for byte
# =======================================================================================

def plant_undecodable(scene: Scene, probe: str) -> None:
    (scene.t / probe).write_bytes(b"\xff" + PROBE_TEXT[probe].encode())


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("reader", READING, ids=reader_id)
def test_an_undecodable_plain_record_warns_in_todays_exact_words(scene, reader, form, caplog):
    """A plain file's decode fault is today's text: the decoder's own words, with no name
    prefix of the bound read's."""
    shape = TREES[reader.tree]
    probe = shape.probes[0]
    plant_undecodable(scene, probe)
    caplog.clear()
    with called_as(scene, reader.tree, form) as (arg, kw):
        got = in_time(lambda: reader.run(arg, kw))

    assert got == reader.expected(scene.t / shape.top, shape.records)
    assert said(caplog) == [
        f"warn: skipping {probe_id(probe)} (malformed {shape.noun}: {DECODE_FAULT})"]


@pytest.mark.parametrize("form", RQT_FORMS)
def test_read_query_template_of_an_undecodable_file_says_todays_exact_words(scene, form, caplog):
    probe = TREES["catalog"].probes[0]
    plant_undecodable(scene, probe)
    with rqt_called_as(scene, probe, form) as (args, kw):
        assert rqt_quietly(caplog, args, kw) == (None, f"malformed template: {DECODE_FAULT}")


@pytest.mark.parametrize("missing", ["leaf", "holding-folder"])
@pytest.mark.parametrize("form", RQT_FORMS)
@pytest.mark.parametrize("probe", TREES["catalog"].probes, ids=probe_id)
def test_read_query_template_of_a_missing_template_says_todays_exact_words(
        scene, probe, form, missing, caplog):
    """Absent at read time (the commit gate's case): today's `FileNotFoundError` text, naming
    the template as spelled (`where / name` in a Bound form), and nothing logged."""
    if missing == "holding-folder":
        shutil.rmtree((scene.t / probe).parent)
    with rqt_called_as(scene, probe, form) as (args, kw):
        got = rqt_quietly(caplog, args, kw)

    assert got == (None, f"malformed template: {gone(scene.t / probe)}")


@pytest.mark.parametrize("form", BOUND_FORMS)
@pytest.mark.parametrize("reader", READING, ids=reader_id)
def test_a_record_gone_between_the_walk_and_the_read_warns_in_todays_exact_words(
        scene, reader, form, caplog):
    """A record the walk listed that is gone when it is read (an `os_` seam removes it at its
    open) is today's absent text, `where / name` spelled, and the rest yields."""
    shape = TREES[reader.tree]
    probe = shape.probes[0]
    scene.put([probe])
    seam = VanishesOnOpen(scene.t / probe)
    caplog.clear()
    with called_as(scene, reader.tree, form, os_=seam) as (arg, kw):
        got = in_time(lambda: reader.run(arg, kw))

    assert seam.fired, "the record was never opened, so the row is void"
    assert got == reader.expected(scene.t / shape.top, shape.records)
    assert said(caplog) == [f"warn: skipping {probe_id(probe)} (malformed {shape.noun}: "
                            f"{gone(scene.t / probe)})"]


@pytest.mark.parametrize("err", [errno.EACCES, errno.EIO], ids=errno.errorcode.get)
@pytest.mark.parametrize("form", BOUND_FORMS)
@pytest.mark.parametrize("reader", READING, ids=reader_id)
def test_a_plain_record_refused_for_an_errno_warns_its_strerror_alone(
        scene, reader, form, err, caplog):
    """A declared delta: a plain record that exists but cannot be opened (EACCES, EIO, through
    an `os_` seam that refuses its open and nothing else: root reads anything) is skipped with
    the read's reason, `strerror` alone."""
    shape = TREES[reader.tree]
    probe = shape.probes[0]
    scene.put([probe])
    caplog.clear()
    seam = RefusesFolder(scene.t / probe, "step", err)
    with called_as(scene, reader.tree, form, os_=seam) as (arg, kw):
        got = in_time(lambda: reader.run(arg, kw))

    assert seam.refused, "the record's open was never refused, so the row is void"

    assert got == reader.expected(scene.t / shape.top, shape.records)
    assert said(caplog) == [
        f"warn: skipping {probe_id(probe)} (malformed {shape.noun}: {os.strerror(err)})"]


@pytest.mark.parametrize("err", [errno.EACCES, errno.EIO], ids=errno.errorcode.get)
@pytest.mark.parametrize("form", RQT_FORMS[1:])
def test_read_query_template_of_a_plain_file_refused_for_an_errno_says_its_strerror(
        scene, form, err, caplog):
    probe = TREES["catalog"].probes[0]
    scene.put([probe])
    seam = RefusesFolder(scene.t / probe, "step", err)
    with rqt_called_as(scene, probe, form, os_=seam) as (args, kw):
        assert rqt_quietly(caplog, args, kw) == (
            None, f"malformed template: {os.strerror(err)}")
    assert seam.refused, "the template's open was never refused, so the row is void"


# =======================================================================================
# Folders: a refused folder warns once (O5.5)
# =======================================================================================

FOLDER_ROWS = [
    pytest.param(reader, site, plant, form,
                 id=f"{reader.name}-{PurePosixPath(site).name}-{plant}-{form}")
    for reader in READERS
    for site in FOLDER_SITES[reader.tree]
    for plant in FOLDER_PLANTS
    for form in FORMS
    if strictly_below(site, form_root(reader.tree, form))
]


@pytest.mark.parametrize(("reader", "site", "plant", "form"), FOLDER_ROWS)
def test_a_linked_or_non_directory_folder_is_skipped_with_one_warning(
        scene, reader, site, plant, form, caplog):
    """The walked folder, or one above it below the held mount, as a link (even to a folder
    full of valid records), a dangling link, a file or a FIFO: nothing yields, ONE warning
    `warn: skipping <where> (<the walk's reason>)`, no raise. A `<sys>` or `_draft` folder so
    replaced is never entered and costs ONE `warn: skipping <where>/<name> (not a plain
    folder)`; the rest of the catalog yields. As a plain file it is silent (as `SCHEMA.md` is).
    Control: the real folder back at the same address yields the whole tree, silently."""
    shape = TREES[reader.tree]
    where = scene.t / shape.top
    planted = plant_folder_at(scene, site, plant)
    rec = None if form == "path" else SpellingRecorder()

    with called_as(scene, reader.tree, form, os_=rec or os) as (arg, kw):
        got, warned = run_guarded(scene, lambda: reader.run(arg, kw), planted=planted,
                                  caplog=caplog, recorder=rec)
        if under(shape.top, site):
            assert got == []
            assert warned == [f"warn: skipping {where} ({PREFIX_REASON[plant]})"]
        else:
            assert got == reader.expected(where, [r for r in shape.records if not under(r, site)])
            name = below(site, shape.top)
            assert warned == ([] if plant == "file" else
                              [f"warn: skipping {where}/{name} ({NOT_A_PLAIN_FOLDER})"])
        got, warned = run_control(scene, planted, [r for r in FILES if under(r, site)],
                                  lambda: reader.run(arg, kw), caplog,
                                  sentinel=sentinel_of(scene, reader))
    assert got == reader.expected(where, shape.records)
    assert warned == []


def holding_folders(probe: str) -> list[str]:
    """`probe`'s holding folders below `t/skills`, outermost first."""
    parents = [p.as_posix() for p in PurePosixPath(probe).parents]
    return [p for p in reversed(parents) if strictly_below(p, "skills")]


RQT_FOLDER_ROWS = [
    pytest.param(probe, site, plant, form,
                 id=f"{probe_id(probe)}-{PurePosixPath(site).name}-{plant}-{form}")
    for probe in TREES["catalog"].probes
    for site in holding_folders(probe)
    for plant in FOLDER_PLANTS
    for form in RQT_PLANT_FORMS
    if strictly_below(site, rqt_root(probe, form))
]


@pytest.mark.parametrize(("probe", "site", "plant", "form"), RQT_FOLDER_ROWS)
def test_read_query_template_refuses_a_linked_or_non_directory_holding_folder(
        scene, probe, site, plant, form, caplog):
    """A holding folder below the Bound's folder, replaced: `(None, "malformed template:
    <the read's reason>")`, never the template a link's target holds. Control: the real folders
    back, the template reads."""
    planted = plant_folder_at(scene, site, plant)
    rec = SpellingRecorder()

    with rqt_called_as(scene, probe, form, os_=rec) as (args, kw):
        got, warned = run_guarded(scene, lambda: read_query_template(*args, **kw),
                                  planted=planted, caplog=caplog, recorder=rec)
        assert got == (None, f"malformed template: {PREFIX_REASON[plant]}")
        assert warned == [], "read_query_template logs nothing: its caller words the refusal"
        got, warned = run_control(scene, planted, [r for r in (*FILES, probe) if under(r, site)],
                                  lambda: read_query_template(*args, **kw), caplog,
                                  sentinel=scene.t / probe)
    assert got == rqt_expected(scene, probe)
    assert warned == []


#: The sites removed for the absent rows: the walked folder and every folder above it.
ABSENT_SITES = {"lessons": ("lessons", ""), "catalog": (CATALOG, "skills/gather", "skills", "")}


def _absent_applies(tree: str, site: str, form: str) -> bool:
    """`bind` answers an absent root absent; `hold` raises on one, so a held form's absent rows
    remove a folder strictly below its mount."""
    if form in ("path", "bound"):
        return True
    return form == "held-view-under" and strictly_below(site, TREES[tree].mount)


ABSENT_ROWS = [
    pytest.param(reader, site, form, id=f"{reader.name}-{site or 't'}-{form}")
    for reader in READERS
    for site in ABSENT_SITES[reader.tree]
    for form in FORMS
    if _absent_applies(reader.tree, site, form)
]


@pytest.mark.parametrize(("reader", "site", "form"), ABSENT_ROWS)
def test_an_absent_root_or_folder_yields_nothing_and_warns_nothing(
        scene, reader, site, form, caplog):
    shutil.rmtree(scene.t / site)
    caplog.clear()
    with called_as(scene, reader.tree, form) as (arg, kw):
        assert in_time(lambda: reader.run(arg, kw)) == []
    assert said(caplog) == []


# -- a folder whose listing is refused, or found gone, through an `os_` seam ----------------

#: Per tree, the folders (relative to the listed folder; `""` is the listed folder) the refusal
#: rows refuse: the listed folder; in the catalog, each folder the selection reads from (a
#: `<sys>` folder, a `<sys>/_draft` folder, the top-level `_draft` system), and two it never
#: reads from (a middle folder that is not `_draft`, which IS listed, and a folder at the
#: listing's last level, which is not); in the corpus, its nested folder (below its one level).
REFUSED_FOLDERS = {"lessons": ("", "sub"),
                   "catalog": ("", ".dotsys", ".dotsys/_draft", "wazuh", "wazuh/_draft",
                               "_draft", "wazuh/notes", "wazuh/_draft/deeper")}
#: The folders the selection reads from: refusing one costs its records and one warning.
SELECTED_FOLDERS = (".dotsys", ".dotsys/_draft", "wazuh", "wazuh/_draft", "_draft")
#: Folders no listing may reach: the corpus is listed one level deep (`depth=1`), so its nested
#: folder is a row and is never listed; the catalog three (`depth=3`), so a folder at the third
#: level is a row and is never listed. Refusing one must cost nothing, and the seam must never
#: be asked for it.
NEVER_ENTERED = ("sub", "wazuh/_draft/deeper")
#: The errnos a refusal row refuses with. EACCES and EIO make the folder's listing refused, its
#: reason `strerror` verbatim; ENOENT on the `step` or `reopen` route makes it gone (`entries()`
#: answers absent): a folder its parent listed as a directory and found missing by its own
#: listing. (ENOENT from `scandir` of an open descriptor is no real fault; not driven.)
REFUSAL_ERRNOS = (errno.EACCES, errno.EIO, errno.ENOENT)

REFUSAL_ROWS = [
    pytest.param(reader, folder, route, form, err,
                 id=f"{reader.name}-{folder or 'top'}-{route}-{form}-{errno.errorcode[err]}")
    for reader in READERS
    for folder in REFUSED_FOLDERS[reader.tree]
    for route in REFUSAL_ROUTES
    for form in BOUND_FORMS
    for err in REFUSAL_ERRNOS
    # `hold` opens its root by spelling and raises on a refusal: not the reader's to answer.
    if not (folder == "" and route == "step" and form == "held-view")
    and not (err == errno.ENOENT and route == "scandir")
]


def refusal_outcome(reader: Reader, folder: str, err: int,
                    where: Path) -> tuple[list[str] | None, list[str]]:
    """`(records kept, or None for nothing yielded, the warnings)` when `folder` (relative to
    the listed folder) is refused with `err` (ENOENT: found gone). A refused folder the
    selection reads from costs its records and ONE warning naming it, with the listing's reason
    verbatim; the listed folder itself, everything and ONE warning naming `where`. A gone one
    (or a gone listed folder: absent) costs the same records and warns nothing. A folder the
    selection never reads from costs nothing either way."""
    shape = TREES[reader.tree]
    rel = f"{shape.top}/{folder}" if folder else shape.top
    warned = err != errno.ENOENT
    if folder in NEVER_ENTERED:
        return list(shape.records), []
    if folder == "":
        return None, [f"warn: skipping {where} ({os.strerror(err)})"] if warned else []
    if folder in SELECTED_FOLDERS:
        return ([r for r in shape.records if not under(r, rel)],
                [f"warn: skipping {where}/{folder} ({os.strerror(err)})"] if warned else [])
    return list(shape.records), []


@pytest.mark.parametrize(("reader", "folder", "route", "form", "err"), REFUSAL_ROWS)
def test_a_refused_listing_warns_once_and_yields_what_it_should(
        scene, reader, folder, route, form, err, caplog):
    """A `<sys>` or `_draft` folder whose own listing is refused (EACCES or EIO, on any route:
    the listing's `refused`): exactly ONE `warn: skipping <where>/<name> (<strerror>)`, and
    every other record, the other systems' included, yields exactly. The same folder found gone
    by its own listing (ENOENT: the listing's `gone`): its records, and no warning, as a missing
    folder never warned. At a folder the selection never reads from: silent, the whole tree. At
    the listed folder itself: one `warn: skipping <where> (<strerror>)` and nothing, or, gone,
    nothing and silence. A folder below the listing's depth is never entered: the seam is never
    asked for it, and it costs nothing. Never a raise. Control: the same form over the real `os`
    yields the whole tree, silently."""
    shape = TREES[reader.tree]
    where = scene.t / shape.top
    seam = RefusesFolder(where / folder if folder else where, route, err)
    kept, warnings = refusal_outcome(reader, folder, err, where)
    caplog.clear()
    with called_as(scene, reader.tree, form, os_=seam) as (arg, kw):
        got = in_time(lambda: reader.run(arg, kw))

    assert got == ([] if kept is None else reader.expected(where, kept))
    assert said(caplog) == warnings
    if folder in NEVER_ENTERED:
        assert seam.asked == 0, f"{folder} lies below the listing's depth, yet was entered"
    else:
        # Exactly once (v3 adversary hole V3-H1): the listing's verdict is the one the reader
        # keeps; a reader that listed the folder again could hear a different answer.
        assert seam.asked == 1, (
            f"the folder was asked for {seam.asked} times; its one listing decides")
    caplog.clear()
    with called_as(scene, reader.tree, form) as (arg, kw):
        assert in_time(lambda: reader.run(arg, kw)) == reader.expected(where, shape.records)
    assert said(caplog) == []


# -- a folder REALLY swapped between its parent's listing and its own -----------------------

#: The catalog folders the swap rows move out of the tree, relative to the catalog: the system
#: that sorts first, the one that sorts last, and a `_draft` folder.
SWAP_SITES = (".dotsys", "wazuh", "wazuh/_draft")
#: What each plant left at a swapped folder's name makes of its own listing: the reason it is
#: refused with (a link is `_step`'s ELOOP, a file or FIFO its ENOTDIR), or None: gone.
SWAP_REASON = {"link": ALIAS, "file": NOT_A_DIR, "fifo": NOT_A_DIR, "nothing": None}
SWAP_BETWEEN_ROWS = [
    pytest.param(reader, site, plant, form, id=f"{reader.name}-{site}-{plant}-{form}")
    for reader in CATALOG_READERS
    for site in SWAP_SITES
    for plant in SWAP_PLANTS
    for form in BOUND_FORMS
]


@pytest.mark.parametrize(("reader", "site", "plant", "form"), SWAP_BETWEEN_ROWS)
def test_a_folder_swapped_between_listings_is_refused_or_gone_and_never_listed_through(
        scene, reader, site, plant, form, caplog):
    """The catalog's own listing shows `site` as a real directory. The moment the reader's
    listing of `site` itself steps into it, the folder is REALLY moved out of the tree and a
    link to a folder of marked records, a file, a FIFO or nothing is left at its name. The
    folder's listing meets the plant: refused (a link, a file, a FIFO), which costs ONE
    `warn: skipping <where>/<site> (<the listing's reason>)`, or gone (nothing there), which is
    silent, as a missing folder always was (a declared choice). Either way its records are
    gone, every other record yields exactly, and nothing below the plant is listed or read: the
    kernel saw no open or listing of the link's target, of any marked record in it, or of the
    moved folder (watched by its inode before the move), and no mark reaches the answer.
    Control: the folder moved back, the same call yields the whole catalog, silently."""
    shape = TREES["catalog"]
    where = scene.t / shape.top
    rel = f"{CATALOG}/{site}"
    real = scene.t / rel
    target = None
    if plant == "link":
        target = scene.host / f"swap-target-{real.name}"
        scene.put([r for r in FILES if under(r, rel)], base=target, site=rel)
        for r in (*FILES, *PROBE_TEXT):
            if under(r, rel) and r.endswith(".md"):
                (target / below(r, rel)).parent.mkdir(parents=True, exist_ok=True)
                (target / below(r, rel)).write_text(HOST_TEXT["catalog"], encoding="utf-8")
    watched = [Path(d) for d, _dirs, _files in os.walk(real)]
    if target is not None:
        watched += [Path(d) for d, _dirs, _files in os.walk(target)]
    marked = [] if target is None else [
        Path(d) / f for d, _dirs, files in os.walk(target) for f in files]
    away = scene.tmp / f"away-{real.name}"
    seam = SwapsFolderBetweenListings(real.parent, real.name, away=away, plant=plant,
                                      target=target, body=HOST_TEXT["catalog"])
    caplog.clear()
    with called_as(scene, "catalog", form, os_=seam) as (arg, kw):
        with kernel_watch(reads=marked, opens=watched) as events:
            got = in_time(lambda: reader.run(arg, kw),
                          fifo=real if plant == "fifo" else None)
            seen = events()
        warned = said(caplog)

        assert seam.fired, "the folder was never stepped into, so the row is void"
        assert seen == [], f"the kernel saw the swapped folder or the plant's target read: {seen}"
        for mark in MARKS:
            assert mark not in repr(got) + repr(warned), f"a planted target was read: {got!r}"
        assert got == reader.expected(where, [r for r in shape.records if not under(r, rel)])
        reason = SWAP_REASON[plant]
        assert warned == ([] if reason is None else [f"warn: skipping {where}/{site} ({reason})"])

        if plant != "nothing":
            real.unlink()
        away.rename(real)
        caplog.clear()
        assert in_time(lambda: reader.run(arg, kw)) == reader.expected(where, shape.records)
    assert said(caplog) == []


@pytest.mark.parametrize("route", REFUSAL_ROUTES)
@pytest.mark.parametrize("form", BOUND_FORMS)
@pytest.mark.parametrize("reader", CATALOG_READERS, ids=reader_id)
def test_an_unlistable_directory_at_a_record_name_is_a_refused_record_not_a_folder(
        scene, reader, form, route, caplog):
    """`<sys>/probe.md` is a directory whose own listing is refused (in the listing's
    `refused`). It is still a SELECTED name: the read refuses it (a directory, or `Permission denied` when the
    seam refuses the open itself), and it costs the malformed-template warning, never a folder
    warning."""
    shape = TREES["catalog"]
    probe = shape.probes[0]
    (scene.t / probe).mkdir()
    (scene.t / probe / "inner.md").write_text(PROBE_TEXT[probe], encoding="utf-8")
    seam = RefusesFolder(scene.t / probe, route, errno.EACCES)
    caplog.clear()
    with called_as(scene, "catalog", form, os_=seam) as (arg, kw):
        got = in_time(lambda: reader.run(arg, kw))

    assert seam.refused, "the seam refused nothing, so the row is void"
    assert got == reader.expected(scene.t / shape.top, shape.records)
    reason = DENIED if route == "step" else ALIAS
    assert said(caplog) == [f"warn: skipping {probe_id(probe)} (malformed template: {reason})"]


# -- a folder unreadable for real, read as an unprivileged user ------------------------------

#: Each case: a tree, and the folder (relative to the walked folder) made mode 0o000.
PERM_CASES: dict[str, tuple[str, str]] = {
    "catalog-sys-first": ("catalog", ".dotsys"),
    "catalog-sys": ("catalog", "wazuh"),
    "catalog-draft": ("catalog", "wazuh/_draft"),
    "catalog-top-level-draft": ("catalog", "_draft"),
    "catalog-middle": ("catalog", "wazuh/notes"),
    "catalog-top": ("catalog", ""),
    "lessons-top": ("lessons", ""),
    "lessons-nested": ("lessons", "sub"),
}
PERM_FORMS = ("path", "bound", "held-view-under")
#: Each case: a tree, and one plain RECORD in it (relative to the walked folder) made mode 0o000:
#: it exists, the walk lists it, and only its open is refused (H2: a Path form that judged the
#: name by `lstat` and read it by its path would word the fault as today's `[Errno 13] ...`).
PERM_RECORDS: dict[str, tuple[str, str]] = {
    "lessons-record": ("lessons", "alpha.md"),
    "catalog-record": ("catalog", "wazuh/auth-events.md"),
}
#: `read_query_template`'s forms in the real-permission run.
PERM_RQT_FORMS = ("path", "bound")
PERM_RECORD_ROWS = [
    pytest.param(case, reader, form, id=f"{case}-{reader.name}-{form}")
    for case, (tree, _rel) in PERM_RECORDS.items()
    for reader in READERS if reader.tree == tree
    for form in PERM_FORMS
]
PERM_ROWS = [
    pytest.param(case, reader, form, id=f"{case}-{reader.name}-{form}")
    for case, (tree, _folder) in PERM_CASES.items()
    for reader in READERS if reader.tree == tree
    for form in PERM_FORMS
]


def reader_scenarios(tmp: Path, case: str, tree: str,
                     forms: Iterable[str]) -> list[dict[str, Any]]:
    """`FILES` built under `tmp/t`, and one child scenario per reader of `tree` per form."""
    Scene(tmp).put(FILES)
    shape = TREES[tree]
    t = tmp / "t"
    return [{"id": f"{case}-{reader.name}-{form}", "reader": reader.name, "form": form,
             "top": str(t / shape.top), "mount": str(t / shape.mount), "prefix": shape.folder}
            for reader in READERS if reader.tree == tree for form in forms]


def rqt_scenarios(tmp: Path, case: str, rel: str, forms: Iterable[str]) -> list[dict[str, Any]]:
    """One child scenario per form of `read_query_template` of the catalog's `rel` under
    `tmp/t`: the bare Path `file`, or `bind(top)` with `name`."""
    top = tmp / "t" / CATALOG
    return [{"id": f"{case}-read_query_template-{form}", "reader": "read_query_template",
             "form": form, "top": str(top), "name": rel, "file": str(top / rel)}
            for form in forms]


def run_reader_child(scenarios: list[dict[str, Any]], mode: str = "unprivileged") -> dict[str, Any]:
    """`_shared_readers_1134.child` in a fresh interpreter over THIS tree's `defender`, under
    `CHILD_DEADLINE`: `unprivileged` (drop to `NOBODY` when root) or `audit`."""
    source = Path(_io.__file__).resolve().parents[1]
    path = [str(source), *([os.environ["PYTHONPATH"]] if os.environ.get("PYTHONPATH") else [])]
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(path), "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        done = subprocess.run(
            [sys.executable, "-c",
             "from defender.tests._shared_readers_1134 import child; child()"],
            input=json.dumps({"mode": mode, "scenarios": scenarios}), capture_output=True,
            text=True, env=env,
            cwd=source, timeout=CHILD_DEADLINE, check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"the reader child did not finish within {CHILD_DEADLINE}s")
    assert done.returncode == 0, f"the reader child failed: {done.stderr[-4000:]}"
    answer = json.loads(done.stdout)
    assert "child_failed" not in answer, answer
    return answer


def _open_up(top: Path) -> None:
    """Every folder at or under `top` back to 0o755, each before it is walked into."""
    os.chmod(top, 0o755)
    for dirpath, dirnames, _files in os.walk(top):
        for d in dirnames:
            with contextlib.suppress(OSError):
                os.chmod(Path(dirpath) / d, 0o755)  # the permission trees hold no link


@pytest.fixture(scope="module")
def unprivileged_reads(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Path, dict]]:
    """Every `PERM_ROWS` and `PERM_RECORD_ROWS` scenario, each case's folder or record made
    0o000 for real (and `read_query_template` of that record), run as an
    unprivileged user: in-process when this process is not root (CI); as root, in a child that
    drops to `NOBODY` after its imports, over a tree under `/tmp` it can reach (pytest's own tmp
    chain is 0700 to root) and owns. Answers the trees' base and the run's JSON."""
    as_root = os.geteuid() == 0
    base = (Path(tempfile.mkdtemp(prefix="shared-readers-1134-", dir="/tmp")) if as_root
            else tmp_path_factory.mktemp("shared-readers-1134"))
    try:
        os.chmod(base, 0o755)
        scenarios = []
        for case, (tree, rel) in {**PERM_CASES, **PERM_RECORDS}.items():
            scenarios += reader_scenarios(base / case, case, tree, PERM_FORMS)
            if case in PERM_RECORDS and tree == "catalog":
                scenarios += rqt_scenarios(base / case, case, rel, PERM_RQT_FORMS)
        if as_root:
            for dirpath, dirs, files in os.walk(base):
                for entry in (".", *dirs, *files):
                    os.lchown(Path(dirpath) / entry, NOBODY, NOBODY)
        for case, (tree, folder) in PERM_CASES.items():
            top = base / case / "t" / TREES[tree].top
            os.chmod(top / folder if folder else top, 0)
        for case, (tree, rel) in PERM_RECORDS.items():
            os.chmod(base / case / "t" / TREES[tree].top / rel, 0)
        answer = run_reader_child(scenarios) if as_root else run_readers(scenarios, drop=False)
        yield base, answer
    finally:
        _open_up(base)
        shutil.rmtree(base, ignore_errors=True)


def test_the_real_permission_rows_ran_unprivileged(unprivileged_reads):
    """Non-vacuity: root's override would list anything."""
    _base, answer = unprivileged_reads
    assert answer["uid"] != 0
    assert answer["uid"] == (NOBODY if os.geteuid() == 0 else os.geteuid())


@pytest.mark.parametrize(("case", "reader", "form"), PERM_ROWS)
def test_a_folder_unreadable_for_real_warns_once_and_the_rest_yields(
        unprivileged_reads, case, reader, form):
    """Through the real `os`, as the drain's unprivileged owner would read it: a `<sys>`, a
    `<sys>/_draft` or a top-level `_draft` folder of mode 0o000 costs exactly its records and
    ONE `warn: skipping <where>/<name> (Permission denied)`; the walked folder itself, ONE
    `warn: skipping <where> (Permission denied)` and nothing; a folder the selection never
    reads from, nothing at all. The bare Path form too."""
    base, answer = unprivileged_reads
    tree, folder = PERM_CASES[case]
    shape = TREES[tree]
    t = base / case / "t"
    where = t / shape.top
    row = answer["rows"][f"{case}-{reader.name}-{form}"]
    assert "raised" not in row, row["raised"]
    kept, warnings = refusal_outcome(reader, folder, errno.EACCES, where)

    want = [] if kept is None else [
        project_record(reader.name, reader.record(where / below(rel, shape.top), TEXT[rel]))
        for rel in sorted(kept, key=lambda rel: PurePosixPath(rel).parts)]
    assert row["records"] == want
    assert row["warnings"] == warnings


@pytest.mark.parametrize(("case", "reader", "form"), PERM_RECORD_ROWS)
def test_a_plain_record_unreadable_for_real_is_skipped_with_strerror_alone(
        unprivileged_reads, case, reader, form):
    """H2, and a declared delta: a plain record of mode 0o000, read through the real `os` as an
    unprivileged user, in the bare Path form too, is listed, refused at its open, and skipped
    with the read's reason, `strerror` alone (`Permission denied`), never today's
    `[Errno 13] Permission denied: '<path>'`. `iter_lesson_paths` only lists it. The rest
    yields."""
    base, answer = unprivileged_reads
    tree, rel = PERM_RECORDS[case]
    shape = TREES[tree]
    where = base / case / "t" / shape.top
    row = answer["rows"][f"{case}-{reader.name}-{form}"]
    assert "raised" not in row, row["raised"]
    refused = f"{shape.top}/{rel}"
    kept = shape.records if not reader.reads else [r for r in shape.records if r != refused]

    assert row["records"] == [
        project_record(reader.name, reader.record(where / below(r, shape.top), TEXT[r]))
        for r in sorted(kept, key=lambda r: PurePosixPath(r).parts)]
    assert row["warnings"] == ([] if not reader.reads else [
        f"warn: skipping {PurePosixPath(rel).name} (malformed {shape.noun}: {DENIED})"])


@pytest.mark.parametrize("form", PERM_RQT_FORMS)
def test_read_query_template_of_a_template_unreadable_for_real_says_strerror_alone(
        unprivileged_reads, form):
    """The same for the one-file reader, the bare Path form included: `(None, "malformed
    template: Permission denied")`, and nothing logged."""
    _base, answer = unprivileged_reads
    row = answer["rows"][f"catalog-record-read_query_template-{form}"]
    assert "raised" not in row, row["raised"]
    assert row["records"] == [None, f"malformed template: {DENIED}"]
    assert row["warnings"] == []


# =======================================================================================
# `where` only spells: it is never opened
# =======================================================================================

@pytest.mark.parametrize("where_is", ["nowhere", "decoy"])
@pytest.mark.parametrize("form", BOUND_FORMS)
@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_where_spells_the_bounds_records_and_is_never_opened(
        scene, reader, form, where_is, caplog):
    """The records come from the Bound and are spelled under `where`, whatever `where` names:
    a path that does not exist (nothing is created there), or a decoy tree holding a marked
    record at every selected name (never opened, never listed, never read)."""
    shape = TREES[reader.tree]
    where = (scene.tmp / "nowhere" / shape.top if where_is == "nowhere"
             else plant_decoy(scene, reader.tree))
    rec = SpellingRecorder()

    with called_as(scene, reader.tree, form, os_=rec) as (arg, _kw):
        got, warned = run_guarded(scene, lambda: reader.run(arg, {"where": where}),
                                  planted=None, caplog=caplog, recorder=rec)

    assert got == reader.expected(where, shape.records)
    assert warned == []
    assert not (scene.tmp / "nowhere").exists()


@pytest.mark.parametrize("where_is", ["nowhere", "decoy"])
@pytest.mark.parametrize("form", RQT_FORMS[1:])
def test_read_query_templates_where_only_spells_the_template(scene, form, where_is, caplog):
    probe = TREES["catalog"].probes[0]
    scene.put([probe])
    where_rel = rqt_where(probe, form)
    if where_is == "decoy":
        plant_decoy(scene, "catalog")
    where = (scene.tmp / "nowhere" if where_is == "nowhere" else scene.decoy) / where_rel
    rec = SpellingRecorder()

    with rqt_called_as(scene, probe, form, os_=rec, where=where) as (args, kw):
        got, warned = run_guarded(scene, lambda: read_query_template(*args, **kw),
                                  planted=None, caplog=caplog, recorder=rec)

    assert got == (template_record(where / below(probe, where_rel), PROBE_TEXT[probe]), "")
    assert warned == []
    assert not (scene.tmp / "nowhere").exists()


# =======================================================================================
# Lifetime
# =======================================================================================

@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_a_bound_passed_in_is_the_callers_and_stays_open(scene, reader):
    """The reader never closes a Bound it was handed, whether it ran to the end or a generator
    was closed after one record: the same Bound still lists and reads after."""
    shape = TREES[reader.tree]
    top = scene.t / shape.top
    first = below(shape.records[0], shape.top).as_posix()
    with bind(top) as bound:
        assert reader.run(bound, {"where": top}) == reader.expected(top, shape.records)
        it = iter(reader.call(bound, where=top))
        next(it)
        close = getattr(it, "close", None)
        if close is not None:
            close()
        after = bound.entries()
        assert (after.absent, after.reason) == (False, None), after
        assert after.entries
        assert bound.read(first).text == TEXT[shape.records[0]]


def test_read_query_template_leaves_a_bound_passed_in_open(scene):
    probe = TREES["catalog"].probes[0]
    scene.put([probe])
    with bind(scene.t / CATALOG) as bound:
        name = below(probe, CATALOG).as_posix()
        assert read_query_template(bound, name, where=scene.t / CATALOG) == rqt_expected(
            scene, probe)
        assert bound.read(name).text == PROBE_TEXT[probe]


#: Path-form calls that must leave no descriptor open when they return.
PATH_FORM_CALLS: dict[str, Callable[[Scene], Any]] = {
    "iter_lesson_paths": lambda s: iter_lesson_paths(s.t / "lessons"),
    "iter_lessons-exhausted": lambda s: list(iter_lessons(s.t / "lessons")),
    "iter_query_templates-exhausted": lambda s: list(iter_query_templates(s.t / CATALOG)),
    "load_catalog": lambda s: ln.load_catalog(s.t / CATALOG),
    "read_query_template": lambda s: read_query_template(s.t / CATALOG / "wazuh/auth-events.md"),
    "read_query_template-missing": lambda s: read_query_template(s.t / CATALOG / "wazuh/no.md"),
}


@pytest.mark.parametrize("call", list(PATH_FORM_CALLS))
def test_the_path_form_closes_its_handle_before_returning(scene, call):
    assert descriptors_under(scene.tmp) == []
    got = PATH_FORM_CALLS[call](scene)
    assert got
    assert descriptors_under(scene.tmp) == []


@pytest.mark.parametrize("ending", ["closed", "collected"])
@pytest.mark.parametrize("reader", [r for r in READING if r.name != "load_catalog"], ids=reader_id)
def test_a_path_form_generator_holds_nothing_before_it_starts_or_after_it_ends(
        scene, reader, ending):
    """The bind is in the generator's body: nothing is open before the first `next`, and the
    handle is closed when the generator is closed or collected partway."""
    top = scene.t / TREES[reader.tree].top
    it = reader.call(top)
    assert descriptors_under(scene.tmp) == [], "the Path form bound before its first `next`"
    assert next(it) is not None
    if ending == "closed":
        it.close()
    else:
        del it
        gc.collect()
    assert descriptors_under(scene.tmp) == []


# =======================================================================================
# The root is the trust root: opened following its spelling (N-h), by design
# =======================================================================================

def root_as_link(scene: Scene, root_rel: str) -> None:
    """The folder at `root_rel` (`""` is `t`) moved beside `t` and a symlink left at its name."""
    at = scene.t / root_rel
    real = scene.tmp / f"real-{root_rel.replace('/', '-') or 't'}"
    at.rename(real)
    at.symlink_to(real, target_is_directory=True)


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_the_root_itself_is_opened_following_its_spelling(scene, reader, form, caplog):
    """Not a guard: a documented fact. The folder a form opens (the bare Path's own folder, a
    Bound's root, the held mount) is a trusted mount point, opened following its spelling, so a
    root that is itself a symlink reads its target's records, spelled under the link. A Path
    roots wherever it is pointed, which is why drain code never hands a shared reader one."""
    root_as_link(scene, form_root(reader.tree, form))

    assert_reads_the_whole_tree(scene, reader, form, caplog)


@pytest.mark.parametrize("form", RQT_FORMS)
@pytest.mark.parametrize("probe", TREES["catalog"].probes, ids=probe_id)
def test_read_query_template_opens_its_root_following_its_spelling(scene, probe, form, caplog):
    """The same fact for the one-file reader: a bare Path roots at its parent, so a linked
    `<sys>` or `_draft` folder above a bare Path is followed."""
    scene.put([probe])
    root_as_link(scene, rqt_root(probe, form))
    with rqt_called_as(scene, probe, form) as (args, kw):
        assert rqt_quietly(caplog, args, kw) == rqt_expected(scene, probe)


@pytest.mark.parametrize("kind", ["file", "fifo"])
@pytest.mark.parametrize("form", ["path", "bound"])
@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_a_non_directory_passed_as_the_root_warns_once_and_yields_nothing(
        scene, reader, form, kind, caplog):
    """A declared delta: the root a Path (or `bind`) is given is a regular file or a FIFO.
    Nothing yields, nothing raises, nothing blocks, and ONE `warn: skipping <path> (Not a
    directory)` (today: silent)."""
    top = scene.t / TREES[reader.tree].top
    shutil.rmtree(top)
    if kind == "file":
        top.write_text(HOST_TEXT[reader.tree], encoding="utf-8")
    else:
        os.mkfifo(top)
    planted = Planted(kind, top)

    with called_as(scene, reader.tree, form) as (arg, kw):
        got, warned = run_guarded(scene, lambda: reader.run(arg, kw), planted=planted,
                                  caplog=caplog)

    assert got == []
    assert warned == [f"warn: skipping {top} ({NOT_A_DIR})"]


# =======================================================================================
# The step-4 adversary's holes (H1-H7): rows added after the implementation
# =======================================================================================
#
# H1 (a non-plain `<sys>` ends the whole walk), H5 (`.md` anywhere in a name) and H7
# (`read_query_template` through a view under a prefix) are closed in the tables above: the
# `.dotsys` sites and refusal folders, the near-miss names in `FILES`, and the
# `held-view-under` form in `RQT_FORMS`. H4 (`read_query_template` logs) is closed by
# `rqt_quietly` and the empty-warning asserts in every `read_query_template` row.

# -- H2: the Path form reads through its held handle, never by a path it formats ------------

#: `(reader, the folder swapped for a link after the first record)`: the walked folder itself,
#: and a `<sys>` folder below it.
SWAP_ROWS = [
    pytest.param(BY_NAME[name], site, form, id=f"{name}-{PurePosixPath(site).name}-{form}")
    for name, site in (("iter_lessons", "lessons"), ("iter_query_templates", CATALOG),
                       ("iter_query_templates", f"{CATALOG}/wazuh"))
    for form in ("path", "bound")
]


def swap_for_marked_link(scene: Scene, site: str) -> Planted:
    """The real folder at `site` moved out of the tree (to `moved-<name>` beside `t`) and a link
    left at its name, to a folder under `host` holding a VALID record carrying `HOST_MARK` at
    every name the real one held."""
    at = scene.t / site
    at.rename(scene.tmp / f"moved-{at.name}")
    target = scene.host / f"swapped-{at.name}"
    for rel in FILES:
        if under(rel, site):
            marked = target / below(rel, site)
            marked.parent.mkdir(parents=True, exist_ok=True)
            marked.write_text(HOST_TEXT[tree_of(site)], encoding="utf-8")
    link_to(at, target)
    return Planted("link", at)


@pytest.mark.parametrize(("reader", "site", "form"), SWAP_ROWS)
def test_a_folder_swapped_for_a_link_mid_iteration_is_never_read_through(
        scene, reader, site, form, caplog):
    """H2: the walk lists the tree once, before the first record. Swap a folder for a link to
    marked records after that, and the rest is still read through the handle the reader holds,
    never by a path it formats (`where / name` would follow the link). The walked folder
    itself swapped: the held handle keeps reading the real folder (moved), so every record
    yields as today, spelled as before, silently. A `<sys>` folder swapped: each record listed
    under it is refused at its read (the link is never stepped through), with the alias
    warning, and every other record yields. Never a marked byte, by any route."""
    shape = TREES[reader.tree]
    where = scene.t / shape.top
    order = sorted(shape.records, key=lambda rel: PurePosixPath(rel).parts)
    with called_as(scene, reader.tree, form) as (arg, kw):
        it = reader.call(arg, **kw)
        first = in_time(lambda: next(it))
        planted = swap_for_marked_link(scene, site)
        rest, warned = run_guarded(scene, lambda: list(it), planted=planted, caplog=caplog)

    assert first == reader.record(where / below(order[0], shape.top), TEXT[order[0]])
    swapped = [rel for rel in order[1:] if strictly_below(rel, site) and site != shape.top]
    assert rest == reader.expected(where, [rel for rel in order[1:] if rel not in swapped])
    assert warned == [f"warn: skipping {PurePosixPath(rel).name} (malformed {shape.noun}: "
                      f"{ALIAS})" for rel in swapped]


#: The Path-form calls the open audit runs: each iterator over its tree, and
#: `read_query_template` of a template and of a draft.
AUDIT_RQT = ("wazuh/auth-events.md", "wazuh/_draft/novel.md")
AUDIT_IDS = [*(f"{reader.tree}-{reader.name}-path" for reader in READERS),
             *(f"catalog-read_query_template-path-{probe_id(rel)}" for rel in AUDIT_RQT)]


@pytest.fixture(scope="module")
def path_form_opens(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict, dict]:
    """Every Path-form call over a plain tree, run in a child interpreter with an audit hook
    recording every `open` by a name (the Path form has no `os_` seam to record through).
    Answers the tree's tmp dir, the scenarios by id, and the run's JSON."""
    tmp = tmp_path_factory.mktemp("path-form-opens-1134")
    scenarios = [*reader_scenarios(tmp, "lessons", "lessons", ("path",)),
                 *reader_scenarios(tmp, "catalog", "catalog", ("path",))]
    for rel in AUDIT_RQT:
        scenarios += [{**row, "id": f"{row['id']}-{probe_id(rel)}"}
                      for row in rqt_scenarios(tmp, "catalog", rel, ("path",))]
    assert sorted(row["id"] for row in scenarios) == sorted(AUDIT_IDS)
    return tmp, {row["id"]: row for row in scenarios}, run_reader_child(scenarios, mode="audit")


def following_opens(opens: list[list[Any]], root: str, tmp: str) -> list[list[Any]]:
    """The opens by a name that could follow a link below `root`: an absolute name under `tmp`
    but `root` itself (the root is opened following its spelling, by design), a relative name
    with a `/` in it, and a single name opened without `O_NOFOLLOW` but `.` (the reopen of a
    held folder for listing)."""
    bad = []
    for name, flags in opens:
        if name.startswith("/"):
            if name != root and name.startswith(f"{tmp}/"):
                bad.append([name, flags])
        elif "/" in name or (name != "." and (flags is None or not flags & os.O_NOFOLLOW)):
            bad.append([name, flags])
    return bad


@pytest.mark.parametrize("scenario_id", AUDIT_IDS)
def test_the_path_form_opens_nothing_below_its_root_by_a_spelling(path_form_opens, scenario_id):
    """H2, below the seam: in the bare Path form, the root (a `read_query_template` file's
    parent) is the one name opened as spelled; everything below it is opened one component at
    a time, no-follow, off a held folder. Never `where / name`, which would follow any link on
    the way. Non-vacuity: the hook saw the root's own open."""
    tmp, scenarios, answer = path_form_opens
    scenario = scenarios[scenario_id]
    row = answer["rows"][scenario_id]
    assert "raised" not in row, row["raised"]
    root = str(Path(scenario["file"]).parent if "file" in scenario else Path(scenario["top"]))

    assert [name for name, _flags in row["opens"] if name == root], (
        f"the audit never saw the root opened: {row['opens']}")
    assert following_opens(row["opens"], root, str(tmp)) == []
    assert row["warnings"] == []


# -- H3: a Bound whose folder is gone reads nothing, and never falls back to `where` -------

def plant_marked_tree(scene: Scene, at: Path, names: Iterable[PurePosixPath], tree: str,
                      what: str) -> list[Path]:
    """A tree of VALID records carrying `DECOY_MARK` at `at`, one at each of `names`: a real
    folder (`what="folder"`), or a link to one under `host`. Answers its folders."""
    base = at if what == "folder" else scene.host / f"marked-{at.name}"
    for name in names:
        record = base / name
        record.parent.mkdir(parents=True, exist_ok=True)
        record.write_text(DECOY_TEXT[tree], encoding="utf-8")
    if what == "link":
        at.parent.mkdir(parents=True, exist_ok=True)
        link_to(at, base)
    return [Path(d) for d, _dirs, _files in os.walk(base)]


@pytest.mark.parametrize("what", ["folder", "link"])
@pytest.mark.parametrize("form", ["bound", "held-view"])
@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_a_bound_whose_folder_is_gone_reads_nothing_and_never_falls_back_to_where(
        scene, reader, form, what, caplog):
    """H3: the folder a Bound holds is removed, and a marked tree (a real folder, or a link to
    one) is put at its spelling, `where`. The Bound answers absent: nothing, silently. `where`
    is never opened, listed or read to make up for it."""
    shape = TREES[reader.tree]
    top = scene.t / shape.top
    with called_as(scene, reader.tree, form) as (arg, kw):
        shutil.rmtree(top)
        folders = plant_marked_tree(
            scene, top, [below(rel, shape.top) for rel in (*shape.records, *shape.probes)],
            reader.tree, what)
        got, warned = run_guarded(scene, lambda: reader.run(arg, kw), planted=None,
                                  caplog=caplog, folders=folders)

    assert got == []
    assert warned == []


@pytest.mark.parametrize("what", ["folder", "link"])
@pytest.mark.parametrize("form", ["bound", "held", "held-view-under"])
@pytest.mark.parametrize("probe", TREES["catalog"].probes, ids=probe_id)
def test_read_query_template_through_a_bound_whose_folder_is_gone_never_reads_where(
        scene, probe, form, what, caplog):
    """H3 for the one-file reader: the folder the form opened is removed and a marked template
    put at `where / name` (in a real folder, or behind a link). The answer is today's absent
    text for `where / name`, nothing logged, and `where` never opened."""
    scene.put([probe])
    name = below(probe, rqt_where(probe, form))
    with rqt_called_as(scene, probe, form) as (args, kw):
        shutil.rmtree(scene.t / rqt_root(probe, form))
        folders = plant_marked_tree(scene, kw["where"], [name], "catalog", what)
        got, warned = run_guarded(scene, lambda: read_query_template(*args, **kw),
                                  planted=None, caplog=caplog, folders=folders)

    assert got == (None, f"malformed template: {gone(scene.t / probe)}")
    assert warned == []


# -- H6: the Path form spells what it was given, a relative path too -----------------------

@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_the_path_form_spells_a_relative_path_as_given(scene, reader, monkeypatch, caplog):
    """H6: a relative Path (the working directory is the tmp dir) spells every record relative,
    as today's `corpus_dir / name` does. Never made absolute."""
    monkeypatch.chdir(scene.tmp)
    shape = TREES[reader.tree]
    scene.put(shape.probes)
    top = Path("t") / shape.top
    caplog.clear()

    assert in_time(lambda: reader.run(top, {})) == reader.expected(
        top, (*shape.records, *shape.probes))
    assert said(caplog) == []


@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_the_path_form_spells_its_warnings_relative_as_given(scene, reader, monkeypatch, caplog):
    """H6 for the warnings: a relative root that is a regular file is warned as spelled; in the
    catalog, a `<sys>` link is warned as `<relative where>/<sys>`; in the corpus, a refused
    lesson reaches `on_skip` and `warn_label` relative."""
    monkeypatch.chdir(scene.tmp)
    shape = TREES[reader.tree]
    top = Path("t") / shape.top
    if reader.tree == "catalog":
        plant_folder_at(scene, f"{CATALOG}/wazuh", "link")
        caplog.clear()
        got = in_time(lambda: reader.run(top, {}))
        assert got == reader.expected(
            top, [r for r in shape.records if not under(r, f"{CATALOG}/wazuh")])
        assert said(caplog) == [f"warn: skipping {top}/wazuh ({NOT_A_PLAIN_FOLDER})"]
    elif reader.reads:
        plant_record(scene, shape.probes[0], "symlink")
        skipped: list[Path] = []
        caplog.clear()
        got = in_time(lambda: list(iter_lessons(top, warn_label=str, on_skip=skipped.append)))
        assert got == reader.expected(top, shape.records)
        assert skipped == [top / "mid.md"]
        assert said(caplog) == [f"warn: skipping {top}/mid.md (malformed lesson: {ALIAS})"]
    shutil.rmtree(scene.t / shape.top)
    (scene.t / shape.top).write_text(HOST_TEXT[reader.tree], encoding="utf-8")
    caplog.clear()
    assert in_time(lambda: reader.run(top, {})) == []
    assert said(caplog) == [f"warn: skipping {top} ({NOT_A_DIR})"]


@pytest.mark.parametrize("missing", [False, True], ids=["present", "missing"])
@pytest.mark.parametrize("probe", TREES["catalog"].probes, ids=probe_id)
def test_read_query_template_spells_a_relative_path_as_given(
        scene, probe, missing, monkeypatch, caplog):
    """H6 for the one-file reader: the template's `path`, and a missing one's fault text, keep
    the relative spelling it was given."""
    monkeypatch.chdir(scene.tmp)
    if not missing:
        scene.put([probe])
    path = Path("t") / probe

    got = rqt_quietly(caplog, (path,), {})

    assert got == ((None, f"malformed template: {gone(path)}") if missing
                   else (template_record(path, PROBE_TEXT[probe]), ""))


# =======================================================================================
# The v3 step-4 adversary's holes (V3-H1 to V3-H5): rows added after the implementation
# =======================================================================================
#
# Each was checked red against the adversary's green-but-wrong reader (scratchpad
# `adv1134v3s4/`) and green against the implementation. V3-H1's other half is the exactly-once
# assert in `test_a_refused_listing_warns_once_and_yields_what_it_should`.

@pytest.mark.parametrize("route", REFUSAL_ROUTES)
@pytest.mark.parametrize("form", BOUND_FORMS)
@pytest.mark.parametrize("reader", CATALOG_READERS, ids=reader_id)
def test_a_folder_refused_once_is_warned_from_that_one_listing(scene, reader, form, route, caplog):
    """V3-H1: a reader that ignored `refused` and listed each `<sys>` again to see whether to
    warn passed every row whose refusal is permanent. Here `wazuh`'s listing is refused with EIO
    the FIRST time only (a transient fault); asked again it would list. The reader keeps what
    its one listing said: wazuh's records are gone, and ONE warning names it with that reason.
    Never silence, never wazuh's records."""
    shape = TREES["catalog"]
    where = scene.t / shape.top
    seam = RefusesFolder(where / "wazuh", route, errno.EIO, once=True)
    caplog.clear()
    with called_as(scene, "catalog", form, os_=seam) as (arg, kw):
        got = in_time(lambda: reader.run(arg, kw))

    assert seam.refused == 1, "the seam refused nothing, so the row is void"
    assert got == reader.expected(where, [r for r in shape.records
                                          if not under(r, f"{CATALOG}/wazuh")])
    assert said(caplog) == [f"warn: skipping {where}/wazuh ({os.strerror(errno.EIO)})"]
    assert seam.asked == 1, f"wazuh was listed {seam.asked} times; its one listing decides"


#: Errnos outside the ones every other row uses (V3-H2): whatever `entries()` says is the reason.
UNCOMMON_ERRNOS = (errno.ENOMEM, errno.EMFILE, errno.ESTALE, errno.ENOTCONN)


@pytest.mark.parametrize("err", UNCOMMON_ERRNOS, ids=errno.errorcode.get)
@pytest.mark.parametrize("route", ["reopen", "scandir"])
@pytest.mark.parametrize("form", BOUND_FORMS)
@pytest.mark.parametrize("site", ["wazuh", "wazuh/_draft"])
def test_a_refused_folders_reason_is_the_listings_verbatim_whatever_the_errno(
        scene, site, form, route, err, caplog):
    """V3-H2: a reader that passed through only the reasons the other rows produce (EACCES, EIO,
    ENOTDIR, the alias sentence) and rewrote the rest passed them all. Any errno's `strerror`
    reaches the warning verbatim."""
    reader = BY_NAME["iter_query_templates"]
    shape = TREES["catalog"]
    where = scene.t / shape.top
    seam = RefusesFolder(where / site, route, err)
    caplog.clear()
    with called_as(scene, "catalog", form, os_=seam) as (arg, kw):
        got = in_time(lambda: reader.run(arg, kw))

    assert seam.refused == 1
    assert got == reader.expected(where, [r for r in shape.records
                                          if not under(r, f"{CATALOG}/{site}")])
    assert said(caplog) == [f"warn: skipping {where}/{site} ({os.strerror(err)})"]


#: Two folder faults in one catalog (V3-H3), each `(site, fault)`: a fault is a seam refusal
#: (`"EIO"`), found gone (`"gone"`), or a plant left by the parent listing (`"fifo"`, `"link"`).
TWO_FAULTS = {
    "refused-first": ((".dotsys", "EIO"), ("wazuh", "fifo")),
    "other-first": ((".dotsys", "link"), ("wazuh", "EIO")),
    "draft-refused-after-sys-other": ((".dotsys", "fifo"), ("wazuh/_draft", "EIO")),
    "gone-between": ((".dotsys", "EIO"), ("cmdb", "gone"), ("wazuh", "fifo")),
}


@pytest.mark.parametrize("form", BOUND_FORMS)
@pytest.mark.parametrize("case", list(TWO_FAULTS))
@pytest.mark.parametrize("reader", CATALOG_READERS, ids=reader_id)
def test_several_folder_faults_warn_once_each_in_path_order(scene, reader, case, form, caplog):
    """V3-H3: every other folder row plants ONE fault, so a reader that warned its refused
    folders after its non-plain ones, or in any order but the catalog's, passed. With several,
    the warnings are exactly one per warned folder, in path-parts order; a gone one is silent;
    every system without a fault yields."""
    shape = TREES["catalog"]
    where = scene.t / shape.top
    seams: list[RefusesFolder] = []
    warnings: list[str] = []
    for site, fault in TWO_FAULTS[case]:
        if fault in ("fifo", "link"):
            plant_folder_at(scene, f"{CATALOG}/{site}", fault)
            warnings.append(f"warn: skipping {where}/{site} ({NOT_A_PLAIN_FOLDER})")
        elif fault == "EIO":
            seams.append(RefusesFolder(where / site, "scandir", errno.EIO))
            warnings.append(f"warn: skipping {where}/{site} ({os.strerror(errno.EIO)})")
        else:
            seams.append(RefusesFolder(where / site, "reopen", errno.ENOENT))
    faulted = [f"{CATALOG}/{site}" for site, _fault in TWO_FAULTS[case]]
    caplog.clear()
    with called_as(scene, "catalog", form, os_=RefusesFolders(seams)) as (arg, kw):
        got = in_time(lambda: reader.run(arg, kw))

    assert all(seam.refused == 1 for seam in seams), [seam.refused for seam in seams]
    assert got == reader.expected(where, [r for r in shape.records
                                          if not any(under(r, f) for f in faulted)])
    assert said(caplog) == warnings


#: Per tree, `(a folder below the listing's depth, a folder the listing must list)`, relative
#: to the listed folder: the corpus is listed one level deep, so `sub/` is a row and never
#: listed (the corpus itself is the control); the catalog three, so `wazuh/notes` (level 2) is
#: listed and `wazuh/_draft/deeper` (level 3) is not.
BELOW_THE_SHAPE = {"lessons": ("sub", ""), "catalog": ("wazuh/_draft/deeper", "wazuh/notes")}


@pytest.mark.parametrize("reader", READERS, ids=reader_id)
def test_the_path_form_never_lists_a_folder_below_the_shape(scene, reader, caplog):
    """V3-H4: the never-entered rows run through an `os_` seam, which the bare Path form has
    not, so a Path form that listed one level deeper than the shape passed. The kernel watch
    sees the Path form list the folder it must list (non-vacuity) and never open or list the
    one below the shape."""
    shape = TREES[reader.tree]
    top = scene.t / shape.top
    deep, listed = BELOW_THE_SHAPE[reader.tree]
    control = top / listed if listed else top
    with kernel_watch(opens=[top / deep, control]) as events:
        got = in_time(lambda: reader.run(top, {}))
        seen = events()

    assert got == reader.expected(top, shape.records)
    assert (str(control), "open") in seen, f"the watch never saw {control} listed: {seen}"
    assert [e for e in seen if e[0].startswith(str(top / deep))] == [], (
        f"{deep} lies below the listing's depth, yet was opened: {seen}")


@pytest.mark.parametrize("reader", [r for r in READING if r.name != "load_catalog"], ids=reader_id)
def test_a_path_form_generator_lists_nothing_before_its_first_next(scene, reader):
    """V3-H5: the descriptor-count row could not see a Path form that bound and listed at call
    time, closed that, and bound again in the generator body (names from one moment, records
    from another). The kernel watch on the root sees no listing before the first `next`, and
    sees one after it (non-vacuity)."""
    top = scene.t / TREES[reader.tree].top
    with kernel_watch(opens=[top]) as events:
        it = reader.call(top)
        before = events()
        assert next(it) is not None
        after = events()
        it.close()

    assert before == [], f"the Path form listed before its first `next`: {before}"
    assert (str(top), "open") in after, f"the watch never saw {top} listed: {after}"
