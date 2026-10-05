"""The open-trees plumbing for #1134's curator step (v3, ported from v2) and the world its new
test files share. It defines no tests.

The curator step moves the corpus-author drain (`learning/author/drain.py`, `shared.py`, both
channel modules) onto the author drain's held mounts: the label is consumed where the trees open
(`drains._maybe_trigger_author`, each channel's `main()`, the eval harness), and below that the
open `DrainTrees` flows. `build_author_config` / `build_questioner_config` take `trees=` (required)
and put two fields on the config: `corpus`, the held corpus mount (`trees.mount(corpus_dir)`), and
`tree_for`, the trees' own lookup. Everything the drain does to a corpus goes through those:
writes and deletes through the `Held`, reads through its view. Every existing caller in
`defender/tests` changes in call shape only (owner decisions 1 and 2 of 2026-09-29), and this
module is the one home of the trees those calls run inside.

Lifetime, the one rule here (as in `_lead_author_1134`). A `Held` closed under a reader does not
raise: the reader answers `Bad file descriptor` as a refusal, which reads as "absent" or
"refused", a silent wrong answer. So every call these helpers serve runs inside trees that are
open:

* `author_trees(paths)` opens the author drain's trees over `paths` exactly as the lane does
  (`open_drain_trees(paths, AUTHOR_DRAIN_LABEL)`), after making any mount point that is missing:
  a drain working copy always has both corpora, a fixture repo may not (`_drain719.make_repo`
  has no `lessons-questioner/`). It is a `DrainTrees`, so `with author_trees(paths) as trees:`
  scopes them; passed inline (`trees=author_trees(paths)`) it stays open for the call it is handed
  to, and for as long as the config built from it is referenced.
* Every other helper hands back an object that REFERENCES the open trees: a config holding the
  `Held` and the bound `tree_for`, a bound `tree_for`, a `Held`, a view. The descriptors stay open
  exactly as long as that object is referenced and are released when it is collected (CPython's
  refcount; `_io._Handle.__del__` closes each).

Fakes for the new tests enter only through injection seams: the `os_` of `DrainTrees.open` /
`hold` (`RecordingOs`, `FailsOn`, and `_shared_readers_1134.RefusesFolder`), or a `Held` handed in
with `dataclasses.replace(cfg, corpus=...)` (`JournalHeld`, a real `Held` subclass: the config is
a strict pydantic model, so anything else is refused at the replace). Nothing is monkeypatched.

Module-level imports are production modules and stdlib-only test helpers, so `_drain719`,
`_spec773` and `conftest` can import from here without a cycle; `world()` imports `_drain719`
when it is called.
"""
from __future__ import annotations

import dataclasses
import logging
import os
import re
import shutil
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender._io import Bound, Held, NotPlainEntry, RecordRead, hold, open_unnamed_at
from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees
from defender.tests._tree_listing_1134 import RealOs, fd_path, last_component

#: The type `DrainTrees.tree_for` has (bound): a working-copy path to `(held mount, name)`, or
#: `None` outside the lane's mounts.
TreeForFn = Callable[[Path | str], "tuple[Held, str] | None"]


# ---------------------------------------------------------------------------------------
# The trees, open
# ---------------------------------------------------------------------------------------


def make_mount_points(paths: LoopPaths) -> None:
    """Make each of the author label's mount points under `paths` that is missing (a drain
    working copy always has both; a fixture repo may lack `lessons-questioner/`). An empty folder
    is invisible to `git status`, so this changes no fixture's tree as git sees it."""
    for mount in AUTHOR_DRAIN_LABEL.writable_trees(paths):
        mount.mkdir(parents=True, exist_ok=True)


def author_trees(paths: LoopPaths) -> DrainTrees:
    """The author drain's trees over `paths`, open: `open_drain_trees(paths, AUTHOR_DRAIN_LABEL)`,
    the two held corpus mounts both curators work through, after `make_mount_points`."""
    make_mount_points(paths)
    return open_drain_trees(paths, AUTHOR_DRAIN_LABEL)


def seamed_trees(paths: LoopPaths, os_: Any) -> DrainTrees:
    """`author_trees`, but held over `os_` (`DrainTrees.open(..., os_=os_)`): every verb and read
    of each mount then goes through that seam. How a fault no root process can make for real
    (EACCES, EIO, ENOSPC) reaches the drain."""
    make_mount_points(paths)
    return DrainTrees.open(AUTHOR_DRAIN_LABEL.writable_trees(paths), os_=os_)


def author_cfg(paths: LoopPaths, *, trees: DrainTrees | None = None, manifest_seed: str | None = None,
               box: Any = None, **replaced: Any) -> Any:
    """The REAL lessons config: `build_author_config(paths, trees=<trees, else author_trees(paths)>,
    manifest_seed=..., box=...)`, with the `replaced` fields swapped in (`dataclasses.replace`)."""
    from defender.learning.author.lessons import run as lessons_run

    cfg = lessons_run.build_author_config(
        paths, trees=trees if trees is not None else author_trees(paths),
        manifest_seed=manifest_seed, box=box)
    return dataclasses.replace(cfg, **replaced) if replaced else cfg


def questioner_cfg(paths: LoopPaths, *, trees: DrainTrees | None = None,
                   manifest_seed: str | None = None, box: Any = None, **replaced: Any) -> Any:
    """The REAL questioner config, as `author_cfg` builds the lessons one."""
    from defender.learning.author.questioner import run as questioner_run

    cfg = questioner_run.build_questioner_config(
        paths, trees=trees if trees is not None else author_trees(paths),
        manifest_seed=manifest_seed, box=box)
    return dataclasses.replace(cfg, **replaced) if replaced else cfg


def held_corpus(root: Path) -> Held:
    """`root` held as a corpus mount is (made first if missing: a drain's mount point always
    exists), for a call that takes the corpus `Held` by itself."""
    root.mkdir(parents=True, exist_ok=True)
    return hold(root)


def corpus_view(root: Path) -> Bound:
    """The view of `root` held as a corpus mount: what `build_curator_user_prompt(corpus=...)`
    takes, with `corpus_dir=root` as its spelling."""
    return held_corpus(root).view()


# ---------------------------------------------------------------------------------------
# Plants: real filesystem entries, never a stand-in
# ---------------------------------------------------------------------------------------

#: What every link target, hard link's other name and moved folder carries (and every plain
#: control at the same address): a reader that followed the plant would put it in its answer.
OUT_MARK = "outside-bytes-1134-c5"

LESSONS_REL = "defender/lessons/"
SIBLING_REL = "defender/lessons-questioner/"


def lesson_text(*ids: str, mark: str = "", **frontmatter: Any) -> str:
    """A corpus lesson citing `ids` under the findings channel's provenance key."""
    lines = ["---", "source_finding_ids:", *[f"- {i}" for i in ids]]
    lines += [f"{k}: {v}" for k, v in frontmatter.items()]
    lines += ["---", "", f"the lesson body {mark}".rstrip(), ""]
    return "\n".join(lines)


def clear(at: Path) -> None:
    """Remove whatever stands at `at` (a link as itself, never followed)."""
    if at.is_symlink() or (os.path.lexists(at) and not at.is_dir()):
        at.unlink()
    elif at.is_dir():
        shutil.rmtree(at)


def put(at: Path, data: str | bytes) -> None:
    """A plain file at `at` holding `data`, replacing whatever stood there."""
    clear(at)
    at.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        at.write_bytes(data)
    else:
        at.write_text(data, encoding="utf-8")


def plant_link(at: Path, target: Path) -> None:
    clear(at)
    at.parent.mkdir(parents=True, exist_ok=True)
    at.symlink_to(target, target_is_directory=target.is_dir())


def plant_hardlink(at: Path, target: Path) -> None:
    clear(at)
    at.parent.mkdir(parents=True, exist_ok=True)
    os.link(target, at)


def plant_fifo(at: Path) -> None:
    clear(at)
    at.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(at)


def plant_socket(at: Path) -> None:
    """A UNIX socket bound at `at`. `bind` takes a path of at most 107 bytes, which a pytest tmp
    path overruns, so the bind names the folder by a descriptor (`/proc/self/fd/<fd>/<name>`):
    the kernel resolves that folder and makes the socket in it."""
    clear(at)
    at.parent.mkdir(parents=True, exist_ok=True)
    folder = os.open(at.parent, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with socket.socket(socket.AF_UNIX) as s:
            s.bind(f"/proc/self/fd/{folder}/{at.name}")
    finally:
        os.close(folder)


def plant_folder(at: Path) -> None:
    """A real folder at `at` (holding one plain file), where a file is expected."""
    clear(at)
    at.mkdir(parents=True)
    (at / "inner.md").write_text("inside a folder planted at a file's name\n", encoding="utf-8")


def move_out_and_link(folder: Path, moved: Path) -> None:
    """The real `folder` moved to `moved` (outside the repo) and a symlink to it left in its
    place: everything it held is now reachable only by following the link."""
    moved.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(folder), str(moved))
    folder.symlink_to(moved, target_is_directory=True)


def is_link_to(at: Path, target: Path) -> bool:
    return os.path.islink(at) and os.readlink(at) == str(target)


def plant_alias(kind: str, at: Path, target: Path) -> None:
    """A `"symlink"` or a `"hard link"` to `target` at `at`."""
    (plant_link if kind == "symlink" else plant_hardlink)(at, target)


def alias_left(kind: str, at: Path, target: Path) -> bool:
    """The plant `plant_alias` made is still where it was: the same symlink, or a hard link
    sharing `target`'s inode."""
    if kind == "symlink":
        return is_link_to(at, target)
    return (os.path.lexists(at) and not os.path.islink(at)
            and os.stat(at).st_ino == os.stat(target).st_ino)


def leaf_refusal(exc: BaseException | None) -> bool:
    """`exc` is the core's refusal of a non-plain entry AT a name, exactly (`NotPlainEntry`, not
    a subclass test): a symlink, hard link, FIFO or folder at the leaf."""
    return type(exc) is NotPlainEntry


def _host_spelling(entry: str) -> re.Pattern[str]:
    """An absolute path ending in `/<entry>`: a `/` at the message's start or after whitespace, a
    quote, `(`, `=` or `:`, then path characters, then the entry at a word's end. A repo-relative
    spelling (`defender/lessons/a.md`) does not start with `/`, so it is not one."""
    return re.compile(r"(?:^|[\s'\"(=:])/[^\s'\"]*/" + re.escape(entry) + r"(?![^\s'\")])")


def warnings_naming(caplog: Any, entry: str) -> list[str]:
    """The WARNING records whose message names `entry` (the contract: "logged at WARNING naming
    the entry", by its corpus name — `Held` has no public root spelling).

    A WARNING that spells `entry` under an absolute path (the host path the core built from the
    held root, e.g. through `str()` of the refusal) fails here outright: the contract's "Log
    spelling" names the entry by its corpus name, not by an absolute path (E10)."""
    named = [r.getMessage() for r in caplog.records
             if r.levelno == logging.WARNING and entry in r.getMessage()]
    spelled = [m for m in named if _host_spelling(entry).search(m)]
    if spelled:
        raise AssertionError(f"a WARNING spells {entry!r} by its host path, not its corpus name: "
                             f"{spelled}")
    return named


# ---------------------------------------------------------------------------------------
# `os_` seams (over the real `os`) and a journalling `Held`
# ---------------------------------------------------------------------------------------


#: The `os` calls whose first positional argument is a descriptor (any other int argument is a
#: flag or a mode, never looked up as a descriptor).
_FD_FIRST = frozenset({"close", "dup", "fstat", "fdopen", "read", "pread", "write", "fsync",
                       "fdatasync", "fchmod", "fchown", "ftruncate", "lseek", "scandir",
                       "listdir", "fstatvfs"})
_FD_KEYWORDS = ("dir_fd", "src_dir_fd", "dst_dir_fd")


@dataclasses.dataclass(frozen=True)
class OsCall:
    """One call through a `RecordingOs`: the verb, each path argument as spelled (usually a leaf
    name relative to a `dir_fd`), and what each descriptor argument names (`/proc/self/fd`)."""

    verb: str
    names: tuple[str, ...]
    fds: tuple[str, ...]


def _os_call(verb: str, a: tuple, k: dict) -> OsCall:
    names = () if verb == "fdopen" else tuple(  # fdopen's strings are its mode
        os.fsdecode(x) for x in a if isinstance(x, str | bytes | os.PathLike))
    fd_args = [a[0]] if verb in _FD_FIRST and a else []
    fd_args += [k[key] for key in _FD_KEYWORDS if key in k]
    fds = tuple(named for fd in fd_args if (named := fd_path(fd)) is not None)
    return OsCall(verb, names, fds)


class RecordingOs(RealOs):
    """The real `os` as a handle's `os_` seam, recording every call made through it: its verb
    (into `calls`, or a shared `log` as `("os", name)`) and what it was called on (`trace`, read
    with `touched`). A record of the right verb on the right name means the caller went through
    THAT handle to THAT entry."""

    def __init__(self, log: list | None = None) -> None:
        self.calls: list[str] = []
        self.trace: list[OsCall] = []
        self.log = log

    def __getattr__(self, name: str) -> Any:
        real = getattr(os, name)
        if not callable(real):
            return real

        def call(*a: Any, **k: Any) -> Any:
            self.calls.append(name)
            self.trace.append(_os_call(name, a, k))
            if self.log is not None:
                self.log.append(("os", name))
            return real(*a, **k)

        return call

    def touched(self, verb: str) -> list[str]:
        """The last component of every path argument a `verb` call was made on, in order."""
        return [last_component(n) for c in self.trace if c.verb == verb for n in c.names]

    def descriptors(self) -> set[str]:
        """Everything a descriptor argument of any recorded call named."""
        return {fd for c in self.trace for fd in c.fds}

    def clear(self) -> None:
        del self.calls[:]
        del self.trace[:]


class FailsOn(RealOs):
    """The real `os` as a handle's `os_` seam, except that a call to `verb` (on the leaf `leaf`
    when given, else on any) raises the plain `OSError(code)` a failing disk gives: `ENOSPC` on
    the `rename` that lands a replace-write, `EIO` or `EACCES` on an `unlink`. It is no refusal
    of the tree's shape (not `NotPlainEntry`), so O5.3 never passes it over. `raised` counts the
    failures, so a test can show the failing call was reached."""

    def __init__(self, verb: str, code: int, *, leaf: str | None = None) -> None:
        self.verb, self.code, self.leaf, self.raised = verb, code, leaf, 0

    def __getattr__(self, name: str) -> Any:
        real = getattr(os, name)
        if name != self.verb:
            return real

        def fail(*a: Any, **k: Any) -> Any:
            target = a[1] if name == "rename" and len(a) > 1 else (a[0] if a else None)
            if self.leaf is not None and os.fspath(target) != self.leaf:
                return real(*a, **k)
            self.raised += 1
            raise OSError(self.code, os.strerror(self.code))

        return fail


_ROOT_FLAGS = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC


class JournalBound(Bound):
    """The view a `JournalHeld` hands out: the real `Bound` over the same held handle, logging
    each read as `(verb, name)` into the journal. A name in `refuse` reads as refused (as a hard
    link there would); a name in `extra` reads, as text, with `extra[name]` appended. Each
    departure is one the drain can only act on if it read through THIS view."""

    def __init__(self, os_: Any, handle: Any, *, log: list, refuse: frozenset[str],
                 extra: dict[str, str]) -> None:
        super().__init__(os_, handle)
        self.log, self.refuse, self.extra = log, refuse, extra

    def read(self, name: Any, *, errors: str = "strict") -> RecordRead:
        key = str(name)
        self.log.append(("read", key))
        if key in self.refuse:
            return RecordRead(name=key, absent=False, reason="refused by the test's view",
                              text=None)
        got = super().read(name, errors=errors)
        if key in self.extra and got.text is not None:
            return dataclasses.replace(got, text=got.text + self.extra[key])
        return got

    def entries(self) -> Any:
        self.log.append(("entries", "."))
        return super().entries()


class JournalHeld(Held):
    """A real `Held` on `root` (held open by descriptor, as `hold` does) that logs every verb
    made on it, and every read made on its view, into `log` as `(verb, name)`. A test's fakes
    append their own marks to the same list, so the journal shows which handle a drain step
    reached the corpus through, and when. Handed in with `dataclasses.replace(cfg, corpus=...)`."""

    def __init__(self, root: Path, log: list, *, refuse: tuple[str, ...] = (),
                 extra: dict[str, str] | None = None) -> None:
        super().__init__(os, os.open(root, _ROOT_FLAGS), root, open_unnamed=open_unnamed_at)
        self.log, self.refuse, self.extra = log, frozenset(refuse), dict(extra or {})

    def view(self) -> Bound:
        return JournalBound(self._os, self._root, log=self.log, refuse=self.refuse,
                            extra=self.extra)

    def write(self, name: Any, text: str | bytes, *, mode: str, durable: bool = False) -> None:
        self.log.append(("write", str(name)))
        super().write(name, text, mode=mode, durable=durable)

    def mkdir(self, folder: Any) -> None:
        self.log.append(("mkdir", str(folder)))
        super().mkdir(folder)

    def unlink(self, name: Any) -> bool:
        self.log.append(("unlink", str(name)))
        return super().unlink(name)


# ---------------------------------------------------------------------------------------
# The world the new curator files share
# ---------------------------------------------------------------------------------------


@dataclasses.dataclass
class World:
    """A committed repo carrying both curator corpora, a folder outside it where every link
    points, and the author drain's trees over the repo, open for as long as the world is
    referenced."""

    tmp: Path
    repo: Path
    paths: LoopPaths
    outside: Path
    trees: DrainTrees

    @property
    def corpus_dir(self) -> Path:
        return self.paths.lessons_dir

    @property
    def sibling_dir(self) -> Path:
        return self.paths.lessons_questioner_dir

    @property
    def corpus(self) -> Held:
        """The held `lessons/` mount, as the lane takes it: `trees.mount(lessons_dir)`."""
        return self.trees.mount(self.corpus_dir)

    @property
    def sibling(self) -> Held:
        return self.trees.mount(self.sibling_dir)

    @property
    def view(self) -> Bound:
        return self.corpus.view()

    @property
    def tree_for(self) -> TreeForFn:
        return self.trees.tree_for

    def cfg(self, **replaced: Any) -> Any:
        """The REAL lessons config over these trees, the drain-run check disarmed."""
        return author_cfg(self.paths, trees=self.trees, **{"forward_check": None, **replaced})

    def target(self, name: str, text: str | bytes | None = None) -> Path:
        """A file outside the repo carrying the mark (or `text`)."""
        at = self.outside / name
        put(at, text if text is not None else lesson_text("f1", mark=OUT_MARK))
        return at

    def git(self, *args: str, check: bool = True) -> Any:
        from defender.tests._drain719 import git

        return git(self.repo, *args, check=check)

    def commit(self, message: str = "seed") -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").stdout.strip()

    def head_text(self, rel: str) -> str | None:
        """`rel`'s blob in HEAD (a symlink's blob is its target), or `None` when HEAD lacks it."""
        proc = self.git("cat-file", "-p", f"HEAD:{rel}", check=False)
        return proc.stdout if proc.returncode == 0 else None

    def head_mode(self, rel: str) -> str | None:
        out = self.git("ls-tree", "HEAD", "--", rel).stdout.split()
        return out[0] if out else None


def world(tmp_path: Path) -> World:
    """`_drain719.make_repo` plus a committed `lessons-questioner/` (the sibling corpus the author
    label also mounts), an `outside/` folder beside the repo, and the author trees, open."""
    from defender.tests._drain719 import git, make_repo

    repo = make_repo(tmp_path)
    sibling = repo / "defender" / "lessons-questioner"
    sibling.mkdir(parents=True, exist_ok=True)
    (sibling / ".gitkeep").write_text("")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "sibling corpus")
    outside = tmp_path / "outside"
    outside.mkdir()
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    return World(tmp=tmp_path, repo=repo, paths=paths, outside=outside, trees=author_trees(paths))
