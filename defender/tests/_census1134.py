"""The #1134 D6 census engine: every host filesystem touch in a module, as a stable anchor.

`test_1134_census.py` holds the policy (the allow-list, the known gaps, the regression fixtures
and the statement of the "provably a handle" rule); this module holds the scanner and the two
module lists it scans by default, so a one-off run against another tree (an adversary's patched
worktree) imports `census` and nothing else.

A hit is anchored at ``(module, qualname, kind, text)`` — the module's path under `defender/`,
the enclosing def's qualified name (``"<module>"`` at top level), what kind of touch it is, and
``ast.unparse`` of the node — never a line number, so an edit elsewhere in the file cannot move
an entry off its hit. The same text twice in one function is two hits on one anchor.

Kinds:

- ``call``      a call whose callee resolves (through imports, aliases, relative imports and
                re-exports, via `scripts/lint/_astlib.py`) to a vocabulary function: every
                public `defender._io` callable that is not in `IO_PURE` and not a constructor,
                and every underscore name of `defender._io` (its private disk helpers —
                `_create_named`, `_open_plain_fd`, `_ensure_dir_component`, ... — classes and
                constants, `io_private_names`); every public `defender._run_paths` function not
                in `RUN_PATHS_PURE`; `os` / `os.path` filesystem, xattr, cwd and process
                functions; any `shutil`, `glob`, `tempfile`, `subprocess`, `filecmp`,
                `linecache`, `fileinput`, `dbm`, `shelve`, `sqlite3`, `pty`, `py_compile`,
                `compileall` or `zipimport` function; the openers (`OPENERS`: the compressed-file
                classes, file-backed logging handlers, module loaders, `asyncio`'s children
                among them) and any `<module>.open` however it is imported;
                `_paths.process_defender_dir`.
- ``attr``      a method call by a Path-verb name (`ATTRS`) whose receiver is neither a module,
                nor a `defender` class whose own body defines the verb (``Episode.open(d)``: a
                `defender` function, judged as any other), nor a provable `Held` / `Bound` that
                has that verb (`Held.mkdir`, `Held.unlink`; `Bound` has none: #1134 addendum 3,
                D1, drops `read_bytes`) — in the verb's own shape (`verb_shape`); on a `pathlib`
                class (``Path.replace(a, b)``, also through a `defender` re-export) at any
                arity. The same receiver rule judges a value's verb referenced without being
                called (``load``).
- ``load``      a vocabulary function or name, shared reader, constructor or a `pathlib` class's
                Path verb referenced without being called (``reader = read_text_soft``,
                ``map(os.unlink, ps)``, ``partial(hold)``, ``filter(Path.is_file, ps)``,
                ``_io._NOT_PLAIN``), and a def with a tree slot or a `TreeFor` slot referenced so
                (``cb = _corpus._lessons``; a `TreeFor` slot's def is judged as
                ``functools.partial``'s callee instead) — except a handle class or path owner
                (`CLASS_WORDS`) in an annotation, a `TypeAlias` value, or as
                `isinstance`/`issubclass`'s class argument; and ``from defender._io import _x``
                (relative, or through a re-export).
- ``getattr``   ``getattr(x, "<a vocabulary, Path-verb or handle-private name>")``,
                ``operator.methodcaller("<such a name>")``, ``operator.attrgetter(...)`` with
                such a name in any dotted segment of any argument, and
                ``getattr(<defender._io>, "_<anything>")``.
- ``construct`` building a handle or a path owner (`CONSTRUCTORS`, resolved by origin):
                ``_io.hold`` / ``bind`` / ``hold_new``, ``Held(...)`` / ``Bound(...)``,
                ``DrainTrees(...)``, ``DrainTrees.open(...)``,
                ``lane_trees.open_drain_trees(...)``, ``_corpus._viewed(...)`` — each roots
                wherever its path points; and any fresh path owner — ``LoopPaths(...)``,
                ``DefenderPaths(...)``, ``<any>.with_repo_root(...)``,
                ``dataclasses.replace(..., repo_root=...)`` (or with a ``**`` mapping) — whose
                mount list is a repo root of the caller's choosing; and any ``x.__class__(...)``
                or ``type(x)(...)``.
- ``reader``    a call with a tree slot not handed a provable handle of its kind: a
                handle-taking function's (`READERS`: the shared readers and B2's `entry_kind` /
                `list_tree` take a `Bound` — a `Held` there is a hit, the drain passes its
                `.view()` — and `view_at` a `Held`), or any parameter, of the top-level def the call resolves to in the
                scanned tree, annotated to admit a handle and something else (`tree_kind`: the
                `_corpus.Tree` alias, `Bound | Path`, `Bound | Path | None` — `_corpus._lessons`
                / `_templates` / `_spelled` among them). A slot not handed at all (``load_catalog()``)
                or hidden by a ``*`` / ``**`` argument is a hit. A value that is the enclosing
                top-level def's own tree slot of that kind, never rebound, passes through
                (`passes_through`): that def's own calls are judged by this same rule.
- ``tree_for``  a ``tree_for=`` keyword argument (any callee), or a `TreeFor` slot of the
                callee — every parameter annotated exactly `TreeFor` (or `TreeFor | None`) of a
                top-level def in the scanned tree, `lane_trees.kind_at` / `read_at`'s positional 1
                among them (`TREE_FOR_TAKERS`), also through
                ``functools.partial(<def>, ...)`` — not handed a provable `TreeFor`
                (``tree_for=lambda _p: None`` sends every path to the D3 plain fallback): handed
                something else, not handed at all, or hidden by a ``*`` argument at or before it
                or a ``**`` mapping (``**{"tree_for": lambda _p: None}``); and any ``**`` argument
                to a callee that is not a def of the scanned tree (a value, a class such as
                `LeadAuthorDeps`, `dataclasses.replace`), whose keys may hold ``tree_for``.
- ``private``   an attribute named for a handle's private state (`Tree.private_attrs`: every
                ``self._x`` a scanned `Held`, `Bound` or `DrainTrees` assigns) on any receiver
                but ``self`` inside the class that assigns it — ``corpus._where``, the held
                mount's spelling, is where every "then go by path" regression starts.
- ``listing``   a folder listed (#1134 addendum 2, B2/B3; C1): a raw ``<x>.entries(...)`` call at
                any arity, an uncalled ``.entries`` off a provable `Bound`, a ``type(...)`` call or
                the class, any ``list_tree(...)`` call, and in a curator module a call of any def
                that lists however deep (`lister`) — each allowed only at the listers the test names.

`defender/_paths.py`'s only export that touches disk is `process_defender_dir`, which resolves
the package's own `__file__`; `adapters_under` and every `DefenderPaths` property only join
path components. A call of a `_git` helper is not in the vocabulary (git's own reads and writes,
N-a); `_git.py` itself is in scan A, so its own `subprocess` children are hits, each allow-listed
N-a by the test, and any other touch there is a hit (`test_1134_curator_handle` also pins it to
no filesystem call). A direct `subprocess` call anywhere is a hit: it can name any path.
"""
from __future__ import annotations

import ast
import functools
import importlib.util
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from defender.tests._by_path import import_lint_lib

_astlib = import_lint_lib("_astlib")

HELD = "defender._io.Held"
BOUND = "defender._io.Bound"
#: The shared readers' tree type (`Bound | Path`): a parameter annotated so is a tree slot.
TREE_ALIAS = "defender._corpus.Tree"
DRAIN_TREES = "defender.learning.core.lane_trees.DrainTrees"
TREE_FOR_TYPE = "defender.learning.core.lane_trees.TreeFor"
#: The four handle kinds of the "provably a handle" rule, each with the class (or alias) an
#: exact annotation must resolve to.
HANDLE_TYPES: dict[str, str] = {
    "held": HELD, "bound": BOUND, "trees": DRAIN_TREES, "tree_for": TREE_FOR_TYPE,
}

OPEN_DRAIN_TREES = "defender.learning.core.lane_trees.open_drain_trees"
DRAIN_TREES_OPEN = "defender.learning.core.lane_trees.DrainTrees.open"
#: Calls whose value is a `DrainTrees` (each still a `construct` hit of its own).
TREES_OPENERS = frozenset({OPEN_DRAIN_TREES, DRAIN_TREES_OPEN})
VIEW_AT = "defender.learning.core.lane_trees.view_at"

#: Calls that build a handle from whatever path they are given (a `Bound` from `bind` or
#: `_corpus._viewed` of a `Path`, a `Held` from `hold` / `hold_new`), or the drain's trees.
CONSTRUCTORS = frozenset({
    "defender._io.hold", "defender._io.bind", "defender._io.hold_new", HELD, BOUND,
    DRAIN_TREES, *TREES_OPENERS, "defender._corpus._viewed",
})
#: The path owners: a fresh one (or `.with_repo_root(...)`, or `dataclasses.replace(...,
#: repo_root=...)`) spells a mount list under a repo root of the caller's choosing, as step 6's
#: v1 adversary did with `LoopPaths(repo_root=repo_root)` (`_rules._bound`).
PATH_OWNERS = frozenset({
    "defender.learning.core.config.LoopPaths",
    "defender._paths.DefenderPaths",
})
#: Classes a `load` may name in an annotation, a `TypeAlias` value or an `isinstance` test
#: without a hit.
CLASS_WORDS = frozenset({*HANDLE_TYPES.values(), *PATH_OWNERS})

#: The public `_io` callables that touch nothing on disk — judged by reading each body. Every
#: other public `_io` def or class is in the vocabulary (the handle classes and openers as
#: `construct`), so a new `_io` export is a census word the moment it lands; so is every
#: underscore name of `_io` (`io_private_names`), pure or not, none judged body by body. The value judges
#: `load_json_artifact` (text), `is_hard_linked` and `is_plain_entry` (a stat result) are pure
#: too, but the #1134 step-7 dispatch pins them into the vocabulary; `test_1134_census` checks
#: the pure bodies call nothing else.
IO_PURE = frozenset({
    "json_nesting_depth",   # bracket depth of a str
    "parse_jsonl_row",      # one str line -> dict | None
    "json_safe",            # value -> JSON-safe value
    "use_utf8_stdio",       # reconfigures sys.stdout / sys.stderr, no path
    "stage_name",           # path -> a sibling Path spelling, nothing opened
    "staged_leaf",          # leaf str -> a staged leaf str
    "EntriesRead",          # a listing's result record
    "RecordRead",           # a read's result record
    "NotPlainEntry",        # the leaf refusal's exception class (`except NotPlainEntry:`)
    "JsonTooDeep",          # `json_safe`'s refusal, an exception class (a `ValueError`)
})

OS_FUNCS = frozenset({
    "open", "unlink", "remove", "rename", "replace", "walk", "scandir", "listdir", "makedirs",
    "mkdir", "rmdir", "stat", "lstat", "link", "symlink", "readlink", "access", "chmod", "utime",
    "fdopen",
    # Not in the dispatch's list, but the same kind of call on a named entry.
    "removedirs", "renames", "truncate", "chown", "lchown", "mkfifo", "mknod",
    # v1 step 7's adversary sweep (h4): walks, xattrs, and shells that name a path in a command.
    "fwalk", "statvfs", "listxattr", "getxattr", "setxattr", "removexattr", "system", "popen",
    # v2 step 7's third pass: the rest of `os`'s calls on a named entry.
    "chdir", "chroot", "pathconf", "chflags", "lchflags", "lchmod", "startfile",
})
#: `os.exec*`, `os.spawn*`, `os.posix_spawn*`: a child process handed a path.
OS_PREFIXES = ("exec", "spawn", "posix_spawn")
OS_PATH_FUNCS = frozenset({
    "lexists", "exists", "isfile", "isdir", "islink", "getsize", "getmtime", "realpath",
    "samefile",
    "getatime", "getctime", "ismount",
})
WHOLE_MODULES = frozenset({
    "shutil", "glob", "tempfile", "subprocess", "filecmp", "linecache", "fileinput",
    # Every function of these opens, runs or compiles what a path names (`dbm.whichdb(path)`
    # reads the file; `pty.spawn` runs a child).
    "dbm", "shelve", "sqlite3", "pty", "py_compile", "compileall", "zipimport",
})
#: Any `<module>.open` (`gzip.open`, `bz2.open`, `lzma.open`, `tokenize.open`, `wave.open`) is
#: an opener too, however it is imported (`Tree.in_vocabulary`).
OPENERS = frozenset({
    "builtins.open", "io.open", "codecs.open", "io.FileIO", "io.open_code", "zipfile.ZipFile",
    "tarfile.open", "tarfile.TarFile", "runpy.run_path", "importlib.util.spec_from_file_location",
    # v2 step 7's third pass: the compressed-file classes, file-backed logging, the module
    # loaders, and the asyncio children.
    "gzip.GzipFile", "bz2.BZ2File", "lzma.LZMAFile",
    "logging.FileHandler", "logging.handlers.WatchedFileHandler",
    "logging.handlers.RotatingFileHandler", "logging.handlers.TimedRotatingFileHandler",
    "logging.handlers.BaseRotatingHandler",
    "importlib.machinery.SourceFileLoader", "importlib.machinery.SourcelessFileLoader",
    "importlib.machinery.ExtensionFileLoader", "importlib.machinery.FileFinder",
    "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
    "asyncio.subprocess.create_subprocess_exec", "asyncio.subprocess.create_subprocess_shell",
})
#: The `pathlib` classes whose Path-verb attributes (`ATTRS`) are flagged when referenced
#: unbound — `filter(Path.is_file, ps)` (v1 step 7's adversary, h1) — as well as when called.
PATH_CLASSES = frozenset({
    "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath",
    "pathlib.PurePosixPath", "pathlib.PureWindowsPath",
})
PATHS_DISK = frozenset({"defender._paths.process_defender_dir"})

#: Path-verb method names. A receiver that resolves to a module, or to a `defender` class that
#: defines the verb, owns it (`ModuleScan.owns`); a provable `Held` / `Bound` that has the verb
#: is the handle's own.
ATTRS = frozenset({
    "is_file", "is_dir", "exists", "is_symlink", "read_text", "read_bytes", "write_text",
    "write_bytes", "unlink", "mkdir", "glob", "rglob", "iterdir", "open", "stat", "lstat",
    "touch", "rename", "replace", "rmdir", "resolve", "readlink", "symlink_to", "hardlink_to",
    "samefile", "chmod",
    # v1 step 7's adversary sweep (h4): the other verbs that stat or change an entry.
    "is_fifo", "is_socket", "is_mount", "is_block_device", "is_char_device", "owner", "lchmod",
    "link_to",
    # Newer `pathlib` verbs (3.12: `walk`, `is_junction`; 3.14: `copy_into`, `move_into`) — not
    # on this 3.11 venv, named so an upgrade does not open a hole. (`Bound` has no `walk`: #1134
    # addendum 2, B1.)
    "walk", "is_junction", "copy_into", "move_into",
    # Not `group`: `Path.group()` stats the entry, but a zero-argument `re.Match.group()` is
    # everywhere (`_io.json_nesting_depth` itself), so it would only ever match by name.
})
#: `Path.replace(target)` / `Path.rename(target)` take one positional and no keyword, or only
#: `target=`; `str.replace(old, new)` takes two, `DataFrame.rename(columns=…)` another keyword.
ONE_ARG_ATTRS = frozenset({"replace", "rename"})
#: `Path.owner()` takes no argument.
ZERO_ARG_ATTRS = frozenset({"owner"})
def verb_shape(attr: str, call: ast.Call | None) -> bool:
    """`<value>.<attr>` — called (`call`) or only referenced — in a Path verb's own shape:
    `rename` / `replace` called with one positional and no keyword (or only `target=`), `owner`
    called with none, any reference. (On a `pathlib` class the instance is the first argument
    and nothing shares the name: every shape is the verb's.)"""
    if call is None:
        return True
    target_only = not call.args and [k.arg for k in call.keywords] == ["target"]
    if attr in ONE_ARG_ATTRS and not target_only and (len(call.args) != 1 or call.keywords):
        return False
    return not (attr in ZERO_ARG_ATTRS and (call.args or call.keywords))

ENTRY_KIND = "defender._tree_listing.entry_kind"
LIST_TREE = "defender._tree_listing.list_tree"

#: Handle-taking function -> (positional slot, keyword, handle kind) of its tree argument, which
#: must be provably a handle of that kind. `-1`: keyword-only. The shared readers and B2's two
#: listing helpers (`entry_kind`, `list_tree`: #1134 addendum 2) take a `Bound` — a `Held` there
#: is a hit; `view_at` takes a `Held`. `where` is every reader's spelling keyword, never its tree.
READERS: dict[str, tuple[int, str, str]] = {
    "defender._corpus.iter_lesson_paths": (0, "corpus", "bound"),
    "defender._corpus.iter_lessons": (0, "corpus", "bound"),
    "defender._corpus.iter_query_templates": (0, "catalog", "bound"),
    "defender._corpus.read_query_template": (0, "source", "bound"),
    "defender.learning.leads.lead_neighbors.load_catalog": (0, "catalog", "bound"),
    "defender.learning.leads.lead_neighbors.load_lane_catalog": (0, "skills", "bound"),
    "defender._scaffold_rules.check_system_skill": (0, "source", "bound"),
    "defender.learning.author.shared.build_corpus_manifest": (0, "corpus", "bound"),
    "defender.learning.author.shared.build_curator_user_prompt": (-1, "corpus", "bound"),
    ENTRY_KIND: (0, "view", "bound"),
    LIST_TREE: (0, "view", "bound"),
    VIEW_AT: (0, "held", "held"),
}

#: The `TreeFor` slots #1134 names — callee -> (positional slot, keyword). The census derives
#: every `TreeFor` slot from the callee's own signature (`ModuleScan.tree_for_slots`);
#: `test_1134_census` pins that the derivation yields these. A `tree_for=` keyword is judged on
#: every call whatever the callee.
TREE_FOR_TAKERS: dict[str, tuple[int, str]] = {
    "defender.learning.core.lane_trees.kind_at": (1, "tree_for"),
    "defender.learning.core.lane_trees.read_at": (1, "tree_for"),
}

#: Calls whose value is a lane's whole-mount `Held` — `trees.mount(...)` behind a raise on a
#: missing mount — when their `trees` argument (slot 0) is provably a `DrainTrees`.
HANDLE_SOURCES = frozenset({
    "defender.learning.leads._lead_spine.lane_skills",
    "defender.learning.author.shared.lane_corpus",
})
#: Attribute spellings typed exactly `Held` / `TreeFor` on their dataclasses
#: (`CorpusAuthorConfig.corpus` / `.tree_for`, `LeadAuthorDeps.skills` / `.tree_for`);
#: `test_1134_census` pins the typing.
PINNED_ATTRS: dict[str, frozenset[str]] = {
    "held": frozenset({"cfg.corpus", "self.cfg.corpus", "deps.skills"}),
    "tree_for": frozenset({"cfg.tree_for", "self.cfg.tree_for", "deps.tree_for"}),
}

#: Scan A — the full vocabulary scan: the #1134 D6 module list, as paths under `defender/`,
#: plus every module a step migrated that holds host touches of the trees
#: (`learning/core/lane_trees.py`, the two curator channels' `run.py`), B2's listing helpers
#: (`_tree_listing.py`), and the git helpers the curator's before-state and sweep come from
#: (`_git.py`: its `subprocess` calls are git's own reads, N-a).
D6_MODULES: tuple[str, ...] = (
    "learning/author/drain.py",
    "learning/author/shared.py",
    "_corpus.py",
    "_scaffold_rules.py",
    "learning/leads/draft_synthesis.py",
    "learning/leads/lead_neighbors.py",
    "learning/leads/lead_render.py",
    "learning/leads/lead_extraction.py",
    "learning/leads/pitfalls_curator.py",
    "learning/leads/_lead_spine.py",
    "learning/leads/lead_author/__init__.py",
    "learning/leads/lead_author/_rules.py",
    "learning/leads/lead_author/_handoff.py",
    "learning/core/lane_trees.py",
    "learning/author/lessons/run.py",
    "learning/author/questioner/run.py",
    "_tree_listing.py",
    "_git.py",
)
#: Scan B — the opener census (`construct` only): scan A plus the modules that open a lane's
#: trees but whose other plain touches have no N-reason to judge (`drains.py` is queue
#: machinery; the harness's `materialize` writes its own scratch repo).
OPENER_MODULES: tuple[str, ...] = (
    *D6_MODULES,
    "learning/core/drains.py",
    "learning/author/_config.py",
    "evals/harness.py",
)

#: The listing method of `Bound` (#1133): a folder's entries. B2's helpers own every listing
#: (#1134 addendum 2, B2/B3; the curator lists no folder, C1): a raw `.entries()` call, and a
#: `list_tree(...)` call, are each a `listing` hit, allowed only at the sites the test names.
LISTING_VERB = "entries"

#: B2's kind checks (#1134 addendum 2, B3: "kind checks use `kind_at` / `entry_kind`"): each
#: lists one parent folder to judge one name, and is no listing of a tree to its callers.
KIND_CHECKS = frozenset({ENTRY_KIND, "defender.learning.core.lane_trees.kind_at"})
#: The curator modules (#1134 addendum 2 correction, C1: the curator lists no folder — its
#: before-state is git's and its sweep `git status`'s). In these, a call of any def that lists a
#: folder, however deep (`lister`), is a `listing` hit of its own, allowed only at the named sites
#: that read the corpus through a shared reader for its findings' ids or the prompt's manifest
#: (s7v3 C: the sweep driven by `iter_lesson_paths`).
CURATOR_MODULES: tuple[str, ...] = (
    "learning/author/drain.py",
    "learning/author/shared.py",
    "learning/author/lessons/run.py",
    "learning/author/questioner/run.py",
)

KINDS = frozenset({
    "call", "attr", "load", "getattr", "construct", "reader", "tree_for", "private", "listing",
})

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)
_FnDef = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class Hit:
    module: str
    qualname: str
    kind: str
    text: str
    line: int
    end_line: int = 0

    @property
    def anchor(self) -> tuple[str, str, str, str]:
        return (self.module, self.qualname, self.kind, self.text)

    def show(self) -> str:
        return f"{self.module}:{self.line} [{self.qualname}] {self.kind}: {self.text}"


def io_vocabulary(io_source: ast.Module) -> frozenset[str]:
    """Every public top-level def or class of `_io`'s source, minus `IO_PURE`."""
    names = {
        n.name for n in io_source.body
        if isinstance(n, (*_DEFS, ast.ClassDef)) and not n.name.startswith("_")
    }
    return frozenset(names - IO_PURE)


def io_private_names(io_source: ast.Module) -> frozenset[str]:
    """Every underscore name `_io`'s source binds at its top level — its private defs, classes
    and constants (`_create_named`, `_open_plain_fd`, `_Handle`, `_NOT_PLAIN`): the module's own
    disk helpers below the handle, every one a census word (`Tree.in_vocabulary`), so none needs
    judging body by body."""
    out: set[str] = set()
    for n in io_source.body:
        if isinstance(n, (*_DEFS, ast.ClassDef)):
            out.add(n.name)
        targets = (n.targets if isinstance(n, ast.Assign)
                   else [n.target] if isinstance(n, ast.AnnAssign) else [])
        out.update(t.id for t in targets if isinstance(t, ast.Name))
    return frozenset(name for name in out if name.startswith("_"))


#: The public `_run_paths` functions that touch nothing on disk. Every other public top-level
#: function there is in the vocabulary (`artifact_file`, `artifact_dir`, `plain_file` lstat the
#: entry; `contained_payload` resolves it); `test_1134_census` checks the split against each
#: body. Its classes (`RunPaths`, ...) only compose names and are not vocabulary.
RUN_PATHS_PURE = frozenset({"is_case_answer_key", "gather_summaries_shape", "resolve_run_bundle"})


def run_paths_vocabulary(source: ast.Module) -> frozenset[str]:
    """Every public top-level function of `_run_paths`' source, minus `RUN_PATHS_PURE`."""
    names = {n.name for n in source.body
             if isinstance(n, _DEFS) and not n.name.startswith("_")}
    return frozenset(names - RUN_PATHS_PURE)


def _class_def(source: ast.Module, name: str) -> ast.ClassDef | None:
    return next((n for n in source.body if isinstance(n, ast.ClassDef) and n.name == name), None)


def self_private_attrs(cls: ast.ClassDef) -> frozenset[str]:
    """Every ``self._x`` the class body assigns (`_x` single-underscore, not a dunder)."""
    out = set()
    for node in ast.walk(cls):
        targets = (node.targets if isinstance(node, ast.Assign)
                   else [node.target] if isinstance(node, (ast.AnnAssign, ast.AugAssign)) else [])
        for t in targets:
            if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                    and t.value.id == "self" and t.attr.startswith("_")
                    and not t.attr.startswith("__")):
                out.add(t.attr)
    return frozenset(out)


def public_methods(cls: ast.ClassDef) -> frozenset[str]:
    return frozenset(n.name for n in cls.body
                     if isinstance(n, _DEFS) and not n.name.startswith("_"))


def module_dotted(module: str) -> str:
    """`learning/author/drain.py` -> `defender.learning.author.drain`."""
    parts = ["defender", *module.removesuffix(".py").split("/")]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


class Tree:
    """One scanned checkout: its `_io` / `_run_paths` vocabularies, its handle classes' private
    attributes and verbs, and the static re-export map of its modules."""

    def __init__(self, repo_root: Path) -> None:
        self.root = repo_root
        _, io_tree = _astlib.read_and_parse(repo_root / "defender" / "_io.py", "defender/_io.py")
        self.io_vocab = io_vocabulary(io_tree)
        self.io_private = io_private_names(io_tree)
        run_paths = repo_root / "defender" / "_run_paths.py"
        self.run_paths_vocab: frozenset[str] = frozenset()
        if run_paths.is_file():
            _, rp_tree = _astlib.read_and_parse(run_paths, "defender/_run_paths.py")
            self.run_paths_vocab = run_paths_vocabulary(rp_tree)
        #: Each handle class's origin -> its class body in this checkout (absent: skipped).
        classes: dict[str, ast.ClassDef] = {}
        for origin, cls in ((HELD, _class_def(io_tree, "Held")),
                            (BOUND, _class_def(io_tree, "Bound"))):
            if cls is not None:
                classes[origin] = cls
        lane_trees = repo_root / "defender" / "learning" / "core" / "lane_trees.py"
        if lane_trees.is_file():
            _, lt_tree = _astlib.read_and_parse(lane_trees, "defender/learning/core/lane_trees.py")
            if (cls := _class_def(lt_tree, "DrainTrees")) is not None:
                classes[DRAIN_TREES] = cls
        #: Private attribute -> the handle classes that assign it on `self`.
        self.private_attrs: dict[str, frozenset[str]] = {}
        for origin, cls in classes.items():
            for attr in self_private_attrs(cls):
                self.private_attrs[attr] = self.private_attrs.get(attr, frozenset()) | {origin}
        #: Handle kind -> its class's public methods (a Path verb among them is the handle's).
        self.verbs: dict[str, frozenset[str]] = {
            kind: public_methods(classes[HANDLE_TYPES[kind]])
            for kind in ("held", "bound") if HANDLE_TYPES[kind] in classes}
        self._files: dict[str, Path | None] = {}
        self._imports: dict[str, dict[str, str]] = {}
        self._modules: dict[str, bool] = {}
        self._scans: dict[str, ModuleScan | None] = {}
        #: Def origin -> whether it lists a folder (`ModuleScan.lister`).
        self.lists: dict[str, bool] = {}

    def scan_of(self, dotted: str) -> ModuleScan | None:
        """The (unscanned) `ModuleScan` of `dotted` in this checkout, for its defs' summaries
        and parameter types."""
        if dotted not in self._scans:
            f = self.module_file(dotted)
            scan = None
            if f is not None:
                rel = f.relative_to(self.root / "defender").as_posix()
                _, parsed = _astlib.read_and_parse(f, f"defender/{rel}")
                scan = ModuleScan(self, rel, parsed)
            self._scans[dotted] = scan
        return self._scans[dotted]

    def module_file(self, dotted: str) -> Path | None:
        if dotted != "defender" and not dotted.startswith("defender."):
            return None
        if dotted not in self._files:
            base = self.root.joinpath(*dotted.split("."))
            self._files[dotted] = next(
                (c for c in (base.with_suffix(".py"), base / "__init__.py") if c.is_file()), None)
        return self._files[dotted]

    def top_imports(self, dotted: str) -> dict[str, str]:
        """`dotted`'s module-scope import bindings, made absolute."""
        if dotted not in self._imports:
            f = self.module_file(dotted)
            imports: dict[str, str] = {}
            if f is not None:
                _, parsed = _astlib.read_and_parse(f, str(f.relative_to(self.root)))
                relative = relative_map(parsed, package_of(dotted, f.name == "__init__.py"))
                imports = {k: absolute(v, relative)
                           for k, v in _astlib.module_env(parsed).imports.items()}
            self._imports[dotted] = imports
        return self._imports[dotted]

    def is_module(self, dotted: str) -> bool:
        if dotted not in self._modules:
            if dotted == "defender" or dotted.startswith("defender."):
                self._modules[dotted] = self.module_file(dotted) is not None
            else:
                try:
                    self._modules[dotted] = importlib.util.find_spec(dotted) is not None
                except (ImportError, ValueError, AttributeError):
                    self._modules[dotted] = False
        return self._modules[dotted]

    def canonical(self, origin: str) -> str:
        """Follow `defender` re-exports (`from x import y` at a module's top level) to the
        module that defines the name; `posixpath` is `os.path`."""
        if origin.startswith("posixpath."):
            origin = "os.path." + origin.removeprefix("posixpath.")
        for _ in range(10):
            parts = origin.split(".")
            cut = next((i for i in range(len(parts), 0, -1)
                        if self.module_file(".".join(parts[:i]))), None)
            if cut is None or cut == len(parts):
                return origin
            bound = self.top_imports(".".join(parts[:cut])).get(parts[cut])
            if bound is None:
                return origin
            origin = ".".join([bound, *parts[cut + 1:]])
        return origin

    def in_vocabulary(self, origin: str) -> bool:
        mod, _, leaf = origin.rpartition(".")
        return (
            origin in OPENERS or origin in PATHS_DISK
            or (mod == "os" and leaf in OS_FUNCS)
            or (mod == "os.path" and leaf in OS_PATH_FUNCS)
            or (mod == "os" and leaf.startswith(OS_PREFIXES))
            or origin.split(".")[0] in WHOLE_MODULES
            or (mod == "defender._io" and (leaf in self.io_vocab or leaf.startswith("_")))
            or (mod == "defender._run_paths" and leaf in self.run_paths_vocab)
            # `<module>.open` however it is spelled: `from gzip import open as g; g(p)`.
            or (leaf == "open" and bool(mod) and self.is_module(mod))
        )

    def getattr_words(self) -> frozenset[str]:
        return ATTRS | self.io_vocab | self.io_private | self.run_paths_vocab | OS_FUNCS | (
            OS_PATH_FUNCS) | {"with_repo_root", LISTING_VERB} | set(self.private_attrs) | {
            o.rpartition(".")[2] for o in (*READERS, *CONSTRUCTORS, *PATH_OWNERS)}

    def is_word(self, origin: str | None) -> bool:
        """A name the `load` and `getattr` kinds look for: vocabulary, reader or constructor."""
        if origin is None:
            return False
        owner, _, leaf = origin.rpartition(".")
        return (origin in READERS or origin in CONSTRUCTORS or origin in PATH_OWNERS
                or self.in_vocabulary(origin) or (owner in PATH_CLASSES and leaf in ATTRS))


def package_of(dotted: str, is_init: bool) -> str:
    return dotted if is_init else dotted.rpartition(".")[0]


def relative_map(parsed: ast.Module, package: str) -> dict[str, str]:
    """`_astlib`'s spelling of each relative from-import in `parsed` (`.mod.y`; `..y` for
    `from . import y`) -> its absolute origin under `package`."""
    out: dict[str, str] = {}
    for node in ast.walk(parsed):
        if isinstance(node, ast.ImportFrom) and node.level:
            base = package.split(".")
            base = base[: len(base) - (node.level - 1)]
            src = ".".join([*base, node.module] if node.module else base)
            for a in node.names:
                out[f"{'.' * node.level}{node.module or ''}.{a.name}"] = f"{src}.{a.name}"
    return out


def absolute(origin: str, relative: dict[str, str]) -> str:
    """A relative `_astlib` origin made absolute through `relative_map`: the longest mapped
    import that prefixes it at a dot boundary."""
    if not origin.startswith("."):
        return origin
    for key in sorted(relative, key=len, reverse=True):
        if origin == key or origin.startswith(key + "."):
            return relative[key] + origin[len(key):]
    return origin


# ---------------------------------------------------------------------------------------------
# Bindings inside one def, for the "provably a handle" rule
# ---------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Binding:
    """How one name is bound once inside a def: `assign` (value), `unpack` (value, index),
    `with` (the context expression, for a plain ``with <value> as <name>:``) or `other`
    (anything else — a loop, an except, a del, a global, an import, a nested def...)."""

    how: str
    value: ast.expr | None = None
    index: int = -1
    line: int = 0


def _target_bindings(
    target: ast.expr, value: ast.expr | None, line: int,
) -> Iterator[tuple[str, Binding]]:
    if isinstance(target, ast.Name):
        yield target.id, (Binding("assign", value, line=line) if value is not None
                          else Binding("other"))
    elif isinstance(target, (ast.Tuple, ast.List)):
        for i, elt in enumerate(target.elts):
            if isinstance(elt, ast.Name) and value is not None and not any(
                    isinstance(e, ast.Starred) for e in target.elts):
                yield elt.id, Binding("unpack", value, i, line)
            else:
                yield from _names_other(elt)
    else:
        yield from _names_other(target)


def _names_other(node: ast.AST) -> Iterator[tuple[str, Binding]]:
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            yield n.id, Binding("other")


def _node_bindings(node: ast.AST) -> Iterator[tuple[str, Binding]]:
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for t in targets:
            yield from _target_bindings(t, node.value, node.lineno)
    elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor, ast.comprehension, ast.Delete)):
        targets = node.targets if isinstance(node, ast.Delete) else [node.target]
        for t in targets:
            yield from _names_other(t)
    elif isinstance(node, ast.withitem) and node.optional_vars is not None:
        if isinstance(node.optional_vars, ast.Name):
            yield node.optional_vars.id, Binding(
                "with", node.context_expr, line=node.context_expr.lineno)
        else:
            yield from _names_other(node.optional_vars)
    else:
        for name in bound_names(node):
            yield name, Binding("other")


def bound_names(node: ast.AST) -> list[str]:
    """The names a non-assignment binding form binds: an except, a global / nonlocal, an import,
    a def or class, a parameter, a `match` capture."""
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return list(node.names)
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [(a.asname or a.name).split(".")[0] for a in node.names]
    if isinstance(node, (*_DEFS, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, ast.MatchMapping):
        return [node.rest] if node.rest else []
    name = getattr(node, "name", None) if isinstance(
        node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) else None
    return [name] if name else []


def def_bindings(fn: _FnDef) -> dict[str, list[Binding]]:
    """Every binding of every name anywhere in `fn`'s body — nested defs, lambdas and
    comprehensions included (a nested scope that binds the name counts against it: the rule
    errs toward a hit). `fn`'s own parameters are not bindings here."""
    out: dict[str, list[Binding]] = {}
    for stmt in fn.body:
        for node in ast.walk(stmt):
            for name, b in _node_bindings(node):
                out.setdefault(name, []).append(b)
    return out


def _is_none(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def none_test(test: ast.expr, name: str) -> str | None:
    """`"is"` when `test` is true whenever `name` is None (`name is None`, or an `or` holding
    such a test); `"is not"` when it is true only when `name` is not None (`name is not None`, or
    an `and` holding such a test); else None."""
    if (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name)
            and test.left.id == name and _is_none(test.comparators[0])):
        if isinstance(test.ops[0], ast.Is):
            return "is"
        if isinstance(test.ops[0], ast.IsNot):
            return "is not"
    if isinstance(test, ast.BoolOp):
        want = "is" if isinstance(test.op, ast.Or) else "is not"
        if any(none_test(v, name) == want for v in test.values):
            return want
    return None


def _is_none_guard(stmt: ast.stmt, name: str) -> bool:
    """`if <test>:` with no `else`, whose body ends in `raise` or `return`, and whose test is
    true whenever `name` is None (`none_test`)."""
    return (
        isinstance(stmt, ast.If) and not stmt.orelse
        and isinstance(stmt.body[-1], (ast.Raise, ast.Return))
        and none_test(stmt.test, name) == "is"
    )


def _block_holding(parent: ast.AST, stmt: ast.stmt) -> tuple[list[ast.stmt], int]:
    """The statement list of `parent` (`body`, `orelse`, `finalbody`, ...) holding `stmt`, and
    its index there."""
    for _field, value in ast.iter_fields(parent):
        if isinstance(value, list):
            for i, item in enumerate(value):
                if item is stmt:
                    return value, i
    raise AssertionError(f"{ast.dump(stmt)[:60]} is not in a block of its parent")


def _params(fn: _FnDef) -> dict[str, ast.arg]:
    a = fn.args
    every = [*a.posonlyargs, *a.args, *a.kwonlyargs]
    every += [x for x in (a.vararg, a.kwarg) if x is not None]
    return {p.arg: p for p in every}


def _param_defaults(fn: _FnDef) -> dict[str, ast.expr]:
    """Parameter name -> its default, for each parameter of `fn` that has one."""
    a = fn.args
    positional = [*a.posonlyargs, *a.args]
    out = dict(zip([p.arg for p in positional[len(positional) - len(a.defaults):]], a.defaults,
                   strict=True))
    out.update((p.arg, d) for p, d in zip(a.kwonlyargs, a.kw_defaults, strict=True) if d is not None)
    return out


def _slot_params(fn: _FnDef) -> list[tuple[int, ast.arg]]:
    """`(positional index or -1, parameter)` of each named parameter of `fn` (not `*args` /
    `**kwargs`)."""
    positional = [*fn.args.posonlyargs, *fn.args.args]
    return [(i, p) for i, p in enumerate(positional)] + [(-1, p) for p in fn.args.kwonlyargs]


def slot_value(args: list[ast.expr], keywords: list[ast.keyword], index: int,
               name: str) -> ast.expr | None:
    """The expression a call (its `args`, `keywords`) hands the parameter at positional `index`
    (-1: keyword-only) named `name`; None when it hands none, or when a `*` argument at or before
    the slot (or, with no positional there, anywhere) or a `**` argument leaves that unknowable."""
    if index >= 0:
        if any(isinstance(a, ast.Starred) for a in args[:index + 1]):
            return None
        if index < len(args):
            return args[index]
    return next((kw.value for kw in keywords if kw.arg == name), None)


def _args_for(call: ast.Call, fn: _FnDef) -> dict[str, ast.expr] | None:
    """Parameter name -> the expression `call` hands it, or None when a `*` / `**` argument or a
    surplus positional leaves that unknowable."""
    positional = [*fn.args.posonlyargs, *fn.args.args]
    if any(isinstance(a, ast.Starred) for a in call.args) or any(
            kw.arg is None for kw in call.keywords) or len(call.args) > len(positional):
        return None
    out = {p.arg: a for p, a in zip(positional, call.args, strict=False)}
    out.update((kw.arg, kw.value) for kw in call.keywords if kw.arg is not None)
    return out


def _own_nodes(fn: _FnDef) -> Iterator[ast.AST]:
    """Every node of `fn`'s body outside its nested defs, lambdas and classes."""
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        yield node
        stack.extend(c for c in ast.iter_child_nodes(node)
                     if not isinstance(c, (*_DEFS, ast.Lambda, ast.ClassDef)))


# ---------------------------------------------------------------------------------------------
# One module's scan
# ---------------------------------------------------------------------------------------------

class ModuleScan:
    """The hits of one module's source, resolved against `tree`."""

    def __init__(self, tree: Tree, module: str, source_tree: ast.Module) -> None:
        self.tree = tree
        self.module = module
        self.dotted = module_dotted(module)
        self.relative = relative_map(
            source_tree, package_of(self.dotted, module.endswith("__init__.py")))
        self.ast = source_tree
        self.env = _astlib.module_env(source_tree)
        #: Names the module binds at its top level other than by import — its defs and classes,
        #: and its assigned names (`TreeFor: TypeAlias = ...`) — so a same-module annotation
        #: resolves to its origin.
        self.module_defs = {
            n.name for n in source_tree.body if isinstance(n, (*_DEFS, ast.ClassDef))}
        for n in source_tree.body:
            targets = (n.targets if isinstance(n, ast.Assign)
                       else [n.target] if isinstance(n, ast.AnnAssign) else [])
            self.module_defs.update(t.id for t in targets if isinstance(t, ast.Name))
        self.parent: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(source_tree):
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node
        self._bindings: dict[ast.AST, dict[str, list[Binding]]] = {}
        #: `(name node's def, name, kind)` being judged: a binding that leans on itself
        #: (`v = v.under("x")`) proves nothing.
        self._judging: set[tuple[ast.AST, str, str]] = set()
        self._summaries: dict[tuple[ast.AST, str, int | None], str] = {}
        self._lists: dict[str, bool] = {}
        self._origins: dict[ast.AST, str | None] = {}
        self.hits: list[Hit] = []

    # -- structure --------------------------------------------------------------------------

    def enclosing(self, node: ast.AST) -> list[ast.AST]:
        """The defs and classes around `node`, innermost first."""
        out: list[ast.AST] = []
        cur = self.parent.get(node)
        while cur is not None:
            if isinstance(cur, (*_DEFS, ast.ClassDef)):
                out.append(cur)
            cur = self.parent.get(cur)
        return out

    def qualname(self, node: ast.AST) -> str:
        chain = list(reversed(self.enclosing(node)))
        if not chain:
            return "<module>"
        parts: list[str] = []
        for i, scope in enumerate(chain):
            parts.append(scope.name)  # type: ignore[attr-defined]
            if isinstance(scope, _DEFS) and i < len(chain) - 1:
                parts.append("<locals>")
        return ".".join(parts)

    def innermost_def(self, node: ast.AST) -> _FnDef | None:
        for scope in self.enclosing(node):
            if isinstance(scope, _DEFS):
                return scope
            return None  # a class body is not a def
        return None

    def innermost_class(self, node: ast.AST) -> ast.ClassDef | None:
        return next((s for s in self.enclosing(node) if isinstance(s, ast.ClassDef)), None)

    def bindings(self, fn: _FnDef) -> dict[str, list[Binding]]:
        if fn not in self._bindings:
            self._bindings[fn] = def_bindings(fn)
        return self._bindings[fn]

    # -- resolution -------------------------------------------------------------------------

    def resolve(self, origin: str | None) -> str | None:
        """An `_astlib` origin as this checkout spells it: a relative import made absolute, a
        `defender` re-export followed to the module that defines the name."""
        if origin is None:
            return None
        return self.tree.canonical(absolute(origin, self.relative))

    def _module_local(self, name: str, at: ast.AST) -> str | None:
        """`name` as this module's own top-level binding, unless a def around `at` rebinds
        it."""
        if name not in self.module_defs:
            return None
        for scope in self.enclosing(at):
            if isinstance(scope, _DEFS) and (
                    name in _params(scope) or name in self.bindings(scope)):
                return None
        return f"{self.dotted}.{name}"

    def origin(self, node: ast.expr) -> str | None:
        if node not in self._origins:
            got = _astlib.origin(node, self.env)
            if got is None:
                base: ast.expr = node
                parts: list[str] = []
                while isinstance(base, ast.Attribute):
                    parts.append(base.attr)
                    base = base.value
                if isinstance(base, ast.Name) and (local := self._module_local(base.id, base)):
                    got = ".".join([local, *reversed(parts)])
            self._origins[node] = self.resolve(got)
        return self._origins[node]

    def owns(self, origin: str | None, attr: str) -> bool:
        """`<origin>.<attr>` is not a path's method but the namespace's own function: `origin`
        (as `origin` returns it) is a module, or a `defender` class whose own body defines
        `attr` (``Episode.open``) — a `defender` function, which the census judges as it judges
        any other. A class from outside the checkout (``os.DirEntry.stat``), one that inherits
        `attr` (a `Path` subclass), or one bound any other way (``Foo = make_class()``) is not
        seen, and its `attr` is judged by name."""
        if origin is None or origin in PATH_CLASSES:
            return False
        if origin == self.dotted or self.tree.is_module(origin):
            return True
        parts = origin.split(".")
        cut = next((i for i in range(len(parts) - 1, 0, -1)
                    if ".".join(parts[:i]) == self.dotted
                    or self.tree.module_file(".".join(parts[:i])) is not None), None)
        if cut is None:
            return False
        module = ".".join(parts[:cut])
        scan = self if module == self.dotted else self.tree.scan_of(module)
        body: list[ast.stmt] = scan.ast.body if scan is not None else []
        for name in parts[cut:]:
            cls = next((n for n in body if isinstance(n, ast.ClassDef) and n.name == name), None)
            if cls is None:
                return False
            body = cls.body
        return any(isinstance(n, _DEFS) and n.name == attr for n in body)

    def path_verb(self, node: ast.Attribute, call: ast.Call | None,
                  verbs: frozenset[str] = ATTRS) -> bool:
        """`node` is a Path verb in `verbs` — called (`call`) or only referenced — on what may
        be a path: on a `pathlib` class in any shape, on anything else the namespace does not
        own (`owns`) in the verb's own shape (`verb_shape`)."""
        if node.attr not in verbs:
            return False
        receiver = self.origin(node.value)
        if receiver in PATH_CLASSES:
            return True
        return not self.owns(receiver, node.attr) and verb_shape(node.attr, call)

    def callee(self, call: ast.Call) -> str | None:
        got = _astlib.callee(call, self.env)
        if got is None and isinstance(call.func, (ast.Name, ast.Attribute)):
            return self.origin(call.func)
        return self.resolve(got)

    # -- "provably a handle" ----------------------------------------------------------------

    @staticmethod
    def _annotation(ann: ast.expr | None) -> ast.expr | None:
        """`ann`, a string annotation parsed. The parsed node carries no scope tag, so it
        resolves at module scope."""
        if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
            try:
                return ast.parse(ann.value, mode="eval").body
            except SyntaxError:
                return None
        return ann

    def _is_type(self, node: ast.expr | None, kind: str) -> bool:
        return (isinstance(node, (ast.Name, ast.Attribute))
                and self.origin(node) == HANDLE_TYPES[kind])

    def is_annotated(self, ann: ast.expr | None, kind: str) -> bool:
        """Exactly the kind's class: a union, a subscript, an alias like `_corpus.Tree` is
        not."""
        return self._is_type(self._annotation(ann), kind)

    def _is_optional_annotation(self, ann: ast.expr | None, kind: str) -> bool:
        """Exactly `<class> | None` (either order) or `Optional[<class>]`."""
        ann = self._annotation(ann)
        if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
            return any(_is_none(a) and self._is_type(b, kind)
                       for a, b in ((ann.left, ann.right), (ann.right, ann.left)))
        return (
            isinstance(ann, ast.Subscript) and isinstance(ann.value, (ast.Name, ast.Attribute))
            and self.origin(ann.value) == "typing.Optional" and self._is_type(ann.slice, kind)
        )

    def _statement_of(self, node: ast.AST) -> ast.stmt | None:
        cur: ast.AST | None = node
        while cur is not None and not isinstance(cur, ast.stmt):
            cur = self.parent.get(cur)
        return cur

    def guard_line(self, node: ast.AST, name: str, fn: _FnDef) -> int | None:
        """The line of the guard that keeps `name` from being None at `node`, or None: an
        `if <name> is None:` (or an `or` holding it) with no `else` whose body ends in `raise` /
        `return`, standing earlier in the block that holds `node`'s statement or in an enclosing
        block up to `fn`'s body; or an enclosing `if` whose test is that `is None` test with
        `node` in its `else`, or an `is not None` test (or an `and` holding it) with `node` in
        its body. A guard nested in an earlier sibling (a branch, a `try`) is not one."""
        cur: ast.AST = node
        while True:
            stmt = self._statement_of(cur)
            if stmt is None or stmt is fn:
                return None
            up = self.parent[stmt]
            block, at = _block_holding(up, stmt)
            for earlier in reversed(block[:at]):
                if _is_none_guard(earlier, name):
                    return earlier.lineno
            if isinstance(up, ast.If):
                test = none_test(up.test, name)
                if (test == "is" and block is up.orelse) or (test == "is not" and block is up.body):
                    return up.lineno
            if up is fn:
                return None
            cur = up

    def is_tree_for_call(self, node: ast.expr | None) -> bool:
        """A call of a provable `TreeFor`: its value is `(Held, name) | None`."""
        return isinstance(node, ast.Call) and self.provable(node.func, "tree_for")

    def _tree_for_result(self, name: str, fn: _FnDef) -> bool:
        """`name` is bound in `fn` only ever as `name = <provable TreeFor>(...)` (or its
        walrus)."""
        if name in _params(fn):
            return False
        bs = self.bindings(fn).get(name, [])
        return bool(bs) and all(b.how == "assign" and self.is_tree_for_call(b.value) for b in bs)

    def _is_hit0(self, node: ast.expr | None) -> bool:
        """`hit[0]` of a `tree_for` result name."""
        if not (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
                and isinstance(node.slice, ast.Constant) and node.slice.value == 0):
            return False
        fn = self.innermost_def(node)
        return fn is not None and self._tree_for_result(node.value.id, fn)

    def _binding(self, b: Binding, kind: str, fn: _FnDef) -> str:
        """`"yes"` when the binding's value is provably `kind`; `"optional"` when it is that or
        None (a summarized helper that also returns None); else `"no"`."""
        if b.how in ("assign", "with"):
            # A `with` target is the context's `__enter__`: `self` for `Held`, `Bound` and
            # `DrainTrees`.
            if self.provable(b.value, kind):
                return "yes"
            return (self.returned(b.value, kind, None)
                    if isinstance(b.value, ast.Call) and b.how == "assign" else "no")
        if b.how == "unpack":
            v = b.value
            if kind == "held" and b.index == 0 and (self.is_tree_for_call(v) or (
                    isinstance(v, ast.Name) and self._tree_for_result(v.id, fn))):
                return "yes"
            return self.returned(v, kind, b.index) if isinstance(v, ast.Call) else "no"
        return "no"

    def _provable_name(self, node: ast.Name, kind: str) -> bool:
        fn = self.innermost_def(node)
        if fn is None:
            return False
        key = (fn, node.id, kind)
        if key in self._judging:
            return False
        self._judging.add(key)
        try:
            params = _params(fn)
            bs = self.bindings(fn).get(node.id, [])
            if node.id in params:
                ann = params[node.id].annotation
                defaults = _param_defaults(fn)
                if bs or (node.id in defaults and not _is_none(defaults[node.id])):
                    return False  # rebound, or a default the caller never proves
                if self.is_annotated(ann, kind) and node.id not in defaults:
                    return True
                return (self.is_annotated(ann, kind) or self._is_optional_annotation(ann, kind)) and (
                    self.guard_line(node, node.id, fn) is not None)
            got = [self._binding(b, kind, fn) for b in bs]
            if got and all(g == "yes" for g in got):
                return True
            # One binding that may be None, then a guard after it that keeps None from `node`.
            guard = self.guard_line(node, node.id, fn) if got == ["optional"] else None
            return guard is not None and bs[0].line < guard
        finally:
            self._judging.discard(key)

    def _method_of(self, node: ast.expr, method: str, receiver: str) -> bool:
        """`<provable receiver-kind>.<method>(...)`."""
        f = node.func if isinstance(node, ast.Call) else None
        return (isinstance(f, ast.Attribute) and f.attr == method
                and self.provable(f.value, receiver))

    def provable(self, node: ast.expr | None, kind: str) -> bool:
        """Is `node` provably a handle of `kind` (`held`, `bound`, `trees`, `tree_for`)? The
        rule `test_1134_census`'s docstring states, clause by clause."""
        if isinstance(node, ast.Name):
            return self._provable_name(node, kind)
        if isinstance(node, ast.Attribute):
            if ast.unparse(node) in PINNED_ATTRS.get(kind, ()):
                return True
            return kind == "tree_for" and node.attr == "tree_for" and self.provable(
                node.value, "trees")
        if isinstance(node, ast.Subscript):
            return kind == "held" and self._is_hit0(node)
        if not isinstance(node, ast.Call):
            return False
        if kind == "held" and (self._method_of(node, "mount", "trees") or (
                self.callee(node) in HANDLE_SOURCES
                and self.provable(_astlib.arg_at(node, 0, "trees"), "trees"))):
            return True
        if kind == "bound" and (
                (self._method_of(node, "view", "held") and not node.args and not node.keywords)
                or self._method_of(node, "under", "bound")
                or (self.callee(node) == VIEW_AT
                    and self.provable(_astlib.arg_at(node, 0, "held"), "held"))):
            return True
        if kind == "trees" and self.callee(node) in TREES_OPENERS:
            return True
        return self.returned(node, kind, None) == "yes"

    # -- a helper's returned handle -----------------------------------------------------------

    def def_of(self, origin: str | None) -> tuple[ModuleScan, _FnDef] | None:
        """The top-level def `origin` names in the scanned tree (this module's own source when
        it is this module), with the scan of its module; its last definition (overload stubs
        come first)."""
        if origin is None:
            return None
        dotted, _, leaf = origin.rpartition(".")
        scan = self if dotted == self.dotted else self.tree.scan_of(dotted)
        if scan is None:
            return None
        fns = [n for n in scan.ast.body if isinstance(n, _DEFS) and n.name == leaf]
        return (scan, fns[-1]) if fns else None

    @staticmethod
    def summarizable(fn: _FnDef) -> bool:
        """A plain undecorated `def`: an `async def` returns a coroutine and a decorator may
        return anything at all."""
        return isinstance(fn, ast.FunctionDef) and not fn.decorator_list

    def typed_params(self, fn: _FnDef) -> list[tuple[int, str, str]]:
        """`(positional index or -1, name, kind)` of each parameter of `fn` (a def of this
        module) annotated exactly a handle kind's class, or that class `| None`."""
        positional = [*fn.args.posonlyargs, *fn.args.args]
        out = []
        for i, p in enumerate([*positional, *fn.args.kwonlyargs]):
            for kind in HANDLE_TYPES:
                if self.is_annotated(p.annotation, kind) or self._is_optional_annotation(
                        p.annotation, kind):
                    out.append((i if i < len(positional) else -1, p.arg, kind))
        return out

    def returned(self, call: ast.Call, kind: str, index: int | None) -> str:
        """What a call of a summarized helper hands back as `kind` — the whole value (`index`
        None) or its tuple element `index`: `"yes"`, `"optional"` (or None), or `"no"`.

        A helper is summarized when the call resolves to a top-level def in the scanned tree,
        every one of its handle-typed parameters (`typed_params`) is handed a provable handle
        of that kind here, and `summary` proves its returns."""
        found = self.def_of(self.callee(call))
        if found is None:
            return "no"
        scan, fn = found
        args = _args_for(call, fn)
        if args is None or not self.summarizable(fn):
            return "no"
        for _i, name, pkind in scan.typed_params(fn):
            if not self.provable(args.get(name), pkind):
                return "no"
        return scan.summary(fn, kind, index)

    def summary(self, fn: _FnDef, kind: str, index: int | None) -> str:
        """`"yes"` when every `return` of `fn` (its own body; not a generator) hands back a
        provable `kind` (as `index`'s tuple element), `"optional"` when some hand back None
        instead (or, for the whole value, the body can end without a `return`), `"no"`
        otherwise. Judged in `fn`'s own scope, its handle-typed parameters taken as typed (the
        caller proved them)."""
        key = (fn, kind, index)
        if key in self._summaries:
            return self._summaries[key]
        self._summaries[key] = "no"  # a helper that leans on itself proves nothing
        own = list(_own_nodes(fn))
        if any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in own):
            return "no"
        none_seen, handle_seen = False, False
        for ret in (n for n in own if isinstance(n, ast.Return)):
            v = ret.value
            if index is not None:
                if not (isinstance(v, ast.Tuple) and len(v.elts) > index
                        and not any(isinstance(e, ast.Starred) for e in v.elts)):
                    return "no"
                v = v.elts[index]
            if v is None or _is_none(v):
                none_seen = True
            elif self.provable(v, kind):
                handle_seen = True
            else:
                return "no"
        if index is None and not isinstance(fn.body[-1], (ast.Return, ast.Raise)):
            none_seen = True
        got = "no" if not handle_seen else "optional" if none_seen else "yes"
        self._summaries[key] = got
        return got

    def tree_for_slots(self, origin: str | None) -> set[tuple[int, str]]:
        """The `(positional index or -1, keyword)` slots of `origin` that take a `TreeFor`: each
        parameter annotated exactly `TreeFor` (or `TreeFor | None`: a `None` there sends every
        path to the plain fallback, as `tree_for=None` would) of the top-level def it names in
        the scanned tree (`lane_trees.kind_at` / `read_at`'s `tree_for` among them)."""
        found = self.def_of(origin)
        if found is None:
            return set()
        scan, fn = found
        return {(i, name) for i, name, kind in scan.typed_params(fn) if kind == "tree_for"}

    # -- tree slots: a parameter that admits a handle or something else ----------------------

    def _union_members(self, ann: ast.expr | None) -> list[ast.expr]:
        """`ann`'s members: each side of a `|`, each element of `Optional[...]` /
        `Union[...]`, flattened (string annotations parsed); else `ann` itself."""
        ann = self._annotation(ann)
        if ann is None:
            return []
        if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
            return [*self._union_members(ann.left), *self._union_members(ann.right)]
        if (isinstance(ann, ast.Subscript) and isinstance(ann.value, (ast.Name, ast.Attribute))
                and self.origin(ann.value) in ("typing.Optional", "typing.Union")):
            elts = ann.slice.elts if isinstance(ann.slice, ast.Tuple) else [ann.slice]
            return [m for e in elts for m in self._union_members(e)]
        return [ann]

    def tree_kind(self, ann: ast.expr | None) -> str | None:
        """The handle kind a parameter annotated `ann` must be handed, when `ann` admits a handle
        AND something that is not one: `bound` for the `_corpus.Tree` alias (`Bound | Path`) or a
        union holding `Bound` and a member that is neither None nor a handle class
        (`Bound | Path`, `Bound | Path | None`, `Bound | str`); `held` / `trees` likewise. An exact
        or optional handle annotation is no tree slot (only mypy holds a caller to it)."""
        members = self._union_members(ann)
        origins = [self.origin(m) if isinstance(m, (ast.Name, ast.Attribute)) else None
                   for m in members]
        if TREE_ALIAS in origins:
            return "bound"
        handles = set(HANDLE_TYPES.values())
        if not any(not _is_none(m) and o not in handles for m, o in zip(members, origins, strict=True)):
            return None
        return next((kind for kind in ("bound", "held", "trees") if HANDLE_TYPES[kind] in origins),
                    None)

    def tree_params(self, fn: _FnDef) -> list[tuple[int, str, str]]:
        """`(positional index or -1, name, kind)` of each tree slot of `fn` (a def of this
        module): each named parameter whose annotation has a `tree_kind`."""
        return [(i, p.arg, kind) for i, p in _slot_params(fn)
                if (kind := self.tree_kind(p.annotation)) is not None]

    def tree_slots(self, origin: str | None) -> set[tuple[int, str, str]]:
        """The tree slots of the callee `origin` names: a handle-taking function's (`READERS`: a
        `Bound`, or `view_at`'s `Held`), else every tree slot (`tree_params`) of the top-level def it names in the
        scanned tree — `_corpus._lessons` / `_templates` / `_spelled` among them."""
        if origin in READERS:
            return {READERS[origin]}
        found = self.def_of(origin)
        if found is None:
            return set()
        scan, fn = found
        return set(scan.tree_params(fn))

    def passes_through(self, value: ast.expr, at: ast.AST, kind: str) -> bool:
        """`value`, handed to a tree slot at `at`, is the enclosing def's own tree slot of the
        same kind, never rebound in it — and that def is the top-level def its module's calls
        resolve to (its last definition), so every call of it is judged by this same rule: the
        value is judged where it enters (`iter_lessons(corpus)` -> `_lessons(corpus, ...)`)."""
        fn = self.innermost_def(at)
        if not isinstance(value, ast.Name) or fn is None:
            return False
        found = self.def_of(f"{self.dotted}.{fn.name}")
        if found is None or found[1] is not fn or value.id in self.bindings(fn):
            return False
        return any(p.arg == value.id and self.tree_kind(p.annotation) == kind
                   for _i, p in _slot_params(fn))

    def handle_verb(self, receiver: ast.expr, verb: str) -> bool:
        """`receiver.<verb>` is a provable `Held`'s or `Bound`'s own verb."""
        return any(verb in self.tree.verbs.get(kind, ()) and self.provable(receiver, kind)
                   for kind in ("held", "bound"))

    # -- the scan ---------------------------------------------------------------------------

    def hit(self, node: ast.AST, kind: str) -> None:
        self.hits.append(Hit(self.module, self.qualname(node), kind, ast.unparse(node),
                             getattr(node, "lineno", 0), getattr(node, "end_lineno", 0) or 0))

    def scan(self) -> list[Hit]:
        for node in ast.walk(self.ast):
            if isinstance(node, ast.Call):
                self.scan_call(node)
                self.scan_tree_for(node)
            if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
                self.scan_load(node)
            if isinstance(node, ast.Attribute):
                self.scan_private(node)
                self.scan_listing(node)
            if isinstance(node, ast.ImportFrom):
                self.scan_import(node)
        self.hits.sort(key=lambda h: (h.line, h.kind, h.text))
        return self.hits

    def scan_call(self, call: ast.Call) -> None:
        origin = self.callee(call)
        if origin == LIST_TREE or self.curator_reaches_a_lister(origin):
            self.hit(call, "listing")  # beside the `reader` judgement of its view slot below
        if origin in CONSTRUCTORS or self.rebuilds_paths(call, origin) or self.rebuilds_own_class(call):
            self.hit(call, "construct")
        elif slots := self.tree_slots(origin):
            for index, name, kind in sorted(slots):
                value = slot_value(call.args, call.keywords, index, name)
                if value is None or not (self.provable(value, kind)
                                         or self.passes_through(value, call, kind)):
                    self.hit(call, "reader")
                    break
        elif origin is not None and self.tree.in_vocabulary(origin):
            self.hit(call, "call")
        elif origin in ("builtins.getattr", "operator.methodcaller", "operator.attrgetter"):
            if self.names_a_word(call, origin):
                self.hit(call, "getattr")
        else:
            self.scan_method(call)

    def names_a_word(self, call: ast.Call, origin: str) -> bool:
        """`getattr(x, "<word>")`, `operator.methodcaller("<word>")`, or
        `operator.attrgetter("<a>", "<b>.<c>", ...)` naming a word in any segment; or
        `getattr(<defender._io>, "_<anything>")`."""
        if origin == "operator.attrgetter":
            words = [w for a in call.args for w in (_astlib.str_value(a, self.env) or "").split(".")]
        else:
            slot = 1 if origin == "builtins.getattr" else 0
            word = _astlib.str_value(call.args[slot], self.env) if len(call.args) > slot else None
            words = [word] if word else []
            if (origin == "builtins.getattr" and word and word.startswith("_")
                    and self.origin(call.args[0]) == "defender._io"):
                return True
        return any(w in self.tree.getattr_words() for w in words)

    def scan_import(self, node: ast.ImportFrom) -> None:
        """`from defender._io import _create_named` (relative, or through a re-export): an `_io`
        underscore name imported. Its every use is a hit of its own too."""
        module = node.module or ""
        if node.level:
            base = package_of(self.dotted, self.module.endswith("__init__.py")).split(".")
            module = ".".join([*base[: len(base) - (node.level - 1)], *([module] if module else [])])
        for a in node.names:
            mod, _, leaf = self.tree.canonical(f"{module}.{a.name}").rpartition(".")
            if mod == "defender._io" and leaf.startswith("_"):
                self.hit(node, "load")
                return

    def scan_tree_for(self, call: ast.Call) -> None:
        """A `tree_for=` keyword (any callee) that is not provably a `TreeFor`; a `TreeFor` slot
        of the callee (`tree_for_slots`; through `functools.partial(<callee>, ...)` too) not
        handed a provable `TreeFor` — one it is not handed at all, or that a `*` / `**` argument
        hides (`slot_value`), included; and a `**` argument to a callee that is not a def of the
        scanned tree (a value, a class such as `LeadAuthorDeps`, `dataclasses.replace`), whose
        keys may hold `tree_for`."""
        given = [kw.value for kw in call.keywords if kw.arg == "tree_for"]
        origin, args = self.callee(call), list(call.args)
        if origin == "functools.partial" and args and isinstance(args[0], (ast.Name, ast.Attribute)):
            origin, args = self.origin(args[0]), args[1:]
        hidden = any(kw.arg is None for kw in call.keywords) and self.def_of(origin) is None
        for index, name in self.tree_for_slots(origin):
            value = slot_value(args, call.keywords, index, name)
            if value is None:
                hidden = True
            else:
                given.append(value)
        if hidden or any(not self.provable(v, "tree_for") for v in given):
            self.hit(call, "tree_for")

    def curator_reaches_a_lister(self, origin: str | None) -> bool:
        """In a curator module, a call of any def that lists a folder, however deep (`lister`): a
        shared reader, a `_corpus` name selector, a curator helper that calls one
        (`build_corpus_manifest`, `existing_finding_ids`) — each call site is its own hit, so a
        new one (a sweep's names from `iter_lesson_paths`, or from a manifest) is a new anchor."""
        return self.module in CURATOR_MODULES and self.lister(origin)

    def lister(self, origin: str | None, seen: frozenset[str] = frozenset()) -> bool:
        """`origin` names a top-level def of the scanned tree whose body (nested defs included)
        lists a folder: an `.entries(...)` call, a `list_tree(...)` call, or a call of another
        such def, however deep — B2's kind checks (`KIND_CHECKS`) aside. A def that leans on
        itself proves nothing more."""
        if origin is None or origin in seen or origin in KIND_CHECKS:
            return False
        found = self.def_of(origin)
        # A def of this scan's own (possibly patched) source is memoized on the scan, one read off
        # the checkout on the tree.
        memo = self._lists if found is not None and found[0] is self else self.tree.lists
        if origin in memo:
            return memo[origin]
        got = False
        if found is not None:
            scan, fn = found
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                f = node.func
                callee = scan.callee(node)
                if ((isinstance(f, ast.Attribute) and f.attr == LISTING_VERB) or callee == LIST_TREE
                        or scan.lister(callee, seen | {origin})):
                    got = True
                    break
        if not seen:
            memo[origin] = got
        return got

    def scan_listing(self, node: ast.Attribute) -> None:
        """A raw listing (#1134 addendum 2, B2/B3): `<x>.entries(...)` called, on any receiver and
        with any arguments (`Bound.entries` is the only `entries` method scan A calls, and a
        listing record's `.entries` field is never called: `view.entries(*())` and the unbound
        `type(view).entries(view)` are listings too — s7v3 A, B); or `.entries` referenced without
        being called off a provable `Bound`, a `type(...)` call, or the `Bound` class
        (`f = view.entries`, `type(view).entries`)."""
        if node.attr != LISTING_VERB or not isinstance(node.ctx, ast.Load):
            return
        up = self.parent.get(node)
        if isinstance(up, ast.Call) and up.func is node:
            self.hit(up, "listing")
        elif (self.provable(node.value, "bound") or self.origin(node.value) == BOUND
              or (isinstance(node.value, ast.Call) and self.callee(node.value) == "builtins.type")):
            self.hit(node, "listing")

    def scan_private(self, node: ast.Attribute) -> None:
        """A handle's private attribute, anywhere but on `self` in a class that assigns it."""
        owners = self.tree.private_attrs.get(node.attr)
        if owners is None:
            return
        cls = self.innermost_class(node)
        own = cls is not None and f"{self.dotted}.{cls.name}" in owners
        if not (own and isinstance(node.value, ast.Name) and node.value.id == "self"):
            self.hit(node, "private")

    @staticmethod
    def rebuilds_paths(call: ast.Call, origin: str | None) -> bool:
        """A fresh path owner: `LoopPaths(...)` / `DefenderPaths(...)`, `<any>.with_repo_root(...)`
        (a spelling pin: `LoopPaths`' own method), or `dataclasses.replace(..., repo_root=...)`
        (or with a `**` mapping, which may hold `repo_root`)."""
        f = call.func
        return (
            origin in PATH_OWNERS
            or (isinstance(f, ast.Attribute) and f.attr == "with_repo_root")  # lint-ast-resolve: ok — a spelling pin on LoopPaths' method, documented in test_1134_census
            or (origin == "dataclasses.replace" and (_astlib.has_kw(call, "repo_root") or any(
                kw.arg is None for kw in call.keywords)))
        )

    def rebuilds_own_class(self, call: ast.Call) -> bool:
        """`x.__class__(...)` or `type(x)(...)`: a fresh object of whatever `x` is — a handle
        or a path owner rebuilt without naming its class."""
        f = call.func
        return (
            (isinstance(f, ast.Attribute) and f.attr == "__class__")  # lint-ast-resolve: ok — the dunder has one meaning
            or (isinstance(f, ast.Call) and len(f.args) == 1 and not f.keywords
                and self.callee(f) == "builtins.type")
        )

    def scan_method(self, call: ast.Call) -> None:
        f = call.func
        if not isinstance(f, ast.Attribute) or f.attr not in ATTRS:
            return
        receiver = self.origin(f.value)
        if receiver is not None and self.tree.is_module(receiver):
            if f.attr == "open":
                self.hit(call, "call")  # a module-level opener (`tarfile.open`, `gzip.open`)
            return
        if self.path_verb(f, call) and not self.handle_verb(f.value, f.attr):
            self.hit(call, "attr")

    def scan_load(self, node: ast.Name | ast.Attribute) -> None:
        up = self.parent.get(node)
        if isinstance(up, ast.Attribute) and up.value is node:
            return  # judged as part of the longer chain
        if self.bound_path_verb(node):
            self.hit(node, "load")
            return
        cur: ast.expr = node
        while isinstance(cur, (ast.Name, ast.Attribute)):
            up = self.parent.get(cur)
            origin = self.origin(cur)
            if self.tree.is_word(origin) or self.slot_def(cur, origin):
                # The longest word in the chain is the reference; a prefix of it (`DrainTrees`
                # in `DrainTrees.open(...)`) is that word's spelling, not a second reference.
                called = isinstance(up, ast.Call) and up.func is cur
                if not called and not (origin in CLASS_WORDS and self.class_reference(cur)):
                    self.hit(cur, "load")
                return
            if not isinstance(cur, ast.Attribute):
                return
            cur = cur.value

    def slot_def(self, node: ast.expr, origin: str | None) -> bool:
        """`node` names a def with a tree slot (`tree_slots`), or one with a `TreeFor` slot other
        than as `functools.partial`'s callee (where `scan_tree_for` judges its slots): the call
        it is handed to cannot be judged (``cb = _corpus._lessons``, ``map(_rules._still_there,
        ...)``)."""
        if self.tree_slots(origin):
            return True
        up = self.parent.get(node)
        partial = (isinstance(up, ast.Call) and up.args[:1] == [node]
                   and self.callee(up) == "functools.partial")
        return not partial and bool(self.tree_for_slots(origin))

    def bound_path_verb(self, node: ast.Name | ast.Attribute) -> bool:
        """`<value>.<Path verb>` referenced without being called (`partial(target.unlink)`,
        `map(p.read_text, ...)`): the verb runs later, wherever the reference is called. Not on
        a module or a `defender` class that defines it (`path_verb`), nor a provable handle's
        own verb."""
        if not isinstance(node, ast.Attribute) or node.attr not in ATTRS:
            return False
        up = self.parent.get(node)
        if isinstance(up, ast.Call) and up.func is node:
            return False
        if self.origin(node.value) in PATH_CLASSES:
            return False  # `Path.is_file`: the class-unbound branch (`is_word`) hits it
        return self.path_verb(node, None) and not self.handle_verb(node.value, node.attr)

    def class_reference(self, node: ast.expr) -> bool:
        """`node` names the class in an annotation (or a `TypeAlias`'s value), or as
        `isinstance`/`issubclass`'s class argument (possibly inside a tuple) — a type test, not
        a construction."""
        child: ast.AST = node
        up = self.parent.get(child)
        while isinstance(up, (ast.Tuple, ast.List, ast.BinOp, ast.Subscript, ast.Attribute)):
            child, up = up, self.parent.get(up)
        if isinstance(up, ast.arg) or (isinstance(up, ast.AnnAssign) and up.annotation is child):
            return True
        if (isinstance(up, ast.AnnAssign) and up.value is child
                and isinstance(up.annotation, (ast.Name, ast.Attribute))
                and self.origin(up.annotation) == "typing.TypeAlias"):
            return True
        if isinstance(up, _DEFS) and up.returns is child:
            return True
        return (isinstance(up, ast.Call) and child in up.args[1:2]
                and self.callee(up) in ("builtins.isinstance", "builtins.issubclass"))


@functools.cache
def tree_of(repo_root: Path) -> Tree:
    """The one `Tree` of the checkout at `repo_root`, shared by every census in the process."""
    return Tree(repo_root)


def census_source(
    repo_root: Path, module: str, source: str, tree: Tree | None = None,
    kinds: frozenset[str] = KINDS,
) -> list[Hit]:
    """The hits of `source`, scanned as if it were `module` of the checkout at `repo_root`."""
    tree = tree or Tree(repo_root)
    return [h for h in ModuleScan(tree, module, ast.parse(source)).scan() if h.kind in kinds]


def census(
    repo_root: Path, modules: Iterable[str] = D6_MODULES, *, tree: Tree | None = None,
    kinds: frozenset[str] = KINDS,
) -> list[Hit]:
    """The hits (of `kinds`) of every module in `modules` (paths under `defender/`) that exists
    under `repo_root`. A module absent from that checkout is skipped, so an older tree scans.
    `repo_root` is the checkout to scan — derive it from a file's own path, never from an
    import (the shared venv's editable install points at the main checkout)."""
    tree = tree or Tree(repo_root)
    out: list[Hit] = []
    for module in modules:
        path = repo_root / "defender" / module
        if not path.is_file():
            continue
        _, parsed = _astlib.read_and_parse(path, f"defender/{module}")
        out.extend(h for h in ModuleScan(tree, module, parsed).scan() if h.kind in kinds)
    return out


def opener_census(repo_root: Path, *, tree: Tree | None = None) -> list[Hit]:
    """Scan B: the `construct` hits of `OPENER_MODULES`."""
    return census(repo_root, OPENER_MODULES, tree=tree, kinds=frozenset({"construct"}))
