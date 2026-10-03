"""#1134 D6 (-> O1) and D5: a census of every host filesystem touch in the migrated modules.

During a drain batch the host reaches the writable trees (`defender/lessons/`,
`defender/lessons-questioner/`, `defender/skills/` in the drain working copy) only through
#1133's handles held at the mount points: writes through a `Held`, reads through its `Bound`
view, and the mounts held by the batch's `DrainTrees` (2026-10-01 addendum, A3/A4); folders
are listed only by B2's two helpers over `Bound.entries()` (`entry_kind`, `list_tree`: design
addendum 2), and the curator lists no folder at all (addendum 2's correction, C1). This test
scans with a pure-AST census (`_census1134`) and holds every hit against an allow-list keyed by
a stable anchor — ``(module, qualname, kind, call text)`` and a count, never a line number —
whose every entry names exactly one reason:

- ``N-a``  git's own reads and writes;
- ``N-d``  a path-only check (a `resolve()` that opens nothing in the trees, the
           `Path(__file__).resolve()` bootstraps);
- ``N-e``  a learning-queue sidecar or other host state (run dir, `_pending/`, markers);
- ``N-h``  a shared reader's `Path` form (its own `bind`, or a module CLI outside the drain);
- ``D3``   a path outside the lane's mounts (a `tree_for` miss, or a checked-in file
           elsewhere) — and the one mount list's own openers: the named `open_drain_trees(...)`
           calls, `DrainTrees.open`'s `hold`, and the path owners those openers read;
- ``B2``   a sanctioned listing (the `listing` kind only, and only that kind): B2's own helpers,
           the shared readers' fixed shapes, the catalog's drafts, `kind_at` at a mount point.

Two scans (`_census1134`): **scan A** (`D6_MODULES`: the D6 list, `learning/core/lane_trees.py`,
both curator channels' `run.py`, `_tree_listing.py` and `_git.py` — the curator's before-state
and sweep names are git's, so its git helpers take the full scan and their `git` children are
allow-listed N-a; `test_1134_curator_handle`'s AST pin on `_git.py` stays beside it) takes every
kind; **scan B** (`OPENER_MODULES`: scan A plus
`learning/core/drains.py`, `learning/author/_config.py`, `evals/harness.py`) takes `construct`
only — `drains.py` is queue machinery and the harness's `materialize` writes its own scratch
repo, neither has an N-reason for its other plain touches, but each opens a lane's trees. Each
module's row fails on a hit the table does not hold (listed with qualname, line and text) and on
an entry that no longer matches its hits with its exact count, so the table cannot rot. A real
unmigrated touch goes in `KNOWN_GAPS` (a strict-xfail row each), never in the table.

**What the census flags** (the vocabulary; `_census1134` has the exact sets):
every public `defender._io` callable except the pinned pure set `IO_PURE` (enumerated from
`_io.py`'s own source, so a new export is a census word the day it lands; the result records,
`NotPlainEntry` and the pure str helpers are pure; the value judges `load_json_artifact`,
`is_hard_linked` and `is_plain_entry` stay in by the dispatch's pin), and every underscore name
`_io` binds — its private disk helpers (`_create_named`, `_open_plain_fd`,
`_ensure_dir_component`, `_refuse_unless_plain`, `_leaf_is_link`, ...), classes and constants,
pure or not, so none is judged body by body and no scanned module reaches below the handle;
every public `defender._run_paths` function except a pinned pure set, enumerated the same way
and checked to be exactly the ones whose bodies touch disk; `os` / `os.path` filesystem
functions (with `os.path.lexists`), walks, xattrs, `chdir` / `chroot` / `pathconf` /
`chflags`, `os.system` / `popen` / `exec*` / `spawn*` / `posix_spawn*`; `shutil.*`, `glob.*`,
`tempfile.*`, `subprocess.*`, `filecmp.*`, `linecache.*`, `fileinput.*`, `dbm.*`, `shelve.*`,
`sqlite3.*`, `pty.*`, `py_compile.*`, `compileall.*`, `zipimport.*`; builtin `open`, `io.open`,
`io.FileIO`, `io.open_code`, `codecs.open`, `zipfile.ZipFile`, `tarfile.open`,
`runpy.run_path`, `importlib.util.spec_from_file_location`, `gzip.GzipFile`, `bz2.BZ2File`,
`lzma.LZMAFile`, `logging.FileHandler` and `logging.handlers`' file handlers,
`importlib.machinery`'s file loaders and `FileFinder`, `asyncio.create_subprocess_exec` /
`_shell`, any `<module>.open` however imported (`from gzip import open as g`);
`_paths.process_defender_dir`. Kinds:

- ``call``      a call of one of those.
- ``attr``      a Path-verb method call (`.is_file`, `.read_text`, `.mkdir`, `.unlink`,
                `.resolve`, `.is_fifo`, `.owner`, `.walk`, ...; on a value, `.replace` /
                `.rename` only in `Path`'s one-argument or `target=` shape and `.owner` only with
                none; on a `pathlib` class, `Path.replace(a, b)`, at any arity) on a receiver
                that is neither a module nor a provable `Held` / `Bound` whose class has that
                verb (`Held.mkdir`, `Held.unlink`; `Bound` has no `kind` or `walk`, addendum 2
                B1, and no `read_bytes`, addendum 3 D1, so `.walk()` or `.read_bytes()` on a view
                is a Path-verb hit).
- ``load``      any of the above, a shared reader or a constructor referenced without being
                called (`reader = read_text_soft`, `map(os.unlink, ps)`, `partial(hold)`,
                `filter(Path.is_file, ps)`, `_io._NOT_PLAIN`); a def with a tree slot or a
                `TreeFor` slot referenced so (`cb = _corpus._lessons`,
                `check = _rules._still_there` — the call it is handed to cannot be judged; a
                `TreeFor` slot's def as `functools.partial`'s callee is judged there instead);
                `from defender._io import _x`; and a Path verb referenced off a value without
                being called (`partial(target.unlink)`) unless it is a provable handle's own
                verb (`_left_for_scrub(name, corpus.unlink, name)`). A handle class or path owner
                in an annotation, a `TypeAlias` value or an `isinstance` test is not one.
- ``getattr``   `getattr(x, "<a vocabulary, Path-verb or handle-private name>")`,
                `operator.methodcaller("<such a name>")`, `operator.attrgetter(...)` naming one
                in any dotted segment of any argument, and `getattr(<defender._io>, "_<any>")`.
- ``construct`` building a handle or a path owner, by origin: `_io.hold`, `bind`, `hold_new`,
                `Held(...)`, `Bound(...)`, `DrainTrees(...)`, `DrainTrees.open(...)`,
                `lane_trees.open_drain_trees(...)`, `_corpus._viewed(...)`; `LoopPaths(...)`,
                `DefenderPaths(...)`, `<any>.with_repo_root(...)`,
                `dataclasses.replace(..., repo_root=...)` (or with a `**` mapping);
                `type(x)(...)`, `x.__class__(...)`.
                Allow-listed only at the named openers, by their unparsed call: swapping
                `DEFAULT_PATHS` into the harness's opener (s5v2 05b) or a constant label into a
                lane seam's (s6v2 E7) is a new anchor and leaves the old one stale.
- ``reader``    a call whose *tree slot* is not handed a provable handle of the slot's kind:
                a handle-taking function's (`READERS`): the shared readers (`iter_lesson_paths`,
                `iter_lessons`, `iter_query_templates`, `read_query_template`, `load_catalog`,
                `load_lane_catalog`, `check_system_skill`, `build_corpus_manifest`,
                `build_curator_user_prompt`) and B2's helpers (`entry_kind`, `list_tree`), each a
                `Bound` — a `Held` there is a hit: the drain passes `.view()` — and `view_at`'s
                `Held`; or any parameter
                of the top-level def the call resolves to in the scanned tree annotated to admit
                a handle and something that is not one — the `_corpus.Tree` alias, `Bound | Path`,
                `Bound | Path | None` (a `Bound`; `Held | Path` a `Held`) — so `_corpus`'s
                private readers (`_lessons`, `_templates`, s7v2 03) are judged like its public
                ones. A slot not handed at all (`load_catalog()`) or hidden by a `*` / `**`
                argument is a hit. **Pass-through:** a value that is the enclosing top-level
                def's own tree slot of that kind, never rebound in it (that def being the one
                its module's calls resolve to), is no hit — that def's own calls are judged by
                this same rule, so a Path is caught where it enters (`iter_lessons(corpus)` ->
                `_lessons(corpus, ...)`; `build_corpus_manifest` -> `iter_lessons`). A method's,
                a nested def's or a `*args` parameter does not pass through.
- ``tree_for``  a `tree_for=` keyword argument (any callee), or a `TreeFor` slot — every
                parameter annotated exactly `TreeFor` (or `TreeFor | None`) of the top-level def
                the call resolves to in the scanned tree (`lane_trees.kind_at` / `read_at`'s
                positional 1 among them, pinned), also through
                `functools.partial(<def>, ...)` — not handed a provable `TreeFor`
                (`tree_for=lambda _p: None` sends every path to the D3 plain fallback: s6v2
                E1, E2a, E2b): handed something else, not handed at all (a partial that leaves
                it to a later call), or hidden by a `*` argument at or before it or a `**`
                mapping (`**{"tree_for": lambda _p: None}`, s7v2 02, 02b); and any `**` argument
                to a callee that is not a def of the scanned tree — a value (`g(**kw)`), a class
                (`LeadAuthorDeps(**kw)`), the stdlib (`dataclasses.replace(cfg, **kw)`) — whose
                keys may hold `tree_for` (scan A has no `**` argument at this base).
- ``private``   an attribute named for a handle's private state — every `self._x` the scanned
                `Held`, `Bound` (`_io.py`) and `DrainTrees` (`lane_trees.py`) assign: `_where`,
                `_root`, `_os`, `_handle`, `_prefix`, `_absent`, `_error`, `_owner`, `_held`,
                `_stack` — on any receiver but `self` inside a class that assigns it. The held
                mount's spelling `held._where` is where every "judge through the handle, then go
                by path" regression starts (s5v2 06, 10; s6v2 E9).
- ``listing``   a folder listed outside B2's sanctioned listers (#1134 addendum 2, B2/B3; C1):
                a raw `<x>.entries(...)` call at any arity, on any receiver (`Bound.entries` is
                the only `entries` method scan A calls; a listing record's `.entries` field is
                never called: `view.entries(*())`, `type(view).entries(view)` — s7v3 A, B); an
                uncalled `.entries` off a provable `Bound`, a `type(...)` call or the `Bound`
                class; any `list_tree(...)` call (resolved; its `view` slot is judged as
                `reader` too); and, in a curator module (`CURATOR_MODULES`: drain.py, shared.py,
                the two channel run.py), a call of any def of the scanned tree that lists,
                however deep (`lister`: a shared reader, a `_corpus` name selector, a curator
                helper over one — s7v3 C) — B2's kind checks `entry_kind` / `kind_at` aside.
                Allowed only at the named listers, reason `B2`: `_tree_listing`'s own three
                listings, `_corpus._listed` (the readers' fixed shapes), `_handoff.
                discover_system_drafts` (the catalog's drafts), `lane_trees.kind_at`'s one
                `.entries()` at a mount point (which `entry_kind` refuses: no listed parent), and
                the curator's reads of its corpus through `iter_lessons` for its findings' ids and
                its prompt's manifest (`CURATOR_READS`). No raw listing in a curator module, and
                no listing at all in drain.py (s5v3 K08, s6v3 E5/E6, s4v3 v1/v8/v12, s7v3 A-C). `Bound.under()` is
                not flagged: it validates a name and opens nothing (`_tree_listing`'s docstring),
                and it is rule 3 of a provable view; the listing happens at `.entries()`.

Callees resolve through imports, aliases, function-local and relative imports and `defender`
re-exports (`scripts/lint/_astlib.py` plus a static re-export walk of the scanned tree), never by
spelling. Git's own reads and writes through `_git` are not in the vocabulary (N-a by
construction; `test_1134_curator_handle` pins `_git.py` to no filesystem call).

**"Provably a handle"** — four kinds, `held` (`defender._io.Held`), `bound`
(`defender._io.Bound`), `trees` (`defender.learning.core.lane_trees.DrainTrees`) and `tree_for`
(`lane_trees.TreeFor`); this, and nothing else (`_census1134.ModuleScan.provable`):

1. a `Name` that is a parameter of the innermost enclosing def, annotated exactly the kind's
   class (resolved by origin; a string annotation is parsed; a union such as `Bound | Path`,
   `Any`, or the `_corpus.Tree` alias is not), with no default (a default the caller never
   proves — `v: Bound = cast(Bound, PATH)` — makes it unprovable; a `None` default makes it
   1b's optional), and never bound anywhere in that def's body — no
   assignment, augmented or annotated assignment, walrus, `for` / `with` / `except` /
   comprehension / `match` target, `del`, `global`, `nonlocal`, import, nested def, nor a nested
   def's or lambda's parameter of that name;
1b. such a parameter annotated exactly `<class> | None` (either order) or `Optional[<class>]`
   (no default, or a `None` one), or exactly `<class>` with a `None` default, never bound in the
   def body, at a use the None-guard (G) covers;
2. `held`: `<provable trees>.mount(...)`; `lane_skills(...)` / `lane_corpus(...)` (resolved,
   `HANDLE_SOURCES`) whose slot-0 `trees` argument is a provable `trees`; `hit[0]` where `hit`
   is a local bound only ever as `hit = <tree_for call>` (or its walrus); the pinned attribute
   spellings `cfg.corpus`, `self.cfg.corpus`, `deps.skills` (typed exactly `Held` on
   `CorpusAuthorConfig` / `LeadAuthorDeps`, pinned below);
3. `bound`: `<provable held>.view()` (no arguments); `<provable bound>.under(...)`;
   `lane_trees.view_at(<provable held>, ...)`;
4. `trees`: an `open_drain_trees(...)` or `DrainTrees.open(...)` call (resolved; each still a
   `construct` hit of its own);
5. `tree_for`: `<provable trees>.tree_for` (the attribute, not called); the pinned spellings
   `cfg.tree_for`, `self.cfg.tree_for`, `deps.tree_for` (typed exactly `TreeFor`, pinned
   below). A *`tree_for` call* is a call whose callee is a provable `tree_for`;
6. a local (not a parameter) whose every binding in the innermost def is one of: an assignment
   or walrus of a value provable as the kind (1-5, 7); a plain `with <value> as <name>:` target
   whose value is provable as the kind (`__enter__` returns `self` on all three classes, so
   `with open_drain_trees(...) as trees:` proves `trees`); for `held`, element 0 of a
   tuple-unpack of a `tree_for` call, or of a name bound only as `hit = <tree_for call>`; or a
   helper's returned handle (7), as the whole value or by tuple-unpack;
7. a helper's returned handle: a call that resolves to a plain (undecorated, not `async`)
   top-level def of the scanned tree, when every parameter of that def annotated exactly a
   handle class (or that class `| None`) is handed a value provable as that kind at the call,
   and every `return` of the def's own body (not a generator) hands back — as the whole value,
   or as tuple element *i* for a local unpacking the call — a value provable in the def's own
   scope by 1-7. A `return None` there (or, for the whole value, a body that can end without a
   `return`) makes the result *optional*: a local bound exactly once by it is provable only at a
   use the None-guard (G) covers with the guard after that binding. (`_rules._catalog_in_tree`
   answers `(view_at(held, name), where)` or `(None, where)`; its callers branch on
   `view is None`.)

G. **The None-guard.** A use is covered when, in the block holding its statement or an
   enclosing block up to the def's body, an earlier sibling statement is an `if` with no `else`
   whose body ends in `raise` or `return` and whose test is `<name> is None` or an `or` holding
   it (`if skills is None or where is None: raise TypeError`); or when the use sits in the
   `else` of an `if` with such a test, or in the body of an `if` whose test is
   `<name> is not None` or an `and` holding it. A guard after the use, in a sibling branch,
   nested inside an earlier sibling statement, `if not <name>:`, a leaving guard with an `else`,
   or a guard that can fall through covers nothing.

A construction is never provable but for the two `DrainTrees` openers (4): `hold(...)`,
`bind(...)`, `hold_new(...)`, `Held(...)`, `Bound(...)` and `_corpus._viewed(...)` give a handle
rooted wherever their path points, so a reader handed one is a `reader` hit beside the
`construct` hit (s6v2 E6, s5v2 07).

**`where=` is spelling, never a tree.** The `where` the drain hands `synthesize_drafts`,
`discover_system_drafts`, `build_handoff`, `_draft_contradicts_skill`, `_minted_identities`,
`load_lane_catalog`, the readers' own `where=` (and the `where` `_catalog_in_tree` /
`_template_in_tree` spell) is the Path a held folder is spelled as, never opened. The census
tells it apart by construction: `where` is never a reader's tree slot, and spelling uses (joins,
f-strings, passing it on as `where=`) are no kind of hit, while an opening use
(`where.is_dir()`, `read_text_soft(where / x)`, `bind(where)`) is a hit by the ordinary kinds —
s6v2 E4 as a fixture, and a positive control over those functions at this base.

**Known limits.** The rule is syntactic and, but for 7's one-level summaries, intraprocedural.
`cfg.corpus`, `self.cfg.corpus`, `deps.skills`, `cfg.tree_for`, `self.cfg.tree_for`,
`deps.tree_for` are spelling pins on the receiver names `cfg` / `deps` (their fields are typed,
pinned below; nothing checks that a `cfg` is a `CorpusAuthorConfig`), as are `.with_repo_root`
and the `tree_for` binding pin below. A parameter's annotation is trusted: only mypy enforces
that a `Held`-typed parameter receives one, and a handle built outside the scanned modules and
passed in is not seen. A `Path` handed to a non-vocabulary helper in another module that reads it
(`_flock`, `persist`, `lead_repository`, `_git`) is not seen. A computed name is not seen:
`getattr(p, "read_" + "text")`, `vars(os)["unlink"]`, `vars(held)["_where"]`. `isinstance`
narrowing is not understood (`_corpus`'s readers stand on their `construct` entries instead).
`listing` matches `.entries(...)` by name (any receiver) and an uncalled `.entries` only off a
provable `Bound`, a `type(...)` call or the class (an uncalled reference on an unprovable
receiver collides with the listing records' `.entries` field); outside the curator modules a
listing reached through a helper is the helper's, not the caller's, and a method or a value
called (`cfg.invoke_repair(...)`) is never judged a lister. `private` matches attribute names, so an unrelated `x._os` in a scanned module is a hit by
design, and a handle's private methods (`Held._dup`) are not in it (each hands back a
descriptor, whose use is an `os.*` call). An `_io` underscore name is a word wherever it is
named, so a pure private helper or constant used in a scanned module is a hit by design too.
A handle-typed parameter that is not a tree slot (exactly `Bound`, `Held`) is trusted at its
callers, as rule 1 says. The stdlib's long tail of path-taking calls outside the sets above
(`xml.etree.ElementTree.parse(path)`, `configparser.ConfigParser().read(path)`, `mailbox`,
`ctypes.CDLL`) is not in the vocabulary. The handle's own verbs (`.read`, `.write`, `.view`,
`.under`) are not Path verbs, so on a receiver the rule cannot prove they are not hits.
`Path.group()` is not in the vocabulary: it collides with every zero-argument
`re.Match.group()`. An allow-list entry is an anchor, not a control-flow fact, so each `D3`
fallback's plain touch (`TREE_FOR_FALLBACKS`) is also pinned behind its miss: in the body of an
`if <miss> is None:`, the true arm of `... if <miss> is None else ...`, or after an earlier
sibling `if <miss> is not None:` that always leaves, where `<miss>` is a `tree_for(...)` result
or element 0 of a rule-7 helper's optional `Bound` (s7v3 E). That is a syntactic pin; whether the
handle branch does the right thing is D7's behaviour tests' job. A module-level path owner
(`DEFAULT_PATHS`, `loop_paths()`) is not a fresh one and not a hit, and an owner rebuilt by
another spelling (`model_copy`, a helper in another module) is not seen.

**D5** (`test_d5_*`): no new `lint-unguarded-tree-write` / `lint-tree-read-follows-link` waiver
in scan A, and every waiver kept there sits on a census hit allow-listed `N-e` (or is the write
lint's name-match on `Held.mkdir`). The baseline pin is red until #1134's D5 commit edits the
baseline: it lists the scan-A keys that commit keeps, each with its reason.
"""
from __future__ import annotations

import ast
import functools
import json
from collections import Counter
from pathlib import Path
from typing import NamedTuple

import pytest

from defender.tests import _census1134 as C
from defender.tests._by_path import import_lint_lib

_astlib = import_lint_lib("_astlib")

#: The worktree this file lives in — never `defender.__file__`: the shared venv's editable
#: install points at the main checkout, so an import-derived root would scan the wrong tree.
WORKTREE = Path(__file__).resolve().parents[2]
TREE = C.Tree(WORKTREE)

DRAIN = "learning/author/drain.py"
SHARED = "learning/author/shared.py"
CORPUS = "_corpus.py"
SCAFFOLD = "_scaffold_rules.py"
SYNTH = "learning/leads/draft_synthesis.py"
NEIGHBORS = "learning/leads/lead_neighbors.py"
RENDER = "learning/leads/lead_render.py"
EXTRACTION = "learning/leads/lead_extraction.py"
PITFALLS = "learning/leads/pitfalls_curator.py"
SPINE = "learning/leads/_lead_spine.py"
LEAD_AUTHOR = "learning/leads/lead_author/__init__.py"
RULES = "learning/leads/lead_author/_rules.py"
HANDOFF = "learning/leads/lead_author/_handoff.py"
LANE_TREES = "learning/core/lane_trees.py"
LESSONS_RUN = "learning/author/lessons/run.py"
QUESTIONER_RUN = "learning/author/questioner/run.py"
TREE_LISTING = "_tree_listing.py"
GIT = "_git.py"
DRAINS = "learning/core/drains.py"
CONFIG = "learning/author/_config.py"
HARNESS = "evals/harness.py"

N_A, N_D, N_E, N_H, D3, B2 = "N-a", "N-d", "N-e", "N-h", "D3", "B2"
REASONS = frozenset({N_A, N_D, N_E, N_H, D3, B2})


class Allowed(NamedTuple):
    module: str
    qualname: str
    kind: str
    text: str
    reason: str
    why: str
    count: int = 1

    @property
    def anchor(self) -> tuple[str, str, str, str]:
        return (self.module, self.qualname, self.kind, self.text)


class Gap(NamedTuple):
    module: str
    qualname: str
    kind: str
    text: str
    proposed: str

    @property
    def anchor(self) -> tuple[str, str, str, str]:
        return (self.module, self.qualname, self.kind, self.text)


_BOOTSTRAP = "Path(__file__).resolve()"
_BOOTSTRAP_WHY = "resolves the module's own file to put the repo root on sys.path; opens nothing in the trees"
_MISS = "`tree_for(...)` is None: the path lies outside the lane's mounts (the box's read-only area)"
_OPENER = "the lane's one mount list, held at its named opener (A3/O4)"
_VIEWED = "the Path form's own `bind`: a `Bound` passes through as given"
_FINDING_IDS = ("the finding-id pre-flight reads the corpus's lessons through `iter_lessons` over the "
                "held view (A4); it names no file to touch")
_MANIFEST = ("the curator prompt's corpus manifest reads the lessons through `iter_lessons` over the "
             "held view (A4); it names no file to touch")
_GIT = "git's own read or write (a `git` child process), never a path opened here"

#: Every host filesystem touch the migrated modules keep at base 87f013fe (the v3 curator head),
#: re-derived by reading each function (seeded from the v3 step log's "plain-path lines" lists
#: for step 4, the lead-author step and the curator step).
ALLOW: tuple[Allowed, ...] = (
    # --- learning/author/drain.py -------------------------------------------------------------
    Allowed(DRAIN, "_put_back", "attr", "target.unlink()", D3,
            _MISS + "; `kind_at` answered it from that path, and only a file is unlinked"),
    Allowed(DRAIN, "retire", "call", "read_jsonl_rows(channel.file)", N_E, "the channel's queue"),
    Allowed(DRAIN, "_bump_rows", "call",
            "append_jsonl(graveyard_file(channel), [{key: rec[key], 'attempts': rec[counter_key], 'deadletter_reason': reason, **retirement_stamp(), 'row': {k: v for k, v in rec.items() if k != counter_key}} for rec in retired])",
            N_E, "the channel's graveyard sidecar"),
    Allowed(DRAIN, "_tick", "call", "read_jsonl_rows_report(channel.file)", N_E, "the channel's queue"),
    Allowed(DRAIN, "_spawn_repair", "attr", "cfg.repair_prompt.is_file()", D3,
            "the checked-in repair prompt under learning/author/, outside every mount"),
    Allowed(DRAIN, "_append_gap_record", "call",
            "append_jsonl(cfg.pending_dir / GAP_LEDGER_NAME, [record])", N_E, "the gap ledger in _pending/"),
    Allowed(DRAIN, "_resolves_inside_runs_dir", "attr", "runs_dir.resolve()", N_D,
            "containment check of a queue row's run id under the host runs dir"),
    Allowed(DRAIN, "_resolves_inside_runs_dir", "attr", "(runs_dir / source_id).resolve()", N_D,
            "containment check of a queue row's run id under the host runs dir"),
    Allowed(DRAIN, "_retire_unkeyable", "call",
            "append_jsonl(graveyard_file(channel), [{**row, 'attempts': int(row.get('attempts') or 0) + 1, 'deadletter_reason': reason, **retirement_stamp()} for row in rows])",
            N_E, "the channel's graveyard sidecar"),
    Allowed(DRAIN, "stuck_record_count", "attr", "path.is_file()", N_E, "the channel's stuck report"),
    Allowed(DRAIN, "stuck_record_count", "call", "read_jsonl_rows(path)", N_E, "the channel's stuck report"),
    Allowed(DRAIN, "_record_stuck", "call", "read_jsonl_rows(path)", N_E, "the channel's stuck report"),
    Allowed(DRAIN, "_record_stuck", "call",
            "append_jsonl(path, [{'fault_class': fault_class, 'row_ids': ids, 'consecutive_ticks': consecutive, 'reason': str(exc), 'recorded_at': now_iso()}])",
            N_E, "the channel's stuck report"),
    # --- learning/author/shared.py ------------------------------------------------------------
    Allowed(SHARED, "invoke_repair", "attr", "cfg.pending_dir.mkdir(parents=True, exist_ok=True)", N_E,
            "the host-side _pending/ queue dir"),
    Allowed(SHARED, "write_disposition_report", "attr", "pending_dir.mkdir(parents=True, exist_ok=True)",
            N_E, "the host-side _pending/ queue dir"),
    Allowed(SHARED, "write_disposition_report", "attr", "report.open('a', encoding='utf-8')", N_E,
            "the held report in _pending/"),
    # --- _corpus.py: the shared readers' own Path form ----------------------------------------
    Allowed(CORPUS, "_viewed", "construct", "bind(Path(tree))", N_H, _VIEWED),
    Allowed(CORPUS, "iter_lesson_paths", "construct", "_viewed(corpus)", N_H, _VIEWED),
    Allowed(CORPUS, "_lessons", "construct", "_viewed(corpus)", N_H, _VIEWED),
    Allowed(CORPUS, "read_query_template", "construct", "bind(path.parent)", N_H,
            "the Path form: the file's own folder bound for one read"),
    Allowed(CORPUS, "_templates", "construct", "_viewed(catalog)", N_H, _VIEWED),
    # --- _scaffold_rules.py -------------------------------------------------------------------
    Allowed(SCAFFOLD, "check_system_skill", "construct", "bind(path.parent)", N_H,
            "the Path form (validate_scaffold and other callers outside the drain)"),
    # --- module bootstraps --------------------------------------------------------------------
    Allowed(SYNTH, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    Allowed(NEIGHBORS, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    Allowed(RENDER, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    Allowed(EXTRACTION, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    Allowed(PITFALLS, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    Allowed(SPINE, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    Allowed(LEAD_AUTHOR, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    Allowed(RULES, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    Allowed(HANDOFF, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    Allowed(LESSONS_RUN, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    Allowed(QUESTIONER_RUN, "<module>", "attr", _BOOTSTRAP, N_D, _BOOTSTRAP_WHY),
    # --- learning/leads/lead_neighbors.py -----------------------------------------------------
    Allowed(NEIGHBORS, "load_catalog", "reader", "iter_query_templates(root, where=where)", N_H,
            "`root` is the caller's view, or the Path / None (PATHS.catalog_dir) form"),
    Allowed(NEIGHBORS, "_cmd_score", "reader", "load_catalog(args.catalog)", N_H,
            "the module's own CLI, outside the drain"),
    Allowed(NEIGHBORS, "_cmd_dump", "reader", "load_catalog(args.catalog)", N_H,
            "the module's own CLI, outside the drain"),
    # --- learning/leads/lead_extraction.py ----------------------------------------------------
    Allowed(EXTRACTION, "extract_from_joined", "attr", "q.raw_ref.is_file()", N_E,
            "a raw payload in the run dir"),
    # --- learning/leads/pitfalls_curator.py ---------------------------------------------------
    Allowed(PITFALLS, "_graveyard_dropped_rows", "call",
            "append_jsonl(_author_drain.graveyard_file(paths.pitfalls), entries)", N_E,
            "the pitfalls queue's graveyard sidecar"),
    # --- learning/leads/_lead_spine.py --------------------------------------------------------
    Allowed(SPINE, "_spawn_author_agent", "attr", "PENDING_DIR.mkdir(parents=True, exist_ok=True)", N_E,
            "the host-side lead-pending state dir"),
    # --- learning/leads/lead_author/__init__.py: run-dir state, and the CLI's opener ----------
    Allowed(LEAD_AUTHOR, "_write_state", "attr", "path.parent.mkdir(parents=True, exist_ok=True)", N_E,
            "the run dir's lead_author/ state"),
    Allowed(LEAD_AUTHOR, "_write_state", "attr", "path.write_text(content, encoding='utf-8')", N_E,
            "the run dir's lead_author/ state"),
    Allowed(LEAD_AUTHOR, "run", "attr", "run_dir.is_dir()", N_E, "the run dir"),
    Allowed(LEAD_AUTHOR, "run", "construct", "open_drain_trees(paths, label)", D3, _OPENER),
    Allowed(LEAD_AUTHOR, "run_under_held_queue_lock", "attr", "run_dir.is_dir()", N_E, "the run dir"),
    Allowed(LEAD_AUTHOR, "_run_locked", "attr", "_done_sentinel(run_dir).is_file()", N_E,
            "the run dir's done sentinel"),
    Allowed(LEAD_AUTHOR, "_run_locked", "attr", "collected_marker.is_file()", N_E,
            "the run dir's pitfalls_collected marker"),
    # --- learning/leads/lead_author/_rules.py: tree_for misses ---------------------------------
    Allowed(RULES, "_template_in_tree", "reader", "_corpus.read_query_template(full)", D3, _MISS),
    Allowed(RULES, "_skills_content_rule", "reader",
            "_scaffold_rules.check_system_skill(repo_root / path, system)", D3, _MISS),
    Allowed(RULES, "_answered_after_batch", "reader", "lead_neighbors.load_catalog(where)", D3,
            "`_catalog_in_tree`'s plain path, behind `view is None`: " + _MISS),
    Allowed(RULES, "_catalog_drafts", "attr", "where.glob('*/_draft/*.md')", D3,
            "`_catalog_in_tree`'s plain path, behind `view is None`: " + _MISS),
    Allowed(RULES, "_catalog_drafts", "reader", "_corpus.read_query_template(p)", D3,
            "`_catalog_in_tree`'s plain path, behind `view is None`: " + _MISS),
    # --- learning/core/lane_trees.py: the D3 fallbacks, and the one mount list's openers -------
    Allowed(LANE_TREES, "DrainTrees.open", "construct", "hold(p, os_=os_)", D3,
            "one `hold` per mount of the list it is handed, at the mount point itself (A3)"),
    Allowed(LANE_TREES, "open_drain_trees", "construct",
            "DrainTrees.open(wt_paths.drain_writable_trees(label))", D3,
            "exactly `drain_writable_trees(label)`, the list the box mounts rw (A3/O4)"),
    Allowed(LANE_TREES, "kind_at", "attr", "full.is_file()", D3, _MISS),
    Allowed(LANE_TREES, "kind_at", "attr", "full.is_dir()", D3, _MISS),
    Allowed(LANE_TREES, "kind_at", "call", "os.path.lexists(full)", D3, _MISS),
    Allowed(LANE_TREES, "read_at", "call", "read_text_soft(full)", D3, _MISS),
    # --- B2's listings (#1134 addendum 2): the owner, and the sanctioned listers ---------------
    Allowed(TREE_LISTING, "entry_kind", "listing",
            "(view.under(folder) if folder else view).entries()", B2,
            "B2's own helper: the one listing of a name's parent"),
    Allowed(TREE_LISTING, "list_tree", "listing", "view.entries()", B2,
            "B2's own helper: the top of a fixed-shape listing"),
    Allowed(TREE_LISTING, "list_tree", "listing", "view.under(folder).entries()", B2,
            "B2's own helper: each folder of the shape listed on its own"),
    Allowed(CORPUS, "_listed", "listing", "list_tree(view, depth=depth)", B2,
            "the shared readers' fixed shapes: a lesson corpus at depth 1, the catalog at 3"),
    Allowed(HANDOFF, "discover_system_drafts", "listing", "list_tree(skills, depth=3)", B2,
            "the catalog's fixed shape, `<sys>/_draft/<draft>` (B3: discover_system_drafts)"),
    Allowed(LANE_TREES, "kind_at", "listing", "held.view().entries()", B2,
            "the mount point itself, which `entry_kind` refuses (it has no listed parent below "
            "the mount): its own listing says present, absent or refused"),
    # --- the curator's reads of its corpus through a shared reader (C1: never a sweep's or a
    # --- before-state's names) — each call site of a def that lists, however deep ---------------
    Allowed(SHARED, "existing_finding_ids", "listing",
            "iter_lessons(cfg.corpus.view(), where=cfg.corpus_dir, warn_label=lambda p: f'finding-id pre-flight: {p.name}')",
            B2, _FINDING_IDS),
    Allowed(SHARED, "build_corpus_manifest", "listing",
            "iter_lessons(corpus, where=where, warn_label=lambda p: f'corpus manifest: {p.name}', on_skip=skipped.append)",
            B2, _MANIFEST),
    Allowed(SHARED, "build_curator_user_prompt", "listing",
            "build_corpus_manifest(corpus, where=corpus_dir, seed=seed)", B2, _MANIFEST),
    Allowed(LESSONS_RUN, "existing_finding_ids", "listing", "_shared.existing_finding_ids(cfg)", B2,
            _FINDING_IDS),
    Allowed(LESSONS_RUN, "_gate_findings", "listing", "existing_finding_ids(cfg)", B2, _FINDING_IDS),
    Allowed(LESSONS_RUN, "build_user_prompt", "listing",
            "_shared.build_curator_user_prompt(findings, batch_id, corpus=cfg.corpus.view(), corpus_dir=cfg.corpus_dir, corpus_dir_rel=cfg.corpus_dir_rel, label='findings', manifest_seed=cfg.manifest_seed, salt=salt)",
            B2, _MANIFEST),
    Allowed(LESSONS_RUN, "invoke_agent", "listing", "build_user_prompt(findings, batch_id, cfg, salt=stage_salt)",
            B2, _MANIFEST),
    Allowed(QUESTIONER_RUN, "questioner_existing_finding_ids", "listing",
            "_shared.existing_finding_ids(cfg)", B2, _FINDING_IDS),
    Allowed(QUESTIONER_RUN, "_gate_questioner", "listing", "questioner_existing_finding_ids(cfg)", B2,
            _FINDING_IDS),
    Allowed(QUESTIONER_RUN, "build_questioner_user_prompt", "listing",
            "_shared.build_curator_user_prompt(findings, batch_id, corpus=cfg.corpus.view(), corpus_dir=cfg.corpus_dir, corpus_dir_rel=cfg.corpus_dir_rel, label='world findings', manifest_seed=cfg.manifest_seed, salt=salt)",
            B2, _MANIFEST),
    Allowed(QUESTIONER_RUN, "invoke_agent", "listing",
            "build_questioner_user_prompt(findings, batch_id, cfg, salt=stage_salt)", B2, _MANIFEST),
    # --- _git.py: git's own reads and writes ---------------------------------------------------
    Allowed(GIT, "<module>", "attr", _BOOTSTRAP, N_D,
            "resolves the module's own file for the default `cwd` (the checkout); opens nothing"),
    Allowed(GIT, "_run", "load", "subprocess.CompletedProcess", N_A,
            "the return annotation: git's result type"),
    Allowed(GIT, "_run", "call",
            "subprocess.run(['git', *args], cwd=cwd, capture_output=True, text=True, encoding='utf-8', errors='surrogateescape', timeout=timeout, input=input)",
            N_A, _GIT),
    Allowed(GIT, "git_unchanged_since", "call",
            "subprocess.run(['git', *args], cwd=cwd, capture_output=True, check=False, env={**os.environ, 'GIT_ATTR_SOURCE': rev})",
            N_A, _GIT + " (`diff --name-only` against the before-state's commit: the curator's "
            "three \"still the before-state?\" checks, addendum 3 D1)"),
    Allowed(GIT, "_run_bytes", "call",
            "subprocess.run(['git', *args], cwd=cwd, capture_output=True, input=input, check=False)",
            N_A, _GIT + " (the before-state's `ls-tree` / `cat-file --batch`)"),
    Allowed(GIT, "git_worktree_files", "call",
            "subprocess.run(['git', *args], cwd=cwd, capture_output=True, check=False, env={**os.environ, 'GIT_INDEX_FILE': absent_index})",
            N_A, _GIT + " (`ls-files` against an index file that does not exist: the restore's "
            "fallback when `git status` fails)"),
    # --- the curator channels' run.py ---------------------------------------------------------
    Allowed(LESSONS_RUN, "disposition_for", "attr", "refs.is_file()", N_E,
            "the run dir's source_refs (`RunPaths(runs_dir / run_id).source_refs`)"),
    Allowed(LESSONS_RUN, "disposition_for", "attr", "refs.read_text(encoding='utf-8')", N_E,
            "the run dir's source_refs (`RunPaths(runs_dir / run_id).source_refs`)"),
    Allowed(LESSONS_RUN, "invoke_agent", "attr", "cfg.pending_dir.mkdir(parents=True, exist_ok=True)",
            N_E, "the host-side _pending/ queue dir"),
    Allowed(LESSONS_RUN, "main", "construct", "open_drain_trees(DEFAULT_PATHS, AUTHOR_DRAIN_LABEL)",
            D3, "the CLI's own trees over the live checkout, for its lane's label: " + _OPENER),
    Allowed(QUESTIONER_RUN, "invoke_agent", "attr",
            "cfg.pending_dir.mkdir(parents=True, exist_ok=True)", N_E, "the host-side _pending/ queue dir"),
    Allowed(QUESTIONER_RUN, "main", "construct",
            "open_drain_trees(DEFAULT_PATHS, AUTHOR_DRAIN_LABEL)", D3,
            "the CLI's own trees over the live checkout, for its lane's label: " + _OPENER),
    # --- scan B only: the lane seams and the eval harness (`construct`) -------------------------
    Allowed(DRAINS, "_invoke_lead_author", "construct", "open_drain_trees(paths, label)", D3,
            "the lead-author work step's trees, for the label its seam was bound: " + _OPENER),
    Allowed(DRAINS, "_maybe_trigger_author", "construct", "open_drain_trees(paths, label)", D3,
            "the curators' work step's trees, for the label its seam was bound: " + _OPENER),
    Allowed(DRAINS, "_invoke_pitfalls", "construct", "open_drain_trees(paths, label)", D3,
            "the pitfalls work step's trees, for the label its seam was bound: " + _OPENER),
    Allowed(DRAINS, "_drain_box_request", "construct", "paths.with_repo_root(wt)", D3,
            "the drain working copy's paths, whose `drain_writable_trees(label)` the box mounts rw "
            "(A3/O4: the one mount list)"),
    Allowed(DRAINS, "_run_worktree_batch", "construct", "paths.with_repo_root(wt)", D3,
            "the drain working copy's paths handed to the work step, whose seam opens exactly "
            "their `drain_writable_trees(label)` (A3/O4: the one mount list)"),
    Allowed(HARNESS, "run_author", "construct", "LoopPaths(repo_root=tmp)", D3,
            "the harness's scratch repo: the paths its opener holds the author trees of "
            "(pinned to `<tmp>` by test_1134_curator_label)"),
    Allowed(HARNESS, "run_author", "construct", "open_drain_trees(paths, AUTHOR_DRAIN_LABEL)", D3,
            "the scratch repo's author trees: " + _OPENER),
)

#: Real unmigrated touches of a mount by plain path (or a handle built outside an allowed
#: opener) that no N-item or D3 covers. Each gets a strict-xfail row asserting it is gone;
#: none at base 87f013fe.
KNOWN_GAPS: tuple[Gap, ...] = ()

#: The allow-list's size by reason at this base — a guard against an entry slipping in
#: unannounced (update it with the table, and say why in the commit).
ALLOW_COUNT_BY_REASON = {N_E: 25, D3: 23, N_D: 14, N_H: 9, B2: 17, N_A: 5}


def judge(
    module: str, hits: list[C.Hit], allow: tuple[Allowed, ...] = ALLOW,
    gaps: tuple[Gap, ...] = KNOWN_GAPS, kinds: frozenset[str] = C.KINDS,
) -> tuple[list[C.Hit], list[str]]:
    """`(unexpected hits, stale entries)` of `module`: a hit beyond its anchor's allowed count
    (known gaps aside), and an entry whose anchor matched fewer hits than it allows. Only the
    entries and hits of `kinds` take part."""
    allowed = {e.anchor: e.count for e in allow if e.module == module and e.kind in kinds}
    gap_anchors = {g.anchor for g in gaps if g.module == module}
    seen: Counter[tuple[str, str, str, str]] = Counter()
    unexpected = []
    for h in hits:
        if h.module != module or h.anchor in gap_anchors or h.kind not in kinds:
            continue
        seen[h.anchor] += 1
        if seen[h.anchor] > allowed.get(h.anchor, 0):
            unexpected.append(h)
    stale = [f"{a[1]} {a[2]}: {a[3]} (allowed x{n}, found x{seen[a]})"
             for a, n in allowed.items() if seen[a] < n]
    return unexpected, stale


def kinds_of(module: str) -> frozenset[str]:
    """Every kind for a scan-A module, `construct` for a scan-B-only one."""
    return C.KINDS if module in C.D6_MODULES else frozenset({"construct"})


def _source(module: str) -> str:
    text, _ = _astlib.read_and_parse(WORKTREE / "defender" / module, f"defender/{module}")
    return text


def _report(module: str, unexpected: list[C.Hit], stale: list[str]) -> None:
    assert not unexpected, (
        f"{module}: host filesystem touches outside the allow-list (reach the tree through its "
        "held mount, or add an entry naming N-a/N-d/N-e/N-h/D3):\n  "
        + "\n  ".join(h.show() for h in unexpected))
    assert not stale, (
        f"{module}: stale allow-list entries (their hits are gone — delete them):\n  "
        + "\n  ".join(stale))


# =============================================================================================
# The census over the migrated modules at this base
# =============================================================================================

def test_every_scanned_module_is_present():
    """`census` skips a module a tree lacks (so an older tree scans); here, none may be missing,
    or a per-module row would pass on nothing."""
    missing = [m for m in C.OPENER_MODULES if not (WORKTREE / "defender" / m).is_file()]
    assert not missing, f"scanned modules missing from {WORKTREE}: {missing}"
    assert set(C.D6_MODULES) < set(C.OPENER_MODULES)


@pytest.mark.parametrize("module", C.D6_MODULES)
def test_the_module_touches_its_trees_only_through_the_handle(module: str):
    """Scan A: every hit is allow-listed with a reason, and every entry still matches its hits."""
    gaps = {g.anchor for g in KNOWN_GAPS if g.module == module}
    both = gaps & {e.anchor for e in ALLOW if e.module == module}
    assert not both, f"known gaps also allow-listed: {sorted(both)}"
    _report(module, *judge(module, C.census(WORKTREE, [module], tree=TREE)))


@pytest.mark.parametrize("module", C.OPENER_MODULES)
def test_the_module_builds_handles_only_at_the_named_openers(module: str):
    """Scan B: every `construct` hit (a handle or path owner built) is allow-listed, and every
    `construct` entry still matches."""
    _report(module, *judge(module, _opener_hits(), kinds=frozenset({"construct"})))


@functools.cache
def _opener_hits() -> list[C.Hit]:
    return C.opener_census(WORKTREE, tree=TREE)


def test_the_lane_seams_curator_modules_are_all_in_scan_a():
    """`drains._CURATOR_MODULES` names every module a lane seam imports and runs inside its
    `with open_drain_trees(...)`: each must take the full scan."""
    tree = ast.parse(_source(DRAINS))
    table = next(n.value for n in tree.body if isinstance(n, ast.Assign)
                 and [ast.unparse(t) for t in n.targets] == ["_CURATOR_MODULES"])
    assert isinstance(table, ast.Dict)
    dotted = [ast.literal_eval(v) for v in table.values]
    assert len(dotted) == 4, dotted
    for name in dotted:
        f = TREE.module_file(name)
        assert f is not None, name
        assert f.relative_to(WORKTREE / "defender").as_posix() in C.D6_MODULES, name


def _gap_rows() -> list:
    rows = [pytest.param(g, id=f"{g.module}:{g.qualname}",
                         marks=pytest.mark.xfail(strict=True, reason="unmigrated, see report"))
            for g in KNOWN_GAPS]
    return rows or [pytest.param(None, id="none", marks=pytest.mark.skip(
        reason="no known gaps at base 87f013fe"))]


@pytest.mark.parametrize("gap", _gap_rows())
def test_a_known_gap_is_closed(gap: Gap):
    hits = C.census(WORKTREE, [gap.module], tree=TREE)
    assert gap.anchor not in {h.anchor for h in hits}


def test_the_allow_list_is_well_formed():
    anchors = Counter(e.anchor for e in ALLOW)
    assert not [a for a, n in anchors.items() if n > 1], "one entry per anchor; use `count`"
    assert all(e.reason in REASONS for e in ALLOW), [e for e in ALLOW if e.reason not in REASONS]
    assert all(e.count >= 1 and e.why for e in ALLOW)
    assert {e.module for e in ALLOW} <= set(C.OPENER_MODULES)
    assert all(e.kind in C.KINDS for e in (*ALLOW, *KNOWN_GAPS))
    assert all(e.kind == "construct" for e in ALLOW if e.module not in C.D6_MODULES), (
        "a scan-B-only module is judged on `construct` alone")
    assert all((e.kind == "listing") == (e.reason == B2) for e in ALLOW), (
        "B2 names a sanctioned listing, and a listing has no other reason")
    by_reason = Counter()
    for e in ALLOW:
        by_reason[e.reason] += e.count
    assert dict(by_reason) == ALLOW_COUNT_BY_REASON


def test_every_construct_entry_is_a_named_opener_or_a_shared_readers_own_bind():
    """No handle is allow-listed as built anywhere but the one mount list's openers (D3) and the
    shared readers' Path form (N-h) — never a "name-only" or other reason."""
    construct = [e for e in ALLOW if e.kind == "construct"]
    assert {e.reason for e in construct} == {D3, N_H}
    assert {e.module for e in construct if e.reason == N_H} == {CORPUS, SCAFFOLD}


#: The modules that may list a folder at all (#1134 addendum 2, B2/B3): B2's owner, the shared
#: readers' fixed shapes, the catalog's drafts, and `kind_at` at a mount point. The curator lists
#: no folder (addendum 2 correction, C1): its before-state is git's and its sweep `git status`'s.
LISTERS = frozenset({
    (TREE_LISTING, "entry_kind"), (TREE_LISTING, "list_tree"), (CORPUS, "_listed"),
    (HANDOFF, "discover_system_drafts"), (LANE_TREES, "kind_at"),
})
#: The curator's reads of its corpus through a shared reader — the finding-id pre-flight and the
#: prompt's corpus manifest, each call site of a def that lists (`_census1134.lister`).
CURATOR_READS = frozenset({
    (SHARED, "existing_finding_ids"), (SHARED, "build_corpus_manifest"),
    (SHARED, "build_curator_user_prompt"), (LESSONS_RUN, "existing_finding_ids"),
    (LESSONS_RUN, "_gate_findings"), (LESSONS_RUN, "build_user_prompt"),
    (LESSONS_RUN, "invoke_agent"), (QUESTIONER_RUN, "questioner_existing_finding_ids"),
    (QUESTIONER_RUN, "_gate_questioner"), (QUESTIONER_RUN, "build_questioner_user_prompt"),
    (QUESTIONER_RUN, "invoke_agent"),
})
CURATOR_MODULES = frozenset({DRAIN, SHARED, LESSONS_RUN, QUESTIONER_RUN})


def test_only_the_named_listers_list_and_the_curator_lists_nothing():
    """A raw listing (`.entries(...)`, `list_tree(...)`) only at the named listers, none in a
    curator module; a curator module reaches a listing only through a shared reader, for its
    findings' ids or its prompt's manifest — never in drain.py, whose before-state is git's and
    whose sweep is `git status`'s (C1)."""
    assert tuple(sorted(C.CURATOR_MODULES)) == tuple(sorted(CURATOR_MODULES))
    raw = {(e.module, e.qualname) for e in ALLOW if e.kind == "listing"
           and (".entries(" in e.text or e.text.startswith("list_tree("))}
    assert raw == LISTERS
    assert not {m for m, _q in raw} & CURATOR_MODULES
    reached = {(e.module, e.qualname) for e in ALLOW if e.kind == "listing"} - raw
    assert reached == CURATOR_READS
    assert DRAIN not in {m for m, _q in reached}
    # `_corpus` lists only through `list_tree` (no raw `.entries()`), and B2's two helpers'
    # `view` slots are tree slots of the `Bound` kind, like a shared reader's.
    assert not [e for e in ALLOW if e.module == CORPUS and e.kind == "listing"
                and ".entries()" in e.text]
    assert C.READERS[C.ENTRY_KIND] == C.READERS[C.LIST_TREE] == (0, "view", "bound")
    assert C.READERS[C.VIEW_AT] == (0, "held", "held")


def test_judge_counts_anchors_and_reports_stale_entries():
    """The mechanics the per-module rows rest on, on a synthetic table: an anchor seen more
    often than allowed is unexpected; an entry seen less often is stale; a known gap is neither,
    a module's hits never answer for another module's entries, and only `kinds` take part."""
    def hit(text: str, kind: str = "call") -> C.Hit:
        return C.Hit("m.py", "f", kind, text, 1)
    allow = (Allowed("m.py", "f", "call", "twice()", D3, "x", count=2),
             Allowed("m.py", "f", "call", "gone()", D3, "x"),
             Allowed("other.py", "f", "call", "once()", D3, "x"),
             Allowed("m.py", "f", "construct", "made()", D3, "x"))
    gaps = (Gap("m.py", "f", "call", "gap()", "fix"),)
    hits = [hit("twice()"), hit("twice()"), hit("twice()"), hit("gap()"), hit("once()"),
            hit("made()", "construct"), hit("built()", "construct")]
    unexpected, stale = judge("m.py", hits, allow, gaps)
    assert [h.text for h in unexpected] == ["twice()", "once()", "built()"]
    assert stale == ["f call: gone() (allowed x1, found x0)"]
    unexpected, stale = judge("m.py", hits, allow, gaps, kinds=frozenset({"construct"}))
    assert [h.text for h in unexpected] == ["built()"]
    assert stale == []


#: The functions whose `D3` entries are a fallback behind a `tree_for` miss. An anchor cannot
#: see the branch in front of it: deleting the `tree_for` branch and keeping the plain one (v1's
#: s5 H2, in its simplest form) leaves every anchor as it was. So each of these must still ask
#: `tree_for` — a structural pin, not a proof of the branch.
TREE_FOR_FALLBACKS = frozenset({
    (DRAIN, "_put_back"), (LANE_TREES, "kind_at"), (LANE_TREES, "read_at"),
    (RULES, "_template_in_tree"), (RULES, "_skills_content_rule"),
    (RULES, "_answered_after_batch"), (RULES, "_catalog_drafts"),
    # `_answered_after_batch`' and `_catalog_drafts`' plain path is `_catalog_in_tree`'s: its
    # branch lives here.
    (RULES, "_catalog_in_tree"),
})


def _asks_tree_for(module: str, source: str, qualname: str) -> bool:
    """Does the def `qualname` (its last definition: overload stubs come first) name
    `tree_for`?"""
    scan = C.ModuleScan(TREE, module, ast.parse(source))
    fn = [n for n in ast.walk(scan.ast)
          if isinstance(n, ast.FunctionDef) and scan.qualname(n.body[0]) == qualname][-1]
    return any(isinstance(n, ast.Name) and n.id == "tree_for" and isinstance(n.ctx, ast.Load)
               for n in ast.walk(fn))


def test_a_d3_fallback_still_asks_tree_for_first():
    d3 = {(e.module, e.qualname) for e in ALLOW if e.reason == D3 and e.kind != "construct"}
    assert d3 - TREE_FOR_FALLBACKS == {(DRAIN, "_spawn_repair")}, (
        "a new D3 entry: is it a fallback behind a `tree_for` miss (add it to "
        "TREE_FOR_FALLBACKS), or a checked-in file outside the mounts?")
    silent = [f for f in sorted(TREE_FOR_FALLBACKS) if not _asks_tree_for(f[0], _source(f[0]), f[1])]
    assert not silent, f"D3 fallbacks that no longer ask `tree_for`: {silent}"
    dropped = _apply(DRAIN, _source(DRAIN), ((_PUT_BACK_TAIL, "    target.unlink()\n", 1),))
    assert not judge(DRAIN, C.census_source(WORKTREE, DRAIN, dropped, tree=TREE))[0], (
        "the anchors alone cannot see a dropped handle branch")
    assert not _asks_tree_for(DRAIN, dropped, "_put_back")


def _is_a_miss(scan: C.ModuleScan, name: str, fn: ast.FunctionDef) -> bool:
    """`name` is a `tree_for` miss in `fn`: bound only ever as `name = <provable tree_for>(...)`,
    or only as element 0 of an unpack of a helper whose element 0 is an optional `Bound` (`view,
    where = _catalog_in_tree(...)`, rule 7's summary: `None` exactly on the miss)."""
    if scan._tree_for_result(name, fn):
        return True
    bs = scan.bindings(fn).get(name, [])
    return bool(bs) and name not in C._params(fn) and all(
        b.how == "unpack" and b.index == 0 and isinstance(b.value, ast.Call)
        and scan.returned(b.value, "bound", 0) == "optional" for b in bs)


def _behind_the_miss(scan: C.ModuleScan, node: ast.AST, fn: ast.FunctionDef) -> bool:
    """`node` runs only on a `tree_for` miss: it sits in the body of an `if <miss> is None:` (or
    the `else` of an `is not None` test), in the true arm of a `... if <miss> is None else ...`,
    or after an earlier sibling `if <miss> is not None:` with no `else` whose body ends in `return`
    or `raise` — in its own block or an enclosing one, up to `fn`'s body."""
    def covers(test: ast.expr, want: str) -> bool:
        return any(C.none_test(test, n) == want and _is_a_miss(scan, n, fn)
                   for n in {x.id for x in ast.walk(test) if isinstance(x, ast.Name)})
    cur: ast.AST = node
    while cur is not fn:
        up = scan.parent[cur]
        if isinstance(up, ast.IfExp) and (
                (cur is up.body and covers(up.test, "is")) or (cur is up.orelse and covers(up.test, "is not"))):
            return True
        if isinstance(cur, ast.stmt):
            block, at = C._block_holding(up, cur)
            if isinstance(up, ast.If) and ((block is up.body and covers(up.test, "is"))
                                           or (block is up.orelse and covers(up.test, "is not"))):
                return True
            if any(isinstance(e, ast.If) and not e.orelse and isinstance(e.body[-1], (ast.Return, ast.Raise))
                   and covers(e.test, "is not") for e in block[:at]):
                return True
        cur = up
    return False


def _d3_fallback_touches(module: str, source: str) -> tuple[list[str], int]:
    """`(off, judged)`: each node of `module` that a `D3` fallback entry (a function in
    `TREE_FOR_FALLBACKS`) anchors and that does not sit behind its function's `tree_for` miss,
    and how many such nodes were judged."""
    scan = C.ModuleScan(TREE, module, ast.parse(source))
    wanted = {(e.qualname, e.text) for e in ALLOW if e.module == module and e.reason == D3
              and (e.module, e.qualname) in TREE_FOR_FALLBACKS}
    off, judged = [], 0
    for node in ast.walk(scan.ast):
        if not isinstance(node, (ast.Call, ast.Attribute, ast.Name)):
            continue
        if (scan.qualname(node), ast.unparse(node)) not in wanted:
            continue
        judged += 1
        fn = scan.innermost_def(node)
        if fn is None or not _behind_the_miss(scan, node, fn):
            off.append(f"{module}:{node.lineno} [{scan.qualname(node)}] {ast.unparse(node)}")
    return off, judged


def test_each_d3_fallback_touch_sits_behind_its_tree_for_miss():
    """An anchor cannot see the branch in front of it, so each `D3` fallback's plain touch is
    also pinned to run only on its `tree_for` miss (s7v3 E: v3's `read_bytes_at` keeping
    `tree_for` but reading every path by `full.read_bytes()`; addendum 3 drops that function, so
    the row re-applies the same shape to `read_at`). Every such entry's node is found and
    judged."""
    seen = 0
    for module in sorted({m for m, _q in TREE_FOR_FALLBACKS}):
        off, judged = _d3_fallback_touches(module, _source(module))
        assert not off, off
        seen += judged
    assert seen == sum(e.count for e in ALLOW if e.reason == D3 and e.kind != "construct"
                       and (e.module, e.qualname) in TREE_FOR_FALLBACKS)


#: Fallbacks moved off their miss, each on this base's text: the anchors stay as they were.
OFF_THE_MISS = {
    # s7v3 E: the handle branch skipped; every path read by its plain spelling. Its site,
    # `read_bytes_at`, is gone (#1134 addendum 3, D1): the same shape on `read_at`, the one
    # read fallback left.
    "s7v3-E-read-at-skips-its-handle-branch": (LANE_TREES, (
        ("    if hit is None:\n        return read_text_soft(full)\n",
         "    if hit is not None:\n        pass\n    if True:\n        return read_text_soft(full)\n",
         1),)),
    # The leaving guard that does not leave: `kind_at`'s plain stats after a non-returning branch.
    "kind-at-handle-branch-falls-through": (LANE_TREES, (
        ("        return KIND_ABSENT if got.absent else str(got.kind)\n    if full.is_file():\n",
         "        _ = KIND_ABSENT if got.absent else str(got.kind)\n    if full.is_file():\n", 1),)),
    # The conditional's arms swapped: the Path form on the hit.
    "skills-content-rule-arms-swapped": (RULES, (
        ("check_system_skill(repo_root / path, system) if hit is None\n",
         "check_system_skill(repo_root / path, system) if hit is not None\n", 1),
        ("            else _scaffold_rules.check_system_skill(hit[0].view(), system, hit[1]),\n",
         "            else _scaffold_rules.check_system_skill(hit[0].view(), system, hit[1]) if hit else None,\n", 1))),
    # A miss that is not one: the guard tests a local the census cannot tie to `tree_for`.
    "put-back-guarded-by-a-stand-in": (DRAIN, (
        ("    hit = tree_for(target)\n    if hit is None:\n",
         "    hit = tree_for(target)\n    gone = None\n    if gone is None:\n", 1),)),
}


@pytest.mark.parametrize("name", sorted(OFF_THE_MISS))
def test_a_fallback_moved_off_its_miss_is_caught(name: str):
    module, edits = OFF_THE_MISS[name]
    patched = _apply(module, _source(module), edits)
    assert not judge(module, C.census_source(WORKTREE, module, patched, tree=TREE))[0], (
        "the anchors alone do not see it: this row is what does")
    assert _d3_fallback_touches(module, patched)[0], name


# =============================================================================================
# The vocabulary and the handle rule's pins
# =============================================================================================

#: The `_io` words the dispatch and the v2/v3 step logs pin into the vocabulary; the lead-author
#: step found the existing lints missed `guarded_mkdir` and `write_atomic`.
IO_MUST = frozenset({
    "write_guarded", "read_guarded", "read_bytes_guarded", "read_plain", "read_plain_bytes",
    "locked_for_rewrite", "guarded_mkdir", "open_guarded", "write_atomic", "append_jsonl",
    "read_text_utf8", "read_text_soft", "read_jsonl_rows", "read_jsonl_rows_report",
    "entry_present", "is_plain_entry", "is_hard_linked", "load_json_artifact", "open_nofollow_fd",
    "open_unnamed", "open_unnamed_at", "sweep_staged", "bind", "hold", "hold_new", "Held", "Bound",
    "rooted_read", "rooted_write", "rooted_mkdir", "rooted_locked_for_rewrite",
})
#: Value judges in the vocabulary by the pin above: a pure body may call these and nothing else.
IO_VALUE_JUDGES = frozenset({"load_json_artifact", "is_hard_linked", "is_plain_entry"})


def _io_public_names() -> set[str]:
    _, io_tree = _astlib.read_and_parse(WORKTREE / "defender" / "_io.py", "defender/_io.py")
    return {n.name for n in io_tree.body
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and not n.name.startswith("_")}


def test_the_pure_set_names_io_exports_and_the_vocabulary_holds_the_pins():
    assert set(C.IO_PURE) <= _io_public_names(), sorted(C.IO_PURE - _io_public_names())
    assert TREE.io_vocab >= IO_MUST, sorted(IO_MUST - TREE.io_vocab)
    assert TREE.io_vocab == _io_public_names() - C.IO_PURE
    for word in ("os.path.lexists", "os.unlink", "shutil.rmtree", "builtins.open", "io.open"):
        assert TREE.in_vocabulary(word), word
    # The `_io` constructors are vocabulary words, judged as `construct` before `call`.
    makers = {f"defender._io.{n}" for n in ("hold", "bind", "hold_new", "Held", "Bound")}
    assert makers <= C.CONSTRUCTORS
    assert all(TREE.is_word(m) for m in makers)


def test_the_vocabulary_is_every_public_io_callable_but_the_pure_set():
    """The AST enumeration agrees with the imported module (this worktree's), so no export is
    bound in a way the enumeration cannot see."""
    import defender._io as io_module
    assert Path(io_module.__file__).resolve().is_relative_to(WORKTREE), (
        f"defender._io imported from {io_module.__file__}, not this worktree: run with "
        f"PYTHONPATH={WORKTREE}")
    public = {n for n, v in vars(io_module).items()
              if not n.startswith("_") and callable(v)
              and getattr(v, "__module__", None) == io_module.__name__}
    assert public - C.IO_PURE == TREE.io_vocab


def test_a_new_io_export_is_a_census_word_the_day_it_lands():
    source = _source("_io.py") + "\n\ndef brand_new_reader(path):\n    return path\n"
    assert "brand_new_reader" in C.io_vocabulary(ast.parse(source))


def test_the_pure_set_bodies_make_no_filesystem_call():
    """Each `IO_PURE` def's census hits (read off `_io.py` itself) are only calls to the pinned
    value judges and references to `_io`'s own underscore names (every one a census word) whose
    bodies — a def's or class's, or a constant's value — are pure by the same test, all the way
    down (`json_safe` -> `_json_safe_walk` -> `_json_key`; `RecordRead` -> `_Read`)."""
    tree = ast.parse(_source("_io.py"))
    hits = C.census_source(WORKTREE, "_io.py", _source("_io.py"), tree=TREE)
    spans = {}
    for n in tree.body:
        targets = ([n.name] if isinstance(n, (ast.FunctionDef, ast.ClassDef)) else
                   [t.id for t in getattr(n, "targets", [getattr(n, "target", None)])
                    if isinstance(t, ast.Name)])
        spans.update((name, (n.lineno, n.end_lineno)) for name in targets)

    def hits_of(name: str) -> list[C.Hit]:
        lo, hi = spans[name]
        return [h for h in hits if lo <= h.line <= hi]

    def bad_in(name: str, seen: frozenset[str]) -> list[str]:
        out = []
        for h in hits_of(name):
            word = h.text.split("(")[0].rpartition(".")[2]
            if h.kind == "call" and word in IO_VALUE_JUDGES:
                continue
            if h.kind in ("call", "load") and word.startswith("_") and word in spans:
                out += [] if word in seen else bad_in(word, seen | {word})
                continue
            out.append(f"{name}: {h.show()}")
        return out

    bad = [b for name in sorted(C.IO_PURE | IO_VALUE_JUDGES) for b in bad_in(name, frozenset({name}))]
    assert not bad, "\n".join(bad)


def test_every_io_underscore_name_is_a_census_word():
    """`_io`'s private defs, classes and constants (`_create_named`, `_open_plain_fd`,
    `_ensure_dir_component`, `_refuse_unless_plain`, `_leaf_is_link`, `_Handle`, `_NOT_PLAIN`)
    are all census words — a call, an uncalled reference, an import or a `getattr` of one is a hit
    — so none is judged body by body, and a new one is a word the day it lands."""
    _, io_tree = _astlib.read_and_parse(WORKTREE / "defender" / "_io.py", "defender/_io.py")
    names = C.io_private_names(io_tree)
    assert {"_create_named", "_open_plain_fd", "_ensure_dir_component", "_refuse_unless_plain",
            "_leaf_is_link", "_Handle", "_NOT_PLAIN"} <= names
    assert names == TREE.io_private
    for name in names:
        assert TREE.in_vocabulary(f"defender._io.{name}"), name
        assert TREE.is_word(f"defender._io.{name}"), name
        assert name in TREE.getattr_words(), name
    source = _source("_io.py") + "\n\ndef _brand_new_helper(path):\n    return path\n"
    assert "_brand_new_helper" in C.io_private_names(ast.parse(source))


def _touching_defs(module: str) -> set[str]:
    """The public top-level functions of `module` whose bodies have a census hit, directly or
    through the module's own private functions they call."""
    scan = C.ModuleScan(TREE, module, ast.parse(_source(module)))
    hit_in = {h.qualname.split(".")[0] for h in scan.scan()}
    defs = {n.name: n for n in scan.ast.body if isinstance(n, ast.FunctionDef)}

    def touches(name: str, seen: frozenset[str]) -> bool:
        if name in hit_in:
            return True
        calls = {c.func.id for c in ast.walk(defs[name])
                 if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                 and c.func.id in defs and c.func.id.startswith("_")}
        return any(touches(c, seen | {name}) for c in calls - seen)

    return {n for n in defs if not n.startswith("_") and touches(n, frozenset())}


def test_the_run_paths_vocabulary_is_its_disk_touching_functions():
    """`_run_paths`' public functions join the vocabulary the way `_io`'s do (enumerated from
    the scanned tree's source, minus a pinned pure set), and the split is exactly the functions
    whose bodies touch disk (v1 step 7's adversary, h2: `artifact_file(path)` lstats a draft's
    plain path)."""
    assert TREE.run_paths_vocab >= {"artifact_file", "artifact_dir", "plain_file"}
    assert TREE.run_paths_vocab == _touching_defs("_run_paths.py"), (
        "a public `_run_paths` function that touches disk is missing from the vocabulary, or a "
        "pure one is in it: fix `RUN_PATHS_PURE`")
    assert TREE.in_vocabulary("defender._run_paths.artifact_file")
    assert not TREE.in_vocabulary("defender._run_paths.resolve_run_bundle")


def test_the_private_vocabulary_is_each_handle_class_own_state():
    """`private` is enumerated from the scanned classes' `self._x` assignments, so a new piece
    of handle state is a census word the day it lands; each name keeps its owners."""
    assert TREE.private_attrs["_where"] == {C.HELD}
    assert TREE.private_attrs["_root"] == {C.HELD}
    assert TREE.private_attrs["_os"] == {C.HELD, C.BOUND}
    assert TREE.private_attrs["_handle"] == TREE.private_attrs["_prefix"] == {C.BOUND}
    assert TREE.private_attrs["_held"] == TREE.private_attrs["_stack"] == {C.DRAIN_TREES}
    io_tree = ast.parse(_source("_io.py"))
    lt_tree = ast.parse(_source(LANE_TREES))
    every = {a for src, name in ((io_tree, "Held"), (io_tree, "Bound"), (lt_tree, "DrainTrees"))
             for a in C.self_private_attrs(C._class_def(src, name))}
    assert set(TREE.private_attrs) == every
    assert set(TREE.private_attrs) <= TREE.getattr_words()


def test_a_handle_verb_is_exempt_only_on_its_own_class():
    """The Path-verb names among each handle class's public methods, read off the scanned
    `_io.py`: a new one changes what a provable receiver may call without an `attr` hit."""
    assert TREE.verbs["held"] & C.ATTRS == {"mkdir", "unlink"}
    # No `Bound.read_bytes` (#1134 addendum 3, D1: the curator's comparisons ask git), so a
    # view has no Path-verb method at all and `.read_bytes()` on one is a Path-verb hit; no
    # `Bound.kind` / `Bound.walk` (addendum 2, B1): nor is `.walk()`.
    assert TREE.verbs["bound"] & C.ATTRS == frozenset()
    assert not {"kind", "walk", "read_bytes"} & TREE.verbs["bound"]


def _class_field(module: str, cls: str, field: str) -> ast.AnnAssign:
    tree = ast.parse(_source(module))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == cls:
            for stmt in node.body:
                if (isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
                        and stmt.target.id == field):
                    return stmt
    raise AssertionError(f"{module}: no {cls}.{field}")


def _class_field_annotation(module: str, cls: str, field: str) -> ast.expr:
    return _class_field(module, cls, field).annotation


@pytest.mark.parametrize(("module", "cls", "field", "kind"), [
    (CONFIG, "CorpusAuthorConfig", "corpus", "held"),
    (CONFIG, "CorpusAuthorConfig", "tree_for", "tree_for"),
    (LEAD_AUTHOR, "LeadAuthorDeps", "skills", "held"),
    (LEAD_AUTHOR, "LeadAuthorDeps", "tree_for", "tree_for"),
])
def test_a_pinned_attribute_is_typed_exactly(module: str, cls: str, field: str, kind: str):
    """`cfg.corpus` / `self.cfg.corpus` / `deps.skills` are provable `Held`s, and `cfg.tree_for`
    / `self.cfg.tree_for` / `deps.tree_for` provable `TreeFor`s, because these fields are typed
    exactly so and have no default (a `= cast(Held, PATH)` there would be a handle no caller
    built)."""
    stmt = _class_field(module, cls, field)
    scan = C.ModuleScan(TREE, module, ast.parse(_source(module)))
    assert scan.is_annotated(stmt.annotation, kind), ast.unparse(stmt.annotation)
    assert stmt.value is None, f"{cls}.{field} has a default: {ast.unparse(stmt.value)}"
    assert any(a.endswith(f".{field}") for a in C.PINNED_ATTRS[kind])


def test_judgement_cfg_is_the_curator_config():
    ann = _class_field_annotation(DRAIN, "_Judgement", "cfg")
    assert ast.unparse(ann) == "CorpusAuthorConfig"


def _def(origin: str) -> tuple[C.ModuleScan, ast.FunctionDef]:
    dotted, _, name = origin.rpartition(".")
    module = TREE.module_file(dotted).relative_to(WORKTREE / "defender").as_posix()
    scan = C.ModuleScan(TREE, module, ast.parse(_source(module)))
    fn = [n for n in scan.ast.body if isinstance(n, ast.FunctionDef) and n.name == name][-1]
    return scan, fn


@pytest.mark.parametrize("origin", sorted(C.HANDLE_SOURCES))
def test_a_handle_source_takes_the_trees_and_returns_a_held(origin: str):
    scan, fn = _def(origin)
    assert scan.is_annotated(fn.returns, "held"), ast.unparse(fn.returns)
    first = [*fn.args.posonlyargs, *fn.args.args][0]
    assert first.arg == "trees"
    assert scan.is_annotated(first.annotation, "trees")


@pytest.mark.parametrize("origin", sorted(C.READERS))
def test_a_reader_tree_slot_is_its_signature(origin: str):
    """`READERS` names each handle-taking function's tree argument by slot, keyword and kind; a
    signature change that moved it would make the census judge the wrong argument. `where` is the
    spelling keyword, never the tree."""
    scan, fn = _def(origin)
    index, keyword, kind = C.READERS[origin]
    if index < 0:
        param = next(a for a in fn.args.kwonlyargs if a.arg == keyword)
    else:
        param = [*fn.args.posonlyargs, *fn.args.args][index]
        assert param.arg == keyword
    assert keyword != "where"
    # The signature derivation agrees wherever the slot admits a path (every reader but
    # `build_curator_user_prompt`, `entry_kind`, `list_tree` and `view_at`, whose slot is exactly
    # the handle class).
    if not scan.is_annotated(param.annotation, kind):
        assert (index, keyword, kind) in scan.tree_params(fn), ast.unparse(param.annotation)


@pytest.mark.parametrize("name", ["_lessons", "_templates", "_spelled", "_viewed"])
def test_corpus_private_readers_are_tree_slots_too(name: str):
    """`_corpus`'s private readers take the same `Tree` its public ones do: the census derives
    their slot from the signature (s7v2 03 handed `_templates` the catalog's spelling)."""
    scan = C.ModuleScan(TREE, CORPUS, ast.parse(_source(CORPUS)))
    fn = next(n for n in scan.ast.body if isinstance(n, ast.FunctionDef) and n.name == name)
    first = [*fn.args.posonlyargs, *fn.args.args][0].arg
    assert scan.tree_slots(f"defender._corpus.{name}") >= {(0, first, "bound")}


@pytest.mark.parametrize("origin", sorted(C.TREE_FOR_TAKERS))
def test_a_tree_for_taker_slot_is_its_signature_and_derived_too(origin: str):
    scan, fn = _def(origin)
    index, keyword = C.TREE_FOR_TAKERS[origin]
    param = [*fn.args.posonlyargs, *fn.args.args][index]
    assert param.arg == keyword
    assert scan.is_annotated(param.annotation, "tree_for")
    assert (index, keyword) in scan.tree_for_slots(origin)


def _tree_for_bindings(module: str, source: str | None = None) -> list[str]:
    """Every binding of the name `tree_for` in `module` that is not a `TreeFor`-typed parameter
    or dataclass field, nor `DrainTrees.tree_for`'s own method def: a def, class, import alias,
    assignment, loop / with / except / match target, global, or an untyped (lambda)
    parameter."""
    scan = C.ModuleScan(TREE, module, ast.parse(_source(module) if source is None else source))
    wrong, fields = [], set()
    for node in ast.walk(scan.ast):
        if isinstance(node, ast.arg) and node.arg == "tree_for":
            if node.annotation is None or not scan.is_annotated(node.annotation, "tree_for"):
                wrong.append(f"{module}:{node.lineno} parameter typed "
                             f"{ast.unparse(node.annotation) if node.annotation else None}")
        elif (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                and node.target.id == "tree_for" and node.value is None
                and scan.is_annotated(node.annotation, "tree_for")):
            fields.add(node.target)
        elif isinstance(node, ast.Name) and node.id == "tree_for" and not isinstance(
                node.ctx, ast.Load) and node not in fields:
            wrong.append(f"{module}:{node.lineno} bound by {type(scan.parent[node]).__name__}")
        elif (not isinstance(node, (ast.arg, ast.Name)) and "tree_for" in C.bound_names(node)
                and not _is_drain_trees_own_tree_for(module, scan, node)):
            wrong.append(f"{module}:{node.lineno} bound by {type(node).__name__}")
    return wrong


def _is_drain_trees_own_tree_for(module: str, scan: C.ModuleScan, node: ast.AST) -> bool:
    """`DrainTrees.tree_for`'s own method def in `lane_trees.py` — and nothing else."""
    return (module == LANE_TREES and isinstance(node, ast.FunctionDef)
            and scan.qualname(node.body[0]) == "DrainTrees.tree_for")


def test_every_tree_for_binding_is_a_typed_tree_for():
    """`tree_for` is half a spelling pin in the handle rule (a `tree_for=` keyword is judged on
    every call): in scan A the name is bound only as a `TreeFor`-typed parameter or dataclass
    field, and as `DrainTrees.tree_for`'s own method — never a def, class, import alias or local
    (v1 step 7's adversary, h3; s6v2 E1's `tree_for = _outside_every_mount`)."""
    wrong = [w for module in C.D6_MODULES for w in _tree_for_bindings(module)]
    assert not wrong, wrong


def test_the_tree_for_binding_pin_sees_a_rebound_or_a_module_level_tree_for():
    """The pin is red on s6v2 E1's two `tree_for = _outside_every_mount` locals and on v1 h3's
    module-level `def tree_for`, re-applied to this base (the fixtures below)."""
    def bindings(name: str) -> list[str]:
        reg = REGRESSIONS[name]
        patched = _apply(reg.module, _source(reg.module), reg.edits)
        return [w.split(" ", 1)[1] for w in _tree_for_bindings(reg.module, patched)]
    assert bindings("s6v2-E1-rules-discard-tree-for") == ["bound by Assign", "bound by Assign"]
    assert bindings("s7-h3-module-level-tree-for") == ["bound by FunctionDef"]


# =============================================================================================
# `where=` is spelling: no hit at base, and an opening use is a hit (E4, below)
# =============================================================================================

#: The functions the step log names as taking or passing a spelling-only `where`.
WHERE_SPELLERS = (
    (SYNTH, "synthesize_drafts"), (HANDOFF, "discover_system_drafts"), (HANDOFF, "build_handoff"),
    (HANDOFF, "_draft_contradicts_skill"), (RULES, "_minted_identities"),
    (RULES, "_catalog_in_tree"), (RULES, "_template_in_tree"), (NEIGHBORS, "load_lane_catalog"),
)


def _mentions_where(node: ast.AST) -> bool:
    return any((isinstance(n, ast.Name) and n.id == "where")
               or (isinstance(n, ast.keyword) and n.arg == "where") for n in ast.walk(node))


@pytest.mark.parametrize(("module", "name"), WHERE_SPELLERS)
def test_a_spelling_where_is_no_hit(module: str, name: str):
    """Each function still spells with `where` (a parameter, a local, or a `where=` passed on —
    so the control is not vacuous), and no census hit in it mentions `where`."""
    _scan, fn = _def(f"{C.module_dotted(module)}.{name}")
    assert _mentions_where(fn), f"{name} no longer spells with `where`"
    hits = [h for h in C.census(WORKTREE, [module], tree=TREE)
            if h.qualname == name or h.qualname.startswith(f"{name}.")]
    assert not [h for h in hits if _mentions_where(ast.parse(h.text))], hits


# =============================================================================================
# D5: the write lint's and the read lint's waivers in scan A
# =============================================================================================

_WRITE_MARK = "lint-unguarded-tree-write: ok"
_READ_MARK = "lint-tree-read-follows-link: ok"

#: The scan-A keys of `lint_unguarded_tree_write_baseline.json` #1134's D5 commit keeps: each
#: still fires there with the waiver deleted (re-measured at 87f013fe), and each gets its reason.
#: (Stale at 87f013fe and deleted by that commit: `lessons/run.py:write_held_report`,
#: `draft_synthesis.py:synthesize_drafts`.)
D5_BASELINE_KEPT = frozenset({
    "learning/author/lessons/run.py:invoke_agent",          # N-e: `cfg.pending_dir.mkdir`
    "learning/author/shared.py:assert_clean_corpus_dir",    # `corpus.mkdir(".")`, a `Held`: name match
    "learning/leads/_lead_spine.py:_spawn_author_agent",    # N-e: `PENDING_DIR.mkdir`
    "learning/leads/lead_author/__init__.py:_write_state",  # N-e: run-dir state
})

#: The inline `# lint-unguarded-tree-write: ok` waivers in scan A: all still fire, all N-e.
D5_INLINE_WAIVERS = frozenset({
    (DRAIN, "_bump_rows"), (DRAIN, "_append_gap_record"), (DRAIN, "_retire_unkeyable"),
    (DRAIN, "_record_stuck"), (SHARED, "invoke_repair"), (SHARED, "write_disposition_report"),
    (QUESTIONER_RUN, "invoke_agent"), (PITFALLS, "_graveyard_dropped_rows"),
})


def _baseline(name: str) -> dict[str, str]:
    return json.loads((WORKTREE / "scripts" / "lint" / name).read_text(encoding="utf-8"))["entries"]


def _waived_lines(module: str, mark: str) -> list[int]:
    return [i for i, line in enumerate(_source(module).splitlines(), 1) if mark in line]


def test_d5_the_write_lint_baseline_keeps_only_live_scan_a_waivers_each_with_its_reason():
    """Red until #1134's D5 commit: at 87f013fe the baseline still holds the two stale scan-A
    keys, and all six have an empty reason."""
    entries = _baseline("lint_unguarded_tree_write_baseline.json")
    in_scan_a = {k: v for k, v in entries.items() if k.split(":")[0] in C.D6_MODULES}
    problems = {
        "missing": sorted(D5_BASELINE_KEPT - set(in_scan_a)),
        "stale": sorted(set(in_scan_a) - D5_BASELINE_KEPT),
        "empty reason": sorted(k for k, v in in_scan_a.items() if not v.strip()),
    }
    assert problems == {"missing": [], "stale": [], "empty reason": []}


def test_d5_each_inline_write_waiver_sits_on_an_n_e_census_hit():
    """The waivers kept in scan A are exactly the eight queue-sidecar and `_pending` lines, and
    each waived line is inside a census hit the table allow-lists as `N-e` — no waiver covers a
    touch of a mount."""
    allow = {e.anchor: e.reason for e in ALLOW}
    waived, bad = set(), []
    for module in C.D6_MODULES:
        lines = _waived_lines(module, _WRITE_MARK)
        if not lines:
            continue
        hits = C.census(WORKTREE, [module], tree=TREE)
        for line in lines:
            on = [h for h in hits if h.line <= line <= max(h.end_line, h.line)]
            waived |= {(module, h.qualname) for h in on}
            if not on or any(allow.get(h.anchor) != N_E for h in on):
                bad.append(f"{module}:{line} {[(h.qualname, h.text[:40]) for h in on]}")
    assert not bad, bad
    assert waived == D5_INLINE_WAIVERS


def test_d5_no_read_lint_waiver_or_baseline_entry_in_scan_a():
    entries = _baseline("lint_tree_read_follows_link_baseline.json")
    assert not [k for k in entries if k.split(":")[0] in C.D6_MODULES]
    assert not [m for m in C.D6_MODULES if _waived_lines(m, _READ_MARK)]


# =============================================================================================
# The census discriminates: the adversaries' regressions, re-applied to this base
# =============================================================================================

class Regression(NamedTuple):
    """`edits` (old, new, occurrences) applied to the real module at this base; each `expect`
    anchor `(qualname, kind, text, count)` must then be `count` unexpected hits beyond what the
    clean module has (which is what the table allows), and each `stale` anchor
    `(qualname, kind, text)` a stale entry."""

    module: str
    edits: tuple[tuple[str, str, int], ...]
    expect: tuple[tuple[str, str, str, int], ...]
    stale: tuple[tuple[str, str, str], ...] = ()


_PUT_BACK_HANDLE = "    held, name = hit\n    if kind in (ENTRY_FILE, ENTRY_OTHER):\n        held.unlink(name)\n"
#: `_put_back` from its `kind_at` to its end: the D3 branch, then the handle branch.
_PUT_BACK_TAIL = (
    "    kind = kind_at(repo_root, tree_for, rel)\n    hit = tree_for(target)\n    if hit is None:\n"
    "        if kind == ENTRY_FILE:\n            target.unlink()\n        return\n" + _PUT_BACK_HANDLE)
_RESTORE_WRITE = "        if name not in unchanged:\n            cfg.corpus.write(name, pre, mode=\"replace\")\n"
_SNAPSHOT_TAIL = "        cfg.corpus.write(name, pre, mode=\"replace\")\n\n\ndef _append_terminal_block("
_IO_IMPORT_TAIL = "    read_jsonl_rows_report,\n)\n"
_RUN_LOCKED_CATALOG = "lead_neighbors.load_lane_catalog(deps.skills.view(), where=skills_dir)"
#: `_snapshot_corpus`'s return: the before-state, git's blobs at `head` (C1).
_BEFORE_STATE = (
    "    return {path[len(prefix):]: blob\n"
    "            for path, blob in _git.git_tree_blobs(repo_root, head, rel).items()}\n")
#: `_restore_corpus`'s two loops: the sweep of `git status`'s names, then the rewrite.
_SWEEP = ("    for rel in made:\n        name = (repo_root / rel).relative_to(corpus_dir).as_posix()\n")
#: `_restore_corpus`'s rewrite of each before-state file git does not find unchanged.
_REWRITE = "        if name not in unchanged:\n            _left_for_scrub("
_PROMPT_ARGS = "corpus=cfg.corpus.view(), corpus_dir=cfg.corpus_dir,"

REGRESSIONS: dict[str, Regression] = {
    # v1 s5 H1 (01-hardlink-plain-unlink): a plain file found by the handle, unlinked by the held
    # mount's spelling.
    "s5-H1-hardlink-plain-unlink": Regression(DRAIN, (
        (_PUT_BACK_HANDLE,
         "    held, name = hit\n    if kind == ENTRY_FILE:\n"
         "        (held._where / name).unlink()\n    elif kind == ENTRY_OTHER:\n"
         "        held.unlink(name)\n", 1),
        ("            cfg.corpus.unlink(name)\n            continue\n",
         "            if entry_kind(view, name).kind == ENTRY_FILE:\n"
         "                (cfg.corpus._where / name).unlink()\n            else:\n"
         "                cfg.corpus.unlink(name)\n            continue\n", 1),
    ), (("_put_back", "attr", "(held._where / name).unlink()", 1),
        ("_put_back", "private", "held._where", 1),
        ("_restore_unapproved_files", "attr", "(cfg.corpus._where / name).unlink()", 1),
        ("_restore_unapproved_files", "private", "cfg.corpus._where", 1))),
    # v1 s5 H2 (08-put-back-ignores-tree-for): `_put_back` judges every name by its plain path.
    "s5-H2-put-back-ignores-tree-for": Regression(DRAIN, (
        ("import os\nfrom dataclasses import replace\n",
         "import os\nimport stat\nfrom dataclasses import replace\n", 1),
        (_PUT_BACK_TAIL,
         "    try:\n        st = os.lstat(target)\n    except FileNotFoundError:\n        return\n"
         "    if stat.S_ISDIR(st.st_mode):\n        return\n"
         "    if stat.S_ISLNK(st.st_mode) or st.st_nlink > 1:\n"
         "        raise OSError(errno.ELOOP, 'refusing an aliased entry', str(target))\n"
         "    target.unlink()\n", 1),
    ), (("_put_back", "call", "os.lstat(target)", 1),)),
    # v1 s5 H3 (02-settle-restores-plain-write) and s5v2 R14: the settle's restores check the
    # mount, then write the corpus folder's spelling by the plain path.
    "s5-H3-settle-restores-plain-write": Regression(DRAIN, (
        (_IO_IMPORT_TAIL, "    read_jsonl_rows_report,\n    write_guarded,\n)\n", 1),
        (_RESTORE_WRITE,
         "        if name not in unchanged:\n            target = cfg.corpus_dir / name\n"
         "            target.parent.mkdir(parents=True, exist_ok=True)\n"
         "            write_guarded(target, pre)\n", 1),
        (_SNAPSHOT_TAIL,
         "        target = cfg.corpus_dir / name\n"
         "        target.parent.mkdir(parents=True, exist_ok=True)\n"
         "        write_guarded(target, pre)\n\n\ndef _append_terminal_block(", 1),
    ), (("_restore_unapproved_files", "attr", "target.parent.mkdir(parents=True, exist_ok=True)", 1),
        ("_restore_unapproved_files", "call", "write_guarded(target, pre)", 1),
        ("_restore_from_snapshot", "attr", "target.parent.mkdir(parents=True, exist_ok=True)", 1),
        ("_restore_from_snapshot", "call", "write_guarded(target, pre)", 1))),
    # v1 s5 H3b (02b-settle-restores-legacy-guarded-write): the same through the legacy seams.
    "s5-H3b-settle-restores-legacy-guarded-write": Regression(DRAIN, (
        (_IO_IMPORT_TAIL, "    read_jsonl_rows_report,\n    guarded_mkdir,\n    write_guarded,\n)\n", 1),
        (_RESTORE_WRITE,
         "        if name not in unchanged:\n            target = cfg.corpus_dir / name\n"
         "            guarded_mkdir(target.parent, base=cfg.corpus_dir)\n"
         "            write_guarded(target, pre)\n", 1),
        (_SNAPSHOT_TAIL,
         "        entry_kind(cfg.corpus.view(), name)  # placed inside the corpus mount\n"
         "        target = cfg.corpus_dir / name\n"
         "        guarded_mkdir(target.parent, base=cfg.corpus_dir)\n"
         "        write_guarded(target, pre)\n\n\ndef _append_terminal_block(", 1),
    ), (("_restore_unapproved_files", "call", "guarded_mkdir(target.parent, base=cfg.corpus_dir)", 1),
        ("_restore_unapproved_files", "call", "write_guarded(target, pre)", 1),
        ("_restore_from_snapshot", "call", "guarded_mkdir(target.parent, base=cfg.corpus_dir)", 1),
        ("_restore_from_snapshot", "call", "write_guarded(target, pre)", 1))),
    # v1 s5 H4 (05-snapshot-plain-read), retargeted: v3 takes the before-state from git (C1),
    # so the snapshot's own walk is gone; s5v3 K02 is its v3 shape — git names the names, and
    # their bytes are read from the worktree by plain path (following a planted link).
    "s5-H4-s5v3-K02-before-state-bytes-from-the-worktree": Regression(DRAIN, (
        (_BEFORE_STATE,
         "    return {path[len(prefix):]: (repo_root / path).read_bytes()\n"
         "            for path in _git.git_tree_blobs(repo_root, head, rel)\n"
         "            if os.lstat(repo_root / path).st_nlink == 1}\n", 1),
    ), (("_snapshot_corpus", "attr", "(repo_root / path).read_bytes()", 1),
        ("_snapshot_corpus", "call", "os.lstat(repo_root / path)", 1))),
    # v1 s5 H5 (07-handle-rebuilt-from-path) and s5v2 R15: the corpus handle rebuilt from
    # `cfg.corpus_dir`, the spelling.
    "s5-H5-handle-rebuilt-from-path": Regression(DRAIN, (
        (_IO_IMPORT_TAIL, "    read_jsonl_rows_report,\n    hold,\n)\n", 1),
        ("return _read_or_empty(self.cfg.corpus.view(), ",
         "return _read_or_empty(hold(self.cfg.corpus_dir).view(), ", 1),
        ("if not (_cited_ids(cfg.corpus.view(), ", "if not (_cited_ids(hold(cfg.corpus_dir).view(), ", 1),
        ("snapshot, corpus=cfg.corpus,", "snapshot, corpus=hold(cfg.corpus_dir),", 1),
    ), (("_Judgement.read", "construct", "hold(self.cfg.corpus_dir)", 1),
        ("_assert_corpus_attributable", "construct", "hold(cfg.corpus_dir)", 1),
        ("_undo_agent_edits", "construct", "hold(cfg.corpus_dir)", 1))),
    # v1 s5 H9 (04-commit-split-plain-lexists) and s5v2 R11: the commit split asks the plain path.
    "s5-H9-commit-split-plain-lexists": Regression(SHARED, (
        ("import json\nimport random\n", "import json\nimport os\nimport random\n", 1),
        ("    present = [p for p in paths if kind_at(cfg.repo_root, cfg.tree_for, p) != KIND_ABSENT]\n",
         "    present = [p for p in paths if os.path.lexists(cfg.repo_root / p)]\n", 1),
    ), (("commit_corpus_paths", "call", "os.path.lexists(cfg.repo_root / p)", 1),)),
    # v1 s6 final.diff, `check_system_skill` kind-then-plain-read, re-spelled where v2 can hold
    # it (a `Bound` has no spelling): the content rule reads the held mount's spelling.
    "s6-check-system-skill-by-held-spelling": Regression(RULES, (
        ("else _scaffold_rules.check_system_skill(hit[0].view(), system, hit[1]),",
         "else _scaffold_rules.check_system_skill(hit[0]._where / hit[1], system),", 1),
    ), (("_skills_content_rule", "reader",
         "_scaffold_rules.check_system_skill(hit[0]._where / hit[1], system)", 1),
        ("_skills_content_rule", "private", "hit[0]._where", 1))),
    # v1 s6 final.diff, `read_at`: kind through the handle, then a plain read of its spelling.
    "s6-read-at-plain-read": Regression(LANE_TREES, (
        ("    rec = held.view().read(name)\n    if rec.text is not None:\n        return rec.text, None\n",
         "    if entry_kind(held.view(), name).kind == ENTRY_FILE:\n"
         "        return read_text_soft(held._where / name)\n"
         "    rec = held.view().read(name)\n", 1),
    ), (("read_at", "call", "read_text_soft(held._where / name)", 1),
        ("read_at", "private", "held._where", 1))),
    # s6v2 R1 (H1): the same, reading the working-copy path the D3 branch reads — one more hit
    # on an allow-listed anchor (the count, not the text, catches it).
    "s6v2-R1-read-at-kind-then-plain-read": Regression(LANE_TREES, (
        ("    rec = held.view().read(name)\n    if rec.text is not None:\n        return rec.text, None\n",
         "    if entry_kind(held.view(), name).kind == ENTRY_FILE:\n        return read_text_soft(full)\n"
         "    rec = held.view().read(name)\n", 1),
    ), (("read_at", "call", "read_text_soft(full)", 1),)),
    # v1 s6 final.diff, `synthesize_drafts` (and s6v2 R3): the catalog by the Path form and the
    # draft written by plain path under the held mount's spelling.
    "s6-synthesize-drafts-plain-writer": Regression(SYNTH, (
        ("from defender._io import ENTRY_DIR, ENTRY_FILE, Held\n",
         "from defender._io import ENTRY_DIR, ENTRY_FILE, Held, guarded_mkdir, write_atomic\n", 1),
        ("        catalog = lead_neighbors.load_lane_catalog(skills.view(), where=where)\n",
         "        catalog = lead_neighbors.load_catalog(where / CATALOG_FOLDER)\n", 1),
        ("            skills.write(\n                name,\n",
         "            guarded_mkdir(draft.parent, base=where)\n            write_atomic(\n"
         "                draft,\n", 1),
        ("                mode=\"replace\",\n            )\n", "            )\n", 1),
    ), (("synthesize_drafts", "reader", "lead_neighbors.load_catalog(where / CATALOG_FOLDER)", 1),
        ("synthesize_drafts", "call", "guarded_mkdir(draft.parent, base=where)", 1),
        ("synthesize_drafts", "call",
         "write_atomic(draft, _draft_skeleton(qid, f'{system}.{suffix}', lead.verb, "
         "_draft_params(lead), lead.goal_text, record, engine))", 1))),
    # v1 s6 final.diff, `build_lead_author_deps`: the skills handle built from `paths.skills_dir`.
    "s6-deps-handle-from-path": Regression(LEAD_AUTHOR, (
        ("from defender._io import Held\n", "from defender._io import Held, hold\n", 1),
        ("    skills = lane_skills(trees, paths)\n", "    skills = hold(paths.skills_dir)\n", 1),
    ), (("build_lead_author_deps", "construct", "hold(paths.skills_dir)", 1),)),
    # v1 s6 final.diff, `_run_locked`: both catalog loads by the Path form, at the held mount's
    # spelling (the same text twice).
    "s6-run-locked-catalog-path-form": Regression(LEAD_AUTHOR, (
        (_RUN_LOCKED_CATALOG, "lead_neighbors.load_catalog(deps.skills._where / 'gather/queries')", 2),
    ), (("_run_locked", "reader", "lead_neighbors.load_catalog(deps.skills._where / 'gather/queries')", 2),
        ("_run_locked", "private", "deps.skills._where", 2))),
    # v1 s6 final.diff, `_handoff` (and s6v2 R3): the catalog by the Path form; a draft judged
    # through the view, then read by its path.
    "s6-handoff-plain-reads": Regression(HANDOFF, (
        ("        catalog = lead_neighbors.load_lane_catalog(skills, where=where)\n",
         "        catalog = lead_neighbors.load_catalog(where / 'gather/queries')\n", 1),
        ("        text = skills.read(draft.relative_to(where).as_posix()).text\n",
         "        if entry_kind(skills, draft.relative_to(where).as_posix()).kind != 'file':\n"
         "            return False\n        text = draft.read_text(encoding='utf-8')\n", 1),
    ), (("build_handoff", "reader", "lead_neighbors.load_catalog(where / 'gather/queries')", 1),
        ("_draft_contradicts_skill", "attr", "draft.read_text(encoding='utf-8')", 1))),
    # v1 s6 final.diff (and s6v2 R4): existence by plain `lexists`, the skill check by Path form.
    "s6-rules-plain-lexists": Regression(RULES, (
        ("import functools\nimport posixpath\n", "import functools\nimport os\nimport posixpath\n", 1),
        ("kind_at(repo_root, tree_for, twin) != KIND_ABSENT", "os.path.lexists(repo_root / twin)", 1),
        ("kind_at(repo_root, tree_for, draft_path) != KIND_ABSENT", "os.path.lexists(draft_path)", 1),
        ("            _scaffold_rules.check_system_skill(repo_root / path, system) if hit is None\n"
         "            else _scaffold_rules.check_system_skill(hit[0].view(), system, hit[1]),\n",
         "            _scaffold_rules.check_system_skill(repo_root / path, Path(path).parent.name),\n", 1),
    ), (("_skills_content_rule", "call", "os.path.lexists(repo_root / twin)", 1),
        ("_departed_drafts", "call", "os.path.lexists(draft_path)", 1),
        ("_skills_content_rule", "reader",
         "_scaffold_rules.check_system_skill(repo_root / path, Path(path).parent.name)", 1)),
        (("_skills_content_rule", "reader",
          "_scaffold_rules.check_system_skill(repo_root / path, system)"),)),
    # v1 s6 final.diff, `render_query`: kind through the view, then a plain read.
    "s6-render-query-plain-read": Regression(RENDER, (
        ("    rec = source.read(name)\n    if rec.text is None:\n"
         "        raise OSError(f\"{rec.name}: {rec.reason or 'absent'}\")\n    text = rec.text\n",
         "    if entry_kind(source, name).kind != 'file':\n"
         "        raise OSError(f'cannot read {name}: not a plain file')\n"
         "    text = Path(name).read_text(encoding='utf-8')\n", 1),
    ), (("render_query", "attr", "Path(name).read_text(encoding='utf-8')", 1),)),
    # v1 s6 final.diff, `collect_general_failures`: `skills: Any = None` — the catalog read's
    # argument is no longer a (guarded) view.
    "s6-collect-failures-any-skills": Regression(EXTRACTION, (
        ("*, skills: Bound | None = None,", "*, skills: Any = None,", 1),
    ), (("collect_general_failures", "reader",
         "lead_neighbors.load_lane_catalog(skills, where=where)", 1),)),
    # v1 s6 final.diff `_rules._bound`, as s6v2 R9 spells it on v2: the rule opens its own trees
    # over a fresh `LoopPaths` for a root of its choosing, and reads through their `tree_for`.
    "s6v2-R9-rule-builds-own-tree-for": Regression(RULES, (
        ("def _frontmatter_id(repo_root: Path, path: str, *, tree_for: TreeFor) -> str | None:\n",
         "def _frontmatter_id(repo_root: Path, path: str, *, tree_for: TreeFor) -> str | None:\n"
         "    from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths\n"
         "    from defender.learning.core.lane_trees import open_drain_trees\n\n"
         "    tree_for = open_drain_trees(LoopPaths(repo_root=repo_root), "
         "LEAD_AUTHOR_DRAIN_LABEL).tree_for\n", 1),
    ), (("_frontmatter_id", "construct",
         "open_drain_trees(LoopPaths(repo_root=repo_root), LEAD_AUTHOR_DRAIN_LABEL)", 1),
        ("_frontmatter_id", "construct", "LoopPaths(repo_root=repo_root)", 1),
        ("_frontmatter_id", "tree_for", "kind_at(repo_root, tree_for, path)", 1),
        ("_frontmatter_id", "tree_for", "read_at(repo_root, tree_for, path)", 1))),
    # v1 step 7's adversary, h1 (path-is-file-callback-minted-identities): the minted drafts
    # filtered by an unbound, link-following `Path.is_file`.
    "s7-h1-path-is-file-callback": Regression(RULES, (
        ("    out: dict[Path, tuple[str, ...]] = {}\n    for path in created:\n",
         "    out: dict[Path, tuple[str, ...]] = {}\n    for path in filter(Path.is_file, created):\n", 1),
    ), (("_minted_identities", "load", "Path.is_file", 1),)),
    # v1 step 7's adversary, h2 (artifact-file-minted-identities): `_run_paths.artifact_file`
    # lstats a draft's plain path inside the skills mount.
    "s7-h2-artifact-file": Regression(RULES, (
        ("from defender import _scaffold_rules\n",
         "from defender import _scaffold_rules\nfrom defender._run_paths import artifact_file\n", 1),
        ("    out: dict[Path, tuple[str, ...]] = {}\n    for path in created:\n",
         "    out: dict[Path, tuple[str, ...]] = {}\n    for path in created:\n"
         "        if not artifact_file(path):\n            continue\n", 1),
    ), (("_minted_identities", "call", "artifact_file(path)", 1),)),
    # v1 step 7's adversary, h3 (module-level-def-tree-for-pin-gap): a module-level `tree_for`
    # that splits a Path into (folder, name), so `hit[0]` looked like a handle.
    "s7-h3-module-level-tree-for": Regression(HANDOFF, (
        ("from defender._tree_listing import list_tree\n",
         "from defender import _corpus\nfrom defender._tree_listing import list_tree\n", 1),
        ("def discover_system_drafts(",
         "def tree_for(path: Path | str):\n    p = Path(path)\n    return p.parent, p.name\n\n\n"
         "def _draft_template(draft: Path, where: Path):\n"
         "    hit = tree_for(draft)\n"
         "    return _corpus.read_query_template(hit[0].view(), hit[1], where=where)[0]\n\n\n"
         "def discover_system_drafts(", 1),
    ), (("_draft_template", "reader",
         "_corpus.read_query_template(hit[0].view(), hit[1], where=where)", 1),)),
    # --- the v2 curator step's adversary (scratchpad s5v2-adv-patches/*.delta.diff) -------------
    # 03: the idempotency read rebinds the corpus by its spelling.
    "s5v2-03-idempotency-read-rebinds-the-spelling": Regression(SHARED, (
        ("        cfg.corpus.view(), where=cfg.corpus_dir,\n"
         "        warn_label=lambda p: f\"finding-id pre-flight: {p.name}\",\n",
         "        cfg.corpus_dir, warn_label=lambda p: f\"finding-id pre-flight: {p.name}\",\n", 1),
    ), (("existing_finding_ids", "reader",
         "iter_lessons(cfg.corpus_dir, warn_label=lambda p: f'finding-id pre-flight: {p.name}')", 1),)),
    # 06, retargeted (v3's snapshot is git's, C1; addendum 3's comparison is git's, D1): the
    # fault-path rewrite compares the held mount's spelling, read by plain path, instead of
    # asking git.
    "s5v2-06-restore-reads-the-held-spelling": Regression(DRAIN, (
        (_REWRITE, "        if Path(corpus._where, name).read_bytes() != blob:\n"
         "            _left_for_scrub(", 1),
    ), (("_restore_corpus", "attr", "Path(corpus._where, name).read_bytes()", 1),
        ("_restore_corpus", "private", "corpus._where", 1))),
    # 07: each channel's prompt manifest rebinds the corpus by its spelling.
    "s5v2-07-lessons-manifest-rebinds-the-spelling": Regression(LESSONS_RUN, (
        ("from defender.learning.author import drain\n",
         "from defender._corpus import _viewed as _corpus_viewed\n"
         "from defender.learning.author import drain\n", 1),
        ("    return _shared.build_curator_user_prompt(\n        findings, batch_id, " + _PROMPT_ARGS,
         "    with _corpus_viewed(cfg.corpus_dir) as corpus:\n"
         "        return _shared.build_curator_user_prompt(\n"
         "        findings, batch_id, corpus=corpus, corpus_dir=cfg.corpus_dir,", 1),
    ), (("build_user_prompt", "construct", "_corpus_viewed(cfg.corpus_dir)", 1),
        ("build_user_prompt", "reader",
         "_shared.build_curator_user_prompt(findings, batch_id, corpus=corpus, "
         "corpus_dir=cfg.corpus_dir, corpus_dir_rel=cfg.corpus_dir_rel, label='findings', "
         "manifest_seed=cfg.manifest_seed, salt=salt)", 1))),
    "s5v2-07-questioner-manifest-rebinds-the-spelling": Regression(QUESTIONER_RUN, (
        ("from defender.learning.author import drain\n",
         "from defender._corpus import _viewed as _corpus_viewed\n"
         "from defender.learning.author import drain\n", 1),
        ("    return _shared.build_curator_user_prompt(\n        findings, batch_id, " + _PROMPT_ARGS,
         "    with _corpus_viewed(cfg.corpus_dir) as corpus:\n"
         "        return _shared.build_curator_user_prompt(\n"
         "        findings, batch_id, corpus=corpus, corpus_dir=cfg.corpus_dir,", 1),
    ), (("build_questioner_user_prompt", "construct", "_corpus_viewed(cfg.corpus_dir)", 1),
        ("build_questioner_user_prompt", "reader",
         "_shared.build_curator_user_prompt(findings, batch_id, corpus=corpus, "
         "corpus_dir=cfg.corpus_dir, corpus_dir_rel=cfg.corpus_dir_rel, label='world findings', "
         "manifest_seed=cfg.manifest_seed, salt=salt)", 1))),
    # 09: the fault path stats the refused name's host path to describe the plant.
    "s5v2-09-describes-the-plant-by-its-host-path": Regression(DRAIN, (
        ("    except NotPlainEntry as e:\n        _logger.warning(f\"warn: {what} left for the scrub: {e.strerror}\")\n",
         "    except NotPlainEntry as e:\n        if _describe_plant(e.filename) is None:\n            raise\n"
         "        _logger.warning(f\"warn: {what} left for the scrub: {e.strerror}\")\n\n\n"
         "def _describe_plant(where: object) -> str | None:\n    import os\n    import stat\n\n"
         "    try:\n        st = os.lstat(str(where))\n    except OSError:\n        return None\n"
         "    return 'symlink' if stat.S_ISLNK(st.st_mode) else None\n", 1),
    ), (("_describe_plant", "call", "os.lstat(str(where))", 1),)),
    # 10, retargeted (v3's snapshot is git's, C1): the restore's scrub warnings spell the entry
    # by the held mount's spelling (a host path in a log line, then a path to go by).
    "s5v2-10-warnings-spell-the-held-spelling": Regression(DRAIN, (
        ("            _left_for_scrub(name, corpus.unlink, name)\n",
         "            _left_for_scrub(str(Path(corpus._where, name)), corpus.unlink, name)\n", 1),
        ("            _left_for_scrub(name, functools.partial(corpus.write, mode=\"replace\"), name, blob)\n",
         "            _left_for_scrub(f\"{corpus._where}/{name}\", functools.partial(corpus.write, "
         "mode=\"replace\"), name, blob)\n", 1),
    ), (("_restore_corpus", "private", "corpus._where", 2),)),
    # 05b: the eval harness opens the author trees over the live checkout (scan B).
    "s5v2-05b-harness-opens-the-live-checkout": Regression(HARNESS, (
        ("    from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LoopPaths\n",
         "    from defender.learning.core.config import AUTHOR_DRAIN_LABEL, DEFAULT_PATHS, LoopPaths\n", 1),
        ("    with open_drain_trees(paths, AUTHOR_DRAIN_LABEL) as trees:\n"
         "        cfg = author.build_author_config(paths, ",
         "    with open_drain_trees(DEFAULT_PATHS, AUTHOR_DRAIN_LABEL) as trees:\n"
         "        cfg = author.build_author_config(DEFAULT_PATHS, ", 1),
    ), (("run_author", "construct", "open_drain_trees(DEFAULT_PATHS, AUTHOR_DRAIN_LABEL)", 1),),
        (("run_author", "construct", "open_drain_trees(paths, AUTHOR_DRAIN_LABEL)"),)),
    # --- the v2 lead-author step's adversary (scratchpad s6v2-adv-patches/*.delta.diff) ---------
    # E1: the composites discard the `tree_for` they are handed.
    "s6v2-E1-rules-discard-tree-for": Regression(RULES, (
        ("def _membership_segment(path: str) -> str:\n",
         "def _outside_every_mount(_path):\n    return None\n\n\n"
         "def _membership_segment(path: str) -> str:\n", 1),
        ("    _skills_path_rule(repo_root, xy, path, systems=systems, tree_for=tree_for)\n",
         "    tree_for = _outside_every_mount\n"
         "    _skills_path_rule(repo_root, xy, path, systems=systems, tree_for=tree_for)\n", 1),
        ("    return _verify_corpus_scope(\n        repo_root, baseline_stray, actor=\"agent\",\n",
         "    tree_for = _outside_every_mount\n"
         "    return _verify_corpus_scope(\n        repo_root, baseline_stray, actor=\"agent\",\n", 1),
    ), (("_skills_rule", "tree_for",
         "_skills_path_rule(repo_root, xy, path, systems=systems, tree_for=tree_for)", 1),
        ("_skills_rule", "tree_for",
         "_skills_content_rule(repo_root, resolver, xy, path, tree_for=tree_for)", 1),
        ("_verify_skills_state", "tree_for",
         "functools.partial(_skills_rule, repo_root, resolver, systems=systems, tree_for=tree_for)", 1),
        ("_verify_skills_state", "tree_for",
         "functools.partial(_covers_rule, repo_root, minted, tree_for=tree_for)", 1))),
    "s6v2-E1-pitfalls-discard-tree-for": Regression(PITFALLS, (
        ("    _pitfalls_content_rule(repo_root, xy, path, tree_for=tree_for)\n",
         "    _pitfalls_content_rule(repo_root, xy, path, tree_for=lambda _p: None)\n", 1),
        ("            systems=systems, reducer_offered=reducer_offered, tree_for=tree_for,\n",
         "            systems=systems, reducer_offered=reducer_offered, tree_for=lambda _p: None,\n", 1),
    ), (("_pitfalls_rule", "tree_for",
         "_pitfalls_content_rule(repo_root, xy, path, tree_for=lambda _p: None)", 1),
        ("_verify_pitfalls_state", "tree_for",
         "partial(_pitfalls_rule, repo_root, systems=systems, reducer_offered=reducer_offered, "
         "tree_for=lambda _p: None)", 1))),
    # E2a / E2b: the commit gates read every path by its plain spelling.
    "s6v2-E2a-run-locked-plain-tree-for": Regression(LEAD_AUTHOR, (
        ("minted=minted, tree_for=deps.tree_for,", "minted=minted, tree_for=lambda _path: None,", 1),
    ), (("_run_locked", "tree_for",
         "_verify_skills_state(repo_root, baseline_stray, systems=deps.systems, minted=minted, "
         "tree_for=lambda _path: None)", 1),)),
    "s6v2-E2b-run-pitfalls-plain-tree-for": Regression(PITFALLS, (
        ("        tree_for=trees.tree_for,\n    )\n    sha = None\n",
         "        tree_for=lambda _path: None,\n    )\n    sha = None\n", 1),
    ), (("run_pitfalls", "tree_for",
         "_verify_pitfalls_state(repo_root, baseline_stray, systems=systems, "
         "reducer_offered=reducer_offered, tree_for=lambda _path: None)", 1),)),
    # E4: `where` stat'ed (following) and trusted over the view.
    "s6v2-E4-where-statted-discover": Regression(HANDOFF, (
        ("    listed = list_tree(skills, depth=3)\n",
         "    if not where.is_dir():\n        return []\n    listed = list_tree(skills, depth=3)\n", 1),
    ), (("discover_system_drafts", "attr", "where.is_dir()", 1),)),
    "s6v2-E4-where-statted-catalog": Regression(NEIGHBORS, (
        ("    return load_catalog(skills.under(CATALOG_FOLDER), ",
         "    if not (where / CATALOG_FOLDER).is_dir():\n        return []\n"
         "    return load_catalog(skills.under(CATALOG_FOLDER), ", 1),
    ), (("load_lane_catalog", "attr", "(where / CATALOG_FOLDER).is_dir()", 1),)),
    # E5: the lift bypass reads a pending draft by its plain path (a function-local import).
    "s6v2-E5-contradicts-by-path": Regression(LEAD_AUTHOR, (
        ("def _prepare_handoffs(\n",
         "def _contradicts_by_path(draft: Path) -> bool:\n"
         "    from defender._frontmatter import parse_frontmatter_or_none\n"
         "    from defender._io import read_text_soft\n\n"
         "    text, _reason = read_text_soft(draft)\n"
         "    fm = parse_frontmatter_or_none(text) if text is not None else None\n"
         "    return fm is not None and fm.get('contradicts_skill') is True\n\n\n"
         "def _prepare_handoffs(\n", 1),
        ("        if _draft_contradicts_skill(deps.skills.view(), d, where=deps.paths.skills_dir)\n",
         "        if _contradicts_by_path(d)\n", 1),
    ), (("_contradicts_by_path", "call", "read_text_soft(draft)", 1),)),
    # E6: the run's reads re-resolve the mount by name — a second handle built from a Path.
    "s6v2-E6-run-locked-rebinds-skills-dir": Regression(LEAD_AUTHOR, (
        ("from defender._io import Held\n", "from defender._io import Held\nfrom defender._io import bind as _bind\n", 1),
        ("    skills_dir = deps.paths.skills_dir\n    catalog = " + _RUN_LOCKED_CATALOG + "\n",
         "    skills_dir = deps.paths.skills_dir\n    with _bind(skills_dir) as fresh:\n"
         "        catalog = lead_neighbors.load_lane_catalog(fresh, where=skills_dir)\n", 1),
        ("    minted = _minted_identities(deps.skills.view(), synth, where=skills_dir)\n",
         "    with _bind(skills_dir) as fresh:\n"
         "        minted = _minted_identities(fresh, synth, where=skills_dir)\n", 1),
        ("    if synth:\n        catalog = " + _RUN_LOCKED_CATALOG + "\n",
         "    if synth:\n        with _bind(skills_dir) as fresh:\n"
         "            catalog = lead_neighbors.load_lane_catalog(fresh, where=skills_dir)\n", 1),
    ), (("_run_locked", "construct", "_bind(skills_dir)", 3),
        ("_run_locked", "reader", "lead_neighbors.load_lane_catalog(fresh, where=skills_dir)", 2))),
    # E7: each lane seam compares its label to one constant and opens its trees for that
    # constant, not the label it was bound (scan B: a new opener anchor, the old one stale).
    "s6v2-E7-seams-open-a-constant-label": Regression(DRAINS, (
        ("    with open_drain_trees(paths, label) as trees:\n        rc = _run_curator_module(\n"
         "            \"lead_author\",",
         "    with open_drain_trees(paths, LEAD_AUTHOR_DRAIN_LABEL) as trees:\n"
         "        rc = _run_curator_module(\n            \"lead_author\",", 1),
        ("    with open_drain_trees(paths, label) as trees:\n        rc = _run_curator_module(\n"
         "            \"pitfalls_curator\",",
         "    with open_drain_trees(paths, LEAD_AUTHOR_DRAIN_LABEL) as trees:\n"
         "        rc = _run_curator_module(\n            \"pitfalls_curator\",", 1),
    ), (("_invoke_lead_author", "construct", "open_drain_trees(paths, LEAD_AUTHOR_DRAIN_LABEL)", 1),
        ("_invoke_pitfalls", "construct", "open_drain_trees(paths, LEAD_AUTHOR_DRAIN_LABEL)", 1)),
        (("_invoke_lead_author", "construct", "open_drain_trees(paths, label)"),
         ("_invoke_pitfalls", "construct", "open_drain_trees(paths, label)"))),
    # E9: the handle only judges; the draft is written by path at the held mount's spelling.
    "s6v2-E9-writer-writes-by-the-held-spelling": Regression(SYNTH, (
        ("from defender._io import ENTRY_DIR, ENTRY_FILE, Held\n",
         "from defender._io import ENTRY_DIR, ENTRY_FILE, Held, guarded_mkdir, write_atomic\n", 1),
        ("            skills.write(\n                name,\n",
         "            root = skills._where\n            guarded_mkdir((root / name).parent, base=root)\n"
         "            write_atomic(\n                root / name,\n", 1),
        ("                mode=\"replace\",\n            )\n", "            )\n", 1),
    ), (("synthesize_drafts", "call", "guarded_mkdir((root / name).parent, base=root)", 1),
        ("synthesize_drafts", "call",
         "write_atomic(root / name, _draft_skeleton(qid, f'{system}.{suffix}', lead.verb, "
         "_draft_params(lead), lead.goal_text, record, engine))", 1),
        ("synthesize_drafts", "private", "skills._where", 1))),
    # --- v2 step 7's adversary, third pass (scratchpad s7v2-adv-patches/) ------------------------
    # 02 / 02b: the `TreeFor` slot handed through a `**` mapping, so the keyword is never spelled.
    "s7v2-02-put-back-tree-for-by-double-star": Regression(DRAIN, (
        ("_put_back(cfg.repo_root, rel, tree_for=cfg.tree_for)",
         "_put_back(cfg.repo_root, rel, **{\"tree_for\": lambda _p: None})", 1),
    ), (("_revert_non_md_strays", "tree_for",
         "_put_back(cfg.repo_root, rel, **{'tree_for': lambda _p: None})", 1),)),
    # 02b's site is gone: addendum 3 (D1) takes `tree_for` off the settle's comparison (git
    # compares), so no `TreeFor` slot is left there to evade (NOT_CENSUS_SHAPED). Its plain-read
    # shape is the addendum-3 rows below.
    # 03: `_corpus`'s private reader handed the catalog's spelling.
    "s7v2-03-private-corpus-reader-templates": Regression(RULES, (
        ("    return answered_identities(lead_neighbors.load_catalog(view, where=where))\n",
         "    return answered_identities(list(_corpus._templates(where, where)))\n", 1),
    ), (("_answered_after_batch", "reader", "_corpus._templates(where, where)", 1),)),
    # 04: `_io`'s private exclusive create, imported in the function, by the host path.
    "s7v2-04-io-private-create-named": Regression(DRAIN, (
        ("    name the snapshot does not hold is skipped.\"\"\"\n",
         "    name the snapshot does not hold is skipped.\"\"\"\n"
         "    from defender._io import _create_named\n\n", 1),
        (_SNAPSHOT_TAIL,
         "        try:\n            _create_named(cfg.repo_root / rel, pre)\n"
         "        except OSError:\n            pass\n" + _SNAPSHOT_TAIL, 1),
    ), (("_restore_from_snapshot", "load", "from defender._io import _create_named", 1),
        ("_restore_from_snapshot", "call", "_create_named(cfg.repo_root / rel, pre)", 1))),
    # --- the v3 curator step's adversary (scratchpad s5v3-adv-patches/), on this base's text ----
    # A3 / D1090: the fault sweep's names from a plain disk walk, not from `git status`.
    "s5v3-A3-sweep-by-a-plain-disk-walk": Regression(DRAIN, (
        ("def _restore_corpus(\n",
         "def _on_disk(repo_root: Path, corpus_dir: Path) -> list[str]:\n"
         "    found: list[str] = []\n"
         "    for dirpath, _dirs, files in os.walk(corpus_dir):\n        for leaf in files:\n"
         "            at = Path(dirpath) / leaf\n            if os.lstat(at).st_nlink:\n"
         "                found.append(at.relative_to(repo_root).as_posix())\n"
         "    return found\n\n\ndef _restore_corpus(\n", 1),
        (_SWEEP, "    made = _on_disk(repo_root, corpus_dir) if made else []\n" + _SWEEP, 1),
    ), (("_on_disk", "call", "os.walk(corpus_dir)", 1), ("_on_disk", "call", "os.lstat(at)", 1))),
    # A7: `_git.py` revives "absent" paths it finds on disk, by an `os` lookup through `getattr`.
    "s5v3-A7-git-py-probes-the-disk-through-getattr": Regression(GIT, (
        ("    if present:\n        git([\"add\", \"--\", *present], cwd=cwd)\n",
         "    revived = [p for p in absent if _on_disk(cwd, p)]\n"
         "    present = [*present, *revived]\n"
         "    if present:\n        git([\"add\", \"--\", *present], cwd=cwd)\n", 1),
        ("def git_fetch(cwd: Path) -> None:\n",
         "_PROBE = \"lstat\"\n\n\ndef _on_disk(cwd: Path, path: str) -> bool:\n    try:\n"
         "        getattr(os, _PROBE)(f\"{cwd}/{path}\")\n    except OSError:\n"
         "        return False\n    return True\n\n\ndef git_fetch(cwd: Path) -> None:\n", 1),
    ), (("_on_disk", "getattr", "getattr(os, _PROBE)", 1),)),
    # A8: the settle's folder test asks the corpus folder's spelling, following a link.
    "s5v3-A8-settle-folder-test-by-a-plain-isdir": Regression(DRAIN, (
        ("            if entry_kind(view, name).kind == ENTRY_DIR:\n",
         "            if (entry_kind(view, name).kind == ENTRY_DIR\n"
         "                    or os.path.isdir(cfg.corpus_dir / name)):\n", 1),
    ), (("_restore_unapproved_files", "call", "os.path.isdir(cfg.corpus_dir / name)", 1),)),
    # K07: the sweep's names from a link-following glob of the corpus folder's spelling.
    "s5v3-K07-sweep-by-rglob-is-file": Regression(DRAIN, (
        (_SWEEP,
         "    made = [p.relative_to(repo_root).as_posix() for p in sorted(corpus_dir.rglob('*'))\n"
         "            if p.is_file()] if made else []\n" + _SWEEP, 1),
    ), (("_restore_corpus", "attr", "corpus_dir.rglob('*')", 1),
        ("_restore_corpus", "attr", "p.is_file()", 1))),
    # K08: the sweep's names from a listing of the held corpus — through the handle, so no O1
    # touch, but the curator lists no folder (C1): a `listing` hit.
    "s5v3-K08-sweep-by-list-tree": Regression(DRAIN, (
        ("from defender._tree_listing import entry_kind\n",
         "from defender._tree_listing import entry_kind, list_tree\n", 1),
        (_SWEEP,
         "    listed = list_tree(corpus.view(), depth=8).entries or {}\n"
         "    made = [n for n, k in listed.items() if k != ENTRY_DIR] if made else []\n" + _SWEEP, 1),
    ), (("_restore_corpus", "listing", "list_tree(corpus.view(), depth=8)", 1),)),
    # K11: the rewrite skips a gone name when the corpus folder's spelling is no folder.
    "s5v3-K11-rewrite-asks-the-corpus-spelling": Regression(DRAIN, (
        (_REWRITE,
         "        if not os.path.isdir(corpus_dir):\n            continue\n" + _REWRITE, 1),
    ), (("_restore_corpus", "call", "os.path.isdir(corpus_dir)", 1),)),
    # K13: the fallback's empty index written by a second git child (one more `subprocess` call
    # on the allow-listed function: the count catches it).
    "s5v3-K13-fallback-writes-an-index": Regression(GIT, (
        ("    proc = subprocess.run([\"git\", *args], cwd=cwd, capture_output=True, check=False,\n"
         "                          env={**os.environ, \"GIT_INDEX_FILE\": absent_index})\n",
         "    subprocess.run([\"git\", \"read-tree\", \"--empty\"], cwd=cwd, check=False,\n"
         "                   capture_output=True, env={**os.environ, \"GIT_INDEX_FILE\": absent_index})\n"
         "    proc = subprocess.run([\"git\", *args], cwd=cwd, capture_output=True, check=False,\n"
         "                          env={**os.environ, \"GIT_INDEX_FILE\": absent_index})\n", 1),
    ), (("git_worktree_files", "call",
         "subprocess.run(['git', 'read-tree', '--empty'], cwd=cwd, check=False, capture_output=True, "
         "env={**os.environ, 'GIT_INDEX_FILE': absent_index})", 1),)),
    # --- this step's adversary (scratchpad s7v3-adv-patches/) ------------------------------------
    # A / B: the sweep's names from a raw listing the no-argument rule missed.
    "s7v3-A-sweep-by-entries-splat": Regression(DRAIN, (
        (_SWEEP, "    made = [(corpus_dir / leaf).relative_to(repo_root).as_posix()\n"
         "            for leaf in (view.entries(*()).entries or {})]\n" + _SWEEP, 1),
    ), (("_restore_corpus", "listing", "view.entries(*())", 1),)),
    "s7v3-B-sweep-by-unbound-entries": Regression(DRAIN, (
        (_SWEEP, "    made = [(corpus_dir / leaf).relative_to(repo_root).as_posix()\n"
         "            for leaf in (type(view).entries(view).entries or {})]\n" + _SWEEP, 1),
    ), (("_restore_corpus", "listing", "type(view).entries(view)", 1),)),
    # C: the sweep's names from a shared reader's listing of the held corpus.
    "s7v3-C-sweep-via-a-shared-reader": Regression(DRAIN, (
        (_SWEEP, "    from defender._corpus import iter_lesson_paths\n"
         "    made = [q.relative_to(repo_root).as_posix() for q in iter_lesson_paths(view, where=corpus_dir)]\n"
         + _SWEEP, 1),
    ), (("_restore_corpus", "listing", "iter_lesson_paths(view, where=corpus_dir)", 1),)),
    # C, through a curator helper that lists (the prompt's manifest), one module over.
    "s7v3-C-sweep-via-the-curator-manifest": Regression(DRAIN, (
        (_SWEEP, "    made = list(author_shared.build_corpus_manifest(view, where=corpus_dir))\n" + _SWEEP, 1),
    ), (("_restore_corpus", "listing", "author_shared.build_corpus_manifest(view, where=corpus_dir)", 1),)),
    # --- the v3 lead-author step's adversary (scratchpad s6v3-adv-patches/), on this base's text --
    # E5 (V3-H7): `discover_system_drafts` lists the catalog by hand beside `list_tree`.
    "s6v3-E5-discover-lists-by-hand": Regression(HANDOFF, (
        ("def discover_system_drafts(\n",
         "def _own_listing(skills: Bound) -> TreeListing:\n    top = skills.entries()\n"
         "    found = dict(top.entries or {})\n"
         "    for folder in [n for n, k in found.items() if k == ENTRY_DIR]:\n"
         "        got = skills.under(folder).entries()\n"
         "        found.update((f'{folder}/{e}', k) for e, k in (got.entries or {}).items())\n"
         "    return TreeListing(absent=top.absent, reason=top.reason, entries=found, refused={}, gone=())\n"
         "\n\ndef discover_system_drafts(\n", 1),
        ("    listed = list_tree(skills, depth=3)\n", "    listed = _own_listing(skills)\n", 1),
    ), (("_own_listing", "listing", "skills.entries()", 1),
        ("_own_listing", "listing", "skills.under(folder).entries()", 1)),
        (("discover_system_drafts", "listing", "list_tree(skills, depth=3)"),)),
    # E6 (V3-H7): `kind_at` lists the name's folder by hand instead of asking `entry_kind`.
    "s6v3-E6-kind-at-lists-by-hand": Regression(LANE_TREES, (
        ("        got = entry_kind(held.view(), name)\n        if got.reason is not None:\n",
         "        folder, _sep, leaf = name.rpartition(\"/\")\n"
         "        listing = (held.view().under(folder) if folder else held.view()).entries()\n"
         "        got = entry_kind(held.view(), name)\n        if got.reason is not None:\n", 1),
    ), (("kind_at", "listing", "(held.view().under(folder) if folder else held.view()).entries()", 1),)),
    # E2 (V3-H4): a refused folder listed again, and the second answer taken.
    "s6v3-E2-discover-relists-a-refused-folder": Regression(HANDOFF, (
        ("    listed = list_tree(skills, depth=3)\n",
         "    listed = list_tree(skills, depth=3)\n    for folder in list(listed.refused):\n"
         "        list_tree(skills.under(folder), depth=3 - len(folder.split('/')))\n", 1),
    ), (("discover_system_drafts", "listing",
         "list_tree(skills.under(folder), depth=3 - len(folder.split('/')))", 1),)),
    # E3 (V3-H6): `kind_at` on the mount point answers "dir" without its own listing — a
    # behaviour fault the census sees only as its one sanctioned listing gone stale.
    "s6v3-E3-mount-point-hardcoded-dir": Regression(LANE_TREES, (
        ("            top = held.view().entries()\n            if top.reason is not None:\n"
         "                return ENTRY_OTHER\n            return KIND_ABSENT if top.absent else ENTRY_DIR\n",
         "            return ENTRY_DIR\n", 1),
    ), (), (("kind_at", "listing", "held.view().entries()"),)),
    # E9: the handle writes the draft, and a stale plain write lands beside it (the #1139 merge).
    "s6v3-E9-stale-plain-write-beside-the-handle": Regression(SYNTH, (
        ("from defender._io import ENTRY_DIR, ENTRY_FILE, Held\n",
         "from defender._io import ENTRY_DIR, ENTRY_FILE, Held, guarded_mkdir, write_atomic\n", 1),
        ("                mode=\"replace\",\n            )\n            created.append(draft)\n",
         "                mode=\"replace\",\n            )\n"
         "            guarded_mkdir(draft.parent, base=where)\n            write_atomic(draft, b'')\n"
         "            created.append(draft)\n", 1),
    ), (("synthesize_drafts", "call", "guarded_mkdir(draft.parent, base=where)", 1),
        ("synthesize_drafts", "call", "write_atomic(draft, b'')", 1))),
    # --- the v3 step 4 adversary (scratchpad adv1134v3s4/), on this base's `_corpus.py` ---------
    # v1: a catalog folder listed again by hand, its warning taken from the second listing.
    "s4v3-v1-catalog-folder-relisted": Regression(CORPUS, (
        ("            elif name in listed.refused:\n",
         "            elif (again := view.under(name).entries()).reason is not None:\n", 1),
    ), (("_template_names", "listing", "view.under(name).entries()", 1),)),
    # v8: a refused or gone catalog folder re-bound by its Path spelling and read from there.
    "s4v3-v8-refused-folder-rebound-by-path": Regression(CORPUS, (
        ("            elif name in listed.refused:\n",
         "            elif name in listed.gone:\n"
         "                with bind(where / name) as again:\n                    again.entries()\n"
         "            elif name in listed.refused:\n", 1),
    ), (("_template_names", "construct", "bind(where / name)", 1),
        ("_template_names", "listing", "again.entries()", 1))),
    # v10: the Path form lists eagerly under a second `bind` of its own.
    "s4v3-v10-path-form-binds-twice": Regression(CORPUS, (
        ("    return _templates(catalog, _spelled(catalog, where))\n",
         "    if not isinstance(catalog, Bound):\n        with bind(Path(catalog)) as listed:\n"
         "            _template_names(listed, _spelled(catalog, where))\n"
         "    return _templates(catalog, _spelled(catalog, where))\n", 1),
    ), (("iter_query_templates", "construct", "bind(Path(catalog))", 1),)),
    # v12: the Path form lists the catalog again, below its fixed shape.
    "s4v3-v12-path-form-lists-below-the-shape": Regression(CORPUS, (
        ("    with _viewed(catalog) as view:\n        for name in _template_names(view, spelled):\n",
         "    with _viewed(catalog) as view:\n"
         "        for name in (list_tree(view, depth=3).entries or {}):\n"
         "            view.under(name).entries()\n"
         "        for name in _template_names(view, spelled):\n", 1),
    ), (("_templates", "listing", "list_tree(view, depth=3)", 1),
        ("_templates", "reader", "list_tree(view, depth=3)", 1),
        ("_templates", "listing", "view.under(name).entries()", 1))),
    # --- #1134 addendum 3 (D1): a "still the before-state?" check that reads the worktree by
    # --- its plain path instead of asking git (each a plain read the census flags) ------------
    "a3-settle-compares-a-plain-read": Regression(DRAIN, (
        ("    return rel in _git.git_unchanged_since(repo_root, \"HEAD\", rel)\n",
         "    head = _git.git_show_file(repo_root, \"HEAD\", rel)\n"
         "    return head is not None and (repo_root / rel).read_bytes() == head.encode()\n", 1),
    ), (("_byte_identical_to_head", "attr", "(repo_root / rel).read_bytes()", 1),)),
    "a3-settle-restore-compares-by-open": Regression(DRAIN, (
        (_RESTORE_WRITE,
         "        with open(cfg.corpus_dir / name, 'rb') as fh:\n            same = fh.read() == pre\n"
         "        if not same:\n            cfg.corpus.write(name, pre, mode=\"replace\")\n", 1),
    ), (("_restore_unapproved_files", "call", "open(cfg.corpus_dir / name, 'rb')", 1),)),
    "a3-unchanged-names-filtered-by-a-text-read": Regression(DRAIN, (
        ("                     for path in _git.git_unchanged_since(repo_root, rev, rel))\n",
         "                     for path in _git.git_unchanged_since(repo_root, rev, rel)\n"
         "                     if (repo_root / path).read_text(encoding='utf-8'))\n", 1),
    ), (("_unchanged_names", "attr", "(repo_root / path).read_text(encoding='utf-8')", 1),)),
}


def _apply(module: str, source: str, edits: tuple[tuple[str, str, int], ...]) -> str:
    """`source` with each fixture edit applied. An edit's `old` text must occur exactly as
    often as the fixture says; when it does not, the module's source was refactored — that is
    not a regression, and not the census failing: the fixture must be re-spelled."""
    for old, new, times in edits:
        found = source.count(old)
        assert found == times, (
            f"FIXTURE OUT OF DATE, not a regression: {module} no longer holds this fixture's "
            f"source text x{times} (found x{found}), so its source line changed. Re-spell the "
            f"fixture's edit against the module's new text, keeping the regression it "
            f"re-applies.\nText looked for:\n{old}")
        source = source.replace(old, new)
    return source


@pytest.mark.parametrize("name", sorted(REGRESSIONS))
def test_an_adversary_regression_is_an_unexpected_hit(name: str):
    """Each real regression from the adversaries (v1: s5-adv-patches/, s6-adv-patches/final.diff,
    s7-adv-patches/; v2: s5v2-adv-patches/, s6v2-adv-patches/, s7v2-adv-patches/; v3:
    adv1134v3s4/, s6v3-adv-patches/, s5v3-adv-patches/ — each re-spelled onto this base's text)
    is caught as the specific (function, kind, text) it adds —
    not as "the census is non-empty"."""
    reg = REGRESSIONS[name]
    kinds = kinds_of(reg.module)
    clean = _source(reg.module)
    allowed = {e.anchor: e.count for e in ALLOW if e.module == reg.module}
    before = Counter(h.anchor for h in C.census_source(
        WORKTREE, reg.module, clean, tree=TREE, kinds=kinds))
    hits = C.census_source(WORKTREE, reg.module, _apply(reg.module, clean, reg.edits), tree=TREE,
                           kinds=kinds)
    unexpected_hits, stale = judge(reg.module, hits, kinds=kinds)
    unexpected = Counter(h.anchor for h in unexpected_hits)
    for qualname, kind, text, count in reg.expect:
        anchor = (reg.module, qualname, kind, text)
        assert before[anchor] == allowed.get(anchor, 0), f"not clean before the regression: {anchor}"
        assert unexpected[anchor] == count, (
            f"{name}: {qualname} {kind} `{text}` not flagged x{count} "
            f"(got x{unexpected[anchor]}); unexpected: {sorted(unexpected)}")
    for qualname, kind, text in reg.stale:
        assert any(s.startswith(f"{qualname} {kind}: {text} (") for s in stale), (name, stale)


#: The adversaries' patches that are not census-shaped — they touch no mount by plain path and
#: build no handle — with the test that owns each (checked to exist below).
NOT_CENSUS_SHAPED: dict[str, tuple[str, str]] = {
    "s5v2-01 O5.3 catch takes NotADirectoryError": (
        "test_1134_curator_drain.py::test_a_non_folder_at_a_holding_folders_name_replaces_the_fault",
        "widens an `except`; no touch"),
    "s5v2-02 byte identity reads text": (
        "test_1134_curator_handle.py::test_a_crlf_only_rewrite_of_a_tracked_lesson_is_not_byte_identical",
        "a text read through the held mount (`read_at`) for git's comparison: no plain touch"),
    "s7v2-02b byte identity tree_for by double star": (
        "test_1134_curator_handle.py::test_the_settle_judges_a_link_at_a_modified_lesson_as_git_sees_it",
        "site gone in addendum 3 (D1): the settle's comparison takes no `TreeFor`, git compares; "
        "a plain read there is a3-settle-compares-a-plain-read"),
    "s5v2-04 snapshot opens every non-folder entry": (
        "test_1134_curator_handle.py::test_the_before_state_reads_no_worktree_entry",
        "site gone in v3: the before-state is git's blobs (C1), and no worktree entry is opened"),
    "s5v2-05 harness opens trees it cannot hold": (
        "test_1134_curator_label.py::test_the_eval_harness_runs_an_empty_queue_scenario_in_its_scratch_repo",
        "drops the scratch repo's mkdir; the opener's anchor is unchanged"),
    "s5v2-08 _git.py revives absent paths": (
        "test_1134_curator_handle.py::test_git_py_makes_no_filesystem_call_and_imports_no_handle",
        "in `_git.py`, outside both scans (N-a)"),
    "s6v2-E3 CLI label local alias": (
        "test_1134_lead_author_holes.py::test_the_cli_runs_under_the_lead_label",
        "a label rebound in `main`; `run`'s opener anchor is unchanged"),
    "s6v2-E8 deps cached past the with": (
        "test_1134_lead_author_adversary.py::test_two_claims_over_one_paths_each_mint_through_their_own_trees",
        "a lifetime fault: the cached handles are the lane's own"),
    "s6v2-E10 stale vulture suppressions kept": (
        "test_1134_lead_author_adversary.py::test_the_lane_trees_entry_points_carry_no_vulture_suppression",
        "a `# noqa` comment"),
    # --- v3 step 4 (adv1134v3s4/): the readers' own selection and warnings over `list_tree` ----
    "s4v3-v2 reason whitelist": (
        "test_1134_shared_readers.py::test_a_refused_folders_reason_is_the_listings_verbatim_whatever_the_errno",
        "rewords a refusal; no touch"),
    "s4v3-v3 warn order": (
        "test_1134_shared_readers.py::test_several_folder_faults_warn_once_each_in_path_order",
        "reorders warnings; no touch"),
    "s4v3-v4/v5 Path form at another depth": (
        "test_1134_shared_readers.py::test_the_path_form_never_lists_a_folder_below_the_shape",
        "the same `list_tree` call at another depth; its anchor is unchanged"),
    "s4v3-v6/v7/v9 gone warned, selection stopped, unselected warned": (
        "test_1134_shared_readers.py::test_a_folder_swapped_between_listings_is_refused_or_gone_and_never_listed_through",
        "the selection over one listing; no touch"),
    "s4v3-v11 absent and refused collapsed": (
        "test_1134_shared_readers.py::test_an_absent_root_or_folder_yields_nothing_and_warns_nothing",
        "a warning's condition; no touch"),
    # --- v3 lead-author step (s6v3-adv-patches/) ----------------------------------------------
    "s6v3-E1/Q1 refused probe stands in for the write": (
        "test_1134_lead_author_v3_holes.py::test_a_refused_listing_alone_does_not_refuse_the_draft",
        "reads `entry_kind`'s answer differently; no touch"),
    "s6v3-E4a run serves its claim after its trees closed": (
        "test_1134_lead_author_v3_holes.py::test_run_without_deps_mints_and_reaches_its_agent_inside_its_own_trees",
        "a lifetime fault: the handles are the lane's own"),
    "s6v3-E4b trees closed early through `tree_for.__self__`": (
        "test_1134_lead_author_adversary.py::test_the_runs_commit_gate_reads_what_the_agent_left_through_the_trees",
        "a lifetime fault: the handles are the lane's own"),
    "s6v3-E7 EIO read as absent": (
        "test_1134_lead_author_v3_holes.py::test_kind_at_answers_other_for_every_refused_listing",
        "maps a reason to a kind; no touch"),
    "s6v3-E8 raw PyYAML": (
        "test_lint_raw_yaml.py::test_the_shared_module_and_its_callers_are_clean",
        "#1139's YAML gate, not a filesystem touch"),
    "s6v3-E10/Q3 refused folder's warning reworded or dropped": (
        "test_1134_lead_author_v3_holes.py::test_discover_warns_an_uncommon_refusal_in_its_own_words",
        "a warning's words; no touch"),
    "s6v3-Q2 gone folder warned": (
        "test_1134_lead_author_holes.py::test_a_folder_found_gone_by_its_own_listing_is_passed_over_silently",
        "a warning; no touch"),
    "s6v3-L1 entry_kind's noqa kept": (
        "test_1134_lead_author_v3_holes.py::test_entry_kind_carries_no_vulture_suppression",
        "a `# noqa` comment"),
    # --- v3 curator step (s5v3-adv-patches/) --------------------------------------------------
    "s5v3-A1 empty before-state read as none": (
        "test_1134_curator_v3_holes.py::test_an_empty_before_state_still_sweeps_and_removes_the_agents_files",
        "a truthiness test; no touch"),
    "s5v3-A2/D677 ls-tree parsed without -z, names decoded strictly": (
        "test_1134_curator_v3_holes.py::test_a_tracked_lesson_with_an_odd_name_is_in_the_before_state_and_restored",
        "git's own output parsed (N-a); no touch"),
    "s5v3-A4 settle skips a refused holding folder": (
        "test_1134_curator_v3_holes.py::test_a_created_name_below_a_linked_folder_propagates_on_the_settle",
        "skips a handle call; no touch"),
    "s5v3-A5/K10 put_back's kind test widened or narrowed": (
        "test_1134_curator_v3_holes.py::test_put_back_outside_the_mounts_unlinks_only_a_file",
        "the D3 branch's condition; its anchor is unchanged"),
    "s5v3-A9/K06/K12 git-failure warnings": (
        "test_1134_curator_handle.py::test_a_broken_index_still_sweeps_through_gits_worktree_listing",
        "a warning's words, or a sweep skipped; no touch"),
    "s5v3-K01 tracked symlinks kept": (
        "test_1134_curator_handle.py::test_a_tracked_symlink_is_not_in_the_before_state_and_never_restored_as_a_file",
        "git's own output filtered (N-a); no touch"),
    "s5v3-K03/K04/K05 a git failure swallowed or rerouted": (
        "test_1134_curator_handle.py::test_a_before_state_git_cannot_read_raises",
        "fault routing; no touch"),
    "s5v3-K09 commit split reads a refusal as absent": (
        "test_1134_curator_handle.py::test_a_dangling_link_at_an_approved_path_counts_as_present",
        "maps `kind_at`'s answer; no touch"),
}


@pytest.mark.parametrize("patch", sorted(NOT_CENSUS_SHAPED))
def test_a_patch_the_census_cannot_see_has_an_owner(patch: str):
    owner, _why = NOT_CENSUS_SHAPED[patch]
    file, _, test = owner.partition("::")
    tree = ast.parse((WORKTREE / "defender" / "tests" / file).read_text(encoding="utf-8"))
    assert test in {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}, owner


# =============================================================================================
# The census discriminates: evasions the vocabulary claims to cover, and handles it must pass
# =============================================================================================

FIXTURE_MODULE = "learning/author/_census_fixture.py"
_H = "from defender._io import Bound, Held\n"
_TL = "from defender._tree_listing import entry_kind, list_tree\n"
_OPT = "from pathlib import Path\nfrom defender._corpus import iter_lessons\n" + _H
_LT = "from defender.learning.core.lane_trees import DrainTrees, TreeFor, open_drain_trees\n"

EVASIONS: dict[str, tuple[str, tuple[tuple[str, str, str], ...]]] = {
    "aliased-module": (
        "import shutil as sh\ndef f(p):\n    sh.rmtree(p)\n",
        (("f", "call", "sh.rmtree(p)"),)),
    "aliased-function": (
        "from os.path import lexists as x\ndef f(p):\n    return x(p)\n",
        (("f", "call", "x(p)"),)),
    "aliased-io-seam": (
        "from defender._io import write_atomic as wa\ndef f(p, t):\n    wa(p, t)\n",
        (("f", "call", "wa(p, t)"),)),
    "function-local-import": (
        "def f(p):\n    import os as q\n    q.remove(p)\n",
        (("f", "call", "q.remove(p)"),)),
    "relative-import": (
        "from ..._io import read_text_soft as r\ndef f(p):\n    return r(p)\n",
        (("f", "call", "r(p)"),)),
    "os-path-module-alias": (
        "import os.path as osp\ndef f(p):\n    return osp.exists(p)\n",
        (("f", "call", "osp.exists(p)"),)),
    "reader-through-a-re-export": (
        "from defender.learning.author.shared import iter_lessons as il\n"
        "def f(p):\n    return list(il(p))\n",
        (("f", "reader", "il(p)"),)),
    "bare-load-assigned": (
        "from defender._io import read_text_soft\ndef f(p):\n    reader = read_text_soft\n"
        "    return reader(p)\n",
        (("f", "load", "read_text_soft"),)),
    "bare-load-as-callback": (
        "import os\ndef f(ps):\n    list(map(os.unlink, ps))\n",
        (("f", "load", "os.unlink"),)),
    "constructor-as-callback": (
        "import functools\nfrom defender._io import hold\n"
        "def f(p):\n    return functools.partial(hold)(p)\n",
        (("f", "load", "hold"),)),
    "bound-path-verb-as-callback": (
        "import functools\ndef f(p, q, ps):\n    functools.partial(p.unlink)()\n"
        "    return list(map(q.read_text, ps))\n",
        (("f", "load", "p.unlink"), ("f", "load", "q.read_text"))),
    "getattr-path-verb": (
        "def f(p):\n    return getattr(p, 'read_text')()\n",
        (("f", "getattr", "getattr(p, 'read_text')"),)),
    "getattr-private": (
        _H + "def f(h: Held):\n    return getattr(h, '_where')\n",
        (("f", "getattr", "getattr(h, '_where')"),)),
    # A `Bound | Path` (or `_corpus.Tree`) parameter is not provably a `Bound`: it is a tree slot
    # of its own def, so the Path is caught where it is handed in.
    "union-annotated-view": (
        _OPT + "def f(t: Bound | Path):\n    return list(iter_lessons(t))\n"
        "def g(p):\n    return f(p)\n",
        (("g", "reader", "f(p)"),)),
    "tree-alias-annotated-view": (
        "from defender import _corpus\n"
        "def f(t: _corpus.Tree):\n    return list(_corpus.iter_lessons(t))\n"
        "def g(p):\n    return f(p)\n",
        (("g", "reader", "f(p)"),)),
    "held-given-to-a-reader": (
        _OPT + "def f(h: Held):\n    return list(iter_lessons(h))\n",
        (("f", "reader", "iter_lessons(h)"),)),
    "rebound-view-parameter": (
        _OPT + "from defender._io import bind\n"
        "def f(t: Bound, p):\n    if p:\n        t = bind(p)\n    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"), ("f", "construct", "bind(p)"))),
    "bind-is-not-provable": (
        _OPT + "from defender._io import bind\n"
        "def f(p):\n    with bind(p) as v:\n        return list(iter_lessons(v))\n",
        (("f", "reader", "iter_lessons(v)"), ("f", "construct", "bind(p)"))),
    "hold-view-is-not-provable": (
        _OPT + "from defender._io import hold\n"
        "def f(p):\n    return list(iter_lessons(hold(p).view()))\n",
        (("f", "reader", "iter_lessons(hold(p).view())"), ("f", "construct", "hold(p)"))),
    "held-spelling-then-plain-read": (
        _H + "def f(held: Held, name):\n    return (held._where / name).read_text()\n",
        (("f", "attr", "(held._where / name).read_text()"), ("f", "private", "held._where"))),
    "bound-private-handle": (
        _H + "def f(v: Bound):\n    return v._handle.fd, v._prefix\n",
        (("f", "private", "v._handle"), ("f", "private", "v._prefix"))),
    "trees-private-held": (
        _LT + "def f(trees: DrainTrees):\n    return trees._held\n",
        (("f", "private", "trees._held"),)),
    "self-private-outside-the-class": (
        "class Other:\n    def f(self):\n        return self._where\n",
        (("Other.f", "private", "self._where"),)),
    "viewed-rebuild": (
        "from defender import _corpus\n"
        "def f(p):\n    return _corpus.read_query_template(_corpus._viewed(p), 'x.md', where=p)\n",
        (("f", "construct", "_corpus._viewed(p)"),
         ("f", "reader", "_corpus.read_query_template(_corpus._viewed(p), 'x.md', where=p)"))),
    "load-catalog-default": (
        "from defender.learning.leads import lead_neighbors\n"
        "def f():\n    return lead_neighbors.load_catalog()\n",
        (("f", "reader", "lead_neighbors.load_catalog()"),)),
    "unbound-path-method": (
        "from pathlib import Path\ndef f(p):\n    return Path.read_text(p)\n",
        (("f", "attr", "Path.read_text(p)"),)),
    "openers": (
        "import codecs\nimport tarfile\ndef f(p):\n    open(p)\n    codecs.open(p)\n"
        "    tarfile.open(p)\n",
        (("f", "call", "open(p)"), ("f", "call", "codecs.open(p)"),
         ("f", "call", "tarfile.open(p)"))),
    "tree-for-element-one": (
        "from defender._corpus import iter_lessons\n" + _LT +
        "def f(tree_for: TreeFor, p):\n    name, tree = tree_for(p)\n"
        "    return list(iter_lessons(tree.view()))\n",
        (("f", "reader", "iter_lessons(tree.view())"),)),
    "local-rebound-to-a-path": (
        _OPT + "def f(h: Held, p):\n    v = h.view()\n    if p:\n        v = p\n"
        "    return list(iter_lessons(v))\n",
        (("f", "reader", "iter_lessons(v)"),)),
    "nested-scope-rebinds-the-view": (
        _OPT + "def f(t: Bound, ps):\n    _ = [t for t in ps]\n    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "view-of-a-bound-is-not-a-view": (
        _OPT + "def f(t: Bound):\n    return list(iter_lessons(t.view()))\n",
        (("f", "reader", "iter_lessons(t.view())"),)),
    "view-at-of-an-untyped-held": (
        _OPT + "from defender.learning.core.lane_trees import view_at\n"
        "def f(held, name):\n    return list(iter_lessons(view_at(held, name)))\n",
        (("f", "reader", "iter_lessons(view_at(held, name))"),)),
    "under-of-a-held-is-not-a-view": (
        _OPT + "def f(h: Held):\n    return list(iter_lessons(h.under('x')))\n",
        (("f", "reader", "iter_lessons(h.under('x'))"),)),
    "mount-of-an-untyped-trees": (
        _OPT + "def f(trees, p):\n    return list(iter_lessons(trees.mount(p).view()))\n",
        (("f", "reader", "iter_lessons(trees.mount(p).view())"),)),
    "lane-skills-of-an-untyped-trees": (
        "from defender.learning.leads import lead_neighbors\n"
        "from defender.learning.leads._lead_spine import lane_skills\n"
        "def f(trees, paths, d):\n    skills = lane_skills(trees, paths)\n"
        "    return lead_neighbors.load_lane_catalog(skills.view(), where=d)\n",
        (("f", "reader", "lead_neighbors.load_lane_catalog(skills.view(), where=d)"),)),
    "with-target-not-an-opener": (
        _OPT + "def f(make, p):\n    with make(p) as trees:\n"
        "        return list(iter_lessons(trees.mount(p).view()))\n",
        (("f", "reader", "iter_lessons(trees.mount(p).view())"),)),
    "view-bytes-on-an-unprovable-receiver": (
        "def f(view, name, held):\n    view.read_bytes(name)\n    held.unlink(name)\n"
        "    held.mkdir('.')\n",
        (("f", "attr", "view.read_bytes(name)"), ("f", "attr", "held.unlink(name)"),
         ("f", "attr", "held.mkdir('.')"))),
    "held-verb-on-a-view": (
        _H + "def f(v: Bound, name):\n    v.unlink(name)\n",
        (("f", "attr", "v.unlink(name)"),)),
    # #1134 addendum 3 (D1): `Bound` has no `read_bytes`, so a provable view's is a Path verb.
    "read-bytes-on-a-provable-view": (
        _H + "def f(v: Bound, h: Held, name):\n    v.read_bytes(name)\n"
        "    return h.view().read_bytes(name)\n",
        (("f", "attr", "v.read_bytes(name)"), ("f", "attr", "h.view().read_bytes(name)"))),
    "trees-open-on-an-instance": (
        _LT + "def f(trees: DrainTrees, p):\n    return trees.open((p,))\n",
        (("f", "attr", "trees.open((p,))"),)),
    "hold-partial": (
        "import functools\nfrom defender import _io\ndef f():\n    return functools.partial(_io.hold)\n",
        (("f", "load", "_io.hold"),)),
    # 1b / G: an optional handle proves nothing without a guard that covers the use.
    "optional-guard-after-use": (
        _OPT + "def f(t: Bound | None):\n    out = list(iter_lessons(t))\n"
        "    if t is None:\n        raise ValueError\n    return out\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-guard-in-sibling-branch": (
        _OPT + "def f(t: Bound | None, c):\n    if c:\n        if t is None:\n"
        "            raise ValueError\n    else:\n        return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-guard-nested-in-earlier-sibling": (
        _OPT + "def f(t: Bound | None, c):\n    if c:\n        if t is None:\n"
        "            raise ValueError\n    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-if-not": (
        _OPT + "def f(t: Bound | None):\n    if not t:\n        raise ValueError\n"
        "    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-guard-with-else": (
        _OPT + "def f(t: Bound | None):\n    if t is None:\n        raise ValueError\n"
        "    else:\n        pass\n    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-guard-falls-through": (
        _OPT + "def f(t: Bound | None):\n    if t is None:\n        print('none')\n"
        "    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-guard-and-chain": (
        _OPT + "def f(t: Bound | None, c):\n    if t is None and c:\n        raise ValueError\n"
        "    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-not-none-body-used-outside": (
        _OPT + "def f(t: Bound | None):\n    if t is not None:\n        pass\n"
        "    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-not-none-or-chain": (
        _OPT + "def f(t: Bound | None, c):\n    if t is not None or c:\n"
        "        return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-leaving-not-none-guard": (
        _OPT + "def f(t: Bound | None):\n    if t is not None:\n        return []\n"
        "    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-is-none-body": (
        _OPT + "def f(t: Bound | None):\n    if t is None:\n        return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-union-with-path": (
        _OPT + "class K:\n    def f(self, t: Bound | Path):\n        if t is None:\n"
        "            raise ValueError\n        return list(iter_lessons(t))\n",
        (("K.f", "reader", "iter_lessons(t)"),)),
    "optional-any": (
        _OPT + "from typing import Any\ndef f(t: Any = None):\n    if t is None:\n"
        "        raise ValueError\n    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "optional-rebound": (
        _OPT + "from defender._io import bind\n"
        "def f(t: Bound | None, p):\n    if t is None:\n        return []\n"
        "    t = t if p is None else bind(p)\n    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"), ("f", "construct", "bind(p)"))),
    # 7: a helper's returned handle — only when its handle-typed parameters are proven at the
    # call, every return is provable, and an optional result is guarded after its one binding.
    "helper-handed-an-unprovable-tree-for": (
        _OPT + _LT + "def g(tree_for: TreeFor, p) -> Bound | None:\n    hit = tree_for(p)\n"
        "    if hit is None:\n        return None\n    held, name = hit\n    return held.view()\n"
        "def f(p):\n    v = g(lambda q: None, p)\n    if v is None:\n        return []\n"
        "    return list(iter_lessons(v))\n",
        (("f", "reader", "iter_lessons(v)"), ("f", "tree_for", "g(lambda q: None, p)"))),
    "helper-returns-a-path": (
        _OPT + "def g(h: Held, p):\n    if p:\n        return h.view()\n    return p\n"
        "def f(h: Held, p):\n    return list(iter_lessons(g(h, p)))\n",
        (("f", "reader", "iter_lessons(g(h, p))"),)),
    "helper-optional-unguarded": (
        _OPT + "def g(h: Held, p):\n    if p:\n        return None\n    return h.view()\n"
        "def f(h: Held, p):\n    v = g(h, p)\n    return list(iter_lessons(v))\n",
        (("f", "reader", "iter_lessons(v)"),)),
    "helper-optional-rebound-after-the-guard": (
        _OPT + "def g(h: Held, p):\n    if p:\n        return (None, p)\n    return (h.view(), p)\n"
        "def f(h: Held, p):\n    v, w = g(h, p)\n    if v is None:\n        return []\n"
        "    v, w = g(h, w)\n    return list(iter_lessons(v))\n",
        (("f", "reader", "iter_lessons(v)"),)),
    "helper-optional-guard-before-its-binding": (
        _OPT + "def g(h: Held, p):\n    if p:\n        return None\n    return h.view()\n"
        "def f(h: Held, ps):\n    for p in ps:\n        if v is None:\n            return []\n"
        "        v = g(h, p)\n        list(iter_lessons(v))\n",
        (("f", "reader", "iter_lessons(v)"),)),
    "helper-decorated": (
        _OPT + "import functools\n@functools.cache\ndef g(h: Held):\n    return h.view()\n"
        "def f(h: Held):\n    return list(iter_lessons(g(h)))\n",
        (("f", "reader", "iter_lessons(g(h))"),)),
    # A fresh path owner spells a mount list under a root of the caller's choosing.
    "fresh-loop-paths": (
        "from defender.learning.core import config as c\n" + _LT +
        "def f(root):\n    return open_drain_trees(c.LoopPaths(repo_root=root), 'lead_author_drain')\n",
        (("f", "construct", "c.LoopPaths(repo_root=root)"),
         ("f", "construct", "open_drain_trees(c.LoopPaths(repo_root=root), 'lead_author_drain')"))),
    "fresh-defender-paths": (
        "from defender._paths import DefenderPaths as DP\ndef f(root):\n    return DP(root).skills_dir\n",
        (("f", "construct", "DP(root)"),)),
    "with-repo-root": (
        "def f(paths, root):\n    return paths.with_repo_root(root).drain_writable_trees('author_drain')\n",
        (("f", "construct", "paths.with_repo_root(root)"),)),
    "replace-repo-root": (
        "import dataclasses\ndef f(paths, root):\n    return dataclasses.replace(paths, repo_root=root)\n",
        (("f", "construct", "dataclasses.replace(paths, repo_root=root)"),)),
    "drain-trees-built-directly": (
        _LT + "def f(mounts):\n    with DrainTrees.open(mounts) as trees:\n        return trees\n",
        (("f", "construct", "DrainTrees.open(mounts)"),)),
    # The `tree_for` kind: a keyword or a `TreeFor` slot handed something not provably one.
    "tree-for-keyword-lambda": (
        "def f(g, p):\n    return g(p, tree_for=lambda _p: None)\n",
        (("f", "tree_for", "g(p, tree_for=lambda _p: None)"),)),
    "tree-for-positional-to-kind-at": (
        "from defender.learning.core import lane_trees\n"
        "def f(root, p):\n    return lane_trees.kind_at(root, lambda _p: None, p)\n",
        (("f", "tree_for", "lane_trees.kind_at(root, lambda _p: None, p)"),)),
    "tree-for-positional-to-a-typed-def": (
        "from defender.learning.leads.lead_author import _rules\n"
        "def f(root, p):\n    return _rules._still_there(root, dict.get, p)\n",
        (("f", "tree_for", "_rules._still_there(root, dict.get, p)"),)),
    "tree-for-none-to-an-optional-slot": (
        _LT + "def g(root, tree_for: TreeFor | None, p):\n    return tree_for\n"
        "def f(root, p):\n    return g(root, None, p)\n",
        (("f", "tree_for", "g(root, None, p)"),)),
    "tree-for-through-partial": (
        "import functools\nfrom defender.learning.leads.lead_author import _rules\n"
        "def f(root):\n    return functools.partial(_rules._catalog_in_tree, root, None)\n",
        (("f", "tree_for", "functools.partial(_rules._catalog_in_tree, root, None)"),)),
    "tree-for-of-an-untyped-trees": (
        "def f(trees, g):\n    return g(tree_for=trees.tree_for)\n",
        (("f", "tree_for", "g(tree_for=trees.tree_for)"),)),
    "tree-for-not-the-parameter": (
        "from pathlib import Path\nfrom defender._corpus import read_query_template\n"
        "def tree_for(p):\n    return Path(p).parent, Path(p).name\n"
        "def f(d, w):\n    hit = tree_for(d)\n    return read_query_template(hit[0].view(), hit[1], where=w)\n",
        (("f", "reader", "read_query_template(hit[0].view(), hit[1], where=w)"),)),
    "tree-for-import-alias": (
        "from defender.learning.core.lane_trees import kind_at as tree_for\n"
        "from defender._corpus import iter_lessons\n"
        "def f(p):\n    tree, name = tree_for(p)\n    return list(iter_lessons(tree.view()))\n",
        (("f", "reader", "iter_lessons(tree.view())"),)),
    "tree-for-rebound-parameter": (
        "from defender._corpus import iter_lessons\n" + _LT +
        "def f(tree_for: TreeFor, p):\n    tree_for = dict\n    tree, name = tree_for(p)\n"
        "    return list(iter_lessons(tree.view()))\n",
        (("f", "reader", "iter_lessons(tree.view())"),)),
    "tree-for-untyped-parameter": (
        "from defender._corpus import iter_lessons\n"
        "def f(tree_for, p):\n    tree, name = tree_for(p)\n    return list(iter_lessons(tree.view()))\n",
        (("f", "reader", "iter_lessons(tree.view())"),)),
    "rename-replace-target-keyword": (
        "def f(a, b):\n    a.rename(target=b)\n    a.replace(target=b)\n",
        (("f", "attr", "a.rename(target=b)"), ("f", "attr", "a.replace(target=b)"))),
    "io-and-archive-openers": (
        "import io, zipfile, tarfile, runpy, importlib.util\ndef f(p):\n"
        "    io.FileIO(p)\n    io.open_code(p)\n    zipfile.ZipFile(p)\n    tarfile.open(p)\n"
        "    runpy.run_path(p)\n    importlib.util.spec_from_file_location('m', p)\n",
        (("f", "call", "io.FileIO(p)"), ("f", "call", "io.open_code(p)"),
         ("f", "call", "zipfile.ZipFile(p)"), ("f", "call", "tarfile.open(p)"),
         ("f", "call", "runpy.run_path(p)"),
         ("f", "call", "importlib.util.spec_from_file_location('m', p)"))),
    "os-walks-xattrs-and-shells": (
        "import os\ndef f(p):\n    os.fwalk(p)\n    os.statvfs(p)\n    os.listxattr(p)\n"
        "    os.getxattr(p, 'a')\n    os.system(p)\n    os.popen(p)\n    os.execv(p, [p])\n"
        "    os.spawnv(0, p, [p])\n    os.posix_spawn(p, [p], {})\n",
        tuple(("f", "call", t) for t in (
            "os.fwalk(p)", "os.statvfs(p)", "os.listxattr(p)", "os.getxattr(p, 'a')",
            "os.system(p)", "os.popen(p)", "os.execv(p, [p])", "os.spawnv(0, p, [p])",
            "os.posix_spawn(p, [p], {})"))),
    "process-and-file-modules": (
        "import subprocess, filecmp, linecache, fileinput\ndef f(p, q):\n"
        "    subprocess.run(['cat', p])\n    filecmp.cmp(p, q)\n    linecache.getlines(p)\n"
        "    fileinput.input([p])\n",
        (("f", "call", "subprocess.run(['cat', p])"), ("f", "call", "filecmp.cmp(p, q)"),
         ("f", "call", "linecache.getlines(p)"), ("f", "call", "fileinput.input([p])"))),
    "more-path-verbs": (
        "def f(p, q):\n    p.is_fifo()\n    p.is_socket()\n    p.is_mount()\n    p.is_block_device()\n"
        "    p.is_char_device()\n    p.owner()\n    p.lchmod(0o644)\n    p.link_to(q)\n",
        tuple(("f", "attr", t) for t in (
            "p.is_fifo()", "p.is_socket()", "p.is_mount()", "p.is_block_device()",
            "p.is_char_device()", "p.owner()", "p.lchmod(420)", "p.link_to(q)"))),
    "methodcaller-verb": (
        "import operator\ndef f(p):\n    return operator.methodcaller('read_text')(p)\n",
        (("f", "getattr", "operator.methodcaller('read_text')"),)),
    "rebuilt-by-its-own-class": (
        _H + "def f(t: Held, paths, p, root):\n    s = t.__class__(p)\n"
        "    v = type(t)(p)\n    return s, v, type(paths)(repo_root=root)\n",
        (("f", "construct", "t.__class__(p)"), ("f", "construct", "type(t)(p)"),
         ("f", "construct", "type(paths)(repo_root=root)"))),
    "path-owner-as-callback": (
        "import functools\nfrom defender.learning.core.config import LoopPaths\n"
        "def f(root):\n    return functools.partial(LoopPaths, state_dir=None)(repo_root=root)\n",
        (("f", "load", "LoopPaths"),)),
    # --- v2 step 7, third pass -----------------------------------------------------------------
    # Hole 1: a `TreeFor` slot reached through `**` / `*`, left to a partial, or a callee whose
    # keys cannot be read.
    "tree-for-double-star-to-a-typed-def": (
        "from defender.learning.author import drain\n"
        "def f(root, rel, kw):\n    drain._put_back(root, rel, **{'tree_for': lambda _p: None})\n"
        "    return drain._revert_strays(root, 'x', [], **kw)\n",
        (("f", "tree_for", "drain._put_back(root, rel, **{'tree_for': lambda _p: None})"),
         ("f", "tree_for", "drain._revert_strays(root, 'x', [], **kw)"))),
    "double-star-to-a-callee-outside-the-tree": (
        "import dataclasses\nfrom defender.learning.leads.lead_author import LeadAuthorDeps\n"
        "def f(g, deps, over, p):\n    g(p, **{'tree_for': lambda _p: None})\n"
        "    dataclasses.replace(deps, **over)\n    return LeadAuthorDeps(**over)\n",
        (("f", "tree_for", "g(p, **{'tree_for': lambda _p: None})"),
         ("f", "tree_for", "dataclasses.replace(deps, **over)"),
         ("f", "tree_for", "LeadAuthorDeps(**over)"))),
    "star-args-before-a-tree-for-slot": (
        "from defender.learning.core.lane_trees import kind_at\n" + _LT +
        "def f(root, tree_for: TreeFor, p):\n    return kind_at(*[root, lambda _p: None], tree_for)\n",
        (("f", "tree_for", "kind_at(*[root, lambda _p: None], tree_for)"),)),
    "tree-for-slot-left-to-a-partial": (
        "import functools\nfrom defender.learning.leads.lead_author import _rules\n"
        "def f(root, p):\n    still = functools.partial(_rules._still_there, root)\n"
        "    return still(lambda _p: None, p)\n",
        (("f", "tree_for", "functools.partial(_rules._still_there, root)"),)),
    "tree-for-slot-def-as-callback": (
        "from defender.learning.leads.lead_author import _rules\n"
        "def f(root, ps):\n    check = _rules._still_there\n"
        "    return [check(root, lambda _p: None, p) for p in ps]\n",
        (("f", "load", "_rules._still_there"),)),
    # Hole 2: every tree slot (`_corpus.Tree`, a union admitting a handle and a path), not only
    # the named readers'.
    "tree-slot-of-a-private-reader": (
        "from defender import _corpus\n"
        "def f(where):\n    return (list(_corpus._templates(where, where)),\n"
        "            list(_corpus._lessons(where, where, str, None)))\n",
        (("f", "reader", "_corpus._templates(where, where)"),
         ("f", "reader", "_corpus._lessons(where, where, str, None)"))),
    "tree-slot-def-as-callback": (
        "import functools\nfrom defender import _corpus\n"
        "def f(p):\n    return functools.partial(_corpus._lessons, p)\n",
        (("f", "load", "_corpus._lessons"),)),
    "reader-slot-hidden-by-star-args": (
        _OPT + "def f(p, d):\n    list(iter_lessons(*[p]))\n    return list(iter_lessons(**d))\n",
        (("f", "reader", "iter_lessons(*[p])"), ("f", "reader", "iter_lessons(**d)"))),
    "pass-through-rebound": (
        _OPT + "def f(t: Bound | Path, p):\n    t = p\n    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"),)),
    "pass-through-in-a-method-or-nested-def": (
        _OPT + "class K:\n    def m(self, t: Bound | Path):\n        return list(iter_lessons(t))\n"
        "def f(t: Bound | Path):\n    def g():\n        return list(iter_lessons(t))\n    return g()\n",
        (("K.m", "reader", "iter_lessons(t)"), ("f.<locals>.g", "reader", "iter_lessons(t)"))),
    "pass-through-of-another-kind-or-star-args": (
        _OPT + "def f(t: Held | Path):\n    return list(iter_lessons(t))\n"
        "def g(*t: Bound | Path):\n    return list(iter_lessons(t))\n",
        (("f", "reader", "iter_lessons(t)"), ("g", "reader", "iter_lessons(t)"))),
    "pass-through-of-a-redefined-def": (
        _OPT + "def f(t: Bound | Path):\n    return list(iter_lessons(t))\ndef f(t):\n    return t\n",
        (("f", "reader", "iter_lessons(t)"),)),
    # Hole 3: `_io`'s underscore names — private defs, classes, constants — are census words.
    "io-private-through-a-local-import": (
        "def f(p, t):\n    from defender._io import _create_named\n    _create_named(p, t)\n",
        (("f", "load", "from defender._io import _create_named"),
         ("f", "call", "_create_named(p, t)"))),
    "io-private-module-attribute-and-reference": (
        "from defender import _io\n"
        "def f(p):\n    fd = _io._open_plain_fd(p)\n    check = _io._refuse_unless_plain\n"
        "    return fd, check, _io._NOT_PLAIN, _io._Handle(None, fd)\n",
        (("f", "call", "_io._open_plain_fd(p)"), ("f", "load", "_io._refuse_unless_plain"),
         ("f", "load", "_io._NOT_PLAIN"), ("f", "call", "_io._Handle(None, fd)"))),
    "io-private-relative-import-alias": (
        "from ..._io import _ensure_dir_component as ensure\ndef f(p):\n    ensure(p)\n",
        (("<module>", "load", "from ..._io import _ensure_dir_component as ensure"),
         ("f", "call", "ensure(p)"))),
    "io-private-getattr": (
        "from defender import _io\n"
        "def f(p):\n    getattr(_io, '_leaf_is_link')(p)\n    return getattr(_io, '__dict__')\n",
        (("f", "getattr", "getattr(_io, '_leaf_is_link')"),
         ("f", "getattr", "getattr(_io, '__dict__')"))),
    # The leads.
    "path-class-verbs-at-any-arity": (
        "from pathlib import Path\n"
        "def f(a, b):\n    Path.replace(a, b)\n    Path.rename(a, b)\n    return Path.owner(a)\n",
        (("f", "attr", "Path.replace(a, b)"), ("f", "attr", "Path.rename(a, b)"),
         ("f", "attr", "Path.owner(a)"))),
    "attrgetter-verb": (
        "import operator\n"
        "def f(p):\n    operator.attrgetter('read_text')(p)()\n"
        "    return operator.attrgetter('name', 'parent.unlink')(p)\n",
        (("f", "getattr", "operator.attrgetter('read_text')"),
         ("f", "getattr", "operator.attrgetter('name', 'parent.unlink')"))),
    "compressed-logging-loader-and-child-openers": (
        "import asyncio, bz2, dbm, gzip, importlib.machinery, logging, logging.handlers, lzma, pty\n"
        "import shelve, sqlite3\ndef f(p):\n"
        "    gzip.GzipFile(p)\n    bz2.BZ2File(p)\n    lzma.LZMAFile(p)\n    logging.FileHandler(p)\n"
        "    logging.handlers.RotatingFileHandler(p)\n    sqlite3.connect(p)\n"
        "    importlib.machinery.SourceFileLoader('m', p)\n    asyncio.create_subprocess_exec(p)\n"
        "    asyncio.create_subprocess_shell(p)\n    pty.spawn(p)\n    shelve.open(p)\n"
        "    dbm.whichdb(p)\n",
        tuple(("f", "call", t) for t in (
            "gzip.GzipFile(p)", "bz2.BZ2File(p)", "lzma.LZMAFile(p)", "logging.FileHandler(p)",
            "logging.handlers.RotatingFileHandler(p)", "sqlite3.connect(p)",
            "importlib.machinery.SourceFileLoader('m', p)", "asyncio.create_subprocess_exec(p)",
            "asyncio.create_subprocess_shell(p)", "pty.spawn(p)", "shelve.open(p)",
            "dbm.whichdb(p)"))),
    "module-open-from-import": (
        "from bz2 import open as bz_open\nfrom gzip import open as gz_open\n"
        "def f(p):\n    gz_open(p)\n    return bz_open(p)\n",
        (("f", "call", "gz_open(p)"), ("f", "call", "bz_open(p)"))),
    "os-cwd-root-and-flags": (
        "import os\ndef f(p):\n    os.chdir(p)\n    os.chroot(p)\n    os.pathconf(p, 'PC_NAME_MAX')\n"
        "    os.lchmod(p, 0)\n",
        tuple(("f", "call", t) for t in (
            "os.chdir(p)", "os.chroot(p)", "os.pathconf(p, 'PC_NAME_MAX')", "os.lchmod(p, 0)"))),
    "newer-path-verbs": (
        "def f(p, q):\n    p.walk()\n    p.is_junction()\n    p.copy_into(q)\n    p.move_into(q)\n",
        tuple(("f", "attr", t) for t in (
            "p.walk()", "p.is_junction()", "p.copy_into(q)", "p.move_into(q)"))),
    "handle-parameter-with-a-default": (
        _OPT + "from typing import cast\n_P = Path('x')\n"
        "def f(v: Bound = cast(Bound, _P)):\n    return list(iter_lessons(v))\n"
        "def g(h: Held = cast(Held, _P)):\n    h.unlink('x')\n"
        "def k(v: Bound = None):\n    return list(iter_lessons(v))\n",
        (("f", "reader", "iter_lessons(v)"), ("g", "attr", "h.unlink('x')"),
         ("k", "reader", "iter_lessons(v)"))),
    "optional-handle-with-a-default-the-guard-cannot-prove": (
        _OPT + "from typing import cast\n"
        "def f(v: Bound | None = cast(Bound, Path('x'))):\n    if v is None:\n        return []\n"
        "    return list(iter_lessons(v))\n",
        (("f", "reader", "iter_lessons(v)"),)),
    "tree-slot-of-a-held-union-or-a-typing-union": (
        _OPT + "from typing import Optional, Union\nfrom defender import _corpus\n"
        "def g(t: Held | Path):\n    return t\n"
        "def h(t: Union[Bound, Path]):\n    return t\n"
        "def k(t: Optional[_corpus.Tree]):\n    return t\n"
        "def f(p):\n    g(p)\n    h(p)\n    return k(p)\n",
        (("f", "reader", "g(p)"), ("f", "reader", "h(p)"), ("f", "reader", "k(p)"))),
    "replace-repo-root-by-double-star": (
        "import dataclasses\ndef f(paths, root):\n"
        "    return dataclasses.replace(paths, **{'repo_root': root})\n",
        (("f", "construct", "dataclasses.replace(paths, **{'repo_root': root})"),)),
    # --- v3: B2's helpers take a provable `Bound`, `view_at` a provable `Held`; listings ----------
    "b2-helpers-handed-an-unprovable-view": (
        _TL + "def f(p, n):\n    entry_kind(p, n)\n    return list_tree(p, depth=1)\n",
        (("f", "reader", "entry_kind(p, n)"), ("f", "reader", "list_tree(p, depth=1)"),
         ("f", "listing", "list_tree(p, depth=1)"))),
    "b2-helper-handed-a-held": (
        _H + _TL + "def f(h: Held, n):\n    return entry_kind(h, n), list_tree(h, depth=3)\n",
        (("f", "reader", "entry_kind(h, n)"), ("f", "reader", "list_tree(h, depth=3)"))),
    "b2-helper-over-a-bind": (
        "from defender._io import bind\n" + _TL +
        "def f(p, n):\n    with bind(p) as v:\n        return entry_kind(v, n)\n",
        (("f", "construct", "bind(p)"), ("f", "reader", "entry_kind(v, n)"))),
    "b2-helper-through-a-module-alias": (
        "from defender import _tree_listing as tl\ndef f(p, n):\n    return tl.entry_kind(p, n)\n",
        (("f", "reader", "tl.entry_kind(p, n)"),)),
    "b2-helper-as-callback": (
        "import functools\n" + _TL + "def f(p):\n    return functools.partial(entry_kind, p)\n",
        (("f", "load", "entry_kind"),)),
    "view-at-of-an-unprovable-held": (
        "from defender.learning.core.lane_trees import view_at\n"
        "def f(held, p, n):\n    view_at(held, n)\n    return view_at(p, '.')\n",
        (("f", "reader", "view_at(held, n)"), ("f", "reader", "view_at(p, '.')"))),
    "raw-listings": (
        _H + "def f(v: Bound, h: Held, x):\n    v.entries()\n    v.under('a').entries()\n"
        "    h.view().entries()\n    x.entries()\n    g = v.entries\n"
        "    return g, getattr(v, 'entries')\n",
        (("f", "listing", "v.entries()"), ("f", "listing", "v.under('a').entries()"),
         ("f", "listing", "h.view().entries()"), ("f", "listing", "x.entries()"),
         ("f", "listing", "v.entries"), ("f", "getattr", "getattr(v, 'entries')"))),
    "list-tree-on-a-provable-view-is-still-a-listing": (
        _H + _TL + "def f(h: Held):\n    return list_tree(h.view(), depth=1)\n",
        (("f", "listing", "list_tree(h.view(), depth=1)"),)),
    # s7v3 A / B: a raw listing at any arity, and unbound.
    "raw-listings-at-any-arity-and-unbound": (
        _H + "def f(v: Bound):\n    v.entries(*())\n    type(v).entries(v)\n    g = type(v).entries\n"
        "    return g, Bound.entries\n",
        (("f", "listing", "v.entries(*())"), ("f", "listing", "type(v).entries(v)"),
         ("f", "listing", "type(v).entries"), ("f", "listing", "Bound.entries"))),
    "a-bound-has-no-walk-or-kind": (
        _H + "def f(v: Bound):\n    v.walk()\n    return v.is_dir()\n",
        (("f", "attr", "v.walk()"), ("f", "attr", "v.is_dir()"))),
}


@pytest.mark.parametrize("name", sorted(EVASIONS))
def test_an_evasion_is_a_hit(name: str):
    source, expect = EVASIONS[name]
    hits = {h.anchor for h in C.census_source(WORKTREE, FIXTURE_MODULE, source, tree=TREE)}
    for qualname, kind, text in expect:
        assert (FIXTURE_MODULE, qualname, kind, text) in hits, (name, sorted(hits))


_SOURCES = (
    "from defender.learning.leads import lead_neighbors\n"
    "from defender.learning.leads._lead_spine import lane_skills\n"
    "from defender.learning.author import shared\n")

PROVEN: dict[str, str] = {
    "exact-parameters": (
        _OPT + "def f(corpus: Held, view: Bound):\n    corpus.mkdir('.')\n    corpus.unlink('x')\n"
        "    view.read('x')\n    return list(iter_lessons(corpus.view())), list(iter_lessons(view))\n"),
    "string-annotation": (
        _OPT + "def f(corpus: 'Held'):\n    return list(iter_lessons(corpus.view()))\n"),
    "held-verb-as-callback": (
        "import functools\n" + _H + "def f(corpus: Held, name, run):\n"
        "    run(name, corpus.unlink, name)\n    run(functools.partial(corpus.write, mode='replace'))\n"),
    "trees-parameter-sources": (
        _SOURCES + _LT +
        "def f(trees: DrainTrees, paths, d, rows):\n    skills = lane_skills(trees, paths)\n"
        "    corpus = shared.lane_corpus(trees, d)\n"
        "    lead_neighbors.load_lane_catalog(skills.view(), where=d)\n"
        "    shared.build_curator_user_prompt(rows, 'b', corpus=corpus.view(), corpus_dir=d,"
        " corpus_dir_rel='x', label='l')\n"
        "    return shared.build_corpus_manifest(corpus.view(), where=d)\n"),
    "tree-for-unpack-subscript-and-view-at": (
        "from defender import _corpus, _scaffold_rules\n" + _LT +
        "from defender.learning.core.lane_trees import view_at\n"
        "def f(tree_for: TreeFor, p, w):\n    hit = tree_for(p)\n    if hit is None:\n        return None\n"
        "    held, name = hit\n    _scaffold_rules.check_system_skill(hit[0].view(), 's', hit[1])\n"
        "    return _corpus.read_query_template(view_at(held, '.'), name, where=w)\n"),
    "tree-for-direct-unpack-and-pinned": (
        "from defender._corpus import read_query_template\n"
        "def f(cfg, p, w):\n    tree, name = cfg.tree_for(p)\n"
        "    return read_query_template(tree.view(), name, where=w)\n"),
    "pinned-attributes": (
        "from defender._corpus import iter_lessons\nfrom defender.learning.leads import lead_neighbors\n"
        "from defender.learning.author.shared import build_curator_user_prompt\n"
        "class J:\n    def g(self):\n        return list(iter_lessons(self.cfg.corpus.view())), self.cfg.tree_for\n"
        "def f(cfg, deps, rows, d, h):\n    list(iter_lessons(cfg.corpus.view()))\n"
        "    h(tree_for=cfg.tree_for)\n    h(tree_for=deps.tree_for)\n"
        "    lead_neighbors.load_lane_catalog(deps.skills.view(), where=d)\n"
        "    return build_curator_user_prompt(rows, 'b', corpus=cfg.corpus.view(), corpus_dir=d,"
        " corpus_dir_rel='x', label='l')\n"),
    "tree-for-keywords-and-slots": (
        "import functools\nfrom defender.learning.core.lane_trees import kind_at\n" + _LT +
        "from defender.learning.leads.lead_author import _rules\n"
        "def f(trees: DrainTrees, tree_for: TreeFor, root, p, g):\n"
        "    g(tree_for=trees.tree_for)\n    kind_at(root, tree_for, p)\n"
        "    _rules._still_there(root, trees.tree_for, p)\n"
        "    return functools.partial(_rules._catalog_in_tree, root, tree_for)\n"),
    "optional-guard-return": (
        _OPT + "def f(t: Bound | None):\n    if t is None:\n        return []\n"
        "    return list(iter_lessons(t))\n"),
    "optional-guard-in-an-enclosing-block": (
        _OPT + "def f(t: Bound | None, c, ps):\n    if t is None:\n"
        "        raise ValueError('no handle')\n    if c:\n        for _p in ps:\n"
        "            try:\n                list(iter_lessons(t))\n            except OSError:\n"
        "                pass\n"),
    "optional-typing-optional": (
        _OPT + "from typing import Optional\ndef f(t: Optional[Bound], catalog=None):\n"
        "    if catalog is None:\n        if t is None:\n            raise TypeError\n"
        "        catalog = list(iter_lessons(t))\n    return catalog\n"),
    "optional-none-first-string": (
        _OPT + "def f(t: 'None | Bound'):\n    if t is None:\n        raise ValueError\n"
        "    return list(iter_lessons(t))\n"),
    "optional-guard-or-chain": (
        _OPT + "def f(t: Bound | None, w=None):\n    if t is None or w is None:\n"
        "        raise TypeError\n    return list(iter_lessons(t, where=w))\n"),
    "optional-else-branch": (
        _OPT + "def f(t: Bound | None):\n    if t is None:\n        out = []\n"
        "    else:\n        out = list(iter_lessons(t))\n    return out\n"),
    "optional-not-none-body": (
        _OPT + "def f(t: Bound | None, c):\n    if t is not None and c:\n"
        "        return list(iter_lessons(t))\n    return []\n"),
    "optional-held-and-trees": (
        _OPT + _LT + "def f(h: Held | None, trees: DrainTrees | None, g, p):\n"
        "    if h is None or trees is None:\n        raise TypeError\n"
        "    g(tree_for=trees.tree_for)\n    return list(iter_lessons(h.view()))\n"),
    "helper-returns-a-guarded-view": (
        _OPT + _LT + "from defender.learning.core.lane_trees import view_at\n"
        "def g(root, tree_for: TreeFor) -> tuple[Bound | None, Path]:\n"
        "    where = root / 'q'\n    hit = tree_for(where)\n    if hit is None:\n"
        "        return None, where\n    held, name = hit\n    return view_at(held, name), where\n"
        "def f(root, tree_for: TreeFor):\n    view, where = g(root, tree_for)\n"
        "    if view is None:\n        return []\n    return list(iter_lessons(view, where=where))\n"
        "def k(root, tree_for: TreeFor):\n    view, where = g(root, tree_for)\n"
        "    if view is None:\n        out = None\n    else:\n"
        "        out = list(iter_lessons(view, where=where))\n    return out\n"),
    "helper-returns-a-view": (
        _OPT + "def g(h: Held):\n    return h.view().under('x')\n"
        "def f(h: Held):\n    v = g(h)\n    return list(iter_lessons(v)), list(iter_lessons(g(h)))\n"),
    "look-alikes": (
        "import dataclasses\n" + _H + "from defender.learning.core.config import LoopPaths\n" + _LT +
        "from defender.runtime.agent_definition import bind\n"
        "def f(s, x, e, t: Held, paths: LoopPaths, v: Bound, trees: DrainTrees) -> LoopPaths:\n"
        "    isinstance(x, (Held, Bound, DrainTrees, LoopPaths, str))\n    dataclasses.replace(x, box=None)\n"
        "    getattr(e, 'write_guarded_alias', False)\n    dataclasses.replace(x, a=1)\n"
        "    bind(x, e)\n"
        "    import re\n    m = re.match('a', s)\n    m.group(1)\n    m.group()\n    type(e).__name__\n"
        "    return s.replace('.', '').replace('-', '')\n"),
    "type-alias-and-annotations": (
        "from collections.abc import Callable\nfrom pathlib import Path\nfrom typing import TypeAlias\n"
        + _H + "Pair: TypeAlias = Callable[[Path | str], tuple[Held, str] | None]\n"
        "def f(v: Bound) -> tuple[Bound | None, Path]:\n    x: Held | None = None\n    return v, Path()\n"),
    # v2 step 7, third pass: a tree slot's pass-through is judged where its def is called.
    "tree-slot-pass-through-and-its-caller": (
        "from pathlib import Path\nfrom defender import _corpus\n" + _H +
        "def g(t: Bound | Path, w: Path):\n"
        "    return list(_corpus.iter_lessons(t, where=w)), list(_corpus._lessons(t, w, str, None))\n"
        "def f(h: Held, w: Path):\n    return g(h.view(), w)\n"),
    "double-star-to-a-def-without-a-tree-for-slot": (
        "from defender._io import json_safe\ndef f(v, d):\n    return json_safe(v, **d)\n"),
    "getattr-and-attrgetter-look-alikes": (
        "import operator\nfrom defender import _io\n"
        "def f(x):\n    operator.attrgetter('name', 'parent.stem')(x)\n    return getattr(_io, 'ENTRY_FILE')\n"),
    "optional-handle-with-a-none-default": (
        _OPT + "def f(v: Bound | None = None):\n    if v is None:\n        return []\n"
        "    return list(iter_lessons(v))\n"),
    # v3: B2's kind helper and `view_at` over provable handles; listing records' fields.
    "b2-kind-and-view-at-on-provable-handles": (
        _H + _TL + _LT + "from defender.learning.core.lane_trees import view_at\n"
        "def f(h: Held, v: Bound, trees: DrainTrees, tree_for: TreeFor, d, n, p):\n"
        "    entry_kind(h.view(), n)\n    entry_kind(v.under('x'), n)\n"
        "    entry_kind(trees.mount(d).view(), n)\n    hit = tree_for(p)\n    if hit is None:\n"
        "        return None\n    held, name = hit\n    entry_kind(view_at(held, name), n)\n"
        "    return view_at(h, n), view_at(hit[0], '.')\n"),
    "listing-record-fields": (
        _H + "def f(rec, listing, v: Bound):\n    v.under('x')\n"
        "    return rec.entries, (listing.entries or {}).items(), listing.entries is None\n"),
}


@pytest.mark.parametrize("name", sorted(PROVEN))
def test_a_proven_handle_or_a_look_alike_is_not_a_hit(name: str):
    hits = C.census_source(WORKTREE, FIXTURE_MODULE, PROVEN[name], tree=TREE)
    assert not hits, "\n".join(h.show() for h in hits)


@pytest.mark.parametrize("opener", [
    "open_drain_trees(paths, AUTHOR_DRAIN_LABEL)", "DrainTrees.open(paths.drain_writable_trees(L))",
])
def test_a_with_opened_trees_chain_is_proven(opener: str):
    """`with <opener> as trees:` -> `trees.mount(...)` -> `.view().under(...)`: every link is
    proven (6, 2, 3), so the only hit is the opener's own `construct`."""
    source = (_OPT + _LT + "from defender.learning.core.config import AUTHOR_DRAIN_LABEL\n"
              f"def f(paths, d, L, g):\n    with {opener} as trees:\n"
              "        held = trees.mount(d)\n        view = held.view().under('gather/queries')\n"
              "        view.read('x.md')\n        held.unlink('x.md')\n"
              "        g(tree_for=trees.tree_for)\n"
              "        return list(iter_lessons(view)), list(iter_lessons(trees.mount(d).view()))\n")
    hits = C.census_source(WORKTREE, FIXTURE_MODULE, source, tree=TREE)
    assert [(h.kind, h.text) for h in hits] == [("construct", opener)]


def test_the_curator_engines_bind_is_not_io_bind():
    """`bind` in the curator engines is `runtime.agent_definition.bind` (an `AgentDeps` builder),
    not `_io.bind`: the census judges by origin, never by spelling, so those calls are no
    `construct` hit."""
    for module in ("learning/author/curator_engine.py", "learning/leads/lead_author_engine.py"):
        source = _source(module)
        scan = C.ModuleScan(TREE, module, ast.parse(source))
        binds = [c for c in ast.walk(scan.ast) if isinstance(c, ast.Call)
                 and isinstance(c.func, (ast.Name, ast.Attribute))
                 and ast.unparse(c.func).split(".")[-1] == "bind"]
        assert binds, f"{module} no longer calls a `bind`: the look-alike row is vacuous"
        assert {scan.callee(c) for c in binds} == {"defender.runtime.agent_definition.bind"}
        assert not [h for h in scan.scan() if h.kind == "construct"]


def test_the_census_tolerates_a_module_the_tree_lacks():
    """An older tree (no such module) still scans: the absent module is skipped, not raised."""
    assert C.census(WORKTREE, ["learning/core/_no_such_module.py"], tree=TREE) == []
