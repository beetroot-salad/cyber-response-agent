"""#1191 design amendment 2, O8 — every lint under `scripts/lint/` that lists source files does it
through `_astlib.source_files`, so all of them share O5: an excluded directory name applies only
BELOW the scanned root (never to its ancestors), git-ignored content is not source, and a new
uncommitted file still is. And O9/O10 reach every one of them.

(a) THE CENSUS, both ways.
    POSITIVE: each of the amendment's 24 lints, and each of amendment 1's five scoped lints,
    calls `_astlib.source_files` — resolved through its imports, not by the call's spelling.
    NEGATIVE: an AST census over `scripts/lint/` (subdirectories included; resolved through
    `_astlib`, so an aliased `os.walk` counts and `ast.walk` does not) finds no file walk
    outside the top-level `_astlib.py`: no `os.walk` / `os.fwalk` / `Path.walk`, no `.rglob`
    (bound, unbound `Path.rglob(root, ...)`, or fetched by `getattr` / `methodcaller`), no glob
    that can cross a directory (`**`, a `/`, `recursive=True`, or a pattern the census cannot
    read), no directory listing (`iterdir` / `scandir` / `listdir`) inside a recursive function
    (direct, nested or mutual) or a loop that feeds it back into itself, and no `find` run as
    a program. A one-level `.glob("*.py")` is not a walk — `lint_run_records`' owner-package
    discovery is one. The amendment's other non-obligations (`lint_stale_refs`: `grep`;
    `lint_vulture`: an external tool) are named in `NON_OBLIGATIONS`.
(b) BEHAVIOUR, ALL 24, the way CI runs them (`python scripts/lint/<lint>.py` in a mini repo):
    a plant under a checkout nested in dirs carrying every excluded name (each holding a
    `pyvenv.cfg`) is reported; in a git fixture ignoring `zz_ign_1191/` and `*_ignored_1191.py`
    (names nothing could prune by spelling), an untracked plant is reported and ignored ones
    are not; a mode-000 dir (O9) or a module whose own or directory name is not UTF-8 (O10)
    blinds the gate — exit 2, named, no traceback on a strict-UTF-8 stdout — outside a repo
    and, untracked, inside one. Six lints also through their in-process doors
    (`main(scope=...)`, `scan(root, ...)`). `lint_unbounded_whole_read` (#1188, later) is held
    to all of it.
(c) DESIGN AMENDMENT 3 (what git would put in the tree), all lints as CI runs them, in a git
    repo: bad names or a mode-000 dir inside an IGNORED dir neither blind the gate nor show up —
    the plant elsewhere is still reported (O5 restated (a)); a tracked module deleted from the
    working tree is not scanned and changes nothing (O17); `lint_run_layout_imports --root
    <relative>` keeps an anchored ignore (O5 (c)); `lint_ci_hygiene` and `lint_raw_yaml` run
    ONE `git ls-files -z --cached --others --exclude-standard` in `defender/` and at most one
    `check-ignore` per run (O18), seen through a logging `git` first on PATH. What IS in the tree
    is scanned: tracked files git would ignore, names git would C-quote, a tracked dangling
    symlink (named, non-zero); a module under a mode-0644 dir is blind (the D17 correction:
    only a GONE path is dropped); with git missing or failing, the walk still finds the plant.
"""
from __future__ import annotations

import ast
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from defender import _git
from defender.tests import test_1191_lint_scopes_fail_loud as T
from defender.tests._by_path import DEFENDER, LINT_DIR, import_lint_lib, load_lint_gate
from defender.tests._repo import seed_repo

#: Lints the amendment names as non-obligations — not file listings in its sense. Exempt from
#: the census by their path under `scripts/lint/`; adding one is a deliberate edit.
NON_OBLIGATIONS: dict[str, str] = {
    "lint_stale_refs.py": "lists through `grep` with EXCLUDED_GREP_DIRS (amendment 2)",
    "lint_vulture.py": "an external tool with --exclude (amendment 2)",
}

#: The one module allowed to walk the tree: the shared listing itself (at the top of
#: `scripts/lint/`, not any module of that name below it).
LISTING_OWNER = "_astlib.py"

#: The 24 lints amendment 2's census names ("Corrected premise") as listing their own files.
CENSUS_24 = tuple(f"lint_{stem}" for stem in (
    "borrowed_vocabulary", "list_as_key_set", "duplicate_helpers", "hand_rolled_frontmatter",
    "raw_yaml", "ci_hygiene", "shared_oracle", "hand_rolled_name_resolution", "unpinned_text_io",
    "silent_row_drop", "run_layout_imports", "log_setup", "dataclass_fields", "raw_git_subprocess",
    "unowned_field", "unnarrowed_parse", "half_read_table", "monkeypatch", "shippable_surface",
    "ungated_artifact_write", "unsafe_jsonl_io", "unanchored_default", "unaccounted_selection",
    "unguarded_verb_dispatch",
))

#: Lints that came later and list through `source_files` too (#1188's whole-read gate): held to
#: every behaviour below like the 24.
LATER_LISTERS = ("lint_unbounded_whole_read",)
#: Every lint the behaviour checks cover.
LISTERS = CENSUS_24 + LATER_LISTERS

#: The five scoped lints of amendment 1, which already list through `source_files`.
SCOPED_5 = (T.TREE_READ, T.RUN_RECORDS, T.TREE_WRITE, T.STAGE_FRAMES, T.ENV_READS)

#: Calls that walk a tree, by their final name wherever they resolve — `os.walk`, `os.fwalk`,
#: `Path.walk`, `<path>.rglob`, `Path.rglob(root, ...)` — `ast.walk` (a node walk) aside.
WALK_NAMES = frozenset({"walk", "fwalk", "rglob"})
NOT_WALKS = frozenset({"ast.walk"})
GLOB_NAMES = frozenset({"glob", "iglob"})
#: Calls that list ONE directory: a walk when repeated — from a recursive function (direct,
#: nested or mutual) or a loop that feeds what it lists back into what it iterates.
LISTING_NAMES = frozenset({"iterdir", "scandir", "listdir"})


def _final(node: ast.Call, origin: str | None) -> str | None:
    """The called name: the last part of where it resolves, else a method's name. An unresolved
    bare name is the module's own function (a local AST `walk(...)`), whose body the census
    reads in its own right."""
    if origin is not None:
        return origin.rsplit(".", 1)[-1]
    return node.func.attr if isinstance(node.func, ast.Attribute) else None


def _glob_walk(node: ast.Call, origin: str | None, env: object) -> str | None:
    """A glob is a walk when it can cross a directory: `recursive=True`, a `**` or `/` in its
    pattern, or a pattern the census cannot read. `glob.glob`'s pattern is a whole path, so
    only `**` / `recursive` / unreadable count there."""
    astlib = import_lint_lib("_astlib")
    if origin in ("glob.glob", "glob.iglob"):
        pattern = astlib.str_value(astlib.arg_at(node, 0, "pathname"), env)
        recursive = astlib.kw_is_true(node, "recursive") or pattern is None or "**" in pattern
        return f"{origin}({pattern!r}, recursive)" if recursive else None
    unbound = origin is not None  # `Path.glob(root, pattern)`: the pattern is the 2nd argument
    pattern = astlib.str_value(astlib.arg_at(node, 1 if unbound else 0, "pattern"), env)
    if pattern is None or "**" in pattern or "/" in pattern:
        return f"{origin or '<path>.glob'}({pattern!r})"
    return None


#: Where a program-running call resolves to (`subprocess.run`, `os.popen`, `os.system`, ...).
SPAWNER_MODULES = ("subprocess.", "os.", "asyncio.create_subprocess")


def _spawns_find(node: ast.Call, env: object) -> bool:
    """`find` run as a program: a program-running call whose argv's first word is `find`, or
    whose command string starts with it."""
    astlib = import_lint_lib("_astlib")
    origin = astlib.callee(node, env)
    if origin is None or not origin.startswith(SPAWNER_MODULES):
        return False
    first = astlib.arg_at(node, 0, "args")
    if isinstance(first, ast.List | ast.Tuple) and first.elts:
        word = astlib.str_value(first.elts[0], env)
    else:
        command = astlib.str_value(first, env)
        word = command.split()[0] if command and command.split() else None
    return word is not None and word.rsplit("/", 1)[-1] == "find"


def _call_walk(node: ast.Call, env: object) -> str | None:
    """The walk shape `node` is, or None. Resolved where it resolves (`os.walk`, `glob.glob`,
    `pathlib.Path.rglob`); a call on a value (`<path>.rglob`) has no origin and is matched by its
    method name; `getattr(x, "rglob")` by the name it fetches."""
    astlib = import_lint_lib("_astlib")
    origin = astlib.callee(node, env)
    if origin in NOT_WALKS:
        return None
    if origin in ("builtins.getattr", "operator.methodcaller"):
        fetched = astlib.str_value(astlib.arg_at(node, 1 if origin == "builtins.getattr" else 0,
                                                 "name"), env)
        if fetched in WALK_NAMES | GLOB_NAMES:
            return f"{origin}(..., {fetched!r})"
    if _spawns_find(node, env):
        return f"{origin} running `find`"
    name = _final(node, origin)
    if name in WALK_NAMES:
        return origin or f"<path>.{name}"
    if name in GLOB_NAMES:
        return _glob_walk(node, origin, env)
    return None


def _lists_a_dir(node: ast.AST, env: object) -> bool:
    astlib = import_lint_lib("_astlib")
    return isinstance(node, ast.Call) and _final(node, astlib.callee(node, env)) in LISTING_NAMES


def _loop_walks(loop: ast.While | ast.For, env: object) -> bool:
    """A loop that lists a directory and is a walk: a `while` loop (a work stack), or a `for`
    over a name that the body grows (`dirs.append(...)` / `.extend(...)` / `+=`)."""
    if not any(_lists_a_dir(n, env) for n in ast.walk(loop)):
        return False
    if isinstance(loop, ast.While):
        return True
    if not isinstance(loop.iter, ast.Name):
        return False
    grown = loop.iter.id
    for n in ast.walk(loop):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("append", "extend", "insert", "appendleft")
                and isinstance(n.func.value, ast.Name) and n.func.value.id == grown):
            return True
        if (isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name)
                and n.target.id == grown):
            return True
    return False


def _recursive_listers(tree: ast.Module, env: object) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Functions that list a directory and sit on a call cycle of the module's own functions —
    direct, nested (`def go(d): ... go(c)`) or mutual (`f` -> `g` -> `f`). Calls are matched by
    name (`f(...)`, `self.f(...)`)."""
    fns = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    calls: dict[str, set[str]] = {}
    for fn in fns:
        names = calls.setdefault(fn.name, set())
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Name):
                    names.add(n.func.id)
                elif isinstance(n.func, ast.Attribute):
                    names.add(n.func.attr)

    def on_cycle(start: str) -> bool:
        seen: set[str] = set()
        todo = [c for c in calls.get(start, ()) if c in calls]
        while todo:
            name = todo.pop()
            if name == start:
                return True
            if name not in seen:
                seen.add(name)
                todo += [c for c in calls[name] if c in calls]
        return False

    return [fn for fn in fns
            if any(_lists_a_dir(n, env) for n in ast.walk(fn)) and on_cycle(fn.name)]


def _walks(source: str, rel: str) -> list[str]:
    """Every file walk in `source`, as `rel:line: shape`."""
    astlib = import_lint_lib("_astlib")
    tree = ast.parse(source)
    env = astlib.module_env(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (shape := _call_walk(node, env)):
            found.append(f"{rel}:{node.lineno}: {shape}")
        elif isinstance(node, ast.While | ast.For) and _loop_walks(node, env):
            found.append(f"{rel}:{node.lineno}: a loop feeding a directory listing back into itself")
    found += [f"{rel}:{fn.lineno}: {fn.name}() lists a directory and recurses"
              for fn in _recursive_listers(tree, env)]
    return found


def _census(lint_dir: Path) -> list[str]:
    """Every walk in every module under `lint_dir`, subdirectories included (caches aside)."""
    found: list[str] = []
    for path in sorted(lint_dir.rglob("*.py")):
        rel = path.relative_to(lint_dir).as_posix()
        if "__pycache__" in path.parts or rel == LISTING_OWNER or rel in NON_OBLIGATIONS:
            continue
        found += _walks(path.read_text(encoding="utf-8"), rel)
    return found


def _calls_source_files(source: str) -> bool:
    """`source` calls `_astlib.source_files` — resolved through its imports (`from _astlib
    import source_files [as x]`, `import _astlib`, the package-relative `._astlib`), not by the
    spelling of the call."""
    astlib = import_lint_lib("_astlib")
    tree = ast.parse(source)
    env = astlib.module_env(tree)
    origins = (astlib.callee(n, env) for n in ast.walk(tree) if isinstance(n, ast.Call))
    return any(o is not None and o.split(".")[-2:] == ["_astlib", "source_files"] for o in origins)


@pytest.mark.parametrize("stem", LISTERS + SCOPED_5)
def test_o8_every_listing_lint_calls_the_shared_listing(stem):
    """O8 (positive census): each of the amendment's 24 lints (and the later
    `lint_unbounded_whole_read`), and each of amendment 1's five scoped lints, calls
    `_astlib.source_files` — the walk census below only forbids the shapes
    it knows; this one requires the shared listing itself."""
    source = (LINT_DIR / f"{stem}.py").read_text(encoding="utf-8")
    assert _calls_source_files(source), f"{stem} never calls _astlib.source_files"


def test_o8_the_positive_census_resolves_the_call():
    """POSITIVE CONTROL for the positive census: an imported, aliased, module-qualified or
    package-relative `source_files` counts; a local function that merely shares the name, or
    another module's `source_files`, does not."""
    counted = [
        "from _astlib import source_files\nsource_files(r, ())\n",
        "from _astlib import source_files as listing\nlisting(r, ())\n",
        "import _astlib\n_astlib.source_files(r, ())\n",
        "try:\n    from ._astlib import source_files\nexcept ImportError:\n"
        "    from _astlib import source_files\nsource_files(r, ())\n",
    ]
    for source in counted:
        assert _calls_source_files(source), f"the positive census missed:\n{source}"
    not_counted = [
        "def source_files(r, e):\n    return sorted(r.rglob('*.py'))\nsource_files(r, ())\n",
        "from _other_1191 import source_files\nsource_files(r, ())\n",
        "import _astlib\n_astlib.read_and_parse(r, 'x')\n",
    ]
    for source in not_counted:
        assert not _calls_source_files(source), f"the positive census counted:\n{source}"


def test_o8_no_lint_lists_files_outside_the_shared_listing():
    """O8(a): no module under `scripts/lint/` (subdirectories included) other than its
    `_astlib.py` walks the file tree — every lint lists its files through
    `_astlib.source_files` (the named non-obligations aside)."""
    walks = _census(LINT_DIR)
    assert not walks, (
        f"{len(walks)} file walk(s) outside _astlib.source_files — list through it instead:\n"
        + "\n".join(walks))


#: Walk shapes the census must see — each an evasion of a narrower census.
WALK_SHAPES = {
    "aliased os.walk": "import os as _o\ndef f(r):\n    return list(_o.walk(r))\n",
    "from-imported os.walk": "from os import walk\ndef f(r):\n    return list(walk(r))\n",
    "os.fwalk": "import os\ndef f(r):\n    return list(os.fwalk(r))\n",
    "Path.walk": "def f(p):\n    return list(p.walk())\n",
    "unbound Path.walk": "from pathlib import Path\ndef f(r):\n    return list(Path.walk(r))\n",
    ".rglob": "def f(p):\n    return sorted(p.rglob('*.py'))\n",
    "Path(x).rglob": "from pathlib import Path\ndef f(r):\n    return sorted(Path(r).rglob('*.py'))\n",
    "unbound Path.rglob": "from pathlib import Path\ndef f(r):\n    return Path.rglob(r, '*.py')\n",
    "lambda rglob": "f = lambda p: sorted(p.rglob('*.py'))\n",
    "getattr rglob": "def f(p):\n    return getattr(p, 'rglob')('*.py')\n",
    "methodcaller rglob": ("import operator\ndef f(p):\n"
                           "    return operator.methodcaller('rglob', '*.py')(p)\n"),
    "** glob": "def f(p):\n    return sorted(p.glob('**/*.py'))\n",
    "multi-level glob": "def f(p):\n    return sorted(p.glob('*/*.py'))\n",
    "unreadable glob": "def f(p, pat):\n    return sorted(p.glob(pat))\n",
    "glob per level": ("def f(root):\n    out = []\n    for pat in ('*.py', '*/*.py'):\n"
                       "        out += root.glob(pat)\n    return out\n"),
    "unbound Path.glob **": ("from pathlib import Path\ndef f(r):\n"
                             "    return list(Path.glob(r, '**/*.py'))\n"),
    "recursive glob.glob": "import glob\ndef f():\n    return glob.glob('x/*.py', recursive=True)\n",
    "aliased iglob **": "from glob import iglob as ig\ndef f(r):\n    return list(ig('x/**/*.py'))\n",
    "iterdir recursion": "def f(p):\n    for c in p.iterdir():\n        if c.is_dir():\n            f(c)\n",
    "nested-def recursion": ("def f(root):\n    def go(d):\n        for c in d.iterdir():\n"
                             "            if c.is_dir():\n                go(c)\n    go(root)\n"),
    "mutual recursion": ("def f(d):\n    for c in d.iterdir():\n        g(c)\n"
                         "def g(c):\n    if c.is_dir():\n        f(c)\n"),
    "method recursion": ("class W:\n    def f(self, d):\n        for c in d.iterdir():\n"
                         "            self.f(c)\n"),
    "scandir recursion": ("import os\ndef f(d):\n    for e in os.scandir(d):\n"
                          "        if e.is_dir():\n            yield from f(e.path)\n"),
    "listdir recursion": ("import os\ndef f(d):\n    for n in os.listdir(d):\n"
                          "        f(os.path.join(d, n))\n"),
    "work stack over iterdir": ("def f(root):\n    stack = [root]\n    while stack:\n"
                                "        d = stack.pop()\n        for c in d.iterdir():\n"
                                "            stack.append(c)\n"),
    "growing list over scandir": ("import os\ndef f(root):\n    dirs = [root]\n"
                                  "    for d in dirs:\n        dirs.extend(os.scandir(d))\n"),
    "find argv": ("import subprocess\ndef f(r):\n"
                  "    return subprocess.run(['find', r, '-name', '*.py'], check=False)\n"),
    "find command string": "import os\ndef f():\n    return os.popen('find . -name *.py').read()\n",
}

#: Shapes that are not walks — the census must stay quiet on them.
NON_WALK_SHAPES = {
    "ast.walk": "import ast\ndef f(t):\n    return list(ast.walk(t))\n",
    "one-level glob": "def f(p):\n    return sorted(p.glob('*.py'))\n",
    "one-level iterdir": "def f(p):\n    return [c for c in p.iterdir() if c.is_dir()]\n",
    "one-level iterdir in a for": "def f(ps):\n    for p in ps:\n        list(p.iterdir())\n",
    "a str.find": "def f(s):\n    return s.find('find ')\n",
    "a local AST walker named walk": ("import ast\ndef f(tree):\n    def walk(node):\n"
                                      "        for c in ast.iter_child_nodes(node):\n"
                                      "            walk(c)\n    walk(tree)\n"),
}


@pytest.mark.parametrize("shape", sorted(WALK_SHAPES))
def test_o8_the_census_sees_every_walk_shape(shape):
    """POSITIVE CONTROL for the census: each walk shape is seen, wherever it resolves."""
    assert _walks(WALK_SHAPES[shape], "walk.py"), f"the census missed {shape}"


@pytest.mark.parametrize("shape", sorted(NON_WALK_SHAPES))
def test_o8_the_census_ignores_what_is_not_a_walk(shape):
    """NEGATIVE CONTROL for the census: `ast.walk`, one-level listings and an unrelated
    `.find` are not walks."""
    assert not _walks(NON_WALK_SHAPES[shape], "quiet.py"), f"the census flagged {shape}"


def test_o8_the_census_sees_a_walk_planted_in_a_copied_lint(tmp_path):
    """POSITIVE CONTROL on real files: a copy of `scripts/lint/` with an `rglob` appended to one
    converted lint (`lint_stage_prompt_frames.py`, which lists through `source_files`) is
    reported by the census at that file; so is one in a module in a SUBDIRECTORY of the copy,
    and one in a nested module that happens to be named `_astlib.py`."""
    lint_dir = tmp_path / "lint"
    shutil.copytree(LINT_DIR, lint_dir, ignore=shutil.ignore_patterns("__pycache__"))
    walk = "\n\ndef _planted_walk_1191(root):\n    return sorted(root.rglob('*.py'))\n"
    target = lint_dir / "lint_stage_prompt_frames.py"
    before = [w for w in _census(lint_dir) if w.startswith(f"{target.name}:")]
    assert not before, f"precondition: {target.name} walks nothing today: {before}"
    with target.open("a", encoding="utf-8") as fh:
        fh.write(walk)
    T._write(lint_dir / "sub_1191" / "helper_1191.py", walk)
    T._write(lint_dir / "sub_1191" / LISTING_OWNER, walk)
    found = _census(lint_dir)
    for rel in (target.name, "sub_1191/helper_1191.py", f"sub_1191/{LISTING_OWNER}"):
        assert any(w.startswith(f"{rel}:") for w in found), f"the census missed the walk in {rel}"


# ======================================================================================
# (b) Behaviour: every listing lint as CI runs it, and five through their in-process doors
# ======================================================================================

#: The violating file's path under a lint's scanned root; the report names it (root- or
#: repo-relative, so this suffix is in it either way).
PLANT_REL = "pkg_1191/planted_1191.py"

#: The git-ignore rules of the git fixture — names no lint could prune by spelling.
IGNORES = T.IGNORES
#: Plants git ignores under those rules, by path under the scanned root, and what of each a
#: report would spell.
IGNORED_PLANTS = ("zz_ign_1191/top_1191.py", "pkg_1191/zz_ign_1191/deep_1191.py",
                  "pkg_1191/deep_ignored_1191.py")
IGNORED_MARKERS = ("zz_ign_1191", "_ignored_1191")

#: The excluded names an ancestor of the checkout carries in the ancestor case — the
#: amendment's (".venv", "__pycache__", "node_modules", "runs"), "tests", and each lint's own
#: EXCLUDED_DIRS on top (see `_ancestors`).
ANCESTOR_NAMES = (".venv", "__pycache__", "node_modules", "runs", "tests")

RAW_YAML_PLANT = "import yaml\n\n\ndef load_1191(text):\n    return yaml.safe_load(text)\n"
JSONL_PLANT = ("import json\n\n\ndef read_1191(p):\n    for line in p.read_text().splitlines():\n"
               "        json.loads(line)\n")
MONKEYPATCH_PLANT = ("def test_planted_1191(monkeypatch):\n"
                     "    monkeypatch.setattr('os.sep', '/')\n")
RAW_GIT_PLANT = ("import subprocess\n\n\ndef status_1191():\n"
                 "    return subprocess.run(['git', 'status'], check=False)\n")
UNPINNED_PLANT = "def read_1191(p):\n    return p.read_text()\n"


def _layout_plant() -> str:
    """An import of a gated run-layout name — taken from the real door's layout universe."""
    name = sorted(load_lint_gate("lint_run_layout_imports",
                                 name="lint_run_layout_imports_1191").layout_names(DEFENDER))[0]
    return f"from defender.run_repository import {name}\n"


def _real_door() -> dict[str, str]:
    """The run-layout lint reads its layout universe from the swept tree: the real door's
    modules, copied."""
    return {f"defender/run_repository/{src.name}": src.read_text(encoding="utf-8")
            for src in sorted((DEFENDER / "run_repository").glob("*.py"))}


@dataclass(frozen=True)
class Plant:
    """A file each listing lint reports at `<under>/PLANT_REL` of a mini repo, and the files
    (repo-relative) the mini repo needs beside it: the lint's other scan roots, or the other
    half of a finding (a duplicate's first definer, a vocabulary's owner, a test oracle)."""

    text: str | Callable[[], str]
    under: str = "defender"
    support: Callable[[], dict[str, str]] = dict
    committed: bool = False

    def source(self) -> str:
        return self.text() if callable(self.text) else self.text


PLANTS: dict[str, Plant] = {
    "lint_borrowed_vocabulary": Plant(
        "from pkg_1191.owner_1191 import VOCAB_1191\n\n\n"
        "def check_1191(value_1191):\n    return value_1191 in VOCAB_1191\n",
        support=lambda: {"defender/pkg_1191/owner_1191.py":
                         'VOCAB_1191 = ("a", "b")\n\n\ndef is_member_1191(value_1191):\n'
                         "    return value_1191 in VOCAB_1191\n"}),
    "lint_list_as_key_set": Plant(
        "def patch_1191(build_1191, order_1191):\n    table_1191 = build_1191(order_1191)\n"
        "    for key_1191 in order_1191:\n        table_1191[key_1191] += 1\n"
        "    return table_1191\n"),
    "lint_duplicate_helpers": Plant(
        "def helper_1191():\n    return 1\n",
        support=lambda: {"defender/pkg_1191/other_1191.py": "def helper_1191():\n    return 1\n"}),
    "lint_raw_yaml": Plant(RAW_YAML_PLANT),
    "lint_ci_hygiene": Plant('HOME_1191 = "/workspace/defender"\n'),
    "lint_shared_oracle": Plant(
        "import subprocess\n\n\ndef list_1191():\n"
        '    return subprocess.run(["git", "ls-files", "-z"], check=True)\n',
        support=lambda: {"defender/tests/test_oracle_1191.py":
                         "import subprocess\n\n\ndef test_oracle_1191():\n"
                         '    subprocess.run(["git", "ls-files", "-z"], check=True)\n'}),
    "lint_hand_rolled_name_resolution": Plant(
        "import ast\n\n\ndef is_run_1191(path_1191, node_1191):\n"
        "    ast.parse(path_1191.read_text())\n"
        '    return node_1191.func.id == "run_1191"\n'),
    "lint_unpinned_text_io": Plant(
        UNPINNED_PLANT, support=lambda: {"spec-flow/scripts/inert_1191.py": T.INERT}),
    "lint_run_layout_imports": Plant(_layout_plant, support=_real_door),
    "lint_log_setup": Plant(
        'def main_1191():\n    return 0\n\n\nif __name__ == "__main__":\n    main_1191()\n'),
    "lint_dataclass_fields": Plant(
        "def fields_1191(obj):\n    return type(obj).__dataclass_fields__\n"),
    "lint_raw_git_subprocess": Plant(RAW_GIT_PLANT),
    "lint_unowned_field": Plant('def produce_1191():\n    """@owns"""\n'),
    "lint_unnarrowed_parse": Plant(
        "import json\n\n\ndef parse_1191(text: str) -> dict[str, int]:\n"
        "    return json.loads(text)\n"),
    "lint_monkeypatch": Plant(MONKEYPATCH_PLANT),
    "lint_ungated_artifact_write": Plant(
        'def write_1191(d):\n    (d / "report.md").write_text("x", encoding="utf-8")\n'),
    "lint_unsafe_jsonl_io": Plant(JSONL_PLANT),
    "lint_unanchored_default": Plant(
        "FALLBACK_1191 = 3\n\n\ndef pick_1191(x=None):\n"
        "    x = x if x is not None else FALLBACK_1191\n    return x\n"),
    "lint_silent_row_drop": Plant(
        "from blocks_1191 import Block\n\n\ndef tokenize_1191(rows_1191) -> list[Block]:\n"
        "    for row_1191 in rows_1191:\n        continue\n",
        under="defender/skills/invlang",
        support=lambda: {"defender/skills/invlang/keep_1191.txt": ""}),
    "lint_half_read_table": Plant(
        "from pkg_1191 import owner_1191\n\n\ndef check_1191(key_1191):\n"
        '    return key_1191 == "alpha_1191"\n',
        support=lambda: {"defender/pkg_1191/owner_1191.py":
                         'TABLE_1191 = {"alpha_1191": len, "beta_1191": len}\n\n\n'
                         "def lookup_1191(key_1191):\n    return TABLE_1191.get(key_1191)\n"}),
    "lint_unguarded_verb_dispatch": Plant(
        "def dispatch_1191(registry_1191, verb_1191):\n"
        '    return registry_1191.verbs("system_1191")[verb_1191]\n'),
    # Resolves its systems from the working tree's adapters dir AND `HEAD:defender/skills`, so
    # its mini repo is a committed git repo.
    "lint_shippable_surface": Plant(
        'VENDOR_1191 = "wazuh"\n', committed=True,
        support=lambda: {"defender/scripts/adapters/keep_1191.txt": "",
                         "defender/skills/keep_1191.txt": ""}),
    "lint_unaccounted_selection": Plant("from parser_1191 import INVLANG_FENCE_RE\n"),
    "lint_hand_rolled_frontmatter": Plant(
        'def split_1191(text_1191):\n    return text_1191.split("---")\n'),
    "lint_unbounded_whole_read": Plant("def read_1191(p):\n    return p.read_text()\n"),
}


def test_every_census_lint_has_a_plant():
    """The behaviour below covers ALL of the amendment's 24 lints (and the later listers), not
    a sample."""
    assert sorted(PLANTS) == sorted(LISTERS)


def _ci_repo(repo: Path, stem: str, *, ignores: str | None = None) -> Path:
    """`repo` laid out as a mini repo for `stem` (a copy of `scripts/lint/`, an inert
    `defender/pkg_1191/`, the plant's support files) — made a git repo with `ignores` as its
    `.gitignore` and the layout staged when `ignores` is given, and committed when the plant
    needs a HEAD. Returns the lint's scanned root there."""
    T._mini_repo(repo, stem)
    T._write(repo / "defender" / "pkg_1191" / "inert_1191.py")
    plant = PLANTS[stem]
    for rel, text in plant.support().items():
        T._write(repo / rel, text)
    if plant.committed:
        T._write(repo / ".gitignore", ignores or "")
        seed_repo(repo)
    elif ignores is not None:
        T._git_repo(repo, ignores)
    return repo / plant.under


def _as_ci_runs_it(repo: Path, stem: str, **env: str) -> subprocess.CompletedProcess[str]:
    return T._run(repo / "scripts" / "lint" / f"{stem}.py", env_extra=env or None)


def _assert_reported(result: subprocess.CompletedProcess[str], why: str) -> None:
    """The run reported the plant: a new finding (exit 1) naming PLANT_REL."""
    said = T._said(result)
    assert result.returncode == 1, f"{why}\n{said}"
    assert PLANT_REL in result.stdout + result.stderr, f"{why}\n{said}"


def _ancestors(stem: str) -> list[str]:
    """Every name an ancestor of the checkout carries in the ancestor case: ANCESTOR_NAMES and
    the lint's own excluded directory names."""
    own = getattr(T._fresh(stem, "_names"), "EXCLUDED_DIRS", ())
    return sorted({*ANCESTOR_NAMES, *(n for n in own if "/" not in n)})


@pytest.mark.parametrize("stem", LISTERS)
def test_o8_each_listing_lint_as_ci_runs_it_scans_under_excluded_ancestors(tmp_path, stem):
    """O8(b), all 24, through the entry point CI uses (`python scripts/lint/<lint>.py`): a
    checkout nested under directories carrying every excluded name — each holding a
    `pyvenv.cfg`, so a venv rule by marker file cannot prune it either — still reports the
    plant (exit 1, named): excluded names apply below the scanned root only."""
    names = _ancestors(stem)
    parent = tmp_path.joinpath(*names)
    for depth in range(1, len(names) + 1):
        T._write(tmp_path.joinpath(*names[:depth]) / "pyvenv.cfg", "home = /nowhere_1191\n")
    repo = parent / "repo"
    root = _ci_repo(repo, stem)
    T._write(root / PLANT_REL, PLANTS[stem].source())
    _assert_reported(_as_ci_runs_it(repo, stem),
                     f"{stem}: under ancestors {names}, the plant {PLANT_REL} was not reported")


@pytest.mark.parametrize("stem", LISTERS)
def test_o8_each_listing_lint_as_ci_runs_it_skips_ignored_content_not_untracked(tmp_path, stem):
    """O8(b), all 24, as CI runs them, in a git-repo fixture ignoring `zz_ign_1191/` and
    `*_ignored_1191.py`: an untracked, not-ignored plant is reported (exit 1, named); the same
    plant where git ignores it — a top-level and a nested ignored dir, an ignored file name — is
    not."""
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    new = T._write(root / PLANT_REL, PLANTS[stem].source())
    _assert_reported(_as_ci_runs_it(repo, stem),
                     f"{stem}: an untracked, not-ignored plant was not reported")
    new.unlink()
    for rel in IGNORED_PLANTS:
        T._write(root / rel, PLANTS[stem].source())
    result = _as_ci_runs_it(repo, stem)
    scanned = [m for m in IGNORED_MARKERS if m in result.stdout + result.stderr]
    assert not scanned, f"{stem}: git-ignored plants were scanned ({scanned})\n{T._said(result)}"


#: An undecodable name, as a module and as a directory, and its escaped spelling.
UNDECODABLE = {
    "file": (b"bad\xff_1191.py", "bad\\udcff_1191.py"),
    "dir": (b"bad\xffdir_1191/m_1191.py", "bad\\udcffdir_1191"),
}


#: The mini repo outside git (the walk), or a git repo where the item is untracked and not
#: ignored (amendment 3's git path lists it).
WHERE_LISTED = {"walk": None, "git": IGNORES}


@pytest.mark.parametrize("listing", sorted(WHERE_LISTED))
@pytest.mark.parametrize("where", sorted(UNDECODABLE))
@pytest.mark.parametrize("stem", LISTERS)
def test_o10_each_listing_lint_as_ci_runs_it_is_blind_on_an_undecodable_name(tmp_path, stem,
                                                                              where, listing):
    """O10, all 24, as CI runs them on a strict-UTF-8 stdout: a module whose name — its own or
    its directory's — is not valid UTF-8 makes the gate blind (exit 2, the name escaped on
    stderr), with no traceback — outside a repo, and in a git repo where it is untracked and
    not ignored (amendment 3 (b))."""
    raw, escaped = UNDECODABLE[where]
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=WHERE_LISTED[listing])
    try:
        T._write(root / "pkg_1191" / os.fsdecode(raw), PLANTS[stem].source())
    except (OSError, UnicodeError) as refused:
        pytest.skip(f"this filesystem refuses an undecodable name: {refused!r}")
    result = _as_ci_runs_it(repo, stem, PYTHONIOENCODING="utf-8:strict")
    assert "Traceback" not in result.stderr, f"{stem}: crashed\n{T._said(result)}"
    T._expect(result, 2, escaped, on="stderr",
              why=f"{stem}: an undecodable {where} name did not blind the scan, escaped")


@pytest.mark.parametrize("listing", sorted(WHERE_LISTED))
@pytest.mark.parametrize("stem", LISTERS)
def test_o9_each_listing_lint_as_ci_runs_it_is_blind_on_an_unreadable_directory(tmp_path, stem,
                                                                                 listing):
    """O9, all 24, as CI runs them: a mode-000 directory under the scanned root — outside a
    repo, or untracked and not ignored in a git repo — makes the gate blind (exit 2 naming it).
    Skipped where the mode is not enforced (root with the DAC capabilities)."""
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=WHERE_LISTED[listing])
    locked = T._locked_dir(root / "pkg_1191" / "locked_1191")
    try:
        result = _as_ci_runs_it(repo, stem)
    finally:
        locked.chmod(0o755)
    T._expect(result, 2, "locked_1191", on="stderr",
              why=f"{stem}: an unreadable directory did not blind the scan")


# --- amendment 3: what git would put in the tree ---------------------------------------


def _quiet_about(result: subprocess.CompletedProcess[str], *markers: str) -> list[str]:
    return [m for m in markers if m in result.stdout + result.stderr]


@pytest.mark.parametrize("stem", LISTERS)
def test_o5_each_listing_lint_as_ci_runs_it_never_enters_an_ignored_dir_of_bad_names(tmp_path,
                                                                                     stem):
    """O5 restated (a), all lints as CI runs them, in a git repo: non-UTF-8 names that git
    ignores — a module and a directory inside ignored `zz_ign_1191/` dirs (top-level and in a
    package), and an ignored file name that is not UTF-8 — neither blind the gate nor show up:
    the plant elsewhere is still reported (exit 1, named), with no traceback on a strict-UTF-8
    stdout."""
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    text = PLANTS[stem].source()
    try:
        for ignored in ("zz_ign_1191", "pkg_1191/zz_ign_1191"):
            T._write(root / ignored / os.fsdecode(b"bad\xff_1191.py"), text)
            T._write(root / ignored / os.fsdecode(b"bad\xffdir_1191") / "m_1191.py", text)
        T._write(root / "pkg_1191" / os.fsdecode(b"bad\xff_ignored_1191.py"), text)
    except (OSError, UnicodeError) as refused:
        pytest.skip(f"this filesystem refuses an undecodable name: {refused!r}")
    T._write(root / PLANT_REL, text)
    result = _as_ci_runs_it(repo, stem, PYTHONIOENCODING="utf-8:strict")
    assert "Traceback" not in result.stderr, f"{stem}: crashed\n{T._said(result)}"
    _assert_reported(result, f"{stem}: ignored bad names blinded the gate or hid the plant")
    shown = _quiet_about(result, "udcff", *IGNORED_MARKERS)
    assert not shown, f"{stem}: ignored content showed up ({shown})\n{T._said(result)}"


@pytest.mark.parametrize("stem", LISTERS)
def test_o5_each_listing_lint_as_ci_runs_it_never_enters_an_ignored_unreadable_dir(tmp_path,
                                                                                   stem):
    """O5 restated (a), all lints as CI runs them, in a git repo: a mode-000 directory inside an
    ignored `zz_ign_1191/` does not blind the gate — the plant elsewhere is still reported
    (exit 1, named) and the locked dir is not mentioned. Skipped where the mode is not enforced
    (root with the DAC capabilities)."""
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    T._write(root / PLANT_REL, PLANTS[stem].source())
    locked = T._locked_dir(root / "zz_ign_1191" / "locked_1191")
    try:
        result = _as_ci_runs_it(repo, stem)
    finally:
        locked.chmod(0o755)
    _assert_reported(result, f"{stem}: an ignored unreadable dir blinded the gate or hid the plant")
    assert not _quiet_about(result, "locked_1191"), f"{stem}: mentions the ignored dir\n{T._said(result)}"


@pytest.mark.parametrize("stem", LISTERS)
def test_o17_each_listing_lint_as_ci_runs_it_skips_a_deleted_tracked_module(tmp_path, stem):
    """O17, all lints as CI runs them: a tracked module (staged with the layout) deleted from the
    working tree is not scanned and does not blind the gate — the run exits as the untouched
    repo does (0 clean; the run-layout lint's mini repo carries its stale allow-list), never 2,
    and never names the gone file."""
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    clean = _as_ci_runs_it(repo, stem)
    assert clean.returncode != 2, f"control: {stem}'s untouched git mini repo\n{T._said(clean)}"
    gone = T._write(root / "pkg_1191" / "gone_1191.py", PLANTS[stem].source())
    _git.git(["add", "-A"], cwd=repo)
    gone.unlink()
    result = _as_ci_runs_it(repo, stem)
    assert result.returncode == clean.returncode, (
        f"{stem}: a deleted tracked module changed the outcome\n{T._said(result)}")
    assert not _quiet_about(result, "gone_1191"), f"{stem}: names the gone file\n{T._said(result)}"


@pytest.mark.parametrize("spelled", ["defender", "./defender", "defender/pkg_1191/.."])
def test_o5_run_layout_imports_from_a_relative_root_keeps_anchored_ignores(tmp_path, spelled):
    """O5 restated (c): `lint_run_layout_imports --root <relative defender/>`, run from its
    repo's top, keeps an ANCHORED ignore (`/defender/zz_ign_1191/`): a plant there is not
    reported. Control: the same plant where git does not ignore it is (exit 1, named)."""
    stem = "lint_run_layout_imports"
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores="/defender/zz_ign_1191/\n")
    lint_file = repo / "scripts" / "lint" / f"{stem}.py"
    kept = T._write(root / PLANT_REL, PLANTS[stem].source())
    _assert_reported(T._run(lint_file, "--root", spelled),
                     f"control: --root {spelled}: a plant not ignored was not reported")
    kept.unlink()
    T._write(root / "zz_ign_1191" / "planted_1191.py", PLANTS[stem].source())
    result = T._run(lint_file, "--root", spelled)
    assert not _quiet_about(result, "zz_ign_1191"), (
        f"--root {spelled}: a plant under the anchored ignore was scanned\n{T._said(result)}")


#: A `git` on PATH that logs each invocation (cwd, then each argument, \x1f-separated) to
#: $GIT_LOG_1191 and runs the real git: an env/PATH seam, nothing patched in-process.
_GIT_SHIM = """#!/bin/sh
{{ printf '%s' "$(pwd -P)"; for a in "$@"; do printf '\\037%s' "$a"; done; printf '\\n'; }} >> "$GIT_LOG_1191"
exec {real} "$@"
"""


def _git_calls(log: Path) -> list[tuple[Path, list[str]]]:
    """(the directory git ran in after any `-C`, its arguments from the subcommand on)."""
    calls: list[tuple[Path, list[str]]] = []
    for line in log.read_text(encoding="utf-8").splitlines() if log.exists() else []:
        cwd, *args = line.split("\x1f")
        where, i = Path(cwd), 0
        while i < len(args) and args[i].startswith("-"):
            if args[i] == "-C" and i + 1 < len(args):
                where = where / args[i + 1]
            i += 2 if args[i] in ("-C", "-c") else 1
        calls.append((where.resolve(), args[i:]))
    return calls


def _shimmed_git(tmp_path: Path) -> tuple[dict[str, str], Path]:
    """The env putting the logging `git` first on PATH, and its log."""
    real = shutil.which("git")
    assert real, "git is not on PATH"
    shim = T._write(tmp_path / "shim" / "git", _GIT_SHIM.format(real=real))
    shim.chmod(0o755)
    log = tmp_path / "git_1191.log"
    return ({"PATH": f"{shim.parent}{os.pathsep}{os.environ.get('PATH', '')}",
             "GIT_LOG_1191": str(log)}, log)


def test_the_git_shim_logs_what_runs_through_it(tmp_path):
    """CONTROL for the shim: a `git ls-files -z` run through it is logged, with where it ran."""
    env, log = _shimmed_git(tmp_path)
    repo = tmp_path / "repo"
    T._write(repo / "defender" / "kept.py")
    T._git_repo(repo, IGNORES)
    subprocess.run(["git", "-C", "defender", "ls-files", "-z"], cwd=repo,  # noqa: S607 — the shim under test
                   env={**os.environ, **env}, capture_output=True, check=True, timeout=60)
    assert _git_calls(log) == [((repo / "defender").resolve(), ["ls-files", "-z"])]


@pytest.mark.parametrize("stem", ["lint_ci_hygiene", "lint_raw_yaml"])
def test_o18_a_lint_run_makes_one_full_listing_of_its_root(tmp_path, stem):
    """O18/D17 ("each lint makes one `git ls-files` call, plus one `check-ignore` on the root";
    `lint_ci_hygiene` "lists defender/ once per run"): through the logging `git` first on PATH,
    a run over a git mini repo with nested untracked packages makes exactly ONE `git ls-files`,
    in `defender/`, asking for `-z --cached --others --exclude-standard`, and at most one
    `check-ignore` — no per-directory or per-file git traffic standing in for a walk."""
    env, log = _shimmed_git(tmp_path)
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    for i in range(5):
        T._write(root / f"d{i}_1191" / f"e{i}_1191" / f"m{i}_1191.py")
    result = _as_ci_runs_it(repo, stem, **env)
    assert result.returncode == 0, f"control: the clean git mini repo\n{T._said(result)}"
    calls = _git_calls(log)
    listings = [(where, args) for where, args in calls if args[:1] == ["ls-files"]]
    assert len(listings) == 1, f"{stem}: {len(listings)} `git ls-files` runs (want one): {calls}"
    where, args = listings[0]
    assert where == root.resolve(), f"{stem}: ls-files ran in {where}, not {root}"
    wanted = {"-z", "--cached", "--others", "--exclude-standard"}
    assert wanted <= set(args), f"{stem}: ls-files asked for {args}, not {sorted(wanted)}"
    checks = [args for _w, args in calls if args[:1] == ["check-ignore"]]
    assert len(checks) <= 1, f"{stem}: {len(checks)} `git check-ignore` runs: {checks}"


# --- amendment 3, the adversary's holes: what IS in the tree, and git failing ----------


def test_o5_ci_hygiene_never_reads_an_ignored_top_level_json(tmp_path):
    """O5 restated (nothing inside an ignored tree is source) for `lint_ci_hygiene`'s top-level
    `.json` listing: an IGNORED, unparseable `defender/x_ignored_1191.json` is never read — the
    gate stays clean (exit 0)."""
    stem = "lint_ci_hygiene"
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES + "*_ignored_1191.json\n")
    T._write(root / "x_ignored_1191.json", "{ not json")
    result = _as_ci_runs_it(repo, stem)
    assert result.returncode == 0, f"an ignored top-level json was read\n{T._said(result)}"


#: Tracked files git would otherwise ignore: under an ignored dir, or by an ignored name.
FORCED = {"dir": "zz_ign_1191/forced_1191.py", "name": "pkg_1191/forced_ignored_1191.py"}


@pytest.mark.parametrize("forced", sorted(FORCED))
@pytest.mark.parametrize("stem", LISTERS)
def test_o5_each_listing_lint_as_ci_runs_it_scans_tracked_files_git_would_ignore(tmp_path, stem,
                                                                                forced):
    """O5 restated ("tracked files plus untracked files that are not ignored"), all lints as CI
    runs them: a plant force-added (`git add -f`) where git would ignore it — under an ignored
    dir, or under an ignored name — is TRACKED, so scanned and reported (exit 1, named)."""
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    rel = FORCED[forced]
    plant = T._write(root / rel, PLANTS[stem].source())
    _git.git(["add", "-f", str(plant.relative_to(repo))], cwd=repo)
    result = _as_ci_runs_it(repo, stem)
    said = T._said(result)
    assert result.returncode == 1, f"{stem}: tracked {rel} was not scanned\n{said}"
    assert rel in result.stdout + result.stderr, f"{stem}: tracked {rel} not named\n{said}"


#: How git can let the listing down: not on PATH at all, or failing every call (exit 128).
NO_GIT = {"missing": None, "failing": "#!/bin/sh\necho 'fatal: broken_1191' >&2\nexit 128\n"}


@pytest.mark.parametrize("how", sorted(NO_GIT))
@pytest.mark.parametrize("stem", [s for s in LISTERS if not PLANTS[s].committed])
def test_d17_each_listing_lint_as_ci_runs_it_walks_when_git_lets_it_down(tmp_path, stem, how):
    """D17 step 3 ("git is unavailable or fails" → the walk), all lints as CI runs them, inside
    a git repo: with no `git` on PATH, or a `git` that exits 128, the plant is still reported
    (exit 1, named) — never an empty listing. (shippable_surface resolves its systems through
    git itself, so it has no git-less run to check.)"""
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    T._write(root / PLANT_REL, PLANTS[stem].source())
    bin_dir = tmp_path / "bin_1191"
    bin_dir.mkdir()
    path = str(bin_dir)
    if NO_GIT[how] is not None:
        T._write(bin_dir / "git", NO_GIT[how]).chmod(0o755)
        path = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"
    _assert_reported(_as_ci_runs_it(repo, stem, PATH=path),
                     f"{stem}: with git {how}, the plant was not scanned")


#: A plant name git C-quotes without `-z` (a `"`, a backslash, a tab), still valid UTF-8.
QUOTED_PLANT = 'pkg_1191/q"uo\\te\tab_1191.py'


@pytest.mark.parametrize("case", ["tracked", "untracked"])
@pytest.mark.parametrize("stem", LISTERS)
def test_o5_each_listing_lint_as_ci_runs_it_reports_a_plant_git_would_quote(tmp_path, stem,
                                                                            case):
    """O5 restated, all lints as CI runs them, in a git repo: a plant whose name git would
    C-quote is in the tree, tracked or untracked, so reported (exit 1, named as it is)."""
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    T._write(root / QUOTED_PLANT, PLANTS[stem].source())
    if case == "tracked":
        _git.git(["add", "-A"], cwd=repo)
    result = _as_ci_runs_it(repo, stem)
    said = T._said(result)
    assert result.returncode == 1, f"{stem}: the {case} quoted-name plant was not scanned\n{said}"
    assert QUOTED_PLANT in result.stdout + result.stderr, f"{stem}: not named as it is\n{said}"


@pytest.mark.parametrize("stem", LISTERS)
def test_d17_each_listing_lint_as_ci_runs_it_names_a_tracked_dangling_module(tmp_path, stem):
    """D17 (as corrected: only a GONE path is dropped), all lints as CI runs them: a tracked
    dangling symlink module is listed, and the gate that cannot read it says so — a non-zero
    exit naming it, never a silent skip."""
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    (root / "pkg_1191").mkdir(parents=True, exist_ok=True)
    os.symlink("nowhere_1191.py", root / "pkg_1191" / "dangling_1191.py")
    _git.git(["add", "-A"], cwd=repo)
    result = _as_ci_runs_it(repo, stem)
    said = T._said(result)
    assert result.returncode != 0, f"{stem}: a dangling tracked module was skipped\n{said}"
    assert "dangling_1191" in result.stdout + result.stderr, f"{stem}: not named\n{said}"


@pytest.mark.parametrize("case", ["tracked", "untracked"])
@pytest.mark.parametrize("stem", LISTERS)
def test_o9_each_listing_lint_as_ci_runs_it_is_blind_on_a_module_it_cannot_stat(tmp_path, stem,
                                                                                case):
    """O9 + the D17 correction, all lints as CI runs them, in a git repo: a module under a
    mode-0644 dir (names readable, entries not statable) — git lists it with no warning — makes
    the gate blind (exit 2 naming it), tracked or untracked. Skipped where the mode is not
    enforced (root with the DAC capabilities)."""
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    T._write(root / "pkg_1191" / "rd_1191" / "m_1191.py", PLANTS[stem].source())
    if case == "tracked":
        _git.git(["add", "-A"], cwd=repo)
    rd = T._unsearchable_dir(root / "pkg_1191" / "rd_1191")
    try:
        result = _as_ci_runs_it(repo, stem)
    finally:
        rd.chmod(0o755)
    T._expect(result, 2, "rd_1191", on="stderr",
              why=f"{stem}: a {case} module it cannot stat did not blind the gate")


def test_o5_run_layout_imports_prunes_nested_venv_and_hidden_dirs_in_a_git_repo(tmp_path):
    """D17 step 4 (`prune` on either path), as CI runs `lint_run_layout_imports` in a git repo:
    plants in a nested venv (`pyvenv.cfg`) and a nested hidden dir, untracked and not ignored,
    are not reported. Control: the plant beside them is (exit 1, named)."""
    stem = "lint_run_layout_imports"
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    text = PLANTS[stem].source()
    T._write(root / "pkg_1191" / "site_env" / "pyvenv.cfg", "home = /usr/bin\n")
    T._write(root / "pkg_1191" / "site_env" / "lib" / "venv_1191.py", text)
    T._write(root / "pkg_1191" / ".hidden_1191" / "hid_1191.py", text)
    T._write(root / PLANT_REL, text)
    result = _as_ci_runs_it(repo, stem)
    _assert_reported(result, "control: the plant beside the pruned dirs was not reported")
    shown = _quiet_about(result, "venv_1191", "hid_1191")
    assert not shown, f"pruned dirs were scanned on the git path: {shown}\n{T._said(result)}"


# --- five lints through their in-process doors -------------------------------------------


def _gate_in_process(stem: str) -> Callable[[Path, Path, pytest.CaptureFixture[str]], str]:
    """A lint with `main(argv, scope=, baseline_path=)`: its report over `defender_root`."""
    def run(repo: Path, defender_root: Path, capsys: pytest.CaptureFixture[str]) -> str:
        lint = load_lint_gate(stem, name=f"{stem}_1191_o8")
        rc = lint.main([], scope=defender_root, baseline_path=repo / "baseline_1191.json")
        captured = capsys.readouterr()
        return f"rc={rc}\n{captured.out}\n{captured.err}"
    return run


def _gate_as_copy(stem: str) -> Callable[[Path, Path, pytest.CaptureFixture[str]], str]:
    """A lint with no root argument: its mini-repo copy run as CI runs it."""
    def run(repo: Path, defender_root: Path, capsys: pytest.CaptureFixture[str]) -> str:
        return T._said(_as_ci_runs_it(repo, stem))
    return run


def _layout_scan(repo: Path, defender_root: Path, capsys: pytest.CaptureFixture[str]) -> str:
    """`lint_run_layout_imports.scan(root, allow_list=[])` — its own root argument, the real
    allow-list left out (its entries name real modules a tmp tree does not hold)."""
    lint = load_lint_gate("lint_run_layout_imports", name="lint_run_layout_imports_1191_o8")
    found = lint.scan(defender_root, allow_list=[])
    return "\n".join(f.display for f in found)


#: lint -> how to run it over a repo-shaped tmp tree through the door it offers.
SAMPLES: dict[str, Callable[[Path, Path, pytest.CaptureFixture[str]], str]] = {
    "lint_raw_yaml": _gate_in_process("lint_raw_yaml"),
    "lint_unsafe_jsonl_io": _gate_in_process("lint_unsafe_jsonl_io"),
    "lint_unpinned_text_io": _gate_in_process("lint_unpinned_text_io"),
    "lint_monkeypatch": _gate_as_copy("lint_monkeypatch"),
    "lint_raw_git_subprocess": _gate_as_copy("lint_raw_git_subprocess"),
    "lint_run_layout_imports": _layout_scan,
}


@pytest.mark.parametrize("stem", sorted(SAMPLES))
def test_o8_a_plant_under_an_excluded_ancestor_is_still_reported(tmp_path, capsys, stem):
    """O8(b) through each sampled lint's own door: over a repo whose ANCESTOR directory is named
    `.venv` (an excluded name of every one of them) it still reports a plant — excluded names
    apply below the root only. Control: before the plant, nothing under that path is
    reported."""
    run = SAMPLES[stem]
    repo = tmp_path / ".venv" / "repo"
    root = _ci_repo(repo, stem)
    assert PLANT_REL not in run(repo, root, capsys), "control: reported before the plant"
    T._write(root / PLANT_REL, PLANTS[stem].source())
    report = run(repo, root, capsys)
    assert PLANT_REL in report, (
        f"{stem}: with the repo under a dir named '.venv', the plant in {PLANT_REL} was not "
        f"reported\n{report}")


@pytest.mark.parametrize("stem", sorted(SAMPLES))
def test_o8_gitignored_content_is_not_scanned_but_untracked_content_is(tmp_path, capsys, stem):
    """O8(b) through each sampled lint's own door, in a git-repo fixture ignoring
    `zz_ign_1191/` and `*_ignored_1191.py` (its layout staged): an untracked, not-ignored plant
    is reported, and the same plant where git ignores it is not."""
    run = SAMPLES[stem]
    repo = tmp_path / "repo"
    root = _ci_repo(repo, stem, ignores=IGNORES)
    new = T._write(root / PLANT_REL, PLANTS[stem].source())
    report = run(repo, root, capsys)
    assert PLANT_REL in report, f"{stem}: an untracked, not-ignored plant was not reported\n{report}"
    new.unlink()
    for rel in IGNORED_PLANTS:
        T._write(root / rel, PLANTS[stem].source())
    report = run(repo, root, capsys)
    scanned = [m for m in IGNORED_MARKERS if m in report]
    assert not scanned, f"{stem}: gitignored plants were scanned ({scanned})\n{report}"
