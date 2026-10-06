"""#1191 design amendment 2, O8 — every lint under `scripts/lint/` that lists source files does it
through `_astlib.source_files`, so all of them share O5: an excluded directory name applies only
BELOW the scanned root (never to its ancestors), git-ignored content is not source, and a new
uncommitted file still is.

(a) THE CENSUS. An AST census over `scripts/lint/*.py` (resolved through `_astlib`, so an aliased
    `os.walk` counts and `ast.walk` does not) finds no file walk outside `_astlib.py`: no
    `.rglob(...)`, no recursive `.glob(...)` (a `**` pattern, or one the census cannot read), no
    `os.walk` / `Path.walk`, no recursive `glob.glob` / `glob.iglob`, and no function that
    recurses through `.iterdir()`. A non-recursive `.glob("*.py")` is not a walk —
    `lint_run_records`' owner-package discovery is one, and the census does not flag it. The
    amendment's other non-obligations (`lint_stale_refs`: `grep`; `lint_vulture`: an external
    tool) are named in `NON_OBLIGATIONS`, so a new exemption is a visible edit here.
(b) BEHAVIOUR, SAMPLED. For five converted lints, each driven through the entry point it offers
    (`main(scope=...)`, `scan(root, ...)`, or a mini-repo copy run as CI runs it): a plant under a
    root whose ANCESTOR is named like one of that lint's excluded names (`.venv`) is still
    reported; in a git-repo fixture ignoring `build/`, an untracked, not-ignored plant is
    reported and the same plant under `build/` is not.

RED UNTIL IMPLEMENTED: the census (24 lints list their own files), and in (b) every case the
named lint gets wrong today — the ancestor case for the lints that match excluded names against
the absolute path, the ignored case for all five.
"""
from __future__ import annotations

import ast
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from defender.tests import test_1191_lint_scopes_fail_loud as T
from defender.tests._by_path import DEFENDER, LINT_DIR, import_lint_lib, load_lint_gate

#: Lints the amendment names as non-obligations — not file listings in its sense. Exempt from
#: the census by name; adding one is a deliberate edit.
NON_OBLIGATIONS: dict[str, str] = {
    "lint_stale_refs.py": "lists through `grep` with EXCLUDED_GREP_DIRS (amendment 2)",
    "lint_vulture.py": "an external tool with --exclude (amendment 2)",
}

#: The one module allowed to walk the tree: the shared listing itself.
LISTING_OWNER = "_astlib.py"


# ======================================================================================
# (a) The census
# ======================================================================================


def _call_walk(node: ast.Call, env: object) -> str | None:
    """The walk shape `node` is, or None. Resolved where it resolves (`os.walk`, `glob.glob`);
    a call on a value (`<path>.rglob`) has no origin and is matched by its method name."""
    astlib = import_lint_lib("_astlib")
    origin = astlib.callee(node, env)
    attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
    if origin == "os.walk":
        return "os.walk"
    if origin in ("glob.glob", "glob.iglob"):
        pattern = astlib.str_value(astlib.arg_at(node, 0, "pathname"), env)
        recursive = astlib.kw_is_true(node, "recursive") or pattern is None or "**" in pattern
        return f"{origin} (recursive)" if recursive else None
    if origin is not None:
        return None
    if attr in ("rglob", "walk"):
        return f"<path>.{attr}"
    if attr == "glob":
        pattern = astlib.str_value(astlib.arg_at(node, 0, "pattern"), env)
        return f"<path>.glob({pattern!r})" if pattern is None or "**" in pattern else None
    return None


def _recurses_through_iterdir(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """`fn` lists a directory and calls itself (or the method of its name): a hand-rolled walk."""
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
    lists = any(isinstance(c.func, ast.Attribute) and c.func.attr == "iterdir" for c in calls)
    recurses = any(
        (isinstance(c.func, ast.Name) and c.func.id == fn.name)
        or (isinstance(c.func, ast.Attribute) and c.func.attr == fn.name)
        for c in calls)
    return lists and recurses


def _walks(source: str, rel: str) -> list[str]:
    """Every file walk in `source`, as `rel:line: shape`."""
    astlib = import_lint_lib("_astlib")
    tree = ast.parse(source)
    env = astlib.module_env(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (shape := _call_walk(node, env)):
            found.append(f"{rel}:{node.lineno}: {shape}")
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _recurses_through_iterdir(node):
            found.append(f"{rel}:{node.lineno}: {node.name}() recurses through .iterdir()")
    return found


def _census(lint_dir: Path) -> list[str]:
    found: list[str] = []
    for path in sorted(lint_dir.glob("*.py")):
        if path.name == LISTING_OWNER or path.name in NON_OBLIGATIONS:
            continue
        found += _walks(path.read_text(encoding="utf-8"), path.name)
    return found


def test_o8_no_lint_lists_files_outside_the_shared_listing():
    """O8(a): no module under `scripts/lint/` other than `_astlib.py` walks the file tree — every
    lint lists its files through `_astlib.source_files` (the named non-obligations aside)."""
    walks = _census(LINT_DIR)
    assert not walks, (
        f"{len(walks)} file walk(s) outside _astlib.source_files — list through it instead:\n"
        + "\n".join(walks))


def test_o8_the_census_sees_every_walk_shape():
    """POSITIVE CONTROL for the census: each walk shape is seen — aliased and from-imported
    `os.walk`, `Path.walk`, `.rglob`, a `**` or unreadable `.glob` pattern, a recursive
    `glob.glob`, a function recursing through `.iterdir()` — and the shapes that are not walks
    are not (`ast.walk`, a non-recursive `.glob("*.py")`, a one-level `.iterdir()`)."""
    walks = [
        "import os as _o\ndef f(r):\n    return list(_o.walk(r))\n",
        "from os import walk\ndef f(r):\n    return list(walk(r))\n",
        "def f(p):\n    return list(p.walk())\n",
        "def f(p):\n    return sorted(p.rglob('*.py'))\n",
        "def f(p):\n    return sorted(p.glob('**/*.py'))\n",
        "def f(p, pat):\n    return sorted(p.glob(pat))\n",
        "import glob\ndef f():\n    return glob.glob('x/*.py', recursive=True)\n",
        "def f(p):\n    for c in p.iterdir():\n        if c.is_dir():\n            f(c)\n",
    ]
    for i, source in enumerate(walks):
        assert _walks(source, f"walk_{i}.py"), f"the census missed a walk:\n{source}"
    quiet = [
        "import ast\ndef f(t):\n    return list(ast.walk(t))\n",
        "def f(p):\n    return sorted(p.glob('*.py'))\n",
        "def f(p):\n    return [c for c in p.iterdir() if c.is_dir()]\n",
    ]
    for i, source in enumerate(quiet):
        assert not _walks(source, f"quiet_{i}.py"), f"the census flagged a non-walk:\n{source}"


def test_o8_the_census_sees_a_walk_planted_in_a_copied_lint(tmp_path):
    """POSITIVE CONTROL on real files: a copy of `scripts/lint/` with an `rglob` appended to one
    converted lint (`lint_stage_prompt_frames.py`, which lists through `source_files`) is
    reported by the census, at that file."""
    lint_dir = tmp_path / "lint"
    shutil.copytree(LINT_DIR, lint_dir, ignore=shutil.ignore_patterns("__pycache__"))
    target = lint_dir / "lint_stage_prompt_frames.py"
    before = [w for w in _census(lint_dir) if w.startswith(f"{target.name}:")]
    assert not before, f"precondition: {target.name} walks nothing today: {before}"
    with target.open("a", encoding="utf-8") as fh:
        fh.write("\n\ndef _planted_walk_1191(root):\n    return sorted(root.rglob('*.py'))\n")
    after = [w for w in _census(lint_dir) if w.startswith(f"{target.name}:")]
    assert after, "the census did not see an rglob planted in a copied lint"


# ======================================================================================
# (b) Behaviour, sampled: five converted lints
# ======================================================================================

#: A plant each sampled lint reports, keyed by lint.
RAW_YAML_PLANT = "import yaml\n\n\ndef load_1191(text):\n    return yaml.safe_load(text)\n"
JSONL_PLANT = ("import json\n\n\ndef read_1191(p):\n    for line in p.read_text().splitlines():\n"
               "        json.loads(line)\n")
MONKEYPATCH_PLANT = ("def test_planted_1191(monkeypatch):\n"
                     "    monkeypatch.setattr('os.sep', '/')\n")
RAW_GIT_PLANT = ("import subprocess\n\n\ndef status_1191():\n"
                 "    return subprocess.run(['git', 'status'], check=False)\n")


def _layout_plant() -> str:
    """An import of a gated run-layout name — taken from the real door's layout universe."""
    name = sorted(load_lint_gate("lint_run_layout_imports",
                                 name="lint_run_layout_imports_1191").layout_names(DEFENDER))[0]
    return f"from defender.run_repository import {name}\n"


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
        result = T._run(repo / "scripts" / "lint" / f"{stem}.py")
        return T._said(result)
    return run


def _layout_scan(repo: Path, defender_root: Path, capsys: pytest.CaptureFixture[str]) -> str:
    """`lint_run_layout_imports.scan(root, allow_list=[])` — its own root argument, the real
    allow-list left out (its entries name real modules a tmp tree does not hold)."""
    lint = load_lint_gate("lint_run_layout_imports", name="lint_run_layout_imports_1191_o8")
    found = lint.scan(defender_root, allow_list=[])
    return "\n".join(f.display for f in found)


#: lint -> (how to run it over a repo-shaped tmp tree, the plant it reports).
SAMPLES: dict[str, tuple[Callable[[Path, Path, pytest.CaptureFixture[str]], str],
                         Callable[[], str]]] = {
    "lint_raw_yaml": (_gate_in_process("lint_raw_yaml"), lambda: RAW_YAML_PLANT),
    "lint_unsafe_jsonl_io": (_gate_in_process("lint_unsafe_jsonl_io"), lambda: JSONL_PLANT),
    "lint_monkeypatch": (_gate_as_copy("lint_monkeypatch"), lambda: MONKEYPATCH_PLANT),
    "lint_raw_git_subprocess": (_gate_as_copy("lint_raw_git_subprocess"), lambda: RAW_GIT_PLANT),
    "lint_run_layout_imports": (_layout_scan, _layout_plant),
}


def _sample_repo(repo: Path, stem: str) -> Path:
    """`repo` laid out as a mini repo for `stem` (a copy of `scripts/lint/`, an inert
    `defender/`); for the run-layout lint, the real door's package too (its layout universe is
    read from the swept tree). Returns the `defender/` root."""
    T._mini_repo(repo, stem)
    root = repo / "defender"
    T._write(root / "pkg_1191" / "inert_1191.py")
    if stem == "lint_run_layout_imports":
        for src in sorted((DEFENDER / "run_repository").glob("*.py")):
            T._write(root / "run_repository" / src.name, src.read_text(encoding="utf-8"))
    return root


def _reported(report: str, rel: str) -> bool:
    return rel in report


@pytest.mark.parametrize("stem", sorted(SAMPLES))
def test_o8_a_plant_under_an_excluded_ancestor_is_still_reported(tmp_path, capsys, stem):
    """O8(b): the sampled lint over a repo whose ANCESTOR directory is named `.venv` (an excluded
    name of every one of them) still reports a plant — excluded names apply below the root only.
    Control: before the plant, nothing under that path is reported."""
    run, plant = SAMPLES[stem]
    repo = tmp_path / ".venv" / "repo"
    root = _sample_repo(repo, stem)
    rel = "pkg_1191/planted_1191.py"
    assert not _reported(run(repo, root, capsys), rel), "control: reported before the plant"
    T._write(root / rel, plant())
    report = run(repo, root, capsys)
    assert _reported(report, rel), (
        f"{stem}: with the repo under a dir named '.venv', the plant in {rel} was not "
        f"reported\n{report}")


@pytest.mark.parametrize("stem", sorted(SAMPLES))
def test_o8_gitignored_content_is_not_scanned_but_untracked_content_is(tmp_path, capsys, stem):
    """O8(b): in a git-repo fixture ignoring `build/` (its layout staged), the sampled lint
    reports an untracked, not-ignored plant, and does not report the same plant under `build/` —
    neither a top-level `defender/build/` nor one inside a package."""
    run, plant = SAMPLES[stem]
    repo = tmp_path / "repo"
    root = _sample_repo(repo, stem)
    T._git_repo(repo, "build/\n")
    new = T._write(root / "pkg_1191" / "new_1191.py", plant())
    report = run(repo, root, capsys)
    assert _reported(report, "pkg_1191/new_1191.py"), (
        f"{stem}: an untracked, not-ignored plant was not reported\n{report}")
    new.unlink()
    for rel in ("build/ignored_1191.py", "pkg_1191/build/ignored_1191.py"):
        T._write(root / rel, plant())
    report = run(repo, root, capsys)
    ignored = [r for r in ("build/ignored_1191.py", "pkg_1191/build/ignored_1191.py")
               if _reported(report, r)]
    assert not ignored, f"{stem}: gitignored plants were scanned: {ignored}\n{report}"
