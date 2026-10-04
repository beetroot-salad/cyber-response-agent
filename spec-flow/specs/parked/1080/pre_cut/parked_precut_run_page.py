# PRE-CUT COPY 2026-10-04 (scope cut of #1080, human-decided; 94-reconciliation-cut.md F-2): preserved, NOT collected.
# This is defender/tests/scripts_1080_split/test_1080_run_page.py as it stood before the cut, copied verbatim
# from the cut author's scratch backup; the only additions are these `#` comment lines. It keeps
# the cells the cut removed from KEPT tests: the OUT halves of narrowed tests, and the tables and
# helpers the cut narrowed or deleted. Each such node carries a `# PRE-CUT …` marker naming the
# issue(s) that own its cut cells; an owner adopts those cells when its module moves. Nodes without
# a marker are unchanged in the live suite, or were parked whole (their canonical copy is
# ../parked_run_page.py, annotated with their owners). The file name does not match test_*.py, so pytest never
# collects it. It imports the LIVE helper modules; their pre-cut versions are
# parked_precut__spec1080.py and parked_precut__census1080.py beside this file (_pointers1080.py did
# not change). The goldens it reads are split between the suite's goldens/ and ../goldens/. Each
# narrowed kept demand's `parked_cells` block in spec-flow/specs/spec_graph_1080-scripts-split.yaml
# points at its pre-cut function here.
"""#1080 — the run page's renderer, its mirror and its consumers after the move (group `runpage`).

The run-page renderer (`visualize_run`: `render_page`, `publish_page`, `mirror_page`,
`mirror_root`, `MirrorRootRefused`, `_MIRROR_WRITER`, `MIRROR_DIR_ENV`, `RUNTIME_JS`), its
stdlib-only mirror writer (`_mirror_write.write_page`, spawned `[sys.executable, "-I", <path>,
dest]` as the mirror folder's owner), its failure type (`_page_failed.VisualizeFailed`) and the
assets beside them land under `defender/reports/` (M-F (a)). Every moved name is reached at CALL
time through the `_spec1080` locator (`S.home_of(..., home=S.REPORTS)`); nothing here imports a
new home at module level, and nothing imports an old `defender.scripts.*` path to compute an
expected value. "As today" values are the BASE's, frozen in `goldens/runpage.json` (its `_meta`
says how) and compared through `_scrub`, the one normalisation both the capture and the tests
use.

The tests here drive no runtime replay; the ones that need a real run dir are in
`test_1080_run_page_e2e.py`, which imports the private helpers below.

THE SHADOW CHECKOUT (`_shadow_checkout`). The mirror root's default is anchored on where the
renderer's own file sits, so the only way to watch the default resolve in a layout other than
this checkout — a main checkout, a linked worktree whose pointer is broken, an unpacked tree with
no `.git` — is to run the renderer FROM such a layout. A shadow is a temp folder holding a copy
of this tree's `defender/` (its large non-code folders linked), so every copied module's
`__file__` — and every value derived from it — sits in the shadow. (`defender` is a namespace
package and several modules put their own checkout root first on `sys.path` at import, so a
shadow of LINKS would hand the import system back to this tree.) A child started in the shadow
with only the shadow on its `PYTHONPATH` and `PYTEST_CURRENT_TEST` scrubbed then imports the
moved renderer from there. The same shadow is where a fault is planted in a copy (a missing
asset, a missing writer), never in the real tree.
"""
from __future__ import annotations

import ast
import contextlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _import_blocker
from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "runpage"
MIRROR_ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"
DEPLOYMENT_ENV = "DEFENDER_DEPLOYMENT"
MIRROR_NAME = "run-visualizations"
PAGE_NAME = "runtime.html"
#: The page and run id the mirror children copy: no render, so no run dir is needed.
CHILD_PAGE = "<html><body>PAGE-1080-RUNPAGE</body></html>"
CHILD_RUN_ID = "r-1080"


# ======================================================================================
# The moved names, reached at call time
# ======================================================================================


def _renderer():
    """The moved run-page renderer module (it defines `publish_page`), under `defender/reports/`."""
    return S.moved_module("publish_page", home=S.REPORTS)


def _renderer_dotted() -> str:
    return S.dotted(S.home_of("publish_page", home=S.REPORTS))


def _writer_path() -> Path:
    """The moved mirror writer's file (the module that defines `write_page`)."""
    return S.REPO_ROOT / S.home_of("write_page", home=S.REPORTS)


def _visualize_failed() -> type[BaseException]:
    return S.moved("VisualizeFailed", home=S.REPORTS)


def _golden(key: str) -> Any:
    data = S.golden(GOLDEN)
    assert key in data, f"goldens/{GOLDEN}.json has no entry {key!r}"
    return data[key]


# ======================================================================================
# The one normalisation (capture and tests both go through it)
# ======================================================================================


def _scrub(value: Any, subs: dict[str, str]) -> Any:
    """`value` (JSON-shaped) with every occurrence of each real path in `subs` replaced by its
    tag (`<TMP>`, `<RUN_DIR>`, ...), longest path first so a nested path is not half-replaced.
    One JSON round trip, so a path inside any string at any depth is caught."""
    text = json.dumps(value, ensure_ascii=False)
    for real, tag in sorted(subs.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(json.dumps(real, ensure_ascii=False)[1:-1], tag)
    return json.loads(text)


def _assert_golden(key: str, observed: Any) -> None:
    """`observed` equals the base's value for `key` in `goldens/runpage.json`."""
    expected = _golden(key)
    assert observed == expected, (
        f"{key}: the moved code's behaviour differs from the base's golden\n"
        f"observed: {json.dumps(observed, ensure_ascii=False, indent=1)[:4000]}\n"
        f"golden:   {json.dumps(expected, ensure_ascii=False, indent=1)[:4000]}")


def _assert_golden_page(name: str, page: str) -> None:
    """`page` (already normalised) equals the base's page frozen as `goldens/runpage/<name>`,
    compared as exact text (bytes decoded, no newline translation)."""
    path = S.GOLDENS / GOLDEN / name
    assert path.is_file(), f"golden page {name} is missing from the suite"
    expected = path.read_bytes().decode("utf-8")
    if page != expected:
        at = next((i for i, (a, b) in enumerate(zip(page, expected, strict=False)) if a != b),
                  min(len(page), len(expected)))
        raise AssertionError(
            f"{name}: the page differs from the base's at char {at} of {len(expected)}:\n"
            f"observed: {page[max(0, at - 200):at + 200]!r}\n"
            f"golden:   {expected[max(0, at - 200):at + 200]!r}")


# ======================================================================================
# The shadow checkout
# ======================================================================================


def _renderer_folder() -> str:
    """The smallest repo-relative folder holding everything the page modules read from their
    own location: the renderer, the mirror writer, the failure type, the episode page and the
    asset files — where a shadow's copy of one of them is looked up to plant a fault."""
    homes = [S.home_of(n, home=S.REPORTS)
             for n in ("publish_page", "write_page", "VisualizeFailed", "ASSETS", "EPISODE_CSS")]
    dirs = [str(Path(h).parent) for h in homes]
    assets = S.moved("ASSETS", home=S.REPORTS)
    dirs.append(S.rel(Path(assets)))
    return os.path.commonpath(dirs)


#: Folders of `defender/` a shadow LINKS instead of copying: large, and nothing a shadow child
#: imports. Virtualenvs and tool caches are left out altogether; bytecode caches are copied
#: (with their sources' times), so a child does not recompile the tree — Python never imports
#: a cached module whose source is gone, so a file removed from the copy stays removed.
_SHADOW_LINKED = frozenset({"tests", "evals", "docs", "fixtures-e2e"})
_SHADOW_SKIPPED = (".venv", "node_modules", ".mypy_cache", ".ruff_cache", ".pytest_cache")


def _shadow_checkout(root: Path) -> Path:
    """`root` made into a checkout of this tree's code: `root/defender/` is a COPY of this
    checkout's `defender/` (the large folders no child imports are links), so every module's
    `__file__` — and each value derived from it, a mirror default, an asset folder, the
    `sys.path` entry a module's bootstrap inserts — sits in the shadow, never back in this tree.
    Answers `root`."""
    dst = root / "defender"
    dst.mkdir(parents=True)
    for entry in sorted(S.DEFENDER.iterdir()):
        if entry.name in _SHADOW_SKIPPED:
            continue
        if entry.name in _SHADOW_LINKED:
            (dst / entry.name).symlink_to(entry)
        elif entry.is_dir() and not entry.is_symlink():
            shutil.copytree(entry, dst / entry.name, symlinks=True,
                            ignore=shutil.ignore_patterns(*_SHADOW_SKIPPED))
        else:
            shutil.copy2(entry, dst / entry.name, follow_symlinks=False)
    return root


def _shadow_env(root: Path, **extra: str) -> dict[str, str]:
    """A child environment that imports `defender` from the shadow at `root` only: no
    `PYTEST_CURRENT_TEST`, no mirror override unless `extra` sets one."""
    return S.child_env(pythonpath=False, PYTHONPATH=str(root), **extra)


#: Run in a child from a checkout: import the renderer named by argv[1], resolve the mirror root
#: with no start, hand `CHILD_PAGE` to the dev-only copy, and report the root, what the copy said,
#: and every WARNING-or-worse line (the resolver's fallback notice is one).
_MIRROR_CHILD = r'''
import importlib, json, logging, sys
from pathlib import Path
seen = []
class _Rec(logging.Handler):
    def emit(self, r):
        seen.append([r.levelname, r.getMessage()])
logging.getLogger().addHandler(_Rec())
logging.getLogger().setLevel(logging.DEBUG)
vr = importlib.import_module(sys.argv[1])
out = {"module_file": str(Path(vr.__file__).resolve())}
try:
    out["root"] = str(vr.mirror_root())
except Exception as e:
    out["root"] = {"raises": type(e).__name__, "message": str(e)}
if sys.argv[2] == "publish":
    out["publish"] = vr.mirror_page(sys.argv[3], sys.argv[4])
out["warnings"] = [m for lvl, m in seen if lvl in ("WARNING", "ERROR", "CRITICAL")]
print(json.dumps(out))
'''


def _default_from(checkout: Path, *, tmp: Path, publish: bool = True) -> dict[str, Any]:
    """The renderer's mirror default as a child started FROM `checkout` sees it — no override,
    no `PYTEST_CURRENT_TEST`, deployment `dev` — and, with `publish`, what the copy did and
    which `runtime.html` files exist under `tmp` afterwards. Paths are scrubbed to `<TMP>`."""
    child = S.python("-c", _MIRROR_CHILD, _renderer_dotted(),
                     "publish" if publish else "resolve", CHILD_PAGE, CHILD_RUN_ID,
                     cwd=checkout, env=_shadow_env(checkout, **{DEPLOYMENT_ENV: "dev"}))
    assert child.returncode == 0, (
        f"the mirror child failed from {checkout}: {child.stderr.decode(errors='replace')[-2000:]}")
    out = json.loads(child.stdout.decode().strip().splitlines()[-1])
    module_file = Path(out.pop("module_file"))
    assert module_file.is_relative_to(checkout), (
        f"precondition: the child imported the renderer from {module_file}, not from the "
        f"checkout {checkout} it was started in")
    if publish:
        out["landed"] = sorted(S.rel(p, tmp) for p in tmp.rglob(PAGE_NAME))
        out["landed_bytes_are_the_page"] = all(
            p.read_text(encoding="utf-8") == CHILD_PAGE for p in tmp.rglob(PAGE_NAME))
    return _scrub(out, {str(tmp): "<TMP>"})


def _git_layout_main(main: Path, *, shadow: bool) -> Path:
    """A main checkout: a `.git/` folder and a `defender/` (the shadow's, or an empty one)."""
    if shadow:
        _shadow_checkout(main)
    else:
        (main / "defender").mkdir(parents=True)
    (main / ".git").mkdir()
    return main


def _git_layout_worktree(main: Path, wt: Path, *, name: str = "wt") -> Path:
    """`wt` (a shadow) as a linked worktree of `main`, exactly the chain `git worktree add`
    leaves: `wt/.git` names `<main>/.git/worktrees/<name>`, whose `commondir` is `../..`.
    Answers the admin folder."""
    admin = main / ".git" / "worktrees" / name
    admin.mkdir(parents=True)
    (admin / "commondir").write_text("../..\n", encoding="utf-8")
    (admin / "gitdir").write_text(f"{wt / '.git'}\n", encoding="utf-8")
    (admin / "HEAD").write_text("ref: refs/heads/wt\n", encoding="utf-8")
    _shadow_checkout(wt)
    (wt / ".git").write_text(f"gitdir: {admin}\n", encoding="utf-8")
    return admin


def _main_checkout_by_git() -> Path:
    """This tree's main checkout, from git itself (independent of the resolver under test)."""
    got = S.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"])
    assert got.returncode == 0, f"git could not name this tree's common dir: {got.stderr!r}"
    return Path(got.stdout.decode().strip()).parent


# ======================================================================================
# Small shared observers
# ======================================================================================


def _stdlib_only_writer_run(writer: Path, dest: Path, page: bytes) -> subprocess.CompletedProcess:
    """`writer` run as the renderer spawns it — `-I`, by path, page bytes on stdin, `dest` in
    argv — under an interpreter whose import system refuses every non-stdlib top-level module
    (`_import_blocker`'s `allow_only=()`, `find_spec` only)."""
    body = ("import runpy, sys\n"
            "sys.argv = sys.argv[1:]\n"
            "runpy.run_path(sys.argv[0], run_name='__main__')\n")
    prelude = _import_blocker.blocker_source(allow_only=())
    return subprocess.run(  # noqa: S603 — this interpreter, the blocker, the writer file
        [sys.executable, "-I", "-c", prelude + body, str(writer), str(dest)],
        input=page, capture_output=True, check=False, cwd="/", timeout=120,
        env=S.child_env(pythonpath=False))


def _with_import(source: str, line: str) -> str:
    """`source` with `line` added as the first statement after its `from __future__` imports
    (which must stay first), or at the top when it has none."""
    lines = source.splitlines(keepends=True)
    at = max((i + 1 for i, ln in enumerate(lines) if ln.startswith("from __future__")), default=0)
    return "".join(lines[:at] + [line + "\n"] + lines[at:])


def _module_level_import_tops(path: Path) -> list[str]:
    """The top-level module of every import statement in the file (relative ones as `.`)."""
    tree = ast.parse(path.read_bytes(), filename=str(path))
    tops: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            tops += [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            tops.append("." if node.level else (node.module or "").split(".")[0])
    return sorted(set(tops))


# ======================================================================================
# Tree helpers for a folder the writer's uid owns (shared with the e2e file)
# ======================================================================================


def _non_root_ids() -> tuple[int, int]:
    import pwd

    try:
        pw = pwd.getpwnam("nobody")
    except KeyError:
        return 65534, 65534
    return pw.pw_uid, pw.pw_gid


@contextlib.contextmanager
def _writer_tree() -> Iterator[tuple[Path, Path, int, int]]:
    """`(base, checkout, uid, gid)`: a temp folder holding `checkout`, the mirror's parent,
    owned by the uid the copy is WRITTEN as — a non-root uid when this process is root (so the
    renderer drops to it, the #1084 lane; the folder is then under /tmp, which that uid can
    traverse, unlike pytest's 0700 tmp), else this process's own uid (the in-process lane).
    Everything is removed afterwards, read-only folders included."""
    root = os.geteuid() == 0
    uid, gid = _non_root_ids() if root else (os.geteuid(), os.getegid())
    base = Path(tempfile.mkdtemp(prefix="spec1080-runpage-", dir="/tmp" if root else None))
    try:
        os.chmod(base, 0o755)
        checkout = base / "checkout"
        checkout.mkdir()
        os.chmod(checkout, 0o755)
        if root:
            os.chown(checkout, uid, gid)
        yield base, checkout, uid, gid
    finally:
        for here, dirs, _files in os.walk(base):
            for d in dirs:
                with contextlib.suppress(OSError):
                    os.chmod(Path(here) / d, 0o755)
        shutil.rmtree(base, ignore_errors=True)


def _owned_dir(path: Path, uid: int, gid: int, mode: int = 0o755) -> Path:
    path.mkdir()
    if os.geteuid() == 0:
        os.chown(path, uid, gid)
    os.chmod(path, mode)
    return path


def _fingerprint(path: Path) -> tuple:
    st = os.lstat(path)
    listing = sorted(os.listdir(path)) if stat.S_ISDIR(st.st_mode) else path.read_bytes()
    return st.st_uid, st.st_gid, st.st_mode, listing


# ======================================================================================
# mirror_write_stdlib_only
# ======================================================================================


def test_1080_the_moved_mirror_writer_runs_under_isolated_python_with_only_the_stdlib(tmp_path):
    """The moved `_mirror_write`, run as `python -I <its path> <dest>` under an interpreter that
    refuses every non-stdlib import, writes stdin's page bytes to `dest` and exits 0.
    `visualize_run`'s `_MIRROR_WRITER` points at that file.

    Observed: the writer is the module under `defender/reports/` that defines `write_page`; the
    renderer's `_MIRROR_WRITER` is that file. Run by path under `-I` with `_import_blocker`'s
    stdlib-only finder, it exits 0 and `dest` holds exactly the bytes sent on stdin (the page
    bytes land — the positive control `s_run_end_publishes_page` names). The production argv
    with no blocker does the same. Negative control: a copy of the same file with one
    third-party import added fails under the same command, so the blocker is armed."""
    writer = _writer_path()
    assert S.moved("_MIRROR_WRITER", home=S.REPORTS) == writer.resolve(), (
        "the renderer's _MIRROR_WRITER is not the moved writer file")
    page = "<html><body>mirror ✓ 1080</body></html>\n".encode()

    dest = tmp_path / "blocked" / "r" / PAGE_NAME
    child = _stdlib_only_writer_run(writer, dest, page)
    assert child.returncode == 0, (
        f"the writer did not run on the stdlib alone: {child.stderr.decode(errors='replace')}")
    assert dest.read_bytes() == page, "the writer did not put stdin's page bytes at dest"

    plain = tmp_path / "plain" / "r" / PAGE_NAME
    child = subprocess.run(  # noqa: S603 — the renderer's own argv shape
        [sys.executable, "-I", str(writer), str(plain)], input=page, capture_output=True,
        check=False, cwd="/", env=S.child_env(pythonpath=False), timeout=120)
    assert child.returncode == 0, child.stderr.decode(errors="replace")
    assert plain.read_bytes() == page

    tainted = tmp_path / "tainted" / writer.name
    tainted.parent.mkdir()
    tainted.write_text(_with_import(writer.read_text(encoding="utf-8"),
                                    "import yaml  # a non-stdlib import"), encoding="utf-8")
    child = _stdlib_only_writer_run(tainted, tmp_path / "tainted-dest" / PAGE_NAME, page)
    assert child.returncode != 0, (
        "negative control: the blocker let a third-party import through, so the green run "
        "above proves nothing")
    assert b"refused by the test import blocker" in child.stderr, child.stderr


# ======================================================================================
# s068
# ======================================================================================


def test_mirror_writer_sits_beside_modules_it_could_import_but_must_not(tmp_path):
    """`_mirror_write.py` stays stdlib-only (it imports only errno, os, sys, tempfile, pathlib)
    wherever it lands, even beside siblings that import third-party or project packages,
    because it is spawned with `python -I` by path; a test pins that its imports are
    stdlib-only so a later sibling import fails in CI, not at spawn time. (10-03: stays
    stdlib-only.)

    Observed on the moved file under `defender/reports/`: its import statements name exactly
    the base's set (golden: `__future__`, errno, os, pathlib, sys, tempfile), every one in
    `sys.stdlib_module_names`, none relative. The placement the seed worries about is real: the
    writer sits in the renderer's folder, and the renderer imports project packages. Driven, not
    only read: the moved file runs to exit 0 under `-I` with a stdlib-only import system; a copy
    of it given the import a sibling uses (`from defender import _io`) fails under the same run
    — the failure a later sibling-style import meets here, in CI, rather than at spawn time."""
    writer = _writer_path()
    tops = _module_level_import_tops(writer)
    _assert_golden("s068", {"imports": tops})
    assert all(t in sys.stdlib_module_names or t == "__future__" for t in tops), tops

    renderer = S.REPO_ROOT / S.home_of("publish_page", home=S.REPORTS)
    assert writer.parent == renderer.parent, (
        f"the writer {S.rel(writer)} is not beside the renderer {S.rel(renderer)} that spawns it")
    assert "defender" in _module_level_import_tops(renderer), (
        "precondition: the sibling renderer imports project packages")

    page = b"<html>s068</html>"
    ok = _stdlib_only_writer_run(writer, tmp_path / "ok" / PAGE_NAME, page)
    assert ok.returncode == 0, ok.stderr.decode(errors="replace")
    assert (tmp_path / "ok" / PAGE_NAME).read_bytes() == page

    sibling_style = tmp_path / "copy" / writer.name
    sibling_style.parent.mkdir()
    sibling_style.write_text(_with_import(writer.read_text(encoding="utf-8"),
                                          "from defender import _io  # what a sibling imports"),
                             encoding="utf-8")
    bad = _stdlib_only_writer_run(sibling_style, tmp_path / "bad" / PAGE_NAME, page)
    assert bad.returncode != 0, "a project import in the writer was not caught"
    assert b"refused by the test import blocker" in bad.stderr, bad.stderr
    assert not (tmp_path / "bad" / PAGE_NAME).exists()


# ======================================================================================
# s019 / s130 / s064 — the mirror root's default
# ======================================================================================


_REAL_DEFAULT_CHILD = r'''
import importlib, sys
vr = importlib.import_module(sys.argv[1])
print(vr.mirror_root())
'''


def test_mirror_root_default_observed_only_outside_the_test_environment(monkeypatch):
    """After the move the mirror root default (no override, no explicit start) equals the
    pre-move value: the `run-visualizations` folder under the main checkout. The test can
    observe that value despite the under-pytest refusal (MirrorRootRefused): from a child
    process with PYTEST_CURRENT_TEST scrubbed, or by reading the anchor, never by a test that
    passes only because the default is never taken. (M2 names the mirror root; #1112 item 3:
    move it, don't change it.)

    Observed: a child started from THIS checkout with `PYTEST_CURRENT_TEST` and the override
    absent imports the moved renderer and prints `mirror_root()`; it equals git's main checkout
    joined with the base's value relative to it (golden: `run-visualizations`). Nothing is
    rendered or written. Positive control that the child is what lifts the refusal: in this
    process, with the override removed, the same call raises the moved `MirrorRootRefused`."""
    child = S.python("-c", _REAL_DEFAULT_CHILD, _renderer_dotted(),
                     env=S.child_env(), cwd=S.REPO_ROOT)
    assert child.returncode == 0, child.stderr.decode(errors="replace")
    got = Path(child.stdout.decode().strip())
    main = _main_checkout_by_git()
    assert got.is_relative_to(main), f"the default mirror root {got} left the main checkout {main}"
    _assert_golden("s019", {"relative_to_main_checkout": got.relative_to(main).as_posix()})

    vr = _renderer()
    monkeypatch.delenv(MIRROR_ENV, raising=False)
    assert "PYTEST_CURRENT_TEST" in os.environ
    with pytest.raises(S.moved("MirrorRootRefused", home=S.REPORTS)):
        vr.mirror_root()


def test_mirror_root_default_with_no_override_in_a_main_checkout(tmp_path, monkeypatch):
    """The default mirror location (no override), outside pytest, is unchanged by the move: from
    a main checkout, `<main checkout>/run-visualizations/<run_id>/runtime.html`; from a linked
    worktree, the main checkout's folder reached through the worktree's pointer; from a tree
    that is not a git checkout (an unpacked archive), the fallback `start` as today; under the
    test runner without an override it is refused (MirrorRootRefused). The re-anchor onto the
    shared constants must give the same values.

    Observed by running the moved renderer FROM each layout (a shadow checkout, module
    docstring) in a child with no override and `PYTEST_CURRENT_TEST` scrubbed, deployment
    `dev`: the root it resolves, what `mirror_page` answers, where `runtime.html` lands and the
    warnings — each equal to the base's golden for the same layout (main checkout, linked
    worktree, unpacked tree). Under pytest in this process, with the override removed, the
    default is refused with the moved `MirrorRootRefused`, and an explicit `start` is not."""
    observed = {}
    main = _git_layout_main(tmp_path / "main-only" / "main", shadow=True)
    observed["main_checkout"] = _default_from(main, tmp=tmp_path / "main-only")

    wt_base = tmp_path / "linked"
    wt_main = _git_layout_main(wt_base / "main", shadow=False)
    wt = wt_base / "trees" / "wt"
    _git_layout_worktree(wt_main, wt)
    observed["linked_worktree"] = _default_from(wt, tmp=wt_base)

    unpacked = _shadow_checkout(tmp_path / "unpacked" / "tree")
    observed["unpacked_tree"] = _default_from(unpacked, tmp=tmp_path / "unpacked")
    _assert_golden("s130", observed)

    vr = _renderer()
    monkeypatch.delenv(MIRROR_ENV, raising=False)
    with pytest.raises(S.moved("MirrorRootRefused", home=S.REPORTS)):
        vr.mirror_root()
    assert vr.mirror_root(start=unpacked) == unpacked / MIRROR_NAME


def _break_prefix(wt: Path, admin: Path, main: Path) -> None:
    (wt / ".git").write_text(f"not-a-gitdir-line {admin}\n", encoding="utf-8")


def _break_missing_folder(wt: Path, admin: Path, main: Path) -> None:
    (wt / ".git").write_text(f"gitdir: {admin.parent / 'gone'}\n", encoding="utf-8")


def _break_main_without_defender(wt: Path, admin: Path, main: Path) -> None:
    (main / "defender").rmdir()


S064_BREAKAGES = {
    "pointer-without-gitdir-prefix": _break_prefix,
    "pointer-to-a-missing-folder": _break_missing_folder,
    "main-checkout-without-defender": _break_main_without_defender,
}


def test_mirror_root_default_is_asked_from_a_secondary_worktree_whose_main_checkout_link_is_broken(
        tmp_path):
    """The mirror root default is resolved as today: the override if set; else the main
    checkout found through the worktree's .git pointer; else `start`. A broken pointer, a
    pointer to a missing folder or a main checkout without defender/ gives the same result and
    the same publish outcome as before the move (probe PO6 pins today's). The root is
    re-anchored onto the shared path constants and does not change value.

    Observed by running the moved renderer from a linked worktree (a shadow checkout) in a child
    with no override and `PYTEST_CURRENT_TEST` scrubbed, deployment `dev`: the resolved root,
    `mirror_page`'s answer, where the page landed and the warnings, per breakage — each equal to
    the base's golden. Positive control on a well-formed pointer first: the page lands in the
    MAIN checkout's folder (also golden), so the fallback below is the breakage's doing. With
    the override set, the override wins over the worktree's own resolution."""
    observed = {}
    for name, breakage in {"well-formed": None, **S064_BREAKAGES}.items():
        base = tmp_path / name
        main = _git_layout_main(base / "main", shadow=False)
        wt = base / "trees" / "wt"
        admin = _git_layout_worktree(main, wt)
        if breakage is not None:
            breakage(wt, admin, main)
        observed[name] = _default_from(wt, tmp=base)
    _assert_golden("s064", observed)

    base = tmp_path / "override"
    main = _git_layout_main(base / "main", shadow=False)
    wt = base / "trees" / "wt"
    _git_layout_worktree(main, wt)
    pages = base / "elsewhere"
    child = S.python("-c", _MIRROR_CHILD, _renderer_dotted(), "resolve", "", "", cwd=wt,
                     env=_shadow_env(wt, **{MIRROR_ENV: str(pages)}))
    assert child.returncode == 0, child.stderr.decode(errors="replace")
    assert json.loads(child.stdout.decode().splitlines()[-1])["root"] == str(pages)


# ======================================================================================
# s175 / s038 — the override and the other knobs, read at call time
# ======================================================================================


def _override_case(name: str, tmp: Path) -> list[str | None]:
    """The override value(s) a case sets, in order (`None` = unset). Built under `tmp`."""
    if name == "empty":
        return [""]
    if name == "relative":
        return ["rel/pages"]
    if name == "trailing-slash":
        return [str(tmp / "pages") + "/"]
    if name == "tilde":
        return ["~/pages"]
    if name == "under-a-missing-parent":
        return [str(tmp / "missing" / "deeper" / "pages")]
    if name == "a-regular-file":
        (tmp / "afile").write_bytes(b"not a folder\n")
        return [str(tmp / "afile")]
    if name == "a-symlink":
        (tmp / "target").mkdir()
        (tmp / "link").symlink_to(tmp / "target")
        return [str(tmp / "link")]
    if name == "changed-between-calls":
        return [str(tmp / "first"), str(tmp / "second")]
    raise AssertionError(name)


S175_CASES = ("empty", "relative", "trailing-slash", "tilde", "under-a-missing-parent",
              "a-regular-file", "a-symlink", "changed-between-calls")


def _observe_override(name: str, tmp: Path, monkeypatch, caplog) -> dict[str, Any]:
    """For one spelling: per value set (in order), the root `mirror_root()` answers (or what it
    raises) and what `mirror_page` answers under `dev`; then every `runtime.html` under `tmp`
    and the number of WARNINGs. cwd is `tmp`, so a relative spelling lands there."""
    import logging

    vr = _renderer()
    monkeypatch.chdir(tmp)
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    calls = []
    for value in _override_case(name, tmp):
        monkeypatch.setenv(MIRROR_ENV, value)
        try:
            root: Any = {"path": str(vr.mirror_root())}
        except Exception as e:  # noqa: BLE001 — the refusal IS the observed outcome
            root = {"raises": type(e).__name__}
        calls.append({"root": root, "publish": vr.mirror_page(CHILD_PAGE, CHILD_RUN_ID)})
    landed = sorted(S.rel(p, tmp) for p in tmp.rglob(PAGE_NAME))
    warnings = sum(1 for r in caplog.records if r.levelno >= logging.WARNING)
    return _scrub({"calls": calls, "landed": landed, "warnings": warnings}, {str(tmp): "<TMP>"})


def test_mirror_override_spelled_unusually(tmp_path, monkeypatch, caplog):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap,
    cluster and rename; O5 where it applies). A mirror override that is empty, relative,
    trailing-slashed, tilde, under a missing parent, a regular file, a symlink, or changed
    between calls resolves as today (read at call time, as now).

    Observed through the moved renderer in this process (the override set AFTER the module was
    imported, so a value read at import would show): per spelling, `mirror_root()`'s answer
    and `mirror_page`'s under `dev`, where `runtime.html` landed and how many warnings — equal
    to the base's golden. The changed-between-calls case answers the second value on the second
    call."""
    observed = {}
    for name in S175_CASES:
        case_tmp = tmp_path / name
        case_tmp.mkdir()
        observed[name] = _observe_override(name, case_tmp, monkeypatch, caplog)
    _assert_golden("s175", observed)


#: argv: the copied `_venv` module's path, `import` (DEFENDER_BOX as the env has it at load) then
#: `call` (set/unset before the call). Prints RETURNED when the call returns; an exec into the
#: planted venv prints the planted interpreter's own line instead.
_VENV_CHILD = r'''
import importlib.util, os, sys
path, at_call = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("spec1080_venv_copy", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
if at_call == "set":
    os.environ["DEFENDER_BOX"] = "1"
else:
    os.environ.pop("DEFENDER_BOX", None)
sys.argv = ["s1080.py"]
mod.reexec_into_venv("s1080.py")
print("RETURNED")
'''


def _observe_venv_knob(tmp: Path) -> dict[str, str]:
    """The moved `reexec_into_venv`, copied to the same repo-relative place under `tmp` beside a
    planted `defender/.venv/bin/python3` that only prints a line: what one call does when
    `DEFENDER_BOX` is unset at import and set at the call, and the reverse."""
    home = S.home_of("reexec_into_venv")
    copy = tmp / home
    copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(S.REPO_ROOT / home, copy)
    fake = tmp / "defender" / ".venv" / "bin" / "python3"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text("#!/bin/sh\necho PLANTED-VENV-RAN\n", encoding="utf-8")
    fake.chmod(0o755)
    out = {}
    for label, at_import, at_call in (("unset-at-import-set-at-call", None, "set"),
                                      ("set-at-import-unset-at-call", "1", "unset")):
        env = S.child_env()
        if at_import is not None:
            env["DEFENDER_BOX"] = at_import
        child = S.python("-c", _VENV_CHILD, str(copy), at_call, env=env, cwd=tmp)
        assert child.returncode == 0, child.stderr.decode(errors="replace")
        out[label] = child.stdout.decode().strip()
    return out


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1105 (the mirror-override knob).
def _observe_knobs(tmp: Path, monkeypatch, capsys) -> dict[str, Any]:
    """Each moved module's knob, set or changed AFTER the module was imported, and what the
    module then acts on."""
    out: dict[str, Any] = {}
    pmax = S.moved("passthrough_max_bytes")
    knob = "DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES"
    cap = []
    for value in (None, "100", "0", "not-a-number"):
        if value is None:
            monkeypatch.delenv(knob, raising=False)
        else:
            monkeypatch.setenv(knob, value)
        cap.append(S.outcome(pmax))
    out["payload_passthrough_cap"] = cap

    sql = S.moved_module("EXIT_NO_RUNTIME")
    box = []
    for value in (None, "1"):
        if value is None:
            monkeypatch.delenv("DEFENDER_BOX", raising=False)
        else:
            monkeypatch.setenv("DEFENDER_BOX", value)
        capsys.readouterr()
        rc = sql._no_runtime("duckdb")
        captured = capsys.readouterr()
        box.append({"rc": rc, "stdout": captured.out, "stderr": captured.err})
    monkeypatch.delenv("DEFENDER_BOX", raising=False)
    out["sql_box_marker"] = box

    out["venv_box_marker"] = _observe_venv_knob(tmp / "venv")

    vr = _renderer()
    roots = []
    for value in (str(tmp / "first"), str(tmp / "second")):
        monkeypatch.setenv(MIRROR_ENV, value)
        roots.append(str(vr.mirror_root()))
    out["mirror_override"] = roots
    return _scrub(out, {str(tmp): "<TMP>"})


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s038); the cut cells are owned by #1105 (the mirror-override knob).
def test_moved_module_reads_its_environment_knob_at_a_different_point(
        tmp_path, monkeypatch, capsys):
    """A moved module reads each environment knob (payload passthrough cap, box marker, mirror
    override) at the same point in the run as before, and the value it acts on is the same
    under every start-up order: no module that read the knob at call time reads it at import,
    and no import that used to be lazy now runs before the run's settings reach the
    environment. (M2; probe P8.)

    Observed with every knob set or changed AFTER the moved module is imported (an import-time
    read would act on the stale value): the moved payload view's passthrough cap for unset /
    `100` / `0` / a non-number; the moved SQL engine's missing-runtime answer with the box
    marker unset and set; the moved venv helper's re-exec with the marker set only at the call
    and unset only at the call (a copy beside a planted venv interpreter, so the exec is seen);
    the moved renderer's mirror root as the override changes. Each equals the base's golden.
    The renderer is also imported by `run_common.visualize` only at the call (s037 pins the
    lazy site's output)."""
    _assert_golden("s038", _observe_knobs(tmp_path, monkeypatch, capsys))


# ======================================================================================
# s053 — module-level consumers meet a stale name at import
# ======================================================================================

# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1105 (run_common, the learning frontend), #1165 (run.py -> ticket_writer) and the case_ticket follow-up.
#: (edge, consumer module, a symbol the moved module defines). The consumer's import of that
#: module is at module level, so a stale name is loud at process start.
S053_EDGES = (
    ("run->ticket_writer", "defender.run", "record_case_ticket"),
    ("run_common->_page_failed", "defender.run_common", "VisualizeFailed"),
    ("frontend_build->visualize_primitives", "defender.learning.frontend.build", "esc_untrusted"),
    ("api_serve->_venv", "defender.api.serve", "reexec_into_venv"),
    ("tools_init->sql", "defender.runtime.tools", "EXIT_NO_RUNTIME"),
    ("query_tool->payload_view", "defender.runtime.query_tool", "ELISION_PREFIX"),
)

_CLEAN_IMPORTS = r'''
import importlib, json, sys
out = {}
for name in sys.argv[1:]:
    try:
        importlib.import_module(name)
        out[name] = None
    except ImportError as e:
        out[name] = e.name or type(e).__name__
print(json.dumps(out))
'''

_STALE_IMPORT = r'''
import importlib, json, sys
target, consumer = sys.argv[1], sys.argv[2]
sys.modules[target] = None
try:
    importlib.import_module(consumer)
except ImportError as e:
    print(json.dumps({"raised": type(e).__name__, "name": e.name}))
else:
    print(json.dumps({"raised": None}))
'''


def _imports_module(consumer_rel: str, target: str) -> list[S.ImportStmt]:
    """The consumer's MODULE-LEVEL import statements that name `target` (as `from target
    import ...`, `import target`, or `from <package> import <target's last part>`)."""
    src = (S.REPO_ROOT / consumer_rel).read_bytes()
    hits = []
    for st in S.import_statements(consumer_rel, src):
        named = {st.module} | {f"{st.module}.{n}" for n in st.names}
        if target in named and st.top_level:
            hits.append(st)
    return hits


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s053); the cut cells are owned by #1105 and #1165 (the run.py, run_common and learning-frontend edges).
def test_module_level_consumers_of_a_moved_module_meet_a_stale_name_at_import():
    """A module-level consumer (run.py, run_common, the learning frontend, the API server, the
    tool package, the query tool) whose import still names the old place fails at process
    start with an ImportError, for every one of them, never later at first use. A missed
    repoint on those is loud (unlike the five fail-open lazy sites).

    Observed per consumer edge: (1) the consumer imports the moved module — found by a symbol
    it defines — through a MODULE-LEVEL import statement naming the module's new dotted path;
    (2) driven: in a fresh child where that dotted path cannot be imported (`None` in
    `sys.modules`, what a name that no longer exists gives), importing the consumer raises
    `ImportError` naming exactly that module, at the import, before any call. Positive control:
    in a fresh child with nothing blocked every consumer imports (the API server may stop only
    at its own uninstalled web framework, never at a `defender` module), so the failure in (2)
    is the stale name's."""
    consumers = [c for _edge, c, _sym in S053_EDGES]
    clean = S.python("-c", _CLEAN_IMPORTS, *consumers, cwd="/")
    assert clean.returncode == 0, clean.stderr.decode(errors="replace")
    verdict = json.loads(clean.stdout.decode().splitlines()[-1])
    for consumer, failed in verdict.items():
        assert failed is None or not str(failed).startswith("defender"), (
            f"positive control: {consumer} does not import cleanly ({failed})")

    for edge, consumer, symbol in S053_EDGES:
        target_rel = S.home_of(symbol)
        target = S.dotted(target_rel)
        consumer_rel = consumer.replace(".", "/") + (
            "/__init__.py" if (S.REPO_ROOT / consumer.replace(".", "/")).is_dir() else ".py")
        assert _imports_module(consumer_rel, target), (
            f"{edge}: {consumer_rel} has no module-level import of {target} (where "
            f"`{symbol}` now lives) — a stale or lazy import there would not fail at start")
        stale = S.python("-c", _STALE_IMPORT, target, consumer, cwd="/")
        assert stale.returncode == 0, stale.stderr.decode(errors="replace")
        got = json.loads(stale.stdout.decode().splitlines()[-1])
        assert got["raised"] in ("ImportError", "ModuleNotFoundError"), (
            f"{edge}: importing {consumer} with {target} gone did not fail at import: {got}")
        assert got["name"] == target, f"{edge}: the import failed on another name: {got}"
