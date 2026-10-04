# PARKED 2026-10-04 (scope cut of #1080, human-decided): preserved, NOT collected.
# Moved verbatim out of defender/tests/scripts_1080_split/test_1080_episode_frontend_and_pricing.py by the cut author:
# 9 test function(s) whose demands were parked with an owner issue, plus the
# imports, constants and helpers they use (a helper the live file still uses is COPIED, not
# moved). The file name does not match test_*.py, so pytest never collects it. Each
# demand is a `form: clause` in spec-flow/specs/spec_graph_1080-scripts-split.yaml whose
# `parked.preserved_test` names its function here; the owner adopts the test into its own
# spec (restoring form: test) when it lands. The module docstring below is the source file's,
# unchanged: it describes the whole suite file as it stood before the cut.
# GOLDENS: the files only parked tests read (exitcodes.json, integrations.json, pages/*.html,
# runpage/*.html) moved to ./goldens/ beside this file; every other golden stays in
# defender/tests/scripts_1080_split/goldens/ (a kept test still reads it). `S.golden` and
# `S.GOLDENS` read the suite's folder, so the adopter moves the parked goldens back with the test.
"""#1080 — group `pages`: the episode page, the run page's footer, the learning frontend's page
primitives and pricing, after `defender/scripts/` is split into its homes.

The renderers land under `defender/reports/` (M-F (a)) and pricing under
`defender/runtime/providers/` (demand text); every other home is found by symbol (dF0). Every
moved name is reached at CALL time through `_spec1080` (`S.moved` / `S.moved_module` /
`S.home_of`), so a missing home is one failure per test, never a collection error. Modules that
do not move (`learning/branch/cli.py`, `learning/frontend/build.py`, `runtime/observe.py`,
`runtime/lessons_push.py`, `runtime/tools/_document.py`) are imported inside the test bodies
too: each imports a moved module at its own module level or lazily, and a stale import there is
exactly the failure these tests exist to show.

"As today" is `goldens/pages.json` (+ `goldens/pages/*.html` for whole pages), captured once at
the base 80888efb by running the BASE code over the same fixtures these tests build. The
fixtures, the run-dir/git setup and the one path normalizer (`_norm`) live here and the capture
script imported them from this file, so capture and test cannot drift on shape.

Faults are real inputs through the real primitive: an unimportable renderer through
`sys.modules` (the test_1110 precedent), an empty PATH, a copy of this checkout's `defender/`
package under `tmp_path` that is not a repository / tracks no lesson / is owned by another uid,
exported repository-locating variables pointing at a real second repository. No
`monkeypatch.setattr`.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from defender._run_paths import RunPaths
from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "pages"


def _g(key: str):
    return copy.deepcopy(S.golden(GOLDEN)[key])


def _golden_bytes(relname: str) -> bytes:
    path = S.GOLDENS / relname
    assert path.is_file(), f"golden page {relname} is missing from the suite"
    return path.read_bytes()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _norm(text: str, **roots: Path | str) -> str:
    """Each root's spelling (as given and resolved) becomes `<NAME>` — longest first, so a
    nested root is replaced before the root that holds it."""
    pairs: list[tuple[str, str]] = []
    for name, root in roots.items():
        token = f"<{name.upper()}>"
        for spelling in {str(root), str(Path(root).resolve())}:
            pairs.append((spelling, token))
    for raw, token in sorted(pairs, key=lambda kv: -len(kv[0])):
        text = text.replace(raw, token)
    return text


def _norm_json(value, **roots):
    return json.loads(_norm(json.dumps(value), **roots))


def _top_level(d: Path) -> list[str]:
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def _listing(root: Path) -> list[str]:
    """Every entry under `root`, repo-style relative, directories with a trailing `/`."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        for name in dirnames + filenames:
            p = here / name
            rel = p.relative_to(root).as_posix()
            out.append(rel + "/" if p.is_dir() and not p.is_symlink() else rel)
    return sorted(out)


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """test_1025's roots: the launcher's episodes root, the runs base and the learning state root
    inside `tmp_path`, so no episode this file builds or launches lands in the checkout."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))

#: The fixture episode's page as the base's by-path spawn wrote it.
EPISODE_PAGE = "pages/episode-sample.html"


def _episode_page_module():
    """The moved episode renderer (M-F (a): under `defender/reports/`)."""
    return S.moved_module("render_episode", home=S.REPORTS)


def _branch_cli():
    return importlib.import_module("defender.learning.branch.cli")


def _launch(tmp_path: Path) -> tuple[int, Path]:
    """One whole episode through the real launcher (`cli.main`), every seam faked by injection —
    `test_1025_stage_timing._launch`'s all-fakes launch, restated so this file loads no collected
    test module. Returns the exit status and the episode directory."""
    cli = _branch_cli()
    _base, src = T.runs_base(tmp_path)
    episode_dir = Path(cli.episode_dir_for(T.EPISODE_ID, tenant=T.current_tenant()))
    rc = cli.main(
        [str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
        spawn=J.FakeSibling(episode_dir),
        judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        door=T.FakeDoor(),
        questioner=T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c")),
        adapters=T.FakeAdapters(),
        invoke=T.FakeAgent(*["same"] * 24),
        preflight=T.no_preflight,
        live_tree=T.source_capture(),
    )
    return rc, episode_dir


def _launch_roots(tmp_path: Path) -> dict[str, Path]:
    """The roots a launch's log lines and listings may spell, for `_norm`."""
    return {"data_root": Path(os.environ["DEFENDER_DATA_ROOT"]), "tmp": tmp_path}


def _log_lines(caplog, *, at_least: int, **roots) -> list[list[str]]:
    return [[r.name, r.levelname, _norm(r.getMessage(), **roots)]
            for r in caplog.records if r.levelno >= at_least]


def _make_unloadable(monkeypatch, dotted: str) -> None:
    """The renderer cannot be imported: `None` in `sys.modules` under its dotted name and the
    attribute gone from its package, so both `import a.b` and `from a import b` fail (the
    test_1110 precedent, RG4 S5)."""
    parent, _, leaf = dotted.rpartition(".")
    package = importlib.import_module(parent)
    monkeypatch.setitem(sys.modules, dotted, None)
    monkeypatch.delattr(package, leaf, raising=False)


def _build_form(form: str, tmp_path: Path) -> Path:  # noqa: C901, PLR0911 — one arm per directory form the demand names
    """The episode directory forms s178 names, each built through the fixture's own writers."""
    if form == "missing":
        return tmp_path / "no-such-episode"
    if form == "empty":
        d = tmp_path / "empty-episode"
        d.mkdir()
        return d
    if form == "no_stamp":
        return E.sample_episode(tmp_path, stamp=False).dir
    if form == "stamp_without_tenant_id":
        # The family stamp exactly as `_write_family_stamp` leaves it for siblings whose run
        # stamps carry no tenant: `agreed` names commit, dirt, model and scope, never a tenant.
        ep = E.sample_episode(tmp_path, stamp=False)
        E.write_stamp(ep.dir)
        return ep.dir
    if form == "stamp_with_unknown_keys":
        ep = E.sample_episode(tmp_path, stamp=False)
        stamp = E.write_stamp(ep.dir)
        doc = json.loads(stamp.read_text(encoding="utf-8"))
        doc["agreed"]["zz_unknown_agreed_key"] = "a key no reader knows"
        doc["zz_unknown_top_key"] = {"nested": [1, 2]}
        stamp.unlink()
        E.plant_raw(stamp, json.dumps(doc, indent=2, sort_keys=True) + "\n")
        return ep.dir
    if form == "partial_records_manifest_only":
        return E.sample_episode(tmp_path, judge=False, family_draw=False, traces=False,
                                runs=False, stamp=False, samples=False, staged=False).dir
    if form == "partial_records_no_manifest":
        ep = E.sample_episode(tmp_path)
        (ep.dir / "family.yaml").unlink()
        return ep.dir
    if form == "symlink":
        ep = E.sample_episode(tmp_path)
        link = tmp_path / "latest"
        link.symlink_to(ep.dir, target_is_directory=True)
        return link
    raise AssertionError(form)

EPISODE_FORMS = ("missing", "empty", "no_stamp", "stamp_without_tenant_id",
                 "stamp_with_unknown_keys", "partial_records_manifest_only",
                 "partial_records_no_manifest", "symlink")


def _observe_form(render_episode, given: Path, tmp_path: Path) -> dict:
    """What a render over `given` does: its outcome, the page reached through `given` (sha), the
    top-level names there afterwards, and whether a link given stays a link."""
    was_link = given.is_symlink()
    outcome = S.outcome(render_episode, given)
    page = given / E.PAGE_NAME
    return _norm_json({
        "outcome": outcome,
        "page_sha256": _sha(page.read_bytes()) if page.is_file() else None,
        "page_is_symlink": page.is_symlink(),
        "top_level": _top_level(given),
        "given_still_a_link": given.is_symlink() if was_link else None,
    }, tmp=tmp_path)

#: The stale page s208 plants before re-rendering.
STALE_PAGE = b"<!doctype html><title>an older page</title>\n"


def _rerender_into_existing(render_episode, tmp_path: Path) -> dict:
    ep = E.sample_episode(tmp_path)
    ep.page.write_bytes(STALE_PAGE)
    stale_inode = ep.page.stat().st_ino
    first = S.outcome(render_episode, ep.dir)
    first_bytes = ep.page.read_bytes()
    first_inode = ep.page.stat().st_ino
    first_top = _top_level(ep.dir)
    second = S.outcome(render_episode, ep.dir)
    return _norm_json({
        "over_a_stale_page": {"outcome": first, "page_sha256": _sha(first_bytes),
                              "inode_replaced": first_inode != stale_inode,
                              "top_level": first_top},
        "over_its_own_page": {"outcome": second, "page_sha256": _sha(ep.page.read_bytes()),
                              "inode_replaced": ep.page.stat().st_ino != first_inode,
                              "top_level": _top_level(ep.dir)},
    }, tmp=tmp_path)

#: The run's tool trace mtime: the footer's `git log --since`.
FOOTER_SINCE = 1_600_000_000

#: Git isolated from the box's own configuration (a global `safe.directory`, colour, abbrev).
GIT_ISOLATED = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

#: A lesson history, oldest first: (committer date, subject, {path under the repo: text}).
LESSON_HISTORY = (
    ("2021-01-01T00:00:00Z", "add the first lesson",
     {"defender/lessons/first.md": "---\nname: first\n---\n\nfirst body\n"}),
    ("2021-01-02T00:00:00Z", "revise the first lesson, add a second",
     {"defender/lessons/first.md": "---\nname: first\n---\n\nfirst body, revised\n",
      "defender/lessons/second.md": "---\nname: second\n---\n\nsecond body\n"}),
)

#: Another repository's lesson history (the target of an exported GIT_DIR).
OTHER_HISTORY = (
    ("2021-02-01T00:00:00Z", "a lesson in another repository",
     {"defender/lessons/other.md": "---\nname: other\n---\n\nother body\n"}),
)

#: A history that never touches the lesson folder.
NO_LESSON_HISTORY = (
    ("2021-01-01T00:00:00Z", "a commit outside the lesson folder", {"README.md": "readme\n"}),
)

#: The uid a checkout is chowned to for the untrusted-directory case.
OTHER_UID = 4242

#: Copied with the package: everything but the suites, the eval corpus, the real lesson corpus
#: (replaced by a synthetic one), the venv and caches.
_NOT_COPIED_TOP = frozenset({"tests", "evals", "lessons"})

_NOT_COPIED_ANYWHERE = frozenset({".venv", "__pycache__", "node_modules", ".mypy_cache",
                                  ".ruff_cache", ".pytest_cache", ".git"})

_FOOTER_CHILD = (
    "import importlib, pathlib, sys\n"
    "footer = importlib.import_module(sys.argv[1]).render_footer\n"
    "sys.stdout.write(footer(pathlib.Path(sys.argv[2]), 'r1'))\n"
)


def _footer_run(tmp_path: Path, *, since: int = FOOTER_SINCE) -> Path:
    run = tmp_path / "run"
    run.mkdir(exist_ok=True)
    trace = RunPaths(run).tool_trace
    trace.write_text("", encoding="utf-8")
    os.utime(trace, (since, since))
    return run


def _git(repo: Path, *args: str, when: str = "2021-01-01T00:00:00Z") -> None:
    env = S.child_env(pythonpath=False, GIT_AUTHOR_NAME="fixture", GIT_AUTHOR_EMAIL="f@x",
                      GIT_COMMITTER_NAME="fixture", GIT_COMMITTER_EMAIL="f@x",
                      GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=when, **GIT_ISOLATED)
    proc = subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True,
                          check=False)
    assert proc.returncode == 0, proc.stderr.decode()


def _history(repo: Path, commits) -> Path:
    """A fresh repository at `repo` whose commits are exactly `commits` (fixed author, dates
    and configuration, so every sha is the same on every machine)."""
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "-c", "init.defaultBranch=main", "init", "-q")
    for when, subject, files in commits:
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text, encoding="utf-8")
            _git(repo, "add", "--", rel, when=when)
        _git(repo, "commit", "-q", "-m", subject, when=when)
    return repo


def _tree_copy(root: Path) -> Path:
    """This checkout's `defender/` package copied to `<root>/defender`, so the footer module's
    own location derives `<root>` as its git working directory. The copy carries a synthetic,
    untracked `defender/lessons/` and no repository of its own."""
    def ignore(directory, names):
        top = Path(directory).resolve() == S.DEFENDER.resolve()
        return [n for n in names if n in _NOT_COPIED_ANYWHERE or (top and n in _NOT_COPIED_TOP)]

    shutil.copytree(S.DEFENDER, root / "defender", ignore=ignore, symlinks=True)
    lessons = root / "defender" / "lessons"
    lessons.mkdir()
    (lessons / "untracked.md").write_text("---\nname: untracked\n---\n\nbody\n", encoding="utf-8")
    return root


def _child_footer(tree: Path, run: Path, footer_module: str) -> subprocess.CompletedProcess:
    """The footer rendered by a child whose `defender` package is the copy under `tree`."""
    return S.python("-c", _FOOTER_CHILD, footer_module, str(run), cwd=run,
                    env=S.child_env(pythonpath=False, PYTHONPATH=str(tree), **GIT_ISOLATED))


def _git_out(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          check=True).stdout

#: The frontend pages the base built from the golden's fixture views.
FRONTEND_QUEUES_PAGE = "pages/frontend-queues.html"

FRONTEND_LESSONS_PAGE = "pages/frontend-lessons.html"

#: The lessons page's input: a small contract-shaped view carrying markup and a handler-shaped
#: word, so the escape the page embeds is exercised.
LESSONS_VIEW = {
    "generated_at": "2026-10-03T00:00:00+00:00",
    "groups": {
        "defender": {"lessons": [{"name": "pivot-<b>one</b>", "description": "img onerror=x",
                                  "path": "defender/lessons/pivot.md", "stale": False}]},
        "actor": {"lessons": []},
        "environment": {"lessons": []},
    },
}


def _frontend_build():
    return importlib.import_module("defender.learning.frontend.build")


# PARKED 2026-10-04 (scope cut): owner #1105; demand episode_page_by_path_test_survives
def test_1080_render_episode_in_process_equals_the_by_path_output_for_the_fixture_episode(
        tmp_path):
    """Once the episode-page `__main__` block is dropped (M-D (a)), `render_episode(episode_dir)`
    called in-process over the fixture episode of test_1025_page_contract yields the output that
    the base's by-path spawn of the episode renderer yielded for the same fixture, taken as a
    golden from the base.

    The fixture is `_episode_1025.sample_episode`; the golden is the page the base's
    `python defender/scripts/visualize/visualize_episode.py <dir>` wrote (exit 0, the page path
    on stdout), byte for byte. The in-process call must return that same path and write those
    same bytes."""
    by_path = _g("episode_by_path")
    assert by_path["returncode"] == 0, "the base spawn itself failed: the golden is not a page"
    ep = E.sample_episode(tmp_path)
    out = _episode_page_module().render_episode(ep.dir)
    assert _norm(f"{Path(out)}\n", episode_dir=ep.dir) == by_path["stdout"], (
        f"render_episode returned {out!r}; the base's spawn printed {by_path['stdout']!r}")
    written = ep.page.read_bytes()
    assert _sha(written) == by_path["page_sha256"], (
        "the in-process page differs from the base's by-path page for the same fixture episode")
    assert written == _golden_bytes(EPISODE_PAGE)


# PARKED 2026-10-04 (scope cut): owner #1105; demand s_episode_page_renders
def test_1080_the_episode_page_renders_through_the_moved_module(tmp_path, caplog):
    """`learning/branch/cli.py`'s episode-page step renders `render_episode(episode_dir)` from
    the moved module, and the page equals the base renderer's output for the same fixture
    episode.

    Two observations. The CLI's own episode step (`cli._render_page`, the hook the launcher
    calls after the judge frame) over the fixture episode writes the base's page byte for byte
    and logs no render failure — a launcher left on the old import path fails open here with a
    WARNING and no page (RG4 S5). Then a whole fake-seamed launch (`cli.main`) writes a page
    that is byte-identical to the moved `render_episode` re-rendering the same directory: the
    launch's own timing record carries real clock values, so its page is compared to the moved
    renderer over that directory, and the moved renderer to the base over the fixture."""
    module = _episode_page_module()
    cli = _branch_cli()
    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    ep = E.sample_episode(fixture_root)
    with caplog.at_level(logging.INFO):
        cli._render_page(ep.dir, episode_id=E.EPISODE_ID)
    failed = _log_lines(caplog, at_least=logging.WARNING, tmp=tmp_path)
    assert failed == [], f"the CLI's episode step did not render: {failed}"
    assert ep.page.is_file(), "the CLI's episode step wrote no page"
    assert ep.page.read_bytes() == _golden_bytes(EPISODE_PAGE), (
        "the page the CLI's episode step wrote is not the base renderer's page")

    caplog.clear()
    with caplog.at_level(logging.INFO):
        rc, episode_dir = _launch(tmp_path)
    assert rc == 0
    page = episode_dir / E.PAGE_NAME
    assert page.is_file(), "the launch wrote no episode page"
    written = page.read_bytes()
    assert b'id="sec-verdict"' in written
    assert E.EPISODE_ID.encode() in written
    rendered = [line for line in _log_lines(caplog, at_least=logging.WARNING, tmp=tmp_path)
                if "could not be rendered" in line[2]]
    assert rendered == [], rendered
    assert Path(module.render_episode(episode_dir)) == page
    assert page.read_bytes() == written, (
        "the launch's page differs from the moved renderer over the same directory")


# PARKED 2026-10-04 (scope cut): owner #1105; demand s051
def test_episode_renderer_cannot_be_loaded_when_the_branch_cli_finishes_an_episode(
        tmp_path, monkeypatch, caplog):
    """When the episode renderer cannot be loaded at the end of an episode, the branch
    command's exit status, the episode directory's contents and the warning in the operator log
    are exactly as today (no page, one warning, unchanged exit); when it loads, the episode page
    is written. The pinning test asserts the page exists and carries content.

    The fault is the renderer's dotted name made unimportable (RG4 S5 executed it at the base:
    `_render_page` returns None with one WARNING on `defender.learning.branch.cli`). Golden: the
    base's exit status, the episode tree's listing and every WARNING-or-worse log line of the
    faulted launch. The one line that names the import error keeps the base's fixed prefix and
    an import-error class; the module path inside the error's repr is the moved one by design.
    Control: the same launch with the renderer loadable writes a page carrying the episode."""
    g = _g("episode_renderer_unloadable")
    dotted = S.dotted(S.home_of("render_episode", home=S.REPORTS))

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-control"))
    rc_ok, control_dir = _launch(tmp_path)
    assert rc_ok == g["control_rc"]
    page = control_dir / E.PAGE_NAME
    assert page.is_file(), "control: the launch with a loadable renderer wrote no page"
    assert b'id="sec-verdict"' in page.read_bytes()
    assert E.EPISODE_ID.encode() in page.read_bytes()
    assert _listing(control_dir) == g["control_listing"]

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _make_unloadable(monkeypatch, dotted)
    caplog.clear()
    with caplog.at_level(logging.INFO):
        rc, episode_dir = _launch(tmp_path)
    assert rc == g["rc"], "an unloadable renderer changed the branch command's exit status"
    assert not (episode_dir / E.PAGE_NAME).exists()
    assert _listing(episode_dir) == g["listing"]
    assert _listing(episode_dir) == [p for p in _listing(control_dir) if p != E.PAGE_NAME]

    lines = _log_lines(caplog, at_least=logging.WARNING, **_launch_roots(tmp_path))
    page_lines = [line for line in lines if line[2].startswith(g["page_warning"]["prefix"])]
    assert len(page_lines) == 1, f"expected one page warning; the log held {lines}"
    name, level, message = page_lines[0]
    assert [name, level] == g["page_warning"]["logger_level"]
    error_class = message[len(g["page_warning"]["prefix"]):].split("(", 1)[0]
    assert error_class in ("ModuleNotFoundError", "ImportError"), message
    assert [line for line in lines if line not in page_lines] == g["other_warnings"]


# PARKED 2026-10-04 (scope cut): owner #1105; demand s178
@pytest.mark.parametrize("form", EPISODE_FORMS)
def test_episode_dir_forms_given_to_the_episode_page(form, tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). An episode directory that is missing, empty, lacks its
    stamp, has a stamp without a tenant id or with unknown keys, a partial set of family records
    or is a symlink renders or fails as today.

    Each form is built through the fixture's own writers and handed to the moved
    `render_episode`; the outcome (the returned path or the raised class and message), the page
    reached through the given path, the top-level names afterwards and, for the link, whether it
    is still a link are compared to what the base did with the same form."""
    expected = _g("episode_dir_forms")[form]
    given = _build_form(form, tmp_path)
    assert _observe_form(_episode_page_module().render_episode, given, tmp_path) == expected


# PARKED 2026-10-04 (scope cut): owner #1105; demand s208
def test_episode_page_rendered_again_into_a_directory_that_already_holds_one(tmp_path):
    """Re-rendering an episode page into a directory that already holds one leaves the new page
    on disk, replacing the old as today.

    A stale page planted at the page's name is replaced by the fixture's page (the base's
    bytes, a new inode, no staged temporary left beside it); a second render over its own page
    replaces it again with the same bytes. Compared to the base's record of both renders."""
    observed = _rerender_into_existing(_episode_page_module().render_episode, tmp_path)
    assert observed == _g("episode_rerender")
    assert observed["over_a_stale_page"]["page_sha256"] == _sha(_golden_bytes(EPISODE_PAGE))


# PARKED 2026-10-04 (scope cut): owner #1105; demand s_frontend_reads_moved_primitives
def test_1080_the_learning_frontend_takes_its_page_primitives_from_the_moved_modules():
    """`learning/frontend/build.py` imports `CSS`, `esc_untrusted` and `pretty_json_html` from
    their new homes (today: `visualize_run.py` and `visualize_primitives.py`, build.py:22,26),
    and the built frontend page is byte-identical to the base for a fixture input.

    The three names bound in `build` are the very objects the moved modules define; the queue
    page built from the golden's fixture view (test_903's seeded state root, its tmp spelling
    replaced) and the lessons page built from this file's view are the base's bytes."""
    g = _g("frontend")
    css = S.moved("CSS", home=S.REPORTS)
    esc_untrusted = S.moved("esc_untrusted", home=S.REPORTS)
    pretty_json_html = S.moved("pretty_json_html", home=S.REPORTS)
    build = _frontend_build()
    assert build.esc_untrusted is esc_untrusted
    assert build.pretty_json_html is pretty_json_html
    assert any(value is css for value in vars(build).values()), (
        "build.py binds no name to the moved run-page stylesheet")
    assert build.render_queues(g["queues_view"]).encode() == _golden_bytes(FRONTEND_QUEUES_PAGE)
    assert g["lessons_view"] == LESSONS_VIEW
    assert build.render(copy.deepcopy(LESSONS_VIEW)).encode() == _golden_bytes(
        FRONTEND_LESSONS_PAGE)


# PARKED 2026-10-04 (scope cut): owner #1105; demand s023
def test_run_page_footer_lesson_tracking_after_the_primitives_moved(tmp_path):
    """The run page footer reports lesson commit tracking, not 'lesson change tracking
    unavailable', for a repository that has lesson history: git runs from the actual checkout
    root (the primitives' re-anchored repo root), and a root one level off is detected by a test
    that compares the footer to `git log` over defender/lessons. (M2; footer is part of the run
    page, O5.)

    First, a copy of this checkout's package under `tmp_path` made a repository with a fixed
    lesson history: a child importing the moved footer from the copy renders the base's footer
    for that history byte for byte (a root one level off lands outside the copy's repository
    and reads "unavailable"). Then the real checkout: the moved footer, in-process, lists exactly
    the commits `git log` over defender/lessons lists from the checkout root since the run's
    trace time — one level up is no repository, one level down matches no lesson path."""
    footer_module = S.dotted(S.home_of("render_footer", home=S.REPORTS))
    footer = S.moved("render_footer", home=S.REPORTS)

    tree = _history(_tree_copy(tmp_path / "tree"), LESSON_HISTORY)
    run = _footer_run(tmp_path)
    proc = _child_footer(tree, run, footer_module)
    assert proc.returncode == 0, proc.stderr.decode()
    assert proc.stdout.decode() == _g("footer")["tracked_history"]

    newest = _git_out("log", "-1", "--format=%ct", "--", "defender/lessons/",
                      cwd=S.REPO_ROOT).strip()
    assert newest, "positive control: this checkout has no lesson history to compare against"
    since = int(newest) - 1
    _footer_run(tmp_path, since=since)
    oracle = _git_out("log", f"--since=@{since}", "--pretty=format:%H", "--",
                      "defender/lessons/", cwd=S.REPO_ROOT).split()
    assert oracle, "positive control: git lists no lesson commit since the newest one"
    out = footer(run, "r1")
    assert "lesson change tracking unavailable" not in out, out[-600:]
    assert "no lesson commits since" not in out, out[-600:]
    assert out.count('class="block lesson-commit"') == len(oracle), (len(oracle), out[-600:])
    for sha in oracle:
        assert sha[:10] in out, f"the footer does not list {sha} that git log lists"


# PARKED 2026-10-04 (scope cut): owner #1105; demand s069
@pytest.mark.parametrize("case", ["no_git_on_path", "untracked_corpus", "not_a_repository"])
def test_footer_lesson_tracking_runs_where_git_is_absent_or_the_corpus_is_untracked(
        case, tmp_path, monkeypatch):
    """The run page footer, with no git on PATH, an untracked lessons folder, or a working
    directory that is not a repository, fails soft: it shows 'lesson change tracking
    unavailable' (or the folder-has-no-history text exactly as today) and the page still
    renders. The two cases show whatever they show today; the move changes neither text.

    No git: the moved footer in-process with PATH holding only an empty directory. Untracked
    and not-a-repository: a copy of this checkout's package under `tmp_path` — a repository
    whose one commit is outside the lesson folder, or no repository at all — and a child that
    renders the moved footer from the copy, so its own location derives that working
    directory. Each footer is the base's, byte for byte; each call returns (the footer is the
    run page's last section, rendered in-line, so a raise would take the page down)."""
    expected = _g("footer")[case]
    run = _footer_run(tmp_path)
    if case == "no_git_on_path":
        footer = S.moved("render_footer", home=S.REPORTS)
        empty = tmp_path / "no-git"
        empty.mkdir()
        monkeypatch.setenv("PATH", str(empty))
        out = footer(run, "r1")
    else:
        tree = _tree_copy(tmp_path / "tree")
        if case == "untracked_corpus":
            _history(tree, NO_LESSON_HISTORY)
        proc = _child_footer(tree, run, S.dotted(S.home_of("render_footer", home=S.REPORTS)))
        assert proc.returncode == 0, proc.stderr.decode()
        out = proc.stdout.decode()
    assert _norm(out, tmp=tmp_path) == expected


# PARKED 2026-10-04 (scope cut): owner #1105; demand s134
@pytest.mark.parametrize("case", ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                                  "untrusted_checkout_as_root"])
def test_page_footer_lesson_tracking_under_an_exported_repository_locating_environment(
        case, tmp_path, monkeypatch):
    """The footer's lesson-tracking git calls behave exactly as they do today under an
    exported GIT_DIR, GIT_WORK_TREE or GIT_INDEX_FILE for another repository, and as root over
    a checkout owned by another user (untrusted-directory refusal): the footer shows what it
    shows today (tracked or 'unavailable') and the run's exit is unchanged. Preserved behavior;
    the move changes only the working directory it derives (probe P25 pins today's).

    The other repository is real, with a fixed lesson history. Each variable is exported
    through `monkeypatch.setenv` and the moved footer rendered in-process from this checkout:
    today an exported GIT_DIR shows the other repository's history (golden bytes), while
    GIT_WORK_TREE and GIT_INDEX_FILE leave the footer byte-identical to the same render with
    the variable unset. The untrusted case (root only) chowns a repository-holding copy of the
    package to another uid and renders from it in a child: git's ownership refusal, as the
    base showed it. Every render returns rather than raising."""
    footer_module = S.dotted(S.home_of("render_footer", home=S.REPORTS))
    footer = S.moved("render_footer", home=S.REPORTS)
    expected = _g("footer")[case]
    run = _footer_run(tmp_path)
    if case == "untrusted_checkout_as_root":
        if os.geteuid() != 0:
            pytest.skip("only root meets git's ownership refusal over another uid's checkout")
        tree = _history(_tree_copy(tmp_path / "tree"), LESSON_HISTORY)
        os.chown(tree, OTHER_UID, OTHER_UID)
        proc = _child_footer(tree, run, footer_module)
        assert proc.returncode == 0, proc.stderr.decode()
        assert _norm(proc.stdout.decode(), tree=tree) == expected
        return
    other = _history(tmp_path / "other", OTHER_HISTORY)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(name, raising=False)
    for name, value in GIT_ISOLATED.items():
        monkeypatch.setenv(name, value)
    unset = footer(run, "r1")
    assert 'class="block lesson-commit"' in unset, "control: this checkout's history is listed"
    value = {"GIT_DIR": other / ".git", "GIT_WORK_TREE": other,
             "GIT_INDEX_FILE": other / ".git" / "index"}[case]
    monkeypatch.setenv(case, str(value))
    out = footer(run, "r1")
    if expected == {"same_as_unset": True}:
        assert out == unset, f"{case} exported changed the footer"
    else:
        assert _norm(out, tmp=tmp_path) == expected
