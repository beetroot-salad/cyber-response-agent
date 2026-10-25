"""#1108 P4 O6 — which bytes the judge is shown for a lesson a sibling loaded.

O6: "pre-move runs (the code commit's tree has `defender/lessons/<name>.md`) read the product
repo at the code commit; others read `exports/<knowledge commit>/agent/...`, materialised from
the clone if missing. `unversioned`/`unavailable`/a commit absent from the clone → unreadable,
naming why." P-1: no reader reads the clone's working tree.

Every scene plants DISTINCT bytes for ONE lesson name in four places, so a reader using the
wrong source is caught by what the judge model was shown (`FakeJudge.prompts`, the outbound
channel), never by inspecting the reader:
  (a) a real git PRODUCT repo: commit `pre` holds `defender/lessons/<name>.md`, commit `post`
      (its child) deleted it — the code commit a sibling's stamp names;
  (b) the tenant's export at the knowledge commit `K1` (the sibling's knowledge stamp);
  (c) a later merged-and-published commit `K2`: `current` and the clone's HEAD;
  (d) the clone's working tree, edited after that publish (uncommitted).

Entry surface: the judge's one entry point, `learning.judge.grade_episode(runs, episode_id,
judge=, state=, draws=, git_show=)`, driven through `_judge_921.grade` over an accepted episode
under the published fixture tenant. The tenant reaches the judge through `runs.tenant` (the
existing seam: the runs repository is the tenant's). ASSUMED SEAM (reported): the existing
`git_show(cwd, rev, path)` keyword stays the judge's ONLY reader of the product repository —
for the body read AND for the pre-move test — so the test points it at a real product repo
(`ProductRepo`) whenever the judge asks for `REPO_ROOT`; any other `cwd` is served by real git
there, so a reader that `git show`s the tenant clone gets the clone's own bytes (and is caught).
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.judge import _judge_921 as J

from ._support import current_commit, export_dir, git, published_tenant

#: The fixture tenant's own lesson (committed under `knowledge/tenant-fixture/agent/lessons/`).
NAME = "fixture-owner-before-close"
TENANT_PATH = f"agent/lessons/{NAME}.md"
PRODUCT_PATH = f"defender/lessons/{NAME}.md"


def _lesson(marker: str) -> str:
    return (f"---\nname: {NAME}\ndescription: P4 O6 fixture lesson.\n"
            f"created_at: 2026-10-04T00:00:00Z\n---\n\n{marker}\n")


PRODUCT = "O6-BODY-FROM-THE-PRODUCT-TREE-AT-THE-CODE-COMMIT"
EXPORT = "O6-BODY-FROM-THE-EXPORT-AT-THE-KNOWLEDGE-COMMIT"
CURRENT = "O6-BODY-FROM-CURRENT-AND-THE-CLONE-HEAD"
WORKTREE = "O6-BODY-FROM-THE-CLONE-WORKING-TREE"
MARKERS = (PRODUCT, EXPORT, CURRENT, WORKTREE)

#: A file in the export's `settings/` half (beside `agent/`) that a lesson name walking out of
#: `agent/lessons/` would reach: `../../settings/verb-grants` → `settings/verb-grants.md`.
TRAVERSAL_NAME = "../../settings/verb-grants"
SETTINGS_MARKER = "O6-SETTINGS-BYTES-A-TRAVERSING-LESSON-NAME-WOULD-REACH"
SETTINGS_BAIT = ("settings/verb-grants.md", f"{SETTINGS_MARKER}\n")

#: A full object id no repository in the scene holds.
ABSENT_COMMIT = "0123456789abcdef" * 2 + "01234567"


@dataclass
class ProductRepo:
    """A real git product repository and the `git_show` seam pointed at it.

    `pre` holds `defender/lessons/<NAME>.md` (bytes `PRODUCT`); `post` is its child that
    deleted it — a code commit from after the move. Calls asking for `REPO_ROOT` are served
    from this repo with real `git show`; any other `cwd` is served by real git at that `cwd`.
    Every call is recorded as `(cwd, rev, path)`. No policy: it answers what git answers."""

    path: Path
    pre: str
    post: str
    asked: list[tuple[Path, str, str]] = field(default_factory=list)

    def __call__(self, cwd, rev: str, path: str):
        from defender import _git
        from defender.run_common import REPO_ROOT

        self.asked.append((Path(cwd), rev, path))
        root = self.path if Path(cwd).resolve() == Path(REPO_ROOT).resolve() else Path(cwd)
        return _git.git_show_file(root, rev, path)


def _product_repo(where: Path) -> ProductRepo:
    where.mkdir(parents=True)
    git(where, "init", "-b", "main")
    git(where, "config", "user.name", "P4 product fixture")
    git(where, "config", "user.email", "p4-product@test.invalid")
    lesson = where / PRODUCT_PATH
    lesson.parent.mkdir(parents=True)
    lesson.write_text(_lesson(PRODUCT), encoding="utf-8")
    (where / "defender" / "run.py").write_text("# product code\n", encoding="utf-8")
    git(where, "add", "-A")
    git(where, "commit", "-m", "before the move: the lab's lessons live in the product tree")
    pre = git(where, "rev-parse", "HEAD")
    git(where, "rm", "-q", PRODUCT_PATH)
    git(where, "commit", "-m", "the move: tenant knowledge leaves the product tree")
    post = git(where, "rev-parse", "HEAD")
    return ProductRepo(path=where, pre=pre, post=post)


@dataclass
class Scene:
    t: object
    product: ProductRepo
    k1: str  # the sibling's knowledge commit (an export exists for it)
    k2: str  # later: `current` and the clone's HEAD
    ep: Path


@pytest.fixture
def scene(tmp_path, data_root):
    """The four-way plant, then an accepted episode under the published tenant (the data
    root's one tenant, so `_judge_921`'s builders land the episode under it)."""
    with published_tenant(tmp_path / "forge", root=data_root,
                          files={TENANT_PATH: _lesson(EXPORT),
                                 SETTINGS_BAIT[0]: SETTINGS_BAIT[1]}) as t:
        k1 = t.commit
        k2 = t.merge({TENANT_PATH: _lesson(CURRENT)}, message="a later merged lesson edit")
        assert t.publish().commit == k2
        (t.clone / TENANT_PATH).write_text(_lesson(WORKTREE), encoding="utf-8")
        product = _product_repo(tmp_path / "product")
        ep = J.accepted_episode(tmp_path / "ep", ledgers={"b": [J.oracle_row("b")], "c": []})
        assert Path(ep).parent.parent.name == t.tenant_id, "fixture bug: episode not the tenant's"
        yield Scene(t=t, product=product, k1=k1, k2=k2, ep=Path(ep))


def _stamp(scene: Scene, *, code: str, knowledge: object,
           names: tuple[str, ...] = (NAME,)) -> None:
    """Every world of the episode ran at code commit `code` with knowledge stamp `knowledge`
    (`KnowledgeRevision` wire, written raw: the stamp is box-writable) and loaded the lessons
    `names` (one `lessons_loaded.jsonl` row each)."""
    for label in ("a", "b", "c"):
        world = scene.ep / "worlds" / T.world_id(scene.ep, label)
        (world / "provenance.json").write_text(json.dumps(J.provenance_record(
            commit=code, knowledge=knowledge, tenant_id=scene.t.tenant_id)), encoding="utf-8")
        (world / "lessons_loaded.jsonl").write_text("".join(json.dumps(
            {"lesson_name": name, "ts": "2026-10-20T10:00:00Z", "kind": "read",
             "role": "main"}) + "\n" for name in names),
            encoding="utf-8")


def _shown(scene: Scene) -> str:
    """Grade the episode for real and return every prompt the judge model was shown."""
    judge = J.scripted_judge()
    J.grade(scene.ep, judge=judge, git_show=scene.product, draws=1)
    assert judge.prompts, "the judge model was never called"
    return "\n".join(judge.prompts)


def _slot(shown: str) -> str:
    """The lesson's own slot in the first prompt that shows it: from its `### <name>` heading
    to the next heading or frame end — so a cause printed elsewhere (a stamp in a run header)
    cannot satisfy the "names why" check."""
    start = shown.index(f"### {NAME}")
    rest = shown[start + len(NAME) + 4:]
    ends = [i for i in (rest.find("\n### "), rest.find("</run-")) if i >= 0]
    return shown[start:start + len(NAME) + 4 + (min(ends) if ends else len(rest))]


def _only(shown: str, expected: str) -> None:
    assert expected in shown, (
        f"the judge was not shown the body from the right source ({expected})")
    wrong = [m for m in MARKERS if m != expected and m in shown]
    assert not wrong, f"the judge was shown bytes from the wrong source(s): {wrong}"


def test_o6_a_pre_move_run_is_judged_on_the_product_tree_at_its_code_commit(scene):
    """O6 pre-move: the code commit's tree holds `defender/lessons/<name>.md`, so the body is the
    product repo's at that commit — not the export, `current`, or the clone. (Today's behaviour:
    a regression guard for P4.)"""
    _stamp(scene, code=scene.product.pre, knowledge={"commit": scene.k1})
    _only(_shown(scene), PRODUCT)
    from defender.run_common import REPO_ROOT

    assert (Path(REPO_ROOT).resolve(), scene.product.pre, PRODUCT_PATH) in [
        (c.resolve(), r, p) for c, r, p in scene.product.asked], (
        "the product body was not read from the product repository at the code commit")


def test_o6_a_post_move_run_is_judged_on_the_export_at_its_knowledge_commit(scene):
    """O6 post-move: the code commit's tree lacks the lesson, so the body is
    `exports/<knowledge commit>/agent/lessons/<name>.md` — not the product tree at an older
    commit, not `current` (a later publish), not the clone's HEAD or working tree (P-1)."""
    _stamp(scene, code=scene.product.post, knowledge={"commit": scene.k1})
    _only(_shown(scene), EXPORT)
    assert current_commit(scene.t.tenant) == scene.k2, "the judge moved `current`"


def test_o6_a_missing_export_is_materialised_from_the_clone_then_read(scene):
    """O6 + flow 2: the knowledge commit's export is absent (exports are derived, P-2), so the
    judge materialises `exports/<K1>/` from the clone's objects and reads it; `current` and
    the clone are untouched, and nothing went to the network."""
    t = scene.t
    shutil.rmtree(export_dir(t.tenant, scene.k1))
    head_before = git(t.clone, "rev-parse", "HEAD")
    calls_before = (len(t.server.seen), len(t.forge.requests), len(t.vault.calls))
    _stamp(scene, code=scene.product.post, knowledge={"commit": scene.k1})

    _only(_shown(scene), EXPORT)
    rebuilt = export_dir(t.tenant, scene.k1) / TENANT_PATH
    assert rebuilt.is_file(), "the missing export was not materialised"
    assert rebuilt.read_text(encoding="utf-8") == _lesson(EXPORT)
    assert current_commit(t.tenant) == scene.k2, "materialising moved `current`"
    assert git(t.clone, "rev-parse", "HEAD") == head_before, "the clone's HEAD moved"
    assert (t.clone / TENANT_PATH).read_text(encoding="utf-8") == _lesson(WORKTREE), (
        "the clone's working tree was rewritten")
    assert (len(t.server.seen), len(t.forge.requests), len(t.vault.calls)) == calls_before, (
        "the judge's read reached the origin, the forge or the issuer (flow 2: no network)")


@pytest.mark.parametrize(("knowledge", "cause"), [
    ("unversioned", "unversioned"),
    ({"unavailable": "O6-REASON-the-knowledge-clone-could-not-be-read"},
     "O6-REASON-the-knowledge-clone-could-not-be-read"),
    ({"commit": ABSENT_COMMIT}, ABSENT_COMMIT),
], ids=["unversioned", "unavailable", "commit-absent-from-clone"])
def test_o6_a_post_move_run_with_no_readable_knowledge_commit_is_unreadable_naming_why(
        scene, knowledge, cause):
    """O6: a post-move sibling whose knowledge stamp is `unversioned`, `unavailable`, or a
    commit the clone does not hold is shown as unreadable, naming why — never some other
    revision's body (not `current`, not the clone, not the product tree). The positive control
    on the same channel is the readable post-move case above."""
    _stamp(scene, code=scene.product.post, knowledge=knowledge)
    shown = _shown(scene)
    leaked = [m for m in MARKERS if m in shown]
    assert not leaked, f"an unreadable revision was replaced by another source's body: {leaked}"
    assert f"### {NAME}" in shown, "the lesson vanished from the judge's view entirely"
    section = _slot(shown)
    assert cause in section, (
        f"the unreadable slot does not name why ({cause!r}):\n{section[:600]}")
    assert not export_dir(scene.t.tenant, ABSENT_COMMIT).exists(), (
        "an export folder was made for a commit the clone does not hold")


def test_o6_a_traversing_lesson_name_is_never_read_out_of_the_export(scene):
    """O6 under the danger lens (R-I8): `lessons_loaded.jsonl` is box-writable, so a row's
    `lesson_name` may walk out of `agent/lessons/` (`../../settings/verb-grants`). The export
    holds a file at exactly that place (`settings/verb-grants.md`); the judge never shows its
    bytes. The row's slot is still shown, named and marked rather than dropped. Positive
    control in the same pass: the ordinary lesson beside it renders from the export."""
    _stamp(scene, code=scene.product.post, knowledge={"commit": scene.k1},
           names=(TRAVERSAL_NAME, NAME))
    assert (export_dir(scene.t.tenant, scene.k1) / SETTINGS_BAIT[0]).is_file(), (
        "fixture bug: the bait the traversal would reach is not in the export")

    shown = _shown(scene)

    assert SETTINGS_MARKER not in shown, (
        "a traversing lesson name was read outside the export's agent/lessons/")
    assert f"### {TRAVERSAL_NAME}" in shown, "the hostile row's slot vanished from the view"
    _only(shown, EXPORT)


HOSTILE_COMMITS = {
    #: Would join to `exports/../knowledge/` — the clone's working tree (`WORKTREE` bytes).
    "parent-walk": "../knowledge",
    #: Option-shaped: `git show --output=<file>` would write a host file.
    "option": "--output={out}",
    #: Absolute: a join would discard `exports/`.
    "absolute": "{abs}",
    #: Hex-looking but not an object id's length.
    "short-hex": "abc",
}


@pytest.mark.parametrize("shape", sorted(HOSTILE_COMMITS))
def test_o6_a_hostile_knowledge_commit_is_unreadable_and_reads_nothing_outside_exports(
        scene, tmp_path, shape):
    """O6 under the danger lens (R-I8): the knowledge stamp is box-writable. A commit that is
    not a full object id — a parent walk, an option, an absolute path, a short hex — is
    unreadable: no body from any source is shown (not the clone's working tree a `../knowledge`
    join reaches, not the absolute path's file), nothing is written outside `exports/` (the
    option's output file never appears), and no export folder is made for it. The slot stays,
    named. Positive control: the readable post-move case (`EXPORT` shown)."""
    out = tmp_path / "written-by-an-option"
    bait = tmp_path / "absolute-bait"
    (bait / "agent" / "lessons").mkdir(parents=True)
    (bait / "agent" / "lessons" / f"{NAME}.md").write_text(
        _lesson("O6-BODY-FROM-AN-ABSOLUTE-PATH"), encoding="utf-8")
    commit = HOSTILE_COMMITS[shape].format(out=out, abs=bait)
    exports = export_dir(scene.t.tenant, scene.k1).parent
    before = sorted(p.name for p in exports.iterdir())
    _stamp(scene, code=scene.product.post, knowledge={"commit": commit})

    shown = _shown(scene)

    leaked = [m for m in (*MARKERS, "O6-BODY-FROM-AN-ABSOLUTE-PATH") if m in shown]
    assert not leaked, f"a hostile knowledge commit read a body from somewhere: {leaked}"
    assert f"### {NAME}" in shown, "the lesson vanished from the judge's view entirely"
    assert not out.exists(), "an option-shaped commit made git write a host file"
    assert sorted(p.name for p in exports.iterdir()) == before, (
        "an export folder was made for a hostile commit")
