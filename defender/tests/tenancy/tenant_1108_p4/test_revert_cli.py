"""#1108 P4 flow 5: `cli/learning/revert_lesson.py --tenant T <lesson>` reverts through
`TenantDelivery.revert` on the tenant repo, never the product repo.

Entry: the CLI's own `main(argv)` over `p4_tenant`, injecting the forge `client` and an `identity`
(so no AppRole login). The lesson to revert is written as a tick writes one (the real commit-maker, its
record in the database) and merged on the fake origin as a human would (`authored_and_merged`). The
revert claims a revert batch in the learning store (#1278 Reverts): a running tick (a working batch of
the lane) makes it exit 3. Its #1278 behaviours beyond these are in `test_1278_revert.py`.
"""
from __future__ import annotations

import importlib
import logging
from pathlib import Path

import pytest
from typing import Any

from defender._git import REPO_ROOT
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    ONE,
    authored_and_merged,
    batches,
    call,
    finding,
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — fixture
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSON_NAME,
    critical_text,
    product_repo,
    remote_branches,
    touched,
)
from defender.tests.tenancy.tenant_1108_p4._support import git

pytestmark = pytest.mark.postgres

LESSON = LESSON_NAME.removesuffix(".md")
LESSON_PATH = f"agent/lessons/{LESSON_NAME}"
#: A lesson of the committed fixture: written by a human, never by the commit-maker.
HUMAN_LESSON = "fixture-owner-before-close"


def _cli() -> Any:
    return importlib.import_module("defender.cli.learning.revert_lesson")


def _revert(t: Any, name: str) -> int:
    return _cli().main(["--tenant", t.tenant_id, name], client=t.forge.client,
                       identity=t.vault.identity(), directory=t.directory)


def _product_refs(repo: Path = REPO_ROOT) -> str:
    """The product checkout's lesson-branch refs (where a product-repo revert would push)."""
    return git(repo, "for-each-ref", "--format=%(refname) %(objectname)",
               "refs/heads/lessons/", "refs/remotes/origin/lessons/")


def test_control_the_product_refs_channel_sees_a_lesson_branch(tmp_path):
    """Control for `_product_refs`, on a scratch checkout (the real one's refs are shared): it
    reads nothing at first, then sees a `lessons/` branch and an `origin/lessons/` ref."""
    repo = product_repo(tmp_path)
    assert _product_refs(repo) == ""
    git(repo, "branch", "lessons/revert-p4")
    head = git(repo, "rev-parse", "HEAD")
    assert _product_refs(repo) == f"refs/heads/lessons/revert-p4 {head}"
    git(repo, "update-ref", "refs/remotes/origin/lessons/revert-p4", head)
    assert "refs/remotes/origin/lessons/revert-p4" in _product_refs(repo)


def test_flow5_revert_cli_opens_a_revert_pr_on_the_tenant_forge_deleting_the_agent_lesson(
        world, capsys, caplog):  # noqa: F811 — the imported fixture
    """Reverting a lesson the commit-maker created (and a human merged) opens a PR on the tenant
    forge whose branch, off the origin's `main`, only deletes the lesson; the CLI prints the PR
    and exits 0, and the product checkout gains no lesson branch. The revert's batch is a working
    revert batch when it asks for its PR, in review after."""
    t = world.t
    authored_and_merged(world)
    main = t.origin_main()
    before = set(remote_branches(t.remote, prefix=""))
    product_before = _product_refs()
    capsys.readouterr()
    at_create: list[list[tuple[str, str]]] = []

    def probe(request: Any) -> None:
        if request.method == "POST" and request.url.path.endswith("/pulls"):
            at_create.append([(b.kind, b.phase) for b in batches(world.dsn, t.tenant_id)
                              if b.kind == "revert"])

    t.forge.on_request = probe

    with caplog.at_level(logging.INFO):
        rc = _revert(t, LESSON)

    assert rc == 0, critical_text(caplog)
    assert at_create == [[("revert", "working")]], "the revert asked for its PR without a working batch of its own"
    new = {b: tip for b, tip in remote_branches(t.remote, prefix="").items() if b not in before}
    assert len(new) == 1, new
    (branch, tip), = new.items()
    assert touched(t.remote, main, tip) == [LESSON_PATH]
    assert git(t.remote, "ls-tree", "--name-only", tip, "--", LESSON_PATH) == ""
    assert [c["head"] for c in t.forge.creates if c["head"] == branch] == [branch]
    pr = next(row for row in t.forge.prs if row["head"]["ref"] == branch)
    assert f"revert PR: {pr['html_url']}" in capsys.readouterr().out
    [revert] = [b for b in batches(world.dsn, t.tenant_id) if b.kind == "revert"]
    assert (revert.phase, revert.pr_number, revert.branch) == ("in_review", pr["number"], branch)
    assert _product_refs() == product_before


def test_flow5_revert_cli_refuses_a_human_written_lesson_naming_why_and_leaves_no_batch_holding_the_lane(
        world, capsys, caplog):  # noqa: F811 — the imported fixture
    """A lesson no commit-maker change produced (the fixture's, human-written) is refused: exit
    2, naming the lesson, no branch pushed and no PR opened, and no revert batch left not ended.
    Control: the previous case."""
    t = world.t
    refs = git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)")

    with caplog.at_level(logging.INFO):
        rc = _revert(t, HUMAN_LESSON)

    assert rc == 2
    assert HUMAN_LESSON in critical_text(caplog), critical_text(caplog)
    assert t.forge.creates == []
    assert git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)") == refs
    assert [b for b in batches(world.dsn, t.tenant_id) if b.phase != "ended"] == [], "a refused revert held the lane"


def test_flow5_revert_cli_waits_out_a_running_author_tick(world):  # noqa: F811 — the imported fixture
    """While the tenant's author tick holds a working batch, the revert exits 3 and asks nothing of
    the forge or the origin, and claims no batch of its own."""
    t = world.t
    call(world.dsn, "publish_findings", t.tenant_id, "run-1", [finding("f1")], kind="finding")
    running = call(world.dsn, "claim", t.tenant_id, AUTHOR_LANE, owner="a-tick", thresholds=ONE)
    t.forge.requests.clear()  # the fixture's own publish asked the forge; only the revert counts

    rc = _revert(t, LESSON)

    assert rc == 3
    assert t.forge.requests == []
    assert [b.id for b in batches(world.dsn, t.tenant_id)] == [running.batch_id]
