"""#1108 P4 slice S-D — flow 5: `cli/learning/revert_lesson.py --tenant T <lesson>` reverts through
`TenantDelivery.revert` (D-peel, amendment 3 R1) on the TENANT repo, never the product repo (O7).

Entry: the CLI's own `main(argv)`, as `python3 defender/cli/learning/revert_lesson.py` runs it,
over S0's fixture tenant published for real (`p4_tenant`). The lesson to revert is written the
way a drain writes one — P3's commit-maker in a batch, finished as a PR — and merged on the fake
origin as a human would (`merged_agent_lesson`).

ASSUMED SEAM (reported; mirrors S-C's `tenant.py update` and the drain's):
    revert_lesson.main(argv, *, client=None, identity=None, issuer_config=None,
                       issuer_transport=None)
  `client`: the forge's HTTP client; `identity` given -> no AppRole login (OD4's `issuer_login`
  otherwise, from `issuer_config`).
The drain lock (`AUTHOR_DRAIN_LOCK`) stays the revert's mutual exclusion with the author drain
(exit 3 when held), as today.
"""
from __future__ import annotations

import fcntl
import importlib
import logging
from pathlib import Path
from typing import Any

from defender._git import REPO_ROOT
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._support import merged_agent_lesson
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, git
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    critical_text,
    product_repo,
    remote_branches,
    touched,
)

LESSON = "p4-reverted"
LESSON_PATH = f"agent/lessons/{LESSON}.md"
#: A lesson of the committed fixture: written by a human, never by the commit-maker.
HUMAN_LESSON = "fixture-owner-before-close"


def _cli() -> Any:
    return importlib.import_module("defender.cli.learning.revert_lesson")


def _revert(t: Any, name: str) -> int:
    return _cli().main(["--tenant", t.tenant_id, name], client=t.forge.client,
                       identity=t.vault.identity())


def _product_refs(repo: Path = REPO_ROOT) -> str:
    """The product checkout's lesson-branch refs (where the legacy revert pushed a branch)."""
    return git(repo, "for-each-ref", "--format=%(refname) %(objectname)",
               "refs/heads/lessons/", "refs/remotes/origin/lessons/")


def test_control_the_product_refs_channel_sees_a_lesson_branch(tmp_path):
    """R-L6 control for `_product_refs`: on a scratch product checkout (never the real one, whose
    refs are shared) it reads nothing at first and sees a `lessons/` branch, and a remote-tracking
    `origin/lessons/` ref, once one is made — the shape the legacy revert left."""
    repo = product_repo(tmp_path)
    assert _product_refs(repo) == ""
    git(repo, "branch", "lessons/revert-p4")
    head = git(repo, "rev-parse", "HEAD")
    assert _product_refs(repo) == f"refs/heads/lessons/revert-p4 {head}"
    git(repo, "update-ref", "refs/remotes/origin/lessons/revert-p4", head)
    assert "refs/remotes/origin/lessons/revert-p4" in _product_refs(repo)


def _lock_is_held(lock: Path) -> bool:
    """Whether another open file description holds `lock` (flock is per open file, so a second
    open in this process contends like another process would). A missing file is not held."""
    if not lock.is_file():
        return False
    with lock.open("a+") as probe:
        try:
            fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(probe.fileno(), fcntl.LOCK_UN)
        return False


def test_flow5_revert_cli_opens_a_revert_pr_on_the_tenant_forge_deleting_the_agent_lesson(
        p4_tenant, capsys, caplog):
    """Flow 5 / O7: reverting a lesson the commit-maker created (and a human merged) opens a PR on
    the TENANT forge whose branch, off the origin's `main`, deletes `agent/lessons/<name>.md`
    and touches nothing else; the CLI prints the PR and exits 0; the product checkout gains no
    lesson branch."""
    t = p4_tenant
    bind_forge(t)
    merged_agent_lesson(t.p3, t.scratch, "seed-revert", LESSON_PATH, b"agent-written lesson\n")
    main = t.origin_main()
    before = set(remote_branches(t.remote, prefix=""))
    product_before = _product_refs()
    capsys.readouterr()
    # The drain lock is held while the revert asks the forge for its PR (moved here from
    # `learning/stages/test_frames_680_lifecycle.py`'s driver case when P4 deleted `revert(branch=)`):
    # observed from a second open of the lock file at the PR's create request.
    from defender.learning.core.state import AUTHOR_DRAIN_LOCK

    lock = location_path(t.tenant.learning) / AUTHOR_DRAIN_LOCK.file
    held_at_create: list[bool] = []

    def probe(request: Any) -> None:
        if request.method == "POST" and request.url.path.endswith("/pulls"):
            held_at_create.append(_lock_is_held(lock))

    t.forge.on_request = probe

    with caplog.at_level(logging.INFO):
        rc = _revert(t, LESSON)

    assert rc == 0, critical_text(caplog)
    assert held_at_create == [True], "the revert asked for its PR without the drain lock held"
    assert not _lock_is_held(lock), "the revert kept the drain lock after it returned"
    new = {b: tip for b, tip in remote_branches(t.remote, prefix="").items() if b not in before}
    assert len(new) == 1, new
    (branch, tip), = new.items()
    assert touched(t.remote, main, tip) == [LESSON_PATH]
    assert git(t.remote, "ls-tree", "--name-only", tip, "--", LESSON_PATH) == ""
    assert [c["head"] for c in t.forge.creates if c["head"] == branch] == [branch]
    url = next(row["html_url"] for row in t.forge.prs if row["head"]["ref"] == branch)
    assert f"revert PR: {url}" in capsys.readouterr().out
    assert _product_refs() == product_before


def test_flow5_revert_cli_refuses_a_human_written_lesson_naming_why(p4_tenant, capsys, caplog):
    """Flow 5 / D-peel: a lesson no commit-maker change produced (the fixture's, human-written)
    is refused — exit 2, the refusal logged naming the lesson — and no branch is pushed and no PR
    opened. (Control: the previous case reverts on the same channels.)"""
    t = p4_tenant
    bind_forge(t)
    refs = git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)")

    with caplog.at_level(logging.INFO):
        rc = _revert(t, HUMAN_LESSON)

    assert rc == 2
    assert HUMAN_LESSON in critical_text(caplog), critical_text(caplog)
    assert t.forge.creates == []
    assert git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)") == refs


def test_flow5_revert_cli_waits_out_a_running_author_drain(p4_tenant):
    """Flow 5: while the tenant's author drain holds its lock, the revert exits 3 and asks
    nothing of the forge or the origin."""
    from defender.learning.core.state import AUTHOR_DRAIN_LOCK

    t = p4_tenant
    bind_forge(t)
    lock = location_path(t.tenant.learning) / AUTHOR_DRAIN_LOCK.file
    lock.parent.mkdir(parents=True, exist_ok=True)
    t.forge.requests.clear()  # the fixture's own publish asked the forge; only the revert counts
    with lock.open("a+") as holder:
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            rc = _revert(t, LESSON)
        finally:
            fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
    assert rc == 3
    assert t.forge.requests == []
