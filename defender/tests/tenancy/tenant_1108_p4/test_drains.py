"""#1108 P4 slice S-D — flow 4 (the drain), O7 (its writes go through `TenantDelivery`), O9 (its
refusals), D-closed on the retained-batch path, and O-SWEEP's draft half.

Flow 4: `--tenant T` → forge binding + issuer config → login → `TenantDelivery.open` → publish →
batches (draft, box windows, ChangeSet per claim, commit-maker) → finish/deliver status
(D-closed) → `discard()`.

Every case drives the REAL drain entry (`defender.learning.core.drains.author_drain`) through the
stage runner the CLI uses (`learning.core.cli._run_stage`), over S0's fixture tenant published
for real (`p4_tenant`: a real clone, a loopback smart-HTTP origin, P3's forge and issuer fakes).
The lessons curator that runs inside the tick is the REAL one (`learning.author.lessons.run`):
only its model spawn (`cfg.invoke_agent`) is replaced, by `_spec773.FakeCurator`, which writes a
lesson where the curator's config says its corpus is. Everything between the spawn and the forge
(draft, ChangeSet, commit-maker, push, PR) is the code under test's.

The drain's `paths.repo_root` is a scratch product checkout (a real git repo), so "nothing lands
in the product repo" is observed on a repo the legacy drain WOULD commit to (positive control:
a hand commit there shows on the same observation).

ASSUMED SEAMS (reported; the implementer provides them; mirror S-C's `tenant.py update` and
TenantDelivery.open's own keywords):
  author_drain(paths, *, trigger_author=, client=, identity=, issuer_config=, issuer_transport=,
               start_box=, stop_box=)
    - `client`: the forge's HTTP client (production builds one); `identity`: a ForgejoIdentity,
      given -> the AppRole login is skipped; absent -> `issuer_login(tenant,
      issuer_config=...)` (orchestrator decision OD4; `issuer_transport` reaches its HTTP client,
      see test_drain_credentials.py).
    - `start_box(request) -> executor` / `stop_box(executor)`: the batch's box (default:
      `TenantDelivery.start_box` / `box.stop_box`). The `branch=` and `scrub=` seams are gone.
    - `trigger_author` keeps its call shape `(paths, state, channel, threshold_env,
      module_name, pending_label, *, box)`; whatever else the drain hands it arrives as keywords
      and is forwarded to the curator's config builder.
"""
from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._scenarios import _AnswerLost
from defender.tests.tenancy.tenant_1108_delivery._support import (
    FORK,
    OURS,
    close_on_remote,
    pr_row,
    fresh_process_env,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSON_NAME,
    LESSON_PATH,
    BoxSpy,
    CuratorTrigger,
    author_drain,
    critical_text,
    draft_entries,
    drafts_dir,
    drain_paths,
    product_repo,
    product_state,
    queue,
    remote_branches,
    touched,
    under,
)
from defender.tests.tenancy.tenant_1108_p4._support import (
    bind_forge,
    current_commit,
    git,
)


@pytest.fixture
def thresholds(monkeypatch):
    """Both curators wake at one authorable row (env-backed knobs, read at call time)."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")


# ---------------------------------------------------------------------------------------------
# Flow 4 / O7: one drain tick lands on the tenant forge and nowhere else
# ---------------------------------------------------------------------------------------------


def test_flow4_author_drain_publishes_then_delivers_a_lesson_pr_on_the_tenant_forge_O7(
        p4_tenant, tmp_path, thresholds, caplog):
    """Flow 4, O7: a drain tick publishes first (a human merge already on the origin's `main`
    becomes `current` and the batch's base), the curator's lesson is one commit-maker commit on a
    `lessons/` branch of the TENANT clone touching only `agent/lessons/<lesson>` (never
    `agent/.tenant-id`), pushed to the tenant origin with a PR against `main` on the tenant
    forge; no checkout moved (the clone sits clean on `main`, one worktree); the draft is
    discarded; the box mounted the draft, never the clone; the row stays queued until the lesson
    reaches `main` (#922/#952: consumption follows durability, `hold_committed`); and the product
    checkout's git state is byte-for-byte what it was."""
    t = p4_tenant
    bind_forge(t)
    merged = t.merge({"agent/lessons/human-merged.md": "a human-reviewed lesson\n"})
    product = product_repo(tmp_path)
    paths = drain_paths(t, product)
    queue(paths, [S.finding_row("f1", run_id="f1")])
    before = product_state(product)
    curator = S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})
    trigger, box = CuratorTrigger(author=curator), BoxSpy()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 0, critical_text(caplog)
    assert curator.calls, "the curator's model step never ran"
    # One tick serves both curators of the lane into its one batch.
    assert trigger.calls == ["author", "questioner_curator"], trigger.calls
    # Publish ran first: the merge is `current`, the clone fast-forwarded to it.
    assert current_commit(t.tenant) == merged
    assert git(t.clone, "rev-parse", "HEAD") == merged
    # One batch branch on the tenant origin, based on the merge, touching the lesson alone.
    branches = remote_branches(t.remote)
    assert len(branches) == 1, branches
    (branch, tip), = branches.items()
    assert git(t.remote, "merge-base", tip, "refs/heads/main") == merged
    assert touched(t.remote, merged, tip) == [LESSON_PATH]
    assert git(t.remote, "show", f"{tip}:{LESSON_PATH}") + "\n" == S.lesson("f1")
    # Its PR, on the tenant forge, against `main`.
    assert [(c["head"], c["base"]) for c in t.forge.creates] == [(branch, "main")]
    assert [row["head"]["ref"] for row in t.forge.prs if row["state"] == "open"] == [branch]
    # The clone: no checkout but the publish's fast-forward, no worktree, nothing left dirty.
    assert git(t.clone, "symbolic-ref", "HEAD") == "refs/heads/main"
    assert git(t.clone, "status", "--porcelain", "--untracked-files=all") == ""
    assert len(git(t.clone, "worktree", "list", "--porcelain").split("\n\n")) == 1
    # The draft is gone (discard), and the box mounted it, never git.
    assert draft_entries(t) == []
    assert len(box.requests) == 1, box.requests
    mounts = box.requests[0].mounts
    staged = [m for m in mounts if m.kind == "staged"]
    assert len(staged) == 1, mounts
    assert under(staged[0].source, drafts_dir(t)), mounts
    assert not [m for m in mounts if under(m.source, t.clone) or under(t.clone, m.source)], mounts
    writable = sorted(Path(m.source).relative_to(staged[0].source).as_posix()
                      for m in mounts if m.writable)
    assert writable == ["agent/lessons", "agent/lessons-questioner"], writable
    # The row is held until its lesson reaches `main` (#952); the product checkout never moved.
    assert [r["finding_id"] for r in S.pending(paths, S.channel_of("findings"))] == ["f1"]
    assert product_state(product) == before
    # Positive control: the same observation shows a product commit.
    (product / "defender" / "lessons" / "x.md").write_text("x\n", encoding="utf-8")
    git(product, "add", "-A")
    git(product, "commit", "-m", "a product-repo lesson")
    assert product_state(product) != before


# ---------------------------------------------------------------------------------------------
# O9: refusals before any model call, named
# ---------------------------------------------------------------------------------------------


def test_o9_a_tenant_with_no_forge_binding_refuses_the_drain_before_any_model_call(
        p4_tenant, tmp_path, thresholds, caplog):
    """O9: no `forge` binding in the tenant row is a misconfiguration, decidable locally: the
    drain refuses (exit 2, the refusal logged naming the forge binding) before the issuer, the
    forge, a draft, a box or the curator is touched. Positive control on the same channels: once
    bound, the same tick calls the curator and reaches the forge."""
    t = p4_tenant
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    trigger, box = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})), BoxSpy()
    t.vault.calls.clear()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 2
    assert "forge" in critical_text(caplog).lower(), critical_text(caplog)
    assert trigger.calls == []
    assert box.requests == []
    assert t.forge.requests == []
    assert t.vault.calls == []
    assert draft_entries(t) == []
    assert remote_branches(t.remote) == {}

    bind_forge(t)
    assert author_drain(t, paths, trigger=trigger, box=box) == 0
    assert trigger.calls
    assert t.forge.requests
    assert t.vault.calls


def test_o9_an_unprotected_tenant_main_surfaces_as_a_drain_refusal_naming_it(
        p4_tenant, tmp_path, thresholds, caplog):
    """O9: a delivery refusal at open (the forge says `main` is unprotected) is the drain's
    refusal: exit 2, logged naming the protection, and no curator, box, draft or branch. (Control:
    the flow-4 case, protected `main`, delivers.)"""
    t = p4_tenant
    bind_forge(t)
    t.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    trigger, box = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})), BoxSpy()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 2
    assert "protect" in critical_text(caplog).lower(), critical_text(caplog)
    assert trigger.calls == []
    assert box.requests == []
    assert draft_entries(t) == []
    assert remote_branches(t.remote) == {}


# ---------------------------------------------------------------------------------------------
# D-closed on the retained-batch path
# ---------------------------------------------------------------------------------------------


def test_flow4_a_retained_batch_whose_pr_was_closed_is_delivered_as_closed_and_never_reopened(
        p4_tenant, tmp_path, thresholds, caplog):
    """Flow 4 + D-closed: a tick whose PR request reached the forge but lost its answer keeps the
    batch for delivery (the failure is logged, never silent). A human then closes that PR. The
    next tick delivers the retained batch first: the forge's answer is `closed`, so nothing is
    pushed and no PR is opened, and the closed status is logged."""
    t = p4_tenant
    bind_forge(t)
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    trigger, box = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})), BoxSpy()
    lost = _AnswerLost(remote=t.remote, origin=t.origin)

    with caplog.at_level(logging.INFO):
        author_drain(t, paths, trigger=trigger, box=box, client=lost.client)
    assert critical_text(caplog), "a lost PR answer was silent"
    (branch, tip), = remote_branches(t.remote).items()
    assert [c["head"] for c in lost.creates] == [branch]
    close_on_remote(t.p3, branch)
    refs_before = git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)")
    caplog.clear()
    # Tick 2's curator writes nothing (the held row is still queued, #952), so any PR or push it
    # makes could only be the closed batch's.
    quiet = CuratorTrigger()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=quiet, box=box)

    assert rc == 0, critical_text(caplog)
    assert t.forge.creates == [], "a closed batch's PR was opened again"
    assert git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)") == refs_before
    said = "\n".join(r.getMessage() for r in caplog.records)
    assert "closed" in said, said
    assert branch in said, said


# ---------------------------------------------------------------------------------------------
# OD8: the writer lease (amendment 3 keeps the `state=open` listing; D-fork)
# ---------------------------------------------------------------------------------------------

#: An open PR row on the tenant forge, by who holds it: our own repository on this lane, a fork
#: on this lane's prefix, a row whose head repository is gone (D-fork), our own repository on
#: the OTHER lane's prefix.
_LEASE_ROWS = {
    "our-open-lessons-pr": lambda: pr_row(3, "lessons/earlier-batch", repo=OURS),
    "fork-pr": lambda: pr_row(3, "lessons/earlier-batch", repo=FORK),
    "no-head-repository": lambda: pr_row(3, "lessons/earlier-batch", repo=None),
    "our-open-lead-author-pr": lambda: pr_row(3, "lead-author/earlier-batch", repo=OURS),
}


@pytest.mark.parametrize("holder", sorted(_LEASE_ROWS))
def test_od8_an_open_tenant_pr_of_the_lane_holds_the_writer_lease_and_nothing_else_does(
        p4_tenant, tmp_path, thresholds, caplog, holder):
    """OD8 (amendment 3 C1, D-fork): an open PR of OUR tenant repository on this lane's branch
    prefix holds the lane's writer lease: the tick starts no batch — no curator, box, draft,
    branch or PR — and leaves its row queued. A fork's PR on the same prefix, a PR row with no
    head repository, and our own open PR on the other lane's prefix hold nothing: the tick
    serves and opens its PR (positive controls on the same channels)."""
    t = p4_tenant
    bind_forge(t)
    t.forge.add_pr(_LEASE_ROWS[holder]())
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    curator = S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})
    trigger, box = CuratorTrigger(author=curator), BoxSpy()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 0, critical_text(caplog)
    if holder == "our-open-lessons-pr":
        assert trigger.calls == []
        assert box.requests == []
        assert draft_entries(t) == []
        assert remote_branches(t.remote) == {}
        assert t.forge.creates == []
        assert [r["finding_id"] for r in S.pending(paths, S.channel_of("findings"))] == ["f1"]
    else:
        (branch, _tip), = remote_branches(t.remote).items()
        assert [c["head"] for c in t.forge.creates] == [branch]


# ---------------------------------------------------------------------------------------------
# O-SWEEP (draft half): a draft whose owner is dead is swept by the next publish
# ---------------------------------------------------------------------------------------------

_DRAFT_OWNER = """
import sys, time
from pathlib import Path
from defender.tests.support.tenancy import _tenants1106 as tenants
from defender.tests.tenancy.tenant_1108_delivery._support import DEFENDER, ForgeHTTP, target
from defender.tests.tenancy.tenant_1108_delivery._identity import VaultHTTP
root, tenant_id, remote, origin, batch_id, ready, release = sys.argv[1:8]
tenant = tenants.accept(Path(root), tenant_id)
forge = ForgeHTTP(remote=remote, origin=origin)
d = target().TenantDelivery.open(tenant, defender_dir=DEFENDER, client=forge.client,
                                 identity=VaultHTTP(tenant_id).identity(), origin=origin)
d.start_batch(batch_id, lanes=("lessons",))
Path(ready).write_text("ready", encoding="utf-8")
started = time.monotonic()
while release != "-" and not Path(release).exists() and time.monotonic() - started < 120:
    time.sleep(0.05)
"""


def _owner_process(t: Any, tmp_path: Path, batch_id: str, *, hold: bool) -> subprocess.Popen:
    """Another process that builds draft `batch_id` through P3's real `start_batch` and then
    exits (`hold=False`) or waits for `<tmp>/release-<id>` (`hold=True`)."""
    ready = tmp_path / f"ready-{batch_id}"
    release = tmp_path / f"release-{batch_id}" if hold else "-"
    proc = subprocess.Popen(
        [sys.executable, "-c", _DRAFT_OWNER, str(location_path(t.data_root)), t.tenant_id,
         str(t.remote), t.origin, batch_id, str(ready), str(release)],
        env=fresh_process_env(t.tenant, tmp_path / f"owner-{batch_id}"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not hold:
        _out, err = proc.communicate(timeout=300)
        assert proc.returncode == 0, err
    else:
        import time

        started = time.monotonic()
        while not ready.exists():
            assert proc.poll() is None, proc.communicate()[1]
            assert time.monotonic() - started < 120, "the owner never built its draft"
            time.sleep(0.05)
    assert (drafts_dir(t) / batch_id).is_dir(), "the owner built no draft"
    return proc


def test_o_sweep_publish_sweeps_a_draft_whose_owner_died_and_keeps_a_live_owners(
        p4_tenant, tmp_path):
    """O-SWEEP: a draft records its owner; the next publish (under the tenant lock) sweeps a
    draft whose owner process is dead. A draft this live process built survives the same
    publish (positive control on the same observation)."""
    t = p4_tenant
    _owner_process(t, tmp_path, "orphan", hold=False)
    mine = t.open_delivery().start_batch("mine", lanes=("lessons",))

    t.publish()

    assert draft_entries(t) == ["mine"], draft_entries(t)
    assert mine.draft_root.is_dir()


def test_o_sweep_a_live_owners_draft_survives_publish_until_its_owner_exits(p4_tenant, tmp_path):
    """O-SWEEP: liveness is the owner's, not the draft's age: while the owner process runs, a
    publish keeps its draft; once it has exited, the next publish sweeps it."""
    t = p4_tenant
    owner = _owner_process(t, tmp_path, "held", hold=True)
    try:
        t.publish()
        assert draft_entries(t) == ["held"], "a live owner's draft was swept"
    finally:
        (tmp_path / "release-held").write_text("go", encoding="utf-8")
        owner.communicate(timeout=300)
    assert owner.returncode == 0

    t.publish()

    assert draft_entries(t) == [], draft_entries(t)


def test_o_sweep_a_draft_never_shows_an_unowned_moment_to_a_publisher(p4_tenant):
    """O-SWEEP: a draft is built as a dot-named temporary with its owner record inside and only
    then renamed into place, so a draft present under its batch id always names a live owner: a
    publish right after `start_batch` in this (live) process keeps it, and no dot-named entry is
    left beside it."""
    t = p4_tenant
    batch = t.open_delivery().start_batch("fresh", lanes=("lessons",))

    t.publish()

    assert draft_entries(t) == ["fresh"]
    assert batch.draft_root.is_dir()
