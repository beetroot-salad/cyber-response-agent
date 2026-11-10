"""#1108 P4 flow 4: the drains deliver through `TenantDelivery` (O7) and refuse what cannot be
delivered (O9); a retained batch whose PR was closed; the writer lease; O-SWEEP's draft half.

Every case drives the real drain entry through the CLI's stage runner over the `world` (`p4_tenant`
bound to its forge, a learning store in PostgreSQL: a real clone, a loopback origin, P3's forge and
issuer fakes; work is queued in the store, #1278), injecting the forge `client`, an
`identity` (so the AppRole login is skipped) and `start_box`/`stop_box`. The curator inside the
tick is the real one with only its model spawn replaced by `_spec773.FakeCurator`; everything
from the draft to the PR is the code under test's. `paths.repo_root` is a scratch product
checkout, so "nothing lands in the product repo" is observed on a real repo (positive control: a
hand commit there shows).
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.learning.core._store1278 import (
    batches,
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — the tick's world: tenant, forge and learning store
)
from defender.learning.core.state import QUESTIONER_FINDINGS
from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._scenarios import _AnswerLost
from defender.tests.tenancy.tenant_1108_delivery._support import (
    FORK,
    NAMESAKE,
    OURS,
    SIBLING_FORK,
    LockAudit,
    close_on_remote,
    pr_row,
    fresh_process_env,
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LEAD_PREFIX,
    LESSON_NAME,
    LESSON_PATH,
    LESSONS_PREFIX,
    BoxSpy,
    CuratorTrigger,
    LeadStep,
    PitfallsStep,
    _dead_process,
    author_drain,
    critical_text,
    draft_entries,
    draft_folder,
    drafts_dir,
    drain_paths,
    drains,
    items_of,
    executed_lead,
    lead_author_drain,
    owner_record,
    process_start,
    product_repo,
    product_state,
    queue,
    queued_run,
    remote_branches,
    run_stage,
    touched,
    under,
    write_owner,
)
from defender.tests.tenancy.tenant_1108_p4._support import (
    bind_forge,
    current_commit,
    git,
    unbind_forge,
)


postgres = pytest.mark.postgres


@pytest.fixture
def thresholds(monkeypatch):
    """Both curators wake at one authorable row (env-backed knobs, read at call time)."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")


def _author_tick(w: Any) -> tuple[Any, CuratorTrigger, BoxSpy]:
    """`(paths, trigger, box)` for an author tick in world `w`: one authorable row queued in the
    learning store, its fake curator writing that row's lesson."""
    paths = w.paths
    queue(paths, [S.finding_row("f1", run_id="f1")])
    return paths, CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})), BoxSpy()


# ---------------------------------------------------------------------------------------------
# Flow 4 / O7: one drain tick lands on the tenant forge and nowhere else
# ---------------------------------------------------------------------------------------------


@postgres
def test_flow4_author_drain_publishes_then_delivers_a_lesson_pr_on_the_tenant_forge_O7(
        world, caplog):  # noqa: F811 — the imported fixture
    """A tick publishes first (a pending human merge becomes `current` and the batch's base), then
    delivers the lesson as one commit on a tenant `lessons/` branch with its PR, moving no
    checkout of the clone and nothing in the product repo."""
    w = world
    t = w.t
    merged = t.merge({"agent/lessons/human-merged.md": "a human-reviewed lesson\n"})
    paths = w.paths
    product = Path(paths.repo_root)
    queue(paths, [S.world_row("w1", systems=["cmdb"])], channel=QUESTIONER_FINDINGS)
    queue(paths, [S.finding_row("f1", run_id="f1")])
    before = product_state(product)
    curator = S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})
    trigger, box = CuratorTrigger(author=curator), BoxSpy()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 0, critical_text(caplog)
    assert curator.calls, "the curator's model step never ran"
    # One tick serves both curators of the lane into its one batch (each handed its own kind's
    # items, A2 D1; a kind with no item is not run).
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
    # The box mounts the draft's `stage/`, never the folder holding `owner`.
    assert Path(staged[0].source).name == "stage", mounts
    assert Path(staged[0].source).parent.parent == drafts_dir(t), mounts
    assert not [m for m in mounts if under(m.source, t.clone) or under(t.clone, m.source)], mounts
    writable = sorted(Path(m.source).relative_to(staged[0].source).as_posix()
                      for m in mounts if m.writable)
    assert writable == ["agent/lessons", "agent/lessons-questioner"], writable
    # The row stays in the batch until its lesson reaches `main` (#952); the product checkout never moved.
    assert items_of(paths)[("finding", "f1")].status == "in_batch"
    assert product_state(product) == before
    # Positive control: the same observation shows a product commit.
    (product / "defender" / "lessons" / "x.md").write_text("x\n", encoding="utf-8")
    git(product, "add", "-A")
    git(product, "commit", "-m", "a product-repo lesson")
    assert product_state(product) != before


# ---------------------------------------------------------------------------------------------
# O9: refusals before any model call, named
# ---------------------------------------------------------------------------------------------


@postgres
def test_o9_a_tenant_with_no_forge_binding_refuses_the_drain_before_any_model_call(
        world, caplog):  # noqa: F811 — the imported fixture
    """No forge binding is decidable locally: the drain refuses (exit 2, naming the binding)
    before touching the issuer, the forge, a draft, a box or the curator. Positive control: once
    bound, the same tick reaches them."""
    t = world.t
    unbind_forge(t)  # the fixture's directory wires every tenant; this case is the unwired one
    paths, trigger, box = _author_tick(world)
    # The fixture's own publish already asked the issuer and the forge; only the drain counts.
    t.vault.calls.clear()
    t.forge.requests.clear()

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


@postgres
def test_o9_an_unprotected_tenant_main_surfaces_as_a_drain_refusal_naming_it(
        world, caplog):  # noqa: F811 — the imported fixture
    """A refusal at open (the forge says `main` is unprotected) is the drain's refusal: exit 2,
    naming the protection, and no curator, box, draft or branch."""
    t = world.t
    t.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    paths, trigger, box = _author_tick(world)

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


@postgres
def test_flow4_a_retained_batch_whose_pr_was_closed_is_delivered_as_closed_and_never_reopened(
        world, caplog):  # noqa: F811 — the imported fixture
    """A tick whose PR answer was lost retains its batch (and logs the failure). After a human
    closes that PR, the next tick takes the retained batch over (recording its PR), serves no new
    work and pushes and opens nothing; the tick after reconciles it as `closed`, still pushing and
    opening nothing, and logs the status. (#1278: the closed status is read by the reconcile step,
    not by the retained delivery.)"""
    t = world.t
    paths, trigger, box = _author_tick(world)
    lost = _AnswerLost(remote=t.remote, origin=t.origin)

    with caplog.at_level(logging.INFO):
        author_drain(t, paths, trigger=trigger, box=box, client=lost.client)
    assert critical_text(caplog), "a lost PR answer was silent"
    (branch, tip), = remote_branches(t.remote).items()
    assert [c["head"] for c in lost.creates] == [branch]
    close_on_remote(t.p3, branch)
    refs_before = git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)")
    caplog.clear()
    # Tick 2's curator writes nothing (the item is still in the retained batch), so any PR or push
    # it makes could only be the closed batch's.
    quiet = CuratorTrigger()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=quiet, box=box)

    assert rc == 0, critical_text(caplog)
    assert quiet.calls == [], "new work was served over the retained batch"
    assert t.forge.creates == [], "a closed batch's PR was opened again"
    assert git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)") == refs_before
    # Tick 3 reconciles the takeover's record against the forge: with no words left on the closed PR
    # the batch ends `closed`, its item held for a person (H2), and still nothing is pushed or opened.
    [recorded] = batches(world.dsn, t.tenant_id)
    t.forge.scopes = {"write:repository", "read:issue"}  # the bot's token reads the PR's words (H7)
    t.forge.reviews[recorded.pr_number], t.forge.comments[recorded.pr_number] = [], []
    caplog.clear()
    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=quiet, box=box)

    assert rc == 0, critical_text(caplog)
    [batch] = batches(world.dsn, t.tenant_id)
    assert (batch.branch, batch.phase, batch.outcome) == (branch, "ended", "closed"), batch
    assert items_of(paths)[("finding", "f1")].status == "held"
    assert t.forge.creates == [], "a closed batch's PR was opened again"
    assert git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)") == refs_before
    said = "\n".join(r.getMessage() for r in caplog.records)
    assert "closed" in said, said
    assert str(batch.id) in said and f"#{batch.pr_number}" in said, said  # names the batch and its PR


# ---------------------------------------------------------------------------------------------
# OD8: the writer lease
# ---------------------------------------------------------------------------------------------

#: An open PR row on the tenant forge, by who holds it, for a drain whose lane prefix is `own` and
#: whose other lane's prefix is `other`.
_LEASE_ROWS = {
    "ours-on-this-lane": lambda own, _other: pr_row(3, f"{own}earlier-batch", repo=OURS),
    "fork-on-this-lane": lambda own, _other: pr_row(3, f"{own}earlier-batch", repo=FORK),
    # A fork under our own owner, and another repository that took our full name: repository
    # identity is the id.
    "sibling-fork-on-this-lane": lambda own, _other: pr_row(3, f"{own}earlier-batch",
                                                            repo=SIBLING_FORK),
    "namesake-on-this-lane": lambda own, _other: pr_row(3, f"{own}earlier-batch", repo=NAMESAKE),
    "no-head-repository": lambda own, _other: pr_row(3, f"{own}earlier-batch", repo=None),
    "ours-on-the-other-lane": lambda _own, other: pr_row(3, f"{other}earlier-batch", repo=OURS),
}
#: The lead lane's model edit for a tick that delivers (an existing catalog template).
_LEAD_TEMPLATE = "gather/queries/cmdb/host-owner.md"


def _lead_tick(w: Any, monkeypatch: Any, label: str) -> tuple[Any, Any, LeadStep]:
    """The lead lane awake on one queued run (a curation request in the learning store), the real
    lead author editing one template: `(paths, run name, step)`. The pitfalls and lift knobs stay
    shut. The product checkout carries the cmdb adapter the lane declares its systems from."""
    t = w.t
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1000")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")
    paths = drain_paths(t, product_repo(w.scratch / label, adapters=("cmdb",)))
    run = queued_run(t, paths, label).name
    step = LeadStep(executed={run: [executed_lead("cmdb.owner-by-tag")]},
                    edits={run: {_LEAD_TEMPLATE: "\nAlso check the asset tag.\n"}})
    return paths, run, step


@postgres
@pytest.mark.parametrize("holder", sorted(_LEASE_ROWS))
@pytest.mark.parametrize("drain", ["author", "lead"])
def test_od8_an_open_tenant_pr_of_the_lane_holds_the_writer_lease_and_nothing_else_does(
        world, monkeypatch, caplog, drain, holder):  # noqa: F811 — the imported fixture
    """Only an open PR of our own tenant repository on this lane's prefix that no batch made is a
    foreign PR holding the lane: the tick opens no PR and its batch goes to a person (D6; was: no
    batch started, #1278 retired the forge-side lease check at batch start). A fork's, a namesake's
    or a headless PR on the prefix, or our own PR on the other lane's, holds nothing: the tick
    opens its PR and the batch is in review."""
    t = world.t
    own, other = (LESSONS_PREFIX, LEAD_PREFIX) if drain == "author" else (LEAD_PREFIX, LESSONS_PREFIX)
    t.forge.add_pr(_LEASE_ROWS[holder](own, other))
    box = BoxSpy()
    if drain == "author":
        paths = world.paths
        queue(paths, [S.finding_row("f1", run_id="f1")])
        curator = S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})
        trigger = CuratorTrigger(author=curator)
        with caplog.at_level(logging.INFO):
            rc = author_drain(t, paths, trigger=trigger, box=box)
        ran = trigger.calls

        def still_queued() -> bool:
            return items_of(paths)[("finding", "f1")].status == "waiting"
    else:
        paths, run, step = _lead_tick(world, monkeypatch, "p4-lease")
        with caplog.at_level(logging.INFO):
            rc = lead_author_drain(t, paths, box=box, run_lead_author=step,
                                   run_pitfalls=lambda *_a, **_k: 0)
        ran = step.served

        def still_queued() -> bool:
            return items_of(paths)[("curation_request", run)].status == "waiting"

    assert rc == 0, critical_text(caplog)
    [batch] = batches(world.dsn, t.tenant_id)
    if holder == "ours-on-this-lane":
        # Design D6 (#1278): the writer lease is the store's lane gate; an open PR of our repository
        # on the prefix that no batch of the store made is met when the batch would open its PR (after
        # authoring): it opens none and goes to a person, its item kept in the batch.
        assert ran
        assert t.forge.creates == []
        assert batch.phase == "needs_person", (batch.phase, critical_text(caplog))
        assert not still_queued(), "the item went back to waiting instead of staying in the batch"
    else:
        (branch, _tip), = remote_branches(t.remote, own).items()
        assert [c["head"] for c in t.forge.creates] == [branch]
        assert ran
        assert batch.phase == "in_review", batch.phase


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


def _sweeps_under(folder: Path):
    """`pick` for P3's `LockAudit`: labels `sweep` the first removal of anything under
    `folder`, or rename of something out of it (a name relative to a folder descriptor is
    resolved through `/proc/self/fd`)."""
    top = os.path.realpath(folder)
    seen: set[str] = set()

    def pick(event: str, args: tuple) -> str | None:
        if event not in {"os.remove", "os.rmdir", "shutil.rmtree", "os.rename"} or "sweep" in seen:
            return None
        path = args[0]
        dir_fd = args[2] if event == "os.rename" else (args[1] if len(args) > 1 else None)
        if not isinstance(path, (str, bytes, os.PathLike)):
            return None
        path = os.fsdecode(path)
        if isinstance(dir_fd, int) and dir_fd >= 0 and not os.path.isabs(path):
            path = os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), path)
        path = os.path.abspath(path)
        if path != top and not path.startswith(top + os.sep):
            return None
        seen.add("sweep")
        return "sweep"
    return pick


def test_o_sweep_publish_sweeps_a_draft_whose_owner_died_and_keeps_a_live_owners(
        p4_tenant, tmp_path):
    """The next publish sweeps, under the tenant lock, a draft whose owner process died; this
    live process's draft survives (control), its owner record naming this pid and start time."""
    t = p4_tenant
    _owner_process(t, tmp_path, "orphan", hold=False)
    mine = t.open_delivery().start_batch("mine", lanes=("lessons",))
    assert draft_entries(t) == ["mine", "orphan"], "control: both drafts stand before the publish"
    audit = LockAudit(t.tenant, _sweeps_under(drafts_dir(t)))

    with audit:
        t.publish()

    assert draft_entries(t) == ["mine"], draft_entries(t)
    assert mine.draft_root.is_dir()
    assert [label for label, _ in audit.probes] == ["sweep"], audit.probes
    assert all("busy" in verdict for _, verdict in audit.probes), "the sweep ran outside the lock"
    record = owner_record(draft_folder(mine))
    assert record["pid"] == os.getpid(), record
    assert str(record["start"]) == process_start(os.getpid()), record


def test_o_sweep_a_live_owners_draft_survives_publish_until_its_owner_exits(p4_tenant, tmp_path):
    """Liveness is the owner's, not the draft's age: another live process's draft survives a
    publish and is swept once that process exits."""
    t = p4_tenant
    owner = _owner_process(t, tmp_path, "held", hold=True)
    try:
        record = owner_record(drafts_dir(t) / "held")
        assert record["pid"] == owner.pid, record
        assert str(record["start"]) == process_start(owner.pid), record
        t.publish()
        assert draft_entries(t) == ["held"], "a live owner's draft was swept"
    finally:
        (tmp_path / "release-held").write_text("go", encoding="utf-8")
        owner.communicate(timeout=300)
    assert owner.returncode == 0

    t.publish()

    assert draft_entries(t) == [], draft_entries(t)


def test_o_sweep_an_owner_record_naming_a_live_pid_with_another_start_time_is_dead(p4_tenant):
    """An owner is pid and start time: a record naming this running pid with another start time
    (a reused pid) is dead, so its draft is swept; this process's true record survives."""
    t = p4_tenant
    d = t.open_delivery()
    reused = d.start_batch("reused", lanes=("lessons",))
    kept = d.start_batch("kept", lanes=("lessons",))
    true_start = process_start(os.getpid())
    write_owner(draft_folder(reused), os.getpid(), str(int(true_start) + 1))
    assert owner_record(draft_folder(kept))["pid"] == os.getpid()

    t.publish()

    assert draft_entries(t) == ["kept"], draft_entries(t)
    assert kept.draft_root.is_dir()


def test_o_sweep_a_dead_owners_half_built_temporary_is_swept_under_the_lock(p4_tenant):
    """A build cut off before its rename leaves a dot-named temporary holding its owner record;
    that owner being dead, the next publish sweeps it under the tenant lock. A live draft
    survives (control)."""
    t = p4_tenant
    kept = t.open_delivery().start_batch("kept", lanes=("lessons",))
    temp = drafts_dir(t) / ".halfbuilt-0a1b2c"
    (temp / "stage" / "agent" / "lessons").mkdir(parents=True)
    (temp / "stage" / "agent" / "lessons" / "seed.md").write_text("half\n", encoding="utf-8")
    write_owner(temp, *_dead_process())
    assert draft_entries(t) == [".halfbuilt-0a1b2c", "kept"], "control: the temporary is seen"
    audit = LockAudit(t.tenant, _sweeps_under(drafts_dir(t)))

    with audit:
        t.publish()

    assert draft_entries(t) == ["kept"], draft_entries(t)
    assert kept.draft_root.is_dir()
    assert [label for label, _ in audit.probes] == ["sweep"], audit.probes
    assert all("busy" in verdict for _, verdict in audit.probes), "the sweep ran outside the lock"


def test_control_o_sweep_a_publish_right_after_start_batch_keeps_the_fresh_draft(p4_tenant):
    """Control: a publish right after `start_batch` in this live process keeps the fresh draft
    and leaves no dot-named entry beside it."""
    t = p4_tenant
    batch = t.open_delivery().start_batch("fresh", lanes=("lessons",))

    t.publish()

    assert draft_entries(t) == ["fresh"]
    assert batch.draft_root.is_dir()


# ---------------------------------------------------------------------------------------------
# OD16: what the drain hands its lane entries
# ---------------------------------------------------------------------------------------------


def _one_batch(batches: list[Any]) -> Any:
    """The one batch every call of a tick was handed (the same object each time)."""
    assert batches, "no lane entry was called"
    assert all(b is batches[0] for b in batches), batches
    return batches[0]


@postgres
def test_od16_the_author_drain_hands_its_curators_the_ticks_batch_and_product_rooted_paths(
        world, caplog):  # noqa: F811 — the imported fixture
    """Every `trigger_author` call of one tick gets this tick's `batch=` (its draft under
    `<T>/drafts/`, mounted as `staged`; the branch pushed) and the drain's own product-rooted
    `paths`, never a draft-rooted `LoopPaths`."""
    t = world.t
    paths, trigger, box = _author_tick(world)
    queue(paths, [S.world_row("w1", systems=["cmdb"])], channel=QUESTIONER_FINDINGS)
    product = Path(paths.repo_root)

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 0, critical_text(caplog)
    assert trigger.calls == ["author", "questioner_curator"], trigger.calls
    assert [{kind for kind, _key, _payload in items} for items in trigger.items_seen] == [
        {"finding"}, {"questioner_finding"}], "a curator was handed items of another kind (A2 D1)"
    batch = _one_batch(trigger.batches)
    draft = Path(batch.draft_root)
    # `draft_root` is `<T>/drafts/<id>/stage`, the folder beside `owner`.
    assert draft.name == "stage", draft
    assert draft_folder(batch).parent == drafts_dir(t), draft
    [staged] = [Path(m.source) for m in box.requests[0].mounts if m.kind == "staged"]
    assert staged == draft, (staged, draft)
    assert list(remote_branches(t.remote)) == [batch.branch]
    assert all(p is paths for p in trigger.paths_seen), trigger.paths_seen
    assert Path(paths.repo_root) == product
    assert not draft.is_relative_to(product)


@postgres
def test_od16_the_lead_drain_hands_both_steps_the_ticks_batch_and_product_rooted_paths(
        world, monkeypatch, caplog):  # noqa: F811 — the imported fixture
    """A lead tick serving a run and curating a pitfall hands both steps the same tick's
    `batch=` and the product-rooted `paths`; the pitfalls curator hands its spawn that batch's
    draft root."""
    from defender.learning.core.state import PITFALLS
    from defender.tests.support.learning.core._declared870 import shim_row

    t = world.t
    paths, run, step = _lead_tick(world, monkeypatch, "p4-od16")
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    queue(paths, [shim_row("p4-run:1")], channel=PITFALLS)
    pitfalls, box = PitfallsStep("- **Name the unnested column.**"), BoxSpy()

    with caplog.at_level(logging.INFO):
        rc = lead_author_drain(t, paths, box=box, run_lead_author=step, run_pitfalls=pitfalls)

    assert rc == 0, critical_text(caplog)
    assert step.served == [run]
    batch = _one_batch(step.batches + pitfalls.batches)
    assert pitfalls.batches, "the pitfalls step was never called"
    draft = Path(batch.draft_root)
    # `draft_root` is `<T>/drafts/<id>/stage`, the folder beside `owner`.
    assert draft.name == "stage", draft
    assert draft_folder(batch).parent == drafts_dir(t), draft
    [staged] = [Path(m.source) for m in box.requests[0].mounts if m.kind == "staged"]
    assert staged == draft
    assert list(remote_branches(t.remote, LEAD_PREFIX)) == [batch.branch]
    assert all(p is paths for p in step.paths_seen + pitfalls.paths_seen)
    assert pitfalls.repo_roots, "the pitfalls curator never spawned"
    assert all(r == draft for r in pitfalls.repo_roots), pitfalls.repo_roots
    assert not draft.is_relative_to(Path(paths.repo_root))


# ---------------------------------------------------------------------------------------------
# R-L4: a fault discards the draft
# ---------------------------------------------------------------------------------------------


class _FaultingStart(BoxSpy):
    """`BoxSpy` whose start raises `BoxFault` after noting the drafts present at the call."""

    def __init__(self, t: Any) -> None:
        super().__init__()
        self.t = t
        self.drafts_at_start: list[list[str]] = []

    def start(self, request: Any, **_kw: Any) -> Any:
        from defender.execution.box_codec import BoxFault

        self.requests.append(request)
        self.drafts_at_start.append(draft_entries(self.t))
        raise BoxFault("p4: the box did not start")


def _fault(kind: str) -> BaseException:
    from defender.execution.box_codec import BoxFault
    from defender.learning.leads.lead_extraction import LeadAuthorError

    return BoxFault("p4: the box went away mid-batch") if kind == "mid-batch-box-fault" \
        else LeadAuthorError("p4: the curator failed")


@postgres
@pytest.mark.parametrize("fault", ["box-start-fault", "mid-batch-box-fault", "curator-fault"])
@pytest.mark.parametrize("drain", ["author", "lead"])
def test_r_l4_a_faulted_tick_leaves_no_draft_behind(
        world, monkeypatch, caplog, drain, fault):  # noqa: F811 — the imported fixture
    """Whatever faults (the box start, the box mid-batch, the curator or lead step), the tick
    leaves nothing under `<T>/drafts/`; the draft was there while the tick ran (control)."""
    t = world.t
    seen: list[list[str]] = []
    box: BoxSpy = _FaultingStart(t) if fault == "box-start-fault" else BoxSpy()

    def failing(*_a: Any, **_k: Any) -> None:
        seen.append(draft_entries(t))
        raise _fault(fault)

    if drain == "author":
        paths = world.paths
        queue(paths, [S.finding_row("f1", run_id="f1")])
        curator = S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")}, also=failing)
        with caplog.at_level(logging.INFO):
            author_drain(t, paths, trigger=CuratorTrigger(author=curator), box=box)
    else:
        paths, _run, _step = _lead_tick(world, monkeypatch, "p4-fault")
        with caplog.at_level(logging.INFO):
            lead_author_drain(t, paths, box=box, run_lead_author=failing,
                              run_pitfalls=lambda *_a, **_k: 0)

    if fault == "box-start-fault":
        assert box.drafts_at_start, "the box was never started"
        assert all(box.drafts_at_start), f"no draft at the box's start: {box.drafts_at_start}"
        assert seen == [], "a lane step ran without a box"
    else:
        assert seen, "the failing step never ran"
        assert all(seen), f"the failing step saw no draft: {seen}"
    assert draft_entries(t) == [], draft_entries(t)


# ---------------------------------------------------------------------------------------------
# R-I3: the drains' default box start never falls back to an unsandboxed lane
# ---------------------------------------------------------------------------------------------


def _default_box_tick(w: Any, monkeypatch: Any, drain: str, label: str) -> tuple[int, list]:
    """One tick through the real drain entry with no `start_box`/`stop_box` seam (production's
    default box start): `(rc, the lane calls made)`."""
    t = w.t
    ran: list[str] = []
    seams = {"client": t.forge.client, "identity": t.vault.identity(), "directory": t.directory}
    if drain == "author":
        paths = w.paths
        queue(paths, [S.finding_row("f1", run_id="f1")])

        def trigger(*_a: Any, **_k: Any) -> None:
            ran.append("curator")

        return run_stage(lambda: drains().author_drain(paths, trigger_author=trigger, **seams)), ran
    paths, _run, _step = _lead_tick(w, monkeypatch, label)

    def lead(*_a: Any, **_k: Any) -> None:
        ran.append("lead")

    def pitfalls(*_a: Any, **_k: Any) -> int:
        ran.append("pitfalls")
        return 0

    return run_stage(lambda: drains().lead_author_drain(
        paths, run_lead_author=lead, run_pitfalls=pitfalls, **seams)), ran


@postgres
@pytest.mark.parametrize("drain", ["author", "lead"])
def test_r_i3_a_drain_with_no_daemon_refuses_even_under_the_unsandboxed_opt_out(
        world, tmp_path, monkeypatch, caplog, drain):  # noqa: F811 — the imported fixture
    """With the default box start, the operator opt-out set and no reachable daemon, the drain
    refuses (exit 2, no lane step, no draft) rather than run on a host executor. Control: over a
    fake daemon (`_box1195.FakeDaemon` on `PATH`) the same tick runs its lane."""
    from defender.tests.support.sandbox._box1195 import FakeDaemon

    t = world.t
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    monkeypatch.setenv("DEFENDER_BOX_RUNTIME", "runc")
    monkeypatch.setenv("DOCKER_HOST", f"unix://{tmp_path / 'no-daemon.sock'}")

    with caplog.at_level(logging.INFO):
        rc, ran = _default_box_tick(world, monkeypatch, drain, "p4-sandbox-down")

    assert rc == 2, critical_text(caplog)
    assert ran == [], ran
    assert draft_entries(t) == []
    assert remote_branches(t.remote, LESSONS_PREFIX if drain == "author" else LEAD_PREFIX) == {}

    daemon = FakeDaemon(tmp_path / "daemon")
    daemon.install(monkeypatch)
    caplog.clear()
    with caplog.at_level(logging.INFO):
        rc, ran = _default_box_tick(world, monkeypatch, drain, "p4-sandbox-up")
    assert rc == 0, critical_text(caplog)
    assert ran, "the control never got past the box start"
    assert draft_entries(t) == []
