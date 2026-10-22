"""#1108 P4 slice S-B — the launch-time publish child, in-process against P3's fakes (O11), and
wired into `run.main` through the `publish=` seam.

The child (assumed entry `version_control.publish_for_run`, see `_s_b_support`) accepts the
tenant from id + data root, reads the tenant row's forge binding and the issuer config file
itself, publishes through P3's real delivery path, and reports ONE outcome. Each case plants a
REAL fault through P3's fakes or real files (issuer 403 / unreachable issuer / unreachable
forge / a stalled fetch / tenant lock held / dirty clone / unprotected `main` / a merged commit
whose `.tenant-id` names another tenant) and asserts the outcome CLASS, never which exception
the child caught (P4-C23: P3 folds them into one `DeliveryRefused`; the child classifies first).

Obligations: O-STALE (classification; misconfiguration refuses), O7b (a merged PR is read, or
the run is recorded stale; lock-busy is fresh iff `current` already equals `origin/main`),
O-BUDGET child half (a stalled network phase ends within the child's own timeouts, leaving no
process, no `index.lock`, no lock held), O9 (misconfiguration refuses the run before any model
call), O8 child half (the config path lies under no box mount source: `test_run_copy.py`).
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

import httpx
import pytest

from defender.tests.tenancy.tenant_1108_delivery._identity import AUDIENCE, ISSUER
from defender.tests.tenancy.tenant_1108_delivery._support import quiet
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import (
    OTHER_TENANT_ID,
    Trickle,
    bind_forge,
    current_commit,
    export_dir,
    unbind_forge,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        yield t


@pytest.fixture
def issuer_config(tmp_path):
    return B.write_issuer_config(tmp_path / "operator")


def _lock(t):
    from defender.learning.author.version_control import tenant_lock

    return tenant_lock(t.tenant)


def _unchanged(t) -> None:
    assert current_commit(t.tenant) == t.commit, (
        "a refused publish moved `current` (it must publish nothing)")


def _stale(line: str, kind: str) -> None:
    assert B.outcome_class(line) == f"stale:{kind}", (
        f"O-STALE: expected stale:{kind}, the child reported {line!r}")
    assert B.outcome_detail(line), f"O-STALE: a stale outcome names its reason: {line!r}"


# --- fresh (positive control for every class below) -------------------------------------------

def test_o7b_a_merge_on_origin_is_published_and_reported_fresh_at_the_merge(tenant, issuer_config):
    """O7b: after a PR merges on the fake origin, the child fetches, publishes the merge as
    `current`, and reports `fresh <merge>`."""
    merged = tenant.merge(B.MERGE_FILES)
    line = B.run_child(tenant, issuer_config)
    assert B.outcome_class(line) == "fresh", line
    assert B.outcome_detail(line) == merged, line
    assert current_commit(tenant.tenant) == merged
    lesson = export_dir(tenant.tenant, merged) / B.LESSON
    assert B.MERGED_MARK in lesson.read_text(encoding="utf-8")


# --- O7b: tenant lock held by a drain ---------------------------------------------------------

def test_o7b_lock_held_and_origin_ahead_is_stale_transient(tenant, issuer_config):
    """O7b/O-STALE: a drain holds the tenant lock and origin has a merge `current` lacks: the
    child does not wait — `stale:transient` (lock busy), `current` unchanged."""
    tenant.merge(B.MERGE_FILES)
    with _lock(tenant):
        line = B.run_child(tenant, issuer_config)
    _stale(line, "transient")
    _unchanged(tenant)


def test_o7b_lock_held_but_current_already_equals_origin_main_is_fresh(tenant, issuer_config):
    """O7b: same lock, but `current` already equals the fetched `origin/main`: `fresh`."""
    assert tenant.origin_main() == tenant.commit
    with _lock(tenant):
        line = B.run_child(tenant, issuer_config)
    assert B.outcome_class(line) == "fresh", line
    assert B.outcome_detail(line) == tenant.commit, line


# --- stale:transient --------------------------------------------------------------------------

def _raising_identity(t):
    from defender.learning.author.version_control import ForgejoIdentity

    def down(request):
        raise httpx.ConnectError("issuer unreachable", request=request)

    return ForgejoIdentity(tenant_id=t.tenant_id, issuer=ISSUER, role=f"tenant-{t.tenant_id}",
                           audience=AUDIENCE, client=httpx.Client(transport=httpx.MockTransport(down)))


def test_o_stale_an_unreachable_issuer_is_transient(tenant, issuer_config):
    tenant.merge(B.MERGE_FILES)
    line = B.run_child(tenant, issuer_config, identity=_raising_identity(tenant))
    _stale(line, "transient")
    _unchanged(tenant)


def test_o_stale_an_unreachable_forge_is_transient(tenant, issuer_config):
    tenant.merge(B.MERGE_FILES)

    def down(request):
        return httpx.ConnectError("forge unreachable", request=request)

    tenant.forge.fault = down
    line = B.run_child(tenant, issuer_config)
    _stale(line, "transient")
    _unchanged(tenant)


def test_o_budget_a_stalled_fetch_ends_within_the_childs_timeout_and_leaves_nothing_behind(
        tenant, issuer_config):
    """O-BUDGET (child half): origin answers the fetch slowly for ever (P3 `Trickle`). With a
    short network timeout the child reports `stale:transient` well inside the 60 s budget,
    leaves no git process in the clone, no `index.lock`, and the tenant lock free."""
    tenant.merge(B.MERGE_FILES)
    stop = threading.Event()
    tenant.server.on_service = lambda service: (
        Trickle(stop) if service == "git-upload-pack" else None)
    tenant.server.rearm()
    started = time.monotonic()
    try:
        line = B.run_child(tenant, issuer_config, network_timeout=2.0)
    finally:
        elapsed = time.monotonic() - started
        stop.set()
    _stale(line, "transient")
    assert elapsed < 30, f"O-BUDGET: the stalled publish took {elapsed:.1f}s"
    clone = B.clone_dir(tenant)
    assert quiet(clone, seconds=5) == [], "a git process outlived the child's publish"
    assert not (clone / ".git" / "index.lock").exists()
    with _lock(tenant):
        pass
    _unchanged(tenant)


# --- stale:operator ---------------------------------------------------------------------------

def test_o_stale_an_issuer_auth_refusal_is_operator(tenant, issuer_config):
    """A refused login (the issuer answers 403: bad `secret_id`/policy) needs a human."""
    tenant.merge(B.MERGE_FILES)
    tenant.vault.status = 403
    tenant.vault.body = {"errors": ["permission denied"]}
    line = B.run_child(tenant, issuer_config)
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_a_dirty_clone_is_operator(tenant, issuer_config):
    tenant.merge(B.MERGE_FILES)
    (B.clone_dir(tenant) / "agent" / "lessons" / "stray-untracked.md").write_text(
        "an operator's stray edit\n", encoding="utf-8")
    line = B.run_child(tenant, issuer_config)
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_an_unprotected_main_is_operator(tenant, issuer_config):
    tenant.merge(B.MERGE_FILES)
    tenant.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    line = B.run_child(tenant, issuer_config)
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_a_merged_commit_naming_another_tenant_is_operator(tenant, issuer_config):
    """A human merged an `agent/.tenant-id` naming another tenant: refused on content."""
    tenant.merge({"agent/.tenant-id": f"{OTHER_TENANT_ID}\n"})
    line = B.run_child(tenant, issuer_config)
    _stale(line, "operator")
    _unchanged(tenant)


# --- misconfiguration: refused, before any network call ---------------------------------------

def _network_marks(t) -> tuple[int, int, int]:
    return len(t.vault.calls), len(t.forge.requests), len(t.server.seen)


@pytest.mark.parametrize("missing", ["issuer-config", "forge-binding"])
def test_o_stale_misconfiguration_is_refused_before_any_network_call(
        tenant, issuer_config, tmp_path, missing):
    """O-STALE/O9: no issuer config file, or no forge binding in the tenant row, is decided
    locally: the child reports `misconfigured <reason>` (S-B's pick: the same report-line channel
    as the other outcomes) and makes no issuer, forge or git request. Control: `test_o7b_a_merge_on_origin_is_published...` (both present)."""
    tenant.merge(B.MERGE_FILES)
    config = issuer_config
    if missing == "issuer-config":
        config = tmp_path / "operator" / "playground-issuer" / "client" / "absent.json"
    else:
        unbind_forge(tenant)
    entry = B.child_entry()  # resolved first: a missing entry is red, never a "refusal"
    before = _network_marks(tenant)
    line = entry(tenant.tenant_id, data_root=tenant.data_root, issuer_config=config,
                 client=tenant.forge.client, identity=tenant.vault.identity())
    assert B.outcome_class(line) == "misconfigured", line
    assert _network_marks(tenant) == before, "a misconfigured child went to the network"
    _unchanged(tenant)


# --- wired into run.main ----------------------------------------------------------------------

def _child_publish(t, issuer_config):
    """`run.main`'s `publish=` bound to the REAL child in-process (identifiers from the parent
    are ignored here; the child is told its tenant by closure, as the CLI would by argv)."""
    return lambda *a, **k: B.run_child(t, issuer_config)


def test_o7b_a_run_launched_after_a_merge_reads_and_stamps_the_merge(tenant, issuer_config,
                                                                      tmp_path):
    """O7b end to end: merge on the fake origin, launch; the run's copy holds the merged lesson,
    its stamp and `knowledge_source` name the merge commit, kind fresh."""
    merged = tenant.merge(B.MERGE_FILES)
    out = B.launch(tenant, tmp_path, publish=_child_publish(tenant, issuer_config))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert B.MERGED_MARK in out.seen[0].agent_files[B.LESSON_REL].decode()
    assert B.stamped_commit(out.stamp_after) == {"commit": merged}
    source = B.knowledge_source(out.stamp_after)
    assert (source.get("kind"), source.get("commit")) == ("fresh", merged), source


def test_o7b_a_run_launched_while_a_drain_holds_the_lock_runs_stale_on_current(
        tenant, issuer_config, tmp_path):
    """O7b: with the lock held by a drain, the run is `stale` on the last snapshot."""
    tenant.merge(B.MERGE_FILES)
    with _lock(tenant):
        out = B.launch(tenant, tmp_path, publish=_child_publish(tenant, issuer_config))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert B.SEEDED_MARK in out.seen[0].agent_files[B.LESSON_REL].decode()
    source = B.knowledge_source(out.stamp_after)
    assert (source.get("kind"), source.get("stale_kind"), source.get("commit")) == (
        "stale", "transient", tenant.commit), source


@pytest.mark.parametrize("missing", ["issuer-config", "forge-binding"])
def test_o9_a_misconfigured_tenant_refuses_the_run_before_any_model_call(
        tenant, issuer_config, tmp_path, missing):
    """O9: missing forge binding or issuer config refuses the run before its lifecycle, though a
    snapshot exists. Control: the O7b launches above."""
    config: Path = issuer_config
    if missing == "issuer-config":
        config = issuer_config.with_name("absent.json")
    else:
        unbind_forge(tenant)
    out = B.launch(tenant, tmp_path, publish=_child_publish(tenant, config))
    assert not out.reached, f"O9: a misconfigured tenant's run reached its box: {out.text()}"
    assert out.raised is None or not isinstance(out.raised, TypeError), out.text()
    assert out.refusal is not None, out.text()


# --- O-BUDGET, parent half (OD11): a REAL child process under a REAL lock ---------------------
#
# The parent launcher (`run.launch_publish`, assumed seam) runs the REAL child's process entry
# (`publish_child_main`) in a subprocess whose fakes are rebuilt inside it (`_s_b_support.
# CHILD_WRAPPER`). Budgets are small but must exceed the child's interpreter start-up and
# imports, which the budget counts; the locked phase is slowed through the child's one
# injectable slow point (`locked_hook`).

WORKTREE = Path(__file__).resolve().parents[4]
#: The parent's budget in these tests, and how long the locked phase is held.
BUDGET = 4.0
LOCKED_SLEEP = 6.0
#: Scheduling slack on every wall-clock bound.
SLACK = 8.0


@pytest.fixture
def child_env(monkeypatch):
    """The child subprocess imports this worktree's `defender` (and the test fakes)."""
    import os

    monkeypatch.setenv("PYTHONPATH", f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")


def _no_leftovers(t, spec: Path) -> None:
    clone = B.clone_dir(t)
    assert quiet(clone, naming=(str(spec),), seconds=5) == [], (
        "O-BUDGET: a child (or its git) outlived the launch")
    assert not (clone / ".git" / "index.lock").exists(), "O-BUDGET: index.lock left behind"
    with _lock(t):  # the tenant lock is free again
        pass


def test_o_budget_the_parent_stops_waiting_at_the_budget_in_the_network_phase(
        tenant, issuer_config, tmp_path, child_env):
    """O-BUDGET: origin stalls the fetch for ever and the child's own network timeout is far
    beyond the budget: the parent stops waiting at the budget, ends the child (no process, no
    `index.lock`, lock free) and reports `stale:transient`; `current` is unchanged."""
    tenant.merge(B.MERGE_FILES)
    stop = threading.Event()
    tenant.server.on_service = lambda service: (
        Trickle(stop, limit=300.0) if service == "git-upload-pack" else None)
    tenant.server.rearm()
    command, spec, marks = B.child_command(tenant, tmp_path, issuer_config,
                                           network_timeout=300.0, locked_sleep=0)
    launch = B.launcher()
    started = time.monotonic()
    try:
        line = launch(tenant.tenant_id, data_root=tenant.data_root, budget=BUDGET,
                      command=command)
    finally:
        elapsed = time.monotonic() - started
        stop.set()
    assert (marks / "started").exists(), "premise: the child process ran"
    _stale(line, "transient")
    assert elapsed < BUDGET + SLACK, f"O-BUDGET: the launch waited {elapsed:.1f}s"
    assert not (marks / "locked").exists(), "premise: the child never reached its locked phase"
    _no_leftovers(tenant, spec)
    _unchanged(tenant)


def test_o_budget_a_child_holding_the_lock_is_allowed_to_finish(tenant, issuer_config, tmp_path,
                                                                child_env):
    """O-BUDGET: the child takes the tenant lock inside the budget and then holds it past the
    budget (its locked phase is slowed). The parent does not kill it: it waits for the child to
    finish, reports `fresh <merge>`, `current` is the merge, and nothing is left behind. It
    never waits past budget + locked phase."""
    merged = tenant.merge(B.MERGE_FILES)
    command, spec, marks = B.child_command(tenant, tmp_path, issuer_config,
                                           network_timeout=30.0, locked_sleep=LOCKED_SLEEP)
    launch = B.launcher()
    started_wall, started = time.time(), time.monotonic()
    line = launch(tenant.tenant_id, data_root=tenant.data_root, budget=BUDGET, command=command)
    elapsed = time.monotonic() - started
    locked_at = float((marks / "locked").read_text(encoding="utf-8")) - started_wall
    assert locked_at < BUDGET, (
        f"premise: the child took the lock {locked_at:.1f}s in, after the {BUDGET}s budget")
    assert (marks / "locked-done").exists(), (
        "O-BUDGET: the parent returned before the lock-holding child finished (killed it?)")
    assert B.outcome_class(line) == "fresh", line
    assert B.outcome_detail(line) == merged, line
    assert current_commit(tenant.tenant) == merged
    assert elapsed > BUDGET, "premise: the locked phase outlasted the budget"
    assert elapsed < BUDGET + LOCKED_SLEEP + SLACK, f"O-BUDGET: the launch waited {elapsed:.1f}s"
    _no_leftovers(tenant, spec)


def test_o_budget_a_run_whose_publish_ran_out_of_budget_proceeds_stale_on_the_last_snapshot(
        tenant, issuer_config, tmp_path, child_env):
    """O-BUDGET/O-STALE through `run.main`: the launcher bound to `publish=` with a stalled
    network phase — the run starts within the budget on `current`, recorded stale/transient."""
    import functools

    tenant.merge(B.MERGE_FILES)
    stop = threading.Event()
    tenant.server.on_service = lambda service: (
        Trickle(stop, limit=300.0) if service == "git-upload-pack" else None)
    tenant.server.rearm()
    command, _spec, _marks = B.child_command(tenant, tmp_path, issuer_config,
                                             network_timeout=300.0, locked_sleep=0)
    publish = functools.partial(B.launcher(), budget=BUDGET, command=command)
    started = time.monotonic()
    try:
        out = B.launch(tenant, tmp_path, publish=publish)
    finally:
        stop.set()
    assert out.reached, out.text()
    assert time.monotonic() - started < BUDGET + 2 * SLACK
    assert B.SEEDED_MARK in out.seen[0].agent_files[B.LESSON_REL].decode()
    source = B.knowledge_source(out.stamp_after)
    assert (source.get("kind"), source.get("stale_kind"), source.get("commit")) == (
        "stale", "transient", tenant.commit), source
