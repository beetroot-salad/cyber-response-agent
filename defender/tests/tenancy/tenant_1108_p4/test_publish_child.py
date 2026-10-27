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

def test_o7b_a_merge_on_origin_is_published_and_reported_fresh_at_the_merge(tenant, tmp_path):
    """O7b/O8: after a PR merges on the fake origin, the child logs in ITSELF from the issuer
    config file (AppRole: the file's role_id/secret_id, nothing injected), fetches with the
    token the issuer minted, publishes the merge as `current`, and reports `fresh <merge>` —
    a line carrying none of the login material or the config path."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import ROLE_ID, SECRET_ID

    merged = tenant.merge(B.MERGE_FILES)
    with B.real_login(tenant, tmp_path / "operator") as (vault, config, secrets):
        line = B.run_child(tenant, config, login=vault)
    assert vault.logins() == [{"role_id": ROLE_ID, "secret_id": SECRET_ID}], (
        "O8: the child did not log in from the config file")
    assert tenant.server.authorized("git-upload-pack"), "the fetch never carried the minted token"
    assert B.leaks(secrets, report_line=line) == []
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

def test_o_stale_an_issuer_auth_refusal_is_operator(tenant, tmp_path):
    """A refused login (the config's `secret_id` is not the one the issuer holds) needs a human:
    `stale:operator`, and the reason names none of the login material."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import write_issuer_config

    tenant.merge(B.MERGE_FILES)
    with B.real_login(tenant, tmp_path / "operator") as (vault, _config, secrets):
        wrong = write_issuer_config(tmp_path / "wrong" / "playground-issuer" / "client",
                                    secret_id="s-b-revoked-secret-id-31d0")
        line = B.run_child(tenant, wrong, login=vault)
    assert vault.logins(), "premise: the child tried to log in"
    _stale(line, "operator")
    assert B.leaks((*secrets, "s-b-revoked-secret-id-31d0", str(wrong)), report_line=line) == []
    _unchanged(tenant)


def test_o_stale_the_forge_rejecting_the_minted_token_is_operator(tenant, issuer_config):
    """The origin refuses the token the issuer minted (the forge's integration does not trust
    it): `stale:operator`."""
    tenant.merge(B.MERGE_FILES)
    tenant.server.refuse.add("git-upload-pack")
    line = B.run_child(tenant, issuer_config)
    assert tenant.server.offered_and_refused("git-upload-pack"), "premise: the token was refused"
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_a_diverged_clone_is_operator(tenant, issuer_config):
    """STALE-DIVERGED: the clone holds an unpushed local commit and origin moved on: the
    fast-forward cannot happen — `stale:operator`, `current` unchanged."""
    from defender.tests.tenancy.tenant_1108_p4._support import git

    clone = B.clone_dir(tenant)
    (clone / "agent" / "lessons" / "local-only.md").write_text("local\n", encoding="utf-8")
    git(clone, "add", "-A")
    git(clone, "commit", "-m", "an operator's local commit, never pushed")
    tenant.merge(B.MERGE_FILES)
    line = B.run_child(tenant, issuer_config)
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_a_merged_link_is_operator(tenant, issuer_config):
    """A human merged a symlink under `agent/`: refused on content — `stale:operator`."""
    from defender.tests.tenancy.tenant_1108_p4._support import index_entry, push_to_remote

    push_to_remote(tenant.p3, tenant.scratch,
                   lambda w: index_entry(w, "120000", "agent/lessons/evil.md", data=b"/etc/passwd"),
                   "a link merged by a human", stage=False)
    line = B.run_child(tenant, issuer_config)
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_an_issuer_api_timeout_is_transient(tenant, tmp_path):
    """The issuer's login endpoint times out: `stale:transient`."""
    tenant.merge(B.MERGE_FILES)
    with B.real_login(tenant, tmp_path / "operator") as (_vault, config, _secrets):
        def slow(request):
            raise httpx.ReadTimeout("issuer read timed out", request=request)

        timing_out = type("TimingOut", (), {"transport": httpx.MockTransport(slow)})()
        line = B.run_child(tenant, config, login=timing_out)
    _stale(line, "transient")
    _unchanged(tenant)


def test_o_stale_a_forge_api_timeout_is_transient(tenant, issuer_config):
    tenant.merge(B.MERGE_FILES)
    tenant.forge.fault = lambda request: httpx.ReadTimeout("forge read timed out", request=request)
    line = B.run_child(tenant, issuer_config)
    _stale(line, "transient")
    _unchanged(tenant)


def test_o7b_lock_held_with_the_clone_at_origin_main_but_current_behind_is_stale(
        tenant, issuer_config):
    """O7b: the clone's HEAD already equals `origin/main` (fast-forwarded outside a publish) but
    `current` still names the older export, and a drain holds the lock: the run cannot read the
    merge, so the outcome is stale — never fresh."""
    from defender.tests.tenancy.tenant_1108_p4._support import git

    merged = tenant.merge(B.MERGE_FILES)
    clone = B.clone_dir(tenant)
    git(clone, "fetch", str(tenant.remote), "+refs/heads/*:refs/remotes/origin/*")
    git(clone, "merge", "--ff-only", "refs/remotes/origin/main")
    assert git(clone, "rev-parse", "HEAD") == merged
    assert current_commit(tenant.tenant) == tenant.commit
    with _lock(tenant):
        line = B.run_child(tenant, issuer_config)
    assert B.outcome_class(line).startswith("stale:"), (
        f"O7b: `current` is behind origin/main and could not move, yet the child said {line!r}")
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


def _force_main(t, how: str) -> str:
    """Move the fake origin's `main` to a commit that does not descend from `current`: back to
    an ancestor (`rewound`), or to a parentless commit of the same tree (`force-pushed`)."""
    import subprocess

    from defender.tests.tenancy.tenant_1108_p4._support import git

    if how == "rewound":
        merged = t.merge(B.MERGE_FILES)
        t.publish()
        assert current_commit(t.tenant) == merged, "premise: current is the merge"
        target = t.commit
    else:
        tree = git(t.remote, "rev-parse", f"{current_commit(t.tenant)}^{{tree}}")
        target = subprocess.run(  # noqa: S603 — the test's own history rewrite
            ["git", "-C", str(t.remote), "-c", "user.name=s-b", "-c", "user.email=s-b@test",
             "commit-tree", tree, "-m", "s-b: history rewritten on origin"],
            check=True, capture_output=True, text=True).stdout.strip()
    git(t.remote, "update-ref", "refs/heads/main", target)
    assert t.origin_main() == target
    return target


@pytest.mark.parametrize("how", ["rewound", "force-pushed"])
def test_n2_origin_rewritten_to_a_non_descendant_of_current_is_operator_and_current_stays(
        tenant, issuer_config, how):
    """N2 (pins the fast-forward-only invariant A-MISMATCH rests on): origin's `main` was
    rewound or force-pushed to a commit that does not descend from `current`. The child reports
    `stale:operator` and `current` does not move. Control: `test_o7b_a_merge_on_origin_is_
    published_and_reported_fresh_at_the_merge` (a descendant is published)."""
    target = _force_main(tenant, how)
    # Read after the rewrite: the `rewound` setup publishes its merge first, so when the child
    # runs `current` is that merge, and origin's `main` is the merge's parent (a non-descendant).
    before = current_commit(tenant.tenant)
    line = B.run_child(tenant, issuer_config)
    _stale(line, "operator")
    assert current_commit(tenant.tenant) == before, (
        f"N2: `current` moved off {before[:12]} to a non-descendant of it ({target[:12]})")


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

def _child_publish(t, issuer_config, *, login=None, lines: list | None = None):
    """`run.main`'s `publish=` bound to the REAL child in-process (identifiers from the parent
    are ignored here; the child is told its tenant by closure, as the CLI would by argv). With
    `login`, the child logs in itself from `issuer_config`. `lines` collects the report lines."""
    def publish(*_a, **_k):
        line = B.run_child(t, issuer_config, login=login)
        if lines is not None:
            lines.append(line)
        return line
    return publish


def test_o7b_a_run_launched_after_a_merge_reads_and_stamps_the_merge(tenant, tmp_path, monkeypatch):
    """O7b end to end, and O8 by value: merge on the fake origin, launch with the REAL child
    logging in itself from the config file; the run's copy holds the merged lesson, its stamp and
    `knowledge_source` name the merge commit, kind fresh. None of role_id, secret_id, the issuer
    client token, the minted forge token or the config path appears in the run process's
    environment, what it handed the child, the stamp, the run page, the posted comment or the
    report line. (Control on the env channel: a value planted in the environment is found.)"""
    import os
    from functools import partial
    from types import SimpleNamespace

    from defender import run_common
    from defender.investigation import ticket_writer
    from defender.tests.support.runtime.engine._spec767 import FakeStore, write_report
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107

    merged = tenant.merge(B.MERGE_FILES)
    store = FakeStore()
    deps = ticket_writer.TicketWriterDeps(request=store)
    writer = SimpleNamespace(
        open_case_ticket=partial(ticket_writer.open_case_ticket, deps=deps),
        record_case_ticket=partial(ticket_writer.record_case_ticket, deps=deps))
    lines: list[str] = []

    def seed(seen: B.Seen) -> None:
        write_report(seen.run_dir)
        S1107.seed_session_store(seen.run_dir)

    with B.real_login(tenant, tmp_path / "operator") as (vault, config, secrets):
        out = B.launch(tenant, tmp_path, publish=_child_publish(tenant, config, login=vault,
                                                                lines=lines),
                       argv_extra=("--update-ticket",), during=seed, ticket_writer=writer,
                       visualize=run_common.visualize)
    assert out.reached, out.text()
    assert store.calls, "control: the run posted its comment"
    assert vault.logins(), "O8: the child did not log in from the config file"
    page = out.run_dir / "runtime.html"
    assert page.is_file(), "control: the run page was saved"
    assert B.leaks(
        secrets, env=out.seen[0].environ, handed=out.publish_calls, report_line=lines,
        stamp=out.stamp_after, host_record=out.host_after, page=page.read_text(encoding="utf-8") if page.is_file() else "",
        comment=[str(c.body) for c in store.calls],
    ) == [], "O8: login material left the publish child"
    monkeypatch.setenv("S_B_CONTROL_PROBE", secrets[1])
    assert B.leaks(secrets[1:2], env=dict(os.environ)) == [("env", secrets[1])]
    assert out.rc == 0, out.text()
    assert B.MERGED_MARK in out.seen[0].agent_files[B.LESSON_REL].decode()
    assert B.stamped_commit(out.stamp_after) == {"commit": merged}
    source = B.knowledge_source(out)
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
    source = B.knowledge_source(out)
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
# The parent launcher (`publish_launch.launch_publish`, assumed seam) runs the REAL child's process entry
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


def _child_saw_no_login_material(marks: Path, secrets: tuple[str, ...]) -> None:
    """O8: what the child process was started with — its argv and its environment — carries no
    secret value and no issuer-named variable (P-4: file-only, never environment)."""
    import json

    seen = json.loads((marks / "seen.json").read_text(encoding="utf-8"))
    assert B.leaks(secrets, argv=seen["argv"], env=seen["env"]) == []
    assert [k for k in seen["env"] if B.ISSUER_ENV.search(k)] == [], (
        "O8: the parent handed its publish child an issuer-named environment variable")
    assert seen["env"].get("S_B_ORDINARY") == "s-b-ordinary-value", (
        "control: an ordinary variable reaches the child, so the env channel is read")


@pytest.fixture
def operator_env(monkeypatch):
    """An operator shell that exported issuer material (it must go nowhere) and an ordinary
    variable (the positive control on the same channel)."""
    monkeypatch.setenv("BAO_TOKEN", "s-b-operator-bao-token-77e1")
    monkeypatch.setenv("VAULT_TOKEN", "s-b-operator-vault-token-91a4")
    monkeypatch.setenv("S_B_ORDINARY", "s-b-ordinary-value")
    return ("s-b-operator-bao-token-77e1", "s-b-operator-vault-token-91a4")


def test_o_budget_the_parent_stops_waiting_at_the_budget_in_the_network_phase(
        tenant, issuer_config, tmp_path, child_env, operator_env):
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
    _child_saw_no_login_material(marks, (*operator_env, B.ISSUER_SECRET_ID, B.ISSUER_ROLE_ID))
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
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("stale_kind"), source.get("commit")) == (
        "stale", "transient", tenant.commit), source


def _child_rc(marks: Path) -> int:
    rc = marks / "rc"
    assert rc.is_file(), "the real child never returned from `publish_child_main`"
    return int(rc.read_text(encoding="utf-8"))


def _child_reported(line: object) -> str:
    """OD20: a reported outcome is the child's own one-line report, passed through."""
    text = str(line)
    assert "\n" not in text.strip(), f"OD20: a report spans lines: {text!r}"
    assert "\r" not in text, f"OD20: a report spans lines: {text!r}"
    assert not B.outcome_detail(text).startswith("publish child failed"), (
        f"OD20: the parent took a child that reported an outcome for a failed one: {text!r}")
    return text


@pytest.mark.parametrize("case", ["dirty-clone", "lock-held", "misconfigured"])
def test_od20_a_real_child_reporting_an_outcome_exits_zero_and_its_line_is_passed_through(
        tenant, issuer_config, tmp_path, child_env, case):
    """OD20: the REAL child process (through `CHILD_WRAPPER`) exits 0 for an outcome it reports,
    and the parent's line is the child's own: a dirty clone → `stale:operator <reason>`; a drain
    holding the tenant lock with origin ahead → `stale:transient` naming the lock; no forge
    binding → `misconfigured <reason>`, and through `run.main` that run refuses before message 0
    although a snapshot exists (O9). None is U11's "publish child failed". `current` is
    unchanged."""
    tenant.merge(B.MERGE_FILES)
    if case == "dirty-clone":
        (B.clone_dir(tenant) / "agent" / "lessons" / "stray-untracked.md").write_text(
            "an operator's stray edit\n", encoding="utf-8")
    if case == "misconfigured":
        unbind_forge(tenant)
    command, _spec, marks = B.child_command(tenant, tmp_path, issuer_config,
                                            network_timeout=30.0, locked_sleep=0)
    launch = B.launcher()
    if case == "lock-held":
        with _lock(tenant):
            line = launch(tenant.tenant_id, data_root=tenant.data_root, budget=30.0,
                          command=command)
    else:
        line = launch(tenant.tenant_id, data_root=tenant.data_root, budget=30.0, command=command)
    assert _child_rc(marks) == 0, "OD20: a child that reported an outcome exited non-zero"
    _child_reported(line)
    if case == "dirty-clone":
        _stale(line, "operator")
    elif case == "lock-held":
        _stale(line, "transient")
        assert "lock" in B.outcome_detail(line).lower(), (
            f"OD20: the lock-busy report does not name the lock: {line!r}")
    else:
        assert B.outcome_class(line) == "misconfigured", line
        assert B.outcome_detail(line), f"a misconfiguration names its reason: {line!r}"
    _unchanged(tenant)
    if case == "misconfigured":
        import functools

        out = B.launch(tenant, tmp_path, publish=functools.partial(launch, budget=30.0,
                                                                   command=command))
        assert _child_rc(marks) == 0, "OD20: the misconfigured child exited non-zero"
        assert not out.reached, f"O9: a misconfigured launch reached its box: {out.text()}"
        assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"
        assert out.refusal is not None, out.text()
        _unchanged(tenant)


def test_od20_a_multi_line_forge_error_is_reported_on_one_line_and_the_run_proceeds_on_it(
        tenant, issuer_config, tmp_path, child_env):
    """OD20: the forge answers with a multi-line error body; the real child reports ONE line
    (newlines collapsed) and exits 0; through `run.main` the run proceeds stale on `current`
    and its host record's reason is that one-line reason."""
    import functools

    tenant.merge(B.MERGE_FILES)
    body = "S-B forge error, first line\nsecond line S-B-ERR-2\r\nthird line S-B-ERR-3\n"
    command, _spec, marks = B.child_command(tenant, tmp_path, issuer_config,
                                            network_timeout=30.0, locked_sleep=0,
                                            forge_error_body=body)
    lines: list[str] = []
    launch = functools.partial(B.launcher(), budget=30.0, command=command)

    def publish(*a, **k):
        lines.append(launch(*a, **k))
        return lines[-1]

    out = B.launch(tenant, tmp_path, publish=publish)
    assert (marks / "forge-error-served").exists(), "premise: the child read the forge's error"
    assert lines, out.text()
    assert _child_rc(marks) == 0, "OD20: a child that reported an outcome exited non-zero"
    line = _child_reported(lines[0])
    assert B.outcome_class(line).startswith("stale:"), line
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("commit")) == ("stale", tenant.commit), source
    reason = str(source.get("reason"))
    assert "\n" not in reason, f"OD20: the recorded reason spans lines: {reason!r}"
    assert reason == B.outcome_detail(line), (
        f"OD20: the recorded reason is not the child's one-line reason: {reason!r} vs {line!r}")
    for later in ("S-B-ERR-2", "S-B-ERR-3"):
        assert later in reason, (
            f"OD20: the forge error's later lines were truncated, not collapsed: {reason!r}")


def test_o_budget_the_parents_default_budget_is_sixty_seconds():
    """O-BUDGET: "at most 60 s" is the launcher's default budget."""
    import inspect

    assert inspect.signature(B.launcher()).parameters["budget"].default == 60.0


class _RecordingSpawn:
    """`launch_publish`'s spawn seam (assumed: `subprocess.Popen`'s signature): records the argv
    and environment the parent would start its child with, then starts a harmless process."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv, **kw):
        import os
        import subprocess
        import sys

        env = kw.get("env")
        self.calls.append((list(map(str, argv)), dict(os.environ if env is None else env)))
        return subprocess.Popen([sys.executable, "-c", "pass"],  # noqa: S603 — a test double
                                stdout=kw.get("stdout"), stderr=kw.get("stderr"),
                                stdin=kw.get("stdin"))


def test_o8_the_default_child_command_carries_identifiers_only_and_no_issuer_environment(
        tenant, operator_env):
    """O8/O11 (parent half, DEFAULT launch — no `command=`): the parent starts the real child
    with the tenant id and data root, and neither its argv nor its environment carries an
    issuer-named variable or any planted secret. U11: the harmless stand-in prints no report
    line, so the parent reports `stale:operator publish child failed: ...` — never fresh."""
    spawn = _RecordingSpawn()
    launch = B.launcher()
    line = launch(tenant.tenant_id, data_root=tenant.data_root, budget=5.0, spawn=spawn)
    assert len(spawn.calls) == 1, f"the parent did not start exactly one child: {spawn.calls}"
    argv, env = spawn.calls[0]
    assert tenant.tenant_id in argv, argv
    assert B.leaks(operator_env, argv=argv, env=env) == []
    assert [k for k in env if B.ISSUER_ENV.search(k)] == [], sorted(env)
    assert env.get("S_B_ORDINARY") == "s-b-ordinary-value", "control: the env channel is read"
    _child_failed(line)


# --- U11: a child with no valid report line ---------------------------------------------------
#
# ASSUMED (U11 wording): the parent's line is `stale:operator publish child failed: <summary>`.
# `command=` replaces the child's argv prefix; the parent appends its own arguments (ignored by
# these `python -c` children: they land in `sys.argv`).

#: Children that end without a valid report line. `fresh-then-exit-1` prints a VALID fresh line
#: and exits non-zero: the exit decides (never fresh).
BAD_CHILDREN = {
    "exit-1": "import sys; sys.exit(1)",
    "crash": "raise RuntimeError('s-b child crashed')",
    "empty-stdout": "pass",
    "junk-stdout": "print('the child had a bad day')",
    "unknown-prefix": "print('published 0123456789abcdef0123456789abcdef01234567')",
    "fresh-then-exit-1": "import sys; print('fresh ' + sys.argv[1]); sys.exit(1)",
}


def _bad_child(case: str, t, tmp_path: Path) -> list[str]:
    import sys

    if case == "missing-executable":
        return [str(tmp_path / "no-such-dir-s-b" / "publish-child")]
    return [sys.executable, "-c", BAD_CHILDREN[case], t.commit]


def _child_failed(line: object) -> None:
    assert B.outcome_class(line) == "stale:operator", (
        f"U11: a child with no valid report line must be stale:operator: {line!r}")
    assert B.outcome_detail(str(line)).startswith("publish child failed"), line


@pytest.mark.parametrize("case", [*BAD_CHILDREN, "missing-executable"])
def test_u11_a_child_with_no_valid_report_line_is_stale_operator(tenant, tmp_path, case):
    """U11: crash, non-zero exit, empty or junk stdout, an unknown prefix, a spawn failure — the
    parent reports `stale:operator ("publish child failed: <summary>")`, never fresh, and
    `current` is untouched. Control: `test_o_budget_a_child_holding_the_lock_is_allowed_to_
    finish` (a real child's valid line is passed through)."""
    line = B.launcher()(tenant.tenant_id, data_root=tenant.data_root, budget=BUDGET,
                        command=_bad_child(case, tenant, tmp_path))
    _child_failed(line)
    _unchanged(tenant)


@pytest.mark.parametrize("case", ["exit-1", "missing-executable"])
def test_u11_a_failed_child_with_a_snapshot_runs_stale_operator_on_it(tenant, tmp_path, case):
    """U11 through `run.main`: with `current`, the run proceeds on the snapshot, its host record
    `stale`/`operator` at `current` with the failure as its reason."""
    import functools

    publish = functools.partial(B.launcher(), budget=BUDGET,
                                command=_bad_child(case, tenant, tmp_path))
    out = B.launch(tenant, tmp_path, publish=publish)
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert B.SEEDED_MARK in out.seen[0].agent_files[B.LESSON_REL].decode()
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("stale_kind"), source.get("commit")) == (
        "stale", "operator", tenant.commit), source
    assert "publish child failed" in str(source.get("reason")), source


@pytest.mark.parametrize("case", ["exit-1", "missing-executable"])
def test_u11_a_failed_child_without_a_snapshot_refuses_before_message_zero(tenant, tmp_path,
                                                                           case):
    """U11/O-A: no `current`, the child failed — the run refuses before its lifecycle, by a
    refusal (not a crash). Control: the snapshot case above runs."""
    import functools

    (export_dir(tenant.tenant, tenant.commit).parent / "current").unlink()
    publish = functools.partial(B.launcher(), budget=BUDGET,
                                command=_bad_child(case, tenant, tmp_path))
    out = B.launch(tenant, tmp_path, publish=publish)
    assert not out.reached, "U11: a failed child with no snapshot reached the box"
    assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"
    assert out.rc not in (0, None) or out.refusal is not None, out.text()


def test_r_s7_a_first_ever_publish_through_the_real_child_is_fresh_and_the_run_proceeds(
        tenant, issuer_config, tmp_path):
    """R-S7: no export has ever been written (`<T>/exports/` empty, no `current`): the real
    child publishes the first one, reports fresh, and the run starts on it."""
    import shutil

    exports = export_dir(tenant.tenant, tenant.commit).parent
    shutil.rmtree(exports)
    exports.mkdir()
    out = B.launch(tenant, tmp_path, publish=_child_publish(tenant, issuer_config))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert current_commit(tenant.tenant) == tenant.commit
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("commit")) == ("fresh", tenant.commit), source
