"""#1108 P4 launch-time publish child: in-process against P3's fakes, as a real process under the
launcher's budget, and wired into `run.main` through `publish=`.

The child (`version_control.publish_for_run`) accepts the tenant from id + data root, reads the
forge wiring and live generation itself, publishes through P3's real delivery path, and reports
one outcome line. Each case plants a real fault through P3's fakes or real files and asserts the
outcome class, never which exception the child caught (P3 folds them into one `DeliveryRefused`;
the child classifies first).
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
    minting,
    unbind_forge,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        yield t


def _lock(t):
    from defender.learning.author.version_control import tenant_lock

    return tenant_lock(t.tenant)


def _unchanged(t) -> None:
    assert current_commit(t.tenant) == t.commit, (
        "a refused publish moved `current` (it must publish nothing)")


def _stale(line: str, kind: str) -> None:
    assert B.outcome_class(line) == f"stale:{kind}", (
        f"expected stale:{kind}, the child reported {line!r}")
    assert B.outcome_detail(line), f"a stale outcome names its reason: {line!r}"


# --- fresh (positive control for every class below) -------------------------------------------

def test_o7b_a_merge_on_origin_is_published_and_reported_fresh_at_the_merge(tenant):
    """The child fetches with the identity it is handed, publishes the merge as `current` and reports
    `fresh <merge>`, a line carrying no config path (login itself: `test_1214_forge_credential`)."""
    merged = tenant.merge(B.MERGE_FILES)
    line = B.run_child(tenant)
    assert tenant.server.authorized("git-upload-pack"), "the fetch never carried the identity's token"
    assert B.outcome_class(line) == "fresh", line
    assert B.outcome_detail(line) == merged, line
    assert current_commit(tenant.tenant) == merged
    lesson = export_dir(tenant.tenant, merged) / B.LESSON
    assert B.MERGED_MARK in lesson.read_text(encoding="utf-8")


# --- O7b: tenant lock held by a drain ---------------------------------------------------------

def test_o7b_lock_held_and_origin_ahead_is_stale_transient(tenant):
    """A drain holds the tenant lock and origin has a merge `current` lacks: the child does not
    wait."""
    tenant.merge(B.MERGE_FILES)
    with _lock(tenant):
        line = B.run_child(tenant)
    _stale(line, "transient")
    _unchanged(tenant)


def test_o7b_lock_held_but_current_already_equals_origin_main_is_fresh(tenant):
    """Same lock, but `current` already equals the fetched `origin/main`."""
    assert tenant.origin_main() == tenant.commit
    with _lock(tenant):
        line = B.run_child(tenant)
    assert B.outcome_class(line) == "fresh", line
    assert B.outcome_detail(line) == tenant.commit, line


# --- stale:transient --------------------------------------------------------------------------

def _raising_identity(t, error=httpx.ConnectError):
    from defender.learning.author.version_control import ForgejoIdentity

    def down(request):
        raise error("issuer unreachable", request=request)

    return ForgejoIdentity(tenant_id=t.tenant_id, issuer=ISSUER, role=f"tenant-{t.tenant_id}",
                           audience=AUDIENCE, client=httpx.Client(transport=httpx.MockTransport(down)))


def test_o_stale_an_unreachable_issuer_is_transient(tenant):
    tenant.merge(B.MERGE_FILES)
    line = B.run_child(tenant, identity=_raising_identity(tenant))
    _stale(line, "transient")
    _unchanged(tenant)


def test_o_stale_an_unreachable_forge_is_transient(tenant):
    tenant.merge(B.MERGE_FILES)

    def down(request):
        return httpx.ConnectError("forge unreachable", request=request)

    tenant.forge.fault = down
    line = B.run_child(tenant)
    _stale(line, "transient")
    _unchanged(tenant)


def test_o_budget_a_stalled_fetch_ends_within_the_childs_timeout_and_leaves_nothing_behind(tenant):
    """Origin trickles the fetch for ever: with a short network timeout the child reports
    `stale:transient` well inside the 60 s budget, leaving no git process, no `index.lock`, and
    the tenant lock free."""
    tenant.merge(B.MERGE_FILES)
    stop = threading.Event()
    tenant.server.on_service = lambda service: (
        Trickle(stop) if service == "git-upload-pack" else None)
    tenant.server.rearm()
    started = time.monotonic()
    try:
        line = B.run_child(tenant, network_timeout=2.0)
    finally:
        elapsed = time.monotonic() - started
        stop.set()
    _stale(line, "transient")
    assert elapsed < 30, f"the stalled publish took {elapsed:.1f}s"
    clone = B.clone_dir(tenant)
    assert quiet(clone, seconds=5) == [], "a git process outlived the child's publish"
    assert not (clone / ".git" / "index.lock").exists()
    with _lock(tenant):
        pass
    _unchanged(tenant)


# --- stale:operator ---------------------------------------------------------------------------

def test_o_stale_an_issuer_auth_refusal_is_operator(tenant, tmp_path):
    """OpenBao refuses the login (the generation's secret id is revoked): `stale:operator`, and the report line
    names neither the secret nor the role id."""
    tenant.merge(B.MERGE_FILES)
    scene = minting(tenant, tmp_path, purpose="publish")
    scene.bao.approles[scene.fields["approle"]].clear()
    line = B.run_child(tenant, identity=scene.credential)
    assert any(login["secret_id"] == scene.secret for login in scene.logins()), "premise: the child tried to log in"
    _stale(line, "operator")
    assert B.leaks(scene.secrets, report_line=line) == []
    _unchanged(tenant)


def test_o_stale_the_forge_rejecting_the_minted_token_is_operator(tenant):
    """The origin refuses the token the issuer minted (the forge's integration does not trust
    it): `stale:operator`."""
    tenant.merge(B.MERGE_FILES)
    tenant.server.refuse.add("git-upload-pack")
    line = B.run_child(tenant)
    assert tenant.server.offered_and_refused("git-upload-pack"), "premise: the token was refused"
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_a_diverged_clone_is_operator(tenant):
    """The clone holds an unpushed local commit and origin moved on, so the fast-forward cannot
    happen."""
    from defender.tests.tenancy.tenant_1108_p4._support import git

    clone = B.clone_dir(tenant)
    (clone / "agent" / "lessons" / "local-only.md").write_text("local\n", encoding="utf-8")
    git(clone, "add", "-A")
    git(clone, "commit", "-m", "an operator's local commit, never pushed")
    tenant.merge(B.MERGE_FILES)
    line = B.run_child(tenant)
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_a_merged_link_is_operator(tenant):
    """A human merged a symlink under `agent/`: refused on content."""
    from defender.tests.tenancy.tenant_1108_p4._support import index_entry, push_to_remote

    push_to_remote(tenant.p3, tenant.scratch,
                   lambda w: index_entry(w, "120000", "agent/lessons/evil.md", data=b"/etc/passwd"),
                   "a link merged by a human", stage=False)
    line = B.run_child(tenant)
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_an_issuer_api_timeout_is_transient(tenant):
    """The issuer's mint endpoint times out: `stale:transient`."""
    tenant.merge(B.MERGE_FILES)
    line = B.run_child(tenant, identity=_raising_identity(tenant, httpx.ReadTimeout))
    _stale(line, "transient")
    _unchanged(tenant)


def test_o_stale_a_forge_api_timeout_is_transient(tenant):
    tenant.merge(B.MERGE_FILES)
    tenant.forge.fault = lambda request: httpx.ReadTimeout("forge read timed out", request=request)
    line = B.run_child(tenant)
    _stale(line, "transient")
    _unchanged(tenant)


def test_o7b_lock_held_with_the_clone_at_origin_main_but_current_behind_is_stale(tenant):
    """The clone's HEAD already equals `origin/main` (fast-forwarded outside a publish) but
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
        line = B.run_child(tenant)
    assert B.outcome_class(line).startswith("stale:"), (
        f"`current` is behind origin/main and could not move, yet the child said {line!r}")
    _unchanged(tenant)


def test_o_stale_a_dirty_clone_is_operator(tenant):
    tenant.merge(B.MERGE_FILES)
    (B.clone_dir(tenant) / "agent" / "lessons" / "stray-untracked.md").write_text(
        "an operator's stray edit\n", encoding="utf-8")
    line = B.run_child(tenant)
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_an_unprotected_main_is_operator(tenant):
    tenant.merge(B.MERGE_FILES)
    tenant.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    line = B.run_child(tenant)
    _stale(line, "operator")
    _unchanged(tenant)


def test_o_stale_a_merged_commit_naming_another_tenant_is_operator(tenant):
    """A human merged an `agent/.tenant-id` naming another tenant: refused on content."""
    tenant.merge({"agent/.tenant-id": f"{OTHER_TENANT_ID}\n"})
    line = B.run_child(tenant)
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
        tenant, how):
    """Origin's `main` rewound or force-pushed off `current`'s line is refused, and `current`
    does not move: the fast-forward-only invariant test_run_start's A-MISMATCH case rests on.
    Control: the first test above (a descendant is published)."""
    target = _force_main(tenant, how)
    # Read after the rewrite: the `rewound` setup publishes its merge first, so when the child
    # runs `current` is that merge, and origin's `main` is the merge's parent (a non-descendant).
    before = current_commit(tenant.tenant)
    line = B.run_child(tenant)
    _stale(line, "operator")
    assert current_commit(tenant.tenant) == before, (
        f"`current` moved off {before[:12]} to a non-descendant of it ({target[:12]})")


# --- misconfiguration: refused, before any network call ---------------------------------------

def _network_marks(t) -> tuple[int, int, int]:
    return len(t.vault.calls), len(t.forge.requests), len(t.server.seen)


@pytest.mark.parametrize("missing", ["host-secret-file", "forge-wiring"])
def test_o_stale_misconfiguration_is_refused_before_any_network_call(tenant, tmp_path, missing):
    """A missing host secret file or forge wiring is decided locally: the child reports
    `misconfigured <reason>` and makes no issuer, forge or git request."""
    tenant.merge(B.MERGE_FILES)
    _misconfigure(tenant, tmp_path, missing)
    before = _network_marks(tenant)
    line = B.run_child(tenant, mint=True)
    assert B.outcome_class(line) == "misconfigured", line
    assert _network_marks(tenant) == before, "a misconfigured child went to the network"
    _unchanged(tenant)


def _misconfigure(t, tmp_path, missing: str) -> None:
    """The two local misconfigurations of #1214: the live generation names a host secret file that is not
    there, or the tenant has no forge wiring."""
    from defender.tests.support.tenancy._active1214 import generation_fields

    if missing == "host-secret-file":
        gone = {**generation_fields(t.tenant_id, tmp_path / "secrets"),
                "host_secret_file": tmp_path / "secrets" / "absent"}
        bind_forge(t, generations=[gone])
    else:
        unbind_forge(t)


# --- wired into run.main ----------------------------------------------------------------------

def _child_publish(t, *, mint: bool = False, lines: list | None = None, identity=None):
    """`run.main`'s `publish=` bound to the REAL child in-process (identifiers from the parent
    are ignored here; the child is told its tenant by closure, as the CLI would by argv). With
    `mint`, the child mints from the live generation; `identity` hands it the real provider over a fake OpenBao.
    `lines` collects the report lines."""
    def publish(*_a, **_k):
        line = B.run_child(t, mint=mint, identity=identity)
        if lines is not None:
            lines.append(line)
        return line
    return publish


def test_o7b_a_run_launched_after_a_merge_reads_and_stamps_the_merge(tenant, tmp_path, monkeypatch):
    """End to end with the real child: the run reads and stamps the merge (fresh), and the host secret
    file's value appears in none of the run's environment, what it handed the child, the stamp, host
    record, page, comment or report line (control: a value planted in the environment is found)."""
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

    scene = minting(tenant, tmp_path, purpose="publish")
    secrets = scene.secrets
    out = B.launch(tenant, tmp_path, publish=_child_publish(tenant, lines=lines, identity=scene.credential),
                   argv_extra=("--update-ticket",), during=seed, ticket_writer=writer,
                   visualize=run_common.visualize)
    assert out.reached, out.text()
    scene.assert_logged_in_with_the_file()
    assert store.calls, "control: the run posted its comment"
    page = out.run_dir / "runtime.html"
    assert page.is_file(), "control: the run page was saved"
    assert B.leaks(
        secrets, env=out.seen[0].environ, handed=out.publish_calls, report_line=lines,
        stamp=out.stamp_after, host_record=out.host_after, page=page.read_text(encoding="utf-8") if page.is_file() else "",
        comment=[str(c.body) for c in store.calls],
    ) == [], "the host secret left the publish child"
    monkeypatch.setenv("S_B_CONTROL_PROBE", scene.secret)
    assert B.leaks(secrets, env=dict(os.environ)) == [("env", scene.secret)]
    assert out.rc == 0, out.text()
    assert B.MERGED_MARK in out.seen[0].agent_files[B.LESSON_REL].decode()
    assert B.stamped_commit(out.stamp_after) == {"commit": merged}
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("commit")) == ("fresh", merged), source


def test_o7b_a_run_launched_while_a_drain_holds_the_lock_runs_stale_on_current(
        tenant, tmp_path):
    tenant.merge(B.MERGE_FILES)
    with _lock(tenant):
        out = B.launch(tenant, tmp_path, publish=_child_publish(tenant))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert B.SEEDED_MARK in out.seen[0].agent_files[B.LESSON_REL].decode()
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("stale_kind"), source.get("commit")) == (
        "stale", "transient", tenant.commit), source


@pytest.mark.parametrize("missing", ["host-secret-file", "forge-wiring"])
def test_o9_a_misconfigured_tenant_refuses_the_run_before_any_model_call(tenant, tmp_path, missing):
    """Refused before its lifecycle though a snapshot exists. Control: the O7b launches above."""
    _misconfigure(tenant, tmp_path, missing)
    out = B.launch(tenant, tmp_path, publish=_child_publish(tenant, mint=True))
    assert not out.reached, f"a misconfigured tenant's run reached its box: {out.text()}"
    assert out.raised is None or not isinstance(out.raised, TypeError), out.text()
    assert out.refusal is not None, out.text()


# --- O-BUDGET, parent half: a real child process under a real lock -----------------------------
#
# `publish_launch.launch_publish` runs the real child entry in a subprocess whose fakes are rebuilt
# inside it (`_s_b_support.CHILD_WRAPPER`). Budgets are small but must exceed the child's
# interpreter start-up and imports, which the budget counts; the locked phase is slowed through
# `locked_hook`.

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
        "a child (or its git) outlived the launch")
    assert not (clone / ".git" / "index.lock").exists(), "index.lock left behind"
    with _lock(t):  # the tenant lock is free again
        pass


def _child_saw_no_login_material(marks: Path, secrets: tuple[str, ...]) -> None:
    """The child's argv and environment carry no secret value and no issuer-named variable
    (login material is file-only)."""
    import json

    seen = json.loads((marks / "seen.json").read_text(encoding="utf-8"))
    assert B.leaks(secrets, argv=seen["argv"], env=seen["env"]) == []
    assert [k for k in seen["env"] if B.ISSUER_ENV.search(k)] == [], (
        "the parent handed its publish child an issuer-named environment variable")
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
        tenant, tmp_path, child_env, operator_env):
    """Origin stalls the fetch and the child's own network timeout is far beyond the budget: the
    parent stops at the budget, ends the child leaving nothing behind, and reports
    `stale:transient`."""
    tenant.merge(B.MERGE_FILES)
    stop = threading.Event()
    tenant.server.on_service = lambda service: (
        Trickle(stop, limit=300.0) if service == "git-upload-pack" else None)
    tenant.server.rearm()
    command, spec, marks = B.child_command(tenant, tmp_path,
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
    assert elapsed < BUDGET + SLACK, f"the launch waited {elapsed:.1f}s"
    assert not (marks / "locked").exists(), "premise: the child never reached its locked phase"
    _child_saw_no_login_material(marks, operator_env)
    _no_leftovers(tenant, spec)
    _unchanged(tenant)


def test_o_budget_a_child_holding_the_lock_is_allowed_to_finish(tenant, tmp_path,
                                                                child_env):
    """A child that takes the tenant lock inside the budget and holds it past the budget is not
    killed: the parent waits (never past budget + locked phase) and reports its `fresh <merge>`."""
    merged = tenant.merge(B.MERGE_FILES)
    command, spec, marks = B.child_command(tenant, tmp_path,
                                           network_timeout=30.0, locked_sleep=LOCKED_SLEEP)
    launch = B.launcher()
    started_wall, started = time.time(), time.monotonic()
    line = launch(tenant.tenant_id, data_root=tenant.data_root, budget=BUDGET, command=command)
    elapsed = time.monotonic() - started
    locked_at = float((marks / "locked").read_text(encoding="utf-8")) - started_wall
    assert locked_at < BUDGET, (
        f"premise: the child took the lock {locked_at:.1f}s in, after the {BUDGET}s budget")
    assert (marks / "locked-done").exists(), (
        "the parent returned before the lock-holding child finished (killed it?)")
    assert B.outcome_class(line) == "fresh", line
    assert B.outcome_detail(line) == merged, line
    assert current_commit(tenant.tenant) == merged
    assert elapsed > BUDGET, "premise: the locked phase outlasted the budget"
    assert elapsed < BUDGET + LOCKED_SLEEP + SLACK, f"the launch waited {elapsed:.1f}s"
    _no_leftovers(tenant, spec)


def test_o_budget_a_run_whose_publish_ran_out_of_budget_proceeds_stale_on_the_last_snapshot(
        tenant, tmp_path, child_env):
    """Through `run.main` with a stalled network phase, the run starts within the budget on
    `current`, recorded stale/transient."""
    import functools

    tenant.merge(B.MERGE_FILES)
    stop = threading.Event()
    tenant.server.on_service = lambda service: (
        Trickle(stop, limit=300.0) if service == "git-upload-pack" else None)
    tenant.server.rearm()
    command, _spec, _marks = B.child_command(tenant, tmp_path,
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
    """A reported outcome is the child's own one-line report, passed through."""
    text = str(line)
    assert "\n" not in text.strip(), f"a report spans lines: {text!r}"
    assert "\r" not in text, f"a report spans lines: {text!r}"
    assert not B.outcome_detail(text).startswith("publish child failed"), (
        f"the parent took a child that reported an outcome for a failed one: {text!r}")
    return text


@pytest.mark.parametrize("case", ["dirty-clone", "lock-held", "misconfigured"])
def test_od20_a_real_child_reporting_an_outcome_exits_zero_and_its_line_is_passed_through(
        tenant, tmp_path, child_env, case):
    """The real child process exits 0 for an outcome it reports, and the parent passes its line
    through, never U11's "publish child failed"; through `run.main` a misconfigured run refuses
    before message 0 although a snapshot exists."""
    tenant.merge(B.MERGE_FILES)
    if case == "dirty-clone":
        (B.clone_dir(tenant) / "agent" / "lessons" / "stray-untracked.md").write_text(
            "an operator's stray edit\n", encoding="utf-8")
    if case == "misconfigured":
        unbind_forge(tenant)
    command, _spec, marks = B.child_command(tenant, tmp_path,
                                            network_timeout=30.0, locked_sleep=0)
    launch = B.launcher()
    if case == "lock-held":
        with _lock(tenant):
            line = launch(tenant.tenant_id, data_root=tenant.data_root, budget=30.0,
                          command=command)
    else:
        line = launch(tenant.tenant_id, data_root=tenant.data_root, budget=30.0, command=command)
    assert _child_rc(marks) == 0, "a child that reported an outcome exited non-zero"
    _child_reported(line)
    if case == "dirty-clone":
        _stale(line, "operator")
    elif case == "lock-held":
        _stale(line, "transient")
        assert "lock" in B.outcome_detail(line).lower(), (
            f"the lock-busy report does not name the lock: {line!r}")
    else:
        assert B.outcome_class(line) == "misconfigured", line
        assert B.outcome_detail(line), f"a misconfiguration names its reason: {line!r}"
    _unchanged(tenant)
    if case == "misconfigured":
        import functools

        out = B.launch(tenant, tmp_path, publish=functools.partial(launch, budget=30.0,
                                                                   command=command))
        assert _child_rc(marks) == 0, "the misconfigured child exited non-zero"
        assert not out.reached, f"a misconfigured launch reached its box: {out.text()}"
        assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"
        assert out.refusal is not None, out.text()
        _unchanged(tenant)


def test_od20_a_multi_line_forge_error_is_reported_on_one_line_and_the_run_proceeds_on_it(
        tenant, tmp_path, child_env):
    """The forge answers with a multi-line error body; the real child reports one line
    (newlines collapsed) and exits 0; through `run.main` the run proceeds stale on `current`
    and its host record's reason is that one-line reason."""
    import functools

    tenant.merge(B.MERGE_FILES)
    body = "S-B forge error, first line\nsecond line S-B-ERR-2\r\nthird line S-B-ERR-3\n"
    command, _spec, marks = B.child_command(tenant, tmp_path,
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
    assert _child_rc(marks) == 0, "a child that reported an outcome exited non-zero"
    line = _child_reported(lines[0])
    assert B.outcome_class(line).startswith("stale:"), line
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("commit")) == ("stale", tenant.commit), source
    reason = str(source.get("reason"))
    assert "\n" not in reason, f"the recorded reason spans lines: {reason!r}"
    assert reason == B.outcome_detail(line), (
        f"the recorded reason is not the child's one-line reason: {reason!r} vs {line!r}")
    for later in ("S-B-ERR-2", "S-B-ERR-3"):
        assert later in reason, (
            f"the forge error's later lines were truncated, not collapsed: {reason!r}")


def test_o_budget_the_parents_default_budget_is_sixty_seconds():
    import inspect

    assert inspect.signature(B.launcher()).parameters["budget"].default == 60.0


class _RecordingSpawn:
    """`launch_publish`'s spawn seam (`subprocess.Popen`'s signature): records the argv
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
    """With the default command, the parent starts the child with the tenant id and data root,
    and neither argv nor environment carries an issuer-named variable or a planted secret. The
    harmless stand-in prints no report line, so the parent reports a failed child."""
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
# The parent's line is `stale:operator publish child failed: <summary>`. It appends its own
# arguments to `command=` (these `python -c` children ignore them in `sys.argv`).

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
        f"a child with no valid report line must be stale:operator: {line!r}")
    assert B.outcome_detail(str(line)).startswith("publish child failed"), line


@pytest.mark.parametrize("case", [*BAD_CHILDREN, "missing-executable"])
def test_u11_a_child_with_no_valid_report_line_is_stale_operator(tenant, tmp_path, case):
    """Crash, non-zero exit, empty or junk stdout, an unknown prefix, a spawn failure: never
    fresh, and `current` is untouched. Control: `test_o_budget_a_child_holding_the_lock_is_
    allowed_to_finish` (a valid line passes through)."""
    line = B.launcher()(tenant.tenant_id, data_root=tenant.data_root, budget=BUDGET,
                        command=_bad_child(case, tenant, tmp_path))
    _child_failed(line)
    _unchanged(tenant)


@pytest.mark.parametrize("case", ["exit-1", "missing-executable"])
def test_u11_a_failed_child_with_a_snapshot_runs_stale_operator_on_it(tenant, tmp_path, case):
    """Through `run.main`: with `current`, the run proceeds on the snapshot, its host record
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
    """With no `current`, the run refuses before its lifecycle by a refusal, not a crash.
    Control: the snapshot case above runs."""
    import functools

    (export_dir(tenant.tenant, tenant.commit).parent / "current").unlink()
    publish = functools.partial(B.launcher(), budget=BUDGET,
                                command=_bad_child(case, tenant, tmp_path))
    out = B.launch(tenant, tmp_path, publish=publish)
    assert not out.reached, "a failed child with no snapshot reached the box"
    assert out.raised is None, f"refused by a crash, not a refusal: {out.raised!r}"
    assert out.rc not in (0, None) or out.refusal is not None, out.text()


def test_r_s7_a_first_ever_publish_through_the_real_child_is_fresh_and_the_run_proceeds(
        tenant, tmp_path):
    """No export has ever been written (`<T>/exports/` empty, no `current`): the real
    child publishes the first one, reports fresh, and the run starts on it."""
    import shutil

    exports = export_dir(tenant.tenant, tenant.commit).parent
    shutil.rmtree(exports)
    exports.mkdir()
    out = B.launch(tenant, tmp_path, publish=_child_publish(tenant))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert current_commit(tenant.tenant) == tenant.commit
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("commit")) == ("fresh", tenant.commit), source
