# ruff: noqa: PT018
"""#1214 failure, restart point and resume; names before things; the spent wrapper; first publish; sweep (O3, P1,
DC-4, RC-4, RC-6, RC-7, RC-8, DC-14) — in-memory twin. Real crashes (lock lost mid-step) are in test_1214_worker_lock."""
from __future__ import annotations

import subprocess

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214._fakes import ORG  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import (  # noqa: E402
    REPOS,
    USERS,
    FailingGit,
    body_of,
    host_openbao_failing,
    openbao_failing,
    stray_secrets,
    sweep_failure,
)
from defender.tests.tenancy.lifecycle_1214._support import REPO_WINDOW, LifecycleWorld  # noqa: E402

ITEM_KEYS = ("state", "pending_action", "step", "step_actor")


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _role_write(r) -> bool:
    return r.method in ("POST", "PUT") and "/identity/oidc/role/" in r.url.path


def _wrap(r) -> bool:
    return r.url.path.endswith("/secret-id") and "x-vault-wrap-ttl" in {k.lower() for k in r.headers}


def _git_push(world):
    failing = FailingGit(world.git, lambda args: "push" in args)
    world.service_actor = world.new_service(world.tenants, identity=world.service, git=failing)
    world.host_actor = world.new_host(world.tenants, git=failing)


def _stale_publish(world):
    world.publish.answers.append("stale 0123abc")


#: key -> (set up the failure, (restart step, restart actor), step named in the failure, text the failure carries)
FAILURES = {
    "provider": (lambda w: openbao_failing(w, _role_write), ("provider", "service"), "provider", "500"),
    "repo": (lambda w: w.forge.fail_next.update({("POST", REPOS): 500}), ("repo", "service"), "repo", "500"),
    "bot": (lambda w: w.forge.fail_next.update({("POST", USERS): 500}), ("bot", "service"), "bot", "500"),
    "integration": (lambda w: setattr(w.integration, "fail_next", 1), ("integration", "service"), "integration",
                    "invalid issuer"),
    "template": (_git_push, ("template", "service"), "template", "injected failure"),
    "wrap": (lambda w: openbao_failing(w, _wrap), ("wrap", "service"), "wrap", "500"),
    "sweep": (sweep_failure, ("sweep", "service"), "sweep", "500"),
    # DC-4: a login failing after the unwrap has spent the wrapper restarts at `wrap`, in the service.
    "install after the unwrap": (lambda w: host_openbao_failing(w, lambda r: r.url.path.endswith("/approle/login")),
                                 ("wrap", "service"), "install", "500"),
    "prepare": (_stale_publish, ("prepare", "host"), "prepare", "stale 0123abc"),
}


def _names(world, tenant) -> tuple[str, ...]:
    [gen] = [g for g in world.generations(tenant)]
    return (gen.bot_login, gen.oidc_role, gen.approle, gen.entity)


def _calls(world) -> int:
    return len(world.forge.calls) + len(world.openbao.calls) + len(world.git.calls) + len(world.integration.calls) \
        + len(world.publish.calls)


@pytest.mark.parametrize("failing", list(FAILURES))
def test_a_failure_records_its_restart_point_is_not_retried_and_resume_only_clears_it(world, failing):
    """A failing step records failure plus its restart point (step, actor), names the step and the answer and no
    secret; nothing retries it; resume changes only `failure`; the job then finishes with no orphan or duplicate;
    the names recorded before the failing call are the ones used (O3, P1, DC-4, DC-14)."""
    setup, restart, failed_in, needle = FAILURES[failing]
    setup(world)
    tenant = world.create()
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["pending_action"]) == ("creating", "create")
    assert (item["step"], item["step_actor"]) == restart
    assert failed_in in item["failure"] and needle in item["failure"]
    assert not [s for s in stray_secrets(world) if s in item["failure"]], "the failure carries a secret"
    names = _names(world, tenant)
    assert all(names), "names were not recorded before the failing step"

    before = _calls(world)
    assert world.drive() == 0 and _calls(world) == before, "a failed step was retried by itself"

    resumed = world.ops.post(f"/admin/tenants/{tenant}/resume")
    assert resumed.status_code == 202, resumed.text
    after = world.item(tenant)
    assert after["failure"] is None
    assert {k: after[k] for k in ITEM_KEYS} == {k: item[k] for k in ITEM_KEYS}, "resume changed more than the failure"

    world.drive()
    assert world.item(tenant)["state"] == "active"
    live = world.live(tenant)
    assert (live.bot_login, live.oidc_role, live.approle, live.entity) == names
    assert (set(world.forge.users), set(world.openbao.oidc_roles), set(world.openbao.approles),
            set(world.openbao.entities)) == ({names[0]}, {names[1]}, {names[2]}, {names[3]})
    assert list(world.forge.repos) == [f"{ORG}/{tenant}"]
    assert world.openbao.secret_accessors(live.approle) == {live.secret_accessor}


def test_a_spent_wrapper_found_when_install_is_taken_up_fails_loudly_and_restarts_at_wrap(world):
    """The wrapper is spent before the host unwraps it: install fails loudly, restarts at `wrap` (service); resume
    makes a fresh wrapped secret and the job finishes with only the live secret id (DC-4, Flow 1.8, P1)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    assert world.openbao.wrapped, "control: a wrapped secret waits for the host"
    world.openbao.wrapped.clear()  # the unwrap happened and the host died before it committed
    world.drive()
    item = world.item(tenant)
    assert (item["step"], item["step_actor"]) == ("wrap", "service")
    assert "install" in item["failure"]
    assert world.drive() == 0
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"
    wraps = [c for c in world.openbao.calls if c.path.endswith("/secret-id") and "x-vault-wrap-ttl" in c.headers]
    assert len(wraps) == 2, "resume did not issue a fresh wrapped secret"
    live = world.live(tenant)
    assert world.openbao.secret_accessors(live.approle) == {live.secret_accessor}


@pytest.mark.parametrize("line", ["stale 0123abc", "fresh", "error: remote refused", "fresh-ish 0123abc"])
def test_prepare_fails_unless_the_first_publish_answers_fresh_and_a_commit(world, line):
    """The first publish must answer `fresh <commit>`; any other line fails prepare, which records the line and
    stays at prepare; the default answer completes it (RC-7, O1)."""
    world.publish.answers.append(line)
    tenant = world.create()
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["step"], item["step_actor"]) == ("creating", "prepare", "host")
    assert item["failure"] and line in item["failure"]
    assert len(world.publish.calls) == 1
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"
    assert len(world.publish.calls) == 2


def _plant_clone(world, tenant: str, origin: str) -> None:
    folder = world.data_root / tenant / "knowledge"
    folder.mkdir(parents=True)
    for args in (["init", "-q", str(folder)], ["-C", str(folder), "remote", "add", "origin", origin]):
        subprocess.run(["git", *args], check=True, capture_output=True)  # noqa: S603, S607
    (folder / "keep.txt").write_text("mine")


def test_prepare_keeps_an_existing_clone_of_the_recorded_repo_and_refuses_any_other(world):
    """A clone whose origin is the recorded one is kept; one with another origin fails prepare and is left as it
    was, publishing nothing (Flow 1.9, O1)."""
    good, bad = world.create(), world.create()
    world.drive(stop=lambda: world.item(good)["step"] == "prepare" and world.item(bad)["step"] == "prepare")
    origin = world.call(world.tenants.forge_wiring, good).origin
    _plant_clone(world, good, origin)
    _plant_clone(world, bad, "http://elsewhere.test/other.git")
    world.drive()
    assert world.item(good)["state"] == "active"
    assert (world.data_root / good / "knowledge" / "keep.txt").read_text() == "mine"
    item = world.item(bad)
    assert (item["state"], item["step"], item["step_actor"]) == ("creating", "prepare", "host")
    assert item["failure"]
    assert (world.data_root / bad / "knowledge" / "keep.txt").read_text() == "mine"
    assert [t for t, _ in world.publish.calls] == [good]


def _tree(path) -> list[str]:
    return sorted(str(p.relative_to(path)) for p in path.rglob("*")) if path.is_dir() else []


@pytest.mark.parametrize("linked", ["tenant", "dangling tenant", "learning"])
def test_prepare_refuses_a_link_at_the_tenant_folder_or_its_learning_root_and_resumes_once_removed(world, tmp_path, linked):
    """A linked or dangling `<T>`, or a linked `<T>/learning`, fails prepare (host) and publishes nothing; the link's
    target is untouched; with the link removed resume completes with a real empty `learning/` (GAP-Re-4, O6, O1)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "prepare")
    origin = world.call(world.tenants.forge_wiring, tenant).origin
    target = tmp_path / "elsewhere"
    link = world.data_root / tenant
    if linked == "dangling tenant":
        link.symlink_to(target)
    else:
        target.mkdir()
        (target / "keep.txt").write_text("mine")
        if linked == "tenant":
            link.symlink_to(target)
        else:
            _plant_clone(world, tenant, origin)
            link = link / "learning"
            link.symlink_to(target)
    before = _tree(target)
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["step"], item["step_actor"]) == ("creating", "prepare", "host"), item
    assert item["failure"]
    assert world.publish.calls == []
    assert link.is_symlink() and _tree(target) == before and target.exists() == (linked != "dangling tenant")
    link.unlink()
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"
    learning = world.data_root / tenant / "learning"
    assert learning.is_dir() and not learning.is_symlink() and list(learning.iterdir()) == []
    assert _tree(target) == before


def test_the_oidc_role_client_id_is_set_before_the_integration_step_commits(world):
    """The client id write fails: the integration step is not committed (no audience recorded) and stays the
    restart point; after resume the repeated, identical integration is the one the role and generation name (RC-6, P1, O3)."""
    flaky = openbao_failing(world, lambda r: _role_write(r) and bool(body_of(r).get("client_id")))
    tenant = world.create()
    world.drive()
    assert flaky.hit, "the client id was never written by the management login"
    item = world.item(tenant)
    assert (item["step"], item["step_actor"]) == ("integration", "service")
    [gen] = world.generations(tenant)
    assert gen.audience is None
    assert len(world.integration.calls) == 1
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"
    first, second = world.integration.calls
    assert first == second, "the repeated integration differs"
    live = world.live(tenant)
    assert world.forge.integrations[live.bot_login][-1] == live.audience
    assert len(world.forge.integrations[live.bot_login]) == 2  # the earlier one dies with the bot
    assert world.openbao.oidc_roles[live.oidc_role]["client_id"] == live.audience


def test_a_failing_bot_step_leaves_no_foreign_collaborator_after_resume(world):
    """Every collaborator but the bot is removed at the bot step, including one added while the job was stopped
    (Flow 1.5, O1)."""
    world.forge.fail_next[("POST", USERS)] = 500
    tenant = world.create()
    world.drive()
    full = f"{ORG}/{tenant}"
    world.forge.repos[full]["collaborators"]["intruder"] = "write"
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.forge.collaborators(full) == {world.live(tenant).bot_login: "write"}


def test_sweep_removes_unrecorded_secret_ids_and_secret_files_but_keeps_the_recorded_ones(world):
    """At the sweep every AppRole secret id but the live one and every file of the tenant's secrets directory no
    generation records are removed; another tenant's file is untouched (P1, RC-8, RC-9, DC-2)."""
    other = world.active_tenant()
    other_file = world.live(other).host_secret_file
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "sweep")
    [gen] = world.generations(tenant)
    stray_file = gen.host_secret_file.parent / "accessor-stray"
    stray_file.write_text("left by a crash")
    world.openbao.approles[gen.approle]["accessor-stray"] = "secret-stray"
    assert gen.host_secret_file.is_file()  # control: the recorded file is there
    world.drive()
    assert world.item(tenant)["state"] == "active"
    live = world.live(tenant)
    assert not stray_file.exists()
    assert live.host_secret_file.is_file() and other_file.is_file()
    assert world.openbao.secret_accessors(live.approle) == {live.secret_accessor}


def test_an_offboard_that_fails_midway_is_resumed_from_its_restart_point_and_finishes(world):
    """The archive fails after the credentials were destroyed: the failure keeps the `offboard` restart point; no
    retry; resume continues and the already-destroyed things are done, not errors (RC-4, DC-4, O4)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    world.forge.fail_next[("PATCH", f"/api/v1/repos/{ORG}/{tenant}")] = 500
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["step"], item["step_actor"]) == ("offboarding", "offboard", "service")
    assert "500" in item["failure"] and "offboard" in item["failure"]
    before = _calls(world)
    assert world.drive() == 0 and _calls(world) == before
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    assert world.item(tenant)["failure"] is None
    world.drive()
    record = world.record(tenant)
    assert (record.state, record.pending_action, record.failure) == ("offboarded", "delete_repo", None)
    assert gen.bot_login not in world.forge.users
    assert world.forge.repos[f"{ORG}/{tenant}"]["archived"] is True
    assert record.repo_delete_after == record.offboarded_at + REPO_WINDOW
