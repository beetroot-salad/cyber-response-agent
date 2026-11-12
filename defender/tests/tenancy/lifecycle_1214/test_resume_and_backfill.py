# ruff: noqa: PT018
"""#1214 failure, restart point and resume; names before things; the spent wrapper; first publish; sweep (O3, P1,
DC-4, RC-4, RC-6, RC-7, RC-8, DC-14) — in-memory twin. Real crashes (lock lost mid-step) are in test_worker_lock.

#1214 the lab's move, in memory over the fakes: the migration backfills the lab as a failed create at `names`; an
administrator records its forge wiring by hand and resumes it; the ordinary create job then makes it `active` on its
existing repo and clone with one fresh generation (O11, RC-9). There is no adoption code: the old row file, issuer
directory and unsalted OpenBao entries are removed by hand. The run on real Forgejo 17 is in `test_live.py`.

#1214 O8 tenant isolation and install's `main` check, in memory over the fakes (O8, O1, DC-11, F-6, F-7).
The live counterpart on real Forgejo and OpenBao is `test_live.py`.
"""
from __future__ import annotations

import subprocess

import pytest
import httpx

pytest.importorskip('fastapi')
pytest.importorskip('httpx')

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
from defender.tests.support.tenancy._active1214 import CREATED  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import FORGE_URL  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import as_bot  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import jwts, protection_reads  # noqa: E402


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
    return (gen.bot_login, gen.oidc_role, gen.approle, gen.entity, gen.sign_approle, gen.sign_entity)


def _calls(world) -> int:
    return len(world.forge.calls) + len(world.openbao.calls) + len(world.git.calls) + len(world.integration.calls) \
        + len(world.publish.calls)


@pytest.mark.parametrize("failing", list(FAILURES))
def test_a_failure_records_its_restart_point_is_not_retried_and_resume_only_clears_it(world, failing):
    """A failing step records failure plus its restart point (step, actor), names the step and the answer and no
    secret; nothing retries it; resume changes only `failure`; the job then finishes with no orphan or duplicate;
    the names recorded before the failing call, the sign ones included, are the ones used (O3, P1, DC-4, DC-14, A24')."""
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
    assert (live.bot_login, live.oidc_role, live.approle, live.entity, live.sign_approle, live.sign_entity) == names
    assert (set(world.forge.users), set(world.openbao.oidc_roles), set(world.openbao.approles),
            set(world.openbao.entities)) == ({names[0]}, {names[1]}, {names[2], names[4]}, {names[3], names[5]})
    assert list(world.forge.repos) == [f"{ORG}/{tenant}"]
    assert world.openbao.secret_accessors(live.approle) == {live.secret_accessor}
    assert world.openbao.secret_accessors(live.sign_approle) == {live.sign_secret_accessor}
    assert len(world.openbao.aliases) == 2 and list(world.openbao.transit_keys) == [f"request-token-{tenant}"]


@pytest.mark.parametrize("spent", ["delivery", "sign", "both"])
def test_a_spent_wrapper_found_when_install_is_taken_up_fails_loudly_and_restarts_at_wrap(world, spent):
    """Either wrapper (or both) is spent before the host unwraps it: install fails loudly, leaves no secret file, restarts
    at `wrap` (service); resume wraps both again and the job finishes with only the live secret ids (DC-4, A24')."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    [gen] = world.generations(tenant)
    assert len(world.openbao.wrapped) == 2, "control: a wrapped secret for each AppRole waits for the host"
    for token, (approle, _secret, _accessor) in dict(world.openbao.wrapped).items():
        if spent == "both" or (approle == gen.sign_approle) == (spent == "sign"):
            del world.openbao.wrapped[token]  # the unwrap happened and the host died before it committed
    world.drive()
    item = world.item(tenant)
    assert (item["step"], item["step_actor"]) == ("wrap", "service")
    assert "install" in item["failure"]
    assert not [p for p in world.config.secrets_dir.rglob("*") if p.is_file()], "a failed install left a secret file"
    assert world.drive() == 0
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"
    wraps = [c for c in world.openbao.calls if c.path.endswith("/secret-id") and "x-vault-wrap-ttl" in c.headers]
    assert len(wraps) == 4, "resume did not wrap a fresh secret for each AppRole"
    live = world.live(tenant)
    assert world.openbao.secret_accessors(live.approle) == {live.secret_accessor}
    assert world.openbao.secret_accessors(live.sign_approle) == {live.sign_secret_accessor}


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


# Retired by #1278 O10/D10: the `learning` case ("a linked `<T>/learning` fails prepare"). Prepare no longer creates or reads
# `<T>/learning` (the tenant's learning state is rows), so a link there is not prepare's to refuse; the folder-link cases stay.
@pytest.mark.parametrize("linked", ["tenant", "dangling tenant"])
def test_prepare_refuses_a_link_at_the_tenant_folder_and_resumes_once_removed(world, tmp_path, linked):
    """A linked or dangling `<T>` fails prepare (host) and publishes nothing; the link's target is untouched; with the
    link removed resume completes and no `learning` entry exists (O6, O1, O10)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "prepare")
    target = tmp_path / "elsewhere"
    link = world.data_root / tenant
    if linked == "dangling tenant":
        link.symlink_to(target)
    else:
        target.mkdir()
        (target / "keep.txt").write_text("mine")
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
    assert not list((world.data_root / tenant).rglob("learning"))
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
    """At the sweep every secret id of both AppRoles but the installed ones and every file of the tenant's secrets
    directory no generation records are removed; another tenant's files are untouched (P1, RC-8, RC-9, DC-2, A24')."""
    other = world.active_tenant()
    other_files = [world.live(other).host_secret_file, world.live(other).sign_secret_file]
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "sweep")
    [gen] = world.generations(tenant)
    stray_file = gen.host_secret_file.parent / "accessor-stray"
    stray_file.write_text("left by a crash")
    world.openbao.approles[gen.approle]["accessor-stray"] = "secret-stray"
    world.openbao.approles[gen.sign_approle]["accessor-stray-sign"] = "secret-stray-sign"
    assert gen.host_secret_file.is_file() and gen.sign_secret_file.is_file()  # control: the recorded files are there
    world.drive()
    assert world.item(tenant)["state"] == "active"
    live = world.live(tenant)
    assert not stray_file.exists()
    assert live.host_secret_file.is_file() and live.sign_secret_file.is_file() and all(p.is_file() for p in other_files)
    assert world.openbao.secret_accessors(live.approle) == {live.secret_accessor}
    assert world.openbao.secret_accessors(live.sign_approle) == {live.sign_secret_accessor}


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


LAB = "5e1f0c7a-3b2d-4c68-9a41-7d8e6f0b2a13"


LAB_REPO = f"{ORG}/playground"


BACKFILL_FAILURE = "registered before #1214: record its forge wiring if it has a repository, then resume"


HAND_MADE = "hand-made-bot"


USER_OWNER = "alice"


def _forge(world: LifecycleWorld, method: str, path: str, **body):
    return world.forge.handle(httpx.Request(method, f"{FORGE_URL}/api/v1/{path}", json=body or None,
                                            headers={"Authorization": "token forge-admin-token"}))


def _git(*args: str, cwd) -> None:
    subprocess.run(["git", "-c", "user.name=lab", "-c", "user.email=lab@example.test", *args],  # noqa: S603, S607
                   cwd=cwd, check=True, capture_output=True)


class Lab:
    """The pre-#1214 lab: forge repo with a commit, a hand-made collaborator and a clone; the row is backfilled
    (step `names`, failure set) and the administrator has recorded its wiring."""

    def __init__(self, world: LifecycleWorld, *, clone_in: str = "knowledge", owner: str = ORG,
                 rule: dict | None = None) -> None:
        """`owner` is the repository's organisation (made if the fake does not know it with an `Owners` team, as a real
        organisation has) or, when it is `alice`, a user; `rule` is a branch protection rule an administrator made by hand."""
        self.world = world
        self.repo = f"{owner}/playground"
        self.folder = world.data_root / LAB
        self.clone = self.folder / clone_in
        if owner == USER_OWNER:
            world.forge.add_user_repo(owner, "playground")
        else:
            world.forge.orgs.setdefault(owner, {"Owners"})
            assert _forge(world, "POST", f"orgs/{owner}/repos", name="playground", private=True).status_code == 201
        assert _forge(world, "POST", "admin/users", username=HAND_MADE).status_code == 201
        assert _forge(world, "PUT", f"repos/{self.repo}/collaborators/{HAND_MADE}", permission="write").status_code == 204
        self.clone.mkdir(parents=True)
        _git("init", "-q", "-b", "main", cwd=self.clone)
        (self.clone / "agent").mkdir()
        (self.clone / "agent" / ".tenant-id").write_text(f"{LAB}\n", encoding="utf-8")
        _git("add", "-A", cwd=self.clone)
        _git("commit", "-q", "-m", "lab", cwd=self.clone)
        _git("remote", "add", "origin", f"{FORGE_URL}/{self.repo}.git", cwd=self.clone)
        _git("push", "-q", str(world.forge.bare(self.repo)), "main", cwd=self.clone)
        (self.clone / "keep.txt").write_text("the lab's own clone\n", encoding="utf-8")
        world.call(world.tenants.add_tenant, LAB, created_at=CREATED, state="creating", pending_action="create",
                   step="names", step_actor="service", failure=BACKFILL_FAILURE, repo=self.repo,
                   origin=f"{FORGE_URL}/{self.repo}.git")
        if rule is not None:
            world.forge.put_rule(self.repo, **rule)
        self.forge_calls = len(world.forge.calls)
        self.git_calls = len(world.git.calls)

    def resume(self) -> None:
        assert self.world.ops.post(f"/admin/tenants/{LAB}/resume").status_code == 202


@pytest.fixture
def lab(world) -> Lab:
    return Lab(world)


def test_a_working_copy_at_the_tenant_folder_itself_is_not_its_clone(world):
    """The tenant's clone is `<T>/knowledge`, where every entry point accepts it; a working copy at `<T>` itself is
    not kept as the clone: prepare clones the recorded origin into `knowledge` (Flow 1.9)."""
    lab = Lab(world, clone_in=".")
    lab.resume()
    world.drive()
    assert world.item(LAB)["state"] == "active"
    assert [1 for args, _e in world.git.calls[lab.git_calls:] if "clone" in args], "the working copy at <T> was kept"
    assert (lab.folder / "knowledge" / ".git").exists()


def test_a_backfilled_row_does_nothing_until_resumed(world, lab):
    """The actors skip the backfilled row: its failure holds it until an administrator resumes it (O11, RC-3)."""
    assert world.drive() == 0
    item = world.item(LAB)
    assert (item["step"], item["step_actor"], item["failure"]) == ("names", "service", BACKFILL_FAILURE)
    assert len(world.forge.calls) == lab.forge_calls and len(world.openbao.calls) == 0


def test_the_job_keeps_the_recorded_wiring_skips_repo_and_template_and_keeps_the_clone(world, lab):
    """Resumed, the actors finish the job on the existing repo `tenants/playground`: wiring kept, no repo created, no
    template push, the clone kept and not re-cloned, no `learning/` made (RC-9, Flow 1.9, O10)."""
    lab.resume()
    world.drive()
    assert world.item(LAB)["state"] == "active"
    wiring = world.call(world.tenants.forge_wiring, LAB)
    assert wiring.repo == LAB_REPO
    assert set(world.forge.repos) == {LAB_REPO}, "the job made another repo"
    new_calls = world.forge.calls[lab.forge_calls:]
    assert not [c for c in new_calls if (c.method, c.path) == ("POST", f"/api/v1/orgs/{ORG}/repos")]
    assert world.git.pushes() == [], "the template was committed over an existing repository"
    assert not [1 for args, _e in world.git.calls[lab.git_calls:] if "clone" in args]
    assert (lab.clone / "keep.txt").read_text(encoding="utf-8") == "the lab's own clone\n"
    assert not (lab.folder / "learning").exists(), "prepare made a learning entry (O10)"
    assert "main" in world.forge.repos[LAB_REPO]["protections"]
    [made] = [c for c in world.integration.created if c["user"] == world.live(LAB).bot_login]
    assert made["repos"] == [LAB_REPO], "the integration names the recorded repo, not one derived from the id (FR-2)"
    assert world.publish.calls == [(LAB, world.data_root)]


def test_the_job_leaves_one_fresh_generation_and_only_its_bot_on_the_repo(world, lab):
    """One live generation; the hand-made collaborator is removed, the new bot is the only collaborator with
    write (Flow 1.5)."""
    assert HAND_MADE in world.forge.collaborators(LAB_REPO), "control: the hand-made bot is there before"
    lab.resume()
    world.drive()
    gens = world.generations(LAB)
    [live] = [g for g in gens if g.status == "live"]
    assert len(gens) == 1
    assert world.forge.collaborators(LAB_REPO) == {live.bot_login: "write"}


# --- A23: the lab's rule on `main` (a rule that exists is changed, not recreated) ---------------------------------

LABS = "labs"


HAND_RULE = {"rule_name": "main", "branch_name": "main", "enable_push": True, "enable_push_whitelist": False,
             "enable_merge_whitelist": False, "required_approvals": 2, "block_on_rejected_reviews": True,
             "enable_status_check": True, "status_check_contexts": ["ci"]}


def _bot_view(world: LifecycleWorld, repo: str) -> dict:
    """`GET branches/main` as the lab's live bot (a fresh JWT of its generation), the check install makes."""
    jwt = [j for role, j in world.openbao.minted if role == world.live(LAB).oidc_role][-1]
    return as_bot(world, jwt, f"repos/{repo}/branches/main").json()


def test_a_lab_without_a_rule_gets_main_protected_for_its_own_organisations_owners_and_no_bot(world):
    """The lab's rule is made with push off and the merge whitelist on naming the lab's organisation's Owners team
    and no user; the bot reads can-push and can-merge false (A23, r8.2)."""
    lab = Lab(world, owner=LABS)
    lab.resume()
    world.drive()
    assert world.item(LAB)["state"] == "active"
    rule = world.forge.rule(LABS + "/playground")
    assert (rule["enable_push"], rule["enable_merge_whitelist"]) == (False, True)
    assert (rule["merge_whitelist_teams"], rule["merge_whitelist_usernames"]) == (["Owners"], [])
    view = _bot_view(world, lab.repo)
    assert (view["protected"], view["user_can_push"], view["user_can_merge"]) == (True, False, False)


def test_a_hand_made_rule_is_patched_keeping_its_other_settings_users_and_teams_and_dropping_every_bot(world):
    """The lab's existing rule is PATCHed, not recreated: push off, whitelist on with the full lists sent (the human user, a
    bot-like login of no generation and the team kept, Owners added, the pending bot removed), every other setting as it was (A23, r8.1/r8.2)."""
    world.forge.team_members[(LABS, "Reviewers")] = {"carol"}
    world.forge.orgs.setdefault(LABS, {"Owners"}).add("Reviewers")
    world.forge.users.update({"carol", "bot-ops"})
    base = f"/api/v1/repos/{LABS}/playground/branch_protections"
    seen: list[None] = []

    def whitelist_the_pending_bot() -> None:  # an administrator's earlier mistake, at the moment the step reads the rule
        if not seen:
            seen.append(None)
            bot = next(u for u in world.forge.users if u.startswith("bot-") and u != "bot-ops")
            world.forge.repos[f"{LABS}/playground"]["collaborators"]["bot-ops"] = "write"  # bot-like, no generation's
            world.forge.put_rule(f"{LABS}/playground", **{**HAND_RULE, "enable_merge_whitelist": True,
                                 "merge_whitelist_usernames": ["carol", "bot-ops", bot], "merge_whitelist_teams": ["Reviewers"]})
    lab = Lab(world, owner=LABS, rule=HAND_RULE)
    world.forge.during[("GET", f"{base}/main")] = whitelist_the_pending_bot
    world.forge.during[("GET", base)] = whitelist_the_pending_bot
    lab.resume()
    world.drive()
    assert world.item(LAB)["state"] == "active"
    assert seen, "control: the rule held the pending bot when the step read it"
    rule = world.forge.rule(lab.repo)
    assert rule["enable_push"] is False and rule["enable_merge_whitelist"] is True
    assert sorted(rule["merge_whitelist_usernames"]) == ["bot-ops", "carol"]
    assert sorted(rule["merge_whitelist_teams"]) == ["Owners", "Reviewers"]
    assert (rule["required_approvals"], rule["status_check_contexts"], rule["block_on_rejected_reviews"]) == (2, ["ci"], True)
    assert world.forge.made("POST", base) == [], "an existing rule was created again"
    [patch] = world.forge.made("PATCH", f"{base}/main")
    assert sorted(patch.body["merge_whitelist_usernames"]) == ["bot-ops", "carol"]
    assert sorted(patch.body["merge_whitelist_teams"]) == ["Owners", "Reviewers"]
    assert (patch.body["enable_merge_whitelist"], patch.body["enable_push"]) == (True, False)
    assert _bot_view(world, lab.repo)["user_can_merge"] is False


def test_a_whitelist_left_with_only_the_bot_is_never_stored_empty(world):
    """A rule whose merge whitelist names only the bot ends naming Owners: an enabled whitelist stored empty would let
    nobody merge, the owners included (A23 never-empty, P-a)."""
    base = f"/api/v1/repos/{LABS}/playground/branch_protections"

    def only_the_pending_bot() -> None:
        bot = next(u for u in world.forge.users if u.startswith("bot-"))
        world.forge.put_rule(f"{LABS}/playground", **{**HAND_RULE, "enable_merge_whitelist": True,
                             "merge_whitelist_usernames": [bot], "merge_whitelist_teams": []})
    lab = Lab(world, owner=LABS, rule=HAND_RULE)
    world.forge.during[("GET", f"{base}/main")] = only_the_pending_bot
    world.forge.during[("GET", base)] = only_the_pending_bot
    lab.resume()
    world.drive()
    rule = world.forge.rule(lab.repo)
    assert (rule["merge_whitelist_usernames"], rule["merge_whitelist_teams"]) == ([], ["Owners"])
    assert world.item(LAB)["state"] == "active"


def test_a_repository_owned_by_a_user_fails_the_template_step_because_the_stored_rule_has_no_team(world):
    """A user-owned repository answers 201 to a team whitelist and stores none: the stored read-back fails the step, so
    the job stops at `template` before any secret is wrapped (A23 read-back, P-a)."""
    lab = Lab(world, owner=USER_OWNER)
    lab.resume()
    world.drive()
    item = world.item(LAB)
    assert (item["state"], item["step"], item["step_actor"]) == ("creating", "template", "service")
    assert item["failure"] and "template" in item["failure"]
    assert world.forge.made("POST", f"/api/v1/repos/{lab.repo}/branch_protections"), "control: the rule was sent"
    assert world.forge.rule(lab.repo)["merge_whitelist_teams"] == []
    assert world.openbao.wrapped == {} and world.openbao.made("POST", "/v1/sys/wrapping/unwrap") == []


def _login_and_mint(world: LifecycleWorld, gen, role: str | None = None) -> httpx.Response:
    """What the host does with a generation's AppRole pair: log in, then read `identity/oidc/token/<role>`."""
    bao = httpx.Client(transport=httpx.MockTransport(world.openbao.handle), base_url="https://openbao.test")
    secret = world.openbao.approles[gen.approle][gen.secret_accessor]
    logged = bao.post("/v1/auth/approle/login", json={"role_id": gen.role_id, "secret_id": secret})
    assert logged.status_code == 200, logged.text
    token = logged.json()["auth"]["client_token"]
    return bao.get(f"/v1/identity/oidc/token/{role or gen.oidc_role}", headers={"X-Vault-Token": token})


def _two(world: LifecycleWorld):
    a, b = world.active_tenant(), world.active_tenant()
    return a, world.live(a), b, world.live(b)


def test_a_credential_of_one_tenant_gets_404_on_the_others_repo_and_200_on_its_own(world):
    """A's bot JWT reads A's repo (200, control) and is told 404 for B's repo through A's integration (O8)."""
    a, gen_a, b, _gen_b = _two(world)
    jwt = jwts(world, gen_a)[-1]
    assert as_bot(world, jwt, f"repos/{ORG}/{a}").status_code == 200
    assert as_bot(world, jwt, f"repos/{ORG}/{b}").status_code == 404


def test_a_jwt_of_one_tenant_is_refused_by_the_others_integration_on_its_claim(world):
    """Mis-wire A's OIDC role to B's audience: B's integration refuses the JWT's `tenant_id` claim (401), while the
    same JWT shape for B itself is accepted (O8, F-6)."""
    a, gen_a, b, gen_b = _two(world)
    minted = _login_and_mint(world, gen_b)
    assert minted.status_code == 200
    own = as_bot(world, minted.json()["data"]["token"], f"repos/{ORG}/{b}")
    assert own.status_code == 200, "control: B's own mint is accepted by B's integration"
    world.openbao.oidc_roles[gen_a.oidc_role]["client_id"] = gen_b.audience
    crossed = _login_and_mint(world, gen_a)
    assert crossed.status_code == 200
    jwt = crossed.json()["data"]["token"]
    assert world.openbao.claims(jwt)["tenant_id"] == a
    assert as_bot(world, jwt, f"repos/{ORG}/{b}").status_code == 401
    assert as_bot(world, jwt, f"repos/{ORG}/{a}").status_code == 401


def test_an_entity_reads_only_its_own_oidc_role(world):
    """The templated policy: A's login mints A's role (control) and is refused B's (O8, F-6)."""
    _a, gen_a, _b, gen_b = _two(world)
    assert _login_and_mint(world, gen_a).status_code == 200
    assert _login_and_mint(world, gen_a, role=gen_b.oidc_role).status_code == 403


def test_the_entity_carries_the_role_and_tenant_the_templated_policy_and_the_claim_read(world):
    """The entity's metadata names its OIDC role and its tenant, and its alias is the AppRole's role id (G10, F-6)."""
    a, gen, _b, _gen_b = _two(world)
    metadata = world.openbao.entities[gen.entity]["metadata"]
    assert metadata["oidc_role"] == gen.oidc_role and metadata["tenant_id"] == a
    assert [x for x in world.openbao.aliases if x.get("name") == gen.role_id], "no alias named by the role id"


def test_each_integration_is_created_with_the_issuer_the_tenant_claim_the_repo_and_a_write_scope(world):
    """`--issuer <config.issuer_url> --claim-eq tenant_id=<T> --repo tenants/<T>` and a write scope (F-6, O8)."""
    a, gen_a, b, gen_b = _two(world)
    for tenant, gen in ((a, gen_a), (b, gen_b)):
        [made] = [c for c in world.integration.created if c["user"] == gen.bot_login]
        assert made["issuer"] == world.config.issuer_url
        assert made["claims_eq"] == {"tenant_id": tenant}
        assert made["repos"] == [f"{ORG}/{tenant}"]
        assert set(made["scopes"]) & {"write:repository", "all"}, made["scopes"]
        assert made["audience"] == gen.audience


# --- install's check that the bot cannot push main (DC-11, F-7) -------------------------------------

def _break_protection(world: LifecycleWorld, tenant: str, how: str) -> dict:
    full = f"{ORG}/{tenant}"
    bot = world.generations(tenant)[0].bot_login
    protections = world.forge.repos[full]["protections"]
    saved = dict(protections["main"])
    if how == "missing":
        del protections["main"]
    elif how == "bot merge-whitelisted":  # A23: the bot is named on the merge whitelist
        protections["main"] = {**saved, "enable_merge_whitelist": True, "merge_whitelist_usernames": [bot]}
    elif how == "merge whitelist off":  # A22: pushes blocked, no merge whitelist: the bot can merge
        protections["main"] = {**saved, "enable_merge_whitelist": False}
    else:
        protections["main"] = {**saved, "enable_push": True, "push_whitelist_usernames": [bot]}
    return saved


@pytest.mark.parametrize("how", ["missing", "bot whitelisted", "bot merge-whitelisted", "merge whitelist off"])
def test_install_fails_loudly_when_the_bot_could_push_or_merge_main_and_resumes_once_it_cannot(world, how):
    """A protection that leaves the bot able to push or merge `main` fails install (failure names it), commits no
    generation, tries no push; restored, resume finishes the job (DC-11, O1, A23)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    saved = _break_protection(world, tenant, how)
    world.drive()
    item = world.item(tenant)
    assert item["state"] == "creating" and "install" in item["failure"], item
    assert (item["step"], item["step_actor"]) == ("wrap", "service"), item  # DC-4: the check runs after the unwrap; the wrapper is spent
    assert not [g for g in world.generations(tenant) if g.status == "live"]
    assert world.publish.calls == []
    assert len(world.git.pushes()) == 1, "only the template commit may be pushed"
    assert not [1 for args, _e in world.git.calls if "--dry-run" in args]
    world.forge.repos[f"{ORG}/{tenant}"]["protections"]["main"] = saved  # control: the same channel, protected again
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"
    assert len(world.git.pushes()) == 1


def test_the_protection_read_back_is_the_rule_on_main_that_stops_the_bot(world):
    """The recorded protection rule is for `main`, does not whitelist the bot, and `branches/main` agrees (O1, DC-11)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    rule = world.forge.repos[f"{ORG}/{tenant}"]["protections"]["main"]
    assert (rule.get("rule_name") or rule.get("branch_name")) == "main"
    assert gen.bot_login not in (rule.get("push_whitelist_usernames") or [])
    reads = [world.forge.calls[i] for i in protection_reads(world, f"{ORG}/{tenant}")]
    assert reads and reads[-1].headers["authorization"].startswith("token "), "read back as the administrator"
