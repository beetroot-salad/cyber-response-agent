# ruff: noqa: PT018
"""#1214 the lab's move, in memory over the fakes: the migration backfills the lab as a failed create at `names`; an
administrator records its forge wiring by hand and resumes it; the ordinary create job then makes it `active` on its
existing repo and clone with one fresh generation (O11, RC-9). There is no adoption code: the old row file, issuer
directory and unsalted OpenBao entries are removed by hand. The run on real Forgejo 17 is in `test_1214_live.py`.
"""
from __future__ import annotations

import subprocess

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.tenancy._active1214 import CREATED  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import FORGE_URL, ORG  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import as_bot  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402

LAB = "5e1f0c7a-3b2d-4c68-9a41-7d8e6f0b2a13"
LAB_REPO = f"{ORG}/playground"
BACKFILL_FAILURE = "registered before #1214: record its forge wiring if it has a repository, then resume"
HAND_MADE = "hand-made-bot"
USER_OWNER = "alice"


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


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
    template push, the clone kept and not re-cloned, an empty `learning/` made (RC-9, Flow 1.9)."""
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
    assert (lab.folder / "learning").is_dir() and not list((lab.folder / "learning").iterdir())
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
    """The lab's existing rule is PATCHed, not recreated: push off, whitelist on with the full lists sent (the human user
    and team kept, Owners added, the pending bot removed), every other setting as it was (A23, r8.1/r8.2)."""
    world.forge.team_members[(LABS, "Reviewers")] = {"carol"}
    world.forge.orgs.setdefault(LABS, {"Owners"}).add("Reviewers")
    base = f"/api/v1/repos/{LABS}/playground/branch_protections"
    seen: list[None] = []

    def whitelist_the_pending_bot() -> None:  # an administrator's earlier mistake, at the moment the step reads the rule
        if not seen:
            seen.append(None)
            bot = next(u for u in world.forge.users if u.startswith("bot-"))
            world.forge.put_rule(f"{LABS}/playground", **{**HAND_RULE, "enable_merge_whitelist": True,
                                 "merge_whitelist_usernames": ["carol", bot], "merge_whitelist_teams": ["Reviewers"]})
    lab = Lab(world, owner=LABS, rule=HAND_RULE)
    world.forge.during[("GET", f"{base}/main")] = whitelist_the_pending_bot
    world.forge.during[("GET", base)] = whitelist_the_pending_bot
    lab.resume()
    world.drive()
    assert world.item(LAB)["state"] == "active"
    assert seen, "control: the rule held the pending bot when the step read it"
    rule = world.forge.rule(lab.repo)
    assert rule["enable_push"] is False and rule["enable_merge_whitelist"] is True
    assert rule["merge_whitelist_usernames"] == ["carol"]
    assert sorted(rule["merge_whitelist_teams"]) == ["Owners", "Reviewers"]
    assert (rule["required_approvals"], rule["status_check_contexts"], rule["block_on_rejected_reviews"]) == (2, ["ci"], True)
    assert world.forge.made("POST", base) == [], "an existing rule was created again"
    [patch] = world.forge.made("PATCH", f"{base}/main")
    assert patch.body["merge_whitelist_usernames"] == ["carol"]
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
