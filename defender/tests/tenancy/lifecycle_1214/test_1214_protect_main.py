# ruff: noqa: PT018
"""#1214 r8: `main`'s rule at tenant creation and at every rotation (A23): push off, merge whitelist on naming the
organisation's Owners team and no bot, other users and teams kept, read back as stored, install's can-merge check. In memory over the fakes."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214._fakes import ORG  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import as_bot, jwts  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _rules(world, tenant: str) -> str:
    return f"/api/v1/repos/{ORG}/{tenant}/branch_protections"


def _rotate(world, tenant: str) -> None:
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202


def _bot_view(world, gen, tenant: str) -> dict:
    return as_bot(world, jwts(world, gen)[-1], f"repos/{ORG}/{tenant}/branches/main").json()


def _writes(world, tenant: str, since: int = 0) -> list:
    return [c for c in world.forge.calls[since:] if c.method in ("POST", "PATCH") and c.path.startswith(_rules(world, tenant))]


def test_creation_stores_the_rule_for_the_owners_team_only_and_the_bot_cannot_merge(world):
    """Create sends push off and a merge whitelist of the Owners team with no user; the stored rule is exactly that
    and the bot reads can-push and can-merge false (A23, r8.2)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    [sent] = _writes(world, tenant)
    assert (sent.method, sent.body["enable_push"], sent.body["enable_merge_whitelist"]) == ("POST", False, True)
    assert (sent.body["merge_whitelist_teams"], sent.body.get("merge_whitelist_usernames") or []) == (["Owners"], [])
    rule = world.forge.rule(f"{ORG}/{tenant}")
    assert (rule["enable_push"], rule["enable_merge_whitelist"]) == (False, True)
    assert (rule["merge_whitelist_teams"], rule["merge_whitelist_usernames"]) == (["Owners"], [])
    view = _bot_view(world, gen, tenant)
    assert (view["protected"], view["user_can_push"], view["user_can_merge"]) == (True, False, False)


def test_a_rule_the_forge_refuses_fails_the_template_step_and_resumes_once_it_accepts(world):
    """The forge answers 422 to a whitelist naming a team the organisation lacks (here Owners): the step fails, no rule
    is stored and the job stops before wrapping anything; with the team back, resume finishes (A23, P-a)."""
    world.forge.orgs[ORG].discard("Owners")
    tenant = world.create()
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["step"], item["step_actor"]) == ("creating", "template", "service")
    assert item["failure"] and "template" in item["failure"]
    assert world.forge.made("POST", _rules(world, tenant)), "control: the forge was sent the rule and refused it"
    assert world.forge.rule(f"{ORG}/{tenant}") is None
    assert world.openbao.wrapped == {}
    world.forge.orgs[ORG].add("Owners")  # control: the same channel with the team present
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"


# --- rotation ---------------------------------------------------------------------------------------------

def test_a_rotation_writes_nothing_to_a_rule_that_already_holds_the_invariant(world):
    """A healthy rule is read back and left alone by rotation's `protect` step: no POST, no PATCH (A23, r8.3)."""
    tenant = world.active_tenant()
    before = dict(world.forge.rule(f"{ORG}/{tenant}"))
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["pending_action"] is None
    assert _writes(world, tenant, mark) == []
    assert any(c.method == "GET" and c.path.startswith(_rules(world, tenant)) for c in world.forge.calls[mark:]), \
        "control: rotation read the rule"
    assert world.forge.rule(f"{ORG}/{tenant}") == before


def test_a_rotation_heals_a_pre_r8_rule_and_the_new_bot_passes_install(world):
    """A tenant created before r8 (push on, no merge whitelist) is PATCHed by rotation to the invariant, the new bot
    can then neither push nor merge, and the rotation completes (A23, r8.3 upgrade)."""
    tenant = world.active_tenant()
    full = f"{ORG}/{tenant}"
    world.forge.put_rule(full, rule_name="main", branch_name="main", enable_push=True, enable_push_whitelist=False,
                         enable_merge_whitelist=False)
    assert _bot_view(world, world.live(tenant), tenant)["user_can_merge"] is True, "control: the old rule lets the bot merge"
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["failure"] is None
    [patch] = _writes(world, tenant, mark)
    assert (patch.method, patch.path) == ("PATCH", f"{_rules(world, tenant)}/main")
    rule = world.forge.rule(full)
    assert (rule["enable_push"], rule["enable_merge_whitelist"], rule["merge_whitelist_teams"]) == (False, True, ["Owners"])
    new = world.live(tenant)
    view = _bot_view(world, new, tenant)
    assert (view["user_can_push"], view["user_can_merge"]) == (False, False)


def test_a_rotation_disables_push_on_a_rule_that_otherwise_holds_the_invariant(world):
    """A rule with push enabled but the merge whitelist on, Owners named and no bot is PATCHed to push off by rotation's
    `protect`, and the rotation completes only with the stored rule holding (A23, r8.4 push disabled)."""
    tenant = world.active_tenant()
    full = f"{ORG}/{tenant}"
    world.forge.put_rule(full, rule_name="main", branch_name="main", enable_push=True, enable_push_whitelist=False,
                         enable_merge_whitelist=True, merge_whitelist_teams=["Owners"], merge_whitelist_usernames=[])
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["failure"] is None
    [patch] = _writes(world, tenant, mark)
    assert (patch.method, patch.body["enable_push"]) == ("PATCH", False)
    rule = world.forge.rule(full)
    assert (rule["enable_push"], rule["enable_merge_whitelist"], rule["merge_whitelist_teams"]) == (False, True, ["Owners"])
    assert _bot_view(world, world.live(tenant), tenant)["user_can_push"] is False


def test_a_rotation_makes_a_rule_that_is_missing(world):
    """A rule deleted by hand is made again by rotation's `protect` step with the invariant (POST) (A23, r8.3)."""
    tenant = world.active_tenant()
    full = f"{ORG}/{tenant}"
    del world.forge.repos[full]["protections"]["main"]
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["failure"] is None
    assert [c.method for c in _writes(world, tenant, mark)] == ["POST"]
    rule = world.forge.rule(full)
    assert (rule["enable_push"], rule["enable_merge_whitelist"], rule["merge_whitelist_teams"]) == (False, True, ["Owners"])


def test_a_rotation_whose_rule_the_forge_refuses_fails_at_protect_and_resumes_once_it_accepts(world):
    """A rule deleted by hand and an organisation that lost Owners: the forge refuses the rule at rotation (422), the
    rotation fails at `protect` with no new generation live; with the team back, resume completes (A23, r8.3)."""
    tenant = world.active_tenant()
    full = f"{ORG}/{tenant}"
    old = world.live(tenant)
    del world.forge.repos[full]["protections"]["main"]
    world.forge.orgs[ORG].discard("Owners")
    _rotate(world, tenant)
    world.drive()
    item = world.item(tenant)
    assert item["state"] == "active" and item["pending_action"] is not None and item["step"] == "protect", item
    assert item["failure"] and "protect" in item["failure"]
    assert world.forge.made("POST", _rules(world, tenant)), "control: the forge was sent the rule and refused it"
    assert world.live(tenant).salt == old.salt
    world.forge.orgs[ORG].add("Owners")  # control: the same channel with the team present
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["pending_action"] is None
    assert world.forge.rule(full)["merge_whitelist_teams"] == ["Owners"]


def test_rotation_removes_the_login_of_every_generation_from_the_whitelist_and_keeps_the_others(world):
    """On the second rotation the whitelist names a destroyed generation's bot, the live one and the pending one, a human, a bot-like
    login of no generation and a team: it ends with the human, that login, the team and Owners, and the PATCH sent that full list (A23, r8.1/r8.2)."""
    tenant = world.active_tenant()
    full = f"{ORG}/{tenant}"
    world.forge.team_members[(ORG, "Reviewers")] = {"carol"}
    world.forge.users.update({"carol", "bot-ops"})
    _rotate(world, tenant)
    world.drive()
    [destroyed] = [g for g in world.generations(tenant) if g.status == "destroyed"]
    first = destroyed.bot_login
    seen: list[None] = []

    def hold_every_generation() -> None:
        if not seen:
            seen.append(None)
            # Added here, after rotation's `bot` step (which leaves only the new bot collaborating, Flow 1.5): a
            # bot-like login that is not a generation's, with access, so "keeps the others" is really tested.
            world.forge.repos[full]["collaborators"]["bot-ops"] = "write"
            bots = [u for u in world.forge.users if u.startswith("bot-") and u != "bot-ops"]
            rule = world.forge.rule(full)
            world.forge.put_rule(full, **{**rule, "merge_whitelist_usernames": ["carol", "bot-ops", *bots],
                                          "merge_whitelist_teams": ["Reviewers", "Owners"]})
            rule = world.forge.rule(full)
            rule["merge_whitelist_usernames"] = [*rule["merge_whitelist_usernames"], first]  # the purged bot's stale name
    base = _rules(world, tenant)
    world.forge.during[("GET", f"{base}/main")] = hold_every_generation
    world.forge.during[("GET", base)] = hold_every_generation
    mark = len(world.forge.calls)
    _rotate(world, tenant)
    world.drive()
    assert seen and world.item(tenant)["state"] == "active"
    rule = world.forge.rule(full)
    assert sorted(rule["merge_whitelist_usernames"]) == ["bot-ops", "carol"]
    assert sorted(rule["merge_whitelist_teams"]) == ["Owners", "Reviewers"]
    [patch] = _writes(world, tenant, mark)
    assert sorted(patch.body["merge_whitelist_usernames"]) == ["bot-ops", "carol"]
    assert sorted(patch.body["merge_whitelist_teams"]) == ["Owners", "Reviewers"]
    assert patch.body["enable_merge_whitelist"] is True


@pytest.mark.parametrize("how", ["bot merge-whitelisted", "merge whitelist off"])
def test_rotation_install_fails_when_the_new_bot_can_merge_main_and_resumes_once_it_cannot(world, how):
    """Rotation's install makes the same check as creation's: a rule at install that lets the new bot merge fails install
    (restart at `wrap`) and commits no generation; restored, resume completes (A23, r8.3)."""
    tenant = world.active_tenant()
    full = f"{ORG}/{tenant}"
    saved = dict(world.forge.rule(full))
    old = world.live(tenant)
    _rotate(world, tenant)
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    [new] = [g for g in world.generations(tenant) if g.status == "pending"]
    broken = ({"enable_merge_whitelist": True, "merge_whitelist_usernames": [new.bot_login]} if how == "bot merge-whitelisted"
              else {"enable_merge_whitelist": False})
    world.forge.repos[full]["protections"]["main"] = {**saved, **broken}
    world.drive()
    item = world.item(tenant)
    assert "install" in (item["failure"] or ""), item
    assert (item["step"], item["step_actor"]) == ("wrap", "service")
    assert world.live(tenant).salt == old.salt, "the new generation went live"
    world.forge.repos[full]["protections"]["main"] = saved  # control: the same channel, protected again
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.live(tenant).salt == new.salt
