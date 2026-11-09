"""#1307 — the programs realm (`defender-programs`) is code: a committed export beside the people realm's,
imported by the dev compose, checked like it (each check also runs against a good synthetic realm and
single-field mutations). The people realm's admin keeping only `manage-users` is already pinned by
`test_1306_realm_export.py::test_the_api_service_account_may_only_manage_users`.
Not observable here: "nothing in master" (a realm export holds one realm; the file is checked to be that realm only)
and "only discovery, token and certs reachable from outside" (the dev compose publishes the whole Keycloak port on
loopback, no proxy: a deployment fact).

Forced choice (FC-10): file `.devcontainer/keycloak/realm-defender-programs.json`; admin client
`defender-api-programs-admin`; audience client `defender-api-programs`.
"""
from __future__ import annotations

import copy
import json

import pytest
import yaml

from defender._git import REPO_ROOT

PROGRAMS_EXPORT = REPO_ROOT / ".devcontainer" / "keycloak" / "realm-defender-programs.json"
COMPOSE = REPO_ROOT / ".devcontainer" / "docker-compose.yml"
REALM = "defender-programs"
ADMIN_CLIENT = "defender-api-programs-admin"
AUDIENCE = "defender-api-programs"
PEOPLE_LOGIN_CLIENT = "defender-api"
FLOWS = ("standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled")


def _clients(realm: dict) -> dict[str, dict]:
    return {c["clientId"]: c for c in realm.get("clients", [])}


def check_realm_switches(realm: dict) -> None:
    assert realm["realm"] == REALM
    assert realm["registrationAllowed"] is False


def check_admin_client_may_only_manage_clients(realm: dict) -> None:
    client = _clients(realm)[ADMIN_CLIENT]
    assert client["serviceAccountsEnabled"] is True
    assert client.get("publicClient") is False
    assert all(client.get(flow) is False for flow in FLOWS)
    [account] = [u for u in realm.get("users", []) if u.get("serviceAccountClientId") == ADMIN_CLIENT]
    assert account["clientRoles"] == {"realm-management": ["manage-clients"]}
    assert set(account.get("realmRoles", [])) <= {f"default-roles-{REALM}"}


def check_the_audience_is_its_own_flowless_client(realm: dict) -> None:
    client = _clients(realm)[AUDIENCE]
    assert client.get("serviceAccountsEnabled", False) is False
    assert all(client.get(flow) is False for flow in FLOWS)


def check_no_people_in_the_realm(realm: dict) -> None:
    assert [u for u in realm.get("users", []) if u.get("serviceAccountClientId") != ADMIN_CLIENT] == []
    assert set(_clients(realm)) & {PEOPLE_LOGIN_CLIENT} == set()


def check_only_program_relevant_clients(realm: dict) -> None:
    """Program clients are created at run time; the export holds the API's admin and audience clients, nothing else."""
    assert sorted(c["clientId"] for c in realm.get("clients", [])) == sorted([ADMIN_CLIENT, AUDIENCE])


def check_no_client_has_a_browser_flow(realm: dict) -> None:
    for client in realm.get("clients", []):
        assert all(client.get(flow) is False for flow in FLOWS), client["clientId"]


def check_admin_client_mints_no_api_tokens(realm: dict) -> None:
    """A mapper on the admin client could put the programs audience into its own tokens."""
    assert _clients(realm)[ADMIN_CLIENT].get("protocolMappers", []) == []


def _role_definitions(realm: dict) -> tuple[dict[str, dict], dict[str, dict[str, dict]]]:
    """(realm role name -> definition, client id -> role name -> definition) as the export spells them; the realm's `defaultRole` is
    the definition of the realm role it names."""
    roles = realm.get("roles", {})
    realm_roles = {r["name"]: r for r in roles.get("realm", [])}
    if "defaultRole" in realm:
        realm_roles.setdefault(realm["defaultRole"]["name"], realm["defaultRole"])
        realm_roles[realm["defaultRole"]["name"]] = {**realm_roles[realm["defaultRole"]["name"]], **realm["defaultRole"]}
    return realm_roles, {cid: {r["name"]: r for r in rows} for cid, rows in roles.get("client", {}).items()}


def _group_roles(realm: dict, paths: list[str]) -> tuple[set[str], dict[str, set[str]]]:
    """The realm and client roles the groups at `paths` give a member: their own and those of every ancestor group (a member of a
    subgroup inherits its parents' roles). The export spells groups as a tree (`groups`, each with `realmRoles`, `clientRoles` and
    `subGroups`); a path that names no group gives nothing."""
    by_path: dict[str, tuple[dict, list[dict]]] = {}

    def walk(groups: list[dict], parent: str, chain: list[dict]) -> None:
        for group in groups:
            path = f"{parent}/{group['name']}"
            by_path[path] = (group, [*chain, group])
            walk(group.get("subGroups", []), path, [*chain, group])

    walk(realm.get("groups", []), "", [])
    realm_roles: set[str] = set()
    client_roles: dict[str, set[str]] = {}
    for path in paths:
        for group in by_path.get(path, ({}, []))[1]:
            realm_roles |= set(group.get("realmRoles", []))
            for client, roles in group.get("clientRoles", {}).items():
                client_roles.setdefault(client, set()).update(roles)
    return realm_roles, client_roles


def effective_roles(realm: dict, realm_roles: set[str], client_roles: dict[str, set[str]],
                    groups: list[str] | None = None) -> tuple[set[str], dict[str, set[str]]]:
    """Every realm role and client role a principal holds once composites are expanded, through realm and client roles alike;
    `groups` (paths) add the roles of those groups and their ancestors before the expansion."""
    group_realm, group_client = _group_roles(realm, groups or [])
    realm_roles = realm_roles | group_realm
    client_roles = {c: set(rs) for c, rs in client_roles.items()}
    for client, roles in group_client.items():
        client_roles.setdefault(client, set()).update(roles)
    realm_defs, client_defs = _role_definitions(realm)
    seen_realm: set[str] = set()
    seen_client: dict[str, set[str]] = {}
    work: list[tuple[str | None, str]] = [(None, r) for r in realm_roles] + [(c, r) for c, rs in client_roles.items() for r in rs]
    while work:
        owner, name = work.pop()
        if owner is None:
            if name in seen_realm:
                continue
            seen_realm.add(name)
            definition = realm_defs.get(name, {})
        else:
            if name in seen_client.setdefault(owner, set()):
                continue
            seen_client[owner].add(name)
            definition = client_defs.get(owner, {}).get(name, {})
        composites = definition.get("composites", {}) if definition.get("composite", True) else {}
        work += [(None, r) for r in composites.get("realm", [])]
        work += [(c, r) for c, rs in composites.get("client", {}).items() for r in rs]
    return seen_realm, seen_client


def check_no_service_account_gets_more_than_its_clients_roles_through_composites(realm: dict) -> None:
    """The default role every new user (every program client's service account) is given contributes no realm-management role,
    and the API's admin account holds exactly `manage-clients` of it once the default role and every composite, realm or client,
    are expanded, groups included (the realm's default groups, the account's own groups and their parents) (OAuth clients: Realm). Direct role lists alone do not show what an account can do."""
    default = realm.get("defaultRole", {}).get("name", f"default-roles-{REALM}")
    default_groups = list(realm.get("defaultGroups", []))  # every new user joins these
    _, from_default = effective_roles(realm, {default}, {}, default_groups)
    assert from_default.get("realm-management", set()) == set(), from_default
    accounts = [u for u in realm.get("users", []) if u.get("serviceAccountClientId")]
    assert ADMIN_CLIENT in {u["serviceAccountClientId"] for u in accounts}
    for account in accounts:
        direct = {k: set(v) for k, v in account.get("clientRoles", {}).items()}
        _, held = effective_roles(realm, {default, *account.get("realmRoles", [])}, direct,
                                  [*default_groups, *account.get("groups", [])])
        management = held.get("realm-management", set())
        if account["serviceAccountClientId"] == ADMIN_CLIENT:
            assert management == {"manage-clients"}, management
        else:
            assert management == set(), (account["username"], management)


CHECKS = [check_realm_switches, check_admin_client_may_only_manage_clients,
          check_the_audience_is_its_own_flowless_client, check_no_people_in_the_realm,
          check_only_program_relevant_clients, check_no_client_has_a_browser_flow,
          check_admin_client_mints_no_api_tokens, check_no_service_account_gets_more_than_its_clients_roles_through_composites]


def _committed() -> dict:
    assert PROGRAMS_EXPORT.is_file(), f"no programs realm export at {PROGRAMS_EXPORT.relative_to(REPO_ROOT)}"
    return json.loads(PROGRAMS_EXPORT.read_text(encoding="utf-8"))


@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.__name__)
def test_the_committed_programs_realm_passes(check):
    """The committed export holds the programs realm's settings (OAuth clients: Realm)."""
    check(_committed())


def test_the_dev_compose_imports_the_programs_realm():
    """Keycloak starts with both realm exports mounted for `--import-realm`."""
    keycloak = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["keycloak"]
    mounted = [str(v).split(":")[0] for v in keycloak.get("volumes", [])]
    assert any((COMPOSE.parent / m).resolve() == PROGRAMS_EXPORT.resolve() for m in mounted), mounted
    targets = [str(v).split(":")[1] for v in keycloak["volumes"] if str(v).split(":")[0].endswith("realm-defender-programs.json")]
    assert [t.rsplit("/", 1)[0] for t in targets] == ["/opt/keycloak/data/import"], targets
    command = keycloak["command"]
    assert "--import-realm" in (command.split() if isinstance(command, str) else command)


# --- the checks themselves can fail --------------------------------------------------------------

def _good() -> dict:
    off = dict.fromkeys(FLOWS, False)
    return {
        "realm": REALM, "registrationAllowed": False,
        "clients": [
            {"clientId": ADMIN_CLIENT, "publicClient": False, "serviceAccountsEnabled": True, **off},
            {"clientId": AUDIENCE, "publicClient": False, "serviceAccountsEnabled": False, **off}],
        "users": [{"username": f"service-account-{ADMIN_CLIENT}", "serviceAccountClientId": ADMIN_CLIENT,
                   "realmRoles": [f"default-roles-{REALM}"],
                   "clientRoles": {"realm-management": ["manage-clients"]}}],
    }


def _mutate(path: list, value) -> dict:
    realm = _good()
    node = realm
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = copy.deepcopy(value)
    return realm


def _with_roles(**parts: object) -> dict:
    realm = _good()
    realm.update(copy.deepcopy(parts))
    return realm


HARMLESS = {"defaultRole": {"name": f"default-roles-{REALM}", "composite": True,
                            "composites": {"realm": ["offline_access", "uma_authorization"],
                                           "client": {"account": ["view-profile", "manage-account"]}}},
            "roles": {"realm": [{"name": "offline_access"}, {"name": "uma_authorization"}],
                      "client": {"account": [{"name": "manage-account", "composite": True,
                                              "composites": {"client": {"account": ["manage-account-links"]}}},
                                             {"name": "manage-account-links"}, {"name": "view-profile"}]}}}


def test_every_check_accepts_a_good_realm():
    """Positive control."""
    for check in CHECKS:
        check(_good())


@pytest.mark.parametrize(("check", "bad"), [
    pytest.param(check_realm_switches, _mutate(["realm"], "defender"), id="people-realm"),
    pytest.param(check_realm_switches, _mutate(["registrationAllowed"], True), id="registration"),
    pytest.param(check_admin_client_may_only_manage_clients, _mutate(
        ["users", 0, "clientRoles"], {"realm-management": ["manage-clients", "manage-users"]}), id="extra-role"),
    pytest.param(check_admin_client_may_only_manage_clients, _mutate(
        ["users", 0, "realmRoles"], ["admin"]), id="realm-role"),
    pytest.param(check_admin_client_may_only_manage_clients, _mutate(
        ["clients", 0, "standardFlowEnabled"], True), id="admin-browser-flow"),
    pytest.param(check_the_audience_is_its_own_flowless_client, _mutate(
        ["clients", 1, "directAccessGrantsEnabled"], True), id="audience-password-grant"),
    pytest.param(check_the_audience_is_its_own_flowless_client, _mutate(
        ["clients", 1, "serviceAccountsEnabled"], True), id="audience-service-account"),
    pytest.param(check_no_people_in_the_realm, _mutate(
        ["users"], [*_good()["users"], {"username": "ann", "email": "ann@a.example"}]), id="a-person"),
    pytest.param(check_no_people_in_the_realm, _mutate(
        ["users"], [*_good()["users"], {"username": "service-account-x", "serviceAccountClientId": "x"}]), id="another-service-account"),
    pytest.param(check_only_program_relevant_clients, _mutate(
        ["clients"], [*_good()["clients"], {"clientId": "defender-api", **dict.fromkeys(FLOWS, False)}]), id="people-client"),
    pytest.param(check_no_client_has_a_browser_flow, _mutate(
        ["clients", 0, "implicitFlowEnabled"], True), id="implicit-flow"),
    pytest.param(check_no_client_has_a_browser_flow, _mutate(
        ["clients", 1, "standardFlowEnabled"], None), id="flow-left-to-default"),
    pytest.param(check_admin_client_mints_no_api_tokens, _mutate(
        ["clients", 0, "protocolMappers"], [{"protocolMapper": "oidc-audience-mapper"}]), id="admin-audience-mapper"),
    pytest.param(check_no_service_account_gets_more_than_its_clients_roles_through_composites, _with_roles(
        defaultRole={"name": f"default-roles-{REALM}", "composite": True,
                         "composites": {"client": {"realm-management": ["realm-admin"]}}}), id="default-role-realm-admin"),
    pytest.param(check_no_service_account_gets_more_than_its_clients_roles_through_composites, _with_roles(
        roles={"realm": [{"name": f"default-roles-{REALM}", "composite": True,
                              "composites": {"client": {"realm-management": ["manage-users"]}}}]}), id="default-role-as-a-realm-role"),
    pytest.param(check_no_service_account_gets_more_than_its_clients_roles_through_composites, _with_roles(
        roles={"realm": [{"name": "ops", "composite": True, "composites": {"realm": ["deeper"]}},
                             {"name": "deeper", "composite": True, "composites": {"client": {"realm-management": ["manage-users"]}}}]},
        users=[{**_good()["users"][0], "realmRoles": [f"default-roles-{REALM}", "ops"]}]), id="realm-composite-chain"),
    pytest.param(check_no_service_account_gets_more_than_its_clients_roles_through_composites, _with_roles(
        roles={"client": {"realm-management": [{"name": "manage-clients", "composite": True,
                                                    "composites": {"client": {"realm-management": ["manage-users"]}}}]}}), id="client-composite"),
    pytest.param(check_no_service_account_gets_more_than_its_clients_roles_through_composites, _with_roles(
        defaultGroups=["/ops"],
        groups=[{"name": "ops", "path": "/ops", "clientRoles": {"realm-management": ["realm-admin"]}}]), id="default-group-realm-admin"),
    pytest.param(check_no_service_account_gets_more_than_its_clients_roles_through_composites, _with_roles(
        defaultGroups=["/ops/sub"],
        groups=[{"name": "ops", "path": "/ops", "clientRoles": {"realm-management": ["realm-admin"]},
                 "subGroups": [{"name": "sub", "path": "/ops/sub"}]}]), id="default-subgroup-inherits-parent-role"),
    pytest.param(check_no_service_account_gets_more_than_its_clients_roles_through_composites, _with_roles(
        defaultGroups=["/ops"], groups=[{"name": "ops", "path": "/ops", "realmRoles": ["deeper"]}],
        roles={"realm": [{"name": "deeper", "composite": True, "composites": {"client": {"realm-management": ["manage-users"]}}}]}),
        id="default-group-realm-role-composite"),
    pytest.param(check_no_service_account_gets_more_than_its_clients_roles_through_composites, _with_roles(
        groups=[{"name": "ops", "path": "/ops", "clientRoles": {"realm-management": ["manage-users"]}}],
        users=[{**_good()["users"][0], "groups": ["/ops"]}]), id="admin-account-in-a-group"),
    pytest.param(check_no_service_account_gets_more_than_its_clients_roles_through_composites, _with_roles(
        groups=[{"name": "ops", "path": "/ops", "clientRoles": {"realm-management": ["manage-users"]}}],
        users=[*_good()["users"], {"username": "service-account-x", "serviceAccountClientId": "x", "groups": ["/ops"]}]),
        id="another-account-in-a-group"),
    pytest.param(check_no_service_account_gets_more_than_its_clients_roles_through_composites, _with_roles(
        users=[*_good()["users"], {"username": "service-account-x", "serviceAccountClientId": "x",
                                       "clientRoles": {"realm-management": ["manage-clients"]}}]), id="another-account-with-a-management-role"),
])
def test_a_check_rejects_the_setting_it_guards(check, bad):
    """Each single-field change is caught by its own check."""
    with pytest.raises(AssertionError):
        check(bad)


def test_the_composite_check_accepts_harmless_composites_and_the_expansion_follows_chains():
    """Controls: ordinary default-role composites (account roles, offline access) pass; a chain through a client composite is followed."""
    good = _with_roles(**HARMLESS)
    check_no_service_account_gets_more_than_its_clients_roles_through_composites(good)
    realm_roles, client_roles = effective_roles(good, {f"default-roles-{REALM}"}, {})
    assert realm_roles >= {"offline_access", "uma_authorization"}
    assert client_roles["account"] == {"view-profile", "manage-account", "manage-account-links"}


def test_the_composite_check_accepts_a_default_group_with_harmless_roles():
    """Control for the group mutations: a default group (and a subgroup of it) holding ordinary account roles passes, and the expansion
    sees them, so the mutations fail on the role and not on the groups' mere presence."""
    good = _with_roles(**HARMLESS, defaultGroups=["/staff/sub"], groups=[
        {"name": "staff", "path": "/staff", "clientRoles": {"account": ["view-profile"]},
         "subGroups": [{"name": "sub", "path": "/staff/sub", "realmRoles": ["offline_access"]}]}])
    check_no_service_account_gets_more_than_its_clients_roles_through_composites(good)
    realm_roles, client_roles = effective_roles(good, set(), {}, ["/staff/sub"])
    assert realm_roles == {"offline_access"}
    assert client_roles == {"account": {"view-profile"}}
