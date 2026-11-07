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
    assert AUDIENCE != PEOPLE_LOGIN_CLIENT
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


def check_access_tokens_are_short(realm: dict) -> None:
    """Not required by the design (it sets 300 s per created client, C23): a realm default no longer than that."""
    assert realm.get("accessTokenLifespan", 300) <= 300


CHECKS = [check_realm_switches, check_admin_client_may_only_manage_clients,
          check_the_audience_is_its_own_flowless_client, check_no_people_in_the_realm,
          check_only_program_relevant_clients, check_no_client_has_a_browser_flow,
          check_admin_client_mints_no_api_tokens, check_access_tokens_are_short]


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
    pytest.param(check_access_tokens_are_short, _mutate(["accessTokenLifespan"], 900), id="long-realm-lifespan"),
])
def test_a_check_rejects_the_setting_it_guards(check, bad):
    """Each single-field change is caught by its own check."""
    with pytest.raises(AssertionError):
        check(bad)
