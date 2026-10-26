"""#1306 A1/A2/DC-8 — the Keycloak realm is code: the committed realm export and the dev compose
carry the settings the identity design relies on. Static and CI-safe; whether a real Keycloak
honours them (C11-C13) is the live check owed to the code stage.

Each check is a function over the realm JSON, so it is also run against a known-good synthetic
realm and against single-field mutations of it: a check that cannot fail would be vacuous.
"""
from __future__ import annotations

import copy
import json

import pytest
import yaml  # tests may load YAML raw (see tests/tenancy/tenant_1108_p4/test_dev_compose.py)

from defender._git import REPO_ROOT

#: Pinned: where the realm export lives, beside the dev compose.
REALM_EXPORT = REPO_ROOT / ".devcontainer" / "keycloak" / "realm-defender.json"
COMPOSE = REPO_ROOT / ".devcontainer" / "docker-compose.yml"
REALM = "defender"
LOGIN_CLIENT = "defender-api"
ADMIN_CLIENT = "defender-api-admin"
AMR_MAPPER = "oidc-amr-mapper"
USER_PROFILE = "kc.user.profile.config"


# --- checks (each raises AssertionError) ---------------------------------------------------------

def _clients(realm: dict) -> dict[str, dict]:
    return {c["clientId"]: c for c in realm.get("clients", [])}


def check_realm_switches(realm: dict) -> None:
    assert realm["realm"] == REALM
    assert realm["registrationAllowed"] is False  # no self-registration (A1)
    assert realm["duplicateEmailsAllowed"] is False  # C11, set explicitly rather than defaulted
    assert realm["editUsernameAllowed"] is False
    assert realm["bruteForceProtected"] is True


def check_email_not_editable_by_the_user(realm: dict) -> None:
    """Keycloak 26 keeps this in the declarative user profile: email's `edit` permission."""
    [profile] = [
        json.loads(raw)
        for provider in realm["components"]["org.keycloak.userprofile.UserProfileProvider"]
        for raw in provider["config"][USER_PROFILE]
    ]
    [email] = [a for a in profile["attributes"] if a["name"] == "email"]
    assert email["permissions"]["edit"] == ["admin"]


def check_amr_mapper_on_the_login_client(realm: dict) -> None:
    mappers = [m for m in _clients(realm)[LOGIN_CLIENT].get("protocolMappers", []) if m["protocolMapper"] == AMR_MAPPER]
    assert len(mappers) == 1
    assert mappers[0]["config"]["id.token.claim"] == "true"


def _executions(realm: dict, alias: str) -> list[dict]:
    [flow] = [f for f in realm["authenticationFlows"] if f["alias"] == alias]
    found: list[dict] = []
    for execution in flow["authenticationExecutions"]:
        found.append(execution)
        if execution.get("flowAlias"):
            found.extend(_executions(realm, execution["flowAlias"]))
    return found


def _reference(realm: dict, authenticator: str) -> str:
    [execution] = [e for e in _executions(realm, realm["browserFlow"]) if e.get("authenticator") == authenticator]
    [config] = [c for c in realm["authenticatorConfig"] if c["alias"] == execution["authenticatorConfig"]]
    return config["config"].get("default.reference.value", "")


def check_browser_flow_labels_password_and_otp(realm: dict) -> None:
    """C13: without these references the token's amr is empty for everyone."""
    assert _reference(realm, "auth-username-password-form") == "pwd"
    assert _reference(realm, "auth-otp-form") == "otp"


def check_service_account_is_limited_to_manage_users(realm: dict) -> None:
    assert _clients(realm)[ADMIN_CLIENT]["serviceAccountsEnabled"] is True
    [account] = [u for u in realm["users"] if u.get("serviceAccountClientId") == ADMIN_CLIENT]
    assert account["clientRoles"] == {"realm-management": ["manage-users"]}
    assert set(account.get("realmRoles", [])) <= {f"default-roles-{REALM}"}


def check_keycloak_mail_goes_to_mailpit(realm: dict) -> None:
    assert realm["smtpServer"]["host"] == "mailpit"


CHECKS = [
    check_realm_switches,
    check_email_not_editable_by_the_user,
    check_amr_mapper_on_the_login_client,
    check_browser_flow_labels_password_and_otp,
    check_service_account_is_limited_to_manage_users,
    check_keycloak_mail_goes_to_mailpit,
]


# --- the committed export ------------------------------------------------------------------------

@pytest.fixture(scope="module")
def realm() -> dict:
    assert REALM_EXPORT.is_file(), f"no realm export at {REALM_EXPORT.relative_to(REPO_ROOT)} (A1)"
    return json.loads(REALM_EXPORT.read_text(encoding="utf-8"))


def test_the_realm_refuses_self_registration_duplicate_emails_and_username_edits_and_throttles_guesses(realm):
    """registrationAllowed, duplicateEmailsAllowed, editUsernameAllowed off; brute-force protection on (A1, C11)."""
    check_realm_switches(realm)


def test_a_person_cannot_edit_their_own_email(realm):
    """The user profile makes email admin-editable only, so email never re-points an account (P-B, C11)."""
    check_email_not_editable_by_the_user(realm)


def test_the_login_client_adds_amr_to_the_id_token(realm):
    """An amr protocol mapper on the API's client puts the sign-in methods in the ID token (A1, C13)."""
    check_amr_mapper_on_the_login_client(realm)


def test_the_browser_flow_labels_the_password_step_pwd_and_the_code_step_otp(realm):
    """Execution references pwd and otp are what make amr say otp exactly when a code was entered (A1, C13)."""
    check_browser_flow_labels_password_and_otp(realm)


def test_the_api_service_account_may_only_manage_users(realm):
    """Its roles are exactly realm-management: manage-users, as C13 showed sufficient (A1)."""
    check_service_account_is_limited_to_manage_users(realm)


def test_keycloaks_own_email_is_sent_through_mailpit(realm):
    """The realm's SMTP host is the dev mail catcher (A2)."""
    check_keycloak_mail_goes_to_mailpit(realm)


# --- the checks themselves can fail --------------------------------------------------------------

def _good_realm() -> dict:
    profile = {"attributes": [{"name": "email", "permissions": {"edit": ["admin"], "view": ["admin", "user"]}}]}
    return {
        "realm": REALM, "registrationAllowed": False, "duplicateEmailsAllowed": False,
        "editUsernameAllowed": False, "bruteForceProtected": True, "browserFlow": "browser",
        "smtpServer": {"host": "mailpit", "port": "1025"},
        "components": {"org.keycloak.userprofile.UserProfileProvider": [
            {"providerId": "declarative-user-profile", "config": {USER_PROFILE: [json.dumps(profile)]}}]},
        "clients": [
            {"clientId": LOGIN_CLIENT, "protocolMappers": [
                {"name": "amr", "protocolMapper": AMR_MAPPER, "config": {"id.token.claim": "true"}}]},
            {"clientId": ADMIN_CLIENT, "serviceAccountsEnabled": True}],
        "users": [{"username": f"service-account-{ADMIN_CLIENT}", "serviceAccountClientId": ADMIN_CLIENT,
                   "realmRoles": [f"default-roles-{REALM}"],
                   "clientRoles": {"realm-management": ["manage-users"]}}],
        "authenticationFlows": [
            {"alias": "browser", "authenticationExecutions": [
                {"flowAlias": "browser forms", "authenticatorFlow": True}]},
            {"alias": "browser forms", "authenticationExecutions": [
                {"authenticator": "auth-username-password-form", "authenticatorConfig": "pwd-ref"},
                {"authenticator": "auth-otp-form", "authenticatorConfig": "otp-ref"}]}],
        "authenticatorConfig": [
            {"alias": "pwd-ref", "config": {"default.reference.value": "pwd"}},
            {"alias": "otp-ref", "config": {"default.reference.value": "otp"}}],
    }


def _mutate(path: list, value) -> dict:
    realm = _good_realm()
    node = realm
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = copy.deepcopy(value)
    return realm


def test_every_check_accepts_a_good_realm():
    """Positive control: the synthetic realm passes all checks."""
    for check in CHECKS:
        check(_good_realm())


@pytest.mark.parametrize(("check", "bad"), [
    pytest.param(check_realm_switches, _mutate(["registrationAllowed"], True), id="registration"),
    pytest.param(check_realm_switches, _mutate(["duplicateEmailsAllowed"], True), id="duplicate-emails"),
    pytest.param(check_realm_switches, _mutate(["editUsernameAllowed"], True), id="edit-username"),
    pytest.param(check_realm_switches, _mutate(["bruteForceProtected"], False), id="brute-force"),
    pytest.param(check_email_not_editable_by_the_user, _mutate(
        ["components", "org.keycloak.userprofile.UserProfileProvider", 0, "config", USER_PROFILE],
        [json.dumps({"attributes": [{"name": "email", "permissions": {"edit": ["admin", "user"]}}]})]),
        id="email-user-editable"),
    pytest.param(check_amr_mapper_on_the_login_client, _mutate(["clients", 0, "protocolMappers"], []), id="no-amr-mapper"),
    pytest.param(check_amr_mapper_on_the_login_client, _mutate(
        ["clients", 0, "protocolMappers"],
        [{"protocolMapper": AMR_MAPPER, "config": {"id.token.claim": "false"}}]), id="amr-not-in-id-token"),
    pytest.param(check_browser_flow_labels_password_and_otp, _mutate(
        ["authenticatorConfig", 0, "config", "default.reference.value"], "password"), id="pwd-label"),
    pytest.param(check_browser_flow_labels_password_and_otp, _mutate(["authenticatorConfig", 1, "config"], {}), id="otp-label"),
    pytest.param(check_service_account_is_limited_to_manage_users, _mutate(
        ["users", 0, "clientRoles"], {"realm-management": ["manage-users", "realm-admin"]}), id="extra-role"),
    pytest.param(check_service_account_is_limited_to_manage_users, _mutate(["users", 0, "clientRoles"], {}), id="no-role"),
    pytest.param(check_keycloak_mail_goes_to_mailpit, _mutate(["smtpServer", "host"], "smtp.example.test"), id="smtp"),
])
def test_a_check_rejects_the_setting_it_guards(check, bad):
    """Each single-field change is caught by its own check."""
    with pytest.raises(AssertionError):
        check(bad)


# --- the dev compose (A2) ------------------------------------------------------------------------

def _services() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]


def test_the_dev_compose_runs_postgres_keycloak_and_mailpit():
    """A2: the three services exist beside the existing ones."""
    assert {"postgres", "keycloak", "mailpit"} <= set(_services())


def test_keycloak_keeps_its_data_in_the_compose_postgres_and_imports_the_realm_export():
    """A2/A1: Keycloak uses postgres and starts from the committed realm file."""
    keycloak = _services()["keycloak"]
    environment = keycloak.get("environment", {})
    if isinstance(environment, list):
        environment = dict(item.split("=", 1) for item in environment)
    assert environment["KC_DB"] == "postgres"
    assert "postgres" in str(environment["KC_DB_URL"])
    command = keycloak["command"]
    assert "--import-realm" in (command.split() if isinstance(command, str) else command)
    mounted = [str(v).split(":")[0] for v in keycloak.get("volumes", [])]
    assert any((COMPOSE.parent / m).resolve() == REALM_EXPORT.resolve() for m in mounted), mounted
