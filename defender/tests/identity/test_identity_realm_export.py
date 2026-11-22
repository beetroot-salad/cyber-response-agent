"""#1306 A1/A2/DC-8 — the Keycloak realm is code: the committed realm export and the dev compose
carry the settings the identity design relies on. Static and CI-safe; whether a real Keycloak
honours them (C11-C13) is the live check owed to the code stage.

Each check is a function over the realm JSON, so it is also run against a known-good synthetic
realm and against single-field mutations of it: a check that cannot fail would be vacuous.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

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
CODE_LIFESPAN_DEFAULT = 60  # Keycloak's accessCodeLifespan when the realm does not set it
#: #1540 F5: the login theme's name, and its folder (D2: Keycloak's `<theme dir>/login/theme.properties`, the folder
#: compose mounts as `/opt/keycloak/themes/defender`).
THEME_NAME = "defender"
#: The product's name, as the sign-in screens show it.
PRODUCT = "Sluice"
THEME = REPO_ROOT / "defender" / "frontend" / "keycloak-theme"
PARENT_STYLES = "css/styles.css"


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


def _reference_config(realm: dict, authenticator: str) -> dict:
    [execution] = [e for e in _executions(realm, realm["browserFlow"]) if e.get("authenticator") == authenticator]
    [config] = [c for c in realm["authenticatorConfig"] if c["alias"] == execution["authenticatorConfig"]]
    return config["config"]


def _reference(realm: dict, authenticator: str) -> str:
    return _reference_config(realm, authenticator).get("default.reference.value", "")


def check_browser_flow_labels_password_and_otp(realm: dict) -> None:
    """C13: without these references the token's amr is empty for everyone."""
    assert _reference(realm, "auth-username-password-form") == "pwd"
    assert _reference(realm, "auth-otp-form") == "otp"


def check_amr_outlives_the_authorization_code(realm: dict) -> None:
    """#1349: Keycloak drops a reference from amr once it is older than its maxAge (default 0: the same second).
    A code exchanged a second after the code step would then carry no otp, and a platform admin is refused.
    It is also how long a later sign-in that Keycloak satisfies from its own session still counts the step,
    so it is kept to the code's lifespan, no longer."""
    lifespan = int(realm.get("accessCodeLifespan", CODE_LIFESPAN_DEFAULT))
    for authenticator in ("auth-username-password-form", "auth-otp-form"):
        assert int(_reference_config(realm, authenticator).get("default.reference.maxAge", 0)) == lifespan


def check_service_account_is_limited_to_manage_users(realm: dict) -> None:
    assert _clients(realm)[ADMIN_CLIENT]["serviceAccountsEnabled"] is True
    [account] = [u for u in realm["users"] if u.get("serviceAccountClientId") == ADMIN_CLIENT]
    assert account["clientRoles"] == {"realm-management": ["manage-users"]}
    assert set(account.get("realmRoles", [])) <= {f"default-roles-{REALM}"}


def check_keycloak_mail_goes_to_mailpit(realm: dict) -> None:
    assert realm["smtpServer"]["host"] == "mailpit"


def check_login_client_redirects_to_the_api_callback(realm: dict) -> None:
    """B3: the registered redirect is the client's own origin plus `/api/auth/callback`, and nothing else."""
    client = _clients(realm)[LOGIN_CLIENT]
    assert client["redirectUris"] == [client["rootUrl"] + "/api/auth/callback"]


def check_realm_names_the_product(realm: dict) -> None:
    """The sign-in screens name the product, not the realm's id: Keycloak shows `displayName` in the page title and
    `displayNameHtml` in the header, and falls back to the realm's name (`defender`) for either one left unset."""
    assert (realm.get("displayName"), realm.get("displayNameHtml")) == (PRODUCT, PRODUCT)


def check_login_client_is_named_for_the_product(realm: dict) -> None:
    """Keycloak shows the sign-in client's name to the person (the consent and device pages): it is the product's."""
    assert _clients(realm)[LOGIN_CLIENT].get("name") == PRODUCT


def check_realm_names_the_theme(realm: dict) -> None:
    """#1540 F5: the dev realm's sign-in screens use the `defender` login theme."""
    assert realm.get("loginTheme") == THEME_NAME


def theme_properties(theme: Path) -> dict[str, str]:
    """The theme's `login/theme.properties` as Java properties read it (`key=value`, `#` comments, `\\` continuations)."""
    path = theme / "login" / "theme.properties"
    assert path.is_file(), f"no {path}"
    joined = re.sub(r"\\\r?\n\s*", "", path.read_text(encoding="utf-8"))
    pairs = (line.split("=", 1) for line in joined.splitlines() if "=" in line and not line.lstrip().startswith("#"))
    return {key.strip(): value.strip() for key, value in pairs}


def stylesheet_references(css: str) -> list[str]:
    """Every `url(...)` and `@import` target in a stylesheet (comments ignored; data: and fragment-only left out)."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    found = re.findall(r"url\(\s*[\"']?([^\"')\s]+)", css) + re.findall(r"@import\s+[\"']([^\"']+)", css)
    return [r for r in dict.fromkeys(found) if not r.startswith(("data:", "#"))]


def check_theme_extends_keycloak_v2_and_lists_both_stylesheets(theme: Path) -> None:
    """#1540 F5 (probe C10): `parent=keycloak.v2`; `styles` is the child's whole list, so the parent's stylesheet comes
    first and the theme's own second, and that second one is a file of the theme."""
    props = theme_properties(theme)
    assert props.get("parent") == "keycloak.v2", props
    styles = props.get("styles", "").split()
    assert len(styles) == 2, f"styles must be `{PARENT_STYLES}` then the theme's own: {styles}"
    assert styles[0] == PARENT_STYLES, styles
    assert styles[1] != PARENT_STYLES, styles
    assert styles[1].endswith(".css"), styles
    own = theme / "login" / "resources" / styles[1]
    assert own.is_file(), f"the theme's own stylesheet {own} is missing"


CHECKS = [
    check_realm_names_the_product,
    check_login_client_is_named_for_the_product,
    check_realm_names_the_theme,
    check_login_client_redirects_to_the_api_callback,
    check_realm_switches,
    check_email_not_editable_by_the_user,
    check_amr_mapper_on_the_login_client,
    check_browser_flow_labels_password_and_otp,
    check_amr_outlives_the_authorization_code,
    check_service_account_is_limited_to_manage_users,
    check_keycloak_mail_goes_to_mailpit,
]


# --- the committed export ------------------------------------------------------------------------

def _committed_realm() -> dict:
    """Read inside each test, so a missing file fails the test with this message rather than erroring in setup."""
    assert REALM_EXPORT.is_file(), f"no realm export at {REALM_EXPORT.relative_to(REPO_ROOT)} (A1)"
    return json.loads(REALM_EXPORT.read_text(encoding="utf-8"))


def test_the_realm_refuses_self_registration_duplicate_emails_and_username_edits_and_throttles_guesses():
    """registrationAllowed, duplicateEmailsAllowed, editUsernameAllowed off; brute-force protection on (A1, C11)."""
    check_realm_switches(_committed_realm())


def test_a_person_cannot_edit_their_own_email():
    """The user profile makes email admin-editable only, so email never re-points an account (P-B, C11)."""
    check_email_not_editable_by_the_user(_committed_realm())


def test_the_login_client_adds_amr_to_the_id_token():
    """An amr protocol mapper on the API's client puts the sign-in methods in the ID token (A1, C13)."""
    check_amr_mapper_on_the_login_client(_committed_realm())


def test_the_browser_flow_labels_the_password_step_pwd_and_the_code_step_otp():
    """Execution references pwd and otp are what make amr say otp exactly when a code was entered (A1, C13)."""
    check_browser_flow_labels_password_and_otp(_committed_realm())


def test_amr_still_lists_the_code_step_when_the_code_is_exchanged_late():
    """The pwd and otp references stay in amr exactly as long as the authorization code is valid (#1349)."""
    check_amr_outlives_the_authorization_code(_committed_realm())


def test_the_login_client_registers_the_apis_callback_under_api_and_no_other():
    """The defender client's `redirectUris` is its `rootUrl` plus `/api/auth/callback`; the old `/auth/callback` is gone (B3)."""
    realm = _committed_realm()
    check_login_client_redirects_to_the_api_callback(realm)
    assert "/auth/callback" not in "".join(_clients(realm)[LOGIN_CLIENT]["redirectUris"]).replace("/api/auth/callback", "")


def test_the_api_service_account_may_only_manage_users():
    """Its roles are exactly realm-management: manage-users, as C13 showed sufficient (A1)."""
    check_service_account_is_limited_to_manage_users(_committed_realm())


def test_keycloaks_own_email_is_sent_through_mailpit():
    """The realm's SMTP host is the dev mail catcher (A2)."""
    check_keycloak_mail_goes_to_mailpit(_committed_realm())


# --- #1592 S3-15: Forgejo's client, and the browser flow it is bound to --------------------------------------

FORGEJO_CLIENT = "forgejo"


def _flow_with_id(realm: dict, reference: str) -> dict:
    """The flow a binding override names. Keycloak 26's import resolves an override only by flow id, never by alias."""
    flows = [f for f in realm["authenticationFlows"] if f.get("id") == reference]
    assert len(flows) == 1, f"the binding override {reference!r} is not the id of a flow in authenticationFlows (an alias is refused at import)"
    return flows[0]


def check_forgejo_client_always_asks_for_the_password(realm: dict) -> None:
    """OD-4: a `forgejo` client, bound to a browser flow that has no Cookie step, so an existing Keycloak session never
    signs a person in to Forgejo without the password; the realm's own browser flow keeps the Cookie step."""
    client = _clients(realm)[FORGEJO_CLIENT]
    assert client["enabled"] is True
    assert client["publicClient"] is False
    assert client["standardFlowEnabled"] is True
    assert client["implicitFlowEnabled"] is False
    assert client["directAccessGrantsEnabled"] is False
    assert client["serviceAccountsEnabled"] is False
    assert client.get("secret"), "the confidential `forgejo` client has no secret (the setup script reads it)"
    assert len(client["redirectUris"]) == 1
    assert client["redirectUris"][0].endswith("/user/oauth2/product/callback"), client["redirectUris"]
    bound = client["authenticationFlowBindingOverrides"]["browser"]
    flow = _flow_with_id(realm, bound)
    assert flow["alias"] != realm["browserFlow"], "the client is bound to the realm's own browser flow"
    executions = _executions(realm, flow["alias"])
    authenticators = [e.get("authenticator") for e in executions]
    assert "auth-cookie" not in authenticators, authenticators
    [password] = [e for e in executions if e.get("authenticator") == "auth-username-password-form"]
    assert password.get("requirement") == "REQUIRED", f"the password form is {password.get('requirement')}: an ALTERNATIVE or DISABLED form lets a session skip it"
    own = [e.get("authenticator") for e in _executions(realm, realm["browserFlow"])]
    assert "auth-cookie" in own, "the product's own sign-in lost its Cookie step"


def test_1592_the_forgejo_client_is_bound_to_a_browser_flow_without_the_cookie_step():
    """S3-15 / OD-4: the committed realm holds the `forgejo` client and its Cookie-less browser flow."""
    check_forgejo_client_always_asks_for_the_password(_committed_realm())


def test_1592_the_forgejo_check_can_fail():
    """S3-15: a client bound to the realm's own browser flow, with no override, no secret or an optional password step, is refused."""
    realm = _committed_realm()
    check_forgejo_client_always_asks_for_the_password(realm)
    own = copy.deepcopy(realm)
    _clients(own)[FORGEJO_CLIENT]["authenticationFlowBindingOverrides"]["browser"] = own["browserFlow"]
    with pytest.raises(AssertionError):
        check_forgejo_client_always_asks_for_the_password(own)
    own_by_id = copy.deepcopy(realm)  # the realm's own flow, named by its id: resolvable, but the wrong flow
    [own_flow] = [f for f in own_by_id["authenticationFlows"] if f["alias"] == own_by_id["browserFlow"]]
    own_flow["id"] = "11111111-1592-4c3e-9b1a-000000000000"
    _clients(own_by_id)[FORGEJO_CLIENT]["authenticationFlowBindingOverrides"]["browser"] = own_flow["id"]
    with pytest.raises(AssertionError):
        check_forgejo_client_always_asks_for_the_password(own_by_id)
    by_alias = copy.deepcopy(realm)  # Keycloak 26 refuses to start on this ("Unable to resolve auth flow binding override")
    overrides = _clients(by_alias)[FORGEJO_CLIENT]["authenticationFlowBindingOverrides"]
    overrides["browser"] = _flow_with_id(by_alias, overrides["browser"])["alias"]
    with pytest.raises(AssertionError):
        check_forgejo_client_always_asks_for_the_password(by_alias)
    for requirement in ("ALTERNATIVE", "DISABLED"):  # the password step is not mandatory: a session could skip it
        optional = copy.deepcopy(realm)
        flow = _flow_with_id(optional, _clients(optional)[FORGEJO_CLIENT]["authenticationFlowBindingOverrides"]["browser"])
        [password] = [e for e in _executions(optional, flow["alias"]) if e.get("authenticator") == "auth-username-password-form"]
        password["requirement"] = requirement
        with pytest.raises(AssertionError):
            check_forgejo_client_always_asks_for_the_password(optional)
    bare = copy.deepcopy(realm)
    del _clients(bare)[FORGEJO_CLIENT]["authenticationFlowBindingOverrides"]
    with pytest.raises(KeyError):
        check_forgejo_client_always_asks_for_the_password(bare)
    secretless = copy.deepcopy(realm)
    _clients(secretless)[FORGEJO_CLIENT].pop("secret", None)
    with pytest.raises(AssertionError):
        check_forgejo_client_always_asks_for_the_password(secretless)


# --- the checks themselves can fail --------------------------------------------------------------

def _good_realm() -> dict:
    profile = {"attributes": [{"name": "email", "permissions": {"edit": ["admin"], "view": ["admin", "user"]}}]}
    return {
        "realm": REALM, "displayName": PRODUCT, "displayNameHtml": PRODUCT, "loginTheme": THEME_NAME, "registrationAllowed": False, "duplicateEmailsAllowed": False,
        "editUsernameAllowed": False, "bruteForceProtected": True, "browserFlow": "browser",
        "smtpServer": {"host": "mailpit", "port": "1025"},
        "components": {"org.keycloak.userprofile.UserProfileProvider": [
            {"providerId": "declarative-user-profile", "config": {USER_PROFILE: [json.dumps(profile)]}}]},
        "clients": [
            {"clientId": LOGIN_CLIENT, "name": PRODUCT, "rootUrl": "http://localhost:8000",
             "redirectUris": ["http://localhost:8000/api/auth/callback"], "protocolMappers": [
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
            {"alias": "pwd-ref", "config": {"default.reference.value": "pwd", "default.reference.maxAge": "60"}},
            {"alias": "otp-ref", "config": {"default.reference.value": "otp", "default.reference.maxAge": "60"}}],
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
    pytest.param(check_realm_names_the_product, _mutate(["displayName"], None), id="no-display-name"),
    pytest.param(check_realm_names_the_product, _mutate(["displayNameHtml"], "defender"), id="header-names-the-realm"),
    pytest.param(check_login_client_is_named_for_the_product, _mutate(["clients", 0, "name"], "Defender API (sign-in)"),
                 id="sign-in-client-says-defender"),
    pytest.param(check_realm_names_the_theme, _mutate(["loginTheme"], "keycloak.v2"), id="other-login-theme"),
    pytest.param(check_realm_switches, _mutate(["registrationAllowed"], True), id="registration"),
    pytest.param(check_realm_switches, _mutate(["duplicateEmailsAllowed"], True), id="duplicate-emails"),
    pytest.param(check_realm_switches, _mutate(["editUsernameAllowed"], True), id="edit-username"),
    pytest.param(check_realm_switches, _mutate(["bruteForceProtected"], False), id="brute-force"),
    pytest.param(check_email_not_editable_by_the_user, _mutate(
        ["components", "org.keycloak.userprofile.UserProfileProvider", 0, "config", USER_PROFILE],
        [json.dumps({"attributes": [{"name": "email", "permissions": {"edit": ["admin", "user"]}}]})]),
        id="email-user-editable"),
    pytest.param(check_login_client_redirects_to_the_api_callback, _mutate(
        ["clients", 0, "redirectUris"], ["http://localhost:8000/auth/callback"]), id="callback-not-under-api"),
    pytest.param(check_login_client_redirects_to_the_api_callback, _mutate(
        ["clients", 0, "redirectUris"], ["http://localhost:8000/api/auth/callback", "http://localhost:8000/auth/callback"]),
        id="old-callback-kept"),
    pytest.param(check_amr_mapper_on_the_login_client, _mutate(["clients", 0, "protocolMappers"], []), id="no-amr-mapper"),
    pytest.param(check_amr_mapper_on_the_login_client, _mutate(
        ["clients", 0, "protocolMappers"],
        [{"protocolMapper": AMR_MAPPER, "config": {"id.token.claim": "false"}}]), id="amr-not-in-id-token"),
    pytest.param(check_browser_flow_labels_password_and_otp, _mutate(
        ["authenticatorConfig", 0, "config", "default.reference.value"], "password"), id="pwd-label"),
    pytest.param(check_browser_flow_labels_password_and_otp, _mutate(["authenticatorConfig", 1, "config"], {}), id="otp-label"),
    pytest.param(check_amr_outlives_the_authorization_code, _mutate(
        ["authenticatorConfig", 1, "config"], {"default.reference.value": "otp", "default.reference.max.age": "60"}),
        id="otp-max-age-misspelt"),
    pytest.param(check_amr_outlives_the_authorization_code, _mutate(
        ["authenticatorConfig", 0, "config", "default.reference.maxAge"], "59"), id="pwd-max-age-short"),
    pytest.param(check_amr_outlives_the_authorization_code, _mutate(
        ["authenticatorConfig", 1, "config", "default.reference.maxAge"], "360"), id="otp-max-age-long"),
    pytest.param(check_amr_outlives_the_authorization_code, _mutate(["accessCodeLifespan"], 61), id="code-outlives-max-age"),
    pytest.param(check_service_account_is_limited_to_manage_users, _mutate(
        ["users", 0, "clientRoles"], {"realm-management": ["manage-users", "realm-admin"]}), id="extra-role"),
    pytest.param(check_service_account_is_limited_to_manage_users, _mutate(["users", 0, "clientRoles"], {}), id="no-role"),
    pytest.param(check_keycloak_mail_goes_to_mailpit, _mutate(["smtpServer", "host"], "smtp.example.test"), id="smtp"),
])
def test_a_check_rejects_the_setting_it_guards(check, bad):
    """Each single-field change is caught by its own check."""
    with pytest.raises(AssertionError):
        check(bad)


def test_the_sign_in_screens_name_the_product():
    """The committed realm's display name, in the title and the header, is the product's."""
    check_realm_names_the_product(_committed_realm())


def test_the_sign_in_client_is_named_for_the_product():
    """The committed realm names the sign-in client for the product, as a person may read it."""
    check_login_client_is_named_for_the_product(_committed_realm())


def test_1540_f5_the_realm_names_the_defender_login_theme():
    """The committed dev realm sets `loginTheme: defender`. (F5)"""
    check_realm_names_the_theme(_committed_realm())


def test_1540_f5_the_theme_extends_keycloak_v2_and_lists_its_stylesheet_after_the_parents():
    """The theme folder's properties: parent `keycloak.v2`, `styles` = `css/styles.css` then its own file. (F5, C10)"""
    check_theme_extends_keycloak_v2_and_lists_both_stylesheets(THEME)


def _good_theme(root: Path) -> Path:
    resources = root / "login" / "resources" / "css"
    resources.mkdir(parents=True)
    (root / "login" / "theme.properties").write_text(
        f"parent=keycloak.v2\nstyles={PARENT_STYLES} css/defender.css\n", encoding="utf-8")
    (resources / "defender.css").write_text("body{}", encoding="utf-8")
    return root


@pytest.mark.parametrize("properties", [
    pytest.param("parent=keycloak.v2\nstyles=css/defender.css\n", id="parent-styles-dropped"),
    pytest.param(f"parent=keycloak.v2\nstyles=css/defender.css {PARENT_STYLES}\n", id="order-swapped"),
    pytest.param(f"parent=keycloak\nstyles={PARENT_STYLES} css/defender.css\n", id="other-parent"),
    pytest.param(f"parent=keycloak.v2\nstyles={PARENT_STYLES} css/missing.css\n", id="stylesheet-absent"),
    pytest.param(f"parent=keycloak.v2\nstyles={PARENT_STYLES}\n", id="no-own-stylesheet"),
])
def test_1540_f5_the_theme_check_refuses_a_bad_properties_file(tmp_path, properties):
    """A good theme passes; each single change to its properties is refused. (F5)"""
    check_theme_extends_keycloak_v2_and_lists_both_stylesheets(_good_theme(tmp_path / "ok"))
    bad = _good_theme(tmp_path / "bad")
    (bad / "login" / "theme.properties").write_text(properties, encoding="utf-8")
    with pytest.raises(AssertionError):
        check_theme_extends_keycloak_v2_and_lists_both_stylesheets(bad)


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


def _databases_created_on_first_init(postgres: dict) -> set[str]:
    """POSTGRES_DB plus every `CREATE DATABASE` in a script mounted into the image's init directory."""
    environment = postgres.get("environment", {})
    if isinstance(environment, list):
        environment = dict(item.split("=", 1) for item in environment)
    created = {str(environment.get("POSTGRES_DB", environment.get("POSTGRES_USER", "postgres")))}
    for volume in postgres.get("volumes", []):
        source, _, target = str(volume).partition(":")
        if not target.split(":")[0].startswith("/docker-entrypoint-initdb.d"):
            continue
        path = COMPOSE.parent / source
        for script in ([path] if path.is_file() else sorted(path.glob("*"))):
            created |= set(re.findall(r'CREATE DATABASE\s+"?(\w+)"?', script.read_text(encoding="utf-8"), re.I))
    return created


def test_the_dev_postgres_is_17_and_creates_the_application_database_beside_keycloaks():
    """O7 (#1339): PostgreSQL 17 by default, and first initialisation creates `defender` and `keycloak`."""
    postgres = _services()["postgres"]
    default = re.fullmatch(r"postgres:\$\{POSTGRES_VERSION:-([^}]+)\}", postgres["image"])
    assert default, postgres["image"]
    assert default.group(1).split(".")[0] == "17"
    assert {"defender", "keycloak"} <= _databases_created_on_first_init(postgres)
