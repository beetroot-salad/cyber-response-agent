"""#1214 boundary fakes — NO test functions, NO production imports. Each fake records every call
and answers as the real system was observed to (grounding G6-G9); none decides lifecycle policy.

- `FakeForge`: Forgejo 17's admin HTTP API as an `httpx.MockTransport` (G9's status codes). Repos
  are real bare git repositories under `root`, so the template commit and the host clone are real
  git (`RoutedGit` routes the forge's clone URLs to them).
- `FakeIntegrationCommand`: `forgejo admin user create-authorized-integration`'s runner; prints
  G6's JSON (with an `audience`); a re-run adds a second integration (G7); a deleted user (purged or not) takes its
  integrations with it (G8, kept on `FakeForge.integrations`).
- `FakeOpenBao`: the OpenBao HTTP paths the design names (OIDC roles, AppRoles and their secret
  ids, wrapping, entities); a destroyed role or AppRole no longer logs in or mints.

r9 additions (slice 0):
- Forge: users carry `must_change_password` (Forgejo's default True; the admin create body or a PATCH
  clears it, G23) and `prohibit_login` (PATCH, G15). A request with `Authorization: Bearer <jwt>` is an
  integration call: the JWT must resolve (via `FakeOpenBao.claims`, wired by `Fakes`) to an audience that one
  bot's integration holds; a bot with `must_change_password` is refused 403 "You must change your password"
  (G23), a login-prohibited one 403 "This account is prohibited from signing in" (G15), a deleted or
  unknown one 401. Integration routes: `GET /repos/{o}/{r}` and `GET /repos/{o}/{r}/branches/main` (G22:
  `protected` / `user_can_push` computed from the recorded protection body and the bot's collaborator
  permission; 404 for a non-collaborator of a private repo). Admin (`token`) calls are unaffected.
  `FakeForge.integration_calls` lists (bot, method, path, status) for every Bearer call.
- Destroy calls on missing things answer 404 (RC-4) on the forge: user/repo/collaborator-of-missing-
  repo, archive of a missing repo. OpenBao DELETE of a missing OIDC role, AppRole or entity answers 204
  (G24, probed on openbao 2.4.1) and GET answers 404; secret-id accessor destroy and LIST of a missing
  AppRole answer 404. (Collaborator removal of a non-collaborator is 204, as Forgejo.)
- OpenBao: the management token (`FakeOpenBao.management_token`) is required for every CRUD/list/role-id
  path; `unwrap`, `approle/login` and `identity/oidc/token` need no management token. So a host that was
  handed a management client is not refused by the fake -- tests assert `tokens_used()` instead (SK-5).
- Git (`RoutedGit`): models the sealed-descriptor transport (DC-10). A call made with `identity=` (anything with
  `.token(min_validity=)`, i.e. a `ForgeCredential`) and `origin=` has its token recorded ONLY in
  `git.sealed` (what `network_git` puts in the sealed memfd config) and never in `git.calls` argv/env,
  unless the caller itself put it there. Tests assert `jwt in git.sealed_tokens()` (positive control)
  and `not git.argv_env_contains(jwt)`.
- `RecordingPublish` answers a `fresh <commit>` line (RC-7); `publish.answers` queues other lines.

Fidelity review 1 additions (F-1, F-6):
- `FakeForge.client(token)` defaults to the admin token; `client(None)` carries NO credential (the host actor's
  `forge=`: its calls present the bot's own `Authorization: Bearer <jwt>`). Every call is classified by its
  credential: `bearer_calls()` (a bot), `admin_token_calls()` (`token <admin>`), `anonymous_calls()`; so "the host
  made bot calls and never presented the admin token" is `bearer_calls()` non-empty (control) and
  `admin_token_calls()` empty over the host's passes (`split_drive` keeps the actors' calls apart).
- `FakeIntegrationCommand` parses and records its arguments (`created`: user, name, issuer, claims_eq, scopes,
  repos, audience) and refuses an issuer other than the one the fakes serve or a user the forge lacks.
  `FakeForge` enforces what was recorded for a Bearer call: the JWT's issuer equals the integration's, every
  `--claim-eq` claim equals the JWT's claim (else 401), a repo outside `--repo` answers 404, a scope that gives no
  repository access answers 403. The fake never decides which tenant a claim or repo ought to name.
- `FakeOpenBao`: an AppRole login resolves its entity through the alias named by the role id (`identity/entity-alias`
  `name`=role_id, `canonical_id`=entity id); the templated policy lets that token read only
  `identity/oidc/token/<entity.metadata.oidc_role>` (else 403, also with no alias/entity or a destroyed entity);
  a minted JWT carries `iss`, `aud` (the role's client id), `role` and the entity's `metadata.tenant_id`
  (`claims(jwt)`, `mint_entity(jwt)`).
- `Fakes(tmp_path)` bundles forge, integration, openbao, git, publish and wires JWT resolution.

r8 additions (slice S1, probes P-a/P-b/P-c of design r8.2/r8.3):
- Forge branch protection (P-a, Forgejo 17.0.1): a rule stores its lists as Forgejo does -- a whitelisted user
  without access to the repository is silently dropped, `merge_whitelist_teams` on a user-owned repository answers
  201/200 and is stored empty, a team of the organisation or a user that does not exist is refused 422 (a user-owned repository's teams are not checked), a PATCH that omits a list leaves it
  unchanged, a POST of an existing rule answers 403. `GET branches/main` as the bot adds `user_can_merge`: true for
  a writer unless an enabled merge whitelist excludes it (an enabled whitelist stored empty excludes everybody).
  Organisations are `FakeForge.orgs` (name -> team names); `add_user_repo` makes a repository owned by a user.
- OpenBao transit (P-b): keys by name (`create` is a no-op on an existing key, `deletion_allowed` via `/config`,
  a delete is refused until it is allowed, a missing key answers 400 on delete as OpenBao does), `transit/sign` for a
  client token only when the AppRole carries `sign_policy` and the key is `request-token-<entity tenant_id>`.
  A second alias for one entity on one mount answers 400 (P-c); a POST of an existing entity answers 204; reading an
  entity lists its aliases; deleting an entity deletes its aliases. An AppRole records the policies it was made with.
"""
from __future__ import annotations

import dataclasses
import itertools
import json
import os
import subprocess
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

FORGE_URL = "http://forge.test"
OPENBAO_URL = "https://openbao.test"
ORG = "tenants"
#: The issuer URL the fakes serve (OpenBao's OIDC issuer) and `lifecycle_config` names; the integration command
#: refuses any other (Forgejo fetches `<issuer>/.well-known/openid-configuration`, G6).
ISSUER_URL = "https://openbao.test:8200/v1/identity/oidc"
ADMIN_TOKEN = "forge-admin-token"
#: The deployment's two templated policies (`LifecycleConfig.token_policy` / `sign_policy` defaults).
TOKEN_POLICY = "defender-tenant-token"
SIGN_POLICY = "defender-tenant-sign"


@dataclasses.dataclass
class Call:
    method: str
    path: str
    query: dict[str, list[str]]
    body: Any
    headers: dict[str, str]


def _json(request: httpx.Request) -> Any:
    return json.loads(request.content) if request.content else None


def _git(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)  # noqa: S603, S607


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[Call] = []
        self.lock = threading.Lock()
        #: (method, path) -> status code answered instead, once each.
        self.fail_next: dict[tuple[str, str], int] = {}
        #: (method, path) -> a callable run inside the call before it answers (an interleaving point).
        self.during: dict[tuple[str, str], Callable[[], None]] = {}

    def _record(self, request: httpx.Request) -> tuple[Call, httpx.Response | None]:
        url = urlsplit(str(request.url))
        call = Call(request.method, url.path, parse_qs(url.query), _json(request), dict(request.headers))
        with self.lock:
            self.calls.append(call)
            status = self.fail_next.pop((call.method, call.path), None)
            hook = self.during.pop((call.method, call.path), None)
        if hook is not None:
            hook()
        if status is not None:
            return call, httpx.Response(status, json={"message": f"injected {status}"})
        return call, None

    def made(self, method: str, path: str) -> list[Call]:
        return [c for c in self.calls if (c.method, c.path) == (method, path)]


class FakeForge(_Recorder):
    """Forgejo's admin HTTP API over `root`'s bare repositories."""

    def __init__(self, root: Path) -> None:
        super().__init__()
        self.root = root
        self.users: set[str] = set()
        #: user -> Forgejo's must_change_password (default True on create, G23).
        self.must_change_password: dict[str, bool] = {}
        #: users with login prohibited (G15).
        self.prohibit_login: set[str] = set()
        #: jwt -> {"role", "aud"}; wired by `Fakes` to `FakeOpenBao.claims`.
        self.jwt_claims: Callable[[str], dict[str, Any] | None] = lambda _jwt: None
        #: (bot, method, path, status) of every Bearer (integration) call.
        self.integration_calls: list[tuple[str | None, str, str, int]] = []
        self.repos: dict[str, dict[str, Any]] = {}
        #: user -> its authorized integrations' audiences (G7, G8).
        self.integrations: dict[str, list[str]] = {}
        #: audience -> {"user", "issuer", "claims_eq", "scopes", "repos"} as the integration command recorded it.
        self.integration_rules: dict[str, dict[str, Any]] = {}
        #: organisation -> its team names (P-a: a repository whose owner is not here is user-owned).
        self.orgs: dict[str, set[str]] = {ORG: {"Owners", "Reviewers"}}
        #: (organisation, team) -> member logins.
        self.team_members: dict[tuple[str, str], set[str]] = {}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def client(self, token: str | None = ADMIN_TOKEN) -> httpx.AsyncClient:
        """The management service's admin client (default), or, with `token=None`, the host actor's client:
        a base URL and NO credential (it presents the bot's Bearer JWT per request)."""
        headers = {} if token is None else {"Authorization": f"token {token}"}
        return httpx.AsyncClient(transport=self.transport(), base_url=FORGE_URL, headers=headers)

    @staticmethod
    def credential_of(call: Call) -> str:
        """`"bearer"` (a bot's JWT), `"token"` (an admin access token) or `"none"`."""
        auth = call.headers.get("authorization", "")
        return "bearer" if auth.startswith("Bearer ") else "token" if auth.startswith("token ") else "none"

    def bearer_calls(self) -> list[Call]:
        return [c for c in self.calls if self.credential_of(c) == "bearer"]

    def admin_token_calls(self, token: str | None = None) -> list[Call]:
        """Calls that presented an admin access token (that of `token` if given)."""
        return [c for c in self.calls if self.credential_of(c) == "token"
                and (token is None or c.headers["authorization"] == f"token {token}")]

    def anonymous_calls(self) -> list[Call]:
        return [c for c in self.calls if self.credential_of(c) == "none"]

    def bare(self, full_name: str) -> Path:
        return self.root / f"{full_name}.git"

    def add_user_repo(self, owner: str, name: str) -> str:
        """A private repository owned by the user `owner` (not an organisation), empty; returns its full name."""
        full = f"{owner}/{name}"
        self.bare(full).parent.mkdir(parents=True, exist_ok=True)
        _git("init", "--bare", "-q", "-b", "main", str(self.bare(full)))
        self.repos[full] = {"private": True, "archived": False, "collaborators": {}, "protections": {}}
        return full

    def rule(self, full_name: str, name: str = "main") -> dict[str, Any] | None:
        """The protection rule as the forge stores it now (None when there is none)."""
        return self.repos[full_name]["protections"].get(name)

    def put_rule(self, full_name: str, **fields: Any) -> None:
        """Store a rule as the forge would after a POST by an administrator (a hand-made rule of an older tenant)."""
        self.repos[full_name]["protections"][fields.get("rule_name", "main")] = self._stored_rule(full_name, fields, None)

    def _stored_rule(self, full: str, body: dict[str, Any], old: dict[str, Any] | None) -> dict[str, Any]:
        """What Forgejo stores for `body` over `old` (P-a): an omitted list keeps its old value; users without access
        to the repository, and every team of a user-owned repository, are dropped (unknown names never reach here: 422)."""
        owner = full.split("/", 1)[0]
        merged = {**(old or {}), **body}
        has_access = set(self.repos[full]["collaborators"]) | {owner}
        for team in self.orgs.get(owner, set()):  # a member of the organisation's teams reaches its repositories
            has_access |= self.team_members.get((owner, team), set())
        for key in ("push_whitelist_usernames", "merge_whitelist_usernames", "approvals_whitelist_username"):
            if key in body:
                merged[key] = [u for u in (body[key] or []) if u in has_access]
        for key in ("push_whitelist_teams", "merge_whitelist_teams", "approvals_whitelist_teams"):
            if key in body:
                merged[key] = [t for t in (body[key] or []) if t in self.orgs.get(owner, set())]
        for key in ("merge_whitelist_usernames", "merge_whitelist_teams", "push_whitelist_usernames",
                    "push_whitelist_teams"):
            merged.setdefault(key, [])
        for key in ("enable_push", "enable_push_whitelist", "enable_merge_whitelist"):
            merged.setdefault(key, False)
        merged["rule_name"] = merged.get("rule_name") or merged.get("branch_name")
        return merged

    def _unknown_names(self, full: str, body: dict[str, Any]) -> list[str]:
        """Names in `body`'s whitelists that Forgejo 17 refuses with 422: a user that does not exist, and a team the owning
        organisation lacks (a user-owned repository's teams are accepted and stored empty)."""
        owner = full.split("/", 1)[0]
        users = [u for key in ("push_whitelist_usernames", "merge_whitelist_usernames", "approvals_whitelist_username")
                 for u in (body.get(key) or []) if u not in self.users]
        teams = [t for key in ("push_whitelist_teams", "merge_whitelist_teams", "approvals_whitelist_teams")
                 for t in (body.get(key) or []) if owner in self.orgs and t not in self.orgs[owner]]
        return [*users, *teams]

    def _can_merge(self, bot: str, full: str, rule: dict[str, Any] | None) -> bool:
        """P-a: a writer merges unless an enabled merge whitelist lacks it (as a user or through a team)."""
        if self.repos[full]["collaborators"].get(bot) not in ("write", "admin"):
            return False
        if rule is None or not rule.get("enable_merge_whitelist"):
            return True
        owner = full.split("/", 1)[0]
        return bot in rule["merge_whitelist_usernames"] or any(
            bot in self.team_members.get((owner, team), set()) for team in rule["merge_whitelist_teams"])

    def has_commits(self, full_name: str) -> bool:
        return _git("rev-parse", "--verify", "-q", "refs/heads/main", cwd=self.bare(full_name)).returncode == 0

    def collaborators(self, full_name: str) -> dict[str, str]:
        return dict(self.repos[full_name]["collaborators"])

    def _delete_user(self, user: str, *, purge: bool) -> httpx.Response:
        """Forgejo 17's user delete: a user owning a repository is refused 422 unless purged (purge deletes what it
        owns); any delete ends its integrations (G8, #1433) and its collaborations."""
        if user not in self.users:
            return httpx.Response(404)
        owned = [full for full in self.repos if full.startswith(f"{user}/")]
        if owned and not purge:
            return httpx.Response(422, json={"message": f"user still has ownership of repositories [uid: {user}]"})
        for full in owned:
            self.repos.pop(full)
        self.users.discard(user)
        self.must_change_password.pop(user, None)
        self.prohibit_login.discard(user)
        for audience in self.integrations.pop(user, []):
            self.integration_rules.pop(audience, None)
        for repo in self.repos.values():
            repo["collaborators"].pop(user, None)
        return httpx.Response(204)

    def handle(self, request: httpx.Request) -> httpx.Response:  # noqa: C901, PLR0911, PLR0912 — one arm per endpoint
        call, injected = self._record(request)
        if injected is not None:
            return injected
        parts = call.path.removeprefix("/api/v1/").split("/")
        body = call.body or {}
        if call.headers.get("authorization", "").startswith("Bearer "):
            response = self._integration(call, parts)
            return response
        match (call.method, parts):
            case ("POST", ["admin", "users"]):
                if body["username"] in self.users:
                    return httpx.Response(422, json={"message": "user already exists"})
                self.users.add(body["username"])
                self.must_change_password[body["username"]] = body.get("must_change_password", True)
                return httpx.Response(201, json={"login": body["username"], "id": len(self.users)})
            case ("PATCH", ["admin", "users", user]):
                if user not in self.users:
                    return httpx.Response(404)
                if "must_change_password" in body:
                    self.must_change_password[user] = bool(body["must_change_password"])
                if "prohibit_login" in body:
                    (self.prohibit_login.add if body["prohibit_login"] else self.prohibit_login.discard)(user)
                return httpx.Response(200, json={"login": user})
            case ("GET", ["users", user]):
                return httpx.Response(200, json={"login": user}) if user in self.users else httpx.Response(404)
            case ("DELETE", ["admin", "users", user]):
                return self._delete_user(user, purge=call.query.get("purge") == ["true"])
            case ("POST", ["orgs", org, "repos"]):
                full = f"{org}/{body['name']}"
                if full in self.repos:
                    return httpx.Response(409, json={"message": "repository already exists"})
                self.bare(full).parent.mkdir(parents=True, exist_ok=True)
                _git("init", "--bare", "-q", "-b", "main", str(self.bare(full)))
                self.repos[full] = {"private": bool(body.get("private")), "archived": False,
                                    "collaborators": {}, "protections": {}}
                return httpx.Response(201, json=self._repo(full))
            case ("GET", [_, _, _]) if parts[0] == "repos":
                full = f"{parts[1]}/{parts[2]}"
                return httpx.Response(200, json=self._repo(full)) if full in self.repos else httpx.Response(404)
            case (_, ["repos", owner, name, *_rest]) if f"{owner}/{name}" not in self.repos:
                return httpx.Response(404, json={"message": "repository does not exist"})
            case ("PATCH", ["repos", owner, name]):
                self.repos[f"{owner}/{name}"]["archived"] = bool(body.get("archived"))
                return httpx.Response(200, json=self._repo(f"{owner}/{name}"))
            case ("DELETE", ["repos", owner, name]):
                if self.repos.pop(f"{owner}/{name}", None) is None:
                    return httpx.Response(404)
                return httpx.Response(204)
            case ("GET", ["repos", owner, name, "collaborators"]):
                return httpx.Response(200, json=[{"login": u} for u in self.repos[f"{owner}/{name}"]["collaborators"]])
            case ("PUT", ["repos", owner, name, "collaborators", user]):
                self.repos[f"{owner}/{name}"]["collaborators"][user] = body.get("permission", "write")
                return httpx.Response(204)
            case ("DELETE", ["repos", owner, name, "collaborators", user]):
                self.repos[f"{owner}/{name}"]["collaborators"].pop(user, None)
                return httpx.Response(204)
            case ("GET", ["repos", owner, name, "collaborators", user, "permission"]):
                perm = self.repos[f"{owner}/{name}"]["collaborators"].get(user)
                return httpx.Response(200, json={"permission": perm}) if perm else httpx.Response(404)
            case ("POST", ["repos", owner, name, "branch_protections"]):
                rule = body.get("rule_name") or body.get("branch_name")
                if rule in self.repos[f"{owner}/{name}"]["protections"]:
                    return httpx.Response(403, json={"message": "Branch protection already exist"})
                if unknown := self._unknown_names(f"{owner}/{name}", body):
                    return httpx.Response(422, json={"message": f"unknown whitelist name {unknown[0]}"})
                stored = self._stored_rule(f"{owner}/{name}", body, None)
                self.repos[f"{owner}/{name}"]["protections"][rule] = stored
                return httpx.Response(201, json=stored)
            case ("PATCH", ["repos", owner, name, "branch_protections", rule]):
                protections = self.repos[f"{owner}/{name}"]["protections"]
                if rule not in protections:
                    return httpx.Response(404, json={"message": "branch protection does not exist"})
                if unknown := self._unknown_names(f"{owner}/{name}", body):
                    return httpx.Response(422, json={"message": f"unknown whitelist name {unknown[0]}"})
                protections[rule] = self._stored_rule(f"{owner}/{name}", body, protections[rule])
                return httpx.Response(200, json=protections[rule])
            case ("GET", ["repos", owner, name, "branch_protections"]):
                return httpx.Response(200, json=list(self.repos[f"{owner}/{name}"]["protections"].values()))
            case ("GET", ["repos", owner, name, "branch_protections", rule]):
                found = self.repos[f"{owner}/{name}"]["protections"].get(rule)
                return httpx.Response(200, json=found) if found else httpx.Response(404)
        return httpx.Response(404, json={"message": f"fake forge: no route {call.method} {call.path}"})

    def _bot_of(self, jwt: str) -> tuple[str | None, dict[str, Any] | None, dict[str, Any] | None]:
        """(bot, its integration's recorded rule, the JWT's claims) for the integration holding the JWT's audience."""
        claims = self.jwt_claims(jwt)
        if claims is None:
            return None, None, None
        bot = next((u for u, audiences in self.integrations.items()
                    if claims.get("aud") in audiences and u in self.users), None)
        rule = self.integration_rules.get(claims.get("aud")) if bot is not None else None
        return bot, rule, claims

    def _integration(self, call: Call, parts: list[str]) -> httpx.Response:
        """A Bearer call: authenticate the bot through its integration, then answer its few routes."""
        bot, rule, claims = self._bot_of(call.headers["authorization"].removeprefix("Bearer "))
        response = self._integration_answer(bot, rule, claims or {}, call, parts)
        self.integration_calls.append((bot, call.method, call.path, response.status_code))
        return response

    def _integration_answer(self, bot: str | None, rule: dict[str, Any] | None, claims: dict[str, Any],
                            call: Call, parts: list[str]) -> httpx.Response:
        if bot is None:
            return httpx.Response(401, json={"message": "token is unauthorized"})
        refused = self._refused_by_rule(rule, claims, parts) if rule is not None else None
        if refused is not None and refused.status_code == 401:
            return refused
        if self.must_change_password.get(bot):  # G23
            return httpx.Response(403, json={"message": "You must change your password"})
        if bot in self.prohibit_login:  # G15
            return httpx.Response(403, json={"message": "This account is prohibited from signing in"})
        if refused is not None:
            return refused
        match (call.method, parts):
            case ("GET", ["repos", owner, name]) if self._can_read(bot, f"{owner}/{name}"):
                return httpx.Response(200, json=self._repo(f"{owner}/{name}"))
            case ("GET", ["repos", owner, name, "branches", branch]) if self._can_read(bot, f"{owner}/{name}"):
                full = f"{owner}/{name}"
                rule_ = self.repos[full]["protections"].get(branch)
                can_write = self.repos[full]["collaborators"].get(bot) in ("write", "admin")
                if rule_ is None:
                    push = can_write
                else:  # G22: protected against pushes unless enabled and (no whitelist or the bot is on it)
                    whitelist = rule_.get("push_whitelist_usernames") or []
                    push = can_write and bool(rule_.get("enable_push")) and (not whitelist or bot in whitelist)
                return httpx.Response(200, json={"name": branch, "protected": rule_ is not None,
                                                 "user_can_push": push,
                                                 "user_can_merge": self._can_merge(bot, full, rule_)})
            case ("GET", ["repos", _, _, "branch_protections", *_]):
                return httpx.Response(403, json={"message": "bot may not read protections"})
        return httpx.Response(404, json={"message": "not found"})

    @staticmethod
    def _refused_by_rule(rule: dict[str, Any], claims: dict[str, Any], parts: list[str]) -> httpx.Response | None:
        """What the integration was created with, enforced (F-6): issuer and `--claim-eq` claims (401), `--repo`
        (404 for another repository) and `--scope` (403 when none gives repository access)."""
        if rule["issuer"] != claims.get("iss") or any(claims.get(k) != v for k, v in rule["claims_eq"].items()):
            return httpx.Response(401, json={"message": "token is unauthorized"})
        if parts[0] == "repos" and len(parts) >= 3:
            if rule["repos"] != ["all"] and f"{parts[1]}/{parts[2]}" not in rule["repos"]:
                return httpx.Response(404, json={"message": "repository does not exist"})
            if not set(rule["scopes"]) & {"all", "read:repository", "write:repository"}:
                return httpx.Response(403, json={"message": "token does not have the repository scope"})
        return None

    def _can_read(self, bot: str, full: str) -> bool:
        return full in self.repos and bot in self.repos[full]["collaborators"]

    def _repo(self, full: str) -> dict[str, Any]:
        repo = self.repos[full]
        return {"full_name": full, "private": repo["private"], "archived": repo["archived"],
                "empty": not self.has_commits(full), "default_branch": "main",
                "clone_url": f"{FORGE_URL}/{full}.git"}


class FakeIntegrationCommand:
    """The fixed command's runner: `(arguments) -> CompletedProcess`, the arguments being those after
    `forgejo admin user create-authorized-integration`. Prints G6's JSON; each run is a new integration (G7).
    The arguments (`--username --name --issuer --claim-eq k=v --scope --repo`, Forgejo 17's flags; `--flag=value`
    also parsed) are recorded in `created` and in `FakeForge.integration_rules`, which the forge enforces."""

    def __init__(self, forge: FakeForge, issuer: str = ISSUER_URL) -> None:
        self.forge = forge
        self.issuer = issuer
        self.calls: list[list[str]] = []
        self.created: list[dict[str, Any]] = []
        self.fail_next = 0

    @staticmethod
    def _flags(args: list[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        i = 0
        while i < len(args):
            flag, eq, value = args[i].partition("=")
            if not eq and i + 1 < len(args):
                value, i = args[i + 1], i + 1
            out.setdefault(flag.lstrip("-"), []).append(value)
            i += 1
        return out

    def __call__(self, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        args = [str(a) for a in arguments]
        self.calls.append(args)
        if self.fail_next:
            self.fail_next -= 1
            return subprocess.CompletedProcess(args, 1, "", "invalid issuer: error when fetching .well-known")
        flags = self._flags(args)
        user, name = flags["username"][0], flags["name"][0]
        issuer = flags.get("issuer", [""])[0]
        if issuer != self.issuer:  # Forgejo fetches <issuer>/.well-known/openid-configuration (G6)
            return subprocess.CompletedProcess(args, 1, "", "invalid issuer: error when fetching .well-known")
        if user not in self.forge.users:
            return subprocess.CompletedProcess(args, 1, "", f"user does not exist [name: {user}]")
        claims = dict(c.split("=", 1) for c in flags.get("claim-eq", []))
        rule = {"user": user, "name": name, "issuer": issuer, "claims_eq": claims,
                "scopes": flags.get("scope", ["all"]), "repos": flags.get("repo", ["all"])}
        audience = f"u:{len(self.forge.users)}:{uuid.uuid4()}"
        self.forge.integrations.setdefault(user, []).append(audience)
        self.forge.integration_rules[audience] = rule
        self.created.append({**rule, "audience": audience})
        return subprocess.CompletedProcess(args, 0, json.dumps({"name": name, "audience": audience}) + "\n", "")


class FakeOpenBao(_Recorder):
    """OpenBao's HTTP API for the paths #1214 names. `X-Vault-Wrap-TTL` wraps a secret id; an
    unwrap spends the wrapper. Login needs a live AppRole and secret id; minting needs a live role."""

    def __init__(self, issuer: str = ISSUER_URL, *, sign_policy: str = SIGN_POLICY) -> None:
        super().__init__()
        self.issuer = issuer
        #: The templated policy that lets a login sign with its own tenant's key (r8.2 A24').
        self.sign_policy = sign_policy
        #: transit key name -> {"type", "deletion_allowed"} (P-b).
        self.transit_keys: dict[str, dict[str, Any]] = {}
        #: every accepted transit sign: (key, the signing login's AppRole, the base64 input).
        self.signs: list[tuple[str, str, str]] = []
        #: AppRole name -> the `token_policies` it was made with.
        self.approle_policies: dict[str, list[str]] = {}
        self.oidc_roles: dict[str, dict[str, Any]] = {}
        self.approles: dict[str, dict[str, str]] = {}  # name -> {accessor: secret_id}
        self.entities: dict[str, dict[str, Any]] = {}
        self.aliases: list[dict[str, Any]] = []
        self.wrapped: dict[str, tuple[str, str, str]] = {}  # token -> (approle, secret_id, accessor)
        self.tokens: dict[str, str] = {}  # client token -> approle
        self.minted: list[tuple[str, str]] = []  # (oidc role, jwt)
        #: the entity name each `minted` entry was minted for (index-aligned with `minted`).
        self.minted_for: list[str | None] = []
        #: the audience and `tenant_id` claim at the moment of the mint (index-aligned): a signed JWT keeps its claims.
        self.minted_claims: list[dict[str, Any]] = []
        #: client token -> its entity (name), or None when the AppRole login resolved no entity alias.
        self.token_entity: dict[str, str | None] = {}
        #: The token the management login holds; CRUD/list/role-id paths need it (the host has none).
        self.management_token = "bao-management-token"
        self._n = itertools.count(1)

    def client(self, token: str | None = "bao-management-token") -> httpx.AsyncClient:
        """The management login's client (default), or, with `token=None`, the host's login client:
        no token header (unwrap sets the wrapping token itself; approle/login needs none)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle), base_url=OPENBAO_URL,
                                 headers={} if token is None else {"X-Vault-Token": token})

    def claims(self, jwt: str) -> dict[str, Any] | None:
        """What Forgejo reads off a minted JWT: issuer, OIDC role, audience (the role's client id) and the
        `tenant_id` claim the role's template takes from the minting entity's metadata (G10)."""
        index = next((i for i, (_r, j) in enumerate(self.minted) if j == jwt), None)
        if index is None:
            return None
        role = self.minted[index][0]
        # A signed JWT is verified by signature: deleting its role (or entity) revokes nothing (r9 FR-8); old JWTs
        # die with the old bot (its integration), not here.
        return {"iss": self.issuer, "role": role, **self.minted_claims[index]}

    def mint_entity(self, jwt: str) -> str | None:
        """The entity name `jwt` was minted for."""
        return next((e for (_r, j), e in zip(self.minted, self.minted_for, strict=True) if j == jwt), None)

    def _entity_of_login(self, role_id: str) -> str | None:
        """The entity a login with `role_id` resolves to: the entity-alias named by the role id (OpenBao's AppRole alias)."""
        for alias in self.aliases:
            if alias.get("name") == role_id:
                return next((n for n, e in self.entities.items()
                             if alias.get("canonical_id") in (e["id"], n)), None)
        return None

    def tokens_used(self) -> set[str]:
        """Every X-Vault-Token value any call carried (SK-5: the host's calls never carry the management one)."""
        return {c.headers["x-vault-token"] for c in self.calls if "x-vault-token" in c.headers}

    def secret_accessors(self, approle: str) -> set[str]:
        return set(self.approles.get(approle, {}))

    def _sign(self, call: Call, key: str, body: dict[str, Any]) -> httpx.Response:
        """`transit/sign/<key>` as the sign policy allows it: a client token of an AppRole made with `sign_policy`,
        whose entity's `tenant_id` names this key. The management token and a delivery login are refused (403)."""
        client = call.headers.get("x-vault-token")
        role = self.tokens.get(client)
        entity = self.token_entity.get(client)
        tenant = (self.entities.get(entity or "", {}).get("metadata") or {}).get("tenant_id")
        if role is None or self.sign_policy not in self.approle_policies.get(role, []) or key != f"request-token-{tenant}":
            return httpx.Response(403, json={"errors": ["permission denied"]})
        if key not in self.transit_keys:
            return httpx.Response(400, json={"errors": ["signing key not found"]})
        self.signs.append((key, role, str(body.get("input"))))
        return httpx.Response(200, json={"data": {"signature": f"vault:v1:{key}:{body.get('input')}", "key_version": 1}})

    def handle(self, request: httpx.Request) -> httpx.Response:  # noqa: C901, PLR0911, PLR0912, PLR0915 — one arm per endpoint
        call, injected = self._record(request)
        if injected is not None:
            return injected
        method = "LIST" if call.query.get("list") == ["true"] else call.method
        parts = call.path.removeprefix("/v1/").split("/")
        body = call.body or {}
        unauthenticated = parts[:2] == ["sys", "wrapping"] or parts[:3] == ["auth", "approle", "login"] \
            or parts[:3] == ["identity", "oidc", "token"] or parts[:2] == ["transit", "sign"]
        if not unauthenticated and call.headers.get("x-vault-token") != self.management_token:
            return httpx.Response(403, json={"errors": ["permission denied"]})
        match (method, parts):
            case ("POST" | "PUT", ["identity", "oidc", "role", name]):
                self.oidc_roles.setdefault(name, {}).update(body)
                return httpx.Response(204)
            case ("GET", ["identity", "oidc", "role", name]):
                return (httpx.Response(200, json={"data": self.oidc_roles[name]}) if name in self.oidc_roles
                        else httpx.Response(404, json={"errors": []}))
            case ("DELETE", ["identity", "oidc", "role", name]):
                self.oidc_roles.pop(name, None)  # G24: OpenBao answers 204 for a missing one too
                return httpx.Response(204)
            case ("POST" | "PUT", ["auth", "approle", "role", name]):
                self.approles.setdefault(name, {})
                self.approle_policies[name] = list(body.get("token_policies") or [])
                return httpx.Response(204)
            case ("DELETE", ["auth", "approle", "role", name]):
                self.approles.pop(name, None)  # G24: OpenBao answers 204 for a missing one too
                self.approle_policies.pop(name, None)
                return httpx.Response(204)
            case ("GET", ["auth", "approle", "role", name, "role-id"]):
                if name not in self.approles:
                    return httpx.Response(404, json={"errors": []})
                return httpx.Response(200, json={"data": {"role_id": f"role-id-{name}"}})
            case ("POST" | "PUT", ["auth", "approle", "role", name, "secret-id"]):
                if name not in self.approles:
                    return httpx.Response(400, json={"errors": [f"role {name} does not exist"]})
                n = next(self._n)
                secret, accessor = f"secret-{n}", f"accessor-{n}"
                self.approles[name][accessor] = secret
                if "x-vault-wrap-ttl" in {k.lower() for k in call.headers}:
                    token = f"wrap-{n}"
                    self.wrapped[token] = (name, secret, accessor)
                    return httpx.Response(200, json={"wrap_info": {"token": token, "accessor": f"wrap-accessor-{n}", "ttl": 600}})
                return httpx.Response(200, json={"data": {"secret_id": secret, "secret_id_accessor": accessor}})
            case ("LIST", ["auth", "approle", "role", name, "secret-id"]):
                if name not in self.approles:
                    return httpx.Response(404, json={"errors": []})
                return httpx.Response(200, json={"data": {"keys": sorted(self.approles.get(name, {}))}})
            case ("POST" | "PUT", ["auth", "approle", "role", name, "secret-id-accessor", "destroy"]):
                if self.approles.get(name, {}).pop(body.get("secret_id_accessor"), None) is None:
                    return httpx.Response(404, json={"errors": []})  # RC-4
                return httpx.Response(204)
            case ("POST" | "PUT", ["sys", "wrapping", "unwrap"]):
                token = (call.body or {}).get("token") or call.headers.get("x-vault-token")
                if token not in self.wrapped:
                    return httpx.Response(400, json={"errors": ["wrapping token is not valid or does not exist"]})
                _role, secret, accessor = self.wrapped.pop(token)
                return httpx.Response(200, json={"data": {"secret_id": secret, "secret_id_accessor": accessor}})
            case ("POST" | "PUT", ["auth", "approle", "login"]):
                role = body.get("role_id", "").removeprefix("role-id-")
                if body.get("secret_id") not in self.approles.get(role, {}).values():
                    return httpx.Response(400, json={"errors": ["invalid role or secret ID"]})
                token = f"client-{next(self._n)}"
                self.tokens[token] = role
                self.token_entity[token] = self._entity_of_login(body["role_id"])
                return httpx.Response(200, json={"auth": {"client_token": token, "entity_id": role}})
            case ("GET", ["identity", "oidc", "token", role]):
                client = call.headers.get("x-vault-token")
                if client not in self.tokens or role not in self.oidc_roles:
                    return httpx.Response(403, json={"errors": ["permission denied"]})
                entity = self.token_entity.get(client)
                if TOKEN_POLICY not in self.approle_policies.get(self.tokens[client], []):  # the policy grants the read, as in _sign
                    return httpx.Response(403, json={"errors": ["permission denied"]})
                # the one templated policy: read identity/oidc/token/{{identity.entity.metadata.oidc_role}}
                if entity not in self.entities or (self.entities[entity].get("metadata") or {}).get("oidc_role") != role:
                    return httpx.Response(403, json={"errors": ["permission denied"]})
                jwt = f"jwt.{role}.{next(self._n)}"
                self.minted.append((role, jwt))
                self.minted_for.append(entity)
                self.minted_claims.append({"aud": self.oidc_roles[role].get("client_id"),
                                           "tenant_id": (self.entities[entity].get("metadata") or {}).get("tenant_id")})
                return httpx.Response(200, json={"data": {"token": jwt, "client_id": self.oidc_roles[role].get("client_id")}})
            case ("POST" | "PUT", ["identity", "entity", "name", name]):
                existing = self.entities.get(name)
                self.entities[name] = {"id": f"entity-{name}", **(existing or {}), **body}
                if existing is not None:  # OpenBao answers an update with no body
                    return httpx.Response(204)
                return httpx.Response(200, json={"data": {"id": f"entity-{name}", "name": name}})
            case ("GET", ["identity", "entity", "name", name]):
                if name not in self.entities:
                    return httpx.Response(404, json={"errors": []})
                entity = self.entities[name]
                aliases = [a for a in self.aliases if a.get("canonical_id") in (entity["id"], name)]
                return httpx.Response(200, json={"data": {**entity, "name": name, "aliases": aliases}})
            case ("DELETE", ["identity", "entity", "name", name]):
                gone = self.entities.pop(name, None)  # G24: OpenBao answers 204 for a missing one too
                if gone is not None:
                    self.aliases = [a for a in self.aliases if a.get("canonical_id") not in (gone["id"], name)]
                return httpx.Response(204)
            case ("POST" | "PUT", ["identity", "entity-alias"]):
                # P-c: one alias per entity per auth mount
                if any(a.get("canonical_id") == body.get("canonical_id")
                       and a.get("mount_accessor") == body.get("mount_accessor") for a in self.aliases):
                    return httpx.Response(400, json={"errors": ["Alias already exists for requested entity and mount accessor"]})
                alias = {"id": f"alias-{next(self._n)}", **body}
                self.aliases.append(alias)
                return httpx.Response(200, json={"data": {"id": alias["id"], "canonical_id": body.get("canonical_id")}})
            case ("LIST", ["identity", "entity-alias", "id"]):
                if not self.aliases:
                    return httpx.Response(404, json={"errors": []})
                return httpx.Response(200, json={"data": {"keys": [a["id"] for a in self.aliases]}})
            case ("GET", ["identity", "entity-alias", "id", alias_id]):
                found = next((a for a in self.aliases if a["id"] == alias_id), None)
                return httpx.Response(200, json={"data": found}) if found else httpx.Response(404, json={"errors": []})
            case ("DELETE", ["identity", "entity-alias", "id", alias_id]):
                self.aliases = [a for a in self.aliases if a["id"] != alias_id]
                return httpx.Response(204)
            case ("GET", ["transit", "keys", name]):
                if name not in self.transit_keys:
                    return httpx.Response(404, json={"errors": []})
                return httpx.Response(200, json={"data": {"name": name, **self.transit_keys[name]}})
            case ("POST" | "PUT", ["transit", "keys", name]):
                # P-b: creating an existing key changes nothing
                self.transit_keys.setdefault(name, {"type": body.get("type", "aes256-gcm96"), "deletion_allowed": False})
                return httpx.Response(204)
            case ("POST" | "PUT", ["transit", "keys", name, "config"]):
                if name not in self.transit_keys:
                    return httpx.Response(400, json={"errors": ["no existing key named " + name + " could be found"]})
                if "deletion_allowed" in body:
                    self.transit_keys[name]["deletion_allowed"] = bool(body["deletion_allowed"])
                return httpx.Response(200, json={"data": {"name": name, **self.transit_keys[name]}})
            case ("DELETE", ["transit", "keys", name]):
                if name not in self.transit_keys:
                    return httpx.Response(400, json={"errors": ["could not delete policy; not found"]})
                if not self.transit_keys[name]["deletion_allowed"]:
                    return httpx.Response(400, json={"errors": ["deletion is not allowed for this key"]})
                del self.transit_keys[name]
                return httpx.Response(204)
            case ("POST" | "PUT", ["transit", "sign", name, *_hash]):
                return self._sign(call, name, body)
            case ("GET", ["sys", "auth"]):
                return httpx.Response(200, json={"data": {"approle/": {"type": "approle", "accessor": "auth_approle_1"}}})
        return httpx.Response(404, json={"errors": [f"fake openbao: no route {method} {call.path}"]})


@dataclasses.dataclass(frozen=True)
class Sealed:
    """What `network_git` puts in the sealed descriptor: the origin's `extraHeader` carrying the JWT."""

    origin: str
    token: str
    args: tuple[str, ...]


class RoutedGit:
    """The `git` runner both actors are given: `(args, *, cwd=None, env=None, origin=None, identity=None)`,
    real git, with the forge's clone URL routed to `forge`'s bare repository. A push to a protected `main`
    is refused as Forgejo refuses it (pre-receive: protected branch). `calls` records each call's args and
    env as passed. With `identity` (a `ForgeCredential`) the fake models `network_git`: it reads
    `identity.token(min_validity=...)` and records it in `sealed` only (DC-10) -- the JWT is in neither argv nor
    the environment unless the caller put it there itself."""

    def __init__(self, forge: FakeForge) -> None:
        self.forge = forge
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.sealed: list[Sealed] = []

    def __call__(self, args: Sequence[str], *, cwd: Path | None = None,
                 env: Mapping[str, str] | None = None, origin: str | None = None,
                 identity: Any = None) -> subprocess.CompletedProcess[str]:
        args = [str(a) for a in args]
        self.calls.append((args, dict(env or {})))
        if identity is not None:
            self.sealed.append(Sealed(origin or FORGE_URL, identity.token(min_validity=60.0), tuple(args)))
        routed = [a.replace(f"{FORGE_URL}/", f"file://{self.forge.root}/") for a in args]
        if "push" in args and any(a.endswith("main") for a in args[args.index("push"):]):
            target = next((a for a in args if a.startswith(FORGE_URL)), None)
            full = None if target is None else target.removeprefix(f"{FORGE_URL}/").removesuffix(".git")
            if full is not None and "main" in self.forge.repos.get(full, {}).get("protections", {}):
                return subprocess.CompletedProcess(args, 1, "", "remote: error: protected branch main\n")
        return subprocess.run(["git", *routed], cwd=cwd, env={**os.environ, **(env or {})},  # noqa: S603, S607
                              capture_output=True, text=True, check=False)

    def pushes(self) -> list[tuple[list[str], dict[str, str]]]:
        return [(a, e) for a, e in self.calls if "push" in a]

    def sealed_tokens(self) -> list[str]:
        return [x.token for x in self.sealed]

    def argv_env_contains(self, secret: str) -> bool:
        """Does `secret` occur in any call's argv or environment (values and names)?"""
        return any(secret in part for args, env in self.calls for part in (*args, *env, *env.values()))


class RecordingPublish:
    """The host actor's first-publish seam (`launch_publish`'s shape): records and answers one line.
    Default `fresh <commit>` (RC-7); queue other lines (`stale`, an error text) in `answers`."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Path]] = []
        self.answers: list[str] = []

    def __call__(self, tenant_id: str, *, data_root: Path, **_kw: Any) -> str:
        self.calls.append((str(tenant_id), Path(data_root)))
        if self.answers:
            return self.answers.pop(0)
        return f"fresh {uuid.uuid4().hex}{uuid.uuid4().hex[:8]}"


class Fakes:
    """Every boundary fake of the lifecycle, wired: the forge resolves a bot's JWT through OpenBao's mints.
    `Fakes(tmp_path)` then `.forge .integration .openbao .git .publish`."""

    def __init__(self, tmp_path: Path, *, sign_policy: str = SIGN_POLICY) -> None:
        self.forge = FakeForge(tmp_path / "forge")
        self.integration = FakeIntegrationCommand(self.forge)
        self.openbao = FakeOpenBao(sign_policy=sign_policy)
        self.git = RoutedGit(self.forge)
        self.publish = RecordingPublish()
        self.forge.jwt_claims = self.openbao.claims
