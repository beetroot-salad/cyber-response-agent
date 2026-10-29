"""#1214 boundary fakes — NO test functions, NO production imports. Each fake records every call
and answers as the real system was observed to (grounding G6-G9); none decides lifecycle policy.

- `FakeForge`: Forgejo 17's admin HTTP API as an `httpx.MockTransport` (G9's status codes). Repos
  are real bare git repositories under `root`, so the template commit and the host clone are real
  git (`RoutedGit` routes the forge's clone URLs to them).
- `FakeIntegrationCommand`: `forgejo admin user create-authorized-integration`'s runner; prints
  G6's JSON (with an `audience`); a re-run adds a second integration (G7); a purged user takes its
  integrations with it (G8, kept on `FakeForge.integrations`).
- `FakeOpenBao`: the OpenBao HTTP paths the design names (OIDC roles, AppRoles and their secret
  ids, wrapping, entities); a destroyed role or AppRole no longer logs in or mints.

r9 additions (slice 0):
- Forge: users carry `must_change_password` (Forgejo's default True; the admin create body or a PATCH
  clears it, G23) and `prohibit_login` (PATCH, G15). A request with `Authorization: Bearer <jwt>` is an
  integration call: the JWT must resolve (via `FakeOpenBao.claims`, wired by `Fakes`) to an audience that one
  bot's integration holds; a bot with `must_change_password` is refused 403 "You must change your password"
  (G23), a login-prohibited one 403 "This account is prohibited from signing in" (G15), a purged or
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
- `Fakes(tmp_path)` bundles forge, integration, openbao, git, publish and wires JWT resolution.
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
OPENBAO_URL = "http://openbao.test"
ORG = "tenants"


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

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def client(self, token: str = "forge-admin-token") -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport(), base_url=FORGE_URL,
                                 headers={"Authorization": f"token {token}"})

    def bare(self, full_name: str) -> Path:
        return self.root / f"{full_name}.git"

    def has_commits(self, full_name: str) -> bool:
        return _git("rev-parse", "--verify", "-q", "refs/heads/main", cwd=self.bare(full_name)).returncode == 0

    def collaborators(self, full_name: str) -> dict[str, str]:
        return dict(self.repos[full_name]["collaborators"])

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
                if user not in self.users:
                    return httpx.Response(404)
                self.users.discard(user)
                self.must_change_password.pop(user, None)
                self.prohibit_login.discard(user)
                if call.query.get("purge") == ["true"]:
                    self.integrations.pop(user, None)  # G8
                for repo in self.repos.values():
                    repo["collaborators"].pop(user, None)
                return httpx.Response(204)
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
                self.repos[f"{owner}/{name}"]["protections"][rule] = body
                return httpx.Response(201, json=body)
            case ("GET", ["repos", owner, name, "branch_protections", rule]):
                found = self.repos[f"{owner}/{name}"]["protections"].get(rule)
                return httpx.Response(200, json=found) if found else httpx.Response(404)
        return httpx.Response(404, json={"message": f"fake forge: no route {call.method} {call.path}"})

    def _bot_of(self, jwt: str) -> str | None:
        claims = self.jwt_claims(jwt)
        if claims is None:
            return None
        return next((u for u, audiences in self.integrations.items()
                     if claims.get("aud") in audiences and u in self.users), None)

    def _integration(self, call: Call, parts: list[str]) -> httpx.Response:
        """A Bearer call: authenticate the bot through its integration, then answer its few routes."""
        bot = self._bot_of(call.headers["authorization"].removeprefix("Bearer "))
        response = self._integration_answer(bot, call, parts)
        self.integration_calls.append((bot, call.method, call.path, response.status_code))
        return response

    def _integration_answer(self, bot: str | None, call: Call, parts: list[str]) -> httpx.Response:
        if bot is None:
            return httpx.Response(401, json={"message": "token is unauthorized"})
        if self.must_change_password.get(bot):  # G23
            return httpx.Response(403, json={"message": "You must change your password"})
        if bot in self.prohibit_login:  # G15
            return httpx.Response(403, json={"message": "This account is prohibited from signing in"})
        match (call.method, parts):
            case ("GET", ["repos", owner, name]) if self._can_read(bot, f"{owner}/{name}"):
                return httpx.Response(200, json=self._repo(f"{owner}/{name}"))
            case ("GET", ["repos", owner, name, "branches", branch]) if self._can_read(bot, f"{owner}/{name}"):
                full = f"{owner}/{name}"
                rule = self.repos[full]["protections"].get(branch)
                can_write = self.repos[full]["collaborators"].get(bot) in ("write", "admin")
                if rule is None:
                    push = can_write
                else:  # G22: protected against pushes unless enabled and (no whitelist or the bot is on it)
                    whitelist = rule.get("push_whitelist_usernames") or []
                    push = can_write and bool(rule.get("enable_push")) and (not whitelist or bot in whitelist)
                return httpx.Response(200, json={"name": branch, "protected": rule is not None,
                                                 "user_can_push": push})
            case ("GET", ["repos", _, _, "branch_protections", *_]):
                return httpx.Response(403, json={"message": "bot may not read protections"})
        return httpx.Response(404, json={"message": "not found"})

    def _can_read(self, bot: str, full: str) -> bool:
        return full in self.repos and bot in self.repos[full]["collaborators"]

    def _repo(self, full: str) -> dict[str, Any]:
        repo = self.repos[full]
        return {"full_name": full, "private": repo["private"], "archived": repo["archived"],
                "empty": not self.has_commits(full), "default_branch": "main",
                "clone_url": f"{FORGE_URL}/{full}.git"}


class FakeIntegrationCommand:
    """The fixed command's runner: `(arguments) -> CompletedProcess`, the arguments being those after
    `forgejo admin user create-authorized-integration`. Prints G6's JSON; each run is a new integration."""

    def __init__(self, forge: FakeForge) -> None:
        self.forge = forge
        self.calls: list[list[str]] = []
        self.fail_next = 0

    def __call__(self, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        args = list(arguments)
        self.calls.append(args)
        if self.fail_next:
            self.fail_next -= 1
            return subprocess.CompletedProcess(args, 1, "", "invalid issuer: error when fetching .well-known")
        user = args[args.index("--username") + 1]
        audience = f"u:{len(self.forge.users)}:{uuid.uuid4()}"
        self.forge.integrations.setdefault(user, []).append(audience)
        out = json.dumps({"name": args[args.index("--name") + 1], "audience": audience})
        return subprocess.CompletedProcess(args, 0, out + "\n", "")


class FakeOpenBao(_Recorder):
    """OpenBao's HTTP API for the paths #1214 names. `X-Vault-Wrap-TTL` wraps a secret id; an
    unwrap spends the wrapper. Login needs a live AppRole and secret id; minting needs a live role."""

    def __init__(self) -> None:
        super().__init__()
        self.oidc_roles: dict[str, dict[str, Any]] = {}
        self.approles: dict[str, dict[str, str]] = {}  # name -> {accessor: secret_id}
        self.entities: dict[str, dict[str, Any]] = {}
        self.aliases: list[dict[str, Any]] = []
        self.wrapped: dict[str, tuple[str, str, str]] = {}  # token -> (approle, secret_id, accessor)
        self.tokens: dict[str, str] = {}  # client token -> approle
        self.minted: list[tuple[str, str]] = []  # (oidc role, jwt)
        #: The token the management login holds; CRUD/list/role-id paths need it (the host has none).
        self.management_token = "bao-management-token"
        self._n = itertools.count(1)

    def client(self, token: str | None = "bao-management-token") -> httpx.AsyncClient:
        """The management login's client (default), or, with `token=None`, the host's login client:
        no token header (unwrap sets the wrapping token itself; approle/login needs none)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle), base_url=OPENBAO_URL,
                                 headers={} if token is None else {"X-Vault-Token": token})

    def claims(self, jwt: str) -> dict[str, Any] | None:
        """What Forgejo reads off a minted JWT: its OIDC role and audience (the role's client id)."""
        role = next((r for r, j in self.minted if j == jwt), None)
        if role is None or role not in self.oidc_roles:
            return None
        return {"role": role, "aud": self.oidc_roles[role].get("client_id")}

    def tokens_used(self) -> set[str]:
        """Every X-Vault-Token value any call carried (SK-5: the host's calls never carry the management one)."""
        return {c.headers["x-vault-token"] for c in self.calls if "x-vault-token" in c.headers}

    def secret_accessors(self, approle: str) -> set[str]:
        return set(self.approles.get(approle, {}))

    def handle(self, request: httpx.Request) -> httpx.Response:  # noqa: C901, PLR0911, PLR0912 — one arm per endpoint
        call, injected = self._record(request)
        if injected is not None:
            return injected
        method = "LIST" if call.query.get("list") == ["true"] else call.method
        parts = call.path.removeprefix("/v1/").split("/")
        body = call.body or {}
        unauthenticated = parts[:2] == ["sys", "wrapping"] or parts[:3] == ["auth", "approle", "login"] \
            or parts[:3] == ["identity", "oidc", "token"]
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
                return httpx.Response(204)
            case ("DELETE", ["auth", "approle", "role", name]):
                self.approles.pop(name, None)  # G24: OpenBao answers 204 for a missing one too
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
                return httpx.Response(200, json={"auth": {"client_token": token, "entity_id": role}})
            case ("GET", ["identity", "oidc", "token", role]):
                if call.headers.get("x-vault-token") not in self.tokens or role not in self.oidc_roles:
                    return httpx.Response(403, json={"errors": ["permission denied"]})
                jwt = f"jwt.{role}.{next(self._n)}"
                self.minted.append((role, jwt))
                return httpx.Response(200, json={"data": {"token": jwt, "client_id": self.oidc_roles[role].get("client_id")}})
            case ("POST" | "PUT", ["identity", "entity", "name", name]):
                self.entities[name] = {"id": f"entity-{name}", **body}
                return httpx.Response(200, json={"data": {"id": f"entity-{name}", "name": name}})
            case ("DELETE", ["identity", "entity", "name", name]):
                self.entities.pop(name, None)  # G24: OpenBao answers 204 for a missing one too
                return httpx.Response(204)
            case ("POST" | "PUT", ["identity", "entity-alias"]):
                self.aliases.append(body)
                return httpx.Response(200, json={"data": {"id": f"alias-{len(self.aliases)}"}})
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

    def __init__(self, tmp_path: Path) -> None:
        self.forge = FakeForge(tmp_path / "forge")
        self.integration = FakeIntegrationCommand(self.forge)
        self.openbao = FakeOpenBao()
        self.git = RoutedGit(self.forge)
        self.publish = RecordingPublish()
        self.forge.jwt_claims = self.openbao.claims
