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
        match (call.method, parts):
            case ("POST", ["admin", "users"]):
                if body["username"] in self.users:
                    return httpx.Response(422, json={"message": "user already exists"})
                self.users.add(body["username"])
                return httpx.Response(201, json={"login": body["username"], "id": len(self.users)})
            case ("GET", ["users", user]):
                return httpx.Response(200, json={"login": user}) if user in self.users else httpx.Response(404)
            case ("DELETE", ["admin", "users", user]):
                if user not in self.users:
                    return httpx.Response(404)
                self.users.discard(user)
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
        self._n = itertools.count(1)

    def client(self, token: str = "bao-management-token") -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle), base_url=OPENBAO_URL,
                                 headers={"X-Vault-Token": token})

    def secret_accessors(self, approle: str) -> set[str]:
        return set(self.approles.get(approle, {}))

    def handle(self, request: httpx.Request) -> httpx.Response:  # noqa: C901, PLR0911, PLR0912 — one arm per endpoint
        call, injected = self._record(request)
        if injected is not None:
            return injected
        method = "LIST" if call.query.get("list") == ["true"] else call.method
        parts = call.path.removeprefix("/v1/").split("/")
        body = call.body or {}
        match (method, parts):
            case ("POST" | "PUT", ["identity", "oidc", "role", name]):
                self.oidc_roles.setdefault(name, {}).update(body)
                return httpx.Response(204)
            case ("GET", ["identity", "oidc", "role", name]):
                return (httpx.Response(200, json={"data": self.oidc_roles[name]}) if name in self.oidc_roles
                        else httpx.Response(404, json={"errors": []}))
            case ("DELETE", ["identity", "oidc", "role", name]):
                self.oidc_roles.pop(name, None)
                return httpx.Response(204)
            case ("POST" | "PUT", ["auth", "approle", "role", name]):
                self.approles.setdefault(name, {})
                return httpx.Response(204)
            case ("DELETE", ["auth", "approle", "role", name]):
                self.approles.pop(name, None)
                return httpx.Response(204)
            case ("GET", ["auth", "approle", "role", name, "role-id"]):
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
                return httpx.Response(200, json={"data": {"keys": sorted(self.approles.get(name, {}))}})
            case ("POST" | "PUT", ["auth", "approle", "role", name, "secret-id-accessor", "destroy"]):
                self.approles.get(name, {}).pop(body.get("secret_id_accessor"), None)
                return httpx.Response(204)
            case ("POST" | "PUT", ["sys", "wrapping", "unwrap"]):
                token = call.headers.get("x-vault-token")
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
                self.entities.pop(name, None)
                return httpx.Response(204)
            case ("POST" | "PUT", ["identity", "entity-alias"]):
                self.aliases.append(body)
                return httpx.Response(200, json={"data": {"id": f"alias-{len(self.aliases)}"}})
            case ("GET", ["sys", "auth"]):
                return httpx.Response(200, json={"data": {"approle/": {"type": "approle", "accessor": "auth_approle_1"}}})
        return httpx.Response(404, json={"errors": [f"fake openbao: no route {method} {call.path}"]})


class RoutedGit:
    """The `git` runner both actors are given (`(args, *, cwd, env) -> CompletedProcess`): real git,
    with the forge's clone URL routed to `forge`'s bare repository. A push to a protected `main` is
    refused as Forgejo refuses it (pre-receive: protected branch). Records each call's args and env."""

    def __init__(self, forge: FakeForge) -> None:
        self.forge = forge
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def __call__(self, args: Sequence[str], *, cwd: Path | None = None,
                 env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        args = [str(a) for a in args]
        self.calls.append((args, dict(env or {})))
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


class RecordingPublish:
    """The host actor's first-publish seam (`launch_publish`'s shape): records and answers fresh."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Path]] = []

    def __call__(self, tenant_id: str, *, data_root: Path, **_kw: Any) -> str:
        self.calls.append((str(tenant_id), Path(data_root)))
        return json.dumps({"outcome": "fresh"})
