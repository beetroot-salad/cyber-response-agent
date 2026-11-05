"""#1163 adapter and run side: helpers for the flows from the adapter to the proxy and for the
run-start tokens. Plants data, records and decodes; nothing here judges what the code under test
must do.

Names this module chooses (the contract's seams, listed in the contract map):
- `VerbContext.proxy_url` and `VerbContext.request_token`: the proxy's address and the request token,
  carried on the call's context (A9: the address is operator configuration handed in by the run,
  never read by an adapter from the model-visible `ctx.env`).
- `run.main(signer=, proxy_url=)`: the operator's seams at the run process.
- `run.main(issuer_transport=)` and the learning launcher's `issuer_transport=` (the name
  `publish_for_run` already uses): the `httpx` transport the in-process signer reaches OpenBao by
  when no `signer=` is injected. The signer logs in as the live generation's sign-only AppRole
  (`sign_role_id` and the host file `sign_secret_file`, read from the tenant records the run or the
  launcher holds, A24') at the deployment's OpenBao address, and signs through transit with that
  tenant's key (A11). Tenant records come in as `directory=` (`Records`, `generation`).
- The ticket writer's legs take `request_token=` and `proxy_url=` keywords.
"""
from __future__ import annotations

import ast
import base64
import contextlib
import json
import re
import secrets
from dataclasses import dataclass
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

from defender.systems.verbs import VerbContext
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import ACCESS_FILE
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, PublishedTenant, published_tenant

#: A signature no honest token can lose: a census looks for it in every channel.
SIGNATURE_CANARY = "CANARY-REQUEST-SIGNATURE-1163"

#: The operator's address variable at the run process. Set here only as a decoy in model-visible
#: environments; the contract does not say which variable an operator uses.
DECOY_PROXY_ENV = "DEFENDER_CREDENTIAL_PROXY_URL"


def prefix_of(system: str) -> str:
    return system.upper().replace("-", "_")


def transport_line(system: str) -> str:
    """The config.env line putting `system` on `http-proxy`: the one place a case writes it."""
    return f'{prefix_of(system)}_TRANSPORT="http-proxy"\n'


def env_text(system: str, *, extra: str = "") -> str:
    """`system`'s config.env on `http-proxy`: an access method and a timeout, no base, no bastion."""
    return f'{transport_line(system)}{prefix_of(system)}_TIMEOUT_SEC="5"\n{extra}'


#: The two POST reads an Elastic declaration lists (#1391 O3); GET /_cluster/health is a read by method.
ELASTIC_READS = (("POST", "/*/_search"), ("POST", "/_query"))
ELASTIC_EVENTS = "logs-*"
ELASTIC_ALERTS = "alerts-*"


def elastic_files(base: str, *, ca: str | bytes | None = None, transport: str | None = "http-proxy",
                  env_extra: str = "", scheme: dict[str, object] | None = None,
                  declared: bool = True) -> dict[str, str | None]:
    """Repo files making `elastic` a proxied system at `base`: a basic-auth declaration with
    `ELASTIC_READS` (and `ca` when given), and a config.env holding the access method (`transport`;
    None writes none), the two index keys and `env_extra` (no URL, Kibana or container key);
    `declared=False` deletes the declaration from the placed fixture (the shipped
    fixture tenant carries one, #1391 D12), as a `None` entry `files` applies after placement."""
    decl = H.declaration(base, scheme=scheme or H.basic_scheme(), reads=ELASTIC_READS, ca=ca)
    method = "" if transport is None else f'ELASTIC_TRANSPORT="{transport}"\n'
    env = (f'{method}ELASTIC_EVENTS_INDEX="{ELASTIC_EVENTS}"\n'
           f'ELASTIC_ALERTS_INDEX="{ELASTIC_ALERTS}"\n{env_extra}')
    files: dict[str, str | None] = dict(H.access_files("elastic", decl, env=env))
    if not declared:
        files[ACCESS_FILE.format(system="elastic")] = None
    return files


@contextlib.contextmanager
def elastic_proxied(tmp_path: Path, data_root: Path, base: str, *, ca: bytes | None = None,
                    ctx_kw: Mapping[str, Any] | None = None, **files_kw: Any) -> Iterator[tuple[VerbContext, Tap]]:
    """`elastic` declared at `base` (basic auth, the two POST reads, `ca` when given; `files_kw`
    shape its files, see `elastic_files`) behind the real proxy over a stored basic credential;
    yields the verb context (`ctx_kw`: more VerbContext fields) and the proxy's `Tap`."""
    with published_tenant(tmp_path / "forge", root=data_root,
                          files=elastic_files(base, ca=ca, **files_kw)) as t:
        store = H.FakeStore({(t.tenant_id, "elastic"): T.basic_set()})
        with proxy_for(t, store) as (url, tap):
            yield ctx_for(tmp_path, T.run_record(t), url,
                          T.token(t.tenant_id, {("elastic", "r")}), **(ctx_kw or {})), tap


def system_files(system: str, decl: str, *, env_extra: str = "") -> dict[str, str]:
    return H.access_files(system, decl, env=env_text(system, extra=env_extra))


@contextlib.contextmanager
def published(scratch: Path, root: Path, systems: Mapping[str, str], *,
              extra_files: Mapping[str, str | None] | None = None,
              **kw: Any) -> Iterator[PublishedTenant]:
    """The fixture tenant published once with every `{system: declaration}` of `systems` on
    `http-proxy`, and `extra_files` (repo path to content, `None` deletes) applied after."""
    files: dict[str, str | None] = {}
    for system, decl in systems.items():
        files.update(system_files(system, decl))
    files.update(extra_files or {})
    with published_tenant(scratch, root=root, files=files, **kw) as t:
        yield t


def duplicate_key_declaration(base: str) -> str:
    """A declaration with a repeated key. YAML text, because JSON cannot be written with one."""
    return ("access: http-proxy\n"
            f"base: {base}\n"
            f"base: {base}other\n"
            "auth: {scheme: bearer, field: api_key}\n"
            "reads: []\nwrites: []\n")


class MarkedSigner(H.FakeSigner):
    """The launcher's sign port with a signature that carries `SIGNATURE_CANARY`."""

    def sign(self, payload: bytes) -> str:
        self.payloads.append(payload)
        return f"{SIGNATURE_CANARY}-{len(self.payloads)}"


class RaisingSigner(H.FakeSigner):
    """A signer whose OpenBao is sealed or unreachable: raises `error` on every sign and records
    that it was asked."""

    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error
        self.asked = 0

    def sign(self, payload: bytes) -> str:
        self.asked += 1
        raise self.error


@dataclass(frozen=True)
class Sign:
    """One transit sign call the stand-in OpenBao answered."""

    client_token: str
    key: str
    payload: bytes
    mount: str = ""


class OpenBaoStandIn(httpx.MockTransport):
    """An OpenBao by transport: AppRole login for the registered `accounts` ({role_id:
    secret_id}), transit sign for any key of any mount (recording the mount) (refusing a client token it did not issue),
    and the housekeeping a client may plausibly use: `sys/health`, `sys/seal-status`, token
    `revoke-self`. Records every request path, login and sign; the signature carries
    `SIGNATURE_CANARY`. Decides nothing about which tenant's key a login may use: the test reads
    `logins` and `signs`. `origins` records each request's (scheme, host, port) beside `requests`' paths, so a test can hold
    the address a client chose to the deployment's (`deployment_origin`); client tokens are random and share no prefix.

    `sealed` ("login" or "sign") answers 503 `Vault is sealed` on that call (and on health, which
    reports sealed); `unreachable` raises a connection error on every request; `login_status` and
    `sign_status` answer that status (an error body) on the login or the sign call; `malformed`
    ("login" or "sign") answers that call 200 with a body lacking `auth.client_token` / `data.signature`; the sign call
    may instead be `"sign-nonjson"` (a 200 whose body is not JSON), `"sign-empty"` (`data.signature` is "") or
    `"sign-nonstring"` (`data.signature` is a number)."""

    def __init__(self, accounts: Mapping[str, str], *, sealed: str | None = None,
                 unreachable: bool = False, login_status: int | None = None,
                 sign_status: int | None = None, malformed: str | None = None) -> None:
        super().__init__(self._handle)
        self.malformed = malformed
        self.accounts = dict(accounts)
        self.sealed = sealed
        self.unreachable = unreachable
        self.login_status = login_status
        self.sign_status = sign_status
        self.requests: list[str] = []
        self.origins: list[tuple[str, str, int | None]] = []
        self.logins: list[tuple[str, str]] = []
        self.signs: list[Sign] = []
        self.refused: list[str] = []
        self.revoked: list[str] = []
        self._tokens: dict[str, str] = {}

    def _sealed_answer(self) -> httpx.Response:
        return httpx.Response(503, json={"errors": ["Vault is sealed"]})

    def _forced(self, call: str, status: int | None) -> httpx.Response | None:
        """The fault this stand-in is set to answer `call` with, if any."""
        if self.sealed == call:
            return self._sealed_answer()
        if status is not None:
            return httpx.Response(status, json={"errors": [f"{call} failed"]})
        if self.malformed == call:
            return httpx.Response(200, json={"auth": {"lease_duration": 600}} if call == "login" else {"data": {}})
        if self.malformed == f"{call}-nonjson":
            return httpx.Response(200, content=b"<html>not json</html>", headers={"Content-Type": "text/html"})
        if self.malformed == f"{call}-empty":
            return httpx.Response(200, json={"data": {"signature": ""}})
        if self.malformed == f"{call}-nonstring":
            return httpx.Response(200, json={"data": {"signature": 7}})
        return None

    def _housekeeping(self, request: httpx.Request) -> httpx.Response | None:
        path = request.url.path
        if path == "/v1/sys/health":
            return httpx.Response(503 if self.sealed else 200, json={
                "initialized": True, "sealed": bool(self.sealed), "standby": False})
        if path == "/v1/sys/seal-status":
            return httpx.Response(200, json={"initialized": True, "sealed": bool(self.sealed)})
        if path == "/v1/auth/token/revoke-self":
            self.revoked.append(request.headers.get("X-Vault-Token", ""))
            return httpx.Response(204)
        return None

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append(path)
        self.origins.append((request.url.scheme, request.url.host, request.url.port))
        if self.unreachable:
            raise httpx.ConnectError("connection refused", request=request)
        housekeeping = self._housekeeping(request)
        if housekeeping is not None:
            return housekeeping
        if path == "/v1/auth/approle/login":
            body = json.loads(request.content)
            self.logins.append((body["role_id"], body["secret_id"]))
            forced = self._forced("login", self.login_status)
            if forced is not None:
                return forced
            if self.accounts.get(body["role_id"]) != body["secret_id"]:
                self.refused.append(path)
                return httpx.Response(403, json={"errors": ["invalid credentials"]})
            token = secrets.token_urlsafe(24)
            self._tokens[token] = body["role_id"]
            return httpx.Response(200, json={"auth": {"client_token": token,
                                                      "lease_duration": 600}})
        match = re.fullmatch(r"/v1/([^/]+)/sign/([^/]+)(?:/[^/]+)?", path)
        if match:
            forced = self._forced("sign", self.sign_status)
            if forced is not None:
                return forced
            token = request.headers.get("X-Vault-Token", "")
            if token not in self._tokens or token in self.revoked:
                self.refused.append(path)
                return httpx.Response(403, json={"errors": ["permission denied"]})
            payload = base64.b64decode(json.loads(request.content)["input"])
            self.signs.append(Sign(token, match.group(2), payload, match.group(1)))
            return httpx.Response(200, json={"data": {
                "signature": f"vault:v1:{SIGNATURE_CANARY}-{len(self.signs)}"}})
        self.refused.append(path)
        return httpx.Response(404, json={"errors": ["unsupported path"]})

    def role_of(self, sign: Sign) -> str:
        """The role whose login produced the client token `sign` used."""
        return self._tokens[sign.client_token]


def deployment_origin() -> tuple[str, str, int | None]:
    """The (scheme, host, port) of the deployment's OpenBao address (A1: the only address a signer may use)."""
    from defender.configuration.issuer import DEPLOYMENT_ISSUER

    url = httpx.URL(DEPLOYMENT_ISSUER.openbao_url)
    return url.scheme, url.host, url.port


def generation(  # noqa: PLR0913 — one keyword per field a test varies
        tenant_id: str, scratch: Path, *, sign_role_id: str, sign_secret: str,
               role_id: str = "delivery-role-1163", delivery_secret: str = "delivery-secret-1163",
               salt: str = "g1", status: str = "live", sign_file: bool = True,
               delivery_file: bool = True) -> dict[str, Any]:
    """The fields of one credential generation of `tenant_id` (#1214's names, plus A24's sign
    login) with its two host secret files written under `scratch` as the host writes them (the
    secret id and a newline). `sign_file=False` / `delivery_file=False` leave that file unwritten.
    Plants data only."""
    scratch.mkdir(parents=True, exist_ok=True)
    delivery, sign = scratch / f"{tenant_id}-{salt}", scratch / f"{tenant_id}-{salt}-sign"
    for path, secret, written in ((delivery, delivery_secret, delivery_file),
                                  (sign, sign_secret, sign_file)):
        if written:
            path.write_text(secret + "\n", encoding="utf-8")
            path.chmod(0o600)
    return {"salt": salt, "status": status, "bot_login": f"bot-{tenant_id}-{salt}",
            "oidc_role": f"oidc-{tenant_id}-{salt}", "approle": f"approle-{tenant_id}-{salt}",
            "role_id": role_id, "entity": f"entity-{tenant_id}-{salt}",
            "audience": f"audience-{tenant_id}-{salt}", "host_secret_file": delivery.absolute(),
            "secret_accessor": f"accessor-{tenant_id}-{salt}",
            "sign_approle": f"sign-{tenant_id}-{salt}", "sign_entity": f"tenant-{tenant_id}-{salt}-sign",
            "sign_role_id": sign_role_id, "sign_secret_file": sign.absolute(),
            "sign_secret_accessor": f"sign-accessor-{tenant_id}-{salt}"}


class Records:
    """Tenant records (#1214's `TenantDirectory` over an `InMemoryTenantRepository`, as its own
    tests build them) holding each of `tenants` ACTIVE with its forge wiring and generations.
    `directory` is what a run or a launcher takes as `directory=`. Build it after the tenant's
    folder is planted (the wiring's origin is read from the folder's clone). The mutators change
    the live generation as the lifecycle would (a rotation, an offboarding) while a run is on."""

    def __init__(self, data_root: Path, tenants: Mapping[str, Sequence[Mapping[str, Any]]]) -> None:
        from defender.tenancy import InMemoryTenantRepository, TenantDirectory
        from defender.tests.support.tenancy import _active1214 as active

        self.twin: Any = InMemoryTenantRepository()
        self._active = active
        for tenant, generations in tenants.items():
            active.run_sync(self.twin.add_tenant(
                tenant, created_at=active.CREATED, state="active", repo=f"tenants/{tenant}",
                origin=active._origin_of(Path(data_root), tenant, None)))  # noqa: SLF001
            for fields in generations:
                active.run_sync(self.twin.add_generation(tenant, **fields))
        self.directory = TenantDirectory(lambda: self.twin)

    def rotate(self, tenant: str, fields: Mapping[str, Any]) -> None:
        """`fields` becomes the tenant's live generation; the one before it is `retiring`."""
        self._set_status(tenant, "live", "retiring")
        self._active.run_sync(self.twin.add_generation(tenant, **fields))

    def offboard(self, tenant: str) -> None:
        """Every generation of the tenant is `destroyed`: it has no live generation."""
        for status in ("live", "retiring", "pending"):
            self._set_status(tenant, status, "destroyed")

    def _set_status(self, tenant: str, before: str, after: str) -> None:
        for (owner, _salt), row in self.twin._generations.items():  # noqa: SLF001 — the in-memory twin's rows
            if owner == tenant and row.status == before:
                row.status = after


def claims_of_payload(payload: bytes) -> dict[str, Any]:
    """The claims a signer was asked to sign: JSON, or base64url of JSON."""
    try:
        return json.loads(payload)
    except ValueError:
        return json.loads(base64.urlsafe_b64decode(payload + b"=" * (-len(payload) % 4)))


def grant_of(claims: Mapping[str, Any]) -> list[tuple[str, str]]:
    return sorted((str(s), str(m)) for s, m in claims["grant"])


class Tap:
    """An ASGI wrapper that records every `Authorization` header value the proxy is sent and
    each request body (`bodies`: the adapter's call, `timeout_sec` included), and answers
    `H.GAUGE_PATH` with the worker threads lent out. It forwards the rest unchanged."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.tokens: list[str] = []
        self.bodies: list[bytes] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["path"] == H.GAUGE_PATH:
            return await H.answer_gauge(send, {"borrowed": H.borrowed_threads()})
        for key, value in scope["headers"]:
            if key == b"authorization":
                self.tokens.append(value.decode().removeprefix("Bearer "))
        chunks: list[bytes] = []

        async def tapped() -> Any:
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body", b""))
                if not message.get("more_body"):
                    self.bodies.append(b"".join(chunks))
            return message

        await self.app(scope, tapped, send)


@contextlib.contextmanager
def proxy_for(t: PublishedTenant, store: Any, **deps_kw: Any) -> Iterator[tuple[str, Tap]]:
    """The real proxy over `t`'s exports, served on loopback: yields its address and a `Tap`."""
    from defender.tests.integrations.credential_proxy_1163._target import proxy

    tap = Tap(proxy().create_app(T.deps({t.tenant_id: T.exports_of(t)}, store, **deps_kw)))
    with H.serve_asgi(tap) as url:
        yield url, tap


def ctx_for(tmp_path: Path, record: Any, proxy_url: str | None, token: str | None, *,
            env: Mapping[str, str] | None = None, **kw: Any) -> VerbContext:
    return VerbContext(defender_dir=DEFENDER, run_dir=tmp_path / "run", env=dict(env or {}),
                       tenant=record, proxy_url=proxy_url, request_token=token, **kw)


#: Calls whose first string argument names a field: `d.get("f")`, `d.pop("f")`, `getattr(o, "f")`.
_FIELD_ACCESSORS = {"get", "pop", "setdefault", "getattr", "hasattr", "setattr"}


def _str_key(node: ast.AST | None) -> set[str]:
    return {node.value} if isinstance(node, ast.Constant) and isinstance(node.value, str) else set()


def _field_of(node: ast.AST) -> set[str]:
    """The names one AST node uses as fields (see `field_names`)."""
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, (ast.arg, ast.keyword)):
        return {node.arg} if node.arg else set()
    if isinstance(node, ast.alias):
        return {node.name.rsplit(".", 1)[-1]}
    if isinstance(node, ast.Dict):
        return set().union(*(_str_key(k) for k in node.keys))
    if isinstance(node, ast.Subscript):
        return _str_key(node.slice)
    if isinstance(node, ast.Call):
        func = node.func
        called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if called in _FIELD_ACCESSORS and node.args:
            by_attr = called in ("getattr", "hasattr", "setattr") and len(node.args) > 1
            return _str_key(node.args[1] if by_attr else node.args[0])
    return set()


def field_names(source: str) -> set[str]:
    """Every name `source` uses as a field: identifiers, attributes, parameter and keyword names,
    dict-literal keys, subscript keys and the key of a `.get(...)`-style access. A string that
    is only a value (a message) is not one."""
    return set().union(*(_field_of(n) for n in ast.walk(ast.parse(source))))


def code_names(path: Path) -> set[str]:
    """The field names (`field_names`) of the module at `path`."""
    return field_names(path.read_text(encoding="utf-8"))


#: What an adapter must not name: the declared credential field names and the accessors that
#: would read a stored set. `password` is left out: the Elastic adapter's own container password
#: is the one credential that stays (H2).
CREDENTIAL_NAME = re.compile(
    r"api_key|apikey|client_secret|client_id|access_token|secret_id|credential",
    re.IGNORECASE)


def text_of(*roots: Path) -> str:
    """Every regular file under each root (de-duplicated), decoded leniently and joined."""
    seen: set[Path] = set()
    parts = []
    for root in roots:
        for path in sorted(Path(root).rglob("*")):
            real = path.resolve()
            if path.is_file() and not path.is_symlink() and real not in seen:
                seen.add(real)
                parts.append(path.read_bytes().decode("utf-8", "replace"))
    return "\n".join(parts)
