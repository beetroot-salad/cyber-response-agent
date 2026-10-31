"""#1163 adapter and run side: helpers for the flows from the adapter to the proxy and for the
run-start tokens. Plants data, records and decodes; nothing here judges what the code under test
must do.

Names this module chooses (the contract's seams, listed in the contract map):
- `VerbContext.proxy_url` and `VerbContext.request_token`: the proxy's address and the request token,
  carried on the call's context (A9: the address is operator configuration handed in by the run,
  never read by an adapter from the model-visible `ctx.env`).
- `run.main(signer=, proxy_url=)`: the operator's seams at the run process.
- The ticket writer's legs take `request_token=` and `proxy_url=` keywords.
"""
from __future__ import annotations

import ast
import base64
import contextlib
import json
import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from defender.systems.verbs import VerbContext
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, PublishedTenant, published_tenant

#: A signature no honest token can lose: a census looks for it in every channel.
SIGNATURE_CANARY = "CANARY-REQUEST-SIGNATURE-1163"

#: The operator's address variable at the run process. Set here only as a decoy in model-visible
#: environments; the contract does not say which variable an operator uses.
DECOY_PROXY_ENV = "DEFENDER_CREDENTIAL_PROXY_URL"


def prefix_of(system: str) -> str:
    return system.upper().replace("-", "_")


def env_text(system: str, *, extra: str = "") -> str:
    """`system`'s config.env on `http-proxy`: an access method and a timeout, no base, no bastion."""
    p = prefix_of(system)
    return f'{p}_TRANSPORT="http-proxy"\n{p}_TIMEOUT_SEC="5"\n{extra}'


def system_files(system: str, decl: str, *, env_extra: str = "") -> dict[str, str]:
    return H.access_files(system, decl, env=env_text(system, extra=env_extra))


@contextlib.contextmanager
def published(scratch: Path, root: Path, systems: Mapping[str, str],
              **kw: Any) -> Iterator[PublishedTenant]:
    """The fixture tenant published once with every `{system: declaration}` of `systems` on
    `http-proxy`."""
    files: dict[str, str] = {}
    for system, decl in systems.items():
        files.update(system_files(system, decl))
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


def claims_of_payload(payload: bytes) -> dict[str, Any]:
    """The claims a signer was asked to sign: JSON, or base64url of JSON."""
    try:
        return json.loads(payload)
    except ValueError:
        return json.loads(base64.urlsafe_b64decode(payload + b"=" * (-len(payload) % 4)))


def grant_of(claims: Mapping[str, Any]) -> list[tuple[str, str]]:
    return sorted((str(s), str(m)) for s, m in claims["grant"])


class Tap:
    """An ASGI wrapper that records every `Authorization` header value the proxy is sent. It
    forwards unchanged and decides nothing."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.tokens: list[str] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            for key, value in scope["headers"]:
                if key == b"authorization":
                    self.tokens.append(value.decode().removeprefix("Bearer "))
        await self.app(scope, receive, send)


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


def _docstring_ids(tree: ast.Module) -> set[int]:
    """The `id` of every docstring constant in `tree`: module, function and class level."""
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(
                    getattr(body[0], "value", None), ast.Constant):
                docstrings.add(id(body[0].value))
    return docstrings


def code_names(path: Path) -> set[str]:
    """Every identifier, attribute and string constant in the module at `path`, docstrings
    excluded: what the code can reach by name."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = _docstring_ids(tree)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.alias):
            names.add(node.name.rsplit(".", 1)[-1])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and id(node) not in docstrings:
            names.add(node.value)
    return names


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
