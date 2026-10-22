"""#1108 P4 slice S-D — A-ID (the drain logs in to OpenBao itself, AppRole), O8's drain half (issuer
login material only in host-side delivery processes: never in a box, a run's environment or any
env var; the client config passed by path and lying under no box mount source), and O9's
"missing issuer config refuses before any model call".

The login is one symbol (orchestrator decision OD4):
    defender.learning.author.version_control.issuer_login(tenant, *, issuer_config: Path)
        -> ForgejoIdentity
It reads the issuer client config FILE and the tenant row's `forge` binding (`{origin, audience,
issuer_role}`, written here with S0's `bind_forge`) and logs in.

ASSUMED SEAM (an extension of OD4, reported): `issuer_login(..., transport=None)` — the
`httpx` transport its OpenBao client sends through (production: none, a real TLS connection
trusting the config's CA). The drain forwards it as `author_drain(..., issuer_transport=)`.

ASSUMED SHAPE (the design fixes only the folder `<repo>/playground-issuer/client/` and the
contents "issuer URL, CA cert, AppRole role_id/secret_id"): a JSON file
    {"issuer": "https://<host>[:port]", "ca_cert": "<path to a PEM>",
     "role_id": "...", "secret_id": "..."}
named `issuer.json` here (S-F's gitignore probe spells the same name). `issuer` is OpenBao's
address; the identity endpoint is `<issuer>/v1/identity/oidc` (OpenBao's own path).

The issuer fake: P3's `VaultHTTP` answers only the identity-token GET and accepts any caller.
`AppRoleVault` below adds OpenBao's AppRole login as the API documents it (`POST
/v1/auth/approle/login` with `{role_id, secret_id}` -> `{auth: {client_token}}`; a bad pair is
`400`) and requires that client token (`X-Vault-Token`) on the identity-token request (else
`403`). It records every request; it decides nothing about the drain. S0/P3 are asked to adopt
it next to `VaultHTTP`.
"""
from __future__ import annotations

import importlib
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

import certifi
import httpx
import pytest

from defender._git import REPO_ROOT
from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.tenancy.tenant_1108_delivery._identity import ISSUER, VaultHTTP
from defender.tests.tenancy.tenant_1108_delivery._identity import token as issuer_token
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, bind_forge, unbind_forge
from defender.tests.tenancy.tenant_1108_p4.test_drains import (
    LESSON_NAME,
    BoxSpy,
    CuratorTrigger,
    author_drain,
    critical_text,
    drain_paths,
    product_repo,
    queue,
    remote_branches,
    under,
)

#: OpenBao's address as the issuer fake serves it (its identity endpoint is `ISSUER`).
ADDRESS = ISSUER.split("/v1/", 1)[0]
LOGIN_PATH = "/v1/auth/approle/login"
ROLE_ID = "p4-role-id-5a1c"
SECRET_ID = "p4-secret-id-9e7f3b"
CLIENT_TOKEN = "hvs.p4-client-token-0d2a"
#: The dev issuer client config folder the design names (O8): under the repo, outside `defender/`.
DEV_CLIENT_DIR = REPO_ROOT / "playground-issuer" / "client"


def vc() -> Any:
    return importlib.import_module("defender.learning.author.version_control")


class AppRoleVault(VaultHTTP):
    """P3's issuer fake plus OpenBao's AppRole login (see the module doc). Tokens are minted at
    the real clock (`now`), as a production identity checks them against `time.time()`."""

    def __init__(self, tenant: str, *, role_id: str = ROLE_ID, secret_id: str = SECRET_ID) -> None:
        super().__init__(tenant, now=int(time.time()))
        self.role_id, self.secret_id = role_id, secret_id
        self.transport = httpx.MockTransport(self.reply)

    def reply(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == LOGIN_PATH:
            self.calls.append(request)
            try:
                body = json.loads(request.content or b"{}")
            except ValueError:
                body = None
            if request.method != "POST" or body != {"role_id": self.role_id,
                                                    "secret_id": self.secret_id}:
                return httpx.Response(400, json={"errors": ["invalid role or secret ID"]})
            return httpx.Response(200, json={"auth": {
                "client_token": CLIENT_TOKEN, "lease_duration": 600, "renewable": True}})
        if request.headers.get("X-Vault-Token") != CLIENT_TOKEN:
            self.calls.append(request)
            return httpx.Response(403, json={"errors": ["permission denied"]})
        return super().reply(request)

    def logins(self) -> list[dict]:
        return [json.loads(r.content) for r in self.calls if r.url.path == LOGIN_PATH]

    def token_requests(self) -> list[httpx.Request]:
        return [r for r in self.calls if r.url.path != LOGIN_PATH]

    def minted(self) -> str:
        return issuer_token(self.tenant, issued=self.now)


def write_issuer_config(folder: Path, **overrides: Any) -> Path:
    """The issuer client config file (assumed shape, module doc) in `folder`, with a real PEM
    bundle as its CA (certifi's), so building a CA-trusting client from it succeeds."""
    folder.mkdir(parents=True, exist_ok=True)
    ca = folder / "ca.pem"
    shutil.copyfile(certifi.where(), ca)
    doc = {"issuer": ADDRESS, "ca_cert": str(ca), "role_id": ROLE_ID, "secret_id": SECRET_ID,
           **overrides}
    path = folder / "issuer.json"
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


def _login(t: Any, config: Path, vault: AppRoleVault) -> Any:
    return vc().issuer_login(t.tenant, issuer_config=config, transport=vault.transport)


# ---------------------------------------------------------------------------------------------
# A-ID: issuer_login
# ---------------------------------------------------------------------------------------------


def test_a_id_issuer_login_logs_in_with_approle_and_mints_the_bound_tenant_token(p4_tenant, tmp_path):
    """A-ID: the login sends the config file's AppRole `role_id`/`secret_id` to OpenBao's login
    endpoint, then asks the identity endpoint for the binding's role with the client token it got;
    the identity it returns is bound to this tenant, the binding's audience and role, and hands
    back the token the issuer minted."""
    t = p4_tenant
    binding = bind_forge(t)
    vault = AppRoleVault(t.tenant_id)
    config = write_issuer_config(tmp_path / "client")

    identity = _login(t, config, vault)
    token = identity.token()

    assert vault.logins() == [{"role_id": ROLE_ID, "secret_id": SECRET_ID}]
    assert [str(r.url) for r in vault.token_requests()] == [
        f"{ISSUER}/token/{binding['issuer_role']}"]
    assert vault.token_requests()[0].headers["X-Vault-Token"] == CLIENT_TOKEN
    assert token == vault.minted()
    assert (identity.tenant_id, identity.role, identity.audience, identity.issuer) == (
        t.tenant_id, binding["issuer_role"], binding["audience"], ISSUER)


def test_a_id_a_refused_approle_login_is_a_refusal_that_never_echoes_the_secret(p4_tenant, tmp_path):
    """A-ID: a `secret_id` OpenBao refuses is a refusal (an auth error), never a token, and its
    text carries neither the `secret_id` nor the `role_id`. Positive control: the same login
    with the right pair succeeds (previous case)."""
    t = p4_tenant
    bind_forge(t)
    vault = AppRoleVault(t.tenant_id)
    config = write_issuer_config(tmp_path / "client", secret_id="p4-wrong-secret-7c41")

    with pytest.raises((vc().ForgejoAuthError, vc().DeliveryRefused)) as refused:
        _login(t, config, vault).token()

    assert vault.logins() == [{"role_id": ROLE_ID, "secret_id": "p4-wrong-secret-7c41"}]
    assert vault.token_requests() == []
    assert "p4-wrong-secret-7c41" not in str(refused.value)
    assert ROLE_ID not in str(refused.value)


@pytest.mark.parametrize("missing", ["config", "binding"])
def test_o9_a_missing_issuer_config_or_forge_binding_refuses_the_login_before_any_request(
        p4_tenant, tmp_path, missing):
    """O9/O-STALE misconfiguration: no issuer client config file, or no forge binding in the
    tenant row, is decidable locally: the login refuses before any request reaches the issuer,
    naming what is missing. (Control: the first case logs in over the same fake.)"""
    t = p4_tenant
    vault = AppRoleVault(t.tenant_id)
    config = write_issuer_config(tmp_path / "client")
    if missing == "config":
        bind_forge(t)
        config.unlink()
    else:
        unbind_forge(t)

    with pytest.raises((vc().ForgejoAuthError, vc().DeliveryRefused)) as refused:
        _login(t, config, vault)

    assert vault.calls == []
    said = str(refused.value).lower()
    assert ("issuer" in said and "config" in said) if missing == "config" else "forge" in said, said


# ---------------------------------------------------------------------------------------------
# The drain logs in itself; O8 drain half
# ---------------------------------------------------------------------------------------------


def test_a_id_o8_the_drain_logs_in_from_the_config_path_and_hands_no_login_material_to_the_box(
        p4_tenant, tmp_path, monkeypatch, caplog):
    """A-ID + O8 (drain half): given only the issuer client config's PATH (no identity), the
    drain logs in with AppRole itself, and its push and PR reach the tenant origin with the
    minted token. The login material never leaves the host process: the batch box's request
    carries no `role_id`, `secret_id`, client token or forge token in its environment, mounts
    no folder holding the config file, and no environment variable of the drain process holds
    any of them while the model step runs. Positive controls on the same channels: the box's
    environment does carry `DEFENDER_AGENT_DIR`; the containment check flags a config under the
    code mount; the env scan sees a variable set the same way."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    t = p4_tenant
    bind_forge(t)
    vault = AppRoleVault(t.tenant_id)
    t.server.token = vault.minted()  # the origin accepts what this issuer mints
    config = write_issuer_config(tmp_path / "playground-issuer" / "client")
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    secrets = (ROLE_ID, SECRET_ID, CLIENT_TOKEN, vault.minted())
    env_seen: list[dict] = []
    curator = S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")},
                            also=lambda *_a: env_seen.append(dict(os.environ)))
    trigger, box = CuratorTrigger(author=curator), BoxSpy()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box, issuer_config=config,
                          issuer_transport=vault.transport)

    assert rc == 0, critical_text(caplog)
    assert vault.logins() == [{"role_id": ROLE_ID, "secret_id": SECRET_ID}]
    (branch, _tip), = remote_branches(t.remote).items()
    assert [c["head"] for c in t.forge.creates] == [branch]
    assert t.server.authorizations
    assert all(a is None or vault.minted() in a for a in t.server.authorizations)
    # The box: no login material in its environment, no mount over the config.
    (request,) = box.requests
    assert "DEFENDER_AGENT_DIR" in request.env, "control: the box environment is read"
    leaked = [(k, s) for k, v in request.env.items() for s in secrets if s in str(v)]
    assert leaked == [], leaked
    sources = [Path(m.source) for m in request.mounts]
    assert not [s for s in sources if under(config, s)], sources
    assert under(DEFENDER / "x" / "issuer.json", DEFENDER), "control: containment is detected"
    # The drain process's environment while the model step ran.
    assert env_seen, "the model step never ran"
    leaked_env = [k for env in env_seen for k, v in env.items() for s in secrets if s in v]
    assert leaked_env == [], leaked_env
    monkeypatch.setenv("P4_CONTROL_PROBE", SECRET_ID)
    assert [k for k, v in os.environ.items() if SECRET_ID in v] == ["P4_CONTROL_PROBE"]


def test_o9_a_drain_with_no_issuer_config_refuses_before_any_model_call(
        p4_tenant, tmp_path, monkeypatch, caplog):
    """O9: a drain given an issuer config path that holds no file refuses at once — exit 2, the
    refusal logged naming the issuer config — with no request to the issuer or the forge and no
    draft, box or curator. (Control: the previous case, same seams, a config present.)"""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    t = p4_tenant
    bind_forge(t)
    vault = AppRoleVault(t.tenant_id)
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    trigger, box = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})), BoxSpy()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box,
                          issuer_config=tmp_path / "playground-issuer" / "client" / "issuer.json",
                          issuer_transport=vault.transport)

    assert rc == 2
    said = critical_text(caplog).lower()
    assert "issuer" in said, said
    assert "config" in said, said
    assert vault.calls == []
    assert t.forge.requests == []
    assert trigger.calls == []
    assert box.requests == []
    assert remote_branches(t.remote) == {}


def test_o8_the_dev_issuer_client_config_lies_under_no_drain_box_mount_source(p4_tenant):
    """O8: the dev issuer client config folder (`<repo>/playground-issuer/client/`) lies under no
    mount source of a drain box (P3's real `Batch.box_request()` over this checkout's
    `defender/`): neither the code mount nor the draft. Positive control: the same check flags a
    path under the code mount."""
    t = p4_tenant
    batch = t.open_delivery().start_batch("o8-mounts", lanes=("lessons",))
    try:
        sources = [Path(m.source) for m in batch.box_request().mounts]
        assert any(under(DEFENDER, s) for s in sources), "control: the code mount is listed"
        assert [s for s in sources if under(DEV_CLIENT_DIR, s)] == [], sources
        assert under(DEFENDER / "playground-issuer" / "client", DEFENDER), "control"
    finally:
        batch.discard()
