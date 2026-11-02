# ruff: noqa: PT018
"""#1214 DC-13 / r9 pin: the AppRole secret is never sent in cleartext. `test_r6_an_http_issuer_is_refused_before_any_request`
varies only the OpenBao address; here the OpenBao address is https and the ISSUER URL is the cleartext one."""
from __future__ import annotations

import contextlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from defender.tests.support.tenancy._active1214 import generation_fields

SECRET_ID = "atk2-secret-id-4d2a"


def _credential(t: Any, tmp_path: Path, *, issuer_url: str, openbao_url: str, transport: Any) -> Any:
    from defender.learning.author.version_control import forge_credential

    fields = generation_fields(t.tenant_id, tmp_path / "secrets")
    fields["host_secret_file"].parent.mkdir(parents=True, exist_ok=True)
    fields["host_secret_file"].write_text(SECRET_ID + "\n", encoding="utf-8")
    config = SimpleNamespace(issuer_url=issuer_url, openbao_url=openbao_url, ca_cert=None)
    return forge_credential(t.tenant_id, "drain", directory=t.directory_with(generations=[fields]), config=config,
                            transport=transport)


@pytest.mark.parametrize(("issuer", "openbao", "refused"), [
    ("http://openbao.test:8200/v1/identity/oidc", "https://openbao.test", True),
    ("https://openbao.test/v1/identity/oidc", "http://openbao.test", True),
    ("https://openbao.test/v1/identity/oidc", "https://openbao.test", False)], ids=["http issuer", "http openbao", "control"])
def test_a_cleartext_issuer_url_is_refused_before_any_request_even_when_the_openbao_address_is_https(
        p4_tenant, tmp_path, issuer, openbao, refused):
    """The issuer URL and the OpenBao address are each checked for https before the secret is read, let alone sent."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.content.decode())
        return httpx.Response(200, json={"auth": {"client_token": "tok"}})

    credential = _credential(p4_tenant, tmp_path, issuer_url=issuer, openbao_url=openbao,
                             transport=httpx.MockTransport(handler))
    with contextlib.suppress(Exception):  # the fake answers no JWT; what matters is whether the login was sent
        credential.token()
    if refused:
        assert seen == [], f"the AppRole secret was POSTed with a cleartext address: {seen}"
    else:
        assert seen and SECRET_ID in seen[0], "control: with both addresses https the login request is made"
