"""#1163 the shipped proxy assembled from operator configuration (A13): the real OpenBao store and
transit verifier, the tenants' exports untouched, the file audit sink. Observed by behaviour."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import (
    proxy,
    secrets_writer,
)

pytestmark = pytest.mark.openbao

OTHER = "9d4e1163-0f6a-4b7c-8e2d-1a3b5c7d9e0f"


def _tree(root: Path) -> dict[str, str]:
    """Every file under `root` and a digest of its content."""
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def test_g1_the_assembled_proxy_reads_real_openbao_leaves_exports_alone_and_audits_to_a_file(
        tmp_path, data_root, openbao):
    """Built from operator config alone, a request is verified by transit and sent with the
    stored key, a crossed-key token is refused, exports are unchanged and each request is a JSON
    line in the audit file. A13, O9, A11."""
    audit_path = tmp_path / "audit" / "proxy.jsonl"
    audit_path.parent.mkdir()
    audit_path.write_text('{"earlier": true}\n', encoding="utf-8")
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH)) as t:
        policies = proxy().store_policies(
            kv_mount=openbao.kv_mount, transit_mount=openbao.transit_mount,
            tenant_keys={t.tenant_id: proxy().transit_key_for(t.tenant_id),
                      OTHER: proxy().transit_key_for(OTHER)})
        tokens = {role: openbao.token_for(openbao.apply_policy(role, hcl))
                  for role, hcl in policies.items()}
        for key in (proxy().transit_key_for(t.tenant_id), proxy().transit_key_for(OTHER)):
            openbao.ok("POST", f"{openbao.transit_mount}/keys/{key}", json={"type": "ed25519"})
        asyncio.run(secrets_writer().OpenBaoSecrets(
            addr=openbao.addr, token=tokens["writer"], mount=openbao.kv_mount
        ).put_credentials(t.tenant_id, "identity", "static", {"api_key": H.CANARY_KEY}))
        signer = {tenant: proxy().TransitSigner(
            addr=openbao.addr, token=tokens[f"launcher-{tenant}"], mount=openbao.transit_mount,
            key=key) for tenant, key in ((t.tenant_id, proxy().transit_key_for(t.tenant_id)),
                         (OTHER, proxy().transit_key_for(OTHER)))}
        exports = T.exports_of(t)
        before = _tree(exports)

        app = proxy().create_app_from_config({
            "openbao_addr": openbao.addr, "openbao_token": tokens["proxy"],
            "kv_mount": openbao.kv_mount, "transit_mount": openbao.transit_mount,
            "tenant_keys": {t.tenant_id: proxy().transit_key_for(t.tenant_id),
                      OTHER: proxy().transit_key_for(OTHER)},
            "tenant_exports": {t.tenant_id: str(exports)}, "audit_path": str(audit_path)})
        client = TestClient(app)
        url, grant = f"{up.url}{T.BASE_PATH}/users/x", {("identity", "r")}
        good = T.ask(client, T.token(t.tenant_id, grant, signer=signer[t.tenant_id]),
                     "identity", "GET", url)
        crossed = T.ask(client, T.token(t.tenant_id, grant, signer=signer[OTHER]),
                        "identity", "GET", url)
        after = _tree(exports)

    assert (good["fault"], crossed["fault"]) == (None, "ConfigFault")
    assert [s.header("Authorization") for s in up.seen] == [f"Bearer {H.CANARY_KEY}"]
    assert after == before
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == '{"earlier": true}'
    records = [json.loads(line) for line in lines[1:]]
    assert [(r["tenant"], r["system"], r["outcome"]) for r in records[:1]] == [
        (t.tenant_id, "identity", "sent 200")]
    assert len(records) == 2
    assert H.CANARY_KEY not in "\n".join(lines)
