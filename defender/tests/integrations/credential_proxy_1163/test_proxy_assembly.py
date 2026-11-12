"""#1163 the shipped proxy assembled from operator configuration (A13): the real OpenBao store and
transit verifier, the tenants' exports untouched, the file audit sink. Observed by behaviour."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.integrations.credential_proxy_1163._target import (
    app_from_config,
    proxy,
    secrets_writer,
)

pytestmark = pytest.mark.openbao


def _tree(root: Path) -> dict[str, str]:
    """Every file under `root` and a digest of its content."""
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def test_g1_the_assembled_proxy_reads_real_openbao_leaves_exports_alone_and_audits_to_a_file(
        tmp_path, data_root, openbao, migrated_database):  # noqa: F811
    """Built from operator config alone (the read-only records login's DSN, no tenant list) before the tenant exists, a
    request is verified by transit and sent with the stored key, a crossed-key token is refused,
    exports are unchanged and each request is a JSON line in the audit file. A13, O9, A11, A26."""
    audit_path = tmp_path / "audit" / "proxy.jsonl"
    audit_path.parent.mkdir()
    audit_path.write_text('{"earlier": true}\n', encoding="utf-8")
    policies = proxy().store_policies(kv_mount=openbao.kv_mount)
    tokens = {role: openbao.token_for(openbao.apply_policy(role, hcl))
              for role, hcl in policies.items()}
    login = contextlib.ExitStack()
    records_dsn = login.enter_context(R.proxy_login(migrated_database))  # #1366: `records_dsn` replaces `data_root`
    app = app_from_config({
        "openbao_token": tokens["proxy"], "kv_mount": openbao.kv_mount,
        "records_dsn": records_dsn, "audit_path": str(audit_path)}, addr=openbao.addr)
    client = TestClient(app)
    tid, stranger = openbao.tenant(), openbao.tenant()  # both keys exist; neither is in any config
    with H.upstream() as up, T.identity_via_proxy(
            tmp_path / "forge", data_root, H.declaration(up.url + T.BASE_PATH),
            tenant_id=tid) as t, login:
        register_tenant(migrated_database, tid, data_root=t.data_root)  # records: the published identity declaration
        asyncio.run(secrets_writer().OpenBaoSecrets(
            addr=openbao.addr, token=tokens["writer"], mount=openbao.kv_mount
        ).put_credentials(tid, "identity", "static", {"api_key": H.CANARY_KEY}, generation=1))
        exports = T.exports_of(t)
        before = _tree(exports)
        url, grant = f"{up.url}{T.BASE_PATH}/users/x", {("identity", "r")}
        good = T.ask(client, T.token(tid, grant, signer=openbao.signer(tid)),
                     "identity", "GET", url)
        crossed = T.ask(client, T.token(tid, grant, signer=openbao.signer(stranger)),
                        "identity", "GET", url)
        after = _tree(exports)

    assert (good["fault"], crossed["fault"]) == (None, "ConfigFault")
    assert [s.header("Authorization") for s in up.seen] == [f"Bearer {H.CANARY_KEY}"]
    assert after == before
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == '{"earlier": true}'
    records = [json.loads(line) for line in lines[1:]]
    assert [(r["tenant"], r["system"], r["outcome"]) for r in records[:1]] == [
        (tid, "identity", "sent 200")]
    assert len(records) == 2
    assert records[1]["outcome"] == "ConfigFault", "the crossed-key refusal is audited as such"
    assert H.CANARY_KEY not in "\n".join(lines)
