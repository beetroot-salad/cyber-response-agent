"""#1470 G4/D9: how the API starts with its secret store (OpenBao) and what the routes say while it is sealed.

`serving` takes an OpenBao transport as it takes Keycloak's; the real `OpenBaoSecrets` runs over `ScriptedOpenBao`, which
scripts seal-status too. A missing or unparsable OpenBao setting refuses start like any other setting
(`test_1083_program`, which sweeps `SETTING_NAMES`). Postgres-gated."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from defender.tests.support.api._config1470 import (
    TICKET,
    TOKEN,
    problem_text,
    served_config,
)
from defender.tests.support.api._openbao1470 import ScriptedOpenBao
from defender.tests.support.api._server1083 import FakeKeycloak, environment

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

SEAL_STATUS = ("GET", "sys/seal-status")


async def _start(dsn: str, tmp_path: Path, bao: ScriptedOpenBao) -> str | None:
    """Start in-process; None if it started (and stopped), else the refusal's message."""
    from defender.api_server import Settings, StartRefused, serving

    try:
        async with serving(Settings.from_environ(environment(tmp_path, dsn=dsn)), transport=FakeKeycloak(),
                           openbao_transport=bao):
            return None
    except StartRefused as refused:
        return str(refused)


_BROKEN_SEAL_STATUS = [
    ("unreachable", httpx.ConnectError("refused")),
    ("timing out", httpx.ReadTimeout("slow")),
    ("not JSON", httpx.Response(200, content=b"<html>proxy error</html>")),
    ("a list", httpx.Response(200, json=[])),
    ("with no sealed field", httpx.Response(200, json={"initialized": True})),
    ("with a sealed field that is not a boolean", httpx.Response(200, json={"initialized": True, "sealed": "no"})),
    ("an error status", httpx.Response(500, json={"errors": ["boom"]})),
]


@pytest.mark.parametrize(("label", "answer"), _BROKEN_SEAL_STATUS, ids=[b[0] for b in _BROKEN_SEAL_STATUS])
async def test_d9_a_seal_status_that_is_unreachable_or_malformed_refuses_start_naming_the_secret_store(migrated_database, tmp_path, label, answer):
    """Seal-status unreachable, or an answer that is not `{"sealed": <bool>}`: start is refused naming the OpenBao
    address, and nothing past that read is asked of it; the same environment healthy starts (control). (D9, G4)"""
    healthy = ScriptedOpenBao()
    assert await _start(migrated_database, tmp_path, healthy) is None
    broken = ScriptedOpenBao()
    broken.seal_status = answer
    message = await _start(migrated_database, tmp_path, broken)
    assert message is not None, f"{label} started"
    assert "DEFENDER_OPENBAO_ADDR" in message or "127.0.0.1:1" in message, message
    assert broken.calls == [SEAL_STATUS]


async def test_g4_an_unsealed_secret_store_is_asked_the_login_by_a_metadata_read_and_nothing_is_written(migrated_database, tmp_path):
    """Unsealed: seal-status first, then only metadata reads (the writer policy cannot look itself up or read a value);
    no set is written or read. (G4)"""
    bao = ScriptedOpenBao()
    assert await _start(migrated_database, tmp_path, bao) is None
    assert bao.calls[0] == SEAL_STATUS
    assert len(bao.calls) >= 2
    assert {(m, p.split("/")[1]) for m, p in bao.calls[1:]} == {("GET", "metadata")}, bao.calls
    assert bao.paths() == []
    assert bao.value_reads == []


async def test_g4_a_login_the_secret_store_refuses_at_start_refuses_start_naming_the_token_file_setting(migrated_database, tmp_path):
    """Unsealed, and the token the file holds is refused (403): start is refused naming DEFENDER_API_OPENBAO_TOKEN_FILE. (G4)"""
    message = await _start(migrated_database, tmp_path, ScriptedOpenBao(token="a-token-the-server-does-not-know"))
    assert message is not None
    assert "DEFENDER_API_OPENBAO_TOKEN_FILE" in message, message
    assert TOKEN not in message


async def test_g4_a_sealed_secret_store_starts_the_api_and_the_routes_that_need_it_answer_503_until_it_is_unsealed(migrated_database, tmp_path):
    """Sealed at start: the API starts having asked only seal-status; system reads, replacing writes and credential
    writes are 503 naming the sealed store; records, the catalog and a create still answer; unsealed, each request asks
    again and the same app serves. (G4, D9, O3, O7)"""
    bao = ScriptedOpenBao()
    bao.sealed = True
    async with served_config(migrated_database, tmp_path, scripted=bao, keep_calls=True) as served:
        assert bao.calls == [SEAL_STATUS]
        assert (await served.get("/adapters")).status_code == 200
        assert (await served.put_system(TICKET, 0)).status_code == 201  # a create reads no secret store
        for refused in (await served.get_system(TICKET), await served.list_systems(), await served.put_system(TICKET, 1),
                        await served.put_credentials(TICKET, 1, {"api_key": TOKEN})):
            assert refused.status_code == 503, refused.text
            assert "sealed" in problem_text(refused).lower()
        assert [v.version for v in served.versions(TICKET)] == [1]
        assert served.stored_generations(TICKET) == []
        bao.sealed = False
        assert (await served.get_system(TICKET)).status_code == 200
        assert (await served.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204
        assert (await served.get_system(TICKET)).json()["has_credentials"] is True


def test_d9_the_command_refuses_an_unreachable_secret_store_in_one_line_without_a_traceback(migrated_database, tmp_path, capsys):
    """`run` over an OpenBao whose seal-status cannot be read: exit 1, one stderr line naming it, no traceback. (D9, Am-3)"""
    from defender.api_server import run

    bao = ScriptedOpenBao()
    bao.seal_status = httpx.ConnectError("refused")
    assert run(environment(tmp_path, dsn=migrated_database), transport=FakeKeycloak(), openbao_transport=bao) == 1
    stderr = capsys.readouterr().err
    assert stderr.count("\n") == 1
    assert "Traceback" not in stderr, stderr
    assert "DEFENDER_OPENBAO_ADDR" in stderr or "127.0.0.1:1" in stderr, stderr
