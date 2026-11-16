"""#1470 G4/D9, #1532 K1-K3: how the API starts with its secret store (OpenBao) and what the routes say while it is sealed.

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
from defender.tests.support.api._openbao1470 import LOOKUP_SELF, ScriptedOpenBao
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
    assert set(broken.calls) == {SEAL_STATUS}  # nothing past seal-status; how often it is asked is not pinned


async def test_g4_an_unsealed_secret_store_is_asked_who_the_token_is_then_a_metadata_read_and_nothing_is_written(
        migrated_database, tmp_path):
    """Unsealed: seal-status first, then the token's lookup-self, then only metadata reads (the writer policy reads no
    value); no set is written or read. (G4; #1532 K1, K2)"""
    bao = ScriptedOpenBao()
    assert await _start(migrated_database, tmp_path, bao) is None
    assert bao.calls[:2] == [SEAL_STATUS, ("GET", LOOKUP_SELF)], bao.calls
    assert len(bao.calls) >= 3
    assert {(m, p.split("/")[1]) for m, p in bao.calls[2:]} == {("GET", "metadata")}, bao.calls
    assert bao.paths() == []
    assert bao.value_reads == []


#: Tokens OpenBao refuses lookup-self (#1532 K1): unknown at this address, or holding no policy that grants it. Each is
#: minted without OpenBao's default policy, as the API's is.
_NOT_ACCEPTED = [
    ("a token the server does not know", {"token": "a-token-the-server-does-not-know"}),
    ("a writer policy from before #1532", {"policies": ["writer-pre-1532"]}),
    ("the proxy's token", {"policies": ["proxy"]}),
    ("a token whose policy does not exist", {"policies": []}),
]


@pytest.mark.parametrize(("label", "made"), _NOT_ACCEPTED, ids=[n[0] for n in _NOT_ACCEPTED])
async def test_1532_k1_a_token_refused_its_lookup_refuses_start_naming_the_address_and_the_token_file(
        migrated_database, tmp_path, label, made):
    """A 403 on lookup-self: start is refused naming both DEFENDER_OPENBAO_ADDR and DEFENDER_API_OPENBAO_TOKEN_FILE (the
    token is not accepted at that address: either can be wrong), and the token's policy granting lookup-self; no metadata
    is read. (#1532 K1, P1)"""
    bao = ScriptedOpenBao(**made)
    message = await _start(migrated_database, tmp_path, bao)
    assert message is not None, f"{label} started"
    for named in ("DEFENDER_OPENBAO_ADDR", "DEFENDER_API_OPENBAO_TOKEN_FILE", "lookup-self"):
        assert named in message, message
    assert TOKEN not in message
    assert "refused the token the file holds" not in message, message  # states what was refused, not that the token is bad (P1)
    assert ("GET", LOOKUP_SELF) in bao.calls
    assert not [c for c in bao.calls if "/metadata/" in c[1]], bao.calls


#: Tokens OpenBao accepts but whose policy does not let them read metadata under the API's mount (#1532 K2).
_NOT_UNDER_THE_MOUNT = [
    ("a writer policy written for another mount", {"policy_mount": "elsewhere", "mounts": ["secret", "elsewhere"]}),
    ("the proxy's token with the default policy", {"policies": ["default", "proxy"]}),
    ("the default policy alone", {"policies": ["default"]}),
]


@pytest.mark.parametrize(("label", "made"), _NOT_UNDER_THE_MOUNT, ids=[n[0] for n in _NOT_UNDER_THE_MOUNT])
async def test_1532_k2_a_valid_token_refused_the_metadata_read_refuses_start_naming_the_mount_the_policy_and_the_token(
        migrated_database, tmp_path, label, made):
    """lookup-self passes and the metadata read is 403: start is refused naming DEFENDER_OPENBAO_KV_MOUNT (and the mount
    it is set to), the token's policy and DEFENDER_API_OPENBAO_TOKEN_FILE, any of which can be why. (#1532 K2, P1)"""
    message = await _start(migrated_database, tmp_path, ScriptedOpenBao(**made))
    assert message is not None, f"{label} started"
    for named in ("DEFENDER_OPENBAO_KV_MOUNT", "'secret'", "polic", "DEFENDER_API_OPENBAO_TOKEN_FILE"):
        assert named in message, message
    assert "refused the token the file holds" not in message, message  # no one cause claimed (P1)
    assert TOKEN not in message


@pytest.mark.parametrize("policies", [["writer"], ["default", "writer"], ["default", "writer-pre-1532"]],
                         ids=["the writer", "the writer with the default policy",
                              "a writer from before #1532 with the default policy"])
async def test_1532_a_token_that_may_look_itself_up_and_read_metadata_under_the_mount_starts(
        migrated_database, tmp_path, policies):
    """Control for K1 and K2: lookup-self and the mount's metadata granted, by whichever policy, and start proceeds."""
    assert await _start(migrated_database, tmp_path, ScriptedOpenBao(policies=policies)) is None


_UNUSABLE_LOOKUP = [
    ("not JSON", httpx.Response(200, content=b"<html>proxy error</html>")),
    ("no data object", httpx.Response(200, json={"request_id": "x"})),
    ("a refused request", httpx.Response(400, json={"errors": ["bad request"]})),
    ("an error status", httpx.Response(500, json={"errors": ["internal error"]})),
    ("sealed since seal-status", httpx.Response(503, json={"errors": ["Vault is sealed"]})),
    ("unreachable", httpx.ConnectError("refused")),
]


@pytest.mark.parametrize(("label", "answer"), _UNUSABLE_LOOKUP, ids=[u[0] for u in _UNUSABLE_LOOKUP])
async def test_1532_k3_a_lookup_answered_other_than_a_usable_200_or_a_403_refuses_start_naming_the_address_only(
        migrated_database, tmp_path, label, answer):
    """lookup-self answered without a usable answer (not OpenBao's `{"data": {...}}`, a 4xx other than 403, a 5xx,
    sealed, or no answer): start is refused naming DEFENDER_OPENBAO_ADDR, not the token file. (#1532 K3)"""
    bao = ScriptedOpenBao()
    bao.answer("GET", LOOKUP_SELF, answer, times=1)
    message = await _start(migrated_database, tmp_path, bao)
    assert message is not None, f"{label} started"
    assert "DEFENDER_OPENBAO_ADDR" in message, message
    assert "DEFENDER_API_OPENBAO_TOKEN_FILE" not in message, message


_UNREADABLE_LOGIN = [
    ("not JSON", httpx.Response(200, content=b"<html>proxy error</html>")),
    ("no data object", httpx.Response(200, json={"request_id": "x"})),
    ("a refused request", httpx.Response(400, json={"errors": ["bad request"]})),
]


@pytest.mark.parametrize(("label", "answer"), _UNREADABLE_LOGIN, ids=[u[0] for u in _UNREADABLE_LOGIN])
async def test_g4_a_login_check_answered_other_than_a_403_refuses_start_naming_the_address_not_the_token(
        migrated_database, tmp_path, label, answer):
    """Unsealed, and the login check's metadata read answered with a 200 that is not KV metadata, or a 4xx other than
    403: start is refused naming DEFENDER_OPENBAO_ADDR, not the token file (the token was not what was refused). (G4;
    r8 Am-1)"""
    bao = ScriptedOpenBao()
    bao.answer("GET", "metadata", answer, times=1)
    message = await _start(migrated_database, tmp_path, bao)
    assert message is not None, f"{label} started"
    assert "DEFENDER_OPENBAO_ADDR" in message, message
    assert "DEFENDER_API_OPENBAO_TOKEN_FILE" not in message, message


async def test_g4_a_sealed_secret_store_starts_the_api_and_the_routes_that_need_it_answer_503_until_it_is_unsealed(migrated_database, tmp_path):
    """Sealed at start: the API starts having asked only seal-status; system reads and credential writes are 503 naming
    the sealed store; records, the catalog and saves (a create, a replace) still answer; unsealed, each request asks
    again and the same app serves. (G4, D9, O3, O7; r8 Am-2)"""
    bao = ScriptedOpenBao()
    bao.sealed = True
    async with served_config(migrated_database, tmp_path, scripted=bao, keep_calls=True) as served:
        assert bao.calls == [SEAL_STATUS]
        assert (await served.get("/adapters")).status_code == 200
        assert (await served.put_system(TICKET, 0)).status_code == 201  # a save reads no secret store
        assert (await served.put_system(TICKET, 1)).status_code == 200
        for refused in (await served.get_system(TICKET), await served.list_systems(),
                        await served.put_credentials(TICKET, 2, {"api_key": TOKEN})):
            assert refused.status_code == 503, refused.text
            assert "sealed" in problem_text(refused).lower()
        assert [v.version for v in served.versions(TICKET)] == [1, 2]
        assert served.stored_generations(TICKET) == []
        bao.sealed = False
        assert (await served.get_system(TICKET)).status_code == 200
        assert (await served.put_credentials(TICKET, 2, {"api_key": TOKEN})).status_code == 204
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


class _CountsCloses(ScriptedOpenBao):
    """The scripted store, counting how often a client over it is closed: an `httpx.AsyncClient` closes its transport
    once, as it closes."""

    def __init__(self) -> None:
        super().__init__()
        self.closes = 0

    async def aclose(self) -> None:
        self.closes += 1


async def test_g4_the_api_asks_the_secret_store_over_one_pooled_client_its_start_opens_and_its_stop_closes(
        migrated_database, tmp_path):
    """The login check and every request after it share one pooled client, opened by the start sequence and closed when
    the program stops: none is opened and closed per call, which would make a page of rows open a connection each.
    (G4, O3; r8 Am-1, r9)"""
    bao = _CountsCloses()
    async with served_config(migrated_database, tmp_path, scripted=bao) as served:
        started = bao.closes  # the seal-status read's own client, closed before the login check
        assert (await served.put_system(TICKET, 0)).status_code == 201
        for _ in range(3):
            assert (await served.list_systems()).status_code == 200
        assert (await served.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204
        assert bao.calls, "premise: the store was asked"
        assert bao.closes == started, "a client was closed while the program served"
    assert bao.closes == started + 1, "the pooled client was not closed once at stop"
