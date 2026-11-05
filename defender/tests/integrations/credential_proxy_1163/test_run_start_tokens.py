"""#1163 the run signs its request tokens in the run process: a read token over the granted
`http-proxy` systems when a call first needs one (r7 A20), and a write-back token for the record
leg when the case system the case-record file names is `http-proxy` (#1359: no open leg). Run start checks configuration only and contacts no
OpenBao. Driven through `run.main` and its injection seams."""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import pytest

from defender.kit.faults import ConfigFault, TransportFault
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._opened_paths import opened, opened_paths
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163._target import proxy, request_signer
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

TABLE = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
  identity:
    get-user: {roles: [gather]}
    health-check: {roles: [gather]}
"""
#: A request token's lifetime, read and write-back alike (r7 A20).
TOKEN_SEC = 600
#: The seconds between the test's clock and the run's stamp of its start.
CLOCK_TOLERANCE = 60


class TicketRecorder:
    """The `ticket_writer` seam of `run.main` (#1359 r4): `record_case_ticket` and `clear_receipt`
    only, so a run that called an open leg would fail. Records each call's keyword arguments."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def clear_receipt(self, run: Any, **kw: Any) -> None:
        self.calls.append(("clear", kw))

    def record_case_ticket(self, run: Any, **kw: Any) -> None:
        self.calls.append(("record", kw))

    def leg(self, name: str) -> dict[str, Any]:
        (kw,) = [k for n, k in self.calls if n == name]
        return kw


#: What a case system on `http-proxy` needs beside its access method (the `ticket` adapter's key
#: grammar) and its one declared write route.
EXTRA = {"ticket": 'TICKET_KEY_PATTERN="[A-Za-z0-9-]+"\n'}
CASE_WRITES = {"ticket": (("POST", "/tickets/*/comments"),)}


def _plant(data_root, *, proxy: tuple[str, ...], case_system: str | None = "ticket", **kw: Any):
    """The playground tenant with each system of `proxy` on `http-proxy` (declaration planted
    beside its config.env) and a case-record file naming `case_system` (None: no such file)."""
    configs = dict(S.config_texts("t1163"))
    for system in proxy:
        configs[system] = A.env_text(system, extra=EXTRA.get(system, ""))
    folder = S.plant(data_root, configs=configs, table=TABLE, case_system=case_system, **kw)
    for system in proxy:
        decl = H.declaration("http://x.invalid/api", writes=CASE_WRITES.get(system, ()))
        for rel, text in H.access_files(system, decl).items():
            (folder / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / rel).write_text(text, encoding="utf-8")


def _config_refusal(refused, *causes: str) -> bool:
    """A run-start refusal for operator configuration: a `ConfigFault`, or run start's own
    `sys.exit` with a message naming one of `causes` (the house refusal style, run.py)."""
    if isinstance(refused, ConfigFault):
        return True
    text = str(getattr(refused, "code", "")).lower()
    return isinstance(refused, SystemExit) and any(c in text for c in causes)


class RunAtHandedRecorder(S.RunRecorder):
    """`S.RunRecorder` whose run folder is the run `run.main` handed `materialize`, as in
    production: the request tokens are signed for that run before it is materialised (r7 A20),
    so the folder must be the same run for a token's investigation to name it."""

    def materialize(self, alert, **kw):
        self.run_dir_at = kw["run"].run_dir
        return super().materialize(alert, **kw)


def _drive(tmp_path, data_root, *, signer=None, ticket=True, summary=None, **seams):
    """Drive `run.main`; with no `signer` none is injected (the production signing path)."""
    rec, tickets = RunAtHandedRecorder(tmp_path / "run", summary=summary), TicketRecorder()
    alert = S.plant_alert(tmp_path / "in")
    started = time.time()
    if signer is not None:
        seams["signer"] = signer
        if "directory" not in seams:  # r8.6 A24: run start checks the sign login even with an injected signer
            seams["directory"] = _records(data_root, tmp_path)[0].directory
    try:
        rc, refused = S.drive_run(
            S.run_argv(alert, data_root, update_ticket=ticket), rec, ticket_writer=tickets,
            proxy_url="http://proxy.invalid", **seams)
    except ConfigFault as fault:
        rc, refused = None, fault
    return rec, tickets, rc, refused, started


def read_access(rec) -> Any:
    """The `RequestAccess` the run handed its lifecycle."""
    (life,) = rec.lifecycle_calls
    return life["access"]


def _claims_of_token(signer: H.FakeSigner, token: str) -> dict[str, Any]:
    (n,) = [i for i in range(1, len(signer.payloads) + 1) if f"{A.SIGNATURE_CANARY}-{i}" in token]
    return A.claims_of_payload(signer.payloads[n - 1])


def test_r1_the_read_token_is_signed_when_first_asked_and_a_write_back_token_for_the_record_leg(
        tmp_path, data_root, caplog):
    """Run start signs no read token; the record leg's one write-back token is `rw` on the case system only.
    The read token, asked of the run's access, is signed then, grants only http-proxy systems,
    lives 600 s and is reused while it has life left; no token reaches disk or log.
    O8, O10, O4, A7, r7 A20."""
    caplog.set_level(logging.DEBUG)
    _plant(data_root, proxy=("identity", "ticket"))
    signer = A.MarkedSigner()
    rec, tickets, rc, refused, started = _drive(tmp_path, data_root, signer=signer)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    run_id = rec.run_dir_at.name
    write_back = [A.claims_of_payload(p) for p in signer.payloads]
    assert [A.grant_of(c) for c in write_back] == [[("ticket", "rw")]], (
        "nothing but the record leg's one write-back token was signed during the run")
    access = read_access(rec)
    asked = time.time()
    first = access.token()
    assert access.token() == first, "a token with life left is reused"
    assert len(signer.payloads) == 2
    read = A.claims_of_payload(signer.payloads[1])
    assert A.grant_of(read) == [("identity", "r")], "the cmdb (docker-exec) system is not granted"
    for c in [*write_back, read]:
        assert (c["tenant"], c["investigation"]) == (S.PLAYGROUND_ID, run_id)
    assert TOKEN_SEC - 1 <= read["exp"] - asked <= TOKEN_SEC + CLOCK_TOLERANCE, read["exp"] - asked
    for c in write_back:
        assert started < c["exp"] <= started + TOKEN_SEC + CLOCK_TOLERANCE

    record_tok = tickets.leg("record")["request_token"]
    assert A.grant_of(_claims_of_token(signer, record_tok)) == [("ticket", "rw")]
    assert [n for n, _ in tickets.calls if n not in ("clear", "record")] == [], "an open leg ran"

    (life,) = rec.lifecycle_calls
    for held in (life["tenant"], life["run"], life["systems"]):
        assert A.SIGNATURE_CANARY not in repr(held), "a token shows in a repr (O10)"
    assert A.SIGNATURE_CANARY not in caplog.text
    on_disk = A.text_of(data_root, tmp_path)
    assert A.SIGNATURE_CANARY not in on_disk, "a token reached a file: run state, record or log"
    assert run_id in on_disk, "positive control: the files the run wrote are read"
    assert S.PLAYGROUND_ID in A.text_of(data_root), "positive control: the data root is read too"
    assert "run_dir=" in caplog.text, "positive control: the log channel is read"


@pytest.mark.parametrize("truncated_by", ["budget", "store", "provider-down"])
def test_r1_a_run_that_will_not_comment_signs_no_write_back_token(tmp_path, data_root, truncated_by):
    """A run cut short before a verdict leaves the case alone: no write-back token is signed for
    it, and the record step is handed none. The case system was judged once, at run start, and
    that verdict reaches the record step. Control: `test_r1_the_read_token_is_signed_…` signs one
    for a run that ends normally. #1392 review."""
    _plant(data_root, proxy=("identity", "ticket"))
    signer = A.MarkedSigner()
    _rec, tickets, rc, refused, _started = _drive(
        tmp_path, data_root, signer=signer, summary={
            "output": "x", "requests": 0, "truncated_by": truncated_by, "closed_before_cut": False})

    assert refused is None, (rc, refused)
    assert signer.payloads == [], "a write-back token was signed for a run that will not comment"
    leg = tickets.leg("record")
    assert "request_token" not in leg, leg
    assert type(leg["case"]).__name__ == "CaseTarget", leg["case"]


def test_r2_a_docker_exec_ticket_system_gets_no_write_back_token(tmp_path, data_root):
    """Only the identity system is `http-proxy`: the record leg is handed no token, and the
    one token signed is the read token, when asked. A7, r7 A20."""
    _plant(data_root, proxy=("identity",))
    signer = A.MarkedSigner()
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, signer=signer)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    assert signer.payloads == []
    read_access(rec).token()
    assert [A.grant_of(A.claims_of_payload(p)) for p in signer.payloads] == [[("identity", "r")]]
    assert tickets.leg("record").get("request_token") is None


def test_r3_a_run_with_no_http_proxy_system_never_contacts_the_signer(tmp_path, data_root):
    """No granted system is `http-proxy`: nothing is signed even by a sealed OpenBao, so existing
    replays need none. A7."""
    _plant(data_root, proxy=())
    signer = A.RaisingSigner(ConfigFault("OpenBao is sealed"))
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, signer=signer)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    assert signer.asked == 0
    assert tickets.leg("record").get("request_token") is None
    assert rec.lifecycle_calls, "positive control: the run reached its lifecycle"


ROLE, SECRET = "role-1163-own", "secret-1163-own"
DECOY_ROLE, DECOY_SECRET = "role-1163-decoy", "secret-1163-decoy"
DECOY_TENANT = fixture_uuid("tenant:1163-decoy")
#: The delivery login of the same generations: the signer must never use it (A24').
DELIVERY_ROLE, DELIVERY_SECRET = "role-1163-delivery", "secret-1163-delivery"


def _records(data_root, tmp_path, **kw):
    """The playground tenant's records with one live generation holding the sign login (ROLE,
    SECRET) in a host file, beside a delivery login the signer must not use."""
    fields = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET,
                          role_id=DELIVERY_ROLE, delivery_secret=DELIVERY_SECRET, **kw)
    return A.Records(data_root, {S.PLAYGROUND_ID: [fields]}), fields


SEALED = {"sealed on login": {"sealed": "login"}, "sealed on sign": {"sealed": "sign"},
          "unreachable": {"unreachable": True}, "login answers 500": {"login_status": 500},
          "sign answers 502": {"sign_status": 502}}


@pytest.mark.parametrize("fault", list(SEALED))
def test_r4_a_sealed_or_unreachable_openbao_does_not_stop_run_start_and_is_retryable(
        tmp_path, data_root, fault):
    """Run start contacts no OpenBao, so one answering 5xx (sealed on login or sign, or any 5xx)
    or not at all does not stop it; the read token asked of it then is `TransportFault`, a fault
    a later call may not meet, and nothing is signed. r7 A20, A18, A24."""
    _plant(data_root, proxy=("identity",))
    records, _ = _records(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: SECRET}, **SEALED[fault])
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, ticket=False, issuer_transport=bao,
                                          directory=records.directory)

    assert (rc, refused) == (0, None)
    assert bao.requests == [], "run start contacted OpenBao"
    with pytest.raises(TransportFault):
        read_access(rec).token()
    assert bao.requests, "positive control: OpenBao was asked for the token"
    assert bao.signs == []


def test_r4b_a_login_openbao_refuses_is_a_config_fault_at_the_mint(tmp_path, data_root):
    """OpenBao refusing the sign login (4xx: a wrong secret) is `ConfigFault`, not a fault a
    retry may clear; the same login with the right secret signs. A24, A18."""
    _plant(data_root, proxy=("identity",))
    records, _ = _records(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: "another-secret"})
    rec, _tickets, rc, refused, _ = _drive(tmp_path, data_root, ticket=False, issuer_transport=bao,
                                           directory=records.directory)
    assert (rc, refused) == (0, None)
    with pytest.raises(ConfigFault):
        read_access(rec).token()
    assert (bao.logins, bao.signs) == ([(ROLE, SECRET)], [])
    bao.accounts[ROLE] = SECRET
    read_access(rec).token()
    assert len(bao.signs) == 1, "positive control: the right secret signs"


@pytest.mark.parametrize(("status", "logins"), [(400, 1), (401, 2), (403, 2)],
                         ids=["bad request", "unauthorized", "forbidden"])
def test_r4e_a_sign_openbao_refuses_with_a_4xx_is_a_config_fault_after_one_relogin_on_401_or_403(
        tmp_path, data_root, status, logins):
    """A sign call answered 4xx (400: a key not yet made; 401/403: a refused client token) is
    `ConfigFault`; a 401 or 403 is retried after exactly one fresh login, a 400 not. Control: a
    sign that is not refused signs. A24 detail (login again once on 401/403), A18."""
    _plant(data_root, proxy=("identity",))
    records, _ = _records(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: SECRET}, sign_status=status)
    rec, _tickets, rc, refused, _ = _drive(tmp_path, data_root, ticket=False, issuer_transport=bao,
                                           directory=records.directory)
    assert (rc, refused) == (0, None)
    with pytest.raises(ConfigFault) as failed:
        read_access(rec).token()
    assert len(bao.logins) == logins, bao.logins
    assert bao.signs == []
    assert SECRET not in str(failed.value)
    bao.sign_status = None
    read_access(rec).token()
    assert len(bao.signs) == 1, "positive control: the same run signs once OpenBao accepts"


def _make_absent(path: Path) -> None:
    path.unlink()


def _make_unreadable(path: Path) -> None:
    path.unlink()
    path.mkdir()  # a read of a folder fails whoever the user is


def _make_empty(path: Path) -> None:
    path.write_text("", encoding="utf-8")


def _make_two_lines(path: Path) -> None:
    path.write_text(f"{SECRET}\n{SECRET}\n", encoding="utf-8")


@pytest.mark.parametrize("status", [500, 502])
def test_r4g_a_sign_answered_5xx_is_a_transport_fault_after_exactly_one_login(tmp_path, data_root, status):
    """A 5xx sign is retryable (`TransportFault`) and is not a refused client token: no second
    login. A18, A24 detail (re-login only on 401/403)."""
    _plant(data_root, proxy=("identity",))
    records, _ = _records(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: SECRET}, sign_status=status)
    signer = request_signer(S.PLAYGROUND_ID, directory=records.directory, transport=bao)
    with pytest.raises(TransportFault):
        signer.sign(b"payload-1163")
    assert bao.logins == [(ROLE, SECRET)], "a 5xx sign logged in again"
    assert bao.signs == []


@pytest.mark.parametrize("malformed", ["login", "sign", "sign-nonjson", "sign-empty", "sign-nonstring"])
def test_r4h_a_2xx_without_a_client_token_or_a_signature_is_a_config_fault(tmp_path, data_root, malformed):
    """A login 200 with no `auth.client_token`, and a sign 200 that is not JSON or has a `data.signature` that is absent,
    empty or not a string, are `ConfigFault`, not a fault a retry clears. A18 ("a malformed 2xx -> ConfigFault"), A24."""
    _plant(data_root, proxy=("identity",))
    records, _ = _records(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: SECRET}, malformed=malformed)
    signer = request_signer(S.PLAYGROUND_ID, directory=records.directory, transport=bao)
    with pytest.raises(ConfigFault):
        signer.sign(b"payload-1163")
    assert bao.signs == []
    assert bao.logins, "positive control: the malformed answer was reached"


def test_r4i_a_signer_holds_its_client_token_across_signs(tmp_path, data_root):
    """Two signs by one signer make one login and both use its client token. A24 detail (the
    signer holds its OpenBao client token)."""
    _plant(data_root, proxy=("identity",))
    records, _ = _records(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: SECRET})
    signer = request_signer(S.PLAYGROUND_ID, directory=records.directory, transport=bao)
    signer.sign(b"payload-1")
    signer.sign(b"payload-2")
    assert bao.logins == [(ROLE, SECRET)], "the second sign logged in again"
    first, second = bao.signs
    assert first.client_token == second.client_token


@pytest.mark.parametrize("spoil", [_make_absent, _make_unreadable], ids=["absent", "unreadable"])
def test_r4j_the_request_signer_opens_only_the_sign_secret_file(tmp_path, data_root, spoil):
    """With the delivery secret file absent or unreadable the signer still signs, and it never opens
    that file (a read whose error is swallowed is still a read). A24' (never reads the delivery file)."""
    _plant(data_root, proxy=("identity",))
    records, fields = _records(data_root, tmp_path)
    spoil(fields["host_secret_file"])
    bao = A.OpenBaoStandIn({ROLE: SECRET})
    signer = request_signer(S.PLAYGROUND_ID, directory=records.directory, transport=bao)
    with opened_paths() as seen:
        signer.sign(b"payload-1163")
    assert bao.logins == [(ROLE, SECRET)], "positive control: signed with the sign pair"
    assert opened(seen, fields["sign_secret_file"]), "positive control: the sign file was read"
    assert not opened(seen, fields["host_secret_file"]), "the signer opened the delivery secret file"


class _CountingDirectory:
    """Tenant records that count every use made of them."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.uses: list[str] = []

    def __getattr__(self, name: str) -> Any:
        self.uses.append(name)
        return getattr(self._inner, name)


def test_r4k_building_a_request_signer_reads_no_records_and_no_file(tmp_path, data_root):
    """Built over records that count their use and secret paths that do not exist, the signer reads
    no record, opens no file and sends nothing; its first sign then reads both. A24' signer handle
    (r8.5: building reads and sends nothing)."""
    _plant(data_root, proxy=("identity",))
    records, fields = _records(data_root, tmp_path, sign_file=False, delivery_file=False)
    counted = _CountingDirectory(records.directory)
    bao = A.OpenBaoStandIn({ROLE: SECRET})
    with opened_paths() as seen:
        signer = request_signer(S.PLAYGROUND_ID, directory=counted, transport=bao)
    assert counted.uses == [], "building the signer read the tenant records"
    assert not opened(seen, fields["sign_secret_file"]), "building the signer opened the sign file"
    assert not opened(seen, fields["host_secret_file"]), "building the signer opened the delivery file"
    assert bao.requests == []
    fields["sign_secret_file"].write_text(SECRET + "\n", encoding="utf-8")
    signer.sign(b"payload-1163")
    assert counted.uses, "positive control: the sign read the records"
    assert bao.logins == [(ROLE, SECRET)], "positive control: the file written after the build is the one used"


def _parts_of(secret: str, size: int = 6) -> list[str]:
    """Every run of `size` characters of `secret` (the whole of it when shorter)."""
    return [secret[i:i + size] for i in range(max(1, len(secret) - size + 1))]


def test_r4f_a_request_signer_shows_no_part_of_the_client_token_or_the_sign_secret(tmp_path, data_root):
    """`request_signer(tenant, directory=, transport=)` sends nothing when built; before and after one sign neither its repr
    nor its str shows the client token the login issued or the sign secret, nor any run of 6 characters of either.
    O10, A24' signer handle (r8.5), r8.6 (A24' repr)."""
    import secrets as _secrets

    _plant(data_root, proxy=("identity",))
    secret = _secrets.token_urlsafe(24)  # random, so a shared run of 6 characters cannot be a coincidence of the fixture
    fields = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=secret)
    records = A.Records(data_root, {S.PLAYGROUND_ID: [fields]})
    bao = A.OpenBaoStandIn({ROLE: secret})
    signer = request_signer(S.PLAYGROUND_ID, directory=records.directory, transport=bao)
    assert bao.requests == [], "building the signer sent a request"
    before = [repr(signer), str(signer)]

    signature = signer.sign(b"payload-1163")
    assert bao.logins == [(ROLE, secret)], "positive control: the sign went through the login"
    assert len(bao.signs) == 1, "positive control: one sign"
    assert A.SIGNATURE_CANARY in signature, "positive control: the stand-in's signature came back"
    client_token = bao.signs[0].client_token
    assert len(client_token) >= 24, "positive control: the stand-in issued a token"
    assert bao.role_of(bao.signs[0]) == ROLE, "positive control: the token is the sign login's"
    assert "Signer" in before[0], "positive control: the repr is read"
    for text in (*before, repr(signer), str(signer)):
        for hidden, what in ((client_token, "client token"), (secret, "sign secret")):
            shown = [part for part in _parts_of(hidden) if part in text]
            assert not shown, f"the signer shows part of the {what}: {shown[:3]}"


@pytest.mark.parametrize("spoil", [_make_absent, _make_unreadable, _make_empty, _make_two_lines],
                         ids=["absent", "unreadable", "empty", "two secrets"])
def test_r4c_a_sign_secret_file_that_fails_at_the_mint_is_a_config_fault(tmp_path, data_root, spoil):
    """The sign secret file spoiled after run start (absent, unreadable, malformed): the mint is
    `ConfigFault`, no login is sent, and the secret is not in the error. A24."""
    _plant(data_root, proxy=("identity",))
    records, fields = _records(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: SECRET})
    rec, _tickets, rc, refused, _ = _drive(tmp_path, data_root, ticket=False, issuer_transport=bao,
                                           directory=records.directory)
    assert (rc, refused) == (0, None)
    spoil(fields["sign_secret_file"])
    with pytest.raises(ConfigFault) as failed:
        read_access(rec).token()
    assert (bao.logins, bao.signs) == ([], [])
    assert SECRET not in str(failed.value)


def test_r4d_a_tenant_offboarded_since_run_start_cannot_mint(tmp_path, data_root):
    """No live generation at the mint (offboarded since run start): `ConfigFault`, no login.
    A24 (control: R6)."""
    _plant(data_root, proxy=("identity",))
    records, _ = _records(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: SECRET})
    rec, _tickets, rc, refused, _ = _drive(tmp_path, data_root, ticket=False, issuer_transport=bao,
                                           directory=records.directory)
    assert (rc, refused) == (0, None)
    access = read_access(rec)
    records.offboard(S.PLAYGROUND_ID)
    with pytest.raises(ConfigFault):
        access.token()
    assert (bao.logins, bao.signs) == ([], [])


def test_r5_the_signing_login_is_never_taken_from_the_environment(
        tmp_path, data_root, monkeypatch):
    """With login material only in the process environment and no signer or live generation,
    run start refuses and nothing is sent to the address the environment names; a run's
    children still get no login variable. A1, A24."""
    from defender.box import run_env
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv
    from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER

    _plant(data_root, proxy=("identity",))
    with H.upstream() as vault:
        for name, value in (("VAULT_ADDR", vault.url), ("BAO_ADDR", vault.url),
                            ("VAULT_TOKEN", "env-login-1163"), ("BAO_TOKEN", "env-login-1163"),
                            ("DEFENDER_BAO_TOKEN", "env-login-1163"),
                            ("ROLE_ID", "env-role-1163"), ("SECRET_ID", "env-secret-1163")):
            monkeypatch.setenv(name, value)
        rec = S.RunRecorder(tmp_path / "run")
        alert = S.plant_alert(tmp_path / "in")
        argv = S.run_argv(alert, data_root)
        # No live generation: the shared fixture's default sign login (#1391 _proxied1391) is withheld.
        try:
            rc, refused = S.drive_run(argv, rec, proxy_url="http://proxy.invalid",
                                      directory=directory_for_argv(argv, generations=()))
        except ConfigFault as fault:
            rc, refused = None, fault
        env = run_env(DEFENDER, tmp_path / "run")

    assert rc is None, "run start proceeded without a sign login"
    assert refused is not None, "run start proceeded without a sign login"
    assert vault.seen == [], "the environment's address was used"
    assert "materialize" not in rec.order, "the run folder was made before the refusal"
    assert not [k for k in env if k in ("VAULT_TOKEN", "BAO_TOKEN", "DEFENDER_BAO_TOKEN",
                                        "ROLE_ID", "SECRET_ID")]
    assert env["DEFENDER_RUN_DIR"], "positive control: the run env was built"


def test_r5b_a_run_with_no_injected_signer_signs_through_the_sign_login_whatever_the_environment_holds(
        tmp_path, data_root, monkeypatch):
    """With operator OpenBao/Vault tokens and addresses in the environment, the run still signs with
    the live generation's sign login through its issuer transport; the environment's address sees
    nothing. A1/A24 (the signing login is never taken from the environment), A24' signer handle."""
    _plant(data_root, proxy=("identity",))
    records, _ = _records(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: SECRET})
    with H.upstream() as canary:
        for name, value in (("VAULT_ADDR", canary.url), ("BAO_ADDR", canary.url),
                            ("VAULT_TOKEN", "env-token-1163"), ("BAO_TOKEN", "env-token-1163")):
            monkeypatch.setenv(name, value)
        rec, _tickets, rc, refused, _ = _drive(tmp_path, data_root, ticket=False, issuer_transport=bao,
                                               directory=records.directory)
        assert (rc, refused) == (0, None)
        token = read_access(rec).token()
    assert canary.seen == [], "the environment's address was used"
    assert bao.logins == [(ROLE, SECRET)]
    assert len(bao.signs) == 1, "positive control: the token was signed"
    assert set(bao.origins) == {A.deployment_origin()}, "the sign login and sign went to the deployment's address (A1)"
    assert A.SIGNATURE_CANARY in token, "the token carries the stand-in's signature"


def test_r6_run_start_signs_with_the_tenants_own_sign_login_and_key(tmp_path, data_root):
    """No injected signer: the read token, when asked, is signed through OpenBao with the live
    generation's sign login (never its delivery login) and the tenant's own transit key, not
    another tenant's. A24', A11, A1, r7 A20."""
    _plant(data_root, proxy=("identity",))
    # A second tenant on the same data root, with its own generation: a run that read the wrong
    # tenant's login, or the wrong key, would be caught.
    S.plant(data_root, DECOY_TENANT)
    own = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET,
                       role_id=DELIVERY_ROLE, delivery_secret=DELIVERY_SECRET)
    decoy = A.generation(DECOY_TENANT, tmp_path / "secrets", sign_role_id=DECOY_ROLE,
                         sign_secret=DECOY_SECRET)
    records = A.Records(data_root, {S.PLAYGROUND_ID: [own], DECOY_TENANT: [decoy]})
    bao = A.OpenBaoStandIn({ROLE: SECRET, DECOY_ROLE: DECOY_SECRET,
                            DELIVERY_ROLE: DELIVERY_SECRET})
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, ticket=False, issuer_transport=bao,
                                          directory=records.directory)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    assert (bao.logins, bao.signs) == ([], []), "run start signed nothing (r7 A20)"
    read_access(rec).token()
    assert bao.logins == [(ROLE, SECRET)], "login with the tenant's own sign pair alone"
    (sign,) = bao.signs
    assert bao.role_of(sign) == ROLE
    assert sign.key == proxy().transit_key_for(S.PLAYGROUND_ID), "the tenant's own transit key (A11)"
    assert sign.key != proxy().transit_key_for(DECOY_TENANT)
    claims = A.claims_of_payload(sign.payload)
    assert (claims["tenant"], A.grant_of(claims)) == (S.PLAYGROUND_ID, [("identity", "r")])
    assert rec.lifecycle_calls, "positive control: the run went on to its lifecycle"


def _no_generation(data_root, tmp_path):
    return A.Records(data_root, {S.PLAYGROUND_ID: []})


def _only_destroyed(data_root, tmp_path):
    fields = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET,
                          status="destroyed")
    return A.Records(data_root, {S.PLAYGROUND_ID: [fields]})


def _only_retiring(data_root, tmp_path):
    fields = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET,
                          status="retiring")
    return A.Records(data_root, {S.PLAYGROUND_ID: [fields]})


def _without(field, value):
    def build(data_root, tmp_path):
        fields = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET)
        fields[field] = value
        return A.Records(data_root, {S.PLAYGROUND_ID: [fields]})
    return build


@pytest.mark.parametrize("setup", [
    _no_generation, _only_destroyed, _only_retiring, _without("sign_role_id", None),
    _without("sign_secret_file", None), _without("sign_secret_file", Path("relative/sign-secret"))],
    ids=["no generation", "only destroyed", "only retiring", "no sign role", "no sign file",
         "relative sign file"])
def test_r7_an_http_proxy_tenant_with_no_usable_sign_login_refuses_run_start(
        tmp_path, data_root, setup):
    """No live generation, or a live one with no sign role or no absolute sign secret file: a
    configuration refusal before the run folder is made, and no OpenBao contact (control: R6).
    A24, A24', r7 A20."""
    _plant(data_root, proxy=("identity",))
    records = setup(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: SECRET})
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, issuer_transport=bao,
                                          directory=records.directory)

    assert rc is None
    assert _config_refusal(refused, "sign", "generation", "login"), refused
    assert bao.requests == []
    assert "materialize" not in rec.order, "the run folder was made before the refusal"
    assert tickets.calls == []


def test_r7b_a_tenant_with_no_http_proxy_system_needs_no_sign_login(tmp_path, data_root):
    """Control for R7: the same records without a generation do not stop a run whose granted systems
    are none `http-proxy`. A20, A24."""
    _plant(data_root, proxy=())
    records = _no_generation(data_root, tmp_path)
    rec, _tickets, rc, refused, _ = _drive(tmp_path, data_root, directory=records.directory)
    assert (rc, refused) == (0, None)
    assert rec.lifecycle_calls


@pytest.mark.parametrize("setup", [_no_generation, _without("sign_role_id", None),
                                   _without("sign_secret_file", None)],
                         ids=["no generation", "no sign role", "no sign file"])
def test_r7c_an_injected_signer_does_not_excuse_a_missing_sign_login(tmp_path, data_root, setup):
    """With a `signer=` injected, an http-proxy tenant whose records hold no usable sign login is
    still refused before the run folder is made, and nothing is signed. r8.6 (A24 run-start check
    is unconditional)."""
    _plant(data_root, proxy=("identity",))
    records = setup(data_root, tmp_path)
    signer = A.MarkedSigner()
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, signer=signer,
                                          directory=records.directory)

    assert rc is None
    assert _config_refusal(refused, "sign", "generation", "login"), refused
    assert signer.payloads == []
    assert "materialize" not in rec.order, "the run folder was made before the refusal"
    assert tickets.calls == []
