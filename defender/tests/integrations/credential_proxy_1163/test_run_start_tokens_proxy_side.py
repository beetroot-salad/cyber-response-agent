"""#1163/#1359 (proxy side): the write-back token is minted at the record leg, for the case system
the case-record file names, and the in-process signer outlives its AppRole login. Run start signs
no write-back token (D-9 corrected), so a run longer than the token's life still comments; a login
token that expired during the investigation is replaced, and a rotation of the tenant's generation
before the leg is followed (A24)."""
from __future__ import annotations

import time
from typing import Any

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163._target import proxy
from defender.tests.integrations.credential_proxy_1163.test_run_start_tokens import (
    TOKEN_SEC,
    RunAtHandedRecorder,
    TicketRecorder,
    _plant,
)
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

ROLE, SECRET = "role-1163-own", "secret-1163-own"
NEW_ROLE, NEW_SECRET = "role-1163-rotated", "secret-1163-rotated"
#: How long the stand-in investigation takes. The write-back token's life must start after it.
INVESTIGATION_SEC = 2


class _LegSees(TicketRecorder):
    """The ticket seam, noting how many tokens OpenBao had signed when the record leg was called."""

    def __init__(self, bao: A.OpenBaoStandIn) -> None:
        super().__init__()
        self._bao = bao
        self.signed_at_leg: int | None = None

    def record_case_ticket(self, run: Any, **kw: Any) -> None:
        self.signed_at_leg = len(self._bao.signs)
        super().record_case_ticket(run, **kw)


class _Investigating(RunAtHandedRecorder):
    """A stand-in investigation: `read_token` has it ask the run's access for a read token (its
    first call, r7 A20); `between` runs after that, before the lifecycle returns (a login expiring,
    a rotation); it takes `INVESTIGATION_SEC`."""

    def __init__(self, *a: Any, bao: A.OpenBaoStandIn, read_token: bool = False,
                 between: Any = None, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self._bao, self._read_token, self._between = bao, read_token, between
        self.signed_during: int | None = None

    def lifecycle(self, **kw: Any) -> dict[str, Any]:
        if self._read_token:
            kw["access"].token()
        if self._between is not None:
            self._between()
        time.sleep(INVESTIGATION_SEC)
        self.signed_during = len(self._bao.signs)
        return super().lifecycle(**kw)


def _drive(tmp_path, data_root, records, bao, *, read_token=False, between=None):
    _plant(data_root, proxy=("identity", "ticket"))
    tickets = _LegSees(bao)
    rec = _Investigating(tmp_path / "run", bao=bao, read_token=read_token, between=between)
    started = time.time()
    rc, refused = S.drive_run(
        S.run_argv(S.plant_alert(tmp_path / "in"), data_root, update_ticket=True), rec,
        ticket_writer=tickets, proxy_url="http://proxy.invalid", issuer_transport=bao,
        directory=records.directory)
    assert (rc, refused) == (0, None), (rc, refused)
    return rec, tickets, started


def _records(data_root, tmp_path, *generations):
    return A.Records(data_root, {S.PLAYGROUND_ID: list(generations)})


def test_r7_the_write_back_token_is_minted_at_the_record_leg_fresh_for_the_named_case_system(
        tmp_path, data_root):
    """Nothing is signed at run start or during the investigation; the one write-back token is
    signed when the record leg is reached, `rw` on the case system the case-record file names only,
    and its life starts after the investigation (a run longer than the token's life still gets a
    live token). D-9 corrected, R4."""
    gen = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET)
    bao = A.OpenBaoStandIn({ROLE: SECRET})
    rec, tickets, started = _drive(tmp_path, data_root, _records(data_root, tmp_path, gen), bao)

    assert rec.signed_during == 0, "a token was signed before the record leg (at run start or mid-run)"
    assert tickets.signed_at_leg == 1, "the record leg was not handed a freshly signed token"
    (sign,) = bao.signs
    claims = A.claims_of_payload(sign.payload)
    assert A.grant_of(claims) == [("ticket", "rw")], claims
    assert (claims["tenant"], claims["investigation"]) == (S.PLAYGROUND_ID, rec.run_dir_at.name)
    assert claims["exp"] >= started + INVESTIGATION_SEC + TOKEN_SEC - 1, (
        "the write-back token's life began before the investigation ended: it was signed at run start")
    assert tickets.leg("record")["request_token"], "the leg got the token it was signed for"
    assert [n for n, _ in tickets.calls if n not in ("clear", "record")] == [], "an open leg ran"


def test_r8_the_signer_logs_in_again_when_its_login_token_has_expired(tmp_path, data_root):
    """The login token that signed the investigation's read token expires before the record leg;
    the leg's write-back token is still signed, with a second login. A1, A7, r7 A20."""
    gen = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET)
    bao = A.OpenBaoStandIn({ROLE: SECRET})

    def expire_logins() -> None:
        bao.revoked.extend(sign.client_token for sign in bao.signs)

    _rec, tickets, _ = _drive(tmp_path, data_root, _records(data_root, tmp_path, gen), bao,
                              read_token=True, between=expire_logins)

    assert len(bao.logins) >= 2, "the expired login was replaced by another login"
    assert len(bao.signs) == 2, "the investigation's read token, then the record write-back token"
    assert tickets.signed_at_leg == 2
    assert bao.signs[1].client_token != bao.signs[0].client_token
    assert bao.signs[1].key == proxy().transit_key_for(S.PLAYGROUND_ID)
    assert A.grant_of(A.claims_of_payload(bao.signs[0].payload)) == [("identity", "r")]
    assert A.grant_of(A.claims_of_payload(bao.signs[1].payload)) == [("ticket", "rw")]
    assert tickets.leg("record")["request_token"], "the record leg got its write-back token"


def test_r9_a_rotation_before_the_record_leg_is_followed_by_the_next_login(tmp_path, data_root):
    """The generation rotates, and the old login token dies, after the investigation signed its
    read token: the record leg's login uses the new generation's sign pair (the old file is gone),
    not a cached one. A24."""
    old = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET)
    new = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=NEW_ROLE,
                       sign_secret=NEW_SECRET, salt="g2")
    records = _records(data_root, tmp_path, old)
    bao = A.OpenBaoStandIn({ROLE: SECRET, NEW_ROLE: NEW_SECRET})

    def rotate() -> None:
        records.rotate(S.PLAYGROUND_ID, new)
        old["sign_secret_file"].unlink()
        bao.revoked.extend(sign.client_token for sign in bao.signs)

    _rec, tickets, _ = _drive(tmp_path, data_root, records, bao, read_token=True, between=rotate)

    assert bao.logins == [(ROLE, SECRET), (NEW_ROLE, NEW_SECRET)]
    first, second = bao.signs
    assert (bao.role_of(first), bao.role_of(second)) == (ROLE, NEW_ROLE)
    assert A.grant_of(A.claims_of_payload(second.payload)) == [("ticket", "rw")]
    assert tickets.leg("record")["request_token"], "the record leg got its write-back token"
