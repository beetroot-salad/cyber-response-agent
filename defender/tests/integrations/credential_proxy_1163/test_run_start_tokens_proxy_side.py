"""#1163/#1359 (proxy side): the in-process signer outlives its AppRole login. A run's read token, signed when first
asked and replaced once its life is spent, is signed through a new login when the login token that signed the earlier
one has expired, and a rotation of the tenant's generation in between is followed (A24). The operator run signs no
write-back token (W7): the write-back pass belongs to the job lane."""
from __future__ import annotations

import time
from typing import Any
from unittest import mock

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163._target import proxy
from defender.tests.integrations.credential_proxy_1163.test_run_start_tokens import (
    TOKEN_SEC,
    RunAtHandedRecorder,
    _plant,
)
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

ROLE, SECRET = "role-1163-own", "secret-1163-own"
NEW_ROLE, NEW_SECRET = "role-1163-rotated", "secret-1163-rotated"


class _Clock:
    """The access holder's clock, moved only by the test."""

    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now


class _Investigating(RunAtHandedRecorder):
    """A stand-in investigation that asks the run's access for a read token, runs `between` (a login expiring, a
    rotation), lets the token's life run out on the holder's clock, and asks again: the second ask signs a new
    token, so the signer's login is the one under test."""

    def __init__(self, *a: Any, clock: _Clock, between: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self._clock, self._between = clock, between

    def lifecycle(self, **kw: Any) -> dict[str, Any]:
        kw["access"].token()
        self._between()
        self._clock.now += TOKEN_SEC
        kw["access"].token()
        return super().lifecycle(**kw)


def _drive(tmp_path, data_root, records, bao, *, between):
    from defender.run import _TokenMint

    clock, real = _Clock(), _TokenMint.for_run
    rec = _Investigating(tmp_path / "run", clock=clock, between=between)
    with mock.patch.object(_TokenMint, "for_run", lambda *a, **kw: real(*a, **kw, clock=clock)):
        rc, refused = S.drive_run(
            S.run_argv(S.plant_alert(tmp_path / "in"), data_root), rec,
            proxy_url="http://proxy.invalid", issuer_transport=bao, directory=records.directory)
    assert (rc, refused) == (0, None), (rc, refused)
    return rec


def _records(data_root, tmp_path, *generations):
    """The tenant planted (identity and ticket reachable, every other system without a declaration), THEN its records
    built over that folder: the records a run starts from are the folder's, which must exist when they are seeded
    (#1366 R8: records are stated, not inferred by a default)."""
    _plant(data_root, proxy=("identity", "ticket"))
    return A.Records(data_root, {S.PLAYGROUND_ID: list(generations)})


def test_r8_the_signer_logs_in_again_when_its_login_token_has_expired(tmp_path, data_root):
    """The login token that signed the investigation's read token expires before the next read token is signed (the
    first one's life spent); that one is still signed, with a second login. A1, A7, r7 A20."""
    gen = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET)
    bao = A.OpenBaoStandIn({ROLE: SECRET})

    def expire_logins() -> None:
        bao.revoked.extend(sign.client_token for sign in bao.signs)

    _drive(tmp_path, data_root, _records(data_root, tmp_path, gen), bao, between=expire_logins)

    assert len(bao.logins) >= 2, "the expired login was replaced by another login"
    assert len(bao.signs) == 2, "the read token, then the one signed once its life was spent"
    assert bao.signs[1].client_token != bao.signs[0].client_token
    assert bao.signs[1].key == proxy().transit_key_for(S.PLAYGROUND_ID)
    assert A.grant_of(A.claims_of_payload(bao.signs[0].payload)) == [("identity", "r")]
    assert A.grant_of(A.claims_of_payload(bao.signs[1].payload)) == [("identity", "r")]


def test_r9_a_rotation_before_the_next_sign_is_followed_by_the_next_login(tmp_path, data_root):
    """The generation rotates, and the old login token dies, after the investigation signed its read token: the next
    token's login uses the new generation's sign pair (the old file is gone), not a cached one. A24."""
    old = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET)
    new = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=NEW_ROLE,
                       sign_secret=NEW_SECRET, salt="g2")
    records = _records(data_root, tmp_path, old)
    bao = A.OpenBaoStandIn({ROLE: SECRET, NEW_ROLE: NEW_SECRET})

    def rotate() -> None:
        records.rotate(S.PLAYGROUND_ID, new)
        old["sign_secret_file"].unlink()
        bao.revoked.extend(sign.client_token for sign in bao.signs)

    _drive(tmp_path, data_root, records, bao, between=rotate)

    assert bao.logins == [(ROLE, SECRET), (NEW_ROLE, NEW_SECRET)]
    first, second = bao.signs
    assert (bao.role_of(first), bao.role_of(second)) == (ROLE, NEW_ROLE)
    assert A.grant_of(A.claims_of_payload(second.payload)) == [("identity", "r")]
